//! Exclusive runtime incarnation and restart reconciliation. This supplies
//! neither native resource leases nor permission to retry an interrupted effect.
use super::*;
use crate::{native_hash::Sha256, optimizer_requests::StoppedOwner};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom, Write};
use uuid::Uuid;
use windows::Win32::{
    Foundation::{ERROR_INVALID_PARAMETER, FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{
        GetCurrentProcessId, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, WaitForSingleObject,
    },
};

pub(super) const RECORD_FILE: &str = "runtime.json";
pub(super) const MAX_RECORD_BYTES: u64 = 4096;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    instance: Uuid,
    process: u32,
    created: u64,
    account: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    record: Record,
    checksum: String,
}

fn checksum(record: &Record) -> io::Result<String> {
    let mut hash = Sha256::new().map_err(|_| invalid("Runtime checksum initialization failed."))?;
    hash.update(&serde_json::to_vec(record).map_err(io::Error::other)?)
        .map_err(|_| invalid("Runtime checksum failed."))?;
    hash.finish()
        .map_err(|_| invalid("Runtime checksum failed."))
}
impl Record {
    fn capture() -> io::Result<Self> {
        let process = unsafe { GetCurrentProcessId() };
        let handle = process_handle(process)?;
        Ok(Self {
            version: 1,
            instance: Uuid::new_v4(),
            process,
            created: creation(&handle)?,
            account: Principal::current()?.user_sid()?,
        })
    }
    fn encode(&self) -> io::Result<Vec<u8>> {
        serde_json::to_vec(&Envelope {
            record: self.clone(),
            checksum: checksum(self)?,
        })
        .map_err(io::Error::other)
    }
    fn decode(bytes: &[u8], expected_account: &str) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(invalid("Runtime record is empty or oversized."));
        }
        let value: Envelope = serde_json::from_slice(bytes)
            .map_err(|_| invalid("Runtime record is corrupt or unsupported."))?;
        let r = value.record;
        if r.version != 1
            || r.instance.is_nil()
            || r.process <= 4
            || r.created == 0
            || r.account != expected_account
            || value.checksum != checksum(&r)?
        {
            return Err(invalid(
                "Runtime record identity or checksum does not match.",
            ));
        }
        Ok(r)
    }
}

fn process_handle(id: u32) -> io::Result<OwnedHandle> {
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            id,
        )
    }
    .map_err(native)?;
    Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
}
fn creation(handle: &OwnedHandle) -> io::Result<u64> {
    let mut created = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(
            HANDLE(handle.as_raw_handle()),
            &mut created,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .map_err(native)?;
    let value = ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64;
    if value == 0 {
        return Err(invalid("Native process creation time is unavailable."));
    }
    Ok(value)
}

/// Only invalid-ID, a different native incarnation of that PID, or a signaled
/// retained process object establishes death. Access denial/inspection errors
/// are never interpreted as exit. No waiting, termination or privilege change.
fn prove_stopped(record: &Record) -> io::Result<StoppedOwner> {
    match process_handle(record.process) {
        Err(error) if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER.0 as i32) => (),
        Err(error) => return Err(error),
        Ok(handle) => {
            if creation(&handle)? == record.created {
                match unsafe { WaitForSingleObject(HANDLE(handle.as_raw_handle()), 0) } {
                    WAIT_OBJECT_0 => (),
                    WAIT_TIMEOUT => {
                        return Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "The recorded runtime process is still alive.",
                        ));
                    }
                    _ => return Err(io::Error::last_os_error()),
                }
            }
        }
    }
    // SAFETY: caller holds the protected storage owner lock; record was decoded
    // from its exact protected file, and native PID/incarnation/exit was checked.
    unsafe { StoppedOwner::from_native_exit(record.instance) }.map_err(io::Error::other)
}

pub(super) struct Admission {
    file: File,
    current: Record,
    previous: Option<StoppedOwner>,
}
impl Admission {
    fn publish(&mut self) -> io::Result<()> {
        let bytes = self.current.encode()?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&bytes)?;
        self.file.set_len(bytes.len() as u64)?;
        self.file.sync_all()?;
        // A torn/failed publication is never repaired or treated as admission.
        self.file.seek(SeekFrom::Start(0))?;
        let mut readback = Vec::new();
        (&mut self.file)
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut readback)?;
        if readback != bytes {
            return Err(invalid("Runtime publication readback differs."));
        }
        Ok(())
    }
}

pub(super) fn admit(root: &Path, access: &Access) -> io::Result<Admission> {
    let mut file = open(
        &root.join(RECORD_FILE),
        false,
        true,
        false,
        Some(&access.file),
    )?;
    verify(&file, access, false, MAX_RECORD_BYTES)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let current = Record::capture()?;
    let previous = if bytes.is_empty() {
        // Missing provenance is never reconstructed from existing SQL records.
        for name in [
            REQUEST_DB,
            INTENT_DB,
            RESOURCE_DB,
            "requests.sqlite3-journal",
            "intents.sqlite3-journal",
            "resources.sqlite3-journal",
        ] {
            match std::fs::metadata(root.join(name)) {
                Ok(info) if info.len() > 0 => {
                    return Err(invalid(
                        "Existing optimizer storage has no runtime provenance; explicit review is required.",
                    ));
                }
                Ok(_) => (),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        }
        None
    } else {
        let record = Record::decode(&bytes, &current.account)?;
        Some(prove_stopped(&record)?)
    };
    let mut admission = Admission {
        file,
        current,
        previous,
    };
    if admission.previous.is_none() {
        // Publish first ownership before the first database is created, so a
        // crash during schema initialization still leaves native provenance.
        admission.publish()?;
    }
    Ok(admission)
}

/// Owns SQL, native files, directory pins and the lifetime lock. Dropping it
/// does not erase provenance or grant same-process restart permission.
pub(crate) struct RuntimeOwner {
    storage: Storage,
    instance: Uuid,
    startup_review_required: bool,
}
impl RuntimeOwner {
    pub(crate) fn for_service() -> io::Result<Self> {
        Self::finish(Storage::for_service()?)
    }
    fn finish(mut storage: Storage) -> io::Result<Self> {
        let mut epoch = storage
            .epoch
            .take()
            .ok_or_else(|| invalid("Runtime provenance was not checked."))?;
        if let Some(proof) = epoch.previous.as_ref() {
            if storage
                .requests
                .has_foreign_running_owner(proof.instance())
                .map_err(io::Error::other)?
                || storage
                    .intents
                    .has_foreign_commit_owner(proof.instance())
                    .map_err(io::Error::other)?
                || storage
                    .resources
                    .has_foreign_active_owner(proof.instance())
                    .map_err(io::Error::other)?
            {
                return Err(invalid(
                    "An active operation belongs to an unproved runtime; no new epoch was published.",
                ));
            }
            // Preserve old provenance until all idempotent SQL reconciliations
            // commit. A crash between databases retries only these bookkeeping
            // transitions, never the native operation.
            storage
                .requests
                .mark_stopped_owner_uncertain(proof)
                .map_err(io::Error::other)?;
            storage
                .intents
                .mark_stopped_owner_uncertain(proof)
                .map_err(io::Error::other)?;
            storage
                .resources
                .mark_stopped_owner_uncertain(proof)
                .map_err(io::Error::other)?;
            epoch.publish()?;
        }
        let instance = epoch.current.instance;
        let review_required = storage
            .requests
            .requires_review()
            .map_err(io::Error::other)?
            || storage
                .intents
                .requires_review()
                .map_err(io::Error::other)?
            || storage
                .resources
                .requires_review(instance)
                .map_err(io::Error::other)?;
        storage.epoch = Some(epoch);
        Ok(Self {
            storage,
            instance,
            startup_review_required: review_required,
        })
    }
    pub(crate) fn instance(&self) -> Uuid {
        self.instance
    }
    /// Startup snapshot, not current service/helper/lease readiness.
    pub(crate) fn startup_requires_review(&self) -> bool {
        self.startup_review_required
    }
    pub(crate) fn stores(&mut self) -> (&mut Ledger, &mut Journal) {
        (&mut self.storage.requests, &mut self.storage.intents)
    }
    pub(crate) fn dispatch_stores(
        &self,
    ) -> (&Ledger, &Journal, &crate::optimizer_resources::Catalog) {
        (
            &self.storage.requests,
            &self.storage.intents,
            &self.storage.resources,
        )
    }
    pub(crate) fn resources(&mut self) -> &mut crate::optimizer_resources::Catalog {
        &mut self.storage.resources
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::windows::process::CommandExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    fn synthetic_intent(
        caller: &crate::optimizer_requests::Caller,
        revision: Uuid,
    ) -> crate::optimizer_intents::Intent {
        use crate::{
            optimizer_identity::{FileIdentity, ImageSnapshot, PeFormat, PeHeader},
            optimizer_intents::{Change, Intent, KeyChange, KeyKind, Name, RawValue},
            optimizer_registration::RegistryView,
        };
        let image = ImageSnapshot {
            requested_path: r"C:\Fixture\sample.exe".into(),
            final_path: r"\\?\C:\Fixture\sample.exe".into(),
            identity: FileIdentity {
                volume_serial: 31,
                file_id: [7; 16],
            },
            size: 4096,
            creation_time: 1,
            last_write_time: 2,
            attributes: 32,
            hard_links: 1,
            sha256: "a".repeat(64),
            pe: PeHeader {
                machine: 0x8664,
                format: PeFormat::Pe32Plus,
                characteristics: 0x22,
                subsystem: 2,
                sections: 1,
                entry_point_rva: 4096,
                image_size: 8192,
                headers_size: 512,
            },
            bytes_read: 4608,
        };
        Intent::from_owner(
            caller,
            Uuid::new_v4(),
            Uuid::new_v4(),
            revision,
            image,
            RegistryView::Registry64,
            vec![KeyChange {
                path: "sample.exe".into(),
                kind: KeyKind::Existing,
                values: vec![Change {
                    name: Name::UseFilter,
                    expected: None,
                    desired: Some(RawValue {
                        kind: 4,
                        bytes: 1u32.to_le_bytes().to_vec(),
                    }),
                }],
            }],
        )
        .unwrap()
    }

    fn insert_running(root: &Path, instance: Uuid) {
        let db = Connection::open(root.join(REQUEST_DB)).unwrap();
        db.execute("INSERT INTO invocations(account,session,invocation,lease,revision,phase,instance,nonce) VALUES(?1,1,?2,?3,?4,1,?5,?6)",rusqlite::params!["S-1-5-21-1-2-3-1001",Uuid::new_v4().as_bytes().as_slice(),Uuid::new_v4().as_bytes().as_slice(),Uuid::new_v4().as_bytes().as_slice(),instance.as_bytes().as_slice(),Uuid::new_v4().as_bytes().as_slice()]).unwrap();
    }

    fn changing_resource(
        storage: &mut Storage,
        instance: Uuid,
    ) -> crate::optimizer_resources::ResourceId {
        use crate::optimizer_resources::{Member, Observation, ResourceId};
        let caller = crate::optimizer_requests::Caller::fixture("S-1-5-21-1-2-3-1001", 1);
        let member = Member::for_caller(&caller, "program:v1:hkcu:64:66697874757265").unwrap();
        let id = unsafe { ResourceId::from_native(1, b"synthetic epoch resource") }.unwrap();
        let observation = || {
            unsafe {
                Observation::from_native(
                    id.clone(),
                    instance,
                    b"original".to_vec(),
                    vec![member.clone()],
                    true,
                )
            }
            .unwrap()
        };
        let revision = storage
            .resources
            .register(observation(), b"sleeping".to_vec())
            .unwrap();
        let revision = storage
            .resources
            .request(&id, revision, &caller, &member, true)
            .unwrap();
        let _lost_claim = storage
            .resources
            .begin(&id, revision, observation())
            .unwrap()
            .unwrap();
        id
    }

    #[test]
    fn native_epoch_resource_commit_failure_retains_old_provenance_until_all_three_stores_reconcile()
     {
        let temp = tempfile::tempdir().unwrap();
        let (root, access, held) = fixture(temp.path());
        let (_child, previous) = exited_child();
        write_record(&root, &access, &previous);
        let mut storage = Storage::inside_impl(root.clone(), access, held, true).unwrap();
        let id = changing_resource(&mut storage, previous.instance);
        insert_running(&root, previous.instance);
        let caller = crate::optimizer_requests::Caller::fixture("S-1-5-21-1-2-3-1001", 1);
        let revision = Uuid::new_v4();
        let intent = synthetic_intent(&caller, revision);
        let crate::optimizer_intents::Preparation::New(prepared) =
            storage.intents.prepare(intent).unwrap()
        else {
            panic!("fresh fixture intent required")
        };
        let _lost_intent = storage
            .intents
            .begin_commit(prepared, revision, previous.instance)
            .unwrap();
        let blocker = Connection::open(root.join(RESOURCE_DB)).unwrap();
        blocker
            .execute_batch("BEGIN;SELECT count(*) FROM resources;")
            .unwrap();
        let before = std::fs::read(root.join(RECORD_FILE)).unwrap();
        assert!(RuntimeOwner::finish(storage).is_err());
        assert_eq!(std::fs::read(root.join(RECORD_FILE)).unwrap(), before);
        let requests = Connection::open(root.join(REQUEST_DB)).unwrap();
        let intents = Connection::open(root.join(INTENT_DB)).unwrap();
        assert_eq!(
            requests
                .query_row("SELECT phase FROM invocations", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            5
        );
        assert_eq!(
            intents
                .query_row("SELECT phase FROM intents", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        drop(requests);
        drop(intents);
        assert_eq!(
            blocker
                .query_row("SELECT phase FROM resources", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        blocker.execute_batch("ROLLBACK").unwrap();
        drop(blocker);
        let mut owner = enter(temp.path()).unwrap();
        assert_ne!(owner.instance(), previous.instance);
        assert!(owner.startup_requires_review());
        assert_eq!(
            owner.resources().inspect(&id).unwrap().unwrap().phase,
            crate::optimizer_resources::Phase::Uncertain
        );
    }

    #[test]
    fn native_epoch_foreign_active_resource_refuses_rotation_before_any_reconciliation() {
        let temp = tempfile::tempdir().unwrap();
        let (root, access, held) = fixture(temp.path());
        let (_child, previous) = exited_child();
        write_record(&root, &access, &previous);
        let mut storage = Storage::inside_impl(root.clone(), access, held, true).unwrap();
        changing_resource(&mut storage, Uuid::new_v4());
        insert_running(&root, previous.instance);
        let before = std::fs::read(root.join(RECORD_FILE)).unwrap();
        assert!(RuntimeOwner::finish(storage).is_err());
        assert_eq!(std::fs::read(root.join(RECORD_FILE)).unwrap(), before);
        let requests = Connection::open(root.join(REQUEST_DB)).unwrap();
        assert_eq!(
            requests
                .query_row("SELECT phase FROM invocations", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn native_epoch_cross_database_interruption_preserves_old_provenance_and_retries_bookkeeping_only()
     {
        let temp = tempfile::tempdir().unwrap();
        let (root, access, held) = fixture(temp.path());
        let (_child, previous) = exited_child();
        write_record(&root, &access, &previous);
        let mut storage = Storage::inside_impl(root.clone(), access, held, true).unwrap();
        insert_running(&root, previous.instance);
        let caller = crate::optimizer_requests::Caller::fixture("S-1-5-21-1-2-3-1001", 1);
        let revision = Uuid::new_v4();
        let intent = synthetic_intent(&caller, revision);
        let crate::optimizer_intents::Preparation::New(prepared) =
            storage.intents.prepare(intent.clone()).unwrap()
        else {
            panic!("no fresh fixture intent")
        };
        let _receipt = storage
            .intents
            .begin_commit(prepared, revision, previous.instance)
            .unwrap()
            .into_attempt();
        let old_record = std::fs::read(root.join(RECORD_FILE)).unwrap();
        let blocker = Connection::open(root.join(INTENT_DB)).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(RuntimeOwner::finish(storage).is_err());
        assert_eq!(std::fs::read(root.join(RECORD_FILE)).unwrap(), old_record);
        let requests = Connection::open(root.join(REQUEST_DB)).unwrap();
        assert_eq!(
            requests
                .query_row("SELECT phase FROM invocations", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            5
        );
        assert_eq!(
            blocker
                .query_row("SELECT phase FROM intents", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        blocker.execute_batch("ROLLBACK").unwrap();
        drop(blocker);
        drop(requests);
        let owner = enter(temp.path()).unwrap();
        assert!(owner.startup_requires_review());
        let intents = Connection::open(root.join(INTENT_DB)).unwrap();
        assert_eq!(
            intents
                .query_row("SELECT phase FROM intents", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_ne!(owner.instance(), previous.instance);
    }

    #[test]
    fn native_epoch_unknown_running_instance_refuses_rotation_before_reconciliation() {
        let temp = tempfile::tempdir().unwrap();
        let (root, access, held) = fixture(temp.path());
        let (_child, previous) = exited_child();
        write_record(&root, &access, &previous);
        let storage = Storage::inside_impl(root.clone(), access, held, true).unwrap();
        insert_running(&root, Uuid::new_v4());
        let bytes = std::fs::read(root.join(RECORD_FILE)).unwrap();
        assert!(RuntimeOwner::finish(storage).is_err());
        assert_eq!(std::fs::read(root.join(RECORD_FILE)).unwrap(), bytes);
        let requests = Connection::open(root.join(REQUEST_DB)).unwrap();
        assert_eq!(
            requests
                .query_row("SELECT phase FROM invocations", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    fn fixture(parent: &Path) -> (PathBuf, Access, Vec<File>) {
        let access = Access::fixture().unwrap();
        let root = parent.join("runtime-owner");
        let held = protected_directory(&root, &access).unwrap();
        (root, access, vec![held])
    }
    fn enter(parent: &Path) -> io::Result<RuntimeOwner> {
        let (root, access, held) = fixture(parent);
        RuntimeOwner::finish(Storage::inside_impl(root, access, held, true)?)
    }
    fn write_record(root: &Path, access: &Access, record: &Record) {
        let mut file = open(
            &root.join(RECORD_FILE),
            false,
            true,
            false,
            Some(&access.file),
        )
        .unwrap();
        let bytes = record.encode().unwrap();
        file.write_all(&bytes).unwrap();
        file.set_len(bytes.len() as u64).unwrap();
        file.sync_all().unwrap();
    }
    fn exited_child() -> (std::process::Child, Record) {
        // Authored disposable console child, no visible window/input/network.
        let mut buffer = [0u16; 32768];
        let length = unsafe {
            windows::Win32::System::SystemInformation::GetSystemDirectoryW(Some(&mut buffer))
        } as usize;
        assert!(length > 0 && length < buffer.len());
        let command = PathBuf::from(String::from_utf16(&buffer[..length]).unwrap()).join("cmd.exe");
        let mut child = Command::new(command)
            .args(["/d", "/c", "exit", "0"])
            .creation_flags(0x08000000)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let process = child.id();
        let handle = process_handle(process).unwrap();
        let record = Record {
            version: 1,
            instance: Uuid::new_v4(),
            process,
            created: creation(&handle).unwrap(),
            account: Principal::current().unwrap().user_sid().unwrap(),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("disposable child did not exit in time");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        (child, record)
    }

    #[test]
    fn native_epoch_rejects_live_incarnation_and_same_process_reentry_before_sql() {
        let temp = tempfile::tempdir().unwrap();
        let owner = enter(temp.path()).unwrap();
        assert!(!owner.startup_requires_review());
        let root = temp.path().join("runtime-owner");
        let bytes = std::fs::read(root.join(RECORD_FILE)).unwrap();
        let database = std::fs::read(root.join(REQUEST_DB)).unwrap();
        drop(owner);
        assert_eq!(
            enter(temp.path()).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(std::fs::read(root.join(RECORD_FILE)).unwrap(), bytes);
        assert_eq!(std::fs::read(root.join(REQUEST_DB)).unwrap(), database);
    }

    #[test]
    fn native_epoch_uses_signaled_retained_process_and_publishes_new_owner() {
        let temp = tempfile::tempdir().unwrap();
        let (root, access, held) = fixture(temp.path());
        let (_child, previous) = exited_child();
        write_record(&root, &access, &previous);
        drop(held);
        let owner = enter(temp.path()).unwrap();
        assert_ne!(owner.instance(), previous.instance);
        let stored = Record::decode(
            &std::fs::read(root.join(RECORD_FILE)).unwrap(),
            &previous.account,
        )
        .unwrap();
        assert_eq!(stored.instance, owner.instance());
        assert_eq!(stored.process, unsafe { GetCurrentProcessId() });
    }

    #[test]
    fn native_epoch_identity_checks_distinguish_pid_reuse_from_live_same_incarnation() {
        let record = Record::capture().unwrap();
        assert_eq!(
            prove_stopped(&record).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        let mut synthetic_old_incarnation = record.clone();
        synthetic_old_incarnation.created -= 1;
        assert_eq!(
            prove_stopped(&synthetic_old_incarnation)
                .unwrap()
                .instance(),
            record.instance
        );
        // Different creation-time input exercises the reuse classifier, not an
        // actual forced PID reuse or an authenticated production record.
    }

    #[test]
    fn native_epoch_refuses_corrupt_foreign_and_unknown_records_without_rewriting() {
        let temp = tempfile::tempdir().unwrap();
        let (root, access, held) = fixture(temp.path());
        let (_child, previous) = exited_child();
        for bytes in [
            b"{torn".to_vec(),
            {
                let mut r = previous.clone();
                r.version = 2;
                r.encode().unwrap()
            },
            {
                let mut r = previous.clone();
                r.account = "S-1-5-18".into();
                if r.account == previous.account {
                    r.account = "S-1-5-19".into();
                }
                r.encode().unwrap()
            },
            {
                let mut v: serde_json::Value =
                    serde_json::from_slice(&previous.encode().unwrap()).unwrap();
                v["checksum"] = serde_json::json!("0".repeat(64));
                serde_json::to_vec(&v).unwrap()
            },
        ] {
            let mut file = open(
                &root.join(RECORD_FILE),
                false,
                true,
                false,
                Some(&access.file),
            )
            .unwrap();
            file.write_all(&bytes).unwrap();
            file.set_len(bytes.len() as u64).unwrap();
            drop(file);
            assert!(admit(&root, &access).is_err());
            assert_eq!(std::fs::read(root.join(RECORD_FILE)).unwrap(), bytes);
            assert!(!root.join(REQUEST_DB).exists());
        }
        drop(held);
    }

    #[test]
    fn native_epoch_never_adopts_populated_databases_without_provenance() {
        for name in [REQUEST_DB, INTENT_DB, RESOURCE_DB] {
            let temp = tempfile::tempdir().unwrap();
            let (root, access, held) = fixture(temp.path());
            let mut database =
                open(&root.join(name), false, true, false, Some(&access.file)).unwrap();
            database
                .write_all(b"nonempty fixture without runtime provenance")
                .unwrap();
            drop(database);
            drop(held);
            let bytes = std::fs::read(root.join(name)).unwrap();
            assert!(enter(temp.path()).is_err());
            assert_eq!(std::fs::read(root.join(name)).unwrap(), bytes);
            assert!(std::fs::read(root.join(RECORD_FILE)).unwrap().is_empty());
        }
    }
}
