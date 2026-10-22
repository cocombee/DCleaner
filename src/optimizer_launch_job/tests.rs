use super::*;
use crate::optimizer_requests::Caller;
use crate::optimizer_resources::{Catalog, Observation, Phase, ResourceId};
use std::{
    fs,
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};
use windows::{
    Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle},
    Win32::System::{
        JobObjects::{
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS, SetInformationJobObject, TerminateJobObject,
        },
        Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList,
            EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, InitializeProcThreadAttributeList,
            LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess, PROC_THREAD_ATTRIBUTE_JOB_LIST,
            PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE, ResumeThread,
            STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
        },
    },
    core::PWSTR,
};

const ROOT_TEST: &str = "optimizer_launch_job::tests::owned_root_entry";
const CHILD_TEST: &str = "optimizer_launch_job::tests::owned_descendant_entry";
const MARKER: &str = "DCleaner owned job fixture v1";
fn no_cancel() -> AtomicBool {
    AtomicBool::new(false)
}
fn current_scope() -> (Principal, Caller, Member) {
    let principal = Principal::current().unwrap();
    let caller = Caller::fixture_boot(
        &principal.user_sid().unwrap(),
        principal.session_id(),
        &principal
            .logon_sid()
            .unwrap()
            .expect("interactive fixture login required"),
        principal.boot_id(),
    );
    let member = Member::for_caller(&caller, "program:v1:hkcu:64:66697874757265").unwrap();
    (principal, caller, member)
}
fn duplicate(value: BorrowedHandle<'_>) -> OwnedHandle {
    let mut target = HANDLE::default();
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle(value),
            GetCurrentProcess(),
            &mut target,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .unwrap();
    unsafe { OwnedHandle::from_raw_handle(target.0) }
}
struct Attributes {
    backing: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}
impl Attributes {
    fn new(job: &HANDLE) -> Self {
        let mut bytes = 0;
        let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut bytes) };
        assert!(bytes > 0 && bytes <= 65536);
        let mut backing = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(backing.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(Some(list), 1, None, &mut bytes) }.unwrap();
        let value = Self { backing, list };
        unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                Some((job as *const HANDLE).cast()),
                size_of::<HANDLE>(),
                None,
                None,
            )
        }
        .unwrap();
        value
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list);
        }
        let _ = self.backing.len();
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    cleanup: Option<OwnedHandle>,
    image: Option<fs::File>,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("optimizer-job-fixture-")
            .tempdir()
            .unwrap();
        assert!(dir.path().is_absolute() && dir.path().starts_with(std::env::temp_dir()));
        fs::write(dir.path().join("fixture.marker"), MARKER).unwrap();
        fs::copy(
            std::env::current_exe().unwrap(),
            dir.path().join("worker.exe"),
        )
        .unwrap();
        let image = fs::OpenOptions::new()
            .access_mode(0x8000_0000 | 0x2000_0000)
            .share_mode(windows::Win32::Storage::FileSystem::FILE_SHARE_READ.0)
            .open(dir.path().join("worker.exe"))
            .unwrap();
        Self {
            dir,
            cleanup: None,
            image: Some(image),
        }
    }
    fn marker(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn create(&mut self) -> (PendingJob, OwnedHandle, OwnedHandle) {
        assert!(self.cleanup.is_none());
        let pending = PendingJob::fixture().unwrap();
        self.cleanup = Some(duplicate(pending.for_creation()));
        let job = handle(pending.for_creation());
        let attributes = Attributes::new(&job);
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.list;
        let exe = self.dir.path().join("worker.exe");
        let application: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut command: Vec<u16> = format!(
            "\"{}\" --exact {ROOT_TEST} --ignored --nocapture",
            exe.display()
        )
        .encode_utf16()
        .chain(Some(0))
        .collect();
        let mut process = PROCESS_INFORMATION::default();
        unsafe {
            CreateProcessW(
                PCWSTR(application.as_ptr()),
                Some(PWSTR(command.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                None,
                PCWSTR::null(),
                &startup.StartupInfo,
                &mut process,
            )
        }
        .unwrap();
        // Attribute storage and its borrowed job HANDLE remain alive through
        // creation and are deleted before the pending job is consumed.
        drop(attributes);
        (
            pending,
            unsafe { OwnedHandle::from_raw_handle(process.hProcess.0) },
            unsafe { OwnedHandle::from_raw_handle(process.hThread.0) },
        )
    }
    fn launch(&mut self, member: Member, instance: Uuid, invocation: Uuid) -> LaunchFamily {
        let (pending, root, thread) = self.create();
        let expected = Principal::current().unwrap();
        // Explicit private fixture creation above, with job association before
        // any user code. Synthetic member/catalog binding is fixture-only.
        let family = unsafe {
            pending.admit_owned_root(
                root,
                self.image.as_ref().unwrap().as_handle(),
                &expected,
                member,
                invocation,
                instance,
                &no_cancel(),
            )
        }
        .unwrap();
        assert_eq!(unsafe { ResumeThread(handle(thread.as_handle())) }, 1);
        drop(thread);
        wait(|| self.marker("root.ready").exists());
        family
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(job) = &self.cleanup {
            // Only this fixture's freshly created private job. Production Drop
            // closes handles and never terminates an app or job.
            let _ = unsafe { TerminateJobObject(handle(job.as_handle()), 99) };
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if accounting(job.as_handle()).is_ok_and(|count| count.ActiveProcesses == 0) {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        drop(self.image.take());
    }
}
fn wait(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(6);
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "owned fixture exceeded its bound"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
fn child_root() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let root = exe.parent().unwrap();
    assert!(
        root.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("optimizer-job-fixture-")
    );
    assert_eq!(
        fs::read_to_string(root.join("fixture.marker")).unwrap(),
        MARKER
    );
    root.to_owned()
}
fn bounded_child_wait(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(12);
    while !path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "Private owned job-root entry; invoked only by the bounded parent fixtures"]
fn owned_root_entry() {
    let root = child_root();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
        .creation_flags(CREATE_NO_WINDOW.0)
        .spawn()
        .unwrap();
    fs::write(root.join("child.pid"), child.id().to_string()).unwrap();
    bounded_child_wait(&root.join("child.ready"));
    assert!(root.join("child.ready").exists());
    fs::write(root.join("root.ready"), b"ready").unwrap();
    bounded_child_wait(&root.join("root.exit"));
    // Closing the launcher handle does not stop its still-running child.
    drop(child);
}
#[test]
#[ignore = "Private owned job-descendant entry; invoked only by the bounded parent fixtures"]
fn owned_descendant_entry() {
    let root = child_root();
    fs::write(root.join("child.ready"), b"ready").unwrap();
    bounded_child_wait(&root.join("child.stop"));
}

#[test]
fn native_family_keeps_wake_demand_after_root_exit_and_releases_only_after_descendant_exit() {
    let (_, caller, member) = current_scope();
    let (instance, invocation) = (Uuid::new_v4(), Uuid::new_v4());
    let id = unsafe { ResourceId::from_native(1, b"synthetic owned job resource") }.unwrap();
    let observation = |state: &[u8]| {
        unsafe {
            Observation::from_native(
                id.clone(),
                instance,
                state.to_vec(),
                vec![member.clone()],
                true,
            )
        }
        .unwrap()
    };
    // Synthetic catalog/effect bytes; only process family observations are real
    // native evidence. This is not an installed app association or registry test.
    let mut fixture = Fixture::new();
    let mut catalog =
        Catalog::open(rusqlite::Connection::open(fixture.marker("resources.sqlite3")).unwrap())
            .unwrap();
    catalog
        .register(observation(b"awake"), b"sleeping".to_vec())
        .unwrap();
    let revision = |catalog: &Catalog| catalog.inspect(&id).unwrap().unwrap().revision;
    catalog
        .request(&id, revision(&catalog), &caller, &member, true)
        .unwrap();
    catalog
        .begin_activation(
            &id,
            revision(&catalog),
            &caller,
            &member,
            invocation,
            instance,
        )
        .unwrap();
    let mut family = fixture.launch(member.clone(), instance, invocation);
    let running = family.observe(&no_cancel()).unwrap();
    assert!(!running.root_exited && running.active_processes >= 2 && !running.ended());
    catalog
        .observe_activation(
            &id,
            revision(&catalog),
            family.activation_observation(&no_cancel()).unwrap(),
        )
        .unwrap();
    assert!(
        catalog
            .begin(&id, revision(&catalog), observation(b"awake"))
            .unwrap()
            .is_none()
    );
    fs::write(fixture.marker("root.exit"), b"exit").unwrap();
    let mut root_exited = None;
    wait(|| {
        let Ok(state) = family.observe(&no_cancel()) else {
            return false;
        };
        if state.root_exited {
            root_exited = Some(state);
            true
        } else {
            false
        }
    });
    let still_running = root_exited.unwrap();
    assert!(still_running.active_processes >= 1 && !still_running.ended());
    catalog
        .observe_activation(
            &id,
            revision(&catalog),
            family.activation_observation(&no_cancel()).unwrap(),
        )
        .unwrap();
    assert!(
        catalog
            .begin(&id, revision(&catalog), observation(b"awake"))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        family
            .activation_observation(&AtomicBool::new(true))
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Interrupted
    );
    fs::write(fixture.marker("child.stop"), b"stop").unwrap();
    let mut ended = None;
    wait(|| {
        let Ok(state) = family.observe(&no_cancel()) else {
            return false;
        };
        if state.ended() {
            ended = Some(state);
            true
        } else {
            false
        }
    });
    catalog
        .observe_activation(
            &id,
            revision(&catalog),
            family.activation_observation(&no_cancel()).unwrap(),
        )
        .unwrap();
    let claim = catalog
        .begin(&id, revision(&catalog), observation(b"awake"))
        .unwrap()
        .unwrap();
    assert_eq!(
        catalog.finish(claim, observation(b"sleeping")).unwrap(),
        Phase::Sleeping
    );
    eprintln!(
        "NATIVE_JOB_FAMILY root_exited_active={} final_active={} total={} catalog_waited_for_descendant=true effects=synthetic windows=false physical_input=false",
        still_running.active_processes,
        ended.unwrap().active_processes,
        ended.unwrap().total_processes
    );
}

#[test]
fn wrong_principal_scope_and_cancelled_admission_cannot_bind_an_owned_root() {
    let (principal, caller, member) = current_scope();
    let wrong = Caller::fixture_boot(
        caller.account(),
        principal.session_id() + 1,
        caller.logon_sid().unwrap(),
        caller.boot_id().unwrap(),
    );
    let wrong_member = Member::for_caller(&wrong, "program:v1:hkcu:64:66697874757265").unwrap();
    for (member, cancelled) in [(wrong_member, false), (member, true)] {
        let mut fixture = Fixture::new();
        let (pending, root, thread) = fixture.create();
        let result = unsafe {
            pending.admit_owned_root(
                root,
                fixture.image.as_ref().unwrap().as_handle(),
                &principal,
                member,
                Uuid::new_v4(),
                Uuid::new_v4(),
                &AtomicBool::new(cancelled),
            )
        };
        assert!(result.is_err());
        drop(thread);
    }
}

#[test]
fn changed_native_job_limits_refuse_lifetime_and_activation_observations() {
    let (_, _, member) = current_scope();
    let mut fixture = Fixture::new();
    let mut family = fixture.launch(member, Uuid::new_v4(), Uuid::new_v4());
    let job = handle(fixture.cleanup.as_ref().unwrap().as_handle());
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit = 8;
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of_val(&limits) as u32,
        )
    }
    .unwrap();
    assert!(family.observe(&no_cancel()).is_err());
    let reset = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&reset as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of_val(&reset) as u32,
        )
    }
    .unwrap();
    // Equal current limits cannot erase an observed gap in family coverage.
    assert!(family.activation_observation(&no_cancel()).is_err());
    // Fixture teardown terminates only the test-owned job, not a real app.
}

#[test]
fn a_root_from_another_owned_job_cannot_be_admitted() {
    let (principal, _, member) = current_scope();
    let mut first = Fixture::new();
    let (pending, first_root, first_thread) = first.create();
    let mut second = Fixture::new();
    let (_second_job, second_root, second_thread) = second.create();
    let result = unsafe {
        pending.admit_owned_root(
            second_root,
            first.image.as_ref().unwrap().as_handle(),
            &principal,
            member,
            Uuid::new_v4(),
            Uuid::new_v4(),
            &no_cancel(),
        )
    };
    assert!(result.is_err());
    drop((first_root, first_thread, second_thread));
}

#[test]
fn a_byte_identical_other_image_cannot_bind_the_owned_invocation() {
    let (principal, _, member) = current_scope();
    let mut source = Fixture::new();
    let (pending, root, thread) = source.create();
    // Both fixtures copy the same currently running Rust image, but retain
    // distinct native files. Matching bytes/name are insufficient admission.
    let other = Fixture::new();
    let result = unsafe {
        pending.admit_owned_root(
            root,
            other.image.as_ref().unwrap().as_handle(),
            &principal,
            member,
            Uuid::new_v4(),
            Uuid::new_v4(),
            &no_cancel(),
        )
    };
    assert_eq!(
        result.err().expect("other image must be refused").kind(),
        io::ErrorKind::PermissionDenied
    );
    drop(thread);
}

#[test]
fn a_native_query_denial_cannot_release_the_invocation() {
    let (_, _, member) = current_scope();
    let mut fixture = Fixture::new();
    let mut family = fixture.launch(member, Uuid::new_v4(), Uuid::new_v4());
    let mut raw = HANDLE::default();
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle(family.job.as_handle()),
            GetCurrentProcess(),
            &mut raw,
            0, // Deliberately remove every access right from this duplicate.
            false,
            windows::Win32::Foundation::DUPLICATE_HANDLE_OPTIONS(0),
        )
    }
    .unwrap();
    let restricted = unsafe { OwnedHandle::from_raw_handle(raw.0) };
    drop(std::mem::replace(&mut family.job, restricted));
    assert_eq!(
        family.observe(&no_cancel()).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        family
            .activation_observation(&no_cancel())
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}

struct ChildCleanup(OwnedHandle);
impl Drop for ChildCleanup {
    fn drop(&mut self) {
        if unsafe { WaitForSingleObject(handle(self.0.as_handle()), 0) } == WAIT_TIMEOUT {
            let _ = unsafe { TerminateProcess(handle(self.0.as_handle()), 99) };
            unsafe {
                WaitForSingleObject(handle(self.0.as_handle()), 3000);
            }
        }
    }
}
#[test]
fn closing_the_last_family_job_handle_does_not_kill_the_owned_descendant() {
    let (_, _, member) = current_scope();
    let mut fixture = Fixture::new();
    let mut family = fixture.launch(member, Uuid::new_v4(), Uuid::new_v4());
    let child_pid: u32 = fs::read_to_string(fixture.marker("child.pid"))
        .unwrap()
        .parse()
        .unwrap();
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION
                | PROCESS_SYNCHRONIZE
                | windows::Win32::System::Threading::PROCESS_TERMINATE,
            false,
            child_pid,
        )
    }
    .unwrap();
    let child = ChildCleanup(unsafe { OwnedHandle::from_raw_handle(raw.0) });
    let mut in_job = BOOL(0);
    unsafe {
        IsProcessInJob(
            handle(child.0.as_handle()),
            Some(handle(family.job.as_handle())),
            &mut in_job,
        )
    }
    .unwrap();
    assert!(in_job.as_bool());
    fs::write(fixture.marker("root.exit"), b"exit").unwrap();
    wait(|| {
        family
            .observe(&no_cancel())
            .is_ok_and(|state| state.root_exited)
    });
    drop(fixture.cleanup.take());
    drop(family);
    assert_eq!(
        unsafe { WaitForSingleObject(handle(child.0.as_handle()), 0) },
        WAIT_TIMEOUT
    );
    fs::write(fixture.marker("child.stop"), b"stop").unwrap();
    assert_eq!(
        unsafe { WaitForSingleObject(handle(child.0.as_handle()), 6000) },
        WAIT_OBJECT_0
    );
}

#[test]
fn service_job_creation_refuses_a_non_system_owner_before_creating_a_job() {
    if Principal::current().unwrap().user_sid().unwrap() != "S-1-5-18" {
        assert_eq!(
            PendingJob::for_service()
                .err()
                .expect("interactive user cannot create service ownership")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        eprintln!("SERVICE_JOB_OWNER interactive_owner_refused=true job_created=false");
    }
}
