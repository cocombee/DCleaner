//! Protected storage for the Windows optimizer owner. SQLite can recover its
//! rollback journal or migrate its schema on open. Native epoch admission checks
//! a recorded predecessor before SQL; a file lock alone never proves process
//! death. Opening never replays optimizer side effects.
#![allow(dead_code)] // The production service owner is not connected yet.

pub(crate) mod epoch;

use crate::{
    optimizer_intents::Journal,
    optimizer_pipe_security::{Descriptor, Principal},
    optimizer_requests::Ledger,
    optimizer_resources::Catalog,
};
use rusqlite::{Connection, OpenFlags};
use std::{
    fs::File,
    io,
    mem::size_of,
    os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
    path::{Path, PathBuf},
};
use windows::{
    Win32::{
        Foundation::{ERROR_ALREADY_EXISTS, GENERIC_READ, GENERIC_WRITE, HANDLE},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_READ_ATTRIBUTES, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            GetFileInformationByHandle, OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL,
        },
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
    },
    core::{BOOL, PCWSTR},
};

const REQUEST_DB: &str = "requests.sqlite3";
const INTENT_DB: &str = "intents.sqlite3";
const RESOURCE_DB: &str = "resources.sqlite3";
const LOCK_FILE: &str = "owner.lock";
const REQUEST_LIMIT: u64 = 16 * 1024 * 1024;
const INTENT_LIMIT: u64 = 64 * 1024 * 1024;
const RESOURCE_LIMIT: u64 = crate::optimizer_resources::MAX_DB_BYTES;
const JOURNAL_LIMIT: u64 = 128 * 1024 * 1024;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn native(error: windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error((error.code().0 as u32 & 0xffff) as i32)
}
fn wide(path: &Path) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    if !path.is_absolute() {
        return Err(invalid(
            "Optimizer storage requires an absolute local path.",
        ));
    }
    let value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) || value.len() > 30_000 || value.starts_with(&[92, 92]) {
        return Err(invalid(
            "Optimizer storage path is not a bounded local DOS path.",
        ));
    }
    Ok(value.into_iter().chain(Some(0)).collect())
}

struct Access {
    directory: Descriptor,
    file: Descriptor,
}
impl Access {
    fn system() -> io::Result<Self> {
        Self::for_owner(
            "S-1-5-18",
            "(A;OICI;0x001200A9;;;BA)",
            "(A;;0x001200A9;;;BA)",
        )
    }
    fn for_owner(owner: &str, directory_extra: &str, file_extra: &str) -> io::Result<Self> {
        Ok(Self {
            directory: Descriptor::from_sddl(&format!(
                "O:{owner}D:P(A;OICI;FA;;;{owner}){directory_extra}"
            ))?,
            file: Descriptor::from_sddl(&format!("O:{owner}D:P(A;;FA;;;{owner}){file_extra}"))?,
        })
    }
    #[cfg(test)]
    fn fixture() -> io::Result<Self> {
        // Files this process creates (including SQLite journals) take the token
        // default owner, which is Administrators on elevated hosts.
        let owner = Principal::default_owner_sid()?;
        Self::for_owner(&owner, "(A;OICI;FA;;;SY)", "(A;;FA;;;SY)")
    }
}

fn attributes(descriptor: &Descriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.native().0,
        bInheritHandle: BOOL(0),
    }
}

fn open(
    path: &Path,
    directory: bool,
    create: bool,
    exclusive: bool,
    descriptor: Option<&Descriptor>,
) -> io::Result<File> {
    let share = if exclusive {
        FILE_SHARE_MODE(0)
    } else if directory {
        FILE_SHARE_READ
    } else {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    };
    open_shared(path, directory, create, share, descriptor)
}

fn open_shared(
    path: &Path,
    directory: bool,
    create: bool,
    share: FILE_SHARE_MODE,
    descriptor: Option<&Descriptor>,
) -> io::Result<File> {
    let path = wide(path)?;
    let attributes = descriptor.map(attributes);
    let desired = if directory {
        READ_CONTROL.0 | FILE_READ_ATTRIBUTES.0
    } else {
        GENERIC_READ.0 | GENERIC_WRITE.0 | READ_CONTROL.0
    };
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            Default::default()
        };
    // No truncate/delete-on-close disposition and no inheritable handle.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            desired,
            share,
            attributes.as_ref().map(|value| value as *const _),
            if create { OPEN_ALWAYS } else { OPEN_EXISTING },
            flags,
            None,
        )
    }
    .map_err(native)?;
    let owned = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    Ok(File::from(owned))
}

fn inspect(file: &File, directory: bool, limit: u64) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
        .map_err(native)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0) != directory
    {
        return Err(invalid(
            "Optimizer storage contains a redirected or wrong-kind object.",
        ));
    }
    if !directory && info.nNumberOfLinks != 1 {
        return Err(invalid(
            "Optimizer storage file must have exactly one hard link.",
        ));
    }
    let bytes = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
    if !directory && bytes > limit {
        return Err(invalid("Optimizer storage file exceeds its size bound."));
    }
    Ok(())
}

fn verify(file: &File, access: &Access, directory: bool, limit: u64) -> io::Result<()> {
    inspect(file, directory, limit)?;
    Descriptor::from_file(file.as_handle())?.verify_file(if directory {
        &access.directory
    } else {
        &access.file
    })
}

fn protected_directory(path: &Path, access: &Access) -> io::Result<File> {
    let name = wide(path)?;
    let attributes = attributes(&access.directory);
    if let Err(error) = unsafe { CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&attributes)) } {
        if error.code() != ERROR_ALREADY_EXISTS.to_hresult() {
            return Err(native(error));
        }
    }
    let file = open(path, true, false, false, None)?;
    verify(&file, access, true, 0)?;
    Ok(file)
}

fn known_program_data() -> io::Result<PathBuf> {
    let value = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
        .map_err(native)?;
    let result = unsafe { value.to_string() }
        .map(PathBuf::from)
        .map_err(io::Error::other);
    unsafe { CoTaskMemFree(Some(value.0.cast())) };
    let path = result?;
    wide(&path)?;
    Ok(path)
}

/// Connections drop before held files and directory handles. None of these
/// handles is inherited or shares delete access. The lock is not a process-death
/// proof and must never be passed to interrupted-operation recovery as one.
pub(crate) struct Storage {
    pub(crate) requests: Ledger,
    pub(crate) intents: Journal,
    pub(crate) resources: Catalog,
    epoch: Option<epoch::Admission>,
    _database_files: Vec<File>,
    _owner_lock: File,
    _directories: Vec<File>,
}
impl Storage {
    fn for_service() -> io::Result<Self> {
        Principal::require_local_system()?;
        let base = known_program_data()?;
        // Pin this namespace against replacement without blocking unrelated
        // writers to the OS-wide ProgramData directory.
        let parent = open_shared(&base, true, false, FILE_SHARE_READ | FILE_SHARE_WRITE, None)?;
        inspect(&parent, true, 0)?;
        let access = Access::system()?;
        // The OS-owned known-folder base is trusted configuration. Each new
        // descendant must independently match the exact protected descriptor.
        let namespace = base.join("DCleaner");
        let namespace_handle = protected_directory(&namespace, &access)?;
        let root = namespace.join("Optimizer");
        let root_handle = protected_directory(&root, &access)?;
        Self::inside_impl(
            root,
            access,
            vec![parent, namespace_handle, root_handle],
            true,
        )
    }

    #[cfg(test)]
    fn inside(root: PathBuf, access: Access, directories: Vec<File>) -> io::Result<Self> {
        Self::inside_impl(root, access, directories, false)
    }

    fn inside_impl(
        root: PathBuf,
        access: Access,
        directories: Vec<File>,
        runtime: bool,
    ) -> io::Result<Self> {
        // OPEN_ALWAYS preserves an existing file. Verify it before opening SQL
        // or modifying bytes; a conflicting owner is never repaired/adopted.
        let owner_lock = open(&root.join(LOCK_FILE), false, true, true, Some(&access.file))?;
        verify(&owner_lock, &access, false, 0)?;
        let names: Vec<_> = std::fs::read_dir(&root)?
            .take(9)
            .collect::<Result<_, _>>()?;
        if names.len() > 8 {
            return Err(invalid("Optimizer storage has too many entries."));
        }
        for entry in names {
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| invalid("Unrecognized optimizer storage entry."))?;
            if name == LOCK_FILE {
                continue;
            }
            let limit = match name {
                REQUEST_DB => REQUEST_LIMIT,
                INTENT_DB => INTENT_LIMIT,
                RESOURCE_DB => RESOURCE_LIMIT,
                epoch::RECORD_FILE => epoch::MAX_RECORD_BYTES,
                "requests.sqlite3-journal"
                | "intents.sqlite3-journal"
                | "resources.sqlite3-journal" => JOURNAL_LIMIT,
                _ => {
                    return Err(invalid(
                        "Unexpected optimizer storage entry; no migration or recovery was attempted.",
                    ));
                }
            };
            let file = open(&entry.path(), false, false, false, None)?;
            if name.ends_with("-journal") {
                inspect(&file, false, limit)?;
                Descriptor::from_file(file.as_handle())?.verify_journal(&access.file)?;
            } else {
                verify(&file, &access, false, limit)?;
            }
        }
        // Native epoch admission happens before SQLite can recover a journal or
        // migrate a schema. A live, unknown or corrupt predecessor is refused.
        let epoch = if runtime {
            Some(epoch::admit(&root, &access)?)
        } else {
            None
        };
        let mut files = Vec::new();
        for (name, limit) in [
            (REQUEST_DB, REQUEST_LIMIT),
            (INTENT_DB, INTENT_LIMIT),
            (RESOURCE_DB, RESOURCE_LIMIT),
        ] {
            let file = open(&root.join(name), false, true, false, Some(&access.file))?;
            verify(&file, &access, false, limit)?;
            files.push(file);
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let requests = Ledger::open(
            Connection::open_with_flags(root.join(REQUEST_DB), flags).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        let intents = Journal::open(
            Connection::open_with_flags(root.join(INTENT_DB), flags).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        let resources = Catalog::open(
            Connection::open_with_flags(root.join(RESOURCE_DB), flags).map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?;
        for (file, limit) in files
            .iter()
            .zip([REQUEST_LIMIT, INTENT_LIMIT, RESOURCE_LIMIT])
        {
            verify(file, &access, false, limit)?;
        }
        Ok(Self {
            requests,
            intents,
            resources,
            epoch,
            _database_files: files,
            _owner_lock: owner_lock,
            _directories: directories,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::{
        Security::{
            ACL,
            Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW},
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
            PROTECTED_DACL_SECURITY_INFORMATION,
        },
        Storage::FileSystem::FILE_SHARE_DELETE,
    };

    fn fixture(parent: &Path) -> io::Result<(PathBuf, Access, Vec<File>)> {
        let access = Access::fixture()?;
        let root = parent.join("protected-optimizer");
        let held = protected_directory(&root, &access)?;
        Ok((root, access, vec![held]))
    }
    fn loosen_dacl(path: &Path) {
        let owner = Principal::default_owner_sid().unwrap();
        let descriptor =
            Descriptor::from_sddl(&format!("O:{owner}D:P(A;;FA;;;{owner})(A;;FR;;;WD)")).unwrap();
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut acl: *mut ACL = std::ptr::null_mut();
        unsafe {
            GetSecurityDescriptorDacl(descriptor.native(), &mut present, &mut acl, &mut defaulted)
        }
        .unwrap();
        let name = wide(path).unwrap();
        unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(name.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(acl),
                None,
            )
        }
        .ok()
        .unwrap();
    }

    #[test]
    fn native_storage_initializes_all_ledgers_and_excludes_second_owner_and_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let (root, access, held) = fixture(temp.path()).unwrap();
        let owner = Storage::inside(root.clone(), access, held).unwrap();
        let (same, access, held) = fixture(temp.path()).unwrap();
        assert!(Storage::inside(same, access, held).is_err());
        for name in [REQUEST_DB, INTENT_DB, RESOURCE_DB] {
            assert!(std::fs::rename(root.join(name), root.join("moved.sqlite3")).is_err());
            assert!(std::fs::remove_file(root.join(name)).is_err());
        }
        assert!(std::fs::rename(&root, temp.path().join("moved-root")).is_err());
        drop(owner);
        let (same, access, held) = fixture(temp.path()).unwrap();
        let reopened = Storage::inside(same, access, held).unwrap();
        drop(reopened);
    }

    #[test]
    fn native_pinned_storage_retains_lease_selected_image_without_launch_authority() {
        use crate::{
            optimizer_identity,
            optimizer_requests::Caller,
            optimizer_resources::{Member, Observation, ResourceId, leases::Selection},
        };
        use std::sync::atomic::AtomicBool;
        let temp = tempfile::tempdir().unwrap();
        let (root, access, held) = fixture(temp.path()).unwrap();
        let mut storage = Storage::inside(root.clone(), access, held).unwrap();
        let principal = Principal::current().unwrap();
        // Native file/storage observations; the caller/association below remain
        // explicit fixtures, not authenticated IPC or app ownership evidence.
        let caller = Caller::fixture_boot(
            &principal.user_sid().unwrap(),
            principal.session_id(),
            &principal.logon_sid().unwrap().unwrap(),
            principal.boot_id(),
        );
        let member = Member::for_caller(&caller, "program:v1:hkcu:64:6c65617365").unwrap();
        let id =
            unsafe { ResourceId::from_native(1, b"synthetic pinned-storage association") }.unwrap();
        let instance = uuid::Uuid::new_v4();
        let observation = unsafe {
            Observation::from_native(
                id.clone(),
                instance,
                b"baseline".to_vec(),
                vec![member.clone()],
                true,
            )
        }
        .unwrap();
        storage
            .resources
            .register(observation, b"sleeping".to_vec())
            .unwrap();
        let cancel = AtomicBool::new(false);
        let image =
            optimizer_identity::inspect(&std::env::current_exe().unwrap(), &cancel).unwrap();
        let lease = uuid::Uuid::new_v4();
        let revision = uuid::Uuid::new_v4();
        let selection = Selection::from_owner_selection(
            &caller,
            member,
            lease,
            revision,
            vec![image.clone()],
            vec![id],
        )
        .unwrap();
        storage
            .resources
            .register_lease(&caller, selection)
            .unwrap();
        assert!(std::fs::rename(root.join(RESOURCE_DB), root.join("replaced.sqlite3")).is_err());
        drop(storage);
        let (same, access, held) = fixture(temp.path()).unwrap();
        let reopened = Storage::inside(same, access, held).unwrap();
        let selected = reopened
            .resources
            .lease_selection(&caller, lease)
            .unwrap()
            .unwrap();
        assert_eq!(selected.revision(), revision);
        assert_eq!(selected.images(), &[image.clone()]);
        assert_eq!(
            optimizer_identity::revalidate(&image, &cancel).unwrap(),
            image
        );
        assert_eq!(
            reopened
                .resources
                .inspect(&selected.resources()[0])
                .unwrap()
                .unwrap()
                .phase,
            crate::optimizer_resources::Phase::Awake
        );
    }

    #[test]
    fn native_storage_rejects_foreign_access_without_rewriting_database() {
        for name in [REQUEST_DB, INTENT_DB, RESOURCE_DB] {
            let temp = tempfile::tempdir().unwrap();
            let (root, access, held) = fixture(temp.path()).unwrap();
            drop(Storage::inside(root.clone(), access, held).unwrap());
            let original = std::fs::read(root.join(name)).unwrap();
            loosen_dacl(&root.join(name));
            let (same, access, held) = fixture(temp.path()).unwrap();
            assert!(Storage::inside(same, access, held).is_err());
            assert_eq!(std::fs::read(root.join(name)).unwrap(), original);
        }
    }

    #[test]
    fn native_storage_rejects_unexpected_sidecars_and_hard_linked_databases() {
        let temp = tempfile::tempdir().unwrap();
        let (root, access, held) = fixture(temp.path()).unwrap();
        drop(Storage::inside(root.clone(), access, held).unwrap());
        let original = std::fs::read(root.join(REQUEST_DB)).unwrap();
        std::fs::hard_link(root.join(REQUEST_DB), temp.path().join("second-link")).unwrap();
        let (same, access, held) = fixture(temp.path()).unwrap();
        assert!(Storage::inside(same, access, held).is_err());
        std::fs::remove_file(temp.path().join("second-link")).unwrap();
        std::fs::write(root.join("requests.sqlite3-wal"), b"do not adopt").unwrap();
        let (same, access, held) = fixture(temp.path()).unwrap();
        assert!(Storage::inside(same, access, held).is_err());
        assert_eq!(std::fs::read(root.join(REQUEST_DB)).unwrap(), original);
        assert_eq!(
            std::fs::read(root.join("requests.sqlite3-wal")).unwrap(),
            b"do not adopt"
        );
    }

    #[test]
    fn native_storage_rejects_wrong_kinds_and_oversized_files_before_sql() {
        let temp = tempfile::tempdir().unwrap();
        let (root, access, held) = fixture(temp.path()).unwrap();
        let oversized = open(
            &root.join(REQUEST_DB),
            false,
            true,
            false,
            Some(&access.file),
        )
        .unwrap();
        oversized.set_len(REQUEST_LIMIT + 1).unwrap();
        drop(oversized);
        assert!(Storage::inside(root.clone(), access, held).is_err());
        std::fs::remove_file(root.join(REQUEST_DB)).unwrap();
        std::fs::create_dir(root.join(REQUEST_DB)).unwrap();
        let (same, access, held) = fixture(temp.path()).unwrap();
        assert!(Storage::inside(same, access, held).is_err());
    }

    #[test]
    fn native_storage_requires_protected_databases_and_lock_but_accepts_exact_inherited_journal() {
        for name in [REQUEST_DB, LOCK_FILE] {
            let temp = tempfile::tempdir().unwrap();
            let (root, access, held) = fixture(temp.path()).unwrap();
            // An otherwise exact inherited DACL is valid for SQLite-created
            // journals, but never for the explicitly protected DB or lock.
            std::fs::write(root.join(name), []).unwrap();
            let bytes = std::fs::read(root.join(name)).unwrap();
            assert!(Storage::inside(root.clone(), access, held).is_err());
            assert_eq!(std::fs::read(root.join(name)).unwrap(), bytes);
        }
        let temp = tempfile::tempdir().unwrap();
        let (root, access, held) = fixture(temp.path()).unwrap();
        let path = root.join("requests.sqlite3-journal");
        std::fs::write(&path, [0; 512]).unwrap();
        let journal = open(&path, false, false, false, None).unwrap();
        let descriptor = Descriptor::from_file(journal.as_handle()).unwrap();
        descriptor.verify_journal(&access.file).unwrap();
        assert!(descriptor.verify_file(&access.file).is_err());
        drop(journal);
        drop(Storage::inside(root, access, held).unwrap());
    }

    #[test]
    fn native_storage_refuses_foreign_root_and_nonempty_owner_lock() {
        let temp = tempfile::tempdir().unwrap();
        let (root, access, held) = fixture(temp.path()).unwrap();
        let lock = open(
            &root.join(LOCK_FILE),
            false,
            true,
            false,
            Some(&access.file),
        )
        .unwrap();
        lock.set_len(1).unwrap();
        drop(lock);
        assert!(Storage::inside(root.clone(), access, held).is_err());
        assert_eq!(std::fs::metadata(root.join(LOCK_FILE)).unwrap().len(), 1);
        loosen_dacl(&root);
        assert!(fixture(temp.path()).is_err());
        assert_eq!(std::fs::metadata(root.join(LOCK_FILE)).unwrap().len(), 1);
    }

    #[test]
    fn production_storage_refuses_non_system_before_provisioning() {
        if Principal::current().unwrap().user_sid().unwrap() != "S-1-5-18" {
            assert_eq!(
                Storage::for_service().err().unwrap().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                epoch::RuntimeOwner::for_service().err().unwrap().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        // FILE_SHARE_DELETE is deliberately absent from all owner handles.
        assert_ne!(
            (FILE_SHARE_READ | FILE_SHARE_WRITE).0,
            (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0
        );
    }
}
