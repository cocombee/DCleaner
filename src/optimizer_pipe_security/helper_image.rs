//! Retained protected helper-file and native process observations. These are
//! prerequisites, not lease/launch authority or proof against same-user process
//! injection/duplicated pipe handles. No effect permit or readiness is produced.
use super::*;
use crate::optimizer_identity::{self, ImageSnapshot};
use std::{
    fs::File,
    os::windows::io::AsHandle,
    path::{Path, PathBuf},
    sync::Arc,
};
use windows::Win32::{
    Foundation::{FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_EXECUTE, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAGS_AND_ATTRIBUTES, FILE_ID_INFO, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
    },
    System::Threading::{
        GetCurrentProcessId, GetProcessId, GetProcessTimes, OpenProcess, PROCESS_QUERY_INFORMATION,
        PROCESS_SYNCHRONIZE, WaitForSingleObject,
    },
};

fn image_error(error: optimizer_identity::ImageError) -> io::Error {
    use optimizer_identity::ImageErrorKind as K;
    let kind = match error.kind {
        K::Cancelled => io::ErrorKind::Interrupted,
        K::AccessDenied => io::ErrorKind::PermissionDenied,
        K::Busy => io::ErrorKind::WouldBlock,
        K::NotFound => io::ErrorKind::NotFound,
        K::UnsupportedPlatform => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(
        kind,
        format!(
            "Helper image {:?} (native {:?}): {}",
            error.kind, error.native_code, error.message
        ),
    )
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        process: *mut c_void,
        class: u32,
        input: *mut c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
}

// Positive observation only. An error is not proof that no matching process
// exists; read-only telemetry must preserve that limitation too.
pub(crate) fn mapped_image(
    process: BorrowedHandle<'_>,
    image: BorrowedHandle<'_>,
) -> io::Result<()> {
    let mut file = image.as_raw_handle();
    // ProcessImageFileMapping (44) takes a file HANDLE as INPUT. It compares the
    // process's executable file object, rather than resolving an image pathname.
    // Private NT interface; any unsupported/negative result refuses the match.
    // https://github.com/winsiderss/phnt/blob/master/ntpsapi.h
    let status = unsafe {
        NtQueryInformationProcess(
            process.as_raw_handle(),
            44,
            (&mut file as *mut *mut c_void).cast(),
            size_of::<*mut c_void>() as u32,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(denied(
            "Process is not mapped from the retained helper file, or native comparison is unavailable.",
        ));
    }
    Ok(())
}

fn file_info(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
        .map_err(native)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(denied("Helper path contains a reparse point."));
    }
    Ok(info)
}
fn identity(info: &BY_HANDLE_FILE_INFORMATION) -> (u32, u32, u32) {
    (
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    )
}
fn same_image_file(file: &File, image: &ImageSnapshot) -> io::Result<()> {
    let mut id = FILE_ID_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(native)?;
    if id.VolumeSerialNumber != image.identity.volume_serial
        || id.FileId.Identifier != image.identity.file_id
    {
        return Err(denied(
            "Helper snapshot does not describe the retained file.",
        ));
    }
    Ok(())
}
fn check_descriptor(desc: &Descriptor, access: &RegistryAccess, namespace: bool) -> io::Result<()> {
    if !access.trusted.contains(&desc.owner()?) {
        return Err(denied("Helper path has an untrusted owner."));
    }
    for ace in desc.acl_bytes(false, false)? {
        if ace[1] & !0x1f != 0 {
            return Err(denied("Unsupported helper ACE flags."));
        }
        if ace[1] & 0x08 != 0 || ace[0] == 1 {
            continue;
        }
        if ace[0] != 0 || ace.len() < 16 {
            return Err(denied("Unsupported helper access ACE."));
        }
        let mask = u32::from_le_bytes(
            ace[4..8]
                .try_into()
                .map_err(|_| invalid("Invalid helper access mask."))?,
        );
        if mask & !0xf11f_01ff != 0 {
            return Err(denied("Unsupported helper access mask."));
        }
        // Fixed ancestors may allow creation of unrelated children. Every
        // existing child is independently pinned/checked. The actual helper
        // directory also rejects add-file/subdirectory rights (DLL planting).
        let mutation = if namespace { 0x000d_0150 } else { 0x000d_0156 };
        if mask & (mutation | 0x5000_0000) == 0 {
            continue;
        }
        let mut aligned = vec![0u32; ace.len().div_ceil(4)];
        unsafe {
            ptr::copy_nonoverlapping(ace.as_ptr(), aligned.as_mut_ptr().cast::<u8>(), ace.len());
        }
        let sid = unsafe { Sid::copy(PSID(aligned.as_mut_ptr().add(2).cast()), ace.len() - 8) }?;
        let creator = sid == access.creator_owner && ace[1] & 0x03 != 0;
        if !access.trusted.contains(&sid) && !creator {
            return Err(denied(
                "Helper path grants mutation to an untrusted principal.",
            ));
        }
    }
    Ok(())
}
fn open(path: &Path, directory: bool) -> io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    let mut path: Vec<u16> = path.as_os_str().encode_wide().collect();
    if path.len() > 30_000 || path.contains(&0) || path.len() < 3 || path[1] != 58 || path[2] != 92
    {
        return Err(invalid(
            "Helper requires a bounded absolute local DOS path.",
        ));
    }
    path.push(0);
    let rights = READ_CONTROL.0
        | FILE_READ_ATTRIBUTES.0
        | SYNCHRONIZE.0
        | if directory {
            0
        } else {
            FILE_READ_DATA.0 | FILE_EXECUTE.0
        };
    let share = if directory {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    } else {
        FILE_SHARE_READ
    };
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            FILE_FLAGS_AND_ATTRIBUTES(0)
        };
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            rights,
            share,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(native)?;
    let file = unsafe { File::from_raw_handle(handle.0) };
    let info = file_info(&file)?;
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(denied("Helper path kind or hard-link count is invalid."));
    }
    Ok(file)
}

struct DirectoryPin {
    path: PathBuf,
    file: File,
    id: (u32, u32, u32),
    namespace: bool,
}
pub(crate) struct ProtectedHelper {
    file: File,
    image: ImageSnapshot,
    directories: Vec<DirectoryPin>,
    access: RegistryAccess,
}
impl ProtectedHelper {
    /// Only the fixed machine install and the same mapped service executable
    /// can bootstrap helper identity. No client path/hash/publisher is accepted.
    /// Packaging and complete authorized helper dispatch remain separate gates.
    pub(crate) fn for_service(cancel: &AtomicBool) -> io::Result<Arc<Self>> {
        use windows::Win32::{
            System::Com::CoTaskMemFree,
            UI::Shell::{FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
        };
        Principal::require_local_system()?;
        let folder = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None) }
            .map_err(native)?;
        let path = unsafe { folder.to_string() };
        unsafe {
            CoTaskMemFree(Some(folder.0.cast()));
        }
        let root =
            PathBuf::from(path.map_err(|_| invalid("Program Files path is not representable."))?)
                .join("DCleaner");
        let image = Self::capture(
            &root.join("DCleaner.exe"),
            None,
            RegistryAccess::machine()?,
            cancel,
        )?;
        let process = process_handle(unsafe { GetCurrentProcessId() })?;
        mapped_image(process.as_handle(), image.file.as_handle())?;
        Ok(Arc::new(image))
    }

    /// Desired debugger command data only, never registry/effect authority.
    /// Revalidate the retained file/directory pins before using their path;
    /// lease ownership and complete helper readiness remain independent gates.
    pub(crate) fn debugger_prefix(
        &self,
        lease: uuid::Uuid,
        cancel: &AtomicBool,
    ) -> io::Result<Vec<u16>> {
        self.revalidate(cancel)?;
        crate::optimizer_helper::debugger_prefix(&self.image.final_path, lease)
    }
    fn capture(
        path: &Path,
        fixture_root: Option<&Path>,
        access: RegistryAccess,
        cancel: &AtomicBool,
    ) -> io::Result<Self> {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Helper inspection cancelled.",
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| invalid("Helper has no parent directory."))?;
        let mut paths: Vec<_> = parent.ancestors().map(Path::to_path_buf).collect();
        paths.reverse();
        if let Some(root) = fixture_root {
            paths.retain(|p| p.starts_with(root));
        }
        if paths.is_empty() || paths.len() > 64 {
            return Err(invalid("Helper directory chain is incomplete or too deep."));
        }
        let mut directories = Vec::new();
        for directory in paths {
            let file = open(&directory, true)?;
            let info = file_info(&file)?;
            let namespace = directory != parent;
            check_descriptor(
                &Descriptor::from_file(file.as_handle())?,
                &access,
                namespace,
            )?;
            directories.push(DirectoryPin {
                path: directory,
                file,
                id: identity(&info),
                namespace,
            });
        }
        let file = open(path, false)?;
        check_descriptor(&Descriptor::from_file(file.as_handle())?, &access, false)?;
        let image = optimizer_identity::inspect(path, cancel).map_err(image_error)?;
        same_image_file(&file, &image)?;
        let info = file_info(&file)?;
        if image.hard_links != 1 || image.size == 0 || info.nNumberOfLinks != 1 {
            return Err(denied("Helper file is not exclusive to its native name."));
        }
        let value = Self {
            file,
            image,
            directories,
            access,
        };
        value.revalidate(cancel)?;
        Ok(value)
    }
    pub(crate) fn revalidate(&self, cancel: &AtomicBool) -> io::Result<()> {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Helper inspection cancelled.",
            ));
        }
        for pin in &self.directories {
            let reopened = open(&pin.path, true)?;
            if identity(&file_info(&pin.file)?) != pin.id
                || identity(&file_info(&reopened)?) != pin.id
            {
                return Err(denied("Helper directory identity changed."));
            }
            check_descriptor(
                &Descriptor::from_file(pin.file.as_handle())?,
                &self.access,
                pin.namespace,
            )?;
        }
        let info = file_info(&self.file)?;
        same_image_file(&self.file, &self.image)?;
        if info.nNumberOfLinks != 1 {
            return Err(denied("Helper gained a hard-link alias."));
        }
        check_descriptor(
            &Descriptor::from_file(self.file.as_handle())?,
            &self.access,
            false,
        )?;
        optimizer_identity::revalidate(&self.image, cancel).map_err(image_error)?;
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn fixture(path: &Path, root: &Path, cancel: &AtomicBool) -> io::Result<Arc<Self>> {
        if !path.starts_with(root) {
            return Err(invalid("Fixture path escapes its private root."));
        }
        Ok(Arc::new(Self::capture(
            path,
            Some(root),
            RegistryAccess::fixture()?,
            cancel,
        )?))
    }
}

fn process_handle(pid: u32) -> io::Result<OwnedHandle> {
    if pid <= 4 {
        return Err(denied("Helper process ID is invalid."));
    }
    let value = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SYNCHRONIZE, false, pid) }
        .map_err(native)?;
    Ok(unsafe { OwnedHandle::from_raw_handle(value.0) })
}
fn creation(process: BorrowedHandle<'_>) -> io::Result<u64> {
    let mut start = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(
            HANDLE(process.as_raw_handle()),
            &mut start,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .map_err(native)?;
    let value = (u64::from(start.dwHighDateTime) << 32) | u64::from(start.dwLowDateTime);
    if value == 0 {
        return Err(invalid("Helper process creation time is unavailable."));
    }
    Ok(value)
}
fn alive(process: BorrowedHandle<'_>) -> io::Result<()> {
    match unsafe { WaitForSingleObject(HANDLE(process.as_raw_handle()), 0) } {
        WAIT_TIMEOUT => Ok(()),
        WAIT_OBJECT_0 => Err(denied("Helper process exited.")),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Native connection/process/file context, never deserializable or rebuildable
/// from a saved PID. The caller must separately bind the service-owned launch
/// incarnation; a pipe creator PID alone does not prove the message's writer.
pub(crate) struct HelperProcess {
    process: OwnedHandle,
    pid: u32,
    created: u64,
    principal: Principal,
    helper: Arc<ProtectedHelper>,
}
impl HelperProcess {
    pub(crate) fn observe(
        policy: &Policy,
        request: &AuthenticatedRequest,
        pipe: BorrowedHandle<'_>,
        helper: Arc<ProtectedHelper>,
        cancel: &AtomicBool,
    ) -> io::Result<Self> {
        use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
        let authenticated = policy.authenticate_client(pipe)?;
        if authenticated != *request.caller() {
            return Err(denied("Message identity changed."));
        }
        let mut pid = 0;
        unsafe { GetNamedPipeClientProcessId(HANDLE(pipe.as_raw_handle()), &mut pid) }
            .map_err(native)?;
        let process = process_handle(pid)?;
        alive(process.as_handle())?;
        let created = creation(process.as_handle())?;
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(HANDLE(process.as_raw_handle()), TOKEN_QUERY, &mut token) }
            .map_err(native)?;
        let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
        let principal = Principal::from_token(token.as_handle())?;
        if principal != authenticated {
            return Err(denied("Pipe and process primary-token identities differ."));
        }
        helper.revalidate(cancel)?;
        mapped_image(process.as_handle(), helper.file.as_handle())?;
        let mut after = 0;
        unsafe { GetNamedPipeClientProcessId(HANDLE(pipe.as_raw_handle()), &mut after) }
            .map_err(native)?;
        if pid != after {
            return Err(denied("Pipe process ID changed during inspection."));
        }
        let value = Self {
            process,
            pid,
            created,
            principal,
            helper,
        };
        value.revalidate(cancel)?;
        Ok(value)
    }
    pub(crate) fn revalidate(&self, cancel: &AtomicBool) -> io::Result<()> {
        alive(self.process.as_handle())?;
        if unsafe { GetProcessId(HANDLE(self.process.as_raw_handle())) } != self.pid
            || creation(self.process.as_handle())? != self.created
        {
            return Err(denied("Retained helper process identity changed."));
        }
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(
                HANDLE(self.process.as_raw_handle()),
                TOKEN_QUERY,
                &mut token,
            )
        }
        .map_err(native)?;
        let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
        if Principal::from_token(token.as_handle())? != self.principal {
            return Err(denied("Retained helper token identity changed."));
        }
        self.helper.revalidate(cancel)?;
        mapped_image(self.process.as_handle(), self.helper.file.as_handle())
    }
}

#[cfg(test)]
mod tests;
