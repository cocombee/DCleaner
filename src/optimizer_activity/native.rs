use super::*;
use crate::{
    optimizer_identity::FileIdentity,
    optimizer_pipe_security::{Principal, helper_image::mapped_image},
};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path, Prefix},
    thread,
    time::Instant,
};
use windows::{
    Win32::{
        Foundation::{ERROR_NO_MORE_FILES, FILETIME, HANDLE, WAIT_TIMEOUT},
        Security::TOKEN_QUERY,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_EXECUTE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_ID_INFO,
            FILE_NAME_NORMALIZED, FILE_SHARE_READ, FileIdInfo, GETFINALPATHNAMEBYHANDLE_FLAGS,
            GetDriveTypeW, GetFileInformationByHandle, GetFileInformationByHandleEx,
            GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
        },
        System::{
            Diagnostics::ToolHelp::*,
            ProcessStatus::{
                GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
            },
            Threading::{
                GetActiveProcessorCount, GetCurrentProcessId, GetProcessId, GetProcessTimes,
                OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE,
                WaitForSingleObject,
            },
        },
    },
    core::PCWSTR,
};

fn error(message: &str) -> io::Error {
    io::Error::other(message)
}
fn win(error: windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error((error.code().0 as u32 & 0xffff) as i32)
}
fn handle(value: BorrowedHandle<'_>) -> HANDLE {
    HANDLE(value.as_raw_handle())
}
fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn fixed_local_path(path: &Path, verbatim: bool) -> bool {
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || wide(path).iter().filter(|c| **c == 0).count() != 1
    {
        return false;
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return false;
    }
    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return false;
    };
    let letter = match prefix.kind() {
        Prefix::Disk(letter) => letter,
        Prefix::VerbatimDisk(letter) if verbatim => letter,
        _ => return false,
    };
    let root = [u16::from(letter), b':' as u16, b'\\' as u16, 0];
    // DRIVE_FIXED. Declared and resolved paths must both be local fixed volumes.
    unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) == 3 }
}

fn file_identity(file: &File) -> io::Result<FileIdentity> {
    let mut basic = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut basic) }.map_err(win)?;
    if basic.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_REPARSE_POINT.0) != 0 {
        return Err(error("Reference is not a regular non-reparse file."));
    }
    let mut id = FILE_ID_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(win)?;
    Ok(FileIdentity {
        volume_serial: id.VolumeSerialNumber,
        file_id: id.FileId.Identifier,
    })
}

struct Image {
    path: PathBuf,
    file: File,
    id: FileIdentity,
}
impl Image {
    fn open(path: &Path) -> io::Result<Self> {
        if !fixed_local_path(path, false) {
            return Err(error("Reference is not a bounded local fixed-volume path."));
        }
        let file = OpenOptions::new()
            .read(true)
            .access_mode(FILE_GENERIC_READ.0 | FILE_EXECUTE.0)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path)?;
        let id = file_identity(&file)?;
        let mut resolved = vec![0u16; 4096];
        let len = unsafe {
            GetFinalPathNameByHandleW(
                HANDLE(file.as_raw_handle()),
                &mut resolved,
                GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
            )
        } as usize;
        if len == 0 || len >= resolved.len() {
            return Err(error("Resolved reference path is unavailable or too long."));
        }
        let resolved = String::from_utf16(&resolved[..len])
            .map_err(|_| error("Resolved reference path is not Unicode."))?;
        if !fixed_local_path(Path::new(&resolved), true) {
            return Err(error("Resolved reference is not on a local fixed volume."));
        }
        Ok(Self {
            path: path.to_owned(),
            file,
            id,
        })
    }
    fn matches(&self, process: BorrowedHandle<'_>) -> bool {
        file_identity(&self.file).is_ok_and(|id| id == self.id)
            && mapped_image(process, self.file.as_handle()).is_ok()
    }
}

fn enumerate(cancel: &AtomicBool) -> io::Result<(Vec<u32>, bool)> {
    if cancel.load(Ordering::Relaxed) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "Process snapshot cancelled.",
        ));
    }
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(win)?;
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw.0) };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut result = Vec::new();
    let mut next = unsafe { Process32FirstW(handle(snapshot.as_handle()), &mut entry) };
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Process snapshot cancelled.",
            ));
        }
        match next {
            Ok(()) => {
                if result.len() == MAX_PROCESSES {
                    return Ok((result, true));
                }
                result.push(entry.th32ProcessID);
            }
            Err(e) if e.code() == ERROR_NO_MORE_FILES.to_hresult() => return Ok((result, false)),
            Err(e) => return Err(win(e)),
        }
        next = unsafe { Process32NextW(handle(snapshot.as_handle()), &mut entry) };
    }
}

fn principal(process: BorrowedHandle<'_>) -> io::Result<Principal> {
    let mut raw = HANDLE::default();
    unsafe { OpenProcessToken(handle(process), TOKEN_QUERY, &mut raw) }.map_err(win)?;
    let token = unsafe { OwnedHandle::from_raw_handle(raw.0) };
    Principal::from_token(token.as_handle())
}
fn alive(process: BorrowedHandle<'_>, pid: u32) -> bool {
    unsafe {
        GetProcessId(handle(process)) == pid
            && WaitForSingleObject(handle(process), 0) == WAIT_TIMEOUT
    }
}
struct Times {
    creation: u64,
    cpu: u64,
    at: Instant,
}
fn times(process: BorrowedHandle<'_>) -> io::Result<Times> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(
            handle(process),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .map_err(win)?;
    let value = |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
    let creation = value(creation);
    if creation == 0 {
        return Err(error("Process creation time is unavailable."));
    }
    Ok(Times {
        creation,
        cpu: value(kernel)
            .checked_add(value(user))
            .ok_or_else(|| error("CPU counters overflowed."))?,
        at: Instant::now(),
    })
}
fn memory(process: BorrowedHandle<'_>) -> io::Result<(u64, u64)> {
    let mut value = PROCESS_MEMORY_COUNTERS_EX {
        cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ..Default::default()
    };
    unsafe {
        GetProcessMemoryInfo(
            handle(process),
            (&mut value as *mut PROCESS_MEMORY_COUNTERS_EX).cast::<PROCESS_MEMORY_COUNTERS>(),
            value.cb,
        )
    }
    .map_err(win)?;
    Ok((value.WorkingSetSize as u64, value.PrivateUsage as u64))
}
struct Started {
    process: OwnedHandle,
    pid: u32,
    image: usize,
    before: Times,
}

pub(super) fn inspect(paths: &[PathBuf], cancel: &AtomicBool) -> Evidence {
    let expected = match Principal::current() {
        Ok(value) if value.logon_sid().ok().flatten().is_some() => value,
        _ => {
            return Evidence::unavailable(
                "The current interactive logon could not be identified for activity observation.",
            );
        }
    };
    // A positive self comparison checks support for this private native query.
    // Its success does not turn other negative results into absence proofs.
    let self_image = std::env::current_exe()
        .ok()
        .and_then(|path| Image::open(&path).ok());
    let self_process = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            GetCurrentProcessId(),
        )
    }
    .ok()
    .map(|raw| unsafe { OwnedHandle::from_raw_handle(raw.0) });
    if !self_image
        .as_ref()
        .zip(self_process.as_ref())
        .is_some_and(|(image, process)| {
            mapped_image(process.as_handle(), image.file.as_handle()).is_ok()
        })
    {
        return Evidence::unavailable(
            "Exact native executable mapping is unavailable on this Windows installation.",
        );
    }
    let (pids, truncated) = match enumerate(cancel) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::Interrupted => {
            return Evidence::empty(Status::Cancelled);
        }
        Err(_) => return Evidence::unavailable("The native process snapshot could not be read."),
    };
    let mut result = observe(paths, &pids, &expected, cancel, SAMPLE_WINDOW);
    if truncated {
        result.note("The process snapshot reached its observation limit.");
    }
    result
}

fn observe(
    paths: &[PathBuf],
    pids: &[u32],
    expected: &Principal,
    cancel: &AtomicBool,
    interval: Duration,
) -> Evidence {
    observe_started(paths, pids, expected, cancel, interval, || {})
}
fn observe_started(
    paths: &[PathBuf],
    pids: &[u32],
    expected: &Principal,
    cancel: &AtomicBool,
    interval: Duration,
    started_hook: impl FnOnce(),
) -> Evidence {
    let mut output = Evidence::empty(Status::Observed);
    output.note("Only positive executable matches in the current logon are shown. Installer key paths are incomplete; this is not an app-wide impact rating or reclaimable memory estimate.");
    let mut images: Vec<Image> = Vec::new();
    for path in paths.iter().take(MAX_IMAGES) {
        if cancel.load(Ordering::Relaxed) {
            output.status = Status::Cancelled;
            return output;
        }
        match Image::open(path) {
            Ok(image) if !images.iter().any(|i| i.id == image.id) => images.push(image),
            Ok(_) => (),
            Err(_) => {
                output.note("Some executable references could not be pinned for observation.")
            }
        }
    }
    output.inspected_images = images.len();
    if paths.len() > MAX_IMAGES {
        output.note("Executable reference observation reached its limit.");
    }
    if images.is_empty() {
        output.status = Status::Unavailable;
        return output;
    }
    let processors = unsafe { GetActiveProcessorCount(u16::MAX) };
    if processors == 0 || processors > 4096 {
        return Evidence::unavailable("The active processor count could not be read.");
    }
    let mut started = Vec::new();
    let mut seen = HashSet::new();
    for pid in pids.iter().copied().take(MAX_PROCESSES) {
        if cancel.load(Ordering::Relaxed) {
            output.status = Status::Cancelled;
            return output;
        }
        if pid <= 4 || !seen.insert(pid) {
            continue;
        }
        let process = match unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SYNCHRONIZE, false, pid)
        } {
            Ok(raw) => unsafe { OwnedHandle::from_raw_handle(raw.0) },
            Err(_) => {
                output.unobservable_processes += 1;
                continue;
            }
        };
        match principal(process.as_handle()) {
            Ok(value) if value == *expected => (),
            Ok(_) => continue,
            Err(_) => {
                output.unobservable_processes += 1;
                continue;
            }
        }
        if !alive(process.as_handle(), pid) {
            output.unobservable_processes += 1;
            continue;
        }
        let mut matched = None;
        for (index, image) in images.iter().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                output.status = Status::Cancelled;
                return output;
            }
            if image.matches(process.as_handle()) {
                matched = Some(index);
                break;
            }
        }
        let Some(image) = matched else { continue };
        let before = match times(process.as_handle()) {
            Ok(value) => value,
            Err(_) => {
                output.unobservable_processes += 1;
                continue;
            }
        };
        started.push(Started {
            process,
            pid,
            image,
            before,
        });
        if started.len() == MAX_MATCHES {
            output.note("Matched-process observation reached its limit.");
            break;
        }
    }
    if pids.len() > MAX_PROCESSES {
        output.note("The selected process list reached its observation limit.");
    }
    if output.unobservable_processes > 0 {
        output.note("Some process identities could not be read. Omitted processes are not proof of zero activity.");
    }
    if started.is_empty() {
        return output;
    }
    started_hook();
    let until = Instant::now() + interval;
    while Instant::now() < until {
        if cancel.load(Ordering::Relaxed) {
            output.status = Status::Cancelled;
            return output;
        }
        thread::sleep(
            until
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(20)),
        );
    }
    let same_processors = unsafe { GetActiveProcessorCount(u16::MAX) } == processors;
    if !same_processors {
        output.note(
            "The active processor count changed during the sample; CPU totals are unavailable.",
        );
    }
    for item in started {
        if cancel.load(Ordering::Relaxed) {
            output.status = Status::Cancelled;
            return output;
        }
        let process = item.process.as_handle();
        if !alive(process, item.pid)
            || principal(process).ok().as_ref() != Some(expected)
            || !images[item.image].matches(process)
        {
            output.note(
                "Some matching processes exited or could not be revalidated during the sample.",
            );
            continue;
        }
        let after = match times(process) {
            Ok(t) if t.creation == item.before.creation => t,
            _ => {
                output.note("Some process counters could not be revalidated.");
                continue;
            }
        };
        let elapsed = after.at.saturating_duration_since(item.before.at);
        let rate = same_processors
            .then(|| cpu_rate(item.before.cpu, after.cpu, elapsed, processors))
            .flatten();
        let mem = memory(process).ok();
        if rate.is_none() {
            output.note("Some CPU counters could not be measured reliably.");
        }
        if mem.is_none() {
            output.note("Some memory counters could not be read.");
        }
        // A process can exit or change access while counters are being read.
        if !alive(process, item.pid)
            || principal(process).ok().as_ref() != Some(expected)
            || !images[item.image].matches(process)
        {
            output.note("Some matching processes changed while reading counters.");
            continue;
        }
        output.processes.push(ProcessUsage {
            pid: item.pid,
            creation_time: after.creation,
            registered_image: images[item.image].path.clone(),
            cpu_basis_points: rate,
            working_set_bytes: mem.map(|v| v.0),
            private_committed_bytes: mem.map(|v| v.1),
            elapsed_millis: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
        });
    }
    output
}

#[cfg(test)]
mod tests;
