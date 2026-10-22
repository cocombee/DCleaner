//! Read current interactive helper context, never service defaults or authority.
//! The supplied original command must already be retained losslessly by the
//! helper bootstrap; this module does not strip/requote argv or implement IPC.
use super::*;
use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf};
use windows::Win32::{
    Foundation::HANDLE,
    Security::TOKEN_QUERY,
    System::{
        Environment::{FreeEnvironmentStringsW, GetCurrentDirectoryW, GetEnvironmentStringsW},
        Threading::{GetCurrentProcess, GetStartupInfoW, OpenProcessToken, STARTUPINFOW},
    },
};
use zeroize::Zeroizing;

fn require_helper(expected: &Principal) -> io::Result<()> {
    if expected.session_id() == 0
        || expected.logon_sid()?.is_none()
        || expected.user_sid()? == "S-1-5-18"
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Original context requires an interactive helper process, not a service identity.",
        ));
    }
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(native)?;
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    // Effective identity alone can be a System thread impersonating the user.
    // Process and effective native identity must independently match the scope.
    if Principal::from_token(token.as_handle())? != *expected || Principal::current()? != *expected
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Helper process/effective identity no longer matches its capture scope.",
        ));
    }
    Ok(())
}

fn copy_environment(
    mut read: impl FnMut(usize) -> u16,
    cancel: &AtomicBool,
) -> io::Result<Zeroizing<Vec<u16>>> {
    let mut result = Zeroizing::new(Vec::new());
    for index in 0..MAX_ENVIRONMENT {
        if index % 1024 == 0 {
            cancelled(cancel)?;
        }
        let unit = read(index);
        let ended = unit == 0 && result.last() == Some(&0);
        result.push(unit);
        if ended {
            cancelled(cancel)?;
            return Ok(result);
        }
    }
    Err(invalid(
        "Helper environment exceeds the capture bound or has no complete terminator.",
    ))
}

struct Environment(windows::core::PWSTR);
impl Drop for Environment {
    fn drop(&mut self) {
        // Windows owns this read-only allocation. Do not scrub or modify it.
        let _ = unsafe { FreeEnvironmentStringsW(PCWSTR(self.0.0)) };
    }
}

/// Worker/helper entry only. Native APIs may block; cancellation is checked
/// before and after reads, not advertised as a hard wall-clock bound.
/// This captures current process data, not a protected helper/image/lease proof.
pub(crate) fn current_helper_input(
    expected: &Principal,
    selected_application: &Path,
    original_command: &OsStr,
    cancel: &AtomicBool,
) -> io::Result<LaunchInput> {
    let original = current_helper_context(expected, original_command, cancel)?;
    LaunchInput::from_original_context(selected_application, &original)
}

pub(crate) fn current_helper_context(
    expected: &Principal,
    original_command: &OsStr,
    cancel: &AtomicBool,
) -> io::Result<crate::optimizer_protocol::OriginalContext> {
    cancelled(cancel)?;
    require_helper(expected)?;
    cancelled(cancel)?;
    let mut directory = vec![0u16; MAX_STRING];
    let length = unsafe { GetCurrentDirectoryW(Some(&mut directory)) } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length >= directory.len() {
        return Err(invalid(
            "Helper working directory is unavailable or exceeds the capture bound.",
        ));
    }
    let directory = PathBuf::from(OsString::from_wide(&directory[..length]));
    cancelled(cancel)?;
    let block = unsafe { GetEnvironmentStringsW() };
    if block.is_null() {
        return Err(io::Error::last_os_error());
    }
    let allocation = Environment(block);
    // GetEnvironmentStringsW supplies a valid double-NUL terminated native
    // block. No caller/remote pointer is accepted; policy bounds retained data.
    let environment = copy_environment(|at| unsafe { allocation.0.0.add(at).read() }, cancel)?;
    drop(allocation);
    cancelled(cancel)?;
    let mut startup = STARTUPINFOW::default();
    unsafe { GetStartupInfoW(&mut startup) };
    let mut command = text(original_command)?;
    command.pop();
    let mut directory = local_path(&directory)?;
    directory.pop();
    let show_window =
        (startup.dwFlags.0 & STARTF_USESHOWWINDOW.0 != 0).then_some(startup.wShowWindow);
    let input = crate::optimizer_protocol::OriginalContext::new(
        command,
        directory,
        environment.to_vec(),
        show_window,
    )
    .map_err(|_| invalid("Original helper context is invalid or exceeds its bounds."))?;
    require_helper(expected)?;
    cancelled(cancel)?;
    // The temporary Rust environment copy is zeroized here; OriginalContext
    // owns its zeroized-on-drop unit buffers. No data is logged or saved.
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_environment_capture_preserves_opaque_units_and_never_returns_a_partial_block() {
        let raw = vec![
            61, 67, 58, 61, 67, 58, 92, 0, 69, 77, 80, 84, 89, 61, 0, 88, 61, 0xd800, 0, 0,
        ];
        let captured = copy_environment(|at| raw[at], &AtomicBool::new(false)).unwrap();
        assert_eq!(&*captured, &raw);
        assert!(environment_valid(&captured));
        assert!(copy_environment(|_| 65, &AtomicBool::new(false)).is_err());
        let cancel = AtomicBool::new(false);
        let error = copy_environment(
            |at| {
                if at == 10 {
                    cancel.store(true, Ordering::Release);
                }
                65
            },
            &cancel,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(
            copy_environment(
                |_| panic!("pre-cancel must not read"),
                &AtomicBool::new(true)
            )
            .is_err()
        );
    }
}
