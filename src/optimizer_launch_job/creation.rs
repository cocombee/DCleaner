//! Suspended native creation, not app eligibility, lease or effect authority.
//! Only a protected dispatcher may call this boundary. Creation and resume are
//! separate so the original launch owner can restore its hook, record the
//! receipt and revalidate before any application code executes. Complete lease,
//! helper and broker lifetime authority remain independent requirements.
use super::*;
use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    path::{Component, Path, Prefix},
};
use windows::{
    Win32::System::Threading::{
        CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESHOWWINDOW,
        STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    },
    core::PWSTR,
};
use zeroize::Zeroize;
pub(crate) mod capture;

const MAX_STRING: usize = 32_767;
const MAX_ENVIRONMENT: usize = 512 * 1024; // UTF-16 units; one MiB policy cap.

fn text(value: &OsStr) -> io::Result<Vec<u16>> {
    let units: Vec<_> = value.encode_wide().take(MAX_STRING).collect();
    if units.is_empty() || units.len() >= MAX_STRING || units.contains(&0) {
        return Err(invalid(
            "Launch text is empty, oversized or contains a NUL.",
        ));
    }
    Ok(units.into_iter().chain(Some(0)).collect())
}
fn local_path(path: &Path) -> io::Result<Vec<u16>> {
    if !path.is_absolute()
        || !matches!(path.components().next(), Some(Component::Prefix(p))
            if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        || path.components().any(|p| matches!(p, Component::ParentDir))
    {
        return Err(invalid("Launch requires an absolute local disk path."));
    }
    text(path.as_os_str())
}
fn environment_valid(value: &[u16]) -> bool {
    if value.len() < 2 || value.len() > MAX_ENVIRONMENT || !value.ends_with(&[0, 0]) {
        return false;
    }
    if value == [0, 0] {
        return true;
    }
    // Preserve the captured block, including =C: per-drive entries, empty
    // values and UTF-16 that cannot round-trip through a Rust String. Reject
    // an early terminator/trailing payload rather than silently dropping it.
    let mut at = 0;
    while at < value.len() - 1 {
        let Some(length) = value[at..].iter().position(|unit| *unit == 0) else {
            return false;
        };
        let entry = &value[at..at + length];
        let start = usize::from(entry.first() == Some(&(b'=' as u16)));
        if entry.len() <= start
            || !entry[start..]
                .iter()
                .position(|u| *u == b'=' as u16)
                .is_some_and(|p| p > 0)
        {
            return false;
        }
        at += length + 1;
    }
    at == value.len() - 1
}

/// Original invocation data retained inside the protected owner; never an IPC
/// authorization payload. No shell parsing, argv re-quoting, PATH search, or
/// service-environment fallback occurs here. No Debug/serialization exposes it.
pub(crate) struct LaunchInput {
    application: Vec<u16>,
    command: Vec<u16>,
    directory: Vec<u16>,
    environment: Vec<u16>,
    show_window: Option<u16>,
}
impl LaunchInput {
    /// The image always comes from the protected owner's selection. Context is
    /// untrusted invocation data and undergoes the same native input checks.
    pub(crate) fn from_original_context(
        application: &Path,
        original: &crate::optimizer_protocol::OriginalContext,
    ) -> io::Result<Self> {
        use std::os::windows::ffi::OsStringExt;
        original
            .validate()
            .map_err(|_| invalid("Original context failed validation."))?;
        let command = std::ffi::OsString::from_wide(original.command());
        let directory =
            std::path::PathBuf::from(std::ffi::OsString::from_wide(original.directory()));
        Self::new(application, &command, &directory, original.environment())?
            .with_original_show_window(
                if original.show_window().is_some() {
                    STARTF_USESHOWWINDOW.0
                } else {
                    0
                },
                original.show_window().unwrap_or(0),
            )
    }

    pub(crate) fn new(
        application: &Path,
        original_command_line: &OsStr,
        directory: &Path,
        original_environment: &[u16],
    ) -> io::Result<Self> {
        if !environment_valid(original_environment) {
            return Err(invalid(
                "Original Unicode launch environment is malformed or oversized.",
            ));
        }
        Ok(Self {
            application: local_path(application)?,
            command: text(original_command_line)?,
            directory: local_path(directory)?,
            environment: original_environment.to_vec(),
            show_window: None,
        })
    }

    /// Preserve only the original show-window instruction, not arbitrary
    /// startup flags, inherited handles, desktop names or launch authority.
    /// Without STARTF_USESHOWWINDOW the original wShowWindow is ignored by
    /// Windows, so even an otherwise invalid value has no meaning here.
    pub(crate) fn with_original_show_window(
        mut self,
        original_flags: u32,
        original_show_window: u16,
    ) -> io::Result<Self> {
        self.show_window = if original_flags & STARTF_USESHOWWINDOW.0 == 0 {
            None
        } else if matches!(original_show_window, 0..=9 | 11) {
            Some(original_show_window)
        } else {
            // STARTUPINFO explicitly excludes SW_SHOWDEFAULT (10). Unknown
            // values must not be coerced to a different presentation request.
            return Err(invalid(
                "Original startup show-window instruction is unsupported.",
            ));
        };
        Ok(self)
    }
}
impl Drop for LaunchInput {
    fn drop(&mut self) {
        self.command.zeroize();
        self.environment.zeroize();
    }
}
pub(crate) struct LaunchScope<'a> {
    pub(crate) expected: &'a Principal,
    pub(crate) member: Member,
    pub(crate) invocation: Uuid,
    pub(crate) instance: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaunchOutcome {
    NotCreated,
    AbortedBeforeResume,
    ExecutionUncertain,
    RollbackUnconfirmed,
}
pub(crate) struct LaunchError {
    pub(crate) cause: io::Error,
    pub(crate) outcome: LaunchOutcome,
    pending: Option<Suspended>,
    family: Option<LaunchFamily>,
}
impl std::fmt::Debug for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchError")
            .field("cause", &self.cause)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}
impl LaunchError {
    fn with_family(mut self, family: LaunchFamily) -> Self {
        if matches!(
            self.outcome,
            LaunchOutcome::ExecutionUncertain | LaunchOutcome::RollbackUnconfirmed
        ) {
            self.family = Some(family);
        }
        self
    }
    /// Retained uncertain-launch lifetime, never an implicit lease release or
    /// permission to retry. Keep this error under the protected owner until
    /// native recovery and durable invocation bookkeeping are reconciled.
    pub(crate) fn retained_family(&mut self) -> Option<&mut LaunchFamily> {
        self.family.as_mut()
    }
    /// Retry only termination observation/cleanup of this factory's exact new
    /// root. This never retries creation/resume or terminates a running family.
    pub(crate) fn confirm_owned_abort(&mut self) -> io::Result<LaunchOutcome> {
        if let Some(pending) = &mut self.pending {
            pending.abort()?;
            self.outcome = if pending.resume_attempted {
                LaunchOutcome::ExecutionUncertain
            } else {
                LaunchOutcome::AbortedBeforeResume
            };
            self.pending = None;
        }
        Ok(self.outcome)
    }
}
impl From<io::Error> for LaunchError {
    fn from(cause: io::Error) -> Self {
        Self {
            cause,
            outcome: LaunchOutcome::NotCreated,
            pending: None,
            family: None,
        }
    }
}
impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.outcome, self.cause)
    }
}
impl std::error::Error for LaunchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

struct Attributes {
    _backing: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}
impl Attributes {
    fn new(job: &HANDLE) -> io::Result<Self> {
        let mut bytes = 0;
        let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut bytes) };
        if bytes == 0 || bytes > 65_536 {
            return Err(invalid("Native creation attribute size is unavailable."));
        }
        let mut backing = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(backing.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(Some(list), 1, None, &mut bytes) }
            .map_err(native)?;
        let value = Self {
            _backing: backing,
            list,
        };
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
        .map_err(native)?;
        Ok(value)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.list) };
    }
}

/// Owns only this factory's new root, including a refused resume with uncertain
/// execution. Never opened by PID or used to terminate an existing app/job.
struct Suspended {
    root: OwnedHandle,
    thread: OwnedHandle,
    disarmed: bool,
    resume_attempted: bool,
    _job: OwnedHandle,
}
impl Suspended {
    fn abort(&mut self) -> io::Result<()> {
        if self.disarmed {
            return Ok(());
        }
        let root = handle(self.root.as_handle());
        if unsafe { WaitForSingleObject(root, 0) } != WAIT_OBJECT_0 {
            unsafe { TerminateProcess(root, 0xDC01) }.map_err(native)?;
        }
        if unsafe { WaitForSingleObject(root, 5000) } != WAIT_OBJECT_0 {
            return Err(io::Error::other(
                "New suspended launch termination is unconfirmed.",
            ));
        }
        self.disarmed = true;
        Ok(())
    }
    fn fail(mut self, cause: io::Error) -> LaunchError {
        match self.abort() {
            Ok(()) => LaunchError {
                cause,
                outcome: if self.resume_attempted {
                    LaunchOutcome::ExecutionUncertain
                } else {
                    LaunchOutcome::AbortedBeforeResume
                },
                pending: None,
                family: None,
            },
            Err(_) => LaunchError {
                cause,
                outcome: LaunchOutcome::RollbackUnconfirmed,
                pending: Some(self),
                family: None,
            },
        }
    }
}
impl Drop for Suspended {
    fn drop(&mut self) {
        // Emergency unwind cleanup; ordinary error paths explicitly report an
        // unconfirmed rollback. No kill-on-job-close behavior is introduced.
        let _ = self.abort();
    }
}

/// Newly created original image, still suspended in its retained job. This is
/// deliberately not a running family and has no clone/serialization/PID API.
/// The hook owner must settle restoration even when creation returns an error;
/// it must never use successful creation as a hook-restoration receipt.
/// Dropping this value aborts only its exact new root as an unwind fallback.
/// Use `abort` on ordinary refusal paths to retain any unconfirmed cleanup.
#[must_use = "Restore the launch hook before resuming, or explicitly abort the suspended root"]
pub(crate) struct SuspendedLaunch {
    suspended: Suspended,
    family: LaunchFamily,
    require_live_logon: bool,
}
impl SuspendedLaunch {
    /// Refuse the original launch without running its code. The returned error
    /// distinguishes confirmed termination from an unconfirmed rollback and
    /// retains the latter's native handles. This never recreates/resumes it.
    pub(crate) fn abort(self, cause: io::Error) -> LaunchError {
        self.suspended.fail(cause).with_family(self.family)
    }

    /// # Safety
    /// The caller must independently verify the original complete invocation,
    /// protected lease/epoch, executable path/ACL/content pins and required hook
    /// restoration's durable native receipt immediately before resume.
    /// `revalidate` must check this authority, not merely a saved phase/boolean.
    /// It must not retry hook effects or launch on an uncertain outcome.
    pub(crate) unsafe fn resume(
        self,
        cancel: &AtomicBool,
        revalidate: impl FnOnce() -> io::Result<()>,
    ) -> Result<LaunchFamily, LaunchError> {
        let Self {
            mut suspended,
            family,
            require_live_logon,
        } = self;
        let validate = (|| {
            cancelled(cancel)?;
            family.owner.check()?;
            revalidate()?;
            // Recheck native scope after the independent owner callback: it
            // may block while completing the hook's durable restore receipt.
            family.owner.check()?;
            if require_live_logon && !family.expected.is_current_logged_on_session()? {
                return Err(invalid("Interactive launch logon changed before resume."));
            }
            cancelled(cancel)?;
            checked_limits(family.job.as_handle())?;
            let counts = accounting(family.job.as_handle())?;
            if counts.TotalProcesses != 1
                || counts.ActiveProcesses != 1
                || unsafe { WaitForSingleObject(handle(suspended.root.as_handle()), 0) }
                    != WAIT_TIMEOUT
            {
                return Err(invalid(
                    "New suspended invocation family changed before resume.",
                ));
            }
            crate::optimizer_pipe_security::helper_image::mapped_image(
                suspended.root.as_handle(),
                family.image.as_handle(),
            )?;
            if principal(suspended.root.as_handle())? != family.expected {
                return Err(invalid("New launch token changed before resume."));
            }
            Ok(())
        })();
        if let Err(error) = validate {
            return Err(suspended.fail(error).with_family(family));
        }
        suspended.resume_attempted = true;
        let previous = unsafe { ResumeThread(handle(suspended.thread.as_handle())) };
        if previous != 1 {
            let cause = if previous == u32::MAX {
                io::Error::last_os_error()
            } else {
                invalid("New launch suspension count changed; execution outcome requires review.")
            };
            return Err(suspended.fail(cause).with_family(family));
        }
        suspended.disarmed = true;
        Ok(family)
    }
}

impl PendingJob {
    /// # Safety
    /// A protected dispatcher must independently own and authorize the complete
    /// app/member/lease/invocation and its current service epoch. This must be
    /// an eligible original user launch, with no out-of-job broker delegation.
    /// `input` must be that invocation's locally retained original data, never
    /// arbitrary IPC launch authority. The executable must be independently
    /// selected, executable-access pinned, and path/ACL/content pins retained.
    /// `revalidate` must check those pins and lease/effect/durable launch state
    /// before creation. IFEO recursion must already be avoided through the
    /// authorized hook owner. A mapped helper instead of the original image is
    /// refused, not recursively trusted. On success, restore the hook and use
    /// the separate resume boundary; on failure, still settle hook restoration.
    /// No ordinary fallback/retry is authorized on an uncertain launch outcome.
    /// This worker-only operation may block in native calls and rollback waits.
    pub(crate) unsafe fn create_suspended(
        self,
        mut input: LaunchInput,
        image: BorrowedHandle<'_>,
        scope: LaunchScope<'_>,
        cancel: &AtomicBool,
        revalidate: impl FnOnce() -> io::Result<()>,
    ) -> Result<SuspendedLaunch, LaunchError> {
        cancelled(cancel)?;
        self.owner.check()?;
        if scope.invocation.is_nil()
            || scope.instance.is_nil()
            || !scope.member.matches_principal(scope.expected)?
        {
            return Err(invalid("Invalid protected invocation scope.").into());
        }
        // System obtains the primary token itself. Never impersonate, change
        // token session, request elevation, or borrow the service environment.
        let token = match &self.owner {
            OwnerContext::System => {
                let (token, current) =
                    Principal::logged_on_session_token(scope.expected.session_id())?;
                if current != *scope.expected {
                    return Err(invalid("Interactive launch logon changed.").into());
                }
                Some(token)
            }
            #[cfg(test)]
            OwnerContext::Fixture(_) => {
                if Principal::current()? != *scope.expected {
                    return Err(invalid("Private fixture launch principal changed.").into());
                }
                None
            }
        };
        revalidate()?;
        self.owner.check()?;
        cancelled(cancel)?;
        checked_limits(self.job.as_handle())?;
        if accounting(self.job.as_handle())?.TotalProcesses != 0 {
            return Err(invalid("Invocation job is no longer empty.").into());
        }
        let job = handle(self.job.as_handle());
        let attributes = Attributes::new(&job)?;
        let mut desktop: Vec<u16> = "winsta0\\default".encode_utf16().chain(Some(0)).collect();
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.lpDesktop = PWSTR(desktop.as_mut_ptr());
        if let Some(show_window) = input.show_window {
            startup.StartupInfo.dwFlags |= STARTF_USESHOWWINDOW;
            startup.StartupInfo.wShowWindow = show_window;
        }
        startup.lpAttributeList = attributes.list;
        let mut process = PROCESS_INFORMATION::default();
        let flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;
        let environment = Some(input.environment.as_ptr().cast());
        // Cleanup authority remains inside the same exclusive protected owner;
        // no job handle is inherited or exposed to the application/helper.
        let cleanup_job = self.job.try_clone()?;
        let created = if let Some(token) = &token {
            unsafe {
                CreateProcessAsUserW(
                    Some(handle(token.as_handle())),
                    PCWSTR(input.application.as_ptr()),
                    Some(PWSTR(input.command.as_mut_ptr())),
                    None,
                    None,
                    false,
                    flags,
                    environment,
                    PCWSTR(input.directory.as_ptr()),
                    &startup.StartupInfo,
                    &mut process,
                )
            }
        } else {
            #[cfg(test)]
            {
                // Only disposable copies of the Rust test image are authorized
                // by private callers. No visible console, inherited handles or
                // service privileges. Production has no current-user fallback.
                unsafe {
                    windows::Win32::System::Threading::CreateProcessW(
                        PCWSTR(input.application.as_ptr()),
                        Some(PWSTR(input.command.as_mut_ptr())),
                        None,
                        None,
                        false,
                        flags | windows::Win32::System::Threading::CREATE_NO_WINDOW,
                        environment,
                        PCWSTR(input.directory.as_ptr()),
                        &startup.StartupInfo,
                        &mut process,
                    )
                }
            }
            #[cfg(not(test))]
            {
                unreachable!("System launch requires a retained session token")
            }
        };
        created.map_err(native)?;
        let suspended = Suspended {
            root: unsafe { OwnedHandle::from_raw_handle(process.hProcess.0) },
            thread: unsafe { OwnedHandle::from_raw_handle(process.hThread.0) },
            disarmed: false,
            resume_attempted: false,
            _job: cleanup_job,
        };
        // No attribute pointer/borrowed job HANDLE survives admission.
        drop(attributes);
        let root = match suspended.root.try_clone() {
            Ok(value) => value,
            Err(error) => return Err(suspended.fail(error)),
        };
        let family = match unsafe {
            self.admit_owned_root(
                root,
                image,
                scope.expected,
                scope.member,
                scope.invocation,
                scope.instance,
                cancel,
            )
        } {
            Ok(family) => family,
            Err(error) => return Err(suspended.fail(error)),
        };
        Ok(SuspendedLaunch {
            suspended,
            family,
            require_live_logon: token.is_some(),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;

// Legacy fixture convenience still exercises both real boundaries. Production
// has only the staged API so a hook owner can settle restoration on every path.
#[cfg(test)]
impl PendingJob {
    unsafe fn launch(
        self,
        input: LaunchInput,
        image: BorrowedHandle<'_>,
        scope: LaunchScope<'_>,
        cancel: &AtomicBool,
        mut revalidate: impl FnMut() -> io::Result<()>,
    ) -> Result<LaunchFamily, LaunchError> {
        let pending =
            unsafe { self.create_suspended(input, image, scope, cancel, &mut revalidate) }?;
        unsafe { pending.resume(cancel, revalidate) }
    }
}
