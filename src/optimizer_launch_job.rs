//! Native invocation-family lifetime for a future protected launch owner.
//!
//! The admission boundary requires a freshly owned, suspended creation and its
//! independently authorized complete invocation scope. No PID, saved record or
//! sampled process roster can construct this observation. Service deployment,
//! original launch forwarding and app/lease ownership are separate gates.
#![allow(dead_code)]
pub(crate) mod creation;
use crate::{
    optimizer_pipe_security::{Descriptor, Principal},
    optimizer_resources::{ActivationObservation, Member},
};
use std::{
    io,
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    sync::atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;
use windows::{
    Win32::{
        Foundation::{FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        Security::{SECURITY_ATTRIBUTES, TOKEN_QUERY},
        System::{
            JobObjects::{
                CreateJobObjectW, IsProcessInJob, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
                JobObjectExtendedLimitInformation, QueryInformationJobObject,
            },
            Threading::{
                GetExitCodeProcess, GetProcessId, GetProcessTimes, OpenProcessToken,
                WaitForSingleObject,
            },
        },
    },
    core::{BOOL, PCWSTR},
};

fn native(error: windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error((error.code().0 as u32 & 0xffff) as i32)
}
fn invalid(text: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, text)
}
fn cancelled(cancel: &AtomicBool) -> io::Result<()> {
    if cancel.load(Ordering::Acquire) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "Invocation observation cancelled.",
        ))
    } else {
        Ok(())
    }
}
fn handle(value: BorrowedHandle<'_>) -> HANDLE {
    HANDLE(value.as_raw_handle())
}
fn query<T: Default>(
    job: BorrowedHandle<'_>,
    class: windows::Win32::System::JobObjects::JOBOBJECTINFOCLASS,
) -> io::Result<T> {
    let mut value = T::default();
    let mut returned = 0;
    unsafe {
        QueryInformationJobObject(
            Some(handle(job)),
            class,
            (&mut value as *mut T).cast(),
            size_of::<T>() as u32,
            Some(&mut returned),
        )
    }
    .map_err(native)?;
    if returned as usize != size_of::<T>() {
        return Err(invalid("Job query returned an unexpected native size."));
    }
    Ok(value)
}
fn checked_limits(job: BorrowedHandle<'_>) -> io::Result<()> {
    let value: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
        query(job, JobObjectExtendedLimitInformation)?;
    // Never enable kill-on-close or either breakaway mode. Do not introduce
    // CPU/memory/UI limits to an ordinary app as an observation side effect.
    if value.BasicLimitInformation.LimitFlags.0 != 0 {
        return Err(invalid("Invocation job limits changed."));
    }
    Ok(())
}
fn accounting(job: BorrowedHandle<'_>) -> io::Result<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION> {
    let value: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
        query(job, JobObjectBasicAccountingInformation)?;
    if value.ActiveProcesses > value.TotalProcesses || value.TotalTerminatedProcesses != 0 {
        return Err(invalid(
            "Invocation job accounting is inconsistent or records a limit termination.",
        ));
    }
    Ok(value)
}
fn process_identity(process: BorrowedHandle<'_>) -> io::Result<(u32, u64)> {
    let pid = unsafe { GetProcessId(handle(process)) };
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    unsafe {
        GetProcessTimes(
            handle(process),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    }
    .map_err(native)?;
    let created = u64::from(created.dwHighDateTime) << 32 | u64::from(created.dwLowDateTime);
    if pid <= 4 || created == 0 {
        return Err(invalid("Owned root creation identity is unavailable."));
    }
    Ok((pid, created))
}
fn principal(process: BorrowedHandle<'_>) -> io::Result<Principal> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(handle(process), TOKEN_QUERY, &mut token) }.map_err(native)?;
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    Principal::from_token(token.as_handle())
}

enum OwnerContext {
    System,
    #[cfg(test)]
    Fixture(Principal),
}
impl OwnerContext {
    fn check(&self) -> io::Result<Principal> {
        match self {
            Self::System => {
                Principal::require_local_system()?;
                Principal::current()
            }
            #[cfg(test)]
            Self::Fixture(expected) => {
                let current = Principal::current()?;
                if current != *expected {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Private fixture owner context changed.",
                    ));
                }
                Ok(current)
            }
        }
    }
}
pub(crate) struct PendingJob {
    job: OwnedHandle,
    owner: OwnerContext,
}
impl PendingJob {
    pub(crate) fn for_service() -> io::Result<Self> {
        Self::create(OwnerContext::System)
    }
    #[cfg(test)]
    pub(crate) fn fixture() -> io::Result<Self> {
        Self::create(OwnerContext::Fixture(Principal::current()?))
    }
    fn create(owner_context: OwnerContext) -> io::Result<Self> {
        let owner = owner_context.check()?.user_sid()?;
        let descriptor =
            Descriptor::from_sddl(&format!("O:{owner}D:P(A;;GA;;;{owner})(A;;GA;;;SY)"))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.native().0,
            bInheritHandle: BOOL(0),
        };
        // Unnamed and non-inheritable: a caller cannot reopen a predictable name
        // or inherit the authority to add unrelated processes to this family.
        let raw = unsafe { CreateJobObjectW(Some(&attributes), PCWSTR::null()) }.map_err(native)?;
        let job = unsafe { OwnedHandle::from_raw_handle(raw.0) };
        checked_limits(job.as_handle())?;
        let counts = accounting(job.as_handle())?;
        if counts.TotalProcesses != 0 || counts.ActiveProcesses != 0 {
            return Err(invalid("New invocation job is not empty."));
        }
        Ok(Self {
            job,
            owner: owner_context,
        })
    }
    /// Borrow only for PROC_THREAD_ATTRIBUTE_JOB_LIST during process creation.
    /// Do not inherit/duplicate this handle or retain an attribute list beyond
    /// creation. No job handle is exposed after consuming admission.
    pub(crate) fn for_creation(&self) -> BorrowedHandle<'_> {
        self.job.as_handle()
    }

    /// # Safety
    /// The exclusive protected launch owner must have created this exact root
    /// suspended with this job in PROC_THREAD_ATTRIBUTE_JOB_LIST, before any
    /// root code could run. It must independently bind `member`, invocation and
    /// epoch to its authorized protected lease and a complete invocation scope.
    /// The scope must not delegate work to brokers/processes outside this job;
    /// such apps need a separately complete lifetime owner. Delete the creation
    /// attribute list and retain no duplicate job handle outside the owner.
    /// Never admit a process opened by PID, caller frame or saved launch hint.
    /// Supply the independently selected, retained executable file with execute
    /// access; its mapping is checked here. The protected owner must also retain
    /// its path/ACL/content pins before resuming. This observation does not grant
    /// registry/effect/association authority.
    pub(crate) unsafe fn admit_owned_root(
        self,
        root: OwnedHandle,
        image: BorrowedHandle<'_>,
        expected: &Principal,
        member: Member,
        invocation: Uuid,
        instance: Uuid,
        cancel: &AtomicBool,
    ) -> io::Result<LaunchFamily> {
        cancelled(cancel)?;
        self.owner.check()?;
        if invocation.is_nil() || instance.is_nil() {
            return Err(invalid("Invalid invocation binding."));
        }
        if !member.matches_principal(expected)? {
            return Err(invalid(
                "Invocation member does not match its native launch principal.",
            ));
        }
        checked_limits(self.job.as_handle())?;
        let counts = accounting(self.job.as_handle())?;
        if counts.TotalProcesses != 1 || counts.ActiveProcesses != 1 {
            return Err(invalid(
                "Invocation job does not contain exactly its newly created root.",
            ));
        }
        let mut in_job = BOOL(0);
        unsafe {
            IsProcessInJob(
                handle(root.as_handle()),
                Some(handle(self.job.as_handle())),
                &mut in_job,
            )
        }
        .map_err(native)?;
        if !in_job.as_bool()
            || unsafe { WaitForSingleObject(handle(root.as_handle()), 0) } != WAIT_TIMEOUT
        {
            return Err(invalid("Owned root is not live in the retained job."));
        }
        if principal(root.as_handle())? != *expected {
            return Err(invalid("Owned root primary-token scope changed."));
        }
        let image = image.try_clone_to_owned()?;
        crate::optimizer_pipe_security::helper_image::mapped_image(
            root.as_handle(),
            image.as_handle(),
        )?;
        let identity = process_identity(root.as_handle())?;
        cancelled(cancel)?;
        Ok(LaunchFamily {
            job: self.job,
            owner: self.owner,
            root: Some(root),
            image,
            root_identity: identity,
            expected: expected.clone(),
            member,
            invocation,
            instance,
            exit_code: None,
            invalidated: false,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FamilyState {
    pub(crate) active_processes: u32,
    pub(crate) total_processes: u32,
    pub(crate) root_exited: bool,
    pub(crate) root_exit_code: Option<u32>,
}
impl FamilyState {
    pub(crate) fn ended(self) -> bool {
        self.root_exited && self.active_processes == 0
    }
}

pub(crate) struct LaunchFamily {
    job: OwnedHandle,
    owner: OwnerContext,
    root: Option<OwnedHandle>,
    image: OwnedHandle,
    root_identity: (u32, u64),
    expected: Principal,
    member: Member,
    invocation: Uuid,
    instance: Uuid,
    exit_code: Option<u32>,
    invalidated: bool,
}
impl LaunchFamily {
    /// Zero-duration process waits and bounded-size native queries; native calls
    /// have no hard wall-clock guarantee. Errors/cancellation never mean exited.
    pub(crate) fn observe(&mut self, cancel: &AtomicBool) -> io::Result<FamilyState> {
        if self.invalidated {
            return Err(invalid(
                "Invocation lifetime coverage requires owner review.",
            ));
        }
        let result = self.observe_inner(cancel);
        if result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::InvalidData)
        {
            self.invalidated = true;
        }
        result
    }
    fn root_exit(&self, root: BorrowedHandle<'_>) -> io::Result<u32> {
        if process_identity(root)? != self.root_identity {
            return Err(invalid("Owned root creation identity changed."));
        }
        let mut code = 0;
        unsafe { GetExitCodeProcess(handle(root), &mut code) }.map_err(native)?;
        Ok(code)
    }
    fn observe_inner(&mut self, cancel: &AtomicBool) -> io::Result<FamilyState> {
        cancelled(cancel)?;
        self.owner.check()?;
        checked_limits(self.job.as_handle())?;
        if self.expected.boot_id() != crate::optimizer_boot::current()? {
            return Err(invalid("Invocation boot scope changed."));
        }
        if let Some(root) = &self.root {
            let exit = match unsafe { WaitForSingleObject(handle(root.as_handle()), 0) } {
                WAIT_OBJECT_0 => Some(self.root_exit(root.as_handle())?),
                WAIT_TIMEOUT => {
                    let live = (|| {
                        if process_identity(root.as_handle())? != self.root_identity
                            || principal(root.as_handle())? != self.expected
                        {
                            return Err(invalid("Owned root incarnation or token changed."));
                        }
                        crate::optimizer_pipe_security::helper_image::mapped_image(
                            root.as_handle(),
                            self.image.as_handle(),
                        )
                    })();
                    // Teardown may remove a mapping after the first zero wait.
                    // Only a fresh signaled retained handle can establish exit;
                    // known identity mismatches remain a permanent refusal.
                    let live = match live {
                        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                            return Err(error);
                        }
                        other => other,
                    };
                    match unsafe { WaitForSingleObject(handle(root.as_handle()), 0) } {
                        WAIT_OBJECT_0 => Some(self.root_exit(root.as_handle())?),
                        WAIT_TIMEOUT => {
                            live?;
                            None
                        }
                        _ => return Err(io::Error::last_os_error()),
                    }
                }
                _ => return Err(io::Error::last_os_error()),
            };
            if let Some(code) = exit {
                self.exit_code = Some(code);
                // Release our root reference after sealing native exit; never
                // reopen its PID. A descendant may still keep this job active.
                self.root = None;
            }
        }
        let counts = accounting(self.job.as_handle())?;
        if counts.TotalProcesses == 0 || (self.root.is_some() && counts.ActiveProcesses == 0) {
            return Err(invalid("Invocation job lost its root accounting."));
        }
        cancelled(cancel)?;
        Ok(FamilyState {
            active_processes: counts.ActiveProcesses,
            total_processes: counts.TotalProcesses,
            root_exited: self.exit_code.is_some(),
            root_exit_code: self.exit_code,
        })
    }
    /// The unsafe admission bound this invocation to its protected member/epoch.
    /// No caller-provided alive flag, PID reopen or serialized proof is accepted.
    pub(crate) fn activation_observation(
        &mut self,
        cancel: &AtomicBool,
    ) -> io::Result<ActivationObservation> {
        let state = self.observe(cancel)?;
        unsafe {
            ActivationObservation::from_native(
                self.member.clone(),
                self.invocation,
                self.instance,
                self.instance,
                !state.ended(),
            )
        }
        .map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests;
