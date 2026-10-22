//! SCM host for the protected Optimizer owner and authenticated local queries.
//!
//! This host never advertises native optimization readiness while lease/effect
//! ownership is unfinished. It does not install/start/configure a service.
use crate::{
    optimizer_pipe_security::{
        AuthenticatedRequest, Policy, Principal, helper_image::ProtectedHelper,
    },
    optimizer_protocol::{
        self as codec, HelperRequest, Readiness, Refusal, ResponseEnvelope, ServiceResponse,
    },
    optimizer_requests::{Caller, Ledger},
    optimizer_resources::{Catalog, Error as ResourceError, leases::Selection},
    optimizer_storage::epoch::RuntimeOwner,
};
use std::{
    ffi::c_void,
    io,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU32, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use uuid::Uuid;
use windows::{
    Win32::{
        Foundation::{
            ERROR_CALL_NOT_IMPLEMENTED, ERROR_CTX_WINSTATION_NOT_FOUND, ERROR_GEN_FAILURE,
            ERROR_NO_SUCH_LOGON_SESSION, ERROR_NO_TOKEN,
        },
        System::{RemoteDesktop::*, Services::*},
    },
    core::{PCWSTR, PWSTR},
};
mod endpoint;
mod images;
mod registry;
use endpoint::Exchange;

enum Dispatch {
    Respond(ResponseEnvelope),
    Inspect(Selection),
}

const SERVICE_NAME: &str = "DCleanerOptimizer";
const MAX_SESSIONS: usize = 32;
const MAX_SESSION_ROWS: usize = 128;
const QUEUE_BOUND: usize = 64;
static CONTROL: OnceLock<Control> = OnceLock::new();
static EXIT_CODE: AtomicU32 = AtomicU32::new(0);

fn native(error: windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error((error.code().0 as u32 & 0xffff) as i32)
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

/// Read-only, authenticated readiness exchange for this Windows account/session.
/// Keep this native call on a worker. It never starts or installs the service.
pub fn query_current_session(
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<ResponseEnvelope> {
    if deadline.saturating_duration_since(Instant::now()) > Duration::from_secs(5) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Readiness probe exceeds its five-second budget.",
        ));
    }
    let policy = Policy::local_system(Principal::current()?)?;
    let pipe = policy.connect(deadline, cancel)?;
    client_exchange(
        pipe,
        deadline,
        cancel,
        codec::RequestEnvelope {
            request_id: Uuid::new_v4(),
            request: HelperRequest::QueryReadiness {},
        },
    )?
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Service closed before a readiness response.",
        )
    })
}

/// Protected-helper entry. Carries invocation data, never a selected executable
/// or a lease/effect permit. Endpoint authentication and owner lookup still apply.
pub(crate) fn reactivate_current_session(
    lease_id: Uuid,
    invocation_id: Uuid,
    original: codec::OriginalContext,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<ResponseEnvelope> {
    if deadline.saturating_duration_since(Instant::now()) > Duration::from_secs(5) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Helper exchange exceeds its budget.",
        ));
    }
    let request = codec::RequestEnvelope {
        request_id: Uuid::new_v4(),
        request: HelperRequest::Reactivate {
            lease_id,
            invocation_id,
            original: Box::new(original),
        },
    };
    let policy = Policy::local_system(Principal::current()?)?;
    let pipe = policy.connect(deadline, cancel)?;
    client_exchange(pipe, deadline, cancel, request)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Service closed before the helper response.",
        )
    })
}

fn client_exchange(
    handle: std::os::windows::io::OwnedHandle,
    deadline: Instant,
    cancel: &AtomicBool,
    request: codec::RequestEnvelope,
) -> io::Result<Option<ResponseEnvelope>> {
    let mut pipe = unsafe {
        crate::optimizer_pipe_io::PipeIo::from_overlapped_byte_pipe(handle, deadline, cancel)
    };
    codec::write_request(&mut pipe, &request).map_err(io::Error::other)?;
    // Closing after the complete response lets the server end this exchange
    // without discarding an unread reply or blocking on FlushFileBuffers.
    codec::read_response(&mut pipe, &request).map_err(io::Error::other)
}

/// Enter only through an explicitly configured SCM service command line.
/// Outside SCM this returns its native error without creating a window,
/// protected storage, pipe, service registration or native optimization effect.
pub fn run_dispatcher() -> io::Result<()> {
    let mut name = wide(SERVICE_NAME);
    let entries = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    unsafe { StartServiceCtrlDispatcherW(entries.as_ptr()) }.map_err(native)?;
    let code = EXIT_CODE.load(Ordering::Acquire);
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

struct NativeStatus {
    handle: usize,
    value: SERVICE_STATUS,
}
struct Control {
    stop: Arc<AtomicBool>,
    refresh: AtomicBool,
    status: Mutex<NativeStatus>,
}

/// Stopped is terminal: SCM must receive it once, after owner/worker cleanup.
fn next_status(
    previous: SERVICE_STATUS,
    state: SERVICE_STATUS_CURRENT_STATE,
    code: u32,
) -> Option<SERVICE_STATUS> {
    if previous.dwCurrentState == SERVICE_STOPPED {
        return None;
    }
    if state == SERVICE_START_PENDING
        && previous.dwCurrentState.0 != 0
        && previous.dwCurrentState != SERVICE_START_PENDING
    {
        return None;
    }
    if state == SERVICE_RUNNING && previous.dwCurrentState != SERVICE_START_PENDING {
        return None;
    }
    if previous.dwCurrentState == SERVICE_STOP_PENDING
        && state != SERVICE_STOP_PENDING
        && state != SERVICE_STOPPED
    {
        return None;
    }
    let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
    Some(SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE
        } else {
            0
        },
        dwWin32ExitCode: code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: if pending {
            if previous.dwCurrentState == state {
                previous.dwCheckPoint.saturating_add(1)
            } else {
                1
            }
        } else {
            0
        },
        dwWaitHint: if state == SERVICE_START_PENDING {
            30_000
        } else if pending {
            5_000
        } else {
            0
        },
    })
}
impl Control {
    fn report(&self, state: SERVICE_STATUS_CURRENT_STATE, code: u32) -> io::Result<()> {
        let mut status = self
            .status
            .lock()
            .map_err(|_| io::Error::other("Service status lock is poisoned."))?;
        if let Some(next) = next_status(status.value, state, code) {
            unsafe { SetServiceStatus(SERVICE_STATUS_HANDLE(status.handle as *mut c_void), &next) }
                .map_err(native)?;
            status.value = next;
        }
        Ok(())
    }
    fn interrogate(&self) -> io::Result<()> {
        let status = self
            .status
            .lock()
            .map_err(|_| io::Error::other("Service status lock is poisoned."))?;
        if status.value.dwCurrentState != SERVICE_STOPPED {
            unsafe {
                SetServiceStatus(
                    SERVICE_STATUS_HANDLE(status.handle as *mut c_void),
                    &status.value,
                )
            }
            .map_err(native)?;
        }
        Ok(())
    }
}
unsafe extern "system" fn handler(control: u32, _: u32, _: *mut c_void, _: *mut c_void) -> u32 {
    let Some(state) = CONTROL.get() else {
        return ERROR_GEN_FAILURE.0;
    };
    let result = match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            state.stop.store(true, Ordering::Release);
            state.report(SERVICE_STOP_PENDING, 0)
        }
        SERVICE_CONTROL_SESSIONCHANGE => {
            state.refresh.store(true, Ordering::Release);
            Ok(())
        }
        SERVICE_CONTROL_INTERROGATE => state.interrogate(),
        _ => return ERROR_CALL_NOT_IMPLEMENTED.0,
    };
    if result.is_ok() {
        0
    } else {
        state.stop.store(true, Ordering::Release);
        ERROR_GEN_FAILURE.0
    }
}
unsafe extern "system" fn service_main(_: u32, _: *mut PWSTR) {
    let name = wide(SERVICE_NAME);
    let handle = match unsafe {
        RegisterServiceCtrlHandlerExW(PCWSTR(name.as_ptr()), Some(handler), None)
    } {
        Ok(handle) => handle,
        Err(error) => {
            EXIT_CODE.store(
                native(error).raw_os_error().unwrap_or(31) as u32,
                Ordering::Release,
            );
            return;
        }
    };
    let state = Control {
        stop: Arc::new(AtomicBool::new(false)),
        refresh: AtomicBool::new(true),
        status: Mutex::new(NativeStatus {
            handle: handle.0 as usize,
            value: SERVICE_STATUS::default(),
        }),
    };
    if CONTROL.set(state).is_err() {
        std::process::abort();
    }
    // A panic cannot unwind across SCM's ABI or falsely publish clean shutdown.
    let result = std::panic::catch_unwind(|| {
        let control = CONTROL.get().expect("registered service control");
        let result = control
            .report(SERVICE_START_PENDING, 0)
            .and_then(|_| run_owner(control));
        let code = result
            .as_ref()
            .err()
            .and_then(io::Error::raw_os_error)
            .map(|v| v as u32)
            .unwrap_or(if result.is_ok() {
                0
            } else {
                ERROR_GEN_FAILURE.0
            });
        EXIT_CODE.store(code, Ordering::Release);
        if control.report(SERVICE_STOPPED, code).is_err() {
            std::process::abort();
        }
    });
    if result.is_err() {
        std::process::abort();
    }
}

struct Worker {
    principal: Principal,
    cancel: Arc<AtomicBool>,
    thread: JoinHandle<io::Result<()>>,
    retiring: bool,
}
impl Worker {
    fn start(
        principal: Principal,
        requests: mpsc::SyncSender<Exchange>,
        helper: Option<Arc<ProtectedHelper>>,
    ) -> io::Result<Self> {
        let policy = Policy::local_system(principal.clone())?;
        let pipe = policy.bind_first()?;
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        let thread = thread::Builder::new()
            .name("optimizer-client".into())
            .spawn(move || endpoint::serve(policy, pipe, stop, requests, helper))?;
        Ok(Self {
            principal,
            cancel,
            thread,
            retiring: false,
        })
    }
    fn retire(&mut self) {
        self.retiring = true;
        self.cancel.store(true, Ordering::Release);
    }
}

fn run_owner(control: &Control) -> io::Result<()> {
    let mut owner = RuntimeOwner::for_service()?;
    // One fixed machine helper, shared across session listeners. Failure keeps
    // read-only queries available; no caller path or user-install fallback can
    // supply the protected helper. Its live image/process is checked again on
    // each reactivation connection and at owner dispatch, not on every query.
    let helper = ProtectedHelper::for_service(&control.stop).ok();
    let (sender, receiver) = mpsc::sync_channel(QUEUE_BOUND);
    let mut workers = Vec::new();
    let mut probes = Vec::new();
    let mut result = owner_loop(
        control,
        &mut owner,
        &sender,
        &receiver,
        &mut workers,
        &mut probes,
        helper.as_ref(),
    );
    control.stop.store(true, Ordering::Release);
    for worker in &mut workers {
        worker.retire();
    }
    let mut checkpoint = Instant::now() - Duration::from_secs(2);
    while workers.iter().any(|worker| !worker.thread.is_finished())
        || probes.iter().any(|probe| !probe.is_finished())
    {
        if checkpoint.elapsed() >= Duration::from_secs(1) {
            if let Err(error) = control.report(SERVICE_STOP_PENDING, 0) {
                result = Err(error);
            }
            checkpoint = Instant::now();
        }
        thread::sleep(Duration::from_millis(25));
    }
    for worker in workers {
        match worker.thread.join() {
            Ok(Ok(())) => (),
            Ok(Err(error)) => {
                if result.is_ok() {
                    result = Err(error);
                }
            }
            Err(_) => result = Err(io::Error::other("A service endpoint panicked.")),
        }
    }
    for probe in probes {
        if probe.join().is_err() {
            result = Err(io::Error::other("A selected-image worker panicked."));
        }
    }
    // The protected epoch stays owned until all endpoint/image work has ended.
    drop(owner);
    result
}
fn owner_loop(
    control: &Control,
    owner: &mut RuntimeOwner,
    sender: &mpsc::SyncSender<Exchange>,
    receiver: &mpsc::Receiver<Exchange>,
    workers: &mut Vec<Worker>,
    probes: &mut Vec<JoinHandle<()>>,
    helper: Option<&Arc<ProtectedHelper>>,
) -> io::Result<()> {
    control.refresh.store(false, Ordering::Release);
    refresh_workers(workers, &session_principals()?, sender, helper)?;
    control.report(SERVICE_RUNNING, 0)?;
    let mut refreshed = Instant::now();
    while !control.stop.load(Ordering::Acquire) {
        let mut probe_index = 0;
        while probe_index < probes.len() {
            if probes[probe_index].is_finished() {
                if probes.swap_remove(probe_index).join().is_err() {
                    return Err(io::Error::other("A selected-image worker panicked."));
                }
            } else {
                probe_index += 1;
            }
        }
        let mut index = 0;
        while index < workers.len() {
            if !workers[index].thread.is_finished() {
                index += 1;
                continue;
            }
            let worker = workers.swap_remove(index);
            match worker.thread.join() {
                Ok(Ok(())) if worker.retiring => control.refresh.store(true, Ordering::Release),
                Ok(Err(error)) => return Err(error),
                _ => return Err(io::Error::other("A service endpoint ended unexpectedly.")),
            }
        }
        if control.refresh.swap(false, Ordering::AcqRel)
            || refreshed.elapsed() >= Duration::from_secs(30)
        {
            refresh_workers(workers, &session_principals()?, sender, helper)?;
            refreshed = Instant::now();
        }
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(exchange) => {
                if control.stop.load(Ordering::Acquire) {
                    break;
                }
                // A valid message can wait in this queue across logoff/session
                // reuse. Re-read WTS identity before dispatch, not just refresh
                // listeners periodically. Failure grants no dispatch authority.
                if !exchange
                    .request
                    .caller()
                    .is_current_logged_on_session()
                    .unwrap_or(false)
                {
                    let _ = exchange.reply.try_send(ResponseEnvelope {
                        request_id: exchange.request.request().request_id,
                        response: ServiceResponse::Refused {
                            reason: Refusal::NotAuthorized,
                        },
                    });
                    continue;
                }
                let instance = owner.instance();
                let (ledger, journal, resources) = owner.dispatch_stores();
                let review = resources
                    .requires_review(instance)
                    .map_err(io::Error::other)?
                    || ledger.requires_review().map_err(io::Error::other)?
                    || journal.requires_review().map_err(io::Error::other)?;
                let decision = dispatch_step(
                    &exchange,
                    instance,
                    review,
                    ledger,
                    resources,
                    &control.stop,
                    exchange.inspection.as_ref(),
                )?;
                match decision {
                    Dispatch::Respond(response) => {
                        let _ = exchange.reply.try_send(response);
                    }
                    Dispatch::Inspect(selection) if probes.len() < MAX_SESSIONS => {
                        probes.push(images::start(
                            exchange,
                            selection,
                            sender.clone(),
                            control.stop.clone(),
                        )?);
                    }
                    Dispatch::Inspect(_) => {
                        let _ = exchange.reply.try_send(ResponseEnvelope {
                            request_id: exchange.request.request().request_id,
                            response: ServiceResponse::Refused {
                                reason: Refusal::ServiceNotReady,
                            },
                        });
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("Service request queue ended."));
            }
        }
    }
    Ok(())
}

fn dispatch_step(
    exchange: &Exchange,
    instance: Uuid,
    review: bool,
    ledger: &Ledger,
    resources: &Catalog,
    cancel: &AtomicBool,
    inspection: Option<&Result<images::SelectedImages, Refusal>>,
) -> io::Result<Dispatch> {
    // Recovery refuses effects independently of helper availability. Preserve
    // that existing refusal, but never dispatch a late/cancelled query or use a
    // stale helper observation as native lease authority.
    let recovery = review
        && matches!(
            exchange.request.request().request,
            HelperRequest::Reactivate { .. }
        );
    let validation = exchange.revalidate(cancel);
    if let Err(reason) = validation {
        return Ok(Dispatch::Respond(ResponseEnvelope {
            request_id: exchange.request.request().request_id,
            response: ServiceResponse::Refused {
                reason: if recovery {
                    Refusal::RecoveryRequired
                } else {
                    reason
                },
            },
        }));
    }
    let response = if matches!(
        exchange.request.request().request,
        HelperRequest::Reactivate { .. }
    ) && !review
    {
        let reason = match resolve_selection(&exchange.request, resources)? {
            Err(reason) => reason,
            Ok(selection) => match inspection {
                None => {
                    if exchange.check_budget(cancel).is_ok() {
                        return Ok(Dispatch::Inspect(selection));
                    }
                    Refusal::ServiceNotReady
                }
                Some(Err(reason)) => *reason,
                Some(Ok(observed)) => {
                    let HelperRequest::Reactivate { original, .. } =
                        &exchange.request.request().request
                    else {
                        unreachable!()
                    };
                    match observed.matches(&selection, original) {
                        Ok(true) => Refusal::ServiceNotReady,
                        Ok(false) => Refusal::OwnershipChanged,
                        Err(reason) => reason,
                    }
                }
            },
        };
        ResponseEnvelope {
            request_id: exchange.request.request().request_id,
            response: ServiceResponse::Refused { reason },
        }
    } else {
        dispatch(&exchange.request, instance, review, ledger, resources)?
    };
    Ok(Dispatch::Respond(finish_dispatch(
        exchange, recovery, response, cancel,
    )))
}

// Synchronous adapter for existing fixture callers. Production uses the bounded
// worker/owner queue above; both paths share every dispatch stage/check.
#[cfg(test)]
fn dispatch_exchange(
    exchange: &Exchange,
    instance: Uuid,
    review: bool,
    ledger: &Ledger,
    resources: &Catalog,
    cancel: &AtomicBool,
) -> io::Result<ResponseEnvelope> {
    match dispatch_step(
        exchange,
        instance,
        review,
        ledger,
        resources,
        cancel,
        exchange.inspection.as_ref(),
    )? {
        Dispatch::Respond(response) => Ok(response),
        Dispatch::Inspect(selection) => {
            let inspection = images::SelectedImages::observe(exchange, selection, cancel);
            match dispatch_step(
                exchange,
                instance,
                review,
                ledger,
                resources,
                cancel,
                Some(&inspection),
            )? {
                Dispatch::Respond(response) => Ok(response),
                Dispatch::Inspect(_) => Err(io::Error::other(
                    "Image observation did not advance dispatch.",
                )),
            }
        }
    }
}
fn finish_dispatch(
    exchange: &Exchange,
    recovery: bool,
    response: ResponseEnvelope,
    cancel: &AtomicBool,
) -> ResponseEnvelope {
    // SQLite lookup is bounded but can wait on another owner/fixture writer.
    // A late/cancelled result never outlives the original exchange budget.
    if let Err(reason) = exchange.check_budget(cancel) {
        return ResponseEnvelope {
            request_id: exchange.request.request().request_id,
            response: ServiceResponse::Refused {
                reason: if recovery {
                    Refusal::RecoveryRequired
                } else {
                    reason
                },
            },
        };
    }
    response
}
fn dispatch(
    request: &AuthenticatedRequest,
    instance: Uuid,
    review: bool,
    ledger: &Ledger,
    resources: &Catalog,
) -> io::Result<ResponseEnvelope> {
    let response = match &request.request().request {
        HelperRequest::QueryReadiness {} => ServiceResponse::Readiness {
            service_instance: instance,
            state: if review {
                Readiness::RecoveryRequired
            } else {
                Readiness::Unavailable
            },
        },
        HelperRequest::QueryInvocation { .. } => ledger
            .query_authenticated(request)
            .map_err(io::Error::other)?,
        HelperRequest::Reactivate { .. } => ServiceResponse::Refused {
            reason: if review {
                Refusal::RecoveryRequired
            } else {
                match resolve_selection(request, resources)? {
                    // This is only a scoped data selection. Native image,
                    // resource, hook, context and effect owners remain missing;
                    // neither lookup success nor these UUIDs can admit work.
                    Ok(_selection) => Refusal::ServiceNotReady,
                    Err(reason) => reason,
                }
            },
        },
    };
    Ok(ResponseEnvelope {
        request_id: request.request().request_id,
        response,
    })
}

fn resolve_selection(
    request: &AuthenticatedRequest,
    resources: &Catalog,
) -> io::Result<Result<Selection, Refusal>> {
    let HelperRequest::Reactivate { lease_id, .. } = request.request().request else {
        return Ok(Err(Refusal::NotAuthorized));
    };
    let caller = Caller::authenticated(request).map_err(io::Error::other)?;
    match resources.lease_selection(&caller, lease_id) {
        Ok(Some(selection)) => Ok(Ok(selection)),
        Ok(None) => Ok(Err(Refusal::UnknownLease)),
        Err(ResourceError::NotAuthorized) => Ok(Err(Refusal::NotAuthorized)),
        Err(ResourceError::Changed | ResourceError::Missing | ResourceError::Stale) => {
            Ok(Err(Refusal::OwnershipChanged))
        }
        // Unexpected storage/schema/data failures stop the owner without a
        // fabricated response, admission, automatic replay or native effect.
        Err(error) => Err(io::Error::other(error)),
    }
}
fn refresh_workers(
    workers: &mut Vec<Worker>,
    wanted: &[Principal],
    sender: &mpsc::SyncSender<Exchange>,
    helper: Option<&Arc<ProtectedHelper>>,
) -> io::Result<()> {
    for worker in workers.iter_mut() {
        if !wanted.contains(&worker.principal) {
            worker.retire();
        }
    }
    for principal in wanted {
        if workers.iter().any(|worker| &worker.principal == principal) {
            continue;
        }
        // Retiring calls keep their slot until native cancellation drains.
        if workers.len() == MAX_SESSIONS {
            continue;
        }
        workers.push(Worker::start(
            principal.clone(),
            sender.clone(),
            helper.cloned(),
        )?);
    }
    Ok(())
}
fn session_principals() -> io::Result<Vec<Principal>> {
    Principal::require_local_system()?;
    let mut rows = std::ptr::null_mut();
    let mut count = 0;
    unsafe { WTSEnumerateSessionsW(None, 0, 1, &mut rows, &mut count) }.map_err(native)?;
    struct Sessions(*mut WTS_SESSION_INFOW);
    impl Drop for Sessions {
        fn drop(&mut self) {
            unsafe { WTSFreeMemory(self.0.cast()) };
        }
    }
    let allocation = Sessions(rows);
    if count as usize > MAX_SESSION_ROWS || (count > 0 && rows.is_null()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows session inventory exceeds its bound.",
        ));
    }
    let mut clients = Vec::new();
    if count == 0 {
        return Ok(clients);
    }
    for row in unsafe { std::slice::from_raw_parts(allocation.0, count as usize) } {
        if row.SessionId == 0 || ![WTSActive, WTSConnected, WTSDisconnected].contains(&row.State) {
            continue;
        }
        match Principal::logged_on_session(row.SessionId) {
            Ok(client) => {
                if !clients.contains(&client) {
                    clients.push(client);
                }
                if clients.len() > MAX_SESSIONS {
                    return Err(io::Error::other("Too many logged-on Optimizer sessions."));
                }
            }
            // Enumeration and token lookup are not atomic. A session can log
            // off between them; absence does not grant any client identity.
            Err(error)
                if [
                    ERROR_NO_TOKEN.0,
                    ERROR_NO_SUCH_LOGON_SESSION.0,
                    ERROR_CTX_WINSTATION_NOT_FOUND.0,
                ]
                .iter()
                .any(|code| error.raw_os_error() == Some(*code as i32)) =>
            {
                ()
            }
            Err(error) => return Err(error),
        }
    }
    Ok(clients)
}

#[cfg(test)]
mod tests;
