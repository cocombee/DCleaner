use super::*;
use crate::{
    optimizer_pipe_io::PipeIo,
    optimizer_protocol::{InvocationState, RequestEnvelope},
    optimizer_requests::Caller,
};
use std::{io::Write, os::windows::io::AsRawHandle};
use windows::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
    },
    System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    },
};

struct Fixture {
    policy: Policy,
    name: Vec<u16>,
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
    requests: Option<mpsc::Receiver<Exchange>>,
    resources: Catalog,
    _directory: tempfile::TempDir,
}
impl Fixture {
    fn new(queue: usize) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let resources = Catalog::open(
            rusqlite::Connection::open(directory.path().join("resources.db")).unwrap(),
        )
        .unwrap();
        let (policy, listener, name) = Policy::fixture_endpoint().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let stopped = cancel.clone();
        let (sender, receiver) = mpsc::sync_channel(queue);
        let service_policy = policy.clone();
        let thread =
            thread::spawn(move || endpoint::serve(service_policy, listener, stopped, sender, None));
        Self {
            policy,
            name,
            cancel,
            thread: Some(thread),
            requests: Some(receiver),
            resources,
            _directory: directory,
        }
    }
    fn client(&self, request: RequestEnvelope) -> JoinHandle<io::Result<Option<ResponseEnvelope>>> {
        let policy = self.policy.clone();
        let name = self.name.clone();
        thread::spawn(move || {
            let cancel = AtomicBool::new(false);
            let deadline = Instant::now() + Duration::from_secs(5);
            let pipe = policy.fixture_connect(&name, deadline, &cancel)?;
            client_exchange(pipe, deadline, &cancel, request)
        })
    }
    fn roundtrip(
        &self,
        operation: HelperRequest,
        review: bool,
        ledger: &Ledger,
        instance: Uuid,
    ) -> ServiceResponse {
        let request = RequestEnvelope {
            request_id: Uuid::new_v4(),
            request: operation,
        };
        let client = self.client(request.clone());
        let exchange = self
            .requests
            .as_ref()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        let actual = Caller::authenticated(&exchange.request).unwrap();
        let current = Principal::current().unwrap();
        assert_eq!(actual.account(), current.user_sid().unwrap());
        assert_eq!(actual.session(), current.session_id());
        assert_eq!(actual.logon_sid(), current.logon_sid().unwrap().as_deref());
        let response = dispatch_exchange(
            &exchange,
            instance,
            review,
            ledger,
            &self.resources,
            &self.cancel,
        )
        .unwrap();
        exchange.reply.send(response).unwrap();
        let response = client.join().unwrap().unwrap().unwrap();
        assert_eq!(response.request_id, request.request_id);
        response.response
    }
    fn finish(mut self) -> io::Result<()> {
        self.cancel.store(true, Ordering::Release);
        let thread = self.thread.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !thread.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            thread.is_finished(),
            "the owned fixture endpoint did not drain cancellation"
        );
        thread.join().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}

#[test]
fn scm_status_is_monotonic_and_stopped_is_reported_only_once() {
    let first = next_status(SERVICE_STATUS::default(), SERVICE_START_PENDING, 0).unwrap();
    assert_eq!(first.dwControlsAccepted, 0);
    assert_eq!(first.dwCheckPoint, 1);
    let starting = next_status(first, SERVICE_START_PENDING, 0).unwrap();
    assert_eq!(starting.dwCheckPoint, 2);
    let running = next_status(starting, SERVICE_RUNNING, 0).unwrap();
    assert_eq!(running.dwCheckPoint, 0);
    assert_ne!(running.dwControlsAccepted & SERVICE_ACCEPT_STOP, 0);
    assert!(next_status(running, SERVICE_START_PENDING, 0).is_none());
    let stopping = next_status(running, SERVICE_STOP_PENDING, 0).unwrap();
    assert_eq!(stopping.dwControlsAccepted, 0);
    assert!(next_status(stopping, SERVICE_RUNNING, 0).is_none());
    let stopped = next_status(stopping, SERVICE_STOPPED, 5).unwrap();
    assert_eq!(stopped.dwWin32ExitCode, 5);
    assert_eq!(stopped.dwWaitHint, 0);
    assert!(next_status(stopped, SERVICE_STOPPED, 5).is_none());
    assert!(next_status(stopped, SERVICE_START_PENDING, 0).is_none());
}

#[test]
fn serial_authenticated_requests_reuse_the_first_listener_without_effect_admission() {
    let directory = tempfile::tempdir().unwrap();
    let ledger =
        Ledger::open(rusqlite::Connection::open(directory.path().join("requests.db")).unwrap())
            .unwrap();
    let instance = Uuid::new_v4();
    let fixture = Fixture::new(4);
    for _ in 0..3 {
        assert_eq!(
            fixture.roundtrip(HelperRequest::QueryReadiness {}, false, &ledger, instance),
            ServiceResponse::Readiness {
                service_instance: instance,
                state: Readiness::Unavailable
            }
        );
        let invocation_id = Uuid::new_v4();
        assert_eq!(
            fixture.roundtrip(
                HelperRequest::Reactivate {
                    lease_id: Uuid::new_v4(),
                    invocation_id,
                    original: Box::new(crate::optimizer_protocol::OriginalContext::fixture()),
                },
                false,
                &ledger,
                instance
            ),
            ServiceResponse::Refused {
                reason: Refusal::ServiceNotReady
            }
        );
        assert_eq!(
            fixture.roundtrip(
                HelperRequest::QueryInvocation { invocation_id },
                false,
                &ledger,
                instance
            ),
            ServiceResponse::Invocation {
                invocation_id,
                state: InvocationState::Unknown
            }
        );
        let imposter = unsafe {
            CreateNamedPipeW(
                PCWSTR(fixture.name.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                8192,
                8192,
                0,
                None,
            )
        };
        if !imposter.is_invalid() {
            unsafe { windows::Win32::Foundation::CloseHandle(imposter) }.unwrap();
            panic!("listener identity was released between clients");
        }
    }
    assert!(ledger.pending_for_review(64).unwrap().tickets.is_empty());
    fixture.finish().unwrap();
}

#[test]
fn recovery_required_never_claims_ready_or_accepts_reactivation() {
    let directory = tempfile::tempdir().unwrap();
    let ledger =
        Ledger::open(rusqlite::Connection::open(directory.path().join("requests.db")).unwrap())
            .unwrap();
    let fixture = Fixture::new(2);
    let instance = Uuid::new_v4();
    assert_eq!(
        fixture.roundtrip(HelperRequest::QueryReadiness {}, true, &ledger, instance),
        ServiceResponse::Readiness {
            service_instance: instance,
            state: Readiness::RecoveryRequired
        }
    );
    assert_eq!(
        fixture.roundtrip(
            HelperRequest::Reactivate {
                lease_id: Uuid::new_v4(),
                invocation_id: Uuid::new_v4(),
                original: Box::new(crate::optimizer_protocol::OriginalContext::fixture()),
            },
            true,
            &ledger,
            instance
        ),
        ServiceResponse::Refused {
            reason: Refusal::RecoveryRequired
        }
    );
    assert!(ledger.pending_for_review(64).unwrap().tickets.is_empty());
    fixture.finish().unwrap();
}

#[test]
fn malformed_client_is_disconnected_before_another_authenticated_exchange() {
    let directory = tempfile::tempdir().unwrap();
    let ledger =
        Ledger::open(rusqlite::Connection::open(directory.path().join("requests.db")).unwrap())
            .unwrap();
    let fixture = Fixture::new(2);
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(5);
    let pipe = fixture
        .policy
        .fixture_connect(&fixture.name, deadline, &cancel)
        .unwrap();
    assert_ne!(pipe.as_raw_handle(), HANDLE::default().0);
    let mut pipe = unsafe { PipeIo::from_overlapped_byte_pipe(pipe, deadline, &cancel) };
    pipe.write_all(b"NOT-A-DCLEANER-FRAME").unwrap();
    drop(pipe);
    assert!(matches!(
        fixture
            .requests
            .as_ref()
            .unwrap()
            .recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert!(matches!(
        fixture.roundtrip(
            HelperRequest::QueryReadiness {},
            false,
            &ledger,
            Uuid::new_v4()
        ),
        ServiceResponse::Readiness {
            state: Readiness::Unavailable,
            ..
        }
    ));
    fixture.finish().unwrap();
}

#[test]
fn bounded_dispatch_queue_refuses_excess_without_claiming_acceptance() {
    let fixture = Fixture::new(0);
    let request = RequestEnvelope {
        request_id: Uuid::new_v4(),
        request: HelperRequest::Reactivate {
            lease_id: Uuid::new_v4(),
            invocation_id: Uuid::new_v4(),
            original: Box::new(crate::optimizer_protocol::OriginalContext::fixture()),
        },
    };
    let response = fixture.client(request).join().unwrap().unwrap().unwrap();
    assert_eq!(
        response.response,
        ServiceResponse::Refused {
            reason: Refusal::ServiceNotReady
        }
    );
    fixture.finish().unwrap();
}

#[test]
fn cancelled_idle_listener_and_lost_dispatcher_both_end() {
    Fixture::new(1).finish().unwrap();
    let mut fixture = Fixture::new(1);
    drop(fixture.requests.take());
    let client = fixture.client(RequestEnvelope {
        request_id: Uuid::new_v4(),
        request: HelperRequest::QueryReadiness {},
    });
    // Windows may surface EOF or ERROR_PIPE_NOT_CONNECTED after the server
    // closes an exchange without a response. Neither is an accepted request.
    assert!(!matches!(client.join().unwrap(), Ok(Some(_))));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fixture.thread.as_ref().unwrap().is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
    assert!(fixture.thread.as_ref().unwrap().is_finished());
    assert_eq!(
        fixture.finish().unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
}

#[test]
fn session_token_queries_cannot_run_under_an_ordinary_account() {
    assert!(Principal::logged_on_session(0).is_err());
    if Principal::require_local_system().is_err() {
        assert!(Principal::logged_on_session(Principal::current().unwrap().session_id()).is_err());
    }
}
