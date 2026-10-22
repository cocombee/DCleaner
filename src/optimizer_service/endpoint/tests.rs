//! Actual serial endpoint -> bounded owner queue -> dispatch with only protected
//! disposable copies of the Rust test image. No installed helper/service/IFEO,
//! lease/effect readiness, original app launch or physical input is exercised.
use super::*;
mod image_probe;
mod lease_dispatch;
use std::{
    os::windows::{ffi::OsStrExt, process::CommandExt},
    path::Path,
    process::{Child, Command, Stdio},
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW,
};

fn protect(path: &Path) {
    let sid = Principal::current().unwrap().user_sid().unwrap();
    let descriptor = crate::optimizer_pipe_security::Descriptor::from_sddl(&format!(
        "O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)"
    ))
    .unwrap();
    let path: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    assert!(
        unsafe {
            SetFileSecurityW(
                PCWSTR(path.as_ptr()),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.native(),
            )
        }
        .as_bool()
    );
}
fn helper() -> (tempfile::TempDir, std::path::PathBuf, Arc<ProtectedHelper>) {
    let dir = tempfile::Builder::new()
        .prefix("optimizer-endpoint-helper-")
        .tempdir()
        .unwrap();
    let root = dir.path().join("protected");
    std::fs::create_dir(&root).unwrap();
    protect(&root);
    let path = root.join("DCleaner.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    protect(&path);
    let helper = ProtectedHelper::fixture(&path, &root, &AtomicBool::new(false)).unwrap();
    (dir, path, helper)
}
struct OwnedChild(Child);
impl OwnedChild {
    fn wait(&mut self) {
        assert!(self.status().success(), "private helper returned failure");
    }
    fn status(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "private helper failed to exit");
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
struct Endpoint {
    policy: Policy,
    name: Vec<u16>,
    cancel: Arc<AtomicBool>,
    requests: mpsc::Receiver<Exchange>,
    queue: mpsc::SyncSender<Exchange>,
    worker: Option<JoinHandle<io::Result<()>>>,
}
impl Endpoint {
    fn new(helper: Option<Arc<ProtectedHelper>>) -> Self {
        let (policy, pipe, name) = Policy::fixture_endpoint().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let (sender, requests) = mpsc::sync_channel(4);
        let queue = sender.clone();
        let server_policy = policy.clone();
        let stop = cancel.clone();
        let worker = thread::spawn(move || serve(server_policy, pipe, stop, sender, helper));
        Self {
            policy,
            name,
            cancel,
            requests,
            queue,
            worker: Some(worker),
        }
    }
    fn child(&self, path: &Path, expected: &str) -> OwnedChild {
        OwnedChild(
            Command::new(path)
                .args([
                    "--exact",
                    "optimizer_pipe_security::helper_image::tests::private_helper_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env(
                    "DCLEANER_PRIVATE_HELPER_PIPE",
                    String::from_utf16(&self.name[..self.name.len() - 1]).unwrap(),
                )
                .env("DCLEANER_PRIVATE_HELPER_OPERATION", "reactivate")
                .env("DCLEANER_PRIVATE_HELPER_EXPECT_REFUSAL", expected)
                .creation_flags(0x08000000)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    fn queued(&self) -> Exchange {
        self.requests.recv_timeout(Duration::from_secs(6)).unwrap()
    }
    fn finish(self) {
        self.finish_result().unwrap();
    }
    fn finish_result(mut self) -> io::Result<()> {
        self.cancel.store(true, Ordering::Release);
        let worker = self.worker.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(6);
        while !worker.is_finished() {
            assert!(
                Instant::now() < deadline,
                "endpoint did not drain cancellation"
            );
            thread::sleep(Duration::from_millis(5));
        }
        worker.join().unwrap()
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}
fn ledger(dir: &Path) -> Ledger {
    Ledger::open(rusqlite::Connection::open(dir.join("requests.db")).unwrap()).unwrap()
}
fn owner_reply(exchange: &Exchange, ledger: &Ledger, cancel: &AtomicBool) -> ResponseEnvelope {
    let directory = tempfile::tempdir().unwrap();
    let resources =
        Catalog::open(rusqlite::Connection::open(directory.path().join("resources.db")).unwrap())
            .unwrap();
    super::super::dispatch_exchange(exchange, Uuid::new_v4(), false, ledger, &resources, cancel)
        .unwrap()
}

#[test]
fn retained_helper_crosses_actual_endpoint_queue_and_is_rechecked_after_native_exit() {
    let (dir, path, helper) = helper();
    let ledger = ledger(dir.path());
    let endpoint = Endpoint::new(Some(helper));
    let mut child = endpoint.child(&path, "unknown_lease");
    let exchange = endpoint.queued();
    assert!(exchange.helper.is_some());
    exchange.revalidate(&AtomicBool::new(false)).unwrap();
    let response = owner_reply(&exchange, &ledger, &endpoint.cancel);
    assert_eq!(
        response.response,
        ServiceResponse::Refused {
            reason: Refusal::UnknownLease
        }
    );
    exchange.reply.send(response).unwrap();
    child.wait();
    assert_eq!(
        exchange.revalidate(&AtomicBool::new(false)),
        Err(Refusal::OwnershipChanged)
    );
    let late = owner_reply(&exchange, &ledger, &endpoint.cancel);
    assert_eq!(
        late.response,
        ServiceResponse::Refused {
            reason: Refusal::OwnershipChanged
        }
    );
    assert!(ledger.pending_for_review(64).unwrap().tickets.is_empty());
    endpoint.finish();
    eprintln!(
        "HELPER_QUEUE native_image=true live_process=true retained_through_dispatch=true exit_refused=true effects=false"
    );
}

#[test]
fn matching_account_and_frame_with_byte_identical_other_image_never_reach_owner_queue() {
    let (_dir, _path, helper) = helper();
    let endpoint = Endpoint::new(Some(helper));
    let mut child = endpoint.child(&std::env::current_exe().unwrap(), "ownership_changed");
    child.wait();
    assert!(matches!(
        endpoint.requests.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    // A rejected image does not kill/rebind the first listener; ordinary UI
    // readiness still uses the same serial endpoint and needs no helper image.
    let policy = endpoint.policy.clone();
    let name = endpoint.name.clone();
    let client = thread::spawn(move || {
        let cancel = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(6);
        let pipe = policy.fixture_connect(&name, deadline, &cancel).unwrap();
        super::super::client_exchange(
            pipe,
            deadline,
            &cancel,
            codec::RequestEnvelope {
                request_id: Uuid::new_v4(),
                request: HelperRequest::QueryReadiness {},
            },
        )
        .unwrap()
        .unwrap()
    });
    let exchange = endpoint.queued();
    assert!(exchange.helper.is_none());
    exchange.revalidate(&endpoint.cancel).unwrap();
    exchange
        .reply
        .send(ResponseEnvelope {
            request_id: exchange.request.request().request_id,
            response: ServiceResponse::Readiness {
                service_instance: Uuid::new_v4(),
                state: Readiness::Unavailable,
            },
        })
        .unwrap();
    assert!(matches!(
        client.join().unwrap().response,
        ServiceResponse::Readiness {
            state: Readiness::Unavailable,
            ..
        }
    ));
    endpoint.finish();
    eprintln!(
        "HELPER_QUEUE wrong_image_refused=true queue_unchanged=true first_listener_reused=true readonly_query=true"
    );
}

#[test]
fn queued_helper_expiry_and_owner_cancellation_refuse_without_durable_effect_admission() {
    for expire in [true, false] {
        let (dir, path, helper) = helper();
        let ledger = ledger(dir.path());
        let endpoint = Endpoint::new(Some(helper));
        let mut child = endpoint.child(&path, "not_ready");
        let mut exchange = endpoint.queued();
        exchange.revalidate(&endpoint.cancel).unwrap();
        let dispatch_cancel = AtomicBool::new(!expire);
        if expire {
            exchange.deadline = Instant::now() - Duration::from_millis(1);
        }
        assert_eq!(
            exchange.revalidate(&dispatch_cancel),
            Err(Refusal::ServiceNotReady)
        );
        let response = owner_reply(&exchange, &ledger, &dispatch_cancel);
        assert_eq!(
            response.response,
            ServiceResponse::Refused {
                reason: Refusal::ServiceNotReady
            }
        );
        exchange.reply.send(response).unwrap();
        child.wait();
        assert!(ledger.pending_for_review(64).unwrap().tickets.is_empty());
        endpoint.finish();
    }
    eprintln!(
        "HELPER_QUEUE expired_refused=true cancelled_refused=true durable_admission=false launch=false"
    );
}
