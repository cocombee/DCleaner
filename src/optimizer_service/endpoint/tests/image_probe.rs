//! Real private helper/pipe/queue + native image worker, without native effects.
use super::lease_dispatch::{bind, catalog, no_admission, readonly_request};
use super::*;
use crate::{
    optimizer_identity,
    optimizer_requests::Caller,
    optimizer_service::{Dispatch, dispatch_step, images},
};

fn selected_copy(directory: &Path) -> std::path::PathBuf {
    let path = directory.join("selected fixture.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    path
}
fn first(exchange: &Exchange, ledger: &Ledger, resources: &Catalog) -> Selection {
    match dispatch_step(
        exchange,
        Uuid::new_v4(),
        false,
        ledger,
        resources,
        &AtomicBool::new(false),
        None,
    )
    .unwrap()
    {
        Dispatch::Inspect(selection) => selection,
        Dispatch::Respond(_) => panic!("valid selected data must request a worker observation"),
    }
}
fn completed(
    exchange: &Exchange,
    ledger: &Ledger,
    resources: &Catalog,
    review: bool,
    stop: &AtomicBool,
) -> ResponseEnvelope {
    match dispatch_step(
        exchange,
        Uuid::new_v4(),
        review,
        ledger,
        resources,
        stop,
        exchange.inspection.as_ref(),
    )
    .unwrap()
    {
        Dispatch::Respond(response) => response,
        Dispatch::Inspect(_) => {
            panic!("completed worker must not recursively request another probe")
        }
    }
}

#[test]
fn image_worker_returns_the_same_authenticated_exchange_and_retains_native_file_until_drop() {
    let (directory, helper_path, helper) = helper();
    let ledger = ledger(directory.path());
    let mut resources = catalog(&directory.path().join("resources.db"));
    let endpoint = Endpoint::new(Some(helper));
    let mut child = endpoint.child(&helper_path, "not_ready");
    let exchange = endpoint.queued();
    let request_id = exchange.request.request().request_id;
    let caller = Caller::authenticated(&exchange.request).unwrap();
    let path = selected_copy(directory.path());
    assert!(std::fs::OpenOptions::new().write(true).open(&path).is_ok());
    let snapshot = optimizer_identity::inspect(&path, &endpoint.cancel).unwrap();
    let (_, id, _) = bind(&mut resources, &exchange, &caller, snapshot);
    let selection = first(&exchange, &ledger, &resources);
    let worker = images::start(
        exchange,
        selection,
        endpoint.queue.clone(),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let exchange = endpoint.queued();
    worker.join().unwrap();
    assert_eq!(exchange.request.request().request_id, request_id);
    assert!(exchange.helper.is_some());
    assert!(exchange.inspection.as_ref().is_some_and(Result::is_ok));
    assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
    let response = completed(
        &exchange,
        &ledger,
        &resources,
        false,
        &AtomicBool::new(false),
    );
    assert_eq!(
        response.response,
        ServiceResponse::Refused {
            reason: Refusal::ServiceNotReady
        }
    );
    exchange.reply.send(response).unwrap();
    drop(exchange);
    assert!(std::fs::OpenOptions::new().write(true).open(&path).is_ok());
    child.wait();
    no_admission(&directory.path().join("requests.db"), &ledger);
    assert_eq!(
        resources.inspect(&id).unwrap().unwrap().phase,
        crate::optimizer_resources::Phase::Awake
    );
    endpoint.finish();
}

#[test]
fn owner_answers_actual_readonly_query_while_selected_image_worker_is_withheld() {
    let (directory, helper_path, helper) = helper();
    let ledger = ledger(directory.path());
    let mut resources = catalog(&directory.path().join("resources.db"));
    let endpoint = Endpoint::new(Some(helper));
    let mut child = endpoint.child(&helper_path, "not_ready");
    let exchange = endpoint.queued();
    let caller = Caller::authenticated(&exchange.request).unwrap();
    let path = selected_copy(directory.path());
    bind(
        &mut resources,
        &exchange,
        &caller,
        optimizer_identity::inspect(&path, &endpoint.cancel).unwrap(),
    );
    let selection = first(&exchange, &ledger, &resources);
    let (started, ready) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let worker = images::start_with(
        exchange,
        selection,
        endpoint.queue.clone(),
        Arc::new(AtomicBool::new(false)),
        move |exchange, selection, stop| {
            started.send(()).unwrap();
            held.recv_timeout(Duration::from_secs(5)).unwrap();
            images::SelectedImages::observe(exchange, selection, stop)
        },
    )
    .unwrap();
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(!worker.is_finished());
    let readonly = Endpoint::new(None);
    assert!(matches!(
        readonly_request(
            &readonly,
            &ledger,
            &resources,
            HelperRequest::QueryReadiness {}
        ),
        ServiceResponse::Readiness {
            state: Readiness::Unavailable,
            ..
        }
    ));
    assert!(!worker.is_finished());
    release.send(()).unwrap();
    let exchange = endpoint.queued();
    worker.join().unwrap();
    exchange
        .reply
        .send(completed(
            &exchange,
            &ledger,
            &resources,
            false,
            &AtomicBool::new(false),
        ))
        .unwrap();
    drop(exchange);
    child.wait();
    readonly.finish();
    endpoint.finish();
}

#[test]
fn native_image_mismatch_and_post_worker_lease_retirement_never_admit() {
    let (directory, helper_path, helper) = helper();
    let ledger = ledger(directory.path());
    for mode in ["image", "retired", "recovery"] {
        let mut resources = catalog(&directory.path().join(format!("{mode}.db")));
        let endpoint = Endpoint::new(Some(helper.clone()));
        let expected = match mode {
            "image" => Refusal::OwnershipChanged,
            "retired" => Refusal::UnknownLease,
            _ => Refusal::RecoveryRequired,
        };
        let mut child = endpoint.child(
            &helper_path,
            match mode {
                "image" => "ownership_changed",
                "retired" => "unknown_lease",
                _ => "recovery_required",
            },
        );
        let exchange = endpoint.queued();
        let caller = Caller::authenticated(&exchange.request).unwrap();
        let lease = match exchange.request.request().request {
            HelperRequest::Reactivate { lease_id, .. } => lease_id,
            _ => unreachable!(),
        };
        let path = directory.path().join(format!("{mode}.exe"));
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let mut snapshot = optimizer_identity::inspect(&path, &endpoint.cancel).unwrap();
        if mode != "retired" {
            let replacement = if snapshot.sha256.starts_with('0') {
                "1"
            } else {
                "0"
            };
            snapshot.sha256.replace_range(0..1, replacement);
        }
        let (_, _, revision) = bind(&mut resources, &exchange, &caller, snapshot);
        let selection = first(&exchange, &ledger, &resources);
        let worker = images::start(
            exchange,
            selection,
            endpoint.queue.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let exchange = endpoint.queued();
        worker.join().unwrap();
        if mode == "retired" {
            resources.retire_lease(&caller, lease, revision).unwrap();
        }
        let response = completed(
            &exchange,
            &ledger,
            &resources,
            mode == "recovery",
            &AtomicBool::new(false),
        );
        assert_eq!(
            response.response,
            ServiceResponse::Refused { reason: expected }
        );
        exchange.reply.send(response).unwrap();
        drop(exchange);
        child.wait();
        no_admission(&directory.path().join("requests.db"), &ledger);
        endpoint.finish();
    }
}

#[test]
fn image_result_queue_pressure_drops_retained_files_and_refuses_without_effects() {
    let (directory, helper_path, helper) = helper();
    let ledger = ledger(directory.path());
    let mut resources = catalog(&directory.path().join("resources.db"));
    let endpoint = Endpoint::new(Some(helper));
    let mut child = endpoint.child(&helper_path, "not_ready");
    let exchange = endpoint.queued();
    let caller = Caller::authenticated(&exchange.request).unwrap();
    let path = selected_copy(directory.path());
    bind(
        &mut resources,
        &exchange,
        &caller,
        optimizer_identity::inspect(&path, &endpoint.cancel).unwrap(),
    );
    let selection = first(&exchange, &ledger, &resources);
    let (full, _receiver) = mpsc::sync_channel(0);
    images::start(exchange, selection, full, Arc::new(AtomicBool::new(false)))
        .unwrap()
        .join()
        .unwrap();
    child.wait();
    assert!(std::fs::OpenOptions::new().write(true).open(path).is_ok());
    no_admission(&directory.path().join("requests.db"), &ledger);
    endpoint.finish();
}

#[test]
fn selected_image_work_preserves_original_deadline_and_service_cancellation() {
    let (directory, helper_path, helper) = helper();
    let ledger = ledger(directory.path());
    for expired in [false, true] {
        let mut resources = catalog(&directory.path().join(format!("cancel-{expired}.db")));
        let endpoint = Endpoint::new(Some(helper.clone()));
        let mut child = endpoint.child(&helper_path, "not_ready");
        let mut exchange = endpoint.queued();
        let caller = Caller::authenticated(&exchange.request).unwrap();
        let path = directory.path().join(format!("cancel-{expired}.exe"));
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        bind(
            &mut resources,
            &exchange,
            &caller,
            optimizer_identity::inspect(&path, &endpoint.cancel).unwrap(),
        );
        let selection = first(&exchange, &ledger, &resources);
        let stop = Arc::new(AtomicBool::new(!expired));
        if expired {
            exchange.deadline = Instant::now() - Duration::from_millis(1);
        }
        let worker =
            images::start(exchange, selection, endpoint.queue.clone(), stop.clone()).unwrap();
        let exchange = endpoint.queued();
        worker.join().unwrap();
        assert!(matches!(
            exchange.inspection,
            Some(Err(Refusal::ServiceNotReady))
        ));
        assert_eq!(
            completed(&exchange, &ledger, &resources, false, &stop).response,
            ServiceResponse::Refused {
                reason: Refusal::ServiceNotReady
            }
        );
        exchange
            .reply
            .send(completed(&exchange, &ledger, &resources, false, &stop))
            .unwrap();
        drop(exchange);
        child.wait();
        assert!(std::fs::OpenOptions::new().write(true).open(path).is_ok());
        no_admission(&directory.path().join("requests.db"), &ledger);
        endpoint.finish();
    }
}
