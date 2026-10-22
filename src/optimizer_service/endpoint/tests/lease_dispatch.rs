//! Real fixture pipe/helper/queue dispatch with explicitly synthetic component
//! associations. No service installation, native maintenance or original launch.
use super::*;
use crate::{
    optimizer_identity,
    optimizer_requests::Caller,
    optimizer_resources::{Member, Observation, ResourceId, leases::Selection},
};

pub(super) fn catalog(path: &Path) -> Catalog {
    Catalog::open(rusqlite::Connection::open(path).unwrap()).unwrap()
}
fn ids(exchange: &Exchange) -> (Uuid, Uuid) {
    if let HelperRequest::Reactivate { original, .. } = &exchange.request.request().request {
        assert_eq!(original.as_ref(), &codec::OriginalContext::fixture());
        original.validate().unwrap();
    }
    match exchange.request.request().request {
        HelperRequest::Reactivate {
            lease_id,
            invocation_id,
            ..
        } => (lease_id, invocation_id),
        _ => panic!("reactivation fixture only"),
    }
}
pub(super) fn bind(
    resources: &mut Catalog,
    exchange: &Exchange,
    caller: &Caller,
    image: optimizer_identity::ImageSnapshot,
) -> (Member, ResourceId, Uuid) {
    let member = Member::for_caller(caller, "program:v1:hkcu:64:6469737061746368").unwrap();
    let id = unsafe { ResourceId::from_native(1, b"synthetic dispatch association") }.unwrap();
    let observation = unsafe {
        Observation::from_native(
            id.clone(),
            Uuid::new_v4(),
            b"baseline".to_vec(),
            vec![member.clone()],
            true,
        )
    }
    .unwrap();
    resources
        .register(observation, b"sleeping".to_vec())
        .unwrap();
    let revision = Uuid::new_v4();
    let selected = Selection::from_owner_selection(
        caller,
        member.clone(),
        ids(exchange).0,
        revision,
        vec![image],
        vec![id.clone()],
    )
    .unwrap();
    resources.register_lease(caller, selected).unwrap();
    (member, id, revision)
}
pub(super) fn no_admission(path: &Path, ledger: &Ledger) {
    assert!(ledger.pending_for_review(64).unwrap().tickets.is_empty());
    assert_eq!(
        rusqlite::Connection::open(path)
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM invocations", [], |r| r.get(0))
            .unwrap(),
        0
    );
}
fn reply(
    endpoint: &Endpoint,
    exchange: &Exchange,
    ledger: &Ledger,
    resources: &Catalog,
    review: bool,
) -> ResponseEnvelope {
    super::super::super::dispatch_exchange(
        exchange,
        Uuid::new_v4(),
        review,
        ledger,
        resources,
        &endpoint.cancel,
    )
    .unwrap()
}

pub(super) fn readonly_request(
    endpoint: &Endpoint,
    ledger: &Ledger,
    resources: &Catalog,
    operation: HelperRequest,
) -> ServiceResponse {
    let policy = endpoint.policy.clone();
    let name = endpoint.name.clone();
    let client = thread::spawn(move || {
        let cancel = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(5);
        let pipe = policy.fixture_connect(&name, deadline, &cancel).unwrap();
        super::super::super::client_exchange(
            pipe,
            deadline,
            &cancel,
            codec::RequestEnvelope {
                request_id: Uuid::new_v4(),
                request: operation,
            },
        )
        .unwrap()
        .unwrap()
    });
    let exchange = endpoint.queued();
    let response = reply(endpoint, &exchange, ledger, resources, false);
    exchange.reply.send(response).unwrap();
    client.join().unwrap().response
}

#[test]
fn authenticated_helper_resolves_exact_selection_without_admission_or_launch() {
    let (directory, path, helper) = helper();
    let ledger = ledger(directory.path());
    let mut resources = catalog(&directory.path().join("resources.db"));
    let endpoint = Endpoint::new(Some(helper));
    let mut child = endpoint.child(&path, "not_ready");
    let exchange = endpoint.queued();
    exchange.revalidate(&endpoint.cancel).unwrap();
    let caller = Caller::authenticated(&exchange.request).unwrap();
    let image =
        optimizer_identity::inspect(&std::env::current_exe().unwrap(), &endpoint.cancel).unwrap();
    let (member, id, revision) = bind(&mut resources, &exchange, &caller, image.clone());
    let selected = super::super::super::resolve_selection(&exchange.request, &resources)
        .unwrap()
        .unwrap();
    assert_eq!(selected.lease(), ids(&exchange).0);
    assert_eq!(selected.revision(), revision);
    assert_eq!(selected.member(), &member);
    assert_eq!(selected.images(), &[image]);
    assert_eq!(selected.resources(), vec![id.clone()]);
    let response = reply(&endpoint, &exchange, &ledger, &resources, false);
    assert_eq!(
        response.response,
        ServiceResponse::Refused {
            reason: Refusal::ServiceNotReady
        }
    );
    exchange.reply.send(response).unwrap();
    child.wait();
    assert!(matches!(
        readonly_request(
            &endpoint,
            &ledger,
            &resources,
            HelperRequest::QueryReadiness {}
        ),
        ServiceResponse::Readiness {
            state: Readiness::Unavailable,
            ..
        }
    ));
    assert_eq!(
        readonly_request(
            &endpoint,
            &ledger,
            &resources,
            HelperRequest::QueryInvocation {
                invocation_id: ids(&exchange).1
            }
        ),
        ServiceResponse::Invocation {
            invocation_id: ids(&exchange).1,
            state: crate::optimizer_protocol::InvocationState::Unknown
        }
    );
    no_admission(&directory.path().join("requests.db"), &ledger);
    assert_eq!(
        resources.inspect(&id).unwrap().unwrap().phase,
        crate::optimizer_resources::Phase::Awake
    );
    endpoint.finish();
    eprintln!(
        "LEASE_DISPATCH authenticated=true exact_selection=true admitted=false original_launch=false"
    );
}

#[test]
fn authenticated_dispatch_rejects_foreign_retired_and_changed_associations() {
    let (directory, path, helper) = helper();
    let image =
        optimizer_identity::inspect(&std::env::current_exe().unwrap(), &AtomicBool::new(false))
            .unwrap();
    for (mode, expected, child_reason) in [
        ("foreign", Refusal::NotAuthorized, "not_authorized"),
        ("retired", Refusal::UnknownLease, "unknown_lease"),
        ("changed", Refusal::OwnershipChanged, "ownership_changed"),
    ] {
        let ledger = ledger(directory.path());
        let database = directory.path().join(format!("resources-{mode}.db"));
        let mut resources = catalog(&database);
        let endpoint = Endpoint::new(Some(helper.clone()));
        let mut child = endpoint.child(&path, child_reason);
        let exchange = endpoint.queued();
        let caller = Caller::authenticated(&exchange.request).unwrap();
        let owner = if mode == "foreign" {
            Caller::fixture_boot(
                caller.account(),
                caller.session(),
                caller.logon_sid().unwrap(),
                Uuid::new_v4(),
            )
        } else {
            caller.clone()
        };
        let (_, _, revision) = bind(&mut resources, &exchange, &owner, image.clone());
        if mode == "retired" {
            resources
                .retire_lease(&caller, ids(&exchange).0, revision)
                .unwrap();
        }
        if mode == "changed" {
            // External database interference, never a native component change.
            let connection = rusqlite::Connection::open(&database).unwrap();
            let raw: String = connection
                .query_row("SELECT members FROM resources", [], |r| r.get(0))
                .unwrap();
            // Preserve the canonical serializer's key order; a reserialized
            // generic Value is intentionally rejected as corrupt elsewhere.
            let changed = raw.replace(
                "program:v1:hkcu:64:6469737061746368",
                "program:v1:hkcu:64:6368616e676564",
            );
            assert_ne!(raw, changed);
            connection
                .execute("UPDATE resources SET members=?1", [changed])
                .unwrap();
        }
        let response = reply(&endpoint, &exchange, &ledger, &resources, false);
        assert_eq!(
            response.response,
            ServiceResponse::Refused { reason: expected },
            "{mode}"
        );
        exchange.reply.send(response).unwrap();
        child.wait();
        no_admission(&directory.path().join("requests.db"), &ledger);
        endpoint.finish();
    }
    eprintln!(
        "LEASE_DISPATCH cross_boot_refused=true retired_refused=true association_drift_refused=true admitted=false"
    );
}

#[test]
fn recovery_and_post_lookup_budget_keep_precedence_without_admission() {
    let (directory, path, helper) = helper();
    let ledger = ledger(directory.path());
    let resources = catalog(&directory.path().join("resources.db"));
    for (review, expire) in [(false, true), (false, false), (true, true)] {
        let endpoint = Endpoint::new(Some(helper.clone()));
        let mut child = endpoint.child(
            &path,
            if review {
                "recovery_required"
            } else {
                "not_ready"
            },
        );
        let mut exchange = endpoint.queued();
        exchange.revalidate(&endpoint.cancel).unwrap();
        // Real authenticated lookup completes first. Expiry/cancellation is
        // then injected at the exact production final-budget boundary; this
        // is a deterministic ordering test, not a native latency benchmark.
        let response = super::super::super::dispatch(
            &exchange.request,
            Uuid::new_v4(),
            review,
            &ledger,
            &resources,
        )
        .unwrap();
        assert_eq!(
            response.response,
            ServiceResponse::Refused {
                reason: if review {
                    Refusal::RecoveryRequired
                } else {
                    Refusal::UnknownLease
                }
            }
        );
        let cancelled = AtomicBool::new(!expire);
        if expire {
            exchange.deadline = Instant::now() - Duration::from_millis(1);
        }
        let response =
            super::super::super::finish_dispatch(&exchange, review, response, &cancelled);
        assert_eq!(
            response.response,
            ServiceResponse::Refused {
                reason: if review {
                    Refusal::RecoveryRequired
                } else {
                    Refusal::ServiceNotReady
                }
            }
        );
        exchange.reply.send(response).unwrap();
        child.wait();
        no_admission(&directory.path().join("requests.db"), &ledger);
        endpoint.finish();
    }
    eprintln!(
        "LEASE_DISPATCH post_lookup_expiry=true post_lookup_cancel=true recovery_precedence=true admitted=false"
    );
}

#[test]
fn corrupt_binding_returns_storage_error_without_fabricating_admission() {
    let (directory, path, helper) = helper();
    let ledger = ledger(directory.path());
    let database = directory.path().join("resources.db");
    let mut resources = catalog(&database);
    let endpoint = Endpoint::new(Some(helper));
    let mut child = endpoint.child(&path, "not_ready");
    let exchange = endpoint.queued();
    let caller = Caller::authenticated(&exchange.request).unwrap();
    let image =
        optimizer_identity::inspect(&std::env::current_exe().unwrap(), &endpoint.cancel).unwrap();
    bind(&mut resources, &exchange, &caller, image);
    rusqlite::Connection::open(&database)
        .unwrap()
        .execute("UPDATE leases SET document='{}'", [])
        .unwrap();
    assert!(
        super::super::super::dispatch_exchange(
            &exchange,
            Uuid::new_v4(),
            false,
            &ledger,
            &resources,
            &endpoint.cancel
        )
        .is_err()
    );
    no_admission(&directory.path().join("requests.db"), &ledger);
    // Production returns an owner error, so no response is synthesized. Drop
    // the exact reply sender: this fixture listener exits with NotConnected,
    // and its private child observes EOF instead of a success receipt.
    drop(exchange);
    assert!(endpoint.finish_result().is_err());
    assert!(!child.status().success());
    eprintln!(
        "LEASE_DISPATCH corrupt_refused=true listener_ended=true success_receipt=false admitted=false"
    );
}
