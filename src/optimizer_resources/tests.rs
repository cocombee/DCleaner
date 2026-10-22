use super::*;
mod boot_scope;
mod logon_scope;
mod root_gate;
use std::path::Path;

fn open(path: &Path) -> Catalog {
    Catalog::open(Connection::open(path).unwrap()).unwrap()
}
fn owner(session: u32) -> Caller {
    Caller::fixture("S-1-5-21-1-2-3-1001", session)
}
fn member(owner: &Caller, name: &str) -> Member {
    let hex: String = name.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    Member::for_caller(owner, &format!("program:v1:hkcu:64:{hex}")).unwrap()
}
fn id() -> ResourceId {
    unsafe { ResourceId::from_native(1, b"synthetic native resource") }.unwrap()
}
fn observe(id: &ResourceId, instance: Uuid, state: &[u8], members: &[Member]) -> Observation {
    // Explicit synthetic source, never used by the production service path.
    unsafe {
        Observation::from_native(id.clone(), instance, state.to_vec(), members.to_vec(), true)
    }
    .unwrap()
}
fn rev(c: &Catalog, id: &ResourceId) -> Uuid {
    c.inspect(id).unwrap().unwrap().revision
}
fn register(c: &mut Catalog, instance: Uuid, members: &[Member]) -> ResourceId {
    let id = id();
    c.register(
        observe(&id, instance, b"original", members),
        b"sleeping".to_vec(),
    )
    .unwrap();
    id
}
fn sleep(c: &mut Catalog, id: &ResourceId, instance: Uuid, caller: &Caller, members: &[Member]) {
    for member in members {
        c.request(id, rev(c, id), caller, member, true).unwrap();
    }
    let claim = c
        .begin(id, rev(c, id), observe(id, instance, b"original", members))
        .unwrap()
        .unwrap();
    assert_eq!(claim.expected(), b"original");
    assert_eq!(claim.desired(), b"sleeping");
    assert_eq!(
        c.finish(claim, observe(id, instance, b"sleeping", members))
            .unwrap(),
        Phase::Sleeping
    );
}

#[test]
fn shared_resource_waits_for_all_members_and_one_wake_restores_the_first_baseline() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = open(&temp.path().join("resources.db"));
    let caller = owner(1);
    let members = vec![member(&caller, "app one"), member(&caller, "app two")];
    let instance = Uuid::new_v4();
    let id = register(&mut c, instance, &members);
    c.request(&id, rev(&c, &id), &caller, &members[0], true)
        .unwrap();
    assert!(
        c.begin(
            &id,
            rev(&c, &id),
            observe(&id, instance, b"original", &members)
        )
        .unwrap()
        .is_none()
    );
    c.request(&id, rev(&c, &id), &caller, &members[1], true)
        .unwrap();
    let claim = c
        .begin(
            &id,
            rev(&c, &id),
            observe(&id, instance, b"original", &members),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        c.finish(claim, observe(&id, instance, b"sleeping", &members))
            .unwrap(),
        Phase::Sleeping
    );
    c.request(&id, rev(&c, &id), &caller, &members[0], false)
        .unwrap();
    let wake = c
        .begin(
            &id,
            rev(&c, &id),
            observe(&id, instance, b"sleeping", &members),
        )
        .unwrap()
        .unwrap();
    assert_eq!(wake.desired(), b"original");
    assert_eq!(
        c.finish(wake, observe(&id, instance, b"original", &members))
            .unwrap(),
        Phase::Awake
    );
    assert!(!c.requires_review(instance).unwrap());
}

#[test]
fn a_new_member_never_inherits_sleep_intent_or_replaces_the_original_baseline() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = open(&temp.path().join("resources.db"));
    let caller = owner(1);
    let first = member(&caller, "first");
    let second = member(&caller, "second");
    let instance = Uuid::new_v4();
    let id = register(&mut c, instance, &[first.clone()]);
    sleep(&mut c, &id, instance, &caller, &[first.clone()]);
    let both = vec![first, second];
    c.register(
        observe(&id, instance, b"sleeping", &both),
        b"sleeping".to_vec(),
    )
    .unwrap();
    assert_eq!(c.inspect(&id).unwrap().unwrap().target, Target::Awake);
    let wake = c
        .begin(
            &id,
            rev(&c, &id),
            observe(&id, instance, b"sleeping", &both),
        )
        .unwrap()
        .unwrap();
    assert_eq!(wake.desired(), b"original");
    c.finish(wake, observe(&id, instance, b"original", &both))
        .unwrap();
    assert_eq!(
        load(&c.connection, &id).unwrap().unwrap().baseline,
        b"original"
    );
}

#[test]
fn incomplete_or_changed_native_state_never_yields_a_claim_and_cannot_replace_baseline() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = open(&temp.path().join("resources.db"));
    let caller = owner(1);
    let members = vec![member(&caller, "app")];
    let instance = Uuid::new_v4();
    let id = register(&mut c, instance, &members);
    c.request(&id, rev(&c, &id), &caller, &members[0], true)
        .unwrap();
    let mut partial = observe(&id, instance, b"original", &members);
    partial.complete = false;
    assert!(matches!(
        c.begin(&id, rev(&c, &id), partial),
        Err(Error::Incomplete)
    ));
    assert!(matches!(
        c.begin(
            &id,
            rev(&c, &id),
            observe(&id, instance, b"foreign", &members)
        ),
        Err(Error::Changed)
    ));
    assert_eq!(c.inspect(&id).unwrap().unwrap().phase, Phase::Uncertain);
    assert!(matches!(
        c.register(
            observe(&id, instance, b"foreign", &members),
            b"sleeping".to_vec()
        ),
        Err(Error::Stale)
    ));
    assert_eq!(
        load(&c.connection, &id).unwrap().unwrap().baseline,
        b"original"
    );
}

#[test]
fn unauthorized_session_and_stale_revision_cannot_change_another_members_demand() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = open(&temp.path().join("resources.db"));
    let caller = owner(1);
    let members = vec![member(&caller, "app")];
    let instance = Uuid::new_v4();
    let id = register(&mut c, instance, &members);
    let original = rev(&c, &id);
    assert!(matches!(
        c.request(&id, original, &owner(2), &members[0], true),
        Err(Error::NotAuthorized)
    ));
    c.request(&id, original, &caller, &members[0], true)
        .unwrap();
    assert!(matches!(
        c.request(&id, original, &caller, &members[0], false),
        Err(Error::Stale)
    ));
    assert_eq!(c.inspect(&id).unwrap().unwrap().target, Target::Sleep);
}

#[test]
fn temporary_activations_are_counted_independently_and_do_not_erase_sleep_intent() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("resources.db");
    let mut c = open(&path);
    let caller = owner(1);
    let members = vec![member(&caller, "app")];
    let instance = Uuid::new_v4();
    let id = register(&mut c, instance, &members);
    sleep(&mut c, &id, instance, &caller, &members);
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    c.begin_activation(&id, rev(&c, &id), &caller, &members[0], a, instance)
        .unwrap();
    let duplicate = rev(&c, &id);
    assert_eq!(
        c.begin_activation(&id, duplicate, &caller, &members[0], a, instance)
            .unwrap(),
        duplicate
    );
    c.begin_activation(&id, rev(&c, &id), &caller, &members[0], b, instance)
        .unwrap();
    let wake = c
        .begin(
            &id,
            rev(&c, &id),
            observe(&id, instance, b"sleeping", &members),
        )
        .unwrap()
        .unwrap();
    c.finish(wake, observe(&id, instance, b"original", &members))
        .unwrap();
    drop(c);
    let mut c = open(&path);
    for (index, invocation) in [a, b].into_iter().enumerate() {
        let proof = unsafe {
            ActivationObservation::from_native(
                members[0].clone(),
                invocation,
                instance,
                instance,
                false,
            )
        }
        .unwrap();
        c.observe_activation(&id, rev(&c, &id), proof).unwrap();
        let view = c.inspect(&id).unwrap().unwrap();
        assert_eq!(view.temporary_activations, 1 - index);
        assert_eq!(
            view.target,
            if index == 0 {
                Target::Awake
            } else {
                Target::Sleep
            }
        );
    }
    let claim = c
        .begin(
            &id,
            rev(&c, &id),
            observe(&id, instance, b"original", &members),
        )
        .unwrap()
        .unwrap();
    assert_eq!(claim.desired(), b"sleeping");
}

#[test]
fn surviving_activation_needs_current_native_revalidation_after_a_runtime_restart() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = open(&temp.path().join("resources.db"));
    let caller = owner(1);
    let members = vec![member(&caller, "app")];
    let old = Uuid::new_v4();
    let new = Uuid::new_v4();
    let id = register(&mut c, old, &members);
    let invocation = Uuid::new_v4();
    c.begin_activation(&id, rev(&c, &id), &caller, &members[0], invocation, old)
        .unwrap();
    c.reconcile(&id, rev(&c, &id), observe(&id, new, b"original", &members))
        .unwrap();
    assert!(c.requires_review(new).unwrap());
    let wrong = unsafe {
        ActivationObservation::from_native(
            members[0].clone(),
            invocation,
            Uuid::new_v4(),
            new,
            true,
        )
    }
    .unwrap();
    assert!(matches!(
        c.observe_activation(&id, rev(&c, &id), wrong),
        Err(Error::Stale)
    ));
    let alive = unsafe {
        ActivationObservation::from_native(members[0].clone(), invocation, old, new, true)
    }
    .unwrap();
    c.observe_activation(&id, rev(&c, &id), alive).unwrap();
    assert!(!c.requires_review(new).unwrap());
    assert_eq!(c.inspect(&id).unwrap().unwrap().temporary_activations, 1);
}

#[test]
fn uncertain_native_outcome_retains_original_and_requires_reconciliation_not_replay() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = open(&temp.path().join("resources.db"));
    let caller = owner(1);
    let members = vec![member(&caller, "app")];
    let instance = Uuid::new_v4();
    let id = register(&mut c, instance, &members);
    c.request(&id, rev(&c, &id), &caller, &members[0], true)
        .unwrap();
    let claim = c
        .begin(
            &id,
            rev(&c, &id),
            observe(&id, instance, b"original", &members),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        c.finish(
            claim,
            observe(&id, instance, b"partially changed", &members)
        )
        .unwrap(),
        Phase::Uncertain
    );
    assert!(matches!(
        c.begin(
            &id,
            rev(&c, &id),
            observe(&id, instance, b"original", &members)
        ),
        Err(Error::Changed)
    ));
    c.reconcile(
        &id,
        rev(&c, &id),
        observe(&id, instance, b"original", &members),
    )
    .unwrap();
    assert!(c.requires_review(instance).unwrap()); // requested Sleep still needs explicit fresh work.
    assert_eq!(
        load(&c.connection, &id).unwrap().unwrap().baseline,
        b"original"
    );
}

#[test]
fn stopped_owner_invalidates_changing_claim_without_recovering_or_executing_it() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("resources.db");
    let mut c = open(&path);
    let caller = owner(1);
    let members = vec![member(&caller, "app")];
    let old = Uuid::new_v4();
    let new = Uuid::new_v4();
    let id = register(&mut c, old, &members);
    c.request(&id, rev(&c, &id), &caller, &members[0], true)
        .unwrap();
    let claim = c
        .begin(&id, rev(&c, &id), observe(&id, old, b"original", &members))
        .unwrap()
        .unwrap();
    assert!(c.has_foreign_active_owner(new).unwrap());
    c.mark_stopped_owner_uncertain(&StoppedOwner::fixture(old))
        .unwrap();
    c.mark_stopped_owner_uncertain(&StoppedOwner::fixture(old))
        .unwrap();
    assert!(!c.has_foreign_active_owner(new).unwrap());
    assert!(matches!(
        c.finish(claim, observe(&id, old, b"sleeping", &members)),
        Err(Error::Stale)
    ));
    drop(c);
    let c = open(&path);
    assert_eq!(c.inspect(&id).unwrap().unwrap().phase, Phase::Uncertain);
}

#[test]
fn only_verified_original_state_allows_releasing_a_member_or_its_last_baseline() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = open(&temp.path().join("resources.db"));
    let caller = owner(1);
    let members = vec![member(&caller, "app")];
    let instance = Uuid::new_v4();
    let id = register(&mut c, instance, &members);
    sleep(&mut c, &id, instance, &caller, &members);
    assert!(matches!(
        c.release_member(
            &id,
            rev(&c, &id),
            &caller,
            &members[0],
            observe(&id, instance, b"sleeping", &members)
        ),
        Err(Error::Changed)
    ));
    c.request(&id, rev(&c, &id), &caller, &members[0], false)
        .unwrap();
    let claim = c
        .begin(
            &id,
            rev(&c, &id),
            observe(&id, instance, b"sleeping", &members),
        )
        .unwrap()
        .unwrap();
    c.finish(claim, observe(&id, instance, b"original", &members))
        .unwrap();
    assert_eq!(
        c.release_member(
            &id,
            rev(&c, &id),
            &caller,
            &members[0],
            observe(&id, instance, b"original", &[])
        )
        .unwrap(),
        None
    );
    assert!(c.inspect(&id).unwrap().is_none());
}

#[test]
fn failed_commit_cannot_yield_a_claim_or_persist_the_changing_phase() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = open(&temp.path().join("resources.db"));
    let caller = owner(1);
    let members = vec![member(&caller, "app")];
    let instance = Uuid::new_v4();
    let id = register(&mut c, instance, &members);
    c.request(&id, rev(&c, &id), &caller, &members[0], true)
        .unwrap();
    let before = rev(&c, &id);
    c.connection.execute_batch("PRAGMA foreign_keys=ON;CREATE TABLE fault_guard(id INTEGER PRIMARY KEY,required INTEGER REFERENCES fault_guard(id) DEFERRABLE INITIALLY DEFERRED);
        CREATE TEMP TRIGGER fail_commit AFTER UPDATE OF phase ON main.resources WHEN NEW.phase=2 BEGIN INSERT INTO fault_guard VALUES(1,999); END;").unwrap();
    assert!(matches!(
        c.begin(&id, before, observe(&id, instance, b"original", &members)),
        Err(Error::Sql(_))
    ));
    assert_eq!(rev(&c, &id), before);
    assert_eq!(c.inspect(&id).unwrap().unwrap().phase, Phase::Awake);
}

#[test]
fn independent_writers_cannot_both_change_the_same_reviewed_revision() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("resources.db");
    let mut c = open(&path);
    let caller = owner(1);
    let members = vec![member(&caller, "app")];
    let instance = Uuid::new_v4();
    let id = register(&mut c, instance, &members);
    let before = rev(&c, &id);
    drop(c);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let id = id.clone();
            let caller = caller.clone();
            let m = members[0].clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut c = open(&path);
                barrier.wait();
                c.request(&id, before, &caller, &m, true)
            })
        })
        .collect();
    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::Stale)))
            .count(),
        1
    );
}

#[test]
fn bounds_and_noncanonical_corruption_fail_without_replacing_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("resources.db");
    let mut c = open(&path);
    let caller = owner(1);
    let members = vec![member(&caller, "app")];
    let instance = Uuid::new_v4();
    let id = register(&mut c, instance, &members);
    assert!(unsafe { ResourceId::from_native(1, &vec![0; 4097]) }.is_err());
    assert!(
        unsafe {
            Observation::from_native(
                id.clone(),
                instance,
                vec![0; MAX_STATE + 1],
                members.clone(),
                true,
            )
        }
        .is_err()
    );
    c.connection
        .execute("UPDATE resources SET members=' [] '", [])
        .unwrap();
    drop(c);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        Catalog::open(Connection::open(&path).unwrap()),
        Err(Error::Corrupt)
    ));
    assert_eq!(before, std::fs::read(&path).unwrap());
}

#[test]
fn readiness_queries_do_not_read_large_state_blobs_or_roster_documents() {
    unsafe extern "C" fn deny_payload(
        _: *mut std::ffi::c_void,
        action: i32,
        table: *const std::ffi::c_char,
        column: *const std::ffi::c_char,
        _: *const std::ffi::c_char,
        _: *const std::ffi::c_char,
    ) -> i32 {
        if action == rusqlite::ffi::SQLITE_READ
            && !table.is_null()
            && !column.is_null()
            && unsafe { std::ffi::CStr::from_ptr(table) }.to_bytes() == b"resources"
            && [
                b"baseline".as_slice(),
                b"sleeping".as_slice(),
                b"members".as_slice(),
            ]
            .contains(&unsafe { std::ffi::CStr::from_ptr(column) }.to_bytes())
        {
            return rusqlite::ffi::SQLITE_DENY;
        }
        rusqlite::ffi::SQLITE_OK
    }
    let temp = tempfile::tempdir().unwrap();
    let mut c = open(&temp.path().join("resources.db"));
    let caller = owner(1);
    let members = vec![member(&caller, "app")];
    let instance = Uuid::new_v4();
    let id = id();
    c.register(
        observe(&id, instance, &vec![0; MAX_STATE], &members),
        vec![1; MAX_STATE],
    )
    .unwrap();
    assert_eq!(
        unsafe {
            rusqlite::ffi::sqlite3_set_authorizer(
                c.connection.handle(),
                Some(deny_payload),
                std::ptr::null_mut(),
            )
        },
        rusqlite::ffi::SQLITE_OK
    );
    assert!(!c.requires_review(instance).unwrap());
    assert!(!c.has_foreign_active_owner(instance).unwrap());
    assert!(c.requires_review(Uuid::new_v4()).unwrap());
    unsafe {
        rusqlite::ffi::sqlite3_set_authorizer(c.connection.handle(), None, std::ptr::null_mut());
    }
}

#[test]
fn corrupted_summary_cannot_be_accepted_as_valid_resource_state() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("resources.db");
    let mut c = open(&path);
    let caller = owner(1);
    let members = vec![member(&caller, "app")];
    register(&mut c, Uuid::new_v4(), &members);
    c.connection
        .execute("UPDATE resources SET target=1", [])
        .unwrap();
    drop(c);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        Catalog::open(Connection::open(&path).unwrap()),
        Err(Error::Corrupt)
    ));
    assert_eq!(before, std::fs::read(&path).unwrap());
}

#[test]
fn stored_native_identity_decode_refuses_noncanonical_data() {
    for kind in 1..=4 {
        let bytes = [0, 1, 15, 16, 127, 128, 255];
        let id = unsafe { ResourceId::from_native(kind, &bytes) }.unwrap();
        assert_eq!(id.native_parts().unwrap(), (kind, bytes.to_vec()));
    }
    for invalid in [
        "native:v1:0:00",
        "native:v1:1:",
        "native:v1:1:Ff",
        "native:v1:1:0",
        "native:v1:1:gg",
        "native:v2:1:00",
        "native:v1:1:00:00",
    ] {
        assert!(ResourceId(invalid.into()).native_parts().is_err());
    }
}
