use super::*;
fn scoped(boot: Uuid) -> Caller {
    Caller::fixture_boot(caller().account(), caller().session(), "S-1-5-5-1-2", boot)
}

#[test]
fn reused_logon_and_invocation_ids_cannot_query_claim_or_finish_another_boot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("requests.db");
    let mut ledger = open(&path);
    let a = scoped(Uuid::new_v4());
    let b = scoped(Uuid::new_v4());
    let id = Uuid::new_v4();
    let lease = Uuid::new_v4();
    let revision = Uuid::new_v4();
    let first = admit(&mut ledger, &a, id, lease, revision);
    assert!(ledger.query(&b, id).unwrap().is_none());
    assert!(matches!(
        ledger.claim(first, preflight(&b, lease, revision), Uuid::new_v4()),
        Err(LedgerError::StaleLease)
    ));
    let second = admit(&mut ledger, &b, id, lease, revision);
    let second = ledger
        .claim(second, preflight(&b, lease, revision), Uuid::new_v4())
        .unwrap();
    ledger
        .finish(&second, WorkerOutcome::VerifiedReenabled)
        .unwrap();
    drop(ledger);
    let mut ledger = open(&path);
    let saved = ledger.pending_for_review(2).unwrap().tickets.remove(0);
    assert_eq!(saved.owner(), &a);
    assert!(!saved.owner.native_origin);
    assert!(
        LeasePreflight::from_owner_observation(
            saved.owner.clone(),
            lease,
            revision,
            crate::optimizer_requests::ContextBinding::fixture_default()
        )
        .is_err()
    );
    let mut first = ledger
        .claim(saved, preflight(&a, lease, revision), Uuid::new_v4())
        .unwrap();
    let native_boot = first.ticket.owner.boot_id;
    first.ticket.owner.boot_id = b.boot_id;
    assert!(matches!(
        ledger.finish(&first, WorkerOutcome::Uncertain),
        Err(LedgerError::StaleClaim)
    ));
    first.ticket.owner.boot_id = native_boot;
    ledger.finish(&first, WorkerOutcome::Uncertain).unwrap();
    assert_eq!(ledger.query(&a, id).unwrap(), Some(Phase::Uncertain));
    assert_eq!(
        ledger.query(&b, id).unwrap(),
        Some(Phase::VerifiedReenabled)
    );
}

fn legacy_logon(path: &Path) -> Vec<(Uuid, i64, Option<Vec<u8>>, Option<Vec<u8>>)> {
    let db = Connection::open(path).unwrap();
    db.execute_batch(LOGON_SCHEMA).unwrap();
    db.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    db.pragma_update(None, "user_version", 2).unwrap();
    (0..6).map(|phase| {
        let id=Uuid::new_v4(); let runtime=(phase!=0).then(||Uuid::new_v4().as_bytes().to_vec());
        let nonce=(phase!=0).then(||Uuid::new_v4().as_bytes().to_vec());
        db.execute("INSERT INTO invocations(account,session,logon,invocation,lease,revision,phase,instance,nonce) VALUES(?1,1,'S-1-5-5-1-2',?2,?3,?4,?5,?6,?7)",
            params![caller().account,id.as_bytes().as_slice(),Uuid::new_v4().as_bytes().as_slice(),Uuid::new_v4().as_bytes().as_slice(),phase,runtime,nonce]).unwrap();
        (id,phase,runtime,nonce)
    }).collect()
}

#[test]
fn v2_request_migration_keeps_logon_and_all_phases_unbound_to_a_boot_without_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    let rows = legacy_logon(&path);
    let mut ledger = open(&path);
    let a = scoped(Uuid::new_v4());
    let old = Caller::fixture_logon(a.account(), a.session(), a.logon_sid().unwrap());
    for (id, phase, instance, nonce) in rows {
        assert_eq!(
            ledger.query(&old, id).unwrap(),
            Some(Phase::parse(phase).unwrap())
        );
        assert!(ledger.query(&a, id).unwrap().is_none());
        let data: (String, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>) = ledger
            .connection
            .query_row(
                "SELECT logon,boot,instance,nonce FROM invocations WHERE invocation=?1",
                [id.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            data,
            (old.logon_sid.clone().unwrap(), vec![0; 16], instance, nonce)
        );
        assert!(matches!(
            ledger
                .admit(&a, id, preflight(&a, Uuid::new_v4(), Uuid::new_v4()))
                .unwrap(),
            Admission::Conflict
        ));
    }
    let hint = ledger.pending_for_review(1).unwrap().tickets.remove(0);
    assert!(hint.owner.boot_id.is_none());
    assert!(!hint.owner.native_origin);
    drop(ledger);
    drop(open(&path));
}

#[test]
fn failed_v2_request_upgrade_commit_restores_exact_database_and_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    legacy_logon(&path);
    let before = std::fs::read(&path).unwrap();
    let db = Connection::open(&path).unwrap();
    unsafe extern "C" fn reject(_: *mut std::ffi::c_void) -> i32 {
        1
    }
    unsafe {
        rusqlite::ffi::sqlite3_commit_hook(db.handle(), Some(reject), std::ptr::null_mut());
    }
    assert!(Ledger::open(db).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let db = Connection::open(&path).unwrap();
    validate_schema(&db, Layout::Logon).unwrap();
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        2
    );
    drop(db);
    drop(open(&path));
}

#[test]
fn malformed_boot_keys_and_boot_without_logon_are_refused_without_replacement() {
    for case in 0..2 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.db");
        let mut ledger = open(&path);
        let a = scoped(Uuid::new_v4());
        drop(admit(
            &mut ledger,
            &a,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        ));
        if case == 0 {
            ledger
                .connection
                .execute_batch(
                    "PRAGMA ignore_check_constraints=ON;UPDATE invocations SET boot=X'01'",
                )
                .unwrap();
        } else {
            ledger
                .connection
                .execute("UPDATE invocations SET logon=''", [])
                .unwrap();
        }
        drop(ledger);
        let before = std::fs::read(&path).unwrap();
        assert!(Ledger::open(Connection::open(&path).unwrap()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
