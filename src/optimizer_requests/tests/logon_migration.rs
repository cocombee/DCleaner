use super::*;

fn scoped(logon: &str) -> Caller {
    let mut value = caller();
    value.logon_sid = Some(logon.into());
    value
}
fn legacy(path: &Path, rows: &[(Uuid, Uuid, Uuid, i64, Option<Uuid>, Option<Uuid>)]) {
    let db = Connection::open(path).unwrap();
    db.execute_batch(LEGACY_SCHEMA).unwrap();
    db.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    db.pragma_update(None, "user_version", 1).unwrap();
    let owner = caller();
    for (invocation, lease, revision, phase, instance, nonce) in rows {
        db.execute("INSERT INTO invocations(account,session,invocation,lease,revision,phase,instance,nonce) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![owner.account,owner.session,invocation.as_bytes().as_slice(),lease.as_bytes().as_slice(),revision.as_bytes().as_slice(),phase,
                instance.map(|v|v.as_bytes().to_vec()),nonce.map(|v|v.as_bytes().to_vec())]).unwrap();
    }
}

#[test]
fn same_account_session_and_invocation_are_isolated_by_durable_logon_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("requests.db");
    let mut ledger = open(&path);
    let first = scoped("S-1-5-5-1-2");
    let second = scoped("S-1-5-5-1-3");
    let invocation = Uuid::new_v4();
    let lease = Uuid::new_v4();
    let revision = Uuid::new_v4();
    let ticket = admit(&mut ledger, &first, invocation, lease, revision);
    let claim = ledger
        .claim(ticket, preflight(&first, lease, revision), Uuid::new_v4())
        .unwrap();
    ledger
        .finish(&claim, WorkerOutcome::VerifiedReenabled)
        .unwrap();
    assert!(ledger.query(&second, invocation).unwrap().is_none());
    let second_ticket = admit(&mut ledger, &second, invocation, lease, revision);
    assert_eq!(
        ledger.query(&second, invocation).unwrap(),
        Some(Phase::Queued)
    );
    assert_eq!(
        ledger.query(&first, invocation).unwrap(),
        Some(Phase::VerifiedReenabled)
    );
    drop(second_ticket);
    drop(ledger);
    let mut ledger = open(&path);
    assert_eq!(
        ledger.query(&first, invocation).unwrap(),
        Some(Phase::VerifiedReenabled)
    );
    assert_eq!(
        ledger.query(&second, invocation).unwrap(),
        Some(Phase::Queued)
    );
    let hint = ledger.pending_for_review(1).unwrap().tickets.remove(0);
    assert_eq!(hint.owner(), &second);
    assert!(!hint.owner.native_origin);
    let claim = ledger
        .claim(hint, preflight(&second, lease, revision), Uuid::new_v4())
        .unwrap();
    ledger.finish(&claim, WorkerOutcome::Rejected).unwrap();
    assert_eq!(
        ledger.query(&first, invocation).unwrap(),
        Some(Phase::VerifiedReenabled)
    );
    assert_eq!(
        ledger.query(&second, invocation).unwrap(),
        Some(Phase::Rejected)
    );
}

#[test]
fn legacy_migration_preserves_every_phase_owner_nonce_and_unknown_logon_without_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("requests.db");
    let rows: Vec<_> = (0..=5)
        .map(|phase| {
            (
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                phase,
                (phase != 0).then(Uuid::new_v4),
                (phase != 0).then(Uuid::new_v4),
            )
        })
        .collect();
    legacy(&path, &rows);
    let mut ledger = open(&path);
    assert_eq!(
        ledger
            .connection
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    let bound = scoped("S-1-5-5-1-2");
    for (invocation, lease, revision, phase, instance, nonce) in &rows {
        assert_eq!(
            ledger.query(&caller(), *invocation).unwrap(),
            Some(Phase::parse(*phase).unwrap())
        );
        assert_eq!(ledger.query(&bound, *invocation).unwrap(), None);
        let actual: (String, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>) = ledger
            .connection
            .query_row(
                "SELECT logon,lease,revision,instance,nonce FROM invocations WHERE invocation=?1",
                [invocation.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            actual,
            (
                String::new(),
                lease.as_bytes().to_vec(),
                revision.as_bytes().to_vec(),
                instance.map(|v| v.as_bytes().to_vec()),
                nonce.map(|v| v.as_bytes().to_vec())
            )
        );
    }
    let hint = ledger.pending_for_review(1).unwrap().tickets.remove(0);
    assert!(hint.owner().logon_sid().is_none());
    assert!(!hint.owner.native_origin);
    assert!(matches!(
        LeasePreflight::from_owner_observation(
            hint.owner().clone(),
            hint.lease,
            hint.revision,
            crate::optimizer_requests::ContextBinding::fixture_default()
        ),
        Err(LedgerError::NotAuthorized)
    ));
    let raw = &rows[0];
    assert!(matches!(
        ledger
            .admit(&bound, raw.0, preflight(&bound, raw.1, raw.2))
            .unwrap(),
        Admission::Conflict
    ));
    let _ = admit(&mut ledger, &bound, Uuid::new_v4(), raw.1, raw.2);
    assert_eq!(
        ledger
            .connection
            .query_row::<i64, _, _>("SELECT count(*) FROM invocations", [], |r| r.get(0))
            .unwrap(),
        7
    );
    assert_eq!(
        ledger.query(&caller(), rows[1].0).unwrap(),
        Some(Phase::Running)
    );
}

#[test]
fn failed_legacy_migration_commit_restores_exact_old_schema_and_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("requests.db");
    let rows = vec![(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        0,
        None,
        None,
    )];
    legacy(&path, &rows);
    let before = std::fs::read(&path).unwrap();
    unsafe extern "C" fn reject(_: *mut std::ffi::c_void) -> i32 {
        1
    }
    let db = Connection::open(&path).unwrap();
    unsafe {
        rusqlite::ffi::sqlite3_commit_hook(db.handle(), Some(reject), std::ptr::null_mut());
    }
    assert!(Ledger::open(db).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        1
    );
    validate_schema(&db, Layout::Legacy).unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM invocations", [], |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row::<Vec<u8>, _, _>("SELECT invocation FROM invocations", [], |r| r.get(0))
            .unwrap(),
        rows[0].0.as_bytes()
    );
    drop(db);
    drop(open(&path));
}

#[test]
fn malformed_legacy_or_noncanonical_current_logon_rows_are_refused_without_replacement() {
    let dir = tempfile::tempdir().unwrap();
    for version in [1, 2] {
        let path = dir.path().join(format!("bad-{version}.db"));
        if version == 1 {
            legacy(&path, &[]);
        } else {
            drop(open(&path));
        }
        let db = Connection::open(&path).unwrap();
        if version == 1 {
            db.execute_batch("PRAGMA ignore_check_constraints=ON; INSERT INTO invocations(account,session,invocation,lease,revision,phase) VALUES('not-a-sid',1,randomblob(16),randomblob(16),randomblob(16),0)").unwrap();
        } else {
            db.execute_batch("INSERT INTO invocations(account,session,logon,invocation,lease,revision,phase) VALUES('S-1-5-18',1,'S-1-5-5-01-2',randomblob(16),randomblob(16),randomblob(16),0)").unwrap();
        }
        drop(db);
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            Ledger::open(Connection::open(&path).unwrap()),
            Err(LedgerError::CorruptDatabase)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn simultaneous_identical_ids_claim_and_finish_only_the_exact_logon_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = open(&dir.path().join("requests.db"));
    let a = scoped("S-1-5-5-1-2");
    let b = scoped("S-1-5-5-1-3");
    let id = Uuid::new_v4();
    let lease = Uuid::new_v4();
    let revision = Uuid::new_v4();
    let first = admit(&mut ledger, &a, id, lease, revision);
    let second = admit(&mut ledger, &b, id, lease, revision);
    let instance = Uuid::new_v4();
    let first = ledger
        .claim(first, preflight(&a, lease, revision), instance)
        .unwrap();
    assert_eq!(ledger.query(&b, id).unwrap(), Some(Phase::Queued));
    let mut second = ledger
        .claim(second, preflight(&b, lease, revision), instance)
        .unwrap();
    ledger
        .finish(&first, WorkerOutcome::VerifiedReenabled)
        .unwrap();
    assert_eq!(ledger.query(&b, id).unwrap(), Some(Phase::Running));
    // Deliberately wrong private test claim identity; even its valid nonce and
    // common lease/revision/runtime cannot change a different namespace.
    second.ticket.owner.logon_sid = a.logon_sid.clone();
    assert!(matches!(
        ledger.finish(&second, WorkerOutcome::Rejected),
        Err(LedgerError::StaleClaim)
    ));
    assert_eq!(ledger.query(&b, id).unwrap(), Some(Phase::Running));
    second.ticket.owner.logon_sid = b.logon_sid.clone();
    ledger.finish(&second, WorkerOutcome::Rejected).unwrap();
    assert_eq!(
        ledger.query(&a, id).unwrap(),
        Some(Phase::VerifiedReenabled)
    );
    assert_eq!(ledger.query(&b, id).unwrap(), Some(Phase::Rejected));
}

#[test]
fn stopped_runtime_recovery_preserves_other_logons_and_never_claims_queued_work() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = open(&dir.path().join("requests.db"));
    let a = scoped("S-1-5-5-1-2");
    let b = scoped("S-1-5-5-1-3");
    let id = Uuid::new_v4();
    let lease = Uuid::new_v4();
    let revision = Uuid::new_v4();
    let old = Uuid::new_v4();
    let current = Uuid::new_v4();
    let first = admit(&mut ledger, &a, id, lease, revision);
    let second = admit(&mut ledger, &b, id, lease, revision);
    let first = ledger
        .claim(first, preflight(&a, lease, revision), old)
        .unwrap();
    let _second = ledger
        .claim(second, preflight(&b, lease, revision), current)
        .unwrap();
    let queued = Uuid::new_v4();
    let _ = admit(&mut ledger, &a, queued, lease, revision);
    assert_eq!(
        ledger
            .mark_stopped_owner_uncertain(&StoppedOwner::fixture(old))
            .unwrap(),
        1
    );
    assert_eq!(ledger.query(&a, id).unwrap(), Some(Phase::Uncertain));
    assert_eq!(ledger.query(&b, id).unwrap(), Some(Phase::Running));
    assert_eq!(ledger.query(&a, queued).unwrap(), Some(Phase::Queued));
    assert!(matches!(
        ledger.finish(&first, WorkerOutcome::VerifiedReenabled),
        Err(LedgerError::StaleClaim)
    ));
}

#[test]
fn legacy_readonly_wal_and_extra_object_failures_do_not_upgrade_or_replace_data() {
    let dir = tempfile::tempdir().unwrap();
    for mode in 0..3 {
        let path = dir.path().join(format!("legacy-{mode}.db"));
        legacy(
            &path,
            &[(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                0,
                None,
                None,
            )],
        );
        let db = Connection::open(&path).unwrap();
        if mode == 1 {
            db.execute_batch("PRAGMA journal_mode=WAL").unwrap();
        }
        if mode == 2 {
            db.execute_batch("CREATE TABLE unexpected(value TEXT)")
                .unwrap();
        }
        drop(db);
        let before = std::fs::read(&path).unwrap();
        let db = if mode == 0 {
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
        } else {
            Connection::open(&path).unwrap()
        };
        assert!(Ledger::open(db).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row::<i64, _, _>("SELECT count(*) FROM invocations", [], |r| r.get(0))
                .unwrap(),
            1
        );
    }
}
