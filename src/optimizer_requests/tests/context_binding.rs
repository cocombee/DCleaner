use super::*;

fn bound(owner: &Caller, lease: Uuid, revision: Uuid, byte: u8) -> LeasePreflight {
    LeasePreflight::from_owner_observation(
        owner.clone(),
        lease,
        revision,
        ContextBinding::fixture(byte),
    )
    .unwrap()
}
fn enqueue(
    ledger: &mut Ledger,
    owner: &Caller,
    id: Uuid,
    lease: Uuid,
    revision: Uuid,
) -> QueueTicket {
    match ledger
        .admit(owner, id, bound(owner, lease, revision, 1))
        .unwrap()
    {
        Admission::New(ticket) => ticket,
        other => panic!("expected one new fixture invocation: {other:?}"),
    }
}

#[test]
fn exact_context_retries_survive_reopen_and_changed_context_never_gets_a_second_ticket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("context.db");
    let owner = caller();
    let (id, lease, revision) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let mut ledger = open(&path);
    let ticket = enqueue(&mut ledger, &owner, id, lease, revision);
    assert_eq!(ticket.context, Some(ContextBinding::fixture(1)));
    assert!(matches!(
        ledger
            .admit(&owner, id, bound(&owner, lease, Uuid::new_v4(), 1))
            .unwrap(),
        Admission::Existing(Phase::Queued)
    ));
    assert!(matches!(
        ledger
            .admit(&owner, id, bound(&owner, lease, revision, 2))
            .unwrap(),
        Admission::Conflict
    ));
    assert!(matches!(
        ledger.claim(ticket, bound(&owner, lease, revision, 2), Uuid::new_v4()),
        Err(LedgerError::StaleLease)
    ));
    drop(ledger);
    let mut ledger = open(&path);
    let ticket = ledger.pending_for_review(1).unwrap().tickets.remove(0);
    assert_eq!(ticket.context, Some(ContextBinding::fixture(1)));
    let claim = ledger
        .claim(ticket, bound(&owner, lease, revision, 1), Uuid::new_v4())
        .unwrap();
    for phase in [Phase::Running, Phase::VerifiedReenabled] {
        assert_eq!(ledger.query(&owner, id).unwrap(), Some(phase));
        assert!(matches!(
            ledger
                .admit(&owner, id, bound(&owner, lease, revision, 2))
                .unwrap(),
            Admission::Conflict
        ));
        assert!(
            matches!(ledger.admit(&owner, id, bound(&owner, lease, revision, 1)).unwrap(), Admission::Existing(current) if current==phase)
        );
        if phase == Phase::Running {
            ledger
                .finish(&claim, WorkerOutcome::VerifiedReenabled)
                .unwrap();
        }
    }
    assert_eq!(
        ledger
            .connection
            .query_row::<i64, _, _>("SELECT count(*) FROM invocations", [], |r| r.get(0))
            .unwrap(),
        1
    );
}

#[test]
fn context_change_between_queue_claim_and_receipt_never_becomes_durable_success() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = open(&dir.path().join("context.db"));
    let owner = caller();
    let (id, lease, revision) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let ticket = enqueue(&mut ledger, &owner, id, lease, revision);
    ledger
        .connection
        .execute(
            "UPDATE invocations SET context=?1",
            [ContextBinding::fixture(2).bytes()],
        )
        .unwrap();
    assert!(matches!(
        ledger.claim(ticket, bound(&owner, lease, revision, 1), Uuid::new_v4()),
        Err(LedgerError::StaleClaim)
    ));
    assert_eq!(ledger.query(&owner, id).unwrap(), Some(Phase::Queued));
    ledger
        .connection
        .execute(
            "UPDATE invocations SET context=?1",
            [ContextBinding::fixture(1).bytes()],
        )
        .unwrap();
    let ticket = ledger.pending_for_review(1).unwrap().tickets.remove(0);
    let claim = ledger
        .claim(ticket, bound(&owner, lease, revision, 1), Uuid::new_v4())
        .unwrap();
    ledger
        .connection
        .execute("UPDATE invocations SET context=NULL", [])
        .unwrap();
    assert!(matches!(
        ledger.finish(&claim, WorkerOutcome::VerifiedReenabled),
        Err(LedgerError::StaleClaim)
    ));
    assert_eq!(ledger.query(&owner, id).unwrap(), Some(Phase::Running));
    assert!(ledger.requires_review().unwrap());
}

fn v3(
    path: &Path,
) -> (
    Caller,
    Vec<(Uuid, Uuid, Uuid, i64, Option<Uuid>, Option<Uuid>)>,
) {
    let owner = Caller::fixture_boot(caller().account(), 1, "S-1-5-5-1-2", Uuid::new_v4());
    let db = Connection::open(path).unwrap();
    db.execute_batch(BOOT_SCHEMA).unwrap();
    db.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    db.pragma_update(None, "user_version", 3).unwrap();
    let rows = (0..=5).map(|phase| {
        let (id, lease, revision) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let instance = (phase != 0).then(Uuid::new_v4);
        let nonce = (phase != 0).then(Uuid::new_v4);
        db.execute("INSERT INTO invocations(account,session,logon,boot,invocation,lease,revision,phase,instance,nonce) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", params![owner.account,owner.session,owner.logon_sid,owner.boot_key().as_slice(),id.as_bytes().as_slice(),lease.as_bytes().as_slice(),revision.as_bytes().as_slice(),phase,instance.map(|v|v.as_bytes().to_vec()),nonce.map(|v|v.as_bytes().to_vec())]).unwrap();
        (id, lease, revision, phase, instance, nonce)
    }).collect();
    (owner, rows)
}

#[test]
fn version3_migration_preserves_all_scopes_phases_and_unknown_context_without_rebinding() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v3.db");
    let (owner, rows) = v3(&path);
    let mut ledger = open(&path);
    assert_eq!(
        ledger
            .connection
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    for (id, lease, revision, phase, instance, nonce) in rows {
        let (stored_lease, stored_revision, stored_phase, context) =
            lookup(&ledger.connection, &owner, id).unwrap().unwrap();
        assert_eq!(
            (stored_lease, stored_revision, stored_phase, context),
            (lease, revision, Phase::parse(phase).unwrap(), None)
        );
        let saved: (Option<Vec<u8>>, Option<Vec<u8>>) = ledger
            .connection
            .query_row(
                "SELECT instance,nonce FROM invocations WHERE invocation=?1",
                [id.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            saved,
            (
                instance.map(|v| v.as_bytes().to_vec()),
                nonce.map(|v| v.as_bytes().to_vec())
            )
        );
        assert!(matches!(
            ledger
                .admit(&owner, id, bound(&owner, lease, revision, 1))
                .unwrap(),
            Admission::Conflict
        ));
    }
    let ticket = ledger.pending_for_review(1).unwrap().tickets.remove(0);
    assert!(ticket.context.is_none());
    let (lease, revision) = (ticket.lease, ticket.revision);
    assert!(matches!(
        ledger.claim(ticket, bound(&owner, lease, revision, 1), Uuid::new_v4()),
        Err(LedgerError::StaleLease)
    ));
    assert!(ledger.requires_review().unwrap());
    drop(ledger);
    let ledger = open(&path);
    assert_eq!(
        ledger
            .connection
            .query_row::<i64, _, _>(
                "SELECT count(*) FROM invocations WHERE context IS NULL",
                [],
                |r| r.get(0)
            )
            .unwrap(),
        6
    );
}

#[test]
fn version3_migration_commit_failure_preserves_exact_bytes_and_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v3.db");
    v3(&path);
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
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        3
    );
    validate_schema(&db, Layout::Boot).unwrap();
    drop(db);
    drop(open(&path));
}

#[test]
fn malformed_context_length_is_preserved_and_refused_before_any_claim() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.db");
    let mut ledger = open(&path);
    enqueue(
        &mut ledger,
        &caller(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    ledger
        .connection
        .execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE invocations SET context=x'01'")
        .unwrap();
    assert!(matches!(
        ledger.pending_for_review(1),
        Err(LedgerError::CorruptDatabase)
    ));
    drop(ledger);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        Ledger::open(Connection::open(&path).unwrap()),
        Err(LedgerError::CorruptDatabase)
    ));
    assert_eq!(std::fs::read(path).unwrap(), before);
}
