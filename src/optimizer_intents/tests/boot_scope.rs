use super::*;
fn caller(boot: Option<Uuid>) -> Caller {
    let c = owner();
    match boot {
        Some(id) => Caller::fixture_boot(c.account(), c.session(), "S-1-5-5-1-2", id),
        None => Caller::fixture_logon(c.account(), c.session(), "S-1-5-5-1-2"),
    }
}
fn scoped(caller: &Caller, base: &Intent) -> Intent {
    Intent::from_owner(
        caller,
        base.operation,
        base.lease,
        base.revision,
        base.image.clone(),
        base.view,
        base.keys.clone(),
    )
    .unwrap()
}

#[test]
fn boot_documents_require_canonical_v5_and_preserve_unbound_v4_bytes() {
    let base = scoped(&caller(None), &intent());
    let bytes = base.encode().unwrap();
    assert_eq!(base.version, 4);
    assert!(!bytes.contains("boot_id"));
    assert_eq!(Intent::decode(&bytes).unwrap(), base);
    let bound = scoped(&caller(Some(Uuid::new_v4())), &base);
    assert_eq!(bound.version, 5);
    let bytes = bound.encode().unwrap();
    assert_eq!(Intent::decode(&bytes).unwrap(), bound);
    let mut bad = bound.clone();
    bad.boot_id = Some(Uuid::nil());
    assert!(bad.encode().is_err());
    bad = bound.clone();
    bad.logon_sid = None;
    assert!(bad.encode().is_err());
    bad = bound.clone();
    bad.version = 4;
    assert!(bad.encode().is_err());
    assert!(
        Intent::decode(&bytes.replace(
            &format!("\"boot_id\":\"{}\"", bound.boot_id.unwrap()),
            "\"boot_id\":null"
        ))
        .is_err()
    );
}

#[test]
fn identical_logon_operation_and_lease_cannot_share_boot_queries_receipts_or_active_reservations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("intents.db");
    let mut j = open(&path);
    let a = caller(Some(Uuid::new_v4()));
    let b = caller(Some(Uuid::new_v4()));
    let first = scoped(&a, &intent());
    let second = scoped(&b, &first);
    let p = prepare(&mut j, first.clone());
    assert!(j.query(&b, first.operation).unwrap().is_none());
    assert!(matches!(j.prepare(second.clone()), Err(Error::BusyLease)));
    let mut extra = first.clone();
    extra.operation = Uuid::new_v4();
    extra.lease = Uuid::new_v4();
    drop(prepare(&mut j, extra));
    let cursor = j.review_after(&a, 1, None).unwrap().next.unwrap();
    assert!(matches!(
        j.review_after(&b, 1, Some(&cursor)),
        Err(Error::Stale)
    ));
    let epoch = Uuid::new_v4();
    let r = j
        .begin_commit(p, first.revision, epoch)
        .unwrap()
        .into_attempt();
    let mut forged = duplicate_fixture_receipt(&r);
    forged.intent = second.clone();
    forged.document = second.encode().unwrap();
    assert!(matches!(j.mark_uncertain(forged), Err(Error::Stale)));
    let receipt = j
        .record_observation_receipt(fixture_proof(r, report(&first, true)))
        .unwrap();
    assert!(receipt.matches(&first, epoch));
    assert!(!receipt.matches(&second, epoch));
    drop(prepare(&mut j, second.clone()));
    drop(j);
    let mut j = open(&path);
    let record = j.query(&b, second.operation).unwrap().unwrap();
    assert!(matches!(
        j.abandon_reviewed_prepared(&a, &record),
        Err(Error::Stale)
    ));
    j.abandon_reviewed_prepared(&b, &record).unwrap();
    assert_eq!(
        j.query(&a, first.operation).unwrap().unwrap().phase,
        Phase::ObservedDesired
    );
    assert_eq!(
        j.query(&b, second.operation).unwrap().unwrap().phase,
        Phase::Abandoned
    );
}

fn seed_v3(
    path: &Path,
) -> Vec<(
    Intent,
    i64,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
)> {
    let db = Connection::open(path).unwrap();
    db.execute_batch(V3_TABLE).unwrap();
    db.execute_batch(INDEX).unwrap();
    db.pragma_update(None, "application_id", APP_ID).unwrap();
    db.pragma_update(None, "user_version", 3).unwrap();
    (0..6).map(|phase| {
        let i=scoped(&caller(None),&intent());
        let observation=match phase {2=>{let mut o=report(&i,true);o.status=ReadStatus::Changed;Some(o.encode(&i).unwrap())},
            4=>Some(report(&i,false).encode(&i).unwrap()),5=>Some(report(&i,true).encode(&i).unwrap()),_=>None};
        let instance=matches!(phase,1|2|4|5).then(||Uuid::new_v4().as_bytes().to_vec());
        let nonce=instance.as_ref().map(|_|Uuid::new_v4().as_bytes().to_vec());
        db.execute("INSERT INTO intents(account,session,logon,operation,lease,revision,document,phase,instance,nonce,observation) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![i.account,i.session,i.logon_sid,i.operation.as_bytes().as_slice(),i.lease.as_bytes().as_slice(),i.revision.as_bytes().as_slice(),i.encode().unwrap(),phase,instance,nonce,observation]).unwrap();
        (i,phase,observation,instance,nonce)
    }).collect()
}

#[test]
fn v3_intent_migration_preserves_scoped_documents_reports_and_all_phases_with_unknown_boot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    let rows = seed_v3(&path);
    let mut j = open(&path);
    let current = caller(Some(Uuid::new_v4()));
    for (i, phase, observation, instance, nonce) in rows {
        let record = j.query(&caller(None), i.operation).unwrap().unwrap();
        assert_eq!(record.intent, i);
        assert_eq!(record.phase, Phase::parse(phase).unwrap());
        let saved: (
            String,
            Vec<u8>,
            Option<String>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        ) = j
            .connection
            .query_row(
                "SELECT document,boot,observation,instance,nonce FROM intents WHERE operation=?1",
                [i.operation.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            saved,
            (
                i.encode().unwrap(),
                vec![0; 16],
                observation,
                instance,
                nonce
            )
        );
        assert!(j.query(&current, i.operation).unwrap().is_none());
        assert!(matches!(
            j.prepare(scoped(&current, &i)),
            Err(Error::Conflict)
        ));
    }
    assert!(
        j.review_after(&current, 64, None)
            .unwrap()
            .records
            .is_empty()
    );
    drop(j);
    drop(open(&path));
}

#[test]
fn failed_v3_intent_upgrade_commit_restores_exact_database_bytes_and_old_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    seed_v3(&path);
    let before = std::fs::read(&path).unwrap();
    let db = Connection::open(&path).unwrap();
    unsafe extern "C" fn reject(_: *mut std::ffi::c_void) -> i32 {
        1
    }
    unsafe {
        rusqlite::ffi::sqlite3_commit_hook(db.handle(), Some(reject), std::ptr::null_mut());
    }
    assert!(Journal::open(db).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let db = Connection::open(&path).unwrap();
    schema(&db, Layout::V3).unwrap();
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        3
    );
    drop(db);
    drop(open(&path));
}

#[test]
fn intent_boot_metadata_mismatch_or_truncation_preserves_the_database_on_refusal() {
    for case in 0..2 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.db");
        let mut j = open(&path);
        drop(prepare(
            &mut j,
            scoped(&caller(Some(Uuid::new_v4())), &intent()),
        ));
        if case == 0 {
            j.connection
                .execute("UPDATE intents SET boot=randomblob(16)", [])
                .unwrap();
        } else {
            j.connection
                .execute_batch("PRAGMA ignore_check_constraints=ON;UPDATE intents SET boot=X'01'")
                .unwrap();
        }
        drop(j);
        let before = std::fs::read(&path).unwrap();
        assert!(Journal::open(Connection::open(&path).unwrap()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
