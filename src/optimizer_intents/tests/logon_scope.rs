use super::*;

fn scoped(logon: &str) -> Caller {
    Caller::fixture_logon(owner().account(), owner().session(), logon)
}
fn scoped_intent(caller: &Caller, base: &Intent) -> Intent {
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
fn query_phase(j: &Journal, caller: &Caller, i: &Intent) -> Phase {
    j.query(caller, i.operation).unwrap().unwrap().phase
}

#[test]
fn logon_documents_use_canonical_v4_and_preserve_old_document_versions() {
    let first = scoped("S-1-5-5-1-2");
    let mut old = intent();
    for version in 1..=3 {
        if version == 2 {
            old.keys[1].kind = KeyKind::RemoveKey;
            old.keys[1].values[0].desired = None;
        }
        if version == 3 {
            old.keys[0].kind = KeyKind::Guarded;
        }
        old.version = version;
        let bytes = old.encode().unwrap();
        assert!(!bytes.contains("logon_sid"));
        assert_eq!(Intent::decode(&bytes).unwrap().encode().unwrap(), bytes);
        let current = scoped_intent(&first, &old);
        assert_eq!(current.version, 4);
        let bytes = current.encode().unwrap();
        assert_eq!(Intent::decode(&bytes).unwrap(), current);
        for bad in [
            "",
            "S-1-5-5-01-2",
            "S-1-5-5-1-4294967296",
            "S-1-5-21-1-2",
            "S-1-5-5-1-2-3",
        ] {
            let mut wrong = current.clone();
            wrong.logon_sid = Some(bad.into());
            assert!(wrong.encode().is_err());
        }
        let mut wrong = current.clone();
        wrong.version = version;
        assert!(wrong.encode().is_err());
        let null = old
            .encode()
            .unwrap()
            .replace("\"image\":", "\"logon_sid\":null,\"image\":");
        assert!(Intent::decode(&null).is_err());
    }
}

#[test]
fn identical_operation_ids_are_isolated_across_reopen_review_and_abandonment() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("intents.db");
    let first = scoped("S-1-5-5-1-2");
    let second = scoped("S-1-5-5-1-3");
    let a = scoped_intent(&first, &intent());
    let mut b = scoped_intent(&second, &a);
    b.lease = Uuid::new_v4();
    let mut j = open(&path);
    drop(prepare(&mut j, a.clone()));
    assert!(j.query(&second, a.operation).unwrap().is_none());
    drop(prepare(&mut j, b.clone()));
    drop(j);
    let mut j = open(&path);
    let reviewed = j.review_after(&first, 1, None).unwrap().records.remove(0);
    assert_eq!(reviewed.intent, a);
    assert!(matches!(
        j.abandon_reviewed_prepared(&second, &reviewed),
        Err(Error::Stale)
    ));
    j.abandon_reviewed_prepared(&first, &reviewed).unwrap();
    assert_eq!(query_phase(&j, &first, &a), Phase::Abandoned);
    assert_eq!(query_phase(&j, &second, &b), Phase::Prepared);
    assert!(j.review_after(&first, 1, None).unwrap().records.is_empty());
    assert_eq!(
        j.review_after(&second, 1, None).unwrap().records[0].intent,
        b
    );
    assert!(j.query(&owner(), a.operation).unwrap().is_none());
}

#[test]
fn lease_exclusion_remains_global_and_cursors_keep_their_logon_scope() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&dir.path().join("intents.db"));
    let first = scoped("S-1-5-5-1-2");
    let second = scoped("S-1-5-5-1-3");
    let a = scoped_intent(&first, &intent());
    let mut b = scoped_intent(&second, &a);
    let p = prepare(&mut j, a.clone());
    assert!(matches!(j.prepare(b.clone()), Err(Error::BusyLease)));
    b.lease = Uuid::new_v4();
    drop(prepare(&mut j, b.clone()));
    let mut a2 = a.clone();
    a2.operation = Uuid::new_v4();
    a2.lease = Uuid::new_v4();
    drop(prepare(&mut j, a2));
    let cursor = j.review_after(&first, 1, None).unwrap().next.unwrap();
    assert!(matches!(
        j.review_after(&second, 1, Some(&cursor)),
        Err(Error::Stale)
    ));
    assert_eq!(
        j.review_after(&first, 1, Some(&cursor))
            .unwrap()
            .records
            .len(),
        1
    );
    let mut all = Vec::new();
    let mut cursor = None;
    loop {
        let page = unsafe { j.review_all_service_after(1, cursor.as_ref()) }.unwrap();
        all.extend(
            page.records
                .into_iter()
                .map(|r| (r.intent.logon_sid, r.intent.operation)),
        );
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(all.len(), 3);
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 3);
    j.abandon_prepared(p).unwrap();
    let mut same_lease = scoped_intent(&second, &a);
    same_lease.operation = Uuid::new_v4();
    drop(prepare(&mut j, same_lease));
}

#[test]
fn receipt_and_state_transitions_cannot_cross_logon_even_with_matching_ids() {
    let dir = tempfile::tempdir().unwrap();
    let mut j = open(&dir.path().join("intents.db"));
    let first = scoped("S-1-5-5-1-2");
    let second = scoped("S-1-5-5-1-3");
    let a = scoped_intent(&first, &intent());
    let b = scoped_intent(&second, &a);
    let r = attempt(&mut j, &a);
    let epoch = r.instance;
    // Deliberately forge private fixture internals to verify SQL CAS, not authority.
    let mut forged = duplicate_fixture_receipt(&r);
    forged.intent = b.clone();
    forged.document = b.encode().unwrap();
    assert!(matches!(j.mark_uncertain(forged), Err(Error::Stale)));
    let saved = j
        .record_observation_receipt(fixture_proof(r, report(&a, true)))
        .unwrap();
    assert!(saved.matches(&a, epoch));
    assert!(!saved.matches(&b, epoch));
    assert_eq!(query_phase(&j, &first, &a), Phase::ObservedDesired);
    let p = prepare(&mut j, b.clone());
    let r = j.begin_commit(p, b.revision, epoch).unwrap().into_attempt();
    j.mark_uncertain(r).unwrap();
    assert_eq!(query_phase(&j, &second, &b), Phase::Uncertain);
    assert_eq!(query_phase(&j, &first, &a), Phase::ObservedDesired);
}

fn seed_v2(
    path: &Path,
) -> Vec<(
    Intent,
    i64,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
)> {
    let db = Connection::open(path).unwrap();
    db.execute_batch(V2_TABLE).unwrap();
    db.execute_batch(INDEX).unwrap();
    db.pragma_update(None, "application_id", APP_ID).unwrap();
    db.pragma_update(None, "user_version", 2).unwrap();
    (0..6)
        .map(|phase| {
            let i = intent();
            let observation = match phase {
                2 => {
                    let mut o = report(&i, true);
                    o.status = ReadStatus::Changed;
                    Some(o.encode(&i).unwrap())
                }
                4 => Some(report(&i, false).encode(&i).unwrap()),
                5 => Some(report(&i, true).encode(&i).unwrap()),
                _ => None,
            };
            let instance =
                matches!(phase, 1 | 2 | 4 | 5).then(|| Uuid::new_v4().as_bytes().to_vec());
            let nonce = instance
                .as_ref()
                .map(|_| Uuid::new_v4().as_bytes().to_vec());
            db.execute(
                "INSERT INTO intents VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    i.account,
                    i.session,
                    i.operation.as_bytes().as_slice(),
                    i.lease.as_bytes().as_slice(),
                    i.revision.as_bytes().as_slice(),
                    i.encode().unwrap(),
                    phase,
                    instance,
                    nonce,
                    observation
                ],
            )
            .unwrap();
            (i, phase, observation, instance, nonce)
        })
        .collect()
}

#[test]
fn v2_migration_preserves_all_phases_exact_documents_reports_and_attempt_ids_unbound() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    let rows = seed_v2(&path);
    let mut j = open(&path);
    let caller = scoped("S-1-5-5-1-2");
    for (i, phase, observation, instance, nonce) in rows {
        let row = j.query(&owner(), i.operation).unwrap().unwrap();
        assert_eq!(row.intent, i);
        assert_eq!(row.phase, Phase::parse(phase).unwrap());
        assert!(row.intent.logon_sid.is_none());
        let persisted: (
            String,
            Option<String>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            String,
        ) = j
            .connection
            .query_row(
                "SELECT document,observation,instance,nonce,logon FROM intents WHERE operation=?1",
                [i.operation.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            persisted,
            (
                i.encode().unwrap(),
                observation,
                instance,
                nonce,
                String::new()
            )
        );
        assert!(j.query(&caller, i.operation).unwrap().is_none());
        assert!(matches!(
            j.prepare(scoped_intent(&caller, &i)),
            Err(Error::Conflict)
        ));
        assert!(matches!(j.prepare(i), Ok(Preparation::Existing(_))));
    }
    assert!(
        j.review_after(&caller, 64, None)
            .unwrap()
            .records
            .is_empty()
    );
    drop(j);
    drop(open(&path));
}

#[test]
fn v1_and_v2_failed_migration_commit_restore_byte_exact_database_and_schema() {
    unsafe extern "C" fn reject(_: *mut std::ffi::c_void) -> i32 {
        1
    }
    for version in [1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        if version == 1 {
            legacy(&path);
        } else {
            seed_v2(&path);
        }
        let before = std::fs::read(&path).unwrap();
        let db = Connection::open(&path).unwrap();
        unsafe {
            rusqlite::ffi::sqlite3_commit_hook(db.handle(), Some(reject), std::ptr::null_mut());
        }
        assert!(Journal::open(db).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            version
        );
        schema(
            &db,
            if version == 1 {
                Layout::Legacy
            } else {
                Layout::V2
            },
        )
        .unwrap();
        drop(db);
        drop(open(&path));
    }
}

#[test]
fn invalid_scope_metadata_and_unsupported_old_databases_preserve_bytes() {
    for case in 0..7 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        if case < 4 {
            seed_v2(&path);
        } else {
            let mut j = open(&path);
            let i = scoped_intent(&scoped("S-1-5-5-1-2"), &intent());
            drop(prepare(&mut j, i));
        }
        let db = Connection::open(&path).unwrap();
        match case {
            1 => db.execute_batch("CREATE TABLE extra(x)").unwrap(),
            2 => {
                db.pragma_update(None, "journal_mode", "WAL").unwrap();
            }
            3 => {
                db.execute("UPDATE intents SET document=document||' '", [])
                    .unwrap();
            }
            4 => {
                db.execute("UPDATE intents SET logon='S-1-5-5-1-3'", [])
                    .unwrap();
            }
            5 => {
                db.execute("UPDATE intents SET logon='S-1-5-5-01-2'", [])
                    .unwrap();
            }
            6 => {
                db.pragma_update(None, "user_version", 99).unwrap();
            }
            _ => (),
        }
        drop(db);
        let before = std::fs::read(&path).unwrap();
        let db = Connection::open(&path).unwrap();
        if case == 0 {
            db.pragma_update(None, "query_only", true).unwrap();
        }
        assert!(Journal::open(db).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn simultaneous_logons_share_lease_exclusion_without_sharing_operation_records() {
    for shared_lease in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("concurrent.db");
        drop(open(&path));
        let first = scoped("S-1-5-5-1-2");
        let second = scoped("S-1-5-5-1-3");
        let a = scoped_intent(&first, &intent());
        let mut b = scoped_intent(&second, &a);
        if !shared_lease {
            b.lease = Uuid::new_v4();
        }
        let barrier = Arc::new(Barrier::new(2));
        let workers: Vec<_> = [a.clone(), b.clone()]
            .into_iter()
            .map(|i| {
                let path = path.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    let mut j = open(&path);
                    barrier.wait();
                    match j.prepare(i) {
                        Ok(Preparation::New(_)) => true,
                        Err(Error::BusyLease) => false,
                        _ => panic!("unexpected concurrent admission outcome"),
                    }
                })
            })
            .collect();
        let admitted = workers
            .into_iter()
            .map(|w| usize::from(w.join().unwrap()))
            .sum::<usize>();
        assert_eq!(admitted, if shared_lease { 1 } else { 2 });
        let j = open(&path);
        let first_row = j.query(&first, a.operation).unwrap();
        let second_row = j.query(&second, b.operation).unwrap();
        assert_eq!(
            usize::from(first_row.is_some()) + usize::from(second_row.is_some()),
            admitted
        );
        if let Some(row) = first_row {
            assert_eq!(row.intent, a);
        }
        if let Some(row) = second_row {
            assert_eq!(row.intent, b);
        }
    }
}
