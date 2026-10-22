use super::*;

fn sleep_plan() -> Vec<KeyChange> {
    vec![
        KeyChange {
            path: "fresh.exe".into(),
            kind: KeyKind::NewRoot,
            values: vec![change(Name::UseFilter, None, Some(dword(1)))],
        },
        KeyChange {
            path: "fresh.exe\\owned".into(),
            kind: KeyKind::NewLeaf,
            values: vec![
                change(Name::Debugger, None, Some(dword(2))),
                change(Name::FilterFullPath, None, Some(dword(3))),
            ],
        },
    ]
}
fn removal_plan() -> Vec<KeyChange> {
    vec![
        KeyChange {
            path: "fresh.exe\\owned".into(),
            kind: KeyKind::RemoveKey,
            values: vec![
                change(Name::Debugger, Some(dword(2)), None),
                change(Name::FilterFullPath, Some(dword(3)), None),
            ],
        },
        KeyChange {
            path: "fresh.exe".into(),
            kind: KeyKind::RemoveKey,
            values: vec![change(Name::UseFilter, Some(dword(1)), None)],
        },
    ]
}
fn finish(h: &mut Harness, mode: u8) -> Vec<Phase> {
    let binding = Completion::bind(
        h.reg.scope(),
        h.intent.clone(),
        std::mem::take(&mut h.claims),
    )
    .unwrap();
    let receipt = commit(&mut h.journal, &binding, h.instance, mode, &h.reg);
    let observations = h.observations();
    binding
        .finish(&mut h.catalog, receipt, observations)
        .unwrap()
}
fn prepare_removal(h: &mut Harness) {
    let keys = removal_plan();
    let mut ids = Vec::new();
    let mut claims = Vec::new();
    for key in &keys {
        for value in &key.values {
            let id = h.reg.scope().value_identity(&key.path, value.name).unwrap();
            let revision = h.catalog.inspect(&id).unwrap().unwrap().revision;
            let revision = h
                .catalog
                .request(&id, revision, &h.caller, &h.member, false)
                .unwrap();
            let observation = h.observation(&id, native_state(&h.reg, &key.path, value.name));
            claims.push(
                h.catalog
                    .begin(&id, revision, observation)
                    .unwrap()
                    .unwrap(),
            );
            ids.push(id);
        }
    }
    h.ids = ids;
    h.claims = claims;
    h.intent = Intent::from_owner(
        &h.caller,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        image(),
        RegistryView::Registry64,
        keys,
    )
    .unwrap();
}

#[test]
fn native_created_image_tree_restores_absence_through_journal_and_catalog() {
    require_txr!();
    let mut h = Harness::with_plan(sleep_plan());
    assert_eq!(serde_json::to_value(&h.intent).unwrap()["version"], 2);
    assert_eq!(finish(&mut h, 0), vec![Phase::Sleeping; 3]);
    let sleep_ids = h.ids.clone();
    prepare_removal(&mut h);
    assert!(h.ids.iter().all(|id| sleep_ids.contains(id)));
    assert_eq!(finish(&mut h, 0), vec![Phase::Awake; 3]);
    assert!(matches!(h.reg.open("fresh.exe"), Err(Failure::Native(2))));
    assert!(matches!(
        h.reg.open("fresh.exe\\owned"),
        Err(Failure::Native(2 | 3))
    ));
    assert_eq!(
        read_value(&h.reg.open("a.exe").unwrap(), Name::Debugger).unwrap(),
        Some(dword(42))
    );
    assert!(!h.catalog.requires_review(h.instance).unwrap());
}

#[test]
fn native_cancelled_tree_creation_and_removal_do_not_publish_false_states() {
    require_txr!();
    let mut h = Harness::with_plan(sleep_plan());
    assert_eq!(finish(&mut h, 1), vec![Phase::Uncertain; 3]);
    assert!(matches!(h.reg.open("fresh.exe"), Err(Failure::Native(2))));
    let mut h = Harness::with_plan(sleep_plan());
    assert_eq!(finish(&mut h, 0), vec![Phase::Sleeping; 3]);
    prepare_removal(&mut h);
    assert_eq!(finish(&mut h, 1), vec![Phase::Uncertain; 3]);
    assert_eq!(
        read_value(&h.reg.open("fresh.exe\\owned").unwrap(), Name::Debugger).unwrap(),
        Some(dword(2))
    );
}

#[test]
fn native_tree_receipt_commit_failure_retains_uncertainty_without_recreation() {
    require_txr!();
    let mut h = Harness::with_plan(sleep_plan());
    assert_eq!(finish(&mut h, 0), vec![Phase::Sleeping; 3]);
    prepare_removal(&mut h);
    let binding = Completion::bind(
        h.reg.scope(),
        h.intent.clone(),
        std::mem::take(&mut h.claims),
    )
    .unwrap();
    let receipt = commit(&mut h.journal, &binding, h.instance, 0, &h.reg);
    let observations = h.observations();
    h.resource_failure.store(true, Ordering::SeqCst);
    assert!(
        binding
            .finish(&mut h.catalog, receipt, observations)
            .is_err()
    );
    h.resource_failure.store(false, Ordering::SeqCst);
    assert_eq!(h.phases(), vec![Phase::ChangingWake; 3]);
    h.catalog =
        Catalog::open(Connection::open(h.dir.path().join("resources.db")).unwrap()).unwrap();
    assert_eq!(h.phases(), vec![Phase::ChangingWake; 3]);
    assert!(matches!(h.reg.open("fresh.exe"), Err(Failure::Native(2))));
}

#[test]
fn native_completion_does_not_allow_sleep_by_deleting_a_preexisting_empty_key() {
    let plan = vec![KeyChange {
        path: "b.exe".into(),
        kind: KeyKind::RemoveKey,
        values: vec![change(Name::UseFilter, None, None)],
    }];
    let mut h = Harness::with_plan(plan);
    assert!(matches!(
        Completion::bind(
            h.reg.scope(),
            h.intent.clone(),
            std::mem::take(&mut h.claims)
        ),
        Err(CompletionError::Invalid)
    ));
    assert!(h.reg.open("b.exe").is_ok());
    assert_eq!(h.phases(), vec![Phase::ChangingSleep]);
}
