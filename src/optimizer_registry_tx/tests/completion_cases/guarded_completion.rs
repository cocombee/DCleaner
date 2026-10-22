use super::*;

fn harness() -> Harness {
    harness_with_root(Some(dword(1)))
}
fn harness_with_root(original: Option<RawValue>) -> Harness {
    Harness::build_with_setup(
        false,
        Some(vec![
            KeyChange {
                path: "b.exe".into(),
                kind: KeyKind::Guarded,
                values: vec![
                    change(Name::UseFilter, original.clone(), Some(dword(1))),
                    change(Name::Debugger, None, None),
                ],
            },
            KeyChange {
                path: "b.exe\\owned".into(),
                kind: KeyKind::NewLeaf,
                values: vec![
                    change(Name::Debugger, None, Some(dword(2))),
                    change(Name::FilterFullPath, None, Some(dword(3))),
                ],
            },
        ]),
        |reg| {
            if let Some(value) = original {
                assert_eq!(
                    write(&reg.open("b.exe").unwrap(), Name::UseFilter, &value),
                    ERROR_SUCCESS
                );
            }
        },
    )
}

#[test]
fn native_guarded_key_can_mix_a_real_change_with_same_state_preconditions() {
    require_txr!();
    let mut h = harness_with_root(None);
    assert_eq!(h.claims.len(), 3);
    let binding = Completion::bind(
        h.reg.scope(),
        h.intent.clone(),
        std::mem::take(&mut h.claims),
    )
    .unwrap();
    let receipt = commit(&mut h.journal, &binding, h.instance, 0, &h.reg);
    assert_eq!(receipt.phase(), IntentPhase::ObservedDesired);
    let observations = h.observations();
    assert_eq!(
        binding
            .finish(&mut h.catalog, receipt, observations)
            .unwrap(),
        vec![Phase::Sleeping; 3]
    );
    assert_eq!(
        read_value(&h.reg.open("b.exe").unwrap(), Name::UseFilter).unwrap(),
        Some(dword(1))
    );
    assert_eq!(
        read_value(&h.reg.open("b.exe").unwrap(), Name::Debugger).unwrap(),
        None
    );
}

#[test]
fn native_guarded_root_uses_only_effect_claims_and_settles_after_durable_observation() {
    require_txr!();
    let mut h = harness();
    assert_eq!(h.claims.len(), 2);
    assert_eq!(serde_json::to_value(&h.intent).unwrap()["version"], 3);
    let binding = Completion::bind(
        h.reg.scope(),
        h.intent.clone(),
        std::mem::take(&mut h.claims),
    )
    .unwrap();
    let receipt = commit(&mut h.journal, &binding, h.instance, 0, &h.reg);
    assert_eq!(receipt.phase(), IntentPhase::ObservedDesired);
    let observations = h.observations();
    assert_eq!(
        binding
            .finish(&mut h.catalog, receipt, observations)
            .unwrap(),
        vec![Phase::Sleeping; 2]
    );
    assert_eq!(
        read_value(&h.reg.open("b.exe").unwrap(), Name::Debugger).unwrap(),
        None
    );
    assert_eq!(
        read_value(&h.reg.open("b.exe").unwrap(), Name::UseFilter).unwrap(),
        Some(dword(1))
    );
}

#[test]
fn native_guard_changed_after_journal_receipt_makes_every_effect_uncertain() {
    require_txr!();
    for name in [Name::UseFilter, Name::Debugger] {
        let mut h = harness();
        let binding = Completion::bind(
            h.reg.scope(),
            h.intent.clone(),
            std::mem::take(&mut h.claims),
        )
        .unwrap();
        let receipt = commit(&mut h.journal, &binding, h.instance, 0, &h.reg);
        assert_eq!(receipt.phase(), IntentPhase::ObservedDesired);
        assert_eq!(
            write(&h.reg.open("b.exe").unwrap(), name, &dword(7)),
            ERROR_SUCCESS
        );
        let observations = h.observations();
        assert_eq!(
            binding
                .finish(&mut h.catalog, receipt, observations)
                .unwrap(),
            vec![Phase::Uncertain; 2]
        );
        assert_eq!(
            read_value(&h.reg.open("b.exe").unwrap(), name).unwrap(),
            Some(dword(7))
        );
        assert!(h.catalog.requires_review(h.instance).unwrap());
    }
}

#[test]
fn native_guard_cancel_and_preexisting_foreign_debugger_do_not_publish_sleep() {
    require_txr!();
    let mut h = harness();
    let binding = Completion::bind(
        h.reg.scope(),
        h.intent.clone(),
        std::mem::take(&mut h.claims),
    )
    .unwrap();
    let receipt = commit(&mut h.journal, &binding, h.instance, 1, &h.reg);
    let observations = h.observations();
    assert_eq!(
        binding
            .finish(&mut h.catalog, receipt, observations)
            .unwrap(),
        vec![Phase::Uncertain; 2]
    );
    assert!(matches!(
        h.reg.open("b.exe\\owned"),
        Err(Failure::Native(2))
    ));
    let mut h = harness();
    let binding = Completion::bind(
        h.reg.scope(),
        h.intent.clone(),
        std::mem::take(&mut h.claims),
    )
    .unwrap();
    assert_eq!(
        write(&h.reg.open("b.exe").unwrap(), Name::Debugger, &dword(7)),
        ERROR_SUCCESS
    );
    let cancel = AtomicBool::new(false);
    assert!(
        binding
            .stage(Instant::now() + Duration::from_secs(5), &cancel)
            .is_err()
    );
    assert_eq!(h.phases(), vec![Phase::ChangingSleep; 2]);
    assert!(matches!(
        h.reg.open("b.exe\\owned"),
        Err(Failure::Native(2))
    ));
}
