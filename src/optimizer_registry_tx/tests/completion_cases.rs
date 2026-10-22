//! Real HKCU bytes and file-backed journals; synthetic app/roster identities.
//! None of these fixture values intercepts or launches an application.
mod guarded_completion;
mod namespace_completion;
mod root_gate_completion;
use super::*;
use crate::{
    optimizer_identity::{FileIdentity, ImageSnapshot, PeFormat, PeHeader},
    optimizer_intents::{Intent, Journal, Phase as IntentPhase, Preparation, RecordedAttempt},
    optimizer_registry_completion::{Completion, Error as CompletionError, slot_state},
    optimizer_requests::Caller,
    optimizer_resources::{Catalog, Claim, Member, Observation, Phase, ResourceId},
};
use rusqlite::Connection;
use std::sync::Arc;
use uuid::Uuid;

fn image() -> ImageSnapshot {
    ImageSnapshot {
        requested_path: r"C:\Fixture\app.exe".into(),
        final_path: r"\\?\C:\Fixture\app.exe".into(),
        identity: FileIdentity {
            volume_serial: 1,
            file_id: [1; 16],
        },
        size: 4096,
        creation_time: 1,
        last_write_time: 2,
        attributes: 32,
        hard_links: 1,
        sha256: "a".repeat(64),
        pe: PeHeader {
            machine: 0x8664,
            format: PeFormat::Pe32Plus,
            characteristics: 0x22,
            subsystem: 2,
            sections: 1,
            entry_point_rva: 4096,
            image_size: 8192,
            headers_size: 512,
        },
        bytes_read: 4608,
    }
}
fn fail_commits(connection: &Connection) -> Arc<AtomicBool> {
    unsafe extern "C" fn hook(context: *mut std::ffi::c_void) -> i32 {
        i32::from(unsafe { &*context.cast::<AtomicBool>() }.load(Ordering::SeqCst))
    }
    let flag = Arc::new(AtomicBool::new(false));
    // Flag is retained in Harness until after both owned connections close.
    unsafe {
        rusqlite::ffi::sqlite3_commit_hook(
            connection.handle(),
            Some(hook),
            Arc::as_ptr(&flag).cast_mut().cast(),
        );
    }
    flag
}
struct Harness {
    reg: Fixture,
    catalog: Catalog,
    journal: Journal,
    resource_failure: Arc<AtomicBool>,
    journal_failure: Arc<AtomicBool>,
    dir: tempfile::TempDir,
    caller: Caller,
    member: Member,
    instance: Uuid,
    ids: Vec<ResourceId>,
    claims: Vec<Claim>,
    intent: Intent,
}
fn native_state(reg: &Fixture, path: &str, name: Name) -> Vec<u8> {
    match reg.open(path) {
        Ok(key) => slot_state(true, read_value(&key, name).unwrap()).unwrap(),
        Err(Failure::Native(2 | 3)) => slot_state(false, None).unwrap(),
        _ => panic!("unexpected fixture key state"),
    }
}
impl Harness {
    fn observation(&self, id: &ResourceId, state: Vec<u8>) -> Observation {
        // Synthetic complete association is valid only inside this exact owned
        // disposable subtree. Actual state bytes came from native fixture reads.
        unsafe {
            Observation::from_native(
                id.clone(),
                self.instance,
                state,
                vec![self.member.clone()],
                true,
            )
        }
        .unwrap()
    }
    fn observations(&self) -> Vec<Observation> {
        self.intent
            .keys()
            .iter()
            .flat_map(|key| {
                key.values
                    .iter()
                    .filter(|v| !key.kind.is_guard(v))
                    .map(move |value| (key, value))
            })
            .zip(&self.ids)
            .map(|((key, value), id)| {
                self.observation(id, native_state(&self.reg, &key.path, value.name))
            })
            .collect()
    }
    fn new(leaf: bool) -> Self {
        Self::build(leaf, None)
    }
    fn with_plan(keys: Vec<KeyChange>) -> Self {
        Self::build(false, Some(keys))
    }
    fn build(leaf: bool, custom: Option<Vec<KeyChange>>) -> Self {
        Self::build_with_setup(leaf, custom, |_| {})
    }
    fn build_with_setup(
        leaf: bool,
        custom: Option<Vec<KeyChange>>,
        setup: impl FnOnce(&Fixture),
    ) -> Self {
        let reg = Fixture::new();
        drop(reg.create("a.exe"));
        drop(reg.create("b.exe"));
        assert_eq!(
            write(&reg.open("a.exe").unwrap(), Name::Debugger, &dword(42)),
            ERROR_SUCCESS
        );
        setup(&reg);
        let dir = tempfile::tempdir().unwrap();
        let r = Connection::open(dir.path().join("resources.db")).unwrap();
        let resource_failure = fail_commits(&r);
        let j = Connection::open(dir.path().join("intents.db")).unwrap();
        let journal_failure = fail_commits(&j);
        let catalog = Catalog::open(r).unwrap();
        let journal = Journal::open(j).unwrap();
        let caller = Caller::fixture("S-1-5-21-1-2-3-1001", 1);
        let member = Member::for_caller(&caller, "program:v1:hkcu:64:612e657865").unwrap();
        let instance = Uuid::new_v4();
        let keys = if let Some(keys) = custom {
            keys
        } else if leaf {
            vec![
                KeyChange {
                    path: "a.exe".into(),
                    kind: KeyKind::Existing,
                    values: vec![change(Name::UseFilter, None, Some(dword(1)))],
                },
                KeyChange {
                    path: "a.exe\\owned".into(),
                    kind: KeyKind::NewLeaf,
                    values: vec![
                        change(Name::Debugger, None, Some(dword(2))),
                        change(Name::FilterFullPath, None, Some(dword(3))),
                    ],
                },
            ]
        } else {
            vec![
                KeyChange {
                    path: "a.exe".into(),
                    kind: KeyKind::Existing,
                    values: vec![change(Name::UseFilter, None, Some(dword(1)))],
                },
                KeyChange {
                    path: "b.exe".into(),
                    kind: KeyKind::Existing,
                    values: vec![change(Name::UseFilter, None, Some(dword(1)))],
                },
            ]
        };
        let intent = Intent::from_owner(
            &caller,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            image(),
            RegistryView::Registry64,
            keys,
        )
        .unwrap();
        let mut h = Self {
            reg,
            catalog,
            journal,
            resource_failure,
            journal_failure,
            dir,
            caller,
            member,
            instance,
            ids: vec![],
            claims: vec![],
            intent,
        };
        let plan = h.intent.clone();
        for key in plan.keys() {
            for value in &key.values {
                if key.kind.is_guard(value) {
                    continue;
                }
                let id = h
                    .reg
                    .scope()
                    .planned_value_identity(&key.path, key.kind, value.name)
                    .unwrap();
                let state = native_state(&h.reg, &key.path, value.name);
                let observation = h.observation(&id, state.clone());
                h.catalog
                    .register(
                        observation,
                        slot_state(key.kind.after_present(), value.desired.clone()).unwrap(),
                    )
                    .unwrap();
                let revision = h.catalog.inspect(&id).unwrap().unwrap().revision;
                let revision = h
                    .catalog
                    .request(&id, revision, &h.caller, &h.member, true)
                    .unwrap();
                let observation = h.observation(&id, state);
                let claim = h
                    .catalog
                    .begin(&id, revision, observation)
                    .unwrap()
                    .unwrap();
                h.ids.push(id);
                h.claims.push(claim);
            }
        }
        h
    }
    fn phases(&self) -> Vec<Phase> {
        self.ids
            .iter()
            .map(|id| self.catalog.inspect(id).unwrap().unwrap().phase)
            .collect()
    }
}
fn commit(
    journal: &mut Journal,
    binding: &Completion<'_>,
    instance: Uuid,
    mode: u8,
    reg: &Fixture,
) -> RecordedAttempt {
    let intent = binding.intent().clone();
    let prepared = match journal.prepare(intent).unwrap() {
        Preparation::New(p) => p,
        _ => panic!("new intent required"),
    };
    let cancel = AtomicBool::new(false);
    let tx = binding
        .stage(Instant::now() + Duration::from_secs(5), &cancel)
        .unwrap();
    // The durable permit must use the exact revision encoded by this intent.
    let row: serde_json::Value = serde_json::to_value(binding.intent()).unwrap();
    let revision = Uuid::parse_str(row["revision"].as_str().unwrap()).unwrap();
    let permit = journal.begin_commit(prepared, revision, instance).unwrap();
    if [1, 5].contains(&mode) {
        cancel.store(true, Ordering::SeqCst);
    }
    let mut attempt = unsafe { tx.commit_recorded_intent(permit) };
    cancel.store(false, Ordering::SeqCst);
    if mode == 2 {
        attempt.outcome = Err(Failure::CommitUncertain(6800));
    }
    if mode == 3 {
        assert_eq!(
            write(&reg.open("b.exe").unwrap(), Name::UseFilter, &dword(7)),
            ERROR_SUCCESS
        );
    }
    if mode == 5 {
        for path in ["a.exe", "b.exe"] {
            assert_eq!(
                write(&reg.open(path).unwrap(), Name::UseFilter, &dword(1)),
                ERROR_SUCCESS
            );
        }
    }
    journal
        .record_observation_receipt(
            attempt.observe(Instant::now() + Duration::from_secs(5), &cancel),
        )
        .unwrap()
}

#[test]
fn native_recorded_group_roundtrip_settles_only_after_durable_receipt_and_preserves_other_values() {
    require_txr!();
    let mut h = Harness::new(false);
    let binding = Completion::bind(
        h.reg.scope(),
        h.intent.clone(),
        std::mem::take(&mut h.claims),
    )
    .unwrap();
    let receipt = commit(&mut h.journal, &binding, h.instance, 0, &h.reg);
    assert_eq!(receipt.phase(), IntentPhase::ObservedDesired);
    assert_eq!(h.phases(), vec![Phase::ChangingSleep; 2]);
    let mut observations = h.observations();
    observations.reverse();
    assert_eq!(
        binding
            .finish(&mut h.catalog, receipt, observations)
            .unwrap(),
        vec![Phase::Sleeping; 2]
    );
    let keys = vec![
        KeyChange {
            path: "a.exe".into(),
            kind: KeyKind::Existing,
            values: vec![change(Name::UseFilter, Some(dword(1)), None)],
        },
        KeyChange {
            path: "b.exe".into(),
            kind: KeyKind::Existing,
            values: vec![change(Name::UseFilter, Some(dword(1)), None)],
        },
    ];
    for id in &h.ids {
        let revision = h.catalog.inspect(id).unwrap().unwrap().revision;
        let revision = h
            .catalog
            .request(id, revision, &h.caller, &h.member, false)
            .unwrap();
        let observation = h.observation(id, slot_state(true, Some(dword(1))).unwrap());
        h.claims
            .push(h.catalog.begin(id, revision, observation).unwrap().unwrap());
    }
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
    let binding = Completion::bind(
        h.reg.scope(),
        h.intent.clone(),
        std::mem::take(&mut h.claims),
    )
    .unwrap();
    let receipt = commit(&mut h.journal, &binding, h.instance, 0, &h.reg);
    let observations = h.observations();
    assert_eq!(
        binding
            .finish(&mut h.catalog, receipt, observations)
            .unwrap(),
        vec![Phase::Awake; 2]
    );
    assert_eq!(
        read_value(&h.reg.open("a.exe").unwrap(), Name::Debugger).unwrap(),
        Some(dword(42))
    );
    assert_eq!(
        read_value(&h.reg.open("a.exe").unwrap(), Name::UseFilter).unwrap(),
        None
    );
}

#[test]
fn native_cancelled_uncertain_mixed_and_late_changed_groups_never_claim_sleep() {
    require_txr!();
    for mode in 1..=6 {
        let mut h = Harness::new(false);
        let binding = Completion::bind(
            h.reg.scope(),
            h.intent.clone(),
            std::mem::take(&mut h.claims),
        )
        .unwrap();
        let receipt = commit(&mut h.journal, &binding, h.instance, mode, &h.reg);
        if mode == 4 {
            assert_eq!(
                write(&h.reg.open("a.exe").unwrap(), Name::UseFilter, &dword(9)),
                ERROR_SUCCESS
            );
        }
        let mut observations = h.observations();
        if mode == 5 {
            assert_eq!(receipt.phase(), IntentPhase::ObservedDesired);
            assert_eq!(receipt.observation().disposition, Disposition::NotEntered);
        }
        if mode == 6 {
            observations[1].constrain_completion(false);
        }
        assert_eq!(
            binding
                .finish(&mut h.catalog, receipt, observations)
                .unwrap(),
            vec![Phase::Uncertain; 2]
        );
        assert!(h.catalog.requires_review(h.instance).unwrap());
    }
}

#[test]
fn native_later_stale_reservation_cannot_partially_settle_group() {
    require_txr!();
    let mut h = Harness::new(false);
    let binding = Completion::bind(
        h.reg.scope(),
        h.intent.clone(),
        std::mem::take(&mut h.claims),
    )
    .unwrap();
    let receipt = commit(&mut h.journal, &binding, h.instance, 0, &h.reg);
    let db = Connection::open(h.dir.path().join("resources.db")).unwrap();
    db.execute("UPDATE resources SET revision=?1 WHERE id=(SELECT id FROM resources ORDER BY id DESC LIMIT 1)",[Uuid::new_v4().as_bytes().as_slice()]).unwrap();
    let observations = h.observations();
    assert!(matches!(
        binding.finish(&mut h.catalog, receipt, observations),
        Err(CompletionError::Resources(
            crate::optimizer_resources::Error::Stale
        ))
    ));
    assert_eq!(h.phases(), vec![Phase::ChangingSleep; 2]);
}

#[test]
fn native_resource_commit_failure_keeps_all_reservations_and_does_not_replay_on_reopen() {
    require_txr!();
    let mut h = Harness::new(false);
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
    assert_eq!(h.phases(), vec![Phase::ChangingSleep; 2]);
    assert_eq!(
        write(&h.reg.open("a.exe").unwrap(), Name::UseFilter, &dword(9)),
        ERROR_SUCCESS
    );
    h.catalog =
        Catalog::open(Connection::open(h.dir.path().join("resources.db")).unwrap()).unwrap();
    assert_eq!(h.phases(), vec![Phase::ChangingSleep; 2]);
    assert_eq!(
        read_value(&h.reg.open("a.exe").unwrap(), Name::UseFilter).unwrap(),
        Some(dword(9))
    );
}

#[test]
fn native_failed_journal_commit_returns_no_completion_ticket_and_does_not_replay() {
    require_txr!();
    let mut h = Harness::new(false);
    let binding = Completion::bind(
        h.reg.scope(),
        h.intent.clone(),
        std::mem::take(&mut h.claims),
    )
    .unwrap();
    let document = serde_json::to_value(binding.intent()).unwrap();
    let revision = Uuid::parse_str(document["revision"].as_str().unwrap()).unwrap();
    let operation = Uuid::parse_str(document["operation"].as_str().unwrap()).unwrap();
    let prepared = match h.journal.prepare(binding.intent().clone()).unwrap() {
        Preparation::New(p) => p,
        _ => panic!("new intent required"),
    };
    let cancel = AtomicBool::new(false);
    let tx = binding
        .stage(Instant::now() + Duration::from_secs(5), &cancel)
        .unwrap();
    let permit = h
        .journal
        .begin_commit(prepared, revision, h.instance)
        .unwrap();
    let attempt = unsafe { tx.commit_recorded_intent(permit) };
    let report = attempt.observe(Instant::now() + Duration::from_secs(5), &cancel);
    h.journal_failure.store(true, Ordering::SeqCst);
    assert!(h.journal.record_observation_receipt(report).is_err());
    h.journal_failure.store(false, Ordering::SeqCst);
    let row = h.journal.query(&h.caller, operation).unwrap().unwrap();
    assert_eq!(row.phase, IntentPhase::CommitStarted);
    assert!(row.observation.is_none());
    assert_eq!(h.phases(), vec![Phase::ChangingSleep; 2]);
    assert_eq!(
        read_value(&h.reg.open("a.exe").unwrap(), Name::UseFilter).unwrap(),
        Some(dword(1))
    );
    drop(binding);
    assert_eq!(
        write(&h.reg.open("a.exe").unwrap(), Name::UseFilter, &dword(9)),
        ERROR_SUCCESS
    );
    h.journal = Journal::open(Connection::open(h.dir.path().join("intents.db")).unwrap()).unwrap();
    assert_eq!(
        h.journal
            .query(&h.caller, operation)
            .unwrap()
            .unwrap()
            .phase,
        IntentPhase::CommitStarted
    );
    assert_eq!(
        read_value(&h.reg.open("a.exe").unwrap(), Name::UseFilter).unwrap(),
        Some(dword(9))
    );
    assert_eq!(h.phases(), vec![Phase::ChangingSleep; 2]);
}

#[test]
fn native_missing_leaf_slots_bind_to_created_objects_and_do_not_fake_namespace_restoration() {
    require_txr!();
    let mut h = Harness::new(true);
    let binding = Completion::bind(
        h.reg.scope(),
        h.intent.clone(),
        std::mem::take(&mut h.claims),
    )
    .unwrap();
    let receipt = commit(&mut h.journal, &binding, h.instance, 0, &h.reg);
    let observations = h.observations();
    assert_eq!(
        binding
            .finish(&mut h.catalog, receipt, observations)
            .unwrap(),
        vec![Phase::Sleeping; 3]
    );
    let sleep_plan = h.intent.clone();
    for ((key, value), id) in sleep_plan
        .keys()
        .iter()
        .flat_map(|k| k.values.iter().map(move |v| (k, v)))
        .zip(&h.ids)
    {
        assert_eq!(
            h.reg.scope().value_identity(&key.path, value.name).unwrap(),
            *id
        );
        let revision = h.catalog.inspect(id).unwrap().unwrap().revision;
        let revision = h
            .catalog
            .request(id, revision, &h.caller, &h.member, false)
            .unwrap();
        let observation = h.observation(id, native_state(&h.reg, &key.path, value.name));
        h.claims
            .push(h.catalog.begin(id, revision, observation).unwrap().unwrap());
    }
    // Removing values would leave an empty key, whereas the saved original
    // leaf did not exist. A future key-removal owner must prove that restoration.
    let keys = sleep_plan
        .keys()
        .iter()
        .map(|k| KeyChange {
            path: k.path.clone(),
            kind: KeyKind::Existing,
            values: k
                .values
                .iter()
                .map(|v| change(v.name, v.desired.clone(), None))
                .collect(),
        })
        .collect();
    let intent = Intent::from_owner(
        &h.caller,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        image(),
        RegistryView::Registry64,
        keys,
    )
    .unwrap();
    assert!(matches!(
        Completion::bind(h.reg.scope(), intent, std::mem::take(&mut h.claims)),
        Err(CompletionError::Invalid)
    ));
    assert_eq!(
        read_value(&h.reg.open("a.exe\\owned").unwrap(), Name::Debugger).unwrap(),
        Some(dword(2))
    );
    assert_eq!(h.phases(), vec![Phase::ChangingWake; 3]);
}

#[test]
fn native_preflight_rejects_wrong_view_resource_and_raw_state_before_public_effects() {
    for mode in 0..3 {
        let mut h = Harness::new(false);
        let mut keys = h.intent.keys().to_vec();
        if mode == 1 {
            keys[0].values[0].expected = Some(dword(0));
        }
        if mode == 2 {
            drop(h.reg.create("other.exe"));
            keys[0].path = "other.exe".into();
        }
        let view = if mode == 0 {
            RegistryView::Registry32
        } else {
            RegistryView::Registry64
        };
        let intent = Intent::from_owner(
            &h.caller,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            image(),
            view,
            keys,
        )
        .unwrap();
        assert!(Completion::bind(h.reg.scope(), intent, std::mem::take(&mut h.claims)).is_err());
        assert_eq!(h.phases(), vec![Phase::ChangingSleep; 2]);
        assert_eq!(
            read_value(&h.reg.open("a.exe").unwrap(), Name::UseFilter).unwrap(),
            None
        );
        assert_eq!(
            read_value(&h.reg.open("b.exe").unwrap(), Name::UseFilter).unwrap(),
            None
        );
    }
}

#[test]
fn native_recorded_receipt_from_another_operation_or_epoch_cannot_settle_reservations() {
    require_txr!();
    for wrong_epoch in [false, true] {
        let mut h = Harness::new(false);
        let binding = Completion::bind(
            h.reg.scope(),
            h.intent.clone(),
            std::mem::take(&mut h.claims),
        )
        .unwrap();
        let mut document = serde_json::to_value(binding.intent()).unwrap();
        if !wrong_epoch {
            document["operation"] = serde_json::Value::String(Uuid::new_v4().to_string());
        }
        let other: Intent = serde_json::from_value(document.clone()).unwrap();
        let revision = Uuid::parse_str(document["revision"].as_str().unwrap()).unwrap();
        let prepared = match h.journal.prepare(other).unwrap() {
            Preparation::New(p) => p,
            _ => panic!("new intent required"),
        };
        let cancel = AtomicBool::new(false);
        let tx = binding
            .stage(Instant::now() + Duration::from_secs(5), &cancel)
            .unwrap();
        let instance = if wrong_epoch {
            Uuid::new_v4()
        } else {
            h.instance
        };
        let permit = h
            .journal
            .begin_commit(prepared, revision, instance)
            .unwrap();
        let attempt = unsafe { tx.commit_recorded_intent(permit) };
        let receipt = h
            .journal
            .record_observation_receipt(
                attempt.observe(Instant::now() + Duration::from_secs(5), &cancel),
            )
            .unwrap();
        assert_eq!(receipt.phase(), IntentPhase::ObservedDesired);
        let observations = h.observations();
        assert!(matches!(
            binding.finish(&mut h.catalog, receipt, observations),
            Err(CompletionError::Invalid)
        ));
        assert_eq!(h.phases(), vec![Phase::ChangingSleep; 2]);
    }
}

#[test]
fn native_duplicate_resource_evidence_is_not_a_complete_effect_group() {
    require_txr!();
    let mut h = Harness::new(false);
    let binding = Completion::bind(
        h.reg.scope(),
        h.intent.clone(),
        std::mem::take(&mut h.claims),
    )
    .unwrap();
    let receipt = commit(&mut h.journal, &binding, h.instance, 0, &h.reg);
    let observations = vec![
        h.observation(&h.ids[0], native_state(&h.reg, "a.exe", Name::UseFilter)),
        h.observation(&h.ids[0], native_state(&h.reg, "a.exe", Name::UseFilter)),
    ];
    assert!(matches!(
        binding.finish(&mut h.catalog, receipt, observations),
        Err(CompletionError::Invalid)
    ));
    assert_eq!(h.phases(), vec![Phase::ChangingSleep; 2]);
}
