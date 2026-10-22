use super::*;

fn scoped(logon: &str) -> Caller {
    Caller::fixture_logon(owner(1).account(), 1, logon)
}
fn pair() -> (Caller, Caller, Vec<Member>) {
    let a = scoped("S-1-5-5-1-2");
    let b = scoped("S-1-5-5-1-3");
    let members = vec![member(&a, "same app"), member(&b, "same app")];
    (a, b, members)
}

#[test]
fn member_logon_is_canonical_and_legacy_bytes_do_not_gain_an_invented_login() {
    let legacy = member(&owner(1), "same app");
    let original = serde_json::to_string(&legacy).unwrap();
    assert!(!original.contains("logon_sid"));
    let restored: Member = serde_json::from_str(&original).unwrap();
    assert_eq!(serde_json::to_string(&restored).unwrap(), original);
    assert!(restored.logon_sid.is_none());
    let (a, b, members) = pair();
    assert_ne!(members[0], members[1]);
    assert_ne!(members[0], legacy);
    assert!(members[0].belongs_to(&a));
    assert!(!members[0].belongs_to(&b));
    assert!(!legacy.belongs_to(&a));
    for text in ["", "S-1-5-5-01-2", "S-1-5-5-1-4294967296", "S-1-5-5-1-2-3"] {
        let mut bad = members[0].clone();
        bad.logon_sid = Some(text.into());
        assert!(bad.validate().is_err());
    }
}

#[test]
fn same_program_and_invocation_keep_separate_sleep_and_activation_state_per_logon() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resources.db");
    let mut c = open(&path);
    let (a, b, members) = pair();
    let epoch = Uuid::new_v4();
    let id = register(&mut c, epoch, &members);
    c.request(&id, rev(&c, &id), &a, &members[0], true).unwrap();
    assert_eq!(c.inspect(&id).unwrap().unwrap().target, Target::Awake);
    let revision = rev(&c, &id);
    assert!(matches!(
        c.request(&id, revision, &b, &members[0], false),
        Err(Error::NotAuthorized)
    ));
    assert_eq!(rev(&c, &id), revision);
    c.request(&id, revision, &b, &members[1], true).unwrap();
    let claim = c
        .begin(
            &id,
            rev(&c, &id),
            observe(&id, epoch, b"original", &members),
        )
        .unwrap()
        .unwrap();
    c.finish(claim, observe(&id, epoch, b"sleeping", &members))
        .unwrap();
    let invocation = Uuid::new_v4();
    c.begin_activation(&id, rev(&c, &id), &a, &members[0], invocation, epoch)
        .unwrap();
    assert!(matches!(
        c.begin_activation(&id, rev(&c, &id), &b, &members[0], invocation, epoch),
        Err(Error::NotAuthorized)
    ));
    c.begin_activation(&id, rev(&c, &id), &b, &members[1], invocation, epoch)
        .unwrap();
    let claim = c
        .begin(
            &id,
            rev(&c, &id),
            observe(&id, epoch, b"sleeping", &members),
        )
        .unwrap()
        .unwrap();
    c.finish(claim, observe(&id, epoch, b"original", &members))
        .unwrap();
    drop(c);
    let mut c = open(&path);
    assert_eq!(c.inspect(&id).unwrap().unwrap().temporary_activations, 2);
    for (index, m) in members.iter().enumerate() {
        // Synthetic process proof exercises exact membership bookkeeping only.
        let proof = unsafe {
            ActivationObservation::from_native(m.clone(), invocation, epoch, epoch, false)
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
    let row = load(&c.connection, &id).unwrap().unwrap();
    assert!(row.members.iter().all(|d| d.sleep && d.wakes.is_empty()));
    assert_eq!(row.baseline, b"original");
}

#[test]
fn legacy_demand_requires_explicit_membership_review_and_cannot_be_inherited_or_released() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resources.db");
    let mut c = open(&path);
    let old = member(&owner(1), "same app");
    let a = scoped("S-1-5-5-1-2");
    let current = member(&a, "same app");
    let epoch = Uuid::new_v4();
    let id = register(&mut c, epoch, &[old.clone()]);
    sleep(&mut c, &id, epoch, &owner(1), &[old.clone()]);
    let bytes: String = c
        .connection
        .query_row("SELECT members FROM resources", [], |r| r.get(0))
        .unwrap();
    drop(c);
    let mut c = open(&path);
    assert_eq!(
        c.connection
            .query_row::<String, _, _>("SELECT members FROM resources", [], |r| r.get(0))
            .unwrap(),
        bytes
    );
    assert!(matches!(
        c.register(
            observe(&id, epoch, b"sleeping", &[current.clone()]),
            b"sleeping".to_vec()
        ),
        Err(Error::Changed)
    ));
    let both = vec![old.clone(), current.clone()];
    c.register(
        observe(&id, epoch, b"sleeping", &both),
        b"sleeping".to_vec(),
    )
    .unwrap();
    let row = load(&c.connection, &id).unwrap().unwrap();
    assert!(row.members.iter().find(|d| d.member == old).unwrap().sleep);
    assert!(
        !row.members
            .iter()
            .find(|d| d.member == current)
            .unwrap()
            .sleep
    );
    assert_eq!(row.target(), Target::Awake);
    assert!(matches!(
        c.request(&id, rev(&c, &id), &a, &old, false),
        Err(Error::NotAuthorized)
    ));
    assert!(matches!(
        c.release_member(
            &id,
            rev(&c, &id),
            &a,
            &old,
            observe(&id, epoch, b"original", &[current])
        ),
        Err(Error::NotAuthorized)
    ));
}

fn root(c: &mut Catalog, epoch: Uuid, members: &[Member], hook: &ResourceId) -> ResourceId {
    let id = id();
    // Synthetic complete ownership fixture, never real IFEO authority.
    unsafe {
        c.register_root_gate(
            observe(&id, epoch, b"original", members),
            b"enabled".to_vec(),
            members.iter().map(|m| (hook.clone(), m.clone())).collect(),
        )
    }
    .unwrap();
    id
}

#[test]
fn shared_hook_references_keep_logon_consent_and_root_reservation_global() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resources.db");
    let mut c = open(&path);
    let (a, b, members) = pair();
    let epoch = Uuid::new_v4();
    let hook = unsafe { ResourceId::from_native(2, b"synthetic shared hook") }.unwrap();
    let id = root(&mut c, epoch, &members, &hook);
    c.request_root_hook(&id, rev(&c, &id), &a, &members[0], &hook, true)
        .unwrap();
    assert!(matches!(
        c.request_root_hook(&id, rev(&c, &id), &b, &members[0], &hook, false),
        Err(Error::NotAuthorized)
    ));
    c.request_root_hook(&id, rev(&c, &id), &b, &members[1], &hook, true)
        .unwrap();
    c.request_root_hook(&id, rev(&c, &id), &a, &members[0], &hook, false)
        .unwrap();
    assert_eq!(c.inspect(&id).unwrap().unwrap().target, Target::Sleep);
    let json: String = c
        .connection
        .query_row("SELECT members FROM resources", [], |r| r.get(0))
        .unwrap();
    assert!(json.starts_with("{\"version\":3,"));
    drop(c);
    let mut c = open(&path);
    let claim = c
        .begin_root_gate(
            &id,
            rev(&c, &id),
            observe(&id, epoch, b"original", &members),
        )
        .unwrap();
    let mut other = open(&path);
    assert!(matches!(
        other.begin_root_gate(
            &id,
            rev(&other, &id),
            observe(&id, epoch, b"original", &members)
        ),
        Err(Error::Busy)
    ));
    c.finish(claim, observe(&id, epoch, b"enabled", &members))
        .unwrap();
    c.request_root_hook(&id, rev(&c, &id), &b, &members[1], &hook, false)
        .unwrap();
    assert_eq!(c.inspect(&id).unwrap().unwrap().target, Target::Awake);
}

#[test]
fn mismatched_logon_rosters_cannot_begin_or_settle_a_resource_claim() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = open(&dir.path().join("resources.db"));
    let (a, _, members) = pair();
    let epoch = Uuid::new_v4();
    let id = register(&mut c, epoch, &members[..1]);
    c.request(&id, rev(&c, &id), &a, &members[0], true).unwrap();
    assert!(matches!(
        c.begin(
            &id,
            rev(&c, &id),
            observe(&id, epoch, b"original", &members[1..])
        ),
        Err(Error::Incomplete)
    ));
    let claim = c
        .begin(
            &id,
            rev(&c, &id),
            observe(&id, epoch, b"original", &members[..1]),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        c.finish(claim, observe(&id, epoch, b"sleeping", &members[1..]))
            .unwrap(),
        Phase::Uncertain
    );
}

#[test]
fn legacy_root_bytes_stay_v2_and_noncanonical_or_wrong_version_rosters_are_preserved_on_refusal() {
    for case in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resources.db");
        let mut c = open(&path);
        let (_, _, scoped_members) = pair();
        let epoch = Uuid::new_v4();
        let legacy = vec![member(&owner(1), "same app")];
        let members = if case == 0 { &legacy } else { &scoped_members };
        let hook = unsafe { ResourceId::from_native(2, b"synthetic hook") }.unwrap();
        let _id = root(&mut c, epoch, members, &hook);
        let original: String = c
            .connection
            .query_row("SELECT members FROM resources", [], |r| r.get(0))
            .unwrap();
        if case == 0 {
            assert!(original.starts_with("{\"version\":2,"));
            drop(c);
            let c = open(&path);
            assert_eq!(
                c.connection
                    .query_row::<String, _, _>("SELECT members FROM resources", [], |r| r.get(0))
                    .unwrap(),
                original
            );
        } else {
            let changed = match case {
                1 => original.replace("\"version\":3", "\"version\":2"),
                2 => original.replace("S-1-5-5-1-2", "S-1-5-5-01-2"),
                _ => original.replace("\"logon_sid\":\"S-1-5-5-1-2\"", "\"logon_sid\":null"),
            };
            assert_ne!(original, changed);
            c.connection
                .execute("UPDATE resources SET members=?1", [changed])
                .unwrap();
            drop(c);
            let before = std::fs::read(&path).unwrap();
            assert!(Catalog::open(Connection::open(&path).unwrap()).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }
}
