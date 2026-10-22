use super::*;
fn hooks(members: &[Member]) -> Vec<(ResourceId, Member)> {
    members
        .iter()
        .map(|member| {
            (
                unsafe { ResourceId::from_native(1, member.program.as_bytes()) }.unwrap(),
                member.clone(),
            )
        })
        .collect()
}

fn gate(c: &mut Catalog, instance: Uuid, members: &[Member], original: &[u8]) -> ResourceId {
    let id = id();
    // Synthetic role/association proof for a private file-backed database.
    unsafe {
        c.register_root_gate(
            observe(&id, instance, original, members),
            b"enabled".to_vec(),
            hooks(members),
        )
    }
    .unwrap();
    id
}
fn settle(
    c: &mut Catalog,
    id: &ResourceId,
    instance: Uuid,
    members: &[Member],
    before: &[u8],
    after: &[u8],
) {
    let claim = c
        .begin_root_gate(id, rev(c, id), observe(id, instance, before, members))
        .unwrap();
    assert!(claim.is_root_gate());
    assert_eq!(claim.expected(), before);
    assert_eq!(claim.desired(), after);
    c.finish(claim, observe(id, instance, after, members))
        .unwrap();
}

#[test]
fn any_owned_hook_keeps_root_enabled_until_the_last_request_releases_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resources.db");
    let mut c = open(&path);
    let caller = owner(1);
    let members = vec![member(&caller, "a"), member(&caller, "b")];
    let instance = Uuid::new_v4();
    let id = gate(&mut c, instance, &members, b"original");
    c.request(&id, rev(&c, &id), &caller, &members[0], true)
        .unwrap();
    assert_eq!(c.inspect(&id).unwrap().unwrap().target, Target::Sleep);
    settle(&mut c, &id, instance, &members, b"original", b"enabled");
    c.request(&id, rev(&c, &id), &caller, &members[1], true)
        .unwrap();
    settle(&mut c, &id, instance, &members, b"enabled", b"enabled");
    drop(c);
    let mut c = open(&path);
    c.request(&id, rev(&c, &id), &caller, &members[0], false)
        .unwrap();
    settle(&mut c, &id, instance, &members, b"enabled", b"enabled");
    c.request(&id, rev(&c, &id), &caller, &members[1], false)
        .unwrap();
    settle(&mut c, &id, instance, &members, b"enabled", b"original");
    assert_eq!(c.inspect(&id).unwrap().unwrap().phase, Phase::Awake);
}

#[test]
fn unchanged_root_reservation_serializes_independent_writers_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resources.db");
    let mut c = open(&path);
    let caller = owner(1);
    let members = vec![member(&caller, "a")];
    let instance = Uuid::new_v4();
    let id = gate(&mut c, instance, &members, b"enabled");
    c.request(&id, rev(&c, &id), &caller, &members[0], true)
        .unwrap();
    settle(&mut c, &id, instance, &members, b"enabled", b"enabled");
    let claim = c
        .begin_root_gate(
            &id,
            rev(&c, &id),
            observe(&id, instance, b"enabled", &members),
        )
        .unwrap();
    assert_eq!(claim.expected(), claim.desired());
    let mut other = open(&path);
    assert!(matches!(
        other.begin_root_gate(
            &id,
            rev(&other, &id),
            observe(&id, instance, b"enabled", &members)
        ),
        Err(Error::Busy)
    ));
    assert!(matches!(
        other.request(&id, rev(&other, &id), &caller, &members[0], false),
        Err(Error::Busy)
    ));
    assert!(matches!(
        unsafe {
            other.register_root_gate(
                observe(&id, instance, b"enabled", &members),
                b"enabled".to_vec(),
                hooks(&members),
            )
        },
        Err(Error::Busy)
    ));
    drop(other);
    drop(c);
    let mut c = open(&path);
    assert_eq!(c.inspect(&id).unwrap().unwrap().phase, Phase::ChangingSleep);
    assert!(c.requires_review(instance).unwrap());
    c.finish(claim, observe(&id, instance, b"enabled", &members))
        .unwrap();
    assert_eq!(c.inspect(&id).unwrap().unwrap().phase, Phase::Sleeping);
}

#[test]
fn preexisting_enabled_root_preserves_its_baseline_and_cannot_change_policy() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = open(&dir.path().join("resources.db"));
    let caller = owner(1);
    let members = vec![member(&caller, "a")];
    let instance = Uuid::new_v4();
    let id = gate(&mut c, instance, &members, b"enabled");
    assert!(matches!(
        c.register(
            observe(&id, instance, b"enabled", &members),
            b"enabled".to_vec()
        ),
        Err(Error::Changed)
    ));
    assert!(matches!(
        c.begin(
            &id,
            rev(&c, &id),
            observe(&id, instance, b"enabled", &members)
        ),
        Err(Error::Invalid)
    ));
    c.request(&id, rev(&c, &id), &caller, &members[0], true)
        .unwrap();
    settle(&mut c, &id, instance, &members, b"enabled", b"enabled");
    c.request(&id, rev(&c, &id), &caller, &members[0], false)
        .unwrap();
    settle(&mut c, &id, instance, &members, b"enabled", b"enabled");
    assert_eq!(c.inspect(&id).unwrap().unwrap().phase, Phase::Awake);
    assert!(matches!(
        c.release_member(
            &id,
            rev(&c, &id),
            &caller,
            &members[0],
            observe(&id, instance, b"enabled", &members)
        ),
        Err(Error::Incomplete)
    ));
    assert!(matches!(
        c.reconcile(
            &id,
            rev(&c, &id),
            observe(&id, instance, b"enabled", &members)
        ),
        Err(Error::Incomplete)
    ));
}

#[test]
fn root_role_is_explicit_versioned_canonical_and_unknown_policy_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resources.db");
    let mut c = open(&path);
    let caller = owner(1);
    let members = vec![member(&caller, "a")];
    let instance = Uuid::new_v4();
    let id = gate(&mut c, instance, &members, b"original");
    let json: String = c
        .connection
        .query_row("SELECT members FROM resources", [], |r| r.get(0))
        .unwrap();
    let row: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(row["version"], 2);
    assert_eq!(row["policy"], "ifeo_any_hook");
    assert_eq!(
        load(&c.connection, &id).unwrap().unwrap().policy,
        Policy::IfeoAnyHook
    );
    for broken in [
        json.replace("ifeo_any_hook", "all_members_sleep"),
        json.replace("\"version\":2", "\"version\":3"),
        format!(" {json}"),
    ] {
        c.connection
            .execute("UPDATE resources SET members=?1", [broken])
            .unwrap();
        assert!(matches!(load(&c.connection, &id), Err(Error::Corrupt)));
    }
    drop(c);
    assert!(Catalog::open(Connection::open(path).unwrap()).is_err());
}

#[test]
fn temporary_wakes_do_not_release_a_gate_still_needed_by_another_owned_hook() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = open(&dir.path().join("resources.db"));
    let caller = owner(1);
    let members = vec![member(&caller, "a"), member(&caller, "b")];
    let instance = Uuid::new_v4();
    let id = gate(&mut c, instance, &members, b"original");
    for m in &members {
        c.request(&id, rev(&c, &id), &caller, m, true).unwrap();
    }
    settle(&mut c, &id, instance, &members, b"original", b"enabled");
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    c.begin_activation(&id, rev(&c, &id), &caller, &members[0], first, instance)
        .unwrap();
    assert_eq!(c.inspect(&id).unwrap().unwrap().target, Target::Sleep);
    settle(&mut c, &id, instance, &members, b"enabled", b"enabled");
    c.begin_activation(&id, rev(&c, &id), &caller, &members[1], second, instance)
        .unwrap();
    assert_eq!(c.inspect(&id).unwrap().unwrap().target, Target::Awake);
    settle(&mut c, &id, instance, &members, b"enabled", b"original");
    let proof = unsafe {
        ActivationObservation::from_native(members[0].clone(), first, instance, instance, false)
    }
    .unwrap();
    c.observe_activation(&id, rev(&c, &id), proof).unwrap();
    assert_eq!(c.inspect(&id).unwrap().unwrap().target, Target::Sleep);
    settle(&mut c, &id, instance, &members, b"original", b"enabled");
}

#[test]
fn two_hooks_of_one_app_are_counted_independently_and_bound_to_their_owner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resources.db");
    let mut c = open(&path);
    let caller = owner(1);
    let members = vec![member(&caller, "a")];
    let instance = Uuid::new_v4();
    let id = id();
    let first = unsafe { ResourceId::from_native(1, b"first hook") }.unwrap();
    let second = unsafe { ResourceId::from_native(1, b"second hook") }.unwrap();
    let refs = vec![
        (first.clone(), members[0].clone()),
        (second.clone(), members[0].clone()),
    ];
    unsafe {
        c.register_root_gate(
            observe(&id, instance, b"original", &members),
            b"enabled".to_vec(),
            refs,
        )
    }
    .unwrap();
    c.request_root_hook(&id, rev(&c, &id), &caller, &members[0], &first, true)
        .unwrap();
    settle(&mut c, &id, instance, &members, b"original", b"enabled");
    c.request_root_hook(&id, rev(&c, &id), &caller, &members[0], &second, true)
        .unwrap();
    c.request_root_hook(&id, rev(&c, &id), &caller, &members[0], &first, false)
        .unwrap();
    drop(c);
    let mut c = open(&path);
    assert_eq!(c.inspect(&id).unwrap().unwrap().target, Target::Sleep);
    assert!(matches!(
        c.request_root_hook(&id, rev(&c, &id), &owner(2), &members[0], &second, false),
        Err(Error::NotAuthorized)
    ));
    let unknown = unsafe { ResourceId::from_native(1, b"unassociated hook") }.unwrap();
    assert!(matches!(
        c.request_root_hook(&id, rev(&c, &id), &caller, &members[0], &unknown, false),
        Err(Error::NotAuthorized)
    ));
    settle(&mut c, &id, instance, &members, b"enabled", b"enabled");
    c.request_root_hook(&id, rev(&c, &id), &caller, &members[0], &second, false)
        .unwrap();
    settle(&mut c, &id, instance, &members, b"enabled", b"original");
}

#[test]
fn shared_physical_hook_retains_the_gate_until_every_owning_reference_releases() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = open(&dir.path().join("resources.db"));
    let caller = owner(1);
    let members = vec![member(&caller, "a"), member(&caller, "b")];
    let instance = Uuid::new_v4();
    let id = id();
    let hook = unsafe { ResourceId::from_native(1, b"shared physical hook") }.unwrap();
    unsafe {
        c.register_root_gate(
            observe(&id, instance, b"original", &members),
            b"enabled".to_vec(),
            members.iter().map(|m| (hook.clone(), m.clone())).collect(),
        )
    }
    .unwrap();
    for m in &members {
        c.request_root_hook(&id, rev(&c, &id), &caller, m, &hook, true)
            .unwrap();
    }
    settle(&mut c, &id, instance, &members, b"original", b"enabled");
    c.request_root_hook(&id, rev(&c, &id), &caller, &members[0], &hook, false)
        .unwrap();
    settle(&mut c, &id, instance, &members, b"enabled", b"enabled");
    c.request_root_hook(&id, rev(&c, &id), &caller, &members[1], &hook, false)
        .unwrap();
    settle(&mut c, &id, instance, &members, b"enabled", b"original");
}

#[test]
fn incomplete_duplicate_or_reassigned_hook_rosters_cannot_replace_saved_requirements() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = open(&dir.path().join("resources.db"));
    let caller = owner(1);
    let members = vec![member(&caller, "a")];
    let instance = Uuid::new_v4();
    let id = gate(&mut c, instance, &members, b"original");
    let original_revision = rev(&c, &id);
    let refs = hooks(&members);
    for invalid in [
        vec![],
        vec![refs[0].clone(), refs[0].clone()],
        vec![(refs[0].0.clone(), member(&caller, "other"))],
    ] {
        assert!(
            unsafe {
                c.register_root_gate(
                    observe(&id, instance, b"original", &members),
                    b"enabled".to_vec(),
                    invalid,
                )
            }
            .is_err()
        );
        assert_eq!(rev(&c, &id), original_revision);
    }
    c.request(&id, rev(&c, &id), &caller, &members[0], true)
        .unwrap();
    settle(&mut c, &id, instance, &members, b"original", b"enabled");
    let new_member = member(&caller, "b");
    let roster = vec![members[0].clone(), new_member.clone()];
    let mut refs = refs;
    refs.push((
        unsafe { ResourceId::from_native(1, b"new hook") }.unwrap(),
        new_member,
    ));
    unsafe {
        c.register_root_gate(
            observe(&id, instance, b"enabled", &roster),
            b"enabled".to_vec(),
            refs,
        )
    }
    .unwrap();
    assert_eq!(c.inspect(&id).unwrap().unwrap().target, Target::Sleep);
    settle(&mut c, &id, instance, &roster, b"enabled", b"enabled");
}
