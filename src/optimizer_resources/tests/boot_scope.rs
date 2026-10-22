use super::*;
fn caller(boot: Option<Uuid>) -> Caller {
    let a = owner(1);
    match boot {
        Some(id) => Caller::fixture_boot(a.account(), a.session(), "S-1-5-5-1-2", id),
        None => Caller::fixture_logon(a.account(), a.session(), "S-1-5-5-1-2"),
    }
}

#[test]
fn reused_logon_and_program_cannot_change_or_release_prior_boot_membership() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resources.db");
    let mut c = open(&path);
    let a = caller(Some(Uuid::new_v4()));
    let b = caller(Some(Uuid::new_v4()));
    let first = member(&a, "same app");
    let second = member(&b, "same app");
    let epoch = Uuid::new_v4();
    assert_ne!(first, second);
    let id = register(&mut c, epoch, &[first.clone()]);
    c.request(&id, rev(&c, &id), &a, &first, true).unwrap();
    assert!(matches!(
        c.request(&id, rev(&c, &id), &b, &first, false),
        Err(Error::NotAuthorized)
    ));
    assert!(matches!(
        c.release_member(
            &id,
            rev(&c, &id),
            &b,
            &first,
            observe(&id, epoch, b"original", &[])
        ),
        Err(Error::NotAuthorized)
    ));
    let both = vec![first.clone(), second.clone()];
    c.register(
        observe(&id, epoch, b"original", &both),
        b"sleeping".to_vec(),
    )
    .unwrap();
    assert_eq!(c.inspect(&id).unwrap().unwrap().target, Target::Awake);
    c.request(&id, rev(&c, &id), &b, &second, true).unwrap();
    let invocation = Uuid::new_v4();
    c.begin_activation(&id, rev(&c, &id), &a, &first, invocation, epoch)
        .unwrap();
    c.begin_activation(&id, rev(&c, &id), &b, &second, invocation, epoch)
        .unwrap();
    drop(c);
    let mut c = open(&path);
    assert_eq!(c.inspect(&id).unwrap().unwrap().temporary_activations, 2);
    for (index, m) in [first, second].into_iter().enumerate() {
        let proof =
            unsafe { ActivationObservation::from_native(m, invocation, epoch, epoch, false) }
                .unwrap();
        c.observe_activation(&id, rev(&c, &id), proof).unwrap();
        assert_eq!(
            c.inspect(&id).unwrap().unwrap().temporary_activations,
            1 - index
        );
    }
    assert_eq!(c.inspect(&id).unwrap().unwrap().target, Target::Sleep);
}

#[test]
fn old_logon_roster_stays_unbound_and_scoped_root_reservations_remain_global() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resources.db");
    let mut c = open(&path);
    let old = caller(None);
    let a = caller(Some(Uuid::new_v4()));
    let b = caller(Some(Uuid::new_v4()));
    let legacy = member(&old, "same app");
    let current = member(&a, "same app");
    let other = member(&b, "same app");
    let epoch = Uuid::new_v4();
    let id = id();
    let hook = unsafe { ResourceId::from_native(2, b"synthetic boot-scoped hook") }.unwrap();
    unsafe {
        c.register_root_gate(
            observe(&id, epoch, b"original", &[legacy.clone()]),
            b"enabled".to_vec(),
            vec![(hook.clone(), legacy.clone())],
        )
    }
    .unwrap();
    let bytes: String = c
        .connection
        .query_row("SELECT members FROM resources", [], |r| r.get(0))
        .unwrap();
    assert!(bytes.starts_with("{\"version\":3,"));
    assert!(!bytes.contains("boot_id"));
    drop(c);
    let mut c = open(&path);
    assert_eq!(
        c.connection
            .query_row::<String, _, _>("SELECT members FROM resources", [], |r| r.get(0))
            .unwrap(),
        bytes
    );
    assert!(matches!(
        c.request_root_hook(&id, rev(&c, &id), &a, &legacy, &hook, true),
        Err(Error::NotAuthorized)
    ));
    let members = vec![legacy.clone(), current.clone(), other.clone()];
    unsafe {
        c.register_root_gate(
            observe(&id, epoch, b"original", &members),
            b"enabled".to_vec(),
            members.iter().map(|m| (hook.clone(), m.clone())).collect(),
        )
    }
    .unwrap();
    let json: String = c
        .connection
        .query_row("SELECT members FROM resources", [], |r| r.get(0))
        .unwrap();
    assert!(json.starts_with("{\"version\":4,"));
    c.request_root_hook(&id, rev(&c, &id), &a, &current, &hook, true)
        .unwrap();
    let claim = c
        .begin_root_gate(
            &id,
            rev(&c, &id),
            observe(&id, epoch, b"original", &members),
        )
        .unwrap();
    let mut competing = open(&path);
    assert!(matches!(
        competing.begin_root_gate(
            &id,
            rev(&competing, &id),
            observe(&id, epoch, b"original", &members)
        ),
        Err(Error::Busy)
    ));
    assert!(matches!(
        competing.request_root_hook(&id, rev(&competing, &id), &b, &other, &hook, true),
        Err(Error::Busy)
    ));
    c.finish(claim, observe(&id, epoch, b"enabled", &members))
        .unwrap();
}

#[test]
fn boot_roster_version_and_identity_fail_closed_without_replacing_saved_state() {
    for case in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.db");
        let mut c = open(&path);
        let a = caller(Some(Uuid::new_v4()));
        let m = member(&a, "same app");
        let epoch = Uuid::new_v4();
        let id = id();
        let hook = unsafe { ResourceId::from_native(2, b"synthetic hook") }.unwrap();
        unsafe {
            c.register_root_gate(
                observe(&id, epoch, b"original", &[m.clone()]),
                b"enabled".to_vec(),
                vec![(hook, m)],
            )
        }
        .unwrap();
        let original: String = c
            .connection
            .query_row("SELECT members FROM resources", [], |r| r.get(0))
            .unwrap();
        let changed = match case {
            0 => original.replace("\"version\":4", "\"version\":3"),
            1 => original.replace(&a.boot_id().unwrap().to_string(), &Uuid::nil().to_string()),
            _ => original.replace(
                &format!("\"boot_id\":\"{}\"", a.boot_id().unwrap()),
                "\"boot_id\":null",
            ),
        };
        assert_ne!(changed, original);
        c.connection
            .execute("UPDATE resources SET members=?1", [changed])
            .unwrap();
        drop(c);
        let before = std::fs::read(&path).unwrap();
        assert!(Catalog::open(Connection::open(&path).unwrap()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
