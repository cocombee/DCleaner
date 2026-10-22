use super::*;
use crate::optimizer_identity::{FileIdentity, PeFormat, PeHeader};
use std::path::PathBuf;

fn image() -> ImageSnapshot {
    ImageSnapshot {
        requested_path: r"C:\Fixture\original.exe".into(),
        final_path: r"\\?\C:\Fixture\original.exe".into(),
        identity: FileIdentity {
            volume_serial: 31,
            file_id: [7; 16],
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
struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    catalog: Catalog,
    caller: Caller,
    member: Member,
    instance: Uuid,
    id: ResourceId,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resources.db");
        let mut catalog = Catalog::open(Connection::open(&path).unwrap()).unwrap();
        let caller = Caller::fixture_boot("S-1-5-21-1-2-3-1001", 1, "S-1-5-5-1-2", Uuid::new_v4());
        let member = Member::for_caller(&caller, "program:v1:hkcu:64:66697874757265").unwrap();
        let instance = Uuid::new_v4();
        let id = unsafe { ResourceId::from_native(1, b"synthetic lease resource") }.unwrap();
        let observation = unsafe {
            Observation::from_native(
                id.clone(),
                instance,
                b"baseline".to_vec(),
                vec![member.clone()],
                true,
            )
        }
        .unwrap();
        catalog.register(observation, b"sleeping".to_vec()).unwrap();
        Self {
            _directory: directory,
            path,
            catalog,
            caller,
            member,
            instance,
            id,
        }
    }
    fn selection(&self) -> Selection {
        Selection::from_owner_selection(
            &self.caller,
            self.member.clone(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            vec![image()],
            vec![self.id.clone()],
        )
        .unwrap()
    }
    fn revision(&self) -> Uuid {
        self.catalog.inspect(&self.id).unwrap().unwrap().revision
    }
    fn observation(&self) -> Observation {
        unsafe {
            Observation::from_native(
                self.id.clone(),
                self.instance,
                b"baseline".to_vec(),
                vec![self.member.clone()],
                true,
            )
        }
        .unwrap()
    }
}
fn copy(selection: &Selection) -> Selection {
    serde_json::from_str(&selection.document().unwrap()).unwrap()
}

#[test]
fn lease_selection_is_durable_exact_and_retry_does_not_replace_it() {
    let mut f = Fixture::new();
    let selected = f.selection();
    let expected = copy(&selected);
    assert!(f.catalog.register_lease(&f.caller, selected).unwrap());
    assert!(
        !f.catalog
            .register_lease(&f.caller, copy(&expected))
            .unwrap()
    );
    let reopened = Catalog::open(Connection::open(&f.path).unwrap()).unwrap();
    let found = reopened
        .lease_selection(&f.caller, expected.lease())
        .unwrap()
        .unwrap();
    assert_eq!(found, expected);
    assert_eq!(found.images()[0], image());
    assert_eq!(found.resources(), vec![f.id]);
    assert_eq!(
        reopened
            .inspect(&found.resources()[0])
            .unwrap()
            .unwrap()
            .phase,
        Phase::Awake
    );
}

#[test]
fn prior_schema_migration_preserves_resource_baseline_roster_and_generation() {
    let mut f = Fixture::new();
    let original = load(&f.catalog.connection, &f.id).unwrap().unwrap();
    f.catalog
        .connection
        .execute_batch("DROP INDEX bound_lease_member; DROP TABLE leases; PRAGMA user_version=1")
        .unwrap();
    f.catalog = Catalog::open(Connection::open(&f.path).unwrap()).unwrap();
    let migrated = load(&f.catalog.connection, &f.id).unwrap().unwrap();
    assert_eq!(original.revision, migrated.revision);
    assert_eq!(original.baseline, migrated.baseline);
    assert_eq!(original.sleeping, migrated.sleeping);
    assert_eq!(original.members, migrated.members);
    assert_eq!(original.phase, migrated.phase);
    assert_eq!(
        f.catalog
            .connection
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        VERSION
    );
    let selected = f.selection();
    f.catalog.register_lease(&f.caller, selected).unwrap();
}

#[test]
fn unknown_prior_schema_is_refused_before_migration() {
    let f = Fixture::new();
    f.catalog.connection.execute_batch("DROP INDEX bound_lease_member; DROP TABLE leases; CREATE TABLE foreign_data(value TEXT); PRAGMA user_version=1").unwrap();
    assert!(matches!(
        Catalog::open(Connection::open(&f.path).unwrap()),
        Err(Error::UnsupportedDatabase)
    ));
    let connection = Connection::open(&f.path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row::<i64, _, _>(
                "SELECT count(*) FROM sqlite_schema WHERE name='leases'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn reused_account_session_logon_or_boot_cannot_resolve_or_retire_another_binding() {
    let mut f = Fixture::new();
    let selected = f.selection();
    let lease = selected.lease();
    let revision = selected.revision();
    f.catalog.register_lease(&f.caller, selected).unwrap();
    for other in [
        Caller::fixture_boot(
            "S-1-5-21-1-2-3-1002",
            1,
            "S-1-5-5-1-2",
            f.caller.boot_id().unwrap(),
        ),
        Caller::fixture_boot(
            f.caller.account(),
            2,
            "S-1-5-5-1-2",
            f.caller.boot_id().unwrap(),
        ),
        Caller::fixture_boot(
            f.caller.account(),
            1,
            "S-1-5-5-1-3",
            f.caller.boot_id().unwrap(),
        ),
        Caller::fixture_boot(f.caller.account(), 1, "S-1-5-5-1-2", Uuid::new_v4()),
        Caller::fixture_logon(f.caller.account(), 1, "S-1-5-5-1-2"),
    ] {
        if other.boot_id().is_some() {
            let other_member = Member::for_caller(&other, &f.member.program).unwrap();
            let foreign = Selection::from_owner_selection(
                &other,
                other_member,
                lease,
                revision,
                vec![image()],
                vec![f.id.clone()],
            )
            .unwrap();
            assert!(matches!(
                f.catalog.register_lease(&other, foreign),
                Err(Error::NotAuthorized)
            ));
        }
        assert!(matches!(
            f.catalog.lease_selection(&other, lease),
            Err(Error::NotAuthorized)
        ));
        assert!(matches!(
            f.catalog.retire_lease(&other, lease, revision),
            Err(Error::NotAuthorized)
        ));
    }
    assert!(
        f.catalog
            .lease_selection(&f.caller, lease)
            .unwrap()
            .is_some()
    );
}

#[test]
fn changed_lease_uuid_generation_image_or_resource_set_never_overwrites_binding() {
    let mut f = Fixture::new();
    let selected = f.selection();
    let expected = copy(&selected);
    f.catalog.register_lease(&f.caller, selected).unwrap();
    let mut changed = copy(&expected);
    changed.revision = Uuid::new_v4();
    assert!(matches!(
        f.catalog.register_lease(&f.caller, changed),
        Err(Error::Stale)
    ));
    let mut changed = copy(&expected);
    changed.images[0].sha256 = "b".repeat(64);
    assert!(matches!(
        f.catalog.register_lease(&f.caller, changed),
        Err(Error::Stale)
    ));
    let mut changed = copy(&expected);
    changed.resources[0] = unsafe { ResourceId::from_native(1, b"other") }.unwrap().0;
    assert!(matches!(
        f.catalog.register_lease(&f.caller, changed),
        Err(Error::Stale)
    ));
    let mut changed = copy(&expected);
    changed.lease = Uuid::new_v4();
    assert!(matches!(
        f.catalog.register_lease(&f.caller, changed),
        Err(Error::Busy)
    ));
    assert_eq!(
        f.catalog
            .lease_selection(&f.caller, expected.lease())
            .unwrap()
            .unwrap(),
        expected
    );
}

#[test]
fn binding_pins_membership_until_stable_retirement_and_keeps_its_tombstone() {
    let mut f = Fixture::new();
    let selected = f.selection();
    let expected = copy(&selected);
    f.catalog.register_lease(&f.caller, selected).unwrap();
    assert!(matches!(
        f.catalog
            .release_member(&f.id, f.revision(), &f.caller, &f.member, f.observation()),
        Err(Error::Busy)
    ));
    assert!(matches!(
        f.catalog
            .retire_lease(&f.caller, expected.lease(), Uuid::new_v4()),
        Err(Error::Stale)
    ));
    f.catalog
        .request(&f.id, f.revision(), &f.caller, &f.member, true)
        .unwrap();
    assert!(matches!(
        f.catalog
            .retire_lease(&f.caller, expected.lease(), expected.revision()),
        Err(Error::Busy)
    ));
    f.catalog
        .request(&f.id, f.revision(), &f.caller, &f.member, false)
        .unwrap();
    assert!(
        f.catalog
            .retire_lease(&f.caller, expected.lease(), expected.revision())
            .unwrap()
    );
    assert!(
        !f.catalog
            .retire_lease(&f.caller, expected.lease(), expected.revision())
            .unwrap()
    );
    assert!(
        f.catalog
            .lease_selection(&f.caller, expected.lease())
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        f.catalog.register_lease(&f.caller, copy(&expected)),
        Err(Error::Stale)
    ));
    f.catalog
        .release_member(&f.id, f.revision(), &f.caller, &f.member, f.observation())
        .unwrap();
    let reopened = Catalog::open(Connection::open(&f.path).unwrap()).unwrap();
    assert!(
        reopened
            .lease_selection(&f.caller, expected.lease())
            .unwrap()
            .is_none()
    );
}

#[test]
fn altered_association_or_document_is_refused_instead_of_becoming_authority() {
    let mut f = Fixture::new();
    let selected = f.selection();
    let lease = selected.lease();
    f.catalog.register_lease(&f.caller, selected).unwrap();
    let mut record = load(&f.catalog.connection, &f.id).unwrap().unwrap();
    record.members[0].member.program = "program:v1:hkcu:64:6f74686572".into();
    save(&f.catalog.connection, &record).unwrap();
    assert!(matches!(
        f.catalog.lease_selection(&f.caller, lease),
        Err(Error::Changed)
    ));
    assert!(matches!(
        Catalog::open(Connection::open(&f.path).unwrap()),
        Err(Error::Changed)
    ));
    let mut f = Fixture::new();
    let selected = f.selection();
    let lease = selected.lease();
    f.catalog.register_lease(&f.caller, selected).unwrap();
    f.catalog
        .connection
        .execute(
            "UPDATE leases SET revision=?1 WHERE lease=?2",
            params![
                Uuid::new_v4().as_bytes().as_slice(),
                lease.as_bytes().as_slice()
            ],
        )
        .unwrap();
    assert!(matches!(
        f.catalog.lease_selection(&f.caller, lease),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        Catalog::open(Connection::open(&f.path).unwrap()),
        Err(Error::Corrupt)
    ));
}

#[test]
fn malformed_or_unbounded_selection_is_rejected_before_any_insert() {
    let f = Fixture::new();
    let selected = f.selection();
    for path in [
        r"relative.exe",
        r"\\server\share\app.exe",
        r"C:\Fixture\..\app.exe",
        r"C:\Fixture\app.exe:stream",
        r"C:\Fixture\\app.exe",
    ] {
        let mut value = copy(&selected);
        value.images[0].final_path = path.into();
        assert!(matches!(value.document(), Err(Error::Invalid)), "{path}");
    }
    let mut value = copy(&selected);
    value.images.push(image());
    assert!(matches!(value.document(), Err(Error::Invalid)));
    let mut value = copy(&selected);
    value.resources.push(value.resources[0].clone());
    assert!(matches!(value.document(), Err(Error::Invalid)));
    let mut value = copy(&selected);
    value.images[0].sha256 = "x".repeat(64);
    assert!(matches!(value.document(), Err(Error::Invalid)));
    let mut value = copy(&selected);
    value.images[0].bytes_read = 1;
    assert!(matches!(value.document(), Err(Error::Invalid)));
    let mut value = copy(&selected);
    value.member.boot_id = None;
    assert!(matches!(value.document(), Err(Error::Invalid)));
    let mut value = copy(&selected);
    value.images.clear();
    assert!(matches!(value.document(), Err(Error::Invalid)));
    let mut value = copy(&selected);
    value.resources = vec![selected.resources[0].clone(); MAX_BINDING_RESOURCES + 1];
    assert!(matches!(value.document(), Err(Error::Invalid)));
    assert_eq!(
        f.catalog
            .connection
            .query_row::<i64, _, _>("SELECT count(*) FROM leases", [], |r| r.get(0))
            .unwrap(),
        0
    );
}

#[test]
fn bounded_catalog_refuses_more_bindings_without_reusing_retired_identifiers() {
    let mut f = Fixture::new();
    let selected = f.selection();
    let tx = f.catalog.connection.transaction().unwrap();
    for _ in 0..MAX_LEASES {
        let mut historical = copy(&selected);
        historical.lease = Uuid::new_v4();
        tx.execute(
            "INSERT INTO leases(lease,revision,member,document,retired) VALUES(?1,?2,?3,?4,1)",
            params![
                historical.lease.as_bytes().as_slice(),
                historical.revision.as_bytes().as_slice(),
                serde_json::to_string(&historical.member).unwrap(),
                historical.document().unwrap()
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    assert!(matches!(
        f.catalog.register_lease(&f.caller, selected),
        Err(Error::Capacity)
    ));
    assert_eq!(
        f.catalog
            .connection
            .query_row::<i64, _, _>("SELECT count(*) FROM leases", [], |r| r.get(0))
            .unwrap(),
        MAX_LEASES
    );
    Catalog::open(Connection::open(&f.path).unwrap()).unwrap();
}

#[test]
fn retiring_one_root_membership_preserves_another_owned_sleeping_hook() {
    let mut f = Fixture::new();
    let second = Member::for_caller(&f.caller, "program:v1:hkcu:64:7365636f6e64").unwrap();
    let root = unsafe { ResourceId::from_native(1, b"synthetic shared root") }.unwrap();
    let first_hook = unsafe { ResourceId::from_native(1, b"first hook") }.unwrap();
    let second_hook = unsafe { ResourceId::from_native(1, b"second hook") }.unwrap();
    let members = vec![f.member.clone(), second.clone()];
    let observe = |state: &[u8]| {
        unsafe {
            Observation::from_native(
                root.clone(),
                f.instance,
                state.to_vec(),
                members.clone(),
                true,
            )
        }
        .unwrap()
    };
    unsafe {
        f.catalog.register_root_gate(
            observe(b"off"),
            b"on".to_vec(),
            vec![
                (first_hook, f.member.clone()),
                (second_hook.clone(), second.clone()),
            ],
        )
    }
    .unwrap();
    let selected = Selection::from_owner_selection(
        &f.caller,
        f.member.clone(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        vec![image()],
        vec![root.clone()],
    )
    .unwrap();
    let lease = selected.lease();
    let revision = selected.revision();
    f.catalog.register_lease(&f.caller, selected).unwrap();
    let generation = f.catalog.inspect(&root).unwrap().unwrap().revision;
    f.catalog
        .request_root_hook(&root, generation, &f.caller, &second, &second_hook, true)
        .unwrap();
    let generation = f.catalog.inspect(&root).unwrap().unwrap().revision;
    let claim = f
        .catalog
        .begin_root_gate(&root, generation, observe(b"off"))
        .unwrap();
    f.catalog.finish(claim, observe(b"on")).unwrap();
    assert_eq!(
        f.catalog.inspect(&root).unwrap().unwrap().phase,
        Phase::Sleeping
    );
    assert!(f.catalog.retire_lease(&f.caller, lease, revision).unwrap());
    let row = load(&f.catalog.connection, &root).unwrap().unwrap();
    assert!(row.hooks.iter().any(|h| h.member == second && h.needed));
    assert_eq!(row.phase, Phase::Sleeping);
    assert_eq!(row.target(), Target::Sleep);
}
