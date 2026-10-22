//! Exact disposable HKCU scopes only; never a production IFEO write scope.
use super::*;
use crate::optimizer_registry_completion::slot_state;
use crate::optimizer_resources::ResourceId;
use windows::Win32::System::Registry::{KEY_READ, REG_LINK, REG_OPTION_CREATE_LINK, RegRenameKey};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn readonly(fixture: &Fixture, view: RegistryView) -> Scope {
    let flags = match view {
        RegistryView::Registry32 => KEY_WOW64_32KEY,
        RegistryView::Registry64 => KEY_WOW64_64KEY,
    };
    let mut key = HKEY::default();
    status(unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(wide(&fixture.path).as_ptr()),
            None,
            KEY_READ | flags,
            &mut key,
        )
    })
    .unwrap();
    let key = Key(key);
    let binding = binding::Binding::fixture(&key, false).unwrap();
    Scope {
        key,
        view: flags,
        view_id: view,
        binding,
    }
}

#[test]
fn scoped_resource_reads_preserve_exact_slots_and_distinguish_missing_namespace() {
    let fixture = Fixture::new();
    let root = fixture.create("café.exe");
    let leaf = fixture.create("café.exe\\filter");
    let expected = raw(REG_BINARY.0, &[0, 0xd8, 0xff, 42]);
    status(write(&leaf, Name::Debugger, &expected)).unwrap();
    let scope = readonly(&fixture, RegistryView::Registry64);
    let id = scope
        .value_identity("café.exe\\filter", Name::Debugger)
        .unwrap();
    let observed = scope
        .observe_resource(&id, deadline(), &AtomicBool::new(false))
        .unwrap();
    assert_eq!(observed.id(), &id);
    assert_eq!(observed.path(), "CAFÉ.EXE\\FILTER");
    assert_eq!(observed.name(), Name::Debugger);
    assert_eq!(observed.view(), RegistryView::Registry64);
    assert_eq!(
        observed.catalog_state().unwrap(),
        slot_state(true, Some(expected.clone())).unwrap()
    );
    assert_eq!(read_value(&leaf, Name::Debugger).unwrap(), Some(expected));
    let empty = scope.value_identity("café.exe", Name::UseFilter).unwrap();
    let missing = scope.slot_identity("missing.exe", Name::UseFilter).unwrap();
    let empty = scope
        .observe_resource(&empty, deadline(), &AtomicBool::new(false))
        .unwrap()
        .catalog_state()
        .unwrap();
    let missing = scope
        .observe_resource(&missing, deadline(), &AtomicBool::new(false))
        .unwrap()
        .catalog_state()
        .unwrap();
    assert_eq!(empty, slot_state(true, None).unwrap());
    assert_eq!(missing, slot_state(false, None).unwrap());
    assert_ne!(empty, missing);
    assert_eq!(read_value(&root, Name::UseFilter).unwrap(), None);
    assert!(observation_key(&scope, "missing.exe").unwrap().is_none());
}

#[test]
fn resource_resolution_rejects_foreign_scopes_unsupported_kinds_and_malformed_slots() {
    let first = Fixture::new();
    let second = Fixture::new();
    drop(first.create("a.exe"));
    drop(second.create("a.exe"));
    let id = first
        .scope()
        .value_identity("a.exe", Name::Debugger)
        .unwrap();
    assert!(matches!(
        second
            .scope()
            .observe_resource(&id, deadline(), &AtomicBool::new(false)),
        Err(Failure::NotAuthorized)
    ));
    let (_, bytes) = id.native_parts().unwrap();
    for kind in 2..=4 {
        let id = unsafe { ResourceId::from_native(kind, &bytes) }.unwrap();
        assert!(matches!(
            first
                .scope()
                .observe_resource(&id, deadline(), &AtomicBool::new(false)),
            Err(Failure::InvalidPlan)
        ));
    }
    for bytes in [vec![1], vec![0, 0, 0, 0], vec![0xff, 0xff]] {
        let id = unsafe { ResourceId::from_native(1, &bytes) }.unwrap();
        assert!(
            first
                .scope()
                .observe_resource(&id, deadline(), &AtomicBool::new(false))
                .is_err()
        );
    }
    for suffix in ["a.exe\\b\\c", "..\\a.exe", "a.exe\\."] {
        let native = format!("{}\\{suffix}", first.scope().native_identity());
        let id = binding::value_identity_at(&native, Name::Debugger).unwrap();
        assert!(matches!(
            first
                .scope()
                .observe_resource(&id, deadline(), &AtomicBool::new(false)),
            Err(Failure::InvalidPlan)
        ));
    }
}

#[test]
fn resource_two_pass_reads_refuse_value_namespace_and_budget_drift_without_replay() {
    let fixture = Fixture::new();
    let key = fixture.create("a.exe");
    status(write(&key, Name::UseFilter, &dword(1))).unwrap();
    let id = fixture
        .scope()
        .value_identity("a.exe", Name::UseFilter)
        .unwrap();
    let result =
        fixture
            .scope()
            .observe_resource_with(&id, deadline(), &AtomicBool::new(false), || {
                status(write(&key, Name::UseFilter, &dword(2))).unwrap();
            });
    assert!(matches!(result, Err(Failure::Changed)));
    assert_eq!(read_value(&key, Name::UseFilter).unwrap(), Some(dword(2)));
    let result =
        fixture
            .scope()
            .observe_resource_with(&id, deadline(), &AtomicBool::new(false), || {
                status(unsafe {
                    RegRenameKey(key.0, PCWSTR::null(), PCWSTR(wide("moved.exe").as_ptr()))
                })
                .unwrap();
            });
    assert!(matches!(result, Err(Failure::Changed)));
    assert!(observation_key(fixture.scope(), "a.exe").unwrap().is_none());
    assert_eq!(read_value(&key, Name::UseFilter).unwrap(), Some(dword(2)));
    assert!(matches!(
        fixture
            .scope()
            .observe_resource(&id, deadline(), &AtomicBool::new(true)),
        Err(Failure::Cancelled)
    ));
    assert!(matches!(
        fixture.scope().observe_resource(
            &id,
            Instant::now() - Duration::from_secs(1),
            &AtomicBool::new(false)
        ),
        Err(Failure::Deadline)
    ));
    assert!(matches!(
        fixture.scope().observe_resource(
            &id,
            Instant::now() + Duration::from_secs(31),
            &AtomicBool::new(false)
        ),
        Err(Failure::Limited)
    ));
    let cancel = AtomicBool::new(false);
    assert!(matches!(
        fixture
            .scope()
            .observe_resource_with(&id, deadline(), &cancel, || cancel
                .store(true, Ordering::Release)),
        Err(Failure::Cancelled)
    ));
}

#[test]
fn shared_views_keep_one_slot_identity_and_readonly_scope_never_grants_a_transaction() {
    let fixture = Fixture::new();
    let key = fixture.create("a.exe");
    status(write(&key, Name::UseFilter, &dword(1))).unwrap();
    let first = readonly(&fixture, RegistryView::Registry32);
    let second = readonly(&fixture, RegistryView::Registry64);
    let id = first.value_identity("a.exe", Name::UseFilter).unwrap();
    assert_eq!(id, second.value_identity("A.EXE", Name::UseFilter).unwrap());
    for scope in [&first, &second] {
        let observed = scope
            .observe_resource(&id, deadline(), &AtomicBool::new(false))
            .unwrap();
        assert_eq!(
            observed.catalog_state().unwrap(),
            slot_state(true, Some(dword(1))).unwrap()
        );
        assert!(matches!(
            Transaction::begin(scope, deadline(), &AtomicBool::new(false)),
            Err(Failure::NotAuthorized)
        ));
    }
    if Principal::require_local_system().is_err() {
        for view in [RegistryView::Registry32, RegistryView::Registry64] {
            assert!(matches!(
                Scope::for_service_ifeo_readonly(view),
                Err(Failure::NotAuthorized)
            ));
        }
    }
}

#[test]
fn resource_batch_refuses_partial_sets_duplicates_and_oversized_values() {
    let fixture = Fixture::new();
    let key = fixture.create("a.exe");
    let scope = readonly(&fixture, RegistryView::Registry64);
    let ids = [Name::Debugger, Name::UseFilter, Name::FilterFullPath]
        .map(|name| scope.value_identity("a.exe", name).unwrap());
    let scopes = [scope];
    let observed =
        resource::observe_resources(&ids, &scopes, deadline(), &AtomicBool::new(false)).unwrap();
    assert!(observed.iter().zip(&ids).all(|(row, id)| row.id() == id));
    assert_eq!(observed.len(), 3);
    assert!(matches!(
        resource::observe_resources(
            &[ids[0].clone(), ids[0].clone()],
            &scopes,
            deadline(),
            &AtomicBool::new(false)
        ),
        Err(Failure::InvalidPlan)
    ));
    let bad = unsafe { ResourceId::from_native(2, b"unsupported service identity") }.unwrap();
    assert!(
        resource::observe_resources(
            &[ids[0].clone(), bad],
            &scopes,
            deadline(),
            &AtomicBool::new(false)
        )
        .is_err()
    );
    status(write(
        &key,
        Name::Debugger,
        &raw(REG_BINARY.0, &vec![7; MAX_BYTES + 1]),
    ))
    .unwrap();
    assert!(matches!(
        scopes[0].observe_resource(&ids[0], deadline(), &AtomicBool::new(false)),
        Err(Failure::Limited)
    ));
    assert!(matches!(
        resource::observe_resources(&[], &scopes, deadline(), &AtomicBool::new(false)),
        Err(Failure::Limited)
    ));
    assert!(matches!(
        resource::observe_resources(&ids, &[], deadline(), &AtomicBool::new(false)),
        Err(Failure::Limited)
    ));
    assert!(matches!(
        resource::observe_resources(
            &vec![ids[1].clone(); 65],
            &scopes,
            deadline(),
            &AtomicBool::new(false)
        ),
        Err(Failure::Limited)
    ));
}

#[test]
fn resource_reader_never_follows_an_owned_registry_link() {
    let fixture = Fixture::new();
    let target = fixture.create("target.exe");
    status(write(&target, Name::UseFilter, &dword(1))).unwrap();
    let mut link = HKEY::default();
    status(unsafe {
        RegCreateKeyExW(
            fixture.scope().key.0,
            PCWSTR(wide("link.exe").as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_CREATE_LINK,
            KEY_ALL_ACCESS | fixture.scope().view,
            None,
            &mut link,
            None,
        )
    })
    .unwrap();
    let link = binding_cases::OwnedLink(Key(link));
    let bytes: Vec<_> = binding::native_name(&target)
        .unwrap()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    status(unsafe {
        RegSetValueExW(
            link.0.0,
            PCWSTR(wide("SymbolicLinkValue").as_ptr()),
            None,
            REG_LINK,
            Some(&bytes),
        )
    })
    .unwrap();
    let id = binding::value_identity_at(
        &format!("{}\\link.exe", fixture.scope().native_identity()),
        Name::UseFilter,
    )
    .unwrap();
    assert!(matches!(
        fixture
            .scope()
            .observe_resource(&id, deadline(), &AtomicBool::new(false)),
        Err(Failure::NotAuthorized)
    ));
    assert_eq!(
        read_value(&target, Name::UseFilter).unwrap(),
        Some(dword(1))
    );
}
