//! Native scope/alias/access adversarial fixtures, never production effects.
use super::*;
use crate::optimizer_pipe_security::Descriptor;
use windows::Win32::{
    Security::SECURITY_ATTRIBUTES,
    System::Registry::{KEY_READ, REG_LINK, REG_OPTION_CREATE_LINK, RegRenameKey},
};
use windows::core::BOOL;

fn alias_scope(fixture: &Fixture, view: RegistryView, writable: bool) -> Scope {
    let mut key = HKEY::default();
    let flags = match view {
        RegistryView::Registry32 => KEY_WOW64_32KEY,
        RegistryView::Registry64 => KEY_WOW64_64KEY,
    };
    let name = wide(&fixture.path);
    status(unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(name.as_ptr()),
            None,
            KEY_READ | flags,
            &mut key,
        )
    })
    .unwrap();
    let key = Key(key);
    let binding = binding::Binding::fixture(&key, writable).unwrap();
    Scope {
        key,
        view: flags,
        view_id: view,
        binding,
    }
}

#[test]
fn native_case_alias_and_recased_key_keep_one_value_identity() {
    require_txr!();
    let fixture = Fixture::new();
    let app = fixture.create("café.exe");
    let first = fixture
        .scope()
        .value_identity("café.exe", Name::Debugger)
        .unwrap();
    assert_eq!(
        first,
        fixture
            .scope()
            .value_identity("CAFÉ.EXE", Name::Debugger)
            .unwrap()
    );
    assert_ne!(
        first,
        fixture
            .scope()
            .value_identity("café.exe", Name::UseFilter)
            .unwrap()
    );
    drop(fixture.create("other.exe"));
    assert_ne!(
        first,
        fixture
            .scope()
            .value_identity("other.exe", Name::Debugger)
            .unwrap()
    );
    // RegRenameKey requires a name that does not already exist. Recase through
    // a distinct owned name; unlike a mocked string this changes native names.
    let hop = wide("rename-hop.exe");
    status(unsafe { RegRenameKey(app.0, PCWSTR::null(), PCWSTR(hop.as_ptr())) }).unwrap();
    assert_ne!(
        first,
        fixture
            .scope()
            .value_identity("rename-hop.exe", Name::Debugger)
            .unwrap()
    );
    let upper = wide("CAFÉ.EXE");
    status(unsafe { RegRenameKey(app.0, PCWSTR::null(), PCWSTR(upper.as_ptr())) }).unwrap();
    assert!(binding::native_name(&app).unwrap().ends_with("CAFÉ.EXE"));
    assert_eq!(
        first,
        fixture
            .scope()
            .value_identity("café.exe", Name::Debugger)
            .unwrap()
    );
}

#[test]
fn shared_native_hkcu_views_do_not_mint_two_resource_ids() {
    let fixture = Fixture::new();
    drop(fixture.create("a.exe"));
    let first = alias_scope(&fixture, RegistryView::Registry32, false);
    let second = alias_scope(&fixture, RegistryView::Registry64, false);
    // One exact random HKCU path opened twice, not two unrelated fixtures.
    assert_eq!(first.native_identity(), second.native_identity());
    for name in [Name::Debugger, Name::UseFilter, Name::FilterFullPath] {
        assert_eq!(
            first.value_identity("a.exe", name).unwrap(),
            second.value_identity("A.EXE", name).unwrap()
        );
    }
}

#[test]
fn read_only_scope_refuses_a_transaction_before_any_staging() {
    let fixture = Fixture::new();
    let app = fixture.create("a.exe");
    let scope = alias_scope(&fixture, RegistryView::Registry64, false);
    let cancel = AtomicBool::new(false);
    let snapshot = scope
        .inspect_image_tree("a.exe", Instant::now() + Duration::from_secs(5), &cancel)
        .unwrap();
    assert!(snapshot.root().is_some());
    assert!(snapshot.children().is_empty());
    assert!(matches!(
        Transaction::begin(&scope, Instant::now() + Duration::from_secs(5), &cancel),
        Err(Failure::NotAuthorized)
    ));
    assert_eq!(read_value(&app, Name::UseFilter).unwrap(), None);
}

fn access_key(fixture: &Fixture, name: &str, public_access: &str) -> Key {
    assert!(component(name));
    let owner = Principal::current().unwrap().user_sid().unwrap();
    let descriptor = Descriptor::from_sddl(&format!(
        "O:{owner}D:P(A;CI;KA;;;{owner})(A;CI;{public_access};;;WD)"
    ))
    .unwrap();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.native().0,
        bInheritHandle: BOOL(0),
    };
    let name = wide(name);
    let mut key = HKEY::default();
    status(unsafe {
        RegCreateKeyExW(
            fixture.scope().key.0,
            PCWSTR(name.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            Some(&attributes),
            &mut key,
            None,
        )
    })
    .unwrap();
    Key(key)
}

#[test]
fn native_public_read_is_allowed_but_public_mutation_blocks_read_and_staging() {
    require_txr!();
    let fixture = Fixture::new();
    let readable = access_key(&fixture, "readable.exe", "KR");
    let writable = access_key(&fixture, "writable.exe", "KW");
    assert!(
        fixture
            .scope()
            .value_identity("readable.exe", Name::UseFilter)
            .is_ok()
    );
    assert!(
        fixture
            .scope()
            .value_identity("writable.exe", Name::UseFilter)
            .is_err()
    );
    let cancel = AtomicBool::new(false);
    assert!(
        fixture
            .scope()
            .inspect_image_tree(
                "readable.exe",
                Instant::now() + Duration::from_secs(5),
                &cancel
            )
            .is_ok()
    );
    assert!(
        fixture
            .scope()
            .inspect_image_tree(
                "writable.exe",
                Instant::now() + Duration::from_secs(5),
                &cancel
            )
            .is_err()
    );
    let mut good = fixture.tx(&cancel);
    good.stage_existing(
        "readable.exe",
        &[change(Name::UseFilter, None, Some(dword(1)))],
    )
    .unwrap();
    commit_fixture(good).unwrap();
    assert_eq!(
        read_value(&readable, Name::UseFilter).unwrap(),
        Some(dword(1))
    );
    let mut bad = fixture.tx(&cancel);
    assert!(
        bad.stage_existing(
            "writable.exe",
            &[change(Name::UseFilter, None, Some(dword(1)))]
        )
        .is_err()
    );
    assert!(matches!(commit_fixture(bad), Err(Failure::Ended)));
    let mut bad_parent = fixture.tx(&cancel);
    assert!(
        bad_parent
            .stage_new_leaf(
                "writable.exe",
                "owned",
                &[change(Name::Debugger, None, Some(dword(1)))]
            )
            .is_err()
    );
    assert!(matches!(commit_fixture(bad_parent), Err(Failure::Ended)));
    assert_eq!(read_value(&writable, Name::UseFilter).unwrap(), None);
    assert!(matches!(
        fixture.open("writable.exe\\owned"),
        Err(Failure::Native(2))
    ));
}

#[test]
fn native_ancestor_value_writer_is_not_a_namespace_or_leaf_writer() {
    use std::os::windows::io::BorrowedHandle;
    let fixture = Fixture::new();
    let value_only = access_key(&fixture, "values", "0x00000002");
    let creates = access_key(&fixture, "creates", "0x00000004");
    let policy = RegistryAccess::fixture().unwrap();
    let value_handle = unsafe { BorrowedHandle::borrow_raw(value_only.0.0) };
    policy.verify_namespace(value_handle).unwrap();
    assert!(policy.verify(value_handle).is_err());
    assert!(
        policy
            .verify_namespace(unsafe { BorrowedHandle::borrow_raw(creates.0.0) })
            .is_err()
    );
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtDeleteKey(key: HANDLE) -> i32;
}
pub(super) struct OwnedLink(pub(super) Key);
impl Drop for OwnedLink {
    fn drop(&mut self) {
        // Exact created link object by handle; never follow a cleanup path.
        let result = unsafe { NtDeleteKey(HANDLE(self.0.0.0)) };
        if !std::thread::panicking() {
            assert_eq!(result, 0, "fixture link cleanup");
        }
    }
}

#[test]
fn native_fixed_alias_change_before_commit_rolls_back_staging_without_repairing_link() {
    require_txr!();
    use windows::Win32::System::Registry::REG_OPTION_OPEN_LINK;
    let fixture = Fixture::new();
    let app = fixture.create("a.exe");
    let other = fixture.create("other");
    let name = wide("scope-alias");
    let mut created = HKEY::default();
    status(unsafe {
        RegCreateKeyExW(
            fixture.scope().key.0,
            PCWSTR(name.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_CREATE_LINK,
            KEY_ALL_ACCESS,
            None,
            &mut created,
            None,
        )
    })
    .unwrap();
    let link = OwnedLink(Key(created));
    let value = wide("SymbolicLinkValue");
    let original: Vec<u8> = fixture
        .scope()
        .native_identity()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let changed: Vec<u8> = binding::native_name(&other)
        .unwrap()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    status(unsafe {
        RegSetValueExW(
            link.0.0,
            PCWSTR(value.as_ptr()),
            None,
            REG_LINK,
            Some(&original),
        )
    })
    .unwrap();
    let mut scope = alias_scope(&fixture, RegistryView::Registry64, true);
    let mut checked_link = HKEY::default();
    status(unsafe {
        RegOpenKeyExW(
            fixture.scope().key.0,
            PCWSTR(name.as_ptr()),
            Some(REG_OPTION_OPEN_LINK.0),
            KEY_READ,
            &mut checked_link,
        )
    })
    .unwrap();
    scope.binding.fixture_alias(Key(checked_link)).unwrap();
    let cancel = AtomicBool::new(false);
    let snapshot = scope
        .inspect_image_tree("a.exe", Instant::now() + Duration::from_secs(5), &cancel)
        .unwrap();
    let mut transaction =
        Transaction::begin(&scope, Instant::now() + Duration::from_secs(5), &cancel).unwrap();
    transaction
        .stage_existing("a.exe", &[change(Name::UseFilter, None, Some(dword(1)))])
        .unwrap();
    status(unsafe {
        RegSetValueExW(
            link.0.0,
            PCWSTR(value.as_ptr()),
            None,
            REG_LINK,
            Some(&changed),
        )
    })
    .unwrap();
    assert!(matches!(commit_fixture(transaction), Err(Failure::Changed)));
    assert!(matches!(
        snapshot.revalidate(Instant::now() + Duration::from_secs(5), &cancel),
        Err(Failure::Changed)
    ));
    drop(snapshot);
    assert_eq!(read_value(&app, Name::UseFilter).unwrap(), None);
    assert!(matches!(
        Transaction::begin(&scope, Instant::now() + Duration::from_secs(5), &cancel),
        Err(Failure::Changed)
    ));
    assert!(
        fixture
            .scope()
            .value_identity("scope-alias", Name::UseFilter)
            .is_err()
    );
    // Our refusal preserved the foreign link edit; it did not retry or repair it.
    assert_eq!(
        binding::native_name(&fixture.open("scope-alias").unwrap()).unwrap(),
        binding::native_name(&other).unwrap()
    );
    drop(scope);
    drop(link);
}

#[test]
fn native_tree_refuses_a_functioning_filter_link_without_following_or_repairing_it() {
    let fixture = Fixture::new();
    drop(fixture.create("a.exe"));
    let target = fixture.create("target.exe");
    assert_eq!(write(&target, Name::UseFilter, &dword(7)), ERROR_SUCCESS);
    let path = wide("a.exe\\foreign-link");
    let mut handle = HKEY::default();
    status(unsafe {
        RegCreateKeyExW(
            fixture.scope().key.0,
            PCWSTR(path.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_CREATE_LINK,
            KEY_ALL_ACCESS | fixture.scope().view,
            None,
            &mut handle,
            None,
        )
    })
    .unwrap();
    let link = OwnedLink(Key(handle));
    let value = wide("SymbolicLinkValue");
    let bytes: Vec<_> = binding::native_name(&target)
        .unwrap()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    status(unsafe {
        RegSetValueExW(
            link.0.0,
            PCWSTR(value.as_ptr()),
            None,
            REG_LINK,
            Some(&bytes),
        )
    })
    .unwrap();
    assert_eq!(
        read_value(
            &fixture.open("a.exe\\foreign-link").unwrap(),
            Name::UseFilter
        )
        .unwrap(),
        Some(dword(7))
    );
    assert!(
        fixture
            .scope()
            .inspect_image_tree(
                "a.exe",
                Instant::now() + Duration::from_secs(5),
                &AtomicBool::new(false)
            )
            .is_err()
    );
    assert_eq!(
        read_value(&target, Name::UseFilter).unwrap(),
        Some(dword(7))
    );
    assert_eq!(
        binding::native_name(&fixture.open("a.exe\\foreign-link").unwrap()).unwrap(),
        binding::native_name(&target).unwrap()
    );
    drop(link);
}

#[test]
fn native_link_cannot_redirect_existing_values_or_new_leaf_creation() {
    let fixture = Fixture::new();
    let target = fixture.create("target.exe");
    assert_eq!(write(&target, Name::UseFilter, &dword(0)), ERROR_SUCCESS);
    let name = wide("link.exe");
    let mut key = HKEY::default();
    status(unsafe {
        RegCreateKeyExW(
            fixture.scope().key.0,
            PCWSTR(name.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_CREATE_LINK,
            KEY_ALL_ACCESS,
            None,
            &mut key,
            None,
        )
    })
    .unwrap();
    let link = OwnedLink(Key(key));
    let target_name = binding::native_name(&target).unwrap();
    assert!(target_name.starts_with(fixture.scope().native_identity()));
    let bytes: Vec<u8> = target_name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let value = wide("SymbolicLinkValue");
    status(unsafe {
        RegSetValueExW(
            link.0.0,
            PCWSTR(value.as_ptr()),
            None,
            REG_LINK,
            Some(&bytes),
        )
    })
    .unwrap();
    // Prove this is a functioning native alias before exercising the guard.
    assert_eq!(
        read_value(&fixture.open("link.exe").unwrap(), Name::UseFilter).unwrap(),
        Some(dword(0))
    );
    assert!(matches!(
        fixture.scope().value_identity("link.exe", Name::UseFilter),
        Err(Failure::NotAuthorized)
    ));
    let cancel = AtomicBool::new(false);
    let mut existing = fixture.tx(&cancel);
    assert!(
        existing
            .stage_existing(
                "link.exe",
                &[change(Name::UseFilter, Some(dword(0)), Some(dword(1)))]
            )
            .is_err()
    );
    assert!(matches!(commit_fixture(existing), Err(Failure::Ended)));
    assert!(
        fixture
            .scope()
            .inspect_image_tree("link.exe", Instant::now() + Duration::from_secs(5), &cancel)
            .is_err()
    );
    let mut guarded = fixture.tx(&cancel);
    assert!(
        guarded
            .stage_guarded(
                "link.exe",
                &[
                    change(Name::UseFilter, Some(dword(0)), Some(dword(0))),
                    change(Name::Debugger, None, None),
                ]
            )
            .is_err()
    );
    assert!(matches!(commit_fixture(guarded), Err(Failure::Ended)));
    let mut create = fixture.tx(&cancel);
    assert!(
        create
            .stage_new_leaf(
                "link.exe",
                "owned",
                &[change(Name::Debugger, None, Some(dword(1)))]
            )
            .is_err()
    );
    assert!(matches!(commit_fixture(create), Err(Failure::Ended)));
    let mut remove = fixture.tx(&cancel);
    assert!(
        remove
            .stage_remove_key("link.exe", &[change(Name::UseFilter, Some(dword(0)), None)])
            .is_err()
    );
    assert!(matches!(commit_fixture(remove), Err(Failure::Ended)));
    let mut create = fixture.tx(&cancel);
    assert!(
        create
            .stage_new_root("link.exe", &[change(Name::UseFilter, None, Some(dword(1)))])
            .is_err()
    );
    assert!(matches!(commit_fixture(create), Err(Failure::Ended)));
    assert_eq!(
        read_value(&target, Name::UseFilter).unwrap(),
        Some(dword(0))
    );
    assert!(matches!(
        fixture.open("target.exe\\owned"),
        Err(Failure::Native(2))
    ));
    drop(link);
    assert_eq!(
        read_value(&target, Name::UseFilter).unwrap(),
        Some(dword(0))
    );
}

#[test]
fn interactive_account_cannot_construct_a_production_write_scope() {
    if Principal::require_local_system().is_ok() {
        return;
    } // Separate System-account acceptance.
    for view in RegistryView::ALL {
        assert!(matches!(
            Scope::for_service_ifeo(view),
            Err(Failure::NotAuthorized)
        ));
    }
}

#[test]
#[ignore = "Opt-in read-only fixed HKLM IFEO scope/ACL/native-view probe; never writes or enumerates app rows"]
fn native_fixed_ifeo_read_only_scope_probe() {
    let cancel = AtomicBool::new(false);
    let missing_image = format!("DCleaner-ReadOnly-Probe-{}.exe", uuid::Uuid::new_v4());
    let scopes: Vec<_> = RegistryView::ALL
        .into_iter()
        .map(|view| binding::open_fixed(view, false).unwrap())
        .collect();
    for scope in &scopes {
        let snapshot = scope
            .inspect_image_tree(
                &missing_image,
                Instant::now() + Duration::from_secs(5),
                &cancel,
            )
            .unwrap();
        assert!(snapshot.root().is_none());
        assert!(snapshot.children().is_empty());
        assert_eq!(
            snapshot.root_id().unwrap(),
            scope
                .slot_identity(&missing_image, Name::UseFilter)
                .unwrap()
        );
        assert!(matches!(
            Transaction::begin(scope, Instant::now() + Duration::from_secs(5), &cancel),
            Err(Failure::NotAuthorized)
        ));
    }
    eprintln!(
        "fixed IFEO roots={} shared_native_root={} read_only=true app_rows_read=0 missing_image_tree_snapshots=2 native_effects=false",
        scopes.len(),
        crate::optimizer_intents::same_registry_path(
            scopes[0].native_identity(),
            scopes[1].native_identity()
        ) == Some(true)
    );
}
