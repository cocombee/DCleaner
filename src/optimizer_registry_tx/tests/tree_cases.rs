//! Complete direct-level observations in unique disposable HKCU fixtures.
use super::*;
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn named(key: &Key, name: &[u16], kind: u32, bytes: &[u8]) {
    let mut name = name.to_vec();
    name.push(0);
    assert_eq!(
        unsafe {
            RegSetValueExW(
                key.0,
                PCWSTR(name.as_ptr()),
                None,
                REG_VALUE_TYPE(kind),
                Some(bytes),
            )
        },
        ERROR_SUCCESS
    );
}
fn ascii(key: &Key, name: &str, kind: u32, bytes: &[u8]) {
    named(key, &name.encode_utf16().collect::<Vec<_>>(), kind, bytes);
}

#[test]
fn native_tree_preserves_all_raw_values_and_checked_native_slot_identities() {
    for view in RegistryView::ALL {
        let fixture = Fixture::in_view(view);
        let root = fixture.create("a.exe");
        assert_eq!(write(&root, Name::UseFilter, &dword(1)), ERROR_SUCCESS);
        ascii(&root, "", 0, &[]);
        ascii(&root, "foreign", 3, &[0, 255, 128, 7]);
        named(&root, &[0xd800], 3, &[9]);
        let child = fixture.create("a.exe\\owned");
        assert_eq!(write(&child, Name::Debugger, &dword(2)), ERROR_SUCCESS);
        assert_eq!(
            write(&child, Name::FilterFullPath, &dword(3)),
            ERROR_SUCCESS
        );
        ascii(&child, "unknown", 42, &[1, 2, 3]);
        let cancel = AtomicBool::new(false);
        let snapshot = fixture
            .scope()
            .inspect_image_tree("A.EXE", deadline(), &cancel)
            .unwrap();
        assert!(snapshot.is_flat());
        assert_eq!(snapshot.root().unwrap().values().len(), 4);
        assert_eq!(
            snapshot.root().unwrap().selected(Name::UseFilter),
            Some(&dword(1))
        );
        assert_eq!(snapshot.root().unwrap().selected(Name::Debugger), None);
        assert!(
            snapshot
                .root()
                .unwrap()
                .values()
                .iter()
                .any(|v| v.name == [0xd800] && v.raw.bytes == [9])
        );
        assert!(
            snapshot
                .root()
                .unwrap()
                .values()
                .iter()
                .any(|v| v.name.is_empty() && v.raw.kind == 0 && v.raw.bytes.is_empty())
        );
        assert_eq!(snapshot.children().len(), 1);
        assert_eq!(snapshot.children()[0].node.values().len(), 3);
        assert_eq!(snapshot.children()[0].node.subkey_count(), 0);
        assert!(
            snapshot
                .root()
                .unwrap()
                .native_name()
                .to_lowercase()
                .ends_with("a.exe")
        );
        assert_eq!(
            snapshot.root_id().unwrap(),
            fixture
                .scope()
                .value_identity("a.exe", Name::UseFilter)
                .unwrap()
        );
        assert_eq!(
            snapshot.hook_id(0).unwrap(),
            fixture
                .scope()
                .value_identity("a.exe\\owned", Name::Debugger)
                .unwrap()
        );
        assert!(snapshot.hook_id(1).is_err());
        assert!(snapshot.revalidate(deadline(), &cancel).unwrap());
        assert_eq!(read_value(&root, Name::UseFilter).unwrap(), Some(dword(1)));
        assert_eq!(read_value(&child, Name::Debugger).unwrap(), Some(dword(2)));
    }
}

#[test]
fn native_tree_distinguishes_missing_empty_and_nested_namespaces_without_creating_keys() {
    let fixture = Fixture::new();
    let cancel = AtomicBool::new(false);
    let missing = fixture
        .scope()
        .inspect_image_tree("a.exe", deadline(), &cancel)
        .unwrap();
    assert!(missing.root().is_none());
    assert!(matches!(fixture.open("a.exe"), Err(Failure::Native(2))));
    let id = missing.root_id().unwrap();
    drop(fixture.create("a.exe"));
    let empty = fixture
        .scope()
        .inspect_image_tree("a.exe", deadline(), &cancel)
        .unwrap();
    assert!(empty.root().is_some());
    assert!(empty.root().unwrap().values().is_empty());
    assert_eq!(id, empty.root_id().unwrap());
    assert!(!missing.revalidate(deadline(), &cancel).unwrap());
    drop(fixture.create("a.exe\\owned\\nested"));
    let nested = fixture
        .scope()
        .inspect_image_tree("a.exe", deadline(), &cancel)
        .unwrap();
    assert!(!nested.is_flat());
    assert_eq!(nested.children()[0].node.subkey_count(), 1);
    assert!(nested.children()[0].node.values().is_empty());
    assert_eq!(nested.children().len(), 1);
}

#[test]
fn native_tree_rejects_changed_child_values_even_when_parent_metadata_is_unchanged() {
    let fixture = Fixture::new();
    let root = fixture.create("a.exe");
    let child = fixture.create("a.exe\\owned");
    assert_eq!(write(&child, Name::Debugger, &dword(1)), ERROR_SUCCESS);
    let cancel = AtomicBool::new(false);
    let before = stamp(&root).unwrap();
    let result = tree::observe_with(fixture.scope(), "a.exe", deadline(), &cancel, || {
        assert_eq!(write(&child, Name::Debugger, &dword(2)), ERROR_SUCCESS);
    });
    assert_eq!(stamp(&root).unwrap(), before);
    assert!(matches!(result, Err(Failure::Changed)));
    assert_eq!(read_value(&child, Name::Debugger).unwrap(), Some(dword(2)));
}

#[test]
fn native_tree_revalidation_rejects_foreign_value_and_child_additions() {
    let fixture = Fixture::new();
    let root = fixture.create("a.exe");
    let cancel = AtomicBool::new(false);
    let initial = fixture
        .scope()
        .inspect_image_tree("a.exe", deadline(), &cancel)
        .unwrap();
    ascii(&root, "foreign", 3, &[17]);
    assert!(!initial.revalidate(deadline(), &cancel).unwrap());
    let current = fixture
        .scope()
        .inspect_image_tree("a.exe", deadline(), &cancel)
        .unwrap();
    drop(fixture.create("a.exe\\foreign"));
    assert!(!current.revalidate(deadline(), &cancel).unwrap());
    let changing = tree::observe_with(fixture.scope(), "a.exe", deadline(), &cancel, || {
        drop(fixture.create("a.exe\\another"));
    });
    assert!(matches!(changing, Err(Failure::Changed)));
    assert!(fixture.open("a.exe\\foreign").is_ok());
    assert!(fixture.open("a.exe\\another").is_ok());
}

#[test]
fn native_tree_refuses_limit_exhaustion_instead_of_returning_a_partial_owned_set() {
    let cancel = AtomicBool::new(false);
    for kind in 0..4 {
        let fixture = Fixture::new();
        let root = fixture.create("a.exe");
        match kind {
            0 => {
                for index in 0..129 {
                    ascii(&root, &format!("v{index}"), 3, &[]);
                }
            }
            1 => {
                for index in 0..65 {
                    drop(fixture.create(&format!("a.exe\\k{index}")));
                }
            }
            2 => ascii(&root, "oversized", 3, &vec![1; MAX_BYTES + 1]),
            _ => {
                for index in 0..17 {
                    ascii(&root, &format!("v{index}"), 3, &vec![1; MAX_BYTES]);
                }
            }
        }
        assert!(matches!(
            fixture
                .scope()
                .inspect_image_tree("a.exe", deadline(), &cancel),
            Err(Failure::Limited)
        ));
        assert!(fixture.open("a.exe").is_ok());
    }
}

#[test]
fn native_tree_enforces_total_value_budget_across_children() {
    let fixture = Fixture::new();
    drop(fixture.create("a.exe"));
    for child in 0..5 {
        let key = fixture.create(&format!("a.exe\\k{child}"));
        for value in 0..103 {
            ascii(&key, &format!("v{value}"), 3, &[]);
        }
    }
    assert!(matches!(
        fixture
            .scope()
            .inspect_image_tree("a.exe", deadline(), &AtomicBool::new(false)),
        Err(Failure::Limited)
    ));
}

#[test]
fn native_tree_cancellation_deadlines_and_image_only_paths_do_not_publish_a_snapshot() {
    let fixture = Fixture::new();
    let cancel = AtomicBool::new(true);
    assert!(matches!(
        fixture
            .scope()
            .inspect_image_tree("a.exe", deadline(), &cancel),
        Err(Failure::Cancelled)
    ));
    cancel.store(false, Ordering::SeqCst);
    assert!(matches!(
        fixture
            .scope()
            .inspect_image_tree("a.exe", Instant::now(), &cancel),
        Err(Failure::Deadline)
    ));
    for image in ["", "..", "a.exe\\owned", "a.exe/b", "a\0b"] {
        assert!(matches!(
            fixture
                .scope()
                .inspect_image_tree(image, deadline(), &cancel),
            Err(Failure::InvalidPlan)
        ));
    }
    assert!(matches!(
        fixture.scope().inspect_image_tree(
            "a.exe",
            Instant::now() + Duration::from_secs(31),
            &cancel
        ),
        Err(Failure::InvalidPlan)
    ));
    assert!(matches!(fixture.open("a.exe"), Err(Failure::Native(2))));
}

#[test]
fn native_tree_accepts_exact_name_value_child_and_aggregate_boundaries() {
    let fixture = Fixture::new();
    let root = fixture.create("a.exe");
    ascii(&root, &"n".repeat(16_383), 3, &vec![3; MAX_BYTES]);
    for index in 0..127 {
        ascii(&root, &format!("v{index}"), 3, &[]);
    }
    for index in 0..64 {
        let name = if index == 0 {
            "k".repeat(255)
        } else {
            format!("k{index}")
        };
        let child = fixture.create(&format!("a.exe\\{name}"));
        if index < 3 {
            for value in 0..128 {
                ascii(&child, &format!("v{value}"), 3, &[]);
            }
        }
    }
    let snapshot = fixture
        .scope()
        .inspect_image_tree("a.exe", deadline(), &AtomicBool::new(false))
        .unwrap();
    assert_eq!(snapshot.root().unwrap().values().len(), 128);
    assert_eq!(snapshot.children().len(), 64);
    assert_eq!(
        snapshot
            .children()
            .iter()
            .map(|c| c.node.values().len())
            .sum::<usize>(),
        384
    );
    assert!(snapshot.is_flat());
    assert!(
        snapshot
            .root()
            .unwrap()
            .values()
            .iter()
            .any(|v| v.name.len() == 16_383 && v.raw.bytes.len() == MAX_BYTES)
    );
}

#[test]
fn native_tree_refuses_non_unicode_child_names_without_omitting_them() {
    let fixture = Fixture::new();
    let root = fixture.create("a.exe");
    let name = [0xd800u16, 0];
    let mut child = HKEY::default();
    status(unsafe {
        RegCreateKeyExW(
            root.0,
            PCWSTR(name.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            None,
            &mut child,
            None,
        )
    })
    .unwrap();
    drop(Key(child));
    assert_eq!(stamp(&root).unwrap().subkeys, 1);
    assert!(matches!(
        fixture
            .scope()
            .inspect_image_tree("a.exe", deadline(), &AtomicBool::new(false)),
        Err(Failure::NotAuthorized)
    ));
    assert_eq!(stamp(&root).unwrap().subkeys, 1);
}
