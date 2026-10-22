//! Native namespace creation/removal experiments in exact random HKCU fixtures.
use super::*;
use windows::Win32::System::Registry::RegDeleteKeyTransactedW;

#[test]
fn native_same_value_and_private_absence_writes_enlist_against_foreign_writers() {
    require_txr!();
    for view in RegistryView::ALL {
        for absent in [false, true] {
            for during_validation in [false, true] {
                let fixture = Fixture::in_view(view);
                let public = fixture.create("a.exe");
                if !absent {
                    assert_eq!(write(&public, Name::UseFilter, &dword(1)), ERROR_SUCCESS);
                }
                let cancel = AtomicBool::new(false);
                let mut tx = fixture.tx(&cancel);
                let private = tx.open("a.exe", KEY_QUERY_VALUE | KEY_SET_VALUE).unwrap();
                if absent {
                    assert_eq!(
                        write(&private, Name::UseFilter, &raw(0, &[])),
                        ERROR_SUCCESS
                    );
                    let name = Name::UseFilter.wide();
                    assert_eq!(
                        unsafe { RegDeleteValueW(private.0, PCWSTR(name.as_ptr())) },
                        ERROR_SUCCESS
                    );
                } else {
                    assert_eq!(write(&private, Name::UseFilter, &dword(1)), ERROR_SUCCESS);
                }
                let original = if absent { None } else { Some(dword(1)) };
                assert_eq!(read_value(&public, Name::UseFilter).unwrap(), original);
                assert_eq!(read_value(&private, Name::UseFilter).unwrap(), original);
                let foreign = if during_validation {
                    Some(write(&public, Name::UseFilter, &dword(7)))
                } else {
                    None
                };
                let matched = read_value(&public, Name::UseFilter).unwrap() == original;
                let foreign = foreign.unwrap_or_else(|| write(&public, Name::UseFilter, &dword(7)));
                drop(private);
                // Raw native experiment, not a production intent or authorization.
                let committed = if matched {
                    unsafe { CommitTransaction(tx.raw()) }.is_ok()
                } else {
                    unsafe { RollbackTransaction(tx.raw()) }.unwrap();
                    false
                };
                if matched && !committed {
                    let _ = unsafe { RollbackTransaction(tx.raw()) };
                }
                tx.ended = true;
                eprintln!(
                    "TxR guard probe view={view:?} absent={absent} during_validation={during_validation} foreign={} committed={committed}",
                    foreign.0
                );
                if foreign == ERROR_SUCCESS {
                    assert!(
                        !committed,
                        "a successful competing writer must not be overwritten"
                    );
                    assert_eq!(
                        read_value(&public, Name::UseFilter).unwrap(),
                        Some(dword(7))
                    );
                } else {
                    assert_eq!(foreign, ERROR_TRANSACTIONAL_CONFLICT);
                    assert!(committed);
                    assert_eq!(read_value(&public, Name::UseFilter).unwrap(), original);
                }
            }
        }
    }
}

#[test]
fn native_private_child_and_parent_removal_preserves_public_prestate_until_commit() {
    require_txr!();
    let fixture = Fixture::new();
    let parent = fixture.create("a.exe");
    let child = fixture.create("a.exe\\owned");
    assert_eq!(write(&parent, Name::UseFilter, &dword(1)), ERROR_SUCCESS);
    assert_eq!(write(&child, Name::Debugger, &dword(2)), ERROR_SUCCESS);
    let cancel = AtomicBool::new(false);
    let mut tx = fixture.tx(&cancel);
    let name = wide("a.exe\\owned");
    status(unsafe {
        RegDeleteKeyTransactedW(
            fixture.scope().key.0,
            PCWSTR(name.as_ptr()),
            fixture.scope().view.0,
            Some(0),
            tx.raw(),
            None,
        )
    })
    .unwrap();
    assert_eq!(read_value(&child, Name::Debugger).unwrap(), Some(dword(2)));
    assert_eq!(stamp(&parent).unwrap().subkeys, 1);
    let private_parent = tx.open("a.exe", KEY_QUERY_VALUE).unwrap();
    assert_eq!(stamp(&private_parent).unwrap().subkeys, 0);
    drop(private_parent);
    let name = wide("a.exe");
    status(unsafe {
        RegDeleteKeyTransactedW(
            fixture.scope().key.0,
            PCWSTR(name.as_ptr()),
            fixture.scope().view.0,
            Some(0),
            tx.raw(),
            None,
        )
    })
    .unwrap();
    assert_eq!(
        read_value(&parent, Name::UseFilter).unwrap(),
        Some(dword(1))
    );
    drop(child);
    drop(parent);
    // Low-level experiment has no production plan/receipt; never used outside
    // this uniquely owned fixture. No recursion, application or IFEO mutation.
    unsafe { CommitTransaction(tx.raw()) }.unwrap();
    tx.ended = true;
    assert!(matches!(fixture.open("a.exe"), Err(Failure::Native(2))));
}

#[test]
fn native_new_image_root_and_filter_restore_original_absent_namespace() {
    require_txr!();
    for view in RegistryView::ALL {
        let fixture = Fixture::in_view(view);
        let cancel = AtomicBool::new(false);
        let mut tx = fixture.tx(&cancel);
        tx.stage_new_root(
            "fresh.exe",
            &[change(Name::UseFilter, None, Some(dword(1)))],
        )
        .unwrap();
        tx.stage_new_leaf(
            "fresh.exe",
            "owned",
            &[
                change(Name::Debugger, None, Some(dword(2))),
                change(Name::FilterFullPath, None, Some(dword(3))),
            ],
        )
        .unwrap();
        assert!(matches!(fixture.open("fresh.exe"), Err(Failure::Native(2))));
        commit_fixture(tx).unwrap();
        assert_eq!(
            read_value(&fixture.open("fresh.exe\\owned").unwrap(), Name::Debugger).unwrap(),
            Some(dword(2))
        );
        let mut tx = fixture.tx(&cancel);
        tx.stage_remove_key(
            "fresh.exe\\owned",
            &[
                change(Name::Debugger, Some(dword(2)), None),
                change(Name::FilterFullPath, Some(dword(3)), None),
            ],
        )
        .unwrap();
        tx.stage_remove_key(
            "fresh.exe",
            &[change(Name::UseFilter, Some(dword(1)), None)],
        )
        .unwrap();
        assert!(fixture.open("fresh.exe\\owned").is_ok());
        commit_fixture(tx).unwrap();
        assert!(matches!(fixture.open("fresh.exe"), Err(Failure::Native(2))));
    }
}

#[test]
fn native_namespace_drop_and_cancel_restore_each_exact_prestate() {
    require_txr!();
    let fixture = Fixture::new();
    let cancel = AtomicBool::new(false);
    let mut tx = fixture.tx(&cancel);
    tx.stage_new_root(
        "fresh.exe",
        &[change(Name::UseFilter, None, Some(dword(1)))],
    )
    .unwrap();
    tx.stage_new_leaf(
        "fresh.exe",
        "owned",
        &[change(Name::Debugger, None, Some(dword(2)))],
    )
    .unwrap();
    drop(tx);
    assert!(matches!(fixture.open("fresh.exe"), Err(Failure::Native(2))));
    let existing = fixture.create("a.exe");
    assert_eq!(write(&existing, Name::UseFilter, &dword(1)), ERROR_SUCCESS);
    let mut tx = fixture.tx(&cancel);
    tx.stage_remove_key("a.exe", &[change(Name::UseFilter, Some(dword(1)), None)])
        .unwrap();
    cancel.store(true, Ordering::SeqCst);
    assert!(matches!(commit_fixture(tx), Err(Failure::Cancelled)));
    assert_eq!(
        read_value(&existing, Name::UseFilter).unwrap(),
        Some(dword(1))
    );
}

#[test]
fn native_removal_refuses_unknown_values_children_and_existing_creation_aliases() {
    let fixture = Fixture::new();
    let cancel = AtomicBool::new(false);
    let a = fixture.create("a.exe");
    assert_eq!(write(&a, Name::UseFilter, &dword(1)), ERROR_SUCCESS);
    assert_eq!(write(&a, Name::Debugger, &dword(7)), ERROR_SUCCESS);
    let mut tx = fixture.tx(&cancel);
    assert!(
        tx.stage_remove_key("a.exe", &[change(Name::UseFilter, Some(dword(1)), None)])
            .is_err()
    );
    assert!(matches!(commit_fixture(tx), Err(Failure::Ended)));
    assert_eq!(read_value(&a, Name::Debugger).unwrap(), Some(dword(7)));
    let b = fixture.create("b.exe");
    drop(fixture.create("b.exe\\foreign"));
    let mut tx = fixture.tx(&cancel);
    assert!(
        tx.stage_remove_key("b.exe", &[change(Name::UseFilter, None, None)])
            .is_err()
    );
    assert!(matches!(commit_fixture(tx), Err(Failure::Ended)));
    assert!(fixture.open("b.exe\\foreign").is_ok());
    drop(b);
    let mut tx = fixture.tx(&cancel);
    assert_eq!(
        tx.stage_new_root("A.EXE", &[change(Name::UseFilter, None, Some(dword(2)))]),
        Err(Failure::Changed)
    );
    assert!(matches!(commit_fixture(tx), Err(Failure::Ended)));
    assert_eq!(read_value(&a, Name::UseFilter).unwrap(), Some(dword(1)));
}

#[test]
fn native_empty_owned_leaf_can_be_removed_without_inventing_a_value_write() {
    require_txr!();
    let fixture = Fixture::new();
    drop(fixture.create("a.exe"));
    let cancel = AtomicBool::new(false);
    let mut tx = fixture.tx(&cancel);
    tx.stage_remove_key("a.exe", &[change(Name::UseFilter, None, None)])
        .unwrap();
    commit_fixture(tx).unwrap();
    assert!(matches!(fixture.open("a.exe"), Err(Failure::Native(2))));
}

#[test]
fn native_value_races_around_removal_preserve_any_successful_foreign_writer() {
    require_txr!();
    use std::cell::Cell;
    for timing in 0..3 {
        let fixture = Fixture::new();
        let a = fixture.create("a.exe");
        assert_eq!(write(&a, Name::UseFilter, &dword(1)), ERROR_SUCCESS);
        let cancel = AtomicBool::new(false);
        let mut tx = fixture.tx(&cancel);
        let foreign = Cell::new(ERROR_SUCCESS);
        let stage = tx.stage_remove_key_with(
            "a.exe",
            &[change(Name::UseFilter, Some(dword(1)), None)],
            || {
                if timing == 0 {
                    foreign.set(write(&a, Name::Debugger, &dword(7)));
                }
            },
            || {
                if timing == 1 {
                    foreign.set(write(&a, Name::Debugger, &dword(7)));
                }
            },
        );
        if timing == 2 {
            foreign.set(write(&a, Name::Debugger, &dword(7)));
        }
        let result = commit_fixture(tx);
        if foreign.get() == ERROR_SUCCESS {
            assert!(
                stage.is_err() || result.is_err(),
                "a successful intervening writer cannot be erased"
            );
            assert!(result.is_err());
            assert_eq!(
                read_value(&fixture.open("a.exe").unwrap(), Name::Debugger).unwrap(),
                Some(dword(7))
            );
        } else {
            assert_eq!(foreign.get(), ERROR_TRANSACTIONAL_CONFLICT);
            stage.unwrap();
            result.unwrap();
        }
    }
}

#[test]
fn native_concurrent_image_root_creation_is_never_adopted_or_overwritten() {
    require_txr!();
    let fixture = Fixture::new();
    let cancel = AtomicBool::new(false);
    let mut tx = fixture.tx(&cancel);
    tx.stage_new_root(
        "fresh.exe",
        &[change(Name::UseFilter, None, Some(dword(1)))],
    )
    .unwrap();
    let name = wide("fresh.exe");
    let mut key = HKEY::default();
    let code = unsafe {
        RegCreateKeyExW(
            fixture.scope().key.0,
            PCWSTR(name.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS | fixture.scope().view,
            None,
            &mut key,
            None,
        )
    };
    if code == ERROR_SUCCESS {
        let key = Key(key);
        assert_eq!(write(&key, Name::Debugger, &dword(7)), ERROR_SUCCESS);
        drop(key);
        assert!(commit_fixture(tx).is_err());
        assert_eq!(
            read_value(&fixture.open("fresh.exe").unwrap(), Name::Debugger).unwrap(),
            Some(dword(7))
        );
    } else {
        // Windows also reports FILE_NOT_FOUND while the unpublished native
        // name is reserved. Neither error is a successful foreign creation.
        assert!([ERROR_TRANSACTIONAL_CONFLICT, ERROR_FILE_NOT_FOUND].contains(&code));
        let result = commit_fixture(tx);
        eprintln!(
            "root creation race: foreign_status={} commit={result:?}",
            code.0
        );
        match result {
            Ok(_) => assert_eq!(
                read_value(&fixture.open("fresh.exe").unwrap(), Name::UseFilter).unwrap(),
                Some(dword(1))
            ),
            Err(Failure::CommitUncertain(_)) => (),
            other => panic!("unexpected native creation outcome: {other:?}"),
        }
    }
}

#[test]
fn native_foreign_child_created_during_parent_removal_survives_with_the_prior_child() {
    require_txr!();
    let fixture = Fixture::new();
    let parent = fixture.create("a.exe");
    drop(fixture.create("a.exe\\owned"));
    assert_eq!(write(&parent, Name::UseFilter, &dword(1)), ERROR_SUCCESS);
    let cancel = AtomicBool::new(false);
    let mut tx = fixture.tx(&cancel);
    tx.stage_remove_key("a.exe\\owned", &[change(Name::Debugger, None, None)])
        .unwrap();
    let mut foreign = ERROR_SUCCESS;
    let stage = tx.stage_remove_key_with(
        "a.exe",
        &[change(Name::UseFilter, Some(dword(1)), None)],
        || {
            let name = wide("foreign");
            let mut key = HKEY::default();
            foreign = unsafe {
                RegCreateKeyExW(
                    parent.0,
                    PCWSTR(name.as_ptr()),
                    None,
                    PCWSTR::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    None,
                    &mut key,
                    None,
                )
            };
            if foreign == ERROR_SUCCESS {
                drop(Key(key));
            }
        },
        || {},
    );
    let committed = commit_fixture(tx);
    if foreign == ERROR_SUCCESS {
        assert!(stage.is_err() || committed.is_err());
        assert!(committed.is_err());
        assert!(fixture.open("a.exe\\foreign").is_ok());
        assert!(fixture.open("a.exe\\owned").is_ok());
    } else {
        assert_eq!(foreign, ERROR_TRANSACTIONAL_CONFLICT);
        stage.unwrap();
        committed.unwrap();
    }
}

#[test]
fn native_wrong_removal_order_poisoning_preserves_earlier_unrelated_staging() {
    require_txr!();
    let fixture = Fixture::new();
    let a = fixture.create("a.exe");
    drop(fixture.create("a.exe\\owned"));
    let b = fixture.create("b.exe");
    assert_eq!(write(&a, Name::UseFilter, &dword(1)), ERROR_SUCCESS);
    let cancel = AtomicBool::new(false);
    let mut tx = fixture.tx(&cancel);
    tx.stage_existing("b.exe", &[change(Name::UseFilter, None, Some(dword(1)))])
        .unwrap();
    assert!(
        tx.stage_remove_key("a.exe", &[change(Name::UseFilter, Some(dword(1)), None)])
            .is_err()
    );
    assert!(matches!(commit_fixture(tx), Err(Failure::Ended)));
    assert_eq!(read_value(&b, Name::UseFilter).unwrap(), None);
    assert!(fixture.open("a.exe\\owned").is_ok());
}
