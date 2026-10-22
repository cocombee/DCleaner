//! Native same-state write guards, confined to random HKCU fixture keys.
use super::*;

fn guards() -> Vec<Change> {
    vec![
        change(Name::UseFilter, Some(dword(1)), Some(dword(1))),
        change(Name::Debugger, None, None),
    ]
}

#[test]
fn native_guarded_shared_root_commits_exact_bytes_without_public_scratch_values() {
    require_txr!();
    for view in RegistryView::ALL {
        let fixture = Fixture::in_view(view);
        let root = fixture.create("a.exe");
        assert_eq!(write(&root, Name::UseFilter, &dword(1)), ERROR_SUCCESS);
        let cancel = AtomicBool::new(false);
        let mut tx = fixture.tx(&cancel);
        tx.stage_guarded_with("a.exe", &guards(), || {
            assert_eq!(read_value(&root, Name::UseFilter).unwrap(), Some(dword(1)));
            assert_eq!(read_value(&root, Name::Debugger).unwrap(), None);
        })
        .unwrap();
        tx.stage_new_leaf(
            "a.exe",
            "owned",
            &[change(Name::Debugger, None, Some(dword(2)))],
        )
        .unwrap();
        assert!(matches!(
            fixture.open("a.exe\\owned"),
            Err(Failure::Native(2))
        ));
        commit_fixture(tx).unwrap();
        assert_eq!(read_value(&root, Name::UseFilter).unwrap(), Some(dword(1)));
        assert_eq!(read_value(&root, Name::Debugger).unwrap(), None);
        assert_eq!(
            read_value(&fixture.open("a.exe\\owned").unwrap(), Name::Debugger).unwrap(),
            Some(dword(2))
        );
    }
}

#[test]
fn native_guarded_preconditions_preserve_competing_writes_at_every_staging_boundary() {
    require_txr!();
    for view in RegistryView::ALL {
        for name in [Name::UseFilter, Name::Debugger] {
            for timing in 0..3 {
                let fixture = Fixture::in_view(view);
                let root = fixture.create("a.exe");
                assert_eq!(write(&root, Name::UseFilter, &dword(1)), ERROR_SUCCESS);
                let cancel = AtomicBool::new(false);
                let mut tx = fixture.tx(&cancel);
                let mut foreign = None;
                if timing == 0 {
                    foreign = Some(write(&root, name, &dword(7)));
                }
                let staged = tx.stage_guarded_with("a.exe", &guards(), || {
                    if timing == 1 {
                        foreign = Some(write(&root, name, &dword(7)));
                    }
                });
                if staged.is_ok() {
                    tx.stage_new_leaf(
                        "a.exe",
                        "owned",
                        &[change(Name::Debugger, None, Some(dword(2)))],
                    )
                    .unwrap();
                }
                if timing == 2 {
                    foreign = Some(write(&root, name, &dword(7)));
                }
                let foreign = foreign.unwrap();
                let committed = commit_fixture(tx);
                eprintln!(
                    "guard boundary view={view:?} name={name:?} timing={timing} foreign={} stage={staged:?} commit={committed:?}",
                    foreign.0
                );
                if foreign == ERROR_SUCCESS {
                    assert!(committed.is_err());
                    assert_eq!(read_value(&root, name).unwrap(), Some(dword(7)));
                    assert!(matches!(
                        fixture.open("a.exe\\owned"),
                        Err(Failure::Native(2))
                    ));
                } else {
                    assert_eq!(foreign, ERROR_TRANSACTIONAL_CONFLICT);
                    staged.unwrap();
                    committed.unwrap();
                }
            }
        }
    }
}

#[test]
fn native_guarded_drop_cancel_and_failed_stage_publish_nothing() {
    require_txr!();
    for mode in 0..4 {
        let fixture = Fixture::new();
        let root = fixture.create("a.exe");
        assert_eq!(write(&root, Name::UseFilter, &dword(1)), ERROR_SUCCESS);
        let cancel = AtomicBool::new(false);
        let mut tx = fixture.tx(&cancel);
        tx.stage_guarded("a.exe", &guards()).unwrap();
        tx.stage_new_leaf(
            "a.exe",
            "owned",
            &[change(Name::Debugger, None, Some(dword(2)))],
        )
        .unwrap();
        if mode == 2 {
            tx.stage_existing("a.exe", &guards()).unwrap_err();
        }
        if mode == 3 {
            tx.stage_guarded("A.EXE", &guards()).unwrap_err();
        }
        if mode == 0 {
            drop(tx);
        } else {
            cancel.store(mode == 1, Ordering::SeqCst);
            assert!(commit_fixture(tx).is_err());
        }
        assert_eq!(read_value(&root, Name::UseFilter).unwrap(), Some(dword(1)));
        assert_eq!(read_value(&root, Name::Debugger).unwrap(), None);
        assert!(matches!(
            fixture.open("a.exe\\owned"),
            Err(Failure::Native(2))
        ));
    }
}
