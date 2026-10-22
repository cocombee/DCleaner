use super::*;
fn json(pinned: bool) -> Vec<u8> {
    format!("{{\"drop\":1,\"windows\":[{{\"tabs\":[{{\"pinned\":{},\"entries\":[{{\"url\":\"owned\"}}]}},{{\"pinned\":false}}],\"drop\":2}}]}}",if pinned {"true"}else{"false"}).into_bytes()
}
fn encoded(pinned: bool) -> Vec<u8> {
    moz_lz4::encode(&json(pinned), &AtomicBool::new(false)).unwrap()
}
#[test]
fn both_recent_mozilla_session_families_discover_special_and_generic_paths_read_only() {
    for browser in [Browser::Firefox, Browser::Thunderbird] {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("Profiles");
        let p = profile(&base.join("owned.default"), browser);
        let names = [
            ("sessionstore.js", json(true)),
            ("sessionstore.jsonlz4", encoded(false)),
            ("sessionstore.bak-old", b"raw backup".to_vec()),
            ("sessionCheckpoints.json", b"raw checkpoints".to_vec()),
            ("session.json", b"raw session".to_vec()),
            (
                "sessionstore-backups/recovery.jsonlz4",
                b"raw generic recovery".to_vec(),
            ),
            ("sessionstore-backups/deep/sessionstore.js", json(true)),
        ];
        let paths = names
            .iter()
            .map(|(n, b)| write(&p, n, b))
            .collect::<Vec<_>>();
        let stamps = paths
            .iter()
            .map(|p| file_stamp(p).unwrap())
            .collect::<Vec<_>>();
        write(&p, "prefs.js", b"unselected root prefs");
        write(&p, "recovery.jsonlz4", b"outside root mask");
        write(&p, "other/sessionstore.js", b"outside root scope");
        let mut inventory = ProfileInventory::default();
        profile_discovery::user_data_profiles(browser, &base, &mut inventory);
        assert_eq!(inventory.profiles.len(), 1, "{:?}", inventory.skipped);
        assert_eq!(inventory.profiles[0].root, p.root);
        let report = scan(&p);
        assert!(!report.partial, "{:?}", report.skipped);
        assert_eq!(report.records.len(), 7);
        assert_eq!(
            report
                .records
                .iter()
                .filter(|r| matches!(r.locator, RecordLocator::Preferences(_)))
                .count(),
            2
        );
        assert!(report.records.iter().all(|r|r.category==PrivacyCategory::Sessions && r.native_item_count().is_none()));
        for (((_, bytes), path), stamp) in names.iter().zip(paths).zip(stamps) {
            assert_eq!(fs::read(&path).unwrap(), *bytes);
            assert_eq!(file_stamp(&path).unwrap(), stamp);
        }
    }
}
#[test]
#[cfg(windows)]
fn windows_mozilla_paths_follow_filekeys_and_first_descriptor_without_chromium_adoption() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/mozilla-session-paths.json"
    ))
    .unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 104);
    for case in cases {
        let rule = catalogue::RULES
            .iter()
            .find(|r| r.id == case["rule"].as_str().unwrap())
            .unwrap();
        let root = PathBuf::from(case["root"].as_str().unwrap());
        let path = root.join(case["relative"].as_str().unwrap());
        let owner = winner(rule, &root, &path);
        match case["status"].as_str().unwrap() {
            "outside_filekey" => assert!(owner.is_none(), "{case}"),
            "FileTextExclude" => {
                assert!(unsupported(rule.browser, &root, &path));
                assert!(
                    binding(rule.browser, &root, &path).is_none()
                        && generic_binding(rule.browser, &root, &path).is_none()
                );
            }
            "FileDelete" => assert_eq!(
                generic_binding(rule.browser, &root, &path),
                Some((rule.id, owner.unwrap().key, false)),
                "{case}"
            ),
            "SessionMozilla" => {
                let expected = if case["owner"]["parameters"].as_array().unwrap().is_empty() {
                    Format::MozillaJson
                } else {
                    Format::MozillaLz4
                };
                assert_eq!(format(rule.browser, &root, &path), Some(expected), "{case}");
            }
            _ => panic!("unknown path result"),
        }
        if let Some(owner) = owner {
            assert_eq!(owner.key, case["owner"]["key"].as_str().unwrap());
        }
    }
}
#[test]
fn malformed_special_files_never_gain_generic_trash_and_declared_backups_keep_generic_ownership() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(temp.path(), Browser::Firefox);
    write(&p, "sessionstore.js", &image(false));
    write(&p, "sessionstore.jsonlz4", b"bad lz4");
    write(&p, "sessionstore-backups/sessionstore.js", b"bad JSON");
    write(&p, "sessionstore.bak", &image(true));
    write(
        &p,
        "sessionstore-backups/recovery.jsonlz4",
        b"generic, no JSON authority",
    );
    write(
        &p,
        "sessionstore-backups/prefs.js",
        b"unsupported text owner",
    );
    let report = scan(&p);
    assert!(report.partial);
    assert_eq!(report.records.len(), 2);
    assert!(
        report
            .records
            .iter()
            .all(|r| matches!(r.locator, RecordLocator::File(_)))
    );
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.reason.contains("text-filter"))
    );
}
#[test]
fn compressed_expansion_is_charged_before_json_observation_and_failed_budget_is_explicit() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(temp.path(), Browser::Firefox);
    let source = serde_json::to_vec(
        &serde_json::json!({"windows":[{"tabs":[{"pinned":true,"padding":"x".repeat(100_000)}]}]}),
    )
    .unwrap();
    let bytes = moz_lz4::encode(&source, &AtomicBool::new(false)).unwrap();
    assert!(bytes.len() < 1000);
    write(&p, "sessionstore.jsonlz4", &bytes);
    let mut report = scan_profiles_with_settings(
        &[],
        &[PrivacyCategory::Sessions],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    );
    let mut budget = 32_000;
    super::super::scan(
        &p,
        &AtomicBool::new(false),
        &mut budget,
        &mut 100,
        &mut HashSet::new(),
        &mut report,
    );
    // The outer scan finalizes `partial` from these component diagnostics.
    assert!(report.truncated && report.skipped_count > 0 && report.records.is_empty());
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.reason == preferences::SESSION_BUDGET_ERROR)
    );
    let report = scan(&p);
    assert_eq!(report.records.len(), 1);
    assert!(!report.partial);
    assert!(report.records[0].size_bytes().is_none());
}
#[test]
#[cfg(windows)]
fn locked_mozilla_leaf_is_a_metadata_only_witness_without_adopting_parent_container() {
    use std::os::windows::fs::OpenOptionsExt;
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().join("Profiles");
    let p = profile(&base.join("child"), Browser::Firefox);
    let path = write(
        &p,
        "sessionstore-backups/recovery.jsonlz4",
        b"not parsed by metadata discovery",
    );
    let held = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(path)
        .unwrap();
    let witness = discover(
        p.browser,
        &p.root,
        true,
        &AtomicBool::new(false),
        100,
        10000,
        true,
    );
    assert_eq!(witness.files.len(), 1);
    let container = discover(
        p.browser,
        &base,
        false,
        &AtomicBool::new(false),
        100,
        10000,
        true,
    );
    assert!(container.files.is_empty());
    drop(held);
    let mut inventory = ProfileInventory::default();
    profile_discovery::user_data_profiles(p.browser, &base, &mut inventory);
    assert_eq!(inventory.profiles.len(), 1);
    assert_eq!(inventory.profiles[0].root, p.root);
}
#[test]
#[cfg(windows)]
fn mixed_mozilla_file_cleanup_uses_exact_ids_durable_trash_and_individual_rewrite_recovery() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Firefox);
    let pinned = write(&p, "sessionstore.js", &json(true));
    let plain = write(&p, "sessionstore.jsonlz4", &encoded(false));
    let raw = write(&p, "sessionstore.bak", b"raw generic");
    let kept = write(
        &p,
        "sessionstore-backups/recovery.jsonlz4",
        b"unselected backup",
    );
    let report = scan(&p);
    let ids = report
        .records
        .iter()
        .filter(|r| !r.source_file().unwrap().contains("recovery"))
        .map(|r| r.id)
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 3);
    assert!(build_cleanup_plan(&report, &[Uuid::new_v4()]).is_err());
    let data = temp.path().join("data");
    let mut trash = OwnedTrash {
        data: data.clone(),
        destination: temp.path().join("trash"),
        moved: vec![],
    };
    let receipt = run(
        &data,
        &build_cleanup_plan(&report, &ids).unwrap(),
        &mut trash,
    );
    assert_eq!(
        (receipt.deleted, receipt.skipped, receipt.uncertain),
        (3, 0, false),
        "{:?}",
        receipt.errors
    );
    assert_eq!(trash.moved.len(), 2);
    assert!(!plain.exists() && !raw.exists());
    assert_eq!(fs::read(&kept).unwrap(), b"unselected backup");
    let after: serde_json::Value = serde_json::from_slice(&fs::read(&pinned).unwrap()).unwrap();
    assert_eq!(after["windows"][0]["tabs"].as_array().unwrap().len(), 1);
    let option = list_privacy_restore_options(&data).unwrap().remove(0);
    let plan = prepare_privacy_restore_with_runtime(&data, option.id, &Closed).unwrap();
    assert!(plan.restores_sessions());
    assert!(
        restore_privacy_database_with_runtime(&data, &plan, &Closed)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read(&pinned).unwrap(), json(true));
    assert!(p.root.join("sessionstore-backups").is_dir());
}
