use super::*;
fn payload(pinned: bool, compressed: bool) -> Vec<u8> {
    let plain=format!("{{\"remove\":1,\"windows\":[{{\"tabs\":[{{\"pinned\":{},\"entries\":[{{\"url\":\"owned\"}}]}},{{\"pinned\":false}}],\"remove\":2}}]}}",if pinned {"true"}else{"false"}).into_bytes();
    if compressed {
        moz_lz4::encode(&plain, &AtomicBool::new(false)).unwrap()
    } else {
        plain
    }
}
fn fixture(root: &Path, browser: Browser, compressed: bool) -> BrowserProfile {
    fs::create_dir_all(root).unwrap();
    fs::write(
        root.join(if compressed {
            "sessionstore.jsonlz4"
        } else {
            "sessionstore.js"
        }),
        payload(true, compressed),
    )
    .unwrap();
    BrowserProfile {
        browser,
        id: Uuid::new_v4().to_string(),
        name: "Owned Mozilla session".into(),
        root: dunce::canonicalize(root).unwrap(),
    }
}
fn scan(p: &BrowserProfile) -> PrivacyReport {
    scan_profiles_with_settings(
        std::slice::from_ref(p),
        &[PrivacyCategory::Sessions],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    )
}
fn review(report: &PrivacyReport) -> Review {
    report
        .records
        .iter()
        .find_map(|r| match &r.locator {
            RecordLocator::Preferences(r) => Some(r.clone()),
            _ => None,
        })
        .unwrap()
}
struct Closed;
impl BrowserRuntime for Closed {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        Ok(vec![])
    }
}
struct NoTrash;
impl crate::cleanup::TrashPort for NoTrash {
    fn move_to_trash(&mut self, _: &Path) -> Result<(), String> {
        panic!("no file move was authorized")
    }
}
fn run(data: &Path, report: &PrivacyReport) -> PrivacyReceipt {
    clean_privacy_with_runtime_and_trash(
        data,
        &build_cleanup_plan(
            report,
            &report.records.iter().map(|r| r.id).collect::<Vec<_>>(),
        )
        .unwrap(),
        &AtomicBool::new(false),
        &Closed,
        &mut NoTrash,
        &mut |_, _| {},
    )
    .unwrap()
}
#[test]
#[cfg(windows)]
fn both_mozilla_families_and_encodings_rewrite_restore_exact_preimages_with_schema3() {
    for browser in [Browser::Firefox, Browser::Thunderbird] {
        for compressed in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let p = fixture(&temp.path().join("profile"), browser, compressed);
            let data = temp.path().join("data");
            let report = scan(&p);
            assert!(!report.partial, "{:?}", report.skipped);
            let chosen = review(&report);
            assert_eq!(chosen.source.version(), 3);
            assert!(
                chosen.field
                    == Target::Session(if compressed {
                        SessionTarget::MozillaLz4
                    } else {
                        SessionTarget::MozillaJson
                    })
            );
            let receipt = run(&data, &report);
            assert_eq!(
                (receipt.deleted, receipt.skipped, receipt.uncertain),
                (1, 0, false),
                "{:?}",
                receipt.errors
            );
            assert_eq!(
                fs::read(&receipt.backups[0]).unwrap(),
                payload(true, compressed)
            );
            let after = fs::read(chosen.source.path()).unwrap();
            let decoded = if compressed {
                moz_lz4::decode(&after, &AtomicBool::new(false)).unwrap()
            } else {
                after.clone()
            };
            let value: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
            assert_eq!(value["windows"][0]["tabs"].as_array().unwrap().len(), 1);
            assert_eq!(value.as_object().unwrap().len(), 1);
            let entries = entries(&data).unwrap();
            assert_eq!(entries[0].intent.version, 3);
            let option = list_privacy_restore_options(&data).unwrap().remove(0);
            let plan = prepare_privacy_restore_with_runtime(&data, option.id, &Closed).unwrap();
            assert!(plan.restores_sessions() && !plan.restores_preferences());
            let restored = restore_privacy_database_with_runtime(&data, &plan, &Closed).unwrap();
            assert!(restored.restored && !restored.uncertain);
            assert_eq!(
                fs::read(restored.current_state_backup.unwrap()).unwrap(),
                after
            );
            assert_eq!(
                fs::read(chosen.source.path()).unwrap(),
                payload(true, compressed)
            );
        }
    }
}
#[test]
#[cfg(windows)]
fn schema3_formats_cannot_be_relabelled_as_legacy_or_other_encoding_targets() {
    let temp = tempfile::tempdir().unwrap();
    let p = fixture(&temp.path().join("profile"), Browser::Firefox, false);
    let data = temp.path().join("data");
    let chosen = review(&scan(&p));
    for target in [SessionTarget::SessionFile, SessionTarget::MozillaLz4] {
        let mut forged = chosen.clone();
        forged.field = Target::Session(target);
        assert!(preflight(&Closed, &[forged]).is_err());
    }
    let mut forged = chosen.clone();
    Arc::make_mut(&mut forged.source).browser = Browser::Chrome;
    assert!(preflight(&Closed, &[forged]).is_err());
    let mut forged = chosen.clone();
    Arc::make_mut(&mut forged.source).relative = Some(PathBuf::from("../sessionstore.js"));
    assert!(preflight(&Closed, &[forged]).is_err());
    assert_eq!(run(&data, &scan(&p)).deleted, 1);
    let entry = entries(&data).unwrap().remove(0);
    let root = private_dir(&data, false).unwrap();
    let path = root.join(format!("{}.jsonl", entry.intent.id));
    let text = fs::read_to_string(&path).unwrap();
    let mut events = text
        .lines()
        .map(|l| serde_json::from_str::<Event>(l).unwrap())
        .collect::<Vec<_>>();
    if let Event::Start { intent } = &mut events[0] {
        intent.version = 2;
    }
    fs::write(
        &path,
        events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    assert!(entries(&data).is_err());
}
#[test]
#[cfg(windows)]
fn same_stamp_mozilla_cleanup_and_restore_drift_never_mutate_the_new_source() {
    for compressed in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let p = fixture(
            &temp.path().join("profile"),
            Browser::Thunderbird,
            compressed,
        );
        let data = temp.path().join("data");
        let report = scan(&p);
        let chosen = review(&report);
        let path = chosen.source.path();
        let original = fs::read(&path).unwrap();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let stamp = file_stamp(&path).unwrap();
        let mut changed = original.clone();
        *changed.last_mut().unwrap() ^= 1;
        fs::write(&path, &changed).unwrap();
        filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(modified)).unwrap();
        assert_eq!(file_stamp(&path).unwrap(), stamp);
        assert_eq!(run(&data, &report).deleted, 0);
        assert_eq!(fs::read(&path).unwrap(), changed);
        fs::write(&path, &original).unwrap();
        assert_eq!(run(&data, &scan(&p)).deleted, 1);
        let option = list_privacy_restore_options(&data).unwrap().remove(0);
        let plan = prepare_privacy_restore_with_runtime(&data, option.id, &Closed).unwrap();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let stamp = file_stamp(&path).unwrap();
        let mut changed = fs::read(&path).unwrap();
        *changed.last_mut().unwrap() ^= 1;
        fs::write(&path, &changed).unwrap();
        filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(modified)).unwrap();
        assert_eq!(file_stamp(&path).unwrap(), stamp);
        assert!(restore_privacy_database_with_runtime(&data, &plan, &Closed).is_err());
        assert_eq!(fs::read(&path).unwrap(), changed);
    }
}
#[test]
#[cfg(windows)]
fn uncertain_mozilla_rewrite_cannot_gain_fresh_file_trash_authority() {
    for compressed in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let p = fixture(&temp.path().join("profile"), Browser::Firefox, compressed);
        let data = temp.path().join("data");
        let chosen = review(&scan(&p));
        let replacement = payload(false, compressed);
        let receipt = clean_group(
            &data,
            Uuid::new_v4(),
            &[chosen.clone()],
            &AtomicBool::new(false),
            &Closed,
            |lease, _| {
                lease.write(&replacement)?;
                Err("injected uncertain write".into())
            },
        )
        .unwrap();
        assert!(receipt.uncertain && receipt.deleted == 0);
        let report = scan(&p);
        assert_eq!(report.records.len(), 1);
        assert!(matches!(report.records[0].locator, RecordLocator::File(_)));
        assert_eq!(run(&data, &report).deleted, 0);
        assert_eq!(fs::read(chosen.source.path()).unwrap(), replacement);
        assert_eq!(
            list_privacy_restore_options(&data).unwrap()[0].state,
            PrivacyRecoveryState::Uncertain
        );
    }
}
#[test]
#[cfg(windows)]
fn interrupted_compressed_restore_saves_current_bytes_and_blocks_retry() {
    let temp = tempfile::tempdir().unwrap();
    let p = fixture(&temp.path().join("profile"), Browser::Firefox, true);
    let data = temp.path().join("data");
    let chosen = review(&scan(&p));
    assert_eq!(run(&data, &scan(&p)).deleted, 1);
    let option = list_privacy_restore_options(&data).unwrap().remove(0);
    let plan = prepare_privacy_restore_with_runtime(&data, option.id, &Closed).unwrap();
    let current = fs::read(chosen.source.path()).unwrap();
    let receipt = restore_effect(
        &data,
        plan.preferences.as_ref().unwrap(),
        &Closed,
        |lease, _| {
            lease.write(b"mozL")?;
            Err("injected partial restore".into())
        },
    )
    .unwrap();
    assert!(receipt.uncertain && !receipt.restored);
    assert_eq!(
        fs::read(receipt.current_state_backup.unwrap()).unwrap(),
        current
    );
    assert!(prepare_privacy_restore_with_runtime(&data, option.id, &Closed).is_err());
    assert_eq!(fs::read(chosen.source.path()).unwrap(), b"mozL");
}
#[test]
#[cfg(windows)]
fn pending_file_intent_beyond_history_display_limit_blocks_new_mozilla_rewrite() {
    let temp = tempfile::tempdir().unwrap();
    let p = fixture(&temp.path().join("profile"), Browser::Thunderbird, true);
    let data = temp.path().join("data");
    let chosen = review(&scan(&p));
    let root = data.join("operations");
    fs::create_dir_all(&root).unwrap();
    for n in 0..102 {
        let id = Uuid::new_v4();
        let mut events = vec![crate::store::JournalEvent::Start {
            id,
            date: format!("{n:04}"),
        }];
        if n == 0 {
            events.push(crate::store::JournalEvent::Intent {
                file_id: Uuid::new_v4(),
                path: chosen.source.path(),
                size: 1,
            });
        } else {
            events.push(crate::store::JournalEvent::Finish { cancelled: false });
        }
        fs::write(
            root.join(format!("{id}.jsonl")),
            events
                .iter()
                .map(|e| serde_json::to_string(e).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
    }
    assert_eq!(crate::store::history(&data).unwrap().len(), 100);
    assert_eq!(run(&data, &scan(&p)).deleted, 0);
    assert_eq!(fs::read(chosen.source.path()).unwrap(), payload(true, true));
}
#[test]
#[cfg(windows)]
fn running_mozilla_browser_refuses_both_effect_routes_before_any_mutation() {
    struct Running(Browser);
    impl BrowserRuntime for Running {
        fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
            Ok(vec![RunningBrowser {
                browser: self.0,
                pid: 123,
                executable: if self.0 == Browser::Firefox {
                    "firefox.exe"
                } else {
                    "thunderbird.exe"
                }
                .into(),
            }])
        }
    }
    for browser in [Browser::Firefox, Browser::Thunderbird] {
        let temp = tempfile::tempdir().unwrap();
        let p = fixture(&temp.path().join("profile"), browser, false);
        fs::write(p.root.join("sessionstore.jsonlz4"), payload(false, true)).unwrap();
        let report = scan(&p);
        let ids = report.records.iter().map(|r| r.id).collect::<Vec<_>>();
        let result = clean_privacy_with_runtime_and_trash(
            &temp.path().join("data"),
            &build_cleanup_plan(&report, &ids).unwrap(),
            &AtomicBool::new(false),
            &Running(browser),
            &mut NoTrash,
            &mut |_, _| {},
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read(p.root.join("sessionstore.js")).unwrap(),
            payload(true, false)
        );
        assert_eq!(
            fs::read(p.root.join("sessionstore.jsonlz4")).unwrap(),
            payload(false, true)
        );
    }
}
#[test]
#[cfg(windows)]
fn hardlinked_mozilla_sources_are_not_observed_or_promoted_to_generic_file_moves() {
    for compressed in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let p = fixture(&temp.path().join("profile"), Browser::Firefox, compressed);
        let path = p.root.join(if compressed {
            "sessionstore.jsonlz4"
        } else {
            "sessionstore.js"
        });
        fs::hard_link(&path, temp.path().join("outside-link")).unwrap();
        let report = scan(&p);
        assert!(report.partial && report.records.is_empty());
        assert_eq!(fs::read(path).unwrap(), payload(true, compressed));
    }
}
#[test]
#[cfg(windows)]
fn skipped_window_is_reported_partial_and_survives_reviewed_supported_window_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let p = fixture(&temp.path().join("profile"), Browser::Firefox, false);
    let source=br#"{"privateRoot":1,"windows":[{"tabs":null,"privateSkipped":"keep"},{"tabs":[{"pinned":true},{"pinned":false}],"privateValid":"remove"}]}"#;
    fs::write(p.root.join("sessionstore.js"), source).unwrap();
    let report = scan(&p);
    assert!(report.partial && report.records.len() == 1);
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.reason.contains("non-array tabs"))
    );
    let receipt = run(&temp.path().join("data"), &report);
    assert_eq!(receipt.deleted, 1);
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(p.root.join("sessionstore.js")).unwrap()).unwrap();
    assert_eq!(value["windows"][0]["privateSkipped"], "keep");
    assert!(value["windows"][1].get("privateValid").is_none());
}
#[test]
#[cfg(windows)]
fn maximum_literal_carrier_above_json_size_bound_has_exact_durable_restore() {
    let temp = tempfile::tempdir().unwrap();
    let p = fixture(&temp.path().join("profile"), Browser::Firefox, true);
    let prefix = br#"{"windows":[{"tabs":[{"pinned":true,"payload":""#;
    let suffix = br#""}]}]}"#;
    let mut plain = prefix.to_vec();
    plain.resize(moz_lz4::MAX_BYTES - suffix.len(), b'a');
    plain.extend_from_slice(suffix);
    assert_eq!(plain.len(), moz_lz4::MAX_BYTES);
    let mut bytes = b"mozLz40\0".to_vec();
    bytes.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    bytes.push(0xf0);
    let mut n = plain.len() - 15;
    while n >= 255 {
        bytes.push(255);
        n -= 255;
    }
    bytes.push(n as u8);
    bytes.extend_from_slice(&plain);
    assert!(bytes.len() > json_members::MAX_BYTES && bytes.len() <= moz_lz4::MAX_CARRIER);
    let path = p.root.join("sessionstore.jsonlz4");
    fs::write(&path, &bytes).unwrap();
    let data = temp.path().join("data");
    let report = scan(&p);
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!(report.records.len(), 1);
    assert_eq!(run(&data, &report).deleted, 1);
    let option = list_privacy_restore_options(&data).unwrap().remove(0);
    let plan = prepare_privacy_restore_with_runtime(&data, option.id, &Closed).unwrap();
    assert!(
        restore_privacy_database_with_runtime(&data, &plan, &Closed)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read(path).unwrap(), bytes);
}
#[test]
#[cfg(windows)]
fn legacy_json_chromium_binary_and_both_mozilla_formats_keep_separate_recovery_authority() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let root = temp.path().join("chrome");
    fs::create_dir_all(root.join("Sessions")).unwrap();
    fs::write(
        root.join("Preferences"),
        br#"{"dns_prefetching":{"startup_list":false}}"#,
    )
    .unwrap();
    let mut bytes = b"SNSS\x01\x00\x00\x00".to_vec();
    bytes.extend_from_slice(&[9, 0, 12, 11, 0, 0, 0, 1, 0, 0, 0, 2, 0, 255, b'x']);
    fs::write(root.join("Sessions/Session_1"), bytes).unwrap();
    let chrome = BrowserProfile {
        browser: Browser::Chrome,
        id: "legacy-chrome".into(),
        name: "Legacy fixture".into(),
        root: dunce::canonicalize(root).unwrap(),
    };
    let report = scan_profiles_with_settings(
        &[chrome],
        &[PrivacyCategory::History, PrivacyCategory::Sessions],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(run(&data, &report).deleted, 2);
    for compressed in [false, true] {
        let p = fixture(
            &temp.path().join(format!("mozilla-{compressed}")),
            Browser::Firefox,
            compressed,
        );
        assert_eq!(run(&data, &scan(&p)).deleted, 1);
    }
    let all = entries(&data).unwrap();
    assert_eq!(all.len(), 4);
    assert_eq!(
        all.iter().map(|e| e.intent.version).collect::<HashSet<_>>(),
        HashSet::from([1, 2, 3])
    );
    let options = list_privacy_restore_options(&data).unwrap();
    assert_eq!(options.len(), 4);
    for option in options {
        let plan = prepare_privacy_restore_with_runtime(&data, option.id, &Closed).unwrap();
        assert!(
            restore_privacy_database_with_runtime(&data, &plan, &Closed)
                .unwrap()
                .restored
        );
    }
}
