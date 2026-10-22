use super::*;
use serde_json::{Value, json};

const INPUT: &[u8] = br#"{"savefile":{"default_directory":"private-old","type":9,"keep":1},"download":{"default_directory":"private-new"},"snap":{"save_location":"private-snap","used":true,"keep":2},"dns_prefetching":{"host_referral_list":[],"startup_list":false},"profile":{"content_settings":{"exceptions":{"media_engagement":{},"site_engagement":0}}},"keep":18446744073709551617}"#;
struct Closed;
impl BrowserRuntime for Closed {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        Ok(vec![])
    }
}
struct NoFiles;
impl crate::cleanup::TrashPort for NoFiles {
    fn move_to_trash(&mut self, _: &Path) -> Result<(), String> {
        panic!("location record attempted Trash")
    }
}
fn fixture(root: &Path, browser: Browser, bytes: &[u8]) -> BrowserProfile {
    fs::create_dir_all(root).unwrap();
    fs::write(root.join("Preferences"), bytes).unwrap();
    BrowserProfile {
        browser,
        id: "owned-location".into(),
        name: "Owned location".into(),
        root: dunce::canonicalize(root).unwrap(),
    }
}
fn scan(profile: &BrowserProfile, categories: &[PrivacyCategory]) -> PrivacyReport {
    scan_profiles_with_settings(
        std::slice::from_ref(profile),
        categories,
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    )
}
fn reviews(report: &PrivacyReport) -> Vec<Review> {
    report
        .records
        .iter()
        .filter_map(|r| match &r.locator {
            RecordLocator::Preferences(p) => Some(p.clone()),
            _ => None,
        })
        .collect()
}
fn selected(report: &PrivacyReport, field: Field) -> Review {
    reviews(report)
        .into_iter()
        .find(|r| r.field == field)
        .unwrap()
}
fn run(data: &Path, plan: &PrivacyPlan) -> PrivacyReceipt {
    clean_privacy_with_runtime_and_trash(
        data,
        plan,
        &AtomicBool::new(false),
        &Closed,
        &mut NoFiles,
        &mut |_, _| {},
    )
    .unwrap()
}

#[test]
fn location_discovery_covers_thirteen_families_but_snap_only_opera_without_read_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let mut count = 0;
    let mut units = 0;
    for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
        let base = temp.path().join(browser.cache_category());
        let profile = fixture(&base.join("Recent Preferences only"), browser, INPUT);
        let path = profile.root.join("Preferences");
        let stamp = file_stamp(&path).unwrap();
        let mut inventory = ProfileInventory::default();
        profile_discovery::user_data_profiles(browser, &base, &mut inventory);
        assert!(!inventory.partial);
        assert_eq!(inventory.profiles.len(), 1);
        let report = scan(
            &inventory.profiles[0],
            &[
                PrivacyCategory::LastDownloadLocation,
                PrivacyCategory::SnapLocation,
            ],
        );
        assert!(!report.partial, "{browser:?}: {:?}", report.skipped);
        let wanted = if matches!(browser, Browser::Opera | Browser::OperaGx) {
            2
        } else {
            1
        };
        assert_eq!(report.records.len(), wanted);
        assert!(
            report
                .records
                .iter()
                .all(|r| !r.site.contains("private") && r.size_bytes().is_none())
        );
        assert_eq!(file_stamp(&path).unwrap(), stamp);
        assert_eq!(fs::read(path).unwrap(), INPUT);
        count += 1;
        units += wanted;
    }
    assert_eq!((count, units), (13, 15));
}

#[test]
#[cfg(windows)]
fn configured_download_reset_preserves_other_settings_remains_candidate_and_restores_exactly() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome, INPUT);
    let data = temp.path().join("data");
    let report = scan(&profile, &[PrivacyCategory::LastDownloadLocation]);
    let chosen = selected(&report, Field::LastDownloadLocation);
    let receipt = run(&data, &build_cleanup_plan(&report, &[chosen.id]).unwrap());
    assert_eq!(
        (
            receipt.selected,
            receipt.deleted,
            receipt.skipped,
            receipt.uncertain
        ),
        (1, 1, 0, false),
        "{:?}",
        receipt.errors
    );
    let after = fs::read(profile.root.join("Preferences")).unwrap();
    let mut expected: Value = serde_json::from_slice(INPUT).unwrap();
    expected["savefile"]["default_directory"] = json!("private-new");
    assert_eq!(serde_json::from_slice::<Value>(&after).unwrap(), expected);
    assert!(
        after
            .windows(b"18446744073709551617".len())
            .any(|w| w == b"18446744073709551617")
    );
    assert_eq!(
        scan(&profile, &[PrivacyCategory::LastDownloadLocation])
            .records
            .len(),
        1
    );
    let options = list_privacy_restore_options(&data).unwrap();
    assert_eq!(options.len(), 1);
    assert_eq!(
        options[0].categories,
        vec![PrivacyCategory::LastDownloadLocation]
    );
    let plan = prepare_privacy_restore_with_runtime(&data, options[0].id, &Closed).unwrap();
    assert!(plan.restores_preferences());
    assert!(
        restore_privacy_database_with_runtime(&data, &plan, &Closed)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read(profile.root.join("Preferences")).unwrap(), INPUT);
}

#[test]
#[cfg(windows)]
fn fallback_and_snap_remove_only_their_own_primary_and_marker() {
    let temp = tempfile::tempdir().unwrap();
    for (n, configured) in [Value::Null, json!(""), json!(23), json!(false)]
        .into_iter()
        .enumerate()
    {
        for category in [
            PrivacyCategory::LastDownloadLocation,
            PrivacyCategory::SnapLocation,
        ] {
            let mut before: Value = serde_json::from_slice(INPUT).unwrap();
            before["download"]["default_directory"] = configured.clone();
            let bytes = serde_json::to_vec(&before).unwrap();
            let root = temp.path().join(format!("{n}-{category:?}"));
            let profile = fixture(&root, Browser::Opera, &bytes);
            let report = scan(&profile, &[category]);
            assert_eq!(report.records.len(), 1);
            let chosen = report.records[0].id;
            assert_eq!(
                run(
                    &root.join("data"),
                    &build_cleanup_plan(&report, &[chosen]).unwrap()
                )
                .deleted,
                1
            );
            let (parent, primary, marker) = if category == PrivacyCategory::LastDownloadLocation {
                ("savefile", "default_directory", "type")
            } else {
                ("snap", "save_location", "used")
            };
            before[parent].as_object_mut().unwrap().remove(primary);
            before[parent].as_object_mut().unwrap().remove(marker);
            assert_eq!(
                serde_json::from_slice::<Value>(&fs::read(root.join("Preferences")).unwrap())
                    .unwrap(),
                before
            );
        }
    }
}

#[test]
#[cfg(windows)]
fn mixed_six_field_plan_has_one_source_backup_distinct_recovery_categories_and_exact_restore() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::OperaGx, INPUT);
    let data = temp.path().join("data");
    let categories = [
        PrivacyCategory::History,
        PrivacyCategory::LastDownloadLocation,
        PrivacyCategory::SnapLocation,
    ];
    let report = scan(&profile, &categories);
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!(reviews(&report).len(), 6);
    let ids = report.records.iter().map(|r| r.id).collect::<Vec<_>>();
    let receipt = run(&data, &build_cleanup_plan(&report, &ids).unwrap());
    assert_eq!(
        (receipt.deleted, receipt.skipped, receipt.backups.len()),
        (6, 0, 1),
        "{:?}",
        receipt.errors
    );
    let remaining = scan(&profile, &categories);
    assert_eq!(remaining.records.len(), 1);
    assert_eq!(
        remaining.records[0].category,
        PrivacyCategory::LastDownloadLocation
    );
    let options = list_privacy_restore_options(&data).unwrap();
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].categories, categories);
    let plan = prepare_privacy_restore_with_runtime(&data, options[0].id, &Closed).unwrap();
    assert!(
        restore_privacy_database_with_runtime(&data, &plan, &Closed)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read(profile.root.join("Preferences")).unwrap(), INPUT);
}

#[test]
#[cfg(windows)]
fn same_stamp_configured_dependency_drift_refuses_reviewed_reset() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome, INPUT);
    let path = profile.root.join("Preferences");
    let report = scan(&profile, &[PrivacyCategory::LastDownloadLocation]);
    let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let stamp = file_stamp(&path).unwrap();
    let changed = String::from_utf8(INPUT.to_vec())
        .unwrap()
        .replace("private-new", "private-alt");
    fs::write(&path, &changed).unwrap();
    filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(modified)).unwrap();
    assert_eq!(file_stamp(&path).unwrap(), stamp);
    let receipt = run(&temp.path().join("data"), &plan);
    assert_eq!(
        (receipt.deleted, receipt.skipped, receipt.uncertain),
        (0, 1, false)
    );
    assert_eq!(fs::read(path).unwrap(), changed.as_bytes());
}

#[test]
fn category_and_family_isolation_avoids_unselected_invalid_preferences() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(
        &temp.path().join("profile"),
        Browser::Chrome,
        br#"{"savefile":{"default_directory":""},"dns_prefetching":false,"snap":false}"#,
    );
    let report = scan(&profile, &[PrivacyCategory::LastDownloadLocation]);
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!(report.records.len(), 1);
    fs::write(profile.root.join("Preferences"), b"invalid JSON").unwrap();
    for categories in [
        &[PrivacyCategory::SnapLocation][..],
        &[PrivacyCategory::Cookies][..],
    ] {
        let mut report = scan(&profile, &[]);
        super::scan(&profile, categories, &AtomicBool::new(false), &mut report);
        assert!(report.records.is_empty() && report.skipped.is_empty() && !report.partial);
    }
}

#[test]
#[cfg(windows)]
fn forged_snap_field_is_refused_for_non_opera_browser_before_effect() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome, INPUT);
    let report = scan(&profile, &[PrivacyCategory::LastDownloadLocation]);
    let mut chosen = selected(&report, Field::LastDownloadLocation);
    chosen.field = Field::SnapLocation.into();
    assert!(preflight(&Closed, &[chosen.clone()]).is_err());
    assert!(
        clean_group(
            &temp.path().join("data"),
            Uuid::new_v4(),
            &[chosen],
            &AtomicBool::new(false),
            &Closed,
            |_, _| panic!("forged field reached write")
        )
        .is_err()
    );
    assert_eq!(fs::read(profile.root.join("Preferences")).unwrap(), INPUT);
}

#[test]
#[cfg(windows)]
fn uncertain_byte_identical_reset_blocks_fresh_reviews_instead_of_replaying() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = String::from_utf8(INPUT.to_vec())
        .unwrap()
        .replace("private-old", "private-new");
    let profile = fixture(
        &temp.path().join("profile"),
        Browser::Chrome,
        bytes.as_bytes(),
    );
    let data = temp.path().join("data");
    let report = scan(&profile, &[PrivacyCategory::LastDownloadLocation]);
    let chosen = selected(&report, Field::LastDownloadLocation);
    let receipt = clean_group(
        &data,
        Uuid::new_v4(),
        &[chosen],
        &AtomicBool::new(false),
        &Closed,
        |_, _| Err("injected ambiguous reset".into()),
    )
    .unwrap();
    assert!(receipt.uncertain);
    assert_eq!(receipt.deleted, 0);
    assert_eq!(
        fs::read(profile.root.join("Preferences")).unwrap(),
        bytes.as_bytes()
    );
    let current = scan(&profile, &[PrivacyCategory::LastDownloadLocation]);
    assert_eq!(current.records.len(), 1);
    let refused = run(
        &data,
        &build_cleanup_plan(&current, &[current.records[0].id]).unwrap(),
    );
    assert_eq!((refused.deleted, refused.skipped), (0, 1));
    assert!(
        list_privacy_restore_options(&data)
            .unwrap()
            .iter()
            .all(|o| o.state != PrivacyRecoveryState::Ready)
    );
}

#[test]
#[cfg(windows)]
fn persisted_snap_journal_cannot_change_to_an_undeclared_browser_family() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Opera, INPUT);
    let data = temp.path().join("data");
    let report = scan(&profile, &[PrivacyCategory::SnapLocation]);
    assert_eq!(
        run(
            &data,
            &build_cleanup_plan(&report, &[report.records[0].id]).unwrap()
        )
        .deleted,
        1
    );
    let after = fs::read(profile.root.join("Preferences")).unwrap();
    let root = private_dir(&data, false).unwrap();
    let path = fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .unwrap();
    let bytes = fs::read(&path).unwrap();
    let mut rewritten = Vec::new();
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let mut event: Event = serde_json::from_slice(line).unwrap();
        if let Event::Start { intent } = &mut event {
            intent.source.browser = Browser::Chrome;
        }
        serde_json::to_writer(&mut rewritten, &event).unwrap();
        rewritten.push(b'\n');
    }
    fs::write(path, rewritten).unwrap();
    assert!(list_privacy_restore_options(&data).is_err());
    assert!(recover_privacy_operations(&data).is_err());
    assert_eq!(fs::read(profile.root.join("Preferences")).unwrap(), after);
}
