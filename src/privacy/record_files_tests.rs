use super::*;
use crate::{cleanup::TrashPort, store::JournalEvent};

fn profile(root: &Path, browser: Browser) -> BrowserProfile {
    fs::create_dir_all(root).unwrap();
    BrowserProfile {
        id: Uuid::new_v4().to_string(),
        browser,
        name: "Owned record-file fixture".into(),
        root: dunce::canonicalize(root).unwrap(),
    }
}
fn write(profile: &BrowserProfile, relative: &str, bytes: &[u8]) -> PathBuf {
    let path = profile.root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    path
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
struct Closed;
impl BrowserRuntime for Closed {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        Ok(vec![])
    }
}
struct OwnedTrash {
    data: PathBuf,
    destination: PathBuf,
    moved: Vec<PathBuf>,
}
impl TrashPort for OwnedTrash {
    fn move_to_trash(&mut self, path: &Path) -> Result<(), String> {
        let events = fs::read_dir(self.data.join("operations"))
            .unwrap()
            .flat_map(|e| {
                fs::read_to_string(e.unwrap().path())
                    .unwrap()
                    .lines()
                    .map(|l| serde_json::from_str::<JournalEvent>(l).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert!(
            events
                .iter()
                .any(|e| matches!(e,JournalEvent::Intent {path:intended,..} if intended==path))
        );
        fs::create_dir_all(&self.destination).unwrap();
        fs::rename(path, self.destination.join(Uuid::new_v4().to_string()))
            .map_err(|e| e.to_string())?;
        self.moved.push(path.to_owned());
        Ok(())
    }
}

#[test]
#[cfg(windows)]
fn native_owned_filename_matrix_matches_all_families_and_preserves_sources() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/record-files.json")).unwrap();
    let temp = tempfile::tempdir().unwrap();
    for (index, group) in corpus["groups"].as_array().unwrap().iter().enumerate() {
        let browser: Browser = serde_json::from_value(group["browser"].clone()).unwrap();
        let category: PrivacyCategory = serde_json::from_value(group["category"].clone()).unwrap();
        let p = profile(&temp.path().join(index.to_string()), browser);
        let mut originals = Vec::new();
        for relative in corpus["input_files"].as_array().unwrap() {
            let relative = relative.as_str().unwrap();
            let content = format!("Owned synthetic {relative}").into_bytes();
            let path = write(&p, relative, &content);
            let stamp = file_stamp(&path).unwrap();
            originals.push((path, content, stamp));
        }
        let report = scan(&p, &[category]);
        let actual = report
            .records
            .iter()
            .filter_map(|r| {
                let RecordLocator::File(file) = &r.locator else {
                    return None;
                };
                let (rule, handler) = file.record_binding().expect("file has wrong owner");
                assert_eq!(rule, group["rule"].as_str().unwrap());
                assert_eq!(r.category, category);
                assert_eq!(r.item_count(), 1);
                assert!(r.actionable());
                let relative = file
                    .candidate
                    .path
                    .strip_prefix(&p.root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                assert_eq!(r.source_file().as_deref(), Some(relative.as_str()));
                Some((relative, handler.to_owned()))
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let expected = group["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["path"].as_str().unwrap().to_owned(),
                    r["handler"].as_str().unwrap().to_owned(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(actual, expected, "{} {:?}", group["rule"], report.skipped);
        for (path, bytes, stamp) in originals {
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(file_stamp(&path).unwrap(), stamp);
        }
    }
}

#[test]
fn file_only_chromium_profiles_have_literal_declared_witnesses() {
    let temp = tempfile::tempdir().unwrap();
    for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
        let base = temp.path().join(browser.cache_category());
        let p = profile(&base.join("Default"), browser);
        write(&p, "Visited Links", b"owned history bytes");
        let mut inventory = ProfileInventory::default();
        profile_discovery::user_data_profiles(browser, &base, &mut inventory);
        assert_eq!(
            inventory.profiles.len(),
            1,
            "{browser:?}: {:?}",
            inventory.skipped
        );
        assert!(same_named_path(&inventory.profiles[0].root, &p.root));
        let report = scan(&inventory.profiles[0], &[PrivacyCategory::History]);
        assert_eq!(report.records.len(), 1);
        assert!(!report.partial, "{:?}", report.skipped);
    }
}

#[test]
fn path_depth_content_and_file_limits_preserve_partial_inventory_without_effects() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(temp.path(), Browser::Chrome);
    write(&p, "Visited Links", b"owned bytes");
    write(&p, "Archived History", b"other bytes");
    let keeps = std::sync::Arc::new(HashSet::new());
    for limits in [
        Limits {
            entries: 0,
            path_bytes: usize::MAX,
            depth: 16,
        },
        Limits {
            entries: usize::MAX,
            path_bytes: 0,
            depth: 16,
        },
    ] {
        let mut report = scan(&p, &[]);
        let mut byte_budget = 1024;
        let mut files = 10;
        scan_with_limits(
            &p,
            &[PrivacyCategory::History],
            &keeps,
            &AtomicBool::new(false),
            &mut byte_budget,
            &mut files,
            &mut HashSet::new(),
            &mut report,
            limits,
        );
        assert!(report.truncated && report.records.is_empty());
    }
    let mut report = scan(&p, &[]);
    let mut files = 10;
    scan_with_limits(
        &p,
        &[PrivacyCategory::History],
        &keeps,
        &AtomicBool::new(false),
        &mut 0,
        &mut files,
        &mut HashSet::new(),
        &mut report,
        Limits {
            entries: 100,
            path_bytes: 10000,
            depth: 16,
        },
    );
    storage_files::group_records(&p, &mut report, &AtomicBool::new(false));
    assert!(
        report.skipped_count > 0
            && report.records.len() == 2
            && report.records.iter().all(|r| !r.actionable())
    );
    let ff = profile(&temp.path().join("firefox"), Browser::Firefox);
    write(&ff, "nested/history.dat", b"deep bytes");
    let mut report = scan(&ff, &[]);
    scan_with_limits(
        &ff,
        &[PrivacyCategory::History],
        &keeps,
        &AtomicBool::new(false),
        &mut 1024,
        &mut 10,
        &mut HashSet::new(),
        &mut report,
        Limits {
            entries: 100,
            path_bytes: 10000,
            depth: 0,
        },
    );
    assert!(report.truncated && report.records.is_empty());
}

#[test]
#[cfg(windows)]
fn redirected_recursive_thumbnail_root_is_not_followed() {
    use std::os::windows::process::CommandExt;
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Firefox);
    let outside = temp.path().join("owned-outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("one.png"), b"outside bytes").unwrap();
    let link = p.root.join("thumbnails");
    let output = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&outside)
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let report = scan(&p, &[PrivacyCategory::History]);
    assert!(report.partial && report.records.is_empty());
    assert!(contains_named_path(&p.root, &link) && is_link(&fs::symlink_metadata(&link).unwrap()));
    fs::remove_dir(&link).unwrap();
    assert_eq!(fs::read(outside.join("one.png")).unwrap(), b"outside bytes");
}

#[test]
#[cfg(windows)]
fn reviewed_history_file_moves_after_intent_and_unselected_downloads_stay() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let chosen = write(&p, "Visited Links", b"chosen");
    let other = write(&p, "DownloadMetadata", b"preserved");
    let report = scan_profiles_with_settings(
        std::slice::from_ref(&p),
        &[PrivacyCategory::History, PrivacyCategory::Downloads],
        &CookieExceptionSettings {
            schema: COOKIE_SETTINGS_SCHEMA,
            keep_domains: vec!["kept.test".into()],
            keep_signed_in: false,
        },
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!(report.records.len(), 2);
    let record = report
        .records
        .iter()
        .find(|r| r.category == PrivacyCategory::History)
        .unwrap();
    let plan = build_cleanup_plan(&report, &[record.id]).unwrap();
    let data = temp.path().join("data");
    let mut trash = OwnedTrash {
        data: data.clone(),
        destination: temp.path().join("trash"),
        moved: vec![],
    };
    let receipt = clean_privacy_with_runtime_and_trash(
        &data,
        &plan,
        &AtomicBool::new(false),
        &Closed,
        &mut trash,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (1, 0),
        "{:?}",
        receipt.errors
    );
    assert!(!chosen.exists());
    assert_eq!(fs::read(other).unwrap(), b"preserved");
    assert_eq!(trash.moved.len(), 1);
}

#[test]
#[cfg(windows)]
fn content_drift_and_unreviewed_sidecars_never_move_record_files() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let path = write(&p, "Top Sites", b"original");
    let report = scan(&p, &[PrivacyCategory::History]);
    let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
    let mtime = filetime::FileTime::from_last_modification_time(&fs::metadata(&path).unwrap());
    fs::write(&path, b"modified").unwrap();
    filetime::set_file_mtime(&path, mtime).unwrap();
    let data = temp.path().join("data");
    let mut trash = OwnedTrash {
        data: data.clone(),
        destination: temp.path().join("trash"),
        moved: vec![],
    };
    let result = clean_privacy_with_runtime_and_trash(
        &data,
        &plan,
        &AtomicBool::new(false),
        &Closed,
        &mut trash,
        &mut |_, _| {},
    );
    assert!(result.as_ref().map(|r| r.deleted == 0).unwrap_or(true));
    assert!(trash.moved.is_empty());
    assert_eq!(fs::read(&path).unwrap(), b"modified");
    write(&p, "Top Sites-wal", b"unreviewed state");
    let report = scan(&p, &[PrivacyCategory::History]);
    assert_eq!(report.records.len(), 1);
    assert!(!report.records[0].actionable());
    assert!(build_cleanup_plan(&report, &[report.records[0].id]).is_err());
}

#[test]
fn recursive_roots_and_exact_masks_do_not_claim_nearby_documents_or_passwords() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(temp.path(), Browser::Firefox);
    write(&p, "nested/downloads.rdf", b"metadata");
    write(&p, "thumbnails/deep/one.png", b"image");
    write(&p, "Downloads/user-file.pdf", b"user document");
    write(&p, "Login Data", b"password data");
    let report = scan(&p, &[PrivacyCategory::History, PrivacyCategory::Downloads]);
    assert_eq!(report.records.len(), 2, "{:?}", report.skipped);
    assert_eq!(
        report
            .records
            .iter()
            .map(PrivacyRecord::item_count)
            .sum::<usize>(),
        2
    );
    assert!(p.root.join("Downloads/user-file.pdf").exists());
    assert!(p.root.join("Login Data").exists());
    let cancelled = scan_profiles_with_settings(
        &[p],
        &[PrivacyCategory::History],
        &Default::default(),
        &AtomicBool::new(true),
        |_| {},
    );
    assert!(cancelled.cancelled && cancelled.records.is_empty());
}

fn owned_files(p: &BrowserProfile, report: &PrivacyReport) -> Vec<(String, &'static str)> {
    let mut owned = report
        .records
        .iter()
        .filter_map(|r| {
            let RecordLocator::File(file) = &r.locator else {
                return None;
            };
            let (_, handler) = file.record_binding()?;
            let relative = file
                .candidate
                .path
                .strip_prefix(&p.root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            Some((relative, handler))
        })
        .collect::<Vec<_>>();
    owned.sort();
    owned
}

#[test]
#[cfg(windows)]
fn saved_password_files_are_owned_only_when_that_category_is_selected() {
    let temp = tempfile::tempdir().unwrap();
    let chrome = profile(&temp.path().join("chrome"), Browser::Chrome);
    write(&chrome, "Login Data", b"owned password store");
    write(&chrome, "Login Data For Account", b"not declared");
    write(&chrome, "History-journal", b"unrelated");
    for unrelated in [PrivacyCategory::History, PrivacyCategory::Downloads] {
        assert!(owned_files(&chrome, &scan(&chrome, &[unrelated])).is_empty());
    }
    let report = scan(&chrome, &[PrivacyCategory::SavedPasswords]);
    assert_eq!(
        owned_files(&chrome, &report),
        [("Login Data".to_owned(), "OnFile1")]
    );
    assert!(report.records.iter().all(|r| r.actionable()));

    let opera = profile(&temp.path().join("opera"), Browser::Opera);
    write(&opera, "Login Data", b"owned");
    write(&opera, "wand.dat", b"owned legacy store");
    assert_eq!(
        owned_files(&opera, &scan(&opera, &[PrivacyCategory::SavedPasswords])),
        [
            ("Login Data".to_owned(), "OnFile1"),
            ("wand.dat".to_owned(), "OnFile3")
        ]
    );
}

#[test]
#[cfg(windows)]
fn mozilla_password_and_site_security_files_keep_keys_and_sql_stores_untouched() {
    let temp = tempfile::tempdir().unwrap();
    for browser in [Browser::Firefox, Browser::Thunderbird] {
        let p = profile(&temp.path().join(browser.cache_category()), browser);
        for name in [
            "logins.json",
            "logins-backup.json",
            "signons3.txt",
            "nested/signons.txt",
            "key4.db",
            "cert9.db",
            "SiteSecurityServiceState.txt",
            "places.sqlite",
        ] {
            write(&p, name, b"owned synthetic");
        }
        let passwords = scan(&p, &[PrivacyCategory::SavedPasswords]);
        assert_eq!(
            owned_files(&p, &passwords),
            [
                ("logins-backup.json".to_owned(), "OnFile2"),
                ("logins.json".to_owned(), "OnFile2"),
                ("nested/signons.txt".to_owned(), "OnFile2"),
                ("signons3.txt".to_owned(), "OnFile2"),
            ],
            "{browser:?}"
        );
        let site = scan(&p, &[PrivacyCategory::SitePreferences]);
        assert_eq!(
            owned_files(&p, &site),
            [("SiteSecurityServiceState.txt".to_owned(), "OnFile4")]
        );
        assert!(p.root.join("key4.db").exists() && p.root.join("cert9.db").exists());
    }
}

#[test]
#[cfg(windows)]
fn reviewed_login_data_moves_after_intent_but_a_live_journal_blocks_it() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Edge);
    let login = write(&p, "Login Data", b"owned password store");
    let history = write(&p, "Visited Links", b"preserved");
    let report = scan(&p, &[PrivacyCategory::SavedPasswords]);
    assert_eq!(report.records.len(), 1, "{:?}", report.skipped);
    let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
    let data = temp.path().join("data");
    let mut trash = OwnedTrash {
        data: data.clone(),
        destination: temp.path().join("trash"),
        moved: vec![],
    };
    let receipt = clean_privacy_with_runtime_and_trash(
        &data,
        &plan,
        &AtomicBool::new(false),
        &Closed,
        &mut trash,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (1, 0),
        "{:?}",
        receipt.errors
    );
    assert!(!login.exists());
    assert_eq!(fs::read(history).unwrap(), b"preserved");

    write(&p, "Login Data", b"browser recreated it");
    write(&p, "Login Data-journal", b"live transaction");
    let report = scan(&p, &[PrivacyCategory::SavedPasswords]);
    assert_eq!(report.records.len(), 1);
    assert!(!report.records[0].actionable());
    assert!(build_cleanup_plan(&report, &[report.records[0].id]).is_err());
}
