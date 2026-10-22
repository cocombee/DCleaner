use super::super::leveldb_format::tests::{batch, empty, log};
use super::*;

fn profile(root: &Path, browser: Browser) -> BrowserProfile {
    fs::create_dir_all(root).unwrap();
    BrowserProfile {
        id: Uuid::new_v4().to_string(),
        browser,
        name: "Owned LevelDB fixture".into(),
        root: dunce::canonicalize(root).unwrap(),
    }
}
fn write(profile: &BrowserProfile) -> PathBuf {
    write_at(profile, "Local Storage/leveldb")
}
fn write_at(profile: &BrowserProfile, relative: &str) -> PathBuf {
    let path = profile.root.join(relative);
    fs::create_dir_all(&path).unwrap();
    let mut files = empty();
    files.insert("LOCK".into(), vec![]);
    files.insert(
        "000003.log".into(),
        log(&[batch(
            11,
            &[
                (b"VERSION", Some(b"1")),
                (b"_https://one.test\0first", Some(b"private first value")),
                (b"_https://one.test\0second", Some(b"private second value")),
                (b"META:https://keep.test", Some(b"private metadata")),
                (b"_https://gone.test\0deleted", Some(b"old")),
                (b"_https://gone.test\0deleted", None),
            ],
        )]),
    );
    for (name, data) in files {
        fs::write(path.join(name), data).unwrap();
    }
    path
}

#[test]
fn all_eligible_chromium_filekey_scopes_recurse_without_age_filter_or_duplicate_key_owners() {
    let temp = tempfile::tempdir().unwrap();
    for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
        let profile = profile(&temp.path().join(browser.cache_category()), browser);
        let paths = [
            "Local Storage/leveldb",
            "databases/extension/deep/store",
            "IndexedDB/chrome-extension_owned/deep/store",
            "IndexedDB/桶/深/store",
        ]
        .map(|relative| write_at(&profile, relative));
        let before: Vec<_> = paths
            .iter()
            .map(|path| {
                (
                    snapshot(
                        &profile.root,
                        path,
                        &AtomicBool::new(false),
                        &mut scan_budget(),
                    )
                    .unwrap(),
                    file_stamp(&path.join("000003.log")).unwrap(),
                )
            })
            .collect();
        let report = scan(&profile, &[]);
        assert_eq!(
            report.records.len(),
            12,
            "{browser:?}: {:?}",
            report.skipped
        );
        assert_eq!(report.partial, !cfg!(windows), "{:?}", report.skipped);
        let mut ids = HashSet::new();
        for record in &report.records {
            assert!(ids.insert(record.id));
            assert!(matches!(record.locator, RecordLocator::LevelDb(_)));
        }
        for (path, (bytes, stamp)) in paths.iter().zip(before) {
            assert_eq!(
                snapshot(
                    &profile.root,
                    path,
                    &AtomicBool::new(false),
                    &mut scan_budget()
                )
                .unwrap(),
                bytes
            );
            assert_eq!(file_stamp(&path.join("000003.log")).unwrap(), stamp);
        }
    }
}

#[test]
fn fallback_only_witnesses_discover_child_profiles_and_keep_optional_absence_empty() {
    let temp = tempfile::tempdir().unwrap();
    for (index, relative) in [
        "databases/extension/store",
        "IndexedDB/chrome-extension_owned/store",
        "IndexedDB/桶/store",
        "WebStorage/桶/store",
    ]
    .iter()
    .enumerate()
    {
        let base = dunce::canonicalize(temp.path())
            .unwrap()
            .join(index.to_string());
        let profile = profile(&base.join("Default"), Browser::Chrome);
        write_at(&profile, relative);
        let mut inventory = ProfileInventory::default();
        profile_discovery::user_data_profiles(Browser::Chrome, &base, &mut inventory);
        assert_eq!(inventory.profiles.len(), 1, "{:?}", inventory.skipped);
        assert!(same_named_path(&inventory.profiles[0].root, &profile.root));
    }
    let profile = profile(&temp.path().join("empty"), Browser::Chrome);
    let report = scan(&profile, &[]);
    assert!(
        report.records.is_empty() && !report.partial,
        "{:?}",
        report.skipped
    );
}

#[test]
fn explicit_lock_scope_is_nonrecursive_and_fallbacks_respect_earlier_file_ownership() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile(temp.path(), Browser::Chrome);
    write_at(&profile, "Local Storage/leveldb/nested");
    write_at(&profile, "outside/store");
    let earlier = write_at(
        &profile,
        "WebStorage/bucket/IndexedDB/https_example.test_0.indexeddb.leveldb",
    );
    let fallback = write_at(&profile, "IndexedDB/chrome-extension_owned.leveldb");
    let inventory = storage_files::discover_paths(
        profile.browser,
        &profile.root,
        &AtomicBool::new(false),
        storage_files::MAX_ENTRIES,
        storage_files::MAX_PATH_BYTES,
    );
    assert_eq!(inventory.leveldb_dirs, vec![fallback]);
    assert!(
        inventory
            .files
            .iter()
            .any(|file| same_named_path(&file.path, &earlier.join("LOCK")))
    );
    assert!(!storage_files::owns_leveldb_lock(
        profile.browser,
        &profile.root,
        &earlier.join("LOCK")
    ));
    let report = scan(&profile, &[]);
    assert_eq!(
        report
            .records
            .iter()
            .filter(|r| matches!(r.locator, RecordLocator::LevelDb(_)))
            .count(),
        3
    );
    assert_eq!(
        report
            .records
            .iter()
            .filter(|r| matches!(r.locator, RecordLocator::File(_)))
            .count(),
        1
    );
    assert!(
        report
            .records
            .iter()
            .filter(|r| matches!(r.locator, RecordLocator::File(_)))
            .all(|r| r.actionable() == cfg!(windows)),
        "{:?}",
        report.skipped
    );
}

#[test]
#[cfg(windows)]
fn native_case_variants_of_declared_store_filenames_keep_one_key_owner() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile(temp.path(), Browser::Chrome);
    let path = write_at(&profile, "IndexedDB/extension/bucket/store");
    for (from, to) in [
        ("LOCK", "lock"),
        ("CURRENT", "current"),
        ("MANIFEST-000001", "manifest-000001"),
    ] {
        fs::rename(path.join(from), path.join(to)).unwrap();
    }
    let report = scan(&profile, &[]);
    assert_eq!(report.records.len(), 3, "{:?}", report.skipped);
    assert!(!report.partial, "{:?}", report.skipped);
    assert!(report.records.iter().all(PrivacyRecord::actionable));
    fs::rename(path.join("000003.log"), path.join("000003.LOG")).unwrap();
    let report = scan(&profile, &[]);
    assert!(
        report.records.is_empty() && !report.partial,
        "{:?}",
        report.skipped
    );
}

#[test]
fn recursive_scope_limits_and_named_metadata_never_create_key_authority() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile(temp.path(), Browser::Chrome);
    let store = write_at(&profile, "IndexedDB/extension/bucket/store");
    fs::write(store.join("Databases.db"), b"owned invalid metadata").unwrap();
    fs::create_dir_all(profile.root.join("WebStorage/LOCK")).unwrap();
    let inspect = |entries, bytes, stopped| {
        storage_files::discover_paths(
            profile.browser,
            &profile.root,
            &AtomicBool::new(stopped),
            entries,
            bytes,
        )
    };
    let inventory = inspect(
        storage_files::MAX_ENTRIES,
        storage_files::MAX_PATH_BYTES,
        false,
    );
    assert_eq!(inventory.leveldb_dirs, vec![store]);
    assert_eq!(inventory.databases.len(), 1);
    assert!(inventory.files.is_empty());
    assert!(inspect(1, storage_files::MAX_PATH_BYTES, false).truncated);
    assert!(inspect(storage_files::MAX_ENTRIES, 1, false).truncated);
    let cancelled = inspect(
        storage_files::MAX_ENTRIES,
        storage_files::MAX_PATH_BYTES,
        true,
    );
    assert!(cancelled.cancelled && cancelled.leveldb_dirs.is_empty());
    let deep = format!(
        "IndexedDB/{}/store",
        std::iter::repeat_n("deep", 18)
            .collect::<Vec<_>>()
            .join("/")
    );
    write_at(&profile, &deep);
    let limited = inspect(
        storage_files::MAX_ENTRIES,
        storage_files::MAX_PATH_BYTES,
        false,
    );
    assert!(limited.truncated);
    assert_eq!(limited.leveldb_dirs.len(), 1);
}

#[test]
#[cfg(windows)]
fn recursive_scope_junction_and_hardlinked_inputs_are_partial_without_following() {
    use std::os::windows::process::CommandExt;
    let temp = tempfile::tempdir().unwrap();
    let profile = profile(&temp.path().join("profile"), Browser::Chrome);
    let external = profile.root.parent().unwrap().join("owned-outside");
    let other = BrowserProfile {
        root: external,
        ..profile.clone()
    };
    let outside = write_at(&other, "store");
    let before = fs::read(outside.join("000003.log")).unwrap();
    fs::create_dir_all(profile.root.join("WebStorage")).unwrap();
    let link = profile
        .root
        .join("WebStorage/linked")
        .components()
        .collect::<PathBuf>();
    let result = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&other.root)
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    assert!(result.status.success(), "{:?}", result.stderr);
    let report = scan(&profile, &[]);
    assert!(report.partial && report.records.is_empty());
    fs::remove_dir(&link).unwrap();
    assert_eq!(fs::read(outside.join("000003.log")).unwrap(), before);
    let local = write_at(&profile, "IndexedDB/extension/bucket/store");
    fs::hard_link(local.join("CURRENT"), temp.path().join("owned-hardlink")).unwrap();
    let report = scan(&profile, &[]);
    assert!(report.partial && report.records.is_empty());
    assert_eq!(fs::read(outside.join("000003.log")).unwrap(), before);
}
fn scan(profile: &BrowserProfile, keep: &[String]) -> PrivacyReport {
    let settings = CookieExceptionSettings {
        schema: COOKIE_SETTINGS_SCHEMA,
        keep_domains: keep.to_vec(),
        keep_signed_in: false,
    };
    scan_profiles_with_settings(
        std::slice::from_ref(profile),
        &[PrivacyCategory::Cookies],
        &settings,
        &AtomicBool::new(false),
        |_| {},
    )
}

#[test]
fn all_thirteen_families_count_live_keys_read_only_and_bind_reviewed_authority() {
    let temp = tempfile::tempdir().unwrap();
    for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
        let profile = profile(&temp.path().join(browser.cache_category()), browser);
        let path = write(&profile);
        let before = snapshot(
            &profile.root,
            &path,
            &AtomicBool::new(false),
            &mut scan_budget(),
        )
        .unwrap();
        let report = scan(&profile, &[]);
        assert_eq!(
            report.records.len(),
            3,
            "{} {:?}",
            browser.cache_category(),
            report.skipped
        );
        assert_eq!(
            report
                .records
                .iter()
                .map(PrivacyRecord::item_count)
                .sum::<usize>(),
            3
        );
        assert_eq!(report.partial, !cfg!(windows));
        assert!(
            report
                .records
                .iter()
                .all(|r| r.actionable() == cfg!(windows) && r.size_bytes().is_none())
        );
        assert!(
            report
                .records
                .iter()
                .all(|r| !r.site.contains("private") && !r.site.contains("first"))
        );
        let ids: Vec<_> = report.records.iter().map(|r| r.id).collect();
        assert_eq!(build_cleanup_plan(&report, &ids).is_ok(), cfg!(windows));
        assert_eq!(
            snapshot(
                &profile.root,
                &path,
                &AtomicBool::new(false),
                &mut scan_budget()
            )
            .unwrap(),
            before
        );
        assert_eq!(fs::read_dir(path).unwrap().count(), 4);
    }
}
#[test]
fn site_transform_matches_retained_native_edge_cases() {
    let cases: &[(&[u8], &str)] = &[
        (b"_https://example.com\0\x01session", "example.com"),
        (b"META:https://example.com", "example.com"),
        (b"VERSION", ""),
        (b"\0https://example.com", ""),
        (b"_http_example.com_0\0a", "example.com"),
        (b"_http_example_0junk_0\0b", "example"),
        (b"_https://example.com/path_0x", ""),
        (b"someprefixhttps://one.test/path", "one.test"),
        (b"_HTTPS://example.com", ""),
        (
            b"_https://user@one.test:443?x#frag\0x",
            "user@one.test:443?x#frag",
        ),
        (b"_0_http_example.com", "example.com"),
        (b"http://", ""),
        ("_https://例子.test\0x".as_bytes(), "例子.test"),
    ];
    for (input, expected) in cases {
        assert_eq!(site(input).unwrap(), *expected);
    }
    assert!(site(b"https://\xff\0x").is_err());
    assert_eq!(site(b"https://valid.test\0\xff").unwrap(), "valid.test");
}
#[test]
fn keep_list_and_selected_category_apply_without_changing_stores() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile(temp.path(), Browser::Chrome);
    write(&profile);
    let report = scan(&profile, &["keep.test".into()]);
    assert_eq!(report.records.len(), 2);
    assert_eq!(report.cookie_exempted, 1);
    let report = scan_profiles_with_settings(
        &[profile],
        &[PrivacyCategory::History],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(report.records.is_empty());
    assert!(!report.partial);
}
#[test]
fn corrupt_store_is_partial_and_absent_optional_store_is_empty() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile(temp.path(), Browser::Chrome);
    let report = scan(&profile, &[]);
    assert!(report.records.is_empty());
    assert!(!report.partial);
    let path = write(&profile);
    let mut data = fs::read(path.join("000003.log")).unwrap();
    data[0] ^= 1;
    fs::write(path.join("000003.log"), data).unwrap();
    let report = scan(&profile, &[]);
    assert!(report.records.is_empty());
    assert!(report.partial);
    assert!(report.skipped.iter().any(|s| s.reason.contains("checksum")));
}
#[test]
fn snapshot_bounds_and_hardlinks_refuse_without_side_effects() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile(temp.path(), Browser::Chrome);
    let path = write(&profile);
    assert!(snapshot(&profile.root, &path, &AtomicBool::new(false), &mut 1).is_err());
    let outside = temp.path().join("other-current");
    fs::hard_link(path.join("CURRENT"), &outside).unwrap();
    assert!(
        snapshot(
            &profile.root,
            &path,
            &AtomicBool::new(false),
            &mut scan_budget()
        )
        .is_err()
    );
    assert!(outside.exists());
    assert!(path.join("LOCK").exists());
}

#[test]
fn second_observation_detects_same_size_time_content_and_namespace_drift() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile(temp.path(), Browser::Chrome);
    let path = write(&profile);
    let cancelled = AtomicBool::new(false);
    let original = snapshot(&profile.root, &path, &cancelled, &mut scan_budget()).unwrap();
    let original_names = names(&profile.root, &path, &cancelled).unwrap();
    let wal = path.join("000003.log");
    let time = filetime::FileTime::from_last_modification_time(&fs::metadata(&wal).unwrap());
    let mut changed = original["000003.log"].clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    fs::write(&wal, changed).unwrap();
    filetime::set_file_mtime(&wal, time).unwrap();
    assert!(
        verify_snapshot(
            &profile.root,
            &path,
            &cancelled,
            &mut scan_budget(),
            &original_names,
            &original
        )
        .unwrap_err()
        .contains("changed")
    );
    fs::write(&wal, &original["000003.log"]).unwrap();
    fs::write(path.join("000099.log"), []).unwrap();
    assert!(
        verify_snapshot(
            &profile.root,
            &path,
            &cancelled,
            &mut scan_budget(),
            &original_names,
            &original
        )
        .unwrap_err()
        .contains("membership")
    );
}

#[test]
fn leveldb_only_profile_is_discovered_as_its_own_root() {
    let temp = tempfile::tempdir().unwrap();
    let base = dunce::canonicalize(temp.path()).unwrap();
    let profile = profile(&base.join("Default"), Browser::Chrome);
    write(&profile);
    let mut inventory = ProfileInventory::default();
    profile_discovery::user_data_profiles(Browser::Chrome, &base, &mut inventory);
    assert_eq!(inventory.profiles.len(), 1, "{:?}", inventory.skipped);
    assert!(same_named_path(&inventory.profiles[0].root, &profile.root));
}
#[test]
#[cfg(windows)]
fn exclusively_locked_log_stays_partial() {
    use std::os::windows::fs::OpenOptionsExt;
    let temp = tempfile::tempdir().unwrap();
    let profile = profile(temp.path(), Browser::Chrome);
    let path = write(&profile);
    let _locked = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(path.join("000003.log"))
        .unwrap();
    let report = scan(&profile, &[]);
    assert!(report.records.is_empty());
    assert!(report.partial);
}
