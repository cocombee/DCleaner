use super::*;

fn put(root: &Path, relative: &str) -> PathBuf {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"owned metadata witness").unwrap();
    path
}
fn witness(browser: Browser, root: &Path, named: bool) -> Witness {
    discover(
        browser,
        root,
        named,
        &AtomicBool::new(false),
        20_000,
        8 * 1024 * 1024,
    )
}

#[test]
fn wildcard_only_chromium_profiles_discover_review_and_preserve_fresh_sources() {
    let temp = tempfile::tempdir().unwrap();
    for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
        let base = temp.path().join(browser.cache_category());
        let root = base.join("Wildcard only");
        let path = put(&root, "History Index 2026-10.txt");
        let extensionless = put(&root, "History Index without extension");
        let before = file_stamp(&path).unwrap();
        put(&base.join("Other data"), "History metadata.txt");
        // Exact Preferences now witnesses the JSON owner; a backup is unrelated.
        put(&base.join("Other data"), "Preferences.backup");
        // Undeclared lookalikes never witness; exact Login Data is a declared
        // saved-password FileKey and witnesses its own profile.
        put(&base.join("Other data"), "Login Data For Account");
        let mut inventory = ProfileInventory::default();
        profile_discovery::user_data_profiles(browser, &base, &mut inventory);
        assert!(!inventory.partial, "{browser:?}: {:?}", inventory.skipped);
        assert_eq!(inventory.profiles.len(), 1, "{browser:?}");
        assert!(same_named_path(&inventory.profiles[0].root, &root));
        let passwords = base.join("Passwords only");
        put(&passwords, "Login Data");
        let mut with_passwords = ProfileInventory::default();
        profile_discovery::user_data_profiles(browser, &base, &mut with_passwords);
        assert_eq!(with_passwords.profiles.len(), 2, "{browser:?}");
        assert!(
            with_passwords
                .profiles
                .iter()
                .any(|profile| same_named_path(&profile.root, &passwords))
        );
        fs::remove_dir_all(&passwords).unwrap();
        let report = scan_profiles_with_settings(
            &inventory.profiles,
            &[PrivacyCategory::History],
            &Default::default(),
            &AtomicBool::new(false),
            |_| {},
        );
        assert!(!report.partial, "{:?}", report.skipped);
        assert_eq!(report.records.len(), 2);
        assert!(report.records.iter().all(PrivacyRecord::actionable));
        assert_eq!(
            report
                .records
                .iter()
                .filter_map(PrivacyRecord::source_file)
                .collect::<HashSet<_>>(),
            [
                "History Index 2026-10.txt".to_owned(),
                "History Index without extension".to_owned()
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(fs::read(&path).unwrap(), b"owned metadata witness");
        assert_eq!(fs::read(extensionless).unwrap(), b"owned metadata witness");
        assert_eq!(file_stamp(&path).unwrap(), before);
    }
}

#[test]
fn mozilla_local_witnesses_do_not_promote_ancestors_or_unrelated_files() {
    for browser in [Browser::Firefox, Browser::Thunderbird] {
        let temp = tempfile::tempdir().unwrap();
        let container = temp.path();
        let root = container.join("legacy.default");
        let path = put(&root, "downloads.json");
        put(&container.join("Other"), "user-download.pdf");
        let result = witness(browser, container, false);
        assert!(!result.found && !result.truncated && result.issues.is_empty());
        let mut inventory = ProfileInventory::default();
        profile_discovery::user_data_profiles(browser, container, &mut inventory);
        assert!(!inventory.partial, "{:?}", inventory.skipped);
        assert_eq!(inventory.profiles.len(), 1);
        assert!(same_named_path(&inventory.profiles[0].root, &root));
        let report = scan_profiles_with_settings(
            &inventory.profiles,
            &[PrivacyCategory::Downloads],
            &Default::default(),
            &AtomicBool::new(false),
            |_| {},
        );
        assert!(!report.partial, "{:?}", report.skipped);
        assert_eq!(report.records.len(), 1);
        assert!(report.records[0].actionable());
        assert_eq!(fs::read(path).unwrap(), b"owned metadata witness");
        put(container, "history.dat");
        assert!(witness(browser, container, false).found);
    }
}

#[test]
fn named_thumbnail_and_opera_vps_scopes_can_witness_profiles_without_databases() {
    for (browser, relative) in [
        (Browser::Firefox, "thumbnails/deep/owned.png"),
        (Browser::Thunderbird, "thumbnails/deep/owned.png"),
        (Browser::Opera, "vps/deep/owned.tmp"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        let root = base.join("Owned Profile");
        let path = put(&root, relative);
        assert!(!witness(browser, &root, false).found);
        let observed = witness(browser, &root, true);
        assert!(observed.found && observed.issues.is_empty());
        let mut inventory = ProfileInventory::default();
        profile_discovery::user_data_profiles(browser, base, &mut inventory);
        assert!(!inventory.partial, "{:?}", inventory.skipped);
        assert_eq!(inventory.profiles.len(), 1);
        assert!(same_named_path(&inventory.profiles[0].root, &root));
        assert_eq!(fs::read(path).unwrap(), b"owned metadata witness");
    }
}

#[test]
fn witness_limits_cancellation_and_depth_remain_explicit_without_content_reads() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let path = put(root, "History Index owned.txt");
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
        let result =
            discover_with_limits(Browser::Chrome, root, true, &AtomicBool::new(false), limits);
        assert!(!result.found && result.truncated && !result.issues.is_empty());
    }
    let cancelled = discover(
        Browser::Chrome,
        root,
        true,
        &AtomicBool::new(true),
        100,
        10_000,
    );
    assert!(cancelled.cancelled && !cancelled.found && cancelled.entries == 0);
    fs::remove_file(&path).unwrap();
    let deep = put(root, "thumbnails/too-deep/owned.png");
    let result = discover_with_limits(
        Browser::Firefox,
        root,
        true,
        &AtomicBool::new(false),
        Limits {
            entries: 100,
            path_bytes: 100_000,
            depth: 0,
        },
    );
    assert!(!result.found && result.truncated);
    assert_eq!(fs::read(deep).unwrap(), b"owned metadata witness");
}

#[test]
#[cfg(windows)]
fn named_witness_junctions_are_not_followed_and_unrelated_root_links_are_ignored() {
    use std::os::windows::process::CommandExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("profile");
    let outside = temp.path().join("outside");
    fs::create_dir_all(&root).unwrap();
    let original = put(&outside, "owned.png");
    for name in ["thumbnails", "Unrelated"] {
        let link = root.join(name);
        let result = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let found = witness(Browser::Firefox, &root, true);
        assert!(!found.found);
        assert_eq!(!found.issues.is_empty(), name == "thumbnails");
        assert_eq!(fs::read(&original).unwrap(), b"owned metadata witness");
        fs::remove_dir(link).unwrap();
    }
}

#[test]
#[cfg(windows)]
fn discovery_uses_metadata_without_opening_locked_witness_contents() {
    use std::os::windows::fs::OpenOptionsExt;
    let temp = tempfile::tempdir().unwrap();
    let path = put(temp.path(), "History Index owned.txt");
    let file = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(path)
        .unwrap();
    let result = witness(Browser::Chrome, temp.path(), true);
    assert!(result.found && result.issues.is_empty());
    drop(file);
}
