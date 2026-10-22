use super::*;

fn environments(root: &Path) -> HashMap<String, PathBuf> {
    ["localappdata", "appdata", "programfiles"]
        .into_iter()
        .map(|name| {
            let path = root.join(name);
            fs::create_dir_all(&path).unwrap();
            (name.to_owned(), path)
        })
        .collect()
}
fn put(root: &Path, path: &str) -> PathBuf {
    let directory = root.join(path);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("History"), b"fixture metadata only").unwrap();
    directory
}
fn discover(env: &HashMap<String, PathBuf>) -> ProfileInventory {
    reference_profiles(|name| env.get(name).cloned())
}

#[test]
fn extension_cookie_only_profiles_are_discovered_without_history_or_network_stores() {
    let dir = tempfile::tempdir().unwrap();
    let env = environments(dir.path());
    let root = env["localappdata"].join("Google/Chrome/User Data/Extension Only");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("Extension Cookies"), b"owned metadata witness").unwrap();
    let report = discover(&env);
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.profiles[0].browser, Browser::Chrome);
    assert!(same_named_path(&report.profiles[0].root, &root));
}

#[test]
fn quota_only_profiles_are_discovered_without_history_or_cookie_stores() {
    let dir = tempfile::tempdir().unwrap();
    let env = environments(dir.path());
    let root = env["localappdata"].join("Google/Chrome/User Data/Quota Only");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("QuotaManager"), b"owned quota metadata witness").unwrap();
    let report = discover(&env);
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!(report.profiles.len(), 1);
    assert!(same_named_path(&report.profiles[0].root, &root));
}

#[test]
fn certificate_and_permission_only_profiles_are_discovered_from_declared_family_roots() {
    let dir = tempfile::tempdir().unwrap();
    let env = environments(dir.path());
    let chrome = env["localappdata"].join("Google/Chrome/User Data/Certificate Only");
    let firefox = env["appdata"].join("Mozilla/Firefox/Profiles/Permissions Only");
    for (root, file) in [
        (&chrome, "Origin Bound Certs"),
        (&firefox, "permissions.sqlite"),
    ] {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join(file), b"owned metadata witness").unwrap();
    }
    let report = discover(&env);
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!(report.profiles.len(), 2);
    assert!(
        report
            .profiles
            .iter()
            .any(|p| p.browser == Browser::Chrome && same_named_path(&p.root, &chrome))
    );
    assert!(
        report
            .profiles
            .iter()
            .any(|p| p.browser == Browser::Firefox && same_named_path(&p.root, &firefox))
    );
}

#[test]
fn webapps_and_nested_websql_only_profiles_use_declared_family_roots() {
    let dir = tempfile::tempdir().unwrap();
    let env = environments(dir.path());
    let fixtures = [
        (
            Browser::Chrome,
            env["localappdata"].join("Google/Chrome/User Data/WebSQL Only"),
            "databases/archive/Databases.db",
        ),
        (
            Browser::Firefox,
            env["appdata"].join("Mozilla/Firefox/Profiles/WebApps Only"),
            "webappsstore.sqlite",
        ),
        (
            Browser::Thunderbird,
            env["appdata"].join("Thunderbird/Profiles/WebApps Only"),
            "webappsstore.sqlite",
        ),
    ];
    for (_, root, file) in &fixtures {
        let path = root.join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"owned metadata witness").unwrap();
    }
    let report = discover(&env);
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!(report.profiles.len(), fixtures.len());
    for (browser, root, _) in fixtures {
        assert!(
            report
                .profiles
                .iter()
                .any(|profile| profile.browser == browser && same_named_path(&profile.root, &root))
        );
    }
}

#[test]
fn every_declared_profile_pattern_reaches_file_only_witnesses_without_adopting_containers() {
    let dir = tempfile::tempdir().unwrap();
    let env = environments(dir.path());
    let mut expected = HashSet::new();
    for rule in catalogue::REFERENCE_PROFILES {
        let relative = rule
            .relative
            .split('/')
            .map(|p| p.replace('*', "FileOnly").replace('?', "Q"))
            .collect::<Vec<_>>()
            .join("/");
        let root = env[rule.environment].join(relative);
        let root = if rule.recursive {
            root.join("legacy.default")
        } else {
            root
        };
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join(if rule.browser.is_chromium() {
                "History Index 2026.txt"
            } else {
                "history.dat"
            }),
            b"owned file-only witness",
        )
        .unwrap();
        expected.insert((
            rule.browser,
            path_identity(&dunce::canonicalize(root).unwrap()),
        ));
    }
    let report = discover(&env);
    assert!(!report.partial, "{:?}", report.skipped);
    let actual = report
        .profiles
        .iter()
        .map(|p| (p.browser, path_identity(&p.root)))
        .collect::<HashSet<_>>();
    assert_eq!(actual, expected);
    assert_eq!(report.profiles.len(), actual.len());
    assert_eq!(
        actual.iter().map(|(b, _)| *b).collect::<HashSet<_>>().len(),
        15
    );
}

#[test]
fn thumbnail_only_mozilla_profiles_respect_the_native_container_child_scope() {
    let dir = tempfile::tempdir().unwrap();
    let env = environments(dir.path());
    let mut expected = HashSet::new();
    for (browser, base) in [
        (Browser::Firefox, "Mozilla/Firefox/Profiles"),
        (Browser::Thunderbird, "Thunderbird/Profiles"),
    ] {
        let container = env["appdata"].join(base);
        for relative in [
            "thumbnails/root-only.png",
            "owned.default/thumbnails/deep/owned.png",
        ] {
            let path = container.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"owned thumbnail").unwrap();
        }
        expected.insert((
            browser,
            path_identity(&dunce::canonicalize(container.join("owned.default")).unwrap()),
        ));
    }
    let report = discover(&env);
    assert!(!report.partial, "{:?}", report.skipped);
    let actual = report
        .profiles
        .iter()
        .map(|p| (p.browser, path_identity(&p.root)))
        .collect::<HashSet<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn every_declared_profile_pattern_reaches_an_owned_database_witness() {
    let dir = tempfile::tempdir().unwrap();
    let env = environments(dir.path());
    let mut expected = HashSet::new();
    for rule in catalogue::REFERENCE_PROFILES {
        let relative = rule
            .relative
            .split('/')
            .map(|p| p.replace('*', "Fixture").replace('?', "Q"))
            .collect::<Vec<_>>()
            .join("/");
        let path = env[rule.environment].join(relative);
        let path = if rule.recursive {
            path.join("profile.default")
        } else {
            path
        };
        fs::create_dir_all(&path).unwrap();
        fs::write(
            path.join(if rule.browser.is_chromium() {
                "History"
            } else {
                "places.sqlite"
            }),
            b"fixture metadata only",
        )
        .unwrap();
        expected.insert((
            rule.browser,
            path_identity(&dunce::canonicalize(&path).unwrap()),
        ));
    }
    let report = discover(&env);
    assert!(!report.partial, "{:?}", report.skipped);
    let actual = report
        .profiles
        .iter()
        .map(|p| (p.browser, path_identity(&p.root)))
        .collect::<HashSet<_>>();
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), report.profiles.len());
    assert_eq!(
        report
            .profiles
            .iter()
            .map(|p| p.browser)
            .collect::<HashSet<_>>()
            .len(),
        15
    );
}
#[test]
fn channel_package_direct_and_non_numeric_profiles_follow_the_declared_scope() {
    let dir = tempfile::tempdir().unwrap();
    let env = environments(dir.path());
    let local = &env["localappdata"];
    let custom = put(local, "Google/Chrome/User Data/Work Team");
    let guest = put(local, "Google/Chrome/User Data/Guest Profile");
    let nested = put(local, "Microsoft/Edge Beta/User Data/Container/Default");
    let outside_scope = put(local, "Google/Chrome Beta/User Data/Container/Default");
    let arc = put(
        local,
        "Packages/TheBrowserCompany.Arc_ttt1ap7aakyb4/LocalCache/Local/Arc/User Data/Named Profile",
    );
    let opera = put(&env["appdata"], "Opera Software/Opera Stable");
    let opera_default = put(&env["appdata"], "Opera Software/Opera Stable/Default");
    let avg_unlisted = put(local, "AVG/Browser/User Data/Unlisted");
    fs::create_dir_all(local.join("Google/Chrome/User Data/Crashpad/reports")).unwrap();
    let report = discover(&env);
    assert!(!report.partial, "{:?}", report.skipped);
    let actual = report
        .profiles
        .iter()
        .map(|p| p.root.clone())
        .collect::<HashSet<_>>();
    assert_eq!(
        actual,
        [custom, guest, nested, arc, opera, opera_default]
            .into_iter()
            .collect()
    );
    assert!(!actual.contains(&outside_scope));
    assert!(!actual.contains(&avg_unlisted));
}
#[test]
fn overlapping_patterns_deduplicate_and_local_state_supplies_only_friendly_names() {
    let dir = tempfile::tempdir().unwrap();
    let env = environments(dir.path());
    let profile = put(&env["localappdata"], "Google/Chrome/User Data/Default");
    fs::write(profile.parent().unwrap().join("Local State"),br#"{"profile":{"info_cache":{"Default":{"name":"Work"},"Unknown":{"name":"not an authority"}}}}"#).unwrap();
    let report = discover(&env);
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.profiles[0].name, "Work");
    assert_eq!(report.profiles[0].root, profile);
}
#[test]
fn policy_and_macos_user_data_roots_accept_actual_custom_profiles_only() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let profile = put(root, "Named Profile");
    fs::create_dir_all(root.join("Not a profile")).unwrap();
    let mut report = ProfileInventory::default();
    user_data_profiles(Browser::Chrome, root, &mut report);
    user_data_profiles(Browser::Chrome, root, &mut report);
    assert!(!report.partial);
    assert_eq!(report.profiles.len(), 1);
    assert_eq!(report.profiles[0].root, profile);
}
#[test]
fn absent_optional_roots_are_empty_and_unresolved_environments_remain_partial() {
    let dir = tempfile::tempdir().unwrap();
    let env = environments(dir.path());
    let empty = discover(&env);
    assert!(empty.profiles.is_empty());
    assert!(!empty.partial);
    let missing = reference_profiles(|name| {
        if name == "localappdata" {
            None
        } else {
            env.get(name).cloned()
        }
    });
    assert!(missing.partial);
    assert!(
        missing
            .skipped
            .iter()
            .any(|s| s.reason.contains("localappdata"))
    );
}
#[test]
fn profile_and_recursive_depth_limits_are_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let env = environments(dir.path());
    for i in 0..129 {
        put(
            &env["localappdata"],
            &format!("Google/Chrome/User Data/Named {i:03}"),
        );
    }
    let report = discover(&env);
    assert_eq!(report.profiles.len(), 128);
    assert!(report.partial);
    assert!(report.skipped.iter().any(|s| s.reason.contains("limit")));
    let dir = tempfile::tempdir().unwrap();
    let env = environments(dir.path());
    let mut path = env["appdata"].join("Mozilla/Firefox/Profiles");
    for _ in 0..16 {
        path = path.join("nested");
    }
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("places.sqlite"), b"owned").unwrap();
    let allowed = dunce::canonicalize(&path).unwrap();
    path = path.join("too-deep");
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("places.sqlite"), b"owned").unwrap();
    let path = dunce::canonicalize(&path).unwrap();
    let report = discover(&env);
    assert!(report.partial);
    assert!(
        report.profiles.iter().any(|p| p.root == allowed),
        "{:?}",
        report
            .skipped
            .iter()
            .map(|s| s.reason.as_str())
            .collect::<Vec<_>>()
    );
    assert!(!report.profiles.iter().any(|p| p.root == path));
    assert!(report.skipped.iter().any(|s| s.reason.contains("depth")));
}
#[test]
fn family_process_guards_include_reference_aliases_and_shared_opera_images() {
    for (image, expected) in [
        ("AVGBrowser.exe", Browser::Avg),
        ("CCleanerBrowser.exe", Browser::Ccleaner),
        ("AvastBrowser.exe", Browser::Avast),
        ("vivaldi.exe", Browser::Vivaldi),
        ("brave.exe", Browser::Brave),
        ("nortonbrowser.exe", Browser::Norton),
        ("avirabrowser.exe", Browser::Avira),
        ("Arc.exe", Browser::Arc),
        ("Neo.exe", Browser::Neo),
        ("thunderbird.exe", Browser::Thunderbird),
        ("seamonkey.exe", Browser::Firefox),
        ("iron.exe", Browser::Chrome),
    ] {
        assert_eq!(browser_for_executable(image), Some(expected));
        assert!(expected.conflicts_with(&RunningBrowser {
            browser: expected,
            pid: 1,
            executable: image.into()
        }));
    }
    let opera = RunningBrowser {
        browser: Browser::Opera,
        pid: 42,
        executable: "opera.exe".into(),
    };
    assert!(Browser::OperaGx.conflicts_with(&opera));
    assert!(!Browser::Chrome.conflicts_with(&opera));
    assert!(!Browser::Brave.conflicts_with(&opera));
    assert_eq!(browser_for_executable("unrelated.exe"), None);
}
#[test]
fn every_cache_family_has_a_stable_privacy_family_and_legacy_names_deserialize() {
    for (id, _) in crate::browser_cache::LABELS {
        let browser = Browser::from_cache_category(id).unwrap();
        assert_eq!(browser.cache_category(), *id);
    }
    assert_eq!(
        serde_json::from_str::<Browser>("\"chrome\"").unwrap(),
        Browser::Chrome
    );
    assert_eq!(
        serde_json::from_str::<Browser>("\"firefox\"").unwrap(),
        Browser::Firefox
    );
    assert_eq!(Browser::from_cache_category("temp"), None);
}
#[cfg(windows)]
#[test]
fn declared_linked_profiles_roots_and_network_databases_are_not_followed() {
    use std::os::windows::process::CommandExt;
    for kind in ["profile", "root", "network"] {
        let dir = tempfile::tempdir().unwrap();
        let env = environments(dir.path());
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("History"), b"preserve history").unwrap();
        fs::write(outside.join("Cookies"), b"preserve cookies").unwrap();
        let base = env["localappdata"].join("Google/Chrome/User Data");
        let link = match kind {
            "profile" => base.join("Default"),
            "root" => base.clone(),
            _ => base.join("Default/Network"),
        };
        fs::create_dir_all(link.parent().unwrap()).unwrap();
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
        let report = discover(&env);
        assert!(report.partial, "{kind}");
        assert!(report.profiles.is_empty(), "{kind}");
        assert_eq!(
            fs::read(outside.join("History")).unwrap(),
            b"preserve history"
        );
        assert_eq!(
            fs::read(outside.join("Cookies")).unwrap(),
            b"preserve cookies"
        );
        fs::remove_dir(link).unwrap();
    }
}
