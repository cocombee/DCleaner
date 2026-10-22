use super::*;
use crate::{cleanup::TrashPort, store::JournalEvent};
#[path = "session_mozilla_files_tests.rs"]
mod mozilla;
fn image(pinned: bool) -> Vec<u8> {
    let mut b = b"SNSS\x01\x00\x00\x00".to_vec();
    let commands = if pinned {
        vec![
            (12, vec![11, 0, 0, 0, 1, 0, 0, 0]),
            (7, vec![11, 0, 0, 0, 3, 0, 0, 0]),
            (6, vec![8, 0, 0, 0, 11, 0, 0, 0, 3, 0, 0, 0]),
            (255, b"owned private payload".to_vec()),
        ]
    } else {
        vec![(255, b"owned private payload".to_vec())]
    };
    for (kind, payload) in commands {
        b.extend_from_slice(&((payload.len() + 1) as u16).to_le_bytes());
        b.push(kind);
        b.extend_from_slice(&payload);
    }
    b
}
fn profile(root: &Path, browser: Browser) -> BrowserProfile {
    fs::create_dir_all(root).unwrap();
    BrowserProfile {
        browser,
        id: Uuid::new_v4().to_string(),
        name: "Owned session fixture".into(),
        root: dunce::canonicalize(root).unwrap(),
    }
}
fn write(p: &BrowserProfile, name: &str, bytes: &[u8]) -> PathBuf {
    let path = p.root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    path
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
                    .map(|s| serde_json::from_str::<JournalEvent>(s).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert!(
            events
                .iter()
                .any(|e| matches!(e,JournalEvent::Intent{path:p,..} if p==path))
        );
        fs::create_dir_all(&self.destination).unwrap();
        fs::rename(path, self.destination.join(self.moved.len().to_string()))
            .map_err(|e| e.to_string())?;
        self.moved.push(path.to_owned());
        Ok(())
    }
}
fn run(data: &Path, plan: &PrivacyPlan, trash: &mut impl TrashPort) -> PrivacyReceipt {
    clean_privacy_with_runtime_and_trash(
        data,
        plan,
        &AtomicBool::new(false),
        &Closed,
        trash,
        &mut |_, _| {},
    )
    .unwrap()
}

#[test]
fn all_thirteen_recent_session_only_profiles_discover_and_scan_both_routes_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let mut units = 0;
    for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
        let base = temp.path().join(browser.cache_category());
        let p = profile(&base.join("Owned"), browser);
        let names = [
            ("Current Session", image(false)),
            ("Sessions/Tabs_101", image(true)),
            ("Sessions/Session_101", image(true)),
            ("Session Storage/Session_102", image(true)),
        ];
        let paths = names
            .iter()
            .map(|(n, b)| write(&p, n, b))
            .collect::<Vec<_>>();
        let stamps = paths
            .iter()
            .map(|p| file_stamp(p).unwrap())
            .collect::<Vec<_>>();
        write(&p, "Last Session", b"ignored malformed");
        write(&p, "Sessions/Last Session", b"ignored malformed");
        let mut inventory = ProfileInventory::default();
        profile_discovery::user_data_profiles(browser, &base, &mut inventory);
        assert!(!inventory.partial, "{browser:?}: {:?}", inventory.skipped);
        assert_eq!(inventory.profiles.len(), 1);
        let report = scan(&inventory.profiles[0]);
        assert!(!report.partial, "{browser:?}: {:?}", report.skipped);
        assert_eq!(report.records.len(), 4);
        assert_eq!(
            report
                .records
                .iter()
                .filter(|r| matches!(r.locator, RecordLocator::File(_)))
                .count(),
            1
        );
        assert_eq!(
            report
                .records
                .iter()
                .filter(|r| matches!(r.locator, RecordLocator::Preferences(_)))
                .count(),
            3
        );
        assert!(report.records.iter().all(|r| r.actionable()
            && r.native_item_count().is_none()
            && r.source_file().is_some()
            && !r.site.contains("private")));
        for (i, path) in paths.iter().enumerate() {
            assert_eq!(file_stamp(path).unwrap(), stamps[i]);
            assert_eq!(fs::read(path).unwrap(), names[i].1);
        }
        units += report.records.len();
    }
    assert_eq!(units, 52);
}

#[test]
#[cfg(windows)]
fn all_owned_windows_path_cases_match_native_filekeys_and_complete_descriptor_order() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/chromium-session-paths.json"
    ))
    .unwrap();
    let mut count = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let rule = catalogue::RULES
            .iter()
            .find(|r| r.id == case["rule"].as_str().unwrap())
            .unwrap();
        let prefix = match case["layout"].as_str().unwrap() {
            "normal" => r"C:\Owned\Ordinary",
            "session-storage-ancestor" => r"C:\Owned\Session Storage",
            _ => r"C:\Owned\Extension State",
        };
        let root = Path::new(prefix).join(rule.id).join("Default");
        let path = root.join(case["relative"].as_str().unwrap());
        let actual = binding(rule.browser, &root, &path);
        let expected = if case["status"] == "ChromiumSessionFile" {
            Some((rule.id, case["owner"]["key"].as_str().unwrap()))
        } else {
            None
        };
        assert_eq!(
            actual, expected,
            "{} {} {}",
            case["rule"], case["layout"], case["relative"]
        );
        let generic = generic_binding(rule.browser, &root, &path);
        let wanted = if case["status"] == "PathDelete" || case["status"] == "FileDelete" {
            Some((
                rule.id,
                case["owner"]["key"].as_str().unwrap(),
                case["status"] == "PathDelete",
            ))
        } else {
            None
        };
        assert_eq!(
            generic, wanted,
            "{} {} {}",
            case["rule"], case["layout"], case["relative"]
        );
        count += 1;
    }
    assert_eq!(count, 1404);
}

#[test]
fn session_categories_are_opt_in_and_unselected_invalid_preferences_are_not_read() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(temp.path(), Browser::Chrome);
    write(&p, "Current Session", &image(false));
    write(&p, "Preferences", b"invalid JSON");
    assert!(!PrivacyCategory::DEFAULT.contains(&PrivacyCategory::Sessions));
    let report = scan(&p);
    assert!(!report.partial);
    assert_eq!(report.records.len(), 1);
    let report = scan_profiles_with_settings(
        &[p],
        &[],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(report.records.is_empty() && !report.partial);
}

#[test]
#[cfg(windows)]
fn exact_file_fallback_and_pinned_rewrite_share_review_but_keep_distinct_effects_and_restore() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let fallback = write(&p, "Current Session", &image(false));
    let pinned = write(&p, "Sessions/Session_1", &image(true));
    let kept = write(&p, "Sessions/Tabs_2", &image(true));
    let report = scan(&p);
    assert!(!report.partial);
    let selected = report
        .records
        .iter()
        .filter(|r| r.source_file().is_some_and(|n| !n.contains("Tabs_2")))
        .map(|r| r.id)
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), 2);
    assert!(build_cleanup_plan(&report, &[Uuid::new_v4()]).is_err());
    let data = temp.path().join("data");
    let mut trash = OwnedTrash {
        data: data.clone(),
        destination: temp.path().join("trash"),
        moved: vec![],
    };
    let receipt = run(
        &data,
        &build_cleanup_plan(&report, &selected).unwrap(),
        &mut trash,
    );
    assert_eq!(
        (receipt.deleted, receipt.skipped, receipt.uncertain),
        (2, 0, false),
        "{:?}",
        receipt.errors
    );
    assert_eq!(trash.moved, vec![fallback.clone()]);
    assert!(!fallback.exists());
    assert_ne!(fs::read(&pinned).unwrap(), image(true));
    assert_eq!(fs::read(&kept).unwrap(), image(true));
    let options = list_privacy_restore_options(&data).unwrap();
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].categories, vec![PrivacyCategory::Sessions]);
    let restore = prepare_privacy_restore_with_runtime(&data, options[0].id, &Closed).unwrap();
    assert!(restore.restores_sessions() && !restore.restores_preferences());
    let receipt = restore_privacy_database_with_runtime(&data, &restore, &Closed).unwrap();
    assert!(receipt.restored && !receipt.uncertain);
    assert_eq!(fs::read(pinned).unwrap(), image(true));
    assert!(!fallback.exists());
}

#[test]
#[cfg(windows)]
fn same_stamp_pin_drift_refuses_old_trash_classification_before_any_move() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let mut original = image(true);
    original[15] = 0;
    let path = write(&p, "Current Session", &original);
    let report = scan(&p);
    assert!(matches!(report.records[0].locator, RecordLocator::File(_)));
    let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let stamp = file_stamp(&path).unwrap();
    let mut changed = original.clone();
    changed[15] = 1;
    fs::write(&path, &changed).unwrap();
    filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(modified)).unwrap();
    assert_eq!(file_stamp(&path).unwrap(), stamp);
    let data = temp.path().join("data");
    let mut trash = OwnedTrash {
        data: data.clone(),
        destination: temp.path().join("trash"),
        moved: vec![],
    };
    let receipt = run(&data, &plan, &mut trash);
    assert_eq!(receipt.deleted, 0);
    assert!(trash.moved.is_empty());
    assert_eq!(fs::read(path).unwrap(), changed);
}

#[test]
fn malformed_limits_and_cancellation_never_create_a_generic_delete_record() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(temp.path(), Browser::Chrome);
    write(&p, "Current Session", b"not SNSS");
    let report = scan(&p);
    assert!(report.partial && report.records.is_empty());
    let inventory = discover(
        p.browser,
        &p.root,
        true,
        &AtomicBool::new(true),
        100,
        10000,
        false,
    );
    assert!(inventory.cancelled && inventory.files.is_empty());
    let inventory = discover(
        p.browser,
        &p.root,
        true,
        &AtomicBool::new(false),
        0,
        10000,
        false,
    );
    assert!(inventory.truncated && inventory.files.is_empty());
    let mut report = scan_profiles_with_settings(
        &[],
        &[PrivacyCategory::Sessions],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    );
    let mut bytes = 0;
    let mut files = 10;
    super::scan(
        &p,
        &AtomicBool::new(false),
        &mut bytes,
        &mut files,
        &mut HashSet::new(),
        &mut report,
    );
    assert!(report.truncated && report.records.is_empty());
}

#[test]
#[cfg(windows)]
fn metadata_witness_does_not_open_locked_contents_and_named_container_scopes_stay_separate() {
    use std::os::windows::fs::OpenOptionsExt;
    let temp = tempfile::tempdir().unwrap();
    let p = profile(temp.path(), Browser::Chrome);
    let path = write(&p, "Sessions/Session_1", &image(true));
    let _held = OpenOptions::new()
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
    assert!(witness.issues.is_empty());
    let container = discover(
        p.browser,
        &p.root,
        false,
        &AtomicBool::new(false),
        100,
        10000,
        true,
    );
    assert!(container.files.is_empty());
}

#[test]
#[cfg(windows)]
fn hardlinked_session_payloads_are_unavailable_and_never_become_file_fallbacks() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let path = write(&p, "Current Session", &image(false));
    let alias = temp.path().join("alias");
    fs::hard_link(&path, &alias).unwrap();
    let report = scan(&p);
    assert!(report.partial && report.records.is_empty());
    assert_eq!(fs::read(alias).unwrap(), image(false));
}

#[test]
#[cfg(windows)]
fn running_browser_refuses_both_effect_routes_without_any_mutation() {
    struct Running;
    impl BrowserRuntime for Running {
        fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
            Ok(vec![RunningBrowser {
                browser: Browser::Chrome,
                pid: 1234,
                executable: "chrome.exe".into(),
            }])
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let p = profile(temp.path(), Browser::Chrome);
    let a = write(&p, "Current Session", &image(false));
    let b = write(&p, "Sessions/Session_1", &image(true));
    let report = scan(&p);
    let ids = report.records.iter().map(|r| r.id).collect::<Vec<_>>();
    let plan = build_cleanup_plan(&report, &ids).unwrap();
    let data = temp.path().join("data");
    let mut trash = OwnedTrash {
        data: data.clone(),
        destination: temp.path().join("trash"),
        moved: vec![],
    };
    assert!(
        clean_privacy_with_runtime_and_trash(
            &data,
            &plan,
            &AtomicBool::new(false),
            &Running,
            &mut trash,
            &mut |_, _| {}
        )
        .is_err()
    );
    assert!(trash.moved.is_empty());
    assert_eq!(fs::read(a).unwrap(), image(false));
    assert_eq!(fs::read(b).unwrap(), image(true));
}

#[test]
#[cfg(windows)]
fn redirected_session_directory_is_not_followed_or_adopted_as_a_witness() {
    use std::os::windows::process::CommandExt;
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let outside = temp.path().join("owned-outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("Session_1"), image(true)).unwrap();
    let link = p.root.join("Sessions");
    let output = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&outside)
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let report = scan(&p);
    assert!(report.partial && report.records.is_empty());
    let witness = discover(
        p.browser,
        &p.root,
        true,
        &AtomicBool::new(false),
        100,
        10000,
        true,
    );
    assert!(witness.files.is_empty() && !witness.issues.is_empty());
    fs::remove_dir(link).unwrap();
    assert_eq!(fs::read(outside.join("Session_1")).unwrap(), image(true));
}

#[test]
fn mozilla_session_scan_does_not_adopt_chromium_file_names() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(temp.path(), Browser::Firefox);
    write(&p, "Current Session", &image(false));
    let report = scan(&p);
    assert!(!report.partial && report.records.is_empty());
}

#[test]
fn all_families_discover_generic_session_state_files_with_complete_directory_groups() {
    let temp = tempfile::tempdir().unwrap();
    let mut files = 0;
    let mut groups = 0;
    for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
        let base = temp.path().join(browser.cache_category());
        let p = profile(&base.join("Owned"), browser);
        for name in [
            "Session Storage/LOG",
            "Session Storage/CURRENT",
            "Extension State/LOG",
        ] {
            write(&p, name, b"owned raw session state");
        }
        if browser == Browser::Opera {
            write(&p, "session.db", b"owned legacy state");
            write(&p, "session.dbak", b"owned legacy backup");
        }
        let mut inventory = ProfileInventory::default();
        profile_discovery::user_data_profiles(browser, &base, &mut inventory);
        assert!(!inventory.partial);
        assert_eq!(inventory.profiles.len(), 1);
        let report = scan(&p);
        assert!(!report.partial, "{browser:?}: {:?}", report.skipped);
        assert!(report.records.iter().all(PrivacyRecord::actionable));
        assert!(
            report
                .records
                .iter()
                .any(|r| r.source_file().as_deref() == Some("Session Storage/")
                    && r.item_count() == 2)
        );
        files += report
            .records
            .iter()
            .map(PrivacyRecord::item_count)
            .sum::<usize>();
        groups += report.records.len();
    }
    assert_eq!((files, groups), (41, 28));
}

#[test]
#[cfg(windows)]
fn generic_directory_group_moves_only_reviewed_complete_members_after_durable_intents() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let a = write(&p, "Session Storage/LOG", b"a");
    let b = write(&p, "Session Storage/CURRENT", b"b");
    let keep = write(&p, "Extension State/LOG", b"keep");
    let report = scan(&p);
    let group = report
        .records
        .iter()
        .find(|r| r.source_file().as_deref() == Some("Session Storage/"))
        .unwrap();
    assert_eq!(group.item_count(), 2);
    let data = temp.path().join("data");
    let mut trash = OwnedTrash {
        data: data.clone(),
        destination: temp.path().join("trash"),
        moved: vec![],
    };
    let receipt = run(
        &data,
        &build_cleanup_plan(&report, &[group.id]).unwrap(),
        &mut trash,
    );
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (1, 0),
        "{:?}",
        receipt.errors
    );
    assert_eq!(trash.moved.len(), 2);
    assert!(!a.exists() && !b.exists());
    assert!(p.root.join("Session Storage").is_dir());
    assert_eq!(fs::read(keep).unwrap(), b"keep");
}

#[test]
#[cfg(windows)]
fn new_or_separately_owned_directory_members_refuse_partial_group_authority() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    write(&p, "Session Storage/LOG", b"owned");
    let report = scan(&p);
    let group = report.records[0].id;
    write(&p, "Session Storage/CURRENT", b"new");
    let data = temp.path().join("data");
    let mut trash = OwnedTrash {
        data: data.clone(),
        destination: temp.path().join("trash"),
        moved: vec![],
    };
    let receipt = run(
        &data,
        &build_cleanup_plan(&report, &[group]).unwrap(),
        &mut trash,
    );
    assert_eq!(receipt.deleted, 0);
    assert!(trash.moved.is_empty());
    write(&p, "Session Storage/Session_1", &image(true));
    let current = scan(&p);
    assert!(current.partial);
    let group = current
        .records
        .iter()
        .find(|r| r.source_file().as_deref() == Some("Session Storage/"))
        .unwrap();
    assert!(!group.actionable());
    assert!(
        current
            .records
            .iter()
            .any(|r| matches!(r.locator, RecordLocator::Preferences(_)) && r.actionable())
    );
}

#[test]
#[cfg(windows)]
fn generic_opera_legacy_files_are_not_reinterpreted_as_pinned_binary_rewrites() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Opera);
    let path = write(&p, "session.db", &image(true));
    let report = scan(&p);
    assert_eq!(report.records.len(), 1);
    assert!(matches!(report.records[0].locator, RecordLocator::File(_)));
    assert!(!claims(p.browser, &p.root, &path));
    let data = temp.path().join("data");
    let mut trash = OwnedTrash {
        data: data.clone(),
        destination: temp.path().join("trash"),
        moved: vec![],
    };
    assert_eq!(
        run(
            &data,
            &build_cleanup_plan(&report, &[report.records[0].id]).unwrap(),
            &mut trash
        )
        .deleted,
        1
    );
    assert_eq!(trash.moved, vec![path]);
}

#[test]
#[cfg(windows)]
fn missing_uncertain_member_still_blocks_new_cleanup_of_its_remaining_directory_group() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let a = write(&p, "Session Storage/LOG", b"moved with missing receipt");
    let b = write(&p, "Session Storage/CURRENT", b"remaining");
    let data = temp.path().join("data");
    let root = data.join("operations");
    fs::create_dir_all(&root).unwrap();
    let id = Uuid::new_v4();
    let events = [
        JournalEvent::Start {
            id,
            date: "owned".into(),
        },
        JournalEvent::Intent {
            file_id: Uuid::new_v4(),
            path: a.clone(),
            size: 26,
        },
    ];
    let text = events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap() + "\n")
        .collect::<String>();
    fs::write(root.join(format!("{id}.jsonl")), text).unwrap();
    fs::rename(&a, temp.path().join("owned-moved")).unwrap();
    let report = scan(&p);
    assert_eq!(report.records.len(), 1);
    assert!(report.records[0].actionable());
    let mut trash = OwnedTrash {
        data: data.clone(),
        destination: temp.path().join("trash"),
        moved: vec![],
    };
    let receipt = run(
        &data,
        &build_cleanup_plan(&report, &[report.records[0].id]).unwrap(),
        &mut trash,
    );
    assert_eq!(receipt.deleted, 0);
    assert!(trash.moved.is_empty());
    assert_eq!(fs::read(b).unwrap(), b"remaining");
}
