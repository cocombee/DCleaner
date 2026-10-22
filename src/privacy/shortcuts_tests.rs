use super::*;

fn corpus() -> serde_json::Value {
    serde_json::from_str(include_str!("../../tests/fixtures/shortcuts-history.json")).unwrap()
}
fn owned_case() -> serde_json::Value {
    corpus()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "UTF-8-nested")
        .unwrap()
        .clone()
}
fn bookmarks(root: &Path, value: &serde_json::Value) {
    fs::create_dir_all(root).unwrap();
    if !value.is_null() {
        fs::write(root.join("Bookmarks"), serde_json::to_vec(value).unwrap()).unwrap();
    }
}
fn fixture(root: &Path, browser: Browser) -> (BrowserProfile, PathBuf) {
    fs::create_dir_all(root).unwrap();
    let profile = BrowserProfile {
        browser,
        id: "owned-shortcuts".into(),
        name: "Owned shortcuts".into(),
        root: dunce::canonicalize(root).unwrap(),
    };
    let case = owned_case();
    let database = profile.root.join("Shortcuts");
    let conn = Connection::open(&database).unwrap();
    conn.execute_batch(case["setup_sql"].as_str().unwrap())
        .unwrap();
    drop(conn);
    bookmarks(&profile.root, &case["bookmarks"]);
    (profile, database)
}
fn scan(profile: &BrowserProfile) -> PrivacyReport {
    scan_profiles_with_settings(
        std::slice::from_ref(profile),
        &[PrivacyCategory::History],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    )
}
fn ids(conn: &Connection) -> Vec<i64> {
    conn.prepare("SELECT rowid FROM omni_box_shortcuts ORDER BY rowid")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}
fn selected(report: &PrivacyReport, row_id: i64) -> Uuid {
    report.records.iter().find(|r| matches!(&r.locator,RecordLocator::Database(row) if row.shortcut.as_ref().is_some_and(|review| review.row_id==row_id)))
        .expect("missing reviewed shortcut").id
}
struct Closed;
impl BrowserRuntime for Closed {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        Ok(vec![])
    }
}
struct NoFiles;
impl crate::cleanup::TrashPort for NoFiles {
    fn move_to_trash(&mut self, _: &Path) -> Result<(), String> {
        panic!("SQL fixture attempted a file move")
    }
}
fn clean(data: &Path, plan: &PrivacyPlan) -> PrivacyReceipt {
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
fn native_text_and_bookmark_matrix_matches_without_source_effects() {
    let temp = tempfile::tempdir().unwrap();
    for (index, case) in corpus()["cases"].as_array().unwrap().iter().enumerate() {
        let root = temp.path().join(index.to_string());
        bookmarks(&root, &case["bookmarks"]);
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(case["setup_sql"].as_str().unwrap())
            .unwrap();
        let before = ids(&conn);
        let current = Snapshot::read(&conn, &root, &AtomicBool::new(false)).unwrap();
        let expected: Vec<i64> = serde_json::from_value(case["expected_row_ids"].clone()).unwrap();
        assert_eq!(
            current.rows.keys().copied().collect::<Vec<_>>(),
            expected,
            "{}",
            case["name"]
        );
        assert_eq!(ids(&conn), before);
        assert!(
            current
                .rows
                .values()
                .all(|r| !r.site.contains("quote'id") && !r.site.contains("/path"))
        );
    }
}

#[test]
fn all_thirteen_shortcut_only_profiles_are_discovered_and_counted_read_only() {
    let temp = tempfile::tempdir().unwrap();
    for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
        let base = temp.path().join(browser.cache_category());
        let (profile, database) = fixture(&base.join("Shortcuts only"), browser);
        let bytes = fs::read(&database).unwrap();
        let stamp = file_stamp(&database).unwrap();
        let marks = fs::read(profile.root.join("Bookmarks")).unwrap();
        let mut inventory = ProfileInventory::default();
        profile_discovery::user_data_profiles(browser, &base, &mut inventory);
        assert!(
            !inventory.partial && inventory.profiles.len() == 1,
            "{browser:?}"
        );
        let report = scan(&inventory.profiles[0]);
        assert!(!report.partial, "{browser:?}: {:?}", report.skipped);
        assert_eq!(report.records.len(), 13, "{browser:?}");
        assert_eq!(
            report
                .records
                .iter()
                .map(PrivacyRecord::item_count)
                .sum::<usize>(),
            13
        );
        assert!(report.records.iter().all(PrivacyRecord::actionable));
        assert_eq!(fs::read(&database).unwrap(), bytes);
        assert_eq!(file_stamp(&database).unwrap(), stamp);
        assert_eq!(fs::read(profile.root.join("Bookmarks")).unwrap(), marks);
    }
}

#[test]
fn reviewed_row_ids_preserve_bookmarked_duplicate_ids_and_unselected_rows_then_restore() {
    let temp = tempfile::tempdir().unwrap();
    let (profile, database) = fixture(&temp.path().join("profile"), Browser::Chrome);
    let report = scan(&profile);
    let plan = build_cleanup_plan(&report, &[selected(&report, 16)]).unwrap();
    let conn = Connection::open(&database).unwrap();
    let before = ids(&conn);
    drop(conn);
    let marks = fs::read(profile.root.join("Bookmarks")).unwrap();
    let data = temp.path().join("data");
    let receipt = clean(&data, &plan);
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (1, 0),
        "{:?}",
        receipt.errors
    );
    assert_eq!(receipt.backups.len(), 1);
    let conn = Connection::open(&database).unwrap();
    assert_eq!(
        ids(&conn),
        before
            .iter()
            .copied()
            .filter(|id| *id != 16)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM omni_box_shortcuts WHERE rowid=15",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT value FROM unrelated", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "preserved"
    );
    drop(conn);
    assert_eq!(fs::read(profile.root.join("Bookmarks")).unwrap(), marks);
    let options = list_privacy_restore_options(&data).unwrap();
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].state, PrivacyRecoveryState::Ready);
    let restore = prepare_privacy_restore_with_runtime(&data, options[0].id, &Closed).unwrap();
    restore_privacy_database_with_runtime(&data, &restore, &Closed).unwrap();
    assert_eq!(ids(&Connection::open(database).unwrap()), before);
}

#[test]
fn wal_only_full_row_drift_blocks_shortcut_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let (profile, database) = fixture(&temp.path().join("profile"), Browser::Chrome);
    let conn = Connection::open(&database).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA wal_checkpoint(TRUNCATE)",
    )
    .unwrap();
    let report = scan(&profile);
    let plan = build_cleanup_plan(&report, &[selected(&report, 2)]).unwrap();
    let stamp = file_stamp(&database).unwrap();
    let before = ids(&conn);
    conn.execute(
        "UPDATE omni_box_shortcuts SET payload=X'0203FF' WHERE rowid=2",
        [],
    )
    .unwrap();
    assert_eq!(file_stamp(&database).unwrap(), stamp);
    let receipt = clean(&temp.path().join("data"), &plan);
    assert_eq!((receipt.deleted, receipt.skipped), (0, 1));
    assert_eq!(ids(&conn), before);
}

#[test]
fn newly_bookmarked_urls_with_preserved_timestamp_cannot_reuse_old_reviews() {
    let temp = tempfile::tempdir().unwrap();
    let (profile, database) = fixture(&temp.path().join("profile"), Browser::Chrome);
    let report = scan(&profile);
    let plan = build_cleanup_plan(&report, &[selected(&report, 2)]).unwrap();
    let path = profile.root.join("Bookmarks");
    let stamp = file_stamp(&path).unwrap();
    let mtime = filetime::FileTime::from_last_modification_time(&fs::metadata(&path).unwrap());
    let old = fs::read_to_string(&path).unwrap();
    fs::write(
        &path,
        old.replace("https://keep.test/page", "https://drop.test/path"),
    )
    .unwrap();
    filetime::set_file_mtime(&path, mtime).unwrap();
    let before = ids(&Connection::open(&database).unwrap());
    // The URL-set comparison is required independently of the DB's unchanged stamp.
    let receipt = clean(&temp.path().join("data"), &plan);
    assert_eq!((receipt.deleted, receipt.skipped), (0, 1));
    assert_eq!(ids(&Connection::open(database).unwrap()), before);
    assert_eq!(file_stamp(&path).unwrap(), stamp);
}

#[test]
#[cfg(windows)]
fn same_stamp_bookmark_replacement_is_refused_by_identity() {
    use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
    use windows::Win32::{
        Foundation::{FILETIME, HANDLE},
        Storage::FileSystem::SetFileTime,
    };
    let temp = tempfile::tempdir().unwrap();
    let (profile, database) = fixture(&temp.path().join("profile"), Browser::Chrome);
    let path = profile.root.join("Bookmarks");
    let report = scan(&profile);
    let plan = build_cleanup_plan(&report, &[selected(&report, 2)]).unwrap();
    let stamp = file_stamp(&path).unwrap();
    let meta = fs::metadata(&path).unwrap();
    let replacement = temp.path().join("replacement");
    fs::write(&replacement, fs::read(&path).unwrap()).unwrap();
    let file = OpenOptions::new().write(true).open(&replacement).unwrap();
    let ft = |value: u64| FILETIME {
        dwLowDateTime: value as u32,
        dwHighDateTime: (value >> 32) as u32,
    };
    unsafe {
        SetFileTime(
            HANDLE(file.as_raw_handle()),
            Some(&ft(meta.creation_time())),
            None,
            Some(&ft(meta.last_write_time())),
        )
    }
    .unwrap();
    drop(file);
    fs::remove_file(&path).unwrap();
    fs::rename(replacement, &path).unwrap();
    assert_eq!(file_stamp(&path).unwrap(), stamp);
    let before = ids(&Connection::open(&database).unwrap());
    let receipt = clean(&temp.path().join("data"), &plan);
    assert_eq!((receipt.deleted, receipt.skipped), (0, 1));
    assert_eq!(ids(&Connection::open(database).unwrap()), before);
}

#[test]
fn absent_tables_do_not_read_unrelated_bad_bookmarks_and_unsafe_layouts_are_explicit() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::write(root.join("Bookmarks"), b"invalid owned JSON").unwrap();
    let conn = Connection::open_in_memory().unwrap();
    assert!(
        Snapshot::read(&conn, root, &AtomicBool::new(false))
            .unwrap()
            .rows
            .is_empty()
    );
    conn.execute_batch("CREATE TABLE omni_box_shortcuts(id,url)")
        .unwrap();
    assert!(Snapshot::read(&conn, root, &AtomicBool::new(false)).is_err());
    fs::remove_file(root.join("Bookmarks")).unwrap();
    for mutation in [
        "CREATE TRIGGER bad AFTER DELETE ON omni_box_shortcuts BEGIN DELETE FROM unrelated; END",
        "CREATE TABLE refs(id TEXT REFERENCES omni_box_shortcuts(id))",
        "ALTER TABLE omni_box_shortcuts ADD COLUMN rowid TEXT",
    ] {
        let conn = Connection::open_in_memory().unwrap();
        let case = owned_case();
        conn.execute_batch(case["setup_sql"].as_str().unwrap())
            .unwrap();
        conn.execute_batch(mutation).unwrap();
        assert!(
            Snapshot::read(&conn, root, &AtomicBool::new(false)).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn shortcut_bounds_cancellation_and_shared_bookmark_checks_remain_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let case = owned_case();
    bookmarks(temp.path(), &case["bookmarks"]);
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(case["setup_sql"].as_str().unwrap())
        .unwrap();
    for limits in [
        Limits {
            rows: 1,
            bytes: usize::MAX,
        },
        Limits {
            rows: 100,
            bytes: 1,
        },
    ] {
        assert!(
            Snapshot::read_with_limits(&conn, temp.path(), &AtomicBool::new(false), limits)
                .is_err()
        );
    }
    assert!(Snapshot::read(&conn, temp.path(), &AtomicBool::new(true)).is_err());
    let before = Snapshot::read(&conn, temp.path(), &AtomicBool::new(false)).unwrap();
    let current = Snapshot::read(&conn, temp.path(), &AtomicBool::new(false)).unwrap();
    let mut checks = HashMap::new();
    assert!(
        before
            .reviews()
            .iter()
            .all(|(_, _, r)| r.matches(&current, &mut checks))
    );
    assert_eq!(checks.len(), 1);
    bookmarks(
        temp.path(),
        &serde_json::json!({"url":"https://drop.test/path"}),
    );
    let changed = Snapshot::read(&conn, temp.path(), &AtomicBool::new(false)).unwrap();
    assert!(
        before
            .reviews()
            .iter()
            .all(|(_, _, r)| !r.matches(&changed, &mut checks))
    );
    assert_eq!(checks.len(), 2);
    assert!(before.bookmarks_unchanged(temp.path()).is_err());
}

#[test]
#[cfg(windows)]
fn bookmark_hardlinks_are_not_read_as_owned_profile_witnesses() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("profile");
    fs::create_dir_all(&root).unwrap();
    let outside = temp.path().join("outside-bookmarks");
    fs::write(&outside, b"{\"url\":\"https://keep.test/page\"}").unwrap();
    fs::hard_link(&outside, root.join("Bookmarks")).unwrap();
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(owned_case()["setup_sql"].as_str().unwrap())
        .unwrap();
    assert!(Snapshot::read(&conn, &root, &AtomicBool::new(false)).is_err());
    assert_eq!(
        fs::read(outside).unwrap(),
        b"{\"url\":\"https://keep.test/page\"}"
    );
}
