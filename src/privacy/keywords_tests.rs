use super::*;

fn corpus() -> serde_json::Value {
    serde_json::from_str(include_str!("../../tests/fixtures/keyword-history.json")).unwrap()
}
fn setup(conn: &Connection) {
    let cases = corpus();
    let case = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "legacy-one")
        .unwrap();
    conn.execute_batch(case["setup_sql"].as_str().unwrap())
        .unwrap();
}
fn ids(conn: &Connection) -> Vec<i64> {
    conn.prepare("SELECT rowid FROM keywords ORDER BY rowid")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}
fn profile(root: &Path, browser: Browser) -> BrowserProfile {
    fs::create_dir_all(root).unwrap();
    BrowserProfile {
        browser,
        root: dunce::canonicalize(root).unwrap(),
        id: "owned-keywords".into(),
        name: "Owned keywords".into(),
    }
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
struct Closed;
impl BrowserRuntime for Closed {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        Ok(vec![])
    }
}
struct NoFileEffects;
impl crate::cleanup::TrashPort for NoFileEffects {
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
        &mut NoFileEffects,
        &mut |_, _| {},
    )
    .unwrap()
}
fn selected(report: &PrivacyReport, row_id: i64) -> Uuid {
    report.records.iter().find(|record| matches!(&record.locator, RecordLocator::Database(row) if row.keyword.as_ref().is_some_and(|review| review.row_id==row_id)))
        .expect("expected reviewed keyword").id
}

#[test]
fn owned_query_matrix_matches_eligible_rows_and_preserves_sources() {
    for case in corpus()["cases"].as_array().unwrap() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(case["setup_sql"].as_str().unwrap())
            .unwrap();
        let before = ids(&conn);
        let snapshot = Snapshot::read(&conn, &AtomicBool::new(false)).unwrap();
        let expected: Vec<i64> = serde_json::from_value(case["expected_row_ids"].clone()).unwrap();
        assert_eq!(
            snapshot.rows.keys().copied().collect::<Vec<_>>(),
            expected,
            "{}",
            case["name"]
        );
        assert_eq!(ids(&conn), before);
        assert_eq!(
            default_provider(&conn).unwrap().0,
            case["provider_int32"].as_i64().unwrap() as i32
        );
        assert!(snapshot.rows.values().all(|row| row.site == "owned.test"));
    }
}

#[test]
fn exact_reviewed_rows_are_removed_with_backups_and_unselected_data_survives() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile(&temp.path().join("profile"), Browser::Chrome);
    let database = profile.root.join("Web Data");
    let conn = Connection::open(&database).unwrap();
    setup(&conn);
    let before = ids(&conn);
    drop(conn);
    let report = scan(&profile);
    assert!(!report.partial, "{:?}", report.skipped);
    let plan = build_cleanup_plan(&report, &[selected(&report, 3)]).unwrap();
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
            .filter(|id| *id != 3)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        conn.query_row("SELECT value FROM autofill", [], |row| row
            .get::<_, String>(0))
            .unwrap(),
        "preserved unrelated data"
    );
    drop(conn);
    let options = list_privacy_restore_options(&data).unwrap();
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].state, PrivacyRecoveryState::Ready);
    let restore = prepare_privacy_restore_with_runtime(&data, options[0].id, &Closed).unwrap();
    restore_privacy_database_with_runtime(&data, &restore, &Closed).unwrap();
    let conn = Connection::open(&database).unwrap();
    assert_eq!(ids(&conn), before);
}

#[test]
fn wal_only_provider_and_full_row_drift_block_keyword_effects() {
    for changed in [
        "UPDATE meta SET value=2",
        "UPDATE keywords SET payload=X'0203FF' WHERE rowid=3",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let profile = profile(&temp.path().join("profile"), Browser::Chrome);
        let database = profile.root.join("Web Data");
        let conn = Connection::open(&database).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
            .unwrap();
        setup(&conn);
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let report = scan(&profile);
        assert!(!report.partial, "{:?}", report.skipped);
        let plan = build_cleanup_plan(&report, &[selected(&report, 3)]).unwrap();
        let stamp = file_stamp(&database).unwrap();
        conn.execute_batch(changed).unwrap();
        assert_eq!(file_stamp(&database).unwrap(), stamp);
        let before = ids(&conn);
        let receipt = clean(&temp.path().join("data"), &plan);
        assert_eq!(receipt.deleted, 0, "{changed}: {:?}", receipt.errors);
        assert_eq!(receipt.skipped, 1);
        assert_eq!(ids(&conn), before);
    }
}

#[test]
fn fresh_web_data_only_profiles_scan_across_all_thirteen_families() {
    let temp = tempfile::tempdir().unwrap();
    for browser in Browser::ALL
        .iter()
        .copied()
        .filter(|browser| browser.is_chromium())
    {
        let base = temp.path().join(browser.cache_category());
        let profile = profile(&base.join("Web Data only"), browser);
        let database = profile.root.join("Web Data");
        let conn = Connection::open(&database).unwrap();
        setup(&conn);
        drop(conn);
        let before = fs::read(&database).unwrap();
        let stamp = file_stamp(&database).unwrap();
        let mut profiles = ProfileInventory::default();
        profile_discovery::user_data_profiles(browser, &base, &mut profiles);
        assert!(
            !profiles.partial && profiles.profiles.len() == 1,
            "{browser:?}"
        );
        let report = scan(&profiles.profiles[0]);
        assert!(!report.partial, "{browser:?}: {:?}", report.skipped);
        assert_eq!(report.records.len(), 7, "{browser:?}");
        assert_eq!(
            report
                .records
                .iter()
                .map(PrivacyRecord::item_count)
                .sum::<usize>(),
            7
        );
        assert!(
            report
                .records
                .iter()
                .all(|row| row.actionable() && row.site == "owned.test")
        );
        assert_eq!(fs::read(&database).unwrap(), before);
        assert_eq!(file_stamp(&database).unwrap(), stamp);
    }
}

#[test]
fn absent_keywords_are_empty_while_ambiguous_or_unsafe_metadata_stays_partial() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE autofill(value TEXT)")
        .unwrap();
    assert!(
        Snapshot::read(&conn, &AtomicBool::new(false))
            .unwrap()
            .rows
            .is_empty()
    );
    for mutation in [
        "DROP TABLE meta",
        "INSERT INTO meta VALUES('Default Search Provider ID',2)",
        "UPDATE meta SET value=zeroblob(5000)",
        "CREATE TRIGGER unreviewed AFTER DELETE ON keywords BEGIN DELETE FROM autofill; END",
        "CREATE TABLE dependent(k INTEGER REFERENCES keywords(id))",
        "ALTER TABLE keywords ADD COLUMN rowid TEXT",
    ] {
        let conn = Connection::open_in_memory().unwrap();
        setup(&conn);
        conn.execute_batch(mutation).unwrap();
        assert!(
            Snapshot::read(&conn, &AtomicBool::new(false)).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn schema_change_after_review_never_deletes_unreviewed_data() {
    let temp = tempfile::tempdir().unwrap();
    let profile = profile(&temp.path().join("profile"), Browser::Chrome);
    let database = profile.root.join("Web Data");
    let conn = Connection::open(&database).unwrap();
    setup(&conn);
    drop(conn);
    let report = scan(&profile);
    let plan = build_cleanup_plan(&report, &[selected(&report, 3)]).unwrap();
    let conn = Connection::open(&database).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER unexpected AFTER DELETE ON keywords BEGIN DELETE FROM autofill; END",
    )
    .unwrap();
    let before = ids(&conn);
    drop(conn);
    let receipt = clean(&temp.path().join("data"), &plan);
    assert_eq!(receipt.deleted, 0);
    let conn = Connection::open(&database).unwrap();
    assert_eq!(ids(&conn), before);
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM autofill", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn keyword_snapshot_limits_and_cancellation_never_return_partial_owners() {
    let conn = Connection::open_in_memory().unwrap();
    setup(&conn);
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
        assert!(Snapshot::read_with_limits(&conn, &AtomicBool::new(false), limits).is_err());
    }
    assert!(Snapshot::read(&conn, &AtomicBool::new(true)).is_err());
    assert_eq!(ids(&conn).len(), 14);
}

#[test]
fn empty_legacy_probe_uses_fallback_and_missing_metadata_does_not_mean_provider_zero() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE keywords(show_in_default_list INTEGER,safe_for_autoreplace INTEGER); CREATE TABLE meta(key TEXT,value);").unwrap();
    // The successful SELECT has no row, so the native helper returns false.
    // Its fallback predicate then references an absent prepopulate_id column.
    assert!(Snapshot::read(&conn, &AtomicBool::new(false)).is_err());
    conn.execute_batch("ALTER TABLE keywords ADD COLUMN prepopulate_id INTEGER; ALTER TABLE keywords ADD COLUMN id INTEGER;").unwrap();
    assert!(
        Snapshot::read(&conn, &AtomicBool::new(false))
            .unwrap()
            .rows
            .is_empty()
    );
    conn.execute_batch("DROP TABLE meta; INSERT INTO keywords VALUES(0,1,0,0);")
        .unwrap();
    assert!(Snapshot::read(&conn, &AtomicBool::new(false)).is_err());
}

#[test]
fn negative_provider_does_not_require_an_id_column_or_decode_opaque_row_values() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE keywords(prepopulate_id INTEGER,safe_for_autoreplace INTEGER,payload BLOB); CREATE TABLE meta(key TEXT,value); INSERT INTO meta VALUES('Default Search Provider ID',-1); INSERT INTO keywords(rowid,prepopulate_id,safe_for_autoreplace,payload) VALUES(-10,0,1,X'FFFE00');").unwrap();
    let snapshot = Snapshot::read(&conn, &AtomicBool::new(false)).unwrap();
    let reviews = snapshot.reviews();
    assert_eq!(reviews.len(), 1);
    assert_eq!(
        (reviews[0].0.as_str(), reviews[0].1),
        ("Keyword history", -10)
    );
    assert!(reviews[0].2.matches(&snapshot));
    conn.execute("UPDATE meta SET value=0", []).unwrap();
    assert!(Snapshot::read(&conn, &AtomicBool::new(false)).is_err());
    assert_eq!(ids(&conn), [-10]);
}
