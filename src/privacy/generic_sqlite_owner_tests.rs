use super::*;
use privacy::{
    BrowserRuntime, PrivacyCategory, PrivacyRecord, RunningBrowser, build_cleanup_plan,
    clean_privacy_with_runtime, scan_profiles_with_settings,
};
use uuid::Uuid;
struct Closed;
impl BrowserRuntime for Closed {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        Ok(vec![])
    }
}
fn profile(root: &Path, browser: Browser) -> BrowserProfile {
    fs::create_dir_all(root).unwrap();
    BrowserProfile {
        id: Uuid::new_v4().to_string(),
        name: "Owned generic table fixture".into(),
        root: dunce::canonicalize(root).unwrap(),
        browser,
    }
}
fn database(p: &BrowserProfile, name: &str, sql: &str) -> PathBuf {
    let path = p.root.join(name);
    Connection::open(&path).unwrap().execute_batch(sql).unwrap();
    path
}
fn scan(p: &BrowserProfile, categories: &[PrivacyCategory]) -> PrivacyReport {
    scan_profiles_with_settings(
        std::slice::from_ref(p),
        categories,
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    )
}
fn clean(data: &Path, report: &PrivacyReport, ids: &[Uuid]) -> privacy::PrivacyReceipt {
    clean_privacy_with_runtime(
        data,
        &build_cleanup_plan(report, ids).unwrap(),
        &AtomicBool::new(false),
        &Closed,
        &mut |_, _| {},
    )
    .unwrap()
}
fn count(path: &Path, table: &str) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |r| {
            r.get(0)
        })
        .unwrap()
}

#[test]
fn all_thirty_rules_are_reachable_as_weighted_private_table_groups() {
    for rule in catalogue::RULES {
        let temp = tempfile::tempdir().unwrap();
        let p = profile(&temp.path().join("profile"), rule.browser);
        let sql=rule.tables.iter().map(|t|format!("CREATE TABLE \"{t}\"(secret BLOB); INSERT INTO \"{t}\" VALUES(X'70726976617465'),(NULL);")).collect::<String>();
        let path = database(&p, rule.database, &sql);
        let before = fs::read(&path).unwrap();
        let category = keys(rule.browser, rule.scope)[0].category();
        let report = scan(&p, &[category]);
        assert_eq!(
            report.records.len(),
            rule.tables.len(),
            "{} {:?}",
            rule.id,
            report.skipped
        );
        assert_eq!(
            report
                .records
                .iter()
                .map(PrivacyRecord::item_count)
                .sum::<usize>(),
            2 * rule.tables.len()
        );
        assert!(report.records.iter().all(|r| r.category == category
            && r.actionable()
            && r.is_database_table()
            && r.native_item_count().is_none()
            && !r.site.contains("private")));
        assert_eq!(fs::read(path).unwrap(), before);
    }
}
#[test]
fn exact_selected_tables_clean_atomically_and_restore_with_unselected_data() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let path = database(
        &p,
        "Web Data",
        "CREATE TABLE autofill(secret); INSERT INTO autofill VALUES('one'),('two'),('two'); CREATE TABLE credit_cards(secret); INSERT INTO credit_cards VALUES('keep'); CREATE TABLE logins(secret); INSERT INTO logins VALUES('password'); CREATE TABLE unrelated(secret); INSERT INTO unrelated VALUES('untouched');",
    );
    let report = scan(
        &p,
        &[PrivacyCategory::SavedForms, PrivacyCategory::SavedPasswords],
    );
    let ids = report
        .records
        .iter()
        .filter(|r| r.site.ends_with(": autofill") || r.site.ends_with(": logins"))
        .map(|r| r.id)
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 2);
    let receipt = clean(&data, &report, &ids);
    assert_eq!(
        (
            receipt.selected,
            receipt.deleted,
            receipt.skipped,
            receipt.uncertain
        ),
        (2, 2, 0, false),
        "{:?}",
        receipt.errors
    );
    assert_eq!(
        (
            count(&path, "autofill"),
            count(&path, "logins"),
            count(&path, "credit_cards"),
            count(&path, "unrelated")
        ),
        (0, 0, 1, 1)
    );
    let options = privacy::list_privacy_restore_options(&data).unwrap();
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].record_count, 2);
    assert_eq!(
        options[0].categories,
        vec![PrivacyCategory::SavedForms, PrivacyCategory::SavedPasswords]
    );
    let plan =
        privacy::prepare_privacy_restore_with_runtime(&data, options[0].id, &Closed).unwrap();
    assert!(
        !plan.restores_preferences()
            && !plan.restores_sessions()
            && !plan.restores_site_storage_keys()
    );
    let restored = privacy::restore_privacy_database_with_runtime(&data, &plan, &Closed).unwrap();
    assert!(restored.restored && !restored.uncertain);
    assert_eq!(
        (
            count(&path, "autofill"),
            count(&path, "logins"),
            count(&path, "credit_cards"),
            count(&path, "unrelated")
        ),
        (3, 1, 1, 1)
    );
}
#[test]
fn same_stamp_same_count_payload_changes_refuse_table_wide_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let path = database(
        &p,
        "Web Data",
        "CREATE TABLE autofill(secret); INSERT INTO autofill VALUES('before');",
    );
    let report = scan(&p, &[PrivacyCategory::SavedForms]);
    let stamp = privacy::file_stamp(&path).unwrap();
    let modified = filetime::FileTime::from_last_modification_time(&fs::metadata(&path).unwrap());
    Connection::open(&path)
        .unwrap()
        .execute("UPDATE autofill SET secret='change'", [])
        .unwrap();
    filetime::set_file_mtime(&path, modified).unwrap();
    assert_eq!(privacy::file_stamp(&path).unwrap(), stamp);
    let receipt = clean(&temp.path().join("data"), &report, &[report.records[0].id]);
    assert_eq!((receipt.deleted, receipt.skipped), (0, 1));
    assert!(
        receipt
            .errors
            .iter()
            .any(|e| e.contains("contents changed")),
        "{:?}",
        receipt.errors
    );
    assert_eq!(count(&path, "autofill"), 1);
}
#[test]
fn committed_wal_changes_are_seen_without_main_file_or_count_changes() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let path = p.root.join("Web Data");
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE autofill(secret); INSERT INTO autofill VALUES('before');").unwrap();
    let report = scan(&p, &[PrivacyCategory::SavedForms]);
    assert_eq!(report.records.len(), 1, "{:?}", report.skipped);
    let main = fs::read(&path).unwrap();
    writer
        .execute("UPDATE autofill SET secret='change'", [])
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), main);
    let receipt = clean(&temp.path().join("data"), &report, &[report.records[0].id]);
    assert_eq!((receipt.deleted, receipt.skipped), (0, 1));
    assert!(
        receipt
            .errors
            .iter()
            .any(|e| e.contains("contents changed")),
        "{:?}",
        receipt.errors
    );
    assert_eq!(fs::read(path).unwrap(), main);
}
#[test]
fn foreign_key_cascades_cannot_change_unselected_tables() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let path = database(
        &p,
        "Web Data",
        "CREATE TABLE autofill(id INTEGER PRIMARY KEY); CREATE TABLE credit_cards(id INTEGER PRIMARY KEY,parent REFERENCES autofill(id) ON DELETE CASCADE); INSERT INTO autofill VALUES(1); INSERT INTO credit_cards VALUES(2,1);",
    );
    let report = scan(&p, &[PrivacyCategory::SavedForms]);
    let id = report
        .records
        .iter()
        .find(|r| r.site.ends_with(": autofill"))
        .unwrap()
        .id;
    let receipt = clean(&temp.path().join("data"), &report, &[id]);
    assert_eq!((receipt.deleted, receipt.skipped), (0, 1));
    assert!(
        receipt
            .errors
            .iter()
            .any(|e| e.contains("unselected table")),
        "{:?}",
        receipt.errors
    );
    assert_eq!(
        (count(&path, "autofill"), count(&path, "credit_cards")),
        (1, 1)
    );
}
#[test]
fn reviewed_cyclic_and_cascading_tables_delete_as_one_transaction() {
    for cascade in ["CASCADE", "NO ACTION"] {
        let temp = tempfile::tempdir().unwrap();
        let p = profile(&temp.path().join("profile"), Browser::Chrome);
        let path = database(
            &p,
            "Web Data",
            &format!(
                "BEGIN; PRAGMA defer_foreign_keys=ON; CREATE TABLE autofill(id INTEGER PRIMARY KEY,other REFERENCES credit_cards(id) ON DELETE {cascade}); CREATE TABLE credit_cards(id INTEGER PRIMARY KEY,other REFERENCES autofill(id) ON DELETE {cascade}); INSERT INTO autofill VALUES(1,2); INSERT INTO credit_cards VALUES(2,1); COMMIT;"
            ),
        );
        let report = scan(&p, &[PrivacyCategory::SavedForms]);
        let ids = report.records.iter().map(|r| r.id).collect::<Vec<_>>();
        let receipt = clean(&temp.path().join("data"), &report, &ids);
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (2, 0),
            "{:?}",
            receipt.errors
        );
        assert_eq!(
            (count(&path, "autofill"), count(&path, "credit_cards")),
            (0, 0)
        );
    }
}
#[test]
fn selected_table_triggers_are_visible_but_never_gain_cleanup_authority() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let path = database(
        &p,
        "Web Data",
        "CREATE TABLE autofill(x); INSERT INTO autofill VALUES(1); CREATE TABLE other(x); CREATE TRIGGER changed AFTER DELETE ON autofill BEGIN INSERT INTO other VALUES(1); END;",
    );
    let report = scan(&p, &[PrivacyCategory::SavedForms]);
    assert_eq!(report.records.len(), 1);
    assert!(!report.records[0].actionable());
    assert!(build_cleanup_plan(&report, &[report.records[0].id]).is_err());
    assert_eq!(count(&path, "other"), 0);
}
#[test]
fn missing_rowids_duplicate_values_and_recent_sources_clean_exact_groups() {
    for schema in [
        "CREATE TABLE autofill(a TEXT,b INTEGER,PRIMARY KEY(a,b)) WITHOUT ROWID; INSERT INTO autofill VALUES('same',1),('same',2);",
        "CREATE TABLE autofill(rowid TEXT,_rowid_ TEXT,oid TEXT); INSERT INTO autofill VALUES('same','same','same'),('same','same','same');",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let p = profile(&temp.path().join("profile"), Browser::Chrome);
        let path = database(&p, "Web Data", schema);
        let report = scan(&p, &[PrivacyCategory::SavedForms]);
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].item_count(), 2);
        let receipt = clean(&temp.path().join("data"), &report, &[report.records[0].id]);
        assert_eq!(receipt.deleted, 1, "{:?}", receipt.errors);
        assert_eq!(count(&path, "autofill"), 0);
    }
}
#[test]
fn mozilla_signons_only_profiles_are_metadata_witnesses_and_tables_stay_separate() {
    for browser in [Browser::Firefox, Browser::Thunderbird] {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("Profiles");
        let p = profile(&base.join("owned.default"), browser);
        let path = database(
            &p,
            "signons.sqlite",
            "CREATE TABLE moz_disabledHosts(host); INSERT INTO moz_disabledHosts VALUES('keep-private'); CREATE TABLE moz_logins(secret); INSERT INTO moz_logins VALUES('password');",
        );
        let before = fs::read(&path).unwrap();
        let mut inventory = privacy::ProfileInventory::default();
        privacy::profile_discovery::user_data_profiles(browser, &base, &mut inventory);
        assert_eq!(inventory.profiles.len(), 1, "{:?}", inventory.skipped);
        let report = scan(
            &p,
            &[
                PrivacyCategory::SavedPasswords,
                PrivacyCategory::SitePreferences,
            ],
        );
        assert_eq!(report.records.len(), 2);
        assert!(
            report
                .records
                .iter()
                .all(|r| !r.site.contains("password") && !r.site.contains("keep-private"))
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        let id = report
            .records
            .iter()
            .find(|r| r.category == PrivacyCategory::SitePreferences)
            .unwrap()
            .id;
        let receipt = clean(&temp.path().join("data"), &report, &[id]);
        assert_eq!(receipt.deleted, 1, "{:?}", receipt.errors);
        assert_eq!(
            (
                count(&path, "moz_disabledHosts"),
                count(&path, "moz_logins")
            ),
            (0, 1)
        );
    }
}
#[test]
fn categories_remain_opt_in_and_unimplemented_formats_are_explicit() {
    for category in [
        PrivacyCategory::SavedForms,
        PrivacyCategory::SavedPasswords,
        PrivacyCategory::SitePreferences,
    ] {
        assert!(!PrivacyCategory::DEFAULT.contains(&category));
        assert!(PrivacyCategory::ALL.contains(&category));
    }
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Firefox);
    let report = scan(&p, &[PrivacyCategory::SavedForms]);
    assert!(report.partial && !report.skipped.is_empty());
    let report = scan(&p, &[PrivacyCategory::SavedPasswords]);
    assert!(
        report.partial
            && report
                .skipped
                .iter()
                .any(|s| s.reason.contains("legacy SQLite"))
    );
}
#[test]
fn old_pending_cleanup_and_restore_intents_block_fresh_reviewed_actions() {
    for restore in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let p = profile(&temp.path().join("profile"), Browser::Chrome);
        let path = database(
            &p,
            "Web Data",
            "CREATE TABLE autofill(x); INSERT INTO autofill VALUES(1);",
        );
        let report = scan(&p, &[PrivacyCategory::SavedForms]);
        let history = data.join("privacy-operations");
        fs::create_dir_all(&history).unwrap();
        for _ in 0..105 {
            fs::write(
                history.join(format!("{}.jsonl", Uuid::new_v4())),
                "{\"kind\":\"finish\",\"cancelled\":false}\n",
            )
            .unwrap();
        }
        let event = if restore {
            serde_json::json!({"kind":"restore_intent","restore_id":Uuid::new_v4(),"source_operation_id":Uuid::new_v4(),"database":path,"source_backup":"owned","current_state_backup":"current","post_state_snapshot":"post","expected_stamp":{"length":1,"modified_ns":"0"},"schema_signature":"owned"})
        } else {
            serde_json::json!({"kind":"intent","database":path,"backup":"owned","record_ids":[Uuid::new_v4()]})
        };
        fs::write(
            history.join(format!("{}.jsonl", Uuid::new_v4())),
            format!("{event}\n"),
        )
        .unwrap();
        assert!(pending(&data, &path).unwrap_err().contains("unresolved"));
        let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
        assert!(
            clean_privacy_with_runtime(
                &data,
                &plan,
                &AtomicBool::new(false),
                &Closed,
                &mut |_, _| {}
            )
            .is_err()
        );
        assert_eq!(count(&path, "autofill"), 1);
    }
}
#[test]
fn namespace_replacement_hardlinks_and_linked_sidecars_are_refused() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let path = database(
        &p,
        "Web Data",
        "CREATE TABLE autofill(x); INSERT INTO autofill VALUES(1);",
    );
    let lease = SourceLease::acquire(&p.root, &path).unwrap();
    #[cfg(windows)]
    assert!(fs::rename(&path, p.root.join("replaced")).is_err());
    drop(lease);
    fs::hard_link(&path, p.root.join("alias")).unwrap();
    let report = scan(&p, &[PrivacyCategory::SavedForms]);
    assert!(report.partial && report.records.is_empty());
    fs::remove_file(p.root.join("alias")).unwrap();
    let foreign = p.root.join("foreign");
    fs::write(&foreign, b"owned foreign WAL").unwrap();
    fs::hard_link(&foreign, p.root.join("Web Data-wal")).unwrap();
    let report = scan(&p, &[PrivacyCategory::SavedForms]);
    assert!(report.partial && report.records.is_empty());
    assert_eq!(fs::read(foreign).unwrap(), b"owned foreign WAL");
}
#[test]
fn cancelled_cleanup_and_stale_ids_never_remove_table_rows() {
    let temp = tempfile::tempdir().unwrap();
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let path = database(
        &p,
        "Web Data",
        "CREATE TABLE autofill(x); INSERT INTO autofill VALUES(1);",
    );
    let report = scan(&p, &[PrivacyCategory::SavedForms]);
    assert!(build_cleanup_plan(&report, &[Uuid::new_v4()]).is_err());
    let fresh = scan(&p, &[PrivacyCategory::SavedForms]);
    assert!(build_cleanup_plan(&fresh, &[report.records[0].id]).is_err());
    let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
    let receipt = clean_privacy_with_runtime(
        &temp.path().join("data"),
        &plan,
        &AtomicBool::new(true),
        &Closed,
        &mut |_, _| {},
    )
    .unwrap();
    assert!(receipt.cancelled && receipt.deleted == 0);
    assert_eq!(count(&path, "autofill"), 1);
}
#[test]
fn snapshot_hash_requires_a_transaction_and_detects_unselected_data_changes() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE autofill(x); INSERT INTO autofill VALUES(1); CREATE TABLE unrelated(x); INSERT INTO unrelated VALUES('before');").unwrap();
    let cancel = AtomicBool::new(false);
    assert!(image(&conn, &cancel).is_err());
    let before = {
        let tx = conn.transaction().unwrap();
        image(&tx, &cancel).unwrap()
    };
    conn.execute("UPDATE unrelated SET x='change'", []).unwrap();
    let after = {
        let tx = conn.transaction().unwrap();
        image(&tx, &cancel).unwrap()
    };
    assert_ne!(before, after);
}

#[test]
fn unresolved_newer_operation_blocks_older_ready_database_restore() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let p = profile(&temp.path().join("profile"), Browser::Chrome);
    let path = database(
        &p,
        "Web Data",
        "CREATE TABLE autofill(x); INSERT INTO autofill VALUES(1);",
    );
    let report = scan(&p, &[PrivacyCategory::SavedForms]);
    let receipt = clean(&data, &report, &[report.records[0].id]);
    assert_eq!(receipt.deleted, 1);
    let options = privacy::list_privacy_restore_options(&data).unwrap();
    assert_eq!(options.len(), 1);
    let pending = serde_json::json!({"kind":"intent","database":path,"backup":"owned-newer-backup","record_ids":[Uuid::new_v4()]});
    fs::write(
        data.join("privacy-operations")
            .join(format!("{}.jsonl", Uuid::new_v4())),
        format!("{pending}\n"),
    )
    .unwrap();
    assert!(
        privacy::prepare_privacy_restore_with_runtime(&data, options[0].id, &Closed)
            .err()
            .unwrap()
            .contains("unresolved")
    );
    assert_eq!(count(&path, "autofill"), 0);
}
