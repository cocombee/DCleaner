use dcleaner::privacy::{
    Browser, BrowserProfile, BrowserRuntime, PrivacyCategory, PrivacyRecoveryState, RunningBrowser,
    build_cleanup_plan, clean_privacy_with_runtime, list_privacy_restore_options,
    load_cookie_exception_settings, prepare_privacy_restore_with_runtime,
    recover_privacy_operations, restore_privacy_database_with_runtime,
    save_cookie_exception_settings, save_cookie_policy, scan_profiles, scan_profiles_with_settings,
    sign_in_policy_categories,
};
use rusqlite::{Connection, OpenFlags, backup::Backup};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};
use uuid::Uuid;

fn cookie_scan(profile: &BrowserProfile) -> dcleaner::privacy::PrivacyReport {
    scan_profiles_with_settings(
        &[profile.clone()],
        &[PrivacyCategory::Cookies],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    )
}

fn quota_fixture(root: &Path, variant: usize) -> (BrowserProfile, PathBuf) {
    let profile_root = root.join("profile");
    fs::create_dir_all(&profile_root).unwrap();
    let path = profile_root.join("QuotaManager");
    let db = Connection::open(&path).unwrap();
    if variant == 0 {
        db.execute_batch("CREATE TABLE OriginInfoTable(origin TEXT,payload TEXT);
            INSERT INTO OriginInfoTable VALUES('http://one.test/','private-a'),('http://one.test/','private-b'),('https://two.test/','private-c'),('opaque','private-d');
            CREATE TABLE HostQuotaTable(host TEXT,payload TEXT);
            INSERT INTO HostQuotaTable VALUES('quota-only.test','retained'),('opaque','retained');").unwrap();
    } else {
        let columns = if variant == 1 {
            "origin TEXT"
        } else if variant == 4 {
            "origin TEXT,storage_key TEXT"
        } else {
            "storage_key TEXT"
        };
        db.execute_batch(&format!("CREATE TABLE buckets({columns},payload TEXT)"))
            .unwrap();
        for (key, payload) in [
            ("http://one.test/", "private-a"),
            ("http://one.test/", "private-b"),
            ("https://two.test/", "private-c"),
            ("opaque", "private-d"),
        ] {
            if variant == 4 {
                db.execute(
                    "INSERT INTO buckets VALUES(?1,?1,?2)",
                    rusqlite::params![key, payload],
                )
                .unwrap();
            } else {
                db.execute(
                    "INSERT INTO buckets VALUES(?1,?2)",
                    rusqlite::params![key, payload],
                )
                .unwrap();
            }
        }
        if variant != 3 {
            db.execute_batch("CREATE TABLE quota(host TEXT,payload TEXT); INSERT INTO quota VALUES('quota-only.test','retained'),('opaque','retained')").unwrap();
        }
    }
    (
        BrowserProfile {
            id: "owned-quota".into(),
            name: "Owned quota".into(),
            browser: Browser::Chrome,
            root: profile_root,
        },
        path,
    )
}

#[test]
fn quota_all_families_preserve_union_counts_and_merge_overlapping_exact_row_effects() {
    for browser in [
        Browser::Chrome,
        Browser::Edge,
        Browser::Avg,
        Browser::Ccleaner,
        Browser::Avast,
        Browser::Opera,
        Browser::Vivaldi,
        Browser::Brave,
        Browser::OperaGx,
        Browser::Norton,
        Browser::Avira,
        Browser::Arc,
        Browser::Neo,
    ] {
        for variant in 0..5 {
            let dir = tempfile::tempdir().unwrap();
            let (mut profile, path) = quota_fixture(dir.path(), variant);
            profile.browser = browser;
            let before = fs::read(&path).unwrap();
            let report = cookie_scan(&profile);
            assert!(
                !report.partial,
                "{browser:?}/{variant}: {:?}",
                report.skipped
            );
            assert_eq!(
                report.records.iter().map(|r| r.item_count()).sum::<usize>(),
                [4, 4, 6, 2, 10][variant]
            );
            assert_eq!(fs::read(&path).unwrap(), before);
            let unavailable = report
                .records
                .iter()
                .filter(|r| !r.actionable())
                .collect::<Vec<_>>();
            assert_eq!(
                unavailable.iter().map(|r| r.item_count()).sum::<usize>(),
                [2, 1, 1, 0, 2][variant]
            );
            for row in unavailable {
                assert!(build_cleanup_plan(&report, &[row.id]).is_err());
                assert!(row.unavailable_reason().unwrap().contains("metadata"));
            }
            let ids = report
                .records
                .iter()
                .filter(|r| r.actionable())
                .map(|r| r.id)
                .collect::<Vec<_>>();
            assert_eq!(ids.len(), [1, 3, 3, 2, 3][variant]);
            let receipt = firefox_clean(dir.path(), &report, &ids);
            assert_eq!(receipt.deleted, ids.len(), "{:?}", receipt.errors);
            assert_eq!(receipt.backups.len(), 1);
            let db = Connection::open(&path).unwrap();
            let table = if variant == 0 {
                "OriginInfoTable"
            } else {
                "buckets"
            };
            assert_eq!(storage_rows(&db, table).len(), [2, 0, 0, 1, 0][variant]);
            if variant != 3 {
                let aux = if variant == 0 {
                    "HostQuotaTable"
                } else {
                    "quota"
                };
                assert_eq!(storage_rows(&db, aux).len(), 2);
            }
            // Candidate units never pretend to be receipt group counts or rows.
            assert_eq!(receipt.selected, ids.len());
        }
    }
}

#[test]
fn quota_keep_alias_overlap_is_reported_but_never_cleanable() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, path) = quota_fixture(dir.path(), 0);
    let settings =
        save_cookie_exception_settings(&dir.path().join("settings"), &["one.test".into()]).unwrap();
    let report = scan_profiles_with_settings(
        &[profile],
        &[PrivacyCategory::Cookies],
        &settings,
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!(report.cookie_exempted, 1);
    let alias = report
        .records
        .iter()
        .find(|r| {
            r.unavailable_reason()
                .is_some_and(|reason| reason.contains("keep list"))
        })
        .unwrap();
    assert_eq!(alias.item_count(), 1);
    assert!(!alias.actionable());
    assert!(build_cleanup_plan(&report, &[alias.id]).is_err());
    assert_eq!(
        storage_rows(&Connection::open(path).unwrap(), "OriginInfoTable").len(),
        4
    );
}

#[test]
fn quota_wal_membership_and_payload_changes_skip_affected_groups_without_expanding_review() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, path) = quota_fixture(dir.path(), 2);
    let db = Connection::open(&path).unwrap();
    db.pragma_update(None, "journal_mode", "WAL").unwrap();
    db.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    let report = cookie_scan(&profile);
    assert!(!report.partial, "{:?}", report.skipped);
    let ids = report
        .records
        .iter()
        .filter(|r| r.actionable())
        .map(|r| r.id)
        .collect::<Vec<_>>();
    let before = fs::read(&path).unwrap();
    db.execute(
        "INSERT INTO buckets VALUES('http://one.test/','new-unreviewed')",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE buckets SET payload='changed' WHERE storage_key='https://two.test/'",
        [],
    )
    .unwrap();
    assert_eq!(fs::read(&path).unwrap(), before, "drift must be WAL-only");
    let receipt = firefox_clean(dir.path(), &report, &ids);
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (1, 2),
        "{:?}",
        receipt.errors
    );
    assert_eq!(storage_rows(&db, "buckets").len(), 4);
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM buckets WHERE storage_key='opaque'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(storage_rows(&db, "quota").len(), 2);
}

#[test]
fn quota_exact_effects_handle_collation_and_nul_prefix_without_sql_key_interpolation() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, path) = quota_fixture(dir.path(), 1);
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "DROP TABLE buckets; CREATE TABLE buckets(origin TEXT COLLATE NOCASE,payload BLOB);
        INSERT INTO buckets VALUES('opaque',X'01'),('http://quo''te.test/',X'02');
        DELETE FROM quota; INSERT INTO quota VALUES('OPAQUE','retained');",
    )
    .unwrap();
    db.execute(
        "INSERT INTO quota VALUES(?1,'retained')",
        ["opaque\0private-suffix"],
    )
    .unwrap();
    db.execute(
        "INSERT INTO buckets VALUES(?1,X'03')",
        ["opaque\0private-suffix"],
    )
    .unwrap();
    let report = cookie_scan(&profile);
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!(
        report.records.iter().map(|r| r.item_count()).sum::<usize>(),
        3
    );
    let ids = report
        .records
        .iter()
        .filter(|r| r.actionable())
        .map(|r| r.id)
        .collect::<Vec<_>>();
    let receipt = firefox_clean(dir.path(), &report, &ids);
    assert_eq!(receipt.deleted, 2, "{:?}", receipt.errors);
    let remaining = storage_rows(&Connection::open(path).unwrap(), "buckets");
    assert_eq!(remaining.len(), 1);
    assert_eq!(
        remaining[0][1],
        rusqlite::types::Value::Text("opaque\0private-suffix".into())
    );
}

#[test]
fn quota_schema_dependencies_views_and_bounds_are_explicit_read_only_omissions() {
    for case in 0..8 {
        let dir = tempfile::tempdir().unwrap();
        let (profile, path) = quota_fixture(dir.path(), 2);
        let db = Connection::open(&path).unwrap();
        match case {
            0=>db.execute_batch("CREATE TRIGGER unreviewed AFTER DELETE ON buckets BEGIN DELETE FROM quota; END").unwrap(),
            1=>db.execute_batch("CREATE TABLE child(owner TEXT REFERENCES buckets(storage_key))").unwrap(),
            2=>db.execute_batch("DROP TABLE buckets; CREATE VIEW buckets AS SELECT host AS storage_key,payload FROM quota").unwrap(),
            3=>db.execute_batch("DROP TABLE buckets; CREATE TABLE buckets(rowid INTEGER,storage_key TEXT)").unwrap(),
            4=>db.execute_batch("DROP TABLE buckets; CREATE TABLE buckets(storage_key TEXT PRIMARY KEY) WITHOUT ROWID").unwrap(),
            5=>db.execute_batch("DROP TABLE buckets; CREATE TABLE buckets(unknown TEXT)").unwrap(),
            6=>db.execute_batch("UPDATE quota SET host=CAST(x'80' AS TEXT)").unwrap(),
            _=>db.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100001) INSERT INTO buckets SELECT 'https://limit.test/',x FROM n").unwrap(),
        }
        drop(db);
        let before = fs::read(&path).unwrap();
        let report = cookie_scan(&profile);
        assert!(
            report.partial && report.records.is_empty(),
            "case {case}: {:?}",
            report.skipped
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn quota_group_backup_restore_retains_all_targets_and_auxiliary_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, path) = quota_fixture(dir.path(), 4);
    let db = Connection::open(&path).unwrap();
    let original = storage_rows(&db, "buckets");
    let metadata = storage_rows(&db, "quota");
    drop(db);
    let report = cookie_scan(&profile);
    let id = report.records.iter().find(|r| r.actionable()).unwrap().id;
    let receipt = firefox_clean(dir.path(), &report, &[id]);
    assert_eq!(receipt.deleted, 1);
    let data = dir.path().join("app-data");
    let options = list_privacy_restore_options(&data).unwrap();
    assert_eq!(options.len(), 1);
    let plan = prepare_privacy_restore_with_runtime(&data, options[0].id, &EmptyRuntime).unwrap();
    assert!(
        restore_privacy_database_with_runtime(&data, &plan, &EmptyRuntime)
            .unwrap()
            .restored
    );
    let db = Connection::open(path).unwrap();
    assert_eq!(storage_rows(&db, "buckets"), original);
    assert_eq!(storage_rows(&db, "quota"), metadata);
}

fn storage_rows(db: &Connection, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
    let mut statement = db
        .prepare(&format!("SELECT rowid,* FROM {table} ORDER BY rowid"))
        .unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| {
            (0..columns)
                .map(|column| row.get(column))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn webapps_database(path: &Path, legacy: bool, current: bool) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = Connection::open(path).unwrap();
    for (enabled, table, column, example, keep) in [
        (
            legacy,
            "webappsstore",
            "domain",
            "tset.elpmaxe.",
            "tset.peek.",
        ),
        (
            current,
            "webappsstore2",
            "scope",
            "tset.elpmaxe.:https:443",
            "tset.peek.:https:443",
        ),
    ] {
        if !enabled {
            continue;
        }
        db.execute_batch(&format!(
            "CREATE TABLE {table}({column} TEXT,key TEXT,value TEXT,secure INTEGER,owner TEXT)"
        ))
        .unwrap();
        for (label, key, value) in [
            (Some(example), "a", "private-a"),
            (Some(example), "b", "private-b"),
            (Some(keep), "c", "private-keep"),
            (Some("foo"), "d", "private-ineligible"),
            (None, "e", "private-null"),
            (Some(""), "f", "private-empty"),
        ] {
            db.execute(
                &format!("INSERT INTO {table} VALUES(?1,?2,?3,1,'owned')"),
                rusqlite::params![label, key, value],
            )
            .unwrap();
        }
    }
    if !legacy && !current {
        db.execute_batch("CREATE TABLE unknown(value TEXT)")
            .unwrap();
    }
}

fn websql_database(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE Databases(id INTEGER PRIMARY KEY,origin TEXT,name TEXT,description TEXT,estimated_size INTEGER);
        INSERT INTO Databases VALUES(1,'https_example.test_0','a','private-a',1),(2,'https_example.test_0','b','private-b',2),(3,'http_keep.test_0','c','private-keep',3),(4,'https://plain.test/','d','private-url',4),(5,'HTTPS_upper.test_0','e','private-upper',5),(6,NULL,'f','private-null',6),(0,'http_zero.test_0','g','private-zero',0);").unwrap();
}

#[test]
fn mozilla_webapps_schema_variants_match_derived_candidates_and_preserve_unreviewed_shared_keys() {
    for browser in [Browser::Firefox, Browser::Thunderbird] {
        for (legacy, current) in [(true, false), (false, true), (true, true), (false, false)] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("profile");
            let path = root.join("webappsstore.sqlite");
            webapps_database(&path, legacy, current);
            let db = Connection::open(&path).unwrap();
            let mut original = Vec::new();
            for (enabled, table, select) in [
                (
                    legacy,
                    "webappsstore",
                    "SELECT domain,domain FROM webappsstore",
                ),
                (
                    current,
                    "webappsstore2",
                    "SELECT scope,scope FROM webappsstore2",
                ),
            ] {
                if enabled {
                    // Independently execute each recovered native SELECT. Three
                    // of six fixture rows have nonempty transformed labels.
                    assert_eq!(
                        db.prepare(select)
                            .unwrap()
                            .query_map([], |r| r.get::<_, Option<String>>(0))
                            .unwrap()
                            .count(),
                        6
                    );
                    original.push((table, storage_rows(&db, table)));
                }
            }
            let profile = BrowserProfile {
                browser,
                id: "owned".into(),
                name: "Owned".into(),
                root,
            };
            let before = fs::read(&path).unwrap();
            let plain = cookie_scan(&profile);
            let tables = usize::from(legacy) + usize::from(current);
            assert_eq!(plain.partial, tables == 0, "{:?}", plain.skipped);
            assert_eq!(plain.records.len(), tables * 3);
            assert_eq!(fs::read(&path).unwrap(), before);
            if tables == 0 {
                continue;
            }
            let settings =
                save_cookie_exception_settings(&dir.path().join("settings"), &["keep.test".into()])
                    .unwrap();
            let report = scan_profiles_with_settings(
                &[profile],
                &[PrivacyCategory::Cookies],
                &settings,
                &AtomicBool::new(false),
                |_| {},
            );
            assert!(!report.partial, "{:?}", report.skipped);
            assert_eq!(report.cookie_exempted, tables);
            assert_eq!(report.records.len(), tables * 2);
            assert!(report.records.iter().all(|row| row.site == "example.test"));
            let receipt = firefox_clean(dir.path(), &report, &[report.records[0].id]);
            assert_eq!(
                (receipt.deleted, receipt.skipped),
                (1, 0),
                "{:?}",
                receipt.errors
            );
            assert_eq!(receipt.backups.len(), 1);
            for (index, (table, mut rows)) in original.into_iter().enumerate() {
                if index == 0 {
                    rows.remove(0);
                }
                assert_eq!(storage_rows(&db, table), rows);
            }
        }
    }
}

#[test]
fn all_thirteen_websql_families_scan_nested_metadata_without_touching_origin_payloads() {
    for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("profile");
        let paths = [
            root.join("databases/Databases.db"),
            root.join("databases/archive/deeper/Databases.DB"),
        ];
        for path in &paths {
            websql_database(path);
        }
        let payload = root.join("databases/https_example.test_0/1");
        fs::create_dir_all(payload.parent().unwrap()).unwrap();
        fs::write(&payload, b"unreviewed origin payload").unwrap();
        let before = paths
            .iter()
            .map(|path| fs::read(path).unwrap())
            .collect::<Vec<_>>();
        let originals = paths
            .iter()
            .map(|path| storage_rows(&Connection::open(path).unwrap(), "Databases"))
            .collect::<Vec<_>>();
        for path in &paths {
            let db = Connection::open(path).unwrap();
            assert_eq!(
                db.prepare("select origin,id from Databases;")
                    .unwrap()
                    .query_map([], |r| r.get::<_, i64>(1))
                    .unwrap()
                    .count(),
                7
            );
        }
        let profile = BrowserProfile {
            browser,
            id: "owned".into(),
            name: "Owned".into(),
            root,
        };
        let plain = cookie_scan(&profile);
        assert!(!plain.partial, "{browser:?}: {:?}", plain.skipped);
        assert_eq!(plain.records.len(), 9);
        assert_eq!(
            plain
                .records
                .iter()
                .filter(|record| record.size_bytes().is_none())
                .count(),
            8
        );
        assert_eq!(
            plain
                .records
                .iter()
                .filter(|record| record.size_bytes().is_some())
                .count(),
            1
        );
        for (path, bytes) in paths.iter().zip(before) {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
        let settings =
            save_cookie_exception_settings(&dir.path().join("settings"), &["keep.test".into()])
                .unwrap();
        let report = scan_profiles_with_settings(
            &[profile],
            &[PrivacyCategory::Cookies],
            &settings,
            &AtomicBool::new(false),
            |_| {},
        );
        assert!(!report.partial, "{:?}", report.skipped);
        assert_eq!((report.records.len(), report.cookie_exempted), (7, 2));
        assert_eq!(
            report
                .records
                .iter()
                .filter(|row| row.site == "zero.test")
                .count(),
            2
        );
        let id = report
            .records
            .iter()
            .find(|row| row.site == "example.test" && row.size_bytes().is_none())
            .unwrap()
            .id;
        let receipt = firefox_clean(dir.path(), &report, &[id]);
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (1, 0),
            "{:?}",
            receipt.errors
        );
        assert_eq!(receipt.backups.len(), 1);
        let mut removed = 0;
        for (path, mut old) in paths.iter().zip(originals) {
            let db = Connection::open(path).unwrap();
            let now = storage_rows(&db, "Databases");
            if now.len() + 1 == old.len() {
                old.retain(|row| row[0] != rusqlite::types::Value::Integer(1));
                removed += 1;
            }
            assert_eq!(now, old);
        }
        assert_eq!(removed, 1);
        assert_eq!(fs::read(payload).unwrap(), b"unreviewed origin payload");
    }
}

#[test]
fn tagged_storage_wal_changes_invalidate_rows_and_new_shared_keys_do_not_expand_effects() {
    for table in ["webappsstore", "webappsstore2", "Databases"] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("profile");
        let websql = table == "Databases";
        let path = root.join(if websql {
            "databases/nested/Databases.db"
        } else {
            "webappsstore.sqlite"
        });
        if websql {
            websql_database(&path);
        } else {
            webapps_database(&path, table == "webappsstore", table == "webappsstore2");
        }
        let db = Connection::open(&path).unwrap();
        db.execute_batch(
            "PRAGMA journal_mode=WAL;PRAGMA wal_autocheckpoint=0;PRAGMA wal_checkpoint(TRUNCATE);",
        )
        .unwrap();
        let profile = BrowserProfile {
            browser: if websql {
                Browser::Brave
            } else {
                Browser::Firefox
            },
            id: "owned".into(),
            name: "Owned".into(),
            root,
        };
        let report = cookie_scan(&profile);
        assert!(!report.partial, "{:?}", report.skipped);
        let ids = report
            .records
            .iter()
            .filter(|row| row.site == "example.test")
            .map(|row| row.id)
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 2);
        let before = fs::read(&path).unwrap();
        let value = if websql { "description" } else { "value" };
        db.execute(
            &format!("UPDATE {table} SET {value}='changed-private' WHERE rowid=1"),
            [],
        )
        .unwrap();
        if websql {
            db.execute_batch(
                "INSERT INTO Databases VALUES(7,'https_example.test_0','new','new-private',0)",
            )
            .unwrap();
        } else {
            let column = if table == "webappsstore" {
                "domain"
            } else {
                "scope"
            };
            db.execute(&format!("INSERT INTO {table}({column},key,value) SELECT {column},'new','new-private' FROM {table} WHERE rowid=1"),[]).unwrap();
        }
        assert_eq!(fs::read(&path).unwrap(), before);
        let changed = storage_rows(&db, table);
        let receipt = firefox_clean(dir.path(), &report, &ids);
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (1, 1),
            "{:?}",
            receipt.errors
        );
        let expected = changed
            .into_iter()
            .filter(|row| row[0] != rusqlite::types::Value::Integer(2))
            .collect::<Vec<_>>();
        assert_eq!(storage_rows(&db, table), expected);
    }
}

#[test]
fn tagged_storage_unknown_schema_objects_dependencies_and_rowid_aliases_remain_explicit() {
    for table in ["webappsstore", "webappsstore2", "Databases"] {
        for variant in ["trigger", "dependency", "alias", "view"] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("profile");
            let websql = table == "Databases";
            let path = root.join(if websql {
                "databases/Databases.db"
            } else {
                "webappsstore.sqlite"
            });
            if websql {
                websql_database(&path);
            } else {
                webapps_database(&path, table == "webappsstore", table == "webappsstore2");
            }
            let db = Connection::open(&path).unwrap();
            match variant {
                "trigger"=>db.execute_batch(&format!("CREATE TABLE audit(value TEXT);CREATE TRIGGER owned AFTER DELETE ON {table} BEGIN INSERT INTO audit VALUES('effect');END;")).unwrap(),
                "dependency"=>db.execute_batch(&format!("CREATE TABLE dependent(parent INTEGER REFERENCES {table}(rowid) ON DELETE CASCADE)")).unwrap(),
                "alias"=>{db.execute(&format!("ALTER TABLE {table} ADD COLUMN rowid INTEGER"),[]).unwrap();},
                _=>db.execute_batch(&format!("ALTER TABLE {table} RENAME TO owned_source;CREATE VIEW {table} AS SELECT * FROM owned_source;")).unwrap(),
            }
            let profile = BrowserProfile {
                browser: if websql {
                    Browser::Chrome
                } else {
                    Browser::Firefox
                },
                id: "owned".into(),
                name: "Owned".into(),
                root,
            };
            let before = fs::read(&path).unwrap();
            let report = cookie_scan(&profile);
            assert!(report.partial, "{table}/{variant}");
            assert!(report.records.is_empty());
            assert_eq!(fs::read(&path).unwrap(), before);
            if variant == "trigger" {
                assert_eq!(
                    db.query_row("SELECT count(*) FROM audit", [], |r| r.get::<_, i64>(0))
                        .unwrap(),
                    0
                );
            }
        }
    }
}

#[cfg(windows)]
#[test]
fn websql_junctions_are_rejected_and_cookie_path_errors_do_not_bleed_into_history_scans() {
    use std::os::windows::process::CommandExt;
    for nested in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("profile");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&root).unwrap();
        websql_database(&outside.join("Databases.db"));
        let link = if nested {
            root.join("databases").join("nested")
        } else {
            root.join("databases")
        };
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        let output = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let profile = BrowserProfile {
            browser: Browser::Chrome,
            id: "owned".into(),
            name: "Owned".into(),
            root,
        };
        let before = fs::read(outside.join("Databases.db")).unwrap();
        let cookies = cookie_scan(&profile);
        assert!(cookies.partial && cookies.records.is_empty());
        let history = scan_profiles_with_settings(
            &[profile],
            &[PrivacyCategory::History],
            &Default::default(),
            &AtomicBool::new(false),
            |_| {},
        );
        assert!(!history.partial, "{:?}", history.skipped);
        assert!(history.records.is_empty());
        assert_eq!(fs::read(outside.join("Databases.db")).unwrap(), before);
        fs::remove_dir(link).unwrap();
    }
}

#[test]
fn tagged_storage_backups_restore_both_shared_tables_and_nested_metadata() {
    for websql in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("profile");
        let path = root.join(if websql {
            "databases/nested/Databases.db"
        } else {
            "webappsstore.sqlite"
        });
        if websql {
            websql_database(&path);
        } else {
            webapps_database(&path, true, true);
        }
        let tables = if websql {
            vec!["Databases"]
        } else {
            vec!["webappsstore", "webappsstore2"]
        };
        let original = tables
            .iter()
            .map(|table| storage_rows(&Connection::open(&path).unwrap(), table))
            .collect::<Vec<_>>();
        let profile = BrowserProfile {
            browser: if websql {
                Browser::Opera
            } else {
                Browser::Thunderbird
            },
            id: "owned".into(),
            name: "Owned".into(),
            root,
        };
        let report = cookie_scan(&profile);
        assert!(!report.partial, "{:?}", report.skipped);
        let ids = report
            .records
            .iter()
            .filter(|row| row.site == "example.test")
            .map(|row| row.id)
            .collect::<Vec<_>>();
        let receipt = firefox_clean(dir.path(), &report, &ids);
        assert_eq!(receipt.deleted, ids.len(), "{:?}", receipt.errors);
        assert_eq!(receipt.backups.len(), 1);
        let data = dir.path().join("app-data");
        let options = list_privacy_restore_options(&data).unwrap();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].state, PrivacyRecoveryState::Ready);
        let plan =
            prepare_privacy_restore_with_runtime(&data, options[0].id, &EmptyRuntime).unwrap();
        assert!(
            restore_privacy_database_with_runtime(&data, &plan, &EmptyRuntime)
                .unwrap()
                .restored
        );
        let db = Connection::open(path).unwrap();
        for (table, expected) in tables.into_iter().zip(original) {
            assert_eq!(storage_rows(&db, table), expected);
        }
    }
}

fn cookie_database(path: &Path, mozilla: bool) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = Connection::open(path).unwrap();
    db.execute_batch(if mozilla {
        "CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY,host TEXT,name TEXT,path TEXT,expiry INTEGER,creationTime INTEGER,lastAccessed INTEGER,value TEXT);
         INSERT INTO moz_cookies VALUES(1,'.example.test','session','/',999,10,20,'private-cookie'),(2,'.other.test','session','/',999,10,20,'private-cookie');"
    } else {
        "CREATE TABLE cookies(host_key TEXT,name TEXT,path TEXT,expires_utc INTEGER,creation_utc INTEGER,last_access_utc INTEGER,encrypted_value BLOB);
         INSERT INTO cookies VALUES('.example.test','session','/',999,10,20,X'736563726574'),('.other.test','session','/',999,10,20,X'736563726574');"
    }).unwrap();
}

fn certificate_database(path: &Path, origins: bool, channels: bool) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = Connection::open(path).unwrap();
    if origins {
        db.execute_batch("CREATE TABLE origin_bound_certs(origin TEXT,creation_time INTEGER,private_key BLOB,certificate BLOB);
            INSERT INTO origin_bound_certs VALUES('https://selected.test',10,X'736563726574',X'61'),('https://keep.test',10,X'736563726574',X'62');").unwrap();
    }
    if channels {
        db.execute_batch("CREATE TABLE channel_id(host TEXT,creation_time INTEGER,private_key BLOB);
            INSERT INTO channel_id VALUES('selected.test',10,X'736563726574'),('keep.test',10,X'736563726574');").unwrap();
    }
    if !origins && !channels {
        db.execute_batch("CREATE TABLE unknown(value TEXT)")
            .unwrap();
    }
}

fn direct_cookie_tables(browser: Browser) -> Vec<(&'static str, &'static str, &'static str)> {
    if browser.is_chromium() {
        vec![
            ("Cookies", "cookies", "host_key"),
            ("Origin Bound Certs", "origin_bound_certs", "origin"),
            ("Origin Bound Certs", "channel_id", "host"),
        ]
    } else {
        vec![
            ("cookies.sqlite", "moz_cookies", "host"),
            ("permissions.sqlite", "moz_hosts", "host"),
        ]
    }
}

fn direct_cookie_table_fixture(path: &Path, table: &str) {
    match table {
        "cookies" => cookie_database(path, false),
        "moz_cookies" => cookie_database(path, true),
        "origin_bound_certs" => certificate_database(path, true, false),
        "channel_id" => certificate_database(path, false, true),
        "moz_hosts" => {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            Connection::open(path).unwrap().execute_batch(
                "CREATE TABLE moz_hosts(id INTEGER PRIMARY KEY,host TEXT,type TEXT DEFAULT 'offline-app',permission INTEGER DEFAULT 1)"
            ).unwrap();
        }
        _ => unreachable!(),
    }
    Connection::open(path)
        .unwrap()
        .execute(&format!("DELETE FROM {table}"), [])
        .unwrap();
}

#[test]
fn all_direct_cookie_adapters_apply_native_empty_gates_normalization_and_exact_reviewed_effects() {
    use rusqlite::types::Value;
    for &browser in Browser::ALL {
        for (file, table, host) in direct_cookie_tables(browser) {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("profile");
            let path = root.join(file);
            direct_cookie_table_fixture(&path, table);
            let db = Connection::open(&path).unwrap();
            let key = match table {
                "cookies" => "creation_utc",
                "origin_bound_certs" | "channel_id" => "creation_time",
                _ => "id",
            };
            let mut inputs = vec![
                (1, Value::Text(".SELECTED.TEST".into()), Value::Integer(10)),
                (2, Value::Text("".into()), Value::Integer(10)),
                (3, Value::Null, Value::Integer(10)),
                (4, Value::Text(".".into()), Value::Integer(10)),
                (5, Value::Text("/".into()), Value::Integer(10)),
                (6, Value::Text("user@".into()), Value::Integer(10)),
                (7, Value::Text("\0hidden.test".into()), Value::Integer(10)),
                (
                    8,
                    Value::Text("nul.test\0hidden-payload".into()),
                    Value::Integer(10),
                ),
                (
                    9,
                    Value::Text("Cookie:#HttpOnly_.KEEP.TEST/".into()),
                    Value::Integer(10),
                ),
                (
                    10,
                    Value::Text("DOMStore:https://SECOND.TEST/".into()),
                    Value::Integer(10),
                ),
                (11, Value::Integer(123), Value::Integer(10)),
                (12, Value::Blob(b".BLOB.TEST".to_vec()), Value::Integer(10)),
            ];
            let mut expected = vec![
                "123",
                "blob.test",
                "keep.test",
                "nul.test",
                "second.test",
                "selected.test",
            ];
            if key != "id" {
                inputs.extend([
                    (13, Value::Text("null-key.test".into()), Value::Null),
                    (
                        14,
                        Value::Text("empty-key.test".into()),
                        Value::Text("".into()),
                    ),
                    (
                        15,
                        Value::Text("nul-key.test".into()),
                        Value::Text("\0hidden".into()),
                    ),
                    (16, Value::Text("zero-key.test".into()), Value::Integer(0)),
                    (
                        17,
                        Value::Text("empty-blob-key.test".into()),
                        Value::Blob(vec![]),
                    ),
                    (
                        18,
                        Value::Text("nul-blob-key.test".into()),
                        Value::Blob(b"\0hidden".to_vec()),
                    ),
                    (
                        19,
                        Value::Text("blob-key.test".into()),
                        Value::Blob(b"10".to_vec()),
                    ),
                    (20, Value::Text("real-key.test".into()), Value::Real(0.5)),
                ]);
                expected.extend(["blob-key.test", "real-key.test", "zero-key.test"]);
            }
            for (id, label, raw_key) in &inputs {
                if key == "id" {
                    db.execute(
                        &format!("INSERT INTO {table}(id,{host}) VALUES(?1,?2)"),
                        rusqlite::params![id, label],
                    )
                    .unwrap();
                } else {
                    db.execute(
                        &format!("INSERT INTO {table}(rowid,{host},{key}) VALUES(?1,?2,?3)"),
                        rusqlite::params![id, label, raw_key],
                    )
                    .unwrap();
                }
            }
            let read_rows = || {
                let mut statement = db
                    .prepare(&format!("SELECT rowid,* FROM {table} ORDER BY rowid"))
                    .unwrap();
                let columns = statement.column_count();
                statement
                    .query_map([], |row| {
                        (0..columns)
                            .map(|column| row.get::<_, Value>(column))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
            };
            let original_rows = read_rows();
            let profile = BrowserProfile {
                browser,
                id: "owned".into(),
                name: "Owned".into(),
                root,
            };
            let before = fs::read(&path).unwrap();
            let report = cookie_scan(&profile);
            assert!(!report.partial, "{browser:?}/{table}: {:?}", report.skipped);
            let mut actual = report
                .records
                .iter()
                .map(|r| r.site.as_str())
                .collect::<Vec<_>>();
            actual.sort();
            expected.sort();
            assert_eq!(actual, expected, "{browser:?}/{table}");
            assert_eq!(fs::read(&path).unwrap(), before);
            // Our saved keep-domain policy operates on the normalized public
            // site; this is not a claim about the unrecovered native matcher.
            let settings =
                save_cookie_exception_settings(&dir.path().join("settings"), &["keep.test".into()])
                    .unwrap();
            let report = scan_profiles_with_settings(
                &[profile],
                &[PrivacyCategory::Cookies],
                &settings,
                &AtomicBool::new(false),
                |_| {},
            );
            assert!(!report.partial, "{:?}", report.skipped);
            assert_eq!(report.cookie_exempted, 1);
            assert_eq!(report.records.len(), expected.len() - 1);
            let ids = report.records.iter().map(|r| r.id).collect::<Vec<_>>();
            let receipt = firefox_clean(dir.path(), &report, &ids);
            assert_eq!(
                (receipt.deleted, receipt.skipped),
                (ids.len(), 0),
                "{:?}",
                receipt.errors
            );
            // Complete typed input values of ineligible/kept rows survive, even
            // when native timestamp cleanup keys collide with selected rows.
            let expected_remaining = original_rows
                .into_iter()
                .filter(|row| {
                    !matches!(row[0], Value::Integer(1 | 8 | 10 | 11 | 12 | 16 | 19 | 20))
                })
                .collect::<Vec<_>>();
            assert_eq!(read_rows(), expected_remaining);
        }
    }
}

#[test]
fn malformed_utf16_cookie_blob_labels_or_keys_are_explicit_scan_gaps() {
    for browser in [Browser::Chrome, Browser::Firefox] {
        for (file, table, host) in direct_cookie_tables(browser) {
            for encoding in ["UTF-16le", "UTF-16be", "UTF-8"] {
                for column in ["host", "key"] {
                    if column == "key" && !browser.is_chromium() {
                        continue;
                    }
                    let dir = tempfile::tempdir().unwrap();
                    let root = dir.path().join("profile");
                    fs::create_dir_all(&root).unwrap();
                    let path = root.join(file);
                    let db = Connection::open(&path).unwrap();
                    db.execute_batch(&format!(
                        "PRAGMA encoding='{encoding}';CREATE TABLE encoding_witness(value TEXT)"
                    ))
                    .unwrap();
                    direct_cookie_table_fixture(&path, table);
                    let key = match table {
                        "cookies" => "creation_utc",
                        "origin_bound_certs" | "channel_id" => "creation_time",
                        _ => "id",
                    };
                    if key == "id" {
                        db.execute(
                            &format!("INSERT INTO {table}(id,{host}) VALUES(1,X'61')"),
                            [],
                        )
                        .unwrap();
                    } else {
                        let values = if column == "host" {
                            "1,X'61',10"
                        } else {
                            "1,'owned.test',X'31'"
                        };
                        db.execute(
                            &format!("INSERT INTO {table}(rowid,{host},{key}) VALUES({values})"),
                            [],
                        )
                        .unwrap();
                    }
                    let profile = BrowserProfile {
                        browser,
                        id: "owned".into(),
                        name: "Owned".into(),
                        root,
                    };
                    let before = fs::read(&path).unwrap();
                    let report = cookie_scan(&profile);
                    assert_eq!(fs::read(&path).unwrap(), before);
                    if encoding == "UTF-8" {
                        assert!(!report.partial, "{:?}", report.skipped);
                        assert_eq!(report.records.len(), 1);
                    } else {
                        assert!(report.partial);
                        assert!(report.records.is_empty());
                        assert!(format!("{:?}", report.skipped).contains("odd-byte UTF-16"));
                    }
                    assert_eq!(
                        db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                            .get::<_, i64>(0))
                            .unwrap(),
                        1
                    );
                }
            }
        }
    }
}

#[test]
fn direct_cookie_wal_eligibility_drift_never_expands_reviewed_cleanup() {
    for browser in [Browser::Chrome, Browser::Firefox] {
        for (file, table, host) in direct_cookie_tables(browser) {
            for changed in ["host", "key", "nul-suffix", "stable"] {
                if changed == "key" && !browser.is_chromium() {
                    continue;
                }
                let dir = tempfile::tempdir().unwrap();
                let root = dir.path().join("profile");
                let path = root.join(file);
                direct_cookie_table_fixture(&path, table);
                let key = if table == "cookies" {
                    "creation_utc"
                } else if browser.is_chromium() {
                    "creation_time"
                } else {
                    "id"
                };
                let db = Connection::open(&path).unwrap();
                let sql = if key == "id" {
                    format!("INSERT INTO {table}(id,{host}) VALUES(1,?1),(2,'')")
                } else {
                    format!("INSERT INTO {table}(rowid,{host},{key}) VALUES(1,?1,10),(2,'',10)")
                };
                db.execute(&sql, ["reviewed.test\0private-before"]).unwrap();
                db.execute_batch("PRAGMA journal_mode=WAL;PRAGMA wal_autocheckpoint=0;PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
                let profile = BrowserProfile {
                    browser,
                    id: "owned".into(),
                    name: "Owned".into(),
                    root,
                };
                let report = cookie_scan(&profile);
                assert!(!report.partial, "{:?}", report.skipped);
                assert_eq!(report.records.len(), 1);
                assert_eq!(report.records[0].site, "reviewed.test");
                let before = fs::read(&path).unwrap();
                if changed == "key" {
                    db.execute(&format!("UPDATE {table} SET {key}=NULL WHERE rowid=1"), [])
                        .unwrap();
                } else if changed != "stable" {
                    db.execute(
                        &format!("UPDATE {table} SET {host}=?1 WHERE rowid=1"),
                        [if changed == "host" {
                            ""
                        } else {
                            "reviewed.test\0private-after"
                        }],
                    )
                    .unwrap();
                }
                db.execute(
                    &format!("UPDATE {table} SET {host}='newly-eligible.test' WHERE rowid=2"),
                    [],
                )
                .unwrap();
                assert_eq!(fs::read(&path).unwrap(), before);
                let receipt = firefox_clean(dir.path(), &report, &[report.records[0].id]);
                assert_eq!(
                    (receipt.deleted, receipt.skipped),
                    if changed == "stable" { (1, 0) } else { (0, 1) },
                    "{:?}",
                    receipt.errors
                );
                assert_eq!(
                    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get::<_, i64>(0))
                        .unwrap(),
                    if changed == "stable" { 1 } else { 2 }
                );
                assert_eq!(
                    db.query_row(
                        &format!("SELECT {host} FROM {table} WHERE rowid=2"),
                        [],
                        |r| r.get::<_, String>(0)
                    )
                    .unwrap(),
                    "newly-eligible.test"
                );
            }
        }
    }
}

#[test]
fn all_thirteen_certificate_stores_match_native_candidate_queries_and_preserve_timestamp_collisions()
 {
    for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("profile");
        let path = root.join("Origin Bound Certs");
        certificate_database(&path, true, true);
        let profile = BrowserProfile {
            browser,
            id: "owned".into(),
            name: "Owned".into(),
            root,
        };
        let before = fs::read(&path).unwrap();
        let db = Connection::open(&path).unwrap();
        // Independently execute the statically recovered select templates.
        let mut native_candidates = Vec::new();
        for sql in [
            "select origin as host_key, creation_time as creation_utc from origin_bound_certs;",
            "select host as host_key, creation_time as creation_utc from channel_id;",
        ] {
            native_candidates.extend(
                db.prepare(sql)
                    .unwrap()
                    .query_map([], |r| r.get::<_, String>(0))
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
            );
        }
        drop(db);
        let report = cookie_scan(&profile);
        assert!(!report.partial, "{}: {:?}", browser.label(), report.skipped);
        assert_eq!(report.records.len(), native_candidates.len());
        assert_eq!(report.records.len(), 4);
        assert_eq!(fs::read(&path).unwrap(), before);
        let selected = report
            .records
            .iter()
            .filter(|r| r.site == "selected.test")
            .map(|r| r.id)
            .collect::<Vec<_>>();
        assert_eq!(selected.len(), 2);
        let receipt = firefox_clean(dir.path(), &report, &selected);
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (2, 0),
            "{:?}",
            receipt.errors
        );
        assert_eq!(receipt.backups.len(), 1);
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row("SELECT origin FROM origin_bound_certs", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "https://keep.test"
        );
        assert_eq!(
            db.query_row("SELECT host FROM channel_id", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "keep.test"
        );
    }
}

#[test]
fn certificate_schema_variants_missing_stores_and_cookie_exclusions_are_distinguished() {
    for (origins, channels) in [(true, false), (false, true), (false, false)] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("profile");
        certificate_database(&root.join("Origin Bound Certs"), origins, channels);
        let profile = BrowserProfile {
            browser: Browser::Brave,
            id: "owned".into(),
            name: "Owned".into(),
            root,
        };
        let settings =
            save_cookie_exception_settings(&dir.path().join("settings"), &["keep.test".into()])
                .unwrap();
        let report = scan_profiles_with_settings(
            &[profile],
            &[PrivacyCategory::Cookies],
            &settings,
            &AtomicBool::new(false),
            |_| {},
        );
        assert_eq!(
            report.partial,
            !origins && !channels,
            "{:?}",
            report.skipped
        );
        assert_eq!(report.records.len(), usize::from(origins || channels));
        assert_eq!(report.cookie_exempted, usize::from(origins || channels));
        assert!(report.records.iter().all(|r| r.site == "selected.test"));
    }
}

#[test]
fn certificate_wal_drift_rejects_changed_key_but_allows_independently_reviewed_channel() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("profile");
    let path = root.join("Origin Bound Certs");
    certificate_database(&path, true, true);
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .unwrap();
    let profile = BrowserProfile {
        browser: Browser::Chrome,
        id: "owned".into(),
        name: "Owned".into(),
        root,
    };
    let report = cookie_scan(&profile);
    let before = fs::read(&path).unwrap();
    db.execute_batch("UPDATE origin_bound_certs SET private_key=X'6368616E676564' WHERE rowid=1")
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
    let ids = report
        .records
        .iter()
        .filter(|r| r.site == "selected.test")
        .map(|r| r.id)
        .collect::<Vec<_>>();
    let receipt = firefox_clean(dir.path(), &report, &ids);
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (1, 1),
        "{:?}",
        receipt.errors
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM origin_bound_certs", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        db.query_row("SELECT host FROM channel_id", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "keep.test"
    );
}

#[test]
fn mozilla_offline_permissions_match_native_filter_and_leave_other_permissions_untouched() {
    for browser in [Browser::Firefox, Browser::Thunderbird] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("profile");
        cookie_database(&root.join("cookies.sqlite"), true);
        let path = root.join("permissions.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE moz_hosts(id INTEGER PRIMARY KEY,host TEXT,type TEXT,permission INTEGER,extra BLOB);
            INSERT INTO moz_hosts VALUES(1,'selected.test','offline-app',1,X'736563726574'),(2,'keep.test','offline-app',1,X'736563726574'),(3,'selected.test','offline-app',2,NULL),(4,'selected.test','camera',1,NULL),(5,'selected.test','OFFLINE-APP',1,NULL);").unwrap();
        let native = db
            .prepare("SELECT host,id FROM moz_hosts where type='offline-app' and permission=1")
            .unwrap()
            .query_map([], |r| r.get::<_, i64>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(native, [1, 2]);
        let profile = BrowserProfile {
            browser,
            id: "owned".into(),
            name: "Owned".into(),
            root,
        };
        let before = fs::read(&path).unwrap();
        let report = cookie_scan(&profile);
        assert!(!report.partial, "{:?}", report.skipped);
        assert_eq!(report.records.len(), 4); // Two cookies plus two offline permissions.
        assert_eq!(fs::read(&path).unwrap(), before);
        let ids = report
            .records
            .iter()
            .filter(|r| r.site == "selected.test")
            .map(|r| r.id)
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 1);
        let receipt = firefox_clean(dir.path(), &report, &ids);
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (1, 0),
            "{:?}",
            receipt.errors
        );
        let remaining = db
            .prepare("SELECT id FROM moz_hosts ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(remaining, [2, 3, 4, 5]);
    }
}

#[test]
fn offline_permission_wal_eligibility_drift_prevents_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("profile");
    cookie_database(&root.join("cookies.sqlite"), true);
    let path = root.join("permissions.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TABLE moz_hosts(id INTEGER PRIMARY KEY,host TEXT,type TEXT,permission INTEGER);
        INSERT INTO moz_hosts VALUES(1,'selected.test','offline-app',1);
        PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .unwrap();
    let profile = BrowserProfile {
        browser: Browser::Firefox,
        id: "owned".into(),
        name: "Owned".into(),
        root,
    };
    let report = cookie_scan(&profile);
    let before = fs::read(&path).unwrap();
    db.execute_batch("UPDATE moz_hosts SET permission=2 WHERE id=1")
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
    let ids = report
        .records
        .iter()
        .filter(|r| r.site == "selected.test")
        .map(|r| r.id)
        .collect::<Vec<_>>();
    let receipt = firefox_clean(dir.path(), &report, &ids);
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (0, 1),
        "{:?}",
        receipt.errors
    );
    assert_eq!(
        db.query_row("SELECT permission FROM moz_hosts WHERE id=1", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn all_chromium_families_review_all_three_cookie_stores_and_keep_unselected_timestamp_collisions() {
    for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("profile");
        let paths = ["Cookies", "Network/Cookies", "Extension Cookies"].map(|p| root.join(p));
        for path in &paths {
            cookie_database(path, false);
        }
        let profile = BrowserProfile {
            browser,
            id: "owned-cookie-profile".into(),
            name: "Owned cookies".into(),
            root: dunce::canonicalize(&root).unwrap(),
        };
        let before = paths.each_ref().map(|path| fs::read(path).unwrap());
        let report = cookie_scan(&profile);
        assert!(!report.partial, "{}: {:?}", browser.label(), report.skipped);
        assert_eq!(report.records.len(), 6);
        assert_eq!(
            report.records.iter().map(|r| r.item_count()).sum::<usize>(),
            6
        );
        for (path, before) in paths.iter().zip(before) {
            assert_eq!(fs::read(path).unwrap(), before);
        }
        let ids = report
            .records
            .iter()
            .filter(|r| r.site == "example.test")
            .map(|r| r.id)
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 3);
        let receipt = firefox_clean(dir.path(), &report, &ids);
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (3, 0),
            "{:?}",
            receipt.errors
        );
        assert_eq!(receipt.backups.len(), 3);
        for path in &paths {
            let db = Connection::open(path).unwrap();
            let hosts = db
                .prepare("SELECT host_key FROM cookies")
                .unwrap()
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(hosts, [".other.test"]);
        }
    }
}

#[test]
fn optional_cookie_stores_are_empty_when_absent_and_legacy_extension_stores_scan_alone() {
    for browser in Browser::ALL.iter().copied() {
        let dir = tempfile::tempdir().unwrap();
        let profile = BrowserProfile {
            browser,
            id: "owned-empty".into(),
            name: "Owned empty".into(),
            root: dir.path().to_owned(),
        };
        let report = scan_fixture(&profile);
        assert!(!report.partial, "{}: {:?}", browser.label(), report.skipped);
        assert!(report.records.is_empty());
        assert_eq!(report.skipped_count, 0);
        fs::remove_dir(dir.path()).unwrap();
        assert!(
            scan_fixture(&profile).partial,
            "an unavailable profile must remain partial"
        );
    }
    for store in [None, Some("Cookies"), Some("Extension Cookies")] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("profile");
        fs::create_dir_all(&root).unwrap();
        if let Some(store) = store {
            cookie_database(&root.join(store), false);
        }
        let profile = BrowserProfile {
            browser: Browser::Chrome,
            id: "owned".into(),
            name: "Owned".into(),
            root,
        };
        let report = cookie_scan(&profile);
        assert!(!report.partial, "{:?}", report.skipped);
        assert_eq!(report.records.len(), if store.is_some() { 2 } else { 0 });
        assert!(!profile.root.join("Network").exists());
    }
}

#[test]
fn cookie_exclusions_apply_to_each_store_and_invalid_optional_parents_stay_partial() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("profile");
    for name in ["Cookies", "Network/Cookies", "Extension Cookies"] {
        cookie_database(&root.join(name), false);
    }
    let profile = BrowserProfile {
        browser: Browser::Chrome,
        id: "owned".into(),
        name: "Owned".into(),
        root,
    };
    let settings =
        save_cookie_exception_settings(&dir.path().join("settings"), &["example.test".into()])
            .unwrap();
    let report = scan_profiles_with_settings(
        &[profile.clone()],
        &[PrivacyCategory::Cookies],
        &settings,
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!((report.records.len(), report.cookie_exempted), (3, 3));
    assert!(report.records.iter().all(|r| r.site == "other.test"));
    fs::remove_file(profile.root.join("Network/Cookies")).unwrap();
    fs::remove_dir(profile.root.join("Network")).unwrap();
    fs::write(profile.root.join("Network"), b"invalid parent").unwrap();
    let report = cookie_scan(&profile);
    assert!(report.partial);
    assert_eq!(report.records.len(), 4);
    assert_eq!(report.skipped_count, 1);
}

#[test]
fn cookie_full_row_fingerprints_reject_wal_only_value_and_schema_drift_for_both_adapters() {
    for mozilla in [false, true] {
        for schema_drift in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("profile");
            let path = root.join(if mozilla { "cookies.sqlite" } else { "Cookies" });
            cookie_database(&path, mozilla);
            let keeper = Connection::open(&path).unwrap();
            keeper.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
            let profile = BrowserProfile {
                browser: if mozilla {
                    Browser::Firefox
                } else {
                    Browser::Chrome
                },
                id: "owned".into(),
                name: "Owned".into(),
                root,
            };
            let report = cookie_scan(&profile);
            assert!(!report.partial, "{:?}", report.skipped);
            let before = fs::read(&path).unwrap();
            let table = if mozilla { "moz_cookies" } else { "cookies" };
            if schema_drift {
                keeper
                    .execute_batch(&format!(
                        "ALTER TABLE {table} ADD COLUMN new_field TEXT DEFAULT 'new';"
                    ))
                    .unwrap();
            } else {
                keeper
                    .execute_batch(if mozilla {
                        "UPDATE moz_cookies SET value='changed-secret' WHERE id=1"
                    } else {
                        "UPDATE cookies SET encrypted_value=X'6368616E676564' WHERE rowid=1"
                    })
                    .unwrap();
            }
            assert_eq!(
                fs::read(&path).unwrap(),
                before,
                "fixture must change WAL only"
            );
            let ids = report
                .records
                .iter()
                .filter(|r| r.site == "example.test")
                .map(|r| r.id)
                .collect::<Vec<_>>();
            let receipt = firefox_clean(dir.path(), &report, &ids);
            assert_eq!(
                (receipt.deleted, receipt.skipped),
                (0, 1),
                "{:?}",
                receipt.errors
            );
            assert_eq!(
                keeper
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                2
            );
            let public_sites = report
                .records
                .iter()
                .map(|r| r.site.as_str())
                .collect::<Vec<_>>();
            assert!(!public_sites.join(" ").contains("private-cookie"));
            assert!(!public_sites.join(" ").contains("changed-secret"));
        }
    }
}

#[test]
fn cookie_cleanup_rejects_wal_added_triggers_before_unreviewed_effects() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let db = Connection::open(&fixture.cookies_path).unwrap();
    db.execute_batch("CREATE TABLE untouched(value TEXT); INSERT INTO untouched VALUES('keep'); PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
    let report = cookie_scan(&fixture.profile);
    let before = fs::read(&fixture.cookies_path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER unreviewed AFTER DELETE ON cookies BEGIN DELETE FROM untouched; END;",
    )
    .unwrap();
    assert_eq!(fs::read(&fixture.cookies_path).unwrap(), before);
    let receipt = firefox_clean(dir.path(), &report, &[report.records[0].id]);
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (0, 1),
        "{:?}",
        receipt.errors
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM untouched", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM cookies", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn cookie_unknown_dependencies_and_shadow_rowids_are_explicit_omissions() {
    for extra in [
        "CREATE TABLE dependent(cookie_id INTEGER REFERENCES cookies(rowid) ON DELETE CASCADE)",
        "ALTER TABLE cookies ADD COLUMN rowid INTEGER",
        "CREATE TABLE untouched(value TEXT); CREATE TRIGGER unknown_effect AFTER DELETE ON cookies BEGIN DELETE FROM untouched; END",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = chrome_fixture(dir.path());
        Connection::open(&fixture.cookies_path)
            .unwrap()
            .execute_batch(extra)
            .unwrap();
        let before = fs::read(&fixture.cookies_path).unwrap();
        let report = cookie_scan(&fixture.profile);
        assert!(report.partial);
        assert!(report.records.is_empty());
        assert_eq!(fs::read(&fixture.cookies_path).unwrap(), before);
    }
}

#[test]
fn mozilla_and_thunderbird_cookie_columns_and_selected_cleanup_accept_native_mixed_case_names() {
    for browser in [Browser::Firefox, Browser::Thunderbird] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("profile");
        let path = root.join("cookies.sqlite");
        cookie_database(&path, true);
        let profile = BrowserProfile {
            browser,
            id: "owned".into(),
            name: "Owned".into(),
            root,
        };
        let report = cookie_scan(&profile);
        assert!(!report.partial, "{:?}", report.skipped);
        assert_eq!(report.records.len(), 2);
        let selected = report
            .records
            .iter()
            .find(|r| r.site == "example.test")
            .unwrap()
            .id;
        let receipt = firefox_clean(dir.path(), &report, &[selected]);
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (1, 0),
            "{:?}",
            receipt.errors
        );
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row("SELECT id FROM moz_cookies", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
}

#[cfg(windows)]
#[test]
fn canonical_long_profile_paths_support_actual_sqlite_scan_and_reviewed_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let mut parent = dir.path().join("owned-long-profile");
    while parent.to_string_lossy().len() < 300 {
        parent = parent.join("owned-long-component-".repeat(3));
    }
    fs::create_dir_all(&parent).unwrap();
    let parent = dunce::canonicalize(parent).unwrap();
    let mut fixture = chrome_fixture(&parent);
    fixture.profile.browser = Browser::Brave;
    assert!(fixture.profile.root.to_string_lossy().len() > 260);
    let before = fs::read(&fixture.cookies_path).unwrap();
    let report = scan_fixture(&fixture.profile);
    assert!(!report.partial, "{:?}", report.skipped);
    let download = report
        .records
        .iter()
        .find(|r| r.category == PrivacyCategory::Downloads)
        .unwrap();
    assert_eq!(download.item_count(), 4);
    let receipt = firefox_clean(dir.path(), &report, &[download.id]);
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (1, 0),
        "{:?}",
        receipt.errors
    );
    assert_eq!(
        Connection::open(&fixture.history_path)
            .unwrap()
            .query_row("SELECT count(*) FROM downloads", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(fs::read(&fixture.cookies_path).unwrap(), before);
}

#[test]
fn all_thirteen_chromium_families_scan_and_clean_only_reviewed_download_rows() {
    let families = Browser::ALL
        .iter()
        .copied()
        .filter(|b| b.is_chromium())
        .collect::<Vec<_>>();
    assert_eq!(families.len(), 13);
    for browser in families {
        let dir = tempfile::tempdir().unwrap();
        let mut fixture = chrome_fixture(dir.path());
        fixture.profile.browser = browser;
        fixture.profile.id = format!("fixture-{}", browser.cache_category());
        let cookies = fs::read(&fixture.cookies_path).unwrap();
        let report = scan_fixture(&fixture.profile);
        assert!(!report.partial, "{}: {:?}", browser.label(), report.skipped);
        assert_eq!(report.records.len(), 5);
        assert!(report.records.iter().all(|r| r.browser == browser));
        let selected = report
            .records
            .iter()
            .find(|r| r.category == PrivacyCategory::Downloads)
            .unwrap();
        assert_eq!(selected.item_count(), 4);
        let receipt = firefox_clean(dir.path(), &report, &[selected.id]);
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (1, 0),
            "{}: {:?}",
            browser.label(),
            receipt.errors
        );
        let db = Connection::open(&fixture.history_path).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM downloads", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM urls", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(fs::read(&fixture.cookies_path).unwrap(), cookies);
    }
}

#[test]
fn thunderbird_routes_modern_places_downloads_through_the_guarded_mozilla_adapter() {
    let dir = tempfile::tempdir().unwrap();
    let (mut profile, path) = firefox_download_fixture(dir.path(), true);
    profile.browser = Browser::Thunderbird;
    let report = firefox_scan(&profile, &[PrivacyCategory::Downloads]);
    assert!(!report.partial);
    assert_eq!(
        report.records.iter().map(|r| r.item_count()).sum::<usize>(),
        11
    );
    assert!(
        report
            .records
            .iter()
            .all(|r| r.browser == Browser::Thunderbird)
    );
    let saved = report
        .records
        .iter()
        .find(|r| r.site == "saved.test")
        .unwrap();
    let receipt = firefox_clean(dir.path(), &report, &[saved.id]);
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (1, 0),
        "{:?}",
        receipt.errors
    );
    let db = Connection::open(path).unwrap();
    assert_eq!(firefox_ids(&db, "moz_places"), vec![1, 2, 3, 4, 5]);
    assert_eq!(firefox_ids(&db, "moz_annos"), vec![11, 12, 23, 31, 41, 51]);
}

#[test]
fn shared_opera_executable_blocks_gx_cleanup_and_both_restore_guards() {
    struct OperaRuntime;
    impl BrowserRuntime for OperaRuntime {
        fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
            Ok(vec![RunningBrowser {
                browser: Browser::Opera,
                pid: 42,
                executable: "opera.exe".into(),
            }])
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let mut fixture = chrome_fixture(dir.path());
    fixture.profile.browser = Browser::OperaGx;
    let report = scan_fixture(&fixture.profile);
    let selected = report
        .records
        .iter()
        .find(|r| r.category == PrivacyCategory::Downloads)
        .unwrap();
    let plan = build_cleanup_plan(&report, &[selected.id]).unwrap();
    let data = dir.path().join("app-data");
    let blocked = clean_privacy_with_runtime(
        &data,
        &plan,
        &AtomicBool::new(false),
        &OperaRuntime,
        &mut |_, _| {},
    );
    assert!(
        blocked
            .err()
            .unwrap()
            .contains("Close the selected browser")
    );
    assert!(!data.exists());
    let cleaned = clean_privacy_with_runtime(
        &data,
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(cleaned.deleted, 1);
    let options = list_privacy_restore_options(&data).unwrap();
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].browser, Browser::OperaGx);
    assert!(
        prepare_privacy_restore_with_runtime(&data, options[0].id, &OperaRuntime)
            .err()
            .unwrap()
            .contains("Close")
    );
    let restore =
        prepare_privacy_restore_with_runtime(&data, options[0].id, &EmptyRuntime).unwrap();
    assert!(
        restore_privacy_database_with_runtime(&data, &restore, &OperaRuntime)
            .err()
            .unwrap()
            .contains("Close")
    );
    let receipt = restore_privacy_database_with_runtime(&data, &restore, &EmptyRuntime).unwrap();
    assert!(receipt.restored);
    assert!(!receipt.uncertain);
    assert_eq!(
        Connection::open(fixture.history_path)
            .unwrap()
            .query_row("SELECT count(*) FROM downloads", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn health_history_groups_downloads_and_routes_reviewed_ids_to_the_download_owner() {
    use dcleaner::{
        domain::{Analysis, CategoryResult},
        health::{
            HealthAction, HealthCategory, HealthCoordinator, HealthFindingId, HealthStep,
            HealthStepReport, PRIVACY_SCAN_CATEGORIES,
        },
        privacy::{CookieExceptionSettings, ProfileInventory},
    };
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let before_history = fs::read(&fixture.history_path).unwrap();
    let before_cookies = fs::read(&fixture.cookies_path).unwrap();
    let records = scan_profiles_with_settings(
        &[fixture.profile.clone()],
        PRIVACY_SCAN_CATEGORIES,
        &CookieExceptionSettings::default(),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(!records.partial);
    assert_eq!(fs::read(&fixture.history_path).unwrap(), before_history);
    assert_eq!(fs::read(&fixture.cookies_path).unwrap(), before_cookies);
    let download_id = records
        .records
        .iter()
        .find(|r| r.category == PrivacyCategory::Downloads)
        .unwrap()
        .id;
    let analysis = Analysis {
        id: Uuid::new_v4(),
        date: "fixture".into(),
        minimum_age_days: 1,
        cleanup_policy: Default::default(),
        elapsed_ms: 0,
        cancelled: false,
        categories: vec![CategoryResult {
            id: "chrome".into(),
            name: "Chrome cache".into(),
            group: "Applications".into(),
            files: vec![],
            skipped: 0,
            available: true,
            truncated: false,
        }],
    };
    let downloads_only = scan_profiles_with_settings(
        &[fixture.profile.clone()],
        &[PrivacyCategory::Downloads],
        &CookieExceptionSettings::default(),
        &AtomicBool::new(false),
        |_| {},
    );
    let only_downloads = HealthStepReport::privacy(
        ProfileInventory {
            profiles: vec![fixture.profile.clone()],
            skipped: vec![],
            partial: false,
        },
        downloads_only,
        analysis.clone(),
    );
    assert_eq!(
        only_downloads
            .categories
            .iter()
            .find(|c| c.category == HealthCategory::BrowsingHistory)
            .unwrap()
            .reported_items,
        4
    );
    let health = HealthStepReport::privacy(
        ProfileInventory {
            profiles: vec![fixture.profile.clone()],
            skipped: vec![],
            partial: false,
        },
        records,
        analysis,
    );
    let history = health
        .categories
        .iter()
        .find(|c| c.category == HealthCategory::BrowsingHistory)
        .unwrap();
    assert_eq!(history.reported_items, 16); // 12 history + download/chain/slice rows.
    assert!(
        history
            .findings
            .iter()
            .any(|f| f.id == HealthFindingId::BrowserRecord(download_id))
    );
    let mut coordinator = HealthCoordinator::new();
    coordinator
        .inspect_privacy_browsers(Ok(Vec::new()))
        .unwrap();
    coordinator.begin_scan(HealthStep::Privacy).unwrap();
    coordinator.complete_scan(health).unwrap();
    coordinator
        .select_finding(HealthFindingId::BrowserRecord(download_id), true)
        .unwrap();
    let plan = coordinator.build_action_plan(false).unwrap();
    let [HealthAction::BrowserPrivacy(download_plan)] = plan.actions() else {
        panic!("Health download selection must keep the privacy cleanup owner");
    };
    let receipt = clean_privacy_with_runtime(
        &dir.path().join("data"),
        download_plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(receipt.selected, 1);
    assert_eq!(receipt.deleted, 1);
    assert!(!receipt.uncertain);
    let db = Connection::open_with_flags(&fixture.history_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    for (table, expected) in [
        ("downloads", 0),
        ("downloads_url_chains", 0),
        ("downloads_slices", 0),
        ("urls", 2),
        ("visits", 2),
        ("logins", 1),
        ("preferences", 1),
    ] {
        let count: i64 = db
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, expected, "{table}");
    }
    assert_eq!(fs::read(&fixture.cookies_path).unwrap(), before_cookies);
}

#[test]
fn health_download_scan_does_not_claim_unsupported_firefox_download_coverage() {
    use dcleaner::{health::PRIVACY_SCAN_CATEGORIES, privacy::CookieExceptionSettings};
    let dir = tempfile::tempdir().unwrap();
    let (profile, places) = firefox_fixture(dir.path());
    Connection::open(&places)
        .unwrap()
        .execute_batch("DROP TABLE moz_anno_attributes;")
        .unwrap();
    let before = fs::read(&places).unwrap();
    let report = scan_profiles_with_settings(
        &[profile],
        PRIVACY_SCAN_CATEGORIES,
        &CookieExceptionSettings::default(),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(report.partial);
    assert!(
        report
            .skipped
            .iter()
            .any(|s| s.category == Some(PrivacyCategory::Downloads))
    );
    assert!(
        !report
            .records
            .iter()
            .any(|r| r.category == PrivacyCategory::Downloads)
    );
    assert_eq!(fs::read(&places).unwrap(), before);
}

struct EmptyRuntime;
impl BrowserRuntime for EmptyRuntime {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        Ok(Vec::new())
    }
}

const SAVED_CHROME_URL: &str = "https://alice:top-secret@example.test/first?token=hidden";

fn downloads_only(profile: &BrowserProfile) -> dcleaner::privacy::PrivacyReport {
    scan_profiles_with_settings(
        &[profile.clone()],
        &[PrivacyCategory::Downloads],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    )
}

#[test]
fn chromium_download_compatible_versions_scan_and_clean_only_reviewed_rows() {
    for version in ["15", "16"] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = chrome_fixture(dir.path());
        let db = Connection::open(&fixture.history_path).unwrap();
        db.execute(
            "UPDATE meta SET value=?1 WHERE key='last_compatible_version'",
            [version],
        )
        .unwrap();
        drop(db);
        let before = fs::read(&fixture.history_path).unwrap();
        let report = downloads_only(&fixture.profile);
        assert!(!report.partial);
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].item_count(), 4);
        assert_eq!(fs::read(&fixture.history_path).unwrap(), before);
        let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
        let receipt = clean_privacy_with_runtime(
            &dir.path().join("data"),
            &plan,
            &AtomicBool::new(false),
            &EmptyRuntime,
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (1, 0),
            "{:?}",
            receipt.errors
        );
        let db = Connection::open(&fixture.history_path).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM downloads", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(core_history_count(&db), 12);
        assert_eq!(
            db.query_row(
                "SELECT value FROM meta WHERE key='last_compatible_version'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            version
        );
    }
}

#[test]
fn chromium_download_unknown_missing_or_ambiguous_versions_are_read_only_partial() {
    for case in 0..6 {
        let dir = tempfile::tempdir().unwrap();
        let fixture = chrome_fixture(dir.path());
        let db = Connection::open(&fixture.history_path).unwrap();
        db.execute_batch(match case {
            0 => "UPDATE meta SET value='14';",
            1 => "UPDATE meta SET value='17';",
            2 => "DELETE FROM meta;",
            3 => "DROP TABLE meta;",
            4 => "DROP TABLE meta; CREATE TABLE meta(key TEXT,value TEXT); INSERT INTO meta VALUES('last_compatible_version','16'),('last_compatible_version','16');",
            _ => "UPDATE meta SET value=CAST(x'80' AS TEXT);",
        }).unwrap();
        drop(db);
        let before = fs::read(&fixture.history_path).unwrap();
        let report = downloads_only(&fixture.profile);
        assert!(report.partial && report.records.is_empty());
        assert!(
            report
                .skipped
                .iter()
                .any(|skip| skip.reason.contains("compatibility"))
        );
        assert_eq!(fs::read(&fixture.history_path).unwrap(), before);
        assert!(build_cleanup_plan(&report, &[]).is_err());
    }
}

#[test]
fn chromium_download_wal_version_drift_skips_downloads_without_blocking_valid_history() {
    for version in ["15", "17"] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = chrome_fixture(dir.path());
        let writer = Connection::open(&fixture.history_path).unwrap();
        writer
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
            .unwrap();
        let report = scan_profiles_with_settings(
            &[fixture.profile.clone()],
            &[PrivacyCategory::History, PrivacyCategory::Downloads],
            &Default::default(),
            &AtomicBool::new(false),
            |_| {},
        );
        assert!(!report.partial);
        assert_eq!(report.records.len(), 3);
        let plan = build_cleanup_plan(
            &report,
            &report
                .records
                .iter()
                .map(|record| record.id)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let before = fs::read(&fixture.history_path).unwrap();
        writer
            .execute(
                "UPDATE meta SET value=?1 WHERE key='last_compatible_version'",
                [version],
            )
            .unwrap();
        assert_eq!(fs::read(&fixture.history_path).unwrap(), before);
        let receipt = clean_privacy_with_runtime(
            &dir.path().join("data"),
            &plan,
            &AtomicBool::new(false),
            &EmptyRuntime,
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (2, 1),
            "{:?}",
            receipt.errors
        );
        assert_eq!(core_history_count(&writer), 0);
        assert_eq!(
            writer
                .query_row("SELECT count(*) FROM downloads", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            writer
                .query_row("SELECT count(*) FROM downloads_url_chains", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
}

fn add_second_download(db: &Connection) {
    db.execute_batch(
        "INSERT INTO downloads VALUES(2,'keep-second-file',400,30);
        INSERT INTO downloads_url_chains VALUES(2,0,'https://second.test/file');
        INSERT INTO downloads_slices VALUES(2,0,30);",
    )
    .unwrap();
}

#[test]
fn chromium_download_counts_and_declared_legacy_ownership_preserve_unselected_data_and_files() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let file = dir.path().join("downloaded-file.bin");
    fs::write(&file, b"This downloaded file must remain untouched").unwrap();
    let db = Connection::open(&fixture.history_path).unwrap();
    add_second_download(&db);
    db.execute_batch("CREATE TABLE accelerated_downloads(opaque_id INTEGER PRIMARY KEY,owner INTEGER,payload BLOB,
        FOREIGN KEY(owner) REFERENCES downloads(id));
        INSERT INTO accelerated_downloads VALUES(10,1,X'736563726574'),(20,2,X'72657461696e');").unwrap();
    db.execute(
        "UPDATE downloads SET target_path=?1 WHERE id=1",
        [file.to_str().unwrap()],
    )
    .unwrap();
    drop(db);
    let before = fs::read(&fixture.history_path).unwrap();
    let cookies = fs::read(&fixture.cookies_path).unwrap();
    let mut found = 0;
    let report = scan_profiles_with_settings(
        &[fixture.profile.clone()],
        &[PrivacyCategory::Downloads],
        &Default::default(),
        &AtomicBool::new(false),
        |progress| found = progress.records_found,
    );
    assert!(!report.partial);
    assert_eq!(report.records.len(), 2);
    assert_eq!(
        report.records.iter().map(|r| r.item_count()).sum::<usize>(),
        9
    );
    assert_eq!(found, 9);
    assert_eq!(fs::read(&fixture.history_path).unwrap(), before);
    let first = report.records.iter().find(|r| r.item_count() == 5).unwrap();
    let plan = build_cleanup_plan(&report, &[first.id]).unwrap();
    let receipt = clean_privacy_with_runtime(
        &dir.path().join("data"),
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (1, 0),
        "{:?}",
        receipt.errors
    );
    let db = Connection::open(&fixture.history_path).unwrap();
    for table in [
        "downloads",
        "downloads_url_chains",
        "downloads_slices",
        "accelerated_downloads",
    ] {
        assert_eq!(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    assert_eq!(core_history_count(&db), 12);
    assert_eq!(
        db.query_row("SELECT owner FROM accelerated_downloads", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM logins", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        fs::read(file).unwrap(),
        b"This downloaded file must remain untouched"
    );
    assert_eq!(fs::read(&fixture.cookies_path).unwrap(), cookies);
}

#[test]
fn chromium_opaque_legacy_columns_do_not_infer_a_download_relationship() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let db = Connection::open(&fixture.history_path).unwrap();
    db.execute_batch(
        "CREATE TABLE accelerated_downloads(download_id INTEGER,payload BLOB);
        INSERT INTO accelerated_downloads VALUES(1,X'736563726574'),(1,X'72657461696e');",
    )
    .unwrap();
    drop(db);
    let report = downloads_only(&fixture.profile);
    assert!(!report.partial);
    assert_eq!(report.records.len(), 3);
    assert_eq!(
        report.records.iter().map(|r| r.item_count()).sum::<usize>(),
        6
    );
    let parent = report.records.iter().find(|r| r.item_count() == 4).unwrap();
    let plan = build_cleanup_plan(&report, &[parent.id]).unwrap();
    let receipt = clean_privacy_with_runtime(
        &dir.path().join("data"),
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(receipt.deleted, 1);
    let db = Connection::open(&fixture.history_path).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM accelerated_downloads", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM downloads", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn chromium_download_orphans_and_absent_optional_tables_have_exact_row_targets() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    let path = root.join("History");
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT);
        INSERT INTO meta VALUES('last_compatible_version','16');
        CREATE TABLE downloads_url_chains(id INTEGER,chain_index INTEGER,url TEXT);
        CREATE TABLE downloads_slices(download_id INTEGER,offset INTEGER,length INTEGER);
        CREATE TABLE accelerated_downloads(payload BLOB);
        INSERT INTO downloads_url_chains VALUES(999,0,'https://orphan1.test/private'),(999,1,'https://orphan2.test/private');
        INSERT INTO downloads_slices VALUES(999,0,1),(999,1,2);
        INSERT INTO accelerated_downloads VALUES(X'6f7061717565');").unwrap();
    drop(db);
    let profile = BrowserProfile {
        id: "download-orphan-fixture".into(),
        browser: Browser::Edge,
        name: "Fixture".into(),
        root,
    };
    let before = fs::read(&path).unwrap();
    let report = downloads_only(&profile);
    assert!(!report.partial);
    assert_eq!(report.records.len(), 5);
    assert!(report.records.iter().all(|r| r.item_count() == 1));
    assert_eq!(fs::read(&path).unwrap(), before);
    let first = report
        .records
        .iter()
        .find(|r| r.site == "orphan1.test")
        .unwrap();
    let plan = build_cleanup_plan(&report, &[first.id]).unwrap();
    let receipt = clean_privacy_with_runtime(
        &dir.path().join("data"),
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (1, 0),
        "{:?}",
        receipt.errors
    );
    let report = downloads_only(&profile);
    assert_eq!(report.records.len(), 4);
    let plan = build_cleanup_plan(
        &report,
        &report.records.iter().map(|r| r.id).collect::<Vec<_>>(),
    )
    .unwrap();
    let receipt = clean_privacy_with_runtime(
        &dir.path().join("data2"),
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(receipt.deleted, 4);
    let db = Connection::open(&path).unwrap();
    for table in [
        "downloads_url_chains",
        "downloads_slices",
        "accelerated_downloads",
    ] {
        assert_eq!(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[test]
fn chromium_download_wal_child_or_schema_drift_never_deletes_unreviewed_rows() {
    for schema_change in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = chrome_fixture(dir.path());
        let writer = Connection::open(&fixture.history_path).unwrap();
        add_second_download(&writer);
        writer
            .execute_batch(
                "CREATE TABLE accelerated_downloads(payload TEXT);
            PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;",
            )
            .unwrap();
        let report = downloads_only(&fixture.profile);
        assert!(!report.partial);
        let plan = build_cleanup_plan(
            &report,
            &report.records.iter().map(|r| r.id).collect::<Vec<_>>(),
        )
        .unwrap();
        let before = fs::read(&fixture.history_path).unwrap();
        if schema_change {
            writer
                .execute_batch("ALTER TABLE accelerated_downloads ADD COLUMN extra INTEGER;")
                .unwrap();
        } else {
            writer
                .execute_batch("UPDATE downloads_slices SET length=999 WHERE download_id=1;")
                .unwrap();
        }
        assert_eq!(fs::read(&fixture.history_path).unwrap(), before);
        let receipt = clean_privacy_with_runtime(
            &dir.path().join("data"),
            &plan,
            &AtomicBool::new(false),
            &EmptyRuntime,
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            if schema_change { (0, 2) } else { (1, 1) },
            "{:?}",
            receipt.errors
        );
        assert_eq!(
            writer
                .query_row("SELECT count(*) FROM downloads WHERE id=1", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(core_history_count(&writer), 12);
    }
}

#[test]
fn chromium_free_database_pages_are_reported_without_fabricating_a_row_or_running_vacuum() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let db = Connection::open(&fixture.history_path).unwrap();
    db.execute_batch("CREATE TABLE disposable_pages(data BLOB); INSERT INTO disposable_pages VALUES(zeroblob(262144)); DROP TABLE disposable_pages;").unwrap();
    let free_before: i64 = db
        .query_row("PRAGMA freelist_count", [], |r| r.get(0))
        .unwrap();
    assert!(free_before > 0);
    drop(db);
    let before = fs::read(&fixture.history_path).unwrap();
    let report = downloads_only(&fixture.profile);
    assert!(report.partial);
    assert!(
        report
            .skipped
            .iter()
            .any(|skip| skip.reason.contains("compaction"))
    );
    assert_eq!(
        report.records.iter().map(|r| r.item_count()).sum::<usize>(),
        4
    );
    assert_eq!(fs::read(&fixture.history_path).unwrap(), before);
    let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
    let receipt = clean_privacy_with_runtime(
        &dir.path().join("data"),
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(receipt.deleted, 1);
    let db = Connection::open(&fixture.history_path).unwrap();
    let free_after: i64 = db
        .query_row("PRAGMA freelist_count", [], |r| r.get(0))
        .unwrap();
    assert!(free_after >= free_before);
    assert_eq!(
        fs::metadata(&fixture.history_path).unwrap().len(),
        before.len() as u64
    );
}

#[test]
fn chromium_download_invalid_schema_text_and_inventory_limits_are_explicitly_partial() {
    for case in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let fixture = chrome_fixture(dir.path());
        let db = Connection::open(&fixture.history_path).unwrap();
        match case {
            0 => db
                .execute_batch("CREATE TABLE accelerated_downloads(rowid INTEGER,payload TEXT);")
                .unwrap(),
            1 => db
                .execute_batch(
                    "UPDATE downloads_url_chains SET url=CAST(x'80' AS TEXT) WHERE chain_index=0;",
                )
                .unwrap(),
            2 => db
                .execute_batch(
                    "CREATE TABLE accelerated_downloads(payload INTEGER);
                WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100001)
                INSERT INTO accelerated_downloads SELECT x FROM n;",
                )
                .unwrap(),
            _ => db
                .execute_batch(
                    "CREATE TABLE accelerated_downloads(a INTEGER,b INTEGER,
                FOREIGN KEY(a,b) REFERENCES downloads(id,target_path));",
                )
                .unwrap(),
        }
        drop(db);
        let before = fs::read(&fixture.history_path).unwrap();
        let report = downloads_only(&fixture.profile);
        assert!(report.partial && report.records.is_empty());
        assert_eq!(fs::read(&fixture.history_path).unwrap(), before);
    }
}

fn history_only(profile: &BrowserProfile) -> dcleaner::privacy::PrivacyReport {
    scan_profiles_with_settings(
        &[profile.clone()],
        &[PrivacyCategory::History],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    )
}

fn core_history_count(db: &Connection) -> usize {
    [
        "urls",
        "visits",
        "visit_source",
        "segments",
        "segment_usage",
        "keyword_search_terms",
    ]
    .iter()
    .map(|table| {
        db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap()
    })
    .sum::<i64>() as usize
}

#[test]
fn chromium_bookmarked_history_keeps_url_cleans_dependencies_and_reports_real_core_rows() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let bookmark_path = fixture.profile.root.join("Bookmarks");
    let bookmarks = serde_json::to_vec(&serde_json::json!({"roots": {"folder": {"children": [
        {"url": SAVED_CHROME_URL}, {"url": SAVED_CHROME_URL},
        {"folder": {"children": [{"URL": "https://example.test/second"}]}}
    ]}}}))
    .unwrap();
    fs::write(&bookmark_path, &bookmarks).unwrap();
    let before = fs::read(&fixture.history_path).unwrap();
    let report = history_only(&fixture.profile);
    assert!(!report.partial);
    assert_eq!(report.records.len(), 2);
    assert_eq!(
        report.records.iter().map(|r| r.item_count()).sum::<usize>(),
        11
    );
    assert_eq!(fs::read(&fixture.history_path).unwrap(), before);
    let selected = report.records.iter().find(|r| r.item_count() == 5).unwrap();
    let plan = build_cleanup_plan(&report, &[selected.id]).unwrap();
    let receipt = clean_privacy_with_runtime(
        &dir.path().join("data"),
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(
        (receipt.selected, receipt.deleted, receipt.skipped),
        (1, 1, 0)
    );
    assert!(!receipt.uncertain);
    let db = Connection::open(&fixture.history_path).unwrap();
    assert_eq!(core_history_count(&db), 7); // Five removed, saved URL + unselected six remain.
    assert_eq!(
        db.query_row("SELECT url FROM urls WHERE id=1", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        SAVED_CHROME_URL
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM visits WHERE url=1", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM visits WHERE url=2", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM logins", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM preferences", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(fs::read(&bookmark_path).unwrap(), bookmarks);
    drop(db);
    let after = history_only(&fixture.profile);
    assert_eq!(after.records.len(), 1); // A saved URL with no history is not offered again.
    assert_eq!(after.records[0].item_count(), 6);
}

#[test]
fn chromium_bookmark_matching_is_full_url_case_sensitive_and_missing_is_valid() {
    for value in [
        None,
        Some(SAVED_CHROME_URL.to_uppercase()),
        Some("https://example.test/".into()),
        Some(SAVED_CHROME_URL.into()),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = chrome_fixture(dir.path());
        if let Some(url) = &value {
            fs::write(
                fixture.profile.root.join("Bookmarks"),
                serde_json::to_vec(&serde_json::json!({"nested": [{"url": url}]})).unwrap(),
            )
            .unwrap();
        }
        let report = history_only(&fixture.profile);
        assert!(!report.partial);
        let protects = value.as_deref() == Some(SAVED_CHROME_URL);
        assert_eq!(
            report.records.iter().map(|r| r.item_count()).sum::<usize>(),
            if protects { 11 } else { 12 }
        );
        let ids = report.records.iter().map(|r| r.id).collect::<Vec<_>>();
        let plan = build_cleanup_plan(&report, &ids).unwrap();
        let receipt = clean_privacy_with_runtime(
            &dir.path().join("data"),
            &plan,
            &AtomicBool::new(false),
            &EmptyRuntime,
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!(receipt.deleted, 2);
        assert!(!receipt.uncertain, "{:?}", receipt.errors);
        let db = Connection::open(&fixture.history_path).unwrap();
        assert_eq!(core_history_count(&db), usize::from(protects));
    }
}

#[test]
fn chromium_bookmark_errors_make_only_history_partial_without_modifying_sources() {
    for content in [b"{invalid".as_slice(), b"[]", b""] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = chrome_fixture(dir.path());
        fs::write(fixture.profile.root.join("Bookmarks"), content).unwrap();
        let before = fs::read(&fixture.history_path).unwrap();
        let report = scan_fixture(&fixture.profile);
        assert!(report.partial);
        assert!(
            !report
                .records
                .iter()
                .any(|r| r.category == PrivacyCategory::History)
        );
        assert_eq!(
            report
                .records
                .iter()
                .filter(|r| r.category == PrivacyCategory::Cookies)
                .count(),
            2
        );
        assert_eq!(fs::read(&fixture.history_path).unwrap(), before);
    }
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    fs::create_dir(fixture.profile.root.join("Bookmarks")).unwrap();
    let report = history_only(&fixture.profile);
    assert!(report.partial && report.records.is_empty());
}

#[test]
fn chromium_bookmark_creation_removal_or_changes_invalidate_reviewed_history() {
    for transition in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let fixture = chrome_fixture(dir.path());
        let path = fixture.profile.root.join("Bookmarks");
        let saved = serde_json::to_vec(&serde_json::json!({"url": SAVED_CHROME_URL})).unwrap();
        if transition != 0 {
            fs::write(&path, &saved).unwrap();
        }
        let report = history_only(&fixture.profile);
        assert!(!report.partial);
        let plan = build_cleanup_plan(
            &report,
            &report.records.iter().map(|r| r.id).collect::<Vec<_>>(),
        )
        .unwrap();
        match transition {
            0 => fs::write(&path, &saved).unwrap(),
            1 => fs::remove_file(&path).unwrap(),
            2 => fs::write(&path, b"{\"url\":\"https://other.test/\"}").unwrap(),
            _ => {
                let modified = fs::metadata(&path).unwrap().modified().unwrap();
                let changed = serde_json::to_vec(
                    &serde_json::json!({"url": SAVED_CHROME_URL.to_uppercase()}),
                )
                .unwrap();
                assert_eq!(changed.len(), saved.len());
                fs::write(&path, changed).unwrap();
                fs::File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_times(fs::FileTimes::new().set_modified(modified))
                    .unwrap();
                assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
            }
        }
        let before = fs::read(&fixture.history_path).unwrap();
        let receipt = clean_privacy_with_runtime(
            &dir.path().join("data"),
            &plan,
            &AtomicBool::new(false),
            &EmptyRuntime,
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!((receipt.deleted, receipt.skipped), (0, 2));
        assert_eq!(fs::read(&fixture.history_path).unwrap(), before);
    }
}

#[test]
fn chromium_wal_dependency_drift_skips_only_the_changed_reviewed_group() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let writer = Connection::open(&fixture.history_path).unwrap();
    writer
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    let report = history_only(&fixture.profile);
    assert!(!report.partial);
    let plan = build_cleanup_plan(
        &report,
        &report.records.iter().map(|r| r.id).collect::<Vec<_>>(),
    )
    .unwrap();
    let before_main = fs::read(&fixture.history_path).unwrap();
    writer
        .execute_batch(
            "INSERT INTO visits VALUES(3,1,300,NULL); INSERT INTO visit_source VALUES(3,9);",
        )
        .unwrap();
    assert_eq!(fs::read(&fixture.history_path).unwrap(), before_main); // Changes are in WAL, not main file metadata.
    let receipt = clean_privacy_with_runtime(
        &dir.path().join("data"),
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (1, 1),
        "{:?}",
        receipt.errors
    );
    assert!(!receipt.uncertain);
    assert_eq!(
        writer
            .query_row("SELECT count(*) FROM urls WHERE id=1", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        writer
            .query_row("SELECT count(*) FROM visits WHERE url=1", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        writer
            .query_row("SELECT count(*) FROM urls WHERE id=2", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn chromium_wal_shared_annotation_drift_invalidates_review_without_deleting_new_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let writer = Connection::open(&fixture.history_path).unwrap();
    writer
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    let report = history_only(&fixture.profile);
    let plan = build_cleanup_plan(
        &report,
        &report.records.iter().map(|r| r.id).collect::<Vec<_>>(),
    )
    .unwrap();
    let before = fs::read(&fixture.history_path).unwrap();
    writer.execute_batch("UPDATE content_annotations SET annotation='new unreviewed annotation' WHERE visit_id=1;").unwrap();
    assert_eq!(fs::read(&fixture.history_path).unwrap(), before);
    let receipt = clean_privacy_with_runtime(
        &dir.path().join("data"),
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!((receipt.deleted, receipt.skipped), (0, 2));
    assert_eq!(core_history_count(&writer), 12);
    assert_eq!(
        writer
            .query_row(
                "SELECT annotation FROM content_annotations WHERE visit_id=1",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
        "new unreviewed annotation"
    );
}

#[test]
fn chromium_selected_visit_cycles_and_chains_preserve_surviving_ancestors() {
    for cycle in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let fixture = chrome_fixture(dir.path());
        let db = Connection::open(&fixture.history_path).unwrap();
        db.execute_batch(
            "PRAGMA foreign_keys=ON;
            INSERT INTO visits VALUES(3,1,300,1),(4,1,400,3);",
        )
        .unwrap();
        if cycle {
            db.execute_batch("UPDATE visits SET from_visit=4 WHERE id=1;")
                .unwrap();
        } else {
            db.execute_batch(
                "UPDATE visits SET from_visit=NULL WHERE id=2;
                UPDATE visits SET from_visit=2 WHERE id=1;
                INSERT INTO visits VALUES(5,2,500,4);",
            )
            .unwrap();
        }
        drop(db);
        let report = history_only(&fixture.profile);
        assert!(!report.partial);
        let selected = report.records.iter().find(|r| r.item_count() == 8).unwrap();
        let plan = build_cleanup_plan(&report, &[selected.id]).unwrap();
        let receipt = clean_privacy_with_runtime(
            &dir.path().join("data"),
            &plan,
            &AtomicBool::new(false),
            &EmptyRuntime,
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (1, 0),
            "{:?}",
            receipt.errors
        );
        let db = Connection::open(&fixture.history_path).unwrap();
        let id = if cycle { 2 } else { 5 };
        let surviving_parent: Option<i64> = db
            .query_row("SELECT from_visit FROM visits WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(surviving_parent, if cycle { None } else { Some(2) });
        assert_eq!(
            db.query_row("SELECT count(*) FROM visits WHERE url=1", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM urls WHERE id=2", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert!(
            db.prepare("PRAGMA foreign_key_check")
                .unwrap()
                .query([])
                .unwrap()
                .next()
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn chromium_orphan_core_rows_get_disjoint_reviewed_targets_and_exact_counts() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let db = Connection::open(&fixture.history_path).unwrap();
    db.execute_batch(
        "PRAGMA foreign_keys=OFF;
        INSERT INTO visits VALUES(50,999,500,NULL); INSERT INTO visit_source VALUES(50,0);
        INSERT INTO segments VALUES(60,999); INSERT INTO segment_usage VALUES(60,1);
        INSERT INTO visit_source VALUES(70,0); INSERT INTO segment_usage VALUES(80,1);
        INSERT INTO keyword_search_terms VALUES(90,'orphan search');",
    )
    .unwrap();
    assert_eq!(core_history_count(&db), 19);
    drop(db);
    let report = history_only(&fixture.profile);
    assert!(!report.partial);
    assert_eq!(report.records.len(), 7);
    assert_eq!(
        report.records.iter().map(|r| r.item_count()).sum::<usize>(),
        19
    );
    let orphan = report
        .records
        .iter()
        .find(|r| r.site.is_empty() && r.item_count() == 1)
        .unwrap();
    let plan = build_cleanup_plan(&report, &[orphan.id]).unwrap();
    // The declared FKs in this fixture make the orphan state inconsistent. The
    // existing transaction gate refuses it rather than using an orphan as repair authority.
    let receipt = clean_privacy_with_runtime(
        &dir.path().join("data"),
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(receipt.deleted, 0);
    assert!(
        receipt
            .errors
            .iter()
            .any(|error| error.contains("foreign-key"))
    );
    let db = Connection::open(&fixture.history_path).unwrap();
    assert_eq!(core_history_count(&db), 19);
}

#[test]
fn chromium_unconstrained_orphans_clean_independently_of_unselected_url_groups() {
    let dir = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(dir.path()).unwrap();
    let path = root.join("History");
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INTEGER,last_visit_time INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER,from_visit INTEGER);
        CREATE TABLE visit_source(id INTEGER PRIMARY KEY,source INTEGER);
        CREATE TABLE segments(id INTEGER PRIMARY KEY,url_id INTEGER);
        CREATE TABLE segment_usage(segment_id INTEGER PRIMARY KEY,visit_count INTEGER);
        CREATE TABLE keyword_search_terms(url_id INTEGER PRIMARY KEY,term TEXT);
        CREATE TABLE logins(password_value TEXT); INSERT INTO logins VALUES('keep this');
        INSERT INTO urls VALUES(1,'https://unselected.test/',NULL,1,1);
        INSERT INTO urls VALUES(2,'https://empty-bookmark.test/',NULL,0,0);
        INSERT INTO urls VALUES(3,'https://saved.test/',NULL,1,1);
        INSERT INTO visits VALUES(10,1,1,NULL),(30,3,1,NULL),(50,999,1,NULL);
        INSERT INTO visit_source VALUES(10,0),(30,0),(50,0),(70,0);
        INSERT INTO segments VALUES(20,1),(40,3),(60,999);
        INSERT INTO segment_usage VALUES(20,1),(40,1),(60,1),(80,1);
        INSERT INTO keyword_search_terms VALUES(1,'keep'),(3,'saved'),(90,'orphan');").unwrap();
    assert_eq!(core_history_count(&db), 20);
    drop(db);
    fs::write(
        root.join("Bookmarks"),
        br#"{"roots":[{"url":"https://empty-bookmark.test/"},{"url":"https://saved.test/"}]}"#,
    )
    .unwrap();
    let profile = BrowserProfile {
        id: "edge-orphan-fixture".into(),
        browser: Browser::Edge,
        name: "Fixture".into(),
        root,
    };
    let report = history_only(&profile);
    assert!(!report.partial);
    assert_eq!(report.records.len(), 7);
    assert_eq!(
        report.records.iter().map(|r| r.item_count()).sum::<usize>(),
        18
    );
    let orphans = report
        .records
        .iter()
        .filter(|r| r.site.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(orphans.len(), 5);
    assert_eq!(orphans.iter().map(|r| r.item_count()).sum::<usize>(), 7);
    let plan =
        build_cleanup_plan(&report, &orphans.iter().map(|r| r.id).collect::<Vec<_>>()).unwrap();
    let receipt = clean_privacy_with_runtime(
        &dir.path().join("data"),
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (5, 0),
        "{:?}",
        receipt.errors
    );
    let db = Connection::open(&path).unwrap();
    assert_eq!(core_history_count(&db), 13);
    assert_eq!(
        db.query_row("SELECT count(*) FROM logins", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    drop(db);
    let report = history_only(&profile);
    assert!(!report.partial);
    assert_eq!(report.records.len(), 2);
    assert_eq!(
        report.records.iter().map(|r| r.item_count()).sum::<usize>(),
        11
    );
    let saved = report
        .records
        .iter()
        .find(|r| r.site == "saved.test")
        .unwrap();
    assert_eq!(saved.item_count(), 5);
    let plan = build_cleanup_plan(&report, &[saved.id]).unwrap();
    let receipt = clean_privacy_with_runtime(
        &dir.path().join("data2"),
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(receipt.deleted, 1);
    let db = Connection::open(&path).unwrap();
    assert_eq!(core_history_count(&db), 8);
    assert_eq!(
        db.query_row("SELECT count(*) FROM urls", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        3
    );
}

#[test]
fn chromium_history_limits_and_invalid_text_report_partial_without_panicking() {
    for case in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let fixture = chrome_fixture(dir.path());
        match case {
            0 => {
                let file = fs::File::create(fixture.profile.root.join("Bookmarks")).unwrap();
                file.set_len(16 * 1024 * 1024 + 1).unwrap();
            }
            1 => {
                let db = Connection::open(&fixture.history_path).unwrap();
                db.execute_batch("UPDATE urls SET title=CAST(x'80' AS TEXT) WHERE id=1;")
                    .unwrap();
            }
            _ => {
                let db = Connection::open(&fixture.history_path).unwrap();
                db.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1000 UNION ALL SELECT x+1 FROM n WHERE x<101000)
                    INSERT INTO visits SELECT x,1,x,NULL FROM n;").unwrap();
            }
        }
        let before = fs::read(&fixture.history_path).unwrap();
        let report = history_only(&fixture.profile);
        assert!(report.partial && report.records.is_empty());
        assert_eq!(fs::read(&fixture.history_path).unwrap(), before);
    }
}

struct ChromeFixture {
    profile: BrowserProfile,
    history_path: PathBuf,
    cookies_path: PathBuf,
}

fn chrome_fixture(root: &Path) -> ChromeFixture {
    let profile_root = root.join("Chrome Profile");
    fs::create_dir_all(profile_root.join("Network")).unwrap();
    let history_path = profile_root.join("History");
    let history = Connection::open(&history_path).unwrap();
    history.execute_batch(
        "PRAGMA foreign_keys=ON;
         CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT NOT NULL,title TEXT,visit_count INTEGER NOT NULL,last_visit_time INTEGER);
         CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER NOT NULL,visit_time INTEGER NOT NULL,from_visit INTEGER,
             FOREIGN KEY(url) REFERENCES urls(id) ON DELETE RESTRICT,
             FOREIGN KEY(from_visit) REFERENCES visits(id) ON DELETE RESTRICT);
         CREATE TABLE visit_source(id INTEGER PRIMARY KEY,source INTEGER NOT NULL,
             FOREIGN KEY(id) REFERENCES visits(id) ON DELETE RESTRICT);
         CREATE TABLE content_annotations(visit_id INTEGER PRIMARY KEY,annotation TEXT,
             FOREIGN KEY(visit_id) REFERENCES visits(id) ON DELETE RESTRICT);
         CREATE TABLE context_annotations(visit_id INTEGER PRIMARY KEY,annotation TEXT,
             FOREIGN KEY(visit_id) REFERENCES visits(id) ON DELETE RESTRICT);
         CREATE TABLE clusters(cluster_id INTEGER PRIMARY KEY);
         CREATE TABLE clusters_and_visits(cluster_id INTEGER NOT NULL,visit_id INTEGER NOT NULL,
             PRIMARY KEY(cluster_id,visit_id),
             FOREIGN KEY(cluster_id) REFERENCES clusters(cluster_id) ON DELETE RESTRICT,
             FOREIGN KEY(visit_id) REFERENCES visits(id) ON DELETE RESTRICT);
         CREATE TABLE cluster_keywords(cluster_id INTEGER NOT NULL,keyword TEXT,
             FOREIGN KEY(cluster_id) REFERENCES clusters(cluster_id) ON DELETE RESTRICT);
         CREATE TABLE cluster_visit_duplicates(visit_id INTEGER NOT NULL,duplicate_visit_id INTEGER NOT NULL,
             PRIMARY KEY(visit_id,duplicate_visit_id),
             FOREIGN KEY(visit_id) REFERENCES visits(id) ON DELETE RESTRICT,
             FOREIGN KEY(duplicate_visit_id) REFERENCES visits(id) ON DELETE RESTRICT);
         CREATE TABLE keyword_search_terms(url_id INTEGER PRIMARY KEY,term TEXT,
             FOREIGN KEY(url_id) REFERENCES urls(id) ON DELETE RESTRICT);
         CREATE TABLE segments(id INTEGER PRIMARY KEY,url_id INTEGER NOT NULL,
             FOREIGN KEY(url_id) REFERENCES urls(id) ON DELETE RESTRICT);
         CREATE TABLE segment_usage(segment_id INTEGER PRIMARY KEY,visit_count INTEGER,
             FOREIGN KEY(segment_id) REFERENCES segments(id) ON DELETE RESTRICT);
         CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT);
         INSERT INTO meta VALUES('last_compatible_version','16');
         CREATE TABLE downloads(id INTEGER PRIMARY KEY,target_path TEXT,start_time INTEGER,received_bytes INTEGER);
         CREATE TABLE downloads_url_chains(id INTEGER NOT NULL,chain_index INTEGER NOT NULL,url TEXT NOT NULL,
             PRIMARY KEY(id,chain_index),FOREIGN KEY(id) REFERENCES downloads(id) ON DELETE RESTRICT);
         CREATE TABLE downloads_slices(download_id INTEGER NOT NULL,offset INTEGER,length INTEGER,
             FOREIGN KEY(download_id) REFERENCES downloads(id) ON DELETE RESTRICT);
         CREATE TABLE logins(username_value TEXT,password_value TEXT);
         CREATE TABLE preferences(name TEXT PRIMARY KEY,value TEXT);
         INSERT INTO urls VALUES(1,'https://alice:top-secret@example.test/first?token=hidden','First title',2,100);
         INSERT INTO urls VALUES(2,'https://example.test/second','Second title',1,200);
         INSERT INTO visits VALUES(1,1,100,NULL);
         INSERT INTO visits VALUES(2,2,200,1);
         INSERT INTO visit_source VALUES(1,0);
         INSERT INTO visit_source VALUES(2,0);
         INSERT INTO content_annotations VALUES(1,'selected visit annotation');
         INSERT INTO context_annotations VALUES(1,'selected visit context');
         INSERT INTO clusters VALUES(10);
         INSERT INTO clusters VALUES(20);
         INSERT INTO clusters_and_visits VALUES(10,1);
         INSERT INTO clusters_and_visits VALUES(20,1);
         INSERT INTO clusters_and_visits VALUES(20,2);
         INSERT INTO cluster_keywords VALUES(10,'orphaned cluster');
         INSERT INTO cluster_keywords VALUES(20,'retained cluster');
         INSERT INTO cluster_visit_duplicates VALUES(2,1);
         INSERT INTO keyword_search_terms VALUES(1,'first search');
         INSERT INTO keyword_search_terms VALUES(2,'second search');
         INSERT INTO segments VALUES(100,1);
         INSERT INTO segments VALUES(200,2);
         INSERT INTO segment_usage VALUES(100,1);
         INSERT INTO segment_usage VALUES(200,1);
         INSERT INTO downloads VALUES(1,'C:/private/file.zip',300,20);
         INSERT INTO downloads_url_chains VALUES(1,0,'https://redirect.example.test/start');
         INSERT INTO downloads_url_chains VALUES(1,1,'https://download.example.test/file');
         INSERT INTO downloads_slices VALUES(1,0,20);
         INSERT INTO logins VALUES('person@example.test','password-must-never-be-read');
         INSERT INTO preferences VALUES('theme','dark');",
    )
    .unwrap();
    drop(history);

    let cookies_path = profile_root.join("Network").join("Cookies");
    let cookies = Connection::open(&cookies_path).unwrap();
    cookies.execute_batch(
        "CREATE TABLE cookies(host_key TEXT,name TEXT,path TEXT,expires_utc INTEGER,creation_utc INTEGER,last_access_utc INTEGER,encrypted_value BLOB);
         INSERT INTO cookies VALUES('.example.test','session','/',999,10,20,X'7365637265742D636F6F6B6965');
         INSERT INTO cookies VALUES('.other.test','preference','/',999,11,21,X'7365637265742D636F6F6B6965');",
    )
    .unwrap();
    drop(cookies);

    ChromeFixture {
        profile: BrowserProfile {
            id: "fixture-chrome-profile".into(),
            browser: Browser::Chrome,
            name: "Fixture profile".into(),
            root: dunce::canonicalize(profile_root).unwrap(),
        },
        history_path,
        cookies_path,
    }
}

fn scan_fixture(profile: &BrowserProfile) -> dcleaner::privacy::PrivacyReport {
    scan_profiles(&[profile.clone()], &AtomicBool::new(false), |_| {})
}

fn firefox_fixture(root: &Path) -> (BrowserProfile, PathBuf) {
    let profile_root = root.join("Firefox Profile");
    fs::create_dir_all(&profile_root).unwrap();
    let places_path = profile_root.join("places.sqlite");
    let places = Connection::open(&places_path).unwrap();
    places.execute_batch(
        "PRAGMA foreign_keys=ON;
         CREATE TABLE moz_places(id INTEGER PRIMARY KEY,url TEXT NOT NULL,title TEXT,
             visit_count INTEGER NOT NULL,last_visit_date INTEGER,foreign_count INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY,place_id INTEGER NOT NULL,
             from_visit INTEGER,visit_date INTEGER NOT NULL,visit_type INTEGER NOT NULL,
             FOREIGN KEY(place_id) REFERENCES moz_places(id) ON DELETE CASCADE,
             FOREIGN KEY(from_visit) REFERENCES moz_historyvisits(id) ON DELETE RESTRICT);
         CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY,fk INTEGER,
             FOREIGN KEY(fk) REFERENCES moz_places(id) ON DELETE RESTRICT);
         CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY,name TEXT);
         CREATE TABLE moz_annos(id INTEGER PRIMARY KEY,place_id INTEGER,anno_attribute_id INTEGER,content TEXT,
             FOREIGN KEY(place_id) REFERENCES moz_places(id) ON DELETE RESTRICT);
         CREATE TABLE moz_inputhistory(place_id INTEGER NOT NULL,input TEXT,
             FOREIGN KEY(place_id) REFERENCES moz_places(id) ON DELETE RESTRICT);
         INSERT INTO moz_places VALUES(1,'https://bookmarked.example.test/','Saved',1,100,1);
         INSERT INTO moz_places VALUES(2,'https://unselected.example.test/','Other',1,200,0);
         INSERT INTO moz_historyvisits VALUES(1,1,NULL,100,1);
         INSERT INTO moz_historyvisits VALUES(2,2,1,200,1);
         INSERT INTO moz_bookmarks VALUES(7,1);
         INSERT INTO moz_anno_attributes VALUES(1,'custom/keep');
         INSERT INTO moz_annos VALUES(1,1,1,'bookmark-associated annotation');
         INSERT INTO moz_inputhistory VALUES(1,'preserve');",
    )
    .unwrap();
    drop(places);
    (
        BrowserProfile {
            id: "fixture-firefox-profile".into(),
            browser: Browser::Firefox,
            name: "Firefox fixture".into(),
            root: dunce::canonicalize(profile_root).unwrap(),
        },
        places_path,
    )
}

fn firefox_download_fixture(root: &Path, extras: bool) -> (BrowserProfile, PathBuf) {
    let profile_root = root.join("Firefox Downloads");
    fs::create_dir_all(&profile_root).unwrap();
    let path = profile_root.join("places.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "PRAGMA foreign_keys=ON;
         CREATE TABLE moz_places(id INTEGER PRIMARY KEY,url TEXT,visit_count INTEGER,last_visit_date INTEGER);
         CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY,place_id INTEGER,from_visit INTEGER,visit_date INTEGER,
             FOREIGN KEY(from_visit) REFERENCES moz_historyvisits(id) ON DELETE RESTRICT);
         CREATE TABLE moz_annos(id INTEGER PRIMARY KEY,place_id INTEGER,anno_attribute_id INTEGER,content TEXT);
         CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY,name TEXT);
         CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY,fk INTEGER);
         CREATE TABLE unrelated_state(data TEXT);
         INSERT INTO unrelated_state VALUES('keep');
         INSERT INTO moz_places VALUES(1,'https://download.test/private?token=secret',2,11),(2,'https://saved.test/',1,20),
             (3,'https://history.test/',1,30),(4,'https://different-prefix.test/',1,40),(5,'https://case.test/',1,50);
         INSERT INTO moz_historyvisits VALUES(10,1,NULL,10),(11,1,10,11),(20,2,11,20),
             (30,3,10,30),(40,4,NULL,40),(50,5,50,50);
         INSERT INTO moz_anno_attributes VALUES(1,'downloads/destinationFileURI'),(2,'downloads/metaData'),
             (3,'custom/keep'),(4,'Downloads/other'),(5,'downloadsX/metaData');
         INSERT INTO moz_annos VALUES(11,1,1,'file:///owned-fixture-only'),(12,1,2,'secret-download-metadata'),
             (21,2,1,'file:///owned-fixture-only'),(22,2,2,'{}'),(23,2,3,'retain'),
             (31,3,3,'retain'),(41,4,5,'retain'),(51,5,4,'{}');
         INSERT INTO moz_bookmarks VALUES(1,NULL),(2,2);",
    ).unwrap();
    if extras {
        db.execute_batch(
            "CREATE TABLE moz_places_extra(place_id INTEGER PRIMARY KEY,sync_json TEXT,
                 FOREIGN KEY(place_id) REFERENCES moz_places(id) ON DELETE CASCADE);
             CREATE TABLE moz_historyvisits_extra(visit_id INTEGER PRIMARY KEY,sync_json TEXT,
                 FOREIGN KEY(visit_id) REFERENCES moz_historyvisits(id) ON DELETE CASCADE);
             INSERT INTO moz_places_extra SELECT id,'fixture sync' FROM moz_places;
             INSERT INTO moz_historyvisits_extra SELECT id,'fixture sync' FROM moz_historyvisits;",
        )
        .unwrap();
    }
    fs::write(
        root.join("downloaded-file.txt"),
        b"actual downloaded contents stay",
    )
    .unwrap();
    fs::write(profile_root.join("prefs.js"), b"preferences stay").unwrap();
    fs::write(profile_root.join("logins.json"), b"credentials stay").unwrap();
    (
        BrowserProfile {
            id: "fixture-firefox-downloads".into(),
            browser: Browser::Firefox,
            name: "Firefox downloads".into(),
            root: dunce::canonicalize(profile_root).unwrap(),
        },
        path,
    )
}

fn firefox_scan(
    profile: &BrowserProfile,
    categories: &[PrivacyCategory],
) -> dcleaner::privacy::PrivacyReport {
    scan_profiles_with_settings(
        &[profile.clone()],
        categories,
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    )
}

fn firefox_clean(
    root: &Path,
    report: &dcleaner::privacy::PrivacyReport,
    ids: &[Uuid],
) -> dcleaner::privacy::PrivacyReceipt {
    let plan = build_cleanup_plan(report, ids).unwrap();
    clean_privacy_with_runtime(
        &root.join("app-data"),
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap()
}

// Independent copies of the three recovered native candidate queries. These
// establish membership/count fidelity, not native GUI aggregation or bytes.
fn firefox_native_download_counts(db: &Connection) -> [i64; 3] {
    [
        "SELECT count(*) FROM moz_historyvisits WHERE place_id IN (SELECT place_id FROM moz_annos WHERE anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name LIKE 'downloads/%'))",
        "SELECT count(*) FROM moz_places WHERE id IN (SELECT place_id FROM moz_annos WHERE anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name LIKE 'downloads/%') AND place_id NOT IN (SELECT fk FROM moz_bookmarks WHERE fk NOT NULL))",
        "SELECT count(*) FROM moz_annos WHERE anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name LIKE 'downloads/%')",
    ].map(|sql|db.query_row(sql,[],|r|r.get(0)).unwrap())
}

fn firefox_ids(db: &Connection, table: &str) -> Vec<i64> {
    db.prepare(&format!("SELECT id FROM {table} ORDER BY id"))
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn firefox_download_scan_matches_native_predicates_without_age_or_history_overlap() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, path) = firefox_download_fixture(dir.path(), true);
    let before = fs::read(&path).unwrap();
    let report = firefox_scan(
        &profile,
        &[PrivacyCategory::Downloads, PrivacyCategory::History],
    );
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!(fs::read(&path).unwrap(), before);
    let downloads = report
        .records
        .iter()
        .filter(|r| r.category == PrivacyCategory::Downloads)
        .collect::<Vec<_>>();
    let mut counts = downloads.iter().map(|r| r.item_count()).collect::<Vec<_>>();
    counts.sort();
    assert_eq!(counts, vec![3, 3, 5]);
    assert_eq!(
        firefox_native_download_counts(&Connection::open(path).unwrap()),
        [4, 2, 5]
    );
    let mut history = report
        .records
        .iter()
        .filter(|r| r.category == PrivacyCategory::History)
        .map(|r| r.site.as_str())
        .collect::<Vec<_>>();
    history.sort();
    assert_eq!(history, ["different-prefix.test", "history.test"]);
    assert!(
        downloads
            .iter()
            .all(|r| !r.site.contains("secret") && !r.site.contains("private"))
    );
}

#[test]
fn firefox_download_full_cleanup_removes_exact_core_and_owned_extra_rows() {
    for extras in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (profile, path) = firefox_download_fixture(dir.path(), extras);
        let report = firefox_scan(&profile, &[PrivacyCategory::Downloads]);
        assert!(!report.partial, "{:?}", report.skipped);
        let receipt = firefox_clean(
            dir.path(),
            &report,
            &report.records.iter().map(|r| r.id).collect::<Vec<_>>(),
        );
        assert_eq!(
            (receipt.selected, receipt.deleted, receipt.skipped),
            (3, 3, 0),
            "{:?}",
            receipt.errors
        );
        let db = Connection::open(path).unwrap();
        assert_eq!(firefox_ids(&db, "moz_places"), vec![2, 3, 4]);
        assert_eq!(firefox_ids(&db, "moz_historyvisits"), vec![30, 40]);
        assert_eq!(firefox_ids(&db, "moz_annos"), vec![23, 31, 41]);
        assert_eq!(firefox_ids(&db, "moz_bookmarks"), vec![1, 2]);
        assert_eq!(firefox_ids(&db, "moz_anno_attributes"), vec![1, 2, 3, 4, 5]);
        let retained: (i64, Option<i64>) = db
            .query_row(
                "SELECT visit_count,last_visit_date FROM moz_places WHERE id=2",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(retained, (0, None));
        assert_eq!(
            db.query_row(
                "SELECT from_visit FROM moz_historyvisits WHERE id=30",
                [],
                |r| r.get::<_, Option<i64>>(0)
            )
            .unwrap(),
            None
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );
        if extras {
            assert_eq!(
                db.query_row("SELECT count(*) FROM moz_places_extra", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                3
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM moz_historyvisits_extra", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                2
            );
        }
        assert_eq!(
            db.query_row("SELECT data FROM unrelated_state", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "keep"
        );
        assert_eq!(
            fs::read(dir.path().join("downloaded-file.txt")).unwrap(),
            b"actual downloaded contents stay"
        );
        assert_eq!(
            fs::read(profile.root.join("prefs.js")).unwrap(),
            b"preferences stay"
        );
        assert_eq!(
            fs::read(profile.root.join("logins.json")).unwrap(),
            b"credentials stay"
        );
    }
}

#[test]
fn firefox_download_selective_cleanup_keeps_bookmarks_and_unselected_downloads() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, path) = firefox_download_fixture(dir.path(), true);
    let report = firefox_scan(&profile, &[PrivacyCategory::Downloads]);
    let selected = report
        .records
        .iter()
        .find(|r| r.site == "saved.test")
        .unwrap();
    let receipt = firefox_clean(dir.path(), &report, &[selected.id]);
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (1, 0),
        "{:?}",
        receipt.errors
    );
    let db = Connection::open(path).unwrap();
    assert_eq!(firefox_ids(&db, "moz_places"), vec![1, 2, 3, 4, 5]);
    assert_eq!(
        firefox_ids(&db, "moz_historyvisits"),
        vec![10, 11, 30, 40, 50]
    );
    assert_eq!(firefox_ids(&db, "moz_annos"), vec![11, 12, 23, 31, 41, 51]);
    assert_eq!(firefox_ids(&db, "moz_bookmarks"), vec![1, 2]);
    assert_eq!(firefox_native_download_counts(&db), [3, 2, 3]);
}

#[test]
fn firefox_history_only_cleanup_preserves_download_annotations_visits_and_pages() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, path) = firefox_download_fixture(dir.path(), true);
    let report = firefox_scan(&profile, &[PrivacyCategory::History]);
    assert_eq!(report.records.len(), 2);
    assert!(!report.partial);
    let receipt = firefox_clean(
        dir.path(),
        &report,
        &report.records.iter().map(|r| r.id).collect::<Vec<_>>(),
    );
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (2, 0),
        "{:?}",
        receipt.errors
    );
    let db = Connection::open(path).unwrap();
    assert_eq!(firefox_ids(&db, "moz_places"), vec![1, 2, 3, 4, 5]);
    assert_eq!(firefox_ids(&db, "moz_historyvisits"), vec![10, 11, 20, 50]);
    assert_eq!(
        firefox_ids(&db, "moz_annos"),
        vec![11, 12, 21, 22, 23, 31, 41, 51]
    );
    assert_eq!(firefox_native_download_counts(&db), [4, 2, 5]);
}

#[test]
fn firefox_download_null_and_orphan_annotations_match_sql_membership() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, path) = firefox_download_fixture(dir.path(), false);
    let db = Connection::open(&path).unwrap();
    db.execute_batch("INSERT INTO moz_annos VALUES(61,999,1,'orphan'),(62,NULL,1,'no place'); INSERT INTO moz_historyvisits VALUES(60,999,NULL,60);").unwrap();
    drop(db);
    let report = firefox_scan(&profile, &[PrivacyCategory::Downloads]);
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!(report.records.len(), 5);
    assert_eq!(
        report.records.iter().map(|r| r.item_count()).sum::<usize>(),
        14
    );
    assert_eq!(
        firefox_native_download_counts(&Connection::open(&path).unwrap()),
        [5, 2, 7]
    );
    let receipt = firefox_clean(
        dir.path(),
        &report,
        &report.records.iter().map(|r| r.id).collect::<Vec<_>>(),
    );
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (5, 0),
        "{:?}",
        receipt.errors
    );
    let db = Connection::open(path).unwrap();
    assert_eq!(firefox_ids(&db, "moz_annos"), vec![23, 31, 41]);
    assert_eq!(firefox_ids(&db, "moz_historyvisits"), vec![30, 40]);
}

#[test]
fn firefox_wal_relationship_and_schema_drift_never_expands_reviewed_effects() {
    for change in [
        "UPDATE moz_annos SET content='changed' WHERE id=12",
        "INSERT INTO moz_annos VALUES(63,1,2,'new dependency')",
        "INSERT INTO moz_bookmarks VALUES(3,1)",
        "UPDATE moz_anno_attributes SET name='custom/changed' WHERE id=1",
        "INSERT INTO moz_historyvisits VALUES(70,3,10,70)",
        "UPDATE moz_historyvisits SET from_visit=11 WHERE id=40",
        "UPDATE moz_places_extra SET sync_json='changed' WHERE place_id=1",
        "UPDATE moz_historyvisits_extra SET sync_json='changed' WHERE visit_id=10",
        "CREATE TRIGGER unsupported_cleanup AFTER DELETE ON moz_annos BEGIN DELETE FROM unrelated_state; END",
        "CREATE TABLE new_child(id INTEGER PRIMARY KEY,place_id INTEGER REFERENCES moz_places(id) ON DELETE CASCADE); INSERT INTO new_child VALUES(1,1)",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (profile, path) = firefox_download_fixture(dir.path(), true);
        let writer = Connection::open(&path).unwrap();
        writer
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        let report = firefox_scan(&profile, &[PrivacyCategory::Downloads]);
        assert!(!report.partial);
        let selected = report
            .records
            .iter()
            .find(|r| r.site == "download.test")
            .unwrap();
        let before = fs::read(&path).unwrap();
        writer.execute_batch(change).unwrap();
        assert_eq!(fs::read(&path).unwrap(), before, "{change}");
        let receipt = firefox_clean(dir.path(), &report, &[selected.id]);
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (0, 1),
            "{change}: {:?}",
            receipt.errors
        );
        assert_eq!(firefox_ids(&writer, "moz_places"), vec![1, 2, 3, 4, 5]);
        assert!(firefox_ids(&writer, "moz_historyvisits").contains(&10));
        assert!(firefox_ids(&writer, "moz_annos").contains(&11));
        assert_eq!(
            writer
                .query_row("SELECT data FROM unrelated_state", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "keep"
        );
    }
}

#[test]
fn firefox_unsupported_shapes_are_read_only_partial_instead_of_claimed_coverage() {
    for change in [
        "DROP TABLE moz_anno_attributes",
        "ALTER TABLE moz_annos RENAME COLUMN anno_attribute_id TO unsupported",
        "UPDATE moz_annos SET content=CAST(x'80' AS TEXT) WHERE id=12",
        "ALTER TABLE moz_places ADD COLUMN rowid INTEGER",
        "CREATE TRIGGER unknown_effect AFTER DELETE ON moz_historyvisits BEGIN DELETE FROM unrelated_state; END",
        "CREATE TABLE unknown_cascade(place_id INTEGER REFERENCES moz_places(id) ON DELETE CASCADE)",
        "DROP TABLE moz_places_extra; CREATE TABLE moz_places_extra(place_id INTEGER PRIMARY KEY,sync_json TEXT)",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (profile, path) = firefox_download_fixture(dir.path(), true);
        let db = Connection::open(&path).unwrap();
        db.execute_batch(change).unwrap();
        drop(db);
        let before = fs::read(&path).unwrap();
        let report = firefox_scan(
            &profile,
            &[PrivacyCategory::Downloads, PrivacyCategory::History],
        );
        assert!(report.partial, "{change}");
        assert!(report.records.is_empty(), "{change}");
        assert_eq!(fs::read(&path).unwrap(), before, "{change}");
    }
}

#[test]
fn firefox_download_constraints_roll_back_prior_selected_groups() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, path) = firefox_download_fixture(dir.path(), false);
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE protected_reference(place_id INTEGER REFERENCES moz_places(id) ON DELETE RESTRICT); INSERT INTO protected_reference VALUES(5);").unwrap();
    drop(db);
    let report = firefox_scan(&profile, &[PrivacyCategory::Downloads]);
    assert!(!report.partial);
    let receipt = firefox_clean(
        dir.path(),
        &report,
        &report.records.iter().map(|r| r.id).collect::<Vec<_>>(),
    );
    assert_eq!((receipt.deleted, receipt.skipped), (0, 3));
    assert!(!receipt.errors.is_empty());
    let db = Connection::open(path).unwrap();
    assert_eq!(firefox_ids(&db, "moz_places"), vec![1, 2, 3, 4, 5]);
    assert_eq!(firefox_native_download_counts(&db), [4, 2, 5]);
    assert_eq!(
        db.query_row(
            "SELECT from_visit FROM moz_historyvisits WHERE id=30",
            [],
            |r| r.get::<_, Option<i64>>(0)
        )
        .unwrap(),
        Some(10)
    );
}

#[test]
fn firefox_combined_history_and_download_cleanup_has_disjoint_owned_effects() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, path) = firefox_download_fixture(dir.path(), true);
    let report = firefox_scan(
        &profile,
        &[PrivacyCategory::History, PrivacyCategory::Downloads],
    );
    assert!(!report.partial);
    assert_eq!(report.records.len(), 5);
    let receipt = firefox_clean(
        dir.path(),
        &report,
        &report.records.iter().map(|r| r.id).collect::<Vec<_>>(),
    );
    assert_eq!(
        (receipt.deleted, receipt.skipped),
        (5, 0),
        "{:?}",
        receipt.errors
    );
    let db = Connection::open(path).unwrap();
    assert_eq!(firefox_ids(&db, "moz_places"), vec![2, 3, 4]);
    assert!(firefox_ids(&db, "moz_historyvisits").is_empty());
    assert_eq!(firefox_ids(&db, "moz_annos"), vec![23, 31, 41]);
    assert_eq!(
        db.query_row("SELECT count(*) FROM moz_historyvisits_extra", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(firefox_ids(&db, "moz_bookmarks"), vec![1, 2]);
}

#[test]
fn firefox_non_download_annotations_require_declared_cascade_ownership() {
    for cascade in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (profile, path) = firefox_download_fixture(dir.path(), false);
        let db = Connection::open(&path).unwrap();
        if cascade {
            db.execute_batch("ALTER TABLE moz_annos RENAME TO old_annos;
                 CREATE TABLE moz_annos(id INTEGER PRIMARY KEY,place_id INTEGER,anno_attribute_id INTEGER,content TEXT,
                    FOREIGN KEY(place_id) REFERENCES moz_places(id) ON DELETE CASCADE);
                 INSERT INTO moz_annos SELECT * FROM old_annos; DROP TABLE old_annos;").unwrap();
        }
        db.execute_batch(
            "INSERT INTO moz_annos VALUES(13,1,3,'unselected non-download metadata');",
        )
        .unwrap();
        drop(db);
        let report = firefox_scan(&profile, &[PrivacyCategory::Downloads]);
        assert!(!report.partial, "{:?}", report.skipped);
        let selected = report
            .records
            .iter()
            .find(|r| r.site == "download.test")
            .unwrap();
        assert_eq!(selected.item_count(), 5); // Only the native core predicate units.
        let receipt = firefox_clean(dir.path(), &report, &[selected.id]);
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (1, 0),
            "{:?}",
            receipt.errors
        );
        let db = Connection::open(path).unwrap();
        assert_eq!(firefox_ids(&db, "moz_annos").contains(&13), !cascade);
        assert_eq!(firefox_ids(&db, "moz_places"), vec![2, 3, 4, 5]);
    }
}

#[test]
fn firefox_places_row_budget_is_explicit_and_does_not_publish_a_partial_effect_set() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, path) = firefox_download_fixture(dir.path(), false);
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "WITH RECURSIVE ids(x) AS (SELECT 100 UNION ALL SELECT x+1 FROM ids WHERE x<100100)
         INSERT INTO moz_anno_attributes SELECT x,'custom/bounded' FROM ids;",
    )
    .unwrap();
    drop(db);
    let before = fs::read(&path).unwrap();
    let report = firefox_scan(&profile, &[PrivacyCategory::Downloads]);
    assert!(report.partial);
    assert!(report.records.is_empty());
    assert!(report.skipped.iter().any(|s| s.reason.contains("limit")));
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn inventory_covers_known_categories_without_exposing_urls_or_cookie_values() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let report = scan_fixture(&fixture.profile);

    assert!(!report.cancelled);
    assert_eq!(report.records.len(), 5);
    assert!(
        report
            .records
            .iter()
            .any(|record| record.category == PrivacyCategory::History)
    );
    assert!(
        report
            .records
            .iter()
            .any(|record| record.category == PrivacyCategory::Cookies)
    );
    assert!(
        report
            .records
            .iter()
            .any(|record| record.category == PrivacyCategory::Downloads)
    );
    let serialized_safe_fields = report
        .records
        .iter()
        .map(|record| format!("{} {:?}", record.site, record.category))
        .collect::<String>();
    assert!(serialized_safe_fields.contains("example.test"));
    assert!(!serialized_safe_fields.contains("top-secret"));
    assert!(!serialized_safe_fields.contains("token=hidden"));
    assert!(!serialized_safe_fields.contains("First title"));
    assert!(!serialized_safe_fields.contains("secret-cookie"));
    assert!(!serialized_safe_fields.contains("password-must-never-be-read"));
}

#[test]
fn selected_rows_are_transactionally_deleted_after_backup_and_unselected_rows_survive() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let report = scan_fixture(&fixture.profile);
    let history_id = report
        .records
        .iter()
        .find(|record| record.category == PrivacyCategory::History)
        .unwrap()
        .id;
    let cookie_id = report
        .records
        .iter()
        .find(|record| record.category == PrivacyCategory::Cookies && record.site == "example.test")
        .unwrap()
        .id;
    let selected = vec![history_id, cookie_id];
    let plan = build_cleanup_plan(&report, &selected).unwrap();
    let data_dir = dir.path().join("app-data");
    let mut progress = Vec::new();
    let receipt = clean_privacy_with_runtime(
        &data_dir,
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |done, total| progress.push((done, total)),
    )
    .unwrap();

    assert_eq!(receipt.selected, 2);
    assert_eq!(receipt.deleted, 2);
    assert_eq!(receipt.skipped, 0);
    assert!(!receipt.uncertain);
    assert_eq!(receipt.backups.len(), 2);
    assert!(receipt.backups.iter().all(|path| path.is_file()));
    assert!(!progress.is_empty());
    assert!(recover_privacy_operations(&data_dir).unwrap().is_empty());

    let history = Connection::open(&fixture.history_path).unwrap();
    let urls: i64 = history
        .query_row("SELECT count(*) FROM urls", [], |row| row.get(0))
        .unwrap();
    let visits: i64 = history
        .query_row("SELECT count(*) FROM visits", [], |row| row.get(0))
        .unwrap();
    let downloads: i64 = history
        .query_row("SELECT count(*) FROM downloads", [], |row| row.get(0))
        .unwrap();
    let logins: i64 = history
        .query_row("SELECT count(*) FROM logins", [], |row| row.get(0))
        .unwrap();
    assert_eq!((urls, visits, downloads, logins), (1, 1, 1, 1));
    let preference: String = history
        .query_row(
            "SELECT value FROM preferences WHERE name='theme'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(preference, "dark");
    let visit_dependencies: i64 = history
        .query_row(
            "SELECT (SELECT count(*) FROM visit_source WHERE id=1)
                  + (SELECT count(*) FROM content_annotations WHERE visit_id=1)
                  + (SELECT count(*) FROM context_annotations WHERE visit_id=1)
                  + (SELECT count(*) FROM clusters_and_visits WHERE visit_id=1)
                  + (SELECT count(*) FROM cluster_visit_duplicates WHERE visit_id=1 OR duplicate_visit_id=1)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(visit_dependencies, 0);
    let retained_cluster_members: i64 = history
        .query_row(
            "SELECT count(*) FROM clusters_and_visits WHERE cluster_id=20 AND visit_id=2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let removed_cluster: i64 = history
        .query_row(
            "SELECT count(*) FROM clusters WHERE cluster_id=10",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let retained_cluster_keyword: i64 = history
        .query_row(
            "SELECT count(*) FROM cluster_keywords WHERE cluster_id=20",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let unselected_download_children: i64 = history
        .query_row(
            "SELECT (SELECT count(*) FROM downloads_url_chains WHERE id=1)
                  + (SELECT count(*) FROM downloads_slices WHERE download_id=1)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        (
            retained_cluster_members,
            removed_cluster,
            retained_cluster_keyword
        ),
        (1, 0, 1)
    );
    assert_eq!(unselected_download_children, 3);
    let foreign_key_errors: i64 = history
        .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(foreign_key_errors, 0);
    let cookies = Connection::open(&fixture.cookies_path).unwrap();
    let remaining_cookies: i64 = cookies
        .query_row("SELECT count(*) FROM cookies", [], |row| row.get(0))
        .unwrap();
    assert_eq!(remaining_cookies, 1);

    // Reopen the verified recovery image as a fresh database and prove it restores the
    // pre-cleanup state, including both visits and the password row (without reading it).
    let backup_path = receipt
        .backups
        .iter()
        .find(|backup| {
            Connection::open_with_flags(backup, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .and_then(|connection| {
                    connection
                        .query_row("SELECT count(*) FROM urls", [], |row| row.get::<_, i64>(0))
                })
                .is_ok()
        })
        .unwrap();
    let restored_path = dir.path().join("restored-history.sqlite");
    let source =
        Connection::open_with_flags(backup_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut restored = Connection::open(&restored_path).unwrap();
    Backup::new(&source, &mut restored)
        .unwrap()
        .run_to_completion(128, std::time::Duration::from_millis(5), None)
        .unwrap();
    assert_eq!(
        restored
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    let restored_counts: (i64, i64, i64) = restored
        .query_row(
            "SELECT (SELECT count(*) FROM urls),(SELECT count(*) FROM visits),(SELECT count(*) FROM logins)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(restored_counts, (2, 2, 1));
}

#[test]
fn chromium_download_cleanup_removes_url_chain_and_slices_transactionally() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let report = scan_fixture(&fixture.profile);
    let download = report
        .records
        .iter()
        .find(|record| record.category == PrivacyCategory::Downloads)
        .unwrap();
    let plan = build_cleanup_plan(&report, &[download.id]).unwrap();
    let receipt = clean_privacy_with_runtime(
        &dir.path().join("app-data"),
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(
        (receipt.selected, receipt.deleted, receipt.skipped),
        (1, 1, 0)
    );
    let history = Connection::open(&fixture.history_path).unwrap();
    let remaining: i64 = history
        .query_row(
            "SELECT (SELECT count(*) FROM downloads WHERE id=1)
                  + (SELECT count(*) FROM downloads_url_chains WHERE id=1)
                  + (SELECT count(*) FROM downloads_slices WHERE download_id=1)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let fk_errors: i64 = history
        .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!((remaining, fk_errors), (0, 0));
}

#[test]
fn firefox_history_removal_preserves_bookmarks_and_referential_consistency() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, places_path) = firefox_fixture(dir.path());
    let report = scan_fixture(&profile);
    // This fixture has no optional cookies database; absence is not a scan gap.
    assert!(!report.partial, "{:?}", report.skipped);
    assert!(report.skipped.is_empty());
    let bookmarked_record = report
        .records
        .iter()
        .find(|record| {
            record.category == PrivacyCategory::History && record.site == "bookmarked.example.test"
        })
        .unwrap();
    let plan = build_cleanup_plan(&report, &[bookmarked_record.id]).unwrap();
    let data_dir = dir.path().join("app-data");
    let receipt = clean_privacy_with_runtime(
        &data_dir,
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();

    assert_eq!(
        (receipt.selected, receipt.deleted, receipt.skipped),
        (1, 1, 0)
    );
    let places = Connection::open(&places_path).unwrap();
    let selected_place: (i64, Option<i64>, i64) = places
        .query_row(
            "SELECT visit_count,last_visit_date,foreign_count FROM moz_places WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let bookmarks: i64 = places
        .query_row("SELECT count(*) FROM moz_bookmarks WHERE fk=1", [], |row| {
            row.get(0)
        })
        .unwrap();
    let visits: i64 = places
        .query_row("SELECT count(*) FROM moz_historyvisits", [], |row| {
            row.get(0)
        })
        .unwrap();
    let referring_visit: Option<i64> = places
        .query_row(
            "SELECT from_visit FROM moz_historyvisits WHERE id=2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let retained_metadata: i64 = places
        .query_row(
            "SELECT (SELECT count(*) FROM moz_annos WHERE place_id=1)
                  + (SELECT count(*) FROM moz_inputhistory WHERE place_id=1)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let fk_errors: i64 = places
        .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(selected_place, (0, None, 1));
    assert_eq!(
        (
            bookmarks,
            visits,
            referring_visit,
            retained_metadata,
            fk_errors
        ),
        (1, 1, None, 2, 0)
    );
}

#[test]
fn unknown_ids_and_cancelled_reports_cannot_build_a_cleanup_plan() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let report = scan_fixture(&fixture.profile);
    assert!(build_cleanup_plan(&report, &[Uuid::new_v4()]).is_err());

    let cancelled = scan_profiles(&[fixture.profile], &AtomicBool::new(true), |_| {});
    assert!(cancelled.cancelled);
    assert!(build_cleanup_plan(&cancelled, &[Uuid::new_v4()]).is_err());
}

#[test]
fn changed_database_is_skipped_without_mutating_fixture_data() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let report = scan_fixture(&fixture.profile);
    let record = report
        .records
        .iter()
        .find(|record| record.category == PrivacyCategory::History)
        .unwrap();
    let plan = build_cleanup_plan(&report, &[record.id]).unwrap();
    let connection = Connection::open(&fixture.history_path).unwrap();
    connection
        .execute("UPDATE urls SET title='Changed after scan' WHERE id=1", [])
        .unwrap();
    drop(connection);

    let data_dir = dir.path().join("app-data");
    let receipt = clean_privacy_with_runtime(
        &data_dir,
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(receipt.deleted, 0);
    assert_eq!(receipt.skipped, 1);
    assert!(receipt.backups.is_empty());
    let connection = Connection::open(&fixture.history_path).unwrap();
    let rows: i64 = connection
        .query_row("SELECT count(*) FROM urls", [], |row| row.get(0))
        .unwrap();
    let title: String = connection
        .query_row("SELECT title FROM urls WHERE id=1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 2);
    assert_eq!(title, "Changed after scan");
}

#[test]
fn running_browser_conflict_blocks_cleanup_before_journal_or_snapshot() {
    struct RunningRuntime;
    impl BrowserRuntime for RunningRuntime {
        fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
            Ok(vec![RunningBrowser {
                browser: Browser::Chrome,
                pid: 42,
                executable: "chrome.exe".into(),
            }])
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let report = scan_fixture(&fixture.profile);
    let record = report
        .records
        .iter()
        .find(|record| record.category == PrivacyCategory::Cookies)
        .unwrap();
    let plan = build_cleanup_plan(&report, &[record.id]).unwrap();
    let data_dir = dir.path().join("app-data");
    let result = clean_privacy_with_runtime(
        &data_dir,
        &plan,
        &AtomicBool::new(false),
        &RunningRuntime,
        &mut |_, _| {},
    );
    assert!(result.unwrap_err().contains("Close the selected browser"));
    assert!(!data_dir.join("privacy-operations").exists());
    assert!(!data_dir.join("privacy-recovery").exists());
    let cookies = Connection::open(&fixture.cookies_path).unwrap();
    let count: i64 = cookies
        .query_row("SELECT count(*) FROM cookies", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn cookie_keep_domains_round_trip_and_filter_only_matching_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let cookies = Connection::open(&fixture.cookies_path).unwrap();
    cookies
        .execute(
            "INSERT INTO cookies VALUES('api.sub.example.test','nested','/',999,12,22,X'6E6F742D72656164')",
            [],
        )
        .unwrap();
    drop(cookies);

    let settings_dir = dir.path().join("app-data");
    let saved = save_cookie_exception_settings(
        &settings_dir,
        &[".EXAMPLE.TEST.".into(), "example.test".into()],
    )
    .unwrap();
    assert_eq!(saved.keep_domains, ["example.test"]);
    assert_eq!(
        load_cookie_exception_settings(&settings_dir)
            .unwrap()
            .keep_domains,
        ["example.test"]
    );
    assert!(
        save_cookie_exception_settings(&settings_dir, &["https://example.test/path".into()])
            .is_err()
    );

    let report = scan_profiles_with_settings(
        &[fixture.profile],
        &[PrivacyCategory::Cookies],
        &saved,
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(report.categories_scanned, [PrivacyCategory::Cookies]);
    assert_eq!(report.cookie_exempted, 2);
    assert_eq!(report.records.len(), 1);
    assert_eq!(report.records[0].site, "other.test");
    let settings_text =
        fs::read_to_string(settings_dir.join("privacy-cookie-settings.json")).unwrap();
    assert!(!settings_text.contains("secret-cookie"));
    assert!(!settings_text.contains("not-read"));
}

#[test]
fn keeping_one_sign_in_domain_keeps_its_whole_account_group_and_subdomains() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let cookies = Connection::open(&fixture.cookies_path).unwrap();
    for (index, host) in [
        ".accounts.google.com",
        ".youtube.com",
        "mail.google.com",
        ".notgoogle.com",
        ".google.com.evil.test",
    ]
    .iter()
    .enumerate()
    {
        cookies
            .execute(
                "INSERT INTO cookies VALUES(?1,'sid','/',999,?2,22,X'00')",
                rusqlite::params![host, 100 + index as i64],
            )
            .unwrap();
    }
    drop(cookies);
    let settings =
        save_cookie_policy(&dir.path().join("app-data"), &["google.com".into()], false).unwrap();
    let report = scan_profiles_with_settings(
        &[fixture.profile],
        &[PrivacyCategory::Cookies],
        &settings,
        &AtomicBool::new(false),
        |_| {},
    );
    let mut sites = report
        .records
        .iter()
        .map(|record| record.site.as_str())
        .collect::<Vec<_>>();
    sites.sort_unstable();
    // Only lookalikes and unrelated hosts remain cleanable.
    assert_eq!(
        sites,
        [
            "example.test",
            "google.com.evil.test",
            "notgoogle.com",
            "other.test"
        ]
    );
    assert_eq!(report.cookie_exempted, 3);
}

#[test]
fn keep_signed_in_defaults_on_and_keeps_every_sign_in_record_out_of_scans() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let settings_dir = dir.path().join("app-data");
    let wanted = [
        PrivacyCategory::History,
        PrivacyCategory::Cookies,
        PrivacyCategory::SavedPasswords,
    ];

    // A fresh install, and a file saved before the switch existed, keep users signed in.
    let fresh = load_cookie_exception_settings(&settings_dir).unwrap();
    assert!(fresh.keep_signed_in);
    fs::create_dir_all(&settings_dir).unwrap();
    fs::write(
        settings_dir.join("privacy-cookie-settings.json"),
        r#"{"schema":1,"keep_domains":["bank.test"]}"#,
    )
    .unwrap();
    let legacy = load_cookie_exception_settings(&settings_dir).unwrap();
    assert!(legacy.keep_signed_in);
    assert_eq!(legacy.keep_domains, ["bank.test"]);

    let kept = sign_in_policy_categories(&wanted, &legacy);
    assert_eq!(kept, [PrivacyCategory::History]);
    let report = scan_profiles_with_settings(
        &[fixture.profile.clone()],
        &kept,
        &legacy,
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(report.records.iter().all(|record| {
        record.category != PrivacyCategory::Cookies
            && record.category != PrivacyCategory::SavedPasswords
    }));
    assert!(
        report
            .records
            .iter()
            .any(|record| record.category == PrivacyCategory::History)
    );

    // Editing keep domains never silently flips the switch.
    let edited = save_cookie_exception_settings(&settings_dir, &["mail.test".into()]).unwrap();
    assert!(edited.keep_signed_in);
    let off = save_cookie_policy(&settings_dir, &edited.keep_domains, false).unwrap();
    assert!(
        !load_cookie_exception_settings(&settings_dir)
            .unwrap()
            .keep_signed_in
    );
    assert!(
        !save_cookie_exception_settings(&settings_dir, &["mail.test".into()])
            .unwrap()
            .keep_signed_in
    );

    // Turned off, cookies are scanned again and keep domains still apply.
    assert_eq!(sign_in_policy_categories(&wanted, &off), wanted);
    let report = scan_profiles_with_settings(
        &[fixture.profile],
        &sign_in_policy_categories(&[PrivacyCategory::Cookies], &off),
        &off,
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(
        report
            .records
            .iter()
            .any(|record| record.category == PrivacyCategory::Cookies)
    );
}

#[test]
fn reviewed_restore_reinstates_fixture_database_and_keeps_current_state_copy() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let report = scan_fixture(&fixture.profile);
    let history_record = report
        .records
        .iter()
        .find(|record| record.category == PrivacyCategory::History)
        .unwrap();
    let plan = build_cleanup_plan(&report, &[history_record.id]).unwrap();
    let data_dir = dir.path().join("app-data");
    let cleanup = clean_privacy_with_runtime(
        &data_dir,
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(cleanup.deleted, 1);

    let options = list_privacy_restore_options(&data_dir).unwrap();
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].state, PrivacyRecoveryState::Ready);
    assert_eq!(options[0].database_name, "History");
    assert_eq!(options[0].record_count, 1);

    let restore_plan =
        prepare_privacy_restore_with_runtime(&data_dir, options[0].id, &EmptyRuntime).unwrap();
    assert_eq!(restore_plan.database_name(), "History");
    assert_eq!(restore_plan.profile_name(), "Fixture profile");
    let restored =
        restore_privacy_database_with_runtime(&data_dir, &restore_plan, &EmptyRuntime).unwrap();
    assert!(restored.restored);
    assert!(!restored.uncertain);
    assert!(restored.current_state_backup.as_ref().unwrap().is_file());

    let history = Connection::open(&fixture.history_path).unwrap();
    let counts: (i64, i64, i64) = history
        .query_row(
            "SELECT (SELECT count(*) FROM urls),(SELECT count(*) FROM visits),(SELECT count(*) FROM logins)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counts, (2, 2, 1));
    assert_eq!(
        history
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    let after = list_privacy_restore_options(&data_dir).unwrap();
    assert_eq!(after[0].state, PrivacyRecoveryState::Restored);
}

#[test]
fn reviewed_restore_refuses_a_database_changed_after_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = chrome_fixture(dir.path());
    let report = scan_fixture(&fixture.profile);
    let history_record = report
        .records
        .iter()
        .find(|record| record.category == PrivacyCategory::History)
        .unwrap();
    let plan = build_cleanup_plan(&report, &[history_record.id]).unwrap();
    let data_dir = dir.path().join("app-data");
    let cleanup = clean_privacy_with_runtime(
        &data_dir,
        &plan,
        &AtomicBool::new(false),
        &EmptyRuntime,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(cleanup.deleted, 1);
    let restore_id = list_privacy_restore_options(&data_dir).unwrap()[0].id;

    let history = Connection::open(&fixture.history_path).unwrap();
    history
        .execute("UPDATE urls SET title='Concurrent edit' WHERE id=2", [])
        .unwrap();
    drop(history);

    let error = prepare_privacy_restore_with_runtime(&data_dir, restore_id, &EmptyRuntime)
        .err()
        .unwrap();
    assert!(error.contains("changed") || error.contains("match"));
    let history = Connection::open(&fixture.history_path).unwrap();
    let title: String = history
        .query_row("SELECT title FROM urls WHERE id=2", [], |row| row.get(0))
        .unwrap();
    assert_eq!(title, "Concurrent edit");
}
