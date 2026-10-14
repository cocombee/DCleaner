use dcleaner::privacy::{
    Browser, BrowserProfile, BrowserRuntime, PrivacyCategory, PrivacyRecoveryState, RunningBrowser,
    build_cleanup_plan, clean_privacy_with_runtime, list_privacy_restore_options,
    load_cookie_exception_settings, prepare_privacy_restore_with_runtime,
    recover_privacy_operations, restore_privacy_database_with_runtime,
    save_cookie_exception_settings, scan_profiles, scan_profiles_with_settings,
};
use rusqlite::{Connection, OpenFlags, backup::Backup};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};
use uuid::Uuid;

struct EmptyRuntime;
impl BrowserRuntime for EmptyRuntime {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        Ok(Vec::new())
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
         CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY,fk INTEGER NOT NULL,
             FOREIGN KEY(fk) REFERENCES moz_places(id) ON DELETE RESTRICT);
         CREATE TABLE moz_annos(place_id INTEGER NOT NULL,value TEXT,
             FOREIGN KEY(place_id) REFERENCES moz_places(id) ON DELETE RESTRICT);
         CREATE TABLE moz_inputhistory(place_id INTEGER NOT NULL,input TEXT,
             FOREIGN KEY(place_id) REFERENCES moz_places(id) ON DELETE RESTRICT);
         INSERT INTO moz_places VALUES(1,'https://bookmarked.example.test/','Saved',1,100,1);
         INSERT INTO moz_places VALUES(2,'https://unselected.example.test/','Other',1,200,0);
         INSERT INTO moz_historyvisits VALUES(1,1,NULL,100,1);
         INSERT INTO moz_historyvisits VALUES(2,2,1,200,1);
         INSERT INTO moz_bookmarks VALUES(7,1);
         INSERT INTO moz_annos VALUES(1,'bookmark-associated annotation');
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
    assert!(report.partial);
    assert!(report.skipped.iter().any(|skip| {
        skip.category == Some(PrivacyCategory::Downloads)
            && skip.reason.contains("Firefox download-history")
    }));
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
