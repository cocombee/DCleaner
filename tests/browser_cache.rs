use dcleaner::{
    browser_cache::{self, CacheRule},
    clean_settings::CustomCleanSettings,
    cleanup::{self, TrashPort},
    custom_clean::{self, ScanOptions},
    domain::Category,
    platform, scanner,
    store::{JournalEvent, JournalSink},
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, SystemTime},
};
use tempfile::TempDir;

fn put(root: &Path, relative: &str) -> PathBuf {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"fixture").unwrap();
    path
}
fn category(id: &str, root: &Path) -> Category {
    Category {
        cache_root_scopes: Default::default(),
        id: id.into(),
        name: id.into(),
        group: "fixture".into(),
        description: String::new(),
        roots: vec![root.into()],
    }
}
fn witness(rule: &CacheRule) -> String {
    let directory = rule
        .directory
        .replace('*', "Fixture Profile")
        .replace('?', "x");
    let filter = rule.files.split(';').next().unwrap();
    let file = if filter == "*.*" || filter == "*" {
        "extensionless".into()
    } else {
        filter.replace('*', "fixture").replace('?', "x")
    };
    if directory.is_empty() {
        file
    } else {
        format!("{directory}/{file}")
    }
}
#[test]
fn every_reference_cache_rule_is_reached_without_a_blanket_profile_scan() {
    for (id, rules) in [
        ("chrome", browser_cache::CHROME_RULES),
        ("edge", browser_cache::EDGE_RULES),
        ("firefox", browser_cache::FIREFOX_RULES),
    ] {
        let fixture = TempDir::new().unwrap();
        let expected: std::collections::HashSet<_> = rules
            .iter()
            .map(|rule| put(fixture.path(), &witness(rule)))
            .collect();
        for file in [
            "Default/Login Data",
            "Default/Bookmarks",
            "Default/Preferences",
            "Default/Network/Cookies",
            "Default/IndexedDB/https_unrelated.example_0.indexeddb.leveldb/secret",
            "Default/Cache-lookalike/preserve",
        ] {
            put(fixture.path(), file);
        }
        let report = scanner::analyze(
            &[category(id, fixture.path())],
            &[id.into()],
            365,
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        let actual: std::collections::HashSet<_> = report.categories[0]
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect();
        assert_eq!(
            actual, expected,
            "{id}: every declared rule and negative fixture"
        );
        assert!(report.categories[0].available);
        assert!(!report.categories[0].truncated);
    }
}
#[derive(Default)]
struct MemoryJournal(Vec<JournalEvent>);
impl JournalSink for MemoryJournal {
    fn append(&mut self, event: &JournalEvent) -> Result<(), String> {
        self.0.push(event.clone());
        Ok(())
    }
}
#[derive(Default)]
struct Trash(Vec<PathBuf>);
impl TrashPort for Trash {
    fn move_to_trash(&mut self, path: &Path) -> Result<(), String> {
        self.0.push(path.into());
        Ok(())
    }
}
#[test]
fn recent_browser_files_are_reviewable_and_cleanable_but_temp_age_and_identity_guards_remain() {
    let fixture = TempDir::new().unwrap();
    let root = fixture.path();
    let recent = put(root, "browser/Default/Cache/data");
    let changed = put(root, "browser/Default/GPUCache/data");
    let old = put(root, "temp/old");
    put(root, "temp/recent");
    filetime::set_file_mtime(
        &old,
        filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_secs(8 * 86400)),
    )
    .unwrap();
    let report = scanner::analyze(
        &[
            category("chrome", &root.join("browser")),
            category("temp", &root.join("temp")),
        ],
        &["chrome".into(), "temp".into()],
        7,
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(report.categories[0].files.len(), 2);
    assert_eq!(report.categories[1].files.len(), 1);
    fs::write(changed, b"changed since analysis").unwrap();
    let ids = report
        .categories
        .iter()
        .flat_map(|c| c.files.iter().map(|f| f.id))
        .collect::<Vec<_>>();
    let mut trash = Trash::default();
    let mut journal = MemoryJournal::default();
    let outcome = cleanup::clean(
        &report,
        &ids,
        &AtomicBool::new(false),
        &mut trash,
        &mut journal,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(outcome.files, 2);
    assert_eq!(outcome.failed.len(), 1);
    assert!(trash.0.contains(&recent));
    assert!(trash.0.contains(&old));
    assert!(!journal.0.is_empty());
}
#[test]
fn custom_clean_uses_the_same_browser_scope_and_zero_age_through_reviewed_cleanup() {
    let fixture = TempDir::new().unwrap();
    put(fixture.path(), "Odd Profile/Cache/new");
    put(fixture.path(), "Odd Profile/ShaderCache/new");
    put(fixture.path(), "Odd Profile/Bookmarks");
    let settings = CustomCleanSettings::default();
    let options = ScanOptions {
        categories: vec![category("chrome", fixture.path())],
        selected_legacy_ids: vec!["chrome".into()],
        ..Default::default()
    };
    let report = custom_clean::scan(&settings, &options, &AtomicBool::new(false), |_| {}).unwrap();
    assert!(!report.partial());
    assert_eq!(report.files().len(), 2);
    assert!(report.files().iter().all(|f| {
        f.eligibility()
            .iter()
            .any(|e| e.age_threshold_days() == Some(0))
    }));
    let ids = report.files().iter().map(|f| f.id()).collect::<Vec<_>>();
    let mut trash = Trash::default();
    let mut journal = MemoryJournal::default();
    let outcome = custom_clean::clean(
        &report,
        &settings,
        &ids,
        false,
        &AtomicBool::new(false),
        &mut trash,
        &mut journal,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(outcome.files, 2);
}
#[test]
fn discovery_covers_channels_store_profiles_and_non_numeric_profiles_without_false_missing_sources()
{
    let fixture = TempDir::new().unwrap();
    let root = fixture.path();
    for d in ["local", "roaming", "program", "common"] {
        fs::create_dir(root.join(d)).unwrap();
    }
    let beta = root.join("local/Google/Chrome Beta/User Data");
    put(&beta, "Work Profile/Media Cache/data");
    let edge = root.join("local/Microsoft/Edge Dev/User Data");
    put(&edge, "Person custom/Storage/ext/extid/def/Code Cache/data");
    put(&edge, "Nested person/Default/ShaderCache/data");
    let roaming_edge = root.join("roaming/Microsoft/Edge/User Data");
    put(&roaming_edge, "Person/Cache/must-stay");
    put(&roaming_edge, "Person/journal-journal");
    put(&roaming_edge, "ShaderCache/data");
    let firefox = root.join(
        "local/Packages/Mozilla.Firefox_n80bbvh6b1yt2/LocalCache/Local/Mozilla/Firefox/Profiles",
    );
    put(&firefox, "custom/cache.trash42/data");
    put(
        &root.join("common/Mozilla-fixture"),
        "profile_count_test.json",
    );
    let cats = platform::browser_categories_at(
        &root.join("local"),
        &root.join("roaming"),
        &root.join("program"),
        &root.join("common"),
    );
    let ids = cats.iter().map(|c| c.id.clone()).collect::<Vec<_>>();
    let report = scanner::analyze(&cats, &ids, 7, &AtomicBool::new(false), |_, _| {}).unwrap();
    assert_eq!(report.count(), 7);
    assert!(
        report
            .categories
            .iter()
            .all(|c| c.available && c.skipped == 0)
    );
    let empty = platform::browser_categories_at(
        &root.join("nothing"),
        &root.join("missing"),
        &root.join("absent"),
        &root.join("no-common"),
    );
    assert!(empty.iter().all(|c| c.roots.is_empty()));
    let report = custom_clean::scan(
        &CustomCleanSettings::default(),
        &ScanOptions {
            categories: empty,
            selected_legacy_ids: ids,
            ..Default::default()
        },
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert!(!report.partial());
    assert!(report.files().is_empty());
}
#[test]
fn wildcard_segments_are_bounded_and_do_not_cross_into_other_website_storage() {
    let root = Path::new("fixture");
    assert!(browser_cache::includes(
        "edge",
        root,
        &root.join("Any Profile/Storage/ext/id/def/Cache/extensionless")
    ));
    assert!(!browser_cache::includes(
        "edge",
        root,
        &root.join("Any Profile/Storage/ext/id/other/Cache/data")
    ));
    assert!(!browser_cache::includes(
        "chrome",
        root,
        &root.join("../Default/Cache/data")
    ));
    assert!(browser_cache::includes(
        "chrome",
        root,
        &root.join("Default/nested/session-journal")
    ));
    assert!(!browser_cache::includes(
        "chrome",
        root,
        &root.join("Default/nested/session-journal-backup")
    ));
    assert!(browser_cache::includes(
        "firefox",
        Path::new("Mozilla-fixture"),
        Path::new("Mozilla-fixture/uninstall_ping_a.json")
    ));
    assert!(!browser_cache::includes(
        "firefox",
        Path::new("Mozilla-fixture"),
        Path::new("Mozilla-fixture/nested/uninstall_ping_a.json")
    ));
}
#[cfg(windows)]
#[test]
fn redirected_cache_roots_are_reported_and_never_followed() {
    let fixture = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    put(outside.path(), "Default/Cache/secret");
    let link = fixture.path().join("linked");
    if let Err(error) = std::os::windows::fs::symlink_dir(outside.path(), &link) {
        eprintln!("Native link fixture unavailable: {error}");
        return;
    }
    let report = scanner::analyze(
        &[category("chrome", &link)],
        &["chrome".into()],
        7,
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(report.count(), 0);
    assert!(!report.categories[0].available);
    fs::remove_dir(&link).unwrap();
}

#[test]
fn all_fifteen_browser_families_match_each_reference_root_in_health_and_custom_scanners() {
    assert_eq!(browser_cache::LABELS.len(), 15);
    for (index, definition) in browser_cache::REFERENCE_ROOTS.iter().enumerate() {
        let fixture = TempDir::new().unwrap();
        let expected: std::collections::HashSet<_> = definition
            .rules
            .iter()
            .map(|rule| put(fixture.path(), &witness(rule)))
            .collect();
        put(fixture.path(), "Default/Login Data");
        put(fixture.path(), "Default/Bookmarks");
        put(fixture.path(), "Default/not-a-cache/private");
        let mut input = category(definition.category, fixture.path());
        input.cache_root_scopes.insert(
            fixture.path().into(),
            browser_cache::RootScope::Reference(index as u16),
        );
        let scan = scanner::analyze(
            &[input.clone()],
            &[definition.category.into()],
            365,
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        let actual: std::collections::HashSet<_> = scan.categories[0]
            .files
            .iter()
            .map(|f| f.path.clone())
            .collect();
        assert_eq!(
            actual, expected,
            "native catalogue root {} {}",
            definition.category, definition.relative
        );
        let custom = custom_clean::scan(
            &CustomCleanSettings::default(),
            &ScanOptions {
                categories: vec![input],
                selected_legacy_ids: vec![definition.category.into()],
                ..Default::default()
            },
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        let actual: std::collections::HashSet<_> = custom
            .files()
            .iter()
            .map(|f| f.path().to_path_buf())
            .collect();
        assert_eq!(
            actual, expected,
            "Custom Clean root {} {}",
            definition.category, definition.relative
        );
        assert!(!custom.partial());
        let ids = custom
            .files()
            .iter()
            .map(|file| file.id())
            .collect::<Vec<_>>();
        let mut trash = Trash::default();
        let mut journal = MemoryJournal::default();
        let result = custom_clean::clean(
            &custom,
            &CustomCleanSettings::default(),
            &ids,
            false,
            &AtomicBool::new(false),
            &mut trash,
            &mut journal,
            |_, _| {},
        )
        .unwrap();
        assert_eq!(
            result.files,
            expected.len(),
            "Custom Clean reviewed cache effect: {}",
            definition.category
        );
        let ids = scan.categories[0]
            .files
            .iter()
            .map(|file| file.id)
            .collect::<Vec<_>>();
        let mut trash = Trash::default();
        let result = cleanup::clean(
            &scan,
            &ids,
            &AtomicBool::new(false),
            &mut trash,
            &mut MemoryJournal::default(),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(
            result.files,
            expected.len(),
            "Health reviewed cache effect: {} {}",
            definition.category,
            definition.relative
        );
    }
}
