use dcleaner::{
    cleanup::{self, TrashPort},
    domain::{Category, Preferences},
    scanner,
    store::{self, JournalEvent, JournalSink},
};
use std::{
    fs,
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, SystemTime},
};
use uuid::Uuid;
struct MockTrash {
    paths: Vec<std::path::PathBuf>,
}
impl TrashPort for MockTrash {
    fn move_to_trash(&mut self, p: &Path) -> Result<(), String> {
        self.paths.push(p.into());
        Ok(())
    }
}
#[derive(Default)]
struct MemoryJournal {
    events: Vec<JournalEvent>,
    fail_at: Option<usize>,
}

#[test]
fn rejected_cleanup_leaves_no_empty_history_file() {
    let (_fixture, category) = fixture();
    let data = tempfile::tempdir().unwrap();
    let mut analysis = scanner::analyze(
        &[category],
        &["temp".into()],
        7,
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    analysis.cleanup_policy = dcleaner::domain::CleanupPolicy::CustomCleanRules;
    let id = analysis.categories[0].files[0].id;
    let mut journal = store::DeferredJournal::new(data.path(), Uuid::new_v4());
    let mut trash = MockTrash { paths: vec![] };
    assert!(
        cleanup::clean(
            &analysis,
            &[id],
            &AtomicBool::new(false),
            &mut trash,
            &mut journal,
            |_, _| {}
        )
        .is_err()
    );
    assert!(!data.path().join("operations").exists());
    assert!(store::history(data.path()).unwrap().is_empty());
    assert!(trash.paths.is_empty());
}

#[test]
fn deferred_journal_persists_real_cleanup_receipts() {
    let (_fixture, category) = fixture();
    let data = tempfile::tempdir().unwrap();
    let analysis = scanner::analyze(
        &[category],
        &["temp".into()],
        7,
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    let id = analysis.categories[0].files[0].id;
    let mut journal = store::DeferredJournal::new(data.path(), Uuid::new_v4());
    let mut trash = MockTrash { paths: vec![] };
    let result = cleanup::clean(
        &analysis,
        &[id],
        &AtomicBool::new(false),
        &mut trash,
        &mut journal,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(result.files, 1);
    let history = store::history(data.path()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].cleaned_ids, vec![id]);
    assert!(!history[0].interrupted);
    assert_eq!(trash.paths.len(), 1);
}

#[cfg(windows)]
#[test]
#[ignore = "Explicit native integration run: moves and restores only a uniquely named test fixture"]
fn native_recycle_bin_roundtrip_preserves_fixture_and_receipt() {
    let (_fixture_dir, category) = fixture();
    let data = tempfile::tempdir().unwrap();
    let analysis = scanner::analyze(
        &[category],
        &["temp".into()],
        7,
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    let file = &analysis.categories[0].files[0];
    let expected = fs::read(&file.path).unwrap();
    let mut journal = store::Journal::create(data.path(), Uuid::new_v4()).unwrap();
    let result = cleanup::clean(
        &analysis,
        &[file.id],
        &AtomicBool::new(false),
        &mut cleanup::SystemTrash,
        &mut journal,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(result.files, 1);
    assert_eq!(result.bytes, expected.len() as u64);
    assert!(!file.path.exists());
    let own_item = trash::os_limited::list()
        .unwrap()
        .into_iter()
        .find(|item| scanner::same_path(&item.original_path(), &file.path))
        .expect("The exact isolated fixture must be in the Recycle Bin");
    trash::os_limited::restore_all([own_item]).unwrap();
    assert_eq!(fs::read(&file.path).unwrap(), expected);
    let recovered = store::history(data.path()).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].files, 1);
    assert!(recovered[0].uncertain.is_empty());
}
impl JournalSink for MemoryJournal {
    fn append(&mut self, event: &JournalEvent) -> Result<(), String> {
        if self.fail_at == Some(self.events.len()) {
            return Err("Simulated durable-write failure".into());
        }
        self.events.push(event.clone());
        Ok(())
    }
}
fn fixture() -> (tempfile::TempDir, Category) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("temp");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("old.tmp"), b"old data").unwrap();
    fs::write(root.join("recent.tmp"), b"recent").unwrap();
    filetime::set_file_mtime(
        root.join("old.tmp"),
        filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_secs(30 * 86400)),
    )
    .unwrap();
    let cat = Category {
        id: "temp".into(),
        name: "Temporary files".into(),
        group: "Test".into(),
        description: "Isolated test fixture".into(),
        roots: vec![root],
    };
    (dir, cat)
}
#[test]
fn scan_is_readonly_and_excludes_recent_files() {
    let (_dir, cat) = fixture();
    let a = scanner::analyze(
        &[cat.clone()],
        &["temp".into()],
        7,
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(a.count(), 1);
    assert_eq!(a.bytes(), 8);
    assert!(cat.roots[0].join("old.tmp").exists());
    assert!(cat.roots[0].join("recent.tmp").exists());
}
#[test]
fn changed_candidate_is_skipped() {
    let (_dir, cat) = fixture();
    let a = scanner::analyze(
        &[cat.clone()],
        &["temp".into()],
        7,
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    let id = a.categories[0].files[0].id;
    fs::write(cat.roots[0].join("old.tmp"), b"changed").unwrap();
    let mut trash = MockTrash { paths: vec![] };
    let mut journal = MemoryJournal::default();
    let r = cleanup::clean(
        &a,
        &[id],
        &AtomicBool::new(false),
        &mut trash,
        &mut journal,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(r.files, 0);
    assert_eq!(r.failed.len(), 1);
    assert!(trash.paths.is_empty());
}
#[test]
fn unknown_ids_reject_entire_command_before_side_effects() {
    let (_dir, cat) = fixture();
    let a = scanner::analyze(
        &[cat],
        &["temp".into()],
        7,
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    let mut trash = MockTrash { paths: vec![] };
    let mut journal = MemoryJournal::default();
    assert!(
        cleanup::clean(
            &a,
            &[a.categories[0].files[0].id, Uuid::new_v4()],
            &AtomicBool::new(false),
            &mut trash,
            &mut journal,
            |_, _| {}
        )
        .is_err()
    );
    assert!(trash.paths.is_empty());
    assert!(journal.events.is_empty());
}
#[test]
fn failed_intent_write_prevents_trash_move() {
    let (_dir, cat) = fixture();
    let a = scanner::analyze(
        &[cat],
        &["temp".into()],
        7,
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    let mut trash = MockTrash { paths: vec![] };
    let mut journal = MemoryJournal {
        fail_at: Some(1),
        ..Default::default()
    };
    assert!(
        cleanup::clean(
            &a,
            &[a.categories[0].files[0].id],
            &AtomicBool::new(false),
            &mut trash,
            &mut journal,
            |_, _| {}
        )
        .is_err()
    );
    assert!(trash.paths.is_empty());
}
#[test]
fn failed_receipt_write_preserves_uncertain_outcome() {
    let (_dir, cat) = fixture();
    let a = scanner::analyze(
        &[cat],
        &["temp".into()],
        7,
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    let mut trash = MockTrash { paths: vec![] };
    let mut journal = MemoryJournal {
        fail_at: Some(2),
        ..Default::default()
    };
    assert!(
        cleanup::clean(
            &a,
            &[a.categories[0].files[0].id],
            &AtomicBool::new(false),
            &mut trash,
            &mut journal,
            |_, _| {}
        )
        .is_err()
    );
    assert_eq!(trash.paths.len(), 1);
    let recovered = store::project_events(&journal.events).unwrap();
    assert!(recovered.interrupted);
    assert_eq!(recovered.files, 0);
    assert_eq!(recovered.uncertain.len(), 1);
}
#[test]
fn successful_receipt_survives_restart_projection() {
    let (_dir, cat) = fixture();
    let a = scanner::analyze(
        &[cat],
        &["temp".into()],
        7,
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    let mut trash = MockTrash { paths: vec![] };
    let mut journal = MemoryJournal::default();
    let r = cleanup::clean(
        &a,
        &[a.categories[0].files[0].id],
        &AtomicBool::new(false),
        &mut trash,
        &mut journal,
        |_, _| {},
    )
    .unwrap();
    let recovered = store::project_events(&journal.events).unwrap();
    assert_eq!(recovered.files, r.files);
    assert_eq!(recovered.bytes, r.bytes);
    assert!(!recovered.interrupted);
    assert!(recovered.uncertain.is_empty());
}
#[test]
fn cancelled_scan_cannot_authorize_cleanup() {
    let (_dir, cat) = fixture();
    let a = scanner::analyze(
        &[cat],
        &["temp".into()],
        7,
        &AtomicBool::new(true),
        |_, _| {},
    )
    .unwrap();
    assert!(a.cancelled);
    assert!(
        cleanup::clean(
            &a,
            &[Uuid::new_v4()],
            &AtomicBool::new(false),
            &mut MockTrash { paths: vec![] },
            &mut MemoryJournal::default(),
            |_, _| {}
        )
        .is_err()
    );
}
#[test]
fn traversal_is_bounded_and_marks_partial_results() {
    let (_dir, cat) = fixture();
    let r = scanner::walk(&cat.roots[0], u128::MAX, &AtomicBool::new(false), 1, |_| {});
    assert!(r.truncated);
    assert!(r.files.len() <= 1);
}
#[test]
fn settings_persist_and_corruption_is_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let prefs = Preferences {
        minimum_age_days: 30,
        dark: true,
        ..Default::default()
    };
    store::save_preferences(dir.path(), &prefs).unwrap();
    assert_eq!(
        store::load_preferences(dir.path())
            .unwrap()
            .minimum_age_days,
        30
    );
    store::save_preferences(dir.path(), &Preferences::default()).unwrap();
    fs::write(dir.path().join("preferences.json"), b"broken").unwrap();
    assert!(store::load_preferences(dir.path()).is_err());
    assert_eq!(
        fs::read(dir.path().join("preferences.json")).unwrap(),
        b"broken"
    );
}
#[test]
fn path_prefix_sibling_is_not_contained() {
    let root = Path::new("safe");
    assert!(!scanner::contained(root, Path::new("safe-other/file")));
    assert!(!scanner::contained(root, root));
    assert!(scanner::contained(root, &root.join("file")));
}
#[cfg(unix)]
#[test]
fn linked_directory_does_not_escape_scan_root() {
    use std::os::unix::fs::symlink;
    let (dir, cat) = fixture();
    let outside = dir.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret"), b"keep").unwrap();
    symlink(&outside, cat.roots[0].join("link")).unwrap();
    let r = scanner::walk(
        &cat.roots[0],
        u128::MAX,
        &AtomicBool::new(false),
        100,
        |_| {},
    );
    assert_eq!(r.files.len(), 2);
    assert_eq!(r.skipped, 1);
}
#[cfg(windows)]
#[test]
fn junction_is_skipped() {
    let (dir, cat) = fixture();
    let outside = dir.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep"), b"keep").unwrap();
    let link = cat.roots[0].join("junction");
    let status = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&outside)
        .output()
        .unwrap();
    assert!(status.status.success());
    let r = scanner::walk(
        &cat.roots[0],
        u128::MAX,
        &AtomicBool::new(false),
        100,
        |_| {},
    );
    assert_eq!(r.files.len(), 2);
    assert_eq!(r.skipped, 1);
    fs::remove_dir(link).unwrap();
}
