use dcleaner::{
    cleanup::{self, TrashPort},
    domain::{Analysis, Category},
    scanner,
    store::{self, JournalEvent, JournalSink},
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime},
};
use uuid::Uuid;

fn fixture(count: usize) -> (tempfile::TempDir, Analysis) {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir(&source).unwrap();
    for index in 0..count {
        let path = source.join(format!("tiny-{index}.tmp"));
        fs::write(&path, [index as u8]).unwrap();
        filetime::set_file_mtime(
            &path,
            filetime::FileTime::from_system_time(
                SystemTime::now() - Duration::from_secs(30 * 86400),
            ),
        )
        .unwrap();
    }
    let analysis = scanner::analyze(
        &[Category {
            cache_root_scopes: Default::default(),
            id: "fixture".into(),
            name: "Fixture".into(),
            group: "Test".into(),
            description: String::new(),
            roots: vec![source],
        }],
        &["fixture".into()],
        7,
        &AtomicBool::new(false),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(analysis.count(), count);
    (dir, analysis)
}
fn ids(analysis: &Analysis) -> Vec<Uuid> {
    analysis.categories[0]
        .files
        .iter()
        .map(|file| file.id)
        .collect()
}

#[derive(Default)]
struct MemoryJournal {
    events: Vec<JournalEvent>,
    fail_at: Option<usize>,
}
impl JournalSink for MemoryJournal {
    fn append(&mut self, event: &JournalEvent) -> Result<(), String> {
        if self.fail_at == Some(self.events.len()) {
            return Err("injected journal failure".into());
        }
        self.events.push(event.clone());
        Ok(())
    }
}
struct FixtureTrash {
    destination: PathBuf,
    batches: Vec<usize>,
    fail_after_first: bool,
}
impl FixtureTrash {
    fn new(root: &Path) -> Self {
        let destination = root.join("owned-trash");
        fs::create_dir(&destination).unwrap();
        Self {
            destination,
            batches: Vec::new(),
            fail_after_first: false,
        }
    }
}
impl TrashPort for FixtureTrash {
    fn move_to_trash(&mut self, _: &Path) -> Result<(), String> {
        panic!("no individual retry")
    }
    fn batch_size(&self) -> usize {
        32
    }
    fn move_batch_to_trash(&mut self, paths: &[&Path]) -> Result<(), String> {
        self.batches.push(paths.len());
        for (index, path) in paths.iter().enumerate() {
            fs::rename(path, self.destination.join(path.file_name().unwrap())).unwrap();
            if self.fail_after_first && index == 0 {
                return Err("injected partial native effect".into());
            }
        }
        Ok(())
    }
}

#[test]
fn bounded_batches_preserve_exact_ids_skip_changed_files_and_reopen_durable_history() {
    let (dir, analysis) = fixture(70);
    let selected = ids(&analysis);
    let changed = &analysis.categories[0].files[4];
    fs::write(&changed.path, b"changed").unwrap();
    let mut trash = FixtureTrash::new(dir.path());
    let data = dir.path().join("data");
    let mut journal = store::DeferredJournal::new(&data, Uuid::new_v4());
    let mut progress = Vec::new();
    let result = cleanup::clean(
        &analysis,
        &selected,
        &AtomicBool::new(false),
        &mut trash,
        &mut journal,
        |done, total| progress.push((done, total)),
    )
    .unwrap();
    assert_eq!(trash.batches, [31, 32, 6]);
    assert_eq!(progress, [(32, 70), (64, 70), (70, 70)]);
    assert_eq!(result.files, 69);
    assert_eq!(result.bytes, 69);
    assert_eq!(result.failed[0].file_id, changed.id);
    assert_eq!(fs::read(&changed.path).unwrap(), b"changed");
    assert!(!result.cleaned_ids.contains(&changed.id));
    drop(journal);
    let history = store::history(&data).unwrap();
    assert_eq!(history[0].cleaned_ids, result.cleaned_ids);
    assert_eq!(history[0].failed.len(), 1);
    assert!(history[0].uncertain.is_empty());
    assert!(!history[0].interrupted);
}

#[test]
fn incomplete_batch_intents_prevent_every_effect() {
    let (dir, analysis) = fixture(40);
    let mut journal = MemoryJournal {
        fail_at: Some(20),
        ..Default::default()
    };
    let mut trash = FixtureTrash::new(dir.path());
    assert!(
        cleanup::clean(
            &analysis,
            &ids(&analysis),
            &AtomicBool::new(false),
            &mut trash,
            &mut journal,
            |_, _| {}
        )
        .is_err()
    );
    assert!(trash.batches.is_empty());
    assert!(
        analysis.categories[0]
            .files
            .iter()
            .all(|file| file.path.exists())
    );
}

#[test]
fn partial_batch_failure_is_not_retried_and_remains_uncertain() {
    let (dir, analysis) = fixture(40);
    let mut journal = MemoryJournal::default();
    let mut trash = FixtureTrash::new(dir.path());
    trash.fail_after_first = true;
    let error = cleanup::clean(
        &analysis,
        &ids(&analysis),
        &AtomicBool::new(false),
        &mut trash,
        &mut journal,
        |_, _| {},
    )
    .unwrap_err();
    assert!(error.contains("unresolved outcomes"));
    assert_eq!(trash.batches, [32]);
    assert_eq!(
        analysis.categories[0]
            .files
            .iter()
            .filter(|file| file.path.exists())
            .count(),
        39
    );
    let history = store::project_events(&journal.events).unwrap();
    assert!(history.interrupted);
    assert_eq!(history.files, 0);
    assert_eq!(history.uncertain.len(), 32);
}

#[test]
fn failed_batch_receipt_prevents_the_next_batch_and_preserves_uncertainty() {
    let (dir, analysis) = fixture(40);
    let mut journal = MemoryJournal {
        fail_at: Some(33),
        ..Default::default()
    };
    let mut trash = FixtureTrash::new(dir.path());
    assert!(
        cleanup::clean(
            &analysis,
            &ids(&analysis),
            &AtomicBool::new(false),
            &mut trash,
            &mut journal,
            |_, _| {}
        )
        .is_err()
    );
    assert_eq!(trash.batches, [32]);
    assert_eq!(
        analysis.categories[0]
            .files
            .iter()
            .filter(|file| file.path.exists())
            .count(),
        8
    );
    let history = store::project_events(&journal.events).unwrap();
    assert!(history.interrupted);
    assert_eq!(history.uncertain.len(), 32);
}

#[test]
fn cancellation_between_batches_leaves_remaining_sources_untouched() {
    let (dir, analysis) = fixture(70);
    let mut journal = MemoryJournal::default();
    let mut trash = FixtureTrash::new(dir.path());
    let cancel = AtomicBool::new(false);
    let result = cleanup::clean(
        &analysis,
        &ids(&analysis),
        &cancel,
        &mut trash,
        &mut journal,
        |_, _| cancel.store(true, Ordering::Release),
    )
    .unwrap();
    assert!(result.cancelled);
    assert_eq!(trash.batches, [32]);
    assert_eq!(result.files, 32);
    assert_eq!(
        analysis.categories[0]
            .files
            .iter()
            .filter(|file| file.path.exists())
            .count(),
        38
    );
    let history = store::project_events(&journal.events).unwrap();
    assert!(history.cancelled);
    assert!(history.uncertain.is_empty());
}

#[cfg(windows)]
#[test]
#[ignore = "Explicit native timing: moves and restores only uniquely named owned tiny fixtures"]
fn native_tiny_file_batches_compare_single_operations_and_restore_every_fixture() {
    use std::time::Instant;
    struct SingleTrash;
    impl TrashPort for SingleTrash {
        fn move_to_trash(&mut self, path: &Path) -> Result<(), String> {
            cleanup::SystemTrash.move_to_trash(path)
        }
    }
    struct LegacyJournal(store::Journal);
    impl JournalSink for LegacyJournal {
        fn append(&mut self, event: &JournalEvent) -> Result<(), String> {
            self.0.append(event)
        }
    }
    fn run(batched: bool) -> serde_json::Value {
        let (dir, analysis) = fixture(64);
        let expected: Vec<_> = analysis.categories[0]
            .files
            .iter()
            .map(|file| (file.path.clone(), fs::read(&file.path).unwrap()))
            .collect();
        let data = dir.path().join("data");
        let journal = store::Journal::create(&data, Uuid::new_v4()).unwrap();
        let start = Instant::now();
        let result = if batched {
            cleanup::clean(
                &analysis,
                &ids(&analysis),
                &AtomicBool::new(false),
                &mut cleanup::SystemTrash,
                &mut { journal },
                |_, _| {},
            )
        } else {
            cleanup::clean(
                &analysis,
                &ids(&analysis),
                &AtomicBool::new(false),
                &mut SingleTrash,
                &mut LegacyJournal(journal),
                |_, _| {},
            )
        };
        let elapsed = start.elapsed().as_secs_f64() * 1000.;
        // Restore only exact paths in this unique private fixture, including on
        // a failed assertion path. Never empty/purge the user's Recycle Bin.
        let own: Vec<_> = trash::os_limited::list()
            .unwrap()
            .into_iter()
            .filter(|item| {
                expected
                    .iter()
                    .any(|(path, _)| scanner::same_path(path, &item.original_path()))
            })
            .collect();
        let restored = own.len();
        trash::os_limited::restore_all(own).unwrap();
        let result = result.unwrap();
        assert_eq!(restored, 64);
        assert_eq!(result.files, 64);
        assert_eq!(result.bytes, 64);
        for (path, bytes) in expected {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
        let history = store::history(&data).unwrap();
        assert_eq!(history[0].files, 64);
        assert!(history[0].uncertain.is_empty());
        serde_json::json!({"batched":batched,"files":64,"bytes":64,"cleanup_ms":elapsed,"restored":restored})
    }
    // Alternate order to expose rather than hide warm-cache effects.
    for batched in [false, true, true, false] {
        println!("TINY_TRASH_TIMING {}", run(batched));
    }
}
