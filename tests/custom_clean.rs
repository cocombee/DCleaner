use clean_settings::{
    CustomCleanSettings, ExclusionRule, ExclusionType, FileDeletionMode, FolderInclusion,
    InclusionLocation, InclusionRule, OverwriteType,
};
use custom_clean::{
    CapabilityKind, MAX_MATCH_STEPS, ScanOptions, SkipReason, clean, rule_id_for_inclusion, scan,
};
use dcleaner::{clean_settings, cleanup, custom_clean, domain, scanner, store};
use domain::{Category, CleanupPolicy};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, SystemTime},
};
use store::{JournalEvent, JournalSink};
use uuid::Uuid;

#[derive(Default)]
struct MockTrash {
    paths: Vec<PathBuf>,
}

impl cleanup::TrashPort for MockTrash {
    fn move_to_trash(&mut self, path: &Path) -> Result<(), String> {
        self.paths.push(path.to_path_buf());
        Ok(())
    }
}

#[derive(Default)]
struct MemoryJournal {
    events: Vec<JournalEvent>,
}

impl JournalSink for MemoryJournal {
    fn append(&mut self, event: &JournalEvent) -> Result<(), String> {
        self.events.push(event.clone());
        Ok(())
    }
}

fn settings_for_folder(
    root: &Path,
    filter: Option<Vec<&str>>,
    recursive: bool,
) -> CustomCleanSettings {
    let mut settings = CustomCleanSettings::default();
    settings.inclusions.push(InclusionRule {
        location: InclusionLocation::Folder(FolderInclusion {
            folder: root.to_string_lossy().into_owned(),
            filter: filter.map(|values| values.into_iter().map(str::to_owned).collect()),
            delete_self: false,
            recursive,
        }),
        age_threshold_hours: None,
    });
    settings.set_rule_selection(".custom", Some(true)).unwrap();
    settings
}

fn settings_for_files(paths: &[&Path], exclusion_pattern: &str) -> CustomCleanSettings {
    let mut settings = CustomCleanSettings::default();
    settings.inclusions = paths
        .iter()
        .map(|path| InclusionRule {
            location: InclusionLocation::File(path.to_string_lossy().into_owned()),
            age_threshold_hours: None,
        })
        .collect();
    settings.exclusions = vec![ExclusionRule {
        exclusion_type: ExclusionType::File,
        path: exclusion_pattern.to_owned(),
    }];
    settings.set_rule_selection(".custom", Some(true)).unwrap();
    settings
}

fn options(now: SystemTime) -> ScanOptions {
    ScanOptions {
        now,
        ..ScanOptions::default()
    }
}

fn set_modified(path: &Path, age: Duration) {
    filetime::set_file_mtime(
        path,
        filetime::FileTime::from_system_time(SystemTime::now() - age),
    )
    .unwrap();
}

#[test]
fn stable_inclusion_ids_do_not_depend_on_rule_order() {
    let first = InclusionRule {
        location: InclusionLocation::File(r"C:\Temp\a.txt".into()),
        age_threshold_hours: Some(2.5),
    };
    let second = InclusionRule {
        location: InclusionLocation::File(r"C:\Temp\b.txt".into()),
        age_threshold_hours: None,
    };
    assert_eq!(
        rule_id_for_inclusion(&first),
        rule_id_for_inclusion(&first.clone())
    );
    let original = [
        rule_id_for_inclusion(&first),
        rule_id_for_inclusion(&second),
    ];
    let reordered = [
        rule_id_for_inclusion(&second),
        rule_id_for_inclusion(&first),
    ];
    assert_eq!(original[0], reordered[1]);
    assert_eq!(original[1], reordered[0]);
}

#[test]
fn custom_inclusions_require_the_explicit_custom_selection_and_filters_apply() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("cache");
    let child = root.join("nested");
    fs::create_dir_all(&child).unwrap();
    fs::write(root.join("top.tmp"), b"top").unwrap();
    fs::write(child.join("nested.tmp"), b"nested").unwrap();
    fs::write(child.join("ignored.log"), b"ignored").unwrap();
    let now = SystemTime::now();
    let settings = settings_for_folder(&root, Some(vec!["*.tmp"]), true);
    let mut unselected = settings.clone();
    unselected
        .set_rule_selection(".custom", Some(false))
        .unwrap();
    let unselected_report =
        scan(&unselected, &options(now), &AtomicBool::new(false), |_| {}).unwrap();
    assert!(unselected_report.files().is_empty());
    assert!(!unselected_report.rules()[0].selected());

    let report = scan(&settings, &options(now), &AtomicBool::new(false), |_| {}).unwrap();
    assert_eq!(report.files().len(), 2);
    assert!(
        report
            .files()
            .iter()
            .all(|file| file.path().extension().is_some_and(|ext| ext == "tmp"))
    );
    assert!(root.join("top.tmp").exists());
    assert_eq!(report.rules()[0].matched(), 2);
}

#[test]
fn recursive_flag_and_overlapping_rules_deduplicate_by_path() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("root");
    let nested = root.join("nested");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("one.tmp"), b"one").unwrap();
    let now = SystemTime::now();

    let nonrecursive = settings_for_folder(&root, None, false);
    let report = scan(
        &nonrecursive,
        &options(now),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert!(report.files().is_empty());

    let mut overlap = settings_for_folder(&root, None, true);
    overlap.inclusions.push(InclusionRule {
        location: InclusionLocation::Folder(FolderInclusion {
            folder: nested.to_string_lossy().into_owned(),
            filter: None,
            delete_self: false,
            recursive: true,
        }),
        age_threshold_hours: None,
    });
    let report = scan(&overlap, &options(now), &AtomicBool::new(false), |_| {}).unwrap();
    assert_eq!(report.files().len(), 1);
    assert_eq!(report.files()[0].matched_rule_ids().len(), 2);
}

#[test]
fn fractional_age_is_per_custom_rule_and_never_inferred_from_temp_path() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("temp");
    fs::create_dir(&root).unwrap();
    let one_hour = root.join("one-hour.tmp");
    let twenty_five_hours = root.join("twenty-five-hours.tmp");
    fs::write(&one_hour, b"one").unwrap();
    fs::write(&twenty_five_hours, b"old").unwrap();
    set_modified(&one_hour, Duration::from_secs(60 * 60));
    set_modified(&twenty_five_hours, Duration::from_secs(25 * 60 * 60));
    let now = SystemTime::now();
    let mut settings = settings_for_folder(&root, None, true);
    settings.inclusions[0].age_threshold_hours = Some(1.5);
    let scan_options = options(now);
    let report = scan(&settings, &scan_options, &AtomicBool::new(false), |_| {}).unwrap();
    assert_eq!(report.files().len(), 2);
    let one = report
        .files()
        .iter()
        .find(|file| file.path() == one_hour)
        .unwrap();
    let old = report
        .files()
        .iter()
        .find(|file| file.path() == twenty_five_hours)
        .unwrap();
    assert!(!one.eligible());
    assert!(old.eligible());
    assert_eq!(one.eligibility()[0].age_threshold_hours(), Some(1.5));
    assert!(!one.eligibility()[0].temporary_24h_applied());
    assert!(!old.eligibility()[0].temporary_24h_applied());
    assert_eq!(report.to_analysis().minimum_age_days, 0);
    assert_eq!(
        report.to_analysis().cleanup_policy,
        CleanupPolicy::CustomCleanRules
    );

    settings.file_deletion.temp_folders_only_older_than_24h = false;
    let report = scan(&settings, &scan_options, &AtomicBool::new(false), |_| {}).unwrap();
    assert!(report.files().iter().all(|file| {
        !file.eligibility()[0].temporary_24h_applied()
            && file.eligible() == (file.path() == twenty_five_hours)
    }));
}

#[test]
fn only_the_builtin_temp_rule_applies_the_24_hour_cutoff_and_intersects_ages() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("temp");
    fs::create_dir(&root).unwrap();
    let two_days = root.join("two-days.tmp");
    let eight_days = root.join("eight-days.tmp");
    fs::write(&two_days, b"recent").unwrap();
    fs::write(&eight_days, b"old").unwrap();
    set_modified(&two_days, Duration::from_secs(2 * 86400));
    set_modified(&eight_days, Duration::from_secs(8 * 86400));

    let now = SystemTime::now();
    let mut scan_options = options(now);
    scan_options.categories = vec![Category {
        cache_root_scopes: Default::default(),
        id: "temp".into(),
        name: "Temporary files".into(),
        group: "System".into(),
        description: "fixture".into(),
        roots: vec![root.clone()],
    }];
    scan_options.selected_legacy_ids = vec!["temp".into()];
    scan_options.default_age_days = 3;
    let settings = CustomCleanSettings::default();
    let report = scan(&settings, &scan_options, &AtomicBool::new(false), |_| {}).unwrap();

    assert_eq!(report.files().len(), 1);
    assert_eq!(report.files()[0].path(), eight_days);
    let eligibility = &report.files()[0].eligibility()[0];
    assert!(eligibility.temporary_24h_applied());
    assert_eq!(eligibility.age_threshold_days(), Some(3));
    assert_eq!(
        eligibility.cutoff_ns(),
        scanner::timestamp(now) - 3 * scanner::DAY_NS
    );

    scan_options.categories[0].id = "user.cache".into();
    scan_options.selected_legacy_ids = vec!["user.cache".into()];
    let other_report = scan(&settings, &scan_options, &AtomicBool::new(false), |_| {}).unwrap();
    assert_eq!(other_report.files().len(), 1);
    assert!(!other_report.files()[0].eligibility()[0].temporary_24h_applied());
}

#[cfg(windows)]
#[test]
fn exclusions_normalize_windows_case_and_path_separators() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("Root");
    let skip = root.join("Skip");
    fs::create_dir_all(&skip).unwrap();
    fs::write(root.join("keep.tmp"), b"keep").unwrap();
    fs::write(root.join("ignore.drop"), b"drop").unwrap();
    fs::write(skip.join("nested.tmp"), b"skip").unwrap();
    let path_rule = skip
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let file_glob = format!("{}/*.drop", root.to_string_lossy().replace('\\', "/"));
    let mut settings = settings_for_folder(&root, None, true);
    settings.exclusions = vec![
        ExclusionRule {
            exclusion_type: ExclusionType::Path,
            path: path_rule,
        },
        ExclusionRule {
            exclusion_type: ExclusionType::File,
            path: file_glob,
        },
    ];
    let report = scan(
        &settings,
        &options(SystemTime::now()),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(report.files().len(), 1);
    assert_eq!(report.files()[0].path().file_name().unwrap(), "keep.tmp");
}

#[test]
fn built_in_categories_use_caller_selection_and_their_own_age_snapshot() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("catalogue");
    fs::create_dir(&root).unwrap();
    let old = root.join("old.cache");
    fs::write(&old, b"old cache").unwrap();
    set_modified(&old, Duration::from_secs(5 * 86400));
    let category = Category {
        cache_root_scopes: Default::default(),
        id: "temp.cache".into(),
        name: "Temporary cache".into(),
        group: "System".into(),
        description: "fixture".into(),
        roots: vec![root],
    };
    let now = SystemTime::now();
    let mut scan_options = options(now);
    scan_options.categories = vec![category];
    scan_options.selected_legacy_ids = vec!["temp.cache".into()];
    scan_options.default_age_days = 3;
    let mut settings = CustomCleanSettings::default();
    let report = scan(&settings, &scan_options, &AtomicBool::new(false), |_| {}).unwrap();
    assert_eq!(report.files().len(), 1);
    assert_eq!(
        report.files()[0].eligibility()[0].age_threshold_days(),
        Some(3)
    );

    settings
        .set_rule_selection("temp.cache", Some(false))
        .unwrap();
    let deselected = scan(&settings, &scan_options, &AtomicBool::new(false), |_| {}).unwrap();
    assert!(deselected.files().is_empty());
    assert!(!deselected.rules()[0].selected());
}

#[test]
fn cancel_and_entry_limit_are_reported_as_partial_without_claiming_complete() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("many");
    fs::create_dir(&root).unwrap();
    for index in 0..4 {
        fs::write(root.join(format!("{index}.tmp")), b"x").unwrap();
    }
    let settings = settings_for_folder(&root, None, true);
    let mut scan_options = options(SystemTime::now());
    scan_options.max_entries = 2;
    let limited = scan(&settings, &scan_options, &AtomicBool::new(false), |_| {}).unwrap();
    assert!(limited.truncated());
    assert!(limited.partial());
    assert!(limited.rules()[0].truncated());

    let cancelled = scan(
        &settings,
        &options(SystemTime::now()),
        &AtomicBool::new(true),
        |_| {},
    )
    .unwrap();
    assert!(cancelled.cancelled());
    assert!(cancelled.partial());
    assert!(cancelled.files().is_empty());
}

#[test]
fn matching_work_limit_must_stay_within_safe_bounds() {
    let settings = CustomCleanSettings::default();
    let mut scan_options = options(SystemTime::now());
    scan_options.max_match_steps = 0;
    assert!(scan(&settings, &scan_options, &AtomicBool::new(false), |_| {}).is_err());
    scan_options.max_match_steps = MAX_MATCH_STEPS + 1;
    assert!(scan(&settings, &scan_options, &AtomicBool::new(false), |_| {}).is_err());
}

#[test]
fn aggregate_matching_limit_fails_closed_and_cleanup_needs_partial_ack_for_verified_ids() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("matches");
    fs::create_dir(&root).unwrap();
    let verified = root.join("a.tmp");
    let limited = root.join(format!("{}.tmp", "z".repeat(80)));
    fs::write(&verified, b"verified").unwrap();
    fs::write(&limited, b"must not be offered").unwrap();
    let exclusion_glob = format!("*{}*.tmp", "z".repeat(80));

    // Measure the first explicit-file rule's exact matching cost, then leave
    // only enough work for the next path and pattern normalization. The second
    // glob itself must stop before it can decide that its file is excluded.
    let first_settings = settings_for_files(&[&verified], &exclusion_glob);
    let first_scan = scan(
        &first_settings,
        &options(SystemTime::now()),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(first_scan.files().len(), 1);
    let first_cost = first_scan.match_steps_used();
    assert!(first_cost > 0);

    let settings = settings_for_files(&[&verified, &limited], &exclusion_glob);
    let complete = scan(
        &settings,
        &options(SystemTime::now()),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(complete.files().len(), 1);
    assert_eq!(complete.files()[0].path(), verified);
    let limited_rule_id = rule_id_for_inclusion(&settings.inclusions[1]);
    assert!(
        complete
            .rules()
            .iter()
            .any(|rule| { rule.id() == limited_rule_id.as_str() && rule.excluded() == 1 })
    );

    let canonical_limited = dunce::canonicalize(&limited).unwrap();
    let path_normalize_steps = canonical_limited.to_str().unwrap().len() + 1;
    let pattern_normalize_steps = exclusion_glob.len() + 1;
    let match_limit = first_cost + path_normalize_steps + pattern_normalize_steps + 1;
    let mut scan_options = options(SystemTime::now());
    scan_options.max_match_steps = match_limit;
    let report = scan(&settings, &scan_options, &AtomicBool::new(false), |_| {}).unwrap();

    assert_eq!(report.match_step_limit(), match_limit);
    assert_eq!(report.match_steps_used(), report.match_step_limit());
    assert!(report.match_steps_used() <= report.match_step_limit());
    assert!(report.truncated());
    assert!(report.partial());
    assert_eq!(report.files().len(), 1);
    assert_eq!(report.files()[0].path(), verified);
    assert!(report.skipped_entries().iter().any(|entry| {
        entry.reason() == SkipReason::MatchingWorkLimit
            && entry
                .path()
                .is_some_and(|path| path == canonical_limited.as_path())
    }));
    assert!(report.rules().iter().any(|rule| {
        rule.id() == limited_rule_id.as_str() && rule.truncated() && rule.skipped() == 1
    }));

    let verified_id = report.files()[0].id();
    assert!(
        report
            .review_selection(&settings, &[verified_id], false)
            .is_err()
    );
    let mut trash = MockTrash::default();
    let mut journal = MemoryJournal::default();
    assert!(
        clean(
            &report,
            &settings,
            &[verified_id],
            false,
            &AtomicBool::new(false),
            &mut trash,
            &mut journal,
            |_, _| {},
        )
        .is_err()
    );
    assert!(trash.paths.is_empty());
    assert!(journal.events.is_empty());

    let result = clean(
        &report,
        &settings,
        &[verified_id],
        true,
        &AtomicBool::new(false),
        &mut trash,
        &mut journal,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(result.files, 1);
    assert_eq!(trash.paths, vec![verified]);
    assert!(limited.exists());
}

#[test]
fn cancellation_after_a_matched_file_never_reaches_mock_trash() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("cancel-matching");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("first.tmp"), b"first").unwrap();
    fs::write(root.join("second.tmp"), b"second").unwrap();
    let mut settings = settings_for_folder(&root, Some(vec!["*.tmp"]), true);
    settings.exclusions = vec![ExclusionRule {
        exclusion_type: ExclusionType::Path,
        path: "*pattern-that-does-not-exist*".into(),
    }];
    let cancel = AtomicBool::new(false);
    let mut first_progress = true;
    let report = scan(&settings, &options(SystemTime::now()), &cancel, |_| {
        if first_progress {
            first_progress = false;
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    })
    .unwrap();

    assert!(report.cancelled());
    assert!(report.partial());
    assert_eq!(report.files().len(), 1);
    assert!(report.match_steps_used() > 0);
    let mut trash = MockTrash::default();
    let mut journal = MemoryJournal::default();
    assert!(
        clean(
            &report,
            &settings,
            &[report.files()[0].id()],
            true,
            &cancel,
            &mut trash,
            &mut journal,
            |_, _| {},
        )
        .is_err()
    );
    assert!(trash.paths.is_empty());
    assert!(journal.events.is_empty());
}

#[test]
fn stale_unknown_excluded_or_changed_ids_never_reach_journal_or_trash() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("cache");
    fs::create_dir(&root).unwrap();
    let file = root.join("selected.tmp");
    fs::write(&file, b"before").unwrap();
    let mut settings = settings_for_folder(&root, None, true);
    let report = scan(
        &settings,
        &options(SystemTime::now()),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    let id = report.files()[0].id();
    assert!(
        report
            .review_selection(&settings, &[Uuid::new_v4()], false)
            .is_err()
    );

    settings.set_rule_selection(".custom", Some(false)).unwrap();
    let mut trash = MockTrash::default();
    let mut journal = MemoryJournal::default();
    assert!(
        clean(
            &report,
            &settings,
            &[id],
            false,
            &AtomicBool::new(false),
            &mut trash,
            &mut journal,
            |_, _| {},
        )
        .is_err()
    );
    assert!(journal.events.is_empty());
    assert!(trash.paths.is_empty());

    settings.set_rule_selection(".custom", Some(true)).unwrap();
    fs::write(&file, b"changed length").unwrap();
    assert!(
        clean(
            &report,
            &settings,
            &[id],
            false,
            &AtomicBool::new(false),
            &mut trash,
            &mut journal,
            |_, _| {},
        )
        .is_err()
    );
    assert!(journal.events.is_empty());
    assert!(trash.paths.is_empty());
}

#[test]
fn confirmed_custom_cleanup_revalidates_per_rule_age_before_mock_trash() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("cache");
    fs::create_dir(&root).unwrap();
    let old = root.join("old.tmp");
    let young = root.join("young.tmp");
    fs::write(&old, b"old").unwrap();
    fs::write(&young, b"young").unwrap();
    set_modified(&old, Duration::from_secs(3 * 60 * 60));
    set_modified(&young, Duration::from_secs(30 * 60));
    let mut settings = settings_for_folder(&root, None, true);
    settings.inclusions[0].age_threshold_hours = Some(1.5);
    let report = scan(
        &settings,
        &options(SystemTime::now()),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    let old_id = report
        .files()
        .iter()
        .find(|candidate| candidate.path() == old)
        .unwrap()
        .id();
    let young_id = report
        .files()
        .iter()
        .find(|candidate| candidate.path() == young)
        .unwrap()
        .id();
    assert!(
        report
            .review_selection(&settings, &[young_id], false)
            .is_err()
    );

    let mut trash = MockTrash::default();
    let mut journal = MemoryJournal::default();
    let result = clean(
        &report,
        &settings,
        &[old_id],
        false,
        &AtomicBool::new(false),
        &mut trash,
        &mut journal,
        |_, _| {},
    )
    .unwrap();
    assert_eq!(result.files, 1);
    assert_eq!(trash.paths, vec![old]);
    assert_eq!(young.exists(), true);
    assert!(matches!(
        journal.events.first(),
        Some(JournalEvent::Start { .. })
    ));
    assert!(matches!(
        journal.events.last(),
        Some(JournalEvent::Finish { .. })
    ));
}

#[test]
fn unsupported_destructive_preferences_block_before_any_journal_intent() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("cache");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("one.tmp"), b"one").unwrap();
    let mut settings = settings_for_folder(&root, None, true);
    settings.advanced_filter_options.file_deletion = FileDeletionMode::Secure;
    settings.advanced_filter_options.overwrite_type = OverwriteType::ThreePass;
    settings.advanced_filter_options.wipe_free_space = true;
    settings.shutdown_after_cleaning = true;
    let report = scan(
        &settings,
        &options(SystemTime::now()),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert!(
        report
            .capabilities()
            .iter()
            .any(|note| note.kind() == CapabilityKind::SecureFileDeletion && note.blocking())
    );
    assert!(
        report
            .capabilities()
            .iter()
            .any(|note| note.kind() == CapabilityKind::WipeFreeSpace && note.blocking())
    );
    let id = report.files()[0].id();
    let mut trash = MockTrash::default();
    let mut journal = MemoryJournal::default();
    assert!(
        clean(
            &report,
            &settings,
            &[id],
            false,
            &AtomicBool::new(false),
            &mut trash,
            &mut journal,
            |_, _| {},
        )
        .is_err()
    );
    assert!(journal.events.is_empty());
    assert!(trash.paths.is_empty());
}
