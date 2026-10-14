use dcleaner::duplicates::{
    DuplicateOptions, DuplicatePhase, SkipReason, build_cleanup_analysis, scan,
    selected_cleanup_analysis,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};
use uuid::Uuid;

fn options() -> DuplicateOptions {
    DuplicateOptions {
        minimum_size: 1,
        max_bytes_read: 1024 * 1024,
        ..DuplicateOptions::default()
    }
}

fn write(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn same_size_different_content_is_not_a_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "first.bin", b"same size");
    write(dir.path(), "second.bin", b"diff size");

    let report = scan(
        &[dir.path().to_path_buf()],
        &options(),
        &AtomicBool::new(false),
        |_| {},
    );

    assert_eq!(report.candidate_files, 2);
    assert_eq!(report.fingerprinted_files, 2);
    assert!(report.groups.is_empty());
    assert_eq!(report.duplicate_files, 0);
}

#[test]
fn default_minimum_size_includes_the_64_kib_boundary() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "small.bin", &vec![7; 65_535]);
    write(dir.path(), "boundary-a.bin", &vec![9; 65_536]);
    write(dir.path(), "boundary-b.bin", &vec![9; 65_536]);

    let report = scan(
        &[dir.path().to_path_buf()],
        &DuplicateOptions::default(),
        &AtomicBool::new(false),
        |_| {},
    );

    assert_eq!(DuplicateOptions::default().minimum_size, 65_536);
    assert_eq!(report.candidate_files, 2);
    assert_eq!(report.filtered_count, 1);
    assert_eq!(report.groups.len(), 1);
    assert_eq!(report.groups[0].size, 65_536);
}

#[test]
fn exact_matches_form_groups_and_selection_builds_a_cleanup_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let oldest = write(dir.path(), "old.bin", b"identical payload");
    let middle = write(dir.path(), "middle.bin", b"identical payload");
    let newest = write(dir.path(), "new.bin", b"identical payload");
    let mut report = scan(
        &[dir.path().to_path_buf()],
        &options(),
        &AtomicBool::new(false),
        |_| {},
    );

    assert_eq!(report.groups.len(), 1);
    assert_eq!(report.groups[0].files.len(), 3);
    assert_eq!(report.duplicate_files, 3);
    assert_eq!(
        report.duplicate_bytes,
        3 * b"identical payload".len() as u64
    );
    assert_eq!(
        report.potential_reclaimable_bytes,
        2 * b"identical payload".len() as u64
    );
    assert_eq!(report.selected_ids().len(), 2);
    let oldest_from_scan = report.groups[0]
        .files
        .iter()
        .min_by(|left, right| {
            left.candidate
                .created_ns
                .unwrap_or_default()
                .cmp(&right.candidate.created_ns.unwrap_or_default())
                .then_with(|| left.candidate.path.cmp(&right.candidate.path))
        })
        .unwrap();
    assert!(!oldest_from_scan.selected);

    let default_analysis = selected_cleanup_analysis(&report).unwrap();
    assert_eq!(default_analysis.minimum_age_days, 0);
    assert_eq!(default_analysis.count(), 2);
    assert!(!default_analysis.cancelled);
    let all_ids = report.groups[0]
        .files
        .iter()
        .map(|file| file.candidate.id)
        .collect::<Vec<_>>();
    assert_eq!(
        build_cleanup_analysis(&report, &all_ids).unwrap().count(),
        3
    );

    // Deliberately invert creation and modification order; an unknown created time
    // sorts as zero and becomes the oldest keeper.
    for file in &mut report.groups[0].files {
        let name = file.candidate.path.file_name().unwrap().to_string_lossy();
        match name.as_ref() {
            "old.bin" => {
                file.candidate.created_ns = Some(10);
                file.candidate.modified_ns = 300;
            }
            "middle.bin" => {
                file.candidate.created_ns = None;
                file.candidate.modified_ns = 200;
            }
            "new.bin" => {
                file.candidate.created_ns = Some(30);
                file.candidate.modified_ns = 100;
            }
            _ => unreachable!(),
        }
    }
    report.keep_oldest();
    assert_eq!(report.selected_ids().len(), 2);
    assert!(
        report.groups[0]
            .files
            .iter()
            .find(|file| file.candidate.path == middle)
            .is_some_and(|file| !file.selected)
    );
    assert_eq!(
        build_cleanup_analysis(&report, &report.selected_ids())
            .unwrap()
            .count(),
        2
    );

    report.keep_newest();
    assert!(
        report.groups[0]
            .files
            .iter()
            .find(|file| file.candidate.path == newest)
            .is_some_and(|file| !file.selected)
    );
    assert!(
        report.groups[0]
            .files
            .iter()
            .find(|file| file.candidate.path == oldest)
            .is_some_and(|file| file.selected)
    );
    report.deselect_all();
    assert!(report.selected_ids().is_empty());
    assert!(selected_cleanup_analysis(&report).is_err());
    assert!(build_cleanup_analysis(&report, &[Uuid::new_v4()]).is_err());
    report.select_all();
    assert_eq!(report.selected_ids().len(), 3);

    // This module only builds a cleanup snapshot; it never moves or deletes fixture files.
    assert!(oldest.exists() && middle.exists() && newest.exists());
}

#[test]
fn nested_selected_roots_are_scanned_once() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("parent");
    let child = parent.join("child");
    fs::create_dir_all(&child).unwrap();
    write(&parent, "first.bin", b"overlap duplicate");
    write(&child, "second.bin", b"overlap duplicate");

    let report = scan(
        &[parent.clone(), child],
        &options(),
        &AtomicBool::new(false),
        |_| {},
    );

    assert_eq!(report.roots_requested, 2);
    assert_eq!(report.roots_available, 2);
    assert_eq!(report.candidate_files, 2);
    assert_eq!(report.groups.len(), 1);
    assert_eq!(report.groups[0].files.len(), 2);
    assert!(!report.partial);
}

#[test]
fn entry_and_byte_limits_and_cancellation_are_explicit() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "a.bin", b"same");
    write(dir.path(), "b.bin", b"same");
    write(dir.path(), "c.bin", b"same");

    let limited = scan(
        &[dir.path().to_path_buf()],
        &DuplicateOptions {
            max_entries: 1,
            ..options()
        },
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(limited.truncated);
    assert!(limited.partial);
    assert_eq!(limited.entries_seen, 1);

    let byte_limited = scan(
        &[dir.path().to_path_buf()],
        &DuplicateOptions {
            max_bytes_read: 2,
            ..options()
        },
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(byte_limited.truncated);
    assert!(byte_limited.partial);
    assert!(byte_limited.bytes_read <= 2);

    let cancelled = scan(
        &[dir.path().to_path_buf()],
        &options(),
        &AtomicBool::new(true),
        |_| {},
    );
    assert!(cancelled.cancelled);
    assert!(cancelled.partial);

    let cancel_during_hash = AtomicBool::new(false);
    let stopped = scan(
        &[dir.path().to_path_buf()],
        &options(),
        &cancel_during_hash,
        |progress| {
            if progress.phase == DuplicatePhase::Fingerprinting {
                cancel_during_hash.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        },
    );
    assert!(stopped.cancelled);
    assert!(stopped.partial);
}

#[test]
fn changed_file_is_reported_and_never_grouped() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "first.bin", b"same bytes");
    write(dir.path(), "second.bin", b"same bytes");
    let mut changed = false;

    let report = scan(
        &[dir.path().to_path_buf()],
        &options(),
        &AtomicBool::new(false),
        |progress| {
            if !changed && progress.phase == DuplicatePhase::Fingerprinting {
                fs::write(progress.path.unwrap(), b"longer changed content").unwrap();
                changed = true;
            }
        },
    );

    assert!(changed);
    assert!(report.partial);
    assert_eq!(report.skipped_count, 1);
    assert!(
        report
            .skipped_entries
            .iter()
            .any(|entry| entry.reason == SkipReason::ChangedDuringRead)
    );
    assert!(report.groups.is_empty());
}

#[test]
fn hidden_and_unselected_file_types_are_filtered() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".hidden.bin", b"hidden contents");
    write(dir.path(), "ignored.txt", b"ignored contents");
    write(dir.path(), "visible.bin", b"visible contents");
    let report = scan(
        &[dir.path().to_path_buf()],
        &DuplicateOptions {
            file_types: vec![".bin".into()],
            include_hidden: false,
            ..options()
        },
        &AtomicBool::new(false),
        |_| {},
    );

    assert_eq!(report.candidate_files, 1);
    assert_eq!(report.filtered_count, 2);
    assert!(report.groups.is_empty());
}

#[test]
fn read_only_files_are_excluded_when_the_filter_is_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "readonly.bin", b"read only data");
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions).unwrap();

    let report = scan(
        &[dir.path().to_path_buf()],
        &DuplicateOptions {
            include_read_only: false,
            ..options()
        },
        &AtomicBool::new(false),
        |_| {},
    );

    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(false);
    fs::set_permissions(&path, permissions).unwrap();
    assert_eq!(report.candidate_files, 0);
    assert_eq!(report.filtered_count, 1);
}
