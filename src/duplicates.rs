use crate::{
    domain::{Analysis, Candidate, CategoryResult},
    scanner::{MAX_ENTRIES, contained, is_link, safe_root, same_path, timestamp},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    fs::{self, File, Metadata},
    hash::Hasher,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use uuid::Uuid;

const READ_BUFFER_SIZE: usize = 64 * 1024;
const MAX_SKIP_DETAILS: usize = 256;
const DEFAULT_MAX_BYTES_READ: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DuplicateOptions {
    /// Files smaller than this are ignored. The default follows CCleaner's 64 KiB default.
    pub minimum_size: u64,
    /// Empty means every file type; otherwise entries are extensions such as "jpg" or "tar.gz".
    pub file_types: Vec<String>,
    pub include_hidden: bool,
    pub include_system: bool,
    pub include_read_only: bool,
    pub include_compressed: bool,
    /// Maximum number of directory entries examined across all selected roots.
    pub max_entries: usize,
    /// Maximum total bytes read, including fingerprint and exact-comparison passes.
    pub max_bytes_read: u64,
}

impl Default for DuplicateOptions {
    fn default() -> Self {
        Self {
            minimum_size: 65_536,
            file_types: Vec::new(),
            include_hidden: true,
            include_system: true,
            include_read_only: true,
            include_compressed: true,
            max_entries: MAX_ENTRIES,
            max_bytes_read: DEFAULT_MAX_BYTES_READ,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DuplicatePhase {
    Traversal,
    Fingerprinting,
    Verification,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DuplicateProgress {
    pub phase: DuplicatePhase,
    pub entries_seen: usize,
    pub files_processed: usize,
    pub candidate_files: usize,
    pub path: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SkipReason {
    UnavailableRoot,
    DirectoryUnreadable,
    EntryUnreadable,
    MetadataUnavailable,
    LinkedEntry,
    OutsideRoot,
    ChangedDuringRead,
    UnreadableFile,
    NonRegularFile,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkippedEntry {
    pub path: Option<PathBuf>,
    pub reason: SkipReason,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DuplicateFile {
    pub candidate: Candidate,
    /// Selected files are included in the cleanup analysis built from selected IDs.
    pub selected: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub id: Uuid,
    pub size: u64,
    pub files: Vec<DuplicateFile>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DuplicateReport {
    pub id: Uuid,
    pub groups: Vec<DuplicateGroup>,
    pub roots_requested: usize,
    pub roots_available: usize,
    pub entries_seen: usize,
    pub candidate_files: usize,
    pub fingerprinted_files: usize,
    pub duplicate_files: usize,
    /// Logical sum of the sizes of all files in duplicate groups.
    pub duplicate_bytes: u64,
    /// Logical size of all but one copy per group; this does not predict physical space reclaimed.
    pub potential_reclaimable_bytes: u64,
    pub filtered_count: usize,
    pub skipped_count: usize,
    pub skipped_entries: Vec<SkippedEntry>,
    pub omitted_skip_details: usize,
    pub bytes_read: u64,
    pub truncated: bool,
    pub cancelled: bool,
    /// True when traversal, reading, or a selected root produced incomplete results.
    pub partial: bool,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

impl DuplicateReport {
    pub fn selected_ids(&self) -> Vec<Uuid> {
        self.groups
            .iter()
            .flat_map(|group| &group.files)
            .filter(|file| file.selected)
            .map(|file| file.candidate.id)
            .collect()
    }

    pub fn select_all(&mut self) {
        for group in &mut self.groups {
            for file in &mut group.files {
                file.selected = true;
            }
        }
    }

    /// Select every duplicate except the oldest file in each group.
    pub fn keep_oldest(&mut self) {
        for group in &mut self.groups {
            let keeper = group
                .files
                .iter()
                .enumerate()
                .min_by(|(_, left), (_, right)| {
                    left.candidate
                        .created_ns
                        .unwrap_or_default()
                        .cmp(&right.candidate.created_ns.unwrap_or_default())
                        .then_with(|| left.candidate.path.cmp(&right.candidate.path))
                })
                .map(|(index, _)| index);
            set_group_selection(group, keeper);
        }
    }

    /// Select every duplicate except the newest file in each group.
    pub fn keep_newest(&mut self) {
        for group in &mut self.groups {
            let keeper = group
                .files
                .iter()
                .enumerate()
                .max_by(|(_, left), (_, right)| {
                    left.candidate
                        .created_ns
                        .unwrap_or_default()
                        .cmp(&right.candidate.created_ns.unwrap_or_default())
                        .then_with(|| right.candidate.path.cmp(&left.candidate.path))
                })
                .map(|(index, _)| index);
            set_group_selection(group, keeper);
        }
    }

    pub fn deselect_all(&mut self) {
        for group in &mut self.groups {
            for file in &mut group.files {
                file.selected = false;
            }
        }
    }
}

fn set_group_selection(group: &mut DuplicateGroup, keeper: Option<usize>) {
    for (index, file) in group.files.iter_mut().enumerate() {
        file.selected = Some(index) != keeper;
    }
}

/// Walk selected roots, fingerprint eligible files in bounded streaming passes, and verify
/// each possible match byte-for-byte before returning it as a duplicate group.
pub fn scan(
    roots: &[PathBuf],
    options: &DuplicateOptions,
    cancel: &AtomicBool,
    mut progress: impl FnMut(DuplicateProgress),
) -> DuplicateReport {
    let started = Instant::now();
    let mut report = DuplicateReport {
        id: Uuid::new_v4(),
        groups: Vec::new(),
        roots_requested: roots.len(),
        roots_available: 0,
        entries_seen: 0,
        candidate_files: 0,
        fingerprinted_files: 0,
        duplicate_files: 0,
        duplicate_bytes: 0,
        potential_reclaimable_bytes: 0,
        filtered_count: 0,
        skipped_count: 0,
        skipped_entries: Vec::new(),
        omitted_skip_details: 0,
        bytes_read: 0,
        truncated: false,
        cancelled: false,
        partial: false,
        elapsed_ms: 0,
        error: None,
    };

    if roots.is_empty() {
        report.error = Some("Choose at least one folder to scan.".into());
        report.partial = true;
        report.elapsed_ms = started.elapsed().as_millis() as u64;
        return report;
    }

    let normalized_types = normalized_file_types(&options.file_types);
    let (scan_roots, available_roots) = normalize_roots(roots, &mut report);
    report.roots_available = available_roots;
    let mut candidates = Vec::<FileSnapshot>::new();
    let mut seen_paths = HashSet::new();
    let mut stop = cancel.load(Ordering::Relaxed);
    if stop {
        report.cancelled = true;
    }

    for root in scan_roots {
        if stop {
            break;
        }
        let mut directories = vec![root.clone()];
        while let Some(directory) = directories.pop() {
            if cancel.load(Ordering::Relaxed) {
                report.cancelled = true;
                stop = true;
                break;
            }
            let Ok(directory_root) = safe_root(&directory) else {
                record_skip(&mut report, Some(directory), SkipReason::LinkedEntry);
                continue;
            };
            if !same_path(&directory_root, &directory) || !path_at_or_below(&root, &directory_root)
            {
                record_skip(&mut report, Some(directory), SkipReason::OutsideRoot);
                continue;
            }
            let entries = match fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(_) => {
                    record_skip(
                        &mut report,
                        Some(directory),
                        SkipReason::DirectoryUnreadable,
                    );
                    continue;
                }
            };

            for entry in entries {
                if cancel.load(Ordering::Relaxed) {
                    report.cancelled = true;
                    stop = true;
                    break;
                }
                if report.entries_seen >= options.max_entries {
                    report.truncated = true;
                    stop = true;
                    break;
                }
                report.entries_seen += 1;
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => {
                        record_skip(
                            &mut report,
                            Some(directory.clone()),
                            SkipReason::EntryUnreadable,
                        );
                        continue;
                    }
                };
                let path = entry.path();
                if !contained(&root, &path) {
                    record_skip(&mut report, Some(path), SkipReason::OutsideRoot);
                    continue;
                }
                let metadata = match fs::symlink_metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(_) => {
                        record_skip(&mut report, Some(path), SkipReason::MetadataUnavailable);
                        continue;
                    }
                };
                if is_link(&metadata) {
                    record_skip(&mut report, Some(path), SkipReason::LinkedEntry);
                    continue;
                }
                let canonical = match dunce::canonicalize(&path) {
                    Ok(canonical) => canonical,
                    Err(_) => {
                        record_skip(&mut report, Some(path), SkipReason::MetadataUnavailable);
                        continue;
                    }
                };
                if !same_path(&canonical, &path) || !contained(&root, &canonical) {
                    record_skip(&mut report, Some(path), SkipReason::OutsideRoot);
                    continue;
                }

                if metadata.is_dir() {
                    let attributes = attributes(&metadata, &path);
                    if excluded_directory(attributes, options) {
                        report.filtered_count += 1;
                    } else {
                        directories.push(path);
                    }
                    continue;
                }
                if !metadata.is_file() {
                    report.filtered_count += 1;
                    continue;
                }
                let attributes = attributes(&metadata, &path);
                if excluded_file(attributes, options)
                    || metadata.len() < options.minimum_size
                    || !matches_file_type(&path, &normalized_types)
                {
                    report.filtered_count += 1;
                    continue;
                }
                if !seen_paths.insert(path_key(&canonical)) {
                    continue;
                }
                let Some(modified) = metadata.modified().ok() else {
                    record_skip(&mut report, Some(path), SkipReason::MetadataUnavailable);
                    continue;
                };
                let candidate = Candidate {
                    id: Uuid::new_v4(),
                    path: canonical,
                    root: root.clone(),
                    size: metadata.len(),
                    modified_ns: timestamp(modified),
                    created_ns: metadata.created().ok().map(timestamp),
                };
                candidates.push(FileSnapshot {
                    candidate,
                    attributes,
                });
                report.candidate_files += 1;
                if report.entries_seen % 64 == 0 {
                    progress(DuplicateProgress {
                        phase: DuplicatePhase::Traversal,
                        entries_seen: report.entries_seen,
                        files_processed: 0,
                        candidate_files: report.candidate_files,
                        path: Some(path),
                    });
                }
            }
            if stop {
                break;
            }
        }
        if stop {
            break;
        }
    }

    let mut fingerprints = HashMap::<(u64, u64), Vec<usize>>::new();
    for (index, file) in candidates.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            break;
        }
        progress(DuplicateProgress {
            phase: DuplicatePhase::Fingerprinting,
            entries_seen: report.entries_seen,
            files_processed: report.fingerprinted_files,
            candidate_files: report.candidate_files,
            path: Some(file.candidate.path.clone()),
        });
        match fingerprint(file, options, cancel, &mut report) {
            Ok(hash) => {
                report.fingerprinted_files += 1;
                fingerprints
                    .entry((file.candidate.size, hash))
                    .or_default()
                    .push(index);
            }
            Err(ReadIssue::Skipped(reason)) => {
                record_skip(&mut report, Some(file.candidate.path.clone()), reason);
            }
            Err(ReadIssue::Cancelled) => {
                report.cancelled = true;
                break;
            }
            Err(ReadIssue::Limit) => {
                report.truncated = true;
                break;
            }
        }
    }

    if !report.cancelled {
        let mut buckets: Vec<_> = fingerprints.into_iter().collect();
        buckets.sort_by_key(|((size, hash), _)| (*size, *hash));
        let mut completed_groups = Vec::<(u64, Vec<usize>)>::new();
        let mut invalid_files = HashSet::new();
        'buckets: for ((size, _), mut members) in buckets {
            if members.len() < 2 {
                continue;
            }
            members.sort_by(|left, right| {
                candidates[*left]
                    .candidate
                    .path
                    .cmp(&candidates[*right].candidate.path)
            });
            let mut classes = Vec::<Vec<usize>>::new();
            for member in members {
                for class in &mut classes {
                    class.retain(|index| !invalid_files.contains(index));
                }
                classes.retain(|class| !class.is_empty());
                if cancel.load(Ordering::Relaxed) {
                    report.cancelled = true;
                    break 'buckets;
                }
                let mut matched_class = None;
                let mut unusable = false;
                for (class_index, class) in classes.iter().enumerate() {
                    let mut found_equal = false;
                    for representative in class {
                        progress(DuplicateProgress {
                            phase: DuplicatePhase::Verification,
                            entries_seen: report.entries_seen,
                            files_processed: completed_groups
                                .iter()
                                .map(|(_, group)| group.len())
                                .sum::<usize>(),
                            candidate_files: report.candidate_files,
                            path: Some(candidates[member].candidate.path.clone()),
                        });
                        match compare_files(
                            &candidates[*representative],
                            &candidates[member],
                            options,
                            cancel,
                            &mut report,
                        ) {
                            Ok(true) => {
                                found_equal = true;
                                break;
                            }
                            Ok(false) => {}
                            Err(CompareIssue::File(reason, is_member)) => {
                                let invalid_index =
                                    if is_member { member } else { *representative };
                                invalid_files.insert(invalid_index);
                                let path = if is_member {
                                    &candidates[member].candidate.path
                                } else {
                                    &candidates[*representative].candidate.path
                                };
                                record_skip(&mut report, Some(path.clone()), reason);
                                if is_member {
                                    unusable = true;
                                    break;
                                }
                            }
                            Err(CompareIssue::Cancelled) => {
                                report.cancelled = true;
                                break 'buckets;
                            }
                            Err(CompareIssue::Limit) => {
                                report.truncated = true;
                                break 'buckets;
                            }
                        }
                    }
                    if found_equal {
                        matched_class = Some(class_index);
                        break;
                    }
                    if unusable {
                        break;
                    }
                }
                if unusable {
                    continue;
                }
                if let Some(class_index) = matched_class {
                    classes[class_index].push(member);
                } else {
                    classes.push(vec![member]);
                }
            }
            for class in classes.into_iter().filter(|class| class.len() > 1) {
                let class = class
                    .into_iter()
                    .filter(|index| !invalid_files.contains(index))
                    .collect::<Vec<_>>();
                let count = class.len();
                if count < 2 {
                    continue;
                }
                report.duplicate_files += count;
                report.duplicate_bytes = report
                    .duplicate_bytes
                    .saturating_add(size.saturating_mul(count as u64));
                report.potential_reclaimable_bytes = report
                    .potential_reclaimable_bytes
                    .saturating_add(size.saturating_mul((count - 1) as u64));
                completed_groups.push((size, class));
            }
        }
        for (size, group) in completed_groups {
            let mut files = group
                .into_iter()
                .filter_map(|index| candidates.get(index))
                .map(|file| DuplicateFile {
                    candidate: file.candidate.clone(),
                    selected: true,
                })
                .collect::<Vec<_>>();
            if files.len() > 1 {
                files.sort_by(|left, right| {
                    left.candidate
                        .modified_ns
                        .cmp(&right.candidate.modified_ns)
                        .then_with(|| left.candidate.path.cmp(&right.candidate.path))
                });
                report.groups.push(DuplicateGroup {
                    id: Uuid::new_v4(),
                    size,
                    files,
                });
            }
        }
    }

    report.groups.sort_by(|left, right| {
        left.files[0]
            .candidate
            .path
            .cmp(&right.files[0].candidate.path)
            .then_with(|| left.size.cmp(&right.size))
    });
    report.keep_oldest();
    report.partial = report.cancelled || report.truncated || report.skipped_count > 0;
    report.elapsed_ms = started.elapsed().as_millis() as u64;
    report
}

/// Convenience wrapper that builds the cleanup snapshot from the report's current selections.
pub fn selected_cleanup_analysis(report: &DuplicateReport) -> Result<Analysis, String> {
    build_cleanup_analysis(report, &report.selected_ids())
}

/// Build a cleanup snapshot only from IDs present in this duplicate report.
/// The default report selection keeps the oldest file in every duplicate group.
/// Callers may explicitly pass every group ID for an allow-all reviewed cleanup.
pub fn build_cleanup_analysis(
    report: &DuplicateReport,
    selected_ids: &[Uuid],
) -> Result<Analysis, String> {
    if selected_ids.is_empty() {
        return Err("Select duplicate files from the current analysis.".into());
    }
    let by_id: HashMap<Uuid, &Candidate> = report
        .groups
        .iter()
        .flat_map(|group| &group.files)
        .map(|file| (file.candidate.id, &file.candidate))
        .collect();
    let mut unique_ids = HashSet::new();
    let mut files = Vec::new();
    for id in selected_ids {
        let Some(file) = by_id.get(id) else {
            return Err("Unknown file ID. Analyze again.".into());
        };
        if unique_ids.insert(*id) {
            files.push((*file).clone());
        }
    }
    Ok(Analysis {
        id: Uuid::new_v4(),
        date: chrono::Local::now().to_rfc3339(),
        minimum_age_days: 0,
        elapsed_ms: report.elapsed_ms,
        cancelled: report.cancelled,
        categories: vec![CategoryResult {
            id: "duplicates".into(),
            name: "Duplicate files".into(),
            group: "Storage".into(),
            files,
            skipped: report.skipped_count,
            available: report.roots_available > 0,
            truncated: report.truncated,
        }],
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct FileAttributes {
    hidden: bool,
    system: bool,
    read_only: bool,
    compressed: bool,
}

#[derive(Clone, Debug)]
struct FileSnapshot {
    candidate: Candidate,
    attributes: FileAttributes,
}

#[derive(Debug)]
enum ReadIssue {
    Skipped(SkipReason),
    Cancelled,
    Limit,
}

fn normalize_roots(roots: &[PathBuf], report: &mut DuplicateReport) -> (Vec<PathBuf>, usize) {
    let mut unique: Vec<PathBuf> = Vec::new();
    for root in roots {
        match safe_root(root) {
            Ok(root) if !unique.iter().any(|seen| same_path(seen, &root)) => unique.push(root),
            Ok(_) => {}
            Err(_) => record_skip(report, Some(root.clone()), SkipReason::UnavailableRoot),
        }
    }
    let available = unique.len();
    unique.sort_by_key(|path| path.components().count());
    let mut disjoint: Vec<PathBuf> = Vec::new();
    for root in unique {
        if disjoint
            .iter()
            .any(|parent| !same_path(parent, &root) && path_at_or_below(parent, &root))
        {
            continue;
        }
        disjoint.push(root);
    }
    (disjoint, available)
}

fn path_at_or_below(root: &Path, path: &Path) -> bool {
    if same_path(root, path) || contained(root, path) {
        return true;
    }
    if !cfg!(windows) {
        return false;
    }
    let root = root.to_string_lossy();
    let path = path.to_string_lossy();
    let root = root.trim_end_matches(['\\', '/']);
    path.get(..root.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(root))
        && path
            .as_bytes()
            .get(root.len())
            .is_some_and(|separator| *separator == b'\\' || *separator == b'/')
}

fn path_key(path: &Path) -> String {
    let value = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        value.to_ascii_lowercase()
    } else {
        value
    }
}

fn attributes(metadata: &Metadata, path: &Path) -> FileAttributes {
    let mut attributes = FileAttributes {
        hidden: path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with('.')),
        read_only: metadata.permissions().readonly(),
        ..FileAttributes::default()
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let flags = metadata.file_attributes();
        attributes.hidden |= flags & 0x2 != 0;
        attributes.system = flags & 0x4 != 0;
        attributes.read_only |= flags & 0x1 != 0;
        attributes.compressed = flags & 0x800 != 0;
    }
    attributes
}

fn excluded_directory(attributes: FileAttributes, options: &DuplicateOptions) -> bool {
    (!options.include_hidden && attributes.hidden) || (!options.include_system && attributes.system)
}

fn excluded_file(attributes: FileAttributes, options: &DuplicateOptions) -> bool {
    (!options.include_hidden && attributes.hidden)
        || (!options.include_system && attributes.system)
        || (!options.include_read_only && attributes.read_only)
        || (!options.include_compressed && attributes.compressed)
}

fn normalized_file_types(file_types: &[String]) -> Vec<String> {
    file_types
        .iter()
        .map(|kind| kind.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|kind| !kind.is_empty())
        .collect()
}

fn matches_file_type(path: &Path, file_types: &[String]) -> bool {
    if file_types.is_empty() {
        return true;
    }
    let Some(name) = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
    else {
        return false;
    };
    file_types.iter().any(|kind| {
        path.extension()
            .is_some_and(|extension| extension.to_string_lossy().eq_ignore_ascii_case(kind))
            || name.ends_with(&format!(".{kind}"))
    })
}

fn record_skip(report: &mut DuplicateReport, path: Option<PathBuf>, reason: SkipReason) {
    report.skipped_count += 1;
    if report.skipped_entries.len() < MAX_SKIP_DETAILS {
        report.skipped_entries.push(SkippedEntry { path, reason });
    } else {
        report.omitted_skip_details += 1;
    }
}

fn validate_snapshot(file: &FileSnapshot) -> Result<(), SkipReason> {
    let root = safe_root(&file.candidate.root).map_err(|_| SkipReason::ChangedDuringRead)?;
    if !same_path(&root, &file.candidate.root) || !contained(&root, &file.candidate.path) {
        return Err(SkipReason::OutsideRoot);
    }
    let metadata =
        fs::symlink_metadata(&file.candidate.path).map_err(|_| SkipReason::ChangedDuringRead)?;
    if is_link(&metadata) {
        return Err(SkipReason::LinkedEntry);
    }
    if !metadata.is_file() {
        return Err(SkipReason::NonRegularFile);
    }
    let canonical =
        dunce::canonicalize(&file.candidate.path).map_err(|_| SkipReason::ChangedDuringRead)?;
    if !same_path(&canonical, &file.candidate.path) || !contained(&root, &canonical) {
        return Err(SkipReason::OutsideRoot);
    }
    let modified = metadata
        .modified()
        .map(timestamp)
        .map_err(|_| SkipReason::MetadataUnavailable)?;
    if metadata.len() != file.candidate.size
        || modified != file.candidate.modified_ns
        || metadata.created().ok().map(timestamp) != file.candidate.created_ns
        || !same_attributes(attributes(&metadata, &file.candidate.path), file.attributes)
    {
        return Err(SkipReason::ChangedDuringRead);
    }
    Ok(())
}

fn same_attributes(left: FileAttributes, right: FileAttributes) -> bool {
    left.hidden == right.hidden
        && left.system == right.system
        && left.read_only == right.read_only
        && left.compressed == right.compressed
}

fn validate_handle(file: &File, snapshot: &FileSnapshot) -> Result<(), SkipReason> {
    let metadata = file.metadata().map_err(|_| SkipReason::UnreadableFile)?;
    if !metadata.is_file() {
        return Err(SkipReason::NonRegularFile);
    }
    let modified = metadata
        .modified()
        .map(timestamp)
        .map_err(|_| SkipReason::MetadataUnavailable)?;
    if metadata.len() != snapshot.candidate.size
        || modified != snapshot.candidate.modified_ns
        || metadata.created().ok().map(timestamp) != snapshot.candidate.created_ns
        || !same_attributes(
            attributes(&metadata, &snapshot.candidate.path),
            snapshot.attributes,
        )
    {
        return Err(SkipReason::ChangedDuringRead);
    }
    Ok(())
}

fn fingerprint(
    snapshot: &FileSnapshot,
    options: &DuplicateOptions,
    cancel: &AtomicBool,
    report: &mut DuplicateReport,
) -> Result<u64, ReadIssue> {
    validate_snapshot(snapshot).map_err(ReadIssue::Skipped)?;
    let mut file = File::open(&snapshot.candidate.path)
        .map_err(|_| ReadIssue::Skipped(SkipReason::UnreadableFile))?;
    validate_handle(&file, snapshot).map_err(ReadIssue::Skipped)?;
    let read_result: Result<u64, ReadIssue> = (|| {
        let mut hasher = DefaultHasher::new();
        let mut buffer = [0u8; READ_BUFFER_SIZE];
        let mut remaining = snapshot.candidate.size;
        while remaining > 0 {
            if cancel.load(Ordering::Relaxed) {
                return Err(ReadIssue::Cancelled);
            }
            let budget = options.max_bytes_read.saturating_sub(report.bytes_read);
            if budget == 0 {
                return Err(ReadIssue::Limit);
            }
            let length = usize::try_from(remaining.min(READ_BUFFER_SIZE as u64).min(budget))
                .unwrap_or(READ_BUFFER_SIZE);
            let read = file
                .read(&mut buffer[..length])
                .map_err(|_| ReadIssue::Skipped(SkipReason::UnreadableFile))?;
            if read == 0 {
                return Err(ReadIssue::Skipped(SkipReason::ChangedDuringRead));
            }
            report.bytes_read = report.bytes_read.saturating_add(read as u64);
            remaining -= read as u64;
            hasher.write(&buffer[..read]);
        }
        Ok(hasher.finish())
    })();
    let post_read = validate_handle(&file, snapshot).and_then(|_| validate_snapshot(snapshot));
    match read_result {
        Ok(hash) => {
            post_read.map_err(ReadIssue::Skipped)?;
            Ok(hash)
        }
        Err(ReadIssue::Skipped(reason)) => {
            Err(ReadIssue::Skipped(post_read.err().unwrap_or(reason)))
        }
        Err(issue) => Err(issue),
    }
}

fn compare_files(
    left: &FileSnapshot,
    right: &FileSnapshot,
    options: &DuplicateOptions,
    cancel: &AtomicBool,
    report: &mut DuplicateReport,
) -> Result<bool, CompareIssue> {
    validate_snapshot(left).map_err(|reason| CompareIssue::File(reason, false))?;
    validate_snapshot(right).map_err(|reason| CompareIssue::File(reason, true))?;
    let mut left_file = File::open(&left.candidate.path)
        .map_err(|_| CompareIssue::File(SkipReason::UnreadableFile, false))?;
    let mut right_file = File::open(&right.candidate.path)
        .map_err(|_| CompareIssue::File(SkipReason::UnreadableFile, true))?;
    validate_handle(&left_file, left).map_err(|reason| CompareIssue::File(reason, false))?;
    validate_handle(&right_file, right).map_err(|reason| CompareIssue::File(reason, true))?;

    let read_result: Result<bool, CompareIssue> = (|| {
        let mut equal = true;
        let mut remaining = left.candidate.size;
        let mut left_buffer = [0u8; READ_BUFFER_SIZE];
        let mut right_buffer = [0u8; READ_BUFFER_SIZE];
        while remaining > 0 {
            if cancel.load(Ordering::Relaxed) {
                return Err(CompareIssue::Cancelled);
            }
            let budget = options.max_bytes_read.saturating_sub(report.bytes_read);
            let max_pair_read = budget / 2;
            if max_pair_read == 0 {
                return Err(CompareIssue::Limit);
            }
            let length = usize::try_from(remaining.min(READ_BUFFER_SIZE as u64).min(max_pair_read))
                .unwrap_or(READ_BUFFER_SIZE);
            read_exact_accounted(&mut left_file, &mut left_buffer[..length], report)
                .map_err(|issue| CompareIssue::File(issue, false))?;
            read_exact_accounted(&mut right_file, &mut right_buffer[..length], report)
                .map_err(|issue| CompareIssue::File(issue, true))?;
            remaining -= length as u64;
            if left_buffer[..length] != right_buffer[..length] {
                equal = false;
                break;
            }
        }
        Ok(equal)
    })();
    let left_post = validate_handle(&left_file, left).and_then(|_| validate_snapshot(left));
    let right_post = validate_handle(&right_file, right).and_then(|_| validate_snapshot(right));
    match read_result {
        Ok(equal) => {
            left_post.map_err(|reason| CompareIssue::File(reason, false))?;
            right_post.map_err(|reason| CompareIssue::File(reason, true))?;
            Ok(equal)
        }
        Err(CompareIssue::File(reason, is_right)) => {
            let post = if is_right { right_post } else { left_post };
            Err(CompareIssue::File(post.err().unwrap_or(reason), is_right))
        }
        Err(issue) => Err(issue),
    }
}

fn read_exact_accounted(
    file: &mut File,
    mut buffer: &mut [u8],
    report: &mut DuplicateReport,
) -> Result<(), SkipReason> {
    while !buffer.is_empty() {
        let read = file.read(buffer).map_err(|_| SkipReason::UnreadableFile)?;
        if read == 0 {
            return Err(SkipReason::ChangedDuringRead);
        }
        report.bytes_read = report.bytes_read.saturating_add(read as u64);
        buffer = &mut buffer[read..];
    }
    Ok(())
}

#[derive(Debug)]
enum CompareIssue {
    File(SkipReason, bool),
    Cancelled,
    Limit,
}
