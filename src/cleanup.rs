use crate::{
    domain::{Analysis, Candidate, CleanupPolicy, CleanupResult, FileOutcome},
    scanner::{DAY_NS, contained, is_link, safe_root, same_path, timestamp},
    store::{JournalEvent, JournalSink},
};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::SystemTime,
};
use uuid::Uuid;
pub trait TrashPort {
    fn move_to_trash(&mut self, path: &Path) -> Result<(), String>;
    fn batch_size(&self) -> usize {
        1
    }
    /// Success applies to the whole batch. Any error can represent a partial
    /// native effect: its durable intents must stay unresolved, without retry.
    fn move_batch_to_trash(&mut self, paths: &[&Path]) -> Result<(), String> {
        if let [path] = paths {
            self.move_to_trash(path)
        } else {
            Err("This Trash backend does not support a batch.".into())
        }
    }
}
pub struct SystemTrash;
impl TrashPort for SystemTrash {
    fn move_to_trash(&mut self, path: &Path) -> Result<(), String> {
        trash::delete(path).map_err(|e| e.to_string())
    }
    fn batch_size(&self) -> usize {
        if cfg!(windows) { 32 } else { 1 }
    }
    fn move_batch_to_trash(&mut self, paths: &[&Path]) -> Result<(), String> {
        // Same native Trash policy as the single-file path, with one Windows
        // IFileOperation/PerformOperations for a bounded set of exact files.
        let before: Vec<_> = paths.iter().map(|path| file_identity(path)).collect();
        trash::delete_all(paths).map_err(|e| e.to_string())?;
        confirm_removed(paths, &before, |path| match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Presence::Absent,
            Ok(_) => Presence::Present(file_identity(path)),
            Err(_) => Presence::Unknown,
        })
    }
}

/// Volume serial and file index: stable for one file across a same-volume
/// Recycle Bin move, and different for a file recreated at the same path.
type FileIdentity = (u32, u64);

enum Presence {
    Absent,
    Present(Option<FileIdentity>),
    Unknown,
}

#[cfg(windows)]
fn file_identity(path: &Path) -> Option<FileIdentity> {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_FLAG_OPEN_REPARSE_POINT, GetFileInformationByHandle,
        },
    };
    // Metadata-only handle; std shares read/write/delete, so the Trash move
    // is not blocked, and the handle closes before the move starts.
    let file = fs::OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .ok()?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }.ok()?;
    Some((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

#[cfg(not(windows))]
fn file_identity(_path: &Path) -> Option<FileIdentity> {
    None
}

/// A path that still exists after a successful batch counts as removed only
/// when it is provably a different file (a program recreated it at once).
/// Same or unknown identity keeps the whole batch unresolved, without retry.
fn confirm_removed(
    paths: &[&Path],
    before: &[Option<FileIdentity>],
    presence: impl Fn(&Path) -> Presence,
) -> Result<(), String> {
    for (path, before) in paths.iter().zip(before) {
        let removed = match presence(path) {
            Presence::Absent => true,
            Presence::Present(Some(now)) => before.is_some_and(|before| before != now),
            Presence::Present(None) | Presence::Unknown => false,
        };
        if !removed {
            return Err(
                "The native Trash operation did not confirm removal of every selected source path."
                    .into(),
            );
        }
    }
    Ok(())
}
pub fn revalidate(file: &Candidate, age: u32) -> Result<(), String> {
    let root = safe_root(&file.root)?;
    if !contained(&root, &file.path) {
        return Err("The candidate is outside its scanned root.".into());
    }
    let meta = fs::symlink_metadata(&file.path).map_err(|e| e.to_string())?;
    if is_link(&meta) || !meta.is_file() {
        return Err("The candidate became a link or is no longer a regular file.".into());
    }
    let real = dunce::canonicalize(&file.path).map_err(|e| e.to_string())?;
    if !contained(&root, &real) || !same_path(&real, &file.path) {
        return Err("The file location changed.".into());
    }
    let modified = meta.modified().map(timestamp).map_err(|e| e.to_string())?;
    if meta.len() != file.size
        || modified != file.modified_ns
        || meta.created().ok().map(timestamp) != file.created_ns
    {
        return Err("The file changed since analysis.".into());
    }
    if modified > timestamp(SystemTime::now()).saturating_sub(u128::from(age) * DAY_NS) {
        return Err("The file is too recent to clean.".into());
    }
    Ok(())
}
pub fn clean(
    analysis: &Analysis,
    ids: &[Uuid],
    cancel: &AtomicBool,
    trash: &mut impl TrashPort,
    journal: &mut impl JournalSink,
    progress: impl FnMut(usize, usize),
) -> Result<CleanupResult, String> {
    if analysis.cleanup_policy != CleanupPolicy::MinimumAge {
        return Err(
            "Configured files require their current Custom Clean rules. Analyze again.".into(),
        );
    }
    let browser_ids: HashMap<_, _> = analysis
        .categories
        .iter()
        .filter(|c| crate::browser_cache::is_category(&c.id))
        .flat_map(|c| c.files.iter().map(|f| (f.id, c.id.as_str())))
        .collect();
    clean_with_validator(analysis, ids, cancel, trash, journal, progress, |file| {
        if let Some(category) = browser_ids.get(&file.id) {
            if !crate::browser_cache::includes(category, &file.root, &file.path) {
                return Err(
                    "The selected file is outside the current browser cache rules. Analyze again."
                        .into(),
                );
            }
        }
        validate_age(
            file,
            if browser_ids.contains_key(&file.id) {
                0
            } else {
                analysis.minimum_age_days
            },
        )
    })
}

fn validate_age(file: &Candidate, age: u32) -> Result<(), String> {
    if file.modified_ns > timestamp(SystemTime::now()).saturating_sub(u128::from(age) * DAY_NS) {
        return Err("The file is too recent to clean.".into());
    }
    Ok(())
}

/// The owning report must resolve exact IDs and enforce its current policy.
/// Core identity and location checks remain mandatory for every effect.
pub(crate) fn clean_with_validator(
    analysis: &Analysis,
    ids: &[Uuid],
    cancel: &AtomicBool,
    trash: &mut impl TrashPort,
    journal: &mut impl JournalSink,
    mut progress: impl FnMut(usize, usize),
    mut validate: impl FnMut(&Candidate) -> Result<(), String>,
) -> Result<CleanupResult, String> {
    if analysis.cancelled {
        return Err("Complete a new analysis before cleaning.".into());
    }
    if ids.is_empty() {
        return Err("Select files from the current analysis.".into());
    }
    let mut by_id = HashMap::new();
    for file in analysis
        .categories
        .iter()
        .flat_map(|category| &category.files)
    {
        if by_id.insert(file.id, file).is_some() {
            return Err("Ambiguous file ID in analysis. Analyze again.".into());
        }
    }
    let mut seen = HashSet::new();
    let mut files = vec![];
    for id in ids {
        let Some(file) = by_id.get(id) else {
            return Err("Unknown file ID. Analyze again.".into());
        };
        if seen.insert(*id) {
            files.push(*file);
        }
    }
    let mut result = CleanupResult {
        id: Uuid::new_v4(),
        date: chrono::Local::now().to_rfc3339(),
        ..Default::default()
    };
    journal.append(&JournalEvent::Start {
        id: result.id,
        date: result.date.clone(),
    })?;
    let batch_size = trash.batch_size().clamp(1, 32);
    let mut completed = 0;
    for batch in files.chunks(batch_size) {
        if cancel.load(Ordering::Relaxed) {
            result.cancelled = true;
            break;
        }
        let intents: Vec<_> = batch
            .iter()
            .map(|file| JournalEvent::Intent {
                file_id: file.id,
                path: file.path.clone(),
                size: file.size,
            })
            .collect();
        // No file action can begin before the entire bounded batch is durable.
        journal.append_batch(&intents)?;
        let mut checks: Vec<_> = batch
            .iter()
            .map(|file| revalidate(file, 0).and_then(|_| validate(file)))
            .collect();
        if cancel.load(Ordering::Relaxed) {
            result.cancelled = true;
            for check in &mut checks {
                if check.is_ok() {
                    *check = Err("Not moved because cleaning stopped.".into());
                }
            }
        }
        let paths: Vec<&Path> = batch
            .iter()
            .zip(&checks)
            .filter(|(_, check)| check.is_ok())
            .map(|(file, _)| file.path.as_path())
            .collect();
        if !paths.is_empty() {
            // An aggregate error cannot identify which individual effects ran.
            // Preserve every intent in this batch as uncertain and stop; never
            // fall back to single-file retries after a partial native operation.
            if let Err(error) = trash.move_batch_to_trash(&paths) {
                if batch_size == 1 {
                    checks[0] = Err(error);
                } else {
                    return Err(format!(
                        "Trash cleanup stopped; this batch has unresolved outcomes. Review its cleanup history before taking further action: {error}"
                    ));
                }
            }
        }
        let outcomes: Vec<_> = batch
            .iter()
            .zip(checks)
            .map(|(file, check)| JournalEvent::Outcome {
                outcome: FileOutcome {
                    file_id: file.id,
                    path: file.path.clone(),
                    size: file.size,
                    success: check.is_ok(),
                    reason: check.err(),
                },
            })
            .collect();
        journal.append_batch(&outcomes)?;
        for event in outcomes {
            let JournalEvent::Outcome { outcome } = event else {
                unreachable!()
            };
            if outcome.success {
                result.files += 1;
                result.bytes += outcome.size;
                result.cleaned_ids.push(outcome.file_id);
            } else {
                result.failed.push(outcome);
            }
        }
        completed += batch.len();
        progress(completed, files.len());
        if result.cancelled {
            break;
        }
    }
    journal.append(&JournalEvent::Finish {
        cancelled: result.cancelled,
    })?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Category;

    #[test]
    fn only_provably_recreated_paths_confirm_a_batch_move() {
        let (a, b) = (Path::new("a.log"), Path::new("b.log"));
        let paths = [a, b];
        let before = [Some((7, 1)), Some((7, 2))];
        // Gone, or replaced by a different file: the originals were moved.
        assert!(
            confirm_removed(&paths, &before, |path| if path == a {
                Presence::Absent
            } else {
                Presence::Present(Some((7, 99)))
            })
            .is_ok()
        );
        // The same file, an unreadable identity, an unknown pre-move identity
        // or an uninspectable path never confirm the batch.
        for presence in [
            |_: &Path| Presence::Present(Some((7, 2))),
            |_: &Path| Presence::Present(None),
            |_: &Path| Presence::Unknown,
        ] {
            assert!(
                confirm_removed(&[b], &[Some((7, 2))], |path| if path == a {
                    Presence::Absent
                } else {
                    presence(path)
                })
                .is_err()
            );
        }
        assert!(confirm_removed(&[b], &[None], |_| Presence::Present(Some((7, 99)))).is_err());
    }

    #[test]
    #[cfg(windows)]
    fn file_identity_is_stable_for_one_file_and_changes_when_recreated() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recreated.log");
        fs::write(&path, b"first").unwrap();
        let first = file_identity(&path).unwrap();
        assert_eq!(file_identity(&path), Some(first));
        let moved = temp.path().join("moved.log");
        fs::rename(&path, &moved).unwrap();
        assert_eq!(file_identity(&moved), Some(first));
        fs::write(&path, b"first").unwrap();
        assert_ne!(file_identity(&path), Some(first));
        assert_eq!(file_identity(&temp.path().join("missing.log")), None);
    }

    #[derive(Default)]
    struct Effects(usize);
    impl TrashPort for Effects {
        fn move_to_trash(&mut self, _: &Path) -> Result<(), String> {
            self.0 += 1;
            Ok(())
        }
    }
    #[derive(Default)]
    struct Journal(Vec<JournalEvent>);
    impl JournalSink for Journal {
        fn append(&mut self, event: &JournalEvent) -> Result<(), String> {
            self.0.push(event.clone());
            Ok(())
        }
    }
    fn fixture() -> (tempfile::TempDir, Analysis) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.tmp");
        fs::write(&path, b"unchanged").unwrap();
        filetime::set_file_mtime(
            &path,
            filetime::FileTime::from_system_time(
                SystemTime::now() - std::time::Duration::from_secs(30 * 86400),
            ),
        )
        .unwrap();
        let analysis = crate::scanner::analyze(
            &[Category {
                cache_root_scopes: Default::default(),
                id: "fixture".into(),
                name: "Fixture".into(),
                group: "Test".into(),
                description: String::new(),
                roots: vec![directory.path().to_path_buf()],
            }],
            &["fixture".into()],
            7,
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(
            analysis.count(),
            1,
            "fixture root validation: {:?}",
            crate::scanner::safe_root(directory.path())
        );
        (directory, analysis)
    }
    #[test]
    fn custom_projection_cannot_use_legacy_effect_path() {
        let (_directory, mut analysis) = fixture();
        analysis.cleanup_policy = CleanupPolicy::CustomCleanRules;
        let id = analysis.categories[0].files[0].id;
        let mut effects = Effects::default();
        let mut journal = Journal::default();
        assert!(
            clean(
                &analysis,
                &[id],
                &AtomicBool::new(false),
                &mut effects,
                &mut journal,
                |_, _| {}
            )
            .is_err()
        );
        assert!(journal.0.is_empty());
        assert_eq!(effects.0, 0);
    }
    #[test]
    fn owner_policy_rejection_never_reaches_trash() {
        let (_directory, analysis) = fixture();
        let id = analysis.categories[0].files[0].id;
        let mut effects = Effects::default();
        let mut journal = Journal::default();
        let result = clean_with_validator(
            &analysis,
            &[id],
            &AtomicBool::new(false),
            &mut effects,
            &mut journal,
            |_, _| {},
            |_| Err("Rule no longer permits this file".into()),
        )
        .unwrap();
        assert_eq!(effects.0, 0);
        assert_eq!(result.failed.len(), 1);
        assert!(matches!(
            journal.0.get(1),
            Some(JournalEvent::Intent { .. })
        ));
        assert!(
            matches!(journal.0.get(2), Some(JournalEvent::Outcome { outcome }) if !outcome.success)
        );
    }
    #[test]
    fn permissive_owner_cannot_bypass_core_file_identity() {
        let (_directory, analysis) = fixture();
        let candidate = &analysis.categories[0].files[0];
        fs::write(&candidate.path, b"changed length").unwrap();
        let mut effects = Effects::default();
        let mut journal = Journal::default();
        let mut owner_called = false;
        let result = clean_with_validator(
            &analysis,
            &[candidate.id],
            &AtomicBool::new(false),
            &mut effects,
            &mut journal,
            |_, _| {},
            |_| {
                owner_called = true;
                Ok(())
            },
        )
        .unwrap();
        assert!(!owner_called);
        assert_eq!(effects.0, 0);
        assert_eq!(result.failed.len(), 1);
    }
    #[test]
    fn ambiguous_analysis_ids_rejected_before_journal() {
        let (_directory, mut analysis) = fixture();
        let candidate = analysis.categories[0].files[0].clone();
        analysis.categories[0].files.push(candidate.clone());
        let mut effects = Effects::default();
        let mut journal = Journal::default();
        assert!(
            clean(
                &analysis,
                &[candidate.id],
                &AtomicBool::new(false),
                &mut effects,
                &mut journal,
                |_, _| {}
            )
            .is_err()
        );
        assert!(journal.0.is_empty());
        assert_eq!(effects.0, 0);
    }
}
