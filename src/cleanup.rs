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
}
pub struct SystemTrash;
impl TrashPort for SystemTrash {
    fn move_to_trash(&mut self, path: &Path) -> Result<(), String> {
        trash::delete(path).map_err(|e| e.to_string())
    }
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
    clean_with_validator(analysis, ids, cancel, trash, journal, progress, |file| {
        validate_age(file, analysis.minimum_age_days)
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
    for (index, file) in files.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            result.cancelled = true;
            break;
        }
        journal.append(&JournalEvent::Intent {
            file_id: file.id,
            path: file.path.clone(),
            size: file.size,
        })?;
        let effect = revalidate(file, 0)
            .and_then(|_| validate(file))
            .and_then(|_| trash.move_to_trash(&file.path));
        let outcome = FileOutcome {
            file_id: file.id,
            path: file.path.clone(),
            size: file.size,
            success: effect.is_ok(),
            reason: effect.err(),
        };
        journal.append(&JournalEvent::Outcome {
            outcome: outcome.clone(),
        })?;
        if outcome.success {
            result.files += 1;
            result.bytes += file.size;
            result.cleaned_ids.push(file.id);
        } else {
            result.failed.push(outcome);
        }
        progress(index + 1, files.len());
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
