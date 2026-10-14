use crate::{
    domain::{Analysis, Candidate, CleanupResult, FileOutcome},
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
    mut progress: impl FnMut(usize, usize),
) -> Result<CleanupResult, String> {
    if analysis.cancelled {
        return Err("Complete a new analysis before cleaning.".into());
    }
    if ids.is_empty() {
        return Err("Select files from the current analysis.".into());
    }
    let by_id: HashMap<_, _> = analysis
        .categories
        .iter()
        .flat_map(|c| &c.files)
        .map(|f| (f.id, f))
        .collect();
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
        let effect = revalidate(file, analysis.minimum_age_days)
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
