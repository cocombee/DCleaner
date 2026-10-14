use crate::domain::{Analysis, Candidate, Category, CategoryResult};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
pub const DAY_NS: u128 = 86_400_000_000_000;
pub const MAX_ENTRIES: usize = 100_000;
pub fn timestamp(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
pub fn is_link(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return true;
        }
    }
    false
}
pub fn safe_root(path: &Path) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if is_link(&metadata) || !metadata.is_dir() {
        return Err("The location is linked or not a directory.".into());
    }
    let absolute = std::path::absolute(path).map_err(|e| e.to_string())?;
    let canonical = dunce::canonicalize(path).map_err(|e| e.to_string())?;
    if !same_path(&absolute, &canonical) {
        return Err("A parent location redirects through a link.".into());
    }
    Ok(canonical)
}
pub fn same_path(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        a.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
    } else {
        a == b
    }
}
pub fn contained(root: &Path, file: &Path) -> bool {
    file.strip_prefix(root).is_ok_and(|p| {
        !p.as_os_str().is_empty()
            && !p
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
    })
}
pub struct WalkResult {
    pub files: Vec<Candidate>,
    pub skipped: usize,
    pub available: bool,
    pub truncated: bool,
}
pub fn walk(
    root: &Path,
    cutoff: u128,
    cancel: &AtomicBool,
    limit: usize,
    mut progress: impl FnMut(usize),
) -> WalkResult {
    let mut result = WalkResult {
        files: vec![],
        skipped: 0,
        available: false,
        truncated: false,
    };
    let Ok(root) = safe_root(root) else {
        return result;
    };
    result.available = true;
    let mut stack = vec![root.clone()];
    let mut visited = 0;
    while let Some(directory) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if safe_root(&directory).is_err() {
            result.skipped += 1;
            continue;
        }
        let entries = match fs::read_dir(&directory) {
            Ok(e) => e,
            Err(_) => {
                result.skipped += 1;
                continue;
            }
        };
        for entry in entries {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            visited += 1;
            if visited > limit {
                result.truncated = true;
                return result;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    result.skipped += 1;
                    continue;
                }
            };
            let file = entry.path();
            if !contained(&root, &file) {
                result.skipped += 1;
                continue;
            }
            let metadata = match fs::symlink_metadata(&file) {
                Ok(m) => m,
                Err(_) => {
                    result.skipped += 1;
                    continue;
                }
            };
            if is_link(&metadata) {
                result.skipped += 1;
                continue;
            }
            if metadata.is_dir() {
                stack.push(file);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let Ok(modified) = metadata.modified() else {
                result.skipped += 1;
                continue;
            };
            if timestamp(modified) > cutoff {
                continue;
            }
            if !dunce::canonicalize(&file)
                .is_ok_and(|p| same_path(&p, &file) && contained(&root, &p))
            {
                result.skipped += 1;
                continue;
            }
            result.files.push(Candidate {
                id: Uuid::new_v4(),
                path: file,
                root: root.clone(),
                size: metadata.len(),
                modified_ns: timestamp(modified),
                created_ns: metadata.created().ok().map(timestamp),
            });
        }
        progress(result.files.len());
    }
    result
}
pub fn analyze(
    categories: &[Category],
    ids: &[String],
    age: u32,
    cancel: &AtomicBool,
    mut progress: impl FnMut(&str, usize),
) -> Result<Analysis, String> {
    if !(1..=365).contains(&age) {
        return Err("Minimum file age must be between 1 and 365 days.".into());
    }
    if ids.is_empty() || ids.iter().any(|id| !categories.iter().any(|c| &c.id == id)) {
        return Err("Choose valid cleaning categories.".into());
    }
    let started = Instant::now();
    let cutoff = timestamp(SystemTime::now()).saturating_sub(u128::from(age) * DAY_NS);
    let mut results = vec![];
    let mut seen = HashSet::new();
    for category in categories.iter().filter(|c| ids.contains(&c.id)) {
        let mut group = CategoryResult {
            id: category.id.clone(),
            name: category.name.clone(),
            group: category.group.clone(),
            files: vec![],
            skipped: 0,
            available: false,
            truncated: false,
        };
        for root in &category.roots {
            let output = walk(root, cutoff, cancel, MAX_ENTRIES, |n| {
                progress(&category.name, n)
            });
            group.available |= output.available;
            group.truncated |= output.truncated;
            group.skipped += output.skipped;
            for file in output.files {
                if seen.insert(file.path.clone()) {
                    group.files.push(file);
                }
            }
            if cancel.load(Ordering::Relaxed) {
                break;
            }
        }
        results.push(group);
        if cancel.load(Ordering::Relaxed) {
            break;
        }
    }
    Ok(Analysis {
        id: Uuid::new_v4(),
        date: chrono::Local::now().to_rfc3339(),
        minimum_age_days: age,
        elapsed_ms: started.elapsed().as_millis() as u64,
        cancelled: cancel.load(Ordering::Relaxed),
        categories: results,
    })
}
