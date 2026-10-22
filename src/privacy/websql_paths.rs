//! Existing WebSQL path regressions now exercise the shared storage walker.
use super::*;
const MAX_ENTRIES: usize = storage_files::MAX_ENTRIES;
const MAX_PATH_BYTES: usize = storage_files::MAX_PATH_BYTES;
const MAX_DEPTH: usize = 16;
struct Inventory {
    paths: Vec<PathBuf>,
    issues: Vec<&'static str>,
    cancelled: bool,
    truncated: bool,
}
fn discover(root: &Path, cancel: &AtomicBool) -> Inventory {
    with_budget(root, cancel, MAX_ENTRIES, MAX_PATH_BYTES)
}
fn with_budget(root: &Path, cancel: &AtomicBool, entries: usize, bytes: usize) -> Inventory {
    let inventory = storage_files::discover_paths(Browser::Chrome, root, cancel, entries, bytes);
    Inventory {
        paths: inventory
            .databases
            .into_iter()
            .filter(|target| target.kind == TableKind::ChromiumWebSql)
            .map(|target| target.path)
            .collect(),
        issues: inventory.issues,
        cancelled: inventory.cancelled,
        truncated: inventory.truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_entry_byte_and_depth_limits_remain_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("databases");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("Databases.db"), b"owned metadata").unwrap();
        for (entries, bytes) in [(0, MAX_PATH_BYTES), (MAX_ENTRIES, 0)] {
            let report = with_budget(dir.path(), &AtomicBool::new(false), entries, bytes);
            assert!(report.truncated);
            assert!(report.paths.is_empty());
            assert!(report.issues.iter().any(|reason| reason.contains("limit")));
        }
        let mut deep = base;
        for _ in 0..=MAX_DEPTH {
            deep.push("child");
        }
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("Databases.db"), b"owned deep metadata").unwrap();
        let report = discover(dir.path(), &AtomicBool::new(false));
        assert!(report.truncated);
        assert_eq!(report.paths.len(), 1);
        assert!(report.issues.iter().any(|reason| reason.contains("depth")));
    }

    #[test]
    fn absent_invalid_and_cancelled_paths_do_not_look_like_complete_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let absent = discover(dir.path(), &AtomicBool::new(false));
        assert!(absent.paths.is_empty() && absent.issues.is_empty() && !absent.truncated);
        fs::write(dir.path().join("databases"), b"not a directory").unwrap();
        let invalid = discover(dir.path(), &AtomicBool::new(false));
        assert!(invalid.paths.is_empty() && !invalid.issues.is_empty());
        let cancelled = discover(dir.path(), &AtomicBool::new(true));
        assert!(cancelled.cancelled && cancelled.paths.is_empty());
    }
}
