use crate::domain::Category;
use std::path::{Path, PathBuf};

pub fn data_directory() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("DCLEANER_DATA_DIR") {
        return Ok(PathBuf::from(path));
    }
    dirs::data_local_dir()
        .map(|p| p.join("DCleaner"))
        .ok_or("No user application-data directory is available.".into())
}
fn category(id: &str, name: &str, group: &str, description: &str, roots: Vec<PathBuf>) -> Category {
    Category {
        id: id.into(),
        name: name.into(),
        group: group.into(),
        description: description.into(),
        roots,
    }
}
fn browser_roots(parent: &Path, caches: &[&str], chromium: bool) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return vec![];
    };
    entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir() && !t.is_symlink()))
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            !chromium
                || name == "Default"
                || name
                    .strip_prefix("Profile ")
                    .is_some_and(|s| s.parse::<u32>().is_ok())
        })
        .flat_map(|e| caches.iter().map(move |c| e.path().join(c)))
        .collect()
}
pub fn categories() -> Vec<Category> {
    #[cfg(target_os = "windows")]
    {
        let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) else {
            return vec![];
        };
        return vec![
            category(
                "temp",
                "Temporary files",
                "Windows",
                "Old files in your local Windows Temp folder.",
                vec![local.join("Temp")],
            ),
            category(
                "crash",
                "Crash reports",
                "Windows",
                "Local application crash dumps.",
                vec![local.join("CrashDumps")],
            ),
            category(
                "chrome",
                "Google Chrome cache",
                "Applications",
                "Cache only. Cookies, history and passwords are retained.",
                browser_roots(
                    &local.join("Google/Chrome/User Data"),
                    &["Cache", "Code Cache", "GPUCache"],
                    true,
                ),
            ),
            category(
                "edge",
                "Microsoft Edge cache",
                "Applications",
                "Cache only. Cookies, history and passwords are retained.",
                browser_roots(
                    &local.join("Microsoft/Edge/User Data"),
                    &["Cache", "Code Cache", "GPUCache"],
                    true,
                ),
            ),
            category(
                "firefox",
                "Mozilla Firefox cache",
                "Applications",
                "Disposable cache2 data from local browser profiles.",
                browser_roots(&local.join("Mozilla/Firefox/Profiles"), &["cache2"], false),
            ),
        ];
    }
    #[cfg(target_os = "macos")]
    {
        let Some(home) = dirs::home_dir() else {
            return vec![];
        };
        vec![
            category(
                "temp",
                "User cache files",
                "macOS",
                "User-local cache files. Permissions and eligibility apply.",
                vec![home.join("Library/Caches")],
            ),
            category(
                "crash",
                "Crash reports",
                "macOS",
                "Local diagnostic reports.",
                vec![home.join("Library/Logs/DiagnosticReports")],
            ),
        ]
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        vec![]
    }
}
pub fn trash_label() -> &'static str {
    if cfg!(target_os = "windows") {
        "Recycle Bin"
    } else {
        "Trash"
    }
}
