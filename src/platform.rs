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
        cache_root_scopes: Default::default(),
        id: id.into(),
        name: name.into(),
        group: group.into(),
        description: description.into(),
        roots,
    }
}
/// Explicit paths make discovery independently testable without changing the
/// process environment or enumerating the user's browser records.
pub fn browser_categories_at(
    local: &Path,
    roaming: &Path,
    program: &Path,
    common: &Path,
) -> Vec<Category> {
    let mut labels = vec![
        ("chrome", "Google Chrome cache"),
        ("edge", "Microsoft Edge cache"),
        ("firefox", "Mozilla Firefox cache"),
    ];
    labels.extend(
        crate::browser_cache::LABELS
            .iter()
            .copied()
            .filter(|(id, _)| !matches!(*id, "chrome" | "edge" | "firefox")),
    );
    let mut result: Vec<_> = labels
        .into_iter()
        .map(|(id, name)| {
            category(
                id,
                name,
                "Applications",
                "Browser cache and temporary website data; review matched files before removal.",
                vec![],
            )
        })
        .collect();
    let mut add = |index: usize, root: PathBuf, force_diagnostic: bool| {
        if !force_diagnostic
            && std::fs::symlink_metadata(&root)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        {
            return;
        }
        let definition = &crate::browser_cache::REFERENCE_ROOTS[index];
        let item = result
            .iter_mut()
            .find(|c| c.id == definition.category)
            .unwrap();
        item.cache_root_scopes.insert(
            root.clone(),
            crate::browser_cache::RootScope::Reference(index as u16),
        );
        item.roots.push(root);
    };
    for (index, definition) in crate::browser_cache::REFERENCE_ROOTS.iter().enumerate() {
        let base = match definition.environment {
            "localappdata" => local,
            "appdata" => roaming,
            "programfiles" => program,
            "commonappdata" => common,
            _ => continue,
        };
        if definition.relative == "Mozilla-*" {
            match std::fs::read_dir(base) {
                Ok(entries) => {
                    for entry in entries {
                        match entry {
                            Ok(entry)
                                if entry
                                    .file_name()
                                    .to_string_lossy()
                                    .to_ascii_lowercase()
                                    .starts_with("mozilla-") =>
                            {
                                add(index, entry.path(), false)
                            }
                            Ok(_) => {}
                            Err(_) => add(index, base.join("Mozilla-*"), true),
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => add(index, base.join("Mozilla-*"), true),
            }
        } else {
            add(index, base.join(definition.relative), false);
        }
    }
    // Missing optional installations do not crowd the sidebar. Keep the three
    // existing catalogue choices so saved selections remain compatible.
    result
        .retain(|c| !c.roots.is_empty() || matches!(c.id.as_str(), "chrome" | "edge" | "firefox"));
    for item in &mut result {
        item.roots.sort();
        item.roots.dedup();
    }
    result
}
pub fn categories() -> Vec<Category> {
    #[cfg(target_os = "windows")]
    {
        let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) else {
            return vec![];
        };
        let mut result = vec![
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
        ];
        let roaming = dirs::config_dir().unwrap_or_else(|| local.clone());
        let program = std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:/Program Files"));
        let common = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:/ProgramData"));
        result.extend(browser_categories_at(&local, &roaming, &program, &common));
        return result;
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
