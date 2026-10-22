//! Declared history/download file rules. Enumeration and content reads are
//! read-only; reviewed effects belong to the shared file journal/Trash owner.
use super::*;

struct Scope {
    directory: &'static str,
    mask: &'static str,
    recursive: bool,
}
struct Handler {
    key: &'static str,
    pattern: &'static str,
    delete: bool,
}
struct Rule {
    browser: Browser,
    category: PrivacyCategory,
    id: &'static str,
    scopes: &'static [Scope],
    handlers: &'static [Handler],
}
#[path = "record_file_catalogue.rs"]
mod catalogue;
#[path = "record_file_discovery.rs"]
pub(super) mod discovery;

fn winner(rule: &Rule, root: &Path, path: &Path) -> Option<&'static str> {
    let parts = storage_files::named_parts(root, path)?;
    let name = *parts.last()?;
    let eligible = rule.scopes.iter().any(|scope| {
        let base = scope
            .directory
            .split('/')
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>();
        parts.len() > base.len()
            && (scope.recursive || parts.len() == base.len() + 1)
            && base.iter().zip(&parts).all(|(a, b)| {
                if cfg!(windows) {
                    a.eq_ignore_ascii_case(b)
                } else {
                    a == b
                }
            })
            && storage_files::matches_pattern(name, scope.mask)
    });
    if !eligible {
        return None;
    }
    let handler = rule
        .handlers
        .iter()
        .find(|h| storage_files::matches_pattern(name, h.pattern))?;
    handler.delete.then_some(handler.key)
}

pub(super) fn owns(
    rule_id: &str,
    handler: &str,
    browser: Browser,
    category: PrivacyCategory,
    root: &Path,
    path: &Path,
) -> bool {
    catalogue::RULES.iter().any(|r| {
        r.id == rule_id
            && r.browser == browser
            && r.category == category
            && winner(r, root, path) == Some(handler)
    })
}
pub(super) fn claims(
    browser: Browser,
    category: PrivacyCategory,
    root: &Path,
    path: &Path,
) -> bool {
    binding(browser, category, root, path).is_some()
}

pub(super) fn binding(
    browser: Browser,
    category: PrivacyCategory,
    root: &Path,
    path: &Path,
) -> Option<(&'static str, &'static str)> {
    catalogue::RULES
        .iter()
        .filter(|r| r.browser == browser && r.category == category)
        .find_map(|r| winner(r, root, path).map(|handler| (r.id, handler)))
}

#[derive(Clone, Copy)]
struct Limits {
    entries: usize,
    path_bytes: usize,
    depth: usize,
}

pub(super) fn scan(
    profile: &BrowserProfile,
    categories: &[PrivacyCategory],
    keeps: &std::sync::Arc<HashSet<String>>,
    cancel: &AtomicBool,
    byte_budget: &mut u64,
    file_budget: &mut usize,
    seen: &mut HashSet<String>,
    report: &mut PrivacyReport,
) {
    scan_with_limits(
        profile,
        categories,
        keeps,
        cancel,
        byte_budget,
        file_budget,
        seen,
        report,
        Limits {
            entries: storage_files::MAX_ENTRIES,
            path_bytes: storage_files::MAX_PATH_BYTES,
            depth: 16,
        },
    );
}

fn scan_with_limits(
    profile: &BrowserProfile,
    categories: &[PrivacyCategory],
    keeps: &std::sync::Arc<HashSet<String>>,
    cancel: &AtomicBool,
    byte_budget: &mut u64,
    file_budget: &mut usize,
    seen: &mut HashSet<String>,
    report: &mut PrivacyReport,
    limits: Limits,
) {
    let mut entries = 0usize;
    let mut path_bytes = 0usize;
    for rule in catalogue::RULES
        .iter()
        .filter(|r| r.browser == profile.browser && categories.contains(&r.category))
    {
        let mut roots = HashSet::new();
        for scope in rule.scopes {
            if !roots.insert((scope.directory, scope.recursive)) {
                continue;
            }
            let base = if scope.directory.is_empty() {
                profile.root.clone()
            } else {
                profile.root.join(scope.directory)
            };
            match fs::symlink_metadata(&base) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Ok(meta) if meta.is_dir() && !is_link(&meta) => {}
                _ => {
                    add_skip(
                        report,
                        &profile.name,
                        Some(rule.category),
                        "A browser record directory is linked or unavailable.",
                    );
                    continue;
                }
            }
            let mut pending = vec![(base, 0usize)];
            while let Some((directory, depth)) = pending.pop() {
                if cancel.load(Ordering::Relaxed) {
                    report.cancelled = true;
                    return;
                }
                if safe_profile_root(&directory).is_err() {
                    add_skip(
                        report,
                        &profile.name,
                        Some(rule.category),
                        "A browser record directory was redirected or became unavailable.",
                    );
                    continue;
                }
                let children = match fs::read_dir(&directory) {
                    Ok(v) => v,
                    Err(_) => {
                        add_skip(
                            report,
                            &profile.name,
                            Some(rule.category),
                            "Browser record directory entries could not be read.",
                        );
                        continue;
                    }
                };
                for child in children {
                    if cancel.load(Ordering::Relaxed) {
                        report.cancelled = true;
                        return;
                    }
                    entries += 1;
                    let path = match child {
                        Ok(v) => v.path(),
                        Err(_) => {
                            add_skip(
                                report,
                                &profile.name,
                                Some(rule.category),
                                "A browser record entry could not be inspected.",
                            );
                            continue;
                        }
                    };
                    path_bytes = path_bytes.saturating_add(path.as_os_str().len());
                    if entries > limits.entries || path_bytes > limits.path_bytes {
                        report.truncated = true;
                        add_skip(
                            report,
                            &profile.name,
                            Some(rule.category),
                            "Browser record path inspection limit reached.",
                        );
                        return;
                    }
                    if path.to_str().is_none() {
                        add_skip(
                            report,
                            &profile.name,
                            Some(rule.category),
                            "A browser record path has unsupported encoding.",
                        );
                        continue;
                    }
                    // Nonrecursive FileKeys cannot own unrelated entries. Do
                    // not turn a cookie-directory link into a history warning.
                    let handler = winner(rule, &profile.root, &path);
                    if !scope.recursive && handler.is_none() {
                        continue;
                    }
                    let meta = match fs::symlink_metadata(&path) {
                        Ok(v) => v,
                        Err(_) => {
                            add_skip(
                                report,
                                &profile.name,
                                Some(rule.category),
                                "A browser record path could not be inspected.",
                            );
                            continue;
                        }
                    };
                    if !scope.recursive && meta.is_dir() {
                        continue;
                    }
                    if is_link(&meta) {
                        add_skip(
                            report,
                            &profile.name,
                            Some(rule.category),
                            "A linked browser record path was not followed.",
                        );
                        continue;
                    }
                    if meta.is_dir() {
                        if scope.recursive {
                            if depth == limits.depth {
                                report.truncated = true;
                                add_skip(
                                    report,
                                    &profile.name,
                                    Some(rule.category),
                                    "Browser record depth limit reached.",
                                );
                            } else {
                                pending.push((path, depth + 1));
                            }
                        }
                        continue;
                    }
                    if !meta.is_file() {
                        continue;
                    }
                    let Some(handler) = handler else {
                        continue;
                    };
                    let key = storage_files::path_key(&path);
                    if !seen.insert(key) {
                        continue;
                    }
                    if *file_budget == 0 || report.records.len() >= MAX_RECORDS {
                        report.truncated = true;
                        add_skip(
                            report,
                            &profile.name,
                            Some(rule.category),
                            "Browser record file inspection limit reached.",
                        );
                        return;
                    }
                    *file_budget -= 1;
                    storage_files::scan_record_file(
                        profile,
                        &storage_files::ObservedFile {
                            path,
                            stamp: FileStamp {
                                length: meta.len(),
                                modified_ns: meta.modified().ok().map(timestamp).unwrap_or(0),
                                created_ns: meta.created().ok().map(timestamp),
                            },
                        },
                        rule.category,
                        rule.id,
                        handler,
                        keeps,
                        cancel,
                        byte_budget,
                        report,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "record_files_tests.rs"]
mod tests;
