//! Metadata-only witnesses for declared history/download file rules. Recursive
//! profile discovery already visits descendants; a root filename must witness
//! its own directory, rather than promoting every ancestor into a profile.
use super::*;

#[derive(Default)]
pub(in crate::privacy) struct Witness {
    pub found: bool,
    pub entries: usize,
    pub path_bytes: usize,
    pub truncated: bool,
    pub cancelled: bool,
    pub issues: Vec<&'static str>,
}
impl Witness {
    fn issue(&mut self, reason: &'static str) {
        if !self.issues.contains(&reason) {
            self.issues.push(reason);
        }
    }
}

pub(in crate::privacy) fn discover(
    browser: Browser,
    root: &Path,
    named_scopes: bool,
    cancel: &AtomicBool,
    entries: usize,
    path_bytes: usize,
) -> Witness {
    discover_with_limits(
        browser,
        root,
        named_scopes,
        cancel,
        Limits {
            entries,
            path_bytes,
            depth: 16,
        },
    )
}

fn discover_with_limits(
    browser: Browser,
    root: &Path,
    named_scopes: bool,
    cancel: &AtomicBool,
    limits: Limits,
) -> Witness {
    let mut result = Witness::default();
    if cancel.load(Ordering::Relaxed) {
        result.cancelled = true;
        return result;
    }
    if safe_profile_root(root).is_err() {
        result.issue("A record-file profile witness root is linked or unavailable.");
        return result;
    }
    let mut scopes = HashSet::new();
    for rule in catalogue::RULES.iter().filter(|r| r.browser == browser) {
        for scope in rule.scopes {
            if !scope.directory.is_empty() && !named_scopes {
                continue;
            }
            // FileKey recursion is for scanning; root witnesses stay local.
            let recursive = !scope.directory.is_empty() && scope.recursive;
            if !scopes.insert((scope.directory, recursive)) {
                continue;
            }
            let base = if scope.directory.is_empty() {
                root.to_owned()
            } else {
                root.join(scope.directory)
            };
            match fs::symlink_metadata(&base) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Ok(meta) if meta.is_dir() && !is_link(&meta) => {}
                _ => {
                    result.issue("A record-file witness directory is linked or unavailable.");
                    continue;
                }
            }
            let mut pending = vec![(base, 0)];
            while let Some((directory, depth)) = pending.pop() {
                if cancel.load(Ordering::Relaxed) {
                    result.cancelled = true;
                    return result;
                }
                if safe_profile_root(&directory).is_err() {
                    result.issue("A record-file witness directory was redirected or unavailable.");
                    continue;
                }
                let children = match fs::read_dir(&directory) {
                    Ok(v) => v,
                    Err(_) => {
                        result.issue("Record-file witness entries could not be read.");
                        continue;
                    }
                };
                for child in children {
                    if cancel.load(Ordering::Relaxed) {
                        result.cancelled = true;
                        return result;
                    }
                    let path = match child {
                        Ok(v) => v.path(),
                        Err(_) => {
                            result.issue("A record-file witness entry could not be read.");
                            continue;
                        }
                    };
                    result.entries = result.entries.saturating_add(1);
                    result.path_bytes = result.path_bytes.saturating_add(path.as_os_str().len());
                    if result.entries > limits.entries || result.path_bytes > limits.path_bytes {
                        result.truncated = true;
                        result.issue("Record-file witness inspection limit reached.");
                        return result;
                    }
                    if path.to_str().is_none() {
                        result.issue("A record-file witness name has unsupported encoding.");
                        continue;
                    }
                    // All same-family rules participate, even when scopes are
                    // deduplicated between History and Downloads.
                    let owned = [
                        PrivacyCategory::History,
                        PrivacyCategory::Downloads,
                        PrivacyCategory::SavedPasswords,
                        PrivacyCategory::SitePreferences,
                    ]
                    .into_iter()
                    .any(|category| claims(browser, category, root, &path));
                    if !recursive && !owned {
                        continue;
                    }
                    let meta = match fs::symlink_metadata(&path) {
                        Ok(v) => v,
                        Err(_) => {
                            result.issue("A record-file witness path could not be inspected.");
                            continue;
                        }
                    };
                    if !recursive && meta.is_dir() {
                        continue;
                    }
                    if is_link(&meta) {
                        result.issue("A linked record-file witness was not followed.");
                        continue;
                    }
                    if meta.is_dir() {
                        if depth == limits.depth {
                            result.truncated = true;
                            result.issue("Record-file witness depth limit reached.");
                        } else {
                            pending.push((path, depth + 1));
                        }
                    } else if meta.is_file() && owned {
                        if validate_database_path(root, &path).is_ok() {
                            result.found = true;
                            return result;
                        }
                        result.issue("A record-file witness was redirected or unavailable.");
                    }
                }
            }
        }
    }
    result
}

#[cfg(test)]
#[path = "record_file_discovery_tests.rs"]
mod tests;
