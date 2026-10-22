//! Ordered session FileKeys/handlers. Discovery reads metadata only; scan
//! classifies one exact source image before selecting Trash or held rewrite.
use super::*;
struct Scope {
    directory: &'static str,
    masks: &'static str,
    recursive: bool,
}
#[derive(Clone, Copy)]
enum Kind {
    Session,
    MozillaJson,
    MozillaLz4,
    Text,
    File,
    Path,
}
struct Handler {
    key: &'static str,
    pattern: &'static str,
    kind: Kind,
}
struct Rule {
    browser: Browser,
    id: &'static str,
    scopes: &'static [Scope],
    handlers: &'static [Handler],
}
#[path = "session_catalogue.rs"]
mod catalogue;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Format {
    Chromium,
    MozillaJson,
    MozillaLz4,
}
pub(super) fn format(browser: Browser, root: &Path, path: &Path) -> Option<Format> {
    catalogue::RULES
        .iter()
        .filter(|r| r.browser == browser)
        .find_map(|r| match winner(r, root, path)?.kind {
            Kind::Session => Some(Format::Chromium),
            Kind::MozillaJson => Some(Format::MozillaJson),
            Kind::MozillaLz4 => Some(Format::MozillaLz4),
            _ => None,
        })
}
fn unsupported(browser: Browser, root: &Path, path: &Path) -> bool {
    catalogue::RULES
        .iter()
        .filter(|r| r.browser == browser)
        .any(|r| winner(r, root, path).is_some_and(|h| matches!(h.kind, Kind::Text)))
}
fn winner(rule: &Rule, root: &Path, path: &Path) -> Option<&'static Handler> {
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
            && scope
                .masks
                .split(';')
                .any(|mask| storage_files::matches_pattern(name, mask))
    });
    if !eligible {
        return None;
    }
    let full = path.to_string_lossy().replace('/', "\\");
    rule.handlers.iter().find(|h| {
        storage_files::matches_pattern(
            if matches!(h.kind, Kind::Path) {
                &full
            } else {
                name
            },
            h.pattern,
        )
    })
}
pub(super) fn binding(
    browser: Browser,
    root: &Path,
    path: &Path,
) -> Option<(&'static str, &'static str)> {
    catalogue::RULES
        .iter()
        .filter(|r| r.browser == browser)
        .find_map(|r| {
            winner(r, root, path)
                .filter(|h| matches!(h.kind, Kind::Session | Kind::MozillaJson | Kind::MozillaLz4))
                .map(|h| (r.id, h.key))
        })
}
pub(super) fn claims(browser: Browser, root: &Path, path: &Path) -> bool {
    binding(browser, root, path).is_some()
}
pub(super) fn generic_binding(
    browser: Browser,
    root: &Path,
    path: &Path,
) -> Option<(&'static str, &'static str, bool)> {
    catalogue::RULES
        .iter()
        .filter(|r| r.browser == browser)
        .find_map(|r| {
            winner(r, root, path)
                .filter(|h| matches!(h.kind, Kind::File | Kind::Path))
                .map(|h| (r.id, h.key, matches!(h.kind, Kind::Path)))
        })
}
pub(super) fn generic_scope(root: &Path, path: &Path, directory: bool) -> (PathBuf, bool) {
    if directory
        && let Some(parts) = storage_files::named_parts(root, path)
        && parts.len() > 1
        && ["Session Storage", "Extension State"]
            .iter()
            .any(|n| parts[0].eq_ignore_ascii_case(n))
    {
        return (root.join(parts[0]), true);
    }
    (path.to_owned(), false)
}
#[derive(Default)]
pub(super) struct Inventory {
    pub files: Vec<storage_files::ObservedFile>,
    pub issues: Vec<&'static str>,
    pub entries: usize,
    pub path_bytes: usize,
    pub truncated: bool,
    pub cancelled: bool,
}
impl Inventory {
    fn issue(&mut self, reason: &'static str) {
        if !self.issues.contains(&reason) {
            self.issues.push(reason);
        }
    }
}
pub(super) fn discover(
    browser: Browser,
    root: &Path,
    named_scopes: bool,
    cancel: &AtomicBool,
    max_entries: usize,
    max_path_bytes: usize,
    witness: bool,
) -> Inventory {
    let mut out = Inventory::default();
    let mut scopes = HashSet::new();
    let mut paths = HashSet::new();
    for rule in catalogue::RULES.iter().filter(|r| r.browser == browser) {
        for scope in rule.scopes {
            if (!named_scopes && !scope.directory.is_empty())
                || !scopes.insert((scope.directory, scope.recursive))
            {
                continue;
            }
            let base = if scope.directory.is_empty() {
                root.to_owned()
            } else {
                root.join(scope.directory)
            };
            match fs::symlink_metadata(&base) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Ok(m) if m.is_dir() && !is_link(&m) => {}
                _ => {
                    out.issue("A session directory is linked or unavailable.");
                    continue;
                }
            }
            let mut pending = vec![(base, 0)];
            while let Some((directory, depth)) = pending.pop() {
                if cancel.load(Ordering::Relaxed) {
                    out.cancelled = true;
                    return out;
                }
                if safe_profile_root(&directory).is_err() {
                    out.issue("A session directory was redirected or became unavailable.");
                    continue;
                }
                let entries = match fs::read_dir(&directory) {
                    Ok(v) => v,
                    Err(_) => {
                        out.issue("Session directory entries could not be read.");
                        continue;
                    }
                };
                for entry in entries {
                    if cancel.load(Ordering::Relaxed) {
                        out.cancelled = true;
                        return out;
                    }
                    let path = match entry {
                        Ok(e) => e.path(),
                        Err(_) => {
                            out.issue("A session directory entry could not be inspected.");
                            continue;
                        }
                    };
                    out.entries = out.entries.saturating_add(1);
                    out.path_bytes = out.path_bytes.saturating_add(path.as_os_str().len());
                    if out.entries > max_entries || out.path_bytes > max_path_bytes {
                        out.truncated = true;
                        out.issue("Session path observation limit reached.");
                        return out;
                    }
                    if path.to_str().is_none() {
                        out.issue("A session filename has unsupported encoding.");
                        continue;
                    }
                    let owned = claims(browser, root, &path)
                        || generic_binding(browser, root, &path).is_some()
                        || unsupported(browser, root, &path);
                    if !scope.recursive && !owned {
                        continue;
                    }
                    let meta = match fs::symlink_metadata(&path) {
                        Ok(m) => m,
                        Err(_) => {
                            out.issue("A session path could not be inspected.");
                            continue;
                        }
                    };
                    if is_link(&meta) {
                        out.issue("A session path is linked and was not followed.");
                        continue;
                    }
                    if meta.is_dir() {
                        if scope.recursive {
                            if depth >= 16 {
                                out.truncated = true;
                                out.issue("Session directory depth limit reached.");
                            } else {
                                pending.push((path, depth + 1));
                            }
                        }
                        continue;
                    }
                    if !owned || !meta.is_file() || !paths.insert(storage_files::path_key(&path)) {
                        continue;
                    }
                    match validate_database_path(root, &path) {
                        Ok((path, stamp, _)) => {
                            out.files.push(storage_files::ObservedFile { path, stamp });
                            if witness {
                                return out;
                            }
                        }
                        Err(_) => out.issue("A session path is redirected or unavailable."),
                    }
                }
            }
        }
    }
    out
}
pub(super) fn scan(
    profile: &BrowserProfile,
    cancel: &AtomicBool,
    byte_budget: &mut u64,
    file_budget: &mut usize,
    seen: &mut HashSet<String>,
    report: &mut PrivacyReport,
) {
    if !catalogue::RULES
        .iter()
        .any(|r| r.browser == profile.browser)
    {
        add_skip(
            report,
            &profile.name,
            Some(PrivacyCategory::Sessions),
            "Session scanning is not yet supported for this browser family.",
        );
        return;
    }
    let inventory = discover(
        profile.browser,
        &profile.root,
        true,
        cancel,
        storage_files::MAX_ENTRIES,
        storage_files::MAX_PATH_BYTES,
        false,
    );
    report.cancelled |= inventory.cancelled;
    report.truncated |= inventory.truncated;
    for reason in inventory.issues {
        add_skip(
            report,
            &profile.name,
            Some(PrivacyCategory::Sessions),
            reason,
        );
    }
    for observed in inventory.files {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            break;
        }
        if *file_budget == 0 || report.records.len() >= MAX_RECORDS {
            report.truncated = true;
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::Sessions),
                "Session file observation limit reached.",
            );
            break;
        }
        if !seen.insert(storage_files::path_key(&observed.path)) {
            continue;
        }
        *file_budget -= 1;
        if unsupported(profile.browser, &profile.root, &observed.path) {
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::Sessions),
                "A declared session text-filter source is not yet supported and was left untouched.",
            );
            continue;
        }
        if let Some((rule, handler, directory)) =
            generic_binding(profile.browser, &profile.root, &observed.path)
        {
            storage_files::scan_session_generic(
                profile,
                &observed,
                rule,
                handler,
                directory,
                cancel,
                byte_budget,
                report,
            );
            continue;
        }
        if observed.stamp.length > *byte_budget {
            report.truncated = true;
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::Sessions),
                "Session content observation budget reached.",
            );
            break;
        }
        *byte_budget -= observed.stamp.length;
        let Some((rule, handler)) = binding(profile.browser, &profile.root, &observed.path) else {
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::Sessions),
                "Session ownership changed during enumeration.",
            );
            continue;
        };
        match preferences::observe_session(
            profile,
            &observed.path,
            &observed.stamp,
            cancel,
            byte_budget,
        ) {
            Ok((review, preferences::SessionDisposition::Trash)) => {
                storage_files::scan_session_file(
                    profile,
                    &observed,
                    rule,
                    handler,
                    &review,
                    cancel,
                    byte_budget,
                    report,
                )
            }
            Ok((review, preferences::SessionDisposition::Rewrite { skipped_windows })) => {
                report.records.push(PrivacyRecord {
                    id: review.id,
                    browser: profile.browser,
                    profile_id: profile.id.clone(),
                    profile_name: profile.name.clone(),
                    category: PrivacyCategory::Sessions,
                    site: "Pinned session data".into(),
                    locator: RecordLocator::Preferences(review),
                });
                if skipped_windows > 0 {
                    add_skip(
                        report,
                        &profile.name,
                        Some(PrivacyCategory::Sessions),
                        "Some session windows have a non-array tabs layout and will be kept unchanged.",
                    );
                }
            }
            Err(reason) => {
                report.cancelled |= cancel.load(Ordering::Relaxed);
                report.truncated |= reason == preferences::SESSION_BUDGET_ERROR;
                add_skip(
                    report,
                    &profile.name,
                    Some(PrivacyCategory::Sessions),
                    &reason,
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "session_files_tests.rs"]
mod tests;
