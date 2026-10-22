//! Whole-file browser storage ownership. LevelDB records have a separate owner;
//! file cleanup never removes database directories.
use super::*;
use crate::domain::{Analysis, Candidate, CategoryResult, CleanupPolicy, CleanupResult};
use sha2::{Digest, Sha256};

pub(super) const MAX_ENTRIES: usize = 20_000;
pub(super) const MAX_PATH_BYTES: usize = 8 * 1024 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
pub(super) const MAX_SCAN_BYTES: u64 = 2 * MAX_FILE_BYTES;
const CHROMIUM_PATTERNS: &[&str] = &[
    "*databases\\http_*_0*",
    "*databases\\https_*_0*",
    "*\\IndexedDB\\http_*.indexeddb.leveldb\\*",
    "*\\IndexedDB\\https_*.indexeddb.leveldb\\*",
    "*\\IndexedDB\\http_*.indexeddb.blob\\*",
    "*\\IndexedDB\\https_*.indexeddb.blob\\*",
];

pub(super) fn path_key(path: &Path) -> String {
    let text = path_identity(path);
    if !cfg!(windows) {
        return text;
    }
    let text = text.replace('/', "\\");
    if let Some(plain) = text.strip_prefix("\\\\?\\") {
        let bytes = plain.as_bytes();
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\'
        {
            return plain.to_owned();
        }
    }
    text
}

#[derive(Clone)]
pub(super) struct Review {
    pub candidate: Candidate,
    browser: Browser,
    profile_root: PathBuf,
    fingerprint: Option<Fingerprint>,
    keep_domains: std::sync::Arc<HashSet<String>>,
    raw_site: String,
    site_valid: bool,
    siblings: Vec<(Candidate, Option<Fingerprint>)>,
    scope: PathBuf,
    directory_scope: bool,
    complete_scope: bool,
    protected_sidecar: bool,
    owner: FileOwner,
    category: PrivacyCategory,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FileOwner {
    StorageDb,
    PathDelete,
    Record {
        rule: &'static str,
        handler: &'static str,
    },
    Session {
        rule: &'static str,
        handler: &'static str,
        generic: bool,
    },
}

#[derive(Clone, Eq, PartialEq)]
struct Fingerprint {
    identity: (u64, u64),
    stamp: FileStamp,
    hash: [u8; 32],
}

impl Review {
    pub(super) fn record_source(&self) -> Option<String> {
        if !matches!(
            self.owner,
            FileOwner::Record { .. } | FileOwner::Session { .. }
        ) {
            return None;
        }
        let grouped = self.directory_scope && matches!(self.owner, FileOwner::Session { .. });
        let parts = named_parts(
            &self.profile_root,
            if grouped {
                &self.scope
            } else {
                &self.candidate.path
            },
        )?;
        let mut source = parts
            .join("/")
            .chars()
            .map(|c| if c.is_control() { '\u{fffd}' } else { c })
            .collect::<String>();
        if grouped {
            source.push('/');
        }
        Some(source)
    }
    #[cfg(test)]
    pub(super) fn record_binding(&self) -> Option<(&'static str, &'static str)> {
        match self.owner {
            FileOwner::Record { rule, handler } => Some((rule, handler)),
            _ => None,
        }
    }
    fn parts(&self) -> impl Iterator<Item = (&Candidate, &Option<Fingerprint>)> {
        std::iter::once((&self.candidate, &self.fingerprint)).chain(
            self.siblings
                .iter()
                .map(|(file, fingerprint)| (file, fingerprint)),
        )
    }
    pub(super) fn item_count(&self) -> usize {
        1 + self.siblings.len()
    }
    pub(super) fn size_bytes(&self) -> u64 {
        self.parts().map(|(file, _)| file.size).sum()
    }
    pub(super) fn all_cleaned(&self, ids: &HashSet<Uuid>) -> bool {
        self.parts().all(|(file, _)| ids.contains(&file.id))
    }
    pub(super) fn partly_cleaned(&self, ids: &HashSet<Uuid>) -> bool {
        self.parts().any(|(file, _)| ids.contains(&file.id)) && !self.all_cleaned(ids)
    }
    pub(super) fn unique_paths(&self, paths: &mut HashSet<String>) -> bool {
        self.parts()
            .all(|(file, _)| paths.insert(path_key(&file.path)))
    }
    pub(super) fn unavailable_reason(&self) -> Option<&'static str> {
        if self.owner == FileOwner::PathDelete && !self.keep_domains.is_empty() {
            Some("These browser files cannot be matched to your kept sites and cannot be cleaned.")
        } else if !self.site_valid {
            Some("This storage file has an unsupported site identity and cannot be cleaned.")
        } else if self.parts().any(|(_, snapshot)| snapshot.is_none()) {
            Some(
                "This storage group could not be fully inspected and cannot be cleaned. Scan again after closing the browser.",
            )
        } else if self.protected_sidecar || !self.complete_scope {
            Some(
                "This storage group includes unavailable, separately owned, or unreviewed database files.",
            )
        } else {
            None
        }
    }

    fn validate(&self, cancel: &AtomicBool) -> Result<(), String> {
        if self.unavailable_reason().is_some()
            || (self.category == PrivacyCategory::Cookies
                && is_cookie_exception(&self.raw_site, &self.keep_domains))
        {
            return Err("The reviewed storage-file policy no longer matches.".into());
        }
        self.validate_membership(&HashSet::new(), cancel)?;
        let mut budget = MAX_SCAN_BYTES;
        for (file, before) in self.parts() {
            self.validate_part(file, before, cancel, &mut budget)?;
        }
        self.validate_membership(&HashSet::new(), cancel)?;
        Ok(())
    }

    fn validate_part(
        &self,
        file: &Candidate,
        before: &Option<Fingerprint>,
        cancel: &AtomicBool,
        budget: &mut u64,
    ) -> Result<(), String> {
        let Some(before) = before else {
            return Err("The storage file has no reviewed content snapshot.".into());
        };
        let same_owner = match self.owner {
            FileOwner::Session {
                rule,
                handler,
                generic,
            } => {
                if generic {
                    session_files::generic_binding(self.browser, &self.profile_root, &file.path)
                        .is_some_and(|(r, h, _)| r == rule && h == handler)
                } else {
                    session_files::binding(self.browser, &self.profile_root, &file.path)
                        == Some((rule, handler))
                }
            }
            FileOwner::Record { rule, handler } => record_files::owns(
                rule,
                handler,
                self.browser,
                self.category,
                &self.profile_root,
                &file.path,
            ),
            _ => file_owner(self.browser, &self.profile_root, &file.path) == Some(self.owner),
        };
        if !same_owner
            || (self.owner == FileOwner::StorageDb
                && site_from_path(&file.path).as_deref() != Some(self.raw_site.as_str()))
            || &fingerprint(&self.profile_root, &file.path, cancel, budget)? != before
        {
            return Err("The storage file changed since its review. Scan again.".into());
        }
        Ok(())
    }

    fn validate_membership(
        &self,
        moved: &HashSet<PathBuf>,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        if self.directory_scope {
            let actual = scope_files(&self.profile_root, &self.scope, cancel)?;
            let expected: HashSet<_> = self
                .parts()
                .filter(|(file, _)| !moved.contains(&file.path))
                .map(|(file, _)| path_key(&file.path))
                .collect();
            if actual != expected {
                return Err("The reviewed storage-group membership changed. Scan again.".into());
            }
        } else if matches!(
            self.owner,
            FileOwner::Record { .. } | FileOwner::Session { .. }
        ) || self
            .scope
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("Extension Cookies"))
            || self
                .scope
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("sqlite"))
        {
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = self.scope.as_os_str().to_owned();
                sidecar.push(suffix);
                match fs::symlink_metadata(PathBuf::from(sidecar)) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err("The storage database has unreviewed sidecar files.".into()),
                }
            }
        }
        Ok(())
    }
}

fn scope_for(profile: &BrowserProfile, path: &Path) -> (PathBuf, bool) {
    if profile.browser.is_chromium() && single_file_key(&profile.root, path) {
        return (path.to_owned(), false);
    }
    if file_owner(profile.browser, &profile.root, path) == Some(FileOwner::PathDelete) {
        return (path.parent().unwrap_or(path).to_owned(), true);
    }
    let Ok(relative) = path.strip_prefix(&profile.root) else {
        return (path.to_owned(), false);
    };
    let parts = relative.components().collect::<Vec<_>>();
    if profile.browser.is_chromium() {
        // A broad WebStorage FileKey can contain several independent origin
        // stores. Bind the matching origin, not its common bucket directory.
        for index in (0..parts.len().saturating_sub(2)).rev() {
            let (Some(parent), Some(origin)) = (
                parts[index].as_os_str().to_str(),
                parts[index + 1].as_os_str().to_str(),
            ) else {
                continue;
            };
            let indexed = parent.eq_ignore_ascii_case("IndexedDB")
                && [
                    "http_*.indexeddb.leveldb",
                    "https_*.indexeddb.leveldb",
                    "http_*.indexeddb.blob",
                    "https_*.indexeddb.blob",
                ]
                .iter()
                .any(|pattern| matches_pattern(origin, pattern));
            let database = parent.eq_ignore_ascii_case("databases")
                && ["http_*_0*", "https_*_0*"]
                    .iter()
                    .any(|pattern| matches_pattern(origin, pattern));
            if indexed || database {
                let scope = parts[..index + 2]
                    .iter()
                    .fold(profile.root.clone(), |p, c| p.join(c));
                return (scope, true);
            }
        }
    }
    (path.to_owned(), false)
}

// Enumerate names only; file contents are independently bound to reviewed hashes.
// A group never gains authority over new entries, redirects, or another owner.
fn scope_files(root: &Path, scope: &Path, cancel: &AtomicBool) -> Result<HashSet<String>, String> {
    let mut pending = vec![(scope.to_owned(), 0usize)];
    let mut files = HashSet::new();
    let mut entries = 0usize;
    let mut bytes = 0usize;
    while let Some((directory, depth)) = pending.pop() {
        if cancel.load(Ordering::Relaxed) {
            return Err("Storage-group inspection stopped.".into());
        }
        if !contains_named_path(root, &directory) || safe_profile_root(&directory).is_err() {
            return Err("A storage-group directory is redirected or unavailable.".into());
        }
        for child in fs::read_dir(&directory).map_err(|_| "A storage group could not be read.")? {
            if cancel.load(Ordering::Relaxed) {
                return Err("Storage-group inspection stopped.".into());
            }
            entries += 1;
            let path = child
                .map_err(|_| "A storage-group entry could not be read.")?
                .path();
            bytes = bytes.saturating_add(path.as_os_str().len());
            if entries > MAX_ENTRIES || bytes > MAX_PATH_BYTES {
                return Err("Storage-group inspection limit reached.".into());
            }
            let meta =
                fs::symlink_metadata(&path).map_err(|_| "A storage-group entry is unavailable.")?;
            if is_link(&meta) {
                return Err("A storage-group entry is linked.".into());
            }
            if meta.is_dir() {
                if depth >= MAX_DEPTH {
                    return Err("Storage-group depth limit reached.".into());
                }
                pending.push((path, depth + 1));
            } else if meta.is_file() {
                files.insert(path_key(&path));
            } else {
                return Err("A storage-group entry has an unsupported type.".into());
            }
        }
    }
    Ok(files)
}

pub(super) fn group_records(
    profile: &BrowserProfile,
    report: &mut PrivacyReport,
    cancel: &AtomicBool,
) {
    let mut groups = std::collections::BTreeMap::<PathBuf, PrivacyRecord>::new();
    let records = std::mem::take(&mut report.records);
    for record in records {
        let RecordLocator::File(file) = &record.locator else {
            report.records.push(record);
            continue;
        };
        if record.browser != profile.browser || record.profile_id != profile.id {
            report.records.push(record);
            continue;
        }
        if let Some(first) = groups.get_mut(&file.scope) {
            let RecordLocator::File(target) = &mut first.locator else {
                unreachable!()
            };
            target.site_valid &=
                file.site_valid && target.raw_site == file.raw_site && target.owner == file.owner;
            target.protected_sidecar |= file.protected_sidecar;
            target
                .siblings
                .push((file.candidate.clone(), file.fingerprint.clone()));
        } else {
            groups.insert(file.scope.clone(), record);
        }
    }
    for mut record in groups.into_values() {
        let RecordLocator::File(file) = &mut record.locator else {
            unreachable!()
        };
        file.complete_scope = !cancel.load(Ordering::Relaxed)
            && file.validate_membership(&HashSet::new(), cancel).is_ok();
        if file.category == PrivacyCategory::Sessions
            && !file.complete_scope
            && !cancel.load(Ordering::Relaxed)
        {
            add_skip(
                report,
                &record.profile_name,
                Some(PrivacyCategory::Sessions),
                "A session file group contains unavailable or separately owned members.",
            );
        }
        if !file.site_valid {
            record.site = "Unsupported storage site".into();
        }
        report.records.push(record);
    }
}

#[derive(Default)]
pub(super) struct Inventory {
    pub files: Vec<ObservedFile>,
    pub leveldb_dirs: Vec<PathBuf>,
    pub databases: Vec<DatabaseTarget>,
    pub issues: Vec<&'static str>,
    pub entries: usize,
    pub path_bytes: usize,
    pub truncated: bool,
    pub cancelled: bool,
}

pub(super) struct ObservedFile {
    pub path: PathBuf,
    pub stamp: FileStamp,
}

impl Inventory {
    fn issue(&mut self, text: &'static str) {
        if !self.issues.contains(&text) {
            self.issues.push(text);
        }
    }
}

fn metadata_kinds(browser: Browser, name: &str) -> &'static [TableKind] {
    if browser.is_chromium() {
        if name.eq_ignore_ascii_case("Databases.db") {
            &[TableKind::ChromiumWebSql]
        } else if name.eq_ignore_ascii_case("cookies")
            || name.eq_ignore_ascii_case("Extension Cookies")
        {
            &[TableKind::ChromiumCookies]
        } else if name.eq_ignore_ascii_case("Origin Bound Certs") {
            &[
                TableKind::ChromiumOriginCerts,
                TableKind::ChromiumChannelIds,
            ]
        } else if name.eq_ignore_ascii_case("QuotaManager") {
            &[TableKind::ChromiumQuota]
        } else {
            &[]
        }
    } else if name.eq_ignore_ascii_case("cookies.sqlite") {
        &[TableKind::FirefoxCookies]
    } else if name.eq_ignore_ascii_case("permissions.sqlite") {
        &[TableKind::FirefoxOfflinePermissions]
    } else if name.eq_ignore_ascii_case("webappsstore.sqlite") {
        &[TableKind::FirefoxWebApps, TableKind::FirefoxWebApps2]
    } else {
        &[]
    }
}

pub(super) fn matches_pattern(text: &str, pattern: &str) -> bool {
    #[cfg(windows)]
    {
        use windows::{Win32::UI::Shell::PathMatchSpecW, core::PCWSTR};
        let text: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        let pattern: Vec<u16> = pattern.encode_utf16().chain(Some(0)).collect();
        unsafe { PathMatchSpecW(PCWSTR(text.as_ptr()), PCWSTR(pattern.as_ptr())).as_bool() }
    }
    #[cfg(not(windows))]
    crate::browser_cache::wildcard(pattern, text)
}

pub(super) fn named_parts<'a>(root: &Path, path: &'a Path) -> Option<Vec<&'a str>> {
    if !contains_named_path(root, path) {
        return None;
    }
    path.components()
        .skip(root.components().count())
        .map(|part| match part {
            std::path::Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect()
}

fn chromium_scope(root: &Path, path: &Path) -> bool {
    let Some(parts) = named_parts(root, path) else {
        return false;
    };
    single_file_key(root, path)
        || parts.len() >= 2
            && ["databases", "IndexedDB", "WebStorage"]
                .iter()
                .any(|base| parts[0].eq_ignore_ascii_case(base))
        || parts.len() == 3
            && parts[0].eq_ignore_ascii_case("Local Storage")
            && parts[1].eq_ignore_ascii_case("leveldb")
            && parts[2].eq_ignore_ascii_case("LOCK")
}

fn single_file_key(root: &Path, path: &Path) -> bool {
    CHROMIUM_COOKIE_DATABASES
        .iter()
        .any(|name| same_named_path(&root.join(name), path))
        || CHROMIUM_SITE_DATABASES
            .iter()
            .any(|(name, _)| same_named_path(&root.join(name), path))
        || same_named_path(&root.join("Local Storage/leveldb/LOCK"), path)
}

pub(super) fn owns_leveldb_lock(browser: Browser, root: &Path, path: &Path) -> bool {
    if !browser.is_chromium() || !contains_named_path(root, path) || !chromium_scope(root, path) {
        return false;
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Some(text) = path.to_str() else {
        return false;
    };
    // Earlier full-path StorageDBs descriptors win even in WebStorage or an
    // unusual profile path. LOCK is never claimed by both effect owners.
    matches_pattern(name, "LOCK")
        && !matches_pattern(&text.replace('/', "\\"), "*\\WebStorage\\*")
        && !CHROMIUM_PATTERNS
            .iter()
            .any(|p| matches_pattern(&text.replace('/', "\\"), p))
}

pub(super) fn owns_file(browser: Browser, root: &Path, path: &Path) -> bool {
    file_owner(browser, root, path).is_some()
}

fn file_owner(browser: Browser, root: &Path, path: &Path) -> Option<FileOwner> {
    let parts = named_parts(root, path)?;
    let Some(name) = parts.last() else {
        return None;
    };
    if !metadata_kinds(browser, name).is_empty()
        && !(browser.is_chromium() && name.eq_ignore_ascii_case("Extension Cookies"))
    {
        return None;
    }
    let Some(text) = path.to_str() else {
        return None;
    };
    let text = text.replace('/', "\\");
    if browser.is_chromium() {
        // Earlier OnFile3/4 consume these names, even below a broad storage root.
        if matches_pattern(name, "*.localstorage") || matches_pattern(name, "*.indexeddb") {
            return None;
        }
        if !chromium_scope(root, path) {
            return None;
        }
        if CHROMIUM_PATTERNS
            .iter()
            .any(|pattern| matches_pattern(&text, pattern))
        {
            Some(FileOwner::StorageDb)
        } else if matches_pattern(&text, "*\\WebStorage\\*") {
            Some(FileOwner::PathDelete)
        } else {
            None
        }
    } else {
        // Mozilla variables name profile *containers*. BrowserProfile already
        // resolves their child profile, consuming the FileKey's `\*` component.
        let old_indexed = parts.len() >= 2 && parts[0].eq_ignore_ascii_case("indexedDB");
        let storage = parts.len() >= 3
            && parts[0].eq_ignore_ascii_case("storage")
            && ["persistent", "permanent", "default", "temporary"]
                .iter()
                .any(|kind| parts[1].eq_ignore_ascii_case(kind));
        ((old_indexed || storage) && matches_pattern(&text, "*\\indexedDB\\*.sqlite"))
            .then_some(FileOwner::StorageDb)
    }
}

fn site_from_text(text: &str) -> String {
    let text = text.split('\0').next().unwrap_or_default();
    let start = text
        .find("http_")
        .map(|at| at + 5)
        .or_else(|| text.find("https_").map(|at| at + 6));
    let Some((start, end)) = start.zip(text.rfind("_0")) else {
        return String::new();
    };
    // Native unsigned subtraction clamps to the remainder if _0 precedes start.
    if end < start {
        text[start..].to_owned()
    } else {
        text[start..end].to_owned()
    }
}

fn site_from_path(path: &Path) -> Option<String> {
    path.to_str().map(|s| site_from_text(&s.replace('/', "\\")))
}

pub(super) fn discover_paths(
    browser: Browser,
    root: &Path,
    cancel: &AtomicBool,
    entries: usize,
    bytes: usize,
) -> Inventory {
    walk_roots(browser, root, cancel, entries, bytes, false)
}

pub(super) fn discover_witness_paths(
    browser: Browser,
    root: &Path,
    cancel: &AtomicBool,
    entries: usize,
    bytes: usize,
) -> Inventory {
    walk_roots(browser, root, cancel, entries, bytes, true)
}

fn walk_roots(
    browser: Browser,
    root: &Path,
    cancel: &AtomicBool,
    entries: usize,
    bytes: usize,
    witness_only: bool,
) -> Inventory {
    let mut out = Inventory::default();
    if cancel.load(Ordering::Relaxed) {
        out.cancelled = true;
        return out;
    }
    if safe_profile_root(root).is_err() {
        out.issue("Site-storage profile is linked, invalid, or unavailable.");
        return out;
    }
    if browser.is_chromium() {
        // Direct FileKeys participate in the same descriptor chain as recursive
        // matches. An ancestor may make Extension Cookies a file-owned target.
        for name in CHROMIUM_COOKIE_DATABASES {
            let path = root.join(name);
            if !owns_file(browser, root, &path) {
                continue;
            }
            if cancel.load(Ordering::Relaxed) {
                out.cancelled = true;
                return out;
            }
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(meta) => {
                    out.entries += 1;
                    out.path_bytes = out.path_bytes.saturating_add(path.as_os_str().len());
                    if out.entries > entries || out.path_bytes > bytes {
                        out.truncated = true;
                        out.issue("Site-storage path inspection limit reached.");
                        return out;
                    }
                    if is_link(&meta) || !meta.is_file() {
                        out.issue("A direct browser-storage file is linked or unavailable.");
                    } else {
                        out.files.push(ObservedFile {
                            path,
                            stamp: FileStamp {
                                length: meta.len(),
                                modified_ns: meta.modified().ok().map(timestamp).unwrap_or(0),
                                created_ns: meta.created().ok().map(timestamp),
                            },
                        });
                    }
                }
                Err(_) => out.issue("A direct browser-storage file could not be inspected."),
            }
        }
    }
    let roots = if browser.is_chromium() {
        vec![
            (root.join("databases"), true),
            (root.join("IndexedDB"), true),
            (root.join("WebStorage"), true),
            (root.join("Local Storage/leveldb"), false),
        ]
    } else if witness_only {
        // Recursive named metadata is not a profile-root witness: otherwise a
        // Profiles container adopts all of its descendant profiles' records.
        vec![
            (root.join("indexedDB"), true),
            (root.join("storage/persistent"), true),
            (root.join("storage/permanent"), true),
            (root.join("storage/default"), true),
            (root.join("storage/temporary"), true),
        ]
    } else {
        vec![(root.to_owned(), true)]
    };
    let mut pending = Vec::new();
    for (base, recursive) in roots {
        match fs::symlink_metadata(&base) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(meta) if !is_link(&meta) && meta.is_dir() => pending.push((base, 0usize, recursive)),
            _ => out.issue("A site-storage directory is linked, invalid, or unavailable."),
        }
    }
    'walk: while let Some((directory, depth, recursive)) = pending.pop() {
        if cancel.load(Ordering::Relaxed) {
            out.cancelled = true;
            break;
        }
        if safe_profile_root(&directory).is_err() {
            out.issue("A site-storage directory is redirected or unavailable.");
            continue;
        }
        let children = match fs::read_dir(&directory) {
            Ok(v) => v,
            Err(_) => {
                out.issue("Site-storage directory entries could not be read.");
                continue;
            }
        };
        for child in children {
            if cancel.load(Ordering::Relaxed) {
                out.cancelled = true;
                break 'walk;
            }
            out.entries += 1;
            if out.entries > entries {
                out.truncated = true;
                out.issue("Site-storage path inspection limit reached.");
                break 'walk;
            }
            let child = match child {
                Ok(v) => v,
                Err(_) => {
                    out.issue("A site-storage entry could not be read.");
                    continue;
                }
            };
            let path = child.path();
            out.path_bytes = out.path_bytes.saturating_add(path.as_os_str().len());
            if out.path_bytes > bytes {
                out.truncated = true;
                out.issue("Site-storage path inspection limit reached.");
                break 'walk;
            }
            if !recursive
                && !path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| matches_pattern(n, "LOCK"))
            {
                continue;
            }
            // Windows enumeration carries this metadata, even when a reader
            // cannot open the payload. Content snapshots are separate authority.
            let meta = match child.metadata() {
                Ok(v) => v,
                Err(_) => {
                    out.issue("A site-storage path could not be inspected.");
                    continue;
                }
            };
            if path.to_str().is_none() {
                out.issue("A site-storage path encoding is unsupported.");
            } else if is_link(&meta) {
                out.issue("A linked site-storage path was not followed.");
            } else if meta.is_dir() {
                if !recursive {
                    continue;
                }
                if depth >= MAX_DEPTH {
                    out.truncated = true;
                    out.issue("Site-storage directory depth limit reached.");
                } else {
                    pending.push((path, depth + 1, true));
                }
            } else if meta.is_file() {
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    out.issue("A site-storage filename is not supported.");
                    continue;
                };
                let kinds = metadata_kinds(browser, name);
                let owned_file = owns_file(browser, root, &path);
                if !kinds.is_empty() && !owned_file {
                    for kind in kinds {
                        out.databases.push(DatabaseTarget {
                            path: path.clone(),
                            kind: *kind,
                        });
                    }
                } else if owned_file {
                    out.files.push(ObservedFile {
                        path,
                        stamp: FileStamp {
                            length: meta.len(),
                            modified_ns: meta.modified().ok().map(timestamp).unwrap_or(0),
                            created_ns: meta.created().ok().map(timestamp),
                        },
                    });
                } else if owns_leveldb_lock(browser, root, &path) {
                    out.leveldb_dirs.push(directory.clone());
                }
            }
        }
    }
    out.files.sort_by_key(|file| path_key(&file.path));
    out.files.dedup_by(|a, b| same_named_path(&a.path, &b.path));
    out.leveldb_dirs.sort_by_key(|path| path_key(path));
    out.leveldb_dirs.dedup_by(|a, b| same_named_path(a, b));
    out
}

pub(super) fn open_file(root: &Path, path: &Path) -> Result<File, String> {
    validate_database_path(root, path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
    }
    let file = options
        .open(path)
        .map_err(|_| "A storage file could not be opened read-only.".to_owned())?;
    let meta = file
        .metadata()
        .map_err(|_| "A storage-file handle could not be inspected.".to_owned())?;
    if is_link(&meta) || !meta.is_file() {
        return Err("A storage-file handle is linked or is not a regular file.".into());
    }
    Ok(file)
}

pub(super) fn identity(file: &File) -> Result<(u64, u64), String> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
            .map_err(|_| "Storage-file identity could not be read.".to_owned())?;
        if info.nNumberOfLinks != 1 {
            return Err("Storage-file hard-link ownership is ambiguous.".into());
        }
        Ok((
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if meta.nlink() != 1 {
            return Err("Storage-file hard-link ownership is ambiguous.".into());
        }
        Ok((meta.dev(), meta.ino()))
    }
    #[cfg(not(any(windows, unix)))]
    Err("Storage-file identities are unsupported on this platform.".into())
}

fn fingerprint(
    root: &Path,
    path: &Path,
    cancel: &AtomicBool,
    budget: &mut u64,
) -> Result<Fingerprint, String> {
    let mut file = open_file(root, path)?;
    let id = identity(&file)?;
    let before = file_stamp(path)?;
    if before.length > MAX_FILE_BYTES || before.length > *budget {
        return Err("Site-storage content inspection limit reached.".into());
    }
    let mut hash = Sha256::new();
    let mut read = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("Site-storage inspection stopped.".into());
        }
        let count = file
            .read(&mut buffer)
            .map_err(|_| "Storage-file contents could not be read.".to_owned())?;
        if count == 0 {
            break;
        }
        read = read.saturating_add(count as u64);
        if read > before.length || count as u64 > *budget {
            return Err("Storage file changed or exceeded its inspection limit.".into());
        }
        *budget -= count as u64;
        hash.update(&buffer[..count]);
    }
    if read != before.length
        || file_stamp(path)? != before
        || identity(&open_file(root, path)?)? != id
    {
        return Err("Storage file changed during inventory.".into());
    }
    Ok(Fingerprint {
        identity: id,
        stamp: before,
        hash: hash.finalize().into(),
    })
}

pub(super) fn scan_file(
    profile: &BrowserProfile,
    observed_file: &ObservedFile,
    keep_domains: &std::sync::Arc<HashSet<String>>,
    cancel: &AtomicBool,
    budget: &mut u64,
    report: &mut PrivacyReport,
) {
    let Some(owner) = file_owner(profile.browser, &profile.root, &observed_file.path) else {
        return;
    };
    append_file_record(
        profile,
        observed_file,
        PrivacyCategory::Cookies,
        owner,
        keep_domains,
        cancel,
        budget,
        report,
    );
}

pub(super) fn scan_record_file(
    profile: &BrowserProfile,
    observed: &ObservedFile,
    category: PrivacyCategory,
    rule: &'static str,
    handler: &'static str,
    keeps: &std::sync::Arc<HashSet<String>>,
    cancel: &AtomicBool,
    budget: &mut u64,
    report: &mut PrivacyReport,
) {
    append_file_record(
        profile,
        observed,
        category,
        FileOwner::Record { rule, handler },
        keeps,
        cancel,
        budget,
        report,
    );
}
pub(super) fn scan_session_file(
    profile: &BrowserProfile,
    observed: &ObservedFile,
    rule: &'static str,
    handler: &'static str,
    proof: &preferences::Review,
    cancel: &AtomicBool,
    budget: &mut u64,
    report: &mut PrivacyReport,
) {
    let start = report.records.len();
    append_file_record(
        profile,
        observed,
        PrivacyCategory::Sessions,
        FileOwner::Session {
            rule,
            handler,
            generic: false,
        },
        &Default::default(),
        cancel,
        budget,
        report,
    );
    if report.records.len() == start {
        return;
    }
    let valid = match &report.records[start].locator {
        RecordLocator::File(file) => file
            .fingerprint
            .as_ref()
            .is_some_and(|p| proof.matches_snapshot(p.identity, &p.stamp, &p.hash)),
        _ => false,
    };
    if !valid {
        report.records.truncate(start);
        add_skip(
            report,
            &profile.name,
            Some(PrivacyCategory::Sessions),
            "Session changed between classification and file review.",
        );
    }
}
pub(super) fn scan_session_generic(
    profile: &BrowserProfile,
    observed: &ObservedFile,
    rule: &'static str,
    handler: &'static str,
    directory: bool,
    cancel: &AtomicBool,
    budget: &mut u64,
    report: &mut PrivacyReport,
) {
    let start = report.records.len();
    append_file_record(
        profile,
        observed,
        PrivacyCategory::Sessions,
        FileOwner::Session {
            rule,
            handler,
            generic: true,
        },
        &Default::default(),
        cancel,
        budget,
        report,
    );
    if let Some(PrivacyRecord {
        locator: RecordLocator::File(file),
        ..
    }) = report.records.get_mut(start)
    {
        (file.scope, file.directory_scope) =
            session_files::generic_scope(&profile.root, &observed.path, directory);
    }
}

fn append_file_record(
    profile: &BrowserProfile,
    observed_file: &ObservedFile,
    category: PrivacyCategory,
    owner: FileOwner,
    keep_domains: &std::sync::Arc<HashSet<String>>,
    cancel: &AtomicBool,
    budget: &mut u64,
    report: &mut PrivacyReport,
) {
    let path = &observed_file.path;
    if report.records.len() >= MAX_RECORDS {
        report.truncated = true;
        return;
    }
    let Some(raw_site) = (if owner != FileOwner::StorageDb {
        Some(String::new())
    } else {
        site_from_path(path)
    }) else {
        add_skip(
            report,
            &profile.name,
            Some(category),
            "A storage-file path is unsupported.",
        );
        return;
    };
    if owner == FileOwner::StorageDb && raw_site.is_empty() {
        return;
    }
    if category == PrivacyCategory::Cookies && is_cookie_exception(&raw_site, keep_domains) {
        report.cookie_exempted += 1;
        return;
    }
    let (stamp, observed) = match fingerprint(&profile.root, path, cancel, budget) {
        Ok(v) => (v.stamp.clone(), Some(v)),
        Err(reason) => {
            report.cancelled |= cancel.load(Ordering::Relaxed);
            add_skip(report, &profile.name, Some(category), &reason);
            if report.cancelled {
                return;
            }
            (observed_file.stamp.clone(), None)
        }
    };
    let id = Uuid::new_v4();
    let site = if owner != FileOwner::StorageDb {
        Some(
            match category {
                PrivacyCategory::History => "Browser history file",
                PrivacyCategory::Downloads => "Download history file",
                PrivacyCategory::Cookies => "Browser site data",
                PrivacyCategory::Sessions => "Browser session file",
                PrivacyCategory::LastDownloadLocation | PrivacyCategory::SnapLocation => {
                    "Browser location data"
                }
                PrivacyCategory::SavedPasswords => "Saved passwords file",
                PrivacyCategory::SitePreferences => "Site security file",
                PrivacyCategory::SavedForms => "Browser database table",
            }
            .to_owned(),
        )
    } else {
        normalize_cookie_domain(&raw_site).ok()
    };
    let candidate = Candidate {
        id,
        path: path.to_owned(),
        root: profile.root.clone(),
        size: stamp.length,
        modified_ns: stamp.modified_ns,
        created_ns: stamp.created_ns,
    };
    let (scope, directory_scope) =
        if matches!(owner, FileOwner::Record { .. } | FileOwner::Session { .. }) {
            (path.to_owned(), false)
        } else {
            scope_for(profile, path)
        };
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let protected_sidecar = ["-wal", "-shm", "-journal"]
        .iter()
        .filter_map(|suffix| name.strip_suffix(suffix))
        .any(|base| {
            matches!(owner, FileOwner::Record { .. } | FileOwner::Session { .. })
                || !metadata_kinds(profile.browser, base).is_empty()
        });
    report.records.push(PrivacyRecord {
        id,
        browser: profile.browser,
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        category,
        site: site
            .clone()
            .unwrap_or_else(|| "Unsupported storage site".into()),
        locator: RecordLocator::File(Review {
            candidate,
            browser: profile.browser,
            profile_root: profile.root.clone(),
            fingerprint: observed,
            keep_domains: keep_domains.clone(),
            raw_site,
            site_valid: site.is_some(),
            siblings: Vec::new(),
            scope,
            directory_scope,
            complete_scope: false,
            protected_sidecar,
            owner,
            category,
        }),
    });
}

fn stopped(runtime: &impl BrowserRuntime, files: &[Review]) -> Result<(), String> {
    let running = runtime.running_browsers()?;
    if files.iter().any(|file| {
        running
            .iter()
            .any(|process| file.browser.conflicts_with(process))
    }) {
        return Err("Close the selected browser before cleaning site-storage files.".into());
    }
    Ok(())
}

pub(super) fn preflight(runtime: &impl BrowserRuntime, files: &[Review]) -> Result<(), String> {
    if files.is_empty() {
        return Ok(());
    }
    stopped(runtime, files)
}

struct GuardedTrash<'a, R, T> {
    runtime: &'a R,
    trash: &'a mut T,
    files: &'a [Review],
    data_dir: &'a Path,
    moved: HashSet<PathBuf>,
    started: HashSet<Uuid>,
    cancel: &'a AtomicBool,
}
impl<R: BrowserRuntime, T: crate::cleanup::TrashPort> GuardedTrash<'_, R, T> {
    fn check(&mut self, paths: &[&Path]) -> Result<(), String> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err("Storage-file cleanup stopped.".into());
        }
        stopped(self.runtime, self.files)?;
        if self
            .files
            .iter()
            .any(|f| f.category == PrivacyCategory::Cookies)
        {
            let settings = load_cookie_exception_settings(self.data_dir)?;
            let current = settings
                .keep_domains
                .iter()
                .map(|d| normalize_cookie_domain(d))
                .collect::<Result<HashSet<_>, _>>()?;
            if self.files.iter().any(|file| {
                file.category == PrivacyCategory::Cookies && file.keep_domains.as_ref() != &current
            }) {
                return Err(
                    "Saved cookie exceptions changed after this storage review. Scan again.".into(),
                );
            }
        }
        let session_paths = self
            .files
            .iter()
            .filter(|group| {
                matches!(group.owner, FileOwner::Session { .. })
                    && group
                        .parts()
                        .any(|(file, _)| paths.contains(&file.path.as_path()))
            })
            .map(|g| g.candidate.path.as_path())
            .collect::<Vec<_>>();
        if !session_paths.is_empty() {
            preferences::blocked_paths(self.data_dir, session_paths, None)?;
        }
        for group in self.files.iter().filter(|group| {
            group
                .parts()
                .any(|(file, _)| paths.contains(&file.path.as_path()))
        }) {
            if !self.started.contains(&group.candidate.id) {
                group.validate_membership(&self.moved, self.cancel)?;
                self.started.insert(group.candidate.id);
            }
        }
        Ok(())
    }
}
impl<R: BrowserRuntime, T: crate::cleanup::TrashPort> crate::cleanup::TrashPort
    for GuardedTrash<'_, R, T>
{
    fn batch_size(&self) -> usize {
        self.trash.batch_size()
    }
    fn move_to_trash(&mut self, path: &Path) -> Result<(), String> {
        self.check(&[path])?;
        self.trash.move_to_trash(path)?;
        self.moved.insert(path.to_owned());
        Ok(())
    }
    fn move_batch_to_trash(&mut self, paths: &[&Path]) -> Result<(), String> {
        self.check(paths)?;
        self.trash.move_batch_to_trash(paths)?;
        self.moved
            .extend(paths.iter().map(|path| path.to_path_buf()));
        Ok(())
    }
}

pub(super) fn clean(
    data_dir: &Path,
    report_id: Uuid,
    files: &[Review],
    runtime: &impl BrowserRuntime,
    trash: &mut impl crate::cleanup::TrashPort,
    cancel: &AtomicBool,
    progress: impl FnMut(usize, usize),
) -> Result<CleanupResult, String> {
    preflight(runtime, files)?;
    let session_paths = files
        .iter()
        .filter(|f| matches!(f.owner, FileOwner::Session { .. }))
        .map(|f| f.candidate.path.as_path())
        .collect::<Vec<_>>();
    if !session_paths.is_empty() {
        preferences::blocked_paths(data_dir, session_paths.iter().copied(), None)?;
        let pending = preferences::session_trash_pending(data_dir)?;
        if files
            .iter()
            .filter(|f| matches!(f.owner, FileOwner::Session { .. }))
            .any(|f| {
                pending.contains(&path_key(&f.candidate.path))
                    || (f.directory_scope
                        && pending.iter().any(|p| {
                            p.starts_with(
                                &(path_key(&f.scope).trim_end_matches(['\\', '/']).to_owned()
                                    + if cfg!(windows) { "\\" } else { "/" }),
                            )
                        }))
            })
        {
            return Err(
                "An unresolved file move blocks session cleanup and automatic replay.".into(),
            );
        }
    }
    let analysis = Analysis {
        id: report_id,
        date: String::new(),
        minimum_age_days: 0,
        cleanup_policy: CleanupPolicy::CustomCleanRules,
        elapsed_ms: 0,
        cancelled: false,
        categories: vec![CategoryResult {
            id: "browser-privacy-files".into(),
            name: "Browser privacy files".into(),
            group: "Applications".into(),
            files: files
                .iter()
                .flat_map(|group| group.parts().map(|(file, _)| file.clone()))
                .collect(),
            skipped: 0,
            available: true,
            truncated: false,
        }],
    };
    let ids = files
        .iter()
        .flat_map(|group| group.parts().map(|(file, _)| file.id))
        .collect::<Vec<_>>();
    let by_id: HashMap<_, _> = files
        .iter()
        .flat_map(|group| {
            group
                .parts()
                .map(move |(file, before)| (file.id, (group, file, before)))
        })
        .collect();
    let mut validated = HashMap::<Uuid, Result<(), String>>::new();
    let mut journal = crate::store::DeferredJournal::new(data_dir, Uuid::new_v4());
    let mut guarded = GuardedTrash {
        runtime,
        trash,
        files,
        data_dir,
        moved: HashSet::new(),
        started: HashSet::new(),
        cancel,
    };
    crate::cleanup::clean_with_validator(
        &analysis,
        &ids,
        cancel,
        &mut guarded,
        &mut journal,
        progress,
        |candidate| {
            let (group, file, before) = by_id
                .get(&candidate.id)
                .ok_or_else(|| "Unknown storage-file review ID.".to_owned())?;
            validated
                .entry(group.candidate.id)
                .or_insert_with(|| group.validate(cancel))
                .clone()?;
            let mut budget = MAX_FILE_BYTES;
            group.validate_part(file, before, cancel, &mut budget)
        },
    )
}

/// Synthetic render-only state. No discovery, file open, or cleanup is performed.
#[cfg(debug_assertions)]
pub(super) fn preview(profile: &BrowserProfile, available: bool) -> PrivacyRecord {
    let id =
        Uuid::from_u128(0x4443_4c45_414e_4552_4649_4c45_0000_0001 + if available { 0 } else { 16 });
    let site = if available {
        "example.test"
    } else {
        "blocked.test"
    };
    let scope = profile
        .root
        .join(format!("IndexedDB/https_{site}_0.indexeddb.leveldb"));
    let stamp = FileStamp {
        length: 512,
        modified_ns: 0,
        created_ns: None,
    };
    let candidate = Candidate {
        id,
        path: scope.join("000003.log"),
        root: profile.root.clone(),
        size: 512,
        modified_ns: 0,
        created_ns: None,
    };
    let fingerprint = available.then_some(Fingerprint {
        identity: (0, 1),
        stamp,
        hash: [0; 32],
    });
    let siblings = if available {
        let mut next = candidate.clone();
        next.id = Uuid::from_u128(id.as_u128() + 1);
        next.path = scope.join("MANIFEST-1");
        vec![(next, fingerprint.clone())]
    } else {
        Vec::new()
    };
    PrivacyRecord {
        id,
        browser: profile.browser,
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        category: PrivacyCategory::Cookies,
        site: site.into(),
        locator: RecordLocator::File(Review {
            candidate,
            browser: profile.browser,
            profile_root: profile.root.clone(),
            fingerprint,
            keep_domains: std::sync::Arc::new(HashSet::new()),
            raw_site: site.into(),
            site_valid: true,
            siblings,
            scope,
            directory_scope: true,
            complete_scope: available,
            protected_sidecar: false,
            owner: FileOwner::StorageDb,
            category: PrivacyCategory::Cookies,
        }),
    }
}

#[cfg(debug_assertions)]
pub(super) fn preview_record(
    profile: &BrowserProfile,
    category: PrivacyCategory,
    name: &str,
    id: Uuid,
    available: bool,
) -> PrivacyRecord {
    let mut record = preview(profile, available);
    let RecordLocator::File(file) = &mut record.locator else {
        unreachable!()
    };
    file.candidate.path = profile.root.join(name);
    file.candidate.id = id;
    let (rule, handler) = record_files::binding(
        profile.browser,
        category,
        &profile.root,
        &file.candidate.path,
    )
    .expect("declared synthetic record rule");
    file.owner = FileOwner::Record { rule, handler };
    file.category = category;
    file.raw_site.clear();
    file.siblings.clear();
    file.scope = file.candidate.path.clone();
    file.directory_scope = false;
    record.id = id;
    record.category = category;
    record.site = if category == PrivacyCategory::History {
        "Browser history file"
    } else {
        "Download history file"
    }
    .into();
    record
}
#[cfg(debug_assertions)]
pub(super) fn preview_session(profile: &BrowserProfile) -> PrivacyRecord {
    let mut record = preview(profile, true);
    let RecordLocator::File(file) = &mut record.locator else {
        unreachable!()
    };
    file.candidate.path = profile.root.join("Current Session");
    file.candidate.id = Uuid::from_u128(0x44434c45414e45525345535300000002);
    let (rule, handler) =
        session_files::binding(profile.browser, &profile.root, &file.candidate.path).unwrap();
    file.owner = FileOwner::Session {
        rule,
        handler,
        generic: false,
    };
    file.category = PrivacyCategory::Sessions;
    file.raw_site.clear();
    file.siblings.clear();
    file.scope = file.candidate.path.clone();
    file.directory_scope = false;
    record.id = file.candidate.id;
    record.category = PrivacyCategory::Sessions;
    record.site = "Browser session file".into();
    record
}
#[cfg(debug_assertions)]
pub(super) fn preview_session_group(profile: &BrowserProfile) -> PrivacyRecord {
    let mut record = preview_session(profile);
    let RecordLocator::File(file) = &mut record.locator else {
        unreachable!()
    };
    file.candidate.id = Uuid::from_u128(0x44434c45414e45525345535300000003);
    file.candidate.path = profile.root.join("Session Storage/LOG");
    let (rule, handler, _) =
        session_files::generic_binding(profile.browser, &profile.root, &file.candidate.path)
            .unwrap();
    file.owner = FileOwner::Session {
        rule,
        handler,
        generic: true,
    };
    file.scope = profile.root.join("Session Storage");
    file.directory_scope = true;
    for (n, name) in ["CURRENT", "000001.log"].into_iter().enumerate() {
        let mut candidate = file.candidate.clone();
        candidate.id = Uuid::from_u128(0x44434c45414e45525345535300000004 + n as u128);
        candidate.path = file.scope.join(name);
        file.siblings.push((candidate, file.fingerprint.clone()));
    }
    record.id = file.candidate.id;
    record.site = "Session storage files".into();
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cleanup::TrashPort, store::JournalEvent};
    use std::sync::atomic::AtomicUsize;

    struct EmptyRuntime;
    impl BrowserRuntime for EmptyRuntime {
        fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
            Ok(Vec::new())
        }
    }
    struct StartsLater(AtomicUsize);
    impl BrowserRuntime for StartsLater {
        fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
            Ok(if self.0.fetch_add(1, Ordering::Relaxed) >= 3 {
                vec![RunningBrowser {
                    browser: Browser::Chrome,
                    pid: 123,
                    executable: "chrome.exe".into(),
                }]
            } else {
                Vec::new()
            })
        }
    }
    struct OwnedTrash {
        destination: PathBuf,
        data_dir: PathBuf,
        moved: Vec<PathBuf>,
        calls: usize,
        fail_after: Option<usize>,
    }
    impl OwnedTrash {
        fn new(root: &Path) -> Self {
            Self {
                destination: root.join("owned-trash"),
                data_dir: root.join("data"),
                moved: Vec::new(),
                calls: 0,
                fail_after: None,
            }
        }
        fn move_one(&mut self, path: &Path) -> Result<(), String> {
            let durable: Vec<JournalEvent> = fs::read_dir(self.data_dir.join("operations"))
                .unwrap()
                .flat_map(|entry| {
                    fs::read_to_string(entry.unwrap().path())
                        .unwrap()
                        .lines()
                        .map(|line| serde_json::from_str(line).unwrap())
                        .collect::<Vec<_>>()
                })
                .collect();
            assert!(durable.iter().any(|event| matches!(event, JournalEvent::Intent { path: intended, .. } if intended==path)),
                "An effect cannot precede its on-disk intent.");
            fs::create_dir_all(&self.destination).map_err(|e| e.to_string())?;
            fs::rename(path, self.destination.join(Uuid::new_v4().to_string()))
                .map_err(|e| e.to_string())?;
            self.moved.push(path.to_owned());
            if self.fail_after == Some(self.moved.len()) {
                return Err("Owned aggregate error after a partial effect.".into());
            }
            Ok(())
        }
    }
    impl TrashPort for OwnedTrash {
        fn batch_size(&self) -> usize {
            32
        }
        fn move_to_trash(&mut self, path: &Path) -> Result<(), String> {
            self.calls += 1;
            self.move_one(path)
        }
        fn move_batch_to_trash(&mut self, paths: &[&Path]) -> Result<(), String> {
            self.calls += 1;
            for path in paths {
                self.move_one(path)?;
            }
            Ok(())
        }
    }
    fn profile(root: &Path, browser: Browser) -> BrowserProfile {
        fs::create_dir_all(root).unwrap();
        BrowserProfile {
            id: "owned-storage".into(),
            browser,
            name: "Owned storage fixture".into(),
            root: root.to_owned(),
        }
    }
    fn write(root: &Path, relative: &str, payload: &[u8]) -> PathBuf {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, payload).unwrap();
        path
    }
    fn scan(profile: &BrowserProfile) -> PrivacyReport {
        scan_profiles_with_settings(
            std::slice::from_ref(profile),
            &[PrivacyCategory::Cookies],
            &Default::default(),
            &AtomicBool::new(false),
            |_| {},
        )
    }

    fn cookie_database(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let db = Connection::open(path).unwrap();
        db.execute_batch("CREATE TABLE cookies(host_key TEXT,name TEXT,path TEXT,expires_utc INTEGER,creation_utc INTEGER,last_access_utc INTEGER,encrypted_value BLOB);
            INSERT INTO cookies VALUES('one.test','first','/',0,1,1,X'00'),('two.test','second','/',0,1,1,X'01');").unwrap();
    }

    #[test]
    fn all_chromium_direct_cookie_filekeys_obey_ancestor_matches_without_duplicate_sql_rows() {
        let dir = tempfile::tempdir().unwrap();
        for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
            for (layout, file_owned) in [
                ("ordinary", false),
                ("WebStorage", true),
                ("IndexedDB/https_example.test_0.indexeddb.leveldb", true),
                ("databases/https_example.test_0", true),
            ] {
                let p = profile(
                    &dir.path()
                        .join(browser.cache_category())
                        .join(layout)
                        .join("Profile"),
                    browser,
                );
                let early = p.root.join("Cookies");
                let late = p.root.join("Extension Cookies");
                cookie_database(&early);
                cookie_database(&late);
                let before = [
                    (fs::read(&early).unwrap(), file_stamp(&early).unwrap()),
                    (fs::read(&late).unwrap(), file_stamp(&late).unwrap()),
                ];
                let report = scan(&p);
                assert!(
                    !report.partial,
                    "{browser:?} {layout}: {:?}",
                    report.skipped
                );
                let file_count = report
                    .records
                    .iter()
                    .filter(|r| matches!(r.locator, RecordLocator::File(_)))
                    .count();
                let rows = report
                    .records
                    .iter()
                    .filter(|r| matches!(r.locator, RecordLocator::Database(_)))
                    .count();
                assert_eq!(
                    (file_count, rows),
                    (usize::from(file_owned), if file_owned { 2 } else { 4 }),
                    "{browser:?} {layout}"
                );
                assert!(report.records.iter().all(PrivacyRecord::actionable));
                for (path, (bytes, stamp)) in [&early, &late].into_iter().zip(before) {
                    assert_eq!(fs::read(path).unwrap(), bytes);
                    assert_eq!(file_stamp(path).unwrap(), stamp);
                }
            }
        }
    }

    #[test]
    #[cfg(windows)]
    fn direct_file_cleanup_does_not_require_or_touch_unrelated_profile_members() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("WebStorage/Profile"), Browser::Chrome);
        let early = p.root.join("Cookies");
        let late = p.root.join("Extension Cookies");
        cookie_database(&early);
        cookie_database(&late);
        let before = fs::read(&early).unwrap();
        let unrelated = write(&p.root, "unrelated", b"preserved");
        let report = scan(&p);
        let selected = report
            .records
            .iter()
            .find(|r| matches!(r.locator, RecordLocator::File(_)))
            .unwrap();
        assert_eq!(selected.item_count(), 1);
        let plan = build_cleanup_plan(&report, &[selected.id]).unwrap();
        let mut trash = OwnedTrash::new(dir.path());
        let receipt = execute(dir.path(), &plan, &mut trash);
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (1, 0),
            "{:?}",
            receipt.errors
        );
        assert!(!late.exists());
        assert_eq!(trash.moved, vec![late]);
        assert_eq!(fs::read(early).unwrap(), before);
        assert_eq!(fs::read(unrelated).unwrap(), b"preserved");
    }

    #[test]
    #[cfg(windows)]
    fn equivalent_windows_profile_spellings_share_one_canonical_direct_file_review() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("WebStorage/Profile"), Browser::Chrome);
        let path = p.root.join("Extension Cookies");
        cookie_database(&path);
        let canonical = dunce::canonicalize(&p.root).unwrap();
        let profiles = [
            BrowserProfile {
                root: canonical.clone(),
                ..p.clone()
            },
            BrowserProfile {
                root: PathBuf::from(canonical.to_string_lossy().replace('\\', "/")),
                ..p.clone()
            },
            BrowserProfile {
                root: PathBuf::from(format!("\\\\?\\{}", canonical.display())),
                ..p.clone()
            },
        ];
        let report = scan_profiles_with_settings(
            &profiles,
            &[PrivacyCategory::Cookies],
            &Default::default(),
            &AtomicBool::new(false),
            |_| {},
        );
        assert_eq!(report.profiles_scanned, 1);
        assert_eq!(report.records.len(), 1);
        let RecordLocator::File(file) = &report.records[0].locator else {
            panic!("wrong owner")
        };
        assert_eq!(file.candidate.path, canonical.join("Extension Cookies"));
        let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
        let mut trash = OwnedTrash::new(dir.path());
        let receipt = execute(dir.path(), &plan, &mut trash);
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (1, 0),
            "{:?}",
            receipt.errors
        );
        assert!(!path.exists());
        assert_eq!(trash.moved.len(), 1);
    }

    #[test]
    fn direct_file_sql_sidecars_and_discovery_limits_never_gain_cleanup_authority() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("WebStorage/Profile"), Browser::Chrome);
        let late = p.root.join("Extension Cookies");
        cookie_database(&late);
        fs::write(
            p.root.join("Extension Cookies-wal"),
            b"owned unreviewed state",
        )
        .unwrap();
        let report = scan(&p);
        assert_eq!(report.records.len(), 1);
        assert!(!report.records[0].actionable());
        assert!(build_cleanup_plan(&report, &[report.records[0].id]).is_err());
        for (entries, bytes) in [(0, MAX_PATH_BYTES), (MAX_ENTRIES, 0)] {
            let inventory =
                discover_paths(p.browser, &p.root, &AtomicBool::new(false), entries, bytes);
            assert!(inventory.truncated && inventory.files.is_empty());
        }
        assert!(
            discover_paths(
                p.browser,
                &p.root,
                &AtomicBool::new(true),
                MAX_ENTRIES,
                MAX_PATH_BYTES
            )
            .cancelled
        );
        assert!(late.exists());
    }

    #[test]
    #[cfg(windows)]
    fn old_sql_plan_is_refused_before_journaling_when_an_earlier_file_rule_owns_it() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("ordinary"), Browser::Chrome);
        let path = p.root.join("Extension Cookies");
        cookie_database(&path);
        let mut report = scan(&p);
        let mut plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
        let shadow = profile(&dir.path().join("WebStorage/Profile"), Browser::Chrome);
        let moved = shadow.root.join("Extension Cookies");
        fs::rename(path, &moved).unwrap();
        let before = fs::read(&moved).unwrap();
        for row in &mut plan.records {
            row.profile_root = shadow.root.clone();
            row.database = moved.clone();
        }
        for record in &mut report.records {
            let RecordLocator::Database(row) = &mut record.locator else {
                panic!("wrong fixture owner")
            };
            row.profile_root = shadow.root.clone();
            row.database = moved.clone();
        }
        assert!(
            build_cleanup_plan(&report, &[report.records[0].id])
                .err()
                .unwrap()
                .contains("file-cleanup rule")
        );
        let data = dir.path().join("data");
        let mut trash = OwnedTrash::new(dir.path());
        let error = clean_privacy_with_runtime_and_trash(
            &data,
            &plan,
            &AtomicBool::new(false),
            &EmptyRuntime,
            &mut trash,
            &mut |_, _| {},
        )
        .unwrap_err();
        assert!(error.contains("file-cleanup rule"), "{error}");
        assert!(!data.exists());
        assert_eq!(trash.calls, 0);
        assert_eq!(fs::read(moved).unwrap(), before);
    }

    #[test]
    fn legacy_sql_restore_listing_cannot_offer_a_file_owned_direct_target() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("WebStorage/Profile"), Browser::Chrome);
        let path = p.root.join("Extension Cookies");
        cookie_database(&path);
        let before = fs::read(&path).unwrap();
        let data = dir.path().join("data");
        let id = Uuid::new_v4();
        let mut journal = PrivacyJournal::create(&data, Uuid::new_v4()).unwrap();
        journal
            .append(&PrivacyJournalEvent::Outcome {
                database: dunce::canonicalize(&path).unwrap(),
                backup: data.join("owned-backup.sqlite"),
                deleted_ids: vec![Uuid::new_v4()],
                skipped_ids: vec![],
                committed: true,
                cancelled: false,
                uncertain: false,
                restore_id: Some(id),
                browser: Some(p.browser),
                profile_name: Some(p.name),
                profile_root: Some(PathBuf::from(format!(
                    "\\\\?\\{}",
                    dunce::canonicalize(&p.root).unwrap().display()
                ))),
                categories: vec![],
                post_state_snapshot: Some(data.join("owned-post.sqlite")),
                post_state_stamp: Some(file_stamp(&path).unwrap()),
                schema_signature: Some("owned fixture schema".into()),
                restore_error: None,
            })
            .unwrap();
        drop(journal);
        let options = list_privacy_restore_options(&data).unwrap();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].state, PrivacyRecoveryState::Unavailable);
        assert!(
            options[0]
                .reason
                .as_deref()
                .unwrap()
                .contains("file-cleanup rule")
        );
        assert!(prepare_privacy_restore_with_runtime(&data, id, &EmptyRuntime).is_err());
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn all_chromium_webstorage_pathdelete_rules_count_files_not_leveldb_keys() {
        let dir = tempfile::tempdir().unwrap();
        for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
            let p = profile(&dir.path().join(browser.cache_category()), browser);
            let lock = write(
                &p.root,
                "WebStorage/bucket/store/LOCK",
                b"not a database lock",
            );
            let payload = write(&p.root, "WebStorage/bucket/store/payload", b"fresh bytes");
            write(
                &p.root,
                "WebStorage/bucket/other/payload",
                b"other fresh bytes",
            );
            let report = scan(&p);
            assert_eq!(report.records.len(), 2, "{:?}", report.skipped);
            assert!(!report.partial, "{:?}", report.skipped);
            assert_eq!(
                report
                    .records
                    .iter()
                    .map(PrivacyRecord::item_count)
                    .sum::<usize>(),
                3
            );
            assert!(
                report
                    .records
                    .iter()
                    .all(|r| r.site == "Browser site data" && r.actionable() == cfg!(windows))
            );
            assert!(report.records.iter().all(
                |r| matches!(&r.locator, RecordLocator::File(f) if f.owner==FileOwner::PathDelete)
            ));
            assert_eq!(fs::read(lock).unwrap(), b"not a database lock");
            assert_eq!(fs::read(payload).unwrap(), b"fresh bytes");
        }
    }

    #[test]
    fn recursive_extension_cookie_names_obey_late_descriptor_order() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(dir.path(), Browser::Chrome);
        let web = write(
            &p.root,
            "WebStorage/bucket/store/Extension Cookies",
            b"owned file",
        );
        let indexed = write(
            &p.root,
            "IndexedDB/https_example.test_0.indexeddb.leveldb/Extension Cookies",
            b"owned file",
        );
        let late = write(
            &p.root,
            "IndexedDB/extension/Extension Cookies",
            b"owned metadata",
        );
        let early = write(
            &p.root,
            "WebStorage/bucket/store/cookies",
            b"owned metadata",
        );
        let inventory = discover_paths(
            p.browser,
            &p.root,
            &AtomicBool::new(false),
            MAX_ENTRIES,
            MAX_PATH_BYTES,
        );
        let files: HashSet<_> = inventory.files.iter().map(|f| path_key(&f.path)).collect();
        let databases: HashSet<_> = inventory
            .databases
            .iter()
            .map(|d| path_key(&d.path))
            .collect();
        assert_eq!(files, HashSet::from([path_key(&web), path_key(&indexed)]));
        assert_eq!(
            databases,
            HashSet::from([path_key(&late), path_key(&early)])
        );
    }

    #[test]
    #[cfg(windows)]
    fn webstorage_exact_group_cleanup_preserves_other_groups_and_kept_site_policy() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(dir.path(), Browser::Chrome);
        let first = write(&p.root, "WebStorage/bucket/store/LOCK", b"owned lock bytes");
        let second = write(&p.root, "WebStorage/bucket/store/data", b"owned data bytes");
        let other = write(&p.root, "WebStorage/bucket/other/data", b"untouched bytes");
        let report = scan(&p);
        let selected = report.records.iter().find(|r| r.item_count() == 2).unwrap();
        let plan = build_cleanup_plan(&report, &[selected.id]).unwrap();
        let mut trash = OwnedTrash::new(dir.path());
        let receipt = execute(dir.path(), &plan, &mut trash);
        assert_eq!(
            (receipt.deleted, receipt.skipped),
            (1, 0),
            "{:?}",
            receipt.errors
        );
        assert!(!first.exists() && !second.exists());
        assert_eq!(trash.moved.len(), 2);
        assert_eq!(fs::read(&other).unwrap(), b"untouched bytes");
        assert!(p.root.join("WebStorage/bucket/store").is_dir());
        let report = scan_profiles_with_settings(
            std::slice::from_ref(&p),
            &[PrivacyCategory::Cookies],
            &CookieExceptionSettings {
                schema: COOKIE_SETTINGS_SCHEMA,
                keep_domains: vec!["keep.test".into()],
                keep_signed_in: false,
            },
            &AtomicBool::new(false),
            |_| {},
        );
        assert_eq!(report.records.len(), 1);
        assert!(!report.records[0].actionable());
        assert!(build_cleanup_plan(&report, &[report.records[0].id]).is_err());
        assert_eq!(fs::read(other).unwrap(), b"untouched bytes");
    }
    fn execute(root: &Path, plan: &PrivacyPlan, trash: &mut OwnedTrash) -> PrivacyReceipt {
        clean_privacy_with_runtime_and_trash(
            &root.join("data"),
            plan,
            &AtomicBool::new(false),
            &EmptyRuntime,
            trash,
            &mut |_, _| {},
        )
        .unwrap()
    }
    fn journal_events(root: &Path) -> Vec<JournalEvent> {
        let path = fs::read_dir(root.join("data/operations"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn all_thirteen_chromium_families_scan_the_six_shipped_file_patterns_without_age_filter_or_scan_writes()
     {
        for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
            let dir = tempfile::tempdir().unwrap();
            let p = profile(&dir.path().join("profile"), browser);
            let paths = [
                "databases/http_one.test_0/1",
                "databases/https_two.test_0/2",
                "IndexedDB/http_three.test_0.indexeddb.leveldb/000003.log",
                "IndexedDB/https_four.test_0.indexeddb.leveldb/MANIFEST-1",
                "IndexedDB/http_five.test_0.indexeddb.blob/1",
                "IndexedDB/https_six.test_0.indexeddb.blob/2",
            ];
            let files = paths
                .iter()
                .map(|path| write(&p.root, path, b"fresh owned content"))
                .collect::<Vec<_>>();
            let before = files
                .iter()
                .map(|path| (fs::read(path).unwrap(), file_stamp(path).unwrap()))
                .collect::<Vec<_>>();
            let report = scan(&p);
            assert!(!report.partial, "{browser:?}: {:?}", report.skipped);
            assert_eq!(report.records.len(), 6);
            assert_eq!(
                report
                    .records
                    .iter()
                    .map(PrivacyRecord::item_count)
                    .sum::<usize>(),
                6
            );
            assert!(
                report
                    .records
                    .iter()
                    .all(|r| r.actionable() && r.browser == browser && r.size_bytes() == Some(19))
            );
            for (path, (bytes, stamp)) in files.iter().zip(before) {
                assert_eq!(fs::read(path).unwrap(), bytes);
                assert_eq!(file_stamp(path).unwrap(), stamp);
            }
            assert!(!dir.path().join("data").exists());
        }
    }

    #[test]
    fn earlier_metadata_and_super_handlers_never_acquire_whole_file_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("profile"), Browser::Chrome);
        let database = write(&p.root, "databases/http_site.test_0/Databases.db", b"");
        let db = Connection::open(&database).unwrap();
        db.execute_batch("CREATE TABLE Databases(id INTEGER PRIMARY KEY,origin TEXT,name TEXT,description TEXT,estimated_size INTEGER);
            INSERT INTO Databases VALUES(1,'https_sql.test_0','owned','description',1);").unwrap();
        drop(db);
        let cookies = write(
            &p.root,
            "IndexedDB/https_site.test_0.indexeddb.leveldb/cookies",
            b"",
        );
        let db = Connection::open(&cookies).unwrap();
        db.execute_batch("CREATE TABLE cookies(host_key TEXT,name TEXT,path TEXT,expires_utc INTEGER,creation_utc INTEGER,last_access_utc INTEGER,encrypted_value BLOB);
            INSERT INTO cookies VALUES('cookie.test','name','/',0,1,1,X'00');").unwrap();
        drop(db);
        write(
            &p.root,
            "IndexedDB/https_site.test_0.indexeddb.leveldb/unused.localstorage",
            b"native Super skip",
        );
        write(
            &p.root,
            "IndexedDB/https_site.test_0.indexeddb.leveldb/unused.indexeddb",
            b"native Super skip",
        );
        let file = write(&p.root, "databases/http_file.test_0/1", b"file");
        let report = scan(&p);
        assert!(!report.partial, "{:?}", report.skipped);
        assert_eq!(report.records.len(), 3);
        assert_eq!(
            report
                .records
                .iter()
                .filter(|r| r.size_bytes().is_some())
                .count(),
            1
        );
        let ids = report.records.iter().map(|r| r.id).collect::<Vec<_>>();
        let plan = build_cleanup_plan(&report, &ids).unwrap();
        let mut trash = OwnedTrash::new(dir.path());
        let receipt = execute(dir.path(), &plan, &mut trash);
        assert_eq!(
            (receipt.selected, receipt.deleted, receipt.skipped),
            (3, 3, 0)
        );
        assert_eq!(trash.moved, vec![file]);
        assert!(database.exists() && cookies.exists());
        assert_eq!(
            Connection::open(database)
                .unwrap()
                .query_row("SELECT COUNT(*) FROM Databases", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn mozilla_filekey_scopes_and_recursive_metadata_are_applied_before_storage_matching() {
        for browser in [Browser::Firefox, Browser::Thunderbird] {
            let dir = tempfile::tempdir().unwrap();
            let p = profile(&dir.path().join("profile"), browser);
            write(&p.root, "indexedDB/https_one.test_0.sqlite", b"one");
            write(
                &p.root,
                "storage/default/origin/indexedDB/http_two.test_0.sqlite",
                b"two",
            );
            write(
                &p.root,
                "child/indexedDB/http_not-in-filekey.test_0.sqlite",
                b"not selected",
            );
            write(
                &p.root,
                "indexedDB/http_journal.test_0.sqlite-journal",
                b"not selected",
            );
            write(
                &p.root,
                "wrong/nested/indexedDB/http_not-in-filekey.test_0.sqlite",
                b"not selected",
            );
            let dbpath = write(&p.root, "a/b/c/cookies.sqlite", b"");
            let db = Connection::open(&dbpath).unwrap();
            db.execute_batch("CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY,host TEXT,name TEXT,path TEXT,expiry INTEGER,creationTime INTEGER,lastAccessed INTEGER,value TEXT);
                INSERT INTO moz_cookies VALUES(1,'sql.test','name','/',0,1,1,'private');").unwrap();
            drop(db);
            let report = scan(&p);
            assert!(!report.partial, "{:?}", report.skipped);
            assert_eq!(report.records.len(), 3);
            assert_eq!(
                report
                    .records
                    .iter()
                    .filter(|r| r.size_bytes().is_some())
                    .count(),
                2
            );
            assert!(report.records.iter().all(PrivacyRecord::actionable));
        }
    }

    #[test]
    fn exact_review_ids_and_content_hash_reject_same_size_same_timestamp_drift() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("profile"), Browser::Chrome);
        let a = write(&p.root, "databases/http_a.test_0/1", b"aaaa");
        let b = write(&p.root, "databases/http_b.test_0/2", b"bbbb");
        let report = scan(&p);
        let id = report
            .records
            .iter()
            .find(|r| r.site == "a.test")
            .unwrap()
            .id;
        assert!(build_cleanup_plan(&report, &[Uuid::new_v4()]).is_err());
        let plan = build_cleanup_plan(&report, &[id, id]).unwrap();
        assert_eq!(plan.file_count(), 1);
        let old = fs::metadata(&a).unwrap();
        fs::write(&a, b"cccc").unwrap();
        filetime::set_file_mtime(&a, filetime::FileTime::from_last_modification_time(&old))
            .unwrap();
        let mut trash = OwnedTrash::new(dir.path());
        let receipt = execute(dir.path(), &plan, &mut trash);
        assert_eq!(
            (receipt.selected, receipt.deleted, receipt.skipped),
            (1, 0, 1)
        );
        assert_eq!(trash.calls, 0);
        assert_eq!(fs::read(a).unwrap(), b"cccc");
        assert_eq!(fs::read(b).unwrap(), b"bbbb");
        let events = journal_events(dir.path());
        assert!(matches!(events[1], JournalEvent::Intent { .. }));
        assert!(matches!(&events[2], JournalEvent::Outcome { outcome } if !outcome.success));
    }

    #[test]
    fn selected_file_moves_only_after_durable_intent_and_unselected_file_stays() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("profile"), Browser::Edge);
        let a = write(&p.root, "databases/http_a.test_0/1", b"a");
        let b = write(&p.root, "databases/http_b.test_0/2", b"b");
        let report = scan(&p);
        let id = report
            .records
            .iter()
            .find(|r| r.site == "a.test")
            .unwrap()
            .id;
        let plan = build_cleanup_plan(&report, &[id]).unwrap();
        let mut trash = OwnedTrash::new(dir.path());
        let receipt = execute(dir.path(), &plan, &mut trash);
        assert_eq!(
            (receipt.selected, receipt.deleted, receipt.skipped),
            (1, 1, 0)
        );
        assert!(!receipt.uncertain);
        assert!(!a.exists() && b.exists());
        assert_eq!(trash.moved, vec![a]);
        let events = journal_events(dir.path());
        assert!(matches!(events[1], JournalEvent::Intent { file_id, .. } if file_id==id));
        assert!(
            matches!(&events[2], JournalEvent::Outcome { outcome } if outcome.file_id==id && outcome.success)
        );
        assert!(matches!(
            events[3],
            JournalEvent::Finish { cancelled: false }
        ));
        let history = crate::store::history(&dir.path().join("data")).unwrap();
        assert_eq!(history[0].files, 1);
    }

    #[test]
    fn partial_native_batch_error_preserves_uncertainty_without_retry_or_success_counts() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("profile"), Browser::Chrome);
        let a = write(&p.root, "databases/http_a.test_0/1", b"a");
        let b = write(&p.root, "databases/http_b.test_0/2", b"b");
        let report = scan(&p);
        let ids = report.records.iter().map(|r| r.id).collect::<Vec<_>>();
        let plan = build_cleanup_plan(&report, &ids).unwrap();
        let mut trash = OwnedTrash::new(dir.path());
        trash.fail_after = Some(1);
        let receipt = execute(dir.path(), &plan, &mut trash);
        assert!(receipt.uncertain);
        assert_eq!(receipt.deleted, 0);
        assert_eq!(trash.calls, 1);
        assert_eq!(trash.moved.len(), 1);
        assert_ne!(a.exists(), b.exists());
        let events = journal_events(dir.path());
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, JournalEvent::Intent { .. }))
                .count(),
            2
        );
        assert!(!events.iter().any(|e| matches!(
            e,
            JournalEvent::Outcome { .. } | JournalEvent::Finish { .. }
        )));
        let history = crate::store::history(&dir.path().join("data")).unwrap();
        assert!(history[0].interrupted);
        assert_eq!(history[0].uncertain.len(), 2);
    }

    #[test]
    fn browser_restart_and_saved_exception_drift_prevent_effects() {
        for change_settings in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let p = profile(&dir.path().join("profile"), Browser::Chrome);
            let path = write(&p.root, "databases/http_a.test_0/1", b"owned");
            let report = scan(&p);
            let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
            let mut trash = OwnedTrash::new(dir.path());
            let data = dir.path().join("data");
            if change_settings {
                save_cookie_exception_settings(&data, &["a.test".into()]).unwrap();
            }
            let runtime = StartsLater(AtomicUsize::new(if change_settings {
                usize::MAX / 2
            } else {
                0
            }));
            let receipt = if change_settings {
                execute(dir.path(), &plan, &mut trash)
            } else {
                clean_privacy_with_runtime_and_trash(
                    &data,
                    &plan,
                    &AtomicBool::new(false),
                    &runtime,
                    &mut trash,
                    &mut |_, _| {},
                )
                .unwrap()
            };
            assert!(receipt.uncertain);
            assert_eq!(receipt.deleted, 0);
            assert!(path.exists());
            assert_eq!(trash.calls, 0);
        }
    }

    #[test]
    fn keep_policy_native_empty_sites_and_unrepresentable_raw_sites_stay_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("profile"), Browser::Chrome);
        write(&p.root, "databases/http_keep.test_0/1", b"keep");
        write(
            &p.root,
            "IndexedDB/HTTP_upper.test_0.indexeddb.leveldb/1",
            b"native empty site",
        );
        write(
            &p.root,
            "IndexedDB/https_missing.test_443.indexeddb.leveldb/1",
            b"native empty site",
        );
        write(
            &p.root,
            "IndexedDB/http_odd.test_0.indexeddb.leveldb/filename_0.log",
            b"raw path site",
        );
        let mut settings = CookieExceptionSettings::default();
        settings.keep_domains.push("keep.test".into());
        let report = scan_profiles_with_settings(
            &[p],
            &[PrivacyCategory::Cookies],
            &settings,
            &AtomicBool::new(false),
            |_| {},
        );
        assert!(!report.partial);
        assert_eq!(report.cookie_exempted, 1);
        assert_eq!(report.records.len(), 1);
        assert!(!report.records[0].actionable());
        assert!(build_cleanup_plan(&report, &[report.records[0].id]).is_err());
        assert_eq!(report.records[0].site, "Unsupported storage site");
        assert_eq!(
            site_from_text(r"C:\_0\http_example.sqlite"),
            "example.sqlite"
        );
        assert_eq!(site_from_text(r"C:\http_a_0\data\file_0"), r"a_0\data\file");
    }

    #[test]
    fn cancellation_journal_failure_and_hardlinks_never_gain_effect_authority() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("profile"), Browser::Chrome);
        let path = write(&p.root, "databases/http_a.test_0/1", b"owned");
        let report = scan(&p);
        let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
        let mut trash = OwnedTrash::new(dir.path());
        let receipt = clean_privacy_with_runtime_and_trash(
            &dir.path().join("cancel"),
            &plan,
            &AtomicBool::new(true),
            &EmptyRuntime,
            &mut trash,
            &mut |_, _| {},
        )
        .unwrap();
        assert!(receipt.cancelled);
        assert_eq!(trash.calls, 0);
        let blocked = dir.path().join("file-instead-of-data-directory");
        fs::write(&blocked, b"owned").unwrap();
        assert!(
            clean_privacy_with_runtime_and_trash(
                &blocked,
                &plan,
                &AtomicBool::new(false),
                &EmptyRuntime,
                &mut trash,
                &mut |_, _| {}
            )
            .is_err()
        );
        assert!(path.exists());
        assert_eq!(trash.calls, 0);
        fs::hard_link(&path, dir.path().join("owned-alias")).unwrap();
        let report = scan(&p);
        assert!(report.partial && report.records.len() == 1 && !report.records[0].actionable());
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.reason.contains("hard-link"))
        );
    }

    #[test]
    fn storage_only_profile_witnesses_and_history_only_scans_use_the_right_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Google/Chrome/User Data/Default");
        let p = profile(&root, Browser::Chrome);
        write(&root, "databases/http_a.test_0/1", b"owned");
        let inventory = profile_discovery::reference_profiles(|_| Some(dir.path().to_owned()));
        assert!(
            inventory
                .profiles
                .iter()
                .any(|p| p.browser == Browser::Chrome && same_named_path(&p.root, &root))
        );
        let report = scan_profiles_with_settings(
            &[p],
            &[PrivacyCategory::History],
            &Default::default(),
            &AtomicBool::new(false),
            |_| {},
        );
        assert!(!report.partial && report.records.is_empty());
        let limited = discover_paths(
            Browser::Chrome,
            &root,
            &AtomicBool::new(false),
            0,
            MAX_PATH_BYTES,
        );
        assert!(limited.truncated && limited.files.is_empty());
        let limited = discover_paths(
            Browser::Chrome,
            &root,
            &AtomicBool::new(false),
            MAX_ENTRIES,
            0,
        );
        assert!(limited.truncated && limited.files.is_empty());
        let stopped = discover_paths(
            Browser::Chrome,
            &root,
            &AtomicBool::new(true),
            MAX_ENTRIES,
            MAX_PATH_BYTES,
        );
        assert!(stopped.cancelled && stopped.files.is_empty());
        for (browser, relative) in [
            (Browser::Firefox, "Mozilla/Firefox/Profiles/Storage Only"),
            (Browser::Thunderbird, "Thunderbird/Profiles/Storage Only"),
        ] {
            let root = dir.path().join(relative);
            let p = profile(&root, browser);
            write(&root, "indexedDB/https_only.test_0.sqlite", b"owned");
            let inventory = profile_discovery::reference_profiles(|_| Some(dir.path().to_owned()));
            assert!(
                inventory
                    .profiles
                    .iter()
                    .any(|profile| profile.browser == browser
                        && same_named_path(&profile.root, &root))
            );
            assert!(
                !inventory
                    .profiles
                    .iter()
                    .any(|profile| same_named_path(&profile.root, root.parent().unwrap()))
            );
            let report = scan(&p);
            assert!(!report.partial && report.records.len() == 1 && report.records[0].actionable());
        }
    }

    #[test]
    fn origin_groups_bind_every_file_and_preserve_candidate_counts_without_partial_authority() {
        for drift in ["none", "contents", "membership"] {
            let dir = tempfile::tempdir().unwrap();
            let p = profile(&dir.path().join("profile"), Browser::Chrome);
            let a = write(
                &p.root,
                "IndexedDB/https_a.test_0.indexeddb.leveldb/000003.log",
                b"a",
            );
            let b = write(
                &p.root,
                "IndexedDB/https_a.test_0.indexeddb.leveldb/MANIFEST-1",
                b"b",
            );
            let report = scan(&p);
            assert_eq!(report.records.len(), 1);
            assert_eq!(report.records[0].item_count(), 2);
            assert_eq!(report.records[0].size_bytes(), Some(2));
            assert!(report.records[0].actionable());
            let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
            assert_eq!(plan.file_count(), 2);
            if drift == "contents" {
                fs::write(&b, b"changed").unwrap();
            }
            if drift == "membership" {
                write(
                    &p.root,
                    "IndexedDB/https_a.test_0.indexeddb.leveldb/000004.log",
                    b"new",
                );
            }
            let mut trash = OwnedTrash::new(dir.path());
            let mut observed_progress = Vec::new();
            let receipt = clean_privacy_with_runtime_and_trash(
                &dir.path().join("data"),
                &plan,
                &AtomicBool::new(false),
                &EmptyRuntime,
                &mut trash,
                &mut |done, total| {
                    assert!(done <= total);
                    observed_progress.push((done, total));
                },
            )
            .unwrap();
            assert_eq!(receipt.selected, 1);
            if drift == "none" {
                assert_eq!(receipt.deleted, 1);
                assert_eq!(trash.moved.len(), 2);
                assert!(!a.exists() && !b.exists());
                assert_eq!(observed_progress.last(), Some(&(1, 1)));
            } else {
                assert_eq!(receipt.deleted, 0);
                assert_eq!(receipt.skipped, 1);
                assert!(a.exists() && b.exists());
                assert_eq!(trash.calls, 0);
            }
        }
    }

    #[test]
    fn sql_sidecars_and_unreviewed_sqlite_sidecars_never_become_payload_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("profile"), Browser::Chrome);
        write(
            &p.root,
            "databases/http_a.test_0/cookies-wal",
            b"unreviewed SQL rows",
        );
        let report = scan(&p);
        assert_eq!(report.records.len(), 1);
        assert!(!report.records[0].actionable());
        let p = profile(&dir.path().join("mozilla"), Browser::Firefox);
        write(&p.root, "indexedDB/https_a.test_0.sqlite", b"owned main DB");
        write(
            &p.root,
            "indexedDB/https_a.test_0.sqlite-wal",
            b"unreviewed WAL",
        );
        let report = scan(&p);
        assert_eq!(report.records.len(), 1);
        assert!(!report.records[0].actionable());
        assert_eq!(report.records[0].item_count(), 1);
    }

    #[test]
    fn large_origin_groups_use_bounded_batches_and_one_logical_success_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("profile"), Browser::Chrome);
        for i in 0..40 {
            write(
                &p.root,
                &format!("IndexedDB/https_a.test_0.indexeddb.leveldb/{i:06}.log"),
                b"owned",
            );
        }
        let report = scan(&p);
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].item_count(), 40);
        let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
        let mut trash = OwnedTrash::new(dir.path());
        let receipt = execute(dir.path(), &plan, &mut trash);
        assert_eq!(
            (receipt.selected, receipt.deleted, receipt.skipped),
            (1, 1, 0)
        );
        assert_eq!(trash.calls, 2);
        assert_eq!(trash.moved.len(), 40);
        let history = crate::store::history(&dir.path().join("data")).unwrap();
        assert_eq!(history[0].files, 40);
        assert!(!history[0].interrupted);
    }

    #[test]
    fn replacement_identity_and_content_budget_are_checked_before_effects() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("profile"), Browser::Chrome);
        let path = write(&p.root, "databases/http_a.test_0/1", b"owned");
        let report = scan(&p);
        let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
        let RecordLocator::File(before) = &report.records[0].locator else {
            unreachable!()
        };
        let old_meta = fs::metadata(&path).unwrap();
        fs::rename(&path, dir.path().join("original-owned-file")).unwrap();
        fs::write(&path, b"owned").unwrap();
        filetime::set_file_mtime(
            &path,
            filetime::FileTime::from_last_modification_time(&old_meta),
        )
        .unwrap();
        let mut budget = MAX_FILE_BYTES;
        let after = fingerprint(&p.root, &path, &AtomicBool::new(false), &mut budget).unwrap();
        assert_eq!(before.fingerprint.as_ref().unwrap().hash, after.hash);
        assert_ne!(
            before.fingerprint.as_ref().unwrap().identity,
            after.identity
        );
        assert!(fingerprint(&p.root, &path, &AtomicBool::new(false), &mut 0).is_err());
        let mut trash = OwnedTrash::new(dir.path());
        let receipt = execute(dir.path(), &plan, &mut trash);
        assert_eq!((receipt.deleted, receipt.skipped), (0, 1));
        assert_eq!(trash.calls, 0);
        assert!(path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn redirected_origin_directory_is_not_followed_by_scan_or_cleanup() {
        use std::os::windows::process::CommandExt;
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("profile"), Browser::Chrome);
        let path = write(
            &p.root,
            "IndexedDB/https_a.test_0.indexeddb.leveldb/000001.log",
            b"owned",
        );
        let report = scan(&p);
        let plan = build_cleanup_plan(&report, &[report.records[0].id]).unwrap();
        let origin = path.parent().unwrap().components().collect::<PathBuf>();
        let original = dir.path().join("original-owned-origin");
        fs::rename(&origin, &original).unwrap();
        let outside = dir.path().join("outside-owned-origin");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("000001.log"), b"outside").unwrap();
        let run = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&origin)
            .arg(&outside)
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "Owned junction setup failed: {} {}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        let mut trash = OwnedTrash::new(dir.path());
        let receipt = execute(dir.path(), &plan, &mut trash);
        assert_eq!((receipt.deleted, receipt.skipped), (0, 1));
        assert_eq!(trash.calls, 0);
        let linked = scan(&p);
        assert!(linked.partial && linked.records.is_empty());
        assert_eq!(fs::read(outside.join("000001.log")).unwrap(), b"outside");
        assert!(origin.starts_with(&p.root) && is_link(&fs::symlink_metadata(&origin).unwrap()));
        fs::remove_dir(&origin).unwrap(); // Only the owned junction, never its target.
    }

    #[cfg(windows)]
    #[test]
    fn equivalent_drive_spellings_do_not_double_count_file_candidates_across_profile_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("profile"), Browser::Chrome);
        write(&p.root, "databases/http_a.test_0/1", b"owned");
        let mut other = p.clone();
        other.id = "owned-alias".into();
        other.browser = Browser::Edge;
        other.root = PathBuf::from(format!("\\\\?\\{}", p.root.display()));
        let report = scan_profiles_with_settings(
            &[p, other],
            &[PrivacyCategory::Cookies],
            &Default::default(),
            &AtomicBool::new(false),
            |_| {},
        );
        assert!(!report.partial, "{:?}", report.skipped);
        assert_eq!(report.records.len(), 1);
    }

    #[test]
    fn enumerated_file_counts_survive_unavailable_contents_without_gaining_effect_authority() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile(&dir.path().join("profile"), Browser::Chrome);
        let path = write(&p.root, "databases/http_a.test_0/1", b"owned");
        let mut report = scan_profiles_with_settings(
            std::slice::from_ref(&p),
            &[],
            &Default::default(),
            &AtomicBool::new(false),
            |_| {},
        );
        let observed = ObservedFile {
            stamp: file_stamp(&path).unwrap(),
            path: path.clone(),
        };
        scan_file(
            &p,
            &observed,
            &std::sync::Arc::new(HashSet::new()),
            &AtomicBool::new(false),
            &mut 0,
            &mut report,
        );
        group_records(&p, &mut report, &AtomicBool::new(false));
        assert_eq!(report.skipped_count, 1);
        assert_eq!(report.records.len(), 1);
        assert_eq!(
            (
                report.records[0].item_count(),
                report.records[0].size_bytes()
            ),
            (1, Some(5))
        );
        assert!(!report.records[0].actionable());
        assert!(build_cleanup_plan(&report, &[report.records[0].id]).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"owned");
        assert!(!dir.path().join("data").exists());
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let lock = OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&path)
                .unwrap();
            let locked = scan(&p);
            assert!(
                locked.partial && locked.records.len() == 1,
                "{:?}",
                locked.skipped
            );
            assert_eq!(locked.records[0].size_bytes(), Some(5));
            assert!(!locked.records[0].actionable());
            assert!(build_cleanup_plan(&locked, &[locked.records[0].id]).is_err());
            drop(lock);
        }
    }
}
