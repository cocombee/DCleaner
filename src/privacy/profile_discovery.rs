//! Bounded profile discovery over the reference's declared folder patterns.
//! Browser identities here identify rule/adapter families, not executable or
//! product attribution for every compatible browser stored under a family.
use super::*;

struct ProfileRule {
    browser: Browser,
    environment: &'static str,
    relative: &'static str,
    recursive: bool,
}
#[path = "profile_catalogue.rs"]
mod catalogue;

const MAX_ENTRIES: usize = 20_000;
const MAX_PATH_BYTES: usize = 8 * 1024 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_LOCAL_STATE: u64 = 2 * 1024 * 1024;

// Canonicalization adds a verbatim drive prefix for long Windows paths. That
// spelling change alone is not a redirect; no other namespace is collapsed.
fn directory_name(path: &Path) -> String {
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

fn inside_directory(base: &Path, path: &Path) -> bool {
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return false;
    }
    let root = directory_name(base);
    let candidate = directory_name(path);
    if candidate == root {
        return true;
    }
    if cfg!(windows) {
        candidate
            .strip_prefix(root.trim_end_matches('\\'))
            .is_some_and(|rest| rest.starts_with('\\'))
    } else {
        contained(base, path)
    }
}

pub(super) fn same_named_path(left: &Path, right: &Path) -> bool {
    directory_name(left) == directory_name(right)
}
pub(super) fn contains_named_path(base: &Path, path: &Path) -> bool {
    !same_named_path(base, path) && inside_directory(base, path)
}

struct Walk {
    inventory: ProfileInventory,
    entries: usize,
    path_bytes: usize,
    exhausted: bool,
    seen: HashSet<(Browser, String)>,
    names: HashMap<PathBuf, HashMap<String, String>>,
}
impl Walk {
    fn new(inventory: ProfileInventory) -> Self {
        let seen = inventory
            .profiles
            .iter()
            .map(|p| (p.browser, path_identity(&p.root)))
            .collect();
        Self {
            inventory,
            entries: 0,
            path_bytes: 0,
            exhausted: false,
            seen,
            names: HashMap::new(),
        }
    }
    fn skip(&mut self, path: &Path, reason: &str) {
        self.inventory.partial = true;
        if self.inventory.skipped.len() < MAX_SKIP_DETAILS {
            self.inventory.skipped.push(InventorySkip {
                path: Some(path.to_owned()),
                reason: reason.into(),
            });
        }
    }
    fn directory(&mut self, base: &Path, path: &Path) -> bool {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() && !is_link(&metadata) => {
                if !inside_directory(base, path)
                    || !dunce::canonicalize(path)
                        .is_ok_and(|canonical| directory_name(&canonical) == directory_name(path))
                {
                    self.skip(
                        path,
                        "A declared browser profile path is redirected or outside its root.",
                    );
                    false
                } else {
                    true
                }
            }
            Ok(metadata) if is_link(&metadata) => {
                self.skip(
                    path,
                    "A declared browser profile directory is linked and was not followed.",
                );
                false
            }
            Ok(_) => false,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => {
                self.skip(
                    path,
                    "A declared browser profile directory could not be inspected.",
                );
                false
            }
        }
    }
    fn children(&mut self, base: &Path, path: &Path, pattern: &str) -> Vec<PathBuf> {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(_) => {
                self.skip(
                    path,
                    "A declared browser profile directory could not be enumerated.",
                );
                return Vec::new();
            }
        };
        let mut output = Vec::new();
        for entry in entries {
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                self.exhausted = true;
                self.skip(path, "Browser profile enumeration limit reached.");
                break;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    self.skip(path, "A browser profile directory entry could not be read.");
                    continue;
                }
            };
            self.path_bytes = self.path_bytes.saturating_add(entry.file_name().len());
            if self.path_bytes > MAX_PATH_BYTES {
                self.exhausted = true;
                self.skip(path, "Browser profile path inspection limit reached.");
                break;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                self.skip(path, "A browser profile directory name is unsupported.");
                continue;
            };
            if crate::browser_cache::wildcard(pattern, &name) && self.directory(base, &entry.path())
            {
                output.push(entry.path());
            }
        }
        output.sort_by_key(|p| path_identity(p));
        output
    }
    fn has_database(&mut self, browser: Browser, path: &Path, named_record_scopes: bool) -> bool {
        let files: Vec<&str> = if browser.is_chromium() {
            std::iter::once("History")
                .chain(CHROMIUM_COOKIE_DATABASES.iter().copied())
                .chain(CHROMIUM_SITE_DATABASES.iter().map(|(name, _)| *name))
                .chain(CHROMIUM_HISTORY_DATABASES.iter().map(|(name, _)| *name))
                // JSON metadata is a profile witness, never a SQLite target.
                .chain(std::iter::once("Preferences"))
                .collect()
        } else {
            std::iter::once("places.sqlite")
                .chain(std::iter::once("cookies.sqlite"))
                .chain(std::iter::once("signons.sqlite"))
                .chain(MOZILLA_SITE_DATABASES.iter().map(|(name, _)| *name))
                .collect()
        };
        let mut found = false;
        for name in files {
            let file = path.join(name);
            match optional_database_absent(path, &file) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(()) => {
                    self.skip(
                        &file,
                        "A declared browser database is linked or unavailable.",
                    );
                    continue;
                }
            }
            match fs::symlink_metadata(&file) {
                Ok(metadata) if is_link(&metadata) => self.skip(
                    &file,
                    "A declared browser database is linked and was not followed.",
                ),
                Ok(metadata) if metadata.is_file() => {
                    if validate_database_path(path, &file).is_ok() {
                        found = true;
                    } else {
                        self.skip(
                            &file,
                            "A declared browser database path is redirected or unavailable.",
                        );
                    }
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => self.skip(&file, "A declared browser database could not be inspected."),
            }
        }
        if browser.is_chromium() || !found {
            let inventory = storage_files::discover_witness_paths(
                browser,
                path,
                &AtomicBool::new(false),
                MAX_ENTRIES.saturating_sub(self.entries),
                MAX_PATH_BYTES.saturating_sub(self.path_bytes),
            );
            self.entries = self.entries.saturating_add(inventory.entries);
            self.path_bytes = self.path_bytes.saturating_add(inventory.path_bytes);
            self.exhausted |= inventory.truncated;
            for reason in inventory.issues {
                self.skip(path, reason);
            }
            found |= !inventory.files.is_empty()
                || !inventory.databases.is_empty()
                || !inventory.leveldb_dirs.is_empty();
        }
        if !found && !self.exhausted {
            let witness = record_files::discovery::discover(
                browser,
                path,
                named_record_scopes,
                &AtomicBool::new(false),
                MAX_ENTRIES.saturating_sub(self.entries),
                MAX_PATH_BYTES.saturating_sub(self.path_bytes),
            );
            self.entries = self.entries.saturating_add(witness.entries);
            self.path_bytes = self.path_bytes.saturating_add(witness.path_bytes);
            self.exhausted |= witness.truncated;
            for reason in witness.issues {
                self.skip(path, reason);
            }
            found |= witness.found;
        }
        if !found && !self.exhausted {
            let witness = session_files::discover(
                browser,
                path,
                named_record_scopes,
                &AtomicBool::new(false),
                MAX_ENTRIES.saturating_sub(self.entries),
                MAX_PATH_BYTES.saturating_sub(self.path_bytes),
                true,
            );
            self.entries = self.entries.saturating_add(witness.entries);
            self.path_bytes = self.path_bytes.saturating_add(witness.path_bytes);
            self.exhausted |= witness.truncated;
            for reason in witness.issues {
                self.skip(path, reason);
            }
            found |= !witness.files.is_empty();
        }
        found
    }
    fn friendly_name(&mut self, path: &Path) -> String {
        let fallback = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let Some(parent) = path.parent() else {
            return fallback;
        };
        let names = self.names.entry(parent.to_owned()).or_insert_with(|| {
            let state = parent.join("Local State");
            let Ok(metadata) = fs::symlink_metadata(&state) else {
                return HashMap::new();
            };
            if !metadata.is_file()
                || is_link(&metadata)
                || metadata.len() > MAX_LOCAL_STATE
                || !dunce::canonicalize(&state).is_ok_and(|p| same_path(&p, &state))
            {
                return HashMap::new();
            }
            let Ok(file) = File::open(state) else {
                return HashMap::new();
            };
            let mut bytes = Vec::new();
            if file
                .take(MAX_LOCAL_STATE + 1)
                .read_to_end(&mut bytes)
                .is_err()
                || bytes.len() as u64 > MAX_LOCAL_STATE
            {
                return HashMap::new();
            }
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                return HashMap::new();
            };
            value
                .pointer("/profile/info_cache")
                .and_then(|v| v.as_object())
                .map(|object| {
                    object
                        .iter()
                        .filter_map(|(key, v)| {
                            v.get("name")
                                .and_then(|v| v.as_str())
                                .filter(|s| s.len() <= 1024)
                                .map(|name| (key.clone(), name.to_owned()))
                        })
                        .collect()
                })
                .unwrap_or_default()
        });
        names.get(&fallback).cloned().unwrap_or(fallback)
    }
    fn candidate(&mut self, browser: Browser, path: &Path, named_record_scopes: bool) {
        let Ok(canonical) = dunce::canonicalize(path) else {
            self.skip(path, "A browser profile disappeared during discovery.");
            return;
        };
        if directory_name(&canonical) != directory_name(path)
            || !fs::symlink_metadata(path)
                .is_ok_and(|metadata| metadata.is_dir() && !is_link(&metadata))
        {
            self.skip(path, "A browser profile was redirected during discovery.");
            return;
        }
        let path = canonical.as_path();
        if self.seen.contains(&(browser, path_identity(path)))
            || !self.has_database(browser, path, named_record_scopes)
        {
            return;
        }
        if self.inventory.profiles.len() >= MAX_PROFILES {
            self.exhausted = true;
            self.skip(path, "Browser profile limit reached.");
            return;
        }
        let name = self.friendly_name(path);
        self.seen.insert((browser, path_identity(path)));
        self.inventory
            .profiles
            .push(make_profile(browser, name, path.to_owned()));
    }
    fn visit(&mut self, browser: Browser, base: &Path, path: &Path, recursive: bool) {
        // Mozilla variables name containers. Their root FileKeys may match
        // here, but a `*\\thumbnails` scope requires a child profile first.
        self.candidate(browser, path, browser.is_chromium());
        if !recursive {
            return;
        }
        let mut stack = vec![(path.to_owned(), 0)];
        while let Some((directory, depth)) = stack.pop() {
            if self.exhausted {
                break;
            }
            let children = self.children(base, &directory, "*");
            if depth >= MAX_DEPTH && !children.is_empty() {
                self.skip(&directory, "Recursive browser profile depth limit reached.");
                continue;
            }
            for child in children.into_iter().rev() {
                self.candidate(browser, &child, true);
                stack.push((child, depth + 1));
            }
        }
    }
}

pub(super) fn reference_profiles(
    mut resolve: impl FnMut(&str) -> Option<PathBuf>,
) -> ProfileInventory {
    let mut walk = Walk::new(ProfileInventory::default());
    let mut roots = HashMap::new();
    for rule in catalogue::REFERENCE_PROFILES {
        if walk.exhausted {
            break;
        }
        let base = roots
            .entry(rule.environment)
            .or_insert_with(|| resolve(rule.environment));
        let Some(base) = base else {
            if !walk
                .inventory
                .skipped
                .iter()
                .any(|s| s.reason.contains(rule.environment))
            {
                walk.inventory.partial = true;
                walk.inventory.skipped.push(InventorySkip {
                    path: None,
                    reason: format!(
                        "The {} browser profile environment is unavailable.",
                        rule.environment
                    ),
                });
            }
            continue;
        };
        if !walk.directory(base, base) {
            continue;
        }
        let mut candidates = vec![base.clone()];
        for part in rule.relative.split('/') {
            let mut next = Vec::new();
            for directory in candidates {
                if walk.exhausted {
                    break;
                }
                if part.contains(['*', '?']) {
                    next.extend(walk.children(base, &directory, part));
                } else {
                    let path = directory.join(part);
                    if walk.directory(base, &path) {
                        next.push(path);
                    }
                }
            }
            candidates = next;
            if candidates.is_empty() || walk.exhausted {
                break;
            }
        }
        for path in candidates {
            if walk.exhausted {
                break;
            }
            walk.visit(rule.browser, base, &path, rule.recursive);
        }
    }
    walk.inventory
}

pub(super) fn user_data_profiles(browser: Browser, root: &Path, inventory: &mut ProfileInventory) {
    let mut walk = Walk::new(std::mem::take(inventory));
    for path in walk.children(root, root, "*") {
        if walk.exhausted {
            break;
        }
        walk.candidate(browser, &path, true);
    }
    *inventory = walk.inventory;
}

#[cfg(test)]
#[path = "profile_discovery_tests.rs"]
mod tests;
