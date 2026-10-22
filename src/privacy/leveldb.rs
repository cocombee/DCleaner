//! Site storage LevelDB inventory. Source handles are read-only; the decoder
//! receives owned bytes. No LevelDB library can perform recovery on the source.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MAX_FILES: usize = 1024;
const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;

pub(super) fn input_name(name: &str) -> bool {
    if name == "CURRENT" {
        return true;
    }
    let stem = name
        .strip_prefix("MANIFEST-")
        .or_else(|| name.strip_suffix(".ldb"))
        .or_else(|| name.strip_suffix(".sst"))
        .or_else(|| name.strip_suffix(".log"));
    stem.is_some_and(|s| !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()))
}

fn canonical_name(name: &str) -> Option<String> {
    let name = if cfg!(windows) {
        let upper = name.to_ascii_uppercase();
        if upper == "LOCK" || upper == "CURRENT" || upper.starts_with("MANIFEST-") {
            upper
        } else {
            // Recovery enumerates numeric log/table names with a case-sensitive
            // filename parser, even on Windows. Do not turn .LOG into .log.
            name.to_owned()
        }
    } else {
        name.to_owned()
    };
    (name == "LOCK" || input_name(&name)).then_some(name)
}

fn directory(root: &Path, path: &Path) -> Result<(), String> {
    if !contains_named_path(root, path) || !same_named_path(&safe_profile_root(path)?, path) {
        return Err("Site storage directory is linked or outside the profile.".into());
    }
    Ok(())
}

pub(super) fn names(root: &Path, path: &Path, cancel: &AtomicBool) -> Result<Vec<String>, String> {
    directory(root, path)?;
    let mut names = Vec::new();
    let mut count = 0;
    for entry in fs::read_dir(path).map_err(|_| "Site storage directory could not be read.")? {
        if cancel.load(Ordering::Relaxed) {
            return Err("Site storage inspection stopped.".into());
        }
        count += 1;
        if count > MAX_FILES {
            return Err("Site storage file limit reached.".into());
        }
        let entry = entry.map_err(|_| "Site storage entry could not be inspected.")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Unsupported Site storage file name.")?;
        if name.len() > 256 {
            return Err("Site storage file name limit reached.".into());
        }
        if let Some(name) = canonical_name(&name) {
            validate_database_path(root, &entry.path())?;
            names.push(name);
        }
    }
    names.sort();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("Browser key-store file names are ambiguous.".into());
    }
    Ok(names)
}

fn bytes(
    root: &Path,
    path: &Path,
    cancel: &AtomicBool,
    budget: &mut u64,
) -> Result<Vec<u8>, String> {
    let (_, before, _) = validate_database_path(root, path)?;
    if before.length > leveldb_format::MAX_BYTES as u64 || before.length > *budget {
        return Err("Site storage content inspection limit reached.".into());
    }
    // Shared no-follow native handle/identity checks; never create or lock files.
    let mut file = storage_files::open_file(root, path)?;
    let identity = storage_files::identity(&file)?;
    let mut out = Vec::with_capacity(before.length as usize);
    let mut buffer = [0; 64 * 1024];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("Site storage inspection stopped.".into());
        }
        let n = file
            .read(&mut buffer)
            .map_err(|_| "Site storage content could not be read.")?;
        if n == 0 {
            break;
        }
        *budget = budget
            .checked_sub(n as u64)
            .ok_or("Site storage scan budget reached.")?;
        if out.len().saturating_add(n) > before.length as usize {
            return Err("Site storage file grew during inspection.".into());
        }
        out.extend_from_slice(&buffer[..n]);
    }
    if out.len() as u64 != before.length
        || file_stamp(path)? != before
        || storage_files::identity(&storage_files::open_file(root, path)?)? != identity
    {
        return Err("Site storage file changed during inspection.".into());
    }
    Ok(out)
}

pub(super) fn snapshot(
    root: &Path,
    path: &Path,
    cancel: &AtomicBool,
    budget: &mut u64,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let before_names = names(root, path, cancel)?;
    if !before_names.iter().any(|n| n == "LOCK") {
        return Err("Site storage has no declared LOCK entry.".into());
    }
    let mut files = BTreeMap::new();
    let mut count = 0usize;
    for name in &before_names {
        // LOCK is only a dispatch witness. Its bytes do not describe user keys.
        if name == "LOCK" {
            continue;
        }
        let data = bytes(root, &path.join(name), cancel, budget)?;
        count = count
            .checked_add(data.len())
            .ok_or("Site storage size overflow.")?;
        if count > leveldb_format::MAX_BYTES {
            return Err("Site storage snapshot limit reached.".into());
        }
        files.insert(name.clone(), data);
    }
    verify_snapshot(root, path, cancel, budget, &before_names, &files)?;
    Ok(files)
}

fn verify_snapshot(
    root: &Path,
    path: &Path,
    cancel: &AtomicBool,
    budget: &mut u64,
    before_names: &[String],
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    // A second complete observation detects WAL-only/content/namespace drift.
    // This is an observation, not an atomic live-browser snapshot or effect grant.
    for (name, before) in files {
        let after = bytes(root, &path.join(name), cancel, budget)?;
        if Sha256::digest(before) != Sha256::digest(after) {
            return Err(
                "Site storage changed during inspection. Scan again after closing the browser."
                    .into(),
            );
        }
    }
    if names(root, path, cancel)? != before_names {
        return Err("Site storage file membership changed during inspection.".into());
    }
    Ok(())
}

/// The native helper decodes the UTF8 prefix before the first NUL, and uses
/// FIRST `_0` for its encoded branch. Preserve the raw key separately upstream.
pub(super) fn site(key: &[u8]) -> Result<String, String> {
    let prefix = key.split(|&b| b == 0).next().unwrap_or_default();
    let text = std::str::from_utf8(prefix)
        .map_err(|_| "A Site storage key has unsupported UTF8 encoding.")?;
    if let Some(end) = text.find("_0") {
        let scheme = text
            .find("http_")
            .map(|n| (n, 5))
            .or_else(|| text.find("https_").map(|n| (n, 6)));
        let Some((start, len)) = scheme else {
            return Ok(String::new());
        };
        let start = start + len;
        return Ok(if end < start {
            &text[start..]
        } else {
            &text[start..end]
        }
        .to_owned());
    }
    let scheme = text
        .find("http://")
        .map(|n| (n, 7))
        .or_else(|| text.find("https://").map(|n| (n, 8)));
    let Some((start, len)) = scheme else {
        return Ok(String::new());
    };
    Ok(text[start + len..]
        .split('/')
        .next()
        .unwrap_or_default()
        .to_owned())
}

pub(super) fn scan(
    profile: &BrowserProfile,
    paths: &[PathBuf],
    keep: &HashSet<String>,
    cancel: &AtomicBool,
    budget: &mut u64,
    report: &mut PrivacyReport,
) {
    if !profile.browser.is_chromium() {
        return;
    }
    for path in paths {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            break;
        }
        if report.records.len() >= MAX_RECORDS {
            report.truncated = true;
            break;
        }
        if !storage_files::owns_leveldb_lock(profile.browser, &profile.root, &path.join("LOCK")) {
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::Cookies),
                "A browser key store is outside its declared scope or belongs to an earlier handler.",
            );
            continue;
        }
        scan_store(profile, path, keep, cancel, budget, report);
    }
}

fn scan_store(
    profile: &BrowserProfile,
    path: &Path,
    keep: &HashSet<String>,
    cancel: &AtomicBool,
    budget: &mut u64,
    report: &mut PrivacyReport,
) {
    let result = snapshot(&profile.root, &path, cancel, budget)
        .and_then(|files| leveldb_format::inspect(&files, cancel).map(|image| (files, image)));
    let (files, image) = match result {
        Ok(image) => image,
        Err(reason) => {
            report.cancelled |= cancel.load(Ordering::Relaxed);
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::Cookies),
                &reason,
            );
            return;
        }
    };
    let store = match leveldb_write::Store::capture(profile, path, &files, &image, cancel) {
        Ok(store) => Some(store),
        Err(reason) => {
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::Cookies),
                &reason,
            );
            None
        }
    };
    let keep = std::sync::Arc::new(keep.clone());
    for (key, value) in &image.records {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            break;
        }
        let raw_site = match site(key) {
            Ok(site) => site,
            Err(reason) => {
                add_skip(
                    report,
                    &profile.name,
                    Some(PrivacyCategory::Cookies),
                    &reason,
                );
                continue;
            }
        };
        if raw_site.is_empty() {
            continue;
        }
        if is_cookie_exception(&raw_site, &keep) {
            report.cookie_exempted += 1;
            continue;
        }
        if report.records.len() >= MAX_RECORDS {
            report.truncated = true;
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::Cookies),
                "Site storage record limit reached.",
            );
            break;
        }
        let id = Uuid::new_v4();
        let review = leveldb_write::Review::new(
            id,
            store.clone(),
            key.clone(),
            value,
            raw_site.clone(),
            keep.clone(),
        );
        if let Some(reason) = review.unavailable_reason() {
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::Cookies),
                reason,
            );
        }
        report.records.push(PrivacyRecord {
            id,
            browser: profile.browser,
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            category: PrivacyCategory::Cookies,
            site: normalize_cookie_domain(&raw_site)
                .unwrap_or_else(|_| "Unsupported storage site".into()),
            locator: RecordLocator::LevelDb(review),
        });
    }
}

pub(super) fn scan_budget() -> u64 {
    MAX_SCAN_BYTES
}

#[cfg(test)]
#[path = "leveldb_tests.rs"]
mod tests;
