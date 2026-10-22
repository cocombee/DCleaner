//! Exact reviewed table groups. The shared privacy owner supplies durable SQL
//! backups, intent, transaction, outcome and whole-database reviewed recovery.
use super::super as privacy;
use super::*;
use privacy::{
    BrowserProfile, PrivacyCategory, PrivacyReport, RecordLocator, RowLocator, TableKind,
};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroize;

const MAX_IMAGE: u64 = 256 * 1024 * 1024;
#[derive(Clone, Debug, Eq, PartialEq)]
struct Image {
    bytes: u64,
    hash: [u8; 32],
}
struct OwnedImage {
    pointer: *mut u8,
    length: usize,
}
impl Drop for OwnedImage {
    fn drop(&mut self) {
        // sqlite3_serialize(flags=0) returns an independently allocated buffer.
        // Its contents are private browser data, so erase before sqlite3_free.
        unsafe {
            std::slice::from_raw_parts_mut(self.pointer, self.length).zeroize();
            ffi::sqlite3_free(self.pointer.cast());
        }
    }
}
fn image(conn: &Connection, cancel: &AtomicBool) -> Result<Image, String> {
    cancelled(cancel)?;
    if conn.is_autocommit() {
        return Err("Browser table fingerprint requires an active snapshot.".into());
    }
    let mut size = 0i64;
    // NOCOPY reports the size even when no contiguous representation exists.
    // No allocation or borrowed pointer is retained from this first call.
    unsafe {
        ffi::sqlite3_serialize(
            conn.handle(),
            c"main".as_ptr(),
            &mut size,
            ffi::SQLITE_SERIALIZE_NOCOPY,
        );
    }
    let size = u64::try_from(size).map_err(|_| unavailable())?;
    if size == 0 || size > MAX_IMAGE {
        return Err("Browser table snapshot exceeds the bounded image limit.".into());
    }
    cancelled(cancel)?;
    let mut actual = 0i64;
    let pointer =
        unsafe { ffi::sqlite3_serialize(conn.handle(), c"main".as_ptr(), &mut actual, 0) };
    if pointer.is_null() {
        return Err("Browser table snapshot could not be captured.".into());
    }
    if actual <= 0 || u64::try_from(actual).is_err() || actual as u64 > MAX_IMAGE {
        unsafe {
            ffi::sqlite3_free(pointer.cast());
        }
        return Err("Browser table snapshot size is invalid.".into());
    }
    let length = actual as usize;
    let owned = OwnedImage { pointer, length };
    if u64::try_from(actual).ok() != Some(size) {
        return Err("Browser table snapshot changed during capture.".into());
    }
    let bytes = unsafe { std::slice::from_raw_parts(owned.pointer, owned.length) };
    let mut hash = Sha256::new();
    hash.update(b"dcleaner-sqlite-reviewed-image-v1");
    hash.update(size.to_le_bytes());
    for chunk in bytes.chunks(64 * 1024) {
        cancelled(cancel)?;
        hash.update(chunk);
    }
    Ok(Image {
        bytes: size,
        hash: hash.finalize().into(),
    })
}

#[derive(Clone)]
pub(in crate::privacy) struct Review {
    key: Key,
    rows: u64,
    image: Arc<Image>,
    identity: (u64, u64),
    trigger: bool,
}
impl Review {
    pub(in crate::privacy) fn item_count(&self) -> usize {
        usize::try_from(self.rows).expect("Bounded ordinary SQLite image fits host counts")
    }
    pub(in crate::privacy) fn unavailable_reason(&self) -> Option<&'static str> {
        self.trigger
            .then_some("Table triggers require a separate reviewed cleanup adapter.")
    }
    pub(in crate::privacy) fn cleanup_note(&self) -> &'static str {
        "Every row in each selected table is removed. Other tables are kept; shared dependencies can block cleanup. Close the browser first."
    }
    pub(in crate::privacy) fn source(&self) -> String {
        self.key.database().expect("Declared table").into()
    }
}

/// A read/attribute-only namespace lease. Windows denies replacement of the
/// database and all directory ancestors while permitting SQLite's own I/O.
pub(in crate::privacy) struct SourceLease {
    _file: File,
    _directories: Vec<File>,
    identity: (u64, u64),
}
impl SourceLease {
    pub(in crate::privacy) fn acquire(root: &Path, path: &Path) -> Result<Self, String> {
        privacy::validate_database_path(root, path)?;
        let mut directories = Vec::new();
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            for directory in root.ancestors().collect::<Vec<_>>().into_iter().rev() {
                privacy::safe_profile_root(directory)?;
                let file = OpenOptions::new()
                    .access_mode(FILE_READ_ATTRIBUTES.0)
                    .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
                    .open(directory)
                    .map_err(|_| "Browser table ancestor could not be held against replacement.")?;
                let meta = file.metadata().map_err(|_| unavailable())?;
                if !meta.is_dir() || privacy::is_link(&meta) {
                    return Err("Browser table ancestor is redirected.".into());
                }
                directories.push(file);
            }
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            options
                .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
        }
        let file = options
            .open(path)
            .map_err(|_| "Browser table source could not be held.")?;
        let identity = privacy::storage_files::identity(&file)?;
        let lease = Self {
            _file: file,
            _directories: directories,
            identity,
        };
        lease.check(root, path)?;
        Ok(lease)
    }
    pub(in crate::privacy) fn check(&self, root: &Path, path: &Path) -> Result<(), String> {
        let file = privacy::storage_files::open_file(root, path)?;
        if privacy::storage_files::identity(&file)? != self.identity {
            return Err("Browser table source was replaced.".into());
        }
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut sidecar = path.as_os_str().to_os_string();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            match privacy::optional_database_absent(root, &sidecar) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(()) => return Err("Browser table sidecar is redirected or unavailable.".into()),
            }
            let held = privacy::storage_files::open_file(root, &sidecar)?;
            privacy::storage_files::identity(&held)?;
            if suffix == "-journal" && held.metadata().map_err(|_| unavailable())?.len() > 0 {
                return Err(
                    "Browser table rollback journal requires browser recovery first.".into(),
                );
            }
        }
        Ok(())
    }
}

fn selected_keys(browser: Browser, categories: &[PrivacyCategory]) -> Vec<Key> {
    [
        Scope::SavedForms,
        Scope::SavedPasswords,
        Scope::SitePreferences,
    ]
    .into_iter()
    .flat_map(|scope| keys(browser, scope))
    .filter(|key| categories.contains(&key.category()))
    .collect()
}
pub(in crate::privacy) fn scan(
    profile: &BrowserProfile,
    categories: &[PrivacyCategory],
    cancel: &AtomicBool,
    report: &mut PrivacyReport,
) {
    let mut databases = BTreeMap::<&str, Vec<Key>>::new();
    for key in selected_keys(profile.browser, categories) {
        databases
            .entry(key.database().expect("Declared table"))
            .or_default()
            .push(key);
    }
    for (database, keys) in databases {
        if report.cancelled || report.truncated {
            break;
        }
        let path = profile.root.join(database);
        let start = report.records.len();
        let category = keys[0].category();
        let result = (|| -> Result<(), String> {
            if privacy::optional_database_absent(&profile.root, &path)
                .map_err(|_| "Browser table database is redirected or unavailable.")?
            {
                return Ok(());
            }
            let (path, before, _) = privacy::validate_database_path(&profile.root, &path)?;
            let lease = SourceLease::acquire(&profile.root, &path)?;
            let mut conn = Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|_| unavailable())?;
            conn.busy_timeout(Duration::from_secs(2))
                .map_err(|_| unavailable())?;
            conn.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF")
                .map_err(|_| unavailable())?;
            let mut reader = Reader::new(&mut conn, cancel)?;
            let mut observations = Vec::new();
            for key in keys {
                match reader.read(key) {
                    Ok(Some(observation)) => observations.push(observation),
                    Ok(None) => {}
                    Err(error) => {
                        cancelled(cancel)?;
                        privacy::add_skip(report, &profile.name, Some(key.category()), &error);
                    }
                }
            }
            if observations.is_empty() {
                return Ok(());
            }
            let image = Arc::new(image(&reader.transaction, cancel)?);
            for observation in observations {
                cancelled(cancel)?;
                if report.records.len() >= privacy::MAX_RECORDS {
                    report.truncated = true;
                    break;
                }
                let key = observation.key;
                let trigger=reader.transaction.query_row("SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type='trigger' AND tbl_name=?1 COLLATE NOCASE)",[key.table()?],|r|r.get::<_,bool>(0)).map_err(|_|unavailable())?;
                let review = Review {
                    key,
                    rows: observation.rows,
                    image: Arc::clone(&image),
                    identity: lease.identity,
                    trigger,
                };
                let id = uuid::Uuid::new_v4();
                report.records.push(privacy::PrivacyRecord {
                    id,
                    browser: profile.browser,
                    profile_id: profile.id.clone(),
                    profile_name: profile.name.clone(),
                    category: key.category(),
                    site: observation.group_label()?,
                    locator: RecordLocator::Database(RowLocator {
                        id,
                        browser: profile.browser,
                        profile_id: profile.id.clone(),
                        profile_name: profile.name.clone(),
                        profile_root: profile.root.clone(),
                        database: path.clone(),
                        database_stamp: before.clone(),
                        kind: TableKind::GenericSqlite(key),
                        row_id: 0,
                        identity: Vec::new(),
                        history: None,
                        download: None,
                        firefox: None,
                        cookie: None,
                        quota: None,
                        keyword: None,
                        shortcut: None,
                        generic: Some(review),
                    }),
                });
            }
            drop(reader);
            drop(conn);
            lease.check(&profile.root, &path)?;
            if privacy::file_stamp(&path)? != before {
                return Err("Browser table database changed during inventory; scan again.".into());
            }
            Ok(())
        })();
        if let Err(reason) = result {
            report.records.truncate(start);
            report.cancelled |= cancel.load(Ordering::Relaxed);
            privacy::add_skip(report, &profile.name, Some(category), &reason);
        }
    }
    if categories.contains(&PrivacyCategory::SavedPasswords) {
        privacy::add_skip(
            report,
            &profile.name,
            Some(PrivacyCategory::SavedPasswords),
            "Saved-password coverage currently includes declared legacy SQLite tables; other declared password stores are not yet supported.",
        );
    }
    for scope in [Scope::SavedForms, Scope::SitePreferences] {
        let category = match scope {
            Scope::SavedForms => PrivacyCategory::SavedForms,
            Scope::SitePreferences => PrivacyCategory::SitePreferences,
            _ => unreachable!(),
        };
        if categories.contains(&category) && super::keys(profile.browser, scope).is_empty() {
            privacy::add_skip(
                report,
                &profile.name,
                Some(category),
                "This browser family's declared data format does not yet have a supported cleanup adapter.",
            );
        }
    }
}

#[cfg(debug_assertions)]
pub(in crate::privacy) fn preview() -> (privacy::ProfileInventory, PrivacyReport) {
    let (mut inventory, mut report) = privacy::visual_preview_fixture();
    let template = report.records[0].clone();
    report.records.clear();
    let mut firefox = inventory.profiles[0].clone();
    firefox.browser = Browser::Firefox;
    firefox.id = "fixture-generic-firefox".into();
    firefox.name = "Fixture Firefox profile".into();
    inventory.profiles.push(firefox);
    for (index, scope, table, count) in [
        (0, Scope::SavedForms, "autofill", 3),
        (0, Scope::SavedPasswords, "logins", 2),
        (1, Scope::SitePreferences, "moz_disabledHosts", 1),
    ] {
        let profile = &inventory.profiles[index];
        let key = keys(profile.browser, scope)
            .into_iter()
            .find(|key| key.table() == Ok(table))
            .unwrap();
        let mut record = template.clone();
        record.id = uuid::Uuid::new_v4();
        record.browser = profile.browser;
        record.profile_id = profile.id.clone();
        record.profile_name = profile.name.clone();
        record.category = key.category();
        record.site = format!("{}: {table}", key.database().unwrap());
        let RecordLocator::Database(row) = &mut record.locator else {
            unreachable!()
        };
        row.id = record.id;
        row.browser = profile.browser;
        row.profile_id = profile.id.clone();
        row.profile_name = profile.name.clone();
        row.profile_root = profile.root.clone();
        row.database = profile.root.join(key.database().unwrap());
        row.kind = TableKind::GenericSqlite(key);
        row.identity.clear();
        row.generic = Some(Review {
            key,
            rows: count,
            image: Arc::new(Image {
                bytes: 8192,
                hash: [0; 32],
            }),
            identity: (0, 0),
            trigger: false,
        });
        report.records.push(record);
    }
    report.profiles_scanned = 2;
    report.categories_scanned = vec![
        PrivacyCategory::SavedForms,
        PrivacyCategory::SavedPasswords,
        PrivacyCategory::SitePreferences,
    ];
    (inventory, report)
}

pub(in crate::privacy) fn validate_selected(
    conn: &Connection,
    records: &[RowLocator],
    lease: &SourceLease,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let reviews = records
        .iter()
        .filter_map(|r| r.generic.as_ref())
        .collect::<Vec<_>>();
    if reviews.is_empty() {
        return Ok(());
    }
    let observed = image(conn, cancel)?;
    let mut selected = HashSet::new();
    for review in reviews {
        if review.identity != lease.identity || *review.image != observed {
            return Err(
                "Browser table contents changed since review. Scan again before cleanup.".into(),
            );
        }
        if review.unavailable_reason().is_some() || !selected.insert(review.key.table()?) {
            return Err("Browser table selection is unsupported or duplicated.".into());
        }
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM \"{}\"", review.key.table()?),
                [],
                |r| r.get(0),
            )
            .map_err(|_| unavailable())?;
        if u64::try_from(count).ok() != Some(review.rows) {
            return Err("Browser table count changed since review.".into());
        }
    }
    Ok(())
}

pub(in crate::privacy) fn delete_selected(
    conn: &Connection,
    records: &[RowLocator],
    cancel: &AtomicBool,
) -> Result<Vec<uuid::Uuid>, String> {
    let reviews = records
        .iter()
        .filter_map(|r| r.generic.as_ref().map(|review| (r.id, review)))
        .collect::<Vec<_>>();
    if reviews.is_empty() {
        return Ok(Vec::new());
    }
    let selected = reviews
        .iter()
        .map(|(_, r)| r.key.table())
        .collect::<Result<HashSet<_>, _>>()?;
    let mut statement = conn
        .prepare("SELECT name FROM main.sqlite_schema WHERE type='table'")
        .map_err(|_| unavailable())?;
    let tables = statement
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|_| unavailable())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| unavailable())?;
    drop(statement);
    for table in tables {
        cancelled(cancel)?;
        let mut statement = conn
            .prepare("SELECT \"table\" FROM pragma_foreign_key_list(?1)")
            .map_err(|_| unavailable())?;
        let parents = statement
            .query_map([&table], |r| r.get::<_, String>(0))
            .map_err(|_| unavailable())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| unavailable())?;
        if !selected.iter().any(|name| table.eq_ignore_ascii_case(name))
            && parents.iter().any(|parent| {
                selected
                    .iter()
                    .any(|name| parent.eq_ignore_ascii_case(name))
            })
        {
            let quoted = table.replace('"', "\"\"");
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM \"{quoted}\""), [], |r| {
                    r.get(0)
                })
                .map_err(|_| unavailable())?;
            if count > 0 {
                return Err("An unselected table depends on a selected table. Review its complete dependency group first.".into());
            }
        }
    }
    // All group fingerprints were checked before effects. Deferral supports
    // selected cyclic references; cascades may only reach selected tables.
    conn.execute_batch("PRAGMA defer_foreign_keys=ON")
        .map_err(|_| unavailable())?;
    for (_, review) in &reviews {
        let table = review.key.table()?;
        let trigger:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type='trigger' AND tbl_name=?1 COLLATE NOCASE)",[table],|r|r.get(0)).map_err(|_|unavailable())?;
        if trigger {
            return Err("Table triggers require a separate reviewed cleanup adapter.".into());
        }
    }
    for (_, review) in &reviews {
        cancelled(cancel)?;
        let table = review.key.table()?;
        conn.execute(&format!("DELETE FROM \"{table}\""), [])
            .map_err(|_| "Reviewed browser table could not be removed transactionally.")?;
    }
    for (_, review) in &reviews {
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM \"{}\"", review.key.table()?),
                [],
                |r| r.get(0),
            )
            .map_err(|_| unavailable())?;
        if count != 0 {
            return Err("Reviewed browser table post-state verification failed.".into());
        }
    }
    Ok(reviews.iter().map(|(id, _)| *id).collect())
}

/// Read every operation, including old hidden entries, without a display cap.
/// Damaged/oversized/redirected journals fail closed rather than permit replay.
pub(in crate::privacy) fn pending(data_dir: &Path, path: &Path) -> Result<(), String> {
    if privacy::preferences::session_trash_pending(data_dir)?
        .contains(&privacy::storage_files::path_key(path))
    {
        return Err("An unresolved file move blocks database cleanup.".into());
    }
    let directory = data_dir.join("privacy-operations");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("Database recovery history is unavailable.".into()),
    };
    let mut files = 0usize;
    for entry in entries {
        let path_journal = entry.map_err(|_| unavailable())?.path();
        if path_journal.extension().is_none_or(|e| e != "jsonl") {
            continue;
        }
        files += 1;
        if files > 10_000 {
            return Err("Database recovery history limit reached.".into());
        }
        let meta = fs::symlink_metadata(&path_journal).map_err(|_| unavailable())?;
        if privacy::is_link(&meta) || !meta.is_file() || meta.len() > 8 * 1024 * 1024 {
            return Err("Database recovery history is redirected or oversized.".into());
        }
        let mut cleanup = HashSet::new();
        let mut restore = HashSet::new();
        let mut reader = BufReader::new(File::open(&path_journal).map_err(|_| unavailable())?);
        let mut journal_bytes = 0usize;
        loop {
            let mut line = Vec::new();
            let length = std::io::Read::take(&mut reader, 1024 * 1024 + 1)
                .read_until(b'\n', &mut line)
                .map_err(|_| unavailable())?;
            if length == 0 {
                break;
            }
            if length > 1024 * 1024 {
                return Err("Database recovery entry limit reached.".into());
            }
            journal_bytes = journal_bytes
                .checked_add(length)
                .filter(|n| *n <= 8 * 1024 * 1024)
                .ok_or("Database recovery history byte limit reached.")?;
            let event: privacy::PrivacyJournalEvent = serde_json::from_slice(&line).map_err(
                |_| "Database recovery history is damaged; automatic replay is blocked.",
            )?;
            match event {
                privacy::PrivacyJournalEvent::Intent {
                    database, backup, ..
                } if privacy::same_path(&database, path) => {
                    cleanup.insert(backup);
                }
                privacy::PrivacyJournalEvent::Outcome {
                    database,
                    backup,
                    uncertain: false,
                    ..
                } if privacy::same_path(&database, path) => {
                    cleanup.remove(&backup);
                }
                privacy::PrivacyJournalEvent::RestoreIntent {
                    database,
                    restore_id,
                    ..
                } if privacy::same_path(&database, path) => {
                    restore.insert(restore_id);
                }
                privacy::PrivacyJournalEvent::RestoreOutcome {
                    database,
                    restore_id,
                    uncertain: false,
                    ..
                } if privacy::same_path(&database, path) => {
                    restore.remove(&restore_id);
                }
                _ => {}
            }
        }
        if !cleanup.is_empty() || !restore.is_empty() {
            return Err("An unresolved database operation blocks cleanup and automatic replay. Review recovery first.".into());
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "generic_sqlite_owner_tests.rs"]
mod tests;
