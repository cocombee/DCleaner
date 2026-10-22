//! Reviewed append-only LevelDB transactions. Scanning never enters this owner.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Seek, SeekFrom};
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Signature {
    identity: (u64, u64),
    stamp: FileStamp,
    hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Store {
    browser: Browser,
    profile_id: String,
    profile_name: String,
    root: PathBuf,
    #[serde(default)]
    directory: Option<PathBuf>,
    files: BTreeMap<String, Signature>,
    log: Option<String>,
    last_sequence: u64,
}
impl Store {
    fn path(&self) -> PathBuf {
        self.directory
            .clone()
            .unwrap_or_else(|| self.root.join("Local Storage/leveldb"))
    }
    pub(super) fn capture(
        profile: &BrowserProfile,
        path: &Path,
        files: &BTreeMap<String, Vec<u8>>,
        image: &leveldb_format::Image,
        cancel: &AtomicBool,
    ) -> Result<Arc<Self>, String> {
        let mut signatures = BTreeMap::new();
        for name in leveldb::names(&profile.root, &path, cancel)? {
            let file = path.join(&name);
            let signature = Signature {
                identity: storage_files::identity(&storage_files::open_file(
                    &profile.root,
                    &file,
                )?)?,
                stamp: file_stamp(&file)?,
                hash: files.get(&name).map(|bytes| digest(bytes)),
            };
            if name != "LOCK" && signature.hash.is_none() {
                return Err("Site storage changed while recording review identities.".into());
            }
            signatures.insert(name, signature);
        }
        if signatures.len() != files.len() + 1 {
            return Err("Site storage review membership changed.".into());
        }
        Ok(Arc::new(Self {
            browser: profile.browser,
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            root: profile.root.clone(),
            directory: Some(path.to_owned()),
            files: signatures,
            log: image.writable_log.clone(),
            last_sequence: image.last_sequence,
        }))
    }
    fn verify(&self, files: &BTreeMap<String, Vec<u8>>, check_time: bool) -> Result<(), String> {
        if files.len() + 1 != self.files.len() {
            return Err("Reviewed Site storage membership changed.".into());
        }
        for (name, signature) in &self.files {
            let path = self.path().join(name);
            let file = storage_files::open_file(&self.root, &path)?;
            if storage_files::identity(&file)? != signature.identity
                || (check_time && file_stamp(&path)? != signature.stamp)
                || (name != "LOCK" && files.get(name).map(|bytes| digest(bytes)) != signature.hash)
            {
                return Err("Site storage content or identity changed since review.".into());
            }
        }
        Ok(())
    }
    fn stopped(&self, runtime: &impl BrowserRuntime) -> Result<(), String> {
        if runtime
            .running_browsers()?
            .iter()
            .any(|process| self.browser.conflicts_with(process))
        {
            return Err(format!(
                "Close {} before changing Site storage.",
                self.browser.label()
            ));
        }
        Ok(())
    }
    fn scope(&self) -> Result<(), String> {
        if !self.browser.is_chromium()
            || self.files.is_empty()
            || self.files.len() > 1024
            || !self.files.contains_key("LOCK")
        {
            return Err("Site storage review scope is invalid.".into());
        }
        let Some(log) = &self.log else {
            return Err("Site storage has no reviewed append log.".into());
        };
        let number = log
            .strip_suffix(".log")
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or("Invalid Site storage log name.")?;
        if *log != format!("{number:06}.log")
            || !self.files.contains_key(log)
            || self
                .files
                .keys()
                .any(|name| name != "LOCK" && !leveldb::input_name(name))
        {
            return Err("Site storage review file names are invalid.".into());
        }
        safe_profile_root(&self.root)?;
        if !storage_files::owns_leveldb_lock(self.browser, &self.root, &self.path().join("LOCK")) {
            return Err("The browser key store is outside its declared scope or belongs to an earlier handler.".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct Review {
    pub id: Uuid,
    store: Option<Arc<Store>>,
    key: Vec<u8>,
    value_hash: [u8; 32],
    raw_site: String,
    keep: Arc<HashSet<String>>,
}
impl Review {
    pub(super) fn new(
        id: Uuid,
        store: Option<Arc<Store>>,
        key: Vec<u8>,
        value: &[u8],
        raw_site: String,
        keep: Arc<HashSet<String>>,
    ) -> Self {
        Self {
            id,
            store,
            key,
            value_hash: digest(value),
            raw_site,
            keep,
        }
    }
    pub(super) fn unavailable_reason(&self) -> Option<&'static str> {
        if !cfg!(windows) {
            return Some("Site storage cleanup is not verified on this platform.");
        }
        let Some(store) = &self.store else {
            return Some("Site storage review identities could not be verified. Scan again.");
        };
        if store.log.is_none() {
            return Some("Site storage has no compatible append log. Key cleanup is unavailable.");
        }
        if store.last_sequence >= (1u64 << 56) - 1 {
            return Some("Site storage sequence space is exhausted. Key cleanup is unavailable.");
        }
        if normalize_cookie_domain(&self.raw_site).is_err() {
            return Some("This Site storage key has an unsupported site identity.");
        }
        None
    }
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

struct Mutation {
    log: String,
    append: Vec<u8>,
    originals: Vec<(Vec<u8>, Vec<u8>)>,
    before_len: usize,
    after_hash: [u8; 32],
    sequence: u64,
}
fn deletions(
    files: &BTreeMap<String, Vec<u8>>,
    selected: &[Review],
    cancel: &AtomicBool,
) -> Result<Mutation, String> {
    if selected.is_empty() || selected.len() > MAX_RECORDS {
        return Err("Select exact current Site storage records.".into());
    }
    let store = selected[0]
        .store
        .as_ref()
        .ok_or("Site storage review is unavailable.")?;
    store.verify(files, true)?;
    let image = leveldb_format::inspect(files, cancel)?;
    let log = image
        .writable_log
        .as_ref()
        .filter(|log| Some(*log) == store.log.as_ref())
        .ok_or("Site storage append log changed.")?
        .clone();
    let mut keys = BTreeSet::new();
    let mut ids = HashSet::new();
    let mut originals = Vec::new();
    for review in selected {
        if review
            .store
            .as_ref()
            .is_none_or(|other| other.as_ref() != store.as_ref())
            || !keys.insert(&review.key)
            || !ids.insert(review.id)
        {
            return Err(
                "Selected Site storage records overlap or have different review snapshots.".into(),
            );
        }
        let value = image
            .records
            .get(&review.key)
            .ok_or("A reviewed Site storage key is no longer live.")?;
        if digest(value) != review.value_hash || leveldb::site(&review.key)? != review.raw_site {
            return Err("A reviewed Site storage key/value changed.".into());
        }
        originals.push((review.key.clone(), value.clone()));
    }
    let before = files
        .get(&log)
        .ok_or("Missing reviewed Site storage log.")?;
    let rows = originals
        .iter()
        .map(|(key, _)| (key.clone(), None))
        .collect::<Vec<_>>();
    let sequence = image
        .last_sequence
        .checked_add(1)
        .ok_or("Site storage sequence exhausted.")?;
    let append = leveldb_format::append_batch(before.len(), sequence, &rows)?;
    let mut after = files.clone();
    after.get_mut(&log).unwrap().extend(&append);
    let observed = leveldb_format::read(&after, cancel)?;
    // Reserve room for the exact compensating PUT batch under recovery's
    // sequence, aggregate-content and physical-log bounds before any effect.
    let restore_sequence = image
        .last_sequence
        .checked_add(originals.len() as u64)
        .and_then(|n| n.checked_add(1))
        .ok_or("Site storage restore sequence exhausted.")?;
    let restore_rows = originals
        .iter()
        .map(|(key, value)| (key.clone(), Some(value.clone())))
        .collect::<Vec<_>>();
    let restore_append =
        leveldb_format::append_batch(after[&log].len(), restore_sequence, &restore_rows)?;
    let total = after.values().map(Vec::len).sum::<usize>();
    if total
        .checked_add(restore_append.len())
        .is_none_or(|n| n > leveldb_format::MAX_BYTES)
    {
        return Err("The reviewed Site storage restore would exceed its content limit; no keys were changed.".into());
    }
    let mut expected = image.records;
    for (key, _) in &originals {
        expected.remove(key);
    }
    if observed != expected {
        return Err("The planned Site storage deletion changed unreviewed keys.".into());
    }
    Ok(Mutation {
        log: log.clone(),
        before_len: before.len(),
        after_hash: digest(&after[&log]),
        append,
        originals,
        sequence,
    })
}

/// Existing files only. The LOCK handle and read/write-sharing restrictions
/// stay alive through verification and receipt. The source writer is opened
/// only after the caller has durably recorded its intent.
struct Lease {
    _lock: File,
    _directories: Vec<File>,
    files: BTreeMap<String, File>,
    writer: File,
    log: String,
}
impl Lease {
    #[cfg(windows)]
    fn acquire(store: &Store, log: &str) -> Result<Self, String> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        let path = store.path();
        store.scope()?;
        if Some(log) != store.log.as_deref()
            || leveldb::names(&store.root, &path, &AtomicBool::new(false))?
                != store.files.keys().cloned().collect::<Vec<_>>()
        {
            return Err("Site storage locked membership differs from review.".into());
        }
        let mut directories = Vec::new();
        let relative = path
            .strip_prefix(&store.root)
            .map_err(|_| "Browser key store is outside the profile.")?;
        let mut ancestors = vec![store.root.clone()];
        let mut current = store.root.clone();
        for part in relative.components() {
            let std::path::Component::Normal(name) = part else {
                return Err("Invalid browser key-store ancestry.".into());
            };
            current.push(name);
            ancestors.push(current.clone());
        }
        for dir in ancestors {
            safe_profile_root(&dir)?;
            let file = OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES.0)
                .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
                .open(&dir)
                .map_err(|_| "Site storage directory could not be held against replacement.")?;
            if is_link(
                &file
                    .metadata()
                    .map_err(|_| "Site storage directory handle is unavailable.")?,
            ) {
                return Err("Site storage directory handle is linked.".into());
            }
            directories.push(file);
        }
        validate_database_path(&store.root, &path.join("LOCK"))?;
        let lock = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path.join("LOCK"))
            .map_err(|_| "Site storage is already open or cannot be locked.")?;
        lock.try_lock()
            .map_err(|_| "Site storage is already locked.")?;
        if storage_files::identity(&lock)?
            != store
                .files
                .get("LOCK")
                .ok_or("Missing reviewed Site storage LOCK.")?
                .identity
        {
            return Err("Site storage LOCK identity changed.".into());
        }
        validate_database_path(&store.root, &path.join(log))?;
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path.join(log))
            .map_err(|_| "Site storage append log could not be held for writing.")?;
        if storage_files::identity(&writer)?
            != store
                .files
                .get(log)
                .ok_or("Missing reviewed Site storage log.")?
                .identity
        {
            return Err("Site storage log identity changed.".into());
        }
        let mut held = BTreeMap::new();
        for (name, signature) in &store.files {
            if name == "LOCK" || name == log {
                continue;
            }
            validate_database_path(&store.root, &path.join(name))?;
            let file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ.0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
                .open(path.join(name))
                .map_err(|_| "A Site storage source file is open or unavailable.")?;
            if storage_files::identity(&file)? != signature.identity {
                return Err("Site storage file identity changed.".into());
            }
            held.insert(name.clone(), file);
        }
        Ok(Self {
            _lock: lock,
            _directories: directories,
            files: held,
            writer,
            log: log.into(),
        })
    }
    #[cfg(not(windows))]
    fn acquire(_: &Store, _: &str) -> Result<Self, String> {
        Err("Site storage native cleanup locking is not verified on this platform.".into())
    }

    fn observe(
        &mut self,
        store: &Store,
        cancel: &AtomicBool,
    ) -> Result<BTreeMap<String, Vec<u8>>, String> {
        let expected = store.files.keys().cloned().collect::<Vec<_>>();
        if leveldb::names(&store.root, &store.path(), cancel)? != expected {
            return Err("Site storage membership changed while locked.".into());
        }
        let mut output = BTreeMap::new();
        let mut total = 0usize;
        for (name, file) in self
            .files
            .iter_mut()
            .chain(std::iter::once((&self.log, &mut self.writer)))
        {
            if cancel.load(Ordering::Relaxed) {
                return Err("Site storage operation stopped.".into());
            }
            let length = file
                .metadata()
                .map_err(|_| "Site storage held file is unavailable.")?
                .len();
            total = total
                .checked_add(usize::try_from(length).map_err(|_| "Site storage length overflow.")?)
                .ok_or("Site storage size overflow.")?;
            if total > leveldb_format::MAX_BYTES {
                return Err("Site storage locked snapshot limit reached.".into());
            }
            file.seek(SeekFrom::Start(0))
                .map_err(|_| "Site storage held read could not seek.")?;
            let mut bytes = Vec::with_capacity(length as usize);
            let mut buffer = [0; 65536];
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Site storage operation stopped.".into());
                }
                let n = file
                    .read(&mut buffer)
                    .map_err(|_| "Site storage held read failed.")?;
                if n == 0 {
                    break;
                }
                if bytes.len().saturating_add(n) > length as usize {
                    return Err("Site storage held file grew.".into());
                }
                bytes.extend_from_slice(&buffer[..n]);
            }
            if bytes.len() != length as usize {
                return Err("Site storage held file was truncated.".into());
            }
            output.insert(name.clone(), bytes);
        }
        Ok(output)
    }

    fn append(&mut self, expected_len: usize, bytes: &[u8]) -> Result<(), String> {
        if self
            .writer
            .seek(SeekFrom::End(0))
            .map_err(|_| "Site storage log could not seek.")?
            != expected_len as u64
        {
            return Err("Site storage append position changed.".into());
        }
        self.writer
            .write_all(bytes)
            .and_then(|_| self.writer.sync_all())
            .map_err(|_| "Site storage append or sync failed; its outcome is uncertain.".into())
    }
}

const MAX_INTENT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupKey {
    id: Uuid,
    key: Vec<u8>,
    value: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u32,
    id: Uuid,
    operation: Uuid,
    store: Store,
    log: String,
    before_len: usize,
    sequence: u64,
    append: Vec<u8>,
    after_hash: [u8; 32],
    keys: Vec<BackupKey>,
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Info {
    id: Uuid,
    operation: Uuid,
    browser: Browser,
    profile_name: String,
    root: PathBuf,
    records: usize,
    intent_hash: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum Outcome {
    Confirmed,
    Refused,
    Uncertain,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Start { info: Info },
    Done { outcome: Outcome },
    RestoreStart { id: Uuid, current_hash: [u8; 32] },
    RestoreDone { restored: bool },
}
struct Journal {
    file: File,
}
impl Journal {
    fn append(&mut self, event: &Event) -> Result<(), String> {
        let mut bytes =
            serde_json::to_vec(event).map_err(|_| "Site storage journal could not be encoded.")?;
        bytes.push(b'\n');
        self.file
            .write_all(&bytes)
            .and_then(|_| self.file.sync_all())
            .map_err(|_| "Site storage journal could not be synced.".into())
    }
}
#[derive(Clone)]
struct Entry {
    info: Info,
    outcome: Option<Outcome>,
    restore: Option<bool>,
    restore_pending: bool,
}

fn private_dir(data_dir: &Path, create: bool) -> Result<PathBuf, String> {
    if create {
        create_private_dir(data_dir)?;
    }
    let data_dir = safe_profile_root(data_dir)?;
    let path = data_dir.join("privacy-leveldb");
    match fs::symlink_metadata(&path) {
        Err(e) if create && e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&path)
                .map_err(|_| "Site storage recovery directory could not be created.")?;
            create_private_dir(&path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(path),
        Err(_) => return Err("Site storage recovery directory is unavailable.".into()),
        Ok(_) => {}
    }
    safe_profile_root(&path)?;
    Ok(path)
}
fn durable_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() as u64 > MAX_INTENT_BYTES {
        return Err("Site storage recovery content limit reached.".into());
    }
    let mut file = private_file_options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "Site storage recovery file could not be created.")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "Site storage recovery file could not be synced.")?;
    sync_directory(path.parent().ok_or("Missing recovery parent.")?)
}
fn private_read(root: &Path, path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut file = storage_files::open_file(root, path)?;
    storage_files::identity(&file)?;
    let size = file
        .metadata()
        .map_err(|_| "Site storage recovery metadata is unavailable.")?
        .len();
    if size > limit {
        return Err("Site storage recovery file limit reached.".into());
    }
    let mut bytes = Vec::with_capacity(size as usize);
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Site storage recovery file could not be read.")?;
    if bytes.len() as u64 != size {
        return Err("Site storage recovery file changed while reading.".into());
    }
    Ok(bytes)
}
fn entries(data_dir: &Path) -> Result<Vec<Entry>, String> {
    if !data_dir
        .try_exists()
        .map_err(|_| "Recovery storage could not be checked.")?
    {
        return Ok(Vec::new());
    }
    let root = private_dir(data_dir, false)?;
    if !root
        .try_exists()
        .map_err(|_| "Site storage recovery directory could not be checked.")?
    {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut count = 0;
    let mut total = 0usize;
    for item in
        fs::read_dir(&root).map_err(|_| "Site storage recovery directory could not be read.")?
    {
        count += 1;
        if count > 4096 {
            return Err("Site storage recovery inventory limit reached.".into());
        }
        let path = item
            .map_err(|_| "Site storage recovery entry is unavailable.")?
            .path();
        if path.extension().is_none_or(|ext| ext != "jsonl") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or("Invalid Site storage journal name.")?;
        if path.file_name().and_then(|s| s.to_str()) != Some(format!("{id}.jsonl").as_str()) {
            return Err("Noncanonical Site storage journal name.".into());
        }
        let bytes = private_read(&root, &path, MAX_JOURNAL_BYTES)?;
        total = total.saturating_add(bytes.len());
        if total > 32 * 1024 * 1024 {
            return Err("Site storage recovery metadata budget reached.".into());
        }
        if !bytes.ends_with(b"\n") {
            return Err(
                "Site storage journal has an incomplete tail; no retry was attempted.".into(),
            );
        }
        let mut entry = None::<Entry>;
        for line in bytes.split(|&b| b == b'\n').filter(|line| !line.is_empty()) {
            let event: Event = serde_json::from_slice(line)
                .map_err(|_| "Site storage journal is invalid; no retry was attempted.")?;
            match event {
                Event::Start { info }
                    if entry.is_none()
                        && info.id == id
                        && info.records > 0
                        && info.records <= MAX_RECORDS =>
                {
                    entry = Some(Entry {
                        info,
                        outcome: None,
                        restore: None,
                        restore_pending: false,
                    })
                }
                Event::Done { outcome }
                    if entry.as_ref().is_some_and(|e| {
                        e.outcome.is_none() && !e.restore_pending && e.restore.is_none()
                    }) =>
                {
                    entry.as_mut().unwrap().outcome = Some(outcome)
                }
                Event::RestoreStart { .. }
                    if entry.as_ref().is_some_and(|e| {
                        e.outcome == Some(Outcome::Confirmed)
                            && e.restore.is_none()
                            && !e.restore_pending
                    }) =>
                {
                    entry.as_mut().unwrap().restore_pending = true
                }
                Event::RestoreDone { restored }
                    if entry.as_ref().is_some_and(|e| e.restore_pending) =>
                {
                    let e = entry.as_mut().unwrap();
                    e.restore_pending = false;
                    e.restore = Some(restored);
                }
                _ => return Err("Site storage journal event order is invalid.".into()),
            }
        }
        out.push(entry.ok_or("Site storage journal has no durable start.")?);
    }
    Ok(out)
}
fn load_intent(data_dir: &Path, entry: &Entry) -> Result<Intent, String> {
    let root = private_dir(data_dir, false)?;
    let bytes = private_read(
        &root,
        &root.join(format!("{}.json", entry.info.id)),
        MAX_INTENT_BYTES,
    )?;
    if digest(&bytes) != entry.info.intent_hash {
        return Err("Site storage recovery intent changed.".into());
    }
    let intent: Intent =
        serde_json::from_slice(&bytes).map_err(|_| "Site storage recovery intent is invalid.")?;
    intent.store.scope()?;
    if intent.version != 1
        || intent.id != entry.info.id
        || intent.operation != entry.info.operation
        || intent.store.browser != entry.info.browser
        || intent.store.profile_name != entry.info.profile_name
        || intent.store.root != entry.info.root
        || intent.keys.len() != entry.info.records
        || Some(&intent.log) != intent.store.log.as_ref()
    {
        return Err("Site storage recovery identity does not match its durable journal.".into());
    }
    let mut ids = HashSet::new();
    let mut keys = BTreeSet::new();
    for key in &intent.keys {
        if !ids.insert(key.id)
            || !keys.insert(&key.key)
            || normalize_cookie_domain(&leveldb::site(&key.key)?).is_err()
        {
            return Err("Site storage recovery keys are invalid or duplicated.".into());
        }
    }
    let rows = intent
        .keys
        .iter()
        .map(|k| (k.key.clone(), None))
        .collect::<Vec<_>>();
    if leveldb_format::append_batch(intent.before_len, intent.sequence, &rows)? != intent.append {
        return Err("Site storage recovery append is not its exact selected-key batch.".into());
    }
    Ok(intent)
}
fn current_keeps(data_dir: &Path, selected: &[Review]) -> Result<(), String> {
    let saved = load_cookie_exception_settings(data_dir)?;
    let keep: HashSet<_> = saved.keep_domains.into_iter().collect();
    for review in selected {
        if keep != *review.keep || is_cookie_exception(&review.raw_site, &keep) {
            return Err("Site storage keep policy changed since review.".into());
        }
    }
    Ok(())
}
pub(super) fn preflight(runtime: &impl BrowserRuntime, selected: &[Review]) -> Result<(), String> {
    for review in selected {
        if let Some(reason) = review.unavailable_reason() {
            return Err(reason.into());
        }
        review.store.as_ref().unwrap().stopped(runtime)?;
    }
    Ok(())
}
fn blocked(data_dir: &Path, entries: &[Entry], store: &Store) -> Result<bool, String> {
    if entries.is_empty() {
        return Ok(false);
    }
    let root = private_dir(data_dir, false)?;
    let mut pending = 0;
    let mut budget = MAX_INTENT_BYTES;
    for entry in entries.iter().filter(|entry| {
        entry.outcome.is_none()
            || entry.outcome == Some(Outcome::Uncertain)
            || entry.restore_pending
            || entry.restore == Some(false)
    }) {
        pending += 1;
        if pending > 32 {
            return Err(
                "Too many unresolved Site storage operations; review recovery before cleanup."
                    .into(),
            );
        }
        let path = root.join(format!("{}.json", entry.info.id));
        let size = fs::symlink_metadata(&path)
            .map_err(|_| "An unresolved Site storage backup is unavailable.")?
            .len();
        budget = budget
            .checked_sub(size)
            .ok_or("Unresolved Site storage verification budget reached.")?;
        // Authenticate the display/namespace header against the actual durable
        // intent too; damaged metadata must not bypass a previous-write block.
        let intent = load_intent(data_dir, entry)?;
        if same_named_path(&intent.store.root, &store.root) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn clean(
    data_dir: &Path,
    operation: Uuid,
    selected: &[Review],
    cancel: &AtomicBool,
    runtime: &impl BrowserRuntime,
) -> Result<PrivacyReceipt, String> {
    preflight(runtime, selected)?;
    let mut groups = BTreeMap::<String, Vec<Review>>::new();
    for review in selected {
        groups
            .entry(storage_files::path_key(
                &review.store.as_ref().unwrap().root,
            ))
            .or_default()
            .push(review.clone());
    }
    let mut receipt = PrivacyReceipt {
        id: operation,
        selected: selected.len(),
        ..Default::default()
    };
    for reviews in groups.values() {
        if cancel.load(Ordering::Relaxed) {
            receipt.cancelled = true;
            receipt.skipped += reviews.len();
            continue;
        }
        match clean_group(
            data_dir,
            operation,
            reviews,
            cancel,
            runtime,
            |lease, mutation| lease.append(mutation.before_len, &mutation.append),
        ) {
            Ok(result) => {
                receipt.deleted += result.deleted;
                receipt.skipped += result.skipped;
                receipt.uncertain |= result.uncertain;
                receipt.backups.extend(result.backups);
                receipt.errors.extend(result.errors);
            }
            Err(reason) => {
                receipt.skipped += reviews.len();
                receipt.errors.push(reason);
            }
        }
    }
    Ok(receipt)
}
fn clean_group(
    data_dir: &Path,
    operation: Uuid,
    selected: &[Review],
    cancel: &AtomicBool,
    runtime: &impl BrowserRuntime,
    effect: impl FnOnce(&mut Lease, &Mutation) -> Result<(), String>,
) -> Result<PrivacyReceipt, String> {
    let store = selected
        .first()
        .and_then(|r| r.store.as_ref())
        .ok_or("Select exact reviewed Site storage keys.")?;
    store.stopped(runtime)?;
    current_keeps(data_dir, selected)?;
    if blocked(data_dir, &entries(data_dir)?, store)? {
        return Err("Site storage has an unresolved earlier write. Review recovery before another cleanup; no retry was attempted.".into());
    }
    let files = leveldb::snapshot(
        &store.root,
        &store.path(),
        cancel,
        &mut leveldb::scan_budget(),
    )?;
    let mutation = deletions(&files, selected, cancel)?;
    let id = Uuid::new_v4();
    let intent = Intent {
        version: 1,
        id,
        operation,
        store: store.as_ref().clone(),
        log: mutation.log.clone(),
        before_len: mutation.before_len,
        sequence: mutation.sequence,
        append: mutation.append.clone(),
        after_hash: mutation.after_hash,
        keys: selected
            .iter()
            .zip(&mutation.originals)
            .map(|(review, (key, value))| BackupKey {
                id: review.id,
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
    };
    let bytes =
        serde_json::to_vec(&intent).map_err(|_| "Site storage backup could not be encoded.")?;
    let root = private_dir(data_dir, true)?;
    let backup = root.join(format!("{id}.json"));
    durable_file(&backup, &bytes)?;
    let mut journal = Journal {
        file: journal_options()
            .create_new(true)
            .write(true)
            .open(root.join(format!("{id}.jsonl")))
            .map_err(|_| "Site storage journal could not be created.")?,
    };
    journal.append(&Event::Start {
        info: Info {
            id,
            operation,
            browser: store.browser,
            profile_name: store.profile_name.clone(),
            root: store.root.clone(),
            records: selected.len(),
            intent_hash: digest(&bytes),
        },
    })?;
    sync_directory(&root)?;
    let mut attempted = false;
    let mut held_lease = None;
    let result = (|| -> Result<(), String> {
        if cancel.load(Ordering::Relaxed) {
            return Err("Site storage cleanup stopped before its write.".into());
        }
        store.stopped(runtime)?;
        current_keeps(data_dir, selected)?;
        held_lease = Some(Lease::acquire(store, &mutation.log)?);
        let lease = held_lease.as_mut().unwrap();
        let held = lease.observe(store, cancel)?;
        store.verify(&held, true)?;
        if held != files {
            return Err("Site storage changed after its durable intent.".into());
        }
        store.stopped(runtime)?;
        current_keeps(data_dir, selected)?;
        if cancel.load(Ordering::Relaxed) {
            return Err("Site storage cleanup stopped before its write.".into());
        }
        attempted = true;
        effect(lease, &mutation)?;
        // Verification must finish after an attempted write, even if cancelled.
        let after = lease.observe(store, &AtomicBool::new(false))?;
        let mut expected = files.clone();
        expected
            .get_mut(&mutation.log)
            .unwrap()
            .extend(&mutation.append);
        if after != expected || digest(&after[&mutation.log]) != mutation.after_hash {
            return Err("Site storage post-write image differs; no retry was attempted.".into());
        }
        leveldb_format::read(&after, &AtomicBool::new(false))?;
        Ok(())
    })();
    let mut receipt = PrivacyReceipt {
        id: operation,
        selected: selected.len(),
        backups: vec![backup],
        ..Default::default()
    };
    let outcome = if result.is_ok() {
        Outcome::Confirmed
    } else if attempted {
        Outcome::Uncertain
    } else {
        Outcome::Refused
    };
    if let Err(reason) = result {
        receipt.errors.push(reason);
    }
    if journal.append(&Event::Done { outcome }).is_err() {
        receipt.uncertain = true;
        receipt
            .errors
            .push("Site storage receipt could not be synced; no retry was attempted.".into());
    }
    receipt.uncertain |= outcome == Outcome::Uncertain;
    receipt.cancelled = cancel.load(Ordering::Relaxed);
    if outcome == Outcome::Confirmed && !receipt.uncertain {
        receipt.deleted = selected.len();
    } else {
        receipt.skipped = selected.len();
    }
    Ok(receipt)
}

pub(super) fn options(data_dir: &Path) -> Result<Vec<PrivacyRestoreOption>, String> {
    Ok(entries(data_dir)?.into_iter().map(|entry| {
        let state = if entry.restore == Some(true) { PrivacyRecoveryState::Restored } else if entry.restore_pending || entry.restore == Some(false) || entry.outcome.is_none() || entry.outcome == Some(Outcome::Uncertain) { PrivacyRecoveryState::Uncertain } else if entry.outcome == Some(Outcome::Confirmed) { PrivacyRecoveryState::Ready } else { PrivacyRecoveryState::Unavailable };
        PrivacyRestoreOption { id: entry.info.id, browser: entry.info.browser, profile_name: entry.info.profile_name, database_name: "Site storage".into(), categories: vec![PrivacyCategory::Cookies], record_count: entry.info.records, state, reason: match state { PrivacyRecoveryState::Uncertain => Some("A Site storage write or receipt is unresolved. Its exact key/value backup is retained; automatic retry and restore are blocked.".into()), PrivacyRecoveryState::Unavailable => Some("The Site storage write was refused before changing keys.".into()), _ => None } }
    }).collect())
}
pub(super) fn recovery(data_dir: &Path) -> Result<Vec<PrivacyRecoveryItem>, String> {
    let root = private_dir(data_dir, false).or_else(|error| {
        if !data_dir.exists() {
            Ok(data_dir.join("privacy-leveldb"))
        } else {
            Err(error)
        }
    })?;
    entries(data_dir)?
        .into_iter()
        .filter(|e| {
            e.outcome.is_none()
                || e.outcome == Some(Outcome::Uncertain)
                || e.restore_pending
                || e.restore == Some(false)
        })
        .map(|entry| {
            let intent = load_intent(data_dir, &entry)?;
            Ok(PrivacyRecoveryItem {
                operation_id: intent.operation,
                database: intent.store.path(),
                backup: root.join(format!("{}.json", intent.id)),
                unresolved_ids: intent.keys.iter().map(|k| k.id).collect(),
                uncertain: true,
            })
        })
        .collect()
}

#[derive(Clone)]
pub(super) struct Restore {
    id: Uuid,
    info: Info,
    intent: Intent,
    current: Store,
}
fn post_store(intent: &Intent, files: &BTreeMap<String, Vec<u8>>) -> Result<Store, String> {
    let mut post = intent.store.clone();
    let source = post
        .files
        .get_mut(&intent.log)
        .ok_or("Missing Site storage recovery log binding.")?;
    source.hash = Some(intent.after_hash);
    source.stamp.length = (intent.before_len + intent.append.len()) as u64;
    post.verify(files, false)?;
    // Bind the exact current timestamps for the subsequent reviewed action.
    let path = post.path();
    for (name, signature) in &mut post.files {
        signature.stamp = file_stamp(&path.join(name))?;
    }
    Ok(post)
}
pub(super) fn prepare_restore(
    data_dir: &Path,
    id: Uuid,
    runtime: &impl BrowserRuntime,
) -> Result<Option<PrivacyRestorePlan>, String> {
    let Some(entry) = entries(data_dir)?.into_iter().find(|e| e.info.id == id) else {
        return Ok(None);
    };
    if entry.outcome != Some(Outcome::Confirmed) || entry.restore.is_some() || entry.restore_pending
    {
        return Err("Site storage recovery is not available for a new restore.".into());
    }
    let intent = load_intent(data_dir, &entry)?;
    intent.store.stopped(runtime)?;
    let files = leveldb::snapshot(
        &intent.store.root,
        &intent.store.path(),
        &AtomicBool::new(false),
        &mut leveldb::scan_budget(),
    )?;
    let current = post_store(&intent, &files)?;
    let image = leveldb_format::inspect(&files, &AtomicBool::new(false))?;
    if intent
        .keys
        .iter()
        .any(|key| image.records.contains_key(&key.key))
    {
        return Err("A cleaned Site storage key is present again; restore was refused.".into());
    }
    let root = private_dir(data_dir, false)?;
    Ok(Some(PrivacyRestorePlan {
        id,
        operation_id: intent.operation,
        browser: intent.store.browser,
        profile_name: intent.store.profile_name.clone(),
        database_name: "Site storage".into(),
        profile_root: intent.store.root.clone(),
        database: intent.store.path(),
        backup: root.join(format!("{id}.json")),
        post_state_snapshot: root.join(format!("{id}.jsonl")),
        post_state_stamp: FileStamp::default(),
        schema_signature: String::new(),
        leveldb: Some(Restore {
            id,
            info: entry.info,
            intent,
            current,
        }),
        preferences: None,
    }))
}
pub(super) fn restore(
    data_dir: &Path,
    plan: &Restore,
    runtime: &impl BrowserRuntime,
) -> Result<PrivacyRestoreReceipt, String> {
    let current_plan = prepare_restore(data_dir, plan.id, runtime)?
        .ok_or("Site storage recovery item disappeared.")?;
    let current = current_plan
        .leveldb
        .as_ref()
        .ok_or("Site storage restore owner changed.")?;
    if current.info != plan.info || current.current != plan.current {
        return Err("Site storage restore review changed. Prepare a new review.".into());
    }
    let intent = &current.intent;
    let store = &current.current;
    let cancelled = AtomicBool::new(false);
    let files = leveldb::snapshot(
        &store.root,
        &store.path(),
        &cancelled,
        &mut leveldb::scan_budget(),
    )?;
    store.verify(&files, true)?;
    let image = leveldb_format::inspect(&files, &cancelled)?;
    let rows = intent
        .keys
        .iter()
        .map(|key| (key.key.clone(), Some(key.value.clone())))
        .collect::<Vec<_>>();
    let before = &files[&intent.log];
    let append = leveldb_format::append_batch(
        before.len(),
        image
            .last_sequence
            .checked_add(1)
            .ok_or("Site storage sequence exhausted.")?,
        &rows,
    )?;
    let mut expected_files = files.clone();
    expected_files.get_mut(&intent.log).unwrap().extend(&append);
    let mut expected_keys = image.records;
    for key in &intent.keys {
        expected_keys.insert(key.key.clone(), key.value.clone());
    }
    if leveldb_format::read(&expected_files, &cancelled)? != expected_keys {
        return Err("The planned restore changed unrelated Site storage keys.".into());
    }
    let restore_id = Uuid::new_v4();
    let root = private_dir(data_dir, false)?;
    let backup = root.join(format!("current-state-{restore_id}.log"));
    durable_file(&backup, before)?;
    let path = root.join(format!("{}.jsonl", plan.id));
    validate_database_path(&root, &path)?;
    let expected_journal_identity =
        storage_files::identity(&storage_files::open_file(&root, &path)?)?;
    let mut journal = Journal {
        file: journal_options()
            .append(true)
            .open(&path)
            .map_err(|_| "Site storage restore journal could not be opened.")?,
    };
    if storage_files::identity(&journal.file)? != expected_journal_identity {
        return Err("Site storage restore journal was replaced.".into());
    }
    let locked = entries(data_dir)?
        .into_iter()
        .find(|e| e.info.id == plan.id)
        .ok_or("Site storage restore journal disappeared.")?;
    if locked.info != plan.info
        || locked.restore.is_some()
        || locked.restore_pending
        || locked.outcome != Some(Outcome::Confirmed)
    {
        return Err("Site storage restore journal changed after review.".into());
    }
    journal.append(&Event::RestoreStart {
        id: restore_id,
        current_hash: digest(before),
    })?;
    let mut attempted = false;
    let mut held_lease = None;
    let result = (|| -> Result<(), String> {
        store.stopped(runtime)?;
        held_lease = Some(Lease::acquire(store, &intent.log)?);
        let lease = held_lease.as_mut().unwrap();
        let held = lease.observe(store, &cancelled)?;
        store.verify(&held, true)?;
        if held != files {
            return Err("Site storage changed after restore intent.".into());
        }
        store.stopped(runtime)?;
        attempted = true;
        lease.append(before.len(), &append)?;
        let after = lease.observe(store, &cancelled)?;
        if after != expected_files || leveldb_format::read(&after, &cancelled)? != expected_keys {
            return Err("Site storage restore post-state could not be verified.".into());
        }
        Ok(())
    })();
    let mut receipt = PrivacyRestoreReceipt {
        id: restore_id,
        source_operation_id: intent.operation,
        current_state_backup: Some(backup),
        ..Default::default()
    };
    let restored = result.is_ok();
    if let Err(reason) = result {
        receipt.errors.push(reason);
        receipt.uncertain = attempted;
    }
    if journal.append(&Event::RestoreDone { restored }).is_err() {
        receipt.uncertain = true;
        receipt
            .errors
            .push("Site storage restore receipt could not be synced.".into());
    }
    receipt.restored = restored && !receipt.uncertain;
    Ok(receipt)
}

fn journal_options() -> OpenOptions {
    let mut options = private_file_options();
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
        options
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
    }
    options
}

/// Render-only capabilities. Confirmation is blocked by the QA event owner;
/// these deliberately nonexistent sources can never pass native preflight.
#[cfg(debug_assertions)]
pub(super) fn preview(profile: &BrowserProfile, id: Uuid, site: &str, available: bool) -> Review {
    let store = available.then(|| {
        Arc::new(Store {
            browser: profile.browser,
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            root: profile.root.clone(),
            directory: None,
            files: BTreeMap::new(),
            log: Some("000003.log".into()),
            last_sequence: 1,
        })
    });
    Review::new(
        id,
        store,
        format!("_https://{site}\0{id}").into_bytes(),
        b"synthetic value",
        site.into(),
        Arc::new(HashSet::new()),
    )
}

#[cfg(debug_assertions)]
pub(super) fn preview_restore(profile: &BrowserProfile) -> PrivacyRestorePlan {
    let id = Uuid::from_u128(0x4443_4c45_414e_4552_4c44_4252_0000_0001);
    let review = preview(profile, id, "example.test", true);
    let store = review.store.unwrap().as_ref().clone();
    let info = Info {
        id,
        operation: id,
        browser: profile.browser,
        profile_name: profile.name.clone(),
        root: profile.root.clone(),
        records: 1,
        intent_hash: [0; 32],
    };
    let intent = Intent {
        version: 1,
        id,
        operation: id,
        store: store.clone(),
        log: "000003.log".into(),
        before_len: 0,
        sequence: 1,
        append: Vec::new(),
        after_hash: [0; 32],
        keys: Vec::new(),
    };
    PrivacyRestorePlan {
        id,
        operation_id: id,
        browser: profile.browser,
        profile_name: profile.name.clone(),
        database_name: "Site storage".into(),
        profile_root: profile.root.clone(),
        database: store.path(),
        backup: PathBuf::new(),
        post_state_snapshot: PathBuf::new(),
        post_state_stamp: FileStamp::default(),
        schema_signature: String::new(),
        leveldb: Some(Restore {
            id,
            info,
            intent,
            current: store,
        }),
        preferences: None,
    }
}

#[cfg(test)]
#[path = "leveldb_write_tests.rs"]
mod tests;
