//! Exact reviewed JSON members and session formats with held native writes and recovery.
//! A failed write can be partial. It is never automatically retried or restored.
use super::*;
use json_members::{Document, Field};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Seek, SeekFrom},
    sync::Arc,
};

const MAX_META: usize = 256 * 1024;
const MAX_ENTRIES: usize = 512;
const MAX_FIELDS: usize = 6;
const MAX_IMAGE_BYTES: usize = moz_lz4::MAX_CARRIER;
pub(super) const SESSION_BUDGET_ERROR: &str = "Session decoded-content observation budget reached.";
pub(super) enum SessionDisposition {
    Trash,
    Rewrite { skipped_windows: usize },
}
enum SessionChange {
    Trash,
    Rewrite {
        bytes: Vec<u8>,
        skipped_windows: usize,
    },
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signature {
    identity: (u64, u64),
    stamp: FileStamp,
    hash: [u8; 32],
}
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    browser: Browser,
    profile_id: String,
    profile_name: String,
    root: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relative: Option<PathBuf>,
    signature: Signature,
}
impl Source {
    fn session_target(&self) -> Option<SessionTarget> {
        if self.relative.is_none() {
            return None;
        }
        Some(
            match session_files::format(self.browser, &self.root, &self.path())? {
                session_files::Format::Chromium => SessionTarget::SessionFile,
                session_files::Format::MozillaJson => SessionTarget::MozillaJson,
                session_files::Format::MozillaLz4 => SessionTarget::MozillaLz4,
            },
        )
    }
    fn path(&self) -> PathBuf {
        self.root
            .join(self.relative.as_deref().unwrap_or(Path::new("Preferences")))
    }
    fn owns(&self) -> bool {
        if let Some(relative) = &self.relative {
            if relative.is_absolute()
                || relative
                    .components()
                    .any(|p| !matches!(p, std::path::Component::Normal(_)))
            {
                return false;
            }
            session_files::claims(self.browser, &self.root, &self.path())
        } else {
            owns(self.browser, &self.root, &self.path())
        }
    }
    fn version(&self) -> u32 {
        match self.session_target() {
            Some(SessionTarget::MozillaJson | SessionTarget::MozillaLz4) => 3,
            _ if self.relative.is_some() => 2,
            _ => 1,
        }
    }
    fn valid_targets(&self, fields: &[Target]) -> bool {
        self.owns()
            && fields.iter().all(|f| f.supported_for(self.browser))
            && if self.relative.is_some() {
                self.session_target()
                    .is_some_and(|target| fields == [Target::Session(target)])
            } else {
                !fields.is_empty()
                    && fields.len() <= MAX_FIELDS
                    && fields.iter().all(|f| matches!(f, Target::Json(_)))
            }
    }
    fn transform(
        &self,
        before: &[u8],
        fields: &[Target],
        cancel: &AtomicBool,
    ) -> Result<Vec<u8>, String> {
        if !self.valid_targets(fields) {
            return Err("Browser data target ownership changed.".into());
        }
        if self.relative.is_some() {
            match self.session_change(before, cancel)? {
                SessionChange::Rewrite { bytes, .. } => Ok(bytes),
                SessionChange::Trash => {
                    Err("Session no longer has the reviewed pinned-state rewrite.".into())
                }
            }
        } else {
            let fields = fields
                .iter()
                .filter_map(|f| match f {
                    Target::Json(field) => Some(*field),
                    _ => None,
                })
                .collect::<Vec<_>>();
            Document::parse(before, cancel)?.apply_fields(&fields)
        }
    }
    fn session_change(&self, bytes: &[u8], cancel: &AtomicBool) -> Result<SessionChange, String> {
        match self
            .session_target()
            .ok_or("Session source no longer has declared format ownership.")?
        {
            SessionTarget::SessionFile => match session_binary::Document::parse(bytes, cancel)?
                .plan(cancel)?
            {
                session_binary::Plan::DeleteFile => Ok(SessionChange::Trash),
                session_binary::Plan::RewritePinned { bytes, .. } => Ok(SessionChange::Rewrite {
                    bytes,
                    skipped_windows: 0,
                }),
            },
            target => {
                let encoding = if target == SessionTarget::MozillaJson {
                    session_mozilla::Encoding::Json
                } else {
                    session_mozilla::Encoding::MozLz4
                };
                match session_mozilla::plan(bytes, encoding, cancel)? {
                    session_mozilla::Plan::DeleteFile => Ok(SessionChange::Trash),
                    session_mozilla::Plan::RewritePinned {
                        bytes,
                        skipped_windows,
                        ..
                    } => Ok(SessionChange::Rewrite {
                        bytes,
                        skipped_windows,
                    }),
                }
            }
        }
    }
    fn validate_format(&self, bytes: &[u8]) -> Result<(), String> {
        if self.relative.is_some() {
            self.session_change(bytes, &AtomicBool::new(false))
                .map(|_| ())
        } else {
            Document::parse(bytes, &AtomicBool::new(false)).map(|_| ())
        }
    }
    fn display_name(&self) -> String {
        if self.relative.is_none() {
            return "Preferences".into();
        }
        self.relative
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/")
            .chars()
            .map(|c| if c.is_control() { '\u{fffd}' } else { c })
            .collect()
    }
    fn stopped(&self, runtime: &impl BrowserRuntime) -> Result<(), String> {
        if !self.owns() {
            return Err("Browser data source ownership changed.".into());
        }
        if runtime
            .running_browsers()?
            .iter()
            .any(|p| self.browser.conflicts_with(p))
        {
            return Err("Close the selected browser before changing browser data.".into());
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "preferences_mozilla_tests.rs"]
mod mozilla_tests;
#[cfg(test)]
#[path = "preferences_session_tests.rs"]
mod session_tests;
// Untagged JSON targets retain the exact legacy journal field spelling. The
// new session target has a distinct spelling and requires source schema2.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
enum Target {
    Json(Field),
    Session(SessionTarget),
}
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SessionTarget {
    SessionFile,
    MozillaJson,
    MozillaLz4,
}
impl From<Field> for Target {
    fn from(field: Field) -> Self {
        Self::Json(field)
    }
}
impl PartialEq<Field> for Target {
    fn eq(&self, field: &Field) -> bool {
        matches!(self,Self::Json(value) if value==field)
    }
}
impl Target {
    fn category(self) -> PrivacyCategory {
        match self {
            Self::Json(f) => f.category(),
            Self::Session(_) => PrivacyCategory::Sessions,
        }
    }
    fn supported_for(self, browser: Browser) -> bool {
        match self {
            Self::Json(f) => f.supported_for(browser),
            Self::Session(SessionTarget::SessionFile) => browser.is_chromium(),
            Self::Session(SessionTarget::MozillaJson | SessionTarget::MozillaLz4) => {
                matches!(browser, Browser::Firefox | Browser::Thunderbird)
            }
        }
    }
    fn cleanup_note(self) -> &'static str {
        match self {
            Self::Json(f) => f.cleanup_note(),
            Self::Session(SessionTarget::SessionFile) => {
                "Retains pinned-tab state and selected navigation entries. Other session records are removed; the session file stays in place."
            }
            Self::Session(SessionTarget::MozillaJson | SessionTarget::MozillaLz4) => {
                "Keeps pinned tabs and tabs without a pinned marker, including their navigation data. Other marked tabs and session metadata are removed; the session file stays in place."
            }
        }
    }
}
#[derive(Clone)]
pub(super) struct Review {
    pub id: Uuid,
    field: Target,
    source: Arc<Source>,
}
impl Review {
    pub(super) fn source_key(&self) -> String {
        storage_files::path_key(&self.source.path())
    }
    pub(super) fn is_session(&self) -> bool {
        matches!(self.field, Target::Session(_))
    }
    pub(super) fn session_source(&self) -> Option<String> {
        self.source.relative.as_ref().map(|p| {
            p.to_string_lossy()
                .chars()
                .map(|c| if c.is_control() { '\u{fffd}' } else { c })
                .collect()
        })
    }
    pub(super) fn matches_snapshot(
        &self,
        identity: (u64, u64),
        stamp: &FileStamp,
        hash: &[u8; 32],
    ) -> bool {
        self.source.signature.identity == identity
            && &self.source.signature.stamp == stamp
            && &self.source.signature.hash == hash
    }
    pub(super) fn cleanup_note(&self) -> &'static str {
        self.field.cleanup_note()
    }
    pub(super) fn unavailable_reason(&self) -> Option<&'static str> {
        if cfg!(windows) {
            None
        } else {
            Some("Browser preference cleanup locking is not verified on this platform.")
        }
    }
}
pub(super) fn owns(browser: Browser, root: &Path, path: &Path) -> bool {
    browser.is_chromium()
        && same_named_path(path, &root.join("Preferences"))
        && !record_files::claims(browser, PrivacyCategory::History, root, path)
}
fn stamp(file: &File) -> Result<FileStamp, String> {
    let meta = file
        .metadata()
        .map_err(|_| "Browser data metadata is unavailable.")?;
    if is_link(&meta) || !meta.is_file() {
        return Err("Browser preferences are linked or not a regular file.".into());
    }
    Ok(FileStamp {
        length: meta.len(),
        modified_ns: meta
            .modified()
            .map(timestamp)
            .map_err(|_| "Browser preference timestamp is unavailable.")?,
        created_ns: meta.created().ok().map(timestamp),
    })
}
fn read_held(file: &mut File, cancel: &AtomicBool) -> Result<(Vec<u8>, Signature), String> {
    let before = stamp(file)?;
    let identity = storage_files::identity(file)?;
    if before.length > MAX_IMAGE_BYTES as u64 {
        return Err("Browser data exceeds the safe size limit.".into());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "Browser data could not seek.")?;
    let mut bytes = Vec::with_capacity(before.length as usize);
    let mut buffer = [0u8; 65536];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("Browser preference observation was cancelled.".into());
        }
        let count = buffer.len().min(
            (before.length as usize)
                .saturating_sub(bytes.len())
                .saturating_add(1),
        );
        let n = file
            .read(&mut buffer[..count])
            .map_err(|_| "Browser data could not be read.")?;
        if n == 0 {
            break;
        }
        if bytes.len().saturating_add(n) > before.length as usize {
            return Err("Browser data changed while reading.".into());
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    if bytes.len() != before.length as usize
        || stamp(file)? != before
        || storage_files::identity(file)? != identity
    {
        return Err("Browser data changed while reading.".into());
    }
    let hash = digest(&bytes);
    Ok((
        bytes,
        Signature {
            identity,
            stamp: before,
            hash,
        },
    ))
}
fn capture(profile: &BrowserProfile, cancel: &AtomicBool) -> Result<(Source, Vec<u8>), String> {
    let path = profile.root.join("Preferences");
    capture_path(profile, &path, None, None, cancel)
}
fn capture_path(
    profile: &BrowserProfile,
    path: &Path,
    relative: Option<PathBuf>,
    expected: Option<&FileStamp>,
    cancel: &AtomicBool,
) -> Result<(Source, Vec<u8>), String> {
    if !(if relative.is_some() {
        session_files::claims(profile.browser, &profile.root, path)
    } else {
        owns(profile.browser, &profile.root, path)
    }) {
        return Err("This browser preference source has another owner.".into());
    }
    let mut file = storage_files::open_file(&profile.root, &path)?;
    if let Some(expected) = expected
        && &stamp(&file)? != expected
    {
        return Err("Browser data changed since enumeration.".into());
    }
    let (bytes, signature) = read_held(&mut file, cancel)?;
    if file_stamp(&path)? != signature.stamp
        || storage_files::identity(&storage_files::open_file(&profile.root, &path)?)?
            != signature.identity
    {
        return Err("Browser data was replaced during observation.".into());
    }
    Ok((
        Source {
            browser: profile.browser,
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            root: profile.root.clone(),
            relative,
            signature,
        },
        bytes,
    ))
}
pub(super) fn observe_session(
    profile: &BrowserProfile,
    path: &Path,
    stamp: &FileStamp,
    cancel: &AtomicBool,
    budget: &mut u64,
) -> Result<(Review, SessionDisposition), String> {
    let parts = storage_files::named_parts(&profile.root, path)
        .ok_or("Session path is outside the reviewed profile.")?;
    let relative = PathBuf::from(parts.join("/"));
    let (source, bytes) = capture_path(profile, path, Some(relative), Some(stamp), cancel)?;
    let target = source
        .session_target()
        .ok_or("Session source has no supported format.")?;
    if target == SessionTarget::MozillaLz4 {
        let decoded = moz_lz4::decoded_length(&bytes)? as u64;
        if decoded > *budget {
            return Err(SESSION_BUDGET_ERROR.into());
        }
        *budget -= decoded;
    }
    let disposition = match source.session_change(&bytes, cancel)? {
        SessionChange::Trash => SessionDisposition::Trash,
        SessionChange::Rewrite {
            skipped_windows, ..
        } => SessionDisposition::Rewrite { skipped_windows },
    };
    Ok((
        Review {
            id: Uuid::new_v4(),
            field: Target::Session(target),
            source: Arc::new(source),
        },
        disposition,
    ))
}
pub(super) fn scan(
    profile: &BrowserProfile,
    categories: &[PrivacyCategory],
    cancel: &AtomicBool,
    report: &mut PrivacyReport,
) {
    let categories = [
        PrivacyCategory::History,
        PrivacyCategory::LastDownloadLocation,
        PrivacyCategory::SnapLocation,
    ]
    .into_iter()
    .filter(|c| {
        categories.contains(c)
            && match c {
                PrivacyCategory::History => Field::DnsReferrals.supported_for(profile.browser),
                PrivacyCategory::LastDownloadLocation => {
                    Field::LastDownloadLocation.supported_for(profile.browser)
                }
                PrivacyCategory::SnapLocation => Field::SnapLocation.supported_for(profile.browser),
                _ => false,
            }
    })
    .collect::<Vec<_>>();
    if categories.is_empty() {
        return;
    }
    let path = profile.root.join("Preferences");
    match optional_database_absent(&profile.root, &path) {
        Ok(true) => return,
        Ok(false) => {}
        Err(()) => {
            for category in &categories {
                add_skip(
                    report,
                    &profile.name,
                    Some(*category),
                    "Browser preferences are linked or unavailable.",
                );
            }
            return;
        }
    }
    let result = capture(profile, cancel);
    match result {
        Ok((source, bytes)) => {
            let source = Arc::new(source);
            let document = match Document::parse(&bytes, cancel) {
                Ok(document) => document,
                Err(reason) => {
                    for category in &categories {
                        add_skip(report, &profile.name, Some(*category), &reason);
                    }
                    report.cancelled |= cancel.load(Ordering::Relaxed);
                    return;
                }
            };
            for category in categories {
                let fields = match document.fields(category) {
                    Ok(fields) => fields,
                    Err(reason) => {
                        add_skip(report, &profile.name, Some(category), &reason);
                        continue;
                    }
                };
                for field in fields {
                    if report.records.len() >= MAX_RECORDS {
                        report.truncated = true;
                        break;
                    }
                    let id = Uuid::new_v4();
                    report.records.push(PrivacyRecord {
                        id,
                        browser: profile.browser,
                        profile_id: profile.id.clone(),
                        profile_name: profile.name.clone(),
                        category,
                        site: field.label().into(),
                        locator: RecordLocator::Preferences(Review {
                            id,
                            field: field.into(),
                            source: source.clone(),
                        }),
                    });
                }
            }
        }
        Err(reason) => {
            report.cancelled |= cancel.load(Ordering::Relaxed);
            for category in categories {
                add_skip(report, &profile.name, Some(category), &reason);
            }
        }
    }
}

/// The source and every directory ancestor are held against replacement. No
/// source write is attempted until the caller has synced its backup and intent.
struct Lease {
    file: File,
    _directories: Vec<File>,
}
impl Lease {
    #[cfg(windows)]
    fn acquire(source: &Source) -> Result<Self, String> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        validate_database_path(&source.root, &source.path())?;
        let mut directories = Vec::new();
        for parent in source
            .root
            .ancestors()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            safe_profile_root(parent)?;
            let file = OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES.0)
                .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
                .open(parent)
                .map_err(
                    |_| "A browser preference ancestor could not be held against replacement.",
                )?;
            let meta = file
                .metadata()
                .map_err(|_| "Browser preference ancestor metadata is unavailable.")?;
            if !meta.is_dir() || is_link(&meta) {
                return Err("A browser preference ancestor is linked.".into());
            }
            directories.push(file);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(source.path())
            .map_err(|_| "Browser preferences are open or cannot be held exclusively.")?;
        let (_, actual) = read_held(&mut file, &AtomicBool::new(false))?;
        if actual != source.signature {
            return Err("Browser data changed since review.".into());
        }
        Ok(Self {
            file,
            _directories: directories,
        })
    }
    #[cfg(not(windows))]
    fn acquire(_: &Source) -> Result<Self, String> {
        Err("Browser preference cleanup locking is not verified on this platform.".into())
    }
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() > MAX_IMAGE_BYTES {
            return Err("Browser preference write exceeds its bound.".into());
        }
        self.file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.write_all(bytes))
            .and_then(|_| self.file.set_len(bytes.len() as u64))
            .and_then(|_| self.file.sync_all())
            .map_err(|_| "Browser data write or sync failed; no retry was attempted.".into())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u32,
    id: Uuid,
    operation: Uuid,
    source: Source,
    selected: Vec<(Uuid, Target)>,
    after_hash: [u8; 32],
}
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
enum Outcome {
    Confirmed,
    Refused,
    Uncertain,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Start {
        intent: Intent,
    },
    Done {
        outcome: Outcome,
        post: Option<Signature>,
    },
    RestoreStart {
        operation: Uuid,
    },
    RestoreDone {
        operation: Uuid,
        outcome: Outcome,
    },
}
struct Journal {
    file: File,
}
impl Journal {
    fn append(&mut self, event: &Event) -> Result<(), String> {
        let mut bytes = serde_json::to_vec(event)
            .map_err(|_| "Browser preference journal could not be encoded.")?;
        bytes.push(b'\n');
        if self
            .file
            .metadata()
            .map_err(|_| "Preference journal metadata is unavailable.")?
            .len()
            .saturating_add(bytes.len() as u64)
            > MAX_META as u64
        {
            return Err("Browser preference journal limit reached.".into());
        }
        self.file
            .write_all(&bytes)
            .and_then(|_| self.file.sync_all())
            .map_err(|_| "Browser preference journal could not be synced.".into())
    }
}
struct Entry {
    intent: Intent,
    outcome: Option<Outcome>,
    post: Option<Signature>,
    pending_restore: Option<Uuid>,
    restored: Option<Outcome>,
    journal_hash: [u8; 32],
    journal_identity: (u64, u64),
    journal_len: usize,
    journal_events: usize,
}
fn private_dir(data_dir: &Path, create: bool) -> Result<PathBuf, String> {
    if !data_dir
        .try_exists()
        .map_err(|_| "Preference recovery directory is unavailable.")?
    {
        if !create {
            return Ok(data_dir.join("privacy-preferences"));
        }
        let ancestor = data_dir
            .ancestors()
            .skip(1)
            .find(|p| p.exists())
            .ok_or("Preference recovery ancestor is unavailable.")?;
        safe_profile_root(ancestor)?;
        create_private_dir(data_dir)?;
    }
    let base = safe_profile_root(data_dir)?;
    let root = base.join("privacy-preferences");
    match fs::symlink_metadata(&root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Ok(root);
            }
            fs::create_dir(&root)
                .map_err(|_| "Preference recovery directory could not be created.")?;
            create_private_dir(&root)?;
        }
        Err(_) => return Err("Preference recovery directory is unavailable.".into()),
        Ok(_) => {}
    }
    safe_profile_root(&root)?;
    Ok(root)
}
fn options_file() -> OpenOptions {
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
fn durable(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err("Preference recovery image exceeds its bound.".into());
    }
    let mut file = options_file()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| "Preference recovery image could not be created.")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "Preference recovery image could not be synced.")?;
    sync_directory(path.parent().ok_or("Missing preference recovery parent.")?)
}
fn private_read(root: &Path, path: &Path, limit: usize) -> Result<(Vec<u8>, (u64, u64)), String> {
    let mut file = storage_files::open_file(root, path)?;
    let identity = storage_files::identity(&file)?;
    let size = file
        .metadata()
        .map_err(|_| "Preference recovery metadata is unavailable.")?
        .len();
    if size > limit as u64 {
        return Err("Preference recovery observation limit reached.".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Preference recovery could not be read.")?;
    if bytes.len() as u64 != size
        || storage_files::identity(&storage_files::open_file(root, path)?)? != identity
    {
        return Err("Preference recovery changed while reading.".into());
    }
    Ok((bytes, identity))
}
fn entries(data_dir: &Path) -> Result<Vec<Entry>, String> {
    let root = private_dir(data_dir, false)?;
    if !root
        .try_exists()
        .map_err(|_| "Preference recovery is unavailable.")?
    {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    let mut inspected = 0;
    for child in fs::read_dir(&root).map_err(|_| "Preference recovery cannot be listed.")? {
        inspected += 1;
        if inspected > MAX_ENTRIES * 4 {
            return Err("Preference recovery entry limit reached.".into());
        }
        let path = child
            .map_err(|_| "Preference recovery entry is unavailable.")?
            .path();
        if path.extension().is_none_or(|x| x != "jsonl") {
            continue;
        }
        if out.len() >= MAX_ENTRIES {
            return Err("Preference journal count limit reached.".into());
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or("Invalid preference journal identifier.")?;
        let (bytes, journal_identity) = private_read(&root, &path, MAX_META)?;
        if !bytes.ends_with(b"\n") {
            return Err(
                "Preference journal is incomplete; it was preserved without replay.".into(),
            );
        }
        let mut entry: Option<Entry> = None;
        for (index, line) in bytes
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .enumerate()
        {
            if index >= 64 {
                return Err("Preference journal event limit reached.".into());
            }
            let event: Event = serde_json::from_slice(line)
                .map_err(|_| "Preference journal is damaged; it was preserved without replay.")?;
            match event {
                Event::Start { intent }
                    if index == 0
                        && intent.id == id
                        && intent.version == intent.source.version()
                        && !intent.selected.is_empty()
                        && intent.selected.len() <= MAX_FIELDS
                        && intent
                            .selected
                            .iter()
                            .all(|(_, field)| field.supported_for(intent.source.browser))
                        && intent.source.valid_targets(
                            &intent
                                .selected
                                .iter()
                                .map(|(_, field)| *field)
                                .collect::<Vec<_>>(),
                        ) =>
                {
                    let ids = intent
                        .selected
                        .iter()
                        .map(|(id, _)| *id)
                        .collect::<HashSet<_>>();
                    let fields = intent
                        .selected
                        .iter()
                        .map(|(_, f)| *f)
                        .collect::<HashSet<_>>();
                    if ids.len() != intent.selected.len() || fields.len() != ids.len() {
                        return Err("Preference journal has ambiguous selected identities.".into());
                    }
                    entry = Some(Entry {
                        intent,
                        outcome: None,
                        post: None,
                        pending_restore: None,
                        restored: None,
                        journal_hash: digest(&bytes),
                        journal_identity,
                        journal_len: bytes.len(),
                        journal_events: bytes
                            .split(|b| *b == b'\n')
                            .filter(|line| !line.is_empty())
                            .count(),
                    });
                }
                Event::Done { outcome, post } => {
                    let e = entry.as_mut().ok_or("Missing preference intent.")?;
                    if e.outcome.is_some() || (outcome == Outcome::Confirmed) != post.is_some() {
                        return Err("Preference outcome is inconsistent.".into());
                    }
                    if let Some(p) = &post {
                        if p.identity != e.intent.source.signature.identity
                            || p.hash != e.intent.after_hash
                        {
                            return Err("Preference post-state does not match its intent.".into());
                        }
                    }
                    e.outcome = Some(outcome);
                    e.post = post;
                }
                Event::RestoreStart { operation } => {
                    let e = entry.as_mut().ok_or("Missing preference intent.")?;
                    if e.outcome != Some(Outcome::Confirmed)
                        || e.pending_restore.is_some()
                        || matches!(e.restored, Some(Outcome::Confirmed | Outcome::Uncertain))
                    {
                        return Err("Preference restore sequence is inconsistent.".into());
                    }
                    e.pending_restore = Some(operation);
                }
                Event::RestoreDone { operation, outcome } => {
                    let e = entry.as_mut().ok_or("Missing preference intent.")?;
                    if e.pending_restore != Some(operation) {
                        return Err("Preference restore outcome has no matching intent.".into());
                    }
                    e.pending_restore = None;
                    e.restored = Some(outcome);
                }
                _ => return Err("Preference journal sequence is invalid.".into()),
            }
        }
        out.push(entry.ok_or("Empty preference journal.")?);
    }
    Ok(out)
}
fn blocked(data_dir: &Path, source: &Source, except: Option<Uuid>) -> Result<(), String> {
    blocked_path(data_dir, &source.path(), except)?;
    if source.relative.is_some() {
        session_trash_available(data_dir, &source.path())?;
    }
    Ok(())
}
pub(super) fn blocked_path(
    data_dir: &Path,
    path: &Path,
    except: Option<Uuid>,
) -> Result<(), String> {
    blocked_paths(data_dir, std::iter::once(path), except)
}
pub(super) fn blocked_paths<'a>(
    data_dir: &Path,
    paths: impl IntoIterator<Item = &'a Path>,
    except: Option<Uuid>,
) -> Result<(), String> {
    let paths = paths
        .into_iter()
        .map(storage_files::path_key)
        .collect::<HashSet<_>>();
    if entries(data_dir)?.iter().any(|e| {
        Some(e.intent.id) != except
            && paths.contains(&storage_files::path_key(&e.intent.source.path()))
            && (e.outcome.is_none()
                || e.outcome == Some(Outcome::Uncertain)
                || e.pending_restore.is_some()
                || e.restored == Some(Outcome::Uncertain))
    }) {
        return Err("An unresolved preference operation blocks cleanup and automatic replay. Review recovery first.".into());
    }
    Ok(())
}
// Check every retained generic file intent, including records beyond the UI's
// history display limit. This prevents crossing from an uncertain Trash attempt
// into a new session rewrite. Reads are bounded and never replay effects.
pub(super) fn session_trash_available(data_dir: &Path, path: &Path) -> Result<(), String> {
    if session_trash_pending(data_dir)?.contains(&storage_files::path_key(path)) {
        return Err("An unresolved file move blocks session cleanup and automatic replay.".into());
    }
    Ok(())
}
pub(super) fn session_trash_pending(data_dir: &Path) -> Result<HashSet<String>, String> {
    let mut pending = HashSet::new();
    let root = data_dir.join("operations");
    match fs::symlink_metadata(&root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(pending),
        Ok(m) if m.is_dir() && !is_link(&m) => {}
        _ => return Err("Session file recovery metadata is unavailable.".into()),
    }
    let mut total = 0usize;
    let mut count = 0usize;
    for entry in fs::read_dir(&root).map_err(|_| "Session file recovery could not be listed.")? {
        count += 1;
        if count > 2048 {
            return Err("Session file recovery inspection limit reached.".into());
        }
        let journal = entry
            .map_err(|_| "Session recovery entry is unavailable.")?
            .path();
        if journal.extension().is_none_or(|x| x != "jsonl") {
            continue;
        }
        let (bytes, _) = private_read(&root, &journal, 32 * 1024 * 1024)?;
        total = total.saturating_add(bytes.len());
        if total > 128 * 1024 * 1024 || !bytes.ends_with(b"\n") {
            return Err(
                "Session recovery metadata is incomplete or exceeds its inspection limit.".into(),
            );
        }
        let mut events = Vec::new();
        for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            if events.len() > 100_004 {
                return Err("Session file recovery event limit reached.".into());
            }
            events.push(
                serde_json::from_slice::<crate::store::JournalEvent>(line)
                    .map_err(|_| "Session recovery metadata is damaged; no effect was started.")?,
            );
        }
        let state = crate::store::project_events(&events)?;
        pending.extend(state.uncertain.iter().map(|p| storage_files::path_key(p)));
    }
    Ok(pending)
}
fn before_image(data_dir: &Path, entry: &Entry) -> Result<(Vec<u8>, Vec<u8>), String> {
    let root = private_dir(data_dir, false)?;
    let (before, _) = private_read(
        &root,
        &root.join(format!("{}.before", entry.intent.id)),
        MAX_IMAGE_BYTES,
    )?;
    if digest(&before) != entry.intent.source.signature.hash {
        return Err("Preference recovery pre-image does not match its intent.".into());
    }
    let fields = entry
        .intent
        .selected
        .iter()
        .map(|(_, f)| *f)
        .collect::<Vec<_>>();
    let after = entry
        .intent
        .source
        .transform(&before, &fields, &AtomicBool::new(false))?;
    if digest(&after) != entry.intent.after_hash {
        return Err("Preference recovery transform does not match its intent.".into());
    }
    Ok((before, after))
}
pub(super) fn preflight(runtime: &impl BrowserRuntime, selected: &[Review]) -> Result<(), String> {
    for review in selected {
        if !review.source.valid_targets(&[review.field]) {
            return Err(
                "This browser data target is not declared for the reviewed browser family.".into(),
            );
        }
        if let Some(reason) = review.unavailable_reason() {
            return Err(reason.into());
        }
        review.source.stopped(runtime)?;
    }
    Ok(())
}
pub(super) fn clean(
    data_dir: &Path,
    operation: Uuid,
    selected: &[Review],
    cancel: &AtomicBool,
    runtime: &impl BrowserRuntime,
) -> Result<PrivacyReceipt, String> {
    let mut groups = BTreeMap::<String, Vec<Review>>::new();
    for review in selected {
        groups
            .entry(storage_files::path_key(&review.source.path()))
            .or_default()
            .push(review.clone());
    }
    let mut receipt = PrivacyReceipt {
        id: operation,
        selected: selected.len(),
        ..Default::default()
    };
    for group in groups.values() {
        match clean_group(
            data_dir,
            operation,
            group,
            cancel,
            runtime,
            |lease, bytes| lease.write(bytes),
        ) {
            Ok(r) => {
                receipt.deleted += r.deleted;
                receipt.skipped += r.skipped;
                receipt.uncertain |= r.uncertain;
                receipt.cancelled |= r.cancelled;
                receipt.backups.extend(r.backups);
                receipt.errors.extend(r.errors);
            }
            Err(reason) => {
                receipt.skipped += group.len();
                receipt.errors.push(reason);
            }
        }
        if cancel.load(Ordering::Relaxed) {
            receipt.cancelled = true;
            break;
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
    effect: impl FnOnce(&mut Lease, &[u8]) -> Result<(), String>,
) -> Result<PrivacyReceipt, String> {
    preflight(runtime, selected)?;
    let source = selected
        .first()
        .ok_or("No selected preference fields.")?
        .source
        .clone();
    if selected.len() > MAX_FIELDS
        || selected.iter().any(|r| r.source != source)
        || selected
            .iter()
            .map(|r| r.field)
            .collect::<HashSet<_>>()
            .len()
            != selected.len()
        || selected.iter().map(|r| r.id).collect::<HashSet<_>>().len() != selected.len()
    {
        return Err("Selected preference fields have inconsistent identities.".into());
    }
    blocked(data_dir, &source, None)?;
    let mut lease = Lease::acquire(&source)?;
    let (before, signature) = read_held(&mut lease.file, cancel)?;
    if signature != source.signature {
        return Err("Browser data changed since review.".into());
    }
    let fields = selected.iter().map(|r| r.field).collect::<Vec<_>>();
    let after = source.transform(&before, &fields, cancel)?;
    source.stopped(runtime)?;
    blocked(data_dir, &source, None)?;
    let id = Uuid::new_v4();
    let intent = Intent {
        version: source.version(),
        id,
        operation,
        source: (*source).clone(),
        selected: selected.iter().map(|r| (r.id, r.field)).collect(),
        after_hash: digest(&after),
    };
    let start = Event::Start { intent };
    if serde_json::to_vec(&start)
        .map_err(|_| "Preference intent could not be encoded.")?
        .len()
        .saturating_add(1025)
        > MAX_META
    {
        return Err(
            "Preference intent has no reserved outcome capacity; no write was started.".into(),
        );
    }
    let root = private_dir(data_dir, true)?;
    let backup = root.join(format!("{id}.before"));
    durable(&backup, &before)?;
    let mut journal = Journal {
        file: options_file()
            .write(true)
            .create_new(true)
            .open(root.join(format!("{id}.jsonl")))
            .map_err(|_| "Preference intent could not be created.")?,
    };
    journal.append(&start)?;
    sync_directory(&root)?;
    let mut attempted = false;
    let mut post = None;
    let result = (|| {
        if cancel.load(Ordering::Relaxed) {
            return Err("Preference cleanup stopped before its write.".into());
        }
        source.stopped(runtime)?;
        blocked(data_dir, &source, Some(id))?;
        if cancel.load(Ordering::Relaxed) {
            return Err("Preference cleanup stopped before its write.".into());
        }
        attempted = true;
        effect(&mut lease, &after)?;
        let (actual, signature) = read_held(&mut lease.file, &AtomicBool::new(false))?;
        if actual != after || signature.identity != source.signature.identity {
            return Err("Preference post-write state differs; no retry was attempted.".into());
        }
        source.validate_format(&actual)?;
        post = Some(signature);
        Ok::<_, String>(())
    })();
    let outcome = if result.is_ok() {
        Outcome::Confirmed
    } else if attempted {
        Outcome::Uncertain
    } else {
        Outcome::Refused
    };
    let mut receipt = PrivacyReceipt {
        id: operation,
        selected: selected.len(),
        backups: vec![backup],
        cancelled: cancel.load(Ordering::Relaxed),
        uncertain: outcome == Outcome::Uncertain,
        ..Default::default()
    };
    if let Err(reason) = result {
        receipt.errors.push(reason);
    }
    if journal.append(&Event::Done { outcome, post }).is_err() {
        receipt.uncertain = true;
        receipt
            .errors
            .push("Preference receipt could not be synced; no retry was attempted.".into());
    }
    if outcome == Outcome::Confirmed && !receipt.uncertain {
        receipt.deleted = selected.len();
    } else {
        receipt.skipped = selected.len();
    }
    Ok(receipt)
}

fn recovery_state(e: &Entry) -> PrivacyRecoveryState {
    if e.pending_restore.is_some()
        || e.restored == Some(Outcome::Uncertain)
        || e.outcome == Some(Outcome::Uncertain)
    {
        PrivacyRecoveryState::Uncertain
    } else if e.outcome.is_none() {
        PrivacyRecoveryState::Interrupted
    } else if e.restored == Some(Outcome::Confirmed) {
        PrivacyRecoveryState::Restored
    } else if e.outcome == Some(Outcome::Confirmed) {
        PrivacyRecoveryState::Ready
    } else {
        PrivacyRecoveryState::Unavailable
    }
}
pub(super) fn options(data_dir: &Path) -> Result<Vec<PrivacyRestoreOption>, String> {
    entries(data_dir)?.into_iter().map(|e| {
        // Listing reads bounded journal metadata only. The selected backup and
        // current source are validated by the fresh restore-review preflight.
        let state=recovery_state(&e);
        let categories=PrivacyCategory::ALL.into_iter().filter(|category| e.intent.selected.iter().any(|(_,field)|field.category()==*category)).collect();
        Ok(PrivacyRestoreOption {id:e.intent.id,browser:e.intent.source.browser,profile_name:e.intent.source.profile_name.clone(),database_name:e.intent.source.display_name(),categories,record_count:e.intent.selected.len(),state,reason:(!matches!(state,PrivacyRecoveryState::Ready|PrivacyRecoveryState::Restored)).then(||"Preference effects are incomplete, refused or uncertain; automatic restore is unavailable.".into())})
    }).collect()
}
pub(super) fn recovery(data_dir: &Path) -> Result<Vec<PrivacyRecoveryItem>, String> {
    let root = private_dir(data_dir, false)?;
    Ok(entries(data_dir)?
        .into_iter()
        .filter(|e| {
            matches!(
                recovery_state(e),
                PrivacyRecoveryState::Interrupted | PrivacyRecoveryState::Uncertain
            )
        })
        .map(|e| PrivacyRecoveryItem {
            operation_id: e.intent.operation,
            database: e.intent.source.path(),
            backup: root.join(format!("{}.before", e.intent.id)),
            unresolved_ids: e.intent.selected.iter().map(|(id, _)| *id).collect(),
            uncertain: true,
        })
        .collect())
}
#[derive(Clone)]
pub(super) struct Restore {
    id: Uuid,
    source: Source,
    journal_hash: [u8; 32],
}
impl Restore {
    pub(super) fn is_session(&self) -> bool {
        self.source.relative.is_some()
    }
}
fn ready(
    data_dir: &Path,
    id: Uuid,
    runtime: &impl BrowserRuntime,
) -> Result<Option<(Entry, Source, Vec<u8>, Vec<u8>)>, String> {
    let Some(entry) = entries(data_dir)?.into_iter().find(|e| e.intent.id == id) else {
        return Ok(None);
    };
    if recovery_state(&entry) != PrivacyRecoveryState::Ready {
        return Err("Preference recovery is not ready for a new restore.".into());
    }
    if entry.journal_len.saturating_add(1024) > MAX_META || entry.journal_events > 62 {
        return Err(
            "Preference journal has no reserved restore outcome capacity; no write was started."
                .into(),
        );
    }
    let (before, after) = before_image(data_dir, &entry)?;
    let mut source = entry.intent.source.clone();
    source.signature = entry
        .post
        .clone()
        .ok_or("Missing confirmed preference post-state.")?;
    source.stopped(runtime)?;
    blocked(data_dir, &source, Some(id))?;
    let profile = BrowserProfile {
        browser: source.browser,
        id: source.profile_id.clone(),
        name: source.profile_name.clone(),
        root: source.root.clone(),
    };
    let (actual, bytes) = capture_path(
        &profile,
        &source.path(),
        source.relative.clone(),
        Some(&source.signature.stamp),
        &AtomicBool::new(false),
    )?;
    if actual != source || bytes != after {
        return Err("Browser data changed after cleanup; restore was refused.".into());
    }
    Ok(Some((entry, source, before, after)))
}
pub(super) fn prepare_restore(
    data_dir: &Path,
    id: Uuid,
    runtime: &impl BrowserRuntime,
) -> Result<Option<PrivacyRestorePlan>, String> {
    let Some((entry, source, _, _)) = ready(data_dir, id, runtime)? else {
        return Ok(None);
    };
    let root = private_dir(data_dir, false)?;
    Ok(Some(PrivacyRestorePlan {
        id,
        operation_id: entry.intent.operation,
        browser: source.browser,
        profile_name: source.profile_name.clone(),
        database_name: source.display_name(),
        profile_root: source.root.clone(),
        database: source.path(),
        backup: root.join(format!("{id}.before")),
        post_state_snapshot: root.join(format!("{id}.jsonl")),
        post_state_stamp: source.signature.stamp.clone(),
        schema_signature: String::new(),
        leveldb: None,
        preferences: Some(Restore {
            id,
            source,
            journal_hash: entry.journal_hash,
        }),
    }))
}
pub(super) fn restore(
    data_dir: &Path,
    plan: &Restore,
    runtime: &impl BrowserRuntime,
) -> Result<PrivacyRestoreReceipt, String> {
    restore_effect(data_dir, plan, runtime, |lease, bytes| lease.write(bytes))
}
fn restore_effect(
    data_dir: &Path,
    plan: &Restore,
    runtime: &impl BrowserRuntime,
    effect: impl FnOnce(&mut Lease, &[u8]) -> Result<(), String>,
) -> Result<PrivacyRestoreReceipt, String> {
    let (entry, source, before, after) =
        ready(data_dir, plan.id, runtime)?.ok_or("Preference recovery item disappeared.")?;
    if source != plan.source || entry.journal_hash != plan.journal_hash {
        return Err("Preference restore review changed; prepare a new review.".into());
    }
    let root = private_dir(data_dir, false)?;
    let mut journal = Journal {
        file: options_file()
            .append(true)
            .read(true)
            .open(root.join(format!("{}.jsonl", plan.id)))
            .map_err(|_| "Preference recovery journal is already in use.")?,
    };
    let mut journal_bytes = Vec::new();
    Read::by_ref(&mut journal.file)
        .take(MAX_META as u64 + 1)
        .read_to_end(&mut journal_bytes)
        .map_err(|_| "Preference recovery journal cannot be checked.")?;
    if journal_bytes.len() > MAX_META
        || digest(&journal_bytes) != entry.journal_hash
        || storage_files::identity(&journal.file)? != entry.journal_identity
    {
        return Err("Preference recovery journal changed after review.".into());
    }
    let mut lease = Lease::acquire(&source)?;
    let (current, signature) = read_held(&mut lease.file, &AtomicBool::new(false))?;
    if current != after || signature != source.signature {
        return Err("Preference source changed after restore review.".into());
    }
    source.stopped(runtime)?;
    blocked(data_dir, &source, Some(plan.id))?;
    let operation = Uuid::new_v4();
    let current_copy = root.join(format!("{operation}.current"));
    durable(&current_copy, &current)?;
    journal.append(&Event::RestoreStart { operation })?;
    let mut attempted = false;
    let result = (|| {
        source.stopped(runtime)?;
        blocked(data_dir, &source, Some(plan.id))?;
        attempted = true;
        effect(&mut lease, &before)?;
        let (actual, signature) = read_held(&mut lease.file, &AtomicBool::new(false))?;
        if actual != before || signature.identity != source.signature.identity {
            return Err("Preference restore post-state differs; no retry was attempted.".into());
        }
        Ok::<_, String>(())
    })();
    let outcome = if result.is_ok() {
        Outcome::Confirmed
    } else if attempted {
        Outcome::Uncertain
    } else {
        Outcome::Refused
    };
    let mut receipt = PrivacyRestoreReceipt {
        id: operation,
        source_operation_id: entry.intent.operation,
        current_state_backup: Some(current_copy),
        uncertain: outcome == Outcome::Uncertain,
        ..Default::default()
    };
    if let Err(reason) = result {
        receipt.errors.push(reason);
    }
    if journal
        .append(&Event::RestoreDone { operation, outcome })
        .is_err()
    {
        receipt.uncertain = true;
        receipt
            .errors
            .push("Preference restore receipt could not be synced; no retry was attempted.".into());
    }
    receipt.restored = outcome == Outcome::Confirmed && !receipt.uncertain;
    Ok(receipt)
}

#[cfg(debug_assertions)]
fn preview_source(profile: &BrowserProfile) -> Arc<Source> {
    Arc::new(Source {
        browser: profile.browser,
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        root: profile.root.clone(),
        relative: None,
        signature: Signature {
            identity: (0, 0),
            stamp: FileStamp::default(),
            hash: [0; 32],
        },
    })
}
#[cfg(debug_assertions)]
pub(super) fn preview(profile: &BrowserProfile) -> Vec<PrivacyRecord> {
    let source = preview_source(profile);
    [
        Field::DnsReferrals,
        Field::DnsStartup,
        Field::MediaEngagement,
        Field::SiteEngagement,
    ]
    .into_iter()
    .enumerate()
    .map(|(n, field)| {
        let id = Uuid::from_u128(0x44434c45414e45525052454600000001 + n as u128);
        PrivacyRecord {
            id,
            browser: profile.browser,
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            category: PrivacyCategory::History,
            site: field.label().into(),
            locator: RecordLocator::Preferences(Review {
                id,
                field: field.into(),
                source: source.clone(),
            }),
        }
    })
    .collect()
}
#[cfg(debug_assertions)]
pub(super) fn preview_locations(profile: &BrowserProfile) -> Vec<PrivacyRecord> {
    let source = preview_source(profile);
    [Field::LastDownloadLocation, Field::SnapLocation]
        .into_iter()
        .enumerate()
        .map(|(n, field)| {
            let id = Uuid::from_u128(0x44434c45414e45524c4f434100000001 + n as u128);
            PrivacyRecord {
                id,
                browser: profile.browser,
                profile_id: profile.id.clone(),
                profile_name: profile.name.clone(),
                category: field.category(),
                site: field.label().into(),
                locator: RecordLocator::Preferences(Review {
                    id,
                    field: field.into(),
                    source: source.clone(),
                }),
            }
        })
        .collect()
}
#[cfg(debug_assertions)]
pub(super) fn preview_session(profile: &BrowserProfile) -> PrivacyRecord {
    let mut source = (*preview_source(profile)).clone();
    source.relative = Some(PathBuf::from("Sessions/Session_001"));
    let id = Uuid::from_u128(0x44434c45414e45525345535300000001);
    PrivacyRecord {
        id,
        browser: profile.browser,
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        category: PrivacyCategory::Sessions,
        site: "Pinned session data".into(),
        locator: RecordLocator::Preferences(Review {
            id,
            field: Target::Session(SessionTarget::SessionFile),
            source: Arc::new(source),
        }),
    }
}
#[cfg(debug_assertions)]
pub(super) fn preview_mozilla_session(profile: &BrowserProfile, compressed: bool) -> PrivacyRecord {
    let mut record = preview_session(profile);
    let RecordLocator::Preferences(review) = &mut record.locator else {
        unreachable!()
    };
    Arc::make_mut(&mut review.source).relative = Some(PathBuf::from(if compressed {
        "sessionstore.jsonlz4"
    } else {
        "sessionstore.js"
    }));
    review.field = Target::Session(if compressed {
        SessionTarget::MozillaLz4
    } else {
        SessionTarget::MozillaJson
    });
    review.id = Uuid::from_u128(if compressed {
        0x44434c45414e45525345535300000011
    } else {
        0x44434c45414e45525345535300000010
    });
    record.id = review.id;
    record
}
#[cfg(debug_assertions)]
pub(super) fn preview_mozilla_restore(profile: &BrowserProfile) -> PrivacyRestorePlan {
    let mut plan = preview_session_restore(profile);
    let restore = plan.preferences.as_mut().unwrap();
    restore.source.relative = Some(PathBuf::from("sessionstore.jsonlz4"));
    plan.database = restore.source.path();
    plan.database_name = restore.source.display_name();
    plan
}
#[cfg(debug_assertions)]
pub(super) fn preview_session_restore(profile: &BrowserProfile) -> PrivacyRestorePlan {
    let mut plan = preview_restore(profile);
    let restore = plan.preferences.as_mut().unwrap();
    restore.source.relative = Some(PathBuf::from("Sessions/Session_001"));
    plan.database = restore.source.path();
    plan.database_name = restore.source.display_name();
    plan
}
#[cfg(debug_assertions)]
pub(super) fn preview_restore(profile: &BrowserProfile) -> PrivacyRestorePlan {
    let id = Uuid::from_u128(0x44434c45414e45525052454600000010);
    let source = (*preview_source(profile)).clone();
    PrivacyRestorePlan {
        id,
        operation_id: id,
        browser: profile.browser,
        profile_name: profile.name.clone(),
        database_name: "Preferences".into(),
        profile_root: profile.root.clone(),
        database: source.path(),
        backup: PathBuf::new(),
        post_state_snapshot: PathBuf::new(),
        post_state_stamp: FileStamp::default(),
        schema_signature: String::new(),
        leveldb: None,
        preferences: Some(Restore {
            id,
            source,
            journal_hash: [0; 32],
        }),
    }
}

#[cfg(test)]
#[path = "preferences_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "preferences_location_tests.rs"]
mod location_tests;
