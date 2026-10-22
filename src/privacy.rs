//! Browser privacy inventory and journaled cleanup of known SQL rows and site-storage files.
//!
//! The inventory intentionally omits URL paths, page titles, cookie names and all cookie
//! contents from its public records. Cleanup is limited to history, download-history and
//! cookie rows in recognized Chromium and Mozilla-family databases, plus explicitly matched site-storage files.

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, TransactionBehavior, backup::Backup, types::Value,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    hash::{Hash, Hasher},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

use crate::scanner::{contained, is_link, same_path, timestamp};

mod chromium_downloads;
mod chromium_history;
mod cookies;
mod firefox_places;
#[allow(dead_code)] // Some retained native catalogue metadata is test/evidence-only.
mod generic_sqlite;
mod json_members;
mod keywords;
mod leveldb;
mod leveldb_format;
mod leveldb_write;
mod moz_lz4;
mod preferences;
mod profile_discovery;
mod quota;
mod record_files;
mod session_binary;
mod session_files;
mod session_mozilla;
mod shortcuts;
mod storage_files;
#[cfg(test)]
mod websql_paths;
use profile_discovery::{contains_named_path, same_named_path};

const MAX_PROFILES: usize = 128;
const MAX_RECORDS: usize = 50_000;
const MAX_DATABASE_BYTES: u64 = 1_073_741_824;
const MAX_SKIP_DETAILS: usize = 2_000;
const CHROMIUM_COOKIE_DATABASES: &[&str] = &["Cookies", "Network/Cookies", "Extension Cookies"];
const CHROMIUM_SITE_DATABASES: &[(&str, TableKind)] = &[
    ("QuotaManager", TableKind::ChromiumQuota),
    ("Origin Bound Certs", TableKind::ChromiumOriginCerts),
    ("Origin Bound Certs", TableKind::ChromiumChannelIds),
];
const CHROMIUM_HISTORY_DATABASES: &[(&str, TableKind)] = &[
    ("Web Data", TableKind::ChromiumKeywords),
    ("Shortcuts", TableKind::ChromiumShortcuts),
];
const MOZILLA_SITE_DATABASES: &[(&str, TableKind)] = &[
    ("permissions.sqlite", TableKind::FirefoxOfflinePermissions),
    ("webappsstore.sqlite", TableKind::FirefoxWebApps),
    ("webappsstore.sqlite", TableKind::FirefoxWebApps2),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Browser {
    Chrome,
    Edge,
    Firefox,
    Avg,
    Ccleaner,
    Avast,
    Opera,
    Vivaldi,
    Brave,
    OperaGx,
    Norton,
    Avira,
    Arc,
    Neo,
    Thunderbird,
}

impl Browser {
    pub const ALL: &[Self] = &[
        Self::Chrome,
        Self::Edge,
        Self::Firefox,
        Self::Avg,
        Self::Ccleaner,
        Self::Avast,
        Self::Opera,
        Self::Vivaldi,
        Self::Brave,
        Self::OperaGx,
        Self::Norton,
        Self::Avira,
        Self::Arc,
        Self::Neo,
        Self::Thunderbird,
    ];

    pub fn is_chromium(self) -> bool {
        !matches!(self, Self::Firefox | Self::Thunderbird)
    }

    pub fn cache_category(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Edge => "edge",
            Self::Firefox => "firefox",
            Self::Avg => "avgsecurebrowser",
            Self::Ccleaner => "ccleanerbrowser",
            Self::Avast => "avastsecurebrowser",
            Self::Opera => "opera",
            Self::Vivaldi => "vivaldi",
            Self::Brave => "brave",
            Self::OperaGx => "operagx",
            Self::Norton => "nortonprivatebrowser",
            Self::Avira => "avirasecurebrowser",
            Self::Arc => "arc",
            Self::Neo => "neobrowser",
            Self::Thunderbird => "thunderbird",
        }
    }
    pub fn from_cache_category(id: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|browser| browser.cache_category() == id)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Edge => "Edge",
            Self::Firefox => "Firefox",
            Self::Avg => "AVG Secure Browser",
            Self::Ccleaner => "CCleaner Browser",
            Self::Avast => "Avast Secure Browser",
            Self::Opera => "Opera",
            Self::Vivaldi => "Vivaldi",
            Self::Brave => "Brave",
            Self::OperaGx => "Opera GX",
            Self::Norton => "Norton Private Browser",
            Self::Avira => "Avira Secure Browser",
            Self::Arc => "Arc",
            Self::Neo => "Neo Browser",
            Self::Thunderbird => "Thunderbird",
        }
    }

    fn process_names(self) -> &'static [&'static str] {
        match self {
            Self::Chrome => &[
                "chrome.exe",
                "google chrome",
                "flock.exe",
                "iron.exe",
                "rockmelt.exe",
                "dragon.exe",
                "spark.exe",
                "torch.exe",
                "browser.exe",
                "chromium.exe",
            ],
            Self::Edge => &["msedge.exe", "microsoft edge"],
            Self::Firefox => &[
                "firefox.exe",
                "firefox",
                "mozilla.exe",
                "seamonkey.exe",
                "palemoon.exe",
                "songbird.exe",
                "k-meleon.exe",
                "icedragon.exe",
                "cyberfox.exe",
            ],
            Self::Avg => &["avgbrowser.exe"],
            Self::Ccleaner => &["ccleanerbrowser.exe"],
            Self::Avast => &["avastbrowser.exe"],
            Self::Opera | Self::OperaGx => &["opera.exe", "opera"],
            Self::Vivaldi => &["vivaldi.exe", "vivaldi"],
            Self::Brave => &["brave.exe", "brave browser"],
            Self::Norton => &["nortonbrowser.exe"],
            Self::Avira => &["avirabrowser.exe"],
            Self::Arc => &["arc.exe", "arc"],
            Self::Neo => &["neo.exe"],
            Self::Thunderbird => &["thunderbird.exe", "thunderbird"],
        }
    }

    /// Executable names do not distinguish shared products such as Opera/GX.
    /// This is a conservative conflict guard, never profile attribution.
    pub fn conflicts_with(self, process: &RunningBrowser) -> bool {
        self == process.browser
            || self
                .process_names()
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&process.executable))
            || self
                .process_names()
                .iter()
                .any(|name| process.browser.process_names().contains(name))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyCategory {
    History,
    Cookies,
    Downloads,
    LastDownloadLocation,
    SnapLocation,
    Sessions,
    SavedForms,
    SavedPasswords,
    SitePreferences,
}
impl PrivacyCategory {
    pub const ALL: [Self; 9] = [
        Self::History,
        Self::Cookies,
        Self::Downloads,
        Self::LastDownloadLocation,
        Self::SnapLocation,
        Self::Sessions,
        Self::SavedForms,
        Self::SavedPasswords,
        Self::SitePreferences,
    ];
    pub const DEFAULT: [Self; 5] = [
        Self::History,
        Self::Cookies,
        Self::Downloads,
        Self::LastDownloadLocation,
        Self::SnapLocation,
    ];
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserProfile {
    /// Stable within this installation and profile path; not a scan-record identifier.
    pub id: String,
    pub browser: Browser,
    pub name: String,
    /// Profile directory, not a database path.
    pub root: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventorySkip {
    pub path: Option<PathBuf>,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct ProfileInventory {
    pub profiles: Vec<BrowserProfile>,
    pub skipped: Vec<InventorySkip>,
    pub partial: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningBrowser {
    pub browser: Browser,
    pub pid: u32,
    /// Native process image name only; command-line arguments and paths are not collected.
    pub executable: String,
}

#[derive(Clone, Debug, Default)]
pub struct CloseRequestReport {
    pub requested: Vec<RunningBrowser>,
    pub still_running: Vec<RunningBrowser>,
    pub stale_selection: Vec<RunningBrowser>,
    pub errors: Vec<String>,
}

/// A deliberately small public summary. Private row locators never appear in Debug or JSON.
#[derive(Clone)]
pub struct PrivacyRecord {
    pub id: Uuid,
    pub browser: Browser,
    pub profile_id: String,
    pub profile_name: String,
    pub category: PrivacyCategory,
    /// A sanitized site/host or fixed history-field label, never a full URL or cookie value.
    pub site: String,
    locator: RecordLocator,
}

impl PrivacyRecord {
    pub fn is_database_table(&self) -> bool {
        matches!(&self.locator, RecordLocator::Database(row) if row.generic.is_some())
    }
    pub fn is_preference_field(&self) -> bool {
        matches!(&self.locator, RecordLocator::Preferences(review) if !review.is_session())
    }
    pub fn is_session_file(&self) -> bool {
        self.category == PrivacyCategory::Sessions
    }
    /// Session rewrites expose a reviewed file selection; native result units
    /// remain unknown until caller aggregation has independent evidence.
    pub fn native_item_count(&self) -> Option<usize> {
        if self.is_session_file() || self.is_database_table() {
            None
        } else {
            Some(self.item_count())
        }
    }
    pub fn preference_cleanup_note(&self) -> Option<&'static str> {
        match &self.locator {
            RecordLocator::Preferences(review) => Some(review.cleanup_note()),
            RecordLocator::Database(row) => row
                .generic
                .as_ref()
                .map(generic_sqlite::Review::cleanup_note),
            _ => None,
        }
    }
    pub fn actionable(&self) -> bool {
        self.unavailable_reason().is_none()
    }

    pub fn unavailable_reason(&self) -> Option<&'static str> {
        match &self.locator {
            RecordLocator::Database(row) => row
                .quota
                .as_ref()
                .and_then(quota::Review::unavailable_reason)
                .or_else(|| {
                    row.generic
                        .as_ref()
                        .and_then(generic_sqlite::Review::unavailable_reason)
                }),
            RecordLocator::File(file) => file.unavailable_reason(),
            RecordLocator::LevelDb(review) => review.unavailable_reason(),
            RecordLocator::Preferences(review) => review.unavailable_reason(),
        }
    }

    /// Candidate units are separate from reviewed groups and confirmed effects.
    pub fn item_count(&self) -> usize {
        if matches!(
            self.locator,
            RecordLocator::LevelDb(_) | RecordLocator::Preferences(_)
        ) {
            return 1;
        }
        let RecordLocator::Database(row) = &self.locator else {
            let RecordLocator::File(file) = &self.locator else {
                unreachable!()
            };
            return file.item_count();
        };
        row.history
            .as_ref()
            .map(|review| review.item_count())
            .or_else(|| row.download.as_ref().map(|review| review.item_count()))
            .or_else(|| row.firefox.as_ref().map(|review| review.item_count()))
            .or_else(|| row.quota.as_ref().map(quota::Review::item_count))
            .or_else(|| row.generic.as_ref().map(generic_sqlite::Review::item_count))
            .unwrap_or(1)
    }

    pub fn size_bytes(&self) -> Option<u64> {
        match &self.locator {
            RecordLocator::File(file) => Some(file.size_bytes()),
            RecordLocator::Database(_)
            | RecordLocator::LevelDb(_)
            | RecordLocator::Preferences(_) => None,
        }
    }

    /// Relative source identity for a reviewed history/download file; never its contents.
    pub fn source_file(&self) -> Option<String> {
        match &self.locator {
            RecordLocator::File(file) => file.record_source(),
            RecordLocator::Preferences(review) => review.session_source(),
            RecordLocator::Database(row) => {
                row.generic.as_ref().map(generic_sqlite::Review::source)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacySkip {
    pub profile_name: String,
    pub category: Option<PrivacyCategory>,
    pub reason: String,
}

#[derive(Clone)]
pub struct PrivacyReport {
    pub id: Uuid,
    pub profiles_scanned: usize,
    pub records: Vec<PrivacyRecord>,
    pub skipped: Vec<PrivacySkip>,
    pub skipped_count: usize,
    pub omitted_skip_details: usize,
    pub partial: bool,
    pub truncated: bool,
    pub cancelled: bool,
    /// Cookie rows omitted because their host matched a saved keep-domain exception.
    pub cookie_exempted: usize,
    pub categories_scanned: Vec<PrivacyCategory>,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug)]
pub struct PrivacyProgress {
    pub profiles_completed: usize,
    pub profiles_total: usize,
    /// Source item units, which may include multiple rows in one reviewed target.
    pub records_found: usize,
    pub profile_name: String,
    pub category: PrivacyCategory,
}

#[derive(Clone)]
pub struct PrivacyPlan {
    report_id: Uuid,
    operation_id: Uuid,
    records: Vec<RowLocator>,
    files: Vec<storage_files::Review>,
    keys: Vec<leveldb_write::Review>,
    preferences: Vec<preferences::Review>,
}

impl PrivacyPlan {
    pub fn file_count(&self) -> usize {
        self.files
            .iter()
            .map(storage_files::Review::item_count)
            .sum()
    }
}

#[derive(Clone, Debug, Default)]
pub struct PrivacyReceipt {
    pub id: Uuid,
    pub selected: usize,
    pub deleted: usize,
    pub skipped: usize,
    pub cancelled: bool,
    pub uncertain: bool,
    pub backups: Vec<PathBuf>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyRecoveryItem {
    pub operation_id: Uuid,
    pub database: PathBuf,
    pub backup: PathBuf,
    pub unresolved_ids: Vec<Uuid>,
    pub uncertain: bool,
}

/// Per-user domains whose cookies are kept out of browser cleanup results.
/// This file contains domain names only; cookie values and names are never stored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CookieExceptionSettings {
    pub schema: u32,
    pub keep_domains: Vec<String>,
    /// "Keep me signed in": while on, Custom Clean and Health Check never scan
    /// cookies, site storage or saved passwords. Files saved before this field
    /// existed load as on, so an upgrade never starts logging the user out.
    #[serde(default = "keep_signed_in_default")]
    pub keep_signed_in: bool,
}

fn keep_signed_in_default() -> bool {
    true
}

impl Default for CookieExceptionSettings {
    fn default() -> Self {
        Self {
            schema: COOKIE_SETTINGS_SCHEMA,
            keep_domains: Vec::new(),
            keep_signed_in: true,
        }
    }
}

/// Categories that hold website sign-ins. Cookies also own site storage
/// (Local Storage, IndexedDB, WebSQL, quota and LevelDB keys).
pub const SIGN_IN_CATEGORIES: &[PrivacyCategory] =
    &[PrivacyCategory::Cookies, PrivacyCategory::SavedPasswords];

/// The categories a scan may use under the saved sign-in policy.
pub fn sign_in_policy_categories(
    categories: &[PrivacyCategory],
    settings: &CookieExceptionSettings,
) -> Vec<PrivacyCategory> {
    categories
        .iter()
        .copied()
        .filter(|category| !settings.keep_signed_in || !SIGN_IN_CATEGORIES.contains(category))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyRecoveryState {
    Ready,
    Restored,
    Interrupted,
    Uncertain,
    Unavailable,
}

/// Safe display metadata for a reviewed browser database restore. File paths and record
/// contents stay private to the engine; callers pass only this stable recovery identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyRestoreOption {
    pub id: Uuid,
    pub browser: Browser,
    pub profile_name: String,
    pub database_name: String,
    pub categories: Vec<PrivacyCategory>,
    pub record_count: usize,
    pub state: PrivacyRecoveryState,
    pub reason: Option<String>,
}

#[derive(Clone)]
pub struct PrivacyRestorePlan {
    id: Uuid,
    operation_id: Uuid,
    browser: Browser,
    profile_name: String,
    database_name: String,
    profile_root: PathBuf,
    database: PathBuf,
    backup: PathBuf,
    post_state_snapshot: PathBuf,
    post_state_stamp: FileStamp,
    schema_signature: String,
    leveldb: Option<leveldb_write::Restore>,
    preferences: Option<preferences::Restore>,
}

impl PrivacyRestorePlan {
    /// Whether this review restores exact browser site-storage keys rather than a
    /// complete SQLite database image. The native source bindings stay private.
    pub fn restores_site_storage_keys(&self) -> bool {
        self.leveldb.is_some()
    }
    pub fn restores_preferences(&self) -> bool {
        self.preferences.as_ref().is_some_and(|p| !p.is_session())
    }
    pub fn restores_sessions(&self) -> bool {
        self.preferences
            .as_ref()
            .is_some_and(preferences::Restore::is_session)
    }
    /// Stable identifier of the cleanup recovery item reviewed by this plan.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Browser profile label shown in the final restore confirmation.
    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    /// Database basename only; the profile's private filesystem path is not exposed.
    pub fn database_name(&self) -> &str {
        &self.database_name
    }
}

#[derive(Clone, Debug, Default)]
pub struct PrivacyRestoreReceipt {
    pub id: Uuid,
    pub source_operation_id: Uuid,
    pub restored: bool,
    pub uncertain: bool,
    pub current_state_backup: Option<PathBuf>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Hash, Serialize)]
#[serde(default)]
struct FileStamp {
    length: u64,
    #[serde(with = "decimal_u128")]
    modified_ns: u128,
    #[serde(default, with = "optional_decimal_u128")]
    created_ns: Option<u128>,
}

mod decimal_u128 {
    use serde::{Deserializer, Serializer, de::Visitor};
    use std::fmt;

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct U128Visitor;
        impl<'de> Visitor<'de> for U128Visitor {
            type Value = u128;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a decimal string or nonnegative integer")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(value as u128)
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                u128::try_from(value).map_err(E::custom)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(U128Visitor)
    }
}

mod optional_decimal_u128 {
    use serde::{Deserializer, Serializer, de::Visitor};
    use std::fmt;

    pub fn serialize<S>(value: &Option<u128>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(number) => serializer.serialize_some(&number.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u128>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptionalU128Visitor;
        impl<'de> Visitor<'de> for OptionalU128Visitor {
            type Value = Option<u128>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("null, a decimal string, or a nonnegative integer")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                super::decimal_u128::deserialize(deserializer).map(Some)
            }
        }

        deserializer.deserialize_option(OptionalU128Visitor)
    }
}

impl Default for FileStamp {
    fn default() -> Self {
        Self {
            length: 0,
            modified_ns: 0,
            created_ns: None,
        }
    }
}

#[derive(Clone)]
enum RecordLocator {
    Database(RowLocator),
    File(storage_files::Review),
    // Observation only until exact-key mutation and durable recovery exist.
    LevelDb(leveldb_write::Review),
    Preferences(preferences::Review),
}

#[derive(Clone)]
struct RowLocator {
    id: Uuid,
    browser: Browser,
    profile_id: String,
    profile_name: String,
    profile_root: PathBuf,
    database: PathBuf,
    database_stamp: FileStamp,
    kind: TableKind,
    row_id: i64,
    identity: Vec<Value>,
    history: Option<chromium_history::Review>,
    download: Option<chromium_downloads::Review>,
    firefox: Option<firefox_places::Review>,
    cookie: Option<cookies::Review>,
    quota: Option<quota::Review>,
    keyword: Option<keywords::Review>,
    shortcut: Option<shortcuts::Review>,
    generic: Option<generic_sqlite::Review>,
}

/// Return a fixed, in-memory browser profile and row for debug visual QA.
///
/// The locator uses a deliberately nonexistent synthetic path. This is not a
/// browser discovery result and must only be used by the isolated UI fixture
/// path, which disables every scan, persistence, and cleanup entry point.
#[cfg(debug_assertions)]
pub fn visual_preview_fixture() -> (ProfileInventory, PrivacyReport) {
    let profile = BrowserProfile {
        id: "fixture-profile-chrome".into(),
        browser: Browser::Chrome,
        name: "Fixture Profile".into(),
        root: PathBuf::from(r"C:\__DCleaner_VISUAL_FIXTURE_ONLY__\Chrome\Default"),
    };
    let id = Uuid::from_u128(0x4443_4c45_414e_4552_5052_4956_0000_0001);
    let record = PrivacyRecord {
        id,
        browser: Browser::Chrome,
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        category: PrivacyCategory::History,
        site: "example.test".into(),
        locator: RecordLocator::Database(RowLocator {
            id,
            browser: Browser::Chrome,
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            profile_root: profile.root.clone(),
            database: profile.root.join("__fixture_only__History"),
            database_stamp: FileStamp::default(),
            kind: TableKind::ChromiumHistory,
            row_id: 1,
            identity: vec![Value::Integer(1)],
            history: None,
            download: None,
            firefox: None,
            cookie: None,
            quota: None,
            keyword: None,
            shortcut: None,
            generic: None,
        }),
    };
    let inventory = ProfileInventory {
        profiles: vec![profile],
        skipped: Vec::new(),
        partial: false,
    };
    let report = PrivacyReport {
        id: Uuid::from_u128(0x4443_4c45_414e_4552_5052_4956_0000_0002),
        profiles_scanned: 1,
        records: vec![record],
        skipped: Vec::new(),
        skipped_count: 0,
        omitted_skip_details: 0,
        partial: false,
        truncated: false,
        cancelled: false,
        cookie_exempted: 0,
        categories_scanned: vec![PrivacyCategory::History],
        elapsed_ms: 12,
    };
    (inventory, report)
}

/// Owned in-memory quota state for CPU-only UI checks; never opens a browser.
#[cfg(debug_assertions)]
pub fn visual_quota_preview_fixture() -> (ProfileInventory, PrivacyReport) {
    let (inventory, mut report) = visual_preview_fixture();
    let original = report.records[0].clone();
    let conn = Connection::open_in_memory().expect("owned quota fixture");
    conn.execute_batch("CREATE TABLE buckets(storage_key TEXT,payload TEXT); INSERT INTO buckets VALUES('https://example.test/','owned'); CREATE TABLE quota(host TEXT); INSERT INTO quota VALUES('quota-only.test')").expect("owned quota fixture schema");
    let observed = quota::Snapshot::read(&conn, &HashSet::new(), &AtomicBool::new(false))
        .expect("owned quota fixture snapshot");
    report.records = observed
        .reviews()
        .enumerate()
        .map(|(index, (site, quota))| {
            let mut record = original.clone();
            record.id = Uuid::from_u128(0x4443_4c45_414e_4552_5155_4f54_0000_0001 + index as u128);
            record.site = site;
            record.category = PrivacyCategory::Cookies;
            let RecordLocator::Database(locator) = &mut record.locator else {
                unreachable!()
            };
            locator.id = record.id;
            locator.kind = TableKind::ChromiumQuota;
            locator.quota = Some(quota);
            record
        })
        .collect();
    report.categories_scanned = vec![PrivacyCategory::Cookies];
    (inventory, report)
}

/// Render-only file groups, including a counted file without content authority.
#[cfg(debug_assertions)]
pub fn visual_storage_preview_fixture() -> (ProfileInventory, PrivacyReport) {
    let (inventory, mut report) = visual_preview_fixture();
    report.records = vec![
        storage_files::preview(&inventory.profiles[0], true),
        storage_files::preview(&inventory.profiles[0], false),
    ];
    report.categories_scanned = vec![PrivacyCategory::Cookies];
    report.partial = true;
    report.skipped_count = 1;
    report.skipped = vec![PrivacySkip {
        profile_name: inventory.profiles[0].name.clone(), category: Some(PrivacyCategory::Cookies),
        reason: "Synthetic fixture: a matching storage file was enumerated but its contents could not be inspected.".into(),
    }];
    (inventory, report)
}

/// Synthetic history/download file rows; never reads source profile files.
#[cfg(debug_assertions)]
pub fn visual_record_files_preview_fixture() -> (ProfileInventory, PrivacyReport) {
    let (inventory, mut report) = visual_storage_preview_fixture();
    report.records = [
        (PrivacyCategory::History, "Visited Links", true),
        (PrivacyCategory::Downloads, "DownloadMetadata", true),
        (PrivacyCategory::History, "Top Sites", false),
    ]
    .into_iter()
    .enumerate()
    .map(|(n, (category, name, available))| {
        storage_files::preview_record(
            &inventory.profiles[0],
            category,
            name,
            Uuid::from_u128(0x4443_4c45_414e_4552_4649_4c45_0000_0001 + n as u128),
            available,
        )
    })
    .collect();
    report.categories_scanned = vec![PrivacyCategory::History, PrivacyCategory::Downloads];
    report.skipped[0].category = Some(PrivacyCategory::History);
    report.skipped[0].reason =
        "Synthetic fixture: one declared history file has unavailable content authority.".into();
    (inventory, report)
}

/// Synthetic key-count inventory; no source paths or LevelDB opens are used.
#[cfg(debug_assertions)]
pub fn visual_leveldb_preview_fixture() -> (ProfileInventory, PrivacyReport) {
    let (inventory, mut report) = visual_storage_preview_fixture();
    let template = report.records[0].clone();
    report.records = ["example.test", "example.test", "other.test"]
        .into_iter()
        .enumerate()
        .map(|(n, site)| {
            let mut record = template.clone();
            record.id = Uuid::from_u128(0x4443_4c45_414e_4552_4c44_424b_0000_0001 + n as u128);
            record.locator = RecordLocator::LevelDb(leveldb_write::preview(
                &inventory.profiles[0],
                record.id,
                site,
                n < 2,
            ));
            record.site = site.into();
            record
        })
        .collect();
    report.skipped[0].reason =
        "Synthetic fixture: one Local Storage key has unavailable review identities.".into();
    (inventory, report)
}

#[cfg(debug_assertions)]
pub fn visual_leveldb_restore_fixture(profile: &BrowserProfile) -> PrivacyRestorePlan {
    leveldb_write::preview_restore(profile)
}

#[cfg(debug_assertions)]
pub fn visual_preferences_preview_fixture() -> (ProfileInventory, PrivacyReport) {
    let (inventory, mut report) = visual_preview_fixture();
    report.records = preferences::preview(&inventory.profiles[0]);
    (inventory, report)
}

#[cfg(debug_assertions)]
pub fn visual_locations_preview_fixture() -> (ProfileInventory, PrivacyReport) {
    let (mut inventory, mut report) = visual_preview_fixture();
    inventory.profiles[0].browser = Browser::Opera;
    report.records = preferences::preview_locations(&inventory.profiles[0]);
    report.categories_scanned = vec![
        PrivacyCategory::LastDownloadLocation,
        PrivacyCategory::SnapLocation,
    ];
    (inventory, report)
}
#[cfg(debug_assertions)]
pub fn visual_sessions_preview_fixture() -> (ProfileInventory, PrivacyReport) {
    let (inventory, mut report) = visual_preview_fixture();
    report.records = vec![
        preferences::preview_session(&inventory.profiles[0]),
        storage_files::preview_session(&inventory.profiles[0]),
        storage_files::preview_session_group(&inventory.profiles[0]),
    ];
    report.categories_scanned = vec![PrivacyCategory::Sessions];
    (inventory, report)
}
#[cfg(debug_assertions)]
pub fn visual_sessions_restore_fixture(profile: &BrowserProfile) -> PrivacyRestorePlan {
    preferences::preview_session_restore(profile)
}
#[cfg(debug_assertions)]
pub fn visual_mozilla_sessions_preview_fixture(mixed: bool) -> (ProfileInventory, PrivacyReport) {
    let (mut inventory, mut report) = visual_sessions_preview_fixture();
    let template = inventory.profiles[0].clone();
    if !mixed {
        inventory.profiles.clear();
        report.records.clear();
    }
    for (browser, compressed) in [(Browser::Firefox, false), (Browser::Thunderbird, true)] {
        let mut profile = template.clone();
        profile.browser = browser;
        profile.id = format!("fixture-mozilla-{}", browser.cache_category());
        profile.name = format!("Fixture {} profile", browser.label());
        report
            .records
            .push(preferences::preview_mozilla_session(&profile, compressed));
        inventory.profiles.push(profile);
    }
    report.profiles_scanned = inventory.profiles.len();
    (inventory, report)
}
#[cfg(debug_assertions)]
pub fn visual_mozilla_session_restore_fixture(profile: &BrowserProfile) -> PrivacyRestorePlan {
    preferences::preview_mozilla_restore(profile)
}

#[cfg(debug_assertions)]
pub fn visual_preferences_restore_fixture(profile: &BrowserProfile) -> PrivacyRestorePlan {
    preferences::preview_restore(profile)
}
#[cfg(debug_assertions)]
pub fn visual_generic_sqlite_preview_fixture() -> (ProfileInventory, PrivacyReport) {
    generic_sqlite::preview()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum TableKind {
    GenericSqlite(generic_sqlite::Key),
    ChromiumHistory,
    ChromiumKeywords,
    ChromiumShortcuts,
    ChromiumCookies,
    ChromiumDownloads,
    FirefoxHistory,
    FirefoxCookies,
    FirefoxDownloads,
    ChromiumOriginCerts,
    ChromiumChannelIds,
    FirefoxOfflinePermissions,
    FirefoxWebApps,
    FirefoxWebApps2,
    ChromiumWebSql,
    ChromiumQuota,
}

impl TableKind {
    fn category(self) -> PrivacyCategory {
        match self {
            Self::GenericSqlite(key) => key.category(),
            Self::ChromiumHistory
            | Self::ChromiumKeywords
            | Self::ChromiumShortcuts
            | Self::FirefoxHistory => PrivacyCategory::History,
            Self::ChromiumCookies
            | Self::FirefoxCookies
            | Self::ChromiumOriginCerts
            | Self::ChromiumChannelIds
            | Self::FirefoxOfflinePermissions
            | Self::FirefoxWebApps
            | Self::FirefoxWebApps2
            | Self::ChromiumWebSql
            | Self::ChromiumQuota => PrivacyCategory::Cookies,
            Self::ChromiumDownloads | Self::FirefoxDownloads => PrivacyCategory::Downloads,
        }
    }

    fn table(self) -> &'static str {
        match self {
            Self::GenericSqlite(key) => key.table().expect("Declared table key"),
            Self::ChromiumHistory => "urls",
            Self::ChromiumKeywords => "keywords",
            Self::ChromiumShortcuts => "omni_box_shortcuts",
            Self::ChromiumCookies => "cookies",
            Self::ChromiumDownloads => "downloads",
            Self::FirefoxHistory => "moz_places",
            Self::FirefoxCookies => "moz_cookies",
            Self::FirefoxDownloads => "moz_downloads",
            Self::ChromiumOriginCerts => "origin_bound_certs",
            Self::ChromiumChannelIds => "channel_id",
            Self::FirefoxOfflinePermissions => "moz_hosts",
            Self::FirefoxWebApps => "webappsstore",
            Self::FirefoxWebApps2 => "webappsstore2",
            Self::ChromiumWebSql => "Databases",
            Self::ChromiumQuota => "buckets",
        }
    }

    fn alternate_cookie_table(self) -> Option<(Self, bool)> {
        match self {
            Self::ChromiumOriginCerts => Some((Self::ChromiumChannelIds, true)),
            Self::ChromiumChannelIds => Some((Self::ChromiumOriginCerts, false)),
            Self::FirefoxWebApps => Some((Self::FirefoxWebApps2, true)),
            Self::FirefoxWebApps2 => Some((Self::FirefoxWebApps, false)),
            _ => None,
        }
    }

    fn query(self) -> &'static str {
        match self {
            Self::GenericSqlite(_) => {
                unreachable!("Generic table groups have their own snapshot owner")
            }
            Self::ChromiumHistory => {
                "SELECT rowid,id,url,title,visit_count,last_visit_time FROM urls ORDER BY id LIMIT ?1"
            }
            Self::ChromiumCookies => {
                "SELECT rowid,host_key,name,path,expires_utc,creation_utc,last_access_utc FROM cookies ORDER BY rowid LIMIT ?1"
            }
            Self::ChromiumDownloads => {
                "SELECT d.rowid,d.id,COALESCE((SELECT u.url FROM downloads_url_chains u WHERE u.id=d.id ORDER BY u.chain_index DESC LIMIT 1),''),d.target_path,d.start_time,d.received_bytes,COALESCE((SELECT group_concat(signature, ',') FROM (SELECT chain_index || ':' || hex(url) AS signature FROM downloads_url_chains WHERE id=d.id ORDER BY chain_index)), '') FROM downloads d ORDER BY d.id LIMIT ?1"
            }
            Self::FirefoxHistory => {
                "SELECT rowid,id,url,title,visit_count,last_visit_date,foreign_count FROM moz_places WHERE EXISTS (SELECT 1 FROM moz_historyvisits WHERE place_id=moz_places.id) ORDER BY id LIMIT ?1"
            }
            Self::FirefoxCookies => {
                "SELECT rowid,id,host,name,path,expiry,creationTime,lastAccessed FROM moz_cookies ORDER BY id LIMIT ?1"
            }
            Self::FirefoxDownloads => {
                "SELECT rowid,id,source,target,startTime,endTime,state FROM moz_downloads ORDER BY id LIMIT ?1"
            }
            Self::ChromiumOriginCerts
            | Self::ChromiumChannelIds
            | Self::FirefoxOfflinePermissions
            | Self::FirefoxWebApps
            | Self::FirefoxWebApps2
            | Self::ChromiumWebSql
            | Self::ChromiumQuota
            | Self::ChromiumKeywords
            | Self::ChromiumShortcuts => {
                unreachable!("Site-storage tables use the cookie snapshot owner")
            }
        }
    }

    fn required_columns(self) -> &'static [&'static str] {
        match self {
            Self::GenericSqlite(_) => {
                unreachable!("Generic table groups have their own snapshot owner")
            }
            Self::ChromiumHistory => &["id", "url", "title", "visit_count", "last_visit_time"],
            Self::ChromiumCookies => &[
                "host_key",
                "name",
                "path",
                "expires_utc",
                "creation_utc",
                "last_access_utc",
            ],
            Self::ChromiumDownloads => &["id", "target_path", "start_time", "received_bytes"],
            Self::FirefoxHistory => &[
                "id",
                "url",
                "title",
                "visit_count",
                "last_visit_date",
                "foreign_count",
            ],
            Self::FirefoxCookies => &[
                "id",
                "host",
                "name",
                "path",
                "expiry",
                "creationTime",
                "lastAccessed",
            ],
            Self::FirefoxDownloads => &["id", "source", "target", "startTime", "endTime", "state"],
            Self::ChromiumOriginCerts => &["origin", "creation_time"],
            Self::ChromiumChannelIds => &["host", "creation_time"],
            Self::FirefoxOfflinePermissions => &["id", "host", "type", "permission"],
            Self::FirefoxWebApps => &["domain"],
            Self::FirefoxWebApps2 => &["scope"],
            Self::ChromiumWebSql => &["origin", "id"],
            Self::ChromiumQuota => unreachable!("Quota storage has a dedicated schema owner"),
            Self::ChromiumKeywords => &["safe_for_autoreplace"],
            Self::ChromiumShortcuts => &["url", "id"],
        }
    }

    fn identity_sql(self) -> &'static str {
        match self {
            Self::GenericSqlite(_) => {
                unreachable!("Generic table groups have their own snapshot owner")
            }
            Self::ChromiumHistory => {
                "SELECT rowid,id,url,title,visit_count,last_visit_time FROM urls WHERE rowid=?1"
            }
            Self::ChromiumCookies => {
                "SELECT rowid,host_key,name,path,expires_utc,creation_utc,last_access_utc FROM cookies WHERE rowid=?1"
            }
            Self::ChromiumDownloads => {
                "SELECT d.rowid,d.id,COALESCE((SELECT u.url FROM downloads_url_chains u WHERE u.id=d.id ORDER BY u.chain_index DESC LIMIT 1),''),d.target_path,d.start_time,d.received_bytes,COALESCE((SELECT group_concat(signature, ',') FROM (SELECT chain_index || ':' || hex(url) AS signature FROM downloads_url_chains WHERE id=d.id ORDER BY chain_index)), '') FROM downloads d WHERE d.rowid=?1"
            }
            Self::FirefoxHistory => {
                "SELECT rowid,id,url,title,visit_count,last_visit_date,foreign_count FROM moz_places WHERE rowid=?1 AND EXISTS (SELECT 1 FROM moz_historyvisits WHERE place_id=moz_places.id)"
            }
            Self::FirefoxCookies => {
                "SELECT rowid,id,host,name,path,expiry,creationTime,lastAccessed FROM moz_cookies WHERE rowid=?1"
            }
            Self::FirefoxDownloads => {
                "SELECT rowid,id,source,target,startTime,endTime,state FROM moz_downloads WHERE rowid=?1"
            }
            Self::ChromiumOriginCerts
            | Self::ChromiumChannelIds
            | Self::FirefoxOfflinePermissions
            | Self::FirefoxWebApps
            | Self::FirefoxWebApps2
            | Self::ChromiumWebSql
            | Self::ChromiumQuota
            | Self::ChromiumKeywords
            | Self::ChromiumShortcuts => {
                unreachable!("Site-storage tables use the cookie snapshot owner")
            }
        }
    }

    fn row_identity(self, row: &rusqlite::Row<'_>) -> rusqlite::Result<Vec<Value>> {
        (1..row.as_ref().column_count())
            .map(|column| {
                let value = row.get_ref(column)?;
                if let rusqlite::types::ValueRef::Text(bytes) = value {
                    std::str::from_utf8(bytes).map_err(rusqlite::Error::Utf8Error)?;
                }
                Ok(Value::from(value))
            })
            .collect()
    }

    fn row_id(self, row: &rusqlite::Row<'_>) -> rusqlite::Result<i64> {
        let row_id: i64 = row.get(0)?;
        if self != Self::ChromiumCookies {
            let declared_id: i64 = row.get(1)?;
            if declared_id != row_id {
                return Err(rusqlite::Error::InvalidQuery);
            }
        }
        Ok(row_id)
    }

    fn site(self, row: &rusqlite::Row<'_>) -> rusqlite::Result<String> {
        let text: String = match self {
            Self::GenericSqlite(_) => {
                unreachable!("Generic table groups have their own snapshot owner")
            }
            Self::ChromiumHistory | Self::ChromiumDownloads => row.get(2)?,
            Self::ChromiumCookies => row.get(1)?,
            Self::FirefoxHistory | Self::FirefoxDownloads => row.get(2)?,
            Self::FirefoxCookies => row.get(2)?,
            Self::ChromiumOriginCerts
            | Self::ChromiumChannelIds
            | Self::FirefoxOfflinePermissions
            | Self::FirefoxWebApps
            | Self::FirefoxWebApps2
            | Self::ChromiumWebSql
            | Self::ChromiumQuota
            | Self::ChromiumKeywords
            | Self::ChromiumShortcuts => {
                unreachable!("Site-storage tables use the cookie snapshot owner")
            }
        };
        Ok(safe_site_label(&text))
    }

    fn verify_delete_schema(self, conn: &Connection) -> Result<(), String> {
        if matches!(self, Self::GenericSqlite(_)) {
            return Err("Generic table groups require their reviewed snapshot owner.".into());
        }
        if self == Self::FirefoxDownloads {
            return Err(
                "Firefox download-history records do not have a supported standalone schema."
                    .into(),
            );
        }
        let columns = table_columns(conn, self.table())?;
        if !self
            .required_columns()
            .iter()
            .all(|name| columns.contains(&name.to_ascii_lowercase()))
        {
            return Err("The browser database schema is not supported.".into());
        }
        match self {
            Self::ChromiumHistory => {
                let visits = table_columns(conn, "visits")?;
                if !["id", "url", "visit_time", "from_visit"]
                    .iter()
                    .all(|name| visits.contains(*name))
                {
                    return Err("The browser history schema is not supported.".into());
                }
                verify_optional_columns(conn, "visit_source", &["id"])?;
                verify_optional_columns(conn, "keyword_search_terms", &["url_id"])?;
                let segments = optional_table_columns(conn, "segments")?;
                if let Some(columns) = segments {
                    if !["id", "url_id"].iter().all(|name| columns.contains(*name)) {
                        return Err("The browser history schema is not supported.".into());
                    }
                    verify_optional_columns(conn, "segment_usage", &["segment_id"])?;
                }
                for (table, required) in [
                    ("content_annotations", &["visit_id"][..]),
                    ("context_annotations", &["visit_id"][..]),
                    ("clusters_and_visits", &["cluster_id", "visit_id"][..]),
                    (
                        "cluster_visit_duplicates",
                        &["visit_id", "duplicate_visit_id"][..],
                    ),
                    ("clusters", &["cluster_id"][..]),
                    ("cluster_keywords", &["cluster_id"][..]),
                ] {
                    verify_optional_columns(conn, table, required)?;
                }
            }
            Self::FirefoxHistory => {
                let visits = table_columns(conn, "moz_historyvisits")?;
                if !["id", "place_id", "from_visit", "visit_date"]
                    .iter()
                    .all(|name| visits.contains(*name))
                {
                    return Err("The browser history schema is not supported.".into());
                }
            }
            Self::ChromiumDownloads => {
                let chains = table_columns(conn, "downloads_url_chains")?;
                if !["id", "chain_index", "url"]
                    .iter()
                    .all(|name| chains.contains(*name))
                {
                    return Err("The browser download-history schema is not supported.".into());
                }
                verify_optional_columns(conn, "downloads_slices", &["download_id"])?;
            }
            Self::FirefoxDownloads => {
                unreachable!("unsupported Firefox downloads are rejected above")
            }
            _ => {}
        }
        Ok(())
    }

    fn delete(self, tx: &rusqlite::Transaction<'_>, row_id: i64) -> rusqlite::Result<usize> {
        match self {
            Self::GenericSqlite(_) => {
                unreachable!("Generic table groups have their own snapshot owner")
            }
            Self::ChromiumHistory => {
                let mut visits = Vec::new();
                {
                    let mut statement =
                        tx.prepare("SELECT id,from_visit FROM visits WHERE url=?1 ORDER BY id")?;
                    let rows = statement.query_map([row_id], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?))
                    })?;
                    for row in rows {
                        visits.push(row?);
                    }
                }
                for (visit_id, referring_visit) in visits {
                    tx.execute(
                        "UPDATE visits SET from_visit=?1 WHERE from_visit=?2",
                        rusqlite::params![referring_visit, visit_id],
                    )?;
                    for table in ["content_annotations", "context_annotations"] {
                        if has_table(tx, table)? {
                            let sql = format!("DELETE FROM {table} WHERE visit_id=?1");
                            tx.execute(&sql, [visit_id])?;
                        }
                    }
                    delete_chromium_cluster_visit(tx, visit_id)?;
                    if has_table(tx, "visit_source")? {
                        tx.execute("DELETE FROM visit_source WHERE id=?1", [visit_id])?;
                    }
                    tx.execute("DELETE FROM visits WHERE id=?1", [visit_id])?;
                }
                if has_table(tx, "segments")? {
                    if has_table(tx, "segment_usage")? {
                        tx.execute(
                            "DELETE FROM segment_usage WHERE segment_id IN (SELECT id FROM segments WHERE url_id=?1)",
                            [row_id],
                        )?;
                    }
                    tx.execute("DELETE FROM segments WHERE url_id=?1", [row_id])?;
                }
                if has_table(tx, "keyword_search_terms")? {
                    tx.execute("DELETE FROM keyword_search_terms WHERE url_id=?1", [row_id])?;
                }
                tx.execute("DELETE FROM urls WHERE rowid=?1", [row_id])
            }
            Self::ChromiumCookies => tx.execute("DELETE FROM cookies WHERE rowid=?1", [row_id]),
            Self::ChromiumDownloads => {
                tx.execute("DELETE FROM downloads_url_chains WHERE id=?1", [row_id])?;
                if has_table(tx, "downloads_slices")? {
                    tx.execute(
                        "DELETE FROM downloads_slices WHERE download_id=?1",
                        [row_id],
                    )?;
                }
                tx.execute("DELETE FROM downloads WHERE id=?1", [row_id])
            }
            Self::FirefoxHistory => {
                let visit_columns = table_columns(tx, "moz_historyvisits")
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                if !visit_columns.contains("from_visit") || !visit_columns.contains("visit_date") {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                tx.execute(
                    "UPDATE moz_historyvisits SET from_visit=NULL WHERE from_visit IN (SELECT id FROM moz_historyvisits WHERE place_id=?1)",
                    [row_id],
                )?;
                tx.execute("DELETE FROM moz_historyvisits WHERE place_id=?1", [row_id])?;
                tx.execute(
                    "UPDATE moz_places SET visit_count=(SELECT count(*) FROM moz_historyvisits WHERE place_id=?1), last_visit_date=(SELECT max(visit_date) FROM moz_historyvisits WHERE place_id=?1) WHERE id=?1",
                    [row_id],
                )?;
                // moz_places is shared with bookmarks and other Places metadata. Keep
                // the page row; Firefox's own History.remove API performs conditional
                // orphan cleanup and observer/sync work that cannot be reproduced here.
                Ok(1)
            }
            Self::FirefoxCookies => tx.execute("DELETE FROM moz_cookies WHERE rowid=?1", [row_id]),
            Self::FirefoxDownloads => Err(rusqlite::Error::InvalidQuery),
            Self::ChromiumOriginCerts
            | Self::ChromiumChannelIds
            | Self::FirefoxOfflinePermissions
            | Self::FirefoxWebApps
            | Self::FirefoxWebApps2
            | Self::ChromiumWebSql
            | Self::ChromiumQuota
            | Self::ChromiumKeywords
            | Self::ChromiumShortcuts => {
                unreachable!("Site-storage tables use the cookie snapshot owner")
            }
        }
    }
}

fn has_table(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [table],
        |row| row.get(0),
    )
}

fn optional_table_columns(
    conn: &Connection,
    table: &str,
) -> Result<Option<HashSet<String>>, String> {
    if has_table(conn, table).map_err(|_| "Schema is unreadable.".to_owned())? {
        table_columns(conn, table).map(Some)
    } else {
        Ok(None)
    }
}

fn verify_optional_columns(
    conn: &Connection,
    table: &str,
    required: &[&str],
) -> Result<(), String> {
    if let Some(columns) = optional_table_columns(conn, table)? {
        if !required.iter().all(|name| columns.contains(*name)) {
            return Err("The browser database dependency schema is not supported.".into());
        }
    }
    Ok(())
}

fn delete_chromium_cluster_visit(
    tx: &rusqlite::Transaction<'_>,
    visit_id: i64,
) -> rusqlite::Result<()> {
    if has_table(tx, "cluster_visit_duplicates")? {
        tx.execute(
            "DELETE FROM cluster_visit_duplicates WHERE visit_id=?1 OR duplicate_visit_id=?1",
            [visit_id],
        )?;
    }
    if !has_table(tx, "clusters_and_visits")? {
        return Ok(());
    }

    let cluster_ids = {
        let mut statement = tx.prepare(
            "SELECT cluster_id FROM clusters_and_visits WHERE visit_id=?1 ORDER BY cluster_id",
        )?;
        statement
            .query_map([visit_id], |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for cluster_id in cluster_ids {
        let member_count: i64 = tx.query_row(
            "SELECT count(*) FROM clusters_and_visits WHERE cluster_id=?1",
            [cluster_id],
            |row| row.get(0),
        )?;
        if member_count == 1 {
            if has_table(tx, "cluster_keywords")? {
                tx.execute(
                    "DELETE FROM cluster_keywords WHERE cluster_id=?1",
                    [cluster_id],
                )?;
            }
            tx.execute(
                "DELETE FROM clusters_and_visits WHERE cluster_id=?1",
                [cluster_id],
            )?;
            if has_table(tx, "clusters")? {
                tx.execute("DELETE FROM clusters WHERE cluster_id=?1", [cluster_id])?;
            }
        } else {
            tx.execute(
                "DELETE FROM clusters_and_visits WHERE cluster_id=?1 AND visit_id=?2",
                rusqlite::params![cluster_id, visit_id],
            )?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct DatabaseTarget {
    path: PathBuf,
    kind: TableKind,
}

// Only a missing component below a verified, nonlinked profile makes an optional
// store absent. In particular, a dangling link must never look like absence.
fn optional_database_absent(root: &Path, path: &Path) -> Result<bool, ()> {
    safe_profile_root(root).map_err(|_| ())?;
    let relative = path.strip_prefix(root).map_err(|_| ())?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err(());
    }
    let mut current = root.to_owned();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return Err(());
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(_) => return Err(()),
            Ok(metadata) => {
                if is_link(&metadata)
                    || (index + 1 < components.len() && !metadata.is_dir())
                    || (index + 1 == components.len() && !metadata.is_file())
                {
                    return Err(());
                }
            }
        }
    }
    Ok(false)
}

fn database_targets(profile: &BrowserProfile) -> Vec<DatabaseTarget> {
    if profile.browser.is_chromium() {
        let mut targets = vec![DatabaseTarget {
            path: profile.root.join("History"),
            kind: TableKind::ChromiumHistory,
        }];
        targets.extend(CHROMIUM_COOKIE_DATABASES.iter().map(|name| DatabaseTarget {
            path: profile.root.join(name),
            kind: TableKind::ChromiumCookies,
        }));
        targets.extend(
            CHROMIUM_SITE_DATABASES
                .iter()
                .map(|(name, kind)| DatabaseTarget {
                    path: profile.root.join(name),
                    kind: *kind,
                }),
        );
        targets.extend(
            CHROMIUM_HISTORY_DATABASES
                .iter()
                .map(|(name, kind)| DatabaseTarget {
                    path: profile.root.join(name),
                    kind: *kind,
                }),
        );
        targets.push(DatabaseTarget {
            path: profile.root.join("History"),
            kind: TableKind::ChromiumDownloads,
        });
        targets
    } else {
        let mut targets = vec![
            DatabaseTarget {
                path: profile.root.join("places.sqlite"),
                kind: TableKind::FirefoxHistory,
            },
            DatabaseTarget {
                path: profile.root.join("cookies.sqlite"),
                kind: TableKind::FirefoxCookies,
            },
            DatabaseTarget {
                path: profile.root.join("places.sqlite"),
                kind: TableKind::FirefoxDownloads,
            },
        ];
        targets.extend(
            MOZILLA_SITE_DATABASES
                .iter()
                .map(|(name, kind)| DatabaseTarget {
                    path: profile.root.join(name),
                    kind: *kind,
                }),
        );
        targets
    }
}

/// Discover declared Windows browser profile patterns and existing macOS roots.
pub fn discover_profiles() -> ProfileInventory {
    let mut inventory = ProfileInventory::default();
    let mut roots = Vec::new();
    if cfg!(windows) {
        inventory = profile_discovery::reference_profiles(|environment| match environment {
            "localappdata" => dirs::data_local_dir(),
            "appdata" => dirs::data_dir(),
            "programfiles" => std::env::var_os("ProgramFiles").map(PathBuf::from),
            _ => None,
        });
        if let Some(roaming) = dirs::data_dir() {
            roots.push((Browser::Firefox, roaming.join("Mozilla/Firefox")));
        }
        #[cfg(windows)]
        for browser in [Browser::Chrome, Browser::Edge] {
            match windows_user_data_policy_roots(browser) {
                Ok(policy_roots) => {
                    roots.extend(policy_roots.into_iter().map(|root| (browser, root)))
                }
                Err(_) => {
                    inventory.partial = true;
                    inventory.skipped.push(InventorySkip {
                        path: None,
                        reason: format!("{} profile policy could not be read.", browser.label()),
                    });
                }
            }
        }
    } else if cfg!(target_os = "macos") {
        if let Some(home) = dirs::home_dir() {
            let support = home.join("Library/Application Support");
            roots.push((Browser::Chrome, support.join("Google/Chrome")));
            roots.push((Browser::Edge, support.join("Microsoft Edge")));
            roots.push((Browser::Firefox, support.join("Firefox")));
        }
    } else {
        inventory.partial = true;
        inventory.skipped.push(InventorySkip {
            path: None,
            reason: "Profile discovery is supported on Windows and macOS.".into(),
        });
        return inventory;
    }

    let mut seen_roots = HashSet::new();
    for (browser, root) in roots {
        if !seen_roots.insert((browser, path_identity(&root))) {
            continue;
        }
        if inventory.profiles.len() >= MAX_PROFILES {
            inventory.partial = true;
            inventory.skipped.push(InventorySkip {
                path: Some(root),
                reason: "Profile limit reached.".into(),
            });
            break;
        }
        match root.try_exists() {
            Ok(false) => continue,
            Ok(true) => {}
            Err(_) => {
                inventory.partial = true;
                inventory.skipped.push(InventorySkip {
                    path: None,
                    reason: format!(
                        "{} profile root could not be checked; discovery may be incomplete.",
                        browser.label()
                    ),
                });
                continue;
            }
        }
        let safe = match safe_profile_root(&root) {
            Ok(path) => path,
            Err(_) => {
                inventory.partial = true;
                inventory.skipped.push(InventorySkip {
                    path: Some(root),
                    reason: "Browser profile root is unavailable or redirected.".into(),
                });
                continue;
            }
        };
        if browser.is_chromium() {
            profile_discovery::user_data_profiles(browser, &safe, &mut inventory);
        } else {
            discover_firefox_profiles(&safe, &mut inventory);
        }
    }
    // Prefer explicit profiles.ini names over an earlier folder-pattern match.
    let mut seen_profiles = HashSet::new();
    inventory.profiles.reverse();
    inventory
        .profiles
        .retain(|profile| seen_profiles.insert((profile.browser, path_identity(&profile.root))));
    inventory.profiles.reverse();
    inventory.profiles.sort_by(|left, right| {
        left.browser
            .label()
            .cmp(right.browser.label())
            .then_with(|| left.name.cmp(&right.name))
    });
    if inventory.profiles.is_empty() {
        mark_empty_inventory_if_indeterminate(&mut inventory, running_browsers());
    }
    inventory
}

fn mark_empty_inventory_if_indeterminate(
    inventory: &mut ProfileInventory,
    running: Result<Vec<RunningBrowser>, String>,
) {
    if !inventory.profiles.is_empty() {
        return;
    }
    match running {
        Ok(processes) if processes.is_empty() => {}
        Ok(processes) => {
            inventory.partial = true;
            inventory.skipped.push(InventorySkip {
                path: None,
                reason: format!(
                    "{} supported browser process(es) are running, but no profile was found in known locations; the active profile location could not be confirmed.",
                    processes.len()
                ),
            });
        }
        Err(_) => {
            inventory.partial = true;
            inventory.skipped.push(InventorySkip {
                path: None,
                reason: "No profile was found in known locations and running-browser status could not be checked; discovery may be incomplete.".into(),
            });
        }
    }
}

#[cfg(windows)]
fn windows_user_data_policy_roots(browser: Browser) -> Result<Vec<PathBuf>, String> {
    use windows::{
        Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
        Win32::System::Registry::{
            HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ, REG_SZ,
            REG_VALUE_TYPE, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
        },
        core::PCWSTR,
    };

    let policy = match browser {
        Browser::Chrome => "Software\\Policies\\Google\\Chrome",
        Browser::Edge => "Software\\Policies\\Microsoft\\Edge",
        _ => return Ok(Vec::new()),
    };
    let key_name = policy
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let value_name = "UserDataDir"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut roots = Vec::new();
    for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let mut key = HKEY(std::ptr::null_mut());
        let status =
            unsafe { RegOpenKeyExW(hive, PCWSTR(key_name.as_ptr()), None, KEY_READ, &mut key) };
        if status == ERROR_FILE_NOT_FOUND {
            continue;
        }
        if status != ERROR_SUCCESS {
            return Err(format!(
                "Registry policy could not be opened (error {}).",
                status.0
            ));
        }
        let value = (|| -> Result<Option<PathBuf>, String> {
            let mut value_type = REG_VALUE_TYPE(0);
            let mut bytes = 0u32;
            let status = unsafe {
                RegQueryValueExW(
                    key,
                    PCWSTR(value_name.as_ptr()),
                    None,
                    Some(&mut value_type),
                    None,
                    Some(&mut bytes),
                )
            };
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            if status != ERROR_SUCCESS || bytes == 0 || bytes > 65_536 || !bytes.is_multiple_of(2) {
                return Err("Browser profile policy value is invalid.".into());
            }
            let mut data = vec![0u8; bytes as usize];
            let status = unsafe {
                RegQueryValueExW(
                    key,
                    PCWSTR(value_name.as_ptr()),
                    None,
                    Some(&mut value_type),
                    Some(data.as_mut_ptr()),
                    Some(&mut bytes),
                )
            };
            if status != ERROR_SUCCESS || (value_type != REG_SZ && value_type != REG_EXPAND_SZ) {
                return Err("Browser profile policy value is unsupported.".into());
            }
            data.truncate(bytes as usize);
            let wide = data
                .chunks_exact(2)
                .map(|word| u16::from_le_bytes([word[0], word[1]]))
                .take_while(|word| *word != 0)
                .collect::<Vec<_>>();
            let raw = String::from_utf16(&wide)
                .map_err(|_| "Browser profile policy is not valid UTF-16.".to_owned())?;
            let expanded = if value_type == REG_EXPAND_SZ {
                expand_percent_environment_variables(&raw)
            } else {
                raw
            };
            let root = PathBuf::from(expanded.trim());
            if !root.is_absolute() {
                return Err("Browser profile policy path must be absolute.".into());
            }
            Ok(Some(root))
        })();
        unsafe {
            let _ = RegCloseKey(key);
        }
        if let Some(root) = value? {
            roots.push(root);
        }
    }
    roots.sort_by_key(|root| path_identity(root));
    roots.dedup_by(|left, right| same_path(left, right));
    Ok(roots)
}

#[cfg(windows)]
fn expand_percent_environment_variables(value: &str) -> String {
    let mut output = String::new();
    let mut remaining = value;
    while let Some(start) = remaining.find('%') {
        output.push_str(&remaining[..start]);
        let after_start = &remaining[start + 1..];
        let Some(end) = after_start.find('%') else {
            output.push_str(&remaining[start..]);
            return output;
        };
        let variable = &after_start[..end];
        if variable.is_empty() {
            output.push('%');
            remaining = &after_start[1..];
            continue;
        }
        if let Some(expanded) = std::env::var_os(variable) {
            output.push_str(&expanded.to_string_lossy());
        } else {
            output.push('%');
            output.push_str(variable);
            output.push('%');
        }
        remaining = &after_start[end + 1..];
    }
    output.push_str(remaining);
    output
}

fn discover_firefox_profiles(root: &Path, inventory: &mut ProfileInventory) {
    let ini = fs::read_to_string(root.join("profiles.ini")).unwrap_or_default();
    let mut section = String::new();
    let mut name = None::<String>;
    let mut path = None::<String>;
    let mut relative = true;
    let mut parsed = Vec::new();
    let finish = |section: &str,
                  name: &mut Option<String>,
                  path: &mut Option<String>,
                  relative: bool,
                  parsed: &mut Vec<(String, PathBuf)>| {
        if section.starts_with("Profile") {
            if let Some(profile_path) = path.take() {
                let base = PathBuf::from(&profile_path);
                let full = if relative { root.join(base) } else { base };
                parsed.push((
                    name.take().unwrap_or_else(|| "Firefox profile".into()),
                    full,
                ));
            }
        }
        *name = None;
        *path = None;
    };
    for line in ini.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            finish(&section, &mut name, &mut path, relative, &mut parsed);
            section = line.trim_matches(['[', ']']).to_owned();
            relative = true;
        } else if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "Name" => name = Some(value.trim().to_owned()),
                "Path" => path = Some(value.trim().to_owned()),
                "IsRelative" => relative = value.trim() != "0",
                _ => {}
            }
        }
    }
    finish(&section, &mut name, &mut path, relative, &mut parsed);
    if parsed.is_empty() {
        if let Ok(entries) = fs::read_dir(root.join("Profiles")) {
            for entry in entries.flatten() {
                parsed.push((
                    entry.file_name().to_string_lossy().into_owned(),
                    entry.path(),
                ));
            }
        }
    }
    for (name, profile_path) in parsed {
        if inventory.profiles.len() >= MAX_PROFILES {
            inventory.partial = true;
            break;
        }
        if !safe_profile_directory(root, &profile_path, true) {
            inventory.partial = true;
            inventory.skipped.push(InventorySkip {
                path: Some(profile_path),
                reason: "Firefox profile is linked, outside its profile root, or unavailable."
                    .into(),
            });
            continue;
        }
        inventory
            .profiles
            .push(make_profile(Browser::Firefox, name, profile_path));
    }
}

fn safe_profile_directory(root: &Path, directory: &Path, allow_external: bool) -> bool {
    let Ok(metadata) = fs::symlink_metadata(directory) else {
        return false;
    };
    if is_link(&metadata) || !metadata.is_dir() {
        return false;
    }
    if !allow_external && !contains_named_path(root, directory) {
        return false;
    }
    dunce::canonicalize(directory).is_ok_and(|canonical| {
        same_named_path(&canonical, directory)
            && (allow_external || contains_named_path(root, &canonical))
    })
}

fn make_profile(browser: Browser, name: String, root: PathBuf) -> BrowserProfile {
    let root = dunce::canonicalize(&root)
        .ok()
        .filter(|canonical| same_named_path(canonical, &root))
        .unwrap_or(root);
    let id = format!(
        "{}:{}",
        browser.label().to_ascii_lowercase(),
        path_identity(&root)
    );
    BrowserProfile {
        id,
        browser,
        name,
        root,
    }
}

fn path_identity(path: &Path) -> String {
    let text = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        text.to_ascii_lowercase()
    } else {
        text
    }
}

/// Enumerate the supported browser processes without reading command-line arguments.
pub fn running_browsers() -> Result<Vec<RunningBrowser>, String> {
    #[cfg(windows)]
    {
        return running_browsers_windows();
    }
    #[cfg(target_os = "macos")]
    {
        return running_browsers_macos();
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err("Running-browser detection is supported on Windows and macOS.".into())
    }
}

/// Ask only the selected browser processes to close gracefully, then re-enumerate them.
/// This never terminates a process forcibly.
pub fn request_close_selected(selected: &[RunningBrowser]) -> CloseRequestReport {
    let mut report = CloseRequestReport::default();
    let current = match running_browsers() {
        Ok(processes) => processes,
        Err(error) => {
            report.errors.push(error);
            return report;
        }
    };
    let selected_current: Vec<_> = selected
        .iter()
        .filter_map(|requested| {
            match current.iter().find(|candidate| {
                candidate.pid == requested.pid
                    && candidate.browser == requested.browser
                    && candidate
                        .executable
                        .eq_ignore_ascii_case(&requested.executable)
            }) {
                Some(candidate) => Some(candidate.clone()),
                None => {
                    report.stale_selection.push(requested.clone());
                    None
                }
            }
        })
        .collect();
    #[cfg(windows)]
    request_windows_close(&selected_current, &mut report);
    #[cfg(target_os = "macos")]
    request_macos_close(&selected_current, &mut report);
    #[cfg(not(any(windows, target_os = "macos")))]
    if !selected_current.is_empty() {
        report
            .errors
            .push("Graceful browser close requests are supported on Windows and macOS.".into());
    }
    if !selected_current.is_empty() {
        thread::sleep(Duration::from_millis(700));
    }
    match running_browsers() {
        Ok(now) => {
            report.still_running = now
                .into_iter()
                .filter(|process| {
                    selected_current.iter().any(|selected| {
                        selected.pid == process.pid && selected.browser == process.browser
                    })
                })
                .collect()
        }
        Err(error) => report
            .errors
            .push(format!("Could not verify browser close status: {error}")),
    }
    report
}

#[cfg(windows)]
fn running_browsers_windows() -> Result<Vec<RunningBrowser>, String> {
    use windows::Win32::{
        Foundation::CloseHandle,
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        },
    };
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| e.to_string())?;
    let mut entry = PROCESSENTRY32W::default();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut processes = Vec::new();
    let mut next = unsafe { Process32FirstW(snapshot, &mut entry) };
    while next.is_ok() {
        let end = entry
            .szExeFile
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(entry.szExeFile.len());
        let executable = String::from_utf16_lossy(&entry.szExeFile[..end]);
        if let Some(browser) = browser_for_executable(&executable) {
            processes.push(RunningBrowser {
                browser,
                pid: entry.th32ProcessID,
                executable,
            });
        }
        next = unsafe { Process32NextW(snapshot, &mut entry) };
    }
    let _ = unsafe { CloseHandle(snapshot) };
    processes.sort_by(|left, right| {
        left.browser
            .label()
            .cmp(right.browser.label())
            .then_with(|| left.pid.cmp(&right.pid))
    });
    Ok(processes)
}

#[cfg(windows)]
fn request_windows_close(selected: &[RunningBrowser], report: &mut CloseRequestReport) {
    use std::collections::HashSet;
    use windows::Win32::{
        Foundation::{HWND, LPARAM},
        UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE},
    };
    use windows::core::BOOL;
    struct WindowsToClose {
        pids: HashSet<u32>,
        windows: Vec<(u32, HWND)>,
    }
    unsafe extern "system" fn collect(hwnd: HWND, parameter: LPARAM) -> BOOL {
        let state = unsafe { &mut *(parameter.0 as *mut WindowsToClose) };
        let mut pid = 0;
        unsafe {
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
        }
        if state.pids.contains(&pid) {
            state.windows.push((pid, hwnd));
        }
        BOOL(1)
    }
    let mut state = WindowsToClose {
        pids: selected.iter().map(|process| process.pid).collect(),
        windows: Vec::new(),
    };
    if let Err(error) = unsafe {
        EnumWindows(
            Some(collect),
            LPARAM((&mut state as *mut WindowsToClose) as isize),
        )
    } {
        report
            .errors
            .push(format!("Could not enumerate browser windows: {error}"));
        return;
    }
    let mut requested_pids = HashSet::new();
    for (pid, hwnd) in state.windows {
        match unsafe { PostMessageW(Some(hwnd), WM_CLOSE, Default::default(), Default::default()) }
        {
            Ok(()) => {
                requested_pids.insert(pid);
            }
            Err(error) => report.errors.push(format!(
                "Could not send a close request to process {pid}: {error}"
            )),
        }
    }
    for process in selected {
        if requested_pids.contains(&process.pid) {
            report.requested.push(process.clone());
        } else {
            report.errors.push(format!(
                "No closable browser window was found for process {}.",
                process.pid
            ));
        }
    }
}

#[cfg(target_os = "macos")]
fn running_browsers_macos() -> Result<Vec<RunningBrowser>, String> {
    use std::ffi::{c_char, c_int, c_void};
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_listpids(
            kind: u32,
            type_info: u32,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;
        fn proc_name(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
    }
    const PROC_ALL_PIDS: u32 = 1;
    let mut pids = vec![0i32; 32_768];
    let bytes = unsafe {
        proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast(),
            std::mem::size_of_val(&*pids) as c_int,
        )
    };
    if bytes < 0 {
        return Err("macOS could not enumerate processes.".into());
    }
    let count = (bytes as usize / std::mem::size_of::<i32>()).min(pids.len());
    let mut processes = Vec::new();
    for pid in pids.into_iter().take(count).filter(|pid| *pid > 0) {
        let mut name = [0 as c_char; 256];
        let length = unsafe { proc_name(pid, name.as_mut_ptr().cast(), name.len() as u32) };
        if length <= 0 {
            continue;
        }
        let executable = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        if let Some(browser) = browser_for_executable(&executable) {
            processes.push(RunningBrowser {
                browser,
                pid: pid as u32,
                executable,
            });
        }
    }
    processes.sort_by(|left, right| {
        left.browser
            .label()
            .cmp(right.browser.label())
            .then_with(|| left.pid.cmp(&right.pid))
    });
    Ok(processes)
}

#[cfg(target_os = "macos")]
fn request_macos_close(selected: &[RunningBrowser], report: &mut CloseRequestReport) {
    use std::ffi::c_int;
    unsafe extern "C" {
        fn kill(pid: c_int, signal: c_int) -> c_int;
    }
    const SIGTERM: c_int = 15;
    for process in selected {
        if unsafe { kill(process.pid as c_int, SIGTERM) } == 0 {
            report.requested.push(process.clone());
        } else {
            report.errors.push(format!(
                "Could not send a graceful close request to process {}.",
                process.pid
            ));
        }
    }
}

fn browser_for_executable(executable: &str) -> Option<Browser> {
    let lower = executable.to_ascii_lowercase();
    Browser::ALL
        .iter()
        .copied()
        .find(|browser| browser.process_names().iter().any(|name| lower == *name))
}

/// Read supported privacy rows without modifying browser databases.
pub fn scan_profiles(
    profiles: &[BrowserProfile],
    cancel: &AtomicBool,
    progress: impl FnMut(PrivacyProgress),
) -> PrivacyReport {
    let settings = CookieExceptionSettings::default();
    scan_profiles_with_settings(
        profiles,
        &PrivacyCategory::DEFAULT,
        &settings,
        cancel,
        progress,
    )
}

/// Read only selected browser categories and omit cookies protected by saved host exceptions.
/// Omitted cookie rows are counted but never exposed as selectable cleanup records.
pub fn scan_profiles_with_settings(
    profiles: &[BrowserProfile],
    categories: &[PrivacyCategory],
    settings: &CookieExceptionSettings,
    cancel: &AtomicBool,
    mut progress: impl FnMut(PrivacyProgress),
) -> PrivacyReport {
    let started = Instant::now();
    let mut included = HashSet::new();
    let selected_categories = categories
        .iter()
        .copied()
        .filter(|category| included.insert(*category))
        .collect::<Vec<_>>();
    let keep_domains = std::sync::Arc::new(
        settings
            .keep_domains
            .iter()
            .filter_map(|domain| normalize_cookie_domain(domain).ok())
            .collect::<HashSet<_>>(),
    );
    let mut report = PrivacyReport {
        id: Uuid::new_v4(),
        profiles_scanned: 0,
        records: Vec::new(),
        skipped: Vec::new(),
        skipped_count: 0,
        omitted_skip_details: 0,
        partial: false,
        truncated: false,
        cancelled: false,
        cookie_exempted: 0,
        categories_scanned: selected_categories.clone(),
        elapsed_ms: 0,
    };
    let mut seen = HashSet::new();
    let selected_profiles = profiles
        .iter()
        .take(MAX_PROFILES)
        .cloned()
        .map(|mut profile| {
            // Only normalize a root after the no-link check succeeds. Invalid
            // roots retain the existing partial-scan refusal path.
            if let Ok(root) = safe_profile_root(&profile.root) {
                profile.root = root;
            }
            profile
        })
        .filter(|profile| seen.insert((profile.browser, path_identity(&profile.root))))
        .collect::<Vec<_>>();
    if profiles.len() > MAX_PROFILES {
        report.truncated = true;
        add_skip(&mut report, "", None, "Profile limit reached.");
    }
    let mut storage_byte_budget = storage_files::MAX_SCAN_BYTES;
    let mut storage_file_budget = MAX_RECORDS;
    let mut seen_storage_paths = HashSet::new();
    let mut leveldb_budget = leveldb::scan_budget();
    for (profile_index, profile) in selected_profiles.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            break;
        }
        report.profiles_scanned += 1;
        let mut targets = database_targets(profile)
            .into_iter()
            .filter(|target| selected_categories.contains(&target.kind.category()))
            .collect::<Vec<_>>();
        let mut storage_paths = Vec::new();
        let mut leveldb_paths = Vec::new();
        if selected_categories.contains(&PrivacyCategory::Cookies) {
            let inventory = storage_files::discover_paths(
                profile.browser,
                &profile.root,
                cancel,
                storage_files::MAX_ENTRIES,
                storage_files::MAX_PATH_BYTES,
            );
            report.cancelled |= inventory.cancelled;
            report.truncated |= inventory.truncated;
            for issue in inventory.issues {
                add_skip(
                    &mut report,
                    &profile.name,
                    Some(PrivacyCategory::Cookies),
                    issue,
                );
            }
            targets.extend(inventory.databases);
            storage_paths = inventory.files;
            leveldb_paths = inventory.leveldb_dirs;
        }
        if selected_categories.iter().any(|c| {
            matches!(
                c,
                PrivacyCategory::History
                    | PrivacyCategory::LastDownloadLocation
                    | PrivacyCategory::SnapLocation
            )
        }) && !report.cancelled
        {
            preferences::scan(profile, &selected_categories, cancel, &mut report);
        }
        let mut seen_targets = HashSet::new();
        targets.retain(|target| {
            !file_owned_category(
                profile.browser,
                target.kind.category(),
                &profile.root,
                &target.path,
            ) && seen_targets.insert((path_identity(&target.path), target.kind))
        });
        for target in targets {
            if cancel.load(Ordering::Relaxed) {
                report.cancelled = true;
                break;
            }
            if report.records.len() >= MAX_RECORDS {
                report.truncated = true;
                add_skip(
                    &mut report,
                    &profile.name,
                    Some(target.kind.category()),
                    "Record limit reached.",
                );
                break;
            }
            scan_database_target(profile, &target, &keep_domains, cancel, &mut report);
            progress(PrivacyProgress {
                profiles_completed: profile_index + 1,
                profiles_total: selected_profiles.len(),
                records_found: report.records.iter().map(PrivacyRecord::item_count).sum(),
                profile_name: profile.name.clone(),
                category: target.kind.category(),
            });
        }
        if !report.cancelled && !report.truncated {
            generic_sqlite::scan(profile, &selected_categories, cancel, &mut report);
        }
        if !report.cancelled && report.records.len() < MAX_RECORDS {
            for observed_file in storage_paths {
                if !seen_storage_paths.insert(storage_files::path_key(&observed_file.path)) {
                    continue;
                }
                if storage_file_budget == 0 {
                    report.truncated = true;
                    add_skip(
                        &mut report,
                        &profile.name,
                        Some(PrivacyCategory::Cookies),
                        "Site-storage file inspection limit reached.",
                    );
                    break;
                }
                storage_file_budget -= 1;
                if cancel.load(Ordering::Relaxed) {
                    report.cancelled = true;
                    break;
                }
                storage_files::scan_file(
                    profile,
                    &observed_file,
                    &keep_domains,
                    cancel,
                    &mut storage_byte_budget,
                    &mut report,
                );
                if report.records.len() >= MAX_RECORDS {
                    report.truncated = true;
                    break;
                }
            }
            record_files::scan(
                profile,
                &selected_categories,
                &keep_domains,
                cancel,
                &mut storage_byte_budget,
                &mut storage_file_budget,
                &mut seen_storage_paths,
                &mut report,
            );
            if selected_categories.contains(&PrivacyCategory::Sessions)
                && !report.cancelled
                && !report.truncated
            {
                session_files::scan(
                    profile,
                    cancel,
                    &mut storage_byte_budget,
                    &mut storage_file_budget,
                    &mut seen_storage_paths,
                    &mut report,
                );
                progress(PrivacyProgress {
                    profiles_completed: profile_index + 1,
                    profiles_total: selected_profiles.len(),
                    records_found: report.records.iter().map(PrivacyRecord::item_count).sum(),
                    profile_name: profile.name.clone(),
                    category: PrivacyCategory::Sessions,
                });
            }
            storage_files::group_records(profile, &mut report, cancel);
            if selected_categories.contains(&PrivacyCategory::Cookies) {
                leveldb::scan(
                    profile,
                    &leveldb_paths,
                    &keep_domains,
                    cancel,
                    &mut leveldb_budget,
                    &mut report,
                );
                progress(PrivacyProgress {
                    profiles_completed: profile_index + 1,
                    profiles_total: selected_profiles.len(),
                    records_found: report.records.iter().map(PrivacyRecord::item_count).sum(),
                    profile_name: profile.name.clone(),
                    category: PrivacyCategory::Cookies,
                });
            }
        }
        if report.cancelled || report.truncated {
            break;
        }
    }
    report.partial = report.cancelled || report.truncated || report.skipped_count > 0;
    report.elapsed_ms = started.elapsed().as_millis() as u64;
    report
}

fn scan_database_target(
    profile: &BrowserProfile,
    target: &DatabaseTarget,
    keep_domains: &HashSet<String>,
    cancel: &AtomicBool,
    report: &mut PrivacyReport,
) {
    let start_index = report.records.len();
    match optional_database_absent(&profile.root, &target.path) {
        Ok(true) => return,
        Ok(false) => {}
        Err(()) => {
            add_skip(
                report,
                &profile.name,
                Some(target.kind.category()),
                "Browser database path is linked, invalid, or unavailable.",
            );
            return;
        }
    }
    let Ok((canonical, before, _root)) = validate_database_path(&profile.root, &target.path) else {
        let reason = match target.path.try_exists() {
            Ok(false) => "Known browser database is missing.",
            Ok(true) => "Database is linked, outside the profile, or unavailable.",
            Err(_) => "Database access could not be checked; this category may be incomplete.",
        };
        add_skip(report, &profile.name, Some(target.kind.category()), reason);
        return;
    };
    if before.length > MAX_DATABASE_BYTES {
        add_skip(
            report,
            &profile.name,
            Some(target.kind.category()),
            "Database exceeds the safe scan size limit.",
        );
        report.truncated = true;
        return;
    }
    let conn = match Connection::open_with_flags(
        &canonical,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(conn) => conn,
        Err(_) => {
            add_skip(
                report,
                &profile.name,
                Some(target.kind.category()),
                "Database is unreadable or busy.",
            );
            return;
        }
    };
    let _ = conn.busy_timeout(Duration::from_secs(2));
    if conn
        .execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
        .is_err()
    {
        add_skip(
            report,
            &profile.name,
            Some(target.kind.category()),
            "Database could not be opened read-only.",
        );
        return;
    }
    if let Some((alternate, report_empty)) = target.kind.alternate_cookie_table() {
        match has_table(&conn, target.kind.table()) {
            Ok(false) => {
                let object_exists = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name=?1 COLLATE NOCASE)",
                    [target.kind.table()],
                    |row| row.get::<_, bool>(0),
                );
                if object_exists != Ok(false) {
                    add_skip(
                        report,
                        &profile.name,
                        Some(PrivacyCategory::Cookies),
                        "Site storage contains an unsupported table object.",
                    );
                    return;
                }
                if report_empty && !has_table(&conn, alternate.table()).unwrap_or(false) {
                    add_skip(
                        report,
                        &profile.name,
                        Some(PrivacyCategory::Cookies),
                        "Site storage has no recognized tables.",
                    );
                }
                return;
            }
            Ok(true) => {}
            Err(_) => {
                add_skip(
                    report,
                    &profile.name,
                    Some(PrivacyCategory::Cookies),
                    "Site storage schema could not be inspected.",
                );
                return;
            }
        }
    }
    if target.kind == TableKind::ChromiumShortcuts {
        shortcuts::scan(&conn, profile, &canonical, &before, cancel, report);
        drop(conn);
        if !file_stamp(&canonical).is_ok_and(|after| after == before) {
            report.records.truncate(start_index);
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::History),
                "Database changed during inventory; its shortcut rows were discarded.",
            );
        }
        return;
    }
    if target.kind == TableKind::ChromiumKeywords {
        keywords::scan(&conn, profile, &canonical, &before, cancel, report);
        drop(conn);
        if !file_stamp(&canonical).is_ok_and(|after| after == before) {
            report.records.truncate(start_index);
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::History),
                "Database changed during inventory; its keyword rows were discarded.",
            );
        }
        return;
    }
    if target.kind == TableKind::ChromiumQuota {
        let observed = conn
            .execute_batch("BEGIN")
            .map_err(|_| "Quota snapshot could not be opened.".to_owned())
            .and_then(|_| quota::Snapshot::read(&conn, keep_domains, cancel));
        match observed {
            Ok(snapshot) => {
                report.cookie_exempted = report.cookie_exempted.saturating_add(snapshot.exempted);
                for reason in &snapshot.issues {
                    add_skip(
                        report,
                        &profile.name,
                        Some(PrivacyCategory::Cookies),
                        reason,
                    );
                }
                for (site, quota) in snapshot.reviews() {
                    if cancel.load(Ordering::Relaxed) {
                        report.cancelled = true;
                        break;
                    }
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
                        category: PrivacyCategory::Cookies,
                        site,
                        locator: RecordLocator::Database(RowLocator {
                            id,
                            browser: profile.browser,
                            profile_id: profile.id.clone(),
                            profile_name: profile.name.clone(),
                            profile_root: profile.root.clone(),
                            database: canonical.clone(),
                            database_stamp: before.clone(),
                            kind: target.kind,
                            row_id: 0,
                            identity: Vec::new(),
                            history: None,
                            download: None,
                            firefox: None,
                            cookie: None,
                            quota: Some(quota),
                            keyword: None,
                            shortcut: None,
                            generic: None,
                        }),
                    });
                }
            }
            Err(reason) => {
                report.cancelled |= cancel.load(Ordering::Relaxed);
                add_skip(
                    report,
                    &profile.name,
                    Some(PrivacyCategory::Cookies),
                    &reason,
                );
            }
        }
        drop(conn);
        if !file_stamp(&canonical).is_ok_and(|after| after == before) {
            report.records.truncate(start_index);
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::Cookies),
                "Database changed during inventory; its rows were discarded.",
            );
        }
        return;
    }
    if target.kind.category() == PrivacyCategory::Cookies {
        let observed = conn
            .execute_batch("BEGIN")
            .map_err(|_| "Cookie snapshot could not be opened.".to_owned())
            .and_then(|_| cookies::Snapshot::read(&conn, target.kind, cancel));
        match observed {
            Ok(snapshot) => {
                for (site, row_id, cookie) in snapshot.reviews() {
                    if cancel.load(Ordering::Relaxed) {
                        report.cancelled = true;
                        break;
                    }
                    if is_cookie_exception(&site, keep_domains) {
                        report.cookie_exempted = report.cookie_exempted.saturating_add(1);
                        continue;
                    }
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
                        category: PrivacyCategory::Cookies,
                        site,
                        locator: RecordLocator::Database(RowLocator {
                            id,
                            browser: profile.browser,
                            profile_id: profile.id.clone(),
                            profile_name: profile.name.clone(),
                            profile_root: profile.root.clone(),
                            database: canonical.clone(),
                            database_stamp: before.clone(),
                            kind: target.kind,
                            row_id,
                            identity: Vec::new(),
                            history: None,
                            download: None,
                            firefox: None,
                            cookie: Some(cookie),
                            quota: None,
                            keyword: None,
                            shortcut: None,
                            generic: None,
                        }),
                    });
                }
            }
            Err(reason) => {
                report.cancelled |= cancel.load(Ordering::Relaxed);
                add_skip(
                    report,
                    &profile.name,
                    Some(PrivacyCategory::Cookies),
                    &reason,
                );
            }
        }
        drop(conn);
        if !file_stamp(&canonical).is_ok_and(|after| after == before) {
            report.records.truncate(start_index);
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::Cookies),
                "Database changed during inventory; its rows were discarded.",
            );
        }
        return;
    }
    if matches!(
        target.kind,
        TableKind::FirefoxHistory | TableKind::FirefoxDownloads
    ) {
        let observed = conn
            .execute_batch("BEGIN")
            .map_err(|_| "Firefox Places snapshot could not be opened.".to_owned())
            .and_then(|_| firefox_places::Snapshot::read(&conn, cancel));
        match observed {
            Ok(snapshot) => {
                for (site, row_id, review) in snapshot.reviews(target.kind.category()) {
                    if cancel.load(Ordering::Relaxed) {
                        report.cancelled = true;
                        break;
                    }
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
                        category: target.kind.category(),
                        site,
                        locator: RecordLocator::Database(RowLocator {
                            id,
                            browser: profile.browser,
                            profile_id: profile.id.clone(),
                            profile_name: profile.name.clone(),
                            profile_root: profile.root.clone(),
                            database: canonical.clone(),
                            database_stamp: before.clone(),
                            kind: target.kind,
                            row_id,
                            identity: Vec::new(),
                            history: None,
                            download: None,
                            firefox: Some(review),
                            cookie: None,
                            quota: None,
                            keyword: None,
                            shortcut: None,
                            generic: None,
                        }),
                    });
                }
            }
            Err(reason) => {
                report.cancelled |= cancel.load(Ordering::Relaxed);
                add_skip(report, &profile.name, Some(target.kind.category()), &reason);
            }
        }
        drop(conn);
        if !file_stamp(&canonical).is_ok_and(|after| after == before) {
            report.records.truncate(start_index);
            add_skip(
                report,
                &profile.name,
                Some(target.kind.category()),
                "Database changed during inventory; its rows were discarded.",
            );
        }
        return;
    }
    if target.kind == TableKind::ChromiumDownloads {
        let observed = conn
            .execute_batch("BEGIN")
            .map_err(|_| "Download snapshot could not be opened.".to_owned())
            .and_then(|_| chromium_downloads::Snapshot::read(&conn, cancel));
        match observed {
            Ok(snapshot) => {
                if let Some(reason) = snapshot.omission {
                    add_skip(
                        report,
                        &profile.name,
                        Some(PrivacyCategory::Downloads),
                        reason,
                    );
                }
                if snapshot.compaction_pending {
                    add_skip(
                        report,
                        &profile.name,
                        Some(PrivacyCategory::Downloads),
                        "Unused database pages were found. Database compaction is not included in this record cleanup.",
                    );
                }
                for (site, row_id, download) in snapshot.reviews() {
                    if cancel.load(Ordering::Relaxed) {
                        report.cancelled = true;
                        break;
                    }
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
                        category: PrivacyCategory::Downloads,
                        site,
                        locator: RecordLocator::Database(RowLocator {
                            id,
                            browser: profile.browser,
                            profile_id: profile.id.clone(),
                            profile_name: profile.name.clone(),
                            profile_root: profile.root.clone(),
                            database: canonical.clone(),
                            database_stamp: before.clone(),
                            kind: target.kind,
                            row_id,
                            identity: Vec::new(),
                            history: None,
                            download: Some(download),
                            firefox: None,
                            cookie: None,
                            quota: None,
                            keyword: None,
                            shortcut: None,
                            generic: None,
                        }),
                    });
                }
            }
            Err(reason) => {
                report.cancelled |= cancel.load(Ordering::Relaxed);
                add_skip(
                    report,
                    &profile.name,
                    Some(PrivacyCategory::Downloads),
                    &reason,
                );
            }
        }
        drop(conn);
        if !file_stamp(&canonical).is_ok_and(|after| after == before) {
            report.records.truncate(start_index);
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::Downloads),
                "Database changed during inventory; its rows were discarded.",
            );
        }
        return;
    }
    if let Err(reason) = target.kind.verify_delete_schema(&conn) {
        add_skip(report, &profile.name, Some(target.kind.category()), &reason);
        return;
    }
    if target.kind == TableKind::ChromiumHistory {
        let observed = (|| {
            conn.execute_batch("BEGIN")
                .map_err(|_| "History snapshot could not be opened.".to_owned())?;
            chromium_history::Snapshot::read(&conn, &profile.root, cancel)
        })();
        match observed {
            Ok(snapshot) => {
                for (site, row_id, history) in snapshot.reviews() {
                    if cancel.load(Ordering::Relaxed) {
                        report.cancelled = true;
                        break;
                    }
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
                        category: PrivacyCategory::History,
                        site,
                        locator: RecordLocator::Database(RowLocator {
                            id,
                            browser: profile.browser,
                            profile_id: profile.id.clone(),
                            profile_name: profile.name.clone(),
                            profile_root: profile.root.clone(),
                            database: canonical.clone(),
                            database_stamp: before.clone(),
                            kind: target.kind,
                            row_id,
                            identity: Vec::new(),
                            history: Some(history),
                            download: None,
                            firefox: None,
                            cookie: None,
                            quota: None,
                            keyword: None,
                            shortcut: None,
                            generic: None,
                        }),
                    });
                }
            }
            Err(reason) => {
                report.cancelled |= cancel.load(Ordering::Relaxed);
                add_skip(
                    report,
                    &profile.name,
                    Some(PrivacyCategory::History),
                    &reason,
                );
            }
        }
        drop(conn);
        if !file_stamp(&canonical).is_ok_and(|after| after == before) {
            report.records.truncate(start_index);
            add_skip(
                report,
                &profile.name,
                Some(PrivacyCategory::History),
                "Database changed during inventory; its rows were discarded.",
            );
        }
        return;
    }
    let remaining = MAX_RECORDS
        .saturating_sub(report.records.len())
        .saturating_add(1);
    let mut statement = match conn.prepare(target.kind.query()) {
        Ok(statement) => statement,
        Err(_) => {
            add_skip(
                report,
                &profile.name,
                Some(target.kind.category()),
                "Browser database schema is unsupported; no rows were read.",
            );
            return;
        }
    };
    let query_limit = i64::try_from(remaining).unwrap_or(i64::MAX);
    let mut rows = match statement.query([query_limit]) {
        Ok(rows) => rows,
        Err(_) => {
            add_skip(
                report,
                &profile.name,
                Some(target.kind.category()),
                "Browser database query was rejected.",
            );
            return;
        }
    };
    let mut query_failed = false;
    while !report.cancelled {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            break;
        }
        let row = match rows.next() {
            Ok(Some(row)) => row,
            Ok(None) => break,
            Err(_) => {
                query_failed = true;
                break;
            }
        };
        if report.records.len() >= MAX_RECORDS {
            report.truncated = true;
            break;
        }
        let row_id = match target.kind.row_id(row) {
            Ok(id) if id >= 0 => id,
            _ => {
                query_failed = true;
                break;
            }
        };
        let identity = match target.kind.row_identity(row) {
            Ok(identity) => identity,
            Err(_) => {
                query_failed = true;
                break;
            }
        };
        let site = match target.kind.site(row) {
            Ok(site) => site,
            Err(_) => {
                query_failed = true;
                break;
            }
        };
        if target.kind.category() == PrivacyCategory::Cookies
            && is_cookie_exception(&site, keep_domains)
        {
            report.cookie_exempted = report.cookie_exempted.saturating_add(1);
            continue;
        }
        let id = Uuid::new_v4();
        report.records.push(PrivacyRecord {
            id,
            browser: profile.browser,
            profile_id: profile.id.clone(),
            profile_name: profile.name.clone(),
            category: target.kind.category(),
            site,
            locator: RecordLocator::Database(RowLocator {
                id,
                browser: profile.browser,
                profile_id: profile.id.clone(),
                profile_name: profile.name.clone(),
                profile_root: profile.root.clone(),
                database: canonical.clone(),
                database_stamp: before.clone(),
                kind: target.kind,
                row_id,
                identity,
                history: None,
                download: None,
                firefox: None,
                cookie: None,
                quota: None,
                keyword: None,
                shortcut: None,
                generic: None,
            }),
        });
    }
    drop(rows);
    drop(statement);
    drop(conn);
    if query_failed {
        report.records.truncate(start_index);
        add_skip(
            report,
            &profile.name,
            Some(target.kind.category()),
            "Database rows could not be read consistently.",
        );
    }
    if !file_stamp(&canonical).is_ok_and(|after| after == before) {
        report.records.truncate(start_index);
        add_skip(
            report,
            &profile.name,
            Some(target.kind.category()),
            "Database changed during inventory; its rows were discarded.",
        );
    }
}

fn add_skip(
    report: &mut PrivacyReport,
    profile: &str,
    category: Option<PrivacyCategory>,
    reason: &str,
) {
    report.skipped_count = report.skipped_count.saturating_add(1);
    if report.skipped.len() < MAX_SKIP_DETAILS {
        report.skipped.push(PrivacySkip {
            profile_name: profile.to_owned(),
            category,
            reason: reason.to_owned(),
        });
    } else {
        report.omitted_skip_details = report.omitted_skip_details.saturating_add(1);
    }
}

fn table_columns(conn: &Connection, table: &str) -> Result<HashSet<String>, String> {
    // `table` comes only from the closed TableKind enum above.
    let sql = format!("PRAGMA table_info('{table}')");
    let mut statement = conn
        .prepare(&sql)
        .map_err(|_| "Schema is unreadable.".to_owned())?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| "Schema is unreadable.".to_owned())?
        .filter_map(Result::ok)
        .map(|column| column.to_ascii_lowercase())
        .collect();
    Ok(columns)
}

fn safe_site_label(value: &str) -> String {
    let value = value.trim();
    let authority = if let Some((scheme, rest)) = value.split_once("://") {
        if scheme.is_empty() {
            value
        } else {
            rest.split(['/', '?', '#']).next().unwrap_or(rest)
        }
    } else {
        value.split(['/', '?', '#']).next().unwrap_or(value)
    };
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or(authority)
        .trim()
        .trim_start_matches('.');
    let host = host.split(':').next().unwrap_or(host);
    let cleaned: String = host
        .chars()
        .filter(|ch| !ch.is_control())
        .take(253)
        .collect();
    if cleaned.is_empty() {
        "Unknown site".into()
    } else {
        cleaned
    }
}

const COOKIE_SETTINGS_SCHEMA: u32 = 1;
const COOKIE_EXCEPTION_LIMIT: usize = 256;
const COOKIE_SETTINGS_MAX_BYTES: u64 = 64 * 1024;

/// Load the validated, per-user keep-domain list. A missing file means an empty list.
pub fn load_cookie_exception_settings(data_dir: &Path) -> Result<CookieExceptionSettings, String> {
    let path = data_dir.join("privacy-cookie-settings.json");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CookieExceptionSettings::default());
        }
        Err(error) => return Err(format!("Cookie settings could not be inspected: {error}")),
    };
    if is_link(&metadata) || !metadata.is_file() || metadata.len() > COOKIE_SETTINGS_MAX_BYTES {
        return Err("Cookie settings are linked, invalid, or exceed the safe size limit.".into());
    }
    let bytes =
        fs::read(&path).map_err(|error| format!("Cookie settings could not be read: {error}"))?;
    let mut settings: CookieExceptionSettings = serde_json::from_slice(&bytes)
        .map_err(|_| "Cookie settings are invalid; they were left unchanged.".to_owned())?;
    if settings.schema != COOKIE_SETTINGS_SCHEMA
        || settings.keep_domains.len() > COOKIE_EXCEPTION_LIMIT
    {
        return Err("Cookie settings use an unsupported format; they were left unchanged.".into());
    }
    let mut domains = settings
        .keep_domains
        .iter()
        .map(|domain| normalize_cookie_domain(domain))
        .collect::<Result<Vec<_>, _>>()?;
    domains.sort_unstable();
    domains.dedup();
    settings.keep_domains = domains;
    Ok(settings)
}

/// Validate and persist cookie keep-domains, preserving the saved "Keep me
/// signed in" choice (on when the current file is missing or unreadable).
pub fn save_cookie_exception_settings(
    data_dir: &Path,
    domains: &[String],
) -> Result<CookieExceptionSettings, String> {
    let keep_signed_in = load_cookie_exception_settings(data_dir)
        .map(|settings| settings.keep_signed_in)
        .unwrap_or(true);
    save_cookie_policy(data_dir, domains, keep_signed_in)
}

/// Validate and persist the cookie policy. Domains accept DNS names, punycode
/// and IP literals, but not URL paths, ports, wildcards or credentials.
pub fn save_cookie_policy(
    data_dir: &Path,
    domains: &[String],
    keep_signed_in: bool,
) -> Result<CookieExceptionSettings, String> {
    if domains.len() > COOKIE_EXCEPTION_LIMIT {
        return Err(format!(
            "Keep at most {COOKIE_EXCEPTION_LIMIT} cookie domains."
        ));
    }
    let mut keep_domains = domains
        .iter()
        .map(|domain| normalize_cookie_domain(domain))
        .collect::<Result<Vec<_>, _>>()?;
    keep_domains.sort_unstable();
    keep_domains.dedup();
    let settings = CookieExceptionSettings {
        schema: COOKIE_SETTINGS_SCHEMA,
        keep_domains,
        keep_signed_in,
    };
    create_private_dir(data_dir)?;
    let path = data_dir.join("privacy-cookie-settings.json");
    if fs::symlink_metadata(&path).is_ok_and(|metadata| is_link(&metadata) || !metadata.is_file()) {
        return Err("Cookie settings path is linked or is not a regular file.".into());
    }
    let temporary = data_dir.join(format!(".privacy-cookie-settings-{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<(), String> {
        let bytes = serde_json::to_vec(&settings).map_err(|error| error.to_string())?;
        let mut file = private_file_options()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("Cookie settings could not be staged: {error}"))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("Cookie settings could not be synced: {error}"))?;
        drop(file);
        fs::rename(&temporary, &path)
            .map_err(|error| format!("Cookie settings could not be committed: {error}"))?;
        sync_directory(data_dir)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(settings)
}

/// Return a canonical lowercase domain or IP literal suitable for the keep list.
pub fn normalize_cookie_domain(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty()
        || trimmed.contains("*")
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains(':') && trimmed.parse::<std::net::IpAddr>().is_err()
        || trimmed.contains('@')
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return Err("Enter a domain or IP address only, without a URL, port, or wildcard.".into());
    }
    if let Ok(address) = trimmed.parse::<std::net::IpAddr>() {
        return Ok(address.to_string());
    }
    let normalized = trimmed
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 || !normalized.is_ascii() {
        return Err("Enter a valid ASCII domain or punycode name.".into());
    }
    for label in normalized.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.as_bytes()[0].is_ascii_alphanumeric()
            || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("Enter a valid domain name made of letters, digits, and hyphens.".into());
        }
    }
    Ok(normalized)
}

/// One account signs in across every domain of a group, so keeping any listed
/// domain keeps the whole group. The reference matches each keep pattern alone
/// (an exact `google.com` keeps neither `accounts.google.com` nor YouTube).
const SIGN_IN_GROUPS: &[&[&str]] = &[
    &[
        "google.com",
        "youtube.com",
        "gmail.com",
        "googleusercontent.com",
    ],
    &[
        "microsoft.com",
        "live.com",
        "microsoftonline.com",
        "office.com",
        "outlook.com",
        "bing.com",
        "msn.com",
        "xbox.com",
        "skype.com",
    ],
    &["facebook.com", "messenger.com", "fb.com"],
    &["apple.com", "icloud.com"],
    &["yahoo.com", "aol.com"],
    &["amazon.com", "primevideo.com", "audible.com"],
];

fn domain_matches(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

fn is_cookie_exception(site: &str, keep_domains: &HashSet<String>) -> bool {
    let Ok(host) = normalize_cookie_domain(site) else {
        return false;
    };
    keep_domains.iter().any(|domain| {
        domain_matches(&host, domain)
            || SIGN_IN_GROUPS
                .iter()
                .filter(|group| group.contains(&domain.as_str()))
                .any(|group| group.iter().any(|member| domain_matches(&host, member)))
    })
}

fn file_stamp(path: &Path) -> Result<FileStamp, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if is_link(&metadata) || !metadata.is_file() {
        return Err("Database is no longer a regular file.".into());
    }
    Ok(FileStamp {
        length: metadata.len(),
        modified_ns: metadata
            .modified()
            .map(timestamp)
            .map_err(|e| e.to_string())?,
        created_ns: metadata.created().ok().map(timestamp),
    })
}

fn validate_database_path(
    profile_root: &Path,
    database: &Path,
) -> Result<(PathBuf, FileStamp, PathBuf), String> {
    let root = safe_profile_root(profile_root)?;
    if !same_named_path(&root, profile_root) || !contains_named_path(&root, database) {
        return Err("Database is outside the profile.".into());
    }
    let metadata = fs::symlink_metadata(database).map_err(|e| e.to_string())?;
    if is_link(&metadata) || !metadata.is_file() {
        return Err("Database is linked or not a regular file.".into());
    }
    let canonical = dunce::canonicalize(database).map_err(|e| e.to_string())?;
    if !same_named_path(&canonical, database) || !contains_named_path(&root, &canonical) {
        return Err("Database resolves outside its profile.".into());
    }
    let stamp = file_stamp(&canonical)?;
    Ok((canonical, stamp, root))
}

fn safe_profile_root(path: &Path) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if is_link(&metadata) || !metadata.is_dir() {
        return Err("The profile root is linked or not a directory.".into());
    }
    let canonical = dunce::canonicalize(path).map_err(|e| e.to_string())?;
    if !same_named_path(&canonical, path) {
        return Err("A profile parent redirects through a link.".into());
    }
    Ok(canonical)
}

/// Build a deletion plan only from exact record IDs in the current inventory.
pub fn build_cleanup_plan(
    report: &PrivacyReport,
    selected_ids: &[Uuid],
) -> Result<PrivacyPlan, String> {
    if report.cancelled {
        return Err("Complete a browser privacy scan before reviewing cleanup.".into());
    }
    if selected_ids.is_empty() {
        return Err("Select browser records from the current scan.".into());
    }
    let by_id: HashMap<Uuid, &PrivacyRecord> = report
        .records
        .iter()
        .map(|record| (record.id, record))
        .collect();
    let mut seen = HashSet::new();
    let mut records = Vec::new();
    let mut files = Vec::new();
    let mut keys = Vec::new();
    let mut preferences = Vec::new();
    for id in selected_ids {
        let Some(record) = by_id.get(id) else {
            return Err("Unknown record ID. Scan again before cleanup.".into());
        };
        if let Some(reason) = record.unavailable_reason() {
            return Err(reason.into());
        }
        if seen.insert(*id) {
            match &record.locator {
                RecordLocator::Database(row) => records.push(row.clone()),
                RecordLocator::File(file) => files.push(file.clone()),
                RecordLocator::LevelDb(key) => {
                    if key.id != record.id {
                        return Err("Local Storage review identity changed.".into());
                    }
                    keys.push(key.clone());
                }
                RecordLocator::Preferences(field) => {
                    if field.id != record.id {
                        return Err("Browser preference review identity changed.".into());
                    }
                    preferences.push(field.clone());
                }
            }
        }
    }
    let mut paths = HashSet::new();
    ensure_sql_owners(&records)?;
    for group in &files {
        if !group.unique_paths(&mut paths) {
            return Err("Selected storage groups overlap. Scan again before cleanup.".into());
        }
    }
    let structured_paths = preferences
        .iter()
        .map(preferences::Review::source_key)
        .collect::<HashSet<_>>();
    if structured_paths.into_iter().any(|key| !paths.insert(key)) {
        return Err("Selected browser data owners overlap. Scan again before cleanup.".into());
    }
    Ok(PrivacyPlan {
        report_id: report.id,
        operation_id: Uuid::new_v4(),
        records,
        files,
        keys,
        preferences,
    })
}

/// Supplies a native process snapshot. The normal production entry point always uses the OS API.
/// This trait also makes the transaction path testable against isolated fixture databases.
pub trait BrowserRuntime {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String>;
}

struct NativeBrowserRuntime;
impl BrowserRuntime for NativeBrowserRuntime {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        running_browsers()
    }
}

/// Back up, journal, revalidate and transactionally remove selected records.
/// Production callers should use this native-guarded function.
pub fn clean_privacy(
    data_dir: &Path,
    plan: &PrivacyPlan,
    cancel: &AtomicBool,
    mut progress: impl FnMut(usize, usize),
) -> Result<PrivacyReceipt, String> {
    clean_privacy_with_runtime(data_dir, plan, cancel, &NativeBrowserRuntime, &mut progress)
}

/// Runtime-injected form used by fixture tests and platform adapters.
pub fn clean_privacy_with_runtime(
    data_dir: &Path,
    plan: &PrivacyPlan,
    cancel: &AtomicBool,
    runtime: &impl BrowserRuntime,
    progress: &mut impl FnMut(usize, usize),
) -> Result<PrivacyReceipt, String> {
    clean_privacy_with_runtime_and_trash(
        data_dir,
        plan,
        cancel,
        runtime,
        &mut crate::cleanup::SystemTrash,
        progress,
    )
}

/// Supplies the recoverable file-effect port as well as the browser runtime.
/// Production uses SystemTrash; fixture ports operate only on owned test files.
pub fn clean_privacy_with_runtime_and_trash(
    data_dir: &Path,
    plan: &PrivacyPlan,
    cancel: &AtomicBool,
    runtime: &impl BrowserRuntime,
    trash: &mut impl crate::cleanup::TrashPort,
    progress: &mut impl FnMut(usize, usize),
) -> Result<PrivacyReceipt, String> {
    if plan.records.is_empty()
        && plan.files.is_empty()
        && plan.keys.is_empty()
        && plan.preferences.is_empty()
    {
        return Err("Select browser records from the current scan.".into());
    }
    ensure_database_access_allowed(runtime, &plan.records)?;
    storage_files::preflight(runtime, &plan.files)?;
    leveldb_write::preflight(runtime, &plan.keys)?;
    preferences::preflight(runtime, &plan.preferences)?;
    for database in plan
        .records
        .iter()
        .map(|r| &r.database)
        .collect::<HashSet<_>>()
    {
        generic_sqlite::pending(data_dir, database)?;
    }

    let mut journal = PrivacyJournal::create(data_dir, plan.operation_id)?;
    journal.append(&PrivacyJournalEvent::Start {
        operation_id: plan.operation_id,
        report_id: plan.report_id,
        date: chrono::Local::now().to_rfc3339(),
    })?;
    let mut receipt = PrivacyReceipt {
        id: plan.operation_id,
        selected: plan.records.len() + plan.files.len() + plan.keys.len() + plan.preferences.len(),
        ..PrivacyReceipt::default()
    };
    let mut grouped: std::collections::BTreeMap<PathBuf, Vec<RowLocator>> =
        std::collections::BTreeMap::new();
    for record in &plan.records {
        grouped
            .entry(record.database.clone())
            .or_default()
            .push(record.clone());
    }
    let total = grouped.values().map(Vec::len).sum::<usize>()
        + plan.files.len()
        + plan.keys.len()
        + plan.preferences.len();
    let mut done = 0;

    for (database, mut records) in grouped {
        // Independent legacy rows precede parent download groups when both
        // were reviewed, so declared legacy references need no inferred cascade.
        records.sort_by_key(|record| {
            record
                .download
                .as_ref()
                .map_or(0, |review| review.priority())
        });
        if cancel.load(Ordering::Relaxed) {
            receipt.cancelled = true;
            break;
        }
        let browser = records[0].browser;
        if records.iter().any(|record| {
            record.browser != browser
                || record.database_stamp != records[0].database_stamp
                || !same_path(&record.profile_root, &records[0].profile_root)
        }) {
            receipt.errors.push(
                "Selected records came from inconsistent profile snapshots. Scan again.".into(),
            );
            receipt.skipped = receipt.skipped.saturating_add(records.len());
            done += records.len();
            progress(done, total);
            continue;
        }
        if let Err(error) = ensure_database_access_allowed(runtime, &records) {
            receipt.errors.push(error);
            receipt.skipped = receipt.skipped.saturating_add(records.len());
            done += records.len();
            progress(done, total);
            continue;
        }
        let (canonical, current_stamp, _) =
            match validate_database_path(&records[0].profile_root, &database) {
                Ok(validated) => validated,
                Err(_) => {
                    receipt
                        .errors
                        .push("A selected browser database is unavailable or redirected.".into());
                    receipt.skipped = receipt.skipped.saturating_add(records.len());
                    done += records.len();
                    progress(done, total);
                    continue;
                }
            };
        if current_stamp != records[0].database_stamp {
            receipt.errors.push(
                "A browser database changed since the scan. Review a new scan before cleaning."
                    .into(),
            );
            receipt.skipped = receipt.skipped.saturating_add(records.len());
            done += records.len();
            progress(done, total);
            continue;
        }
        if current_stamp.length > MAX_DATABASE_BYTES {
            receipt
                .errors
                .push("A selected database exceeds the safe recovery size limit.".into());
            receipt.skipped = receipt.skipped.saturating_add(records.len());
            done += records.len();
            progress(done, total);
            continue;
        }

        let source_lease = if records.iter().any(|record| record.generic.is_some()) {
            match generic_sqlite::SourceLease::acquire(&records[0].profile_root, &canonical) {
                Ok(lease) => Some(lease),
                Err(error) => {
                    receipt.errors.push(error);
                    receipt.skipped = receipt.skipped.saturating_add(records.len());
                    done += records.len();
                    progress(done, total);
                    continue;
                }
            }
        } else {
            None
        };
        let backup =
            match make_database_backup(data_dir, plan.operation_id, &records[0], &canonical) {
                Ok(path) => path,
                Err(error) => {
                    receipt
                        .errors
                        .push(format!("Could not make a verified recovery copy: {error}"));
                    receipt.skipped = receipt.skipped.saturating_add(records.len());
                    done += records.len();
                    progress(done, total);
                    continue;
                }
            };
        receipt.backups.push(backup.clone());
        if !file_stamp(&canonical).is_ok_and(|stamp| stamp == records[0].database_stamp) {
            receipt
                .errors
                .push("A browser database changed while its recovery copy was made.".into());
            let _ = fs::remove_file(&backup);
            receipt.backups.pop();
            receipt.skipped = receipt.skipped.saturating_add(records.len());
            done += records.len();
            progress(done, total);
            continue;
        }
        if let Err(error) = ensure_database_access_allowed(runtime, &records) {
            receipt.errors.push(error);
            let _ = fs::remove_file(&backup);
            receipt.backups.pop();
            receipt.skipped = receipt.skipped.saturating_add(records.len());
            done += records.len();
            progress(done, total);
            continue;
        }

        let record_ids = records.iter().map(|record| record.id).collect::<Vec<_>>();
        journal.append(&PrivacyJournalEvent::Intent {
            database: canonical.clone(),
            backup: backup.clone(),
            record_ids: record_ids.clone(),
        })?;
        let mut database_deleted = Vec::new();
        let mut database_skipped = Vec::new();
        let mut database_cancelled = false;
        let tx_outcome = (|| -> Result<(), String> {
            let mut conn = Connection::open_with_flags(
                &canonical,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|_| "Browser database could not be opened for a transaction.".to_owned())?;
            conn.busy_timeout(Duration::from_secs(2))
                .map_err(|e| e.to_string())?;
            conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
                .map_err(|e| format!("Could not configure durable browser database writes: {e}"))?;
            if !file_stamp(&canonical).is_ok_and(|stamp| stamp == records[0].database_stamp) {
                return Err("A browser database changed before its cleanup transaction.".into());
            }
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| format!("Browser database is busy: {e}"))?;
            ensure_database_access_allowed(runtime, &records)?;
            verify_foreign_keys(&tx)?;
            if let Some(lease) = &source_lease {
                lease.check(&records[0].profile_root, &canonical)?;
                generic_sqlite::validate_selected(&tx, &records, lease, cancel)?;
            }
            let mut cookie_snapshots = HashMap::new();
            let quota = if let Some(review) = records.iter().find_map(|r| r.quota.as_ref()) {
                if records
                    .iter()
                    .filter_map(|r| r.quota.as_ref())
                    .any(|r| r.keep_domains() != review.keep_domains())
                {
                    return Err("Quota keep policy differs between reviewed groups.".into());
                }
                let observed = quota::Snapshot::read(&tx, review.keep_domains(), cancel);
                if cancel.load(Ordering::Relaxed) {
                    database_cancelled = true;
                    database_skipped.extend(records.iter().map(|r| r.id));
                    tx.rollback()
                        .map_err(|_| "Cancelled quota cleanup could not roll back.".to_owned())?;
                    return Ok(());
                }
                Some(observed?)
            } else {
                None
            };
            let shortcut_snapshot = if records.iter().any(|record| record.shortcut.is_some()) {
                let observed = shortcuts::Snapshot::read(&tx, &records[0].profile_root, cancel);
                if cancel.load(Ordering::Relaxed) {
                    database_cancelled = true;
                    database_skipped.extend(records.iter().map(|record| record.id));
                    tx.rollback().map_err(|_| {
                        "Cancelled shortcut cleanup could not roll back.".to_owned()
                    })?;
                    return Ok(());
                }
                Some(observed?)
            } else {
                None
            };
            let mut shared_shortcut_checks = HashMap::new();
            let keyword_snapshot = if records.iter().any(|record| record.keyword.is_some()) {
                let observed = keywords::Snapshot::read(&tx, cancel);
                if cancel.load(Ordering::Relaxed) {
                    database_cancelled = true;
                    database_skipped.extend(records.iter().map(|record| record.id));
                    tx.rollback()
                        .map_err(|_| "Cancelled keyword cleanup could not roll back.".to_owned())?;
                    return Ok(());
                }
                Some(observed?)
            } else {
                None
            };
            for kind in records
                .iter()
                .filter(|record| record.cookie.is_some())
                .map(|record| record.kind)
                .collect::<HashSet<_>>()
            {
                let observed = cookies::Snapshot::read(&tx, kind, cancel);
                if cancel.load(Ordering::Relaxed) {
                    database_cancelled = true;
                    database_skipped.extend(records.iter().map(|record| record.id));
                    tx.rollback()
                        .map_err(|_| "Cancelled cookie cleanup could not roll back.".to_owned())?;
                    return Ok(());
                }
                cookie_snapshots.insert(kind, observed?);
            }
            let history = if records.iter().any(|record| record.history.is_some()) {
                TableKind::ChromiumHistory.verify_delete_schema(&tx)?;
                let observed =
                    chromium_history::Snapshot::read(&tx, &records[0].profile_root, cancel);
                if cancel.load(Ordering::Relaxed) {
                    database_cancelled = true;
                    database_skipped.extend(records.iter().map(|record| record.id));
                    tx.rollback()
                        .map_err(|_| "Cancelled history cleanup could not roll back.".to_owned())?;
                    return Ok(());
                }
                Some(observed?)
            } else {
                None
            };
            // All dependency observations are checked against the same initial
            // transaction snapshot, before our own referring-visit repairs.
            let downloads = if records.iter().any(|record| record.download.is_some()) {
                let observed = chromium_downloads::Snapshot::read(&tx, cancel);
                if cancel.load(Ordering::Relaxed) {
                    database_cancelled = true;
                    database_skipped.extend(records.iter().map(|record| record.id));
                    tx.rollback().map_err(|_| {
                        "Cancelled download cleanup could not roll back.".to_owned()
                    })?;
                    return Ok(());
                }
                Some(observed?)
            } else {
                None
            };
            let firefox = if records.iter().any(|record| record.firefox.is_some()) {
                let observed = firefox_places::Snapshot::read(&tx, cancel);
                if cancel.load(Ordering::Relaxed) {
                    database_cancelled = true;
                    database_skipped.extend(records.iter().map(|record| record.id));
                    tx.rollback()
                        .map_err(|_| "Cancelled Firefox cleanup could not roll back.".to_owned())?;
                    return Ok(());
                }
                Some(observed?)
            } else {
                None
            };
            let mut shared_firefox_checks = HashMap::new();
            let valid_firefox = records
                .iter()
                .filter_map(|record| {
                    record
                        .firefox
                        .as_ref()
                        .filter(|review| {
                            firefox.as_ref().is_some_and(|current| {
                                review.matches(current, &mut shared_firefox_checks)
                            })
                        })
                        .map(|_| record.id)
                })
                .collect::<HashSet<_>>();
            if let Some(current) = &firefox {
                let repaired = current.repair_visits(
                    &tx,
                    records
                        .iter()
                        .filter(|record| valid_firefox.contains(&record.id))
                        .filter_map(|record| record.firefox.as_ref()),
                    cancel,
                );
                if cancel.load(Ordering::Relaxed) {
                    database_cancelled = true;
                    database_skipped.extend(records.iter().map(|record| record.id));
                    tx.rollback().map_err(|_| {
                        "Cancelled Firefox reference repair could not roll back.".to_owned()
                    })?;
                    return Ok(());
                }
                repaired?;
            }
            let mut shared_download_checks = HashMap::new();
            let valid_downloads = records
                .iter()
                .filter_map(|record| {
                    record
                        .download
                        .as_ref()
                        .filter(|review| {
                            downloads.as_ref().is_some_and(|current| {
                                review.matches(current, &mut shared_download_checks)
                            })
                        })
                        .map(|_| record.id)
                })
                .collect::<HashSet<_>>();
            let mut shared_history_checks = HashMap::new();
            let valid_history = records
                .iter()
                .filter_map(|record| {
                    record
                        .history
                        .as_ref()
                        .filter(|review| {
                            history.as_ref().is_some_and(|current| {
                                review.matches(current, &mut shared_history_checks)
                            })
                        })
                        .map(|_| record.id)
                })
                .collect::<HashSet<_>>();
            if let Some(history) = &history {
                let repaired = history.repair_visits(
                    &tx,
                    records
                        .iter()
                        .filter(|record| valid_history.contains(&record.id))
                        .filter_map(|record| record.history.as_ref()),
                    cancel,
                );
                if cancel.load(Ordering::Relaxed) {
                    database_cancelled = true;
                    database_skipped.extend(records.iter().map(|record| record.id));
                    tx.rollback()
                        .map_err(|_| "Cancelled history cleanup could not roll back.".to_owned())?;
                    return Ok(());
                }
                repaired?;
            }
            for record in &records {
                if record.generic.is_some() {
                    continue;
                }
                if cancel.load(Ordering::Relaxed) {
                    database_cancelled = true;
                    break;
                }
                if let Some(review) = &record.shortcut {
                    if !shortcut_snapshot
                        .as_ref()
                        .is_some_and(|current| review.matches(current, &mut shared_shortcut_checks))
                    {
                        database_skipped.push(record.id);
                        continue;
                    }
                    if review.delete(&tx)? != 1 {
                        return Err("A reviewed shortcut changed during cleanup.".into());
                    }
                    database_deleted.push(record.id);
                    continue;
                }
                if let Some(review) = &record.keyword {
                    if !keyword_snapshot
                        .as_ref()
                        .is_some_and(|current| review.matches(current))
                    {
                        database_skipped.push(record.id);
                        continue;
                    }
                    if review.delete(&tx)? != 1 {
                        return Err("A reviewed keyword changed during cleanup.".into());
                    }
                    database_deleted.push(record.id);
                    continue;
                }
                if let Some(review) = &record.quota {
                    if !quota
                        .as_ref()
                        .is_some_and(|current| review.matches(current))
                    {
                        database_skipped.push(record.id);
                        continue;
                    }
                    let removed = review.delete(&tx, cancel);
                    if cancel.load(Ordering::Relaxed) {
                        database_cancelled = true;
                        break;
                    }
                    if removed? != 1 {
                        return Err("A reviewed quota group changed during cleanup.".into());
                    }
                    database_deleted.push(record.id);
                    continue;
                }
                if let Some(review) = &record.cookie {
                    if !cookie_snapshots
                        .get(&record.kind)
                        .is_some_and(|observed| review.matches(observed))
                    {
                        database_skipped.push(record.id);
                        continue;
                    }
                    if review.delete(&tx)? != 1 {
                        return Err("A reviewed cookie changed during cleanup.".into());
                    }
                    database_deleted.push(record.id);
                    continue;
                }
                if let Some(review) = &record.firefox {
                    if !valid_firefox.contains(&record.id) {
                        database_skipped.push(record.id);
                        continue;
                    }
                    let removed = review.delete(&tx, cancel);
                    if cancel.load(Ordering::Relaxed) {
                        database_cancelled = true;
                        break;
                    }
                    if removed? != 1 {
                        return Err("A reviewed Firefox target changed during cleanup.".into());
                    }
                    database_deleted.push(record.id);
                    continue;
                }
                if let Some(review) = &record.download {
                    if !valid_downloads.contains(&record.id) {
                        database_skipped.push(record.id);
                        continue;
                    }
                    if review.delete(&tx).map_err(|_| {
                        "A selected download target could not be removed transactionally."
                            .to_owned()
                    })? != 1
                    {
                        return Err("A selected download target changed during cleanup.".into());
                    }
                    database_deleted.push(record.id);
                    continue;
                }
                record.kind.verify_delete_schema(&tx)?;
                if let Some(review) = &record.history {
                    if !valid_history.contains(&record.id) {
                        database_skipped.push(record.id);
                        continue;
                    }
                    if review.delete(&tx).map_err(|_| {
                        "A selected history target could not be removed transactionally.".to_owned()
                    })? != 1
                    {
                        return Err("A selected history target changed during cleanup.".into());
                    }
                    database_deleted.push(record.id);
                    continue;
                }
                let current = tx
                    .query_row(record.kind.identity_sql(), [record.row_id], |row| {
                        record.kind.row_identity(row)
                    })
                    .optional()
                    .map_err(|_| {
                        "A selected browser record could not be revalidated.".to_owned()
                    })?;
                if current.as_deref() != Some(record.identity.as_slice()) {
                    database_skipped.push(record.id);
                    continue;
                }
                let changed = record.kind.delete(&tx, record.row_id).map_err(|_| {
                    "A selected browser record could not be removed transactionally.".to_owned()
                })?;
                if changed != 1 {
                    return Err("A selected browser record changed during its transaction.".into());
                }
                database_deleted.push(record.id);
            }
            verify_foreign_keys(&tx)?;
            if let Some(current) = &shortcut_snapshot {
                current.bookmarks_unchanged(&records[0].profile_root)?;
            }
            if let Some(history) = &history {
                history.bookmarks_unchanged(&records[0].profile_root)?;
            }
            if records.iter().any(|record| record.generic.is_some()) && !database_cancelled {
                match generic_sqlite::delete_selected(&tx, &records, cancel) {
                    Ok(ids) => database_deleted.extend(ids),
                    Err(error) => {
                        let was_cancelled = cancel.load(Ordering::Relaxed);
                        tx.rollback().map_err(|_| {
                            "Browser table rollback failed; its final state may be uncertain."
                                .to_owned()
                        })?;
                        database_deleted.clear();
                        database_skipped = records.iter().map(|r| r.id).collect();
                        if was_cancelled {
                            database_cancelled = true;
                            return Ok(());
                        }
                        return Err(error);
                    }
                }
                if let Err(error) = verify_foreign_keys(&tx) {
                    tx.rollback().map_err(|_| {
                        "Browser table rollback failed; its final state may be uncertain."
                            .to_owned()
                    })?;
                    return Err(error);
                }
            }
            if database_cancelled {
                tx.rollback()
                    .map_err(|e| format!("Cancelled cleanup could not be rolled back; its final state may be uncertain: {e}"))?;
                database_deleted.clear();
                database_skipped.extend(records.iter().map(|record| record.id));
                return Ok(());
            }
            tx.commit().map_err(|e| {
                format!("Browser database commit failed; its final state may be uncertain: {e}")
            })?;
            Ok(())
        })();

        let commit_uncertain = tx_outcome
            .as_ref()
            .is_err_and(|error| error.contains("may be uncertain"));
        if tx_outcome.is_err() {
            database_deleted.clear();
            if !commit_uncertain {
                database_skipped = records.iter().map(|record| record.id).collect();
            }
        }
        let mut restore_id = None;
        let mut post_state_snapshot = None;
        let mut post_state_stamp = None;
        let mut schema_signature = None;
        let mut restore_error = None;
        let categories = records
            .iter()
            .map(|record| record.kind.category())
            .collect::<HashSet<_>>();
        let mut categories = categories.into_iter().collect::<Vec<_>>();
        categories.sort_by_key(|category| match category {
            PrivacyCategory::History => 0,
            PrivacyCategory::Cookies => 1,
            PrivacyCategory::Downloads => 2,
            PrivacyCategory::LastDownloadLocation => 3,
            PrivacyCategory::SnapLocation => 4,
            PrivacyCategory::Sessions => 5,
            PrivacyCategory::SavedForms => 6,
            PrivacyCategory::SavedPasswords => 7,
            PrivacyCategory::SitePreferences => 8,
        });
        if tx_outcome.is_ok() && !database_cancelled && !database_deleted.is_empty() {
            let id = Uuid::new_v4();
            restore_id = Some(id);
            let snapshot_result = ensure_database_access_allowed(runtime, &records)
                .and_then(|_| make_post_state_snapshot(&canonical, &backup, id));
            match snapshot_result {
                Ok((path, stamp, signature)) => {
                    post_state_snapshot = Some(path);
                    post_state_stamp = Some(stamp);
                    schema_signature = Some(signature);
                }
                Err(error) => {
                    receipt.errors.push(format!(
                        "Cleanup committed, but a verified post-cleanup state copy could not be made; reviewed restore is unavailable for this database: {error}"
                    ));
                    restore_error = Some(error);
                }
            }
        }
        let outcome_event = PrivacyJournalEvent::Outcome {
            database: canonical.clone(),
            backup: backup.clone(),
            deleted_ids: database_deleted.clone(),
            skipped_ids: database_skipped.clone(),
            committed: tx_outcome.is_ok() && !database_cancelled,
            cancelled: database_cancelled,
            uncertain: commit_uncertain,
            restore_id,
            browser: Some(records[0].browser),
            profile_name: Some(records[0].profile_name.clone()),
            profile_root: Some(records[0].profile_root.clone()),
            categories,
            post_state_snapshot,
            post_state_stamp,
            schema_signature,
            restore_error,
        };
        if let Err(error) = &tx_outcome {
            receipt.errors.push(error.clone());
        }
        if journal.append(&outcome_event).is_err() {
            receipt.uncertain = true;
            receipt.errors.push("The database outcome could not be synced to the privacy journal; review recovery status before retrying.".into());
        }
        if commit_uncertain {
            receipt.uncertain = true;
        }
        if tx_outcome.is_ok() {
            receipt.deleted = receipt.deleted.saturating_add(database_deleted.len());
        }
        receipt.skipped = receipt.skipped.saturating_add(database_skipped.len());
        receipt.cancelled |= database_cancelled;
        done += records.len();
        progress(done, total);
        if database_cancelled {
            break;
        }
    }
    if !receipt.cancelled && !plan.files.is_empty() {
        let group_ends = plan
            .files
            .iter()
            .scan(0usize, |total, group| {
                *total += group.item_count();
                Some(*total)
            })
            .collect::<Vec<_>>();
        match storage_files::clean(
            data_dir,
            plan.report_id,
            &plan.files,
            runtime,
            trash,
            cancel,
            |completed, _| {
                progress(
                    done + group_ends.partition_point(|end| *end <= completed),
                    total,
                )
            },
        ) {
            Ok(files) => {
                let confirmed: HashSet<_> = files.cleaned_ids.iter().copied().collect();
                let completed = plan
                    .files
                    .iter()
                    .filter(|group| group.all_cleaned(&confirmed))
                    .count();
                receipt.deleted = receipt.deleted.saturating_add(completed);
                receipt.skipped = receipt
                    .skipped
                    .saturating_add(plan.files.len().saturating_sub(completed));
                if plan
                    .files
                    .iter()
                    .any(|group| group.partly_cleaned(&confirmed))
                {
                    receipt.errors.push("Only part of a reviewed storage group moved to Trash; review cleanup history before further action.".into());
                }
                receipt.cancelled |= files.cancelled;
                receipt.uncertain |= files.interrupted || !files.uncertain.is_empty();
                let mut seen_errors: HashSet<_> = receipt.errors.iter().cloned().collect();
                let remaining = MAX_SKIP_DETAILS.saturating_sub(receipt.errors.len());
                receipt.errors.extend(
                    files
                        .failed
                        .into_iter()
                        .filter_map(|file| file.reason)
                        .filter(|error| seen_errors.insert(error.clone()))
                        .take(remaining),
                );
            }
            Err(error) => {
                receipt.uncertain = true;
                receipt.errors.push(format!(
                    "Storage-file cleanup stopped: {error}. Review cleanup history before retrying."
                ));
            }
        }
    }
    if !plan.keys.is_empty() {
        match leveldb_write::clean(data_dir, plan.operation_id, &plan.keys, cancel, runtime) {
            Ok(keys) => {
                receipt.deleted += keys.deleted;
                receipt.skipped += keys.skipped;
                receipt.cancelled |= keys.cancelled;
                receipt.uncertain |= keys.uncertain;
                receipt.backups.extend(keys.backups);
                receipt.errors.extend(keys.errors);
            }
            Err(error) => {
                receipt.skipped += plan.keys.len();
                receipt.errors.push(error);
            }
        }
        progress(total, total);
    }
    if !plan.preferences.is_empty() && !receipt.cancelled {
        match preferences::clean(
            data_dir,
            plan.operation_id,
            &plan.preferences,
            cancel,
            runtime,
        ) {
            Ok(fields) => {
                receipt.deleted += fields.deleted;
                receipt.skipped += fields.skipped;
                receipt.cancelled |= fields.cancelled;
                receipt.uncertain |= fields.uncertain;
                receipt.backups.extend(fields.backups);
                receipt.errors.extend(fields.errors);
            }
            Err(error) => {
                receipt.skipped += plan.preferences.len();
                receipt.errors.push(error);
            }
        }
        progress(total, total);
    }
    if journal
        .append(&PrivacyJournalEvent::Finish {
            cancelled: receipt.cancelled,
        })
        .is_err()
    {
        receipt.uncertain = true;
        receipt.errors.push("The privacy operation finish state could not be synced; review recovery status before retrying.".into());
    }
    Ok(receipt)
}

fn verify_foreign_keys(conn: &Connection) -> Result<(), String> {
    let mut statement = conn
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| "Browser database constraints could not be checked.".to_owned())?;
    let mut rows = statement
        .query([])
        .map_err(|_| "Browser database constraints could not be checked.".to_owned())?;
    match rows.next() {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err("Browser database has a foreign-key inconsistency.".into()),
        Err(_) => Err("Browser database constraints could not be checked.".into()),
    }
}

fn file_owned_category(
    browser: Browser,
    category: PrivacyCategory,
    root: &Path,
    path: &Path,
) -> bool {
    (category == PrivacyCategory::Cookies && storage_files::owns_file(browser, root, path))
        || (category == PrivacyCategory::Sessions
            && (session_files::claims(browser, root, path)
                || session_files::generic_binding(browser, root, path).is_some()))
        || record_files::claims(browser, category, root, path)
        || (matches!(
            category,
            PrivacyCategory::History
                | PrivacyCategory::LastDownloadLocation
                | PrivacyCategory::SnapLocation
        ) && preferences::owns(browser, root, path))
}

fn ensure_sql_owners(records: &[RowLocator]) -> Result<(), String> {
    let mut seen = HashSet::new();
    if records.iter().any(|record| {
        seen.insert((
            record.browser,
            record.kind.category(),
            &record.profile_root,
            &record.database,
        )) && file_owned_category(
            record.browser,
            record.kind.category(),
            &record.profile_root,
            &record.database,
        )
    }) {
        return Err(
            "These browser records now belong to a file-cleanup rule. Scan again before cleanup."
                .into(),
        );
    }
    Ok(())
}

fn ensure_database_access_allowed(
    runtime: &impl BrowserRuntime,
    records: &[RowLocator],
) -> Result<(), String> {
    ensure_sql_owners(records)?;
    let running = runtime.running_browsers()?;
    let required = records
        .iter()
        .map(|record| record.browser)
        .collect::<HashSet<_>>();
    let conflicts = running
        .iter()
        .filter(|process| {
            required
                .iter()
                .any(|browser| browser.conflicts_with(process))
        })
        .map(|process| process.browser.label())
        .collect::<HashSet<_>>();
    if conflicts.is_empty() {
        Ok(())
    } else {
        let mut names = conflicts.into_iter().collect::<Vec<_>>();
        names.sort_unstable();
        Err(format!(
            "Close the selected browser{} before cleaning: {}.",
            if names.len() == 1 { "" } else { "s" },
            names.join(", ")
        ))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PrivacyJournalEvent {
    Start {
        operation_id: Uuid,
        report_id: Uuid,
        date: String,
    },
    Intent {
        database: PathBuf,
        backup: PathBuf,
        record_ids: Vec<Uuid>,
    },
    Outcome {
        database: PathBuf,
        backup: PathBuf,
        deleted_ids: Vec<Uuid>,
        skipped_ids: Vec<Uuid>,
        committed: bool,
        cancelled: bool,
        uncertain: bool,
        #[serde(default)]
        restore_id: Option<Uuid>,
        #[serde(default)]
        browser: Option<Browser>,
        #[serde(default)]
        profile_name: Option<String>,
        #[serde(default)]
        profile_root: Option<PathBuf>,
        #[serde(default)]
        categories: Vec<PrivacyCategory>,
        #[serde(default)]
        post_state_snapshot: Option<PathBuf>,
        #[serde(default)]
        post_state_stamp: Option<FileStamp>,
        #[serde(default)]
        schema_signature: Option<String>,
        #[serde(default)]
        restore_error: Option<String>,
    },
    RestoreIntent {
        restore_id: Uuid,
        source_operation_id: Uuid,
        database: PathBuf,
        source_backup: PathBuf,
        current_state_backup: PathBuf,
        post_state_snapshot: PathBuf,
        expected_stamp: FileStamp,
        schema_signature: String,
    },
    RestoreOutcome {
        restore_id: Uuid,
        database: PathBuf,
        current_state_backup: PathBuf,
        restored: bool,
        uncertain: bool,
        error: Option<String>,
    },
    Finish {
        cancelled: bool,
    },
}

struct PrivacyJournal {
    file: File,
}
impl PrivacyJournal {
    fn create(data_dir: &Path, id: Uuid) -> Result<Self, String> {
        let directory = data_dir.join("privacy-operations");
        create_private_dir(&directory)?;
        let file_path = directory.join(format!("{id}.jsonl"));
        let file = private_file_options()
            .create_new(true)
            .write(true)
            .open(file_path)
            .map_err(|e| format!("Could not create privacy journal: {e}"))?;
        sync_directory(&directory)?;
        Ok(Self { file })
    }
    fn append(&mut self, event: &PrivacyJournalEvent) -> Result<(), String> {
        let mut bytes = serde_json::to_vec(event).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        self.file
            .write_all(&bytes)
            .and_then(|_| self.file.sync_all())
            .map_err(|e| format!("Could not sync privacy journal: {e}"))
    }
}

/// Read unresolved/uncertain database intents after restart. No automatic restore or retry occurs.
pub fn recover_privacy_operations(data_dir: &Path) -> Result<Vec<PrivacyRecoveryItem>, String> {
    let mut result = recover_sqlite_operations(data_dir)?;
    result.extend(leveldb_write::recovery(data_dir)?);
    result.extend(preferences::recovery(data_dir)?);
    Ok(result)
}

fn recover_sqlite_operations(data_dir: &Path) -> Result<Vec<PrivacyRecoveryItem>, String> {
    let directory = data_dir.join("privacy-operations");
    match directory.try_exists() {
        Ok(false) => return Ok(Vec::new()),
        Ok(true) => {}
        Err(_) => return Err("Privacy recovery directory could not be checked.".into()),
    }
    let entries = fs::read_dir(&directory).map_err(|e| e.to_string())?;
    let mut recovery = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path
            .extension()
            .is_none_or(|extension| extension != "jsonl")
        {
            continue;
        }
        let operation_id = path
            .file_stem()
            .and_then(|stem| Uuid::parse_str(&stem.to_string_lossy()).ok())
            .ok_or_else(|| "Privacy journal has an invalid operation identifier.".to_owned())?;
        let file = File::open(&path).map_err(|e| e.to_string())?;
        let mut intents: HashMap<(PathBuf, PathBuf), Vec<Uuid>> = HashMap::new();
        let mut uncertain = HashSet::<(PathBuf, PathBuf)>::new();
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|e| e.to_string())?;
            let event: PrivacyJournalEvent = serde_json::from_str(&line).map_err(|error| {
                format!("A privacy journal is damaged and was preserved for recovery: {error}")
            })?;
            match event {
                PrivacyJournalEvent::Intent {
                    database,
                    backup,
                    record_ids,
                } => {
                    intents.insert((database, backup), record_ids);
                }
                PrivacyJournalEvent::Outcome {
                    database,
                    backup,
                    uncertain: outcome_uncertain,
                    ..
                } => {
                    let key = (database, backup);
                    if outcome_uncertain {
                        uncertain.insert(key.clone());
                    } else {
                        intents.remove(&key);
                    }
                }
                PrivacyJournalEvent::Start { .. }
                | PrivacyJournalEvent::RestoreIntent { .. }
                | PrivacyJournalEvent::RestoreOutcome { .. }
                | PrivacyJournalEvent::Finish { .. } => {}
            }
        }
        for ((database, backup), unresolved_ids) in intents {
            recovery.push(PrivacyRecoveryItem {
                operation_id,
                database: database.clone(),
                backup: backup.clone(),
                unresolved_ids,
                uncertain: uncertain.contains(&(database, backup)),
            });
        }
    }
    recovery.sort_by(|left, right| {
        left.operation_id
            .cmp(&right.operation_id)
            .then_with(|| left.database.cmp(&right.database))
    });
    Ok(recovery)
}

#[derive(Clone)]
struct RestoreSource {
    option: PrivacyRestoreOption,
    source_operation_id: Uuid,
    profile_root: Option<PathBuf>,
    database: PathBuf,
    backup: PathBuf,
    post_state_snapshot: Option<PathBuf>,
    post_state_stamp: Option<FileStamp>,
    schema_signature: Option<String>,
}

/// List durable cleanup backups and show whether each one is available for review.
/// A `Ready` item still needs a fresh preflight before any restore can run.
pub fn list_privacy_restore_options(data_dir: &Path) -> Result<Vec<PrivacyRestoreOption>, String> {
    let mut options = load_restore_sources(data_dir)?
        .into_iter()
        .map(|source| source.option)
        .collect::<Vec<_>>();
    options.extend(leveldb_write::options(data_dir)?);
    options.extend(preferences::options(data_dir)?);
    Ok(options)
}

fn load_restore_sources(data_dir: &Path) -> Result<Vec<RestoreSource>, String> {
    let directory = data_dir.join("privacy-operations");
    match directory.try_exists() {
        Ok(false) => return Ok(Vec::new()),
        Ok(true) => {}
        Err(_) => return Err("Privacy recovery directory could not be checked.".into()),
    }
    let entries = fs::read_dir(&directory).map_err(|error| error.to_string())?;
    let mut sources = HashMap::<Uuid, RestoreSource>::new();
    let mut restore_states = HashMap::<Uuid, (PrivacyRecoveryState, Option<String>)>::new();
    for entry in entries {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path
            .extension()
            .is_none_or(|extension| extension != "jsonl")
        {
            continue;
        }
        let operation_id = path
            .file_stem()
            .and_then(|stem| Uuid::parse_str(&stem.to_string_lossy()).ok())
            .ok_or_else(|| "Privacy journal has an invalid operation identifier.".to_owned())?;
        let file = File::open(&path).map_err(|error| error.to_string())?;
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|error| error.to_string())?;
            let event: PrivacyJournalEvent = serde_json::from_str(&line).map_err(|error| {
                format!("A privacy journal is damaged and was preserved for recovery: {error}")
            })?;
            match event {
                PrivacyJournalEvent::Outcome {
                    database,
                    backup,
                    deleted_ids,
                    committed,
                    uncertain,
                    restore_id: Some(id),
                    browser,
                    profile_name,
                    profile_root,
                    categories,
                    post_state_snapshot,
                    post_state_stamp,
                    schema_signature,
                    restore_error,
                    ..
                } => {
                    if !committed || deleted_ids.is_empty() {
                        continue;
                    }
                    let browser = browser.ok_or_else(|| {
                        "A recovery journal is missing its browser identity.".to_owned()
                    })?;
                    let profile_name = profile_name.unwrap_or_else(|| "Browser profile".into());
                    let (state, reason) = if uncertain {
                        (
                            PrivacyRecoveryState::Uncertain,
                            Some(
                                "Cleanup outcome is uncertain; automatic restore is blocked."
                                    .into(),
                            ),
                        )
                    } else if let Some(reason) = restore_error {
                        (PrivacyRecoveryState::Unavailable, Some(reason))
                    } else if post_state_snapshot.is_none()
                        || post_state_stamp.is_none()
                        || schema_signature.is_none()
                        || profile_root.is_none()
                    {
                        (
                            PrivacyRecoveryState::Unavailable,
                            Some("Verified post-cleanup state is missing; reviewed restore is unavailable.".into()),
                        )
                    } else {
                        (PrivacyRecoveryState::Ready, None)
                    };
                    let database_name = database
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "browser database".into());
                    sources.insert(
                        id,
                        RestoreSource {
                            option: PrivacyRestoreOption {
                                id,
                                browser,
                                profile_name,
                                database_name,
                                categories,
                                record_count: deleted_ids.len(),
                                state,
                                reason,
                            },
                            source_operation_id: operation_id,
                            profile_root,
                            database,
                            backup,
                            post_state_snapshot,
                            post_state_stamp,
                            schema_signature,
                        },
                    );
                }
                PrivacyJournalEvent::RestoreIntent { restore_id, .. } => {
                    restore_states.insert(
                        restore_id,
                        (
                            PrivacyRecoveryState::Uncertain,
                            Some("Restore was interrupted; the current-state copy is preserved and automatic retry is blocked.".into()),
                        ),
                    );
                }
                PrivacyJournalEvent::RestoreOutcome {
                    restore_id,
                    restored,
                    uncertain,
                    error,
                    ..
                } => {
                    let state = if uncertain {
                        PrivacyRecoveryState::Uncertain
                    } else if restored {
                        PrivacyRecoveryState::Restored
                    } else {
                        PrivacyRecoveryState::Unavailable
                    };
                    restore_states.insert(restore_id, (state, error));
                }
                PrivacyJournalEvent::Start { .. }
                | PrivacyJournalEvent::Intent { .. }
                | PrivacyJournalEvent::Finish { .. }
                | PrivacyJournalEvent::Outcome { .. } => {}
            }
        }
    }
    for (id, (state, reason)) in restore_states {
        if let Some(source) = sources.get_mut(&id) {
            source.option.state = state;
            source.option.reason = reason;
        }
    }
    let mut result = sources.into_values().collect::<Vec<_>>();
    for source in &mut result {
        if source.option.state == PrivacyRecoveryState::Ready
            && source.profile_root.as_ref().is_some_and(|root| {
                PrivacyCategory::ALL.iter().any(|category| {
                    file_owned_category(source.option.browser, *category, root, &source.database)
                })
            })
        {
            source.option.state = PrivacyRecoveryState::Unavailable;
            source.option.reason = Some("This database now belongs to a browser file-cleanup rule; database restore is unavailable.".into());
        }
    }
    result.sort_by(|left, right| {
        left.option
            .browser
            .label()
            .cmp(right.option.browser.label())
            .then_with(|| left.option.profile_name.cmp(&right.option.profile_name))
            .then_with(|| left.option.database_name.cmp(&right.option.database_name))
    });
    Ok(result)
}

/// Check a selected backup and current database, without changing either one.
pub fn prepare_privacy_restore(
    data_dir: &Path,
    restore_id: Uuid,
) -> Result<PrivacyRestorePlan, String> {
    prepare_privacy_restore_with_runtime(data_dir, restore_id, &NativeBrowserRuntime)
}

/// Runtime-injected preflight used by isolated fixture tests.
pub fn prepare_privacy_restore_with_runtime(
    data_dir: &Path,
    restore_id: Uuid,
    runtime: &impl BrowserRuntime,
) -> Result<PrivacyRestorePlan, String> {
    if let Some(plan) = preferences::prepare_restore(data_dir, restore_id, runtime)? {
        return Ok(plan);
    }
    if let Some(plan) = leveldb_write::prepare_restore(data_dir, restore_id, runtime)? {
        return Ok(plan);
    }
    let source = load_restore_sources(data_dir)?
        .into_iter()
        .find(|source| source.option.id == restore_id)
        .ok_or_else(|| "The selected recovery item is no longer available.".to_owned())?;
    if source.option.state != PrivacyRecoveryState::Ready {
        return Err(source
            .option
            .reason
            .unwrap_or_else(|| "This recovery item is not available for restore.".into()));
    }
    generic_sqlite::pending(data_dir, &source.database)?;
    if runtime
        .running_browsers()?
        .iter()
        .any(|process| source.option.browser.conflicts_with(process))
    {
        return Err(format!(
            "Close {} before restoring its browser database.",
            source.option.browser.label()
        ));
    }
    let profile_root = source
        .profile_root
        .ok_or_else(|| "The recorded browser profile is missing.".to_owned())?;
    let (database, current_stamp, _) = validate_database_path(&profile_root, &source.database)
        .map_err(|_| "The recorded browser database is unavailable or redirected.".to_owned())?;
    let post_state_stamp = source
        .post_state_stamp
        .ok_or_else(|| "The post-cleanup database identity is missing.".to_owned())?;
    if current_stamp != post_state_stamp {
        return Err("The browser database changed since cleanup; restore is blocked.".into());
    }
    ensure_no_database_sidecars(&database)?;
    let post_state_snapshot = source
        .post_state_snapshot
        .ok_or_else(|| "The verified post-cleanup state copy is missing.".to_owned())?;
    validate_recovery_artifact(data_dir, &source.backup)?;
    validate_recovery_artifact(data_dir, &post_state_snapshot)?;
    if !files_identical(&database, &post_state_snapshot)? {
        return Err(
            "The current browser database no longer matches its exact post-cleanup state copy."
                .into(),
        );
    }
    let (_, schema_signature) = verify_readonly_database(&database)?;
    let expected_schema = source
        .schema_signature
        .ok_or_else(|| "The recorded database schema is missing.".to_owned())?;
    if schema_signature != expected_schema {
        return Err(
            "The browser database schema changed since cleanup; restore is blocked.".into(),
        );
    }
    let (_, backup_schema) = verify_readonly_database(&source.backup)?;
    if backup_schema != expected_schema {
        return Err(
            "The pre-cleanup recovery copy does not match the recorded database schema.".into(),
        );
    }
    if !file_stamp(&database).is_ok_and(|stamp| stamp == post_state_stamp)
        || !files_identical(&database, &post_state_snapshot)?
    {
        return Err("The browser database changed during restore review; review it again.".into());
    }
    Ok(PrivacyRestorePlan {
        id: restore_id,
        operation_id: source.source_operation_id,
        browser: source.option.browser,
        profile_name: source.option.profile_name,
        database_name: source.option.database_name,
        profile_root,
        database,
        backup: source.backup,
        post_state_snapshot,
        post_state_stamp,
        schema_signature: expected_schema,
        leveldb: None,
        preferences: None,
    })
}

/// Restore a reviewed browser database from its verified pre-cleanup image.
/// The current state is copied and journaled before SQLite is changed.
pub fn restore_privacy_database(
    data_dir: &Path,
    plan: &PrivacyRestorePlan,
) -> Result<PrivacyRestoreReceipt, String> {
    restore_privacy_database_with_runtime(data_dir, plan, &NativeBrowserRuntime)
}

/// Runtime-injected restore path used by fixture tests.
pub fn restore_privacy_database_with_runtime(
    data_dir: &Path,
    plan: &PrivacyRestorePlan,
    runtime: &impl BrowserRuntime,
) -> Result<PrivacyRestoreReceipt, String> {
    if let Some(fields) = &plan.preferences {
        return preferences::restore(data_dir, fields, runtime);
    }
    if let Some(keys) = &plan.leveldb {
        return leveldb_write::restore(data_dir, keys, runtime);
    }
    let current = prepare_privacy_restore_with_runtime(data_dir, plan.id, runtime)?;
    if current.operation_id != plan.operation_id
        || current.profile_name != plan.profile_name
        || !same_path(&current.profile_root, &plan.profile_root)
        || !same_path(&current.database, &plan.database)
        || !same_path(&current.backup, &plan.backup)
        || !same_path(&current.post_state_snapshot, &plan.post_state_snapshot)
        || current.post_state_stamp != plan.post_state_stamp
        || current.schema_signature != plan.schema_signature
    {
        return Err(
            "The restore review changed. Prepare a new recovery plan before continuing.".into(),
        );
    }
    let restore_operation_id = Uuid::new_v4();
    let current_state_backup = current
        .post_state_snapshot
        .with_file_name(format!("current-state-{restore_operation_id}.sqlite"));
    snapshot_exact_database_state(
        &current.database,
        &current_state_backup,
        current.post_state_stamp.clone(),
        &current.schema_signature,
    )?;
    if !files_identical(&current.database, &current.post_state_snapshot)?
        || !file_stamp(&current.database).is_ok_and(|stamp| stamp == current.post_state_stamp)
    {
        let _ = fs::remove_file(&current_state_backup);
        return Err("The browser database changed after review; no restore was started.".into());
    }

    let mut journal = PrivacyJournal::create(data_dir, restore_operation_id)?;
    journal.append(&PrivacyJournalEvent::Start {
        operation_id: restore_operation_id,
        report_id: current.operation_id,
        date: chrono::Local::now().to_rfc3339(),
    })?;
    journal.append(&PrivacyJournalEvent::RestoreIntent {
        restore_id: current.id,
        source_operation_id: current.operation_id,
        database: current.database.clone(),
        source_backup: current.backup.clone(),
        current_state_backup: current_state_backup.clone(),
        post_state_snapshot: current.post_state_snapshot.clone(),
        expected_stamp: current.post_state_stamp.clone(),
        schema_signature: current.schema_signature.clone(),
    })?;

    let result = (|| -> Result<(), String> {
        if runtime
            .running_browsers()?
            .iter()
            .any(|process| current.browser.conflicts_with(process))
        {
            return Err(format!(
                "{} started while restore was being prepared.",
                current.browser.label()
            ));
        }
        if !file_stamp(&current.database).is_ok_and(|stamp| stamp == current.post_state_stamp)
            || !files_identical(&current.database, &current.post_state_snapshot)?
        {
            return Err(
                "Browser database changed immediately before restore; no write was made.".into(),
            );
        }
        validate_recovery_artifact(data_dir, &current.backup)?;
        let (live_database, live_stamp, _) =
            validate_database_path(&current.profile_root, &current.database)
                .map_err(|_| "Browser database was redirected during restore review.".to_owned())?;
        if !same_path(&live_database, &current.database)
            || live_stamp != current.post_state_stamp
            || !files_identical(&live_database, &current.post_state_snapshot)?
        {
            return Err(
                "Browser database changed or was redirected immediately before restore.".into(),
            );
        }
        let (_, source_schema) = verify_readonly_database(&current.backup)?;
        if source_schema != current.schema_signature {
            return Err("Pre-cleanup recovery copy changed after restore review.".into());
        }
        let source = Connection::open_with_flags(
            &current.backup,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| "Pre-cleanup recovery copy could not be opened.".to_owned())?;
        let mut destination = Connection::open_with_flags(
            &live_database,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| "Browser database could not be opened for the reviewed restore.".to_owned())?;
        destination
            .busy_timeout(Duration::from_secs(2))
            .map_err(|error| error.to_string())?;
        destination
            .execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")
            .map_err(|error| format!("Could not configure the restore: {error}"))?;
        if runtime
            .running_browsers()?
            .iter()
            .any(|process| current.browser.conflicts_with(process))
        {
            return Err(format!(
                "{} started while restore was being opened.",
                current.browser.label()
            ));
        }
        Backup::new(&source, &mut destination)
            .map_err(|error| error.to_string())?
            .run_to_completion(128, Duration::from_millis(5), None)
            .map_err(|error| format!("Database restore did not complete: {error}"))?;
        let integrity: String = destination
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|_| "Restored database integrity could not be checked.".to_owned())?;
        if integrity != "ok" {
            return Err("Restored database integrity check failed.".into());
        }
        verify_foreign_keys(&destination)?;
        if schema_signature(&destination)? != current.schema_signature {
            return Err("Restored database schema does not match the reviewed backup.".into());
        }
        drop(destination);
        drop(source);
        ensure_no_database_sidecars(&current.database)?;
        let (_, restored_schema) = verify_readonly_database(&current.database)?;
        if restored_schema != current.schema_signature {
            return Err("Restored database changed after verification.".into());
        }
        Ok(())
    })();

    let error = result.err();
    let restored = error.is_none();
    let mut receipt = PrivacyRestoreReceipt {
        id: restore_operation_id,
        source_operation_id: current.operation_id,
        restored,
        uncertain: !restored,
        current_state_backup: Some(current_state_backup.clone()),
        ..PrivacyRestoreReceipt::default()
    };
    if let Some(error) = error {
        receipt.errors.push(error);
    }
    if journal
        .append(&PrivacyJournalEvent::RestoreOutcome {
            restore_id: current.id,
            database: current.database.clone(),
            current_state_backup,
            restored,
            uncertain: !restored,
            error: receipt.errors.first().cloned(),
        })
        .is_err()
    {
        receipt.uncertain = true;
        receipt
            .errors
            .push("Restore outcome could not be synced; automatic retry is blocked.".into());
    }
    if journal
        .append(&PrivacyJournalEvent::Finish { cancelled: false })
        .is_err()
    {
        receipt.uncertain = true;
        receipt.errors.push(
            "Restore finish state could not be synced; review recovery status before retrying."
                .into(),
        );
    }
    Ok(receipt)
}

fn validate_recovery_artifact(data_dir: &Path, path: &Path) -> Result<(), String> {
    let root = data_dir.join("privacy-recovery");
    let root_metadata = fs::symlink_metadata(&root)
        .map_err(|_| "Private recovery storage is unavailable.".to_owned())?;
    if is_link(&root_metadata) || !root_metadata.is_dir() {
        return Err("Private recovery storage is linked or not a directory.".into());
    }
    let canonical_root = dunce::canonicalize(&root)
        .map_err(|_| "Private recovery storage is unavailable.".to_owned())?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "A required private recovery image is unavailable.".to_owned())?;
    if is_link(&metadata)
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_DATABASE_BYTES
    {
        return Err("A required private recovery image is linked, invalid, or empty.".into());
    }
    let canonical = dunce::canonicalize(path)
        .map_err(|_| "A required private recovery image is unavailable.".to_owned())?;
    if !same_path(&canonical, path) || !contained(&canonical_root, &canonical) {
        return Err("A required private recovery image is outside protected storage.".into());
    }
    Ok(())
}

fn snapshot_exact_database_state(
    database: &Path,
    destination: &Path,
    expected_stamp: FileStamp,
    expected_schema: &str,
) -> Result<(), String> {
    ensure_no_database_sidecars(database)?;
    if !file_stamp(database).is_ok_and(|stamp| stamp == expected_stamp) {
        return Err("Browser database metadata changed before current-state backup.".into());
    }
    let (_, schema) = verify_readonly_database(database)?;
    if schema != expected_schema {
        return Err("Browser database schema changed before current-state backup.".into());
    }
    private_file_options()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| format!("Could not create current-state backup: {error}"))?;
    let result = (|| -> Result<(), String> {
        let mut source = File::open(database).map_err(|error| error.to_string())?;
        let mut output = OpenOptions::new()
            .write(true)
            .open(destination)
            .map_err(|error| error.to_string())?;
        std::io::copy(&mut source, &mut output)
            .and_then(|_| output.sync_all())
            .map_err(|error| format!("Could not sync current-state backup: {error}"))?;
        drop(output);
        drop(source);
        if !file_stamp(database).is_ok_and(|stamp| stamp == expected_stamp)
            || !files_identical(database, destination)?
        {
            return Err("Browser database changed while current-state backup was made.".into());
        }
        ensure_no_database_sidecars(database)?;
        let (_, snapshot_schema) = verify_readonly_database(destination)?;
        if snapshot_schema != expected_schema {
            return Err("Current-state backup schema verification failed.".into());
        }
        let parent = destination
            .parent()
            .ok_or_else(|| "Recovery directory is unavailable.".to_owned())?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn make_database_backup(
    data_dir: &Path,
    operation: Uuid,
    record: &RowLocator,
    database: &Path,
) -> Result<PathBuf, String> {
    let mut profile_hasher = std::collections::hash_map::DefaultHasher::new();
    record.browser.hash(&mut profile_hasher);
    record.profile_id.hash(&mut profile_hasher);
    let mut db_hasher = std::collections::hash_map::DefaultHasher::new();
    path_identity(database).hash(&mut db_hasher);
    let directory = data_dir
        .join("privacy-recovery")
        .join(operation.to_string())
        .join(format!("{:016x}", profile_hasher.finish()));
    create_private_dir(&directory)?;
    let backup = directory.join(format!("database-{:016x}.sqlite", db_hasher.finish()));
    let before = file_stamp(database)?;
    if before != record.database_stamp {
        return Err("Database changed since scan.".into());
    }
    private_file_options()
        .write(true)
        .create_new(true)
        .open(&backup)
        .map_err(|e| format!("Could not create private snapshot: {e}"))?;
    let result = (|| -> Result<(), String> {
        let source = Connection::open_with_flags(
            database,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| e.to_string())?;
        let mut destination = Connection::open_with_flags(
            &backup,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| e.to_string())?;
        Backup::new(&source, &mut destination)
            .map_err(|e| e.to_string())?
            .run_to_completion(128, Duration::from_millis(5), None)
            .map_err(|e| e.to_string())?;
        let integrity: String = destination
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|e| e.to_string())?;
        if integrity != "ok" {
            return Err("Recovery snapshot failed its integrity check.".into());
        }
        drop(destination);
        drop(source);
        let sync_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&backup)
            .map_err(|e| format!("Could not reopen recovery snapshot for syncing: {e}"))?;
        sync_file
            .sync_all()
            .map_err(|e| format!("Could not sync recovery snapshot: {e}"))?;
        drop(sync_file);
        sync_directory(&directory)?;
        let backup_stamp = file_stamp(&backup)?;
        if backup_stamp.length == 0 {
            return Err("Recovery snapshot is empty after syncing.".into());
        }
        let verification = Connection::open_with_flags(
            &backup,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| format!("Could not reopen the synced recovery snapshot: {e}"))?;
        let post_sync_check: String = verification
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|e| format!("Could not reverify the synced recovery snapshot: {e}"))?;
        drop(verification);
        if post_sync_check != "ok" {
            return Err("Synced recovery snapshot failed its integrity check.".into());
        }
        if !file_stamp(&backup).is_ok_and(|after| after == backup_stamp) {
            return Err("Recovery snapshot changed after it was synced.".into());
        }
        if !file_stamp(database).is_ok_and(|after| after == record.database_stamp) {
            return Err("Database changed while creating the recovery snapshot.".into());
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&backup);
        return Err(error);
    }
    Ok(backup)
}

fn make_post_state_snapshot(
    database: &Path,
    pre_cleanup_backup: &Path,
    restore_id: Uuid,
) -> Result<(PathBuf, FileStamp, String), String> {
    let directory = pre_cleanup_backup
        .parent()
        .ok_or_else(|| "Recovery snapshot directory is unavailable.".to_owned())?;
    create_private_dir(directory)?;
    let snapshot = directory.join(format!("post-state-{restore_id}.sqlite"));
    let before = file_stamp(database)?;
    if before.length == 0 || before.length > MAX_DATABASE_BYTES {
        return Err("Post-cleanup database size is outside the recovery limit.".into());
    }
    ensure_no_database_sidecars(database)?;
    let (_, schema_before) = verify_readonly_database(database)?;
    private_file_options()
        .write(true)
        .create_new(true)
        .open(&snapshot)
        .map_err(|error| format!("Could not create post-cleanup state copy: {error}"))?;
    let result = (|| -> Result<(FileStamp, String), String> {
        let mut source = File::open(database).map_err(|error| error.to_string())?;
        let mut destination = OpenOptions::new()
            .write(true)
            .open(&snapshot)
            .map_err(|error| error.to_string())?;
        std::io::copy(&mut source, &mut destination)
            .and_then(|_| destination.sync_all())
            .map_err(|error| format!("Could not sync post-cleanup state copy: {error}"))?;
        drop(destination);
        drop(source);
        sync_directory(directory)?;
        let after = file_stamp(database)?;
        if after != before {
            return Err("Database metadata changed while saving post-cleanup state.".into());
        }
        ensure_no_database_sidecars(database)?;
        if !files_identical(database, &snapshot)? {
            return Err("Database bytes changed while saving post-cleanup state.".into());
        }
        let (snapshot_check, snapshot_signature) = verify_readonly_database(&snapshot)?;
        let (live_check, live_signature) = verify_readonly_database(database)?;
        if snapshot_check != "ok"
            || live_check != "ok"
            || snapshot_signature != schema_before
            || live_signature != schema_before
        {
            return Err("Post-cleanup schema changed while saving recovery state.".into());
        }
        Ok((after, snapshot_signature))
    })();
    match result {
        Ok((stamp, signature)) => Ok((snapshot, stamp, signature)),
        Err(error) => {
            let _ = fs::remove_file(&snapshot);
            Err(error)
        }
    }
}

fn ensure_no_database_sidecars(database: &Path) -> Result<(), String> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = database.as_os_str().to_os_string();
        name.push(suffix);
        let path = PathBuf::from(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if is_link(&metadata) || !metadata.is_file() => {
                return Err("A browser database sidecar is linked or not a regular file.".into());
            }
            Ok(metadata) if metadata.len() > 0 => {
                return Err(
                    "A browser database sidecar is still present; reviewed restore is unavailable."
                        .into(),
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Database sidecars could not be inspected: {error}")),
        }
    }
    Ok(())
}

fn verify_readonly_database(database: &Path) -> Result<(String, String), String> {
    let conn = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| "Database could not be opened read-only for recovery verification.".to_owned())?;
    conn.busy_timeout(Duration::from_secs(2))
        .map_err(|_| "Database could not be verified for recovery.".to_owned())?;
    conn.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
        .map_err(|_| "Database could not be verified read-only.".to_owned())?;
    let integrity: String = conn
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| "Database integrity could not be checked.".to_owned())?;
    if integrity != "ok" {
        return Err("Database integrity check did not pass.".into());
    }
    let signature = schema_signature(&conn)?;
    Ok((integrity, signature))
}

fn schema_signature(conn: &Connection) -> Result<String, String> {
    const MAX_SCHEMA_OBJECTS: usize = 50_000;
    let mut statement = conn
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name LIMIT ?1")
        .map_err(|_| "Database schema could not be read.".to_owned())?;
    let rows = statement
        .query_map([MAX_SCHEMA_OBJECTS as i64 + 1], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|_| "Database schema could not be read.".to_owned())?;
    let objects = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| "Database schema changed while being read.".to_owned())?;
    if objects.len() > MAX_SCHEMA_OBJECTS {
        return Err("Database schema exceeds the recovery verification limit.".into());
    }
    serde_json::to_string(&objects).map_err(|_| "Database schema could not be recorded.".into())
}

fn files_identical(left: &Path, right: &Path) -> Result<bool, String> {
    let mut left = File::open(left).map_err(|error| error.to_string())?;
    let mut right = File::open(right).map_err(|error| error.to_string())?;
    let mut left_buffer = [0u8; 64 * 1024];
    let mut right_buffer = [0u8; 64 * 1024];
    loop {
        let left_count = left
            .read(&mut left_buffer)
            .map_err(|error| error.to_string())?;
        let right_count = right
            .read(&mut right_buffer)
            .map_err(|error| error.to_string())?;
        if left_count != right_count || left_buffer[..left_count] != right_buffer[..right_count] {
            return Ok(false);
        }
        if left_count == 0 {
            return Ok(true);
        }
    }
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|e| format!("Could not create private recovery storage: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Could not restrict recovery directory permissions: {e}"))?;
    }
    Ok(())
}

fn private_file_options() -> OpenOptions {
    #[allow(unused_mut)]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod discovery_tests {
    use super::*;

    #[test]
    fn empty_inventory_is_partial_when_supported_browser_is_running() {
        let mut inventory = ProfileInventory::default();
        let running = vec![RunningBrowser {
            browser: Browser::Chrome,
            pid: 42,
            executable: "chrome.exe".into(),
        }];

        mark_empty_inventory_if_indeterminate(&mut inventory, Ok(running));

        assert!(inventory.profiles.is_empty());
        assert!(inventory.partial);
        assert_eq!(inventory.skipped.len(), 1);
        assert!(inventory.skipped[0].path.is_none());
        assert!(
            inventory.skipped[0]
                .reason
                .contains("profile location could not be confirmed")
        );
        assert!(!inventory.skipped[0].reason.contains("chrome.exe"));
    }

    #[test]
    fn empty_inventory_is_partial_when_process_status_is_unavailable() {
        let mut inventory = ProfileInventory::default();

        mark_empty_inventory_if_indeterminate(
            &mut inventory,
            Err("native process query details must not leak".into()),
        );

        assert!(inventory.partial);
        assert_eq!(inventory.skipped.len(), 1);
        assert!(
            inventory.skipped[0]
                .reason
                .contains("status could not be checked")
        );
        assert!(
            !inventory.skipped[0]
                .reason
                .contains("native process query details")
        );
    }

    #[test]
    fn empty_inventory_remains_complete_when_no_browser_is_running() {
        let mut inventory = ProfileInventory::default();

        mark_empty_inventory_if_indeterminate(&mut inventory, Ok(Vec::new()));

        assert!(!inventory.partial);
        assert!(inventory.skipped.is_empty());
    }

    #[test]
    fn discovered_profile_does_not_become_empty_or_partial_from_process_status() {
        let mut inventory = ProfileInventory {
            profiles: vec![BrowserProfile {
                id: "fixture-profile".into(),
                browser: Browser::Chrome,
                name: "Default".into(),
                root: PathBuf::from("fixture/Default"),
            }],
            ..ProfileInventory::default()
        };

        mark_empty_inventory_if_indeterminate(&mut inventory, Err("unavailable".into()));

        assert!(!inventory.partial);
        assert!(inventory.skipped.is_empty());
        assert_eq!(inventory.profiles.len(), 1);
    }
}
