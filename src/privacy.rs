//! Browser privacy inventory and carefully journaled deletion for known SQLite schemas.
//!
//! The inventory intentionally omits URL paths, page titles, cookie names and all cookie
//! contents from its public records. Cleanup is limited to history, download-history and
//! cookie rows in recognized Chrome, Edge and Firefox databases.

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

use crate::scanner::{contained, is_link, safe_root, same_path, timestamp};

const MAX_PROFILES: usize = 128;
const MAX_RECORDS: usize = 50_000;
const MAX_DATABASE_BYTES: u64 = 1_073_741_824;
const MAX_SKIP_DETAILS: usize = 2_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Browser {
    Chrome,
    Edge,
    Firefox,
}

impl Browser {
    pub fn label(self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Edge => "Edge",
            Self::Firefox => "Firefox",
        }
    }

    fn process_names(self) -> &'static [&'static str] {
        match self {
            Self::Chrome => &["chrome.exe", "google chrome"],
            Self::Edge => &["msedge.exe", "microsoft edge"],
            Self::Firefox => &["firefox.exe", "firefox"],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyCategory {
    History,
    Cookies,
    Downloads,
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
    /// A sanitized site/host label, never a full URL or a cookie value.
    pub site: String,
    locator: RowLocator,
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
    pub records_found: usize,
    pub profile_name: String,
    pub category: PrivacyCategory,
}

#[derive(Clone)]
pub struct PrivacyPlan {
    report_id: Uuid,
    operation_id: Uuid,
    records: Vec<RowLocator>,
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
}

impl Default for CookieExceptionSettings {
    fn default() -> Self {
        Self {
            schema: COOKIE_SETTINGS_SCHEMA,
            keep_domains: Vec::new(),
        }
    }
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
}

impl PrivacyRestorePlan {
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TableKind {
    ChromiumHistory,
    ChromiumCookies,
    ChromiumDownloads,
    FirefoxHistory,
    FirefoxCookies,
    FirefoxDownloads,
}

impl TableKind {
    fn category(self) -> PrivacyCategory {
        match self {
            Self::ChromiumHistory | Self::FirefoxHistory => PrivacyCategory::History,
            Self::ChromiumCookies | Self::FirefoxCookies => PrivacyCategory::Cookies,
            Self::ChromiumDownloads | Self::FirefoxDownloads => PrivacyCategory::Downloads,
        }
    }

    fn table(self) -> &'static str {
        match self {
            Self::ChromiumHistory => "urls",
            Self::ChromiumCookies => "cookies",
            Self::ChromiumDownloads => "downloads",
            Self::FirefoxHistory => "moz_places",
            Self::FirefoxCookies => "moz_cookies",
            Self::FirefoxDownloads => "moz_downloads",
        }
    }

    fn query(self) -> &'static str {
        match self {
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
        }
    }

    fn required_columns(self) -> &'static [&'static str] {
        match self {
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
        }
    }

    fn identity_sql(self) -> &'static str {
        match self {
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
        }
    }

    fn row_identity(self, row: &rusqlite::Row<'_>) -> rusqlite::Result<Vec<Value>> {
        (1..row.as_ref().column_count())
            .map(|column| row.get_ref(column).map(Value::from))
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
            Self::ChromiumHistory | Self::ChromiumDownloads => row.get(2)?,
            Self::ChromiumCookies => row.get(1)?,
            Self::FirefoxHistory | Self::FirefoxDownloads => row.get(2)?,
            Self::FirefoxCookies => row.get(2)?,
        };
        Ok(safe_site_label(&text))
    }

    fn verify_delete_schema(self, conn: &Connection) -> Result<(), String> {
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
            .all(|name| columns.contains(*name))
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

fn database_targets(profile: &BrowserProfile) -> Vec<DatabaseTarget> {
    match profile.browser {
        Browser::Chrome | Browser::Edge => vec![
            DatabaseTarget {
                path: profile.root.join("History"),
                kind: TableKind::ChromiumHistory,
            },
            DatabaseTarget {
                path: match profile.root.join("Network").join("Cookies").try_exists() {
                    Ok(false) => profile.root.join("Cookies"),
                    Ok(true) | Err(_) => profile.root.join("Network").join("Cookies"),
                },
                kind: TableKind::ChromiumCookies,
            },
            DatabaseTarget {
                path: profile.root.join("History"),
                kind: TableKind::ChromiumDownloads,
            },
        ],
        Browser::Firefox => vec![
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
        ],
    }
}

/// Discover standard Chrome, Edge and Firefox profiles for the current Windows or macOS user.
pub fn discover_profiles() -> ProfileInventory {
    let mut inventory = ProfileInventory::default();
    let mut roots = Vec::new();
    if cfg!(windows) {
        if let Some(local) = dirs::data_local_dir() {
            roots.push((Browser::Chrome, local.join("Google/Chrome/User Data")));
            roots.push((Browser::Edge, local.join("Microsoft/Edge/User Data")));
        }
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
        let safe = match safe_root(&root) {
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
        match browser {
            Browser::Chrome | Browser::Edge => {
                discover_chromium_profiles(browser, &safe, &mut inventory)
            }
            Browser::Firefox => discover_firefox_profiles(&safe, &mut inventory),
        }
    }
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
        Browser::Firefox => return Ok(Vec::new()),
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

fn discover_chromium_profiles(browser: Browser, root: &Path, inventory: &mut ProfileInventory) {
    let friendly_names = fs::read(root.join("Local State"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| value.pointer("/profile/info_cache").cloned())
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => {
            inventory.partial = true;
            inventory.skipped.push(InventorySkip {
                path: Some(root.to_path_buf()),
                reason: "Browser profile directory could not be read.".into(),
            });
            return;
        }
    };
    for entry in entries {
        if inventory.profiles.len() >= MAX_PROFILES {
            inventory.partial = true;
            break;
        }
        let Ok(entry) = entry else {
            inventory.partial = true;
            continue;
        };
        let profile_path = entry.path();
        let Some(directory) = profile_path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if directory != "Default" && !directory.starts_with("Profile ") {
            continue;
        }
        if !safe_profile_directory(root, &profile_path, false) {
            continue;
        }
        let name = friendly_names
            .get(directory)
            .and_then(|profile| profile.get("name"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if directory == "Default" {
                    "Default".into()
                } else {
                    directory.into()
                }
            });
        inventory
            .profiles
            .push(make_profile(browser, name, profile_path));
    }
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
    if !allow_external && !contained(root, directory) {
        return false;
    }
    dunce::canonicalize(directory).is_ok_and(|canonical| {
        same_path(&canonical, directory) && (allow_external || contained(root, &canonical))
    })
}

fn make_profile(browser: Browser, name: String, root: PathBuf) -> BrowserProfile {
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
    [Browser::Chrome, Browser::Edge, Browser::Firefox]
        .into_iter()
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
        &[
            PrivacyCategory::History,
            PrivacyCategory::Cookies,
            PrivacyCategory::Downloads,
        ],
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
    let keep_domains = settings
        .keep_domains
        .iter()
        .filter_map(|domain| normalize_cookie_domain(domain).ok())
        .collect::<HashSet<_>>();
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
        .filter(|profile| seen.insert((profile.browser, path_identity(&profile.root))))
        .cloned()
        .collect::<Vec<_>>();
    if profiles.len() > MAX_PROFILES {
        report.truncated = true;
        add_skip(&mut report, "", None, "Profile limit reached.");
    }
    for (profile_index, profile) in selected_profiles.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            break;
        }
        report.profiles_scanned += 1;
        let targets = database_targets(profile)
            .into_iter()
            .filter(|target| selected_categories.contains(&target.kind.category()))
            .collect::<Vec<_>>();
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
                records_found: report.records.len(),
                profile_name: profile.name.clone(),
                category: target.kind.category(),
            });
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
    if let Err(reason) = target.kind.verify_delete_schema(&conn) {
        add_skip(report, &profile.name, Some(target.kind.category()), &reason);
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
            locator: RowLocator {
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
            },
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
            return Ok(CookieExceptionSettings {
                schema: COOKIE_SETTINGS_SCHEMA,
                keep_domains: Vec::new(),
            });
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

/// Validate and persist cookie keep-domains. This accepts DNS names, punycode and IP literals,
/// but not URL paths, ports, wildcards or credentials.
pub fn save_cookie_exception_settings(
    data_dir: &Path,
    domains: &[String],
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

fn is_cookie_exception(site: &str, keep_domains: &HashSet<String>) -> bool {
    let Ok(host) = normalize_cookie_domain(site) else {
        return false;
    };
    keep_domains.iter().any(|domain| {
        host == *domain
            || (host.len() > domain.len()
                && host.ends_with(domain)
                && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
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
    let root = safe_root(profile_root)?;
    if !same_path(&root, profile_root) || !contained(&root, database) {
        return Err("Database is outside the profile.".into());
    }
    let metadata = fs::symlink_metadata(database).map_err(|e| e.to_string())?;
    if is_link(&metadata) || !metadata.is_file() {
        return Err("Database is linked or not a regular file.".into());
    }
    let canonical = dunce::canonicalize(database).map_err(|e| e.to_string())?;
    if !same_path(&canonical, database) || !contained(&root, &canonical) {
        return Err("Database resolves outside its profile.".into());
    }
    let stamp = file_stamp(&canonical)?;
    Ok((canonical, stamp, root))
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
    for id in selected_ids {
        let Some(record) = by_id.get(id) else {
            return Err("Unknown record ID. Scan again before cleanup.".into());
        };
        if seen.insert(*id) {
            records.push(record.locator.clone());
        }
    }
    Ok(PrivacyPlan {
        report_id: report.id,
        operation_id: Uuid::new_v4(),
        records,
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
    if plan.records.is_empty() {
        return Err("Select browser records from the current scan.".into());
    }
    ensure_browsers_stopped(runtime, &plan.records)?;

    let mut journal = PrivacyJournal::create(data_dir, plan.operation_id)?;
    journal.append(&PrivacyJournalEvent::Start {
        operation_id: plan.operation_id,
        report_id: plan.report_id,
        date: chrono::Local::now().to_rfc3339(),
    })?;
    let mut receipt = PrivacyReceipt {
        id: plan.operation_id,
        selected: plan.records.len(),
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
    let total = grouped.values().map(Vec::len).sum::<usize>();
    let mut done = 0;

    for (database, records) in grouped {
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
        if let Err(error) = ensure_browsers_stopped(runtime, &records) {
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
        if let Err(error) = ensure_browsers_stopped(runtime, &records) {
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
            ensure_browsers_stopped(runtime, &records)?;
            verify_foreign_keys(&tx)?;
            for record in &records {
                if cancel.load(Ordering::Relaxed) {
                    database_cancelled = true;
                    break;
                }
                record.kind.verify_delete_schema(&tx)?;
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
            if database_cancelled {
                tx.rollback()
                    .map_err(|e| format!("Cancelled cleanup could not be rolled back: {e}"))?;
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
        });
        if tx_outcome.is_ok() && !database_cancelled && !database_deleted.is_empty() {
            let id = Uuid::new_v4();
            restore_id = Some(id);
            let snapshot_result = ensure_browsers_stopped(runtime, &records)
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

fn ensure_browsers_stopped(
    runtime: &impl BrowserRuntime,
    records: &[RowLocator],
) -> Result<(), String> {
    let running = runtime.running_browsers()?;
    let required = records
        .iter()
        .map(|record| record.browser)
        .collect::<HashSet<_>>();
    let conflicts = running
        .iter()
        .filter(|process| required.contains(&process.browser))
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
    Ok(load_restore_sources(data_dir)?
        .into_iter()
        .map(|source| source.option)
        .collect())
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
    if runtime
        .running_browsers()?
        .iter()
        .any(|process| process.browser == source.option.browser)
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
            .any(|process| process.browser == current.browser)
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
            .any(|process| process.browser == current.browser)
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
