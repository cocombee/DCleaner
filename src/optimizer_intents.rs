//! Durable exact registry intent records for the future optimizer resource owner.
//! No native effect, replay, lease authorization or verified outcome is produced.
//! The service must provide protected storage, validated native image/resource
//! identity, current generation and helper readiness. Those owners are not wired.
#![allow(dead_code)]

use crate::{
    optimizer_identity::ImageSnapshot, optimizer_registration::RegistryView,
    optimizer_requests::Caller,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

const APP_ID: i64 = 0x4443_5249;
const VERSION: i64 = 1;
const MAX_JSON: usize = 4 * 1024 * 1024;
const MAX_DB: i64 = 64 * 1024 * 1024;
const MAX_RECORDS: i64 = 512;
const TABLE: &str = r#"CREATE TABLE intents (
 account TEXT NOT NULL CHECK(length(account) BETWEEN 1 AND 184 AND instr(account,char(0))=0),
 session INTEGER NOT NULL CHECK(session BETWEEN 0 AND 4294967295),
 operation BLOB NOT NULL CHECK(length(operation)=16 AND operation!=zeroblob(16)),
 lease BLOB NOT NULL CHECK(length(lease)=16 AND lease!=zeroblob(16)),
 revision BLOB NOT NULL CHECK(length(revision)=16 AND revision!=zeroblob(16)),
 document TEXT NOT NULL CHECK(length(CAST(document AS BLOB)) BETWEEN 1 AND 4194304),
 phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 3),
 instance BLOB CHECK(instance IS NULL OR (length(instance)=16 AND instance!=zeroblob(16))),
 nonce BLOB CHECK(nonce IS NULL OR (length(nonce)=16 AND nonce!=zeroblob(16))),
 CHECK((phase IN(0,3) AND instance IS NULL AND nonce IS NULL) OR
       (phase IN(1,2) AND instance IS NOT NULL AND nonce IS NOT NULL)),
 PRIMARY KEY(account,session,operation)
) STRICT, WITHOUT ROWID"#;
const INDEX: &str = "CREATE UNIQUE INDEX active_lease ON intents(lease) WHERE phase IN(0,1,2)";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Name {
    Debugger,
    FilterFullPath,
    UseFilter,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawValue {
    pub(crate) kind: u32,
    pub(crate) bytes: Vec<u8>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Change {
    pub(crate) name: Name,
    pub(crate) expected: Option<RawValue>,
    pub(crate) desired: Option<RawValue>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum KeyKind {
    Existing,
    NewLeaf,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyChange {
    pub(crate) path: String,
    pub(crate) kind: KeyKind,
    pub(crate) values: Vec<Change>,
}

/// IDs and image bytes are records, never authority supplied by an IPC client.
/// Registry root is fixed to the IFEO subtree by this schema version. Root
/// provisioning, native case/alias checks and foreign-filter policy remain the
/// resource owner's obligations; syntactic validation does not establish them.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    version: u32,
    operation: Uuid,
    lease: Uuid,
    revision: Uuid,
    account: String,
    session: u32,
    image: ImageSnapshot,
    view: RegistryView,
    keys: Vec<KeyChange>,
}
impl Intent {
    pub(crate) fn from_owner(
        caller: &Caller,
        operation: Uuid,
        lease: Uuid,
        revision: Uuid,
        image: ImageSnapshot,
        view: RegistryView,
        keys: Vec<KeyChange>,
    ) -> Result<Self, Error> {
        let intent = Self {
            version: 1,
            operation,
            lease,
            revision,
            account: caller.account().into(),
            session: caller.session(),
            image,
            view,
            keys,
        };
        intent.validate()?;
        Ok(intent)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.version != 1
            || [self.operation, self.lease, self.revision]
                .iter()
                .any(Uuid::is_nil)
            || self.account.is_empty()
            || self.account.len() > 184
            || !self.account.is_ascii()
            || !self.account.starts_with("S-1-")
            || self.account.contains('\0')
            || self.keys.is_empty()
            || self.keys.len() > 16
            || self.image.sha256.len() != 64
            || !self.image.sha256.bytes().all(|c| c.is_ascii_hexdigit())
            || self.image.size > crate::optimizer_identity::MAX_IMAGE_BYTES
            || [&self.image.requested_path, &self.image.final_path]
                .iter()
                .any(|p| {
                    p.as_os_str().is_empty() || p.as_os_str().as_encoded_bytes().len() > 131_068
                })
        {
            return Err(Error::InvalidIntent);
        }
        let mut bytes = 0;
        for (i, key) in self.keys.iter().enumerate() {
            if key.path.len() > 2041
                || key.path.split('\\').count() > 2
                || !key.path.split('\\').all(component)
                || (key.kind == KeyKind::NewLeaf && key.path.split('\\').count() != 2)
                || same_registry_path(&key.path, &key.path).is_none()
                || self.keys[..i]
                    .iter()
                    .any(|k| same_registry_path(&k.path, &key.path) != Some(false))
                || key.values.is_empty()
                || key.values.len() > 3
            {
                return Err(Error::InvalidIntent);
            }
            for (j, value) in key.values.iter().enumerate() {
                if value.expected == value.desired
                    || key.values[..j].iter().any(|v| v.name == value.name)
                    || (key.kind == KeyKind::NewLeaf && value.expected.is_some())
                {
                    return Err(Error::InvalidIntent);
                }
                for raw in [&value.expected, &value.desired].into_iter().flatten() {
                    if raw.bytes.len() > 65536 {
                        return Err(Error::InvalidIntent);
                    }
                    bytes += raw.bytes.len();
                    if bytes > 1048576 {
                        return Err(Error::InvalidIntent);
                    }
                }
            }
        }
        Ok(())
    }
    fn encode(&self) -> Result<String, Error> {
        self.validate()?;
        let json = serde_json::to_string(self).map_err(|_| Error::InvalidIntent)?;
        if json.len() > MAX_JSON {
            return Err(Error::InvalidIntent);
        }
        Ok(json)
    }
    fn decode(json: &str) -> Result<Self, Error> {
        if json.len() > MAX_JSON {
            return Err(Error::Corrupt);
        }
        let value: Self = serde_json::from_str(json).map_err(|_| Error::Corrupt)?;
        if value.encode().map_err(|_| Error::Corrupt)? != json {
            return Err(Error::Corrupt);
        }
        Ok(value)
    }
}
fn component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 1020
        && s != "."
        && s != ".."
        && !s.contains(['\\', '/', '\0'])
        && s.encode_utf16().count() <= 255
}

/// Windows ordinal registry-name comparison. Other hosts can validate ASCII
/// fixture names; they must not invent equivalence rules for Unicode names.
pub(crate) fn same_registry_path(a: &str, b: &str) -> Option<bool> {
    #[cfg(windows)]
    {
        use windows::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
        let a: Vec<u16> = a.encode_utf16().collect();
        let b: Vec<u16> = b.encode_utf16().collect();
        let result = unsafe { CompareStringOrdinal(&a, &b, true) };
        if result.0 == 0 {
            None
        } else {
            Some(result == CSTR_EQUAL)
        }
    }
    #[cfg(not(windows))]
    {
        if a.is_ascii() && b.is_ascii() {
            Some(a.eq_ignore_ascii_case(b))
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub(crate) enum Error {
    Sql(rusqlite::Error),
    InvalidIntent,
    UnsupportedDatabase,
    UnsupportedDurability,
    Corrupt,
    Conflict,
    BusyLease,
    Capacity,
    Stale,
}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Optimizer native intent: {self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Prepared,
    CommitStarted,
    Uncertain,
    Abandoned,
}
impl Phase {
    fn parse(n: i64) -> Result<Self, Error> {
        match n {
            0 => Ok(Self::Prepared),
            1 => Ok(Self::CommitStarted),
            2 => Ok(Self::Uncertain),
            3 => Ok(Self::Abandoned),
            _ => Err(Error::Corrupt),
        }
    }
}
#[derive(Debug)]
pub(crate) struct Record {
    pub(crate) intent: Intent,
    pub(crate) phase: Phase,
}
pub(crate) struct ReviewCursor {
    account: String,
    session: u32,
    operation: Uuid,
}
pub(crate) struct ReviewPage {
    pub(crate) records: Vec<Record>,
    pub(crate) next: Option<ReviewCursor>,
}
/// Not cloneable or deserializable. Returned only after intent COMMIT.
pub(crate) struct Prepared {
    intent: Intent,
    document: String,
}
pub(crate) enum Preparation {
    New(Prepared),
    Existing(Record),
}
/// Returned only after durable CommitStarted. Not an executable lease or helper
/// readiness proof; future native owner must match the EXACT staged plan.
pub(crate) struct CommitPermit {
    intent: Intent,
    document: String,
    instance: Uuid,
    nonce: Uuid,
}
impl CommitPermit {
    pub(crate) fn intent(&self) -> &Intent {
        &self.intent
    }
    pub(crate) fn matches_plan(&self, view: RegistryView, keys: &[KeyChange]) -> bool {
        self.intent.view == view && self.intent.keys == keys
    }
    pub(crate) fn into_attempt(self) -> AttemptReceipt {
        AttemptReceipt {
            intent: self.intent,
            document: self.document,
            instance: self.instance,
            nonce: self.nonce,
        }
    }
}
/// A consumed attempt's journal identity. It cannot become another commit
/// permit and asserts no native success; used only for uncertainty/reconciliation.
pub(crate) struct AttemptReceipt {
    intent: Intent,
    document: String,
    instance: Uuid,
    nonce: Uuid,
}

pub(crate) struct Journal {
    connection: Connection,
}
impl Journal {
    /// Owned file-backed protected service connection; no production factory.
    /// Unknown/corrupt/future databases are rejected without replacing bytes.
    /// SQLite's own hot-journal recovery is outside that preservation claim.
    pub(crate) fn open(mut connection: Connection) -> Result<Self, Error> {
        if !connection.is_autocommit() {
            return Err(Error::UnsupportedDatabase);
        }
        connection.busy_timeout(Duration::from_millis(250))?;
        connection.pragma_update(None, "trusted_schema", false)?;
        let file: String = connection.query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |r| r.get(0),
        )?;
        let attached: i64 = connection.query_row(
            "SELECT count(*) FROM pragma_database_list WHERE name NOT IN ('main','temp')",
            [],
            |r| r.get(0),
        )?;
        let temporary: i64 =
            connection.query_row("SELECT count(*) FROM sqlite_temp_schema", [], |r| r.get(0))?;
        if file.is_empty() || attached != 0 || temporary != 0 {
            return Err(Error::UnsupportedDatabase);
        }
        let fresh = header(&connection)?;
        integrity(&connection)?;
        if !fresh {
            validate_rows(&connection)?;
        }
        let mode: String = connection.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(Error::UnsupportedDurability);
        }
        connection.pragma_update(None, "synchronous", "EXTRA")?;
        let sync: i64 = connection.pragma_query_value(None, "synchronous", |r| r.get(0))?;
        if sync != 3 {
            return Err(Error::UnsupportedDurability);
        }
        let page: i64 = connection.pragma_query_value(None, "page_size", |r| r.get(0))?;
        if !(512..=65536).contains(&page) || (page & (page - 1)) != 0 {
            return Err(Error::Corrupt);
        }
        connection.pragma_update(None, "max_page_count", MAX_DB / page)?;
        let max_pages: i64 = connection.pragma_query_value(None, "max_page_count", |r| r.get(0))?;
        if max_pages != MAX_DB / page {
            return Err(Error::UnsupportedDurability);
        }
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if header(&tx)? {
            tx.execute_batch(TABLE)?;
            tx.execute_batch(INDEX)?;
            tx.pragma_update(None, "application_id", APP_ID)?;
            tx.pragma_update(None, "user_version", VERSION)?;
        }
        schema(&tx)?;
        integrity(&tx)?;
        validate_rows(&tx)?;
        tx.commit()?;
        Ok(Self { connection })
    }
    pub(crate) fn prepare(&mut self, intent: Intent) -> Result<Preparation, Error> {
        let document = intent.encode()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = if let Some(record) =
            lookup(&tx, &intent.account, intent.session, intent.operation)?
        {
            if record.intent.encode()? != document {
                return Err(Error::Conflict);
            }
            Preparation::Existing(record)
        } else {
            let count: i64 = tx.query_row("SELECT count(*) FROM intents", [], |r| r.get(0))?;
            if count >= MAX_RECORDS {
                return Err(Error::Capacity);
            }
            let active: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM intents WHERE lease=?1 AND phase IN(0,1,2))",
                [intent.lease.as_bytes().as_slice()],
                |r| r.get(0),
            )?;
            if active {
                return Err(Error::BusyLease);
            }
            tx.execute("INSERT INTO intents(account,session,operation,lease,revision,document,phase) VALUES(?1,?2,?3,?4,?5,?6,0)",
                params![intent.account,intent.session,intent.operation.as_bytes().as_slice(),intent.lease.as_bytes().as_slice(),intent.revision.as_bytes().as_slice(),document])?;
            Preparation::New(Prepared { intent, document })
        };
        tx.commit()?;
        Ok(result)
    }
    pub(crate) fn query(&self, caller: &Caller, operation: Uuid) -> Result<Option<Record>, Error> {
        if operation.is_nil() {
            return Err(Error::InvalidIntent);
        }
        lookup(
            &self.connection,
            caller.account(),
            caller.session(),
            operation,
        )
    }
    pub(crate) fn begin_commit(
        &mut self,
        prepared: Prepared,
        current_revision: Uuid,
        instance: Uuid,
    ) -> Result<CommitPermit, Error> {
        if instance.is_nil() || current_revision != prepared.intent.revision {
            return Err(Error::Stale);
        }
        let nonce = Uuid::new_v4();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let i = &prepared.intent;
        let count=tx.execute("UPDATE intents SET phase=1,instance=?1,nonce=?2 WHERE account=?3 AND session=?4 AND operation=?5 AND revision=?6 AND document=?7 AND lease=?8 AND phase=0",
            params![instance.as_bytes().as_slice(),nonce.as_bytes().as_slice(),i.account,i.session,i.operation.as_bytes().as_slice(),current_revision.as_bytes().as_slice(),prepared.document,i.lease.as_bytes().as_slice()])?;
        if count != 1 {
            return Err(Error::Stale);
        }
        tx.commit()?;
        Ok(CommitPermit {
            intent: prepared.intent,
            document: prepared.document,
            instance,
            nonce,
        })
    }
    pub(crate) fn abandon_prepared(&mut self, prepared: Prepared) -> Result<(), Error> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let i = &prepared.intent;
        let count=tx.execute("UPDATE intents SET phase=3 WHERE account=?1 AND session=?2 AND operation=?3 AND document=?4 AND lease=?5 AND revision=?6 AND phase=0",
            params![i.account,i.session,i.operation.as_bytes().as_slice(),prepared.document,i.lease.as_bytes().as_slice(),i.revision.as_bytes().as_slice()])?;
        if count != 1 {
            return Err(Error::Stale);
        }
        tx.commit()?;
        Ok(())
    }
    /// Explicit exact-plan CAS after review, including a lost Prepared ticket.
    /// An old ticket cannot start after this transition. CommitStarted/Uncertain
    /// never enter this path; their effects require separate reconciliation.
    pub(crate) fn abandon_reviewed_prepared(
        &mut self,
        caller: &Caller,
        reviewed: &Record,
    ) -> Result<(), Error> {
        let i = &reviewed.intent;
        if reviewed.phase != Phase::Prepared
            || caller.account() != i.account
            || caller.session() != i.session
        {
            return Err(Error::Stale);
        }
        let document = i.encode()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count=tx.execute("UPDATE intents SET phase=3 WHERE account=?1 AND session=?2 AND operation=?3 AND lease=?4 AND revision=?5 AND document=?6 AND phase=0",
            params![i.account,i.session,i.operation.as_bytes().as_slice(),i.lease.as_bytes().as_slice(),i.revision.as_bytes().as_slice(),document])?;
        if count != 1 {
            return Err(Error::Stale);
        }
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn mark_uncertain(&mut self, permit: AttemptReceipt) -> Result<(), Error> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let i = &permit.intent;
        let count=tx.execute("UPDATE intents SET phase=2 WHERE account=?1 AND session=?2 AND operation=?3 AND document=?4 AND instance=?5 AND nonce=?6 AND lease=?7 AND revision=?8 AND phase=1",
            params![i.account,i.session,i.operation.as_bytes().as_slice(),permit.document,permit.instance.as_bytes().as_slice(),permit.nonce.as_bytes().as_slice(),i.lease.as_bytes().as_slice(),i.revision.as_bytes().as_slice()])?;
        if count != 1 {
            return Err(Error::Stale);
        }
        tx.commit()?;
        Ok(())
    }
    /// Explicit review only. No recovery, permit creation, state transition or
    /// native retry occurs on reopen or listing. Includes uncertain operations.
    pub(crate) fn review_after(
        &self,
        caller: &Caller,
        limit: usize,
        cursor: Option<&ReviewCursor>,
    ) -> Result<ReviewPage, Error> {
        if cursor.is_some_and(|c| c.account != caller.account() || c.session != caller.session()) {
            return Err(Error::Stale);
        }
        self.review_matching(Some(caller), limit, cursor)
    }
    /// # Safety
    /// Only the privileged protected-storage/resource owner may enumerate all
    /// accounts. Never expose these records or cursors through user IPC/UI.
    pub(crate) unsafe fn review_all_service_after(
        &self,
        limit: usize,
        cursor: Option<&ReviewCursor>,
    ) -> Result<ReviewPage, Error> {
        self.review_matching(None, limit, cursor)
    }
    fn review_matching(
        &self,
        caller: Option<&Caller>,
        limit: usize,
        cursor: Option<&ReviewCursor>,
    ) -> Result<ReviewPage, Error> {
        if limit == 0 || limit > 64 {
            return Err(Error::InvalidIntent);
        }
        let mut statement=self.connection.prepare("SELECT account,session,operation,lease,revision,document,phase FROM intents WHERE phase!=3 AND (?1 OR (account,session,operation)>(?2,?3,?4)) AND (?6 OR (account=?7 AND session=?8)) ORDER BY account,session,operation LIMIT ?5")?;
        let nil = Uuid::nil();
        let rows = statement.query_map(
            params![
                cursor.is_none(),
                cursor.map_or("", |c| c.account.as_str()),
                cursor.map_or(0, |c| c.session),
                cursor.map_or(nil.as_bytes().as_slice(), |c| c
                    .operation
                    .as_bytes()
                    .as_slice()),
                limit as i64 + 1,
                caller.is_none(),
                caller.map_or("", |c| c.account()),
                caller.map_or(0, |c| c.session())
            ],
            stored_row,
        )?;
        let mut records = Vec::new();
        for row in rows {
            records.push(decode_row(row?)?);
        }
        let more = records.len() > limit;
        records.truncate(limit);
        let next = if more {
            records.last().map(|r| ReviewCursor {
                account: r.intent.account.clone(),
                session: r.intent.session,
                operation: r.intent.operation,
            })
        } else {
            None
        };
        Ok(ReviewPage { records, next })
    }
    #[cfg(test)]
    fn review(&self, limit: usize) -> Result<(Vec<Record>, bool), Error> {
        let page = unsafe { self.review_all_service_after(limit, None) }?;
        Ok((page.records, page.next.is_some()))
    }
}
fn lookup(
    c: &Connection,
    account: &str,
    session: u32,
    operation: Uuid,
) -> Result<Option<Record>, Error> {
    let row: Option<StoredRow> = c
        .query_row(
            "SELECT account,session,operation,lease,revision,document,phase FROM intents WHERE account=?1 AND session=?2 AND operation=?3",
            params![account, session, operation.as_bytes().as_slice()],
            stored_row,
        )
        .optional()?;
    row.map(decode_row).transpose()
}
type StoredRow = (String, u32, Vec<u8>, Vec<u8>, Vec<u8>, String, i64);
fn stored_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRow> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
    ))
}
fn decode_row(row: StoredRow) -> Result<Record, Error> {
    let (account, session, operation, lease, revision, document, phase) = row;
    let intent = Intent::decode(&document)?;
    if account != intent.account
        || session != intent.session
        || operation != intent.operation.as_bytes()
        || lease != intent.lease.as_bytes()
        || revision != intent.revision.as_bytes()
    {
        return Err(Error::Corrupt);
    }
    Ok(Record {
        intent,
        phase: Phase::parse(phase)?,
    })
}
fn header(c: &Connection) -> Result<bool, Error> {
    let app: i64 = c.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let count: i64 = c.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
    let pages: i64 = c.pragma_query_value(None, "page_count", |r| r.get(0))?;
    let size: i64 = c.pragma_query_value(None, "page_size", |r| r.get(0))?;
    if pages < 0 || size <= 0 || pages.checked_mul(size).is_none_or(|n| n > MAX_DB) {
        return Err(Error::Corrupt);
    }
    if app == 0 && version == 0 && count == 0 {
        return Ok(true);
    }
    if app != APP_ID || version != VERSION || count != 2 {
        return Err(Error::UnsupportedDatabase);
    }
    schema(c)?;
    Ok(false)
}
fn schema(c: &Connection) -> Result<(), Error> {
    for (kind, name, want) in [
        ("table", "intents", TABLE),
        ("index", "active_lease", INDEX),
    ] {
        let sql: Option<String> = c
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type=?1 AND name=?2",
                params![kind, name],
                |r| r.get(0),
            )
            .optional()?;
        if sql.as_deref() != Some(want) {
            return Err(Error::UnsupportedDatabase);
        }
    }
    Ok(())
}
fn integrity(c: &Connection) -> Result<(), Error> {
    let result: String = c.query_row("PRAGMA quick_check(1)", [], |r| r.get(0))?;
    if result != "ok" {
        Err(Error::Corrupt)
    } else {
        Ok(())
    }
}
fn validate_rows(c: &Connection) -> Result<(), Error> {
    let count: i64 = c.query_row("SELECT count(*) FROM intents", [], |r| r.get(0))?;
    if count > MAX_RECORDS {
        return Err(Error::Corrupt);
    }
    let mut statement =
        c.prepare("SELECT account,session,operation,lease,revision,document,phase FROM intents")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        decode_row(stored_row(row)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer_identity::{FileIdentity, PeFormat, PeHeader};
    use std::{
        path::Path,
        sync::{Arc, Barrier},
        thread,
    };

    fn owner() -> Caller {
        Caller::fixture("S-1-5-21-1-2-3-1001", 1)
    }
    fn open(path: &Path) -> Journal {
        Journal::open(Connection::open(path).unwrap()).unwrap()
    }
    fn image() -> ImageSnapshot {
        ImageSnapshot {
            requested_path: r"C:\Fixture\sample.exe".into(),
            final_path: r"\\?\C:\Fixture\sample.exe".into(),
            identity: FileIdentity {
                volume_serial: 31,
                file_id: [7; 16],
            },
            size: 4096,
            creation_time: 1,
            last_write_time: 2,
            attributes: 32,
            hard_links: 1,
            sha256: "a".repeat(64),
            pe: PeHeader {
                machine: 0x8664,
                format: PeFormat::Pe32Plus,
                characteristics: 0x22,
                subsystem: 2,
                sections: 1,
                entry_point_rva: 4096,
                image_size: 8192,
                headers_size: 512,
            },
            bytes_read: 4608,
        }
    }
    fn intent() -> Intent {
        Intent::from_owner(
            &owner(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            image(),
            RegistryView::Registry64,
            vec![
                KeyChange {
                    path: "sample.exe".into(),
                    kind: KeyKind::Existing,
                    values: vec![Change {
                        name: Name::UseFilter,
                        expected: None,
                        desired: Some(RawValue {
                            kind: 4,
                            bytes: 1u32.to_le_bytes().to_vec(),
                        }),
                    }],
                },
                KeyChange {
                    path: "sample.exe\\owned".into(),
                    kind: KeyKind::NewLeaf,
                    values: vec![Change {
                        name: Name::Debugger,
                        expected: None,
                        desired: Some(RawValue {
                            kind: 3,
                            bytes: vec![0, 255, 128, 0],
                        }),
                    }],
                },
            ],
        )
        .unwrap()
    }
    fn prepare(j: &mut Journal, i: Intent) -> Prepared {
        match j.prepare(i).unwrap() {
            Preparation::New(p) => p,
            _ => panic!("expected one new ticket"),
        }
    }
    fn phase(j: &Journal, i: &Intent) -> Phase {
        j.query(&owner(), i.operation).unwrap().unwrap().phase
    }

    #[test]
    fn exact_native_intent_survives_reopen_without_reissuing_a_ticket_or_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("native.db");
        let original = intent();
        let expected = original.encode().unwrap();
        let mut j = open(&path);
        drop(prepare(&mut j, original.clone()));
        drop(j);
        let mut j = open(&path);
        let record = j.query(&owner(), original.operation).unwrap().unwrap();
        assert_eq!(record.intent.encode().unwrap(), expected);
        assert_eq!(record.phase, Phase::Prepared);
        assert!(matches!(
            j.prepare(original),
            Ok(Preparation::Existing(Record {
                phase: Phase::Prepared,
                ..
            }))
        ));
        let (review, more) = j.review(64).unwrap();
        assert!(!more);
        assert_eq!(review.len(), 1);
        assert_eq!(review[0].intent.encode().unwrap(), expected);
        let sync: i64 = j
            .connection
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .unwrap();
        assert_eq!(sync, 3);
        let reviewed = j.query(&owner(), record.intent.operation).unwrap().unwrap();
        let wrong_owner = Caller::fixture(owner().account(), 2);
        assert!(matches!(
            j.abandon_reviewed_prepared(&wrong_owner, &reviewed),
            Err(Error::Stale)
        ));
        let stale = Prepared {
            document: reviewed.intent.encode().unwrap(),
            intent: reviewed.intent.clone(),
        };
        j.abandon_reviewed_prepared(&owner(), &reviewed).unwrap();
        assert_eq!(phase(&j, &reviewed.intent), Phase::Abandoned);
        assert!(matches!(
            j.begin_commit(stale, reviewed.intent.revision, Uuid::new_v4()),
            Err(Error::Stale)
        ));
    }

    #[test]
    fn changed_plan_and_foreign_owner_ids_never_replace_original_or_disclose_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = open(&dir.path().join("native.db"));
        let original = intent();
        drop(prepare(&mut j, original.clone()));
        for field in 0..3 {
            let mut changed = original.clone();
            match field {
                0 => changed.image.last_write_time += 1,
                1 => changed.revision = Uuid::new_v4(),
                _ => changed.keys[0].values[0].desired.as_mut().unwrap().bytes[0] = 2,
            }
            assert!(matches!(j.prepare(changed), Err(Error::Conflict)));
        }
        for other in [
            Caller::fixture(owner().account(), 2),
            Caller::fixture("S-1-5-21-1-2-3-1002", 1),
        ] {
            assert!(j.query(&other, original.operation).unwrap().is_none());
        }
        let mut hijack = original.clone();
        hijack.account = "S-1-5-21-1-2-3-1002".into();
        assert!(matches!(j.prepare(hijack), Err(Error::BusyLease)));
        assert_eq!(
            j.query(&owner(), original.operation)
                .unwrap()
                .unwrap()
                .intent
                .encode()
                .unwrap(),
            original.encode().unwrap()
        );
        let mut other = original.clone();
        other.operation = Uuid::new_v4();
        other.lease = Uuid::new_v4();
        other.account = "S-1-5-21-1-2-3-1002".into();
        drop(prepare(&mut j, other.clone()));
        let page = j.review_after(&owner(), 64, None).unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].intent.account, owner().account());
        let foreign = Caller::fixture(&other.account, other.session);
        let page = j.review_after(&foreign, 64, None).unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].intent.operation, other.operation);
        let fake_cursor = ReviewCursor {
            account: owner().account().into(),
            session: owner().session(),
            operation: original.operation,
        };
        assert!(matches!(
            j.review_after(&foreign, 64, Some(&fake_cursor)),
            Err(Error::Stale)
        ));
        assert_eq!(
            unsafe { j.review_all_service_after(64, None) }
                .unwrap()
                .records
                .len(),
            2
        );
    }

    #[test]
    fn stale_generation_and_abandonment_cannot_authorize_native_commit() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = open(&dir.path().join("native.db"));
        let i = intent();
        let p = prepare(&mut j, i.clone());
        assert!(matches!(
            j.begin_commit(p, Uuid::new_v4(), Uuid::new_v4()),
            Err(Error::Stale)
        ));
        assert_eq!(phase(&j, &i), Phase::Prepared);
        let mut second = intent();
        second.lease = i.lease;
        assert!(matches!(j.prepare(second), Err(Error::BusyLease)));
        // Only a genuinely retained Prepared token can abandon; listing cannot mint one.
        let p = Prepared {
            intent: i.clone(),
            document: i.encode().unwrap(),
        }; // adversarial stale-token fixture
        let duplicate = Prepared {
            intent: i.clone(),
            document: i.encode().unwrap(),
        };
        j.abandon_prepared(p).unwrap();
        assert_eq!(phase(&j, &i), Phase::Abandoned);
        assert!(matches!(
            j.begin_commit(duplicate, i.revision, Uuid::new_v4()),
            Err(Error::Stale)
        ));
        assert!(j.review(64).unwrap().0.is_empty());
        let mut next = intent();
        next.lease = i.lease;
        drop(prepare(&mut j, next));
    }

    #[test]
    fn commit_started_and_uncertain_rows_survive_reopen_without_retry_authority() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("native.db");
        let mut j = open(&path);
        let i = intent();
        let p = prepare(&mut j, i.clone());
        let permit = j.begin_commit(p, i.revision, Uuid::new_v4()).unwrap();
        assert_eq!(permit.intent().encode().unwrap(), i.encode().unwrap());
        assert_eq!(phase(&j, &i), Phase::CommitStarted);
        drop(j);
        let mut j = open(&path);
        assert_eq!(phase(&j, &i), Phase::CommitStarted);
        assert!(matches!(
            j.prepare(i.clone()),
            Ok(Preparation::Existing(Record {
                phase: Phase::CommitStarted,
                ..
            }))
        ));
        let stale = CommitPermit {
            intent: permit.intent.clone(),
            document: permit.document.clone(),
            instance: permit.instance,
            nonce: Uuid::new_v4(),
        };
        assert!(matches!(
            j.mark_uncertain(stale.into_attempt()),
            Err(Error::Stale)
        ));
        j.mark_uncertain(permit.into_attempt()).unwrap();
        assert_eq!(phase(&j, &i), Phase::Uncertain);
        drop(j);
        let mut j = open(&path);
        assert!(matches!(
            j.prepare(i.clone()),
            Ok(Preparation::Existing(Record {
                phase: Phase::Uncertain,
                ..
            }))
        ));
        assert_eq!(j.review(1).unwrap().0[0].phase, Phase::Uncertain);
        let mut later = intent();
        later.lease = i.lease;
        assert!(matches!(j.prepare(later), Err(Error::BusyLease)));
    }

    fn commit_fault(j: &Journal, operation: &str) {
        j.connection.execute_batch(&format!("PRAGMA foreign_keys=ON;
            CREATE TABLE fault_guard(id INTEGER PRIMARY KEY,required INTEGER REFERENCES fault_guard(id) DEFERRABLE INITIALLY DEFERRED);
            CREATE TEMP TRIGGER fail_commit AFTER {operation} ON main.intents
            BEGIN INSERT INTO fault_guard VALUES(1,999); END;")).unwrap();
    }
    fn clear_fault(j: &Journal) {
        j.connection
            .execute_batch("DROP TRIGGER fail_commit;DROP TABLE fault_guard")
            .unwrap();
    }

    #[test]
    fn statement_and_commit_failures_never_escape_as_prepared_or_commit_permits() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = open(&dir.path().join("native.db"));
        let i = intent();
        j.connection.execute_batch("CREATE TEMP TRIGGER fail_insert BEFORE INSERT ON main.intents BEGIN SELECT RAISE(ABORT,'fixture denial'); END").unwrap();
        assert!(matches!(j.prepare(i.clone()), Err(Error::Sql(_))));
        assert!(j.query(&owner(), i.operation).unwrap().is_none());
        j.connection
            .execute_batch("DROP TRIGGER fail_insert")
            .unwrap();
        commit_fault(&j, "INSERT");
        assert!(matches!(j.prepare(i.clone()), Err(Error::Sql(_))));
        assert!(j.query(&owner(), i.operation).unwrap().is_none());
        clear_fault(&j);
        let p = prepare(&mut j, i.clone());
        commit_fault(&j, "UPDATE OF phase");
        assert!(matches!(
            j.begin_commit(p, i.revision, Uuid::new_v4()),
            Err(Error::Sql(_))
        ));
        assert_eq!(phase(&j, &i), Phase::Prepared);
        clear_fault(&j);
        let p = Prepared {
            intent: i.clone(),
            document: i.encode().unwrap(),
        };
        let permit = j.begin_commit(p, i.revision, Uuid::new_v4()).unwrap();
        commit_fault(&j, "UPDATE OF phase");
        assert!(matches!(
            j.mark_uncertain(permit.into_attempt()),
            Err(Error::Sql(_))
        ));
        assert_eq!(phase(&j, &i), Phase::CommitStarted);
        clear_fault(&j);
    }

    #[test]
    fn concurrent_exact_preparation_emits_only_one_post_commit_ticket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("native.db");
        drop(open(&path));
        let i = intent();
        let barrier = Arc::new(Barrier::new(4));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let path = path.clone();
                let i = i.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    let mut j = open(&path);
                    barrier.wait();
                    matches!(j.prepare(i).unwrap(), Preparation::New(_))
                })
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .filter(|new| *new)
                .count(),
            1
        );
        let j = open(&path);
        assert_eq!(j.review(64).unwrap().0.len(), 1);
    }

    #[test]
    fn unknown_future_corrupt_and_noncanonical_documents_are_preserved() {
        let dir = tempfile::tempdir().unwrap();
        for (index, setup) in [
            "CREATE TABLE unrelated(value TEXT)",
            "PRAGMA application_id=1145262665;PRAGMA user_version=99",
            "CREATE TABLE sqliteXunexpected(value TEXT)",
        ]
        .into_iter()
        .enumerate()
        {
            let path = dir.path().join(format!("foreign{index}.db"));
            let c = Connection::open(&path).unwrap();
            c.execute_batch(setup).unwrap();
            drop(c);
            let before = std::fs::read(&path).unwrap();
            assert!(Journal::open(Connection::open(&path).unwrap()).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
        for (index, corruption) in [
            "UPDATE intents SET document='{}'",
            "UPDATE intents SET document=document||' '",
            "UPDATE intents SET revision=randomblob(16)",
            "PRAGMA ignore_check_constraints=ON;UPDATE intents SET phase=99",
        ]
        .into_iter()
        .enumerate()
        {
            let path = dir.path().join(format!("corrupt{index}.db"));
            let mut j = open(&path);
            drop(prepare(&mut j, intent()));
            j.connection.execute_batch(corruption).unwrap();
            drop(j);
            let before = std::fs::read(&path).unwrap();
            assert!(Journal::open(Connection::open(&path).unwrap()).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
        let path = dir.path().join("broken.db");
        std::fs::write(&path, b"not a sqlite file").unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(Journal::open(Connection::open(&path).unwrap()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(matches!(
            Journal::open(Connection::open_in_memory().unwrap()),
            Err(Error::UnsupportedDatabase)
        ));
    }

    #[test]
    fn attached_temp_wal_and_busy_or_readonly_connections_do_not_admit_work() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("native.db");
        drop(open(&path));
        for setup in [
            "CREATE TEMP TABLE other(value TEXT)",
            "ATTACH ':memory:' AS other",
        ] {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(setup).unwrap();
            assert!(matches!(Journal::open(c), Err(Error::UnsupportedDatabase)));
        }
        let c = Connection::open(&path).unwrap();
        c.execute_batch("PRAGMA journal_mode=WAL").unwrap();
        drop(c);
        assert!(matches!(
            Journal::open(Connection::open(&path).unwrap()),
            Err(Error::UnsupportedDurability)
        ));
        let c = Connection::open(&path).unwrap();
        assert_eq!(
            c.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        c.execute_batch("PRAGMA journal_mode=DELETE").unwrap();
        drop(c);
        let mut j = open(&path);
        let lock = Connection::open(&path).unwrap();
        lock.execute_batch("BEGIN IMMEDIATE").unwrap();
        let i = intent();
        assert!(matches!(j.prepare(i.clone()), Err(Error::Sql(_))));
        lock.execute_batch("ROLLBACK").unwrap();
        assert!(j.query(&owner(), i.operation).unwrap().is_none());
        drop(j);
        let mut readonly = Journal::open(
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap(),
        )
        .unwrap();
        assert!(matches!(readonly.prepare(i.clone()), Err(Error::Sql(_))));
        assert!(readonly.query(&owner(), i.operation).unwrap().is_none());
    }

    #[test]
    fn malformed_and_over_budget_intents_are_rejected_before_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = open(&dir.path().join("native.db"));
        let mut cases = Vec::new();
        let base = intent();
        let mut i = base.clone();
        i.operation = Uuid::nil();
        cases.push(i);
        let mut i = base.clone();
        i.version = 2;
        cases.push(i);
        let mut i = base.clone();
        i.keys[0].path = "..\\bad".into();
        cases.push(i);
        let mut i = base.clone();
        i.keys[1].path = "missing_parent".into();
        cases.push(i);
        let mut i = base.clone();
        i.keys[1].values[0].expected = Some(RawValue {
            kind: 0,
            bytes: vec![],
        });
        cases.push(i);
        let mut i = base.clone();
        i.keys[0].values[0].desired = None;
        cases.push(i);
        let mut i = base.clone();
        i.keys[0].values[0].desired.as_mut().unwrap().bytes = vec![0; 65537];
        cases.push(i);
        let mut i = base.clone();
        i.keys = vec![i.keys[0].clone(); 17];
        cases.push(i);
        let mut i = base.clone();
        i.image.sha256 = "z".repeat(64);
        cases.push(i);
        let mut i = base.clone();
        let duplicate = i.keys[0].values[0].clone();
        i.keys[0].values.push(duplicate);
        cases.push(i);
        for alias in ["SAMPLE.EXE", "Sample.Exe"] {
            let mut i = base.clone();
            let mut duplicate = i.keys[0].clone();
            duplicate.path = alias.into();
            i.keys.push(duplicate);
            cases.push(i);
        }
        let mut i = base.clone();
        let mut duplicate = i.keys[1].clone();
        duplicate.path = "SAMPLE.EXE\\OWNED".into();
        i.keys.push(duplicate);
        cases.push(i);
        #[cfg(windows)]
        {
            let mut i = base.clone();
            i.keys[0].path = "é.exe".into();
            let mut duplicate = i.keys[0].clone();
            duplicate.path = "É.exe".into();
            i.keys.push(duplicate);
            cases.push(i);
        }
        #[cfg(not(windows))]
        {
            let mut i = base.clone();
            i.keys[0].path = "é.exe".into();
            cases.push(i);
        }
        for i in cases {
            assert!(matches!(j.prepare(i), Err(Error::InvalidIntent)));
        }
        assert!(j.review(64).unwrap().0.is_empty());
        assert!(j.review(0).is_err());
        assert!(j.review(65).is_err());
    }

    #[test]
    fn review_and_capacity_are_bounded_without_pruning_unresolved_intents() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = open(&dir.path().join("native.db"));
        let first = intent();
        drop(prepare(&mut j, first.clone()));
        for _ in 1..MAX_RECORDS {
            drop(prepare(&mut j, intent()));
        }
        let (rows, more) = j.review(64).unwrap();
        assert_eq!(rows.len(), 64);
        assert!(more);
        let mut cursor = None;
        let mut seen = std::collections::HashSet::new();
        loop {
            let page = j.review_after(&owner(), 17, cursor.as_ref()).unwrap();
            assert!(page.records.len() <= 17);
            for record in page.records {
                assert!(seen.insert(record.intent.operation));
            }
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(seen.len(), MAX_RECORDS as usize);
        assert!(matches!(j.prepare(intent()), Err(Error::Capacity)));
        assert!(matches!(j.prepare(first), Ok(Preparation::Existing(_))));
        let page: i64 = j
            .connection
            .pragma_query_value(None, "page_size", |r| r.get(0))
            .unwrap();
        let max: i64 = j
            .connection
            .pragma_query_value(None, "max_page_count", |r| r.get(0))
            .unwrap();
        assert_eq!(page * max, MAX_DB);
    }

    #[test]
    fn live_column_changes_are_rejected_by_queries_review_and_commit_cas() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = open(&dir.path().join("native.db"));
        let i = intent();
        let p = prepare(&mut j, i.clone());
        j.connection
            .execute(
                "UPDATE intents SET lease=?1",
                [Uuid::new_v4().as_bytes().as_slice()],
            )
            .unwrap();
        assert!(matches!(
            j.query(&owner(), i.operation),
            Err(Error::Corrupt)
        ));
        assert!(matches!(
            j.review_after(&owner(), 1, None),
            Err(Error::Corrupt)
        ));
        assert!(matches!(
            j.begin_commit(p, i.revision, Uuid::new_v4()),
            Err(Error::Stale)
        ));
        j.connection
            .execute(
                "UPDATE intents SET lease=?1",
                [i.lease.as_bytes().as_slice()],
            )
            .unwrap();
        let reviewed = j.query(&owner(), i.operation).unwrap().unwrap();
        j.connection
            .execute(
                "UPDATE intents SET revision=?1",
                [Uuid::new_v4().as_bytes().as_slice()],
            )
            .unwrap();
        assert!(matches!(
            j.abandon_reviewed_prepared(&owner(), &reviewed),
            Err(Error::Stale)
        ));
    }
}
