//! Durable local account bindings and cloud-effect journal.
//!
//! This module stores no credentials and performs no provider requests or
//! effects. Callers reserve a unique review/item/action key before attempting
//! an effect, then record a terminal observation with a compare-and-set.
//! Opening a store never replays or rewrites interrupted operations.

use crate::cloud_inventory::{AccountScope, Provider};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Row, TransactionBehavior, params, types::Type,
};
use serde_json::Value;
use std::{
    fmt,
    fs::{self, Metadata},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const DATABASE_NAME: &str = "cloud-store.sqlite3";
const APPLICATION_ID: i64 = 0x4443_4353;
const SCHEMA_VERSION: i64 = 1;
const MAX_DATABASE_BYTES: i64 = 64 * 1024 * 1024;
const MAX_ACCOUNTS: i64 = 128;
const MAX_OPERATIONS: i64 = 100_000;
const MAX_PAGE_SIZE: usize = 200;
const MAX_CLIENT_ID_BYTES: usize = 512;
const MAX_LABEL_BYTES: usize = 512;
const MAX_REMOTE_ID_BYTES: usize = 512;
const MAX_NAME_BYTES: usize = 4_096;
const MAX_REVISION_BYTES: usize = 512;
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_METADATA_NODES: usize = 10_000;
const MAX_METADATA_DEPTH: usize = 32;
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

const SCHEMA: &str = r#"
CREATE TABLE accounts (
    id BLOB PRIMARY KEY CHECK(length(id)=16 AND id!=zeroblob(16)),
    provider INTEGER NOT NULL CHECK(provider BETWEEN 0 AND 3),
    subject_id TEXT NOT NULL CHECK(length(CAST(subject_id AS BLOB)) BETWEEN 1 AND 512),
    storage_id TEXT CHECK(storage_id IS NULL OR length(CAST(storage_id AS BLOB)) BETWEEN 1 AND 512),
    client_id TEXT NOT NULL CHECK(length(CAST(client_id AS BLOB)) BETWEEN 1 AND 512),
    label TEXT NOT NULL CHECK(length(CAST(label AS BLOB)) BETWEEN 1 AND 512),
    generation BLOB NOT NULL CHECK(length(generation)=16 AND generation!=zeroblob(16)),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    created_at INTEGER NOT NULL CHECK(created_at>=0),
    updated_at INTEGER NOT NULL CHECK(updated_at>=0)
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX account_exact_scope ON accounts(
    provider, subject_id, COALESCE(storage_id, '')
);
CREATE TABLE operations (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL UNIQUE CHECK(length(id)=16 AND id!=zeroblob(16)),
    account_id BLOB NOT NULL CHECK(length(account_id)=16 AND account_id!=zeroblob(16)),
    account_generation BLOB NOT NULL CHECK(length(account_generation)=16 AND account_generation!=zeroblob(16)),
    action INTEGER NOT NULL CHECK(action IN (0, 1)),
    review_key BLOB NOT NULL CHECK(length(review_key)=16 AND review_key!=zeroblob(16)),
    item_key BLOB NOT NULL CHECK(length(item_key)=16 AND item_key!=zeroblob(16)),
    remote_id TEXT NOT NULL CHECK(length(CAST(remote_id AS BLOB)) BETWEEN 1 AND 512),
    name TEXT NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 4096),
    revision TEXT CHECK(revision IS NULL OR length(CAST(revision AS BLOB)) BETWEEN 1 AND 512),
    metadata TEXT NOT NULL CHECK(length(CAST(metadata AS BLOB)) BETWEEN 2 AND 65536),
    state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 3),
    status_code INTEGER CHECK(status_code IS NULL OR status_code BETWEEN 1 AND 12),
    created_at INTEGER NOT NULL CHECK(created_at>=0),
    CHECK(state!=0 OR status_code IS NULL),
    UNIQUE(account_id, action, review_key, item_key)
) STRICT;
CREATE INDEX operations_account_sequence ON operations(account_id, seq DESC);
CREATE INDEX operations_restore_review ON operations(account_id,review_key) WHERE action=1;
"#;

/// Failures are intentionally coarse so database paths, query contents and
/// provider metadata are not copied into diagnostics by default.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum StoreError {
    Database,
    UnsafePath,
    UnsupportedDatabase,
    CorruptDatabase,
    InvalidInput,
    AccountScopeConflict,
    AccountGenerationChanged,
    UnknownAccount,
    DuplicateReservation,
    InvalidTransition,
    InvalidCursor,
    InvalidPageLimit,
    Capacity,
}

impl StoreError {
    const fn message(self) -> &'static str {
        match self {
            Self::Database => "Cloud account storage could not be read or written.",
            Self::UnsafePath => "Cloud account storage path is linked or unsafe.",
            Self::UnsupportedDatabase => "Cloud account storage has an unsupported format.",
            Self::CorruptDatabase => "Cloud account storage failed integrity checks.",
            Self::InvalidInput => "Cloud account or journal input is invalid.",
            Self::AccountScopeConflict => "An account ID or exact provider scope is already bound.",
            Self::AccountGenerationChanged => {
                "The cloud account binding changed since this operation was reviewed."
            }
            Self::UnknownAccount => "The cloud account is no longer connected.",
            Self::DuplicateReservation => "This item action was already reserved for this review.",
            Self::InvalidTransition => "The journal operation is no longer in the Started state.",
            Self::InvalidCursor => "The operation history cursor is invalid for this page.",
            Self::InvalidPageLimit => {
                "The operation history page limit is outside the allowed range."
            }
            Self::Capacity => "Cloud account storage reached its safe capacity limit.",
        }
    }
}

impl fmt::Debug for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Database => "StoreError::Database",
            Self::UnsafePath => "StoreError::UnsafePath",
            Self::UnsupportedDatabase => "StoreError::UnsupportedDatabase",
            Self::CorruptDatabase => "StoreError::CorruptDatabase",
            Self::InvalidInput => "StoreError::InvalidInput",
            Self::AccountScopeConflict => "StoreError::AccountScopeConflict",
            Self::AccountGenerationChanged => "StoreError::AccountGenerationChanged",
            Self::UnknownAccount => "StoreError::UnknownAccount",
            Self::DuplicateReservation => "StoreError::DuplicateReservation",
            Self::InvalidTransition => "StoreError::InvalidTransition",
            Self::InvalidCursor => "StoreError::InvalidCursor",
            Self::InvalidPageLimit => "StoreError::InvalidPageLimit",
            Self::Capacity => "StoreError::Capacity",
        })
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}
impl std::error::Error for StoreError {}

/// New account binding. Scope identity cannot be changed after its UUID is
/// created; callers use a fresh UUID for a different provider account.
pub struct AccountInput {
    pub id: Uuid,
    pub scope: AccountScope,
    pub client_id: String,
    pub label: String,
}

/// Persisted account binding with a new generation on every accepted upsert.
#[derive(Clone, Eq, PartialEq)]
pub struct AccountRecord {
    id: Uuid,
    scope: AccountScope,
    client_id: String,
    label: String,
    generation: Uuid,
}

impl AccountRecord {
    pub const fn id(&self) -> Uuid {
        self.id
    }
    pub fn scope(&self) -> &AccountScope {
        &self.scope
    }
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn label(&self) -> &str {
        &self.label
    }
    pub const fn generation(&self) -> Uuid {
        self.generation
    }
}

impl fmt::Debug for AccountRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountRecord")
            .field("id", &"[redacted]")
            .field("scope", &self.scope)
            .field("client_id", &"[redacted]")
            .field("label", &"[redacted]")
            .field("generation", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudAction {
    Trash,
    Restore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationState {
    Started,
    Confirmed,
    Failed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalState {
    Confirmed,
    Failed,
    Uncertain,
}

/// Closed local status vocabulary; arbitrary provider messages are not stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum OperationStatusCode {
    Interrupted = 1,
    ProviderConflict = 2,
    ProviderNotFound = 3,
    AuthenticationRequired = 4,
    PermissionDenied = 5,
    RateLimited = 6,
    TemporarilyUnavailable = 7,
    InvalidResponse = 8,
    Cancelled = 9,
    Other = 10,
    AlreadySatisfied = 11,
    AccountChanged = 12,
}

/// Input captured from an exact reviewed row. `metadata` is bounded JSON
/// restore context, never an access token or arbitrary provider response.
pub struct OperationInput {
    pub account_id: Uuid,
    pub action: CloudAction,
    pub review_key: Uuid,
    pub item_key: Uuid,
    pub remote_id: String,
    pub name: String,
    pub revision: Option<String>,
    pub metadata: String,
}

/// Durable journal row. Raw identifiers and metadata are available only through
/// explicit getters and are never included in its `Debug` output.
#[derive(Clone, Eq, PartialEq)]
pub struct OperationRecord {
    id: Uuid,
    account_id: Uuid,
    account_generation: Uuid,
    action: CloudAction,
    review_key: Uuid,
    item_key: Uuid,
    remote_id: String,
    name: String,
    revision: Option<String>,
    metadata: String,
    state: OperationState,
    status_code: Option<OperationStatusCode>,
    created_at_unix_seconds: i64,
}

impl OperationRecord {
    pub const fn id(&self) -> Uuid {
        self.id
    }
    pub const fn account_id(&self) -> Uuid {
        self.account_id
    }
    pub const fn account_generation(&self) -> Uuid {
        self.account_generation
    }
    pub const fn action(&self) -> CloudAction {
        self.action
    }
    pub const fn review_key(&self) -> Uuid {
        self.review_key
    }
    pub const fn item_key(&self) -> Uuid {
        self.item_key
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn remote_id(&self) -> &str {
        &self.remote_id
    }
    pub fn revision(&self) -> Option<&str> {
        self.revision.as_deref()
    }
    pub fn metadata(&self) -> &str {
        &self.metadata
    }
    pub const fn state(&self) -> OperationState {
        self.state
    }
    pub const fn status_code(&self) -> Option<OperationStatusCode> {
        self.status_code
    }
    pub const fn created_at_unix_seconds(&self) -> i64 {
        self.created_at_unix_seconds
    }
}

impl fmt::Debug for OperationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperationRecord")
            .field("id", &"[redacted]")
            .field("account_id", &"[redacted]")
            .field("action", &self.action)
            .field("review_key", &"[redacted]")
            .field("item_key", &"[redacted]")
            .field("remote_id", &"[redacted]")
            .field("name", &"[redacted]")
            .field("revision", &self.revision.as_ref().map(|_| "[redacted]"))
            .field("metadata", &"[redacted]")
            .field("state", &self.state)
            .field("status_code", &self.status_code)
            .field("created_at_unix_seconds", &self.created_at_unix_seconds)
            .finish()
    }
}

pub struct OperationPage {
    pub records: Vec<OperationRecord>,
    pub next_cursor: Option<Uuid>,
}

impl OperationPage {
    pub fn records(&self) -> &[OperationRecord] {
        &self.records
    }
    pub fn into_records(self) -> Vec<OperationRecord> {
        self.records
    }
    pub const fn next_cursor(&self) -> Option<Uuid> {
        self.next_cursor
    }
}

/// A single-connection SQLite store. It deliberately has no automatic recovery
/// behavior; the owning service must establish that an older worker stopped
/// before explicitly converting its remaining `Started` rows to `Uncertain`.
pub struct CloudStore {
    connection: Connection,
}

impl CloudStore {
    /// Open the fixed local database below a non-linked data directory.
    /// SQLite durability is configured and read back as `synchronous=FULL`.
    pub fn open(data_dir: &Path) -> Result<Self, StoreError> {
        let root = ensure_safe_directory(data_dir)?;
        let path = root.join(DATABASE_NAME);
        inspect_database_path(&path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection =
            Connection::open_with_flags(&path, flags).map_err(|_| StoreError::Database)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|_| StoreError::Database)?;
        inspect_database_path(&path)?;
        let canonical_file = dunce::canonicalize(&path).map_err(|_| StoreError::UnsafePath)?;
        if !same_path(
            canonical_file.parent().ok_or(StoreError::UnsafePath)?,
            &root,
        ) {
            return Err(StoreError::UnsafePath);
        }

        verify_connection_is_file_backed(&connection)?;
        let header = database_header(&connection)?;
        verify_integrity(&connection)?;
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(|_| StoreError::Database)?;
        if !journal_mode.eq_ignore_ascii_case("delete") {
            return Err(StoreError::UnsupportedDatabase);
        }

        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;",
            )
            .map_err(|_| StoreError::Database)?;
        let synchronous: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .map_err(|_| StoreError::Database)?;
        let foreign_keys: i64 = connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .map_err(|_| StoreError::Database)?;
        if synchronous != 2 || foreign_keys != 1 {
            return Err(StoreError::UnsupportedDatabase);
        }

        match header {
            DatabaseHeader::Fresh => initialize_schema(&mut connection)?,
            DatabaseHeader::Current => validate_schema(&connection)?,
            DatabaseHeader::Unsupported => return Err(StoreError::UnsupportedDatabase),
        }

        let page_size: i64 = connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .map_err(|_| StoreError::Database)?;
        if page_size <= 0 {
            return Err(StoreError::CorruptDatabase);
        }
        let max_pages = MAX_DATABASE_BYTES / page_size;
        connection
            .pragma_update(None, "max_page_count", max_pages)
            .map_err(|_| StoreError::Database)?;
        let page_count: i64 = connection
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .map_err(|_| StoreError::Database)?;
        if page_count > max_pages {
            return Err(StoreError::Capacity);
        }
        validate_schema(&connection)?;
        verify_integrity(&connection)?;
        inspect_database_path(&path)?;
        Ok(Self { connection })
    }

    pub fn accounts(&self) -> Result<Vec<AccountRecord>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id,provider,subject_id,storage_id,client_id,label,generation \
                 FROM accounts WHERE active=1 ORDER BY updated_at DESC,id",
            )
            .map_err(|_| StoreError::Database)?;
        let rows = statement
            .query_map([], account_from_row)
            .map_err(|_| StoreError::Database)?;
        let mut accounts = Vec::new();
        for row in rows {
            if accounts.len() >= MAX_ACCOUNTS as usize {
                return Err(StoreError::CorruptDatabase);
            }
            accounts.push(row.map_err(|_| StoreError::CorruptDatabase)?);
        }
        Ok(accounts)
    }

    /// Find a previously known exact account scope, including disconnected
    /// identities, so reconnect can retain its local UUID and journal history.
    pub fn known_account_for_scope(
        &self,
        scope: &AccountScope,
    ) -> Result<Option<AccountRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id,provider,subject_id,storage_id,client_id,label,generation \
                 FROM accounts WHERE provider=?1 AND subject_id=?2 \
                 AND COALESCE(storage_id,'')=COALESCE(?3,'')",
                params![
                    provider_code(scope.provider()),
                    scope.subject_id(),
                    scope.storage_id(),
                ],
                account_from_row,
            )
            .optional()
            .map_err(|_| StoreError::CorruptDatabase)
    }

    /// Insert a new exact scope or refresh an existing record with the same ID
    /// and unchanged scope. Every accepted upsert creates a fresh generation.
    pub fn upsert_account(&mut self, input: AccountInput) -> Result<AccountRecord, StoreError> {
        if input.id.is_nil()
            || !valid_text(&input.client_id, MAX_CLIENT_ID_BYTES)
            || !valid_text(&input.label, MAX_LABEL_BYTES)
        {
            return Err(StoreError::InvalidInput);
        }
        let now = unix_seconds()?;
        let generation = Uuid::new_v4();
        let id_blob = uuid_blob(input.id);
        let generation_blob = uuid_blob(generation);
        let provider = provider_code(input.scope.provider());
        let subject_id = input.scope.subject_id();
        let storage_id = input.scope.storage_id();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Database)?;

        let existing = tx
            .query_row(
                "SELECT provider,subject_id,storage_id FROM accounts WHERE id=?1",
                [&id_blob],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| StoreError::Database)?;

        if let Some((existing_provider, existing_subject, existing_storage)) = existing {
            let existing_scope =
                decode_scope(existing_provider, existing_subject, existing_storage)?;
            if existing_scope != input.scope {
                return Err(StoreError::AccountScopeConflict);
            }
            tx.execute(
                "UPDATE accounts SET client_id=?1,label=?2,generation=?3,active=1,updated_at=?4 WHERE id=?5",
                params![
                    input.client_id,
                    input.label,
                    &generation_blob,
                    now,
                    &id_blob
                ],
            )
            .map_err(|_| StoreError::Database)?;
        } else {
            let duplicate_scope: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM accounts WHERE provider=?1 AND subject_id=?2 \
                     AND COALESCE(storage_id,'')=COALESCE(?3,'') LIMIT 1",
                    params![provider, subject_id, storage_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| StoreError::Database)?;
            if duplicate_scope.is_some() {
                return Err(StoreError::AccountScopeConflict);
            }
            let count: i64 = tx
                .query_row("SELECT count(*) FROM accounts", [], |row| row.get(0))
                .map_err(|_| StoreError::Database)?;
            if count >= MAX_ACCOUNTS {
                return Err(StoreError::Capacity);
            }
            tx.execute(
                "INSERT INTO accounts(id,provider,subject_id,storage_id,client_id,label,generation,active,created_at,updated_at) \
                 VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8,?8)",
                params![
                    &id_blob,
                    provider,
                    subject_id,
                    storage_id,
                    input.client_id,
                    input.label,
                    &generation_blob,
                    now,
                ],
            )
            .map_err(|_| StoreError::Database)?;
        }
        tx.commit().map_err(|_| StoreError::Database)?;
        Ok(AccountRecord {
            id: input.id,
            scope: input.scope,
            client_id: input.client_id,
            label: input.label,
            generation,
        })
    }

    /// Disconnect the active account while retaining its exact identity and
    /// operation history for a later reconnect.
    pub fn remove_account(&mut self, id: Uuid) -> Result<(), StoreError> {
        if id.is_nil() {
            return Err(StoreError::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Database)?;
        let changed = tx
            .execute(
                "UPDATE accounts SET active=0,updated_at=?1 WHERE id=?2 AND active=1",
                params![unix_seconds()?, uuid_blob(id)],
            )
            .map_err(|_| StoreError::Database)?;
        if changed != 1 {
            return Err(StoreError::UnknownAccount);
        }
        tx.commit().map_err(|_| StoreError::Database)
    }

    /// Disconnect only the currently active generation supplied by the caller.
    /// This prevents a stale UI command from deactivating a reconnected account.
    pub fn deactivate_account_for_generation(
        &mut self,
        id: Uuid,
        generation: Uuid,
    ) -> Result<(), StoreError> {
        if id.is_nil() || generation.is_nil() {
            return Err(StoreError::InvalidInput);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Database)?;
        let current: Option<(Vec<u8>, i64)> = tx
            .query_row(
                "SELECT generation,active FROM accounts WHERE id=?1",
                [uuid_blob(id)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| StoreError::Database)?;
        let Some((current_generation, active)) = current else {
            return Err(StoreError::UnknownAccount);
        };
        if active != 1 || parse_uuid(&current_generation) != Some(generation) {
            return Err(StoreError::AccountGenerationChanged);
        }
        let changed = tx
            .execute(
                "UPDATE accounts SET active=0,updated_at=?1 \
                 WHERE id=?2 AND active=1 AND generation=?3",
                params![unix_seconds()?, uuid_blob(id), uuid_blob(generation)],
            )
            .map_err(|_| StoreError::Database)?;
        if changed != 1 {
            return Err(StoreError::AccountGenerationChanged);
        }
        tx.commit().map_err(|_| StoreError::Database)
    }

    /// Reserve one exact reviewed item before the caller attempts any effect.
    /// The active account generation is copied into the immutable journal row.
    pub fn reserve_operation(
        &mut self,
        input: OperationInput,
    ) -> Result<OperationRecord, StoreError> {
        self.reserve_operation_inner(input, None)
    }

    /// Reserve only if the account binding still has the generation captured
    /// when the caller prepared the reviewed operation. The comparison occurs
    /// inside the same immediate transaction as the journal insert.
    pub fn reserve_operation_for_generation(
        &mut self,
        input: OperationInput,
        expected_generation: Uuid,
    ) -> Result<OperationRecord, StoreError> {
        if expected_generation.is_nil() {
            return Err(StoreError::InvalidInput);
        }
        self.reserve_operation_inner(input, Some(expected_generation))
    }

    fn reserve_operation_inner(
        &mut self,
        input: OperationInput,
        expected_generation: Option<Uuid>,
    ) -> Result<OperationRecord, StoreError> {
        let metadata = validate_operation_input(&input)?;
        let now = unix_seconds()?;
        let id = Uuid::new_v4();
        let account_blob = uuid_blob(input.account_id);
        let id_blob = uuid_blob(id);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Database)?;
        let generation_blob: Option<Vec<u8>> = tx
            .query_row(
                "SELECT generation FROM accounts WHERE id=?1 AND active=1",
                [&account_blob],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StoreError::Database)?;
        let Some(generation_blob) = generation_blob else {
            return Err(StoreError::UnknownAccount);
        };
        let account_generation = parse_uuid(&generation_blob).ok_or(StoreError::CorruptDatabase)?;
        if expected_generation.is_some_and(|expected| expected != account_generation) {
            return Err(StoreError::AccountGenerationChanged);
        }
        let duplicate: Option<i64> = match input.action {
            CloudAction::Trash => tx
                .query_row(
                    "SELECT 1 FROM operations WHERE account_id=?1 AND action=?2 \
                     AND review_key=?3 AND item_key=?4 LIMIT 1",
                    params![
                        &account_blob,
                        action_code(input.action),
                        uuid_blob(input.review_key),
                        uuid_blob(input.item_key),
                    ],
                    |row| row.get(0),
                )
                .optional(),
            CloudAction::Restore => tx
                .query_row(
                    "SELECT 1 FROM operations WHERE account_id=?1 AND action=1 \
                     AND review_key=?2 LIMIT 1",
                    params![&account_blob, uuid_blob(input.review_key)],
                    |row| row.get(0),
                )
                .optional(),
        }
        .map_err(|_| StoreError::Database)?;
        if duplicate.is_some() {
            return Err(StoreError::DuplicateReservation);
        }
        let count: i64 = tx
            .query_row("SELECT count(*) FROM operations", [], |row| row.get(0))
            .map_err(|_| StoreError::Database)?;
        if count >= MAX_OPERATIONS {
            return Err(StoreError::Capacity);
        }
        tx.execute(
            "INSERT INTO operations(id,account_id,account_generation,action,review_key,item_key,remote_id,name,revision,metadata,state,status_code,created_at) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,NULL,?11)",
            params![
                &id_blob,
                &account_blob,
                &generation_blob,
                action_code(input.action),
                uuid_blob(input.review_key),
                uuid_blob(input.item_key),
                input.remote_id,
                input.name,
                input.revision,
                &metadata,
                now,
            ],
        )
        .map_err(|_| StoreError::Database)?;
        tx.commit().map_err(|_| StoreError::Database)?;
        Ok(OperationRecord {
            id,
            account_id: input.account_id,
            account_generation,
            action: input.action,
            review_key: input.review_key,
            item_key: input.item_key,
            remote_id: input.remote_id,
            name: input.name,
            revision: input.revision,
            metadata,
            state: OperationState::Started,
            status_code: None,
            created_at_unix_seconds: now,
        })
    }

    /// Return one durable journal row by its opaque operation UUID.
    pub fn operation(&self, id: Uuid) -> Result<Option<OperationRecord>, StoreError> {
        if id.is_nil() {
            return Err(StoreError::InvalidInput);
        }
        self.connection
            .query_row(
                "SELECT id,account_id,account_generation,action,review_key,item_key,remote_id,name,revision,metadata,state,status_code,created_at \
                 FROM operations WHERE id=?1",
                [uuid_blob(id)],
                operation_from_row,
            )
            .optional()
            .map_err(|_| StoreError::CorruptDatabase)
    }

    /// Whether an item in this account has an unresolved or previously
    /// uncertain effect, irrespective of action type.
    pub fn has_uncertain(&self, account_id: Uuid, remote_id: &str) -> Result<bool, StoreError> {
        if account_id.is_nil() || !valid_text(remote_id, MAX_REMOTE_ID_BYTES) {
            return Err(StoreError::InvalidInput);
        }
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM operations \
                 WHERE account_id=?1 AND remote_id=?2 AND state IN (0,3))",
                params![uuid_blob(account_id), remote_id],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::Database)
    }

    /// Whether any restore attempt has already been journaled for this trash
    /// operation. All restore states count; reservation also enforces one
    /// restore attempt per account and original-operation review key.
    pub fn has_restore_attempt(&self, original_trash_operation: Uuid) -> Result<bool, StoreError> {
        if original_trash_operation.is_nil() {
            return Err(StoreError::InvalidInput);
        }
        let original_blob = uuid_blob(original_trash_operation);
        let original: Option<(Vec<u8>, i64)> = self
            .connection
            .query_row(
                "SELECT account_id,action FROM operations WHERE id=?1",
                [&original_blob],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| StoreError::Database)?;
        let Some((account_blob, action)) = original else {
            return Ok(false);
        };
        if action != action_code(CloudAction::Trash) {
            return Err(StoreError::InvalidInput);
        }
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM operations \
                 WHERE account_id=?1 AND action=1 AND review_key=?2)",
                params![account_blob, original_blob],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::Database)
    }

    /// Compare-and-set a reservation from Started to a terminal observation.
    /// Optional receipt JSON replaces restore metadata only at this point.
    pub fn finish_operation(
        &mut self,
        id: Uuid,
        terminal: TerminalState,
        receipt_json: Option<&str>,
        status_code: Option<OperationStatusCode>,
    ) -> Result<(), StoreError> {
        if id.is_nil() {
            return Err(StoreError::InvalidInput);
        }
        let receipt_json = receipt_json.map(validate_metadata).transpose()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Database)?;
        let changed = tx
            .execute(
                "UPDATE operations SET state=?1,metadata=COALESCE(?2,metadata),status_code=?3 \
                 WHERE id=?4 AND state=0",
                params![
                    terminal_code(terminal),
                    receipt_json,
                    status_code.map(|value| value as i64),
                    uuid_blob(id),
                ],
            )
            .map_err(|_| StoreError::Database)?;
        if changed != 1 {
            return Err(StoreError::InvalidTransition);
        }
        tx.commit().map_err(|_| StoreError::Database)
    }

    /// Convert remaining Started rows only after the owner has proved its prior
    /// worker stopped. This method is explicit and is never called by `open`.
    pub fn mark_interrupted_uncertain(&mut self) -> Result<usize, StoreError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Database)?;
        let changed = tx
            .execute(
                "UPDATE operations SET state=3,status_code=?1 WHERE state=0",
                [OperationStatusCode::Interrupted as i64],
            )
            .map_err(|_| StoreError::Database)?;
        tx.commit().map_err(|_| StoreError::Database)?;
        Ok(changed)
    }

    /// Read descending, stable history pages. The opaque UUID cursor points to
    /// the last returned row and is checked against the optional account filter.
    pub fn operations(
        &self,
        account_id: Option<Uuid>,
        cursor: Option<Uuid>,
        limit: usize,
    ) -> Result<OperationPage, StoreError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(StoreError::InvalidPageLimit);
        }
        if account_id.is_some_and(|id| id.is_nil()) {
            return Err(StoreError::InvalidInput);
        }
        let account_blob = account_id.map(uuid_blob);
        let before_seq = if let Some(cursor) = cursor {
            if cursor.is_nil() {
                return Err(StoreError::InvalidCursor);
            }
            let cursor_blob = uuid_blob(cursor);
            let found = match account_blob.as_deref() {
                Some(account) => self
                    .connection
                    .query_row(
                        "SELECT seq FROM operations WHERE id=?1 AND account_id=?2",
                        params![&cursor_blob, account],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional(),
                None => self
                    .connection
                    .query_row(
                        "SELECT seq FROM operations WHERE id=?1",
                        [&cursor_blob],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional(),
            }
            .map_err(|_| StoreError::Database)?;
            found.ok_or(StoreError::InvalidCursor)?
        } else {
            i64::MAX
        };
        let fetch = i64::try_from(limit + 1).map_err(|_| StoreError::InvalidPageLimit)?;
        let mut statement = match account_blob.as_deref() {
            Some(_) => self.connection.prepare(
                "SELECT id,account_id,account_generation,action,review_key,item_key,remote_id,name,revision,metadata,state,status_code,created_at \
                 FROM operations WHERE seq<?1 AND account_id=?2 ORDER BY seq DESC LIMIT ?3",
            ),
            None => self.connection.prepare(
                "SELECT id,account_id,account_generation,action,review_key,item_key,remote_id,name,revision,metadata,state,status_code,created_at \
                 FROM operations WHERE seq<?1 ORDER BY seq DESC LIMIT ?2",
            ),
        }
        .map_err(|_| StoreError::Database)?;
        let mapped = match account_blob.as_deref() {
            Some(account) => {
                statement.query_map(params![before_seq, account, fetch], operation_from_row)
            }
            None => statement.query_map(params![before_seq, fetch], operation_from_row),
        }
        .map_err(|_| StoreError::Database)?;
        let mut records = Vec::new();
        for row in mapped {
            if records.len() > MAX_PAGE_SIZE {
                return Err(StoreError::CorruptDatabase);
            }
            records.push(row.map_err(|_| StoreError::CorruptDatabase)?);
        }
        let next_cursor = if records.len() > limit {
            records.pop();
            records.last().map(OperationRecord::id)
        } else {
            None
        };
        Ok(OperationPage {
            records,
            next_cursor,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DatabaseHeader {
    Fresh,
    Current,
    Unsupported,
}

fn initialize_schema(connection: &mut Connection) -> Result<(), StoreError> {
    if database_header(connection)? != DatabaseHeader::Fresh {
        return Err(StoreError::UnsupportedDatabase);
    }
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| StoreError::Database)?;
    tx.execute_batch(SCHEMA).map_err(|_| StoreError::Database)?;
    tx.pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(|_| StoreError::Database)?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(|_| StoreError::Database)?;
    validate_schema(&tx)?;
    verify_integrity(&tx)?;
    tx.commit().map_err(|_| StoreError::Database)
}

fn database_header(connection: &Connection) -> Result<DatabaseHeader, StoreError> {
    let app_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| StoreError::Database)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| StoreError::Database)?;
    let user_tables: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::Database)?;
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|_| StoreError::Database)?;
    let page_count: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|_| StoreError::Database)?;
    if page_size <= 0
        || page_count < 0
        || page_count
            .checked_mul(page_size)
            .map_or(true, |bytes| bytes > MAX_DATABASE_BYTES)
    {
        return Err(StoreError::Capacity);
    }
    Ok(match (app_id, version, user_tables) {
        (0, 0, 0) => DatabaseHeader::Fresh,
        (APPLICATION_ID, SCHEMA_VERSION, 2) => DatabaseHeader::Current,
        _ => DatabaseHeader::Unsupported,
    })
}

fn verify_connection_is_file_backed(connection: &Connection) -> Result<(), StoreError> {
    if !connection.is_autocommit() {
        return Err(StoreError::UnsupportedDatabase);
    }
    let file: String = connection
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::Database)?;
    let attached: i64 = connection
        .query_row(
            "SELECT count(*) FROM pragma_database_list WHERE name NOT IN ('main','temp')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::Database)?;
    let temporary: i64 = connection
        .query_row("SELECT count(*) FROM sqlite_temp_schema", [], |row| {
            row.get(0)
        })
        .map_err(|_| StoreError::Database)?;
    if file.is_empty() || attached != 0 || temporary != 0 {
        return Err(StoreError::UnsupportedDatabase);
    }
    Ok(())
}

fn verify_integrity(connection: &Connection) -> Result<(), StoreError> {
    let result: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| StoreError::Database)?;
    if result.eq_ignore_ascii_case("ok") {
        Ok(())
    } else {
        Err(StoreError::CorruptDatabase)
    }
}

fn validate_schema(connection: &Connection) -> Result<(), StoreError> {
    if database_header(connection)? != DatabaseHeader::Current {
        return Err(StoreError::UnsupportedDatabase);
    }
    let tables = table_names(connection)?;
    if tables.len() != 2 || tables[0] != "accounts" || tables[1] != "operations" {
        return Err(StoreError::UnsupportedDatabase);
    }
    validate_table(
        connection,
        "accounts",
        &[
            ("id", "BLOB"),
            ("provider", "INTEGER"),
            ("subject_id", "TEXT"),
            ("storage_id", "TEXT"),
            ("client_id", "TEXT"),
            ("label", "TEXT"),
            ("generation", "BLOB"),
            ("active", "INTEGER"),
            ("created_at", "INTEGER"),
            ("updated_at", "INTEGER"),
        ],
    )?;
    validate_table(
        connection,
        "operations",
        &[
            ("seq", "INTEGER"),
            ("id", "BLOB"),
            ("account_id", "BLOB"),
            ("account_generation", "BLOB"),
            ("action", "INTEGER"),
            ("review_key", "BLOB"),
            ("item_key", "BLOB"),
            ("remote_id", "TEXT"),
            ("name", "TEXT"),
            ("revision", "TEXT"),
            ("metadata", "TEXT"),
            ("state", "INTEGER"),
            ("status_code", "INTEGER"),
            ("created_at", "INTEGER"),
        ],
    )?;
    for index in [
        "account_exact_scope",
        "operations_account_sequence",
        "operations_restore_review",
    ] {
        let exists: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type='index' AND name=?1",
                [index],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::Database)?;
        if exists != 1 {
            return Err(StoreError::UnsupportedDatabase);
        }
    }
    let account_count: i64 = connection
        .query_row("SELECT count(*) FROM accounts", [], |row| row.get(0))
        .map_err(|_| StoreError::Database)?;
    let operation_count: i64 = connection
        .query_row("SELECT count(*) FROM operations", [], |row| row.get(0))
        .map_err(|_| StoreError::Database)?;
    if !(0..=MAX_ACCOUNTS).contains(&account_count)
        || !(0..=MAX_OPERATIONS).contains(&operation_count)
    {
        return Err(StoreError::Capacity);
    }
    Ok(())
}

fn table_names(connection: &Connection) -> Result<Vec<String>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .map_err(|_| StoreError::Database)?;
    let rows = statement
        .query_map([], |row| row.get(0))
        .map_err(|_| StoreError::Database)?;
    rows.collect::<Result<Vec<String>, _>>()
        .map_err(|_| StoreError::Database)
}

fn validate_table(
    connection: &Connection,
    table: &str,
    expected: &[(&str, &str)],
) -> Result<(), StoreError> {
    let strict: i64 = connection
        .query_row(
            "SELECT strict FROM pragma_table_list WHERE name=?1 AND type='table'",
            [table],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::UnsupportedDatabase)?;
    if strict != 1 {
        return Err(StoreError::UnsupportedDatabase);
    }
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|_| StoreError::Database)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })
        .map_err(|_| StoreError::Database)?;
    let actual = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StoreError::Database)?;
    if actual.len() != expected.len()
        || !actual
            .iter()
            .zip(expected)
            .all(|((name, kind), (expected_name, expected_kind))| {
                name == expected_name && kind.eq_ignore_ascii_case(expected_kind)
            })
    {
        return Err(StoreError::UnsupportedDatabase);
    }
    Ok(())
}

fn ensure_safe_directory(path: &Path) -> Result<PathBuf, StoreError> {
    if !path.is_absolute() {
        return Err(StoreError::UnsafePath);
    }
    let mut prefix = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(value) => prefix.push(value.as_os_str()),
            Component::RootDir => prefix.push(component.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => return Err(StoreError::UnsafePath),
            Component::Normal(value) => prefix.push(value),
        }
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        ensure_one_directory(&prefix)?;
    }
    if prefix.as_os_str().is_empty() {
        return Err(StoreError::UnsafePath);
    }
    ensure_one_directory(&prefix)?;
    let canonical = dunce::canonicalize(path).map_err(|_| StoreError::UnsafePath)?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|_| StoreError::UnsafePath)?;
    if !metadata.is_dir() || is_link_or_reparse(&metadata) {
        return Err(StoreError::UnsafePath);
    }
    Ok(canonical)
}

fn ensure_one_directory(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.is_dir() && !is_link_or_reparse(&metadata) {
                Ok(())
            } else {
                Err(StoreError::UnsafePath)
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match fs::create_dir(path) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(_) => return Err(StoreError::Database),
            }
            let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::UnsafePath)?;
            if metadata.is_dir() && !is_link_or_reparse(&metadata) {
                Ok(())
            } else {
                Err(StoreError::UnsafePath)
            }
        }
        Err(_) => Err(StoreError::Database),
    }
}

fn inspect_database_path(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || is_link_or_reparse(&metadata) {
                return Err(StoreError::UnsafePath);
            }
            if metadata.len() > MAX_DATABASE_BYTES as u64 {
                return Err(StoreError::Capacity);
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(StoreError::Database),
    }
}

fn is_link_or_reparse(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn provider_code(provider: Provider) -> i64 {
    match provider {
        Provider::GoogleDrive => 0,
        Provider::Gmail => 1,
        Provider::OneDrive => 2,
        Provider::Dropbox => 3,
    }
}

fn provider_from_code(value: i64) -> Option<Provider> {
    match value {
        0 => Some(Provider::GoogleDrive),
        1 => Some(Provider::Gmail),
        2 => Some(Provider::OneDrive),
        3 => Some(Provider::Dropbox),
        _ => None,
    }
}

fn decode_scope(
    provider: i64,
    subject_id: String,
    storage_id: Option<String>,
) -> Result<AccountScope, StoreError> {
    let provider = provider_from_code(provider).ok_or(StoreError::CorruptDatabase)?;
    AccountScope::new(provider, subject_id, storage_id).map_err(|_| StoreError::CorruptDatabase)
}

fn action_code(action: CloudAction) -> i64 {
    match action {
        CloudAction::Trash => 0,
        CloudAction::Restore => 1,
    }
}

fn action_from_code(value: i64) -> Option<CloudAction> {
    match value {
        0 => Some(CloudAction::Trash),
        1 => Some(CloudAction::Restore),
        _ => None,
    }
}

fn state_code(state: OperationState) -> i64 {
    match state {
        OperationState::Started => 0,
        OperationState::Confirmed => 1,
        OperationState::Failed => 2,
        OperationState::Uncertain => 3,
    }
}

fn state_from_code(value: i64) -> Option<OperationState> {
    match value {
        0 => Some(OperationState::Started),
        1 => Some(OperationState::Confirmed),
        2 => Some(OperationState::Failed),
        3 => Some(OperationState::Uncertain),
        _ => None,
    }
}

fn terminal_code(state: TerminalState) -> i64 {
    match state {
        TerminalState::Confirmed => state_code(OperationState::Confirmed),
        TerminalState::Failed => state_code(OperationState::Failed),
        TerminalState::Uncertain => state_code(OperationState::Uncertain),
    }
}

fn status_from_code(value: i64) -> Option<OperationStatusCode> {
    match value {
        1 => Some(OperationStatusCode::Interrupted),
        2 => Some(OperationStatusCode::ProviderConflict),
        3 => Some(OperationStatusCode::ProviderNotFound),
        4 => Some(OperationStatusCode::AuthenticationRequired),
        5 => Some(OperationStatusCode::PermissionDenied),
        6 => Some(OperationStatusCode::RateLimited),
        7 => Some(OperationStatusCode::TemporarilyUnavailable),
        8 => Some(OperationStatusCode::InvalidResponse),
        9 => Some(OperationStatusCode::Cancelled),
        10 => Some(OperationStatusCode::Other),
        11 => Some(OperationStatusCode::AlreadySatisfied),
        12 => Some(OperationStatusCode::AccountChanged),
        _ => None,
    }
}

fn uuid_blob(id: Uuid) -> Vec<u8> {
    id.as_bytes().to_vec()
}

fn parse_uuid(bytes: &[u8]) -> Option<Uuid> {
    let id = Uuid::from_slice(bytes).ok()?;
    (!id.is_nil()).then_some(id)
}

fn row_uuid(row: &Row<'_>, index: usize) -> rusqlite::Result<Uuid> {
    let bytes: Vec<u8> = row.get(index)?;
    parse_uuid(&bytes).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid UUID blob",
            )),
        )
    })
}

fn account_from_row(row: &Row<'_>) -> rusqlite::Result<AccountRecord> {
    let id = row_uuid(row, 0)?;
    let provider: i64 = row.get(1)?;
    let subject_id: String = row.get(2)?;
    let storage_id: Option<String> = row.get(3)?;
    let client_id: String = row.get(4)?;
    let label: String = row.get(5)?;
    let generation = row_uuid(row, 6)?;
    let scope = decode_scope(provider, subject_id, storage_id).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid account scope",
            )),
        )
    })?;
    if !valid_text(&client_id, MAX_CLIENT_ID_BYTES) || !valid_text(&label, MAX_LABEL_BYTES) {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            4,
            Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid account fields",
            )),
        ));
    }
    Ok(AccountRecord {
        id,
        scope,
        client_id,
        label,
        generation,
    })
}

fn operation_from_row(row: &Row<'_>) -> rusqlite::Result<OperationRecord> {
    let id = row_uuid(row, 0)?;
    let account_id = row_uuid(row, 1)?;
    let account_generation = row_uuid(row, 2)?;
    let action_value: i64 = row.get(3)?;
    let action = action_from_code(action_value).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid operation action",
            )),
        )
    })?;
    let review_key = row_uuid(row, 4)?;
    let item_key = row_uuid(row, 5)?;
    let remote_id: String = row.get(6)?;
    let name: String = row.get(7)?;
    let revision: Option<String> = row.get(8)?;
    let metadata: String = row.get(9)?;
    let state_value: i64 = row.get(10)?;
    let state = state_from_code(state_value).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            10,
            Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid operation state",
            )),
        )
    })?;
    let status_value: Option<i64> = row.get(11)?;
    let status_code = match status_value {
        Some(value) => Some(status_from_code(value).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                11,
                Type::Integer,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid operation status code",
                )),
            )
        })?),
        None => None,
    };
    let created_at_unix_seconds: i64 = row.get(12)?;
    if !valid_text(&remote_id, MAX_REMOTE_ID_BYTES)
        || !valid_text(&name, MAX_NAME_BYTES)
        || revision
            .as_deref()
            .is_some_and(|value| !valid_text(value, MAX_REVISION_BYTES))
        || validate_metadata(&metadata).is_err()
        || created_at_unix_seconds < 0
        || (state == OperationState::Started && status_code.is_some())
    {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            6,
            Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid operation fields",
            )),
        ));
    }
    Ok(OperationRecord {
        id,
        account_id,
        account_generation,
        action,
        review_key,
        item_key,
        remote_id,
        name,
        revision,
        metadata,
        state,
        status_code,
        created_at_unix_seconds,
    })
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn validate_operation_input(input: &OperationInput) -> Result<String, StoreError> {
    if input.account_id.is_nil()
        || input.review_key.is_nil()
        || input.item_key.is_nil()
        || !valid_text(&input.remote_id, MAX_REMOTE_ID_BYTES)
        || !valid_text(&input.name, MAX_NAME_BYTES)
        || input
            .revision
            .as_deref()
            .is_some_and(|value| !valid_text(value, MAX_REVISION_BYTES))
    {
        return Err(StoreError::InvalidInput);
    }
    validate_metadata(&input.metadata)
}

fn validate_metadata(raw: &str) -> Result<String, StoreError> {
    if raw.is_empty() || raw.len() > MAX_METADATA_BYTES {
        return Err(StoreError::InvalidInput);
    }
    let value: Value = serde_json::from_str(raw).map_err(|_| StoreError::InvalidInput)?;
    if !value.is_object() {
        return Err(StoreError::InvalidInput);
    }
    let mut nodes = 0usize;
    validate_json_value(&value, 0, &mut nodes)?;
    // Store only the parsed object so duplicate keys cannot hide an earlier
    // credential-shaped key in raw JSON that would otherwise be persisted.
    serde_json::to_string(&value).map_err(|_| StoreError::InvalidInput)
}

fn validate_json_value(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), StoreError> {
    if depth > MAX_METADATA_DEPTH {
        return Err(StoreError::InvalidInput);
    }
    *nodes = nodes.checked_add(1).ok_or(StoreError::InvalidInput)?;
    if *nodes > MAX_METADATA_NODES {
        return Err(StoreError::InvalidInput);
    }
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if !valid_text(key, 256) || sensitive_metadata_key(key) {
                    return Err(StoreError::InvalidInput);
                }
                validate_json_value(value, depth + 1, nodes)?;
            }
        }
        Value::Array(array) => {
            for value in array {
                validate_json_value(value, depth + 1, nodes)?;
            }
        }
        Value::String(value) if value.chars().any(char::is_control) => {
            return Err(StoreError::InvalidInput);
        }
        _ => (),
    }
    Ok(())
}

fn sensitive_metadata_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['-', ' '], "_");
    normalized.contains("token")
        || normalized.contains("authorization")
        || normalized.contains("client_secret")
        || normalized == "secret"
        || normalized == "password"
}

fn unix_seconds() -> Result<i64, StoreError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::Database)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| StoreError::Capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: Uuid, subject: &str, label: &str) -> AccountInput {
        AccountInput {
            id,
            scope: AccountScope::new(
                Provider::OneDrive,
                subject,
                Some("drive-fixture".to_owned()),
            )
            .unwrap(),
            client_id: "fixture-client".to_owned(),
            label: label.to_owned(),
        }
    }

    fn operation(
        account_id: Uuid,
        action: CloudAction,
        review_key: Uuid,
        item_key: Uuid,
    ) -> OperationInput {
        OperationInput {
            account_id,
            action,
            review_key,
            item_key,
            remote_id: "opaque-item-id".to_owned(),
            name: "fixture.txt".to_owned(),
            revision: Some("etag-fixture".to_owned()),
            metadata: r#"{"restore":"fixture"}"#.to_owned(),
        }
    }

    #[test]
    fn account_scope_is_immutable_and_refresh_creates_generation() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CloudStore::open(directory.path()).unwrap();
        let account_id = Uuid::new_v4();
        let first = store
            .upsert_account(account(account_id, "subject-a", "First"))
            .unwrap();
        let refreshed = store
            .upsert_account(account(account_id, "subject-a", "Renamed"))
            .unwrap();
        assert_ne!(first.generation(), refreshed.generation());
        assert_eq!(refreshed.label(), "Renamed");
        let refreshed_rows = store.accounts().unwrap();
        assert_eq!(refreshed_rows.len(), 1);
        assert_eq!(refreshed_rows[0], refreshed);
        assert_eq!(
            store.upsert_account(account(account_id, "subject-b", "Changed")),
            Err(StoreError::AccountScopeConflict)
        );
        assert_eq!(
            store.upsert_account(account(Uuid::new_v4(), "subject-a", "Duplicate")),
            Err(StoreError::AccountScopeConflict)
        );
        drop(store);
        let reopened = CloudStore::open(directory.path()).unwrap();
        let persisted_rows = reopened.accounts().unwrap();
        assert_eq!(persisted_rows.len(), 1);
        assert_eq!(persisted_rows[0], refreshed);
        let synchronous: i64 = reopened
            .connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(synchronous, 2);
    }

    #[test]
    fn generation_bound_reservation_is_atomic_and_terminal_updates_are_cas() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CloudStore::open(directory.path()).unwrap();
        let account_id = Uuid::new_v4();
        let saved = store
            .upsert_account(account(account_id, "subject-a", "OneDrive"))
            .unwrap();
        let current = store
            .upsert_account(account(account_id, "subject-a", "Renamed"))
            .unwrap();
        let review = Uuid::new_v4();
        let item = Uuid::new_v4();
        assert_eq!(
            store.reserve_operation_for_generation(
                operation(account_id, CloudAction::Trash, review, item),
                saved.generation()
            ),
            Err(StoreError::AccountGenerationChanged)
        );
        assert!(
            store
                .operations(Some(account_id), None, 10)
                .unwrap()
                .records
                .is_empty()
        );
        let input = operation(account_id, CloudAction::Trash, review, item);
        let started = store
            .reserve_operation_for_generation(input, current.generation())
            .unwrap();
        assert_eq!(started.state(), OperationState::Started);
        assert_eq!(
            store.operation(started.id()).unwrap(),
            Some(started.clone())
        );
        assert!(store.has_uncertain(account_id, "opaque-item-id").unwrap());
        assert_eq!(
            store.reserve_operation_for_generation(
                operation(account_id, CloudAction::Trash, review, item),
                current.generation()
            ),
            Err(StoreError::DuplicateReservation)
        );
        store
            .finish_operation(
                started.id(),
                TerminalState::Failed,
                Some(r#"{"receipt":"fixture-failure"}"#),
                Some(OperationStatusCode::Other),
            )
            .unwrap();
        let failed = store.operation(started.id()).unwrap().unwrap();
        assert_eq!(failed.state(), OperationState::Failed);
        assert_eq!(failed.status_code(), Some(OperationStatusCode::Other));
        assert_eq!(failed.metadata(), r#"{"receipt":"fixture-failure"}"#);
        assert!(!store.has_uncertain(account_id, "opaque-item-id").unwrap());
        assert_eq!(
            store.finish_operation(started.id(), TerminalState::Confirmed, None, None),
            Err(StoreError::InvalidTransition)
        );

        let restore = store
            .reserve_operation_for_generation(
                operation(account_id, CloudAction::Restore, started.id(), item),
                current.generation(),
            )
            .unwrap();
        assert!(store.has_restore_attempt(started.id()).unwrap());
        assert_eq!(
            store.reserve_operation_for_generation(
                operation(
                    account_id,
                    CloudAction::Restore,
                    started.id(),
                    Uuid::new_v4()
                ),
                current.generation()
            ),
            Err(StoreError::DuplicateReservation)
        );
        store
            .finish_operation(
                restore.id(),
                TerminalState::Uncertain,
                None,
                Some(OperationStatusCode::TemporarilyUnavailable),
            )
            .unwrap();
        assert!(store.has_restore_attempt(started.id()).unwrap());
    }

    #[test]
    fn reconnect_reuses_disconnected_identity_and_preserves_history() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CloudStore::open(directory.path()).unwrap();
        let account_id = Uuid::new_v4();
        let saved = store
            .upsert_account(account(account_id, "subject-a", "OneDrive"))
            .unwrap();
        let first = store
            .reserve_operation_for_generation(
                operation(
                    account_id,
                    CloudAction::Trash,
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                ),
                saved.generation(),
            )
            .unwrap();
        store
            .reserve_operation_for_generation(
                operation(
                    account_id,
                    CloudAction::Trash,
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                ),
                saved.generation(),
            )
            .unwrap();
        let page1 = store.operations(Some(account_id), None, 1).unwrap();
        assert_eq!(page1.records.len(), 1);
        let cursor = page1.next_cursor.unwrap();
        let page2 = store.operations(Some(account_id), Some(cursor), 1).unwrap();
        assert_eq!(page2.records.len(), 1);
        assert_eq!(page2.records[0].id(), first.id());
        assert!(page2.next_cursor.is_none());

        store.remove_account(account_id).unwrap();
        drop(store);
        let mut store = CloudStore::open(directory.path()).unwrap();
        assert_eq!(store.accounts().unwrap().len(), 0);
        let disconnected = store
            .known_account_for_scope(saved.scope())
            .unwrap()
            .unwrap();
        assert_eq!(disconnected.id(), account_id);
        assert_eq!(disconnected.generation(), saved.generation());
        let other_storage = AccountScope::new(
            Provider::OneDrive,
            "subject-a",
            Some("other-drive".to_owned()),
        )
        .unwrap();
        assert!(
            store
                .known_account_for_scope(&other_storage)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .operations(Some(account_id), None, 10)
                .unwrap()
                .records
                .len(),
            2
        );
        assert_eq!(
            store.reserve_operation_for_generation(
                operation(
                    account_id,
                    CloudAction::Trash,
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                ),
                saved.generation()
            ),
            Err(StoreError::UnknownAccount)
        );

        let reconnected = store
            .upsert_account(account(disconnected.id(), "subject-a", "Reconnected"))
            .unwrap();
        assert_eq!(reconnected.id(), account_id);
        assert_ne!(reconnected.generation(), disconnected.generation());
        assert_eq!(store.accounts().unwrap(), vec![reconnected.clone()]);
        assert_eq!(
            store.reserve_operation_for_generation(
                operation(
                    account_id,
                    CloudAction::Trash,
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                ),
                saved.generation()
            ),
            Err(StoreError::AccountGenerationChanged)
        );
        store
            .reserve_operation_for_generation(
                operation(
                    account_id,
                    CloudAction::Trash,
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                ),
                reconnected.generation(),
            )
            .unwrap();
        assert_eq!(
            store
                .operations(Some(account_id), None, 10)
                .unwrap()
                .records
                .len(),
            3
        );
    }

    #[test]
    fn stale_generation_cannot_deactivate_reconnected_account() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CloudStore::open(directory.path()).unwrap();
        let account_id = Uuid::new_v4();
        let old = store
            .upsert_account(account(account_id, "subject-a", "OneDrive"))
            .unwrap();
        let current = store
            .upsert_account(account(account_id, "subject-a", "Reconnected"))
            .unwrap();

        assert_eq!(
            store.deactivate_account_for_generation(account_id, old.generation()),
            Err(StoreError::AccountGenerationChanged)
        );
        assert_eq!(store.accounts().unwrap(), vec![current.clone()]);
        store
            .deactivate_account_for_generation(account_id, current.generation())
            .unwrap();
        assert!(store.accounts().unwrap().is_empty());
        assert_eq!(
            store.deactivate_account_for_generation(account_id, current.generation()),
            Err(StoreError::AccountGenerationChanged)
        );
        assert_eq!(
            store
                .known_account_for_scope(current.scope())
                .unwrap()
                .unwrap()
                .id(),
            account_id
        );
    }

    #[test]
    fn opening_does_not_recover_started_rows_but_explicit_recovery_does() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CloudStore::open(directory.path()).unwrap();
        let account_id = Uuid::new_v4();
        let saved = store
            .upsert_account(account(account_id, "subject-a", "OneDrive"))
            .unwrap();
        let started = store
            .reserve_operation_for_generation(
                operation(
                    account_id,
                    CloudAction::Trash,
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                ),
                saved.generation(),
            )
            .unwrap();
        drop(store);

        let mut reopened = CloudStore::open(directory.path()).unwrap();
        assert_eq!(
            reopened.operation(started.id()).unwrap().unwrap().state(),
            OperationState::Started
        );
        assert_eq!(reopened.mark_interrupted_uncertain().unwrap(), 1);
        let recovered = reopened.operation(started.id()).unwrap().unwrap();
        assert_eq!(recovered.state(), OperationState::Uncertain);
        assert_eq!(
            recovered.status_code(),
            Some(OperationStatusCode::Interrupted)
        );
    }

    #[test]
    fn invalid_pages_and_sensitive_metadata_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CloudStore::open(directory.path()).unwrap();
        assert!(matches!(
            store.operations(None, None, 0),
            Err(StoreError::InvalidPageLimit)
        ));
        assert!(matches!(
            store.operations(Some(Uuid::nil()), None, 1),
            Err(StoreError::InvalidInput)
        ));
        let account_id = Uuid::new_v4();
        let saved = store
            .upsert_account(account(account_id, "subject-a", "OneDrive"))
            .unwrap();
        let mut input = operation(
            account_id,
            CloudAction::Trash,
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        input.metadata = r#"{"access_token":"fixture-secret"}"#.to_owned();
        assert_eq!(
            store.reserve_operation_for_generation(input, saved.generation()),
            Err(StoreError::InvalidInput)
        );
    }

    #[cfg(unix)]
    #[test]
    fn linked_data_directory_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let real = tempfile::tempdir().unwrap();
        let linked = root.path().join("linked-data");
        std::os::unix::fs::symlink(real.path(), &linked).unwrap();
        assert!(matches!(
            CloudStore::open(&linked),
            Err(StoreError::UnsafePath)
        ));

        let database_dir = tempfile::tempdir().unwrap();
        drop(CloudStore::open(database_dir.path()).unwrap());
        let linked_database = root.path().join(DATABASE_NAME);
        std::os::unix::fs::symlink(database_dir.path().join(DATABASE_NAME), &linked_database)
            .unwrap();
        assert!(matches!(
            CloudStore::open(root.path()),
            Err(StoreError::UnsafePath)
        ));
    }
}
