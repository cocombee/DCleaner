//! Native-derived generic table counts, with a separate reviewed source owner.
//! Count/schema observations alone never grant effect authority. The owner binds
//! them to a complete, coherent SQLite image and the native source identity.
use super::Browser;
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, ffi, types::ValueRef,
};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Scope {
    SavedForms,
    SavedPasswords,
    SitePreferences,
}
struct Rule {
    browser: Browser,
    id: &'static str,
    handler: &'static str,
    scope: Scope,
    database: &'static str,
    tables: &'static [&'static str],
    native_default: Option<bool>,
}
#[path = "generic_sqlite_catalogue.rs"]
mod catalogue;
#[path = "generic_sqlite_owner.rs"]
mod owner;
#[cfg(debug_assertions)]
pub(super) use owner::preview;
pub(super) use owner::{Review, SourceLease, delete_selected, pending, scan, validate_selected};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) struct Key {
    rule: u8,
    table: u8,
}
impl Key {
    pub(super) fn category(self) -> super::PrivacyCategory {
        match self
            .binding()
            .expect("Catalogue keys are constructed internally")
            .0
            .scope
        {
            Scope::SavedForms => super::PrivacyCategory::SavedForms,
            Scope::SavedPasswords => super::PrivacyCategory::SavedPasswords,
            Scope::SitePreferences => super::PrivacyCategory::SitePreferences,
        }
    }
    fn binding(self) -> Result<(&'static Rule, &'static str), String> {
        let rule = catalogue::RULES
            .get(self.rule as usize)
            .ok_or("Generic browser table rule is not declared.")?;
        let table = *rule
            .tables
            .get(self.table as usize)
            .ok_or("Generic browser table is not declared.")?;
        Ok((rule, table))
    }
    pub(super) fn table(self) -> Result<&'static str, String> {
        self.binding().map(|(_, table)| table)
    }
    pub(super) fn database(self) -> Result<&'static str, String> {
        self.binding().map(|(rule, _)| rule.database)
    }
    pub(super) fn native_rule(self) -> Result<&'static str, String> {
        self.binding().map(|(rule, _)| rule.id)
    }
}
pub(super) fn keys(browser: Browser, scope: Scope) -> Vec<Key> {
    catalogue::RULES
        .iter()
        .enumerate()
        .filter(|(_, r)| r.browser == browser && r.scope == scope)
        .flat_map(|(rule, r)| {
            (0..r.tables.len()).map(move |table| Key {
                rule: rule as u8,
                table: table as u8,
            })
        })
        .collect()
}
pub(super) fn lookup(browser: Browser, rule_id: &str, table: &str) -> Option<Key> {
    catalogue::RULES.iter().enumerate().find_map(|(rule, r)| {
        if r.browser != browser || r.id != rule_id {
            return None;
        }
        r.tables
            .iter()
            .position(|name| *name == table)
            .map(|table| Key {
                rule: rule as u8,
                table: table as u8,
            })
    })
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Observation {
    pub key: Key,
    pub rows: u64,
    /// Schema identity only. It never authorizes deletion or proves row data.
    pub schema_signature: [u8; 32],
}
impl Observation {
    pub(super) fn group_label(&self) -> Result<String, String> {
        Ok(format!("{}: {}", self.key.database()?, self.key.table()?))
    }
}
#[derive(Clone, Copy)]
struct Bounds {
    schema_bytes: usize,
    schema_objects: usize,
    tables: usize,
    rows: u64,
}
impl Default for Bounds {
    fn default() -> Self {
        Self {
            schema_bytes: 2 * 1024 * 1024,
            schema_objects: 2048,
            tables: 512,
            rows: i64::MAX as u64,
        }
    }
}
struct LimitLease {
    handle: *mut ffi::sqlite3,
    length: i32,
    sql: i32,
}
impl LimitLease {
    fn acquire(conn: &Connection) -> Self {
        // The reader exclusively borrows the connection until Drop. Restore
        // its original connection-local limits, including construction errors.
        let handle = unsafe { conn.handle() };
        let length = unsafe { ffi::sqlite3_limit(handle, ffi::SQLITE_LIMIT_LENGTH, -1) };
        let sql = unsafe { ffi::sqlite3_limit(handle, ffi::SQLITE_LIMIT_SQL_LENGTH, -1) };
        unsafe {
            ffi::sqlite3_limit(
                handle,
                ffi::SQLITE_LIMIT_LENGTH,
                length.min(2 * 1024 * 1024),
            );
            ffi::sqlite3_limit(handle, ffi::SQLITE_LIMIT_SQL_LENGTH, sql.min(1024 * 1024));
        }
        Self {
            handle,
            length,
            sql,
        }
    }
}
impl Drop for LimitLease {
    fn drop(&mut self) {
        unsafe {
            ffi::sqlite3_limit(self.handle, ffi::SQLITE_LIMIT_LENGTH, self.length);
            ffi::sqlite3_limit(self.handle, ffi::SQLITE_LIMIT_SQL_LENGTH, self.sql);
        }
    }
}
pub(super) struct Reader<'db, 'cancel> {
    transaction: Transaction<'db>,
    _limits: LimitLease,
    cancel: &'cancel AtomicBool,
    bounds: Bounds,
    schema_signature: [u8; 32],
    tables: usize,
    rows: u64,
}
fn cancelled(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Generic browser table observation was cancelled.".into())
    } else {
        Ok(())
    }
}
fn unavailable() -> String {
    "Generic browser table metadata or count is unavailable.".into()
}
fn schema_signature(
    conn: &Connection,
    cancel: &AtomicBool,
    bounds: Bounds,
) -> Result<[u8; 32], String> {
    let mut statement=conn.prepare("SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name COLLATE BINARY LIMIT ?1").map_err(|_|unavailable())?;
    let mut rows = statement
        .query([(bounds.schema_objects + 1) as i64])
        .map_err(|_| unavailable())?;
    let (mut bytes, mut count) = (0usize, 0usize);
    let mut hash = Sha256::new();
    hash.update(b"dcleaner-generic-table-schema-v1");
    while let Some(row) = rows.next().map_err(|_| unavailable())? {
        cancelled(cancel)?;
        count += 1;
        if count > bounds.schema_objects {
            return Err("Generic browser schema object limit reached.".into());
        }
        hash.update([0xa7]);
        for column in 0..4 {
            match row.get_ref(column).map_err(|_| unavailable())? {
                ValueRef::Null => hash.update([0]),
                ValueRef::Text(value) => {
                    bytes = bytes
                        .checked_add(value.len())
                        .filter(|n| *n <= bounds.schema_bytes)
                        .ok_or("Generic browser schema byte limit reached.")?;
                    hash.update([1]);
                    hash.update((value.len() as u64).to_le_bytes());
                    hash.update(value);
                }
                _ => return Err(unavailable()),
            }
        }
    }
    cancelled(cancel)?;
    Ok(hash.finalize().into())
}
impl<'db, 'cancel> Reader<'db, 'cancel> {
    pub(super) fn new(
        conn: &'db mut Connection,
        cancel: &'cancel AtomicBool,
    ) -> Result<Self, String> {
        Self::with_bounds(conn, cancel, Bounds::default())
    }
    fn with_bounds(
        conn: &'db mut Connection,
        cancel: &'cancel AtomicBool,
        bounds: Bounds,
    ) -> Result<Self, String> {
        cancelled(cancel)?;
        let limits = LimitLease::acquire(conn);
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| unavailable())?;
        let schema_signature = schema_signature(&transaction, cancel, bounds)?;
        Ok(Self {
            transaction,
            _limits: limits,
            cancel,
            bounds,
            schema_signature,
            tables: 0,
            rows: 0,
        })
    }
    pub(super) fn read(&mut self, key: Key) -> Result<Option<Observation>, String> {
        cancelled(self.cancel)?;
        let (_, table) = key.binding()?;
        self.tables = self
            .tables
            .checked_add(1)
            .filter(|n| *n <= self.bounds.tables)
            .ok_or("Generic browser table observation limit reached.")?;
        // Native existence checking is exact-case and excludes views. Do not
        // use the general browser helper's case-insensitive table fallback.
        let exists: Option<i64> = self
            .transaction
            .query_row(
                "SELECT 1 FROM main.sqlite_schema WHERE type='table' AND name=?1 COLLATE BINARY",
                [table],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| unavailable())?;
        if exists.is_none() {
            return Ok(None);
        }
        let layout: String = self
            .transaction
            .query_row(
                "SELECT type FROM pragma_table_list WHERE schema='main' AND name=?1 COLLATE BINARY",
                [table],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())?;
        if layout != "table" {
            return Err("Virtual or shadow browser tables require a separate adapter.".into());
        }
        let sql = format!("SELECT COUNT(*) FROM \"{table}\"");
        let count: i64 = self
            .transaction
            .query_row(&sql, [], |row| row.get(0))
            .map_err(|_| unavailable())?;
        cancelled(self.cancel)?;
        let count = u64::try_from(count).map_err(|_| unavailable())?;
        if count == 0 {
            return Ok(None);
        }
        self.rows = self
            .rows
            .checked_add(count)
            .filter(|n| *n <= self.bounds.rows)
            .ok_or("Generic browser row-count observation limit reached.")?;
        Ok(Some(Observation {
            key,
            rows: count,
            schema_signature: self.schema_signature,
        }))
    }
}

#[cfg(test)]
#[path = "generic_sqlite_tests.rs"]
mod tests;
