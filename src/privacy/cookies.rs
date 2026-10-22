//! Cookie rows are independently reviewed, including across legacy and Network
//! stores. Fingerprints bind every SQLite field without retaining cookie secrets.
//! The reference's Chromium timestamp delete key is deliberately not used: two
//! hosts can share a timestamp, but an unreviewed row must never be removed.

use super::*;
use rusqlite::types::ValueRef;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::BTreeMap;

const MAX_ROWS: usize = 100_000;
const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub(super) struct Review {
    kind: TableKind,
    row_id: i64,
    fingerprint: [u8; 32],
    schema: [u8; 32],
}

struct ObservedRow {
    site: String,
    fingerprint: [u8; 32],
}

pub(super) struct Snapshot {
    kind: TableKind,
    schema: [u8; 32],
    rows: BTreeMap<i64, ObservedRow>,
}

// Typed, length-prefixed fields keep NULL, blobs, text and numbers distinct.
// Values are borrowed from SQLite only for this call; only digests survive it.
pub(super) fn fingerprint(row: &rusqlite::Row<'_>, bytes: &mut usize) -> Result<[u8; 32], String> {
    let mut digest = Sha256::new();
    digest.update((row.as_ref().column_count() as u64).to_le_bytes());
    for column in 0..row.as_ref().column_count() {
        let value = row
            .get_ref(column)
            .map_err(|_| "Cookie field is unreadable.")?;
        let (tag, length) = match value {
            ValueRef::Null => (0, 0),
            ValueRef::Integer(_) => (1, 8),
            ValueRef::Real(_) => (2, 8),
            ValueRef::Text(value) => (3, value.len()),
            ValueRef::Blob(value) => (4, value.len()),
        };
        *bytes = bytes.saturating_add(length).saturating_add(9);
        if *bytes > MAX_BYTES {
            return Err("Cookie observation exceeds the safe byte limit.".into());
        }
        digest.update([tag]);
        digest.update((length as u64).to_le_bytes());
        match value {
            ValueRef::Null => {}
            ValueRef::Integer(value) => digest.update(value.to_le_bytes()),
            ValueRef::Real(value) => digest.update(value.to_bits().to_le_bytes()),
            ValueRef::Text(value) | ValueRef::Blob(value) => digest.update(value),
        }
    }
    Ok(digest.finalize().into())
}

fn schema(conn: &Connection, kind: TableKind, cancel: &AtomicBool) -> Result<[u8; 32], String> {
    kind.verify_delete_schema(conn)?;
    schema_for_table(conn, kind.table(), cancel)
}

pub(super) fn schema_for_table(
    conn: &Connection,
    table: &str,
    cancel: &AtomicBool,
) -> Result<[u8; 32], String> {
    let (table_type, without_rowid): (String, i64) = conn
        .query_row(
            "SELECT type,wr FROM pragma_table_list WHERE schema='main' AND name=?1",
            [table],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| "Cookie table layout is unsupported.")?;
    if table_type != "table" || without_rowid != 0 {
        return Err("Cookie table must be an ordinary row-ID table.".into());
    }
    let shadowed: i64 = conn.query_row(
        "SELECT count(*) FROM pragma_table_xinfo(?1) WHERE lower(name) IN ('rowid','oid','_rowid_')",
        [table], |row| row.get(0),
    ).map_err(|_| "Cookie row-ID layout is unreadable.")?;
    if shadowed != 0 {
        return Err("Cookie row-ID columns are ambiguous.".into());
    }
    let mut statement = conn
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name LIMIT 4097")
        .map_err(|_| "Cookie schema is unreadable.")?;
    let mut rows = statement
        .query([])
        .map_err(|_| "Cookie schema is unreadable.")?;
    let mut digest = Sha256::new();
    let mut bytes = 0;
    let mut count = 0;
    while let Some(row) = rows.next().map_err(|_| "Cookie schema is unreadable.")? {
        if cancel.load(Ordering::Relaxed) {
            return Err("Cookie observation was cancelled.".into());
        }
        count += 1;
        if count > 4096 || bytes > 1024 * 1024 {
            return Err("Cookie schema exceeds the safe limit.".into());
        }
        digest.update(fingerprint(row, &mut bytes)?);
        if bytes > 1024 * 1024 {
            return Err("Cookie schema exceeds the safe limit.".into());
        }
        let object_type: String = row.get(0).map_err(|_| "Cookie schema is unsupported.")?;
        if object_type == "trigger" {
            return Err("Cookie database has unreviewed triggers; no rows were listed.".into());
        }
        if object_type == "table" {
            let name: String = row.get(1).map_err(|_| "Cookie schema is unsupported.")?;
            let incoming: i64 = conn.query_row(
                "SELECT count(*) FROM pragma_foreign_key_list(?1) WHERE lower(\"table\")=lower(?2)",
                rusqlite::params![name, table], |row| row.get(0),
            ).map_err(|_| "Cookie dependencies could not be checked.")?;
            if incoming != 0 {
                return Err(
                    "Cookie table has unreviewed dependent rows; no rows were listed.".into(),
                );
            }
        }
    }
    if bytes > 1024 * 1024 {
        return Err("Cookie schema exceeds the safe limit.".into());
    }
    Ok(digest.finalize().into())
}

// Native CookiesSQLite3DB normalizes SELECT column 0 before its nonempty gate.
// Keep this separate from the additional display/keep-domain sanitization. The
// recovered helper removes fixed UTF-16 prefix lengths on a case-sensitive
// substring match; it is not a general URL parser. ASCII folding follows the
// default C-locale mapping; the reference CRT locale/case mapping is unverified.
fn transformed_label(kind: TableKind, value: &str) -> Result<Cow<'_, str>, String> {
    match kind {
        TableKind::ChromiumWebSql => {
            let marker = if value.contains("http_") {
                "http_"
            } else if value.contains("https_") {
                "https_"
            } else {
                return Ok(Cow::Borrowed(""));
            };
            Ok(Cow::Owned(value.replace(marker, "").replace("_0", "")))
        }
        TableKind::FirefoxWebApps | TableKind::FirefoxWebApps2 => {
            let (prefix, scoped) = if let Some((prefix, _)) = value.split_once(".:") {
                (prefix, true)
            } else {
                (value, false)
            };
            let mut units: Vec<u16> = prefix.encode_utf16().collect();
            units.reverse();
            if !scoped {
                let Some(dot) = units.iter().position(|unit| *unit == u16::from(b'.')) else {
                    return Ok(Cow::Borrowed(""));
                };
                units.drain(..=dot);
            }
            // Reverse UTF-16 units before taking the fallback suffix. A malformed
            // prefix can be discarded by that suffix operation; retained invalid
            // surrogate sequences remain unsupported instead of being replaced.
            String::from_utf16(&units)
                .map(Cow::Owned)
                .map_err(|_| "Cookie storage domain has unsupported reversed UTF-16.".into())
        }
        _ => Ok(Cow::Borrowed(value)),
    }
}

pub(super) fn normalized_label(value: &str) -> Result<String, String> {
    let mut value = value.to_owned();
    for (marker, length) in [("Cookie:", 7), ("#HttpOnly_", 10)] {
        if value.contains(marker) {
            value = String::from_utf16(&value.encode_utf16().skip(length).collect::<Vec<_>>())
                .map_err(|_| "Cookie host prefix has an unsupported encoding.")?;
            // The native helper's empty-after-prefix behavior is not established.
            if value.is_empty() {
                return Err("Cookie host has an unsupported empty prefix payload.".into());
            }
        }
    }
    if value.ends_with('/') {
        value.pop();
    }
    if let Some((_, host)) = value.split_once('@') {
        value = host.to_owned();
    }
    if value.starts_with('.') {
        value.remove(0);
    }
    value = value
        .replace("DOMStore:http://", "")
        .replace("DOMStore:https://", "");
    value.make_ascii_lowercase();
    Ok(value)
}

impl Snapshot {
    pub(super) fn read(
        conn: &Connection,
        kind: TableKind,
        cancel: &AtomicBool,
    ) -> Result<Self, String> {
        if kind.category() != PrivacyCategory::Cookies {
            return Err("Unsupported cookie adapter.".into());
        }
        let schema = schema(conn, kind, cancel)?;
        let host_column = match kind {
            TableKind::ChromiumCookies => "host_key",
            TableKind::ChromiumOriginCerts => "origin",
            TableKind::ChromiumWebSql => "origin",
            TableKind::FirefoxWebApps => "domain",
            TableKind::FirefoxWebApps2 => "scope",
            _ => "host",
        };
        let key_column = match kind {
            TableKind::ChromiumCookies => "creation_utc",
            TableKind::ChromiumOriginCerts | TableKind::ChromiumChannelIds => "creation_time",
            TableKind::FirefoxWebApps => "domain",
            TableKind::FirefoxWebApps2 => "scope",
            _ => "id",
        };
        let utf16_database = conn
            .query_row("PRAGMA encoding", [], |row| row.get::<_, String>(0))
            .map_err(|_| "Cookie text encoding is unreadable.")?
            .starts_with("UTF-16");
        let mut statement = conn
            .prepare(&format!(
                "SELECT rowid,*,CAST({host_column} AS TEXT),CAST({key_column} AS TEXT) FROM {}{} ORDER BY rowid LIMIT {}",
                kind.table(),
                if kind == TableKind::FirefoxOfflinePermissions {
                    " WHERE type='offline-app' AND permission=1"
                } else {
                    ""
                },
                MAX_ROWS + 1,
            ))
            .map_err(|_| "Cookie rows have an unsupported layout.")?;
        // SQLite performs its own text conversion, as the reference getter does.
        // Positional trailing columns cannot be shadowed by stored column names.
        let raw_host_column = statement
            .column_index(host_column)
            .map_err(|_| "Cookie host column is unavailable.")?;
        let raw_key_column = statement
            .column_index(key_column)
            .map_err(|_| "Cookie cleanup key column is unavailable.")?;
        let host_column = statement.column_count() - 2;
        let key_column = statement.column_count() - 1;
        let id_column = if matches!(
            kind,
            TableKind::FirefoxCookies | TableKind::FirefoxOfflinePermissions
        ) {
            Some(
                statement
                    .column_index("id")
                    .map_err(|_| "Cookie ID column is unavailable.")?,
            )
        } else {
            None
        };
        let mut query = statement
            .query([])
            .map_err(|_| "Cookie query was rejected.")?;
        let mut rows = BTreeMap::new();
        let mut bytes = 0;
        let mut observed_count = 0;
        while let Some(row) = query
            .next()
            .map_err(|_| "Cookie rows could not be read consistently.")?
        {
            if cancel.load(Ordering::Relaxed) {
                return Err("Cookie observation was cancelled.".into());
            }
            observed_count += 1;
            if observed_count > MAX_ROWS {
                return Err("Cookie observation exceeds the safe row limit.".into());
            }
            let id: i64 = row.get(0).map_err(|_| "Cookie row ID is unsupported.")?;
            if id < 0 || id_column.is_some_and(|column| row.get::<_, i64>(column).ok() != Some(id))
            {
                return Err("Cookie row ID is ambiguous.".into());
            }
            let fingerprint = fingerprint(row, &mut bytes)?;
            if utf16_database {
                for column in [raw_host_column, raw_key_column] {
                    // A malformed odd-byte UTF-16 blob can expose a different
                    // span through column_text16 than through CAST. Its native
                    // C-string result is unverified; never silently omit it.
                    if matches!(row.get_ref(column), Ok(ValueRef::Blob(value)) if value.len() % 2 != 0)
                    {
                        return Err("Cookie text has an unsupported odd-byte UTF-16 blob.".into());
                    }
                }
            }
            let host = match row
                .get_ref(host_column)
                .map_err(|_| "Cookie host encoding is unsupported.")?
            {
                ValueRef::Null => continue,
                ValueRef::Text(host) => host,
                _ => return Err("Cookie host encoding is unsupported.".into()),
            };
            // The native caller uses NUL-terminated strings. Fingerprints above
            // still bind all original bytes, including any suffix after a NUL.
            let host = host.split(|byte| *byte == 0).next().unwrap_or_default();
            let host =
                std::str::from_utf8(host).map_err(|_| "Cookie host encoding is unsupported.")?;
            let transformed = transformed_label(kind, host)?;
            let host = normalized_label(&transformed)?;
            if host.is_empty() {
                continue;
            }
            match row
                .get_ref(key_column)
                .map_err(|_| "Cookie cleanup key is unreadable.")?
            {
                ValueRef::Null => continue,
                ValueRef::Text(key) if key.is_empty() || key[0] == 0 => continue,
                ValueRef::Text(_) => {}
                _ => return Err("Cookie cleanup key is unsupported.".into()),
            }
            let observed = ObservedRow {
                site: safe_site_label(&host),
                fingerprint,
            };
            if rows.insert(id, observed).is_some() {
                return Err("Cookie row IDs are ambiguous.".into());
            }
        }
        Ok(Self { kind, schema, rows })
    }

    pub(super) fn reviews(&self) -> impl Iterator<Item = (String, i64, Review)> + '_ {
        self.rows.iter().map(|(&row_id, row)| {
            (
                row.site.clone(),
                row_id,
                Review {
                    kind: self.kind,
                    row_id,
                    fingerprint: row.fingerprint,
                    schema: self.schema,
                },
            )
        })
    }
}

impl Review {
    pub(super) fn matches(&self, observed: &Snapshot) -> bool {
        self.kind == observed.kind
            && self.schema == observed.schema
            && observed
                .rows
                .get(&self.row_id)
                .is_some_and(|row| row.fingerprint == self.fingerprint)
    }
    pub(super) fn delete(&self, tx: &rusqlite::Transaction<'_>) -> Result<usize, String> {
        tx.execute(
            &format!(
                "DELETE FROM {} WHERE rowid=?1{}",
                self.kind.table(),
                if self.kind == TableKind::FirefoxOfflinePermissions {
                    " AND type='offline-app' AND permission=1"
                } else {
                    ""
                }
            ),
            [self.row_id],
        )
        .map_err(|_| "A reviewed cookie could not be removed transactionally.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_storage_transformations_match_recovered_native_cases() {
        for (input, expected) in [
            ("http_example.com_0", "example.com"),
            ("https_example.com_0", "example.com"),
            ("abc_http_host_0_suffix", "abc_host_suffix"),
            ("http_http_a_0_0", "a"),
            ("HTTPS_host_0", ""),
            ("https://example.com/", ""),
            ("http_example.com_443", "example.com_443"),
            ("http_example_0thing_0", "examplething"),
            ("http_a_https_b_0", "a_https_b"),
            ("", ""),
        ] {
            assert_eq!(
                transformed_label(TableKind::ChromiumWebSql, input).unwrap(),
                expected
            );
        }
        for kind in [TableKind::FirefoxWebApps, TableKind::FirefoxWebApps2] {
            for (input, expected) in [
                ("moc.elpmaxe.:https:443", "example.com"),
                ("moc.elpmaxe.", "example.com"),
                ("foo", ""),
                ("moc.elpmaxe", "com"),
                ("prefix.:other.:", "xiferp"),
                (".:https:443", ""),
                ("sometext.:", "txetemos"),
                ("", ""),
                // Reverse units first: invalid surrogate units are discarded
                // with the prefix before the fallback's first dot.
                ("moc.elpmaxe.😀", "example.com"),
            ] {
                assert_eq!(transformed_label(kind, input).unwrap(), expected);
            }
            assert!(transformed_label(kind, "😀.:https:443").is_err());
        }
    }

    #[test]
    fn native_ascii_label_cases_keep_fixed_prefix_and_order_semantics() {
        // Independently recovered helper 0x1409d9010; these are static-contract
        // cases, not observations from an executing native target.
        for (raw, expected) in [
            ("Cookie:#HttpOnly_.EXAMPLE.COM/", "example.com"),
            ("Cookie:user@.EXAMPLE.COM/", "example.com"),
            ("xxCookie:EXAMPLE.COM", "e:example.com"),
            ("DOMStore:http://EXAMPLE.COM/", "example.com"),
            ("prefixDOMStore:http://EXAMPLE.COM/", "prefixexample.com"),
            ("foo.com/path", "foo.com/path"),
            ("..EXAMPLE.COM", ".example.com"),
            ("EXAMPLE.COM//", "example.com/"),
            ("HTTP://EXAMPLE.COM/", "http://example.com"),
            ("cookie:EXAMPLE.COM", "cookie:example.com"),
            ("", ""),
            (".", ""),
            ("/", ""),
            ("user@", ""),
        ] {
            assert_eq!(normalized_label(raw).unwrap(), expected, "{raw:?}");
        }
        for raw in ["Cookie:", "#HttpOnly_", "Cookie:#HttpOnly_"] {
            assert!(normalized_label(raw).is_err());
        }
        // Do not substitute Rust's expanding Unicode lowercasing for the
        // unverified locale-dependent, per-UTF-16-unit native CRT mapping.
        assert_eq!(normalized_label("İ.TEST").unwrap(), "İ.test");
    }

    #[test]
    fn observation_bounds_and_invalid_host_encoding_do_not_yield_partial_row_sets() {
        for extra in [
            "INSERT INTO cookies VALUES('.example.test','name','/',1,1,1,zeroblob(67108864))",
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100001) INSERT INTO cookies SELECT '.example.test','name','/',1,x,1,NULL FROM n",
            "INSERT INTO cookies VALUES(CAST(X'FF' AS TEXT),'name','/',1,1,1,NULL)",
            // Ineligible rows still count toward the observation bound.
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100001) INSERT INTO cookies SELECT '', 'name','/',1,NULL,1,NULL FROM n",
        ] {
            let db = Connection::open_in_memory().unwrap();
            db.execute_batch("CREATE TABLE cookies(host_key TEXT,name TEXT,path TEXT,expires_utc INTEGER,creation_utc INTEGER,last_access_utc INTEGER,encrypted_value BLOB)").unwrap();
            db.execute_batch(extra).unwrap();
            assert!(
                Snapshot::read(&db, TableKind::ChromiumCookies, &AtomicBool::new(false)).is_err()
            );
            assert!(
                db.query_row("SELECT count(*) FROM cookies", [], |r| r.get::<_, i64>(0))
                    .unwrap()
                    > 0
            );
        }
    }
}
