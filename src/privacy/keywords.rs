//! HistoryKeywords owns eligible Web Data rows, not the whole database. The
//! schema-dependent predicate and default-provider observation bind review.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MAX_ROWS: usize = 100_000;
const MAX_META_BYTES: usize = 4096;
#[derive(Clone, Copy)]
struct Limits {
    rows: usize,
    bytes: usize,
}

#[derive(Clone)]
pub(super) struct Review {
    row_id: i64,
    fingerprint: [u8; 32],
    context: [u8; 32],
}
struct Row {
    site: String,
    fingerprint: [u8; 32],
}
pub(super) struct Snapshot {
    context: [u8; 32],
    rows: BTreeMap<i64, Row>,
}

fn error(reason: String) -> String {
    reason.replace("Cookie", "Keyword")
}

fn default_provider(conn: &Connection) -> Result<(i32, [u8; 32]), String> {
    // A native metadata SQL exception exits before counting. An empty query
    // result instead returns zero; retain that distinction in scan omissions.
    let mut statement = conn.prepare(
        "SELECT value, CAST(value AS INTEGER) FROM meta WHERE key='Default Search Provider ID' LIMIT 2",
    ).map_err(|_| "Keyword default-provider metadata is missing or unsupported.")?;
    let mut rows = statement
        .query([])
        .map_err(|_| "Keyword default-provider metadata could not be read.")?;
    let mut bytes = 0;
    let (value, digest) = match rows
        .next()
        .map_err(|_| "Keyword default-provider metadata could not be read.")?
    {
        None => (
            0,
            Sha256::digest(b"keyword-default-provider-empty-result").into(),
        ),
        Some(row) => {
            if matches!(row.get_ref(0), Ok(rusqlite::types::ValueRef::Text(value) | rusqlite::types::ValueRef::Blob(value)) if value.len() > MAX_META_BYTES)
            {
                return Err("Keyword default-provider metadata exceeds the safe limit.".into());
            }
            let digest = cookies::fingerprint(row, &mut bytes).map_err(error)?;
            if bytes > MAX_META_BYTES {
                return Err("Keyword default-provider metadata exceeds the safe limit.".into());
            }
            let number: Option<i64> = row
                .get(1)
                .map_err(|_| "Keyword default-provider metadata has an unsupported scalar.")?;
            (number.unwrap_or(0) as i32, digest)
        }
    };
    if rows
        .next()
        .map_err(|_| "Keyword default-provider metadata could not be read.")?
        .is_some()
    {
        return Err("Keyword default-provider metadata is ambiguous.".into());
    }
    Ok((value, digest))
}

impl Snapshot {
    pub(super) fn read(conn: &Connection, cancel: &AtomicBool) -> Result<Self, String> {
        Self::read_with_limits(
            conn,
            cancel,
            Limits {
                rows: MAX_ROWS,
                bytes: 64 * 1024 * 1024,
            },
        )
    }
    fn read_with_limits(
        conn: &Connection,
        cancel: &AtomicBool,
        limits: Limits,
    ) -> Result<Self, String> {
        if cancel.load(Ordering::Relaxed) {
            return Err("Keyword observation was cancelled.".into());
        }
        if !has_table(conn, "keywords").map_err(|_| "Keyword schema could not be read.")? {
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='keywords' COLLATE NOCASE)",
                [], |row| row.get(0),
            ).map_err(|_| "Keyword schema could not be read.")?;
            if exists {
                return Err("Keyword storage has an unsupported table object.".into());
            }
            return Ok(Self {
                context: [0; 32],
                rows: BTreeMap::new(),
            });
        }
        let schema = cookies::schema_for_table(conn, "keywords", cancel).map_err(error)?;
        // Native probe steps SELECT show_in_default_list,safe_for_autoreplace;
        // its nonempty result selects the legacy discriminator.
        let legacy = (|| -> rusqlite::Result<bool> {
            let mut probe =
                conn.prepare("SELECT show_in_default_list, safe_for_autoreplace FROM keywords")?;
            let mut rows = probe.query([])?;
            Ok(rows.next()?.is_some())
        })()
        .unwrap_or(false);
        let discriminator = if legacy {
            "show_in_default_list"
        } else {
            "prepopulate_id"
        };
        let (provider, metadata) = default_provider(conn)?;
        let mut context = Sha256::new();
        context.update(schema);
        context.update(metadata);
        context.update(discriminator.as_bytes());
        let context = context.finalize().into();
        let condition = if provider >= 0 { " AND id != ?1" } else { "" };
        let sql = format!(
            "SELECT rowid,* FROM keywords WHERE {discriminator}=0 AND safe_for_autoreplace=1{condition} ORDER BY rowid LIMIT {}",
            limits.rows.saturating_add(1)
        );
        let mut statement = conn
            .prepare(&sql)
            .map_err(|_| "Keyword storage has an unsupported eligibility schema.")?;
        let url = statement.column_index("url").ok();
        let mut query = if provider >= 0 {
            statement.query([i64::from(provider)])
        } else {
            statement.query([])
        }
        .map_err(|_| "Keyword rows could not be read.")?;
        let mut rows = BTreeMap::new();
        let mut bytes = 0;
        while let Some(row) = query
            .next()
            .map_err(|_| "Keyword rows could not be read consistently.")?
        {
            if cancel.load(Ordering::Relaxed) {
                return Err("Keyword observation was cancelled.".into());
            }
            if rows.len() >= limits.rows {
                return Err("Keyword observation exceeds the safe row limit.".into());
            }
            let row_id: i64 = row
                .get(0)
                .map_err(|_| "Keyword row identity is unsupported.")?;
            let fingerprint = cookies::fingerprint(row, &mut bytes).map_err(error)?;
            if bytes > limits.bytes {
                return Err("Keyword observation exceeds the safe byte limit.".into());
            }
            let site = url
                .and_then(|index| row.get::<_, String>(index).ok())
                .map(|value| safe_site_label(&value))
                .unwrap_or_else(|| "Keyword history".into());
            if rows.insert(row_id, Row { site, fingerprint }).is_some() {
                return Err("Keyword row identity is ambiguous.".into());
            }
        }
        Ok(Self { context, rows })
    }
    fn reviews(&self) -> Vec<(String, i64, Review)> {
        self.rows
            .iter()
            .map(|(&row_id, row)| {
                (
                    row.site.clone(),
                    row_id,
                    Review {
                        row_id,
                        fingerprint: row.fingerprint,
                        context: self.context,
                    },
                )
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "keywords_tests.rs"]
mod tests;
impl Review {
    pub(super) fn matches(&self, current: &Snapshot) -> bool {
        self.context == current.context
            && current
                .rows
                .get(&self.row_id)
                .is_some_and(|row| row.fingerprint == self.fingerprint)
    }
    pub(super) fn delete(&self, tx: &rusqlite::Transaction<'_>) -> Result<usize, String> {
        tx.execute("DELETE FROM keywords WHERE rowid=?1", [self.row_id])
            .map_err(|_| "A reviewed keyword row could not be removed transactionally.".into())
    }
}

pub(super) fn scan(
    conn: &Connection,
    profile: &BrowserProfile,
    canonical: &Path,
    stamp: &FileStamp,
    cancel: &AtomicBool,
    report: &mut PrivacyReport,
) {
    let observed = conn
        .execute_batch("BEGIN")
        .map_err(|_| "Keyword snapshot could not be opened.".to_owned())
        .and_then(|_| Snapshot::read(conn, cancel));
    match observed {
        Ok(snapshot) => {
            for (site, row_id, review) in snapshot.reviews() {
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
                        database: canonical.to_owned(),
                        database_stamp: stamp.clone(),
                        kind: TableKind::ChromiumKeywords,
                        row_id,
                        identity: Vec::new(),
                        history: None,
                        download: None,
                        firefox: None,
                        cookie: None,
                        quota: None,
                        keyword: Some(review),
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
}
