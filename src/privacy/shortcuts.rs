//! Shortcut history uses native text prefixes and exact bookmark URLs. Private
//! row IDs replace the reference's interpolated declared-ID delete predicate.
use super::*;
use std::{collections::BTreeMap, sync::Arc};

const MAX_ROWS: usize = 100_000;
#[derive(Clone, Copy)]
struct Limits {
    rows: usize,
    bytes: usize,
}
#[derive(Clone, PartialEq)]
struct Context {
    schema: [u8; 32],
    bookmarks: Option<chromium_history::Bookmarks>,
}
struct Row {
    site: String,
    fingerprint: [u8; 32],
}
#[derive(Clone)]
pub(super) struct Review {
    row_id: i64,
    fingerprint: [u8; 32],
    context: Arc<Context>,
}
pub(super) struct Snapshot {
    context: Arc<Context>,
    rows: BTreeMap<i64, Row>,
}
fn error(reason: String) -> String {
    reason.replace("Cookie", "Shortcut")
}
fn prefix<'a>(row: &'a rusqlite::Row<'_>, column: usize) -> Result<Option<&'a str>, String> {
    use rusqlite::types::ValueRef;
    match row
        .get_ref(column)
        .map_err(|_| "Shortcut text could not be read.")?
    {
        ValueRef::Null => Ok(None),
        ValueRef::Text(bytes) => {
            std::str::from_utf8(bytes.split(|b| *b == 0).next().unwrap_or_default())
                .map(|s| (!s.is_empty()).then_some(s))
                .map_err(|_| "Shortcut text encoding is unsupported.".into())
        }
        _ => Err("Shortcut text conversion is unsupported.".into()),
    }
}
impl Snapshot {
    pub(super) fn read(
        conn: &Connection,
        root: &Path,
        cancel: &AtomicBool,
    ) -> Result<Self, String> {
        Self::read_with_limits(
            conn,
            root,
            cancel,
            Limits {
                rows: MAX_ROWS,
                bytes: 64 * 1024 * 1024,
            },
        )
    }
    fn read_with_limits(
        conn: &Connection,
        root: &Path,
        cancel: &AtomicBool,
        limits: Limits,
    ) -> Result<Self, String> {
        if cancel.load(Ordering::Relaxed) {
            return Err("Shortcut observation was cancelled.".into());
        }
        if !has_table(conn, "omni_box_shortcuts")
            .map_err(|_| "Shortcut schema could not be read.")?
        {
            let exists: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='omni_box_shortcuts' COLLATE NOCASE)", [], |r| r.get(0))
                .map_err(|_| "Shortcut schema could not be read.")?;
            if exists {
                return Err("Shortcut history has an unsupported table object.".into());
            }
            return Ok(Self {
                context: Arc::new(Context {
                    schema: [0; 32],
                    bookmarks: None,
                }),
                rows: BTreeMap::new(),
            });
        }
        let bookmarks = chromium_history::Bookmarks::read(root)?;
        let schema =
            cookies::schema_for_table(conn, "omni_box_shortcuts", cancel).map_err(error)?;
        let utf16 = conn
            .query_row("PRAGMA encoding", [], |r| r.get::<_, String>(0))
            .map_err(|_| "Shortcut text encoding could not be read.")?
            .starts_with("UTF-16");
        let mut statement = conn.prepare(&format!(
            "SELECT rowid,*,CAST(url AS TEXT),CAST(id AS TEXT) FROM omni_box_shortcuts ORDER BY rowid LIMIT {}",
            limits.rows.saturating_add(1),
        )).map_err(|_| "Shortcut rows have an unsupported layout.")?;
        let raw_url = statement
            .column_index("url")
            .map_err(|_| "Shortcut URL column is missing.")?;
        let raw_id = statement
            .column_index("id")
            .map_err(|_| "Shortcut ID column is missing.")?;
        let url_column = statement.column_count() - 2;
        let id_column = statement.column_count() - 1;
        let mut query = statement
            .query([])
            .map_err(|_| "Shortcut rows could not be read.")?;
        let mut rows = BTreeMap::new();
        let mut observed = 0;
        let mut bytes = 0;
        while let Some(row) = query
            .next()
            .map_err(|_| "Shortcut rows could not be read consistently.")?
        {
            if cancel.load(Ordering::Relaxed) {
                return Err("Shortcut observation was cancelled.".into());
            }
            observed += 1;
            if observed > limits.rows {
                return Err("Shortcut observation exceeds the safe row limit.".into());
            }
            if utf16 {
                for column in [raw_url, raw_id] {
                    if matches!(row.get_ref(column), Ok(rusqlite::types::ValueRef::Blob(v)) if v.len()%2!=0)
                    {
                        return Err("Shortcut text has an unsupported odd-byte UTF-16 blob.".into());
                    }
                }
            }
            if prefix(row, id_column)?.is_none() {
                continue;
            }
            let url = prefix(row, url_column)?;
            if url.is_some_and(|url| bookmarks.contains(url)) {
                continue;
            }
            let site = url
                .map(safe_site_label)
                .unwrap_or_else(|| "Empty shortcut URL".into());
            let row_id = row
                .get(0)
                .map_err(|_| "Shortcut row identity is unsupported.")?;
            let fingerprint = cookies::fingerprint(row, &mut bytes).map_err(error)?;
            if bytes > limits.bytes {
                return Err("Shortcut observation exceeds the safe byte limit.".into());
            }
            if rows.insert(row_id, Row { site, fingerprint }).is_some() {
                return Err("Shortcut row identity is ambiguous.".into());
            }
        }
        if bookmarks != chromium_history::Bookmarks::read(root)? {
            return Err("Browser bookmarks changed during shortcut inventory.".into());
        }
        Ok(Self {
            context: Arc::new(Context {
                schema,
                bookmarks: Some(bookmarks),
            }),
            rows,
        })
    }
    pub(super) fn bookmarks_unchanged(&self, root: &Path) -> Result<(), String> {
        if let Some(bookmarks) = &self.context.bookmarks
            && *bookmarks != chromium_history::Bookmarks::read(root)?
        {
            return Err(
                "Browser bookmarks changed since review; shortcut cleanup was rolled back.".into(),
            );
        }
        Ok(())
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
                        context: self.context.clone(),
                    },
                )
            })
            .collect()
    }
}
impl Review {
    pub(super) fn matches(
        &self,
        current: &Snapshot,
        shared: &mut HashMap<(usize, usize), bool>,
    ) -> bool {
        let context = *shared
            .entry((
                Arc::as_ptr(&self.context) as usize,
                Arc::as_ptr(&current.context) as usize,
            ))
            .or_insert_with(|| self.context == current.context);
        context
            && current
                .rows
                .get(&self.row_id)
                .is_some_and(|row| row.fingerprint == self.fingerprint)
    }
    pub(super) fn delete(&self, tx: &rusqlite::Transaction<'_>) -> Result<usize, String> {
        tx.execute(
            "DELETE FROM omni_box_shortcuts WHERE rowid=?1",
            [self.row_id],
        )
        .map_err(|_| "A reviewed shortcut could not be removed transactionally.".into())
    }
}

#[cfg(test)]
#[path = "shortcuts_tests.rs"]
mod tests;
pub(super) fn scan(
    conn: &Connection,
    profile: &BrowserProfile,
    path: &Path,
    stamp: &FileStamp,
    cancel: &AtomicBool,
    report: &mut PrivacyReport,
) {
    let observed = conn
        .execute_batch("BEGIN")
        .map_err(|_| "Shortcut snapshot could not be opened.".to_owned())
        .and_then(|_| Snapshot::read(conn, &profile.root, cancel));
    match observed {
        Ok(snapshot) => {
            for (site, row_id, shortcut) in snapshot.reviews() {
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
                        database: path.to_owned(),
                        database_stamp: stamp.clone(),
                        kind: TableKind::ChromiumShortcuts,
                        row_id,
                        identity: vec![],
                        history: None,
                        download: None,
                        firefox: None,
                        cookie: None,
                        quota: None,
                        keyword: None,
                        shortcut: Some(shortcut),
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
