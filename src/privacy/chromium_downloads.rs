//! Reviewed row ownership for the reference's four download-history tables.
//! Opaque legacy rows stay independent unless a declared single-column foreign
//! key proves their download owner. Column names alone never imply ownership.

use super::*;
use std::{collections::BTreeMap, sync::Arc};

const MAX_ROWS: usize = 100_000;
const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum Table {
    Downloads,
    Chains,
    Slices,
    Accelerated,
}

impl Table {
    fn name(self) -> &'static str {
        match self {
            Self::Downloads => "downloads",
            Self::Chains => "downloads_url_chains",
            Self::Slices => "downloads_slices",
            Self::Accelerated => "accelerated_downloads",
        }
    }
    fn required(self) -> &'static [&'static str] {
        match self {
            Self::Downloads => &["id"],
            Self::Chains => &["id", "chain_index", "url"],
            Self::Slices => &["download_id"],
            Self::Accelerated => &[],
        }
    }
}

#[derive(Clone, PartialEq)]
struct Shape {
    table: Table,
    columns: Arc<Vec<String>>,
    sql: String,
}

#[derive(Clone, PartialEq)]
struct Compatibility {
    schema: String,
    value: Value,
}

fn compatibility(
    conn: &Connection,
) -> Result<(Option<Compatibility>, Option<&'static str>), String> {
    let schema: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='meta'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| "Download compatibility metadata is unreadable.")?;
    let Some(schema) = schema else {
        return Ok((
            None,
            Some("Download compatibility metadata is missing; its records were not listed."),
        ));
    };
    if schema.len() > 65_536
        || schema
            .trim_start()
            .to_ascii_uppercase()
            .starts_with("CREATE VIRTUAL")
    {
        return Err("Download compatibility metadata has an unsupported layout.".into());
    }
    let mut statement = conn.prepare(
        "SELECT value, CAST(value AS INTEGER) FROM meta WHERE key='last_compatible_version' LIMIT 2",
    ).map_err(|_| "Download compatibility metadata has an unsupported schema.")?;
    let mut rows = statement
        .query([])
        .map_err(|_| "Download compatibility metadata could not be read.")?;
    let Some(row) = rows
        .next()
        .map_err(|_| "Download compatibility metadata could not be read.")?
    else {
        return Ok((
            None,
            Some("Download compatibility version is missing; its records were not listed."),
        ));
    };
    let value = row
        .get_ref(0)
        .map_err(|_| "Download compatibility value is unsupported.")?;
    if let rusqlite::types::ValueRef::Text(bytes) | rusqlite::types::ValueRef::Blob(bytes) = value {
        if bytes.len() > 1024 {
            return Err("Download compatibility value exceeds the safe limit.".into());
        }
    }
    if let rusqlite::types::ValueRef::Text(bytes) = value {
        std::str::from_utf8(bytes)
            .map_err(|_| "Download compatibility text encoding is unsupported.")?;
    }
    let value = Value::from(value);
    let version: Option<i64> = row
        .get(1)
        .map_err(|_| "Download compatibility version is unsupported.")?;
    if rows
        .next()
        .map_err(|_| "Download compatibility metadata could not be read.")?
        .is_some()
    {
        return Err("Download compatibility metadata is ambiguous.".into());
    }
    let observation = Some(Compatibility { schema, value });
    // The shipped handler reads this scalar as a 32-bit integer and accepts
    // last_compatible_version 15 or 16. Bind both its value and schema to review.
    if version.is_some_and(|version| matches!(version as u32, 15 | 16)) {
        Ok((observation, None))
    } else {
        Ok((
            observation,
            Some(
                "This download database has an unsupported compatibility version; its records were not listed.",
            ),
        ))
    }
}

#[derive(Clone, PartialEq)]
struct Row {
    table: Table,
    id: i64,
    columns: Arc<Vec<String>>,
    values: Vec<Value>,
}

impl Row {
    fn value(&self, column: &str) -> Option<&Value> {
        self.columns
            .iter()
            .position(|name| name == column)
            .and_then(|i| self.values.get(i))
    }
    fn integer(&self, column: &str) -> Result<Option<i64>, String> {
        match self.value(column) {
            Some(Value::Integer(id)) => Ok(Some(*id)),
            Some(Value::Null) => Ok(None),
            _ => Err("A download-history relationship is unsupported.".into()),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
enum Key {
    Download(i64),
    Chain(i64),
    Slice(i64),
    Accelerated(i64),
}

#[derive(Clone, PartialEq)]
struct Group {
    key: Key,
    rows: Vec<Row>,
}

#[derive(Clone)]
pub(super) struct Review {
    group: Arc<Group>,
    shapes: Arc<Vec<Shape>>,
    compatibility: Arc<Option<Compatibility>>,
}

impl Review {
    pub(super) fn item_count(&self) -> usize {
        self.group.rows.len()
    }
    pub(super) fn priority(&self) -> u8 {
        u8::from(matches!(self.group.key, Key::Download(_)))
    }
    pub(super) fn matches(&self, current: &Snapshot, shared: &mut HashMap<usize, bool>) -> bool {
        let same_schema = *shared
            .entry(Arc::as_ptr(&self.shapes) as usize)
            .or_insert_with(|| {
                self.shapes == current.shapes && self.compatibility == current.compatibility
            });
        same_schema && current.groups.get(&self.group.key) == Some(&self.group)
    }
    pub(super) fn delete(&self, tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<usize> {
        for table in [
            Table::Accelerated,
            Table::Chains,
            Table::Slices,
            Table::Downloads,
        ] {
            for row in self.group.rows.iter().filter(|row| row.table == table) {
                if tx.execute(
                    &format!("DELETE FROM {} WHERE rowid=?1", table.name()),
                    [row.id],
                )? != 1
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
        }
        Ok(1)
    }
}

pub(super) struct Snapshot {
    groups: BTreeMap<Key, Arc<Group>>,
    shapes: Arc<Vec<Shape>>,
    compatibility: Arc<Option<Compatibility>>,
    pub(super) omission: Option<&'static str>,
    pub(super) compaction_pending: bool,
}

impl Snapshot {
    pub(super) fn read(conn: &Connection, cancel: &AtomicBool) -> Result<Self, String> {
        let (version, omission) = compatibility(conn)?;
        let compatibility = Arc::new(version);
        if omission.is_some() {
            return Ok(Self {
                groups: BTreeMap::new(),
                shapes: Arc::new(Vec::new()),
                compatibility,
                omission,
                compaction_pending: false,
            });
        }
        let mut groups = BTreeMap::<Key, Group>::new();
        let mut parents = HashSet::new();
        let mut shapes = Vec::new();
        let mut total_rows = 0;
        let mut total_bytes = 0usize;
        for table in [
            Table::Downloads,
            Table::Chains,
            Table::Slices,
            Table::Accelerated,
        ] {
            let sql: Option<String> = conn
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                    [table.name()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| "Download-history schema is unreadable.")?;
            let Some(sql) = sql else {
                continue;
            };
            if sql
                .trim_start()
                .to_ascii_uppercase()
                .starts_with("CREATE VIRTUAL")
            {
                return Err("Virtual download-history tables are unsupported.".into());
            }
            let mut statement = conn
                .prepare(&format!(
                    "SELECT rowid,* FROM {} ORDER BY rowid LIMIT ?1",
                    table.name()
                ))
                .map_err(|_| "Download-history row identity is unsupported.")?;
            let columns = Arc::new(
                statement
                    .column_names()
                    .iter()
                    .skip(1)
                    .map(|s| (*s).to_owned())
                    .collect::<Vec<_>>(),
            );
            if columns
                .iter()
                .any(|name| name.eq_ignore_ascii_case("rowid"))
                || !table
                    .required()
                    .iter()
                    .all(|name| columns.iter().any(|column| column == name))
            {
                return Err("Download-history columns are unsupported.".into());
            }
            shapes.push(Shape {
                table,
                columns: columns.clone(),
                sql,
            });
            let accelerated_parent = if table == Table::Accelerated {
                let mut foreign_keys = conn
                    .prepare("PRAGMA foreign_key_list(accelerated_downloads)")
                    .map_err(|_| "Legacy download relationships could not be inspected.")?;
                let links = foreign_keys
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    })
                    .map_err(|_| "Legacy download relationships could not be inspected.")?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(|_| "Legacy download relationships could not be inspected.")?;
                let links = links
                    .into_iter()
                    .filter(|(_, target, _, _)| target.eq_ignore_ascii_case("downloads"))
                    .collect::<Vec<_>>();
                if links.len() > 1
                    || links.first().is_some_and(|(sequence, _, _, column)| {
                        *sequence != 0
                            || column
                                .as_ref()
                                .is_some_and(|column| !column.eq_ignore_ascii_case("id"))
                    })
                {
                    return Err("Composite legacy download relationships are unsupported.".into());
                }
                links.into_iter().next().map(|(_, _, source, _)| source)
            } else {
                None
            };
            let mut rows = statement
                .query([(MAX_ROWS - total_rows + 1) as i64])
                .map_err(|_| "Download-history rows could not be read.")?;
            while let Some(row) = rows
                .next()
                .map_err(|_| "Download-history rows could not be read.")?
            {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Download-history inventory was cancelled.".into());
                }
                total_rows += 1;
                if total_rows > MAX_ROWS {
                    return Err("Download-history inventory limit reached.".into());
                }
                let id: i64 = row
                    .get(0)
                    .map_err(|_| "Download-history row identity is unsupported.")?;
                let mut values = Vec::new();
                for index in 1..row.as_ref().column_count() {
                    let value = row
                        .get_ref(index)
                        .map_err(|_| "Download-history content is unsupported.")?;
                    total_bytes = total_bytes.saturating_add(match value {
                        rusqlite::types::ValueRef::Text(b) | rusqlite::types::ValueRef::Blob(b) => {
                            b.len()
                        }
                        _ => 8,
                    });
                    if total_bytes > MAX_BYTES {
                        return Err("Download-history content limit reached.".into());
                    }
                    if let rusqlite::types::ValueRef::Text(bytes) = value {
                        std::str::from_utf8(bytes)
                            .map_err(|_| "Download-history text encoding is unsupported.")?;
                    }
                    values.push(Value::from(value));
                }
                let row = Row {
                    table,
                    id,
                    columns: columns.clone(),
                    values,
                };
                let key = match table {
                    Table::Downloads => {
                        if row.integer("id")? != Some(id) {
                            return Err("Download primary row identity is unsupported.".into());
                        }
                        parents.insert(id);
                        Key::Download(id)
                    }
                    Table::Chains => row
                        .integer("id")?
                        .filter(|id| parents.contains(id))
                        .map(Key::Download)
                        .unwrap_or(Key::Chain(id)),
                    Table::Slices => row
                        .integer("download_id")?
                        .filter(|id| parents.contains(id))
                        .map(Key::Download)
                        .unwrap_or(Key::Slice(id)),
                    Table::Accelerated => match accelerated_parent.as_deref() {
                        Some(column) => row
                            .integer(column)?
                            .filter(|id| parents.contains(id))
                            .map(Key::Download)
                            .unwrap_or(Key::Accelerated(id)),
                        None => Key::Accelerated(id),
                    },
                };
                groups
                    .entry(key.clone())
                    .or_insert_with(|| Group {
                        key,
                        rows: Vec::new(),
                    })
                    .rows
                    .push(row);
            }
        }
        let free_pages: i64 = conn
            .query_row("PRAGMA freelist_count", [], |row| row.get(0))
            .map_err(|_| "Database free pages could not be inspected.")?;
        Ok(Self {
            groups: groups
                .into_iter()
                .map(|(key, group)| (key, Arc::new(group)))
                .collect(),
            shapes: Arc::new(shapes),
            compatibility,
            omission: None,
            compaction_pending: free_pages > 0,
        })
    }

    pub(super) fn reviews(&self) -> impl Iterator<Item = (String, i64, Review)> + '_ {
        self.groups.values().map(|group| {
            let site = group
                .rows
                .iter()
                .filter(|row| row.table == Table::Chains)
                .filter_map(|row| {
                    match (row.integer("chain_index").ok().flatten(), row.value("url")) {
                        (Some(index), Some(Value::Text(url))) => Some((index, url)),
                        _ => None,
                    }
                })
                .max_by_key(|(index, _)| *index)
                .map(|(_, url)| safe_site_label(url))
                .unwrap_or_default();
            let id = match group.key {
                Key::Download(id) | Key::Chain(id) | Key::Slice(id) | Key::Accelerated(id) => id,
            };
            (
                site,
                id,
                Review {
                    group: group.clone(),
                    shapes: self.shapes.clone(),
                    compatibility: self.compatibility.clone(),
                },
            )
        })
    }
}
