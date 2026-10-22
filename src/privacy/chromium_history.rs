//! Disjoint reviewed ownership for the six core Chromium history tables.
//!
//! The reference counts these physical rows separately and retains bookmarked
//! URL rows. A UI target owns its dependencies; it never authorizes a table wipe.

use super::*;
use std::{collections::BTreeMap, sync::Arc};

const MAX_CORE_ROWS: usize = 100_000;
const MAX_CORE_BYTES: usize = 64 * 1024 * 1024;
const MAX_BOOKMARK_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Table {
    Urls,
    Visits,
    Sources,
    Segments,
    Usage,
    Keywords,
}

impl Table {
    fn name(self) -> &'static str {
        match self {
            Self::Urls => "urls",
            Self::Visits => "visits",
            Self::Sources => "visit_source",
            Self::Segments => "segments",
            Self::Usage => "segment_usage",
            Self::Keywords => "keyword_search_terms",
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum Key {
    Url(i64),
    Visit(i64),
    Segment(i64),
    Source(i64),
    Usage(i64),
    Keyword(i64),
}

#[derive(Clone, PartialEq)]
struct CoreRow {
    table: Table,
    rowid: i64,
    columns: Arc<Vec<String>>,
    values: Vec<Value>,
}

impl CoreRow {
    fn value(&self, name: &str) -> Result<&Value, String> {
        self.columns
            .iter()
            .position(|column| column == name)
            .and_then(|index| self.values.get(index))
            .ok_or_else(|| "A browser history column is unavailable.".into())
    }

    fn integer(&self, name: &str) -> Result<Option<i64>, String> {
        match self.value(name)? {
            Value::Integer(id) => Ok(Some(*id)),
            Value::Null => Ok(None),
            _ => Err("A browser history relationship has an unsupported type.".into()),
        }
    }

    fn url(&self) -> Result<&str, String> {
        match self.value("url")? {
            Value::Text(url) => Ok(url),
            Value::Null => Ok(""),
            _ => Err("A browser history URL has an unsupported type.".into()),
        }
    }
}

#[derive(Clone, PartialEq)]
pub(super) struct Group {
    key: Key,
    rows: Vec<CoreRow>,
    preserve_url: bool,
}

impl Group {
    pub(super) fn item_count(&self) -> usize {
        self.rows.len() - usize::from(self.preserve_url)
    }

    pub(super) fn site(&self) -> String {
        self.rows
            .iter()
            .find(|row| row.table == Table::Urls)
            .and_then(|row| row.url().ok())
            .map(safe_site_label)
            .unwrap_or_default()
    }

    pub(super) fn row_id(&self) -> i64 {
        match self.key {
            Key::Url(id)
            | Key::Visit(id)
            | Key::Segment(id)
            | Key::Source(id)
            | Key::Usage(id)
            | Key::Keyword(id) => id,
        }
    }

    pub(super) fn delete(&self, tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<usize> {
        // Validate all selected groups before entering this method. Internal
        // referring-visit repairs may legitimately change another selected row.
        for row in self.rows.iter().filter(|row| row.table == Table::Visits) {
            let id = row
                .integer("id")
                .map_err(|_| rusqlite::Error::InvalidQuery)?
                .ok_or(rusqlite::Error::InvalidQuery)?;
            for table in ["content_annotations", "context_annotations"] {
                if has_table(tx, table)? {
                    tx.execute(&format!("DELETE FROM {table} WHERE visit_id=?1"), [id])?;
                }
            }
            delete_chromium_cluster_visit(tx, id)?;
        }
        for table in [
            Table::Sources,
            Table::Visits,
            Table::Usage,
            Table::Segments,
            Table::Keywords,
            Table::Urls,
        ] {
            if table == Table::Urls && self.preserve_url {
                continue;
            }
            for row in self.rows.iter().filter(|row| row.table == table) {
                let changed = tx.execute(
                    &format!("DELETE FROM {} WHERE rowid=?1", table.name()),
                    [row.rowid],
                )?;
                if changed != 1 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
        }
        Ok(1) // One reviewed target, containing item_count() core database rows.
    }
}

#[derive(Clone, PartialEq)]
pub(super) struct Bookmarks {
    stamp: Option<FileStamp>,
    identity: Option<(u64, u64)>,
    urls: HashSet<String>,
}

impl Bookmarks {
    pub(super) fn read(profile: &Path) -> Result<Self, String> {
        let path = profile.join("Bookmarks");
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    stamp: None,
                    identity: None,
                    urls: HashSet::new(),
                });
            }
            Err(_) => return Err("Browser bookmarks could not be inspected.".into()),
            Ok(_) => {}
        }
        let (path, before, _) = validate_database_path(profile, &path)
            .map_err(|_| "Browser bookmarks are linked, redirected or unreadable.".to_owned())?;
        if before.length > MAX_BOOKMARK_BYTES {
            return Err("Browser bookmarks exceed the safe inventory limit.".into());
        }
        let mut bytes = Vec::new();
        let mut file = storage_files::open_file(profile, &path)?;
        let identity = storage_files::identity(&file)?;
        std::io::Read::by_ref(&mut file)
            .take(MAX_BOOKMARK_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Browser bookmarks could not be read.".to_owned())?;
        if bytes.len() as u64 > MAX_BOOKMARK_BYTES {
            return Err("Browser bookmarks exceed the safe inventory limit.".into());
        }
        let json: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| "Browser bookmark JSON is unsupported or incomplete.".to_owned())?;
        if !json.is_object() {
            return Err("Browser bookmark JSON is not an object.".into());
        }
        let mut pending = vec![&json];
        let mut urls = HashSet::new();
        while let Some(value) = pending.pop() {
            match value {
                serde_json::Value::Object(object) => {
                    for (key, child) in object {
                        if key == "url"
                            && let Some(url) = child.as_str()
                        {
                            urls.insert(url.to_owned());
                        } else if child.is_object() || child.is_array() {
                            pending.push(child);
                        }
                    }
                }
                serde_json::Value::Array(array) => pending.extend(array),
                _ => {}
            }
        }
        if file_stamp(&path)? != before
            || storage_files::identity(&storage_files::open_file(profile, &path)?)? != identity
        {
            return Err("Browser bookmarks changed during inventory.".into());
        }
        Ok(Self {
            stamp: Some(before),
            identity: Some(identity),
            urls,
        })
    }
    pub(super) fn contains(&self, url: &str) -> bool {
        self.urls.contains(url)
    }
}

#[derive(Clone)]
pub(super) struct Review {
    group: Arc<Group>,
    bookmarks: Arc<Bookmarks>,
    dependencies: Arc<Vec<DependencyTable>>,
}

impl Review {
    pub(super) fn item_count(&self) -> usize {
        self.group.item_count()
    }
    pub(super) fn matches(
        &self,
        current: &Snapshot,
        shared: &mut HashMap<(usize, usize), bool>,
    ) -> bool {
        // Source Arcs stay alive for this validation pass. Their addresses only
        // cache an equality result; they never grant cleanup authority.
        let key = (
            Arc::as_ptr(&self.bookmarks) as usize,
            Arc::as_ptr(&self.dependencies) as usize,
        );
        let unchanged = *shared.entry(key).or_insert_with(|| {
            self.bookmarks == current.bookmarks && self.dependencies == current.dependencies
        });
        unchanged && current.groups.get(&self.group.key) == Some(&self.group)
    }
    pub(super) fn delete(&self, tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<usize> {
        self.group.delete(tx)
    }
}

pub(super) struct Snapshot {
    groups: BTreeMap<Key, Arc<Group>>,
    bookmarks: Arc<Bookmarks>,
    dependencies: Arc<Vec<DependencyTable>>,
}

/// Shared annotation/cluster observations guard cleanup without contributing
/// unverified units to the reference's six-table count. Shared clusters cannot
/// safely be assigned to just one URL, so any drift invalidates history review.
#[derive(Clone, PartialEq)]
struct DependencyTable {
    name: &'static str,
    columns: Vec<String>,
    rows: Vec<(i64, Vec<Value>)>,
}

fn dependency_tables(
    conn: &Connection,
    cancel: &AtomicBool,
    total_rows: &mut usize,
    total_bytes: &mut usize,
) -> Result<Vec<DependencyTable>, String> {
    let mut observed = Vec::new();
    for table in [
        "content_annotations",
        "context_annotations",
        "clusters_and_visits",
        "cluster_visit_duplicates",
        "clusters",
        "cluster_keywords",
    ] {
        if !has_table(conn, table).map_err(|_| "History dependencies are unreadable.")? {
            continue;
        }
        let mut statement = conn
            .prepare(&format!(
                "SELECT rowid,* FROM {table} ORDER BY rowid LIMIT ?1"
            ))
            .map_err(|_| "History dependency layout is unsupported.")?;
        let columns = statement
            .column_names()
            .iter()
            .skip(1)
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>();
        if columns
            .iter()
            .any(|name| name.eq_ignore_ascii_case("rowid"))
        {
            return Err("History dependency row identity is ambiguous.".into());
        }
        let mut table_rows = Vec::new();
        let mut rows = statement
            .query([(MAX_CORE_ROWS - *total_rows + 1) as i64])
            .map_err(|_| "History dependencies could not be read.")?;
        while let Some(row) = rows
            .next()
            .map_err(|_| "History dependencies could not be read.")?
        {
            if cancel.load(Ordering::Relaxed) {
                return Err("History inventory was cancelled.".into());
            }
            *total_rows += 1;
            if *total_rows > MAX_CORE_ROWS {
                return Err("History dependency inventory limit reached.".into());
            }
            let rowid: i64 = row
                .get(0)
                .map_err(|_| "History dependency row identity is unsupported.")?;
            let mut values = Vec::new();
            for index in 1..row.as_ref().column_count() {
                let value = row
                    .get_ref(index)
                    .map_err(|_| "History dependency content is unsupported.")?;
                *total_bytes = total_bytes.saturating_add(match value {
                    rusqlite::types::ValueRef::Text(bytes)
                    | rusqlite::types::ValueRef::Blob(bytes) => bytes.len(),
                    _ => 8,
                });
                if *total_bytes > MAX_CORE_BYTES {
                    return Err("History dependency content limit reached.".into());
                }
                if let rusqlite::types::ValueRef::Text(bytes) = value {
                    std::str::from_utf8(bytes)
                        .map_err(|_| "History dependency text encoding is unsupported.")?;
                }
                values.push(Value::from(value));
            }
            table_rows.push((rowid, values));
        }
        observed.push(DependencyTable {
            name: table,
            columns,
            rows: table_rows,
        });
    }
    Ok(observed)
}

impl Snapshot {
    pub(super) fn repair_visits<'a>(
        &self,
        tx: &rusqlite::Transaction<'_>,
        selected: impl Iterator<Item = &'a Review>,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        let selected = selected
            .flat_map(|review| review.group.rows.iter())
            .filter(|row| row.table == Table::Visits)
            .map(|row| row.rowid)
            .collect::<HashSet<_>>();
        if selected.is_empty() {
            return Ok(());
        }
        let mut parents = HashMap::new();
        for row in self
            .groups
            .values()
            .flat_map(|group| &group.rows)
            .filter(|row| row.table == Table::Visits)
        {
            parents.insert(row.rowid, row.integer("from_visit")?);
        }
        let mut resolved = HashMap::<i64, Option<i64>>::new();
        let mut repairs = Vec::new();
        for (&id, &parent) in &parents {
            if cancel.load(Ordering::Relaxed) {
                return Err("History cleanup was cancelled.".into());
            }
            if selected.contains(&id) {
                if parent.is_some() {
                    repairs.push((id, None));
                }
                continue;
            }
            if !parent.is_some_and(|p| selected.contains(&p)) {
                continue;
            }
            let mut cursor = parent;
            let mut path = Vec::new();
            let mut seen = HashSet::new();
            while let Some(ancestor) = cursor {
                if !selected.contains(&ancestor) {
                    if !parents.contains_key(&ancestor) {
                        cursor = None;
                    }
                    break;
                }
                if let Some(&known) = resolved.get(&ancestor) {
                    cursor = known;
                    break;
                }
                if !seen.insert(ancestor) {
                    cursor = None;
                    break;
                }
                path.push(ancestor);
                cursor = parents.get(&ancestor).copied().flatten();
            }
            for ancestor in path {
                resolved.insert(ancestor, cursor);
            }
            repairs.push((id, cursor));
        }
        let mut update = tx
            .prepare("UPDATE visits SET from_visit=?1 WHERE rowid=?2")
            .map_err(|_| "History reference repair could not be prepared.".to_owned())?;
        for (id, parent) in repairs {
            if cancel.load(Ordering::Relaxed) {
                return Err("History cleanup was cancelled.".into());
            }
            if update
                .execute(rusqlite::params![parent, id])
                .map_err(|_| "History reference repair failed.".to_owned())?
                != 1
            {
                return Err("History references changed during cleanup.".into());
            }
        }
        Ok(())
    }

    pub(super) fn read(
        conn: &Connection,
        profile: &Path,
        cancel: &AtomicBool,
    ) -> Result<Self, String> {
        let bookmarks = Arc::new(Bookmarks::read(profile)?);
        let mut groups = BTreeMap::<Key, Group>::new();
        let mut urls = HashMap::new();
        let mut visits = HashMap::new();
        let mut segments = HashMap::new();
        let mut total_rows = 0usize;
        let mut total_bytes = 0usize;
        for table in [
            Table::Urls,
            Table::Visits,
            Table::Segments,
            Table::Sources,
            Table::Usage,
            Table::Keywords,
        ] {
            if !has_table(conn, table.name()).map_err(|_| "History schema is unreadable.")? {
                continue;
            }
            let sql = format!(
                "SELECT rowid,* FROM {} ORDER BY rowid LIMIT ?1",
                table.name()
            );
            let mut statement = conn
                .prepare(&sql)
                .map_err(|_| "History table layout is unsupported.")?;
            let columns = Arc::new(
                statement
                    .column_names()
                    .iter()
                    .skip(1)
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>(),
            );
            // Hidden rowid aliases and virtual/generated layouts are not guessed.
            if columns
                .iter()
                .any(|name| name.eq_ignore_ascii_case("rowid"))
            {
                return Err("History row identity is ambiguous.".into());
            }
            let mut rows = statement
                .query([(MAX_CORE_ROWS - total_rows + 1) as i64])
                .map_err(|_| "History rows could not be read.")?;
            while let Some(row) = rows.next().map_err(|_| "History rows could not be read.")? {
                if cancel.load(Ordering::Relaxed) {
                    return Err("History inventory was cancelled.".into());
                }
                total_rows += 1;
                if total_rows > MAX_CORE_ROWS {
                    return Err("History row inventory limit reached.".into());
                }
                let rowid: i64 = row
                    .get(0)
                    .map_err(|_| "History row identity is unsupported.")?;
                let mut values = Vec::new();
                for index in 1..row.as_ref().column_count() {
                    let value = row
                        .get_ref(index)
                        .map_err(|_| "History row content is unsupported.")?;
                    total_bytes = total_bytes.saturating_add(match value {
                        rusqlite::types::ValueRef::Text(bytes)
                        | rusqlite::types::ValueRef::Blob(bytes) => bytes.len(),
                        _ => 8,
                    });
                    if total_bytes > MAX_CORE_BYTES {
                        return Err("History content inventory limit reached.".into());
                    }
                    if let rusqlite::types::ValueRef::Text(bytes) = value {
                        std::str::from_utf8(bytes)
                            .map_err(|_| "History text encoding is unsupported.")?;
                    }
                    values.push(Value::from(value));
                }
                let core = CoreRow {
                    table,
                    rowid,
                    columns: columns.clone(),
                    values,
                };
                if matches!(table, Table::Urls | Table::Visits | Table::Segments)
                    && core.integer("id")? != Some(rowid)
                {
                    return Err("History primary row identity is unsupported.".into());
                }
                let (key, preserve_url) = match table {
                    Table::Urls => {
                        urls.insert(rowid, Key::Url(rowid));
                        (Key::Url(rowid), bookmarks.urls.contains(core.url()?))
                    }
                    Table::Visits => {
                        let key = core
                            .integer("url")?
                            .and_then(|id| urls.get(&id).cloned())
                            .unwrap_or(Key::Visit(rowid));
                        visits.insert(rowid, key.clone());
                        (key, false)
                    }
                    Table::Segments => {
                        let key = core
                            .integer("url_id")?
                            .and_then(|id| urls.get(&id).cloned())
                            .unwrap_or(Key::Segment(rowid));
                        segments.insert(rowid, key.clone());
                        (key, false)
                    }
                    Table::Sources => (
                        core.integer("id")?
                            .and_then(|id| visits.get(&id).cloned())
                            .unwrap_or(Key::Source(rowid)),
                        false,
                    ),
                    Table::Usage => (
                        core.integer("segment_id")?
                            .and_then(|id| segments.get(&id).cloned())
                            .unwrap_or(Key::Usage(rowid)),
                        false,
                    ),
                    Table::Keywords => (
                        core.integer("url_id")?
                            .and_then(|id| urls.get(&id).cloned())
                            .unwrap_or(Key::Keyword(rowid)),
                        false,
                    ),
                };
                groups
                    .entry(key.clone())
                    .or_insert_with(|| Group {
                        key,
                        rows: Vec::new(),
                        preserve_url,
                    })
                    .rows
                    .push(core);
            }
        }
        let dependencies = Arc::new(dependency_tables(
            conn,
            cancel,
            &mut total_rows,
            &mut total_bytes,
        )?);
        if *bookmarks != Bookmarks::read(profile)? {
            return Err("Browser bookmarks changed during inventory.".into());
        }
        Ok(Self {
            groups: groups
                .into_iter()
                .filter(|(_, group)| group.item_count() > 0)
                .map(|(key, group)| (key, Arc::new(group)))
                .collect(),
            bookmarks,
            dependencies,
        })
    }

    pub(super) fn bookmarks_unchanged(&self, profile: &Path) -> Result<(), String> {
        if *self.bookmarks == Bookmarks::read(profile)? {
            Ok(())
        } else {
            Err("Browser bookmarks changed since review; cleanup was rolled back.".into())
        }
    }

    pub(super) fn reviews(&self) -> impl Iterator<Item = (String, i64, Review)> + '_ {
        self.groups.values().map(|group| {
            (
                group.site(),
                group.row_id(),
                Review {
                    group: group.clone(),
                    bookmarks: self.bookmarks.clone(),
                    dependencies: self.dependencies.clone(),
                },
            )
        })
    }
}
