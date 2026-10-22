//! Reviewed Firefox Places groups. Download membership follows the recovered
//! annotation predicates; ordinary history excludes those places. Native query
//! counters cover visits, unbookmarked places and download annotations only.

use super::*;
use std::{collections::BTreeMap, sync::Arc};

const MAX_ROWS: usize = 100_000;
const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Table {
    Places,
    Visits,
    Annos,
    Attributes,
    Bookmarks,
    PlaceExtra,
    VisitExtra,
}

impl Table {
    fn name(self) -> &'static str {
        match self {
            Self::Places => "moz_places",
            Self::Visits => "moz_historyvisits",
            Self::Annos => "moz_annos",
            Self::Attributes => "moz_anno_attributes",
            Self::Bookmarks => "moz_bookmarks",
            Self::PlaceExtra => "moz_places_extra",
            Self::VisitExtra => "moz_historyvisits_extra",
        }
    }
    fn columns(self) -> &'static [&'static str] {
        match self {
            Self::Places => &["id", "url", "visit_count", "last_visit_date"],
            Self::Visits => &["id", "place_id", "from_visit", "visit_date"],
            Self::Annos => &["id", "place_id", "anno_attribute_id"],
            Self::Attributes => &["id", "name"],
            Self::Bookmarks => &["id", "fk"],
            Self::PlaceExtra => &["place_id"],
            Self::VisitExtra => &["visit_id"],
        }
    }
    fn optional(self) -> bool {
        matches!(self, Self::PlaceExtra | Self::VisitExtra)
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
    fn value(&self, name: &str) -> Option<&Value> {
        self.columns
            .iter()
            .position(|c| c == name)
            .map(|i| &self.values[i])
    }
    fn integer(&self, name: &str) -> Result<Option<i64>, String> {
        match self.value(name) {
            Some(Value::Integer(id)) => Ok(Some(*id)),
            Some(Value::Null) => Ok(None),
            _ => Err("Firefox Places relationships have an unsupported type.".into()),
        }
    }
}

#[derive(PartialEq)]
struct Observation {
    schema: Vec<(String, String, String)>,
    rows: Vec<Arc<Row>>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
enum Key {
    History(i64),
    Download(i64),
    Annotation(i64),
}

struct Group {
    key: Key,
    rows: Vec<Arc<Row>>,
    visits: Vec<i64>,
    retained_place: Option<i64>,
    site: String,
    count: usize,
}

#[derive(Clone)]
pub(super) struct Review {
    group: Arc<Group>,
    observation: Arc<Observation>,
}

impl Review {
    pub(super) fn item_count(&self) -> usize {
        self.group.count
    }
    pub(super) fn matches(&self, current: &Snapshot, cache: &mut HashMap<usize, bool>) -> bool {
        // Check shared content once per original read snapshot. This includes
        // incoming visit edges, bookmarks, attributes and cascade dependencies,
        // so WAL-only changes cannot expand the reviewed effect set.
        *cache
            .entry(Arc::as_ptr(&self.observation) as usize)
            .or_insert_with(|| self.observation == current.observation)
            && current.groups.contains_key(&self.group.key)
    }
    pub(super) fn delete(
        &self,
        tx: &rusqlite::Transaction<'_>,
        cancel: &AtomicBool,
    ) -> Result<usize, String> {
        for table in [
            Table::VisitExtra,
            Table::PlaceExtra,
            Table::Visits,
            Table::Annos,
            Table::Places,
        ] {
            for row in self.group.rows.iter().filter(|row| row.table == table) {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Firefox cleanup was cancelled.".into());
                }
                let changed = tx
                    .execute(
                        &format!("DELETE FROM {} WHERE rowid=?1", table.name()),
                        [row.id],
                    )
                    .map_err(|_| "A reviewed Firefox row could not be removed transactionally.")?;
                if changed != 1 {
                    return Err("A reviewed Firefox row changed during cleanup.".into());
                }
            }
        }
        // Retained bookmark pages keep their other metadata and accurate visit
        // counters. This explicit repair is not an extra native count unit.
        if let Some(id) = self.group.retained_place {
            tx.execute("UPDATE moz_places SET visit_count=(SELECT count(*) FROM moz_historyvisits WHERE place_id=?1), last_visit_date=(SELECT max(visit_date) FROM moz_historyvisits WHERE place_id=?1) WHERE id=?1", [id])
                .map_err(|_| "Retained Firefox visit counters could not be repaired.")?;
        }
        Ok(1)
    }
}

pub(super) struct Snapshot {
    observation: Arc<Observation>,
    groups: BTreeMap<Key, Arc<Group>>,
}

impl Snapshot {
    pub(super) fn read(conn: &Connection, cancel: &AtomicBool) -> Result<Self, String> {
        let mut schema_statement = conn.prepare("SELECT type,name,coalesce(sql,'') FROM sqlite_master WHERE type IN ('table','trigger') ORDER BY type,name LIMIT 1025")
            .map_err(|_| "Firefox schema could not be inspected.")?;
        let mut schema = Vec::new();
        let mut schema_bytes = 0usize;
        let mut schema_rows = schema_statement
            .query([])
            .map_err(|_| "Firefox schema could not be read.")?;
        while let Some(row) = schema_rows
            .next()
            .map_err(|_| "Firefox schema is unsupported.")?
        {
            if cancel.load(Ordering::Relaxed) {
                return Err("Firefox schema inventory was cancelled.".into());
            }
            let mut fields = Vec::new();
            for i in 0..3 {
                let value = row
                    .get_ref(i)
                    .map_err(|_| "Firefox schema is unsupported.")?;
                let rusqlite::types::ValueRef::Text(bytes) = value else {
                    return Err("Firefox schema text is unsupported.".into());
                };
                schema_bytes = schema_bytes.saturating_add(bytes.len());
                if schema.len() >= 1024 || schema_bytes > 1024 * 1024 {
                    return Err("Firefox schema exceeds the inspection limit.".into());
                }
                fields.push(
                    std::str::from_utf8(bytes)
                        .map_err(|_| "Firefox schema encoding is unsupported.")?
                        .to_owned(),
                );
            }
            schema.push((fields.remove(0), fields.remove(0), fields.remove(0)));
        }
        // A persistent trigger could mutate unrelated tables, including tables
        // outside this adapter. Firefox's own TEMP triggers are not installed
        // by this independent read-only connection.
        let writable = [
            Table::Places,
            Table::Visits,
            Table::Annos,
            Table::PlaceExtra,
            Table::VisitExtra,
        ];
        for table in writable {
            let triggers: i64 = conn.query_row("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND tbl_name=?1 COLLATE NOCASE", [table.name()], |r| r.get(0))
                .map_err(|_| "Firefox triggers could not be inspected.")?;
            if triggers != 0 {
                return Err("Firefox Places has unsupported persistent cleanup triggers.".into());
            }
        }
        let mut annos_cascade = false;
        for (_, name, _) in schema.iter().filter(|s| s.0 == "table") {
            let quoted = name.replace('"', "\"\"");
            let mut stmt = conn
                .prepare(&format!("PRAGMA foreign_key_list(\"{quoted}\")"))
                .map_err(|_| "Firefox relationships could not be inspected.")?;
            let links = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, String>(6)?,
                    ))
                })
                .map_err(|_| "Firefox relationships could not be read.")?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|_| "Firefox relationships are unsupported.")?;
            for (id, seq, parent, source, column, action) in &links {
                if !writable
                    .iter()
                    .any(|t| t.name().eq_ignore_ascii_case(parent))
                {
                    continue;
                }
                let simple = *seq == 0 && links.iter().filter(|l| l.0 == *id).count() == 1;
                let id_target = column.as_ref().is_none_or(|c| c.eq_ignore_ascii_case("id"));
                let extra = (name == Table::PlaceExtra.name()
                    && source == "place_id"
                    && parent == Table::Places.name())
                    || (name == Table::VisitExtra.name()
                        && source == "visit_id"
                        && parent == Table::Visits.name());
                let core = (name == Table::Visits.name()
                    && source == "place_id"
                    && parent == Table::Places.name())
                    || (name == Table::Annos.name()
                        && source == "place_id"
                        && parent == Table::Places.name())
                    || (name == Table::Visits.name()
                        && source == "from_visit"
                        && parent == Table::Visits.name());
                if extra && (!simple || !id_target || action != "CASCADE") {
                    return Err("Firefox extra metadata ownership is unsupported.".into());
                }
                let observed_action = (action == "CASCADE" && (extra || core))
                    || (action == "SET NULL"
                        && name == Table::Visits.name()
                        && source == "from_visit"
                        && parent == Table::Visits.name());
                if !matches!(action.as_str(), "NO ACTION" | "RESTRICT")
                    && !(simple && id_target && observed_action)
                {
                    return Err("Firefox has an unreviewed cascading relationship.".into());
                }
                if name == Table::Annos.name()
                    && source == "place_id"
                    && parent == Table::Places.name()
                    && action == "CASCADE"
                {
                    annos_cascade = true;
                }
            }
            if matches!(
                name.as_str(),
                "moz_places_extra" | "moz_historyvisits_extra"
            ) {
                let (source, parent) = if name == "moz_places_extra" {
                    ("place_id", "moz_places")
                } else {
                    ("visit_id", "moz_historyvisits")
                };
                if links.len() != 1
                    || links[0].1 != 0
                    || links[0].2 != parent
                    || links[0].3 != source
                    || links[0].4.as_ref().is_some_and(|c| c != "id")
                    || links[0].5 != "CASCADE"
                {
                    return Err("Firefox extra metadata ownership is unsupported.".into());
                }
            }
        }
        let mut all = Vec::new();
        let mut bytes = 0usize;
        for table in [
            Table::Places,
            Table::Visits,
            Table::Annos,
            Table::Attributes,
            Table::Bookmarks,
            Table::PlaceExtra,
            Table::VisitExtra,
        ] {
            let definition = schema
                .iter()
                .find(|s| s.0 == "table" && s.1 == table.name());
            let Some((_, _, sql)) = definition else {
                if table.optional() {
                    continue;
                }
                return Err(
                    "Firefox Places download/history schema is incomplete or unsupported.".into(),
                );
            };
            if sql
                .trim_start()
                .to_ascii_uppercase()
                .starts_with("CREATE VIRTUAL")
            {
                return Err("Virtual Firefox Places tables are unsupported.".into());
            }
            let mut statement = conn
                .prepare(&format!(
                    "SELECT rowid,* FROM {} ORDER BY rowid LIMIT ?1",
                    table.name()
                ))
                .map_err(|_| "Firefox Places row identities are unsupported.")?;
            let columns = Arc::new(
                statement
                    .column_names()
                    .iter()
                    .skip(1)
                    .map(|c| (*c).to_owned())
                    .collect::<Vec<_>>(),
            );
            if columns.len() > 128
                || columns.iter().any(|c| {
                    ["rowid", "oid", "_rowid_"]
                        .iter()
                        .any(|alias| c.eq_ignore_ascii_case(alias))
                })
                || !table
                    .columns()
                    .iter()
                    .all(|c| columns.iter().any(|s| s == c))
            {
                return Err("Firefox Places download/history columns are unsupported.".into());
            }
            let mut rows = statement
                .query([(MAX_ROWS - all.len() + 1) as i64])
                .map_err(|_| "Firefox Places rows are unreadable.")?;
            while let Some(row) = rows
                .next()
                .map_err(|_| "Firefox Places rows are unreadable.")?
            {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Firefox Places inventory was cancelled.".into());
                }
                if all.len() >= MAX_ROWS {
                    return Err("Firefox Places row inspection limit reached.".into());
                }
                let id = row
                    .get(0)
                    .map_err(|_| "Firefox Places row identity is unsupported.")?;
                let mut values = Vec::new();
                for i in 1..row.as_ref().column_count() {
                    let value = row
                        .get_ref(i)
                        .map_err(|_| "Firefox Places content is unsupported.")?;
                    bytes = bytes.saturating_add(match value {
                        rusqlite::types::ValueRef::Text(b) | rusqlite::types::ValueRef::Blob(b) => {
                            b.len()
                        }
                        _ => 8,
                    });
                    if bytes > MAX_BYTES {
                        return Err("Firefox Places content inspection limit reached.".into());
                    }
                    if let rusqlite::types::ValueRef::Text(b) = value {
                        std::str::from_utf8(b)
                            .map_err(|_| "Firefox Places text encoding is unsupported.")?;
                    }
                    values.push(Value::from(value));
                }
                let row = Arc::new(Row {
                    table,
                    id,
                    columns: columns.clone(),
                    values,
                });
                if !table.optional() && row.integer("id")? != Some(id) {
                    return Err("Firefox Places primary identity is unsupported.".into());
                }
                all.push(row);
            }
        }
        let mut attributes = HashSet::new();
        // SQLite LIKE's ASCII case behavior is retained instead of substituting
        // Rust's case-sensitive prefix matching. Neither predicate uses age.
        let mut stmt = conn
            .prepare("SELECT id FROM moz_anno_attributes WHERE name LIKE 'downloads/%'")
            .map_err(|_| "Firefox annotation membership is unsupported.")?;
        for id in stmt
            .query_map([], |r| r.get::<_, i64>(0))
            .map_err(|_| "Firefox annotation membership is unreadable.")?
        {
            attributes.insert(id.map_err(|_| "Firefox annotation identity is unsupported.")?);
        }
        let mut download_places = HashSet::new();
        let mut download_annos = HashSet::new();
        let mut bookmarks = HashSet::new();
        let mut places = BTreeMap::new();
        let mut visits = BTreeMap::<i64, Vec<Arc<Row>>>::new();
        let mut annotations = BTreeMap::<i64, Vec<Arc<Row>>>::new();
        let mut place_extras = BTreeMap::<i64, Vec<Arc<Row>>>::new();
        let mut visit_extras = BTreeMap::<i64, Vec<Arc<Row>>>::new();
        for row in &all {
            match row.table {
                Table::Places => {
                    places.insert(row.id, row.clone());
                }
                Table::Visits => {
                    row.integer("from_visit")?;
                    if let Some(id) = row.integer("place_id")? {
                        visits.entry(id).or_default().push(row.clone());
                    }
                }
                Table::Annos => {
                    let place = row.integer("place_id")?;
                    if let Some(id) = place {
                        annotations.entry(id).or_default().push(row.clone());
                    }
                    if row
                        .integer("anno_attribute_id")?
                        .is_some_and(|id| attributes.contains(&id))
                    {
                        download_annos.insert(row.id);
                        if let Some(id) = place {
                            download_places.insert(id);
                        }
                    }
                }
                Table::Bookmarks => {
                    if let Some(id) = row.integer("fk")? {
                        bookmarks.insert(id);
                    }
                }
                Table::PlaceExtra => {
                    if let Some(id) = row.integer("place_id")? {
                        place_extras.entry(id).or_default().push(row.clone());
                    }
                }
                Table::VisitExtra => {
                    if let Some(id) = row.integer("visit_id")? {
                        visit_extras.entry(id).or_default().push(row.clone());
                    }
                }
                Table::Attributes => {}
            }
        }
        let mut groups = BTreeMap::new();
        for id in download_places
            .iter()
            .chain(places.keys().filter(|id| !download_places.contains(id)))
        {
            if cancel.load(Ordering::Relaxed) {
                return Err("Firefox Places grouping was cancelled.".into());
            }
            let download = download_places.contains(id);
            let parent = places.get(id);
            let group_visits = visits.get(id).cloned().unwrap_or_default();
            if !download && group_visits.is_empty() {
                continue;
            }
            let delete_parent = download && parent.is_some() && !bookmarks.contains(id);
            let mut rows = group_visits.clone();
            let mut count = if download { group_visits.len() } else { 1 };
            if download {
                for row in annotations.get(id).into_iter().flatten() {
                    let selected = download_annos.contains(&row.id);
                    if selected {
                        count += 1;
                    }
                    if selected || (delete_parent && annos_cascade) {
                        rows.push(row.clone());
                    }
                }
                if delete_parent {
                    count += 1;
                    rows.push(parent.unwrap().clone());
                    rows.extend(place_extras.get(id).into_iter().flatten().cloned());
                }
            }
            for row in &group_visits {
                rows.extend(visit_extras.get(&row.id).into_iter().flatten().cloned());
            }
            let key = if download {
                Key::Download(*id)
            } else {
                Key::History(*id)
            };
            let site = parent
                .and_then(|p| p.value("url"))
                .and_then(|v| match v {
                    Value::Text(url) => Some(safe_site_label(url)),
                    _ => None,
                })
                .unwrap_or_default();
            groups.insert(
                key.clone(),
                Arc::new(Group {
                    key,
                    rows,
                    visits: group_visits.iter().map(|r| r.id).collect(),
                    retained_place: parent.filter(|_| !delete_parent).map(|_| *id),
                    site,
                    count,
                }),
            );
        }
        // NULL annotation places participate in the annotation predicate, but
        // not in SQL IN membership for visits or parent pages.
        for row in all
            .iter()
            .filter(|r| r.table == Table::Annos && download_annos.contains(&r.id))
        {
            if row.integer("place_id")?.is_none() {
                let key = Key::Annotation(row.id);
                groups.insert(
                    key.clone(),
                    Arc::new(Group {
                        key,
                        rows: vec![row.clone()],
                        visits: Vec::new(),
                        retained_place: None,
                        site: String::new(),
                        count: 1,
                    }),
                );
            }
        }
        Ok(Self {
            observation: Arc::new(Observation { schema, rows: all }),
            groups,
        })
    }
    pub(super) fn reviews(
        &self,
        category: PrivacyCategory,
    ) -> impl Iterator<Item = (String, i64, Review)> + '_ {
        self.groups
            .values()
            .filter(move |g| {
                matches!(
                    (&g.key, category),
                    (Key::History(_), PrivacyCategory::History)
                        | (
                            Key::Download(_) | Key::Annotation(_),
                            PrivacyCategory::Downloads
                        )
                )
            })
            .map(|g| {
                let id = match g.key {
                    Key::History(id) | Key::Download(id) | Key::Annotation(id) => id,
                };
                (
                    g.site.clone(),
                    id,
                    Review {
                        group: g.clone(),
                        observation: self.observation.clone(),
                    },
                )
            })
    }
    pub(super) fn repair_visits<'a>(
        &self,
        tx: &rusqlite::Transaction<'_>,
        reviews: impl Iterator<Item = &'a Review>,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        let selected = reviews
            .flat_map(|r| r.group.visits.iter().copied())
            .collect::<HashSet<_>>();
        for row in self
            .observation
            .rows
            .iter()
            .filter(|r| r.table == Table::Visits && !selected.contains(&r.id))
        {
            if cancel.load(Ordering::Relaxed) {
                return Err("Firefox reference repair was cancelled.".into());
            }
            if row
                .integer("from_visit")?
                .is_some_and(|id| selected.contains(&id))
            {
                tx.execute(
                    "UPDATE moz_historyvisits SET from_visit=NULL WHERE rowid=?1",
                    [row.id],
                )
                .map_err(|_| "Firefox visit references could not be repaired.")?;
            }
        }
        // Selected rows can reference each other (including cycles), with a
        // restrictive declared FK. Clear only observed selected edges first.
        for id in selected {
            if cancel.load(Ordering::Relaxed) {
                return Err("Firefox reference repair was cancelled.".into());
            }
            tx.execute(
                "UPDATE moz_historyvisits SET from_visit=NULL WHERE rowid=?1",
                [id],
            )
            .map_err(|_| "Firefox selected visit references could not be repaired.")?;
        }
        Ok(())
    }
}
