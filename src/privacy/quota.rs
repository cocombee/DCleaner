//! Quota SELECT candidates and DELETE targets are different units. Preserve all
//! compatible descriptors, but merge their overlapping row ownership before
//! review. Quota/HostQuota metadata is never a deletion target. Native dynamic
//! key interpolation is deliberately replaced by exact reviewed row-ID effects.

use super::*;
use rusqlite::{params_from_iter, types::ValueRef};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

const MAX_ROWS: usize = 100_000;
const MAX_EDGES: usize = 200_000;
const MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    Legacy,
    Buckets,
}
impl Target {
    fn table(self) -> &'static str {
        match self {
            Self::Legacy => "OriginInfoTable",
            Self::Buckets => "buckets",
        }
    }
}

struct Descriptor {
    target: Target,
    column: &'static str,
    select: String,
    predicate: String,
}

// The repeated http condition in the legacy HTTPS arm is in the shipped rule.
fn descriptor(
    target: Target,
    column: &'static str,
    quota: Option<&str>,
    legacy: bool,
) -> Descriptor {
    let table = target.table();
    let mut select = format!(
        "select SubStr({column}, instr({column}, 'http://') + 7, LENGTH({column}) - 8) as host_key, {column} as raw from {table} WHERE instr({column}, 'http://') > 0 UNION select SubStr({column}, instr({column}, 'https://') + 8, LENGTH({column}) - 9) as host_key, {column} as raw from {table} WHERE instr({column}, '{}') > 0",
        if legacy { "http://" } else { "https://" }
    );
    if let Some(quota) = quota {
        select.push_str(&format!(
            " UNION select host as host_key, host as raw from {quota}"
        ));
    }
    Descriptor {
        target,
        column,
        select,
        predicate: if legacy || quota.is_none() {
            format!(" AND (instr(t.{column},'http://')>0 OR instr(t.{column},'https://')>0)")
        } else {
            String::new()
        },
    }
}

type Effect = (Target, i64);
struct Candidate {
    digest: [u8; 32],
    site: String,
    raw: String,
    kept: bool,
}
#[derive(Clone)]
pub(super) struct Review {
    fingerprint: [u8; 32],
    schema: [u8; 32],
    rows: Vec<Effect>,
    units: usize,
    keep_domains: Arc<HashSet<String>>,
    protected: bool,
}
struct Group {
    site: String,
    review: Review,
}
pub(super) struct Snapshot {
    groups: BTreeMap<[u8; 32], Group>,
    pub(super) exempted: usize,
    pub(super) issues: Vec<&'static str>,
}

fn prefix(row: &rusqlite::Row<'_>, column: usize) -> Result<Option<String>, String> {
    match row
        .get_ref(column)
        .map_err(|_| "Quota text is unreadable.")?
    {
        ValueRef::Null => Ok(None),
        ValueRef::Text(bytes) => {
            std::str::from_utf8(bytes.split(|b| *b == 0).next().unwrap_or_default())
                .map(|s| Some(s.to_owned()))
                .map_err(|_| "Quota text encoding is unsupported.".into())
        }
        _ => Err("Quota text encoding is unsupported.".into()),
    }
}
fn root(parents: &mut [usize], mut index: usize) -> usize {
    while parents[index] != index {
        parents[index] = parents[parents[index]];
        index = parents[index];
    }
    index
}

impl Snapshot {
    pub(super) fn read(
        conn: &Connection,
        keep_domains: &HashSet<String>,
        cancel: &AtomicBool,
    ) -> Result<Self, String> {
        let mut descriptors = Vec::new();
        let mut issues = Vec::new();
        let legacy = optional_table_columns(conn, "OriginInfoTable")?;
        let buckets = optional_table_columns(conn, "buckets")?;
        let host_quota = optional_table_columns(conn, "HostQuotaTable")?;
        let quota = optional_table_columns(conn, "quota")?;
        if let Some(columns) = &legacy {
            if columns.contains("origin") && host_quota.as_ref().is_some_and(|c| c.contains("host"))
            {
                descriptors.push(descriptor(
                    Target::Legacy,
                    "origin",
                    Some("HostQuotaTable"),
                    true,
                ));
            } else {
                issues.push("Legacy quota tables have an unsupported layout.");
            }
        }
        if let Some(columns) = &buckets {
            if quota
                .as_ref()
                .is_some_and(|columns| !columns.contains("host"))
            {
                issues.push("Quota host metadata has an unsupported layout.");
            }
            if columns.contains("origin") && quota.as_ref().is_some_and(|c| c.contains("host")) {
                descriptors.push(descriptor(Target::Buckets, "origin", Some("quota"), false));
            }
            if columns.contains("storage_key") {
                if quota.as_ref().is_some_and(|c| c.contains("host")) {
                    descriptors.push(descriptor(
                        Target::Buckets,
                        "storage_key",
                        Some("quota"),
                        false,
                    ));
                }
                descriptors.push(descriptor(Target::Buckets, "storage_key", None, false));
            }
            if !columns.contains("storage_key")
                && (!columns.contains("origin")
                    || !quota.as_ref().is_some_and(|c| c.contains("host")))
            {
                issues.push("Quota bucket tables have an unsupported layout.");
            }
        }
        if descriptors.is_empty() {
            return Err("Quota storage has no supported table descriptors.".into());
        }
        let mut schema = None;
        let mut effects = BTreeMap::new();
        let mut bytes = 0;
        let mut source_rows = 0;
        for (target, exists) in [
            (Target::Legacy, legacy.is_some()),
            (Target::Buckets, buckets.is_some()),
        ] {
            if !exists || !descriptors.iter().any(|d| d.target == target) {
                continue;
            }
            let observed = cookies::schema_for_table(conn, target.table(), cancel)?;
            if schema.is_some_and(|s| s != observed) {
                return Err("Quota schema changed during observation.".into());
            }
            schema = Some(observed);
            let mut statement = conn
                .prepare(&format!(
                    "SELECT rowid,* FROM {} ORDER BY rowid LIMIT {}",
                    target.table(),
                    MAX_ROWS + 1
                ))
                .map_err(|_| "Quota target layout is unsupported.")?;
            let mut rows = statement
                .query([])
                .map_err(|_| "Quota rows are unreadable.")?;
            while let Some(row) = rows.next().map_err(|_| "Quota rows are unreadable.")? {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Quota observation was cancelled.".into());
                }
                source_rows += 1;
                if source_rows > MAX_ROWS {
                    return Err("Quota observation exceeds the safe row limit.".into());
                }
                let id = row
                    .get::<_, i64>(0)
                    .map_err(|_| "Quota row ID is ambiguous.")?;
                effects.insert((target, id), cookies::fingerprint(row, &mut bytes)?);
            }
        }
        // Validate auxiliary objects too; views/virtual tables/row-ID aliases or
        // unreviewed triggers/dependencies cannot silently become cleanup owners.
        for (table, exists) in [
            ("HostQuotaTable", host_quota.is_some()),
            ("quota", quota.is_some()),
        ] {
            if exists {
                cookies::schema_for_table(conn, table, cancel)?;
            }
        }
        let utf16 = conn
            .query_row("PRAGMA encoding", [], |r| r.get::<_, String>(0))
            .map_err(|_| "Quota encoding is unreadable.")?
            .starts_with("UTF-16");
        let mut candidates = Vec::new();
        let mut parents = Vec::new();
        let mut owners: BTreeMap<Effect, usize> = BTreeMap::new();
        let mut edges = 0;
        let mut observed_candidates = 0;
        for (variant, descriptor) in descriptors.iter().enumerate() {
            let start = candidates.len();
            let mut statement=conn.prepare(&format!("SELECT host_key,raw,CAST(host_key AS TEXT),CAST(raw AS TEXT) FROM ({}) LIMIT {}",descriptor.select,MAX_ROWS+1)).map_err(|_| "Quota selection layout is unsupported.")?;
            let mut rows = statement.query([]).map_err(|_| "Quota selection failed.")?;
            while let Some(row) = rows
                .next()
                .map_err(|_| "Quota candidates are unreadable.")?
            {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Quota observation was cancelled.".into());
                }
                observed_candidates += 1;
                if observed_candidates > MAX_ROWS {
                    return Err("Quota candidate limit exceeded.".into());
                }
                let fingerprint = cookies::fingerprint(row, &mut bytes)?;
                if utf16
                    && [0, 1]
                        .iter()
                        .any(|&i| matches!(row.get_ref(i),Ok(ValueRef::Blob(b)) if b.len()%2!=0))
                {
                    return Err("Quota text has an unsupported odd-byte UTF-16 blob.".into());
                }
                let Some(label) = prefix(row, 2)? else {
                    continue;
                };
                let label = cookies::normalized_label(&label)?;
                let Some(raw) = prefix(row, 3)? else { continue };
                if label.is_empty() || raw.is_empty() {
                    continue;
                }
                let site = safe_site_label(&label);
                let mut digest = Sha256::new();
                digest.update([variant as u8]);
                digest.update(fingerprint);
                parents.push(parents.len());
                candidates.push(Candidate {
                    digest: digest.finalize().into(),
                    kept: is_cookie_exception(&site, keep_domains),
                    site,
                    raw,
                });
            }
            drop(rows);
            drop(statement);
            // Bind converted raw keys as TEXT. SQLite supplies the target's own
            // affinity/collation; no SQL string interpolation of stored values.
            for chunk in (start..candidates.len()).collect::<Vec<_>>().chunks(200) {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Quota observation was cancelled.".into());
                }
                let mut parameters = Vec::with_capacity(chunk.len() * 2);
                for &index in chunk {
                    parameters.push(Value::Integer(index as i64));
                    parameters.push(Value::Text(candidates[index].raw.clone()));
                }
                let sql = format!(
                    "WITH c(n,raw) AS (VALUES {}) SELECT c.n,t.rowid FROM c JOIN {} t ON t.{}=c.raw WHERE 1{} LIMIT {}",
                    vec!["(?,?)"; chunk.len()].join(","),
                    descriptor.target.table(),
                    descriptor.column,
                    descriptor.predicate,
                    MAX_EDGES + 1
                );
                let mut statement = conn
                    .prepare(&sql)
                    .map_err(|_| "Quota target relationship is unsupported.")?;
                let mut rows = statement
                    .query(params_from_iter(parameters))
                    .map_err(|_| "Quota target relationship is unreadable.")?;
                while let Some(row) = rows
                    .next()
                    .map_err(|_| "Quota target relationship is unreadable.")?
                {
                    if cancel.load(Ordering::Relaxed) {
                        return Err("Quota observation was cancelled.".into());
                    }
                    edges += 1;
                    if edges > MAX_EDGES {
                        return Err("Quota ownership exceeds the safe edge limit.".into());
                    }
                    let index = row
                        .get::<_, i64>(0)
                        .map_err(|_| "Quota candidate identity is unsupported.")?;
                    let index = usize::try_from(index)
                        .map_err(|_| "Quota candidate identity is unsupported.")?;
                    if index >= candidates.len() {
                        return Err("Quota candidate identity is out of bounds.".into());
                    }
                    let effect = (
                        descriptor.target,
                        row.get::<_, i64>(1)
                            .map_err(|_| "Quota row identity is unsupported.")?,
                    );
                    if !effects.contains_key(&effect) {
                        return Err("Quota ownership changed during observation.".into());
                    }
                    if let Some(&other) = owners.get(&effect) {
                        let a = root(&mut parents, index);
                        let b = root(&mut parents, other);
                        parents[a] = b;
                    } else {
                        owners.insert(effect, index);
                    }
                }
            }
        }
        // Raw SQL-key text is not retained in a report/plan, only fingerprints.
        let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for index in 0..candidates.len() {
            let owner = root(&mut parents, index);
            groups.entry(owner).or_default().push(index);
        }
        let mut group_rows: BTreeMap<usize, Vec<Effect>> = BTreeMap::new();
        for (effect, index) in owners {
            let owner = root(&mut parents, index);
            group_rows.entry(owner).or_default().push(effect);
        }
        let keep_domains = Arc::new(keep_domains.clone());
        let mut result = Self {
            groups: BTreeMap::new(),
            exempted: 0,
            issues,
        };
        for (owner, indices) in groups {
            let kept = indices.iter().filter(|&&i| candidates[i].kept).count();
            result.exempted = result.exempted.saturating_add(kept);
            let units = indices.len() - kept;
            if units == 0 {
                continue;
            }
            let rows = group_rows.remove(&owner).unwrap_or_default();
            let mut digest = Sha256::new();
            let mut tokens = indices
                .iter()
                .map(|&i| candidates[i].digest)
                .collect::<Vec<_>>();
            tokens.sort();
            digest.update((tokens.len() as u64).to_le_bytes());
            for token in tokens {
                digest.update(token);
            }
            digest.update((rows.len() as u64).to_le_bytes());
            for &(target, id) in &rows {
                digest.update([target as u8]);
                digest.update(id.to_le_bytes());
                digest.update(effects[&(target, id)]);
            }
            let fingerprint = digest.finalize().into();
            let site = indices
                .iter()
                .filter(|&&i| !candidates[i].kept)
                .map(|&i| candidates[i].site.as_str())
                .next()
                .unwrap_or_default()
                .to_owned();
            let site = if indices
                .iter()
                .filter(|&&i| !candidates[i].kept)
                .all(|&i| candidates[i].site == site)
            {
                site
            } else {
                "Multiple sites".into()
            };
            let review = Review {
                fingerprint,
                schema: schema.unwrap(),
                rows,
                units,
                keep_domains: keep_domains.clone(),
                protected: kept > 0,
            };
            result.groups.insert(fingerprint, Group { site, review });
        }
        if bytes > MAX_BYTES {
            return Err("Quota observation exceeds the safe byte limit.".into());
        }
        Ok(result)
    }
    pub(super) fn reviews(&self) -> impl Iterator<Item = (String, Review)> + '_ {
        self.groups
            .values()
            .map(|g| (g.site.clone(), g.review.clone()))
    }
}
impl Review {
    pub(super) fn item_count(&self) -> usize {
        self.units
    }
    pub(super) fn unavailable_reason(&self) -> Option<&'static str> {
        if self.protected {
            Some("This quota group overlaps a site in your keep list.")
        } else if self.rows.is_empty() {
            Some("Quota metadata was found without matching removable storage rows.")
        } else {
            None
        }
    }
    pub(super) fn keep_domains(&self) -> &HashSet<String> {
        &self.keep_domains
    }
    pub(super) fn matches(&self, observed: &Snapshot) -> bool {
        self.unavailable_reason().is_none()
            && observed.groups.get(&self.fingerprint).is_some_and(|g| {
                g.review.schema == self.schema
                    && g.review.unavailable_reason().is_none()
                    && g.review.keep_domains == self.keep_domains
            })
    }
    pub(super) fn delete(
        &self,
        tx: &rusqlite::Transaction<'_>,
        cancel: &AtomicBool,
    ) -> Result<usize, String> {
        if self.unavailable_reason().is_some() {
            return Err("Quota selection has no reviewed removable rows.".into());
        }
        for target in [Target::Legacy, Target::Buckets] {
            let ids = self
                .rows
                .iter()
                .filter(|(table, _)| *table == target)
                .map(|(_, id)| *id)
                .collect::<Vec<_>>();
            for chunk in ids.chunks(500) {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Quota cleanup was cancelled.".into());
                }
                let removed = tx
                    .execute(
                        &format!(
                            "DELETE FROM {} WHERE rowid IN ({})",
                            target.table(),
                            vec!["?"; chunk.len()].join(",")
                        ),
                        params_from_iter(chunk),
                    )
                    .map_err(|_| "Reviewed quota rows could not be removed transactionally.")?;
                if removed != chunk.len() {
                    return Err("Reviewed quota rows changed during cleanup.".into());
                }
            }
        }
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_ownership_edge_bound_and_cancellation_are_explicit() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE buckets(storage_key TEXT COLLATE NOCASE); CREATE TABLE quota(host TEXT)",
        )
        .unwrap();
        for _ in 0..450 {
            conn.execute("INSERT INTO buckets VALUES('abcdefghi')", [])
                .unwrap();
        }
        for mask in 0..500 {
            let key = "abcdefghi"
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if mask & (1 << i) != 0 {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                })
                .collect::<String>();
            conn.execute("INSERT INTO quota VALUES(?1)", [key]).unwrap();
        }
        let result = Snapshot::read(&conn, &HashSet::new(), &AtomicBool::new(false));
        assert!(result.err().unwrap().contains("edge limit"));
        let result = Snapshot::read(&conn, &HashSet::new(), &AtomicBool::new(true));
        assert!(result.err().unwrap().contains("cancelled"));
        assert_eq!(
            conn.query_row("SELECT count(*) FROM buckets", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            450
        );
    }

    #[test]
    fn incompatible_auxiliary_schema_keeps_supported_descriptor_but_reports_gap() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE buckets(storage_key TEXT); INSERT INTO buckets VALUES('https://example.test/');CREATE TABLE quota(unknown TEXT)").unwrap();
        let snapshot = Snapshot::read(&conn, &HashSet::new(), &AtomicBool::new(false)).unwrap();
        assert_eq!(snapshot.issues.len(), 1);
        let reviews = snapshot.reviews().collect::<Vec<_>>();
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].1.item_count(), 1);
        assert!(reviews[0].1.unavailable_reason().is_none());
    }
}
