//! Protected lease-to-selection records, not native Sleep/launch authority.
//!
//! These records share the resource owner's bounded, pinned SQLite connection.
//! Only an owner-selected immutable image/resource set may be registered. A
//! lookup does not certify association completeness, current file/native state,
//! hook ownership, helper readiness or successful effects. No IPC accepts this
//! document and no preflight/claim/launch permit is produced here.
use super::*;
use crate::optimizer_identity::{ImageSnapshot, MAX_HEADER_BYTES, MAX_IMAGE_BYTES};

const MAX_LEASES: i64 = 256;
const MAX_DOCUMENT: usize = 2 * 1024 * 1024;
const MAX_IMAGES: usize = 32;
const MAX_BINDING_RESOURCES: usize = 64;

pub(super) const SCHEMA: &str = r#"CREATE TABLE leases (
 lease BLOB PRIMARY KEY NOT NULL CHECK(length(lease)=16 AND lease!=zeroblob(16)),
 revision BLOB NOT NULL CHECK(length(revision)=16 AND revision!=zeroblob(16)),
 member TEXT NOT NULL CHECK(length(CAST(member AS BLOB)) BETWEEN 1 AND 16384),
 document TEXT NOT NULL CHECK(length(CAST(document AS BLOB)) BETWEEN 1 AND 2097152),
 retired INTEGER NOT NULL CHECK(retired IN(0,1))
) STRICT, WITHOUT ROWID"#;
pub(super) const INDEX: &str =
    "CREATE UNIQUE INDEX bound_lease_member ON leases(member) WHERE retired=0";

/// Durable selection data. Deliberately not a LeasePreflight or native permit.
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    version: u8,
    lease: Uuid,
    revision: Uuid,
    member: Member,
    images: Vec<ImageSnapshot>,
    resources: Vec<String>,
}
impl Selection {
    pub(crate) fn from_owner_selection(
        caller: &Caller,
        member: Member,
        lease: Uuid,
        revision: Uuid,
        images: Vec<ImageSnapshot>,
        resources: Vec<ResourceId>,
    ) -> Result<Self, Error> {
        let selection = Self {
            version: 1,
            lease,
            revision,
            member,
            images,
            resources: resources.into_iter().map(|r| r.0).collect(),
        };
        selection.validate()?;
        if !selection.member.belongs_to(caller) {
            return Err(Error::NotAuthorized);
        }
        Ok(selection)
    }
    pub(crate) fn lease(&self) -> Uuid {
        self.lease
    }
    pub(crate) fn revision(&self) -> Uuid {
        self.revision
    }
    pub(crate) fn member(&self) -> &Member {
        &self.member
    }
    pub(crate) fn images(&self) -> &[ImageSnapshot] {
        &self.images
    }
    pub(crate) fn resources(&self) -> Vec<ResourceId> {
        self.resources.iter().cloned().map(ResourceId).collect()
    }
    fn validate(&self) -> Result<(), Error> {
        self.member.validate()?;
        if self.version != 1
            || self.lease.is_nil()
            || self.revision.is_nil()
            || self.member.session == 0
            || self.member.account == "S-1-5-18"
            || self.member.logon_sid.is_none()
            || self.member.boot_id.is_none()
            || self.images.is_empty()
            || self.images.len() > MAX_IMAGES
            || self.resources.is_empty()
            || self.resources.len() > MAX_BINDING_RESOURCES
        {
            return Err(Error::Invalid);
        }
        for (index, image) in self.images.iter().enumerate() {
            if image.size == 0
                || image.size > MAX_IMAGE_BYTES
                || image.bytes_read < image.size
                || image.bytes_read > image.size.saturating_add(MAX_HEADER_BYTES as u64)
                || image.sha256.len() != 64
                || !image
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || image.identity.file_id == [0; 16]
                || image.hard_links == 0
                || !local_image_path(&image.requested_path)
                || !local_image_path(&image.final_path)
                || self.images[..index].iter().any(|prior| {
                    prior.identity == image.identity
                        || prior
                            .final_path
                            .to_string_lossy()
                            .eq_ignore_ascii_case(&image.final_path.to_string_lossy())
                })
            {
                return Err(Error::Invalid);
            }
        }
        for (index, id) in self.resources.iter().enumerate() {
            if !ResourceId(id.clone()).valid() || self.resources[..index].contains(id) {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
    fn document(&self) -> Result<String, Error> {
        self.validate()?;
        let document = serde_json::to_string(self).map_err(|_| Error::Invalid)?;
        if document.len() > MAX_DOCUMENT {
            return Err(Error::Capacity);
        }
        Ok(document)
    }
}

fn local_image_path(path: &std::path::Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    if text.encode_utf16().count() > 32766 || text.contains(['\0', '"', '/']) {
        return false;
    }
    let text = text.strip_prefix(r"\\?\").unwrap_or(text);
    let bytes = text.as_bytes();
    bytes.len() > 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..3] == *b":\\"
        && text[3..]
            .split('\\')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains(':'))
}

struct Row {
    selection: Selection,
    retired: bool,
}
fn decode(
    lease: Vec<u8>,
    revision: Vec<u8>,
    member: String,
    document: String,
    retired: i64,
) -> Result<Row, Error> {
    if document.is_empty() || document.len() > MAX_DOCUMENT || member.len() > 16384 {
        return Err(Error::Corrupt);
    }
    let selection: Selection = serde_json::from_str(&document).map_err(|_| Error::Corrupt)?;
    if selection.document().map_err(|_| Error::Corrupt)? != document
        || lease.as_slice() != selection.lease.as_bytes()
        || revision.as_slice() != selection.revision.as_bytes()
        || member != serde_json::to_string(&selection.member).map_err(|_| Error::Corrupt)?
        || !matches!(retired, 0 | 1)
    {
        return Err(Error::Corrupt);
    }
    Ok(Row {
        selection,
        retired: retired == 1,
    })
}
fn read(connection: &Connection, lease: Uuid) -> Result<Option<Row>, Error> {
    let raw = connection
        .query_row(
            "SELECT lease,revision,member,document,retired FROM leases WHERE lease=?1",
            [lease.as_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    raw.map(|(a, b, c, d, e)| decode(a, b, c, d, e)).transpose()
}
fn associations(connection: &Connection, selection: &Selection) -> Result<(), Error> {
    for id in selection.resources() {
        let record = load(connection, &id)?.ok_or(Error::Missing)?;
        if !record.members.iter().any(|d| d.member == selection.member) {
            return Err(Error::Changed);
        }
    }
    Ok(())
}
pub(super) fn validate_rows(connection: &Connection) -> Result<(), Error> {
    let count: i64 = connection.query_row("SELECT count(*) FROM leases", [], |r| r.get(0))?;
    if count > MAX_LEASES {
        return Err(Error::Capacity);
    }
    let mut statement =
        connection.prepare("SELECT lease,revision,member,document,retired FROM leases")?;
    let mut rows = statement.query([])?;
    while let Some(raw) = rows.next()? {
        let row = decode(
            raw.get(0)?,
            raw.get(1)?,
            raw.get(2)?,
            raw.get(3)?,
            raw.get(4)?,
        )?;
        if !row.retired {
            associations(connection, &row.selection)?;
        }
    }
    Ok(())
}
pub(super) fn member_is_bound(
    connection: &Connection,
    id: &ResourceId,
    member: &Member,
) -> Result<bool, Error> {
    let member = serde_json::to_string(member).map_err(|_| Error::Invalid)?;
    let lease: Option<Vec<u8>> = connection
        .query_row(
            "SELECT lease FROM leases WHERE member=?1 AND retired=0",
            [member],
            |r| r.get(0),
        )
        .optional()?;
    let Some(lease) = lease else {
        return Ok(false);
    };
    let lease = Uuid::from_slice(&lease).map_err(|_| Error::Corrupt)?;
    let row = read(connection, lease)?.ok_or(Error::Corrupt)?;
    Ok(row.selection.resources.contains(&id.0))
}

impl Catalog {
    /// Commit a service-owned selection before hook effects can reference its
    /// lease. An exact retry is idempotent; UUID reuse and replacement are refused.
    pub(crate) fn register_lease(
        &mut self,
        caller: &Caller,
        selection: Selection,
    ) -> Result<bool, Error> {
        let document = selection.document()?;
        if !selection.member.belongs_to(caller) {
            return Err(Error::NotAuthorized);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(prior) = read(&tx, selection.lease)? {
            if !prior.selection.member.belongs_to(caller) {
                return Err(Error::NotAuthorized);
            }
            if prior.selection != selection || prior.retired {
                return Err(Error::Stale);
            }
            associations(&tx, &selection)?;
            tx.commit()?;
            return Ok(false);
        }
        associations(&tx, &selection)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM leases", [], |r| r.get(0))?;
        if count >= MAX_LEASES {
            return Err(Error::Capacity);
        }
        let member = serde_json::to_string(&selection.member).map_err(|_| Error::Invalid)?;
        let bound: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM leases WHERE member=?1 AND retired=0)",
            [&member],
            |r| r.get(0),
        )?;
        if bound {
            return Err(Error::Busy);
        }
        tx.execute(
            "INSERT INTO leases(lease,revision,member,document,retired) VALUES(?1,?2,?3,?4,0)",
            params![
                selection.lease.as_bytes().as_slice(),
                selection.revision.as_bytes().as_slice(),
                member,
                document
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }
    /// Caller-scoped data lookup only. Fresh native observations and all other
    /// lease/effect prerequisites remain mandatory after this returns.
    pub(crate) fn lease_selection(
        &self,
        caller: &Caller,
        lease: Uuid,
    ) -> Result<Option<Selection>, Error> {
        if lease.is_nil() {
            return Err(Error::Invalid);
        }
        let tx = self.connection.unchecked_transaction()?;
        let Some(row) = read(&tx, lease)? else {
            tx.commit()?;
            return Ok(None);
        };
        if !row.selection.member.belongs_to(caller) {
            return Err(Error::NotAuthorized);
        }
        if row.retired {
            tx.commit()?;
            return Ok(None);
        }
        associations(&tx, &row.selection)?;
        tx.commit()?;
        Ok(Some(row.selection))
    }
    /// Tombstone only a stable, no-longer-requested binding. This does not erase
    /// baselines, restore native state, release resources or discharge recovery.
    pub(crate) fn retire_lease(
        &mut self,
        caller: &Caller,
        lease: Uuid,
        revision: Uuid,
    ) -> Result<bool, Error> {
        if lease.is_nil() || revision.is_nil() {
            return Err(Error::Invalid);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = read(&tx, lease)?.ok_or(Error::Missing)?;
        if !row.selection.member.belongs_to(caller) {
            return Err(Error::NotAuthorized);
        }
        if row.selection.revision != revision {
            return Err(Error::Stale);
        }
        if row.retired {
            tx.commit()?;
            return Ok(false);
        }
        for id in row.selection.resources() {
            let record = load(&tx, &id)?.ok_or(Error::Missing)?;
            let demand = record
                .members
                .iter()
                .find(|d| d.member == row.selection.member)
                .ok_or(Error::Changed)?;
            if demand.sleep
                || !demand.wakes.is_empty()
                || record.activation_review()
                || !matches!(
                    (record.phase, record.target()),
                    (Phase::Awake, Target::Awake) | (Phase::Sleeping, Target::Sleep)
                )
                || record
                    .hooks
                    .iter()
                    .any(|h| h.member == row.selection.member && h.needed)
            {
                return Err(Error::Busy);
            }
        }
        if tx.execute(
            "UPDATE leases SET retired=1 WHERE lease=?1 AND revision=?2 AND retired=0",
            params![lease.as_bytes().as_slice(), revision.as_bytes().as_slice()],
        )? != 1
        {
            return Err(Error::Stale);
        }
        tx.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
