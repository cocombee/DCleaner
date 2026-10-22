//! Durable shared-resource bookkeeping for the protected Optimizer owner.
//!
//! Records, resource IDs and claims are not native effect authority. A native
//! adapter must independently prove canonical scope/aliases, association coverage,
//! permissions, helper ownership and current state, then use the intent/KTM
//! boundary before any effect. No production observation adapter is wired yet.
#![allow(dead_code)]
use crate::{
    optimizer_inventory,
    optimizer_requests::{Caller, StoppedOwner},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) mod leases;

const APP_ID: i64 = 0x4443_5253;
const VERSION: i64 = 2;
pub(crate) const MAX_DB_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RESOURCES: usize = 512;
const MAX_MEMBERS: usize = 32;
const MAX_STATE: usize = 1024 * 1024;
const MAX_ROSTER: usize = 128 * 1024;
const SCHEMA: &str = r#"CREATE TABLE resources (
 id TEXT PRIMARY KEY NOT NULL CHECK(length(id) BETWEEN 1 AND 8224),
 revision BLOB NOT NULL CHECK(length(revision)=16 AND revision!=zeroblob(16)),
 phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 4),
 instance BLOB NOT NULL CHECK(length(instance)=16 AND instance!=zeroblob(16)),
 nonce BLOB CHECK(nonce IS NULL OR (length(nonce)=16 AND nonce!=zeroblob(16))),
 target INTEGER NOT NULL CHECK(target IN(0,1)),
 activation_review INTEGER NOT NULL CHECK(activation_review IN(0,1)),
 members TEXT NOT NULL CHECK(length(CAST(members AS BLOB)) BETWEEN 1 AND 131072),
 baseline BLOB NOT NULL CHECK(length(baseline)<=1048576),
 sleeping BLOB NOT NULL CHECK(length(sleeping)<=1048576),
 CHECK((phase IN(0,1) AND nonce IS NULL) OR (phase IN(2,3) AND nonce IS NOT NULL) OR phase=4)
) STRICT, WITHOUT ROWID"#;

#[derive(Debug)]
pub(crate) enum Error {
    Sql(rusqlite::Error),
    Invalid,
    UnsupportedDatabase,
    Corrupt,
    Durability,
    Capacity,
    Missing,
    Stale,
    Busy,
    NotAuthorized,
    Incomplete,
    Changed,
}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Optimizer resource ledger: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Stable native identity, not a display name, install-root prefix or JSON ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResourceId(String);
impl ResourceId {
    /// # Safety
    /// The trusted adapter must bind kind and bytes to one actual native resource
    /// and canonicalize all relevant aliases/shared registry views. This is
    /// identification only, not caller association or effect permission.
    pub(crate) unsafe fn from_native(kind: u8, identity: &[u8]) -> Result<Self, Error> {
        if !(1..=4).contains(&kind) || identity.is_empty() || identity.len() > 4096 {
            return Err(Error::Invalid);
        }
        let mut id = format!("native:v1:{kind}:");
        for byte in identity {
            use std::fmt::Write;
            write!(&mut id, "{byte:02x}").map_err(|_| Error::Invalid)?;
        }
        Ok(Self(id))
    }
    /// Stored identity data only. Native consumers must independently bind the
    /// decoded bytes to their fixed scope; this grants no native access right.
    pub(crate) fn native_parts(&self) -> Result<(u8, Vec<u8>), Error> {
        if !self.valid() {
            return Err(Error::Invalid);
        }
        let mut parts = self.0.split(':');
        parts.next();
        parts.next();
        let kind = parts
            .next()
            .ok_or(Error::Invalid)?
            .parse()
            .map_err(|_| Error::Invalid)?;
        let hex = parts.next().ok_or(Error::Invalid)?;
        let bytes = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| {
                    if byte <= b'9' {
                        byte - b'0'
                    } else {
                        byte - b'a' + 10
                    }
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect();
        Ok((kind, bytes))
    }
    fn valid(&self) -> bool {
        if self.0.len() > 8224 {
            return false;
        }
        let parts: Vec<_> = self.0.split(':').collect();
        parts.len() == 4
            && parts[0] == "native"
            && parts[1] == "v1"
            && matches!(parts[2], "1" | "2" | "3" | "4")
            && !parts[3].is_empty()
            && parts[3].len() <= 8192
            && parts[3].len() % 2 == 0
            && parts[3]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}

/// Association metadata. Its presence is never authorization for this caller.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Member {
    account: String,
    session: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    logon_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    boot_id: Option<Uuid>,
    program: String,
}
impl Member {
    pub(crate) fn for_caller(caller: &Caller, program: &str) -> Result<Self, Error> {
        let value = Self {
            account: caller.account().into(),
            session: caller.session(),
            logon_sid: caller.logon_sid().map(str::to_owned),
            boot_id: caller.boot_id(),
            program: program.to_ascii_lowercase(),
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.account.is_empty()
            || self.account.len() > 184
            || !self.account.is_ascii()
            || !self.account.starts_with("S-1-")
            || self.account.contains('\0')
            || self
                .boot_id
                .is_some_and(|id| id.is_nil() || self.logon_sid.is_none())
            || self
                .logon_sid
                .as_deref()
                .is_some_and(|s| !crate::optimizer_requests::canonical_logon_sid(s))
            || self.program.to_ascii_lowercase() != self.program
        {
            return Err(Error::Invalid);
        }
        optimizer_inventory::validate_key(&self.program).map_err(|_| Error::Invalid)
    }
    fn belongs_to(&self, caller: &Caller) -> bool {
        self.account == caller.account()
            && self.session == caller.session()
            && self.logon_sid.as_deref() == caller.logon_sid()
            && self.boot_id == caller.boot_id()
    }
    #[cfg(windows)]
    pub(crate) fn matches_principal(
        &self,
        principal: &crate::optimizer_pipe_security::Principal,
    ) -> std::io::Result<bool> {
        Ok(self.account == principal.user_sid()?
            && self.session == principal.session_id()
            && self.logon_sid == principal.logon_sid()?
            && self.boot_id == Some(principal.boot_id()))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Demand {
    member: Member,
    sleep: bool,
    wakes: Vec<Activation>,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Activation {
    invocation: Uuid,
    origin: Uuid,
    validated: Uuid,
}

/// An independently revalidated owned child/invocation, not a client saying
/// "finished" or a process ID alone. The producer must retain its process
/// creation identity in protected invocation state; that native adapter is open.
pub(crate) struct ActivationObservation {
    member: Member,
    invocation: Uuid,
    origin: Uuid,
    current: Uuid,
    alive: bool,
}
impl ActivationObservation {
    /// # Safety
    /// Prove this exact owned invocation's process creation identity and current
    /// alive/exited state natively. Bind the member and originating epoch to the
    /// protected launch record. Uninspectable/reused PID, caller messages and a
    /// stopped service epoch alone are not child-process exit evidence. A
    /// durably proven launch that was never entered may also release a pending
    /// activation; an uncertain process-creation result must never do so.
    pub(crate) unsafe fn from_native(
        member: Member,
        invocation: Uuid,
        origin: Uuid,
        current: Uuid,
        alive: bool,
    ) -> Result<Self, Error> {
        member.validate()?;
        if [invocation, origin, current].iter().any(Uuid::is_nil) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            member,
            invocation,
            origin,
            current,
            alive,
        })
    }
}

/// Consumed live native observation. Persistence/IPC cannot construct this type.
pub(crate) struct Observation {
    id: ResourceId,
    instance: Uuid,
    actual: Vec<u8>,
    members: Vec<Member>,
    complete: bool,
}
impl Observation {
    pub(crate) fn id(&self) -> &ResourceId {
        &self.id
    }
    pub(crate) fn actual(&self) -> &[u8] {
        &self.actual
    }
    /// A completion consumer may narrow evidence, never promote it to complete.
    pub(crate) fn constrain_completion(&mut self, accepted: bool) {
        self.complete &= accepted;
    }
    /// # Safety
    /// Bind the actual bytes and complete member roster to this exact native
    /// resource under the current exclusive runtime. Independently establish
    /// association, permissions and absence of foreign ownership. Do not create
    /// this from a saved row, request payload, path-containment proposal or
    /// unverified component list. This is not a lock across the later effect.
    pub(crate) unsafe fn from_native(
        id: ResourceId,
        instance: Uuid,
        actual: Vec<u8>,
        mut members: Vec<Member>,
        complete: bool,
    ) -> Result<Self, Error> {
        members.sort();
        if !id.valid()
            || instance.is_nil()
            || actual.len() > MAX_STATE
            || members.len() > MAX_MEMBERS
            || members.windows(2).any(|w| w[0] == w[1])
        {
            return Err(Error::Invalid);
        }
        for member in &members {
            member.validate()?;
        }
        Ok(Self {
            id,
            instance,
            actual,
            members,
            complete,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Awake,
    Sleeping,
    ChangingSleep,
    ChangingWake,
    Uncertain,
}
impl Phase {
    fn code(self) -> i64 {
        match self {
            Self::Awake => 0,
            Self::Sleeping => 1,
            Self::ChangingSleep => 2,
            Self::ChangingWake => 3,
            Self::Uncertain => 4,
        }
    }
    fn parse(v: i64) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::Awake),
            1 => Ok(Self::Sleeping),
            2 => Ok(Self::ChangingSleep),
            3 => Ok(Self::ChangingWake),
            4 => Ok(Self::Uncertain),
            _ => Err(Error::Corrupt),
        }
    }
    fn changing(self) -> bool {
        matches!(self, Self::ChangingSleep | Self::ChangingWake)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Target {
    Awake,
    Sleep,
}
/// Background components require unanimous sleep. An IFEO root gate is needed
/// while ANY owned hook requires it. These policies are never interchangeable.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Policy {
    AllMembersSleep,
    IfeoAnyHook,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootRoster {
    version: u8,
    policy: Policy,
    members: Vec<Demand>,
    hooks: Vec<HookRequirement>,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct HookRequirement {
    id: String,
    member: Member,
    needed: bool,
}
#[derive(Clone, Debug)]
struct Record {
    id: ResourceId,
    revision: Uuid,
    phase: Phase,
    instance: Uuid,
    nonce: Option<Uuid>,
    baseline: Vec<u8>,
    sleeping: Vec<u8>,
    members: Vec<Demand>,
    policy: Policy,
    hooks: Vec<HookRequirement>,
}
impl Record {
    fn validate(&self) -> Result<(), Error> {
        if !self.id.valid()
            || self.revision.is_nil()
            || self.instance.is_nil()
            || self.nonce.is_some_and(|v| v.is_nil())
            || (self.baseline == self.sleeping && self.policy != Policy::IfeoAnyHook)
            || self.baseline.len() > MAX_STATE
            || self.sleeping.len() > MAX_STATE
            || self.members.is_empty()
            || self.members.len() > MAX_MEMBERS
            || (self.phase.changing() && self.nonce.is_none())
            || (matches!(self.phase, Phase::Awake | Phase::Sleeping) && self.nonce.is_some())
            || self.members.windows(2).any(|w| w[0].member >= w[1].member)
        {
            return Err(Error::Corrupt);
        }
        for demand in &self.members {
            demand.member.validate().map_err(|_| Error::Corrupt)?;
            if demand.wakes.len() > 32
                || demand
                    .wakes
                    .windows(2)
                    .any(|w| w[0].invocation >= w[1].invocation)
                || demand.wakes.iter().any(|w| {
                    [w.invocation, w.origin, w.validated]
                        .iter()
                        .any(Uuid::is_nil)
                })
            {
                return Err(Error::Corrupt);
            }
        }
        if self.policy == Policy::AllMembersSleep {
            if !self.hooks.is_empty() {
                return Err(Error::Corrupt);
            }
        } else if self.hooks.is_empty()
            || self.hooks.len() > 64
            || self
                .members
                .iter()
                .any(|d| d.sleep || !self.hooks.iter().any(|h| h.member == d.member))
            || self
                .hooks
                .windows(2)
                .any(|w| (&w[0].id, &w[0].member) >= (&w[1].id, &w[1].member))
            || self.hooks.iter().any(|h| {
                !ResourceId(h.id.clone()).valid()
                    || h.id == self.id.0
                    || !self.members.iter().any(|d| d.member == h.member)
            })
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    fn target(&self) -> Target {
        let needs_hook = |d: &Demand| d.sleep && d.wakes.is_empty();
        if match self.policy {
            Policy::AllMembersSleep => self.members.iter().all(needs_hook),
            Policy::IfeoAnyHook => self.hooks.iter().any(|h| {
                h.needed
                    && self
                        .members
                        .iter()
                        .any(|d| d.member == h.member && d.wakes.is_empty())
            }),
        } {
            Target::Sleep
        } else {
            Target::Awake
        }
    }
    fn activation_review(&self) -> bool {
        self.members
            .iter()
            .any(|d| d.wakes.iter().any(|w| w.validated != self.instance))
    }
    fn matches_roster(&self, observation: &Observation) -> bool {
        self.members
            .iter()
            .map(|d| &d.member)
            .eq(observation.members.iter())
    }
    fn expected(&self) -> Option<&[u8]> {
        match self.phase {
            Phase::Awake => Some(&self.baseline),
            Phase::Sleeping => Some(&self.sleeping),
            _ => None,
        }
    }
}

/// Returned only after durable Changing state. It reserves bookkeeping, not a
/// native mutation; a separate exact intent, native scope/CAS and receipt remain
/// mandatory. No plan or missing claim is automatically replayed.
pub(crate) struct Claim {
    id: ResourceId,
    revision: Uuid,
    instance: Uuid,
    nonce: Uuid,
    target: Target,
    expected: Vec<u8>,
    desired: Vec<u8>,
    policy: Policy,
    source: Phase,
    hooks: Vec<HookRequirement>,
    members: Vec<Demand>,
}
impl Claim {
    pub(crate) fn is_root_gate(&self) -> bool {
        self.policy == Policy::IfeoAnyHook
    }
    pub(crate) fn covers_hook(&self, id: &ResourceId) -> bool {
        self.is_root_gate() && self.hooks.iter().any(|h| h.id == id.0)
    }
    pub(crate) fn permits_hook(&self, id: &ResourceId, needed: bool) -> bool {
        let refs: Vec<_> = self.hooks.iter().filter(|h| h.id == id.0).collect();
        if !self.is_root_gate() || refs.is_empty() {
            return false;
        }
        let effective = |h: &&HookRequirement| {
            h.needed
                && self
                    .members
                    .iter()
                    .any(|d| d.member == h.member && d.wakes.is_empty())
        };
        if needed {
            refs.iter().all(effective)
        } else {
            refs.iter().any(|h| !effective(h))
        }
    }
    pub(crate) fn target(&self) -> Target {
        self.target
    }
    pub(crate) fn id(&self) -> &ResourceId {
        &self.id
    }
    pub(crate) fn instance(&self) -> Uuid {
        self.instance
    }
    pub(crate) fn operation(&self) -> Uuid {
        self.nonce
    }
    pub(crate) fn expected(&self) -> &[u8] {
        &self.expected
    }
    pub(crate) fn desired(&self) -> &[u8] {
        &self.desired
    }
}

pub(crate) struct Catalog {
    connection: Connection,
}
pub(crate) struct View {
    pub(crate) revision: Uuid,
    pub(crate) phase: Phase,
    pub(crate) target: Target,
    pub(crate) temporary_activations: usize,
}
impl Catalog {
    pub(crate) fn inspect(&self, id: &ResourceId) -> Result<Option<View>, Error> {
        Ok(load(&self.connection, id)?.map(|r| View {
            revision: r.revision,
            phase: r.phase,
            target: r.target(),
            temporary_activations: r.members.iter().map(|d| d.wakes.len()).sum(),
        }))
    }
    pub(crate) fn open(mut connection: Connection) -> Result<Self, Error> {
        if !connection.is_autocommit() {
            return Err(Error::UnsupportedDatabase);
        }
        connection.busy_timeout(std::time::Duration::from_millis(250))?;
        connection.pragma_update(None, "trusted_schema", false)?;
        let path: String = connection.query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |r| r.get(0),
        )?;
        let attached: i64 = connection.query_row(
            "SELECT count(*) FROM pragma_database_list WHERE name NOT IN ('main','temp')",
            [],
            |r| r.get(0),
        )?;
        let temporary: i64 =
            connection.query_row("SELECT count(*) FROM sqlite_temp_schema", [], |r| r.get(0))?;
        if path.is_empty() || attached != 0 || temporary != 0 {
            return Err(Error::UnsupportedDatabase);
        }
        header(&connection)?;
        integrity(&connection)?;
        let mode: String = connection.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(Error::Durability);
        }
        connection.pragma_update(None, "synchronous", "EXTRA")?;
        let sync: i64 = connection.pragma_query_value(None, "synchronous", |r| r.get(0))?;
        if sync != 3 {
            return Err(Error::Durability);
        }
        let page: i64 = connection.pragma_query_value(None, "page_size", |r| r.get(0))?;
        if !(512..=65536).contains(&page) || (page & (page - 1)) != 0 {
            return Err(Error::Corrupt);
        }
        connection.pragma_update(
            None,
            "max_page_count",
            (MAX_DB_BYTES / (page as u64)) as i64,
        )?;
        let max: i64 = connection.pragma_query_value(None, "max_page_count", |r| r.get(0))?;
        if max as u64 != MAX_DB_BYTES / page as u64 {
            return Err(Error::Durability);
        }
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if header(&tx)? {
            tx.execute_batch(SCHEMA)?;
            tx.pragma_update(None, "application_id", APP_ID)?;
        }
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version < VERSION {
            tx.execute_batch(leases::SCHEMA)?;
            tx.execute_batch(leases::INDEX)?;
            tx.pragma_update(None, "user_version", VERSION)?;
        }
        validate(&tx)?;
        integrity(&tx)?;
        tx.commit()?;
        Ok(Self { connection })
    }

    /// Capture the baseline once. New associations enter Awake demand; they can
    /// never overwrite an earlier baseline or silently inherit a sleep request.
    pub(crate) fn register(
        &mut self,
        observation: Observation,
        sleeping: Vec<u8>,
    ) -> Result<Uuid, Error> {
        self.register_policy(observation, sleeping, Policy::AllMembersSleep, vec![])
    }
    /// # Safety
    /// Prove this resource is the exact canonical IFEO image-root UseFilter
    /// slot, with a complete canonical hook-reference/app roster and no foreign
    /// ownership. Multiple hooks per app and shared hook references are explicit.
    /// Requests represent hook requirements, not background-component consent.
    /// Every hook mutation must reserve this gate FIRST and include its claim
    /// in the same native-intent/catalog completion group. This API does not
    /// establish that native authority or build the effect plan.
    pub(crate) unsafe fn register_root_gate(
        &mut self,
        observation: Observation,
        enabled: Vec<u8>,
        hooks: Vec<(ResourceId, Member)>,
    ) -> Result<Uuid, Error> {
        if hooks.len() > 64
            || hooks
                .iter()
                .any(|(id, member)| !id.valid() || member.validate().is_err())
        {
            return Err(Error::Invalid);
        }
        let mut hooks: Vec<_> = hooks
            .into_iter()
            .map(|(id, member)| HookRequirement {
                id: id.0,
                member,
                needed: false,
            })
            .collect();
        hooks.sort_by(|a, b| (&a.id, &a.member).cmp(&(&b.id, &b.member)));
        if hooks.is_empty()
            || hooks
                .windows(2)
                .any(|w| w[0].id == w[1].id && w[0].member == w[1].member)
        {
            return Err(Error::Invalid);
        }
        self.register_policy(observation, enabled, Policy::IfeoAnyHook, hooks)
    }
    fn register_policy(
        &mut self,
        observation: Observation,
        sleeping: Vec<u8>,
        policy: Policy,
        hooks: Vec<HookRequirement>,
    ) -> Result<Uuid, Error> {
        if !observation.complete {
            return Err(Error::Incomplete);
        }
        if observation.members.is_empty() || sleeping.len() > MAX_STATE {
            return Err(Error::Invalid);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = if let Some(mut record) = load(&tx, &observation.id)? {
            if record.phase.changing() {
                return Err(Error::Busy);
            }
            if record.phase == Phase::Uncertain || record.instance != observation.instance {
                return Err(Error::Stale);
            }
            if record.sleeping != sleeping || record.policy != policy {
                return Err(Error::Changed);
            }
            if record.expected() != Some(observation.actual.as_slice()) {
                record.phase = Phase::Uncertain;
                record.revision = Uuid::new_v4();
                save(&tx, &record)?;
                tx.commit()?;
                return Err(Error::Changed);
            }
            if !record
                .members
                .iter()
                .all(|d| observation.members.contains(&d.member))
            {
                return Err(Error::Changed);
            }
            for member in &observation.members {
                if !record.members.iter().any(|d| &d.member == member) {
                    record.members.push(Demand {
                        member: member.clone(),
                        sleep: false,
                        wakes: Vec::new(),
                    });
                }
            }
            record.members.sort_by(|a, b| a.member.cmp(&b.member));
            if !record.hooks.iter().all(|old| {
                hooks
                    .iter()
                    .any(|h| h.id == old.id && h.member == old.member)
            }) {
                return Err(Error::Changed);
            }
            for hook in hooks {
                if !record
                    .hooks
                    .iter()
                    .any(|h| h.id == hook.id && h.member == hook.member)
                {
                    record.hooks.push(hook);
                }
            }
            record
                .hooks
                .sort_by(|a, b| (&a.id, &a.member).cmp(&(&b.id, &b.member)));
            record
        } else {
            let count: i64 = tx.query_row("SELECT count(*) FROM resources", [], |r| r.get(0))?;
            if count as usize >= MAX_RESOURCES {
                return Err(Error::Capacity);
            }
            if observation.actual == sleeping && policy != Policy::IfeoAnyHook {
                return Err(Error::Invalid);
            }
            Record {
                id: observation.id,
                revision: Uuid::new_v4(),
                phase: Phase::Awake,
                instance: observation.instance,
                nonce: None,
                baseline: observation.actual,
                sleeping,
                policy,
                hooks,
                members: observation
                    .members
                    .into_iter()
                    .map(|member| Demand {
                        member,
                        sleep: false,
                        wakes: Vec::new(),
                    })
                    .collect(),
            }
        };
        record.revision = Uuid::new_v4();
        save(&tx, &record)?;
        tx.commit()?;
        Ok(record.revision)
    }

    /// For a root gate, an app-wide request updates all of this member's hook
    /// references. An individual hook transition uses request_root_hook instead.
    /// The native owner must cover the affected hooks in its exact effect plan.
    pub(crate) fn request(
        &mut self,
        id: &ResourceId,
        revision: Uuid,
        caller: &Caller,
        member: &Member,
        sleep: bool,
    ) -> Result<Uuid, Error> {
        if !member.belongs_to(caller) {
            return Err(Error::NotAuthorized);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load(&tx, id)?.ok_or(Error::Missing)?;
        if record.revision != revision {
            return Err(Error::Stale);
        }
        if record.phase.changing() {
            return Err(Error::Busy);
        }
        let demand = record
            .members
            .iter_mut()
            .find(|d| &d.member == member)
            .ok_or(Error::NotAuthorized)?;
        if record.policy == Policy::IfeoAnyHook {
            for hook in record.hooks.iter_mut().filter(|h| &h.member == member) {
                hook.needed = sleep;
            }
        } else {
            demand.sleep = sleep;
        }
        record.revision = Uuid::new_v4();
        save(&tx, &record)?;
        tx.commit()?;
        Ok(record.revision)
    }

    /// Change one owned hook reference without releasing other hooks belonging
    /// to the same app. Caller messages/IDs alone grant no effect authority.
    pub(crate) fn request_root_hook(
        &mut self,
        id: &ResourceId,
        revision: Uuid,
        caller: &Caller,
        member: &Member,
        hook: &ResourceId,
        needed: bool,
    ) -> Result<Uuid, Error> {
        if !member.belongs_to(caller) || !hook.valid() {
            return Err(Error::NotAuthorized);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load(&tx, id)?.ok_or(Error::Missing)?;
        if record.policy != Policy::IfeoAnyHook {
            return Err(Error::Invalid);
        }
        if record.revision != revision {
            return Err(Error::Stale);
        }
        if record.phase.changing() {
            return Err(Error::Busy);
        }
        let item = record
            .hooks
            .iter_mut()
            .find(|h| h.id == hook.0 && &h.member == member)
            .ok_or(Error::NotAuthorized)?;
        item.needed = needed;
        record.revision = Uuid::new_v4();
        save(&tx, &record)?;
        tx.commit()?;
        Ok(record.revision)
    }

    /// Temporarily awaken without erasing the member's persistent sleep intent.
    /// The invocation owner must authorize/bind the ID before this bookkeeping.
    pub(crate) fn begin_activation(
        &mut self,
        id: &ResourceId,
        revision: Uuid,
        caller: &Caller,
        member: &Member,
        invocation: Uuid,
        instance: Uuid,
    ) -> Result<Uuid, Error> {
        if !member.belongs_to(caller) {
            return Err(Error::NotAuthorized);
        }
        if invocation.is_nil() || instance.is_nil() {
            return Err(Error::Invalid);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load(&tx, id)?.ok_or(Error::Missing)?;
        if record.revision != revision || record.instance != instance {
            return Err(Error::Stale);
        }
        let demand = record
            .members
            .iter_mut()
            .find(|d| &d.member == member)
            .ok_or(Error::NotAuthorized)?;
        if demand.wakes.iter().any(|w| w.invocation == invocation) {
            return Ok(record.revision);
        }
        if record.phase.changing() {
            return Err(Error::Busy);
        }
        if demand.wakes.len() >= 32 {
            return Err(Error::Capacity);
        }
        demand.wakes.push(Activation {
            invocation,
            origin: instance,
            validated: instance,
        });
        demand.wakes.sort_by_key(|w| w.invocation);
        record.revision = Uuid::new_v4();
        save(&tx, &record)?;
        tx.commit()?;
        Ok(record.revision)
    }

    pub(crate) fn observe_activation(
        &mut self,
        id: &ResourceId,
        revision: Uuid,
        proof: ActivationObservation,
    ) -> Result<Uuid, Error> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load(&tx, id)?.ok_or(Error::Missing)?;
        if record.revision != revision || record.instance != proof.current {
            return Err(Error::Stale);
        }
        if record.phase.changing() {
            return Err(Error::Busy);
        }
        let demand = record
            .members
            .iter_mut()
            .find(|d| d.member == proof.member)
            .ok_or(Error::NotAuthorized)?;
        let Some(index) = demand
            .wakes
            .iter()
            .position(|w| w.invocation == proof.invocation)
        else {
            return Ok(record.revision);
        };
        if demand.wakes[index].origin != proof.origin {
            return Err(Error::Stale);
        }
        if proof.alive {
            demand.wakes[index].validated = proof.current;
        } else {
            demand.wakes.remove(index);
        }
        record.revision = Uuid::new_v4();
        save(&tx, &record)?;
        tx.commit()?;
        Ok(record.revision)
    }

    pub(crate) fn begin(
        &mut self,
        id: &ResourceId,
        revision: Uuid,
        observation: Observation,
    ) -> Result<Option<Claim>, Error> {
        self.begin_policy(id, revision, observation, Policy::AllMembersSleep)
    }
    /// Always reserve an IFEO root before a hook mutation, even if UseFilter
    /// stays unchanged. Busy state blocks other root/roster/demand mutations;
    /// no claim is silently omitted just because another hook already needs it.
    pub(crate) fn begin_root_gate(
        &mut self,
        id: &ResourceId,
        revision: Uuid,
        observation: Observation,
    ) -> Result<Claim, Error> {
        self.begin_policy(id, revision, observation, Policy::IfeoAnyHook)?
            .ok_or(Error::Corrupt)
    }
    fn begin_policy(
        &mut self,
        id: &ResourceId,
        revision: Uuid,
        observation: Observation,
        policy: Policy,
    ) -> Result<Option<Claim>, Error> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load(&tx, id)?.ok_or(Error::Missing)?;
        if record.policy != policy {
            return Err(Error::Invalid);
        }
        if record.revision != revision
            || observation.id != record.id
            || observation.instance != record.instance
        {
            return Err(Error::Stale);
        }
        if record.phase.changing() {
            return Err(Error::Busy);
        }
        if record.phase == Phase::Uncertain {
            return Err(Error::Changed);
        }
        if !observation.complete || !record.matches_roster(&observation) {
            return Err(Error::Incomplete);
        }
        if record.expected() != Some(observation.actual.as_slice()) {
            record.phase = Phase::Uncertain;
            record.revision = Uuid::new_v4();
            save(&tx, &record)?;
            tx.commit()?;
            return Err(Error::Changed);
        }
        let target = record.target();
        if policy == Policy::AllMembersSleep
            && matches!(
                (record.phase, target),
                (Phase::Awake, Target::Awake) | (Phase::Sleeping, Target::Sleep)
            )
        {
            tx.commit()?;
            return Ok(None);
        }
        let nonce = Uuid::new_v4();
        let source = record.phase;
        let expected = observation.actual;
        let desired = if target == Target::Sleep {
            record.sleeping.clone()
        } else {
            record.baseline.clone()
        };
        record.phase = if target == Target::Sleep {
            Phase::ChangingSleep
        } else {
            Phase::ChangingWake
        };
        record.nonce = Some(nonce);
        record.revision = Uuid::new_v4();
        save(&tx, &record)?;
        let claim = Claim {
            members: if record.policy == Policy::IfeoAnyHook {
                record.members.clone()
            } else {
                vec![]
            },
            hooks: record.hooks,
            id: record.id,
            revision: record.revision,
            instance: record.instance,
            nonce,
            target,
            expected,
            desired,
            policy,
            source,
        };
        tx.commit()?;
        Ok(Some(claim))
    }

    pub(crate) fn finish(
        &mut self,
        claim: Claim,
        observation: Observation,
    ) -> Result<Phase, Error> {
        Ok(self.finish_batch(vec![(claim, observation)])?.remove(0))
    }
    /// One bookkeeping COMMIT for the complete native effect group. A stale
    /// later reservation leaves every earlier row unchanged. Partial evidence
    /// makes the complete group uncertain, never a partially successful report.
    pub(crate) fn finish_batch(
        &mut self,
        entries: Vec<(Claim, Observation)>,
    ) -> Result<Vec<Phase>, Error> {
        if entries.is_empty() || entries.len() > 48 {
            return Err(Error::Capacity);
        }
        if entries
            .iter()
            .enumerate()
            .any(|(i, (claim, _))| entries[..i].iter().any(|(other, _)| other.id == claim.id))
        {
            return Err(Error::Invalid);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut records = Vec::with_capacity(entries.len());
        for (claim, observation) in entries {
            let record = load(&tx, &claim.id)?.ok_or(Error::Missing)?;
            records.push((
                claim.nonce,
                Self::completed_record(record, &claim, observation)?,
            ));
        }
        let uncertain = records
            .iter()
            .any(|(_, record)| record.phase == Phase::Uncertain);
        let mut phases = Vec::with_capacity(records.len());
        for (nonce, mut record) in records {
            if uncertain {
                record.phase = Phase::Uncertain;
                record.nonce = Some(nonce);
            }
            save(&tx, &record)?;
            phases.push(record.phase);
        }
        tx.commit()?;
        Ok(phases)
    }
    fn completed_record(
        mut record: Record,
        claim: &Claim,
        observation: Observation,
    ) -> Result<Record, Error> {
        if record.revision != claim.revision
            || record.policy != claim.policy
            || record.hooks != claim.hooks
            || (claim.is_root_gate() && record.members != claim.members)
            || !matches!(claim.source, Phase::Awake | Phase::Sleeping)
            || record.instance != claim.instance
            || record.nonce != Some(claim.nonce)
            || record.phase
                != if claim.target == Target::Sleep {
                    Phase::ChangingSleep
                } else {
                    Phase::ChangingWake
                }
            || claim.expected.as_slice()
                != if claim.source == Phase::Awake {
                    record.baseline.as_slice()
                } else {
                    record.sleeping.as_slice()
                }
            || claim.desired.as_slice()
                != if claim.target == Target::Sleep {
                    record.sleeping.as_slice()
                } else {
                    record.baseline.as_slice()
                }
            || observation.id != claim.id
            || observation.instance != claim.instance
        {
            return Err(Error::Stale);
        }
        let verified = observation.complete
            && record.matches_roster(&observation)
            && observation.actual == claim.desired;
        record.phase = if verified {
            if claim.target == Target::Sleep {
                Phase::Sleeping
            } else {
                Phase::Awake
            }
        } else {
            Phase::Uncertain
        };
        if verified {
            record.nonce = None;
        }
        record.revision = Uuid::new_v4();
        Ok(record)
    }

    /// Explicit native reconciliation, never effect retry. Do not abandon a
    /// live Changing owner; only a sealed stopped-owner pass can make it Uncertain.
    pub(crate) fn reconcile(
        &mut self,
        id: &ResourceId,
        revision: Uuid,
        observation: Observation,
    ) -> Result<Uuid, Error> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load(&tx, id)?.ok_or(Error::Missing)?;
        // A root slot alone cannot prove the physical owned-hook set. In
        // particular, preexisting UseFilter=1 is both baseline and enabled.
        // Keep root ownership uncertain until a complete hook owner supplies
        // its separate recovery proof; never infer release from equal bytes.
        if record.policy == Policy::IfeoAnyHook {
            return Err(Error::Incomplete);
        }
        if record.revision != revision || observation.id != record.id {
            return Err(Error::Stale);
        }
        if record.phase.changing() {
            return Err(Error::Busy);
        }
        if !observation.complete || !record.matches_roster(&observation) {
            return Err(Error::Incomplete);
        }
        record.phase = if observation.actual == record.baseline {
            Phase::Awake
        } else if observation.actual == record.sleeping {
            Phase::Sleeping
        } else {
            return Err(Error::Changed);
        };
        record.instance = observation.instance;
        record.nonce = None;
        record.revision = Uuid::new_v4();
        save(&tx, &record)?;
        tx.commit()?;
        Ok(record.revision)
    }

    /// Forget only an independently observed original state. An unknown or
    /// sleeping resource retains its baseline and every remaining membership.
    pub(crate) fn release_member(
        &mut self,
        id: &ResourceId,
        revision: Uuid,
        caller: &Caller,
        member: &Member,
        observation: Observation,
    ) -> Result<Option<Uuid>, Error> {
        if !member.belongs_to(caller) {
            return Err(Error::NotAuthorized);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = load(&tx, id)?.ok_or(Error::Missing)?;
        if record.policy == Policy::IfeoAnyHook {
            return Err(Error::Incomplete);
        }
        if record.revision != revision
            || observation.id != record.id
            || observation.instance != record.instance
        {
            return Err(Error::Stale);
        }
        if record.phase != Phase::Awake
            || !observation.complete
            || observation.actual != record.baseline
        {
            return Err(Error::Changed);
        }
        let index = record
            .members
            .iter()
            .position(|d| &d.member == member)
            .ok_or(Error::NotAuthorized)?;
        if leases::member_is_bound(&tx, id, member)? {
            return Err(Error::Busy);
        }
        record.members.remove(index);
        let result = if record.members.is_empty() {
            tx.execute("DELETE FROM resources WHERE id=?1", [&record.id.0])?;
            None
        } else {
            record.revision = Uuid::new_v4();
            save(&tx, &record)?;
            Some(record.revision)
        };
        tx.commit()?;
        Ok(result)
    }

    pub(crate) fn requires_review(&self, instance: Uuid) -> Result<bool, Error> {
        // Summaries are derived/validated with each complete row write. Routine
        // readiness must not reload up to 64 MiB of baseline/target payloads.
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM resources WHERE instance!=?1 OR phase IN(2,3,4) OR activation_review=1 OR (phase=0 AND target=1) OR (phase=1 AND target=0))",
            [instance.as_bytes().as_slice()],|r|r.get(0))?)
    }
    pub(crate) fn has_foreign_active_owner(&self, instance: Uuid) -> Result<bool, Error> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM resources WHERE phase IN(2,3) AND instance!=?1)",
            [instance.as_bytes().as_slice()],
            |r| r.get(0),
        )?)
    }
    pub(crate) fn mark_stopped_owner_uncertain(
        &mut self,
        proof: &StoppedOwner,
    ) -> Result<(), Error> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate(&tx)?;
        tx.execute(
            "UPDATE resources SET phase=4 WHERE phase IN(2,3) AND instance=?1",
            [proof.instance().as_bytes().as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn load(connection: &Connection, id: &ResourceId) -> Result<Option<Record>, Error> {
    if !id.valid() {
        return Err(Error::Invalid);
    }
    let row=connection.query_row("SELECT id,revision,phase,instance,nonce,baseline,sleeping,members,target,activation_review FROM resources WHERE id=?1",[&id.0],read_row).optional()?;
    row.map(|r| decode(r)).transpose()
}
type Stored = (
    String,
    Vec<u8>,
    i64,
    Vec<u8>,
    Option<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
    String,
    i64,
    i64,
);
fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Stored> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    ))
}
fn decode(r: Stored) -> Result<Record, Error> {
    if r.7.len() > MAX_ROSTER {
        return Err(Error::Capacity);
    }
    let (members, policy, hooks) = if r.7.starts_with('[') {
        (
            serde_json::from_str::<Vec<Demand>>(&r.7).map_err(|_| Error::Corrupt)?,
            Policy::AllMembersSleep,
            vec![],
        )
    } else {
        let roster: RootRoster = serde_json::from_str(&r.7).map_err(|_| Error::Corrupt)?;
        let version = root_roster_version(&roster.members);
        if roster.version != version || roster.policy != Policy::IfeoAnyHook {
            return Err(Error::Corrupt);
        }
        (roster.members, roster.policy, roster.hooks)
    };
    if encode_roster(&members, policy, &hooks)? != r.7 {
        return Err(Error::Corrupt);
    }
    let value = Record {
        id: ResourceId(r.0),
        revision: Uuid::from_slice(&r.1).map_err(|_| Error::Corrupt)?,
        phase: Phase::parse(r.2)?,
        instance: Uuid::from_slice(&r.3).map_err(|_| Error::Corrupt)?,
        nonce: r
            .4
            .map(|v| Uuid::from_slice(&v).map_err(|_| Error::Corrupt))
            .transpose()?,
        baseline: r.5,
        sleeping: r.6,
        members,
        policy,
        hooks,
    };
    value.validate()?;
    if r.8 != i64::from(value.target() == Target::Sleep)
        || r.9 != i64::from(value.activation_review())
    {
        return Err(Error::Corrupt);
    }
    Ok(value)
}
fn save(connection: &Connection, record: &Record) -> Result<(), Error> {
    record.validate()?;
    let members = encode_roster(&record.members, record.policy, &record.hooks)?;
    if members.len() > MAX_ROSTER {
        return Err(Error::Capacity);
    }
    connection.execute("INSERT INTO resources(id,revision,phase,instance,nonce,baseline,sleeping,members,target,activation_review) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
     ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,phase=excluded.phase,instance=excluded.instance,nonce=excluded.nonce,baseline=excluded.baseline,sleeping=excluded.sleeping,members=excluded.members,target=excluded.target,activation_review=excluded.activation_review",
     params![record.id.0,record.revision.as_bytes().as_slice(),record.phase.code(),record.instance.as_bytes().as_slice(),record.nonce.map(|v|v.as_bytes().to_vec()),record.baseline,record.sleeping,members,i64::from(record.target()==Target::Sleep),i64::from(record.activation_review())])?;
    Ok(())
}
fn encode_roster(
    members: &[Demand],
    policy: Policy,
    hooks: &[HookRequirement],
) -> Result<String, Error> {
    if policy == Policy::AllMembersSleep {
        // Existing documents stay byte-canonical; old readers fail closed on
        // the explicit versioned object used only for the new root-gate role.
        serde_json::to_string(members)
    } else {
        serde_json::to_string(&RootRoster {
            version: root_roster_version(members),
            policy,
            members: members.to_vec(),
            hooks: hooks.to_vec(),
        })
    }
    .map_err(|_| Error::Invalid)
}
fn root_roster_version(members: &[Demand]) -> u8 {
    if members.iter().any(|d| d.member.boot_id.is_some()) {
        4
    } else if members.iter().any(|d| d.member.logon_sid.is_some()) {
        3
    } else {
        2
    }
}
fn records(connection: &Connection) -> Result<Vec<Record>, Error> {
    let mut query=connection.prepare("SELECT id,revision,phase,instance,nonce,baseline,sleeping,members,target,activation_review FROM resources ORDER BY id LIMIT 513")?;
    let mut result = Vec::new();
    for row in query.query_map([], read_row)? {
        result.push(decode(row?)?);
        if result.len() > MAX_RESOURCES {
            return Err(Error::Capacity);
        }
    }
    Ok(result)
}
fn header(connection: &Connection) -> Result<bool, Error> {
    let app: i64 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let count: i64 =
        connection.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
    let pages: i64 = connection.pragma_query_value(None, "page_count", |r| r.get(0))?;
    let size: i64 = connection.pragma_query_value(None, "page_size", |r| r.get(0))?;
    if pages
        .checked_mul(size)
        .is_none_or(|v| v < 0 || v as u64 > MAX_DB_BYTES)
    {
        return Err(Error::Capacity);
    }
    if app == 0 && version == 0 && count == 0 {
        return Ok(true);
    }
    if app != APP_ID || !matches!(version, 1 | VERSION) {
        return Err(Error::UnsupportedDatabase);
    }
    validate(connection)?;
    Ok(false)
}
fn validate(connection: &Connection) -> Result<(), Error> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let count: i64 =
        connection.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
    let schema: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='resources' AND type='table'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if count != if version == 1 { 1 } else { 3 }
        || schema.as_deref().map(|s| s.trim().trim_end_matches(';')) != Some(SCHEMA.trim())
    {
        return Err(Error::UnsupportedDatabase);
    }
    if version == VERSION {
        for (kind, name, expected) in [
            ("table", "leases", leases::SCHEMA),
            ("index", "bound_lease_member", leases::INDEX),
        ] {
            let actual: Option<String> = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type=?1 AND name=?2",
                    params![kind, name],
                    |r| r.get(0),
                )
                .optional()?;
            if actual.as_deref().map(|s| s.trim().trim_end_matches(';')) != Some(expected.trim()) {
                return Err(Error::UnsupportedDatabase);
            }
        }
    }
    records(connection)?;
    if version == VERSION {
        leases::validate_rows(connection)?;
    }
    Ok(())
}
fn integrity(connection: &Connection) -> Result<(), Error> {
    let state: String = connection.query_row("PRAGMA quick_check(1)", [], |r| r.get(0))?;
    if state != "ok" {
        return Err(Error::Corrupt);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
