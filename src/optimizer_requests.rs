//! Durable invocation ledger for the future optimizer background owner.
//!
//! This does not discover/authorize native leases or execute effects. Its caller
//! must supply a fresh service-owned lease preflight before admission AND claim,
//! and independently verify native outcomes before recording success. Queue
//! tickets are wake hints, not effect authority. No interrupted work is replayed.
//!
//! The runtime must supply an exclusively managed connection in protected service
//! storage and establish that an old owner stopped before requesting recovery.
//! SQLite transactions do not establish filesystem ACLs or service singleton
//! ownership. Nothing here is connected to application startup or an installed
//! service. Fixture databases are ordinary temporary files.

#![allow(dead_code)]

use crate::optimizer_protocol::{InvocationState, Refusal, ServiceResponse};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::time::Duration;
use uuid::Uuid;

const APPLICATION_ID: i64 = 0x4443_4f50;
const SCHEMA_VERSION: i64 = 4;
const MAX_RECORDS: i64 = 4096;
const MAX_DB_BYTES: i64 = 16 * 1024 * 1024;
const MAX_REVIEW_BATCH: usize = 64;
mod context;
pub(crate) use context::ContextBinding;
const LEGACY_SCHEMA: &str = r#"CREATE TABLE invocations (
    account TEXT NOT NULL CHECK(length(account) BETWEEN 1 AND 184 AND instr(account,char(0))=0),
    session INTEGER NOT NULL CHECK(session BETWEEN 0 AND 4294967295),
    invocation BLOB NOT NULL CHECK(length(invocation)=16 AND invocation!=zeroblob(16)),
    lease BLOB NOT NULL CHECK(length(lease)=16 AND lease!=zeroblob(16)),
    revision BLOB NOT NULL CHECK(length(revision)=16 AND revision!=zeroblob(16)),
    phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 5),
    instance BLOB CHECK(instance IS NULL OR (length(instance)=16 AND instance!=zeroblob(16))),
    nonce BLOB CHECK(nonce IS NULL OR (length(nonce)=16 AND nonce!=zeroblob(16))),
    CHECK((phase=0 AND instance IS NULL AND nonce IS NULL) OR
          (phase!=0 AND instance IS NOT NULL AND nonce IS NOT NULL)),
    PRIMARY KEY(account,session,invocation)
) STRICT, WITHOUT ROWID"#;
const LOGON_SCHEMA: &str = r#"CREATE TABLE invocations (
    account TEXT NOT NULL CHECK(length(account) BETWEEN 1 AND 184 AND instr(account,char(0))=0),
    session INTEGER NOT NULL CHECK(session BETWEEN 0 AND 4294967295),
    logon TEXT NOT NULL DEFAULT '' CHECK(length(logon)<=64 AND instr(logon,char(0))=0),
    invocation BLOB NOT NULL CHECK(length(invocation)=16 AND invocation!=zeroblob(16)),
    lease BLOB NOT NULL CHECK(length(lease)=16 AND lease!=zeroblob(16)),
    revision BLOB NOT NULL CHECK(length(revision)=16 AND revision!=zeroblob(16)),
    phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 5),
    instance BLOB CHECK(instance IS NULL OR (length(instance)=16 AND instance!=zeroblob(16))),
    nonce BLOB CHECK(nonce IS NULL OR (length(nonce)=16 AND nonce!=zeroblob(16))),
    CHECK((phase=0 AND instance IS NULL AND nonce IS NULL) OR
          (phase!=0 AND instance IS NOT NULL AND nonce IS NOT NULL)),
    PRIMARY KEY(account,session,logon,invocation)
) STRICT, WITHOUT ROWID"#;
const BOOT_SCHEMA: &str = r#"CREATE TABLE invocations (
    account TEXT NOT NULL CHECK(length(account) BETWEEN 1 AND 184 AND instr(account,char(0))=0),
    session INTEGER NOT NULL CHECK(session BETWEEN 0 AND 4294967295),
    logon TEXT NOT NULL DEFAULT '' CHECK(length(logon)<=64 AND instr(logon,char(0))=0),
    boot BLOB NOT NULL DEFAULT X'00000000000000000000000000000000' CHECK(length(boot)=16),
    invocation BLOB NOT NULL CHECK(length(invocation)=16 AND invocation!=zeroblob(16)),
    lease BLOB NOT NULL CHECK(length(lease)=16 AND lease!=zeroblob(16)),
    revision BLOB NOT NULL CHECK(length(revision)=16 AND revision!=zeroblob(16)),
    phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 5),
    instance BLOB CHECK(instance IS NULL OR (length(instance)=16 AND instance!=zeroblob(16))),
    nonce BLOB CHECK(nonce IS NULL OR (length(nonce)=16 AND nonce!=zeroblob(16))),
    CHECK((phase=0 AND instance IS NULL AND nonce IS NULL) OR
          (phase!=0 AND instance IS NOT NULL AND nonce IS NOT NULL)),
    PRIMARY KEY(account,session,logon,boot,invocation)
) STRICT, WITHOUT ROWID"#;
const SCHEMA: &str = r#"CREATE TABLE invocations (
    account TEXT NOT NULL CHECK(length(account) BETWEEN 1 AND 184 AND instr(account,char(0))=0),
    session INTEGER NOT NULL CHECK(session BETWEEN 0 AND 4294967295),
    logon TEXT NOT NULL DEFAULT '' CHECK(length(logon)<=64 AND instr(logon,char(0))=0),
    boot BLOB NOT NULL DEFAULT X'00000000000000000000000000000000' CHECK(length(boot)=16),
    invocation BLOB NOT NULL CHECK(length(invocation)=16 AND invocation!=zeroblob(16)),
    lease BLOB NOT NULL CHECK(length(lease)=16 AND lease!=zeroblob(16)),
    revision BLOB NOT NULL CHECK(length(revision)=16 AND revision!=zeroblob(16)),
    phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 5),
    instance BLOB CHECK(instance IS NULL OR (length(instance)=16 AND instance!=zeroblob(16))),
    nonce BLOB CHECK(nonce IS NULL OR (length(nonce)=16 AND nonce!=zeroblob(16))),
    context BLOB CHECK(context IS NULL OR length(context)=32),
    CHECK((phase=0 AND instance IS NULL AND nonce IS NULL) OR
          (phase!=0 AND instance IS NOT NULL AND nonce IS NOT NULL)),
    PRIMARY KEY(account,session,logon,boot,invocation)
) STRICT, WITHOUT ROWID"#;
#[derive(Clone, Copy, Eq, PartialEq)]
enum Layout {
    Fresh,
    Legacy,
    Logon,
    Boot,
    Current,
}

#[derive(Debug)]
pub(crate) enum LedgerError {
    Sql(rusqlite::Error),
    InvalidIdentity,
    ContextHash,
    RequestMismatch,
    UnsupportedDatabase,
    CorruptDatabase,
    UnsupportedDurability,
    Capacity,
    NotAuthorized,
    StaleLease,
    StaleClaim,
}
impl From<rusqlite::Error> for LedgerError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sql(error)
    }
}
impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Optimizer request ledger: {self:?}")
    }
}
impl std::error::Error for LedgerError {}

/// Runtime callers derive this from authenticated native identity, not JSON.
/// Logon is part of the durable key. A stored key is not an authenticated native
/// caller: only native-origin snapshots can supply a fresh owner preflight.
/// Native origin does not prove that a snapshot is still current at effect time.
#[derive(Clone, Debug)]
pub(crate) struct Caller {
    account: String,
    session: u32,
    logon_sid: Option<String>,
    boot_id: Option<Uuid>,
    native_origin: bool,
}
impl PartialEq for Caller {
    fn eq(&self, other: &Self) -> bool {
        self.account == other.account
            && self.session == other.session
            && self.logon_sid == other.logon_sid
            && self.boot_id == other.boot_id
    }
}
impl Eq for Caller {}
impl Caller {
    pub(crate) fn account(&self) -> &str {
        &self.account
    }
    pub(crate) fn session(&self) -> u32 {
        self.session
    }
    pub(crate) fn logon_sid(&self) -> Option<&str> {
        self.logon_sid.as_deref()
    }
    pub(crate) fn boot_id(&self) -> Option<Uuid> {
        self.boot_id
    }
    fn boot_key(&self) -> [u8; 16] {
        boot_key(self.boot_id)
    }
    #[cfg(test)]
    pub(crate) fn fixture(account: &str, session: u32) -> Self {
        Self {
            account: account.into(),
            session,
            logon_sid: None,
            boot_id: None,
            native_origin: true,
        }
    }
    #[cfg(test)]
    pub(crate) fn fixture_logon(account: &str, session: u32, logon_sid: &str) -> Self {
        let mut caller = Self::fixture(account, session);
        caller.logon_sid = Some(logon_sid.into());
        caller.validate().unwrap();
        caller
    }
    #[cfg(test)]
    pub(crate) fn fixture_boot(
        account: &str,
        session: u32,
        logon_sid: &str,
        boot_id: Uuid,
    ) -> Self {
        let mut caller = Self::fixture_logon(account, session, logon_sid);
        caller.boot_id = Some(boot_id);
        caller.validate().unwrap();
        caller
    }
    #[cfg(windows)]
    pub(crate) fn authenticated(
        request: &crate::optimizer_pipe_security::AuthenticatedRequest,
    ) -> Result<Self, LedgerError> {
        let account = request
            .caller()
            .user_sid()
            .map_err(|_| LedgerError::InvalidIdentity)?;
        let caller = Self {
            account,
            session: request.caller().session_id(),
            logon_sid: request
                .caller()
                .logon_sid()
                .map_err(|_| LedgerError::InvalidIdentity)?,
            boot_id: Some(request.caller().boot_id()),
            native_origin: true,
        };
        caller.validate()?;
        Ok(caller)
    }
    fn validate(&self) -> Result<(), LedgerError> {
        if self.account.is_empty()
            || self.account.len() > 184
            || !self.account.is_ascii()
            || self.account.contains('\0')
            || !self.account.starts_with("S-1-")
            || self
                .boot_id
                .is_some_and(|id| id.is_nil() || self.logon_sid.is_none())
            || self
                .logon_sid
                .as_deref()
                .is_some_and(|s| !canonical_logon_sid(s))
        {
            Err(LedgerError::InvalidIdentity)
        } else {
            Ok(())
        }
    }
}

pub(crate) fn canonical_logon_sid(s: &str) -> bool {
    if s.len() > 64 || !s.is_ascii() || !s.starts_with("S-1-5-5-") {
        return false;
    }
    let parts: Vec<_> = s.split('-').collect();
    parts.len() == 6
        && parts[4..]
            .iter()
            .all(|p| p.parse::<u32>().ok().is_some_and(|n| n.to_string() == *p))
}
pub(crate) fn boot_key(id: Option<Uuid>) -> [u8; 16] {
    *id.unwrap_or(Uuid::nil()).as_bytes()
}
fn stored_boot(bytes: Vec<u8>) -> Result<Option<Uuid>, LedgerError> {
    let id = Uuid::from_slice(&bytes).map_err(|_| LedgerError::CorruptDatabase)?;
    Ok((!id.is_nil()).then_some(id))
}

/// Constructed by the trusted lease owner after fresh ownership/generation
/// checks. No frame field can construct this value. It is consumed so admission
/// and worker claim cannot accidentally reuse the same preflight object.
pub(crate) struct LeasePreflight {
    owner: Caller,
    lease: Uuid,
    revision: Uuid,
    context: ContextBinding,
}
impl LeasePreflight {
    pub(crate) fn from_owner_observation(
        owner: Caller,
        lease: Uuid,
        revision: Uuid,
        context: ContextBinding,
    ) -> Result<Self, LedgerError> {
        owner.validate()?;
        if !owner.native_origin {
            return Err(LedgerError::NotAuthorized);
        }
        valid_id(lease)?;
        valid_id(revision)?;
        Ok(Self {
            owner,
            lease,
            revision,
            context,
        })
    }
}

/// Native owner-death evidence, never supplied by a request or reconstructed
/// from a database UUID alone. Reconciliation consumes no effect authority.
pub(crate) struct StoppedOwner {
    instance: Uuid,
}
impl StoppedOwner {
    /// # Safety
    /// The exclusive protected runtime must bind this ID to its validated
    /// persisted epoch and prove that epoch's process has ended using native
    /// process identity/exit observations. A released lock is insufficient.
    #[cfg(windows)]
    pub(crate) unsafe fn from_native_exit(instance: Uuid) -> Result<Self, LedgerError> {
        valid_id(instance)?;
        Ok(Self { instance })
    }
    pub(crate) fn instance(&self) -> Uuid {
        self.instance
    }
    #[cfg(test)]
    pub(crate) fn fixture(instance: Uuid) -> Self {
        Self { instance }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Queued,
    Running,
    VerifiedReenabled,
    Partial,
    Rejected,
    Uncertain,
}
impl Phase {
    fn code(self) -> i64 {
        match self {
            Self::Queued => 0,
            Self::Running => 1,
            Self::VerifiedReenabled => 2,
            Self::Partial => 3,
            Self::Rejected => 4,
            Self::Uncertain => 5,
        }
    }
    fn parse(value: i64) -> Result<Self, LedgerError> {
        match value {
            0 => Ok(Self::Queued),
            1 => Ok(Self::Running),
            2 => Ok(Self::VerifiedReenabled),
            3 => Ok(Self::Partial),
            4 => Ok(Self::Rejected),
            5 => Ok(Self::Uncertain),
            _ => Err(LedgerError::CorruptDatabase),
        }
    }
    pub(crate) fn response(self, invocation_id: Uuid) -> ServiceResponse {
        let state = match self {
            Self::Queued => InvocationState::Queued,
            Self::Running => InvocationState::Running,
            Self::VerifiedReenabled => InvocationState::VerifiedReenabled,
            Self::Partial => InvocationState::Partial,
            Self::Rejected => InvocationState::Rejected,
            Self::Uncertain => {
                return ServiceResponse::Refused {
                    reason: Refusal::RecoveryRequired,
                };
            }
        };
        ServiceResponse::Invocation {
            invocation_id,
            state,
        }
    }
}

#[derive(Debug)]
pub(crate) struct QueueTicket {
    owner: Caller,
    invocation: Uuid,
    lease: Uuid,
    revision: Uuid,
    // None is preserved only for older records, never a claimable context.
    context: Option<ContextBinding>,
}
impl QueueTicket {
    pub(crate) fn owner(&self) -> &Caller {
        &self.owner
    }
    pub(crate) fn invocation(&self) -> Uuid {
        self.invocation
    }
    pub(crate) fn lease(&self) -> Uuid {
        self.lease
    }
    pub(crate) fn revision(&self) -> Uuid {
        self.revision
    }
}
#[derive(Debug)]
pub(crate) enum Admission {
    New(QueueTicket),
    Existing(Phase),
    Conflict,
}

/// Non-cloneable claim returned only after a committed Queued -> Running CAS.
#[derive(Debug)]
pub(crate) struct Claim {
    ticket: QueueTicket,
    instance: Uuid,
    nonce: Uuid,
}
impl Claim {
    pub(crate) fn invocation(&self) -> Uuid {
        self.ticket.invocation
    }
    pub(crate) fn lease(&self) -> Uuid {
        self.ticket.lease
    }
}

/// The trusted worker must establish this outcome through independent native
/// observations. Persisting this enum does not perform or verify any change.
pub(crate) enum WorkerOutcome {
    VerifiedReenabled,
    Partial,
    Rejected,
    Uncertain,
}
impl WorkerOutcome {
    fn phase(self) -> Phase {
        match self {
            Self::VerifiedReenabled => Phase::VerifiedReenabled,
            Self::Partial => Phase::Partial,
            Self::Rejected => Phase::Rejected,
            Self::Uncertain => Phase::Uncertain,
        }
    }
}

pub(crate) struct PendingReview {
    pub(crate) tickets: Vec<QueueTicket>,
    pub(crate) has_more: bool,
}

pub(crate) struct Ledger {
    connection: Connection,
}
impl Ledger {
    /// The production admission boundary keeps the native caller, command and
    /// exact wire IDs together. Readiness/query commands cannot enqueue work.
    #[cfg(windows)]
    pub(crate) fn admit_authenticated(
        &mut self,
        request: &crate::optimizer_pipe_security::AuthenticatedRequest,
        preflight: LeasePreflight,
    ) -> Result<Admission, LedgerError> {
        use crate::optimizer_protocol::HelperRequest;
        let HelperRequest::Reactivate {
            lease_id,
            invocation_id,
            original,
        } = &request.request().request
        else {
            return Err(LedgerError::RequestMismatch);
        };
        if *lease_id != preflight.lease || ContextBinding::observe(original)? != preflight.context {
            return Err(LedgerError::RequestMismatch);
        }
        let caller = Caller::authenticated(request)?;
        self.admit(&caller, *invocation_id, preflight)
    }

    #[cfg(windows)]
    pub(crate) fn query_authenticated(
        &self,
        request: &crate::optimizer_pipe_security::AuthenticatedRequest,
    ) -> Result<ServiceResponse, LedgerError> {
        use crate::optimizer_protocol::HelperRequest;
        let HelperRequest::QueryInvocation { invocation_id } = &request.request().request else {
            return Err(LedgerError::RequestMismatch);
        };
        let caller = Caller::authenticated(request)?;
        Ok(match self.query(&caller, *invocation_id)? {
            Some(phase) => phase.response(*invocation_id),
            None if legacy_collision(&self.connection, &caller, *invocation_id)? => {
                ServiceResponse::Refused {
                    reason: Refusal::RecoveryRequired,
                }
            }
            None => ServiceResponse::Invocation {
                invocation_id: *invocation_id,
                state: InvocationState::Unknown,
            },
        })
    }

    /// Takes an owned, unshared, file-backed connection from the service's
    /// protected storage owner. This verifies format/settings, not path safety.
    /// Opens never recover or replay a running invocation automatically.
    pub(crate) fn open(mut connection: Connection) -> Result<Self, LedgerError> {
        if !connection.is_autocommit() {
            return Err(LedgerError::UnsupportedDatabase);
        }
        connection.busy_timeout(Duration::from_millis(250))?;
        connection.pragma_update(None, "trusted_schema", false)?;
        let database: String = connection.query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |row| row.get(0),
        )?;
        let attachments: i64 = connection.query_row(
            "SELECT count(*) FROM pragma_database_list WHERE name NOT IN ('main','temp')",
            [],
            |row| row.get(0),
        )?;
        let temporary_objects: i64 =
            connection.query_row("SELECT count(*) FROM sqlite_temp_schema", [], |row| {
                row.get(0)
            })?;
        if database.is_empty() || attachments != 0 || temporary_objects != 0 {
            return Err(LedgerError::UnsupportedDatabase);
        }
        validate_header(&connection)?;
        validate_integrity(&connection)?;
        let mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        connection.pragma_update(None, "synchronous", "EXTRA")?;
        let synchronous: i64 =
            connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("delete") || synchronous != 3 {
            return Err(LedgerError::UnsupportedDurability);
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let layout = validate_header(&transaction)?;
        if layout == Layout::Fresh {
            transaction.execute_batch(SCHEMA)?;
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        } else if matches!(layout, Layout::Legacy | Layout::Logon | Layout::Boot) {
            transaction.execute_batch("ALTER TABLE invocations RENAME TO invocations_old;")?;
            transaction.execute_batch(SCHEMA)?;
            transaction.execute_batch(if layout == Layout::Legacy {
                "INSERT INTO invocations(account,session,logon,invocation,lease,revision,phase,instance,nonce)
                SELECT account,session,'',invocation,lease,revision,phase,instance,nonce FROM invocations_old;
                DROP TABLE invocations_old;"
            } else if layout == Layout::Logon {
                "INSERT INTO invocations(account,session,logon,invocation,lease,revision,phase,instance,nonce)
                SELECT account,session,logon,invocation,lease,revision,phase,instance,nonce FROM invocations_old;
                DROP TABLE invocations_old;"
            } else {
                "INSERT INTO invocations(account,session,logon,boot,invocation,lease,revision,phase,instance,nonce)
                SELECT account,session,logon,boot,invocation,lease,revision,phase,instance,nonce FROM invocations_old;
                DROP TABLE invocations_old;"
            })?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        validate_schema(&transaction, Layout::Current)?;
        validate_integrity(&transaction)?;
        transaction.commit()?;
        Ok(Self { connection })
    }

    /// The trusted owner must authorize the requested lease before this call.
    /// A ticket is returned after COMMIT only; lost delivery leaves a durable
    /// queued row for explicit review, never another automatic admission.
    fn admit(
        &mut self,
        caller: &Caller,
        invocation: Uuid,
        preflight: LeasePreflight,
    ) -> Result<Admission, LedgerError> {
        caller.validate()?;
        valid_id(invocation)?;
        if preflight.owner != *caller {
            return Err(LedgerError::NotAuthorized);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = lookup(&tx, caller, invocation)?;
        let result = if let Some((lease, _stored_revision, phase, context)) = existing {
            // Revision is a worker generation guard, not a field supplied by
            // the client. A same-request retry returns its historical state;
            // it cannot replace the original revision or issue a new ticket.
            if lease != preflight.lease || context != Some(preflight.context) {
                Admission::Conflict
            } else {
                Admission::Existing(phase)
            }
        } else if legacy_collision(&tx, caller, invocation)? {
            // Unknown legacy identity is not another known login. Do not turn
            // a retry of its nonce into a second launch or reveal its phase.
            Admission::Conflict
        } else {
            let count: i64 =
                tx.query_row("SELECT count(*) FROM invocations", [], |row| row.get(0))?;
            if count >= MAX_RECORDS {
                return Err(LedgerError::Capacity);
            }
            tx.execute("INSERT INTO invocations(account,session,logon,invocation,lease,revision,phase,boot,context) VALUES(?1,?2,?3,?4,?5,?6,0,?7,?8)",
                params![caller.account,caller.session,caller.logon_sid.as_deref().unwrap_or(""),invocation.as_bytes().as_slice(),preflight.lease.as_bytes().as_slice(),preflight.revision.as_bytes().as_slice(),caller.boot_key().as_slice(),preflight.context.bytes()])?;
            Admission::New(QueueTicket {
                owner: caller.clone(),
                invocation,
                lease: preflight.lease,
                revision: preflight.revision,
                context: Some(preflight.context),
            })
        };
        tx.commit()?;
        Ok(result)
    }

    fn query(&self, caller: &Caller, invocation: Uuid) -> Result<Option<Phase>, LedgerError> {
        caller.validate()?;
        valid_id(invocation)?;
        Ok(lookup(&self.connection, caller, invocation)?.map(|(_, _, phase, _)| phase))
    }

    /// Fresh service-owned lease authorization is required again at claim.
    /// No native effect may begin before the returned claim exists.
    pub(crate) fn claim(
        &mut self,
        ticket: QueueTicket,
        preflight: LeasePreflight,
        instance: Uuid,
    ) -> Result<Claim, LedgerError> {
        valid_id(instance)?;
        if preflight.owner != ticket.owner
            || preflight.lease != ticket.lease
            || preflight.revision != ticket.revision
            || Some(preflight.context) != ticket.context
        {
            return Err(LedgerError::StaleLease);
        }
        let nonce = Uuid::new_v4();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed=tx.execute("UPDATE invocations SET phase=1,instance=?1,nonce=?2 WHERE account=?3 AND session=?4 AND invocation=?5 AND lease=?6 AND revision=?7 AND logon=?8 AND boot=?9 AND context=?10 AND phase=0",
            params![instance.as_bytes().as_slice(),nonce.as_bytes().as_slice(),ticket.owner.account,ticket.owner.session,ticket.invocation.as_bytes().as_slice(),ticket.lease.as_bytes().as_slice(),ticket.revision.as_bytes().as_slice(),ticket.owner.logon_sid.as_deref().unwrap_or(""),ticket.owner.boot_key().as_slice(),preflight.context.bytes()])?;
        if changed != 1 {
            return Err(LedgerError::StaleClaim);
        }
        tx.commit()?;
        Ok(Claim {
            ticket,
            instance,
            nonce,
        })
    }

    /// Requires the exact committed claim and a separately observed worker result.
    /// A commit failure means the receipt is not known durable; do not retry effects.
    pub(crate) fn finish(
        &mut self,
        claim: &Claim,
        outcome: WorkerOutcome,
    ) -> Result<Phase, LedgerError> {
        let phase = outcome.phase();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let ticket = &claim.ticket;
        let changed=tx.execute("UPDATE invocations SET phase=?1 WHERE account=?2 AND session=?3 AND invocation=?4 AND lease=?5 AND revision=?6 AND instance=?7 AND nonce=?8 AND logon=?9 AND boot=?10 AND context=?11 AND phase=1",
            params![phase.code(),ticket.owner.account,ticket.owner.session,ticket.invocation.as_bytes().as_slice(),ticket.lease.as_bytes().as_slice(),ticket.revision.as_bytes().as_slice(),claim.instance.as_bytes().as_slice(),claim.nonce.as_bytes().as_slice(),ticket.owner.logon_sid.as_deref().unwrap_or(""),ticket.owner.boot_key().as_slice(),ticket.context.as_ref().map(ContextBinding::bytes)])?;
        if changed != 1 {
            return Err(LedgerError::StaleClaim);
        }
        tx.commit()?;
        Ok(phase)
    }

    /// Requires a sealed native-death proof and the runtime's exclusive storage
    /// ownership. This SQL operation never makes work runnable.
    pub(crate) fn mark_stopped_owner_uncertain(
        &mut self,
        proof: &StoppedOwner,
    ) -> Result<usize, LedgerError> {
        let previous_instance = proof.instance();
        valid_id(previous_instance)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE invocations SET phase=5 WHERE phase=1 AND instance=?1",
            [previous_instance.as_bytes().as_slice()],
        )?;
        tx.commit()?;
        Ok(changed)
    }

    pub(crate) fn has_foreign_running_owner(&self, instance: Uuid) -> Result<bool, LedgerError> {
        valid_id(instance)?;
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM invocations WHERE phase=1 AND instance<>?1)",
            [instance.as_bytes().as_slice()],
            |r| r.get(0),
        )?)
    }

    pub(crate) fn requires_review(&self) -> Result<bool, LedgerError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM invocations WHERE phase IN(0,1,5))",
            [],
            |r| r.get(0),
        )?)
    }

    /// Returns bounded wake hints for explicit fresh lease review. Reading this
    /// list never claims, schedules or replays an effect.
    pub(crate) fn pending_for_review(&self, limit: usize) -> Result<PendingReview, LedgerError> {
        if limit == 0 || limit > MAX_REVIEW_BATCH {
            return Err(LedgerError::Capacity);
        }
        let mut statement=self.connection.prepare("SELECT account,session,invocation,lease,revision,logon,boot,context FROM invocations WHERE phase=0 ORDER BY account,session,logon,boot,invocation LIMIT ?1")?;
        let mut rows = statement.query([limit as i64 + 1])?;
        let mut tickets = Vec::new();
        while let Some(row) = rows.next()? {
            let owner = Caller {
                account: row.get(0)?,
                session: row.get(1)?,
                logon_sid: nonempty_logon(row.get(5)?),
                boot_id: stored_boot(row.get(6)?)?,
                native_origin: false,
            };
            owner.validate()?;
            tickets.push(QueueTicket {
                owner,
                invocation: row_id(row, 2)?,
                lease: row_id(row, 3)?,
                revision: row_id(row, 4)?,
                context: row
                    .get::<_, Option<Vec<u8>>>(7)?
                    .map(ContextBinding::stored)
                    .transpose()?,
            });
        }
        let has_more = tickets.len() > limit;
        tickets.truncate(limit);
        Ok(PendingReview { tickets, has_more })
    }
}

fn valid_id(id: Uuid) -> Result<(), LedgerError> {
    if id.is_nil() {
        Err(LedgerError::InvalidIdentity)
    } else {
        Ok(())
    }
}
fn row_id(row: &rusqlite::Row<'_>, index: usize) -> Result<Uuid, LedgerError> {
    let bytes: Vec<u8> = row.get(index)?;
    let id = Uuid::from_slice(&bytes).map_err(|_| LedgerError::CorruptDatabase)?;
    valid_id(id).map_err(|_| LedgerError::CorruptDatabase)?;
    Ok(id)
}
fn lookup(
    connection: &Connection,
    owner: &Caller,
    id: Uuid,
) -> Result<Option<(Uuid, Uuid, Phase, Option<ContextBinding>)>, LedgerError> {
    let raw:Option<(Vec<u8>,Vec<u8>,i64,Option<Vec<u8>>)>=connection.query_row("SELECT lease,revision,phase,context FROM invocations WHERE account=?1 AND session=?2 AND invocation=?3 AND logon=?4 AND boot=?5",
        params![owner.account,owner.session,id.as_bytes().as_slice(),owner.logon_sid.as_deref().unwrap_or(""),owner.boot_key().as_slice()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional()?;
    raw.map(|(lease, revision, phase, context)| {
        let lease = Uuid::from_slice(&lease).map_err(|_| LedgerError::CorruptDatabase)?;
        let revision = Uuid::from_slice(&revision).map_err(|_| LedgerError::CorruptDatabase)?;
        valid_id(lease).map_err(|_| LedgerError::CorruptDatabase)?;
        valid_id(revision).map_err(|_| LedgerError::CorruptDatabase)?;
        Ok((
            lease,
            revision,
            Phase::parse(phase)?,
            context.map(ContextBinding::stored).transpose()?,
        ))
    })
    .transpose()
}
fn nonempty_logon(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}
fn legacy_collision(
    connection: &Connection,
    caller: &Caller,
    invocation: Uuid,
) -> Result<bool, LedgerError> {
    if caller.logon_sid.is_none() {
        return Ok(false);
    }
    Ok(connection.query_row("SELECT EXISTS(SELECT 1 FROM invocations WHERE account=?1 AND session=?2 AND invocation=?3 AND boot=zeroblob(16) AND (logon='' OR (?4 AND logon=?5)))",
        params![caller.account,caller.session,invocation.as_bytes().as_slice(),caller.boot_id.is_some(),caller.logon_sid.as_deref().unwrap_or("")],|r|r.get(0))?)
}
/// Unknown data is not reset; a known v1 format can migrate without guessing a login.
fn validate_header(connection: &Connection) -> Result<Layout, LedgerError> {
    let application: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let objects: i64 =
        connection.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))?;
    let pages: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
    let page_size: i64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    if pages
        .checked_mul(page_size)
        .is_none_or(|bytes| bytes > MAX_DB_BYTES)
    {
        return Err(LedgerError::Capacity);
    }
    if application == 0 && version == 0 && objects == 0 {
        return Ok(Layout::Fresh);
    }
    if application != APPLICATION_ID || ![1, 2, 3, SCHEMA_VERSION].contains(&version) {
        return Err(LedgerError::UnsupportedDatabase);
    }
    let layout = if version == 1 {
        Layout::Legacy
    } else if version == 2 {
        Layout::Logon
    } else if version == 3 {
        Layout::Boot
    } else {
        Layout::Current
    };
    validate_schema(connection, layout)?;
    Ok(layout)
}
fn validate_schema(connection: &Connection, layout: Layout) -> Result<(), LedgerError> {
    let objects: i64 =
        connection.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))?;
    let schema: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='invocations' AND type='table'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if objects != 1
        || schema
            .as_deref()
            .map(|sql| sql.trim().trim_end_matches(';'))
            != Some(match layout {
                Layout::Legacy => LEGACY_SCHEMA.trim(),
                Layout::Logon => LOGON_SCHEMA.trim(),
                Layout::Boot => BOOT_SCHEMA.trim(),
                _ => SCHEMA.trim(),
            })
    {
        return Err(LedgerError::UnsupportedDatabase);
    }
    let count: i64 =
        connection.query_row("SELECT count(*) FROM invocations", [], |row| row.get(0))?;
    if count > MAX_RECORDS {
        return Err(LedgerError::Capacity);
    }
    let logon = if layout == Layout::Legacy {
        "''"
    } else {
        "logon"
    };
    let boot = if matches!(layout, Layout::Boot | Layout::Current) {
        "boot"
    } else {
        "zeroblob(16)"
    };
    let context = if layout == Layout::Current {
        "context"
    } else {
        "NULL"
    };
    let mut query = connection.prepare(&format!("SELECT account,session,{logon},invocation,lease,revision,phase,instance,nonce,{boot},{context} FROM invocations LIMIT 4097"))?;
    for row in query.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, Option<Vec<u8>>>(7)?,
            row.get::<_, Option<Vec<u8>>>(8)?,
            row.get::<_, Vec<u8>>(9)?,
            row.get::<_, Option<Vec<u8>>>(10)?,
        ))
    })? {
        let (
            account,
            session,
            logon,
            invocation,
            lease,
            revision,
            phase,
            instance,
            nonce,
            boot,
            context,
        ) = row?;
        Caller {
            account,
            session,
            logon_sid: nonempty_logon(logon),
            boot_id: stored_boot(boot)?,
            native_origin: false,
        }
        .validate()
        .map_err(|_| LedgerError::CorruptDatabase)?;
        for id in [
            Some(invocation),
            Some(lease),
            Some(revision),
            instance.clone(),
            nonce.clone(),
        ]
        .into_iter()
        .flatten()
        {
            let id = Uuid::from_slice(&id).map_err(|_| LedgerError::CorruptDatabase)?;
            valid_id(id).map_err(|_| LedgerError::CorruptDatabase)?;
        }
        context.map(ContextBinding::stored).transpose()?;
        Phase::parse(phase)?;
        if (phase == 0 && (instance.is_some() || nonce.is_some()))
            || (phase != 0 && (instance.is_none() || nonce.is_none()))
        {
            return Err(LedgerError::CorruptDatabase);
        }
    }
    Ok(())
}

fn validate_integrity(connection: &Connection) -> Result<(), LedgerError> {
    let integrity: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(LedgerError::CorruptDatabase);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    mod boot_scope;
    mod context_binding;
    mod logon_migration;
    #[test]
    fn live_logon_scope_must_match_both_admission_and_worker_preflight() {
        let directory = tempfile::tempdir().unwrap();
        let mut ledger = open(&directory.path().join("requests.db"));
        let mut first = caller();
        first.logon_sid = Some("S-1-5-5-1-2".into());
        let mut second = first.clone();
        second.logon_sid = Some("S-1-5-5-1-3".into());
        let invocation = Uuid::new_v4();
        let lease = Uuid::new_v4();
        let revision = Uuid::new_v4();
        assert!(matches!(
            ledger.admit(&first, invocation, preflight(&second, lease, revision)),
            Err(LedgerError::NotAuthorized)
        ));
        let ticket = match ledger
            .admit(&first, invocation, preflight(&first, lease, revision))
            .unwrap()
        {
            Admission::New(ticket) => ticket,
            _ => panic!("fresh invocation required"),
        };
        assert!(matches!(
            ledger.claim(ticket, preflight(&second, lease, revision), Uuid::new_v4()),
            Err(LedgerError::StaleLease)
        ));
        assert_eq!(
            ledger.query(&first, invocation).unwrap(),
            Some(Phase::Queued)
        );
    }

    #[test]
    fn persisted_queue_hint_cannot_reconstruct_a_live_logon_caller() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("requests.db");
        let mut ledger = open(&path);
        let mut owner = caller();
        owner.logon_sid = Some("S-1-5-5-1-2".into());
        let invocation = Uuid::new_v4();
        let lease = Uuid::new_v4();
        let revision = Uuid::new_v4();
        let _ = ledger
            .admit(&owner, invocation, preflight(&owner, lease, revision))
            .unwrap();
        drop(ledger);
        let mut ledger = open(&path);
        let mut hints = ledger.pending_for_review(1).unwrap();
        assert_eq!(hints.tickets.len(), 1);
        let hint = hints.tickets.remove(0);
        assert_eq!(hint.owner().logon_sid(), owner.logon_sid());
        assert!(!hint.owner.native_origin);
        assert!(matches!(
            LeasePreflight::from_owner_observation(
                hint.owner().clone(),
                lease,
                revision,
                crate::optimizer_requests::ContextBinding::fixture_default()
            ),
            Err(LedgerError::NotAuthorized)
        ));
        let mut changed = owner.clone();
        changed.logon_sid = Some("S-1-5-5-1-3".into());
        assert!(matches!(
            ledger.claim(hint, preflight(&changed, lease, revision), Uuid::new_v4()),
            Err(LedgerError::StaleLease)
        ));
        assert_eq!(
            ledger.query(&owner, invocation).unwrap(),
            Some(Phase::Queued)
        );
    }

    #[test]
    fn logon_sid_text_is_canonical_bounded_and_not_a_caller_supplied_account_alias() {
        for sid in [
            "S-1-5-18",
            "S-1-5-5-01-2",
            "S-1-5-5-1-4294967296",
            "S-1-5-5-1-2\0",
            "S-1-5-5-1",
            "S-1-5-5-1-2-3",
        ] {
            let mut owner = caller();
            owner.logon_sid = Some(sid.into());
            assert!(owner.validate().is_err());
        }
        let mut owner = caller();
        owner.logon_sid = Some("S-1-5-5-4294967295-4294967295".into());
        assert!(owner.validate().is_ok());
        owner.logon_sid = Some("S-1-5-5-".repeat(100));
        assert!(owner.validate().is_err());
    }
    use super::*;
    use std::{
        path::Path,
        sync::{Arc, Barrier},
        thread,
    };

    fn caller() -> Caller {
        Caller {
            account: "S-1-5-21-1-2-3-1001".into(),
            session: 1,
            logon_sid: None,
            boot_id: None,
            native_origin: true,
        }
    }
    fn open(path: &Path) -> Ledger {
        Ledger::open(Connection::open(path).unwrap()).unwrap()
    }
    fn preflight(owner: &Caller, lease: Uuid, revision: Uuid) -> LeasePreflight {
        LeasePreflight::from_owner_observation(
            owner.clone(),
            lease,
            revision,
            crate::optimizer_requests::ContextBinding::fixture_default(),
        )
        .unwrap()
    }
    fn admit(
        ledger: &mut Ledger,
        owner: &Caller,
        id: Uuid,
        lease: Uuid,
        revision: Uuid,
    ) -> QueueTicket {
        match ledger
            .admit(owner, id, preflight(owner, lease, revision))
            .unwrap()
        {
            Admission::New(ticket) => ticket,
            other => panic!("Expected first admission, got {other:?}"),
        }
    }

    #[test]
    fn lost_queue_hint_survives_reopen_without_readmission_or_automatic_claim() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("requests.db");
        let owner = caller();
        let id = Uuid::new_v4();
        let lease = Uuid::new_v4();
        let revision = Uuid::new_v4();
        let mut ledger = open(&path);
        drop(admit(&mut ledger, &owner, id, lease, revision)); // Commit succeeded, delivery lost.
        drop(ledger);
        let mut ledger = open(&path);
        assert_eq!(ledger.query(&owner, id).unwrap(), Some(Phase::Queued));
        assert!(matches!(
            ledger
                .admit(&owner, id, preflight(&owner, lease, revision))
                .unwrap(),
            Admission::Existing(Phase::Queued)
        ));
        let ticket = ledger.pending_for_review(1).unwrap().tickets.pop().unwrap();
        assert!(matches!(
            ledger.claim(
                ticket,
                preflight(&owner, lease, Uuid::new_v4()),
                Uuid::new_v4()
            ),
            Err(LedgerError::StaleLease)
        ));
        assert_eq!(ledger.query(&owner, id).unwrap(), Some(Phase::Queued));
        let ticket = ledger.pending_for_review(1).unwrap().tickets.pop().unwrap();
        let claim = ledger
            .claim(ticket, preflight(&owner, lease, revision), Uuid::new_v4())
            .unwrap();
        assert_eq!(claim.invocation(), id);
        drop(ledger);
        let ledger = open(&path);
        assert_eq!(ledger.query(&owner, id).unwrap(), Some(Phase::Running)); // Opening is not recovery.
        assert!(ledger.pending_for_review(1).unwrap().tickets.is_empty());
    }

    #[test]
    fn caller_scope_prevents_state_disclosure_and_conflicting_ids_do_not_requeue() {
        let directory = tempfile::tempdir().unwrap();
        let mut ledger = open(&directory.path().join("requests.db"));
        let owner = caller();
        let id = Uuid::new_v4();
        let lease = Uuid::new_v4();
        let revision = Uuid::new_v4();
        admit(&mut ledger, &owner, id, lease, revision);
        for other in [
            Caller {
                session: 2,
                ..owner.clone()
            },
            Caller {
                account: "S-1-5-21-1-2-3-1002".into(),
                ..owner.clone()
            },
        ] {
            assert_eq!(ledger.query(&other, id).unwrap(), None);
            assert!(matches!(
                ledger.admit(&other, id, preflight(&owner, lease, revision)),
                Err(LedgerError::NotAuthorized)
            ));
            assert!(matches!(
                ledger
                    .admit(&other, id, preflight(&other, lease, revision))
                    .unwrap(),
                Admission::New(_)
            ));
        }
        for (next_lease, next_revision) in [(Uuid::new_v4(), revision)] {
            assert!(matches!(
                ledger
                    .admit(&owner, id, preflight(&owner, next_lease, next_revision))
                    .unwrap(),
                Admission::Conflict
            ));
        }
        assert!(matches!(
            ledger
                .admit(&owner, id, preflight(&owner, lease, Uuid::new_v4()))
                .unwrap(),
            Admission::Existing(Phase::Queued)
        ));
        assert_eq!(ledger.query(&owner, id).unwrap(), Some(Phase::Queued));
        assert!(matches!(
            ledger.admit(&owner, Uuid::nil(), preflight(&owner, lease, revision)),
            Err(LedgerError::InvalidIdentity)
        ));
    }

    #[test]
    fn concurrent_duplicate_admission_yields_exactly_one_new_ticket() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("requests.db");
        let first = open(&path);
        let second = open(&path);
        let barrier = Arc::new(Barrier::new(2));
        let owner = caller();
        let id = Uuid::new_v4();
        let lease = Uuid::new_v4();
        let revision = Uuid::new_v4();
        let handles: Vec<_> = [first, second]
            .into_iter()
            .map(|mut ledger| {
                let barrier = barrier.clone();
                let owner = owner.clone();
                thread::spawn(move || {
                    barrier.wait();
                    ledger.admit(&owner, id, preflight(&owner, lease, revision))
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().unwrap().unwrap())
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Admission::New(_)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Admission::Existing(Phase::Queued)))
                .count(),
            1
        );
        assert_eq!(open(&path).pending_for_review(2).unwrap().tickets.len(), 1);
    }

    #[test]
    fn competing_claims_commit_only_one_running_owner() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("requests.db");
        let owner = caller();
        let id = Uuid::new_v4();
        let lease = Uuid::new_v4();
        let revision = Uuid::new_v4();
        let mut first = open(&path);
        admit(&mut first, &owner, id, lease, revision);
        let second = open(&path);
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [first, second]
            .into_iter()
            .map(|mut ledger| {
                let barrier = barrier.clone();
                let owner = owner.clone();
                let ticket = ledger.pending_for_review(1).unwrap().tickets.pop().unwrap();
                thread::spawn(move || {
                    barrier.wait();
                    ledger.claim(ticket, preflight(&owner, lease, revision), Uuid::new_v4())
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(LedgerError::StaleClaim)))
                .count(),
            1
        );
        assert_eq!(open(&path).query(&owner, id).unwrap(), Some(Phase::Running));
    }

    #[test]
    fn failed_admission_statement_never_yields_a_ticket_or_partial_row() {
        let directory = tempfile::tempdir().unwrap();
        let mut ledger = open(&directory.path().join("requests.db"));
        let owner = caller();
        let id = Uuid::new_v4();
        let lease = Uuid::new_v4();
        let revision = Uuid::new_v4();
        ledger.connection.execute_batch("CREATE TEMP TRIGGER fail_admit BEFORE INSERT ON main.invocations BEGIN SELECT RAISE(ABORT,'fixture failure'); END").unwrap();
        assert!(matches!(
            ledger.admit(&owner, id, preflight(&owner, lease, revision)),
            Err(LedgerError::Sql(_))
        ));
        assert_eq!(ledger.query(&owner, id).unwrap(), None);
        ledger
            .connection
            .execute_batch("DROP TRIGGER fail_admit")
            .unwrap();
        admit(&mut ledger, &owner, id, lease, revision);
    }

    fn install_commit_fault(ledger: &Ledger, phase: i64) {
        ledger.connection.execute_batch(&format!("PRAGMA foreign_keys=ON;
            CREATE TABLE fault_guard(id INTEGER PRIMARY KEY,required INTEGER REFERENCES fault_guard(id) DEFERRABLE INITIALLY DEFERRED);
            CREATE TEMP TRIGGER fail_commit AFTER UPDATE OF phase ON main.invocations WHEN NEW.phase={phase}
            BEGIN INSERT INTO fault_guard VALUES(1,999); END;")).unwrap();
    }
    fn clear_commit_fault(ledger: &Ledger) {
        ledger
            .connection
            .execute_batch("DROP TRIGGER fail_commit;DROP TABLE fault_guard;")
            .unwrap();
    }

    #[test]
    fn claim_and_finish_commit_failures_never_escape_as_durable_success() {
        let directory = tempfile::tempdir().unwrap();
        let mut ledger = open(&directory.path().join("requests.db"));
        let owner = caller();
        let id = Uuid::new_v4();
        let lease = Uuid::new_v4();
        let revision = Uuid::new_v4();
        let ticket = admit(&mut ledger, &owner, id, lease, revision);
        install_commit_fault(&ledger, 1);
        assert!(matches!(
            ledger.claim(ticket, preflight(&owner, lease, revision), Uuid::new_v4()),
            Err(LedgerError::Sql(_))
        ));
        assert_eq!(ledger.query(&owner, id).unwrap(), Some(Phase::Queued));
        clear_commit_fault(&ledger);
        let instance = Uuid::new_v4();
        let ticket = ledger.pending_for_review(1).unwrap().tickets.pop().unwrap();
        let claim = ledger
            .claim(ticket, preflight(&owner, lease, revision), instance)
            .unwrap();
        install_commit_fault(&ledger, 2);
        assert!(matches!(
            ledger.finish(&claim, WorkerOutcome::VerifiedReenabled),
            Err(LedgerError::Sql(_))
        ));
        assert_eq!(ledger.query(&owner, id).unwrap(), Some(Phase::Running));
        clear_commit_fault(&ledger);
        assert_eq!(
            ledger
                .mark_stopped_owner_uncertain(&StoppedOwner::fixture(instance))
                .unwrap(),
            1
        );
        assert_eq!(ledger.query(&owner, id).unwrap(), Some(Phase::Uncertain));
    }

    #[test]
    fn recovery_invalidates_old_claims_and_leaves_queued_work_unscheduled() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("requests.db");
        let mut ledger = open(&path);
        let owner = caller();
        let id = Uuid::new_v4();
        let queued = Uuid::new_v4();
        let lease = Uuid::new_v4();
        let revision = Uuid::new_v4();
        let instance = Uuid::new_v4();
        let ticket = admit(&mut ledger, &owner, id, lease, revision);
        let claim = ledger
            .claim(ticket, preflight(&owner, lease, revision), instance)
            .unwrap();
        admit(&mut ledger, &owner, queued, lease, revision);
        assert_eq!(
            ledger
                .mark_stopped_owner_uncertain(&StoppedOwner::fixture(Uuid::new_v4()))
                .unwrap(),
            0
        );
        assert_eq!(
            ledger
                .mark_stopped_owner_uncertain(&StoppedOwner::fixture(instance))
                .unwrap(),
            1
        );
        assert_eq!(
            ledger
                .mark_stopped_owner_uncertain(&StoppedOwner::fixture(instance))
                .unwrap(),
            0
        );
        assert!(matches!(
            ledger.finish(&claim, WorkerOutcome::VerifiedReenabled),
            Err(LedgerError::StaleClaim)
        ));
        assert!(matches!(
            Phase::Uncertain.response(id),
            ServiceResponse::Refused {
                reason: Refusal::RecoveryRequired
            }
        ));
        assert!(matches!(
            ledger
                .admit(&owner, id, preflight(&owner, lease, revision))
                .unwrap(),
            Admission::Existing(Phase::Uncertain)
        ));
        drop(ledger);
        let ledger = open(&path);
        assert_eq!(ledger.query(&owner, id).unwrap(), Some(Phase::Uncertain));
        let pending = ledger.pending_for_review(2).unwrap();
        assert_eq!(pending.tickets.len(), 1);
        assert_eq!(pending.tickets[0].invocation(), queued);
        assert_eq!(ledger.query(&owner, queued).unwrap(), Some(Phase::Queued));
    }

    #[test]
    fn terminal_receipts_survive_reopen_and_cannot_be_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("requests.db");
        let owner = caller();
        let lease = Uuid::new_v4();
        let revision = Uuid::new_v4();
        let mut records = Vec::new();
        let mut ledger = open(&path);
        for (outcome, expected) in [
            (WorkerOutcome::VerifiedReenabled, Phase::VerifiedReenabled),
            (WorkerOutcome::Partial, Phase::Partial),
            (WorkerOutcome::Rejected, Phase::Rejected),
            (WorkerOutcome::Uncertain, Phase::Uncertain),
        ] {
            let id = Uuid::new_v4();
            let ticket = admit(&mut ledger, &owner, id, lease, revision);
            let claim = ledger
                .claim(ticket, preflight(&owner, lease, revision), Uuid::new_v4())
                .unwrap();
            assert_eq!(ledger.finish(&claim, outcome).unwrap(), expected);
            assert!(matches!(
                ledger.finish(&claim, WorkerOutcome::VerifiedReenabled),
                Err(LedgerError::StaleClaim)
            ));
            assert!(
                matches!(ledger.admit(&owner,id,preflight(&owner,lease,revision)).unwrap(),Admission::Existing(p) if p==expected)
            );
            records.push((id, expected));
        }
        drop(ledger);
        let ledger = open(&path);
        for (id, phase) in records {
            assert_eq!(ledger.query(&owner, id).unwrap(), Some(phase));
        }
    }

    #[test]
    fn unknown_future_and_corrupt_closed_databases_are_not_replaced() {
        let directory = tempfile::tempdir().unwrap();
        for (index,setup) in ["CREATE TABLE unrelated(value TEXT)","PRAGMA application_id=1145261904;PRAGMA user_version=99","PRAGMA application_id=1145261904;PRAGMA user_version=1;CREATE TABLE invocations(wrong TEXT)"].into_iter().enumerate() {
            let path=directory.path().join(format!("unsupported-{index}.db"));
            let connection=Connection::open(&path).unwrap();connection.execute_batch(setup).unwrap();drop(connection);
            let before=std::fs::read(&path).unwrap();
            assert!(Ledger::open(Connection::open(&path).unwrap()).is_err());
            assert_eq!(std::fs::read(&path).unwrap(),before);
        }
        let path = directory.path().join("corrupt.db");
        let bytes = b"not a sqlite database; preserve this fixture";
        std::fs::write(&path, bytes).unwrap();
        assert!(Ledger::open(Connection::open(&path).unwrap()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(matches!(
            Ledger::open(Connection::open_in_memory().unwrap()),
            Err(LedgerError::UnsupportedDatabase)
        ));
        // A LIKE 'sqlite_%' filter would accidentally ignore this nonreserved
        // name because '_' is a wildcard. Every schema object is accounted for.
        let path = directory.path().join("extra-object.db");
        drop(open(&path));
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE sqliteXunexpected(value TEXT)")
            .unwrap();
        drop(connection);
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(
            Ledger::open(Connection::open(&path).unwrap()),
            Err(LedgerError::UnsupportedDatabase)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let path = directory.path().join("temp-object.db");
        drop(open(&path));
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TEMP TABLE unexpected(value TEXT)")
            .unwrap();
        assert!(matches!(
            Ledger::open(connection),
            Err(LedgerError::UnsupportedDatabase)
        ));
        for corrupt in [false, true] {
            let path = directory.path().join(format!("wal-{corrupt}.db"));
            drop(open(&path));
            let connection = Connection::open(&path).unwrap();
            connection.execute_batch("PRAGMA journal_mode=WAL").unwrap();
            if corrupt {
                connection.execute_batch("PRAGMA ignore_check_constraints=ON;
                    INSERT INTO invocations(account,session,invocation,lease,revision,phase)
                    VALUES('S-1-5-18',0,x'01010101010101010101010101010101',x'02020202020202020202020202020202',x'03030303030303030303030303030303',5)").unwrap();
            }
            drop(connection);
            let before = std::fs::read(&path).unwrap();
            let result = Ledger::open(Connection::open(&path).unwrap());
            assert!(if corrupt {
                matches!(result, Err(LedgerError::CorruptDatabase))
            } else {
                matches!(result, Err(LedgerError::UnsupportedDurability))
            });
            assert_eq!(std::fs::read(&path).unwrap(), before);
            let connection = Connection::open(&path).unwrap();
            let mode: String = connection
                .query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .unwrap();
            assert_eq!(mode, "wal");
        }
    }

    #[test]
    fn capacity_preserves_dedupe_and_review_batches_are_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let mut ledger = open(&directory.path().join("requests.db"));
        let owner = caller();
        let lease = Uuid::new_v4();
        let revision = Uuid::new_v4();
        let first = Uuid::new_v4();
        admit(&mut ledger, &owner, first, lease, revision);
        let tx = ledger.connection.transaction().unwrap();
        for _ in 1..MAX_RECORDS {
            tx.execute("INSERT INTO invocations(account,session,invocation,lease,revision,phase) VALUES(?1,?2,?3,?4,?5,0)",params![owner.account,owner.session,Uuid::new_v4().as_bytes().as_slice(),lease.as_bytes().as_slice(),revision.as_bytes().as_slice()]).unwrap();
        }
        tx.commit().unwrap();
        assert!(matches!(
            ledger.admit(&owner, Uuid::new_v4(), preflight(&owner, lease, revision)),
            Err(LedgerError::Capacity)
        ));
        assert!(matches!(
            ledger
                .admit(&owner, first, preflight(&owner, lease, revision))
                .unwrap(),
            Admission::Existing(Phase::Queued)
        ));
        let pending = ledger.pending_for_review(2).unwrap();
        assert_eq!(pending.tickets.len(), 2);
        assert!(pending.has_more);
        assert!(ledger.pending_for_review(0).is_err());
        assert!(ledger.pending_for_review(MAX_REVIEW_BATCH + 1).is_err());
        let count: i64 = ledger
            .connection
            .query_row("SELECT count(*) FROM invocations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, MAX_RECORDS);
    }

    #[test]
    fn busy_and_readonly_admission_failures_never_leave_authorized_work() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("requests.db");
        let mut ledger = open(&path);
        let owner = caller();
        let id = Uuid::new_v4();
        let lease = Uuid::new_v4();
        let revision = Uuid::new_v4();
        let mut other = Connection::open(&path).unwrap();
        let lock = other
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(matches!(
            ledger.admit(&owner, id, preflight(&owner, lease, revision)),
            Err(LedgerError::Sql(_))
        ));
        drop(lock);
        assert_eq!(ledger.query(&owner, id).unwrap(), None);
        ledger
            .connection
            .pragma_update(None, "query_only", true)
            .unwrap();
        assert!(matches!(
            ledger.admit(&owner, id, preflight(&owner, lease, revision)),
            Err(LedgerError::Sql(_))
        ));
        assert_eq!(ledger.query(&owner, id).unwrap(), None);
        ledger
            .connection
            .pragma_update(None, "query_only", false)
            .unwrap();
        admit(&mut ledger, &owner, id, lease, revision);
    }
}
