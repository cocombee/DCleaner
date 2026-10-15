//! Explicit, single-item cloud trash and restore operations.
//!
//! Every mutation is preceded by a fresh account-scope and item check. This
//! module has no permanent-delete route and never retries a request. A network
//! failure after a mutation is sent is reported as an unknown outcome so the
//! caller can reconcile it instead of repeating the effect.

use crate::{
    cloud_http::AccessToken,
    cloud_inventory::{
        AccountScope, Provider, ProviderTimestamp, ProviderTimestampBasis, RemoteItem,
        RemoteItemKind, SizeAccuracy, TrashStatus,
    },
};
use reqwest::{Method, Url, blocking::Client, header};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    io::Read,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const MAX_RECORD_BYTES: usize = 32 * 1024;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_ID_BYTES: usize = 512;
const MAX_REVISION_BYTES: usize = 512;
const MAX_PATH_BYTES: usize = 4 * 1024;
const MAX_NAME_BYTES: usize = 4 * 1024;
const ACTION_TIMEOUT: Duration = Duration::from_secs(90);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DRIVE_SCOPE: &str = "drive:user:api-visible:untrashed";
const GMAIL_SCOPE: &str = "gmail:user:api-visible:excluding-spam-trash";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredProvider {
    GoogleDrive,
    Gmail,
    OneDrive,
    Dropbox,
}

impl From<Provider> for StoredProvider {
    fn from(value: Provider) -> Self {
        match value {
            Provider::GoogleDrive => Self::GoogleDrive,
            Provider::Gmail => Self::Gmail,
            Provider::OneDrive => Self::OneDrive,
            Provider::Dropbox => Self::Dropbox,
        }
    }
}

impl From<StoredProvider> for Provider {
    fn from(value: StoredProvider) -> Self {
        match value {
            StoredProvider::GoogleDrive => Self::GoogleDrive,
            StoredProvider::Gmail => Self::Gmail,
            StoredProvider::OneDrive => Self::OneDrive,
            StoredProvider::Dropbox => Self::Dropbox,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredKind {
    File,
    Mail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredSizeAccuracy {
    Exact,
    Estimate,
    GmailEstimate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSize {
    bytes: u64,
    accuracy: StoredSizeAccuracy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredTimestampBasis {
    Modified,
    Received,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredTimestamp {
    unix_millis: i64,
    basis: StoredTimestampBasis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredTrashStatus {
    NotTrashed,
    Unknown,
}

/// A bounded, private-cloneable reference to one inventory item. The scope,
/// opaque provider ID and revision are persisted so the controller can journal
/// exactly what the user selected; Debug intentionally suppresses them.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionTarget {
    schema: u8,
    provider: StoredProvider,
    subject_id: String,
    storage_id: Option<String>,
    scan_id: uuid::Uuid,
    row_id: uuid::Uuid,
    provider_item_id: String,
    display_name: String,
    kind: StoredKind,
    revision: String,
    size: Option<StoredSize>,
    timestamp: Option<StoredTimestamp>,
    trash_status: StoredTrashStatus,
}

impl ActionTarget {
    /// Build an action target from one row and its inventory scope. Folder
    /// mutations are rejected until the caller can present a reviewed
    /// descendant set; a folder trash can affect every child.
    pub fn from_item(scope: &AccountScope, item: &RemoteItem) -> Result<Self, ActionError> {
        if item.kind() == RemoteItemKind::Folder {
            return Err(ActionError::FolderUnsupported);
        }
        if item.trash_status() == TrashStatus::Trashed {
            return Err(ActionError::AlreadyTrashed);
        }
        let kind = match (scope.provider(), item.kind()) {
            (Provider::Gmail, RemoteItemKind::Mail) => StoredKind::Mail,
            (
                Provider::GoogleDrive | Provider::OneDrive | Provider::Dropbox,
                RemoteItemKind::File,
            ) => StoredKind::File,
            _ => return Err(ActionError::InvalidTarget),
        };
        let revision = item
            .provider_revision()
            .ok_or(ActionError::MissingRevision)?
            .to_owned();
        let target = Self {
            schema: 1,
            provider: scope.provider().into(),
            subject_id: scope.subject_id().to_owned(),
            storage_id: scope.storage_id().map(str::to_owned),
            scan_id: item.id().scan_id(),
            row_id: item.id().uuid(),
            provider_item_id: item.provider_item_id().to_owned(),
            display_name: item.display_name().to_owned(),
            kind,
            revision,
            size: item.size().map(|size| StoredSize {
                bytes: size.bytes(),
                accuracy: match size.accuracy() {
                    SizeAccuracy::ProviderReportedExact => StoredSizeAccuracy::Exact,
                    SizeAccuracy::ProviderReportedEstimate => StoredSizeAccuracy::Estimate,
                    SizeAccuracy::GmailMessageEstimate => StoredSizeAccuracy::GmailEstimate,
                },
            }),
            timestamp: item.provider_timestamp().map(|timestamp| StoredTimestamp {
                unix_millis: timestamp.unix_millis(),
                basis: match timestamp.basis() {
                    ProviderTimestampBasis::Modified => StoredTimestampBasis::Modified,
                    ProviderTimestampBasis::Received => StoredTimestampBasis::Received,
                },
            }),
            trash_status: match item.trash_status() {
                TrashStatus::NotTrashed => StoredTrashStatus::NotTrashed,
                TrashStatus::Unknown(_) => StoredTrashStatus::Unknown,
                TrashStatus::Trashed => return Err(ActionError::AlreadyTrashed),
            },
        };
        target.validate()?;
        Ok(target)
    }

    pub fn provider(&self) -> Provider {
        self.provider.into()
    }

    pub fn restore_source_scan(&self) -> uuid::Uuid {
        self.scan_id
    }

    pub fn restore_source_row(&self) -> uuid::Uuid {
        self.row_id
    }

    pub fn provider_item_id(&self) -> &str {
        &self.provider_item_id
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn size_bytes(&self) -> Option<u64> {
        self.size.map(|value| value.bytes)
    }

    pub fn size_accuracy(&self) -> Option<SizeAccuracy> {
        self.size.map(|value| match value.accuracy {
            StoredSizeAccuracy::Exact => SizeAccuracy::ProviderReportedExact,
            StoredSizeAccuracy::Estimate => SizeAccuracy::ProviderReportedEstimate,
            StoredSizeAccuracy::GmailEstimate => SizeAccuracy::GmailMessageEstimate,
        })
    }

    pub fn provider_timestamp(&self) -> Option<ProviderTimestamp> {
        self.timestamp.and_then(|timestamp| {
            let basis = match timestamp.basis {
                StoredTimestampBasis::Modified => ProviderTimestampBasis::Modified,
                StoredTimestampBasis::Received => ProviderTimestampBasis::Received,
            };
            ProviderTimestamp::new(timestamp.unix_millis, basis).ok()
        })
    }

    pub fn scope(&self) -> Result<AccountScope, ActionError> {
        self.scope_inner()
    }

    pub fn to_json(&self) -> Result<Vec<u8>, ActionError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ActionError::InvalidRecord)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ActionError::RecordTooLarge);
        }
        Ok(bytes)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, ActionError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ActionError::RecordTooLarge);
        }
        let target: Self = serde_json::from_slice(bytes).map_err(|_| ActionError::InvalidRecord)?;
        target.validate()?;
        Ok(target)
    }

    fn scope_inner(&self) -> Result<AccountScope, ActionError> {
        AccountScope::new(
            self.provider.into(),
            self.subject_id.clone(),
            self.storage_id.clone(),
        )
        .map_err(|_| ActionError::InvalidRecord)
    }

    fn validate(&self) -> Result<(), ActionError> {
        if self.schema != 1
            || self.scan_id.is_nil()
            || self.row_id.is_nil()
            || !valid_text(&self.subject_id, MAX_ID_BYTES)
            || !valid_text(&self.provider_item_id, MAX_ID_BYTES)
            || self.display_name.trim().is_empty()
            || !valid_text(&self.display_name, MAX_NAME_BYTES)
            || !valid_text(&self.revision, MAX_REVISION_BYTES)
        {
            return Err(ActionError::InvalidTarget);
        }
        let scope = self.scope_inner()?;
        match self.provider() {
            Provider::GoogleDrive if self.storage_id.as_deref() != Some(DRIVE_SCOPE) => {
                return Err(ActionError::InvalidTarget);
            }
            Provider::Gmail if self.storage_id.as_deref() != Some(GMAIL_SCOPE) => {
                return Err(ActionError::InvalidTarget);
            }
            Provider::OneDrive | Provider::Dropbox if self.storage_id.is_none() => {
                return Err(ActionError::InvalidTarget);
            }
            _ => {}
        }
        let _ = scope;
        if (self.provider() == Provider::Gmail) != (self.kind == StoredKind::Mail) {
            return Err(ActionError::InvalidTarget);
        }
        if self.provider() == Provider::Gmail
            && self
                .size
                .is_some_and(|size| size.accuracy != StoredSizeAccuracy::GmailEstimate)
            || self.provider() != Provider::Gmail
                && self
                    .size
                    .is_some_and(|size| size.accuracy == StoredSizeAccuracy::GmailEstimate)
        {
            return Err(ActionError::InvalidTarget);
        }
        if let Some(timestamp) = self.timestamp {
            let basis = match timestamp.basis {
                StoredTimestampBasis::Modified => ProviderTimestampBasis::Modified,
                StoredTimestampBasis::Received => ProviderTimestampBasis::Received,
            };
            if (self.provider() == Provider::Gmail && basis != ProviderTimestampBasis::Received)
                || (self.provider() != Provider::Gmail && basis != ProviderTimestampBasis::Modified)
                || ProviderTimestamp::new(timestamp.unix_millis, basis).is_err()
            {
                return Err(ActionError::InvalidTarget);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ActionTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActionTarget")
            .field("provider", &self.provider())
            .field("scope", &"[redacted]")
            .field("provider_item_id", &"[redacted]")
            .field("revision", &"[redacted]")
            .field("scan_id", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreCapability {
    Available,
    UnsupportedForDriveType,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionOutcome {
    Trashed,
    Restored,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "provider")]
enum ReceiptDetails {
    GoogleDrive {
        trashed_version: String,
    },
    Gmail {
        thread_id: String,
        trashed_history_id: String,
    },
    OneDrive {
        drive_type: DriveType,
        name: String,
        parent_id: Option<String>,
        trashed_etag: String,
    },
    Dropbox {
        path_lower: String,
        revision: String,
        restorable: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DriveType {
    Personal,
    Business,
    DocumentLibrary,
}

/// A confirmed trash result with just enough provider metadata for a later
/// explicit restore. It contains no credentials and has bounded versioned JSON.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionReceipt {
    schema: u8,
    target: ActionTarget,
    details: ReceiptDetails,
}

impl ActionReceipt {
    pub fn target(&self) -> &ActionTarget {
        &self.target
    }

    pub fn provider(&self) -> Provider {
        self.target.provider()
    }

    pub fn restore_capability(&self) -> RestoreCapability {
        match &self.details {
            ReceiptDetails::OneDrive {
                drive_type: DriveType::Business | DriveType::DocumentLibrary,
                ..
            } => RestoreCapability::UnsupportedForDriveType,
            ReceiptDetails::Dropbox {
                restorable: false, ..
            } => RestoreCapability::Unavailable,
            _ => RestoreCapability::Available,
        }
    }

    pub fn can_restore(&self) -> bool {
        self.restore_capability() == RestoreCapability::Available
    }

    pub fn to_json(&self) -> Result<Vec<u8>, ActionError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ActionError::InvalidRecord)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ActionError::RecordTooLarge);
        }
        Ok(bytes)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, ActionError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(ActionError::RecordTooLarge);
        }
        let receipt: Self =
            serde_json::from_slice(bytes).map_err(|_| ActionError::InvalidRecord)?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), ActionError> {
        if self.schema != 1 {
            return Err(ActionError::InvalidRecord);
        }
        self.target.validate()?;
        match (&self.details, self.provider()) {
            (ReceiptDetails::GoogleDrive { trashed_version }, Provider::GoogleDrive)
                if valid_decimal(trashed_version) =>
            {
                Ok(())
            }
            (
                ReceiptDetails::Gmail {
                    thread_id,
                    trashed_history_id,
                },
                Provider::Gmail,
            ) if valid_text(thread_id, MAX_ID_BYTES) && valid_decimal(trashed_history_id) => Ok(()),
            (
                ReceiptDetails::OneDrive {
                    drive_type: _,
                    name,
                    parent_id,
                    trashed_etag,
                },
                Provider::OneDrive,
            ) if valid_text(name, MAX_NAME_BYTES)
                && parent_id
                    .as_ref()
                    .is_none_or(|id| valid_text(id, MAX_ID_BYTES))
                && valid_header(trashed_etag) =>
            {
                Ok(())
            }
            (
                ReceiptDetails::Dropbox {
                    path_lower,
                    revision,
                    restorable: _,
                },
                Provider::Dropbox,
            ) if valid_dropbox_path(path_lower) && valid_text(revision, MAX_REVISION_BYTES) => {
                Ok(())
            }
            _ => Err(ActionError::InvalidRecord),
        }
    }
}

impl fmt::Debug for ActionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActionReceipt")
            .field("provider", &self.provider())
            .field("target", &"[redacted]")
            .field("restore_capability", &self.restore_capability())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionError {
    InvalidTarget,
    InvalidRecord,
    RecordTooLarge,
    FolderUnsupported,
    MissingRevision,
    ScopeMismatch,
    ChangedSinceScan,
    AlreadyTrashed,
    NotTrashed,
    Unsupported,
    Cancelled,
    TimedOut,
    ClientUnavailable,
    Transport,
    HttpRejected(u16),
    ResponseLimit,
    InvalidResponse,
    OutcomeUnknown,
}

impl fmt::Display for ActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidTarget => "The selected cloud item is not a valid action target.",
            Self::InvalidRecord => "The saved cloud action record is invalid.",
            Self::RecordTooLarge => "The saved cloud action record exceeded its safe size limit.",
            Self::FolderUnsupported => "Folder actions are unavailable until every affected child can be reviewed.",
            Self::MissingRevision => "The provider did not supply a revision needed for safe revalidation.",
            Self::ScopeMismatch => "The connected cloud account or storage scope changed.",
            Self::ChangedSinceScan => "The selected item changed since the inventory was scanned.",
            Self::AlreadyTrashed => "The selected item is already in the provider's Trash.",
            Self::NotTrashed => "The selected item is not in the provider's Trash.",
            Self::Unsupported => "This provider or storage type does not support this action.",
            Self::Cancelled => "The cloud action was cancelled before dispatch.",
            Self::TimedOut => "The cloud preflight exceeded its time limit.",
            Self::ClientUnavailable => "The secure cloud action client could not be initialized.",
            Self::Transport => "The cloud preflight failed; no mutation was sent.",
            Self::HttpRejected(_) => "The provider rejected the cloud action.",
            Self::ResponseLimit => "The cloud response exceeded its safe size limit.",
            Self::InvalidResponse => "The provider returned invalid action metadata.",
            Self::OutcomeUnknown => "The provider may have applied this action; check its current state before trying again.",
        })?;
        if let Self::HttpRejected(status) = self {
            write!(f, " (HTTP {status})")
        } else {
            Ok(())
        }
    }
}

impl std::error::Error for ActionError {}

impl ActionError {
    /// True when a provider may have applied a dispatched mutation.
    pub const fn outcome_unknown(self) -> bool {
        matches!(self, Self::OutcomeUnknown)
    }
}

/// A single-item action adapter. Construction is local; each operation checks
/// the live provider account and storage scope before reading or mutating.
pub struct NativeActions(ActionCore<NativeTransport>);

impl NativeActions {
    pub fn new(token: AccessToken, scope: AccountScope) -> Result<Self, ActionError> {
        validate_scope(&scope)?;
        let transport = NativeTransport::new(token)?;
        Ok(Self(ActionCore { scope, transport }))
    }

    pub fn trash(
        &mut self,
        target: &ActionTarget,
        cancel: &AtomicBool,
    ) -> Result<ActionReceipt, ActionError> {
        self.0.trash(target, cancel)
    }

    pub fn restore(
        &mut self,
        receipt: &ActionReceipt,
        cancel: &AtomicBool,
    ) -> Result<ActionOutcome, ActionError> {
        self.0.restore(receipt, cancel)
    }
}

struct RequestSpec {
    method: Method,
    url: Url,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

struct HttpReply {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

trait ActionTransport {
    fn send(
        &mut self,
        request: RequestSpec,
        cancel: &AtomicBool,
        deadline: Instant,
        mutation: bool,
    ) -> Result<HttpReply, ActionError>;
}

struct NativeTransport {
    client: Client,
    token: AccessToken,
}

impl NativeTransport {
    fn new(token: AccessToken) -> Result<Self, ActionError> {
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .referer(false)
            .connect_timeout(Duration::from_secs(10))
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| ActionError::ClientUnavailable)?;
        Ok(Self { client, token })
    }
}

impl ActionTransport for NativeTransport {
    fn send(
        &mut self,
        request: RequestSpec,
        cancel: &AtomicBool,
        deadline: Instant,
        mutation: bool,
    ) -> Result<HttpReply, ActionError> {
        check_before_dispatch(cancel, deadline)?;
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(REQUEST_TIMEOUT);
        let mut builder = self
            .client
            .request(request.method, request.url)
            .timeout(timeout)
            .header(header::ACCEPT, "application/json");
        builder = self.token.authorize(builder);
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        let response = match builder.send() {
            Ok(response) => response,
            Err(error) => {
                return if mutation {
                    Err(ActionError::OutcomeUnknown)
                } else if error.is_timeout() {
                    Err(ActionError::TimedOut)
                } else {
                    Err(ActionError::Transport)
                };
            }
        };
        if !mutation {
            if cancel.load(Ordering::Relaxed) {
                return Err(ActionError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(ActionError::TimedOut);
            }
        }
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_ascii_lowercase(), value.to_owned()))
            })
            .collect();
        // Error payloads are never needed: status alone distinguishes a
        // known rejection from an ambiguous server failure, and avoids
        // retaining arbitrary provider diagnostics.
        if !(200..300).contains(&status) {
            return Ok(HttpReply {
                status,
                headers,
                body: Vec::new(),
            });
        }
        if response.headers().contains_key(header::CONTENT_ENCODING)
            || response
                .content_length()
                .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return if mutation {
                Err(ActionError::OutcomeUnknown)
            } else {
                Err(ActionError::ResponseLimit)
            };
        }
        let mut response = response;
        let mut body = Vec::new();
        if response
            .by_ref()
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut body)
            .is_err()
        {
            return if mutation {
                Err(ActionError::OutcomeUnknown)
            } else {
                Err(ActionError::Transport)
            };
        }
        if body.len() > MAX_RESPONSE_BYTES {
            return if mutation {
                Err(ActionError::OutcomeUnknown)
            } else {
                Err(ActionError::ResponseLimit)
            };
        }
        Ok(HttpReply {
            status,
            headers,
            body,
        })
    }
}

struct ActionCore<T> {
    scope: AccountScope,
    transport: T,
}

impl<T: ActionTransport> ActionCore<T> {
    fn send(
        &mut self,
        method: Method,
        url: Url,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        cancel: &AtomicBool,
        deadline: Instant,
        mutation: bool,
    ) -> Result<HttpReply, ActionError> {
        self.transport.send(
            RequestSpec {
                method,
                url,
                headers,
                body,
            },
            cancel,
            deadline,
            mutation,
        )
    }

    fn get_json<TWire: for<'de> Deserialize<'de>>(
        &mut self,
        url: Url,
        headers: Vec<(String, String)>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<(TWire, BTreeMap<String, String>), ActionError> {
        let reply = self.send(Method::GET, url, headers, None, cancel, deadline, false)?;
        if !(200..300).contains(&reply.status) {
            return Err(ActionError::HttpRejected(reply.status));
        }
        let value =
            serde_json::from_slice(&reply.body).map_err(|_| ActionError::InvalidResponse)?;
        Ok((value, reply.headers))
    }

    fn mutation_json<TWire: for<'de> Deserialize<'de>>(
        &mut self,
        method: Method,
        url: Url,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<(TWire, BTreeMap<String, String>), ActionError> {
        let reply = self.send(method, url, headers, body, cancel, deadline, true)?;
        if !(200..300).contains(&reply.status) {
            return if reply.status >= 500 {
                Err(ActionError::OutcomeUnknown)
            } else {
                Err(ActionError::HttpRejected(reply.status))
            };
        }
        let value = serde_json::from_slice(&reply.body).map_err(|_| ActionError::OutcomeUnknown)?;
        Ok((value, reply.headers))
    }

    fn mutation_empty(
        &mut self,
        method: Method,
        url: Url,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<BTreeMap<String, String>, ActionError> {
        let reply = self.send(method, url, headers, body, cancel, deadline, true)?;
        if !(200..300).contains(&reply.status) {
            return if reply.status >= 500 {
                Err(ActionError::OutcomeUnknown)
            } else {
                Err(ActionError::HttpRejected(reply.status))
            };
        }
        if !reply.body.is_empty() {
            return Err(ActionError::OutcomeUnknown);
        }
        Ok(reply.headers)
    }

    fn trash(
        &mut self,
        target: &ActionTarget,
        cancel: &AtomicBool,
    ) -> Result<ActionReceipt, ActionError> {
        target.validate()?;
        if target.scope()? != self.scope {
            return Err(ActionError::ScopeMismatch);
        }
        let deadline = Instant::now() + ACTION_TIMEOUT;
        check_before_dispatch(cancel, deadline)?;
        let drive_type = self.revalidate_scope(cancel, deadline)?;
        check_before_dispatch(cancel, deadline)?;
        match target.provider() {
            Provider::GoogleDrive => self.trash_drive(target, cancel, deadline),
            Provider::Gmail => self.trash_gmail(target, cancel, deadline),
            Provider::OneDrive => self.trash_onedrive(
                target,
                drive_type.ok_or(ActionError::ScopeMismatch)?,
                cancel,
                deadline,
            ),
            Provider::Dropbox => self.trash_dropbox(target, cancel, deadline),
        }
    }

    fn restore(
        &mut self,
        receipt: &ActionReceipt,
        cancel: &AtomicBool,
    ) -> Result<ActionOutcome, ActionError> {
        receipt.validate()?;
        if receipt.target.scope()? != self.scope {
            return Err(ActionError::ScopeMismatch);
        }
        if receipt.restore_capability() != RestoreCapability::Available {
            return Err(ActionError::Unsupported);
        }
        let deadline = Instant::now() + ACTION_TIMEOUT;
        check_before_dispatch(cancel, deadline)?;
        let drive_type = self.revalidate_scope(cancel, deadline)?;
        check_before_dispatch(cancel, deadline)?;
        match (&receipt.details, receipt.provider()) {
            (ReceiptDetails::GoogleDrive { trashed_version }, Provider::GoogleDrive) => {
                self.restore_drive(&receipt.target, trashed_version, cancel, deadline)?;
            }
            (
                ReceiptDetails::Gmail {
                    thread_id,
                    trashed_history_id,
                },
                Provider::Gmail,
            ) => {
                self.restore_gmail(
                    &receipt.target,
                    thread_id,
                    trashed_history_id,
                    cancel,
                    deadline,
                )?;
            }
            (
                ReceiptDetails::OneDrive {
                    drive_type: receipt_type,
                    name,
                    parent_id,
                    trashed_etag,
                },
                Provider::OneDrive,
            ) => {
                if drive_type != Some(*receipt_type) || *receipt_type != DriveType::Personal {
                    return Err(ActionError::ScopeMismatch);
                }
                self.restore_onedrive(
                    &receipt.target,
                    name,
                    parent_id.as_deref(),
                    trashed_etag,
                    cancel,
                    deadline,
                )?;
            }
            (
                ReceiptDetails::Dropbox {
                    path_lower,
                    revision,
                    ..
                },
                Provider::Dropbox,
            ) => {
                self.restore_dropbox(&receipt.target, path_lower, revision, cancel, deadline)?;
            }
            _ => return Err(ActionError::InvalidRecord),
        }
        Ok(ActionOutcome::Restored)
    }

    fn revalidate_scope(
        &mut self,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<Option<DriveType>, ActionError> {
        let current = match self.scope.provider() {
            Provider::GoogleDrive => self.drive_scope(cancel, deadline)?,
            Provider::Gmail => self.gmail_scope(cancel, deadline)?,
            Provider::OneDrive => {
                let (scope, drive_type) = self.onedrive_scope(cancel, deadline)?;
                if scope != self.scope {
                    return Err(ActionError::ScopeMismatch);
                }
                return Ok(Some(drive_type));
            }
            Provider::Dropbox => self.dropbox_scope(cancel, deadline)?,
        };
        if current != self.scope {
            return Err(ActionError::ScopeMismatch);
        }
        Ok(None)
    }

    fn drive_scope(
        &mut self,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<AccountScope, ActionError> {
        #[derive(Deserialize)]
        struct Account {
            user: DriveUser,
        }
        #[derive(Deserialize)]
        struct DriveUser {
            #[serde(rename = "permissionId")]
            permission_id: String,
        }
        let url = fixed_url("https://www.googleapis.com/drive/v3/about?fields=user(permissionId)")?;
        let (account, _) = self.get_json::<Account>(url, Vec::new(), cancel, deadline)?;
        if !valid_text(&account.user.permission_id, MAX_ID_BYTES) {
            return Err(ActionError::InvalidResponse);
        }
        AccountScope::new(
            Provider::GoogleDrive,
            account.user.permission_id,
            Some(DRIVE_SCOPE.into()),
        )
        .map_err(|_| ActionError::InvalidResponse)
    }

    fn gmail_scope(
        &mut self,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<AccountScope, ActionError> {
        #[derive(Deserialize)]
        struct UserInfo {
            sub: String,
        }
        let url = fixed_url("https://openidconnect.googleapis.com/v1/userinfo")?;
        let (user, _) = self.get_json::<UserInfo>(url, Vec::new(), cancel, deadline)?;
        if !valid_text(&user.sub, MAX_ID_BYTES) {
            return Err(ActionError::InvalidResponse);
        }
        AccountScope::new(Provider::Gmail, user.sub, Some(GMAIL_SCOPE.into()))
            .map_err(|_| ActionError::InvalidResponse)
    }

    fn onedrive_scope(
        &mut self,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<(AccountScope, DriveType), ActionError> {
        #[derive(Deserialize)]
        struct User {
            id: String,
        }
        #[derive(Deserialize)]
        struct DrivesPage {
            value: Vec<DriveRow>,
            #[serde(rename = "@odata.nextLink")]
            next_link: Option<String>,
        }
        #[derive(Deserialize)]
        struct DriveRow {
            id: String,
            #[serde(rename = "driveType")]
            drive_type: String,
        }
        let mut me = fixed_url("https://graph.microsoft.com/v1.0/me")?;
        me.query_pairs_mut().append_pair("$select", "id");
        let (user, _) = self.get_json::<User>(me, Vec::new(), cancel, deadline)?;
        if !valid_text(&user.id, MAX_ID_BYTES) {
            return Err(ActionError::InvalidResponse);
        }
        let expected_drive = self
            .scope
            .storage_id()
            .ok_or(ActionError::ScopeMismatch)?
            .to_owned();
        let mut cursor: Option<String> = None;
        let mut seen = HashSet::new();
        let mut found = None;
        let mut total = 0usize;
        let mut completed = false;
        for _ in 0..100 {
            check_before_dispatch(cancel, deadline)?;
            let mut url = fixed_url("https://graph.microsoft.com/v1.0/me/drives")?;
            {
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("$select", "id,driveType")
                    .append_pair("$top", "100");
                if let Some(token) = cursor.as_deref() {
                    query.append_pair("$skiptoken", token);
                }
            }
            let (page, _) = self.get_json::<DrivesPage>(url, Vec::new(), cancel, deadline)?;
            if page.value.len() > 100 || total.saturating_add(page.value.len()) > 1_000 {
                return Err(ActionError::ResponseLimit);
            }
            total += page.value.len();
            for row in page.value {
                if !valid_text(&row.id, MAX_ID_BYTES) {
                    return Err(ActionError::InvalidResponse);
                }
                if row.id == expected_drive {
                    if found.is_some() {
                        return Err(ActionError::ScopeMismatch);
                    }
                    let kind =
                        parse_drive_type(&row.drive_type).ok_or(ActionError::InvalidResponse)?;
                    found = Some(kind);
                }
            }
            match page.next_link {
                Some(link) => {
                    let token = graph_skip_token(&link)?;
                    if !seen.insert(token.clone()) {
                        return Err(ActionError::InvalidResponse);
                    }
                    cursor = Some(token);
                }
                None => {
                    completed = true;
                    break;
                }
            }
        }
        // A 100-page cap is a bounded failure, not evidence that the drive
        // list was complete.
        if !completed {
            return Err(ActionError::ResponseLimit);
        }
        if found.is_none() {
            return Err(ActionError::ScopeMismatch);
        }
        Ok((
            AccountScope::new(Provider::OneDrive, user.id, Some(expected_drive))
                .map_err(|_| ActionError::InvalidResponse)?,
            found.unwrap(),
        ))
    }

    fn dropbox_scope(
        &mut self,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<AccountScope, ActionError> {
        #[derive(Deserialize)]
        struct Account {
            account_id: String,
            root_info: RootInfo,
        }
        #[derive(Deserialize)]
        struct RootInfo {
            #[serde(rename = ".tag")]
            tag: String,
            root_namespace_id: String,
        }
        let storage = self
            .scope
            .storage_id()
            .ok_or(ActionError::ScopeMismatch)?
            .to_owned();
        let url = fixed_url("https://api.dropboxapi.com/2/users/get_current_account")?;
        let reply = self.send(Method::POST, url, Vec::new(), None, cancel, deadline, false)?;
        if !(200..300).contains(&reply.status) {
            return Err(ActionError::HttpRejected(reply.status));
        }
        let account: Account =
            serde_json::from_slice(&reply.body).map_err(|_| ActionError::InvalidResponse)?;
        if !valid_text(&account.account_id, MAX_ID_BYTES)
            || !matches!(account.root_info.tag.as_str(), "user" | "team")
            || !valid_text(&account.root_info.root_namespace_id, MAX_ID_BYTES)
        {
            return Err(ActionError::InvalidResponse);
        }
        if account.root_info.root_namespace_id != storage {
            return Err(ActionError::ScopeMismatch);
        }
        AccountScope::new(
            Provider::Dropbox,
            account.account_id,
            Some(account.root_info.root_namespace_id),
        )
        .map_err(|_| ActionError::InvalidResponse)
    }
}

fn validate_scope(scope: &AccountScope) -> Result<(), ActionError> {
    let provider = scope.provider();
    if !valid_text(scope.subject_id(), MAX_ID_BYTES) {
        return Err(ActionError::ScopeMismatch);
    }
    match provider {
        Provider::GoogleDrive if scope.storage_id() == Some(DRIVE_SCOPE) => Ok(()),
        Provider::Gmail if scope.storage_id() == Some(GMAIL_SCOPE) => Ok(()),
        Provider::OneDrive | Provider::Dropbox
            if scope
                .storage_id()
                .is_some_and(|storage| valid_text(storage, MAX_ID_BYTES)) =>
        {
            Ok(())
        }
        _ => Err(ActionError::ScopeMismatch),
    }
}

fn check_before_dispatch(cancel: &AtomicBool, deadline: Instant) -> Result<(), ActionError> {
    if cancel.load(Ordering::Relaxed) {
        return Err(ActionError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(ActionError::TimedOut);
    }
    Ok(())
}

fn fixed_url(value: &str) -> Result<Url, ActionError> {
    let url = Url::parse(value).map_err(|_| ActionError::ClientUnavailable)?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
        || !matches!(
            url.host_str(),
            Some(
                "www.googleapis.com"
                    | "gmail.googleapis.com"
                    | "openidconnect.googleapis.com"
                    | "graph.microsoft.com"
                    | "api.dropboxapi.com"
            )
        )
    {
        return Err(ActionError::ClientUnavailable);
    }
    Ok(url)
}

fn graph_action_url(scope: &AccountScope, item_id: &str, action: &str) -> Result<Url, ActionError> {
    if scope.provider() != Provider::OneDrive
        || !valid_text(item_id, MAX_ID_BYTES)
        || action != "restore"
    {
        return Err(ActionError::InvalidTarget);
    }
    let drive_id = scope.storage_id().ok_or(ActionError::ScopeMismatch)?;
    if !valid_text(drive_id, MAX_ID_BYTES) {
        return Err(ActionError::ScopeMismatch);
    }
    let mut url = fixed_url("https://graph.microsoft.com/v1.0/drives/")?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| ActionError::InvalidTarget)?;
        segments
            .pop_if_empty()
            .push(drive_id)
            .push("items")
            .push(item_id)
            .push(action);
    }
    Ok(url)
}

fn graph_skip_token(value: &str) -> Result<String, ActionError> {
    if value.len() > MAX_PATH_BYTES {
        return Err(ActionError::ResponseLimit);
    }
    let url = Url::parse(value).map_err(|_| ActionError::InvalidResponse)?;
    if url.scheme() != "https"
        || url.host_str() != Some("graph.microsoft.com")
        || url.port_or_known_default() != Some(443)
        || url.path() != "/v1.0/me/drives"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ActionError::InvalidResponse);
    }
    let mut token = None;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "$skiptoken" if token.is_none() => token = Some(value.into_owned()),
            "$top" if value == "100" => {}
            "$select" if value == "id,driveType" => {}
            _ => return Err(ActionError::InvalidResponse),
        }
    }
    let token = token.ok_or(ActionError::InvalidResponse)?;
    if !valid_text(&token, crate::cloud_http::MAX_CURSOR_BYTES) {
        return Err(ActionError::InvalidResponse);
    }
    Ok(token)
}

fn parse_drive_type(value: &str) -> Option<DriveType> {
    match value {
        "personal" => Some(DriveType::Personal),
        "business" => Some(DriveType::Business),
        "documentLibrary" => Some(DriveType::DocumentLibrary),
        _ => None,
    }
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && !value.trim().is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
}

fn valid_header(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REVISION_BYTES
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn valid_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn parse_u64_decimal(value: &str) -> Result<u64, ActionError> {
    if !valid_decimal(value) {
        return Err(ActionError::InvalidResponse);
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| ActionError::InvalidResponse)?;
    if parsed > i64::MAX as u64 {
        return Err(ActionError::InvalidResponse);
    }
    Ok(parsed)
}

fn parse_rfc3339_timestamp(
    value: Option<&str>,
    basis: ProviderTimestampBasis,
) -> Result<Option<StoredTimestamp>, ActionError> {
    value
        .map(|value| {
            let time = chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| ActionError::InvalidResponse)?;
            let unix_millis = time.timestamp_millis();
            ProviderTimestamp::new(unix_millis, basis).map_err(|_| ActionError::InvalidResponse)?;
            Ok(StoredTimestamp {
                unix_millis,
                basis: match basis {
                    ProviderTimestampBasis::Modified => StoredTimestampBasis::Modified,
                    ProviderTimestampBasis::Received => StoredTimestampBasis::Received,
                },
            })
        })
        .transpose()
}

fn parse_gmail_timestamp(value: Option<&str>) -> Result<Option<StoredTimestamp>, ActionError> {
    value
        .map(|value| {
            let digits = value.strip_prefix('-').unwrap_or(value);
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ActionError::InvalidResponse);
            }
            let unix_millis = value
                .parse::<i64>()
                .map_err(|_| ActionError::InvalidResponse)?;
            ProviderTimestamp::new(unix_millis, ProviderTimestampBasis::Received)
                .map_err(|_| ActionError::InvalidResponse)?;
            Ok(StoredTimestamp {
                unix_millis,
                basis: StoredTimestampBasis::Received,
            })
        })
        .transpose()
}

fn check_snapshot_metadata(
    target: &ActionTarget,
    name: &str,
    revision: Option<&str>,
    size: Option<StoredSize>,
    timestamp: Option<StoredTimestamp>,
) -> Result<(), ActionError> {
    if name != target.display_name
        || revision.is_some_and(|revision| revision != target.revision)
        || target.size.is_some_and(|expected| size != Some(expected))
        || target
            .timestamp
            .is_some_and(|expected| timestamp != Some(expected))
    {
        return Err(ActionError::ChangedSinceScan);
    }
    Ok(())
}

fn gmail_subject(message: &GmailMessageWire) -> Result<String, ActionError> {
    let mut subject = None;
    if let Some(payload) = &message.payload {
        if payload.headers.len() > 512 {
            return Err(ActionError::ResponseLimit);
        }
        for header in &payload.headers {
            if header.name.eq_ignore_ascii_case("subject") {
                if subject.is_some() || !valid_text(&header.value, MAX_NAME_BYTES) {
                    return Err(ActionError::InvalidResponse);
                }
                subject = Some(header.value.clone());
            }
        }
    }
    Ok(subject.unwrap_or_else(|| "(No subject)".to_owned()))
}

fn validate_gmail_labels(labels: &Option<Vec<String>>) -> Result<(), ActionError> {
    let labels = labels.as_ref().ok_or(ActionError::InvalidResponse)?;
    if labels.len() > 256 {
        return Err(ActionError::ResponseLimit);
    }
    let mut seen = HashSet::new();
    for label in labels {
        if !valid_text(label, 256) || !seen.insert(label) {
            return Err(ActionError::InvalidResponse);
        }
    }
    Ok(())
}

fn contains_label(labels: &Option<Vec<String>>, expected: &str) -> bool {
    labels
        .as_ref()
        .is_some_and(|labels| labels.iter().any(|label| label == expected))
}

fn dropbox_headers(storage_id: &str) -> Result<Vec<(String, String)>, ActionError> {
    if !valid_text(storage_id, MAX_ID_BYTES) {
        return Err(ActionError::ScopeMismatch);
    }
    let value = serde_json::to_string(&serde_json::json!({
        ".tag": "root",
        "root": storage_id
    }))
    .map_err(|_| ActionError::InvalidTarget)?;
    if value.len() > MAX_ID_BYTES + 32 || value.chars().any(char::is_control) {
        return Err(ActionError::InvalidTarget);
    }
    Ok(vec![("Dropbox-API-Path-Root".into(), value)])
}

fn valid_dropbox_path(value: &str) -> bool {
    if !value.starts_with('/')
        || value.len() > MAX_PATH_BYTES
        || value.chars().any(char::is_control)
        || value.contains('\\')
        || value == "/"
    {
        return false;
    }
    value
        .split('/')
        .skip(1)
        .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn dropbox_id_path(item_id: &str) -> Result<String, ActionError> {
    if !valid_text(item_id, MAX_ID_BYTES) || !item_id.starts_with("id:") || item_id.len() <= 3 {
        return Err(ActionError::InvalidTarget);
    }
    Ok(item_id.to_owned())
}

fn is_dropbox_not_found(body: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: Option<ErrorRoot>,
    }
    #[derive(Deserialize)]
    struct ErrorRoot {
        #[serde(rename = ".tag")]
        tag: Option<String>,
        path: Option<ErrorPath>,
    }
    #[derive(Deserialize)]
    struct ErrorPath {
        #[serde(rename = ".tag")]
        tag: Option<String>,
    }
    let Ok(error) = serde_json::from_slice::<ErrorBody>(body) else {
        return false;
    };
    error.error.is_some_and(|error| {
        error.tag.as_deref() == Some("path")
            && error.path.and_then(|path| path.tag).as_deref() == Some("not_found")
    })
}

#[derive(Deserialize)]
#[serde(tag = ".tag")]
enum DropboxMetadataWire {
    #[serde(rename = "file")]
    File(DropboxFileWire),
    #[serde(rename = "folder")]
    Folder(DropboxFolderWire),
    #[serde(rename = "deleted")]
    Deleted(DropboxDeletedWire),
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct DropboxFileWire {
    id: String,
    name: String,
    rev: String,
    size: Option<u64>,
    path_lower: Option<String>,
    server_modified: Option<String>,
}

#[derive(Deserialize)]
struct DropboxFolderWire {}

#[derive(Deserialize)]
struct DropboxDeletedWire {
    name: String,
    path_lower: Option<String>,
    is_restorable: Option<bool>,
}

#[derive(Deserialize)]
struct DropboxDeleteResultWire {
    metadata: DropboxMetadataWire,
}

fn check_dropbox_snapshot(
    target: &ActionTarget,
    file: &DropboxFileWire,
) -> Result<(), ActionError> {
    if file.id != target.provider_item_id
        || file.name != target.display_name
        || !valid_text(&file.id, MAX_ID_BYTES)
        || !valid_text(&file.name, MAX_NAME_BYTES)
        || file.rev != target.revision
        || !valid_text(&file.rev, MAX_REVISION_BYTES)
        || file
            .path_lower
            .as_deref()
            .is_none_or(|path| !valid_dropbox_path(path))
    {
        return Err(ActionError::ChangedSinceScan);
    }
    let size = file.size.map(|bytes| StoredSize {
        bytes,
        accuracy: StoredSizeAccuracy::Exact,
    });
    let timestamp = parse_rfc3339_timestamp(
        file.server_modified.as_deref(),
        ProviderTimestampBasis::Modified,
    )?;
    check_snapshot_metadata(target, &file.name, Some(&file.rev), size, timestamp)
}

fn parse_graph_timestamp(value: Option<&str>) -> Result<Option<StoredTimestamp>, ActionError> {
    parse_rfc3339_timestamp(value, ProviderTimestampBasis::Modified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud_inventory::{
        PageCursor, ProviderFailure, RemoteItemDraft, RemotePage, RemotePort, SizeObservation,
        Snapshot, scan,
    };
    use std::collections::VecDeque;

    const ITEM_TIME: &str = "2025-03-04T05:06:07.123Z";
    const ITEM_MILLIS: i64 = 1_741_064_767_123;

    struct OnePagePort {
        scope: AccountScope,
        drafts: Option<Vec<RemoteItemDraft>>,
    }

    impl RemotePort for OnePagePort {
        fn current_scope(&mut self, _: &AtomicBool) -> Result<AccountScope, ProviderFailure> {
            Ok(self.scope.clone())
        }

        fn list_page(
            &mut self,
            expected_scope: &AccountScope,
            _: Option<&PageCursor>,
            _: &AtomicBool,
        ) -> Result<RemotePage, ProviderFailure> {
            if expected_scope != &self.scope {
                return Err(ProviderFailure::MalformedResponse);
            }
            Ok(RemotePage::new(
                self.scope.clone(),
                self.drafts.take().unwrap_or_default(),
                None,
            ))
        }
    }

    fn scope(provider: Provider) -> AccountScope {
        match provider {
            Provider::GoogleDrive => {
                AccountScope::new(provider, "permission-1", Some(DRIVE_SCOPE.to_owned())).unwrap()
            }
            Provider::Gmail => {
                AccountScope::new(provider, "subject-1", Some(GMAIL_SCOPE.to_owned())).unwrap()
            }
            Provider::OneDrive => {
                AccountScope::new(provider, "user-1", Some("drive-1".to_owned())).unwrap()
            }
            Provider::Dropbox => {
                AccountScope::new(provider, "dbid:account-1", Some("root-1".to_owned())).unwrap()
            }
        }
    }

    fn target(
        provider: Provider,
        item_id: &str,
        name: &str,
        revision: &str,
        bytes: u64,
        received_time: Option<i64>,
    ) -> (AccountScope, ActionTarget) {
        let scope = scope(provider);
        let kind = if provider == Provider::Gmail {
            RemoteItemKind::Mail
        } else {
            RemoteItemKind::File
        };
        let accuracy = if provider == Provider::Gmail {
            SizeAccuracy::GmailMessageEstimate
        } else {
            SizeAccuracy::ProviderReportedExact
        };
        let basis = if provider == Provider::Gmail {
            ProviderTimestampBasis::Received
        } else {
            ProviderTimestampBasis::Modified
        };
        let draft = RemoteItemDraft::new(item_id, name, kind)
            .with_mime_type(
                (provider == Provider::GoogleDrive).then(|| "application/octet-stream".to_owned()),
            )
            .with_size(Some(SizeObservation::new(bytes, accuracy)))
            .with_provider_revision(Some(revision.to_owned()))
            .with_provider_timestamp(
                received_time.map(|value| ProviderTimestamp::new(value, basis).unwrap()),
            )
            .with_trash_status(TrashStatus::NotTrashed);
        let mut port = OnePagePort {
            scope: scope.clone(),
            drafts: Some(vec![draft]),
        };
        let snapshot: Snapshot = scan(&mut port, &scope, &AtomicBool::new(false));
        assert!(snapshot.is_complete());
        let target = ActionTarget::from_item(&scope, &snapshot.items()[0]).unwrap();
        (scope, target)
    }

    fn reply(status: u16, value: serde_json::Value, headers: &[(&str, &str)]) -> HttpReply {
        HttpReply {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), (*value).to_owned()))
                .collect(),
            body: serde_json::to_vec(&value).unwrap(),
        }
    }

    fn empty_reply(status: u16) -> HttpReply {
        HttpReply {
            status,
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }

    struct FakeTransport {
        replies: VecDeque<Result<HttpReply, ActionError>>,
        requests: Vec<(RequestSpec, bool)>,
    }

    impl FakeTransport {
        fn new(replies: impl IntoIterator<Item = Result<HttpReply, ActionError>>) -> Self {
            Self {
                replies: replies.into_iter().collect(),
                requests: Vec::new(),
            }
        }
    }

    impl ActionTransport for FakeTransport {
        fn send(
            &mut self,
            request: RequestSpec,
            _: &AtomicBool,
            _: Instant,
            mutation: bool,
        ) -> Result<HttpReply, ActionError> {
            self.requests.push((request, mutation));
            self.replies
                .pop_front()
                .unwrap_or(Err(ActionError::Transport))
        }
    }

    fn drive_item(trashed: bool, version: &str) -> serde_json::Value {
        serde_json::json!({
            "id": "drive-item",
            "name": "report.bin",
            "mimeType": "application/octet-stream",
            "size": "12",
            "version": version,
            "modifiedTime": ITEM_TIME,
            "trashed": trashed,
            "explicitlyTrashed": trashed,
            "capabilities": {"canTrash": true, "canUntrash": true}
        })
    }

    fn drive_core(
        extra: impl IntoIterator<Item = Result<HttpReply, ActionError>>,
    ) -> ActionCore<FakeTransport> {
        let mut replies = vec![Ok(reply(
            200,
            serde_json::json!({"user":{"permissionId":"permission-1"}}),
            &[],
        ))];
        replies.extend(extra);
        ActionCore {
            scope: scope(Provider::GoogleDrive),
            transport: FakeTransport::new(replies),
        }
    }

    fn optional_header<'a>(request: &'a RequestSpec, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn target_record_roundtrips_expected_metadata_and_debug_redacts_identifiers() {
        let (_, target) = target(
            Provider::GoogleDrive,
            "drive-item",
            "report.bin",
            "7",
            12,
            Some(ITEM_MILLIS),
        );
        let bytes = target.to_json().unwrap();
        let restored = ActionTarget::from_json(&bytes).unwrap();
        assert_eq!(target, restored);
        assert_eq!(restored.provider_item_id(), "drive-item");
        assert_eq!(restored.display_name(), "report.bin");
        assert_eq!(restored.revision(), "7");
        assert_eq!(
            restored.size_accuracy(),
            Some(SizeAccuracy::ProviderReportedExact)
        );
        assert_eq!(
            restored.provider_timestamp().unwrap().unix_millis(),
            ITEM_MILLIS
        );
        assert!(!format!("{target:?}").contains("drive-item"));
        assert_eq!(
            ActionTarget::from_json(&vec![b'x'; MAX_RECORD_BYTES + 1]),
            Err(ActionError::RecordTooLarge)
        );
        assert!(ActionTarget::from_json(b"{broken").is_err());
    }

    #[test]
    fn drive_trash_uses_exact_item_url_revision_precondition_and_confirmed_response() {
        let (scope, target) = target(
            Provider::GoogleDrive,
            "drive-item",
            "report.bin",
            "7",
            12,
            Some(ITEM_MILLIS),
        );
        let mut core = drive_core([
            Ok(reply(
                200,
                drive_item(false, "7"),
                &[("etag", "\"etag-7\"")],
            )),
            Ok(reply(200, drive_item(true, "8"), &[])),
        ]);
        let receipt = core.trash(&target, &AtomicBool::new(false)).unwrap();
        assert_eq!(receipt.target(), &target);
        assert!(receipt.can_restore());
        assert_eq!(core.transport.requests.len(), 3);
        let (preflight, mutation) = &core.transport.requests[1];
        assert!(!mutation);
        assert_eq!(preflight.url.path(), "/drive/v3/files/drive-item");
        assert!(!preflight.url.path().contains("//files"));
        let query = preflight.url.query().unwrap_or_default();
        assert!(query.contains("canTrash"));
        assert!(query.contains("canUntrash"));
        let (request, mutation) = &core.transport.requests[2];
        assert!(*mutation);
        assert_eq!(request.method, Method::PATCH);
        assert_eq!(request.url.path(), "/drive/v3/files/drive-item");
        assert_eq!(optional_header(request, "if-match"), Some("\"etag-7\""));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(request.body.as_deref().unwrap()).unwrap(),
            serde_json::json!({"trashed":true})
        );
        let stored = ActionReceipt::from_json(&receipt.to_json().unwrap()).unwrap();
        assert_eq!(stored, receipt);
        assert_eq!(stored.target().scope().unwrap(), scope);
    }

    #[test]
    fn drive_restore_accepts_provider_modified_time_change_after_receipt_version_check() {
        let (scope, target) = target(
            Provider::GoogleDrive,
            "drive-item",
            "report.bin",
            "7",
            12,
            Some(ITEM_MILLIS),
        );
        let receipt = ActionReceipt {
            schema: 1,
            target,
            details: ReceiptDetails::GoogleDrive {
                trashed_version: "8".to_owned(),
            },
        };
        let mut changed = drive_item(false, "9");
        changed["modifiedTime"] = serde_json::json!("2025-03-04T05:06:08.123Z");
        let mut core = drive_core([
            Ok(reply(200, drive_item(true, "8"), &[("etag", "\"etag-8\"")])),
            Ok(reply(200, changed, &[("etag", "\"etag-9\"")])),
        ]);

        assert_eq!(
            core.restore(&receipt, &AtomicBool::new(false)),
            Ok(ActionOutcome::Restored)
        );
        let (request, mutation) = &core.transport.requests[2];
        assert!(*mutation);
        assert_eq!(request.method, Method::PATCH);
        assert_eq!(optional_header(request, "if-match"), Some("\"etag-8\""));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(request.body.as_deref().unwrap()).unwrap(),
            serde_json::json!({"trashed":false})
        );
        assert_eq!(scope, receipt.target().scope().unwrap());
    }

    #[test]
    fn stale_size_blocks_drive_write_and_ambiguous_dispatch_is_not_retried() {
        let (_, target) = target(
            Provider::GoogleDrive,
            "drive-item",
            "report.bin",
            "7",
            12,
            Some(ITEM_MILLIS),
        );
        let mut stale = drive_core([Ok(reply(
            200,
            {
                let mut item = drive_item(false, "7");
                item["size"] = serde_json::json!("13");
                item
            },
            &[("etag", "\"etag-7\"")],
        ))]);
        assert_eq!(
            stale.trash(&target, &AtomicBool::new(false)),
            Err(ActionError::ChangedSinceScan)
        );
        assert!(
            stale
                .transport
                .requests
                .iter()
                .all(|(_, mutation)| !mutation)
        );

        let mut unknown = drive_core([
            Ok(reply(
                200,
                drive_item(false, "7"),
                &[("etag", "\"etag-7\"")],
            )),
            Ok(empty_reply(503)),
        ]);
        assert_eq!(
            unknown.trash(&target, &AtomicBool::new(false)),
            Err(ActionError::OutcomeUnknown)
        );
        assert!(ActionError::OutcomeUnknown.outcome_unknown());
        assert_eq!(
            unknown
                .transport
                .requests
                .iter()
                .filter(|(_, write)| *write)
                .count(),
            1
        );
    }

    #[test]
    fn cancelled_action_dispatches_no_provider_calls() {
        let (_, target) = target(
            Provider::GoogleDrive,
            "drive-item",
            "report.bin",
            "7",
            12,
            Some(ITEM_MILLIS),
        );
        let mut core = ActionCore {
            scope: scope(Provider::GoogleDrive),
            transport: FakeTransport::new([]),
        };
        let cancel = AtomicBool::new(true);
        assert_eq!(core.trash(&target, &cancel), Err(ActionError::Cancelled));
        assert!(core.transport.requests.is_empty());
    }

    #[test]
    fn gmail_trash_uses_message_specific_route_and_requires_confirmed_label_state() {
        let (scope, target) = target(
            Provider::Gmail,
            "message-1",
            "Quarterly report",
            "7",
            500,
            Some(ITEM_MILLIS),
        );
        let before = serde_json::json!({
            "id":"message-1", "threadId":"thread-1", "labelIds":["INBOX"],
            "sizeEstimate":500, "internalDate":ITEM_MILLIS.to_string(), "historyId":"7",
            "payload":{"headers":[{"name":"Subject","value":"Quarterly report"}]}
        });
        let after = serde_json::json!({
            "id":"message-1", "threadId":"thread-1", "labelIds":["TRASH"], "historyId":"8"
        });
        let mut core = ActionCore {
            scope: scope.clone(),
            transport: FakeTransport::new([
                Ok(reply(200, serde_json::json!({"sub":"subject-1"}), &[])),
                Ok(reply(200, before, &[])),
                Ok(reply(200, after, &[])),
            ]),
        };
        let receipt = core.trash(&target, &AtomicBool::new(false)).unwrap();
        assert_eq!(receipt.provider(), Provider::Gmail);
        assert!(receipt.can_restore());
        assert_eq!(core.transport.requests.len(), 3);
        assert_eq!(
            core.transport.requests[1].0.url.path(),
            "/gmail/v1/users/me/messages/message-1"
        );
        let (request, mutation) = &core.transport.requests[2];
        assert!(*mutation);
        assert_eq!(request.method, Method::POST);
        assert_eq!(
            request.url.path(),
            "/gmail/v1/users/me/messages/message-1/trash"
        );
        assert!(request.body.is_none());
    }

    fn graph_item(deleted: bool, etag: &str, ctag: &str) -> serde_json::Value {
        let mut item = serde_json::json!({
            "id":"item-1", "name":"report.bin", "eTag":etag, "cTag":ctag,
            "size":12, "file":{}, "lastModifiedDateTime":ITEM_TIME,
            "parentReference":{"id":"parent-1","driveId":"drive-1"}
        });
        if deleted {
            item["deleted"] = serde_json::json!({});
        }
        item
    }

    fn graph_identity_replies() -> [Result<HttpReply, ActionError>; 2] {
        [
            Ok(reply(200, serde_json::json!({"id":"user-1"}), &[])),
            Ok(reply(
                200,
                serde_json::json!({"value":[{"id":"drive-1","driveType":"personal"}]}),
                &[],
            )),
        ]
    }

    #[test]
    fn onedrive_personal_trash_and_restore_revalidate_drive_and_etag() {
        let (scope, target) = target(
            Provider::OneDrive,
            "item-1",
            "report.bin",
            "c7",
            12,
            Some(ITEM_MILLIS),
        );
        let mut replies = graph_identity_replies().into_iter().collect::<Vec<_>>();
        replies.extend([
            Ok(reply(200, graph_item(false, "e7", "c7"), &[])),
            Ok(empty_reply(204)),
            Ok(reply(200, graph_item(true, "e8", "c8"), &[])),
        ]);
        replies.extend(graph_identity_replies());
        replies.extend([
            Ok(reply(200, graph_item(true, "e8", "c8"), &[])),
            Ok(reply(200, graph_item(false, "e9", "c9"), &[])),
        ]);
        let mut core = ActionCore {
            scope,
            transport: FakeTransport::new(replies),
        };
        let cancel = AtomicBool::new(false);
        let receipt = core.trash(&target, &cancel).unwrap();
        assert!(receipt.can_restore());
        let (delete, mutation) = &core.transport.requests[3];
        assert!(*mutation);
        assert_eq!(delete.method, Method::DELETE);
        assert_eq!(delete.url.path(), "/v1.0/drives/drive-1/items/item-1");
        assert_eq!(optional_header(delete, "if-match"), Some("e7"));
        assert_eq!(core.restore(&receipt, &cancel), Ok(ActionOutcome::Restored));
        let (restore, mutation) = core.transport.requests.last().unwrap();
        assert!(*mutation);
        assert_eq!(restore.method, Method::POST);
        assert_eq!(
            restore.url.path(),
            "/v1.0/drives/drive-1/items/item-1/restore"
        );
        let body: serde_json::Value =
            serde_json::from_slice(restore.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["name"], "report.bin");
        assert_eq!(body["parentReference"]["id"], "parent-1");
    }

    fn dropbox_account() -> HttpReply {
        reply(
            200,
            serde_json::json!({
                "account_id":"dbid:account-1",
                "root_info":{".tag":"user","root_namespace_id":"root-1"}
            }),
            &[],
        )
    }

    fn dropbox_file(rev: &str) -> serde_json::Value {
        serde_json::json!({
            ".tag":"file", "id":"id:abc123", "name":"report.txt", "rev":rev,
            "size":10, "path_lower":"/docs/report.txt", "server_modified":ITEM_TIME
        })
    }

    #[test]
    fn dropbox_trash_and_restore_bind_path_revision_and_path_root() {
        let (scope, target) = target(
            Provider::Dropbox,
            "id:abc123",
            "report.txt",
            "rev-1",
            10,
            Some(ITEM_MILLIS),
        );
        let deleted = serde_json::json!({
            ".tag":"deleted", "name":"report.txt", "path_lower":"/docs/report.txt",
            "is_restorable":true
        });
        let mut replies = vec![
            Ok(dropbox_account()),
            Ok(reply(200, dropbox_file("rev-1"), &[])),
            Ok(reply(
                200,
                serde_json::json!({"metadata":dropbox_file("rev-1")}),
                &[],
            )),
            Ok(reply(200, deleted.clone(), &[])),
            Ok(dropbox_account()),
            Ok(reply(200, deleted, &[])),
            Ok(HttpReply {
                status: 409,
                headers: BTreeMap::new(),
                body: br#"{"error":{".tag":"path","path":{".tag":"not_found"}}}"#.to_vec(),
            }),
            Ok(reply(
                200,
                {
                    let mut restored = dropbox_file("rev-2");
                    restored["server_modified"] = serde_json::json!("2025-03-04T05:06:08.123Z");
                    restored
                },
                &[],
            )),
        ];
        let mut core = ActionCore {
            scope,
            transport: FakeTransport::new(replies.drain(..)),
        };
        let cancel = AtomicBool::new(false);
        let receipt = core.trash(&target, &cancel).unwrap();
        assert!(receipt.can_restore());
        assert_eq!(core.transport.requests[0].0.method, Method::POST);
        assert_eq!(
            core.transport.requests[1].0.url.path(),
            "/2/files/get_metadata"
        );
        assert_eq!(
            optional_header(&core.transport.requests[1].0, "Dropbox-API-Path-Root"),
            Some(r#"{".tag":"root","root":"root-1"}"#)
        );
        let (delete, mutation) = &core.transport.requests[2];
        assert!(*mutation);
        assert_eq!(delete.url.path(), "/2/files/delete_v2");
        let delete_body: serde_json::Value =
            serde_json::from_slice(delete.body.as_deref().unwrap()).unwrap();
        assert_eq!(delete_body["path"], "id:abc123");
        assert_eq!(delete_body["parent_rev"], "rev-1");
        assert_eq!(core.restore(&receipt, &cancel), Ok(ActionOutcome::Restored));
        let (restore, mutation) = core.transport.requests.last().unwrap();
        assert!(*mutation);
        assert_eq!(restore.url.path(), "/2/files/restore");
        let restore_body: serde_json::Value =
            serde_json::from_slice(restore.body.as_deref().unwrap()).unwrap();
        assert_eq!(restore_body["path"], "/docs/report.txt");
        assert_eq!(restore_body["rev"], "rev-1");
    }

    #[test]
    fn fixed_routes_and_provider_metadata_reject_unsafe_inputs() {
        assert_eq!(dropbox_id_path("id:stable").unwrap(), "id:stable");
        assert!(dropbox_id_path("/arbitrary/path").is_err());
        assert!(valid_dropbox_path("/folder/report.txt"));
        assert!(!valid_dropbox_path("/folder/../report.txt"));
        assert!(graph_skip_token(
            "https://graph.microsoft.com/v1.0/me/drives?$skiptoken=opaque-token&$top=100&$select=id%2CdriveType"
        )
        .is_ok());
        assert!(
            graph_skip_token("https://attacker.invalid/v1.0/me/drives?$skiptoken=token").is_err()
        );
        assert!(
            graph_skip_token(
                "https://graph.microsoft.com/v1.0/me/drives?redirect=https://evil.invalid"
            )
            .is_err()
        );
        assert!(fixed_url("http://graph.microsoft.com/v1.0/me").is_err());
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveItemWire {
    id: String,
    name: String,
    mime_type: Option<String>,
    version: Option<String>,
    size: Option<String>,
    modified_time: Option<String>,
    trashed: Option<bool>,
    explicitly_trashed: Option<bool>,
    capabilities: Option<DriveCapabilitiesWire>,
}

#[derive(Deserialize)]
struct DriveCapabilitiesWire {
    #[serde(rename = "canTrash")]
    can_trash: Option<bool>,
    #[serde(rename = "canUntrash")]
    can_untrash: Option<bool>,
}

impl<T: ActionTransport> ActionCore<T> {
    fn drive_item_url(id: &str) -> Result<Url, ActionError> {
        if !valid_text(id, MAX_ID_BYTES) {
            return Err(ActionError::InvalidTarget);
        }
        let mut url = fixed_url("https://www.googleapis.com/drive/v3/files/")?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| ActionError::InvalidTarget)?;
            segments.pop_if_empty().push(id);
        }
        url.query_pairs_mut()
            .append_pair("supportsAllDrives", "true")
            .append_pair(
                "fields",
                "id,name,mimeType,size,version,modifiedTime,trashed,explicitlyTrashed,capabilities(canTrash,canUntrash)",
            );
        Ok(url)
    }

    fn check_drive_snapshot(
        target: &ActionTarget,
        item: &DriveItemWire,
    ) -> Result<(), ActionError> {
        if item.id != target.provider_item_id
            || !valid_text(&item.name, MAX_NAME_BYTES)
            || item.name != target.display_name
            || item.version.as_deref() != Some(target.revision.as_str())
        {
            return Err(ActionError::ChangedSinceScan);
        }
        let size = item
            .size
            .as_deref()
            .map(parse_u64_decimal)
            .transpose()?
            .map(|bytes| StoredSize {
                bytes,
                accuracy: StoredSizeAccuracy::Exact,
            });
        let timestamp = parse_rfc3339_timestamp(
            item.modified_time.as_deref(),
            ProviderTimestampBasis::Modified,
        )?;
        check_snapshot_metadata(target, &item.name, item.version.as_deref(), size, timestamp)?;
        if item.mime_type.as_deref().is_none_or(|value| {
            !valid_text(value, 512) || value == "application/vnd.google-apps.folder"
        }) {
            return Err(ActionError::InvalidResponse);
        }
        Ok(())
    }

    fn trash_drive(
        &mut self,
        target: &ActionTarget,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<ActionReceipt, ActionError> {
        let (item, headers) = self.get_json::<DriveItemWire>(
            Self::drive_item_url(&target.provider_item_id)?,
            Vec::new(),
            cancel,
            deadline,
        )?;
        Self::check_drive_snapshot(target, &item)?;
        match item.trashed {
            Some(false) => {}
            Some(true) => return Err(ActionError::AlreadyTrashed),
            None => return Err(ActionError::InvalidResponse),
        }
        if item.capabilities.as_ref().and_then(|value| value.can_trash) != Some(true) {
            return Err(ActionError::Unsupported);
        }
        let etag = headers
            .get("etag")
            .filter(|value| valid_header(value))
            .ok_or(ActionError::Unsupported)?;
        check_before_dispatch(cancel, deadline)?;
        let url = Self::drive_item_url(&target.provider_item_id)?;
        let body = serde_json::to_vec(&serde_json::json!({"trashed":true}))
            .map_err(|_| ActionError::InvalidTarget)?;
        let (changed, _) = self.mutation_json::<DriveItemWire>(
            Method::PATCH,
            url,
            vec![("if-match".to_owned(), etag.to_owned())],
            Some(body),
            cancel,
            deadline,
        )?;
        if changed.id != target.provider_item_id || changed.trashed != Some(true) {
            return Err(ActionError::OutcomeUnknown);
        }
        let version = changed.version.ok_or(ActionError::OutcomeUnknown)?;
        if !valid_decimal(&version) {
            return Err(ActionError::OutcomeUnknown);
        }
        let receipt = ActionReceipt {
            schema: 1,
            target: target.clone(),
            details: ReceiptDetails::GoogleDrive {
                trashed_version: version,
            },
        };
        receipt
            .validate()
            .map_err(|_| ActionError::OutcomeUnknown)?;
        Ok(receipt)
    }

    fn restore_drive(
        &mut self,
        target: &ActionTarget,
        expected_trashed_version: &str,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<(), ActionError> {
        let (item, headers) = self.get_json::<DriveItemWire>(
            Self::drive_item_url(&target.provider_item_id)?,
            Vec::new(),
            cancel,
            deadline,
        )?;
        if item.id != target.provider_item_id
            || item.trashed != Some(true)
            || item.explicitly_trashed != Some(true)
            || item.version.as_deref() != Some(expected_trashed_version)
            || item
                .capabilities
                .as_ref()
                .and_then(|capability| capability.can_untrash)
                != Some(true)
        {
            return Err(ActionError::NotTrashed);
        }
        let etag = headers
            .get("etag")
            .filter(|value| valid_header(value))
            .ok_or(ActionError::Unsupported)?;
        check_before_dispatch(cancel, deadline)?;
        let body = serde_json::to_vec(&serde_json::json!({"trashed":false}))
            .map_err(|_| ActionError::InvalidTarget)?;
        let (changed, _) = self.mutation_json::<DriveItemWire>(
            Method::PATCH,
            Self::drive_item_url(&target.provider_item_id)?,
            vec![("if-match".to_owned(), etag.to_owned())],
            Some(body),
            cancel,
            deadline,
        )?;
        if changed.id != target.provider_item_id || changed.trashed != Some(false) {
            return Err(ActionError::OutcomeUnknown);
        }
        if !valid_text(&changed.name, MAX_NAME_BYTES) || changed.name != target.display_name {
            return Err(ActionError::OutcomeUnknown);
        }
        let changed_size = changed
            .size
            .as_deref()
            .map(parse_u64_decimal)
            .transpose()
            .map_err(|_| ActionError::OutcomeUnknown)?
            .map(|bytes| StoredSize {
                bytes,
                accuracy: StoredSizeAccuracy::Exact,
            });
        parse_rfc3339_timestamp(
            changed.modified_time.as_deref(),
            ProviderTimestampBasis::Modified,
        )
        .map_err(|_| ActionError::OutcomeUnknown)?;
        if target
            .size
            .is_some_and(|expected| changed_size != Some(expected))
        {
            return Err(ActionError::OutcomeUnknown);
        }
        Ok(())
    }

    fn gmail_message_url(id: &str, action: Option<&str>) -> Result<Url, ActionError> {
        if !valid_text(id, MAX_ID_BYTES) {
            return Err(ActionError::InvalidTarget);
        }
        let mut url = fixed_url("https://gmail.googleapis.com/gmail/v1/users/")?;
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| ActionError::InvalidTarget)?;
            path.pop_if_empty().push("me").push("messages").push(id);
            if let Some(action) = action {
                path.push(action);
            }
        }
        if action.is_none() {
            url.query_pairs_mut()
                .append_pair("format", "metadata")
                .append_pair("metadataHeaders", "Subject")
                .append_pair("fields", "id,threadId,labelIds,sizeEstimate,internalDate,historyId,payload(headers(name,value))");
        } else {
            url.query_pairs_mut()
                .append_pair("fields", "id,threadId,labelIds,historyId");
        }
        Ok(url)
    }

    fn check_gmail_snapshot(
        target: &ActionTarget,
        message: &GmailMessageWire,
    ) -> Result<(), ActionError> {
        if message.id != target.provider_item_id
            || !valid_text(&message.thread_id, MAX_ID_BYTES)
            || message.history_id.as_deref() != Some(target.revision.as_str())
        {
            return Err(ActionError::ChangedSinceScan);
        }
        let subject = gmail_subject(message)?;
        if subject != target.display_name {
            return Err(ActionError::ChangedSinceScan);
        }
        let size = message.size_estimate.map(|bytes| StoredSize {
            bytes,
            accuracy: StoredSizeAccuracy::GmailEstimate,
        });
        let timestamp = parse_gmail_timestamp(message.internal_date.as_deref())?;
        check_snapshot_metadata(target, &subject, Some(&target.revision), size, timestamp)?;
        Ok(())
    }

    fn trash_gmail(
        &mut self,
        target: &ActionTarget,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<ActionReceipt, ActionError> {
        let (message, _) = self.get_json::<GmailMessageWire>(
            Self::gmail_message_url(&target.provider_item_id, None)?,
            Vec::new(),
            cancel,
            deadline,
        )?;
        Self::check_gmail_snapshot(target, &message)?;
        validate_gmail_labels(&message.label_ids)?;
        if contains_label(&message.label_ids, "TRASH") {
            return Err(ActionError::AlreadyTrashed);
        }
        if contains_label(&message.label_ids, "SPAM") {
            return Err(ActionError::Unsupported);
        }
        check_before_dispatch(cancel, deadline)?;
        let (changed, _) = self.mutation_json::<GmailMessageWire>(
            Method::POST,
            Self::gmail_message_url(&target.provider_item_id, Some("trash"))?,
            Vec::new(),
            None,
            cancel,
            deadline,
        )?;
        if changed.id != target.provider_item_id
            || changed.thread_id != message.thread_id
            || !contains_label(&changed.label_ids, "TRASH")
        {
            return Err(ActionError::OutcomeUnknown);
        }
        validate_gmail_labels(&changed.label_ids).map_err(|_| ActionError::OutcomeUnknown)?;
        if contains_label(&changed.label_ids, "SPAM") {
            return Err(ActionError::OutcomeUnknown);
        }
        let history = changed.history_id.ok_or(ActionError::OutcomeUnknown)?;
        if !valid_decimal(&history) {
            return Err(ActionError::OutcomeUnknown);
        }
        let receipt = ActionReceipt {
            schema: 1,
            target: target.clone(),
            details: ReceiptDetails::Gmail {
                thread_id: message.thread_id,
                trashed_history_id: history,
            },
        };
        receipt
            .validate()
            .map_err(|_| ActionError::OutcomeUnknown)?;
        Ok(receipt)
    }

    fn restore_gmail(
        &mut self,
        target: &ActionTarget,
        expected_thread_id: &str,
        expected_history_id: &str,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<(), ActionError> {
        let (message, _) = self.get_json::<GmailMessageWire>(
            Self::gmail_message_url(&target.provider_item_id, None)?,
            Vec::new(),
            cancel,
            deadline,
        )?;
        if message.id != target.provider_item_id
            || message.thread_id != expected_thread_id
            || message.history_id.as_deref() != Some(expected_history_id)
        {
            return Err(ActionError::ChangedSinceScan);
        }
        validate_gmail_labels(&message.label_ids)?;
        if !contains_label(&message.label_ids, "TRASH") {
            return Err(ActionError::NotTrashed);
        }
        check_before_dispatch(cancel, deadline)?;
        let (changed, _) = self.mutation_json::<GmailMessageWire>(
            Method::POST,
            Self::gmail_message_url(&target.provider_item_id, Some("untrash"))?,
            Vec::new(),
            None,
            cancel,
            deadline,
        )?;
        if changed.id != target.provider_item_id
            || changed.thread_id != expected_thread_id
            || contains_label(&changed.label_ids, "TRASH")
        {
            return Err(ActionError::OutcomeUnknown);
        }
        validate_gmail_labels(&changed.label_ids).map_err(|_| ActionError::OutcomeUnknown)?;
        if contains_label(&changed.label_ids, "SPAM") {
            return Err(ActionError::OutcomeUnknown);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphItemWire {
    id: String,
    name: String,
    e_tag: Option<String>,
    c_tag: Option<String>,
    size: Option<u64>,
    file: Option<serde_json::Value>,
    folder: Option<serde_json::Value>,
    remote_item: Option<serde_json::Value>,
    deleted: Option<serde_json::Value>,
    last_modified_date_time: Option<String>,
    parent_reference: Option<GraphParentWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphParentWire {
    id: Option<String>,
    drive_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailMessageWire {
    id: String,
    thread_id: String,
    label_ids: Option<Vec<String>>,
    size_estimate: Option<u64>,
    internal_date: Option<String>,
    history_id: Option<String>,
    payload: Option<GmailPayloadWire>,
}

#[derive(Deserialize)]
struct GmailPayloadWire {
    #[serde(default)]
    headers: Vec<GmailHeaderWire>,
}

#[derive(Deserialize)]
struct GmailHeaderWire {
    name: String,
    value: String,
}

impl<T: ActionTransport> ActionCore<T> {
    fn graph_item_url(&self, item_id: &str) -> Result<Url, ActionError> {
        let drive_id = self.scope.storage_id().ok_or(ActionError::ScopeMismatch)?;
        if !valid_text(drive_id, MAX_ID_BYTES) || !valid_text(item_id, MAX_ID_BYTES) {
            return Err(ActionError::InvalidTarget);
        }
        let mut url = fixed_url("https://graph.microsoft.com/v1.0/drives/")?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| ActionError::InvalidTarget)?;
            segments
                .pop_if_empty()
                .push(drive_id)
                .push("items")
                .push(item_id);
        }
        url.query_pairs_mut().append_pair(
            "$select",
            "id,name,eTag,cTag,size,file,folder,remoteItem,deleted,lastModifiedDateTime,parentReference",
        );
        Ok(url)
    }

    fn check_graph_snapshot(
        target: &ActionTarget,
        item: &GraphItemWire,
    ) -> Result<(), ActionError> {
        if item.id != target.provider_item_id
            || item.name != target.display_name
            || !valid_text(&item.name, MAX_NAME_BYTES)
            || item.c_tag.as_deref().or(item.e_tag.as_deref()) != Some(target.revision.as_str())
        {
            return Err(ActionError::ChangedSinceScan);
        }
        if !item.file.as_ref().is_some_and(serde_json::Value::is_object)
            || item.folder.is_some()
            || item.remote_item.is_some()
        {
            return Err(ActionError::InvalidResponse);
        }
        let size = item.size.map(|bytes| StoredSize {
            bytes,
            accuracy: StoredSizeAccuracy::Exact,
        });
        let timestamp = parse_graph_timestamp(item.last_modified_date_time.as_deref())?;
        check_snapshot_metadata(
            target,
            &item.name,
            item.c_tag.as_deref().or(item.e_tag.as_deref()),
            size,
            timestamp,
        )?;
        let drive_id = target
            .storage_id
            .as_deref()
            .ok_or(ActionError::ScopeMismatch)?;
        if item
            .parent_reference
            .as_ref()
            .and_then(|parent| parent.drive_id.as_deref())
            .is_some_and(|actual| actual != drive_id)
        {
            return Err(ActionError::ScopeMismatch);
        }
        if item.e_tag.as_deref().is_none_or(|etag| !valid_header(etag)) {
            return Err(ActionError::Unsupported);
        }
        if item.deleted.is_some() {
            return Err(ActionError::AlreadyTrashed);
        }
        Ok(())
    }

    fn trash_onedrive(
        &mut self,
        target: &ActionTarget,
        drive_type: DriveType,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<ActionReceipt, ActionError> {
        let (item, _) = self.get_json::<GraphItemWire>(
            self.graph_item_url(&target.provider_item_id)?,
            Vec::new(),
            cancel,
            deadline,
        )?;
        Self::check_graph_snapshot(target, &item)?;
        let etag = item
            .e_tag
            .as_deref()
            .ok_or(ActionError::Unsupported)?
            .to_owned();
        let parent_id = item
            .parent_reference
            .as_ref()
            .and_then(|parent| parent.id.clone());
        if parent_id
            .as_deref()
            .is_some_and(|id| !valid_text(id, MAX_ID_BYTES))
        {
            return Err(ActionError::InvalidResponse);
        }
        check_before_dispatch(cancel, deadline)?;
        self.mutation_empty(
            Method::DELETE,
            self.graph_item_url(&target.provider_item_id)?,
            vec![("if-match".to_owned(), etag)],
            None,
            cancel,
            deadline,
        )?;
        let (deleted, _) = self
            .get_json::<GraphItemWire>(
                self.graph_item_url(&target.provider_item_id)?,
                Vec::new(),
                cancel,
                deadline,
            )
            .map_err(|_| ActionError::OutcomeUnknown)?;
        let trashed_etag = deleted
            .e_tag
            .as_deref()
            .filter(|value| valid_header(value))
            .ok_or(ActionError::OutcomeUnknown)?
            .to_owned();
        if deleted.id != target.provider_item_id
            || !deleted
                .deleted
                .as_ref()
                .is_some_and(serde_json::Value::is_object)
            || deleted.name != item.name
            || deleted
                .parent_reference
                .as_ref()
                .and_then(|parent| parent.id.as_deref())
                != parent_id.as_deref()
        {
            return Err(ActionError::OutcomeUnknown);
        }
        let receipt = ActionReceipt {
            schema: 1,
            target: target.clone(),
            details: ReceiptDetails::OneDrive {
                drive_type,
                name: item.name,
                parent_id,
                trashed_etag,
            },
        };
        receipt
            .validate()
            .map_err(|_| ActionError::OutcomeUnknown)?;
        Ok(receipt)
    }

    fn restore_onedrive(
        &mut self,
        target: &ActionTarget,
        expected_name: &str,
        expected_parent_id: Option<&str>,
        expected_trashed_etag: &str,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<(), ActionError> {
        let (item, _) = self.get_json::<GraphItemWire>(
            self.graph_item_url(&target.provider_item_id)?,
            Vec::new(),
            cancel,
            deadline,
        )?;
        if item.id != target.provider_item_id
            || !item
                .deleted
                .as_ref()
                .is_some_and(serde_json::Value::is_object)
            || item.folder.is_some()
            || !item.file.as_ref().is_some_and(serde_json::Value::is_object)
            || item.name != expected_name
            || item.remote_item.is_some()
            || item.e_tag.as_deref() != Some(expected_trashed_etag)
            || item
                .parent_reference
                .as_ref()
                .and_then(|parent| parent.id.as_deref())
                != expected_parent_id
        {
            return Err(ActionError::NotTrashed);
        }
        check_before_dispatch(cancel, deadline)?;
        let mut body = serde_json::Map::new();
        body.insert(
            "name".to_owned(),
            serde_json::Value::String(expected_name.to_owned()),
        );
        if let Some(parent_id) = expected_parent_id {
            body.insert(
                "parentReference".to_owned(),
                serde_json::json!({"id": parent_id}),
            );
        }
        let (restored, _) = self.mutation_json::<GraphItemWire>(
            Method::POST,
            graph_action_url(&self.scope, &target.provider_item_id, "restore")?,
            Vec::new(),
            Some(
                serde_json::to_vec(&serde_json::Value::Object(body))
                    .map_err(|_| ActionError::InvalidTarget)?,
            ),
            cancel,
            deadline,
        )?;
        if restored.id != target.provider_item_id
            || restored.deleted.is_some()
            || restored.folder.is_some()
            || !restored
                .file
                .as_ref()
                .is_some_and(serde_json::Value::is_object)
            || restored.name != expected_name
            || restored.remote_item.is_some()
            || restored
                .parent_reference
                .as_ref()
                .and_then(|parent| parent.id.as_deref())
                != expected_parent_id
            || target
                .size
                .is_some_and(|size| restored.size != Some(size.bytes))
        {
            return Err(ActionError::OutcomeUnknown);
        }
        Ok(())
    }

    fn dropbox_metadata(
        &mut self,
        path: &str,
        include_deleted: bool,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<DropboxMetadataWire, ActionError> {
        let storage = self.scope.storage_id().ok_or(ActionError::ScopeMismatch)?;
        let url = fixed_url("https://api.dropboxapi.com/2/files/get_metadata")?;
        let headers = dropbox_headers(storage)?;
        let body = serde_json::to_vec(&serde_json::json!({
            "path": path,
            "include_deleted": include_deleted,
            "include_media_info": false,
            "include_has_explicit_shared_members": false
        }))
        .map_err(|_| ActionError::InvalidTarget)?;
        let reply = self.send(
            Method::POST,
            url,
            headers,
            Some(body),
            cancel,
            deadline,
            false,
        )?;
        if reply.status == 409 && is_dropbox_not_found(&reply.body) {
            return Err(ActionError::NotTrashed);
        }
        if !(200..300).contains(&reply.status) {
            return Err(ActionError::HttpRejected(reply.status));
        }
        serde_json::from_slice(&reply.body).map_err(|_| ActionError::InvalidResponse)
    }

    fn trash_dropbox(
        &mut self,
        target: &ActionTarget,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<ActionReceipt, ActionError> {
        let id_path = dropbox_id_path(&target.provider_item_id)?;
        let metadata = self.dropbox_metadata(&id_path, true, cancel, deadline)?;
        let file = match metadata {
            DropboxMetadataWire::File(file) => file,
            DropboxMetadataWire::Deleted(_) | DropboxMetadataWire::Folder(_) => {
                return Err(ActionError::AlreadyTrashed);
            }
        };
        check_dropbox_snapshot(target, &file)?;
        let path_lower = file
            .path_lower
            .as_deref()
            .filter(|path| valid_dropbox_path(path))
            .ok_or(ActionError::Unsupported)?
            .to_owned();
        check_before_dispatch(cancel, deadline)?;
        let url = fixed_url("https://api.dropboxapi.com/2/files/delete_v2")?;
        let headers = dropbox_headers(
            target
                .storage_id
                .as_deref()
                .ok_or(ActionError::ScopeMismatch)?,
        )?;
        let body = serde_json::to_vec(&serde_json::json!({
            "path": id_path,
            "parent_rev": target.revision
        }))
        .map_err(|_| ActionError::InvalidTarget)?;
        let (result, _) = self.mutation_json::<DropboxDeleteResultWire>(
            Method::POST,
            url,
            headers,
            Some(body),
            cancel,
            deadline,
        )?;
        let deleted = match result.metadata {
            DropboxMetadataWire::File(file) => file,
            DropboxMetadataWire::Folder(_) | DropboxMetadataWire::Deleted(_) => {
                return Err(ActionError::OutcomeUnknown);
            }
        };
        if deleted.id != target.provider_item_id
            || deleted.path_lower.as_deref() != Some(path_lower.as_str())
            || deleted.rev != target.revision
        {
            return Err(ActionError::OutcomeUnknown);
        }
        let confirmed = self
            .dropbox_metadata(&id_path, true, cancel, deadline)
            .map_err(|_| ActionError::OutcomeUnknown)?;
        let restore_supported = match confirmed {
            DropboxMetadataWire::Deleted(item)
                if item.name == target.display_name
                    && item.path_lower.as_deref() == Some(path_lower.as_str()) =>
            {
                item.is_restorable == Some(true)
            }
            _ => return Err(ActionError::OutcomeUnknown),
        };
        let receipt = ActionReceipt {
            schema: 1,
            target: target.clone(),
            details: ReceiptDetails::Dropbox {
                path_lower,
                revision: deleted.rev,
                restorable: restore_supported,
            },
        };
        receipt
            .validate()
            .map_err(|_| ActionError::OutcomeUnknown)?;
        Ok(receipt)
    }

    fn restore_dropbox(
        &mut self,
        target: &ActionTarget,
        expected_path: &str,
        expected_revision: &str,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<(), ActionError> {
        let id_path = dropbox_id_path(&target.provider_item_id)?;
        match self.dropbox_metadata(&id_path, true, cancel, deadline)? {
            DropboxMetadataWire::Deleted(item) => {
                if item.path_lower.as_deref() != Some(expected_path)
                    || item.name != target.display_name
                    || item.is_restorable != Some(true)
                {
                    return Err(ActionError::ChangedSinceScan);
                }
            }
            DropboxMetadataWire::File(_) | DropboxMetadataWire::Folder(_) => {
                return Err(ActionError::NotTrashed);
            }
        }
        // Restore targets a path rather than an immutable Dropbox file ID. It
        // refuses to proceed if a live entry now occupies that path.
        let live = self.dropbox_metadata(expected_path, false, cancel, deadline);
        match live {
            Ok(_) => return Err(ActionError::ChangedSinceScan),
            Err(ActionError::NotTrashed) => {}
            Err(other) => return Err(other),
        }
        check_before_dispatch(cancel, deadline)?;
        let url = fixed_url("https://api.dropboxapi.com/2/files/restore")?;
        let headers = dropbox_headers(
            target
                .storage_id
                .as_deref()
                .ok_or(ActionError::ScopeMismatch)?,
        )?;
        let body = serde_json::to_vec(&serde_json::json!({
            "path": expected_path,
            "rev": expected_revision
        }))
        .map_err(|_| ActionError::InvalidTarget)?;
        let (restored, _) = self.mutation_json::<DropboxFileWire>(
            Method::POST,
            url,
            headers,
            Some(body),
            cancel,
            deadline,
        )?;
        if restored.id != target.provider_item_id
            || restored.path_lower.as_deref() != Some(expected_path)
            || restored.name != target.display_name
            || !valid_text(&restored.rev, MAX_REVISION_BYTES)
        {
            return Err(ActionError::OutcomeUnknown);
        }
        let size = restored.size.map(|bytes| StoredSize {
            bytes,
            accuracy: StoredSizeAccuracy::Exact,
        });
        parse_rfc3339_timestamp(
            restored.server_modified.as_deref(),
            ProviderTimestampBasis::Modified,
        )
        .map_err(|_| ActionError::OutcomeUnknown)?;
        if target.size.is_some_and(|expected| size != Some(expected)) {
            return Err(ActionError::OutcomeUnknown);
        }
        Ok(())
    }
}
