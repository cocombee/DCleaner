//! Bounded, provider-neutral cloud metadata inventory.
//!
//! This module only lists metadata. It does not store credentials, fetch remote
//! content, construct deletion plans, or expose remote mutation operations.
//! Every association in this module is an observation, never an authorization
//! to remove or change an item.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use uuid::Uuid;

const MAX_SCOPE_ID_BYTES: usize = 512;
const MAX_CURSOR_BYTES: usize = 2_048;
const MAX_ITEM_ID_BYTES: usize = 512;
const MAX_DISPLAY_NAME_BYTES: usize = 4_096;
const MAX_MIME_TYPE_BYTES: usize = 512;
const MAX_REVISION_BYTES: usize = 512;
const MAX_HASH_ALGORITHM_BYTES: usize = 128;
const MAX_HASH_DIGEST_BYTES: usize = 512;
const MAX_ITEM_BYTES: usize = 8 * 1024;
const MAX_PAGE_ITEMS: usize = 1_000;
const MAX_PAGES: usize = 512;
const MAX_ROWS_SEEN: usize = 50_000;
const MAX_RETAINED_ROWS: usize = 50_000;
const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const MAX_ISSUES: usize = 64;
const DEFAULT_SCAN_BUDGET: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Provider {
    GoogleDrive,
    Gmail,
    OneDrive,
    Dropbox,
}

impl Provider {
    pub const fn label(self) -> &'static str {
        match self {
            Self::GoogleDrive => "Google Drive",
            Self::Gmail => "Gmail",
            Self::OneDrive => "OneDrive",
            Self::Dropbox => "Dropbox",
        }
    }
}

impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Immutable provider account and storage identity. Values are opaque and are
/// intentionally excluded from `Debug` and serialization.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct AccountScope {
    provider: Provider,
    subject_id: String,
    storage_id: Option<String>,
}

impl AccountScope {
    pub fn new(
        provider: Provider,
        subject_id: impl Into<String>,
        storage_id: Option<String>,
    ) -> Result<Self, InputError> {
        let subject_id = subject_id.into();
        validate_opaque("account subject", &subject_id, MAX_SCOPE_ID_BYTES)?;
        if let Some(storage_id) = &storage_id {
            validate_opaque("storage scope", storage_id, MAX_SCOPE_ID_BYTES)?;
        }
        Ok(Self {
            provider,
            subject_id,
            storage_id,
        })
    }

    pub const fn provider(&self) -> Provider {
        self.provider
    }

    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    pub fn storage_id(&self) -> Option<&str> {
        self.storage_id.as_deref()
    }
}

impl fmt::Debug for AccountScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountScope")
            .field("provider", &self.provider)
            .field("subject_id", &"[redacted]")
            .field(
                "storage_id",
                &self.storage_id.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputError {
    Empty,
    TooLong,
    ContainsControl,
    InvalidDigest,
    InvalidPageCursor,
    InvalidTimestamp,
}

fn validate_opaque(_label: &str, value: &str, max: usize) -> Result<(), InputError> {
    if value.is_empty() {
        return Err(InputError::Empty);
    }
    if value.len() > max {
        return Err(InputError::TooLong);
    }
    if value.chars().any(char::is_control) {
        return Err(InputError::ContainsControl);
    }
    Ok(())
}

/// Opaque pagination cursor. It is tied to the account/storage scope that
/// issued it and is never included in snapshots or diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct PageCursor {
    scope: AccountScope,
    value: String,
}

impl PageCursor {
    pub fn new(scope: &AccountScope, value: impl Into<String>) -> Result<Self, InputError> {
        let value = value.into();
        validate_opaque("page cursor", &value, MAX_CURSOR_BYTES)
            .map_err(|_| InputError::InvalidPageCursor)?;
        Ok(Self {
            scope: scope.clone(),
            value,
        })
    }

    /// Pass the opaque token back to the provider adapter. Do not log it.
    pub fn provider_value(&self) -> &str {
        &self.value
    }

    /// Whether this cursor belongs to the immutable account/storage scope.
    /// Adapters can check this without exposing the scope's internals.
    pub fn belongs_to(&self, scope: &AccountScope) -> bool {
        &self.scope == scope
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageCursor")
            .field("scope", &self.scope)
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RemoteItemKind {
    File,
    Folder,
    Mail,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SizeAccuracy {
    ProviderReportedExact,
    ProviderReportedEstimate,
    /// Gmail `sizeEstimate` is an estimate and is not an exact message size.
    GmailMessageEstimate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SizeObservation {
    bytes: u64,
    accuracy: SizeAccuracy,
}

impl SizeObservation {
    pub const fn new(bytes: u64, accuracy: SizeAccuracy) -> Self {
        Self { bytes, accuracy }
    }

    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    pub const fn accuracy(self) -> SizeAccuracy {
        self.accuracy
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    ProviderNative(String),
}

impl fmt::Debug for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Md5 => f.write_str("MD5"),
            Self::Sha1 => f.write_str("SHA-1"),
            Self::Sha256 => f.write_str("SHA-256"),
            Self::ProviderNative(_) => f.write_str("ProviderNative([opaque])"),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ContentHash {
    provider: Provider,
    algorithm: HashAlgorithm,
    digest: String,
}

impl ContentHash {
    pub fn new(
        provider: Provider,
        algorithm: HashAlgorithm,
        digest: impl Into<String>,
    ) -> Result<Self, InputError> {
        let mut digest = digest.into();
        validate_opaque("content hash", &digest, MAX_HASH_DIGEST_BYTES)?;
        if !matches!(
            (&algorithm, digest.len()),
            (HashAlgorithm::Md5, 32)
                | (HashAlgorithm::Sha1, 40)
                | (HashAlgorithm::Sha256, 64)
                | (HashAlgorithm::ProviderNative(_), _)
        ) || matches!(&algorithm, HashAlgorithm::ProviderNative(name) if name.is_empty() || name.len() > MAX_HASH_ALGORITHM_BYTES || name.chars().any(char::is_control))
            || (!matches!(&algorithm, HashAlgorithm::ProviderNative(_))
                && !digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(InputError::InvalidDigest);
        }
        if !matches!(&algorithm, HashAlgorithm::ProviderNative(_)) {
            digest.make_ascii_lowercase();
        }
        Ok(Self {
            provider,
            algorithm,
            digest,
        })
    }

    pub const fn provider(&self) -> Provider {
        self.provider
    }

    pub fn algorithm(&self) -> &HashAlgorithm {
        &self.algorithm
    }

    /// Expose only when a provider adapter needs the raw digest. Do not treat
    /// a match as proof of content equality.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentHash")
            .field("provider", &self.provider)
            .field("algorithm", &self.algorithm)
            .field("digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UnknownFieldReason {
    NotProvided,
    NotSupported,
    PermissionDenied,
    MalformedProviderData,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TrashStatus {
    Trashed,
    NotTrashed,
    Unknown(UnknownFieldReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderTimestampBasis {
    Modified,
    Received,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderTimestamp {
    unix_millis: i64,
    basis: ProviderTimestampBasis,
}
impl ProviderTimestamp {
    pub fn new(unix_millis: i64, basis: ProviderTimestampBasis) -> Result<Self, InputError> {
        if chrono::DateTime::<chrono::Utc>::from_timestamp_millis(unix_millis).is_none() {
            return Err(InputError::InvalidTimestamp);
        }
        Ok(Self { unix_millis, basis })
    }
    pub const fn unix_millis(self) -> i64 {
        self.unix_millis
    }
    pub const fn basis(self) -> ProviderTimestampBasis {
        self.basis
    }
}

/// Unvalidated provider row. The inventory validates each field before it is
/// retained. It is deliberately not serializable and its Debug output omits
/// provider identifiers and display metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct RemoteItemDraft {
    provider_item_id: String,
    display_name: String,
    mime_type: Option<String>,
    kind: RemoteItemKind,
    size: Option<SizeObservation>,
    content_hash: Option<ContentHash>,
    provider_revision: Option<String>,
    provider_timestamp: Option<ProviderTimestamp>,
    trash_status: TrashStatus,
}

impl RemoteItemDraft {
    pub fn new(
        provider_item_id: impl Into<String>,
        display_name: impl Into<String>,
        kind: RemoteItemKind,
    ) -> Self {
        Self {
            provider_item_id: provider_item_id.into(),
            display_name: display_name.into(),
            mime_type: None,
            kind,
            size: None,
            content_hash: None,
            provider_revision: None,
            provider_timestamp: None,
            trash_status: TrashStatus::Unknown(UnknownFieldReason::NotProvided),
        }
    }

    pub fn with_mime_type(mut self, mime_type: Option<String>) -> Self {
        self.mime_type = mime_type;
        self
    }

    pub fn with_size(mut self, size: Option<SizeObservation>) -> Self {
        self.size = size;
        self
    }

    pub fn with_content_hash(mut self, content_hash: Option<ContentHash>) -> Self {
        self.content_hash = content_hash;
        self
    }

    pub fn with_provider_revision(mut self, revision: Option<String>) -> Self {
        self.provider_revision = revision;
        self
    }

    pub fn with_provider_timestamp(mut self, timestamp: Option<ProviderTimestamp>) -> Self {
        self.provider_timestamp = timestamp;
        self
    }

    pub fn with_trash_status(mut self, status: TrashStatus) -> Self {
        self.trash_status = status;
        self
    }
}

impl fmt::Debug for RemoteItemDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteItemDraft")
            .field("provider_item_id", &"[redacted]")
            .field("display_name", &"[redacted]")
            .field("kind", &self.kind)
            .field("has_size", &self.size.is_some())
            .field("has_content_hash", &self.content_hash.is_some())
            .field("has_revision", &self.provider_revision.is_some())
            .field("trash_status", &self.trash_status)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IncompletePageReason {
    ProviderReportedIncompleteSearch,
    ProviderTruncatedResults,
    ProviderReportedUnknownLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageCompleteness {
    Complete,
    Incomplete(IncompletePageReason),
}

/// A provider response and the exact account/storage scope used for that
/// response. `next_cursor` is opaque and scope-bound.
#[derive(Clone, Eq, PartialEq)]
pub struct RemotePage {
    scope: AccountScope,
    items: Vec<RemoteItemDraft>,
    next_cursor: Option<PageCursor>,
    completeness: PageCompleteness,
}

impl RemotePage {
    pub fn new(
        scope: AccountScope,
        items: Vec<RemoteItemDraft>,
        next_cursor: Option<PageCursor>,
    ) -> Self {
        Self {
            scope,
            items,
            next_cursor,
            completeness: PageCompleteness::Complete,
        }
    }

    pub fn with_completeness(mut self, completeness: PageCompleteness) -> Self {
        self.completeness = completeness;
        self
    }
}

impl fmt::Debug for RemotePage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemotePage")
            .field("scope", &self.scope)
            .field("item_count", &self.items.len())
            .field("has_next_cursor", &self.next_cursor.is_some())
            .field("completeness", &self.completeness)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderFailure {
    Unavailable,
    StorageSelectionRequired,
    Cancelled,
    AccountScopeMismatch,
    AuthenticationRequired,
    PermissionDenied,
    RateLimited,
    TimedOut,
    ResponseLimit,
    ClientUnavailable,
    Transport,
    TemporarilyUnavailable,
    MalformedResponse,
    Other,
}

/// Read-only adapter seam. Implementations must bind each page to the supplied
/// immutable scope and return the scope actually used in `RemotePage`.
/// Cancellation is checked around every call; adapters should also observe it
/// where possible, but an in-flight HTTP operation may not be interruptible.
pub trait RemotePort {
    fn current_scope(&mut self, cancel: &AtomicBool) -> Result<AccountScope, ProviderFailure>;

    fn list_page(
        &mut self,
        expected_scope: &AccountScope,
        cursor: Option<&PageCursor>,
        cancel: &AtomicBool,
    ) -> Result<RemotePage, ProviderFailure>;
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvalidRowReason {
    EmptyItemId,
    ItemIdTooLong,
    InvalidDisplayName,
    DisplayNameTooLong,
    InvalidMimeType,
    MimeTypeTooLong,
    InvalidRevision,
    RevisionTooLong,
    HashProviderMismatch,
    ItemKindProviderMismatch,
    SizeAccuracyProviderMismatch,
    FolderHasContentMetadata,
    ExactGmailMessageSize,
    RecordTooLarge,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InventoryIssueKind {
    Cancelled,
    AccountScopeUnavailable(ProviderFailure),
    AccountScopeChanged,
    PageScopeMismatch,
    CursorScopeMismatch,
    ProviderPageFailed(ProviderFailure),
    ProviderReportedIncomplete(IncompletePageReason),
    ScanDeadlineReached,
    DuplicateProviderItemId,
    MalformedRow(InvalidRowReason),
    PageItemLimitReached,
    PageLimitReached,
    RowLimitReached,
    RetainedByteLimitReached,
    PaginationCursorCycle,
    AdditionalIssuesOmitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InventoryIssue {
    kind: InventoryIssueKind,
    occurrences: usize,
}

impl InventoryIssue {
    pub const fn kind(self) -> InventoryIssueKind {
        self.kind
    }

    pub const fn occurrences(self) -> usize {
        self.occurrences
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotStatus {
    Complete,
    Partial,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ScanItemId {
    scan_id: Uuid,
    item_id: Uuid,
}

impl ScanItemId {
    pub const fn scan_id(self) -> Uuid {
        self.scan_id
    }

    pub const fn uuid(self) -> Uuid {
        self.item_id
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RemoteItem {
    id: ScanItemId,
    provider_item_id: String,
    display_name: String,
    mime_type: Option<String>,
    kind: RemoteItemKind,
    size: Option<SizeObservation>,
    content_hash: Option<ContentHash>,
    provider_revision: Option<String>,
    provider_timestamp: Option<ProviderTimestamp>,
    trash_status: TrashStatus,
    retained_bytes: usize,
}

impl RemoteItem {
    pub const fn id(&self) -> ScanItemId {
        self.id
    }

    /// Stable opaque ID in the provider scope. Keep it out of logs.
    pub fn provider_item_id(&self) -> &str {
        &self.provider_item_id
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn mime_type(&self) -> Option<&str> {
        self.mime_type.as_deref()
    }

    pub const fn kind(&self) -> RemoteItemKind {
        self.kind
    }

    pub const fn size(&self) -> Option<SizeObservation> {
        self.size
    }

    pub fn content_hash(&self) -> Option<&ContentHash> {
        self.content_hash.as_ref()
    }

    pub fn provider_revision(&self) -> Option<&str> {
        self.provider_revision.as_deref()
    }

    pub const fn provider_timestamp(&self) -> Option<ProviderTimestamp> {
        self.provider_timestamp
    }

    pub const fn trash_status(&self) -> TrashStatus {
        self.trash_status
    }
}

impl fmt::Debug for RemoteItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteItem")
            .field("id", &self.id)
            .field("provider_item_id", &"[redacted]")
            .field("display_name", &"[redacted]")
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field(
                "content_hash",
                &self.content_hash.as_ref().map(|_| "[redacted]"),
            )
            .field("has_revision", &self.provider_revision.is_some())
            .field("trash_status", &self.trash_status)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Snapshot {
    scan_id: Uuid,
    scope: AccountScope,
    status: SnapshotStatus,
    items: Vec<RemoteItem>,
    issues: Vec<InventoryIssue>,
}

impl Snapshot {
    #[cfg(debug_assertions)]
    pub fn visual_preview_partial_fixture(scope: AccountScope) -> Self {
        let mut snapshot = Self::visual_preview_fixture(scope);
        for kind in [
            InventoryIssueKind::ScanDeadlineReached,
            InventoryIssueKind::PageLimitReached,
            InventoryIssueKind::RowLimitReached,
            InventoryIssueKind::RetainedByteLimitReached,
        ] {
            record_partial(&mut snapshot, kind);
        }
        snapshot
    }
    #[cfg(debug_assertions)]
    pub fn visual_preview_fixture(scope: AccountScope) -> Self {
        let scan_id = Uuid::from_u128(0x4443_434c_4f55_4400_0000_0000_0000_0003);
        Self {
            scan_id,
            scope,
            status: SnapshotStatus::Complete,
            issues: Vec::new(),
            items: vec![RemoteItem {
                id: ScanItemId {
                    scan_id,
                    item_id: Uuid::from_u128(0x4443_434c_4f55_4400_0000_0000_0000_0004),
                },
                provider_item_id: "__inert_visual_fixture_file__".into(),
                display_name: "Example archive.zip".into(),
                mime_type: Some("application/zip".into()),
                kind: RemoteItemKind::File,
                size: Some(SizeObservation {
                    bytes: 24 * 1024 * 1024,
                    accuracy: SizeAccuracy::ProviderReportedExact,
                }),
                content_hash: None,
                provider_revision: Some("synthetic-revision".into()),
                provider_timestamp: None,
                trash_status: TrashStatus::NotTrashed,
                retained_bytes: 512,
            }],
        }
    }
    pub const fn scan_id(&self) -> Uuid {
        self.scan_id
    }

    pub fn scope(&self) -> &AccountScope {
        &self.scope
    }

    pub const fn status(&self) -> SnapshotStatus {
        self.status
    }

    pub fn is_complete(&self) -> bool {
        self.status == SnapshotStatus::Complete
    }

    pub fn items(&self) -> &[RemoteItem] {
        &self.items
    }

    pub fn issues(&self) -> &[InventoryIssue] {
        &self.issues
    }

    /// Threshold-based candidates only. Exact and estimated sizes remain
    /// distinguishable; an estimate is never promoted to an exact size.
    pub fn large_item_candidates(&self, minimum_bytes: u64) -> LargeItemAssessment {
        let candidates = self
            .items
            .iter()
            .filter_map(|item| {
                (item.kind != RemoteItemKind::Folder)
                    .then_some(item.size)
                    .flatten()
                    .filter(|size| size.bytes >= minimum_bytes)
                    .map(|size| LargeItemCandidate {
                        item_id: item.id,
                        kind: item.kind,
                        bytes: size.bytes,
                        accuracy: size.accuracy,
                    })
            })
            .collect();
        LargeItemAssessment {
            scan_id: self.scan_id,
            snapshot_status: self.status,
            minimum_bytes,
            candidates,
        }
    }

    /// Hash matches create review candidates only. Size equality is never used
    /// as duplicate evidence and no result proves that content is identical.
    /// Contradictory exact sizes for equal hash metadata are surfaced as
    /// conflicts instead of being grouped as possible duplicates.
    pub fn possible_duplicate_groups(&self) -> DuplicateAssessment {
        let mut buckets: BTreeMap<HashNamespace, Vec<(ScanItemId, Option<SizeObservation>)>> =
            BTreeMap::new();
        for item in &self.items {
            let Some(hash) = &item.content_hash else {
                continue;
            };
            buckets
                .entry(HashNamespace {
                    provider: hash.provider,
                    kind: item.kind,
                    algorithm: hash.algorithm.clone(),
                    digest: hash.digest.clone(),
                })
                .or_default()
                .push((item.id, item.size));
        }
        let mut groups = Vec::new();
        let mut conflicts = Vec::new();
        for (namespace, mut items) in buckets {
            if items.len() < 2 {
                continue;
            }
            let mut exact_sizes = HashSet::new();
            for (_, size) in &items {
                if let Some(size) = *size {
                    if size.accuracy == SizeAccuracy::ProviderReportedExact {
                        exact_sizes.insert(size.bytes);
                    }
                }
            }
            items.sort_by_key(|(id, _)| id.uuid());
            let item_ids: Vec<_> = items.into_iter().map(|(id, _)| id).collect();
            if exact_sizes.len() > 1 {
                conflicts.push(HashEvidenceConflict {
                    provider: namespace.provider,
                    kind: namespace.kind,
                    algorithm: namespace.algorithm,
                    item_ids,
                });
            } else {
                groups.push(PossibleDuplicateGroup {
                    provider: namespace.provider,
                    kind: namespace.kind,
                    algorithm: namespace.algorithm,
                    item_ids,
                });
            }
        }
        DuplicateAssessment {
            scan_id: self.scan_id,
            snapshot_status: self.status,
            groups,
            conflicts,
        }
    }
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("scan_id", &self.scan_id)
            .field("scope", &self.scope)
            .field("status", &self.status)
            .field("item_count", &self.items.len())
            .field("issues", &self.issues)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LargeItemCandidate {
    item_id: ScanItemId,
    kind: RemoteItemKind,
    bytes: u64,
    accuracy: SizeAccuracy,
}

impl LargeItemCandidate {
    pub const fn item_id(self) -> ScanItemId {
        self.item_id
    }

    pub const fn kind(self) -> RemoteItemKind {
        self.kind
    }

    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    pub const fn accuracy(self) -> SizeAccuracy {
        self.accuracy
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LargeItemAssessment {
    scan_id: Uuid,
    snapshot_status: SnapshotStatus,
    minimum_bytes: u64,
    candidates: Vec<LargeItemCandidate>,
}

impl LargeItemAssessment {
    pub const fn scan_id(&self) -> Uuid {
        self.scan_id
    }

    pub const fn snapshot_status(&self) -> SnapshotStatus {
        self.snapshot_status
    }

    pub const fn minimum_bytes(&self) -> u64 {
        self.minimum_bytes
    }

    pub fn candidates(&self) -> &[LargeItemCandidate] {
        &self.candidates
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PossibleDuplicateGroup {
    provider: Provider,
    kind: RemoteItemKind,
    algorithm: HashAlgorithm,
    item_ids: Vec<ScanItemId>,
}

impl PossibleDuplicateGroup {
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    pub const fn kind(&self) -> RemoteItemKind {
        self.kind
    }

    pub fn algorithm(&self) -> &HashAlgorithm {
        &self.algorithm
    }

    pub fn item_ids(&self) -> &[ScanItemId] {
        &self.item_ids
    }

    pub const fn equality_is_unverified(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplicateAssessment {
    scan_id: Uuid,
    snapshot_status: SnapshotStatus,
    groups: Vec<PossibleDuplicateGroup>,
    conflicts: Vec<HashEvidenceConflict>,
}

impl DuplicateAssessment {
    pub const fn scan_id(&self) -> Uuid {
        self.scan_id
    }

    pub const fn snapshot_status(&self) -> SnapshotStatus {
        self.snapshot_status
    }

    pub fn groups(&self) -> &[PossibleDuplicateGroup] {
        &self.groups
    }

    pub fn conflicts(&self) -> &[HashEvidenceConflict] {
        &self.conflicts
    }
}

/// Hash identity and exact-size evidence disagree. Such rows are retained for
/// inspection but are deliberately excluded from possible-duplicate groups.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashEvidenceConflict {
    provider: Provider,
    kind: RemoteItemKind,
    algorithm: HashAlgorithm,
    item_ids: Vec<ScanItemId>,
}

impl HashEvidenceConflict {
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    pub const fn kind(&self) -> RemoteItemKind {
        self.kind
    }

    pub fn algorithm(&self) -> &HashAlgorithm {
        &self.algorithm
    }

    pub fn item_ids(&self) -> &[ScanItemId] {
        &self.item_ids
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct HashNamespace {
    provider: Provider,
    kind: RemoteItemKind,
    algorithm: HashAlgorithm,
    digest: String,
}

#[derive(Clone, Copy)]
struct Limits {
    max_page_items: usize,
    max_pages: usize,
    max_rows_seen: usize,
    max_retained_rows: usize,
    max_retained_bytes: usize,
}

const DEFAULT_LIMITS: Limits = Limits {
    max_page_items: MAX_PAGE_ITEMS,
    max_pages: MAX_PAGES,
    max_rows_seen: MAX_ROWS_SEEN,
    max_retained_rows: MAX_RETAINED_ROWS,
    max_retained_bytes: MAX_RETAINED_BYTES,
};

/// Read a bounded metadata listing for exactly one account/storage scope.
/// `Complete` means all pages exposed by the provider's selected listing/query
/// were traversed; it is not a claim that the provider exposed every item in
/// the account or that the remote collection was an atomic point-in-time view.
/// Provider errors return a Failed or Partial snapshot rather than an empty
/// success. The scan has a five-minute soft budget and discards provider data
/// returned after its deadline. The budget is checked between calls; it cannot
/// interrupt a native/provider call that is already blocked, so wall time can
/// exceed five minutes until that call returns. A Partial/Cancelled/Failed
/// snapshot is never a complete view.
pub fn scan(
    port: &mut impl RemotePort,
    expected_scope: &AccountScope,
    cancel: &AtomicBool,
) -> Snapshot {
    scan_with_limits_and_item_hook(port, expected_scope, cancel, DEFAULT_LIMITS, || {})
}

fn scan_with_limits_and_item_hook(
    port: &mut impl RemotePort,
    expected_scope: &AccountScope,
    cancel: &AtomicBool,
    limits: Limits,
    before_item: impl FnMut(),
) -> Snapshot {
    let started = Instant::now();
    scan_with_clock(
        port,
        expected_scope,
        cancel,
        limits,
        before_item,
        || started.elapsed(),
        DEFAULT_SCAN_BUDGET,
    )
}

fn scan_with_clock(
    port: &mut impl RemotePort,
    expected_scope: &AccountScope,
    cancel: &AtomicBool,
    limits: Limits,
    mut before_item: impl FnMut(),
    mut elapsed: impl FnMut() -> Duration,
    budget: Duration,
) -> Snapshot {
    let mut snapshot = Snapshot {
        scan_id: Uuid::new_v4(),
        scope: expected_scope.clone(),
        status: SnapshotStatus::Complete,
        items: Vec::new(),
        issues: Vec::new(),
    };
    let mut retained: Vec<Option<RemoteItem>> = Vec::new();
    let mut retained_bytes = 0usize;
    let mut seen_ids: HashMap<String, usize> = HashMap::new();
    let mut duplicate_ids = HashSet::new();
    let mut seen_cursors = HashSet::new();
    let mut cursor: Option<PageCursor> = None;
    let mut pages = 0usize;
    let mut rows_seen = 0usize;

    loop {
        if cancellation_requested(cancel) {
            record_cancelled(&mut snapshot);
            break;
        }
        if deadline_reached(&mut elapsed, budget) {
            record_scan_deadline(&mut snapshot, has_retained(&retained));
            break;
        }
        if pages >= limits.max_pages {
            record_partial(&mut snapshot, InventoryIssueKind::PageLimitReached);
            break;
        }
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.scope != *expected_scope)
        {
            record_failure(
                &mut snapshot,
                has_retained(&retained),
                InventoryIssueKind::CursorScopeMismatch,
            );
            break;
        }

        if cancellation_requested(cancel) {
            record_cancelled(&mut snapshot);
            break;
        }
        if deadline_reached(&mut elapsed, budget) {
            record_scan_deadline(&mut snapshot, has_retained(&retained));
            break;
        }
        let before_scope = port.current_scope(cancel);
        if cancellation_requested(cancel) {
            record_cancelled(&mut snapshot);
            break;
        }
        if deadline_reached(&mut elapsed, budget) {
            record_scan_deadline(&mut snapshot, has_retained(&retained));
            break;
        }
        match before_scope {
            Err(error) => {
                record_failure(
                    &mut snapshot,
                    has_retained(&retained),
                    InventoryIssueKind::AccountScopeUnavailable(error),
                );
                break;
            }
            Ok(scope) if scope != *expected_scope => {
                record_failure(
                    &mut snapshot,
                    has_retained(&retained),
                    InventoryIssueKind::AccountScopeChanged,
                );
                break;
            }
            Ok(_) => {}
        }

        if cancellation_requested(cancel) {
            record_cancelled(&mut snapshot);
            break;
        }
        if deadline_reached(&mut elapsed, budget) {
            record_scan_deadline(&mut snapshot, has_retained(&retained));
            break;
        }
        let page_result = port.list_page(expected_scope, cursor.as_ref(), cancel);
        pages += 1;
        if cancellation_requested(cancel) {
            record_cancelled(&mut snapshot);
            break;
        }
        if deadline_reached(&mut elapsed, budget) {
            // Do not inspect or retain a page that arrived after the deadline.
            record_scan_deadline(&mut snapshot, has_retained(&retained));
            break;
        }

        // Read the current account again after each provider page call. A page
        // is not accepted if the selected account/storage changed in-flight.
        if cancellation_requested(cancel) {
            record_cancelled(&mut snapshot);
            break;
        }
        if deadline_reached(&mut elapsed, budget) {
            record_scan_deadline(&mut snapshot, has_retained(&retained));
            break;
        }
        let after_scope = port.current_scope(cancel);
        if cancellation_requested(cancel) {
            record_cancelled(&mut snapshot);
            break;
        }
        if deadline_reached(&mut elapsed, budget) {
            // The page is discarded if the verification read completes late.
            record_scan_deadline(&mut snapshot, has_retained(&retained));
            break;
        }
        let after_scope_ok = match after_scope {
            Err(error) => {
                record_failure(
                    &mut snapshot,
                    has_retained(&retained),
                    InventoryIssueKind::AccountScopeUnavailable(error),
                );
                false
            }
            Ok(scope) if scope != *expected_scope => {
                record_failure(
                    &mut snapshot,
                    has_retained(&retained),
                    InventoryIssueKind::AccountScopeChanged,
                );
                false
            }
            Ok(_) => true,
        };
        if !after_scope_ok {
            break;
        }

        let page = match page_result {
            Ok(page) => page,
            Err(error) => {
                record_failure(
                    &mut snapshot,
                    has_retained(&retained),
                    InventoryIssueKind::ProviderPageFailed(error),
                );
                break;
            }
        };
        if page.scope != *expected_scope {
            record_failure(
                &mut snapshot,
                has_retained(&retained),
                InventoryIssueKind::PageScopeMismatch,
            );
            break;
        }
        if let PageCompleteness::Incomplete(reason) = page.completeness {
            record_partial(
                &mut snapshot,
                InventoryIssueKind::ProviderReportedIncomplete(reason),
            );
        }

        let page_item_limit_reached = page.items.len() > limits.max_page_items;
        if page_item_limit_reached {
            record_partial(&mut snapshot, InventoryIssueKind::PageItemLimitReached);
        }
        let mut stop_after_page = page_item_limit_reached;
        let page_items = page.items.into_iter().take(limits.max_page_items);
        for draft in page_items {
            if cancellation_requested(cancel) {
                record_cancelled(&mut snapshot);
                stop_after_page = true;
                break;
            }
            if deadline_reached(&mut elapsed, budget) {
                record_scan_deadline(&mut snapshot, has_retained(&retained));
                stop_after_page = true;
                break;
            }
            before_item();
            if cancellation_requested(cancel) {
                record_cancelled(&mut snapshot);
                stop_after_page = true;
                break;
            }
            if deadline_reached(&mut elapsed, budget) {
                record_scan_deadline(&mut snapshot, has_retained(&retained));
                stop_after_page = true;
                break;
            }
            if rows_seen >= limits.max_rows_seen {
                record_partial(&mut snapshot, InventoryIssueKind::RowLimitReached);
                stop_after_page = true;
                break;
            }
            rows_seen += 1;
            let item = match validate_draft(expected_scope, snapshot.scan_id, draft) {
                Ok(item) => item,
                Err(reason) => {
                    record_partial(&mut snapshot, InventoryIssueKind::MalformedRow(reason));
                    continue;
                }
            };
            if cancellation_requested(cancel) {
                record_cancelled(&mut snapshot);
                stop_after_page = true;
                break;
            }
            if deadline_reached(&mut elapsed, budget) {
                record_scan_deadline(&mut snapshot, has_retained(&retained));
                stop_after_page = true;
                break;
            }
            let provider_id = item.provider_item_id.clone();
            if duplicate_ids.contains(&provider_id) {
                record_partial(&mut snapshot, InventoryIssueKind::DuplicateProviderItemId);
                continue;
            }
            if let Some(index) = seen_ids.remove(&provider_id) {
                if let Some(previous) = retained[index].take() {
                    retained_bytes = retained_bytes.saturating_sub(previous.retained_bytes);
                }
                duplicate_ids.insert(provider_id);
                record_partial(&mut snapshot, InventoryIssueKind::DuplicateProviderItemId);
                continue;
            }
            if retained.len() >= limits.max_retained_rows {
                record_partial(&mut snapshot, InventoryIssueKind::RowLimitReached);
                stop_after_page = true;
                break;
            }
            if retained_bytes.saturating_add(item.retained_bytes) > limits.max_retained_bytes {
                record_partial(&mut snapshot, InventoryIssueKind::RetainedByteLimitReached);
                stop_after_page = true;
                break;
            }
            let index = retained.len();
            retained_bytes += item.retained_bytes;
            seen_ids.insert(provider_id, index);
            retained.push(Some(item));
        }
        if stop_after_page {
            break;
        }
        if cancellation_requested(cancel) {
            record_cancelled(&mut snapshot);
            break;
        }
        let Some(next_cursor) = page.next_cursor else {
            break;
        };
        if next_cursor.scope != *expected_scope {
            record_failure(
                &mut snapshot,
                has_retained(&retained),
                InventoryIssueKind::CursorScopeMismatch,
            );
            break;
        }
        if !seen_cursors.insert(next_cursor.value.clone()) {
            record_partial(&mut snapshot, InventoryIssueKind::PaginationCursorCycle);
            break;
        }
        if pages >= limits.max_pages {
            record_partial(&mut snapshot, InventoryIssueKind::PageLimitReached);
            break;
        }
        if rows_seen >= limits.max_rows_seen {
            record_partial(&mut snapshot, InventoryIssueKind::RowLimitReached);
            break;
        }
        cursor = Some(next_cursor);
    }

    snapshot.items = retained.into_iter().flatten().collect();
    if snapshot.status != SnapshotStatus::Cancelled {
        if cancellation_requested(cancel) {
            record_cancelled(&mut snapshot);
        } else if deadline_reached(&mut elapsed, budget) {
            let has_items = !snapshot.items.is_empty();
            record_scan_deadline(&mut snapshot, has_items);
        }
    }
    snapshot
}

fn deadline_reached(elapsed: &mut impl FnMut() -> Duration, budget: Duration) -> bool {
    elapsed() >= budget
}

fn cancellation_requested(cancel: &AtomicBool) -> bool {
    cancel.load(Ordering::Relaxed)
}

fn has_retained(items: &[Option<RemoteItem>]) -> bool {
    items.iter().any(Option::is_some)
}

fn record_partial(snapshot: &mut Snapshot, kind: InventoryIssueKind) {
    if snapshot.status == SnapshotStatus::Complete {
        snapshot.status = SnapshotStatus::Partial;
    }
    record_issue(snapshot, kind);
}

fn record_failure(snapshot: &mut Snapshot, has_items: bool, kind: InventoryIssueKind) {
    if matches!(snapshot.status, SnapshotStatus::Complete) {
        snapshot.status = if has_items {
            SnapshotStatus::Partial
        } else {
            SnapshotStatus::Failed
        };
    } else if snapshot.status == SnapshotStatus::Partial && !has_items {
        // Preserve Partial for malformed or provider-incomplete data already
        // observed; failure does not make it a clean empty result.
    }
    record_issue(snapshot, kind);
}

fn record_cancelled(snapshot: &mut Snapshot) {
    snapshot.status = SnapshotStatus::Cancelled;
    record_issue(snapshot, InventoryIssueKind::Cancelled);
}

fn record_scan_deadline(snapshot: &mut Snapshot, has_items: bool) {
    snapshot.status = if has_items {
        SnapshotStatus::Partial
    } else {
        SnapshotStatus::Failed
    };
    if !snapshot
        .issues
        .iter()
        .any(|issue| issue.kind == InventoryIssueKind::ScanDeadlineReached)
    {
        record_issue(snapshot, InventoryIssueKind::ScanDeadlineReached);
    }
}

fn record_issue(snapshot: &mut Snapshot, kind: InventoryIssueKind) {
    if let Some(existing) = snapshot.issues.iter_mut().find(|issue| issue.kind == kind) {
        existing.occurrences = existing.occurrences.saturating_add(1);
        return;
    }
    if snapshot.issues.len() < MAX_ISSUES {
        snapshot.issues.push(InventoryIssue {
            kind,
            occurrences: 1,
        });
    } else if let Some(existing) = snapshot
        .issues
        .iter_mut()
        .find(|issue| issue.kind == InventoryIssueKind::AdditionalIssuesOmitted)
    {
        existing.occurrences = existing.occurrences.saturating_add(1);
    } else if let Some(last) = snapshot.issues.last_mut() {
        *last = InventoryIssue {
            kind: InventoryIssueKind::AdditionalIssuesOmitted,
            occurrences: 1,
        };
    }
}

fn validate_draft(
    scope: &AccountScope,
    scan_id: Uuid,
    draft: RemoteItemDraft,
) -> Result<RemoteItem, InvalidRowReason> {
    if draft.provider_item_id.is_empty() {
        return Err(InvalidRowReason::EmptyItemId);
    }
    if draft.provider_item_id.len() > MAX_ITEM_ID_BYTES
        || draft.provider_item_id.chars().any(char::is_control)
    {
        return Err(InvalidRowReason::ItemIdTooLong);
    }
    if draft.display_name.trim().is_empty() || draft.display_name.chars().any(char::is_control) {
        return Err(InvalidRowReason::InvalidDisplayName);
    }
    if draft.display_name.len() > MAX_DISPLAY_NAME_BYTES {
        return Err(InvalidRowReason::DisplayNameTooLong);
    }
    if let Some(mime_type) = &draft.mime_type {
        if mime_type.is_empty() || mime_type.chars().any(char::is_control) {
            return Err(InvalidRowReason::InvalidMimeType);
        }
        if mime_type.len() > MAX_MIME_TYPE_BYTES {
            return Err(InvalidRowReason::MimeTypeTooLong);
        }
    }
    if let Some(revision) = &draft.provider_revision {
        if revision.is_empty() || revision.chars().any(char::is_control) {
            return Err(InvalidRowReason::InvalidRevision);
        }
        if revision.len() > MAX_REVISION_BYTES {
            return Err(InvalidRowReason::RevisionTooLong);
        }
    }
    let provider_kind_ok = match scope.provider {
        Provider::Gmail => draft.kind == RemoteItemKind::Mail,
        Provider::GoogleDrive | Provider::OneDrive | Provider::Dropbox => {
            draft.kind != RemoteItemKind::Mail
        }
    };
    if !provider_kind_ok {
        return Err(InvalidRowReason::ItemKindProviderMismatch);
    }
    if draft.size.is_some_and(|size| {
        size.accuracy == SizeAccuracy::GmailMessageEstimate
            && (scope.provider != Provider::Gmail || draft.kind != RemoteItemKind::Mail)
    }) {
        return Err(InvalidRowReason::SizeAccuracyProviderMismatch);
    }
    if draft
        .content_hash
        .as_ref()
        .is_some_and(|hash| hash.provider != scope.provider)
    {
        return Err(InvalidRowReason::HashProviderMismatch);
    }
    if draft.kind == RemoteItemKind::Folder
        && (draft.size.is_some() || draft.content_hash.is_some())
    {
        return Err(InvalidRowReason::FolderHasContentMetadata);
    }
    if scope.provider == Provider::Gmail
        && draft.kind == RemoteItemKind::Mail
        && draft
            .size
            .is_some_and(|size| size.accuracy == SizeAccuracy::ProviderReportedExact)
    {
        return Err(InvalidRowReason::ExactGmailMessageSize);
    }

    let retained_bytes = draft
        .provider_item_id
        .len()
        .saturating_add(draft.display_name.len())
        .saturating_add(draft.mime_type.as_ref().map_or(0, String::len))
        .saturating_add(draft.provider_revision.as_ref().map_or(0, String::len))
        .saturating_add(
            draft
                .content_hash
                .as_ref()
                .map_or(0, |hash| hash.digest.len()),
        )
        .saturating_add(match &draft.content_hash {
            Some(ContentHash {
                algorithm: HashAlgorithm::ProviderNative(name),
                ..
            }) => name.len(),
            _ => 0,
        });
    if retained_bytes > MAX_ITEM_BYTES {
        return Err(InvalidRowReason::RecordTooLarge);
    }
    Ok(RemoteItem {
        id: ScanItemId {
            scan_id,
            item_id: Uuid::new_v4(),
        },
        provider_item_id: draft.provider_item_id,
        display_name: draft.display_name,
        mime_type: draft.mime_type,
        kind: draft.kind,
        size: draft.size,
        content_hash: draft.content_hash,
        provider_revision: draft.provider_revision,
        provider_timestamp: draft.provider_timestamp,
        trash_status: draft.trash_status,
        retained_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, collections::VecDeque, rc::Rc};

    struct FakePort {
        default_scope: AccountScope,
        scopes: VecDeque<Result<AccountScope, ProviderFailure>>,
        pages: VecDeque<Result<RemotePage, ProviderFailure>>,
        scope_calls: usize,
        list_calls: usize,
        cursors: Vec<Option<String>>,
    }

    struct DeadlinePort {
        inner: FakePort,
        elapsed: Rc<Cell<Duration>>,
        budget: Duration,
        expire_after_scope_call: Option<usize>,
        expire_after_list_call: Option<usize>,
    }

    impl DeadlinePort {
        fn advance_after_scope_if_due(&mut self) {
            if self.expire_after_scope_call == Some(self.inner.scope_calls) {
                self.elapsed.set(self.budget);
            }
        }

        fn advance_after_list_if_due(&mut self) {
            if self.expire_after_list_call == Some(self.inner.list_calls) {
                self.elapsed.set(self.budget);
            }
        }
    }

    impl RemotePort for DeadlinePort {
        fn current_scope(&mut self, cancel: &AtomicBool) -> Result<AccountScope, ProviderFailure> {
            let result = self.inner.current_scope(cancel);
            self.advance_after_scope_if_due();
            result
        }

        fn list_page(
            &mut self,
            expected_scope: &AccountScope,
            cursor: Option<&PageCursor>,
            cancel: &AtomicBool,
        ) -> Result<RemotePage, ProviderFailure> {
            let result = self.inner.list_page(expected_scope, cursor, cancel);
            self.advance_after_list_if_due();
            result
        }
    }

    impl FakePort {
        fn new(scope: AccountScope, pages: Vec<Result<RemotePage, ProviderFailure>>) -> Self {
            Self {
                default_scope: scope,
                scopes: VecDeque::new(),
                pages: pages.into(),
                scope_calls: 0,
                list_calls: 0,
                cursors: Vec::new(),
            }
        }

        fn scopes(mut self, scopes: Vec<Result<AccountScope, ProviderFailure>>) -> Self {
            self.scopes = scopes.into();
            self
        }
    }

    impl RemotePort for FakePort {
        fn current_scope(&mut self, _cancel: &AtomicBool) -> Result<AccountScope, ProviderFailure> {
            self.scope_calls += 1;
            self.scopes
                .pop_front()
                .unwrap_or_else(|| Ok(self.default_scope.clone()))
        }

        fn list_page(
            &mut self,
            expected_scope: &AccountScope,
            cursor: Option<&PageCursor>,
            _cancel: &AtomicBool,
        ) -> Result<RemotePage, ProviderFailure> {
            assert_eq!(expected_scope, &self.default_scope);
            self.list_calls += 1;
            self.cursors
                .push(cursor.map(|cursor| cursor.provider_value().to_owned()));
            self.pages
                .pop_front()
                .unwrap_or(Err(ProviderFailure::Other))
        }
    }

    fn drive_scope() -> AccountScope {
        AccountScope::new(
            Provider::GoogleDrive,
            "account-A",
            Some("drive-main".into()),
        )
        .unwrap()
    }

    fn drive_file(id: &str, name: &str) -> RemoteItemDraft {
        RemoteItemDraft::new(id, name, RemoteItemKind::File)
            .with_size(Some(SizeObservation::new(
                100,
                SizeAccuracy::ProviderReportedExact,
            )))
            .with_trash_status(TrashStatus::NotTrashed)
    }

    fn page(scope: &AccountScope, items: Vec<RemoteItemDraft>, next: Option<&str>) -> RemotePage {
        RemotePage::new(
            scope.clone(),
            items,
            next.map(|token| PageCursor::new(scope, token).unwrap()),
        )
    }

    #[test]
    fn pages_are_scope_checked_before_and_after_each_call() {
        let scope = drive_scope();
        let first = page(&scope, vec![drive_file("id-1", "one.txt")], Some("p2"));
        let second = page(&scope, vec![drive_file("id-2", "two.txt")], None);
        let mut port = FakePort::new(scope.clone(), vec![Ok(first), Ok(second)]);
        let snapshot = scan(&mut port, &scope, &AtomicBool::new(false));

        assert_eq!(snapshot.status(), SnapshotStatus::Complete);
        assert_eq!(snapshot.items().len(), 2);
        assert_eq!(port.list_calls, 2);
        assert_eq!(port.scope_calls, 4);
        assert_eq!(port.cursors, [None, Some("p2".into())]);
        assert!(
            snapshot
                .items()
                .iter()
                .all(|item| item.id().scan_id() == snapshot.scan_id())
        );
    }

    #[test]
    fn empty_success_is_complete_but_provider_error_is_not_empty_success() {
        let scope = drive_scope();
        let mut empty = FakePort::new(scope.clone(), vec![Ok(page(&scope, vec![], None))]);
        let complete = scan(&mut empty, &scope, &AtomicBool::new(false));
        assert_eq!(complete.status(), SnapshotStatus::Complete);
        assert!(complete.items().is_empty());

        let mut failed = FakePort::new(
            scope.clone(),
            vec![Err(ProviderFailure::AuthenticationRequired)],
        );
        let failed = scan(&mut failed, &scope, &AtomicBool::new(false));
        assert_eq!(failed.status(), SnapshotStatus::Failed);
        assert!(failed.items().is_empty());
        assert!(failed.issues().iter().any(|issue| matches!(
            issue.kind(),
            InventoryIssueKind::ProviderPageFailed(ProviderFailure::AuthenticationRequired)
        )));
    }

    #[test]
    fn provider_failure_after_rows_preserves_them_as_partial() {
        let scope = drive_scope();
        let first = page(&scope, vec![drive_file("id-1", "one.txt")], Some("p2"));
        let mut port = FakePort::new(
            scope.clone(),
            vec![Ok(first), Err(ProviderFailure::RateLimited)],
        );
        let snapshot = scan(&mut port, &scope, &AtomicBool::new(false));
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        assert_eq!(snapshot.items().len(), 1);
        assert!(snapshot.issues().iter().any(|issue| matches!(
            issue.kind(),
            InventoryIssueKind::ProviderPageFailed(ProviderFailure::RateLimited)
        )));
    }

    #[test]
    fn provider_failure_classes_survive_without_raw_error_text() {
        let scope = drive_scope();
        let failures = [
            ProviderFailure::Cancelled,
            ProviderFailure::AccountScopeMismatch,
            ProviderFailure::TimedOut,
            ProviderFailure::ResponseLimit,
            ProviderFailure::ClientUnavailable,
            ProviderFailure::Transport,
        ];
        for failure in failures {
            let mut port = FakePort::new(scope.clone(), vec![Err(failure)]);
            let snapshot = scan(&mut port, &scope, &AtomicBool::new(false));
            assert_eq!(snapshot.status(), SnapshotStatus::Failed);
            assert!(
                snapshot.issues().iter().any(|issue| {
                    issue.kind() == InventoryIssueKind::ProviderPageFailed(failure)
                })
            );
        }
    }

    #[test]
    fn deadline_before_scan_or_after_scope_call_stops_without_listing() {
        let scope = drive_scope();
        let budget = Duration::from_secs(10);

        let elapsed = Rc::new(Cell::new(budget));
        let clock = elapsed.clone();
        let mut port = FakePort::new(scope.clone(), vec![Ok(page(&scope, vec![], None))]);
        let snapshot = scan_with_clock(
            &mut port,
            &scope,
            &AtomicBool::new(false),
            DEFAULT_LIMITS,
            || {},
            move || clock.get(),
            budget,
        );
        assert_eq!(snapshot.status(), SnapshotStatus::Failed);
        assert_eq!(port.scope_calls, 0);
        assert_eq!(port.list_calls, 0);
        assert!(
            snapshot
                .issues()
                .iter()
                .any(|issue| issue.kind() == InventoryIssueKind::ScanDeadlineReached)
        );

        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let clock = elapsed.clone();
        let mut port = DeadlinePort {
            inner: FakePort::new(scope.clone(), vec![Ok(page(&scope, vec![], None))]),
            elapsed,
            budget,
            expire_after_scope_call: Some(1),
            expire_after_list_call: None,
        };
        let snapshot = scan_with_clock(
            &mut port,
            &scope,
            &AtomicBool::new(false),
            DEFAULT_LIMITS,
            || {},
            move || clock.get(),
            budget,
        );
        assert_eq!(snapshot.status(), SnapshotStatus::Failed);
        assert_eq!(port.inner.list_calls, 0);
        assert!(
            snapshot
                .issues()
                .iter()
                .any(|issue| issue.kind() == InventoryIssueKind::ScanDeadlineReached)
        );
    }

    #[test]
    fn deadline_during_row_processing_does_not_retain_late_row() {
        let scope = drive_scope();
        let budget = Duration::from_secs(10);
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let clock = elapsed.clone();
        let set_deadline = elapsed.clone();
        let mut port = FakePort::new(
            scope.clone(),
            vec![Ok(page(&scope, vec![drive_file("late", "late")], None))],
        );
        let snapshot = scan_with_clock(
            &mut port,
            &scope,
            &AtomicBool::new(false),
            DEFAULT_LIMITS,
            move || set_deadline.set(budget),
            move || clock.get(),
            budget,
        );
        assert_eq!(snapshot.status(), SnapshotStatus::Failed);
        assert!(snapshot.items().is_empty());
        assert!(
            snapshot
                .issues()
                .iter()
                .any(|issue| issue.kind() == InventoryIssueKind::ScanDeadlineReached)
        );
    }

    #[test]
    fn late_page_is_discarded_while_predeadline_rows_remain_partial() {
        let scope = drive_scope();
        let budget = Duration::from_secs(10);
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let clock = elapsed.clone();
        let mut port = DeadlinePort {
            inner: FakePort::new(
                scope.clone(),
                vec![
                    Ok(page(&scope, vec![drive_file("early", "early")], Some("p2"))),
                    Ok(page(&scope, vec![drive_file("late", "late")], None)),
                ],
            ),
            elapsed,
            budget,
            expire_after_scope_call: None,
            expire_after_list_call: Some(2),
        };
        let snapshot = scan_with_clock(
            &mut port,
            &scope,
            &AtomicBool::new(false),
            DEFAULT_LIMITS,
            || {},
            move || clock.get(),
            budget,
        );
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        assert_eq!(snapshot.items().len(), 1);
        assert_eq!(snapshot.items()[0].provider_item_id(), "early");
        assert_eq!(port.inner.list_calls, 2);
        assert!(
            snapshot
                .issues()
                .iter()
                .any(|issue| issue.kind() == InventoryIssueKind::ScanDeadlineReached)
        );
    }

    #[test]
    fn account_change_before_or_during_a_page_never_mixes_scopes() {
        let scope = drive_scope();
        let other = AccountScope::new(
            Provider::GoogleDrive,
            "account-B",
            Some("drive-main".into()),
        )
        .unwrap();
        let response = page(&scope, vec![drive_file("id-1", "one.txt")], None);
        let mut before_change = FakePort::new(scope.clone(), vec![Ok(response.clone())])
            .scopes(vec![Ok(other.clone())]);
        let before = scan(&mut before_change, &scope, &AtomicBool::new(false));
        assert_eq!(before.status(), SnapshotStatus::Failed);
        assert!(before.items().is_empty());
        assert_eq!(before_change.list_calls, 0);

        let mut in_flight_change = FakePort::new(scope.clone(), vec![Ok(response)])
            .scopes(vec![Ok(scope.clone()), Ok(other)]);
        let changed = scan(&mut in_flight_change, &scope, &AtomicBool::new(false));
        assert_eq!(changed.status(), SnapshotStatus::Failed);
        assert!(changed.items().is_empty());
        assert!(
            changed
                .issues()
                .iter()
                .any(|issue| { issue.kind() == InventoryIssueKind::AccountScopeChanged })
        );
    }

    #[test]
    fn page_scope_mismatch_and_incomplete_search_are_explicit() {
        let scope = drive_scope();
        let other = AccountScope::new(
            Provider::GoogleDrive,
            "account-B",
            Some("drive-main".into()),
        )
        .unwrap();
        let mut mismatched = FakePort::new(
            scope.clone(),
            vec![Ok(page(
                &other,
                vec![drive_file("id", "wrong scope")],
                None,
            ))],
        );
        let mismatch = scan(&mut mismatched, &scope, &AtomicBool::new(false));
        assert_eq!(mismatch.status(), SnapshotStatus::Failed);
        assert!(mismatch.items().is_empty());
        assert!(
            mismatch
                .issues()
                .iter()
                .any(|issue| { issue.kind() == InventoryIssueKind::PageScopeMismatch })
        );

        let incomplete = page(&scope, vec![drive_file("id", "visible")], None).with_completeness(
            PageCompleteness::Incomplete(IncompletePageReason::ProviderReportedIncompleteSearch),
        );
        let mut port = FakePort::new(scope.clone(), vec![Ok(incomplete)]);
        let snapshot = scan(&mut port, &scope, &AtomicBool::new(false));
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        assert_eq!(snapshot.items().len(), 1);
        assert!(snapshot.issues().iter().any(|issue| matches!(
            issue.kind(),
            InventoryIssueKind::ProviderReportedIncomplete(
                IncompletePageReason::ProviderReportedIncompleteSearch
            )
        )));
    }

    #[test]
    fn repeated_cursor_stops_with_partial_snapshot_and_keeps_valid_page() {
        let scope = drive_scope();
        let first = page(&scope, vec![drive_file("id-1", "one")], Some("cycle"));
        let repeated = page(&scope, vec![drive_file("id-2", "two")], Some("cycle"));
        let mut port = FakePort::new(scope.clone(), vec![Ok(first), Ok(repeated)]);
        let snapshot = scan(&mut port, &scope, &AtomicBool::new(false));
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        assert_eq!(snapshot.items().len(), 2);
        assert_eq!(port.list_calls, 2);
        assert!(
            snapshot
                .issues()
                .iter()
                .any(|issue| { issue.kind() == InventoryIssueKind::PaginationCursorCycle })
        );
    }

    #[test]
    fn duplicate_provider_ids_omit_all_ambiguous_copies() {
        let scope = drive_scope();
        let first = page(&scope, vec![drive_file("same-id", "first")], Some("p2"));
        let second = page(&scope, vec![drive_file("same-id", "second")], None);
        let mut port = FakePort::new(scope.clone(), vec![Ok(first), Ok(second)]);
        let snapshot = scan(&mut port, &scope, &AtomicBool::new(false));
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        assert!(snapshot.items().is_empty());
        assert!(
            snapshot
                .issues()
                .iter()
                .any(|issue| { issue.kind() == InventoryIssueKind::DuplicateProviderItemId })
        );
    }

    #[test]
    fn malformed_rows_are_omitted_and_never_make_an_empty_success() {
        let scope = drive_scope();
        let malformed = RemoteItemDraft::new("", "bad row", RemoteItemKind::File);
        let mut port = FakePort::new(scope.clone(), vec![Ok(page(&scope, vec![malformed], None))]);
        let snapshot = scan(&mut port, &scope, &AtomicBool::new(false));
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        assert!(snapshot.items().is_empty());
        assert!(snapshot.issues().iter().any(|issue| {
            issue.kind() == InventoryIssueKind::MalformedRow(InvalidRowReason::EmptyItemId)
        }));
    }

    #[test]
    fn exact_zero_unknown_and_estimated_sizes_remain_distinct() {
        let gmail = AccountScope::new(Provider::Gmail, "mail-account", None).unwrap();
        let zero = RemoteItemDraft::new("zero", "zero bytes", RemoteItemKind::Mail).with_size(
            Some(SizeObservation::new(0, SizeAccuracy::GmailMessageEstimate)),
        );
        let unknown = RemoteItemDraft::new("unknown", "unknown size", RemoteItemKind::Mail);
        let estimated =
            RemoteItemDraft::new("estimate", "estimated", RemoteItemKind::Mail).with_size(Some(
                SizeObservation::new(4_000_000, SizeAccuracy::GmailMessageEstimate),
            ));
        let mut port = FakePort::new(
            gmail.clone(),
            vec![Ok(page(&gmail, vec![zero, unknown, estimated], None))],
        );
        let snapshot = scan(&mut port, &gmail, &AtomicBool::new(false));
        assert_eq!(snapshot.status(), SnapshotStatus::Complete);
        let known_zero = snapshot
            .items()
            .iter()
            .find(|item| item.provider_item_id() == "zero")
            .unwrap();
        assert_eq!(known_zero.size().unwrap().bytes(), 0);
        assert!(
            snapshot
                .items()
                .iter()
                .find(|item| item.provider_item_id() == "unknown")
                .unwrap()
                .size()
                .is_none()
        );
        let assessment = snapshot.large_item_candidates(1_000_000);
        assert_eq!(assessment.snapshot_status(), SnapshotStatus::Complete);
        assert_eq!(assessment.candidates().len(), 1);
        assert_eq!(
            assessment.candidates()[0].accuracy(),
            SizeAccuracy::GmailMessageEstimate
        );

        let exact = RemoteItemDraft::new("bad-exact", "must not imply exact", RemoteItemKind::Mail)
            .with_size(Some(SizeObservation::new(
                123,
                SizeAccuracy::ProviderReportedExact,
            )));
        let mut bad = FakePort::new(gmail.clone(), vec![Ok(page(&gmail, vec![exact], None))]);
        let bad = scan(&mut bad, &gmail, &AtomicBool::new(false));
        assert_eq!(bad.status(), SnapshotStatus::Partial);
        assert!(bad.issues().iter().any(|issue| {
            issue.kind()
                == InventoryIssueKind::MalformedRow(InvalidRowReason::ExactGmailMessageSize)
        }));

        let drive_zero = drive_file("zero", "zero").with_size(Some(SizeObservation::new(
            0,
            SizeAccuracy::ProviderReportedExact,
        )));
        let mut drive = FakePort::new(
            drive_scope(),
            vec![Ok(page(
                &drive_scope(),
                vec![drive_zero, drive_file("unknown", "unknown").with_size(None)],
                None,
            ))],
        );
        let drive_snapshot = scan(&mut drive, &drive_scope(), &AtomicBool::new(false));
        assert_eq!(drive_snapshot.status(), SnapshotStatus::Complete);
        assert_eq!(drive_snapshot.items()[0].size().unwrap().bytes(), 0);
        assert!(drive_snapshot.items()[1].size().is_none());

        let mislabeled = drive_file("bad-label", "bad label").with_size(Some(
            SizeObservation::new(200, SizeAccuracy::GmailMessageEstimate),
        ));
        let mut bad = FakePort::new(
            drive_scope(),
            vec![Ok(page(&drive_scope(), vec![mislabeled], None))],
        );
        let bad = scan(&mut bad, &drive_scope(), &AtomicBool::new(false));
        assert!(bad.issues().iter().any(|issue| {
            issue.kind()
                == InventoryIssueKind::MalformedRow(InvalidRowReason::SizeAccuracyProviderMismatch)
        }));
    }

    #[test]
    fn duplicate_candidates_require_same_provider_algorithm_kind_and_digest() {
        let scope = drive_scope();
        let sha = |digest: &str| {
            ContentHash::new(Provider::GoogleDrive, HashAlgorithm::Sha256, digest).unwrap()
        };
        let digest_a = "a".repeat(64);
        let digest_b = "b".repeat(64);
        let first = drive_file("one", "one").with_content_hash(Some(sha(&digest_a)));
        let same = drive_file("two", "two").with_content_hash(Some(sha(&digest_a)));
        let same_size_different_hash =
            drive_file("three", "three").with_content_hash(Some(sha(&digest_b)));
        let other_algorithm = drive_file("four", "four").with_content_hash(Some(
            ContentHash::new(
                Provider::GoogleDrive,
                HashAlgorithm::ProviderNative("sha256".into()),
                &digest_a,
            )
            .unwrap(),
        ));
        let folder = RemoteItemDraft::new("folder", "folder", RemoteItemKind::Folder)
            .with_content_hash(Some(sha(&digest_a)));
        let mut port = FakePort::new(
            scope.clone(),
            vec![Ok(page(
                &scope,
                vec![
                    first,
                    same,
                    same_size_different_hash,
                    other_algorithm,
                    folder,
                ],
                None,
            ))],
        );
        let snapshot = scan(&mut port, &scope, &AtomicBool::new(false));
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        let duplicates = snapshot.possible_duplicate_groups();
        assert_eq!(duplicates.groups().len(), 1);
        assert_eq!(duplicates.groups()[0].item_ids().len(), 2);
        assert!(duplicates.groups()[0].equality_is_unverified());
        assert!(
            duplicates.groups()[0]
                .item_ids()
                .iter()
                .all(|id| id.scan_id() == snapshot.scan_id())
        );
    }

    #[test]
    fn contradictory_exact_sizes_are_reported_as_hash_conflicts_not_groups() {
        let scope = drive_scope();
        let hash = || {
            ContentHash::new(Provider::GoogleDrive, HashAlgorithm::Sha256, "A".repeat(64)).unwrap()
        };
        let first = RemoteItemDraft::new("one", "one", RemoteItemKind::File)
            .with_size(Some(SizeObservation::new(
                100,
                SizeAccuracy::ProviderReportedExact,
            )))
            .with_content_hash(Some(hash()));
        let second = RemoteItemDraft::new("two", "two", RemoteItemKind::File)
            .with_size(Some(SizeObservation::new(
                101,
                SizeAccuracy::ProviderReportedExact,
            )))
            .with_content_hash(Some(hash()));
        let mut port = FakePort::new(
            scope.clone(),
            vec![Ok(page(&scope, vec![first, second], None))],
        );
        let snapshot = scan(&mut port, &scope, &AtomicBool::new(false));
        let assessment = snapshot.possible_duplicate_groups();

        assert!(assessment.groups().is_empty());
        assert_eq!(assessment.conflicts().len(), 1);
        assert_eq!(assessment.conflicts()[0].item_ids().len(), 2);
        assert_eq!(
            snapshot.items()[0].content_hash().unwrap().digest(),
            "a".repeat(64)
        );
    }

    #[test]
    fn equal_sizes_never_create_duplicate_groups_and_hash_provider_mismatch_is_rejected() {
        let scope = drive_scope();
        let first = drive_file("one", "one").with_content_hash(Some(
            ContentHash::new(Provider::GoogleDrive, HashAlgorithm::Md5, "a".repeat(32)).unwrap(),
        ));
        let unrelated_hash = drive_file("two", "two").with_content_hash(Some(
            ContentHash::new(Provider::GoogleDrive, HashAlgorithm::Md5, "b".repeat(32)).unwrap(),
        ));
        let mismatched_hash = drive_file("three", "three").with_content_hash(Some(
            ContentHash::new(Provider::Dropbox, HashAlgorithm::Md5, "a".repeat(32)).unwrap(),
        ));
        let rows = vec![first, unrelated_hash, mismatched_hash];
        let mut port = FakePort::new(scope.clone(), vec![Ok(page(&scope, rows, None))]);
        let snapshot = scan(&mut port, &scope, &AtomicBool::new(false));
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        assert!(snapshot.possible_duplicate_groups().groups().is_empty());
        assert_eq!(snapshot.items().len(), 2);
        assert!(snapshot.issues().iter().any(|issue| {
            issue.kind() == InventoryIssueKind::MalformedRow(InvalidRowReason::HashProviderMismatch)
        }));
    }

    #[test]
    fn bounds_preserve_rows_but_mark_the_snapshot_partial() {
        let scope = drive_scope();
        let mut port = FakePort::new(
            scope.clone(),
            vec![Ok(page(
                &scope,
                vec![drive_file("one", "one"), drive_file("two", "two")],
                Some("p2"),
            ))],
        );
        let limits = Limits {
            max_page_items: 4,
            max_pages: 5,
            max_rows_seen: 4,
            max_retained_rows: 1,
            max_retained_bytes: MAX_RETAINED_BYTES,
        };
        let snapshot = scan_with_limits_and_item_hook(
            &mut port,
            &scope,
            &AtomicBool::new(false),
            limits,
            || {},
        );
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        assert_eq!(snapshot.items().len(), 1);
        assert!(
            snapshot
                .issues()
                .iter()
                .any(|issue| { issue.kind() == InventoryIssueKind::RowLimitReached })
        );

        let too_big = RemoteItemDraft::new("x", "x", RemoteItemKind::File)
            .with_provider_revision(Some("r".repeat(MAX_ITEM_BYTES)));
        let mut port = FakePort::new(scope.clone(), vec![Ok(page(&scope, vec![too_big], None))]);
        let snapshot = scan(&mut port, &scope, &AtomicBool::new(false));
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        assert!(snapshot.items().is_empty());
        assert!(snapshot.issues().iter().any(|issue| {
            issue.kind() == InventoryIssueKind::MalformedRow(InvalidRowReason::RevisionTooLong)
        }));

        let scope = drive_scope();
        let mut port = FakePort::new(
            scope.clone(),
            vec![Ok(page(
                &scope,
                vec![drive_file("one", "one"), drive_file("two", "two")],
                None,
            ))],
        );
        let limits = Limits {
            max_page_items: 2,
            max_pages: 5,
            max_rows_seen: 5,
            max_retained_rows: 5,
            max_retained_bytes: 6,
        };
        let snapshot = scan_with_limits_and_item_hook(
            &mut port,
            &scope,
            &AtomicBool::new(false),
            limits,
            || {},
        );
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        assert_eq!(snapshot.items().len(), 1);
        assert!(
            snapshot
                .issues()
                .iter()
                .any(|issue| { issue.kind() == InventoryIssueKind::RetainedByteLimitReached })
        );

        let mut port = FakePort::new(
            scope.clone(),
            vec![Ok(page(&scope, vec![drive_file("one", "one")], Some("p2")))],
        );
        let limits = Limits {
            max_page_items: 2,
            max_pages: 1,
            max_rows_seen: 5,
            max_retained_rows: 5,
            max_retained_bytes: MAX_RETAINED_BYTES,
        };
        let snapshot = scan_with_limits_and_item_hook(
            &mut port,
            &scope,
            &AtomicBool::new(false),
            limits,
            || {},
        );
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        assert_eq!(snapshot.items().len(), 1);
        assert!(
            snapshot
                .issues()
                .iter()
                .any(|issue| issue.kind() == InventoryIssueKind::PageLimitReached)
        );
    }

    #[test]
    fn cancellation_before_provider_calls_and_during_rows_is_explicit() {
        let scope = drive_scope();
        let cancel = AtomicBool::new(true);
        let mut untouched = FakePort::new(scope.clone(), vec![]);
        let before = scan(&mut untouched, &scope, &cancel);
        assert_eq!(before.status(), SnapshotStatus::Cancelled);
        assert_eq!(untouched.scope_calls, 0);
        assert_eq!(untouched.list_calls, 0);

        let mut port = FakePort::new(
            scope.clone(),
            vec![Ok(page(
                &scope,
                vec![drive_file("one", "one"), drive_file("two", "two")],
                None,
            ))],
        );
        let cancel = AtomicBool::new(false);
        let mut item_checks = 0;
        let snapshot =
            scan_with_limits_and_item_hook(&mut port, &scope, &cancel, DEFAULT_LIMITS, || {
                item_checks += 1;
                if item_checks == 2 {
                    cancel.store(true, Ordering::Relaxed);
                }
            });
        assert_eq!(snapshot.status(), SnapshotStatus::Cancelled);
        assert_eq!(snapshot.items().len(), 1);
        assert!(
            snapshot
                .issues()
                .iter()
                .any(|issue| { issue.kind() == InventoryIssueKind::Cancelled })
        );
    }

    #[test]
    fn opaque_scope_cursor_and_hash_do_not_debug_raw_identifiers() {
        let scope = drive_scope();
        let cursor = PageCursor::new(&scope, "secret-page-token").unwrap();
        let hash =
            ContentHash::new(Provider::GoogleDrive, HashAlgorithm::Sha256, "a".repeat(64)).unwrap();
        let debug = format!("{scope:?} {cursor:?} {hash:?}");
        assert!(!debug.contains("account-A"));
        assert!(!debug.contains("drive-main"));
        assert!(!debug.contains("secret-page-token"));
        assert!(!debug.contains(&"a".repeat(64)));
        assert!(cursor.belongs_to(&scope));
        let other = AccountScope::new(
            Provider::GoogleDrive,
            "account-B",
            Some("drive-main".into()),
        )
        .unwrap();
        assert!(!cursor.belongs_to(&other));
    }
}
