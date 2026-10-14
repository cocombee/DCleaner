//! Read-only inventory and reviewed per-item operations for the current user's
//! operating-system recycle bin.
//!
//! Permanent purge is intentionally exposed only as an explicit operation over
//! IDs from a reviewed inventory. It never accepts a filesystem path. Every
//! attempted item receives a durable intent before the native operation, and
//! incomplete effects are reported as uncertain rather than replayed.

use serde::Serialize;
use std::{
    collections::HashSet,
    ffi::OsString,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;

const MAX_INVENTORY_ITEMS: usize = 20_000;
const JOURNAL_FEATURE: &str = "recycle-bin";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryCompletion {
    Complete,
    Partial,
    Cancelled,
    Failed,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RecycleBinSize {
    /// Logical file length reported by the operating system.
    Bytes(u64),
    /// Directory entry count. This is not recursive and is not a byte count.
    Entries(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortErrorKind {
    Denied,
    Unavailable,
    Unsupported,
    Failed,
}

/// A backend error suitable for displaying to the user. Native adapters should
/// avoid including full paths or item names in `message`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortError {
    pub kind: PortErrorKind,
    pub message: String,
}

impl PortError {
    pub fn denied(message: impl Into<String>) -> Self {
        Self {
            kind: PortErrorKind::Denied,
            message: message.into(),
        }
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            kind: PortErrorKind::Unavailable,
            message: message.into(),
        }
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self {
            kind: PortErrorKind::Unsupported,
            message: message.into(),
        }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            kind: PortErrorKind::Failed,
            message: message.into(),
        }
    }
}

/// Stable native locator and immutable shell metadata returned by a backend.
/// The token is opaque to callers and deliberately omitted from `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct PortItem {
    native_token: Vec<u8>,
    name: OsString,
    original_parent: PathBuf,
    deleted_at_unix_seconds: i64,
}

impl PortItem {
    /// Construct an item for a backend implementation. The token must identify
    /// exactly one item in that backend and must not be a filesystem path.
    pub fn new(
        native_token: Vec<u8>,
        name: OsString,
        original_parent: PathBuf,
        deleted_at_unix_seconds: i64,
    ) -> Self {
        Self {
            native_token,
            name,
            original_parent,
            deleted_at_unix_seconds,
        }
    }

    fn same_shell_identity(&self, other: &Self) -> bool {
        self.native_token == other.native_token
            && self.name == other.name
            && self.original_parent == other.original_parent
            && self.deleted_at_unix_seconds == other.deleted_at_unix_seconds
    }
}

impl std::fmt::Debug for PortItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortItem")
            .field("native_token", &"<opaque>")
            .field("name", &self.name)
            .field("original_parent", &self.original_parent)
            .field("deleted_at_unix_seconds", &self.deleted_at_unix_seconds)
            .finish()
    }
}

/// Implement this small port to adapt another operating-system trash API or to
/// provide an isolated fake backend in tests.
pub trait RecycleBinPort {
    fn list(&mut self) -> Result<Vec<PortItem>, PortError>;
    fn metadata(&mut self, item: &PortItem) -> Result<RecycleBinSize, PortError>;
    fn restore_one(&mut self, item: &PortItem) -> Result<(), PortError>;
    fn purge_one(&mut self, item: &PortItem) -> Result<(), PortError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryIssueKind {
    MetadataUnreadable,
    DuplicateNativeIdentity,
    ItemLimitReached,
    BackendUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryIssue {
    pub item_id: Option<Uuid>,
    pub kind: InventoryIssueKind,
    pub message: String,
}

/// A public row exposes only display details and a random, scan-local ID. The
/// native token and captured metadata remain private so selection cannot be
/// retargeted by editing a report row.
#[derive(Clone)]
pub struct RecycleBinItem {
    id: Uuid,
    shell_item: PortItem,
    size: Option<RecycleBinSize>,
}

impl RecycleBinItem {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn name(&self) -> String {
        self.shell_item.name.to_string_lossy().into_owned()
    }

    pub fn original_parent(&self) -> &Path {
        &self.shell_item.original_parent
    }

    pub fn original_path(&self) -> PathBuf {
        self.shell_item.original_parent.join(&self.shell_item.name)
    }

    pub fn deleted_at_unix_seconds(&self) -> i64 {
        self.shell_item.deleted_at_unix_seconds
    }

    pub fn size(&self) -> Option<RecycleBinSize> {
        self.size
    }

    pub fn is_size_readable(&self) -> bool {
        self.size.is_some()
    }
}

#[derive(Clone)]
pub struct RecycleBinInventory {
    pub id: Uuid,
    pub completion: InventoryCompletion,
    pub items: Vec<RecycleBinItem>,
    pub issues: Vec<InventoryIssue>,
    /// Sum of known file lengths. Directory sizes are never treated as bytes.
    pub known_file_bytes: u64,
}

impl RecycleBinInventory {
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    pub fn issue_count(&self) -> usize {
        self.issues.len()
    }
}

/// Inventory the backend's current user's recycle bin. Native list APIs may
/// enumerate their item list in one non-cancellable call; cancellation is
/// honored before that call and while reading per-item metadata afterward.
pub fn inventory(
    port: &mut impl RecycleBinPort,
    cancel: &AtomicBool,
    mut progress: impl FnMut(usize, usize),
) -> RecycleBinInventory {
    let mut report = RecycleBinInventory {
        id: Uuid::new_v4(),
        completion: InventoryCompletion::Complete,
        items: Vec::new(),
        issues: Vec::new(),
        known_file_bytes: 0,
    };
    if cancel.load(Ordering::Relaxed) {
        report.completion = InventoryCompletion::Cancelled;
        progress(0, 0);
        return report;
    }

    let native_items = match port.list() {
        Ok(items) => items,
        Err(error) => {
            report.completion = match error.kind {
                PortErrorKind::Unsupported => InventoryCompletion::Unsupported,
                _ => InventoryCompletion::Failed,
            };
            report.issues.push(InventoryIssue {
                item_id: None,
                kind: InventoryIssueKind::BackendUnavailable,
                message: error.message,
            });
            progress(0, 0);
            return report;
        }
    };

    let total = native_items.len();
    let limit = total.min(MAX_INVENTORY_ITEMS);
    let mut tokens = HashSet::with_capacity(limit);
    let mut partial = total > MAX_INVENTORY_ITEMS;
    if partial {
        report.issues.push(InventoryIssue {
            item_id: None,
            kind: InventoryIssueKind::ItemLimitReached,
            message: format!(
                "The inventory limit of {MAX_INVENTORY_ITEMS} items was reached; remaining entries were not read."
            ),
        });
    }

    for (index, shell_item) in native_items.into_iter().take(limit).enumerate() {
        if cancel.load(Ordering::Relaxed) {
            report.completion = InventoryCompletion::Cancelled;
            break;
        }
        if !tokens.insert(shell_item.native_token.clone()) {
            partial = true;
            report.issues.push(InventoryIssue {
                item_id: None,
                kind: InventoryIssueKind::DuplicateNativeIdentity,
                message: "The operating-system list repeated an item identity; the duplicate was skipped."
                    .into(),
            });
            progress(index + 1, limit);
            continue;
        }

        let id = Uuid::new_v4();
        let size = match port.metadata(&shell_item) {
            Ok(size) => Some(size),
            Err(error) => {
                partial = true;
                report.issues.push(InventoryIssue {
                    item_id: Some(id),
                    kind: InventoryIssueKind::MetadataUnreadable,
                    message: error.message,
                });
                None
            }
        };
        if let Some(RecycleBinSize::Bytes(bytes)) = size {
            report.known_file_bytes = report.known_file_bytes.saturating_add(bytes);
        }
        report.items.push(RecycleBinItem {
            id,
            shell_item,
            size,
        });
        progress(index + 1, limit);
    }

    if report.completion != InventoryCompletion::Cancelled {
        if cancel.load(Ordering::Relaxed) {
            report.completion = InventoryCompletion::Cancelled;
        } else if partial {
            report.completion = InventoryCompletion::Partial;
        }
    }
    report
}

pub struct ReviewedSelection {
    inventory_id: Uuid,
    items: Vec<RecycleBinItem>,
}

impl ReviewedSelection {
    pub fn inventory_id(&self) -> Uuid {
        self.inventory_id
    }

    pub fn ids(&self) -> Vec<Uuid> {
        self.items.iter().map(RecycleBinItem::id).collect()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Bind user-reviewed IDs to immutable snapshots from one inventory. Unknown
/// IDs reject the entire selection; repeated IDs are harmlessly deduplicated.
pub fn reviewed_selection(
    report: &RecycleBinInventory,
    ids: &[Uuid],
) -> Result<ReviewedSelection, String> {
    if ids.is_empty() {
        return Err("Select recycle-bin items from the current inventory.".into());
    }
    let requested: HashSet<_> = ids.iter().copied().collect();
    let known: HashSet<_> = report.items.iter().map(RecycleBinItem::id).collect();
    if let Some(unknown) = requested.difference(&known).next() {
        return Err(format!(
            "Recycle-bin item {unknown} is not in the current inventory. Scan again."
        ));
    }
    let items: Vec<_> = report
        .items
        .iter()
        .filter(|item| requested.contains(&item.id))
        .cloned()
        .collect();
    if items.is_empty() {
        return Err("Select recycle-bin items from the current inventory.".into());
    }
    Ok(ReviewedSelection {
        inventory_id: report.id,
        items,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecycleBinOperation {
    Restore,
    Purge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemOperationState {
    Restored,
    Purged,
    Missing,
    Changed,
    Denied,
    Unknown,
    Failed,
    Uncertain,
    Cancelled,
    NotAttempted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemOperationReceipt {
    pub item_id: Uuid,
    pub state: ItemOperationState,
    pub message: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationCompletion {
    Complete,
    Partial,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecycleBinOperationReport {
    pub id: Uuid,
    pub operation: RecycleBinOperation,
    pub completion: OperationCompletion,
    /// One result per item in the reviewed selection, in inventory order.
    pub receipts: Vec<ItemOperationReceipt>,
}

#[derive(Serialize)]
struct JournalIntent {
    operation: &'static str,
    inventory_id: Uuid,
    item_id: Uuid,
    identity_fingerprint: String,
}

#[derive(Serialize)]
struct JournalReceipt {
    item_id: Uuid,
    outcome: &'static str,
    message: Option<String>,
}

/// Restore only the exact reviewed items. The item is re-listed and its
/// metadata rechecked after the durable intent and immediately before the
/// backend call. A successful native return is verified by a subsequent list.
pub fn restore_selected(
    data_dir: &Path,
    selection: &ReviewedSelection,
    port: &mut impl RecycleBinPort,
    cancel: &AtomicBool,
    progress: impl FnMut(usize, usize),
) -> RecycleBinOperationReport {
    operate_selected(
        data_dir,
        selection,
        port,
        cancel,
        RecycleBinOperation::Restore,
        progress,
    )
}

/// Permanently purge only the exact reviewed items. This is the sole purge
/// entry point and delegates to the operating-system recycle-bin API; it does
/// not accept a filesystem path or call general-purpose filesystem deletion.
pub fn purge_selected(
    data_dir: &Path,
    selection: &ReviewedSelection,
    port: &mut impl RecycleBinPort,
    cancel: &AtomicBool,
    progress: impl FnMut(usize, usize),
) -> RecycleBinOperationReport {
    operate_selected(
        data_dir,
        selection,
        port,
        cancel,
        RecycleBinOperation::Purge,
        progress,
    )
}

fn operate_selected(
    data_dir: &Path,
    selection: &ReviewedSelection,
    port: &mut impl RecycleBinPort,
    cancel: &AtomicBool,
    operation: RecycleBinOperation,
    mut progress: impl FnMut(usize, usize),
) -> RecycleBinOperationReport {
    let report_id = Uuid::new_v4();
    let total = selection.items.len();
    let mut receipts = Vec::with_capacity(total);
    let mut cancelled = false;
    let mut stopped_for_journal = false;

    for (index, selected) in selection.items.iter().enumerate() {
        if stopped_for_journal {
            receipts.push(ItemOperationReceipt {
                item_id: selected.id,
                state: ItemOperationState::NotAttempted,
                message: Some("No effect was attempted because durable intent could not be written for a prior item.".into()),
            });
            progress(index + 1, total);
            continue;
        }
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            receipts.push(ItemOperationReceipt {
                item_id: selected.id,
                state: ItemOperationState::Cancelled,
                message: Some("Cancelled before this item was attempted.".into()),
            });
            progress(index + 1, total);
            continue;
        }

        let effect_id = Uuid::new_v4();
        let intent = JournalIntent {
            operation: match operation {
                RecycleBinOperation::Restore => "restore",
                RecycleBinOperation::Purge => "purge",
            },
            inventory_id: selection.inventory_id,
            item_id: selected.id,
            identity_fingerprint: identity_fingerprint(selected),
        };
        let mut journal = match crate::effects::EffectJournal::create(
            data_dir,
            JOURNAL_FEATURE,
            effect_id,
            &intent,
        ) {
            Ok(journal) => journal,
            Err(error) => {
                receipts.push(ItemOperationReceipt {
                    item_id: selected.id,
                    state: ItemOperationState::Failed,
                    message: Some(format!(
                        "Durable intent could not be written; no effect was attempted: {error}"
                    )),
                });
                stopped_for_journal = true;
                progress(index + 1, total);
                continue;
            }
        };

        let preflight = revalidate_selected(port, selected);
        let state = match preflight {
            Err(failure) => {
                let journal_state = if failure.state == ItemOperationState::Uncertain {
                    "uncertain"
                } else {
                    "failed"
                };
                let receipt = JournalReceipt {
                    item_id: selected.id,
                    outcome: state_label(failure.state),
                    message: failure.message.clone(),
                };
                if let Err(error) = journal.finish(journal_state, &receipt) {
                    ItemOperationReceipt {
                        item_id: selected.id,
                        state: ItemOperationState::Uncertain,
                        message: Some(format!(
                            "{} The no-effect result could not be recorded durably: {error}",
                            failure.message.unwrap_or_default()
                        )),
                    }
                } else {
                    ItemOperationReceipt {
                        item_id: selected.id,
                        state: failure.state,
                        message: failure.message,
                    }
                }
            }
            Ok(current) => {
                if cancel.load(Ordering::Relaxed) {
                    cancelled = true;
                    let receipt = JournalReceipt {
                        item_id: selected.id,
                        outcome: "cancelled",
                        message: Some(
                            "Cancelled after revalidation and before the native operation.".into(),
                        ),
                    };
                    let cancelled_receipt = if let Err(error) = journal.finish("failed", &receipt) {
                        ItemOperationReceipt {
                            item_id: selected.id,
                            state: ItemOperationState::Uncertain,
                            message: Some(format!(
                                "No native effect was attempted, but the cancellation receipt failed: {error}"
                            )),
                        }
                    } else {
                        ItemOperationReceipt {
                            item_id: selected.id,
                            state: ItemOperationState::Cancelled,
                            message: receipt.message,
                        }
                    };
                    receipts.push(cancelled_receipt);
                    progress(index + 1, total);
                    continue;
                }
                let effect_result = match operation {
                    RecycleBinOperation::Restore => port.restore_one(&current),
                    RecycleBinOperation::Purge => port.purge_one(&current),
                };
                let result = verify_effect(port, selected, operation, effect_result);
                let (journal_state, journal_outcome) = match result.state {
                    ItemOperationState::Restored => ("restored", "restored"),
                    ItemOperationState::Purged => ("applied", "purged"),
                    ItemOperationState::Uncertain => ("uncertain", "uncertain"),
                    _ => ("failed", state_label(result.state)),
                };
                let journal_receipt = JournalReceipt {
                    item_id: selected.id,
                    outcome: journal_outcome,
                    message: result.message.clone(),
                };
                if let Err(error) = journal.finish(journal_state, &journal_receipt) {
                    ItemOperationReceipt {
                        item_id: selected.id,
                        state: ItemOperationState::Uncertain,
                        message: Some(format!(
                            "The native operation was attempted, but its durable receipt failed: {error}"
                        )),
                    }
                } else {
                    result
                }
            }
        };
        receipts.push(state);
        progress(index + 1, total);
    }

    let completion = if cancelled {
        OperationCompletion::Cancelled
    } else if receipts.iter().all(|receipt| {
        matches!(
            receipt.state,
            ItemOperationState::Restored | ItemOperationState::Purged
        )
    }) {
        OperationCompletion::Complete
    } else {
        OperationCompletion::Partial
    };
    RecycleBinOperationReport {
        id: report_id,
        operation,
        completion,
        receipts,
    }
}

struct PreflightFailure {
    state: ItemOperationState,
    message: Option<String>,
}

fn revalidate_selected(
    port: &mut impl RecycleBinPort,
    selected: &RecycleBinItem,
) -> Result<PortItem, PreflightFailure> {
    let current_items = port.list().map_err(|error| PreflightFailure {
        state: error_state(&error, false),
        message: Some(error.message),
    })?;
    let current = find_identity(&current_items, &selected.shell_item)?;
    let current_size = port.metadata(current).map_err(|error| PreflightFailure {
        state: error_state(&error, false),
        message: Some(error.message),
    })?;
    if Some(current_size) != selected.size {
        return Err(PreflightFailure {
            state: ItemOperationState::Changed,
            message: Some("The item size or type changed since inventory. Scan again.".into()),
        });
    }
    Ok(current.clone())
}

fn verify_effect(
    port: &mut impl RecycleBinPort,
    selected: &RecycleBinItem,
    operation: RecycleBinOperation,
    effect_result: Result<(), PortError>,
) -> ItemOperationReceipt {
    let after = match port.list() {
        Ok(items) => items,
        Err(error) => {
            let detail = match effect_result {
                Ok(()) => "The native operation returned success, but post-operation verification was unavailable.".to_string(),
                Err(effect_error) => format!(
                    "The native operation returned an error and post-operation verification was unavailable: {}",
                    effect_error.message
                ),
            };
            let _ = error;
            return ItemOperationReceipt {
                item_id: selected.id,
                state: ItemOperationState::Uncertain,
                message: Some(detail),
            };
        }
    };
    let matching: Vec<_> = after
        .iter()
        .filter(|item| item.native_token == selected.shell_item.native_token)
        .collect();
    let remains = !matching.is_empty();
    match effect_result {
        Ok(()) if !remains => ItemOperationReceipt {
            item_id: selected.id,
            state: match operation {
                RecycleBinOperation::Restore => ItemOperationState::Restored,
                RecycleBinOperation::Purge => ItemOperationState::Purged,
            },
            message: None,
        },
        Ok(()) => ItemOperationReceipt {
            item_id: selected.id,
            state: ItemOperationState::Uncertain,
            message: Some("The native operation returned success, but this item is still listed in the recycle bin.".into()),
        },
        Err(error) if remains => {
            let current = matching[0];
            let changed = matching.len() != 1
                || !current.same_shell_identity(&selected.shell_item)
                || match port.metadata(current) {
                    Ok(size) => Some(size) != selected.size,
                    Err(read_error) => {
                        if read_error.kind == PortErrorKind::Denied {
                            return ItemOperationReceipt {
                                item_id: selected.id,
                                state: ItemOperationState::Denied,
                                message: Some(read_error.message),
                            };
                        }
                        if read_error.kind != PortErrorKind::Unavailable {
                            return ItemOperationReceipt {
                                item_id: selected.id,
                                state: ItemOperationState::Unknown,
                                message: Some(read_error.message),
                            };
                        }
                        false
                    }
                };
            ItemOperationReceipt {
                item_id: selected.id,
                state: if changed {
                    ItemOperationState::Changed
                } else if error.kind == PortErrorKind::Denied {
                    ItemOperationState::Denied
                } else {
                    ItemOperationState::Failed
                },
                message: Some(error.message),
            }
        }
        Err(error) => ItemOperationReceipt {
            item_id: selected.id,
            state: ItemOperationState::Uncertain,
            message: Some(format!(
                "The native operation returned an error, but the item is no longer listed: {}",
                error.message
            )),
        },
    }
}

fn find_identity<'a>(
    items: &'a [PortItem],
    expected: &PortItem,
) -> Result<&'a PortItem, PreflightFailure> {
    let mut matching = items
        .iter()
        .filter(|item| item.native_token == expected.native_token);
    let Some(current) = matching.next() else {
        return Err(PreflightFailure {
            state: ItemOperationState::Missing,
            message: Some("The selected item is no longer in the recycle bin.".into()),
        });
    };
    if matching.next().is_some() {
        return Err(PreflightFailure {
            state: ItemOperationState::Unknown,
            message: Some(
                "The backend returned an ambiguous native item identity; no effect was attempted."
                    .into(),
            ),
        });
    }
    if !current.same_shell_identity(expected) {
        return Err(PreflightFailure {
            state: ItemOperationState::Changed,
            message: Some("The selected item's name, original location, or deletion time changed since inventory.".into()),
        });
    }
    Ok(current)
}

fn error_state(error: &PortError, after_effect: bool) -> ItemOperationState {
    if after_effect {
        return ItemOperationState::Uncertain;
    }
    match error.kind {
        PortErrorKind::Denied => ItemOperationState::Denied,
        PortErrorKind::Unavailable | PortErrorKind::Unsupported | PortErrorKind::Failed => {
            ItemOperationState::Unknown
        }
    }
}

fn state_label(state: ItemOperationState) -> &'static str {
    match state {
        ItemOperationState::Restored => "restored",
        ItemOperationState::Purged => "purged",
        ItemOperationState::Missing => "missing",
        ItemOperationState::Changed => "changed",
        ItemOperationState::Denied => "denied",
        ItemOperationState::Unknown => "unknown",
        ItemOperationState::Failed => "failed",
        ItemOperationState::Uncertain => "uncertain",
        ItemOperationState::Cancelled => "cancelled",
        ItemOperationState::NotAttempted => "not_attempted",
    }
}

fn identity_fingerprint(item: &RecycleBinItem) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    item.shell_item.native_token.hash(&mut hasher);
    item.shell_item.name.hash(&mut hasher);
    item.shell_item.original_parent.hash(&mut hasher);
    item.shell_item.deleted_at_unix_seconds.hash(&mut hasher);
    item.size.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Native backend using the OS-limited functions from `trash` 5.2.9. On
/// Windows this enumerates the current user's shell Recycle Bin. macOS is
/// deliberately reported unsupported rather than exposing an unreviewed path
/// based implementation.
pub struct SystemRecycleBin;

impl SystemRecycleBin {
    pub fn new() -> Self {
        Self
    }

    fn find_native(&mut self, expected: &PortItem) -> Result<trash::TrashItem, PortError> {
        let items = native_list()?;
        let current_port_items: Vec<_> = items.iter().map(port_item_from_native).collect();
        let current = find_identity(&current_port_items, expected).map_err(|failure| {
            PortError::unavailable(
                failure
                    .message
                    .unwrap_or_else(|| "The selected recycle-bin item is unavailable.".into()),
            )
        })?;
        items
            .into_iter()
            .find(|item| os_string_token(&item.id) == current.native_token)
            .ok_or_else(|| PortError::unavailable("The selected recycle-bin item disappeared."))
    }
}

impl Default for SystemRecycleBin {
    fn default() -> Self {
        Self::new()
    }
}

impl RecycleBinPort for SystemRecycleBin {
    fn list(&mut self) -> Result<Vec<PortItem>, PortError> {
        native_list().map(|items| items.iter().map(port_item_from_native).collect())
    }

    fn metadata(&mut self, item: &PortItem) -> Result<RecycleBinSize, PortError> {
        let native = self.find_native(item)?;
        native_metadata(&native)
    }

    fn restore_one(&mut self, item: &PortItem) -> Result<(), PortError> {
        let native = self.find_native(item)?;
        native_restore_one(native)
    }

    fn purge_one(&mut self, item: &PortItem) -> Result<(), PortError> {
        let native = self.find_native(item)?;
        native_purge_one(native)
    }
}

#[cfg(any(
    target_os = "windows",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android")
    )
))]
fn native_list() -> Result<Vec<trash::TrashItem>, PortError> {
    trash::os_limited::list().map_err(map_trash_error)
}

#[cfg(not(any(
    target_os = "windows",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android")
    )
)))]
fn native_list() -> Result<Vec<trash::TrashItem>, PortError> {
    Err(PortError::unsupported(
        "This operating system does not expose a supported current-user recycle-bin inventory.",
    ))
}

#[cfg(any(
    target_os = "windows",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android")
    )
))]
fn native_metadata(item: &trash::TrashItem) -> Result<RecycleBinSize, PortError> {
    trash::os_limited::metadata(item)
        .map(|metadata| match metadata.size {
            trash::TrashItemSize::Bytes(bytes) => RecycleBinSize::Bytes(bytes),
            trash::TrashItemSize::Entries(entries) => RecycleBinSize::Entries(entries),
        })
        .map_err(map_trash_error)
}

#[cfg(not(any(
    target_os = "windows",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android")
    )
)))]
fn native_metadata(_item: &trash::TrashItem) -> Result<RecycleBinSize, PortError> {
    Err(PortError::unsupported(
        "This operating system does not expose recycle-bin item metadata.",
    ))
}

#[cfg(any(
    target_os = "windows",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android")
    )
))]
fn native_restore_one(item: trash::TrashItem) -> Result<(), PortError> {
    trash::os_limited::restore_all(std::iter::once(item)).map_err(map_trash_error)
}

#[cfg(not(any(
    target_os = "windows",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android")
    )
)))]
fn native_restore_one(_item: trash::TrashItem) -> Result<(), PortError> {
    Err(PortError::unsupported(
        "This operating system does not support reviewed recycle-bin restore.",
    ))
}

#[cfg(any(
    target_os = "windows",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android")
    )
))]
fn native_purge_one(item: trash::TrashItem) -> Result<(), PortError> {
    trash::os_limited::purge_all(std::iter::once(item)).map_err(map_trash_error)
}

#[cfg(not(any(
    target_os = "windows",
    all(
        unix,
        not(target_os = "macos"),
        not(target_os = "ios"),
        not(target_os = "android")
    )
)))]
fn native_purge_one(_item: trash::TrashItem) -> Result<(), PortError> {
    Err(PortError::unsupported(
        "This operating system does not support reviewed recycle-bin purge.",
    ))
}

fn port_item_from_native(item: &trash::TrashItem) -> PortItem {
    PortItem::new(
        os_string_token(&item.id),
        item.name.clone(),
        item.original_parent.clone(),
        item.time_deleted,
    )
}

#[cfg(windows)]
fn os_string_token(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().flat_map(u16::to_le_bytes).collect()
}

#[cfg(unix)]
fn os_string_token(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

#[cfg(not(any(windows, unix)))]
fn os_string_token(value: &std::ffi::OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

fn map_trash_error(error: trash::Error) -> PortError {
    match error {
        trash::Error::Os { code, .. } if is_access_denied_code(code) => {
            PortError::denied("The operating system denied access to this recycle-bin item.")
        }
        trash::Error::RestoreCollision { .. } => {
            PortError::failed("The original location already contains an item with this name.")
        }
        trash::Error::CouldNotAccess { .. } => {
            PortError::unavailable("The operating system could not access this recycle-bin item.")
        }
        trash::Error::TargetedRoot => PortError::failed(
            "The operating system rejected an unexpected root item in the recycle bin.",
        ),
        _ => PortError::failed("The operating-system recycle-bin operation failed."),
    }
}

fn is_access_denied_code(code: i32) -> bool {
    // ERROR_ACCESS_DENIED and HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED).
    code == 5 || code == -2_147_024_891
}
