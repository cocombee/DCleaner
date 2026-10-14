//! Native Windows Startup Manager inventories and reversible, journal-friendly changes.
//!
//! The UI should persist [`ChangeIntent`] before calling [`StartupManager::apply_intent`]
//! and persist the returned [`ChangeReceipt`] afterwards. If the process stops between
//! those steps, [`StartupManager::restore_intent`] can restore only when the selected
//! item still matches the exact before/after snapshot in the durable intent.

use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

pub const MAX_ITEMS_PER_SOURCE: usize = 4_096;
pub const CHANGE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupSection {
    StartupApps,
    ScheduledTasks,
    ContextMenu,
    WindowsServices,
}

impl StartupSection {
    pub const ALL: [Self; 4] = [
        Self::StartupApps,
        Self::ScheduledTasks,
        Self::ContextMenu,
        Self::WindowsServices,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::StartupApps => "Startup apps",
            Self::ScheduledTasks => "Scheduled tasks",
            Self::ContextMenu => "Context menu",
            Self::WindowsServices => "Windows services",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum FieldValue<T> {
    Known { value: T },
    Unknown { reason: String },
    NotApplicable,
}

impl<T> FieldValue<T> {
    fn known(value: T) -> Self {
        Self::Known { value }
    }

    fn unknown(reason: impl Into<String>) -> Self {
        Self::Unknown {
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum EnabledState {
    Enabled,
    Disabled,
    Unknown { reason: String },
}

impl EnabledState {
    fn from_bool(enabled: bool) -> Self {
        if enabled {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Enabled => Some(true),
            Self::Disabled => Some(false),
            Self::Unknown { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum SourceState {
    Read { items: usize },
    NotPresent,
    Inaccessible { reason: String },
    Failed { reason: String },
    Truncated { limit: usize, reason: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceOutcome {
    /// A human-readable native source, such as a registry key or folder.
    pub source: String,
    pub state: SourceState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryQuality {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StartupInventory {
    pub section: StartupSection,
    pub quality: InventoryQuality,
    pub entries: Vec<StartupEntry>,
    /// Every source is represented, including absent and inaccessible locations.
    pub sources: Vec<SourceOutcome>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StartupEntry {
    /// Stable digest of the exact native identity. It contains no program path.
    pub id: StartupId,
    pub section: StartupSection,
    pub program: FieldValue<String>,
    pub publisher: FieldValue<String>,
    pub version: FieldValue<String>,
    pub file_path: FieldValue<String>,
    pub command: FieldValue<String>,
    pub enabled: EnabledState,
    pub identity: EntryIdentity,
    pub can_change_enabled: bool,
    pub change_limitation: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StartupId(pub String);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryHive {
    CurrentUser,
    LocalMachine,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct StartupFileMetadata {
    file_description: Option<String>,
    product_name: Option<String>,
    company_name: Option<String>,
    file_version: Option<String>,
}

fn startup_program_label(
    link_description: Option<&str>,
    metadata: Option<&StartupFileMetadata>,
    fallback_name: &str,
) -> String {
    [
        link_description,
        metadata.and_then(|metadata| metadata.file_description.as_deref()),
        metadata.and_then(|metadata| metadata.product_name.as_deref()),
        Some(fallback_name),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .find(|value| !value.is_empty())
    .unwrap_or(fallback_name)
    .to_owned()
}

fn startup_metadata_field(value: Option<&str>, missing_reason: &'static str) -> FieldValue<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| FieldValue::known(value.to_owned()))
        .unwrap_or_else(|| FieldValue::unknown(missing_reason))
}

fn normalize_windows_path_for_comparison(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_owned()
}

fn is_reserved_startup_folder_metadata(name: &str) -> bool {
    name.eq_ignore_ascii_case("desktop.ini") || name.eq_ignore_ascii_case("thumbs.db")
}

type StartupFolderMarkerCounts = std::collections::HashMap<(RegistryHive, String), usize>;

fn startup_folder_marker_name_is_ambiguous(
    counts: &StartupFolderMarkerCounts,
    hive: RegistryHive,
    name: &str,
) -> bool {
    counts
        .get(&(hive, name.to_lowercase()))
        .is_some_and(|count| *count > 1)
}

fn startup_folder_approval_hive_for_roots(
    item_path: &Path,
    user_root: Option<&Path>,
    common_root: Option<&Path>,
) -> Option<RegistryHive> {
    let item = normalize_windows_path_for_comparison(item_path);
    let parent = item.rsplit_once('\\')?.0;
    startup_folder_root_hive_for_roots(Path::new(parent), user_root, common_root)
}

fn startup_folder_root_hive_for_roots(
    folder_root: &Path,
    user_root: Option<&Path>,
    common_root: Option<&Path>,
) -> Option<RegistryHive> {
    let folder_root = normalize_windows_path_for_comparison(folder_root);
    let user_match = user_root.is_some_and(|root| {
        normalize_windows_path_for_comparison(root).eq_ignore_ascii_case(&folder_root)
    });
    let common_match = common_root.is_some_and(|root| {
        normalize_windows_path_for_comparison(root).eq_ignore_ascii_case(&folder_root)
    });
    match (user_match, common_match) {
        (true, false) => Some(RegistryHive::CurrentUser),
        (false, true) => Some(RegistryHive::LocalMachine),
        // Missing, out-of-scope, or overlapping roots cannot select an approval hive safely.
        _ => None,
    }
}

#[cfg(test)]
mod startup_folder_scope_tests {
    use super::{
        RegistryHive, StartupFileMetadata, StartupFolderMarkerCounts,
        is_reserved_startup_folder_metadata, startup_folder_approval_hive_for_roots,
        startup_folder_marker_name_is_ambiguous, startup_folder_root_hive_for_roots,
        startup_metadata_field, startup_program_label,
    };
    use std::path::Path;

    #[test]
    fn approval_hive_follows_exact_user_or_common_startup_root() {
        let user = Path::new(
            r"C:\Users\Example\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        );
        let common = Path::new(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup");

        assert_eq!(
            startup_folder_approval_hive_for_roots(
                Path::new(
                    r"c:/programdata/Microsoft/Windows/Start Menu/Programs/Startup/Audient.lnk"
                ),
                Some(user),
                Some(common),
            ),
            Some(RegistryHive::LocalMachine),
        );
        assert_eq!(
            startup_folder_approval_hive_for_roots(
                Path::new(
                    r"C:\Users\Example\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Example.lnk"
                ),
                Some(user),
                Some(common),
            ),
            Some(RegistryHive::CurrentUser),
        );
        assert_eq!(
            startup_folder_approval_hive_for_roots(
                Path::new(r"C:\Other\Startup\Unrelated.lnk"),
                Some(user),
                Some(common),
            ),
            None,
        );
    }

    #[test]
    fn overlapping_startup_roots_fail_closed() {
        let root = Path::new(r"C:\ProgramData\Startup");
        assert_eq!(
            startup_folder_root_hive_for_roots(root, Some(root), Some(root),),
            None,
        );
    }

    #[test]
    fn inventory_root_selection_maps_exact_user_and_common_folders() {
        let user = Path::new(
            r"C:\Users\Example\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        );
        let common = Path::new(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup");

        assert_eq!(
            startup_folder_root_hive_for_roots(
                Path::new(r"c:/programdata/Microsoft/Windows/Start Menu/Programs/Startup"),
                Some(user),
                Some(common)
            ),
            Some(RegistryHive::LocalMachine),
        );
        assert_eq!(
            startup_folder_root_hive_for_roots(user, Some(user), Some(common)),
            Some(RegistryHive::CurrentUser),
        );
        assert_eq!(
            startup_folder_root_hive_for_roots(
                Path::new(r"C:\Other\Startup"),
                Some(user),
                Some(common)
            ),
            None,
        );
    }

    #[test]
    fn desktop_metadata_is_excluded_from_startup_fixture_names() {
        let fixture_names = [
            "desktop.ini",
            "Thumbs.db",
            "AudientAppLauncher Autostart.lnk",
        ];
        let startup_items = fixture_names
            .into_iter()
            .filter(|name| !is_reserved_startup_folder_metadata(name))
            .collect::<Vec<_>>();

        assert_eq!(startup_items, ["AudientAppLauncher Autostart.lnk"]);
    }

    #[test]
    fn startup_marker_collisions_are_scoped_to_the_approval_hive() {
        let mut counts = StartupFolderMarkerCounts::default();
        counts.insert((RegistryHive::CurrentUser, "shared.lnk".into()), 1);
        counts.insert((RegistryHive::LocalMachine, "shared.lnk".into()), 1);
        assert!(!startup_folder_marker_name_is_ambiguous(
            &counts,
            RegistryHive::CurrentUser,
            "shared.lnk",
        ));
        assert!(!startup_folder_marker_name_is_ambiguous(
            &counts,
            RegistryHive::LocalMachine,
            "shared.lnk",
        ));

        counts.insert((RegistryHive::LocalMachine, "shared.lnk".into()), 2);
        assert!(startup_folder_marker_name_is_ambiguous(
            &counts,
            RegistryHive::LocalMachine,
            "SHARED.LNK",
        ));
        assert_eq!(
            counts.get(&(RegistryHive::CurrentUser, "shared.lnk".into())),
            Some(&1)
        );
    }

    #[test]
    fn startup_program_and_publisher_use_file_version_fixture_with_unknown_fallbacks() {
        let metadata = StartupFileMetadata {
            file_description: Some("Device Background Service".into()),
            product_name: Some("Device Utility".into()),
            company_name: Some("Example Audio".into()),
            file_version: Some("2.4.1".into()),
        };
        assert_eq!(
            startup_program_label(None, Some(&metadata), "Device.lnk"),
            "Device Background Service",
        );
        assert_eq!(
            startup_program_label(Some("Friendly shortcut"), Some(&metadata), "Device.lnk"),
            "Friendly shortcut",
        );
        assert_eq!(
            startup_metadata_field(metadata.company_name.as_deref(), "missing company"),
            super::FieldValue::Known {
                value: "Example Audio".into(),
            },
        );
        assert_eq!(
            startup_metadata_field(None, "company version resource unavailable"),
            super::FieldValue::Unknown {
                reason: "company version resource unavailable".into(),
            },
        );
        assert_eq!(
            startup_metadata_field(metadata.file_version.as_deref(), "missing version"),
            super::FieldValue::Known {
                value: "2.4.1".into(),
            },
        );
    }
}

/// Native identity required to find and revalidate one selected entry.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EntryIdentity {
    StartupRunValue {
        hive: RegistryHive,
        key: String,
        value_name: String,
        approval_hive: RegistryHive,
        approval_key: String,
    },
    StartupFolderItem {
        path: String,
    },
    ContextMenuRegistration {
        hive: RegistryHive,
        key: String,
        registration: String,
    },
    ScheduledTask {
        path: String,
    },
    WindowsService {
        name: String,
    },
}

impl EntryIdentity {
    fn section(&self) -> StartupSection {
        match self {
            Self::StartupRunValue { .. } | Self::StartupFolderItem { .. } => {
                StartupSection::StartupApps
            }
            Self::ContextMenuRegistration { .. } => StartupSection::ContextMenu,
            Self::ScheduledTask { .. } => StartupSection::ScheduledTasks,
            Self::WindowsService { .. } => StartupSection::WindowsServices,
        }
    }

    fn canonical_key(&self) -> String {
        match self {
            Self::StartupRunValue {
                hive,
                key,
                value_name,
                approval_hive,
                approval_key,
            } => format!(
                "run|{}|{}|{}|{}|{}",
                hive_tag(*hive),
                key.to_lowercase(),
                value_name.to_lowercase(),
                hive_tag(*approval_hive),
                approval_key.to_lowercase()
            ),
            Self::StartupFolderItem { path } => {
                format!("folder|{}", path.to_lowercase())
            }
            Self::ContextMenuRegistration {
                hive,
                key,
                registration,
            } => format!(
                "context|{}|{}|{}",
                hive_tag(*hive),
                key.to_lowercase(),
                registration.to_lowercase()
            ),
            Self::ScheduledTask { path } => format!("task|{}", path.to_lowercase()),
            Self::WindowsService { name } => format!("service|{}", name.to_lowercase()),
        }
    }
}

fn hive_tag(hive: RegistryHive) -> &'static str {
    match hive {
        RegistryHive::CurrentUser => "hkcu",
        RegistryHive::LocalMachine => "hklm",
    }
}

impl StartupId {
    pub fn for_identity(identity: &EntryIdentity) -> Self {
        // Two independent FNV-1a streams make a compact deterministic 128-bit opaque ID.
        // The full identity is still revalidated before any write; the digest is a lookup
        // handle, never authorization by itself.
        let key = identity.canonical_key();
        let mut low = 0xcbf29ce484222325u64;
        let mut high = 0x84222325cbf29ce4u64;
        for byte in key.as_bytes() {
            low ^= u64::from(*byte);
            low = low.wrapping_mul(0x100000001b3);
            high ^= u64::from(*byte).wrapping_add(0x9d);
            high = high.wrapping_mul(0x100000001b3);
        }
        let category = match identity.section() {
            StartupSection::StartupApps => "sa",
            StartupSection::ScheduledTasks => "st",
            StartupSection::ContextMenu => "cm",
            StartupSection::WindowsServices => "sv",
        };
        Self(format!("st-{category}-{:016x}{:016x}", high, low))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryValueSnapshot {
    pub value_type: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StartupFolderFileSnapshot {
    pub volume_serial: u32,
    pub file_index: u64,
    pub file_size: u64,
    pub last_write_time: u64,
    pub attributes: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StartupFolderSnapshot {
    pub approval: Option<RegistryValueSnapshot>,
    pub file: StartupFolderFileSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextMenuVerbSnapshot {
    pub legacy_disable: Option<RegistryValueSnapshot>,
    pub command: RegistryValueSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceConfigSnapshot {
    pub service_type: u32,
    pub start_type: u32,
    pub error_control: u32,
    pub binary_path: String,
    pub load_order_group: String,
    pub dependencies: Vec<String>,
    pub service_start_name: String,
    pub display_name: String,
}

/// Exact before/after fields needed for compare-and-set and safe restoration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum NativeState {
    StartupRunValue {
        value: RegistryValueSnapshot,
        approval: Option<RegistryValueSnapshot>,
    },
    StartupFolderItem {
        snapshot: StartupFolderSnapshot,
    },
    ContextMenuVerb {
        snapshot: ContextMenuVerbSnapshot,
    },
    ScheduledTask {
        /// Task XML is needed to revalidate a selected task. Oversized XML makes the
        /// task visible but intentionally not changeable.
        xml: Option<String>,
    },
    WindowsService {
        config: ServiceConfigSnapshot,
    },
    ReadOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedState {
    pub id: StartupId,
    pub identity: EntryIdentity,
    pub enabled: EnabledState,
    pub native: NativeState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChangeIntent {
    pub schema_version: u32,
    pub intent_id: Uuid,
    pub id: StartupId,
    pub target_enabled: bool,
    pub before: ObservedState,
    pub expected_after: ObservedState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChangeReceipt {
    pub schema_version: u32,
    pub intent_id: Uuid,
    pub id: StartupId,
    pub before: ObservedState,
    pub after: ObservedState,
    pub outcome: ChangeOutcome,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOutcome {
    Applied,
    AlreadyApplied,
    Restored,
    AlreadyRestored,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum StartupErrorKind {
    UnknownId,
    Unsupported,
    ChangedSinceReview,
    Inaccessible,
    NativeFailure,
    InvalidIntent,
    VerificationFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StartupError {
    pub kind: StartupErrorKind,
    pub message: String,
}

impl StartupError {
    pub fn new(kind: StartupErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// OS adapter. `compare_and_set` must re-read and compare the exact expected state
/// at the native handle it mutates; the manager also verifies the resulting state.
pub trait StartupPlatform {
    fn inventory(&mut self, section: StartupSection) -> StartupInventory;
    fn observe(&mut self, id: &StartupId) -> Result<ObservedState, StartupError>;
    fn compare_and_set(
        &mut self,
        id: &StartupId,
        expected: &ObservedState,
        desired: &ObservedState,
    ) -> Result<(), StartupError>;
}

pub struct StartupManager<P> {
    platform: P,
}

impl<P: StartupPlatform> StartupManager<P> {
    pub fn new(platform: P) -> Self {
        Self { platform }
    }

    pub fn inventory(&mut self, section: StartupSection) -> StartupInventory {
        self.platform.inventory(section)
    }

    pub fn platform(&self) -> &P {
        &self.platform
    }

    pub fn platform_mut(&mut self) -> &mut P {
        &mut self.platform
    }

    pub fn into_platform(self) -> P {
        self.platform
    }

    pub fn prepare_change(
        &mut self,
        id: &StartupId,
        target_enabled: bool,
    ) -> Result<ChangeIntent, StartupError> {
        let before = self.platform.observe(id)?;
        if before.id != *id || StartupId::for_identity(&before.identity) != *id {
            return Err(StartupError::new(
                StartupErrorKind::ChangedSinceReview,
                "Native identity does not match the selected startup item.",
            ));
        }
        if before.enabled.as_bool() == Some(target_enabled) {
            return Err(StartupError::new(
                StartupErrorKind::ChangedSinceReview,
                "The selected item is already in the requested state.",
            ));
        }
        let expected_after = expected_state(&before, target_enabled)?;
        Ok(ChangeIntent {
            schema_version: CHANGE_SCHEMA_VERSION,
            intent_id: Uuid::new_v4(),
            id: id.clone(),
            target_enabled,
            before,
            expected_after,
        })
    }

    /// Call only after the caller has durably saved `intent`.
    pub fn apply_intent(&mut self, intent: &ChangeIntent) -> Result<ChangeReceipt, StartupError> {
        validate_intent(intent)?;
        let current = self.platform.observe(&intent.id)?;
        if current == intent.expected_after {
            return Ok(receipt_from_intent(
                intent,
                current,
                ChangeOutcome::AlreadyApplied,
            ));
        }
        if current != intent.before {
            return Err(StartupError::new(
                StartupErrorKind::ChangedSinceReview,
                "The startup item changed after review; no change was made.",
            ));
        }
        self.platform
            .compare_and_set(&intent.id, &intent.before, &intent.expected_after)?;
        let after = self.platform.observe(&intent.id)?;
        if after != intent.expected_after {
            return Err(StartupError::new(
                StartupErrorKind::VerificationFailed,
                "The native API returned, but the requested startup state could not be verified. The saved intent is required for recovery review.",
            ));
        }
        Ok(receipt_from_intent(intent, after, ChangeOutcome::Applied))
    }

    /// Restore from a receipt after normal completion. The exact post-change snapshot
    /// prevents overwriting a later external change.
    pub fn restore_receipt(
        &mut self,
        receipt: &ChangeReceipt,
    ) -> Result<ChangeReceipt, StartupError> {
        validate_receipt(receipt)?;
        self.restore_exact(
            receipt.intent_id,
            &receipt.id,
            &receipt.before,
            &receipt.after,
        )
    }

    /// Best-effort recovery when only the durable pre-change intent survived. The
    /// native item must still match the planned after snapshot exactly.
    pub fn restore_intent(&mut self, intent: &ChangeIntent) -> Result<ChangeReceipt, StartupError> {
        validate_intent(intent)?;
        self.restore_exact(
            intent.intent_id,
            &intent.id,
            &intent.before,
            &intent.expected_after,
        )
    }

    fn restore_exact(
        &mut self,
        intent_id: Uuid,
        id: &StartupId,
        before: &ObservedState,
        after: &ObservedState,
    ) -> Result<ChangeReceipt, StartupError> {
        let current = self.platform.observe(id)?;
        if current == *before {
            return Ok(ChangeReceipt {
                schema_version: CHANGE_SCHEMA_VERSION,
                intent_id,
                id: id.clone(),
                before: before.clone(),
                after: current,
                outcome: ChangeOutcome::AlreadyRestored,
            });
        }
        if current != *after {
            return Err(StartupError::new(
                StartupErrorKind::ChangedSinceReview,
                "The startup item no longer matches the saved change; restoration was refused.",
            ));
        }
        self.platform.compare_and_set(id, after, before)?;
        let restored = self.platform.observe(id)?;
        if restored != *before {
            return Err(StartupError::new(
                StartupErrorKind::VerificationFailed,
                "The prior startup state could not be verified after restoration.",
            ));
        }
        Ok(ChangeReceipt {
            schema_version: CHANGE_SCHEMA_VERSION,
            intent_id,
            id: id.clone(),
            before: before.clone(),
            after: restored,
            outcome: ChangeOutcome::Restored,
        })
    }
}

fn validate_intent(intent: &ChangeIntent) -> Result<(), StartupError> {
    if intent.schema_version != CHANGE_SCHEMA_VERSION
        || intent.id != intent.before.id
        || intent.id != intent.expected_after.id
        || intent.before.identity != intent.expected_after.identity
        || StartupId::for_identity(&intent.before.identity) != intent.id
        || intent.before.enabled.as_bool() == Some(intent.target_enabled)
        || intent.expected_after.enabled.as_bool() != Some(intent.target_enabled)
    {
        return Err(StartupError::new(
            StartupErrorKind::InvalidIntent,
            "The saved startup change intent is invalid or does not match its native identity.",
        ));
    }
    if expected_state(&intent.before, intent.target_enabled)? != intent.expected_after {
        return Err(StartupError::new(
            StartupErrorKind::InvalidIntent,
            "The saved startup change does not contain the exact reversible after-state.",
        ));
    }
    Ok(())
}

fn validate_receipt(receipt: &ChangeReceipt) -> Result<(), StartupError> {
    if receipt.schema_version != CHANGE_SCHEMA_VERSION
        || receipt.id != receipt.before.id
        || receipt.id != receipt.after.id
        || receipt.before.identity != receipt.after.identity
        || StartupId::for_identity(&receipt.before.identity) != receipt.id
    {
        return Err(StartupError::new(
            StartupErrorKind::InvalidIntent,
            "The saved startup change receipt is invalid or does not match its native identity.",
        ));
    }
    if matches!(
        receipt.outcome,
        ChangeOutcome::Restored | ChangeOutcome::AlreadyRestored
    ) {
        if receipt.before != receipt.after {
            return Err(StartupError::new(
                StartupErrorKind::InvalidIntent,
                "The restoration receipt does not describe the original state.",
            ));
        }
    } else {
        let target = receipt.after.enabled.as_bool().ok_or_else(|| {
            StartupError::new(
                StartupErrorKind::InvalidIntent,
                "The applied receipt has an unknown resulting state.",
            )
        })?;
        if expected_state(&receipt.before, target)? != receipt.after {
            return Err(StartupError::new(
                StartupErrorKind::InvalidIntent,
                "The applied receipt does not contain the exact reversible change.",
            ));
        }
    }
    Ok(())
}

fn receipt_from_intent(
    intent: &ChangeIntent,
    after: ObservedState,
    outcome: ChangeOutcome,
) -> ChangeReceipt {
    ChangeReceipt {
        schema_version: CHANGE_SCHEMA_VERSION,
        intent_id: intent.intent_id,
        id: intent.id.clone(),
        before: intent.before.clone(),
        after,
        outcome,
    }
}

fn expected_state(
    before: &ObservedState,
    target_enabled: bool,
) -> Result<ObservedState, StartupError> {
    if before.enabled.as_bool().is_none() {
        return Err(StartupError::new(
            StartupErrorKind::Unsupported,
            "The current enabled state is unknown, so this item cannot be changed safely.",
        ));
    }
    let mut after = before.clone();
    after.enabled = EnabledState::from_bool(target_enabled);
    match (&before.identity, &before.native, &mut after.native) {
        (
            EntryIdentity::StartupRunValue {
                hive: RegistryHive::CurrentUser,
                key,
                ..
            },
            NativeState::StartupRunValue { approval, .. },
            NativeState::StartupRunValue {
                approval: after_approval,
                ..
            },
        ) if key.eq_ignore_ascii_case("Software\\Microsoft\\Windows\\CurrentVersion\\Run") => {
            if target_enabled {
                if let Some(existing) = approval {
                    let mut enabled = existing.clone();
                    if enabled.value_type != REG_BINARY_RAW || enabled.data.is_empty() {
                        return Err(StartupError::new(
                            StartupErrorKind::Unsupported,
                            "StartupApproved has an unrecognized value; no change will be attempted.",
                        ));
                    }
                    enabled.data[0] = STARTUP_APPROVED_ENABLED;
                    *after_approval = Some(enabled);
                } else {
                    *after_approval = None;
                }
            } else {
                let mut disabled = approval.clone().unwrap_or(RegistryValueSnapshot {
                    value_type: REG_BINARY_RAW,
                    data: vec![0; 8],
                });
                if disabled.value_type != REG_BINARY_RAW || disabled.data.is_empty() {
                    return Err(StartupError::new(
                        StartupErrorKind::Unsupported,
                        "StartupApproved has an unrecognized value; no change will be attempted.",
                    ));
                }
                disabled.data[0] = STARTUP_APPROVED_DISABLED;
                *after_approval = Some(disabled);
            }
        }
        (
            EntryIdentity::ScheduledTask { .. },
            NativeState::ScheduledTask { xml: Some(_) },
            NativeState::ScheduledTask { xml: Some(_) },
        ) => {}
        (
            EntryIdentity::WindowsService { .. },
            NativeState::WindowsService { config },
            NativeState::WindowsService {
                config: after_config,
            },
        ) => {
            after_config.start_type = if target_enabled {
                if config.start_type == SERVICE_DISABLED_RAW {
                    SERVICE_DEMAND_START_RAW
                } else {
                    config.start_type
                }
            } else {
                SERVICE_DISABLED_RAW
            };
        }
        (
            EntryIdentity::StartupFolderItem { .. },
            NativeState::StartupFolderItem { snapshot },
            NativeState::StartupFolderItem {
                snapshot: after_snapshot,
            },
        ) => {
            after_snapshot.approval =
                startup_approval_after(snapshot.approval.as_ref(), target_enabled)?;
        }
        (
            EntryIdentity::ContextMenuRegistration { hive, key, .. },
            NativeState::ContextMenuVerb { snapshot },
            NativeState::ContextMenuVerb {
                snapshot: after_snapshot,
            },
        ) if *hive == RegistryHive::CurrentUser && is_plain_shell_key(key) => {
            after_snapshot.legacy_disable = if target_enabled {
                None
            } else {
                Some(
                    snapshot
                        .legacy_disable
                        .clone()
                        .unwrap_or(RegistryValueSnapshot {
                            value_type: REG_SZ_RAW,
                            data: vec![0, 0],
                        }),
                )
            };
        }
        (EntryIdentity::StartupFolderItem { .. }, _, _)
        | (EntryIdentity::ContextMenuRegistration { .. }, _, _)
        | (EntryIdentity::StartupRunValue { .. }, _, _)
        | (EntryIdentity::ScheduledTask { .. }, _, _) => {
            return Err(StartupError::new(
                StartupErrorKind::Unsupported,
                "This item is visible but has no supported reversible change path.",
            ));
        }
        _ => {
            return Err(StartupError::new(
                StartupErrorKind::InvalidIntent,
                "The native state does not match the selected startup item type.",
            ));
        }
    }
    Ok(after)
}

fn validate_native_transition(
    expected: &ObservedState,
    desired: &ObservedState,
) -> Result<(), StartupError> {
    let desired_enabled = desired.enabled.as_bool().ok_or_else(|| {
        StartupError::new(
            StartupErrorKind::InvalidIntent,
            "The requested native state is unknown.",
        )
    })?;
    if expected.id != desired.id
        || expected.identity != desired.identity
        || StartupId::for_identity(&expected.identity) != expected.id
    {
        return Err(StartupError::new(
            StartupErrorKind::InvalidIntent,
            "The requested native transition does not match the selected identity.",
        ));
    }
    if expected_state(expected, desired_enabled).is_ok_and(|state| state == *desired)
        || valid_restore_pair(expected, desired)
    {
        Ok(())
    } else {
        Err(StartupError::new(
            StartupErrorKind::InvalidIntent,
            "The requested native state is not a reversible toggle of the expected state.",
        ))
    }
}

fn valid_restore_pair(expected: &ObservedState, desired: &ObservedState) -> bool {
    let (Some(expected_enabled), Some(desired_enabled)) =
        (expected.enabled.as_bool(), desired.enabled.as_bool())
    else {
        return false;
    };
    if expected_enabled == desired_enabled
        || expected.id != desired.id
        || expected.identity != desired.identity
        || StartupId::for_identity(&expected.identity) != expected.id
    {
        return false;
    }
    match (&expected.native, &desired.native) {
        (
            NativeState::StartupRunValue {
                value: expected_value,
                approval: expected_approval,
            },
            NativeState::StartupRunValue {
                value: desired_value,
                approval: desired_approval,
            },
        ) => {
            expected_value == desired_value
                && startup_approval_matches(expected_approval.as_ref(), expected_enabled)
                && startup_approval_matches(desired_approval.as_ref(), desired_enabled)
        }
        (
            NativeState::StartupFolderItem {
                snapshot: expected_snapshot,
            },
            NativeState::StartupFolderItem {
                snapshot: desired_snapshot,
            },
        ) => {
            expected_snapshot.file == desired_snapshot.file
                && startup_approval_matches(expected_snapshot.approval.as_ref(), expected_enabled)
                && startup_approval_matches(desired_snapshot.approval.as_ref(), desired_enabled)
        }
        (
            NativeState::ContextMenuVerb {
                snapshot: expected_snapshot,
            },
            NativeState::ContextMenuVerb {
                snapshot: desired_snapshot,
            },
        ) => {
            expected_snapshot.command == desired_snapshot.command
                && legacy_disable_matches(
                    expected_snapshot.legacy_disable.as_ref(),
                    expected_enabled,
                )
                && legacy_disable_matches(desired_snapshot.legacy_disable.as_ref(), desired_enabled)
        }
        (
            NativeState::ScheduledTask {
                xml: Some(expected_xml),
            },
            NativeState::ScheduledTask {
                xml: Some(desired_xml),
            },
        ) => expected_xml == desired_xml,
        (
            NativeState::WindowsService {
                config: expected_config,
            },
            NativeState::WindowsService {
                config: desired_config,
            },
        ) => {
            expected_config.start_type != desired_config.start_type
                && (expected_config.start_type != SERVICE_DISABLED_RAW) == expected_enabled
                && (desired_config.start_type != SERVICE_DISABLED_RAW) == desired_enabled
                && service_config_except_start_type_equal(expected_config, desired_config)
        }
        _ => false,
    }
}

fn startup_approval_matches(value: Option<&RegistryValueSnapshot>, enabled: bool) -> bool {
    match (value, enabled) {
        (None, true) => true,
        (Some(value), true) => {
            value.value_type == REG_BINARY_RAW
                && value.data.first() == Some(&STARTUP_APPROVED_ENABLED)
        }
        (Some(value), false) => {
            value.value_type == REG_BINARY_RAW
                && value.data.first() == Some(&STARTUP_APPROVED_DISABLED)
        }
        (None, false) => false,
    }
}

fn legacy_disable_matches(value: Option<&RegistryValueSnapshot>, enabled: bool) -> bool {
    value.is_none() == enabled
}

fn service_config_except_start_type_equal(
    left: &ServiceConfigSnapshot,
    right: &ServiceConfigSnapshot,
) -> bool {
    left.service_type == right.service_type
        && left.error_control == right.error_control
        && left.binary_path == right.binary_path
        && left.load_order_group == right.load_order_group
        && left.dependencies == right.dependencies
        && left.service_start_name == right.service_start_name
        && left.display_name == right.display_name
}

// These numeric values are the documented Windows registry / SCM constants. Keeping
// the pure change contract available on non-Windows targets lets tests avoid touching
// a user's actual startup configuration.
const REG_BINARY_RAW: u32 = 3;
const REG_SZ_RAW: u32 = 1;
const STARTUP_APPROVED_ENABLED: u8 = 2;
const STARTUP_APPROVED_DISABLED: u8 = 3;
const SERVICE_DISABLED_RAW: u32 = 4;
const SERVICE_DEMAND_START_RAW: u32 = 3;

fn is_plain_shell_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.starts_with("software\\classes\\")
        && key.ends_with("\\shell")
        && !key.contains("\\shellex\\")
}

fn startup_approval_after(
    current: Option<&RegistryValueSnapshot>,
    target_enabled: bool,
) -> Result<Option<RegistryValueSnapshot>, StartupError> {
    if target_enabled {
        return match current {
            Some(value) if value.value_type == REG_BINARY_RAW && !value.data.is_empty() => {
                let mut enabled = value.clone();
                enabled.data[0] = STARTUP_APPROVED_ENABLED;
                Ok(Some(enabled))
            }
            Some(_) => Err(StartupError::new(
                StartupErrorKind::Unsupported,
                "StartupApproved has an unrecognized value; no change will be attempted.",
            )),
            None => Ok(None),
        };
    }
    match current {
        Some(value) if value.value_type == REG_BINARY_RAW && !value.data.is_empty() => {
            let mut disabled = value.clone();
            disabled.data[0] = STARTUP_APPROVED_DISABLED;
            Ok(Some(disabled))
        }
        Some(_) => Err(StartupError::new(
            StartupErrorKind::Unsupported,
            "StartupApproved has an unrecognized value; no change will be attempted.",
        )),
        None => Ok(Some(RegistryValueSnapshot {
            value_type: REG_BINARY_RAW,
            data: vec![STARTUP_APPROVED_DISABLED, 0, 0, 0, 0, 0, 0, 0],
        })),
    }
}

fn inventory_quality(sources: &[SourceOutcome], item_count: usize) -> InventoryQuality {
    if sources.is_empty() {
        return InventoryQuality::Unavailable;
    }
    let mut read_or_missing = 0usize;
    let mut failed = 0usize;
    let mut truncated = false;
    for source in sources {
        match &source.state {
            SourceState::Read { .. } | SourceState::NotPresent => read_or_missing += 1,
            SourceState::Inaccessible { .. } | SourceState::Failed { .. } => failed += 1,
            SourceState::Truncated { .. } => {
                failed += 1;
                truncated = true;
            }
        }
    }
    if failed == 0 {
        InventoryQuality::Complete
    } else if read_or_missing == 0 && item_count == 0 && !truncated {
        InventoryQuality::Unavailable
    } else {
        InventoryQuality::Partial
    }
}

#[cfg(windows)]
mod windows_backend {
    use super::*;
    use std::{
        collections::HashMap,
        mem::ManuallyDrop,
        path::{Path, PathBuf},
        ptr,
    };
    use windows::{
        Win32::{
            Foundation::{
                CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA,
                ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HANDLE, VARIANT_BOOL,
            },
            Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
                FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
                GetFileVersionInfoSizeW, GetFileVersionInfoW, OPEN_EXISTING, VerQueryValueW,
            },
            System::{
                Com::{
                    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                    CoUninitialize, IPersistFile, STGM_READ,
                },
                Registry::{
                    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_READ,
                    KEY_SET_VALUE, REG_BINARY, REG_EXPAND_SZ, REG_SAM_FLAGS, REG_SZ,
                    REG_VALUE_TYPE, RegCloseKey, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW,
                    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
                },
                Services::{
                    ChangeServiceConfigW, CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW,
                    EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
                    QueryServiceConfigW, SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT,
                    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_CHANGE_CONFIG, SERVICE_DISABLED,
                    SERVICE_ERROR, SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG, SERVICE_START_TYPE,
                    SERVICE_STATE_ALL, SERVICE_WIN32,
                },
                TaskScheduler::{IRegisteredTask, ITaskFolder, ITaskService, TASK_ENUM_HIDDEN},
                Variant::{VARIANT, VARIANT_0_0, VARIANT_0_0_0, VT_I4},
            },
            UI::Shell::IShellLinkW,
        },
        core::{BSTR, GUID, Interface, PCWSTR, PWSTR},
    };

    const MAX_TASK_XML_UNITS: usize = 512 * 1024;
    const MAX_TASK_DEPTH: usize = 16;
    const MAX_CONTEXT_REGISTRATIONS: usize = 4_096;
    const MAX_SERVICE_BUFFER: usize = 16 * 1024 * 1024;
    const MAX_REGISTRY_SOURCE_BYTES: usize = 16 * 1024 * 1024;
    const MAX_REGISTRY_VALUE_BYTES: usize = 1024 * 1024;
    const MAX_CONTEXT_SOURCE_BYTES: usize = 16 * 1024 * 1024;
    const MAX_VERSION_RESOURCE_BYTES: usize = 256 * 1024;
    const MAX_STARTUP_VERSION_LOOKUPS: usize = 256;
    const SHELL_LINK_PATH_CHARS: usize = 260;
    const CLSID_TASK_SCHEDULER_V2: GUID = GUID::from_u128(0x0f87369f_a4e5_4cfc_bd3e_73e6154572dd);
    const CLSID_SHELL_LINK: GUID = GUID::from_u128(0x00021401_0000_0000_c000_000000000046);
    const STARTUP_FOLDER_APPROVAL_KEY: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";
    const SHELL_SOURCE_KEYS: &[&str] = &[
        r"Software\Classes\*\shell",
        r"Software\Classes\AllFilesystemObjects\shell",
        r"Software\Classes\Directory\shell",
        r"Software\Classes\Directory\Background\shell",
        r"Software\Classes\Drive\shell",
        r"Software\Classes\Folder\shell",
        r"Software\Classes\*\shellex\ContextMenuHandlers",
        r"Software\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers",
        r"Software\Classes\Directory\shellex\ContextMenuHandlers",
        r"Software\Classes\Directory\Background\shellex\ContextMenuHandlers",
        r"Software\Classes\Drive\shellex\ContextMenuHandlers",
        r"Software\Classes\Folder\shellex\ContextMenuHandlers",
    ];

    pub struct WindowsStartupPlatform;

    impl WindowsStartupPlatform {
        pub fn new() -> Self {
            Self
        }

        fn scan_startup_apps(&mut self) -> StartupInventory {
            let mut entries = Vec::new();
            let mut sources = Vec::new();
            let mut version_metadata_lookups = 0usize;
            for (hive, run_key) in [
                (
                    RegistryHive::CurrentUser,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                ),
                (
                    RegistryHive::CurrentUser,
                    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                ),
                (
                    RegistryHive::LocalMachine,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                ),
                (
                    RegistryHive::LocalMachine,
                    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                ),
            ] {
                let approval_key = if run_key.ends_with("RunOnce") {
                    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\RunOnce"
                        .to_string()
                } else {
                    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
                        .to_string()
                };
                let approval_hive = RegistryHive::CurrentUser;
                let source = format!("{}\\{}", hive_tag(hive), run_key);
                match read_registry_values(hive, run_key) {
                    Ok(Some((values, values_truncated))) => {
                        let approval_key_available =
                            match registry_key_exists(approval_hive, &approval_key) {
                                Ok(available) => available,
                                Err(error) => {
                                    sources.push(SourceOutcome {
                                        source: format!(
                                            "{}\\{}",
                                            hive_tag(approval_hive),
                                            approval_key
                                        ),
                                        state: registry_source_error(error),
                                    });
                                    false
                                }
                            };
                        let mut count = 0usize;
                        for (name, value) in values.into_iter().take(MAX_ITEMS_PER_SOURCE) {
                            let (approval, enabled, approval_readable) =
                                match read_registry_value(approval_hive, &approval_key, &name) {
                                    Ok(approval) => {
                                        let enabled = startup_approved_enabled(approval.as_ref());
                                        (approval, enabled, true)
                                    }
                                    Err(error) => {
                                        sources.push(SourceOutcome {
                                            source: format!(
                                                "{}\\{}\\{}",
                                                hive_tag(approval_hive),
                                                approval_key,
                                                name
                                            ),
                                            state: registry_source_error(error),
                                        });
                                        (
                                            None,
                                            EnabledState::Unknown {
                                                reason:
                                                    "The StartupApproved state could not be read."
                                                        .into(),
                                            },
                                            false,
                                        )
                                    }
                                };
                            let identity = EntryIdentity::StartupRunValue {
                                hive,
                                key: run_key.to_string(),
                                value_name: name.clone(),
                                approval_hive,
                                approval_key: approval_key.clone(),
                            };
                            let id = StartupId::for_identity(&identity);
                            let value_text = registry_value_string(&value);
                            let command = match value_text {
                                Some(value) => FieldValue::known(value),
                                None => FieldValue::unknown(
                                    "The registry value is not a readable command string.",
                                ),
                            };
                            let file_path = command
                                .known_value()
                                .and_then(executable_from_command)
                                .map(FieldValue::known)
                                .unwrap_or_else(|| {
                                    FieldValue::unknown(
                                        "The executable path could not be parsed from the command.",
                                    )
                                });
                            let file_metadata = file_path.known_value().and_then(|path| {
                                if version_metadata_lookups >= MAX_STARTUP_VERSION_LOOKUPS {
                                    None
                                } else {
                                    version_metadata_lookups += 1;
                                    read_file_version_metadata(Path::new(path))
                                }
                            });
                            let program =
                                startup_program_label(None, file_metadata.as_ref(), &name);
                            let publisher = startup_metadata_field(
                                file_metadata
                                    .as_ref()
                                    .and_then(|metadata| metadata.company_name.as_deref()),
                                "The startup executable's CompanyName metadata is unavailable.",
                            );
                            let version = startup_metadata_field(
                                file_metadata
                                    .as_ref()
                                    .and_then(|metadata| metadata.file_version.as_deref()),
                                "The startup executable's FileVersion metadata is unavailable.",
                            );
                            let can_change = hive == RegistryHive::CurrentUser
                                && run_key.eq_ignore_ascii_case(
                                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                                )
                                && enabled.as_bool().is_some()
                                && approval_readable
                                && approval_key_available
                                && approval.as_ref().is_none_or(|v| {
                                    v.value_type == REG_BINARY.0 && !v.data.is_empty()
                                });
                            entries.push(StartupEntry {
                                id: id.clone(),
                                section: StartupSection::StartupApps,
                                program: FieldValue::known(program),
                                publisher,
                                version,
                                file_path,
                                command,
                                enabled: enabled.clone(),
                                identity,
                                can_change_enabled: can_change,
                                change_limitation: (!can_change).then(|| {
                                    startup_run_limitation(
                                        hive,
                                        run_key,
                                        &enabled,
                                        approval.as_ref(),
                                    )
                                }),
                            });
                            count += 1;
                        }
                        let truncated = count == MAX_ITEMS_PER_SOURCE || values_truncated;
                        sources.push(SourceOutcome {
                            source,
                            state: if truncated {
                                SourceState::Truncated {
                                    limit: MAX_ITEMS_PER_SOURCE,
                                    reason: "The per-key startup-item bound was reached.".into(),
                                }
                            } else if count == 0 {
                                SourceState::Read { items: 0 }
                            } else {
                                SourceState::Read { items: count }
                            },
                        });
                    }
                    Ok(None) => sources.push(SourceOutcome {
                        source,
                        state: SourceState::NotPresent,
                    }),
                    Err(error) => sources.push(SourceOutcome {
                        source,
                        state: registry_source_error(error),
                    }),
                }
            }
            let (folder_marker_names, folder_name_check_error) = startup_folder_name_counts();
            for (label, folder) in startup_folder_paths() {
                let approval_hive = match startup_folder_root_approval_hive(&folder) {
                    Ok(hive) => hive,
                    Err(error) => {
                        sources.push(SourceOutcome {
                            source: format!("{label} StartupApproved source"),
                            state: SourceState::Inaccessible {
                                reason: error.message,
                            },
                        });
                        continue;
                    }
                };
                let approval_access =
                    registry_key_exists(approval_hive, STARTUP_FOLDER_APPROVAL_KEY)
                        .map_err(|error| error.message);
                let mut folder_marker_errors = Vec::new();
                let mut folder_marker_count = 0usize;
                match read_startup_folder(
                    &folder,
                    approval_hive,
                    &approval_access,
                    &folder_marker_names,
                    folder_name_check_error.as_deref(),
                    &mut version_metadata_lookups,
                    &mut folder_marker_errors,
                    &mut folder_marker_count,
                ) {
                    Ok((items, state)) => {
                        entries.extend(items);
                        sources.push(SourceOutcome {
                            source: format!("{label}: {}", folder.display()),
                            state,
                        });
                    }
                    Err(error) => sources.push(SourceOutcome {
                        source: format!("{label}: {}", folder.display()),
                        state: SourceState::Inaccessible {
                            reason: error.to_string(),
                        },
                    }),
                }
                let folder_approval_state = if !folder_marker_errors.is_empty() {
                    SourceState::Failed {
                        reason: format!(
                            "{} StartupApproved StartupFolder value(s) were not readable: {}",
                            folder_marker_errors.len(),
                            folder_marker_errors.join("; ")
                        ),
                    }
                } else {
                    match &approval_access {
                        Ok(true) => SourceState::Read {
                            items: folder_marker_count,
                        },
                        Ok(false) => SourceState::NotPresent,
                        Err(reason) => SourceState::Inaccessible {
                            reason: reason.clone(),
                        },
                    }
                };
                sources.push(SourceOutcome {
                    source: format!("{}\\{STARTUP_FOLDER_APPROVAL_KEY}", hive_tag(approval_hive)),
                    state: folder_approval_state,
                });
            }
            sources.push(SourceOutcome {
                source: "Startup-folder approval marker name uniqueness".into(),
                state: folder_name_check_error.map_or(SourceState::Read { items: 1 }, |reason| {
                    SourceState::Failed { reason }
                }),
            });
            finish_inventory(StartupSection::StartupApps, entries, sources)
        }

        fn scan_context_menu(&mut self) -> StartupInventory {
            let mut entries = Vec::new();
            let mut sources = Vec::new();
            let mut context_bytes = 0usize;
            for hive in [RegistryHive::CurrentUser, RegistryHive::LocalMachine] {
                for key in SHELL_SOURCE_KEYS {
                    let source = format!("{}\\{}", hive_tag(hive), key);
                    match read_registry_subkeys(hive, key) {
                        Ok(Some((registrations, subkeys_truncated))) => {
                            let mut count = 0usize;
                            let mut detail_failures = Vec::new();
                            let mut category_truncated = subkeys_truncated;
                            for registration in
                                registrations.into_iter().take(MAX_CONTEXT_REGISTRATIONS)
                            {
                                if entries.len() >= MAX_ITEMS_PER_SOURCE {
                                    category_truncated = true;
                                    break;
                                }
                                let full_key = format!("{key}\\{registration}");
                                let label = match read_registry_value(hive, &full_key, "") {
                                    Ok(value) => value
                                        .and_then(|value| registry_value_string(&value))
                                        .filter(|value| !value.trim().is_empty())
                                        .unwrap_or_else(|| registration.clone()),
                                    Err(error) => {
                                        record_context_error(&mut detail_failures, error);
                                        registration.clone()
                                    }
                                };
                                let is_shellex = key.to_ascii_lowercase().contains("\\shellex\\");
                                let command_key = if is_shellex {
                                    None
                                } else {
                                    Some(format!("{full_key}\\command"))
                                };
                                let (command, command_snapshot) = if is_shellex {
                                    (FieldValue::NotApplicable, None)
                                } else {
                                    match read_registry_value(
                                        hive,
                                        command_key.as_deref().unwrap_or_default(),
                                        "",
                                    ) {
                                        Ok(Some(value)) => (
                                            registry_value_string(&value)
                                                .map(FieldValue::known)
                                                .unwrap_or_else(|| {
                                                    FieldValue::unknown(
                                                        "The registered command is not a string value.",
                                                    )
                                                }),
                                            Some(value),
                                        ),
                                        Ok(None) => (
                                            FieldValue::unknown(
                                                "No command subkey is registered for this menu item.",
                                            ),
                                            None,
                                        ),
                                        Err(error) => {
                                            record_context_error(&mut detail_failures, error);
                                            (
                                                FieldValue::unknown(
                                                    "The command registration could not be read.",
                                                ),
                                                None,
                                            )
                                        }
                                    }
                                };
                                let marker_result = if is_shellex {
                                    Ok(None)
                                } else {
                                    read_registry_value(hive, &full_key, "LegacyDisable")
                                };
                                let marker_readable = marker_result.is_ok();
                                let legacy_disable = match marker_result {
                                    Ok(value) => value,
                                    Err(error) => {
                                        record_context_error(&mut detail_failures, error);
                                        None
                                    }
                                };
                                let delegate_values = if is_shellex {
                                    Some(false)
                                } else {
                                    match context_verb_has_delegate(
                                        hive,
                                        &full_key,
                                        command_key.as_deref(),
                                    ) {
                                        Ok(has_delegate) => Some(has_delegate),
                                        Err(error) => {
                                            record_context_error(&mut detail_failures, error);
                                            None
                                        }
                                    }
                                };
                                let enabled = if is_shellex {
                                    EnabledState::Unknown {
                                        reason: "Windows does not expose a reliable per-registration enabled state for this shell extension handler.".into(),
                                    }
                                } else if !marker_readable {
                                    EnabledState::Unknown {
                                        reason: "The LegacyDisable state could not be read.".into(),
                                    }
                                } else if legacy_disable.is_some() {
                                    EnabledState::Disabled
                                } else {
                                    EnabledState::Enabled
                                };
                                let identity = EntryIdentity::ContextMenuRegistration {
                                    hive,
                                    key: key.to_string(),
                                    registration: registration.clone(),
                                };
                                let id = StartupId::for_identity(&identity);
                                let file_path = command.known_value().and_then(executable_from_command)
                                    .map(FieldValue::known)
                                    .unwrap_or_else(|| FieldValue::unknown("The registered handler executable is not available from this key."));
                                let entry_bytes = registration.len()
                                    + label.len()
                                    + command.known_value().map_or(0, str::len)
                                    + file_path.known_value().map_or(0, str::len);
                                if context_bytes.saturating_add(entry_bytes)
                                    > MAX_CONTEXT_SOURCE_BYTES
                                {
                                    category_truncated = true;
                                    break;
                                }
                                context_bytes += entry_bytes;
                                let can_change_enabled = hive == RegistryHive::CurrentUser
                                    && !is_shellex
                                    && is_plain_shell_key(key)
                                    && command_snapshot.as_ref().is_some_and(|value| {
                                        value.value_type == REG_SZ.0
                                            || value.value_type == REG_EXPAND_SZ.0
                                    })
                                    && delegate_values == Some(false)
                                    && marker_readable;
                                let change_limitation = (!can_change_enabled).then(|| {
                                    context_change_limitation(
                                        hive,
                                        is_shellex,
                                        is_plain_shell_key(key),
                                        command_snapshot.as_ref(),
                                        delegate_values,
                                        marker_readable,
                                    )
                                });
                                entries.push(StartupEntry {
                                    id,
                                    section: StartupSection::ContextMenu,
                                    program: FieldValue::known(label),
                                    publisher: FieldValue::unknown("Publisher metadata was not available from the context-menu registration."),
                                    version: FieldValue::NotApplicable,
                                    file_path,
                                    command,
                                    enabled,
                                    identity,
                                    can_change_enabled,
                                    change_limitation,
                                });
                                count += 1;
                            }
                            let state = if !detail_failures.is_empty() {
                                SourceState::Failed {
                                    reason: format!(
                                        "{} context registration detail(s) were not readable; {}",
                                        detail_failures.len(),
                                        detail_failures.join("; ")
                                    ),
                                }
                            } else if count >= MAX_CONTEXT_REGISTRATIONS || category_truncated {
                                SourceState::Truncated {
                                    limit: MAX_ITEMS_PER_SOURCE,
                                    reason: "The context-menu enumeration bound was reached."
                                        .into(),
                                }
                            } else {
                                SourceState::Read { items: count }
                            };
                            sources.push(SourceOutcome { source, state });
                        }
                        Ok(None) => sources.push(SourceOutcome {
                            source,
                            state: SourceState::NotPresent,
                        }),
                        Err(error) => sources.push(SourceOutcome {
                            source,
                            state: registry_source_error(error),
                        }),
                    }
                }
            }
            finish_inventory(StartupSection::ContextMenu, entries, sources)
        }

        fn scan_tasks(&mut self) -> StartupInventory {
            match TaskClient::connect() {
                Ok(mut client) => {
                    let mut entries = Vec::new();
                    let mut sources = vec![SourceOutcome {
                        source: "Task Scheduler service".into(),
                        state: SourceState::Read { items: 0 },
                    }];
                    match client.root_folder() {
                        Ok(root) => {
                            let mut folders = 0usize;
                            let mut truncated = false;
                            enumerate_task_folder(
                                &root,
                                0,
                                &mut folders,
                                &mut entries,
                                &mut sources,
                                &mut truncated,
                            );
                            sources[0].state = if truncated {
                                SourceState::Truncated {
                                    limit: MAX_ITEMS_PER_SOURCE,
                                    reason: "The task or folder enumeration bound was reached."
                                        .into(),
                                }
                            } else {
                                SourceState::Read {
                                    items: entries.len(),
                                }
                            };
                        }
                        Err(error) => {
                            sources[0].state = SourceState::Failed {
                                reason: format!("Task Scheduler root could not be read: {error}"),
                            }
                        }
                    }
                    finish_inventory(StartupSection::ScheduledTasks, entries, sources)
                }
                Err(error) => StartupInventory {
                    section: StartupSection::ScheduledTasks,
                    quality: InventoryQuality::Unavailable,
                    entries: Vec::new(),
                    sources: vec![SourceOutcome {
                        source: "Task Scheduler service".into(),
                        state: SourceState::Inaccessible { reason: error },
                    }],
                },
            }
        }

        fn scan_services(&mut self) -> StartupInventory {
            let mut entries = Vec::new();
            let mut sources = Vec::new();
            match service_manager(SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE) {
                Ok(manager) => match enumerate_services(manager.0) {
                    Ok((services, truncated)) => {
                        for (name, display_name) in &services {
                            match query_service_config(manager.0, name) {
                                Ok(config) => {
                                    let identity =
                                        EntryIdentity::WindowsService { name: name.clone() };
                                    let id = StartupId::for_identity(&identity);
                                    let enabled = EnabledState::from_bool(
                                        config.start_type != SERVICE_DISABLED.0,
                                    );
                                    let can_change = config.service_type & 0x30 != 0;
                                    let command_text =
                                        nonempty(&config.binary_path).map(str::to_owned);
                                    let path =
                                        command_text.as_deref().and_then(executable_from_command);
                                    entries.push(StartupEntry {
                                        id,
                                        section: StartupSection::WindowsServices,
                                        program: if config.display_name.is_empty() { FieldValue::known(display_name.clone()) } else { FieldValue::known(config.display_name.clone()) },
                                        publisher: FieldValue::unknown("Service publisher metadata was not queried."),
                                        version: FieldValue::NotApplicable,
                                        file_path: path.clone().map(FieldValue::known).unwrap_or_else(|| FieldValue::unknown("The Service Control Manager returned no image path.")),
                                        command: command_text.map(FieldValue::known).unwrap_or_else(|| FieldValue::unknown("The Service Control Manager returned no image path.")),
                                        enabled,
                                        identity,
                                        can_change_enabled: can_change,
                                        change_limitation: (!can_change).then(|| "Driver and non-Win32 service types are inventory-only.".into()),
                                    });
                                }
                                Err(error) => sources.push(SourceOutcome {
                                    source: format!("Service configuration: {name}"),
                                    state: SourceState::Inaccessible {
                                        reason: error.message,
                                    },
                                }),
                            }
                        }
                        sources.push(SourceOutcome {
                            source: "Service Control Manager (Win32 services)".into(),
                            state: if truncated {
                                SourceState::Truncated {
                                    limit: MAX_ITEMS_PER_SOURCE,
                                    reason: "The service enumeration bound was reached.".into(),
                                }
                            } else {
                                SourceState::Read {
                                    items: entries.len(),
                                }
                            },
                        });
                    }
                    Err(error) => sources.push(SourceOutcome {
                        source: "Service Control Manager (Win32 services)".into(),
                        state: SourceState::Failed { reason: error },
                    }),
                },
                Err(error) => sources.push(SourceOutcome {
                    source: "Service Control Manager".into(),
                    state: SourceState::Inaccessible { reason: error },
                }),
            }
            finish_inventory(StartupSection::WindowsServices, entries, sources)
        }
    }

    impl StartupPlatform for WindowsStartupPlatform {
        fn inventory(&mut self, section: StartupSection) -> StartupInventory {
            match section {
                StartupSection::StartupApps => self.scan_startup_apps(),
                StartupSection::ScheduledTasks => self.scan_tasks(),
                StartupSection::ContextMenu => self.scan_context_menu(),
                StartupSection::WindowsServices => self.scan_services(),
            }
        }

        fn observe(&mut self, id: &StartupId) -> Result<ObservedState, StartupError> {
            // Identity-specific lookup avoids broad rescans for a consequential action.
            match find_identity_by_id(self, id)? {
                EntryIdentity::StartupRunValue {
                    hive,
                    key,
                    value_name,
                    approval_hive,
                    approval_key,
                } => {
                    if hive != RegistryHive::CurrentUser
                        || !key
                            .eq_ignore_ascii_case(r"Software\Microsoft\Windows\CurrentVersion\Run")
                    {
                        return Err(StartupError::new(
                            StartupErrorKind::Unsupported,
                            "Only current-user Run values have a supported reversible toggle.",
                        ));
                    }
                    let value = read_registry_value(hive, &key, &value_name)?.ok_or_else(|| {
                        StartupError::new(
                            StartupErrorKind::UnknownId,
                            "The selected Run value no longer exists.",
                        )
                    })?;
                    if !registry_key_exists(approval_hive, &approval_key)? {
                        return Err(StartupError::new(
                            StartupErrorKind::Unsupported,
                            "The StartupApproved key is absent; this Run value is inventory-only.",
                        ));
                    }
                    let approval = read_registry_value(approval_hive, &approval_key, &value_name)?;
                    let enabled = startup_approved_enabled(approval.as_ref());
                    Ok(ObservedState {
                        id: id.clone(),
                        identity: EntryIdentity::StartupRunValue {
                            hive,
                            key,
                            value_name,
                            approval_hive,
                            approval_key,
                        },
                        enabled,
                        native: NativeState::StartupRunValue { value, approval },
                    })
                }
                EntryIdentity::ScheduledTask { path } => {
                    let task = self.open_task(&path)?;
                    observe_task(id, path, &task.task)
                }
                EntryIdentity::StartupFolderItem { path } => observe_startup_folder(id, path),
                EntryIdentity::ContextMenuRegistration {
                    hive: RegistryHive::CurrentUser,
                    key,
                    registration,
                } if is_plain_shell_key(&key) => observe_context_verb(id, key, registration),
                EntryIdentity::WindowsService { name } => {
                    let manager = service_manager(SC_MANAGER_CONNECT).map_err(|message| {
                        StartupError::new(StartupErrorKind::Inaccessible, message)
                    })?;
                    let config = query_service_config(manager.0, &name)?;
                    if config.service_type & 0x30 == 0 {
                        return Err(StartupError::new(
                            StartupErrorKind::Unsupported,
                            "Driver and non-Win32 service types are inventory-only.",
                        ));
                    }
                    let enabled = EnabledState::from_bool(config.start_type != SERVICE_DISABLED.0);
                    Ok(ObservedState {
                        id: id.clone(),
                        identity: EntryIdentity::WindowsService { name },
                        enabled,
                        native: NativeState::WindowsService { config },
                    })
                }
                identity => {
                    let enabled = match self
                        .inventory(identity.section())
                        .entries
                        .into_iter()
                        .find(|entry| entry.id == *id)
                    {
                        Some(entry) => entry.enabled,
                        None => {
                            return Err(StartupError::new(
                                StartupErrorKind::UnknownId,
                                "The selected startup item no longer exists.",
                            ));
                        }
                    };
                    Ok(ObservedState {
                        id: id.clone(),
                        identity,
                        enabled,
                        native: NativeState::ReadOnly,
                    })
                }
            }
        }

        fn compare_and_set(
            &mut self,
            id: &StartupId,
            expected: &ObservedState,
            desired: &ObservedState,
        ) -> Result<(), StartupError> {
            if expected.id != *id || desired.id != *id || expected.identity != desired.identity {
                return Err(StartupError::new(
                    StartupErrorKind::InvalidIntent,
                    "The startup change does not match the selected item.",
                ));
            }
            if StartupId::for_identity(&expected.identity) != *id {
                return Err(StartupError::new(
                    StartupErrorKind::InvalidIntent,
                    "The selected ID does not match its native identity.",
                ));
            }
            validate_native_transition(expected, desired)?;
            if let (
                EntryIdentity::StartupRunValue {
                    hive,
                    key,
                    value_name,
                    approval_hive,
                    approval_key,
                },
                NativeState::StartupRunValue { .. },
                NativeState::StartupRunValue {
                    approval: desired_approval,
                    ..
                },
            ) = (&expected.identity, &expected.native, &desired.native)
            {
                if *hive != RegistryHive::CurrentUser
                    || !key.eq_ignore_ascii_case(r"Software\Microsoft\Windows\CurrentVersion\Run")
                {
                    return Err(StartupError::new(
                        StartupErrorKind::Unsupported,
                        "Only current-user Run values have a supported reversible toggle.",
                    ));
                }
                write_registry_approval(
                    *approval_hive,
                    *hive,
                    key,
                    expected,
                    approval_key,
                    value_name,
                    desired_approval.as_ref(),
                )
            } else if let (
                EntryIdentity::StartupFolderItem { path },
                NativeState::StartupFolderItem {
                    snapshot: expected_snapshot,
                },
                NativeState::StartupFolderItem {
                    snapshot: desired_snapshot,
                },
            ) = (&expected.identity, &expected.native, &desired.native)
            {
                let current = observe_startup_folder(id, path.clone())?;
                if current != *expected {
                    return Err(StartupError::new(
                        StartupErrorKind::ChangedSinceReview,
                        "The selected Startup-folder item changed after review.",
                    ));
                }
                write_startup_folder_approval(path, expected_snapshot, desired_snapshot)
            } else if let (
                EntryIdentity::ContextMenuRegistration {
                    hive: RegistryHive::CurrentUser,
                    key,
                    registration,
                },
                NativeState::ContextMenuVerb {
                    snapshot: expected_snapshot,
                },
                NativeState::ContextMenuVerb {
                    snapshot: desired_snapshot,
                },
            ) = (&expected.identity, &expected.native, &desired.native)
            {
                let current = observe_context_verb(id, key.clone(), registration.clone())?;
                if current != *expected {
                    return Err(StartupError::new(
                        StartupErrorKind::ChangedSinceReview,
                        "The selected context-menu command changed after review.",
                    ));
                }
                write_context_verb(key, registration, expected_snapshot, desired_snapshot)
            } else if let (
                EntryIdentity::ScheduledTask { path },
                NativeState::ScheduledTask { xml: Some(_) },
                NativeState::ScheduledTask { .. },
            ) = (&expected.identity, &expected.native, &desired.native)
            {
                let task = self.open_task(path)?;
                let current = observe_task(id, path.clone(), &task.task)?;
                if current != *expected {
                    return Err(StartupError::new(
                        StartupErrorKind::ChangedSinceReview,
                        "The selected scheduled task changed after review.",
                    ));
                }
                let enabled = desired.enabled.as_bool().ok_or_else(|| {
                    StartupError::new(
                        StartupErrorKind::InvalidIntent,
                        "The requested task state is unknown.",
                    )
                })?;
                unsafe {
                    task.task.SetEnabled(if enabled {
                        VARIANT_BOOL(-1)
                    } else {
                        VARIANT_BOOL(0)
                    })
                }
                .map_err(|error| {
                    StartupError::new(
                        StartupErrorKind::NativeFailure,
                        format!(
                            "Task Scheduler rejected the change: {}",
                            hresult_text(error.code().0)
                        ),
                    )
                })
            } else if let (
                EntryIdentity::WindowsService { name },
                NativeState::WindowsService {
                    config: expected_config,
                },
                NativeState::WindowsService {
                    config: desired_config,
                },
            ) = (&expected.identity, &expected.native, &desired.native)
            {
                let manager = service_manager(SC_MANAGER_CONNECT).map_err(|message| {
                    StartupError::new(StartupErrorKind::Inaccessible, message)
                })?;
                let service = open_service(
                    manager.0,
                    name,
                    SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG,
                )?;
                let current = query_service_config_on_handle(service.0)?;
                if current != *expected_config {
                    return Err(StartupError::new(
                        StartupErrorKind::ChangedSinceReview,
                        "The selected service configuration changed after review.",
                    ));
                }
                let native_type = SERVICE_START_TYPE(desired_config.start_type);
                unsafe {
                    ChangeServiceConfigW(
                        service.0,
                        windows::Win32::System::Services::ENUM_SERVICE_TYPE(
                            expected_config.service_type,
                        ),
                        native_type,
                        SERVICE_ERROR(SERVICE_NO_CHANGE),
                        PCWSTR::null(),
                        PCWSTR::null(),
                        None,
                        PCWSTR::null(),
                        PCWSTR::null(),
                        PCWSTR::null(),
                        PCWSTR::null(),
                    )
                }
                .map_err(|error| {
                    StartupError::new(
                        StartupErrorKind::NativeFailure,
                        format!(
                            "Service Control Manager rejected the change: {}",
                            hresult_text(error.code().0)
                        ),
                    )
                })
            } else {
                Err(StartupError::new(
                    StartupErrorKind::Unsupported,
                    "This item has no supported reversible change path.",
                ))
            }
        }
    }

    impl WindowsStartupPlatform {
        fn open_task(&mut self, path: &str) -> Result<TaskHandle, StartupError> {
            let mut client = TaskClient::connect()
                .map_err(|message| StartupError::new(StartupErrorKind::Inaccessible, message))?;
            let parent_path = task_parent(path);
            let name = task_leaf(path);
            let folder = client
                .get_folder(parent_path)
                .map_err(|message| StartupError::new(StartupErrorKind::Inaccessible, message))?;
            let bstr = BSTR::from(name);
            let task = unsafe { folder.GetTask(&bstr) }.map_err(|error| {
                StartupError::new(
                    StartupErrorKind::UnknownId,
                    format!(
                        "The selected task could not be reopened: {}",
                        hresult_text(error.code().0)
                    ),
                )
            })?;
            Ok(TaskHandle {
                _apartment: client._apartment,
                task,
            })
        }
    }

    fn finish_inventory(
        section: StartupSection,
        entries: Vec<StartupEntry>,
        sources: Vec<SourceOutcome>,
    ) -> StartupInventory {
        let quality = inventory_quality(&sources, entries.len());
        StartupInventory {
            section,
            quality,
            entries,
            sources,
        }
    }

    fn startup_run_limitation(
        hive: RegistryHive,
        key: &str,
        enabled: &EnabledState,
        approval: Option<&RegistryValueSnapshot>,
    ) -> String {
        if enabled.as_bool().is_none() {
            "The StartupApproved state is unrecognized; the entry is read-only.".into()
        } else if approval
            .is_some_and(|value| value.value_type != REG_BINARY.0 || value.data.is_empty())
        {
            "StartupApproved contains an unrecognized value; the entry is read-only.".into()
        } else if hive != RegistryHive::CurrentUser
            || !key.eq_ignore_ascii_case(r"Software\Microsoft\Windows\CurrentVersion\Run")
        {
            "Only current-user Run values use the supported reversible StartupApproved toggle."
                .into()
        } else {
            "No reversible change path is available for this startup registration.".into()
        }
    }

    fn record_context_error(errors: &mut Vec<String>, error: StartupError) {
        if errors.len() < 8 {
            errors.push(error.message);
        }
    }

    fn context_verb_has_delegate(
        hive: RegistryHive,
        verb_key: &str,
        command_key: Option<&str>,
    ) -> Result<bool, StartupError> {
        let mut probes = vec![
            (verb_key, "DelegateExecute"),
            (verb_key, "ExplorerCommandHandler"),
            (verb_key, "CommandStateHandler"),
        ];
        if let Some(command_key) = command_key {
            probes.extend([
                (command_key, "DelegateExecute"),
                (command_key, "ExplorerCommandHandler"),
                (command_key, "CommandStateHandler"),
            ]);
        }
        for (key, name) in probes {
            if read_registry_value(hive, key, name)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn context_change_limitation(
        hive: RegistryHive,
        is_shellex: bool,
        plain_shell_key: bool,
        command: Option<&RegistryValueSnapshot>,
        delegate_values: Option<bool>,
        marker_readable: bool,
    ) -> String {
        if hive != RegistryHive::CurrentUser {
            "Only per-user static shell verbs use the reversible toggle.".into()
        } else if is_shellex {
            "Shell extension handlers do not expose a scoped reversible disable marker.".into()
        } else if !plain_shell_key {
            "This registration is not a supported static shell verb.".into()
        } else if !marker_readable {
            "The LegacyDisable state could not be read.".into()
        } else if command
            .is_none_or(|value| value.value_type != REG_SZ.0 && value.value_type != REG_EXPAND_SZ.0)
        {
            "A readable string command is required for the scoped verb toggle.".into()
        } else if delegate_values != Some(false) {
            "Delegated command handlers are inventory-only.".into()
        } else {
            "The registration does not meet the safe static-verb toggle requirements.".into()
        }
    }

    fn startup_approved_enabled(value: Option<&RegistryValueSnapshot>) -> EnabledState {
        match value {
            None => EnabledState::Enabled,
            Some(value)
                if value.value_type == REG_BINARY.0
                    && value.data.first() == Some(&STARTUP_APPROVED_ENABLED) =>
            {
                EnabledState::Enabled
            }
            Some(value)
                if value.value_type == REG_BINARY.0
                    && value.data.first() == Some(&STARTUP_APPROVED_DISABLED) =>
            {
                EnabledState::Disabled
            }
            Some(_) => EnabledState::Unknown {
                reason: "The StartupApproved marker is not a recognized binary state.".into(),
            },
        }
    }

    fn startup_folder_paths() -> Vec<(&'static str, PathBuf)> {
        let mut paths = Vec::with_capacity(2);
        if let Some(root) = dirs::data_dir() {
            paths.push((
                "User Startup folder",
                root.join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
            ));
        }
        if let Some(root) = std::env::var_os("PROGRAMDATA") {
            paths.push((
                "Common Startup folder",
                PathBuf::from(root).join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
            ));
        }
        paths
    }

    #[derive(Default)]
    struct ShellLinkMetadata {
        target_path: Option<String>,
        description: Option<String>,
    }

    fn read_shell_link_metadata(path: &Path) -> Option<ShellLinkMetadata> {
        let path_text = path.to_str()?;
        let _apartment = ComApartment::initialize().ok()?;
        let shell_link: IShellLinkW =
            unsafe { CoCreateInstance(&CLSID_SHELL_LINK, None, CLSCTX_INPROC_SERVER) }.ok()?;
        let persist_file: IPersistFile = shell_link.cast().ok()?;
        let path_wide = wide(path_text);
        unsafe { persist_file.Load(PCWSTR(path_wide.as_ptr()), STGM_READ) }.ok()?;

        // Read the stored target and description only. This deliberately does not call
        // IShellLink::Resolve, display prompts, or launch the target.
        let mut target = vec![0u16; SHELL_LINK_PATH_CHARS];
        let target_path = unsafe { shell_link.GetPath(&mut target, ptr::null_mut(), 0) }
            .ok()
            .and_then(|()| wide_buffer_text(&target));
        let mut description = vec![0u16; SHELL_LINK_PATH_CHARS];
        let description = unsafe { shell_link.GetDescription(&mut description) }
            .ok()
            .and_then(|()| wide_buffer_text(&description));
        (target_path.is_some() || description.is_some()).then_some(ShellLinkMetadata {
            target_path,
            description,
        })
    }

    fn read_file_version_metadata(path: &Path) -> Option<StartupFileMetadata> {
        let path_text = path.to_str()?;
        let path_wide = wide(path_text);
        let mut ignored_handle = 0u32;
        let size = unsafe {
            GetFileVersionInfoSizeW(PCWSTR(path_wide.as_ptr()), Some(&mut ignored_handle))
        } as usize;
        if size == 0 || size > MAX_VERSION_RESOURCE_BYTES {
            return None;
        }
        let mut version_resource = vec![0u8; size];
        unsafe {
            GetFileVersionInfoW(
                PCWSTR(path_wide.as_ptr()),
                Some(ignored_handle),
                size as u32,
                version_resource.as_mut_ptr().cast(),
            )
        }
        .ok()?;

        let mut translations = version_resource_translations(&version_resource);
        for fallback in [(0x0409, 1200), (0x0409, 1252)] {
            if !translations.contains(&fallback) {
                translations.push(fallback);
            }
        }
        let metadata = StartupFileMetadata {
            file_description: first_version_string(
                &version_resource,
                &translations,
                "FileDescription",
            ),
            product_name: first_version_string(&version_resource, &translations, "ProductName"),
            company_name: first_version_string(&version_resource, &translations, "CompanyName"),
            file_version: first_version_string(&version_resource, &translations, "FileVersion"),
        };
        (metadata.file_description.is_some()
            || metadata.product_name.is_some()
            || metadata.company_name.is_some()
            || metadata.file_version.is_some())
        .then_some(metadata)
    }

    fn version_resource_translations(resource: &[u8]) -> Vec<(u16, u16)> {
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Translation {
            language: u16,
            code_page: u16,
        }

        let query = wide(r"\VarFileInfo\Translation");
        let mut value = ptr::null_mut();
        let mut length = 0u32;
        let success = unsafe {
            VerQueryValueW(
                resource.as_ptr().cast(),
                PCWSTR(query.as_ptr()),
                &mut value,
                &mut length,
            )
        };
        let count = (length as usize / std::mem::size_of::<Translation>()).min(32);
        if !success.as_bool() || value.is_null() || count == 0 {
            return Vec::new();
        }
        let translations =
            unsafe { std::slice::from_raw_parts(value.cast::<Translation>(), count) };
        translations
            .iter()
            .map(|translation| (translation.language, translation.code_page))
            .collect()
    }

    fn first_version_string(
        resource: &[u8],
        translations: &[(u16, u16)],
        name: &str,
    ) -> Option<String> {
        translations
            .iter()
            .find_map(|(language, code_page)| version_string(resource, *language, *code_page, name))
    }

    fn version_string(
        resource: &[u8],
        language: u16,
        code_page: u16,
        name: &str,
    ) -> Option<String> {
        let query = wide(&format!(
            r"\StringFileInfo\{language:04X}{code_page:04X}\{name}"
        ));
        let mut value = ptr::null_mut();
        let mut length = 0u32;
        let success = unsafe {
            VerQueryValueW(
                resource.as_ptr().cast(),
                PCWSTR(query.as_ptr()),
                &mut value,
                &mut length,
            )
        };
        if !success.as_bool() || value.is_null() || length == 0 || length as usize > 65_536 {
            return None;
        }
        let units = unsafe { std::slice::from_raw_parts(value.cast::<u16>(), length as usize) };
        let result = wide_buffer_text(units)?;
        let result = result.trim();
        (!result.is_empty()).then(|| result.to_owned())
    }

    fn wide_buffer_text(buffer: &[u16]) -> Option<String> {
        let end = buffer
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(buffer.len());
        (end > 0).then(|| String::from_utf16_lossy(&buffer[..end]))
    }

    fn startup_folder_approval_hive(path: &Path) -> Result<RegistryHive, StartupError> {
        let roots = startup_folder_paths();
        let user_root = roots
            .iter()
            .find(|(label, _)| *label == "User Startup folder")
            .map(|(_, path)| path.as_path());
        let common_root = roots
            .iter()
            .find(|(label, _)| *label == "Common Startup folder")
            .map(|(_, path)| path.as_path());
        startup_folder_approval_hive_for_roots(path, user_root, common_root).ok_or_else(|| {
            StartupError::new(
                StartupErrorKind::Unsupported,
                "The Startup-folder item does not resolve to exactly one supported user or common folder.",
            )
        })
    }

    fn startup_folder_root_approval_hive(root: &Path) -> Result<RegistryHive, StartupError> {
        let roots = startup_folder_paths();
        let user_root = roots
            .iter()
            .find(|(label, _)| *label == "User Startup folder")
            .map(|(_, path)| path.as_path());
        let common_root = roots
            .iter()
            .find(|(label, _)| *label == "Common Startup folder")
            .map(|(_, path)| path.as_path());
        startup_folder_root_hive_for_roots(root, user_root, common_root).ok_or_else(|| {
            StartupError::new(
                StartupErrorKind::Unsupported,
                "The Startup folder does not resolve to exactly one supported user or common root.",
            )
        })
    }

    fn read_startup_folder(
        path: &Path,
        approval_hive: RegistryHive,
        approval_access: &Result<bool, String>,
        marker_names: &StartupFolderMarkerCounts,
        marker_name_check_error: Option<&str>,
        version_metadata_lookups: &mut usize,
        marker_errors: &mut Vec<String>,
        marker_count: &mut usize,
    ) -> std::io::Result<(Vec<StartupEntry>, SourceState)> {
        let read_dir = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok((Vec::new(), SourceState::NotPresent));
            }
            Err(error) => return Err(error),
        };
        let mut entries = Vec::new();
        let mut total_bytes = 0usize;
        let mut processed_items = 0usize;
        for result in read_dir {
            if let Ok(entry) = &result {
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(is_reserved_startup_folder_metadata)
                {
                    continue;
                }
            }
            if processed_items >= MAX_ITEMS_PER_SOURCE {
                return Ok((
                    entries,
                    SourceState::Truncated {
                        limit: MAX_ITEMS_PER_SOURCE,
                        reason: "The per-folder startup-item bound was reached.".into(),
                    },
                ));
            }
            processed_items += 1;
            match result {
                Ok(entry) => {
                    let item_path = entry.path();
                    let file_type = match entry.file_type() {
                        Ok(file_type) if file_type.is_file() || file_type.is_dir() => file_type,
                        Ok(_) => continue,
                        Err(error) => {
                            // Preserve source-level uncertainty rather than silently treating
                            // an unreadable directory child as no startup item.
                            return Ok((
                                entries,
                                SourceState::Failed {
                                    reason: format!(
                                        "A startup-folder item's type could not be read: {error}"
                                    ),
                                },
                            ));
                        }
                    };
                    let path_text = item_path.to_string_lossy().into_owned();
                    let name = entry.file_name();
                    let Some(program) = name.to_str().map(str::to_owned) else {
                        return Ok((
                            entries,
                            SourceState::Failed {
                                reason: "A startup-folder filename is not valid Unicode.".into(),
                            },
                        ));
                    };
                    let entry_bytes = path_text.len().saturating_mul(2) + program.len();
                    if total_bytes.saturating_add(entry_bytes) > MAX_REGISTRY_SOURCE_BYTES {
                        return Ok((
                            entries,
                            SourceState::Truncated {
                                limit: MAX_ITEMS_PER_SOURCE,
                                reason: "The per-folder startup data bound was reached.".into(),
                            },
                        ));
                    }
                    total_bytes += entry_bytes;
                    let file_snapshot = if file_type.is_file() {
                        startup_folder_file_snapshot(&item_path).ok()
                    } else {
                        None
                    };
                    let approval_result = match approval_access {
                        Ok(true) => read_registry_value(
                            approval_hive,
                            STARTUP_FOLDER_APPROVAL_KEY,
                            &program,
                        ),
                        Ok(false) => Ok(None),
                        Err(reason) => Err(StartupError::new(
                            StartupErrorKind::Inaccessible,
                            reason.clone(),
                        )),
                    };
                    let approval_readable = approval_result.is_ok();
                    let approval = match approval_result {
                        Ok(approval) => {
                            if approval.is_some() {
                                *marker_count = (*marker_count).saturating_add(1);
                            }
                            approval
                        }
                        Err(error) => {
                            if marker_errors.len() < 8 {
                                marker_errors.push(error.message);
                            }
                            None
                        }
                    };
                    let enabled = if approval_readable {
                        startup_approved_enabled(approval.as_ref())
                    } else {
                        EnabledState::Unknown {
                            reason: "The StartupApproved StartupFolder state could not be read."
                                .into(),
                        }
                    };
                    let marker_name_ambiguous = startup_folder_marker_name_is_ambiguous(
                        marker_names,
                        approval_hive,
                        &program,
                    );
                    let can_change = matches!(approval_access, Ok(true))
                        && marker_name_check_error.is_none()
                        && !marker_name_ambiguous
                        && file_snapshot.is_some()
                        && enabled.as_bool().is_some();
                    let change_limitation = if can_change {
                        None
                    } else if marker_name_check_error.is_some() {
                        Some("Startup-folder marker-name uniqueness could not be verified; this item is read-only.".into())
                    } else if marker_name_ambiguous {
                        Some("The StartupApproved marker name is ambiguous across Startup folders; this item is read-only.".into())
                    } else if !file_type.is_file() {
                        Some(
                            "Only regular files in the Startup folders use this reversible toggle."
                                .into(),
                        )
                    } else if !approval_readable {
                        Some("StartupApproved StartupFolder state is inaccessible.".into())
                    } else if matches!(approval_access, Ok(false)) {
                        Some(
                            "StartupApproved StartupFolder key is absent; this item is read-only."
                                .into(),
                        )
                    } else if file_snapshot.is_none() {
                        Some("Windows did not provide a stable file identity for this item.".into())
                    } else {
                        Some("The Startup-folder enabled state is unknown.".into())
                    };
                    let identity = EntryIdentity::StartupFolderItem {
                        path: path_text.clone(),
                    };
                    let is_shell_link = file_type.is_file()
                        && item_path
                            .extension()
                            .and_then(|extension| extension.to_str())
                            .is_some_and(|extension| extension.eq_ignore_ascii_case("lnk"));
                    let shell_link = is_shell_link
                        .then(|| read_shell_link_metadata(&item_path))
                        .flatten();
                    let metadata_path = if is_shell_link {
                        shell_link
                            .as_ref()
                            .and_then(|link| link.target_path.as_deref())
                            .map(Path::new)
                    } else if file_type.is_file() {
                        Some(item_path.as_path())
                    } else {
                        None
                    };
                    let file_metadata = metadata_path.and_then(|path| {
                        if *version_metadata_lookups >= MAX_STARTUP_VERSION_LOOKUPS {
                            None
                        } else {
                            *version_metadata_lookups += 1;
                            read_file_version_metadata(path)
                        }
                    });
                    let target_fallback = shell_link
                        .as_ref()
                        .and_then(|link| link.target_path.as_deref())
                        .and_then(|target| Path::new(target).file_stem())
                        .and_then(|stem| stem.to_str())
                        .filter(|stem| !stem.is_empty())
                        .unwrap_or(&program);
                    let program_label = startup_program_label(
                        shell_link
                            .as_ref()
                            .and_then(|link| link.description.as_deref()),
                        file_metadata.as_ref(),
                        target_fallback,
                    );
                    let publisher = startup_metadata_field(
                        file_metadata
                            .as_ref()
                            .and_then(|metadata| metadata.company_name.as_deref()),
                        "The startup target's CompanyName metadata is unavailable.",
                    );
                    let version = startup_metadata_field(
                        file_metadata
                            .as_ref()
                            .and_then(|metadata| metadata.file_version.as_deref()),
                        "The startup target's FileVersion metadata is unavailable.",
                    );
                    let display_path = if is_shell_link {
                        shell_link
                            .as_ref()
                            .and_then(|link| link.target_path.as_ref())
                            .cloned()
                            .map(FieldValue::known)
                            .unwrap_or_else(|| {
                                FieldValue::unknown("The Shell link target path could not be read.")
                            })
                    } else {
                        FieldValue::known(path_text)
                    };
                    entries.push(StartupEntry {
                        id: StartupId::for_identity(&identity),
                        section: StartupSection::StartupApps,
                        program: FieldValue::known(program_label),
                        publisher,
                        version,
                        file_path: display_path,
                        command: FieldValue::NotApplicable,
                        enabled,
                        identity,
                        can_change_enabled: can_change,
                        change_limitation,
                    });
                }
                Err(error) => {
                    return Ok((
                        entries,
                        SourceState::Failed {
                            reason: format!("A startup-folder item could not be read: {error}"),
                        },
                    ));
                }
            }
        }
        let count = entries.len();
        Ok((entries, SourceState::Read { items: count }))
    }

    fn startup_folder_name_counts() -> (StartupFolderMarkerCounts, Option<String>) {
        let mut counts = HashMap::new();
        let mut scanned_roots = Vec::<PathBuf>::new();
        for (_, root) in startup_folder_paths() {
            if scanned_roots
                .iter()
                .any(|scanned| same_windows_path(scanned, &root))
            {
                continue;
            }
            scanned_roots.push(root.clone());
            let approval_hive = match startup_folder_root_approval_hive(&root) {
                Ok(hive) => hive,
                Err(error) => return (counts, Some(error.message)),
            };
            let read_dir = match std::fs::read_dir(&root) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {
                    return (
                        counts,
                        Some(
                            "A Startup folder could not be read for marker-name collision checks."
                                .into(),
                        ),
                    );
                }
            };
            let mut processed_items = 0usize;
            for entry in read_dir {
                if let Ok(entry) = &entry {
                    if entry
                        .file_name()
                        .to_str()
                        .is_some_and(is_reserved_startup_folder_metadata)
                    {
                        continue;
                    }
                }
                if processed_items >= MAX_ITEMS_PER_SOURCE {
                    return (
                        counts,
                        Some("The Startup-folder marker-name collision check reached its item bound.".into()),
                    );
                }
                processed_items += 1;
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => {
                        return (
                            counts,
                            Some("A Startup-folder item could not be checked for marker-name collisions.".into()),
                        );
                    }
                };
                let name = match entry.file_name().to_str().map(str::to_owned) {
                    Some(name) => name,
                    None => {
                        return (
                            counts,
                            Some("A Startup-folder filename could not be checked for marker-name collisions.".into()),
                        );
                    }
                };
                let count = counts
                    .entry((approval_hive, name.to_lowercase()))
                    .or_insert(0usize);
                *count = count.saturating_add(1);
            }
        }
        (counts, None)
    }

    fn read_registry_values(
        hive: RegistryHive,
        subkey: &str,
    ) -> Result<Option<(Vec<(String, RegistryValueSnapshot)>, bool)>, StartupError> {
        let Some(key) = open_registry_key(hive, subkey, KEY_READ)? else {
            return Ok(None);
        };
        let mut values = Vec::new();
        let mut total_bytes = 0usize;
        let mut truncated = false;
        let mut name_buffer = vec![0u16; 16_384];
        for index in 0..=MAX_ITEMS_PER_SOURCE {
            let mut name_len = name_buffer.len() as u32;
            let code = unsafe {
                RegEnumValueW(
                    key.0,
                    index as u32,
                    Some(PWSTR(name_buffer.as_mut_ptr())),
                    &mut name_len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if code == ERROR_NO_MORE_ITEMS {
                break;
            }
            if code != ERROR_SUCCESS {
                return Err(registry_error("enumerate registry values", code.0));
            }
            let name = String::from_utf16_lossy(&name_buffer[..name_len as usize]);
            let value = read_registry_value(hive, subkey, &name)?.ok_or_else(|| {
                StartupError::new(
                    StartupErrorKind::ChangedSinceReview,
                    "A registry value disappeared during inventory.",
                )
            })?;
            let entry_bytes = name.encode_utf16().count() * 2 + value.data.len();
            if total_bytes.saturating_add(entry_bytes) > MAX_REGISTRY_SOURCE_BYTES {
                truncated = true;
                break;
            }
            total_bytes += entry_bytes;
            values.push((name, value));
            if values.len() >= MAX_ITEMS_PER_SOURCE {
                truncated = true;
                break;
            }
        }
        Ok(Some((values, truncated)))
    }

    fn read_registry_subkeys(
        hive: RegistryHive,
        subkey: &str,
    ) -> Result<Option<(Vec<String>, bool)>, StartupError> {
        let Some(key) = open_registry_key(hive, subkey, KEY_READ)? else {
            return Ok(None);
        };
        let mut names = Vec::new();
        let mut total_bytes = 0usize;
        let mut truncated = false;
        let mut name_buffer = vec![0u16; 16_384];
        for index in 0..=MAX_CONTEXT_REGISTRATIONS {
            let mut name_len = name_buffer.len() as u32;
            let code = unsafe {
                RegEnumKeyExW(
                    key.0,
                    index as u32,
                    Some(PWSTR(name_buffer.as_mut_ptr())),
                    &mut name_len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if code == ERROR_NO_MORE_ITEMS {
                break;
            }
            if code != ERROR_SUCCESS {
                return Err(registry_error("enumerate registry subkeys", code.0));
            }
            let name = String::from_utf16_lossy(&name_buffer[..name_len as usize]);
            let name_bytes = name.encode_utf16().count() * 2;
            if total_bytes.saturating_add(name_bytes) > MAX_REGISTRY_SOURCE_BYTES {
                truncated = true;
                break;
            }
            total_bytes += name_bytes;
            names.push(name);
            if names.len() >= MAX_CONTEXT_REGISTRATIONS {
                truncated = true;
                break;
            }
        }
        Ok(Some((names, truncated)))
    }

    fn read_registry_value(
        hive: RegistryHive,
        subkey: &str,
        value_name: &str,
    ) -> Result<Option<RegistryValueSnapshot>, StartupError> {
        let Some(key) = open_registry_key(hive, subkey, KEY_READ)? else {
            return Ok(None);
        };
        read_registry_value_on_handle(key.0, value_name)
    }

    fn read_registry_value_on_handle(
        key: HKEY,
        value_name: &str,
    ) -> Result<Option<RegistryValueSnapshot>, StartupError> {
        let value_name_wide = wide(value_name);
        let value_name_ptr = PCWSTR(value_name_wide.as_ptr());
        let mut value_type = REG_VALUE_TYPE(0);
        let mut length = 0u32;
        let first = unsafe {
            RegQueryValueExW(
                key,
                value_name_ptr,
                None,
                Some(&mut value_type),
                None,
                Some(&mut length),
            )
        };
        if first.0 == ERROR_FILE_NOT_FOUND.0 {
            return Ok(None);
        }
        if first != ERROR_SUCCESS && first != ERROR_MORE_DATA {
            return Err(registry_error("query registry value size", first.0));
        }
        if length as usize > MAX_REGISTRY_VALUE_BYTES {
            return Err(StartupError::new(
                StartupErrorKind::Inaccessible,
                "Registry value exceeds the 1 MiB safe read bound.",
            ));
        }
        let mut data = vec![0u8; length as usize];
        let code = unsafe {
            RegQueryValueExW(
                key,
                value_name_ptr,
                None,
                Some(&mut value_type),
                Some(data.as_mut_ptr()),
                Some(&mut length),
            )
        };
        if code.0 == ERROR_FILE_NOT_FOUND.0 {
            return Ok(None);
        }
        if code != ERROR_SUCCESS {
            return Err(registry_error("read registry value", code.0));
        }
        data.truncate(length as usize);
        Ok(Some(RegistryValueSnapshot {
            value_type: value_type.0,
            data,
        }))
    }

    fn write_registry_approval(
        approval_hive: RegistryHive,
        run_hive: RegistryHive,
        run_key_path: &str,
        expected: &ObservedState,
        approval_key_path: &str,
        name: &str,
        value: Option<&RegistryValueSnapshot>,
    ) -> Result<(), StartupError> {
        let access = REG_SAM_FLAGS(KEY_QUERY_VALUE.0 | KEY_SET_VALUE.0);
        let run_key =
            open_registry_key(run_hive, run_key_path, KEY_QUERY_VALUE)?.ok_or_else(|| {
                StartupError::new(
                    StartupErrorKind::ChangedSinceReview,
                    "The selected Run key no longer exists.",
                )
            })?;
        let approval_key = open_registry_key(approval_hive, approval_key_path, access)?
            .ok_or_else(|| {
                StartupError::new(
                    StartupErrorKind::Inaccessible,
                    "StartupApproved key is absent; the selected item was not changed.",
                )
            })?;
        let (expected_value, expected_approval) = match &expected.native {
            NativeState::StartupRunValue { value, approval } => (value, approval),
            _ => {
                return Err(StartupError::new(
                    StartupErrorKind::InvalidIntent,
                    "The selected item is not a Run registry value.",
                ));
            }
        };
        let current_value = read_registry_value_on_handle(run_key.0, name)?;
        let current_approval = read_registry_value_on_handle(approval_key.0, name)?;
        if current_value.as_ref() != Some(expected_value) || &current_approval != expected_approval
        {
            return Err(StartupError::new(
                StartupErrorKind::ChangedSinceReview,
                "The selected Run registration changed immediately before the write.",
            ));
        }
        let name_wide = wide(name);
        let status = match value {
            Some(value) => unsafe {
                RegSetValueExW(
                    approval_key.0,
                    PCWSTR(name_wide.as_ptr()),
                    None,
                    REG_VALUE_TYPE(value.value_type),
                    Some(&value.data),
                )
            },
            None => unsafe { RegDeleteValueW(approval_key.0, PCWSTR(name_wide.as_ptr())) },
        };
        if status != ERROR_SUCCESS {
            return Err(registry_error("write StartupApproved state", status.0));
        }
        Ok(())
    }

    fn write_startup_folder_approval(
        path: &str,
        expected: &StartupFolderSnapshot,
        desired: &StartupFolderSnapshot,
    ) -> Result<(), StartupError> {
        if expected.file != desired.file {
            return Err(StartupError::new(
                StartupErrorKind::InvalidIntent,
                "The Startup-folder change does not preserve the selected file identity.",
            ));
        }
        let current_file = startup_folder_file_snapshot(Path::new(path))?;
        if current_file != expected.file {
            return Err(StartupError::new(
                StartupErrorKind::ChangedSinceReview,
                "The selected Startup-folder file changed immediately before the write.",
            ));
        }
        let name = Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                StartupError::new(
                    StartupErrorKind::Unsupported,
                    "The Startup-folder filename cannot be represented in the approval key.",
                )
            })?;
        let approval_hive = startup_folder_approval_hive(Path::new(path))?;
        ensure_startup_folder_marker_unambiguous(name, approval_hive)?;
        let access = REG_SAM_FLAGS(KEY_QUERY_VALUE.0 | KEY_SET_VALUE.0);
        let approval_key = open_registry_key(approval_hive, STARTUP_FOLDER_APPROVAL_KEY, access)?
            .ok_or_else(|| {
            StartupError::new(
                StartupErrorKind::Inaccessible,
                "StartupApproved StartupFolder key is absent; the selected item was not changed.",
            )
        })?;
        let current_approval = read_registry_value_on_handle(approval_key.0, name)?;
        if current_approval != expected.approval {
            return Err(StartupError::new(
                StartupErrorKind::ChangedSinceReview,
                "The Startup-folder approval marker changed immediately before the write.",
            ));
        }
        write_registry_value_on_handle(approval_key.0, name, desired.approval.as_ref()).map_err(
            |error| {
                StartupError::new(
                    error.kind,
                    format!(
                        "The Startup-folder enabled state could not be written: {}",
                        error.message
                    ),
                )
            },
        )
    }

    fn write_context_verb(
        key: &str,
        registration: &str,
        expected: &ContextMenuVerbSnapshot,
        desired: &ContextMenuVerbSnapshot,
    ) -> Result<(), StartupError> {
        if !is_plain_shell_key(key)
            || registration.is_empty()
            || registration.contains('\\')
            || registration.contains('/')
            || expected.command != desired.command
        {
            return Err(StartupError::new(
                StartupErrorKind::InvalidIntent,
                "The context-menu change does not preserve one static verb identity.",
            ));
        }
        let verb_key_path = format!("{key}\\{registration}");
        let command_key_path = format!("{verb_key_path}\\command");
        let access = REG_SAM_FLAGS(KEY_QUERY_VALUE.0 | KEY_SET_VALUE.0);
        let verb_key = open_registry_key(RegistryHive::CurrentUser, &verb_key_path, access)?
            .ok_or_else(|| {
                StartupError::new(
                    StartupErrorKind::ChangedSinceReview,
                    "The selected context-menu verb no longer exists.",
                )
            })?;
        let command_key =
            open_registry_key(RegistryHive::CurrentUser, &command_key_path, KEY_READ)?.ok_or_else(
                || {
                    StartupError::new(
                        StartupErrorKind::ChangedSinceReview,
                        "The selected context-menu command key no longer exists.",
                    )
                },
            )?;
        let command = read_registry_value_on_handle(command_key.0, "")?;
        let legacy_disable = read_registry_value_on_handle(verb_key.0, "LegacyDisable")?;
        if command.as_ref() != Some(&expected.command)
            || legacy_disable != expected.legacy_disable
            || context_verb_has_delegate_on_handles(verb_key.0, command_key.0)?
        {
            return Err(StartupError::new(
                StartupErrorKind::ChangedSinceReview,
                "The selected context-menu command changed immediately before the write.",
            ));
        }
        write_registry_value_on_handle(verb_key.0, "LegacyDisable", desired.legacy_disable.as_ref())
    }

    fn context_verb_has_delegate_on_handles(
        verb_key: HKEY,
        command_key: HKEY,
    ) -> Result<bool, StartupError> {
        for (key, name) in [
            (verb_key, "DelegateExecute"),
            (verb_key, "ExplorerCommandHandler"),
            (verb_key, "CommandStateHandler"),
            (command_key, "DelegateExecute"),
            (command_key, "ExplorerCommandHandler"),
            (command_key, "CommandStateHandler"),
        ] {
            if read_registry_value_on_handle(key, name)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn write_registry_value_on_handle(
        key: HKEY,
        name: &str,
        value: Option<&RegistryValueSnapshot>,
    ) -> Result<(), StartupError> {
        let name_wide = wide(name);
        let status = match value {
            Some(value) => unsafe {
                RegSetValueExW(
                    key,
                    PCWSTR(name_wide.as_ptr()),
                    None,
                    REG_VALUE_TYPE(value.value_type),
                    Some(&value.data),
                )
            },
            None => unsafe { RegDeleteValueW(key, PCWSTR(name_wide.as_ptr())) },
        };
        if status != ERROR_SUCCESS {
            return Err(registry_error("write registry value", status.0));
        }
        Ok(())
    }

    fn open_registry_key(
        hive: RegistryHive,
        subkey: &str,
        access: REG_SAM_FLAGS,
    ) -> Result<Option<RegistryHandle>, StartupError> {
        let root = match hive {
            RegistryHive::CurrentUser => HKEY_CURRENT_USER,
            RegistryHive::LocalMachine => HKEY_LOCAL_MACHINE,
        };
        let subkey = wide(subkey);
        let mut opened = HKEY(ptr::null_mut());
        let status =
            unsafe { RegOpenKeyExW(root, PCWSTR(subkey.as_ptr()), None, access, &mut opened) };
        if status.0 == ERROR_FILE_NOT_FOUND.0 || status.0 == 3 {
            return Ok(None);
        }
        if status.0 == ERROR_ACCESS_DENIED.0 {
            return Err(StartupError::new(
                StartupErrorKind::Inaccessible,
                "Registry access was denied.",
            ));
        }
        if status != ERROR_SUCCESS {
            return Err(registry_error("open registry key", status.0));
        }
        Ok(Some(RegistryHandle(opened)))
    }

    fn registry_key_exists(hive: RegistryHive, subkey: &str) -> Result<bool, StartupError> {
        Ok(open_registry_key(hive, subkey, KEY_READ)?.is_some())
    }

    struct RegistryHandle(HKEY);
    impl Drop for RegistryHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    fn registry_source_error(error: StartupError) -> SourceState {
        if error.kind == StartupErrorKind::Inaccessible {
            SourceState::Inaccessible {
                reason: error.message,
            }
        } else {
            SourceState::Failed {
                reason: error.message,
            }
        }
    }

    fn registry_error(action: &str, code: u32) -> StartupError {
        let kind = if code == ERROR_ACCESS_DENIED.0 {
            StartupErrorKind::Inaccessible
        } else {
            StartupErrorKind::NativeFailure
        };
        StartupError::new(kind, format!("Could not {action} (Windows error {code})."))
    }

    fn registry_value_string(value: &RegistryValueSnapshot) -> Option<String> {
        if value.value_type != REG_SZ.0 && value.value_type != REG_EXPAND_SZ.0 {
            return None;
        }
        if value.data.len() % 2 != 0 {
            return None;
        }
        let units = value
            .data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|unit| *unit != 0)
            .collect::<Vec<_>>();
        Some(String::from_utf16_lossy(&units))
    }

    trait KnownFieldExt {
        fn known_value(&self) -> Option<&str>;
    }

    impl KnownFieldExt for FieldValue<String> {
        fn known_value(&self) -> Option<&str> {
            match self {
                FieldValue::Known { value } => Some(value),
                _ => None,
            }
        }
    }

    fn executable_from_command(command: &str) -> Option<String> {
        let command = command.trim();
        if command.is_empty() {
            return None;
        }
        if let Some(rest) = command.strip_prefix('"') {
            let end = rest.find('"')?;
            let value = rest[..end].trim();
            return (!value.is_empty()).then(|| value.to_string());
        }
        let lower = command.to_ascii_lowercase();
        for extension in [".exe", ".com", ".cmd", ".bat", ".scr"] {
            if let Some(index) = lower.find(extension) {
                return Some(command[..index + extension.len()].trim().to_string());
            }
        }
        command.split_whitespace().next().map(str::to_string)
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn wide_ptr_to_string(value: PWSTR) -> String {
        if value.0.is_null() {
            return String::new();
        }
        unsafe {
            let mut length = 0usize;
            while *value.0.add(length) != 0 {
                length += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(value.0, length))
        }
    }

    fn hresult_text(code: i32) -> String {
        format!("HRESULT 0x{:08X}", code as u32)
    }

    fn find_identity_by_id(
        platform: &mut WindowsStartupPlatform,
        id: &StartupId,
    ) -> Result<EntryIdentity, StartupError> {
        let section = if id.0.starts_with("st-sa-") {
            StartupSection::StartupApps
        } else if id.0.starts_with("st-st-") {
            StartupSection::ScheduledTasks
        } else if id.0.starts_with("st-cm-") {
            StartupSection::ContextMenu
        } else if id.0.starts_with("st-sv-") {
            StartupSection::WindowsServices
        } else {
            return Err(StartupError::new(
                StartupErrorKind::UnknownId,
                "The selected startup ID is not recognized.",
            ));
        };
        let mut matches = platform
            .inventory(section)
            .entries
            .into_iter()
            .filter(|entry| entry.id == *id)
            .map(|entry| entry.identity)
            .collect::<Vec<_>>();
        match matches.len() {
            0 => Err(StartupError::new(
                StartupErrorKind::UnknownId,
                "The selected startup item no longer exists.",
            )),
            1 => Ok(matches.remove(0)),
            _ => Err(StartupError::new(
                StartupErrorKind::ChangedSinceReview,
                "The selected startup ID is ambiguous.",
            )),
        }
    }

    fn task_parent(path: &str) -> &str {
        let trimmed = path.trim_end_matches('\\');
        match trimmed.rfind('\\') {
            Some(0) | None => "\\",
            Some(index) => &trimmed[..index],
        }
    }

    fn task_leaf(path: &str) -> &str {
        path.trim_end_matches('\\')
            .rsplit('\\')
            .next()
            .unwrap_or(path)
    }

    fn observe_startup_folder(id: &StartupId, path: String) -> Result<ObservedState, StartupError> {
        let file = startup_folder_file_snapshot(Path::new(&path))?;
        let approval_hive = startup_folder_approval_hive(Path::new(&path))?;
        if !registry_key_exists(approval_hive, STARTUP_FOLDER_APPROVAL_KEY)? {
            return Err(StartupError::new(
                StartupErrorKind::Unsupported,
                "The StartupApproved StartupFolder key is absent; this item is inventory-only.",
            ));
        }
        let file_name = Path::new(&path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                StartupError::new(
                    StartupErrorKind::Unsupported,
                    "The startup-folder item has no supported Unicode filename.",
                )
            })?;
        ensure_startup_folder_marker_unambiguous(file_name, approval_hive)?;
        let approval = read_registry_value(approval_hive, STARTUP_FOLDER_APPROVAL_KEY, file_name)?;
        let enabled = startup_approved_enabled(approval.as_ref());
        Ok(ObservedState {
            id: id.clone(),
            identity: EntryIdentity::StartupFolderItem { path },
            enabled,
            native: NativeState::StartupFolderItem {
                snapshot: StartupFolderSnapshot { approval, file },
            },
        })
    }

    fn startup_folder_file_snapshot(
        path: &Path,
    ) -> Result<StartupFolderFileSnapshot, StartupError> {
        let parent = path.parent().ok_or_else(|| {
            StartupError::new(
                StartupErrorKind::Unsupported,
                "The selected path is not inside a supported Startup folder.",
            )
        })?;
        if !startup_folder_paths()
            .iter()
            .any(|(_, root)| same_windows_path(parent, root))
        {
            return Err(StartupError::new(
                StartupErrorKind::Unsupported,
                "The selected path is outside the user or common Startup folder.",
            ));
        }
        let path_text = path.to_str().ok_or_else(|| {
            StartupError::new(
                StartupErrorKind::Unsupported,
                "The Startup-folder item path is not valid Unicode.",
            )
        })?;
        let path_wide = wide(path_text);
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                FILE_READ_ATTRIBUTES.0,
                FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0),
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map(StartupFileHandle)
        .map_err(|error| {
            let code = error.code().0 as u32;
            let kind = if code == 0x8007_0005 {
                StartupErrorKind::Inaccessible
            } else if code == 0x8007_0002 {
                StartupErrorKind::UnknownId
            } else {
                StartupErrorKind::NativeFailure
            };
            StartupError::new(
                kind,
                format!(
                    "The selected Startup-folder file could not be opened (Windows status 0x{code:08X})."
                ),
            )
        })?;
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(handle.0, &mut information) }.map_err(|error| {
            StartupError::new(
                StartupErrorKind::NativeFailure,
                format!(
                    "Windows could not read the selected Startup-folder file identity (HRESULT 0x{:08X}).",
                    error.code().0 as u32
                ),
            )
        })?;
        if information.dwFileAttributes
            & (FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_REPARSE_POINT.0)
            != 0
        {
            return Err(StartupError::new(
                StartupErrorKind::Unsupported,
                "Only regular, non-reparse files in a supported Startup folder can be changed.",
            ));
        }
        let file_index =
            (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
        let file_size =
            (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow);
        let last_write_time = (u64::from(information.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(information.ftLastWriteTime.dwLowDateTime);
        Ok(StartupFolderFileSnapshot {
            volume_serial: information.dwVolumeSerialNumber,
            file_index,
            file_size,
            last_write_time,
            attributes: information.dwFileAttributes,
        })
    }

    struct StartupFileHandle(HANDLE);
    impl Drop for StartupFileHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn same_windows_path(left: &Path, right: &Path) -> bool {
        let left = std::fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf());
        let right = std::fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf());
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }

    fn ensure_startup_folder_marker_unambiguous(
        name: &str,
        approval_hive: RegistryHive,
    ) -> Result<(), StartupError> {
        let (counts, error) = startup_folder_name_counts();
        if let Some(reason) = error {
            return Err(StartupError::new(StartupErrorKind::Unsupported, reason));
        }
        if startup_folder_marker_name_is_ambiguous(&counts, approval_hive, name) {
            return Err(StartupError::new(
                StartupErrorKind::Unsupported,
                "The StartupApproved marker name is ambiguous within this registry hive.",
            ));
        }
        Ok(())
    }

    fn observe_context_verb(
        id: &StartupId,
        key: String,
        registration: String,
    ) -> Result<ObservedState, StartupError> {
        if !is_plain_shell_key(&key)
            || registration.is_empty()
            || registration.contains('\\')
            || registration.contains('/')
        {
            return Err(StartupError::new(
                StartupErrorKind::Unsupported,
                "Only a single per-user static shell verb can be changed.",
            ));
        }
        let full_key = format!("{key}\\{registration}");
        let command_key = format!("{full_key}\\command");
        let command = read_registry_value(RegistryHive::CurrentUser, &command_key, "")?
            .ok_or_else(|| {
                StartupError::new(
                    StartupErrorKind::Unsupported,
                    "The selected shell verb has no command value and is inventory-only.",
                )
            })?;
        if command.value_type != REG_SZ.0 && command.value_type != REG_EXPAND_SZ.0
            || context_verb_has_delegate(RegistryHive::CurrentUser, &full_key, Some(&command_key))?
        {
            return Err(StartupError::new(
                StartupErrorKind::Unsupported,
                "Delegated or non-string shell verbs are inventory-only.",
            ));
        }
        let legacy_disable =
            read_registry_value(RegistryHive::CurrentUser, &full_key, "LegacyDisable")?;
        let enabled = if legacy_disable.is_some() {
            EnabledState::Disabled
        } else {
            EnabledState::Enabled
        };
        Ok(ObservedState {
            id: id.clone(),
            identity: EntryIdentity::ContextMenuRegistration {
                hive: RegistryHive::CurrentUser,
                key,
                registration,
            },
            enabled,
            native: NativeState::ContextMenuVerb {
                snapshot: ContextMenuVerbSnapshot {
                    legacy_disable,
                    command,
                },
            },
        })
    }

    fn observe_task(
        id: &StartupId,
        path: String,
        task: &IRegisteredTask,
    ) -> Result<ObservedState, StartupError> {
        let enabled = unsafe { task.Enabled() }
            .map(|value| EnabledState::from_bool(value.0 != 0))
            .map_err(|error| {
                StartupError::new(
                    StartupErrorKind::NativeFailure,
                    format!(
                        "Could not read scheduled-task enabled state: {}",
                        hresult_text(error.code().0)
                    ),
                )
            })?;
        let xml = unsafe { task.Xml() }.map_err(|error| {
            StartupError::new(
                StartupErrorKind::NativeFailure,
                format!(
                    "Could not read scheduled-task identity: {}",
                    hresult_text(error.code().0)
                ),
            )
        })?;
        let xml_text = String::from_utf16_lossy(xml.as_ref());
        let xml = if xml_text.encode_utf16().count() <= MAX_TASK_XML_UNITS {
            Some(task_definition_fingerprint(&xml_text))
        } else {
            None
        };
        Ok(ObservedState {
            id: id.clone(),
            identity: EntryIdentity::ScheduledTask { path },
            enabled,
            native: NativeState::ScheduledTask { xml },
        })
    }

    // IRegisteredTask::Enabled is a separate native state and is often reflected by
    // the task XML's <Enabled> setting. Excluding that node keeps the snapshot stable
    // across our reversible enabled toggle while still revalidating all other task
    // definition content before a write or restore.
    fn task_definition_fingerprint(xml: &str) -> String {
        let bytes = xml.as_bytes();
        let mut output = String::with_capacity(xml.len());
        let mut cursor = 0usize;
        let mut skip_depth = 0usize;

        while cursor < bytes.len() {
            if bytes[cursor] != b'<' {
                let end = bytes[cursor..]
                    .iter()
                    .position(|byte| *byte == b'<')
                    .map_or(bytes.len(), |offset| cursor + offset);
                if skip_depth == 0 {
                    output.push_str(&xml[cursor..end]);
                }
                cursor = end;
                continue;
            }

            let rest = &xml[cursor..];
            let special_end = if rest.starts_with("<!--") {
                rest.find("-->").map(|offset| cursor + offset + 3)
            } else if rest.starts_with("<![CDATA[") {
                rest.find("]]>").map(|offset| cursor + offset + 3)
            } else if rest.starts_with("<?") {
                rest.find("?>").map(|offset| cursor + offset + 2)
            } else {
                None
            };
            if let Some(end) = special_end {
                if skip_depth == 0 {
                    output.push_str(&xml[cursor..end]);
                }
                cursor = end;
                continue;
            }

            let mut quote = None;
            let mut end = cursor + 1;
            while end < bytes.len() {
                let byte = bytes[end];
                match (quote, byte) {
                    (Some(active), value) if active == value => quote = None,
                    (None, b'\'' | b'"') => quote = Some(byte),
                    (None, b'>') => break,
                    _ => {}
                }
                end += 1;
            }
            if end == bytes.len() {
                if skip_depth == 0 {
                    output.push_str(&xml[cursor..]);
                }
                break;
            }

            let token = &xml[cursor..=end];
            let body = &xml[cursor + 1..end];
            if body.starts_with('!') {
                if skip_depth == 0 {
                    output.push_str(token);
                }
                cursor = end + 1;
                continue;
            }
            let closing = body.starts_with('/');
            let name_start = usize::from(closing);
            let name_end = body[name_start..]
                .find(|character: char| character.is_whitespace() || character == '/')
                .map_or(body.len(), |offset| name_start + offset);
            let qualified_name = &body[name_start..name_end];
            let local_name = qualified_name.rsplit(':').next().unwrap_or(qualified_name);
            let self_closing = body.trim_end().ends_with('/');

            if skip_depth == 0 {
                if !closing && local_name.eq_ignore_ascii_case("Enabled") {
                    if !self_closing {
                        skip_depth = 1;
                    }
                } else {
                    output.push_str(token);
                }
            } else if closing {
                skip_depth = skip_depth.saturating_sub(1);
            } else if !self_closing {
                skip_depth = skip_depth.saturating_add(1);
            }
            cursor = end + 1;
        }
        output
    }

    struct TaskClient {
        service: ITaskService,
        _apartment: ComApartment,
    }

    struct TaskHandle {
        task: IRegisteredTask,
        _apartment: ComApartment,
    }

    impl TaskClient {
        fn connect() -> Result<Self, String> {
            let apartment = ComApartment::initialize()?;
            let service: ITaskService =
                unsafe { CoCreateInstance(&CLSID_TASK_SCHEDULER_V2, None, CLSCTX_INPROC_SERVER) }
                    .map_err(|error| {
                    format!(
                        "Task Scheduler COM activation failed: {}",
                        hresult_text(error.code().0)
                    )
                })?;
            let empty = VARIANT::default();
            unsafe { service.Connect(&empty, &empty, &empty, &empty) }.map_err(|error| {
                format!(
                    "Task Scheduler connection failed: {}",
                    hresult_text(error.code().0)
                )
            })?;
            Ok(Self {
                service,
                _apartment: apartment,
            })
        }

        fn root_folder(&mut self) -> Result<ITaskFolder, String> {
            self.get_folder("\\")
        }

        fn get_folder(&mut self, path: &str) -> Result<ITaskFolder, String> {
            let bstr = BSTR::from(path);
            unsafe { self.service.GetFolder(&bstr) }.map_err(|error| {
                format!(
                    "Task Scheduler folder could not be read: {}",
                    hresult_text(error.code().0)
                )
            })
        }
    }

    struct ComApartment;
    impl ComApartment {
        fn initialize() -> Result<Self, String> {
            unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
                .ok()
                .map_err(|error| {
                    format!(
                        "COM apartment initialization failed: {}",
                        hresult_text(error.code().0)
                    )
                })?;
            Ok(Self)
        }
    }
    impl Drop for ComApartment {
        fn drop(&mut self) {
            unsafe {
                CoUninitialize();
            }
        }
    }

    fn enumerate_task_folder(
        folder: &ITaskFolder,
        depth: usize,
        folder_count: &mut usize,
        entries: &mut Vec<StartupEntry>,
        sources: &mut Vec<SourceOutcome>,
        truncated: &mut bool,
    ) {
        if depth > MAX_TASK_DEPTH || *folder_count >= MAX_ITEMS_PER_SOURCE {
            *truncated = true;
            return;
        }
        *folder_count += 1;
        let folder_path = unsafe { folder.Path() }
            .map(|value| String::from_utf16_lossy(value.as_ref()))
            .unwrap_or_else(|_| "<unreadable task folder>".into());
        match unsafe { folder.GetTasks(TASK_ENUM_HIDDEN.0) } {
            Ok(tasks) => {
                match unsafe { tasks.Count() } {
                    Ok(count) => {
                        for index in 1..=count.max(0) {
                            if entries.len() >= MAX_ITEMS_PER_SOURCE {
                                *truncated = true;
                                return;
                            }
                            let mut index_variant = integer_variant(index);
                            let task = unsafe { tasks.get_Item(&index_variant) };
                            unsafe {
                                let _ = windows::Win32::System::Variant::VariantClear(
                                    &mut index_variant,
                                );
                            }
                            match task {
                            Ok(task) => match (unsafe { task.Path() }, unsafe { task.Name() }, unsafe { task.Enabled() }) {
                                (Ok(path), Ok(name), Ok(enabled)) => {
                                    let path = String::from_utf16_lossy(path.as_ref());
                                    let name = String::from_utf16_lossy(name.as_ref());
                                    let identity = EntryIdentity::ScheduledTask { path: path.clone() };
                                    let id = StartupId::for_identity(&identity);
                                    let xml = unsafe { task.Xml() }.ok().map(|value| String::from_utf16_lossy(value.as_ref()));
                                    let xml = xml.filter(|value| value.encode_utf16().count() <= MAX_TASK_XML_UNITS);
                                    let can_change = xml.is_some();
                                    entries.push(StartupEntry {
                                        id,
                                        section: StartupSection::ScheduledTasks,
                                        program: FieldValue::known(name),
                                        publisher: FieldValue::unknown("Task author metadata was not queried."),
                                        version: FieldValue::NotApplicable,
                                        file_path: FieldValue::unknown("Task Scheduler task identity is shown; action executable parsing is unavailable."),
                                        command: FieldValue::NotApplicable,
                                        enabled: EnabledState::from_bool(enabled.0 != 0),
                                        identity,
                                        can_change_enabled: can_change,
                                        change_limitation: (!can_change).then(|| "Task definition exceeds the safe snapshot bound or could not be read.".into()),
                                    });
                                }
                                _ => sources.push(SourceOutcome {
                                    source: format!("Task Scheduler task in {folder_path}"),
                                    state: SourceState::Failed { reason: "A task's identity or enabled state could not be read.".into() },
                                }),
                            },
                            Err(error) => sources.push(SourceOutcome {
                                source: format!("Task Scheduler folder {folder_path}"),
                                state: SourceState::Failed { reason: format!("A task could not be read: {}", hresult_text(error.code().0)) },
                            }),
                        }
                        }
                    }
                    Err(error) => sources.push(SourceOutcome {
                        source: format!("Task Scheduler folder {folder_path}"),
                        state: SourceState::Failed {
                            reason: format!(
                                "Task list count failed: {}",
                                hresult_text(error.code().0)
                            ),
                        },
                    }),
                }
            }
            Err(error) => sources.push(SourceOutcome {
                source: format!("Task Scheduler folder {folder_path}"),
                state: SourceState::Inaccessible {
                    reason: format!(
                        "Task list could not be read: {}",
                        hresult_text(error.code().0)
                    ),
                },
            }),
        }
        if *folder_count >= MAX_ITEMS_PER_SOURCE {
            *truncated = true;
            return;
        }
        match unsafe { folder.GetFolders(0) } {
            Ok(folders) => match unsafe { folders.Count() } {
                Ok(count) => {
                    for index in 1..=count.max(0) {
                        if *folder_count >= MAX_ITEMS_PER_SOURCE {
                            *truncated = true;
                            return;
                        }
                        let mut index_variant = integer_variant(index);
                        let child = unsafe { folders.get_Item(&index_variant) };
                        unsafe {
                            let _ =
                                windows::Win32::System::Variant::VariantClear(&mut index_variant);
                        }
                        match child {
                            Ok(child) => enumerate_task_folder(
                                &child,
                                depth + 1,
                                folder_count,
                                entries,
                                sources,
                                truncated,
                            ),
                            Err(error) => sources.push(SourceOutcome {
                                source: format!("Task Scheduler folder {folder_path}"),
                                state: SourceState::Inaccessible {
                                    reason: format!(
                                        "A child folder could not be read: {}",
                                        hresult_text(error.code().0)
                                    ),
                                },
                            }),
                        }
                        if *truncated {
                            return;
                        }
                    }
                }
                Err(error) => sources.push(SourceOutcome {
                    source: format!("Task Scheduler folder {folder_path}"),
                    state: SourceState::Failed {
                        reason: format!(
                            "Folder list count failed: {}",
                            hresult_text(error.code().0)
                        ),
                    },
                }),
            },
            Err(error) => sources.push(SourceOutcome {
                source: format!("Task Scheduler folder {folder_path}"),
                state: SourceState::Inaccessible {
                    reason: format!(
                        "Child folders could not be read: {}",
                        hresult_text(error.code().0)
                    ),
                },
            }),
        }
    }

    fn integer_variant(value: i32) -> VARIANT {
        let mut variant = VARIANT::default();
        variant.Anonymous.Anonymous = ManuallyDrop::new(VARIANT_0_0 {
            vt: VT_I4,
            wReserved1: 0,
            wReserved2: 0,
            wReserved3: 0,
            Anonymous: VARIANT_0_0_0 { lVal: value },
        });
        variant
    }

    struct ServiceHandle(SC_HANDLE);
    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }

    fn service_manager(access: u32) -> Result<ServiceHandle, String> {
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }
            .map(ServiceHandle)
            .map_err(|error| {
                format!(
                    "Service Control Manager is unavailable ({}).",
                    error.code().0 as u32
                )
            })
    }

    fn open_service(
        manager: SC_HANDLE,
        name: &str,
        access: u32,
    ) -> Result<ServiceHandle, StartupError> {
        let name = wide(name);
        unsafe { OpenServiceW(manager, PCWSTR(name.as_ptr()), access) }
            .map(ServiceHandle)
            .map_err(|error| {
                StartupError::new(
                    StartupErrorKind::Inaccessible,
                    format!(
                        "The selected service could not be opened (Windows error {}).",
                        error.code().0 as u32
                    ),
                )
            })
    }

    fn enumerate_services(manager: SC_HANDLE) -> Result<(Vec<(String, String)>, bool), String> {
        let mut buffer = vec![0u8; 64 * 1024];
        let mut resume = 0u32;
        let mut services = Vec::new();
        loop {
            let mut bytes_needed = 0u32;
            let mut returned = 0u32;
            let result = unsafe {
                EnumServicesStatusExW(
                    manager,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_STATE_ALL,
                    Some(&mut buffer),
                    &mut bytes_needed,
                    &mut returned,
                    Some(&mut resume),
                    PCWSTR::null(),
                )
            };
            if let Err(error) = result {
                let code = win32_code_from_hresult(error.code().0);
                if code == ERROR_MORE_DATA.0
                    && bytes_needed as usize > buffer.len()
                    && bytes_needed as usize <= MAX_SERVICE_BUFFER
                {
                    buffer.resize(bytes_needed as usize, 0);
                    continue;
                }
                if code == ERROR_MORE_DATA.0 {
                    return Ok((services, true));
                }
                return Err(format!(
                    "Service enumeration failed (Windows error {code})."
                ));
            }
            let records = unsafe {
                std::slice::from_raw_parts(
                    buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
                    returned as usize,
                )
            };
            for record in records {
                services.push((
                    wide_ptr_to_string(record.lpServiceName),
                    wide_ptr_to_string(record.lpDisplayName),
                ));
                if services.len() >= MAX_ITEMS_PER_SOURCE {
                    return Ok((services, true));
                }
            }
            if resume == 0 {
                break;
            }
            if services.len() >= MAX_ITEMS_PER_SOURCE {
                return Ok((services, true));
            }
        }
        Ok((services, false))
    }

    fn win32_code_from_hresult(code: i32) -> u32 {
        let bits = code as u32;
        if bits & 0xffff_0000 == 0x8007_0000 {
            bits & 0x0000_ffff
        } else {
            bits
        }
    }

    fn query_service_config(
        manager: SC_HANDLE,
        name: &str,
    ) -> Result<ServiceConfigSnapshot, StartupError> {
        let handle = open_service(manager, name, SERVICE_QUERY_CONFIG)?;
        query_service_config_on_handle(handle.0)
    }

    fn query_service_config_on_handle(
        service: SC_HANDLE,
    ) -> Result<ServiceConfigSnapshot, StartupError> {
        let mut needed = 0u32;
        let first = unsafe { QueryServiceConfigW(service, None, 0, &mut needed) };
        if first.is_ok() || needed == 0 {
            return Err(StartupError::new(
                StartupErrorKind::NativeFailure,
                "Service configuration size query returned an unexpected result.",
            ));
        }
        if needed as usize > 1_048_576 {
            return Err(StartupError::new(
                StartupErrorKind::Inaccessible,
                "Service configuration exceeds the safe read bound.",
            ));
        }
        let mut buffer = vec![0u8; needed as usize];
        unsafe {
            QueryServiceConfigW(
                service,
                Some(buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
                needed,
                &mut needed,
            )
        }
        .map_err(|error| {
            StartupError::new(
                StartupErrorKind::Inaccessible,
                format!(
                    "Service configuration could not be read (Windows error {}).",
                    error.code().0 as u32
                ),
            )
        })?;
        let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
        Ok(ServiceConfigSnapshot {
            service_type: config.dwServiceType.0,
            start_type: config.dwStartType.0,
            error_control: config.dwErrorControl.0,
            binary_path: wide_ptr_to_string(config.lpBinaryPathName),
            load_order_group: wide_ptr_to_string(config.lpLoadOrderGroup),
            dependencies: multi_sz_to_strings(config.lpDependencies),
            service_start_name: wide_ptr_to_string(config.lpServiceStartName),
            display_name: wide_ptr_to_string(config.lpDisplayName),
        })
    }

    fn multi_sz_to_strings(value: PWSTR) -> Vec<String> {
        if value.0.is_null() {
            return Vec::new();
        }
        unsafe {
            let mut cursor = value.0;
            let mut result = Vec::new();
            loop {
                let mut length = 0usize;
                while *cursor.add(length) != 0 {
                    length += 1;
                }
                if length == 0 {
                    break;
                }
                result.push(String::from_utf16_lossy(std::slice::from_raw_parts(
                    cursor, length,
                )));
                cursor = cursor.add(length + 1);
            }
            result
        }
    }

    fn nonempty(value: &str) -> Option<&str> {
        (!value.trim().is_empty()).then_some(value)
    }
}

#[cfg(windows)]
pub use windows_backend::WindowsStartupPlatform;

#[cfg(not(windows))]
pub struct WindowsStartupPlatform;

#[cfg(not(windows))]
impl WindowsStartupPlatform {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(windows))]
impl StartupPlatform for WindowsStartupPlatform {
    fn inventory(&mut self, section: StartupSection) -> StartupInventory {
        StartupInventory {
            section,
            quality: InventoryQuality::Unavailable,
            entries: Vec::new(),
            sources: vec![SourceOutcome {
                source: "Windows Startup Manager".into(),
                state: SourceState::Failed {
                    reason: "This backend is available only on Windows.".into(),
                },
            }],
        }
    }

    fn observe(&mut self, _id: &StartupId) -> Result<ObservedState, StartupError> {
        Err(StartupError::new(
            StartupErrorKind::Unsupported,
            "This backend is available only on Windows.",
        ))
    }

    fn compare_and_set(
        &mut self,
        _id: &StartupId,
        _expected: &ObservedState,
        _desired: &ObservedState,
    ) -> Result<(), StartupError> {
        Err(StartupError::new(
            StartupErrorKind::Unsupported,
            "This backend is available only on Windows.",
        ))
    }
}

#[cfg(test)]
mod native_transition_tests {
    use super::*;

    fn run_state() -> ObservedState {
        let identity = EntryIdentity::StartupRunValue {
            hive: RegistryHive::CurrentUser,
            key: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
            value_name: "Sample".into(),
            approval_hive: RegistryHive::CurrentUser,
            approval_key: r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
                .into(),
        };
        ObservedState {
            id: StartupId::for_identity(&identity),
            identity,
            enabled: EnabledState::Enabled,
            native: NativeState::StartupRunValue {
                value: RegistryValueSnapshot {
                    value_type: REG_SZ_RAW,
                    data: vec![0; 8],
                },
                approval: None,
            },
        }
    }

    fn folder_state() -> ObservedState {
        let identity = EntryIdentity::StartupFolderItem {
            path: r"C:\Users\Example\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Sample.lnk".into(),
        };
        ObservedState {
            id: StartupId::for_identity(&identity),
            identity,
            enabled: EnabledState::Enabled,
            native: NativeState::StartupFolderItem {
                snapshot: StartupFolderSnapshot {
                    approval: None,
                    file: StartupFolderFileSnapshot {
                        volume_serial: 1,
                        file_index: 2,
                        file_size: 3,
                        last_write_time: 4,
                        attributes: 0x20,
                    },
                },
            },
        }
    }

    fn context_state() -> ObservedState {
        let identity = EntryIdentity::ContextMenuRegistration {
            hive: RegistryHive::CurrentUser,
            key: r"Software\Classes\*\shell".into(),
            registration: "SampleVerb".into(),
        };
        ObservedState {
            id: StartupId::for_identity(&identity),
            identity,
            enabled: EnabledState::Enabled,
            native: NativeState::ContextMenuVerb {
                snapshot: ContextMenuVerbSnapshot {
                    legacy_disable: None,
                    command: RegistryValueSnapshot {
                        value_type: REG_SZ_RAW,
                        data: vec![0; 8],
                    },
                },
            },
        }
    }

    fn task_state() -> ObservedState {
        let identity = EntryIdentity::ScheduledTask {
            path: r"\Sample\Task".into(),
        };
        ObservedState {
            id: StartupId::for_identity(&identity),
            identity,
            enabled: EnabledState::Enabled,
            native: NativeState::ScheduledTask {
                xml: Some("<Task><Actions /></Task>".into()),
            },
        }
    }

    fn service_state() -> ObservedState {
        let identity = EntryIdentity::WindowsService {
            name: "SampleService".into(),
        };
        ObservedState {
            id: StartupId::for_identity(&identity),
            identity,
            enabled: EnabledState::Enabled,
            native: NativeState::WindowsService {
                config: ServiceConfigSnapshot {
                    service_type: 0x10,
                    start_type: 2,
                    error_control: 1,
                    binary_path: r"C:\Sample.exe".into(),
                    load_order_group: String::new(),
                    dependencies: vec![],
                    service_start_name: "LocalService".into(),
                    display_name: "Sample service".into(),
                },
            },
        }
    }

    #[test]
    fn every_supported_native_change_accepts_exact_restore_snapshot() {
        for before in [
            run_state(),
            folder_state(),
            context_state(),
            task_state(),
            service_state(),
        ] {
            let after = expected_state(&before, false).unwrap();
            validate_native_transition(&before, &after).unwrap();
            validate_native_transition(&after, &before).unwrap();
        }
    }

    #[test]
    fn restore_transition_refuses_changed_command_and_service_identity() {
        let before = context_state();
        let after = expected_state(&before, false).unwrap();
        let mut changed = before.clone();
        if let NativeState::ContextMenuVerb { snapshot } = &mut changed.native {
            snapshot.command.data.push(1);
        }
        assert_eq!(
            validate_native_transition(&after, &changed)
                .unwrap_err()
                .kind,
            StartupErrorKind::InvalidIntent
        );

        let before = service_state();
        let after = expected_state(&before, false).unwrap();
        let mut changed = before;
        if let NativeState::WindowsService { config } = &mut changed.native {
            config.binary_path.push_str(" --changed");
        }
        assert_eq!(
            validate_native_transition(&after, &changed)
                .unwrap_err()
                .kind,
            StartupErrorKind::InvalidIntent
        );
    }
}
