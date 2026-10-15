//! Windows device inventory, WUA driver catalogue, and guarded driver actions.
//!
//! This module deliberately separates "Windows offered a driver update" from a
//! claim that the installed driver is obsolete. WUA does not expose a candidate
//! version through `IWindowsDriverUpdate`, and its offer is scoped to the update
//! source selected by Windows policy. Installation is permitted only through a
//! reviewed, exact-identity boundary with a durable intent and signed package
//! export; all partial outcomes stay visible as uncertain.

use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

pub const DRIVER_SCHEMA_VERSION: u32 = 1;
pub const MAX_DEVICES: usize = 4_096;
pub const MAX_CANDIDATES: usize = 2_048;
pub const MAX_PROPERTY_BYTES: usize = 64 * 1024;
pub const MAX_HARDWARE_IDS_PER_DEVICE: usize = 256;
pub const MAX_ISSUES: usize = 256;
const MAX_SETTINGS_BYTES: u64 = 512 * 1024;
const MAX_PREFERENCES: usize = 2_000;
const MAX_BACKUP_PACKAGE_FILES: usize = 8_192;
const MAX_BACKUP_PACKAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_SINGLE_PACKAGE_FILE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum FieldValue<T> {
    Known { value: T },
    Unknown { failure: FieldFailure },
}

impl<T> FieldValue<T> {
    pub fn as_known(&self) -> Option<&T> {
        match self {
            Self::Known { value } => Some(value),
            Self::Unknown { .. } => None,
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known { .. })
    }
}

fn field_failure<T>(field: &FieldValue<T>) -> Option<FieldFailure> {
    match field {
        FieldValue::Known { .. } => None,
        FieldValue::Unknown { failure } => Some(failure.clone()),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldFailureKind {
    AccessDenied,
    NotPresent,
    NotProvidedByApi,
    UnsupportedType,
    MalformedData,
    LimitExceeded,
    NativeFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FieldFailure {
    pub kind: FieldFailureKind,
    /// Native HRESULT/Win32 code where one was returned. Paths and raw command
    /// text are never included in diagnostic messages.
    pub native_code: Option<u32>,
}

impl FieldFailure {
    fn new(kind: FieldFailureKind, native_code: Option<u32>) -> Self {
        Self { kind, native_code }
    }

    pub fn summary(&self) -> &'static str {
        match self.kind {
            FieldFailureKind::AccessDenied => "Windows denied access to this property.",
            FieldFailureKind::NotPresent => "Windows did not report this property.",
            FieldFailureKind::NotProvidedByApi => {
                "The Windows Update Agent interface does not expose this value."
            }
            FieldFailureKind::UnsupportedType => "Windows returned an unsupported property type.",
            FieldFailureKind::MalformedData => "Windows returned malformed property data.",
            FieldFailureKind::LimitExceeded => "The property exceeded the safe read limit.",
            FieldFailureKind::NativeFailure => "The Windows API could not read this property.",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryQuality {
    Complete,
    Partial,
    Truncated,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NativeIssue {
    pub source: String,
    pub operation: String,
    pub failure: FieldFailure,
}

impl NativeIssue {
    fn new(source: &str, operation: &str, failure: FieldFailure) -> Self {
        Self {
            source: source.to_owned(),
            operation: operation.to_owned(),
            failure,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceReport {
    pub quality: InventoryQuality,
    pub item_count: usize,
    pub issues: Vec<NativeIssue>,
}

impl SourceReport {
    fn complete(count: usize) -> Self {
        Self {
            quality: InventoryQuality::Complete,
            item_count: count,
            issues: Vec::new(),
        }
    }

    fn unavailable(issue: NativeIssue) -> Self {
        Self {
            quality: InventoryQuality::Unavailable,
            item_count: 0,
            issues: vec![issue],
        }
    }

    fn issue(&mut self, issue: NativeIssue) {
        if self.issues.len() < MAX_ISSUES {
            self.issues.push(issue);
        }
        if self.quality == InventoryQuality::Complete {
            self.quality = InventoryQuality::Partial;
        }
    }

    fn truncate(&mut self, operation: &'static str) {
        self.quality = InventoryQuality::Truncated;
        if self.issues.len() < MAX_ISSUES {
            self.issues.push(NativeIssue {
                source: "Windows native inventory".into(),
                operation: operation.into(),
                failure: FieldFailure::new(FieldFailureKind::LimitExceeded, None),
            });
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct DeviceId(pub String);

impl DeviceId {
    pub fn from_instance_id(instance_id: &str) -> Option<Self> {
        let identity = instance_id.trim();
        if identity.is_empty() || identity.len() > 32_768 || identity.contains('\0') {
            return None;
        }
        Some(Self(format!(
            "dev-{}",
            digest(identity.to_ascii_lowercase().as_bytes())
        )))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CandidateId(pub String);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CandidateIdentity {
    /// Exact GUID text returned by WUA; matching and revalidation preserve it.
    pub update_id: String,
    /// WUA revision is independent of the update GUID and is part of identity.
    pub revision: u32,
    pub source: WuaSource,
    /// WUA driver hardware ID is included in the candidate identity because a
    /// single update record must never be silently rebound to another device.
    pub driver_hardware_id: String,
}

impl CandidateIdentity {
    pub fn is_valid(&self) -> bool {
        self.update_id.len() <= 128
            && uuid::Uuid::parse_str(&self.update_id).is_ok()
            && self.revision > 0
            && !self.driver_hardware_id.trim().is_empty()
            && self.driver_hardware_id.len() <= 16_384
            && !self.driver_hardware_id.chars().any(char::is_control)
            && self.source.service_id.len() <= 4_096
            && !self.source.service_id.chars().any(char::is_control)
    }

    pub fn id(&self) -> CandidateId {
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}",
            self.source.server_selection.identity_code(),
            self.source.service_id.to_ascii_lowercase(),
            self.source.online_search,
            self.update_id.to_ascii_lowercase(),
            self.revision,
            self.driver_hardware_id.to_ascii_lowercase()
        );
        CandidateId(format!("wua-{}", digest(canonical.as_bytes())))
    }
}

/// Returns whether two per-device candidate records represent the same exact
/// WUA offer. Hardware IDs are intentionally excluded here: a single WUA
/// update/revision/source can be matched to several related device instances,
/// and a batch must submit that offer only once.
pub fn same_wua_update(left: &CandidateIdentity, right: &CandidateIdentity) -> bool {
    left.update_id.eq_ignore_ascii_case(&right.update_id)
        && left.revision == right.revision
        && left.source == right.source
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WuaServerSelection {
    PolicyDefault,
    ManagedServer,
    WindowsUpdate,
    Other,
    Unknown(i32),
}

impl WuaServerSelection {
    fn identity_code(self) -> i32 {
        match self {
            Self::PolicyDefault => 0,
            Self::ManagedServer => 1,
            Self::WindowsUpdate => 2,
            Self::Other => 3,
            Self::Unknown(value) => value,
        }
    }

    fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::PolicyDefault,
            1 => Self::ManagedServer,
            2 => Self::WindowsUpdate,
            3 => Self::Other,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct WuaSource {
    pub server_selection: WuaServerSelection,
    /// Empty means WUA did not provide a service ID for the selected default.
    pub service_id: String,
    pub online_search: bool,
}

impl WuaSource {
    pub fn label(&self) -> String {
        match self.server_selection {
            WuaServerSelection::PolicyDefault if self.service_id.is_empty() => {
                "Windows Update Agent default source (policy-selected)".into()
            }
            WuaServerSelection::PolicyDefault => {
                format!("Windows Update Agent default source · {}", self.service_id)
            }
            WuaServerSelection::ManagedServer => "Managed Windows Update source".into(),
            WuaServerSelection::WindowsUpdate => "Windows Update".into(),
            WuaServerSelection::Other if self.service_id.is_empty() => {
                "Other Windows Update Agent source".into()
            }
            WuaServerSelection::Other => {
                format!("Windows Update Agent source · {}", self.service_id)
            }
            WuaServerSelection::Unknown(_) => "Unknown Windows Update Agent source".into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DriverDevice {
    pub id: Option<DeviceId>,
    pub instance_id: FieldValue<String>,
    pub friendly_name: FieldValue<String>,
    pub class_name: FieldValue<String>,
    pub class_guid: String,
    pub hardware_ids: FieldValue<Vec<String>>,
    pub compatible_ids: FieldValue<Vec<String>>,
    pub provider: FieldValue<String>,
    pub installed_version: FieldValue<String>,
    pub installed_date: FieldValue<String>,
    pub inf_path: FieldValue<String>,
    /// Device Manager's problem code. Zero is a known healthy PnP status;
    /// missing or denied properties stay unknown and are never treated as 0.
    pub problem_code: FieldValue<u32>,
    pub offer: DeviceOffer,
}

/// A real SetupAPI device-class grouping used by the Driver Updater filters.
/// Unknown classes remain visible under `Other`; they are not discarded.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverDeviceCategory {
    Audio,
    Battery,
    Biometric,
    Bluetooth,
    Camera,
    Computer,
    Connectivity,
    Display,
    Keyboard,
    Monitor,
    Mouse,
    Multifunction,
    Other,
    Printer,
    Processor,
    SecurityDevices,
    Sensor,
    Storage,
    System,
    Usb,
}

impl DriverDeviceCategory {
    pub fn label(self) -> &'static str {
        match self {
            Self::Audio => "Audio",
            Self::Battery => "Battery",
            Self::Biometric => "Biometric",
            Self::Bluetooth => "Bluetooth",
            Self::Camera => "Camera",
            Self::Computer => "Computer",
            Self::Connectivity => "Connectivity",
            Self::Display => "Display",
            Self::Keyboard => "Keyboard",
            Self::Monitor => "Monitor",
            Self::Mouse => "Mouse",
            Self::Multifunction => "Multifunction",
            Self::Other => "Other",
            Self::Printer => "Printer",
            Self::Processor => "Processor",
            Self::SecurityDevices => "Security devices",
            Self::Sensor => "Sensor",
            Self::Storage => "Storage",
            Self::System => "System",
            Self::Usb => "USB",
        }
    }
}

impl DriverDevice {
    pub fn category(&self) -> DriverDeviceCategory {
        let class = self.class_name.as_known().map(|value| value.trim());
        match class.map(|value| value.to_ascii_lowercase()).as_deref() {
            Some("audioendpoint" | "media" | "sound") => DriverDeviceCategory::Audio,
            Some("battery") => DriverDeviceCategory::Battery,
            Some("biometric") => DriverDeviceCategory::Biometric,
            Some("bluetooth") => DriverDeviceCategory::Bluetooth,
            Some("camera" | "image") => DriverDeviceCategory::Camera,
            Some("computer") => DriverDeviceCategory::Computer,
            Some("net" | "network" | "ports") => DriverDeviceCategory::Connectivity,
            Some("display") => DriverDeviceCategory::Display,
            Some("keyboard") => DriverDeviceCategory::Keyboard,
            Some("monitor") => DriverDeviceCategory::Monitor,
            Some("mouse" | "mousedev") => DriverDeviceCategory::Mouse,
            Some("multifunction") => DriverDeviceCategory::Multifunction,
            Some("printer" | "printqueue") => DriverDeviceCategory::Printer,
            Some("processor") => DriverDeviceCategory::Processor,
            Some("securitydevices" | "smartcardreader") => DriverDeviceCategory::SecurityDevices,
            Some("sensor") => DriverDeviceCategory::Sensor,
            Some("diskdrive" | "scsiadapter" | "hdc" | "volume") => DriverDeviceCategory::Storage,
            Some("system") => DriverDeviceCategory::System,
            Some("usb") => DriverDeviceCategory::Usb,
            _ => match self
                .class_guid
                .trim_matches(['{', '}'])
                .to_ascii_lowercase()
                .as_str()
            {
                "4d36e968-e325-11ce-bfc1-08002be10318" => DriverDeviceCategory::Display,
                "4d36e96c-e325-11ce-bfc1-08002be10318" => DriverDeviceCategory::Audio,
                "4d36e972-e325-11ce-bfc1-08002be10318" => DriverDeviceCategory::Connectivity,
                "e0cbf06c-cd8b-4647-bb8a-263b43f0f974" => DriverDeviceCategory::Bluetooth,
                "4d36e96b-e325-11ce-bfc1-08002be10318" => DriverDeviceCategory::Keyboard,
                "4d36e96f-e325-11ce-bfc1-08002be10318" => DriverDeviceCategory::Mouse,
                "4d36e96e-e325-11ce-bfc1-08002be10318" => DriverDeviceCategory::Monitor,
                "4d36e97d-e325-11ce-bfc1-08002be10318" => DriverDeviceCategory::System,
                "4d36e979-e325-11ce-bfc1-08002be10318" => DriverDeviceCategory::Printer,
                "4d36e97b-e325-11ce-bfc1-08002be10318" => DriverDeviceCategory::Storage,
                "36fc9e60-c465-11cf-8056-444553540000" => DriverDeviceCategory::Usb,
                _ => DriverDeviceCategory::Other,
            },
        }
    }

    pub fn has_confirmed_problem(&self) -> Option<bool> {
        self.problem_code.as_known().map(|code| *code != 0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum DeviceOffer {
    CandidateAvailable { candidates: Vec<CandidateId> },
    NoOfferFromSource { source: WuaSource },
    Unknown { failure: FieldFailure },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum CandidateMatch {
    Matched { devices: Vec<DeviceId> },
    NoMatchingPresentDevice,
    Unknown { failure: FieldFailure },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DriverCandidate {
    pub id: CandidateId,
    pub identity: CandidateIdentity,
    pub title: FieldValue<String>,
    pub manufacturer: FieldValue<String>,
    pub model: FieldValue<String>,
    pub class: FieldValue<String>,
    pub provider: FieldValue<String>,
    pub release_date: FieldValue<String>,
    /// The current WUA `IWindowsDriverUpdate` bindings expose no candidate
    /// version property. Never infer a version from its title.
    pub candidate_version: FieldValue<String>,
    pub applicability: CandidateMatch,
    /// WUA EULA state. The application never accepts a license on a user's
    /// behalf; updates requiring acceptance in Windows remain blocked.
    pub eula_accepted: FieldValue<bool>,
    pub installed: FieldValue<bool>,
    pub hidden: FieldValue<bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceInventory {
    pub source: SourceReport,
    pub devices: Vec<DriverDevice>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum CatalogueState {
    Read { source: WuaSource },
    Partial { source: WuaSource },
    Unavailable { issue: NativeIssue },
    Truncated { source: WuaSource },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DriverCatalogue {
    pub state: CatalogueState,
    pub candidates: Vec<DriverCandidate>,
    pub issues: Vec<NativeIssue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DriverSnapshot {
    pub schema_version: u32,
    pub scanned_at: chrono::DateTime<chrono::Utc>,
    pub inventory: DeviceInventory,
    pub catalogue: DriverCatalogue,
}

impl DriverSnapshot {
    pub fn assemble(mut inventory: DeviceInventory, mut catalogue: DriverCatalogue) -> Self {
        let catalogue_complete = matches!(catalogue.state, CatalogueState::Read { .. });
        let source = match &catalogue.state {
            CatalogueState::Read { source }
            | CatalogueState::Partial { source }
            | CatalogueState::Truncated { source } => Some(source.clone()),
            CatalogueState::Unavailable { .. } => None,
        };
        match_candidates(
            &mut inventory.devices,
            &mut catalogue.candidates,
            source.as_ref(),
            catalogue_complete,
        );
        Self {
            schema_version: DRIVER_SCHEMA_VERSION,
            scanned_at: chrono::Utc::now(),
            inventory,
            catalogue,
        }
    }

    pub fn status_for(&self, device: &DriverDevice, settings: &DriverSettings) -> DriverStatus {
        let Some(device_id) = device.id.as_ref() else {
            return DriverStatus::Unknown;
        };
        if settings.is_ignored(device_id) {
            return DriverStatus::Ignored;
        }
        match &device.offer {
            DeviceOffer::CandidateAvailable { candidates } => {
                let mut actionable = false;
                let mut any_candidate = false;
                for candidate_id in candidates {
                    let Some(candidate) = self
                        .catalogue
                        .candidates
                        .iter()
                        .find(|candidate| candidate.id == *candidate_id)
                    else {
                        continue;
                    };
                    any_candidate = true;
                    if !settings.is_skipped(device_id, &candidate.identity) {
                        actionable = true;
                    }
                }
                if actionable {
                    DriverStatus::UpdateAvailable
                } else if any_candidate {
                    DriverStatus::Skipped
                } else {
                    DriverStatus::Unknown
                }
            }
            DeviceOffer::NoOfferFromSource { .. } => DriverStatus::NoOfferFromSource,
            DeviceOffer::Unknown { .. } => DriverStatus::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverStatus {
    UpdateAvailable,
    NoOfferFromSource,
    Skipped,
    Ignored,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DriverPreference {
    IgnoreDevice {
        device_id: DeviceId,
    },
    SkipCandidate {
        device_id: DeviceId,
        candidate: CandidateIdentity,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverSettings {
    pub schema: u32,
    pub preferences: Vec<DriverPreference>,
}

impl Default for DriverSettings {
    fn default() -> Self {
        Self {
            schema: 1,
            preferences: Vec::new(),
        }
    }
}

impl DriverSettings {
    pub fn is_ignored(&self, device_id: &DeviceId) -> bool {
        self.preferences.iter().any(|preference| {
            matches!(preference, DriverPreference::IgnoreDevice { device_id: saved } if saved == device_id)
        })
    }

    pub fn is_skipped(&self, device_id: &DeviceId, candidate: &CandidateIdentity) -> bool {
        self.preferences.iter().any(|preference| {
            matches!(preference, DriverPreference::SkipCandidate { device_id: saved_device, candidate: saved } if saved_device == device_id && saved == candidate)
        })
    }

    pub fn set_ignored(&mut self, device_id: DeviceId, ignored: bool) -> Result<(), SettingsError> {
        let target = DriverPreference::IgnoreDevice { device_id };
        self.set_preference(target, ignored)
    }

    pub fn set_skipped(
        &mut self,
        device_id: DeviceId,
        candidate: CandidateIdentity,
        skipped: bool,
    ) -> Result<(), SettingsError> {
        let target = DriverPreference::SkipCandidate {
            device_id,
            candidate,
        };
        self.set_preference(target, skipped)
    }

    fn set_preference(
        &mut self,
        preference: DriverPreference,
        enabled: bool,
    ) -> Result<(), SettingsError> {
        validate_preference(&preference)?;
        if enabled {
            if let Some(existing) = self
                .preferences
                .iter_mut()
                .find(|item| **item == preference)
            {
                *existing = preference;
            } else {
                if self.preferences.len() >= MAX_PREFERENCES {
                    return Err(SettingsError(
                        "the driver settings rule limit was reached.".into(),
                    ));
                }
                self.preferences.push(preference);
            }
        } else {
            self.preferences.retain(|item| *item != preference);
        }
        self.preferences.sort_by_key(preference_key);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettingsError(pub String);

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SettingsError {}

fn preference_key(preference: &DriverPreference) -> String {
    match preference {
        DriverPreference::IgnoreDevice { device_id } => format!("ignore:{}", device_id.0),
        DriverPreference::SkipCandidate {
            device_id,
            candidate,
        } => {
            format!("skip:{}:{}", device_id.0, candidate.id().0)
        }
    }
}

fn validate_preference(preference: &DriverPreference) -> Result<(), SettingsError> {
    let valid_device = |id: &DeviceId| {
        id.0.strip_prefix("dev-").is_some_and(|digest| {
            digest.len() == 32 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    };
    let valid = match preference {
        DriverPreference::IgnoreDevice { device_id } => valid_device(device_id),
        DriverPreference::SkipCandidate {
            device_id,
            candidate,
        } => valid_device(device_id) && candidate.is_valid(),
    };
    if valid {
        Ok(())
    } else {
        Err(SettingsError(
            "the driver preference has an invalid native identity.".into(),
        ))
    }
}

pub fn load_settings(root: &Path) -> Result<DriverSettings, SettingsError> {
    if !root.is_absolute() {
        return Err(SettingsError(
            "the application data directory is not absolute.".into(),
        ));
    }
    let path = root.join("drivers-settings.json");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DriverSettings::default());
        }
        Err(error) => return Err(SettingsError(error.to_string())),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_SETTINGS_BYTES
    {
        return Err(SettingsError("the driver settings file is linked, not a regular file, or exceeds its limit; original bytes were preserved.".into()));
    }
    let settings: DriverSettings =
        serde_json::from_slice(&fs::read(path).map_err(|error| SettingsError(error.to_string()))?)
            .map_err(|error| {
                SettingsError(format!(
                    "driver settings could not be decoded; original bytes were preserved: {error}"
                ))
            })?;
    validate_settings(&settings)?;
    Ok(settings)
}

pub fn save_settings(root: &Path, settings: &DriverSettings) -> Result<(), SettingsError> {
    if !root.is_absolute() {
        return Err(SettingsError(
            "the application data directory is not absolute.".into(),
        ));
    }
    validate_settings(settings)?;
    fs::create_dir_all(root).map_err(|error| {
        SettingsError(format!(
            "could not create the driver settings directory: {error}"
        ))
    })?;
    let destination = root.join("drivers-settings.json");
    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(SettingsError(
                    "the existing driver settings path is not a regular file; it was preserved."
                        .into(),
                ));
            }
            // Preserve malformed and newer-version bytes. A valid new value
            // must never silently turn into an implicit reset operation.
            load_settings(root)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(SettingsError(format!(
                "could not inspect the existing driver settings file: {error}"
            )));
        }
    }
    let temporary = root.join(format!("drivers-settings.{}.tmp", uuid::Uuid::new_v4()));
    let bytes =
        serde_json::to_vec_pretty(settings).map_err(|error| SettingsError(error.to_string()))?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| {
                format!("could not create the temporary driver settings file: {error}")
            })?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("could not flush the driver settings file: {error}"))?;
        drop(file);
        // Re-read immediately before commit as a second guard against
        // replacing a corrupt/future-version file created during the write.
        load_settings(root).map_err(|error| error.to_string())?;
        replace_settings_file(&temporary, &destination)
            .map_err(|error| format!("could not replace the driver settings file: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(SettingsError)
}

fn replace_settings_file(temporary: &Path, destination_path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows::{
            Win32::Storage::FileSystem::{
                MOVEFILE_WRITE_THROUGH, MoveFileExW, REPLACE_FILE_FLAGS, ReplaceFileW,
            },
            core::PCWSTR,
        };

        let temporary_wide: Vec<u16> = temporary
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let destination_wide: Vec<u16> = destination_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let temporary = PCWSTR(temporary_wide.as_ptr());
        let destination = PCWSTR(destination_wide.as_ptr());
        match fs::symlink_metadata(destination_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(
                        "the existing driver settings path changed to a non-file; it was preserved."
                            .into(),
                    );
                }
                unsafe {
                    ReplaceFileW(
                        destination,
                        temporary,
                        PCWSTR::null(),
                        REPLACE_FILE_FLAGS(0),
                        None,
                        None,
                    )
                }
                .map_err(|error| error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                unsafe { MoveFileExW(temporary, destination, MOVEFILE_WRITE_THROUGH) }
                    .map_err(|error| error.to_string())
            }
            Err(error) => Err(format!(
                "could not inspect the driver settings destination: {error}"
            )),
        }
    }
    #[cfg(not(windows))]
    {
        fs::rename(temporary, destination_path).map_err(|error| error.to_string())
    }
}

fn validate_settings(settings: &DriverSettings) -> Result<(), SettingsError> {
    if settings.schema != 1 || settings.preferences.len() > MAX_PREFERENCES {
        return Err(SettingsError(
            "unsupported driver settings schema or rule count; original bytes were preserved."
                .into(),
        ));
    }
    let mut seen = HashSet::new();
    for preference in &settings.preferences {
        validate_preference(preference)?;
        if !seen.insert(preference_key(preference)) {
            return Err(SettingsError(
                "duplicate driver preference; original bytes were preserved.".into(),
            ));
        }
    }
    Ok(())
}

fn match_candidates(
    devices: &mut [DriverDevice],
    candidates: &mut [DriverCandidate],
    source: Option<&WuaSource>,
    catalogue_complete: bool,
) {
    let mut offers: HashMap<DeviceId, Vec<CandidateId>> = HashMap::new();
    let mut uncertain_offers: HashMap<DeviceId, FieldFailure> = HashMap::new();
    for candidate in candidates {
        let hardware_id = candidate
            .identity
            .driver_hardware_id
            .trim()
            .trim_start_matches('\u{feff}');
        if hardware_id.is_empty() {
            candidate.applicability = CandidateMatch::Unknown {
                failure: FieldFailure::new(FieldFailureKind::MalformedData, None),
            };
            continue;
        }
        let mut matches = Vec::new();
        let mut identity_read_failure = None;
        for device in devices.iter() {
            let mut known_ids = Vec::new();
            let mut unknown_id_failure = None;
            match &device.hardware_ids {
                FieldValue::Known { value } => known_ids.extend(value.iter()),
                FieldValue::Unknown { failure } => {
                    unknown_id_failure.get_or_insert_with(|| failure.clone());
                }
            }
            match &device.compatible_ids {
                FieldValue::Known { value } => known_ids.extend(value.iter()),
                FieldValue::Unknown { failure } => {
                    unknown_id_failure.get_or_insert_with(|| failure.clone());
                }
            }
            let has_known_match = known_ids
                .iter()
                .any(|id| id.eq_ignore_ascii_case(hardware_id));
            if has_known_match {
                if let Some(id) = &device.id {
                    matches.push(id.clone());
                } else if let Some(failure) = field_failure(&device.instance_id) {
                    identity_read_failure.get_or_insert(failure);
                } else {
                    identity_read_failure.get_or_insert_with(|| {
                        FieldFailure::new(FieldFailureKind::MalformedData, None)
                    });
                }
            } else if let Some(failure) = unknown_id_failure {
                // An unreadable ID on any other present device can conceal a
                // second target. Do not classify a known match as exclusive.
                identity_read_failure.get_or_insert(failure);
            }
        }
        matches.sort_by(|a, b| a.0.cmp(&b.0));
        matches.dedup();
        let match_state = if let Some(failure) = identity_read_failure {
            for device_id in &matches {
                uncertain_offers
                    .entry(device_id.clone())
                    .or_insert_with(|| failure.clone());
            }
            CandidateMatch::Unknown { failure }
        } else if !matches.is_empty() {
            for device_id in &matches {
                offers
                    .entry(device_id.clone())
                    .or_default()
                    .push(candidate.id.clone());
            }
            CandidateMatch::Matched { devices: matches }
        } else {
            CandidateMatch::NoMatchingPresentDevice
        };
        candidate.applicability = match_state;
    }

    for device in devices {
        device.offer = if let Some(id) = &device.id {
            if let Some(failure) = uncertain_offers.remove(id) {
                DeviceOffer::Unknown { failure }
            } else if let Some(mut candidates) = offers.remove(id) {
                candidates.sort_by(|a, b| a.0.cmp(&b.0));
                candidates.dedup();
                DeviceOffer::CandidateAvailable { candidates }
            } else if !catalogue_complete {
                DeviceOffer::Unknown {
                    failure: FieldFailure::new(FieldFailureKind::NativeFailure, None),
                }
            } else if let Some(source) = source {
                if device.hardware_ids.is_known() && device.compatible_ids.is_known() {
                    DeviceOffer::NoOfferFromSource {
                        source: source.clone(),
                    }
                } else {
                    DeviceOffer::Unknown {
                        failure: FieldFailure::new(FieldFailureKind::NotPresent, None),
                    }
                }
            } else {
                DeviceOffer::Unknown {
                    failure: FieldFailure::new(FieldFailureKind::NativeFailure, None),
                }
            }
        } else {
            DeviceOffer::Unknown {
                failure: FieldFailure::new(FieldFailureKind::NotPresent, None),
            }
        };
    }
}

/// Read-only inventory and catalog operations. Mutations go through the
/// separate reviewed boundary below so callers cannot accidentally turn a
/// scan operation into a driver install.
pub trait DriverPlatform {
    fn inventory_devices(&mut self) -> DeviceInventory;
    fn search_catalogue(&mut self) -> DriverCatalogue;
}

pub struct DriverManager<P> {
    platform: P,
}

impl<P: DriverPlatform> DriverManager<P> {
    pub fn new(platform: P) -> Self {
        Self { platform }
    }

    pub fn scan(&mut self) -> DriverSnapshot {
        let inventory = self.platform.inventory_devices();
        let catalogue = self.platform.search_catalogue();
        DriverSnapshot::assemble(inventory, catalogue)
    }

    pub fn platform(&self) -> &P {
        &self.platform
    }

    pub fn platform_mut(&mut self) -> &mut P {
        &mut self.platform
    }
}

/// Results returned by the native Windows Update Agent installer for the
/// single update in the reviewed collection. `2` is WUA's succeeded result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverInstallOutcome {
    /// Aggregate WUA download result for the one-item collection.
    pub download_result_code: i32,
    pub download_hresult: i32,
    pub download_item_result_code: i32,
    pub download_item_hresult: i32,
    pub downloaded_verified: bool,
    /// Aggregate WUA install result for the one-item collection.
    pub install_result_code: Option<i32>,
    pub install_hresult: Option<i32>,
    pub install_item_result_code: Option<i32>,
    pub install_item_hresult: Option<i32>,
    pub reboot: RebootRequirement,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverRestoreOutcome {
    /// Published Driver Store INF identity returned by SetupCopyOEMInf.
    pub staged_inf: String,
    pub reboot: RebootRequirement,
}

/// Narrow native boundary used by the reviewed workflow. Fake implementations
/// exercise ordering and revalidation in tests; only the Windows implementation
/// below can perform native package export or WUA installation.
pub trait DriverActionBoundary: DriverPlatform {
    fn current_device(&mut self, id: &DeviceId) -> Result<DriverDevice, DriverOperationError>;
    fn exact_candidate(
        &mut self,
        identity: &CandidateIdentity,
    ) -> Result<DriverCandidate, DriverOperationError>;
    fn create_restore_point(&mut self, description: &str) -> Result<i64, DriverOperationError>;
    fn export_driver_package(
        &mut self,
        root: &Path,
        intent: &DriverUpdateIntent,
        backup_id: uuid::Uuid,
    ) -> Result<DriverBackupReceipt, DriverOperationError>;
    fn download_and_install(
        &mut self,
        intent: &DriverUpdateIntent,
    ) -> Result<DriverInstallOutcome, DriverOperationError>;
    fn candidate_is_installed(
        &mut self,
        identity: &CandidateIdentity,
    ) -> Result<bool, DriverOperationError>;
    fn restore_from_package(
        &mut self,
        root: &Path,
        intent: &DriverRestoreIntent,
    ) -> Result<DriverRestoreOutcome, DriverOperationError>;
}

fn state_from_intent(
    intent: &DriverUpdateIntent,
) -> Result<DriverInstalledState, DriverOperationError> {
    Ok(DriverInstalledState {
        provider: intent.provider.clone(),
        version: intent
            .installed_version
            .as_known()
            .cloned()
            .ok_or(DriverOperationError::UpdateUnavailable)?,
        date: intent
            .installed_date
            .as_known()
            .cloned()
            .ok_or(DriverOperationError::UpdateUnavailable)?,
        inf: intent
            .installed_inf
            .as_known()
            .cloned()
            .ok_or(DriverOperationError::UpdateUnavailable)?,
    })
}

fn finish_driver_journal(
    journal: &mut crate::effects::EffectJournal,
    state: &str,
    receipt: &impl Serialize,
) -> Result<(), DriverOperationError> {
    journal
        .finish(state, receipt)
        .map_err(|_| DriverOperationError::JournalFailure)
}

/// Performs one explicitly reviewed device update. The durable intent is
/// synced before the restore point, package export, download, or install.
/// Failures after calling WUA installation are recorded as uncertain; callers
/// must inspect history instead of retrying automatically.
pub fn apply_reviewed_update<P: DriverActionBoundary>(
    root: &Path,
    intent: &DriverUpdateIntent,
    platform: &mut P,
) -> Result<DriverUpdateReceipt, DriverOperationError> {
    if !root.is_absolute() || !update_intent_is_well_formed(intent) {
        return Err(DriverOperationError::UpdateUnavailable);
    }
    let current = platform.current_device(&intent.device_id)?;
    let candidate = platform.exact_candidate(&intent.candidate)?;
    if candidate.eula_accepted.as_known() != Some(&true) {
        return Err(DriverOperationError::EulaNotAccepted);
    }
    validate_update_identity(intent, &current, &candidate)?;

    let original_state = state_from_intent(intent)?;
    let mut receipt = DriverUpdateReceipt {
        schema_version: DRIVER_SCHEMA_VERSION,
        intent_id: intent.intent_id,
        device_id: intent.device_id.clone(),
        device_instance_id: intent.device_instance_id.clone(),
        candidate: intent.candidate.clone(),
        original_state,
        backup: None,
        restore_point_sequence: None,
        phase: DriverEffectPhase::Prepared,
        download_result_code: None,
        download_hresult: None,
        download_item_result_code: None,
        download_item_hresult: None,
        downloaded_verified: false,
        wua_result_code: None,
        hresult: None,
        install_item_result_code: None,
        install_item_hresult: None,
        reboot: RebootRequirement::Unknown,
        installed_after: None,
    };
    let mut journal =
        crate::effects::EffectJournal::create(root, "drivers", intent.intent_id, intent)
            .map_err(|_| DriverOperationError::JournalFailure)?;

    let restore_point = match platform.create_restore_point("DCleaner driver update") {
        Ok(sequence) if sequence > 0 => sequence,
        Ok(_) => {
            receipt.phase = DriverEffectPhase::Failed;
            finish_driver_journal(&mut journal, "failed", &receipt)?;
            return Err(DriverOperationError::NativeUpdateBoundaryUnavailable);
        }
        Err(error) => {
            receipt.phase = DriverEffectPhase::Failed;
            finish_driver_journal(&mut journal, "failed", &receipt)?;
            return Err(error);
        }
    };
    receipt.restore_point_sequence = Some(restore_point);

    let backup = match platform.export_driver_package(root, intent, uuid::Uuid::new_v4()) {
        Ok(backup)
            if backup.is_well_formed()
                && backup.device_id == intent.device_id
                && backup.device_instance_id == intent.device_instance_id
                && backup.original_inf.eq_ignore_ascii_case(
                    intent
                        .installed_inf
                        .as_known()
                        .map(String::as_str)
                        .unwrap_or_default(),
                ) =>
        {
            backup
        }
        Ok(_) => {
            receipt.phase = DriverEffectPhase::Failed;
            finish_driver_journal(&mut journal, "failed", &receipt)?;
            return Err(DriverOperationError::BackupUnavailable);
        }
        Err(error) => {
            receipt.phase = DriverEffectPhase::Failed;
            finish_driver_journal(&mut journal, "failed", &receipt)?;
            return Err(error);
        }
    };
    receipt.backup = Some(backup);
    receipt.phase = DriverEffectPhase::BackupVerified;

    // The exact hardware and candidate identities are re-read immediately
    // before WUA. A package export can take long enough for either to change.
    let current = match platform.current_device(&intent.device_id) {
        Ok(device) => device,
        Err(error) => {
            receipt.phase = DriverEffectPhase::Failed;
            finish_driver_journal(&mut journal, "failed", &receipt)?;
            return Err(error);
        }
    };
    let candidate = match platform.exact_candidate(&intent.candidate) {
        Ok(candidate) => candidate,
        Err(error) => {
            receipt.phase = DriverEffectPhase::Failed;
            finish_driver_journal(&mut journal, "failed", &receipt)?;
            return Err(error);
        }
    };
    if candidate.eula_accepted.as_known() != Some(&true) {
        receipt.phase = DriverEffectPhase::Failed;
        finish_driver_journal(&mut journal, "failed", &receipt)?;
        return Err(DriverOperationError::EulaNotAccepted);
    }
    if validate_update_identity(intent, &current, &candidate).is_err() {
        receipt.phase = DriverEffectPhase::Failed;
        finish_driver_journal(&mut journal, "failed", &receipt)?;
        return Err(DriverOperationError::UpdateUnavailable);
    }

    let outcome = match platform.download_and_install(intent) {
        Ok(outcome) => outcome,
        Err(error) => {
            receipt.phase = DriverEffectPhase::Uncertain;
            let _ = finish_driver_journal(&mut journal, "uncertain", &receipt);
            return Err(error);
        }
    };
    receipt.download_result_code = Some(outcome.download_result_code);
    receipt.download_hresult = Some(outcome.download_hresult);
    receipt.download_item_result_code = Some(outcome.download_item_result_code);
    receipt.download_item_hresult = Some(outcome.download_item_hresult);
    receipt.downloaded_verified = outcome.downloaded_verified;
    receipt.wua_result_code = outcome.install_result_code;
    receipt.hresult = outcome.install_hresult;
    receipt.install_item_result_code = outcome.install_item_result_code;
    receipt.install_item_hresult = outcome.install_item_hresult;
    receipt.reboot = outcome.reboot;
    if outcome.download_result_code != 2
        || outcome.download_hresult != 0
        || outcome.download_item_result_code != 2
        || outcome.download_item_hresult != 0
        || !outcome.downloaded_verified
    {
        receipt.phase = DriverEffectPhase::Failed;
        finish_driver_journal(&mut journal, "failed", &receipt)?;
        return Err(DriverOperationError::UpdateFailed {
            hresult: (outcome.download_item_hresult != 0)
                .then_some(outcome.download_item_hresult)
                .or_else(|| (outcome.download_hresult != 0).then_some(outcome.download_hresult)),
            result_code: (outcome.download_item_result_code != 2)
                .then_some(outcome.download_item_result_code)
                .or_else(|| {
                    (outcome.download_result_code != 2).then_some(outcome.download_result_code)
                }),
        });
    }
    if outcome.install_result_code != Some(2)
        || outcome.install_hresult != Some(0)
        || outcome.install_item_result_code != Some(2)
        || outcome.install_item_hresult != Some(0)
    {
        receipt.phase = DriverEffectPhase::Uncertain;
        finish_driver_journal(&mut journal, "uncertain", &receipt)?;
        return Err(DriverOperationError::UpdateFailed {
            hresult: outcome
                .install_item_hresult
                .filter(|code| *code != 0)
                .or_else(|| outcome.install_hresult.filter(|code| *code != 0))
                .or_else(|| {
                    (outcome.download_item_hresult != 0).then_some(outcome.download_item_hresult)
                })
                .or_else(|| (outcome.download_hresult != 0).then_some(outcome.download_hresult)),
            result_code: outcome
                .install_item_result_code
                .filter(|code| *code != 2)
                .or_else(|| outcome.install_result_code.filter(|code| *code != 2))
                .or_else(|| {
                    (outcome.download_item_result_code != 2)
                        .then_some(outcome.download_item_result_code)
                })
                .or_else(|| {
                    (outcome.download_result_code != 2).then_some(outcome.download_result_code)
                }),
        });
    }
    if outcome.reboot == RebootRequirement::Required {
        receipt.phase = DriverEffectPhase::AwaitingRestart;
        finish_driver_journal(&mut journal, "applied", &receipt)?;
        return Ok(receipt);
    }
    if outcome.reboot != RebootRequirement::NotRequired {
        receipt.phase = DriverEffectPhase::Uncertain;
        finish_driver_journal(&mut journal, "uncertain", &receipt)?;
        return Err(DriverOperationError::VerificationFailed);
    }

    let installed = match platform.current_device(&intent.device_id) {
        Ok(device) => device,
        Err(_) => {
            receipt.phase = DriverEffectPhase::Uncertain;
            finish_driver_journal(&mut journal, "uncertain", &receipt)?;
            return Err(DriverOperationError::VerificationFailed);
        }
    };
    let installed_state = match DriverInstalledState::from_device(&installed) {
        Ok(state) => state,
        Err(_) => {
            receipt.phase = DriverEffectPhase::Uncertain;
            finish_driver_journal(&mut journal, "uncertain", &receipt)?;
            return Err(DriverOperationError::VerificationFailed);
        }
    };
    let candidate_installed = platform
        .candidate_is_installed(&intent.candidate)
        .unwrap_or(false);
    let provider_matches = candidate
        .provider
        .as_known()
        .is_none_or(|provider| provider.eq_ignore_ascii_case(&installed_state.provider));
    if installed.id.as_ref() != Some(&intent.device_id)
        || installed
            .instance_id
            .as_known()
            .is_none_or(|instance| instance != &intent.device_instance_id)
        || installed.hardware_ids.as_known() != Some(&intent.hardware_ids)
        || installed.compatible_ids.as_known() != Some(&intent.compatible_ids)
        || installed_state == receipt.original_state
        || !candidate_installed
        || !provider_matches
    {
        receipt.installed_after = Some(installed_state);
        receipt.phase = DriverEffectPhase::Uncertain;
        finish_driver_journal(&mut journal, "uncertain", &receipt)?;
        return Err(DriverOperationError::VerificationFailed);
    }
    receipt.installed_after = Some(installed_state);
    receipt.phase = DriverEffectPhase::Verified;
    finish_driver_journal(&mut journal, "verified", &receipt)?;
    Ok(receipt)
}

/// Reinstall the exact previously exported package onto the exact device.
/// The backup manifest and INF signature are checked again immediately before
/// SetupAPI stages the package. A post-reboot restore is never performed
/// automatically; this entry point requires a fresh explicit review.
pub fn apply_reviewed_restore<P: DriverActionBoundary>(
    root: &Path,
    update_intent: &DriverUpdateIntent,
    update_receipt: &DriverUpdateReceipt,
    restore_intent: &DriverRestoreIntent,
    platform: &mut P,
) -> Result<DriverRestoreReceipt, DriverOperationError> {
    if !root.is_absolute() || restore_intent.restore_id.is_nil() {
        return Err(DriverOperationError::UpdateUnavailable);
    }
    let current = platform.current_device(&restore_intent.device_id)?;
    validate_restore_intent(restore_intent, update_intent, update_receipt, &current)?;

    let mut receipt = DriverRestoreReceipt {
        schema_version: DRIVER_SCHEMA_VERSION,
        restore_id: restore_intent.restore_id,
        update_intent_id: restore_intent.update_intent_id,
        device_id: restore_intent.device_id.clone(),
        restored_state: None,
        staged_inf: None,
        backup_verified: false,
        phase: DriverEffectPhase::Prepared,
        hresult: None,
        reboot: RebootRequirement::Unknown,
    };
    let mut journal = crate::effects::EffectJournal::create(
        root,
        "drivers",
        restore_intent.restore_id,
        restore_intent,
    )
    .map_err(|_| DriverOperationError::JournalFailure)?;

    // The native boundary can stage files before installing the device. If it
    // fails after the journal is durable, the final state must be inspected.
    let outcome = match platform.restore_from_package(root, restore_intent) {
        Ok(outcome)
            if is_oem_inf_name(&outcome.staged_inf) && outcome.staged_inf.len() <= 32_768 =>
        {
            outcome
        }
        Ok(_) => {
            receipt.phase = DriverEffectPhase::Uncertain;
            let _ = finish_driver_journal(&mut journal, "uncertain", &receipt);
            return Err(DriverOperationError::VerificationFailed);
        }
        Err(error) => {
            receipt.phase = DriverEffectPhase::Uncertain;
            let _ = finish_driver_journal(&mut journal, "uncertain", &receipt);
            return Err(error);
        }
    };
    receipt.staged_inf = Some(outcome.staged_inf);
    receipt.backup_verified = true;
    receipt.hresult = Some(0);
    let reboot = outcome.reboot;
    receipt.reboot = reboot;
    if reboot == RebootRequirement::Required {
        receipt.phase = DriverEffectPhase::AwaitingRestart;
        finish_driver_journal(&mut journal, "applied", &receipt)?;
        return Ok(receipt);
    }
    if reboot != RebootRequirement::NotRequired {
        receipt.phase = DriverEffectPhase::Uncertain;
        finish_driver_journal(&mut journal, "uncertain", &receipt)?;
        return Err(DriverOperationError::VerificationFailed);
    }

    let restored = match platform.current_device(&restore_intent.device_id) {
        Ok(device) => device,
        Err(_) => {
            receipt.phase = DriverEffectPhase::Uncertain;
            finish_driver_journal(&mut journal, "uncertain", &receipt)?;
            return Err(DriverOperationError::VerificationFailed);
        }
    };
    let restored_state = match DriverInstalledState::from_device(&restored) {
        Ok(state) => state,
        Err(_) => {
            receipt.phase = DriverEffectPhase::Uncertain;
            finish_driver_journal(&mut journal, "uncertain", &receipt)?;
            return Err(DriverOperationError::VerificationFailed);
        }
    };
    if restored.id.as_ref() != Some(&restore_intent.device_id)
        || restored.instance_id.as_known() != Some(&restore_intent.device_instance_id)
        || restored.hardware_ids.as_known() != Some(&restore_intent.hardware_ids)
        || restored.compatible_ids.as_known() != Some(&restore_intent.compatible_ids)
        || restored_state != update_receipt.original_state
    {
        receipt.restored_state = Some(restored_state);
        receipt.phase = DriverEffectPhase::Uncertain;
        finish_driver_journal(&mut journal, "uncertain", &receipt)?;
        return Err(DriverOperationError::VerificationFailed);
    }
    receipt.restored_state = Some(restored_state);
    receipt.phase = DriverEffectPhase::Verified;
    finish_driver_journal(&mut journal, "restored", &receipt)?;
    Ok(receipt)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DriverOperationError {
    UpdateUnavailable,
    BackupUnavailable,
    PackageSignatureUnavailable,
    NativeUpdateBoundaryUnavailable,
    PrivilegeRequired,
    EulaNotAccepted,
    NativeFailure {
        native_code: Option<u32>,
    },
    JournalFailure,
    UpdateFailed {
        hresult: Option<i32>,
        result_code: Option<i32>,
    },
    VerificationFailed,
}

impl fmt::Display for DriverOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UpdateUnavailable => f.write_str("The reviewed WUA driver offer is not available."),
            Self::BackupUnavailable => f.write_str("A complete, independently verifiable driver backup is not available; installation is blocked."),
            Self::PackageSignatureUnavailable => f.write_str("The driver package signature has not been verified."),
            Self::NativeUpdateBoundaryUnavailable => f.write_str("A supported native driver install and post-install verification boundary is not available."),
            Self::PrivilegeRequired => f.write_str("Windows requires administrator access for this driver operation."),
            Self::EulaNotAccepted => f.write_str("The Windows Update offer requires license acceptance in Windows before it can be installed."),
            Self::NativeFailure { native_code: Some(code) } => write!(f, "Windows could not complete the driver operation (0x{code:08X})."),
            Self::NativeFailure { native_code: None } => f.write_str("Windows could not complete the driver operation."),
            Self::JournalFailure => f.write_str("The driver operation outcome could not be recorded durably. Review the operation history before retrying."),
            Self::UpdateFailed { hresult: Some(code), .. } => write!(f, "Windows could not install the reviewed driver update (0x{code:08X})."),
            Self::UpdateFailed { hresult: None, .. } => f.write_str("Windows did not complete the reviewed driver update."),
            Self::VerificationFailed => f.write_str("Windows reported an update result, but the exact device and installed driver state could not be verified."),
        }
    }
}

impl std::error::Error for DriverOperationError {}

/// A reviewed install intent is useful only when it captures both the exact
/// device state and exact WUA candidate identity. It cannot authorize a write
/// by itself; callers must use the reviewed workflow which journals, backs up,
/// revalidates, installs, and verifies.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DriverUpdateIntent {
    pub schema_version: u32,
    pub intent_id: uuid::Uuid,
    pub device_id: DeviceId,
    pub device_instance_id: String,
    pub hardware_ids: Vec<String>,
    pub compatible_ids: Vec<String>,
    pub class_guid: String,
    pub provider: String,
    pub installed_version: FieldValue<String>,
    pub installed_date: FieldValue<String>,
    pub installed_inf: FieldValue<String>,
    pub problem_code: FieldValue<u32>,
    pub candidate: CandidateIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverInstalledState {
    pub provider: String,
    pub version: String,
    pub date: String,
    pub inf: String,
}

impl DriverInstalledState {
    pub fn from_device(device: &DriverDevice) -> Result<Self, DriverOperationError> {
        Ok(Self {
            provider: device
                .provider
                .as_known()
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .ok_or(DriverOperationError::UpdateUnavailable)?,
            version: device
                .installed_version
                .as_known()
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .ok_or(DriverOperationError::UpdateUnavailable)?,
            date: device
                .installed_date
                .as_known()
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .ok_or(DriverOperationError::UpdateUnavailable)?,
            inf: device
                .inf_path
                .as_known()
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .ok_or(DriverOperationError::UpdateUnavailable)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverBackupFile {
    /// Slash-separated path relative to the operation's private backup folder.
    pub relative_path: String,
    pub byte_length: u64,
    /// SHA-256 is required before a native restore adapter may consume a file.
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverBackupReceipt {
    pub schema_version: u32,
    pub backup_id: uuid::Uuid,
    pub device_id: DeviceId,
    pub device_instance_id: String,
    pub original_inf: String,
    /// Must be a relative path under the application data directory.
    pub relative_directory: String,
    pub files: Vec<DriverBackupFile>,
    pub manifest_sha256: String,
    /// Set only after the Windows Driver Store export and signed catalog were
    /// verified by the native backup implementation.
    pub signature_verified: bool,
}

impl DriverBackupReceipt {
    pub fn is_well_formed(&self) -> bool {
        let inf_name = self.original_inf.trim();
        let relative_root = format!("drivers/backups/{}", self.backup_id);
        let mut paths = HashSet::new();
        self.schema_version == DRIVER_SCHEMA_VERSION
            && self.device_instance_id.len() <= 32_768
            && !self.device_instance_id.trim().is_empty()
            && !self.device_instance_id.chars().any(char::is_control)
            && is_oem_inf_name(inf_name)
            && self.relative_directory == relative_root
            && self.files.len() <= MAX_BACKUP_FILES
            && !self.files.is_empty()
            && is_sha256(&self.manifest_sha256)
            && self.signature_verified
            && self.files.iter().all(|file| {
                is_safe_relative_package_path(&file.relative_path)
                    && file.byte_length > 0
                    && is_sha256(&file.sha256)
                    && paths.insert(file.relative_path.to_ascii_lowercase())
            })
            && self.files.iter().any(|file| {
                file.relative_path
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(inf_name))
            })
            && self
                .files
                .iter()
                .any(|file| file.relative_path.to_ascii_lowercase().ends_with(".cat"))
    }
}

const MAX_BACKUP_FILES: usize = 8_192;

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_oem_inf_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower
        .strip_prefix("oem")
        .and_then(|suffix| suffix.strip_suffix(".inf"))
        .is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn is_safe_relative_package_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 32_768
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains(':')
        || value.chars().any(char::is_control)
    {
        return false;
    }
    value
        .split('/')
        .all(|component| !component.is_empty() && component != "." && component != "..")
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverEffectPhase {
    Prepared,
    BackupVerified,
    Downloaded,
    Installed,
    AwaitingRestart,
    Verified,
    Failed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebootRequirement {
    NotRequired,
    Required,
    Unknown,
}

/// Durable effect evidence. A successful COM return alone is not a verified
/// driver update; `Verified` requires a post-install SetupAPI read of this
/// exact device and candidate result. An unfinished journal remains uncertain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverUpdateReceipt {
    pub schema_version: u32,
    pub intent_id: uuid::Uuid,
    pub device_id: DeviceId,
    pub device_instance_id: String,
    pub candidate: CandidateIdentity,
    pub original_state: DriverInstalledState,
    pub backup: Option<DriverBackupReceipt>,
    pub restore_point_sequence: Option<i64>,
    pub phase: DriverEffectPhase,
    pub download_result_code: Option<i32>,
    pub download_hresult: Option<i32>,
    pub download_item_result_code: Option<i32>,
    pub download_item_hresult: Option<i32>,
    #[serde(default)]
    pub downloaded_verified: bool,
    pub wua_result_code: Option<i32>,
    pub hresult: Option<i32>,
    pub install_item_result_code: Option<i32>,
    pub install_item_hresult: Option<i32>,
    pub reboot: RebootRequirement,
    pub installed_after: Option<DriverInstalledState>,
}

impl DriverUpdateReceipt {
    pub fn is_restore_eligible(&self) -> bool {
        self.schema_version == DRIVER_SCHEMA_VERSION
            && !self.intent_id.is_nil()
            && self.candidate.is_valid()
            && self.phase == DriverEffectPhase::Verified
            && self.wua_result_code == Some(2)
            && self.hresult == Some(0)
            && self.download_result_code == Some(2)
            && self.download_hresult == Some(0)
            && self.download_item_result_code == Some(2)
            && self.download_item_hresult == Some(0)
            && self.downloaded_verified
            && self.install_item_result_code == Some(2)
            && self.install_item_hresult == Some(0)
            && self.reboot != RebootRequirement::Unknown
            && self.backup.as_ref().is_some_and(|backup| {
                backup.is_well_formed()
                    && backup
                        .original_inf
                        .eq_ignore_ascii_case(&self.original_state.inf)
            })
            && self
                .installed_after
                .as_ref()
                .is_some_and(installed_state_is_well_formed)
    }
}

/// Only a matching, fully verified, no-restart result permits the next item in
/// a sequential batch. Errors, mismatched receipts, pending restarts and
/// uncertain phases stop the batch.
pub fn should_continue_driver_batch(
    expected_intent_id: uuid::Uuid,
    result: &Result<DriverUpdateReceipt, DriverOperationError>,
) -> bool {
    matches!(
        result,
        Ok(receipt)
            if receipt.intent_id == expected_intent_id
                && receipt.phase == DriverEffectPhase::Verified
                && receipt.reboot == RebootRequirement::NotRequired
    )
}

/// Keeps the batch success claim scoped to verified WUA offers and the single
/// representative device checked for each offer.
pub fn representative_batch_completion_notice(verified_offers: usize) -> String {
    format!(
        "Windows verified the representative device for all {verified_offers} reviewed driver offers. Signed package backups are recorded. Related devices in shared offer groups were not individually verified."
    )
}

fn installed_state_is_well_formed(state: &DriverInstalledState) -> bool {
    !state.provider.trim().is_empty()
        && !state.version.trim().is_empty()
        && !state.date.trim().is_empty()
        && !state.inf.trim().is_empty()
        && ![&state.provider, &state.version, &state.date, &state.inf]
            .iter()
            .any(|value| value.chars().any(char::is_control))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverRestoreIntent {
    pub schema_version: u32,
    pub restore_id: uuid::Uuid,
    pub update_intent_id: uuid::Uuid,
    pub device_id: DeviceId,
    pub device_instance_id: String,
    pub hardware_ids: Vec<String>,
    pub compatible_ids: Vec<String>,
    pub expected_installed_state: DriverInstalledState,
    pub backup: DriverBackupReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriverRestoreReceipt {
    pub schema_version: u32,
    pub restore_id: uuid::Uuid,
    pub update_intent_id: uuid::Uuid,
    pub device_id: DeviceId,
    pub restored_state: Option<DriverInstalledState>,
    pub staged_inf: Option<String>,
    #[serde(default)]
    pub backup_verified: bool,
    pub phase: DriverEffectPhase,
    pub hresult: Option<i32>,
    pub reboot: RebootRequirement,
}

pub fn prepare_restore_intent(
    update_intent: &DriverUpdateIntent,
    receipt: &DriverUpdateReceipt,
    current: &DriverDevice,
) -> Result<DriverRestoreIntent, DriverOperationError> {
    let backup = receipt
        .backup
        .clone()
        .filter(DriverBackupReceipt::is_well_formed)
        .ok_or(DriverOperationError::BackupUnavailable)?;
    if receipt.schema_version != DRIVER_SCHEMA_VERSION
        || receipt.intent_id != update_intent.intent_id
        || receipt.device_id != update_intent.device_id
        || receipt.device_instance_id != update_intent.device_instance_id
        || receipt.candidate != update_intent.candidate
        || receipt.original_state
            != (DriverInstalledState {
                provider: update_intent.provider.clone(),
                version: update_intent
                    .installed_version
                    .as_known()
                    .cloned()
                    .unwrap_or_default(),
                date: update_intent
                    .installed_date
                    .as_known()
                    .cloned()
                    .unwrap_or_default(),
                inf: update_intent
                    .installed_inf
                    .as_known()
                    .cloned()
                    .unwrap_or_default(),
            })
        || receipt.phase != DriverEffectPhase::Verified
        || !receipt.is_restore_eligible()
        || receipt.installed_after.is_none()
        || backup.device_id != update_intent.device_id
        || backup.device_instance_id != update_intent.device_instance_id
        || !update_intent
            .installed_inf
            .as_known()
            .is_some_and(|inf| backup.original_inf.eq_ignore_ascii_case(inf))
        || !update_intent_is_well_formed(update_intent)
    {
        return Err(DriverOperationError::UpdateUnavailable);
    }
    let expected_installed_state = receipt
        .installed_after
        .clone()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let hardware_ids = current
        .hardware_ids
        .as_known()
        .cloned()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let compatible_ids = current
        .compatible_ids
        .as_known()
        .cloned()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let intent = DriverRestoreIntent {
        schema_version: DRIVER_SCHEMA_VERSION,
        restore_id: uuid::Uuid::new_v4(),
        update_intent_id: update_intent.intent_id,
        device_id: update_intent.device_id.clone(),
        device_instance_id: update_intent.device_instance_id.clone(),
        hardware_ids,
        compatible_ids,
        expected_installed_state,
        backup,
    };
    validate_restore_intent(&intent, update_intent, receipt, current)?;
    Ok(intent)
}

pub fn validate_restore_intent(
    intent: &DriverRestoreIntent,
    update_intent: &DriverUpdateIntent,
    receipt: &DriverUpdateReceipt,
    current: &DriverDevice,
) -> Result<(), DriverOperationError> {
    let current_instance = current
        .instance_id
        .as_known()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let current_hardware_ids = current
        .hardware_ids
        .as_known()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let current_compatible_ids = current
        .compatible_ids
        .as_known()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let current_state = DriverInstalledState::from_device(current)?;
    if !intent.backup.is_well_formed() {
        return Err(DriverOperationError::BackupUnavailable);
    }
    if intent.schema_version != DRIVER_SCHEMA_VERSION
        || intent.restore_id.is_nil()
        || intent.update_intent_id != update_intent.intent_id
        || intent.device_id != update_intent.device_id
        || intent.device_instance_id != update_intent.device_instance_id
        || intent.device_id != intent.backup.device_id
        || intent.device_instance_id != intent.backup.device_instance_id
        || !update_intent
            .installed_inf
            .as_known()
            .is_some_and(|inf| intent.backup.original_inf.eq_ignore_ascii_case(inf))
        || current.id.as_ref() != Some(&intent.device_id)
        || current_instance != &intent.device_instance_id
        || current_hardware_ids != &intent.hardware_ids
        || current_compatible_ids != &intent.compatible_ids
        || current_state != intent.expected_installed_state
        || receipt.schema_version != DRIVER_SCHEMA_VERSION
        || receipt.intent_id != intent.update_intent_id
        || receipt.device_id != intent.device_id
        || receipt.device_instance_id != intent.device_instance_id
        || receipt.candidate != update_intent.candidate
        || receipt.backup.as_ref() != Some(&intent.backup)
        || receipt.phase != DriverEffectPhase::Verified
        || !receipt.is_restore_eligible()
        || receipt.installed_after.as_ref() != Some(&intent.expected_installed_state)
        || !update_intent_is_well_formed(update_intent)
    {
        return Err(DriverOperationError::UpdateUnavailable);
    }
    Ok(())
}

fn update_intent_is_well_formed(intent: &DriverUpdateIntent) -> bool {
    intent.schema_version == DRIVER_SCHEMA_VERSION
        && !intent.intent_id.is_nil()
        && !intent.device_instance_id.trim().is_empty()
        && !intent.device_instance_id.chars().any(char::is_control)
        && intent.candidate.is_valid()
        && intent
            .installed_version
            .as_known()
            .is_some_and(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        && intent
            .installed_date
            .as_known()
            .is_some_and(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        && intent
            .installed_inf
            .as_known()
            .is_some_and(|value| !value.trim().is_empty() && !value.chars().any(char::is_control))
        && !intent.provider.trim().is_empty()
        && !intent.provider.chars().any(char::is_control)
        && DeviceId::from_instance_id(&intent.device_instance_id)
            .is_some_and(|id| id == intent.device_id)
        && intent.hardware_ids.len() <= MAX_HARDWARE_IDS_PER_DEVICE
        && intent.compatible_ids.len() <= MAX_HARDWARE_IDS_PER_DEVICE
        && intent
            .hardware_ids
            .iter()
            .chain(&intent.compatible_ids)
            .all(|id| {
                !id.trim().is_empty() && id.len() <= 16_384 && !id.chars().any(char::is_control)
            })
        && intent
            .hardware_ids
            .iter()
            .chain(&intent.compatible_ids)
            .any(|id| id.eq_ignore_ascii_case(&intent.candidate.driver_hardware_id))
}

pub fn prepare_update_intent(
    device: &DriverDevice,
    candidate: &DriverCandidate,
) -> Result<DriverUpdateIntent, DriverOperationError> {
    let device_id = device
        .id
        .clone()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let instance_id = device
        .instance_id
        .as_known()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let hardware_ids = device
        .hardware_ids
        .as_known()
        .cloned()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let compatible_ids = device
        .compatible_ids
        .as_known()
        .cloned()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let provider = device
        .provider
        .as_known()
        .cloned()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let installed_version = device
        .installed_version
        .as_known()
        .cloned()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let installed_date = device
        .installed_date
        .as_known()
        .cloned()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let installed_inf = device
        .inf_path
        .as_known()
        .cloned()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let matched = candidate_matches_only_device(candidate, &device_id);
    let candidate_hardware_matches = hardware_ids
        .iter()
        .chain(&compatible_ids)
        .any(|id| id.eq_ignore_ascii_case(&candidate.identity.driver_hardware_id));
    if candidate.id != candidate.identity.id()
        || !candidate.identity.is_valid()
        || !matched
        || !candidate_hardware_matches
        || candidate.eula_accepted.as_known() != Some(&true)
        || candidate.installed.as_known() != Some(&false)
        || candidate.hidden.as_known() != Some(&false)
    {
        return Err(DriverOperationError::UpdateUnavailable);
    }
    Ok(DriverUpdateIntent {
        schema_version: DRIVER_SCHEMA_VERSION,
        intent_id: uuid::Uuid::new_v4(),
        device_id,
        device_instance_id: instance_id,
        hardware_ids,
        compatible_ids,
        class_guid: device.class_guid.clone(),
        provider,
        installed_version: FieldValue::Known {
            value: installed_version,
        },
        installed_date: FieldValue::Known {
            value: installed_date,
        },
        installed_inf: FieldValue::Known {
            value: installed_inf,
        },
        problem_code: device.problem_code.clone(),
        candidate: candidate.identity.clone(),
    })
}

pub fn validate_update_intent(
    intent: &DriverUpdateIntent,
    current: &DriverDevice,
    candidate: &DriverCandidate,
) -> Result<(), DriverOperationError> {
    validate_update_identity(intent, current, candidate)
}

pub fn validate_update_identity(
    intent: &DriverUpdateIntent,
    current: &DriverDevice,
    candidate: &DriverCandidate,
) -> Result<(), DriverOperationError> {
    if !update_intent_is_well_formed(intent) {
        return Err(DriverOperationError::UpdateUnavailable);
    }
    let current_instance = current
        .instance_id
        .as_known()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let current_hardware_ids = current
        .hardware_ids
        .as_known()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let current_compatible_ids = current
        .compatible_ids
        .as_known()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    let current_provider = current
        .provider
        .as_known()
        .ok_or(DriverOperationError::UpdateUnavailable)?;
    if current.installed_version.as_known().is_none()
        || current.installed_date.as_known().is_none()
        || current.inf_path.as_known().is_none()
    {
        return Err(DriverOperationError::UpdateUnavailable);
    }
    if intent.schema_version != DRIVER_SCHEMA_VERSION
        || current.id.as_ref() != Some(&intent.device_id)
        || current_instance != &intent.device_instance_id
        || current_hardware_ids != &intent.hardware_ids
        || current_compatible_ids != &intent.compatible_ids
        || current.class_guid != intent.class_guid
        || current_provider != &intent.provider
        || current.installed_version != intent.installed_version
        || current.installed_date != intent.installed_date
        || current.inf_path != intent.installed_inf
        || current.problem_code != intent.problem_code
        || candidate.id != candidate.identity.id()
        || !candidate.identity.is_valid()
        || candidate.identity != intent.candidate
        || !candidate_matches_only_device(candidate, &intent.device_id)
        || !intent
            .hardware_ids
            .iter()
            .chain(&intent.compatible_ids)
            .any(|id| id.eq_ignore_ascii_case(&intent.candidate.driver_hardware_id))
        || candidate.installed.as_known() != Some(&false)
        || candidate.eula_accepted.as_known() != Some(&true)
        || candidate.hidden.as_known() != Some(&false)
    {
        return Err(DriverOperationError::UpdateUnavailable);
    }
    Ok(())
}

fn device_matches_update_intent(intent: &DriverUpdateIntent, current: &DriverDevice) -> bool {
    current.id.as_ref() == Some(&intent.device_id)
        && current.instance_id.as_known() == Some(&intent.device_instance_id)
        && current.hardware_ids.as_known() == Some(&intent.hardware_ids)
        && current.compatible_ids.as_known() == Some(&intent.compatible_ids)
        && current.class_guid == intent.class_guid
        && current.provider.as_known() == Some(&intent.provider)
        && current.installed_version == intent.installed_version
        && current.installed_date == intent.installed_date
        && current.inf_path == intent.installed_inf
        && current.problem_code == intent.problem_code
}

fn candidate_matches_only_device(candidate: &DriverCandidate, device_id: &DeviceId) -> bool {
    matches!(
        &candidate.applicability,
        CandidateMatch::Matched { devices } if devices.len() == 1 && devices[0] == *device_id
    )
}

fn digest(bytes: &[u8]) -> String {
    let mut left = 0xcbf29ce484222325u64;
    let mut right = 0x84222325cbf29ce4u64;
    for byte in bytes {
        left ^= u64::from(*byte);
        left = left.wrapping_mul(0x100000001b3);
        right ^= u64::from(*byte).wrapping_add(0x9d);
        right = right.wrapping_mul(0x100000001b3);
    }
    format!("{left:016x}{right:016x}")
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::mem::size_of;
    use std::{
        ffi::OsString,
        io::Read,
        os::windows::{
            ffi::{OsStrExt, OsStringExt},
            process::CommandExt,
        },
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    use windows::{
        Win32::{
            Devices::{
                DeviceAndDriverInstallation::{
                    DIGCF_ALLCLASSES, DIGCF_PRESENT, DIIDFLAG_NOFINISHINSTALLUI, DiInstallDevice,
                    HDEVINFO, SETUP_DI_REGISTRY_PROPERTY, SP_COPY_NOOVERWRITE, SP_DEVINFO_DATA,
                    SP_DRVINFO_DATA_V2_W, SP_DRVINFO_DETAIL_DATA_W, SP_INF_SIGNER_INFO_V2_W,
                    SPDIT_COMPATDRIVER, SPDRP_CLASS, SPDRP_DEVICEDESC, SPOST_PATH,
                    SetupCopyOEMInfW, SetupDiBuildDriverInfoList, SetupDiDestroyDeviceInfoList,
                    SetupDiDestroyDriverInfoList, SetupDiEnumDeviceInfo, SetupDiEnumDriverInfoW,
                    SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW, SetupDiGetDevicePropertyW,
                    SetupDiGetDeviceRegistryPropertyW, SetupDiGetDriverInfoDetailW,
                    SetupDiOpenDeviceInfoW, SetupDiSetSelectedDriverW,
                    SetupGetInfDriverStoreLocationW, SetupVerifyInfFileW,
                },
                Properties::{
                    DEVPKEY_Device_Class, DEVPKEY_Device_CompatibleIds, DEVPKEY_Device_DriverDate,
                    DEVPKEY_Device_DriverInfPath, DEVPKEY_Device_DriverProvider,
                    DEVPKEY_Device_DriverVersion, DEVPKEY_Device_FriendlyName,
                    DEVPKEY_Device_HardwareIds, DEVPKEY_Device_ProblemCode, DEVPROP_TYPE_FILETIME,
                    DEVPROP_TYPE_STRING, DEVPROP_TYPE_STRING_INDIRECT, DEVPROP_TYPE_STRING_LIST,
                    DEVPROP_TYPE_UINT32,
                },
            },
            Foundation::{DEVPROPKEY, ERROR_NO_MORE_ITEMS, GetLastError, VARIANT_BOOL},
            Security::Cryptography::{
                BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE, BCRYPT_OBJECT_LENGTH,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_SHA256_ALGORITHM,
                BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash,
                BCryptFinishHash, BCryptGetProperty, BCryptHashData, BCryptOpenAlgorithmProvider,
            },
            System::{
                Com::{
                    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                    CoUninitialize,
                },
                Restore::{
                    BEGIN_SYSTEM_CHANGE, CANCELLED_OPERATION, DEVICE_DRIVER_INSTALL,
                    END_SYSTEM_CHANGE, RESTOREPOINTINFOW, SRSetRestorePointW, STATEMGRSTATUS,
                },
                SystemInformation::GetSystemDirectoryW,
                UpdateAgent::{
                    IUpdate, IUpdateCollection, IWindowsDriverUpdate, UpdateCollection,
                    UpdateSession, orcSucceeded, orcSucceededWithErrors, ssDefault,
                    ssManagedServer, ssOthers, ssWindowsUpdate,
                },
            },
        },
        core::{BOOL, BSTR, Interface, PCWSTR},
    };

    pub struct WindowsDriverPlatform;

    impl DriverPlatform for WindowsDriverPlatform {
        fn inventory_devices(&mut self) -> DeviceInventory {
            enumerate_devices()
        }

        fn search_catalogue(&mut self) -> DriverCatalogue {
            search_wua_catalogue()
        }
    }

    impl DriverActionBoundary for WindowsDriverPlatform {
        fn current_device(&mut self, id: &DeviceId) -> Result<DriverDevice, DriverOperationError> {
            let inventory = enumerate_devices();
            if inventory.source.quality != InventoryQuality::Complete {
                return Err(DriverOperationError::UpdateUnavailable);
            }
            let mut matches = inventory
                .devices
                .into_iter()
                .filter(|device| device.id.as_ref() == Some(id));
            let device = matches
                .next()
                .ok_or(DriverOperationError::UpdateUnavailable)?;
            if matches.next().is_some() {
                return Err(DriverOperationError::UpdateUnavailable);
            }
            Ok(device)
        }

        fn exact_candidate(
            &mut self,
            identity: &CandidateIdentity,
        ) -> Result<DriverCandidate, DriverOperationError> {
            if !identity.is_valid() {
                return Err(DriverOperationError::UpdateUnavailable);
            }
            let inventory = enumerate_devices();
            let catalogue = search_wua_catalogue();
            if inventory.source.quality != InventoryQuality::Complete
                || !matches!(catalogue.state, CatalogueState::Read { .. })
            {
                return Err(DriverOperationError::UpdateUnavailable);
            }
            let snapshot = DriverSnapshot::assemble(inventory, catalogue);
            snapshot
                .catalogue
                .candidates
                .into_iter()
                .find(|candidate| candidate.identity == *identity)
                .ok_or(DriverOperationError::UpdateUnavailable)
        }

        fn create_restore_point(&mut self, description: &str) -> Result<i64, DriverOperationError> {
            create_system_restore_point(description)
        }

        fn export_driver_package(
            &mut self,
            root: &Path,
            intent: &DriverUpdateIntent,
            backup_id: uuid::Uuid,
        ) -> Result<DriverBackupReceipt, DriverOperationError> {
            export_installed_package(root, intent, backup_id)
        }

        fn download_and_install(
            &mut self,
            intent: &DriverUpdateIntent,
        ) -> Result<DriverInstallOutcome, DriverOperationError> {
            download_and_install_exact(intent)
        }

        fn candidate_is_installed(
            &mut self,
            identity: &CandidateIdentity,
        ) -> Result<bool, DriverOperationError> {
            exact_candidate_installed(identity)
        }

        fn restore_from_package(
            &mut self,
            root: &Path,
            intent: &DriverRestoreIntent,
        ) -> Result<DriverRestoreOutcome, DriverOperationError> {
            restore_exact_device_from_backup(root, intent)
        }
    }

    fn create_system_restore_point(description: &str) -> Result<i64, DriverOperationError> {
        if description.is_empty() || description.chars().any(char::is_control) {
            return Err(DriverOperationError::NativeUpdateBoundaryUnavailable);
        }
        let mut info = RESTOREPOINTINFOW::default();
        info.dwEventType = BEGIN_SYSTEM_CHANGE;
        info.dwRestorePtType = DEVICE_DRIVER_INSTALL;
        let mut text = [0u16; 256];
        for (slot, value) in text.iter_mut().take(255).zip(description.encode_utf16()) {
            *slot = value;
        }
        info.szDescription = text;
        let mut status = STATEMGRSTATUS::default();
        let created = unsafe { SRSetRestorePointW(&info, &mut status) };
        if !created.as_bool() {
            let code = unsafe { std::ptr::addr_of!(status.nStatus).read_unaligned() }.0;
            return Err(DriverOperationError::NativeFailure {
                native_code: Some(code),
            });
        }
        let sequence = unsafe { std::ptr::addr_of!(status.llSequenceNumber).read_unaligned() };
        if sequence <= 0 {
            return Err(DriverOperationError::NativeUpdateBoundaryUnavailable);
        }
        // Close the restore-point transaction immediately. The point itself
        // remains a pre-change snapshot even if a later backup or WUA step
        // fails, and Windows does not retain an open restore operation.
        end_system_restore_point(sequence, true)?;
        Ok(sequence)
    }

    fn end_system_restore_point(
        sequence: i64,
        operation_succeeded: bool,
    ) -> Result<(), DriverOperationError> {
        if sequence <= 0 {
            return Err(DriverOperationError::NativeUpdateBoundaryUnavailable);
        }
        let mut info = RESTOREPOINTINFOW::default();
        info.dwEventType = END_SYSTEM_CHANGE;
        info.dwRestorePtType = if operation_succeeded {
            DEVICE_DRIVER_INSTALL
        } else {
            CANCELLED_OPERATION
        };
        info.llSequenceNumber = sequence;
        let mut status = STATEMGRSTATUS::default();
        let ended = unsafe { SRSetRestorePointW(&info, &mut status) };
        if ended.as_bool() {
            Ok(())
        } else {
            let code = unsafe { std::ptr::addr_of!(status.nStatus).read_unaligned() }.0;
            Err(DriverOperationError::NativeFailure {
                native_code: Some(code),
            })
        }
    }

    fn system_directory() -> Result<std::path::PathBuf, DriverOperationError> {
        let mut buffer = vec![0u16; 32_768];
        let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
        if length == 0 || length >= buffer.len() {
            return Err(DriverOperationError::NativeFailure {
                native_code: Some(unsafe { GetLastError() }.0),
            });
        }
        buffer.truncate(length);
        Ok(std::path::PathBuf::from(OsString::from_wide(&buffer)))
    }

    fn ensure_plain_directory(path: &Path) -> Result<(), DriverOperationError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if crate::scanner::is_link(&metadata) || !metadata.is_dir() => {
                Err(DriverOperationError::BackupUnavailable)
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(path).map_err(|_| DriverOperationError::BackupUnavailable)?;
                let metadata = fs::symlink_metadata(path)
                    .map_err(|_| DriverOperationError::BackupUnavailable)?;
                if crate::scanner::is_link(&metadata) || !metadata.is_dir() {
                    Err(DriverOperationError::BackupUnavailable)
                } else {
                    Ok(())
                }
            }
            Err(_) => Err(DriverOperationError::BackupUnavailable),
        }
    }

    fn create_backup_directory(
        root: &Path,
        backup_id: uuid::Uuid,
    ) -> Result<std::path::PathBuf, DriverOperationError> {
        if !root.is_absolute() {
            return Err(DriverOperationError::BackupUnavailable);
        }
        let root_meta =
            fs::symlink_metadata(root).map_err(|_| DriverOperationError::BackupUnavailable)?;
        if crate::scanner::is_link(&root_meta) || !root_meta.is_dir() {
            return Err(DriverOperationError::BackupUnavailable);
        }
        let canonical_root =
            fs::canonicalize(root).map_err(|_| DriverOperationError::BackupUnavailable)?;
        let drivers = canonical_root.join("drivers");
        ensure_plain_directory(&drivers)?;
        let backups = drivers.join("backups");
        ensure_plain_directory(&backups)?;
        let target = backups.join(backup_id.to_string());
        ensure_plain_directory(&target)?;
        if fs::read_dir(&target)
            .map_err(|_| DriverOperationError::BackupUnavailable)?
            .next()
            .is_some()
        {
            return Err(DriverOperationError::BackupUnavailable);
        }
        Ok(target)
    }

    fn run_pnputil_export(inf: &str, target: &Path) -> Result<(), DriverOperationError> {
        if !is_oem_inf_name(inf) {
            return Err(DriverOperationError::BackupUnavailable);
        }
        let executable = system_directory()?.join("pnputil.exe");
        let metadata = fs::symlink_metadata(&executable)
            .map_err(|_| DriverOperationError::NativeUpdateBoundaryUnavailable)?;
        if crate::scanner::is_link(&metadata) || !metadata.is_file() {
            return Err(DriverOperationError::NativeUpdateBoundaryUnavailable);
        }
        let mut child = Command::new(executable)
            .arg("/export-driver")
            .arg(inf)
            .arg(target)
            .creation_flags(0x0800_0000)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| DriverOperationError::NativeFailure { native_code: None })?;
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => {
                    return Err(DriverOperationError::NativeFailure {
                        native_code: status.code().map(|code| code as u32),
                    });
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(DriverOperationError::NativeFailure { native_code: None });
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(DriverOperationError::NativeFailure { native_code: None });
                }
            }
        }
    }

    fn export_installed_package(
        root: &Path,
        intent: &DriverUpdateIntent,
        backup_id: uuid::Uuid,
    ) -> Result<DriverBackupReceipt, DriverOperationError> {
        let fresh = enumerate_devices();
        if fresh.source.quality != InventoryQuality::Complete
            || fresh
                .devices
                .iter()
                .filter(|device| device.id.as_ref() == Some(&intent.device_id))
                .count()
                != 1
            || !fresh
                .devices
                .iter()
                .find(|device| device.id.as_ref() == Some(&intent.device_id))
                .is_some_and(|device| device_matches_update_intent(intent, device))
        {
            return Err(DriverOperationError::UpdateUnavailable);
        }
        let inf = intent
            .installed_inf
            .as_known()
            .map(String::as_str)
            .filter(|value| is_oem_inf_name(value))
            .ok_or(DriverOperationError::BackupUnavailable)?;
        let backup_dir = create_backup_directory(root, backup_id)?;
        run_pnputil_export(inf, &backup_dir)?;

        let mut files = Vec::new();
        let mut total_bytes = 0u64;
        collect_package_files(&backup_dir, &backup_dir, 0, &mut files, &mut total_bytes)?;
        files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        let inf_file = files
            .iter()
            .find(|file| {
                file.relative_path
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(inf))
            })
            .ok_or(DriverOperationError::BackupUnavailable)?;
        let inf_path = backup_dir.join(
            inf_file
                .relative_path
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        );
        verify_signed_inf(&inf_path)?;
        let manifest_sha256 = manifest_hash(&files)?;
        let receipt = DriverBackupReceipt {
            schema_version: DRIVER_SCHEMA_VERSION,
            backup_id,
            device_id: intent.device_id.clone(),
            device_instance_id: intent.device_instance_id.clone(),
            original_inf: inf.to_owned(),
            relative_directory: format!("drivers/backups/{backup_id}"),
            files,
            manifest_sha256,
            signature_verified: true,
        };
        if receipt.is_well_formed() {
            Ok(receipt)
        } else {
            Err(DriverOperationError::BackupUnavailable)
        }
    }

    fn restore_exact_device_from_backup(
        root: &Path,
        intent: &DriverRestoreIntent,
    ) -> Result<DriverRestoreOutcome, DriverOperationError> {
        let (_backup_dir, source_inf) = verify_backup_artifacts(root, &intent.backup)?;
        let source_wide = source_inf
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        // SetupCopyOEMInf documents MAX_PATH for the INF path. Long paths are
        // rejected here rather than normalized or shortened.
        if source_wide.len() > 260 {
            return Err(DriverOperationError::BackupUnavailable);
        }

        let set = unsafe {
            SetupDiGetClassDevsW(None, PCWSTR::null(), None, DIGCF_ALLCLASSES | DIGCF_PRESENT)
        }
        .map(DeviceSet)
        .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
        let instance_wide = intent
            .device_instance_id
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut data = SP_DEVINFO_DATA {
            cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        unsafe {
            SetupDiOpenDeviceInfoW(
                set.0,
                PCWSTR::from_raw(instance_wide.as_ptr()),
                None,
                0,
                Some(&mut data),
            )
        }
        .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
        let initial = read_device(set.0, &data);
        if !device_matches_restore_identity(intent, &initial) {
            return Err(DriverOperationError::UpdateUnavailable);
        }

        let mut destination_wide = vec![0u16; 260];
        let mut required = 0u32;
        unsafe {
            SetupCopyOEMInfW(
                PCWSTR::from_raw(source_wide.as_ptr()),
                PCWSTR::null(),
                SPOST_PATH,
                SP_COPY_NOOVERWRITE,
                Some(&mut destination_wide),
                Some(&mut required),
                None,
            )
        }
        .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
        if required as usize > destination_wide.len() {
            return Err(DriverOperationError::BackupUnavailable);
        }
        let destination_len = destination_wide
            .iter()
            .position(|value| *value == 0)
            .ok_or(DriverOperationError::BackupUnavailable)?;
        if destination_len == 0 || destination_len >= destination_wide.len() {
            return Err(DriverOperationError::BackupUnavailable);
        }
        let staged_inf =
            std::path::PathBuf::from(OsString::from_wide(&destination_wide[..destination_len]));
        let staged_name = staged_inf
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| is_oem_inf_name(value))
            .ok_or(DriverOperationError::BackupUnavailable)?;
        verify_signed_inf(&staged_inf)?;
        let expected_store_inf = inf_driver_store_location(&staged_inf)?;
        verify_signed_inf(&expected_store_inf)?;
        unsafe { SetupDiBuildDriverInfoList(set.0, Some(&mut data), SPDIT_COMPATDRIVER) }
            .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;

        let install = (|| {
            let mut selected: Option<SP_DRVINFO_DATA_V2_W> = None;
            for index in 0..=MAX_CANDIDATES {
                let mut driver = SP_DRVINFO_DATA_V2_W {
                    cbSize: size_of::<SP_DRVINFO_DATA_V2_W>() as u32,
                    ..Default::default()
                };
                match unsafe {
                    SetupDiEnumDriverInfoW(
                        set.0,
                        Some(&data),
                        SPDIT_COMPATDRIVER,
                        index as u32,
                        &mut driver,
                    )
                } {
                    Ok(()) => {}
                    Err(error) if is_error(&error, ERROR_NO_MORE_ITEMS.0) => break,
                    Err(error) => {
                        return Err(operation_error_from_hresult(error.code().0 as u32));
                    }
                }
                if index == MAX_CANDIDATES {
                    return Err(DriverOperationError::UpdateUnavailable);
                }
                let bytes = size_of::<SP_DRVINFO_DETAIL_DATA_W>()
                    .checked_add(MAX_PROPERTY_BYTES)
                    .ok_or(DriverOperationError::BackupUnavailable)?;
                let mut storage = vec![0u64; bytes.div_ceil(size_of::<u64>())];
                let detail = storage.as_mut_ptr().cast::<SP_DRVINFO_DETAIL_DATA_W>();
                unsafe {
                    detail.write(SP_DRVINFO_DETAIL_DATA_W {
                        cbSize: size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32,
                        ..Default::default()
                    });
                }
                let mut needed = 0u32;
                unsafe {
                    SetupDiGetDriverInfoDetailW(
                        set.0,
                        Some(&data),
                        &driver,
                        Some(detail),
                        u32::try_from(bytes)
                            .map_err(|_| DriverOperationError::BackupUnavailable)?,
                        Some(&mut needed),
                    )
                }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
                if needed as usize > bytes {
                    return Err(DriverOperationError::BackupUnavailable);
                }
                let inf_wide =
                    unsafe { std::ptr::addr_of!((*detail).InfFileName).read_unaligned() };
                let inf = decode_fixed_wide(&inf_wide);
                if inf.is_empty() {
                    return Err(DriverOperationError::UpdateUnavailable);
                }
                let is_exact_package = std::path::Path::new(&inf)
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.eq_ignore_ascii_case(staged_name));
                if is_exact_package {
                    let candidate_store_inf =
                        inf_driver_store_location(std::path::Path::new(&inf))?;
                    if !same_canonical_path(&candidate_store_inf, &expected_store_inf)? {
                        return Err(DriverOperationError::UpdateUnavailable);
                    }
                    if !driver_detail_matches_hardware(detail, bytes, intent) {
                        return Err(DriverOperationError::UpdateUnavailable);
                    }
                    if selected.replace(driver).is_some() {
                        return Err(DriverOperationError::UpdateUnavailable);
                    }
                }
            }
            let mut selected = selected.ok_or(DriverOperationError::UpdateUnavailable)?;

            // Device and package identity are checked again after building the
            // SetupAPI list and directly before selecting/installing it.
            let current = read_device(set.0, &data);
            if !device_matches_restore_identity(intent, &current) {
                return Err(DriverOperationError::UpdateUnavailable);
            }
            unsafe { SetupDiSetSelectedDriverW(set.0, Some(&mut data), Some(&mut selected)) }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            let mut reboot = BOOL(0);
            unsafe {
                DiInstallDevice(
                    None,
                    set.0,
                    &data,
                    Some(&selected),
                    DIIDFLAG_NOFINISHINSTALLUI,
                    Some(&mut reboot),
                )
            }
            .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            Ok(if reboot.0 != 0 {
                RebootRequirement::Required
            } else {
                RebootRequirement::NotRequired
            })
        })();
        let cleanup =
            unsafe { SetupDiDestroyDriverInfoList(set.0, Some(&data), SPDIT_COMPATDRIVER) };
        match (install, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(operation_error_from_hresult(error.code().0 as u32)),
            (Ok(reboot), Ok(())) => Ok(DriverRestoreOutcome {
                staged_inf: staged_name.to_owned(),
                reboot,
            }),
        }
    }

    fn device_matches_restore_identity(
        intent: &DriverRestoreIntent,
        device: &DriverDevice,
    ) -> bool {
        device.id.as_ref() == Some(&intent.device_id)
            && device.instance_id.as_known() == Some(&intent.device_instance_id)
            && device.hardware_ids.as_known() == Some(&intent.hardware_ids)
            && device.compatible_ids.as_known() == Some(&intent.compatible_ids)
            && DriverInstalledState::from_device(device).as_ref()
                == Ok(&intent.expected_installed_state)
    }

    fn inf_driver_store_location(path: &Path) -> Result<std::path::PathBuf, DriverOperationError> {
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        if wide.len() > 260 {
            return Err(DriverOperationError::BackupUnavailable);
        }
        let mut buffer = vec![0u16; 260];
        let mut required = 0u32;
        unsafe {
            SetupGetInfDriverStoreLocationW(
                PCWSTR::from_raw(wide.as_ptr()),
                None,
                PCWSTR::null(),
                &mut buffer,
                Some(&mut required),
            )
        }
        .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
        if required as usize > buffer.len() {
            return Err(DriverOperationError::BackupUnavailable);
        }
        let length = buffer
            .iter()
            .position(|value| *value == 0)
            .ok_or(DriverOperationError::BackupUnavailable)?;
        if length == 0 || length >= buffer.len() {
            return Err(DriverOperationError::BackupUnavailable);
        }
        Ok(std::path::PathBuf::from(OsString::from_wide(
            &buffer[..length],
        )))
    }

    fn same_canonical_path(left: &Path, right: &Path) -> Result<bool, DriverOperationError> {
        let left = fs::canonicalize(left).map_err(|_| DriverOperationError::BackupUnavailable)?;
        let right = fs::canonicalize(right).map_err(|_| DriverOperationError::BackupUnavailable)?;
        Ok(left
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy()))
    }

    fn driver_detail_matches_hardware(
        detail: *const SP_DRVINFO_DETAIL_DATA_W,
        byte_length: usize,
        intent: &DriverRestoreIntent,
    ) -> bool {
        let offset = std::mem::offset_of!(SP_DRVINFO_DETAIL_DATA_W, HardwareID);
        let Some(hardware_length) = byte_length.checked_sub(offset) else {
            return false;
        };
        let units = hardware_length / size_of::<u16>();
        if units == 0 {
            return false;
        }
        let hardware_start = unsafe { std::ptr::addr_of!((*detail).HardwareID).cast::<u16>() };
        let hardware = unsafe { std::slice::from_raw_parts(hardware_start, units) };
        let Some(end) = hardware.iter().position(|value| *value == 0) else {
            return false;
        };
        let Ok(hardware_id) = String::from_utf16(&hardware[..end]) else {
            return false;
        };
        intent
            .hardware_ids
            .iter()
            .chain(&intent.compatible_ids)
            .any(|id| id.eq_ignore_ascii_case(hardware_id.trim()))
    }

    fn verify_backup_artifacts(
        root: &Path,
        backup: &DriverBackupReceipt,
    ) -> Result<(std::path::PathBuf, std::path::PathBuf), DriverOperationError> {
        if !backup.is_well_formed() {
            return Err(DriverOperationError::BackupUnavailable);
        }
        let root_meta =
            fs::symlink_metadata(root).map_err(|_| DriverOperationError::BackupUnavailable)?;
        if crate::scanner::is_link(&root_meta) || !root_meta.is_dir() {
            return Err(DriverOperationError::BackupUnavailable);
        }
        let canonical_root =
            fs::canonicalize(root).map_err(|_| DriverOperationError::BackupUnavailable)?;
        let expected_root = canonical_root.join("drivers").join("backups");
        for directory in [canonical_root.join("drivers"), expected_root.clone()] {
            let metadata = fs::symlink_metadata(&directory)
                .map_err(|_| DriverOperationError::BackupUnavailable)?;
            if crate::scanner::is_link(&metadata) || !metadata.is_dir() {
                return Err(DriverOperationError::BackupUnavailable);
            }
        }
        let backup_dir = expected_root.join(backup.backup_id.to_string());
        let metadata = fs::symlink_metadata(&backup_dir)
            .map_err(|_| DriverOperationError::BackupUnavailable)?;
        if crate::scanner::is_link(&metadata) || !metadata.is_dir() {
            return Err(DriverOperationError::BackupUnavailable);
        }
        let canonical_backup =
            fs::canonicalize(&backup_dir).map_err(|_| DriverOperationError::BackupUnavailable)?;
        if !canonical_backup.starts_with(&canonical_root) {
            return Err(DriverOperationError::BackupUnavailable);
        }

        let mut observed = Vec::new();
        let mut total_bytes = 0u64;
        collect_package_files(
            &canonical_backup,
            &canonical_backup,
            0,
            &mut observed,
            &mut total_bytes,
        )?;
        observed.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        if observed != backup.files || manifest_hash(&observed)? != backup.manifest_sha256 {
            return Err(DriverOperationError::BackupUnavailable);
        }
        let inf = observed
            .iter()
            .find(|file| {
                file.relative_path
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&backup.original_inf))
            })
            .map(|file| {
                canonical_backup.join(
                    file.relative_path
                        .replace('/', std::path::MAIN_SEPARATOR_STR),
                )
            })
            .ok_or(DriverOperationError::BackupUnavailable)?;
        verify_signed_inf(&inf)?;
        Ok((canonical_backup, inf))
    }

    fn collect_package_files(
        root: &Path,
        directory: &Path,
        depth: usize,
        output: &mut Vec<DriverBackupFile>,
        total_bytes: &mut u64,
    ) -> Result<(), DriverOperationError> {
        if depth > 24 || output.len() > MAX_BACKUP_PACKAGE_FILES {
            return Err(DriverOperationError::BackupUnavailable);
        }
        for entry in fs::read_dir(directory).map_err(|_| DriverOperationError::BackupUnavailable)? {
            let entry = entry.map_err(|_| DriverOperationError::BackupUnavailable)?;
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| DriverOperationError::BackupUnavailable)?;
            if crate::scanner::is_link(&metadata) {
                return Err(DriverOperationError::BackupUnavailable);
            }
            if metadata.is_dir() {
                collect_package_files(root, &path, depth + 1, output, total_bytes)?;
                continue;
            }
            if !metadata.is_file()
                || metadata.len() == 0
                || metadata.len() > MAX_SINGLE_PACKAGE_FILE_BYTES
                || output.len() >= MAX_BACKUP_PACKAGE_FILES
            {
                return Err(DriverOperationError::BackupUnavailable);
            }
            *total_bytes = total_bytes
                .checked_add(metadata.len())
                .filter(|value| *value <= MAX_BACKUP_PACKAGE_BYTES)
                .ok_or(DriverOperationError::BackupUnavailable)?;
            let relative_path = path
                .strip_prefix(root)
                .map_err(|_| DriverOperationError::BackupUnavailable)?
                .components()
                .map(|component| component.as_os_str().to_str())
                .collect::<Option<Vec<_>>>()
                .ok_or(DriverOperationError::BackupUnavailable)?
                .join("/");
            if !is_safe_relative_package_path(&relative_path) {
                return Err(DriverOperationError::BackupUnavailable);
            }
            let (length, sha256) = hash_package_file(&path)?;
            if length != metadata.len() {
                return Err(DriverOperationError::BackupUnavailable);
            }
            output.push(DriverBackupFile {
                relative_path,
                byte_length: length,
                sha256,
            });
        }
        Ok(())
    }

    fn verify_signed_inf(path: &Path) -> Result<(), DriverOperationError> {
        let mut signer = SP_INF_SIGNER_INFO_V2_W::default();
        signer.cbSize = size_of::<SP_INF_SIGNER_INFO_V2_W>() as u32;
        let inf_wide = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let verified =
            unsafe { SetupVerifyInfFileW(PCWSTR::from_raw(inf_wide.as_ptr()), None, &mut signer) };
        if !verified.as_bool() {
            return Err(DriverOperationError::PackageSignatureUnavailable);
        }
        let catalog = unsafe { std::ptr::addr_of!(signer.CatalogFile).read_unaligned() };
        let signer_name = unsafe { std::ptr::addr_of!(signer.DigitalSigner).read_unaligned() };
        if decode_fixed_wide(&catalog).is_empty() || decode_fixed_wide(&signer_name).is_empty() {
            return Err(DriverOperationError::PackageSignatureUnavailable);
        }
        Ok(())
    }

    fn decode_fixed_wide(value: &[u16]) -> String {
        let end = value
            .iter()
            .position(|item| *item == 0)
            .unwrap_or(value.len());
        String::from_utf16(&value[..end]).unwrap_or_default()
    }

    fn manifest_hash(files: &[DriverBackupFile]) -> Result<String, DriverOperationError> {
        let mut hash = Sha256::new()?;
        for file in files {
            hash.update(file.relative_path.as_bytes())?;
            hash.update(&[0])?;
            hash.update(&file.byte_length.to_le_bytes())?;
            hash.update(file.sha256.as_bytes())?;
            hash.update(&[b'\n'])?;
        }
        hash.finish()
    }

    fn hash_package_file(path: &Path) -> Result<(u64, String), DriverOperationError> {
        let mut file = fs::File::open(path).map_err(|_| DriverOperationError::BackupUnavailable)?;
        let mut hash = Sha256::new()?;
        let mut buffer = [0u8; 64 * 1024];
        let mut length = 0u64;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| DriverOperationError::BackupUnavailable)?;
            if read == 0 {
                break;
            }
            length = length
                .checked_add(read as u64)
                .filter(|value| *value <= MAX_SINGLE_PACKAGE_FILE_BYTES)
                .ok_or(DriverOperationError::BackupUnavailable)?;
            hash.update(&buffer[..read])?;
        }
        Ok((length, hash.finish()?))
    }

    fn with_exact_wua_update<T>(
        expected: &CandidateIdentity,
        allow_installed: bool,
        action: impl FnOnce(
            &windows::Win32::System::UpdateAgent::IUpdateSession,
            &IUpdate,
        ) -> Result<T, DriverOperationError>,
    ) -> Result<T, DriverOperationError> {
        if !expected.is_valid() {
            return Err(DriverOperationError::UpdateUnavailable);
        }
        let _apartment =
            ComApartment::initialize().map_err(|issue| DriverOperationError::NativeFailure {
                native_code: issue.failure.native_code,
            })?;
        let session = unsafe {
            CoCreateInstance::<_, windows::Win32::System::UpdateAgent::IUpdateSession>(
                &UpdateSession,
                None,
                CLSCTX_INPROC_SERVER,
            )
        }
        .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
        let searcher = unsafe { session.CreateUpdateSearcher() }
            .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
        let selection = match expected.source.server_selection {
            WuaServerSelection::PolicyDefault => ssDefault,
            WuaServerSelection::ManagedServer => ssManagedServer,
            WuaServerSelection::WindowsUpdate => ssWindowsUpdate,
            WuaServerSelection::Other => ssOthers,
            WuaServerSelection::Unknown(_) => {
                return Err(DriverOperationError::UpdateUnavailable);
            }
        };
        unsafe { searcher.SetServerSelection(selection) }
            .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
        if !expected.source.service_id.is_empty() {
            let service_id = BSTR::from(expected.source.service_id.as_str());
            unsafe { searcher.SetServiceID(&service_id) }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
        }
        unsafe {
            searcher.SetOnline(VARIANT_BOOL(if expected.source.online_search {
                -1
            } else {
                0
            }))
        }
        .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
        let actual_source = WuaSource {
            server_selection: WuaServerSelection::from_raw(
                unsafe { searcher.ServerSelection() }
                    .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?
                    .0,
            ),
            service_id: unsafe { searcher.ServiceID() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?
                .to_string(),
            online_search: unsafe { searcher.Online() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?
                .0
                != 0,
        };
        if actual_source != expected.source {
            return Err(DriverOperationError::UpdateUnavailable);
        }
        let criteria = BSTR::from(if allow_installed {
            "Type='Driver'"
        } else {
            "Type='Driver' and IsInstalled=0 and IsHidden=0"
        });
        let result = unsafe { searcher.Search(&criteria) }
            .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
        let result_code = unsafe { result.ResultCode() }
            .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
        if result_code != orcSucceeded {
            return Err(DriverOperationError::UpdateUnavailable);
        }
        let updates = unsafe { result.Updates() }
            .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
        let count = unsafe { updates.Count() }
            .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
        if count < 0 || usize::try_from(count).unwrap_or(usize::MAX) > MAX_CANDIDATES {
            return Err(DriverOperationError::UpdateUnavailable);
        }
        let mut matched = None;
        for index in 0..count {
            let update = unsafe { updates.get_Item(index) }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            let candidate = read_candidate(Ok(update.clone()), &actual_source)
                .map_err(|_| DriverOperationError::UpdateUnavailable)?;
            if candidate.identity == *expected {
                if candidate.eula_accepted.as_known() != Some(&true) {
                    return Err(DriverOperationError::EulaNotAccepted);
                }
                if (!allow_installed && candidate.installed.as_known() != Some(&false))
                    || candidate.hidden.as_known() != Some(&false)
                {
                    return Err(DriverOperationError::UpdateUnavailable);
                }
                if matched.is_some() {
                    return Err(DriverOperationError::UpdateUnavailable);
                }
                matched = Some(update);
            }
        }
        let update = matched.ok_or(DriverOperationError::UpdateUnavailable)?;
        action(&session, &update)
    }

    fn download_and_install_exact(
        intent: &DriverUpdateIntent,
    ) -> Result<DriverInstallOutcome, DriverOperationError> {
        with_exact_wua_update(&intent.candidate, false, |session, update| {
            if unsafe { update.EulaAccepted() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?
                .0
                == 0
            {
                return Err(DriverOperationError::EulaNotAccepted);
            }
            let collection = unsafe {
                CoCreateInstance::<_, IUpdateCollection>(
                    &UpdateCollection,
                    None,
                    CLSCTX_INPROC_SERVER,
                )
            }
            .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            unsafe { collection.Add(update) }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            let downloader = unsafe { session.CreateUpdateDownloader() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            unsafe { downloader.SetClientApplicationID(&BSTR::from("DCleaner")) }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            unsafe { downloader.SetUpdates(&collection) }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            let download = unsafe { downloader.Download() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            let download_result = unsafe { download.ResultCode() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?
                .0;
            let download_hresult = unsafe { download.HResult() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            let per_download = unsafe { download.GetUpdateResult(0) }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            let download_item_result_code = unsafe { per_download.ResultCode() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?
                .0;
            let download_item_hresult = unsafe { per_download.HResult() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            let downloaded_verified = unsafe { update.IsDownloaded() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?
                .0
                != 0;
            if download_result != orcSucceeded.0
                || download_hresult != 0
                || download_item_result_code != orcSucceeded.0
                || download_item_hresult != 0
                || !downloaded_verified
            {
                return Ok(DriverInstallOutcome {
                    download_result_code: download_result,
                    download_hresult,
                    download_item_result_code,
                    download_item_hresult,
                    downloaded_verified,
                    install_result_code: None,
                    install_hresult: None,
                    install_item_result_code: None,
                    install_item_hresult: None,
                    reboot: RebootRequirement::Unknown,
                });
            }

            let inventory = enumerate_devices();
            if inventory.source.quality != InventoryQuality::Complete
                || !inventory
                    .devices
                    .iter()
                    .find(|device| device.id.as_ref() == Some(&intent.device_id))
                    .is_some_and(|device| device_matches_update_intent(intent, device))
            {
                return Err(DriverOperationError::UpdateUnavailable);
            }

            let installer = unsafe { session.CreateUpdateInstaller() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            unsafe { installer.SetClientApplicationID(&BSTR::from("DCleaner")) }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            unsafe { installer.SetIsForced(VARIANT_BOOL(0)) }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            unsafe { installer.SetAllowSourcePrompts(VARIANT_BOOL(0)) }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            unsafe { installer.SetUpdates(&collection) }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            let installed = unsafe { installer.Install() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            let install_result = unsafe { installed.ResultCode() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?
                .0;
            let install_hresult = unsafe { installed.HResult() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            let per_install = unsafe { installed.GetUpdateResult(0) }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            let per_install_code = unsafe { per_install.ResultCode() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?
                .0;
            let per_install_hresult = unsafe { per_install.HResult() }
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))?;
            let reboot = match unsafe { installed.RebootRequired() } {
                Ok(value) if value.0 != 0 => RebootRequirement::Required,
                Ok(_) => RebootRequirement::NotRequired,
                Err(_) => RebootRequirement::Unknown,
            };
            Ok(DriverInstallOutcome {
                download_result_code: download_result,
                download_hresult,
                download_item_result_code,
                download_item_hresult,
                downloaded_verified,
                install_result_code: Some(install_result),
                install_hresult: Some(install_hresult),
                install_item_result_code: Some(per_install_code),
                install_item_hresult: Some(per_install_hresult),
                reboot,
            })
        })
    }

    fn exact_candidate_installed(
        identity: &CandidateIdentity,
    ) -> Result<bool, DriverOperationError> {
        with_exact_wua_update(identity, true, |_session, update| {
            unsafe { update.IsInstalled() }
                .map(|value| value.0 != 0)
                .map_err(|error| operation_error_from_hresult(error.code().0 as u32))
        })
    }

    fn operation_error_from_hresult(code: u32) -> DriverOperationError {
        if code == 0x8007_0005 {
            DriverOperationError::PrivilegeRequired
        } else {
            DriverOperationError::NativeFailure {
                native_code: Some(code),
            }
        }
    }

    struct Sha256 {
        algorithm: BCRYPT_ALG_HANDLE,
        hash: BCRYPT_HASH_HANDLE,
        object: Vec<u8>,
    }

    impl Sha256 {
        fn new() -> Result<Self, DriverOperationError> {
            let mut algorithm = BCRYPT_ALG_HANDLE::default();
            let status = unsafe {
                BCryptOpenAlgorithmProvider(
                    &mut algorithm,
                    BCRYPT_SHA256_ALGORITHM,
                    PCWSTR::null(),
                    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
                )
            };
            if status.0 < 0 {
                return Err(DriverOperationError::NativeFailure {
                    native_code: Some(status.0 as u32),
                });
            }
            let mut property = [0u8; 4];
            let mut returned = 0u32;
            let status = unsafe {
                BCryptGetProperty(
                    algorithm.into(),
                    BCRYPT_OBJECT_LENGTH,
                    Some(&mut property),
                    &mut returned,
                    0,
                )
            };
            if status.0 < 0 || returned != 4 {
                let _ = unsafe { BCryptCloseAlgorithmProvider(algorithm, 0) };
                return Err(DriverOperationError::NativeFailure {
                    native_code: Some(status.0 as u32),
                });
            }
            let object_length = u32::from_le_bytes(property) as usize;
            if object_length == 0 || object_length > 1_048_576 {
                let _ = unsafe { BCryptCloseAlgorithmProvider(algorithm, 0) };
                return Err(DriverOperationError::NativeUpdateBoundaryUnavailable);
            }
            let mut object = vec![0u8; object_length];
            let mut hash = BCRYPT_HASH_HANDLE::default();
            let status =
                unsafe { BCryptCreateHash(algorithm, &mut hash, Some(&mut object), None, 0) };
            if status.0 < 0 {
                let _ = unsafe { BCryptCloseAlgorithmProvider(algorithm, 0) };
                return Err(DriverOperationError::NativeFailure {
                    native_code: Some(status.0 as u32),
                });
            }
            Ok(Self {
                algorithm,
                hash,
                object,
            })
        }

        fn update(&mut self, bytes: &[u8]) -> Result<(), DriverOperationError> {
            let status = unsafe { BCryptHashData(self.hash, bytes, 0) };
            if status.0 < 0 {
                Err(DriverOperationError::NativeFailure {
                    native_code: Some(status.0 as u32),
                })
            } else {
                Ok(())
            }
        }

        fn finish(mut self) -> Result<String, DriverOperationError> {
            let mut output = [0u8; 32];
            let status = unsafe { BCryptFinishHash(self.hash, &mut output, 0) };
            unsafe {
                let _ = BCryptDestroyHash(self.hash);
                let _ = BCryptCloseAlgorithmProvider(self.algorithm, 0);
            }
            self.hash = BCRYPT_HASH_HANDLE::default();
            self.algorithm = BCRYPT_ALG_HANDLE::default();
            self.object.clear();
            if status.0 < 0 {
                return Err(DriverOperationError::NativeFailure {
                    native_code: Some(status.0 as u32),
                });
            }
            Ok(output.iter().map(|byte| format!("{byte:02x}")).collect())
        }
    }

    impl Drop for Sha256 {
        fn drop(&mut self) {
            unsafe {
                if !self.hash.is_invalid() {
                    let _ = BCryptDestroyHash(self.hash);
                }
                if !self.algorithm.is_invalid() {
                    let _ = BCryptCloseAlgorithmProvider(self.algorithm, 0);
                }
            }
        }
    }

    struct DeviceSet(HDEVINFO);

    impl Drop for DeviceSet {
        fn drop(&mut self) {
            let _ = unsafe { SetupDiDestroyDeviceInfoList(self.0) };
        }
    }

    struct ComApartment {
        uninitialize: bool,
    }

    impl ComApartment {
        fn initialize() -> Result<Self, NativeIssue> {
            let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            if result.is_ok() {
                Ok(Self { uninitialize: true })
            } else {
                Err(issue_from_code(
                    "Windows Update Agent",
                    "initialize COM",
                    result.0 as u32,
                ))
            }
        }
    }

    impl Drop for ComApartment {
        fn drop(&mut self) {
            if self.uninitialize {
                unsafe { CoUninitialize() };
            }
        }
    }

    fn enumerate_devices() -> DeviceInventory {
        let set = match unsafe {
            SetupDiGetClassDevsW(
                None,
                windows::core::PCWSTR::null(),
                None,
                DIGCF_ALLCLASSES | DIGCF_PRESENT,
            )
        } {
            Ok(set) => DeviceSet(set),
            Err(error) => {
                return DeviceInventory {
                    source: SourceReport::unavailable(issue_from_hresult(
                        "SetupAPI present device set",
                        "enumerate devices",
                        error.code().0 as u32,
                    )),
                    devices: Vec::new(),
                };
            }
        };
        let mut report = SourceReport::complete(0);
        let mut devices = Vec::new();
        let mut index = 0u32;
        loop {
            if devices.len() >= MAX_DEVICES {
                let mut probe = SP_DEVINFO_DATA {
                    cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                    ..Default::default()
                };
                match unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut probe) } {
                    Ok(()) => report.truncate("enumerate present devices"),
                    Err(error) if is_error(&error, ERROR_NO_MORE_ITEMS.0) => {}
                    Err(error) => report.issue(issue_from_hresult(
                        "SetupAPI present device set",
                        "finish device enumeration",
                        error.code().0 as u32,
                    )),
                }
                break;
            }
            let mut data = SP_DEVINFO_DATA {
                cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };
            match unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut data) } {
                Ok(()) => {
                    let device = read_device(set.0, &data);
                    for (operation, failure) in [
                        (
                            "read device instance ID",
                            field_failure(&device.instance_id),
                        ),
                        ("read device name", field_failure(&device.friendly_name)),
                        ("read device class", field_failure(&device.class_name)),
                        (
                            "read device hardware IDs",
                            field_failure(&device.hardware_ids),
                        ),
                        (
                            "read device compatible IDs",
                            field_failure(&device.compatible_ids),
                        ),
                        (
                            "read installed driver provider",
                            field_failure(&device.provider),
                        ),
                        (
                            "read installed driver version",
                            field_failure(&device.installed_version),
                        ),
                        (
                            "read installed driver date",
                            field_failure(&device.installed_date),
                        ),
                        (
                            "read installed INF identity",
                            field_failure(&device.inf_path),
                        ),
                        (
                            "read device problem code",
                            field_failure(&device.problem_code),
                        ),
                    ] {
                        if let Some(failure) = failure {
                            report.issue(NativeIssue::new(
                                "SetupAPI device properties",
                                operation,
                                failure,
                            ));
                        }
                    }
                    devices.push(device);
                    index = index.saturating_add(1);
                    report.item_count = devices.len();
                }
                Err(error) if is_error(&error, ERROR_NO_MORE_ITEMS.0) => break,
                Err(error) => {
                    report.issue(issue_from_hresult(
                        "SetupAPI present device set",
                        "enumerate present devices",
                        error.code().0 as u32,
                    ));
                    break;
                }
            }
        }
        DeviceInventory {
            source: report,
            devices,
        }
    }

    fn read_device(set: HDEVINFO, data: &SP_DEVINFO_DATA) -> DriverDevice {
        let instance_id = read_instance_id(set, data);
        let id = instance_id
            .as_known()
            .and_then(|value| DeviceId::from_instance_id(value));
        DriverDevice {
            id,
            instance_id,
            friendly_name: read_string_with_registry_fallback(
                set,
                data,
                &DEVPKEY_Device_FriendlyName,
                SPDRP_DEVICEDESC,
            ),
            class_name: read_string_with_registry_fallback(
                set,
                data,
                &DEVPKEY_Device_Class,
                SPDRP_CLASS,
            ),
            class_guid: format!("{:?}", data.ClassGuid),
            hardware_ids: read_string_list(set, data, &DEVPKEY_Device_HardwareIds),
            compatible_ids: read_string_list(set, data, &DEVPKEY_Device_CompatibleIds),
            provider: read_string(set, data, &DEVPKEY_Device_DriverProvider),
            installed_version: read_string(set, data, &DEVPKEY_Device_DriverVersion),
            installed_date: read_driver_date(set, data),
            inf_path: read_string(set, data, &DEVPKEY_Device_DriverInfPath),
            problem_code: read_problem_code(set, data),
            offer: DeviceOffer::Unknown {
                failure: FieldFailure::new(FieldFailureKind::NativeFailure, None),
            },
        }
    }

    fn read_instance_id(set: HDEVINFO, data: &SP_DEVINFO_DATA) -> FieldValue<String> {
        let mut required = 0u32;
        let first = unsafe { SetupDiGetDeviceInstanceIdW(set, data, None, Some(&mut required)) };
        if required == 0 || required as usize > 32_768 {
            return FieldValue::Unknown {
                failure: FieldFailure::new(
                    if required == 0 {
                        FieldFailureKind::NativeFailure
                    } else {
                        FieldFailureKind::LimitExceeded
                    },
                    first.err().map(|error| error.code().0 as u32),
                ),
            };
        }
        let mut buffer = vec![0u16; required as usize];
        match unsafe {
            SetupDiGetDeviceInstanceIdW(set, data, Some(&mut buffer), Some(&mut required))
        } {
            Ok(()) if required > 0 && required as usize <= buffer.len() => {
                buffer.truncate(required as usize);
                if buffer.last() == Some(&0) {
                    buffer.pop();
                }
                match String::from_utf16(&buffer) {
                    Ok(value) if !value.is_empty() => FieldValue::Known { value },
                    _ => FieldValue::Unknown {
                        failure: FieldFailure::new(FieldFailureKind::MalformedData, None),
                    },
                }
            }
            Ok(()) => FieldValue::Unknown {
                failure: FieldFailure::new(FieldFailureKind::MalformedData, None),
            },
            Err(error) => FieldValue::Unknown {
                failure: failure_from_hresult(error.code().0 as u32),
            },
        }
    }

    fn property_bytes(
        set: HDEVINFO,
        data: &SP_DEVINFO_DATA,
        key: &DEVPROPKEY,
    ) -> Result<(u32, Vec<u8>), FieldFailure> {
        let mut kind = windows::Win32::Devices::Properties::DEVPROPTYPE(0);
        let mut required = 0u32;
        let first = unsafe {
            SetupDiGetDevicePropertyW(set, data, key, &mut kind, None, Some(&mut required), 0)
        };
        if required == 0 {
            return Err(first
                .err()
                .map(|error| failure_from_hresult(error.code().0 as u32))
                .unwrap_or_else(|| FieldFailure::new(FieldFailureKind::MalformedData, None)));
        }
        if required as usize > MAX_PROPERTY_BYTES {
            return Err(FieldFailure::new(FieldFailureKind::LimitExceeded, None));
        }
        let mut buffer = vec![0u8; required as usize];
        match unsafe {
            SetupDiGetDevicePropertyW(
                set,
                data,
                key,
                &mut kind,
                Some(&mut buffer),
                Some(&mut required),
                0,
            )
        } {
            Ok(()) if required as usize <= buffer.len() => {
                buffer.truncate(required as usize);
                Ok((kind.0, buffer))
            }
            Ok(()) => Err(FieldFailure::new(FieldFailureKind::MalformedData, None)),
            Err(error) => Err(failure_from_hresult(error.code().0 as u32)),
        }
    }

    fn read_string(set: HDEVINFO, data: &SP_DEVINFO_DATA, key: &DEVPROPKEY) -> FieldValue<String> {
        match property_bytes(set, data, key) {
            Ok((kind, bytes))
                if kind == DEVPROP_TYPE_STRING.0 || kind == DEVPROP_TYPE_STRING_INDIRECT.0 =>
            {
                decode_wide_string(&bytes)
            }
            Ok(_) => FieldValue::Unknown {
                failure: FieldFailure::new(FieldFailureKind::UnsupportedType, None),
            },
            Err(failure) => FieldValue::Unknown { failure },
        }
    }

    fn read_string_with_registry_fallback(
        set: HDEVINFO,
        data: &SP_DEVINFO_DATA,
        key: &DEVPROPKEY,
        registry_property: SETUP_DI_REGISTRY_PROPERTY,
    ) -> FieldValue<String> {
        let primary = read_string(set, data, key);
        if primary
            .as_known()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return primary;
        }
        let fallback = read_registry_string(set, data, registry_property);
        if fallback
            .as_known()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return fallback;
        }
        match primary {
            FieldValue::Unknown { failure } => FieldValue::Unknown { failure },
            FieldValue::Known { .. } => FieldValue::Unknown {
                failure: field_failure(&fallback)
                    .unwrap_or_else(|| FieldFailure::new(FieldFailureKind::MalformedData, None)),
            },
        }
    }

    fn read_registry_string(
        set: HDEVINFO,
        data: &SP_DEVINFO_DATA,
        property: SETUP_DI_REGISTRY_PROPERTY,
    ) -> FieldValue<String> {
        let mut registry_type = 0u32;
        let mut required = 0u32;
        let first = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                set,
                data,
                property,
                Some(&mut registry_type),
                None,
                Some(&mut required),
            )
        };
        if required == 0 || required as usize > MAX_PROPERTY_BYTES {
            return FieldValue::Unknown {
                failure: if required == 0 {
                    first
                        .err()
                        .map(|error| failure_from_hresult(error.code().0 as u32))
                        .unwrap_or_else(|| FieldFailure::new(FieldFailureKind::MalformedData, None))
                } else {
                    FieldFailure::new(FieldFailureKind::LimitExceeded, None)
                },
            };
        }
        let mut buffer = vec![0u8; required as usize];
        match unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                set,
                data,
                property,
                Some(&mut registry_type),
                Some(&mut buffer),
                Some(&mut required),
            )
        } {
            Ok(()) if registry_type == 1 && required as usize <= buffer.len() => {
                buffer.truncate(required as usize);
                decode_wide_string(&buffer)
            }
            Ok(()) if registry_type != 1 => FieldValue::Unknown {
                failure: FieldFailure::new(FieldFailureKind::UnsupportedType, None),
            },
            Ok(()) => FieldValue::Unknown {
                failure: FieldFailure::new(FieldFailureKind::MalformedData, None),
            },
            Err(error) => FieldValue::Unknown {
                failure: failure_from_hresult(error.code().0 as u32),
            },
        }
    }

    fn read_string_list(
        set: HDEVINFO,
        data: &SP_DEVINFO_DATA,
        key: &DEVPROPKEY,
    ) -> FieldValue<Vec<String>> {
        match property_bytes(set, data, key) {
            Ok((kind, bytes)) if kind == DEVPROP_TYPE_STRING_LIST.0 => decode_multi_sz(&bytes),
            Ok(_) => FieldValue::Unknown {
                failure: FieldFailure::new(FieldFailureKind::UnsupportedType, None),
            },
            Err(failure) => FieldValue::Unknown { failure },
        }
    }

    fn read_driver_date(set: HDEVINFO, data: &SP_DEVINFO_DATA) -> FieldValue<String> {
        match property_bytes(set, data, &DEVPKEY_Device_DriverDate) {
            Ok((kind, bytes)) if kind == DEVPROP_TYPE_FILETIME.0 && bytes.len() == 8 => {
                let raw = u64::from_le_bytes(bytes.try_into().unwrap_or_default());
                filetime_date(raw).map_or_else(
                    || FieldValue::Unknown {
                        failure: FieldFailure::new(FieldFailureKind::MalformedData, None),
                    },
                    |value| FieldValue::Known { value },
                )
            }
            Ok(_) => FieldValue::Unknown {
                failure: FieldFailure::new(FieldFailureKind::UnsupportedType, None),
            },
            Err(failure) => FieldValue::Unknown { failure },
        }
    }

    fn read_problem_code(set: HDEVINFO, data: &SP_DEVINFO_DATA) -> FieldValue<u32> {
        match property_bytes(set, data, &DEVPKEY_Device_ProblemCode) {
            Ok((kind, bytes)) if kind == DEVPROP_TYPE_UINT32.0 && bytes.len() == 4 => {
                FieldValue::Known {
                    value: u32::from_le_bytes(bytes.try_into().unwrap_or_default()),
                }
            }
            Ok(_) => FieldValue::Unknown {
                failure: FieldFailure::new(FieldFailureKind::UnsupportedType, None),
            },
            Err(failure) => FieldValue::Unknown { failure },
        }
    }

    fn decode_wide_string(bytes: &[u8]) -> FieldValue<String> {
        if bytes.len() % 2 != 0 {
            return FieldValue::Unknown {
                failure: FieldFailure::new(FieldFailureKind::MalformedData, None),
            };
        }
        let mut wide = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        if wide.last() == Some(&0) {
            wide.pop();
        }
        String::from_utf16(&wide)
            .map(|value| FieldValue::Known { value })
            .unwrap_or_else(|_| FieldValue::Unknown {
                failure: FieldFailure::new(FieldFailureKind::MalformedData, None),
            })
    }

    fn decode_multi_sz(bytes: &[u8]) -> FieldValue<Vec<String>> {
        if bytes.len() % 2 != 0 {
            return FieldValue::Unknown {
                failure: FieldFailure::new(FieldFailureKind::MalformedData, None),
            };
        }
        let wide = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        if wide.len() < 2 || wide[wide.len() - 2..] != [0, 0] {
            return FieldValue::Unknown {
                failure: FieldFailure::new(FieldFailureKind::MalformedData, None),
            };
        }
        let mut values = Vec::new();
        let mut start = 0;
        for index in 0..wide.len() {
            if wide[index] == 0 {
                if index == start {
                    break;
                }
                if values.len() >= MAX_HARDWARE_IDS_PER_DEVICE {
                    return FieldValue::Unknown {
                        failure: FieldFailure::new(FieldFailureKind::LimitExceeded, None),
                    };
                }
                match String::from_utf16(&wide[start..index]) {
                    Ok(value) if !value.is_empty() => values.push(value),
                    _ => {
                        return FieldValue::Unknown {
                            failure: FieldFailure::new(FieldFailureKind::MalformedData, None),
                        };
                    }
                }
                start = index + 1;
            }
        }
        if values.is_empty() {
            FieldValue::Unknown {
                failure: FieldFailure::new(FieldFailureKind::NotPresent, None),
            }
        } else {
            FieldValue::Known { value: values }
        }
    }

    fn filetime_date(value: u64) -> Option<String> {
        const UNIX_EPOCH_FILETIME: i128 = 116_444_736_000_000_000;
        let ticks = i128::from(value).checked_sub(UNIX_EPOCH_FILETIME)?;
        let seconds = i64::try_from(ticks / 10_000_000).ok()?;
        chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
            .map(|date| date.format("%Y-%m-%d").to_string())
    }

    fn search_wua_catalogue() -> DriverCatalogue {
        match search_wua_inner() {
            Ok(catalogue) => catalogue,
            Err(issue) => DriverCatalogue {
                state: CatalogueState::Unavailable {
                    issue: issue.clone(),
                },
                candidates: Vec::new(),
                issues: vec![issue],
            },
        }
    }

    fn search_wua_inner() -> Result<DriverCatalogue, NativeIssue> {
        let _apartment = ComApartment::initialize()?;
        let session = unsafe {
            CoCreateInstance::<_, windows::Win32::System::UpdateAgent::IUpdateSession>(
                &UpdateSession,
                None,
                CLSCTX_INPROC_SERVER,
            )
        }
        .map_err(|error| {
            issue_from_hresult(
                "Windows Update Agent",
                "create update session",
                error.code().0 as u32,
            )
        })?;
        let searcher = unsafe { session.CreateUpdateSearcher() }.map_err(|error| {
            issue_from_hresult(
                "Windows Update Agent",
                "create driver search",
                error.code().0 as u32,
            )
        })?;
        let source = WuaSource {
            server_selection: WuaServerSelection::from_raw(
                unsafe { searcher.ServerSelection() }
                    .map_err(|error| {
                        issue_from_hresult(
                            "Windows Update Agent",
                            "read search source",
                            error.code().0 as u32,
                        )
                    })?
                    .0,
            ),
            service_id: unsafe { searcher.ServiceID() }
                .map_err(|error| {
                    issue_from_hresult(
                        "Windows Update Agent",
                        "read update service identity",
                        error.code().0 as u32,
                    )
                })?
                .to_string(),
            online_search: true,
        };
        unsafe { searcher.SetOnline(windows::Win32::Foundation::VARIANT_BOOL(-1)) }.map_err(
            |error| {
                issue_from_hresult(
                    "Windows Update Agent",
                    "request online search",
                    error.code().0 as u32,
                )
            },
        )?;
        let criteria = BSTR::from("Type='Driver' and IsInstalled=0 and IsHidden=0");
        let result = unsafe { searcher.Search(&criteria) }.map_err(|error| {
            issue_from_hresult(
                "Windows Update Agent",
                "search driver catalogue",
                error.code().0 as u32,
            )
        })?;
        let result_code = unsafe { result.ResultCode() }.map_err(|error| {
            issue_from_hresult(
                "Windows Update Agent",
                "read search result status",
                error.code().0 as u32,
            )
        })?;
        if result_code != orcSucceeded && result_code != orcSucceededWithErrors {
            return Err(NativeIssue::new(
                "Windows Update Agent",
                "search driver catalogue",
                FieldFailure::new(FieldFailureKind::NativeFailure, Some(result_code.0 as u32)),
            ));
        }
        let partial = result_code == orcSucceededWithErrors;
        let updates = unsafe { result.Updates() }.map_err(|error| {
            issue_from_hresult(
                "Windows Update Agent",
                "read driver search results",
                error.code().0 as u32,
            )
        })?;
        let count = unsafe { updates.Count() }.map_err(|error| {
            issue_from_hresult(
                "Windows Update Agent",
                "count driver search results",
                error.code().0 as u32,
            )
        })?;
        if count < 0 {
            return Err(NativeIssue::new(
                "Windows Update Agent",
                "count driver search results",
                FieldFailure::new(FieldFailureKind::MalformedData, None),
            ));
        }
        let mut candidates = Vec::new();
        let mut issues = Vec::new();
        let bounded_count = usize::try_from(count).unwrap_or(0).min(MAX_CANDIDATES);
        for index in 0..bounded_count {
            match read_candidate(unsafe { updates.get_Item(index as i32) }, &source) {
                Ok(candidate) => {
                    for (operation, failure) in [
                        ("read driver update title", field_failure(&candidate.title)),
                        (
                            "read candidate manufacturer",
                            field_failure(&candidate.manufacturer),
                        ),
                        ("read candidate model", field_failure(&candidate.model)),
                        ("read candidate class", field_failure(&candidate.class)),
                        (
                            "read candidate provider",
                            field_failure(&candidate.provider),
                        ),
                        (
                            "read candidate date",
                            field_failure(&candidate.release_date),
                        ),
                        (
                            "read candidate installed state",
                            field_failure(&candidate.installed),
                        ),
                        (
                            "read candidate EULA state",
                            field_failure(&candidate.eula_accepted),
                        ),
                        (
                            "read candidate hidden state",
                            field_failure(&candidate.hidden),
                        ),
                    ] {
                        if let Some(failure) = failure {
                            if issues.len() < MAX_ISSUES {
                                issues.push(NativeIssue::new(
                                    "Windows Update Agent",
                                    operation,
                                    failure,
                                ));
                            }
                        }
                    }
                    candidates.push(candidate);
                }
                Err(issue) if issues.len() < MAX_ISSUES => issues.push(issue),
                Err(_) => {}
            }
        }
        let quality = if usize::try_from(count).unwrap_or(0) > MAX_CANDIDATES {
            InventoryQuality::Truncated
        } else if partial || !issues.is_empty() {
            InventoryQuality::Partial
        } else {
            InventoryQuality::Complete
        };
        if usize::try_from(count).unwrap_or(0) > MAX_CANDIDATES && issues.len() < MAX_ISSUES {
            issues.push(NativeIssue::new(
                "Windows Update Agent",
                "read driver search results",
                FieldFailure::new(FieldFailureKind::LimitExceeded, None),
            ));
        }
        let state = match quality {
            InventoryQuality::Complete => CatalogueState::Read {
                source: source.clone(),
            },
            InventoryQuality::Partial => CatalogueState::Partial {
                source: source.clone(),
            },
            InventoryQuality::Truncated => CatalogueState::Truncated {
                source: source.clone(),
            },
            InventoryQuality::Unavailable => CatalogueState::Unavailable {
                issue: NativeIssue::new(
                    "Windows Update Agent",
                    "search driver catalogue",
                    FieldFailure::new(FieldFailureKind::NativeFailure, None),
                ),
            },
        };
        Ok(DriverCatalogue {
            state,
            candidates,
            issues,
        })
    }

    fn read_candidate(
        update: windows::core::Result<IUpdate>,
        source: &WuaSource,
    ) -> Result<DriverCandidate, NativeIssue> {
        let update = update.map_err(|error| {
            issue_from_hresult(
                "Windows Update Agent",
                "read a driver candidate",
                error.code().0 as u32,
            )
        })?;
        let driver = update.cast::<IWindowsDriverUpdate>().map_err(|error| {
            issue_from_hresult(
                "Windows Update Agent",
                "read driver-specific metadata",
                error.code().0 as u32,
            )
        })?;
        let identity = unsafe { update.Identity() }.map_err(|error| {
            issue_from_hresult(
                "Windows Update Agent",
                "read driver candidate identity",
                error.code().0 as u32,
            )
        })?;
        let update_id = unsafe { identity.UpdateID() }
            .map_err(|error| {
                issue_from_hresult(
                    "Windows Update Agent",
                    "read driver update ID",
                    error.code().0 as u32,
                )
            })?
            .to_string();
        let revision = unsafe { identity.RevisionNumber() }.map_err(|error| {
            issue_from_hresult(
                "Windows Update Agent",
                "read driver update revision",
                error.code().0 as u32,
            )
        })?;
        if update_id.is_empty() || uuid::Uuid::parse_str(&update_id).is_err() || revision <= 0 {
            return Err(NativeIssue::new(
                "Windows Update Agent",
                "validate driver candidate identity",
                FieldFailure::new(FieldFailureKind::MalformedData, None),
            ));
        }
        let hardware_id = unsafe { driver.DriverHardwareID() }
            .map_err(|error| {
                issue_from_hresult(
                    "Windows Update Agent",
                    "read driver hardware ID",
                    error.code().0 as u32,
                )
            })?
            .to_string();
        if hardware_id.is_empty() || hardware_id.len() > 16_384 || hardware_id.contains('\0') {
            return Err(NativeIssue::new(
                "Windows Update Agent",
                "validate driver hardware ID",
                FieldFailure::new(FieldFailureKind::MalformedData, None),
            ));
        }
        let candidate_identity = CandidateIdentity {
            update_id,
            revision: revision as u32,
            source: source.clone(),
            driver_hardware_id: hardware_id,
        };
        let id = candidate_identity.id();
        let installed = unsafe { update.IsInstalled() }
            .map(|value| FieldValue::Known {
                value: value.0 != 0,
            })
            .unwrap_or_else(|error| FieldValue::Unknown {
                failure: failure_from_hresult(error.code().0 as u32),
            });
        let eula_accepted = unsafe { update.EulaAccepted() }
            .map(|value| FieldValue::Known {
                value: value.0 != 0,
            })
            .unwrap_or_else(|error| FieldValue::Unknown {
                failure: failure_from_hresult(error.code().0 as u32),
            });
        let hidden = unsafe { update.IsHidden() }
            .map(|value| FieldValue::Known {
                value: value.0 != 0,
            })
            .unwrap_or_else(|error| FieldValue::Unknown {
                failure: failure_from_hresult(error.code().0 as u32),
            });
        let title = unsafe { update.Title() }
            .map(|value| FieldValue::Known {
                value: value.to_string(),
            })
            .unwrap_or_else(|error| FieldValue::Unknown {
                failure: failure_from_hresult(error.code().0 as u32),
            });
        let manufacturer = unsafe { driver.DriverManufacturer() }
            .map(|value| FieldValue::Known {
                value: value.to_string(),
            })
            .unwrap_or_else(|error| FieldValue::Unknown {
                failure: failure_from_hresult(error.code().0 as u32),
            });
        let model = unsafe { driver.DriverModel() }
            .map(|value| FieldValue::Known {
                value: value.to_string(),
            })
            .unwrap_or_else(|error| FieldValue::Unknown {
                failure: failure_from_hresult(error.code().0 as u32),
            });
        let class = unsafe { driver.DriverClass() }
            .map(|value| FieldValue::Known {
                value: value.to_string(),
            })
            .unwrap_or_else(|error| FieldValue::Unknown {
                failure: failure_from_hresult(error.code().0 as u32),
            });
        let provider = unsafe { driver.DriverProvider() }
            .map(|value| FieldValue::Known {
                value: value.to_string(),
            })
            .unwrap_or_else(|error| FieldValue::Unknown {
                failure: failure_from_hresult(error.code().0 as u32),
            });
        let release_date = match unsafe { driver.DriverVerDate() } {
            Ok(value) => ole_date(value)
                .map(|value| FieldValue::Known { value })
                .unwrap_or_else(|| FieldValue::Unknown {
                    failure: FieldFailure::new(FieldFailureKind::MalformedData, None),
                }),
            Err(error) => FieldValue::Unknown {
                failure: failure_from_hresult(error.code().0 as u32),
            },
        };
        Ok(DriverCandidate {
            id,
            identity: candidate_identity,
            title,
            manufacturer,
            model,
            class,
            provider,
            release_date,
            candidate_version: FieldValue::Unknown {
                failure: FieldFailure::new(FieldFailureKind::NotProvidedByApi, None),
            },
            applicability: CandidateMatch::NoMatchingPresentDevice,
            eula_accepted,
            installed,
            hidden,
        })
    }

    fn ole_date(value: f64) -> Option<String> {
        if !value.is_finite() || value < -657_434.0 || value > 2_958_465.0 {
            return None;
        }
        let days = value.trunc() as i64;
        chrono::NaiveDate::from_ymd_opt(1899, 12, 30)?
            .checked_add_signed(chrono::Duration::days(days))
            .map(|date| date.format("%Y-%m-%d").to_string())
    }

    fn is_error(error: &windows::core::Error, win32_code: u32) -> bool {
        error.code().0 as u32 == hresult_from_win32(win32_code)
    }

    fn hresult_from_win32(code: u32) -> u32 {
        if code == 0 {
            0
        } else {
            (code & 0x0000_ffff) | 0x8007_0000
        }
    }

    fn failure_from_hresult(code: u32) -> FieldFailure {
        let win32 = if code & 0xffff_0000 == 0x8007_0000 {
            Some(code & 0xffff)
        } else {
            None
        };
        let kind = match win32 {
            Some(5) => FieldFailureKind::AccessDenied,
            Some(2 | 1168) => FieldFailureKind::NotPresent,
            _ => FieldFailureKind::NativeFailure,
        };
        FieldFailure::new(kind, Some(code))
    }

    fn issue_from_hresult(source: &'static str, operation: &'static str, code: u32) -> NativeIssue {
        NativeIssue::new(source, operation, failure_from_hresult(code))
    }

    fn issue_from_code(source: &'static str, operation: &'static str, code: u32) -> NativeIssue {
        issue_from_hresult(source, operation, code)
    }
}

#[cfg(windows)]
pub use native::WindowsDriverPlatform;

#[cfg(not(windows))]
pub struct WindowsDriverPlatform;

#[cfg(not(windows))]
impl DriverPlatform for WindowsDriverPlatform {
    fn inventory_devices(&mut self) -> DeviceInventory {
        DeviceInventory {
            source: SourceReport::unavailable(NativeIssue::new(
                "Windows SetupAPI",
                "enumerate devices",
                FieldFailure::new(FieldFailureKind::NativeFailure, None),
            )),
            devices: Vec::new(),
        }
    }

    fn search_catalogue(&mut self) -> DriverCatalogue {
        let issue = NativeIssue::new(
            "Windows Update Agent",
            "search driver catalogue",
            FieldFailure::new(FieldFailureKind::NativeFailure, None),
        );
        DriverCatalogue {
            state: CatalogueState::Unavailable {
                issue: issue.clone(),
            },
            candidates: Vec::new(),
            issues: vec![issue],
        }
    }
}

// Keep the shared UI and reviewed workflow callable on other platforms while
// rejecting Windows-only operations before any native effect or durable intent.
#[cfg(not(windows))]
impl DriverActionBoundary for WindowsDriverPlatform {
    fn current_device(&mut self, _: &DeviceId) -> Result<DriverDevice, DriverOperationError> {
        Err(DriverOperationError::NativeUpdateBoundaryUnavailable)
    }

    fn exact_candidate(
        &mut self,
        _: &CandidateIdentity,
    ) -> Result<DriverCandidate, DriverOperationError> {
        Err(DriverOperationError::NativeUpdateBoundaryUnavailable)
    }

    fn create_restore_point(&mut self, _: &str) -> Result<i64, DriverOperationError> {
        Err(DriverOperationError::NativeUpdateBoundaryUnavailable)
    }

    fn export_driver_package(
        &mut self,
        _: &Path,
        _: &DriverUpdateIntent,
        _: uuid::Uuid,
    ) -> Result<DriverBackupReceipt, DriverOperationError> {
        Err(DriverOperationError::NativeUpdateBoundaryUnavailable)
    }

    fn download_and_install(
        &mut self,
        _: &DriverUpdateIntent,
    ) -> Result<DriverInstallOutcome, DriverOperationError> {
        Err(DriverOperationError::NativeUpdateBoundaryUnavailable)
    }

    fn candidate_is_installed(
        &mut self,
        _: &CandidateIdentity,
    ) -> Result<bool, DriverOperationError> {
        Err(DriverOperationError::NativeUpdateBoundaryUnavailable)
    }

    fn restore_from_package(
        &mut self,
        _: &Path,
        _: &DriverRestoreIntent,
    ) -> Result<DriverRestoreOutcome, DriverOperationError> {
        Err(DriverOperationError::NativeUpdateBoundaryUnavailable)
    }
}

/// The native update boundary is compiled only for Windows. Individual
/// operations still fail closed when the system refuses package export,
/// restore-point creation, WUA, SetupAPI, or required privilege.
#[cfg(windows)]
pub fn supported_update_actions() -> Result<(), DriverOperationError> {
    Ok(())
}

#[cfg(not(windows))]
pub fn supported_update_actions() -> Result<(), DriverOperationError> {
    Err(DriverOperationError::NativeUpdateBoundaryUnavailable)
}

/// Ensures that callers which persist future driver operations use the shared
/// application data directory and the established durable journal contract.
pub fn operation_history(root: &Path) -> Result<Vec<crate::effects::EffectHistory>, String> {
    crate::effects::history(root, "drivers")
}
