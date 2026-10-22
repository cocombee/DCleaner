//! Versioned, validated storage for the settings exposed by CCleaner's Custom Clean UI.
//!
//! The shipped UI stores inclusion rules as either a file path or a folder object
//! (`folder`, optional string-list `filter`, `recursive`, and `delete-self`), with
//! an optional `age-threshold-hours`. Exclusions carry one of `file`, `path`,
//! `registry_key`, `registry_key_value`, or `cookie` plus a path/value string.
//! It also stores temporary/recycle-bin 24-hour policies, file deletion mode,
//! overwrite mode, free-space/alternate-stream/per-drive MFT choices, optional
//! `rule-selections` as a string-to-boolean record, skipped-close rule IDs, the
//! registry-attention preference, and shutdown-after-cleaning preference.
//!
//! These are preferences only. Persisting `secure`, overwrite passes, wiping,
//! process handling, or shutdown does not authorize or execute those effects.
//! Every effect represented here remains unsupported until a separate reviewed
//! engine implements it and obtains the required user review/confirmation.

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};
use uuid::Uuid;

pub const CLEAN_SETTINGS_SCHEMA_VERSION: u32 = 1;
pub const CLEAN_SETTINGS_FILE: &str = "custom-clean-settings.json";

const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;
const MAX_RULES: usize = 10_000;
const MAX_RULE_SELECTIONS: usize = 10_000;
const MAX_RULE_ID_BYTES: usize = 1024;
const MAX_PATH_BYTES: usize = 32 * 1024;
const MAX_FILTERS_PER_FOLDER: usize = 4096;
const MAX_SKIPPED_CLOSE_RULES: usize = 10_000;
const MAX_DRIVE_PREFERENCES: usize = 64;

/// All values in this module are saved preferences; none currently authorizes a
/// filesystem, process, or shutdown operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustomCleanEffect {
    ApplyInclusions,
    ApplyExclusions,
    EnforceTemporaryAge,
    EnforceRecycleBinAge,
    SecureFileDeletion,
    OverwritePasses,
    WipeFreeSpace,
    WipeAlternateDataStreams,
    WipeDriveMftFreeSpace,
    ApplyRuleSelections,
    SkipCloseProcesses,
    SuppressRegistryAttention,
    ShutdownAfterCleaning,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectSupport {
    StoredOnly,
}

/// Reports execution support separately from a stored preference. This module
/// intentionally reports no executable effect as supported.
pub const fn effect_support(_effect: CustomCleanEffect) -> EffectSupport {
    EffectSupport::StoredOnly
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCleanSettings {
    pub schema: u32,
    #[serde(default)]
    pub inclusions: Vec<InclusionRule>,
    #[serde(default)]
    pub exclusions: Vec<ExclusionRule>,
    #[serde(default, rename = "file-deletion")]
    pub file_deletion: FileDeletionPolicy,
    #[serde(default, rename = "advanced-filter-options")]
    pub advanced_filter_options: AdvancedFilterOptions,
    /// `None` preserves the shipped contract's absent/undefined default.
    #[serde(
        default,
        rename = "rule-selections",
        skip_serializing_if = "Option::is_none"
    )]
    pub rule_selections: Option<BTreeMap<String, bool>>,
    #[serde(default, rename = "skipped-close-programs")]
    pub skipped_close_programs: Vec<String>,
    #[serde(default, rename = "skip-show-registry-attention")]
    pub skip_show_registry_attention: bool,
    #[serde(default, rename = "shut-down-after-cleaning")]
    pub shutdown_after_cleaning: bool,
}

impl Default for CustomCleanSettings {
    fn default() -> Self {
        Self {
            schema: CLEAN_SETTINGS_SCHEMA_VERSION,
            inclusions: Vec::new(),
            exclusions: Vec::new(),
            file_deletion: FileDeletionPolicy::default(),
            advanced_filter_options: AdvancedFilterOptions::default(),
            rule_selections: None,
            skipped_close_programs: Vec::new(),
            skip_show_registry_attention: false,
            shutdown_after_cleaning: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionRule {
    pub location: InclusionLocation,
    #[serde(
        default,
        rename = "age-threshold-hours",
        skip_serializing_if = "Option::is_none"
    )]
    pub age_threshold_hours: Option<f64>,
}

/// Shipped serialization is an untagged string for files, or a folder object.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum InclusionLocation {
    File(String),
    Folder(FolderInclusion),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FolderInclusion {
    pub folder: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Vec<String>>,
    #[serde(rename = "delete-self")]
    pub delete_self: bool,
    pub recursive: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionType {
    File,
    Path,
    RegistryKey,
    RegistryKeyValue,
    Cookie,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExclusionRule {
    #[serde(rename = "exclusion-type")]
    pub exclusion_type: ExclusionType,
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileDeletionPolicy {
    #[serde(rename = "temp-folders-only-older-than-24h")]
    pub temp_folders_only_older_than_24h: bool,
    #[serde(rename = "recycle-bin-only-older-than-24h")]
    pub recycle_bin_only_older_than_24h: bool,
}

impl Default for FileDeletionPolicy {
    fn default() -> Self {
        Self {
            temp_folders_only_older_than_24h: true,
            recycle_bin_only_older_than_24h: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvancedFilterOptions {
    #[serde(rename = "file-deletion")]
    pub file_deletion: FileDeletionMode,
    #[serde(rename = "overwrite-type")]
    pub overwrite_type: OverwriteType,
    #[serde(rename = "wipe-free-space")]
    pub wipe_free_space: bool,
    #[serde(rename = "wipe-alternate-data-streams")]
    pub wipe_alternate_data_streams: bool,
    #[serde(rename = "wipe-free-space-drives")]
    pub wipe_free_space_drives: Vec<WipeDrivePreference>,
}

impl Default for AdvancedFilterOptions {
    fn default() -> Self {
        Self {
            file_deletion: FileDeletionMode::Normal,
            overwrite_type: OverwriteType::Disabled,
            wipe_free_space: false,
            wipe_alternate_data_streams: false,
            wipe_free_space_drives: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDeletionMode {
    Normal,
    Secure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverwriteType {
    Disabled,
    SinglePass,
    ThreePass,
    SevenPass,
    ThirtyFivePass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WipeDrivePreference {
    pub drive: String,
    pub wipe_mft_free_space: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanSettingsError(pub String);

impl fmt::Display for CleanSettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CleanSettingsError {}

impl CustomCleanSettings {
    pub fn validate(&self) -> Result<(), CleanSettingsError> {
        if self.schema != CLEAN_SETTINGS_SCHEMA_VERSION {
            return Err(CleanSettingsError(
                "unsupported Custom Clean settings schema; original settings were preserved."
                    .into(),
            ));
        }
        if self.inclusions.len() > MAX_RULES || self.exclusions.len() > MAX_RULES {
            return Err(CleanSettingsError(
                "the Custom Clean rule limit was exceeded.".into(),
            ));
        }

        let mut seen_inclusions = BTreeSet::new();
        for rule in &self.inclusions {
            validate_inclusion(rule)?;
            let identity = serde_json::to_vec(rule).map_err(|error| {
                CleanSettingsError(format!(
                    "Custom Clean inclusion could not be validated: {error}"
                ))
            })?;
            if !seen_inclusions.insert(identity) {
                return Err(CleanSettingsError(
                    "duplicate Custom Clean inclusion rule.".into(),
                ));
            }
        }

        let mut seen_exclusions = BTreeSet::new();
        for rule in &self.exclusions {
            validate_text(&rule.path, "exclusion path", MAX_PATH_BYTES)?;
            let key = (rule.exclusion_type, rule.path.to_ascii_lowercase());
            if !seen_exclusions.insert(key) {
                return Err(CleanSettingsError(
                    "duplicate Custom Clean exclusion rule.".into(),
                ));
            }
        }

        if let Some(selections) = &self.rule_selections {
            if selections.len() > MAX_RULE_SELECTIONS {
                return Err(CleanSettingsError(
                    "the Custom Clean rule-selection limit was exceeded.".into(),
                ));
            }
            for rule_id in selections.keys() {
                validate_rule_id(rule_id, "selected rule identity")?;
            }
        }

        if self.skipped_close_programs.len() > MAX_SKIPPED_CLOSE_RULES {
            return Err(CleanSettingsError(
                "the skipped-close-program rule limit was exceeded.".into(),
            ));
        }
        let mut seen_skipped = BTreeSet::new();
        for rule_id in &self.skipped_close_programs {
            validate_rule_id(rule_id, "skipped-close-program identity")?;
            if !seen_skipped.insert(rule_id) {
                return Err(CleanSettingsError(
                    "duplicate skipped-close-program identity.".into(),
                ));
            }
        }

        let drives = &self.advanced_filter_options.wipe_free_space_drives;
        if drives.len() > MAX_DRIVE_PREFERENCES {
            return Err(CleanSettingsError(
                "the free-space drive preference limit was exceeded.".into(),
            ));
        }
        let mut seen_drives = BTreeSet::new();
        for drive in drives {
            let mut chars = drive.drive.chars();
            let Some(letter) = chars.next() else {
                return Err(CleanSettingsError(
                    "a free-space wipe preference has an invalid drive identity.".into(),
                ));
            };
            if !letter.is_ascii_alphabetic() || chars.next().is_some() {
                return Err(CleanSettingsError(
                    "a free-space wipe preference must use one drive letter.".into(),
                ));
            }
            if !seen_drives.insert(letter.to_ascii_uppercase()) {
                return Err(CleanSettingsError(
                    "duplicate free-space drive preference.".into(),
                ));
            }
        }
        Ok(())
    }

    /// Return an explicit saved value; `None` means shipped rule defaults apply.
    pub fn rule_selection(&self, rule_id: &str) -> Option<bool> {
        self.rule_selections
            .as_ref()
            .and_then(|selections| selections.get(rule_id).copied())
    }

    /// Set or remove one explicit rule override without collapsing the absent-map default.
    pub fn set_rule_selection(
        &mut self,
        rule_id: &str,
        selected: Option<bool>,
    ) -> Result<(), CleanSettingsError> {
        validate_rule_id(rule_id, "selected rule identity")?;
        match selected {
            Some(selected) => {
                let selections = self.rule_selections.get_or_insert_with(BTreeMap::new);
                if !selections.contains_key(rule_id) && selections.len() >= MAX_RULE_SELECTIONS {
                    return Err(CleanSettingsError(
                        "the Custom Clean rule-selection limit was reached.".into(),
                    ));
                }
                selections.insert(rule_id.to_owned(), selected);
            }
            None => {
                if let Some(selections) = self.rule_selections.as_mut() {
                    selections.remove(rule_id);
                    if selections.is_empty() {
                        self.rule_selections = None;
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn load_settings(root: &Path) -> Result<CustomCleanSettings, CleanSettingsError> {
    validate_root(root)?;
    let path = root.join(CLEAN_SETTINGS_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CustomCleanSettings::default());
        }
        Err(error) => {
            return Err(CleanSettingsError(format!(
                "Custom Clean settings could not be inspected: {error}"
            )));
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_SETTINGS_BYTES
    {
        return Err(CleanSettingsError(
            "Custom Clean settings are linked, not a regular file, or exceed the safe size limit; original bytes were preserved.".into(),
        ));
    }
    let bytes = fs::read(&path).map_err(|error| {
        CleanSettingsError(format!("Custom Clean settings could not be read: {error}"))
    })?;
    let settings: CustomCleanSettings = serde_json::from_slice(&bytes).map_err(|error| {
        CleanSettingsError(format!(
            "Custom Clean settings could not be decoded; original bytes were preserved: {error}"
        ))
    })?;
    settings.validate()?;
    Ok(settings)
}

pub fn save_settings(
    root: &Path,
    settings: &CustomCleanSettings,
) -> Result<(), CleanSettingsError> {
    validate_root(root)?;
    settings.validate()?;
    fs::create_dir_all(root).map_err(|error| {
        CleanSettingsError(format!(
            "Custom Clean settings directory could not be created: {error}"
        ))
    })?;
    let destination = root.join(CLEAN_SETTINGS_FILE);
    let existing_settings = match fs::symlink_metadata(&destination) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > MAX_SETTINGS_BYTES =>
        {
            return Err(CleanSettingsError(
                "the existing Custom Clean settings path is linked, invalid, or exceeds the safe size limit; it was preserved.".into(),
            ));
        }
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(CleanSettingsError(format!(
                "the existing Custom Clean settings path could not be inspected: {error}"
            )));
        }
    };
    if existing_settings {
        // Never replace unreadable, corrupt, or newer-version settings with a
        // valid defaults-based save. An explicit recovery/reset flow can be
        // added separately if the product later needs one.
        load_settings(root)?;
    }
    let bytes = serde_json::to_vec_pretty(settings).map_err(|error| {
        CleanSettingsError(format!(
            "Custom Clean settings could not be encoded: {error}"
        ))
    })?;
    if bytes.len() as u64 > MAX_SETTINGS_BYTES {
        return Err(CleanSettingsError(
            "Custom Clean settings exceed the safe size limit; previous settings remain.".into(),
        ));
    }

    let temporary = root.join(format!("custom-clean-settings.{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("temporary settings file could not be created: {error}"))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("temporary settings file could not be flushed: {error}"))?;
        drop(file);
        fs::rename(&temporary, &destination)
            .map_err(|error| format!("settings could not be atomically replaced: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(CleanSettingsError)
}

fn validate_root(root: &Path) -> Result<(), CleanSettingsError> {
    if root.is_absolute() {
        Ok(())
    } else {
        Err(CleanSettingsError(
            "the application data directory is not absolute.".into(),
        ))
    }
}

fn validate_inclusion(rule: &InclusionRule) -> Result<(), CleanSettingsError> {
    if rule
        .age_threshold_hours
        .is_some_and(|hours| !hours.is_finite())
    {
        return Err(CleanSettingsError(
            "an inclusion age threshold must be a finite number of hours.".into(),
        ));
    }
    match &rule.location {
        InclusionLocation::File(path) => validate_text(path, "inclusion file path", MAX_PATH_BYTES),
        InclusionLocation::Folder(folder) => {
            validate_text(&folder.folder, "inclusion folder path", MAX_PATH_BYTES)?;
            if let Some(filters) = &folder.filter {
                if filters.len() > MAX_FILTERS_PER_FOLDER {
                    return Err(CleanSettingsError(
                        "a folder inclusion contains too many filters.".into(),
                    ));
                }
                let mut seen = BTreeSet::new();
                for filter in filters {
                    validate_text(filter, "folder filter", MAX_RULE_ID_BYTES)?;
                    if !seen.insert(filter) {
                        return Err(CleanSettingsError(
                            "a folder inclusion contains a duplicate filter.".into(),
                        ));
                    }
                }
            }
            Ok(())
        }
    }
}

fn validate_text(value: &str, label: &str, max_bytes: usize) -> Result<(), CleanSettingsError> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(CleanSettingsError(format!(
            "the {label} is empty, too long, or contains control characters."
        )));
    }
    Ok(())
}

fn validate_rule_id(value: &str, label: &str) -> Result<(), CleanSettingsError> {
    validate_text(value, label, MAX_RULE_ID_BYTES)
}

/// The reference's shipped, editable cookie keep entries. They seed the
/// Trusted websites list (the policy the browser scanners apply) on first run;
/// as generic exclusions no scanner ever read them. Dynamic hidden/vendor
/// exclusions are intentionally not included.
pub fn default_cookie_domains() -> Vec<String> {
    let mut domains = [
        "services.adobe.com",
        "aol.com",
        "login.comcast.net",
        "webmail.earthlink.net",
        "facebook.com",
        "fastmail.com",
        "google.com",
        "mail.lycos.com",
        "icloud.com",
        "login.live.com",
        "auth.me.com",
        "mail.netscape.com",
        "ovi.com",
        "twitter.com",
        "yahoo.com",
    ];
    domains.sort_unstable();
    domains.into_iter().map(str::to_owned).collect()
}
