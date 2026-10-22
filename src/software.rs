//! A conservative WinGet-backed software updater.
//!
//! WinGet's installed-package command has no structured output mode in the
//! supported CLI. This module parses its fixed-width table, binds each package
//! to one exact uninstall registration, and revalidates both sources before
//! handing an update to WinGet. Inventory and parsing never launch installers.

use crate::{
    programs,
    programs::{InstalledProgram, ProgramIdentity, RegistryPort, RegistrySource},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const WINGET_SOURCE: &str = "winget";
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ROWS: usize = 1_000;
const MAX_SETTINGS_BYTES: u64 = 512 * 1024;
const MAX_SETTINGS_RULES: usize = 2_000;
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SoftwareError {
    UnsupportedPlatform,
    WinGetUnavailable(String),
    ProcessTimeout,
    OutputLimit,
    ProcessFailed { code: Option<i32>, detail: String },
    InvalidTable(String),
    Registry(String),
    Settings(String),
    InvalidIdentity(String),
    UpdateBlocked(String),
    Process(String),
}

impl fmt::Display for SoftwareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => f.write_str(
                "Software inventory and updates are unavailable on this platform until a native adapter is implemented.",
            ),
            Self::WinGetUnavailable(message) => write!(f, "WinGet is unavailable: {message}"),
            Self::ProcessTimeout => f.write_str("WinGet did not finish within 30 seconds."),
            Self::OutputLimit => f.write_str("WinGet output exceeded the safe read limit."),
            Self::ProcessFailed { code, detail } => write!(
                f,
                "WinGet inventory failed{}{}",
                code.map(|value| format!(" with exit code {value}")).unwrap_or_default(),
                if detail.trim().is_empty() {
                    ".".to_owned()
                } else {
                    format!(": {}", detail.trim())
                }
            ),
            Self::InvalidTable(message) => write!(f, "WinGet output could not be read safely: {message}"),
            Self::Registry(message) => write!(f, "The installed-program registration could not be read: {message}"),
            Self::Settings(message) => write!(f, "Software updater settings are unavailable: {message}"),
            Self::InvalidIdentity(message) => write!(f, "The package identity is invalid: {message}"),
            Self::UpdateBlocked(message) => write!(f, "The reviewed update is no longer safe to run: {message}"),
            Self::Process(message) => write!(f, "WinGet could not run the reviewed update: {message}"),
        }
    }
}

impl std::error::Error for SoftwareError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WingetRow {
    pub name: String,
    pub package_id: String,
    pub installed_version: Option<String>,
    pub available_version: Option<String>,
    pub source_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct SoftwareIdentity {
    /// Exact uninstall-registration identity and the registry view used to read it.
    pub registration: ProgramIdentity,
    pub registry_source: RegistrySource,
    /// Canonical lower-case WinGet identity. The launch request retains the exact
    /// ID as returned by WinGet for its argument vector.
    pub package_id: String,
    pub source_id: String,
}

impl SoftwareIdentity {
    pub fn stable_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            match self.registration.hive {
                programs::RegistryHive::CurrentUser => "hkcu",
                programs::RegistryHive::LocalMachine => "hklm",
            },
            self.registry_source.view as u8,
            self.registration.key_name.len(),
            self.registration.key_name,
            self.source_id,
            self.package_id.len(),
            self.package_id
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwarePreferenceState {
    SkipVersion,
    Ignored,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwarePreference {
    pub identity: SoftwareIdentity,
    pub state: SoftwarePreferenceState,
    /// Present only for SkipVersion; a newer offered version remains actionable.
    pub skipped_version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareSettings {
    pub schema: u32,
    pub preferences: Vec<SoftwarePreference>,
}

impl Default for SoftwareSettings {
    fn default() -> Self {
        Self {
            schema: 1,
            preferences: Vec::new(),
        }
    }
}

impl SoftwareSettings {
    pub fn preference_for(&self, identity: &SoftwareIdentity) -> Option<&SoftwarePreference> {
        self.preferences
            .iter()
            .find(|preference| preference.identity == *identity)
    }

    pub fn set(&mut self, preference: SoftwarePreference) -> Result<(), SoftwareError> {
        validate_identity(&preference.identity)?;
        match preference.state {
            SoftwarePreferenceState::SkipVersion
                if preference
                    .skipped_version
                    .as_deref()
                    .is_none_or(|version| !valid_version(version)) =>
            {
                return Err(SoftwareError::Settings(
                    "A skipped update must name its exact offered version.".into(),
                ));
            }
            SoftwarePreferenceState::Ignored if preference.skipped_version.is_some() => {
                return Err(SoftwareError::Settings(
                    "An ignored package cannot also store a skipped version.".into(),
                ));
            }
            _ => {}
        }
        if let Some(existing) = self
            .preferences
            .iter_mut()
            .find(|existing| existing.identity == preference.identity)
        {
            *existing = preference;
        } else {
            if self.preferences.len() >= MAX_SETTINGS_RULES {
                return Err(SoftwareError::Settings(
                    "The updater settings limit has been reached.".into(),
                ));
            }
            self.preferences.push(preference);
        }
        self.preferences
            .sort_by_key(|rule| rule.identity.stable_key());
        Ok(())
    }

    pub fn restore(&mut self, identity: &SoftwareIdentity) -> bool {
        let before = self.preferences.len();
        self.preferences
            .retain(|preference| preference.identity != *identity);
        self.preferences.len() != before
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareStatus {
    Current,
    UpdateAvailable,
    SkippedVersion,
    Ignored,
    Unmatched,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SoftwareItem {
    pub row: WingetRow,
    pub registration: Option<InstalledProgram>,
    pub identity: Option<SoftwareIdentity>,
    pub status: SoftwareStatus,
    pub association_note: Option<String>,
    pub preference_note: Option<String>,
}

impl SoftwareItem {
    pub fn can_update(&self) -> bool {
        self.status == SoftwareStatus::UpdateAvailable
            && self.identity.is_some()
            && self.row.source_id.eq_ignore_ascii_case(WINGET_SOURCE)
            && self.identity.as_ref().is_some_and(|identity| {
                self.row
                    .package_id
                    .eq_ignore_ascii_case(&identity.package_id)
                    && self.row.source_id.eq_ignore_ascii_case(&identity.source_id)
            })
            && self
                .registration
                .as_ref()
                .is_some_and(|program| update_block_reasons(program).is_empty())
    }

    pub fn row_key(&self) -> String {
        self.identity
            .as_ref()
            .map(|identity| {
                format!(
                    "{}:{}:{}",
                    identity.stable_key(),
                    self.row.installed_version.as_deref().unwrap_or(""),
                    self.row.available_version.as_deref().unwrap_or("")
                )
            })
            .unwrap_or_else(|| {
                format!(
                    "unmatched:{}:{}:{}:{}",
                    self.row.source_id.to_ascii_lowercase(),
                    self.row.package_id.to_ascii_lowercase(),
                    self.row.installed_version.as_deref().unwrap_or(""),
                    self.row.available_version.as_deref().unwrap_or("")
                )
            })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SoftwareSnapshot {
    pub items: Vec<SoftwareItem>,
    pub registration_issues: Vec<String>,
}

/// Parse the fixed-width table emitted by `winget list --source winget`.
/// WinGet 1.29 omits the Source column for `list`; in that format, the explicit
/// `--source winget` argument is the source binding. Older/alternate output
/// that includes a Source column is still checked row-by-row. Truncated
/// identities are rejected instead of being guessed from display names.
pub fn parse_winget_table(
    output: &str,
    expected_source: &str,
) -> Result<Vec<WingetRow>, SoftwareError> {
    if !valid_source_id(expected_source) || !expected_source.eq_ignore_ascii_case(WINGET_SOURCE) {
        return Err(SoftwareError::InvalidIdentity("WinGet source name".into()));
    }
    let cleaned = strip_ansi(output);
    let lines: Vec<&str> = cleaned.lines().collect();
    let Some((header_index, columns)) = lines
        .iter()
        .enumerate()
        .find_map(|(index, line)| parse_header(line).map(|columns| (index, columns)))
    else {
        return Err(SoftwareError::InvalidTable(
            "The package table header is missing or unsupported.".into(),
        ));
    };
    let mut rows = Vec::new();
    let mut in_rows = false;
    for line in lines.iter().skip(header_index + 1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if in_rows {
                continue;
            }
            continue;
        }
        if !in_rows {
            if trimmed
                .chars()
                .all(|ch| ch == '-' || ch == ' ' || ch == '─')
            {
                in_rows = true;
            }
            continue;
        }
        if trimmed
            .chars()
            .all(|ch| ch == '-' || ch == ' ' || ch == '─')
        {
            continue;
        }
        let cells = columns
            .iter()
            .map(|column| table_cell(line, column.start, column.end))
            .collect::<Vec<_>>();
        let name = cell(&cells, &columns, "name");
        let package_id = cell(&cells, &columns, "id");
        let installed_version = cell(&cells, &columns, "version");
        let available_version = cell(&cells, &columns, "available");
        let source_id = if columns.iter().any(|column| column.name == "source") {
            cell(&cells, &columns, "source")
        } else {
            expected_source.to_ascii_lowercase()
        };
        if name.is_empty() && package_id.is_empty() && installed_version.is_empty() {
            continue;
        }
        if name.is_empty()
            || !valid_package_id(&package_id)
            || source_id.is_empty()
            || !source_id.eq_ignore_ascii_case(expected_source)
        {
            return Err(SoftwareError::InvalidTable(
                "A row is truncated, has an invalid package ID, or names a different source."
                    .into(),
            ));
        }
        if installed_version.contains('…')
            || installed_version.contains("...")
            || available_version.contains('…')
            || available_version.contains("...")
        {
            return Err(SoftwareError::InvalidTable(
                "A package version was truncated by the console table.".into(),
            ));
        }
        rows.push(WingetRow {
            name,
            package_id,
            installed_version: nonempty(installed_version),
            available_version: nonempty(available_version),
            source_id: expected_source.to_ascii_lowercase(),
        });
        if rows.len() > MAX_ROWS {
            return Err(SoftwareError::InvalidTable(
                "The result exceeds the 1,000-package review limit.".into(),
            ));
        }
    }

    Ok(rows)
}

#[derive(Clone, Debug)]
struct Column {
    name: &'static str,
    start: usize,
    end: usize,
}

fn parse_header(line: &str) -> Option<Vec<Column>> {
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    let has_source = match tokens.as_slice() {
        ["Name", "Id", "Version", "Available"] => false,
        ["Name", "Id", "Version", "Available", "Source"] => true,
        _ => return None,
    };
    let labels: &[(&str, &str)] = if has_source {
        &[
            ("Name", "name"),
            ("Id", "id"),
            ("Version", "version"),
            ("Available", "available"),
            ("Source", "source"),
        ]
    } else {
        &[
            ("Name", "name"),
            ("Id", "id"),
            ("Version", "version"),
            ("Available", "available"),
        ]
    };
    let mut found = labels
        .iter()
        .map(|(label, name)| {
            let byte_index = line.find(*label)?;
            Some(Column {
                name: *name,
                start: line[..byte_index].encode_utf16().count(),
                end: usize::MAX,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    for index in 0..found.len() - 1 {
        found[index].end = found[index + 1].start;
    }
    Some(found)
}

fn table_cell(line: &str, start: usize, end: usize) -> String {
    let units: Vec<u16> = line.encode_utf16().collect();
    let start = start.min(units.len());
    let end = end.min(units.len());
    String::from_utf16_lossy(&units[start..end])
        .trim()
        .to_owned()
}

fn cell(cells: &[String], columns: &[Column], name: &str) -> String {
    columns
        .iter()
        .position(|column| column.name == name)
        .and_then(|index| cells.get(index))
        .cloned()
        .unwrap_or_default()
}

fn strip_ansi(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(code) = chars.next() {
                    if ('@'..='~').contains(&code) {
                        break;
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }
    result
}

fn nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.trim().to_owned())
}

fn valid_package_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-:".contains(&byte))
        && !value.ends_with("...")
}

fn valid_source_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn valid_version(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(|ch| ch.is_control())
}

fn validate_identity(identity: &SoftwareIdentity) -> Result<(), SoftwareError> {
    if identity.registry_source.hive != identity.registration.hive
        || identity.registration.key_name.is_empty()
        || identity.registration.key_name.contains(['\\', '/', '\0'])
        || matches!(identity.registration.key_name.as_str(), "." | "..")
        || identity.registration.key_name.len() > 1_024
        || identity.registration.key_name != identity.registration.key_name.to_ascii_lowercase()
        || !valid_package_id(&identity.package_id)
        || identity.package_id != identity.package_id.to_ascii_lowercase()
        || !valid_source_id(&identity.source_id)
        || !identity.source_id.eq_ignore_ascii_case(WINGET_SOURCE)
        || identity.source_id != identity.source_id.to_ascii_lowercase()
    {
        return Err(SoftwareError::InvalidIdentity(
            "source, registration, or package ID".into(),
        ));
    }
    Ok(())
}

pub fn build_snapshot(
    rows: Vec<WingetRow>,
    registrations: &[InstalledProgram],
    registration_issues: Vec<String>,
    settings: &SoftwareSettings,
) -> SoftwareSnapshot {
    let mut package_counts = std::collections::HashMap::new();
    for row in &rows {
        *package_counts
            .entry((
                row.source_id.to_ascii_lowercase(),
                row.package_id.to_ascii_lowercase(),
            ))
            .or_insert(0usize) += 1;
    }
    let mut items = rows
        .into_iter()
        .map(|row| {
            let duplicate_package = package_counts
                .get(&(
                    row.source_id.to_ascii_lowercase(),
                    row.package_id.to_ascii_lowercase(),
                ))
                .is_some_and(|count| *count > 1);
            let candidates = registrations
                .iter()
                .filter(|program| {
                    program.display_name.eq_ignore_ascii_case(&row.name)
                        && row.installed_version.as_deref().is_some_and(|version| {
                            program
                                .version
                                .as_deref()
                                .is_some_and(|registered| registered.eq_ignore_ascii_case(version))
                        })
                })
                .collect::<Vec<_>>();
            let (registration, identity, association_note) = if duplicate_package {
                (
                    None,
                    None,
                    Some("WinGet returned multiple rows for this source and package ID.".to_owned()),
                )
            } else {
                match candidates.as_slice() {
                [program] => {
                    let identity = SoftwareIdentity {
                        registration: program.identity.clone(),
                        registry_source: program.source,
                        package_id: row.package_id.to_ascii_lowercase(),
                        source_id: row.source_id.to_ascii_lowercase(),
                    };
                    (Some((*program).clone()), Some(identity), None)
                }
                [] => (
                    None,
                    None,
                    Some("No unique uninstall registration has the exact package name and installed version.".to_owned()),
                ),
                _ => (
                    None,
                    None,
                    Some("More than one uninstall registration matches this package name and version.".to_owned()),
                ),
                }
            };
            let base_status = if identity.is_none() {
                SoftwareStatus::Unmatched
            } else if row.available_version.is_some() {
                SoftwareStatus::UpdateAvailable
            } else {
                SoftwareStatus::Current
            };
            let (status, preference_note) = identity
                .as_ref()
                .and_then(|identity| settings.preference_for(identity))
                .map(|preference| match preference.state {
                    SoftwarePreferenceState::Ignored => (
                        SoftwareStatus::Ignored,
                        Some("Updates for this exact registration and package are ignored until restored.".to_owned()),
                    ),
                    SoftwarePreferenceState::SkipVersion => {
                        let offered = row.available_version.as_deref();
                        if offered == preference.skipped_version.as_deref() {
                            (
                                SoftwareStatus::SkippedVersion,
                                Some(format!("Version {} is skipped.", offered.unwrap_or(""))),
                            )
                        } else {
                            (
                                base_status,
                                Some("The skipped version is no longer offered; a different update may be reviewed.".to_owned()),
                            )
                        }
                    }
                })
                .unwrap_or((base_status, None));
            SoftwareItem {
                row,
                registration,
                identity,
                status,
                association_note,
                preference_note,
            }
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        left.row
            .name
            .to_lowercase()
            .cmp(&right.row.name.to_lowercase())
            .then_with(|| {
                left.row
                    .package_id
                    .to_lowercase()
                    .cmp(&right.row.package_id.to_lowercase())
            })
    });
    SoftwareSnapshot {
        items,
        registration_issues,
    }
}

pub fn load_settings(root: &Path) -> Result<SoftwareSettings, SoftwareError> {
    if !root.is_absolute() {
        return Err(SoftwareError::Settings(
            "the application data directory is not absolute.".into(),
        ));
    }
    let path = root.join("software-settings.json");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SoftwareSettings::default());
        }
        Err(error) => return Err(SoftwareError::Settings(error.to_string())),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_SETTINGS_BYTES
    {
        return Err(SoftwareError::Settings(
            "the settings file is linked, not a regular file, or exceeds its size limit; original bytes were preserved.".into(),
        ));
    }
    let settings: SoftwareSettings = serde_json::from_slice(
        &fs::read(&path).map_err(|error| SoftwareError::Settings(error.to_string()))?,
    )
    .map_err(|error| {
        SoftwareError::Settings(format!(
            "settings could not be decoded; original bytes were preserved: {error}"
        ))
    })?;
    validate_settings(&settings)?;
    Ok(settings)
}

pub fn save_settings(root: &Path, settings: &SoftwareSettings) -> Result<(), SoftwareError> {
    if !root.is_absolute() {
        return Err(SoftwareError::Settings(
            "the application data directory is not absolute.".into(),
        ));
    }
    validate_settings(settings)?;
    fs::create_dir_all(root).map_err(|error| SoftwareError::Settings(error.to_string()))?;
    let destination = root.join("software-settings.json");
    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(SoftwareError::Settings(
                    "the existing settings path is not a regular file; it was preserved.".into(),
                ));
            }
            // A failed read or a newer/corrupt document must not become an
            // implicit reset merely because the current UI has an older copy.
            load_settings(root)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(SoftwareError::Settings(error.to_string())),
    }
    let temporary = root.join(format!("software-settings.{}.tmp", Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(settings)
        .map_err(|error| SoftwareError::Settings(error.to_string()))?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
        drop(file);
        load_settings(root).map_err(|error| error.to_string())?;
        fs::rename(&temporary, &destination).map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(SoftwareError::Settings)
}

fn validate_settings(settings: &SoftwareSettings) -> Result<(), SoftwareError> {
    if settings.schema != 1 || settings.preferences.len() > MAX_SETTINGS_RULES {
        return Err(SoftwareError::Settings(
            "unsupported schema or rule count; original bytes were preserved.".into(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for preference in &settings.preferences {
        validate_identity(&preference.identity)?;
        if !seen.insert(preference.identity.clone()) {
            return Err(SoftwareError::Settings(
                "duplicate identities were found; original bytes were preserved.".into(),
            ));
        }
        match preference.state {
            SoftwarePreferenceState::SkipVersion
                if preference
                    .skipped_version
                    .as_deref()
                    .is_none_or(|version| !valid_version(version)) =>
            {
                return Err(SoftwareError::Settings(
                    "a skipped version is missing or invalid; original bytes were preserved."
                        .into(),
                ));
            }
            SoftwarePreferenceState::Ignored if preference.skipped_version.is_some() => {
                return Err(SoftwareError::Settings(
                    "an ignored preference includes an unexpected version; original bytes were preserved.".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn prepare_update(item: &SoftwareItem) -> Result<UpdateRequest, SoftwareError> {
    let identity = item.identity.as_ref().ok_or_else(|| {
        SoftwareError::UpdateBlocked(
            "the package is not matched to one exact installed-program registration.".into(),
        )
    })?;
    validate_identity(identity)?;
    let program = item.registration.as_ref().ok_or_else(|| {
        SoftwareError::UpdateBlocked("the registered installation is unavailable.".into())
    })?;
    if !update_block_reasons(program).is_empty() {
        return Err(SoftwareError::UpdateBlocked(
            update_block_reasons(program).join(" "),
        ));
    }
    if item.status != SoftwareStatus::UpdateAvailable {
        return Err(SoftwareError::UpdateBlocked(
            "the package is current, skipped, ignored, or otherwise not actionable.".into(),
        ));
    }
    let installed_version = item
        .row
        .installed_version
        .as_deref()
        .filter(|version| valid_version(version))
        .ok_or_else(|| {
            SoftwareError::UpdateBlocked(
                "WinGet did not provide an exact installed version.".into(),
            )
        })?;
    let target_version = item
        .row
        .available_version
        .as_deref()
        .filter(|version| valid_version(version))
        .ok_or_else(|| {
            SoftwareError::UpdateBlocked(
                "WinGet did not provide an exact available version.".into(),
            )
        })?;
    if item.row.source_id != WINGET_SOURCE
        || !item
            .row
            .package_id
            .eq_ignore_ascii_case(&identity.package_id)
        || !item.row.source_id.eq_ignore_ascii_case(&identity.source_id)
    {
        return Err(SoftwareError::InvalidIdentity(
            "the displayed source or package ID changed.".into(),
        ));
    }
    if program.display_name.eq_ignore_ascii_case("DCleaner")
        || program.identity.key_name.eq_ignore_ascii_case("dcleaner")
    {
        return Err(SoftwareError::UpdateBlocked(
            "DCleaner cannot update itself through this page.".into(),
        ));
    }
    Ok(UpdateRequest {
        request_id: Uuid::new_v4(),
        identity: identity.clone(),
        display_name: program.display_name.clone(),
        package_id: item.row.package_id.clone(),
        source_id: item.row.source_id.clone(),
        installed_version: installed_version.to_owned(),
        target_version: target_version.to_owned(),
    })
}

fn update_block_reasons(program: &InstalledProgram) -> Vec<String> {
    let mut reasons = Vec::new();
    if program.system_component {
        reasons.push("Windows marks the program as a system component.".into());
    }
    if program.protected {
        reasons.push("The registration marks the program as protected.".into());
    }
    if program.display_name.eq_ignore_ascii_case("DCleaner")
        || program.identity.key_name.eq_ignore_ascii_case("dcleaner")
    {
        reasons.push("DCleaner cannot update itself through this page.".into());
    }
    reasons
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateRequest {
    pub request_id: Uuid,
    pub identity: SoftwareIdentity,
    pub display_name: String,
    pub package_id: String,
    pub source_id: String,
    pub installed_version: String,
    pub target_version: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateVerification {
    Verified,
    Uncertain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateProcessReceipt {
    pub process_id: u32,
    pub exit_code: Option<i32>,
    /// A wait failure happens after the child starts and therefore leaves an
    /// uncertain operation unless the post-check can verify the target state.
    pub wait_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateReceipt {
    pub request_id: Uuid,
    pub identity: SoftwareIdentity,
    pub package_id: String,
    pub target_version: String,
    pub process: UpdateProcessReceipt,
    pub verification: UpdateVerification,
    pub observed_registry_version: Option<String>,
    pub observed_winget_version: Option<String>,
    pub verification_note: Option<String>,
    pub finished_at: chrono::DateTime<chrono::Utc>,
}

impl UpdateReceipt {
    pub fn journal_state(&self) -> &'static str {
        match self.verification {
            UpdateVerification::Verified => "verified",
            UpdateVerification::Uncertain => "uncertain",
        }
    }
}

pub trait WingetPort {
    fn list(&self) -> Result<Vec<WingetRow>, SoftwareError>;
}

pub trait UpdateProcessPort {
    fn run(&mut self, request: &UpdateRequest) -> Result<UpdateProcessReceipt, String>;
}

/// Re-read registration and WinGet catalog state before the durable request is
/// handed off. After WinGet exits, verify both registry and WinGet installed
/// versions; a process exit by itself is never success.
pub fn update_and_verify(
    request: &UpdateRequest,
    registry: &impl RegistryPort,
    winget: &impl WingetPort,
    process: &mut impl UpdateProcessPort,
) -> Result<UpdateReceipt, SoftwareError> {
    validate_request(request)?;
    let raw = registry
        .read_registration(
            request.identity.registry_source,
            &request.identity.registration,
        )
        .map_err(SoftwareError::Registry)?
        .ok_or_else(|| {
            SoftwareError::UpdateBlocked(
                "the uninstall registration was removed after review.".into(),
            )
        })?;
    if raw.key_name.to_ascii_lowercase() != request.identity.registration.key_name
        || raw.display_name.as_deref().map(str::trim) != Some(request.display_name.as_str())
        || raw.display_version.as_deref().map(str::trim) != Some(request.installed_version.as_str())
    {
        return Err(SoftwareError::UpdateBlocked(
            "the exact registration name or installed version changed after review.".into(),
        ));
    }
    if raw.system_component || raw.protected {
        return Err(SoftwareError::UpdateBlocked(
            "the registration is now marked as a system or protected component.".into(),
        ));
    }
    let preflight = winget.list()?;
    let row = unique_row(&preflight, &request.package_id, &request.source_id)?;
    if row.installed_version.as_deref() != Some(request.installed_version.as_str())
        || row.available_version.as_deref() != Some(request.target_version.as_str())
    {
        return Err(SoftwareError::UpdateBlocked(
            "the installed or offered WinGet version changed after review.".into(),
        ));
    }
    let process_receipt = process.run(request).map_err(SoftwareError::Process)?;

    let post_registration = registry
        .read_registration(
            request.identity.registry_source,
            &request.identity.registration,
        )
        .map_err(SoftwareError::Registry);
    let post_rows = winget.list();
    let mut observed_registry_version = None;
    let mut observed_winget_version = None;
    let mut verification_note = None;
    let registration_ok = match post_registration {
        Ok(Some(raw))
            if raw.key_name.to_ascii_lowercase() == request.identity.registration.key_name
                && raw.display_name.as_deref().map(str::trim)
                    == Some(request.display_name.as_str()) =>
        {
            observed_registry_version = raw.display_version;
            observed_registry_version.as_deref() == Some(request.target_version.as_str())
        }
        Ok(None) => {
            verification_note =
                Some("The original uninstall registration is no longer present.".into());
            false
        }
        Ok(Some(_)) => {
            verification_note =
                Some("The registration identity changed while WinGet was running.".into());
            false
        }
        Err(error) => {
            verification_note = Some(error.to_string());
            false
        }
    };
    let winget_ok = match post_rows {
        Ok(rows) => match unique_row(&rows, &request.package_id, &request.source_id) {
            Ok(row) => {
                observed_winget_version = row.installed_version.clone();
                observed_winget_version.as_deref() == Some(request.target_version.as_str())
            }
            Err(error) => {
                if verification_note.is_none() {
                    verification_note = Some(error.to_string());
                }
                false
            }
        },
        Err(error) => {
            if verification_note.is_none() {
                verification_note = Some(error.to_string());
            }
            false
        }
    };
    let verification = if registration_ok && winget_ok {
        UpdateVerification::Verified
    } else {
        if verification_note.is_none() {
            verification_note = Some(
                "WinGet and the registration did not both report the requested installed version."
                    .into(),
            );
        }
        UpdateVerification::Uncertain
    };
    Ok(UpdateReceipt {
        request_id: request.request_id,
        identity: request.identity.clone(),
        package_id: request.package_id.clone(),
        target_version: request.target_version.clone(),
        process: process_receipt,
        verification,
        observed_registry_version,
        observed_winget_version,
        verification_note,
        finished_at: chrono::Utc::now(),
    })
}

fn validate_request(request: &UpdateRequest) -> Result<(), SoftwareError> {
    validate_identity(&request.identity)?;
    if request.source_id != WINGET_SOURCE
        || !request
            .source_id
            .eq_ignore_ascii_case(&request.identity.source_id)
        || !request
            .package_id
            .eq_ignore_ascii_case(&request.identity.package_id)
        || !valid_package_id(&request.package_id)
        || !valid_version(&request.installed_version)
        || !valid_version(&request.target_version)
        || request.installed_version == request.target_version
        || request.display_name.trim().is_empty()
        || request.display_name.eq_ignore_ascii_case("DCleaner")
        || request
            .identity
            .registration
            .key_name
            .eq_ignore_ascii_case("dcleaner")
    {
        return Err(SoftwareError::InvalidIdentity(
            "update request fields".into(),
        ));
    }
    Ok(())
}

fn unique_row<'a>(
    rows: &'a [WingetRow],
    package_id: &str,
    source_id: &str,
) -> Result<&'a WingetRow, SoftwareError> {
    let mut matches = rows.iter().filter(|row| {
        row.package_id.eq_ignore_ascii_case(package_id)
            && row.source_id.eq_ignore_ascii_case(source_id)
    });
    let Some(row) = matches.next() else {
        return Err(SoftwareError::UpdateBlocked(
            "the exact package disappeared from the selected source.".into(),
        ));
    };
    if matches.next().is_some() {
        return Err(SoftwareError::UpdateBlocked(
            "the selected source returned multiple rows for the package ID.".into(),
        ));
    }
    Ok(row)
}

/// Real WinGet adapter. It always selects the public `winget` source explicitly,
/// never accepts agreements, and never invokes a shell.
pub struct NativeWinget;

impl WingetPort for NativeWinget {
    fn list(&self) -> Result<Vec<WingetRow>, SoftwareError> {
        #[cfg(windows)]
        {
            let output = bounded_output(
                "winget",
                &["list", "--source", WINGET_SOURCE, "--disable-interactivity"],
                INVENTORY_TIMEOUT,
            )?;
            if !output.status.success() {
                return Err(SoftwareError::ProcessFailed {
                    code: output.status.code(),
                    detail: bounded_winget_diagnostic(&output.stdout, &output.stderr),
                });
            }
            return parse_winget_table(&String::from_utf8_lossy(&output.stdout), WINGET_SOURCE);
        }
        #[cfg(not(windows))]
        {
            Err(SoftwareError::UnsupportedPlatform)
        }
    }
}

fn bounded_winget_diagnostic(stdout: &[u8], stderr: &[u8]) -> String {
    const MAX_DIAGNOSTIC_CHARS: usize = 800;
    let mut detail = String::new();
    for bytes in [stdout, stderr] {
        for line in String::from_utf8_lossy(bytes).lines() {
            let line = line.trim();
            if line.is_empty() || !is_winget_diagnostic_line(line) {
                continue;
            }
            let compact = line.split_whitespace().collect::<Vec<_>>().join(" ");
            let remaining = MAX_DIAGNOSTIC_CHARS.saturating_sub(detail.chars().count());
            if remaining == 0 {
                return detail;
            }
            if !detail.is_empty() {
                detail.push_str(" · ");
            }
            detail.extend(compact.chars().take(remaining));
            if detail.chars().count() >= MAX_DIAGNOSTIC_CHARS {
                return detail;
            }
        }
    }
    if detail.is_empty() {
        "WinGet returned no readable error detail. Check the selected source and retry.".into()
    } else {
        detail
    }
}

fn is_winget_diagnostic_line(line: &str) -> bool {
    let lower = line.trim_start().to_ascii_lowercase();
    [
        "[err",
        "[warn",
        "error",
        "failed",
        "invalid",
        "unknown",
        "unrecognized",
        "unexpected",
        "warning",
        "source",
        "0x8a",
        "0x800",
        "could not",
        "unable",
        "must be",
        "not found",
        "not supported",
        "requires",
        "expected",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

pub fn installed_software(settings: &SoftwareSettings) -> Result<SoftwareSnapshot, SoftwareError> {
    #[cfg(windows)]
    {
        let rows = NativeWinget.list()?;
        let inventory = programs::installed_programs().map_err(SoftwareError::Registry)?;
        let issues = inventory
            .errors
            .into_iter()
            .map(|error| {
                format!(
                    "{}{}: {}",
                    match error.source.hive {
                        programs::RegistryHive::CurrentUser => "HKCU",
                        programs::RegistryHive::LocalMachine => "HKLM",
                    },
                    error
                        .key_name
                        .map(|name| format!("\\{name}"))
                        .unwrap_or_default(),
                    error.message
                )
            })
            .collect();
        Ok(build_snapshot(rows, &inventory.programs, issues, settings))
    }
    #[cfg(not(windows))]
    {
        let _ = settings;
        Err(SoftwareError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
fn bounded_output(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<std::process::Output, SoftwareError> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut child = Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| SoftwareError::WinGetUnavailable(error.to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SoftwareError::Process("WinGet stdout was not available.".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| SoftwareError::Process("WinGet stderr was not available.".into()))?;
    let (tx, rx) = mpsc::channel();
    let streams: Vec<(Box<dyn Read + Send>, bool)> =
        vec![(Box::new(stdout), true), (Box::new(stderr), false)];
    for (stream, is_stdout) in streams {
        let tx = tx.clone();
        thread::spawn(move || {
            let mut stream = stream;
            let mut data = Vec::new();
            let mut buffer = [0u8; 8192];
            let mut too_large = false;
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        if data.len().saturating_add(count) <= MAX_OUTPUT_BYTES {
                            data.extend_from_slice(&buffer[..count]);
                        } else {
                            too_large = true;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send((is_stdout, data, too_large));
        });
    }
    drop(tx);
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| SoftwareError::Process(error.to_string()))?
        {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SoftwareError::ProcessTimeout);
        }
        thread::sleep(Duration::from_millis(25));
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut too_large = false;
    for _ in 0..2 {
        let (is_stdout, data, limit) =
            rx.recv_timeout(Duration::from_secs(2)).map_err(|error| {
                SoftwareError::Process(format!("WinGet output reader did not finish: {error}"))
            })?;
        if is_stdout {
            stdout = data;
        } else {
            stderr = data;
        }
        too_large |= limit;
    }
    if too_large {
        return Err(SoftwareError::OutputLimit);
    }
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(windows)]
pub struct NativeUpdateProcess;

#[cfg(windows)]
impl UpdateProcessPort for NativeUpdateProcess {
    fn run(&mut self, request: &UpdateRequest) -> Result<UpdateProcessReceipt, String> {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        let mut child = Command::new("winget")
            .args([
                "upgrade",
                "--id",
                &request.package_id,
                "--exact",
                "--source",
                &request.source_id,
                "--version",
                &request.target_version,
                "--interactive",
            ])
            .creation_flags(CREATE_NEW_CONSOLE)
            .spawn()
            .map_err(|error| error.to_string())?;
        let process_id = child.id();
        let (exit_code, wait_error) = match child.wait() {
            Ok(status) => (status.code(), None),
            Err(error) => (None, Some(error.to_string())),
        };
        Ok(UpdateProcessReceipt {
            process_id,
            exit_code,
            wait_error,
        })
    }
}

#[cfg(not(windows))]
pub struct NativeUpdateProcess;

#[cfg(not(windows))]
impl UpdateProcessPort for NativeUpdateProcess {
    fn run(&mut self, _request: &UpdateRequest) -> Result<UpdateProcessReceipt, String> {
        Err("The native WinGet update adapter is unavailable on this platform.".into())
    }
}

pub fn run_native_update(request: &UpdateRequest) -> Result<UpdateReceipt, SoftwareError> {
    #[cfg(windows)]
    {
        return update_and_verify(
            request,
            &programs::WindowsRegistry,
            &NativeWinget,
            &mut NativeUpdateProcess,
        );
    }
    #[cfg(not(windows))]
    {
        let _ = request;
        Err(SoftwareError::UnsupportedPlatform)
    }
}

/// Resolve the persisted settings path only when the application data root is a
/// real absolute directory. The returned path is informational, not executable.
pub fn settings_path(root: &Path) -> Result<PathBuf, SoftwareError> {
    if !root.is_absolute() {
        return Err(SoftwareError::Settings(
            "the application data directory is not absolute.".into(),
        ));
    }
    Ok(root.join("software-settings.json"))
}
