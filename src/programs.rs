//! Installed-program inventory and safe handoff to a registered uninstaller.
//!
//! Inventory only reads uninstall registrations. Callers must obtain user
//! confirmation and persist their own intent before calling `handoff_uninstall`.

use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt, path::PathBuf};
use uuid::Uuid;

const UNINSTALL_REGISTRY_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryHive {
    CurrentUser,
    LocalMachine,
}

impl RegistryHive {
    fn label(self) -> &'static str {
        match self {
            Self::CurrentUser => "HKCU",
            Self::LocalMachine => "HKLM",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryView {
    Registry32,
    Registry64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RegistrySource {
    pub hive: RegistryHive,
    pub view: RegistryView,
}

impl RegistrySource {
    pub const fn all() -> [Self; 4] {
        [
            Self {
                hive: RegistryHive::CurrentUser,
                view: RegistryView::Registry64,
            },
            Self {
                hive: RegistryHive::CurrentUser,
                view: RegistryView::Registry32,
            },
            Self {
                hive: RegistryHive::LocalMachine,
                view: RegistryView::Registry64,
            },
            Self {
                hive: RegistryHive::LocalMachine,
                view: RegistryView::Registry32,
            },
        ]
    }
}

/// Stable registered identity: hive plus uninstall subkey, normalized because
/// Windows registry key names are case-insensitive. Registry view is retained
/// separately as the exact source used to re-read the selected registration.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ProgramIdentity {
    pub hive: RegistryHive,
    pub key_name: String,
}

impl ProgramIdentity {
    fn from_registration(hive: RegistryHive, key_name: &str) -> Result<Self, String> {
        if key_name.is_empty()
            || key_name.contains(['\\', '/', '\0'])
            || key_name == "."
            || key_name == ".."
        {
            return Err("The uninstall registration has an invalid subkey name.".into());
        }
        Ok(Self {
            hive,
            key_name: key_name.to_lowercase(),
        })
    }

    pub fn stable_id(&self) -> String {
        format!(
            "{}\\{}\\{}",
            self.hive.label(),
            UNINSTALL_REGISTRY_PATH,
            self.key_name
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UninstallCommand {
    /// Exact registration text, retained for preview and revalidation.
    pub registered: String,
    /// Parsed executable and arguments are preview data; inventory never runs them.
    pub executable: String,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstalledProgram {
    pub identity: ProgramIdentity,
    pub source: RegistrySource,
    pub display_name: String,
    /// Registered icon resource locator from the uninstall key's DisplayIcon value.
    /// This is metadata only and is never executed.
    #[serde(default)]
    pub display_icon: Option<String>,
    pub publisher: Option<String>,
    pub version: Option<String>,
    pub install_location: Option<PathBuf>,
    /// Raw Windows `InstallDate` value, commonly formatted as YYYYMMDD.
    pub install_date: Option<String>,
    /// Windows `EstimatedSize` is stored in KiB and exposed here in bytes.
    pub estimated_size_bytes: Option<u64>,
    pub registered_uninstall_command: Option<String>,
    pub uninstall_command: Option<UninstallCommand>,
    pub uninstall_command_error: Option<String>,
    pub system_component: bool,
    pub protected: bool,
    pub no_remove: bool,
}

impl InstalledProgram {
    pub fn removal_block_reasons(&self) -> Vec<RemovalBlockReason> {
        let mut reasons = Vec::new();
        if is_current_application(&self.identity, &self.display_name) {
            reasons.push(RemovalBlockReason::CurrentApplication);
        }
        if self.system_component {
            reasons.push(RemovalBlockReason::SystemComponent);
        }
        if self.protected {
            reasons.push(RemovalBlockReason::Protected);
        }
        if self.no_remove {
            reasons.push(RemovalBlockReason::NoRemove);
        }
        if self.uninstall_command.is_none() {
            reasons.push(if self.registered_uninstall_command.is_some() {
                RemovalBlockReason::InvalidUninstallCommand
            } else {
                RemovalBlockReason::MissingUninstallCommand
            });
        }
        reasons
    }

    pub fn can_uninstall(&self) -> bool {
        self.removal_block_reasons().is_empty()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemovalBlockReason {
    CurrentApplication,
    SystemComponent,
    Protected,
    NoRemove,
    MissingUninstallCommand,
    InvalidUninstallCommand,
}

impl fmt::Display for RemovalBlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CurrentApplication => "DCleaner cannot uninstall itself.",
            Self::SystemComponent => "Windows marks this entry as a system component.",
            Self::Protected => "This entry is marked as protected.",
            Self::NoRemove => "The registration disables removal.",
            Self::MissingUninstallCommand => "No registered uninstall command is available.",
            Self::InvalidUninstallCommand => {
                "The registered uninstall command cannot be launched safely."
            }
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct InventorySnapshot {
    pub programs: Vec<InstalledProgram>,
    pub errors: Vec<InventoryError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InventoryError {
    pub source: RegistrySource,
    pub key_name: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct RegistrySourceRead {
    pub registrations: Vec<RawProgramRegistration>,
    pub errors: Vec<RegistryEntryError>,
}

#[derive(Clone, Debug)]
pub struct RegistryEntryError {
    pub key_name: Option<String>,
    pub message: String,
}

/// Values read from one uninstall subkey. The adapter treats absent and
/// malformed individual values as unavailable metadata rather than inventing it.
#[derive(Clone, Debug, Default)]
pub struct RawProgramRegistration {
    pub key_name: String,
    pub display_name: Option<String>,
    pub display_icon: Option<String>,
    pub publisher: Option<String>,
    pub display_version: Option<String>,
    pub install_location: Option<String>,
    pub install_date: Option<String>,
    pub estimated_size_kib: Option<u64>,
    pub uninstall_string: Option<String>,
    pub system_component: bool,
    pub protected: bool,
    pub no_remove: bool,
}

/// Read-only registry boundary, injectable so parsing and stale-registration
/// behavior can be tested without accessing the user's registry.
pub trait RegistryPort {
    fn read_source(&self, source: RegistrySource) -> Result<RegistrySourceRead, String>;

    fn read_registration(
        &self,
        source: RegistrySource,
        identity: &ProgramIdentity,
    ) -> Result<Option<RawProgramRegistration>, String>;
}

pub fn enumerate_from(registry: &impl RegistryPort) -> InventorySnapshot {
    let mut snapshot = InventorySnapshot::default();
    let mut seen = HashSet::new();

    // Registry64 sources precede Registry32, so duplicate registrations resolve
    // deterministically to the native view. HKCU and HKLM remain distinct IDs.
    for source in RegistrySource::all() {
        let read = match registry.read_source(source) {
            Ok(read) => read,
            Err(message) => {
                snapshot.errors.push(InventoryError {
                    source,
                    key_name: None,
                    message,
                });
                continue;
            }
        };
        snapshot
            .errors
            .extend(read.errors.into_iter().map(|error| InventoryError {
                source,
                key_name: error.key_name,
                message: error.message,
            }));

        for raw in read.registrations {
            let identity = match ProgramIdentity::from_registration(source.hive, &raw.key_name) {
                Ok(identity) => identity,
                Err(message) => {
                    snapshot.errors.push(InventoryError {
                        source,
                        key_name: Some(raw.key_name),
                        message,
                    });
                    continue;
                }
            };
            let Some(display_name) = raw
                .display_name
                .as_deref()
                .map(str::trim)
                .filter(|name| !name.is_empty())
            else {
                snapshot.errors.push(InventoryError {
                    source,
                    key_name: Some(raw.key_name),
                    message: "The registration has no display name and was skipped.".into(),
                });
                continue;
            };
            if !seen.insert(identity.clone()) {
                continue;
            }
            snapshot.programs.push(to_installed_program(
                identity,
                source,
                display_name.to_owned(),
                raw,
            ));
        }
    }

    snapshot.programs.sort_by(|left, right| {
        left.display_name
            .to_lowercase()
            .cmp(&right.display_name.to_lowercase())
            .then_with(|| left.identity.stable_id().cmp(&right.identity.stable_id()))
    });
    snapshot
}

fn to_installed_program(
    identity: ProgramIdentity,
    source: RegistrySource,
    display_name: String,
    raw: RawProgramRegistration,
) -> InstalledProgram {
    let registered_uninstall_command = raw
        .uninstall_string
        .filter(|command| !command.trim().is_empty());
    let (uninstall_command, uninstall_command_error) =
        if let Some(registered) = registered_uninstall_command.as_deref() {
            match parse_uninstall_command(registered) {
                Ok(command) => (
                    Some(UninstallCommand {
                        registered: registered.to_owned(),
                        executable: command.executable,
                        arguments: command.arguments,
                    }),
                    None,
                ),
                Err(error) => (None, Some(error)),
            }
        } else {
            (None, None)
        };

    InstalledProgram {
        identity,
        source,
        display_name,
        display_icon: raw.display_icon,
        publisher: raw.publisher,
        version: raw.display_version,
        install_location: raw
            .install_location
            .map(|value| expand_environment_variables(value.trim()))
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
        install_date: raw.install_date.map(|value| value.trim().to_owned()),
        estimated_size_bytes: raw
            .estimated_size_kib
            .and_then(|size| size.checked_mul(1024)),
        registered_uninstall_command,
        uninstall_command,
        uninstall_command_error,
        system_component: raw.system_component,
        protected: raw.protected,
        no_remove: raw.no_remove,
    }
}

fn is_current_application(identity: &ProgramIdentity, display_name: &str) -> bool {
    display_name.trim().eq_ignore_ascii_case("DCleaner")
        || identity.key_name.eq_ignore_ascii_case("dcleaner")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UninstallRequest {
    pub request_id: Uuid,
    pub identity: ProgramIdentity,
    pub source: RegistrySource,
    /// Exact command text observed during review; execution requires it to match.
    pub expected_registered_command: String,
}

pub fn prepare_uninstall(
    program: &InstalledProgram,
) -> Result<UninstallRequest, Vec<RemovalBlockReason>> {
    let reasons = program.removal_block_reasons();
    if !reasons.is_empty() {
        return Err(reasons);
    }
    let Some(expected_registered_command) = program.registered_uninstall_command.clone() else {
        return Err(vec![RemovalBlockReason::MissingUninstallCommand]);
    };
    Ok(UninstallRequest {
        request_id: Uuid::new_v4(),
        identity: program.identity.clone(),
        source: program.source,
        expected_registered_command,
    })
}

pub trait ProcessPort {
    /// Launches the parsed executable with argument values, without a command shell.
    fn launch(&mut self, command: &UninstallCommand) -> Result<u32, String>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
/// Confirms that the requested process was launched; it does not represent an
/// uninstall outcome. The caller must observe and journal that separately.
pub struct UninstallHandoffReceipt {
    pub request_id: Uuid,
    pub identity: ProgramIdentity,
    pub process_id: u32,
    pub handed_off_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UninstallHandoffError {
    InvalidRequest,
    Registry(String),
    RegistrationMissing,
    IdentityChanged,
    CommandChanged,
    Blocked(Vec<RemovalBlockReason>),
    Process(String),
}

impl fmt::Display for UninstallHandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => f.write_str("The uninstall request has an invalid source."),
            Self::Registry(message) => {
                write!(f, "Could not re-read the uninstall registration: {message}")
            }
            Self::RegistrationMissing => {
                f.write_str("The uninstall registration no longer exists.")
            }
            Self::IdentityChanged => f.write_str("The uninstall registration identity changed."),
            Self::CommandChanged => {
                f.write_str("The registered uninstall command changed after review.")
            }
            Self::Blocked(reasons) => write!(
                f,
                "Removal is blocked: {}",
                reasons
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            Self::Process(message) => {
                write!(f, "Could not start the registered uninstaller: {message}")
            }
        }
    }
}

pub fn handoff_uninstall(
    request: &UninstallRequest,
    registry: &impl RegistryPort,
    process: &mut impl ProcessPort,
) -> Result<UninstallHandoffReceipt, UninstallHandoffError> {
    if request.source.hive != request.identity.hive {
        return Err(UninstallHandoffError::InvalidRequest);
    }
    let raw = registry
        .read_registration(request.source, &request.identity)
        .map_err(UninstallHandoffError::Registry)?
        .ok_or(UninstallHandoffError::RegistrationMissing)?;
    let current_identity = ProgramIdentity::from_registration(request.source.hive, &raw.key_name)
        .map_err(|_| UninstallHandoffError::IdentityChanged)?;
    if current_identity != request.identity {
        return Err(UninstallHandoffError::IdentityChanged);
    }
    if raw.uninstall_string.as_deref() != Some(request.expected_registered_command.as_str()) {
        return Err(UninstallHandoffError::CommandChanged);
    }

    let display_name = raw
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(UninstallHandoffError::IdentityChanged)?
        .to_owned();
    let current = to_installed_program(current_identity.clone(), request.source, display_name, raw);
    let reasons = current.removal_block_reasons();
    if !reasons.is_empty() {
        return Err(UninstallHandoffError::Blocked(reasons));
    }
    let command = current
        .uninstall_command
        .as_ref()
        .ok_or(UninstallHandoffError::Blocked(vec![
            RemovalBlockReason::InvalidUninstallCommand,
        ]))?;
    let process_id = process
        .launch(command)
        .map_err(UninstallHandoffError::Process)?;

    Ok(UninstallHandoffReceipt {
        request_id: request.request_id,
        identity: current_identity,
        process_id,
        handed_off_at: chrono::Utc::now(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedUninstallCommand {
    pub executable: String,
    pub arguments: Vec<String>,
}

/// Parses a registered Windows command line into direct process arguments.
/// `cmd.exe`, PowerShell, and script files are rejected so no shell is involved.
pub fn parse_uninstall_command(raw: &str) -> Result<ParsedUninstallCommand, String> {
    let expanded = expand_environment_variables(raw).trim().to_owned();
    if expanded.is_empty() {
        return Err("The registered uninstall command is empty.".into());
    }

    let (executable, arguments) = if expanded.starts_with('"') {
        let mut tokens = split_windows_command_line(&expanded);
        if tokens.is_empty() || tokens[0].is_empty() {
            return Err("The registered command does not identify an executable.".into());
        }
        let executable = tokens.remove(0);
        (executable, tokens)
    } else {
        parse_unquoted_command(&expanded)?
    };

    if forbidden_shell(&executable) {
        return Err("Shell commands are not accepted for uninstall handoff.".into());
    }
    let extension = executable
        .rsplit(['\\', '/', ':'])
        .next()
        .unwrap_or(&executable)
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase());
    if matches!(
        extension.as_deref(),
        Some("bat" | "cmd" | "ps1" | "vbs" | "js")
    ) {
        return Err("Script-based uninstall commands cannot be launched directly.".into());
    }
    Ok(ParsedUninstallCommand {
        executable,
        arguments,
    })
}

fn parse_unquoted_command(raw: &str) -> Result<(String, Vec<String>), String> {
    let tokens = split_windows_command_line(raw);
    let Some(first) = tokens.first() else {
        return Err("The registered command does not identify an executable.".into());
    };

    let mut unresolved_path_with_spaces = false;
    for (index, _) in raw.char_indices().filter(|(_, ch)| ch.is_whitespace()) {
        let candidate = raw[..index].trim_end();
        let lower = candidate.to_ascii_lowercase();
        if !(lower.ends_with(".exe") || lower.ends_with(".com")) {
            continue;
        }
        if !candidate.contains(['\\', '/', ':']) {
            continue;
        }
        unresolved_path_with_spaces = true;
        if PathBuf::from(candidate).is_file() {
            let arguments = split_windows_command_line(&raw[index..]);
            return Ok((candidate.to_owned(), arguments));
        }
    }

    let first_lower = first.to_ascii_lowercase();
    if unresolved_path_with_spaces
        || (first.contains(['\\', '/', ':'])
            && !(first_lower.ends_with(".exe") || first_lower.ends_with(".com")))
    {
        return Err("The unquoted executable path could not be resolved safely.".into());
    }
    Ok((first.clone(), tokens.into_iter().skip(1).collect()))
}

fn split_windows_command_line(input: &str) -> Vec<String> {
    let chars: Vec<char> = input.chars().collect();
    let mut output = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut token_started = false;
    let mut index = 0;

    while index < chars.len() {
        if !quoted && chars[index].is_whitespace() {
            if token_started {
                output.push(std::mem::take(&mut token));
                token_started = false;
            }
            index += 1;
            continue;
        }

        if chars[index] == '\\' {
            let start = index;
            while index < chars.len() && chars[index] == '\\' {
                index += 1;
            }
            let slash_count = index - start;
            if index < chars.len() && chars[index] == '"' {
                token.extend(std::iter::repeat_n('\\', slash_count / 2));
                token_started = true;
                if slash_count % 2 == 1 {
                    token.push('"');
                    index += 1;
                } else if quoted && index + 1 < chars.len() && chars[index + 1] == '"' {
                    token.push('"');
                    index += 2;
                } else {
                    quoted = !quoted;
                    index += 1;
                }
            } else {
                token.extend(std::iter::repeat_n('\\', slash_count));
                token_started = true;
            }
            continue;
        }

        if chars[index] == '"' {
            token_started = true;
            if quoted && index + 1 < chars.len() && chars[index + 1] == '"' {
                token.push('"');
                index += 2;
            } else {
                quoted = !quoted;
                index += 1;
            }
            continue;
        }

        token.push(chars[index]);
        token_started = true;
        index += 1;
    }

    if token_started {
        output.push(token);
    }
    output
}

fn forbidden_shell(executable: &str) -> bool {
    let basename = executable
        .rsplit(['\\', '/', ':'])
        .next()
        .unwrap_or(executable);
    matches!(
        basename.to_ascii_lowercase().as_str(),
        "cmd"
            | "cmd.exe"
            | "command.com"
            | "powershell"
            | "powershell.exe"
            | "powershell_ise.exe"
            | "pwsh"
            | "pwsh.exe"
    )
}

fn expand_environment_variables(input: &str) -> String {
    let mut expanded = String::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input.as_bytes()[index] == b'%' {
            if let Some(relative_end) = input[index + 1..].find('%') {
                let end = index + 1 + relative_end;
                let name = &input[index + 1..end];
                if !name.is_empty() {
                    if let Some(value) = std::env::var_os(name) {
                        expanded.push_str(&value.to_string_lossy());
                    } else {
                        expanded.push_str(&input[index..=end]);
                    }
                    index = end + 1;
                    continue;
                }
            }
        }
        let character = input[index..].chars().next().expect("index is in bounds");
        expanded.push(character);
        index += character.len_utf8();
    }
    expanded
}

/// Errors explicitly when no native adapter exists; macOS never receives fake Windows data.
pub fn installed_programs() -> Result<InventorySnapshot, String> {
    #[cfg(windows)]
    {
        return Ok(enumerate_from(&WindowsRegistry));
    }
    #[cfg(target_os = "macos")]
    {
        Err("Installed-program inventory is unavailable on macOS until its native adapter is implemented.".into())
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err("Installed-program inventory is available only on supported desktop platforms.".into())
    }
}

#[cfg(windows)]
pub struct WindowsRegistry;

#[cfg(windows)]
impl RegistryPort for WindowsRegistry {
    fn read_source(&self, source: RegistrySource) -> Result<RegistrySourceRead, String> {
        windows_registry::read_source(source)
    }

    fn read_registration(
        &self,
        source: RegistrySource,
        identity: &ProgramIdentity,
    ) -> Result<Option<RawProgramRegistration>, String> {
        windows_registry::read_registration(source, identity)
    }
}

#[cfg(windows)]
pub struct WindowsProcess;

#[cfg(windows)]
impl ProcessPort for WindowsProcess {
    fn launch(&mut self, command: &UninstallCommand) -> Result<u32, String> {
        std::process::Command::new(&command.executable)
            .args(&command.arguments)
            .spawn()
            .map(|child| child.id())
            .map_err(|error| error.to_string())
    }
}

#[cfg(windows)]
mod windows_registry {
    use super::*;
    use windows::{
        Win32::{
            Foundation::{
                ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS,
            },
            System::Registry::{
                HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY,
                KEY_WOW64_64KEY, REG_DWORD, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE, RegCloseKey,
                RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
            },
        },
        core::{PCWSTR, PWSTR},
    };

    const MAX_VALUE_BYTES: u32 = 1024 * 1024;

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    fn nul_terminated(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn source_root(source: RegistrySource) -> HKEY {
        match source.hive {
            RegistryHive::CurrentUser => HKEY_CURRENT_USER,
            RegistryHive::LocalMachine => HKEY_LOCAL_MACHINE,
        }
    }

    fn source_access(source: RegistrySource) -> windows::Win32::System::Registry::REG_SAM_FLAGS {
        KEY_READ
            | match source.view {
                RegistryView::Registry32 => KEY_WOW64_32KEY,
                RegistryView::Registry64 => KEY_WOW64_64KEY,
            }
    }

    fn open_key(
        root: HKEY,
        subkey: &str,
        access: windows::Win32::System::Registry::REG_SAM_FLAGS,
    ) -> Result<Option<Key>, String> {
        let wide = nul_terminated(subkey);
        let mut result = HKEY(std::ptr::null_mut());
        let status =
            unsafe { RegOpenKeyExW(root, PCWSTR(wide.as_ptr()), None, access, &mut result) };
        if status == ERROR_FILE_NOT_FOUND {
            Ok(None)
        } else if status != ERROR_SUCCESS {
            Err(format!("Windows registry error {}.", status.0))
        } else {
            Ok(Some(Key(result)))
        }
    }

    pub(super) fn read_source(source: RegistrySource) -> Result<RegistrySourceRead, String> {
        let Some(root) = open_key(
            source_root(source),
            UNINSTALL_REGISTRY_PATH,
            source_access(source),
        )?
        else {
            return Ok(RegistrySourceRead::default());
        };
        let mut result = RegistrySourceRead::default();
        let mut index = 0u32;
        loop {
            let mut name = vec![0u16; 512];
            let mut length = name.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    root.0,
                    index,
                    Some(PWSTR(name.as_mut_ptr())),
                    &mut length,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status == ERROR_MORE_DATA {
                name.resize(32_768, 0);
                length = name.len() as u32;
                let retry = unsafe {
                    RegEnumKeyExW(
                        root.0,
                        index,
                        Some(PWSTR(name.as_mut_ptr())),
                        &mut length,
                        None,
                        None,
                        None,
                        None,
                    )
                };
                if retry != ERROR_SUCCESS {
                    result.errors.push(RegistryEntryError {
                        key_name: None,
                        message: format!(
                            "Could not enumerate registry entries (error {}).",
                            retry.0
                        ),
                    });
                    break;
                }
            } else if status != ERROR_SUCCESS {
                result.errors.push(RegistryEntryError {
                    key_name: None,
                    message: format!("Could not enumerate registry entries (error {}).", status.0),
                });
                break;
            }

            let key_name = String::from_utf16_lossy(&name[..length as usize]);
            match read_key(root.0, source_access(source), &key_name) {
                Ok(Some(registration)) => result.registrations.push(registration),
                Ok(None) => {}
                Err(message) => result.errors.push(RegistryEntryError {
                    key_name: Some(key_name),
                    message,
                }),
            }
            index = index.saturating_add(1);
            if index == u32::MAX {
                result.errors.push(RegistryEntryError {
                    key_name: None,
                    message: "Registry enumeration exceeded the supported entry count.".into(),
                });
                break;
            }
        }
        Ok(result)
    }

    pub(super) fn read_registration(
        source: RegistrySource,
        identity: &ProgramIdentity,
    ) -> Result<Option<RawProgramRegistration>, String> {
        if source.hive != identity.hive {
            return Err("The source hive does not match the registration identity.".into());
        }
        let identity = ProgramIdentity::from_registration(identity.hive, &identity.key_name)?;
        let Some(root) = open_key(
            source_root(source),
            UNINSTALL_REGISTRY_PATH,
            source_access(source),
        )?
        else {
            return Ok(None);
        };
        read_key(root.0, source_access(source), &identity.key_name)
    }

    fn read_key(
        root: HKEY,
        access: windows::Win32::System::Registry::REG_SAM_FLAGS,
        key_name: &str,
    ) -> Result<Option<RawProgramRegistration>, String> {
        let Some(key) = open_key(root, key_name, access)? else {
            return Ok(None);
        };
        let text = |name| read_text(key.0, name);
        let dword = |name| read_dword(key.0, name);
        Ok(Some(RawProgramRegistration {
            key_name: key_name.to_owned(),
            display_name: text("DisplayName")?,
            display_icon: text("DisplayIcon")?,
            publisher: text("Publisher")?,
            display_version: text("DisplayVersion")?,
            install_location: text("InstallLocation")?,
            install_date: text("InstallDate")?,
            estimated_size_kib: dword("EstimatedSize")?.map(u64::from),
            uninstall_string: text("UninstallString")?,
            system_component: dword("SystemComponent")?.unwrap_or_default() != 0,
            protected: dword("Protected")?.unwrap_or_default() != 0,
            no_remove: dword("NoRemove")?.unwrap_or_default() != 0,
        }))
    }

    fn query_value(key: HKEY, name: &str) -> Result<Option<(REG_VALUE_TYPE, Vec<u8>)>, String> {
        let wide = nul_terminated(name);
        for _ in 0..3 {
            let mut value_type = REG_VALUE_TYPE(0);
            let mut bytes = 0u32;
            let status = unsafe {
                RegQueryValueExW(
                    key,
                    PCWSTR(wide.as_ptr()),
                    None,
                    Some(&mut value_type),
                    None,
                    Some(&mut bytes),
                )
            };
            if status == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
                return Err(format!(
                    "Could not read registry value {name} (error {}).",
                    status.0
                ));
            }
            if bytes > MAX_VALUE_BYTES {
                return Err(format!("Registry value {name} exceeds the supported size."));
            }
            let mut data = vec![0u8; bytes as usize];
            let status = unsafe {
                RegQueryValueExW(
                    key,
                    PCWSTR(wide.as_ptr()),
                    None,
                    Some(&mut value_type),
                    Some(data.as_mut_ptr()),
                    Some(&mut bytes),
                )
            };
            if status == ERROR_MORE_DATA {
                continue;
            }
            if status != ERROR_SUCCESS {
                return Err(format!(
                    "Could not read registry value {name} (error {}).",
                    status.0
                ));
            }
            data.truncate(bytes as usize);
            return Ok(Some((value_type, data)));
        }
        Err(format!(
            "Registry value {name} kept changing while being read."
        ))
    }

    fn read_text(key: HKEY, name: &str) -> Result<Option<String>, String> {
        let Some((value_type, data)) = query_value(key, name)? else {
            return Ok(None);
        };
        if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
            return Ok(None);
        }
        if !data.len().is_multiple_of(2) {
            return Err(format!("Registry value {name} is not valid UTF-16."));
        }
        let wide: Vec<u16> = data
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .take_while(|character| *character != 0)
            .collect();
        Ok(Some(String::from_utf16_lossy(&wide)))
    }

    fn read_dword(key: HKEY, name: &str) -> Result<Option<u32>, String> {
        let Some((value_type, data)) = query_value(key, name)? else {
            return Ok(None);
        };
        if value_type != REG_DWORD || data.len() != 4 {
            return Ok(None);
        }
        Ok(Some(u32::from_le_bytes(
            data.try_into().expect("four-byte DWORD"),
        )))
    }
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn _windows_types_are_intentionally_unavailable() {}
