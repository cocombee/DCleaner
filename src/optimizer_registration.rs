//! Read-only, bounded IFEO registration snapshots for reviewed executable paths.
//!
//! This module deliberately reports registry observations only. It does not decide
//! whether a debugger is effective, belongs to this application, or should be
//! removed. Windows can expose IFEO through shared registry views, so the two view
//! observations are kept explicit without treating them as independent hooks.

use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

pub const MAX_EXECUTABLE_PATHS: usize = 32;
pub const MAX_EXECUTABLE_PATH_UTF16_UNITS: usize = 32_767;
pub const MAX_DIRECT_SUBKEYS_PER_VIEW: usize = 64;
pub const MAX_VALUES_PER_KEY: usize = 128;
pub const MAX_VALUES_PER_VIEW: usize = 512;
pub const MAX_VALUE_NAME_UTF16_UNITS: usize = 16_383;
pub const MAX_SUBKEY_NAME_UTF16_UNITS: usize = 255;
pub const MAX_RAW_VALUE_BYTES: usize = 64 * 1024;
pub const MAX_RAW_BYTES_PER_VIEW: usize = 1024 * 1024;

const IFEO_ROOT: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const REG_SZ_RAW: u32 = 1;
const REG_EXPAND_SZ_RAW: u32 = 2;
const REG_DWORD_RAW: u32 = 4;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryView {
    Registry32,
    Registry64,
}

impl RegistryView {
    pub const ALL: [Self; 2] = [Self::Registry32, Self::Registry64];
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ObservationState {
    Complete,
    Missing,
    Denied { win32_code: u32 },
    Failed { win32_code: u32 },
    Malformed { reason: String },
    Limited { reason: String },
    Cancelled,
    Unsupported { reason: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportState {
    Complete,
    Partial,
    Limited,
    Cancelled,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistrationReport {
    pub state: ReportState,
    pub executables: Vec<ExecutableRegistration>,
    /// Number of supplied paths that were not inspected because of path-count or
    /// cancellation bounds. Invalid paths are represented in `executables`.
    pub unexamined_path_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutableRegistration {
    /// A syntactically valid bounded caller path, if it could safely be retained.
    /// This does not assert that the file exists or that any registration belongs
    /// to a product. Invalid or overlong identity is omitted; `input_index` remains.
    pub executable: Option<PathBuf>,
    pub input_index: usize,
    pub state: ObservationState,
    pub views: Vec<RegistryViewRegistration>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryViewRegistration {
    pub view: RegistryView,
    pub root: RegistryKeySnapshot,
    /// Direct children of the IFEO image key are retained as observations. Their
    /// names are not treated as proof of registration ownership or precedence.
    pub direct_subkeys: Vec<DirectSubkeySnapshot>,
    pub direct_subkeys_state: ObservationState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirectSubkeySnapshot {
    pub name: String,
    pub key: RegistryKeySnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryKeySnapshot {
    /// Relative to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`.
    pub key_path: String,
    pub state: ObservationState,
    /// All values found on a complete or partial read are retained, including
    /// unrelated values, so a caller cannot mistake a partial view for an empty key.
    pub values: Vec<RegistryValueSnapshot>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryValueRole {
    RootDebugger,
    RootUseFilter,
    FilterFullPath,
    FilterDebugger,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ValueValidation {
    NotApplicable,
    WellFormed,
    Malformed { reason: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryValueSnapshot {
    pub name: String,
    /// Native registry type as returned by `RegQueryValueExW`.
    pub value_type: u32,
    /// Exact raw bytes returned by the registry. No environment expansion or
    /// command interpretation is performed.
    pub data: Vec<u8>,
    pub role: RegistryValueRole,
    pub validation: ValueValidation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawRegistryValue {
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawKeyRead {
    /// `Missing` means the key did not exist. Other states can carry values read
    /// before a later access, format, or bound failure.
    pub state: ObservationState,
    pub values: Vec<RawRegistryValue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSubkeyRead {
    pub state: ObservationState,
    pub names: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyScope {
    ImageRoot,
    DirectSubkey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadBudget {
    pub values_remaining: usize,
    pub subkeys_remaining: usize,
    pub raw_bytes_remaining: usize,
}

impl ReadBudget {
    pub fn bounded() -> Self {
        Self {
            values_remaining: MAX_VALUES_PER_VIEW,
            subkeys_remaining: MAX_DIRECT_SUBKEYS_PER_VIEW,
            raw_bytes_remaining: MAX_RAW_BYTES_PER_VIEW,
        }
    }
}

/// Fixtureable read-only boundary. Implementations must use only the supplied
/// HKLM view/key, honor cancellation between native reads, and stop at `budget`.
pub trait RegistrationReadPort {
    fn read_key(
        &mut self,
        view: RegistryView,
        key_path: &str,
        scope: KeyScope,
        cancel: &AtomicBool,
        budget: &mut ReadBudget,
    ) -> RawKeyRead;

    fn enumerate_direct_subkeys(
        &mut self,
        view: RegistryView,
        key_path: &str,
        cancel: &AtomicBool,
        budget: &mut ReadBudget,
    ) -> RawSubkeyRead;
}

/// Inspects the requested absolute executable paths under HKLM IFEO in both
/// registry views. This API returns observations only and never writes the registry.
#[cfg(windows)]
pub fn inspect(paths: &[PathBuf], cancel: &AtomicBool) -> RegistrationReport {
    let mut port = windows_backend::WindowsRegistrationReadPort;
    inspect_with_port(paths, cancel, &mut port)
}

/// On non-Windows targets the native registry is unavailable; this explicit report
/// prevents an unsupported platform from being mistaken for an empty IFEO result.
#[cfg(not(windows))]
pub fn inspect(paths: &[PathBuf], _cancel: &AtomicBool) -> RegistrationReport {
    RegistrationReport {
        state: ReportState::Unsupported,
        executables: Vec::new(),
        unexamined_path_count: paths.len(),
    }
}

/// Runs the report assembly through an injectable read port. Production callers
/// should use [`inspect`]; this entry point exists so state and bound behavior can
/// be tested without reading or changing a machine registry.
pub fn inspect_with_port<P: RegistrationReadPort>(
    paths: &[PathBuf],
    cancel: &AtomicBool,
    port: &mut P,
) -> RegistrationReport {
    let mut executables = Vec::new();
    let mut saw_problem = false;
    let mut saw_limit = paths.len() > MAX_EXECUTABLE_PATHS;
    let mut was_cancelled = false;
    let path_limit = paths.len().min(MAX_EXECUTABLE_PATHS);

    for (input_index, executable) in paths.iter().take(path_limit).enumerate() {
        if cancel.load(Ordering::Acquire) {
            was_cancelled = true;
            break;
        }
        let Some(image_name) = image_name_from_absolute_path(executable) else {
            saw_problem = true;
            executables.push(ExecutableRegistration {
                executable: None,
                input_index,
                state: ObservationState::Malformed {
                    reason: "Only a bounded absolute Windows executable path can be inspected."
                        .into(),
                },
                views: Vec::new(),
            });
            continue;
        };

        let relative_root = format!("{IFEO_ROOT}\\{image_name}");
        let mut executable_registration = ExecutableRegistration {
            executable: Some(executable.clone()),
            input_index,
            state: ObservationState::Complete,
            views: Vec::with_capacity(RegistryView::ALL.len()),
        };

        for view in RegistryView::ALL {
            if cancel.load(Ordering::Acquire) {
                was_cancelled = true;
                executable_registration.state = ObservationState::Cancelled;
                break;
            }
            let mut budget = ReadBudget::bounded();
            let root_raw = port.read_key(
                view,
                &relative_root,
                KeyScope::ImageRoot,
                cancel,
                &mut budget,
            );
            let root = make_key_snapshot(&relative_root, KeyScope::ImageRoot, root_raw);
            note_state(
                &root.state,
                &mut saw_problem,
                &mut saw_limit,
                &mut was_cancelled,
            );

            let mut direct_subkeys = Vec::new();
            let mut direct_subkeys_state = match &root.state {
                ObservationState::Missing
                | ObservationState::Cancelled
                | ObservationState::Denied { .. }
                | ObservationState::Failed { .. }
                | ObservationState::Unsupported { .. } => root.state.clone(),
                ObservationState::Complete
                | ObservationState::Malformed { .. }
                | ObservationState::Limited { .. } => ObservationState::Complete,
            };

            if root.state != ObservationState::Missing
                && !matches!(
                    &root.state,
                    ObservationState::Denied { .. }
                        | ObservationState::Failed { .. }
                        | ObservationState::Cancelled
                        | ObservationState::Unsupported { .. }
                )
            {
                if cancel.load(Ordering::Acquire) {
                    direct_subkeys_state = ObservationState::Cancelled;
                } else {
                    let mut raw_subkeys =
                        port.enumerate_direct_subkeys(view, &relative_root, cancel, &mut budget);
                    if raw_subkeys.names.len() > MAX_DIRECT_SUBKEYS_PER_VIEW {
                        raw_subkeys.names.truncate(MAX_DIRECT_SUBKEYS_PER_VIEW);
                        raw_subkeys.state = ObservationState::Limited {
                            reason: "The direct IFEO subkey count exceeded the inspection bound."
                                .into(),
                        };
                    }
                    direct_subkeys_state = raw_subkeys.state;
                    note_state(
                        &direct_subkeys_state,
                        &mut saw_problem,
                        &mut saw_limit,
                        &mut was_cancelled,
                    );
                    if direct_subkeys_state != ObservationState::Cancelled {
                        for child_name in raw_subkeys.names {
                            if cancel.load(Ordering::Acquire) {
                                was_cancelled = true;
                                direct_subkeys_state = ObservationState::Cancelled;
                                break;
                            }
                            if !valid_registry_component(&child_name) {
                                saw_problem = true;
                                direct_subkeys.push(DirectSubkeySnapshot {
                                name: child_name,
                                key: RegistryKeySnapshot {
                                    key_path: relative_root.clone(),
                                    state: ObservationState::Malformed {
                                        reason: "A direct IFEO subkey name was not a safe single component."
                                            .into(),
                                    },
                                    values: Vec::new(),
                                },
                            });
                                continue;
                            }
                            let child_path = format!("{relative_root}\\{child_name}");
                            let raw_key = port.read_key(
                                view,
                                &child_path,
                                KeyScope::DirectSubkey,
                                cancel,
                                &mut budget,
                            );
                            let mut key =
                                make_key_snapshot(&child_path, KeyScope::DirectSubkey, raw_key);
                            if key.state == ObservationState::Missing {
                                // The parent enumerated this name, but the child vanished before
                                // its values were read. Preserve that race as incomplete evidence.
                                key.state = ObservationState::Failed { win32_code: 2 };
                            }
                            note_state(
                                &key.state,
                                &mut saw_problem,
                                &mut saw_limit,
                                &mut was_cancelled,
                            );
                            direct_subkeys.push(DirectSubkeySnapshot {
                                name: child_name,
                                key,
                            });
                            if was_cancelled {
                                direct_subkeys_state = ObservationState::Cancelled;
                                break;
                            }
                        }
                    }
                }
            }

            if cancel.load(Ordering::Acquire) {
                was_cancelled = true;
                direct_subkeys_state = ObservationState::Cancelled;
            }
            note_state(
                &direct_subkeys_state,
                &mut saw_problem,
                &mut saw_limit,
                &mut was_cancelled,
            );
            executable_registration
                .views
                .push(RegistryViewRegistration {
                    view,
                    root,
                    direct_subkeys,
                    direct_subkeys_state,
                });
            if was_cancelled {
                executable_registration.state = ObservationState::Cancelled;
                break;
            }
        }
        if executable_registration.state != ObservationState::Cancelled {
            executable_registration.state = aggregate_view_state(&executable_registration.views);
        }
        executables.push(executable_registration);
        if was_cancelled {
            break;
        }
    }

    let unexamined_path_count = paths.len().saturating_sub(executables.len());
    if unexamined_path_count > 0 && was_cancelled {
        saw_limit = false;
    }
    let state = if was_cancelled {
        ReportState::Cancelled
    } else if saw_limit {
        ReportState::Limited
    } else if saw_problem {
        ReportState::Partial
    } else {
        ReportState::Complete
    };
    RegistrationReport {
        state,
        executables,
        unexamined_path_count,
    }
}

fn note_state(
    state: &ObservationState,
    saw_problem: &mut bool,
    saw_limit: &mut bool,
    was_cancelled: &mut bool,
) {
    match state {
        ObservationState::Complete | ObservationState::Missing => {}
        ObservationState::Limited { .. } => *saw_limit = true,
        ObservationState::Cancelled => *was_cancelled = true,
        ObservationState::Denied { .. }
        | ObservationState::Failed { .. }
        | ObservationState::Malformed { .. }
        | ObservationState::Unsupported { .. } => *saw_problem = true,
    }
}

fn aggregate_view_state(views: &[RegistryViewRegistration]) -> ObservationState {
    let mut partial = None;
    for view in views {
        for state in std::iter::once(&view.root.state)
            .chain(std::iter::once(&view.direct_subkeys_state))
            .chain(view.direct_subkeys.iter().map(|child| &child.key.state))
        {
            match state {
                ObservationState::Cancelled => return ObservationState::Cancelled,
                ObservationState::Limited { .. } => return state.clone(),
                ObservationState::Denied { .. }
                | ObservationState::Failed { .. }
                | ObservationState::Malformed { .. }
                | ObservationState::Unsupported { .. } => {
                    if partial.is_none() {
                        partial = Some(state.clone());
                    }
                }
                ObservationState::Complete | ObservationState::Missing => {}
            }
        }
    }
    partial.unwrap_or(ObservationState::Complete)
}

fn make_key_snapshot(key_path: &str, scope: KeyScope, raw: RawKeyRead) -> RegistryKeySnapshot {
    let raw_value_count = raw.values.len();
    let mut values = Vec::with_capacity(raw_value_count.min(MAX_VALUES_PER_KEY));
    let mut malformed = false;
    for value in raw.values.into_iter().take(MAX_VALUES_PER_KEY) {
        let role = value_role(scope, &value.name);
        let validation = validate_value(role, value.value_type, &value.data);
        malformed |= matches!(&validation, ValueValidation::Malformed { .. });
        values.push(RegistryValueSnapshot {
            name: value.name,
            value_type: value.value_type,
            data: value.data,
            role,
            validation,
        });
    }
    let state = if raw_value_count > MAX_VALUES_PER_KEY {
        ObservationState::Limited {
            reason: "The per-key value count exceeded the report bound.".into(),
        }
    } else if malformed && raw.state == ObservationState::Complete {
        ObservationState::Malformed {
            reason: "A recognized IFEO value had an unexpected registry type or encoding.".into(),
        }
    } else {
        raw.state
    };
    RegistryKeySnapshot {
        key_path: key_path.to_owned(),
        state,
        values,
    }
}

fn value_role(scope: KeyScope, name: &str) -> RegistryValueRole {
    match (scope, name.to_ascii_lowercase().as_str()) {
        (KeyScope::ImageRoot, "debugger") => RegistryValueRole::RootDebugger,
        (KeyScope::ImageRoot, "usefilter") => RegistryValueRole::RootUseFilter,
        (KeyScope::DirectSubkey, "filterfullpath") => RegistryValueRole::FilterFullPath,
        (KeyScope::DirectSubkey, "debugger") => RegistryValueRole::FilterDebugger,
        _ => RegistryValueRole::Other,
    }
}

fn validate_value(role: RegistryValueRole, value_type: u32, data: &[u8]) -> ValueValidation {
    match role {
        RegistryValueRole::RootDebugger
        | RegistryValueRole::FilterDebugger
        | RegistryValueRole::FilterFullPath => {
            if value_type != REG_SZ_RAW && value_type != REG_EXPAND_SZ_RAW {
                return malformed_validation("Expected REG_SZ or REG_EXPAND_SZ for this value.");
            }
            if data.len() % 2 != 0 {
                return malformed_validation("The UTF-16 registry data had an odd byte length.");
            }
            let units = data
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            if String::from_utf16(&units).is_err() {
                return malformed_validation("The registry string contained invalid UTF-16.");
            }
            if units.last().copied() != Some(0) {
                return malformed_validation("The registry string was not NUL-terminated.");
            }
            if units[..units.len().saturating_sub(1)].contains(&0) {
                return malformed_validation(
                    "The registry string contained an interior NUL or trailing payload.",
                );
            }
            ValueValidation::WellFormed
        }
        RegistryValueRole::RootUseFilter => {
            if value_type != REG_DWORD_RAW || data.len() != 4 {
                malformed_validation("Expected a four-byte REG_DWORD for UseFilter.")
            } else {
                ValueValidation::WellFormed
            }
        }
        RegistryValueRole::Other => ValueValidation::NotApplicable,
    }
}

fn malformed_validation(reason: &str) -> ValueValidation {
    ValueValidation::Malformed {
        reason: reason.to_owned(),
    }
}

pub(crate) fn image_name_from_absolute_path(path: &std::path::Path) -> Option<String> {
    let path_text = path.to_str()?;
    let path_units_over_limit = path_text
        .encode_utf16()
        .take(MAX_EXECUTABLE_PATH_UTF16_UNITS + 1)
        .count()
        > MAX_EXECUTABLE_PATH_UTF16_UNITS;
    if path_text.is_empty() || path_units_over_limit {
        return None;
    }
    if path_text.contains('\0') {
        return None;
    }
    let normalized = path_text.replace('/', "\\");
    let bytes = normalized.as_bytes();
    let drive_absolute =
        bytes.len() >= 4 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    let unc_absolute = normalized.starts_with("\\\\")
        && !normalized.starts_with("\\\\?\\")
        && !normalized.starts_with("\\\\.\\")
        && normalized
            .strip_prefix("\\\\")
            .is_some_and(|rest| valid_file_components(rest.split('\\'), true));
    if !drive_absolute && !unc_absolute {
        return None;
    }
    if drive_absolute && !valid_file_components(normalized[3..].split('\\'), false) {
        return None;
    }
    let image_name = normalized.rsplit('\\').next()?;
    if !valid_registry_component(image_name)
        || image_name.encode_utf16().count() > MAX_SUBKEY_NAME_UTF16_UNITS
    {
        return None;
    }
    Some(image_name.to_owned())
}

fn valid_file_components<'a>(
    components: impl Iterator<Item = &'a str>,
    require_unc_parts: bool,
) -> bool {
    let mut count = 0usize;
    for component in components {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.chars().any(|character| {
                character.is_control()
                    || matches!(character, ':' | '*' | '?' | '<' | '>' | '"' | '|')
            })
        {
            return false;
        }
        count += 1;
    }
    !require_unc_parts || count >= 3
}

fn valid_registry_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && !component
            .chars()
            .any(|character| matches!(character, '\\' | '/' | '\0'))
        && component.encode_utf16().count() <= MAX_SUBKEY_NAME_UTF16_UNITS
}

#[cfg(windows)]
mod windows_backend {
    use super::*;
    use std::ptr;
    use windows::{
        Win32::{
            Foundation::{
                ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
                ERROR_SUCCESS,
            },
            System::Registry::{
                HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
                REG_SAM_FLAGS, REG_VALUE_TYPE, RegCloseKey, RegEnumKeyExW, RegEnumValueW,
                RegOpenKeyExW, RegQueryValueExW,
            },
        },
        core::{PCWSTR, PWSTR},
    };

    pub(super) struct WindowsRegistrationReadPort;

    impl RegistrationReadPort for WindowsRegistrationReadPort {
        fn read_key(
            &mut self,
            view: RegistryView,
            key_path: &str,
            _scope: KeyScope,
            cancel: &AtomicBool,
            budget: &mut ReadBudget,
        ) -> RawKeyRead {
            if cancel.load(Ordering::Acquire) {
                return raw_read(ObservationState::Cancelled);
            }
            let handle = match open_hklm_key(view, key_path) {
                Ok(Some(handle)) => handle,
                Ok(None) => return raw_read(ObservationState::Missing),
                Err(status) => return raw_read(error_state(status)),
            };
            let mut values = Vec::new();
            let mut state = ObservationState::Complete;
            let per_key_limit = MAX_VALUES_PER_KEY.min(budget.values_remaining);
            if per_key_limit == 0 {
                return RawKeyRead {
                    state: ObservationState::Limited {
                        reason: "The total IFEO value inspection budget was exhausted.".into(),
                    },
                    values,
                };
            }
            let mut name_buffer = vec![0u16; MAX_VALUE_NAME_UTF16_UNITS + 1];
            for index in 0..=per_key_limit {
                if cancel.load(Ordering::Acquire) {
                    state = ObservationState::Cancelled;
                    break;
                }
                let mut name_len = name_buffer.len() as u32;
                let code = unsafe {
                    RegEnumValueW(
                        handle.0,
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
                if code == ERROR_MORE_DATA {
                    state = ObservationState::Limited {
                        reason: "A registry value name exceeded the bounded name buffer.".into(),
                    };
                    break;
                }
                if code != ERROR_SUCCESS {
                    state = error_state(code.0);
                    break;
                }
                if index == per_key_limit {
                    state = ObservationState::Limited {
                        reason:
                            "The value count exceeded the per-key or per-view inspection bound."
                                .into(),
                    };
                    break;
                }
                let Ok(name) = String::from_utf16(&name_buffer[..name_len as usize]) else {
                    state = ObservationState::Malformed {
                        reason: "A registry value name contained invalid UTF-16.".into(),
                    };
                    break;
                };
                if name.contains('\0') {
                    state = ObservationState::Malformed {
                        reason: "A registry value name contained an embedded NUL.".into(),
                    };
                    break;
                }
                let name_bytes = name_len as usize * 2;
                if name_bytes > budget.raw_bytes_remaining {
                    state = ObservationState::Limited {
                        reason: "The per-view raw byte budget was exhausted by value names.".into(),
                    };
                    break;
                }
                match read_value(handle.0, &name, name_bytes, cancel, budget) {
                    Ok(Some(value)) => values.push(value),
                    Ok(None) => {
                        state = ObservationState::Failed {
                            win32_code: ERROR_FILE_NOT_FOUND.0,
                        };
                        break;
                    }
                    Err(read_state) => {
                        state = read_state;
                        break;
                    }
                }
            }
            RawKeyRead { state, values }
        }

        fn enumerate_direct_subkeys(
            &mut self,
            view: RegistryView,
            key_path: &str,
            cancel: &AtomicBool,
            budget: &mut ReadBudget,
        ) -> RawSubkeyRead {
            if cancel.load(Ordering::Acquire) {
                return RawSubkeyRead {
                    state: ObservationState::Cancelled,
                    names: Vec::new(),
                };
            }
            let handle = match open_hklm_key(view, key_path) {
                Ok(Some(handle)) => handle,
                Ok(None) => {
                    return RawSubkeyRead {
                        state: ObservationState::Failed {
                            win32_code: ERROR_FILE_NOT_FOUND.0,
                        },
                        names: Vec::new(),
                    };
                }
                Err(status) => {
                    return RawSubkeyRead {
                        state: error_state(status),
                        names: Vec::new(),
                    };
                }
            };
            let limit = MAX_DIRECT_SUBKEYS_PER_VIEW.min(budget.subkeys_remaining);
            let mut names = Vec::new();
            let mut state = ObservationState::Complete;
            if limit == 0 {
                return RawSubkeyRead {
                    state: ObservationState::Limited {
                        reason: "The direct-subkey inspection budget was exhausted.".into(),
                    },
                    names,
                };
            }
            let mut name_buffer = vec![0u16; MAX_SUBKEY_NAME_UTF16_UNITS + 1];
            for index in 0..=limit {
                if cancel.load(Ordering::Acquire) {
                    state = ObservationState::Cancelled;
                    break;
                }
                let mut name_len = name_buffer.len() as u32;
                let code = unsafe {
                    RegEnumKeyExW(
                        handle.0,
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
                if code == ERROR_MORE_DATA {
                    state = ObservationState::Limited {
                        reason: "A direct IFEO subkey name exceeded the bounded buffer.".into(),
                    };
                    break;
                }
                if code != ERROR_SUCCESS {
                    state = error_state(code.0);
                    break;
                }
                if index == limit {
                    state = ObservationState::Limited {
                        reason: "The direct IFEO subkey count exceeded its inspection bound."
                            .into(),
                    };
                    break;
                }
                let Ok(name) = String::from_utf16(&name_buffer[..name_len as usize]) else {
                    state = ObservationState::Malformed {
                        reason: "A direct IFEO subkey name contained invalid UTF-16.".into(),
                    };
                    break;
                };
                if !valid_registry_component(&name) {
                    state = ObservationState::Malformed {
                        reason: "A direct IFEO subkey name was not a safe path component.".into(),
                    };
                    break;
                }
                let name_bytes = name_len as usize * 2;
                if name_bytes > budget.raw_bytes_remaining {
                    state = ObservationState::Limited {
                        reason: "The per-view raw byte budget was exhausted by subkey names."
                            .into(),
                    };
                    break;
                }
                budget.raw_bytes_remaining -= name_bytes;
                budget.subkeys_remaining = budget.subkeys_remaining.saturating_sub(1);
                names.push(name);
            }
            RawSubkeyRead { state, names }
        }
    }

    fn read_value(
        key: HKEY,
        name: &str,
        name_bytes: usize,
        cancel: &AtomicBool,
        budget: &mut ReadBudget,
    ) -> Result<Option<RawRegistryValue>, ObservationState> {
        if cancel.load(Ordering::Acquire) {
            return Err(ObservationState::Cancelled);
        }
        let wide_name = wide(name);
        let name_ptr = PCWSTR(wide_name.as_ptr());
        let mut value_type = REG_VALUE_TYPE(0);
        let mut length = 0u32;
        let first = unsafe {
            RegQueryValueExW(
                key,
                name_ptr,
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
            return Err(error_state(first.0));
        }
        let length = length as usize;
        let available = budget.raw_bytes_remaining.saturating_sub(name_bytes);
        if length > MAX_RAW_VALUE_BYTES || length > available {
            return Err(ObservationState::Limited {
                reason: "A registry value exceeded the per-value or per-view byte bound.".into(),
            });
        }
        // Allocate one byte even for an empty value so the second native query
        // always revalidates existence, type, and size without passing a null ptr.
        let mut data = vec![0u8; length.max(1)];
        if cancel.load(Ordering::Acquire) {
            return Err(ObservationState::Cancelled);
        }
        let mut actual_length = data.len() as u32;
        let second = unsafe {
            RegQueryValueExW(
                key,
                name_ptr,
                None,
                Some(&mut value_type),
                Some(data.as_mut_ptr()),
                Some(&mut actual_length),
            )
        };
        if second.0 == ERROR_FILE_NOT_FOUND.0 {
            return Ok(None);
        }
        if second == ERROR_MORE_DATA {
            return Err(ObservationState::Limited {
                reason: "The registry value changed size during the bounded read.".into(),
            });
        }
        if second != ERROR_SUCCESS {
            return Err(error_state(second.0));
        }
        if actual_length as usize > length {
            return Err(ObservationState::Limited {
                reason: "The registry value grew beyond the allocated read bound.".into(),
            });
        }
        data.truncate(actual_length as usize);
        budget.values_remaining = budget.values_remaining.saturating_sub(1);
        budget.raw_bytes_remaining = budget
            .raw_bytes_remaining
            .saturating_sub(name_bytes.saturating_add(data.len()));
        Ok(Some(RawRegistryValue {
            name: name.to_owned(),
            value_type: value_type.0,
            data,
        }))
    }

    fn open_hklm_key(view: RegistryView, path: &str) -> Result<Option<RegistryHandle>, u32> {
        let access = REG_SAM_FLAGS(
            KEY_READ.0
                | match view {
                    RegistryView::Registry32 => KEY_WOW64_32KEY.0,
                    RegistryView::Registry64 => KEY_WOW64_64KEY.0,
                },
        );
        let key_path = wide(path);
        let mut opened = HKEY(ptr::null_mut());
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(key_path.as_ptr()),
                None,
                access,
                &mut opened,
            )
        };
        if status.0 == ERROR_FILE_NOT_FOUND.0 || status.0 == 3 {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(status.0);
        }
        Ok(Some(RegistryHandle(opened)))
    }

    fn error_state(code: u32) -> ObservationState {
        if code == ERROR_ACCESS_DENIED.0 {
            ObservationState::Denied { win32_code: code }
        } else {
            ObservationState::Failed { win32_code: code }
        }
    }

    fn raw_read(state: ObservationState) -> RawKeyRead {
        RawKeyRead {
            state,
            values: Vec::new(),
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct RegistryHandle(HKEY);

    impl Drop for RegistryHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}
