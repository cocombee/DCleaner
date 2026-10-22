//! Bounded, advisory artwork lookup for browsers which are not running.
use dcleaner::privacy::Browser;
use std::{collections::HashMap, path::PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scope {
    User64,
    User32,
    Machine64,
    Machine32,
}
const SCOPES: [Scope; 4] = [
    Scope::User64,
    Scope::User32,
    Scope::Machine64,
    Scope::Machine32,
];
const BROWSERS: [(Browser, &str); 3] = [
    (Browser::Chrome, "chrome.exe"),
    (Browser::Edge, "msedge.exe"),
    (Browser::Firefox, "firefox.exe"),
];
const MAX_VALUE_BYTES: usize = 65_536;

pub(super) fn supplement(
    mut resources: HashMap<Browser, String>,
    mut read: impl FnMut(Scope, &str) -> Option<String>,
) -> HashMap<Browser, String> {
    for (browser, executable) in BROWSERS {
        if resources
            .get(&browser)
            .and_then(|raw| executable_resource(raw, executable))
            .is_some()
        {
            continue;
        }
        resources.remove(&browser);
        for scope in SCOPES {
            if let Some(path) =
                read(scope, executable).and_then(|raw| executable_resource(&raw, executable))
            {
                resources.insert(browser, path);
                break;
            }
        }
    }
    resources
}
fn executable_resource(raw: &str, executable: &str) -> Option<String> {
    let raw = raw.trim();
    let path = if raw.starts_with('"') {
        raw.strip_prefix('"')?.strip_suffix('"')?
    } else {
        raw
    };
    if path.contains('"') || path.contains('\0') {
        return None;
    }
    let path = super::expand_path_variables(path)?;
    if path.starts_with("\\\\") || path.starts_with("//") {
        return None;
    }
    let path = PathBuf::from(path);
    if !path.is_absolute()
        || !path
            .file_name()?
            .to_string_lossy()
            .eq_ignore_ascii_case(executable)
        || !path.is_file()
    {
        return None;
    }
    Some(path.to_string_lossy().into_owned())
}
fn decode(kind: u32, bytes: &[u8]) -> Option<String> {
    if !matches!(kind, 1 | 2)
        || bytes.is_empty()
        || bytes.len() > MAX_VALUE_BYTES
        || bytes.len() % 2 != 0
    {
        return None;
    }
    let mut units = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect::<Vec<_>>();
    while units.last() == Some(&0) {
        units.pop();
    }
    if units.is_empty() || units.contains(&0) {
        return None;
    }
    String::from_utf16(&units).ok()
}

#[cfg(windows)]
pub(super) fn registered_path(scope: Scope, executable: &str) -> Option<String> {
    use windows::{
        Win32::{Foundation::ERROR_SUCCESS, System::Registry::*},
        core::PCWSTR,
    };
    let (root, view) = match scope {
        Scope::User64 => (HKEY_CURRENT_USER, KEY_WOW64_64KEY),
        Scope::User32 => (HKEY_CURRENT_USER, KEY_WOW64_32KEY),
        Scope::Machine64 => (HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY),
        Scope::Machine32 => (HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY),
    };
    let path: Vec<u16> =
        format!(r"Software\Microsoft\Windows\CurrentVersion\App Paths\{executable}")
            .encode_utf16()
            .chain(Some(0))
            .collect();
    let mut key = HKEY::default();
    if unsafe {
        RegOpenKeyExW(
            root,
            PCWSTR(path.as_ptr()),
            None,
            KEY_QUERY_VALUE | view,
            &mut key,
        )
    } != ERROR_SUCCESS
    {
        return None;
    }
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
    let key = Key(key);
    let mut kind = REG_VALUE_TYPE(0);
    let mut length = 0u32;
    if unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR::null(),
            None,
            Some(&mut kind),
            None,
            Some(&mut length),
        )
    } != ERROR_SUCCESS
        || !matches!(kind, REG_SZ | REG_EXPAND_SZ)
        || length == 0
        || length as usize > MAX_VALUE_BYTES
    {
        return None;
    }
    let expected_kind = kind;
    let mut bytes = vec![0u8; length as usize];
    if unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR::null(),
            None,
            Some(&mut kind),
            Some(bytes.as_mut_ptr()),
            Some(&mut length),
        )
    } != ERROR_SUCCESS
        || kind != expected_kind
        || length as usize > bytes.len()
    {
        return None;
    }
    bytes.truncate(length as usize);
    decode(kind.0, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn file(dir: &std::path::Path, name: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, b"synthetic icon locator only").unwrap();
        path.to_string_lossy().into_owned()
    }
    #[test]
    fn observed_artwork_wins_and_registered_fallbacks_use_user_before_machine() {
        let dir = tempfile::tempdir().unwrap();
        let chrome = file(dir.path(), "chrome.exe");
        let edge = file(dir.path(), "msedge.exe");
        let mut calls = Vec::new();
        let result = supplement(
            HashMap::from([(Browser::Chrome, chrome.clone())]),
            |scope, exe| {
                calls.push((scope, exe.to_owned()));
                if exe == "msedge.exe" && scope == Scope::User32 {
                    Some(format!("\"{edge}\""))
                } else {
                    None
                }
            },
        );
        assert_eq!(result[&Browser::Chrome], chrome);
        assert_eq!(result[&Browser::Edge], edge);
        assert!(!result.contains_key(&Browser::Firefox));
        assert!(calls.iter().all(|(_, e)| e != "chrome.exe"));
        assert_eq!(
            calls
                .iter()
                .filter(|(_, e)| e == "msedge.exe")
                .map(|(s, _)| *s)
                .collect::<Vec<_>>(),
            [Scope::User64, Scope::User32]
        );
        assert_eq!(calls.iter().filter(|(_, e)| e == "firefox.exe").count(), 4);
    }
    #[test]
    fn registered_paths_refuse_commands_other_executables_and_network_locators() {
        let dir = tempfile::tempdir().unwrap();
        let path = file(dir.path(), "chrome.exe");
        assert!(executable_resource(&path, "chrome.exe").is_some());
        for value in [
            format!("\"{path}\" --flag"),
            format!("{path},0"),
            format!("\"{path}"),
            "chrome.exe".into(),
            r"\\server\share\chrome.exe".into(),
            "https://example.com/chrome.exe".into(),
        ] {
            assert!(
                executable_resource(&value, "chrome.exe").is_none(),
                "{value}"
            );
        }
        assert!(executable_resource(&path, "firefox.exe").is_none());
    }
    #[test]
    fn registry_strings_are_bounded_and_reject_non_strings_or_malformed_utf16() {
        let bytes = |s: &str| {
            s.encode_utf16()
                .chain(Some(0))
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            decode(1, &bytes("C:\\Example\\chrome.exe")).as_deref(),
            Some("C:\\Example\\chrome.exe")
        );
        assert!(decode(3, &bytes("C:\\Example\\chrome.exe")).is_none());
        for b in [
            vec![],
            vec![1],
            vec![0, 0],
            vec![0, 0xd8],
            bytes("before\0after"),
            vec![1; MAX_VALUE_BYTES + 2],
        ] {
            assert!(decode(1, &b).is_none());
        }
    }
    #[test]
    fn an_unusable_observed_path_does_not_hide_a_registered_resource() {
        let dir = tempfile::tempdir().unwrap();
        let chrome = file(dir.path(), "chrome.exe");
        let result = supplement(
            HashMap::from([(Browser::Chrome, "C:\\missing\\chrome.exe".into())]),
            |scope, exe| (scope == Scope::Machine64 && exe == "chrome.exe").then(|| chrome.clone()),
        );
        assert_eq!(result.get(&Browser::Chrome), Some(&chrome));
    }
}
