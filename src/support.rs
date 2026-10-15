//! Fixed support destinations and a deliberately small diagnostic export.
//!
//! Browser success means only that the platform accepted the handoff request;
//! it does not confirm that a browser opened or loaded the destination.

use serde::Serialize;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::{fs::OpenOptions, io::Write, path::Path};

const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;
const HELP_CENTRE_URL: &str =
    "https://github.com/cocombee/DCleaner/blob/main/docs/PLAN.md#user-guide";
const CONTACT_SUPPORT_URL: &str = "https://github.com/cocombee/DCleaner/issues";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Destination {
    HelpCentre,
    ContactSupport,
}

impl Destination {
    pub const fn url(self) -> &'static str {
        match self {
            Self::HelpCentre => HELP_CENTRE_URL,
            Self::ContactSupport => CONTACT_SUPPORT_URL,
        }
    }
}

/// A small seam for testing destination selection without launching a browser.
pub trait BrowserPort {
    fn open(&mut self, url: &'static str) -> Result<(), String>;
}

/// An OS handoff acknowledgement; it says nothing about webpage loading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserHandoff {
    pub destination: Destination,
    pub url: &'static str,
}

/// Requests an operating-system browser handoff to one of the fixed destinations.
pub fn open(
    destination: Destination,
    port: &mut impl BrowserPort,
) -> Result<BrowserHandoff, String> {
    let url = destination.url();
    port.open(url)?;
    Ok(BrowserHandoff { destination, url })
}

/// Requests the fixed destination through the native platform browser adapter.
pub fn open_native(destination: Destination) -> Result<BrowserHandoff, String> {
    open(destination, &mut NativeBrowser)
}

/// Production browser adapter. Kept crate-visible so callers choose a fixed
/// destination through open instead of supplying a URL.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NativeBrowser;

impl BrowserPort for NativeBrowser {
    fn open(&mut self, url: &'static str) -> Result<(), String> {
        native_handoff(url)
    }
}

#[cfg(windows)]
fn native_handoff(url: &'static str) -> Result<(), String> {
    use windows::{
        Win32::{
            Foundation::HINSTANCE,
            UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
        },
        core::{PCWSTR, w},
    };

    let wide_url: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    let result: HINSTANCE = unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            PCWSTR(wide_url.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if result.0 as isize <= 32 {
        Err("Windows did not accept the browser handoff request.".into())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn native_handoff(url: &'static str) -> Result<(), String> {
    let status = Command::new("/usr/bin/open")
        .arg(url)
        .status()
        .map_err(|error| format!("macOS could not accept the browser handoff request: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "macOS rejected the browser handoff request with status {status}."
        ))
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn native_handoff(_url: &'static str) -> Result<(), String> {
    Err("Browser handoff is unavailable on this platform.".into())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DiagnosticReport {
    schema: u32,
    product: &'static str,
    version: &'static str,
    operating_system: &'static str,
    architecture: &'static str,
    generated_at_utc: String,
    preferences_available: bool,
    history_available: bool,
}

impl DiagnosticReport {
    /// Constructs the complete report from availability flags only.
    pub fn new(preferences_available: bool, history_available: bool) -> Self {
        Self {
            schema: 1,
            product: "DCleaner",
            version: env!("CARGO_PKG_VERSION"),
            operating_system: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            generated_at_utc: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            preferences_available,
            history_available,
        }
    }

    /// Encodes the full, fixed-schema report or fails; output is never truncated.
    pub fn to_json(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("Diagnostic report could not be encoded: {error}"))?;
        if bytes.len() > MAX_DIAGNOSTIC_BYTES {
            return Err("Diagnostic report exceeded its safe size limit.".into());
        }
        Ok(bytes)
    }
}

/// Exports a new report file without replacing an existing path.
///
/// On a write or sync failure, the newly created file may remain partial; this
/// function deliberately does not delete it or retry the export.
pub fn export_new(path: &Path, report: &DiagnosticReport) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("Choose an absolute destination for the diagnostic export.".into());
    }
    let bytes = report.to_json()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!("Diagnostic export could not create a new file; existing files were preserved: {error}")
        })?;
    file.write_all(&bytes).map_err(|error| {
        format!(
            "Diagnostic export did not complete; a partial newly created file may remain: {error}"
        )
    })?;
    file.sync_all().map_err(|error| {
        format!("Diagnostic export could not be synced; a partial newly created file may remain: {error}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};
    use tempfile::tempdir;

    #[derive(Default)]
    struct FakeBrowser {
        opened: Vec<&'static str>,
        failure: Option<String>,
    }

    impl BrowserPort for FakeBrowser {
        fn open(&mut self, url: &'static str) -> Result<(), String> {
            self.opened.push(url);
            match &self.failure {
                Some(message) => Err(message.clone()),
                None => Ok(()),
            }
        }
    }

    #[test]
    fn destinations_use_only_the_fixed_urls_and_return_handoff_acknowledgements() {
        let mut browser = FakeBrowser::default();
        let help = open(Destination::HelpCentre, &mut browser).unwrap();
        let contact = open(Destination::ContactSupport, &mut browser).unwrap();

        assert_eq!(help.destination, Destination::HelpCentre);
        assert_eq!(help.url, HELP_CENTRE_URL);
        assert_eq!(contact.destination, Destination::ContactSupport);
        assert_eq!(contact.url, CONTACT_SUPPORT_URL);
        assert_eq!(browser.opened, [HELP_CENTRE_URL, CONTACT_SUPPORT_URL]);
    }

    #[test]
    fn browser_failure_returns_no_success_acknowledgement() {
        let mut browser = FakeBrowser {
            opened: Vec::new(),
            failure: Some("fixture handoff failure".into()),
        };

        let error = open(Destination::HelpCentre, &mut browser).unwrap_err();
        assert_eq!(error, "fixture handoff failure");
        assert!(!browser.opened.is_empty());
    }

    #[test]
    fn report_has_only_the_fixed_non_sensitive_fields_and_is_complete() {
        let report = DiagnosticReport::new(true, false);
        let bytes = report.to_json().unwrap();
        assert!(bytes.len() <= MAX_DIAGNOSTIC_BYTES);

        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let object = value.as_object().unwrap();
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "architecture",
                "generated_at_utc",
                "history_available",
                "operating_system",
                "preferences_available",
                "product",
                "schema",
                "version",
            ]
        );
        assert_eq!(object["schema"], 1);
        assert_eq!(object["product"], "DCleaner");
        assert_eq!(object["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(object["operating_system"], std::env::consts::OS);
        assert_eq!(object["architecture"], std::env::consts::ARCH);
        assert_eq!(object["preferences_available"], true);
        assert_eq!(object["history_available"], false);
        chrono::DateTime::parse_from_rfc3339(object["generated_at_utc"].as_str().unwrap()).unwrap();
    }

    #[test]
    fn export_creates_a_new_complete_file_and_preserves_existing_bytes() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("support-report.json");
        let report = DiagnosticReport::new(false, true);
        export_new(&destination, &report).unwrap();

        let exported = fs::read(&destination).unwrap();
        assert_eq!(exported, report.to_json().unwrap());
        let parsed: serde_json::Value = serde_json::from_slice(&exported).unwrap();
        assert_eq!(parsed["preferences_available"], false);
        assert_eq!(parsed["history_available"], true);

        let before = b"preserve this existing file";
        fs::write(&destination, before).unwrap();
        assert!(export_new(&destination, &report).is_err());
        assert_eq!(fs::read(&destination).unwrap(), before);
    }

    #[test]
    fn export_rejects_relative_destinations_without_creating_files() {
        let report = DiagnosticReport::new(false, false);
        let relative = PathBuf::from(format!(
            "relative-support-report-{}.json",
            uuid::Uuid::new_v4()
        ));
        assert!(export_new(&relative, &report).is_err());
        assert!(!relative.exists());
    }
}
