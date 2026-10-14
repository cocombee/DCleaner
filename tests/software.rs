use dcleaner::{
    programs::{
        InstalledProgram, ProgramIdentity, RawProgramRegistration, RegistryHive, RegistryPort,
        RegistrySource, RegistrySourceRead, RegistryView,
    },
    software::{
        SoftwareError, SoftwareIdentity, SoftwarePreference, SoftwarePreferenceState,
        SoftwareSettings, SoftwareStatus, UpdateProcessPort, UpdateProcessReceipt, UpdateRequest,
        UpdateVerification, WINGET_SOURCE, WingetPort, WingetRow, build_snapshot, load_settings,
        parse_winget_table, prepare_update, save_settings, update_and_verify,
    },
};
use std::{cell::RefCell, collections::VecDeque, path::PathBuf};

fn registry_source() -> RegistrySource {
    RegistrySource {
        hive: RegistryHive::LocalMachine,
        view: RegistryView::Registry64,
    }
}

fn program(name: &str, key: &str, version: &str) -> InstalledProgram {
    InstalledProgram {
        identity: ProgramIdentity {
            hive: RegistryHive::LocalMachine,
            key_name: key.to_ascii_lowercase(),
        },
        source: registry_source(),
        display_name: name.into(),
        display_icon: None,
        publisher: Some("Example Publisher".into()),
        version: Some(version.into()),
        install_location: Some(PathBuf::from(r"C:\Apps\Example")),
        install_date: Some("20260101".into()),
        estimated_size_bytes: Some(1024),
        registered_uninstall_command: Some(r#""C:\Apps\Example\uninstall.exe" /quiet"#.into()),
        uninstall_command: None,
        uninstall_command_error: None,
        system_component: false,
        protected: false,
        no_remove: false,
    }
}

fn row(name: &str, id: &str, installed: &str, available: Option<&str>) -> WingetRow {
    WingetRow {
        name: name.into(),
        package_id: id.into(),
        installed_version: Some(installed.into()),
        available_version: available.map(str::to_owned),
        source_id: WINGET_SOURCE.into(),
    }
}

fn table(rows: &[WingetRow]) -> String {
    let mut output = format!(
        "{:<28}{:<20}{:<16}{:<16}{}\n{}\n",
        "Name",
        "Id",
        "Version",
        "Available",
        "Source",
        "-".repeat(96)
    );
    for row in rows {
        output.push_str(&format!(
            "{:<28}{:<20}{:<16}{:<16}{}\n",
            row.name,
            row.package_id,
            row.installed_version.as_deref().unwrap_or(""),
            row.available_version.as_deref().unwrap_or(""),
            row.source_id
        ));
    }
    output
}

fn current_winget_list_table(rows: &[WingetRow]) -> String {
    // Sanitized fixed-width layout captured from WinGet 1.29.380 on this host:
    // `list --source winget` prints four headers and relies on the selected
    // source argument rather than emitting a Source column.
    let mut output = format!(
        "{:<61}{:<39}{:<16}{}\n{}\n",
        "Name",
        "Id",
        "Version",
        "Available",
        "-".repeat(129)
    );
    for row in rows {
        output.push_str(&format!(
            "{:<61}{:<39}{:<16}{}\n",
            row.name,
            row.package_id,
            row.installed_version.as_deref().unwrap_or(""),
            row.available_version.as_deref().unwrap_or("")
        ));
    }
    output
}

fn matching_item(available: Option<&str>) -> dcleaner::software::SoftwareItem {
    build_snapshot(
        vec![row("Example App", "Example.App", "1.0.0", available)],
        &[program("Example App", "Example-App", "1.0.0")],
        vec![],
        &SoftwareSettings::default(),
    )
    .items
    .remove(0)
}

#[test]
fn parses_fixed_width_output_and_ignores_ansi_colors() {
    let output = format!(
        "\u{1b}[32m{}\u{1b}[0m",
        table(&[
            row("7-Zip 24.09 (x64)", "7zip.7zip", "24.09", Some("24.09.00")),
            row("Example Utility", "Vendor.Utility", "3.2", None),
        ])
    );
    let parsed = parse_winget_table(&output, WINGET_SOURCE).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].name, "7-Zip 24.09 (x64)");
    assert_eq!(parsed[0].package_id, "7zip.7zip");
    assert_eq!(parsed[0].available_version.as_deref(), Some("24.09.00"));
    assert_eq!(parsed[1].available_version, None);
}

#[test]
fn parses_current_winget_list_header_without_source_column() {
    let parsed = parse_winget_table(
        &current_winget_list_table(&[
            row("Example Utility", "Vendor.Utility", "3.2", Some("3.3")),
            row("Another Tool", "Vendor.Another", "1.0", None),
        ]),
        WINGET_SOURCE,
    )
    .unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].package_id, "Vendor.Utility");
    assert_eq!(parsed[0].source_id, WINGET_SOURCE);
    assert_eq!(parsed[0].available_version.as_deref(), Some("3.3"));
    assert_eq!(parsed[1].available_version, None);
}

#[test]
fn rejects_missing_headers_wrong_source_and_truncated_ids_but_keeps_duplicate_rows_visible() {
    assert!(matches!(
        parse_winget_table("not structured output", WINGET_SOURCE),
        Err(SoftwareError::InvalidTable(_))
    ));
    let wrong_source =
        table(&[row("Example App", "Example.App", "1", Some("2"))]).replace("winget", "msstore");
    assert!(matches!(
        parse_winget_table(&wrong_source, WINGET_SOURCE),
        Err(SoftwareError::InvalidTable(_))
    ));
    let duplicate = table(&[
        row("Example App", "Example.App", "1", Some("2")),
        row("Example App 2", "Example.App", "1", Some("2")),
    ]);
    assert_eq!(
        parse_winget_table(&duplicate, WINGET_SOURCE).unwrap().len(),
        2
    );
    let truncated = table(&[row("Example App", "Example.App...", "1", Some("2"))]);
    assert!(matches!(
        parse_winget_table(&truncated, WINGET_SOURCE),
        Err(SoftwareError::InvalidTable(_))
    ));
}

#[test]
fn exact_name_and_version_association_is_required_and_ambiguous_is_blocked() {
    let rows = vec![row("Example App", "Example.App", "1.0.0", Some("2.0.0"))];
    let none = build_snapshot(
        rows.clone(),
        &[program("Example App", "Example-App", "9.9")],
        vec![],
        &SoftwareSettings::default(),
    );
    assert_eq!(none.items[0].status, SoftwareStatus::Unmatched);
    assert!(!none.items[0].can_update());
    assert!(prepare_update(&none.items[0]).is_err());

    let ambiguous = build_snapshot(
        rows,
        &[
            program("Example App", "Example-App-A", "1.0.0"),
            program("Example App", "Example-App-B", "1.0.0"),
        ],
        vec![],
        &SoftwareSettings::default(),
    );
    assert_eq!(ambiguous.items[0].status, SoftwareStatus::Unmatched);
    assert!(!ambiguous.items[0].can_update());
}

#[test]
fn current_and_outdated_statuses_follow_available_version() {
    assert_eq!(
        matching_item(Some("2.0.0")).status,
        SoftwareStatus::UpdateAvailable
    );
    assert_eq!(matching_item(None).status, SoftwareStatus::Current);
}

#[test]
fn skip_is_pinned_to_one_offered_version_while_ignore_is_reversible() {
    let item = matching_item(Some("2.0.0"));
    let identity = item.identity.clone().unwrap();
    let mut settings = SoftwareSettings::default();
    settings
        .set(SoftwarePreference {
            identity: identity.clone(),
            state: SoftwarePreferenceState::SkipVersion,
            skipped_version: Some("2.0.0".into()),
        })
        .unwrap();
    let skipped = build_snapshot(
        vec![row("Example App", "Example.App", "1.0.0", Some("2.0.0"))],
        &[program("Example App", "Example-App", "1.0.0")],
        vec![],
        &settings,
    );
    assert_eq!(skipped.items[0].status, SoftwareStatus::SkippedVersion);
    let newer = build_snapshot(
        vec![row("Example App", "Example.App", "1.0.0", Some("2.1.0"))],
        &[program("Example App", "Example-App", "1.0.0")],
        vec![],
        &settings,
    );
    assert_eq!(newer.items[0].status, SoftwareStatus::UpdateAvailable);

    settings
        .set(SoftwarePreference {
            identity: identity.clone(),
            state: SoftwarePreferenceState::Ignored,
            skipped_version: None,
        })
        .unwrap();
    let ignored = build_snapshot(
        vec![row("Example App", "Example.App", "1.0.0", Some("2.0.0"))],
        &[program("Example App", "Example-App", "1.0.0")],
        vec![],
        &settings,
    );
    assert_eq!(ignored.items[0].status, SoftwareStatus::Ignored);
    assert!(settings.restore(&identity));
    assert_eq!(settings.preferences.len(), 0);
}

#[test]
fn settings_are_persisted_and_corrupt_bytes_are_preserved() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let item = matching_item(Some("2.0.0"));
    let mut settings = SoftwareSettings::default();
    settings
        .set(SoftwarePreference {
            identity: item.identity.unwrap(),
            state: SoftwarePreferenceState::SkipVersion,
            skipped_version: Some("2.0.0".into()),
        })
        .unwrap();
    save_settings(root, &settings).unwrap();
    assert_eq!(load_settings(root).unwrap(), settings);
    let path = root.join("software-settings.json");
    std::fs::write(&path, b"{broken").unwrap();
    assert!(load_settings(root).is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"{broken");
}

#[test]
fn prepare_update_rejects_protected_and_self_update() {
    let mut protected = matching_item(Some("2.0.0"));
    protected.registration.as_mut().unwrap().protected = true;
    assert!(prepare_update(&protected).is_err());

    let self_program = program("DCleaner", "DCleaner", "1.0.0");
    let self_item = build_snapshot(
        vec![row("DCleaner", "Example.DCleaner", "1.0.0", Some("2.0.0"))],
        &[self_program],
        vec![],
        &SoftwareSettings::default(),
    )
    .items
    .remove(0);
    assert!(prepare_update(&self_item).is_err());
}

#[derive(Default)]
struct FakeRegistry {
    reads: RefCell<VecDeque<Result<Option<RawProgramRegistration>, String>>>,
}

impl RegistryPort for FakeRegistry {
    fn read_source(&self, _source: RegistrySource) -> Result<RegistrySourceRead, String> {
        Ok(RegistrySourceRead::default())
    }

    fn read_registration(
        &self,
        _source: RegistrySource,
        _identity: &ProgramIdentity,
    ) -> Result<Option<RawProgramRegistration>, String> {
        self.reads
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Ok(None))
    }
}

fn raw_registration(version: &str) -> RawProgramRegistration {
    RawProgramRegistration {
        key_name: "example-app".into(),
        display_name: Some("Example App".into()),
        display_version: Some(version.into()),
        ..Default::default()
    }
}

#[derive(Default)]
struct FakeWinget {
    listings: RefCell<VecDeque<Result<Vec<WingetRow>, SoftwareError>>>,
}

impl WingetPort for FakeWinget {
    fn list(&self) -> Result<Vec<WingetRow>, SoftwareError> {
        self.listings
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Err(SoftwareError::InvalidTable("fake listing exhausted".into())))
    }
}

struct FakeProcess {
    runs: usize,
    result: Result<UpdateProcessReceipt, String>,
}

impl Default for FakeProcess {
    fn default() -> Self {
        Self {
            runs: 0,
            result: Err("fake update process is not configured".into()),
        }
    }
}

impl UpdateProcessPort for FakeProcess {
    fn run(&mut self, _request: &UpdateRequest) -> Result<UpdateProcessReceipt, String> {
        self.runs += 1;
        self.result.clone()
    }
}

fn update_request() -> UpdateRequest {
    let item = matching_item(Some("2.0.0"));
    prepare_update(&item).unwrap()
}

#[test]
fn update_revalidates_exact_registration_and_catalog_before_process_handoff() {
    let request = update_request();
    let registry = FakeRegistry {
        reads: RefCell::new(VecDeque::from([Ok(Some(raw_registration("1.0.0")))])),
    };
    let winget = FakeWinget {
        listings: RefCell::new(VecDeque::from([Ok(vec![row(
            "Example App",
            "Example.App",
            "1.0.0",
            Some("2.1.0"),
        )])])),
    };
    let mut process = FakeProcess::default();
    assert!(update_and_verify(&request, &registry, &winget, &mut process).is_err());
    assert_eq!(process.runs, 0);
}

#[test]
fn update_launch_is_not_success_until_both_sources_verify_target_version() {
    let request = update_request();
    let registry = FakeRegistry {
        reads: RefCell::new(VecDeque::from([
            Ok(Some(raw_registration("1.0.0"))),
            Ok(Some(raw_registration("2.0.0"))),
        ])),
    };
    let winget = FakeWinget {
        listings: RefCell::new(VecDeque::from([
            Ok(vec![row(
                "Example App",
                "Example.App",
                "1.0.0",
                Some("2.0.0"),
            )]),
            Ok(vec![row("Example App", "Example.App", "2.0.0", None)]),
        ])),
    };
    let mut process = FakeProcess {
        runs: 0,
        result: Ok(UpdateProcessReceipt {
            process_id: 42,
            exit_code: Some(0),
            wait_error: None,
        }),
    };
    let receipt = update_and_verify(&request, &registry, &winget, &mut process).unwrap();
    assert_eq!(process.runs, 1);
    assert_eq!(receipt.verification, UpdateVerification::Verified);
    assert_eq!(receipt.journal_state(), "verified");
}

#[test]
fn zero_process_exit_with_old_versions_is_uncertain_not_verified() {
    let request = update_request();
    let registry = FakeRegistry {
        reads: RefCell::new(VecDeque::from([
            Ok(Some(raw_registration("1.0.0"))),
            Ok(Some(raw_registration("1.0.0"))),
        ])),
    };
    let winget = FakeWinget {
        listings: RefCell::new(VecDeque::from([
            Ok(vec![row(
                "Example App",
                "Example.App",
                "1.0.0",
                Some("2.0.0"),
            )]),
            Ok(vec![row(
                "Example App",
                "Example.App",
                "1.0.0",
                Some("2.0.0"),
            )]),
        ])),
    };
    let mut process = FakeProcess {
        runs: 0,
        result: Ok(UpdateProcessReceipt {
            process_id: 43,
            exit_code: Some(0),
            wait_error: None,
        }),
    };
    let receipt = update_and_verify(&request, &registry, &winget, &mut process).unwrap();
    assert_eq!(receipt.verification, UpdateVerification::Uncertain);
    assert_eq!(receipt.journal_state(), "uncertain");
}

#[test]
fn software_identity_includes_registry_view_and_package_source() {
    let item = matching_item(Some("2.0.0"));
    let identity = item.identity.unwrap();
    let mut other_view = identity.clone();
    other_view.registry_source.view = RegistryView::Registry32;
    assert_ne!(identity.stable_key(), other_view.stable_key());
    let mut other_source = identity.clone();
    other_source.source_id = "msstore".into();
    assert_ne!(identity.stable_key(), other_source.stable_key());
    assert_ne!(
        identity.stable_key(),
        SoftwareIdentity {
            package_id: "different.package".into(),
            ..identity.clone()
        }
        .stable_key()
    );
}

#[test]
fn update_request_cannot_be_retargeted_to_shell_or_other_source() {
    let mut request = update_request();
    request.package_id = "Example.App && powershell".into();
    assert!(matches!(
        update_and_verify(
            &request,
            &FakeRegistry::default(),
            &FakeWinget::default(),
            &mut FakeProcess::default()
        ),
        Err(SoftwareError::InvalidIdentity(_))
    ));
    let mut request = update_request();
    request.source_id = "msstore".into();
    assert!(prepare_update(&matching_item(Some("2.0.0"))).is_ok());
    assert!(matches!(
        update_and_verify(
            &request,
            &FakeRegistry::default(),
            &FakeWinget::default(),
            &mut FakeProcess::default()
        ),
        Err(SoftwareError::InvalidIdentity(_))
    ));
}

#[test]
fn request_is_bound_to_the_exact_registration_source() {
    let mut request = update_request();
    request.identity.registry_source.view = RegistryView::Registry32;
    assert!(matches!(
        update_and_verify(
            &request,
            &FakeRegistry::default(),
            &FakeWinget::default(),
            &mut FakeProcess::default()
        ),
        Err(SoftwareError::UpdateBlocked(_))
    ));
}

#[cfg(windows)]
#[test]
#[ignore = "read-only smoke test against the machine's explicit WinGet source"]
fn readonly_winget_inventory_smoke_reports_only_a_count() {
    let rows = dcleaner::software::NativeWinget.list().unwrap();
    assert!(rows.len() <= 1_000);
    eprintln!("WinGet read-only inventory rows: {}", rows.len());
}
