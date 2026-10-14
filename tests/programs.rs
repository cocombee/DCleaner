use dcleaner::programs::{
    InstalledProgram, InventorySnapshot, ProcessPort, ProgramIdentity, RawProgramRegistration,
    RegistryEntryError, RegistryHive, RegistryPort, RegistrySource, RegistrySourceRead,
    RegistryView, UninstallCommand, UninstallHandoffError, enumerate_from, handoff_uninstall,
    installed_programs, parse_uninstall_command, prepare_uninstall,
};
use std::collections::HashMap;

#[derive(Default)]
struct FakeRegistry {
    sources: HashMap<RegistrySource, Result<RegistrySourceRead, String>>,
    registrations: HashMap<(RegistrySource, ProgramIdentity), RawProgramRegistration>,
}

impl FakeRegistry {
    fn add(&mut self, source: RegistrySource, registration: RawProgramRegistration) {
        let identity = ProgramIdentity {
            hive: source.hive,
            key_name: registration.key_name.to_lowercase(),
        };
        self.sources
            .entry(source)
            .or_insert_with(|| Ok(RegistrySourceRead::default()))
            .as_mut()
            .unwrap()
            .registrations
            .push(registration.clone());
        self.registrations.insert((source, identity), registration);
    }

    fn set_source_error(&mut self, source: RegistrySource, message: &str) {
        self.sources.insert(source, Err(message.into()));
    }
}

impl RegistryPort for FakeRegistry {
    fn read_source(&self, source: RegistrySource) -> Result<RegistrySourceRead, String> {
        self.sources
            .get(&source)
            .cloned()
            .unwrap_or_else(|| Ok(RegistrySourceRead::default()))
    }

    fn read_registration(
        &self,
        source: RegistrySource,
        identity: &ProgramIdentity,
    ) -> Result<Option<RawProgramRegistration>, String> {
        Ok(self.registrations.get(&(source, identity.clone())).cloned())
    }
}

#[derive(Default)]
struct FakeProcess {
    commands: Vec<UninstallCommand>,
}

impl ProcessPort for FakeProcess {
    fn launch(&mut self, command: &UninstallCommand) -> Result<u32, String> {
        self.commands.push(command.clone());
        Ok(4321)
    }
}

fn source(hive: RegistryHive, view: RegistryView) -> RegistrySource {
    RegistrySource { hive, view }
}

fn registration(key_name: &str, display_name: &str, uninstall: &str) -> RawProgramRegistration {
    RawProgramRegistration {
        key_name: key_name.into(),
        display_name: Some(display_name.into()),
        display_icon: Some(r#"C:\Example\App\Example.exe,0"#.into()),
        publisher: Some("Example Publisher".into()),
        display_version: Some("1.2.3".into()),
        install_location: Some(r"C:\Example\App".into()),
        install_date: Some("20261015".into()),
        estimated_size_kib: Some(2048),
        uninstall_string: Some(uninstall.into()),
        ..Default::default()
    }
}

fn one_program(registry: &FakeRegistry) -> InstalledProgram {
    let InventorySnapshot { programs, errors } = enumerate_from(registry);
    assert!(errors.is_empty(), "unexpected inventory errors: {errors:?}");
    assert_eq!(programs.len(), 1);
    programs.into_iter().next().unwrap()
}

#[test]
fn parses_quoted_executable_and_windows_escaped_arguments() {
    let parsed = parse_uninstall_command(
        r#""C:\Tools\uninstall.exe" /quiet "name with space" "say \"hello\"""#,
    )
    .unwrap();
    assert_eq!(parsed.executable, r"C:\Tools\uninstall.exe");
    assert_eq!(
        parsed.arguments,
        ["/quiet", "name with space", "say \"hello\""]
    );
}

#[test]
fn resolves_an_unquoted_executable_path_with_spaces_from_the_filesystem() {
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("Vendor Suite").join("uninstall.exe");
    std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
    std::fs::write(&executable, b"test fixture; never executed").unwrap();
    let raw = format!("{} /silent", executable.display());

    let parsed = parse_uninstall_command(&raw).unwrap();
    assert_eq!(parsed.executable, executable.to_string_lossy());
    assert_eq!(parsed.arguments, ["/silent"]);
}

#[test]
fn rejects_shell_handoffs_and_script_commands() {
    assert!(parse_uninstall_command(r#"cmd.exe /c "echo unsafe""#).is_err());
    assert!(parse_uninstall_command(r#"powershell.exe -Command "Write-Host unsafe""#).is_err());
    assert!(parse_uninstall_command(r#""C:\Vendor\remove.cmd" /quiet"#).is_err());
}

#[test]
fn inventory_deduplicates_registry_identity_not_display_name() {
    let mut registry = FakeRegistry::default();
    registry.add(
        source(RegistryHive::LocalMachine, RegistryView::Registry64),
        registration(
            "{PRODUCT-GUID}",
            "Example Suite",
            r#""C:\App\uninstall.exe" /64"#,
        ),
    );
    registry.add(
        source(RegistryHive::LocalMachine, RegistryView::Registry32),
        registration(
            "{product-guid}",
            "Example Suite (duplicate view)",
            r#""C:\App\uninstall.exe" /32"#,
        ),
    );
    registry.add(
        source(RegistryHive::CurrentUser, RegistryView::Registry64),
        registration(
            "Example Suite User",
            "Example Suite",
            r#"uninstall.exe /user"#,
        ),
    );

    let snapshot = enumerate_from(&registry);
    assert!(snapshot.errors.is_empty());
    assert_eq!(snapshot.programs.len(), 2);
    assert_eq!(
        snapshot
            .programs
            .iter()
            .filter(|program| program.display_name == "Example Suite")
            .count(),
        2
    );
    let product = snapshot
        .programs
        .iter()
        .find(|program| program.identity.key_name == "{product-guid}")
        .unwrap();
    assert_eq!(product.source.view, RegistryView::Registry64);
    assert_eq!(product.estimated_size_bytes, Some(2 * 1024 * 1024));
    assert_eq!(
        product.display_icon.as_deref(),
        Some(r#"C:\Example\App\Example.exe,0"#)
    );
}

#[test]
fn missing_saved_icon_metadata_defaults_to_none() {
    let mut registry = FakeRegistry::default();
    registry.add(
        source(RegistryHive::CurrentUser, RegistryView::Registry64),
        registration("app-guid", "Example App", r#"uninstall.exe /remove"#),
    );
    let program = one_program(&registry);
    let mut saved = serde_json::to_value(program).unwrap();
    saved.as_object_mut().unwrap().remove("display_icon");

    let restored: InstalledProgram = serde_json::from_value(saved).unwrap();
    assert_eq!(restored.display_icon, None);
}

#[test]
fn inventory_keeps_other_sources_when_one_registry_view_fails() {
    let mut registry = FakeRegistry::default();
    let available = source(RegistryHive::CurrentUser, RegistryView::Registry64);
    let failed = source(RegistryHive::LocalMachine, RegistryView::Registry32);
    registry.add(
        available,
        registration("app-guid", "Example App", r#"uninstall.exe /remove"#),
    );
    registry.set_source_error(failed, "access denied");

    let snapshot = enumerate_from(&registry);
    assert_eq!(snapshot.programs.len(), 1);
    assert_eq!(snapshot.errors.len(), 1);
    assert_eq!(snapshot.errors[0].source, failed);
    assert_eq!(snapshot.errors[0].message, "access denied");
}

#[test]
fn exposes_system_and_current_application_removal_blocks() {
    let mut registry = FakeRegistry::default();
    let hklm = source(RegistryHive::LocalMachine, RegistryView::Registry64);
    let mut system = registration("windows-component", "Windows Component", "remove.exe");
    system.system_component = true;
    registry.add(hklm, system);
    registry.add(
        source(RegistryHive::CurrentUser, RegistryView::Registry64),
        registration("dcleaner", "DCleaner", "remove.exe"),
    );

    let snapshot = enumerate_from(&registry);
    let component = snapshot
        .programs
        .iter()
        .find(|program| program.display_name == "Windows Component")
        .unwrap();
    assert!(component.system_component);
    assert!(!component.can_uninstall());
    assert!(
        component
            .removal_block_reasons()
            .contains(&dcleaner::programs::RemovalBlockReason::SystemComponent)
    );
    let app = snapshot
        .programs
        .iter()
        .find(|program| program.display_name == "DCleaner")
        .unwrap();
    assert!(
        app.removal_block_reasons()
            .contains(&dcleaner::programs::RemovalBlockReason::CurrentApplication)
    );
    assert!(prepare_uninstall(app).is_err());
}

#[test]
fn handoff_rechecks_exact_registration_and_uses_a_process_port() {
    let selected_source = source(RegistryHive::CurrentUser, RegistryView::Registry64);
    let raw = registration(
        "example-app",
        "Example App",
        r#""C:\Example\uninstall.exe" /quiet"#,
    );
    let mut registry = FakeRegistry::default();
    registry.add(selected_source, raw);
    let program = one_program(&registry);
    let request = prepare_uninstall(&program).unwrap();
    let mut process = FakeProcess::default();

    let receipt = handoff_uninstall(&request, &registry, &mut process).unwrap();
    assert_eq!(receipt.process_id, 4321);
    assert_eq!(receipt.request_id, request.request_id);
    assert_eq!(process.commands.len(), 1);
    assert_eq!(process.commands[0].arguments, ["/quiet"]);
}

#[test]
fn stale_command_is_rejected_before_process_launch() {
    let selected_source = source(RegistryHive::CurrentUser, RegistryView::Registry64);
    let mut registry = FakeRegistry::default();
    registry.add(
        selected_source,
        registration(
            "example-app",
            "Example App",
            r#""C:\Example\uninstall.exe" /quiet"#,
        ),
    );
    let program = one_program(&registry);
    let request = prepare_uninstall(&program).unwrap();
    registry.registrations.insert(
        (selected_source, program.identity.clone()),
        registration(
            "example-app",
            "Example App",
            r#""C:\Example\other.exe" /quiet"#,
        ),
    );
    let mut process = FakeProcess::default();

    assert_eq!(
        handoff_uninstall(&request, &registry, &mut process).unwrap_err(),
        UninstallHandoffError::CommandChanged
    );
    assert!(process.commands.is_empty());
}

#[test]
fn revalidated_protection_prevents_process_launch() {
    let selected_source = source(RegistryHive::CurrentUser, RegistryView::Registry64);
    let mut registry = FakeRegistry::default();
    registry.add(
        selected_source,
        registration("example-app", "Example App", "uninstall.exe /quiet"),
    );
    let program = one_program(&registry);
    let request = prepare_uninstall(&program).unwrap();
    let mut became_protected = registration("example-app", "Example App", "uninstall.exe /quiet");
    became_protected.protected = true;
    registry
        .registrations
        .insert((selected_source, program.identity), became_protected);
    let mut process = FakeProcess::default();

    assert!(matches!(
        handoff_uninstall(&request, &registry, &mut process),
        Err(UninstallHandoffError::Blocked(_))
    ));
    assert!(process.commands.is_empty());
}

#[test]
fn entry_errors_can_be_reported_alongside_valid_registrations() {
    let selected_source = source(RegistryHive::CurrentUser, RegistryView::Registry64);
    let mut registry = FakeRegistry::default();
    registry.add(
        selected_source,
        registration("example-app", "Example App", "uninstall.exe"),
    );
    registry.sources.insert(
        selected_source,
        Ok(RegistrySourceRead {
            registrations: vec![registration("example-app", "Example App", "uninstall.exe")],
            errors: vec![RegistryEntryError {
                key_name: Some("unreadable".into()),
                message: "one subkey could not be read".into(),
            }],
        }),
    );

    let snapshot: InventorySnapshot = enumerate_from(&registry);
    assert_eq!(snapshot.programs.len(), 1);
    assert_eq!(snapshot.errors.len(), 1);
    assert_eq!(snapshot.errors[0].key_name.as_deref(), Some("unreadable"));
}

#[cfg(windows)]
#[test]
#[ignore = "Manual read-only Windows smoke check; outputs the inventory count only."]
fn native_inventory_smoke_reports_count_only() {
    let snapshot = installed_programs().expect("Windows native inventory adapter is available");
    println!("native_read_only_program_count={}", snapshot.programs.len());
}
