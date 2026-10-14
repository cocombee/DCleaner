use dcleaner::startup::{
    ChangeOutcome, ContextMenuVerbSnapshot, EnabledState, EntryIdentity, InventoryQuality,
    NativeState, ObservedState, RegistryHive, RegistryValueSnapshot, ServiceConfigSnapshot,
    SourceOutcome, SourceState, StartupErrorKind, StartupFolderFileSnapshot, StartupFolderSnapshot,
    StartupId, StartupInventory, StartupManager, StartupPlatform, StartupSection,
};
use std::collections::HashMap;

fn hresult_code(text: &str) -> Option<u32> {
    let bytes = text.as_bytes();
    for index in 0..bytes.len().saturating_sub(9) {
        if &bytes[index..index + 2] == b"0x" {
            let digits = &bytes[index + 2..index + 10];
            if digits.iter().all(u8::is_ascii_hexdigit) {
                let digits = std::str::from_utf8(digits).ok()?;
                return u32::from_str_radix(digits, 16).ok();
            }
        }
    }
    None
}

#[derive(Default)]
struct FakePlatform {
    states: HashMap<StartupId, ObservedState>,
    inventory: Option<StartupInventory>,
    writes: usize,
}

impl StartupPlatform for FakePlatform {
    fn inventory(&mut self, section: StartupSection) -> StartupInventory {
        self.inventory.clone().unwrap_or_else(|| StartupInventory {
            section,
            quality: InventoryQuality::Unavailable,
            entries: vec![],
            sources: vec![SourceOutcome {
                source: "fake source".into(),
                state: SourceState::Inaccessible {
                    reason: "permission denied".into(),
                },
            }],
        })
    }

    fn observe(
        &mut self,
        id: &StartupId,
    ) -> Result<ObservedState, dcleaner::startup::StartupError> {
        self.states.get(id).cloned().ok_or_else(|| {
            dcleaner::startup::StartupError::new(StartupErrorKind::UnknownId, "unknown id")
        })
    }

    fn compare_and_set(
        &mut self,
        id: &StartupId,
        expected: &ObservedState,
        desired: &ObservedState,
    ) -> Result<(), dcleaner::startup::StartupError> {
        let current = self.observe(id)?;
        if current != *expected {
            return Err(dcleaner::startup::StartupError::new(
                StartupErrorKind::ChangedSinceReview,
                "changed in fake backend",
            ));
        }
        self.states.insert(id.clone(), desired.clone());
        self.writes += 1;
        Ok(())
    }
}

fn run_state() -> ObservedState {
    let identity = EntryIdentity::StartupRunValue {
        hive: RegistryHive::CurrentUser,
        key: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
        value_name: "SampleApp".into(),
        approval_hive: RegistryHive::CurrentUser,
        approval_key: r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
            .into(),
    };
    let id = StartupId::for_identity(&identity);
    ObservedState {
        id,
        identity,
        enabled: EnabledState::Enabled,
        native: NativeState::StartupRunValue {
            value: RegistryValueSnapshot {
                value_type: 1,
                data: "C:\\Apps\\Sample.exe\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            },
            approval: None,
        },
    }
}

fn task_state(xml: &str, enabled: bool) -> ObservedState {
    let identity = EntryIdentity::ScheduledTask {
        path: r"\Company\SampleTask".into(),
    };
    ObservedState {
        id: StartupId::for_identity(&identity),
        identity,
        enabled: if enabled {
            EnabledState::Enabled
        } else {
            EnabledState::Disabled
        },
        native: NativeState::ScheduledTask {
            xml: Some(xml.into()),
        },
    }
}

fn service_state(start_type: u32) -> ObservedState {
    let identity = EntryIdentity::WindowsService {
        name: "SampleService".into(),
    };
    ObservedState {
        id: StartupId::for_identity(&identity),
        identity,
        enabled: if start_type == 4 {
            EnabledState::Disabled
        } else {
            EnabledState::Enabled
        },
        native: NativeState::WindowsService {
            config: ServiceConfigSnapshot {
                service_type: 0x10,
                start_type,
                error_control: 1,
                binary_path: "C:\\Apps\\service.exe".into(),
                load_order_group: String::new(),
                dependencies: vec![],
                service_start_name: "LocalSystem".into(),
                display_name: "Sample service".into(),
            },
        },
    }
}

fn startup_folder_state(enabled: bool) -> ObservedState {
    let identity = EntryIdentity::StartupFolderItem {
        path: r"C:\Users\Example\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Sample.lnk".into(),
    };
    ObservedState {
        id: StartupId::for_identity(&identity),
        identity,
        enabled: if enabled {
            EnabledState::Enabled
        } else {
            EnabledState::Disabled
        },
        native: NativeState::StartupFolderItem {
            snapshot: StartupFolderSnapshot {
                approval: (!enabled).then(|| RegistryValueSnapshot {
                    value_type: 3,
                    data: vec![3, 0, 0, 0, 0, 0, 0, 0],
                }),
                file: StartupFolderFileSnapshot {
                    volume_serial: 7,
                    file_index: 42,
                    file_size: 512,
                    last_write_time: 1234,
                    attributes: 0x20,
                },
            },
        },
    }
}

fn common_startup_folder_state_disabled() -> ObservedState {
    let identity = EntryIdentity::StartupFolderItem {
        path: r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\AudientAppLauncher Autostart.lnk".into(),
    };
    ObservedState {
        id: StartupId::for_identity(&identity),
        identity,
        enabled: EnabledState::Disabled,
        native: NativeState::StartupFolderItem {
            snapshot: StartupFolderSnapshot {
                approval: Some(RegistryValueSnapshot {
                    value_type: 3,
                    data: vec![3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                }),
                file: StartupFolderFileSnapshot {
                    volume_serial: 12,
                    file_index: 456,
                    file_size: 512,
                    last_write_time: 7890,
                    attributes: 0x20,
                },
            },
        },
    }
}

fn context_verb_state(enabled: bool) -> ObservedState {
    let identity = EntryIdentity::ContextMenuRegistration {
        hive: RegistryHive::CurrentUser,
        key: r"Software\Classes\*\shell".into(),
        registration: "SampleAction".into(),
    };
    ObservedState {
        id: StartupId::for_identity(&identity),
        identity,
        enabled: if enabled {
            EnabledState::Enabled
        } else {
            EnabledState::Disabled
        },
        native: NativeState::ContextMenuVerb {
            snapshot: ContextMenuVerbSnapshot {
                legacy_disable: (!enabled).then(|| RegistryValueSnapshot {
                    value_type: 1,
                    data: vec![0, 0],
                }),
                command: RegistryValueSnapshot {
                    value_type: 1,
                    data: r"C:\Apps\Verb.exe %1\0"
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect(),
                },
            },
        },
    }
}

#[test]
fn run_value_toggle_is_journalable_and_restores_exact_original_marker() {
    let before = run_state();
    let id = before.id.clone();
    let mut fake = FakePlatform::default();
    fake.states.insert(id.clone(), before.clone());
    let mut manager = StartupManager::new(fake);

    let intent = manager.prepare_change(&id, false).unwrap();
    assert_eq!(intent.before, before);
    assert_eq!(intent.expected_after.enabled, EnabledState::Disabled);
    let NativeState::StartupRunValue { value, approval } = &intent.expected_after.native else {
        panic!("expected Run registry snapshot");
    };
    assert_eq!(
        value,
        match &before.native {
            NativeState::StartupRunValue { value, .. } => value,
            _ => unreachable!(),
        }
    );
    let approval = approval
        .as_ref()
        .expect("disable marker is prepared before any write");
    assert_eq!(approval.value_type, 3);
    assert_eq!(approval.data.first(), Some(&3));

    let encoded = serde_json::to_vec(&intent).unwrap();
    let restored_intent = serde_json::from_slice(&encoded).unwrap();
    let receipt = manager.apply_intent(&restored_intent).unwrap();
    assert_eq!(receipt.outcome, ChangeOutcome::Applied);
    assert_eq!(receipt.before, before);
    assert_eq!(
        manager.restore_receipt(&receipt).unwrap().outcome,
        ChangeOutcome::Restored
    );
    assert_eq!(manager.platform().states.get(&id), Some(&before));
    assert_eq!(manager.platform().writes, 2);
}

#[test]
fn startup_change_refuses_a_value_changed_after_review() {
    let before = run_state();
    let id = before.id.clone();
    let mut fake = FakePlatform::default();
    fake.states.insert(id.clone(), before);
    let mut manager = StartupManager::new(fake);
    let intent = manager.prepare_change(&id, false).unwrap();

    let mut changed = run_state();
    let NativeState::StartupRunValue { value, .. } = &mut changed.native else {
        unreachable!()
    };
    value.data.extend([0, 0]);
    manager.platform_mut().states.insert(id, changed);

    let error = manager.apply_intent(&intent).unwrap_err();
    assert_eq!(error.kind, StartupErrorKind::ChangedSinceReview);
    assert_eq!(manager.platform().writes, 0);
}

#[test]
fn altered_durable_intent_cannot_smuggle_a_different_native_state() {
    let before = run_state();
    let id = before.id.clone();
    let mut fake = FakePlatform::default();
    fake.states.insert(id.clone(), before);
    let mut manager = StartupManager::new(fake);
    let mut intent = manager.prepare_change(&id, false).unwrap();
    let NativeState::StartupRunValue { value, .. } = &mut intent.expected_after.native else {
        unreachable!()
    };
    value.data.push(0xff);

    let error = manager.apply_intent(&intent).unwrap_err();
    assert_eq!(error.kind, StartupErrorKind::InvalidIntent);
    assert_eq!(manager.platform().writes, 0);
}

#[test]
fn restoration_refuses_a_task_definition_changed_after_the_change() {
    let before = task_state("<Task><Actions><Exec/></Actions></Task>", true);
    let id = before.id.clone();
    let mut fake = FakePlatform::default();
    fake.states.insert(id.clone(), before);
    let mut manager = StartupManager::new(fake);
    let intent = manager.prepare_change(&id, false).unwrap();
    let receipt = manager.apply_intent(&intent).unwrap();
    manager.platform_mut().states.insert(
        id,
        task_state(
            "<Task><Actions><Exec changed='yes'/></Actions></Task>",
            false,
        ),
    );

    let error = manager.restore_receipt(&receipt).unwrap_err();
    assert_eq!(error.kind, StartupErrorKind::ChangedSinceReview);
    assert_eq!(manager.platform().writes, 1);
}

#[test]
fn disabled_service_is_enabled_manually_and_restores_its_original_start_mode() {
    let before = service_state(4);
    let id = before.id.clone();
    let mut fake = FakePlatform::default();
    fake.states.insert(id.clone(), before.clone());
    let mut manager = StartupManager::new(fake);
    let intent = manager.prepare_change(&id, true).unwrap();

    let NativeState::WindowsService { config } = &intent.expected_after.native else {
        unreachable!()
    };
    assert_eq!(
        config.start_type, 3,
        "enabling a disabled service uses demand start"
    );
    let receipt = manager.apply_intent(&intent).unwrap();
    assert_eq!(receipt.after.enabled, EnabledState::Enabled);
    assert_eq!(
        manager.restore_receipt(&receipt).unwrap().outcome,
        ChangeOutcome::Restored
    );
    assert_eq!(manager.platform().states.get(&id), Some(&before));
}

#[test]
fn startup_folder_marker_toggle_preserves_exact_file_identity_and_restores() {
    let before = startup_folder_state(true);
    let id = before.id.clone();
    let mut fake = FakePlatform::default();
    fake.states.insert(id.clone(), before.clone());
    let mut manager = StartupManager::new(fake);

    let intent = manager.prepare_change(&id, false).unwrap();
    let NativeState::StartupFolderItem { snapshot } = &intent.expected_after.native else {
        panic!("expected StartupFolder marker snapshot");
    };
    assert_eq!(
        snapshot.file,
        match &before.native {
            NativeState::StartupFolderItem { snapshot } => snapshot.file.clone(),
            _ => unreachable!(),
        }
    );
    assert_eq!(snapshot.approval.as_ref().unwrap().data[0], 3);
    let receipt = manager.apply_intent(&intent).unwrap();
    assert_eq!(receipt.outcome, ChangeOutcome::Applied);
    assert_eq!(
        manager.restore_receipt(&receipt).unwrap().outcome,
        ChangeOutcome::Restored
    );
    assert_eq!(manager.platform().states.get(&id), Some(&before));
}

#[test]
fn disabled_common_startup_marker_is_authoritative_and_restores_exact_bytes() {
    let before = common_startup_folder_state_disabled();
    let id = before.id.clone();
    let mut fake = FakePlatform::default();
    fake.states.insert(id.clone(), before.clone());
    let mut manager = StartupManager::new(fake);

    let already_disabled = manager.prepare_change(&id, false).unwrap_err();
    assert_eq!(already_disabled.kind, StartupErrorKind::ChangedSinceReview);
    assert_eq!(manager.platform().writes, 0);

    let enable_intent = manager.prepare_change(&id, true).unwrap();
    let NativeState::StartupFolderItem { snapshot } = &enable_intent.expected_after.native else {
        panic!("expected StartupFolder marker snapshot");
    };
    let approval = snapshot.approval.as_ref().unwrap();
    assert_eq!(approval.data[0], 2);
    assert_eq!(&approval.data[1..], &[0; 11]);

    let receipt = manager.apply_intent(&enable_intent).unwrap();
    assert_eq!(receipt.before, before);
    assert_eq!(receipt.after.enabled, EnabledState::Enabled);
    assert_eq!(
        manager.restore_receipt(&receipt).unwrap().outcome,
        ChangeOutcome::Restored
    );
    assert_eq!(manager.platform().states.get(&id), Some(&before));
    assert_eq!(manager.platform().writes, 2);
}

#[test]
fn startup_folder_toggle_refuses_changed_file_snapshot() {
    let before = startup_folder_state(true);
    let id = before.id.clone();
    let mut fake = FakePlatform::default();
    fake.states.insert(id.clone(), before);
    let mut manager = StartupManager::new(fake);
    let intent = manager.prepare_change(&id, false).unwrap();
    let mut changed = startup_folder_state(true);
    let NativeState::StartupFolderItem { snapshot } = &mut changed.native else {
        unreachable!()
    };
    snapshot.file.file_index += 1;
    manager.platform_mut().states.insert(id, changed);

    assert_eq!(
        manager.apply_intent(&intent).unwrap_err().kind,
        StartupErrorKind::ChangedSinceReview
    );
    assert_eq!(manager.platform().writes, 0);
}

#[test]
fn static_context_verb_uses_exact_legacy_disable_receipt() {
    let before = context_verb_state(true);
    let id = before.id.clone();
    let mut fake = FakePlatform::default();
    fake.states.insert(id.clone(), before.clone());
    let mut manager = StartupManager::new(fake);

    let intent = manager.prepare_change(&id, false).unwrap();
    let NativeState::ContextMenuVerb { snapshot } = &intent.expected_after.native else {
        panic!("expected static-verb state");
    };
    assert_eq!(snapshot.legacy_disable.as_ref().unwrap().value_type, 1);
    assert_eq!(snapshot.legacy_disable.as_ref().unwrap().data, vec![0, 0]);
    assert_eq!(
        snapshot.command,
        match &before.native {
            NativeState::ContextMenuVerb { snapshot } => snapshot.command.clone(),
            _ => unreachable!(),
        }
    );
    let receipt = manager.apply_intent(&intent).unwrap();
    assert_eq!(
        manager.restore_receipt(&receipt).unwrap().outcome,
        ChangeOutcome::Restored
    );
    assert_eq!(manager.platform().states.get(&id), Some(&before));
}

#[test]
fn static_context_verb_rejects_command_changed_after_review() {
    let before = context_verb_state(true);
    let id = before.id.clone();
    let mut fake = FakePlatform::default();
    fake.states.insert(id.clone(), before);
    let mut manager = StartupManager::new(fake);
    let intent = manager.prepare_change(&id, false).unwrap();
    let mut changed = context_verb_state(true);
    let NativeState::ContextMenuVerb { snapshot } = &mut changed.native else {
        unreachable!();
    };
    snapshot.command.data.extend([65, 0]);
    manager.platform_mut().states.insert(id, changed);

    assert_eq!(
        manager.apply_intent(&intent).unwrap_err().kind,
        StartupErrorKind::ChangedSinceReview
    );
    assert_eq!(manager.platform().writes, 0);
}

#[cfg(windows)]
#[test]
#[ignore = "Read-only, Audient-specific snapshot of this Windows host; it never changes startup state."]
fn native_audient_common_startup_state_matches_raw_machine_marker() {
    use dcleaner::startup::{
        EnabledState, EntryIdentity, FieldValue, NativeState, StartupPlatform, StartupSection,
        WindowsStartupPlatform,
    };
    use std::{path::PathBuf, ptr};
    use windows::{
        Win32::{
            Foundation::ERROR_SUCCESS,
            System::Registry::{
                HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, REG_VALUE_TYPE, RegCloseKey,
                RegOpenKeyExW, RegQueryValueExW,
            },
        },
        core::PCWSTR,
    };

    const ITEM_NAME: &str = "AudientAppLauncher Autostart.lnk";
    const APPROVAL_KEY: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";

    struct ReadOnlyRegistryHandle(HKEY);
    impl Drop for ReadOnlyRegistryHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    let program_data =
        std::env::var_os("PROGRAMDATA").expect("the current Windows host has a ProgramData folder");
    let target_path = PathBuf::from(program_data)
        .join(r"Microsoft\Windows\Start Menu\Programs\Startup")
        .join(ITEM_NAME);
    assert!(
        target_path.is_file(),
        "the known Audient shortcut is absent from the common Startup folder"
    );
    let target_text = target_path.to_string_lossy().into_owned();

    let mut platform = WindowsStartupPlatform::new();
    let inventory = platform.inventory(StartupSection::StartupApps);
    let entry = inventory.entries.iter().find(|entry| {
        matches!(
            &entry.identity,
            EntryIdentity::StartupFolderItem { path }
                if path.eq_ignore_ascii_case(&target_text)
        )
    });
    let entry = entry.expect("the known Audient shortcut appears in native inventory");
    assert!(matches!(
        &entry.identity,
        EntryIdentity::StartupFolderItem { path } if path.eq_ignore_ascii_case(&target_text)
    ));
    assert!(matches!(
        &entry.program,
        FieldValue::Known { value } if value != ITEM_NAME
    ));
    assert!(matches!(
        &entry.file_path,
        FieldValue::Known { value } if !value.to_ascii_lowercase().ends_with(".lnk")
    ));
    let target_executable = match &entry.file_path {
        FieldValue::Known { value } => value,
        FieldValue::Unknown { reason } => {
            panic!("the Audient link target is unavailable: {reason}")
        }
        FieldValue::NotApplicable => panic!("the Audient link target is not applicable"),
    };
    assert!(
        PathBuf::from(target_executable).is_file(),
        "the resolved Audient target is a file"
    );
    let publisher = match &entry.publisher {
        FieldValue::Known { value } if !value.trim().is_empty() => value,
        FieldValue::Known { .. } => panic!("the Audient CompanyName resource is empty"),
        FieldValue::Unknown { reason } => {
            panic!("the Audient CompanyName metadata is unavailable: {reason}")
        }
        FieldValue::NotApplicable => panic!("the Audient publisher is not applicable"),
    };
    assert!(
        publisher.to_ascii_lowercase().contains("audient"),
        "the target CompanyName metadata identifies Audient"
    );
    let version = match &entry.version {
        FieldValue::Known { value } if !value.trim().is_empty() => value,
        FieldValue::Known { .. } => panic!("the Audient FileVersion resource is empty"),
        FieldValue::Unknown { reason } => {
            panic!("the Audient FileVersion metadata is unavailable: {reason}")
        }
        FieldValue::NotApplicable => panic!("the Audient file version is not applicable"),
    };
    assert!(!version.trim().is_empty());

    let key_name = APPROVAL_KEY
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut raw_key = HKEY(ptr::null_mut());
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key_name.as_ptr()),
            None,
            KEY_QUERY_VALUE,
            &mut raw_key,
        )
    };
    assert_eq!(
        status, ERROR_SUCCESS,
        "the machine approval key is readable"
    );
    let key = ReadOnlyRegistryHandle(raw_key);

    let value_name = ITEM_NAME.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut marker_type = REG_VALUE_TYPE(0);
    let mut marker_length = 0u32;
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(value_name.as_ptr()),
            None,
            Some(&mut marker_type),
            None,
            Some(&mut marker_length),
        )
    };
    assert_eq!(
        status, ERROR_SUCCESS,
        "the known machine approval marker exists"
    );
    let mut raw_marker = vec![0u8; marker_length as usize];
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(value_name.as_ptr()),
            None,
            Some(&mut marker_type),
            Some(raw_marker.as_mut_ptr()),
            Some(&mut marker_length),
        )
    };
    assert_eq!(
        status, ERROR_SUCCESS,
        "the known machine approval marker is readable"
    );
    raw_marker.truncate(marker_length as usize);

    assert_eq!(marker_type.0, 3, "the approval marker is REG_BINARY");
    assert_eq!(raw_marker.first(), Some(&3), "the OS marker says disabled");
    assert!(
        matches!(&entry.enabled, EnabledState::Disabled),
        "native Startup Manager state matches the disabled OS marker"
    );
    let observed = platform
        .observe(&entry.id)
        .expect("the current Audient identity can be re-observed");
    assert!(
        matches!(&observed.enabled, EnabledState::Disabled),
        "identity-specific observation matches the disabled OS marker"
    );
    let NativeState::StartupFolderItem { snapshot } = &observed.native else {
        panic!("the known item remains a Startup-folder inventory entry");
    };
    let observed_marker = snapshot
        .approval
        .as_ref()
        .expect("native inventory captured the approval marker");
    assert_eq!(observed_marker.value_type, marker_type.0);
    assert_eq!(observed_marker.data, raw_marker);
}

#[test]
fn unknown_ids_and_read_only_context_items_cannot_be_changed() {
    let mut manager = StartupManager::new(FakePlatform::default());
    let unknown = manager
        .prepare_change(&StartupId("st-sa-unknown".into()), false)
        .unwrap_err();
    assert_eq!(unknown.kind, StartupErrorKind::UnknownId);

    let identity = EntryIdentity::ContextMenuRegistration {
        hive: RegistryHive::CurrentUser,
        key: r"Software\Classes\*\shell".into(),
        registration: "SampleAction".into(),
    };
    let state = ObservedState {
        id: StartupId::for_identity(&identity),
        identity,
        enabled: EnabledState::Enabled,
        native: NativeState::ReadOnly,
    };
    let id = state.id.clone();
    let mut manager = StartupManager::new(FakePlatform {
        states: HashMap::from([(id.clone(), state)]),
        ..Default::default()
    });
    assert_eq!(
        manager.prepare_change(&id, false).unwrap_err().kind,
        StartupErrorKind::Unsupported
    );
    assert_eq!(manager.platform().writes, 0);
}

#[test]
fn unavailable_sources_remain_explicit_in_an_empty_inventory() {
    let fake = FakePlatform {
        inventory: Some(StartupInventory {
            section: StartupSection::StartupApps,
            quality: InventoryQuality::Unavailable,
            entries: vec![],
            sources: vec![SourceOutcome {
                source: "HKLM\\Software\\...\\Run".into(),
                state: SourceState::Inaccessible {
                    reason: "access denied".into(),
                },
            }],
        }),
        ..Default::default()
    };
    let mut manager = StartupManager::new(fake);
    let inventory = manager.inventory(StartupSection::StartupApps);
    assert_eq!(inventory.quality, InventoryQuality::Unavailable);
    assert!(inventory.entries.is_empty());
    assert_eq!(
        inventory.sources[0].state,
        SourceState::Inaccessible {
            reason: "access denied".into()
        }
    );
}

#[test]
fn hresult_diagnostic_extracts_only_the_numeric_status() {
    assert_eq!(
        hresult_code("Task Scheduler connection failed: HRESULT 0x80070005"),
        Some(0x80070005)
    );
    assert_eq!(hresult_code("No native HRESULT was supplied."), None);
}

#[cfg(windows)]
#[test]
#[ignore = "read-only smoke check against the current Windows startup configuration"]
fn native_inventory_smoke_reports_aggregate_counts_only() {
    use dcleaner::startup::WindowsStartupPlatform;

    let mut platform = WindowsStartupPlatform::new();
    for section in StartupSection::ALL {
        let inventory = platform.inventory(section);
        assert_eq!(inventory.section, section);
        assert!(
            !inventory.sources.is_empty(),
            "each native category should report source outcomes"
        );
        let mut read = 0usize;
        let mut absent = 0usize;
        let mut inaccessible = 0usize;
        let mut failed = 0usize;
        let mut truncated = 0usize;
        for source in &inventory.sources {
            match source.state {
                SourceState::Read { .. } => read += 1,
                SourceState::NotPresent => absent += 1,
                SourceState::Inaccessible { .. } => inaccessible += 1,
                SourceState::Failed { .. } => failed += 1,
                SourceState::Truncated { .. } => truncated += 1,
            }
        }
        if section == StartupSection::ScheduledTasks {
            let scheduled_tasks_hresult = inventory.sources.iter().find_map(|source| {
                let reason = match &source.state {
                    SourceState::Inaccessible { reason }
                    | SourceState::Failed { reason }
                    | SourceState::Truncated { reason, .. } => reason,
                    SourceState::Read { .. } | SourceState::NotPresent => return None,
                };
                hresult_code(reason)
            });
            if let Some(code) = scheduled_tasks_hresult {
                println!("scheduled_tasks_hresult=0x{code:08X}");
            }
        }
        println!(
            "{} quality={:?} items={} sources={} read={} absent={} inaccessible={} failed={} truncated={}",
            section.label(),
            inventory.quality,
            inventory.entries.len(),
            inventory.sources.len(),
            read,
            absent,
            inaccessible,
            failed,
            truncated
        );
    }
}
