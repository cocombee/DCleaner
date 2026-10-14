use dcleaner::drivers::{
    self, CandidateId, CandidateIdentity, CandidateMatch, CatalogueState, DeviceId,
    DeviceInventory, DeviceOffer, DriverCandidate, DriverCatalogue, DriverDevice, DriverManager,
    DriverPlatform, DriverPreference, DriverSettings, DriverSnapshot, DriverStatus, FieldFailure,
    FieldFailureKind, FieldValue, InventoryQuality, NativeIssue, RebootRequirement, SourceReport,
    WuaServerSelection, WuaSource,
};
use std::{collections::VecDeque, path::Path};

fn known<T>(value: T) -> FieldValue<T> {
    FieldValue::Known { value }
}

fn unknown<T>(kind: FieldFailureKind) -> FieldValue<T> {
    FieldValue::Unknown {
        failure: FieldFailure {
            kind,
            native_code: None,
        },
    }
}

fn source() -> WuaSource {
    WuaSource {
        server_selection: WuaServerSelection::PolicyDefault,
        service_id: String::new(),
        online_search: true,
    }
}

fn device(instance_id: &str, hardware_ids: Vec<&str>, compatible_ids: Vec<&str>) -> DriverDevice {
    DriverDevice {
        id: DeviceId::from_instance_id(instance_id),
        instance_id: known(instance_id.into()),
        friendly_name: known("Graphics adapter".into()),
        class_name: known("Display".into()),
        class_guid: "{4d36e968-e325-11ce-bfc1-08002be10318}".into(),
        hardware_ids: known(hardware_ids.into_iter().map(str::to_owned).collect()),
        compatible_ids: known(compatible_ids.into_iter().map(str::to_owned).collect()),
        provider: known("Device Vendor".into()),
        installed_version: known("1.0.0.0".into()),
        installed_date: known("2025-01-01".into()),
        inf_path: known("oem42.inf".into()),
        problem_code: known(0),
        offer: DeviceOffer::Unknown {
            failure: FieldFailure {
                kind: FieldFailureKind::NativeFailure,
                native_code: None,
            },
        },
    }
}

fn candidate(hardware_id: &str, revision: u32) -> DriverCandidate {
    let identity = CandidateIdentity {
        update_id: "11111111-2222-3333-4444-555555555555".into(),
        revision,
        source: source(),
        driver_hardware_id: hardware_id.into(),
    };
    DriverCandidate {
        id: identity.id(),
        identity,
        title: known("Device driver update".into()),
        manufacturer: known("Device Vendor".into()),
        model: known("Graphics adapter".into()),
        class: known("Display".into()),
        provider: known("Device Vendor".into()),
        release_date: known("2026-01-01".into()),
        candidate_version: unknown(FieldFailureKind::NotProvidedByApi),
        applicability: CandidateMatch::NoMatchingPresentDevice,
        eula_accepted: known(true),
        installed: known(false),
        hidden: known(false),
    }
}

fn inventory(devices: Vec<DriverDevice>) -> DeviceInventory {
    DeviceInventory {
        source: SourceReport {
            quality: InventoryQuality::Complete,
            item_count: devices.len(),
            issues: Vec::new(),
        },
        devices,
    }
}

fn catalogue(candidates: Vec<DriverCandidate>) -> DriverCatalogue {
    DriverCatalogue {
        state: CatalogueState::Read { source: source() },
        candidates,
        issues: Vec::new(),
    }
}

#[derive(Clone)]
struct FakePlatform {
    inventory: DeviceInventory,
    catalogue: DriverCatalogue,
}

impl DriverPlatform for FakePlatform {
    fn inventory_devices(&mut self) -> DeviceInventory {
        self.inventory.clone()
    }

    fn search_catalogue(&mut self) -> DriverCatalogue {
        self.catalogue.clone()
    }
}

struct FakeActionPlatform {
    inventory: DeviceInventory,
    catalogue: DriverCatalogue,
    candidate: DriverCandidate,
    device_reads: VecDeque<DriverDevice>,
    fallback_device: DriverDevice,
    backup: drivers::DriverBackupReceipt,
    update_result: Result<drivers::DriverInstallOutcome, drivers::DriverOperationError>,
    restore_result: Result<drivers::DriverRestoreOutcome, drivers::DriverOperationError>,
    candidate_installed: Result<bool, drivers::DriverOperationError>,
    journal_path: std::path::PathBuf,
    events: Vec<&'static str>,
}

impl DriverPlatform for FakeActionPlatform {
    fn inventory_devices(&mut self) -> DeviceInventory {
        self.inventory.clone()
    }

    fn search_catalogue(&mut self) -> DriverCatalogue {
        self.catalogue.clone()
    }
}

impl drivers::DriverActionBoundary for FakeActionPlatform {
    fn current_device(
        &mut self,
        id: &DeviceId,
    ) -> Result<DriverDevice, drivers::DriverOperationError> {
        self.events.push("current-device");
        self.device_reads
            .pop_front()
            .or_else(|| Some(self.fallback_device.clone()))
            .filter(|device| device.id.as_ref() == Some(id))
            .ok_or(drivers::DriverOperationError::UpdateUnavailable)
    }

    fn exact_candidate(
        &mut self,
        identity: &CandidateIdentity,
    ) -> Result<DriverCandidate, drivers::DriverOperationError> {
        self.events.push("exact-candidate");
        (self.candidate.identity == *identity)
            .then(|| self.candidate.clone())
            .ok_or(drivers::DriverOperationError::UpdateUnavailable)
    }

    fn create_restore_point(
        &mut self,
        _description: &str,
    ) -> Result<i64, drivers::DriverOperationError> {
        self.events.push("restore-point");
        assert!(self.journal_path.is_file(), "intent must be durable first");
        Ok(7)
    }

    fn export_driver_package(
        &mut self,
        _root: &Path,
        _intent: &drivers::DriverUpdateIntent,
        _backup_id: uuid::Uuid,
    ) -> Result<drivers::DriverBackupReceipt, drivers::DriverOperationError> {
        self.events.push("export-package");
        Ok(self.backup.clone())
    }

    fn download_and_install(
        &mut self,
        _intent: &drivers::DriverUpdateIntent,
    ) -> Result<drivers::DriverInstallOutcome, drivers::DriverOperationError> {
        self.events.push("install-update");
        self.update_result.clone()
    }

    fn candidate_is_installed(
        &mut self,
        _identity: &CandidateIdentity,
    ) -> Result<bool, drivers::DriverOperationError> {
        self.events.push("verify-candidate");
        self.candidate_installed.clone()
    }

    fn restore_from_package(
        &mut self,
        _root: &Path,
        _intent: &drivers::DriverRestoreIntent,
    ) -> Result<drivers::DriverRestoreOutcome, drivers::DriverOperationError> {
        self.events.push("restore-package");
        self.restore_result.clone()
    }
}

fn successful_update_outcome(reboot: RebootRequirement) -> drivers::DriverInstallOutcome {
    drivers::DriverInstallOutcome {
        download_result_code: 2,
        download_hresult: 0,
        download_item_result_code: 2,
        download_item_hresult: 0,
        downloaded_verified: true,
        install_result_code: Some(2),
        install_hresult: Some(0),
        install_item_result_code: Some(2),
        install_item_hresult: Some(0),
        reboot,
    }
}

fn batch_receipt(
    intent_id: uuid::Uuid,
    phase: drivers::DriverEffectPhase,
    reboot: RebootRequirement,
) -> drivers::DriverUpdateReceipt {
    drivers::DriverUpdateReceipt {
        schema_version: drivers::DRIVER_SCHEMA_VERSION,
        intent_id,
        device_id: DeviceId::from_instance_id("PCI\\VEN_A&DEV_B\\SERIAL").unwrap(),
        device_instance_id: "PCI\\VEN_A&DEV_B\\SERIAL".into(),
        candidate: candidate("PCI\\VEN_A&DEV_B", 3).identity,
        original_state: drivers::DriverInstalledState {
            provider: "Device Vendor".into(),
            version: "1.0.0.0".into(),
            date: "2025-01-01".into(),
            inf: "oem42.inf".into(),
        },
        backup: None,
        restore_point_sequence: None,
        phase,
        download_result_code: None,
        download_hresult: None,
        download_item_result_code: None,
        download_item_hresult: None,
        downloaded_verified: false,
        wua_result_code: None,
        hresult: None,
        install_item_result_code: None,
        install_item_hresult: None,
        reboot,
        installed_after: None,
    }
}

fn backup_for(device: &DriverDevice) -> drivers::DriverBackupReceipt {
    let device_id = device.id.clone().unwrap();
    let device_instance_id = device.instance_id.as_known().unwrap().clone();
    let backup_id = uuid::Uuid::new_v4();
    drivers::DriverBackupReceipt {
        schema_version: drivers::DRIVER_SCHEMA_VERSION,
        backup_id,
        device_id,
        device_instance_id,
        original_inf: "oem42.inf".into(),
        relative_directory: format!("drivers/backups/{backup_id}"),
        files: vec![
            drivers::DriverBackupFile {
                relative_path: "oem42.cat".into(),
                byte_length: 256,
                sha256: "b".repeat(64),
            },
            drivers::DriverBackupFile {
                relative_path: "oem42.inf".into(),
                byte_length: 64,
                sha256: "a".repeat(64),
            },
        ],
        manifest_sha256: "c".repeat(64),
        signature_verified: true,
    }
}

fn make_action_platform(
    root: &Path,
    old: &DriverDevice,
    candidate: DriverCandidate,
    backup: drivers::DriverBackupReceipt,
    reads: impl IntoIterator<Item = DriverDevice>,
    fallback_device: DriverDevice,
) -> FakeActionPlatform {
    FakeActionPlatform {
        inventory: inventory(vec![old.clone()]),
        catalogue: catalogue(vec![candidate.clone()]),
        candidate,
        device_reads: reads.into_iter().collect(),
        fallback_device,
        backup,
        update_result: Ok(successful_update_outcome(RebootRequirement::NotRequired)),
        restore_result: Ok(drivers::DriverRestoreOutcome {
            staged_inf: "oem99.inf".into(),
            reboot: RebootRequirement::NotRequired,
        }),
        candidate_installed: Ok(true),
        journal_path: root.join("effects/drivers").join("pending"),
        events: Vec::new(),
    }
}

#[test]
fn fake_platform_combines_setupapi_and_wua_without_inventing_versions() {
    let device = device(
        "PCI\\VEN_1234&DEV_5678\\5&ABCD&0&00",
        vec!["PCI\\VEN_1234&DEV_5678"],
        vec!["PCI\\VEN_1234"],
    );
    let id = device.id.clone().unwrap();
    let mut manager = DriverManager::new(FakePlatform {
        inventory: inventory(vec![device]),
        catalogue: catalogue(vec![candidate("pci\\ven_1234&dev_5678", 2)]),
    });

    let snapshot = manager.scan();

    assert_eq!(snapshot.inventory.devices.len(), 1);
    assert_eq!(
        snapshot.inventory.devices[0].offer,
        DeviceOffer::CandidateAvailable {
            candidates: vec![snapshot.catalogue.candidates[0].id.clone()],
        }
    );
    assert_eq!(
        snapshot.catalogue.candidates[0].applicability,
        CandidateMatch::Matched { devices: vec![id] }
    );
    assert_eq!(snapshot.catalogue.candidates[0].identity.revision, 2);
    assert_eq!(
        snapshot.catalogue.candidates[0].candidate_version,
        unknown(FieldFailureKind::NotProvidedByApi)
    );
    assert_eq!(snapshot.catalogue.candidates[0].identity.source, source());
}

#[test]
fn hardware_id_matching_is_exact_except_for_case_and_surrounding_space() {
    let device = device(
        "USB\\VID_1111&PID_2222\\SERIAL",
        vec!["USB\\VID_1111&PID_2222"],
        vec![],
    );
    let near_miss = candidate("USB\\VID_1111&PID_2222&REV_0100", 1);
    let snapshot = DriverSnapshot::assemble(inventory(vec![device]), catalogue(vec![near_miss]));

    assert_eq!(
        snapshot.catalogue.candidates[0].applicability,
        CandidateMatch::NoMatchingPresentDevice
    );
    assert_eq!(
        snapshot.inventory.devices[0].offer,
        DeviceOffer::NoOfferFromSource { source: source() }
    );
}

#[test]
fn a_second_unreadable_present_device_blocks_exclusive_candidate_matching() {
    let matched = device(
        "PCI\\VEN_1234&DEV_5678\\TARGET",
        vec!["PCI\\VEN_1234&DEV_5678"],
        vec!["PCI\\VEN_1234"],
    );
    let mut unreadable = device("USB\\VID_9999&PID_8888\\UNKNOWN", vec![], vec![]);
    unreadable.hardware_ids = unknown(FieldFailureKind::AccessDenied);
    unreadable.compatible_ids = unknown(FieldFailureKind::AccessDenied);
    let mut inventory = inventory(vec![matched, unreadable]);
    inventory.source.quality = InventoryQuality::Partial;
    inventory.source.issues.push(NativeIssue {
        source: "SetupAPI device properties".into(),
        operation: "read unreadable device IDs".into(),
        failure: FieldFailure {
            kind: FieldFailureKind::AccessDenied,
            native_code: Some(0x8007_0005),
        },
    });

    let snapshot = DriverSnapshot::assemble(
        inventory,
        catalogue(vec![candidate("PCI\\VEN_1234&DEV_5678", 2)]),
    );

    assert!(matches!(
        snapshot.catalogue.candidates[0].applicability,
        CandidateMatch::Unknown {
            failure: FieldFailure {
                kind: FieldFailureKind::AccessDenied,
                ..
            }
        }
    ));
    assert!(matches!(
        snapshot.inventory.devices[0].offer,
        DeviceOffer::Unknown { .. }
    ));
    assert_eq!(
        snapshot.status_for(&snapshot.inventory.devices[0], &DriverSettings::default()),
        DriverStatus::Unknown
    );
}

#[test]
fn partial_device_or_catalogue_reads_never_report_no_offer_as_current() {
    let mut device = device(
        "PCI\\VEN_1&DEV_2\\A",
        vec!["PCI\\VEN_1&DEV_2"],
        vec!["PCI\\VEN_1"],
    );
    device.compatible_ids = unknown(FieldFailureKind::AccessDenied);
    let partial_inventory = DeviceInventory {
        source: SourceReport {
            quality: InventoryQuality::Partial,
            item_count: 1,
            issues: vec![NativeIssue {
                source: "SetupAPI device properties".into(),
                operation: "read compatible IDs".into(),
                failure: FieldFailure {
                    kind: FieldFailureKind::AccessDenied,
                    native_code: Some(0x8007_0005),
                },
            }],
        },
        devices: vec![device],
    };
    let partial_catalogue = DriverCatalogue {
        state: CatalogueState::Partial { source: source() },
        candidates: vec![],
        issues: vec![NativeIssue {
            source: "Windows Update Agent".into(),
            operation: "search driver catalogue".into(),
            failure: FieldFailure {
                kind: FieldFailureKind::NativeFailure,
                native_code: Some(0x8024_0000),
            },
        }],
    };

    let snapshot = DriverSnapshot::assemble(partial_inventory, partial_catalogue);

    assert_eq!(snapshot.inventory.source.quality, InventoryQuality::Partial);
    assert!(matches!(
        snapshot.inventory.devices[0].offer,
        DeviceOffer::Unknown { .. }
    ));
    assert_eq!(
        snapshot.status_for(&snapshot.inventory.devices[0], &DriverSettings::default()),
        DriverStatus::Unknown
    );
}

#[test]
fn no_offer_requires_all_device_ids_and_a_complete_wua_search() {
    let mut device = device(
        "PCI\\VEN_A&DEV_B\\X",
        vec!["PCI\\VEN_A&DEV_B"],
        vec!["PCI\\VEN_A"],
    );
    device.hardware_ids = unknown(FieldFailureKind::NotPresent);
    let snapshot = DriverSnapshot::assemble(inventory(vec![device]), catalogue(vec![]));

    assert!(matches!(
        snapshot.inventory.devices[0].offer,
        DeviceOffer::Unknown { .. }
    ));
    assert_eq!(
        snapshot.status_for(&snapshot.inventory.devices[0], &DriverSettings::default()),
        DriverStatus::Unknown
    );
}

#[test]
fn skip_is_bound_to_exact_candidate_revision_and_ignore_is_device_scoped() {
    let device = device("PCI\\VEN_A&DEV_B\\X", vec!["PCI\\VEN_A&DEV_B"], vec![]);
    let id = device.id.clone().unwrap();
    let snapshot = DriverSnapshot::assemble(
        inventory(vec![device]),
        catalogue(vec![
            candidate("PCI\\VEN_A&DEV_B", 1),
            candidate("PCI\\VEN_A&DEV_B", 2),
        ]),
    );
    let device = &snapshot.inventory.devices[0];
    let mut settings = DriverSettings::default();

    assert_eq!(
        snapshot.status_for(device, &settings),
        DriverStatus::UpdateAvailable
    );
    settings
        .set_skipped(
            id.clone(),
            snapshot.catalogue.candidates[0].identity.clone(),
            true,
        )
        .unwrap();
    assert_eq!(
        snapshot.status_for(device, &settings),
        DriverStatus::UpdateAvailable
    );
    settings
        .set_skipped(
            id.clone(),
            snapshot.catalogue.candidates[1].identity.clone(),
            true,
        )
        .unwrap();
    assert_eq!(
        snapshot.status_for(device, &settings),
        DriverStatus::Skipped
    );
    settings.set_ignored(id.clone(), true).unwrap();
    assert_eq!(
        snapshot.status_for(device, &settings),
        DriverStatus::Ignored
    );
    settings.set_ignored(id.clone(), false).unwrap();
    assert_eq!(
        snapshot.status_for(device, &settings),
        DriverStatus::Skipped
    );
    settings
        .set_skipped(id, snapshot.catalogue.candidates[1].identity.clone(), false)
        .unwrap();
    assert_eq!(
        snapshot.status_for(device, &settings),
        DriverStatus::UpdateAvailable
    );
}

#[test]
fn candidate_id_changes_when_source_or_revision_changes() {
    let original = candidate("PCI\\VEN_A&DEV_B", 3).identity;
    let mut new_revision = original.clone();
    new_revision.revision += 1;
    let mut new_source = original.clone();
    new_source.source.server_selection = WuaServerSelection::ManagedServer;
    let mut new_hardware = original.clone();
    new_hardware.driver_hardware_id.push_str("&REV_2");

    assert_ne!(original.id(), new_revision.id());
    assert_ne!(original.id(), new_source.id());
    assert_ne!(original.id(), new_hardware.id());
}

#[test]
fn batch_offer_identity_deduplicates_hardware_variants_but_keeps_source_and_revision() {
    let mut first = candidate("PCI\\VEN_A&DEV_B", 3).identity;
    first.update_id = "A1111111-2222-3333-4444-555555555555".into();
    let mut hardware_variant = candidate("PCI\\VEN_A&DEV_B&REV_2", 3).identity;
    hardware_variant.update_id = first.update_id.to_ascii_lowercase();
    assert_ne!(
        first.driver_hardware_id,
        hardware_variant.driver_hardware_id
    );
    assert!(drivers::same_wua_update(&first, &hardware_variant));

    let mut new_revision = hardware_variant.clone();
    new_revision.revision += 1;
    assert!(!drivers::same_wua_update(&first, &new_revision));

    let mut new_source = hardware_variant.clone();
    new_source.source.service_id = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".into();
    assert!(!drivers::same_wua_update(&first, &new_source));

    let mut different_update = hardware_variant;
    different_update.update_id = "B1111111-2222-3333-4444-555555555555".into();
    assert!(!drivers::same_wua_update(&first, &different_update));
}

#[test]
fn driver_batch_continues_only_after_matching_verified_no_restart_receipt() {
    let expected = uuid::Uuid::new_v4();
    let verified = batch_receipt(
        expected,
        drivers::DriverEffectPhase::Verified,
        RebootRequirement::NotRequired,
    );
    assert!(drivers::should_continue_driver_batch(
        expected,
        &Ok(verified)
    ));

    for (phase, reboot) in [
        (
            drivers::DriverEffectPhase::Verified,
            RebootRequirement::Required,
        ),
        (
            drivers::DriverEffectPhase::Verified,
            RebootRequirement::Unknown,
        ),
        (
            drivers::DriverEffectPhase::AwaitingRestart,
            RebootRequirement::Required,
        ),
        (
            drivers::DriverEffectPhase::Uncertain,
            RebootRequirement::NotRequired,
        ),
        (
            drivers::DriverEffectPhase::Failed,
            RebootRequirement::NotRequired,
        ),
    ] {
        let receipt = batch_receipt(expected, phase, reboot);
        assert!(!drivers::should_continue_driver_batch(
            expected,
            &Ok(receipt)
        ));
    }

    let mismatched = batch_receipt(
        uuid::Uuid::new_v4(),
        drivers::DriverEffectPhase::Verified,
        RebootRequirement::NotRequired,
    );
    assert!(!drivers::should_continue_driver_batch(
        expected,
        &Ok(mismatched)
    ));
    assert!(!drivers::should_continue_driver_batch(
        expected,
        &Err(drivers::DriverOperationError::VerificationFailed)
    ));
}

#[test]
fn representative_batch_success_notice_does_not_claim_related_devices_verified() {
    let notice = drivers::representative_batch_completion_notice(2);
    assert!(notice.contains("representative device"));
    assert!(notice.contains("all 2 reviewed driver offers"));
    assert!(
        notice.contains("Related devices in shared offer groups were not individually verified")
    );
    assert!(!notice.contains("all devices"));
}

#[test]
fn prepare_and_validate_install_intent_revalidate_exact_device_and_offer_then_fail_closed() {
    let device = device(
        "PCI\\VEN_A&DEV_B\\X",
        vec!["PCI\\VEN_A&DEV_B"],
        vec!["PCI\\VEN_A"],
    );
    let snapshot = DriverSnapshot::assemble(
        inventory(vec![device]),
        catalogue(vec![candidate("PCI\\VEN_A&DEV_B", 4)]),
    );
    let current = &snapshot.inventory.devices[0];
    let candidate = &snapshot.catalogue.candidates[0];
    let intent = drivers::prepare_update_intent(current, candidate).unwrap();

    assert_eq!(
        drivers::validate_update_intent(&intent, current, candidate),
        Ok(())
    );
    let mut changed_device = current.clone();
    changed_device.installed_version = known("9.9.9.9".into());
    assert_eq!(
        drivers::validate_update_intent(&intent, &changed_device, candidate),
        Err(drivers::DriverOperationError::UpdateUnavailable)
    );
    assert_eq!(
        drivers::supported_update_actions(),
        if cfg!(windows) {
            Ok(())
        } else {
            Err(drivers::DriverOperationError::NativeUpdateBoundaryUnavailable)
        }
    );
}

#[test]
fn update_rejects_a_wua_package_that_matches_multiple_present_devices() {
    let first = device("PCI\\VEN_A&DEV_B\\ONE", vec!["PCI\\VEN_A&DEV_B"], vec![]);
    let second = device("PCI\\VEN_A&DEV_B\\TWO", vec!["PCI\\VEN_A&DEV_B"], vec![]);
    let snapshot = DriverSnapshot::assemble(
        inventory(vec![first, second]),
        catalogue(vec![candidate("PCI\\VEN_A&DEV_B", 4)]),
    );

    assert!(matches!(
        &snapshot.catalogue.candidates[0].applicability,
        CandidateMatch::Matched { devices } if devices.len() == 2
    ));
    assert_eq!(
        drivers::prepare_update_intent(
            &snapshot.inventory.devices[0],
            &snapshot.catalogue.candidates[0],
        ),
        Err(drivers::DriverOperationError::UpdateUnavailable)
    );
}

#[test]
fn reviewed_update_journals_before_install_and_checks_exact_post_state() {
    let original = device("PCI\\VEN_A&DEV_B\\X", vec!["PCI\\VEN_A&DEV_B"], vec![]);
    let snapshot = DriverSnapshot::assemble(
        inventory(vec![original.clone()]),
        catalogue(vec![candidate("PCI\\VEN_A&DEV_B", 4)]),
    );
    let old = snapshot.inventory.devices[0].clone();
    let candidate = snapshot.catalogue.candidates[0].clone();
    let intent = drivers::prepare_update_intent(&old, &candidate).unwrap();
    let backup = backup_for(&old);
    let mut updated = old.clone();
    updated.installed_version = known("2.0.0.0".into());
    updated.installed_date = known("2026-01-01".into());
    updated.inf_path = known("oem84.inf".into());

    let root = tempfile::tempdir().unwrap();
    let mut platform = make_action_platform(
        root.path(),
        &old,
        candidate,
        backup,
        [old.clone(), old.clone(), updated],
        old.clone(),
    );
    platform.journal_path = root
        .path()
        .join("effects/drivers")
        .join(format!("{}.jsonl", intent.intent_id));

    let receipt = drivers::apply_reviewed_update(root.path(), &intent, &mut platform).unwrap();

    assert_eq!(receipt.phase, drivers::DriverEffectPhase::Verified);
    let restore_point = platform
        .events
        .iter()
        .position(|event| *event == "restore-point")
        .unwrap();
    let export = platform
        .events
        .iter()
        .position(|event| *event == "export-package")
        .unwrap();
    let install = platform
        .events
        .iter()
        .position(|event| *event == "install-update")
        .unwrap();
    let verify = platform
        .events
        .iter()
        .position(|event| *event == "verify-candidate")
        .unwrap();
    assert!(restore_point < export && export < install && install < verify);
    let history = drivers::operation_history(root.path()).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].state, "verified");
}

#[test]
fn update_with_an_unaccepted_eula_stops_before_creating_a_journal() {
    let original = device("PCI\\VEN_A&DEV_B\\X", vec!["PCI\\VEN_A&DEV_B"], vec![]);
    let snapshot = DriverSnapshot::assemble(
        inventory(vec![original.clone()]),
        catalogue(vec![candidate("PCI\\VEN_A&DEV_B", 4)]),
    );
    let old = snapshot.inventory.devices[0].clone();
    let candidate = snapshot.catalogue.candidates[0].clone();
    let intent = drivers::prepare_update_intent(&old, &candidate).unwrap();
    let mut blocked_candidate = candidate.clone();
    blocked_candidate.eula_accepted = known(false);

    let root = tempfile::tempdir().unwrap();
    let mut platform = make_action_platform(
        root.path(),
        &old,
        blocked_candidate,
        backup_for(&old),
        [old.clone()],
        old.clone(),
    );
    platform.journal_path = root
        .path()
        .join("effects/drivers")
        .join(format!("{}.jsonl", intent.intent_id));

    assert_eq!(
        drivers::apply_reviewed_update(root.path(), &intent, &mut platform),
        Err(drivers::DriverOperationError::EulaNotAccepted)
    );
    assert!(
        platform.events.iter().all(|event| {
            !["restore-point", "export-package", "install-update"].contains(event)
        })
    );
    assert!(drivers::operation_history(root.path()).unwrap().is_empty());
}

#[test]
fn reviewed_update_fails_before_wua_if_device_changes_after_backup() {
    let original = device("PCI\\VEN_A&DEV_B\\X", vec!["PCI\\VEN_A&DEV_B"], vec![]);
    let snapshot = DriverSnapshot::assemble(
        inventory(vec![original.clone()]),
        catalogue(vec![candidate("PCI\\VEN_A&DEV_B", 4)]),
    );
    let old = snapshot.inventory.devices[0].clone();
    let candidate = snapshot.catalogue.candidates[0].clone();
    let intent = drivers::prepare_update_intent(&old, &candidate).unwrap();
    let mut changed = old.clone();
    changed.installed_version = known("9.9.9.9".into());

    let root = tempfile::tempdir().unwrap();
    let mut platform = make_action_platform(
        root.path(),
        &old,
        candidate,
        backup_for(&old),
        [old.clone(), changed],
        old.clone(),
    );
    platform.journal_path = root
        .path()
        .join("effects/drivers")
        .join(format!("{}.jsonl", intent.intent_id));

    assert_eq!(
        drivers::apply_reviewed_update(root.path(), &intent, &mut platform),
        Err(drivers::DriverOperationError::UpdateUnavailable)
    );
    assert!(!platform.events.contains(&"install-update"));
    assert_eq!(
        drivers::operation_history(root.path()).unwrap()[0].state,
        "failed"
    );
}

#[test]
fn item_level_wua_failure_is_not_hidden_by_successful_aggregate_result() {
    let original = device("PCI\\VEN_A&DEV_B\\X", vec!["PCI\\VEN_A&DEV_B"], vec![]);
    let snapshot = DriverSnapshot::assemble(
        inventory(vec![original.clone()]),
        catalogue(vec![candidate("PCI\\VEN_A&DEV_B", 4)]),
    );
    let old = snapshot.inventory.devices[0].clone();
    let candidate = snapshot.catalogue.candidates[0].clone();
    let intent = drivers::prepare_update_intent(&old, &candidate).unwrap();
    let mut outcome = successful_update_outcome(RebootRequirement::NotRequired);
    outcome.install_item_result_code = Some(4);

    let root = tempfile::tempdir().unwrap();
    let mut platform = make_action_platform(
        root.path(),
        &old,
        candidate,
        backup_for(&old),
        [old.clone(), old.clone()],
        old.clone(),
    );
    platform.update_result = Ok(outcome);
    platform.journal_path = root
        .path()
        .join("effects/drivers")
        .join(format!("{}.jsonl", intent.intent_id));

    assert_eq!(
        drivers::apply_reviewed_update(root.path(), &intent, &mut platform),
        Err(drivers::DriverOperationError::UpdateFailed {
            hresult: None,
            result_code: Some(4),
        })
    );
    assert_eq!(
        drivers::operation_history(root.path()).unwrap()[0].state,
        "uncertain"
    );
}

#[test]
fn reboot_required_update_is_recorded_as_pending_without_claiming_verification() {
    let original = device("PCI\\VEN_A&DEV_B\\X", vec!["PCI\\VEN_A&DEV_B"], vec![]);
    let snapshot = DriverSnapshot::assemble(
        inventory(vec![original.clone()]),
        catalogue(vec![candidate("PCI\\VEN_A&DEV_B", 4)]),
    );
    let old = snapshot.inventory.devices[0].clone();
    let candidate = snapshot.catalogue.candidates[0].clone();
    let intent = drivers::prepare_update_intent(&old, &candidate).unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut platform = make_action_platform(
        root.path(),
        &old,
        candidate,
        backup_for(&old),
        [old.clone(), old.clone()],
        old.clone(),
    );
    platform.update_result = Ok(successful_update_outcome(RebootRequirement::Required));
    platform.journal_path = root
        .path()
        .join("effects/drivers")
        .join(format!("{}.jsonl", intent.intent_id));

    let receipt = drivers::apply_reviewed_update(root.path(), &intent, &mut platform).unwrap();

    assert_eq!(receipt.phase, drivers::DriverEffectPhase::AwaitingRestart);
    assert!(receipt.installed_after.is_none());
    assert!(!platform.events.contains(&"verify-candidate"));
    assert_eq!(
        drivers::operation_history(root.path()).unwrap()[0].state,
        "applied"
    );
}

#[test]
fn unknown_identity_and_unmatched_candidate_cannot_prepare_review_intent() {
    let mut device = device("PCI\\VEN_A&DEV_B\\X", vec!["PCI\\VEN_A&DEV_B"], vec![]);
    device.inf_path = unknown(FieldFailureKind::AccessDenied);
    let snapshot = DriverSnapshot::assemble(
        inventory(vec![device]),
        catalogue(vec![candidate("PCI\\VEN_A&DEV_C", 4)]),
    );

    assert_eq!(
        drivers::prepare_update_intent(
            &snapshot.inventory.devices[0],
            &snapshot.catalogue.candidates[0]
        ),
        Err(drivers::DriverOperationError::UpdateUnavailable)
    );
}

#[test]
fn category_and_problem_filter_use_native_class_and_keep_unknown_status_unknown() {
    let mut display = device("PCI\\VEN_A&DEV_B\\X", vec!["PCI\\VEN_A&DEV_B"], vec![]);
    display.class_name = known("Display".into());
    assert_eq!(display.category(), drivers::DriverDeviceCategory::Display);
    assert_eq!(display.has_confirmed_problem(), Some(false));

    display.problem_code = unknown(FieldFailureKind::AccessDenied);
    assert_eq!(display.has_confirmed_problem(), None);
    display.class_name = unknown(FieldFailureKind::NotPresent);
    display.class_guid = "{ffffffff-ffff-ffff-ffff-ffffffffffff}".into();
    assert_eq!(display.category(), drivers::DriverDeviceCategory::Other);
}

#[test]
fn update_review_rejects_forged_candidate_identity_and_revision() {
    let device = device("PCI\\VEN_A&DEV_B\\X", vec!["PCI\\VEN_A&DEV_B"], vec![]);
    let snapshot = DriverSnapshot::assemble(
        inventory(vec![device]),
        catalogue(vec![candidate("PCI\\VEN_A&DEV_B", 4)]),
    );
    let mut forged = snapshot.catalogue.candidates[0].clone();
    forged.id.0.push_str("-wrong");
    assert_eq!(
        drivers::prepare_update_intent(&snapshot.inventory.devices[0], &forged),
        Err(drivers::DriverOperationError::UpdateUnavailable)
    );

    let mut malformed = snapshot.catalogue.candidates[0].clone();
    malformed.identity.update_id = "not-a-guid".into();
    malformed.id = malformed.identity.id();
    assert_eq!(
        drivers::prepare_update_intent(&snapshot.inventory.devices[0], &malformed),
        Err(drivers::DriverOperationError::UpdateUnavailable)
    );
}

#[test]
fn restore_contract_requires_confirmed_backup_and_exact_post_update_device_state() {
    let old = device(
        "PCI\\VEN_A&DEV_B\\X",
        vec!["PCI\\VEN_A&DEV_B"],
        vec!["PCI\\VEN_A"],
    );
    let snapshot = DriverSnapshot::assemble(
        inventory(vec![old]),
        catalogue(vec![candidate("PCI\\VEN_A&DEV_B", 4)]),
    );
    let old_device = &snapshot.inventory.devices[0];
    let update_intent =
        drivers::prepare_update_intent(old_device, &snapshot.catalogue.candidates[0]).unwrap();
    let device_id = old_device.id.clone().unwrap();
    let instance_id = old_device.instance_id.as_known().unwrap().clone();
    let backup_id = uuid::Uuid::new_v4();
    let backup = drivers::DriverBackupReceipt {
        schema_version: drivers::DRIVER_SCHEMA_VERSION,
        backup_id,
        device_id: device_id.clone(),
        device_instance_id: instance_id.clone(),
        original_inf: "oem42.inf".into(),
        relative_directory: format!("drivers/backups/{backup_id}"),
        files: vec![
            drivers::DriverBackupFile {
                relative_path: "oem42.inf".into(),
                byte_length: 64,
                sha256: "a".repeat(64),
            },
            drivers::DriverBackupFile {
                relative_path: "oem42.cat".into(),
                byte_length: 256,
                sha256: "b".repeat(64),
            },
        ],
        manifest_sha256: "c".repeat(64),
        signature_verified: true,
    };
    assert!(backup.is_well_formed());
    let updated = drivers::DriverInstalledState {
        provider: "Device Vendor".into(),
        version: "2.0.0.0".into(),
        date: "2026-01-01".into(),
        inf: "oem42.inf".into(),
    };
    let receipt = drivers::DriverUpdateReceipt {
        schema_version: drivers::DRIVER_SCHEMA_VERSION,
        intent_id: update_intent.intent_id,
        device_id: device_id.clone(),
        device_instance_id: instance_id.clone(),
        candidate: update_intent.candidate.clone(),
        original_state: drivers::DriverInstalledState::from_device(old_device).unwrap(),
        backup: Some(backup.clone()),
        restore_point_sequence: Some(7),
        phase: drivers::DriverEffectPhase::Verified,
        download_result_code: Some(2),
        download_hresult: Some(0),
        download_item_result_code: Some(2),
        download_item_hresult: Some(0),
        downloaded_verified: true,
        wua_result_code: Some(2),
        hresult: Some(0),
        install_item_result_code: Some(2),
        install_item_hresult: Some(0),
        reboot: drivers::RebootRequirement::NotRequired,
        installed_after: Some(updated.clone()),
    };
    let mut current = old_device.clone();
    current.provider = known(updated.provider.clone());
    current.installed_version = known(updated.version.clone());
    current.installed_date = known(updated.date.clone());
    current.inf_path = known(updated.inf.clone());

    let restore = drivers::prepare_restore_intent(&update_intent, &receipt, &current).unwrap();
    assert_eq!(restore.expected_installed_state, updated);
    assert_eq!(
        drivers::validate_restore_intent(&restore, &update_intent, &receipt, &current),
        Ok(())
    );

    let mut changed = current.clone();
    changed.hardware_ids = known(vec!["PCI\\VEN_A&DEV_C".into()]);
    assert_eq!(
        drivers::validate_restore_intent(&restore, &update_intent, &receipt, &changed),
        Err(drivers::DriverOperationError::UpdateUnavailable)
    );
    let mut unverified = backup;
    unverified.signature_verified = false;
    assert!(!unverified.is_well_formed());
}

#[test]
fn reviewed_restore_rechecks_the_device_journals_and_verifies_original_state() {
    let original = device("PCI\\VEN_A&DEV_B\\X", vec!["PCI\\VEN_A&DEV_B"], vec![]);
    let snapshot = DriverSnapshot::assemble(
        inventory(vec![original.clone()]),
        catalogue(vec![candidate("PCI\\VEN_A&DEV_B", 4)]),
    );
    let old = snapshot.inventory.devices[0].clone();
    let candidate = snapshot.catalogue.candidates[0].clone();
    let update_intent = drivers::prepare_update_intent(&old, &candidate).unwrap();
    let backup = backup_for(&old);
    let mut updated = old.clone();
    updated.installed_version = known("2.0.0.0".into());
    updated.installed_date = known("2026-01-01".into());
    updated.inf_path = known("oem84.inf".into());
    let original_state = drivers::DriverInstalledState::from_device(&old).unwrap();
    let updated_state = drivers::DriverInstalledState::from_device(&updated).unwrap();
    let update_receipt = drivers::DriverUpdateReceipt {
        schema_version: drivers::DRIVER_SCHEMA_VERSION,
        intent_id: update_intent.intent_id,
        device_id: update_intent.device_id.clone(),
        device_instance_id: update_intent.device_instance_id.clone(),
        candidate: update_intent.candidate.clone(),
        original_state,
        backup: Some(backup.clone()),
        restore_point_sequence: Some(7),
        phase: drivers::DriverEffectPhase::Verified,
        download_result_code: Some(2),
        download_hresult: Some(0),
        download_item_result_code: Some(2),
        download_item_hresult: Some(0),
        downloaded_verified: true,
        wua_result_code: Some(2),
        hresult: Some(0),
        install_item_result_code: Some(2),
        install_item_hresult: Some(0),
        reboot: RebootRequirement::NotRequired,
        installed_after: Some(updated_state),
    };
    let restore_intent =
        drivers::prepare_restore_intent(&update_intent, &update_receipt, &updated).unwrap();

    let root = tempfile::tempdir().unwrap();
    let mut platform = make_action_platform(
        root.path(),
        &old,
        candidate,
        backup,
        [updated, old.clone()],
        old.clone(),
    );
    platform.journal_path = root
        .path()
        .join("effects/drivers")
        .join(format!("{}.jsonl", restore_intent.restore_id));

    let restore = drivers::apply_reviewed_restore(
        root.path(),
        &update_intent,
        &update_receipt,
        &restore_intent,
        &mut platform,
    )
    .unwrap();

    assert_eq!(restore.phase, drivers::DriverEffectPhase::Verified);
    assert_eq!(
        restore.restored_state,
        Some(update_receipt.original_state.clone())
    );
    assert_eq!(restore.staged_inf.as_deref(), Some("oem99.inf"));
    assert!(restore.backup_verified);
    assert!(platform.events.contains(&"restore-package"));
    assert_eq!(
        drivers::operation_history(root.path()).unwrap()[0].state,
        "restored"
    );
}

#[test]
fn settings_round_trip_and_reject_corrupt_or_duplicate_identities() {
    let root = tempfile::tempdir().unwrap();
    let device_id = DeviceId::from_instance_id("PCI\\VEN_A&DEV_B\\SERIAL").unwrap();
    let identity = candidate("PCI\\VEN_A&DEV_B", 2).identity;
    let mut settings = DriverSettings::default();
    settings
        .set_skipped(device_id.clone(), identity.clone(), true)
        .unwrap();
    settings.set_ignored(device_id.clone(), true).unwrap();

    drivers::save_settings(root.path(), &settings).unwrap();
    assert_eq!(drivers::load_settings(root.path()).unwrap(), settings);
    assert!(settings.is_skipped(&device_id, &identity));
    assert!(settings.is_ignored(&device_id));

    let replacement = DriverSettings::default();
    drivers::save_settings(root.path(), &replacement).unwrap();
    assert_eq!(drivers::load_settings(root.path()).unwrap(), replacement);

    let mut duplicated = settings.clone();
    duplicated
        .preferences
        .push(DriverPreference::IgnoreDevice { device_id });
    assert!(drivers::save_settings(root.path(), &duplicated).is_err());

    let settings_path = root.path().join("drivers-settings.json");
    for invalid in [
        b"not-json".as_slice(),
        br#"{"schema":2,"preferences":[]}"#.as_slice(),
    ] {
        std::fs::write(&settings_path, invalid).unwrap();
        assert!(drivers::load_settings(root.path()).is_err());
        assert!(drivers::save_settings(root.path(), &replacement).is_err());
        assert_eq!(std::fs::read(&settings_path).unwrap(), invalid);
    }
}

#[test]
fn failed_sources_have_explicit_quality_and_no_fabricated_rows() {
    let mut fake = FakePlatform {
        inventory: DeviceInventory {
            source: SourceReport {
                quality: InventoryQuality::Unavailable,
                item_count: 0,
                issues: vec![NativeIssue {
                    source: "SetupAPI".into(),
                    operation: "enumerate".into(),
                    failure: FieldFailure {
                        kind: FieldFailureKind::AccessDenied,
                        native_code: Some(0x8007_0005),
                    },
                }],
            },
            devices: vec![],
        },
        catalogue: DriverCatalogue {
            state: CatalogueState::Unavailable {
                issue: NativeIssue {
                    source: "Windows Update Agent".into(),
                    operation: "search".into(),
                    failure: FieldFailure {
                        kind: FieldFailureKind::AccessDenied,
                        native_code: Some(0x8007_0005),
                    },
                },
            },
            candidates: vec![],
            issues: vec![],
        },
    };
    let snapshot = DriverManager::new(fake.clone()).scan();

    assert_eq!(
        snapshot.inventory.source.quality,
        InventoryQuality::Unavailable
    );
    assert!(snapshot.inventory.devices.is_empty());
    assert!(matches!(
        snapshot.catalogue.state,
        CatalogueState::Unavailable { .. }
    ));
    assert!(snapshot.catalogue.candidates.is_empty());
    // Keep the fake mutable in this suite to exercise the port's ownership contract.
    fake.catalogue = catalogue(vec![]);
    assert_eq!(fake.catalogue.candidates.len(), 0);
}

#[cfg(windows)]
#[test]
fn native_setupapi_smoke_reports_only_count_and_quality() {
    let mut platform = drivers::WindowsDriverPlatform;
    let inventory = platform.inventory_devices();

    assert_eq!(inventory.source.item_count, inventory.devices.len());
    if inventory.source.quality == InventoryQuality::Unavailable {
        assert!(!inventory.source.issues.is_empty());
    }
    let mut issue_counts = std::collections::BTreeMap::<&str, usize>::new();
    for issue in &inventory.source.issues {
        *issue_counts.entry(&issue.operation).or_default() += 1;
    }
    eprintln!(
        "SetupAPI quality={:?}, present_device_count={}, issue_count={}, operations={:?}",
        inventory.source.quality,
        inventory.source.item_count,
        inventory.source.issues.len(),
        issue_counts
    );
}

#[test]
fn device_identity_digest_is_stable_case_insensitive_and_nonempty_only() {
    assert_eq!(
        DeviceId::from_instance_id("PCI\\VEN_A&DEV_B\\SERIAL"),
        DeviceId::from_instance_id("pci\\ven_a&dev_b\\serial")
    );
    assert!(DeviceId::from_instance_id("  ").is_none());
    assert!(DeviceId::from_instance_id("bad\0identity").is_none());
}

#[test]
fn catalogue_with_partial_metadata_remains_explicit_and_candidate_version_unknown() {
    let mut item = candidate("PCI\\VEN_A&DEV_B", 1);
    item.candidate_version = unknown(FieldFailureKind::NotProvidedByApi);
    item.provider = unknown(FieldFailureKind::AccessDenied);
    let mut catalogue = catalogue(vec![item]);
    catalogue.state = CatalogueState::Partial { source: source() };
    catalogue.issues.push(NativeIssue {
        source: "Windows Update Agent".into(),
        operation: "read provider".into(),
        failure: FieldFailure {
            kind: FieldFailureKind::AccessDenied,
            native_code: Some(0x8007_0005),
        },
    });
    let snapshot = DriverSnapshot::assemble(
        inventory(vec![device(
            "PCI\\VEN_A&DEV_B\\X",
            vec!["PCI\\VEN_A&DEV_B"],
            vec![],
        )]),
        catalogue,
    );

    assert!(matches!(
        snapshot.catalogue.state,
        CatalogueState::Partial { .. }
    ));
    assert_eq!(
        snapshot.catalogue.candidates[0].candidate_version,
        unknown(FieldFailureKind::NotProvidedByApi)
    );
    assert_eq!(
        snapshot.status_for(&snapshot.inventory.devices[0], &DriverSettings::default()),
        DriverStatus::UpdateAvailable
    );
}

#[test]
fn candidate_id_shape_is_namespaced_and_stable() {
    let identity = candidate("PCI\\VEN_A&DEV_B", 1).identity;
    let id: CandidateId = identity.id();
    assert!(id.0.starts_with("wua-"));
    assert_eq!(id, identity.id());
}
