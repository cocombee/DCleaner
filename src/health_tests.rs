use super::*;
use crate::domain::{Candidate, CategoryResult};
use std::path::PathBuf;

struct FixtureBin {
    items: Vec<recycle_bin::PortItem>,
}

impl recycle_bin::RecycleBinPort for FixtureBin {
    fn list(&mut self) -> Result<Vec<recycle_bin::PortItem>, recycle_bin::PortError> {
        Ok(self.items.clone())
    }

    fn metadata(
        &mut self,
        _item: &recycle_bin::PortItem,
    ) -> Result<RecycleBinSize, recycle_bin::PortError> {
        Ok(RecycleBinSize::Bytes(24))
    }

    fn restore_one(&mut self, _item: &recycle_bin::PortItem) -> Result<(), recycle_bin::PortError> {
        panic!("Health workflow test must not restore items")
    }

    fn purge_one(&mut self, _item: &recycle_bin::PortItem) -> Result<(), recycle_bin::PortError> {
        panic!("Health workflow test must not purge items")
    }
}

fn analysis_with_file(id: Uuid) -> Analysis {
    Analysis {
        id: Uuid::new_v4(),
        date: "fixture-time".into(),
        minimum_age_days: 1,
        elapsed_ms: 0,
        cancelled: false,
        categories: vec![CategoryResult {
            id: "chrome".into(),
            name: "Chrome cache".into(),
            group: "Applications".into(),
            files: vec![Candidate {
                id,
                path: PathBuf::from("fixture/cache/item.tmp"),
                root: PathBuf::from("fixture/cache"),
                size: 12,
                modified_ns: 1,
                created_ns: Some(1),
            }],
            skipped: 0,
            available: true,
            truncated: false,
        }],
    }
}

fn empty_privacy_report() -> PrivacyReport {
    PrivacyReport {
        id: Uuid::new_v4(),
        profiles_scanned: 0,
        records: Vec::new(),
        skipped: Vec::new(),
        skipped_count: 0,
        omitted_skip_details: 0,
        partial: false,
        truncated: false,
        cancelled: false,
        cookie_exempted: 0,
        categories_scanned: vec![PrivacyCategory::Cookies, PrivacyCategory::History],
        elapsed_ms: 0,
    }
}

fn privacy_fixture_report(file_id: Uuid) -> HealthStepReport {
    HealthStepReport::privacy(
        ProfileInventory::default(),
        empty_privacy_report(),
        analysis_with_file(file_id),
    )
}

#[test]
fn privacy_scan_requires_browser_conflict_review_before_start() {
    let mut workflow = HealthCoordinator::new();
    let browser = RunningBrowser {
        browser: privacy::Browser::Chrome,
        pid: 100,
        executable: "chrome.exe".into(),
    };
    workflow
        .inspect_privacy_browsers(Ok(vec![browser.clone()]))
        .unwrap();
    assert!(matches!(
        workflow.status(HealthStep::Privacy),
        HealthStepStatus::AwaitingBrowserReview { running, .. } if running == &vec![browser]
    ));
    assert!(workflow.begin_scan(HealthStep::Privacy).is_err());
    workflow.accept_browser_review().unwrap();
    workflow.begin_scan(HealthStep::Privacy).unwrap();
}

#[test]
fn process_status_failure_does_not_silently_allow_privacy_scan() {
    let mut workflow = HealthCoordinator::new();
    workflow
        .inspect_privacy_browsers(Err("fixture only".into()))
        .unwrap();
    assert!(matches!(
        workflow.status(HealthStep::Privacy),
        HealthStepStatus::AwaitingBrowserReview {
            status_unavailable: true,
            ..
        }
    ));
    assert!(workflow.accept_browser_review().is_err());
    assert!(workflow.begin_scan(HealthStep::Privacy).is_err());
}

#[test]
fn exact_file_ids_are_carried_to_the_existing_cleanup_owner() {
    let id = Uuid::new_v4();
    let report = privacy_fixture_report(id);
    let mut workflow = HealthCoordinator::new();
    workflow.inspect_privacy_browsers(Ok(Vec::new())).unwrap();
    workflow.begin_scan(HealthStep::Privacy).unwrap();
    workflow.complete_scan(report).unwrap();
    let count = workflow
        .select_category(HealthCategory::InternetTemporaryFiles, true)
        .unwrap();
    assert_eq!(count, 1);
    let plan = workflow.build_action_plan(false).unwrap();
    assert_eq!(plan.selected_count(), 1);
    assert!(matches!(
        &plan.actions()[0],
        HealthAction::MoveFilesToTrash { candidate_ids, .. } if candidate_ids == &vec![id]
    ));
    assert!(!plan.requires_permanent_confirmation());
    workflow.begin_effects(&plan, true, false).unwrap();
    assert!(
        workflow
            .complete_effects(
                plan.id(),
                vec![HealthEffectReceipt::Files(crate::domain::CleanupResult {
                    files: 1,
                    cleaned_ids: vec![Uuid::new_v4()],
                    ..Default::default()
                })]
            )
            .is_err()
    );
    workflow
        .complete_effects(
            plan.id(),
            vec![HealthEffectReceipt::Files(crate::domain::CleanupResult {
                files: 1,
                cleaned_ids: vec![id],
                ..Default::default()
            })],
        )
        .unwrap();
}

#[test]
fn unknown_selected_ids_and_cancelled_reports_cannot_authorize_actions() {
    let id = Uuid::new_v4();
    let report = privacy_fixture_report(id);
    assert!(
        report
            .build_action_plan(
                &HashSet::from([HealthFindingId::FileCandidate(Uuid::new_v4())]),
                false
            )
            .is_err()
    );

    let mut cancelled = privacy_fixture_report(id);
    cancelled.quality = HealthScanQuality::Cancelled;
    assert!(
        cancelled
            .build_action_plan(&HashSet::from([HealthFindingId::FileCandidate(id)]), true)
            .is_err()
    );
}

#[test]
fn partial_report_requires_acknowledgement_before_reviewed_cleanup() {
    let file_id = Uuid::new_v4();
    let mut workflow = HealthCoordinator::new();
    workflow.inspect_privacy_browsers(Ok(Vec::new())).unwrap();
    workflow.begin_scan(HealthStep::Privacy).unwrap();
    let mut report = privacy_fixture_report(file_id);
    report.quality = HealthScanQuality::Partial;
    report.categories[0].coverage = HealthCoverage::Partial {
        reason: "fixture incomplete".into(),
    };
    workflow.complete_scan(report).unwrap();
    workflow.select_all().unwrap();
    assert!(workflow.build_action_plan(false).is_err());
    let plan = workflow.build_action_plan(true).unwrap();
    workflow.begin_effects(&plan, true, false).unwrap();
    workflow
        .complete_effects(
            plan.id(),
            vec![HealthEffectReceipt::Files(crate::domain::CleanupResult {
                files: 1,
                cleaned_ids: vec![file_id],
                ..Default::default()
            })],
        )
        .unwrap();
    assert!(matches!(
        workflow.status(HealthStep::Privacy),
        HealthStepStatus::Results {
            quality: HealthEffectQuality::Complete,
            ..
        }
    ));
}

#[test]
fn skipped_steps_advance_in_shipped_order_and_finish_at_summary() {
    let mut workflow = HealthCoordinator::new();
    workflow.inspect_privacy_browsers(Ok(Vec::new())).unwrap();
    workflow.skip_current_step().unwrap();
    assert_eq!(workflow.advance().unwrap(), Some(HealthStep::Space));
    workflow.skip_current_step().unwrap();
    assert_eq!(workflow.advance().unwrap(), Some(HealthStep::ResolveIssues));
    workflow.skip_current_step().unwrap();
    assert_eq!(workflow.advance().unwrap(), None);
    assert_eq!(workflow.current_step(), None);
}

#[test]
fn issue_step_keeps_missing_services_and_classifier_visible() {
    let startup = StartupInventory {
        section: crate::startup::StartupSection::StartupApps,
        quality: InventoryQuality::Complete,
        entries: Vec::new(),
        sources: Vec::new(),
    };
    let report = HealthStepReport::resolve_issues(startup, Ok(SoftwareSnapshot::default()));
    assert_eq!(report.quality, HealthScanQuality::Partial);
    assert!(report.categories.iter().any(|category| {
        category.category == HealthCategory::StartupAppsForReview
            && matches!(&category.coverage, HealthCoverage::NeedsReview { .. })
    }));
    assert!(report.categories.iter().any(|category| {
        category.category == HealthCategory::DriverUpdates
            && matches!(&category.coverage, HealthCoverage::Unsupported { .. })
    }));
    assert!(report.categories.iter().any(|category| {
        category.category == HealthCategory::BackgroundApps
            && matches!(&category.coverage, HealthCoverage::Unsupported { .. })
    }));
}

#[test]
fn startup_rows_remain_visible_but_not_actionable_without_a_recommendation() {
    let identity = crate::startup::EntryIdentity::StartupFolderItem {
        path: "fixture/startup-item.lnk".into(),
    };
    let startup = StartupInventory {
        section: crate::startup::StartupSection::StartupApps,
        quality: InventoryQuality::Complete,
        entries: vec![crate::startup::StartupEntry {
            id: StartupId::for_identity(&identity),
            section: crate::startup::StartupSection::StartupApps,
            program: FieldValue::Known {
                value: "Fixture app".into(),
            },
            publisher: FieldValue::NotApplicable,
            version: FieldValue::NotApplicable,
            file_path: FieldValue::Known {
                value: "fixture/app.exe".into(),
            },
            command: FieldValue::Known {
                value: "fixture/app.exe --startup".into(),
            },
            enabled: EnabledState::Enabled,
            identity,
            can_change_enabled: true,
            change_limitation: None,
        }],
        sources: Vec::new(),
    };
    let report = HealthStepReport::resolve_issues(startup, Ok(SoftwareSnapshot::default()));
    let finding = report
        .categories
        .iter()
        .find(|category| category.category == HealthCategory::StartupAppsForReview)
        .and_then(|category| category.findings.first())
        .unwrap();
    assert_eq!(finding.name, "Fixture app");
    assert!(!finding.actionable);
    assert!(
        report
            .build_action_plan(&HashSet::from([finding.id.clone()]), true)
            .is_err()
    );
}

#[test]
fn cancelled_scan_records_cancel_state_without_action_review() {
    let mut workflow = HealthCoordinator::new();
    workflow.inspect_privacy_browsers(Ok(Vec::new())).unwrap();
    workflow.begin_scan(HealthStep::Privacy).unwrap();
    workflow.request_cancel(HealthStep::Privacy).unwrap();
    assert!(matches!(
        workflow.status(HealthStep::Privacy),
        HealthStepStatus::Scanning {
            cancel_requested: true,
            ..
        }
    ));
    let mut report = privacy_fixture_report(Uuid::new_v4());
    report.quality = HealthScanQuality::Cancelled;
    workflow.complete_scan(report).unwrap();
    assert_eq!(
        workflow.status(HealthStep::Privacy),
        &HealthStepStatus::Cancelled
    );
    assert!(workflow.build_action_plan(true).is_err());
}

#[test]
fn cancelled_effects_with_prior_success_are_reported_as_partial() {
    let interrupted_after_one_file = HealthEffectReceipt::Files(crate::domain::CleanupResult {
        files: 1,
        cancelled: true,
        ..Default::default()
    });
    assert_eq!(
        classify_effect_receipts(&[interrupted_after_one_file]),
        HealthEffectQuality::Partial
    );

    let cancelled_before_any_effect = HealthEffectReceipt::Files(crate::domain::CleanupResult {
        cancelled: true,
        ..Default::default()
    });
    assert_eq!(
        classify_effect_receipts(&[cancelled_before_any_effect]),
        HealthEffectQuality::Cancelled
    );
}

#[test]
fn recycle_purge_needs_a_separate_acknowledgement_without_running_effects() {
    use std::ffi::OsString;

    let mut bin = FixtureBin {
        items: vec![recycle_bin::PortItem::new(
            b"fixture-token".to_vec(),
            OsString::from("discard.txt"),
            PathBuf::from("fixture/recycle-bin"),
            1,
        )],
    };
    let inventory = recycle_bin::inventory(&mut bin, &AtomicBool::new(false), |_, _| {});
    let report = HealthStepReport::space(empty_analysis(), inventory);
    let mut workflow = HealthCoordinator::new();
    workflow.skip_current_step().unwrap();
    assert_eq!(workflow.advance().unwrap(), Some(HealthStep::Space));
    workflow.begin_scan(HealthStep::Space).unwrap();
    workflow.complete_scan(report).unwrap();
    assert_eq!(
        workflow
            .select_category(HealthCategory::RecycleBin, true)
            .unwrap(),
        1
    );
    let plan = workflow.build_action_plan(true).unwrap();
    assert!(plan.requires_permanent_confirmation());
    assert!(workflow.begin_effects(&plan, true, false).is_err());
    assert!(matches!(
        workflow.status(HealthStep::Space),
        HealthStepStatus::ActionReview { .. }
    ));
    workflow.begin_effects(&plan, true, true).unwrap();
}
