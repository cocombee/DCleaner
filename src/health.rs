//! Health Check orchestration over the existing scan and effect owners.
//!
//! This module owns step state, category/row selections and reviewed action plans.
//! It does not delete files, purge the Recycle Bin, close browsers, change startup
//! state, or launch updates; callers delegate those operations to their owning
//! services after the user reviews the exact action plan.

use crate::{
    domain::{Analysis, Candidate},
    privacy::{
        self, CloseRequestReport, PrivacyCategory, PrivacyPlan, PrivacyReceipt, PrivacyReport,
        ProfileInventory, RunningBrowser,
    },
    recycle_bin::{
        self, InventoryCompletion, RecycleBinInventory, RecycleBinOperationReport, RecycleBinSize,
        ReviewedSelection,
    },
    software::{
        self, SoftwareItem, SoftwareSnapshot, SoftwareStatus, UpdateReceipt, UpdateVerification,
    },
    startup::{
        ChangeReceipt, EnabledState, FieldValue, InventoryQuality, StartupId, StartupInventory,
    },
};
use std::{collections::HashSet, path::Path, sync::atomic::AtomicBool};
use uuid::Uuid;

const HEALTH_FILE_MINIMUM_AGE_DAYS: u32 = 1;
const MAX_HEALTH_FINDINGS: usize = 50_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HealthStep {
    Privacy,
    Space,
    ResolveIssues,
}

impl HealthStep {
    pub const ORDER: [Self; 3] = [Self::Privacy, Self::Space, Self::ResolveIssues];

    pub fn next(self) -> Option<Self> {
        match self {
            Self::Privacy => Some(Self::Space),
            Self::Space => Some(Self::ResolveIssues),
            Self::ResolveIssues => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthCategory {
    InternetTemporaryFiles,
    Cookies,
    BrowsingHistory,
    RecycleBin,
    TemporarySystemFiles,
    ApplicationCache,
    StartupAppsForReview,
    OutdatedApplications,
    DriverUpdates,
    BackgroundApps,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HealthCoverage {
    Complete,
    Partial { reason: String },
    NeedsReview { reason: String },
    Unsupported { reason: String },
    Failed { reason: String },
}

impl HealthCoverage {
    fn incomplete(&self) -> bool {
        !matches!(self, Self::Complete)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum HealthFindingId {
    BrowserRecord(Uuid),
    FileCandidate(Uuid),
    RecycleBinItem(Uuid),
    StartupEntry(StartupId),
    SoftwareUpdate(SoftwareKey),
}

/// An exact current snapshot key for one updater row. The key is not a display name.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SoftwareKey(String);

impl SoftwareKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthFinding {
    pub id: HealthFindingId,
    pub category: HealthCategory,
    pub name: String,
    pub detail: Option<String>,
    pub size_bytes: Option<u64>,
    /// False means the source has no supported reviewed operation for this row.
    pub actionable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthCategoryReport {
    pub category: HealthCategory,
    pub coverage: HealthCoverage,
    pub findings: Vec<HealthFinding>,
    pub reported_items: usize,
    pub reported_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthScanQuality {
    Complete,
    Partial,
    Cancelled,
    Failed,
}

#[derive(Clone)]
pub enum HealthServiceData {
    Privacy {
        profiles: ProfileInventory,
        browser_records: PrivacyReport,
        browser_cache_files: Analysis,
    },
    Space {
        files: Analysis,
        recycle_bin: RecycleBinInventory,
    },
    ResolveIssues {
        startup: StartupInventory,
        software: Result<SoftwareSnapshot, String>,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Clone)]
pub struct HealthStepReport {
    pub id: Uuid,
    pub step: HealthStep,
    pub quality: HealthScanQuality,
    pub categories: Vec<HealthCategoryReport>,
    /// Safe user-facing notes from bounded native inventories.
    pub notes: Vec<String>,
    source: HealthServiceData,
}

impl HealthStepReport {
    /// Build privacy findings from the actual browser and cache scan snapshots.
    /// `browser_records` should scan only the Health Check categories (cookies and history).
    pub fn privacy(
        profiles: ProfileInventory,
        browser_records: PrivacyReport,
        browser_cache_files: Analysis,
    ) -> Self {
        let mut categories = Vec::new();
        let mut notes = Vec::new();

        if profiles.partial {
            notes.push(
                "Browser profile discovery was partial; some locations could not be confirmed."
                    .into(),
            );
        }
        if browser_records.skipped_count > 0 {
            notes.push(format!(
                "{} browser database source(s) were skipped or unavailable.",
                browser_records.skipped_count
            ));
        }

        let browser_cache =
            analysis_category_ids(&browser_cache_files, &["chrome", "edge", "firefox"]);
        categories.push(file_category(
            HealthCategory::InternetTemporaryFiles,
            &browser_cache_files,
            &browser_cache,
            "Browser cache analysis was cancelled.".into(),
        ));
        categories.push(privacy_category(
            HealthCategory::Cookies,
            PrivacyCategory::Cookies,
            &profiles,
            &browser_records,
        ));
        categories.push(privacy_category(
            HealthCategory::BrowsingHistory,
            PrivacyCategory::History,
            &profiles,
            &browser_records,
        ));

        let cancelled = browser_records.cancelled || browser_cache_files.cancelled;
        let quality = aggregate_quality(&categories, cancelled, false);
        Self {
            id: Uuid::new_v4(),
            step: HealthStep::Privacy,
            quality,
            categories,
            notes,
            source: HealthServiceData::Privacy {
                profiles,
                browser_records,
                browser_cache_files,
            },
        }
    }

    /// Build space findings from the existing file analysis and exact Recycle Bin inventory.
    pub fn space(files: Analysis, recycle_bin: RecycleBinInventory) -> Self {
        let mut categories = Vec::new();
        let mut notes = Vec::new();
        let temp = analysis_category_ids(&files, &["temp", "crash"]);
        let app_cache = analysis_category_ids(&files, &["chrome", "edge", "firefox"]);
        categories.push(file_category(
            HealthCategory::TemporarySystemFiles,
            &files,
            &temp,
            "Temporary-file analysis was cancelled.".into(),
        ));
        categories.push(file_category(
            HealthCategory::ApplicationCache,
            &files,
            &app_cache,
            "Application-cache analysis was cancelled.".into(),
        ));
        categories.push(recycle_bin_category(&recycle_bin));
        if !recycle_bin.issues.is_empty() {
            notes.push(format!(
                "{} Recycle Bin inventory issue(s) need review.",
                recycle_bin.issues.len()
            ));
        }
        let cancelled = files.cancelled || recycle_bin.completion == InventoryCompletion::Cancelled;
        let quality = aggregate_quality(&categories, cancelled, false);
        Self {
            id: Uuid::new_v4(),
            step: HealthStep::Space,
            quality,
            categories,
            notes,
            source: HealthServiceData::Space { files, recycle_bin },
        }
    }

    /// Build issue findings from the installed startup and software services.
    /// Missing proprietary driver/background-app classifiers remain explicit gaps.
    pub fn resolve_issues(
        startup: StartupInventory,
        software: Result<SoftwareSnapshot, String>,
    ) -> Self {
        let mut categories = vec![startup_category(&startup)];
        categories.push(software_category(&software));
        categories.push(unsupported_category(
            HealthCategory::DriverUpdates,
            "Driver-update results are not yet included in this Health Check scan.",
        ));
        categories.push(unsupported_category(
            HealthCategory::BackgroundApps,
            "No background-app optimizer classifier or verified sleep/wake service is integrated.",
        ));
        let notes = vec![
            "Startup entries are shown for review; the current startup inventory does not classify entries as unnecessary.".into(),
            "Driver updater and background-app optimizer results are unsupported and were not simulated.".into(),
        ];
        let quality = aggregate_quality(&categories, false, false);
        Self {
            id: Uuid::new_v4(),
            step: HealthStep::ResolveIssues,
            quality,
            categories,
            notes,
            source: HealthServiceData::ResolveIssues { startup, software },
        }
    }

    pub fn failed(step: HealthStep, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            id: Uuid::new_v4(),
            step,
            quality: HealthScanQuality::Failed,
            categories: Vec::new(),
            notes: vec![reason.clone()],
            source: HealthServiceData::Unavailable { reason },
        }
    }

    pub fn source(&self) -> &HealthServiceData {
        &self.source
    }

    pub fn actionable_findings(&self) -> impl Iterator<Item = &HealthFinding> {
        self.categories
            .iter()
            .flat_map(|category| &category.findings)
            .filter(|finding| finding.actionable)
    }

    pub fn finding(&self, id: HealthFindingId) -> Option<&HealthFinding> {
        self.categories
            .iter()
            .flat_map(|category| &category.findings)
            .find(|finding| finding.id == id)
    }

    fn build_action_plan(
        &self,
        selected: &HashSet<HealthFindingId>,
        acknowledge_partial: bool,
    ) -> Result<HealthActionPlan, String> {
        if self.quality == HealthScanQuality::Cancelled {
            return Err("A cancelled Health Check scan cannot authorize actions.".into());
        }
        if self.quality == HealthScanQuality::Failed {
            return Err("A failed Health Check scan cannot authorize actions.".into());
        }
        if self.quality == HealthScanQuality::Partial && !acknowledge_partial {
            return Err("Review the partial scan warning before continuing.".into());
        }
        if selected.is_empty() {
            return Err("Select current Health Check findings before continuing.".into());
        }

        let mut privacy_ids = Vec::new();
        let mut file_ids = Vec::new();
        let mut recycle_ids = Vec::new();
        let mut startup_ids = Vec::new();
        let mut software_items = Vec::new();
        let mut known = HashSet::new();
        for finding in self
            .categories
            .iter()
            .flat_map(|category| &category.findings)
        {
            if !selected.contains(&finding.id) {
                continue;
            }
            known.insert(finding.id.clone());
            if !finding.actionable {
                return Err("A selected finding has no supported reviewed action.".into());
            }
            match &finding.id {
                HealthFindingId::BrowserRecord(id) => privacy_ids.push(*id),
                HealthFindingId::FileCandidate(id) => file_ids.push(*id),
                HealthFindingId::RecycleBinItem(id) => recycle_ids.push(*id),
                HealthFindingId::StartupEntry(id) => startup_ids.push(id.clone()),
                HealthFindingId::SoftwareUpdate(key) => {
                    software_items.push(key.clone());
                }
            }
        }
        if known.len() != selected.len() {
            return Err("A selected finding is not in this current Health Check report.".into());
        }

        let mut actions = Vec::new();
        match &self.source {
            HealthServiceData::Privacy {
                browser_records,
                browser_cache_files,
                ..
            } => {
                if !privacy_ids.is_empty() {
                    actions.push(HealthAction::BrowserPrivacy(privacy::build_cleanup_plan(
                        browser_records,
                        &privacy_ids,
                    )?));
                }
                if !file_ids.is_empty() {
                    actions.push(file_cleanup_action(browser_cache_files, &file_ids)?);
                }
            }
            HealthServiceData::Space { files, recycle_bin } => {
                if !file_ids.is_empty() {
                    actions.push(file_cleanup_action(files, &file_ids)?);
                }
                if !recycle_ids.is_empty() {
                    let selection = recycle_bin::reviewed_selection(recycle_bin, &recycle_ids)?;
                    actions.push(HealthAction::PurgeRecycleBin(selection));
                }
            }
            HealthServiceData::ResolveIssues { startup, software } => {
                if !startup_ids.is_empty() {
                    validate_startup_selection(startup, &startup_ids)?;
                    actions.push(HealthAction::DisableStartup(startup_ids));
                }
                if !software_items.is_empty() {
                    let snapshot = software.as_ref().map_err(|_| {
                        "The current software-update inventory is unavailable.".to_owned()
                    })?;
                    let rows = select_software_rows(snapshot, &software_items)?;
                    actions.push(HealthAction::UpdateApplications(rows));
                }
            }
            HealthServiceData::Unavailable { .. } => {
                return Err("The Health Check source report is unavailable.".into());
            }
        }
        if actions.is_empty() {
            return Err("The selected findings have no compatible service action.".into());
        }
        Ok(HealthActionPlan {
            id: Uuid::new_v4(),
            report_id: self.id,
            step: self.step,
            actions,
            selected_count: selected.len(),
            partial_acknowledged: acknowledge_partial,
        })
    }
}

fn analysis_category_ids(analysis: &Analysis, ids: &[&str]) -> Vec<String> {
    analysis
        .categories
        .iter()
        .filter(|category| ids.contains(&category.id.as_str()))
        .map(|category| category.id.clone())
        .collect()
}

fn file_category(
    category: HealthCategory,
    analysis: &Analysis,
    category_ids: &[String],
    cancelled_reason: String,
) -> HealthCategoryReport {
    let source_categories = analysis
        .categories
        .iter()
        .filter(|item| category_ids.contains(&item.id))
        .collect::<Vec<_>>();
    let mut findings = Vec::new();
    let mut bytes = 0u64;
    let mut truncated = false;
    let mut skipped = 0usize;
    let mut unavailable = false;
    for source in &source_categories {
        truncated |= source.truncated;
        skipped += source.skipped;
        unavailable |= !source.available;
        for candidate in &source.files {
            if findings.len() >= MAX_HEALTH_FINDINGS {
                truncated = true;
                break;
            }
            bytes = bytes.saturating_add(candidate.size);
            findings.push(file_finding(category, candidate));
        }
    }
    let coverage = if analysis.cancelled {
        HealthCoverage::Partial {
            reason: cancelled_reason,
        }
    } else if source_categories.is_empty() {
        HealthCoverage::Unsupported {
            reason: "The platform file-scan service returned no matching categories.".into(),
        }
    } else if truncated || skipped > 0 || unavailable {
        HealthCoverage::Partial {
            reason: format!(
                "File inventory is incomplete ({} skipped; limit reached: {}).",
                skipped, truncated
            ),
        }
    } else {
        HealthCoverage::Complete
    };
    let reported_bytes = matches!(&coverage, HealthCoverage::Complete).then_some(bytes);
    HealthCategoryReport {
        category,
        coverage,
        reported_items: findings.len(),
        reported_bytes,
        findings,
    }
}

fn file_finding(category: HealthCategory, candidate: &Candidate) -> HealthFinding {
    let name = candidate
        .path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "File candidate".into());
    HealthFinding {
        id: HealthFindingId::FileCandidate(candidate.id),
        category,
        name,
        detail: None,
        size_bytes: Some(candidate.size),
        actionable: true,
    }
}

fn privacy_category(
    category: HealthCategory,
    source_category: PrivacyCategory,
    profiles: &ProfileInventory,
    report: &PrivacyReport,
) -> HealthCategoryReport {
    let found_profiles = !profiles.profiles.is_empty();
    let scanned = report.categories_scanned.contains(&source_category);
    let mut findings = Vec::new();
    let mut row_limit_reached = false;
    if scanned {
        let source_rows = report
            .records
            .iter()
            .filter(|row| row.category == source_category)
            .collect::<Vec<_>>();
        row_limit_reached = source_rows.len() > MAX_HEALTH_FINDINGS;
        for row in source_rows.into_iter().take(MAX_HEALTH_FINDINGS) {
            let label = if row.site.is_empty() {
                source_category_label(source_category).to_owned()
            } else {
                row.site.clone()
            };
            findings.push(HealthFinding {
                id: HealthFindingId::BrowserRecord(row.id),
                category,
                name: label,
                detail: Some(format!("{} · {}", row.browser.label(), row.profile_name)),
                size_bytes: None,
                actionable: true,
            });
        }
    }
    let coverage = if !scanned {
        HealthCoverage::Unsupported {
            reason: "This browser privacy category was not included in the scan.".into(),
        }
    } else if profiles.partial || report.partial || report.truncated || row_limit_reached {
        HealthCoverage::Partial {
            reason: if row_limit_reached {
                "Browser record display limit reached; scan results are incomplete.".into()
            } else {
                "Browser profile or database inventory is partial.".into()
            },
        }
    } else if !found_profiles && report.profiles_scanned == 0 {
        HealthCoverage::Complete
    } else {
        HealthCoverage::Complete
    };
    HealthCategoryReport {
        category,
        coverage,
        reported_items: findings.len(),
        reported_bytes: None,
        findings,
    }
}

fn source_category_label(category: PrivacyCategory) -> &'static str {
    match category {
        PrivacyCategory::History => "Browsing history",
        PrivacyCategory::Cookies => "Cookie record",
        PrivacyCategory::Downloads => "Download history",
    }
}

fn recycle_bin_category(inventory: &RecycleBinInventory) -> HealthCategoryReport {
    let mut findings = Vec::new();
    let mut bytes = 0u64;
    let mut sizes_known = true;
    let truncated = inventory.items.len() > MAX_HEALTH_FINDINGS;
    for item in inventory.items.iter().take(MAX_HEALTH_FINDINGS) {
        let size_bytes = match item.size() {
            Some(RecycleBinSize::Bytes(size)) => {
                bytes = bytes.saturating_add(size);
                Some(size)
            }
            Some(RecycleBinSize::Entries(_)) | None => {
                sizes_known = false;
                None
            }
        };
        findings.push(HealthFinding {
            id: HealthFindingId::RecycleBinItem(item.id()),
            category: HealthCategory::RecycleBin,
            name: item.name(),
            detail: Some(item.original_path().to_string_lossy().into_owned()),
            size_bytes,
            actionable: true,
        });
    }
    let coverage = match inventory.completion {
        InventoryCompletion::Complete if inventory.issues.is_empty() && !truncated => {
            HealthCoverage::Complete
        }
        InventoryCompletion::Complete | InventoryCompletion::Partial => HealthCoverage::Partial {
            reason: if truncated {
                "Recycle Bin display limit reached; inventory results are incomplete.".into()
            } else {
                "Recycle Bin inventory has unreadable or omitted entries.".into()
            },
        },
        InventoryCompletion::Cancelled => HealthCoverage::Partial {
            reason: "Recycle Bin inventory was cancelled.".into(),
        },
        InventoryCompletion::Failed => HealthCoverage::Failed {
            reason: "Recycle Bin inventory failed.".into(),
        },
        InventoryCompletion::Unsupported => HealthCoverage::Unsupported {
            reason: "Recycle Bin inventory is unsupported on this platform.".into(),
        },
    };
    let reported_bytes =
        (sizes_known && matches!(&coverage, HealthCoverage::Complete)).then_some(bytes);
    HealthCategoryReport {
        category: HealthCategory::RecycleBin,
        coverage,
        reported_items: findings.len(),
        reported_bytes,
        findings,
    }
}

fn startup_category(inventory: &StartupInventory) -> HealthCategoryReport {
    let mut findings = Vec::new();
    let truncated = inventory.entries.len() > MAX_HEALTH_FINDINGS;
    for entry in inventory.entries.iter().take(MAX_HEALTH_FINDINGS) {
        let name = match &entry.program {
            FieldValue::Known { value } if !value.trim().is_empty() => value.clone(),
            FieldValue::Unknown { .. } | FieldValue::NotApplicable | FieldValue::Known { .. } => {
                "Unknown startup entry".into()
            }
        };
        findings.push(HealthFinding {
            id: HealthFindingId::StartupEntry(entry.id.clone()),
            category: HealthCategory::StartupAppsForReview,
            name,
            detail: None,
            size_bytes: None,
            // Health Check does not have a recommendation classifier yet. Listing
            // an enabled item is not evidence that disabling it is appropriate.
            actionable: false,
        });
    }
    let coverage = if truncated {
        HealthCoverage::Partial {
            reason: "Startup-entry display limit reached; inventory results are incomplete.".into(),
        }
    } else {
        match inventory.quality {
            InventoryQuality::Complete => HealthCoverage::NeedsReview {
                reason: "The native inventory does not determine whether an entry is unnecessary."
                    .into(),
            },
            InventoryQuality::Partial => HealthCoverage::Partial {
                reason: "Startup inventory is partial; recommendations are unavailable.".into(),
            },
            InventoryQuality::Unavailable => HealthCoverage::Failed {
                reason: "Startup inventory is unavailable on this platform.".into(),
            },
        }
    };
    HealthCategoryReport {
        category: HealthCategory::StartupAppsForReview,
        coverage,
        reported_items: findings.len(),
        reported_bytes: None,
        findings,
    }
}

fn software_category(snapshot: &Result<SoftwareSnapshot, String>) -> HealthCategoryReport {
    let Ok(snapshot) = snapshot else {
        return HealthCategoryReport {
            category: HealthCategory::OutdatedApplications,
            coverage: HealthCoverage::Failed {
                reason: "Software update inventory is unavailable; open Software Updater for its diagnostic.".into(),
            },
            findings: Vec::new(),
            reported_items: 0,
            reported_bytes: None,
        };
    };
    let mut findings = Vec::new();
    let truncated = snapshot
        .items
        .iter()
        .filter(|item| item.status == SoftwareStatus::UpdateAvailable)
        .count()
        > MAX_HEALTH_FINDINGS;
    for item in snapshot
        .items
        .iter()
        .filter(|item| item.status == SoftwareStatus::UpdateAvailable)
        .take(MAX_HEALTH_FINDINGS)
    {
        findings.push(HealthFinding {
            id: HealthFindingId::SoftwareUpdate(SoftwareKey(item.row_key())),
            category: HealthCategory::OutdatedApplications,
            name: item.row.name.clone(),
            detail: Some(format!(
                "{} → {}",
                item.row.installed_version.as_deref().unwrap_or("unknown"),
                item.row.available_version.as_deref().unwrap_or("unknown")
            )),
            size_bytes: None,
            actionable: item.can_update(),
        });
    }
    let coverage = if truncated {
        HealthCoverage::Partial {
            reason: "Software-update display limit reached; inventory results are incomplete."
                .into(),
        }
    } else if !snapshot.registration_issues.is_empty() {
        HealthCoverage::Partial {
            reason: format!(
                "{} software registration source(s) had inventory issues.",
                snapshot.registration_issues.len()
            ),
        }
    } else {
        HealthCoverage::Complete
    };
    HealthCategoryReport {
        category: HealthCategory::OutdatedApplications,
        reported_items: findings.len(),
        reported_bytes: None,
        coverage,
        findings,
    }
}

fn unsupported_category(category: HealthCategory, reason: &str) -> HealthCategoryReport {
    HealthCategoryReport {
        category,
        coverage: HealthCoverage::Unsupported {
            reason: reason.into(),
        },
        findings: Vec::new(),
        reported_items: 0,
        reported_bytes: None,
    }
}

fn aggregate_quality(
    categories: &[HealthCategoryReport],
    cancelled: bool,
    failed: bool,
) -> HealthScanQuality {
    if cancelled {
        HealthScanQuality::Cancelled
    } else if failed {
        HealthScanQuality::Failed
    } else if categories
        .iter()
        .any(|category| category.coverage.incomplete())
    {
        HealthScanQuality::Partial
    } else {
        HealthScanQuality::Complete
    }
}

fn file_cleanup_action(analysis: &Analysis, ids: &[Uuid]) -> Result<HealthAction, String> {
    if analysis.cancelled {
        return Err("A cancelled file analysis cannot authorize cleanup.".into());
    }
    if ids.is_empty() {
        return Err("Select files from the current Health Check analysis.".into());
    }
    let known = analysis
        .categories
        .iter()
        .flat_map(|category| &category.files)
        .map(|candidate| candidate.id)
        .collect::<HashSet<_>>();
    if ids.iter().any(|id| !known.contains(id)) {
        return Err("A selected file is not in the current analysis.".into());
    }
    Ok(HealthAction::MoveFilesToTrash {
        analysis: analysis.clone(),
        candidate_ids: deduplicate(ids),
    })
}

fn validate_startup_selection(
    inventory: &StartupInventory,
    ids: &[StartupId],
) -> Result<(), String> {
    let by_id = inventory
        .entries
        .iter()
        .map(|entry| (entry.id.clone(), entry))
        .collect::<std::collections::HashMap<_, _>>();
    for id in ids {
        let Some(entry) = by_id.get(id) else {
            return Err("A startup selection is not in the current Health Check inventory.".into());
        };
        if !entry.can_change_enabled || entry.enabled != EnabledState::Enabled {
            return Err(
                "A startup selection is not currently eligible for a reviewed disable.".into(),
            );
        }
    }
    Ok(())
}

fn select_software_rows(
    snapshot: &SoftwareSnapshot,
    keys: &[SoftwareKey],
) -> Result<Vec<SoftwareItem>, String> {
    let mut rows = Vec::new();
    let mut used = HashSet::new();
    for key in keys {
        if !used.insert(key.0.clone()) {
            continue;
        }
        let Some(row) = snapshot.items.iter().find(|row| row.row_key() == key.0) else {
            return Err("A software update selection is not in the current inventory.".into());
        };
        if row.status != SoftwareStatus::UpdateAvailable || !row.can_update() {
            return Err("A selected software row no longer has a supported update request.".into());
        }
        rows.push(row.clone());
    }
    if rows.is_empty() {
        return Err("Select updateable applications from the current inventory.".into());
    }
    Ok(rows)
}

fn deduplicate(ids: &[Uuid]) -> Vec<Uuid> {
    let mut seen = HashSet::new();
    ids.iter().copied().filter(|id| seen.insert(*id)).collect()
}

pub enum HealthAction {
    BrowserPrivacy(PrivacyPlan),
    MoveFilesToTrash {
        analysis: Analysis,
        candidate_ids: Vec<Uuid>,
    },
    PurgeRecycleBin(ReviewedSelection),
    DisableStartup(Vec<StartupId>),
    UpdateApplications(Vec<SoftwareItem>),
}

impl HealthAction {
    pub fn requires_permanent_confirmation(&self) -> bool {
        matches!(self, Self::PurgeRecycleBin(_))
    }

    pub fn kind(&self) -> HealthActionKind {
        match self {
            Self::BrowserPrivacy(_) => HealthActionKind::BrowserPrivacy,
            Self::MoveFilesToTrash { .. } => HealthActionKind::FilesToTrash,
            Self::PurgeRecycleBin(_) => HealthActionKind::RecycleBinPurge,
            Self::DisableStartup(_) => HealthActionKind::StartupDisable,
            Self::UpdateApplications(_) => HealthActionKind::SoftwareUpdate,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HealthActionKind {
    BrowserPrivacy,
    FilesToTrash,
    RecycleBinPurge,
    StartupDisable,
    SoftwareUpdate,
}

pub struct HealthActionPlan {
    id: Uuid,
    report_id: Uuid,
    step: HealthStep,
    actions: Vec<HealthAction>,
    selected_count: usize,
    partial_acknowledged: bool,
}

impl HealthActionPlan {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn report_id(&self) -> Uuid {
        self.report_id
    }

    pub fn step(&self) -> HealthStep {
        self.step
    }

    pub fn actions(&self) -> &[HealthAction] {
        &self.actions
    }

    pub fn selected_count(&self) -> usize {
        self.selected_count
    }

    pub fn requires_permanent_confirmation(&self) -> bool {
        self.actions
            .iter()
            .any(HealthAction::requires_permanent_confirmation)
    }

    pub fn partial_acknowledged(&self) -> bool {
        self.partial_acknowledged
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthProgress {
    pub completed: u64,
    pub total: Option<u64>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HealthStepStatus {
    Ready,
    AwaitingBrowserReview {
        running: Vec<RunningBrowser>,
        status_unavailable: bool,
    },
    Scanning {
        progress: HealthProgress,
        cancel_requested: bool,
    },
    Reviewing {
        report_id: Uuid,
        quality: HealthScanQuality,
    },
    ActionReview {
        plan_id: Uuid,
    },
    Applying {
        plan_id: Uuid,
    },
    Results {
        report_id: Uuid,
        quality: HealthEffectQuality,
    },
    Skipped,
    Cancelled,
    Failed {
        message: String,
    },
}

impl Default for HealthStepStatus {
    fn default() -> Self {
        Self::Ready
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthEffectQuality {
    Complete,
    Partial,
    Cancelled,
    Uncertain,
}

#[derive(Clone, Debug)]
pub enum HealthEffectReceipt {
    BrowserPrivacy(PrivacyReceipt),
    Files(crate::domain::CleanupResult),
    RecycleBin(RecycleBinOperationReport),
    Startup(ChangeReceipt),
    Software(UpdateReceipt),
}

#[derive(Clone)]
struct StepRecord {
    status: HealthStepStatus,
    report: Option<HealthStepReport>,
    selected: HashSet<HealthFindingId>,
    pending_plan_id: Option<Uuid>,
    pending_receipt_kinds: Vec<HealthActionKind>,
    effect_message: Option<String>,
    receipts: Vec<HealthEffectReceipt>,
}

impl Default for StepRecord {
    fn default() -> Self {
        Self {
            status: HealthStepStatus::Ready,
            report: None,
            selected: HashSet::new(),
            pending_plan_id: None,
            pending_receipt_kinds: Vec::new(),
            effect_message: None,
            receipts: Vec::new(),
        }
    }
}

pub struct HealthCoordinator {
    id: Uuid,
    current: Option<HealthStep>,
    privacy_gate_reviewed: bool,
    records: [StepRecord; 3],
}

impl Default for HealthCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthCoordinator {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            current: Some(HealthStep::Privacy),
            privacy_gate_reviewed: false,
            records: std::array::from_fn(|_| StepRecord::default()),
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn current_step(&self) -> Option<HealthStep> {
        self.current
    }

    pub fn status(&self, step: HealthStep) -> &HealthStepStatus {
        &self.records[index(step)].status
    }

    pub fn report(&self, step: HealthStep) -> Option<&HealthStepReport> {
        self.records[index(step)].report.as_ref()
    }

    pub fn current_report(&self) -> Option<&HealthStepReport> {
        self.current.and_then(|step| self.report(step))
    }

    pub fn effect_receipts(&self, step: HealthStep) -> &[HealthEffectReceipt] {
        &self.records[index(step)].receipts
    }

    pub fn effect_message(&self, step: HealthStep) -> Option<&str> {
        self.records[index(step)].effect_message.as_deref()
    }

    /// Record a fresh native process check before the privacy scan. A nonempty list
    /// must be reviewed in the browser selection dialog; it does not force a close.
    pub fn inspect_privacy_browsers(
        &mut self,
        running: Result<Vec<RunningBrowser>, String>,
    ) -> Result<(), String> {
        self.require_current(HealthStep::Privacy)?;
        if !matches!(
            self.status(HealthStep::Privacy),
            HealthStepStatus::Ready | HealthStepStatus::AwaitingBrowserReview { .. }
        ) {
            return Err("Running browsers can be checked only before the privacy scan.".into());
        }
        match running {
            Ok(processes) => {
                self.privacy_gate_reviewed = false;
                if processes.is_empty() {
                    self.privacy_gate_reviewed = true;
                    self.records[index(HealthStep::Privacy)].status = HealthStepStatus::Ready;
                } else {
                    self.records[index(HealthStep::Privacy)].status =
                        HealthStepStatus::AwaitingBrowserReview {
                            running: processes,
                            status_unavailable: false,
                        };
                }
            }
            Err(_) => {
                self.privacy_gate_reviewed = false;
                self.records[index(HealthStep::Privacy)].status =
                    HealthStepStatus::AwaitingBrowserReview {
                        running: Vec::new(),
                        status_unavailable: true,
                    };
            }
        }
        Ok(())
    }

    /// Continue the read-only scan after the user chooses not to close the listed browsers.
    /// Later browser cleanup remains subject to the privacy service's fresh process check.
    pub fn accept_browser_review(&mut self) -> Result<(), String> {
        self.require_current(HealthStep::Privacy)?;
        let record = &mut self.records[index(HealthStep::Privacy)];
        match &record.status {
            HealthStepStatus::AwaitingBrowserReview {
                status_unavailable: false,
                ..
            } => {
                self.privacy_gate_reviewed = true;
                record.status = HealthStepStatus::Ready;
                Ok(())
            }
            HealthStepStatus::AwaitingBrowserReview {
                status_unavailable: true,
                ..
            } => Err("Running-browser status must be checked before the privacy scan.".into()),
            _ => Err("There is no pending browser conflict to accept.".into()),
        }
    }

    /// Reconcile a graceful close request. Remaining or stale processes require another
    /// read/review; the coordinator never closes or terminates processes itself.
    pub fn record_browser_close(&mut self, report: &CloseRequestReport) -> Result<(), String> {
        self.require_current(HealthStep::Privacy)?;
        if !matches!(
            self.status(HealthStep::Privacy),
            HealthStepStatus::AwaitingBrowserReview { .. }
        ) {
            return Err("There is no pending browser close review.".into());
        }
        if report.errors.is_empty()
            && report.stale_selection.is_empty()
            && report.still_running.is_empty()
        {
            self.privacy_gate_reviewed = true;
            self.records[index(HealthStep::Privacy)].status = HealthStepStatus::Ready;
        } else {
            self.privacy_gate_reviewed = false;
            self.records[index(HealthStep::Privacy)].status =
                HealthStepStatus::AwaitingBrowserReview {
                    running: report.still_running.clone(),
                    status_unavailable: !report.errors.is_empty()
                        || !report.stale_selection.is_empty(),
                };
        }
        Ok(())
    }

    pub fn begin_scan(&mut self, step: HealthStep) -> Result<(), String> {
        self.require_current(step)?;
        if step == HealthStep::Privacy && !self.privacy_gate_reviewed {
            return Err("Review running browsers before scanning privacy data.".into());
        }
        if !matches!(
            self.status(step),
            HealthStepStatus::Ready
                | HealthStepStatus::Reviewing { .. }
                | HealthStepStatus::Cancelled
                | HealthStepStatus::Failed { .. }
                | HealthStepStatus::Results { .. }
        ) {
            return Err("This Health Check step is not ready to scan.".into());
        }
        let record = &mut self.records[index(step)];
        record.report = None;
        record.selected.clear();
        record.pending_plan_id = None;
        record.pending_receipt_kinds.clear();
        record.effect_message = None;
        record.receipts.clear();
        record.status = HealthStepStatus::Scanning {
            progress: HealthProgress {
                completed: 0,
                total: None,
                detail: None,
            },
            cancel_requested: false,
        };
        Ok(())
    }

    /// A cancellation before any reviewed owner operation began is a terminal
    /// cancelled result, not an effect failure or an uncertain change.
    pub fn cancel_effects_before_any(
        &mut self,
        plan_id: Uuid,
        message: impl Into<String>,
    ) -> Result<(), String> {
        let step = self
            .current
            .ok_or("Health Check is at its final summary.")?;
        let record = &mut self.records[index(step)];
        if !matches!(&record.status, HealthStepStatus::Applying { plan_id: current } if *current == plan_id)
        {
            return Err("Health Check cancellation does not match the active plan.".into());
        }
        record.pending_plan_id = None;
        record.pending_receipt_kinds.clear();
        record.effect_message = Some(message.into());
        record.status = HealthStepStatus::Cancelled;
        Ok(())
    }

    pub fn progress(
        &mut self,
        step: HealthStep,
        completed: u64,
        total: Option<u64>,
        detail: Option<String>,
    ) -> Result<(), String> {
        if total.is_some_and(|total| completed > total) {
            return Err("Health Check progress cannot exceed its reported total.".into());
        }
        self.require_current(step)?;
        let record = &mut self.records[index(step)];
        let HealthStepStatus::Scanning {
            cancel_requested, ..
        } = &record.status
        else {
            return Err("Health Check progress arrived outside a scan.".into());
        };
        let cancel_requested = *cancel_requested;
        record.status = HealthStepStatus::Scanning {
            progress: HealthProgress {
                completed,
                total,
                detail,
            },
            cancel_requested,
        };
        Ok(())
    }

    pub fn request_cancel(&mut self, step: HealthStep) -> Result<(), String> {
        self.require_current(step)?;
        let record = &mut self.records[index(step)];
        let HealthStepStatus::Scanning {
            progress,
            cancel_requested: _,
        } = &record.status
        else {
            return Err("Only an active Health Check scan can be cancelled.".into());
        };
        let progress = progress.clone();
        record.status = HealthStepStatus::Scanning {
            progress,
            cancel_requested: true,
        };
        Ok(())
    }

    pub fn complete_scan(&mut self, report: HealthStepReport) -> Result<(), String> {
        self.require_current(report.step)?;
        if !matches!(self.status(report.step), HealthStepStatus::Scanning { .. }) {
            return Err("Health Check scan result arrived outside an active scan.".into());
        }
        let record = &mut self.records[index(report.step)];
        record.selected.clear();
        record.pending_plan_id = None;
        record.pending_receipt_kinds.clear();
        record.status = match report.quality {
            HealthScanQuality::Complete | HealthScanQuality::Partial => {
                HealthStepStatus::Reviewing {
                    report_id: report.id,
                    quality: report.quality,
                }
            }
            HealthScanQuality::Cancelled => HealthStepStatus::Cancelled,
            HealthScanQuality::Failed => HealthStepStatus::Failed {
                message: report
                    .notes
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Health Check scan failed.".into()),
            },
        };
        record.report = Some(report);
        Ok(())
    }

    pub fn fail_scan(
        &mut self,
        step: HealthStep,
        message: impl Into<String>,
    ) -> Result<(), String> {
        self.require_current(step)?;
        if !matches!(self.status(step), HealthStepStatus::Scanning { .. }) {
            return Err("Health Check failure arrived outside an active scan.".into());
        }
        self.records[index(step)].status = HealthStepStatus::Failed {
            message: message.into(),
        };
        Ok(())
    }

    pub fn select_finding(&mut self, id: HealthFindingId, selected: bool) -> Result<(), String> {
        let step = self
            .current
            .ok_or("Health Check is at its final summary.")?;
        let record = &mut self.records[index(step)];
        if !matches!(&record.status, HealthStepStatus::Reviewing { .. }) {
            return Err("Findings can be selected only in the current review.".into());
        }
        let report = record
            .report
            .as_ref()
            .ok_or("The current scan report is unavailable.")?;
        let finding = report
            .finding(id.clone())
            .ok_or("The selected finding is not in the current report.")?;
        if selected && !finding.actionable {
            return Err("This finding has no supported reviewed action.".into());
        }
        if selected {
            record.selected.insert(id);
        } else {
            record.selected.remove(&id);
        }
        Ok(())
    }

    pub fn select_category(
        &mut self,
        category: HealthCategory,
        selected: bool,
    ) -> Result<usize, String> {
        let step = self
            .current
            .ok_or("Health Check is at its final summary.")?;
        let record = &mut self.records[index(step)];
        if !matches!(&record.status, HealthStepStatus::Reviewing { .. }) {
            return Err("Categories can be selected only in the current review.".into());
        }
        let report = record
            .report
            .as_ref()
            .ok_or("The current scan report is unavailable.")?;
        let matching = report
            .categories
            .iter()
            .filter(|result| result.category == category)
            .flat_map(|result| &result.findings)
            .filter(|finding| !selected || finding.actionable)
            .map(|finding| finding.id.clone())
            .collect::<Vec<_>>();
        if matching.is_empty()
            && !report
                .categories
                .iter()
                .any(|result| result.category == category)
        {
            return Err("The selected category is not part of this Health Check step.".into());
        }
        for id in &matching {
            if selected {
                record.selected.insert(id.clone());
            } else {
                record.selected.remove(id);
            }
        }
        Ok(matching.len())
    }

    pub fn select_all(&mut self) -> Result<usize, String> {
        let step = self
            .current
            .ok_or("Health Check is at its final summary.")?;
        let report = self.records[index(step)]
            .report
            .as_ref()
            .ok_or("The current scan report is unavailable.")?;
        let ids = report
            .actionable_findings()
            .map(|finding| finding.id.clone())
            .collect::<Vec<_>>();
        let count = ids.len();
        for id in ids {
            self.select_finding(id, true)?;
        }
        Ok(count)
    }

    pub fn deselect_all(&mut self) -> Result<(), String> {
        let step = self
            .current
            .ok_or("Health Check is at its final summary.")?;
        if !matches!(
            self.status(step),
            HealthStepStatus::Reviewing { .. } | HealthStepStatus::ActionReview { .. }
        ) {
            return Err("Selections can be cleared only during review.".into());
        }
        self.records[index(step)].selected.clear();
        self.records[index(step)].pending_plan_id = None;
        self.records[index(step)].pending_receipt_kinds.clear();
        self.records[index(step)].status = self.records[index(step)]
            .report
            .as_ref()
            .map(|report| HealthStepStatus::Reviewing {
                report_id: report.id,
                quality: report.quality,
            })
            .unwrap_or(HealthStepStatus::Ready);
        Ok(())
    }

    pub fn selected_ids(&self, step: HealthStep) -> Vec<HealthFindingId> {
        let record = &self.records[index(step)];
        let Some(report) = &record.report else {
            return Vec::new();
        };
        report
            .categories
            .iter()
            .flat_map(|category| &category.findings)
            .filter(|finding| record.selected.contains(&finding.id))
            .map(|finding| finding.id.clone())
            .collect()
    }

    pub fn build_action_plan(
        &mut self,
        acknowledge_partial: bool,
    ) -> Result<HealthActionPlan, String> {
        let step = self
            .current
            .ok_or("Health Check is at its final summary.")?;
        let record = &mut self.records[index(step)];
        if !matches!(&record.status, HealthStepStatus::Reviewing { .. }) {
            return Err("An action plan requires a current scan review.".into());
        }
        let report = record
            .report
            .as_ref()
            .ok_or("The current scan report is unavailable.")?;
        let plan = report.build_action_plan(&record.selected, acknowledge_partial)?;
        record.pending_receipt_kinds = expected_receipt_kinds(&plan.actions);
        record.pending_plan_id = Some(plan.id);
        record.status = HealthStepStatus::ActionReview { plan_id: plan.id };
        Ok(plan)
    }

    pub fn cancel_action_review(&mut self, plan_id: Uuid) -> Result<(), String> {
        let step = self
            .current
            .ok_or("Health Check is at its final summary.")?;
        let record = &mut self.records[index(step)];
        if record.pending_plan_id != Some(plan_id)
            || !matches!(&record.status, HealthStepStatus::ActionReview { plan_id: current } if *current == plan_id)
        {
            return Err("The action review is stale.".into());
        }
        record.pending_plan_id = None;
        record.pending_receipt_kinds.clear();
        record.status = record
            .report
            .as_ref()
            .map(|report| HealthStepStatus::Reviewing {
                report_id: report.id,
                quality: report.quality,
            })
            .unwrap_or(HealthStepStatus::Ready);
        Ok(())
    }

    /// Start owner-service effects only after the user explicitly confirms the plan.
    pub fn begin_effects(
        &mut self,
        plan: &HealthActionPlan,
        confirmed: bool,
        permanent_purge_confirmed: bool,
    ) -> Result<(), String> {
        let step = self
            .current
            .ok_or("Health Check is at its final summary.")?;
        if !confirmed {
            return Err("Health Check actions require explicit review confirmation.".into());
        }
        if plan.step != step
            || self.records[index(step)].pending_plan_id != Some(plan.id)
            || !matches!(self.status(step), HealthStepStatus::ActionReview { plan_id } if *plan_id == plan.id)
        {
            return Err("The Health Check action plan is stale.".into());
        }
        if plan.requires_permanent_confirmation() && !permanent_purge_confirmed {
            return Err(
                "Permanent Recycle Bin purge requires its separate acknowledgement.".into(),
            );
        }
        self.records[index(step)].status = HealthStepStatus::Applying { plan_id: plan.id };
        Ok(())
    }

    pub fn complete_effects(
        &mut self,
        plan_id: Uuid,
        receipts: Vec<HealthEffectReceipt>,
    ) -> Result<(), String> {
        self.complete_effects_with_issues(plan_id, receipts, Vec::new(), false)
    }

    /// Complete a reviewed batch while preserving owner-service failures that did
    /// not produce a receipt. An attempted effect with an unknown outcome is never
    /// reported as complete.
    pub fn complete_effects_with_issues(
        &mut self,
        plan_id: Uuid,
        receipts: Vec<HealthEffectReceipt>,
        issues: Vec<String>,
        uncertain: bool,
    ) -> Result<(), String> {
        let step = self
            .current
            .ok_or("Health Check is at its final summary.")?;
        let record = &mut self.records[index(step)];
        if !matches!(&record.status, HealthStepStatus::Applying { plan_id: current } if *current == plan_id)
        {
            return Err("Health Check effect result does not match the active plan.".into());
        }
        if receipts.is_empty() {
            return Err("No owner-service receipt was provided for the reviewed action.".into());
        }
        let mut expected = record.pending_receipt_kinds.iter().fold(
            std::collections::HashMap::new(),
            |mut counts, kind| {
                *counts.entry(*kind).or_insert(0usize) += 1;
                counts
            },
        );
        for receipt in &receipts {
            let kind = receipt_kind(receipt);
            let Some(count) = expected.get_mut(&kind) else {
                return Err(
                    "An owner-service receipt does not match the reviewed Health Check actions."
                        .into(),
                );
            };
            if *count == 0 {
                return Err(
                    "An owner-service returned more receipts than the reviewed action selected."
                        .into(),
                );
            }
            *count -= 1;
        }
        let missing_receipts = expected.values().any(|count| *count > 0);
        let missing_targets = validate_receipt_targets(
            &receipts,
            &record.selected,
            record
                .report
                .as_ref()
                .ok_or("The report for this action is unavailable.")?,
        )?;
        let receipt_quality = classify_effect_receipts(&receipts);
        let quality = if uncertain || receipt_quality == HealthEffectQuality::Uncertain {
            HealthEffectQuality::Uncertain
        } else if receipt_quality == HealthEffectQuality::Cancelled {
            HealthEffectQuality::Cancelled
        } else if missing_receipts || missing_targets || !issues.is_empty() {
            HealthEffectQuality::Partial
        } else {
            receipt_quality
        };
        let report_id = record
            .report
            .as_ref()
            .map(|report| report.id)
            .ok_or("The report for this action is unavailable.")?;
        record.receipts = receipts;
        record.pending_plan_id = None;
        record.pending_receipt_kinds.clear();
        record.effect_message = (!issues.is_empty()).then(|| issues.join(" "));
        record.status = HealthStepStatus::Results { report_id, quality };
        Ok(())
    }

    pub fn fail_effects(
        &mut self,
        plan_id: Uuid,
        message: impl Into<String>,
        uncertain: bool,
    ) -> Result<(), String> {
        let step = self
            .current
            .ok_or("Health Check is at its final summary.")?;
        let record = &mut self.records[index(step)];
        if !matches!(&record.status, HealthStepStatus::Applying { plan_id: current } if *current == plan_id)
        {
            return Err("Health Check effect failure does not match the active plan.".into());
        }
        let report_id = record
            .report
            .as_ref()
            .map(|report| report.id)
            .ok_or("The report for this action is unavailable.")?;
        record.pending_plan_id = None;
        record.pending_receipt_kinds.clear();
        if uncertain {
            record.effect_message = Some(message.into());
            record.status = HealthStepStatus::Results {
                report_id,
                quality: HealthEffectQuality::Uncertain,
            };
        } else {
            record.effect_message = None;
            record.status = HealthStepStatus::Failed {
                message: message.into(),
            };
        }
        Ok(())
    }

    pub fn skip_current_step(&mut self) -> Result<(), String> {
        let step = self
            .current
            .ok_or("Health Check is at its final summary.")?;
        if matches!(
            self.status(step),
            HealthStepStatus::Scanning { .. } | HealthStepStatus::Applying { .. }
        ) {
            return Err("Stop the active operation before skipping this Health Check step.".into());
        }
        let record = &mut self.records[index(step)];
        record.status = HealthStepStatus::Skipped;
        record.pending_plan_id = None;
        record.pending_receipt_kinds.clear();
        Ok(())
    }

    pub fn advance(&mut self) -> Result<Option<HealthStep>, String> {
        let Some(step) = self.current else {
            return Ok(None);
        };
        if !matches!(
            self.status(step),
            HealthStepStatus::Results { .. }
                | HealthStepStatus::Skipped
                | HealthStepStatus::Cancelled
                | HealthStepStatus::Failed { .. }
        ) {
            return Err("Review, skip, or finish the current Health Check step first.".into());
        }
        self.current = step.next();
        if let Some(next) = self.current {
            self.records[index(next)].status = HealthStepStatus::Ready;
        }
        Ok(self.current)
    }

    fn require_current(&self, step: HealthStep) -> Result<(), String> {
        if self.current != Some(step) {
            return Err("This operation does not match the current Health Check step.".into());
        }
        Ok(())
    }
}

fn expected_receipt_kinds(actions: &[HealthAction]) -> Vec<HealthActionKind> {
    let mut expected = Vec::new();
    for action in actions {
        match action {
            HealthAction::BrowserPrivacy(_) => expected.push(HealthActionKind::BrowserPrivacy),
            HealthAction::MoveFilesToTrash { .. } => expected.push(HealthActionKind::FilesToTrash),
            HealthAction::PurgeRecycleBin(_) => expected.push(HealthActionKind::RecycleBinPurge),
            HealthAction::DisableStartup(ids) => expected.extend(std::iter::repeat_n(
                HealthActionKind::StartupDisable,
                ids.len(),
            )),
            HealthAction::UpdateApplications(items) => expected.extend(std::iter::repeat_n(
                HealthActionKind::SoftwareUpdate,
                items.len(),
            )),
        }
    }
    expected
}

fn receipt_kind(receipt: &HealthEffectReceipt) -> HealthActionKind {
    match receipt {
        HealthEffectReceipt::BrowserPrivacy(_) => HealthActionKind::BrowserPrivacy,
        HealthEffectReceipt::Files(_) => HealthActionKind::FilesToTrash,
        HealthEffectReceipt::RecycleBin(_) => HealthActionKind::RecycleBinPurge,
        HealthEffectReceipt::Startup(_) => HealthActionKind::StartupDisable,
        HealthEffectReceipt::Software(_) => HealthActionKind::SoftwareUpdate,
    }
}

/// Ensure owner receipts name only IDs in the reviewed selection. Missing IDs
/// are reported as partial so a bounded/cancelled owner operation stays honest.
fn validate_receipt_targets(
    receipts: &[HealthEffectReceipt],
    selected: &HashSet<HealthFindingId>,
    report: &HealthStepReport,
) -> Result<bool, String> {
    let mut browser_remaining = selected
        .iter()
        .filter_map(|id| match id {
            HealthFindingId::BrowserRecord(id) => Some(*id),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut file_remaining = selected
        .iter()
        .filter_map(|id| match id {
            HealthFindingId::FileCandidate(id) => Some(*id),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut recycle_remaining = selected
        .iter()
        .filter_map(|id| match id {
            HealthFindingId::RecycleBinItem(id) => Some(*id),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut startup_remaining = selected
        .iter()
        .filter_map(|id| match id {
            HealthFindingId::StartupEntry(id) => Some(id.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut software_remaining = selected
        .iter()
        .filter_map(|id| match id {
            HealthFindingId::SoftwareUpdate(key) => Some(key.0.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();

    let software_lookup = match &report.source {
        HealthServiceData::ResolveIssues {
            software: Ok(snapshot),
            ..
        } => snapshot
            .items
            .iter()
            .map(|item| (item.row_key(), item))
            .collect::<std::collections::HashMap<_, _>>(),
        _ => std::collections::HashMap::new(),
    };
    let mut missing = false;
    for receipt in receipts {
        match receipt {
            HealthEffectReceipt::BrowserPrivacy(receipt) => {
                if receipt.selected > browser_remaining.len() {
                    return Err(
                        "Browser cleanup receipt exceeds the reviewed record selection.".into(),
                    );
                }
                if receipt.selected < browser_remaining.len() {
                    missing = true;
                }
                // Privacy cleanup receipts are aggregate-only; the owner plan
                // holds the exact selected record IDs and validates each row.
                browser_remaining.clear();
            }
            HealthEffectReceipt::Files(receipt) => {
                if receipt.files != receipt.cleaned_ids.len() {
                    return Err("File cleanup receipt count does not match its cleaned IDs.".into());
                }
                let mut seen = HashSet::new();
                for id in &receipt.cleaned_ids {
                    if !seen.insert(*id) || !file_remaining.remove(id) {
                        return Err(
                            "File cleanup receipt contains an unselected or repeated ID.".into(),
                        );
                    }
                }
                for failed in &receipt.failed {
                    if failed.success
                        || !seen.insert(failed.file_id)
                        || !file_remaining.remove(&failed.file_id)
                    {
                        return Err("File cleanup receipt contains an unselected or inconsistent failure ID.".into());
                    }
                }
                if !receipt.cancelled
                    && !receipt.interrupted
                    && receipt.uncertain.is_empty()
                    && !file_remaining.is_empty()
                {
                    missing = true;
                }
                file_remaining.clear();
            }
            HealthEffectReceipt::RecycleBin(receipt) => {
                if receipt.operation != recycle_bin::RecycleBinOperation::Purge {
                    return Err(
                        "Health Check only accepts a Recycle Bin purge receipt for this action."
                            .into(),
                    );
                }
                let mut seen = HashSet::new();
                for item in &receipt.receipts {
                    if !seen.insert(item.item_id) || !recycle_remaining.remove(&item.item_id) {
                        return Err(
                            "Recycle Bin receipt contains an unselected or repeated item ID."
                                .into(),
                        );
                    }
                }
                if !recycle_remaining.is_empty() {
                    missing = true;
                }
                recycle_remaining.clear();
            }
            HealthEffectReceipt::Startup(receipt) => {
                if !startup_remaining.remove(&receipt.id) {
                    return Err(
                        "Startup receipt contains an unselected or repeated entry ID.".into(),
                    );
                }
            }
            HealthEffectReceipt::Software(receipt) => {
                let matching_key = software_remaining
                    .iter()
                    .find(|key| {
                        software_lookup.get(*key).is_some_and(|item| {
                            item.identity.as_ref() == Some(&receipt.identity)
                                && item.row.available_version.as_deref()
                                    == Some(receipt.target_version.as_str())
                        })
                    })
                    .cloned();
                let Some(key) = matching_key else {
                    return Err(
                        "Software update receipt does not match a selected current row.".into(),
                    );
                };
                software_remaining.remove(&key);
            }
        }
    }
    missing |= !browser_remaining.is_empty()
        || !file_remaining.is_empty()
        || !recycle_remaining.is_empty()
        || !startup_remaining.is_empty()
        || !software_remaining.is_empty();
    Ok(missing)
}

fn classify_effect_receipts(receipts: &[HealthEffectReceipt]) -> HealthEffectQuality {
    let mut partial = false;
    let mut cancelled = false;
    let mut any_completed_effect = false;
    for receipt in receipts {
        match receipt {
            HealthEffectReceipt::BrowserPrivacy(receipt) => {
                if receipt.uncertain {
                    return HealthEffectQuality::Uncertain;
                }
                cancelled |= receipt.cancelled;
                any_completed_effect |= receipt.deleted > 0;
                partial |= (!receipt.cancelled && receipt.deleted < receipt.selected)
                    || receipt.skipped > 0
                    || !receipt.errors.is_empty();
            }
            HealthEffectReceipt::Files(receipt) => {
                if receipt.interrupted || !receipt.uncertain.is_empty() {
                    return HealthEffectQuality::Uncertain;
                }
                cancelled |= receipt.cancelled;
                any_completed_effect |= receipt.files > 0;
                partial |= !receipt.failed.is_empty();
            }
            HealthEffectReceipt::RecycleBin(receipt) => {
                if receipt.operation != recycle_bin::RecycleBinOperation::Purge {
                    return HealthEffectQuality::Uncertain;
                }
                if receipt
                    .receipts
                    .iter()
                    .any(|item| item.state == recycle_bin::ItemOperationState::Uncertain)
                {
                    return HealthEffectQuality::Uncertain;
                }
                if receipt
                    .receipts
                    .iter()
                    .any(|item| item.state == recycle_bin::ItemOperationState::Restored)
                {
                    return HealthEffectQuality::Uncertain;
                }
                cancelled |= receipt.completion == recycle_bin::OperationCompletion::Cancelled;
                any_completed_effect |= receipt
                    .receipts
                    .iter()
                    .any(|item| item.state == recycle_bin::ItemOperationState::Purged);
                partial |= receipt.completion == recycle_bin::OperationCompletion::Partial
                    || receipt.receipts.iter().any(|item| {
                        matches!(
                            item.state,
                            recycle_bin::ItemOperationState::Missing
                                | recycle_bin::ItemOperationState::Changed
                                | recycle_bin::ItemOperationState::Denied
                                | recycle_bin::ItemOperationState::Unknown
                                | recycle_bin::ItemOperationState::Failed
                        )
                    })
                    || (receipt.completion == recycle_bin::OperationCompletion::Complete
                        && receipt
                            .receipts
                            .iter()
                            .any(|item| item.state != recycle_bin::ItemOperationState::Purged));
            }
            HealthEffectReceipt::Startup(receipt) => {
                if !matches!(
                    receipt.outcome,
                    crate::startup::ChangeOutcome::Applied
                        | crate::startup::ChangeOutcome::AlreadyApplied
                ) || receipt.after.enabled != EnabledState::Disabled
                {
                    return HealthEffectQuality::Uncertain;
                }
                any_completed_effect = true;
            }
            HealthEffectReceipt::Software(receipt) => {
                if receipt.verification == UpdateVerification::Uncertain {
                    return HealthEffectQuality::Uncertain;
                }
                any_completed_effect = true;
            }
        }
    }
    if cancelled && !any_completed_effect && !partial {
        HealthEffectQuality::Cancelled
    } else if partial || cancelled && any_completed_effect {
        HealthEffectQuality::Partial
    } else if cancelled {
        HealthEffectQuality::Cancelled
    } else {
        HealthEffectQuality::Complete
    }
}

fn index(step: HealthStep) -> usize {
    match step {
        HealthStep::Privacy => 0,
        HealthStep::Space => 1,
        HealthStep::ResolveIssues => 2,
    }
}

/// Native scan adapter for Health Check's More Privacy step. It is called only
/// in response to an explicit scan request and performs read-only inventories.
pub fn scan_privacy_step(
    cancel: &AtomicBool,
    mut progress: impl FnMut(HealthStep, u64, Option<u64>, Option<String>),
) -> HealthStepReport {
    let data_dir = match crate::platform::data_directory() {
        Ok(path) => path,
        Err(error) => return HealthStepReport::failed(HealthStep::Privacy, error),
    };
    let cookie_settings = match privacy::load_cookie_exception_settings(&data_dir) {
        Ok(settings) => settings,
        Err(error) => return HealthStepReport::failed(HealthStep::Privacy, error),
    };
    let profiles = privacy::discover_profiles();
    progress(
        HealthStep::Privacy,
        0,
        None,
        Some("Scanning browser history and cookies".into()),
    );
    let browser_records = privacy::scan_profiles_with_settings(
        &profiles.profiles,
        &[PrivacyCategory::History, PrivacyCategory::Cookies],
        &cookie_settings,
        cancel,
        |update| {
            progress(
                HealthStep::Privacy,
                update.profiles_completed as u64,
                Some(update.profiles_total as u64),
                Some(format!(
                    "{} · {}",
                    update.profile_name,
                    source_category_label(update.category)
                )),
            )
        },
    );
    let cache_categories = crate::platform::categories();
    let cache_ids = cache_categories
        .iter()
        .filter(|category| ["chrome", "edge", "firefox"].contains(&category.id.as_str()))
        .map(|category| category.id.clone())
        .collect::<Vec<_>>();
    let (browser_cache_files, cache_error) = match crate::scanner::analyze(
        &cache_categories,
        &cache_ids,
        HEALTH_FILE_MINIMUM_AGE_DAYS,
        cancel,
        |category, count| {
            progress(
                HealthStep::Privacy,
                count as u64,
                None,
                Some(format!("Scanning {category}")),
            )
        },
    ) {
        Ok(analysis) => (analysis, None),
        Err(error) => (empty_analysis(), Some(error)),
    };
    let mut report = HealthStepReport::privacy(profiles, browser_records, browser_cache_files);
    if let Some(error) = cache_error {
        report.quality = HealthScanQuality::Partial;
        report
            .notes
            .push(format!("Browser cache analysis failed: {error}"));
    }
    report
}

/// Native scan adapter for More Space. The Recycle Bin and filesystem remain
/// separate exact-ID inventories and are never scanned through a common path walker.
pub fn scan_space_step(
    cancel: &AtomicBool,
    mut progress: impl FnMut(HealthStep, u64, Option<u64>, Option<String>),
) -> HealthStepReport {
    let categories = crate::platform::categories();
    let ids = categories
        .iter()
        .filter(|category| {
            ["temp", "crash", "chrome", "edge", "firefox"].contains(&category.id.as_str())
        })
        .map(|category| category.id.clone())
        .collect::<Vec<_>>();
    let (files, file_error) = match crate::scanner::analyze(
        &categories,
        &ids,
        HEALTH_FILE_MINIMUM_AGE_DAYS,
        cancel,
        |category, count| {
            progress(
                HealthStep::Space,
                count as u64,
                None,
                Some(format!("Scanning {category}")),
            )
        },
    ) {
        Ok(analysis) => (analysis, None),
        Err(error) => (empty_analysis(), Some(error)),
    };
    progress(
        HealthStep::Space,
        0,
        None,
        Some("Reading the current user's Recycle Bin".into()),
    );
    let mut port = recycle_bin::SystemRecycleBin::new();
    let recycle_bin = recycle_bin::inventory(&mut port, cancel, |done, total| {
        progress(
            HealthStep::Space,
            done as u64,
            Some(total as u64),
            Some("Reading Recycle Bin item metadata".into()),
        )
    });
    let mut report = HealthStepReport::space(files, recycle_bin);
    if let Some(error) = file_error {
        report.quality = HealthScanQuality::Partial;
        report
            .notes
            .push(format!("Temporary-file analysis failed: {error}"));
    }
    report
}

/// Native scan adapter for Resolve Issues. A startup inventory is review-only
/// until a recommendation classifier exists; software results come from WinGet.
pub fn scan_resolve_issues_step(
    cancel: &AtomicBool,
    data_dir: &Path,
    mut progress: impl FnMut(HealthStep, u64, Option<u64>, Option<String>),
) -> HealthStepReport {
    use crate::startup::{StartupManager, StartupSection, WindowsStartupPlatform};

    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        let mut report = HealthStepReport::failed(
            HealthStep::ResolveIssues,
            "Health Check scan was cancelled before it started.",
        );
        report.quality = HealthScanQuality::Cancelled;
        return report;
    }

    progress(
        HealthStep::ResolveIssues,
        0,
        None,
        Some("Reading startup-app inventory".into()),
    );
    let startup =
        StartupManager::new(WindowsStartupPlatform::new()).inventory(StartupSection::StartupApps);
    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        let mut report = HealthStepReport::resolve_issues(
            startup,
            Err("Software scan was not started because Health Check was cancelled.".into()),
        );
        report.quality = HealthScanQuality::Cancelled;
        report
            .notes
            .push("Cancellation is observed between native inventory services.".into());
        return report;
    }
    progress(
        HealthStep::ResolveIssues,
        0,
        None,
        Some("Checking installed applications against the configured update source".into()),
    );
    let software = software::load_settings(data_dir)
        .map_err(|error| error.to_string())
        .and_then(|settings| {
            software::installed_software(&settings).map_err(|error| error.to_string())
        });
    let mut report = HealthStepReport::resolve_issues(startup, software);
    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        report.quality = HealthScanQuality::Cancelled;
        report.notes.push(
            "Cancellation is observed after the active software inventory call returns.".into(),
        );
    }
    report
}

fn empty_analysis() -> Analysis {
    Analysis {
        id: Uuid::new_v4(),
        date: chrono::Local::now().to_rfc3339(),
        minimum_age_days: HEALTH_FILE_MINIMUM_AGE_DAYS,
        cleanup_policy: Default::default(),
        elapsed_ms: 0,
        cancelled: false,
        categories: Vec::new(),
    }
}

#[cfg(test)]
#[path = "health_tests.rs"]
mod tests;
