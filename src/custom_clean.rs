//! Custom Clean scanner and reviewed cleanup adapter for file inclusions and
//! selected cache catalogue entries. Effects are delegated to the shared
//! cleanup owner only after exact-ID review and owner-specific revalidation.

#[cfg(debug_assertions)]
use crate::clean_settings::FolderInclusion;
use crate::{
    clean_settings::{
        CustomCleanSettings, ExclusionType, FileDeletionMode, InclusionLocation, InclusionRule,
        OverwriteType,
    },
    cleanup::{TrashPort, clean_with_validator},
    domain::{Analysis, Candidate, Category, CategoryResult, CleanupPolicy, CleanupResult},
    scanner::{DAY_NS, MAX_ENTRIES, contained, is_link, safe_root, same_path, timestamp},
    store::JournalSink,
};
use serde::Serialize;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Instant, SystemTime},
};
use uuid::Uuid;

const MAX_CUSTOM_RULES: usize = 512;
const MAX_CUSTOM_EXCLUSIONS: usize = 4096;
const MAX_FILTERS: usize = 4096;
const MAX_FILTER_BYTES: usize = 1024;
const MAX_MATCH_INPUT_BYTES: usize = 32_768;
pub const MAX_MATCH_STEPS: usize = 128_000_000;
const MAX_SCAN_DEPTH: usize = 128;
const MAX_SKIP_DETAILS: usize = 2048;
const HOUR_NS: f64 = 3_600_000_000_000.0;
const TEMP_AGE_NS: u128 = 24 * 60 * 60 * 1_000_000_000;

/// Inputs owned by the caller. `categories` and `selected_legacy_ids` are the
/// existing application cache catalogue; this scanner invents no scan roots.
#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub categories: Vec<Category>,
    pub selected_legacy_ids: Vec<String>,
    pub default_age_days: u32,
    pub now: SystemTime,
    /// A caller may lower the bound, never raise it above the shared scanner cap.
    pub max_entries: usize,
    /// Aggregate matching work for the whole scan, including normalization and
    /// wildcard retries. A lower caller limit is useful for bounded scans.
    pub max_match_steps: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            categories: Vec::new(),
            selected_legacy_ids: Vec::new(),
            default_age_days: 7,
            now: SystemTime::now(),
            max_entries: MAX_ENTRIES,
            max_match_steps: MAX_MATCH_STEPS,
        }
    }
}

/// One per-rule scan result. Inclusions are stable content-derived IDs; built-in
/// catalogue rules retain the exact caller-provided category ID.
#[derive(Clone, Debug, Serialize)]
pub struct RuleScan {
    id: String,
    name: String,
    selected: bool,
    available: bool,
    visited: usize,
    matched: usize,
    eligible: usize,
    too_recent: usize,
    excluded: usize,
    skipped: usize,
    truncated: bool,
    reason: Option<String>,
}

impl RuleScan {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn selected(&self) -> bool {
        self.selected
    }

    pub fn available(&self) -> bool {
        self.available
    }

    pub fn visited(&self) -> usize {
        self.visited
    }

    pub fn matched(&self) -> usize {
        self.matched
    }

    pub fn eligible(&self) -> usize {
        self.eligible
    }

    pub fn too_recent(&self) -> usize {
        self.too_recent
    }

    pub fn excluded(&self) -> usize {
        self.excluded
    }

    pub fn skipped(&self) -> usize {
        self.skipped
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

/// The age decision captured for a single matching rule. `cutoff_ns` is absolute
/// scan-time evidence, so later cleanup cannot substitute the global cache age.
#[derive(Clone, Debug, Serialize)]
pub struct RuleEligibility {
    rule_id: String,
    selected: bool,
    eligible: bool,
    cutoff_ns: u128,
    age_threshold_hours: Option<f64>,
    age_threshold_days: Option<u32>,
    temporary_24h_applied: bool,
}

impl RuleEligibility {
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    pub fn selected(&self) -> bool {
        self.selected
    }

    pub fn eligible(&self) -> bool {
        self.eligible
    }

    pub fn cutoff_ns(&self) -> u128 {
        self.cutoff_ns
    }

    pub fn age_threshold_hours(&self) -> Option<f64> {
        self.age_threshold_hours
    }

    pub fn age_threshold_days(&self) -> Option<u32> {
        self.age_threshold_days
    }

    pub fn temporary_24h_applied(&self) -> bool {
        self.temporary_24h_applied
    }
}

/// A scan-local file row backed by the shared immutable `Candidate` identity.
/// All fields remain private; consumers obtain read-only accessors and resolve
/// actions through the current report by UUID.
#[derive(Clone, Debug, Serialize)]
pub struct CustomCleanFile {
    candidate: Candidate,
    matched_rule_ids: Vec<String>,
    eligibility: Vec<RuleEligibility>,
}

impl CustomCleanFile {
    pub fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    pub fn id(&self) -> Uuid {
        self.candidate.id
    }

    pub fn path(&self) -> &Path {
        &self.candidate.path
    }

    pub fn size(&self) -> u64 {
        self.candidate.size
    }

    pub fn matched_rule_ids(&self) -> &[String] {
        &self.matched_rule_ids
    }

    pub fn eligibility(&self) -> &[RuleEligibility] {
        &self.eligibility
    }

    pub fn eligible(&self) -> bool {
        self.eligibility
            .iter()
            .any(|entry| entry.selected && entry.eligible)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum SkipReason {
    UnavailableRoot,
    ReadDirectoryFailed,
    EntryReadFailed,
    LinkedEntry,
    OutsideRoot,
    MetadataUnavailable,
    NonRegularFile,
    DepthLimit,
    TooRecent,
    ExcludedByFileRule,
    ExcludedByPathRule,
    EntryLimit,
    ChangedDuringScan,
    MatchingWorkLimit,
    MatchingInputLimit,
    MatchingCancelled,
}

impl SkipReason {
    pub fn description(self) -> &'static str {
        match self {
            Self::UnavailableRoot => "Location unavailable",
            Self::ReadDirectoryFailed => "Folder could not be read",
            Self::EntryReadFailed => "Folder entry could not be read",
            Self::LinkedEntry => "Linked or redirected location skipped",
            Self::OutsideRoot => "Location moved outside its selected folder",
            Self::MetadataUnavailable => "File information unavailable",
            Self::NonRegularFile => "Not an ordinary file",
            Self::DepthLimit => "Folder nesting limit reached",
            Self::TooRecent => "File is newer than the selected age limit",
            Self::ExcludedByFileRule => "Excluded by a file rule",
            Self::ExcludedByPathRule => "Excluded by a folder rule",
            Self::EntryLimit => "Scan entry limit reached",
            Self::ChangedDuringScan => "File changed during the scan",
            Self::MatchingWorkLimit => {
                "Matching limit reached; remaining locations were not scanned"
            }
            Self::MatchingInputLimit => "Path or filter text exceeds supported matching limits",
            Self::MatchingCancelled => "Matching stopped at your request",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SkippedEntry {
    rule_id: Option<String>,
    path: Option<PathBuf>,
    reason: SkipReason,
}

impl SkippedEntry {
    pub fn rule_id(&self) -> Option<&str> {
        self.rule_id.as_deref()
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn reason(&self) -> SkipReason {
        self.reason
    }
}

/// These describe requested effects which the file-scanning owner cannot
/// perform. `blocking` is true when silently proceeding would change the
/// selected effect (for example secure deletion or folder-self removal).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CapabilityKind {
    DeleteInclusionFolder,
    RegistryExclusion,
    CookieExclusion,
    RecycleBinAgePolicy,
    SecureFileDeletion,
    OverwritePasses,
    WipeFreeSpace,
    WipeAlternateDataStreams,
    WipeDriveMftFreeSpace,
    ShutdownAfterCleaning,
    SkipCloseProcesses,
}

#[derive(Clone, Debug, Serialize)]
pub struct CapabilityNote {
    kind: CapabilityKind,
    blocking: bool,
    rule_id: Option<String>,
    detail: String,
}

impl CapabilityNote {
    pub fn kind(&self) -> CapabilityKind {
        self.kind
    }

    pub fn blocking(&self) -> bool {
        self.blocking
    }

    pub fn rule_id(&self) -> Option<&str> {
        self.rule_id.as_deref()
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// A bounded, read-only Custom Clean scan. This report can be serialized for a
/// local review record but deliberately has no deserializer or mutable fields.
#[derive(Clone, Debug, Serialize)]
pub struct CustomCleanReport {
    id: Uuid,
    date: String,
    settings_fingerprint: String,
    #[serde(skip)]
    settings_snapshot: CustomCleanSettings,
    default_age_days: u32,
    elapsed_ms: u64,
    match_steps_used: usize,
    match_step_limit: usize,
    cancelled: bool,
    partial: bool,
    truncated: bool,
    skipped_count: usize,
    omitted_skip_details: usize,
    rules: Vec<RuleScan>,
    files: Vec<CustomCleanFile>,
    skipped_entries: Vec<SkippedEntry>,
    capabilities: Vec<CapabilityNote>,
    #[cfg(debug_assertions)]
    #[serde(skip)]
    visual_fixture: bool,
}

#[cfg(debug_assertions)]
impl CustomCleanReport {
    /// Fixed, synthetic report used only by debug visual QA. It never scans a
    /// path and its hardcoded fixture identities must not authorize effects.
    pub fn visual_fixture() -> Self {
        Self::visual_fixture_populated()
    }

    #[cfg(debug_assertions)]
    pub fn visual_fixture_empty() -> Self {
        visual_fixture_report(VisualFixtureKind::Empty)
    }

    #[cfg(debug_assertions)]
    pub fn visual_fixture_populated() -> Self {
        visual_fixture_report(VisualFixtureKind::Populated)
    }

    #[cfg(debug_assertions)]
    pub fn visual_fixture_details() -> Self {
        visual_fixture_report(VisualFixtureKind::Details)
    }

    #[cfg(debug_assertions)]
    pub fn visual_fixture_error() -> Self {
        visual_fixture_report(VisualFixtureKind::Unavailable)
    }
}

#[cfg(debug_assertions)]
#[derive(Clone, Copy)]
enum VisualFixtureKind {
    Empty,
    Populated,
    Details,
    Unavailable,
}

#[cfg(debug_assertions)]
fn visual_fixture_report(kind: VisualFixtureKind) -> CustomCleanReport {
    let folder = FolderInclusion {
        folder: r"C:\__dcleaner_qa_fixture__\included".into(),
        filter: Some(vec!["*.tmp".into(), "*.cache".into()]),
        delete_self: false,
        recursive: true,
    };
    let inclusion = InclusionRule {
        location: InclusionLocation::Folder(folder),
        age_threshold_hours: Some(24.0),
    };
    let rule_id = rule_id_for_inclusion(&inclusion);
    let mut settings = CustomCleanSettings::default();
    settings.inclusions.push(inclusion);
    let _ = settings.set_rule_selection(".custom", Some(true));
    let _ = settings.set_rule_selection(&rule_id, Some(true));

    let unavailable = matches!(kind, VisualFixtureKind::Unavailable);
    let detailed = matches!(
        kind,
        VisualFixtureKind::Details | VisualFixtureKind::Unavailable
    );
    let mut files = Vec::new();
    if matches!(
        kind,
        VisualFixtureKind::Populated | VisualFixtureKind::Details
    ) {
        files.push(visual_fixture_file(
            0x7a31_4d0e_95c2_4a60_8a12_5b8dfd93c101,
            "recent-cache.tmp",
            2_048,
            &rule_id,
            true,
        ));
        if detailed {
            files.push(visual_fixture_file(
                0x7a31_4d0e_95c2_4a60_8a12_5b8dfd93c102,
                "older-cache.cache",
                16_384,
                &rule_id,
                true,
            ));
            files.push(visual_fixture_file(
                0x7a31_4d0e_95c2_4a60_8a12_5b8dfd93c103,
                "too-recent.tmp",
                512,
                &rule_id,
                false,
            ));
        }
    }

    let skipped_entries = if detailed {
        vec![SkippedEntry {
            rule_id: Some(rule_id.clone()),
            path: Some(PathBuf::from(
                r"C:\__dcleaner_qa_fixture__\included\unreadable.tmp",
            )),
            reason: if unavailable {
                SkipReason::UnavailableRoot
            } else {
                SkipReason::EntryReadFailed
            },
        }]
    } else {
        Vec::new()
    };
    let capabilities = if matches!(kind, VisualFixtureKind::Details) {
        vec![CapabilityNote {
            kind: CapabilityKind::CookieExclusion,
            blocking: false,
            rule_id: None,
            detail: "Cookie exclusions are stored settings and are not applied by this filesystem scanner. (Synthetic QA preview.)".into(),
        }]
    } else {
        Vec::new()
    };
    let (visited, matched, eligible, too_recent, excluded, skipped, reason) = if unavailable {
        (
            0,
            0,
            0,
            0,
            0,
            1,
            Some("The synthetic fixture location is unavailable.".into()),
        )
    } else if matches!(kind, VisualFixtureKind::Empty) {
        (18, 0, 0, 0, 0, 0, None)
    } else if detailed {
        (36, 3, 2, 1, 0, 1, None)
    } else {
        (12, 1, 1, 0, 0, 0, None)
    };
    let partial = unavailable || detailed;
    let rules = vec![RuleScan {
        id: rule_id,
        name: "Synthetic included folder".into(),
        selected: true,
        available: !unavailable,
        visited,
        matched,
        eligible,
        too_recent,
        excluded,
        skipped,
        truncated: false,
        reason,
    }];
    CustomCleanReport {
        id: Uuid::from_u128(0x7a31_4d0e_95c2_4a60_8a12_5b8dfd930001),
        date: "2026-10-15T09:00:00+08:00".into(),
        settings_fingerprint: settings_fingerprint(&settings),
        settings_snapshot: settings,
        default_age_days: 7,
        elapsed_ms: 42,
        match_steps_used: 128,
        match_step_limit: MAX_MATCH_STEPS,
        cancelled: false,
        partial,
        truncated: false,
        skipped_count: skipped,
        omitted_skip_details: 0,
        rules,
        files,
        skipped_entries,
        capabilities,
        visual_fixture: true,
    }
}

#[cfg(debug_assertions)]
fn visual_fixture_file(
    id: u128,
    name: &str,
    size: u64,
    rule_id: &str,
    eligible: bool,
) -> CustomCleanFile {
    let root = PathBuf::from(r"C:\__dcleaner_qa_fixture__\included");
    CustomCleanFile {
        candidate: Candidate {
            id: Uuid::from_u128(id),
            path: root.join(name),
            root,
            size,
            modified_ns: 1_760_000_000_000_000_000,
            created_ns: None,
        },
        matched_rule_ids: vec![rule_id.to_owned()],
        eligibility: vec![RuleEligibility {
            rule_id: rule_id.to_owned(),
            selected: true,
            eligible,
            cutoff_ns: 1_759_900_000_000_000_000,
            age_threshold_hours: Some(24.0),
            age_threshold_days: None,
            temporary_24h_applied: false,
        }],
    }
}

impl CustomCleanReport {
    pub fn match_steps_used(&self) -> usize {
        self.match_steps_used
    }
    pub fn match_step_limit(&self) -> usize {
        self.match_step_limit
    }
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn date(&self) -> &str {
        &self.date
    }

    pub fn default_age_days(&self) -> u32 {
        self.default_age_days
    }

    pub fn settings_fingerprint(&self) -> &str {
        &self.settings_fingerprint
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }

    pub fn cancelled(&self) -> bool {
        self.cancelled
    }

    pub fn partial(&self) -> bool {
        self.partial
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn skipped_count(&self) -> usize {
        self.skipped_count
    }

    pub fn omitted_skip_details(&self) -> usize {
        self.omitted_skip_details
    }

    pub fn rules(&self) -> &[RuleScan] {
        &self.rules
    }

    pub fn files(&self) -> &[CustomCleanFile] {
        &self.files
    }

    pub fn skipped_entries(&self) -> &[SkippedEntry] {
        &self.skipped_entries
    }

    pub fn capabilities(&self) -> &[CapabilityNote] {
        &self.capabilities
    }

    pub fn file(&self, id: Uuid) -> Option<&CustomCleanFile> {
        self.files.iter().find(|file| file.id() == id)
    }

    /// A UI/history projection only. `minimum_age_days = 0` is intentional:
    /// the legacy global-age cleanup API cannot represent per-rule fractional
    /// thresholds. Configured cleanup must resolve the Custom Clean report ID
    /// and revalidate its private snapshots through its owner-specific adapter.
    pub fn to_analysis(&self) -> Analysis {
        let available = self.rules.iter().any(RuleScan::available);
        Analysis {
            id: self.id,
            date: self.date.clone(),
            minimum_age_days: 0,
            cleanup_policy: CleanupPolicy::CustomCleanRules,
            elapsed_ms: self.elapsed_ms,
            cancelled: self.cancelled,
            categories: vec![CategoryResult {
                id: "custom-clean-results".into(),
                name: "Custom Clean".into(),
                group: "custom-clean".into(),
                files: self
                    .files
                    .iter()
                    .filter(|file| file.eligible())
                    .map(|file| file.candidate.clone())
                    .collect(),
                skipped: self.skipped_count,
                available,
                truncated: self.truncated,
            }],
        }
    }

    /// A non-effecting, exact-ID review snapshot. It refuses stale settings,
    /// unknown/duplicate IDs, ineligible files, unacknowledged partial results,
    /// and configured effects this owner cannot safely execute.
    pub fn review_selection(
        &self,
        settings: &CustomCleanSettings,
        ids: &[Uuid],
        acknowledge_partial: bool,
    ) -> Result<CustomCleanReview, String> {
        #[cfg(debug_assertions)]
        if self.visual_fixture {
            return Err("A synthetic Custom Clean QA preview cannot authorize cleanup.".into());
        }
        settings
            .validate()
            .map_err(|error| format!("Custom Clean settings are invalid: {error}"))?;
        if settings_fingerprint(settings) != self.settings_fingerprint
            || settings != &self.settings_snapshot
        {
            return Err("Custom Clean settings changed after the scan; scan again.".into());
        }
        if self.cancelled {
            return Err("A cancelled Custom Clean scan cannot authorize file review.".into());
        }
        if self.partial && !acknowledge_partial {
            return Err("Acknowledge the partial Custom Clean scan before review.".into());
        }
        if ids.is_empty() {
            return Err("Select current eligible Custom Clean file IDs.".into());
        }
        let mut seen = HashSet::new();
        let mut files = Vec::with_capacity(ids.len());
        let mut selected_rules = BTreeSet::new();
        for id in ids {
            if !seen.insert(*id) {
                return Err("A Custom Clean file ID was selected more than once.".into());
            }
            let file = self
                .file(*id)
                .ok_or_else(|| "A selected Custom Clean file ID is unknown.".to_owned())?;
            let allowed_rules: Vec<_> = file
                .eligibility
                .iter()
                .filter(|entry| entry.selected && entry.eligible)
                .collect();
            if allowed_rules.is_empty() {
                return Err("A selected Custom Clean file is too recent or unselected.".into());
            }
            for rule in &allowed_rules {
                selected_rules.insert(rule.rule_id.clone());
            }
            if self.capabilities.iter().any(|note| {
                note.blocking
                    && (note.rule_id.is_none()
                        || allowed_rules
                            .iter()
                            .any(|rule| Some(rule.rule_id.as_str()) == note.rule_id.as_deref()))
            }) {
                return Err(
                    "A selected Custom Clean effect is unsupported; no files were reviewed.".into(),
                );
            }
            revalidate_snapshot(&file.candidate)?;
            files.push(ReviewedFile {
                candidate: file.candidate.clone(),
                eligibility: allowed_rules.into_iter().cloned().collect(),
            });
        }
        Ok(CustomCleanReview {
            report_id: self.id,
            settings_fingerprint: self.settings_fingerprint.clone(),
            settings_snapshot: self.settings_snapshot.clone(),
            acknowledged_partial: self.partial && acknowledge_partial,
            selected_rule_ids: selected_rules.into_iter().collect(),
            files,
        })
    }
}

/// Typed review input resolved by the Custom Clean cleanup owner.
#[derive(Clone, Debug, Serialize)]
pub struct CustomCleanReview {
    report_id: Uuid,
    settings_fingerprint: String,
    #[serde(skip)]
    settings_snapshot: CustomCleanSettings,
    acknowledged_partial: bool,
    selected_rule_ids: Vec<String>,
    files: Vec<ReviewedFile>,
}

#[derive(Clone, Debug, Serialize)]
struct ReviewedFile {
    candidate: Candidate,
    eligibility: Vec<RuleEligibility>,
}

impl CustomCleanReview {
    pub fn report_id(&self) -> Uuid {
        self.report_id
    }

    pub fn acknowledged_partial(&self) -> bool {
        self.acknowledged_partial
    }

    pub fn selected_rule_ids(&self) -> &[String] {
        &self.selected_rule_ids
    }

    pub fn candidates(&self) -> impl Iterator<Item = &Candidate> {
        self.files.iter().map(|file| &file.candidate)
    }

    /// Recheck exact report/settings identity and current file metadata before
    /// an effect owner considers a selected candidate.
    pub fn revalidate_candidate<'a>(
        &'a self,
        settings: &CustomCleanSettings,
        id: Uuid,
    ) -> Result<&'a Candidate, String> {
        settings
            .validate()
            .map_err(|error| format!("Custom Clean settings are invalid: {error}"))?;
        if settings_fingerprint(settings) != self.settings_fingerprint
            || settings != &self.settings_snapshot
        {
            return Err("Custom Clean settings changed after review.".into());
        }
        let file = self
            .files
            .iter()
            .find(|file| file.candidate.id == id)
            .ok_or_else(|| "A reviewed Custom Clean file ID is unknown.".to_owned())?;
        if file.eligibility.is_empty()
            || !file.eligibility.iter().any(|rule| {
                rule.selected
                    && rule.eligible
                    && file.candidate.modified_ns <= rule.cutoff_ns
                    && self.selected_rule_ids.contains(&rule.rule_id)
            })
        {
            return Err("The reviewed file no longer has an eligible selected rule.".into());
        }
        revalidate_snapshot(&file.candidate)?;
        Ok(&file.candidate)
    }
}

/// Execute only exact IDs from this scan after checking current settings and
/// every supported per-rule age/exclusion snapshot. Journal and native Trash
/// calls remain in the cleanup owner; secure erase and other unsupported effects
/// fail during `review_selection` before the journal is opened.
pub fn clean(
    report: &CustomCleanReport,
    settings: &CustomCleanSettings,
    ids: &[Uuid],
    acknowledge_partial: bool,
    cancel: &AtomicBool,
    trash: &mut impl TrashPort,
    journal: &mut impl JournalSink,
    progress: impl FnMut(usize, usize),
) -> Result<CleanupResult, String> {
    let review = report.review_selection(settings, ids, acknowledge_partial)?;
    let analysis = report.to_analysis();
    clean_with_validator(
        &analysis,
        ids,
        cancel,
        trash,
        journal,
        progress,
        |candidate| {
            let reviewed = review.revalidate_candidate(settings, candidate.id)?;
            if reviewed.path != candidate.path
                || reviewed.root != candidate.root
                || reviewed.size != candidate.size
                || reviewed.modified_ns != candidate.modified_ns
                || reviewed.created_ns != candidate.created_ns
            {
                return Err("The Custom Clean candidate identity changed before cleanup.".into());
            }
            Ok(())
        },
    )
}

#[derive(Clone, Debug)]
pub struct ScanProgress {
    pub rule_id: String,
    pub rule_name: String,
    pub visited: usize,
    pub matched: usize,
}

/// Stable rule identity used by `rule-selections`. It depends on serialized rule
/// contents, never on its position in the settings list.
pub fn rule_id_for_inclusion(rule: &InclusionRule) -> String {
    let bytes = serde_json::to_vec(rule).unwrap_or_default();
    let first = stable_hash(&bytes, 0xcbf29ce484222325);
    let second = stable_hash(&bytes, 0x84222325cbf29ce4);
    format!("custom.inclusion.{first:016x}{second:016x}")
}

/// Scan only caller-provided roots. No default home, drive, browser or user-data
/// traversal is performed by this module.
pub fn scan(
    settings: &CustomCleanSettings,
    options: &ScanOptions,
    cancel: &AtomicBool,
    mut progress: impl FnMut(ScanProgress),
) -> Result<CustomCleanReport, String> {
    settings
        .validate()
        .map_err(|error| format!("Custom Clean settings are invalid: {error}"))?;
    validate_options(options)?;
    let rule_count = options.categories.len() + settings.inclusions.len();
    if rule_count > MAX_CUSTOM_RULES {
        return Err("Custom Clean scan rule limit exceeded.".into());
    }
    let file_exclusion_count = settings
        .exclusions
        .iter()
        .filter(|exclusion| {
            matches!(
                exclusion.exclusion_type,
                ExclusionType::File | ExclusionType::Path
            )
        })
        .count();
    if file_exclusion_count > MAX_CUSTOM_EXCLUSIONS {
        return Err("Custom Clean exclusion scan limit exceeded.".into());
    }
    let filter_count: usize = settings
        .inclusions
        .iter()
        .filter_map(|rule| match &rule.location {
            InclusionLocation::Folder(folder) => folder.filter.as_ref(),
            InclusionLocation::File(_) => None,
        })
        .map(Vec::len)
        .sum();
    if filter_count > MAX_FILTERS
        || settings.inclusions.iter().any(|rule| match &rule.location {
            InclusionLocation::Folder(folder) => folder.filter.as_ref().is_some_and(|patterns| {
                patterns
                    .iter()
                    .any(|pattern| pattern.len() > MAX_FILTER_BYTES)
            }),
            InclusionLocation::File(_) => false,
        })
    {
        return Err("Custom Clean filter scan limit exceeded.".into());
    }
    if settings
        .inclusions
        .iter()
        .any(|rule| rule.age_threshold_hours.is_some_and(|hours| hours < 0.0))
    {
        return Err("Custom Clean age thresholds cannot be negative.".into());
    }
    if settings.exclusions.iter().any(|exclusion| {
        matches!(
            exclusion.exclusion_type,
            ExclusionType::File | ExclusionType::Path
        ) && exclusion.path.len() > MAX_FILTER_BYTES
    }) {
        return Err("Custom Clean exclusion pattern exceeds the safe length limit.".into());
    }
    let known_category_ids: HashSet<_> = options.categories.iter().map(|c| c.id.as_str()).collect();
    if options
        .selected_legacy_ids
        .iter()
        .any(|id| !known_category_ids.contains(id.as_str()))
    {
        return Err("A selected built-in Custom Clean category ID is unknown.".into());
    }

    let started = Instant::now();
    let now_ns = timestamp(options.now);
    let mut builder = ReportBuilder {
        matcher: MatchBudget::new(options.max_match_steps),
        ..Default::default()
    };
    let file_exclusions: Vec<_> = settings
        .exclusions
        .iter()
        .filter(|rule| {
            matches!(
                rule.exclusion_type,
                ExclusionType::File | ExclusionType::Path
            )
        })
        .cloned()
        .collect();
    let exclusions = &file_exclusions;
    let mut budget = options.max_entries;
    let mut seen_rules = HashMap::<String, String>::new();

    for category in &options.categories {
        if cancel.load(Ordering::Relaxed) || builder.matcher.exhausted {
            break;
        }
        let selected = settings.rule_selection(&category.id).unwrap_or_else(|| {
            options
                .selected_legacy_ids
                .iter()
                .any(|id| id == &category.id)
        });
        let rule = RuleScan::new(category.id.clone(), category.name.clone(), selected);
        if !selected {
            builder.rules.push(rule);
            continue;
        }
        let mut rule = rule;
        let cutoff = now_ns.saturating_sub(u128::from(options.default_age_days) * DAY_NS);
        for root in &category.roots {
            if cancel.load(Ordering::Relaxed) || builder.matcher.exhausted {
                break;
            }
            scan_legacy_root(
                root,
                &category.id,
                &category.name,
                cutoff,
                settings,
                exclusions,
                now_ns,
                options.default_age_days,
                &mut budget,
                cancel,
                &mut builder,
                &mut rule,
                &mut progress,
            );
        }
        if rule.visited == 0 && !rule.available && !category.roots.is_empty() {
            rule.reason = Some("No selected cache root was available.".into());
        }
        progress(ScanProgress {
            rule_id: category.id.clone(),
            rule_name: category.name.clone(),
            visited: rule.visited,
            matched: rule.matched,
        });
        builder.rules.push(rule);
    }

    let custom_enabled = settings.rule_selection(".custom") == Some(true);
    for inclusion in &settings.inclusions {
        if cancel.load(Ordering::Relaxed) || builder.matcher.exhausted {
            break;
        }
        let rule_id = rule_id_for_inclusion(inclusion);
        if let Some(existing) = seen_rules.insert(rule_id.clone(), format!("{inclusion:?}")) {
            if existing != format!("{inclusion:?}") {
                return Err("A Custom Clean inclusion identity collision was detected.".into());
            }
        }
        let name = inclusion_name(inclusion);
        let selected = custom_enabled && settings.rule_selection(&rule_id).unwrap_or(true);
        let mut rule = RuleScan::new(rule_id.clone(), name.clone(), selected);
        if !selected {
            rule.reason = Some(if !custom_enabled {
                "The .custom inclusion group is not selected.".into()
            } else {
                "This inclusion rule is unselected.".into()
            });
            builder.rules.push(rule);
            continue;
        }
        match &inclusion.location {
            InclusionLocation::File(path) => {
                match scan_file_inclusion(
                    path,
                    &rule_id,
                    exclusions,
                    &mut budget,
                    cancel,
                    &mut builder,
                    &mut rule,
                ) {
                    Ok(candidate) => {
                        if let Some(candidate) = candidate {
                            let eligibility = eligibility_for_custom(
                                &rule_id,
                                true,
                                candidate.modified_ns,
                                inclusion.age_threshold_hours,
                                now_ns,
                                false,
                            );
                            if eligibility.eligible {
                                rule.eligible += 1;
                            } else {
                                rule.too_recent += 1;
                            }
                            rule.matched += 1;
                            builder.add_file(candidate, rule_id.clone(), eligibility);
                        }
                    }
                    Err((path, reason)) => {
                        builder.record_failure(&mut rule, path, reason);
                    }
                }
            }
            InclusionLocation::Folder(folder) => {
                scan_folder_inclusion(
                    folder,
                    inclusion.age_threshold_hours,
                    &rule_id,
                    exclusions,
                    now_ns,
                    &mut budget,
                    cancel,
                    &mut builder,
                    &mut rule,
                    &mut progress,
                );
            }
        }
        if rule.visited == 0 && !rule.available && rule.reason.is_none() {
            rule.reason =
                Some("The inclusion location was unavailable or could not be inspected.".into());
        }
        builder.rules.push(rule);
    }

    let cancelled = cancel.load(Ordering::Relaxed);
    let capabilities = capability_notes(settings);
    let partial = cancelled
        || builder.truncated
        || builder.skipped_count > 0
        || builder
            .rules
            .iter()
            .any(|rule| !rule.available && rule.selected);
    let elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let match_steps_used = builder.matcher.limit - builder.matcher.remaining;
    let date = chrono::DateTime::<chrono::Local>::from(options.now).to_rfc3339();
    let ReportBuilder {
        rules,
        files,
        skipped_entries,
        skipped_count,
        omitted_skip_details,
        truncated,
        ..
    } = builder;
    Ok(CustomCleanReport {
        id: Uuid::new_v4(),
        date,
        settings_fingerprint: settings_fingerprint(settings),
        settings_snapshot: settings.clone(),
        default_age_days: options.default_age_days,
        elapsed_ms,
        match_steps_used,
        match_step_limit: options.max_match_steps,
        cancelled,
        partial,
        truncated,
        skipped_count,
        omitted_skip_details,
        rules,
        files,
        skipped_entries,
        capabilities,
        #[cfg(debug_assertions)]
        visual_fixture: false,
    })
}

fn validate_options(options: &ScanOptions) -> Result<(), String> {
    if !(1..=MAX_MATCH_STEPS).contains(&options.max_match_steps) {
        return Err("Custom Clean matching limit is outside the safe bounds.".into());
    }
    if !(1..=365).contains(&options.default_age_days) {
        return Err("Minimum built-in cache age must be between 1 and 365 days.".into());
    }
    if options.max_entries == 0 || options.max_entries > MAX_ENTRIES {
        return Err("Custom Clean entry limit is outside the shared safe bounds.".into());
    }
    if options.categories.len() > MAX_CUSTOM_RULES {
        return Err("Custom Clean scan input exceeds the safe rule limit.".into());
    }
    let mut seen = HashSet::new();
    for category in &options.categories {
        if category.id.trim().is_empty() || !seen.insert(category.id.as_str()) {
            return Err("Custom Clean built-in category IDs must be nonempty and unique.".into());
        }
    }
    Ok(())
}

#[derive(Default)]
struct ReportBuilder {
    matcher: MatchBudget,
    rules: Vec<RuleScan>,
    files: Vec<CustomCleanFile>,
    file_index: HashMap<String, usize>,
    skipped_entries: Vec<SkippedEntry>,
    skipped_count: usize,
    omitted_skip_details: usize,
    truncated: bool,
}

impl ReportBuilder {
    fn record_failure(&mut self, rule: &mut RuleScan, path: Option<PathBuf>, reason: SkipReason) {
        if reason == SkipReason::MatchingWorkLimit {
            self.truncated = true;
            rule.truncated = true;
            rule.reason =
                Some("Matching work limit reached; remaining locations were not scanned.".into());
        }
        rule.skipped = rule.skipped.saturating_add(1);
        self.skip(Some(rule.id.clone()), path, reason);
    }
    fn add_file(&mut self, candidate: Candidate, rule_id: String, eligibility: RuleEligibility) {
        let key = path_key(&candidate.path);
        if let Some(index) = self.file_index.get(&key).copied() {
            let existing = &mut self.files[index];
            if !existing.matched_rule_ids.contains(&rule_id) {
                existing.matched_rule_ids.push(rule_id.clone());
                existing.matched_rule_ids.sort();
            }
            if !existing
                .eligibility
                .iter()
                .any(|entry| entry.rule_id == rule_id)
            {
                existing.eligibility.push(eligibility);
                existing
                    .eligibility
                    .sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
            }
            // Preserve the first Candidate UUID and root so every overlap shares
            // one immutable file identity.
        } else {
            self.file_index.insert(key, self.files.len());
            self.files.push(CustomCleanFile {
                candidate,
                matched_rule_ids: vec![rule_id],
                eligibility: vec![eligibility],
            });
        }
    }

    fn skip(&mut self, rule_id: Option<String>, path: Option<PathBuf>, reason: SkipReason) {
        self.skipped_count = self.skipped_count.saturating_add(1);
        if self.skipped_entries.len() < MAX_SKIP_DETAILS {
            self.skipped_entries.push(SkippedEntry {
                rule_id,
                path,
                reason,
            });
        } else {
            self.omitted_skip_details = self.omitted_skip_details.saturating_add(1);
        }
    }

    fn mark_truncated(&mut self, rule_id: Option<String>, path: Option<PathBuf>) {
        self.truncated = true;
        self.skip(rule_id, path, SkipReason::EntryLimit);
    }
}

impl RuleScan {
    fn new(id: String, name: String, selected: bool) -> Self {
        Self {
            id,
            name,
            selected,
            available: false,
            visited: 0,
            matched: 0,
            eligible: 0,
            too_recent: 0,
            excluded: 0,
            skipped: 0,
            truncated: false,
            reason: None,
        }
    }
}

fn scan_file_inclusion(
    path: &str,
    rule_id: &str,
    exclusions: &[crate::clean_settings::ExclusionRule],
    budget: &mut usize,
    cancel: &AtomicBool,
    builder: &mut ReportBuilder,
    rule: &mut RuleScan,
) -> Result<Option<Candidate>, (Option<PathBuf>, SkipReason)> {
    if cancel.load(Ordering::Relaxed) {
        return Ok(None);
    }
    if *budget == 0 {
        builder.mark_truncated(Some(rule_id.to_owned()), Some(PathBuf::from(path)));
        rule.truncated = true;
        return Ok(None);
    }
    *budget -= 1;
    rule.visited = rule.visited.saturating_add(1);
    let requested = PathBuf::from(path);
    let absolute = std::path::absolute(&requested)
        .map_err(|_| (Some(requested.clone()), SkipReason::MetadataUnavailable))?;
    let metadata = fs::symlink_metadata(&absolute)
        .map_err(|_| (Some(absolute.clone()), SkipReason::UnavailableRoot))?;
    if is_link(&metadata) {
        return Err((Some(absolute), SkipReason::LinkedEntry));
    }
    if !metadata.is_file() {
        return Err((Some(absolute), SkipReason::NonRegularFile));
    }
    let parent = absolute
        .parent()
        .ok_or_else(|| (Some(absolute.clone()), SkipReason::OutsideRoot))?;
    let root =
        safe_root(parent).map_err(|_| (Some(parent.to_path_buf()), SkipReason::UnavailableRoot))?;
    let canonical = dunce::canonicalize(&absolute)
        .map_err(|_| (Some(absolute.clone()), SkipReason::MetadataUnavailable))?;
    if !same_path(&canonical, &absolute) || !contained(&root, &canonical) {
        return Err((Some(absolute), SkipReason::OutsideRoot));
    }
    rule.available = true;
    if exclusion_reason(&canonical, exclusions, &mut builder.matcher, cancel)
        .map_err(|reason| (Some(canonical.clone()), reason))?
        .is_some()
    {
        rule.excluded = rule.excluded.saturating_add(1);
        return Ok(None);
    }
    let modified_ns = metadata
        .modified()
        .map(timestamp)
        .map_err(|_| (Some(canonical.clone()), SkipReason::MetadataUnavailable))?;
    let candidate = Candidate {
        id: Uuid::new_v4(),
        path: canonical,
        root,
        size: metadata.len(),
        modified_ns,
        created_ns: metadata.created().ok().map(timestamp),
    };
    revalidate_snapshot(&candidate)
        .map_err(|_| (Some(candidate.path.clone()), SkipReason::ChangedDuringScan))?;
    Ok(Some(candidate))
}

#[allow(clippy::too_many_arguments)]
fn scan_folder_inclusion(
    folder: &crate::clean_settings::FolderInclusion,
    age_hours: Option<f64>,
    rule_id: &str,
    exclusions: &[crate::clean_settings::ExclusionRule],
    now_ns: u128,
    budget: &mut usize,
    cancel: &AtomicBool,
    builder: &mut ReportBuilder,
    rule: &mut RuleScan,
    progress: &mut impl FnMut(ScanProgress),
) {
    let root = PathBuf::from(&folder.folder);
    let safe = match safe_root(&root) {
        Ok(root) => root,
        Err(_) => {
            rule.skipped = rule.skipped.saturating_add(1);
            builder.skip(
                Some(rule_id.to_owned()),
                Some(root),
                SkipReason::UnavailableRoot,
            );
            return;
        }
    };
    rule.available = true;
    let mut stack = vec![(safe.clone(), 0usize)];
    while let Some((directory, depth)) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if *budget == 0 {
            rule.truncated = true;
            builder.mark_truncated(Some(rule_id.to_owned()), Some(directory));
            break;
        }
        let safe_directory = match safe_root(&directory) {
            Ok(path)
                if same_path(&path, &directory)
                    && (same_path(&safe, &path) || contained(&safe, &path)) =>
            {
                path
            }
            _ => {
                rule.skipped = rule.skipped.saturating_add(1);
                builder.skip(
                    Some(rule_id.to_owned()),
                    Some(directory),
                    SkipReason::OutsideRoot,
                );
                continue;
            }
        };
        let entries = match fs::read_dir(&safe_directory) {
            Ok(entries) => entries,
            Err(_) => {
                rule.skipped = rule.skipped.saturating_add(1);
                builder.skip(
                    Some(rule_id.to_owned()),
                    Some(safe_directory),
                    SkipReason::ReadDirectoryFailed,
                );
                continue;
            }
        };
        for entry in entries {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            if *budget == 0 {
                rule.truncated = true;
                builder.mark_truncated(Some(rule_id.to_owned()), Some(safe_directory.clone()));
                break;
            }
            *budget -= 1;
            rule.visited = rule.visited.saturating_add(1);
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    rule.skipped = rule.skipped.saturating_add(1);
                    builder.skip(Some(rule_id.to_owned()), None, SkipReason::EntryReadFailed);
                    continue;
                }
            };
            let path = entry.path();
            if !contained(&safe, &path) {
                rule.skipped = rule.skipped.saturating_add(1);
                builder.skip(
                    Some(rule_id.to_owned()),
                    Some(path),
                    SkipReason::OutsideRoot,
                );
                continue;
            }
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => {
                    rule.skipped = rule.skipped.saturating_add(1);
                    builder.skip(
                        Some(rule_id.to_owned()),
                        Some(path),
                        SkipReason::MetadataUnavailable,
                    );
                    continue;
                }
            };
            if is_link(&metadata) {
                rule.skipped = rule.skipped.saturating_add(1);
                builder.skip(
                    Some(rule_id.to_owned()),
                    Some(path),
                    SkipReason::LinkedEntry,
                );
                continue;
            }
            if metadata.is_dir() {
                if !folder.recursive {
                    continue;
                }
                if depth >= MAX_SCAN_DEPTH {
                    rule.skipped = rule.skipped.saturating_add(1);
                    builder.skip(Some(rule_id.to_owned()), Some(path), SkipReason::DepthLimit);
                    continue;
                }
                match safe_root(&path) {
                    Ok(child) if same_path(&child, &path) && contained(&safe, &child) => {
                        match is_excluded_directory(
                            &child,
                            exclusions,
                            &mut builder.matcher,
                            cancel,
                        ) {
                            Ok(false) => stack.push((child, depth + 1)),
                            Ok(true) => rule.excluded = rule.excluded.saturating_add(1),
                            Err(reason) => {
                                builder.record_failure(rule, Some(child), reason);
                                if builder.matcher.exhausted || cancel.load(Ordering::Relaxed) {
                                    return;
                                }
                            }
                        }
                    }
                    _ => {
                        rule.skipped = rule.skipped.saturating_add(1);
                        builder.skip(
                            Some(rule_id.to_owned()),
                            Some(path),
                            SkipReason::OutsideRoot,
                        );
                    }
                }
                continue;
            }
            if !metadata.is_file() {
                rule.skipped = rule.skipped.saturating_add(1);
                builder.skip(
                    Some(rule_id.to_owned()),
                    Some(path),
                    SkipReason::NonRegularFile,
                );
                continue;
            }
            let canonical = match dunce::canonicalize(&path) {
                Ok(canonical) if same_path(&canonical, &path) && contained(&safe, &canonical) => {
                    canonical
                }
                _ => {
                    rule.skipped = rule.skipped.saturating_add(1);
                    builder.skip(
                        Some(rule_id.to_owned()),
                        Some(path),
                        SkipReason::OutsideRoot,
                    );
                    continue;
                }
            };
            let matching = matches_folder_filter(
                &canonical,
                &safe,
                folder.filter.as_deref(),
                &mut builder.matcher,
                cancel,
            )
            .and_then(|included| {
                if !included {
                    return Ok(false);
                }
                exclusion_reason(&canonical, exclusions, &mut builder.matcher, cancel).map(
                    |reason| {
                        if reason.is_some() {
                            rule.excluded = rule.excluded.saturating_add(1);
                        }
                        reason.is_none()
                    },
                )
            });
            match matching {
                Ok(true) => {}
                Ok(false) => continue,
                Err(reason) => {
                    builder.record_failure(rule, Some(canonical), reason);
                    if builder.matcher.exhausted || cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    continue;
                }
            }
            let modified_ns = match metadata.modified() {
                Ok(modified) => timestamp(modified),
                Err(_) => {
                    rule.skipped = rule.skipped.saturating_add(1);
                    builder.skip(
                        Some(rule_id.to_owned()),
                        Some(canonical),
                        SkipReason::MetadataUnavailable,
                    );
                    continue;
                }
            };
            let age_ok = age_eligible(modified_ns, age_hours, now_ns);
            let eligible = age_ok;
            if !eligible {
                rule.too_recent = rule.too_recent.saturating_add(1);
            }
            rule.matched = rule.matched.saturating_add(1);
            if eligible {
                rule.eligible = rule.eligible.saturating_add(1);
            }
            let candidate = Candidate {
                id: Uuid::new_v4(),
                path: canonical,
                root: safe.clone(),
                size: metadata.len(),
                modified_ns,
                created_ns: metadata.created().ok().map(timestamp),
            };
            if revalidate_snapshot(&candidate).is_err() {
                rule.skipped = rule.skipped.saturating_add(1);
                builder.skip(
                    Some(rule_id.to_owned()),
                    Some(candidate.path.clone()),
                    SkipReason::ChangedDuringScan,
                );
                continue;
            }
            let eligibility =
                eligibility_for_custom(rule_id, true, modified_ns, age_hours, now_ns, false);
            builder.add_file(candidate, rule_id.to_owned(), eligibility);
            progress(ScanProgress {
                rule_id: rule_id.to_owned(),
                rule_name: rule.name.clone(),
                visited: rule.visited,
                matched: rule.matched,
            });
        }
    }
    if folder.delete_self {
        // The active capability is emitted once below; this note lets the view
        // associate the unsupported directory-self action with its rule.
    }
}

fn eligibility_for_custom(
    rule_id: &str,
    selected: bool,
    modified_ns: u128,
    age_hours: Option<f64>,
    now_ns: u128,
    temporary_24h_applied: bool,
) -> RuleEligibility {
    let mut cutoff_ns = age_hours
        .map(|hours| now_ns.saturating_sub(hours_to_ns(hours)))
        .unwrap_or(u128::MAX);
    if temporary_24h_applied {
        cutoff_ns = cutoff_ns.min(now_ns.saturating_sub(TEMP_AGE_NS));
    }
    RuleEligibility {
        rule_id: rule_id.into(),
        selected,
        eligible: modified_ns <= cutoff_ns,
        cutoff_ns,
        age_threshold_hours: age_hours,
        age_threshold_days: None,
        temporary_24h_applied,
    }
}

fn age_eligible(modified_ns: u128, age_hours: Option<f64>, now_ns: u128) -> bool {
    age_hours.is_none_or(|hours| modified_ns <= now_ns.saturating_sub(hours_to_ns(hours)))
}

fn hours_to_ns(hours: f64) -> u128 {
    if !hours.is_finite() || hours <= 0.0 {
        0
    } else {
        (hours * HOUR_NS).ceil() as u128
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_legacy_root(
    requested_root: &Path,
    rule_id: &str,
    rule_name: &str,
    cutoff_ns: u128,
    settings: &CustomCleanSettings,
    exclusions: &[crate::clean_settings::ExclusionRule],
    now_ns: u128,
    age_days: u32,
    budget: &mut usize,
    cancel: &AtomicBool,
    builder: &mut ReportBuilder,
    rule: &mut RuleScan,
    progress: &mut impl FnMut(ScanProgress),
) {
    let root = match safe_root(requested_root) {
        Ok(root) => root,
        Err(_) => {
            rule.skipped = rule.skipped.saturating_add(1);
            builder.skip(
                Some(rule_id.to_owned()),
                Some(requested_root.to_path_buf()),
                SkipReason::UnavailableRoot,
            );
            return;
        }
    };
    rule.available = true;
    let mut stack = vec![(root.clone(), 0usize)];
    while let Some((directory, depth)) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if *budget == 0 {
            rule.truncated = true;
            builder.mark_truncated(Some(rule_id.to_owned()), Some(directory));
            break;
        }
        let safe_directory = match safe_root(&directory) {
            Ok(path)
                if same_path(&path, &directory)
                    && (same_path(&root, &path) || contained(&root, &path)) =>
            {
                path
            }
            _ => {
                rule.skipped = rule.skipped.saturating_add(1);
                builder.skip(
                    Some(rule_id.to_owned()),
                    Some(directory),
                    SkipReason::OutsideRoot,
                );
                continue;
            }
        };
        let entries = match fs::read_dir(&safe_directory) {
            Ok(entries) => entries,
            Err(_) => {
                rule.skipped = rule.skipped.saturating_add(1);
                builder.skip(
                    Some(rule_id.to_owned()),
                    Some(safe_directory),
                    SkipReason::ReadDirectoryFailed,
                );
                continue;
            }
        };
        for entry in entries {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            if *budget == 0 {
                rule.truncated = true;
                builder.mark_truncated(Some(rule_id.to_owned()), Some(safe_directory.clone()));
                break;
            }
            *budget -= 1;
            rule.visited = rule.visited.saturating_add(1);
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    rule.skipped = rule.skipped.saturating_add(1);
                    builder.skip(Some(rule_id.to_owned()), None, SkipReason::EntryReadFailed);
                    continue;
                }
            };
            let path = entry.path();
            if !contained(&root, &path) {
                rule.skipped = rule.skipped.saturating_add(1);
                builder.skip(
                    Some(rule_id.to_owned()),
                    Some(path),
                    SkipReason::OutsideRoot,
                );
                continue;
            }
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => {
                    rule.skipped = rule.skipped.saturating_add(1);
                    builder.skip(
                        Some(rule_id.to_owned()),
                        Some(path),
                        SkipReason::MetadataUnavailable,
                    );
                    continue;
                }
            };
            if is_link(&metadata) {
                rule.skipped = rule.skipped.saturating_add(1);
                builder.skip(
                    Some(rule_id.to_owned()),
                    Some(path),
                    SkipReason::LinkedEntry,
                );
                continue;
            }
            if metadata.is_dir() {
                if depth >= MAX_SCAN_DEPTH {
                    rule.skipped = rule.skipped.saturating_add(1);
                    builder.skip(Some(rule_id.to_owned()), Some(path), SkipReason::DepthLimit);
                    continue;
                }
                match safe_root(&path) {
                    Ok(child) if same_path(&child, &path) && contained(&root, &child) => {
                        match is_excluded_directory(
                            &child,
                            exclusions,
                            &mut builder.matcher,
                            cancel,
                        ) {
                            Ok(false) => stack.push((child, depth + 1)),
                            Ok(true) => rule.excluded = rule.excluded.saturating_add(1),
                            Err(reason) => {
                                builder.record_failure(rule, Some(child), reason);
                                if builder.matcher.exhausted || cancel.load(Ordering::Relaxed) {
                                    return;
                                }
                            }
                        }
                    }
                    _ => {
                        rule.skipped = rule.skipped.saturating_add(1);
                        builder.skip(
                            Some(rule_id.to_owned()),
                            Some(path),
                            SkipReason::OutsideRoot,
                        );
                    }
                }
                continue;
            }
            if !metadata.is_file() {
                rule.skipped = rule.skipped.saturating_add(1);
                builder.skip(
                    Some(rule_id.to_owned()),
                    Some(path),
                    SkipReason::NonRegularFile,
                );
                continue;
            }
            let canonical = match dunce::canonicalize(&path) {
                Ok(canonical) if same_path(&canonical, &path) && contained(&root, &canonical) => {
                    canonical
                }
                _ => {
                    rule.skipped = rule.skipped.saturating_add(1);
                    builder.skip(
                        Some(rule_id.to_owned()),
                        Some(path),
                        SkipReason::OutsideRoot,
                    );
                    continue;
                }
            };
            match exclusion_reason(&canonical, exclusions, &mut builder.matcher, cancel) {
                Ok(Some(_)) => {
                    rule.excluded = rule.excluded.saturating_add(1);
                    continue;
                }
                Ok(None) => {}
                Err(reason) => {
                    builder.record_failure(rule, Some(canonical), reason);
                    if builder.matcher.exhausted || cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    continue;
                }
            }
            let modified_ns = match metadata.modified() {
                Ok(modified) => timestamp(modified),
                Err(_) => {
                    rule.skipped = rule.skipped.saturating_add(1);
                    builder.skip(
                        Some(rule_id.to_owned()),
                        Some(canonical),
                        SkipReason::MetadataUnavailable,
                    );
                    continue;
                }
            };
            let is_temp = is_temporary_rule(rule_id)
                && settings.file_deletion.temp_folders_only_older_than_24h;
            let temp_cutoff_ns = now_ns.saturating_sub(TEMP_AGE_NS);
            let effective_cutoff_ns = if is_temp {
                cutoff_ns.min(temp_cutoff_ns)
            } else {
                cutoff_ns
            };
            if modified_ns > effective_cutoff_ns {
                rule.too_recent = rule.too_recent.saturating_add(1);
                continue;
            }
            rule.matched = rule.matched.saturating_add(1);
            rule.eligible = rule.eligible.saturating_add(1);
            let candidate = Candidate {
                id: Uuid::new_v4(),
                path: canonical,
                root: root.clone(),
                size: metadata.len(),
                modified_ns,
                created_ns: metadata.created().ok().map(timestamp),
            };
            if let Err(error) = revalidate_snapshot(&candidate) {
                let _ = error;
                rule.skipped = rule.skipped.saturating_add(1);
                builder.skip(
                    Some(rule_id.to_owned()),
                    Some(candidate.path),
                    SkipReason::ChangedDuringScan,
                );
                continue;
            }
            let eligibility = RuleEligibility {
                rule_id: rule_id.to_owned(),
                selected: true,
                eligible: true,
                cutoff_ns: effective_cutoff_ns,
                age_threshold_hours: None,
                age_threshold_days: Some(age_days),
                temporary_24h_applied: is_temp,
            };
            builder.add_file(candidate, rule_id.to_owned(), eligibility);
            progress(ScanProgress {
                rule_id: rule_id.to_owned(),
                rule_name: rule_name.to_owned(),
                visited: rule.visited,
                matched: rule.matched,
            });
        }
    }
}

fn is_temporary_rule(rule_id: &str) -> bool {
    matches!(rule_id, "temp" | "windows.tempfiles")
}

#[derive(Default)]
struct MatchBudget {
    limit: usize,
    remaining: usize,
    exhausted: bool,
}
impl MatchBudget {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            remaining: limit,
            exhausted: false,
        }
    }
    fn charge(&mut self, units: usize, cancel: &AtomicBool) -> Result<(), SkipReason> {
        if cancel.load(Ordering::Relaxed) {
            return Err(SkipReason::MatchingCancelled);
        }
        if self.exhausted || units > self.remaining {
            self.remaining = 0;
            self.exhausted = true;
            return Err(SkipReason::MatchingWorkLimit);
        }
        self.remaining -= units;
        Ok(())
    }
    fn normalize(
        &mut self,
        value: &str,
        maximum: usize,
        cancel: &AtomicBool,
    ) -> Result<String, SkipReason> {
        if value.len() > maximum {
            return Err(SkipReason::MatchingInputLimit);
        }
        self.charge(value.len() + 1, cancel)?;
        let normalized = normalized_text(value);
        if normalized.len() > maximum {
            return Err(SkipReason::MatchingInputLimit);
        }
        Ok(normalized)
    }
    fn path(&mut self, path: &Path, cancel: &AtomicBool) -> Result<String, SkipReason> {
        self.normalize(
            path.to_str().ok_or(SkipReason::MatchingInputLimit)?,
            MAX_MATCH_INPUT_BYTES,
            cancel,
        )
    }
}

fn is_excluded_directory(
    path: &Path,
    rules: &[crate::clean_settings::ExclusionRule],
    budget: &mut MatchBudget,
    cancel: &AtomicBool,
) -> Result<bool, SkipReason> {
    let mut value = None;
    for rule in rules
        .iter()
        .filter(|rule| rule.exclusion_type == ExclusionType::Path)
    {
        if value.is_none() {
            value = Some(budget.path(path, cancel)?);
        }
        let pattern = budget.normalize(&rule.path, MAX_FILTER_BYTES, cancel)?;
        if path_rule_matches(
            value.as_deref().expect("normalized above"),
            &pattern,
            budget,
            cancel,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn exclusion_reason(
    path: &Path,
    rules: &[crate::clean_settings::ExclusionRule],
    budget: &mut MatchBudget,
    cancel: &AtomicBool,
) -> Result<Option<SkipReason>, SkipReason> {
    let mut value = None;
    for rule in rules {
        if !matches!(
            rule.exclusion_type,
            ExclusionType::File | ExclusionType::Path
        ) {
            continue;
        }
        if value.is_none() {
            value = Some(budget.path(path, cancel)?);
        }
        let value = value.as_deref().expect("normalized above");
        let pattern = budget.normalize(&rule.path, MAX_FILTER_BYTES, cancel)?;
        let matched = match rule.exclusion_type {
            ExclusionType::File => file_rule_matches(value, &pattern, budget, cancel)?,
            ExclusionType::Path => path_rule_matches(value, &pattern, budget, cancel)?,
            _ => unreachable!(),
        };
        if matched {
            return Ok(Some(if rule.exclusion_type == ExclusionType::File {
                SkipReason::ExcludedByFileRule
            } else {
                SkipReason::ExcludedByPathRule
            }));
        }
    }
    Ok(None)
}

fn file_rule_matches(
    path: &str,
    pattern: &str,
    budget: &mut MatchBudget,
    cancel: &AtomicBool,
) -> Result<bool, SkipReason> {
    if has_glob(pattern) {
        glob_matches(pattern, path, budget, cancel)
    } else {
        budget.charge(path.len() + pattern.len() + 1, cancel)?;
        Ok(path == pattern)
    }
}

fn path_rule_matches(
    path: &str,
    pattern: &str,
    budget: &mut MatchBudget,
    cancel: &AtomicBool,
) -> Result<bool, SkipReason> {
    if has_glob(pattern) {
        glob_matches(pattern, path, budget, cancel)
    } else {
        budget.charge(path.len() + pattern.len() + 1, cancel)?;
        let pattern = pattern.trim_end_matches('/');
        Ok(path == pattern
            || path
                .strip_prefix(pattern)
                .is_some_and(|tail| tail.starts_with('/')))
    }
}

fn matches_folder_filter(
    path: &Path,
    root: &Path,
    filters: Option<&[String]>,
    budget: &mut MatchBudget,
    cancel: &AtomicBool,
) -> Result<bool, SkipReason> {
    let Some(filters) = filters.filter(|filters| !filters.is_empty()) else {
        return Ok(true);
    };
    let basename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(SkipReason::MatchingInputLimit)?;
    let basename = budget.normalize(basename, MAX_MATCH_INPUT_BYTES, cancel)?;
    let relative = budget.path(path.strip_prefix(root).unwrap_or(path), cancel)?;
    for filter in filters {
        let filter = budget.normalize(filter, MAX_FILTER_BYTES, cancel)?;
        let value = if filter.contains('/') {
            &relative
        } else {
            &basename
        };
        if glob_matches(&filter, value, budget, cancel)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn has_glob(value: &str) -> bool {
    value.contains('*') || value.contains('?')
}

/// Linear-space wildcard matching with one remembered `*`; pattern and path
/// input lengths are separately bounded before scanning.
fn glob_matches(
    pattern: &str,
    value: &str,
    budget: &mut MatchBudget,
    cancel: &AtomicBool,
) -> Result<bool, SkipReason> {
    if pattern.len() > MAX_FILTER_BYTES || value.len() > MAX_MATCH_INPUT_BYTES {
        return Err(SkipReason::MatchingInputLimit);
    }
    budget.charge(pattern.len() + value.len() + 1, cancel)?;
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let (mut p, mut v) = (0usize, 0usize);
    let mut star = None;
    let mut retry = 0usize;
    while v < value.len() {
        budget.charge(1, cancel)?;
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(star_position) = star {
            retry += 1;
            v = retry;
            p = star_position + 1;
        } else {
            return Ok(false);
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        budget.charge(1, cancel)?;
        p += 1;
    }
    Ok(p == pattern.len())
}

fn normalized_path(path: &Path) -> String {
    normalized_text(&path.to_string_lossy())
}

#[cfg(test)]
mod matching_tests {
    use super::*;

    fn oracle(pattern: &[u8], value: &[u8]) -> bool {
        let mut row = vec![false; value.len() + 1];
        row[0] = true;
        for &symbol in pattern {
            let mut next = vec![false; value.len() + 1];
            next[0] = symbol == b'*' && row[0];
            for index in 1..=value.len() {
                next[index] = if symbol == b'*' {
                    row[index] || next[index - 1]
                } else {
                    row[index - 1] && (symbol == b'?' || symbol == value[index - 1])
                };
            }
            row = next;
        }
        row[value.len()]
    }
    fn words(alphabet: &[char], length: usize) -> Vec<String> {
        let mut all = vec![String::new()];
        let mut level = vec![String::new()];
        for _ in 0..length {
            level = level
                .iter()
                .flat_map(|word| alphabet.iter().map(move |symbol| format!("{word}{symbol}")))
                .collect();
            all.extend(level.iter().cloned());
        }
        all
    }
    #[test]
    fn bounded_matcher_preserves_wildcard_semantics_against_independent_oracle() {
        let cancel = AtomicBool::new(false);
        for pattern in words(&['a', 'b', '?', '*'], 4) {
            for value in words(&['a', 'b'], 4) {
                assert_eq!(
                    glob_matches(&pattern, &value, &mut MatchBudget::new(10_000), &cancel),
                    Ok(oracle(pattern.as_bytes(), value.as_bytes())),
                    "{pattern:?} / {value:?}"
                );
            }
        }
    }
    #[test]
    fn wildcard_retries_cannot_exceed_shared_work_budget() {
        let cancel = AtomicBool::new(false);
        let mut budget = MatchBudget::new(4096);
        let pattern = format!("*{}b", "a".repeat(64));
        let value = "a".repeat(2000);
        assert_eq!(
            glob_matches(&pattern, &value, &mut budget, &cancel),
            Err(SkipReason::MatchingWorkLimit)
        );
        assert!(budget.exhausted);
        assert_eq!(budget.remaining, 0);
        assert_eq!(
            glob_matches("*", "safe", &mut budget, &cancel),
            Err(SkipReason::MatchingWorkLimit)
        );
    }
    #[test]
    fn oversized_unicode_exclusion_input_is_an_error_instead_of_a_false_match() {
        let cancel = AtomicBool::new(false);
        let path = PathBuf::from("文".repeat(11_000));
        let rules = vec![crate::clean_settings::ExclusionRule {
            exclusion_type: ExclusionType::File,
            path: "*".into(),
        }];
        let mut budget = MatchBudget::new(MAX_MATCH_STEPS);
        assert_eq!(
            exclusion_reason(&path, &rules, &mut budget, &cancel),
            Err(SkipReason::MatchingInputLimit)
        );
        assert!(!budget.exhausted);
    }
    #[test]
    fn cancellation_prevents_subsequent_match_work_without_becoming_a_nonmatch() {
        let cancel = AtomicBool::new(false);
        let mut budget = MatchBudget::new(10_000);
        assert_eq!(glob_matches("*", "first", &mut budget, &cancel), Ok(true));
        let remaining = budget.remaining;
        cancel.store(true, Ordering::Relaxed);
        assert_eq!(
            glob_matches("*a*b", "second", &mut budget, &cancel),
            Err(SkipReason::MatchingCancelled)
        );
        assert_eq!(budget.remaining, remaining);
    }
}

fn normalized_text(value: &str) -> String {
    let separators = value.replace('\\', "/");
    if cfg!(windows) {
        separators.chars().flat_map(char::to_lowercase).collect()
    } else {
        separators
    }
}

fn path_key(path: &Path) -> String {
    normalized_path(path)
}

fn inclusion_name(rule: &InclusionRule) -> String {
    match &rule.location {
        InclusionLocation::File(path) => Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone()),
        InclusionLocation::Folder(folder) => folder.folder.clone(),
    }
}

fn settings_fingerprint(settings: &CustomCleanSettings) -> String {
    let bytes = serde_json::to_vec(settings).unwrap_or_default();
    let first = stable_hash(&bytes, 0xcbf29ce484222325);
    let second = stable_hash(&bytes, 0x84222325cbf29ce4);
    format!("{first:016x}{second:016x}")
}

fn stable_hash(bytes: &[u8], mut hash: u64) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn capability_notes(settings: &CustomCleanSettings) -> Vec<CapabilityNote> {
    let mut notes = Vec::new();
    let custom_enabled = settings.rule_selection(".custom") == Some(true);
    for inclusion in &settings.inclusions {
        if let InclusionLocation::Folder(folder) = &inclusion.location {
            if folder.delete_self {
                let rule_id = rule_id_for_inclusion(inclusion);
                let rule_selected =
                    custom_enabled && settings.rule_selection(&rule_id).unwrap_or(true);
                notes.push(CapabilityNote {
                    kind: CapabilityKind::DeleteInclusionFolder,
                    blocking: rule_selected,
                    rule_id: Some(rule_id),
                    detail: if rule_selected {
                        "Removing an inclusion folder itself is unsupported; files selected through that rule cannot be cleaned.".into()
                    } else {
                        "Removing an inclusion folder itself is stored but unsupported; this rule is not selected.".into()
                    },
                });
            }
        }
    }
    if settings.exclusions.iter().any(|exclusion| {
        matches!(
            exclusion.exclusion_type,
            ExclusionType::RegistryKey | ExclusionType::RegistryKeyValue
        )
    }) {
        notes.push(CapabilityNote {
            kind: CapabilityKind::RegistryExclusion,
            blocking: false,
            rule_id: None,
            detail: "Registry exclusions are stored preferences and are not interpreted by the file scanner.".into(),
        });
    }
    if settings
        .exclusions
        .iter()
        .any(|exclusion| exclusion.exclusion_type == ExclusionType::Cookie)
    {
        notes.push(CapabilityNote {
            kind: CapabilityKind::CookieExclusion,
            blocking: false,
            rule_id: None,
            detail: "Cookie exclusions are stored settings and are not applied by this filesystem scanner.".into(),
        });
    }
    if settings.file_deletion.recycle_bin_only_older_than_24h {
        notes.push(CapabilityNote {
            kind: CapabilityKind::RecycleBinAgePolicy,
            blocking: false,
            rule_id: None,
            detail: "Recycle Bin age is stored but is not applied by this filesystem scanner."
                .into(),
        });
    }
    let advanced = &settings.advanced_filter_options;
    if advanced.file_deletion == FileDeletionMode::Secure {
        notes.push(global_block(
            CapabilityKind::SecureFileDeletion,
            "Secure deletion is stored but unsupported; normal Trash movement is not substituted.",
        ));
    }
    if advanced.overwrite_type != OverwriteType::Disabled {
        notes.push(global_block(
            CapabilityKind::OverwritePasses,
            "Overwrite passes are stored but unsupported.",
        ));
    }
    if advanced.wipe_free_space {
        notes.push(global_block(
            CapabilityKind::WipeFreeSpace,
            "Free-space wiping is stored but unsupported.",
        ));
    }
    if advanced.wipe_alternate_data_streams {
        notes.push(global_block(
            CapabilityKind::WipeAlternateDataStreams,
            "Alternate-stream wiping is stored but unsupported.",
        ));
    }
    if advanced
        .wipe_free_space_drives
        .iter()
        .any(|drive| drive.wipe_mft_free_space)
    {
        notes.push(global_block(
            CapabilityKind::WipeDriveMftFreeSpace,
            "Drive MFT free-space wiping is stored but unsupported.",
        ));
    }
    if settings.shutdown_after_cleaning {
        notes.push(global_block(
            CapabilityKind::ShutdownAfterCleaning,
            "Shutdown after cleaning is stored but unsupported.",
        ));
    }
    if !settings.skipped_close_programs.is_empty() {
        notes.push(CapabilityNote {
            kind: CapabilityKind::SkipCloseProcesses,
            blocking: false,
            rule_id: None,
            detail: "Skipped-close-program preferences are stored; this scanner does not close or coordinate processes.".into(),
        });
    }
    notes
}

fn global_block(kind: CapabilityKind, detail: &str) -> CapabilityNote {
    CapabilityNote {
        kind,
        blocking: true,
        rule_id: None,
        detail: detail.into(),
    }
}

fn revalidate_snapshot(candidate: &Candidate) -> Result<(), String> {
    let root = safe_root(&candidate.root)
        .map_err(|_| "The scanned file root is unavailable or redirected.".to_owned())?;
    if !same_path(&root, &candidate.root) || !contained(&root, &candidate.path) {
        return Err("The file is outside its scanned root.".into());
    }
    let metadata = fs::symlink_metadata(&candidate.path)
        .map_err(|_| "The file is unavailable after scanning.".to_owned())?;
    if is_link(&metadata) || !metadata.is_file() {
        return Err("The file became a link or is no longer a regular file.".into());
    }
    let canonical = dunce::canonicalize(&candidate.path)
        .map_err(|_| "The file path changed after scanning.".to_owned())?;
    if !same_path(&canonical, &candidate.path) || !contained(&root, &canonical) {
        return Err("The file location changed after scanning.".into());
    }
    let modified_ns = metadata
        .modified()
        .map(timestamp)
        .map_err(|_| "The file modification time is unavailable.".to_owned())?;
    if metadata.len() != candidate.size
        || modified_ns != candidate.modified_ns
        || metadata.created().ok().map(timestamp) != candidate.created_ns
    {
        return Err("The file changed after the Custom Clean scan.".into());
    }
    Ok(())
}
