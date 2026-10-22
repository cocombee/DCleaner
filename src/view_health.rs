use super::{App, CleanupHistory, Event};
use crate::theme::{self, Tokens};
use dcleaner::{
    cleanup::{self, SystemTrash},
    effects::EffectJournal,
    health::{
        self, HealthAction, HealthActionPlan, HealthCategory, HealthCategoryReport, HealthCoverage,
        HealthEffectQuality, HealthEffectReceipt, HealthFinding, HealthFindingId,
        HealthScanQuality, HealthServiceData, HealthStep, HealthStepReport, HealthStepStatus,
    },
    privacy::{self, Browser, CloseRequestReport, CookieExceptionSettings, RunningBrowser},
    recycle_bin::{self, SystemRecycleBin},
    software::{self},
    store::{self, Journal},
};
use eframe::egui::{self, Align, Layout, RichText};
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
use uuid::Uuid;

pub(super) struct HealthUi {
    coordinator: health::HealthCoordinator,
    started: bool,
    initialized: bool,
    initializing: bool,
    running: Vec<RunningBrowser>,
    browser_icons: std::collections::HashMap<Browser, String>,
    process_error: Option<String>,
    browser_review_open: bool,
    selected_processes: HashSet<(Browser, u32)>,
    cookie_settings: CookieExceptionSettings,
    cookie_settings_readable: bool,
    cookie_settings_error: Option<String>,
    cookie_settings_stale: bool,
    expanded_categories: Vec<HealthCategory>,
    partial_acknowledged: bool,
    scan_details_open: bool,
    permanent_acknowledged: bool,
    detail_id: Option<HealthFindingId>,
    action_plan: Option<HealthActionPlan>,
}

impl Default for HealthUi {
    fn default() -> Self {
        Self {
            coordinator: health::HealthCoordinator::new(),
            started: false,
            initialized: false,
            initializing: false,
            running: Vec::new(),
            browser_icons: Default::default(),
            process_error: None,
            browser_review_open: false,
            selected_processes: HashSet::new(),
            cookie_settings: CookieExceptionSettings::default(),
            cookie_settings_readable: false,
            cookie_settings_error: None,
            cookie_settings_stale: false,
            expanded_categories: Vec::new(),
            partial_acknowledged: false,
            scan_details_open: false,
            permanent_acknowledged: false,
            detail_id: None,
            action_plan: None,
        }
    }
}

pub(super) enum HealthEvent {
    Prerequisites {
        running: Result<Vec<RunningBrowser>, String>,
        browser_icons: std::collections::HashMap<Browser, String>,
        cookie_settings: Result<CookieExceptionSettings, String>,
    },
    RunningBrowsers(Result<Vec<RunningBrowser>, String>),
    BrowserClose {
        report: CloseRequestReport,
        remaining: Result<Vec<RunningBrowser>, String>,
    },
    ScanProgress {
        step: HealthStep,
        completed: u64,
        total: Option<u64>,
        detail: Option<String>,
    },
    ScanFinished(HealthStepReport),
    EffectProgress(String),
    EffectsFinished {
        plan_id: Uuid,
        receipts: Vec<HealthEffectReceipt>,
        issues: Vec<String>,
        attempted: bool,
        uncertain: bool,
        cancelled_before_any: bool,
        history: CleanupHistory,
    },
}

struct HealthEffectRun {
    receipts: Vec<HealthEffectReceipt>,
    issues: Vec<String>,
    attempted: bool,
    uncertain: bool,
    cancelled_before_any: bool,
}

#[derive(serde::Serialize)]
struct HealthUpdateFailure<'a> {
    request_id: Uuid,
    error: &'a str,
}

impl App {
    pub(super) fn sync_health_cookie_settings(&mut self, settings: CookieExceptionSettings) {
        let changed = settings != self.health_ui.cookie_settings;
        self.health_ui.cookie_settings = settings;
        self.health_ui.cookie_settings_readable = true;
        self.health_ui.cookie_settings_error = None;
        if changed
            && self
                .health_ui
                .coordinator
                .report(HealthStep::Privacy)
                .is_some()
        {
            self.health_ui.cookie_settings_stale = true;
            if self.health_ui.coordinator.current_step() != Some(HealthStep::Privacy) {
                return;
            }
            if let Some(plan_id) = self
                .health_ui
                .action_plan
                .as_ref()
                .map(HealthActionPlan::id)
            {
                match self.health_ui.coordinator.cancel_action_review(plan_id) {
                    Ok(()) => self.health_ui.action_plan = None,
                    Err(error) => self.error = Some(error),
                }
            }
            self.health_ui.permanent_acknowledged = false;
            if matches!(
                self.health_ui.coordinator.status(HealthStep::Privacy),
                HealthStepStatus::Reviewing { .. }
            ) {
                let _ = self.health_ui.coordinator.deselect_all();
            }
        }
    }

    pub(super) fn mark_health_cookie_settings_unverified(&mut self, message: &str) {
        self.health_ui.cookie_settings_readable = false;
        self.health_ui.cookie_settings_error = Some(message.to_owned());
        self.health_ui.cookie_settings_stale = true;
        if self.health_ui.coordinator.current_step() != Some(HealthStep::Privacy) {
            return;
        }
        if let Some(plan_id) = self
            .health_ui
            .action_plan
            .as_ref()
            .map(HealthActionPlan::id)
        {
            match self.health_ui.coordinator.cancel_action_review(plan_id) {
                Ok(()) => self.health_ui.action_plan = None,
                Err(error) => self.error = Some(error),
            }
        }
        self.health_ui.permanent_acknowledged = false;
        if matches!(
            self.health_ui.coordinator.status(HealthStep::Privacy),
            HealthStepStatus::Reviewing { .. }
        ) {
            let _ = self.health_ui.coordinator.deselect_all();
        }
    }

    #[cfg(test)]
    pub(super) fn health_cookie_test_state(
        &self,
    ) -> (CookieExceptionSettings, bool, bool, bool, bool) {
        (
            self.health_ui.cookie_settings.clone(),
            self.health_ui.cookie_settings_readable,
            self.health_ui.cookie_settings_stale,
            self.health_ui
                .coordinator
                .report(HealthStep::Privacy)
                .is_some(),
            self.health_ui.action_plan.is_some(),
        )
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_health_state(&self) -> serde_json::Value {
        let step = self.health_ui.coordinator.current_step();
        serde_json::json!({
            "step": step.map(step_label),
            "review_open": self.health_ui.action_plan.is_some(),
            "details_open": self.health_ui.detail_id.is_some(),
            "expanded": self.health_ui.expanded_categories.iter().map(|category| category_label(*category)).collect::<Vec<_>>(),
            "selected": step.map(|step| self.health_ui.coordinator.selected_ids(step).len()).unwrap_or(0),
            "cancel_requested": self.cancel.load(Ordering::Relaxed),
            "privacy_rules_blocked": self.health_privacy_rules_blocked(),
            "browser_review_open": self.health_ui.browser_review_open,
            "selected_browser_processes": self.health_ui.selected_processes.len(),
            "started": self.health_ui.started,
            "scan_details_open": self.health_ui.scan_details_open,
            "partial_acknowledged": self.health_ui.partial_acknowledged,
        })
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_health_action(&self, label: &str, after: bool) -> Option<bool> {
        let state = self.qa_health_state();
        Some(match label {
            "Select Google Chrome Temporary internet files" => {
                self.health_ui.coordinator.current_step() == Some(HealthStep::Privacy)
                    && self
                        .health_ui
                        .expanded_categories
                        .contains(&HealthCategory::InternetTemporaryFiles)
                    && !self.health_privacy_rules_blocked()
            }
            "Scan details" => state["scan_details_open"] == after,
            "Hide scan details" => state["scan_details_open"] == !after,
            "I reviewed the partial-scan warning" => state["partial_acknowledged"] == after,
            "Cookie settings" => self.qa_clean_settings_state()["open"] == after,
            "Close settings" => self.qa_clean_settings_state()["open"] == !after,
            "Clean" | "Resolve" => state["review_open"] == after,
            "Back to findings" | "Close Health review" => state["review_open"] == !after,
            "Close finding details" | "Close details" => state["details_open"] == !after,
            "Show Temporary internet files" | "Show Browsing history" => {
                state["expanded"]
                    .as_array()?
                    .iter()
                    .any(|value| value == label.trim_start_matches("Show "))
                    == after
            }
            "Hide Temporary internet files" | "Hide Browsing history" => {
                state["expanded"]
                    .as_array()?
                    .iter()
                    .any(|value| value == label.trim_start_matches("Hide "))
                    == !after
            }
            "Select all Health findings" => {
                if after {
                    state["selected"] == 0
                } else {
                    state["selected"].as_u64()? > 0
                }
            }
            "Stop scan" | "Stop cleaning" => state["cancel_requested"] == after,
            "Skip" => state["step"] == if after { "More space" } else { "More privacy" },
            "Details" => state["details_open"] == after,
            "Close" => state["details_open"] == !after,
            "Select all" => {
                state["browser_review_open"] == true
                    && if after {
                        state["selected_browser_processes"] == 0
                    } else {
                        state["selected_browser_processes"].as_u64()? > 0
                    }
            }
            "Skip closing browsers" => {
                if after {
                    state["browser_review_open"] == false
                        && matches!(
                            self.health_ui.coordinator.status(HealthStep::Privacy),
                            HealthStepStatus::Ready
                        )
                } else {
                    state["browser_review_open"] == true && state["selected_browser_processes"] == 0
                }
            }
            "Cancel" | "Cancel browser review" => {
                if after {
                    state["browser_review_open"] == false && state["started"] == false
                } else {
                    state["browser_review_open"] == true
                }
            }
            _ => return None,
        })
    }

    #[cfg(debug_assertions)]
    pub(super) fn seed_health_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Health fixtures are available only in isolated visual QA.".into());
        }
        if case != "health-intro" {
            self.mark_feature_seen("health");
        }
        self.health_ui = HealthUi::default();
        self.health_ui.cookie_settings_readable = true;
        self.health_ui.initialized = true;
        if case == "health-activity" {
            self.history = super::qa_core::history_fixture();
        }
        if case == "health-activity-unavailable" {
            self.history.clear();
            self.history_readable = false;
        }
        if matches!(
            case,
            "health-welcome" | "health-intro" | "health-activity" | "health-activity-unavailable"
        ) {
            return Ok(());
        }
        self.health_ui.started = true;
        if matches!(
            case,
            "health-privacy-multi-profile"
                | "health-privacy-empty-browsers"
                | "health-privacy-large"
        ) {
            let report = health_browser_fixture_report(case);
            let coordinator = &mut self.health_ui.coordinator;
            coordinator.inspect_privacy_browsers(Ok(Vec::new()))?;
            coordinator.begin_scan(HealthStep::Privacy)?;
            coordinator.complete_scan(report)?;
            coordinator.select_all()?;
            self.health_ui
                .expanded_categories
                .push(if case == "health-privacy-empty-browsers" {
                    HealthCategory::Cookies
                } else {
                    HealthCategory::InternetTemporaryFiles
                });
            return Ok(());
        }
        if case == "health-error" {
            let coordinator = &mut self.health_ui.coordinator;
            coordinator.inspect_privacy_browsers(Ok(Vec::new()))?;
            coordinator.begin_scan(HealthStep::Privacy)?;
            coordinator.complete_scan(HealthStepReport::failed(
                HealthStep::Privacy,
                "Synthetic fixture error: the read-only browser scan could not be completed.",
            ))?;
            return Ok(());
        }

        if case == "health-scanning" {
            let coordinator = &mut self.health_ui.coordinator;
            coordinator.inspect_privacy_browsers(Ok(Vec::new()))?;
            coordinator.begin_scan(HealthStep::Privacy)?;
            coordinator.progress(
                HealthStep::Privacy,
                1,
                Some(2),
                Some("Synthetic scan progress; no files were read".into()),
            )?;
            return Ok(());
        }
        if case == "health-browser-review" {
            let running = vec![
                RunningBrowser {
                    browser: Browser::Chrome,
                    pid: 900001,
                    executable: "fixture-chrome.exe".into(),
                },
                RunningBrowser {
                    browser: Browser::Edge,
                    pid: 900002,
                    executable: "fixture-msedge.exe".into(),
                },
            ];
            self.health_ui
                .coordinator
                .inspect_privacy_browsers(Ok(running.clone()))?;
            self.health_ui.selected_processes = running
                .iter()
                .map(|browser| (browser.browser, browser.pid))
                .collect();
            self.health_ui.running = running;
            self.health_ui.browser_review_open = true;
            return Ok(());
        }
        let target = match case {
            "health-privacy"
            | "health-privacy-row-counts"
            | "health-privacy-expanded"
            | "health-privacy-cancelled"
            | "health-privacy-stale"
            | "health-privacy-review"
            | "health-finding-details"
            | "health-cookie-settings"
            | "health-cleaning" => Some(HealthStep::Privacy),
            "health-space"
            | "health-space-review"
            | "health-results-complete"
            | "health-results-partial"
            | "health-results-cancelled"
            | "health-results-uncertain" => Some(HealthStep::Space),
            "health-issues" => Some(HealthStep::ResolveIssues),
            "health-summary" => None,
            _ => return Err(format!("Unsupported Health visual fixture: {case}")),
        };
        let coordinator = &mut self.health_ui.coordinator;
        for step in HealthStep::ORDER {
            if target.is_some_and(|target| step == target) {
                if case == "health-privacy-row-counts" {
                    coordinator.inspect_privacy_browsers(Ok(Vec::new()))?;
                    coordinator.begin_scan(step)?;
                    let mut report = health_fixture_report(step);
                    for category in &mut report.categories {
                        if category.category == HealthCategory::BrowsingHistory {
                            for finding in &mut category.findings {
                                finding.item_count = 6;
                            }
                            category.reported_items = category
                                .findings
                                .iter()
                                .map(|finding| finding.item_count)
                                .sum();
                        }
                    }
                    coordinator.complete_scan(report)?;
                    coordinator.select_all()?;
                } else if case == "health-privacy-cancelled" {
                    coordinator.inspect_privacy_browsers(Ok(Vec::new()))?;
                    coordinator.begin_scan(step)?;
                    let mut report = health_fixture_report(step);
                    report.quality = HealthScanQuality::Cancelled;
                    coordinator.complete_scan(report)?;
                } else {
                    seed_health_fixture_step(coordinator, step)?;
                }
                break;
            }
            if target.is_none() || target.is_some_and(|target| step != target) {
                seed_health_fixture_step(coordinator, step)?;
                coordinator.skip_current_step()?;
                coordinator.advance()?;
            }
            if target.is_some_and(|target| step == target) {
                break;
            }
        }
        if matches!(
            case,
            "health-privacy-expanded" | "health-privacy-cancelled" | "health-privacy-stale"
        ) {
            self.health_ui
                .expanded_categories
                .push(HealthCategory::InternetTemporaryFiles);
        }
        if case == "health-privacy-stale" {
            self.sync_health_cookie_settings(CookieExceptionSettings {
                schema: 1,
                keep_domains: vec!["trusted.example".into()],
                keep_signed_in: false,
            });
        }
        if case == "health-finding-details" {
            self.health_ui.detail_id = self
                .health_ui
                .coordinator
                .report(HealthStep::Privacy)
                .and_then(|report| {
                    report
                        .categories
                        .iter()
                        .flat_map(|category| category.findings.iter())
                        .next()
                })
                .map(|finding| finding.id.clone());
        }
        if matches!(
            case,
            "health-privacy-review" | "health-space-review" | "health-cleaning"
        ) {
            self.begin_health_action_review();
            if case == "health-cleaning" {
                let plan = self
                    .health_ui
                    .action_plan
                    .take()
                    .ok_or("Synthetic cleanup review was not prepared")?;
                self.health_ui
                    .coordinator
                    .begin_effects(&plan, true, false)?;
            }
        }
        if case == "health-cookie-settings" {
            self.open_health_cookie_settings(&egui::Context::default());
        }
        if case.starts_with("health-results-") {
            self.seed_health_result(case)?;
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    fn seed_health_result(&mut self, case: &str) -> Result<(), String> {
        let plan = self.health_ui.coordinator.build_action_plan(false)?;
        let mut receipts = Vec::new();
        for action in plan.actions() {
            let HealthAction::MoveFilesToTrash {
                analysis,
                candidate_ids,
            } = action
            else {
                return Err("Unexpected synthetic Health result action.".into());
            };
            let mut receipt = dcleaner::domain::CleanupResult {
                id: Uuid::from_u128(0x4443_4c45_414e_4552_4845_414c_5448_9999),
                date: "fixture-only".into(),
                ..Default::default()
            };
            match case {
                "health-results-complete" => {
                    receipt.cleaned_ids = candidate_ids.clone();
                    receipt.files = receipt.cleaned_ids.len();
                    receipt.bytes = analysis
                        .categories
                        .iter()
                        .flat_map(|category| &category.files)
                        .filter(|file| candidate_ids.contains(&file.id))
                        .map(|file| file.size)
                        .sum();
                }
                "health-results-partial" => {
                    for file in analysis
                        .categories
                        .iter()
                        .flat_map(|category| &category.files)
                        .filter(|file| candidate_ids.contains(&file.id))
                    {
                        receipt.failed.push(dcleaner::domain::FileOutcome {
                            file_id: file.id,
                            path: file.path.clone(),
                            size: file.size,
                            success: false,
                            reason: Some("Synthetic fixture: source changed.".into()),
                        });
                    }
                }
                "health-results-cancelled" => receipt.cancelled = true,
                "health-results-uncertain" => receipt.interrupted = true,
                _ => return Err("Unknown synthetic Health result state.".into()),
            }
            receipts.push(HealthEffectReceipt::Files(receipt));
        }
        self.health_ui
            .coordinator
            .begin_effects(&plan, true, false)?;
        self.health_ui
            .coordinator
            .complete_effects(plan.id(), receipts)?;
        self.health_completion_notice();
        Ok(())
    }

    /// Explicit pre-captured 32px artwork only. Rendering still reads no host
    /// browser inventory, process, registry, profile or cleanup data.
    #[cfg(debug_assertions)]
    pub(super) fn seed_health_qa_artwork(&mut self, context: &egui::Context) -> Result<(), String> {
        let Some(directory) = std::env::var_os("DCLEANER_QA_BROWSER_ARTWORK_DIR") else {
            return Ok(());
        };
        if !self.qa_fixture_mode() {
            return Err("Browser artwork fixtures require isolated fixture mode.".into());
        }
        let directory = std::path::PathBuf::from(directory);
        if !directory.is_absolute() {
            return Err(
                "An explicit absolute browser-artwork fixture directory is required.".into(),
            );
        }
        for (browser, name) in [
            (Browser::Chrome, "chrome"),
            (Browser::Edge, "edge"),
            (Browser::Firefox, "firefox"),
        ] {
            use std::io::Read;
            let path = directory.join(format!("{name}.png"));
            if !path.exists() {
                continue;
            }
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .map_err(|e| e.to_string())?
                .take(65_537)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > 65_536 {
                return Err("Browser-artwork fixture exceeds its byte bound.".into());
            }
            let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
            decoder.set_limits(png::Limits { bytes: 65_536 });
            let mut reader = decoder.read_info().map_err(|e| e.to_string())?;
            let info = reader.info();
            if info.width != 32
                || info.height != 32
                || info.color_type != png::ColorType::Rgba
                || info.bit_depth != png::BitDepth::Eight
            {
                return Err("Browser-artwork fixtures must be 32×32 RGBA8.".into());
            }
            let mut rgba = vec![0; 32 * 32 * 4];
            let output = reader.next_frame(&mut rgba).map_err(|e| e.to_string())?;
            if output.buffer_size() != rgba.len() {
                return Err("Unexpected browser-artwork fixture output.".into());
            }
            let key = format!("qa-native-browser-{name}");
            self.app_icons.seed_qa_image(
                context,
                key.clone(),
                egui::ColorImage::from_rgba_unmultiplied([32, 32], &rgba),
            );
            self.health_ui.browser_icons.insert(browser, key);
        }
        Ok(())
    }

    pub(super) fn health_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if !self.feature_seen("health") {
            if self.feature_intro(ui, t, "health", "Run your first scan", "Review privacy records, reclaimable space and system issues. You choose what to change after reviewing the results.", &[]) {
                self.mark_feature_seen("health");
                self.health_ui.started = true;
                self.begin_health_prerequisites(ctx);
            }
            return;
        }
        if !self.health_ui.started {
            self.overview(ui, t);
            return;
        }
        if !self.qa_fixture_mode()
            && !self.health_ui.initialized
            && !self.health_ui.initializing
            && !self.busy()
        {
            self.begin_health_prerequisites(ctx);
        }
        if !self.qa_fixture_mode() && self.health_ui.initialized && !self.busy() {
            if let Some(step) = self.health_ui.coordinator.current_step() {
                if matches!(
                    self.health_ui.coordinator.status(step),
                    HealthStepStatus::Ready
                ) && (step != HealthStep::Privacy || self.health_ui.cookie_settings_readable)
                {
                    self.begin_health_scan(step, ctx);
                }
            }
        }
        self.health_stepper(ui, t);
        ui.add_space(26.);

        let Some(step) = self.health_ui.coordinator.current_step() else {
            self.health_final_summary(ui, t);
            return;
        };
        self.health_step_page(ui, t, ctx, step);
    }

    pub(super) fn rescan_health(&mut self, ctx: &egui::Context) {
        self.health_ui.started = true;
        self.begin_health_prerequisites(ctx);
    }

    pub(super) fn health_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if !self.feature_seen("health") {
            if !self.feature_intro_wide(ctx) {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if theme::primary(ui, "Scan now", t, !self.busy()) {
                        self.mark_feature_seen("health");
                        self.rescan_health(ctx);
                    }
                });
            }
            return;
        }
        if !self.health_ui.started {
            return;
        }
        let Some(step) = self.health_ui.coordinator.current_step() else {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if theme::primary(ui, "Restart Health Check", t, !self.busy()) {
                    self.health_ui = HealthUi::default();
                    self.error = None;
                    self.notice = None;
                    self.rescan_health(ctx);
                }
            });
            return;
        };
        let status = self.health_ui.coordinator.status(step).clone();
        let busy = self.busy();
        let ids = self
            .health_ui
            .coordinator
            .selected_ids(step)
            .into_iter()
            .collect::<HashSet<_>>();
        let selected = self.health_ui.coordinator.report(step).map_or(0, |report| {
            report
                .categories
                .iter()
                .flat_map(|category| &category.findings)
                .filter(|finding| ids.contains(&finding.id))
                .map(|finding| finding.item_count)
                .sum::<usize>()
        });
        let selected_bytes = self.health_ui.coordinator.report(step).and_then(|report| {
            report
                .categories
                .iter()
                .flat_map(|category| &category.findings)
                .filter(|finding| ids.contains(&finding.id))
                .try_fold(0u64, |total, finding| {
                    finding
                        .size_bytes
                        .and_then(|bytes| total.checked_add(bytes))
                })
        });
        let mut review = false;
        let mut skip = false;
        let mut scan = false;
        let mut next = false;
        ui.with_layout(
            Layout::right_to_left(Align::Center).with_main_wrap(true),
            |ui| match status {
                HealthStepStatus::Reviewing { .. } => {
                    let partial = self
                        .health_ui
                        .coordinator
                        .report(step)
                        .is_some_and(|report| report.quality == HealthScanQuality::Partial);
                    review = theme::primary(
                        ui,
                        if step == HealthStep::ResolveIssues {
                            "Resolve"
                        } else {
                            "Clean"
                        },
                        t,
                        !busy
                            && selected > 0
                            && self.history_readable
                            && (self.data_dir.is_absolute() || self.qa_fixture_mode())
                            && !self.health_privacy_rules_blocked()
                            && (!partial || self.health_ui.partial_acknowledged),
                    );
                    skip = theme::secondary(ui, "Skip", !busy);
                    let summary = if selected == 0 {
                        "Nothing selected".to_owned()
                    } else if let Some(bytes) = selected_bytes {
                        format!(
                            "{} · {} selected",
                            format_bytes(bytes),
                            theme::counted_label(selected, "item", "items")
                        )
                    } else {
                        format!(
                            "{} selected",
                            theme::counted_label(selected, "item", "items")
                        )
                    };
                    theme::muted(ui, summary, t);
                }
                HealthStepStatus::Ready => {
                    scan = theme::primary(
                        ui,
                        "Scan now",
                        t,
                        !busy
                            && self.health_ui.initialized
                            && (step != HealthStep::Privacy
                                || self.health_ui.cookie_settings_readable)
                            && self.data_dir.is_absolute(),
                    );
                    skip = theme::secondary(ui, "Skip", !busy);
                }
                HealthStepStatus::AwaitingBrowserReview { .. } => {
                    if theme::primary(
                        ui,
                        "Review browser status",
                        t,
                        !busy && self.health_ui.initialized,
                    ) {
                        self.health_ui.browser_review_open = true;
                    }
                    skip = theme::secondary(ui, "Skip", !busy);
                }
                HealthStepStatus::Results { .. }
                | HealthStepStatus::Skipped
                | HealthStepStatus::Cancelled
                | HealthStepStatus::Failed { .. } => {
                    next = theme::primary(ui, "Continue", t, !busy);
                    scan = theme::secondary(ui, "Scan again", !busy);
                }
                HealthStepStatus::ActionReview { .. } => {
                    theme::muted(ui, "Review the selected actions in the open dialog.", t);
                }
                HealthStepStatus::Scanning { .. } | HealthStepStatus::Applying { .. } => {}
            },
        );
        if review {
            self.begin_health_action_review();
        }
        if skip {
            self.skip_health_step();
        }
        if scan {
            self.begin_health_scan(step, ctx);
        }
        if next {
            self.advance_health_step();
        }
    }

    pub(super) fn health_dialog(&mut self, ctx: &egui::Context) {
        if self.health_ui.detail_id.is_some() {
            self.health_detail_dialog(ctx);
        }
        if self.health_ui.browser_review_open {
            self.health_browser_review_dialog(ctx);
        }
        if self.health_ui.action_plan.is_some() {
            self.health_action_review_dialog(ctx);
        }
    }

    pub(super) fn health_event(&mut self, event: HealthEvent) {
        match event {
            HealthEvent::Prerequisites {
                running,
                browser_icons,
                cookie_settings,
            } => {
                self.worker = None;
                self.health_ui.initializing = false;
                self.health_ui.initialized = true;
                self.health_ui.browser_icons = browser_icons;
                self.health_ui.selected_processes = running
                    .as_ref()
                    .map(|processes| {
                        processes
                            .iter()
                            .map(|process| (process.browser, process.pid))
                            .collect()
                    })
                    .unwrap_or_default();
                self.update_health_browser_state(running);
                match cookie_settings {
                    Ok(settings) => {
                        self.sync_cookie_settings_owners(settings);
                    }
                    Err(error) => {
                        self.mark_cookie_settings_unverified();
                        self.health_ui.cookie_settings_error = Some(format!(
                            "Cookie rules could not be verified: {error}. Reload saved rules before scanning or cleanup."
                        ));
                    }
                }
            }
            HealthEvent::RunningBrowsers(result) => {
                self.worker = None;
                self.update_health_browser_state(result);
            }
            HealthEvent::BrowserClose { report, remaining } => {
                self.worker = None;
                let _ = self.health_ui.coordinator.record_browser_close(&report);
                self.update_health_browser_state(remaining);
                if report.errors.is_empty()
                    && report.stale_selection.is_empty()
                    && report.still_running.is_empty()
                {
                    self.set_notice("Selected browsers received a graceful close request.".into());
                    if matches!(
                        self.health_ui.coordinator.status(HealthStep::Privacy),
                        HealthStepStatus::AwaitingBrowserReview {
                            status_unavailable: false,
                            ..
                        }
                    ) {
                        if let Err(error) = self.health_ui.coordinator.accept_browser_review() {
                            self.error = Some(error);
                        }
                    }
                    self.health_ui.browser_review_open = false;
                } else {
                    self.set_notice(format!(
                        "{} selected browser process(es) remain open or changed; refresh and review them before scanning.",
                        report.still_running.len()
                            + report.stale_selection.len()
                            + report.errors.len()
                    ));
                }
                self.health_ui.selected_processes.clear();
            }
            HealthEvent::ScanProgress {
                step,
                completed,
                total,
                detail,
            } => {
                if let Err(error) =
                    self.health_ui
                        .coordinator
                        .progress(step, completed, total, detail.clone())
                {
                    self.error = Some(error);
                }
                self.progress = match (completed, total, detail) {
                    (_, Some(total), Some(detail)) => {
                        format!("{detail} · {completed} of {total}")
                    }
                    (completed, _, Some(detail)) => format!("{detail} · {completed} items"),
                    (completed, Some(total), None) => format!("{completed} of {total}"),
                    (completed, None, None) => format!("{completed} items"),
                };
            }
            HealthEvent::ScanFinished(report) => {
                self.worker = None;
                let select_complete = report.quality == HealthScanQuality::Complete;
                match self.health_ui.coordinator.complete_scan(report) {
                    Ok(()) => {
                        self.health_ui.partial_acknowledged = false;
                        self.health_ui.cookie_settings_stale = false;
                        self.health_ui.detail_id = None;
                        self.health_ui.expanded_categories.clear();
                        if select_complete {
                            let _ = self.health_ui.coordinator.select_all();
                        }
                        self.error = None;
                    }
                    Err(error) => self.error = Some(error),
                }
            }
            HealthEvent::EffectProgress(message) => self.progress = message,
            HealthEvent::EffectsFinished {
                plan_id,
                receipts,
                issues,
                attempted,
                uncertain,
                cancelled_before_any,
                history,
            } => {
                self.worker = None;
                self.health_ui.action_plan = None;
                self.health_ui.permanent_acknowledged = false;
                if receipts.is_empty() {
                    if cancelled_before_any && !attempted {
                        if let Err(error) = self.health_ui.coordinator.cancel_effects_before_any(
                            plan_id,
                            "Stopped before any reviewed action began; no effect was attempted.",
                        ) {
                            self.error = Some(error);
                        }
                    } else if let Err(error) = self.health_ui.coordinator.fail_effects(
                        plan_id,
                        if issues.is_empty() {
                            "The reviewed actions produced no owner-service receipt.".to_owned()
                        } else {
                            issues.join(" ")
                        },
                        uncertain,
                    ) {
                        self.error = Some(error);
                    }
                } else if let Err(error) = self.health_ui.coordinator.complete_effects_with_issues(
                    plan_id,
                    receipts,
                    issues.clone(),
                    uncertain,
                ) {
                    self.error = Some(error);
                } else {
                    self.health_completion_notice();
                }
                self.apply_cleanup_history(history);
            }
        }
    }

    pub(super) fn health_started(&self) -> bool {
        self.health_ui.started
    }

    fn health_completion_notice(&mut self) {
        let Some(step) = self.health_ui.coordinator.current_step() else {
            return;
        };
        let HealthStepStatus::Results { quality, .. } = *self.health_ui.coordinator.status(step)
        else {
            return;
        };
        // Recovery remains in the result; avoid a duplicate temporary alert.
        if quality == HealthEffectQuality::Uncertain {
            return;
        }
        let mut message = effect_quality_label(quality).to_owned();
        if let Some(detail) = self.health_ui.coordinator.effect_message(step) {
            message.push_str(&format!(" · {detail}"));
        }
        self.set_page_notice(
            message,
            super::Page::Overview,
            if quality == HealthEffectQuality::Complete {
                theme::StatusKind::Success
            } else {
                theme::StatusKind::Info
            },
            false,
        );
    }

    fn update_health_browser_state(&mut self, running: Result<Vec<RunningBrowser>, String>) {
        let coordinator_input = running.clone();
        match running {
            Ok(processes) => {
                self.health_ui.running = processes.clone();
                self.health_ui.process_error = None;
                self.health_ui.browser_review_open = !processes.is_empty();
            }
            Err(error) => {
                self.health_ui.running.clear();
                self.health_ui.process_error = Some(error);
                self.health_ui.browser_review_open = true;
            }
        }
        if let Err(error) = self
            .health_ui
            .coordinator
            .inspect_privacy_browsers(coordinator_input)
        {
            self.error = Some(error);
        }
    }

    fn begin_health_prerequisites(&mut self, ctx: &egui::Context) {
        if self.qa_fixture_mode() || self.busy() || self.health_ui.initializing {
            return;
        }
        self.health_ui.initializing = true;
        self.progress = "Checking browser status and cookie rules…".into();
        let root = self.data_dir.clone();
        let repaint = ctx.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let running = privacy::running_browsers();
            let browser_icons = running
                .as_ref()
                .map(|processes| crate::app_icons::browser_icon_sources(processes))
                .unwrap_or_default();
            let settings = if root.as_os_str().is_empty() {
                Err(
                    "Application data storage is unavailable; cookie keep rules cannot be read."
                        .into(),
                )
            } else {
                privacy::load_cookie_exception_settings(&root)
            };
            let _ = tx.send(Event::Health(HealthEvent::Prerequisites {
                running,
                browser_icons,
                cookie_settings: settings,
            }));
            repaint.request_repaint();
        });
    }

    fn begin_health_scan(&mut self, step: HealthStep, ctx: &egui::Context) {
        if self.qa_fixture_mode() || self.busy() {
            return;
        }
        if step == HealthStep::Privacy && !self.health_ui.cookie_settings_readable {
            self.health_ui.cookie_settings_error = Some(
                "Valid cookie keep-domain settings are required before this privacy scan.".into(),
            );
            return;
        }
        if let Err(error) = self.health_ui.coordinator.begin_scan(step) {
            self.error = Some(error);
            return;
        }
        self.error = None;
        self.notice = None;
        self.progress = format!("Preparing {} scan…", step_label(step));
        self.cancel = Arc::new(AtomicBool::new(false));
        if step == HealthStep::Privacy {
            self.health_ui.cookie_settings_stale = false;
        }
        let cancel = self.cancel.clone();
        let root = self.data_dir.clone();
        let repaint = ctx.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let report = match step {
                HealthStep::Privacy => {
                    health::scan_privacy_step(&cancel, |step, completed, total, detail| {
                        send_health_progress(&tx, &repaint, step, completed, total, detail);
                    })
                }
                HealthStep::Space => {
                    health::scan_space_step(&cancel, |step, completed, total, detail| {
                        send_health_progress(&tx, &repaint, step, completed, total, detail);
                    })
                }
                HealthStep::ResolveIssues => health::scan_resolve_issues_step(
                    &cancel,
                    &root,
                    |step, completed, total, detail| {
                        send_health_progress(&tx, &repaint, step, completed, total, detail);
                    },
                ),
            };
            let _ = tx.send(Event::Health(HealthEvent::ScanFinished(report)));
            repaint.request_repaint();
        });
    }

    fn request_health_cancel(&mut self, step: HealthStep) {
        if let Err(error) = self.health_ui.coordinator.request_cancel(step) {
            self.error = Some(error);
            return;
        }
        self.cancel.store(true, Ordering::Relaxed);
    }

    fn begin_health_browser_refresh(&mut self, ctx: &egui::Context) {
        if self.qa_fixture_mode() || self.busy() {
            return;
        }
        let repaint = ctx.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        self.progress = "Refreshing running-browser status…".into();
        thread::spawn(move || {
            let result = privacy::running_browsers();
            let _ = tx.send(Event::Health(HealthEvent::RunningBrowsers(result)));
            repaint.request_repaint();
        });
    }

    fn begin_health_browser_close(&mut self, ctx: &egui::Context) {
        if self.qa_fixture_mode() || self.busy() {
            return;
        }
        let selected = self
            .health_ui
            .running
            .iter()
            .filter(|process| {
                self.health_ui
                    .selected_processes
                    .contains(&(process.browser, process.pid))
            })
            .cloned()
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return;
        }
        let repaint = ctx.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        self.progress = "Requesting a graceful close for selected browsers…".into();
        thread::spawn(move || {
            let report = privacy::request_close_selected(&selected);
            let remaining = privacy::running_browsers();
            let _ = tx.send(Event::Health(HealthEvent::BrowserClose {
                report,
                remaining,
            }));
            repaint.request_repaint();
        });
    }

    fn health_privacy_rules_blocked(&self) -> bool {
        self.health_ui.coordinator.current_step() == Some(HealthStep::Privacy)
            && (!self.health_ui.cookie_settings_readable || self.health_ui.cookie_settings_stale)
    }

    fn begin_health_action_review(&mut self) {
        if self.health_privacy_rules_blocked() {
            return;
        }
        let partial = self
            .health_ui
            .coordinator
            .current_report()
            .is_some_and(|report| report.quality == HealthScanQuality::Partial);
        match self
            .health_ui
            .coordinator
            .build_action_plan(!partial || self.health_ui.partial_acknowledged)
        {
            Ok(plan) => {
                self.health_ui.permanent_acknowledged = false;
                self.health_ui.action_plan = Some(plan);
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn begin_health_effects(&mut self, ctx: &egui::Context) {
        if self.qa_fixture_mode()
            || self.busy()
            || !self.history_readable
            || self.health_privacy_rules_blocked()
        {
            return;
        }
        let Some(plan) = self.health_ui.action_plan.take() else {
            return;
        };
        let plan_id = plan.id();
        if let Err(error) = self.health_ui.coordinator.begin_effects(
            &plan,
            true,
            self.health_ui.permanent_acknowledged,
        ) {
            self.error = Some(error);
            self.health_ui.action_plan = Some(plan);
            return;
        }
        self.error = None;
        self.health_ui.permanent_acknowledged = false;
        self.progress = "Starting the reviewed Health Check actions…".into();
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let root = self.data_dir.clone();
        let repaint = ctx.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let run = run_health_effects(&root, &plan, &cancel, |message| {
                let _ = tx.send(Event::Health(HealthEvent::EffectProgress(message)));
                repaint.request_repaint();
            });
            let _ = tx.send(Event::Health(HealthEvent::EffectProgress(
                "Refreshing cleanup history…".into(),
            )));
            repaint.request_repaint();
            let history = store::history(&root);
            let _ = tx.send(Event::Health(HealthEvent::EffectsFinished {
                plan_id,
                receipts: run.receipts,
                issues: run.issues,
                attempted: run.attempted,
                uncertain: run.uncertain,
                cancelled_before_any: run.cancelled_before_any,
                history,
            }));
            repaint.request_repaint();
        });
    }

    fn advance_health_step(&mut self) {
        match self.health_ui.coordinator.advance() {
            Ok(Some(step)) => {
                self.health_ui.browser_review_open = false;
                self.health_ui.selected_processes.clear();
                self.health_ui.partial_acknowledged = false;
                self.health_ui.detail_id = None;
                self.health_ui.cookie_settings_stale = false;
                if step == HealthStep::Privacy {
                    self.begin_health_prerequisites_if_needed();
                }
            }
            Ok(None) => self.set_notice("Health Check reached its final summary.".into()),
            Err(error) => self.error = Some(error),
        }
    }

    fn begin_health_prerequisites_if_needed(&mut self) {
        // A completed Health Check keeps the initial browser snapshot for this run.
        self.health_ui.browser_review_open = matches!(
            self.health_ui.coordinator.status(HealthStep::Privacy),
            HealthStepStatus::AwaitingBrowserReview { .. }
        );
    }

    fn skip_health_step(&mut self) {
        if self.health_ui.action_plan.is_some() {
            if let Some(plan) = self.health_ui.action_plan.take() {
                let _ = self.health_ui.coordinator.cancel_action_review(plan.id());
            }
        }
        match self.health_ui.coordinator.skip_current_step() {
            Ok(()) => self.advance_health_step(),
            Err(error) => self.error = Some(error),
        }
    }

    pub(super) fn health_progress_active(&self) -> bool {
        self.health_ui.started
            && (self.health_ui.initializing
                || self
                    .health_ui
                    .coordinator
                    .current_step()
                    .is_some_and(|step| {
                        matches!(
                            self.health_ui.coordinator.status(step),
                            HealthStepStatus::Scanning { .. } | HealthStepStatus::Applying { .. }
                        )
                    }))
    }

    fn health_stepper(&self, ui: &mut egui::Ui, t: Tokens) {
        let width = ui.available_width().min(510.);
        let inset = ((ui.available_width() - width) / 2.).max(0.);
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 64.), egui::Sense::hover());
        let left = rect.left() + inset;
        let painter = ui.painter();
        let current = self.health_ui.coordinator.current_step();
        for (index, step) in HealthStep::ORDER.into_iter().enumerate() {
            let center = egui::pos2(left + width * (index as f32 + 0.5) / 3., rect.top() + 16.);
            let status = self.health_ui.coordinator.status(step);
            let active = current == Some(step);
            let has_results = matches!(status, HealthStepStatus::Results { .. });
            let finished = matches!(
                status,
                HealthStepStatus::Results {
                    quality: HealthEffectQuality::Complete,
                    ..
                }
            );
            let skipped = matches!(
                status,
                HealthStepStatus::Skipped
                    | HealthStepStatus::Cancelled
                    | HealthStepStatus::Results {
                        quality: HealthEffectQuality::Cancelled,
                        ..
                    }
            );
            let warning = matches!(
                status,
                HealthStepStatus::Failed { .. }
                    | HealthStepStatus::Results {
                        quality: HealthEffectQuality::Partial | HealthEffectQuality::Uncertain,
                        ..
                    }
            );
            if index < 2 {
                let next_x = left + width * (index as f32 + 1.5) / 3.;
                painter.line_segment(
                    [
                        center + egui::vec2(20., 0.),
                        egui::pos2(next_x - 20., center.y),
                    ],
                    egui::Stroke::new(1., t.border),
                );
            }
            if active {
                painter.circle_stroke(center, 14., egui::Stroke::new(0.9, t.primary));
            }
            theme::paint_icon(
                painter,
                egui::Rect::from_center_size(center, egui::Vec2::splat(18.)),
                health_step_icon(step),
                if active || has_results {
                    t.foreground
                } else {
                    t.muted
                },
            );
            // Status supplements the step pictogram; it never replaces it.
            // Reviewing means there are results to review, not a scan failure.
            if finished || skipped || warning {
                let marker = center + egui::vec2(12., 10.);
                painter.circle_filled(marker, 6., t.canvas);
                if finished {
                    painter.add(egui::Shape::line(
                        vec![
                            marker + egui::vec2(-4., 0.),
                            marker + egui::vec2(-1., 3.),
                            marker + egui::vec2(4., -3.),
                        ],
                        egui::Stroke::new(1.2, t.primary),
                    ));
                } else if skipped {
                    painter.line_segment(
                        [marker - egui::vec2(4., 0.), marker + egui::vec2(4., 0.)],
                        egui::Stroke::new(0.9, t.muted),
                    );
                } else {
                    painter.text(
                        marker,
                        egui::Align2::CENTER_CENTER,
                        "!",
                        egui::FontId::new(theme::FONT_BODY, theme::semibold()),
                        t.attention,
                    );
                }
            }
            painter.text(
                center + egui::vec2(0., 33.),
                egui::Align2::CENTER_CENTER,
                step_label(step),
                egui::FontId::new(
                    theme::FONT_BODY,
                    if active {
                        theme::semibold()
                    } else {
                        egui::FontFamily::Proportional
                    },
                ),
                if active || has_results {
                    t.foreground
                } else {
                    t.muted
                },
            );
        }
    }

    fn health_progress_page(
        &mut self,
        ui: &mut egui::Ui,
        t: Tokens,
        step: HealthStep,
        status: &HealthStepStatus,
    ) {
        let applying = matches!(status, HealthStepStatus::Applying { .. });
        let fraction = match status {
            HealthStepStatus::Scanning { progress, .. } => progress
                .total
                .filter(|total| *total > 0)
                .map(|total| (progress.completed as f64 / total as f64).clamp(0., 1.) as f32),
            _ => None,
        };
        // Reserve room for the heading, wrapped explanation and full-height
        // stop action before centering the artwork in a short window.
        let diameter = (ui.available_height() - 220.).clamp(96., 220.);
        let spare = (ui.available_height() - diameter - 220.).max(0.);
        ui.add_space((spare / 2.).min(90.));
        ui.vertical_centered(|ui| {
            let (rect, _) =
                ui.allocate_exact_size(egui::vec2(diameter, diameter), egui::Sense::hover());
            let center = rect.center();
            let radius = diameter / 2. - 4.;
            ui.painter()
                .circle_stroke(center, radius, egui::Stroke::new(1., t.border));
            let time = ui.input(|input| input.time) as f32;
            let begin =
                -std::f32::consts::FRAC_PI_2 + if fraction.is_none() { time * 1.5 } else { 0. };
            let sweep = std::f32::consts::TAU * fraction.unwrap_or(0.23);
            let points = (0..=96)
                .map(|i| {
                    center
                        + egui::vec2(
                            (begin + sweep * i as f32 / 96.).cos(),
                            (begin + sweep * i as f32 / 96.).sin(),
                        ) * radius
                })
                .collect::<Vec<_>>();
            ui.painter()
                .add(egui::Shape::line(points, egui::Stroke::new(2.5, t.primary)));
            if let Some(fraction) = fraction {
                ui.painter().text(
                    center,
                    egui::Align2::CENTER_CENTER,
                    format!("{:.0}%", fraction * 100.),
                    egui::FontId::new(theme::FONT_DISPLAY, theme::semibold()),
                    t.foreground,
                );
            }
            ui.add_space(26.);
            ui.label(
                RichText::new(if applying {
                    "Cleaning things up…"
                } else if self.health_ui.initializing {
                    "Checking your browsers…"
                } else {
                    "Gathering and analyzing files…"
                })
                .size(theme::FONT_DISPLAY)
                .family(theme::semibold()),
            );
            ui.add_space(4.);
            theme::muted(
                ui,
                if self.progress.is_empty() {
                    step_description(step)
                } else {
                    self.progress.as_str()
                },
                t,
            );
            ui.add_space(24.);
            if !self.health_ui.initializing
                && theme::secondary(
                    ui,
                    if applying {
                        "Stop cleaning"
                    } else {
                        "Stop scan"
                    },
                    (self.busy() || self.qa_fixture_mode())
                        && !self.cancel.load(Ordering::Relaxed)
                        && !matches!(
                            status,
                            HealthStepStatus::Scanning {
                                cancel_requested: true,
                                ..
                            }
                        ),
                )
            {
                if applying {
                    self.cancel.store(true, Ordering::Relaxed);
                } else {
                    self.request_health_cancel(step);
                }
            }
        });
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(33));
    }

    fn health_step_page(
        &mut self,
        ui: &mut egui::Ui,
        t: Tokens,
        ctx: &egui::Context,
        step: HealthStep,
    ) {
        let status = self.health_ui.coordinator.status(step).clone();
        if self.health_progress_active() {
            self.health_progress_page(ui, t, step, &status);
            return;
        }
        let report = self.health_ui.coordinator.report_snapshot(step);
        let total = report
            .as_ref()
            .map(|report| {
                report
                    .categories
                    .iter()
                    .map(|category| category.reported_items)
                    .sum::<usize>()
            })
            .unwrap_or(0);
        let heading = if let HealthStepStatus::Results { quality, .. } = status {
            match quality {
                HealthEffectQuality::Complete => "Cleanup complete",
                HealthEffectQuality::Partial => "Cleanup partially completed",
                HealthEffectQuality::Cancelled => "Cleanup stopped",
                HealthEffectQuality::Uncertain => "Cleanup needs recovery review",
            }
            .to_owned()
        } else if matches!(status, HealthStepStatus::Failed { .. }) {
            match step {
                HealthStep::Privacy => "Privacy scan unavailable",
                HealthStep::Space => "Space scan unavailable",
                HealthStep::ResolveIssues => "Issue scan unavailable",
            }
            .to_owned()
        } else if let Some(report) = &report {
            match step {
                HealthStep::Privacy => format!("{total} records found"),
                HealthStep::Space => report
                    .categories
                    .iter()
                    .try_fold(0u64, |sum, category| {
                        category
                            .reported_bytes
                            .and_then(|bytes| sum.checked_add(bytes))
                    })
                    .map(|bytes| format!("{} can be cleaned", format_bytes(bytes)))
                    .unwrap_or_else(|| "Review your cleanup results".into()),
                HealthStep::ResolveIssues => {
                    let known_issues = report
                        .categories
                        .iter()
                        .filter(|category| {
                            category.category == HealthCategory::OutdatedApplications
                        })
                        .map(|category| category.reported_items)
                        .sum::<usize>();
                    if known_issues > 0 {
                        format!("{known_issues} issues found on your PC")
                    } else {
                        "Review your PC’s issues".into()
                    }
                }
            }
        } else {
            step_title(step).to_owned()
        };
        let needs_result_rescan = report.is_some()
            && matches!(status, HealthStepStatus::Reviewing { .. })
            && step == HealthStep::Privacy
            && self.health_privacy_rules_blocked();
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(heading)
                    .size(theme::FONT_DISPLAY)
                    .family(theme::semibold()),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if step == HealthStep::Privacy
                    && theme::field_action(ui, "Cookie settings", !self.busy())
                {
                    self.open_health_cookie_settings(ctx);
                }
                if needs_result_rescan && theme::header_action(ui, "Scan again", !self.busy()) {
                    self.begin_health_scan(step, ctx);
                }
            });
        });
        let terminal = matches!(status, HealthStepStatus::Results { .. });
        theme::muted(
            ui,
            if terminal {
                "These are the reviewed action results. Scan again for a fresh inventory."
            } else {
                step_description(step)
            },
            t,
        );
        ui.add_space(26.);
        if terminal {
            self.health_effect_result(ui, t, step);
            ui.add_space(16.);
            theme::muted(ui, "Scan snapshot before this action", t);
            ui.add_space(8.);
        }
        if let HealthStepStatus::Failed { message } = &status {
            theme::status_banner(ui, message, theme::StatusKind::Error, false, false);
            ui.add_space(8.);
        }
        if step == HealthStep::Privacy {
            self.health_browser_gate_panel(ui, t);
        }
        if let Some(report) = report {
            self.health_results_card(ui, t, step, &report);
        } else if matches!(status, HealthStepStatus::Ready) {
            theme::muted(ui, "Start a scan to review what can be cleaned.", t);
        }
    }

    fn health_browser_gate_panel(&mut self, ui: &mut egui::Ui, t: Tokens) {
        let status = self
            .health_ui
            .coordinator
            .status(HealthStep::Privacy)
            .clone();
        let HealthStepStatus::AwaitingBrowserReview {
            running,
            status_unavailable,
        } = status
        else {
            if let Some(error) = &self.health_ui.process_error {
                theme::card(t).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.colored_label(t.attention, format!("Browser status unavailable: {error}"));
                });
            }
            return;
        };
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Running browser review").family(theme::semibold()));
                theme::muted(ui, format!("{} process(es)", running.len()), t);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if theme::secondary(
                        ui,
                        "Review…",
                                !self.busy(),
                    ) {
                        self.health_ui.browser_review_open = true;
                    }
                });
            });
            if status_unavailable {
                ui.add_space(4.);
                ui.colored_label(
                    t.attention,
                    "The running-browser check could not be verified. Refresh it before scanning privacy data.",
                );
            } else {
                ui.add_space(4.);
                theme::muted(
                    ui,
                    "Continue with a read-only scan or choose exact browser processes for a graceful close request.",
                    t,
                );
            }
        });
    }

    fn health_results_card(
        &mut self,
        ui: &mut egui::Ui,
        t: Tokens,
        step: HealthStep,
        report: &HealthStepReport,
    ) {
        let busy = self.busy();
        let reviewing = matches!(
            self.health_ui.coordinator.status(step),
            HealthStepStatus::Reviewing { .. }
        );
        let selection_enabled = reviewing
            && !busy
            && !self.health_privacy_rules_blocked()
            && !matches!(
                report.quality,
                HealthScanQuality::Cancelled | HealthScanQuality::Failed
            );
        let selected = self
            .health_ui
            .coordinator
            .selected_ids(step)
            .into_iter()
            .collect::<HashSet<_>>();
        let all_ids = report
            .categories
            .iter()
            .flat_map(|category| &category.findings)
            .filter(|finding| finding.actionable)
            .map(|finding| finding.id.clone())
            .collect::<Vec<_>>();
        let mut select_ids = Vec::new();
        let mut clear_ids = Vec::new();
        if report.quality == HealthScanQuality::Partial {
            egui::Frame::new()
                .fill(t.card)
                .stroke(egui::Stroke::new(1., t.border))
                .corner_radius(theme::SECTION_RADIUS)
                .inner_margin(10.)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal_top(|ui| {
                        let (icon, _) =
                            ui.allocate_exact_size(egui::Vec2::splat(20.), egui::Sense::hover());
                        theme::paint_icon(ui.painter(), icon, theme::Icon::Info, t.attention);
                        ui.vertical(|ui| {
                            ui.set_width(ui.available_width());
                            ui.spacing_mut().item_spacing.y = 4.;
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new("Incomplete scan").family(theme::semibold()).color(t.attention));
                                theme::muted(ui, "Review the gaps before cleaning.", t);
                                if theme::row_action(ui, if self.health_ui.scan_details_open { "Hide scan details" } else { "Scan details" }, true).clicked() {
                                    self.health_ui.scan_details_open = !self.health_ui.scan_details_open;
                                }
                            });
                            if self.health_ui.scan_details_open {
                                theme::muted(ui, "Some sources could not be scanned. Results include only the sources that returned data.", t);
                                for note in &report.notes {
                                    theme::muted(ui, note, t);
                                }
                            }
                            if theme::checkbox(
                                ui,
                                &mut self.health_ui.partial_acknowledged,
                                "I reviewed the partial-scan warning",
                                selection_enabled,
                            )
                            .changed()
                                && !self.health_ui.partial_acknowledged
                            {
                                let _ = self.health_ui.coordinator.deselect_all();
                            }
                        });
                    });
                });
            ui.add_space(16.);
        } else {
            for note in &report.notes {
                if matches!(
                    self.health_ui.coordinator.status(step),
                    HealthStepStatus::Failed { message } if message == note
                ) {
                    continue;
                }
                theme::muted(ui, note, t);
            }
        }
        let mut recovery_notes = Vec::new();
        if report.quality == HealthScanQuality::Cancelled {
            recovery_notes.push("This scan was stopped. Scan again before cleaning.");
        }
        if self.health_ui.cookie_settings_stale && step == HealthStep::Privacy {
            recovery_notes
                .push("Cookie settings changed. Scan Privacy again before cleaning these results.");
        }
        if !recovery_notes.is_empty() {
            theme::status_banner(
                ui,
                &recovery_notes.join(" "),
                theme::StatusKind::Info,
                false,
                false,
            );
            ui.add_space(8.);
        }
        let width = ui.available_width();
        let issue_step = step == HealthStep::ResolveIssues;
        let row_height = if ui.ctx().content_rect().height() < 680. {
            64.
        } else {
            74.
        };
        let size_width = if issue_step { 0. } else { 90. };
        let item_width = 70.;
        let name_width =
            (width - 24. - item_width - size_width - 22. - 4. * theme::LABEL_GAP).max(160.);
        let mut all_checked = !all_ids.is_empty() && all_ids.iter().all(|id| selected.contains(id));
        let some_checked = all_ids.iter().any(|id| selected.contains(id));
        let mixed = some_checked && !all_checked;
        ui.horizontal(|ui| {
            if theme::checkbox_named(
                ui,
                &mut all_checked,
                mixed,
                "Select all Health findings",
                selection_enabled && !all_ids.is_empty(),
            )
            .changed()
            {
                if all_checked {
                    select_ids.extend(all_ids.clone());
                } else {
                    clear_ids.extend(all_ids.clone());
                }
            }
            theme::table_cell(
                ui,
                RichText::new("Category").color(t.muted),
                name_width,
                32.,
            );
            health_count_cell(
                ui,
                RichText::new(if issue_step { "Issues" } else { "Items" }).color(t.muted),
                item_width,
                32.,
            );
            if !issue_step {
                health_count_cell(ui, RichText::new("Size").color(t.muted), size_width, 32.);
            }
        });
        let previous_y_spacing = ui.spacing().item_spacing.y;
        ui.spacing_mut().item_spacing.y = 0.;
        for (category_index, category) in report.categories.iter().enumerate() {
            let ids = category
                .findings
                .iter()
                .filter(|finding| finding.actionable)
                .map(|finding| finding.id.clone())
                .collect::<Vec<_>>();
            let selected_count = ids.iter().filter(|id| selected.contains(*id)).count();
            let mut checked = !ids.is_empty() && selected_count == ids.len();
            let mixed = selected_count > 0 && !checked;
            let selection_label = format!("Select {}", category_label(category.category));
            let open = self
                .health_ui
                .expanded_categories
                .contains(&category.category);
            let expand_label = format!(
                "{} {}",
                if open { "Hide" } else { "Show" },
                category_label(category.category)
            );
            egui::Frame::new()
                .fill(if selected_count > 0 {
                    t.card
                } else {
                    egui::Color32::TRANSPARENT
                })
                .show(ui, |ui| {
                    ui.set_min_width(width);
                    let row = ui.horizontal(|ui| {
                        ui.set_min_height(row_height);
                        if theme::checkbox_named(
                            ui,
                            &mut checked,
                            mixed,
                            &selection_label,
                            selection_enabled && !ids.is_empty(),
                        )
                        .changed()
                        {
                            if checked {
                                select_ids.extend(ids.clone());
                            } else {
                                clear_ids.extend(ids.clone());
                            }
                        }
                        ui.allocate_ui_with_layout(
                            egui::vec2(name_width, row_height),
                            Layout::left_to_right(Align::Center),
                            |ui| {
                                ui.set_min_size(egui::vec2(name_width, row_height));
                                ui.set_max_width(name_width);
                                let (icon_rect, _) = ui.allocate_exact_size(
                                    egui::Vec2::splat(24.),
                                    egui::Sense::hover(),
                                );
                                theme::paint_icon(
                                    ui.painter(),
                                    icon_rect,
                                    health_category_icon(category.category),
                                    t.muted,
                                );
                                ui.allocate_ui_with_layout(
                                    egui::vec2((name_width - 32.).max(100.), 40.),
                                    Layout::top_down(Align::Min),
                                    |ui| {
                                        ui.spacing_mut().item_spacing.y = 3.;
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(category_label(category.category))
                                                    .size(theme::FONT_BODY)
                                                    .family(theme::semibold()),
                                            )
                                            .truncate(),
                                        );
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(
                                                    coverage_reason(&category.coverage)
                                                        .unwrap_or_else(|| {
                                                            health_category_description(
                                                                category.category,
                                                            )
                                                        }),
                                                )
                                                .size(theme::FONT_CAPTION)
                                                .color(t.muted),
                                            )
                                            .truncate()
                                            .show_tooltip_when_elided(false),
                                        )
                                        .on_hover_text(
                                            coverage_reason(&category.coverage).unwrap_or_else(
                                                || health_category_description(category.category),
                                            ),
                                        );
                                    },
                                );
                            },
                        );
                        health_count_cell(
                            ui,
                            if issue_step
                                && category.category == HealthCategory::StartupAppsForReview
                            {
                                "Review".into()
                            } else {
                                category.reported_items.to_string()
                            },
                            item_width,
                            row_height,
                        );
                        if !issue_step {
                            health_count_cell(
                                ui,
                                category
                                    .reported_bytes
                                    .map(format_bytes)
                                    .unwrap_or_else(|| "—".into()),
                                size_width,
                                row_height,
                            );
                        }
                        if theme::disclosure(ui, &expand_label, open).clicked() {
                            if open {
                                self.health_ui
                                    .expanded_categories
                                    .retain(|existing| *existing != category.category);
                            } else {
                                self.health_ui.expanded_categories.push(category.category);
                            }
                        }
                    });
                    if !open && category_index + 1 < report.categories.len() {
                        ui.painter().hline(
                            row.response.rect.x_range(),
                            row.response.rect.bottom(),
                            egui::Stroke::new(1., t.border),
                        );
                    }
                });
            if open {
                if category.findings.is_empty() && step != HealthStep::Privacy {
                    theme::muted(
                        ui,
                        coverage_reason(&category.coverage)
                            .unwrap_or("No items found in this category."),
                        t,
                    );
                } else if step == HealthStep::Privacy {
                    let groups = health_browser_groups_for_report(report, category);
                    if groups.is_empty() {
                        theme::muted(
                            ui,
                            coverage_reason(&category.coverage)
                                .unwrap_or("No items found in this category."),
                            t,
                        );
                    }
                    for group in groups {
                        let ids = group
                            .findings
                            .iter()
                            .filter(|f| f.actionable)
                            .map(|f| f.id.clone())
                            .collect::<Vec<_>>();
                        let selected_count = ids.iter().filter(|id| selected.contains(*id)).count();
                        let mut checked = !ids.is_empty() && selected_count == ids.len();
                        let label = health_browser_label(group.browser);
                        ui.horizontal(|ui| {
                            ui.set_min_height(44.);
                            ui.add_space(35.);
                            if theme::checkbox_named(
                                ui,
                                &mut checked,
                                selected_count > 0 && selected_count < ids.len(),
                                &format!("Select {label} {}", category_label(category.category)),
                                selection_enabled && !ids.is_empty(),
                            )
                            .changed()
                            {
                                if checked {
                                    select_ids.extend(ids.clone());
                                } else {
                                    clear_ids.extend(ids.clone());
                                }
                            }
                            ui.allocate_ui_with_layout(
                                egui::vec2((name_width - 35.).max(100.), 44.),
                                Layout::left_to_right(Align::Center),
                                |ui| {
                                    ui.set_min_width((name_width - 35.).max(100.));
                                    ui.set_max_width((name_width - 35.).max(100.));
                                    let resource = group
                                        .browser
                                        .and_then(|browser| {
                                            self.health_ui.browser_icons.get(&browser)
                                        })
                                        .map(String::as_str);
                                    self.app_icons.show_browser(ui, resource, 20.);
                                    theme::table_cell(ui, label, (name_width - 63.).max(60.), 44.);
                                },
                            );
                            health_count_cell(
                                ui,
                                group
                                    .findings
                                    .iter()
                                    .map(|finding| finding.item_count)
                                    .sum::<usize>()
                                    .to_string(),
                                item_width,
                                44.,
                            );
                            let bytes = group.findings.iter().try_fold(0u64, |sum, f| {
                                f.size_bytes.and_then(|size| sum.checked_add(size))
                            });
                            health_count_cell(
                                ui,
                                bytes.map(format_bytes).unwrap_or_else(|| "—".into()),
                                size_width,
                                44.,
                            );
                            ui.add_space(26.);
                        });
                    }
                } else {
                    for finding in &category.findings {
                        ui.horizontal(|ui| {
                            ui.set_min_height(44.);
                            let mut row_selected = selected.contains(&finding.id);
                            if theme::checkbox_named(
                                ui,
                                &mut row_selected,
                                false,
                                &format!("Select {}", finding.name),
                                selection_enabled && finding.actionable,
                            )
                            .changed()
                            {
                                if row_selected {
                                    select_ids.push(finding.id.clone());
                                } else {
                                    clear_ids.push(finding.id.clone());
                                }
                            }
                            let detail_width = (ui.available_width() - 90. - 76. - 24.).max(140.);
                            theme::table_cell_with_tooltip(
                                ui,
                                &finding.name,
                                detail_width,
                                44.,
                                finding.detail.as_deref().unwrap_or(&finding.name),
                            );
                            theme::table_cell(
                                ui,
                                finding
                                    .size_bytes
                                    .map(format_bytes)
                                    .unwrap_or_else(|| "—".into()),
                                76.,
                                44.,
                            );
                            if theme::row_action(ui, "Details", true).clicked() {
                                self.health_ui.detail_id = Some(finding.id.clone());
                            }
                        });
                    }
                }
                ui.add_space(8.);
            }
        }
        ui.spacing_mut().item_spacing.y = previous_y_spacing;
        if !clear_ids.is_empty() {
            if let Err(error) = self
                .health_ui
                .coordinator
                .select_findings(&clear_ids, false)
            {
                self.error = Some(error);
            }
        }
        if !select_ids.is_empty() {
            if let Err(error) = self
                .health_ui
                .coordinator
                .select_findings(&select_ids, true)
            {
                self.error = Some(error);
            }
        }
    }

    fn health_effect_result(&self, ui: &mut egui::Ui, t: Tokens, step: HealthStep) {
        let status = self.health_ui.coordinator.status(step).clone();
        let message = self
            .health_ui
            .coordinator
            .effect_message(step)
            .map(str::to_owned);
        let receipts = self.health_ui.coordinator.effect_receipts(step).to_vec();
        let HealthStepStatus::Results { quality, .. } = status else {
            return;
        };
        let mut summary = effect_quality_label(quality).to_owned();
        if let Some(message) = &message {
            summary.push_str(&format!(" · {message}"));
        }
        if quality == HealthEffectQuality::Uncertain {
            summary
                .push_str(" · Review the recovery history before retrying an uncertain operation.");
        }
        if quality == HealthEffectQuality::Uncertain {
            theme::status_banner(ui, &summary, theme::StatusKind::Info, false, false);
            ui.add_space(8.);
        }
        theme::scroll_vertical()
            .id_salt("health-action-receipts")
            .max_height(96.)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for receipt in &receipts {
                    theme::muted(ui, effect_receipt_summary(receipt), t);
                }
                if quality != HealthEffectQuality::Uncertain {
                    if let Some(message) = &message {
                        theme::muted(ui, format!("Result note: {message}"), t);
                    }
                }
            });
    }

    fn health_final_summary(&self, ui: &mut egui::Ui, t: Tokens) {
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.heading("Health Check summary");
            ui.add_space(6.);
            theme::muted(
                ui,
                "Each result below comes from the current owner service. Unsupported categories remain visible as gaps; no overall score is inferred.",
                t,
            );
            for step in HealthStep::ORDER {
                ui.add_space(9.);
                let status = self.health_ui.coordinator.status(step);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(step_label(step)).family(theme::semibold()));
                    theme::muted(ui, status_label(status), t);
                });
                if let Some(report) = self.health_ui.coordinator.report(step) {
                    for category in &report.categories {
                        theme::muted(
                            ui,
                            format!(
                                "{} · {} · {}",
                                category_label(category.category),
                                coverage_label(&category.coverage),
                                category_summary(category)
                            ),
                            t,
                        );
                    }
                }
                if let Some(message) = self.health_ui.coordinator.effect_message(step) {
                    ui.add(egui::Label::new(RichText::new(message).color(t.attention)).wrap());
                }
            }
        });
    }

    fn health_browser_review_dialog(&mut self, ctx: &egui::Context) {
        let busy = self.busy();
        let t = theme::tokens(self.prefs.dark);
        let running = self.health_ui.running.clone();
        let unavailable = self.health_ui.process_error.clone();
        let mut browsers = Vec::new();
        for process in &running {
            if !browsers.contains(&process.browser) {
                browsers.push(process.browser);
            }
        }
        let mut refresh = false;
        let mut proceed = false;
        let mut close = !busy && ctx.input(|input| input.key_pressed(egui::Key::Escape));
        let selected_count = running
            .iter()
            .filter(|process| {
                self.health_ui
                    .selected_processes
                    .contains(&(process.browser, process.pid))
            })
            .count();
        let width = (ctx.content_rect().width() - 48.).clamp(280., 552.);
        let response = egui::Modal::new(egui::Id::new("health-browser-gate"))
            .frame(theme::dialog_frame(t))
            .show(ctx, |ui| {
                ui.set_width(width);
                ui.horizontal(|ui| {
                    ui.allocate_exact_size(egui::Vec2::new(28., 32.), egui::Sense::hover());
                    ui.allocate_ui_with_layout(egui::Vec2::new(width - 56. - 2. * ui.spacing().item_spacing.x, 32.), Layout::top_down(Align::Center), |ui| {
                        ui.label(RichText::new("Please close running browsers").size(theme::FONT_DISPLAY).family(theme::semibold()));
                    });
                    close |= theme::close_button(ui, "Cancel browser review", !busy);
                });
                ui.add_space(8.);
                ui.vertical_centered(|ui| theme::muted(ui, "Close the browsers you select before continuing. Unselected browsers remain open.", t));
                ui.add_space(20.);
                theme::scroll_vertical().max_height((ctx.content_rect().height() - 280.).max(100.)).auto_shrink([false, true]).show(ui, |ui| {
                    if let Some(error) = &unavailable {
                        ui.colored_label(t.attention, format!("Browser status could not be checked: {error}"));
                        refresh = theme::secondary(ui, "Refresh status", !busy);
                    }
                    if browsers.len() > 1 {
                        let mut all = selected_count == running.len();
                        if theme::checkbox_mixed(ui, &mut all, selected_count > 0 && selected_count < running.len(), "Select all", !busy).changed() {
                            self.health_ui.selected_processes = if all { running.iter().map(|process| (process.browser, process.pid)).collect() } else { HashSet::new() };
                        }
                        ui.add_space(8.);
                    }
                    for browser in &browsers {
                        let processes = running.iter().filter(|process| process.browser == *browser).collect::<Vec<_>>();
                        let selected = processes.iter().filter(|process| self.health_ui.selected_processes.contains(&(process.browser, process.pid))).count();
                        let mut checked = selected == processes.len();
                        ui.horizontal(|ui| {
                            if theme::checkbox_named(ui, &mut checked, selected > 0 && selected < processes.len(), browser.label(), !busy).changed() {
                                for process in &processes {
                                    if checked { self.health_ui.selected_processes.insert((process.browser, process.pid)); }
                                    else { self.health_ui.selected_processes.remove(&(process.browser, process.pid)); }
                                }
                            }
                            if let Some(resource) = self.health_ui.browser_icons.get(browser) {
                                self.app_icons.show(ui, Some(resource), 20.);
                            } else {
                                let (rect, _) = ui.allocate_exact_size(egui::Vec2::splat(20.), egui::Sense::hover());
                                theme::paint_icon(ui.painter(), rect, theme::Icon::Browser, t.muted);
                            }
                            ui.label(browser.label());
                        });
                        ui.add_space(8.);
                    }
                    if busy { ui.spinner(); theme::muted(ui, &self.progress, t); }
                });
                ui.add_space(20.);
                let selected_now = running.iter().filter(|process| self.health_ui.selected_processes.contains(&(process.browser, process.pid))).count();
                let proceed_label = if selected_now == 0 { "Skip closing browsers" } else if selected_now == running.len() { "Close all browsers" } else { "Close selected browsers" };
                let button_width = ["Cancel", proceed_label].into_iter().map(|label| ui.painter().layout_no_wrap(label.into(), egui::FontId::new(theme::FONT_BODY, theme::semibold()), t.foreground).size().x + 2. * theme::CONTROL_PADDING_X).sum::<f32>() + ui.spacing().item_spacing.x;
                ui.horizontal(|ui| {
                    ui.add_space(((ui.available_width() - button_width) / 2.).max(0.));
                    close |= theme::secondary(ui, "Cancel", !busy);
                    proceed = theme::primary(ui, proceed_label, t, !busy && unavailable.is_none());
                });
            });
        if refresh {
            self.begin_health_browser_refresh(ctx);
        } else if proceed {
            let selected = running.iter().any(|process| {
                self.health_ui
                    .selected_processes
                    .contains(&(process.browser, process.pid))
            });
            if selected {
                self.begin_health_browser_close(ctx);
            } else if let Err(error) = self.health_ui.coordinator.accept_browser_review() {
                self.error = Some(error);
            } else {
                self.health_ui.browser_review_open = false;
            }
        } else if (close || response.should_close()) && !busy {
            self.health_ui.browser_review_open = false;
            self.health_ui.started = false;
        }
    }

    fn health_action_review_dialog(&mut self, ctx: &egui::Context) {
        let busy = self.busy();
        if !busy && ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.cancel_health_action_review();
            return;
        }
        let Some(plan) = self.health_ui.action_plan.as_ref() else {
            return;
        };
        let plan_id = plan.id();
        let step = plan.step();
        let selected_count = plan.selected_count();
        let requires_permanent = plan.requires_permanent_confirmation();
        let partial = plan.partial_acknowledged();
        let actions = plan
            .actions()
            .iter()
            .map(action_summary)
            .collect::<Vec<_>>();
        let selected_rows = self
            .health_ui
            .coordinator
            .selected_ids(step)
            .into_iter()
            .filter_map(|id| {
                self.health_ui
                    .coordinator
                    .report(step)
                    .and_then(|report| report.finding(id.clone()).cloned())
                    .map(|finding| (id, finding))
            })
            .collect::<Vec<_>>();
        if selected_rows.len() != selected_count {
            self.cancel_health_action_review();
            self.error = Some(
                "The reviewed Health Check selection no longer matches its current report.".into(),
            );
            return;
        }

        let t = theme::tokens(self.prefs.dark);
        let mut close = false;
        let mut confirm = false;
        let width = (ctx.content_rect().width() - 32.).clamp(300., 620.);
        let body_height = (ctx.content_rect().height() - 210.).max(120.);
        let response = egui::Modal::new(egui::Id::new("health-action-review"))
            .frame(theme::dialog_frame(t))
            .show(ctx, |ui| {
                ui.set_width(width);
                ui.set_max_width(width);
                ui.horizontal(|ui| {
                    ui.heading("Review Health Check actions");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        close |= theme::close_button(ui, "Close Health review", !busy);
                    });
                });
                ui.separator();
                theme::scroll_vertical()
                    .max_height(body_height)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                    ui.add_space(7.);
                    ui.label(format!(
                        "{} selected from {}",
                        theme::counted_label(selected_count, "finding", "findings"),
                        step_label(step)
                    ));
                    if partial {
                        ui.add_space(5.);
                        ui.colored_label(
                            t.attention,
                            "This action plan uses a partial scan that you acknowledged.",
                        );
                    }
                    ui.add_space(7.);
                    for action in &actions {
                        theme::muted(ui, action, t);
                    }
                    ui.add_space(8.);
                    ui.label(RichText::new("Selected rows").family(theme::semibold()));
                    for (_, finding) in selected_rows.iter().take(16) {
                        ui.add(
                            egui::Label::new(format!(
                                "{} · {}",
                                category_label(finding.category),
                                finding.name
                            ))
                            .wrap(),
                        );
                    }
                    if selected_rows.len() > 16 {
                        theme::muted(
                            ui,
                            format!("{} more selected rows", selected_rows.len() - 16),
                            t,
                        );
                    }
                    if requires_permanent {
                        ui.add_space(10.);
                        ui.colored_label(
                            t.attention,
                            "This plan permanently purges selected Recycle Bin items through the operating system. This cannot be undone.",
                        );
                        theme::checkbox(
                            ui,
                            &mut self.health_ui.permanent_acknowledged,
                            "I understand this purge is permanent",
                            !busy,
                        );
                    }
                    if !self.history_readable || self.data_dir.as_os_str().is_empty() {
                        ui.add_space(7.);
                        ui.colored_label(
                            t.attention,
                            "Durable operation history is unavailable. No action can start.",
                        );
                    }
                    if busy {
                        ui.add_space(7.);
                        ui.horizontal(|ui| {
                            ui.spinner();
                            theme::muted(ui, self.progress.clone(), t);
                        });
                    }
                });
                ui.add_space(6.);
                ui.separator();
                theme::action_row(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        close |= theme::secondary(ui, "Back to findings", !busy);
                        confirm = theme::primary(
                            ui,
                            "Confirm reviewed actions",
                            t,
                            !busy
                                && self.history_readable
                                && self.data_dir.is_absolute()
                                && !self.health_privacy_rules_blocked()
                                && (!requires_permanent || self.health_ui.permanent_acknowledged),
                        );
                    });
                });
            });
        if confirm {
            if self
                .health_ui
                .action_plan
                .as_ref()
                .is_some_and(|plan| plan.id() == plan_id)
            {
                self.begin_health_effects(ctx);
            }
        } else if close || (response.should_close() && !busy) {
            self.cancel_health_action_review();
        }
    }

    fn health_detail_dialog(&mut self, ctx: &egui::Context) {
        let Some(id) = self.health_ui.detail_id.clone() else {
            return;
        };
        if !self.busy() && ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.health_ui.detail_id = None;
            return;
        }
        let report = self
            .health_ui
            .coordinator
            .current_step()
            .and_then(|step| self.health_ui.coordinator.report(step));
        let finding = report.and_then(|report| report.finding(id.clone()).cloned());
        let extra = report.and_then(|report| finding_source_details(report, &id));
        let t = theme::tokens(self.prefs.dark);
        let width = (ctx.content_rect().width() - 32.).clamp(280., 580.);
        let body_height = (ctx.content_rect().height() - 200.).max(120.);
        let mut close = false;
        let response = egui::Modal::new(egui::Id::new("health-finding-detail"))
            .frame(theme::dialog_frame(t))
            .show(ctx, |ui| {
                ui.set_width(width);
                ui.set_max_width(width);
                ui.horizontal(|ui| {
                    ui.heading("Health Check finding details");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        close |= theme::close_button(ui, "Close finding details", true);
                    });
                });
                ui.separator();
                theme::scroll_vertical()
                    .max_height(body_height)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                    ui.add_space(8.);
                    if let Some(finding) = &finding {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&finding.name).family(theme::semibold()),
                            )
                            .wrap(),
                        );
                        detail_row(ui, "Category", category_label(finding.category), t);
                        if let Some(detail) = &finding.detail {
                            detail_row(ui, "Scan detail", detail, t);
                        }
                        if let Some(size) = finding.size_bytes {
                            detail_row(ui, "Reported size", &format_bytes(size), t);
                        }
                        if let Some(extra) = &extra {
                            ui.add_space(7.);
                            for (label, value) in extra {
                                detail_row(ui, label, value, t);
                            }
                        }
                        ui.add_space(8.);
                        theme::muted(
                            ui,
                            if finding.actionable {
                                "Include this item in your cleanup selection."
                            } else {
                                "This item is for review. No cleanup action is available."
                            },
                            t,
                        );
                    } else {
                        ui.colored_label(
                            t.attention,
                            "This item is no longer in the current results. Scan again to review it.",
                        );
                    }
                });
                ui.add_space(6.);
                ui.separator();
                theme::action_row(ui, |ui| {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        close |= theme::secondary(ui, "Close details", true);
                    });
                });
            });
        if close || response.should_close() {
            self.health_ui.detail_id = None;
        }
    }

    fn cancel_health_action_review(&mut self) {
        if let Some(plan) = self.health_ui.action_plan.take() {
            if let Err(error) = self.health_ui.coordinator.cancel_action_review(plan.id()) {
                self.error = Some(error);
            }
        }
        self.health_ui.permanent_acknowledged = false;
    }
}

struct HealthBrowserGroup<'a> {
    browser: Option<Browser>,
    findings: Vec<&'a HealthFinding>,
}

fn health_browser_label(browser: Option<Browser>) -> &'static str {
    match browser {
        Some(Browser::Chrome) => "Google Chrome",
        Some(Browser::Edge) => "Microsoft Edge",
        Some(Browser::Firefox) => "Mozilla Firefox",
        Some(browser) => browser.label(),
        None => "Other browser records",
    }
}

fn health_browser_groups(category: &HealthCategoryReport) -> Vec<HealthBrowserGroup<'_>> {
    let mut groups: Vec<HealthBrowserGroup<'_>> = Vec::new();
    for finding in &category.findings {
        if let Some(group) = groups
            .iter_mut()
            .find(|group| group.browser == finding.browser)
        {
            group.findings.push(finding);
        } else {
            groups.push(HealthBrowserGroup {
                browser: finding.browser,
                findings: vec![finding],
            });
        }
    }
    sort_health_browser_groups(&mut groups);
    groups
}
fn sort_health_browser_groups(groups: &mut [HealthBrowserGroup<'_>]) {
    // The reference orders by bytes descending. Unknown-byte records keep the
    // stable source order among zero/unknown totals and still display a dash.
    groups.sort_by_key(|group| {
        std::cmp::Reverse(
            group
                .findings
                .iter()
                .try_fold(0u64, |sum, f| {
                    f.size_bytes.and_then(|bytes| sum.checked_add(bytes))
                })
                .unwrap_or(0),
        )
    });
}
fn health_browser_groups_for_report<'a>(
    report: &HealthStepReport,
    category: &'a HealthCategoryReport,
) -> Vec<HealthBrowserGroup<'a>> {
    let mut groups = health_browser_groups(category);
    if !matches!(category.coverage, HealthCoverage::Complete)
        || matches!(
            report.quality,
            HealthScanQuality::Cancelled | HealthScanQuality::Failed
        )
    {
        return groups;
    }
    let HealthServiceData::Privacy {
        profiles,
        browser_records,
        browser_cache_files,
    } = report.source()
    else {
        return groups;
    };
    let mut empty_browsers = Vec::new();
    match category.category {
        HealthCategory::InternetTemporaryFiles if !browser_cache_files.cancelled => {
            for source in &browser_cache_files.categories {
                if source.available
                    && !source.truncated
                    && source.skipped == 0
                    && source.files.is_empty()
                {
                    if let Some(browser) = Browser::from_cache_category(&source.id) {
                        empty_browsers.push(browser);
                    }
                }
            }
        }
        HealthCategory::Cookies | HealthCategory::BrowsingHistory
            if !profiles.partial
                && profiles.skipped.is_empty()
                && !browser_records.partial
                && !browser_records.truncated
                && !browser_records.cancelled
                && browser_records.skipped_count == 0
                && browser_records.skipped.is_empty()
                && browser_records.omitted_skip_details == 0
                && browser_records.profiles_scanned == profiles.profiles.len() =>
        {
            let wanted = if category.category == HealthCategory::Cookies {
                privacy::PrivacyCategory::Cookies
            } else {
                privacy::PrivacyCategory::History
            };
            if browser_records.categories_scanned.contains(&wanted) {
                for profile in &profiles.profiles {
                    if !browser_records
                        .records
                        .iter()
                        .any(|row| row.browser == profile.browser && row.category == wanted)
                    {
                        empty_browsers.push(profile.browser);
                    }
                }
            }
        }
        _ => {}
    }
    for browser in empty_browsers {
        if !groups.iter().any(|group| group.browser == Some(browser)) {
            groups.push(HealthBrowserGroup {
                browser: Some(browser),
                findings: Vec::new(),
            });
        }
    }
    sort_health_browser_groups(&mut groups);
    groups
}

#[cfg(test)]
mod ui_contract_tests {
    use super::*;

    fn fixture(case: &str) -> App {
        App::new_fixture_with_context(&egui::Context::default(), case).unwrap()
    }

    #[test]
    fn terminal_visual_fixtures_retain_distinct_verified_owner_receipt_qualities() {
        for (case, expected) in [
            ("health-results-complete", HealthEffectQuality::Complete),
            ("health-results-partial", HealthEffectQuality::Partial),
            ("health-results-cancelled", HealthEffectQuality::Cancelled),
            ("health-results-uncertain", HealthEffectQuality::Uncertain),
        ] {
            let app = fixture(case);
            assert!(
                matches!(app.health_ui.coordinator.status(HealthStep::Space), HealthStepStatus::Results {quality, ..} if *quality==expected)
            );
            let receipts = app.health_ui.coordinator.effect_receipts(HealthStep::Space);
            assert_eq!(receipts.len(), 1);
            let HealthEffectReceipt::Files(receipt) = &receipts[0] else {
                panic!("file receipt")
            };
            assert_eq!(
                receipt.files,
                if expected == HealthEffectQuality::Complete {
                    3
                } else {
                    0
                }
            );
            assert_eq!(
                receipt.interrupted,
                expected == HealthEffectQuality::Uncertain
            );
            assert_eq!(
                receipt.cancelled,
                expected == HealthEffectQuality::Cancelled
            );
            if expected == HealthEffectQuality::Uncertain {
                assert!(app.notice.is_none(), "recovery has no duplicate toast");
            } else {
                assert!(
                    app.notice_deadline.is_some(),
                    "routine completion alerts expire"
                );
            }
        }
    }

    #[test]
    fn effect_completion_consumes_worker_history_without_turning_cancel_into_success() {
        for history_ok in [false, true] {
            let mut app = fixture("health-cleaning");
            app.data_dir = r"C:\__DCleaner_NEVER_READ_TERMINAL_FIXTURE__".into();
            let HealthStepStatus::Applying { plan_id } = app
                .health_ui
                .coordinator
                .status(HealthStep::Privacy)
                .clone()
            else {
                panic!("fixture must be applying")
            };
            let history = if history_ok {
                Ok(super::super::qa_core::history_fixture())
            } else {
                Err("fixture history unavailable".into())
            };
            app.health_event(HealthEvent::EffectsFinished {
                plan_id,
                receipts: Vec::new(),
                issues: Vec::new(),
                attempted: false,
                uncertain: false,
                cancelled_before_any: true,
                history,
            });
            assert!(matches!(
                app.health_ui.coordinator.status(HealthStep::Privacy),
                HealthStepStatus::Cancelled
            ));
            assert_eq!(app.history_readable, history_ok);
            if history_ok {
                assert_eq!(app.history.len(), 2);
            } else {
                assert!(
                    app.error
                        .as_ref()
                        .unwrap()
                        .contains("fixture history unavailable")
                );
            }
        }
    }

    #[test]
    fn multiple_profiles_group_exact_ids_by_browser_and_descending_bytes() {
        let app = fixture("health-privacy-multi-profile");
        let report = app
            .health_ui
            .coordinator
            .report(HealthStep::Privacy)
            .unwrap();
        let category = report
            .categories
            .iter()
            .find(|c| c.category == HealthCategory::InternetTemporaryFiles)
            .unwrap();
        let groups = health_browser_groups_for_report(report, category);
        assert_eq!(
            groups.iter().map(|g| g.browser).collect::<Vec<_>>(),
            vec![
                Some(Browser::Firefox),
                Some(Browser::Chrome),
                Some(Browser::Edge)
            ]
        );
        assert_eq!(
            groups.iter().map(|g| g.findings.len()).collect::<Vec<_>>(),
            vec![1, 2, 0]
        );
        let grouped = groups
            .iter()
            .flat_map(|g| g.findings.iter().map(|f| f.id.clone()))
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            grouped,
            app.health_ui
                .coordinator
                .selected_ids(HealthStep::Privacy)
                .into_iter()
                .collect::<std::collections::HashSet<_>>()
        );
    }

    #[test]
    fn empty_browser_rows_require_complete_source_and_never_add_action_ids() {
        let report = health_browser_fixture_report("health-privacy-empty-browsers");
        let category = report
            .categories
            .iter()
            .find(|c| c.category == HealthCategory::Cookies)
            .unwrap();
        let groups = health_browser_groups_for_report(&report, category);
        assert_eq!(groups.len(), 3);
        assert!(groups.iter().all(|g| g.findings.is_empty()));
        let mut incomplete = category.clone();
        incomplete.coverage = HealthCoverage::Unsupported {
            reason: "fixture unavailable".into(),
        };
        assert!(health_browser_groups_for_report(&report, &incomplete).is_empty());
        let mut cancelled = report.clone();
        cancelled.quality = HealthScanQuality::Cancelled;
        assert!(health_browser_groups_for_report(&cancelled, category).is_empty());
    }

    #[test]
    fn browser_groups_preserve_exact_ids_and_do_not_guess_from_labels() {
        let mut app = fixture("health-privacy-expanded");
        let report = app
            .health_ui
            .coordinator
            .report(HealthStep::Privacy)
            .unwrap();
        let mut category = report
            .categories
            .iter()
            .find(|c| c.category == HealthCategory::InternetTemporaryFiles)
            .unwrap()
            .clone();
        let original = category.findings[0].id.clone();
        category.findings[0].name = "Firefox misleading name".into();
        let mut other = category.findings[0].clone();
        other.id = HealthFindingId::FileCandidate(Uuid::new_v4());
        other.browser = None;
        other.name = "Google Chrome misleading name".into();
        let other_id = other.id.clone();
        category.findings.push(other);
        let groups = health_browser_groups(&category);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].browser, Some(Browser::Chrome));
        assert_eq!(groups[0].findings[0].id, original);
        assert_eq!(groups[1].browser, None);
        assert_eq!(groups[1].findings[0].id, other_id);
        // Group selection continues to use the existing coordinator's exact IDs.
        for finding in &groups[0].findings {
            app.health_ui
                .coordinator
                .select_finding(finding.id.clone(), false)
                .unwrap();
        }
        let selected = app.health_ui.coordinator.selected_ids(HealthStep::Privacy);
        assert!(!selected.contains(&original));
        assert_eq!(selected.len(), 1);
    }

    #[test]
    fn unreadable_cookie_settings_block_privacy_review_without_blocking_space() {
        let mut privacy = fixture("health-privacy");
        privacy.mark_health_cookie_settings_unverified("fixture unreadable");
        privacy.begin_health_action_review();
        assert!(privacy.health_ui.action_plan.is_none());
        assert!(privacy.health_privacy_rules_blocked());

        let mut space = fixture("health-space");
        space.mark_health_cookie_settings_unverified("fixture unreadable");
        assert!(!space.health_privacy_rules_blocked());
        space.begin_health_action_review();
        assert!(space.health_ui.action_plan.is_some());
        assert!(matches!(
            space.health_ui.coordinator.status(HealthStep::Space),
            HealthStepStatus::ActionReview { .. }
        ));
    }

    #[test]
    fn complete_scan_review_does_not_claim_partial_acknowledgement() {
        let app = fixture("health-space-review");
        let plan = app.health_ui.action_plan.as_ref().unwrap();
        assert!(!plan.partial_acknowledged());
    }

    #[test]
    fn cookie_settings_changes_do_not_cancel_an_open_space_action_review() {
        let mut app = fixture("health-space-review");
        let plan_id = app.health_ui.action_plan.as_ref().unwrap().id();
        app.sync_health_cookie_settings(CookieExceptionSettings {
            schema: 1,
            keep_domains: vec!["trusted.example".into()],
            keep_signed_in: false,
        });
        assert_eq!(app.health_ui.action_plan.as_ref().unwrap().id(), plan_id);
        app.mark_health_cookie_settings_unverified("fixture unreadable");
        assert_eq!(app.health_ui.action_plan.as_ref().unwrap().id(), plan_id);
        assert!(!app.health_privacy_rules_blocked());
    }

    #[test]
    fn cancelling_review_keeps_the_exact_selection_without_running_effects() {
        let mut app = fixture("health-privacy-review");
        let ids = app.health_ui.coordinator.selected_ids(HealthStep::Privacy);
        assert!(app.health_ui.action_plan.is_some());
        app.cancel_health_action_review();
        assert!(app.health_ui.action_plan.is_none());
        assert_eq!(
            app.health_ui.coordinator.selected_ids(HealthStep::Privacy),
            ids
        );
        assert!(app.worker.is_none());
    }

    #[test]
    fn stop_scan_requests_cancellation_without_turning_progress_into_success() {
        let mut app = fixture("health-scanning");
        app.request_health_cancel(HealthStep::Privacy);
        assert!(app.cancel.load(Ordering::Relaxed));
        assert!(matches!(
            app.health_ui.coordinator.status(HealthStep::Privacy),
            HealthStepStatus::Scanning {
                cancel_requested: true,
                ..
            }
        ));
        assert!(
            app.health_ui
                .coordinator
                .report(HealthStep::Privacy)
                .is_none()
        );
    }
}

fn health_count_cell(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    width: f32,
    height: f32,
) -> egui::Response {
    ui.allocate_ui_with_layout(
        egui::vec2(width, height),
        Layout::right_to_left(Align::Center),
        |ui| {
            ui.set_min_size(egui::vec2(width, height));
            ui.set_max_width(width);
            ui.add(egui::Label::new(text).truncate())
        },
    )
    .inner
}

fn category_label(category: HealthCategory) -> &'static str {
    match category {
        HealthCategory::InternetTemporaryFiles => "Temporary internet files",
        HealthCategory::Cookies => "Cookies",
        HealthCategory::BrowsingHistory => "Browsing history",
        HealthCategory::RecycleBin => "Recycle Bin",
        HealthCategory::TemporarySystemFiles => "Temporary system files",
        HealthCategory::ApplicationCache => "Application cache",
        HealthCategory::StartupAppsForReview => "Startup apps",
        HealthCategory::OutdatedApplications => "Outdated apps",
        HealthCategory::DriverUpdates => "Driver updates",
        HealthCategory::BackgroundApps => "Background apps",
    }
}

fn health_category_icon(category: HealthCategory) -> theme::Icon {
    match category {
        HealthCategory::InternetTemporaryFiles => theme::Icon::Browser,
        HealthCategory::Cookies => theme::Icon::Cookie,
        HealthCategory::BrowsingHistory => theme::Icon::History,
        HealthCategory::RecycleBin => theme::Icon::Trash,
        HealthCategory::TemporarySystemFiles => theme::Icon::Disk,
        HealthCategory::ApplicationCache => theme::Icon::Duplicate,
        HealthCategory::StartupAppsForReview => theme::Icon::Startup,
        HealthCategory::OutdatedApplications => theme::Icon::Update,
        HealthCategory::DriverUpdates => theme::Icon::Driver,
        HealthCategory::BackgroundApps => theme::Icon::Optimizer,
    }
}

fn health_category_description(category: HealthCategory) -> &'static str {
    match category {
        HealthCategory::InternetTemporaryFiles => "Remove temporary files stored by web browsers.",
        HealthCategory::Cookies => "Remove website data, keeping your trusted websites.",
        HealthCategory::BrowsingHistory => "Clear records of visited websites and searches.",
        HealthCategory::RecycleBin => "Clear your bin to free up valuable storage space.",
        HealthCategory::TemporarySystemFiles => {
            "Remove temporary files left by Windows and applications."
        }
        HealthCategory::ApplicationCache => "Free space used by cached application files.",
        HealthCategory::StartupAppsForReview => "Review which applications start automatically.",
        HealthCategory::OutdatedApplications => {
            "Review available updates for installed applications."
        }
        HealthCategory::DriverUpdates => "Review available device driver updates.",
        HealthCategory::BackgroundApps => "Review applications running in the background.",
    }
}

fn category_summary(category: &HealthCategoryReport) -> String {
    let count = category.reported_items;
    match category.reported_bytes {
        Some(bytes) => format!("{count} row(s) · {}", format_bytes(bytes)),
        None => format!("{count} row(s)"),
    }
}

fn coverage_label(coverage: &HealthCoverage) -> &'static str {
    match coverage {
        HealthCoverage::Complete => "Complete inventory",
        HealthCoverage::Partial { .. } => "Partial inventory",
        HealthCoverage::NeedsReview { .. } => "Needs review",
        HealthCoverage::Unsupported { .. } => "Not supported here",
        HealthCoverage::Failed { .. } => "Unavailable",
    }
}

fn coverage_reason(coverage: &HealthCoverage) -> Option<&str> {
    match coverage {
        HealthCoverage::Complete => None,
        HealthCoverage::Partial { reason }
        | HealthCoverage::NeedsReview { reason }
        | HealthCoverage::Unsupported { reason }
        | HealthCoverage::Failed { reason } => Some(reason),
    }
}

fn quality_label(quality: HealthScanQuality) -> &'static str {
    match quality {
        HealthScanQuality::Complete => "Complete scan",
        HealthScanQuality::Partial => "Partial scan",
        HealthScanQuality::Cancelled => "Cancelled",
        HealthScanQuality::Failed => "Failed",
    }
}

fn effect_quality_label(quality: HealthEffectQuality) -> &'static str {
    match quality {
        HealthEffectQuality::Complete => "Complete",
        HealthEffectQuality::Partial => "Partial",
        HealthEffectQuality::Cancelled => "Cancelled before any confirmed change",
        HealthEffectQuality::Uncertain => "Outcome needs recovery review",
    }
}

fn health_step_icon(step: HealthStep) -> theme::Icon {
    match step {
        HealthStep::Privacy => theme::Icon::EyeOff,
        HealthStep::Space => theme::Icon::Disk,
        HealthStep::ResolveIssues => theme::Icon::Settings,
    }
}

fn step_label(step: HealthStep) -> &'static str {
    match step {
        HealthStep::Privacy => "More privacy",
        HealthStep::Space => "More space",
        HealthStep::ResolveIssues => "Resolve issues",
    }
}

fn step_title(step: HealthStep) -> &'static str {
    match step {
        HealthStep::Privacy => "More privacy",
        HealthStep::Space => "More space",
        HealthStep::ResolveIssues => "Resolve issues",
    }
}

fn step_description(step: HealthStep) -> &'static str {
    match step {
        HealthStep::Privacy => {
            "Review supported browser records and browser cache files. Passwords and unrelated browser settings are kept."
        }
        HealthStep::Space => {
            "Review current temporary-file candidates and the current user’s Recycle Bin inventory."
        }
        HealthStep::ResolveIssues => {
            "Review startup entries and supported application update results. Recommendations are shown only when the owner service supports them."
        }
    }
}

fn status_label(status: &HealthStepStatus) -> String {
    match status {
        HealthStepStatus::Ready => "Ready to scan".into(),
        HealthStepStatus::AwaitingBrowserReview {
            running,
            status_unavailable,
        } => {
            if *status_unavailable {
                "Browser status needs refresh".into()
            } else {
                format!("{} browser process(es) need review", running.len())
            }
        }
        HealthStepStatus::Scanning {
            progress,
            cancel_requested,
        } => format!(
            "Scanning · {}{}",
            progress.detail.as_deref().unwrap_or("working"),
            if *cancel_requested {
                " · stopping"
            } else {
                ""
            }
        ),
        HealthStepStatus::Reviewing { quality, .. } => {
            format!("{} · review findings", quality_label(*quality))
        }
        HealthStepStatus::ActionReview { .. } => "Action review open".into(),
        HealthStepStatus::Applying { .. } => "Applying reviewed actions".into(),
        HealthStepStatus::Results { quality, .. } => {
            format!("{} action result", effect_quality_label(*quality))
        }
        HealthStepStatus::Skipped => "Skipped".into(),
        HealthStepStatus::Cancelled => "Cancelled".into(),
        HealthStepStatus::Failed { message } => format!("Failed · {message}"),
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut amount = bytes as f64;
    let mut unit = 0;
    while amount >= 1024. && unit + 1 < UNITS.len() {
        amount /= 1024.;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{amount:.1} {}", UNITS[unit])
    }
}

fn detail_row(ui: &mut egui::Ui, label: &str, value: &str, t: Tokens) {
    ui.horizontal_top(|ui| {
        ui.add_sized(
            [118., 22.],
            egui::Label::new(RichText::new(label).color(t.muted)),
        );
        ui.add(egui::Label::new(value).wrap());
    });
}

fn field_value(value: &dcleaner::startup::FieldValue<String>) -> Option<String> {
    match value {
        dcleaner::startup::FieldValue::Known { value } => Some(value.clone()),
        dcleaner::startup::FieldValue::Unknown { reason } => Some(format!("Unavailable: {reason}")),
        dcleaner::startup::FieldValue::NotApplicable => None,
    }
}

fn finding_source_details(
    report: &HealthStepReport,
    id: &HealthFindingId,
) -> Option<Vec<(&'static str, String)>> {
    let mut details = Vec::new();
    match (report.source(), id) {
        (
            HealthServiceData::Privacy {
                browser_records, ..
            },
            HealthFindingId::BrowserRecord(target),
        ) => {
            let row = browser_records
                .records
                .iter()
                .find(|row| row.id == *target)?;
            details.push(("Browser", row.browser.label().to_owned()));
            details.push(("Profile", row.profile_name.clone()));
            details.push(("Record type", format!("{:?}", row.category)));
            details.push(("Sanitized site", row.site.clone()));
        }
        (
            HealthServiceData::Privacy {
                browser_cache_files,
                ..
            },
            HealthFindingId::FileCandidate(target),
        )
        | (
            HealthServiceData::Space {
                files: browser_cache_files,
                ..
            },
            HealthFindingId::FileCandidate(target),
        ) => {
            let candidate = browser_cache_files
                .categories
                .iter()
                .flat_map(|category| &category.files)
                .find(|candidate| candidate.id == *target)?;
            details.push(("Current file path", candidate.path.display().to_string()));
            details.push(("Scanned root", candidate.root.display().to_string()));
            details.push(("Snapshot size", format_bytes(candidate.size)));
        }
        (HealthServiceData::Space { recycle_bin, .. }, HealthFindingId::RecycleBinItem(target)) => {
            let item = recycle_bin.items.iter().find(|item| item.id() == *target)?;
            details.push(("Original path", item.original_path().display().to_string()));
            details.push((
                "Deleted timestamp",
                item.deleted_at_unix_seconds().to_string(),
            ));
            details.push(("Item size", format!("{:?}", item.size())));
        }
        (
            HealthServiceData::ResolveIssues { startup, .. },
            HealthFindingId::StartupEntry(target),
        ) => {
            let entry = startup.entries.iter().find(|entry| entry.id == *target)?;
            details.push(("Startup section", entry.section.label().to_owned()));
            if let Some(value) = field_value(&entry.publisher) {
                details.push(("Publisher", value));
            }
            if let Some(value) = field_value(&entry.version) {
                details.push(("Version", value));
            }
            if let Some(value) = field_value(&entry.file_path) {
                details.push(("Program path", value));
            }
            details.push(("Current state", format!("{:?}", entry.enabled)));
            if let Some(limitation) = &entry.change_limitation {
                details.push(("Change status", limitation.clone()));
            }
        }
        (
            HealthServiceData::ResolveIssues { software, .. },
            HealthFindingId::SoftwareUpdate(target),
        ) => {
            let snapshot = software.as_ref().ok()?;
            let item = snapshot
                .items
                .iter()
                .find(|item| item.row_key() == target.as_str())?;
            details.push(("Package ID", item.row.package_id.clone()));
            details.push(("Update source", item.row.source_id.clone()));
            details.push((
                "Installed version",
                item.row
                    .installed_version
                    .clone()
                    .unwrap_or_else(|| "Unknown".into()),
            ));
            details.push((
                "Available version",
                item.row
                    .available_version
                    .clone()
                    .unwrap_or_else(|| "Unknown".into()),
            ));
            details.push((
                "Update action",
                if item.can_update() {
                    "Supported"
                } else {
                    "Review only"
                }
                .into(),
            ));
        }
        _ => return None,
    }
    Some(details)
}

fn action_summary(action: &HealthAction) -> String {
    match action {
        HealthAction::BrowserPrivacy(plan) => {
            if plan.file_count() > 0 {
                "Browser privacy: revalidate selected records; move reviewed storage files to Trash"
                    .into()
            } else {
                "Browser privacy: revalidate and remove selected database records".into()
            }
        }
        HealthAction::MoveFilesToTrash { candidate_ids, .. } => format!(
            "Move {} selected file(s) to the operating-system Trash",
            candidate_ids.len()
        ),
        HealthAction::PurgeRecycleBin(selection) => format!(
            "Permanently purge {} selected Recycle Bin item(s)",
            selection.len()
        ),
        HealthAction::DisableStartup(ids) => format!(
            "Disable {} startup item(s) (no Health Check classifier is enabled)",
            ids.len()
        ),
        HealthAction::UpdateApplications(items) => format!(
            "Update {} selected application(s) through the verified updater",
            items.len()
        ),
    }
}

fn send_health_progress(
    tx: &crate::worker_events::Sender<Event>,
    repaint: &egui::Context,
    step: HealthStep,
    completed: u64,
    total: Option<u64>,
    detail: Option<String>,
) {
    let _ = tx.send(Event::Health(HealthEvent::ScanProgress {
        step,
        completed,
        total,
        detail,
    }));
    repaint.request_repaint();
}

fn effect_receipt_summary(receipt: &HealthEffectReceipt) -> String {
    match receipt {
        HealthEffectReceipt::BrowserPrivacy(receipt) => format!(
            "Browser selections: {} of {} cleaned · {} skipped · {} error(s){}",
            receipt.deleted,
            receipt.selected,
            receipt.skipped,
            receipt.errors.len(),
            if receipt.cancelled {
                " · cancelled"
            } else {
                ""
            }
        ),
        HealthEffectReceipt::Files(receipt) => format!(
            "Files moved to Trash: {} · {} · {} failed{}",
            receipt.files,
            format_bytes(receipt.bytes),
            receipt.failed.len(),
            if receipt.cancelled {
                " · cancelled"
            } else {
                ""
            }
        ),
        HealthEffectReceipt::RecycleBin(receipt) => {
            let purged = receipt
                .receipts
                .iter()
                .filter(|item| item.state == recycle_bin::ItemOperationState::Purged)
                .count();
            let uncertain = receipt
                .receipts
                .iter()
                .filter(|item| item.state == recycle_bin::ItemOperationState::Uncertain)
                .count();
            format!(
                "Recycle Bin purge: {purged} purged · {} item result(s) · {} uncertain · {:?}",
                receipt.receipts.len(),
                uncertain,
                receipt.completion
            )
        }
        HealthEffectReceipt::Startup(receipt) => {
            format!("Startup change: {} · {:?}", receipt.id.0, receipt.outcome)
        }
        HealthEffectReceipt::Software(receipt) => format!(
            "Application update: {} to {} · {:?} verification · exit code {:?}",
            receipt.package_id,
            receipt.target_version,
            receipt.verification,
            receipt.process.exit_code
        ),
    }
}

fn run_health_effects(
    root: &std::path::Path,
    plan: &HealthActionPlan,
    cancel: &AtomicBool,
    mut progress: impl FnMut(String),
) -> HealthEffectRun {
    let mut result = HealthEffectRun {
        receipts: Vec::new(),
        issues: Vec::new(),
        attempted: false,
        uncertain: false,
        cancelled_before_any: false,
    };
    for action in plan.actions() {
        if cancel.load(Ordering::Relaxed) {
            if !result.attempted {
                result.cancelled_before_any = true;
            } else {
                result.issues.push("The action batch stopped after the active owner operation observed cancellation.".into());
            }
            break;
        }
        match action {
            HealthAction::BrowserPrivacy(privacy_plan) => {
                progress("Rechecking browser processes and verified database snapshots…".into());
                result.attempted = true;
                match privacy::clean_privacy(root, privacy_plan, cancel, |done, total| {
                    progress(format!("Removing browser records · {done} of {total}"));
                }) {
                    Ok(receipt) => {
                        result.uncertain |= receipt.uncertain;
                        result.issues.extend(receipt.errors.iter().cloned());
                        result
                            .receipts
                            .push(HealthEffectReceipt::BrowserPrivacy(receipt));
                    }
                    Err(error) => {
                        result.uncertain = true;
                        result.issues.push(format!(
                            "Browser cleanup ended without a complete receipt: {error}"
                        ));
                    }
                }
            }
            HealthAction::MoveFilesToTrash {
                analysis,
                candidate_ids,
            } => {
                let operation_id = Uuid::new_v4();
                let mut journal = match Journal::create(root, operation_id) {
                    Ok(journal) => journal,
                    Err(error) => {
                        result.issues.push(format!("File cleanup intent could not be created; no file action started: {error}"));
                        continue;
                    }
                };
                progress(format!(
                    "Moving {} selected file(s) to Trash…",
                    candidate_ids.len()
                ));
                result.attempted = true;
                let mut trash = SystemTrash;
                match cleanup::clean(
                    analysis,
                    candidate_ids,
                    cancel,
                    &mut trash,
                    &mut journal,
                    |done, total| progress(format!("Moving files to Trash · {done} of {total}")),
                ) {
                    Ok(receipt) => {
                        result.uncertain |= receipt.interrupted || !receipt.uncertain.is_empty();
                        result.receipts.push(HealthEffectReceipt::Files(receipt));
                    }
                    Err(error) => {
                        result.uncertain = true;
                        result.issues.push(format!("File cleanup stopped without a complete receipt; inspect the cleanup journal: {error}"));
                    }
                }
            }
            HealthAction::PurgeRecycleBin(selection) => {
                progress(format!(
                    "Revalidating {} selected Recycle Bin item(s)…",
                    selection.len()
                ));
                result.attempted = true;
                let mut backend = SystemRecycleBin::new();
                let receipt = recycle_bin::purge_selected(
                    root,
                    selection,
                    &mut backend,
                    cancel,
                    |done, total| {
                        progress(format!(
                            "Purging selected Recycle Bin items · {done} of {total}"
                        ))
                    },
                );
                result.uncertain |= receipt
                    .receipts
                    .iter()
                    .any(|item| item.state == recycle_bin::ItemOperationState::Uncertain);
                result
                    .issues
                    .extend(receipt.receipts.iter().filter_map(|item| {
                        item.message
                            .as_ref()
                            .map(|message| format!("Recycle Bin item {}: {message}", item.item_id))
                    }));
                result
                    .receipts
                    .push(HealthEffectReceipt::RecycleBin(receipt));
            }
            HealthAction::DisableStartup(_) => {
                result.issues.push(
                    "Startup recommendations are informational in this Health Check; the current scan has no recommendation classifier or reviewed startup action adapter.".into(),
                );
            }
            HealthAction::UpdateApplications(items) => {
                for item in items {
                    if cancel.load(Ordering::Relaxed) {
                        if !result.attempted {
                            result.cancelled_before_any = true;
                        } else {
                            result.issues.push("The update batch stopped before the next application was attempted.".into());
                        }
                        break;
                    }
                    let request = match software::prepare_update(item) {
                        Ok(request) => request,
                        Err(error) => {
                            result
                                .issues
                                .push(format!("{} was not updated: {error}", item.row.name));
                            continue;
                        }
                    };
                    let mut journal = match EffectJournal::create(
                        root,
                        "health-check",
                        request.request_id,
                        &request,
                    ) {
                        Ok(journal) => journal,
                        Err(error) => {
                            result.issues.push(format!("{} was not updated because its durable intent could not be saved: {error}", item.row.name));
                            continue;
                        }
                    };
                    progress(format!(
                        "Launching verified update for {}…",
                        request.display_name
                    ));
                    result.attempted = true;
                    match software::run_native_update(&request) {
                        Ok(receipt) => {
                            if let Err(error) = journal.finish(receipt.journal_state(), &receipt) {
                                result.uncertain = true;
                                result.issues.push(format!("{} returned an update receipt, but its final journal entry could not be saved: {error}", request.display_name));
                            }
                            result.uncertain |=
                                receipt.verification == software::UpdateVerification::Uncertain;
                            result.receipts.push(HealthEffectReceipt::Software(receipt));
                        }
                        Err(error) => {
                            result.uncertain = true;
                            let error_text = error.to_string();
                            let failure = HealthUpdateFailure {
                                request_id: request.request_id,
                                error: &error_text,
                            };
                            let journal_error = journal.finish("uncertain", &failure).err();
                            result.issues.push(format!(
                                "{} update outcome is uncertain: {}{}",
                                request.display_name,
                                error,
                                journal_error
                                    .map(|error| format!(
                                        " The failure receipt could not be saved: {error}"
                                    ))
                                    .unwrap_or_default()
                            ));
                        }
                    }
                }
            }
        }
    }
    result
}

#[cfg(debug_assertions)]
fn seed_health_fixture_step(
    coordinator: &mut health::HealthCoordinator,
    step: HealthStep,
) -> Result<(), String> {
    if step == HealthStep::Privacy {
        coordinator.inspect_privacy_browsers(Ok(Vec::new()))?;
    }
    coordinator.begin_scan(step)?;
    coordinator.complete_scan(health_fixture_report(step))?;
    if coordinator
        .current_report()
        .is_some_and(|report| report.quality == HealthScanQuality::Complete)
    {
        coordinator.select_all()?;
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn health_browser_fixture_report(case: &str) -> HealthStepReport {
    use dcleaner::{domain::Candidate, privacy::BrowserProfile};
    let base = health_fixture_report(HealthStep::Privacy);
    let HealthServiceData::Privacy {
        profiles,
        browser_records,
        browser_cache_files,
    } = base.source()
    else {
        unreachable!()
    };
    let mut profiles = profiles.clone();
    profiles.profiles = [
        (Browser::Chrome, "chrome", "Default"),
        (Browser::Chrome, "chrome", "Profile1"),
        (Browser::Firefox, "firefox", "Default"),
        (Browser::Edge, "edge", "Default"),
    ]
    .into_iter()
    .map(|(browser, key, name)| BrowserProfile {
        id: format!("visual-{key}-{name}"),
        browser,
        name: name.into(),
        root: format!(r"C:\__DCleaner_VISUAL_FIXTURE_ONLY__\{key}\{name}").into(),
    })
    .collect();
    let mut records = browser_records.clone();
    records.records.clear();
    records.profiles_scanned = profiles.profiles.len();
    let mut cache = browser_cache_files.clone();
    let template = cache.categories[0].clone();
    cache.categories = ["chrome", "firefox", "edge"]
        .into_iter()
        .map(|key| {
            let mut category = template.clone();
            category.id = key.into();
            category.name = format!("{key} cache");
            category.files.clear();
            category
        })
        .collect();
    let count = match case {
        "health-privacy-empty-browsers" => 0,
        "health-privacy-large" => 5_000,
        _ => 3,
    };
    for index in 0..count {
        let group = if count == 3 {
            usize::from(index == 2)
        } else {
            index % 3
        };
        let category = &mut cache.categories[group];
        let profile = if group == 0 && index % 2 == 1 {
            "Profile1"
        } else {
            "Default"
        };
        let root: std::path::PathBuf = format!(
            r"C:\__DCleaner_VISUAL_FIXTURE_ONLY__\{}\{profile}",
            category.id
        )
        .into();
        category.files.push(Candidate {
            id: Uuid::from_u128(0x4443_4c45_414e_4552_4845_414c_5500_0000 + index as u128),
            path: root.join(format!("synthetic-cache-{index}.bin")),
            root,
            size: if count == 3 {
                4096 << index
            } else {
                1024 * (index as u64 % 7 + 1)
            },
            modified_ns: 1,
            created_ns: Some(1),
        });
    }
    HealthStepReport::privacy(profiles, records, cache)
}

#[cfg(debug_assertions)]
fn health_fixture_report(step: HealthStep) -> HealthStepReport {
    use dcleaner::{
        domain::{Analysis, Candidate, CategoryResult, CleanupPolicy},
        privacy::PrivacyCategory,
        recycle_bin::{InventoryCompletion, RecycleBinInventory},
        startup::{InventoryQuality, SourceOutcome, SourceState, StartupInventory, StartupSection},
    };

    fn analysis(categories: &[(&str, &str, &str)]) -> Analysis {
        Analysis {
            id: Uuid::from_u128(0x4443_4c45_414e_4552_4845_414c_5448_0001),
            date: "fixture-only".into(),
            minimum_age_days: 1,
            cleanup_policy: CleanupPolicy::MinimumAge,
            elapsed_ms: 18,
            cancelled: false,
            categories: categories
                .iter()
                .enumerate()
                .map(|(index, (id, name, group))| CategoryResult {
                    id: (*id).into(),
                    name: (*name).into(),
                    group: (*group).into(),
                    files: vec![Candidate {
                        id: Uuid::from_u128(
                            0x4443_4c45_414e_4552_4845_414c_5448_0100 + index as u128,
                        ),
                        root: std::path::PathBuf::from(format!(
                            r"C:\__DCleaner_VISUAL_FIXTURE_ONLY__\{id}"
                        )),
                        path: std::path::PathBuf::from(format!(
                            r"C:\__DCleaner_VISUAL_FIXTURE_ONLY__\{id}\synthetic-cache.bin"
                        )),
                        size: 4096 * (index as u64 + 1),
                        modified_ns: 1,
                        created_ns: Some(1),
                    }],
                    skipped: 0,
                    available: true,
                    truncated: false,
                })
                .collect(),
        }
    }

    match step {
        HealthStep::Privacy => {
            let (profiles, mut records) = privacy::visual_preview_fixture();
            records.categories_scanned = vec![PrivacyCategory::Cookies, PrivacyCategory::History];
            HealthStepReport::privacy(
                profiles,
                records,
                analysis(&[("chrome", "Browser cache", "Fixture")]),
            )
        }
        HealthStep::Space => HealthStepReport::space(
            analysis(&[
                ("temp", "Temporary files", "Fixture"),
                ("crash", "Crash reports", "Fixture"),
                ("chrome", "Application cache", "Fixture"),
            ]),
            RecycleBinInventory {
                id: Uuid::from_u128(0x4443_4c45_414e_4552_4845_414c_5448_0003),
                completion: InventoryCompletion::Complete,
                items: Vec::new(),
                issues: Vec::new(),
                known_file_bytes: 0,
            },
        ),
        HealthStep::ResolveIssues => HealthStepReport::resolve_issues(
            StartupInventory {
                section: StartupSection::StartupApps,
                quality: InventoryQuality::Complete,
                entries: Vec::new(),
                sources: vec![SourceOutcome {
                    source: "Synthetic in-memory fixture".into(),
                    state: SourceState::Read { items: 0 },
                }],
            },
            Err("Synthetic fixture: installed-application inventory is unavailable.".into()),
        ),
    }
}
