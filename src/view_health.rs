use super::{App, Event};
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
        mpsc,
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
    process_error: Option<String>,
    browser_review_open: bool,
    selected_processes: HashSet<(Browser, u32)>,
    cookie_settings: CookieExceptionSettings,
    cookie_settings_readable: bool,
    cookie_settings_error: Option<String>,
    cookie_domain_input: String,
    clear_cookie_input_on_save: bool,
    cookie_settings_stale: bool,
    partial_acknowledged: bool,
    permanent_acknowledged: bool,
    search: String,
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
            process_error: None,
            browser_review_open: false,
            selected_processes: HashSet::new(),
            cookie_settings: CookieExceptionSettings::default(),
            cookie_settings_readable: false,
            cookie_settings_error: None,
            cookie_domain_input: String::new(),
            clear_cookie_input_on_save: false,
            cookie_settings_stale: false,
            partial_acknowledged: false,
            permanent_acknowledged: false,
            search: String::new(),
            detail_id: None,
            action_plan: None,
        }
    }
}

pub(super) enum HealthEvent {
    Prerequisites {
        running: Result<Vec<RunningBrowser>, String>,
        cookie_settings: Result<CookieExceptionSettings, String>,
    },
    RunningBrowsers(Result<Vec<RunningBrowser>, String>),
    BrowserClose {
        report: CloseRequestReport,
        remaining: Result<Vec<RunningBrowser>, String>,
    },
    CookieSettingsSaved(Result<CookieExceptionSettings, String>),
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
        if matches!(case, "health-welcome" | "health-intro") {
            return Ok(());
        }
        self.health_ui.started = true;
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

        let target = match case {
            "health-privacy" => Some(HealthStep::Privacy),
            "health-space" => Some(HealthStep::Space),
            "health-issues" => Some(HealthStep::ResolveIssues),
            "health-summary" => None,
            _ => return Err(format!("Unsupported Health visual fixture: {case}")),
        };
        let coordinator = &mut self.health_ui.coordinator;
        for step in HealthStep::ORDER {
            if target.is_some_and(|target| step == target) {
                seed_health_fixture_step(coordinator, step)?;
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
        self.health_stepper(ui, t);
        ui.add_space(10.);

        let Some(step) = self.health_ui.coordinator.current_step() else {
            self.health_final_summary(ui, t);
            return;
        };
        self.health_step_page(ui, t, ctx, step);
    }

    pub(super) fn health_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if !self.feature_seen("health") {
            if !self.feature_intro_wide(ctx) {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if theme::primary(ui, "Scan now", t, !self.busy()) {
                        self.mark_feature_seen("health");
                        self.health_ui.started = true;
                        self.begin_health_prerequisites(ctx);
                    }
                });
            } else {
                theme::muted(
                    ui,
                    "Start a read-only review of current system findings.",
                    t,
                );
            }
            return;
        }
        if !self.health_ui.started {
            let busy = self.busy();
            theme::action_row(ui, |ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let status_width = (ui.available_width() - 185.).max(80.);
                    let start = theme::primary(ui, "Start Health Check", t, !busy);
                    ui.add_space(8.);
                    ui.add_sized(
                        [status_width, theme::CONTROL_HEIGHT],
                        egui::Label::new(
                            RichText::new("Start a read-only review of current system findings.")
                                .color(t.muted),
                        )
                        .truncate(),
                    );
                    if start {
                        self.health_ui.started = true;
                        self.begin_health_prerequisites(ctx);
                    }
                });
            });
            return;
        }
        let Some(step) = self.health_ui.coordinator.current_step() else {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if theme::primary(ui, "Restart Health Check", t, !self.busy()) {
                    self.health_ui = HealthUi::default();
                    self.error = None;
                    self.notice = None;
                }
            });
            return;
        };

        let status = self.health_ui.coordinator.status(step).clone();
        let busy = self.busy();
        ui.horizontal(|ui| match status {
            HealthStepStatus::Scanning { .. } => {
                theme::muted(ui, self.progress.clone(), t);
                ui.add_space(8.);
                if theme::secondary(ui, "Stop scan", busy) {
                    self.request_health_cancel(step);
                }
            }
            HealthStepStatus::Applying { .. } => {
                theme::muted(ui, self.progress.clone(), t);
                ui.add_space(8.);
                if theme::secondary(ui, "Stop after this action", busy) {
                    self.cancel.store(true, Ordering::Relaxed);
                }
            }
            _ => {
                let selected = self.health_ui.coordinator.selected_ids(step).len();
                theme::muted(
                    ui,
                    format!(
                        "{} · {selected} actionable findings selected",
                        step_label(step)
                    ),
                    t,
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    match status {
                        HealthStepStatus::Scanning { .. } | HealthStepStatus::Applying { .. } => {
                            theme::muted(ui, self.progress.clone(), t);
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
                        }
                        HealthStepStatus::Ready => {
                            if theme::primary(
                                ui,
                                "Scan this step",
                                t,
                                !busy
                                    && self.health_ui.initialized
                                    && (step != HealthStep::Privacy
                                        || self.health_ui.cookie_settings_readable)
                                    && self.data_dir.is_absolute(),
                            ) {
                                self.begin_health_scan(step, ctx);
                            }
                        }
                        HealthStepStatus::Reviewing { .. } => {
                            let report = self.health_ui.coordinator.report(step);
                            let partial =
                                report.is_some_and(|r| r.quality == HealthScanQuality::Partial);
                            if theme::secondary(ui, "Scan again", !busy) {
                                self.begin_health_scan(step, ctx);
                            }
                            if theme::primary(
                                ui,
                                "Review selected",
                                t,
                                !busy
                                    && selected > 0
                                    && self.history_readable
                                    && self.data_dir.is_absolute()
                                    && !self.health_ui.cookie_settings_stale
                                    && (!partial || self.health_ui.partial_acknowledged),
                            ) {
                                self.begin_health_action_review();
                            }
                        }
                        HealthStepStatus::ActionReview { .. } => {
                            theme::muted(ui, "Review the exact action list in the open dialog.", t);
                        }
                        HealthStepStatus::Results { .. }
                        | HealthStepStatus::Skipped
                        | HealthStepStatus::Cancelled
                        | HealthStepStatus::Failed { .. } => {
                            if theme::secondary(ui, "Scan again", !busy) {
                                self.begin_health_scan(step, ctx);
                            }
                            if theme::primary(ui, "Continue", t, !busy) {
                                self.advance_health_step();
                            }
                        }
                    }
                    if can_skip(&status) && theme::secondary(ui, "Skip step", !busy) {
                        self.skip_health_step();
                    }
                });
            }
        });
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
                cookie_settings,
            } => {
                self.worker = None;
                self.health_ui.initializing = false;
                self.health_ui.initialized = true;
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
                    self.notice =
                        Some("Selected browsers received a graceful close request.".into());
                } else {
                    self.notice = Some(format!(
                        "{} selected browser process(es) remain open or changed; refresh and review them before scanning.",
                        report.still_running.len()
                            + report.stale_selection.len()
                            + report.errors.len()
                    ));
                }
                self.health_ui.selected_processes.clear();
            }
            HealthEvent::CookieSettingsSaved(result) => {
                self.worker = None;
                match result {
                    Ok(settings) => {
                        if self.health_ui.clear_cookie_input_on_save {
                            self.health_ui.cookie_domain_input.clear();
                        }
                        self.health_ui.clear_cookie_input_on_save = false;
                        let changed = settings != self.health_ui.cookie_settings;
                        self.sync_cookie_settings_owners(settings);
                        self.notice = Some(
                            if changed
                                && self
                                    .health_ui
                                    .coordinator
                                    .report(HealthStep::Privacy)
                                    .is_some()
                            {
                                "Cookie rules changed. Rescan Privacy before reviewing its earlier rows.".into()
                            } else {
                                "Cookie keep-domain rules were saved.".into()
                            },
                        );
                    }
                    Err(error) => {
                        self.health_ui.clear_cookie_input_on_save = false;
                        self.mark_cookie_settings_unverified();
                        self.health_ui.cookie_settings_error = Some(format!(
                            "Cookie-save outcome is uncertain: {error}. Reload saved rules before scanning or cleanup."
                        ));
                    }
                }
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
                match self.health_ui.coordinator.complete_scan(report) {
                    Ok(()) => {
                        self.health_ui.partial_acknowledged = false;
                        self.health_ui.cookie_settings_stale = false;
                        self.health_ui.search.clear();
                        self.health_ui.detail_id = None;
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
                } else if !issues.is_empty() {
                    self.notice = Some(issues.join(" "));
                } else {
                    self.notice =
                        Some("Reviewed Health Check actions finished with owner receipts.".into());
                }
                match store::history(&self.data_dir) {
                    Ok(history) => {
                        self.history = history;
                        self.history_readable = true;
                    }
                    Err(error) => {
                        self.error =
                            Some(format!("Cleanup history could not be refreshed: {error}"));
                        self.history_readable = false;
                    }
                }
            }
        }
    }

    pub(super) fn health_started(&self) -> bool {
        self.health_ui.started
    }

    fn update_health_browser_state(&mut self, running: Result<Vec<RunningBrowser>, String>) {
        let coordinator_input = running.clone();
        match running {
            Ok(processes) => {
                self.health_ui.running = processes.clone();
                self.health_ui.process_error = None;
                if !processes.is_empty() {
                    self.health_ui.browser_review_open = true;
                }
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
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let running = privacy::running_browsers();
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
        let (tx, rx) = mpsc::channel();
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
        let (tx, rx) = mpsc::channel();
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
        let (tx, rx) = mpsc::channel();
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

    fn begin_health_cookie_save(
        &mut self,
        domains: Vec<String>,
        ctx: &egui::Context,
        clear_input_on_success: bool,
    ) {
        if self.qa_fixture_mode() || self.busy() {
            return;
        }
        if !self.health_ui.cookie_settings_readable {
            self.health_ui.cookie_settings_error =
                Some("Reload saved cookie rules before changing them.".into());
            return;
        }
        if self.data_dir.as_os_str().is_empty() {
            self.health_ui.cookie_settings_error = Some(
                "Application data storage is unavailable; cookie rules were not saved.".into(),
            );
            return;
        }
        let root = self.data_dir.clone();
        self.health_ui.clear_cookie_input_on_save = clear_input_on_success;
        let repaint = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        self.progress = "Saving cookie keep-domain rules…".into();
        thread::spawn(move || {
            let result = privacy::save_cookie_exception_settings(&root, &domains);
            let _ = tx.send(Event::Health(HealthEvent::CookieSettingsSaved(result)));
            repaint.request_repaint();
        });
    }

    fn begin_health_action_review(&mut self) {
        if self.qa_fixture_mode()
            || !self.health_ui.cookie_settings_readable
            || self.health_ui.cookie_settings_stale
        {
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
            || !self.health_ui.cookie_settings_readable
            || self.health_ui.cookie_settings_stale
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
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let run = run_health_effects(&root, &plan, &cancel, |message| {
                let _ = tx.send(Event::Health(HealthEvent::EffectProgress(message)));
                repaint.request_repaint();
            });
            let _ = tx.send(Event::Health(HealthEvent::EffectsFinished {
                plan_id,
                receipts: run.receipts,
                issues: run.issues,
                attempted: run.attempted,
                uncertain: run.uncertain,
                cancelled_before_any: run.cancelled_before_any,
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
                self.health_ui.search.clear();
                self.health_ui.detail_id = None;
                self.health_ui.cookie_settings_stale = false;
                if step == HealthStep::Privacy {
                    self.begin_health_prerequisites_if_needed();
                }
            }
            Ok(None) => self.notice = Some("Health Check reached its final summary.".into()),
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

    fn health_stepper(&self, ui: &mut egui::Ui, t: Tokens) {
        ui.horizontal_wrapped(|ui| {
            for (index, step) in HealthStep::ORDER.into_iter().enumerate() {
                let active = self.health_ui.coordinator.current_step() == Some(step);
                let status = self.health_ui.coordinator.status(step);
                let label = format!("{}  {}", index + 1, step_label(step));
                if active {
                    ui.label(
                        RichText::new(label)
                            .family(theme::semibold())
                            .color(t.foreground),
                    );
                } else {
                    theme::muted(ui, format!("{label}  ·  {}", status_label(status)), t);
                }
                if index + 1 < HealthStep::ORDER.len() {
                    theme::muted(ui, "›", t);
                }
            }
        });
    }

    fn health_step_page(
        &mut self,
        ui: &mut egui::Ui,
        t: Tokens,
        ctx: &egui::Context,
        step: HealthStep,
    ) {
        let status = self.health_ui.coordinator.status(step).clone();
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new(step_title(step)).family(theme::semibold()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    theme::muted(ui, status_label(&status), t);
                });
            });
            ui.add_space(5.);
            theme::muted(ui, step_description(step), t);
            if self.health_ui.initializing {
                ui.add_space(10.);
                ui.horizontal(|ui| {
                    ui.spinner();
                    theme::muted(ui, "Checking browser state and saved privacy rules…", t);
                });
            }
            if let HealthStepStatus::Failed { message } = &status {
                ui.add_space(8.);
                ui.colored_label(t.attention, message);
            }
        });

        if step == HealthStep::Privacy {
            ui.add_space(8.);
            self.health_browser_gate_panel(ui, t);
            ui.add_space(8.);
            self.health_cookie_settings(ui, t, ctx);
        }
        if let Some(report) = self.health_ui.coordinator.report(step).cloned() {
            ui.add_space(8.);
            self.health_results_card(ui, t, step, &report);
        } else if matches!(status, HealthStepStatus::Ready) {
            ui.add_space(8.);
            theme::card(t).show(ui, |ui| {
                ui.set_width(ui.available_width());
                theme::muted(
                    ui,
                    "This step has not been scanned. The scan button reads current system inventory and does not make changes.",
                    t,
                );
            });
        }
        if matches!(status, HealthStepStatus::Results { .. }) {
            ui.add_space(8.);
            self.health_effect_result(ui, t, step);
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

    fn health_cookie_settings(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let busy = self.busy();
        let editable = !busy
            && self.health_ui.cookie_settings_readable
            && self.data_dir.is_absolute()
            && !matches!(
                self.health_ui.coordinator.status(HealthStep::Privacy),
                HealthStepStatus::Scanning { .. }
                    | HealthStepStatus::ActionReview { .. }
                    | HealthStepStatus::Applying { .. }
            );
        let mut add_domain = false;
        let mut remove_index = None;
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Cookie keep domains").family(theme::semibold()));
                theme::muted(ui, "Matching cookies are omitted from scan results", t);
            });
            ui.add_space(5.);
            theme::control_row(ui, |ui| {
                theme::input(
                    ui,
                    &mut self.health_ui.cookie_domain_input,
                    230.,
                    "example.com",
                    editable,
                );
                add_domain = theme::field_action(ui, "Add domain", editable);
                if !self.health_ui.cookie_settings_readable {
                    theme::muted(ui, "Rules unavailable; scanning is blocked", t);
                }
            });
            if let Some(error) = &self.health_ui.cookie_settings_error {
                ui.colored_label(t.attention, error);
            }
            if self.health_ui.cookie_settings_stale {
                ui.colored_label(
                    t.attention,
                    "Rules changed after this scan. Rescan Privacy before reviewing these earlier rows.",
                );
            }
            if self.health_ui.cookie_settings.keep_domains.is_empty() {
                theme::muted(ui, "No keep domains saved.", t);
            } else {
                for (index, domain) in self
                    .health_ui
                    .cookie_settings
                    .keep_domains
                    .iter()
                    .enumerate()
                {
                    ui.horizontal(|ui| {
                        theme::muted(ui, domain, t);
                        if theme::row_action(ui, "Remove", editable).clicked() {
                            remove_index = Some(index);
                        }
                    });
                }
            }
        });

        if add_domain {
            match privacy::normalize_cookie_domain(&self.health_ui.cookie_domain_input) {
                Ok(domain) => {
                    let mut domains = self.health_ui.cookie_settings.keep_domains.clone();
                    if !domains.contains(&domain) {
                        domains.push(domain);
                        self.begin_health_cookie_save(domains, ctx, true);
                    } else {
                        self.health_ui.cookie_domain_input.clear();
                    }
                }
                Err(error) => self.health_ui.cookie_settings_error = Some(error),
            }
        }
        if let Some(index) = remove_index {
            let mut domains = self.health_ui.cookie_settings.keep_domains.clone();
            if index < domains.len() {
                domains.remove(index);
                self.begin_health_cookie_save(domains, ctx, false);
            }
        }
    }

    fn health_results_card(
        &mut self,
        ui: &mut egui::Ui,
        t: Tokens,
        step: HealthStep,
        report: &HealthStepReport,
    ) {
        let status = self.health_ui.coordinator.status(step).clone();
        let reviewing = matches!(status, HealthStepStatus::Reviewing { .. });
        let busy = self.busy();
        let selection_enabled = reviewing
            && !busy
            && !self.health_ui.cookie_settings_stale
            && report.quality != HealthScanQuality::Cancelled
            && report.quality != HealthScanQuality::Failed;
        let selected = self
            .health_ui
            .coordinator
            .selected_ids(step)
            .into_iter()
            .collect::<HashSet<_>>();
        let categories = report.categories.clone();
        let notes = report.notes.clone();
        let quality = report.quality;
        let query = self.health_ui.search.trim().to_ascii_lowercase();
        let mut select_all = false;
        let mut clear_selection = false;
        let mut select_visible = Vec::new();
        let mut deselect_visible = Vec::new();

        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Scan results").family(theme::semibold()));
                theme::muted(ui, quality_label(quality), t);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    theme::muted(
                        ui,
                        format!(
                            "{} categories · {} listed rows",
                            categories.len(),
                            categories.iter().map(|category| category.findings.len()).sum::<usize>()
                        ),
                        t,
                    );
                });
            });
            for note in &notes {
                ui.add(egui::Label::new(RichText::new(note).color(t.muted)).wrap());
            }
            if quality == HealthScanQuality::Partial {
                ui.add_space(6.);
                ui.colored_label(
                    t.attention,
                    "Some sources or records were incomplete. Review the gaps before applying selected actions.",
                );
                let changed = theme::checkbox(
                    ui,
                    &mut self.health_ui.partial_acknowledged,
                    "I reviewed the partial-scan warning",
                    selection_enabled,
                )
                .changed();
                if changed && !self.health_ui.partial_acknowledged {
                    let _ = self.health_ui.coordinator.deselect_all();
                }
            } else if quality == HealthScanQuality::Cancelled {
                ui.add_space(6.);
                ui.colored_label(
                    t.attention,
                    "Cancelled scan results are view-only. Run the step again to create a reviewable snapshot.",
                );
            }
            if self.health_ui.cookie_settings_stale && step == HealthStep::Privacy {
                ui.add_space(6.);
                ui.colored_label(
                    t.attention,
                    "Cookie keep rules changed after this scan. Earlier rows cannot be selected until Privacy is rescanned.",
                );
            }

            ui.add_space(8.);
            theme::control_row(ui, |ui| {
                let search_width = (ui.available_width() - 250.).clamp(170., 360.);
                theme::input(
                    ui,
                    &mut self.health_ui.search,
                    search_width,
                    "Search current results",
                    !busy,
                );
                select_all = theme::field_action(ui, "Select all actionable", selection_enabled);
                clear_selection = theme::field_action(ui, "Clear selection", !busy && reviewing);
                theme::muted(ui, format!("{} selected", selected.len()), t);
            });

            if categories.is_empty() {
                ui.add_space(10.);
                theme::muted(ui, "This scan returned no category results.", t);
            }

            for category in &categories {
                ui.add_space(8.);
                let actionable_ids = category
                    .findings
                    .iter()
                    .filter(|finding| finding.actionable)
                    .map(|finding| finding.id.clone())
                    .collect::<Vec<_>>();
                let actionable_selected = actionable_ids
                    .iter()
                    .filter(|id| selected.contains(*id))
                    .count();
                let mut category_selected = !actionable_ids.is_empty()
                    && actionable_selected == actionable_ids.len();
                let mut category_checkbox_changed = false;
                theme::card(t).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        category_checkbox_changed = theme::checkbox_widget(
                            ui,
                            egui::Checkbox::without_text(&mut category_selected),
                            selection_enabled && !actionable_ids.is_empty(),
                        )
                        .changed();
                        ui.label(
                            RichText::new(category_label(category.category))
                                .family(theme::semibold()),
                        );
                        theme::muted(ui, coverage_label(&category.coverage), t);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            theme::muted(ui, category_summary(category), t);
                        });
                    });
                    if let Some(reason) = coverage_reason(&category.coverage) {
                        ui.add(egui::Label::new(RichText::new(reason).color(t.muted)).wrap());
                    }
                    if category.findings.is_empty() {
                        ui.add_space(5.);
                        theme::muted(ui, "No rows were returned for this category.", t);
                        return;
                    }
                    let rows = category
                        .findings
                        .iter()
                        .filter(|finding| finding_matches(finding, &query))
                        .collect::<Vec<_>>();
                    let visible_actionable = rows
                        .iter()
                        .filter(|finding| finding.actionable)
                        .map(|finding| finding.id.clone())
                        .collect::<Vec<_>>();
                    if !query.is_empty() {
                        ui.add_space(4.);
                        theme::muted(ui, format!("{} matching row(s)", rows.len()), t);
                    }
                    let available = ui.available_width().max(520.);
                    let name_width = (available * 0.34).clamp(150., 280.);
                    let detail_width = (available - name_width - 150.).max(170.);
                    ui.add_space(5.);
                    ui.horizontal(|ui| {
                        theme::table_cell(ui, "Finding", name_width, 25.);
                        theme::table_cell(ui, "Details", detail_width, 25.);
                        theme::table_cell(ui, "Size", 76., 25.);
                        theme::table_cell(ui, "", 70., 25.);
                    });
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .id_salt(("health-category-rows", step as u8, category.category as u8))
                        .max_height(260.)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for finding in rows {
                                ui.set_min_width(available);
                                ui.horizontal(|ui| {
                                    let mut row_selected = selected.contains(&finding.id);
                                    let response = theme::checkbox_widget(
                                        ui,
                                        egui::Checkbox::without_text(&mut row_selected),
                                        selection_enabled && finding.actionable,
                                    );
                                    if response.changed() {
                                        if row_selected {
                                            select_visible.push(finding.id.clone());
                                        } else {
                                            deselect_visible.push(finding.id.clone());
                                        }
                                    }
                                    ui.add_sized(
                                        [name_width - 24., 32.],
                                        egui::Label::new(finding.name.clone()).truncate(),
                                    );
                                    let detail = finding.detail.as_deref().unwrap_or_else(|| {
                                        if finding.actionable {
                                            "Ready for reviewed action"
                                        } else {
                                            "Review only"
                                        }
                                    });
                                    ui.add_sized(
                                        [detail_width, 32.],
                                        egui::Label::new(RichText::new(detail).color(t.muted))
                                            .truncate(),
                                    );
                                    ui.add_sized(
                                        [76., 32.],
                                        egui::Label::new(
                                            finding
                                                .size_bytes
                                                .map(format_bytes)
                                                .unwrap_or_else(|| "—".into()),
                                        ),
                                    );
                                    if theme::row_action(ui, "Details", true).clicked() {
                                        self.health_ui.detail_id = Some(finding.id.clone());
                                    }
                                });
                            }
                        });
                    if category_checkbox_changed {
                        if category_selected {
                            select_visible.extend(actionable_ids.clone());
                        } else {
                            deselect_visible.extend(actionable_ids.clone());
                        }
                    }
                    if selection_enabled && !visible_actionable.is_empty() {
                        let all_selected = visible_actionable.iter().all(|id| selected.contains(id));
                        if theme::field_action(
                            ui,
                            if all_selected { "Clear visible" } else { "Select visible" },
                            !busy,
                        ) {
                            if all_selected {
                                deselect_visible.extend(visible_actionable);
                            } else {
                                select_visible.extend(visible_actionable);
                            }
                        }
                    }
                });
            }
        });

        if select_all {
            if let Err(error) = self.health_ui.coordinator.select_all() {
                self.error = Some(error);
            }
        }
        if clear_selection {
            if let Err(error) = self.health_ui.coordinator.deselect_all() {
                self.error = Some(error);
            }
        }
        for id in deselect_visible {
            if let Err(error) = self.health_ui.coordinator.select_finding(id, false) {
                self.error = Some(error);
                break;
            }
        }
        for id in select_visible {
            if let Err(error) = self.health_ui.coordinator.select_finding(id, true) {
                self.error = Some(error);
                break;
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
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Action outcome").family(theme::semibold()));
                theme::muted(ui, effect_quality_label(quality), t);
            });
            if let Some(message) = &message {
                ui.add_space(5.);
                ui.add(egui::Label::new(RichText::new(message).color(t.attention)).wrap());
            }
            for receipt in &receipts {
                ui.add_space(4.);
                theme::muted(ui, effect_receipt_summary(receipt), t);
            }
            if quality == HealthEffectQuality::Uncertain {
                ui.add_space(7.);
                ui.colored_label(
                    t.attention,
                    "At least one owner operation has an uncertain outcome. Review its recovery history before retrying.",
                );
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
        if !busy && ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.health_ui.browser_review_open = false;
            return;
        }
        let t = theme::tokens(self.prefs.dark);
        let running = self.health_ui.running.clone();
        let unavailable = self.health_ui.process_error.clone();
        let mut refresh = false;
        let mut accept = false;
        let mut close_selected = false;
        let mut close = false;
        let mut selected_count = 0usize;
        let width = (ctx.content_rect().width() - 32.).clamp(300., 620.);
        let body_height = (ctx.content_rect().height() - 210.).max(120.);
        let response = egui::Modal::new(egui::Id::new("health-browser-gate"))
            .frame(theme::dialog_frame(t))
            .show(ctx, |ui| {
                ui.set_width(width);
                ui.set_max_width(width);
                theme::action_row(ui, |ui| {
                    ui.heading("Review running browsers");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        refresh = theme::secondary(ui, "Refresh status", !busy);
                    });
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .max_height(body_height)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                    theme::muted(
                        ui,
                        "This check scans browser history and cookies. You can continue with browsers open; cleanup will perform its own fresh conflict check.",
                        t,
                    );
                    if let Some(error) = &unavailable {
                        ui.add_space(7.);
                        ui.colored_label(t.attention, format!("Process status unavailable: {error}"));
                    }
                    if running.is_empty() {
                        ui.add_space(8.);
                        theme::muted(ui, "No supported browser process is listed.", t);
                    } else {
                        ui.add_space(8.);
                        for process in &running {
                            let key = (process.browser, process.pid);
                            let mut selected = self.health_ui.selected_processes.contains(&key);
                            theme::action_row(ui, |ui| {
                                if theme::checkbox_widget(
                                    ui,
                                    egui::Checkbox::without_text(&mut selected),
                                    !busy,
                                )
                                .changed()
                                {
                                    if selected {
                                        self.health_ui.selected_processes.insert(key);
                                    } else {
                                        self.health_ui.selected_processes.remove(&key);
                                    }
                                }
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(process.browser.label())
                                            .family(theme::semibold()),
                                    );
                                    theme::muted(
                                        ui,
                                        format!("PID {} · {}", process.pid, process.executable),
                                        t,
                                    );
                                });
                            });
                            if self.health_ui.selected_processes.contains(&key) {
                                selected_count += 1;
                            }
                        }
                    }
                    ui.add_space(8.);
                    theme::muted(
                        ui,
                        "A close request is graceful and applies only to the exact selected process IDs. The app never force-terminates browsers.",
                        t,
                    );
                    if busy {
                        ui.add_space(8.);
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
                        close = theme::secondary(ui, "Close", !busy);
                        close_selected = theme::secondary(
                            ui,
                            "Request graceful close",
                            !busy && selected_count > 0,
                        );
                        accept = theme::primary(
                            ui,
                            "Continue to read-only scan",
                            t,
                            !busy && unavailable.is_none(),
                        );
                    });
                });
            });
        if refresh {
            self.begin_health_browser_refresh(ctx);
        } else if close_selected {
            self.begin_health_browser_close(ctx);
        } else if accept {
            match self.health_ui.coordinator.accept_browser_review() {
                Ok(()) => {
                    self.health_ui.browser_review_open = false;
                    self.health_ui.selected_processes.clear();
                }
                Err(error) => self.error = Some(error),
            }
        } else if (close || response.should_close()) && !busy {
            self.health_ui.browser_review_open = false;
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
                ui.heading("Review exact Health Check actions");
                ui.separator();
                egui::ScrollArea::vertical()
                    .max_height(body_height)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                    ui.add_space(7.);
                    ui.label(format!(
                        "{} selected finding(s) from {}",
                        selected_count,
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
                    for (id, finding) in selected_rows.iter().take(16) {
                        ui.add(
                            egui::Label::new(format!(
                                "{} · {} · {}",
                                category_label(finding.category),
                                finding.name,
                                finding_id_label(id)
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
                        close = theme::secondary(ui, "Back to findings", !busy);
                        confirm = theme::primary(
                            ui,
                            "Confirm reviewed actions",
                            t,
                            !busy
                                && self.history_readable
                                && self.data_dir.is_absolute()
                                && self.health_ui.cookie_settings_readable
                                && !self.health_ui.cookie_settings_stale
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
                ui.heading("Health Check finding details");
                ui.separator();
                egui::ScrollArea::vertical()
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
                        detail_row(ui, "Current finding ID", &finding_id_label(&finding.id), t);
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
                                "This row can be included in an exact owner-service review plan."
                            } else {
                                "This row is informational. The current Health Check has no supported action for it."
                            },
                            t,
                        );
                    } else {
                        ui.colored_label(
                            t.attention,
                            "This ID is no longer in the current report. Rescan before reviewing it.",
                        );
                    }
                });
                ui.add_space(6.);
                ui.separator();
                theme::action_row(ui, |ui| {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        close = theme::secondary(ui, "Close details", true);
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

fn category_label(category: HealthCategory) -> &'static str {
    match category {
        HealthCategory::InternetTemporaryFiles => "Internet temporary files",
        HealthCategory::Cookies => "Cookies",
        HealthCategory::BrowsingHistory => "Browsing history",
        HealthCategory::RecycleBin => "Recycle Bin",
        HealthCategory::TemporarySystemFiles => "Temporary system files",
        HealthCategory::ApplicationCache => "Application cache",
        HealthCategory::StartupAppsForReview => "Startup apps for review",
        HealthCategory::OutdatedApplications => "Outdated applications",
        HealthCategory::DriverUpdates => "Driver updates",
        HealthCategory::BackgroundApps => "Background apps",
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

fn step_label(step: HealthStep) -> &'static str {
    match step {
        HealthStep::Privacy => "Privacy",
        HealthStep::Space => "More space",
        HealthStep::ResolveIssues => "Resolve issues",
    }
}

fn step_title(step: HealthStep) -> &'static str {
    match step {
        HealthStep::Privacy => "Privacy",
        HealthStep::Space => "More space",
        HealthStep::ResolveIssues => "Resolve issues",
    }
}

fn step_description(step: HealthStep) -> &'static str {
    match step {
        HealthStep::Privacy => {
            "Review supported browser records and browser cache files. Passwords and browser settings are not included."
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

fn can_skip(status: &HealthStepStatus) -> bool {
    !matches!(
        status,
        HealthStepStatus::Scanning { .. } | HealthStepStatus::Applying { .. }
    )
}

fn finding_matches(finding: &HealthFinding, query: &str) -> bool {
    query.is_empty()
        || finding.name.to_ascii_lowercase().contains(query)
        || finding
            .detail
            .as_deref()
            .is_some_and(|detail| detail.to_ascii_lowercase().contains(query))
        || finding_id_label(&finding.id)
            .to_ascii_lowercase()
            .contains(query)
}

fn finding_id_label(id: &HealthFindingId) -> String {
    match id {
        HealthFindingId::BrowserRecord(id)
        | HealthFindingId::FileCandidate(id)
        | HealthFindingId::RecycleBinItem(id) => id.to_string(),
        HealthFindingId::StartupEntry(id) => id.0.clone(),
        HealthFindingId::SoftwareUpdate(key) => key.as_str().to_owned(),
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
        HealthAction::BrowserPrivacy(_) => {
            "Browser privacy: revalidate and remove selected database records".into()
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
    tx: &mpsc::Sender<Event>,
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
            "Browser records: {} of {} removed · {} skipped · {} error(s){}",
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
    coordinator.complete_scan(health_fixture_report(step))
}

#[cfg(debug_assertions)]
fn health_fixture_report(step: HealthStep) -> HealthStepReport {
    use dcleaner::{
        domain::{Analysis, CategoryResult, CleanupPolicy},
        privacy::{PrivacyCategory, PrivacyReport, ProfileInventory},
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
                .map(|(id, name, group)| CategoryResult {
                    id: (*id).into(),
                    name: (*name).into(),
                    group: (*group).into(),
                    files: Vec::new(),
                    skipped: 0,
                    available: true,
                    truncated: false,
                })
                .collect(),
        }
    }

    match step {
        HealthStep::Privacy => HealthStepReport::privacy(
            ProfileInventory::default(),
            PrivacyReport {
                id: Uuid::from_u128(0x4443_4c45_414e_4552_4845_414c_5448_0002),
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
                elapsed_ms: 18,
            },
            analysis(&[("chrome", "Browser cache", "Fixture")]),
        ),
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
