use super::{App, Event};
use crate::theme::{self, Tokens};
use dcleaner::{
    privacy::{
        self, Browser, BrowserProfile, CloseRequestReport, CookieExceptionSettings,
        PrivacyCategory, PrivacyProgress, PrivacyRecord, PrivacyRecoveryState, PrivacyReport,
        PrivacyRestoreOption, PrivacyRestorePlan, PrivacyRestoreReceipt, ProfileInventory,
        RunningBrowser,
    },
    store,
};
use eframe::egui::{self, Align, Layout, RichText, Vec2};
use std::{
    collections::HashSet,
    sync::{Arc, mpsc},
    thread,
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum PrivacyOperation {
    #[default]
    Idle,
    Loading,
    Scanning,
    ClosingBrowsers,
    SavingSettings,
    Cleaning,
    PreparingRestore,
    Restoring,
}

pub(super) struct PrivacyUi {
    loaded: bool,
    inventory_partial: bool,
    inventory_skips: Vec<String>,
    profiles: Vec<BrowserProfile>,
    selected_profiles: HashSet<String>,
    running: Vec<RunningBrowser>,
    process_error: Option<String>,
    categories: HashSet<PrivacyCategory>,
    cookie_settings: CookieExceptionSettings,
    cookie_settings_readable: bool,
    cookie_settings_error: Option<String>,
    cookie_domain_input: String,
    report: Option<PrivacyReport>,
    selected_ids: HashSet<Uuid>,
    search: String,
    detail_id: Option<Uuid>,
    cleanup_review: bool,
    close_review: bool,
    selected_processes: HashSet<(Browser, u32)>,
    close_report: Option<CloseRequestReport>,
    restore_options: Vec<PrivacyRestoreOption>,
    restore_error: Option<String>,
    restore_plan: Option<PrivacyRestorePlan>,
    restore_review: bool,
    operation: PrivacyOperation,
}

impl Default for PrivacyUi {
    fn default() -> Self {
        Self {
            loaded: false,
            inventory_partial: false,
            inventory_skips: Vec::new(),
            profiles: Vec::new(),
            selected_profiles: HashSet::new(),
            running: Vec::new(),
            process_error: None,
            categories: [
                PrivacyCategory::History,
                PrivacyCategory::Cookies,
                PrivacyCategory::Downloads,
            ]
            .into_iter()
            .collect(),
            cookie_settings: CookieExceptionSettings::default(),
            cookie_settings_readable: false,
            cookie_settings_error: None,
            cookie_domain_input: String::new(),
            report: None,
            selected_ids: HashSet::new(),
            search: String::new(),
            detail_id: None,
            cleanup_review: false,
            close_review: false,
            selected_processes: HashSet::new(),
            close_report: None,
            restore_options: Vec::new(),
            restore_error: None,
            restore_plan: None,
            restore_review: false,
            operation: PrivacyOperation::Idle,
        }
    }
}

pub(super) enum PrivacyEvent {
    InventoryLoaded {
        inventory: ProfileInventory,
        running: Result<Vec<RunningBrowser>, String>,
        settings: Result<CookieExceptionSettings, String>,
        restores: Result<Vec<PrivacyRestoreOption>, String>,
    },
    RunningUpdated(Result<Vec<RunningBrowser>, String>),
    Progress(PrivacyProgress),
    Scanned(PrivacyReport),
    CloseRequested {
        report: CloseRequestReport,
        remaining: Result<Vec<RunningBrowser>, String>,
    },
    SettingsSaved(Result<CookieExceptionSettings, String>),
    CleanupProgress {
        done: usize,
        total: usize,
    },
    Cleaned(Result<privacy::PrivacyReceipt, String>),
    RestorePrepared {
        id: Uuid,
        result: Result<PrivacyRestorePlan, String>,
    },
    Restored(Result<PrivacyRestoreReceipt, String>),
}

impl App {
    pub(super) fn privacy_overview_status(&self) -> String {
        match self.privacy_ui.report.as_ref() {
            Some(report) if !report.cancelled => {
                let partial = if report.partial { " · partial" } else { "" };
                format!("{} records{partial}", report.records.len())
            }
            _ => "Not scanned".into(),
        }
    }

    pub(super) fn privacy_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if !self.privacy_ui.loaded && self.privacy_ui.operation == PrivacyOperation::Idle {
            self.begin_privacy_inventory(ctx);
        }
        self.privacy_sources(ui, t, ctx);
        ui.add_space(10.);
        self.privacy_cookie_settings(ui, t, ctx);
        ui.add_space(10.);
        if self.privacy_ui.report.is_some() {
            self.privacy_results(ui, t, ctx);
            ui.add_space(10.);
        }
        self.privacy_recovery(ui, t, ctx);
    }

    pub(super) fn privacy_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let privacy_busy = self.privacy_ui.operation != PrivacyOperation::Idle;
        ui.set_min_height(40.);
        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            match self.privacy_ui.operation {
                PrivacyOperation::Scanning => {
                    theme::muted(ui, self.progress.clone(), t);
                    ui.add_space(10.);
                    if theme::secondary(ui, "Stop scan", true) {
                        self.cancel
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                PrivacyOperation::Cleaning => {
                    theme::muted(ui, self.progress.clone(), t);
                    ui.add_space(10.);
                    if theme::secondary(ui, "Stop cleanup", true) {
                        self.cancel
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                PrivacyOperation::Restoring => {
                    theme::muted(ui, "Restoring the reviewed browser database…", t);
                }
                PrivacyOperation::Loading
                | PrivacyOperation::ClosingBrowsers
                | PrivacyOperation::SavingSettings
                | PrivacyOperation::PreparingRestore => {
                    theme::muted(ui, self.progress.clone(), t);
                }
                PrivacyOperation::Idle => {
                    theme::muted(
                        ui,
                        format!(
                            "{} selected · {} profiles",
                            self.privacy_ui.selected_ids.len(),
                            self.privacy_ui.selected_profiles.len()
                        ),
                        t,
                    );
                    ui.add_space(10.);
                    if theme::secondary(
                        ui,
                        "Scan browser data",
                        !privacy_busy
                            && self.privacy_ui.loaded
                            && !self.privacy_ui.selected_profiles.is_empty()
                            && !self.privacy_ui.categories.is_empty()
                            && (!self
                                .privacy_ui
                                .categories
                                .contains(&PrivacyCategory::Cookies)
                                || self.privacy_ui.cookie_settings_readable),
                    ) {
                        self.begin_privacy_scan(ctx);
                    }
                    let can_review = self.privacy_ui.report.as_ref().is_some_and(|report| {
                        !report.cancelled
                            && !self.privacy_ui.selected_ids.is_empty()
                            && self
                                .privacy_ui
                                .selected_ids
                                .iter()
                                .all(|id| report.records.iter().any(|record| record.id == *id))
                    });
                    if theme::primary(ui, "Review selected", t, !privacy_busy && can_review) {
                        self.privacy_ui.cleanup_review = true;
                    }
                }
            }
        });
    }

    pub(super) fn privacy_dialog(&mut self, ctx: &egui::Context) {
        if self.privacy_ui.detail_id.is_some() {
            self.privacy_detail_dialog(ctx);
        }
        if self.privacy_ui.cleanup_review {
            self.privacy_cleanup_dialog(ctx);
        }
        if self.privacy_ui.close_review {
            self.privacy_close_dialog(ctx);
        }
        if self.privacy_ui.restore_review {
            self.privacy_restore_dialog(ctx);
        }
    }

    pub(super) fn privacy_event(&mut self, event: PrivacyEvent) {
        match event {
            PrivacyEvent::InventoryLoaded {
                inventory,
                running,
                settings,
                restores,
            } => {
                self.worker = None;
                self.privacy_ui.operation = PrivacyOperation::Idle;
                let previously_selected = self.privacy_ui.selected_profiles.clone();
                self.privacy_ui.profiles = inventory.profiles;
                self.privacy_ui.selected_profiles = self
                    .privacy_ui
                    .profiles
                    .iter()
                    .filter(|profile| {
                        previously_selected.is_empty() || previously_selected.contains(&profile.id)
                    })
                    .map(|profile| profile.id.clone())
                    .collect();
                if previously_selected.is_empty() {
                    self.privacy_ui.selected_profiles = self
                        .privacy_ui
                        .profiles
                        .iter()
                        .map(|profile| profile.id.clone())
                        .collect();
                }
                self.privacy_ui.inventory_partial = inventory.partial;
                self.privacy_ui.inventory_skips = inventory
                    .skipped
                    .into_iter()
                    .map(|skip| skip.reason)
                    .collect();
                self.privacy_ui.loaded = true;
                match running {
                    Ok(processes) => {
                        self.privacy_ui.running = processes;
                        self.privacy_ui.process_error = None;
                    }
                    Err(error) => self.privacy_ui.process_error = Some(error),
                }
                match settings {
                    Ok(settings) => {
                        self.privacy_ui.cookie_settings = settings;
                        self.privacy_ui.cookie_settings_readable = true;
                        self.privacy_ui.cookie_settings_error = None;
                    }
                    Err(error) => {
                        self.privacy_ui.cookie_settings_readable = false;
                        self.privacy_ui.cookie_settings_error = Some(error);
                        self.privacy_ui.categories.remove(&PrivacyCategory::Cookies);
                    }
                }
                match restores {
                    Ok(options) => {
                        self.privacy_ui.restore_options = options;
                        self.privacy_ui.restore_error = None;
                    }
                    Err(error) => self.privacy_ui.restore_error = Some(error),
                }
                if self.privacy_ui.inventory_partial {
                    self.notice = Some(
                        "Browser profile discovery was partial. Review the profile notes before scanning.".into(),
                    );
                }
            }
            PrivacyEvent::RunningUpdated(result) => match result {
                Ok(processes) => {
                    self.privacy_ui.running = processes;
                    self.privacy_ui.process_error = None;
                }
                Err(error) => self.privacy_ui.process_error = Some(error),
            },
            PrivacyEvent::Progress(progress) => {
                self.progress = format!(
                    "{} · {} of {} profiles · {} records",
                    category_label(progress.category),
                    progress.profiles_completed,
                    progress.profiles_total,
                    progress.records_found
                );
            }
            PrivacyEvent::Scanned(report) => {
                self.worker = None;
                self.privacy_ui.operation = PrivacyOperation::Idle;
                self.privacy_ui.selected_ids.clear();
                self.privacy_ui.report = Some(report.clone());
                if report.cancelled {
                    self.notice = Some(
                        "Browser scan stopped. The partial rows are for review only and cannot be cleaned.".into(),
                    );
                } else if report.partial {
                    self.notice = Some(format!(
                        "Scan finished with partial coverage: {} database or profile checks were skipped.",
                        report.skipped_count
                    ));
                } else {
                    self.notice = None;
                }
            }
            PrivacyEvent::CloseRequested { report, remaining } => {
                self.worker = None;
                self.privacy_ui.operation = PrivacyOperation::Idle;
                self.privacy_ui.close_report = Some(report);
                match remaining {
                    Ok(processes) => {
                        self.privacy_ui.running = processes;
                        self.privacy_ui.process_error = None;
                    }
                    Err(error) => self.privacy_ui.process_error = Some(error),
                }
            }
            PrivacyEvent::SettingsSaved(result) => {
                self.worker = None;
                self.privacy_ui.operation = PrivacyOperation::Idle;
                match result {
                    Ok(settings) => {
                        self.privacy_ui.cookie_settings = settings;
                        self.privacy_ui.cookie_settings_readable = true;
                        self.privacy_ui.cookie_settings_error = None;
                        self.privacy_ui.report = None;
                        self.privacy_ui.selected_ids.clear();
                        self.notice = Some(
                            "Cookie keep domains were saved. Scan again to apply them to results."
                                .into(),
                        );
                    }
                    Err(error) => self.privacy_ui.cookie_settings_error = Some(error),
                }
            }
            PrivacyEvent::CleanupProgress { done, total } => {
                self.progress = format!("Reviewed {done} of {total} selected browser records");
            }
            PrivacyEvent::Cleaned(result) => {
                self.worker = None;
                self.privacy_ui.operation = PrivacyOperation::Idle;
                self.privacy_ui.cleanup_review = false;
                self.privacy_ui.report = None;
                self.privacy_ui.selected_ids.clear();
                match result {
                    Ok(receipt) => {
                        let mut message = format!(
                            "{} browser records removed; {} skipped{}.",
                            receipt.deleted,
                            receipt.skipped,
                            if receipt.cancelled {
                                "; stopped by request"
                            } else {
                                ""
                            }
                        );
                        if receipt.uncertain {
                            message.push_str(" Outcome needs recovery review.");
                        }
                        self.notice = Some(message);
                        if !receipt.errors.is_empty() {
                            self.error = Some(receipt.errors.join(" "));
                        }
                    }
                    Err(error) => {
                        self.error = Some(format!(
                            "Browser cleanup stopped: {error}. Review privacy recovery before retrying."
                        ));
                    }
                }
                match store::history(&self.data_dir) {
                    Ok(history) => {
                        self.history = history;
                        self.history_readable = true;
                    }
                    Err(error) => {
                        self.error = Some(error);
                        self.history_readable = false;
                    }
                }
                self.refresh_privacy_recovery_options();
            }
            PrivacyEvent::RestorePrepared { id, result } => {
                self.worker = None;
                self.privacy_ui.operation = PrivacyOperation::Idle;
                match result {
                    Ok(plan) if plan.id() == id => {
                        self.privacy_ui.restore_plan = Some(plan);
                        self.privacy_ui.restore_review = true;
                        self.privacy_ui.restore_error = None;
                    }
                    Ok(_) => {
                        self.privacy_ui.restore_error = Some(
                            "Recovery review returned a different database identifier; no restore was started.".into(),
                        );
                    }
                    Err(error) => self.privacy_ui.restore_error = Some(error),
                }
            }
            PrivacyEvent::Restored(result) => {
                self.worker = None;
                self.privacy_ui.operation = PrivacyOperation::Idle;
                self.privacy_ui.restore_review = false;
                self.privacy_ui.restore_plan = None;
                match result {
                    Ok(receipt) if receipt.restored && !receipt.uncertain => {
                        self.notice = Some(
                            "The reviewed pre-cleanup database was restored. A copy of the previous state was retained.".into(),
                        );
                    }
                    Ok(receipt) => {
                        self.error = Some(format!(
                            "Restore needs recovery review: {}",
                            receipt.errors.join(" ")
                        ));
                    }
                    Err(error) => self.error = Some(error),
                }
                self.refresh_privacy_recovery_options();
                self.privacy_ui.report = None;
                self.privacy_ui.selected_ids.clear();
            }
        }
    }

    fn privacy_sources(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let busy = self.privacy_ui.operation != PrivacyOperation::Idle || self.busy();
        let mut inventory_changed = false;
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Browser profiles").family(theme::semibold()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if theme::secondary(ui, "Refresh profiles", !busy) {
                        inventory_changed = true;
                        self.begin_privacy_inventory(ctx);
                    }
                });
            });
            ui.add_space(6.);
            if !self.privacy_ui.loaded {
                theme::muted(ui, "Checking known Chrome, Edge and Firefox profile locations…", t);
            } else if self.privacy_ui.profiles.is_empty() {
                theme::muted(
                    ui,
                    "No supported browser profiles were found in known profile locations.",
                    t,
                );
                theme::muted(
                    ui,
                    "Custom profile paths are not searched automatically. Use the browser's default profile location or ask for explicit path support.",
                    t,
                );
            } else {
                let profile_count = self.privacy_ui.profiles.len();
                let checked = self.privacy_ui.selected_profiles.len();
                ui.horizontal_wrapped(|ui| {
                    theme::muted(ui, format!("{checked} of {profile_count} profiles selected"), t);
                    if theme::secondary(ui, "Select all", !busy) {
                        self.privacy_ui.selected_profiles = self
                            .privacy_ui
                            .profiles
                            .iter()
                            .map(|profile| profile.id.clone())
                            .collect();
                        inventory_changed = true;
                    }
                    if theme::secondary(ui, "Clear", !busy) {
                        self.privacy_ui.selected_profiles.clear();
                        inventory_changed = true;
                    }
                });
                ui.add_space(4.);
                egui::Grid::new("privacy-profile-choices")
                    .num_columns(2)
                    .spacing(Vec2::new(24., 4.))
                    .show(ui, |ui| {
                        for (index, profile) in self.privacy_ui.profiles.iter().enumerate() {
                            let mut selected = self
                                .privacy_ui
                                .selected_profiles
                                .contains(&profile.id);
                            if ui
                                .add_enabled(
                                    !busy,
                                    egui::Checkbox::new(
                                        &mut selected,
                                        format!("{} · {}", profile.browser.label(), profile.name),
                                    ),
                                )
                                .changed()
                            {
                                if selected {
                                    self.privacy_ui.selected_profiles.insert(profile.id.clone());
                                } else {
                                    self.privacy_ui.selected_profiles.remove(&profile.id);
                                }
                                inventory_changed = true;
                            }
                            if index % 2 == 1 {
                                ui.end_row();
                            }
                        }
                    });
                if inventory_changed {
                    self.invalidate_privacy_report();
                }
            }
            ui.add_space(8.);
            ui.horizontal_wrapped(|ui| {
                theme::muted(ui, "Categories", t);
                for (category, label) in [
                    (PrivacyCategory::History, "History"),
                    (PrivacyCategory::Cookies, "Cookies"),
                    (PrivacyCategory::Downloads, "Downloads"),
                ] {
                    let mut selected = self.privacy_ui.categories.contains(&category);
                    let enabled = !busy
                        && (category != PrivacyCategory::Cookies
                            || self.privacy_ui.cookie_settings_readable);
                    if ui
                        .add_enabled(enabled, egui::Checkbox::new(&mut selected, label))
                        .changed()
                    {
                        if selected {
                            self.privacy_ui.categories.insert(category);
                        } else {
                            self.privacy_ui.categories.remove(&category);
                        }
                        inventory_changed = true;
                    }
                }
            });
            theme::muted(
                ui,
                "History and download metadata show site labels only. Cookie names and values are never included in results.",
                t,
            );
            if !self.privacy_ui.running.is_empty() {
                ui.add_space(4.);
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(
                        t.attention,
                        format!(
                            "{} supported browser process{} running. Cleanup requires the matching browser to be closed.",
                            self.privacy_ui.running.len(),
                            if self.privacy_ui.running.len() == 1 { " is" } else { "es are" }
                        ),
                    );
                    if theme::secondary(ui, "Refresh status", !busy) {
                        self.refresh_running_browsers(ctx);
                    }
                    if theme::secondary(ui, "Review running browsers", !busy) {
                        self.privacy_ui.close_review = true;
                        self.privacy_ui.selected_processes.clear();
                    }
                });
            } else {
                ui.horizontal_wrapped(|ui| {
                    theme::muted(ui, "No supported browser process is currently running.", t);
                    if theme::secondary(ui, "Refresh status", !busy) {
                        self.refresh_running_browsers(ctx);
                    }
                });
            }
            if let Some(error) = &self.privacy_ui.process_error {
                ui.colored_label(t.attention, format!("Running-browser status unavailable: {error}"));
            }
            if self.privacy_ui.inventory_partial {
                ui.add_space(4.);
                ui.colored_label(t.attention, "Profile discovery was partial.");
            }
            if !self.privacy_ui.inventory_skips.is_empty() {
                egui::CollapsingHeader::new(format!(
                    "Profile discovery notes · {}",
                    self.privacy_ui.inventory_skips.len()
                ))
                .id_salt("privacy-profile-skip-notes")
                .show(ui, |ui| {
                    for reason in &self.privacy_ui.inventory_skips {
                        theme::muted(ui, reason, t);
                    }
                });
            }
        });
    }

    fn privacy_cookie_settings(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let busy = self.privacy_ui.operation != PrivacyOperation::Idle || self.busy();
        let mut changed = false;
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Cookie keep domains").family(theme::semibold()));
                theme::muted(ui, "Matching cookies stay out of cleanup results", t);
            });
            ui.add_space(6.);
            ui.horizontal_wrapped(|ui| {
                ui.add_enabled(
                    !busy,
                    egui::TextEdit::singleline(&mut self.privacy_ui.cookie_domain_input)
                        .desired_width(245.)
                        .hint_text("example.com"),
                );
                if theme::secondary(ui, "Add domain", !busy) {
                    match privacy::normalize_cookie_domain(&self.privacy_ui.cookie_domain_input) {
                        Ok(domain) => {
                            let mut domains = self.privacy_ui.cookie_settings.keep_domains.clone();
                            if !domains.iter().any(|existing| existing == &domain) {
                                domains.push(domain);
                                self.begin_save_cookie_settings(domains, ctx);
                            }
                            self.privacy_ui.cookie_domain_input.clear();
                        }
                        Err(error) => self.privacy_ui.cookie_settings_error = Some(error),
                    }
                }
            });
            if !self.privacy_ui.cookie_settings_readable {
                ui.colored_label(
                    t.attention,
                    "Cookie settings could not be validated. Cookie scanning stays disabled until valid settings are saved.",
                );
            }
            if let Some(error) = &self.privacy_ui.cookie_settings_error {
                ui.colored_label(t.attention, error);
            }
            if self.privacy_ui.cookie_settings.keep_domains.is_empty() {
                theme::muted(ui, "No keep domains saved.", t);
            } else {
                let mut remove = None;
                for (index, domain) in self.privacy_ui.cookie_settings.keep_domains.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(domain);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if theme::secondary(ui, "Remove", !busy) {
                                remove = Some(index);
                            }
                        });
                    });
                }
                if let Some(index) = remove {
                    let mut domains = self.privacy_ui.cookie_settings.keep_domains.clone();
                    domains.remove(index);
                    self.begin_save_cookie_settings(domains, ctx);
                    changed = true;
                }
            }
        });
        if changed {
            self.invalidate_privacy_report();
        }
    }

    fn privacy_results(&mut self, ui: &mut egui::Ui, t: Tokens, _ctx: &egui::Context) {
        let busy = self.privacy_ui.operation != PrivacyOperation::Idle || self.busy();
        let Some(report) = &mut self.privacy_ui.report else {
            return;
        };
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Browser records found").family(theme::semibold()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    theme::muted(
                        ui,
                        format!(
                            "{} selected · {} available · {:.1}s",
                            self.privacy_ui.selected_ids.len(),
                            report.records.len(),
                            report.elapsed_ms as f64 / 1000.
                        ),
                        t,
                    );
                });
            });
            ui.add_space(6.);
            ui.horizontal_wrapped(|ui| {
                for category in [
                    PrivacyCategory::History,
                    PrivacyCategory::Cookies,
                    PrivacyCategory::Downloads,
                ] {
                    let count = report
                        .records
                        .iter()
                        .filter(|record| record.category == category)
                        .count();
                    theme::muted(ui, format!("{} {count}", category_label(category)), t);
                }
                if report.cookie_exempted > 0 {
                    theme::muted(
                        ui,
                        format!(
                            "{} cookie rows kept by domain rules",
                            report.cookie_exempted
                        ),
                        t,
                    );
                }
            });
            if report.partial {
                ui.add_space(4.);
                ui.colored_label(
                    t.attention,
                    format!(
                        "{} skipped checks · {} skip details omitted · {}{}",
                        report.skipped_count,
                        report.omitted_skip_details,
                        if report.truncated {
                            "limit reached"
                        } else {
                            "no scan limit reached"
                        },
                        if report.cancelled {
                            " · cancelled, review only"
                        } else {
                            ""
                        }
                    ),
                );
            }
            ui.add_space(6.);
            ui.horizontal_wrapped(|ui| {
                ui.label("Search");
                ui.add_enabled(
                    !busy,
                    egui::TextEdit::singleline(&mut self.privacy_ui.search)
                        .desired_width(220.)
                        .hint_text("Site, profile, category, or record ID"),
                );
                if theme::secondary(ui, "Select visible", !busy && !report.cancelled) {
                    for record in report
                        .records
                        .iter()
                        .filter(|record| record_matches(record, &self.privacy_ui.search))
                    {
                        self.privacy_ui.selected_ids.insert(record.id);
                    }
                }
                if theme::secondary(ui, "Clear selection", !busy) {
                    self.privacy_ui.selected_ids.clear();
                }
            });
            ui.separator();
            if report.records.is_empty() {
                theme::muted(
                    ui,
                    if report.cancelled {
                        "The scan stopped before any selectable browser records were read."
                    } else {
                        "No supported browser records matched the selected profiles and categories."
                    },
                    t,
                );
            } else {
                let query = self.privacy_ui.search.clone();
                egui::ScrollArea::vertical()
                    .id_salt("privacy-records")
                    .max_height(390.)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        egui::Grid::new("privacy-record-table")
                            .num_columns(5)
                            .spacing(Vec2::new(12., 5.))
                            .striped(false)
                            .show(ui, |ui| {
                                for label in ["Select", "Browser and profile", "Type", "Site", ""] {
                                    ui.label(RichText::new(label).family(theme::semibold()));
                                }
                                ui.end_row();
                                for record in &report.records {
                                    if !record_matches(record, &query) {
                                        continue;
                                    }
                                    let mut selected =
                                        self.privacy_ui.selected_ids.contains(&record.id);
                                    if ui
                                        .add_enabled(
                                            !busy && !report.cancelled,
                                            egui::Checkbox::without_text(&mut selected),
                                        )
                                        .changed()
                                    {
                                        if selected {
                                            self.privacy_ui.selected_ids.insert(record.id);
                                        } else {
                                            self.privacy_ui.selected_ids.remove(&record.id);
                                        }
                                    }
                                    ui.vertical(|ui| {
                                        ui.label(
                                            RichText::new(record.browser.label())
                                                .family(theme::semibold()),
                                        );
                                        theme::muted(ui, &record.profile_name, t);
                                    });
                                    ui.label(category_label(record.category));
                                    ui.add(egui::Label::new(&record.site).truncate())
                                        .on_hover_text(&record.site);
                                    ui.horizontal(|ui| {
                                        if ui.small_button("Details").clicked() {
                                            self.privacy_ui.detail_id = Some(record.id);
                                        }
                                        if ui
                                            .add_enabled(
                                                !busy && !report.cancelled,
                                                egui::Button::new("Review"),
                                            )
                                            .clicked()
                                        {
                                            self.privacy_ui.selected_ids.clear();
                                            self.privacy_ui.selected_ids.insert(record.id);
                                            self.privacy_ui.cleanup_review = true;
                                        }
                                    });
                                    ui.end_row();
                                }
                            });
                    });
            }
            if report.skipped_count > 0 {
                ui.add_space(6.);
                egui::CollapsingHeader::new(format!(
                    "Skipped browser data · {}",
                    report.skipped_count
                ))
                .id_salt("privacy-skipped-rows")
                .show(ui, |ui| {
                    for skip in &report.skipped {
                        ui.horizontal_wrapped(|ui| {
                            theme::muted(ui, &skip.profile_name, t);
                            if let Some(category) = skip.category {
                                theme::muted(ui, category_label(category), t);
                            }
                            theme::muted(ui, &skip.reason, t);
                        });
                    }
                    if report.omitted_skip_details > 0 {
                        theme::muted(
                            ui,
                            format!(
                                "{} additional skip details are omitted.",
                                report.omitted_skip_details
                            ),
                            t,
                        );
                    }
                });
            }
        });
    }

    fn privacy_recovery(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let busy = self.privacy_ui.operation != PrivacyOperation::Idle || self.busy();
        let options = self.privacy_ui.restore_options.clone();
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Browser recovery copies").family(theme::semibold()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if theme::secondary(ui, "Refresh recovery", !busy) {
                        self.refresh_privacy_recovery_options();
                    }
                });
            });
            theme::muted(
                ui,
                "Restore is available only when the browser is closed and its database still exactly matches the saved post-cleanup state.",
                t,
            );
            if let Some(error) = &self.privacy_ui.restore_error {
                ui.colored_label(t.attention, error);
            }
            if options.is_empty() {
                theme::muted(ui, "No verified browser cleanup recovery copies are available.", t);
            } else {
                for option in &options {
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(format!(
                                    "{} · {} · {}",
                                    option.browser.label(),
                                    option.profile_name,
                                    option.database_name
                                ))
                                .family(theme::semibold()),
                            );
                            theme::muted(
                                ui,
                                format!(
                                    "{} records · {} · {}",
                                    option.record_count,
                                    option
                                        .categories
                                        .iter()
                                        .map(|category| category_label(*category))
                                        .collect::<Vec<_>>()
                                        .join(", "),
                                    recovery_state_label(option.state)
                                ),
                                t,
                            );
                            if let Some(reason) = &option.reason {
                                theme::muted(ui, reason, t);
                            }
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if theme::secondary(
                                ui,
                                "Review restore",
                                !busy && option.state == PrivacyRecoveryState::Ready,
                            ) {
                                self.begin_prepare_restore(option.id, ctx);
                            }
                        });
                    });
                }
            }
        });
    }

    fn privacy_detail_dialog(&mut self, ctx: &egui::Context) {
        if !self.busy() && ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.privacy_ui.detail_id = None;
            return;
        }
        let t = theme::tokens(self.prefs.dark);
        let record = self.privacy_ui.report.as_ref().and_then(|report| {
            report
                .records
                .iter()
                .find(|record| Some(record.id) == self.privacy_ui.detail_id)
                .cloned()
        });
        let Some(record) = record else {
            self.privacy_ui.detail_id = None;
            return;
        };
        egui::Modal::new(egui::Id::new("privacy-record-details")).show(ctx, |ui| {
            ui.set_width(450.);
            ui.heading("Browser record details");
            ui.add_space(10.);
            detail_line(ui, "Browser", record.browser.label());
            detail_line(ui, "Profile", &record.profile_name);
            detail_line(ui, "Category", category_label(record.category));
            detail_line(ui, "Site", &record.site);
            detail_line(ui, "Current record ID", &record.id.to_string());
            ui.add_space(8.);
            theme::muted(
                ui,
                "The scan stores only this sanitized site label. It does not expose cookie names, cookie values, full URLs, page titles, passwords, or browser settings.",
                t,
            );
            ui.add_space(14.);
            if theme::secondary(ui, "Close details", true) {
                self.privacy_ui.detail_id = None;
            }
        });
    }

    fn privacy_cleanup_dialog(&mut self, ctx: &egui::Context) {
        if !self.busy() && ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.privacy_ui.cleanup_review = false;
            return;
        }
        let t = theme::tokens(self.prefs.dark);
        let Some(report) = self.privacy_ui.report.as_ref() else {
            self.privacy_ui.cleanup_review = false;
            return;
        };
        let selected = self
            .privacy_ui
            .selected_ids
            .iter()
            .filter_map(|id| {
                report
                    .records
                    .iter()
                    .find(|record| record.id == *id)
                    .cloned()
            })
            .collect::<Vec<_>>();
        let conflicts = self
            .privacy_ui
            .running
            .iter()
            .filter(|process| {
                selected
                    .iter()
                    .any(|record| record.browser == process.browser)
            })
            .count();
        let cancelled = report.cancelled;
        let partial = report.partial;
        egui::Modal::new(egui::Id::new("privacy-cleanup-review")).show(ctx, |ui| {
            ui.set_width(470.);
            ui.heading("Review browser cleanup");
            ui.add_space(10.);
            ui.label(format!(
                "Remove {} selected records from {} browser profile{}?",
                selected.len(),
                selected.iter().map(|record| record.profile_id.as_str()).collect::<HashSet<_>>().len(),
                if selected.len() == 1 { "" } else { "s" }
            ));
            ui.add_space(8.);
            for category in [PrivacyCategory::History, PrivacyCategory::Cookies, PrivacyCategory::Downloads] {
                let count = selected.iter().filter(|record| record.category == category).count();
                if count > 0 {
                    theme::muted(ui, format!("{count} {} records", category_label(category)), t);
                }
            }
            ui.add_space(8.);
            theme::muted(
                ui,
                "A verified database snapshot and synced intent are required before each transaction. Passwords and browser settings are outside these cleanup categories.",
                t,
            );
            if partial {
                ui.add_space(8.);
                ui.colored_label(t.attention, "This scan has skipped or unsupported data. Only listed current IDs can be cleaned.");
            }
            if conflicts > 0 || self.privacy_ui.process_error.is_some() {
                ui.add_space(8.);
                ui.colored_label(
                    t.attention,
                    format!("{} selected browser process conflict{}; cleanup will remain blocked until closed.", conflicts, if conflicts == 1 { "" } else { "s" }),
                );
            }
            ui.add_space(16.);
            ui.horizontal(|ui| {
                if theme::secondary(ui, "Back to results", true) {
                    self.privacy_ui.cleanup_review = false;
                }
                if conflicts > 0 && theme::secondary(ui, "Review open browsers", true) {
                    self.privacy_ui.close_review = true;
                    self.privacy_ui.selected_processes.clear();
                }
                let can_clean = !selected.is_empty()
                    && !cancelled
                    && conflicts == 0
                    && self.privacy_ui.process_error.is_none()
                    && self.history_readable;
                if theme::primary(ui, "Remove selected records", t, can_clean) {
                    self.begin_privacy_cleanup(ctx);
                }
            });
            if cancelled {
                theme::muted(ui, "Cancelled scans cannot be used for cleanup. Run a new scan first.", t);
            }
        });
    }

    fn privacy_close_dialog(&mut self, ctx: &egui::Context) {
        let busy = self.busy();
        if !busy && ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.privacy_ui.close_review = false;
            return;
        }
        let t = theme::tokens(self.prefs.dark);
        let running = self.privacy_ui.running.clone();
        let close_report = self.privacy_ui.close_report.clone();
        let process_error = self.privacy_ui.process_error.clone();
        egui::Modal::new(egui::Id::new("privacy-close-browser-review")).show(ctx, |ui| {
            ui.set_width(460.);
            ui.heading("Review running browsers");
            ui.add_space(8.);
            theme::muted(
                ui,
                "Only selected browser processes receive a graceful close request. DCleaner never force-terminates them.",
                t,
            );
            if running.is_empty() {
                theme::muted(ui, "No supported browser processes are currently running.", t);
            } else {
                for process in &running {
                    let key = (process.browser, process.pid);
                    let mut selected = self.privacy_ui.selected_processes.contains(&key);
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled_ui(!busy, |ui| {
                                ui.checkbox(&mut selected, "")
                            })
                            .inner
                            .changed()
                        {
                            if selected {
                                self.privacy_ui.selected_processes.insert(key);
                            } else {
                                self.privacy_ui.selected_processes.remove(&key);
                            }
                        }
                        ui.label(format!("{} · process {}", process.browser.label(), process.pid));
                    });
                }
                self.privacy_ui.selected_processes.retain(|key| {
                    running
                        .iter()
                        .any(|process| process.browser == key.0 && process.pid == key.1)
                });
            }
            if let Some(report) = &close_report {
                ui.add_space(8.);
                if !report.requested.is_empty() {
                    theme::muted(ui, format!("{} graceful request(s) sent.", report.requested.len()), t);
                }
                if !report.still_running.is_empty() {
                    ui.colored_label(t.attention, "Some selected browsers are still open. Close them manually, then refresh status.");
                }
                if !report.stale_selection.is_empty() {
                    theme::muted(ui, "A selected process ended before the request was sent.", t);
                }
                for error in &report.errors {
                    ui.colored_label(t.attention, error);
                }
            }
            if let Some(error) = &process_error {
                ui.colored_label(t.attention, error);
            }
            ui.add_space(14.);
            ui.horizontal(|ui| {
                if theme::secondary(ui, "Refresh status", !busy) {
                    self.refresh_running_browsers(ctx);
                }
                if theme::secondary(ui, "Cancel", true) {
                    self.privacy_ui.close_review = false;
                }
                let can_request = !busy && !self.privacy_ui.selected_processes.is_empty();
                if theme::primary(ui, "Request graceful close", t, can_request) {
                    self.begin_close_request(ctx);
                }
            });
        });
    }

    fn privacy_restore_dialog(&mut self, ctx: &egui::Context) {
        if !self.busy() && ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.privacy_ui.restore_review = false;
            self.privacy_ui.restore_plan = None;
            return;
        }
        let t = theme::tokens(self.prefs.dark);
        let Some(plan) = self.privacy_ui.restore_plan.as_ref() else {
            self.privacy_ui.restore_review = false;
            return;
        };
        let plan = plan.clone();
        egui::Modal::new(egui::Id::new("privacy-restore-review")).show(ctx, |ui| {
            ui.set_width(470.);
            ui.heading("Review database restore");
            ui.add_space(8.);
            ui.label(format!(
                "Restore the pre-cleanup {} database for {}?",
                plan.database_name(),
                plan.profile_name()
            ));
            ui.add_space(8.);
            theme::muted(
                ui,
                "The exact current database was rechecked against its saved post-cleanup bytes, metadata and schema. A fresh copy of the current state and a durable restore intent will be saved before the database is changed.",
                t,
            );
            ui.add_space(14.);
            ui.horizontal(|ui| {
                if theme::secondary(ui, "Keep current database", true) {
                    self.privacy_ui.restore_review = false;
                    self.privacy_ui.restore_plan = None;
                }
                if theme::primary(ui, "Restore reviewed copy", t, !self.busy()) {
                    self.begin_privacy_restore(ctx);
                }
            });
        });
    }

    fn begin_privacy_inventory(&mut self, ctx: &egui::Context) {
        if self.busy() || self.privacy_ui.operation != PrivacyOperation::Idle {
            return;
        }
        self.privacy_ui.operation = PrivacyOperation::Loading;
        self.privacy_ui.loaded = false;
        self.privacy_ui.report = None;
        self.privacy_ui.selected_ids.clear();
        self.progress = "Checking known browser profile locations…".into();
        let data_dir = self.data_dir.clone();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let inventory = privacy::discover_profiles();
            let running = privacy::running_browsers();
            let settings = if data_dir.as_os_str().is_empty() {
                Err(
                    "Application data storage is unavailable; cookie exceptions cannot be loaded."
                        .into(),
                )
            } else {
                privacy::load_cookie_exception_settings(&data_dir)
            };
            let restores = if data_dir.as_os_str().is_empty() {
                Err(
                    "Application data storage is unavailable; recovery history cannot be read."
                        .into(),
                )
            } else {
                privacy::list_privacy_restore_options(&data_dir)
            };
            let _ = tx.send(Event::Privacy(PrivacyEvent::InventoryLoaded {
                inventory,
                running,
                settings,
                restores,
            }));
            ctx.request_repaint();
        });
    }

    fn begin_privacy_scan(&mut self, ctx: &egui::Context) {
        if self.busy() || self.privacy_ui.operation != PrivacyOperation::Idle {
            return;
        }
        let profiles = self
            .privacy_ui
            .profiles
            .iter()
            .filter(|profile| self.privacy_ui.selected_profiles.contains(&profile.id))
            .cloned()
            .collect::<Vec<_>>();
        if profiles.is_empty() {
            self.error = Some("Select at least one discovered browser profile.".into());
            return;
        }
        let categories = [
            PrivacyCategory::History,
            PrivacyCategory::Cookies,
            PrivacyCategory::Downloads,
        ]
        .into_iter()
        .filter(|category| self.privacy_ui.categories.contains(category))
        .collect::<Vec<_>>();
        if categories.is_empty() {
            self.error = Some("Select at least one browser-data category.".into());
            return;
        }
        if categories.contains(&PrivacyCategory::Cookies)
            && !self.privacy_ui.cookie_settings_readable
        {
            self.error = Some(
                "Valid cookie keep-domain settings are required before scanning cookies.".into(),
            );
            return;
        }
        self.error = None;
        self.notice = None;
        self.privacy_ui.report = None;
        self.privacy_ui.selected_ids.clear();
        self.privacy_ui.operation = PrivacyOperation::Scanning;
        self.progress = "Preparing read-only browser scan…".into();
        self.cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let settings = self.privacy_ui.cookie_settings.clone();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let report = privacy::scan_profiles_with_settings(
                &profiles,
                &categories,
                &settings,
                &cancel,
                |progress| {
                    let _ = tx.send(Event::Privacy(PrivacyEvent::Progress(progress)));
                    ctx.request_repaint();
                },
            );
            let _ = tx.send(Event::Privacy(PrivacyEvent::Scanned(report)));
            ctx.request_repaint();
        });
    }

    fn begin_close_request(&mut self, ctx: &egui::Context) {
        if self.busy() || self.privacy_ui.operation != PrivacyOperation::Idle {
            return;
        }
        let selected = self
            .privacy_ui
            .running
            .iter()
            .filter(|process| {
                self.privacy_ui
                    .selected_processes
                    .contains(&(process.browser, process.pid))
            })
            .cloned()
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return;
        }
        self.privacy_ui.operation = PrivacyOperation::ClosingBrowsers;
        self.progress = "Requesting selected browsers to close gracefully…".into();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let report = privacy::request_close_selected(&selected);
            let remaining = privacy::running_browsers();
            let _ = tx.send(Event::Privacy(PrivacyEvent::CloseRequested {
                report,
                remaining,
            }));
            ctx.request_repaint();
        });
    }

    fn refresh_running_browsers(&mut self, ctx: &egui::Context) {
        if self.busy() || self.privacy_ui.operation != PrivacyOperation::Idle {
            return;
        }
        self.privacy_ui.operation = PrivacyOperation::ClosingBrowsers;
        self.progress = "Refreshing running-browser status…".into();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let result = privacy::running_browsers();
            let _ = tx.send(Event::Privacy(PrivacyEvent::RunningUpdated(result)));
            ctx.request_repaint();
        });
    }

    fn begin_save_cookie_settings(&mut self, domains: Vec<String>, ctx: &egui::Context) {
        if self.busy() || self.privacy_ui.operation != PrivacyOperation::Idle {
            return;
        }
        if self.data_dir.as_os_str().is_empty() {
            self.privacy_ui.cookie_settings_error =
                Some("Application data storage is unavailable.".into());
            return;
        }
        self.privacy_ui.operation = PrivacyOperation::SavingSettings;
        self.progress = "Saving cookie keep domains…".into();
        let data_dir = self.data_dir.clone();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let result = privacy::save_cookie_exception_settings(&data_dir, &domains);
            let _ = tx.send(Event::Privacy(PrivacyEvent::SettingsSaved(result)));
            ctx.request_repaint();
        });
    }

    fn begin_privacy_cleanup(&mut self, ctx: &egui::Context) {
        if self.busy()
            || self.privacy_ui.operation != PrivacyOperation::Idle
            || !self.history_readable
        {
            return;
        }
        let Some(report) = self.privacy_ui.report.as_ref() else {
            self.privacy_ui.cleanup_review = false;
            return;
        };
        let ids = self
            .privacy_ui
            .selected_ids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let plan = match privacy::build_cleanup_plan(report, &ids) {
            Ok(plan) => plan,
            Err(error) => {
                self.error = Some(error);
                self.privacy_ui.cleanup_review = false;
                return;
            }
        };
        let data_dir = self.data_dir.clone();
        self.privacy_ui.cleanup_review = false;
        self.privacy_ui.operation = PrivacyOperation::Cleaning;
        self.progress = "Verifying selected browser records…".into();
        self.cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let receipt = privacy::clean_privacy(&data_dir, &plan, &cancel, |done, total| {
                let _ = tx.send(Event::Privacy(PrivacyEvent::CleanupProgress {
                    done,
                    total,
                }));
                ctx.request_repaint();
            });
            let _ = tx.send(Event::Privacy(PrivacyEvent::Cleaned(receipt)));
            ctx.request_repaint();
        });
    }

    fn begin_prepare_restore(&mut self, id: Uuid, ctx: &egui::Context) {
        if self.busy()
            || self.privacy_ui.operation != PrivacyOperation::Idle
            || self.data_dir.as_os_str().is_empty()
        {
            return;
        }
        self.privacy_ui.operation = PrivacyOperation::PreparingRestore;
        self.progress = "Rechecking the exact browser database state…".into();
        let data_dir = self.data_dir.clone();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let result = privacy::prepare_privacy_restore(&data_dir, id);
            let _ = tx.send(Event::Privacy(PrivacyEvent::RestorePrepared { id, result }));
            ctx.request_repaint();
        });
    }

    fn begin_privacy_restore(&mut self, ctx: &egui::Context) {
        if self.busy() || self.privacy_ui.operation != PrivacyOperation::Idle {
            return;
        }
        let Some(plan) = self.privacy_ui.restore_plan.clone() else {
            return;
        };
        let data_dir = self.data_dir.clone();
        self.privacy_ui.restore_review = false;
        self.privacy_ui.operation = PrivacyOperation::Restoring;
        self.progress = "Saving current state and restoring the reviewed database…".into();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let result = privacy::restore_privacy_database(&data_dir, &plan);
            let _ = tx.send(Event::Privacy(PrivacyEvent::Restored(result)));
            ctx.request_repaint();
        });
    }

    fn refresh_privacy_recovery_options(&mut self) {
        if self.data_dir.as_os_str().is_empty() {
            self.privacy_ui.restore_error = Some("Application data storage is unavailable.".into());
            return;
        }
        match privacy::list_privacy_restore_options(&self.data_dir) {
            Ok(options) => {
                self.privacy_ui.restore_options = options;
                self.privacy_ui.restore_error = None;
            }
            Err(error) => self.privacy_ui.restore_error = Some(error),
        }
    }

    fn invalidate_privacy_report(&mut self) {
        if self.privacy_ui.report.take().is_some() {
            self.privacy_ui.selected_ids.clear();
            self.privacy_ui.cleanup_review = false;
            self.notice =
                Some("Browser scan choices changed. Run a new scan before cleanup.".into());
        }
    }
}

fn category_label(category: PrivacyCategory) -> &'static str {
    match category {
        PrivacyCategory::History => "History",
        PrivacyCategory::Cookies => "Cookies",
        PrivacyCategory::Downloads => "Downloads",
    }
}

fn recovery_state_label(state: PrivacyRecoveryState) -> &'static str {
    match state {
        PrivacyRecoveryState::Ready => "available for review",
        PrivacyRecoveryState::Restored => "already restored",
        PrivacyRecoveryState::Interrupted => "interrupted; manual review required",
        PrivacyRecoveryState::Uncertain => "uncertain; automatic restore blocked",
        PrivacyRecoveryState::Unavailable => "unavailable",
    }
}

fn record_matches(record: &PrivacyRecord, query: &str) -> bool {
    let query = query.trim().to_ascii_lowercase();
    query.is_empty()
        || record.site.to_ascii_lowercase().contains(&query)
        || record.profile_name.to_ascii_lowercase().contains(&query)
        || record.browser.label().to_ascii_lowercase().contains(&query)
        || category_label(record.category)
            .to_ascii_lowercase()
            .contains(&query)
        || record.id.to_string().contains(&query)
}

fn detail_line(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{label}: ")).family(theme::semibold()));
        ui.add(egui::Label::new(value.to_owned()).truncate())
            .on_hover_text(value);
    });
}
