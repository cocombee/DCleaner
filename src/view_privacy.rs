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
use std::{collections::HashSet, sync::Arc, thread};
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
    clear_cookie_input_on_save: bool,
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
            categories: PrivacyCategory::DEFAULT.into_iter().collect(),
            cookie_settings: CookieExceptionSettings::default(),
            cookie_settings_readable: false,
            cookie_settings_error: None,
            cookie_domain_input: String::new(),
            clear_cookie_input_on_save: false,
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
    pub(super) fn sync_privacy_cookie_settings(&mut self, settings: CookieExceptionSettings) {
        let changed = settings != self.privacy_ui.cookie_settings;
        self.privacy_ui.cookie_settings = settings;
        self.privacy_ui.cookie_settings_readable = true;
        self.privacy_ui.cookie_settings_error = None;
        if changed {
            self.privacy_ui.report = None;
            self.privacy_ui.selected_ids.clear();
            self.privacy_ui.cleanup_review = false;
            self.privacy_ui.detail_id = None;
        }
    }

    pub(super) fn mark_privacy_cookie_settings_unverified(&mut self, message: &str) {
        self.privacy_ui.cookie_settings_readable = false;
        self.privacy_ui.cookie_settings_error = Some(message.to_owned());
        self.privacy_ui.report = None;
        self.privacy_ui.selected_ids.clear();
        self.privacy_ui.cleanup_review = false;
        self.privacy_ui.detail_id = None;
    }

    #[cfg(test)]
    pub(super) fn privacy_cookie_test_state(&self) -> (CookieExceptionSettings, bool, bool, bool) {
        (
            self.privacy_ui.cookie_settings.clone(),
            self.privacy_ui.cookie_settings_readable,
            self.privacy_ui.report.is_some(),
            self.privacy_ui.cleanup_review,
        )
    }

    #[cfg(debug_assertions)]
    pub(super) fn seed_privacy_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Privacy fixtures are available only in isolated visual QA.".into());
        }
        let ui = &mut self.privacy_ui;
        *ui = PrivacyUi::default();
        ui.loaded = true;
        ui.cookie_settings_readable = true;
        ui.restore_error = Some("Synthetic visual fixture; recovery storage was not read.".into());
        match case {
            "privacy-empty" => {
                let (_, mut report) = privacy::visual_preview_fixture();
                report.records.clear();
                report.profiles_scanned = 0;
                ui.report = Some(report);
                ui.cookie_settings.keep_domains = vec!["example.test".into()];
            }
            "privacy-populated"
            | "privacy-selected"
            | "privacy-details"
            | "privacy-quota"
            | "privacy-storage"
            | "privacy-record-files"
            | "privacy-leveldb"
            | "privacy-leveldb-restore"
            | "privacy-preferences"
            | "privacy-locations"
            | "privacy-locations-review"
            | "privacy-sessions"
            | "privacy-sessions-review"
            | "privacy-sessions-restore"
            | "privacy-mozilla-sessions"
            | "privacy-mozilla-sessions-review"
            | "privacy-mozilla-sessions-restore"
            | "privacy-generic-sqlite"
            | "privacy-generic-sqlite-review"
            | "privacy-preferences-restore" => {
                let (inventory, report) = if case.starts_with("privacy-generic-sqlite") {
                    privacy::visual_generic_sqlite_preview_fixture()
                } else if matches!(case, "privacy-leveldb" | "privacy-leveldb-restore") {
                    privacy::visual_leveldb_preview_fixture()
                } else if matches!(
                    case,
                    "privacy-sessions" | "privacy-sessions-review" | "privacy-sessions-restore"
                ) {
                    privacy::visual_sessions_preview_fixture()
                } else if matches!(
                    case,
                    "privacy-mozilla-sessions"
                        | "privacy-mozilla-sessions-review"
                        | "privacy-mozilla-sessions-restore"
                ) {
                    privacy::visual_mozilla_sessions_preview_fixture(case.ends_with("-review"))
                } else if matches!(case, "privacy-locations" | "privacy-locations-review") {
                    privacy::visual_locations_preview_fixture()
                } else if matches!(case, "privacy-preferences" | "privacy-preferences-restore") {
                    privacy::visual_preferences_preview_fixture()
                } else if case == "privacy-record-files" {
                    privacy::visual_record_files_preview_fixture()
                } else if case == "privacy-storage" {
                    privacy::visual_storage_preview_fixture()
                } else if case == "privacy-quota" {
                    privacy::visual_quota_preview_fixture()
                } else {
                    privacy::visual_preview_fixture()
                };
                ui.profiles = inventory.profiles;
                ui.selected_profiles = ui
                    .profiles
                    .iter()
                    .map(|profile| profile.id.clone())
                    .collect();
                ui.report = Some(report);
                if case.starts_with("privacy-generic-sqlite") {
                    ui.categories = HashSet::from([
                        PrivacyCategory::SavedForms,
                        PrivacyCategory::SavedPasswords,
                        PrivacyCategory::SitePreferences,
                    ]);
                }
                if case.starts_with("privacy-sessions")
                    || case.starts_with("privacy-mozilla-sessions")
                {
                    ui.categories = HashSet::from([PrivacyCategory::Sessions]);
                }
                if case == "privacy-leveldb-restore" {
                    ui.restore_plan =
                        Some(privacy::visual_leveldb_restore_fixture(&ui.profiles[0]));
                    ui.restore_review = true;
                }
                if case == "privacy-preferences-restore" {
                    ui.restore_plan =
                        Some(privacy::visual_preferences_restore_fixture(&ui.profiles[0]));
                    ui.restore_review = true;
                }
                if case == "privacy-sessions-restore" {
                    ui.restore_plan =
                        Some(privacy::visual_sessions_restore_fixture(&ui.profiles[0]));
                    ui.restore_review = true;
                }
                if case == "privacy-mozilla-sessions-restore" {
                    ui.restore_plan = Some(privacy::visual_mozilla_session_restore_fixture(
                        ui.profiles.last().unwrap(),
                    ));
                    ui.restore_review = true;
                }
                if matches!(
                    case,
                    "privacy-selected"
                        | "privacy-locations-review"
                        | "privacy-sessions-review"
                        | "privacy-mozilla-sessions-review"
                        | "privacy-generic-sqlite-review"
                ) {
                    ui.selected_ids = ui
                        .report
                        .iter()
                        .flat_map(|report| &report.records)
                        .map(|record| record.id)
                        .collect();
                }
                if matches!(
                    case,
                    "privacy-locations-review"
                        | "privacy-sessions-review"
                        | "privacy-mozilla-sessions-review"
                        | "privacy-generic-sqlite-review"
                ) {
                    ui.cleanup_review = true;
                }
                if case == "privacy-details" {
                    ui.detail_id = ui
                        .report
                        .as_ref()
                        .and_then(|report| report.records.first())
                        .map(|record| record.id);
                }
            }
            "privacy-error" => {
                ui.inventory_partial = true;
                ui.inventory_skips = vec![
                    "Synthetic fixture error: browser profile discovery was unavailable.".into(),
                ];
                ui.cookie_settings_readable = false;
                ui.cookie_settings_error =
                    Some("Synthetic fixture error: cookie settings could not be validated.".into());
                ui.restore_error =
                    Some("Synthetic fixture error: recovery metadata is unavailable.".into());
            }
            _ => return Err(format!("Unsupported Privacy visual fixture: {case}")),
        }
        Ok(())
    }

    pub(super) fn privacy_overview_status(&self) -> String {
        match self.privacy_ui.report.as_ref() {
            Some(report) if !report.cancelled => {
                let partial = if report.partial { " · partial" } else { "" };
                format!(
                    "{} {}{partial}",
                    report
                        .records
                        .iter()
                        .map(|record| record.item_count())
                        .sum::<usize>(),
                    if report
                        .records
                        .iter()
                        .any(privacy::PrivacyRecord::is_session_file)
                    {
                        "items"
                    } else {
                        "records"
                    }
                )
            }
            _ => "Not scanned".into(),
        }
    }

    pub(super) fn privacy_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if !self.qa_fixture_mode()
            && !self.privacy_ui.loaded
            && self.privacy_ui.operation == PrivacyOperation::Idle
        {
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

    #[cfg(debug_assertions)]
    pub(super) fn qa_privacy_profile_action(
        &self,
        label: &str,
        after: bool,
    ) -> Result<serde_json::Value, String> {
        let profiles = &self.privacy_ui.profiles;
        let selected = &self.privacy_ui.selected_profiles;
        let valid = self.qa_fixture_mode()
            && !profiles.is_empty()
            && self.privacy_ui.operation == PrivacyOperation::Idle
            && (!after
                || (self.privacy_ui.report.is_none()
                    && self.privacy_ui.selected_ids.is_empty()
                    && match label {
                        "Select all" => {
                            selected.len() == profiles.len()
                                && profiles
                                    .iter()
                                    .all(|profile| selected.contains(&profile.id))
                        }
                        "Clear" => selected.is_empty(),
                        _ => false,
                    }));
        if !valid {
            return Err(format!(
                "Browser profile action did not reach its expected state: {label}"
            ));
        }
        Ok(
            serde_json::json!({"profiles": profiles.len(), "selected_profiles": selected.len(), "report_present": self.privacy_ui.report.is_some(), "selected_records": self.privacy_ui.selected_ids.len()}),
        )
    }
    pub(super) fn privacy_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let privacy_busy = self.privacy_ui.operation != PrivacyOperation::Idle || self.busy();
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
                    ui.with_layout(
                        Layout::right_to_left(Align::Center).with_main_wrap(true),
                        |ui| {
                            let can_review =
                                self.privacy_ui.report.as_ref().is_some_and(|report| {
                                    !report.cancelled
                                        && !self.privacy_ui.selected_ids.is_empty()
                                        && self.privacy_ui.selected_ids.iter().all(|id| {
                                            report.records.iter().any(|record| {
                                                record.id == *id && record.actionable()
                                            })
                                        })
                                });
                            let count = self.privacy_ui.report.as_ref().map_or(0, |report| {
                                report
                                    .records
                                    .iter()
                                    .filter(|record| {
                                        self.privacy_ui.selected_ids.contains(&record.id)
                                    })
                                    .map(|record| record.item_count())
                                    .sum::<usize>()
                            });
                            let label = if count == 0 {
                                "Review selected".into()
                            } else {
                                format!(
                                    "Review {}",
                                    if self.privacy_ui.report.as_ref().is_some_and(|r| r
                                        .records
                                        .iter()
                                        .any(privacy::PrivacyRecord::is_session_file))
                                    {
                                        theme::counted_label(count, "item", "items")
                                    } else {
                                        theme::counted_label(count, "record", "records")
                                    }
                                )
                            };
                            if theme::primary(ui, &label, t, !privacy_busy && can_review) {
                                self.privacy_ui.cleanup_review = true;
                            }
                            theme::muted(
                                ui,
                                format!(
                                    "{} selected · {}",
                                    count,
                                    theme::counted_label(
                                        self.privacy_ui.selected_profiles.len(),
                                        "profile",
                                        "profiles"
                                    )
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
                        },
                    );
                }
            }
        });
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_privacy_record_action(
        &self,
        label: &str,
        after: bool,
    ) -> Result<serde_json::Value, String> {
        let report = self
            .privacy_ui
            .report
            .as_ref()
            .ok_or("Browser record fixture is missing.")?;
        let visible = report
            .records
            .iter()
            .filter(|r| r.actionable() && record_matches(r, &self.privacy_ui.search))
            .map(|r| r.id)
            .collect::<HashSet<_>>();
        let selected = &self.privacy_ui.selected_ids;
        let valid = self.qa_fixture_mode()
            && self.privacy_ui.operation == PrivacyOperation::Idle
            && (after || (self.privacy_ui.detail_id.is_none() && !self.privacy_ui.cleanup_review))
            && selected
                .iter()
                .all(|id| report.records.iter().any(|r| r.id == *id && r.actionable()))
            && (!after
                || match label {
                    "Select visible" => selected == &visible,
                    "Clear selection" => selected.is_empty(),
                    "Details" => self
                        .privacy_ui
                        .detail_id
                        .is_some_and(|id| report.records.iter().any(|record| record.id == id)),
                    "Review" => self.privacy_ui.cleanup_review && selected.len() == 1,
                    _ => false,
                });
        if !valid {
            return Err("Browser selection included unavailable records or did not reach its expected state.".into());
        }
        let mut state = serde_json::json!({"selected_records":selected.len(),"selectable_records":visible.len(),"unavailable_records":report.records.iter().filter(|r|!r.actionable()).count(),"selected_items":report.records.iter().filter(|r|selected.contains(&r.id)).map(|r|r.item_count()).sum::<usize>()});
        if matches!(label, "Details" | "Review") {
            let details = self
                .privacy_ui
                .detail_id
                .and_then(|id| report.records.iter().find(|record| record.id == id));
            state["dialog"] = serde_json::json!(if self.privacy_ui.detail_id.is_some() {
                "details"
            } else if self.privacy_ui.cleanup_review {
                "cleanup_review"
            } else {
                "none"
            });
            state["detail_items"] = serde_json::json!(details.map(PrivacyRecord::item_count));
            state["detail_bytes"] = serde_json::json!(details.and_then(PrivacyRecord::size_bytes));
            state["detail_actionable"] = serde_json::json!(details.map(PrivacyRecord::actionable));
            state["detail_browser"] = serde_json::json!(details.map(|r| r.browser.label()));
            state["detail_source"] =
                serde_json::json!(details.and_then(PrivacyRecord::source_file));
            state["detail_cleanup_note"] =
                serde_json::json!(details.and_then(PrivacyRecord::preference_cleanup_note));
        }
        Ok(state)
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
                        self.sync_cookie_settings_owners(settings);
                    }
                    Err(error) => {
                        self.mark_cookie_settings_unverified();
                        self.privacy_ui.cookie_settings_error = Some(format!(
                            "Cookie rules could not be verified: {error}. Reload saved rules before scanning or cleanup."
                        ));
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
                    self.set_notice(
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
                    self.set_notice(
                        "Browser scan stopped. The partial rows are for review only and cannot be cleaned.".into(),
                    );
                } else if report.partial {
                    self.set_notice(format!(
                        "Scan finished with partial coverage: {} browser source or profile checks were skipped.",
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
                        if self.privacy_ui.clear_cookie_input_on_save {
                            self.privacy_ui.cookie_domain_input.clear();
                        }
                        self.privacy_ui.clear_cookie_input_on_save = false;
                        self.sync_cookie_settings_owners(settings);
                        self.privacy_ui.report = None;
                        self.privacy_ui.selected_ids.clear();
                        self.privacy_ui.cleanup_review = false;
                        self.set_notice(
                            "Cookie keep domains were saved. Scan again to apply them to results."
                                .into(),
                        );
                    }
                    Err(error) => {
                        self.privacy_ui.clear_cookie_input_on_save = false;
                        self.mark_cookie_settings_unverified();
                        self.privacy_ui.cookie_settings_error = Some(format!(
                            "Cookie-save outcome is uncertain: {error}. Reload saved rules before scanning or cleanup."
                        ));
                    }
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
                            "{} browser selections cleaned; {} skipped{}.",
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
                        self.set_notice(message);
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
                let restored_keys = self
                    .privacy_ui
                    .restore_plan
                    .as_ref()
                    .is_some_and(privacy::PrivacyRestorePlan::restores_site_storage_keys);
                let restored_preferences = self
                    .privacy_ui
                    .restore_plan
                    .as_ref()
                    .is_some_and(privacy::PrivacyRestorePlan::restores_preferences);
                let restored_sessions = self
                    .privacy_ui
                    .restore_plan
                    .as_ref()
                    .is_some_and(privacy::PrivacyRestorePlan::restores_sessions);
                self.privacy_ui.restore_plan = None;
                match result {
                    Ok(receipt) if receipt.restored && !receipt.uncertain => {
                        self.set_notice(
                            if restored_keys { "The reviewed site-storage keys were restored. A copy of the previous state was retained." } else if restored_sessions { "The reviewed pre-cleanup browser session file was restored. A copy of the previous state was retained." } else if restored_preferences { "The reviewed pre-cleanup browser preferences were restored. A copy of the previous state was retained." } else { "The reviewed pre-cleanup database was restored. A copy of the previous state was retained." }.into(),
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
            theme::action_row(ui, |ui| {
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
                theme::control_row(ui, |ui| {
                    theme::muted(ui, format!("{checked} of {profile_count} profiles selected"), t);
                    if theme::field_action(ui, "Select all", !busy) {
                        self.privacy_ui.selected_profiles = self
                            .privacy_ui
                            .profiles
                            .iter()
                            .map(|profile| profile.id.clone())
                            .collect();
                        inventory_changed = true;
                    }
                    if theme::field_action(ui, "Clear", !busy) {
                        self.privacy_ui.selected_profiles.clear();
                        inventory_changed = true;
                    }
                });
                ui.add_space(4.);
                let columns = if ui.available_width() >= 480. { 2 } else { 1 };
                let column_width = (ui.available_width() - 24. * (columns - 1) as f32) / columns as f32;
                egui::Grid::new("privacy-profile-choices")
                    .num_columns(columns)
                    .min_col_width(column_width)
                    .max_col_width(column_width)
                    .spacing(Vec2::new(24., 4.))
                    .show(ui, |ui| {
                        for (index, profile) in self.privacy_ui.profiles.iter().enumerate() {
                            let mut selected = self
                                .privacy_ui
                                .selected_profiles
                                .contains(&profile.id);
                            if theme::checkbox(
                                ui,
                                &mut selected,
                                format!("{} · {}", profile.browser.label(), profile.name),
                                !busy,
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
                            if index % columns == columns - 1 {
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
                    (PrivacyCategory::LastDownloadLocation, "Last download location"),
                    (PrivacyCategory::SnapLocation, "Snap location"),
                    (PrivacyCategory::Sessions,"Sessions"),
                    (PrivacyCategory::SavedForms,"Saved forms"),
                    (PrivacyCategory::SavedPasswords,"Saved passwords"),
                    (PrivacyCategory::SitePreferences,"Site preferences"),
                ] {
                    let mut selected = self.privacy_ui.categories.contains(&category);
                    let enabled = !busy
                        && (category != PrivacyCategory::Cookies
                            || self.privacy_ui.cookie_settings_readable);
                    if theme::checkbox(ui, &mut selected, label, enabled).changed()
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
                "Browser records show sites or field names. Private values, including stored folder paths and cookie values, are never displayed.",
                t,
            );
            if !self.privacy_ui.running.is_empty() {
                ui.add_space(4.);
                theme::action_row(ui, |ui| {
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
                theme::action_row(ui, |ui| {
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
                theme::Disclosure::new(format!(
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
        let editable = !busy && self.privacy_ui.cookie_settings_readable;
        let mut changed = false;
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Cookie keep domains").family(theme::semibold()));
                theme::muted(ui, "Matching cookies stay out of cleanup results", t);
            });
            ui.add_space(6.);
            theme::control_row(ui, |ui| {
                theme::input(ui, &mut self.privacy_ui.cookie_domain_input, 245., "example.com", editable);
                if theme::field_action(ui, "Add domain", editable) {
                    match privacy::normalize_cookie_domain(&self.privacy_ui.cookie_domain_input) {
                        Ok(domain) => {
                            let mut domains = self.privacy_ui.cookie_settings.keep_domains.clone();
                            if !domains.iter().any(|existing| existing == &domain) {
                                domains.push(domain);
                                self.begin_save_cookie_settings(domains, ctx, true);
                            } else {
                                self.privacy_ui.cookie_domain_input.clear();
                            }
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
                    theme::action_row(ui, |ui| {
                        ui.label(domain);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if theme::secondary(ui, "Remove", editable) {
                                remove = Some(index);
                            }
                        });
                    });
                }
                if let Some(index) = remove {
                    let mut domains = self.privacy_ui.cookie_settings.keep_domains.clone();
                    domains.remove(index);
                    self.begin_save_cookie_settings(domains, ctx, false);
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
                ui.label(
                    RichText::new(
                        if report
                            .records
                            .iter()
                            .any(privacy::PrivacyRecord::is_session_file)
                        {
                            "Browser data found"
                        } else {
                            "Browser records found"
                        },
                    )
                    .family(theme::semibold()),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    theme::muted(
                        ui,
                        format!(
                            "{} selected · {} available · {:.1}s",
                            report
                                .records
                                .iter()
                                .filter(|record| self.privacy_ui.selected_ids.contains(&record.id))
                                .map(|record| record.item_count())
                                .sum::<usize>(),
                            report
                                .records
                                .iter()
                                .map(|record| record.item_count())
                                .sum::<usize>(),
                            report.elapsed_ms as f64 / 1000.
                        ),
                        t,
                    );
                });
            });
            ui.add_space(6.);
            ui.horizontal_wrapped(|ui| {
                for category in PrivacyCategory::ALL.into_iter().filter(|category| {
                    matches!(
                        category,
                        PrivacyCategory::History
                            | PrivacyCategory::Cookies
                            | PrivacyCategory::Downloads
                    ) || report.categories_scanned.contains(category)
                }) {
                    let count = report
                        .records
                        .iter()
                        .filter(|record| record.category == category)
                        .map(|record| record.item_count())
                        .sum::<usize>();
                    theme::muted(ui, format!("{} {count}", category_label(category)), t);
                }
                if report.cookie_exempted > 0 {
                    theme::muted(
                        ui,
                        format!(
                            "{} cookie items kept by domain rules",
                            report.cookie_exempted
                        ),
                        t,
                    );
                }
            });
            if report
                .records
                .iter()
                .any(privacy::PrivacyRecord::is_session_file)
            {
                theme::muted(
                    ui,
                    "Session totals count files. Some rows include several files.",
                    t,
                );
            }
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
            theme::control_row(ui, |ui| {
                ui.label("Search");
                theme::input(
                    ui,
                    &mut self.privacy_ui.search,
                    220.,
                    "Site, profile, category, or record ID",
                    !busy,
                );
                if theme::field_action(ui, "Select visible", !busy && !report.cancelled) {
                    for record in report.records.iter().filter(|record| {
                        record.actionable() && record_matches(record, &self.privacy_ui.search)
                    }) {
                        self.privacy_ui.selected_ids.insert(record.id);
                    }
                }
                if theme::field_action(ui, "Clear selection", !busy) {
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
                // The outer page already scrolls. Reserve enough bounded space
                // for short result sets even when first laid out below its fold;
                // egui's default minimum otherwise leaves only one row visible.
                let visible_rows = report
                    .records
                    .iter()
                    .filter(|record| record_matches(record, &query))
                    .count()
                    .min(8);
                let has_locations = report.records.iter().any(|record| {
                    matches!(
                        record.category,
                        PrivacyCategory::LastDownloadLocation | PrivacyCategory::SnapLocation
                    )
                });
                let field_width = (ui.available_width() - if has_locations { 460. } else { 405. })
                    .clamp(100., 180.);
                theme::scroll_vertical()
                    .id_salt("privacy-records")
                    .min_scrolled_height((24. + visible_rows as f32 * 45.).clamp(64., 390.))
                    .max_height(390.)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        egui::Grid::new("privacy-record-table")
                            .num_columns(5)
                            .spacing(Vec2::new(12., 5.))
                            .striped(false)
                            .show(ui, |ui| {
                                for label in
                                    ["Select", "Browser and profile", "Type", "Site / field", ""]
                                {
                                    ui.label(RichText::new(label).family(theme::semibold()));
                                }
                                ui.end_row();
                                for record in &report.records {
                                    if !record_matches(record, &query) {
                                        continue;
                                    }
                                    let mut selected =
                                        self.privacy_ui.selected_ids.contains(&record.id);
                                    if theme::checkbox_widget(
                                        ui,
                                        &mut selected,
                                        !busy && !report.cancelled && record.actionable(),
                                    )
                                    .on_disabled_hover_text(record.unavailable_reason().unwrap_or(
                                        "Selection is unavailable while work is in progress.",
                                    ))
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
                                    if record.is_preference_field() {
                                        ui.allocate_ui_with_layout(
                                            [field_width, 36.].into(),
                                            Layout::top_down(Align::Min),
                                            |ui| {
                                                ui.set_width(field_width);
                                                ui.add(egui::Label::new(&record.site).wrap());
                                            },
                                        );
                                    } else {
                                        ui.add(
                                            egui::Label::new(&record.site)
                                                .truncate()
                                                .show_tooltip_when_elided(false),
                                        )
                                        .on_hover_text(&record.site);
                                    }
                                    ui.horizontal(|ui| {
                                        if theme::row_action(ui, "Details", true).clicked() {
                                            self.privacy_ui.detail_id = Some(record.id);
                                        }
                                        if theme::row_action(
                                            ui,
                                            "Review",
                                            !busy && !report.cancelled && record.actionable(),
                                        )
                                        .on_disabled_hover_text(
                                            record.unavailable_reason().unwrap_or(
                                                "Review is unavailable while work is in progress.",
                                            ),
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
                theme::Disclosure::new(format!("Skipped browser data · {}", report.skipped_count))
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
            theme::action_row(ui, |ui| {
                ui.label(RichText::new("Browser recovery copies").family(theme::semibold()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if theme::secondary(ui, "Refresh recovery", !busy) {
                        self.refresh_privacy_recovery_options();
                    }
                });
            });
            theme::muted(
                ui,
                "Restore requires the browser to be closed and its current data to match the saved post-cleanup state.",
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
        egui::Modal::new(egui::Id::new("privacy-record-details")).frame(theme::dialog_frame(t)).show(ctx, |ui| {
            ui.set_width(450.);
            ui.heading(if record.is_session_file(){"Browser session details"}else{"Browser record details"});
            ui.add_space(10.);
            detail_line(ui, "Browser", record.browser.label());
            detail_line(ui, "Profile", &record.profile_name);
            detail_line(ui, "Category", category_label(record.category));
            detail_line(ui, if record.is_database_table(){"Browser table"}else if record.is_session_file(){"Browser data"}else if record.is_preference_field() { "Browser field" } else { "Site" }, &record.site);
            if let Some(note) = record.preference_cleanup_note() {
                ui.label(RichText::new("Cleanup:").family(theme::semibold()));
                ui.add(egui::Label::new(note).wrap());
            }
            if let Some(source) = record.source_file() { detail_line(ui, "Source file", &source); }
            if let Some(bytes) = record.size_bytes() {
                detail_line(ui, "Storage group", &format!("{} · {}", theme::counted_label(record.item_count(), "file", "files"), crate::app::size(bytes)));
                if record.actionable() { detail_line(ui, "Cleanup", "Move reviewed files to Trash"); }
            }
            if let Some(reason) = record.unavailable_reason() {
                ui.label(RichText::new("Cleanup:").family(theme::semibold()));
                ui.add(egui::Label::new(reason).wrap());
            }
            detail_line(ui, "Current record ID", &record.id.to_string());
            ui.add_space(8.);
            theme::muted(
                ui,
                "The list shows a site or browser field name. Private values, full URLs, page titles and passwords are not displayed.",
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
        let selected = report
            .records
            .iter()
            .filter(|record| self.privacy_ui.selected_ids.contains(&record.id))
            .cloned()
            .collect::<Vec<_>>();
        let conflicts = self
            .privacy_ui
            .running
            .iter()
            .filter(|process| {
                selected
                    .iter()
                    .any(|record| record.browser.conflicts_with(process))
            })
            .count();
        let cancelled = report.cancelled;
        let partial = report.partial;
        egui::Modal::new(egui::Id::new("privacy-cleanup-review")).frame(theme::dialog_frame(t)).show(ctx, |ui| {
            ui.set_width(470.);
            ui.heading("Review browser cleanup");
            ui.add_space(10.);
            ui.label(format!(
                "Clean {} selected items from {} browser profile{}?",
                selected.iter().map(|record| record.item_count()).sum::<usize>(),
                selected.iter().map(|record| record.profile_id.as_str()).collect::<HashSet<_>>().len(),
                if selected.iter().map(|record| record.profile_id.as_str()).collect::<HashSet<_>>().len() == 1 { "" } else { "s" }
            ));
            ui.add_space(8.);
            for category in PrivacyCategory::ALL {
                let count = selected.iter().filter(|record| record.category == category).map(|record| record.item_count()).sum::<usize>();
                if count > 0 {
                    theme::muted(ui, if category==PrivacyCategory::Sessions {format!("{count} session {}",if count==1 {"file"}else{"files"})} else {format!("{count} {} {}", category_label(category), if count == 1 { "record" } else { "records" })}, t);
                }
            }
            let sources = selected.iter().filter_map(privacy::PrivacyRecord::source_file).collect::<Vec<_>>();
            for source in sources.iter().take(8) { detail_line(ui, "File", source); }
            if sources.len() > 8 { theme::muted(ui, format!("{} more reviewed files", sources.len()-8), t); }
            ui.add_space(8.);
            theme::muted(
                ui,
                if selected.iter().any(|record| record.size_bytes().is_some()) {
                    "Selected browser files move to Trash. Other records use recovery copies. Only reviewed, unchanged items are cleaned; close the browser first."
                } else if selected.iter().any(|record|record.category==PrivacyCategory::SavedPasswords) {
                    "Recovery copies are saved before changes. All rows in selected legacy password tables are removed; close the browser first."
                } else {
                    "Recovery copies are saved before changes. Only reviewed browser records are removed or reset. Passwords and unrelated browser settings are kept; close the browser first."
                },
                t,
            );
            for category in [PrivacyCategory::LastDownloadLocation, PrivacyCategory::SnapLocation, PrivacyCategory::Sessions] {
                let mut notes=HashSet::new();
                let notes=selected.iter().filter(|record| record.category == category).filter_map(privacy::PrivacyRecord::preference_cleanup_note).filter(|note|notes.insert(*note)).collect::<Vec<_>>();
                let scoped=category==PrivacyCategory::Sessions && notes.len()>1;
                for note in notes {
                    ui.add_space(6.);
                    if scoped {
                        let browsers=selected.iter().filter(|record|record.category==category && record.preference_cleanup_note()==Some(note)).map(|record|record.browser.label()).collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>().join(", ");
                        theme::muted(ui,format!("{browsers}: {note}"),t);
                    } else { theme::muted(ui, note, t); }
                }
            }
            if let Some(note)=selected.iter().find(|record|record.is_database_table()).and_then(|record|record.preference_cleanup_note()) {
                ui.add_space(6.);theme::muted(ui,note,t);
            }
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
                if theme::primary(ui, "Clean selected records", t, can_clean) {
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
                        if theme::checkbox_widget(
                            ui,
                            &mut selected,
                            !busy,
                        )
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
        let keys = plan.restores_site_storage_keys();
        let preferences = plan.restores_preferences();
        let sessions = plan.restores_sessions();
        egui::Modal::new(egui::Id::new("privacy-restore-review")).frame(theme::dialog_frame(t)).show(ctx, |ui| {
            ui.set_width(470.);
            ui.heading(if keys { "Review site-storage restore" } else if sessions { "Review browser session restore" } else if preferences { "Review browser preferences restore" } else { "Review database restore" });
            ui.add_space(8.);
            ui.label(format!(
                "{} for {}?",
                if keys { "Restore the reviewed site-storage keys".to_owned() } else if sessions { format!("Restore the pre-cleanup {} session file", plan.database_name()) } else if preferences { "Restore the pre-cleanup browser preferences".to_owned() } else { format!("Restore the pre-cleanup {} database", plan.database_name()) }, plan.profile_name()
            ));
            ui.add_space(8.);
            theme::muted(
                ui,
                if keys { "Only keys removed by this cleanup will be put back. The store must still match its reviewed post-cleanup state. A copy of the current log and a durable restore intent will be saved first." } else if sessions { "The session file must still match its reviewed post-cleanup state. A current copy and restore intent are saved before the reviewed pre-cleanup bytes are restored. Close the browser first." } else if preferences { "The browser preferences must still match their reviewed post-cleanup state. The current file is backed up before the saved copy is restored. Close the browser first. Passwords and unrelated settings are preserved." } else { "The exact current database was rechecked against its saved post-cleanup bytes, metadata and schema. A fresh copy of the current state and a durable restore intent will be saved before the database is changed." },
                t,
            );
            ui.add_space(14.);
            ui.horizontal(|ui| {
                if theme::secondary(ui, if keys || preferences || sessions { "Keep current data" } else { "Keep current database" }, true) {
                    self.privacy_ui.restore_review = false;
                    self.privacy_ui.restore_plan = None;
                }
                if theme::primary(ui, if keys { "Restore reviewed keys" } else { "Restore reviewed copy" }, t, !self.busy()) {
                    self.begin_privacy_restore(ctx);
                }
            });
        });
    }

    fn begin_privacy_inventory(&mut self, ctx: &egui::Context) {
        if self.qa_fixture_mode()
            || self.busy()
            || self.privacy_ui.operation != PrivacyOperation::Idle
        {
            return;
        }
        self.privacy_ui.operation = PrivacyOperation::Loading;
        self.privacy_ui.loaded = false;
        self.privacy_ui.report = None;
        self.privacy_ui.selected_ids.clear();
        self.progress = "Checking known browser profile locations…".into();
        let data_dir = self.data_dir.clone();
        let ctx = ctx.clone();
        let (tx, rx) = crate::worker_events::channel();
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
        if self.qa_fixture_mode()
            || self.busy()
            || self.privacy_ui.operation != PrivacyOperation::Idle
        {
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
        let categories = PrivacyCategory::ALL
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
        let (tx, rx) = crate::worker_events::channel();
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
        if self.qa_fixture_mode()
            || self.busy()
            || self.privacy_ui.operation != PrivacyOperation::Idle
        {
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
        let (tx, rx) = crate::worker_events::channel();
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
        if self.qa_fixture_mode()
            || self.busy()
            || self.privacy_ui.operation != PrivacyOperation::Idle
        {
            return;
        }
        self.privacy_ui.operation = PrivacyOperation::ClosingBrowsers;
        self.progress = "Refreshing running-browser status…".into();
        let ctx = ctx.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let result = privacy::running_browsers();
            let _ = tx.send(Event::Privacy(PrivacyEvent::RunningUpdated(result)));
            ctx.request_repaint();
        });
    }

    fn begin_save_cookie_settings(
        &mut self,
        domains: Vec<String>,
        ctx: &egui::Context,
        clear_input_on_success: bool,
    ) {
        if self.qa_fixture_mode()
            || self.busy()
            || self.privacy_ui.operation != PrivacyOperation::Idle
            || !self.privacy_ui.cookie_settings_readable
        {
            return;
        }
        if self.data_dir.as_os_str().is_empty() {
            self.privacy_ui.cookie_settings_error =
                Some("Application data storage is unavailable.".into());
            return;
        }
        self.privacy_ui.operation = PrivacyOperation::SavingSettings;
        self.privacy_ui.clear_cookie_input_on_save = clear_input_on_success;
        self.progress = "Saving cookie keep domains…".into();
        let data_dir = self.data_dir.clone();
        let ctx = ctx.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let result = privacy::save_cookie_exception_settings(&data_dir, &domains);
            let _ = tx.send(Event::Privacy(PrivacyEvent::SettingsSaved(result)));
            ctx.request_repaint();
        });
    }

    fn begin_privacy_cleanup(&mut self, ctx: &egui::Context) {
        if self.qa_fixture_mode()
            || self.busy()
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
        let (tx, rx) = crate::worker_events::channel();
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
        if self.qa_fixture_mode()
            || self.busy()
            || self.privacy_ui.operation != PrivacyOperation::Idle
            || self.data_dir.as_os_str().is_empty()
        {
            return;
        }
        self.privacy_ui.operation = PrivacyOperation::PreparingRestore;
        self.progress = "Rechecking the exact browser database state…".into();
        let data_dir = self.data_dir.clone();
        let ctx = ctx.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let result = privacy::prepare_privacy_restore(&data_dir, id);
            let _ = tx.send(Event::Privacy(PrivacyEvent::RestorePrepared { id, result }));
            ctx.request_repaint();
        });
    }

    fn begin_privacy_restore(&mut self, ctx: &egui::Context) {
        if self.qa_fixture_mode()
            || self.busy()
            || self.privacy_ui.operation != PrivacyOperation::Idle
        {
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
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let result = privacy::restore_privacy_database(&data_dir, &plan);
            let _ = tx.send(Event::Privacy(PrivacyEvent::Restored(result)));
            ctx.request_repaint();
        });
    }

    fn refresh_privacy_recovery_options(&mut self) {
        if self.qa_fixture_mode() {
            return;
        }
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
            self.set_notice("Browser scan choices changed. Run a new scan before cleanup.".into());
        }
    }
}

fn category_label(category: PrivacyCategory) -> &'static str {
    match category {
        PrivacyCategory::History => "History",
        PrivacyCategory::Cookies => "Cookies",
        PrivacyCategory::Downloads => "Downloads",
        PrivacyCategory::LastDownloadLocation => "Last download",
        PrivacyCategory::SnapLocation => "Snap location",
        PrivacyCategory::Sessions => "Session files",
        PrivacyCategory::SavedForms => "Saved forms",
        PrivacyCategory::SavedPasswords => "Saved passwords",
        PrivacyCategory::SitePreferences => "Site preferences",
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
        ui.add(
            egui::Label::new(value.to_owned())
                .truncate()
                .show_tooltip_when_elided(false),
        )
        .on_hover_text(value);
    });
}
