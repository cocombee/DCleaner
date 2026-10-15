use super::*;
use crate::theme;
use dcleaner::{
    effects::{self, EffectHistory, EffectJournal},
    programs::InstalledProgram,
    software::{
        self, SoftwareItem, SoftwarePreference, SoftwarePreferenceState, SoftwareSettings,
        SoftwareSnapshot, SoftwareStatus, UpdateReceipt, UpdateRequest, UpdateVerification,
    },
};
#[cfg(debug_assertions)]
use dcleaner::{
    programs::{ProgramIdentity, RegistryHive, RegistrySource, RegistryView},
    software::{SoftwareIdentity, WingetRow},
};
use serde::Serialize;
use std::{cmp::Ordering, collections::HashSet, sync::atomic::AtomicBool};

#[derive(Default)]
pub(super) struct SoftwareUi {
    intro_fixture: bool,
    snapshot: Option<SoftwareSnapshot>,
    attempted: bool,
    loading: bool,
    load_error: Option<String>,
    query: String,
    tab: SoftwareTab,
    sort: SoftwareSort,
    descending: bool,
    app_updates_collapsed: bool,
    selected: Option<String>,
    dialog: Option<SoftwareDialog>,
    settings: SoftwareSettings,
    settings_error: Option<String>,
    history: Vec<EffectHistory>,
    history_error: Option<String>,
    refresh_after_update: bool,
    selected_updates: HashSet<String>,
    eligible_updates: HashSet<String>,
    snapshot_revision: u64,
    last_scan_completed_at: Option<chrono::DateTime<chrono::Utc>>,
    batch_running: bool,
    batch_report: Option<BatchReport>,
    #[cfg(debug_assertions)]
    qa_more_open: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SoftwareTab {
    #[default]
    Outdated,
    UpToDate,
    SkippedIgnored,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SoftwareSort {
    #[default]
    Name,
    Installed,
    Available,
    Importance,
    Status,
}

#[derive(Clone)]
enum SoftwareDialog {
    UpdateReview(UpdateRequest),
    BatchReview(BatchReview),
    Details(SoftwareItem),
}

#[derive(Clone)]
struct BatchReview {
    snapshot_revision: u64,
    requests: Vec<UpdateRequest>,
    skipped: Vec<BatchSkipped>,
    not_selected: usize,
    error: Option<String>,
}

#[derive(Clone, Debug)]
struct BatchSkipped {
    display_name: String,
    reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BatchItemState {
    Verified,
    Uncertain,
    Failed,
    NotAttempted,
}

#[derive(Clone, Debug)]
struct BatchItemOutcome {
    request_id: Uuid,
    display_name: String,
    target_version: String,
    state: BatchItemState,
    detail: String,
}

#[derive(Clone, Debug, Default)]
pub(super) struct BatchReport {
    outcomes: Vec<BatchItemOutcome>,
    skipped: Vec<BatchSkipped>,
    not_selected: usize,
    stop_reason: Option<String>,
}

pub(super) enum SoftwareEvent {
    Progress(String),
    Loaded {
        inventory: Result<SoftwareSnapshot, String>,
        settings: Result<SoftwareSettings, String>,
        history: Result<Vec<EffectHistory>, String>,
        completed_at: chrono::DateTime<chrono::Utc>,
    },
    UpdateFinished {
        request_id: Uuid,
        display_name: String,
        journal_created: bool,
        result: Result<UpdateReceipt, String>,
        journal_error: Option<String>,
    },
    BatchUpdateFinished(BatchReport),
}

#[derive(Serialize)]
struct UpdateFailureReceipt<'a> {
    request_id: Uuid,
    error: &'a str,
}

impl App {
    #[cfg(debug_assertions)]
    pub(super) fn qa_software_state(&self) -> serde_json::Value {
        let dialog = match self.software_ui.dialog.as_ref() {
            Some(SoftwareDialog::UpdateReview(_)) => Some("update_review"),
            Some(SoftwareDialog::BatchReview(_)) => Some("batch_review"),
            Some(SoftwareDialog::Details(_)) => Some("details"),
            None => None,
        };
        let visible_eligible_updates = self
            .software_ui
            .snapshot
            .as_ref()
            .map(|snapshot| {
                let visible: Vec<_> = snapshot
                    .items
                    .iter()
                    .filter(|item| {
                        tab_matches(self.software_ui.tab, item)
                            && matches_query(item, &self.software_ui.query)
                    })
                    .cloned()
                    .collect();
                visible_eligible_keys(&visible, &self.software_ui.eligible_updates)
            })
            .unwrap_or_default();
        let selected_visible_updates = visible_eligible_updates
            .iter()
            .filter(|key| self.software_ui.selected_updates.contains(*key))
            .count();
        serde_json::json!({
            "tab": software_tab_name(self.software_ui.tab),
            "sort": software_sort_name(self.software_ui.sort),
            "descending": self.software_ui.descending,
            "snapshot_present": self.software_ui.snapshot.is_some(),
            "row_count": self.software_ui.snapshot.as_ref().map_or(0, |snapshot| snapshot.items.len()),
            "selected": self.software_ui.selected.is_some(),
            "eligible_updates": self.software_ui.eligible_updates.len(),
            "selected_update_count": self.software_ui.selected_updates.len(),
            "visible_eligible_updates": visible_eligible_updates.len(),
            "selected_visible_updates": selected_visible_updates,
            "app_updates_expanded": !self.software_ui.app_updates_collapsed,
            "dialog": dialog,
            "more_open": self.software_ui.qa_more_open.is_some(),
            "worker_active": self.worker.is_some(),
            "fixture_mode": self.qa_fixture_mode(),
        })
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_software_action_precondition(&self, label: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Software action checks require isolated fixture mode.".into());
        }
        let has_snapshot = self.software_ui.snapshot.is_some();
        let visible = self.software_ui.snapshot.as_ref().is_some_and(|snapshot| {
            snapshot.items.iter().any(|item| {
                tab_matches(self.software_ui.tab, item)
                    && matches_query(item, &self.software_ui.query)
            })
        });
        let visible_eligible_count = self
            .software_ui
            .snapshot
            .as_ref()
            .map(|snapshot| {
                let filtered: Vec<_> = snapshot
                    .items
                    .iter()
                    .filter(|item| {
                        tab_matches(self.software_ui.tab, item)
                            && matches_query(item, &self.software_ui.query)
                    })
                    .cloned()
                    .collect();
                visible_eligible_keys(&filtered, &self.software_ui.eligible_updates).len()
            })
            .unwrap_or_default();
        let can_dismiss = !self.busy();
        let valid = match label {
            "Outdated software" | "Up-to-date software" | "Skipped & ignored" => has_snapshot,
            "Sort Software" | "Sort Current version" | "Sort New version" | "Sort Importance" => {
                has_snapshot
            }
            "Select all eligible updates" | "Select App updates" => {
                can_dismiss
                    && visible_eligible_count > 0
                    && self.software_ui.tab == SoftwareTab::Outdated
            }
            "Collapse App updates" => {
                visible
                    && self.software_ui.tab == SoftwareTab::Outdated
                    && !self.software_ui.app_updates_collapsed
            }
            "Expand App updates" => {
                visible
                    && self.software_ui.tab == SoftwareTab::Outdated
                    && self.software_ui.app_updates_collapsed
            }
            "Update" => {
                can_dismiss
                    && self.software_ui.snapshot.as_ref().is_some_and(|snapshot| {
                        snapshot.items.iter().any(|item| {
                            tab_matches(self.software_ui.tab, item)
                                && matches_query(item, &self.software_ui.query)
                                && item.can_update()
                        })
                    })
            }
            "Update all" => {
                can_dismiss
                    && self.software_ui.dialog.is_none()
                    && self.software_ui.selected_updates.is_empty()
                    && !self.software_ui.eligible_updates.is_empty()
            }
            "Update selected" => {
                can_dismiss
                    && self.software_ui.dialog.is_none()
                    && !self.software_ui.selected_updates.is_empty()
            }
            "More" | "More options" => {
                can_dismiss && visible && self.software_ui.qa_more_open.is_none()
            }
            "Details" | "View details" => {
                can_dismiss
                    && self.software_ui.dialog.is_none()
                    && self.software_ui.qa_more_open.is_some()
                    && visible
            }
            "Cancel" | "Close" | "Close dialog" => can_dismiss && self.software_ui.dialog.is_some(),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(format!(
                "Software action precondition is not satisfied: {label}"
            ))
        }
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_software_action_state(
        &self,
        label: &str,
    ) -> Result<serde_json::Value, String> {
        let state = self.qa_software_state();
        let valid = match label {
            "Outdated software" | "Up-to-date software" | "Skipped & ignored" => {
                state["tab"] == label
            }
            "Sort Software" => state["sort"] == "Software",
            "Sort Current version" => state["sort"] == "Current version",
            "Sort New version" => state["sort"] == "New version",
            "Sort Importance" => state["sort"] == "Importance",
            "Update" => state["dialog"] == "update_review",
            "Update all" | "Update selected" => state["dialog"] == "batch_review",
            "Select App updates" => {
                state["selected_visible_updates"] == state["visible_eligible_updates"]
                    && state["visible_eligible_updates"] != 0
            }
            "Collapse App updates" => state["app_updates_expanded"] == false,
            "Expand App updates" => state["app_updates_expanded"] == true,
            "Select all eligible updates" => {
                state["selected_visible_updates"] == state["visible_eligible_updates"]
                    && state["visible_eligible_updates"] != 0
            }
            "More" | "More options" => state["more_open"] == true,
            "Details" | "View details" => state["dialog"] == "details",
            "Cancel" | "Close" | "Close dialog" => state["dialog"].is_null(),
            _ => false,
        };
        if valid {
            Ok(state)
        } else {
            Err(format!(
                "Software action did not reach its expected state: {label}"
            ))
        }
    }

    #[cfg(debug_assertions)]
    pub(super) fn seed_software_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Software Updater visual fixtures require fixture mode.".into());
        }
        if !matches!(
            case,
            "software-intro"
                | "software-empty"
                | "software-populated"
                | "software-details"
                | "software-update-review"
                | "software-error"
                | "software-batch-review"
        ) {
            return Err(format!("Unsupported Software Updater fixture: {case}"));
        }
        if case == "software-intro" {
            self.software_ui = SoftwareUi {
                intro_fixture: true,
                ..SoftwareUi::default()
            };
            self.error = None;
            self.notice = None;
            self.progress.clear();
            return Ok(());
        }

        let items = if matches!(
            case,
            "software-populated"
                | "software-details"
                | "software-update-review"
                | "software-batch-review"
        ) {
            vec![
                software_qa_item(
                    "Example Editor",
                    "Example.Editor",
                    "1.0.0",
                    Some("1.1.0"),
                    SoftwareStatus::UpdateAvailable,
                ),
                software_qa_item(
                    "Example Browser",
                    "Example.Browser",
                    "2.0.0",
                    Some("2.1.0"),
                    SoftwareStatus::UpdateAvailable,
                ),
                software_qa_item(
                    "Example Runtime",
                    "Example.Runtime",
                    "3.4.0",
                    None,
                    SoftwareStatus::Current,
                ),
            ]
        } else {
            Vec::new()
        };
        let selected_item = items.first().cloned();
        let snapshot = SoftwareSnapshot {
            items,
            registration_issues: Vec::new(),
        };
        let mut selected_updates = HashSet::new();
        let eligible_updates = batch_eligible_keys(&snapshot);
        let mut dialog = if case == "software-details" {
            selected_item.clone().map(SoftwareDialog::Details)
        } else {
            None
        };
        if case == "software-batch-review" {
            if let Some(item) = snapshot.items.first() {
                selected_updates.insert(item.row_key());
            }
            dialog = Some(SoftwareDialog::BatchReview(
                prepare_batch_review(&snapshot, &selected_updates, 0)
                    .expect("fixed software batch QA fixture is valid"),
            ));
        }
        if case == "software-update-review"
            && let Some(item) = snapshot.items.first()
        {
            dialog = Some(SoftwareDialog::UpdateReview(
                software::prepare_update(item).expect("fixed software update QA fixture is valid"),
            ));
        }
        self.software_ui = SoftwareUi {
            snapshot: if case == "software-error" {
                None
            } else {
                Some(snapshot)
            },
            attempted: true,
            loading: false,
            load_error: (case == "software-error")
                .then(|| "Synthetic fixture error; WinGet and registry were not queried.".into()),
            selected: selected_item.as_ref().map(SoftwareItem::row_key),
            dialog,
            selected_updates,
            eligible_updates,
            history: Vec::new(),
            history_error: None,
            ..SoftwareUi::default()
        };
        self.error = None;
        self.notice = None;
        self.progress.clear();
        Ok(())
    }

    pub(super) fn software_overview_status(&self) -> String {
        self.software_counts()
            .map(|(outdated, _, _)| format!("{outdated} outdated"))
            .unwrap_or_else(|| "Not scanned".to_owned())
    }

    pub(super) fn software_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if self.software_intro_active() {
            if self.feature_intro(
                ui,
                t,
                "software",
                "Find available software updates",
                "Scan installed packages against the configured WinGet source, then review each exact package before starting an update.",
                &[
                    (
                        theme::Icon::Update,
                        "Scan for updates",
                        "Read update offers from the configured WinGet source; other catalogues are not included.",
                    ),
                    (
                        theme::Icon::Info,
                        "Keep control of each change",
                        "Review package identity and version first. Some updates use the vendor’s interactive installer or require a restart.",
                    ),
                ],
            ) {
                self.start_software_scan(ctx);
            }
            return;
        }
        if !self.qa_fixture_mode()
            && (!self.software_ui.attempted || self.software_ui.refresh_after_update)
            && !self.busy()
        {
            self.begin_software_load(ctx);
        }
        let tab_counts = self.software_counts();
        let scan_time = self
            .software_ui
            .last_scan_completed_at
            .as_ref()
            .map(|time| format!("Last scan {} UTC", time.format("%Y-%m-%d %H:%M")));
        ui.set_width(ui.available_width());
        let mut rescan = false;
        ui.horizontal_wrapped(|ui| {
            for (tab, icon, label, count) in [
                (
                    SoftwareTab::Outdated,
                    theme::Icon::Update,
                    "Outdated software",
                    tab_counts.map(|counts| counts.0),
                ),
                (
                    SoftwareTab::UpToDate,
                    theme::Icon::WindowCheck,
                    "Up-to-date software",
                    tab_counts.map(|counts| counts.1),
                ),
                (
                    SoftwareTab::SkippedIgnored,
                    theme::Icon::EyeOff,
                    "Skipped & ignored",
                    tab_counts.map(|counts| counts.2),
                ),
            ] {
                let response = theme::tab_with_icon_count(
                    ui,
                    self.software_ui.tab == tab,
                    icon,
                    label,
                    count,
                    t,
                );
                if response.clicked() {
                    self.software_ui.tab = tab;
                    (self.software_ui.sort, self.software_ui.descending) = sort_for_tab_change(
                        self.software_ui.sort,
                        self.software_ui.descending,
                        tab,
                    );
                }
            }
        });
        ui.add_space(12.);
        theme::action_row(ui, |ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let response = theme::header_action(ui, "Rescan", !self.busy());
                rescan = response;
                if let Some(scan_time) = scan_time.as_deref() {
                    ui.label(RichText::new("Last scan").color(t.muted))
                        .on_hover_text(scan_time);
                }
            });
        });
        if rescan {
            self.software_ui.attempted = false;
            self.software_ui.refresh_after_update = false;
            self.begin_software_load(ctx);
        }
        if self.software_ui.loading {
            ui.add_space(8.);
            ui.horizontal(|ui| {
                ui.spinner();
                theme::muted(ui, "Reading WinGet and installed-program registrations…", t);
            });
        }
        if let Some(error) = self.software_ui.load_error.clone() {
            ui.add_space(8.);
            status_card(ui, t, "Software inventory unavailable", &error);
        }
        if let Some(error) = self.software_ui.settings_error.as_deref() {
            ui.add_space(8.);
            status_card(
                ui,
                t,
                "Saved updater choices are unavailable",
                &format!(
                    "{error} Existing bytes are preserved; skip and ignore controls are disabled until this is resolved."
                ),
            );
        }
        if let Some(report) = self.software_ui.batch_report.as_ref() {
            ui.add_space(8.);
            self.software_batch_results(ui, t, report);
        }
        ui.add_space(8.);
        self.software_table(ui, t, ctx);

        if self.software_ui.history_error.is_some() {
            self.software_history(ui, t);
        } else {
            egui::CollapsingHeader::new(format!(
                "Updater history ({})",
                self.software_ui.history.len()
            ))
            .id_salt("software-history-disclosure")
            .default_open(false)
            .show(ui, |ui| self.software_history(ui, t));
        }
        ui.add_space(12.);
        egui::CollapsingHeader::new("Updater details")
            .default_open(false)
            .id_salt("software-updater-details")
            .show(ui, |ui| {
                theme::muted(ui, "This version reads and updates packages reported by WinGet's winget source. It does not read Microsoft Store listings or claim parity for CCleaner's separate vendor catalogues, severity metadata, reboot handling, or update simulator.", t);
            });
    }

    pub(super) fn software_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if self.software_intro_active() {
            let compact = !self.feature_intro_wide(ctx);
            let mut start = false;
            ui.horizontal_wrapped(|ui| {
                theme::muted(
                    ui,
                    if compact {
                        "Start a read-only software update scan"
                    } else {
                        "Choose Scan now in the introduction to check available updates"
                    },
                    t,
                );
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if compact && theme::primary(ui, "Scan now", t, !self.busy()) {
                        start = true;
                    }
                });
            });
            if start {
                self.start_software_scan(ctx);
            }
            return;
        }
        if self.software_ui.batch_running {
            ui.horizontal_wrapped(|ui| {
                theme::muted(
                    ui,
                    "WinGet updates run one at a time. Stop is checked after the current update finishes.",
                    t,
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if theme::secondary(ui, "Stop after current update", true) {
                        self.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                });
            });
            return;
        }
        if self.software_ui.loading {
            theme::muted(ui, "WinGet inventory is running.", t);
            return;
        }
        if self.busy() {
            theme::muted(
                ui,
                "Wait for the current background operation to finish.",
                t,
            );
            return;
        }
        let available = self.software_ui.eligible_updates.len();
        if self.software_ui.snapshot.is_none() {
            theme::muted(ui, "Scan installed packages before reviewing updates.", t);
            return;
        }
        let selected = self.software_ui.selected_updates.len();
        let visible_selected = self.software_ui.snapshot.as_ref().map_or(0, |snapshot| {
            snapshot
                .items
                .iter()
                .filter(|item| {
                    tab_matches(self.software_ui.tab, item)
                        && matches_query(item, &self.software_ui.query)
                        && self.software_ui.selected_updates.contains(&item.row_key())
                })
                .count()
        });
        let hidden_selected = selected.saturating_sub(visible_selected);
        ui.horizontal_wrapped(|ui| {
            theme::muted(
                ui,
                if selected == 0 {
                    format!("{available} eligible updates available")
                } else {
                    if hidden_selected > 0 {
                        format!("{selected} selected · {hidden_selected} outside this view")
                    } else {
                        format!("{selected} selected")
                    }
                },
                t,
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if selected == 0 {
                    if theme::primary(ui, "Update all", t, available > 0) {
                        self.open_batch_review(false);
                    }
                } else if theme::primary(ui, "Update selected", t, selected > 0 && available > 0) {
                    self.open_batch_review(true);
                }
            });
        });
    }

    pub(super) fn software_dialog(&mut self, ctx: &egui::Context) {
        if self.software_ui.dialog.is_some()
            && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            let details_are_safe_to_close = matches!(
                self.software_ui.dialog.as_ref(),
                Some(SoftwareDialog::Details(_))
            );
            if details_are_safe_to_close || !self.busy() {
                self.software_ui.dialog = None;
            }
            return;
        }
        let Some(dialog) = self.software_ui.dialog.clone() else {
            return;
        };
        let t = theme::tokens(self.prefs.dark);
        match dialog {
            SoftwareDialog::Details(item) => {
                let mut close = false;
                let modal_width = (ctx.content_rect().width() - 32.).min(560.).max(280.);
                let body_height = dialog_body_max_height(ctx, 88.0);
                let response = egui::Modal::new(egui::Id::new("software-details-dialog"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(modal_width);
                        close |= software_dialog_heading(ui, &item.row.name, true);
                        ui.add_space(8.);
                        egui::ScrollArea::vertical()
                            .max_height(body_height)
                            .auto_shrink([false, true])
                            .show(ui, |body| self.software_details(body, t, &item));
                        ui.add_space(8.);
                        ui.separator();
                        theme::action_row(ui, |ui| {
                            let enabled = !self.busy()
                                && self.software_ui.settings_error.is_none()
                                && item.identity.is_some();
                            if matches!(
                                item.status,
                                SoftwareStatus::SkippedVersion | SoftwareStatus::Ignored
                            ) {
                                if theme::secondary(
                                    ui,
                                    if item.status == SoftwareStatus::Ignored {
                                        "Stop ignoring updates"
                                    } else {
                                        "Unskip update"
                                    },
                                    enabled,
                                ) {
                                    self.restore_software_preference(&item);
                                    close |= self.error.is_none();
                                }
                            } else {
                                if theme::secondary(
                                    ui,
                                    "Skip update",
                                    enabled && item.row.available_version.is_some(),
                                ) {
                                    self.skip_software_version(&item);
                                    close |= self.error.is_none();
                                }
                                if theme::secondary(ui, "Ignore updates", enabled) {
                                    self.ignore_software_package(&item);
                                    close |= self.error.is_none();
                                }
                            }
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                close |= theme::primary(ui, "Close", t, true);
                            });
                        });
                    });
                if close || response.should_close() {
                    self.software_ui.dialog = None;
                }
            }
            SoftwareDialog::UpdateReview(request) => {
                let mut accept = false;
                let mut cancel = false;
                let can_dismiss = !self.busy();
                let modal_width = (ctx.content_rect().width() - 32.).min(510.).max(280.);
                let body_height = dialog_body_max_height(ctx, 56.0);
                let response = egui::Modal::new(egui::Id::new("software-update-review"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(modal_width);
                        cancel |= software_dialog_heading(
                            ui,
                            "Review software update",
                            can_dismiss,
                        );
                        ui.add_space(8.);
                        egui::ScrollArea::vertical()
                            .max_height(body_height)
                            .auto_shrink([false, true])
                            .show(ui, |body| {
                                theme::muted(
                                    body,
                                    "WinGet opens its interactive update prompt after you confirm.",
                                    t,
                                );
                                body.add_space(12.);
                                review_row(body, "Program", &request.display_name, t);
                                review_row(body, "Package ID", &request.package_id, t);
                                review_row(body, "Source", &request.source_id, t);
                                review_row(body, "Installed version", &request.installed_version, t);
                                review_row(body, "Requested version", &request.target_version, t);
                                egui::CollapsingHeader::new("Command details")
                                    .default_open(false)
                                    .show(body, |body| {
                                        body.add(
                                            egui::Label::new(
                                                RichText::new(format!(
                                                    "winget upgrade --id \"{}\" --exact --source \"{}\" --version \"{}\" --interactive",
                                                    request.package_id,
                                                    request.source_id,
                                                    request.target_version
                                                ))
                                                .monospace(),
                                            )
                                            .wrap(),
                                        );
                                        theme::muted(body, "This is an informational preview. DCleaner rechecks the same registration and source row before launch; it does not accept agreements or use silent-install flags.", t);
                                    });
                            });
                        ui.add_space(8.);
                        ui.separator();
                        ui.add_space(8.);
                        ui.horizontal_wrapped(|actions| {
                            if theme::secondary(actions, "Cancel", can_dismiss) {
                                cancel = true;
                            }
                            if theme::primary(actions, "Run reviewed update", t, can_dismiss) {
                                accept = true;
                            }
                        });
                    });
                if can_dismiss && (cancel || response.should_close()) {
                    self.software_ui.dialog = None;
                } else if can_dismiss && accept {
                    self.begin_software_update(request, ctx);
                }
            }
            SoftwareDialog::BatchReview(mut review) => {
                let mut accept = false;
                let mut cancel = false;
                let can_dismiss = !self.busy();
                let modal_width = (ctx.content_rect().width() - 32.).min(620.).max(280.);
                let body_height = dialog_body_max_height(ctx, 56.0);
                let response = egui::Modal::new(egui::Id::new("software-batch-review"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(modal_width);
                        cancel |= software_dialog_heading(
                            ui,
                            "Review software updates",
                            can_dismiss,
                        );
                        ui.add_space(8.);
                        egui::ScrollArea::vertical()
                            .max_height(body_height)
                            .auto_shrink([false, true])
                            .show(ui, |body| {
                                theme::muted(body, "Each package is updated separately in WinGet's interactive prompt. DCleaner rechecks the exact registration and offer before every launch.", t);
                                body.add_space(10.);
                                body.label(RichText::new(format!(
                                    "Updates in this review ({})",
                                    review.requests.len()
                                )).family(theme::semibold()));
                                body.add_space(4.);
                                for request in &review.requests {
                                    body.group(|row| {
                                        row.set_width(row.available_width());
                                        row.label(RichText::new(&request.display_name).family(theme::semibold()));
                                        theme::muted(row, format!("{} · {} → {}", request.package_id, request.installed_version, request.target_version), t);
                                    });
                                }
                                if review.not_selected > 0 {
                                    body.add_space(8.);
                                    theme::muted(body, format!("{} other eligible update{} were not selected.", review.not_selected, if review.not_selected == 1 { "" } else { "s" }), t);
                                }
                                if !review.skipped.is_empty() {
                                    body.add_space(8.);
                                    body.label(RichText::new(format!("Not included ({})", review.skipped.len())).family(theme::semibold()));
                                    for skipped in &review.skipped {
                                        body.group(|row| {
                                            row.set_width(row.available_width());
                                            row.label(RichText::new(&skipped.display_name).family(theme::semibold()));
                                            theme::muted(row, &skipped.reason, t);
                                        });
                                    }
                                }
                                if let Some(error) = review.error.as_deref() {
                                    body.add_space(8.);
                                    body.colored_label(t.attention, error);
                                }
                            });
                        ui.add_space(8.);
                        ui.separator();
                        ui.add_space(8.);
                        ui.horizontal_wrapped(|actions| {
                            if theme::secondary(actions, "Cancel", can_dismiss) {
                                cancel = true;
                            }
                            let run_label = format!("Run {} reviewed updates", review.requests.len());
                            if theme::primary(
                                actions,
                                &run_label,
                                t,
                                can_dismiss
                                    && !review.requests.is_empty()
                                    && review.error.is_none(),
                            ) {
                                accept = true;
                            }
                        });
                    });
                if can_dismiss && (cancel || response.should_close()) {
                    self.software_ui.dialog = None;
                } else if can_dismiss && accept {
                    match self.begin_software_batch(&review, ctx) {
                        Ok(()) => self.software_ui.dialog = None,
                        Err(error) => {
                            review.error = Some(error);
                            self.software_ui.dialog = Some(SoftwareDialog::BatchReview(review));
                        }
                    }
                }
            }
        }
    }

    pub(super) fn software_event(&mut self, event: SoftwareEvent) {
        match event {
            SoftwareEvent::Progress(progress) => self.progress = progress,
            SoftwareEvent::Loaded {
                inventory,
                settings,
                history,
                completed_at,
            } => {
                self.worker = None;
                self.software_ui.loading = false;
                self.software_ui.attempted = true;
                self.software_ui.last_scan_completed_at = Some(completed_at);
                self.software_ui.refresh_after_update = false;
                match settings {
                    Ok(settings) => {
                        self.software_ui.settings = settings;
                        self.software_ui.settings_error = None;
                    }
                    Err(error) => {
                        self.software_ui.settings_error = Some(error);
                    }
                }
                match inventory {
                    Ok(snapshot) => {
                        self.software_ui.snapshot_revision =
                            self.software_ui.snapshot_revision.saturating_add(1);
                        let eligible_keys = batch_eligible_keys(&snapshot);
                        self.software_ui.snapshot = Some(snapshot);
                        self.software_ui.load_error = None;
                        self.software_ui.eligible_updates = eligible_keys.clone();
                        self.software_ui
                            .selected_updates
                            .retain(|key| eligible_keys.contains(key));
                        if self.software_ui.selected.as_ref().is_some_and(|key| {
                            !self
                                .software_ui
                                .snapshot
                                .as_ref()
                                .unwrap()
                                .items
                                .iter()
                                .any(|item| &item.row_key() == key)
                        }) {
                            self.software_ui.selected = None;
                        }
                    }
                    Err(error) => {
                        self.software_ui.snapshot_revision =
                            self.software_ui.snapshot_revision.saturating_add(1);
                        self.software_ui.snapshot = None;
                        self.software_ui.selected_updates.clear();
                        self.software_ui.eligible_updates.clear();
                        self.software_ui.load_error = Some(error);
                    }
                }
                match history {
                    Ok(history) => {
                        self.software_ui.history = history;
                        self.software_ui.history_error = None;
                    }
                    Err(error) => self.software_ui.history_error = Some(error),
                }
            }
            SoftwareEvent::UpdateFinished {
                request_id,
                display_name,
                journal_created,
                result,
                journal_error,
            } => {
                self.worker = None;
                self.software_ui.dialog = None;
                self.software_ui.refresh_after_update = true;
                match result {
                    Ok(receipt) if receipt.request_id == request_id => {
                        self.error = None;
                        self.notice = Some(match receipt.verification {
                            UpdateVerification::Verified => format!(
                                "{} now reports version {} in both WinGet and its registration. The requested update is verified.{}",
                                display_name,
                                receipt.target_version,
                                journal_error
                                    .as_deref()
                                    .map(|error| format!(
                                        " The journal receipt could not be saved: {error}"
                                    ))
                                    .unwrap_or_default()
                            ),
                            UpdateVerification::Uncertain => format!(
                                "WinGet finished for {display_name}, but the requested version could not be verified. Review Updater History before retrying.{}",
                                receipt
                                    .verification_note
                                    .as_deref()
                                    .map(|note| format!(" {note}"))
                                    .unwrap_or_default()
                            ),
                        });
                    }
                    Ok(_) => {
                        self.error = Some("The update receipt did not match the reviewed request; the result is uncertain.".into());
                    }
                    Err(error) => {
                        self.error = Some(if journal_created {
                            format!(
                                "The reviewed update for {display_name} was not confirmed: {error}. Review Updater History before retrying."
                            )
                        } else {
                            format!(
                                "The update for {display_name} did not start because its durable intent could not be recorded: {error}"
                            )
                        });
                    }
                }
                if let Some(error) = journal_error {
                    self.error = Some(format!(
                        "The update outcome was recorded in memory but its receipt could not be saved: {error}. The journal remains uncertain; review before retrying."
                    ));
                }
            }
            SoftwareEvent::BatchUpdateFinished(report) => {
                self.worker = None;
                self.software_ui.batch_running = false;
                self.software_ui.refresh_after_update = true;
                self.software_ui.selected_updates.clear();
                let verified = report
                    .outcomes
                    .iter()
                    .filter(|outcome| outcome.state == BatchItemState::Verified)
                    .count();
                let uncertain = report
                    .outcomes
                    .iter()
                    .filter(|outcome| outcome.state == BatchItemState::Uncertain)
                    .count();
                let failed = report
                    .outcomes
                    .iter()
                    .filter(|outcome| outcome.state == BatchItemState::Failed)
                    .count();
                let not_attempted = report
                    .outcomes
                    .iter()
                    .filter(|outcome| outcome.state == BatchItemState::NotAttempted)
                    .count();
                self.notice = Some(format!(
                    "Batch review finished: {verified} verified, {uncertain} uncertain, {failed} failed, {not_attempted} not started. Review the per-package results before trying again."
                ));
                self.software_ui.batch_report = Some(report);
            }
        }
    }

    fn begin_software_load(&mut self, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        self.software_ui.loading = true;
        self.software_ui.attempted = true;
        self.software_ui.refresh_after_update = false;
        self.software_ui.load_error = None;
        self.progress = "Reading WinGet package inventory".into();
        let root = self.data_dir.clone();
        let previous_settings = self.software_ui.settings.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let repaint = ctx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Software(SoftwareEvent::Progress(
                "Checking the explicit winget source without accepting agreements".into(),
            )));
            repaint.request_repaint();
            let settings = software::load_settings(&root);
            let effective_settings = settings
                .clone()
                .unwrap_or_else(|_| previous_settings.clone());
            let inventory = software::installed_software(&effective_settings)
                .map_err(|error| error.to_string());
            let history = effects::history(&root, "software-update");
            let _ = tx.send(Event::Software(SoftwareEvent::Loaded {
                inventory,
                settings: settings.map_err(|error| error.to_string()),
                history,
                completed_at: chrono::Utc::now(),
            }));
            repaint.request_repaint();
        });
    }

    fn software_intro_active(&self) -> bool {
        if self.qa_fixture_mode() {
            self.software_ui.intro_fixture
        } else {
            !self.feature_seen("software")
        }
    }

    fn start_software_scan(&mut self, ctx: &egui::Context) {
        self.mark_feature_seen("software");
        self.begin_software_load(ctx);
    }

    fn begin_software_update(&mut self, request: UpdateRequest, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        let display_name = request.display_name.clone();
        self.software_ui.dialog = None;
        self.progress = format!("Preparing durable update intent for {display_name}");
        self.error = None;
        let root = self.data_dir.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let repaint = ctx.clone();
        thread::spawn(move || {
            let event =
                match EffectJournal::create(&root, "software-update", request.request_id, &request)
                {
                    Err(error) => SoftwareEvent::UpdateFinished {
                        request_id: request.request_id,
                        display_name,
                        journal_created: false,
                        result: Err(format!("Durable intent could not be written: {error}")),
                        journal_error: None,
                    },
                    Ok(mut journal) => {
                        let _ = tx.send(Event::Software(SoftwareEvent::Progress(
                            "WinGet is running the reviewed update in an interactive window".into(),
                        )));
                        repaint.request_repaint();
                        let result = software::run_native_update(&request)
                            .map_err(|error| error.to_string());
                        let journal_error = match &result {
                            Ok(receipt) => journal.finish(receipt.journal_state(), receipt).err(),
                            Err(error) => journal
                                .finish(
                                    "failed",
                                    &UpdateFailureReceipt {
                                        request_id: request.request_id,
                                        error,
                                    },
                                )
                                .err(),
                        };
                        SoftwareEvent::UpdateFinished {
                            request_id: request.request_id,
                            display_name,
                            journal_created: true,
                            result,
                            journal_error,
                        }
                    }
                };
            let _ = tx.send(Event::Software(event));
            repaint.request_repaint();
        });
    }

    fn open_batch_review(&mut self, selected_only: bool) {
        let Some(snapshot) = self.software_ui.snapshot.as_ref() else {
            self.error =
                Some("Read the installed software inventory before reviewing updates.".into());
            return;
        };
        let empty = HashSet::new();
        let selected = if selected_only {
            &self.software_ui.selected_updates
        } else {
            &empty
        };
        match prepare_batch_review(snapshot, selected, self.software_ui.snapshot_revision) {
            Ok(review) => {
                self.software_ui.dialog = Some(SoftwareDialog::BatchReview(review));
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn begin_software_batch(
        &mut self,
        review: &BatchReview,
        ctx: &egui::Context,
    ) -> Result<(), String> {
        if self.busy() || self.qa_fixture_mode() {
            return Err("Batch updates cannot start while another operation is running.".into());
        }
        validate_batch_review(
            review,
            self.software_ui.snapshot.as_ref(),
            self.software_ui.snapshot_revision,
        )?;
        let requests = review.requests.clone();
        let skipped = review.skipped.clone();
        let not_selected = review.not_selected;
        let root = self.data_dir.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        self.software_ui.batch_running = true;
        self.software_ui.batch_report = None;
        self.error = None;
        self.progress = format!("Preparing {} reviewed software updates", requests.len());
        let repaint = ctx.clone();
        thread::spawn(move || {
            let progress_tx = tx.clone();
            let progress_repaint = repaint.clone();
            let mut report = run_batch_sequence(
                &requests,
                &cancel,
                |index, request| {
                    let _ = progress_tx.send(Event::Software(SoftwareEvent::Progress(format!(
                        "Software update {} of {} · {}",
                        index + 1,
                        requests.len(),
                        request.display_name
                    ))));
                    progress_repaint.request_repaint();
                },
                |request| run_journaled_update(&root, request),
            );
            report.skipped = skipped;
            report.not_selected = not_selected;
            let _ = tx.send(Event::Software(SoftwareEvent::BatchUpdateFinished(report)));
            repaint.request_repaint();
        });
        Ok(())
    }

    fn open_software_review(&mut self, item: &SoftwareItem) {
        match software::prepare_update(item) {
            Ok(request) => self.software_ui.dialog = Some(SoftwareDialog::UpdateReview(request)),
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn software_counts(&self) -> Option<(usize, usize, usize)> {
        let items = &self.software_ui.snapshot.as_ref()?.items;
        Some(software_tab_counts(items))
    }

    fn software_table(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let Some(snapshot) = self.software_ui.snapshot.clone() else {
            if !self.software_ui.loading && self.software_ui.load_error.is_none() {
                theme::muted(ui, "Select Refresh to read WinGet packages.", t);
            }
            return;
        };
        let row_actions_enabled = !self.busy();
        let preference_actions_enabled =
            row_actions_enabled && self.software_ui.settings_error.is_none();
        let eligible_keys = self.software_ui.eligible_updates.clone();
        let mut items: Vec<SoftwareItem> = snapshot
            .items
            .into_iter()
            .filter(|item| tab_matches(self.software_ui.tab, item))
            .filter(|item| matches_query(item, &self.software_ui.query))
            .collect();
        sort_items(
            &mut items,
            self.software_ui.sort,
            self.software_ui.descending,
        );
        let visible_eligible = visible_eligible_keys(&items, &eligible_keys);
        egui::ScrollArea::horizontal().id_salt("software-table-columns").auto_shrink([false, true]).show(ui, |ui| {
        ui.set_min_width(580.);
        let table_width = ui.available_width().max(580.);
        let action_width = 108.0;
        let state_width = 88.0;
        let installed_width = 88.0;
        let available_width = 72.0;
        let name_width = (table_width - action_width - state_width - installed_width - available_width - 32.).max(192.);
        let previous_y_spacing = ui.spacing().item_spacing.y;
        ui.spacing_mut().item_spacing.y = 0.;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            ui.allocate_ui_with_layout(
                [name_width, 32.].into(),
                Layout::left_to_right(Align::Center),
                |ui| {
                    ui.set_min_width(name_width);
                    ui.set_max_width(name_width);
                    if self.software_ui.tab == SoftwareTab::Outdated && !visible_eligible.is_empty()
                    {
                        let selected_count = visible_eligible
                            .iter()
                            .filter(|key| self.software_ui.selected_updates.contains(*key))
                            .count();
                        let all_selected = selected_count == visible_eligible.len();
                        let mixed = selected_count > 0 && !all_selected;
                        let mut select_all = all_selected;
                        if theme::checkbox_named(
                            ui,
                            &mut select_all,
                            mixed,
                            "Select all eligible updates",
                            row_actions_enabled,
                        )
                        .changed()
                        {
                            set_visible_update_selection(
                                &mut self.software_ui.selected_updates,
                                &visible_eligible,
                                select_all,
                            );
                        }
                    } else {
                        ui.add_space(22.);
                    }
                    if sortable_heading(
                        ui,
                        "Software",
                        (name_width - 32.).max(60.),
                        self.software_ui.sort == SoftwareSort::Name,
                        self.software_ui.descending,
                        t,
                    )
                    .clicked()
                    {
                        select_header_sort(
                            &mut self.software_ui.sort,
                            &mut self.software_ui.descending,
                            SoftwareSort::Name,
                        );
                    }
                },
            );
            for (heading, width, sort) in [
                ("Current version", installed_width, SoftwareSort::Installed),
                ("New version", available_width, SoftwareSort::Available),
            ] {
                if sortable_heading(
                    ui,
                    heading,
                    width,
                    self.software_ui.sort == sort,
                    self.software_ui.descending,
                    t,
                )
                .clicked()
                {
                    select_header_sort(
                        &mut self.software_ui.sort,
                        &mut self.software_ui.descending,
                        sort,
                    );
                }
            }
            let state_sort = if self.software_ui.tab == SoftwareTab::Outdated {
                SoftwareSort::Importance
            } else {
                SoftwareSort::Status
            };
            let state_heading = if state_sort == SoftwareSort::Importance {
                "Importance"
            } else {
                "Status"
            };
            let state_header = sortable_heading(
                ui,
                state_heading,
                state_width,
                self.software_ui.sort == state_sort,
                self.software_ui.descending,
                t,
            );
            let state_header = if state_sort == SoftwareSort::Importance {
                state_header.on_hover_text(
                    "WinGet does not provide an importance rating; all listed values are Unavailable.",
                )
            } else {
                state_header
            };
            if state_header.clicked() {
                select_header_sort(
                    &mut self.software_ui.sort,
                    &mut self.software_ui.descending,
                    state_sort,
                );
            }
            table_heading(ui, "Actions", action_width, t);
        });
        ui.add_space(3.);
        ui.separator();
        let body_height =
            (ctx.content_rect().bottom() - ui.cursor().top() - 74. - 28. - 50.).max(120.);
        let has_app_updates_group =
            self.software_ui.tab == SoftwareTab::Outdated && !items.is_empty();
        let app_updates_expanded = !self.software_ui.app_updates_collapsed;
        let group_row_count = usize::from(has_app_updates_group);
        let row_count = if has_app_updates_group {
            group_row_count + if app_updates_expanded { items.len() } else { 0 }
        } else {
            items.len()
        };
        egui::ScrollArea::vertical()
            .id_salt("software-table-body")
            .max_height(body_height)
            .auto_shrink([false, true])
            .show_rows(ui, 44.0, row_count, |rows_ui, visible_rows| {
                for virtual_index in visible_rows {
                    if has_app_updates_group && virtual_index == 0 {
                        let selected_count = visible_eligible
                            .iter()
                            .filter(|key| self.software_ui.selected_updates.contains(*key))
                            .count();
                        let all_selected = !visible_eligible.is_empty()
                            && selected_count == visible_eligible.len();
                        let mixed = selected_count > 0 && !all_selected;
                        let mut select_group = all_selected;
                        let group_response = rows_ui.allocate_ui_with_layout(
                            [table_width, 44.].into(),
                            Layout::left_to_right(Align::Center),
                            |row| {
                                row.set_min_height(44.0);
                                row.spacing_mut().item_spacing.x = 8.0;
                                if selected_count > 0 {
                                    row.painter().rect_filled(
                                        egui::Rect::from_min_size(
                                            row.cursor().min,
                                            [table_width, 44.].into(),
                                        ),
                                        0.,
                                        t.tint,
                                    );
                                }
                                let checkbox = theme::checkbox_named(
                                    row,
                                    &mut select_group,
                                    mixed,
                                    "Select App updates",
                                    row_actions_enabled && !visible_eligible.is_empty(),
                                );
                                if checkbox.changed() {
                                    set_visible_update_selection(
                                        &mut self.software_ui.selected_updates,
                                        &visible_eligible,
                                        select_group,
                                    );
                                }
                                let label_width = (table_width - 68.0).max(60.0);
                                let group_label = row.add_sized(
                                    [label_width, 40.],
                                    egui::Button::new((
                                        RichText::new(format!("App updates ({})", items.len()))
                                            .family(theme::semibold())
                                            .color(t.foreground),
                                        egui::Atom::grow(),
                                    ))
                                    .frame(false)
                                    .truncate(),
                                );
                                let disclosure_label = if app_updates_expanded {
                                    "Collapse App updates"
                                } else {
                                    "Expand App updates"
                                };
                                let disclosure =
                                    theme::disclosure(row, disclosure_label, app_updates_expanded);
                                if group_label.clicked() || disclosure.clicked() {
                                    self.software_ui.app_updates_collapsed =
                                        !self.software_ui.app_updates_collapsed;
                                }
                            },
                        );
                        let rect = group_response.response.rect;
                        rows_ui.painter().hline(
                            rect.x_range(),
                            rect.bottom(),
                            egui::Stroke::new(1., t.border),
                        );
                        continue;
                    }
                    let index = virtual_index.saturating_sub(group_row_count);
                    if has_app_updates_group && !app_updates_expanded {
                        continue;
                    }
                    let Some(item) = items.get(index) else {
                        continue;
                    };
                    let key = item.row_key();
                    rows_ui.push_id(&key, |ui| {
                        let row_response = ui.allocate_ui_with_layout(
                            [table_width, 44.].into(),
                            Layout::left_to_right(Align::Center),
                            |row| {
                                row.set_min_height(44.0);
                                row.spacing_mut().item_spacing.x = 8.0;
                                row.spacing_mut().item_spacing.y = previous_y_spacing;
                                let selected = self.software_ui.selected_updates.contains(&key);
                                if selected {
                                    row.painter().rect_filled(
                                        egui::Rect::from_min_size(
                                            row.cursor().min,
                                            [table_width, 44.].into(),
                                        ),
                                        0.,
                                        t.tint,
                                    );
                                }
                                let icon = if self.qa_fixture_mode() {
                                    None
                                } else {
                                    item.registration
                                        .as_ref()
                                        .and_then(|program| program.icon_resource())
                                };
                                let name = row
                                    .allocate_ui_with_layout(
                                        [name_width, 40.].into(),
                                        Layout::left_to_right(Align::Center),
                                        |cell| {
                                            cell.set_min_width(name_width);
                                            cell.set_max_width(name_width);
                                            cell.spacing_mut().item_spacing.x = 8.;
                                            cell.add_space(32.);
                                            let mut update_selected =
                                                self.software_ui.selected_updates.contains(&key);
                                            if eligible_keys.contains(&key) {
                                                let checkbox_label = format!(
                                                    "Select update for {} ({})",
                                                    item.row.name, item.row.package_id
                                                );
                                                let response = theme::checkbox_named(
                                                    cell,
                                                    &mut update_selected,
                                                    false,
                                                    &checkbox_label,
                                                    row_actions_enabled,
                                                );
                                                if response.changed() {
                                                    if update_selected {
                                                        self.software_ui
                                                            .selected_updates
                                                            .insert(key.clone());
                                                    } else {
                                                        self.software_ui
                                                            .selected_updates
                                                            .remove(&key);
                                                    }
                                                }
                                            } else {
                                                cell.add_space(22.);
                                            }
                                            self.app_icons.show(cell, icon.as_deref(), 22.0);
                                            cell.scope(|cell| {
                                                cell.visuals_mut().selection.bg_fill = t.tint;
                                                cell.visuals_mut().selection.stroke.color =
                                                    t.foreground;
                                                cell.spacing_mut().button_padding.x = 0.;
                                                cell.add_sized(
                                                    [
                                                        (name_width - 98.).clamp(48., name_width),
                                                        40.,
                                                    ],
                                                    egui::Button::selectable(
                                                        false,
                                                        (
                                                            RichText::new(&item.row.name)
                                                                .family(theme::semibold())
                                                                .color(t.foreground),
                                                            egui::Atom::grow(),
                                                        ),
                                                    )
                                                    .frame(false)
                                                    .truncate(),
                                                )
                                            })
                                            .inner
                                        },
                                    )
                                    .inner;
                                if name.clicked() {
                                    self.software_ui.selected = Some(key.clone());
                                }
                                name.on_hover_text(&item.row.name)
                                    .on_hover_text(&item.row.package_id);
                                theme::table_cell(
                                    row,
                                    RichText::new(
                                        item.row.installed_version.as_deref().unwrap_or("—"),
                                    )
                                    .color(t.muted),
                                    installed_width,
                                    40.,
                                );
                                theme::table_cell(
                                    row,
                                    RichText::new(
                                        item.row.available_version.as_deref().unwrap_or("—"),
                                    )
                                    .color(status_color(item.status, t)),
                                    available_width,
                                    40.,
                                );
                                if self.software_ui.tab == SoftwareTab::Outdated {
                                    theme::table_cell(
                                        row,
                                        RichText::new("Unavailable").color(t.muted),
                                        state_width,
                                        40.,
                                    )
                                    .on_hover_text("WinGet does not provide an importance rating.");
                                } else {
                                    theme::table_cell(
                                        row,
                                        RichText::new(status_label(item))
                                            .color(status_color(item.status, t)),
                                        state_width,
                                        40.,
                                    );
                                }
                                let mut primary_clicked = false;
                                row.allocate_ui_with_layout(
                                    [72., 40.].into(),
                                    Layout::left_to_right(Align::Center),
                                    |primary| {
                                        primary.set_min_width(72.0);
                                        primary.set_max_width(72.0);
                                        if item.can_update() {
                                            primary_clicked = theme::row_action(
                                                primary,
                                                "Update",
                                                row_actions_enabled,
                                            )
                                            .on_hover_text("Review this update before starting it")
                                            .clicked();
                                        } else if item.status == SoftwareStatus::UpdateAvailable {
                                            let reason = item
                                        .registration
                                        .as_ref()
                                        .map(|program| {
                                            if program.system_component {
                                                "Windows marks this package as a system component."
                                            } else if program.protected {
                                                "The installed-program registration is protected."
                                            } else {
                                                "This package did not pass update identity checks."
                                            }
                                        })
                                        .or(item.association_note.as_deref())
                                        .unwrap_or("No eligible update action is available.");
                                            primary
                                                .label(
                                                    RichText::new("Blocked")
                                                        .color(t.muted)
                                                        .size(theme::FONT_CAPTION),
                                                )
                                                .on_hover_text(reason);
                                        } else {
                                            theme::muted(primary, "—", t);
                                        }
                                    },
                                );
                                if primary_clicked {
                                    self.open_software_review(item);
                                }
                                let more = theme::row_more(row, true);
                                #[cfg(debug_assertions)]
                                if self.qa_fixture_mode() {
                                    theme::record_fixture_control(row, "More", &more);
                                }
                                #[cfg(debug_assertions)]
                                if self.qa_fixture_mode() && more.clicked() {
                                    self.software_ui.qa_more_open =
                                        if self.software_ui.qa_more_open.as_deref() == Some(&key) {
                                            None
                                        } else {
                                            Some(key.clone())
                                        };
                                }
                                egui::Popup::menu(&more).show(|ui| {
                                    let details = theme::menu_action(
                                        ui,
                                        theme::Icon::Info,
                                        "Details",
                                        true,
                                    );
                                    if details.clicked() {
                                        self.software_ui.selected = Some(key.clone());
                                        self.software_ui.dialog =
                                            Some(SoftwareDialog::Details(item.clone()));
                                        #[cfg(debug_assertions)]
                                        {
                                            self.software_ui.qa_more_open = None;
                                        }
                                        ui.close();
                                    }
                                    ui.separator();
                                    if let Some(identity) = item.identity.as_ref() {
                                        let preference = self
                                            .software_ui
                                            .settings
                                            .preference_for(identity)
                                            .map(|value| value.state);
                                        match preference {
                                            Some(SoftwarePreferenceState::SkipVersion) => {
                                                if theme::menu_action(
                                                    ui,
                                                    theme::Icon::Undo,
                                                    "Restore skipped version",
                                                    preference_actions_enabled,
                                                )
                                                .clicked()
                                                {
                                                    self.restore_software_preference(item);
                                                    ui.close();
                                                }
                                            }
                                            Some(SoftwarePreferenceState::Ignored) => {
                                                if theme::menu_action(
                                                    ui,
                                                    theme::Icon::Undo,
                                                    "Restore ignored package",
                                                    preference_actions_enabled,
                                                )
                                                .clicked()
                                                {
                                                    self.restore_software_preference(item);
                                                    ui.close();
                                                }
                                            }
                                            None if item.row.available_version.is_some() => {
                                                if theme::menu_action(
                                                    ui,
                                                    theme::Icon::Forward,
                                                    "Skip this version",
                                                    preference_actions_enabled,
                                                )
                                                .clicked()
                                                {
                                                    self.skip_software_version(item);
                                                    ui.close();
                                                }
                                                if theme::menu_action(
                                                    ui,
                                                    theme::Icon::EyeOff,
                                                    "Ignore package",
                                                    preference_actions_enabled,
                                                )
                                                .clicked()
                                                {
                                                    self.ignore_software_package(item);
                                                    ui.close();
                                                }
                                            }
                                            None => {
                                                if theme::menu_action(
                                                    ui,
                                                    theme::Icon::EyeOff,
                                                    "Ignore package",
                                                    preference_actions_enabled,
                                                )
                                                .clicked()
                                                {
                                                    self.ignore_software_package(item);
                                                    ui.close();
                                                }
                                            }
                                        }
                                    } else {
                                        theme::muted(
                                    ui,
                                    "No unique installed registration matches this package.",
                                    t,
                                );
                                    }
                                });
                            },
                        );
                        let rect = row_response.response.rect;
                        ui.painter().hline(
                            rect.x_range(),
                            rect.bottom(),
                            egui::Stroke::new(1., t.border),
                        );
                    });
                }
            });
        ui.spacing_mut().item_spacing.y = previous_y_spacing;
        });
        if items.is_empty() {
            ui.add_space(8.);
            theme::muted(ui, "No packages match this view.", t);
        }
        if !snapshot.registration_issues.is_empty() {
            ui.add_space(8.);
            egui::CollapsingHeader::new("Registration read issues")
                .id_salt("software-registration-errors")
                .show(ui, |ui| {
                    for issue in &snapshot.registration_issues {
                        theme::muted(ui, issue, t);
                    }
                });
        }
    }

    fn software_details(&self, ui: &mut egui::Ui, t: Tokens, item: &SoftwareItem) {
        detail(
            ui,
            "Current version",
            item.row.installed_version.as_deref().unwrap_or("Unknown"),
            t,
        );
        detail(
            ui,
            "Available version",
            item.row
                .available_version
                .as_deref()
                .unwrap_or("No update listed"),
            t,
        );
        detail(ui, "Importance", "Unavailable", t);
        detail(ui, "Last updated", "Unknown", t);
        ui.add_space(8.);
        egui::CollapsingHeader::new("Advanced details").id_salt("software-details-advanced").default_open(false).show(ui, |ui| {
            theme::muted(ui, "WinGet does not provide an importance rating or a reliable last-update date.", t);
            detail(ui, "Status", status_label(item), t);
            detail(ui, "Publisher", item.registration.as_ref().and_then(|program| program.publisher.as_deref()).unwrap_or("Not exposed by WinGet"), t);
            detail(ui, "Package ID", &item.row.package_id, t);
            detail(ui, "Source", &item.row.source_id, t);
            if let Some(program) = item.registration.as_ref() {
                detail(ui, "Registration identity", &program.identity.stable_id(), t);
                detail(ui, "Registry view", match program.source.view {
                    dcleaner::programs::RegistryView::Registry32 => "32-bit",
                    dcleaner::programs::RegistryView::Registry64 => "64-bit",
                }, t);
                detail(ui, "Install location", &program.install_location.as_ref().map(|path| path.display().to_string()).unwrap_or_else(|| "Not registered".into()), t);
            } else if let Some(note) = item.association_note.as_deref() {
                ui.add_space(4.);
                ui.colored_label(t.attention, note);
                theme::muted(ui, "The row stays visible, but update and per-registration settings are disabled until an exact registration match is found.", t);
            }
            if let Some(note) = item.preference_note.as_deref() {
                ui.add_space(5.);
                theme::muted(ui, note, t);
            }
        });
    }

    fn software_batch_results(&self, ui: &mut egui::Ui, t: Tokens, report: &BatchReport) {
        let verified = report
            .outcomes
            .iter()
            .filter(|outcome| outcome.state == BatchItemState::Verified)
            .count();
        let uncertain = report
            .outcomes
            .iter()
            .filter(|outcome| outcome.state == BatchItemState::Uncertain)
            .count();
        let failed = report
            .outcomes
            .iter()
            .filter(|outcome| outcome.state == BatchItemState::Failed)
            .count();
        let not_attempted = report
            .outcomes
            .iter()
            .filter(|outcome| outcome.state == BatchItemState::NotAttempted)
            .count();
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Batch update results").family(theme::semibold()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    theme::muted(
                        ui,
                        format!("{verified} verified · {uncertain} uncertain · {failed} failed · {not_attempted} not started"),
                        t,
                    );
                });
            });
            if let Some(reason) = report.stop_reason.as_deref() {
                ui.add_space(4.);
                ui.colored_label(t.attention, reason);
            }
            for outcome in &report.outcomes {
                ui.add_space(6.);
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    let (label, color) = match outcome.state {
                        BatchItemState::Verified => ("Verified", t.primary),
                        BatchItemState::Uncertain => ("Uncertain", t.attention),
                        BatchItemState::Failed => ("Failed", t.attention),
                        BatchItemState::NotAttempted => ("Not started", t.muted),
                    };
                    ui.label(RichText::new(label).family(theme::semibold()).color(color));
                    ui.label(RichText::new(format!("{} · {}", outcome.display_name, outcome.target_version)).family(theme::semibold()));
                });
                theme::muted(ui, &outcome.detail, t);
                if outcome.state == BatchItemState::Uncertain {
                    theme::muted(ui, format!("Request {} · review Updater History and rescan before trying again.", outcome.request_id), t);
                }
            }
            if !report.skipped.is_empty() {
                ui.add_space(8.);
                egui::CollapsingHeader::new(format!("Not included in the review ({})", report.skipped.len()))
                    .id_salt("software-batch-skipped-results")
                    .show(ui, |ui| {
                        for skipped in &report.skipped {
                            ui.label(RichText::new(&skipped.display_name).family(theme::semibold()));
                            theme::muted(ui, &skipped.reason, t);
                        }
                    });
            }
            if report.not_selected > 0 {
                ui.add_space(4.);
                theme::muted(ui, format!("{} eligible updates were not selected for this batch.", report.not_selected), t);
            }
        });
    }

    fn software_history(&self, ui: &mut egui::Ui, t: Tokens) {
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Updater history").family(theme::semibold()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    theme::muted(ui, "Durable local journal", t);
                });
            });
            ui.add_space(8.);
            if let Some(error) = self.software_ui.history_error.as_deref() {
                theme::muted(ui, format!("History unavailable: {error}"), t);
            } else if self.software_ui.history.is_empty() {
                theme::muted(ui, "No update attempts recorded.", t);
            } else {
                for entry in self.software_ui.history.iter().take(6) {
                    ui.separator();
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(history_state(&entry.state)).family(theme::semibold()));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            theme::muted(ui, format_date(&entry.date), t);
                        });
                    });
                    let package = entry.intent.get("package_id").and_then(serde_json::Value::as_str).unwrap_or("package identity unavailable");
                    let version = entry.intent.get("target_version").and_then(serde_json::Value::as_str).unwrap_or("version unavailable");
                    theme::muted(ui, format!("{package} · requested {version}"), t);
                    if entry.state == "uncertain" || entry.state == "handed_off" {
                        ui.colored_label(t.attention, "The process launch is not proof of an installed update. Review the latest inventory before retrying.");
                    }
                    if let Some(receipt) = entry.receipt.as_ref() {
                        if let Some(note) = receipt.get("verification_note").and_then(serde_json::Value::as_str) {
                            theme::muted(ui, note, t);
                        }
                    }
                }
            }
        });
    }

    fn skip_software_version(&mut self, item: &SoftwareItem) {
        let (Some(identity), Some(version)) = (&item.identity, &item.row.available_version) else {
            self.error = Some(
                "This package has no exact registered identity or available version to skip."
                    .into(),
            );
            return;
        };
        self.persist_preference(SoftwarePreference {
            identity: identity.clone(),
            state: SoftwarePreferenceState::SkipVersion,
            skipped_version: Some(version.clone()),
        });
    }

    fn ignore_software_package(&mut self, item: &SoftwareItem) {
        let Some(identity) = &item.identity else {
            self.error =
                Some("Only a package matched to one exact registration can be ignored.".into());
            return;
        };
        self.persist_preference(SoftwarePreference {
            identity: identity.clone(),
            state: SoftwarePreferenceState::Ignored,
            skipped_version: None,
        });
    }

    fn restore_software_preference(&mut self, item: &SoftwareItem) {
        if self.qa_fixture_mode() {
            return;
        }
        let Some(identity) = &item.identity else {
            return;
        };
        if self.software_ui.settings_error.is_some() {
            self.error = Some(
                "Saved updater choices cannot be changed until the settings file can be read."
                    .into(),
            );
            return;
        }
        let mut proposed = self.software_ui.settings.clone();
        if !proposed.restore(identity) {
            return;
        }
        self.save_proposed_software_settings(proposed);
    }

    fn persist_preference(&mut self, preference: SoftwarePreference) {
        if self.qa_fixture_mode() {
            return;
        }
        if self.software_ui.settings_error.is_some() {
            self.error = Some(
                "Saved updater choices cannot be changed until the settings file can be read."
                    .into(),
            );
            return;
        }
        let mut proposed = self.software_ui.settings.clone();
        if let Err(error) = proposed.set(preference) {
            self.error = Some(error.to_string());
            return;
        }
        self.save_proposed_software_settings(proposed);
    }

    fn save_proposed_software_settings(&mut self, proposed: SoftwareSettings) {
        if self.qa_fixture_mode() {
            return;
        }
        match software::save_settings(&self.data_dir, &proposed) {
            Ok(()) => {
                self.software_ui.settings = proposed;
                self.rebuild_software_snapshot();
                self.error = None;
                self.notice = Some(
                    "The updater choice was saved and can be restored from this package row."
                        .into(),
                );
            }
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn rebuild_software_snapshot(&mut self) {
        let Some(current) = self.software_ui.snapshot.as_ref() else {
            return;
        };
        let rows = current.items.iter().map(|item| item.row.clone()).collect();
        let registrations: Vec<InstalledProgram> = current
            .items
            .iter()
            .filter_map(|item| item.registration.clone())
            .collect();
        self.software_ui.snapshot = Some(software::build_snapshot(
            rows,
            &registrations,
            current.registration_issues.clone(),
            &self.software_ui.settings,
        ));
        self.software_ui.snapshot_revision = self.software_ui.snapshot_revision.saturating_add(1);
        if let Some(snapshot) = self.software_ui.snapshot.as_ref() {
            let eligible_keys = batch_eligible_keys(snapshot);
            self.software_ui.eligible_updates = eligible_keys.clone();
            self.software_ui
                .selected_updates
                .retain(|key| eligible_keys.contains(key));
        }
    }
}

fn batch_eligible_keys(snapshot: &SoftwareSnapshot) -> HashSet<String> {
    let mut counts = std::collections::HashMap::<String, usize>::new();
    let mut package_counts = std::collections::HashMap::<(String, String), usize>::new();
    for item in &snapshot.items {
        *counts.entry(item.row_key()).or_default() += 1;
        *package_counts.entry(package_source_key(item)).or_default() += 1;
    }
    snapshot
        .items
        .iter()
        .filter(|item| {
            item.can_update()
                && counts.get(&item.row_key()) == Some(&1)
                && package_counts.get(&package_source_key(item)) == Some(&1)
                && software::prepare_update(item).is_ok()
        })
        .map(SoftwareItem::row_key)
        .collect()
}

fn prepare_batch_review(
    snapshot: &SoftwareSnapshot,
    selected: &HashSet<String>,
    snapshot_revision: u64,
) -> Result<BatchReview, String> {
    let selected_only = !selected.is_empty();
    let mut eligible_keys = HashSet::new();
    let mut row_key_counts = std::collections::HashMap::<String, usize>::new();
    let mut package_counts = std::collections::HashMap::<(String, String), usize>::new();
    for item in &snapshot.items {
        *row_key_counts.entry(item.row_key()).or_default() += 1;
        *package_counts.entry(package_source_key(item)).or_default() += 1;
    }
    for key in selected {
        if !snapshot
            .items
            .iter()
            .any(|item| item.can_update() && item.row_key().as_str() == key.as_str())
        {
            return Err("The selected update no longer matches an eligible package row. Rescan and review the current offer.".into());
        }
    }

    let mut requests = Vec::new();
    let mut skipped = Vec::new();
    let mut not_selected = 0;
    for item in &snapshot.items {
        if item.status != SoftwareStatus::UpdateAvailable {
            continue;
        }
        let key = item.row_key();
        if !item.can_update() {
            skipped.push(BatchSkipped {
                display_name: item.row.name.clone(),
                reason: software::prepare_update(item)
                    .err()
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| {
                        "The package did not pass update eligibility checks.".into()
                    }),
            });
            continue;
        }
        if row_key_counts.get(&key).copied().unwrap_or(0) != 1
            || package_counts
                .get(&package_source_key(item))
                .copied()
                .unwrap_or(0)
                != 1
        {
            if selected.contains(&key) {
                return Err("A selected package row is ambiguous in the current inventory. Rescan before reviewing updates.".into());
            }
            skipped.push(BatchSkipped {
                display_name: item.row.name.clone(),
                reason: "More than one installed or catalogue row maps to this WinGet package ID; it was excluded as ambiguous.".into(),
            });
            continue;
        }
        eligible_keys.insert(key.clone());
        if selected_only && !selected.contains(&key) {
            not_selected += 1;
            continue;
        }
        match software::prepare_update(item) {
            Ok(request) => requests.push(request),
            Err(error) => skipped.push(BatchSkipped {
                display_name: item.row.name.clone(),
                reason: error.to_string(),
            }),
        }
    }
    if selected_only && selected.iter().any(|key| !eligible_keys.contains(key)) {
        return Err("A selected package is no longer eligible for this update batch. Rescan and review the current offer.".into());
    }
    Ok(BatchReview {
        snapshot_revision,
        requests,
        skipped,
        not_selected,
        error: None,
    })
}

fn package_source_key(item: &SoftwareItem) -> (String, String) {
    (
        item.row.source_id.to_ascii_lowercase(),
        item.row.package_id.to_ascii_lowercase(),
    )
}

fn validate_batch_review(
    review: &BatchReview,
    snapshot: Option<&SoftwareSnapshot>,
    current_revision: u64,
) -> Result<(), String> {
    if review.snapshot_revision != current_revision {
        return Err("The installed software snapshot changed after this batch was reviewed. Rescan and review it again.".into());
    }
    if review.requests.is_empty() {
        return Err("This batch no longer contains any eligible updates.".into());
    }
    let snapshot = snapshot.ok_or_else(|| {
        "The installed software snapshot is unavailable; this batch cannot start.".to_owned()
    })?;
    for request in &review.requests {
        let mut matches = snapshot.items.iter().filter(|item| {
            item.identity.as_ref() == Some(&request.identity)
                && item.row.package_id == request.package_id
                && item.row.source_id == request.source_id
                && item.row.installed_version.as_deref() == Some(request.installed_version.as_str())
                && item.row.available_version.as_deref() == Some(request.target_version.as_str())
        });
        let item = matches.next().ok_or_else(|| {
            format!(
                "{} no longer matches the reviewed package row. Rescan before starting.",
                request.display_name
            )
        })?;
        if matches.next().is_some() || !item.can_update() {
            return Err(format!(
                "{} is no longer one unambiguous eligible update. Rescan before starting.",
                request.display_name
            ));
        }
        let current = software::prepare_update(item).map_err(|error| {
            format!(
                "{} can no longer be prepared safely: {error}",
                request.display_name
            )
        })?;
        if current.identity != request.identity
            || current.display_name != request.display_name
            || current.package_id != request.package_id
            || current.source_id != request.source_id
            || current.installed_version != request.installed_version
            || current.target_version != request.target_version
        {
            return Err(format!(
                "{} changed after this batch was reviewed. Rescan before starting.",
                request.display_name
            ));
        }
    }
    Ok(())
}

struct BatchExecution {
    state: BatchItemState,
    detail: String,
}

fn run_batch_sequence<P, F>(
    requests: &[UpdateRequest],
    cancel: &AtomicBool,
    mut progress: P,
    mut run_one: F,
) -> BatchReport
where
    P: FnMut(usize, &UpdateRequest),
    F: FnMut(&UpdateRequest) -> BatchExecution,
{
    let mut report = BatchReport::default();
    for (index, request) in requests.iter().enumerate() {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            report.stop_reason = Some("Stopped after the current update at your request. Remaining updates were not started.".into());
            report
                .outcomes
                .extend(requests[index..].iter().map(|pending| {
                    batch_outcome(
                        pending,
                        BatchItemState::NotAttempted,
                        "Not started because you asked to stop the batch after the current update.",
                    )
                }));
            break;
        }
        progress(index, request);
        let execution = run_one(request);
        let stop_after = execution.state == BatchItemState::Uncertain;
        report
            .outcomes
            .push(batch_outcome(request, execution.state, execution.detail));
        if stop_after {
            report.stop_reason = Some("Stopped after an uncertain update result. Remaining updates were not started; review Updater History and rescan before trying again.".into());
            report
                .outcomes
                .extend(requests[index + 1..].iter().map(|pending| {
                    batch_outcome(
                        pending,
                        BatchItemState::NotAttempted,
                        "Not started because the preceding update result is uncertain.",
                    )
                }));
            break;
        }
    }
    report
}

fn batch_outcome(
    request: &UpdateRequest,
    state: BatchItemState,
    detail: impl Into<String>,
) -> BatchItemOutcome {
    BatchItemOutcome {
        request_id: request.request_id,
        display_name: request.display_name.clone(),
        target_version: request.target_version.clone(),
        state,
        detail: detail.into(),
    }
}

fn run_journaled_update(root: &std::path::Path, request: &UpdateRequest) -> BatchExecution {
    let mut journal = match EffectJournal::create(
        root,
        "software-update",
        request.request_id,
        request,
    ) {
        Ok(journal) => journal,
        Err(error) => {
            return BatchExecution {
                state: BatchItemState::Failed,
                detail: format!(
                    "The durable intent could not be written, so WinGet was not launched: {error}"
                ),
            };
        }
    };
    match software::run_native_update(request) {
        Ok(receipt) if receipt.request_id != request.request_id => {
            let journal_error = journal.finish("uncertain", &receipt).err();
            BatchExecution {
                state: BatchItemState::Uncertain,
                detail: format!(
                    "The native update returned a receipt for a different request; no further package was started.{}",
                    journal_error
                        .map(|error| format!(" The uncertain result could not be saved: {error}"))
                        .unwrap_or_default()
                ),
            }
        }
        Ok(receipt) => {
            let verification = receipt.verification;
            let detail = match verification {
                UpdateVerification::Verified => format!(
                    "WinGet and the installed-program registration both report version {}.",
                    receipt.target_version
                ),
                UpdateVerification::Uncertain => format!(
                    "WinGet returned, but the requested installed version could not be verified.{}",
                    receipt
                        .verification_note
                        .as_deref()
                        .map(|note| format!(" {note}"))
                        .unwrap_or_default()
                ),
            };
            let journal_error = journal.finish(receipt.journal_state(), &receipt).err();
            if let Some(error) = journal_error {
                BatchExecution {
                    state: BatchItemState::Uncertain,
                    detail: format!(
                        "{detail} The durable outcome receipt could not be saved: {error}"
                    ),
                }
            } else {
                BatchExecution {
                    state: match verification {
                        UpdateVerification::Verified => BatchItemState::Verified,
                        UpdateVerification::Uncertain => BatchItemState::Uncertain,
                    },
                    detail,
                }
            }
        }
        Err(error) => {
            let error_message = error.to_string();
            let journal_error = journal
                .finish(
                    "failed",
                    &UpdateFailureReceipt {
                        request_id: request.request_id,
                        error: &error_message,
                    },
                )
                .err();
            if let Some(journal_error) = journal_error {
                BatchExecution {
                    state: BatchItemState::Uncertain,
                    detail: format!(
                        "The update was not confirmed: {error}. Its durable outcome could not be saved: {journal_error}"
                    ),
                }
            } else {
                BatchExecution {
                    state: BatchItemState::Failed,
                    detail: format!("The update failed or did not start: {error}."),
                }
            }
        }
    }
}

fn tab_matches(tab: SoftwareTab, item: &SoftwareItem) -> bool {
    match tab {
        SoftwareTab::Outdated => {
            item.row.available_version.is_some()
                && !matches!(
                    item.status,
                    SoftwareStatus::SkippedVersion | SoftwareStatus::Ignored
                )
        }
        SoftwareTab::UpToDate => item.status == SoftwareStatus::Current,
        SoftwareTab::SkippedIgnored => matches!(
            item.status,
            SoftwareStatus::SkippedVersion | SoftwareStatus::Ignored
        ),
    }
}

fn software_tab_counts(items: &[SoftwareItem]) -> (usize, usize, usize) {
    (
        items
            .iter()
            .filter(|item| tab_matches(SoftwareTab::Outdated, item))
            .count(),
        items
            .iter()
            .filter(|item| tab_matches(SoftwareTab::UpToDate, item))
            .count(),
        items
            .iter()
            .filter(|item| tab_matches(SoftwareTab::SkippedIgnored, item))
            .count(),
    )
}

fn matches_query(item: &SoftwareItem, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    [
        Some(item.row.name.as_str()),
        Some(item.row.package_id.as_str()),
        Some(item.row.source_id.as_str()),
        item.row.installed_version.as_deref(),
        item.row.available_version.as_deref(),
        item.registration
            .as_ref()
            .and_then(|program| program.publisher.as_deref()),
        item.registration
            .as_ref()
            .map(|program| program.identity.key_name.as_str()),
    ]
    .into_iter()
    .flatten()
    .any(|value| value.to_lowercase().contains(&query))
}

fn visible_eligible_keys(items: &[SoftwareItem], eligible: &HashSet<String>) -> Vec<String> {
    items
        .iter()
        .map(SoftwareItem::row_key)
        .filter(|key| eligible.contains(key))
        .collect()
}

fn set_visible_update_selection(
    selected: &mut HashSet<String>,
    visible_eligible: &[String],
    is_selected: bool,
) {
    if is_selected {
        selected.extend(visible_eligible.iter().cloned());
    } else {
        for key in visible_eligible {
            selected.remove(key);
        }
    }
}

fn sort_for_tab_change(
    sort: SoftwareSort,
    descending: bool,
    next_tab: SoftwareTab,
) -> (SoftwareSort, bool) {
    match (sort, next_tab) {
        (SoftwareSort::Status, SoftwareTab::Outdated) => (SoftwareSort::Importance, false),
        (SoftwareSort::Importance, _) if next_tab != SoftwareTab::Outdated => {
            (SoftwareSort::Status, false)
        }
        _ => (sort, descending),
    }
}

fn sort_items(items: &mut [SoftwareItem], sort: SoftwareSort, descending: bool) {
    items.sort_by(|left, right| {
        let ordering = match sort {
            SoftwareSort::Name => left
                .row
                .name
                .to_lowercase()
                .cmp(&right.row.name.to_lowercase()),
            SoftwareSort::Installed => version_sort(
                left.row.installed_version.as_deref(),
                right.row.installed_version.as_deref(),
            ),
            SoftwareSort::Available => version_sort(
                left.row.available_version.as_deref(),
                right.row.available_version.as_deref(),
            ),
            // WinGet exposes no severity/importance value, so all current values are unknown.
            // Keep that sort useful and deterministic by falling back to the package name.
            SoftwareSort::Importance => left
                .row
                .name
                .to_lowercase()
                .cmp(&right.row.name.to_lowercase()),
            SoftwareSort::Status => status_label(left).cmp(status_label(right)),
        };
        let ordering = if descending {
            ordering.reverse()
        } else {
            ordering
        };
        ordering.then_with(|| {
            left.row
                .package_id
                .to_lowercase()
                .cmp(&right.row.package_id.to_lowercase())
        })
    });
}

fn select_header_sort(current: &mut SoftwareSort, descending: &mut bool, selected: SoftwareSort) {
    if *current == selected {
        *descending = !*descending;
    } else {
        *current = selected;
        *descending = false;
    }
}

#[cfg(debug_assertions)]
fn software_qa_item(
    name: &str,
    package_id: &str,
    installed_version: &str,
    available_version: Option<&str>,
    status: SoftwareStatus,
) -> SoftwareItem {
    let registration = ProgramIdentity {
        hive: RegistryHive::CurrentUser,
        key_name: format!(
            "fixture-{}",
            package_id.to_ascii_lowercase().replace('.', "-")
        ),
    };
    let registry_source = RegistrySource {
        hive: RegistryHive::CurrentUser,
        view: RegistryView::Registry64,
    };
    let software_identity = SoftwareIdentity {
        registration: registration.clone(),
        registry_source,
        package_id: package_id.to_ascii_lowercase(),
        source_id: software::WINGET_SOURCE.into(),
    };
    let registered_program = InstalledProgram {
        identity: registration,
        source: registry_source,
        display_name: name.into(),
        display_icon: None,
        publisher: Some("Example Publisher".into()),
        version: Some(installed_version.into()),
        install_location: Some(std::path::PathBuf::from(format!(
            r"C:\Fixture\{}",
            package_id.replace('.', "-")
        ))),
        install_date: Some("20250115".into()),
        estimated_size_bytes: Some(18_874_368),
        registered_uninstall_command: None,
        uninstall_command: None,
        uninstall_command_error: None,
        system_component: false,
        protected: false,
        no_remove: false,
    };
    SoftwareItem {
        row: WingetRow {
            name: name.into(),
            package_id: package_id.into(),
            installed_version: Some(installed_version.into()),
            available_version: available_version.map(str::to_owned),
            source_id: software::WINGET_SOURCE.into(),
        },
        registration: Some(registered_program),
        identity: Some(software_identity),
        status,
        association_note: None,
        preference_note: None,
    }
}

fn version_sort(left: Option<&str>, right: Option<&str>) -> Ordering {
    left.unwrap_or("").cmp(right.unwrap_or(""))
}

fn status_label(item: &SoftwareItem) -> &'static str {
    match item.status {
        SoftwareStatus::Current => "Current",
        SoftwareStatus::UpdateAvailable => "Outdated",
        SoftwareStatus::SkippedVersion => "Skipped version",
        SoftwareStatus::Ignored => "Ignored",
        SoftwareStatus::Unmatched if item.row.available_version.is_some() => "Update · unmatched",
        SoftwareStatus::Unmatched => "Unmatched",
    }
}

fn status_color(status: SoftwareStatus, t: Tokens) -> eframe::egui::Color32 {
    match status {
        SoftwareStatus::Current => t.muted,
        SoftwareStatus::UpdateAvailable => t.primary,
        SoftwareStatus::SkippedVersion | SoftwareStatus::Ignored => t.attention,
        SoftwareStatus::Unmatched => t.attention,
    }
}

fn sortable_heading(
    ui: &mut egui::Ui,
    label: &str,
    width: f32,
    selected: bool,
    descending: bool,
    t: Tokens,
) -> egui::Response {
    let indicator = if selected {
        if descending { " ↓" } else { " ↑" }
    } else {
        ""
    };
    let response = ui
        .allocate_ui_with_layout(
            [width, 22.].into(),
            egui::Layout::left_to_right(egui::Align::Center),
            |cell| {
                cell.set_min_size([width, 22.].into());
                cell.set_max_width(width);
                cell.add(
                    egui::Label::new(
                        RichText::new(format!("{label}{indicator}"))
                            .size(theme::FONT_CAPTION)
                            .color(if selected { t.foreground } else { t.muted }),
                    )
                    .truncate()
                    .sense(egui::Sense::click()),
                )
            },
        )
        .inner
        .on_hover_text(if selected {
            format!("Sorted by {label}; click to reverse")
        } else {
            format!("Sort by {label}")
        });
    #[cfg(debug_assertions)]
    theme::record_fixture_control(ui, &format!("Sort {label}"), &response);
    response
}

fn table_heading(ui: &mut egui::Ui, label: &str, width: f32, t: Tokens) {
    theme::table_cell(
        ui,
        RichText::new(label)
            .size(theme::FONT_CAPTION)
            .color(t.muted),
        width,
        22.,
    );
}

fn dialog_body_max_height(ctx: &egui::Context, footer_height: f32) -> f32 {
    // Reserve the 24px dialog padding, pinned title, pinned actions, and inter-widget gaps.
    (ctx.content_rect().height() - 48.0 - 40.0 - footer_height - 24.0).max(80.0)
}

fn status_card(ui: &mut egui::Ui, t: Tokens, heading: &str, body: &str) {
    egui::Frame::new()
        .fill(t.tint)
        .stroke(egui::Stroke::new(1., t.border))
        .corner_radius(9)
        .inner_margin(12.)
        .show(ui, |ui| {
            ui.label(RichText::new(heading).family(theme::semibold()));
            ui.add_space(4.);
            theme::muted(ui, body, t);
        });
}

fn detail(ui: &mut egui::Ui, name: &str, value: &str, t: Tokens) {
    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(
            [132., 24.].into(),
            Layout::left_to_right(Align::Center),
            |label| {
                label.set_min_size([132., 24.].into());
                label.set_max_width(132.);
                theme::muted(label, name, t);
            },
        );
        let width = ui.available_width();
        ui.allocate_ui_with_layout(
            [width, 24.].into(),
            Layout::left_to_right(Align::Center),
            |value_ui| {
                value_ui.set_min_size([width, 24.].into());
                value_ui.set_max_width(width);
                value_ui.add(egui::Label::new(value).wrap());
            },
        );
    });
}

fn review_row(ui: &mut egui::Ui, label: &str, value: &str, t: Tokens) {
    detail(ui, label, value, t);
}

fn history_state(state: &str) -> &str {
    match state {
        "verified" => "Update verified",
        "failed" => "Update failed or did not start",
        "handed_off" => "WinGet launched · outcome not confirmed",
        "uncertain" => "Update outcome uncertain · review before retrying",
        other => other,
    }
}

#[cfg(all(test, debug_assertions))]
mod batch_tests {
    use super::*;

    #[test]
    fn filtered_header_selection_excludes_hidden_and_ineligible_updates() {
        let browser = software_qa_item(
            "Browser",
            "Example.Browser",
            "1.0",
            Some("2.0"),
            SoftwareStatus::UpdateAvailable,
        );
        let editor = software_qa_item(
            "Editor",
            "Example.Editor",
            "1.0",
            Some("2.0"),
            SoftwareStatus::UpdateAvailable,
        );
        let current = software_qa_item(
            "Current",
            "Example.Current",
            "1.0",
            None,
            SoftwareStatus::Current,
        );
        let snapshot = SoftwareSnapshot {
            items: vec![browser.clone(), editor.clone(), current.clone()],
            registration_issues: Vec::new(),
        };
        let eligible = batch_eligible_keys(&snapshot);
        assert!(eligible.contains(&editor.row_key()));
        let visible = visible_eligible_keys(&[browser.clone(), current], &eligible);
        assert_eq!(visible, vec![browser.row_key()]);
        let selected: HashSet<_> = visible.into_iter().collect();
        let review = prepare_batch_review(&snapshot, &selected, 1).unwrap();
        assert_eq!(review.requests.len(), 1);
        assert_eq!(review.requests[0].package_id, "Example.Browser");
        assert_eq!(review.not_selected, 1);
    }

    fn request(name: &str, package_id: &str, installed: &str, available: &str) -> UpdateRequest {
        let item = software_qa_item(
            name,
            package_id,
            installed,
            Some(available),
            SoftwareStatus::UpdateAvailable,
        );
        software::prepare_update(&item).expect("fixture update is eligible")
    }

    #[test]
    fn review_includes_only_exact_eligible_rows_and_explains_blocked_rows() {
        let eligible = software_qa_item(
            "Example Editor",
            "Example.Editor",
            "1.0.0",
            Some("1.1.0"),
            SoftwareStatus::UpdateAvailable,
        );
        let mut protected = software_qa_item(
            "Protected Runtime",
            "Example.Protected",
            "2.0.0",
            Some("2.1.0"),
            SoftwareStatus::UpdateAvailable,
        );
        protected.registration.as_mut().unwrap().protected = true;
        let current = software_qa_item(
            "Current Runtime",
            "Example.Current",
            "3.0.0",
            None,
            SoftwareStatus::Current,
        );
        let snapshot = SoftwareSnapshot {
            items: vec![eligible, protected, current],
            registration_issues: Vec::new(),
        };

        let review = prepare_batch_review(&snapshot, &HashSet::new(), 4).unwrap();

        assert_eq!(review.requests.len(), 1);
        assert_eq!(review.requests[0].package_id, "Example.Editor");
        assert_eq!(review.skipped.len(), 1);
        assert!(review.skipped[0].reason.contains("protected"));
        assert_eq!(review.not_selected, 0);
    }

    #[test]
    fn selected_review_keeps_selection_boundary_and_rejects_stale_keys() {
        let first = software_qa_item(
            "First",
            "Example.First",
            "1.0.0",
            Some("1.1.0"),
            SoftwareStatus::UpdateAvailable,
        );
        let second = software_qa_item(
            "Second",
            "Example.Second",
            "2.0.0",
            Some("2.1.0"),
            SoftwareStatus::UpdateAvailable,
        );
        let first_key = first.row_key();
        let snapshot = SoftwareSnapshot {
            items: vec![first, second],
            registration_issues: Vec::new(),
        };
        let selected = HashSet::from([first_key]);

        let review = prepare_batch_review(&snapshot, &selected, 2).unwrap();

        assert_eq!(review.requests.len(), 1);
        assert_eq!(review.requests[0].package_id, "Example.First");
        assert_eq!(review.not_selected, 1);
        assert!(
            prepare_batch_review(&snapshot, &HashSet::from(["stale-row-key".to_owned()]), 2,)
                .is_err()
        );
    }

    #[test]
    fn duplicate_winget_package_rows_are_excluded_as_ambiguous() {
        let first = software_qa_item(
            "Example Editor",
            "Example.Editor",
            "1.0.0",
            Some("1.1.0"),
            SoftwareStatus::UpdateAvailable,
        );
        let second = software_qa_item(
            "Example Editor Copy",
            "Example.Editor",
            "1.0.0",
            Some("1.1.0"),
            SoftwareStatus::UpdateAvailable,
        );
        let snapshot = SoftwareSnapshot {
            items: vec![first, second],
            registration_issues: Vec::new(),
        };

        assert!(batch_eligible_keys(&snapshot).is_empty());
        let review = prepare_batch_review(&snapshot, &HashSet::new(), 1).unwrap();
        assert!(review.requests.is_empty());
        assert_eq!(review.skipped.len(), 2);
        assert!(review.skipped[0].reason.contains("ambiguous"));
    }

    #[test]
    fn three_page_tabs_preserve_current_skip_ignore_and_unmatched_offer_groups() {
        let outdated = software_qa_item(
            "Outdated",
            "Example.Outdated",
            "1.0.0",
            Some("1.1.0"),
            SoftwareStatus::UpdateAvailable,
        );
        let mut unmatched_offer = software_qa_item(
            "Unmatched offer",
            "Example.UnmatchedOffer",
            "1.0.0",
            Some("1.1.0"),
            SoftwareStatus::UpdateAvailable,
        );
        unmatched_offer.registration = None;
        unmatched_offer.identity = None;
        unmatched_offer.status = SoftwareStatus::Unmatched;
        let current = software_qa_item(
            "Current",
            "Example.Current",
            "1.0.0",
            None,
            SoftwareStatus::Current,
        );
        let skipped = software_qa_item(
            "Skipped",
            "Example.Skipped",
            "1.0.0",
            Some("1.1.0"),
            SoftwareStatus::SkippedVersion,
        );
        let ignored = software_qa_item(
            "Ignored",
            "Example.Ignored",
            "1.0.0",
            Some("1.1.0"),
            SoftwareStatus::Ignored,
        );
        let snapshot = [outdated, unmatched_offer, current, skipped, ignored];

        assert_eq!(software_tab_counts(&snapshot), (2, 1, 2));
        assert!(tab_matches(SoftwareTab::Outdated, &snapshot[1]));
        assert!(!tab_matches(SoftwareTab::UpToDate, &snapshot[1]));
        assert!(tab_matches(SoftwareTab::UpToDate, &snapshot[2]));
        assert!(tab_matches(SoftwareTab::SkippedIgnored, &snapshot[3]));
        assert!(tab_matches(SoftwareTab::SkippedIgnored, &snapshot[4]));
        assert_eq!(status_label(&snapshot[3]), "Skipped version");
        assert_eq!(status_label(&snapshot[4]), "Ignored");
    }

    #[test]
    fn reviewed_batch_is_rejected_after_snapshot_or_offer_changes() {
        let item = software_qa_item(
            "Example Editor",
            "Example.Editor",
            "1.0.0",
            Some("1.1.0"),
            SoftwareStatus::UpdateAvailable,
        );
        let snapshot = SoftwareSnapshot {
            items: vec![item],
            registration_issues: Vec::new(),
        };
        let review = prepare_batch_review(&snapshot, &HashSet::new(), 7).unwrap();

        assert!(validate_batch_review(&review, Some(&snapshot), 8).is_err());
        let mut changed = snapshot.clone();
        changed.items[0].row.available_version = Some("1.2.0".into());
        assert!(validate_batch_review(&review, Some(&changed), 7).is_err());
    }

    #[test]
    fn batch_checks_cancellation_between_updates_without_interrupt_claims() {
        let requests = vec![
            request("First", "Example.First", "1.0.0", "1.1.0"),
            request("Second", "Example.Second", "2.0.0", "2.1.0"),
        ];
        let cancel = AtomicBool::new(false);
        let mut started = Vec::new();
        let report = run_batch_sequence(
            &requests,
            &cancel,
            |_, _| {},
            |request| {
                started.push(request.package_id.clone());
                cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                BatchExecution {
                    state: BatchItemState::Verified,
                    detail: "Verified by the fixture executor.".into(),
                }
            },
        );

        assert_eq!(started, vec!["Example.First".to_owned()]);
        assert_eq!(report.outcomes.len(), 2);
        assert_eq!(report.outcomes[0].state, BatchItemState::Verified);
        assert_eq!(report.outcomes[1].state, BatchItemState::NotAttempted);
        assert!(
            report
                .stop_reason
                .as_deref()
                .unwrap()
                .contains("your request")
        );
    }

    #[test]
    fn uncertain_result_stops_batch_and_marks_remaining_updates_not_started() {
        let requests = vec![
            request("First", "Example.First", "1.0.0", "1.1.0"),
            request("Second", "Example.Second", "2.0.0", "2.1.0"),
        ];
        let cancel = AtomicBool::new(false);
        let mut started = Vec::new();
        let report = run_batch_sequence(
            &requests,
            &cancel,
            |_, _| {},
            |request| {
                started.push(request.package_id.clone());
                BatchExecution {
                    state: BatchItemState::Uncertain,
                    detail: "Fixture cannot verify the installed version.".into(),
                }
            },
        );

        assert_eq!(started, vec!["Example.First".to_owned()]);
        assert_eq!(report.outcomes[0].state, BatchItemState::Uncertain);
        assert_eq!(report.outcomes[1].state, BatchItemState::NotAttempted);
        assert!(report.stop_reason.as_deref().unwrap().contains("uncertain"));
    }

    #[test]
    fn failed_package_does_not_change_later_reviewed_request_identity() {
        let requests = vec![
            request("First", "Example.First", "1.0.0", "1.1.0"),
            request("Second", "Example.Second", "2.0.0", "2.1.0"),
        ];
        let report = run_batch_sequence(
            &requests,
            &AtomicBool::new(false),
            |_, _| {},
            |request| BatchExecution {
                state: if request.package_id == "Example.First" {
                    BatchItemState::Failed
                } else {
                    BatchItemState::Verified
                },
                detail: "Fixture executor result.".into(),
            },
        );

        assert_eq!(report.outcomes.len(), 2);
        assert_eq!(report.outcomes[0].request_id, requests[0].request_id);
        assert_eq!(report.outcomes[0].state, BatchItemState::Failed);
        assert_eq!(report.outcomes[1].request_id, requests[1].request_id);
        assert_eq!(report.outcomes[1].state, BatchItemState::Verified);
    }

    #[test]
    fn sortable_headers_select_a_column_and_reverse_it_on_second_click() {
        let mut sort = SoftwareSort::Name;
        let mut descending = false;

        select_header_sort(&mut sort, &mut descending, SoftwareSort::Available);
        assert_eq!(sort, SoftwareSort::Available);
        assert!(!descending);

        select_header_sort(&mut sort, &mut descending, SoftwareSort::Available);
        assert_eq!(sort, SoftwareSort::Available);
        assert!(descending);

        select_header_sort(&mut sort, &mut descending, SoftwareSort::Status);
        assert_eq!(sort, SoftwareSort::Status);
        assert!(!descending);
    }

    #[test]
    fn tab_change_uses_importance_only_for_outdated_and_keeps_status_elsewhere() {
        assert_eq!(
            sort_for_tab_change(SoftwareSort::Status, true, SoftwareTab::Outdated),
            (SoftwareSort::Importance, false)
        );
        assert_eq!(
            sort_for_tab_change(SoftwareSort::Importance, true, SoftwareTab::UpToDate),
            (SoftwareSort::Status, false)
        );
        assert_eq!(
            sort_for_tab_change(SoftwareSort::Available, true, SoftwareTab::SkippedIgnored),
            (SoftwareSort::Available, true)
        );
    }

    #[test]
    fn importance_sort_falls_back_to_name_when_source_has_no_rating() {
        let mut items = vec![
            software_qa_item(
                "Zulu Tool",
                "Example.Zulu",
                "1.0",
                Some("2.0"),
                SoftwareStatus::UpdateAvailable,
            ),
            software_qa_item(
                "Alpha Tool",
                "Example.Alpha",
                "1.0",
                Some("3.0"),
                SoftwareStatus::Unmatched,
            ),
        ];

        sort_items(&mut items, SoftwareSort::Importance, false);

        assert_eq!(
            items
                .iter()
                .map(|item| item.row.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Alpha Tool", "Zulu Tool"]
        );
    }

    #[test]
    fn app_updates_group_selection_changes_only_filtered_eligible_rows() {
        let visible_update = software_qa_item(
            "Visible update",
            "Example.Visible",
            "1.0",
            Some("2.0"),
            SoftwareStatus::UpdateAvailable,
        );
        let filtered_update = software_qa_item(
            "Filtered update",
            "Example.Filtered",
            "1.0",
            Some("2.0"),
            SoftwareStatus::UpdateAvailable,
        );
        let current = software_qa_item(
            "Current package",
            "Example.Current",
            "1.0",
            None,
            SoftwareStatus::Current,
        );
        let snapshot = SoftwareSnapshot {
            items: vec![
                visible_update.clone(),
                filtered_update.clone(),
                current.clone(),
            ],
            registration_issues: Vec::new(),
        };
        let eligible = batch_eligible_keys(&snapshot);
        let group_visible = visible_eligible_keys(&[visible_update.clone(), current], &eligible);
        let mut selected = HashSet::new();

        set_visible_update_selection(&mut selected, &group_visible, true);

        assert_eq!(group_visible, vec![visible_update.row_key()]);
        assert_eq!(selected, HashSet::from([visible_update.row_key()]));
        assert!(!selected.contains(&filtered_update.row_key()));

        set_visible_update_selection(&mut selected, &group_visible, false);
        assert!(selected.is_empty());
    }
}

fn format_date(date: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(date)
        .map(|date| date.format("%d %b %Y, %H:%M").to_string())
        .unwrap_or_else(|_| date.to_owned())
}

fn software_dialog_heading(ui: &mut egui::Ui, title: &str, close_enabled: bool) -> bool {
    let mut close = false;
    ui.horizontal(|ui| {
        let width = (ui.available_width() - 36.).max(1.);
        ui.allocate_ui_with_layout(
            [width, 32.].into(),
            Layout::left_to_right(Align::Center),
            |heading| {
                heading.set_min_width(width);
                heading.set_max_width(width);
                heading
                    .add(
                        egui::Label::new(
                            RichText::new(title)
                                .size(theme::FONT_DISPLAY)
                                .family(theme::semibold()),
                        )
                        .truncate(),
                    )
                    .on_hover_text(title);
            },
        );
        close = theme::close_button(ui, "Close dialog", close_enabled);
    });
    close
}

#[cfg(debug_assertions)]
fn software_tab_name(tab: SoftwareTab) -> &'static str {
    match tab {
        SoftwareTab::Outdated => "Outdated software",
        SoftwareTab::UpToDate => "Up-to-date software",
        SoftwareTab::SkippedIgnored => "Skipped & ignored",
    }
}

#[cfg(debug_assertions)]
fn software_sort_name(sort: SoftwareSort) -> &'static str {
    match sort {
        SoftwareSort::Name => "Software",
        SoftwareSort::Installed => "Current version",
        SoftwareSort::Available => "New version",
        SoftwareSort::Importance => "Importance",
        SoftwareSort::Status => "Status",
    }
}
