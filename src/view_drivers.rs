use super::*;
use crate::theme;
#[cfg(debug_assertions)]
use dcleaner::drivers::{
    DeviceInventory, DriverCatalogue, FieldFailure, FieldFailureKind, NativeIssue, SourceReport,
};
use dcleaner::{
    drivers::{
        self, CatalogueState, DeviceId, DeviceOffer, DriverCandidate, DriverDevice,
        DriverDeviceCategory, DriverRestoreIntent, DriverRestoreReceipt, DriverSettings,
        DriverSnapshot, DriverStatus, DriverUpdateIntent, DriverUpdateReceipt, FieldValue,
        InventoryQuality, RebootRequirement, WindowsDriverPlatform,
    },
    effects::EffectHistory,
};
use std::collections::BTreeMap;

const MAX_DRIVER_BATCH_OFFERS: usize = 16;

pub(super) struct DriverUi {
    snapshot: Option<DriverSnapshot>,
    attempted: bool,
    intro_fixture: bool,
    loading: bool,
    query: String,
    tab: DriverTab,
    sort: DriverSort,
    descending: bool,
    selected: Option<DeviceId>,
    selected_updates: Vec<SelectedDriverUpdate>,
    dialog: Option<DriverDialog>,
    settings: Option<DriverSettings>,
    settings_error: Option<String>,
    history: Vec<EffectHistory>,
    history_error: Option<String>,
}

impl Default for DriverUi {
    fn default() -> Self {
        Self {
            snapshot: None,
            attempted: false,
            intro_fixture: false,
            loading: false,
            query: String::new(),
            tab: DriverTab::Outdated,
            sort: DriverSort::Device,
            descending: false,
            selected: None,
            selected_updates: Vec::new(),
            dialog: None,
            settings: None,
            settings_error: None,
            history: Vec::new(),
            history_error: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DriverTab {
    #[default]
    Outdated,
    Current,
    Deferred,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DriverSort {
    #[default]
    Device,
    Provider,
    Installed,
    Release,
    State,
}

impl DriverSort {
    const ALL: [Self; 5] = [
        Self::Device,
        Self::Provider,
        Self::Installed,
        Self::Release,
        Self::State,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Device => "Device",
            Self::Provider => "Provider",
            Self::Installed => "Installed version",
            Self::Release => "Offer release",
            Self::State => "State",
        }
    }
}

#[derive(Clone)]
enum DriverDialog {
    Details(DriverDevice),
    Update(DriverUpdateIntent),
    BatchReview(Vec<SelectedDriverUpdate>),
    Restore {
        update_intent: DriverUpdateIntent,
        update_receipt: DriverUpdateReceipt,
        restore_intent: DriverRestoreIntent,
    },
}

#[derive(Clone)]
struct SelectedDriverUpdate {
    intent: DriverUpdateIntent,
    devices: Vec<SelectedDriverDevice>,
}

#[derive(Clone)]
struct SelectedDriverDevice {
    id: DeviceId,
    candidate: drivers::CandidateIdentity,
}

pub(super) struct DriverBatchItemResult {
    intent_id: Uuid,
    display_name: String,
    result: Result<DriverUpdateReceipt, String>,
}

pub(super) enum DriverEvent {
    Loaded {
        snapshot: DriverSnapshot,
        settings: Result<DriverSettings, String>,
        history: Result<Vec<EffectHistory>, String>,
    },
    UpdateFinished {
        intent_id: Uuid,
        display_name: String,
        result: Result<DriverUpdateReceipt, String>,
    },
    BatchUpdateFinished {
        requested: usize,
        results: Vec<DriverBatchItemResult>,
    },
    RestoreFinished {
        restore_id: Uuid,
        display_name: String,
        result: Result<DriverRestoreReceipt, String>,
    },
}

enum DetailAction {
    Review(DriverUpdateIntent),
    Select(DriverUpdateIntent, DeviceId, bool),
    Restore {
        update_intent: DriverUpdateIntent,
        update_receipt: DriverUpdateReceipt,
        restore_intent: DriverRestoreIntent,
    },
    Ignore(DeviceId, bool),
    Skip(DeviceId, drivers::CandidateIdentity, bool),
    Error(String),
}

impl App {
    #[cfg(debug_assertions)]
    pub(super) fn seed_drivers_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Driver QA fixtures require isolated fixture mode.".into());
        }
        if case == "drivers-intro" {
            self.drivers_ui = DriverUi {
                intro_fixture: true,
                settings: Some(DriverSettings::default()),
                ..DriverUi::default()
            };
            self.error = None;
            self.notice = None;
            self.progress.clear();
            return Ok(());
        }
        let mut ui = DriverUi {
            attempted: true,
            settings: Some(DriverSettings::default()),
            ..DriverUi::default()
        };
        self.error = None;
        self.notice = None;
        self.progress.clear();
        match case {
            "drivers-empty" => ui.snapshot = Some(driver_qa_snapshot(false)),
            "drivers-populated" | "drivers-details" => {
                let snapshot = driver_qa_snapshot(true);
                // The synthetic device has no matching Windows Update offer, so show it under
                // the no-offer / unknown tab instead of hiding it in Outdated.
                ui.tab = DriverTab::Current;
                if case == "drivers-details" {
                    if let Some(device) = snapshot.inventory.devices.first() {
                        ui.selected = device.id.clone();
                        ui.dialog = Some(DriverDialog::Details(device.clone()));
                    }
                }
                ui.snapshot = Some(snapshot);
            }
            "drivers-error" => {
                self.error = Some(
                    "Synthetic QA fixture error. No device inventory or update source was queried."
                        .into(),
                );
            }
            _ => return Err(format!("Unsupported Drivers QA fixture: {case}")),
        }
        self.drivers_ui = ui;
        Ok(())
    }

    pub(super) fn drivers_event(&mut self, event: DriverEvent) {
        match event {
            DriverEvent::Loaded {
                snapshot,
                settings,
                history,
            } => {
                self.worker = None;
                self.drivers_ui.loading = false;
                self.drivers_ui.attempted = true;
                self.drivers_ui.snapshot = Some(snapshot);
                match settings {
                    Ok(settings) => {
                        self.drivers_ui.settings = Some(settings);
                        self.drivers_ui.settings_error = None;
                    }
                    Err(error) => {
                        self.drivers_ui.settings = None;
                        self.drivers_ui.settings_error = Some(error);
                    }
                }
                match history {
                    Ok(history) => {
                        self.drivers_ui.history = history;
                        self.drivers_ui.history_error = None;
                    }
                    Err(error) => {
                        self.drivers_ui.history.clear();
                        self.drivers_ui.history_error = Some(error);
                    }
                }
                self.revalidate_selected_driver_offers();
                let selected_exists = self.drivers_ui.selected.as_ref().is_some_and(|id| {
                    self.drivers_ui.snapshot.as_ref().is_some_and(|snapshot| {
                        snapshot
                            .inventory
                            .devices
                            .iter()
                            .any(|device| device.id.as_ref() == Some(id))
                    })
                });
                if !selected_exists {
                    self.drivers_ui.selected = None;
                }
            }
            DriverEvent::UpdateFinished {
                intent_id,
                display_name,
                result,
            } => {
                self.worker = None;
                self.drivers_ui.dialog = None;
                self.drivers_ui.attempted = false;
                match result {
                    Ok(receipt) if receipt.intent_id == intent_id => {
                        self.error = None;
                        self.notice = Some(match receipt.phase {
                            drivers::DriverEffectPhase::Verified => format!(
                                "Windows verified the reviewed driver update for {display_name}. A signed package backup is recorded.{}",
                                reboot_note(receipt.reboot)
                            ),
                            drivers::DriverEffectPhase::AwaitingRestart => format!(
                                "Windows accepted the reviewed driver update for {display_name}, but requires a restart before verification. DCleaner will not restart Windows automatically.{}",
                                reboot_note(receipt.reboot)
                            ),
                            _ => format!(
                                "Windows returned an unverified result for {display_name}. Review Driver Updater history before retrying."
                            ),
                        });
                    }
                    Ok(_) => {
                        self.error = Some(
                            "The driver-update receipt did not match the reviewed intent. The outcome is uncertain; review history before retrying.".into(),
                        );
                    }
                    Err(error) => {
                        self.error = Some(format!(
                            "The reviewed driver update for {display_name} was not confirmed: {error}. Review history before retrying if Windows began the operation."
                        ));
                    }
                }
            }
            DriverEvent::BatchUpdateFinished { requested, results } => {
                self.worker = None;
                self.drivers_ui.dialog = None;
                self.drivers_ui.attempted = false;
                self.drivers_ui.selected_updates.clear();
                let mut completed = 0usize;
                let mut awaiting_restart = None;
                let mut failure = None;
                for item in results {
                    match item.result {
                        Ok(receipt) if receipt.intent_id == item.intent_id => match receipt.phase {
                            drivers::DriverEffectPhase::Verified => completed += 1,
                            drivers::DriverEffectPhase::AwaitingRestart => {
                                completed += 1;
                                awaiting_restart = Some(item.display_name);
                                break;
                            }
                            _ => {
                                failure = Some(format!(
                                    "Windows returned an unverified result for {}.",
                                    item.display_name
                                ));
                                break;
                            }
                        },
                        Ok(_) => {
                            failure = Some(format!(
                                "The receipt for {} did not match its reviewed intent.",
                                item.display_name
                            ));
                            break;
                        }
                        Err(error) => {
                            failure = Some(format!(
                                "The update for {} was not confirmed: {error}.",
                                item.display_name
                            ));
                            break;
                        }
                    }
                }
                if let Some(display_name) = awaiting_restart {
                    self.error = None;
                    self.notice = Some(format!(
                        "Windows accepted {completed} of {requested} reviewed driver updates and requires a restart for {display_name}. The remaining offers were not started. DCleaner will not restart Windows; rescan and review remaining devices after restart."
                    ));
                } else if let Some(failure) = failure {
                    self.error = Some(format!(
                        "{completed} of {requested} reviewed driver updates were verified. The batch stopped: {failure} Review Driver Updater history before retrying."
                    ));
                } else if completed == requested {
                    self.error = None;
                    self.notice = Some(drivers::representative_batch_completion_notice(completed));
                } else {
                    self.error = Some(format!(
                        "Only {completed} of {requested} reviewed driver updates returned results. The outcome is uncertain; review Driver Updater history before retrying."
                    ));
                }
            }
            DriverEvent::RestoreFinished {
                restore_id,
                display_name,
                result,
            } => {
                self.worker = None;
                self.drivers_ui.dialog = None;
                self.drivers_ui.attempted = false;
                match result {
                    Ok(receipt) if receipt.restore_id == restore_id => {
                        self.error = None;
                        self.notice = Some(match receipt.phase {
                            drivers::DriverEffectPhase::Verified => format!(
                                "Windows verified restoration of the saved driver for {display_name}.{}",
                                reboot_note(receipt.reboot)
                            ),
                            drivers::DriverEffectPhase::AwaitingRestart => format!(
                                "Windows staged the saved driver for {display_name}; a restart is required before verification. DCleaner will not restart Windows automatically.{}",
                                reboot_note(receipt.reboot)
                            ),
                            _ => format!(
                                "Windows did not verify restoration for {display_name}. Review Driver Updater history before retrying."
                            ),
                        });
                    }
                    Ok(_) => {
                        self.error = Some(
                            "The driver-restore receipt did not match the reviewed intent. The outcome is uncertain; review history before retrying.".into(),
                        );
                    }
                    Err(error) => {
                        self.error = Some(format!(
                            "The saved driver for {display_name} was not confirmed as restored: {error}. Review history before retrying if Windows began the operation."
                        ));
                    }
                }
            }
        }
    }

    pub(super) fn drivers_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if self.qa_fixture_mode() {
            theme::muted(
                ui,
                "QA fixture — synthetic data only; no device inventory or driver effects were run.",
                t,
            );
            ui.add_space(6.);
        }
        if self.drivers_intro_active() {
            if self.feature_intro(
                ui,
                t,
                "drivers",
                "Review your device drivers",
                "Check detected devices and matching Windows Update offers before deciding whether to update a driver.",
                &[
                    (
                        "Easy to review",
                        "See the detected device, its current driver details, and any offer Windows actually returns.",
                    ),
                    (
                        "Check the change first",
                        "Review the exact device and signed offer, plus backup and restart requirements, before confirming a supported update.",
                    ),
                ],
            ) {
                self.start_driver_scan(ctx);
            }
            return;
        }
        if !self.drivers_ui.attempted && !self.busy() && !self.qa_fixture_mode() {
            self.begin_driver_load(ctx);
        }

        self.driver_tabs(ui, t);
        ui.add_space(7.);
        self.driver_search(ui, t);
        ui.add_space(6.);

        if self.drivers_ui.loading {
            ui.horizontal(|ui| {
                ui.spinner();
                theme::muted(
                    ui,
                    "Reading present devices and Windows Update Agent offers. This native search cannot be cancelled once started.",
                    t,
                );
            });
            ui.add_space(5.);
        }

        if let Some(snapshot) = self.drivers_ui.snapshot.clone() {
            self.driver_quality_line(ui, t, &snapshot);
            ui.add_space(7.);
            self.driver_table(ui, t, ctx, &snapshot);
            ui.add_space(7.);
            self.driver_sources_panel(ui, t, &snapshot);
            ui.add_space(8.);
            self.driver_history_panel(ui, t);
        } else if self.drivers_ui.loading {
            theme::card(t).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Windows is reading the device inventory and querying its configured update source…");
                });
            });
        } else if self.drivers_ui.attempted {
            status_card(
                ui,
                t,
                "Driver inventory unavailable",
                "No device or update result was returned. Use Scan again to try again.",
            );
        }
        if let Some(error) = self.drivers_ui.settings_error.as_deref() {
            ui.add_space(7.);
            status_card(
                ui,
                t,
                "Saved driver choices could not be read",
                &format!(
                    "{error} Skip and ignore controls are disabled. Driver actions are also blocked until saved choices can be read safely."
                ),
            );
        }
        if let Some(error) = self.drivers_ui.history_error.as_deref() {
            ui.add_space(7.);
            status_card(
                ui,
                t,
                "Driver operation history unavailable",
                &format!(
                    "{error} Saved driver changes cannot be offered for restore until history is readable."
                ),
            );
        }
    }

    pub(super) fn drivers_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if self.drivers_intro_active() {
            let compact = !self.feature_intro_wide(ctx);
            let mut start = false;
            ui.horizontal_wrapped(|ui| {
                theme::muted(
                    ui,
                    if compact {
                        "Start a read-only device and driver scan"
                    } else {
                        "Choose Scan now in the introduction to read device and driver offers"
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
                self.start_driver_scan(ctx);
            }
            return;
        }
        let busy = self.busy();
        let selected = self.selected_driver().cloned();
        let selected_updates = self.drivers_ui.selected_updates.clone();
        let summary = self.driver_footer_summary();
        let mut refresh = false;
        let mut show_details = false;
        let mut review_update = false;
        let mut review_selected = false;
        let mut review_restore = false;

        ui.horizontal_wrapped(|ui| {
            theme::muted(ui, summary, t);
            ui.separator();
            if theme::secondary(ui, "Scan again", !busy) {
                refresh = true;
            }
            if !selected_updates.is_empty()
                && theme::primary(
                    ui,
                    &format!("Update selected · {}", selected_updates.len()),
                    t,
                    !busy,
                )
            {
                review_selected = true;
            }
            if let Some(device) = selected.as_ref() {
                if theme::secondary(ui, "Details", !busy) {
                    show_details = true;
                }
                let candidate_count = self
                    .drivers_ui
                    .snapshot
                    .as_ref()
                    .map(|snapshot| candidates_for(Some(snapshot), device).len())
                    .unwrap_or(0);
                if candidate_count > 0 {
                    let label = if candidate_count == 1 {
                        "Review update"
                    } else {
                        "Choose offer"
                    };
                    let action_enabled = !busy
                        && self.drivers_ui.settings_error.is_none()
                        && (self.driver_selected_candidate_intent(device).is_some()
                            || self.driver_has_actionable_offer(device));
                    if theme::primary(ui, label, t, action_enabled) {
                        review_update = true;
                    }
                }
                if self.driver_selected_restore_intent(device).is_some()
                    && theme::secondary(ui, "Restore backup", !busy)
                {
                    review_restore = true;
                }
            }
        });

        if refresh {
            self.drivers_ui.attempted = false;
            self.begin_driver_load(ctx);
        }
        if show_details {
            if let Some(device) = selected.clone() {
                self.drivers_ui.dialog = Some(DriverDialog::Details(device));
            }
        }
        if review_selected {
            self.drivers_ui.dialog = Some(DriverDialog::BatchReview(selected_updates));
        }
        if review_update {
            if let Some(device) = selected.as_ref() {
                let candidates = self
                    .drivers_ui
                    .snapshot
                    .as_ref()
                    .map(|snapshot| candidates_for(Some(snapshot), device))
                    .unwrap_or_default();
                if candidates.len() == 1 {
                    match drivers::prepare_update_intent(device, candidates[0]) {
                        Ok(intent) => {
                            self.drivers_ui.dialog = Some(DriverDialog::Update(intent));
                        }
                        Err(error) => {
                            self.error = Some(format!(
                                "The selected driver offer is not ready for review: {error}"
                            ))
                        }
                    }
                } else if !candidates.is_empty() {
                    self.drivers_ui.dialog = Some(DriverDialog::Details(device.clone()));
                }
            }
        }
        if review_restore {
            if let Some(device) = selected.as_ref() {
                if let Some((update_intent, update_receipt, restore_intent)) =
                    self.driver_selected_restore_intent(device)
                {
                    self.drivers_ui.dialog = Some(DriverDialog::Restore {
                        update_intent,
                        update_receipt,
                        restore_intent,
                    });
                }
            }
        }
    }

    pub(super) fn drivers_dialog(&mut self, ctx: &egui::Context) {
        let Some(dialog) = self.drivers_ui.dialog.clone() else {
            return;
        };
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            if !self.busy() || matches!(dialog, DriverDialog::Details(_)) {
                self.drivers_ui.dialog = None;
            }
            return;
        }
        let t = theme::tokens(self.prefs.dark);
        match dialog {
            DriverDialog::Details(device) => {
                let mut close = false;
                let mut action = None;
                let width = (ctx.content_rect().width() - 32.).min(590.).max(300.);
                let max_height = (ctx.content_rect().height() - 150.).clamp(180., 600.);
                let response = egui::Modal::new(egui::Id::new("driver-device-details"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(width);
                        ui.heading("Driver details");
                        ui.add_space(8.);
                        egui::ScrollArea::vertical()
                            .max_height(max_height)
                            .auto_shrink([false, true])
                            .show(ui, |body| {
                                action = self.driver_details(body, t, &device);
                            });
                        ui.add_space(7.);
                        ui.separator();
                        ui.add_space(7.);
                        if theme::secondary(ui, "Close", true) {
                            close = true;
                        }
                    });
                if close || response.should_close() {
                    self.drivers_ui.dialog = None;
                }
                match action {
                    Some(DetailAction::Review(intent)) => {
                        self.drivers_ui.dialog = Some(DriverDialog::Update(intent));
                    }
                    Some(DetailAction::Select(intent, device_id, selected)) => {
                        self.set_driver_offer_selected(intent, device_id, selected);
                    }
                    Some(DetailAction::Restore {
                        update_intent,
                        update_receipt,
                        restore_intent,
                    }) => {
                        self.drivers_ui.dialog = Some(DriverDialog::Restore {
                            update_intent,
                            update_receipt,
                            restore_intent,
                        });
                    }
                    Some(DetailAction::Ignore(id, ignored)) => {
                        self.set_driver_ignored(id, ignored);
                    }
                    Some(DetailAction::Skip(id, candidate, skipped)) => {
                        self.set_driver_skipped(id, candidate, skipped);
                    }
                    Some(DetailAction::Error(error)) => self.error = Some(error),
                    None => {}
                }
            }
            DriverDialog::Update(intent) => {
                let mut accept = false;
                let mut close = false;
                let can_dismiss = !self.busy();
                let width = (ctx.content_rect().width() - 32.).min(560.).max(300.);
                let body_height = (ctx.content_rect().height() - 180.).clamp(150., 560.);
                let response = egui::Modal::new(egui::Id::new("driver-update-review"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(width);
                        ui.heading("Review driver update");
                        ui.add_space(7.);
                        egui::ScrollArea::vertical()
                            .max_height(body_height)
                            .auto_shrink([false, true])
                            .show(ui, |body| self.driver_update_review(body, t, &intent));
                        ui.add_space(7.);
                        ui.separator();
                        ui.add_space(7.);
                        ui.horizontal_wrapped(|actions| {
                            if theme::secondary(actions, "Cancel", can_dismiss) {
                                close = true;
                            }
                            if theme::primary(
                                actions,
                                "Install reviewed driver",
                                t,
                                can_dismiss
                                    && self.drivers_ui.settings_error.is_none()
                                    && self.driver_intent_can_apply(&intent)
                                    && drivers::supported_update_actions().is_ok(),
                            ) {
                                accept = true;
                            }
                        });
                    });
                if can_dismiss && (close || response.should_close()) {
                    self.drivers_ui.dialog = None;
                } else if can_dismiss && accept {
                    self.begin_driver_update(intent, ctx);
                }
            }
            DriverDialog::BatchReview(selected_updates) => {
                let mut accept = false;
                let mut close = false;
                let can_dismiss = !self.busy();
                let can_apply = can_dismiss && self.driver_batch_can_apply(&selected_updates);
                let width = (ctx.content_rect().width() - 32.).min(600.).max(300.);
                let body_height = (ctx.content_rect().height() - 180.).clamp(150., 560.);
                let response = egui::Modal::new(egui::Id::new("driver-batch-review"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(width);
                        ui.heading(format!("Review {} selected offers", selected_updates.len()));
                        ui.add_space(7.);
                        egui::ScrollArea::vertical()
                            .max_height(body_height)
                            .auto_shrink([false, true])
                            .show(ui, |body| {
                                self.driver_batch_review(body, t, &selected_updates)
                            });
                        ui.add_space(7.);
                        ui.separator();
                        ui.add_space(7.);
                        ui.horizontal_wrapped(|actions| {
                            if theme::secondary(actions, "Cancel", can_dismiss) {
                                close = true;
                            }
                            if theme::primary(actions, "Install reviewed updates", t, can_apply) {
                                accept = true;
                            }
                        });
                    });
                if can_dismiss && (close || response.should_close()) {
                    self.drivers_ui.dialog = None;
                } else if can_apply && accept {
                    self.begin_driver_batch(selected_updates, ctx);
                }
            }
            DriverDialog::Restore {
                update_intent,
                update_receipt,
                restore_intent,
            } => {
                let mut accept = false;
                let mut close = false;
                let can_dismiss = !self.busy();
                let width = (ctx.content_rect().width() - 32.).min(560.).max(300.);
                let body_height = (ctx.content_rect().height() - 180.).clamp(150., 560.);
                let response = egui::Modal::new(egui::Id::new("driver-restore-review"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(width);
                        ui.heading("Review driver restore");
                        ui.add_space(7.);
                        egui::ScrollArea::vertical()
                            .max_height(body_height)
                            .auto_shrink([false, true])
                            .show(ui, |body| {
                                theme::muted(
                                    body,
                                    "DCleaner will stage the exact signed package saved before the verified update, then re-read this device. Nothing changes until you confirm.",
                                    t,
                                );
                                body.add_space(10.);
                                detail(
                                    body,
                                    "Device",
                                    &self.driver_display_name(&update_intent),
                                    t,
                                );
                                detail(
                                    body,
                                    "Device instance identity",
                                    &update_intent.device_instance_id,
                                    t,
                                );
                                detail(
                                    body,
                                    "Driver to restore",
                                    &update_receipt.original_state.version,
                                    t,
                                );
                                detail(
                                    body,
                                    "Original provider",
                                    &update_receipt.original_state.provider,
                                    t,
                                );
                                detail(
                                    body,
                                    "Original INF",
                                    &update_receipt.original_state.inf,
                                    t,
                                );
                                detail(
                                    body,
                                    "Saved package",
                                    &restore_intent.backup.relative_directory,
                                    t,
                                );
                                body.add_space(8.);
                                theme::muted(
                                    body,
                                    "The restore is revalidated against the current device and saved receipt. If Windows requires a restart, DCleaner will leave that decision to you.",
                                    t,
                                );
                            });
                        ui.add_space(7.);
                        ui.separator();
                        ui.add_space(7.);
                        ui.horizontal_wrapped(|actions| {
                            if theme::secondary(actions, "Cancel", can_dismiss) {
                                close = true;
                            }
                            if theme::primary(
                                actions,
                                "Restore saved driver",
                                t,
                                can_dismiss && drivers::supported_update_actions().is_ok(),
                            ) {
                                accept = true;
                            }
                        });
                    });
                if can_dismiss && (close || response.should_close()) {
                    self.drivers_ui.dialog = None;
                } else if can_dismiss && accept {
                    self.begin_driver_restore(update_intent, update_receipt, restore_intent, ctx);
                }
            }
        }
    }

    fn begin_driver_load(&mut self, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        self.drivers_ui.attempted = true;
        self.drivers_ui.loading = true;
        self.progress =
            "Reading present devices and the configured Windows Update Agent source".into();
        let root = self.data_dir.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let repaint = ctx.clone();
        thread::spawn(move || {
            let settings = drivers::load_settings(&root).map_err(|error| error.to_string());
            let mut manager = drivers::DriverManager::new(WindowsDriverPlatform);
            let snapshot = manager.scan();
            let history = drivers::operation_history(&root);
            let _ = tx.send(Event::Drivers(DriverEvent::Loaded {
                snapshot,
                settings,
                history,
            }));
            repaint.request_repaint();
        });
    }

    fn drivers_intro_active(&self) -> bool {
        if self.qa_fixture_mode() {
            self.drivers_ui.intro_fixture
        } else {
            !self.feature_seen("drivers")
        }
    }

    fn start_driver_scan(&mut self, ctx: &egui::Context) {
        self.mark_feature_seen("drivers");
        self.begin_driver_load(ctx);
    }

    fn begin_driver_update(&mut self, intent: DriverUpdateIntent, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        self.drivers_ui.selected_updates.retain(|selected| {
            !drivers::same_wua_update(&selected.intent.candidate, &intent.candidate)
        });
        let display_name = self.driver_display_name(&intent);
        self.drivers_ui.dialog = None;
        self.progress = "Windows is preparing the reviewed driver change. This phase cannot be cancelled; no automatic restart will occur.".into();
        self.error = None;
        let root = self.data_dir.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let repaint = ctx.clone();
        thread::spawn(move || {
            let mut platform = WindowsDriverPlatform;
            let result = drivers::apply_reviewed_update(&root, &intent, &mut platform)
                .map_err(|error| error.to_string());
            let _ = tx.send(Event::Drivers(DriverEvent::UpdateFinished {
                intent_id: intent.intent_id,
                display_name,
                result,
            }));
            repaint.request_repaint();
        });
    }

    fn begin_driver_batch(
        &mut self,
        selected_updates: Vec<SelectedDriverUpdate>,
        ctx: &egui::Context,
    ) {
        if self.busy() || self.qa_fixture_mode() || !self.driver_batch_can_apply(&selected_updates)
        {
            return;
        }
        let items: Vec<(DriverUpdateIntent, String)> = selected_updates
            .iter()
            .filter_map(|selected| {
                Some((
                    selected.intent.clone(),
                    self.driver_selected_group_label(selected),
                ))
            })
            .collect();
        if items.len() != selected_updates.len() || items.is_empty() {
            self.error = Some(
                "A selected device or exact Windows Update offer is no longer available. Refresh and review the selection again.".into(),
            );
            self.drivers_ui.dialog = None;
            return;
        }

        let requested = items.len();
        self.drivers_ui.dialog = None;
        self.progress = format!(
            "Windows is applying up to {requested} reviewed driver offers sequentially. No percentage is available; the batch stops on an unverified result or restart requirement."
        );
        self.error = None;
        let root = self.data_dir.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let repaint = ctx.clone();
        thread::spawn(move || {
            let mut platform = WindowsDriverPlatform;
            let mut results = Vec::with_capacity(requested);
            for (intent, display_name) in items {
                let operation_result =
                    drivers::apply_reviewed_update(&root, &intent, &mut platform);
                let continue_batch =
                    drivers::should_continue_driver_batch(intent.intent_id, &operation_result);
                let result = operation_result.map_err(|error| error.to_string());
                results.push(DriverBatchItemResult {
                    intent_id: intent.intent_id,
                    display_name,
                    result,
                });
                if !continue_batch {
                    break;
                }
            }
            let _ = tx.send(Event::Drivers(DriverEvent::BatchUpdateFinished {
                requested,
                results,
            }));
            repaint.request_repaint();
        });
    }

    fn begin_driver_restore(
        &mut self,
        update_intent: DriverUpdateIntent,
        update_receipt: DriverUpdateReceipt,
        restore_intent: DriverRestoreIntent,
        ctx: &egui::Context,
    ) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        let display_name = self.driver_display_name(&update_intent);
        self.drivers_ui.dialog = None;
        self.progress = "Windows is staging the reviewed saved driver. This phase cannot be cancelled; no automatic restart will occur.".into();
        self.error = None;
        let root = self.data_dir.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let repaint = ctx.clone();
        thread::spawn(move || {
            let mut platform = WindowsDriverPlatform;
            let result = drivers::apply_reviewed_restore(
                &root,
                &update_intent,
                &update_receipt,
                &restore_intent,
                &mut platform,
            )
            .map_err(|error| error.to_string());
            let _ = tx.send(Event::Drivers(DriverEvent::RestoreFinished {
                restore_id: restore_intent.restore_id,
                display_name,
                result,
            }));
            repaint.request_repaint();
        });
    }

    fn driver_tabs(&mut self, ui: &mut egui::Ui, t: Tokens) {
        let counts = self.driver_tab_counts();
        theme::tabs(ui, |ui| {
            for (tab, label, count) in [
                (DriverTab::Outdated, "Outdated", counts.0),
                (DriverTab::Current, "No offer / unknown", counts.1),
                (DriverTab::Deferred, "Skipped & Ignored", counts.2),
            ] {
                let text = count.map(|count| format!("{label} · {count}"));
                theme::tab_value(
                    ui,
                    &mut self.drivers_ui.tab,
                    tab,
                    text.as_deref().unwrap_or(label),
                );
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let explanation = match self.drivers_ui.tab {
                    DriverTab::Outdated => "A Windows Update source has offered a driver",
                    DriverTab::Current => {
                        "No offer is not proof of currentness; unknown stays unknown"
                    }
                    DriverTab::Deferred => "Saved local skip and ignore choices",
                };
                theme::muted(ui, explanation, t);
            });
        });
        ui.add_space(4.);
        ui.separator();
    }

    fn driver_search(&mut self, ui: &mut egui::Ui, t: Tokens) {
        let sort_labels: Vec<&str> = DriverSort::ALL.iter().map(|sort| sort.label()).collect();
        let width = theme::search_width(ui, &sort_labels);
        theme::control_row(ui, |ui| {
            ui.label(RichText::new("Search").color(t.muted));
            theme::input(
                ui,
                &mut self.drivers_ui.query,
                width,
                "Device, class, provider or offer…",
                true,
            );
            ui.add_space(8.);
            ui.label(RichText::new("Sort by").color(t.muted));
            theme::selector(
                ui,
                "drivers-sort",
                self.drivers_ui.sort.label(),
                &sort_labels,
                |menu| {
                    for sort in DriverSort::ALL {
                        menu.selectable_value(&mut self.drivers_ui.sort, sort, sort.label());
                    }
                },
            );
            ui.add_space(8.);
            theme::checkbox(ui, &mut self.drivers_ui.descending, "Descending", true);
        });
    }

    fn driver_quality_line(&self, ui: &mut egui::Ui, t: Tokens, snapshot: &DriverSnapshot) {
        let inventory_quality = match snapshot.inventory.source.quality {
            InventoryQuality::Complete => "complete",
            InventoryQuality::Partial => "partial",
            InventoryQuality::Truncated => "truncated",
            InventoryQuality::Unavailable => "unavailable",
        };
        let catalogue_quality = catalogue_label(&snapshot.catalogue.state);
        let unknown = self.driver_tab_counts().1.unwrap_or_default();
        ui.horizontal_wrapped(|ui| {
            theme::muted(
                ui,
                format!(
                    "SetupAPI · {inventory_quality} · {} devices",
                    snapshot.inventory.source.item_count
                ),
                t,
            );
            ui.separator();
            theme::muted(ui, format!("Windows Update Agent · {catalogue_quality}"), t);
            if unknown > 0 {
                ui.separator();
                theme::muted(ui, format!("{unknown} no-offer or unknown rows"), t);
            }
        });
    }

    fn driver_table(
        &mut self,
        ui: &mut egui::Ui,
        t: Tokens,
        ctx: &egui::Context,
        snapshot: &DriverSnapshot,
    ) {
        let settings = self.drivers_ui.settings.clone().unwrap_or_default();
        let settings_readable =
            self.drivers_ui.settings_error.is_none() && self.drivers_ui.settings.is_some();
        let mut devices: Vec<(DriverDevice, DriverStatus)> = snapshot
            .inventory
            .devices
            .iter()
            .filter_map(|device| {
                let status = if settings_readable {
                    snapshot.status_for(device, &settings)
                } else {
                    DriverStatus::Unknown
                };
                (tab_matches(self.drivers_ui.tab, status)
                    && driver_matches_query(snapshot, device, &self.drivers_ui.query))
                .then(|| (device.clone(), status))
            })
            .collect();
        let sort = self.drivers_ui.sort;
        let descending = self.drivers_ui.descending;
        devices.sort_by(|(left, left_status), (right, right_status)| {
            left.category().cmp(&right.category()).then_with(|| {
                let ordering =
                    compare_devices(snapshot, left, *left_status, right, *right_status, sort);
                if descending {
                    ordering.reverse()
                } else {
                    ordering
                }
            })
        });

        let width = ui.available_width().max(340.);
        let show_offer = width >= 760.;
        let show_installed = width >= 590.;
        let show_candidate_version = width >= 900.;
        let show_release = width >= 960.;
        let action_width = 136.;
        let state_width = if width >= 590. { 94. } else { 78. };
        let offer_width = if show_offer { 148. } else { 0. };
        let installed_width = if show_installed { 92. } else { 0. };
        let candidate_version_width = if show_candidate_version { 118. } else { 0. };
        let release_width = if show_release { 92. } else { 0. };
        let column_count = 3
            + show_offer as usize
            + show_installed as usize
            + show_candidate_version as usize
            + show_release as usize;
        let gaps = 8. * column_count.saturating_sub(1) as f32;
        let name_width = (width
            - action_width
            - state_width
            - offer_width
            - installed_width
            - candidate_version_width
            - release_width
            - gaps)
            .max(112.);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.;
            table_heading(ui, "Device", name_width, t);
            if show_installed {
                table_heading(ui, "Installed", installed_width, t);
            }
            if show_offer {
                table_heading(ui, "Windows Update offer", offer_width, t);
            }
            if show_candidate_version {
                table_heading(ui, "Candidate version", candidate_version_width, t);
            }
            if show_release {
                table_heading(ui, "Release", release_width, t);
            }
            table_heading(ui, "State", state_width, t);
            table_heading(ui, "Select / actions", action_width, t);
        });
        ui.add_space(3.);
        ui.separator();

        if devices.is_empty() {
            let message = if snapshot.inventory.source.quality == InventoryQuality::Unavailable {
                "Windows did not return a device inventory. See the source details below."
            } else if self.drivers_ui.query.trim().is_empty()
                && self.drivers_ui.tab == DriverTab::Current
                && matches!(
                    &snapshot.catalogue.state,
                    CatalogueState::Unavailable { .. }
                )
            {
                "No verified up-to-date state is available because the Windows Update Agent search failed."
            } else {
                "No devices match this tab and search."
            };
            theme::card(t).show(ui, |ui| theme::muted(ui, message, t));
            return;
        }

        enum Row {
            Group(
                DriverDeviceCategory,
                usize,
                Vec<(DriverUpdateIntent, DeviceId)>,
            ),
            Device(DriverDevice, DriverStatus),
        }
        let mut grouped: BTreeMap<DriverDeviceCategory, Vec<(DriverDevice, DriverStatus)>> =
            BTreeMap::new();
        for (device, status) in devices {
            grouped
                .entry(device.category())
                .or_default()
                .push((device, status));
        }
        let mut rows = Vec::new();
        for (category, items) in grouped {
            let group_offers = items
                .iter()
                .filter_map(|(device, _)| {
                    Some((self.single_driver_offer_intent(device)?, device.id.clone()?))
                })
                .collect();
            rows.push(Row::Group(category, items.len(), group_offers));
            rows.extend(
                items
                    .into_iter()
                    .map(|(device, status)| Row::Device(device, status)),
            );
        }
        let table_width = width;
        let body_height = (ctx.content_rect().bottom() - ui.cursor().top() - 90.).max(140.);
        egui::ScrollArea::vertical()
            .id_salt("driver-device-table")
            .max_height(body_height)
            .auto_shrink([false, false])
            .show_rows(ui, 44., rows.len(), |body, visible_rows| {
                for index in visible_rows {
                    match &rows[index] {
                        Row::Group(category, count, offers) => {
                            body.allocate_ui_with_layout(
                                [table_width, 44.].into(),
                                Layout::left_to_right(Align::Center),
                                |group| {
                                    group.set_min_height(44.);
                                    group.horizontal(|group| {
                                        group.label(
                                            RichText::new(format!(
                                                "{}  ·  {} devices",
                                                category.label(),
                                                count
                                            ))
                                            .family(theme::semibold())
                                            .color(t.muted),
                                        );
                                        group.with_layout(
                                            Layout::right_to_left(Align::Center),
                                            |actions| {
                                                let all_selected = !offers.is_empty()
                                                    && offers.iter().all(|(intent, device_id)| {
                                                        self.driver_offer_selected(intent, device_id)
                                                    });
                                                let label = if all_selected { "Clear group" } else { "Select group" };
                                                if theme::row_action(
                                                    actions,
                                                    label,
                                                    !offers.is_empty() && !self.busy(),
                                                )
                                                .on_hover_text(if offers.is_empty() {
                                                    "No single, actionable Windows Update offer is available for this group."
                                                } else {
                                                    "Select or clear devices with one unambiguous exact offer. Offers shared by devices are deduplicated."
                                                })
                                                .clicked()
                                                {
                                                    for (intent, device_id) in offers {
                                                        self.set_driver_offer_selected(
                                                            intent.clone(),
                                                            device_id.clone(),
                                                            !all_selected,
                                                        );
                                                    }
                                                }
                                            },
                                        );
                                    });
                                },
                            );
                        }
                        Row::Device(device, status) => {
                            let id = device.id.as_ref().map(|id| id.0.as_str()).unwrap_or("unknown");
                            body.push_id(id, |row| {
                                row.allocate_ui_with_layout(
                                    [table_width, 44.].into(),
                                    Layout::left_to_right(Align::Center),
                                    |row| {
                                        row.set_min_height(44.);
                                        row.spacing_mut().item_spacing.x = 8.;
                                        let selected = device.id.as_ref() == self.drivers_ui.selected.as_ref();
                                        let name_response = row
                                            .allocate_ui_with_layout(
                                                [name_width, 40.].into(),
                                                Layout::left_to_right(Align::Center),
                                                |cell| {
                                                    cell.set_min_width(name_width);
                                                    cell.set_max_width(name_width);
                                                    cell.spacing_mut().item_spacing.x = 8.;
                                                    let name = known(&device.friendly_name)
                                                        .unwrap_or("Device name unavailable");
                                                    let response = cell.add_sized(
                                                        [(name_width - 8.).max(64.), 40.],
                                                        egui::Button::selectable(
                                                            selected,
                                                            (
                                                                RichText::new(name)
                                                                    .family(theme::semibold()),
                                                                egui::Atom::grow(),
                                                            ),
                                                        )
                                                        .truncate(),
                                                    );
                                                    response.on_hover_text(device_identity_tooltip(device))
                                                },
                                            )
                                            .inner;
                                        if name_response.clicked() {
                                            self.drivers_ui.selected = device.id.clone();
                                        }
                                        if show_installed {
                                            let installed = field_display(&device.installed_version);
                                            theme::table_cell(
                                                row,
                                                RichText::new(installed).color(t.muted),
                                                installed_width,
                                                40.,
                                            )
                                            .on_hover_text(field_tooltip(&device.installed_version));
                                        }
                                        if show_offer {
                                            let offer = self
                                                .drivers_ui
                                                .snapshot
                                                .as_ref()
                                                .map(|current| offer_display(current, device))
                                                .unwrap_or_else(|| "Unknown".into());
                                            theme::table_cell(
                                                row,
                                                RichText::new(offer.clone())
                                                    .color(status_color(*status, t)),
                                                offer_width,
                                                40.,
                                            )
                                            .on_hover_text(offer);
                                        }
                                        if show_candidate_version {
                                            theme::table_cell(
                                                row,
                                                RichText::new(candidate_version_cell_display(
                                                    snapshot, device,
                                                ))
                                                .color(t.muted),
                                                candidate_version_width,
                                                40.,
                                            )
                                            .on_hover_text(candidate_version_tooltip(
                                                snapshot, device,
                                            ));
                                        }
                                        if show_release {
                                            let release = release_display(snapshot, device);
                                            theme::table_cell(
                                                row,
                                                RichText::new(release).color(t.muted),
                                                release_width,
                                                40.,
                                            );
                                        }
                                        theme::table_cell(
                                            row,
                                            RichText::new(status_label(*status))
                                                .color(status_color(*status, t)),
                                            state_width,
                                            40.,
                                        );
                                        row.allocate_ui_with_layout(
                                            [action_width, 40.].into(),
                                            Layout::left_to_right(Align::Center),
                                            |actions| {
                                                actions.set_min_width(action_width);
                                                actions.set_max_width(action_width);
                                                actions.spacing_mut().item_spacing.x = 6.;
                                                let candidates = candidates_for(Some(snapshot), device);
                                                let single_intent = self.single_driver_offer_intent(device);
                                                let device_id = device.id.clone();
                                                let mut offer_selected = single_intent
                                                    .as_ref()
                                                    .zip(device_id.as_ref())
                                                    .is_some_and(|(intent, id)| self.driver_offer_selected(intent, id));
                                                let selection = theme::checkbox_widget(
                                                    actions,
                                                    egui::Checkbox::new(&mut offer_selected, ""),
                                                    single_intent.is_some() && !self.busy(),
                                                )
                                                .on_hover_text(if candidates.len() > 1 {
                                                    "Open Details and select one exact offer for this device."
                                                } else if single_intent.is_some() {
                                                    "Add this exact Windows Update offer to the reviewed selection."
                                                } else {
                                                    "Selection requires one unambiguous, actionable offer."
                                                });
                                                if selection.changed()
                                                    && let (Some(intent), Some(device_id)) = (single_intent.clone(), device_id.clone())
                                                {
                                                    self.set_driver_offer_selected(
                                                        intent,
                                                        device_id,
                                                        offer_selected,
                                                    );
                                                }
                                                let (review_label, review_reason) = match status {
                                                    DriverStatus::UpdateAvailable if candidates.len() > 1 => (
                                                        "Choose",
                                                        "Choose one exact Windows Update offer to review.",
                                                    ),
                                                    DriverStatus::UpdateAvailable => (
                                                        "Review",
                                                        "Review the exact Windows Update offer before any driver change.",
                                                    ),
                                                    DriverStatus::NoOfferFromSource => (
                                                        "No offer",
                                                        "The selected Windows Update source returned no matching offer.",
                                                    ),
                                                    DriverStatus::Skipped => (
                                                        "Skipped",
                                                        "This exact offer is skipped in saved DCleaner choices.",
                                                    ),
                                                    DriverStatus::Ignored => (
                                                        "Ignored",
                                                        "This device is ignored in saved DCleaner choices.",
                                                    ),
                                                    DriverStatus::Unknown => (
                                                        "Unknown",
                                                        "Windows did not provide enough information to classify this device.",
                                                    ),
                                                };
                                                let can_review = *status == DriverStatus::UpdateAvailable
                                                    && self.drivers_ui.settings_error.is_none()
                                                    && self.driver_has_actionable_offer(device)
                                                    && !self.busy();
                                                if theme::row_action(actions, review_label, can_review)
                                                    .on_hover_text(if self.drivers_ui.settings_error.is_some() && *status == DriverStatus::UpdateAvailable {
                                                        "Saved choices could not be read; review actions are locked."
                                                    } else {
                                                        review_reason
                                                    })
                                                    .clicked()
                                                {
                                                    if candidates.len() == 1 {
                                                        match drivers::prepare_update_intent(device, candidates[0]) {
                                                            Ok(intent) => self.drivers_ui.dialog = Some(DriverDialog::Update(intent)),
                                                            Err(error) => self.error = Some(format!("The selected driver offer is not ready for review: {error}")),
                                                        }
                                                    } else if !candidates.is_empty() {
                                                        self.drivers_ui.dialog = Some(DriverDialog::Details(device.clone()));
                                                    }
                                                }
                                                if theme::row_more(actions, !self.busy()).clicked() {
                                                    self.drivers_ui.selected = device.id.clone();
                                                    self.drivers_ui.dialog = Some(DriverDialog::Details(device.clone()));
                                                }
                                            },
                                        );
                                    },
                                );
                            });
                        }
                    }
                }
            });
    }

    fn driver_sources_panel(&self, ui: &mut egui::Ui, t: Tokens, snapshot: &DriverSnapshot) {
        egui::CollapsingHeader::new("Inventory and source details")
            .default_open(
                snapshot.inventory.source.quality != InventoryQuality::Complete
                    || !matches!(&snapshot.catalogue.state, CatalogueState::Read { .. }),
            )
            .id_salt("driver-source-details")
            .show(ui, |ui| {
                detail(
                    ui,
                    "SetupAPI inventory",
                    &format!(
                        "{:?} · {} present devices",
                        snapshot.inventory.source.quality,
                        snapshot.inventory.source.item_count
                    ),
                    t,
                );
                detail(ui, "Windows Update Agent", &catalogue_label(&snapshot.catalogue.state), t);
                if let CatalogueState::Read { source }
                | CatalogueState::Partial { source }
                | CatalogueState::Truncated { source } = &snapshot.catalogue.state
                {
                    detail(ui, "Selected update source", &source.label(), t);
                }
                if let CatalogueState::Unavailable { issue } = &snapshot.catalogue.state {
                    issue_line(ui, t, issue);
                }
                for issue in snapshot
                    .inventory
                    .source
                    .issues
                    .iter()
                    .chain(snapshot.catalogue.issues.iter())
                    .take(12)
                {
                    issue_line(ui, t, issue);
                }
                if snapshot.inventory.source.issues.len() + snapshot.catalogue.issues.len() > 12 {
                    theme::muted(ui, "Additional native read issues were omitted from this view.", t);
                }
                ui.add_space(5.);
                theme::muted(
                    ui,
                    "An offer means the selected Windows Update Agent source returned a matching driver update. No offer is not a comparison against every manufacturer catalogue. WUA does not expose a candidate driver version here, so DCleaner does not infer one. Device problem codes are read-only in this page.",
                    t,
                );
                ui.add_space(4.);
                theme::muted(
                    ui,
                    "The native SetupAPI/WUA search has no cancellation boundary. Driver installation and restore are review-gated, may require a restart, and never restart Windows automatically.",
                    t,
                );
            });
    }

    fn driver_history_panel(&self, ui: &mut egui::Ui, t: Tokens) {
        let records: Vec<&EffectHistory> = self
            .drivers_ui
            .history
            .iter()
            .filter(|record| record.feature == "drivers")
            .rev()
            .take(12)
            .collect();
        egui::CollapsingHeader::new(format!("Driver operation history · {}", records.len()))
            .default_open(false)
            .id_salt("driver-operation-history")
            .show(ui, |ui| {
                if records.is_empty() {
                    theme::muted(ui, "No recorded driver changes are available.", t);
                }
                for record in records {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(history_label(&record.state)).family(theme::semibold()));
                        theme::muted(ui, record.date.clone(), t);
                        if let Some(receipt) = record.receipt.as_ref() {
                            if let Ok(update) = serde_json::from_value::<DriverUpdateReceipt>(receipt.clone()) {
                                theme::muted(
                                    ui,
                                    format!("{:?} · restart {:?}", update.phase, update.reboot),
                                    t,
                                );
                            } else if let Ok(restore) = serde_json::from_value::<DriverRestoreReceipt>(receipt.clone()) {
                                theme::muted(
                                    ui,
                                    format!("{:?} · restart {:?}", restore.phase, restore.reboot),
                                    t,
                                );
                            }
                        } else {
                            theme::muted(ui, "No confirmed receipt · review before retrying", t);
                        }
                    });
                    ui.separator();
                }
                theme::muted(
                    ui,
                    "Incomplete or uncertain operations are never replayed automatically. A saved driver is offered for restore only when its confirmed receipt and exact current device identity pass validation.",
                    t,
                );
            });
    }

    fn driver_details(
        &self,
        ui: &mut egui::Ui,
        t: Tokens,
        device: &DriverDevice,
    ) -> Option<DetailAction> {
        let snapshot = self.drivers_ui.snapshot.as_ref()?;
        let Some(device_id) = device.id.as_ref() else {
            status_card(
                ui,
                t,
                "Actions unavailable",
                "Windows did not provide a stable identity for this device.",
            );
            return None;
        };
        detail(
            ui,
            "Device",
            known(&device.friendly_name).unwrap_or("Name unavailable"),
            t,
        );
        detail(ui, "Class", &field_display(&device.class_name), t);
        detail(ui, "Category", device.category().label(), t);
        detail(ui, "Provider", &field_display(&device.provider), t);
        detail(
            ui,
            "Installed version",
            &field_display(&device.installed_version),
            t,
        );
        detail(ui, "Driver date", &field_display(&device.installed_date), t);
        detail(ui, "Published INF", &field_display(&device.inf_path), t);
        detail(
            ui,
            "Device instance identity",
            &field_display(&device.instance_id),
            t,
        );
        if let Some(problem) = device.problem_code.as_known() {
            detail(ui, "Windows problem code", &problem.to_string(), t);
        } else {
            detail(ui, "Windows problem code", "Unknown", t);
        }

        if let Some(ids) = device.hardware_ids.as_known() {
            egui::CollapsingHeader::new(format!("Hardware IDs · {}", ids.len()))
                .default_open(false)
                .show(ui, |ui| {
                    for id in ids.iter().take(20) {
                        ui.add(egui::Label::new(RichText::new(id).monospace()).wrap());
                    }
                    if ids.len() > 20 {
                        theme::muted(ui, "Additional hardware IDs are not shown here.", t);
                    }
                });
        } else {
            let hardware_ids = match &device.hardware_ids {
                FieldValue::Unknown { failure } => {
                    format!("Unknown · {}", failure.summary())
                }
                FieldValue::Known { value } => format!("{} IDs reported", value.len()),
            };
            detail(ui, "Hardware IDs", &hardware_ids, t);
        }

        let candidates = candidates_for(Some(snapshot), device);
        let mut action = None;
        if !candidates.is_empty() {
            ui.add_space(6.);
            ui.separator();
            ui.label(RichText::new("Windows Update offers").family(theme::semibold()));
            for candidate in candidates {
                ui.add_space(4.);
                candidate_details(ui, t, &candidate);
                if self.driver_candidate_actionable(device, candidate)
                    && self.drivers_ui.settings_error.is_none()
                    && let Ok(intent) = drivers::prepare_update_intent(device, candidate)
                {
                    let mut selected_offer = self.driver_offer_selected(&intent, device_id);
                    let response = theme::checkbox(
                        ui,
                        &mut selected_offer,
                        "Select this exact offer for Update selected",
                        !self.busy(),
                    );
                    if response.changed() {
                        action = Some(DetailAction::Select(
                            intent,
                            device_id.clone(),
                            selected_offer,
                        ));
                    }
                }
                if theme::row_action(
                    ui,
                    "Review offer",
                    !self.busy()
                        && self.drivers_ui.settings_error.is_none()
                        && self.driver_candidate_actionable(device, candidate),
                )
                .clicked()
                {
                    match drivers::prepare_update_intent(device, &candidate) {
                        Ok(intent) => action = Some(DetailAction::Review(intent)),
                        Err(error) => {
                            action = Some(DetailAction::Error(format!(
                                "The selected driver offer is not ready for review: {error}"
                            )))
                        }
                    }
                }
                ui.separator();
            }
        } else {
            match &device.offer {
                DeviceOffer::NoOfferFromSource { source } => {
                    theme::muted(
                        ui,
                        format!("No matching offer was returned by {}.", source.label()),
                        t,
                    );
                }
                DeviceOffer::Unknown { failure } => {
                    theme::muted(
                        ui,
                        format!("Offer state is unknown: {}", failure.summary()),
                        t,
                    );
                }
                DeviceOffer::CandidateAvailable { .. } => {
                    theme::muted(
                        ui,
                        "The exact offer details are not available in this inventory.",
                        t,
                    );
                }
            }
        }

        let settings = self.drivers_ui.settings.as_ref();
        let ignored = settings.is_some_and(|settings| settings.is_ignored(device_id));
        let mut ignored_value = ignored;
        let mut ignore_changed = false;
        ui.add_space(6.);
        ui.separator();
        ui.label(RichText::new("Saved choices").family(theme::semibold()));
        let checkbox = theme::checkbox(
            ui,
            &mut ignored_value,
            "Ignore this device",
            !self.busy() && self.drivers_ui.settings_error.is_none(),
        );
        if checkbox.changed() {
            ignore_changed = true;
        }
        if ignore_changed {
            action = Some(DetailAction::Ignore(device_id.clone(), ignored_value));
        }
        for candidate in candidates_for(Some(snapshot), device) {
            let skipped = settings
                .is_some_and(|settings| settings.is_skipped(device_id, &candidate.identity));
            let mut skip_value = skipped;
            let label = format!(
                "Skip this exact offer · {}",
                known(&candidate.title).unwrap_or("Offer details unavailable")
            );
            let response = theme::checkbox(
                ui,
                &mut skip_value,
                label,
                !self.busy() && self.drivers_ui.settings_error.is_none(),
            );
            if response.changed() {
                action = Some(DetailAction::Skip(
                    device_id.clone(),
                    candidate.identity.clone(),
                    skip_value,
                ));
            }
        }
        if self.drivers_ui.settings_error.is_some() {
            theme::muted(
                ui,
                "Saved choices are locked until the settings file is readable.",
                t,
            );
        }

        if let Some((update_intent, update_receipt, restore_intent)) =
            self.driver_selected_restore_intent(device)
        {
            ui.add_space(6.);
            ui.separator();
            ui.label(RichText::new("Verified backup available").family(theme::semibold()));
            theme::muted(
                ui,
                "The saved package can be restored only after the current device state and receipt pass exact revalidation.",
                t,
            );
            if theme::row_action(ui, "Review restore", !self.busy()).clicked() {
                action = Some(DetailAction::Restore {
                    update_intent,
                    update_receipt,
                    restore_intent,
                });
            }
        }

        if device.has_confirmed_problem() == Some(true) {
            ui.add_space(6.);
            ui.separator();
            theme::row_action(ui, "Fix a problem", false)
                .on_hover_text("No native troubleshooting operation is available in this build.");
            theme::muted(
                ui,
                "Windows reports a device problem code. This version can show the code, but has no safe native troubleshooting action; no reset or reinstall is attempted.",
                t,
            );
        }
        Some(action).flatten()
    }

    fn driver_update_review(&self, ui: &mut egui::Ui, t: Tokens, intent: &DriverUpdateIntent) {
        let candidate = self.drivers_ui.snapshot.as_ref().and_then(|snapshot| {
            snapshot
                .catalogue
                .candidates
                .iter()
                .find(|candidate| &candidate.identity == &intent.candidate)
        });
        theme::muted(
            ui,
            "Nothing changes until you confirm. DCleaner rechecks the exact device, hardware IDs and Windows Update offer before download and install.",
            t,
        );
        ui.add_space(10.);
        review_detail(ui, "Device", &self.driver_display_name(intent), t);
        review_detail(
            ui,
            "Device class",
            candidate
                .and_then(|value| known(&value.class))
                .unwrap_or("Unavailable"),
            t,
        );
        review_detail(
            ui,
            "Offer title",
            candidate
                .and_then(|value| known(&value.title))
                .unwrap_or("Offer details unavailable"),
            t,
        );
        review_detail(
            ui,
            "Manufacturer",
            candidate
                .and_then(|value| known(&value.manufacturer))
                .unwrap_or("Unavailable"),
            t,
        );
        review_detail(
            ui,
            "Provider",
            candidate
                .and_then(|value| known(&value.provider))
                .unwrap_or(intent.provider.as_str()),
            t,
        );
        review_detail(
            ui,
            "Current installed version",
            known(&intent.installed_version).unwrap_or("Unknown"),
            t,
        );
        review_detail(
            ui,
            "Candidate version",
            &candidate
                .map(candidate_version_display)
                .unwrap_or_else(|| "Offer not available in this snapshot".into()),
            t,
        );
        review_detail(
            ui,
            "Offer release date",
            candidate
                .and_then(|value| known(&value.release_date))
                .unwrap_or("Unavailable"),
            t,
        );
        review_detail(ui, "Update source", &intent.candidate.source.label(), t);
        review_detail(
            ui,
            "Exact WUA update identity",
            &format!(
                "{} · revision {}",
                intent.candidate.update_id, intent.candidate.revision
            ),
            t,
        );
        review_detail(
            ui,
            "Matched hardware ID",
            &intent.candidate.driver_hardware_id,
            t,
        );
        review_detail(
            ui,
            "Installed INF",
            known(&intent.installed_inf).unwrap_or("Unknown"),
            t,
        );
        ui.add_space(8.);
        egui::Frame::new()
            .fill(t.tint)
            .corner_radius(8)
            .inner_margin(10.)
            .show(ui, |ui| {
                ui.label(RichText::new("Before Windows is changed").family(theme::semibold()));
                ui.add_space(4.);
                theme::muted(ui, "DCleaner writes a durable intent, creates a Windows restore point, exports and verifies the signed installed package, then revalidates the exact WUA revision before installation. Windows may require a restart; DCleaner never restarts automatically.", t);
                theme::muted(ui, "The Windows operation cannot be cancelled once started. A partial result stays in history as uncertain and is not retried automatically.", t);
            });
        if candidate.is_some_and(|candidate| candidate.eula_accepted.as_known() != Some(&true)) {
            ui.add_space(8.);
            status_card(
                ui,
                t,
                "Windows license acceptance required",
                "Accept the offer in Windows first. DCleaner will not accept a driver license on your behalf.",
            );
        }
        if candidate.is_none() {
            ui.add_space(8.);
            status_card(
                ui,
                t,
                "Offer could not be re-read",
                "Refresh the native inventory and review the exact offer again before continuing.",
            );
        }
        if drivers::supported_update_actions().is_err() {
            ui.add_space(8.);
            status_card(
                ui,
                t,
                "Native driver actions unavailable",
                "This build does not have a supported native install and restore boundary.",
            );
        }
    }

    fn selected_driver(&self) -> Option<&DriverDevice> {
        let id = self.drivers_ui.selected.as_ref()?;
        self.drivers_ui
            .snapshot
            .as_ref()?
            .inventory
            .devices
            .iter()
            .find(|device| device.id.as_ref() == Some(id))
    }

    fn driver_display_name(&self, intent: &DriverUpdateIntent) -> String {
        self.drivers_ui
            .snapshot
            .as_ref()
            .and_then(|snapshot| {
                snapshot
                    .inventory
                    .devices
                    .iter()
                    .find(|device| device.id.as_ref() == Some(&intent.device_id))
            })
            .and_then(|device| known(&device.friendly_name))
            .filter(|name| !name.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| "Selected device".into())
    }

    fn driver_batch_review(
        &self,
        ui: &mut egui::Ui,
        t: Tokens,
        selected_updates: &[SelectedDriverUpdate],
    ) {
        theme::muted(
            ui,
            "Offers with the same Windows Update GUID, revision, and source are grouped and sent once. Windows controls which matching devices receive an offer; DCleaner revalidates and verifies the representative device shown in each group, not every related device instance. Each offer gets its own synced intent, restore point, and signed package backup. The sequence stops at the first unverified result or restart requirement; it cannot be cancelled after a native operation starts.",
            t,
        );
        ui.add_space(8.);
        let Some(snapshot) = self.drivers_ui.snapshot.as_ref() else {
            status_card(
                ui,
                t,
                "Selection is no longer available",
                "Refresh the native inventory before reviewing driver updates.",
            );
            return;
        };
        for (index, selected) in selected_updates.iter().enumerate() {
            if index > 0 {
                ui.add_space(6.);
                ui.separator();
            }
            let candidate = snapshot
                .catalogue
                .candidates
                .iter()
                .find(|candidate| candidate.identity == selected.intent.candidate);
            ui.label(
                RichText::new(format!("Offer {} of {}", index + 1, selected_updates.len()))
                    .family(theme::semibold()),
            );
            review_detail(
                ui,
                "Matched devices",
                &self.driver_selected_group_label(selected),
                t,
            );
            if let Some(candidate) = candidate {
                review_detail(
                    ui,
                    "Windows Update offer",
                    known(&candidate.title).unwrap_or("Offer details unavailable"),
                    t,
                );
                review_detail(
                    ui,
                    "Provider / manufacturer",
                    &format!(
                        "{} / {}",
                        known(&candidate.provider).unwrap_or("Unknown"),
                        known(&candidate.manufacturer).unwrap_or("Unknown")
                    ),
                    t,
                );
                review_detail(
                    ui,
                    "Candidate version",
                    &candidate_version_display(candidate),
                    t,
                );
                review_detail(
                    ui,
                    "Offer release date",
                    known(&candidate.release_date).unwrap_or("Unavailable"),
                    t,
                );
                review_detail(
                    ui,
                    "Exact WUA identity",
                    &format!(
                        "{} · revision {} · {}",
                        candidate.identity.update_id,
                        candidate.identity.revision,
                        candidate.identity.source.label()
                    ),
                    t,
                );
                review_detail(
                    ui,
                    "WUA service identity",
                    if candidate.identity.source.service_id.is_empty() {
                        "No service ID reported by Windows Update Agent"
                    } else {
                        candidate.identity.source.service_id.as_str()
                    },
                    t,
                );
                for selected_device in &selected.devices {
                    if let Some(device) = snapshot
                        .inventory
                        .devices
                        .iter()
                        .find(|device| device.id.as_ref() == Some(&selected_device.id))
                    {
                        review_detail(
                            ui,
                            if selected_device.id == selected.intent.device_id {
                                "Representative device"
                            } else {
                                "Other selected device"
                            },
                            &format!(
                                "{} · {}",
                                known(&device.friendly_name).unwrap_or("Name unavailable"),
                                field_display(&device.instance_id)
                            ),
                            t,
                        );
                        review_detail(
                            ui,
                            "Current installed version",
                            &field_display(&device.installed_version),
                            t,
                        );
                        if let Some(candidate) = snapshot
                            .catalogue
                            .candidates
                            .iter()
                            .find(|candidate| candidate.identity == selected_device.candidate)
                        {
                            review_detail(
                                ui,
                                "Matched hardware ID",
                                &candidate.identity.driver_hardware_id,
                                t,
                            );
                        }
                    } else {
                        review_detail(ui, "Device instance", "No longer in inventory", t);
                    }
                }
                review_detail(
                    ui,
                    "Windows license state",
                    match candidate.eula_accepted.as_known() {
                        Some(true) => "Accepted",
                        Some(false) => "Not accepted",
                        None => "Unknown",
                    },
                    t,
                );
            } else {
                status_card(
                    ui,
                    t,
                    "Exact offer is no longer available",
                    "Refresh the inventory and select a current Windows Update offer.",
                );
            }
        }
        if selected_updates.len() > MAX_DRIVER_BATCH_OFFERS {
            ui.add_space(8.);
            status_card(
                ui,
                t,
                "Too many offers for one non-cancellable batch",
                "Select at most 16 unique Windows Update offers. Windows operations cannot be cancelled after they start, and the batch stops only at a verified result or a restart/error boundary.",
            );
        } else if !self.driver_batch_can_apply(selected_updates) {
            ui.add_space(8.);
            status_card(
                ui,
                t,
                "Selected offers cannot be applied yet",
                "A device, exact offer, saved choice, Windows license acceptance, or native action capability changed or is unavailable. Refresh and review the affected items again.",
            );
        }
    }

    fn driver_selected_group_label(&self, selected: &SelectedDriverUpdate) -> String {
        let Some(snapshot) = self.drivers_ui.snapshot.as_ref() else {
            return "Selected devices unavailable".into();
        };
        let names: Vec<String> = selected
            .devices
            .iter()
            .filter_map(|selected_device| {
                let device = snapshot
                    .inventory
                    .devices
                    .iter()
                    .find(|device| device.id.as_ref() == Some(&selected_device.id))?;
                Some(
                    known(&device.friendly_name)
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or("Name unavailable")
                        .to_owned(),
                )
            })
            .collect();
        if names.is_empty() {
            "Selected devices unavailable".into()
        } else {
            names.join(", ")
        }
    }

    fn driver_batch_can_apply(&self, selected_updates: &[SelectedDriverUpdate]) -> bool {
        if selected_updates.is_empty()
            || selected_updates.len() > MAX_DRIVER_BATCH_OFFERS
            || self.drivers_ui.settings_error.is_some()
            || self.drivers_ui.settings.is_none()
            || drivers::supported_update_actions().is_err()
            || selected_updates
                .iter()
                .enumerate()
                .any(|(index, selected)| {
                    selected_updates[..index].iter().any(|previous| {
                        drivers::same_wua_update(
                            &previous.intent.candidate,
                            &selected.intent.candidate,
                        )
                    })
                })
        {
            return false;
        }
        let Some(snapshot) = self.drivers_ui.snapshot.as_ref() else {
            return false;
        };
        selected_updates.iter().all(|selected| {
            if selected.devices.is_empty()
                || !selected.devices.iter().any(|device| {
                    device.id == selected.intent.device_id
                        && device.candidate == selected.intent.candidate
                })
            {
                return false;
            }
            let Some(candidate) = snapshot
                .catalogue
                .candidates
                .iter()
                .find(|candidate| candidate.identity == selected.intent.candidate)
            else {
                return false;
            };
            if candidate.eula_accepted.as_known() != Some(&true) {
                return false;
            }
            selected.devices.iter().all(|selected_device| {
                let Some(device) = snapshot
                    .inventory
                    .devices
                    .iter()
                    .find(|device| device.id.as_ref() == Some(&selected_device.id))
                else {
                    return false;
                };
                let Some(device_candidate) = candidates_for(Some(snapshot), device)
                    .into_iter()
                    .find(|current| current.identity == selected_device.candidate)
                else {
                    return false;
                };
                drivers::same_wua_update(&device_candidate.identity, &candidate.identity)
                    && device_candidate.eula_accepted.as_known() == Some(&true)
                    && self.driver_candidate_actionable(device, device_candidate)
            })
        })
    }

    fn driver_offer_selected(&self, intent: &DriverUpdateIntent, device_id: &DeviceId) -> bool {
        self.drivers_ui.selected_updates.iter().any(|selected| {
            drivers::same_wua_update(&selected.intent.candidate, &intent.candidate)
                && selected.devices.iter().any(|selected_device| {
                    &selected_device.id == device_id
                        && selected_device.candidate == intent.candidate
                })
        })
    }

    fn set_driver_offer_selected(
        &mut self,
        intent: DriverUpdateIntent,
        device_id: DeviceId,
        selected: bool,
    ) {
        if selected {
            if let Some(existing) =
                self.drivers_ui.selected_updates.iter_mut().find(|item| {
                    drivers::same_wua_update(&item.intent.candidate, &intent.candidate)
                })
            {
                if let Some(existing_device) = existing
                    .devices
                    .iter_mut()
                    .find(|existing_device| existing_device.id == device_id)
                {
                    existing_device.candidate = intent.candidate.clone();
                    if existing.intent.device_id == device_id {
                        existing.intent = intent;
                    }
                } else {
                    existing.devices.push(SelectedDriverDevice {
                        id: device_id,
                        candidate: intent.candidate,
                    });
                }
            } else {
                let candidate = intent.candidate.clone();
                self.drivers_ui.selected_updates.push(SelectedDriverUpdate {
                    intent,
                    devices: vec![SelectedDriverDevice {
                        id: device_id,
                        candidate,
                    }],
                });
            }
        } else {
            let identity = intent.candidate.clone();
            for item in &mut self.drivers_ui.selected_updates {
                if drivers::same_wua_update(&item.intent.candidate, &identity) {
                    item.devices.retain(|selected_device| {
                        selected_device.id != device_id || selected_device.candidate != identity
                    });
                }
            }
            self.drivers_ui
                .selected_updates
                .retain(|item| !item.devices.is_empty());
            let Some(snapshot) = self.drivers_ui.snapshot.clone() else {
                return;
            };
            for item in &mut self.drivers_ui.selected_updates {
                if item.devices.iter().any(|selected_device| {
                    selected_device.id == item.intent.device_id
                        && selected_device.candidate == item.intent.candidate
                }) {
                    continue;
                }
                let Some(selected_device) = item.devices.first() else {
                    continue;
                };
                let Some(device) = snapshot
                    .inventory
                    .devices
                    .iter()
                    .find(|device| device.id.as_ref() == Some(&selected_device.id))
                else {
                    continue;
                };
                let Some(candidate) = candidates_for(Some(&snapshot), device)
                    .into_iter()
                    .find(|candidate| candidate.identity == selected_device.candidate)
                else {
                    continue;
                };
                if let Ok(intent) = drivers::prepare_update_intent(device, candidate) {
                    item.intent = intent;
                }
            }
        }
    }

    fn single_driver_offer_intent(&self, device: &DriverDevice) -> Option<DriverUpdateIntent> {
        let snapshot = self.drivers_ui.snapshot.as_ref()?;
        let candidates = candidates_for(Some(snapshot), device);
        if candidates.len() != 1 || !self.driver_candidate_actionable(device, candidates[0]) {
            return None;
        }
        drivers::prepare_update_intent(device, candidates[0]).ok()
    }

    fn driver_selected_candidate_intent(
        &self,
        device: &DriverDevice,
    ) -> Option<DriverUpdateIntent> {
        let snapshot = self.drivers_ui.snapshot.as_ref()?;
        let candidates = candidates_for(Some(snapshot), device);
        if candidates.len() != 1 || !self.driver_candidate_actionable(device, candidates[0]) {
            return None;
        }
        drivers::prepare_update_intent(device, candidates[0]).ok()
    }

    fn revalidate_selected_driver_offers(&mut self) {
        let (Some(snapshot), Some(settings)) = (
            self.drivers_ui.snapshot.clone(),
            self.drivers_ui.settings.clone(),
        ) else {
            self.drivers_ui.selected_updates.clear();
            return;
        };
        let mut retained = Vec::new();
        for mut selected in std::mem::take(&mut self.drivers_ui.selected_updates) {
            selected.devices.retain(|selected_device| {
                let Some(device) = snapshot
                    .inventory
                    .devices
                    .iter()
                    .find(|device| device.id.as_ref() == Some(&selected_device.id))
                else {
                    return false;
                };
                let Some(candidate) = candidates_for(Some(&snapshot), device)
                    .into_iter()
                    .find(|candidate| candidate.identity == selected_device.candidate)
                else {
                    return false;
                };
                drivers::same_wua_update(&candidate.identity, &selected.intent.candidate)
                    && !settings.is_ignored(&selected_device.id)
                    && !settings.is_skipped(&selected_device.id, &candidate.identity)
            });
            if selected.devices.is_empty() {
                continue;
            }
            let representative_is_current = selected.devices.iter().any(|device| {
                device.id == selected.intent.device_id
                    && device.candidate == selected.intent.candidate
            });
            if !representative_is_current {
                let Some(selected_device) = selected.devices.first() else {
                    continue;
                };
                let Some(device) = snapshot
                    .inventory
                    .devices
                    .iter()
                    .find(|device| device.id.as_ref() == Some(&selected_device.id))
                else {
                    continue;
                };
                let Some(candidate) = candidates_for(Some(&snapshot), device)
                    .into_iter()
                    .find(|candidate| candidate.identity == selected_device.candidate)
                else {
                    continue;
                };
                let Ok(intent) = drivers::prepare_update_intent(device, candidate) else {
                    continue;
                };
                selected.intent = intent;
            }
            retained.push(selected);
        }
        self.drivers_ui.selected_updates = retained;
    }

    fn driver_intent_can_apply(&self, intent: &DriverUpdateIntent) -> bool {
        let Some(snapshot) = self.drivers_ui.snapshot.as_ref() else {
            return false;
        };
        let Some(candidate) = snapshot
            .catalogue
            .candidates
            .iter()
            .find(|candidate| candidate.identity == intent.candidate)
        else {
            return false;
        };
        let device = snapshot
            .inventory
            .devices
            .iter()
            .find(|device| device.id.as_ref() == Some(&intent.device_id));
        candidate.eula_accepted.as_known() == Some(&true)
            && device.is_some_and(|device| self.driver_candidate_actionable(device, candidate))
    }

    fn driver_has_actionable_offer(&self, device: &DriverDevice) -> bool {
        let Some(snapshot) = self.drivers_ui.snapshot.as_ref() else {
            return false;
        };
        candidates_for(Some(snapshot), device)
            .into_iter()
            .any(|candidate| self.driver_candidate_actionable(device, candidate))
    }

    fn driver_candidate_actionable(
        &self,
        device: &DriverDevice,
        candidate: &DriverCandidate,
    ) -> bool {
        let Some(device_id) = device.id.as_ref() else {
            return false;
        };
        self.drivers_ui.settings.as_ref().is_some_and(|settings| {
            !settings.is_ignored(device_id) && !settings.is_skipped(device_id, &candidate.identity)
        })
    }

    fn driver_selected_restore_intent(
        &self,
        device: &DriverDevice,
    ) -> Option<(DriverUpdateIntent, DriverUpdateReceipt, DriverRestoreIntent)> {
        let device_id = device.id.as_ref()?;
        for record in self.drivers_ui.history.iter().rev() {
            if record.feature != "drivers" || record.state != "verified" {
                continue;
            }
            let Ok(intent) = serde_json::from_value::<DriverUpdateIntent>(record.intent.clone())
            else {
                continue;
            };
            let Some(receipt_value) = record.receipt.clone() else {
                continue;
            };
            let Ok(receipt) = serde_json::from_value::<DriverUpdateReceipt>(receipt_value) else {
                continue;
            };
            if &intent.device_id != device_id || !receipt.is_restore_eligible() {
                continue;
            }
            let Ok(restore) = drivers::prepare_restore_intent(&intent, &receipt, device) else {
                continue;
            };
            return Some((intent, receipt, restore));
        }
        None
    }

    fn driver_tab_counts(&self) -> (Option<usize>, Option<usize>, Option<usize>) {
        let Some(snapshot) = self.drivers_ui.snapshot.as_ref() else {
            return (None, None, None);
        };
        let Some(settings) = self.drivers_ui.settings.as_ref() else {
            return (None, None, None);
        };
        (
            snapshot
                .inventory
                .devices
                .iter()
                .filter(|device| {
                    snapshot.status_for(device, settings) == DriverStatus::UpdateAvailable
                })
                .count()
                .into(),
            snapshot
                .inventory
                .devices
                .iter()
                .filter(|device| {
                    matches!(
                        snapshot.status_for(device, settings),
                        DriverStatus::NoOfferFromSource | DriverStatus::Unknown
                    )
                })
                .count()
                .into(),
            snapshot
                .inventory
                .devices
                .iter()
                .filter(|device| {
                    matches!(
                        snapshot.status_for(device, settings),
                        DriverStatus::Skipped | DriverStatus::Ignored
                    )
                })
                .count()
                .into(),
        )
    }

    fn driver_footer_summary(&self) -> String {
        let Some(snapshot) = self.drivers_ui.snapshot.as_ref() else {
            return if self.drivers_ui.loading {
                "Reading device and Windows Update source".into()
            } else {
                "Driver inventory not loaded".into()
            };
        };
        let counts = self.driver_tab_counts();
        format!(
            "{} devices · {} with offers · {:?}",
            snapshot.inventory.source.item_count,
            counts.0.unwrap_or_default(),
            snapshot.inventory.source.quality
        )
    }

    fn set_driver_ignored(&mut self, device_id: DeviceId, ignored: bool) {
        if self.qa_fixture_mode() {
            self.error =
                Some("QA fixture mode is read-only; no driver preference was saved.".into());
            return;
        }
        let Some(current) = self.drivers_ui.settings.clone() else {
            self.error =
                Some("Saved driver choices are not readable; the device was not changed.".into());
            return;
        };
        let mut updated = current;
        if let Err(error) = updated.set_ignored(device_id, ignored) {
            self.error = Some(error.to_string());
            return;
        }
        match drivers::save_settings(&self.data_dir, &updated) {
            Ok(()) => {
                self.drivers_ui.settings = Some(updated);
                self.revalidate_selected_driver_offers();
                self.error = None;
                self.notice = Some(if ignored {
                    "This device is hidden under Skipped & Ignored. Windows was not changed.".into()
                } else {
                    "The device ignore choice was removed. Windows was not changed.".into()
                });
            }
            Err(error) => {
                self.error = Some(format!("The saved device choice was not written: {error}"))
            }
        }
    }

    fn set_driver_skipped(
        &mut self,
        device_id: DeviceId,
        candidate: drivers::CandidateIdentity,
        skipped: bool,
    ) {
        if self.qa_fixture_mode() {
            self.error =
                Some("QA fixture mode is read-only; no driver preference was saved.".into());
            return;
        }
        let Some(current) = self.drivers_ui.settings.clone() else {
            self.error =
                Some("Saved driver choices are not readable; the offer was not changed.".into());
            return;
        };
        let mut updated = current;
        if let Err(error) = updated.set_skipped(device_id, candidate, skipped) {
            self.error = Some(error.to_string());
            return;
        }
        match drivers::save_settings(&self.data_dir, &updated) {
            Ok(()) => {
                self.drivers_ui.settings = Some(updated);
                self.revalidate_selected_driver_offers();
                self.error = None;
                self.notice = Some(if skipped {
                    "This exact Windows Update offer is skipped. Windows was not changed.".into()
                } else {
                    "The saved skip choice was removed. Windows was not changed.".into()
                });
            }
            Err(error) => {
                self.error = Some(format!("The saved offer choice was not written: {error}"))
            }
        }
    }
}

#[cfg(debug_assertions)]
fn driver_qa_snapshot(populated: bool) -> DriverSnapshot {
    let issue = NativeIssue {
        source: "Synthetic QA fixture".into(),
        operation: "No native device or update-source query was issued.".into(),
        failure: FieldFailure {
            kind: FieldFailureKind::NotPresent,
            native_code: None,
        },
    };
    let devices = if populated {
        let instance_id = "QA\\SYNTHETIC\\DISPLAY".to_owned();
        vec![DriverDevice {
            id: DeviceId::from_instance_id(&instance_id),
            instance_id: FieldValue::Known { value: instance_id },
            friendly_name: FieldValue::Known {
                value: "QA fixture display adapter (synthetic)".into(),
            },
            class_name: FieldValue::Known {
                value: "Display".into(),
            },
            class_guid: "4d36e968-e325-11ce-bfc1-08002be10318".into(),
            hardware_ids: FieldValue::Known {
                value: vec!["QA\\SYNTHETIC\\DISPLAY".into()],
            },
            compatible_ids: FieldValue::Known { value: Vec::new() },
            provider: FieldValue::Known {
                value: "Synthetic fixture metadata".into(),
            },
            installed_version: FieldValue::Known {
                value: "0.0-qa".into(),
            },
            installed_date: FieldValue::Unknown {
                failure: issue.failure.clone(),
            },
            inf_path: FieldValue::Unknown {
                failure: issue.failure.clone(),
            },
            problem_code: FieldValue::Unknown {
                failure: issue.failure.clone(),
            },
            offer: DeviceOffer::Unknown {
                failure: issue.failure.clone(),
            },
        }]
    } else {
        Vec::new()
    };
    let inventory = DeviceInventory {
        source: SourceReport {
            quality: if populated {
                InventoryQuality::Partial
            } else {
                InventoryQuality::Unavailable
            },
            item_count: devices.len(),
            issues: vec![issue.clone()],
        },
        devices,
    };
    let catalogue = DriverCatalogue {
        state: CatalogueState::Unavailable {
            issue: issue.clone(),
        },
        candidates: Vec::new(),
        issues: vec![issue],
    };
    DriverSnapshot::assemble(inventory, catalogue)
}

fn candidates_for<'a>(
    snapshot: Option<&'a DriverSnapshot>,
    device: &DriverDevice,
) -> Vec<&'a DriverCandidate> {
    let (Some(snapshot), DeviceOffer::CandidateAvailable { candidates }) =
        (snapshot, &device.offer)
    else {
        return Vec::new();
    };
    candidates
        .iter()
        .filter_map(|id| {
            snapshot
                .catalogue
                .candidates
                .iter()
                .find(|candidate| candidate.id == *id)
        })
        .collect()
}

fn tab_matches(tab: DriverTab, status: DriverStatus) -> bool {
    match tab {
        DriverTab::Outdated => status == DriverStatus::UpdateAvailable,
        DriverTab::Current => matches!(
            status,
            DriverStatus::NoOfferFromSource | DriverStatus::Unknown
        ),
        DriverTab::Deferred => matches!(status, DriverStatus::Skipped | DriverStatus::Ignored),
    }
}

fn driver_matches_query(snapshot: &DriverSnapshot, device: &DriverDevice, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    let mut fields: Vec<&str> = [
        known(&device.friendly_name),
        known(&device.class_name),
        known(&device.provider),
        known(&device.instance_id),
    ]
    .into_iter()
    .flatten()
    .collect();
    if let Some(ids) = device.hardware_ids.as_known() {
        fields.extend(ids.iter().map(String::as_str));
    }
    if let Some(ids) = device.compatible_ids.as_known() {
        fields.extend(ids.iter().map(String::as_str));
    }
    fields.extend(
        candidates_for(Some(snapshot), device)
            .into_iter()
            .flat_map(|candidate| {
                [
                    known(&candidate.title),
                    known(&candidate.manufacturer),
                    known(&candidate.model),
                    known(&candidate.provider),
                ]
                .into_iter()
                .flatten()
            }),
    );
    fields
        .into_iter()
        .any(|value| value.to_lowercase().contains(&query))
}

fn offer_display(snapshot: &DriverSnapshot, device: &DriverDevice) -> String {
    match &device.offer {
        DeviceOffer::CandidateAvailable { .. } => {
            let candidates = candidates_for(Some(snapshot), device);
            match candidates.as_slice() {
                [candidate] => known(&candidate.title)
                    .unwrap_or("Offer details unavailable")
                    .to_owned(),
                candidates if !candidates.is_empty() => format!("{} offers", candidates.len()),
                _ => "Offer details unavailable".into(),
            }
        }
        DeviceOffer::NoOfferFromSource { .. } => "No matching offer".into(),
        DeviceOffer::Unknown { .. } => "Unknown".into(),
    }
}

fn release_display(snapshot: &DriverSnapshot, device: &DriverDevice) -> String {
    let candidates = candidates_for(Some(snapshot), device);
    match candidates.as_slice() {
        [candidate] => field_display(&candidate.release_date),
        candidates if candidates.len() > 1 => "Multiple offers".into(),
        _ => "—".into(),
    }
}

fn candidate_version_cell_display(snapshot: &DriverSnapshot, device: &DriverDevice) -> String {
    match candidates_for(Some(snapshot), device).as_slice() {
        [candidate] => candidate
            .candidate_version
            .as_known()
            .filter(|version| !version.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| "Unknown".into()),
        candidates if candidates.len() > 1 => "Multiple offers".into(),
        _ if matches!(&device.offer, DeviceOffer::Unknown { .. }) => "Unknown".into(),
        _ => "—".into(),
    }
}

fn candidate_version_tooltip(snapshot: &DriverSnapshot, device: &DriverDevice) -> String {
    match candidates_for(Some(snapshot), device).as_slice() {
        [candidate] => match &candidate.candidate_version {
            FieldValue::Known { value } if !value.trim().is_empty() => {
                "Candidate version reported by Windows Update Agent".into()
            }
            FieldValue::Known { .. } => {
                "Windows Update Agent returned an empty candidate version".into()
            }
            FieldValue::Unknown { failure } => failure.summary().into(),
        },
        candidates if candidates.len() > 1 => {
            "Several exact offers are available; review an offer to see its version field.".into()
        }
        _ => match &device.offer {
            DeviceOffer::Unknown { failure } => failure.summary().into(),
            DeviceOffer::NoOfferFromSource { .. } => {
                "The selected source returned no matching offer.".into()
            }
            DeviceOffer::CandidateAvailable { .. } => {
                "Exact offer details are unavailable in this result.".into()
            }
        },
    }
}

fn compare_devices(
    snapshot: &DriverSnapshot,
    left: &DriverDevice,
    left_status: DriverStatus,
    right: &DriverDevice,
    right_status: DriverStatus,
    sort: DriverSort,
) -> std::cmp::Ordering {
    let compare_text = |left: &str, right: &str| left.to_lowercase().cmp(&right.to_lowercase());
    let ordering = match sort {
        DriverSort::Device => compare_text(
            known(&left.friendly_name).unwrap_or(""),
            known(&right.friendly_name).unwrap_or(""),
        ),
        DriverSort::Provider => compare_text(
            known(&left.provider).unwrap_or(""),
            known(&right.provider).unwrap_or(""),
        ),
        DriverSort::Installed => compare_text(
            known(&left.installed_version).unwrap_or(""),
            known(&right.installed_version).unwrap_or(""),
        ),
        DriverSort::Release => compare_text(
            &release_display(snapshot, left),
            &release_display(snapshot, right),
        ),
        DriverSort::State => status_label(left_status).cmp(status_label(right_status)),
    };
    ordering.then_with(|| {
        compare_text(
            known(&left.friendly_name).unwrap_or(""),
            known(&right.friendly_name).unwrap_or(""),
        )
    })
}

fn status_label(status: DriverStatus) -> &'static str {
    match status {
        DriverStatus::UpdateAvailable => "Offer available",
        DriverStatus::NoOfferFromSource => "No offer",
        DriverStatus::Skipped => "Skipped",
        DriverStatus::Ignored => "Ignored",
        DriverStatus::Unknown => "Unknown",
    }
}

fn status_color(status: DriverStatus, t: Tokens) -> egui::Color32 {
    match status {
        DriverStatus::UpdateAvailable => t.primary,
        DriverStatus::Skipped | DriverStatus::Ignored | DriverStatus::Unknown => t.attention,
        DriverStatus::NoOfferFromSource => t.muted,
    }
}

fn catalogue_label(state: &CatalogueState) -> String {
    match state {
        CatalogueState::Read { .. } => "search completed".into(),
        CatalogueState::Partial { .. } => "partial search".into(),
        CatalogueState::Unavailable { .. } => "unavailable".into(),
        CatalogueState::Truncated { .. } => "result limit reached".into(),
    }
}

fn known(field: &FieldValue<String>) -> Option<&str> {
    field.as_known().map(String::as_str)
}

fn field_display<T: std::fmt::Display>(field: &FieldValue<T>) -> String {
    match field {
        FieldValue::Known { value } if !value.to_string().trim().is_empty() => value.to_string(),
        FieldValue::Known { .. } => "Empty value reported by Windows".into(),
        FieldValue::Unknown { failure } => format!("Unknown · {}", failure.summary()),
    }
}

fn field_tooltip<T>(field: &FieldValue<T>) -> String {
    match field {
        FieldValue::Known { .. } => "Reported by Windows SetupAPI".into(),
        FieldValue::Unknown { failure } => failure.summary().into(),
    }
}

fn device_identity_tooltip(device: &DriverDevice) -> String {
    format!(
        "{}\n{}",
        field_display(&device.friendly_name),
        field_display(&device.instance_id)
    )
}

fn tab_header(ui: &mut egui::Ui, label: &str, width: f32, t: Tokens) {
    theme::table_cell(
        ui,
        RichText::new(label)
            .size(theme::FONT_CAPTION)
            .color(t.muted),
        width,
        22.,
    );
}

fn table_heading(ui: &mut egui::Ui, label: &str, width: f32, t: Tokens) {
    tab_header(ui, label, width, t);
}

fn detail(ui: &mut egui::Ui, name: &str, value: &str, t: Tokens) {
    theme::muted(ui, name, t);
    ui.add(egui::Label::new(value).wrap());
    ui.add_space(4.);
}

fn review_detail(ui: &mut egui::Ui, name: &str, value: &str, t: Tokens) {
    theme::muted(ui, name, t);
    ui.add(egui::Label::new(value).wrap());
    ui.add_space(5.);
}

fn candidate_details(ui: &mut egui::Ui, t: Tokens, candidate: &DriverCandidate) {
    detail(
        ui,
        "Offer",
        known(&candidate.title).unwrap_or("Offer details unavailable"),
        t,
    );
    detail(
        ui,
        "Provider / manufacturer",
        &format!(
            "{} / {}",
            known(&candidate.provider).unwrap_or("Unknown"),
            known(&candidate.manufacturer).unwrap_or("Unknown")
        ),
        t,
    );
    detail(
        ui,
        "Candidate version",
        &candidate_version_display(candidate),
        t,
    );
    detail(
        ui,
        "Release date",
        known(&candidate.release_date).unwrap_or("Unavailable"),
        t,
    );
    detail(
        ui,
        "Exact WUA identity",
        &format!(
            "{} · revision {}",
            candidate.identity.update_id, candidate.identity.revision
        ),
        t,
    );
    detail(
        ui,
        "License state",
        match candidate.eula_accepted.as_known() {
            Some(true) => "Accepted in Windows",
            Some(false) => "Not accepted in Windows",
            None => "Unknown",
        },
        t,
    );
}

fn candidate_version_display(candidate: &DriverCandidate) -> String {
    match candidate.candidate_version.as_known() {
        Some(version) if !version.trim().is_empty() => version.clone(),
        _ => field_display(&candidate.candidate_version),
    }
}

fn issue_line(ui: &mut egui::Ui, t: Tokens, issue: &drivers::NativeIssue) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{} · {}", issue.source, issue.operation)).color(t.muted));
        ui.label(issue.failure.summary());
        if let Some(code) = issue.failure.native_code {
            ui.label(
                RichText::new(format!("0x{code:08X}"))
                    .monospace()
                    .color(t.muted),
            );
        }
    });
}

fn history_label(state: &str) -> &str {
    match state {
        "verified" => "Update verified",
        "applied" => "Applied · restart or verification pending",
        "restored" => "Driver restored",
        "failed" => "Operation failed",
        "uncertain" => "Outcome uncertain · inspect before retry",
        other => other,
    }
}

fn reboot_note(requirement: RebootRequirement) -> String {
    match requirement {
        RebootRequirement::Required => " Restart required; it will not be automatic.".into(),
        RebootRequirement::NotRequired => " No restart was reported by Windows.".into(),
        RebootRequirement::Unknown => " Windows did not provide a restart requirement.".into(),
    }
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
