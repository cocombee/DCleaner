use super::*;
use crate::theme;
use dcleaner::startup::RegistryValueSnapshot;
#[cfg(any(test, debug_assertions))]
use dcleaner::startup::{CHANGE_SCHEMA_VERSION, RegistryView, SourceOutcome};
use dcleaner::{
    effects::{self, EffectHistory, EffectJournal},
    startup::{
        ChangeIntent, ChangeOutcome, ChangeReceipt, EnabledState, EntryIdentity, FieldValue,
        InventoryQuality, NativeState, ObservedState, SourceState, StartupEntry, StartupId,
        StartupInventory, StartupManager, StartupPlatform, StartupSection, WindowsStartupPlatform,
    },
    startup_removal::{
        RemovalIntent, RemovalOutcome, RemovalReceipt, RemovalRestoreIntent, RemovalRestoreOutcome,
        RemovalRestoreReceipt, RunValueRemovalManager, RunValueSlots,
        WindowsRunValueRemovalPlatform, valid_removal_intent, valid_removal_receipt,
        valid_restore_intent, valid_restore_receipt,
    },
};
use std::{collections::HashMap, path::Path, sync::Arc};

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortColumn {
    Program,
    Publisher,
    FilePath,
    Enabled,
}

fn startup_section_icon(section: StartupSection) -> theme::Icon {
    match section {
        StartupSection::StartupApps => theme::Icon::Startup,
        StartupSection::ScheduledTasks => theme::Icon::History,
        StartupSection::ContextMenu => theme::Icon::ContextMenu,
        StartupSection::WindowsServices => theme::Icon::Services,
    }
}

fn startup_section_description(section: StartupSection) -> &'static str {
    match section {
        StartupSection::StartupApps => {
            "Run entries and Startup-folder shortcuts registered for the user or machine."
        }
        StartupSection::ScheduledTasks => {
            "Task Scheduler registrations, with their available trigger and action details."
        }
        StartupSection::ContextMenu => {
            "Shell commands and extensions registered for Windows Explorer menus."
        }
        StartupSection::WindowsServices => {
            "Service startup configuration and current service state."
        }
    }
}

fn startup_cached_tab_count(inventory: Option<&StartupInventory>) -> Option<usize> {
    let inventory = inventory?;
    match inventory.quality {
        InventoryQuality::Complete => Some(inventory.entries.len()),
        InventoryQuality::Partial | InventoryQuality::Unavailable => None,
    }
}

pub(super) struct StartupUi {
    section: StartupSection,
    inventories: HashMap<StartupSection, Arc<StartupInventory>>,
    loaded: bool,
    history: Arc<Vec<EffectHistory>>,
    history_view: Arc<HistoryView>,
    history_error: Option<String>,
    query: String,
    sort: SortColumn,
    descending: bool,
    selected: Option<StartupId>,
    details_open: bool,
    was_focused: bool,
    last_refresh: Option<std::time::Instant>,
    background_read: Option<Receiver<StartupInventory>>,
    selected_history: Option<Uuid>,
    review: Option<ReviewAction>,
    removal_review: Option<RemovalReview>,
    #[cfg(debug_assertions)]
    qa_more_open: bool,
}

impl Default for StartupUi {
    fn default() -> Self {
        Self {
            section: StartupSection::StartupApps,
            inventories: HashMap::new(),
            loaded: false,
            history: Arc::new(Vec::new()),
            history_view: Arc::new(HistoryView::default()),
            history_error: None,
            query: String::new(),
            sort: SortColumn::Program,
            descending: false,
            selected: None,
            details_open: false,
            was_focused: false,
            last_refresh: None,
            background_read: None,
            selected_history: None,
            review: None,
            removal_review: None,
            #[cfg(debug_assertions)]
            qa_more_open: false,
        }
    }
}

pub(super) enum StartupEvent {
    Loaded {
        inventories: Vec<StartupInventory>,
        history: Result<PreparedHistory, String>,
    },
    Prepared {
        id: StartupId,
        target_enabled: bool,
        result: Result<ChangeIntent, String>,
    },
    Changed(Result<ChangeReceipt, String>),
    RemovalPrepared {
        id: StartupId,
        result: Result<RemovalIntent, String>,
    },
    RemovalRestorePrepared {
        source_operation_id: Uuid,
        result: Result<RemovalRestoreIntent, String>,
    },
    Removed(Result<RemovalReceipt, String>),
    RemovalRestored(Result<RemovalRestoreReceipt, String>),
}

#[derive(Clone)]
enum RemovalReview {
    Remove(RemovalIntent),
    Restore(RemovalRestoreIntent),
}

#[derive(Clone)]
enum RemovalHistorySource {
    Intent(RemovalIntent),
    Receipt(RemovalReceipt),
}

#[derive(Clone)]
enum ReviewAction {
    Apply(ChangeIntent),
    Restore(ChangeReceipt),
    RecoverIntent(ChangeIntent),
    RecoverReceipt(ChangeReceipt),
}

#[derive(Default)]
struct HistoryView {
    rows: Vec<HistoryRow>,
    has_uncertain: bool,
}

struct HistoryRow {
    id: Uuid,
    label: String,
    state: String,
    action: Option<ReviewAction>,
    removal: Option<RemovalHistorySource>,
}

pub(super) struct PreparedHistory {
    records: Arc<Vec<EffectHistory>>,
    view: Arc<HistoryView>,
}

impl PreparedHistory {
    // Prepared on the loader worker. These cached candidates never bypass the
    // existing review and native revalidation required to perform an action.
    fn prepare(records: Vec<EffectHistory>, cancel: &AtomicBool) -> Result<Self, String> {
        let mut view = HistoryView::default();
        if cancel.load(Ordering::Relaxed) {
            return Err("Startup history preparation cancelled".into());
        }
        for record in &records {
            if cancel.load(Ordering::Relaxed) {
                return Err("Startup history preparation cancelled".into());
            }
            view.has_uncertain |= record.state == "uncertain";
            view.rows.push(HistoryRow {
                id: record.id,
                label: format!(
                    "{} · {} · {}",
                    record.date,
                    history_state_label(record),
                    history_record_summary(record)
                ),
                state: record.state.clone(),
                action: history_review_action(record, &records),
                removal: history_removal_source(record, &records),
            });
        }
        if cancel.load(Ordering::Relaxed) {
            return Err("Startup history preparation cancelled".into());
        }
        Ok(Self {
            records: Arc::new(records),
            view: Arc::new(view),
        })
    }
}

impl ReviewAction {
    fn id(&self) -> &StartupId {
        match self {
            Self::Apply(intent) | Self::RecoverIntent(intent) => &intent.id,
            Self::Restore(receipt) | Self::RecoverReceipt(receipt) => &receipt.id,
        }
    }

    fn snapshots(&self) -> (&ObservedState, &ObservedState) {
        match self {
            Self::Apply(intent) => (&intent.before, &intent.expected_after),
            Self::Restore(receipt) | Self::RecoverReceipt(receipt) => {
                (&receipt.after, &receipt.before)
            }
            Self::RecoverIntent(intent) => (&intent.expected_after, &intent.before),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Apply(_) => "Apply reviewed change",
            Self::Restore(_) => "Restore confirmed change",
            Self::RecoverIntent(_) | Self::RecoverReceipt(_) => "Review guarded recovery",
        }
    }

    fn is_recovery(&self) -> bool {
        matches!(self, Self::RecoverIntent(_) | Self::RecoverReceipt(_))
    }
}

impl App {
    #[cfg(debug_assertions)]
    pub(super) fn seed_startup_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Startup visual fixtures require fixture mode.".into());
        }
        if !matches!(
            case,
            "startup-empty"
                | "startup-populated"
                | "startup-details"
                | "startup-error"
                | "startup-history"
                | "startup-history-review"
        ) {
            return Err(format!("Unsupported Startup Manager fixture: {case}"));
        }

        let populated = !matches!(case, "startup-empty");
        let partial = case == "startup-error";
        let mut inventories = HashMap::new();
        for section in StartupSection::ALL {
            let entries = if populated {
                vec![startup_qa_entry(
                    section,
                    if partial {
                        EnabledState::Unknown {
                            reason: "Synthetic fixture state is unknown.".into(),
                        }
                    } else if section == StartupSection::ScheduledTasks
                        || section == StartupSection::WindowsServices
                    {
                        EnabledState::Disabled
                    } else {
                        EnabledState::Enabled
                    },
                )]
            } else {
                Vec::new()
            };
            let mut sources = vec![SourceOutcome {
                source: format!("Synthetic {case} fixture"),
                state: SourceState::Read {
                    items: entries.len(),
                },
            }];
            if partial {
                sources.push(SourceOutcome {
                    source: "Synthetic inaccessible fixture source".into(),
                    state: SourceState::Inaccessible {
                        reason: "Synthetic permission error; no native source was read.".into(),
                    },
                });
            }
            inventories.insert(
                section,
                Arc::new(StartupInventory {
                    section,
                    quality: if partial {
                        InventoryQuality::Partial
                    } else {
                        InventoryQuality::Complete
                    },
                    entries,
                    sources,
                }),
            );
        }

        let selected = inventories
            .get(&StartupSection::StartupApps)
            .and_then(|inventory| inventory.entries.first())
            .map(|entry| entry.id.clone());
        self.startup_ui = StartupUi {
            inventories,
            loaded: true,
            selected: selected.clone(),
            details_open: case == "startup-details" && selected.is_some(),
            last_refresh: Some(std::time::Instant::now()),
            ..StartupUi::default()
        };
        if matches!(case, "startup-history" | "startup-history-review") {
            let entry = &self.startup_ui.inventories[&StartupSection::StartupApps].entries[0];
            let mut intent =
                startup_qa_intent(entry, false).ok_or("Invalid synthetic history intent")?;
            intent.intent_id = Uuid::from_u128(0x400);
            let history = PreparedHistory::prepare(
                vec![EffectHistory {
                    id: intent.intent_id,
                    feature: "startup".into(),
                    date: "2026-10-17T00:00:00Z".into(),
                    intent: serde_json::to_value(&intent).map_err(|e| e.to_string())?,
                    state: "uncertain".into(),
                    receipt: None,
                }],
                &AtomicBool::new(false),
            )?;
            self.startup_ui.history = history.records;
            self.startup_ui.history_view = history.view;
            self.startup_ui.selected_history = Some(intent.intent_id);
            if case == "startup-history-review" {
                self.startup_ui.review = Some(ReviewAction::RecoverIntent(intent));
            }
        }
        self.error = None;
        self.notice = None;
        self.progress.clear();
        Ok(())
    }

    pub(super) fn startup_overview_status(&self) -> String {
        self.startup_ui
            .inventories
            .get(&StartupSection::StartupApps)
            .map(|inventory| {
                format!(
                    "{} items{}",
                    inventory.entries.len(),
                    if inventory.quality != InventoryQuality::Complete {
                        " · partial"
                    } else {
                        ""
                    }
                )
            })
            .unwrap_or_else(|| "Not scanned".into())
    }
    pub(super) fn startup_event(&mut self, event: StartupEvent) {
        match event {
            StartupEvent::Loaded {
                inventories,
                history,
            } => {
                self.worker = None;
                let ui = &mut self.startup_ui;
                ui.inventories = inventories
                    .into_iter()
                    .map(|inventory| (inventory.section, Arc::new(inventory)))
                    .collect();
                ui.loaded = true;
                ui.last_refresh = Some(std::time::Instant::now());
                match history {
                    Ok(history) => {
                        ui.history = history.records;
                        ui.history_view = history.view;
                        ui.history_error = None;
                        if ui
                            .selected_history
                            .is_some_and(|id| !ui.history.iter().any(|record| record.id == id))
                        {
                            ui.selected_history = None;
                        }
                    }
                    Err(error) => {
                        ui.history = Arc::new(Vec::new());
                        ui.history_view = Arc::new(HistoryView::default());
                        ui.selected_history = None;
                        ui.history_error = Some(error);
                    }
                }
                if ui.selected.as_ref().is_some_and(|id| {
                    !ui.inventories
                        .values()
                        .any(|inventory| inventory.entries.iter().any(|entry| &entry.id == id))
                }) {
                    ui.selected = None;
                }
            }
            StartupEvent::Prepared {
                id,
                target_enabled,
                result,
            } => {
                self.worker = None;
                match result {
                    Ok(intent)
                        if intent.id == id
                            && intent.target_enabled == target_enabled
                            && valid_change_intent(&intent) =>
                    {
                        self.error = None;
                        self.startup_ui.review = Some(ReviewAction::Apply(intent));
                    }
                    Ok(_) => {
                        self.error = Some(
                            "The selected startup item changed during review. No action was taken."
                                .into(),
                        );
                    }
                    Err(error) => {
                        self.error = Some(format!(
                            "The selected startup item could not be prepared: {error}"
                        ));
                    }
                }
            }
            StartupEvent::Changed(result) => {
                self.worker = None;
                self.startup_ui.review = None;
                self.startup_ui.loaded = false;
                match result {
                    Ok(receipt) => {
                        self.error = None;
                        self.set_notice(match receipt.outcome {
                            ChangeOutcome::Applied => {
                                "The reviewed startup setting changed and was verified. A restore receipt was saved.".into()
                            }
                            ChangeOutcome::AlreadyApplied => {
                                "The requested startup state was already present. No native write was made.".into()
                            }
                            ChangeOutcome::Restored => {
                                "The original startup setting was restored and verified.".into()
                            }
                            ChangeOutcome::AlreadyRestored => {
                                "The original startup setting was already in place. No native write was made.".into()
                            }
                        });
                    }
                    Err(error) => {
                        self.error = Some(error);
                    }
                }
            }
            StartupEvent::RemovalPrepared { id, result } => {
                self.worker = None;
                match result {
                    Ok(intent) if intent.id == id && valid_removal_intent(&intent) => {
                        self.error = None;
                        self.startup_ui.removal_review = Some(RemovalReview::Remove(intent));
                    }
                    Ok(_) => {
                        self.error = Some(
                            "The selected Run registration changed during removal review. No action was taken.".into(),
                        );
                    }
                    Err(error) => {
                        self.error = Some(format!(
                            "The selected Run registration could not be prepared for removal: {error}"
                        ));
                    }
                }
            }
            StartupEvent::RemovalRestorePrepared {
                source_operation_id,
                result,
            } => {
                self.worker = None;
                match result {
                    Ok(intent)
                        if intent.source_operation_id == source_operation_id
                            && valid_restore_intent(&intent) =>
                    {
                        self.error = None;
                        self.startup_ui.removal_review = Some(RemovalReview::Restore(intent));
                    }
                    Ok(_) => {
                        self.error = Some(
                            "The saved removal identity changed during restore review. No action was taken.".into(),
                        );
                    }
                    Err(error) => {
                        self.error = Some(format!(
                            "The saved Run registration could not be prepared for restoration: {error}"
                        ));
                    }
                }
            }
            StartupEvent::Removed(result) => {
                self.worker = None;
                self.startup_ui.removal_review = None;
                self.startup_ui.loaded = false;
                match result {
                    Ok(receipt) => match receipt.outcome {
                        RemovalOutcome::Removed => {
                            self.error = None;
                            self.set_notice(
                                "The exact current-user Run value was removed transactionally and verified. A restore receipt was saved.".into(),
                            );
                        }
                        RemovalOutcome::NoChange => {
                            self.error = Some(
                                "No startup value was removed. The reviewed state changed or Windows rejected the transactional operation; review the saved history before trying again.".into(),
                            );
                        }
                        RemovalOutcome::Uncertain => {
                            self.error = Some(
                                "The removal outcome is uncertain. Review the saved operation and current registry state before taking another action.".into(),
                            );
                        }
                    },
                    Err(error) => self.error = Some(error),
                }
            }
            StartupEvent::RemovalRestored(result) => {
                self.worker = None;
                self.startup_ui.removal_review = None;
                self.startup_ui.loaded = false;
                match result {
                    Ok(receipt) => match receipt.outcome {
                        RemovalRestoreOutcome::Restored => {
                            self.error = None;
                            self.set_notice(
                                "The exact saved Run value and marker bytes were restored transactionally and verified.".into(),
                            );
                        }
                        RemovalRestoreOutcome::AlreadyRestored => {
                            self.error = None;
                            self.set_notice(
                                "The original Run registration was already present. No registry write was made.".into(),
                            );
                        }
                        RemovalRestoreOutcome::NoChange => {
                            self.error = Some(
                                "No registry value was restored. Review the current state and saved history before trying again.".into(),
                            );
                        }
                        RemovalRestoreOutcome::Uncertain => {
                            self.error = Some(
                                "The restore outcome is uncertain. Review the current registry state and saved operation before taking another action.".into(),
                            );
                        }
                    },
                    Err(error) => self.error = Some(error),
                }
            }
        }
    }

    pub(super) fn startup_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if !self.qa_fixture_mode() && !self.startup_ui.loaded && !self.busy() {
            self.begin_startup_load(ctx);
        }

        self.startup_tabs(ui);
        ui.add_space(8.);

        let inventory = self
            .startup_ui
            .inventories
            .get(&self.startup_ui.section)
            .cloned();

        if let Some(inventory) = inventory {
            if inventory.quality != InventoryQuality::Complete {
                self.inventory_summary(ui, t, &inventory);
                ui.add_space(6.);
            }
            self.inventory_table(ui, t, &inventory, ctx);
            ui.add_space(8.);
            self.sources_panel(ui, t, &inventory);
        } else if self.busy() {
            theme::card(t).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Reading native startup sources…");
                });
            });
        } else {
            theme::card(t).show(ui, |ui| {
                ui.label("No inventory result is available yet.");
            });
        }

        ui.add_space(8.);
        self.history_panel(ui, t);
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_startup_sort_state(&self) -> serde_json::Value {
        serde_json::json!({"column":match self.startup_ui.sort {SortColumn::Program => "Program", SortColumn::Publisher => "Publisher", SortColumn::FilePath => "File path", SortColumn::Enabled => state_header_label(self.startup_ui.section)},"descending":self.startup_ui.descending})
    }

    #[cfg(debug_assertions)]
    pub(crate) fn qa_startup_state(&self) -> serde_json::Value {
        let inventory = self.startup_ui.inventories.get(&self.startup_ui.section);
        let selected = self.selected_entry();
        let review_kind = match &self.startup_ui.review {
            Some(ReviewAction::Apply(_)) => Some("change"),
            Some(ReviewAction::Restore(_)) => Some("restore"),
            Some(ReviewAction::RecoverIntent(_) | ReviewAction::RecoverReceipt(_)) => {
                Some("recovery")
            }
            None => None,
        };
        let removal_review_kind = match &self.startup_ui.removal_review {
            Some(RemovalReview::Remove(_)) => Some("remove"),
            Some(RemovalReview::Restore(_)) => Some("restore"),
            None => None,
        };
        let enabled = selected.map(|entry| match &entry.enabled {
            EnabledState::Enabled => "enabled",
            EnabledState::Disabled => "disabled",
            EnabledState::Unknown { .. } => "unknown",
        });

        serde_json::json!({
            "section": self.startup_ui.section.label(),
            "loaded": self.startup_ui.loaded,
            "quality": inventory.map(|inventory| match inventory.quality {
                InventoryQuality::Complete => "complete",
                InventoryQuality::Partial => "partial",
                InventoryQuality::Unavailable => "unavailable",
            }),
            "entry_count": inventory.map_or(0, |inventory| inventory.entries.len()),
            "selected": selected.is_some(),
            "selected_enabled": enabled,
            "selected_can_toggle": selected.is_some_and(|entry| {
                entry.can_change_enabled && known_enabled_value(&entry.enabled).is_some()
            }),
            "selected_remove_supported": selected.is_some_and(|entry| {
                dcleaner::startup_removal::supports_run_value_removal(&entry.identity)
            }),
            "details_open": self.startup_ui.details_open,
            "more_open": self.startup_ui.qa_more_open,
            "review_kind": review_kind,
            "removal_review_kind": removal_review_kind,
            "worker_active": self.worker.is_some() || self.startup_ui.background_read.is_some(),
            "busy": self.busy(),
            "error_present": self.error.is_some(),
            "notice_present": self.notice.is_some(),
            "synthetic_notice": self.notice.as_deref().is_some_and(|notice| notice.starts_with("Synthetic ")),
            "history_count": self.startup_ui.history_view.rows.len(),
            "selected_history": self.startup_ui.selected_history,
        })
    }

    #[cfg(debug_assertions)]
    pub(crate) fn qa_startup_action_precondition(&self, label: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Startup UI action checks require isolated fixture mode.".into());
        }
        let entries = self
            .startup_ui
            .inventories
            .get(&self.startup_ui.section)
            .map(|inventory| inventory.entries.as_slice())
            .unwrap_or_default();
        let valid = match label {
            "Review recovery" | "Review restore" => {
                !self.busy()
                    && self.startup_ui.review.is_none()
                    && self.startup_ui.removal_review.is_none()
                    && self.startup_ui.history_view.rows.iter().any(|row| {
                        Some(row.id) == self.startup_ui.selected_history
                            && (row.action.is_some() || row.removal.is_some())
                            && (row.state == "uncertain") == (label == "Review recovery")
                    })
            }
            "Select startup history record" => !self.startup_ui.history_view.rows.is_empty(),
            "Windows services" => {
                self.startup_ui.loaded
                    && !self.busy()
                    && self
                        .startup_ui
                        .inventories
                        .contains_key(&StartupSection::WindowsServices)
            }
            "Enable startup item" => entries.iter().any(|entry| {
                entry.can_change_enabled
                    && matches!(&entry.enabled, EnabledState::Disabled)
                    && !self.busy()
            }),
            "Disable startup item" => entries.iter().any(|entry| {
                entry.can_change_enabled
                    && matches!(&entry.enabled, EnabledState::Enabled)
                    && !self.busy()
            }),
            "More" => !entries.is_empty() && !self.startup_ui.qa_more_open && !self.busy(),
            "Close" => self.startup_ui.details_open,
            "Show details" => self.startup_ui.qa_more_open && !entries.is_empty() && !self.busy(),
            "Remove" => {
                self.startup_ui.qa_more_open
                    && !self.busy()
                    && entries.iter().any(|entry| {
                        dcleaner::startup_removal::supports_run_value_removal(&entry.identity)
                    })
            }
            "Cancel" => {
                self.startup_ui.review.is_some() || self.startup_ui.removal_review.is_some()
            }
            "Confirm fixture review" => {
                self.qa_fixture_mode()
                    && (self.startup_ui.review.is_some()
                        || self.startup_ui.removal_review.is_some())
                    && !self.busy()
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(format!(
                "Startup action precondition is not satisfied: {label}"
            ))
        }
    }

    #[cfg(debug_assertions)]
    pub(crate) fn qa_startup_action_state(&self, label: &str) -> Result<serde_json::Value, String> {
        let state = self.qa_startup_state();
        let valid = match label {
            "Review recovery" => {
                state["review_kind"] == "recovery" || state["removal_review_kind"] == "restore"
            }
            "Review restore" => {
                state["review_kind"] == "restore" || state["removal_review_kind"] == "restore"
            }
            "Select startup history record" => self
                .startup_ui
                .history_view
                .rows
                .iter()
                .any(|row| Some(row.id) == self.startup_ui.selected_history),
            "Windows services" => {
                state["section"] == "Windows services"
                    && state["selected"] == false
                    && state["worker_active"] == false
            }
            "Enable startup item" | "Disable startup item" => state["review_kind"] == "change",
            "More" => state["more_open"] == true,
            "Show details" => state["details_open"] == true,
            "Close" => state["details_open"] == false,
            "Remove" => state["removal_review_kind"] == "remove",
            "Cancel" => state["review_kind"].is_null() && state["removal_review_kind"].is_null(),
            "Confirm fixture review" => {
                state["review_kind"].is_null()
                    && state["removal_review_kind"].is_null()
                    && state["synthetic_notice"] == true
                    && state["worker_active"] == false
            }
            _ => false,
        };
        if valid {
            Ok(state)
        } else {
            Err(format!(
                "Startup action did not reach its expected state: {label}"
            ))
        }
    }

    pub(super) fn startup_refresh_external_state(&mut self, ctx: &egui::Context) {
        if self.qa_fixture_mode() {
            return;
        }
        if let Some(receiver) = self.startup_ui.background_read.take() {
            match receiver.try_recv() {
                Ok(inventory) => {
                    self.startup_ui
                        .inventories
                        .insert(inventory.section, Arc::new(inventory));
                    self.startup_ui.last_refresh = Some(std::time::Instant::now());
                }
                Err(mpsc::TryRecvError::Empty) => self.startup_ui.background_read = Some(receiver),
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.error = Some("Startup refresh stopped before returning a result. The previous inventory is still shown.".into());
                }
            }
        }
        let focused = ctx.input(|input| input.viewport().focused.unwrap_or(false));
        let returned = focused && !self.startup_ui.was_focused;
        self.startup_ui.was_focused = focused;
        let stale = self
            .startup_ui
            .last_refresh
            .is_some_and(|time| time.elapsed() >= Duration::from_secs(10));
        if self.page == Page::Startup
            && focused
            && self.startup_ui.loaded
            && self.startup_ui.background_read.is_none()
            && !self.busy()
            && self.startup_ui.review.is_none()
            && !self.startup_ui.details_open
            && (returned || stale)
        {
            let section = self.startup_ui.section;
            let (sender, receiver) = mpsc::channel();
            self.startup_ui.background_read = Some(receiver);
            let context = ctx.clone();
            thread::spawn(move || {
                let inventory = WindowsStartupPlatform::new().inventory(section);
                let _ = sender.send(inventory);
                context.request_repaint();
            });
        }
        if self.page == Page::Startup && focused {
            ctx.request_repaint_after(Duration::from_secs(2));
        }
    }

    pub(super) fn startup_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let busy = self.busy();
        let history = self.startup_ui.history_view.clone();
        let selected_history = self
            .startup_ui
            .selected_history
            .and_then(|id| history.rows.iter().find(|record| record.id == id));
        let history_action = selected_history
            .as_ref()
            .and_then(|record| record.action.as_ref());
        let removal_history_source = selected_history
            .as_ref()
            .and_then(|record| record.removal.as_ref());
        let section = self.startup_ui.section;
        let mut inventory_summary = self
            .startup_ui
            .inventories
            .get(&section)
            .map(|inventory| {
                format!(
                    "{} · {} · {:?}",
                    section.label(),
                    theme::counted_label(inventory.entries.len(), "entry", "entries"),
                    inventory.quality
                )
            })
            .unwrap_or_else(|| format!("{} · not loaded", section.label()));
        let reading_state = self.startup_ui.background_read.is_some()
            || self.progress.starts_with("Reading native startup")
            || self
                .progress
                .starts_with("Re-reading the selected native item")
            || self.progress.starts_with("Re-reading the exact Run value")
            || self
                .progress
                .starts_with("Re-reading the selected Run slots");
        let changing_state = self.busy() && self.startup_ui.loaded && !reading_state;
        if let Some(freshness) = startup_freshness_label(
            reading_state,
            changing_state,
            self.startup_ui.last_refresh.map(|time| time.elapsed()),
        ) {
            inventory_summary.push_str(" · ");
            inventory_summary.push_str(freshness);
        }
        let mut should_refresh = false;
        let mut should_export = false;
        let mut open_history_review = false;

        ui.horizontal_wrapped(|ui| {
            theme::muted(ui, inventory_summary, t);
            ui.separator();
            if theme::secondary(ui, "Refresh", !busy && !self.qa_fixture_mode()) {
                should_refresh = true;
            }
            if theme::secondary(
                ui,
                "Export JSON",
                !busy && self.startup_ui.loaded && !self.qa_fixture_mode(),
            ) {
                should_export = true;
            }
            if (history_action.is_some() || removal_history_source.is_some())
                && theme::secondary(
                    ui,
                    if selected_history
                        .as_ref()
                        .is_some_and(|item| item.state == "uncertain")
                    {
                        "Review recovery"
                    } else {
                        "Review restore"
                    },
                    !busy,
                )
            {
                open_history_review = true;
            }
        });

        if should_refresh {
            self.startup_ui.loaded = false;
            self.begin_startup_load(ctx);
        }
        if should_export {
            self.export_startup_inventory();
        }
        if open_history_review {
            if let Some(action) = history_action {
                self.startup_ui.review = Some(action.clone());
            } else if let Some(source) = removal_history_source {
                self.begin_startup_removal_restore_review(source.clone(), ctx);
            }
        }
    }

    pub(super) fn startup_dialog(&mut self, ctx: &egui::Context) {
        if self.startup_ui.details_open {
            let t = theme::tokens(self.prefs.dark);
            let mut close = false;
            let modal = egui::Modal::new(egui::Id::new("startup-item-details"))
                .frame(theme::dialog_frame(t))
                .show(ctx, |ui| {
                    ui.set_width((ctx.content_rect().width() - 100.).clamp(300., 540.));
                    ui.heading("Startup item details");
                    ui.add_space(12.);
                    theme::scroll_vertical()
                        .max_height((ctx.content_rect().height() - 190.).clamp(140., 520.))
                        .show(ui, |ui| self.entry_details(ui, t));
                    ui.add_space(12.);
                    ui.separator();
                    ui.add_space(8.);
                    theme::centered_dialog_actions(ui, &["Close"], |actions| {
                        close = theme::primary(actions, "Close", t, true);
                    });
                });
            if close || modal.should_close() {
                self.startup_ui.details_open = false;
            }
            return;
        }
        if self.startup_ui.removal_review.is_some() {
            self.startup_removal_dialog(ctx);
            return;
        }
        let Some(action) = self.startup_ui.review.clone() else {
            return;
        };
        let t = theme::tokens(self.prefs.dark);
        let (from, to) = action.snapshots();
        let identity = identity_summary(&from.identity);
        let command = self
            .entry_for_id(action.id())
            .map(|entry| field_text(&entry.command))
            .unwrap_or_else(|| "Not present in the latest inventory".into());
        let mut accept = false;
        let mut cancel = false;

        let modal = egui::Modal::new(egui::Id::new("startup-reviewed-change")).frame(theme::dialog_frame(t)).show(ctx, |ui| {
            ui.set_width(520.);
            let max_detail_height = (ui.ctx().content_rect().height() - 210.).clamp(160., 520.);
            theme::scroll_vertical()
                .max_height(max_detail_height)
                .show(ui, |ui| {
                    ui.heading(if action.is_recovery() {
                        "Review guarded recovery"
                    } else if matches!(action, ReviewAction::Apply(_)) {
                        "Review startup change"
                    } else {
                        "Review restoration"
                    });
                    ui.add_space(8.);
                    theme::muted(ui, "Nothing changes until you confirm here.", t);
                    ui.add_space(10.);
                    review_detail(ui, "Native identity", &identity, t);
                    review_detail(ui, "Command", &command, t);
                    review_detail(
                        ui,
                        "Current reviewed state",
                        &state_summary(from),
                        t,
                    );
                    review_detail(ui, "Requested state", &state_summary(to), t);
                    if self.qa_fixture_mode() {
                        ui.add_space(8.);
                        theme::muted(
                            ui,
                            "Synthetic fixture review only. Confirming closes this review; it does not change a Windows item or write a journal.",
                            t,
                        );
                    } else if action.is_recovery() {
                        ui.add_space(8.);
                        ui.label(
                            RichText::new(
                                "Recovery re-reads the native item and restores only when its identity and saved state match exactly. It will refuse changed or unknown items; no uncertain operation is replayed automatically.",
                            )
                            .color(t.attention),
                        );
                    } else {
                        ui.add_space(8.);
                        theme::muted(
                            ui,
                            "The change is journaled before the Windows API call and verified afterward. You can restore a confirmed change from Startup Manager history.",
                            t,
                        );
                    }
                });
            ui.add_space(12.);
            ui.separator();
            ui.add_space(8.);
            let confirm_label = if self.qa_fixture_mode() {
                "Confirm fixture review"
            } else {
                action.label()
            };
            theme::centered_dialog_actions(ui, &["Cancel", confirm_label], |ui| {
                if theme::secondary(ui, "Cancel", true) {
                    cancel = true;
                }
                if theme::primary(ui, confirm_label, t, !self.busy()) {
                    accept = true;
                }
            });
        });

        if !self.busy() && modal.should_close() {
            self.startup_ui.review = None;
            return;
        }

        if cancel {
            self.startup_ui.review = None;
        } else if accept && !self.busy() {
            self.startup_ui.review = None;
            if self.qa_fixture_mode() {
                self.set_notice(
                    "Synthetic review accepted. No Windows startup setting was changed.".into(),
                );
            } else {
                self.begin_startup_action(action, ctx);
            }
        }
    }

    fn startup_removal_dialog(&mut self, ctx: &egui::Context) {
        let Some(action) = self.startup_ui.removal_review.clone() else {
            return;
        };
        let t = theme::tokens(self.prefs.dark);
        let mut accept = false;
        let mut cancel = false;
        let identity = match &action {
            RemovalReview::Remove(intent) => identity_summary(&intent.identity),
            RemovalReview::Restore(intent) => identity_summary(&intent.identity),
        };
        let reviewed_slots = match &action {
            RemovalReview::Remove(intent) => &intent.before,
            RemovalReview::Restore(intent) => &intent.before,
        };
        let command = registry_command_summary(reviewed_slots);
        let (current_summary, requested_summary, title, confirm_label): (String, String, &str, &str) = match &action {
            RemovalReview::Remove(intent) => (
                removal_slots_summary(&intent.before),
                if intent.before.approval.is_some() {
                    "Remove this exact Run value and its same-name StartupApproved marker.".into()
                } else {
                    "Remove this exact Run value. No StartupApproved marker was present in the reviewed snapshot.".into()
                },
                "Review startup entry removal",
                "Remove this entry",
            ),
            RemovalReview::Restore(intent) => (
                removal_slots_summary(&intent.expected_current),
                "Restore the saved raw Run value and marker bytes only where the exact slots are absent. Existing different bytes will be preserved and cause refusal.".into(),
                "Review startup entry restoration",
                "Restore exact values",
            ),
        };

        let modal = egui::Modal::new(egui::Id::new("startup-reviewed-removal"))
            .frame(theme::dialog_frame(t))
            .show(ctx, |ui| {
                ui.set_width((ctx.content_rect().width() - 100.).clamp(300., 560.));
                let max_body_height = (ctx.content_rect().height() - 210.).clamp(150., 500.);
                theme::scroll_vertical()
                    .max_height(max_body_height)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.heading(title);
                        ui.add_space(8.);
                        theme::muted(ui, "Nothing changes until you confirm here.", t);
                        ui.add_space(10.);
                        review_detail(ui, "Exact registry identity", &identity, t);
                        review_detail(ui, "Command represented by saved Run bytes", &command, t);
                        review_detail(ui, "Current raw slots", &current_summary, t);
                        review_detail(ui, "Requested operation", &requested_summary, t);
                        if self.qa_fixture_mode() {
                            ui.add_space(8.);
                            theme::muted(
                                ui,
                                "Synthetic fixture only. Confirming closes this review; it does not write the operation journal or touch Windows registry state.",
                                t,
                            );
                        } else {
                            ui.add_space(8.);
                            theme::muted(
                                ui,
                                "The intent is saved before a transactional registry operation. A lost commit acknowledgement remains uncertain and is never retried automatically.",
                                t,
                            );
                        }
                    });
                ui.separator();
                ui.add_space(8.);
                let confirm = if self.qa_fixture_mode() {
                    "Confirm fixture review"
                } else {
                    confirm_label
                };
                theme::centered_dialog_actions(ui, &["Cancel", confirm], |ui| {
                    if theme::secondary(ui, "Cancel", true) {
                        cancel = true;
                    }
                    if theme::primary(ui, confirm, t, !self.busy()) {
                        accept = true;
                    }
                });
            });
        if !self.busy() && ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            // Escape is the only keyboard dismissal. Enter never confirms a registry action.
            self.startup_ui.removal_review = None;
            return;
        }
        if !self.busy() && modal.should_close() {
            self.startup_ui.removal_review = None;
            return;
        }
        if cancel {
            self.startup_ui.removal_review = None;
        } else if accept && !self.busy() {
            self.startup_ui.removal_review = None;
            if self.qa_fixture_mode() {
                self.set_notice(
                    "Synthetic removal review accepted. No registry state or journal was changed."
                        .into(),
                );
            } else {
                self.begin_startup_removal_action(action, ctx);
            }
        }
    }

    fn begin_startup_load(&mut self, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        self.startup_ui.background_read = None;
        self.progress = "Reading native startup inventories and operation history…".into();
        self.cancel = Arc::new(AtomicBool::new(false));
        let root = self.data_dir.clone();
        let cancel = self.cancel.clone();
        let ctx = ctx.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let mut platform = WindowsStartupPlatform::new();
            let inventories = StartupSection::ALL
                .into_iter()
                .map(|section| platform.inventory(section))
                .collect();
            let history = effects::history(&root, "startup")
                .and_then(|records| PreparedHistory::prepare(records, &cancel));
            let _ = tx.send(Event::Startup(StartupEvent::Loaded {
                inventories,
                history,
            }));
            ctx.request_repaint();
        });
    }

    fn begin_startup_prepare(&mut self, id: StartupId, target_enabled: bool, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        if self.qa_fixture_mode() {
            self.error = None;
            self.startup_ui.review = None;
            self.startup_ui.selected = Some(id.clone());
            #[cfg(debug_assertions)]
            {
                if let Some(intent) = self
                    .entry_for_id(&id)
                    .and_then(|entry| startup_qa_intent(entry, target_enabled))
                {
                    self.startup_ui.review = Some(ReviewAction::Apply(intent));
                } else {
                    self.error = Some(
                        "The synthetic startup row does not have a known changeable state.".into(),
                    );
                }
            }
            return;
        }
        self.startup_ui.background_read = None;
        self.error = None;
        self.startup_ui.review = None;
        self.startup_ui.selected = Some(id.clone());
        self.progress = "Re-reading the selected native item for review…".into();
        self.cancel = Arc::new(AtomicBool::new(false));
        let ctx = ctx.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let mut manager = StartupManager::new(WindowsStartupPlatform::new());
            let result = manager
                .prepare_change(&id, target_enabled)
                .map_err(|error| error.message);
            let _ = tx.send(Event::Startup(StartupEvent::Prepared {
                id,
                target_enabled,
                result,
            }));
            ctx.request_repaint();
        });
    }

    fn begin_startup_removal_prepare(&mut self, id: StartupId, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        if self.qa_fixture_mode() {
            #[cfg(debug_assertions)]
            {
                let intent = self.entry_for_id(&id).and_then(startup_qa_removal_intent);
                if let Some(intent) = intent {
                    self.startup_ui.removal_review = Some(RemovalReview::Remove(intent));
                    self.error = None;
                } else {
                    self.error = Some(
                        "This synthetic row does not represent a supported Run-value registration."
                            .into(),
                    );
                }
            }
            return;
        }
        self.error = None;
        self.startup_ui.removal_review = None;
        self.startup_ui.selected = Some(id.clone());
        self.progress = "Re-reading the exact Run value and marker for removal review…".into();
        self.cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        let context = ctx.clone();
        thread::spawn(move || {
            let mut manager = RunValueRemovalManager::new(WindowsRunValueRemovalPlatform::new());
            let result = manager.prepare_removal(&id).map_err(|error| error.message);
            let _ = tx.send(Event::Startup(StartupEvent::RemovalPrepared { id, result }));
            context.request_repaint();
        });
    }

    fn begin_startup_removal_restore_review(
        &mut self,
        source: RemovalHistorySource,
        ctx: &egui::Context,
    ) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        let source_operation_id = match &source {
            RemovalHistorySource::Intent(intent) => intent.operation_id,
            RemovalHistorySource::Receipt(receipt) => receipt.operation_id,
        };
        self.error = None;
        self.startup_ui.removal_review = None;
        self.progress = "Re-reading the selected Run slots for a guarded restore review…".into();
        self.cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        let context = ctx.clone();
        thread::spawn(move || {
            let mut manager = RunValueRemovalManager::new(WindowsRunValueRemovalPlatform::new());
            let result = match source {
                RemovalHistorySource::Intent(intent) => {
                    manager.prepare_restore_from_intent(&intent)
                }
                RemovalHistorySource::Receipt(receipt) => {
                    manager.prepare_restore_from_receipt(&receipt)
                }
            }
            .map_err(|error| error.message);
            let _ = tx.send(Event::Startup(StartupEvent::RemovalRestorePrepared {
                source_operation_id,
                result,
            }));
            context.request_repaint();
        });
    }

    fn begin_startup_removal_action(&mut self, action: RemovalReview, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        self.error = None;
        self.progress = match &action {
            RemovalReview::Remove(_) => {
                "Saving the startup removal intent before the transactional registry call…".into()
            }
            RemovalReview::Restore(_) => {
                "Saving the startup restore intent before the transactional registry call…".into()
            }
        };
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let root = self.data_dir.clone();
        let context = ctx.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            match action {
                RemovalReview::Remove(intent) => {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        apply_startup_removal(&root, &intent, &cancel)
                    }))
                    .unwrap_or_else(|_| {
                        Err("The removal worker stopped unexpectedly. Its saved intent remains for manual review; no automatic retry was made.".into())
                    });
                    let _ = tx.send(Event::Startup(StartupEvent::Removed(result)));
                }
                RemovalReview::Restore(intent) => {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        restore_startup_removal(&root, &intent, &cancel)
                    }))
                    .unwrap_or_else(|_| {
                        Err("The restore worker stopped unexpectedly. Review its saved intent and current registry state before another action.".into())
                    });
                    let _ = tx.send(Event::Startup(StartupEvent::RemovalRestored(result)));
                }
            }
            context.request_repaint();
        });
    }

    fn begin_startup_action(&mut self, action: ReviewAction, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        self.error = None;
        self.progress = match &action {
            ReviewAction::Apply(_) => "Saving the startup intent before the Windows change…".into(),
            ReviewAction::Restore(_)
            | ReviewAction::RecoverIntent(_)
            | ReviewAction::RecoverReceipt(_) => {
                "Saving the restore intent before the Windows change…".into()
            }
        };
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let root = self.data_dir.clone();
        let ctx = ctx.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let result = match action {
                ReviewAction::Apply(intent) => apply_startup_change(&root, &intent, &cancel),
                ReviewAction::Restore(receipt) | ReviewAction::RecoverReceipt(receipt) => {
                    restore_startup_receipt(&root, &receipt, &cancel)
                }
                ReviewAction::RecoverIntent(intent) => {
                    restore_startup_intent(&root, &intent, &cancel)
                }
            };
            let _ = tx.send(Event::Startup(StartupEvent::Changed(result)));
            ctx.request_repaint();
        });
    }

    fn startup_tabs(&mut self, ui: &mut egui::Ui) {
        theme::tabs(ui, |ui| {
            for section in StartupSection::ALL {
                let inventory = self.startup_ui.inventories.get(&section);
                let response = theme::tab_with_icon_count(
                    ui,
                    self.startup_ui.section == section,
                    startup_section_icon(section),
                    section.label(),
                    startup_cached_tab_count(inventory.map(Arc::as_ref)),
                    theme::tokens(self.prefs.dark),
                );
                let description = startup_section_description(section);
                let tooltip = match inventory.map(|inventory| &inventory.quality) {
                    Some(InventoryQuality::Partial) => format!(
                        "{description}\n\nThe count is omitted because some startup sources could not be read."
                    ),
                    Some(InventoryQuality::Unavailable) => format!(
                        "{description}\n\nThe count is unavailable because Windows did not return a complete inventory."
                    ),
                    Some(InventoryQuality::Complete) | None => description.to_owned(),
                };
                let response = response.on_hover_text(tooltip);
                theme::focus_ring(ui, &response, 18);
                if response.clicked() {
                    self.startup_ui.section = section;
                    self.startup_ui.selected = None;
                    #[cfg(debug_assertions)]
                    {
                        self.startup_ui.qa_more_open = false;
                    }
                }
            }
        });
    }

    fn inventory_summary(&self, ui: &mut egui::Ui, t: Tokens, inventory: &StartupInventory) {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!("{:?}", inventory.quality))
                    .family(theme::semibold())
                    .color(match &inventory.quality {
                        InventoryQuality::Complete => t.primary,
                        InventoryQuality::Partial => t.attention,
                        InventoryQuality::Unavailable => t.attention,
                    }),
            );
            ui.separator();
            ui.label(format!("{} visible entries", inventory.entries.len()));
            ui.separator();
            ui.label(format!("{} native sources", inventory.sources.len()));
            theme::muted(
                ui,
                match &inventory.quality {
                    InventoryQuality::Complete => "Readable sources only",
                    InventoryQuality::Partial => {
                        "Some sources failed, are inaccessible, or were truncated"
                    }
                    InventoryQuality::Unavailable => {
                        "No usable inventory; an empty list does not prove absence"
                    }
                },
                t,
            );
        });
    }

    fn sources_panel(&self, ui: &mut egui::Ui, t: Tokens, inventory: &StartupInventory) {
        theme::Disclosure::new("Inventory sources and access")
            .id_salt(("startup-sources", inventory.section.label()))
            .default_open(inventory.quality != InventoryQuality::Complete)
            .show(ui, |ui| {
                for source in &inventory.sources {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(source_state_label(&source.state))
                                .family(theme::semibold()),
                        );
                        theme::muted(ui, &source.source, t);
                    });
                    if let Some(reason) = source_state_reason(&source.state) {
                        theme::muted(ui, reason, t);
                    }
                    ui.separator();
                }
            });
    }

    fn inventory_table(
        &mut self,
        ui: &mut egui::Ui,
        t: Tokens,
        inventory: &StartupInventory,
        ctx: &egui::Context,
    ) {
        let query = self.startup_ui.query.trim().to_lowercase();
        let mut entries = inventory
            .entries
            .iter()
            .filter(|entry| {
                query.is_empty() || searchable_entry_text(entry).to_lowercase().contains(&query)
            })
            .collect::<Vec<_>>();
        let sort = self.startup_ui.sort;
        sort_startup_entries(&mut entries, sort, self.startup_ui.descending);

        if entries.is_empty() {
            theme::card(t).show(ui, |ui| {
                let text = if inventory.entries.is_empty() {
                    "No entries were returned by the readable sources. Check the source panel for inaccessible or absent sources."
                } else {
                    "No entries match this search."
                };
                theme::muted(ui, text, t);
            });
            return;
        }

        let mut prepare_change = None;
        let mut open_location = None;
        let mut detail_selection = None;
        let mut save_text = false;
        let mut removal_selection = None;
        let busy = self.busy();
        let checking_state = self.startup_ui.background_read.is_some();
        egui::Frame::NONE.show(ui, |ui| {
            ui.set_width(ui.available_width());
            let available = ui.available_width().max(320.);
            let wide = available >= 900.;
            let action_width = 34.;
            let state_text_width = ["Enabled", "Disabled", "Unknown"].into_iter()
                .map(|text| ui.painter().layout_no_wrap(text.into(), egui::FontId::proportional(theme::FONT_BODY), t.foreground).size().x)
                .fold(0., f32::max);
            let state_width = (36. + 4. + state_text_width + 8.).max(if wide { 120. } else { 96. }).ceil();
            let publisher_width = if wide { 180. } else { (available * 0.17).clamp(96., 110.) };
            let path_width = if wide { 260. } else { (available * 0.24).clamp(120., 160.) };
            let columns = 5;
            let column_spacing = ui.spacing().item_spacing.x * (columns - 1) as f32;
            let program_min_width = 180.;
            let program_width = (available
                - action_width
                - state_width
                - publisher_width
                - path_width
                - column_spacing
                - 8.)
                .max(program_min_width);
            let table_min_width = program_width
                + publisher_width
                + path_width
                + state_width
                + action_width
                + column_spacing
                + 8.;
            theme::scroll_horizontal()
                .id_salt(("startup-table-horizontal", inventory.section.label()))
                .auto_shrink([false, true])
                .show(ui, |table_ui| {
                    table_ui.set_min_width(table_min_width);
                    table_ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.;
                        for (column, width, label) in [
                            (SortColumn::Program, program_width, "Program"),
                            (SortColumn::Publisher, publisher_width, "Publisher"),
                            (SortColumn::FilePath, path_width, "File path"),
                            (
                                SortColumn::Enabled,
                                state_width,
                                state_header_label(inventory.section),
                            ),
                        ] {
                            if sortable_header(
                                ui,
                                width,
                                label,
                                self.startup_ui.sort == column,
                                self.startup_ui.descending,
                                t,
                            ) {
                                if self.startup_ui.sort == column {
                                    self.startup_ui.descending = !self.startup_ui.descending;
                                } else {
                                    self.startup_ui.sort = column;
                                    self.startup_ui.descending = false;
                                }
                            }
                        }
                        ui.allocate_space([action_width, 24.].into());
                    });
                    table_ui.separator();
                    let body_height = (table_ui.ctx().content_rect().bottom()
                        - table_ui.cursor().top()
                        - 74.
                        - 28.
                        - 80.)
                        .max(120.);
                    let previous_y_spacing = table_ui.spacing().item_spacing.y;
                    table_ui.spacing_mut().item_spacing.y = 0.;
                    theme::scroll_vertical()
                        .id_salt(("startup-table-body", inventory.section.label()))
                        .max_height(body_height)
                        .auto_shrink([false, true])
                        .show_rows(table_ui, theme::TABLE_ROW_HEIGHT, entries.len(), |ui, range| {
                egui::Grid::new(("startup-inventory-grid", inventory.section.label()))
                .num_columns(columns)
                .striped(false)
                .min_row_height(theme::TABLE_ROW_HEIGHT)
                .spacing([8., 0.])
                .min_col_width(0.)
                .show(ui, |ui| {
                    for entry in &entries[range] {
                        let selected = self.startup_ui.selected.as_ref() == Some(&entry.id);
                        let program = field_text(&entry.program);
                        let response = ui.allocate_ui_with_layout([program_width, 36.].into(), Layout::left_to_right(Align::Center), |ui| {
                            ui.set_min_width(program_width);
                            ui.set_max_width(program_width);
                            ui.spacing_mut().item_spacing.x = 8.;
                            let resource = if self.qa_fixture_mode() {
                                None
                            } else {
                                match &entry.file_path {
                                    FieldValue::Known { value } => Some(value.as_str()),
                                    _ => None,
                                }
                            };
                            self.app_icons.show(ui, resource, 22.);
                            ui.spacing_mut().button_padding = Vec2::ZERO;
                            theme::frameless_button(ui,
                            [(program_width - 30.).max(40.), 36.],
                            egui::Button::new((
                                RichText::new(program.clone())
                                    .family(theme::semibold())
                                    .size(theme::FONT_BODY)
                                    .color(t.foreground),
                                egui::Atom::grow(),
                            ))
                            .selected(selected)
                            .frame_when_inactive(selected)
                            .frame(false)
                            .truncate(),
                        )}).inner;
                        theme::focus_ring(ui, &response, 18);
                        if response.clicked() {
                            self.startup_ui.selected = Some(entry.id.clone());
                        }
                        response.on_hover_text(&program);

                        field_cell(ui, publisher_width, &entry.publisher);
                        field_cell(ui, path_width, &entry.file_path);

                        let state_value = known_enabled_value(&entry.enabled);
                        let state_text = enabled_label(&entry.enabled);
                        let can_toggle =
                            entry.can_change_enabled && state_value.is_some() && !busy && !checking_state;
                        ui.allocate_ui_with_layout([state_width, 36.].into(), Layout::left_to_right(Align::Center), |ui| {
                            ui.set_min_size([state_width, 36.].into());
                            ui.spacing_mut().item_spacing.x = 4.;
                            let switch = startup_enabled_switch(
                                ui,
                                &entry.id,
                                inventory.section,
                                state_value,
                                can_toggle,
                                t,
                            );
                            if let Some(current) = state_value {
                                if switch.clicked() {
                                    prepare_change = Some((entry.id.clone(), !current));
                                }
                            }
                            let reason = entry
                                .change_limitation
                                .as_deref()
                                .or_else(|| match &entry.enabled {
                                    EnabledState::Unknown { reason } => Some(reason.as_str()),
                                    _ => None,
                                });
                            let state_label = ui.add_sized(
                                [ui.available_width(), 36.],
                                egui::Label::new(RichText::new(state_text).size(theme::FONT_BODY)).truncate(),
                            );
                            if let Some(reason) = reason {
                                state_label.on_hover_text(reason);
                            }
                        });
                        ui.allocate_ui_with_layout([action_width, 36.].into(), Layout::left_to_right(Align::Center), |ui| {
                            ui.set_min_size([action_width, 36.].into());
                            ui.spacing_mut().item_spacing.x = 0.;
                            let more = theme::row_more(ui, !busy);
                            #[cfg(debug_assertions)]
                            {
                                theme::record_fixture_control(ui, "More", &more);
                                if more.clicked() {
                                    self.startup_ui.qa_more_open = !self.startup_ui.qa_more_open;
                                }
                            }
                            egui::Popup::menu(&more).show(|ui| {
                                let details = theme::menu_action(
                                    ui,
                                    theme::Icon::Info,
                                    "Show details",
                                    true,
                                );
                                if details.clicked() {
                                    detail_selection = Some(entry.id.clone());
                                    #[cfg(debug_assertions)]
                                    {
                                        self.startup_ui.qa_more_open = false;
                                    }
                                    ui.close();
                                }
                                let remove_supported =
                                    dcleaner::startup_removal::supports_run_value_removal(
                                        &entry.identity,
                                    );
                                let remove = theme::menu_action(
                                    ui,
                                    theme::Icon::Trash,
                                    "Remove",
                                    remove_supported && !busy && !checking_state,
                                );
                                if remove_supported {
                                    if remove
                                        .on_hover_text(
                                            "Remove this exact current-user Run registration after reviewing its raw values. The operation is journaled and transactional; other startup sources remain read-only.",
                                        )
                                        .clicked()
                                    {
                                        removal_selection = Some(entry.id.clone());
                                        #[cfg(debug_assertions)]
                                        {
                                            self.startup_ui.qa_more_open = false;
                                        }
                                        ui.close();
                                    }
                                } else {
                                    remove.on_hover_text(
                                        "Removal is supported only for exact current-user Run values with a known 32-bit or 64-bit registry view.",
                                    );
                                }
                                let save_to_text = theme::menu_action(
                                    ui,
                                    theme::Icon::Export,
                                    "Save to text file",
                                    !busy
                                        && !checking_state
                                        && inventory.quality != InventoryQuality::Unavailable,
                                );
                                if save_to_text.clicked() {
                                    save_text = true;
                                    ui.close();
                                }
                                theme::menu_action(
                                    ui,
                                    theme::Icon::Registry,
                                    "Open in RegEdit",
                                    false,
                                )
                                .on_hover_text("A safe Registry Editor handoff is not implemented for startup entries.");
                                if let FieldValue::Known { value } = &entry.file_path {
                                    if !value.is_empty()
                                        && theme::menu_action(
                                            ui,
                                            theme::Icon::Folder,
                                            "Open in folder",
                                            !busy && !self.qa_fixture_mode(),
                                        )
                                        .clicked()
                                    {
                                        open_location = Some(value.clone());
                                        ui.close();
                                    }
                                }
                            });
                        });
                        ui.end_row();
                        let y = ui.cursor().min.y;
                        ui.painter().hline(ui.max_rect().left()..=ui.max_rect().right(), y, egui::Stroke::new(1., t.border));
                    }
                });
            });
                    table_ui.spacing_mut().item_spacing.y = previous_y_spacing;
                });
        });
        if save_text {
            self.export_startup_text(inventory);
        }
        if let Some(id) = detail_selection {
            self.startup_ui.selected = Some(id);
            self.startup_ui.details_open = true;
        }
        if let Some(id) = removal_selection {
            self.begin_startup_removal_prepare(id, ctx);
        }
        if let Some(path) = open_location {
            match open_in_explorer(&path) {
                Ok(()) => self.set_notice("The file location was opened in Explorer.".into()),
                Err(error) => {
                    self.error = Some(format!("The file location could not be opened: {error}"))
                }
            }
        }
        if let Some((id, target)) = prepare_change {
            self.begin_startup_prepare(id, target, ctx);
        }
    }

    fn entry_details(&self, ui: &mut egui::Ui, t: Tokens) {
        let Some(entry) = self.selected_entry() else {
            return;
        };
        ui.vertical(|ui| {
            review_detail(ui, "Program", &field_text(&entry.program), t);
            review_detail(ui, "Publisher", &field_text(&entry.publisher), t);
            review_detail(ui, "Version", &field_text(&entry.version), t);
            review_detail(ui, "File path", &field_text(&entry.file_path), t);
            review_detail(ui, "Command", &field_text(&entry.command), t);
            review_detail(ui, "Native identity", &identity_summary(&entry.identity), t);
            review_detail(ui, "Current state", &enabled_label(&entry.enabled), t);
            if let Some(reason) = field_reason(&entry.program)
                .or_else(|| field_reason(&entry.publisher))
                .or_else(|| field_reason(&entry.file_path))
                .or_else(|| field_reason(&entry.command))
            {
                ui.add_space(4.);
                theme::muted(ui, reason, t);
            }
            if let Some(limitation) = &entry.change_limitation {
                ui.add_space(6.);
                theme::muted(ui, limitation, t);
            }
        });
    }

    fn history_panel(&mut self, ui: &mut egui::Ui, t: Tokens) {
        let history_error = self.startup_ui.history_error.clone();
        let history = self.startup_ui.history_view.clone();
        theme::Disclosure::new("Change history and recovery")
            .id_salt("startup-effect-history")
            .default_open(history.has_uncertain)
            .show(ui, |ui| {
                if let Some(error) = history_error {
                    theme::muted(
                        ui,
                        format!("Native operation history is unavailable: {error}"),
                        t,
                    );
                } else if history.rows.is_empty() {
                    theme::muted(ui, "No startup changes have been recorded.", t);
                }
                for record in &history.rows {
                    let action = record.action.as_ref();
                    let removal_action = record.removal.as_ref();
                    let response = theme::stable_selectable(
                            ui,
                            self.startup_ui.selected_history == Some(record.id),
                            egui::RichText::new(&record.label).size(theme::FONT_CAPTION).family(
                                if self.startup_ui.selected_history == Some(record.id) {
                                    theme::semibold()
                                } else {
                                    egui::FontFamily::Proportional
                                }
                            ),
                        )
                        .on_hover_text(if record.state == "uncertain" {
                            "Outcome not confirmed. Review the typed saved intent before attempting guarded recovery."
                        } else {
                            "Select this record to inspect a safe restore or recovery action."
                        });
                    #[cfg(debug_assertions)]
                    theme::record_fixture_control(ui, "Select startup history record", &response);
                    if response.clicked() {
                        self.startup_ui.selected_history = Some(record.id);
                    }
                    if record.state == "uncertain" {
                        theme::muted(
                            ui,
                            if action.is_some() || removal_action.is_some() {
                                "Pending / uncertain. No action was replayed automatically; choose Review recovery in the footer."
                            } else {
                                "Pending / uncertain. The saved payload is not a supported startup intent, so no recovery action is offered."
                            },
                            t,
                        );
                    } else if record.state == "applied"
                        && action.is_none()
                        && removal_action.is_none()
                    {
                        theme::muted(
                            ui,
                            "This change is already restored or has no supported safe receipt.",
                            t,
                        );
                    }
                }
            });
    }

    fn selected_entry(&self) -> Option<&StartupEntry> {
        let id = self.startup_ui.selected.as_ref()?;
        self.startup_ui
            .inventories
            .get(&self.startup_ui.section)?
            .entries
            .iter()
            .find(|entry| &entry.id == id)
    }

    fn entry_for_id(&self, id: &StartupId) -> Option<&StartupEntry> {
        self.startup_ui
            .inventories
            .values()
            .flat_map(|inventory| &inventory.entries)
            .find(|entry| &entry.id == id)
    }

    fn export_startup_inventory(&mut self) {
        if self.qa_fixture_mode() {
            return;
        }
        let mut inventories = StartupSection::ALL
            .into_iter()
            .filter_map(|section| self.startup_ui.inventories.get(&section).map(Arc::as_ref))
            .collect::<Vec<_>>();
        inventories.sort_by_key(|inventory| {
            StartupSection::ALL
                .iter()
                .position(|section| *section == inventory.section)
                .unwrap_or(usize::MAX)
        });
        let Some(path) = rfd::FileDialog::new()
            .set_title("Export Startup Manager inventory")
            .set_file_name("DCleaner Startup Inventory.json")
            .add_filter("JSON", &["json"])
            .save_file()
        else {
            return;
        };
        match serde_json::to_vec_pretty(&inventories)
            .map_err(|error| error.to_string())
            .and_then(|bytes| std::fs::write(path, bytes).map_err(|error| error.to_string()))
        {
            Ok(()) => self.set_notice("Startup inventory exported.".into()),
            Err(error) => {
                self.error = Some(format!("Startup inventory could not be exported: {error}"))
            }
        }
    }

    fn export_startup_text(&mut self, inventory: &StartupInventory) {
        if matches!(&inventory.quality, InventoryQuality::Unavailable) {
            self.error = Some(
                "This tab has no usable inventory to export. Refresh the native sources first."
                    .into(),
            );
            return;
        }
        let contents = inventory
            .entries
            .iter()
            .map(|entry| {
                [
                    startup_export_enabled(&entry.enabled).to_owned(),
                    startup_export_field(&entry.program),
                    startup_export_field(&entry.publisher),
                    startup_export_field(&entry.file_path),
                ]
                .join("\t")
            })
            .collect::<Vec<_>>()
            .join("\r\n");
        if self.qa_fixture_mode() {
            self.set_notice(format!(
                "Synthetic TSV preview prepared ({} bytes); no file was written.",
                contents.len()
            ));
            return;
        }
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save Startup Manager entries")
            .set_file_name("startup.txt")
            .add_filter("Text files", &["txt"])
            .save_file()
        else {
            return;
        };
        match std::fs::write(path, contents) {
            Ok(()) => {
                self.set_notice(if matches!(&inventory.quality, InventoryQuality::Partial) {
                    "Text file saved. It includes only entries from sources Windows allowed DCleaner to read.".into()
                } else {
                    "Startup entries saved to a text file.".into()
                });
            }
            Err(error) => {
                self.error = Some(format!(
                    "The Startup Manager text file could not be saved: {error}"
                ));
            }
        }
    }
}

#[cfg(debug_assertions)]
fn startup_qa_entry(section: StartupSection, enabled: EnabledState) -> StartupEntry {
    let identity = match section {
        StartupSection::StartupApps => EntryIdentity::StartupRunValue {
            hive: dcleaner::startup::RegistryHive::CurrentUser,
            view: RegistryView::process_default(),
            key: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
            value_name: "FixtureExample".into(),
            approval_hive: dcleaner::startup::RegistryHive::CurrentUser,
            approval_key: r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
                .into(),
        },
        StartupSection::ScheduledTasks => EntryIdentity::ScheduledTask {
            path: r"\Fixture\ExampleTask".into(),
        },
        StartupSection::ContextMenu => EntryIdentity::ContextMenuRegistration {
            hive: dcleaner::startup::RegistryHive::CurrentUser,
            key: r"Software\Classes\*\shell\FixtureExample".into(),
            registration: "FixtureVerb".into(),
        },
        StartupSection::WindowsServices => EntryIdentity::WindowsService {
            name: "FixtureService".into(),
        },
    };
    let (program, file_path, command) = match section {
        StartupSection::StartupApps => (
            "Example Startup App",
            FieldValue::Known {
                value: r"C:\Fixture\Example\example.exe".into(),
            },
            FieldValue::Known {
                value: r#""C:\Fixture\Example\example.exe" --start"#.into(),
            },
        ),
        StartupSection::ScheduledTasks => (
            "Example Scheduled Task",
            FieldValue::Known {
                value: r"C:\Fixture\Example\task.exe".into(),
            },
            FieldValue::Known {
                value: r#""C:\Fixture\Example\task.exe" --scheduled"#.into(),
            },
        ),
        StartupSection::ContextMenu => (
            "Example Context Menu Command",
            FieldValue::Known {
                value: r"C:\Fixture\Example\context.exe".into(),
            },
            FieldValue::Known {
                value: r#""C:\Fixture\Example\context.exe" --menu"#.into(),
            },
        ),
        StartupSection::WindowsServices => (
            "Example Windows Service",
            FieldValue::Known {
                value: r"C:\Fixture\Example\service.exe".into(),
            },
            FieldValue::Known {
                value: r#""C:\Fixture\Example\service.exe" --service"#.into(),
            },
        ),
    };
    let can_change_enabled = !matches!(&enabled, EnabledState::Unknown { .. });
    let change_limitation = match &enabled {
        EnabledState::Unknown { reason } => Some(reason.clone()),
        EnabledState::Enabled | EnabledState::Disabled => None,
    };
    StartupEntry {
        id: StartupId::for_identity(&identity),
        section,
        program: FieldValue::Known {
            value: program.into(),
        },
        publisher: FieldValue::Known {
            value: "Example Publisher".into(),
        },
        version: FieldValue::Known {
            value: "1.2.3".into(),
        },
        file_path,
        command,
        enabled,
        identity,
        can_change_enabled,
        change_limitation,
    }
}

#[cfg(debug_assertions)]
fn startup_qa_intent(entry: &StartupEntry, target_enabled: bool) -> Option<ChangeIntent> {
    let current_enabled = known_enabled_value(&entry.enabled)?;
    if !entry.can_change_enabled || current_enabled == target_enabled {
        return None;
    }
    let before = ObservedState {
        id: entry.id.clone(),
        identity: entry.identity.clone(),
        enabled: entry.enabled.clone(),
        native: NativeState::ReadOnly,
    };
    let expected_after = ObservedState {
        id: entry.id.clone(),
        identity: entry.identity.clone(),
        enabled: if target_enabled {
            EnabledState::Enabled
        } else {
            EnabledState::Disabled
        },
        native: NativeState::ReadOnly,
    };
    let intent = ChangeIntent {
        schema_version: CHANGE_SCHEMA_VERSION,
        intent_id: Uuid::new_v4(),
        id: entry.id.clone(),
        target_enabled,
        before,
        expected_after,
    };
    valid_change_intent(&intent).then_some(intent)
}

#[cfg(debug_assertions)]
fn startup_qa_removal_intent(entry: &StartupEntry) -> Option<RemovalIntent> {
    if !dcleaner::startup_removal::supports_run_value_removal(&entry.identity) {
        return None;
    }
    let command = match &entry.command {
        FieldValue::Known { value } => value,
        FieldValue::Unknown { .. } | FieldValue::NotApplicable => return None,
    };
    let data = command
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let before = RunValueSlots {
        run: Some(RegistryValueSnapshot {
            value_type: 1,
            data,
        }),
        approval: None,
    };
    let intent = RemovalIntent {
        schema_version: dcleaner::startup_removal::REMOVAL_SCHEMA_VERSION,
        operation_id: Uuid::new_v4(),
        id: entry.id.clone(),
        identity: entry.identity.clone(),
        before,
    };
    valid_removal_intent(&intent).then_some(intent)
}

fn startup_export_enabled(state: &EnabledState) -> &'static str {
    match state {
        EnabledState::Enabled => "Yes",
        EnabledState::Disabled => "No",
        EnabledState::Unknown { .. } => "Unknown",
    }
}

fn startup_export_field(field: &FieldValue<String>) -> String {
    let value = match field {
        FieldValue::Known { value } => value.as_str(),
        FieldValue::Unknown { .. } => "Unknown",
        FieldValue::NotApplicable => "",
    };
    value
        .replace('\t', " ")
        .replace('\r', " ")
        .replace('\n', " ")
}

fn apply_startup_change(
    root: &Path,
    intent: &ChangeIntent,
    cancel: &AtomicBool,
) -> Result<ChangeReceipt, String> {
    let mut journal =
        EffectJournal::create(root, "startup", intent.intent_id, intent).map_err(|error| {
            format!("The startup intent could not be saved; no change was made: {error}")
        })?;
    if cancel.load(Ordering::Relaxed) {
        journal
            .finish("failed", &serde_json::json!({"outcome":"cancelled_before_native_change"}))
            .map_err(|error| format!("The operation was cancelled before the Windows call, but its journal could not be finalized: {error}"))?;
        return Err(
            "The operation was cancelled before the Windows API call. No native change was made."
                .into(),
        );
    }

    let mut manager = StartupManager::new(WindowsStartupPlatform::new());
    let result = manager.apply_intent(intent);
    match result {
        Ok(receipt) => finish_apply_journal(&mut journal, receipt),
        Err(error) => {
            let current = manager.platform_mut().observe(&intent.id);
            if current
                .as_ref()
                .is_ok_and(|state| state == &intent.expected_after)
            {
                match manager.apply_intent(intent) {
                    Ok(receipt) => finish_apply_journal(&mut journal, receipt),
                    Err(recheck) => Err(format!(
                        "The native change outcome is uncertain ({}; verification retry: {}). The durable intent remains available for guarded recovery.",
                        error.message, recheck.message
                    )),
                }
            } else if current.as_ref().is_ok_and(|state| state == &intent.before) {
                journal
                    .finish("failed", &error)
                    .map_err(|journal_error| format!(
                        "No native change was observed, but the failure receipt could not be saved ({journal_error}); the intent remains pending."
                    ))?;
                Err(format!("No change was made: {}", error.message))
            } else {
                Err(format!(
                    "The startup change outcome is uncertain ({}). The durable intent remains available for guarded recovery; no automatic restore was attempted.",
                    error.message
                ))
            }
        }
    }
}

fn apply_startup_removal(
    root: &Path,
    intent: &RemovalIntent,
    cancel: &AtomicBool,
) -> Result<RemovalReceipt, String> {
    if !valid_removal_intent(intent) {
        return Err(
            "The saved Run-value removal intent is invalid; no registry call was made.".into(),
        );
    }
    let mut journal =
        EffectJournal::create(root, "startup", intent.operation_id, intent).map_err(|error| {
            format!("The startup removal intent could not be saved; no change was made: {error}")
        })?;
    if cancel.load(Ordering::Relaxed) {
        journal
            .finish(
                "failed",
                &serde_json::json!({"outcome":"cancelled_before_native_change"}),
            )
            .map_err(|error| {
                format!("Removal was cancelled before the Windows call, but its journal could not be finalized: {error}")
            })?;
        return Err(
            "Removal was cancelled before the transactional registry call. No change was made."
                .into(),
        );
    }

    let mut manager = RunValueRemovalManager::new(WindowsRunValueRemovalPlatform::new());
    match manager.apply_removal(intent) {
        Err(error) => {
            journal.finish("failed", &error).map_err(|journal_error| {
                format!(
                    "The removal was refused before commit, but its failure receipt could not be saved ({journal_error}); the intent remains pending."
                )
            })?;
            Err(format!("No startup value was removed: {}", error.message))
        }
        Ok(receipt) => {
            if !valid_removal_receipt(&receipt) {
                journal
                    .finish("uncertain", &serde_json::json!({"outcome":"invalid_receipt"}))
                    .map_err(|error| {
                        format!("The removal result was invalid and its uncertainty could not be recorded: {error}")
                    })?;
                return Err(
                    "The removal result could not be validated. Review the pending journal before another action.".into(),
                );
            }
            let state = match receipt.outcome {
                RemovalOutcome::Removed => "applied",
                RemovalOutcome::NoChange => "failed",
                RemovalOutcome::Uncertain => "uncertain",
            };
            journal.finish(state, &receipt).map_err(|error| {
                format!(
                    "The removal outcome is {:?}, but its final receipt could not be saved: {error}. The original intent remains pending for review.",
                    receipt.outcome
                )
            })?;
            Ok(receipt)
        }
    }
}

fn restore_startup_removal(
    root: &Path,
    intent: &RemovalRestoreIntent,
    cancel: &AtomicBool,
) -> Result<RemovalRestoreReceipt, String> {
    if !valid_restore_intent(intent) {
        return Err(
            "The saved Run-value restore intent is invalid; no registry call was made.".into(),
        );
    }
    let mut journal =
        EffectJournal::create(root, "startup", intent.restore_id, intent).map_err(|error| {
            format!("The startup restore intent could not be saved; no change was made: {error}")
        })?;
    if cancel.load(Ordering::Relaxed) {
        journal
            .finish(
                "failed",
                &serde_json::json!({"outcome":"cancelled_before_native_change"}),
            )
            .map_err(|error| {
                format!("Restore was cancelled before the Windows call, but its journal could not be finalized: {error}")
            })?;
        return Err(
            "Restore was cancelled before the transactional registry call. No change was made."
                .into(),
        );
    }

    let mut manager = RunValueRemovalManager::new(WindowsRunValueRemovalPlatform::new());
    match manager.apply_restore(intent) {
        Err(error) => {
            journal.finish("failed", &error).map_err(|journal_error| {
                format!(
                    "Restore was refused before commit, but its failure receipt could not be saved ({journal_error}); the intent remains pending."
                )
            })?;
            Err(format!("No startup value was restored: {}", error.message))
        }
        Ok(receipt) => {
            if !valid_restore_receipt(&receipt) {
                journal
                    .finish("uncertain", &serde_json::json!({"outcome":"invalid_receipt"}))
                    .map_err(|error| {
                        format!("The restore result was invalid and its uncertainty could not be recorded: {error}")
                    })?;
                return Err(
                    "The restore result could not be validated. Review the pending journal before another action.".into(),
                );
            }
            let state = match receipt.outcome {
                RemovalRestoreOutcome::Restored => "restored",
                RemovalRestoreOutcome::AlreadyRestored => "verified",
                RemovalRestoreOutcome::NoChange => "failed",
                RemovalRestoreOutcome::Uncertain => "uncertain",
            };
            journal.finish(state, &receipt).map_err(|error| {
                format!(
                    "The restore outcome is {:?}, but its final receipt could not be saved: {error}. The original intent remains pending for review.",
                    receipt.outcome
                )
            })?;
            Ok(receipt)
        }
    }
}

fn finish_apply_journal(
    journal: &mut EffectJournal,
    receipt: ChangeReceipt,
) -> Result<ChangeReceipt, String> {
    let state = match receipt.outcome {
        ChangeOutcome::Applied => "applied",
        ChangeOutcome::AlreadyApplied => "verified",
        ChangeOutcome::Restored | ChangeOutcome::AlreadyRestored => "verified",
    };
    journal.finish(state, &receipt).map_err(|error| {
        format!(
            "The native state was verified, but its final journal receipt could not be saved: {error}. The saved intent remains available for review."
        )
    })?;
    Ok(receipt)
}

fn restore_startup_receipt(
    root: &Path,
    receipt: &ChangeReceipt,
    cancel: &AtomicBool,
) -> Result<ChangeReceipt, String> {
    let mut journal =
        EffectJournal::create(root, "startup", Uuid::new_v4(), receipt).map_err(|error| {
            format!("The restore intent could not be saved; no change was made: {error}")
        })?;
    if cancel.load(Ordering::Relaxed) {
        journal
            .finish("failed", &serde_json::json!({"outcome":"cancelled_before_native_change"}))
            .map_err(|error| format!("The restore was cancelled before the Windows call, but its journal could not be finalized: {error}"))?;
        return Err(
            "The restore was cancelled before the Windows API call. No native change was made."
                .into(),
        );
    }
    let mut manager = StartupManager::new(WindowsStartupPlatform::new());
    match manager.restore_receipt(receipt) {
        Ok(restored) => finish_restore_journal(&mut journal, restored),
        Err(error) => {
            let current = manager.platform_mut().observe(&receipt.id);
            if current.as_ref().is_ok_and(|state| state == &receipt.after) {
                journal.finish("failed", &error).map_err(|journal_error| {
                    format!("Restore made no verified change, but its failure receipt could not be saved: {journal_error}")
                })?;
                Err(format!(
                    "The original state was not restored: {}",
                    error.message
                ))
            } else {
                Err(format!(
                    "The restore outcome is uncertain ({}). The durable receipt remains available for guarded recovery; no automatic retry was made.",
                    error.message
                ))
            }
        }
    }
}

fn restore_startup_intent(
    root: &Path,
    intent: &ChangeIntent,
    cancel: &AtomicBool,
) -> Result<ChangeReceipt, String> {
    let mut journal =
        EffectJournal::create(root, "startup", Uuid::new_v4(), intent).map_err(|error| {
            format!("The recovery intent could not be saved; no change was made: {error}")
        })?;
    if cancel.load(Ordering::Relaxed) {
        journal
            .finish("failed", &serde_json::json!({"outcome":"cancelled_before_native_change"}))
            .map_err(|error| format!("Recovery was cancelled before the Windows call, but its journal could not be finalized: {error}"))?;
        return Err(
            "Recovery was cancelled before the Windows API call. No native change was made.".into(),
        );
    }
    let mut manager = StartupManager::new(WindowsStartupPlatform::new());
    match manager.restore_intent(intent) {
        Ok(restored) => finish_restore_journal(&mut journal, restored),
        Err(error) => {
            let current = manager.platform_mut().observe(&intent.id);
            if current
                .as_ref()
                .is_ok_and(|state| state == &intent.expected_after)
            {
                journal.finish("failed", &error).map_err(|journal_error| {
                    format!("Recovery made no verified change, but its failure receipt could not be saved: {journal_error}")
                })?;
                Err(format!("Guarded recovery was refused: {}", error.message))
            } else {
                Err(format!(
                    "Guarded recovery outcome is uncertain ({}). The durable intent remains available for review; no automatic retry was made.",
                    error.message
                ))
            }
        }
    }
}

fn finish_restore_journal(
    journal: &mut EffectJournal,
    receipt: ChangeReceipt,
) -> Result<ChangeReceipt, String> {
    let state = match receipt.outcome {
        ChangeOutcome::Restored => "restored",
        ChangeOutcome::AlreadyRestored => "verified",
        ChangeOutcome::Applied | ChangeOutcome::AlreadyApplied => "verified",
    };
    journal.finish(state, &receipt).map_err(|error| {
        format!(
            "The original native state was verified, but its final journal receipt could not be saved: {error}. Review the pending operation before trying again."
        )
    })?;
    Ok(receipt)
}

fn open_in_explorer(path: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        std::process::Command::new("explorer.exe")
            .arg(format!("/select,{path}"))
            .spawn()
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err("Explorer handoff is available only on Windows.".into())
    }
}

fn valid_change_intent(intent: &ChangeIntent) -> bool {
    dcleaner::startup::change_schema_is_supported(intent.schema_version, &intent.before.identity)
        && intent.id == intent.before.id
        && intent.id == intent.expected_after.id
        && intent.before.identity == intent.expected_after.identity
        && StartupId::for_identity(&intent.before.identity) == intent.id
        && match intent.target_enabled {
            true => {
                !matches!(&intent.before.enabled, EnabledState::Enabled)
                    && matches!(&intent.expected_after.enabled, EnabledState::Enabled)
            }
            false => {
                !matches!(&intent.before.enabled, EnabledState::Disabled)
                    && matches!(&intent.expected_after.enabled, EnabledState::Disabled)
            }
        }
}

fn valid_change_receipt(receipt: &ChangeReceipt) -> bool {
    dcleaner::startup::change_schema_is_supported(receipt.schema_version, &receipt.before.identity)
        && receipt.id == receipt.before.id
        && receipt.id == receipt.after.id
        && receipt.before.identity == receipt.after.identity
        && StartupId::for_identity(&receipt.before.identity) == receipt.id
        && match receipt.outcome {
            ChangeOutcome::Applied | ChangeOutcome::AlreadyApplied => {
                matches!(
                    (&receipt.before.enabled, &receipt.after.enabled),
                    (EnabledState::Enabled, EnabledState::Disabled)
                        | (EnabledState::Disabled, EnabledState::Enabled)
                )
            }
            ChangeOutcome::Restored | ChangeOutcome::AlreadyRestored => {
                receipt.before == receipt.after
            }
        }
}

fn history_review_action(
    record: &EffectHistory,
    history: &[EffectHistory],
) -> Option<ReviewAction> {
    match record.state.as_str() {
        "applied" => {
            let receipt: ChangeReceipt = serde_json::from_value(record.receipt.clone()?).ok()?;
            if !valid_change_receipt(&receipt)
                || !matches!(
                    receipt.outcome,
                    ChangeOutcome::Applied | ChangeOutcome::AlreadyApplied
                )
                || history.iter().any(|candidate| {
                    matches!(candidate.state.as_str(), "restored" | "verified")
                        && serde_json::from_value::<ChangeReceipt>(candidate.intent.clone())
                            .is_ok_and(|prior| {
                                valid_change_receipt(&prior) && prior.intent_id == receipt.intent_id
                            })
                        && candidate
                            .receipt
                            .as_ref()
                            .and_then(|value| {
                                serde_json::from_value::<ChangeReceipt>(value.clone()).ok()
                            })
                            .is_some_and(|restore| {
                                valid_change_receipt(&restore)
                                    && matches!(
                                        restore.outcome,
                                        ChangeOutcome::Restored | ChangeOutcome::AlreadyRestored
                                    )
                            })
                })
            {
                return None;
            }
            Some(ReviewAction::Restore(receipt))
        }
        "uncertain" => {
            if let Ok(intent) = serde_json::from_value::<ChangeIntent>(record.intent.clone()) {
                if valid_change_intent(&intent) {
                    return Some(ReviewAction::RecoverIntent(intent));
                }
            }
            let receipt = serde_json::from_value::<ChangeReceipt>(record.intent.clone()).ok()?;
            (valid_change_receipt(&receipt)
                && matches!(
                    receipt.outcome,
                    ChangeOutcome::Applied | ChangeOutcome::AlreadyApplied
                ))
            .then_some(ReviewAction::RecoverReceipt(receipt))
        }
        _ => None,
    }
}

fn history_removal_source(
    record: &EffectHistory,
    history: &[EffectHistory],
) -> Option<RemovalHistorySource> {
    if record.feature != "startup" {
        return None;
    }
    let source = match record.state.as_str() {
        "applied" => {
            let intent = removal_intent_from_history(record)?;
            let receipt = removal_receipt_from_history(record)?;
            if !removal_receipt_matches_intent(&receipt, &intent)
                || receipt.outcome != RemovalOutcome::Removed
            {
                return None;
            }
            RemovalHistorySource::Receipt(receipt)
        }
        "uncertain" => {
            if let Some(intent) = exact_history_payload::<RemovalIntent>(&record.intent) {
                if !valid_removal_intent(&intent) || intent.operation_id != record.id {
                    return None;
                }
                if !uncertain_removal_receipt_matches(record, &intent) {
                    return None;
                }
                RemovalHistorySource::Intent(intent)
            } else {
                let restore = removal_restore_intent_from_history(record)?;
                if !uncertain_restore_receipt_matches(record, &restore)
                    || !removal_source_matches_history(
                        restore.source_operation_id,
                        &restore.id,
                        &restore.identity,
                        &restore.before,
                        history,
                    )
                {
                    return None;
                }
                let intent = RemovalIntent {
                    schema_version: dcleaner::startup_removal::REMOVAL_SCHEMA_VERSION,
                    operation_id: restore.source_operation_id,
                    id: restore.id,
                    identity: restore.identity,
                    before: restore.before,
                };
                if !valid_removal_intent(&intent) {
                    return None;
                }
                RemovalHistorySource::Intent(intent)
            }
        }
        _ => return None,
    };
    let operation_id = match &source {
        RemovalHistorySource::Intent(intent) => intent.operation_id,
        RemovalHistorySource::Receipt(receipt) => receipt.operation_id,
    };
    if removal_has_confirmed_restore(operation_id, history) {
        return None;
    }
    Some(source)
}

fn removal_has_confirmed_restore(operation_id: Uuid, history: &[EffectHistory]) -> bool {
    history.iter().any(|record| {
        if !record.feature.eq("startup")
            || !matches!(record.state.as_str(), "restored" | "verified")
        {
            return false;
        }
        let Some(intent) = removal_restore_intent_from_history(record) else {
            return false;
        };
        let Some(receipt) = removal_restore_receipt_from_history(record) else {
            return false;
        };
        intent.source_operation_id == operation_id
            && restore_receipt_matches_intent(&receipt, &intent)
            && matches!(
                receipt.outcome,
                RemovalRestoreOutcome::Restored | RemovalRestoreOutcome::AlreadyRestored
            )
            && removal_source_matches_history(
                intent.source_operation_id,
                &intent.id,
                &intent.identity,
                &intent.before,
                history,
            )
    })
}

fn exact_history_payload<T>(value: &serde_json::Value) -> Option<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let payload: T = serde_json::from_value(value.clone()).ok()?;
    (serde_json::to_value(&payload).ok()?.eq(value)).then_some(payload)
}

fn removal_intent_from_history(record: &EffectHistory) -> Option<RemovalIntent> {
    let intent = exact_history_payload::<RemovalIntent>(&record.intent)?;
    (record.feature == "startup"
        && intent.operation_id == record.id
        && valid_removal_intent(&intent))
    .then_some(intent)
}

fn removal_receipt_from_history(record: &EffectHistory) -> Option<RemovalReceipt> {
    let receipt = exact_history_payload::<RemovalReceipt>(record.receipt.as_ref()?)?;
    (record.feature == "startup"
        && receipt.operation_id == record.id
        && valid_removal_receipt(&receipt))
    .then_some(receipt)
}

fn removal_receipt_matches_intent(receipt: &RemovalReceipt, intent: &RemovalIntent) -> bool {
    valid_removal_receipt(receipt)
        && valid_removal_intent(intent)
        && receipt.operation_id == intent.operation_id
        && receipt.id == intent.id
        && receipt.identity == intent.identity
        && receipt.before == intent.before
}

fn removal_restore_intent_from_history(record: &EffectHistory) -> Option<RemovalRestoreIntent> {
    let intent = exact_history_payload::<RemovalRestoreIntent>(&record.intent)?;
    (record.feature == "startup" && intent.restore_id == record.id && valid_restore_intent(&intent))
        .then_some(intent)
}

fn removal_restore_receipt_from_history(record: &EffectHistory) -> Option<RemovalRestoreReceipt> {
    let receipt = exact_history_payload::<RemovalRestoreReceipt>(record.receipt.as_ref()?)?;
    (record.feature == "startup"
        && receipt.restore_id == record.id
        && valid_restore_receipt(&receipt))
    .then_some(receipt)
}

fn restore_receipt_matches_intent(
    receipt: &RemovalRestoreReceipt,
    intent: &RemovalRestoreIntent,
) -> bool {
    valid_restore_receipt(receipt)
        && valid_restore_intent(intent)
        && receipt.restore_id == intent.restore_id
        && receipt.source_operation_id == intent.source_operation_id
        && receipt.id == intent.id
        && receipt.identity == intent.identity
        && receipt.before == intent.before
        && receipt.expected_current == intent.expected_current
}

fn uncertain_removal_receipt_matches(record: &EffectHistory, intent: &RemovalIntent) -> bool {
    let Some(value) = record.receipt.as_ref() else {
        return true;
    };
    if value == &serde_json::json!({"outcome":"invalid_receipt"}) {
        return true;
    }
    let Some(receipt) = exact_history_payload::<RemovalReceipt>(value) else {
        return false;
    };
    removal_receipt_matches_intent(&receipt, intent) && receipt.outcome == RemovalOutcome::Uncertain
}

fn uncertain_restore_receipt_matches(
    record: &EffectHistory,
    intent: &RemovalRestoreIntent,
) -> bool {
    let Some(value) = record.receipt.as_ref() else {
        return true;
    };
    if value == &serde_json::json!({"outcome":"invalid_receipt"}) {
        return true;
    }
    let Some(receipt) = exact_history_payload::<RemovalRestoreReceipt>(value) else {
        return false;
    };
    restore_receipt_matches_intent(&receipt, intent)
        && receipt.outcome == RemovalRestoreOutcome::Uncertain
}

fn removal_source_matches_history(
    operation_id: Uuid,
    id: &StartupId,
    identity: &EntryIdentity,
    before: &RunValueSlots,
    history: &[EffectHistory],
) -> bool {
    history.iter().any(|record| {
        if record.id != operation_id || record.feature != "startup" {
            return false;
        }
        match record.state.as_str() {
            "applied" => {
                let Some(intent) = removal_intent_from_history(record) else {
                    return false;
                };
                let Some(receipt) = removal_receipt_from_history(record) else {
                    return false;
                };
                removal_receipt_matches_intent(&receipt, &intent)
                    && receipt.outcome == RemovalOutcome::Removed
                    && intent.id == *id
                    && intent.identity == *identity
                    && intent.before == *before
            }
            "uncertain" => {
                let Some(intent) = removal_intent_from_history(record) else {
                    return false;
                };
                intent.id == *id
                    && intent.identity == *identity
                    && intent.before == *before
                    && uncertain_removal_receipt_matches(record, &intent)
            }
            _ => false,
        }
    })
}

fn history_record_summary(record: &EffectHistory) -> String {
    if let Ok(intent) = serde_json::from_value::<ChangeIntent>(record.intent.clone()) {
        format!(
            "{} · {} to {}",
            identity_summary(&intent.before.identity),
            enabled_label(&intent.before.enabled),
            enabled_label(&intent.expected_after.enabled)
        )
    } else if let Ok(receipt) = serde_json::from_value::<ChangeReceipt>(record.intent.clone()) {
        format!(
            "{} · {} to {}",
            identity_summary(&receipt.before.identity),
            enabled_label(&receipt.before.enabled),
            enabled_label(&receipt.after.enabled)
        )
    } else if let Ok(intent) = serde_json::from_value::<RemovalIntent>(record.intent.clone()) {
        format!(
            "Remove {} · {}",
            identity_summary(&intent.identity),
            removal_slots_summary(&intent.before)
        )
    } else if let Some(receipt) = record
        .receipt
        .as_ref()
        .and_then(|value| serde_json::from_value::<RemovalReceipt>(value.clone()).ok())
    {
        format!(
            "Remove {} · {}",
            identity_summary(&receipt.identity),
            removal_slots_summary(&receipt.before)
        )
    } else if let Ok(intent) = serde_json::from_value::<RemovalRestoreIntent>(record.intent.clone())
    {
        format!(
            "Restore {} · current {}",
            identity_summary(&intent.identity),
            removal_slots_summary(&intent.expected_current)
        )
    } else if let Some(receipt) = record
        .receipt
        .as_ref()
        .and_then(|value| serde_json::from_value::<RemovalRestoreReceipt>(value.clone()).ok())
    {
        let state = receipt
            .after
            .as_ref()
            .map(removal_slots_summary)
            .unwrap_or_else(|| "current slots could not be reread".into());
        format!(
            "Restore {} · {}",
            identity_summary(&receipt.identity),
            state
        )
    } else {
        "Unsupported saved payload · no action available".into()
    }
}

fn removal_slots_summary(slots: &RunValueSlots) -> String {
    let run = registry_snapshot_summary(slots.run.as_ref());
    let approval = registry_snapshot_summary(slots.approval.as_ref());
    format!("Run value: {run}; StartupApproved marker: {approval}")
}

fn registry_command_summary(slots: &RunValueSlots) -> String {
    let Some(value) = &slots.run else {
        return "The Run value is absent.".into();
    };
    if !matches!(value.value_type, 1 | 2) {
        return format!(
            "Not decoded: {} has {} raw bytes.",
            registry_type_label(value.value_type),
            value.data.len()
        );
    }
    if value.data.len() % 2 != 0 {
        return "Not decoded: the registry string has an odd byte length.".into();
    }
    let mut units = value
        .data
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    while units.last() == Some(&0) {
        units.pop();
    }
    let Ok(text) = String::from_utf16(&units) else {
        return "Not decoded: the registry string contains invalid UTF-16.".into();
    };
    let mut safe = String::with_capacity(text.len().min(2048));
    for (index, character) in text.chars().enumerate() {
        if index == 512 {
            safe.push('…');
            break;
        }
        match character {
            '\0' => safe.push_str("\\0"),
            '\r' => safe.push_str("\\r"),
            '\n' => safe.push_str("\\n"),
            '\t' => safe.push_str("\\t"),
            character if character.is_control() => safe.push('�'),
            character => safe.push(character),
        }
    }
    format!("{}: {safe}", registry_type_label(value.value_type))
}

fn registry_snapshot_summary(value: Option<&RegistryValueSnapshot>) -> String {
    value
        .map(|value| {
            format!(
                "{} · {} bytes",
                registry_type_label(value.value_type),
                value.data.len()
            )
        })
        .unwrap_or_else(|| "absent".into())
}

fn registry_type_label(value_type: u32) -> &'static str {
    match value_type {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        _ => "Unknown registry type",
    }
}

fn history_state_label(record: &EffectHistory) -> &'static str {
    match record.state.as_str() {
        "applied"
            if serde_json::from_value::<RemovalIntent>(record.intent.clone()).is_ok()
                || record.receipt.as_ref().is_some_and(|value| {
                    serde_json::from_value::<RemovalReceipt>(value.clone()).is_ok()
                }) =>
        {
            "Removed · verified"
        }
        "applied" => "Applied · verified",
        "removed" => "Removed · verified",
        "restored" => "Restored · verified",
        "verified" => "Verified · no write needed",
        "failed" => "Failed · no change confirmed",
        "uncertain" => "Pending / uncertain",
        _ => "Unrecognized · no action available",
    }
}

fn sort_key(entry: &StartupEntry, sort: SortColumn) -> String {
    match sort {
        SortColumn::Program => field_text(&entry.program),
        SortColumn::Publisher => field_text(&entry.publisher),
        SortColumn::FilePath => field_text(&entry.file_path),
        SortColumn::Enabled => enabled_label(&entry.enabled),
    }
    .to_lowercase()
}

fn sort_startup_entries(entries: &mut [&StartupEntry], sort: SortColumn, descending: bool) {
    if descending {
        entries.sort_by_cached_key(|entry| std::cmp::Reverse(sort_key(entry, sort)));
    } else {
        entries.sort_by_cached_key(|entry| sort_key(entry, sort));
    }
}

fn searchable_entry_text(entry: &StartupEntry) -> String {
    format!(
        "{} {} {} {} {} {}",
        field_text(&entry.program),
        field_text(&entry.publisher),
        field_text(&entry.file_path),
        field_text(&entry.command),
        identity_summary(&entry.identity),
        enabled_label(&entry.enabled)
    )
}

fn field_cell(ui: &mut egui::Ui, width: f32, field: &FieldValue<String>) {
    let tooltip = field_reason(field).or_else(|| match field {
        FieldValue::Known { value } => Some(value.as_str()),
        _ => None,
    });
    if let Some(tooltip) = tooltip {
        theme::table_cell_with_tooltip(ui, field_text(field), width, 36., tooltip);
    } else {
        theme::table_cell(ui, field_text(field), width, 36.);
    }
}

fn sortable_header(
    ui: &mut egui::Ui,
    width: f32,
    label: &str,
    selected: bool,
    descending: bool,
    t: Tokens,
) -> bool {
    let arrow = if selected {
        if descending { "↓" } else { "↑" }
    } else {
        "↕"
    };
    let response = theme::frameless_button(
        ui,
        [width, 24.],
        egui::Button::new((
            RichText::new(label).size(theme::FONT_BODY).color(t.muted),
            egui::Atom::grow(),
            RichText::new(arrow)
                .size(theme::FONT_BODY)
                .color(if selected { t.primary } else { t.muted }),
        ))
        .frame(false),
    );
    #[cfg(debug_assertions)]
    theme::record_fixture_control(ui, &format!("Sort {label}"), &response);
    response.on_hover_text(format!("Sort by {label}")).clicked()
}

fn state_header_label(section: StartupSection) -> &'static str {
    if section == StartupSection::ScheduledTasks {
        "Enable"
    } else {
        "Start up"
    }
}

fn startup_freshness_label(
    checking: bool,
    changing: bool,
    age: Option<Duration>,
) -> Option<&'static str> {
    if checking {
        Some("checking current state")
    } else if changing {
        Some("change in progress; shown state not refreshed")
    } else if age.is_some_and(|age| age >= Duration::from_secs(10)) {
        Some("state may be stale")
    } else {
        None
    }
}

fn startup_enabled_switch(
    ui: &mut egui::Ui,
    id: &StartupId,
    section: StartupSection,
    current: Option<bool>,
    interactive: bool,
    t: Tokens,
) -> egui::Response {
    let response = ui
        .push_id(("startup-state-switch", section, id), |ui| {
            ui.add_enabled_ui(interactive && current.is_some(), |ui| {
                ui.allocate_response(Vec2::new(36., 20.), egui::Sense::click())
            })
            .inner
        })
        .inner;

    let track_rect = egui::Rect::from_center_size(response.rect.center(), Vec2::new(28.8, 17.6));
    let (track, knob_x, label) = match current {
        Some(true) => (t.primary, track_rect.right() - 8.8, "Disable startup item"),
        Some(false) => (t.border, track_rect.left() + 8.8, "Enable startup item"),
        None => (
            t.canvas,
            response.rect.center().x,
            "Startup item state unavailable",
        ),
    };
    let painter = ui.painter();
    painter.rect_filled(track_rect, 8.8, track);
    painter.rect_stroke(
        track_rect,
        8.8,
        egui::Stroke::new(
            1.,
            if current.is_some() {
                t.primary
            } else {
                t.muted
            },
        ),
        egui::StrokeKind::Inside,
    );
    let knob_center = egui::pos2(knob_x, response.rect.center().y);
    painter.circle_filled(
        knob_center,
        6.4,
        if current == Some(true) {
            t.primary_text
        } else {
            t.foreground
        },
    );
    painter.circle_stroke(knob_center, 6.4, egui::Stroke::new(0.8, t.border));
    theme::keyboard_focus_ring(ui, &response, 12);
    response.widget_info(|| {
        egui::WidgetInfo::labeled(
            egui::WidgetType::Checkbox,
            interactive && current.is_some(),
            label,
        )
    });
    #[cfg(debug_assertions)]
    theme::record_fixture_control(ui, label, &response);
    response
}

fn field_text(field: &FieldValue<String>) -> String {
    match field {
        FieldValue::Known { value } if value.is_empty() => "(empty)".into(),
        FieldValue::Known { value } => value.clone(),
        FieldValue::Unknown { .. } => "Unknown".into(),
        FieldValue::NotApplicable => "—".into(),
    }
}

fn field_reason(field: &FieldValue<String>) -> Option<&str> {
    match field {
        FieldValue::Unknown { reason } => Some(reason),
        FieldValue::Known { .. } | FieldValue::NotApplicable => None,
    }
}

fn enabled_label(state: &EnabledState) -> String {
    match state {
        EnabledState::Enabled => "Enabled".into(),
        EnabledState::Disabled => "Disabled".into(),
        EnabledState::Unknown { .. } => "Unknown".into(),
    }
}

fn known_enabled_value(state: &EnabledState) -> Option<bool> {
    match state {
        EnabledState::Enabled => Some(true),
        EnabledState::Disabled => Some(false),
        EnabledState::Unknown { .. } => None,
    }
}

fn identity_summary(identity: &EntryIdentity) -> String {
    match identity {
        EntryIdentity::StartupRunValue {
            hive,
            view,
            key,
            value_name,
            ..
        } => format!(
            "{}[{}]\\{} · {}",
            hive_label(*hive),
            view.tag(),
            key,
            value_name
        ),
        EntryIdentity::StartupFolderItem { path } => path.clone(),
        EntryIdentity::ContextMenuRegistration {
            hive,
            key,
            registration,
        } => format!("{}\\{}\\{}", hive_label(*hive), key, registration),
        EntryIdentity::ScheduledTask { path } => path.clone(),
        EntryIdentity::WindowsService { name } => name.clone(),
    }
}

fn hive_label(hive: dcleaner::startup::RegistryHive) -> &'static str {
    match hive {
        dcleaner::startup::RegistryHive::CurrentUser => "HKCU",
        dcleaner::startup::RegistryHive::LocalMachine => "HKLM",
    }
}

fn source_state_label(state: &SourceState) -> String {
    match state {
        SourceState::Read { items } => format!("Read · {items}"),
        SourceState::NotPresent => "Not present".into(),
        SourceState::Inaccessible { .. } => "Inaccessible".into(),
        SourceState::Failed { .. } => "Failed".into(),
        SourceState::Truncated { .. } => "Truncated".into(),
    }
}

fn source_state_reason(state: &SourceState) -> Option<&str> {
    match state {
        SourceState::Inaccessible { reason } | SourceState::Failed { reason } => Some(reason),
        SourceState::Truncated { reason, .. } => Some(reason),
        SourceState::Read { .. } | SourceState::NotPresent => None,
    }
}

fn state_summary(state: &ObservedState) -> String {
    let enabled = enabled_label(&state.enabled);
    match &state.native {
        NativeState::StartupRunValue { approval, .. } => format!(
            "{enabled}; StartupApproved marker {}",
            if approval.is_some() {
                "present"
            } else {
                "absent"
            }
        ),
        NativeState::ScheduledTask { xml } => format!(
            "{enabled}; task definition {}",
            if xml.is_some() {
                "revalidated"
            } else {
                "unavailable"
            }
        ),
        NativeState::StartupFolderItem { snapshot } => format!(
            "{enabled}; StartupApproved marker {}; file identity revalidated",
            if snapshot.approval.is_some() {
                "present"
            } else {
                "absent"
            }
        ),
        NativeState::ContextMenuVerb { snapshot } => format!(
            "{enabled}; LegacyDisable marker {}; static command revalidated",
            if snapshot.legacy_disable.is_some() {
                "present"
            } else {
                "absent"
            }
        ),
        NativeState::WindowsService { config } => format!(
            "{enabled}; start mode {}",
            service_start_mode(config.start_type)
        ),
        NativeState::ReadOnly => format!("{enabled}; inventory-only"),
    }
}

fn service_start_mode(start_type: u32) -> &'static str {
    match start_type {
        0 => "boot",
        1 => "system",
        2 => "automatic",
        3 => "manual / demand",
        4 => "disabled",
        _ => "unknown",
    }
}

fn review_detail(ui: &mut egui::Ui, label: &str, value: &str, t: Tokens) {
    theme::muted(ui, label, t);
    ui.add(egui::Label::new(RichText::new(value).size(theme::FONT_CAPTION)).wrap());
    ui.add_space(8.);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(debug_assertions)]
    #[test]
    fn expanded_startup_history_frame_cost() {
        let stage = std::env::var("DCLEANER_BENCH_STAGE").unwrap_or_else(|_| "ordinary".into());
        for count in [64usize, 192] {
            let context = egui::Context::default();
            let mut app = App::new_fixture_with_context(&context, "startup-history").unwrap();
            let seed = app.startup_ui.inventories[&StartupSection::StartupApps].entries[0].clone();
            let mut history = Vec::new();
            for index in 0..count {
                let mut intent = startup_qa_intent(&seed, false).unwrap();
                intent.intent_id = Uuid::from_u128(index as u128 + 1);
                let receipt = ChangeReceipt {
                    schema_version: intent.schema_version,
                    intent_id: intent.intent_id,
                    id: intent.id.clone(),
                    before: intent.before.clone(),
                    after: intent.expected_after.clone(),
                    outcome: ChangeOutcome::Applied,
                };
                assert!(valid_change_receipt(&receipt));
                history.push(if index == 0 {
                    EffectHistory {
                        id: intent.intent_id,
                        feature: "startup".into(),
                        date: "2026-10-17T00:00:00Z".into(),
                        intent: serde_json::to_value(&intent).unwrap(),
                        state: "uncertain".into(),
                        receipt: None,
                    }
                } else {
                    EffectHistory {
                        id: intent.intent_id,
                        feature: "startup".into(),
                        date: "2026-10-17T00:00:00Z".into(),
                        intent: serde_json::to_value(&receipt).unwrap(),
                        state: if index % 2 == 0 {
                            "applied"
                        } else {
                            "restored"
                        }
                        .into(),
                        receipt: if index % 2 == 0 {
                            Some(serde_json::to_value(&receipt).unwrap())
                        } else {
                            None
                        },
                    }
                });
            }
            let preparation_started = std::time::Instant::now();
            let history = PreparedHistory::prepare(history, &AtomicBool::new(false)).unwrap();
            let preparation_ms = preparation_started.elapsed().as_secs_f64() * 1000.;
            app.startup_ui.history = history.records;
            app.startup_ui.history_view = history.view;
            app.startup_ui.selected_history = Some(Uuid::from_u128(1));
            let mut samples = Vec::new();
            for tick in 0..8 {
                let started = std::time::Instant::now();
                let mut output = context.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(920., 612.),
                        )),
                        ..Default::default()
                    },
                    |ui| app.paint(ui),
                );
                if tick >= 3 {
                    samples.push(started.elapsed().as_secs_f64() * 1000.);
                }
                assert!(!output.shapes.is_empty());
                output.textures_delta.clear();
            }
            eprintln!(
                "EXPANDED_HISTORY_BENCH {}",
                serde_json::json!({"stage":stage,"records":count,"history_expanded":true,"preparation_ms":preparation_ms,"warm_layout_ms":samples,"synthetic":true,"native_window":false,"physical_input":false})
            );
        }
    }

    fn synthetic_history_record(id: Uuid, text: &str) -> EffectHistory {
        EffectHistory {
            id,
            feature: "startup".into(),
            date: "2026-10-17T00:00:00Z".into(),
            intent: serde_json::json!({"synthetic":true,"text":text}),
            state: "cancelled".into(),
            receipt: None,
        }
    }

    #[test]
    fn prepared_history_preserves_recovery_rules_across_restore_generations() {
        let receipt = ChangeReceipt {
            schema_version: dcleaner::startup::CHANGE_SCHEMA_VERSION,
            intent_id: Uuid::new_v4(),
            id: fake_task_state(true).id.clone(),
            before: fake_task_state(true),
            after: fake_task_state(false),
            outcome: ChangeOutcome::Applied,
        };
        assert!(valid_change_receipt(&receipt));
        let applied = EffectHistory {
            id: receipt.intent_id,
            feature: "startup".into(),
            date: "2026-10-17T00:00:00Z".into(),
            intent: serde_json::to_value(&receipt).unwrap(),
            state: "applied".into(),
            receipt: Some(serde_json::to_value(&receipt).unwrap()),
        };
        let mut uncertain = applied.clone();
        uncertain.id = Uuid::new_v4();
        uncertain.state = "uncertain".into();
        uncertain.receipt = None;
        let mut unsupported = synthetic_history_record(Uuid::new_v4(), "opaque");
        unsupported.state = "uncertain".into();
        let records = vec![applied.clone(), uncertain, unsupported];
        let before = PreparedHistory::prepare(records.clone(), &AtomicBool::new(false)).unwrap();
        assert_eq!(before.records.len(), before.view.rows.len());
        assert!(before.view.has_uncertain);
        assert!(matches!(
            before.view.rows[0].action,
            Some(ReviewAction::Restore(_))
        ));
        assert!(matches!(
            before.view.rows[1].action,
            Some(ReviewAction::RecoverReceipt(_))
        ));
        assert!(before.view.rows[2].action.is_none());
        assert!(before.view.rows.iter().all(|row| row.removal.is_none()));
        for (record, row) in before.records.iter().zip(&before.view.rows) {
            assert_eq!(record.id, row.id);
            assert_eq!(
                row.label,
                format!(
                    "{} · {} · {}",
                    record.date,
                    history_state_label(record),
                    history_record_summary(record)
                )
            );
        }
        let restored_receipt = ChangeReceipt {
            after: receipt.before.clone(),
            outcome: ChangeOutcome::Restored,
            ..receipt
        };
        assert!(valid_change_receipt(&restored_receipt));
        let mut restored = applied;
        restored.id = Uuid::new_v4();
        restored.state = "restored".into();
        restored.receipt = Some(serde_json::to_value(restored_receipt).unwrap());
        let mut records = records;
        records.push(restored);
        let after = PreparedHistory::prepare(records, &AtomicBool::new(false)).unwrap();
        assert!(after.view.rows[0].action.is_none());
        assert!(matches!(
            before.view.rows[0].action,
            Some(ReviewAction::Restore(_))
        ));
        assert!(!Arc::ptr_eq(&before.view, &after.view));
        assert!(
            PreparedHistory::prepare(before.records.as_ref().clone(), &AtomicBool::new(true))
                .is_err()
        );
        assert!(PreparedHistory::prepare(Vec::new(), &AtomicBool::new(true)).is_err());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn startup_history_worker_result_is_published_as_one_generation() {
        let context = egui::Context::default();
        let mut app = App::new_fixture_with_context(&context, "startup-history").unwrap();
        let records = app.startup_ui.history.as_ref().clone();
        let old_view = app.startup_ui.history_view.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let prepared = PreparedHistory::prepare(records, &AtomicBool::new(false)).unwrap();
            ready_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            result_tx.send(prepared).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            result_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        let mut output = context.run_ui(Default::default(), |ui| app.paint(ui));
        assert!(!output.shapes.is_empty());
        output.textures_delta.clear();
        assert!(Arc::ptr_eq(&old_view, &app.startup_ui.history_view));
        release_tx.send(()).unwrap();
        let prepared = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let prepared_view = prepared.view.clone();
        app.startup_event(StartupEvent::Loaded {
            inventories: Vec::new(),
            history: Ok(prepared),
        });
        assert!(Arc::ptr_eq(&prepared_view, &app.startup_ui.history_view));
        assert!(!Arc::ptr_eq(&old_view, &app.startup_ui.history_view));
        assert_eq!(
            app.startup_ui.history[0].id,
            app.startup_ui.history_view.rows[0].id
        );
        assert!(matches!(
            app.startup_ui.history_view.rows[0].action,
            Some(ReviewAction::RecoverIntent(_))
        ));
        worker.join().unwrap();
    }

    #[cfg(debug_assertions)]
    #[test]
    fn startup_loaded_generations_preserve_retained_readers_and_current_selection() {
        let context = egui::Context::default();
        let mut app = App::new_fixture_with_context(&context, "startup-populated").unwrap();
        let mut inventory = app.startup_ui.inventories[&StartupSection::StartupApps]
            .as_ref()
            .clone();
        let entry_id = inventory.entries[0].id.clone();
        let old_program = inventory.entries[0].program.clone();
        let operation = Uuid::new_v4();
        app.startup_event(StartupEvent::Loaded {
            inventories: vec![inventory.clone()],
            history: PreparedHistory::prepare(
                vec![synthetic_history_record(operation, "before")],
                &AtomicBool::new(false),
            ),
        });
        app.startup_ui.selected = Some(entry_id.clone());
        app.startup_ui.selected_history = Some(operation);
        let prior_inventory = app.startup_ui.inventories[&StartupSection::StartupApps].clone();
        let prior_history = app.startup_ui.history.clone();
        let prior_view = app.startup_ui.history_view.clone();
        inventory.entries[0].program = FieldValue::Known {
            value: "Replacement synthetic startup entry".into(),
        };
        app.startup_event(StartupEvent::Loaded {
            inventories: vec![inventory],
            history: PreparedHistory::prepare(
                vec![synthetic_history_record(operation, "after")],
                &AtomicBool::new(false),
            ),
        });
        let current_inventory = app.startup_ui.inventories[&StartupSection::StartupApps].clone();
        let current_history = app.startup_ui.history.clone();
        assert!(!Arc::ptr_eq(&prior_inventory, &current_inventory));
        assert!(!Arc::ptr_eq(&prior_history, &current_history));
        assert!(!Arc::ptr_eq(&prior_view, &app.startup_ui.history_view));
        assert_eq!(prior_view.rows[0].id, prior_history[0].id);
        assert_eq!(
            app.startup_ui.history_view.rows[0].id,
            current_history[0].id
        );
        assert_eq!(prior_inventory.entries[0].program, old_program);
        assert_eq!(prior_history[0].intent["text"], "before");
        assert_eq!(current_history[0].intent["text"], "after");
        assert_eq!(app.startup_ui.selected, Some(entry_id));
        assert_eq!(app.startup_ui.selected_history, Some(operation));
        let mut output = context.run_ui(Default::default(), |ui| app.paint(ui));
        assert!(!output.shapes.is_empty());
        output.textures_delta.clear();
        assert!(Arc::ptr_eq(
            &current_inventory,
            &app.startup_ui.inventories[&StartupSection::StartupApps]
        ));
        assert!(Arc::ptr_eq(&current_history, &app.startup_ui.history));
        assert_eq!(prior_inventory.entries[0].program, old_program);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn startup_failed_history_reload_clears_current_records_without_invalidating_retained_reader() {
        let context = egui::Context::default();
        let mut app = App::new_fixture_with_context(&context, "startup-populated").unwrap();
        let inventory = app.startup_ui.inventories[&StartupSection::StartupApps]
            .as_ref()
            .clone();
        let operation = Uuid::new_v4();
        app.startup_event(StartupEvent::Loaded {
            inventories: vec![inventory.clone()],
            history: PreparedHistory::prepare(
                vec![synthetic_history_record(operation, "retained")],
                &AtomicBool::new(false),
            ),
        });
        let prior = app.startup_ui.history.clone();
        app.startup_ui.selected_history = Some(operation);
        app.startup_event(StartupEvent::Loaded {
            inventories: vec![inventory],
            history: Err("Synthetic unreadable operation history".into()),
        });
        assert!(app.startup_ui.history.is_empty());
        assert!(app.startup_ui.history_view.rows.is_empty());
        assert!(app.startup_ui.selected_history.is_none());
        assert!(!Arc::ptr_eq(&prior, &app.startup_ui.history));
        assert_eq!(prior[0].id, operation);
        assert_eq!(prior[0].intent["text"], "retained");
        assert_eq!(
            app.startup_ui.history_error.as_deref(),
            Some("Synthetic unreadable operation history")
        );
        let mut output = context.run_ui(Default::default(), |ui| app.paint(ui));
        assert!(!output.shapes.is_empty());
        output.textures_delta.clear();
        assert!(app.startup_ui.history.is_empty());
        assert_eq!(prior[0].intent["text"], "retained");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn cached_startup_sort_preserves_case_folded_ties_and_each_column_direction() {
        let seed = startup_qa_entry(StartupSection::StartupApps, EnabledState::Enabled);
        let entries: Vec<_> = ["Zeta", "Alpha", "alpha"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                let mut entry = seed.clone();
                entry.id = StartupId(format!("{index:064x}"));
                entry.program = FieldValue::Known { value: name.into() };
                entry.publisher = FieldValue::Known {
                    value: ["Same", "same", "Other"][index].into(),
                };
                entry.file_path = FieldValue::Known {
                    value: [r"C:\Z", r"c:\a", r"C:\A"][index].into(),
                };
                entry.enabled = [
                    EnabledState::Enabled,
                    EnabledState::Disabled,
                    EnabledState::Unknown {
                        reason: "Synthetic unknown".into(),
                    },
                ][index]
                    .clone();
                entry
            })
            .collect();
        for (sort, ascending, descending) in [
            (SortColumn::Program, [1, 2, 0], [0, 1, 2]),
            (SortColumn::Publisher, [2, 0, 1], [0, 1, 2]),
            (SortColumn::FilePath, [1, 2, 0], [0, 1, 2]),
            (SortColumn::Enabled, [1, 0, 2], [2, 0, 1]),
        ] {
            for (reverse, expected) in [(false, ascending), (true, descending)] {
                let mut rows = entries.iter().collect::<Vec<_>>();
                sort_startup_entries(&mut rows, sort, reverse);
                assert_eq!(
                    rows.iter().map(|row| row.id.clone()).collect::<Vec<_>>(),
                    expected.map(|index| entries[index].id.clone())
                );
            }
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn startup_inventory_frame_cost() {
        let stage = std::env::var("DCLEANER_BENCH_STAGE").unwrap_or_else(|_| "ordinary".into());
        for count in [128usize, 1024] {
            let context = egui::Context::default();
            let mut app = App::new_fixture_with_context(&context, "startup-populated").unwrap();
            let mut inventory = app.startup_ui.inventories[&StartupSection::StartupApps]
                .as_ref()
                .clone();
            let seed = inventory.entries[0].clone();
            inventory.entries = (0..count)
                .map(|slot| {
                    let index = (slot * 997) % count;
                    let mut entry = seed.clone();
                    entry.id = StartupId(format!("{index:064x}"));
                    entry.program = FieldValue::Known {
                        value: format!("Synthetic startup {index:04}"),
                    };
                    entry.command = FieldValue::Known {
                        value: format!(
                            "SYNTHETIC_NOT_EXECUTABLE_{index}_{}",
                            "metadata ".repeat(448)
                        ),
                    };
                    entry
                })
                .collect();
            app.startup_ui
                .inventories
                .insert(StartupSection::StartupApps, Arc::new(inventory));
            let history = PreparedHistory::prepare((0..count.min(1000))
                .map(|index| EffectHistory {
                    id: Uuid::from_u128(index as u128 + 1),
                    feature: "startup".into(),
                    date: "2026-10-17T00:00:00Z".into(),
                    intent: serde_json::json!({"synthetic":true,"opaque": "history ".repeat(512)}),
                    state: "cancelled".into(),
                    receipt: None,
                })
                .collect(), &AtomicBool::new(false)).unwrap();
            app.startup_ui.history = history.records;
            app.startup_ui.history_view = history.view;
            app.startup_ui.selected = None;
            let pointer = app.startup_ui.inventories[&StartupSection::StartupApps]
                .entries
                .as_ptr();
            let mut samples = Vec::new();
            for tick in 0..8 {
                let started = std::time::Instant::now();
                let mut output = context.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(920., 612.),
                        )),
                        ..Default::default()
                    },
                    |ui| app.paint(ui),
                );
                if tick >= 3 {
                    samples.push(started.elapsed().as_secs_f64() * 1000.);
                }
                assert!(!output.shapes.is_empty());
                output.textures_delta.clear();
            }
            assert_eq!(
                app.startup_ui.inventories[&StartupSection::StartupApps]
                    .entries
                    .as_ptr(),
                pointer
            );
            assert_eq!(
                app.startup_ui.inventories[&StartupSection::StartupApps]
                    .entries
                    .len(),
                count
            );
            eprintln!(
                "STARTUP_FRAME_BENCH {}",
                serde_json::json!({"stage":stage,"rows":count,"history_records":count.min(1000),"history_expanded":false,"warm_layout_ms":samples,"synthetic":true,"physical_input":false,"native_window":false})
            );
        }
    }

    #[test]
    fn startup_tabs_only_show_exact_counts_from_complete_cached_inventories() {
        let complete = StartupInventory {
            section: StartupSection::StartupApps,
            quality: InventoryQuality::Complete,
            entries: Vec::new(),
            sources: Vec::new(),
        };
        let partial_with_rows = StartupInventory {
            section: StartupSection::ScheduledTasks,
            quality: InventoryQuality::Partial,
            entries: vec![startup_qa_entry(
                StartupSection::ScheduledTasks,
                EnabledState::Enabled,
            )],
            sources: Vec::new(),
        };
        let partial_empty = StartupInventory {
            section: StartupSection::ContextMenu,
            quality: InventoryQuality::Partial,
            entries: Vec::new(),
            sources: Vec::new(),
        };
        let unavailable = StartupInventory {
            section: StartupSection::WindowsServices,
            quality: InventoryQuality::Unavailable,
            entries: Vec::new(),
            sources: Vec::new(),
        };

        assert_eq!(startup_cached_tab_count(None), None);
        assert_eq!(startup_cached_tab_count(Some(&complete)), Some(0));
        assert_eq!(startup_cached_tab_count(Some(&partial_with_rows)), None);
        assert_eq!(startup_cached_tab_count(Some(&partial_empty)), None);
        assert_eq!(startup_cached_tab_count(Some(&unavailable)), None);
    }

    #[test]
    fn startup_switch_and_header_use_only_observed_state() {
        assert_eq!(known_enabled_value(&EnabledState::Enabled), Some(true));
        assert_eq!(known_enabled_value(&EnabledState::Disabled), Some(false));
        assert_eq!(
            known_enabled_value(&EnabledState::Unknown {
                reason: "fixture unknown".into()
            }),
            None
        );
        assert_eq!(state_header_label(StartupSection::ScheduledTasks), "Enable");
        assert_eq!(state_header_label(StartupSection::StartupApps), "Start up");
        assert_eq!(state_header_label(StartupSection::ContextMenu), "Start up");
        assert_eq!(
            state_header_label(StartupSection::WindowsServices),
            "Start up"
        );
    }

    #[test]
    fn startup_freshness_warning_survives_a_stalled_refresh() {
        assert_eq!(
            startup_freshness_label(true, false, Some(Duration::from_secs(30))),
            Some("checking current state")
        );
        assert_eq!(
            startup_freshness_label(false, true, Some(Duration::from_secs(2))),
            Some("change in progress; shown state not refreshed")
        );
        assert_eq!(
            startup_freshness_label(false, false, Some(Duration::from_secs(30))),
            Some("state may be stale")
        );
        assert_eq!(
            startup_freshness_label(false, false, Some(Duration::from_secs(9))),
            None
        );
        assert_eq!(startup_freshness_label(false, false, None), None);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn fixture_review_intent_is_typed_read_only_and_unknown_cannot_toggle() {
        let enabled = startup_qa_entry(StartupSection::StartupApps, EnabledState::Enabled);
        let intent = startup_qa_intent(&enabled, false).unwrap();
        assert!(valid_change_intent(&intent));
        assert_eq!(intent.before.native, NativeState::ReadOnly);
        assert_eq!(intent.expected_after.native, NativeState::ReadOnly);

        let mut unknown = startup_qa_entry(
            StartupSection::StartupApps,
            EnabledState::Unknown {
                reason: "fixture unknown".into(),
            },
        );
        unknown.can_change_enabled = true;
        assert!(startup_qa_intent(&unknown, true).is_none());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn fixture_run_removal_review_is_typed_and_contains_no_live_registry_snapshot() {
        let entry = startup_qa_entry(StartupSection::StartupApps, EnabledState::Enabled);
        let intent = startup_qa_removal_intent(&entry).unwrap();
        assert!(valid_removal_intent(&intent));
        assert!(dcleaner::startup_removal::supports_run_value_removal(
            &intent.identity
        ));
        assert_eq!(intent.id, entry.id);
        assert_eq!(intent.before.approval, None);
        assert_eq!(
            intent.before.run.unwrap().value_type,
            1,
            "the fixture represents an explicitly synthetic REG_SZ"
        );
    }

    #[test]
    fn removal_history_only_offers_guarded_restore_until_one_is_confirmed() {
        let intent = {
            #[cfg(debug_assertions)]
            {
                startup_qa_removal_intent(&startup_qa_entry(
                    StartupSection::StartupApps,
                    EnabledState::Enabled,
                ))
                .unwrap()
            }
            #[cfg(not(debug_assertions))]
            {
                let identity = EntryIdentity::StartupRunValue {
                    hive: dcleaner::startup::RegistryHive::CurrentUser,
                    view: RegistryView::Registry64,
                    key: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
                    value_name: "FixtureEntry".into(),
                    approval_hive: dcleaner::startup::RegistryHive::CurrentUser,
                    approval_key:
                        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
                            .into(),
                };
                let intent = RemovalIntent {
                    schema_version: dcleaner::startup_removal::REMOVAL_SCHEMA_VERSION,
                    operation_id: Uuid::new_v4(),
                    id: StartupId::for_identity(&identity),
                    identity,
                    before: RunValueSlots {
                        run: Some(RegistryValueSnapshot {
                            value_type: 1,
                            data: vec![b'x', 0, 0, 0],
                        }),
                        approval: None,
                    },
                };
                assert!(valid_removal_intent(&intent));
                intent
            }
        };
        let removal = RemovalReceipt {
            schema_version: dcleaner::startup_removal::REMOVAL_SCHEMA_VERSION,
            operation_id: intent.operation_id,
            id: intent.id.clone(),
            identity: intent.identity.clone(),
            before: intent.before.clone(),
            after: Some(RunValueSlots {
                run: None,
                approval: None,
            }),
            outcome: RemovalOutcome::Removed,
            error: None,
        };
        let record = EffectHistory {
            id: intent.operation_id,
            feature: "startup".into(),
            date: "2026-10-15T00:00:00Z".into(),
            intent: serde_json::to_value(&intent).unwrap(),
            state: "applied".into(),
            receipt: Some(serde_json::to_value(&removal).unwrap()),
        };
        assert!(matches!(
            history_removal_source(&record, std::slice::from_ref(&record)),
            Some(RemovalHistorySource::Receipt(_))
        ));

        let restore_intent = RemovalRestoreIntent {
            schema_version: dcleaner::startup_removal::REMOVAL_SCHEMA_VERSION,
            restore_id: Uuid::new_v4(),
            source_operation_id: intent.operation_id,
            id: intent.id.clone(),
            identity: intent.identity.clone(),
            before: intent.before.clone(),
            expected_current: RunValueSlots {
                run: None,
                approval: None,
            },
        };
        assert!(valid_restore_intent(&restore_intent));
        let uncertain_restore = EffectHistory {
            id: restore_intent.restore_id,
            feature: "startup".into(),
            date: "2026-10-15T00:00:30Z".into(),
            intent: serde_json::to_value(&restore_intent).unwrap(),
            state: "uncertain".into(),
            receipt: None,
        };
        assert!(matches!(
            history_removal_source(
                &uncertain_restore,
                &[record.clone(), uncertain_restore.clone()]
            ),
            Some(RemovalHistorySource::Intent(_))
        ));

        let restored = RemovalRestoreReceipt {
            schema_version: dcleaner::startup_removal::REMOVAL_SCHEMA_VERSION,
            restore_id: restore_intent.restore_id,
            source_operation_id: intent.operation_id,
            id: intent.id,
            identity: intent.identity,
            before: intent.before.clone(),
            expected_current: restore_intent.expected_current.clone(),
            after: Some(intent.before),
            outcome: RemovalRestoreOutcome::Restored,
            error: None,
        };
        let restore_record = EffectHistory {
            id: restored.restore_id,
            feature: "startup".into(),
            date: "2026-10-15T00:01:00Z".into(),
            intent: serde_json::to_value(&restore_intent).unwrap(),
            state: "restored".into(),
            receipt: Some(serde_json::to_value(restored).unwrap()),
        };
        assert!(history_removal_source(&record, &[record.clone(), restore_record]).is_none());
    }

    #[test]
    fn removal_history_rejects_payloads_that_do_not_match_the_journal_intent() {
        let intent = {
            #[cfg(debug_assertions)]
            {
                startup_qa_removal_intent(&startup_qa_entry(
                    StartupSection::StartupApps,
                    EnabledState::Enabled,
                ))
                .unwrap()
            }
            #[cfg(not(debug_assertions))]
            {
                let identity = EntryIdentity::StartupRunValue {
                    hive: dcleaner::startup::RegistryHive::CurrentUser,
                    view: RegistryView::Registry64,
                    key: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
                    value_name: "FixtureEntry".into(),
                    approval_hive: dcleaner::startup::RegistryHive::CurrentUser,
                    approval_key:
                        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
                            .into(),
                };
                RemovalIntent {
                    schema_version: dcleaner::startup_removal::REMOVAL_SCHEMA_VERSION,
                    operation_id: Uuid::new_v4(),
                    id: StartupId::for_identity(&identity),
                    identity,
                    before: RunValueSlots {
                        run: Some(RegistryValueSnapshot {
                            value_type: 1,
                            data: vec![b'x', 0, 0, 0],
                        }),
                        approval: None,
                    },
                }
            }
        };
        assert!(valid_removal_intent(&intent));
        let mut receipt = RemovalReceipt {
            schema_version: dcleaner::startup_removal::REMOVAL_SCHEMA_VERSION,
            operation_id: intent.operation_id,
            id: intent.id.clone(),
            identity: intent.identity.clone(),
            before: intent.before.clone(),
            after: Some(RunValueSlots {
                run: None,
                approval: None,
            }),
            outcome: RemovalOutcome::Removed,
            error: None,
        };
        assert!(valid_removal_receipt(&receipt));
        let mut record = EffectHistory {
            id: intent.operation_id,
            feature: "startup".into(),
            date: "2026-10-15T00:00:00Z".into(),
            intent: serde_json::to_value(&intent).unwrap(),
            state: "applied".into(),
            receipt: Some(serde_json::to_value(&receipt).unwrap()),
        };
        assert!(matches!(
            history_removal_source(&record, std::slice::from_ref(&record)),
            Some(RemovalHistorySource::Receipt(_))
        ));

        if let EntryIdentity::StartupRunValue { value_name, .. } = &mut receipt.identity {
            *value_name = "DifferentEntry".into();
        }
        receipt.id = StartupId::for_identity(&receipt.identity);
        assert!(valid_removal_receipt(&receipt));
        record.receipt = Some(serde_json::to_value(&receipt).unwrap());
        assert!(history_removal_source(&record, std::slice::from_ref(&record)).is_none());

        let mut changed_intent = intent.clone();
        changed_intent.before.run.as_mut().unwrap().data = vec![b'y', 0, 0, 0];
        assert!(valid_removal_intent(&changed_intent));
        record.intent = serde_json::to_value(changed_intent).unwrap();
        record.receipt = Some(
            serde_json::to_value(RemovalReceipt {
                schema_version: dcleaner::startup_removal::REMOVAL_SCHEMA_VERSION,
                operation_id: intent.operation_id,
                id: intent.id,
                identity: intent.identity,
                before: intent.before,
                after: Some(RunValueSlots {
                    run: None,
                    approval: None,
                }),
                outcome: RemovalOutcome::Removed,
                error: None,
            })
            .unwrap(),
        );
        assert!(history_removal_source(&record, std::slice::from_ref(&record)).is_none());
    }

    #[test]
    fn uncertain_restore_history_requires_its_original_removal_and_matching_receipt() {
        let identity = EntryIdentity::StartupRunValue {
            hive: dcleaner::startup::RegistryHive::CurrentUser,
            view: RegistryView::Registry64,
            key: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
            value_name: "FixtureEntry".into(),
            approval_hive: dcleaner::startup::RegistryHive::CurrentUser,
            approval_key: r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
                .into(),
        };
        let removal_intent = RemovalIntent {
            schema_version: dcleaner::startup_removal::REMOVAL_SCHEMA_VERSION,
            operation_id: Uuid::new_v4(),
            id: StartupId::for_identity(&identity),
            identity: identity.clone(),
            before: RunValueSlots {
                run: Some(RegistryValueSnapshot {
                    value_type: 1,
                    data: vec![b'x', 0, 0, 0],
                }),
                approval: None,
            },
        };
        let restore_intent = RemovalRestoreIntent {
            schema_version: dcleaner::startup_removal::REMOVAL_SCHEMA_VERSION,
            restore_id: Uuid::new_v4(),
            source_operation_id: removal_intent.operation_id,
            id: removal_intent.id.clone(),
            identity: identity.clone(),
            before: removal_intent.before.clone(),
            expected_current: RunValueSlots {
                run: None,
                approval: None,
            },
        };
        let uncertain_restore = EffectHistory {
            id: restore_intent.restore_id,
            feature: "startup".into(),
            date: "2026-10-15T00:00:00Z".into(),
            intent: serde_json::to_value(&restore_intent).unwrap(),
            state: "uncertain".into(),
            receipt: None,
        };
        assert!(
            history_removal_source(&uncertain_restore, std::slice::from_ref(&uncertain_restore))
                .is_none()
        );

        let removal_receipt = RemovalReceipt {
            schema_version: dcleaner::startup_removal::REMOVAL_SCHEMA_VERSION,
            operation_id: removal_intent.operation_id,
            id: removal_intent.id.clone(),
            identity: identity.clone(),
            before: removal_intent.before.clone(),
            after: Some(RunValueSlots {
                run: None,
                approval: None,
            }),
            outcome: RemovalOutcome::Removed,
            error: None,
        };
        let source = EffectHistory {
            id: removal_intent.operation_id,
            feature: "startup".into(),
            date: "2026-10-14T00:00:00Z".into(),
            intent: serde_json::to_value(&removal_intent).unwrap(),
            state: "applied".into(),
            receipt: Some(serde_json::to_value(&removal_receipt).unwrap()),
        };
        assert!(
            history_removal_source(
                &uncertain_restore,
                &[source.clone(), uncertain_restore.clone()]
            )
            .is_some()
        );

        let mut alternate_identity = identity.clone();
        if let EntryIdentity::StartupRunValue { value_name, .. } = &mut alternate_identity {
            *value_name = "AlternateEntry".into();
        }
        let mut alternate_restore_intent = restore_intent.clone();
        alternate_restore_intent.identity = alternate_identity.clone();
        alternate_restore_intent.id = StartupId::for_identity(&alternate_identity);
        assert!(valid_restore_intent(&alternate_restore_intent));
        let alternate_restore_record = EffectHistory {
            id: alternate_restore_intent.restore_id,
            feature: "startup".into(),
            date: "2026-10-15T00:00:10Z".into(),
            intent: serde_json::to_value(alternate_restore_intent).unwrap(),
            state: "uncertain".into(),
            receipt: None,
        };
        assert!(
            history_removal_source(
                &alternate_restore_record,
                &[source.clone(), alternate_restore_record.clone()]
            )
            .is_none()
        );

        let mut mismatched_restore_receipt = RemovalRestoreReceipt {
            schema_version: dcleaner::startup_removal::REMOVAL_SCHEMA_VERSION,
            restore_id: restore_intent.restore_id,
            source_operation_id: restore_intent.source_operation_id,
            id: restore_intent.id.clone(),
            identity,
            before: restore_intent.before.clone(),
            expected_current: restore_intent.expected_current.clone(),
            after: Some(restore_intent.before.clone()),
            outcome: RemovalRestoreOutcome::Restored,
            error: None,
        };
        mismatched_restore_receipt.source_operation_id = Uuid::new_v4();
        assert!(valid_restore_receipt(&mismatched_restore_receipt));
        let mut confirmed_restore = uncertain_restore.clone();
        confirmed_restore.state = "restored".into();
        confirmed_restore.receipt =
            Some(serde_json::to_value(&mismatched_restore_receipt).unwrap());
        assert!(
            history_removal_source(&source, &[source.clone(), confirmed_restore.clone()]).is_some()
        );

        mismatched_restore_receipt.source_operation_id = restore_intent.source_operation_id;
        let mut changed_restore_intent = restore_intent.clone();
        changed_restore_intent.expected_current = removal_intent.before.clone();
        assert!(valid_restore_intent(&changed_restore_intent));
        confirmed_restore.intent = serde_json::to_value(changed_restore_intent).unwrap();
        confirmed_restore.receipt =
            Some(serde_json::to_value(&mismatched_restore_receipt).unwrap());
        assert!(valid_restore_receipt(&mismatched_restore_receipt));
        assert!(
            history_removal_source(&source, &[source.clone(), confirmed_restore.clone()]).is_some()
        );

        confirmed_restore.intent = serde_json::to_value(&restore_intent).unwrap();
        assert!(history_removal_source(&source, &[source.clone(), confirmed_restore]).is_none());
    }

    #[test]
    fn text_export_uses_explicit_unknowns_and_sanitizes_record_delimiters() {
        assert_eq!(startup_export_enabled(&EnabledState::Enabled), "Yes");
        assert_eq!(
            startup_export_enabled(&EnabledState::Unknown { reason: "x".into() }),
            "Unknown"
        );
        assert_eq!(
            startup_export_field(&FieldValue::Known {
                value: "one\ttwo\r\nthree".into()
            }),
            "one two  three"
        );
        assert_eq!(
            startup_export_field(&FieldValue::Unknown {
                reason: "no path".into()
            }),
            "Unknown"
        );
    }

    #[test]
    fn task_change_xml_payloads_are_only_offered_as_typed_recovery() {
        let before = fake_task_state(true);
        let receipt = ChangeReceipt {
            schema_version: dcleaner::startup::CHANGE_SCHEMA_VERSION,
            intent_id: Uuid::new_v4(),
            id: before.id.clone(),
            before,
            after: fake_task_state(false),
            outcome: ChangeOutcome::Applied,
        };
        let mut record = EffectHistory {
            id: Uuid::new_v4(),
            feature: "startup".into(),
            date: "2026-10-15T00:00:00Z".into(),
            intent: serde_json::to_value(&receipt).unwrap(),
            state: "uncertain".into(),
            receipt: None,
        };
        assert!(matches!(
            history_review_action(&record, std::slice::from_ref(&record)),
            Some(ReviewAction::RecoverReceipt(_))
        ));
        record.intent = serde_json::json!({"arbitrary":"payload"});
        assert!(history_review_action(&record, &[record.clone()]).is_none());
    }

    fn fake_task_state(enabled: bool) -> ObservedState {
        let identity = EntryIdentity::ScheduledTask {
            path: r"\Example\Task".into(),
        };
        ObservedState {
            id: StartupId::for_identity(&identity),
            identity,
            enabled: if enabled {
                EnabledState::Enabled
            } else {
                EnabledState::Disabled
            },
            native: NativeState::ScheduledTask {
                xml: Some("<Task/>".into()),
            },
        }
    }
}
