use super::{App, Event};
use crate::theme::{self, Tokens};
use dcleaner::{
    effects::{self, EffectHistory},
    recycle_bin::{
        self, InventoryCompletion, ItemOperationState, OperationCompletion, RecycleBinInventory,
        RecycleBinItem, RecycleBinOperation, RecycleBinOperationReport, RecycleBinSize,
        SystemRecycleBin,
    },
};
use eframe::egui::{self, Align, Layout, RichText};
#[cfg(debug_assertions)]
use std::{collections::VecDeque, ffi::OsString, path::PathBuf};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, mpsc},
    thread,
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ItemFilter {
    #[default]
    All,
    Files,
    Folders,
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum RecycleBinOperationState {
    #[default]
    Idle,
    Loading,
    Restoring,
    Purging,
}

pub(super) struct RecycleBinUi {
    loaded: bool,
    inventory: Option<RecycleBinInventory>,
    history: Vec<EffectHistory>,
    journal_readable: bool,
    journal_error: Option<String>,
    operation: RecycleBinOperationState,
    selected_ids: HashSet<Uuid>,
    search: String,
    filter: ItemFilter,
    detail_id: Option<Uuid>,
    review_open: bool,
    acknowledge_purge: bool,
    last_report: Option<RecycleBinOperationReport>,
    last_labels: HashMap<Uuid, String>,
}

impl Default for RecycleBinUi {
    fn default() -> Self {
        Self {
            loaded: false,
            inventory: None,
            history: Vec::new(),
            journal_readable: false,
            journal_error: None,
            operation: RecycleBinOperationState::Idle,
            selected_ids: HashSet::new(),
            search: String::new(),
            filter: ItemFilter::All,
            detail_id: None,
            review_open: false,
            acknowledge_purge: false,
            last_report: None,
            last_labels: HashMap::new(),
        }
    }
}

pub(super) enum RecycleBinEvent {
    InventoryProgress {
        done: usize,
        total: usize,
    },
    InventoryLoaded {
        inventory: RecycleBinInventory,
        history: Result<Vec<EffectHistory>, String>,
    },
    OperationProgress {
        operation: RecycleBinOperation,
        done: usize,
        total: usize,
    },
    OperationFinished {
        report: RecycleBinOperationReport,
        labels: HashMap<Uuid, String>,
        inventory: RecycleBinInventory,
        history: Result<Vec<EffectHistory>, String>,
    },
}

impl App {
    #[cfg(debug_assertions)]
    pub(super) fn seed_recycle_bin_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Recycle Bin fixtures are available only in isolated visual QA.".into());
        }
        let mut ui = RecycleBinUi::default();
        ui.loaded = true;
        ui.journal_readable = false;
        ui.journal_error = Some("Synthetic visual fixture; operation history was not read.".into());
        match case {
            "recyclebin-empty" => {
                ui.inventory = Some(build_recycle_bin_preview_inventory(false, false));
            }
            "recyclebin-populated" | "recyclebin-selected" | "recyclebin-details" => {
                ui.inventory = Some(build_recycle_bin_preview_inventory(false, true));
                if case == "recyclebin-selected" {
                    if let Some(item) = ui
                        .inventory
                        .as_ref()
                        .and_then(|inventory| inventory.items.first())
                    {
                        ui.selected_ids.insert(item.id());
                    }
                }
                if case == "recyclebin-details" {
                    ui.detail_id = ui
                        .inventory
                        .as_ref()
                        .and_then(|inventory| inventory.items.first())
                        .map(RecycleBinItem::id);
                }
            }
            "recyclebin-error" => {
                ui.inventory = Some(build_recycle_bin_preview_inventory(true, false));
            }
            _ => return Err(format!("Unsupported Recycle Bin visual fixture: {case}")),
        }
        self.recycle_bin_ui = ui;
        Ok(())
    }

    /// Called by the Custom Clean navigation transition whenever the user
    /// enters Junk > Recycle Bin. The list is always refreshed for that visit.
    pub(super) fn recycle_bin_entered(&mut self, ctx: &egui::Context) {
        if self.qa_fixture_mode()
            || self.busy()
            || self.recycle_bin_ui.operation != RecycleBinOperationState::Idle
        {
            return;
        }
        self.recycle_bin_ui.loaded = false;
        self.recycle_bin_ui.inventory = None;
        self.recycle_bin_ui.selected_ids.clear();
        self.recycle_bin_ui.detail_id = None;
        self.recycle_bin_ui.review_open = false;
        self.recycle_bin_ui.last_report = None;
        self.recycle_bin_ui.last_labels.clear();
        self.begin_recycle_bin_inventory(ctx);
    }

    pub(super) fn recycle_bin_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if !self.qa_fixture_mode()
            && !self.recycle_bin_ui.loaded
            && self.recycle_bin_ui.operation == RecycleBinOperationState::Idle
            && !self.busy()
        {
            self.begin_recycle_bin_inventory(ctx);
        }

        let busy = self.busy();
        let mut refresh = false;
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Recycle Bin").family(theme::semibold()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    refresh = theme::secondary(ui, "Refresh", !busy);
                });
            });
            ui.add_space(5.);
            theme::muted(
                ui,
                "Read-only inventory of the current user’s operating-system recycle bin.",
                t,
            );

            if let Some(inventory) = self.recycle_bin_ui.inventory.as_ref() {
                ui.add_space(10.);
                self.recycle_bin_inventory_summary(ui, inventory, t);
            } else if self.recycle_bin_ui.operation == RecycleBinOperationState::Loading {
                ui.add_space(12.);
                ui.horizontal(|ui| {
                    ui.spinner();
                    theme::muted(ui, "Reading recycle-bin items and metadata…", t);
                });
            } else {
                ui.add_space(10.);
                theme::muted(ui, "Inventory has not been loaded.", t);
            }
        });
        if refresh {
            self.begin_recycle_bin_inventory(ctx);
        }

        ui.add_space(10.);
        self.recycle_bin_results(ui, t, busy);
        ui.add_space(10.);
        self.recycle_bin_recovery_history(ui, t);
        if let Some(report) = self.recycle_bin_ui.last_report.as_ref() {
            ui.add_space(10.);
            self.recycle_bin_operation_result(ui, report, t);
        }
    }

    pub(super) fn recycle_bin_footer(
        &mut self,
        ui: &mut egui::Ui,
        t: Tokens,
        _ctx: &egui::Context,
    ) {
        let busy = self.busy();
        ui.set_min_height(40.);
        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            match self.recycle_bin_ui.operation {
                RecycleBinOperationState::Loading => {
                    theme::muted(ui, self.progress.clone(), t);
                    ui.add_space(10.);
                    if theme::secondary(ui, "Stop inventory", true) {
                        self.cancel
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                RecycleBinOperationState::Restoring | RecycleBinOperationState::Purging => {
                    theme::muted(ui, self.progress.clone(), t);
                    ui.add_space(10.);
                    if theme::secondary(ui, "Stop after this item", true) {
                        self.cancel
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                RecycleBinOperationState::Idle => {
                    ui.with_layout(
                        Layout::right_to_left(Align::Center).with_main_wrap(true),
                        |ui| {
                            let selected = self.recycle_bin_ui.selected_ids.len();
                            let selected_bytes = self.selected_known_bytes();
                            let can_review = !busy
                                && selected > 0
                                && self.recycle_bin_ui.journal_readable
                                && self.recycle_bin_ui.inventory.as_ref().is_some_and(
                                    |inventory| {
                                        inventory.completion == InventoryCompletion::Complete
                                            && self.recycle_bin_ui.selected_ids.iter().all(|id| {
                                                inventory.items.iter().any(|item| item.id() == *id)
                                            })
                                    },
                                );
                            let label = if selected == 0 {
                                "Review selected".into()
                            } else {
                                format!(
                                    "Review {}",
                                    theme::counted_label(selected, "item", "items")
                                )
                            };
                            if theme::primary(ui, &label, t, can_review) {
                                self.recycle_bin_ui.review_open = true;
                                self.recycle_bin_ui.acknowledge_purge = false;
                            }
                            theme::muted(
                                ui,
                                format!(
                                    "{selected} selected · {} known file bytes",
                                    format_bytes(selected_bytes)
                                ),
                                t,
                            );
                        },
                    );
                }
            }
        });
    }

    pub(super) fn recycle_bin_dialog(&mut self, ctx: &egui::Context) {
        if self.recycle_bin_ui.detail_id.is_some() {
            self.recycle_bin_detail_dialog(ctx);
        }
        if self.recycle_bin_ui.review_open {
            self.recycle_bin_review_dialog(ctx);
        }
    }

    pub(super) fn recycle_bin_event(&mut self, event: RecycleBinEvent) {
        match event {
            RecycleBinEvent::InventoryProgress { done, total } => {
                self.progress = if total == 0 {
                    "Reading recycle-bin inventory…".into()
                } else {
                    format!("Reading recycle-bin metadata · {done} of {total}")
                };
            }
            RecycleBinEvent::InventoryLoaded { inventory, history } => {
                self.worker = None;
                self.recycle_bin_ui.operation = RecycleBinOperationState::Idle;
                self.recycle_bin_ui.loaded = true;
                self.recycle_bin_ui.selected_ids.clear();
                self.recycle_bin_ui.detail_id = None;
                self.recycle_bin_ui.inventory = Some(inventory);
                self.update_recycle_bin_history(history);
                self.recycle_bin_ui.review_open = false;
                self.recycle_bin_ui.acknowledge_purge = false;
                if let Some(inventory) = self.recycle_bin_ui.inventory.as_ref() {
                    match inventory.completion {
                        InventoryCompletion::Complete => self.notice = None,
                        InventoryCompletion::Partial => {
                            self.notice = Some(format!(
                                "Recycle Bin inventory is partial: {} item details need review.",
                                inventory.issue_count()
                            ));
                        }
                        InventoryCompletion::Cancelled => {
                            self.notice = Some(
                                "Recycle Bin inventory was stopped. Review actions require a complete fresh inventory.".into(),
                            );
                        }
                        InventoryCompletion::Failed | InventoryCompletion::Unsupported => {
                            self.notice = inventory
                                .issues
                                .first()
                                .map(|issue| issue.message.clone())
                                .or_else(|| {
                                    Some(
                                        "Recycle Bin inventory is unavailable on this system."
                                            .into(),
                                    )
                                });
                        }
                    }
                }
            }
            RecycleBinEvent::OperationProgress {
                operation,
                done,
                total,
            } => {
                let verb = match operation {
                    RecycleBinOperation::Restore => "Restoring",
                    RecycleBinOperation::Purge => "Purging",
                };
                self.progress = format!("{verb} reviewed items · {done} of {total}");
            }
            RecycleBinEvent::OperationFinished {
                report,
                labels,
                inventory,
                history,
            } => {
                self.worker = None;
                self.recycle_bin_ui.operation = RecycleBinOperationState::Idle;
                self.recycle_bin_ui.loaded = true;
                self.recycle_bin_ui.inventory = Some(inventory);
                self.recycle_bin_ui.selected_ids.clear();
                self.recycle_bin_ui.review_open = false;
                self.recycle_bin_ui.acknowledge_purge = false;
                self.recycle_bin_ui.last_labels = labels;
                self.recycle_bin_ui.last_report = Some(report.clone());
                self.update_recycle_bin_history(history);
                let succeeded = report
                    .receipts
                    .iter()
                    .filter(|receipt| {
                        matches!(
                            receipt.state,
                            ItemOperationState::Restored | ItemOperationState::Purged
                        )
                    })
                    .count();
                let uncertain = report
                    .receipts
                    .iter()
                    .filter(|receipt| receipt.state == ItemOperationState::Uncertain)
                    .count();
                let total = report.receipts.len();
                let verb = match report.operation {
                    RecycleBinOperation::Restore => "restored",
                    RecycleBinOperation::Purge => "permanently purged",
                };
                if succeeded > 0 {
                    self.notice = Some(format!(
                        "{succeeded} of {total} selected items {verb}. Review the item outcomes below."
                    ));
                } else {
                    self.notice = Some(format!(
                        "No selected items were confirmed {verb}. Review the item outcomes below."
                    ));
                }
                if uncertain > 0 {
                    self.error = Some(format!(
                        "{uncertain} item outcome(s) are uncertain. Review the durable Recycle Bin history; DCleaner will not retry them automatically."
                    ));
                }
                if let Some(error) = self.recycle_bin_ui.journal_error.clone() {
                    self.error = Some(format!(
                        "The operation report is available, but durable Recycle Bin history could not be read: {error}"
                    ));
                }
            }
        }
    }

    fn recycle_bin_inventory_summary(
        &self,
        ui: &mut egui::Ui,
        inventory: &RecycleBinInventory,
        t: Tokens,
    ) {
        let files = inventory
            .items
            .iter()
            .filter(|item| matches!(item.size(), Some(RecycleBinSize::Bytes(_))))
            .count();
        let folders = inventory
            .items
            .iter()
            .filter(|item| matches!(item.size(), Some(RecycleBinSize::Entries(_))))
            .count();
        let unknown = inventory.items.len().saturating_sub(files + folders);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(inventory.item_count().to_string())
                    .size(theme::FONT_DISPLAY)
                    .family(theme::semibold()),
            );
            theme::muted(ui, "items", t);
            theme::muted(
                ui,
                format!(
                    "{} · {}",
                    theme::counted_label(files, "file", "files"),
                    theme::counted_label(folders, "folder", "folders")
                ),
                t,
            );
            theme::muted(
                ui,
                format!(
                    "{} known file bytes",
                    format_bytes(inventory.known_file_bytes)
                ),
                t,
            );
            if unknown > 0 {
                ui.colored_label(t.attention, format!("{unknown} unreadable sizes"));
            }
        });

        match inventory.completion {
            InventoryCompletion::Complete => {}
            InventoryCompletion::Partial => {
                ui.colored_label(
                    t.attention,
                    format!(
                        "Partial inventory · {} issue(s). Reviewed actions are disabled until a complete refresh.",
                        inventory.issue_count()
                    ),
                );
            }
            InventoryCompletion::Cancelled => {
                ui.colored_label(
                    t.attention,
                    "Inventory stopped · reviewed actions are disabled until a complete refresh.",
                );
            }
            InventoryCompletion::Failed => {
                ui.colored_label(
                    t.attention,
                    "Inventory failed. No item actions are available.",
                );
            }
            InventoryCompletion::Unsupported => {
                ui.colored_label(
                    t.attention,
                    "This platform does not expose a supported current-user recycle-bin inventory.",
                );
            }
        }
        if !inventory.issues.is_empty() {
            egui::CollapsingHeader::new(format!("Inventory notes · {}", inventory.issues.len()))
                .id_salt("recycle-bin-inventory-notes")
                .show(ui, |ui| {
                    for issue in inventory.issues.iter().take(20) {
                        ui.add(egui::Label::new(issue.message.as_str()).wrap());
                    }
                    if inventory.issues.len() > 20 {
                        theme::muted(
                            ui,
                            format!(
                                "{} additional notes are hidden.",
                                inventory.issues.len() - 20
                            ),
                            t,
                        );
                    }
                });
        }
    }

    fn recycle_bin_results(&mut self, ui: &mut egui::Ui, t: Tokens, busy: bool) {
        let Some(inventory) = self.recycle_bin_ui.inventory.as_ref() else {
            if self.recycle_bin_ui.operation == RecycleBinOperationState::Loading {
                return;
            }
            theme::card(t).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Recycle Bin items").family(theme::semibold()));
                ui.add_space(6.);
                theme::muted(
                    ui,
                    "No inventory is available. Refresh to read supported recycle-bin entries.",
                    t,
                );
            });
            return;
        };

        let complete = inventory.completion == InventoryCompletion::Complete;
        let inventory_items = inventory.items.clone();
        let mut detail = None;
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Recycle Bin items").family(theme::semibold()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    theme::muted(ui, format!("{} entries", inventory_items.len()), t);
                });
            });
            ui.add_space(8.);
            theme::control_row(ui, |ui| {
                let search_width = (ui.available_width() - 220.).clamp(170., 340.);
                theme::input(
                    ui,
                    &mut self.recycle_bin_ui.search,
                    search_width,
                    "Search name or original location",
                    true,
                );
                theme::selector(
                    ui,
                    "recycle-bin-filter",
                    filter_label(self.recycle_bin_ui.filter),
                    &["All items", "Files", "Folders", "Unknown size"],
                    |ui| {
                        theme::choice_value(
                            ui,
                            &mut self.recycle_bin_ui.filter,
                            ItemFilter::All,
                            "All items",
                        );
                        theme::choice_value(
                            ui,
                            &mut self.recycle_bin_ui.filter,
                            ItemFilter::Files,
                            "Files",
                        );
                        theme::choice_value(
                            ui,
                            &mut self.recycle_bin_ui.filter,
                            ItemFilter::Folders,
                            "Folders",
                        );
                        theme::choice_value(
                            ui,
                            &mut self.recycle_bin_ui.filter,
                            ItemFilter::Unknown,
                            "Unknown size",
                        );
                    },
                );
            });
            let query = self.recycle_bin_ui.search.trim().to_ascii_lowercase();
            let visible = inventory_items
                .iter()
                .filter(|item| filter_matches(self.recycle_bin_ui.filter, item))
                .filter(|item| item_matches_query(item, &query))
                .cloned()
                .collect::<Vec<_>>();
            let visible_ids = visible
                .iter()
                .filter(|item| item.is_size_readable())
                .map(RecycleBinItem::id)
                .collect::<Vec<_>>();
            ui.add_space(6.);
            theme::control_row(ui, |ui| {
                theme::muted(
                    ui,
                    format!(
                        "{} visible · {} selected",
                        visible.len(),
                        self.recycle_bin_ui.selected_ids.len()
                    ),
                    t,
                );
                if theme::field_action(
                    ui,
                    "Select visible",
                    !busy && complete && !visible_ids.is_empty(),
                ) {
                    self.recycle_bin_ui
                        .selected_ids
                        .extend(visible_ids.iter().copied());
                }
                if theme::field_action(ui, "Clear selection", !busy) {
                    self.recycle_bin_ui.selected_ids.clear();
                }
            });

            if visible.is_empty() {
                ui.add_space(14.);
                theme::muted(
                    ui,
                    if inventory_items.is_empty() {
                        "The current user’s recycle bin contains no readable entries."
                    } else {
                        "No entries match this search and filter."
                    },
                    t,
                );
                return;
            }

            let available = ui.available_width().max(620.);
            let check_width = 28.;
            let action_width = 76.;
            let deleted_width = 110.;
            let size_width = 76.;
            let gaps = ui.spacing().item_spacing.x * 5.;
            let flexible =
                (available - check_width - action_width - deleted_width - size_width - gaps)
                    .max(190.);
            let name_width = flexible * 0.44;
            let path_width = flexible - name_width;

            theme::scroll_horizontal()
                .id_salt("recycle-bin-table-horizontal")
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.set_min_width(available);
                    ui.horizontal(|ui| {
                        let all_visible_selected = !visible_ids.is_empty()
                            && visible_ids
                                .iter()
                                .all(|id| self.recycle_bin_ui.selected_ids.contains(id));
                        let mut all_visible_selected = all_visible_selected;
                        let mixed = !all_visible_selected
                            && visible_ids
                                .iter()
                                .any(|id| self.recycle_bin_ui.selected_ids.contains(id));
                        let select_response = theme::checkbox_mixed(
                            ui,
                            &mut all_visible_selected,
                            mixed,
                            (),
                            !busy && complete && !visible_ids.is_empty(),
                        );
                        if select_response.changed() {
                            if all_visible_selected {
                                self.recycle_bin_ui
                                    .selected_ids
                                    .extend(visible_ids.iter().copied());
                            } else {
                                for id in &visible_ids {
                                    self.recycle_bin_ui.selected_ids.remove(id);
                                }
                            }
                        }
                        theme::table_cell(ui, "Name", name_width, 30.);
                        theme::table_cell(ui, "Original location", path_width, 30.);
                        theme::table_cell(ui, "Deleted", deleted_width, 30.);
                        theme::table_cell(ui, "Size", size_width, 30.);
                        theme::table_cell(ui, "", action_width, 30.);
                    });
                    ui.separator();
                    theme::scroll_vertical()
                        .id_salt("recycle-bin-table-rows")
                        .max_height(420.)
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            for item in &visible {
                                ui.set_min_width(available);
                                ui.horizontal(|ui| {
                                    let actionable = complete && item.is_size_readable();
                                    let mut selected =
                                        self.recycle_bin_ui.selected_ids.contains(&item.id());
                                    let response = theme::checkbox_widget(
                                        ui,
                                        &mut selected,
                                        !busy && actionable,
                                    );
                                    if response.changed() {
                                        if selected {
                                            self.recycle_bin_ui.selected_ids.insert(item.id());
                                        } else {
                                            self.recycle_bin_ui.selected_ids.remove(&item.id());
                                        }
                                    }
                                    let name = item.name();
                                    theme::table_cell(
                                        ui,
                                        RichText::new(name.clone()).family(theme::semibold()),
                                        name_width,
                                        40.,
                                    )
                                    .on_hover_text(name);
                                    let parent = item.original_parent().display().to_string();
                                    theme::table_cell(ui, parent.clone(), path_width, 40.)
                                        .on_hover_text(parent);
                                    theme::table_cell(
                                        ui,
                                        deleted_date(item.deleted_at_unix_seconds()),
                                        deleted_width,
                                        40.,
                                    );
                                    theme::table_cell(ui, size_label(item.size()), size_width, 40.);
                                    if theme::row_action(ui, "Details", true).clicked() {
                                        detail = Some(item.id());
                                    }
                                });
                                ui.separator();
                            }
                        });
                });
        });
        if let Some(id) = detail {
            self.recycle_bin_ui.detail_id = Some(id);
        }
    }

    fn recycle_bin_recovery_history(&self, ui: &mut egui::Ui, t: Tokens) {
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Recent operation history").family(theme::semibold()));
            ui.add_space(6.);
            if let Some(error) = self.recycle_bin_ui.journal_error.as_deref() {
                ui.colored_label(t.attention, format!("History unavailable: {error}"));
                theme::muted(
                    ui,
                    "Restore and purge remain disabled until the durable history can be read.",
                    t,
                );
            } else if self.recycle_bin_ui.history.is_empty() {
                theme::muted(
                    ui,
                    "Reviewed restores and purges will appear here. Interrupted intents are marked uncertain and are never retried automatically.",
                    t,
                );
            } else {
                for entry in self.recycle_bin_ui.history.iter().take(8) {
                    let operation = entry
                        .intent
                        .get("operation")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("operation");
                    let item_id = entry
                        .intent
                        .get("item_id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("item identity unavailable");
                    let label = format!(
                        "{} · {} · {}",
                        history_state_label(&entry.state),
                        operation_label(operation),
                        short_uuid(item_id)
                    );
                    let is_uncertain = entry.state == "uncertain";
                    ui.horizontal_wrapped(|ui| {
                        if is_uncertain {
                            ui.colored_label(t.attention, label);
                        } else {
                            ui.label(label);
                        }
                        theme::muted(ui, entry.date.clone(), t);
                    });
                }
                if self.recycle_bin_ui.history.len() > 8 {
                    theme::muted(
                        ui,
                        format!(
                            "{} older entries are retained in durable operation history.",
                            self.recycle_bin_ui.history.len() - 8
                        ),
                        t,
                    );
                }
            }
        });
    }

    fn recycle_bin_operation_result(
        &self,
        ui: &mut egui::Ui,
        report: &RecycleBinOperationReport,
        t: Tokens,
    ) {
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let verb = match report.operation {
                RecycleBinOperation::Restore => "Restore results",
                RecycleBinOperation::Purge => "Permanent purge results",
            };
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(verb).family(theme::semibold()));
                theme::muted(
                    ui,
                    format!(
                        "{} · {} item(s)",
                        completion_label(report.completion),
                        report.receipts.len()
                    ),
                    t,
                );
            });
            ui.add_space(6.);
            for receipt in &report.receipts {
                let name = self
                    .recycle_bin_ui
                    .last_labels
                    .get(&receipt.item_id)
                    .cloned()
                    .unwrap_or_else(|| "Selected item".into());
                ui.horizontal_wrapped(|ui| {
                    let state = item_state_label(receipt.state);
                    if matches!(
                        receipt.state,
                        ItemOperationState::Uncertain
                            | ItemOperationState::Unknown
                            | ItemOperationState::Denied
                            | ItemOperationState::Failed
                    ) {
                        ui.colored_label(t.attention, state);
                    } else {
                        theme::muted(ui, state, t);
                    }
                    ui.add(egui::Label::new(name).wrap());
                });
                if let Some(message) = receipt.message.as_deref() {
                    ui.add(egui::Label::new(message).wrap());
                }
                ui.separator();
            }
        });
    }

    fn recycle_bin_detail_dialog(&mut self, ctx: &egui::Context) {
        if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.recycle_bin_ui.detail_id = None;
            return;
        }
        let item = self
            .recycle_bin_ui
            .inventory
            .as_ref()
            .and_then(|inventory| {
                inventory
                    .items
                    .iter()
                    .find(|item| Some(item.id()) == self.recycle_bin_ui.detail_id)
                    .cloned()
            });
        let t = theme::tokens(self.prefs.dark);
        let width = (ctx.content_rect().width() - 32.).clamp(280., 560.);
        let height = (ctx.content_rect().height() - 90.).max(180.);
        let mut close = false;
        let response = egui::Modal::new(egui::Id::new("recycle-bin-item-details"))
            .frame(theme::dialog_frame(t))
            .show(ctx, |ui| {
                ui.set_width(width);
                ui.set_max_width(width);
                theme::scroll_vertical()
                    .max_height(height)
                    .show(ui, |ui| {
                        ui.heading("Recycle Bin item details");
                        ui.add_space(10.);
                        if let Some(item) = item.as_ref() {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(item.name()).family(theme::semibold()),
                                )
                                .wrap(),
                            );
                            ui.add_space(10.);
                            wrapped_detail(ui, "Original location", &item.original_parent().display().to_string());
                            wrapped_detail(ui, "Full original path", &item.original_path().display().to_string());
                            wrapped_detail(
                                ui,
                                "Deleted",
                                &deleted_date(item.deleted_at_unix_seconds()),
                            );
                            wrapped_detail(ui, "Size", &size_label(item.size()));
                            if !item.is_size_readable() {
                                ui.add_space(8.);
                                ui.colored_label(
                                    t.attention,
                                    "Metadata could not be read. This item cannot be selected for a reviewed operation.",
                                );
                            }
                        } else {
                            theme::muted(
                                ui,
                                "This item is no longer in the current inventory. Refresh before reviewing it.",
                                t,
                            );
                        }
                        ui.add_space(16.);
                        if theme::secondary(ui, "Close", true) {
                            close = true;
                        }
                    });
            });
        if response.should_close() || close {
            self.recycle_bin_ui.detail_id = None;
        }
    }

    fn recycle_bin_review_dialog(&mut self, ctx: &egui::Context) {
        if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.recycle_bin_ui.review_open = false;
            self.recycle_bin_ui.acknowledge_purge = false;
            return;
        }
        let selected = self.selected_items();
        if selected.is_empty() {
            self.recycle_bin_ui.review_open = false;
            self.recycle_bin_ui.acknowledge_purge = false;
            return;
        }
        let t = theme::tokens(self.prefs.dark);
        let width = (ctx.content_rect().width() - 32.).clamp(280., 560.);
        let height = (ctx.content_rect().height() - 90.).max(180.);
        let mut close = false;
        let mut start = None;
        let can_operate = !self.busy()
            && self.recycle_bin_ui.journal_readable
            && self
                .recycle_bin_ui
                .inventory
                .as_ref()
                .is_some_and(|inventory| inventory.completion == InventoryCompletion::Complete);
        let total_bytes = selected.iter().fold(0u64, |sum, item| {
            sum.saturating_add(match item.size() {
                Some(RecycleBinSize::Bytes(bytes)) => bytes,
                _ => 0,
            })
        });
        let response = egui::Modal::new(egui::Id::new("recycle-bin-reviewed-operation"))
            .frame(theme::dialog_frame(t))
            .show(ctx, |ui| {
                ui.set_width(width);
                ui.set_max_width(width);
                theme::scroll_vertical()
                    .max_height(height)
                    .show(ui, |ui| {
                        ui.heading("Review selected Recycle Bin items");
                        ui.add_space(8.);
                        ui.add(
                            egui::Label::new(format!(
                                "{} selected · {} known file bytes",
                                selected.len(),
                                format_bytes(total_bytes)
                            ))
                            .wrap(),
                        );
                        ui.add_space(8.);
                        theme::muted(
                            ui,
                            "Restore returns each item to its recorded original location. The operating system may refuse an item if its destination is occupied or unavailable.",
                            t,
                        );
                        ui.add_space(8.);
                        ui.colored_label(
                            t.attention,
                            "Permanent purge removes selected items through the operating-system recycle-bin API. It cannot be undone.",
                        );
                        ui.add_space(8.);
                        theme::checkbox(
                            ui,
                            &mut self.recycle_bin_ui.acknowledge_purge,
                            "I understand that permanent purge cannot be undone",
                            true,
                        );
                        ui.add_space(10.);
                        ui.label(RichText::new("Items in this review").family(theme::semibold()));
                        for item in selected.iter().take(12) {
                            ui.add(egui::Label::new(item.name()).wrap());
                        }
                        if selected.len() > 12 {
                            theme::muted(
                                ui,
                                format!("{} more selected items.", selected.len() - 12),
                                t,
                            );
                        }
                        if !self.recycle_bin_ui.journal_readable {
                            ui.add_space(8.);
                            ui.colored_label(
                                t.attention,
                                "Durable operation history is unavailable. No item action can start.",
                            );
                        }
                        ui.add_space(16.);
                        ui.horizontal_wrapped(|ui| {
                            if theme::secondary(ui, "Close", true) {
                                close = true;
                            }
                            if theme::primary(ui, "Restore selected", t, can_operate) {
                                start = Some(RecycleBinOperation::Restore);
                            }
                            if theme::secondary(
                                ui,
                                "Permanently purge",
                                can_operate && self.recycle_bin_ui.acknowledge_purge,
                            ) {
                                start = Some(RecycleBinOperation::Purge);
                            }
                        });
                    });
            });
        if response.should_close() && !self.busy() {
            close = true;
        }
        if close && start.is_none() {
            self.recycle_bin_ui.review_open = false;
            self.recycle_bin_ui.acknowledge_purge = false;
        }
        if let Some(operation) = start {
            self.begin_recycle_bin_operation(operation, ctx);
        }
    }

    fn begin_recycle_bin_inventory(&mut self, ctx: &egui::Context) {
        if self.qa_fixture_mode()
            || self.busy()
            || self.recycle_bin_ui.operation != RecycleBinOperationState::Idle
        {
            return;
        }
        self.recycle_bin_ui.operation = RecycleBinOperationState::Loading;
        self.recycle_bin_ui.loaded = false;
        self.recycle_bin_ui.selected_ids.clear();
        self.recycle_bin_ui.detail_id = None;
        self.recycle_bin_ui.review_open = false;
        self.recycle_bin_ui.acknowledge_purge = false;
        self.error = None;
        self.notice = None;
        self.progress = "Reading current-user Recycle Bin…".into();
        self.cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let data_dir = self.data_dir.clone();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let mut port = SystemRecycleBin::new();
            let inventory = recycle_bin::inventory(&mut port, &cancel, |done, total| {
                let _ = tx.send(Event::RecycleBin(RecycleBinEvent::InventoryProgress {
                    done,
                    total,
                }));
                ctx.request_repaint();
            });
            let history = if data_dir.as_os_str().is_empty() {
                Err("Application data storage is unavailable.".into())
            } else {
                effects::history(&data_dir, "recycle-bin")
            };
            let _ = tx.send(Event::RecycleBin(RecycleBinEvent::InventoryLoaded {
                inventory,
                history,
            }));
            ctx.request_repaint();
        });
    }

    fn begin_recycle_bin_operation(&mut self, operation: RecycleBinOperation, ctx: &egui::Context) {
        if self.qa_fixture_mode()
            || self.busy()
            || self.recycle_bin_ui.operation != RecycleBinOperationState::Idle
            || !self.recycle_bin_ui.journal_readable
            || self.data_dir.as_os_str().is_empty()
        {
            return;
        }
        if operation == RecycleBinOperation::Purge && !self.recycle_bin_ui.acknowledge_purge {
            return;
        }
        let Some(inventory) = self.recycle_bin_ui.inventory.as_ref() else {
            self.recycle_bin_ui.review_open = false;
            return;
        };
        if inventory.completion != InventoryCompletion::Complete {
            self.error =
                Some("A complete inventory is required before restoring or purging items.".into());
            self.recycle_bin_ui.review_open = false;
            return;
        }
        let ids = self
            .recycle_bin_ui
            .selected_ids
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let selection = match recycle_bin::reviewed_selection(inventory, &ids) {
            Ok(selection) => selection,
            Err(error) => {
                self.error = Some(error);
                self.recycle_bin_ui.review_open = false;
                return;
            }
        };
        if inventory.items.iter().any(|item| {
            self.recycle_bin_ui.selected_ids.contains(&item.id()) && !item.is_size_readable()
        }) {
            self.error = Some(
                "Items with unreadable metadata cannot be included in a reviewed operation.".into(),
            );
            self.recycle_bin_ui.review_open = false;
            return;
        }
        let labels = inventory
            .items
            .iter()
            .filter(|item| self.recycle_bin_ui.selected_ids.contains(&item.id()))
            .map(|item| (item.id(), item.name()))
            .collect::<HashMap<_, _>>();
        let data_dir = self.data_dir.clone();
        self.recycle_bin_ui.operation = match operation {
            RecycleBinOperation::Restore => RecycleBinOperationState::Restoring,
            RecycleBinOperation::Purge => RecycleBinOperationState::Purging,
        };
        self.recycle_bin_ui.review_open = false;
        self.recycle_bin_ui.acknowledge_purge = false;
        self.error = None;
        self.notice = None;
        self.progress = match operation {
            RecycleBinOperation::Restore => "Preparing reviewed restore…".into(),
            RecycleBinOperation::Purge => "Preparing reviewed permanent purge…".into(),
        };
        self.cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let mut port = SystemRecycleBin::new();
            let progress_operation = operation;
            let progress_tx = tx.clone();
            let progress_ctx = ctx.clone();
            let progress = move |done, total| {
                let _ = progress_tx.send(Event::RecycleBin(RecycleBinEvent::OperationProgress {
                    operation: progress_operation,
                    done,
                    total,
                }));
                progress_ctx.request_repaint();
            };
            let report = match operation {
                RecycleBinOperation::Restore => recycle_bin::restore_selected(
                    &data_dir, &selection, &mut port, &cancel, progress,
                ),
                RecycleBinOperation::Purge => {
                    recycle_bin::purge_selected(&data_dir, &selection, &mut port, &cancel, progress)
                }
            };
            let refresh_cancel = std::sync::atomic::AtomicBool::new(false);
            let inventory = recycle_bin::inventory(&mut port, &refresh_cancel, |_, _| {});
            let history = effects::history(&data_dir, "recycle-bin");
            let _ = tx.send(Event::RecycleBin(RecycleBinEvent::OperationFinished {
                report,
                labels,
                inventory,
                history,
            }));
            ctx.request_repaint();
        });
    }

    fn update_recycle_bin_history(&mut self, result: Result<Vec<EffectHistory>, String>) {
        match result {
            Ok(history) => {
                self.recycle_bin_ui.history = history;
                self.recycle_bin_ui.journal_readable = true;
                self.recycle_bin_ui.journal_error = None;
            }
            Err(error) => {
                self.recycle_bin_ui.history.clear();
                self.recycle_bin_ui.journal_readable = false;
                self.recycle_bin_ui.journal_error = Some(error);
            }
        }
    }

    fn selected_items(&self) -> Vec<RecycleBinItem> {
        let Some(inventory) = self.recycle_bin_ui.inventory.as_ref() else {
            return Vec::new();
        };
        inventory
            .items
            .iter()
            .filter(|item| self.recycle_bin_ui.selected_ids.contains(&item.id()))
            .cloned()
            .collect()
    }

    fn selected_known_bytes(&self) -> u64 {
        self.selected_items().iter().fold(0u64, |sum, item| {
            sum.saturating_add(match item.size() {
                Some(RecycleBinSize::Bytes(bytes)) => bytes,
                _ => 0,
            })
        })
    }
}

fn filter_label(filter: ItemFilter) -> &'static str {
    match filter {
        ItemFilter::All => "All items",
        ItemFilter::Files => "Files",
        ItemFilter::Folders => "Folders",
        ItemFilter::Unknown => "Unknown size",
    }
}

fn filter_matches(filter: ItemFilter, item: &RecycleBinItem) -> bool {
    match filter {
        ItemFilter::All => true,
        ItemFilter::Files => matches!(item.size(), Some(RecycleBinSize::Bytes(_))),
        ItemFilter::Folders => matches!(item.size(), Some(RecycleBinSize::Entries(_))),
        ItemFilter::Unknown => item.size().is_none(),
    }
}

fn item_matches_query(item: &RecycleBinItem, query: &str) -> bool {
    query.is_empty()
        || item.name().to_ascii_lowercase().contains(query)
        || item
            .original_parent()
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains(query)
        || item.id().to_string().contains(query)
}

fn size_label(size: Option<RecycleBinSize>) -> String {
    match size {
        Some(RecycleBinSize::Bytes(bytes)) => format_bytes(bytes),
        Some(RecycleBinSize::Entries(entries)) => format!("{entries} entries"),
        None => "Unknown".into(),
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024. && unit < UNITS.len() - 1 {
        value /= 1024.;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn deleted_date(timestamp: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, 0)
        .map(|date| {
            date.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|| "Unknown".into())
}

fn wrapped_detail(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.vertical(|ui| {
        ui.label(RichText::new(label).family(theme::semibold()));
        ui.add(egui::Label::new(value.to_owned()).wrap());
    });
    ui.add_space(8.);
}

fn completion_label(completion: OperationCompletion) -> &'static str {
    match completion {
        OperationCompletion::Complete => "Complete",
        OperationCompletion::Partial => "Partial",
        OperationCompletion::Cancelled => "Stopped",
    }
}

fn item_state_label(state: ItemOperationState) -> &'static str {
    match state {
        ItemOperationState::Restored => "Restored",
        ItemOperationState::Purged => "Permanently purged",
        ItemOperationState::Missing => "No longer present",
        ItemOperationState::Changed => "Changed since inventory",
        ItemOperationState::Denied => "Permission denied",
        ItemOperationState::Unknown => "Outcome unknown",
        ItemOperationState::Failed => "Failed",
        ItemOperationState::Uncertain => "Uncertain outcome",
        ItemOperationState::Cancelled => "Stopped before action",
        ItemOperationState::NotAttempted => "Not attempted",
    }
}

fn history_state_label(state: &str) -> &str {
    match state {
        "restored" => "Restored",
        "applied" => "Purged",
        "failed" => "Failed",
        "uncertain" => "Uncertain · review required",
        "completed" | "verified" => "Completed",
        other => other,
    }
}

fn operation_label(operation: &str) -> &str {
    match operation {
        "restore" => "restore",
        "purge" => "permanent purge",
        other => other,
    }
}

fn short_uuid(value: &str) -> &str {
    value.get(..8).unwrap_or(value)
}

#[cfg(debug_assertions)]
struct RecycleBinPreviewPort {
    items: Vec<recycle_bin::PortItem>,
    sizes: VecDeque<RecycleBinSize>,
    fail_list: bool,
}

#[cfg(debug_assertions)]
impl recycle_bin::RecycleBinPort for RecycleBinPreviewPort {
    fn list(&mut self) -> Result<Vec<recycle_bin::PortItem>, recycle_bin::PortError> {
        if self.fail_list {
            return Err(recycle_bin::PortError::unavailable(
                "Synthetic fixture error: recycle-bin inventory was unavailable.",
            ));
        }
        Ok(self.items.clone())
    }

    fn metadata(
        &mut self,
        _item: &recycle_bin::PortItem,
    ) -> Result<RecycleBinSize, recycle_bin::PortError> {
        self.sizes.pop_front().ok_or_else(|| {
            recycle_bin::PortError::failed("Synthetic fixture metadata was not seeded.")
        })
    }

    fn restore_one(&mut self, _item: &recycle_bin::PortItem) -> Result<(), recycle_bin::PortError> {
        Err(recycle_bin::PortError::unsupported(
            "Visual fixtures never restore items.",
        ))
    }

    fn purge_one(&mut self, _item: &recycle_bin::PortItem) -> Result<(), recycle_bin::PortError> {
        Err(recycle_bin::PortError::unsupported(
            "Visual fixtures never purge items.",
        ))
    }
}

#[cfg(debug_assertions)]
fn build_recycle_bin_preview_inventory(fail_list: bool, populated: bool) -> RecycleBinInventory {
    let items = if populated {
        vec![
            recycle_bin::PortItem::new(
                b"fixture-item-1".to_vec(),
                OsString::from("meeting-notes.txt"),
                PathBuf::from(r"C:\Fixture\Documents"),
                1_790_000_000,
            ),
            recycle_bin::PortItem::new(
                b"fixture-item-2".to_vec(),
                OsString::from("render-cache.bin"),
                PathBuf::from(r"C:\Fixture\Projects"),
                1_789_000_000,
            ),
            recycle_bin::PortItem::new(
                b"fixture-item-3".to_vec(),
                OsString::from("archive-folder"),
                PathBuf::from(r"C:\Fixture\Backups"),
                1_788_000_000,
            ),
        ]
    } else {
        Vec::new()
    };
    let sizes = if populated {
        VecDeque::from([
            RecycleBinSize::Bytes(2_048),
            RecycleBinSize::Bytes(0),
            RecycleBinSize::Entries(3),
        ])
    } else {
        VecDeque::new()
    };
    let mut port = RecycleBinPreviewPort {
        items,
        sizes,
        fail_list,
    };
    recycle_bin::inventory(
        &mut port,
        &std::sync::atomic::AtomicBool::new(false),
        |_, _| {},
    )
}
