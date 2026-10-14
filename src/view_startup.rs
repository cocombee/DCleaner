use super::*;
use crate::theme;
use dcleaner::{
    effects::{self, EffectHistory, EffectJournal},
    startup::{
        CHANGE_SCHEMA_VERSION, ChangeIntent, ChangeOutcome, ChangeReceipt, EnabledState,
        EntryIdentity, FieldValue, InventoryQuality, NativeState, ObservedState, SourceState,
        StartupEntry, StartupId, StartupInventory, StartupManager, StartupPlatform, StartupSection,
        WindowsStartupPlatform,
    },
};
use std::{collections::HashMap, path::Path};

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortColumn {
    Program,
    Publisher,
    FilePath,
    Identity,
    Enabled,
}

impl SortColumn {
    const ALL: [Self; 5] = [
        Self::Program,
        Self::Publisher,
        Self::FilePath,
        Self::Identity,
        Self::Enabled,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Program => "Program",
            Self::Publisher => "Publisher",
            Self::FilePath => "File path",
            Self::Identity => "Native identity",
            Self::Enabled => "State",
        }
    }
}

pub(super) struct StartupUi {
    section: StartupSection,
    inventories: HashMap<StartupSection, StartupInventory>,
    loaded: bool,
    history: Vec<EffectHistory>,
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
}

impl Default for StartupUi {
    fn default() -> Self {
        Self {
            section: StartupSection::StartupApps,
            inventories: HashMap::new(),
            loaded: false,
            history: Vec::new(),
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
        }
    }
}

pub(super) enum StartupEvent {
    Loaded {
        inventories: Vec<StartupInventory>,
        history: Result<Vec<EffectHistory>, String>,
    },
    Prepared {
        id: StartupId,
        target_enabled: bool,
        result: Result<ChangeIntent, String>,
    },
    Changed(Result<ChangeReceipt, String>),
}

#[derive(Clone)]
enum ReviewAction {
    Apply(ChangeIntent),
    Restore(ChangeReceipt),
    RecoverIntent(ChangeIntent),
    RecoverReceipt(ChangeReceipt),
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
                    .map(|inventory| (inventory.section, inventory))
                    .collect();
                ui.loaded = true;
                ui.last_refresh = Some(std::time::Instant::now());
                match history {
                    Ok(history) => {
                        ui.history = history;
                        ui.history_error = None;
                        if ui
                            .selected_history
                            .is_some_and(|id| !ui.history.iter().any(|record| record.id == id))
                        {
                            ui.selected_history = None;
                        }
                    }
                    Err(error) => {
                        ui.history.clear();
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
                        self.notice = Some(match receipt.outcome {
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
        }
    }

    pub(super) fn startup_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if !self.startup_ui.loaded && !self.busy() {
            self.begin_startup_load(ctx);
        }

        self.startup_tabs(ui);
        ui.add_space(8.);

        let inventory = self
            .startup_ui
            .inventories
            .get(&self.startup_ui.section)
            .cloned();
        self.startup_search_and_sort(ui);
        ui.add_space(6.);

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

    pub(super) fn startup_refresh_external_state(&mut self, ctx: &egui::Context) {
        if let Some(receiver) = self.startup_ui.background_read.take() {
            match receiver.try_recv() {
                Ok(inventory) => {
                    self.startup_ui
                        .inventories
                        .insert(inventory.section, inventory);
                    self.startup_ui.last_refresh = Some(std::time::Instant::now());
                }
                Err(mpsc::TryRecvError::Empty) => self.startup_ui.background_read = Some(receiver),
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.startup_ui.last_refresh = Some(std::time::Instant::now());
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
        let selected_entry = self.selected_entry().cloned();
        let selected_history = self
            .startup_ui
            .selected_history
            .and_then(|id| {
                self.startup_ui
                    .history
                    .iter()
                    .find(|record| record.id == id)
            })
            .cloned();
        let history_action = selected_history
            .as_ref()
            .and_then(|record| history_review_action(record, &self.startup_ui.history));
        let section = self.startup_ui.section;
        let inventory_summary = self
            .startup_ui
            .inventories
            .get(&section)
            .map(|inventory| {
                format!(
                    "{} · {} entries · {:?}",
                    section.label(),
                    inventory.entries.len(),
                    inventory.quality
                )
            })
            .unwrap_or_else(|| format!("{} · not loaded", section.label()));
        let mut should_refresh = false;
        let mut should_export = false;
        let mut prepare_change = None;
        let mut open_history_review = false;
        let mut open_location = None;

        ui.horizontal_wrapped(|ui| {
            theme::muted(ui, inventory_summary, t);
            ui.separator();
            if theme::secondary(ui, "Refresh", !busy) {
                should_refresh = true;
            }
            if theme::secondary(ui, "Export JSON", !busy && self.startup_ui.loaded) {
                should_export = true;
            }
            if let Some(entry) = &selected_entry {
                if let FieldValue::Known { value } = &entry.file_path {
                    if theme::secondary(ui, "Open file location", !busy) {
                        open_location = Some(value.clone());
                    }
                }
                if entry.can_change_enabled {
                    let target = !matches!(&entry.enabled, EnabledState::Enabled);
                    let label = if target { "Enable" } else { "Disable" };
                    if theme::primary(ui, label, t, !busy) {
                        prepare_change = Some((entry.id.clone(), target));
                    }
                } else if let Some(limitation) = &entry.change_limitation {
                    ui.add_enabled(false, egui::Button::new("Read only"))
                        .on_hover_text(limitation);
                }
            }
            if history_action.is_some()
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
        if let Some(path) = open_location {
            match open_in_explorer(&path) {
                Ok(()) => self.notice = Some("The file location was opened in Explorer.".into()),
                Err(error) => {
                    self.error = Some(format!("The file location could not be opened: {error}"))
                }
            }
        }
        if let Some((id, target)) = prepare_change {
            self.begin_startup_prepare(id, target, ctx);
        }
        if open_history_review {
            self.startup_ui.review = history_action;
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
                    egui::ScrollArea::vertical()
                        .max_height((ctx.content_rect().height() - 190.).clamp(140., 520.))
                        .show(ui, |ui| self.entry_details(ui, t));
                    ui.add_space(12.);
                    close = theme::secondary(ui, "Close", true);
                });
            if close || modal.should_close() {
                self.startup_ui.details_open = false;
            }
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
            egui::ScrollArea::vertical()
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
                    if action.is_recovery() {
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
            ui.add_space(14.);
            ui.horizontal(|ui| {
                if theme::secondary(ui, "Cancel", true) {
                    cancel = true;
                }
                if theme::primary(ui, action.label(), t, !self.busy()) {
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
            self.begin_startup_action(action, ctx);
        }
    }

    fn begin_startup_load(&mut self, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        self.startup_ui.background_read = None;
        self.progress = "Reading native startup inventories and operation history…".into();
        self.cancel = Arc::new(AtomicBool::new(false));
        let root = self.data_dir.clone();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let mut platform = WindowsStartupPlatform::new();
            let inventories = StartupSection::ALL
                .into_iter()
                .map(|section| platform.inventory(section))
                .collect();
            let history = effects::history(&root, "startup");
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
        self.startup_ui.background_read = None;
        self.error = None;
        self.startup_ui.review = None;
        self.startup_ui.selected = Some(id.clone());
        self.progress = "Re-reading the selected native item for review…".into();
        self.cancel = Arc::new(AtomicBool::new(false));
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
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

    fn begin_startup_action(&mut self, action: ReviewAction, ctx: &egui::Context) {
        if self.busy() {
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
        let (tx, rx) = mpsc::channel();
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
        ui.horizontal_wrapped(|ui| {
            for section in StartupSection::ALL {
                if ui
                    .selectable_label(self.startup_ui.section == section, section.label())
                    .clicked()
                {
                    self.startup_ui.section = section;
                    self.startup_ui.selected = None;
                }
            }
        });
    }

    fn startup_search_and_sort(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Search").family(theme::semibold()))
                .on_hover_text("Search uses only details Windows returned.");
            ui.add(
                egui::TextEdit::singleline(&mut self.startup_ui.query)
                    .hint_text("Name, publisher, path, command or identity")
                    .desired_width(300.),
            );
            ui.label("Sort by");
            egui::ComboBox::from_id_salt("startup-sort")
                .selected_text(self.startup_ui.sort.label())
                .show_ui(ui, |ui| {
                    for sort in SortColumn::ALL {
                        ui.selectable_value(&mut self.startup_ui.sort, sort, sort.label());
                    }
                });
            ui.checkbox(&mut self.startup_ui.descending, "Descending");
            if !self.startup_ui.query.is_empty()
                && ui
                    .small_button("Clear")
                    .on_hover_text("Clear search")
                    .clicked()
            {
                self.startup_ui.query.clear();
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
        egui::CollapsingHeader::new("Inventory sources and access")
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
            .cloned()
            .collect::<Vec<_>>();
        let sort = self.startup_ui.sort;
        entries.sort_by(|left, right| {
            let order = sort_key(left, sort).cmp(&sort_key(right, sort));
            if self.startup_ui.descending {
                order.reverse()
            } else {
                order
            }
        });

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
        let busy = self.busy();
        egui::Frame::NONE.show(ui, |ui| {
            ui.set_width(ui.available_width());
            let available = ui.available_width().max(320.);
            let show_publisher = available >= 800.;
            let show_path = available >= 900.;
            let action_width = if available >= 700. {
                130.
            } else if available >= 520. {
                116.
            } else {
                106.
            };
            let state_width = if available >= 700. {
                96.
            } else if available >= 520. {
                82.
            } else {
                72.
            };
            let publisher_width = if show_publisher { 120. } else { 0. };
            let path_width = if show_path { 200. } else { 0. };
            let columns = 3 + (show_publisher as usize) + (show_path as usize);
            let column_spacing = ui.spacing().item_spacing.x * (columns.saturating_sub(1) as f32);
            let program_min_width = if available >= 700. { 180. } else { 140. };
            let program_width = (available
                - action_width
                - state_width
                - publisher_width
                - path_width
                - column_spacing
                - 8.)
                .max(program_min_width);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.;
                table_header(ui, program_width, "Program");
                if show_publisher { table_header(ui, publisher_width, "Publisher"); }
                if show_path { table_header(ui, path_width, "File path"); }
                table_header(ui, state_width, "State");
                table_header(ui, action_width, "Actions");
            });
            ui.separator();
            let body_height = (ui.ctx().content_rect().bottom() - ui.cursor().top() - 74. - 28. - 80.).max(120.);
            egui::ScrollArea::vertical().id_salt(("startup-table-body", inventory.section.label()))
                .max_height(body_height).auto_shrink([false, false]).show(ui, |ui| {
                egui::Grid::new(("startup-inventory-grid", inventory.section.label()))
                .num_columns(columns)
                .striped(false)
                .min_row_height(44.)
                .spacing([8., 0.])
                .min_col_width(0.)
                .show(ui, |ui| {
                    for entry in entries {
                        let selected = self.startup_ui.selected.as_ref() == Some(&entry.id);
                        let program = field_text(&entry.program);
                        let response = ui.allocate_ui_with_layout([program_width, 36.].into(), Layout::left_to_right(Align::Center), |ui| {
                            ui.set_min_width(program_width);
                            ui.set_max_width(program_width);
                            ui.spacing_mut().item_spacing.x = 8.;
                            let resource = match &entry.file_path { FieldValue::Known { value } => Some(value.as_str()), _ => None };
                            self.app_icons.show(ui, resource, 22.);
                            ui.spacing_mut().button_padding = Vec2::ZERO;
                            ui.add_sized(
                            [(program_width - 30.).max(40.), 36.],
                            egui::Button::new((
                                RichText::new(program.clone()).family(theme::semibold()),
                                egui::Atom::grow(),
                            ))
                            .selected(selected)
                            .frame_when_inactive(selected)
                            .frame(false)
                            .truncate(),
                        )}).inner;
                        if response.clicked() {
                            self.startup_ui.selected = Some(entry.id.clone());
                        }
                        response.on_hover_text(&program);

                        if show_publisher {
                            field_cell(ui, publisher_width, &entry.publisher);
                        }
                        if show_path {
                            field_cell(ui, path_width, &entry.file_path);
                        }

                        let identity = identity_summary(&entry.identity);
                        let state = enabled_label(&entry.enabled);
                        theme::table_cell(ui, state.clone(), state_width, 36.)
                        .on_hover_text(enabled_tooltip(&entry.enabled));
                        ui.allocate_ui_with_layout([action_width, 36.].into(), Layout::left_to_right(Align::Center), |ui| {
                            ui.set_min_size([action_width, 36.].into());
                            ui.spacing_mut().item_spacing.x = 4.;
                            if entry.can_change_enabled {
                                let target = matches!(&entry.enabled, EnabledState::Disabled);
                                let label = if target { "Enable" } else { "Disable" };
                                if theme::row_action(ui, label, !busy)
                                    .on_hover_text(
                                        "Review the exact native identity and current state before applying.",
                                    )
                                    .clicked()
                                {
                                    prepare_change = Some((entry.id.clone(), target));
                                }
                            } else {
                                let reason = entry
                                    .change_limitation
                                    .as_deref()
                                    .or_else(|| match &entry.enabled {
                                        EnabledState::Unknown { reason } => Some(reason),
                                        _ => None,
                                    })
                                    .unwrap_or(
                                        "This item has no supported reversible change path.",
                                    );
                                theme::row_action(ui, "Read only", false)
                                .on_hover_text(reason);
                            }
                            let more = theme::row_more(ui, !busy);
                            egui::Popup::menu(&more).show(|ui| {
                                if ui.button("Show details").clicked() {
                                    detail_selection = Some(entry.id.clone());
                                }
                                if let FieldValue::Known { value } = &entry.file_path {
                                    if !value.is_empty()
                                        && ui.button("Open file location").clicked()
                                    {
                                        open_location = Some(value.clone());
                                    }
                                }
                                if ui.button("Copy native identity").clicked() {
                                    ui.ctx().copy_text(identity.clone());
                                }
                            });
                        });
                        ui.end_row();
                        let y = ui.cursor().min.y;
                        ui.painter().hline(ui.max_rect().left()..=ui.max_rect().right(), y, egui::Stroke::new(1., t.border));
                    }
                });
            });
        });
        if let Some(id) = detail_selection {
            self.startup_ui.selected = Some(id);
            self.startup_ui.details_open = true;
        }
        if let Some(path) = open_location {
            match open_in_explorer(&path) {
                Ok(()) => self.notice = Some("The file location was opened in Explorer.".into()),
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
        let history = self.startup_ui.history.clone();
        egui::CollapsingHeader::new("Change history and recovery")
            .id_salt("startup-effect-history")
            .default_open(history.iter().any(|record| record.state == "uncertain"))
            .show(ui, |ui| {
                if let Some(error) = history_error {
                    theme::muted(
                        ui,
                        format!("Native operation history is unavailable: {error}"),
                        t,
                    );
                } else if history.is_empty() {
                    theme::muted(ui, "No startup changes have been recorded.", t);
                }
                for record in &history {
                    let action = history_review_action(record, &history);
                    let summary = history_record_summary(record);
                    let label = format!(
                        "{} · {} · {}",
                        record.date,
                        history_state_label(record),
                        summary
                    );
                    if ui
                        .selectable_label(
                            self.startup_ui.selected_history == Some(record.id),
                            egui::RichText::new(label).size(12.),
                        )
                        .on_hover_text(if record.state == "uncertain" {
                            "Outcome not confirmed. Review the typed saved intent before attempting guarded recovery."
                        } else {
                            "Select this record to inspect a safe restore or recovery action."
                        })
                        .clicked()
                    {
                        self.startup_ui.selected_history = Some(record.id);
                    }
                    if record.state == "uncertain" {
                        theme::muted(
                            ui,
                            if action.is_some() {
                                "Pending / uncertain. No action was replayed automatically; choose Review recovery in the footer."
                            } else {
                                "Pending / uncertain. The saved payload is not a supported startup intent, so no recovery action is offered."
                            },
                            t,
                        );
                    } else if record.state == "applied" && action.is_none() {
                        theme::muted(ui, "This change is already restored or has no safe receipt.", t);
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
        let mut inventories = StartupSection::ALL
            .into_iter()
            .filter_map(|section| self.startup_ui.inventories.get(&section).cloned())
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
            Ok(()) => self.notice = Some("Startup inventory exported.".into()),
            Err(error) => {
                self.error = Some(format!("Startup inventory could not be exported: {error}"))
            }
        }
    }
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
    intent.schema_version == CHANGE_SCHEMA_VERSION
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
    receipt.schema_version == CHANGE_SCHEMA_VERSION
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

fn history_record_summary(record: &EffectHistory) -> String {
    if let Ok(intent) = serde_json::from_value::<ChangeIntent>(record.intent.clone()) {
        format!(
            "{} · {} → {}",
            identity_summary(&intent.before.identity),
            enabled_label(&intent.before.enabled),
            enabled_label(&intent.expected_after.enabled)
        )
    } else if let Ok(receipt) = serde_json::from_value::<ChangeReceipt>(record.intent.clone()) {
        format!(
            "{} · {} → {}",
            identity_summary(&receipt.before.identity),
            enabled_label(&receipt.before.enabled),
            enabled_label(&receipt.after.enabled)
        )
    } else {
        "Unsupported saved payload · no action available".into()
    }
}

fn history_state_label(record: &EffectHistory) -> &'static str {
    match record.state.as_str() {
        "applied" => "Applied · verified",
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
        SortColumn::Identity => identity_summary(&entry.identity),
        SortColumn::Enabled => enabled_label(&entry.enabled),
    }
    .to_lowercase()
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
    let response = theme::table_cell(ui, field_text(field), width, 36.);
    if let Some(reason) = field_reason(field) {
        response.on_hover_text(reason);
    } else if let FieldValue::Known { value } = field {
        response.on_hover_text(value);
    }
}

fn table_header(ui: &mut egui::Ui, width: f32, label: &str) {
    theme::table_cell(
        ui,
        RichText::new(label)
            .size(12.)
            .color(ui.visuals().weak_text_color()),
        width,
        24.,
    );
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

fn enabled_tooltip(state: &EnabledState) -> String {
    match state {
        EnabledState::Unknown { reason } => reason.clone(),
        _ => enabled_label(state),
    }
}

fn identity_summary(identity: &EntryIdentity) -> String {
    match identity {
        EntryIdentity::StartupRunValue {
            hive,
            key,
            value_name,
            ..
        } => format!("{}\\{} · {}", hive_label(*hive), key, value_name),
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
    ui.add(egui::Label::new(RichText::new(value).size(12.)).wrap());
    ui.add_space(8.);
}

#[cfg(test)]
mod tests {
    use super::*;

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
