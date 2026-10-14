use super::*;
use dcleaner::programs::{
    self, InstalledProgram, InventorySnapshot, ProgramIdentity, RegistryHive, RegistrySource,
    RegistryView, UninstallHandoffReceipt, UninstallRequest,
};
use serde::Serialize;

#[derive(Default)]
pub(super) struct ProgramsUi {
    inventory: Option<InventorySnapshot>,
    initial_load_attempted: bool,
    load_error: Option<String>,
    loading: bool,
    search: String,
    tab: ProgramTab,
    sort: ProgramSort,
    descending: bool,
    selected: Option<ProgramIdentity>,
    dialog: Option<ProgramsDialog>,
    journal: Vec<dcleaner::effects::EffectHistory>,
    journal_loaded: bool,
    journal_error: Option<String>,
    waiting_for_uninstaller_return: bool,
    saw_focus_loss: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ProgramTab {
    #[default]
    Installed,
    Disabled,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ProgramSort {
    #[default]
    Name,
    Publisher,
    Version,
    InstallDate,
    Size,
}

impl ProgramSort {
    const ALL: [Self; 5] = [
        Self::Name,
        Self::Publisher,
        Self::Version,
        Self::InstallDate,
        Self::Size,
    ];
}

#[derive(Clone, Debug)]
enum ProgramsDialog {
    Details(ProgramIdentity),
    UninstallReview(UninstallRequest),
}

pub(super) enum ProgramsEvent {
    Inventory(Result<InventorySnapshot, String>),
    UninstallHandoff {
        request_id: Uuid,
        target_name: String,
        journal_created: bool,
        result: Result<UninstallHandoffReceipt, String>,
        journal_error: Option<String>,
    },
}

#[derive(Serialize)]
struct HandoffFailureReceipt<'a> {
    request_id: Uuid,
    error: &'a str,
}

impl App {
    pub(super) fn programs_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if !self.program_ui.initial_load_attempted && !self.busy() {
            self.begin_program_inventory(ctx);
        }
        self.load_program_journal();
        self.refresh_program_inventory_after_return(ctx);

        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            theme::tabs(ui, |ui| {
                theme::tab_value(
                    ui,
                    &mut self.program_ui.tab,
                    ProgramTab::Installed,
                    "Installed",
                );
                theme::tab_value(
                    ui,
                    &mut self.program_ui.tab,
                    ProgramTab::Disabled,
                    "Disabled  ·  unavailable",
                );
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                theme::muted(
                    ui,
                    self.program_ui
                        .inventory
                        .as_ref()
                        .map(|inventory| format!("{} installed", inventory.programs.len()))
                        .unwrap_or_else(|| "Inventory not loaded".into()),
                    t,
                );
            });
        });
        ui.add_space(6.);
        ui.separator();
        ui.add_space(6.);
        if self.program_ui.tab == ProgramTab::Disabled {
            unavailable_card(
                ui,
                t,
                "Disabled programs are not available",
                "This version has no reversible disable/enable implementation. No entries are presented as disabled.",
            );
        } else {
            self.program_inventory_panel(ui, t, ctx);
        }

        ui.add_space(14.);
        self.program_operation_history(ui, t);
        ui.add_space(12.);
        egui::CollapsingHeader::new("Feature availability")
            .default_open(false)
            .id_salt("program-feature-availability")
            .show(ui, |ui| {
                theme::muted(
                    ui,
                    "Installed-program inventory and registered uninstall handoff are available on Windows. Temporary disable/enable, uninstall simulation, and automatic cleanup after 30, 90, or 120 days are not available.",
                    t,
                );
            });
    }

    pub(super) fn programs_footer(&mut self, ui: &mut egui::Ui, _t: Tokens, ctx: &egui::Context) {
        ui.horizontal_wrapped(|ui| {
            let selected = self.selected_program().cloned();
            let selected_name = selected
                .as_ref()
                .map(|program| program.display_name.as_str())
                .unwrap_or("No program selected");
            ui.add_sized(
                [220., 22.],
                egui::Label::new(RichText::new(selected_name).family(theme::semibold())).truncate(),
            );
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                let remove_enabled = !self.busy()
                    && selected
                        .as_ref()
                        .is_some_and(InstalledProgram::can_uninstall);
                if theme::secondary(ui, "Review uninstall…", remove_enabled) {
                    self.open_program_uninstall_review();
                }
                if theme::secondary(ui, "Details", selected.is_some()) {
                    if let Some(program) = selected.as_ref() {
                        self.program_ui.dialog =
                            Some(ProgramsDialog::Details(program.identity.clone()));
                    }
                }
                if theme::secondary(ui, "Refresh", !self.busy()) {
                    self.begin_program_inventory(ctx);
                }
            });
        });
    }

    pub(super) fn programs_dialog(&mut self, ctx: &egui::Context) {
        if self.program_ui.dialog.is_some()
            && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            let can_dismiss = matches!(
                self.program_ui.dialog.as_ref(),
                Some(ProgramsDialog::Details(_))
            ) || !self.busy();
            if can_dismiss {
                self.program_ui.dialog = None;
            }
            return;
        }
        let Some(dialog) = self.program_ui.dialog.clone() else {
            return;
        };
        let t = theme::tokens(self.prefs.dark);
        let mut close = false;
        let mut start_handoff: Option<UninstallRequest> = None;
        let modal_width = (ctx.content_rect().width() - 32.).min(560.).max(280.);
        let body_height = dialog_body_max_height(ctx);
        let can_dismiss = matches!(&dialog, ProgramsDialog::Details(_)) || !self.busy();
        let heading = match &dialog {
            ProgramsDialog::Details(_) => "Installed program details",
            ProgramsDialog::UninstallReview(_) => "Review native uninstall handoff",
        };
        let response = egui::Modal::new(egui::Id::new("programs-dialog"))
            .frame(theme::dialog_frame(t))
            .show(ctx, |ui| {
                ui.set_width(modal_width);
                ui.heading(heading);
                ui.add_space(8.);
                egui::ScrollArea::vertical()
                    .max_height(body_height)
                    .auto_shrink([false, true])
                    .show(ui, |body| match &dialog {
                        ProgramsDialog::Details(identity) => {
                            if let Some(program) = self.program_by_identity(identity).cloned() {
                                body.add(
                                    egui::Label::new(
                                        RichText::new(&program.display_name)
                                            .family(theme::semibold()),
                                    )
                                    .wrap(),
                                );
                                body.add_space(12.);
                                detail_row(body, "Publisher", optional(&program.publisher), t);
                                detail_row(body, "Version", optional(&program.version), t);
                                detail_row(
                                    body,
                                    "Install location",
                                    program
                                        .install_location
                                        .as_ref()
                                        .map(|path| path.display().to_string())
                                        .unwrap_or_else(|| "Not registered".into()),
                                    t,
                                );
                                detail_row(
                                    body,
                                    "Install date",
                                    program
                                        .install_date
                                        .as_deref()
                                        .map(format_install_date)
                                        .unwrap_or_else(|| "Not registered".into()),
                                    t,
                                );
                                detail_row(
                                    body,
                                    "Estimated size",
                                    program
                                        .estimated_size_bytes
                                        .map(format_size)
                                        .unwrap_or_else(|| "Not registered".into()),
                                    t,
                                );
                                detail_row(body, "Registration", source_label(program.source), t);
                                detail_row(body, "Stable identity", program.identity.stable_id(), t);
                                body.add_space(10.);
                                body.label(
                                    RichText::new("Registered uninstall command (preview only)")
                                        .family(theme::semibold()),
                                );
                                body.add_space(6.);
                                command_preview(body, &program, t);
                                if !program.removal_block_reasons().is_empty() {
                                    body.add_space(8.);
                                    for reason in program.removal_block_reasons() {
                                        body.colored_label(t.attention, reason.to_string());
                                    }
                                }
                            } else {
                                theme::muted(
                                    body,
                                    "This program is no longer in inventory. Refresh before reviewing it.",
                                    t,
                                );
                            }
                        }
                        ProgramsDialog::UninstallReview(request) => {
                            if let Some(program) =
                                self.program_by_identity(&request.identity).cloned()
                            {
                                body.add(
                                    egui::Label::new(
                                        RichText::new(format!(
                                            "Start the registered uninstaller for {}?",
                                            program.display_name
                                        ))
                                        .family(theme::semibold()),
                                    )
                                    .wrap(),
                                );
                                body.add_space(10.);
                                theme::muted(body, "DCleaner will re-read this exact registration and verify its identity, protection flags, and command before launching it directly. The command is preview data here; it has not run.", t);
                                body.add_space(12.);
                                detail_row(body, "Registration", source_label(request.source), t);
                                detail_row(body, "Stable identity", request.identity.stable_id(), t);
                                body.add_space(6.);
                                body.label(
                                    RichText::new("Exact registered command")
                                        .family(theme::semibold()),
                                );
                                body.add_space(5.);
                                if let Some(command) = program.uninstall_command.as_ref() {
                                    body.add(
                                        egui::Label::new(
                                            RichText::new(&command.registered).monospace(),
                                        )
                                        .wrap(),
                                    );
                                } else {
                                    body.colored_label(
                                        t.attention,
                                        "The command is no longer available for safe handoff.",
                                    );
                                }
                                body.add_space(12.);
                                body.colored_label(t.attention, "Launching does not confirm removal. The program may request elevation or require a restart.");
                            } else {
                                theme::muted(
                                    body,
                                    "This registration disappeared from the current inventory. Refresh before trying again.",
                                    t,
                                );
                            }
                        }
                    });
                ui.add_space(8.);
                ui.separator();
                ui.add_space(8.);
                ui.horizontal_wrapped(|actions| match &dialog {
                    ProgramsDialog::Details(_) => {
                        if theme::secondary(actions, "Close", true) {
                            close = true;
                        }
                    }
                    ProgramsDialog::UninstallReview(request) => {
                        let program = self.program_by_identity(&request.identity);
                        if theme::secondary(actions, "Cancel", !self.busy()) {
                            close = true;
                        }
                        let enabled = !self.busy()
                            && program.is_some_and(InstalledProgram::can_uninstall);
                        if theme::primary(actions, "Start registered uninstaller", t, enabled) {
                            start_handoff = Some(request.clone());
                            close = true;
                        }
                    }
                });
            });
        if response.should_close() && can_dismiss {
            close = true;
        }
        if close && can_dismiss {
            self.program_ui.dialog = None;
        }
        if let Some(request) = start_handoff {
            self.program_ui.dialog = None;
            self.begin_program_uninstall(request, ctx);
        }
    }

    pub(super) fn programs_event(&mut self, event: ProgramsEvent) {
        match event {
            ProgramsEvent::Inventory(result) => {
                self.worker = None;
                self.program_ui.loading = false;
                match result {
                    Ok(inventory) => {
                        let still_exists =
                            self.program_ui.selected.as_ref().is_some_and(|identity| {
                                inventory
                                    .programs
                                    .iter()
                                    .any(|program| &program.identity == identity)
                            });
                        if !still_exists {
                            self.program_ui.selected = None;
                        }
                        self.program_ui.inventory = Some(inventory);
                        self.program_ui.load_error = None;
                    }
                    Err(error) => self.program_ui.load_error = Some(error),
                }
            }
            ProgramsEvent::UninstallHandoff {
                request_id,
                target_name,
                journal_created,
                result,
                journal_error,
            } => {
                self.worker = None;
                self.program_ui.loading = false;
                self.program_ui.journal_loaded = false;
                match result {
                    Ok(receipt) => {
                        self.program_ui.waiting_for_uninstaller_return = true;
                        self.program_ui.saw_focus_loss = false;
                        let receipt_text = if journal_error.is_some() {
                            format!(
                                "The uninstaller for {target_name} started as process {}. Its durable handoff receipt could not be completed, so the outcome remains uncertain.",
                                receipt.process_id
                            )
                        } else {
                            format!(
                                "The registered uninstaller for {target_name} started as process {}. Removal is not confirmed; DCleaner will refresh the registration inventory after you return.",
                                receipt.process_id
                            )
                        };
                        self.notice = Some(receipt_text);
                        if let Some(error) = journal_error {
                            self.error = Some(format!(
                                "Uninstaller started, but the journal receipt failed: {error}"
                            ));
                        }
                    }
                    Err(error) => {
                        self.program_ui.waiting_for_uninstaller_return = false;
                        let prefix = if journal_created {
                            "The registered uninstaller was not started."
                        } else {
                            "The uninstaller was not started because its durable intent could not be recorded."
                        };
                        self.error = Some(match journal_error {
                            Some(journal_error) => {
                                format!("{prefix} {error} Journal update: {journal_error}")
                            }
                            None => format!("{prefix} {error}"),
                        });
                    }
                }
                let _ = request_id;
            }
        }
    }

    fn program_inventory_panel(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let sort_choices = ProgramSort::ALL.map(ProgramSort::label);
        theme::control_row(ui, |ui| {
            let search_width = theme::search_width(ui, &sort_choices);
            ui.label(RichText::new("Search").color(t.muted));
            theme::input(
                ui,
                &mut self.program_ui.search,
                search_width,
                "Name, publisher, version, location or registration…",
                true,
            );
            ui.add_space(8.);
            ui.label(RichText::new("Sort by").color(t.muted));
            theme::selector(
                ui,
                "program-sort",
                self.program_ui.sort.label(),
                &sort_choices,
                |ui| {
                    for sort in ProgramSort::ALL {
                        ui.selectable_value(&mut self.program_ui.sort, sort, sort.label());
                    }
                },
            );
            ui.add_space(8.);
            theme::checkbox(ui, &mut self.program_ui.descending, "Descending", true);
        });
        ui.add_space(10.);

        if self.program_ui.loading && self.program_ui.inventory.is_none() {
            ui.horizontal(|ui| {
                ui.spinner();
                theme::muted(ui, "Reading uninstall registrations…", t);
            });
        }
        if let Some(error) = self.program_ui.load_error.as_deref() {
            unavailable_card(ui, t, "Inventory unavailable", error);
        }
        let busy = self.busy();
        let mut row_details = None;
        let mut row_uninstall_review = None;
        if let Some(inventory) = self.program_ui.inventory.as_ref() {
            let mut visible: Vec<_> = inventory
                .programs
                .iter()
                .filter(|program| matches_search(program, &self.program_ui.search))
                .collect();
            sort_programs(
                &mut visible,
                self.program_ui.sort,
                self.program_ui.descending,
            );
            ui.horizontal(|ui| {
                theme::muted(ui, format!("{} shown", visible.len()), t);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    theme::muted(
                        ui,
                        format!("{} registry read issues", inventory.errors.len()),
                        t,
                    );
                });
            });
            ui.add_space(6.);
            let table_width = ui.available_width().max(0.0);
            let action_width = 152.0;
            let version_width = 84.0;
            let show_publisher = table_width >= 900.0;
            let publisher_width = if show_publisher { 150.0 } else { 0.0 };
            let column_gaps = if show_publisher { 24.0 } else { 16.0 };
            let name_width =
                (table_width - action_width - version_width - publisher_width - column_gaps)
                    .max(110.0);
            let previous_y_spacing = ui.spacing().item_spacing.y;
            ui.spacing_mut().item_spacing.y = 0.;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                table_heading(ui, "Program", name_width, t);
                if show_publisher {
                    table_heading(ui, "Publisher", publisher_width, t);
                }
                table_heading(ui, "Version", version_width, t);
                table_heading(ui, "Actions", action_width, t);
            });
            ui.add_space(3.);
            ui.separator();
            let body_height =
                (ctx.content_rect().bottom() - ui.cursor().top() - 74. - 28. - 50.).max(120.);
            egui::ScrollArea::vertical()
                .id_salt("installed-programs-table-body")
                .max_height(body_height)
                .auto_shrink([false, false])
                .show_rows(ui, 44.0, visible.len(), |rows_ui, visible_rows| {
            for index in visible_rows {
                let program = visible[index];
                rows_ui.push_id(program.identity.stable_id(), |ui| {
                    let row_response = ui.allocate_ui_with_layout(
                        [table_width, 44.].into(),
                        Layout::left_to_right(Align::Center),
                        |row| {
                            row.set_min_height(44.0);
                            row.spacing_mut().item_spacing.x = 8.0;
                            row.spacing_mut().item_spacing.y = previous_y_spacing;
                            let is_selected =
                                self.program_ui.selected.as_ref() == Some(&program.identity);
                            let icon = program.icon_resource();
                            let name = row
                                .allocate_ui_with_layout(
                                    [name_width, 40.].into(),
                                    Layout::left_to_right(Align::Center),
                                    |cell| {
                                        cell.set_min_width(name_width);
                                        cell.set_max_width(name_width);
                                        cell.spacing_mut().item_spacing.x = 8.;
                                        self.app_icons.show(cell, icon.as_deref(), 22.0);
                                        cell.scope(|cell| {
                                            cell.spacing_mut().button_padding.x = 0.;
                                            cell.add_sized(
                                                [(name_width - 30.).clamp(60., name_width), 40.],
                                        egui::Button::selectable(
                                            is_selected,
                                            (
                                                RichText::new(&program.display_name)
                                                    .family(theme::semibold()),
                                                egui::Atom::grow(),
                                            ),
                                        )
                                        .truncate(),
                                    )
                                        })
                                        .inner
                                    },
                                )
                                .inner;
                            if name.clicked() {
                                self.program_ui.selected = Some(program.identity.clone());
                            }
                            name.on_hover_text(&program.display_name);
                            if show_publisher {
                                theme::table_cell(
                                    row,
                                    RichText::new(optional(&program.publisher)).color(t.muted),
                                    publisher_width,
                                    40.,
                                );
                            }
                            theme::table_cell(
                                row,
                                RichText::new(optional(&program.version)).color(t.muted),
                                version_width,
                                40.,
                            );
                            row.allocate_ui_with_layout(
                                [action_width, 40.].into(),
                                Layout::left_to_right(Align::Center),
                                |actions| {
                                    actions.spacing_mut().item_spacing.x = 5.0;
                                    if theme::row_action(actions, "Details", true).clicked() {
                                        row_details = Some(program.identity.clone());
                                    }
                                    let reasons = program.removal_block_reasons();
                                    if reasons.is_empty() {
                                        if theme::row_action(actions, "Uninstall", !busy)
                                            .on_hover_text(
                                                "Review the exact registered uninstaller before it starts.",
                                            )
                                            .clicked()
                                        {
                                            row_uninstall_review =
                                                Some(program.identity.clone());
                                        }
                                    } else {
                                        theme::row_action(actions, "Blocked", false)
                                            .on_hover_text(
                                                reasons
                                                    .iter()
                                                    .map(ToString::to_string)
                                                    .collect::<Vec<_>>()
                                                    .join(" "),
                                            );
                                    }
                                },
                            );
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
            if visible.is_empty() {
                ui.add_space(10.);
                theme::muted(ui, "No installed programs match this search.", t);
            }
            if !inventory.errors.is_empty() {
                ui.add_space(8.);
                egui::CollapsingHeader::new("Registry read issues")
                    .id_salt("program-registry-errors")
                    .show(ui, |ui| {
                        for error in &inventory.errors {
                            theme::muted(
                                ui,
                                format!(
                                    "{}{} — {}",
                                    source_label(error.source),
                                    error
                                        .key_name
                                        .as_ref()
                                        .map(|name| format!(" / {name}"))
                                        .unwrap_or_default(),
                                    error.message
                                ),
                                t,
                            );
                        }
                    });
            }
        } else if self.program_ui.load_error.is_none() && !self.program_ui.loading {
            theme::muted(ui, "Select Refresh to read registered programs.", t);
        }
        if let Some(identity) = row_details {
            self.program_ui.selected = Some(identity.clone());
            self.program_ui.dialog = Some(ProgramsDialog::Details(identity));
        } else if let Some(identity) = row_uninstall_review {
            self.program_ui.selected = Some(identity);
            self.open_program_uninstall_review();
        }
    }

    fn program_operation_history(&mut self, ui: &mut egui::Ui, t: Tokens) {
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Uninstall handoff history").family(theme::semibold()));
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    theme::muted(ui, "Durable local journal", t);
                });
            });
            ui.add_space(8.);
            if let Some(error) = self.program_ui.journal_error.as_deref() {
                theme::muted(ui, format!("Journal history unavailable: {error}"), t);
            } else if self.program_ui.journal.is_empty() {
                theme::muted(ui, "No uninstall handoffs recorded.", t);
            } else {
                for entry in self.program_ui.journal.iter().take(5) {
                    ui.separator();
                    ui.add_space(6.);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(journal_state_label(&entry.state))
                                .family(theme::semibold()),
                        );
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            theme::muted(ui, format_timestamp(&entry.date), t);
                        });
                    });
                    let identity = entry
                        .intent
                        .get("identity")
                        .and_then(|identity| identity.get("key_name"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("program registration");
                    theme::muted(ui, identity, t);
                    if entry.state == "handed_off" || entry.state == "uncertain" {
                        theme::muted(ui, "Removal is not confirmed by the handoff record.", t);
                    }
                }
            }
        });
    }

    fn selected_program(&self) -> Option<&InstalledProgram> {
        self.program_ui
            .selected
            .as_ref()
            .and_then(|identity| self.program_by_identity(identity))
    }

    fn program_by_identity(&self, identity: &ProgramIdentity) -> Option<&InstalledProgram> {
        self.program_ui
            .inventory
            .as_ref()?
            .programs
            .iter()
            .find(|program| &program.identity == identity)
    }

    fn begin_program_inventory(&mut self, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        self.program_ui.initial_load_attempted = true;
        self.program_ui.loading = true;
        self.program_ui.load_error = None;
        self.progress = "Reading installed-program registrations".into();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let repaint = ctx.clone();
        thread::spawn(move || {
            let result = programs::installed_programs();
            let _ = tx.send(Event::Programs(ProgramsEvent::Inventory(result)));
            repaint.request_repaint();
        });
    }

    fn begin_program_uninstall(&mut self, request: UninstallRequest, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        let target_name = self
            .program_by_identity(&request.identity)
            .map(|program| program.display_name.clone())
            .unwrap_or_else(|| request.identity.key_name.clone());
        self.program_ui.loading = true;
        self.progress = format!("Revalidating registration for {target_name}");
        let root = self.data_dir.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let repaint = ctx.clone();
        thread::spawn(move || {
            let event = match dcleaner::effects::EffectJournal::create(
                &root,
                "program-uninstall",
                request.request_id,
                &request,
            ) {
                Err(error) => ProgramsEvent::UninstallHandoff {
                    request_id: request.request_id,
                    target_name,
                    journal_created: false,
                    result: Err(format!("Durable intent could not be written: {error}")),
                    journal_error: None,
                },
                Ok(mut journal) => {
                    #[cfg(windows)]
                    let result = programs::handoff_uninstall(
                        &request,
                        &programs::WindowsRegistry,
                        &mut programs::WindowsProcess,
                    )
                    .map_err(|error| error.to_string());

                    #[cfg(not(windows))]
                    let result: Result<UninstallHandoffReceipt, String> =
                        Err("Native uninstall handoff is unavailable on this platform.".into());

                    let journal_error = match &result {
                        Ok(receipt) => journal.finish("handed_off", receipt).err(),
                        Err(error) => journal
                            .finish(
                                "failed",
                                &HandoffFailureReceipt {
                                    request_id: request.request_id,
                                    error,
                                },
                            )
                            .err(),
                    };
                    ProgramsEvent::UninstallHandoff {
                        request_id: request.request_id,
                        target_name,
                        journal_created: true,
                        result,
                        journal_error,
                    }
                }
            };
            let _ = tx.send(Event::Programs(event));
            repaint.request_repaint();
        });
    }

    fn open_program_uninstall_review(&mut self) {
        let Some(program) = self.selected_program() else {
            return;
        };
        match programs::prepare_uninstall(program) {
            Ok(request) => self.program_ui.dialog = Some(ProgramsDialog::UninstallReview(request)),
            Err(reasons) => {
                self.error = Some(
                    reasons
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            }
        }
    }

    fn load_program_journal(&mut self) {
        if self.program_ui.journal_loaded {
            return;
        }
        self.program_ui.journal_loaded = true;
        match dcleaner::effects::history(&self.data_dir, "program-uninstall") {
            Ok(history) => {
                self.program_ui.journal = history;
                self.program_ui.journal_error = None;
            }
            Err(error) => {
                self.program_ui.journal.clear();
                self.program_ui.journal_error = Some(error);
            }
        }
    }

    fn refresh_program_inventory_after_return(&mut self, ctx: &egui::Context) {
        if !self.program_ui.waiting_for_uninstaller_return || self.busy() {
            return;
        }
        match ctx.input(|input| input.viewport().focused) {
            Some(false) => self.program_ui.saw_focus_loss = true,
            Some(true) if self.program_ui.saw_focus_loss => {
                self.program_ui.waiting_for_uninstaller_return = false;
                self.begin_program_inventory(ctx);
            }
            _ => {}
        }
    }
}

fn table_heading(ui: &mut egui::Ui, label: &str, width: f32, t: Tokens) {
    theme::table_cell(
        ui,
        RichText::new(label).size(12.).color(t.muted),
        width,
        22.,
    );
}

fn dialog_body_max_height(ctx: &egui::Context) -> f32 {
    // Keep the 24px dialog padding, pinned title, pinned action footer, and layout gaps visible.
    (ctx.content_rect().height() - 48.0 - 40.0 - 56.0 - 24.0).max(80.0)
}

fn unavailable_card(ui: &mut egui::Ui, t: Tokens, heading: &str, message: &str) {
    egui::Frame::new()
        .fill(t.tint)
        .stroke(egui::Stroke::new(1., t.border))
        .corner_radius(10)
        .inner_margin(14)
        .show(ui, |ui| {
            ui.label(RichText::new(heading).family(theme::semibold()));
            ui.add_space(5.);
            theme::muted(ui, message, t);
        });
}

fn detail_row(ui: &mut egui::Ui, label: &str, value: impl Into<String>, t: Tokens) {
    theme::muted(ui, label, t);
    ui.add(egui::Label::new(value.into()).wrap());
    ui.add_space(5.);
}

fn command_preview(ui: &mut egui::Ui, program: &InstalledProgram, t: Tokens) {
    let frame = egui::Frame::new()
        .fill(t.canvas)
        .stroke(egui::Stroke::new(1., t.border))
        .corner_radius(8)
        .inner_margin(10);
    frame.show(ui, |ui| {
        if let Some(command) = &program.uninstall_command {
            ui.add(egui::Label::new(RichText::new(&command.registered).monospace()).wrap());
        } else if let Some(error) = &program.uninstall_command_error {
            ui.colored_label(t.attention, error);
        } else {
            theme::muted(ui, "No registered uninstall command.", t);
        }
    });
}

fn optional(value: &Option<String>) -> String {
    value
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("—")
        .to_owned()
}

fn matches_search(program: &InstalledProgram, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    let location = program
        .install_location
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    [
        Some(program.display_name.as_str()),
        program.publisher.as_deref(),
        program.version.as_deref(),
        location.as_deref(),
        Some(program.identity.key_name.as_str()),
    ]
    .into_iter()
    .flatten()
    .any(|value| value.to_lowercase().contains(&query))
}

fn sort_programs(programs: &mut [&InstalledProgram], sort: ProgramSort, descending: bool) {
    programs.sort_by(|left, right| {
        let ordering = match sort {
            ProgramSort::Name => left
                .display_name
                .to_lowercase()
                .cmp(&right.display_name.to_lowercase()),
            ProgramSort::Publisher => left
                .publisher
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .cmp(&right.publisher.as_deref().unwrap_or("").to_lowercase()),
            ProgramSort::Version => left
                .version
                .as_deref()
                .unwrap_or("")
                .cmp(right.version.as_deref().unwrap_or("")),
            ProgramSort::InstallDate => left
                .install_date
                .as_deref()
                .unwrap_or("")
                .cmp(right.install_date.as_deref().unwrap_or("")),
            ProgramSort::Size => left.estimated_size_bytes.cmp(&right.estimated_size_bytes),
        };
        let ordering = if descending {
            ordering.reverse()
        } else {
            ordering
        };
        ordering.then_with(|| left.identity.stable_id().cmp(&right.identity.stable_id()))
    });
}

impl ProgramSort {
    fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Publisher => "Publisher",
            Self::Version => "Version",
            Self::InstallDate => "Install date",
            Self::Size => "Estimated size",
        }
    }
}

fn source_label(source: RegistrySource) -> String {
    format!(
        "{} · {} view",
        match source.hive {
            RegistryHive::CurrentUser => "Current user",
            RegistryHive::LocalMachine => "Local machine",
        },
        match source.view {
            RegistryView::Registry32 => "32-bit",
            RegistryView::Registry64 => "64-bit",
        }
    )
}

fn format_install_date(value: &str) -> String {
    if value.len() == 8 && value.bytes().all(|byte| byte.is_ascii_digit()) {
        format!("{}-{}-{}", &value[0..4], &value[4..6], &value[6..8])
    } else if value.is_empty() {
        "—".into()
    } else {
        value.to_owned()
    }
}

fn format_size(bytes: u64) -> String {
    let mut value = bytes as f64;
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut unit = 0;
    while value >= 1024. && unit < units.len() - 1 {
        value /= 1024.;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", units[unit])
    }
}

fn format_timestamp(value: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|date| date.format("%d %b %Y, %H:%M").to_string())
        .unwrap_or_else(|_| value.to_owned())
}

fn journal_state_label(state: &str) -> &str {
    match state {
        "handed_off" => "Uninstaller launched · outcome not confirmed",
        "failed" => "Handoff failed",
        "completed" => "Completion recorded",
        "uncertain" => "Outcome uncertain · review before retrying",
        other => other,
    }
}
