use super::*;
use dcleaner::{
    optimizer_inventory::{self, Program, Settings, Snapshot},
    startup::FieldValue,
};
#[cfg(debug_assertions)]
use dcleaner::{
    programs::{InstalledProgram, ProgramIdentity, RegistryHive, RegistrySource, RegistryView},
    startup::{EnabledState, EntryIdentity, StartupEntry, StartupId, StartupSection},
};

#[derive(Clone, Copy, Default, PartialEq)]
enum Tab {
    #[default]
    Applications,
    Active,
    Sleeping,
    Excluded,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SortColumn {
    #[default]
    Program,
    Publisher,
}

#[derive(Default)]
pub(super) struct OptimizerUi {
    snapshot: Option<Arc<Snapshot>>,
    settings: Settings,
    settings_error: Option<String>,
    attempted: bool,
    loading: bool,
    query: String,
    tab: Tab,
    sort: SortColumn,
    descending: bool,
    dialog: Option<Dialog>,
}
#[derive(Clone)]
enum Dialog {
    Details(Arc<Program>),
    RetainedKey(String),
    Exclusion {
        key: String,
        name: String,
        excluded: bool,
    },
}
pub(super) enum OptimizerEvent {
    Loaded {
        inventory: Result<Snapshot, String>,
        settings: Result<Settings, String>,
    },
    Saved(Result<Settings, String>),
}

impl App {
    #[cfg(debug_assertions)]
    pub(super) fn seed_optimizer_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Optimizer QA fixtures require isolated fixture mode.".into());
        }
        let intro = case == "optimizer-intro";
        let mut ui = OptimizerUi {
            attempted: !intro,
            ..OptimizerUi::default()
        };
        self.error = None;
        self.notice = None;
        self.progress.clear();
        match case {
            "optimizer-intro" => {}
            "optimizer-empty" => {
                ui.snapshot = Some(Arc::new(Snapshot::default()));
            }
            "optimizer-populated" | "optimizer-details" => {
                let program = optimizer_qa_program();
                ui.snapshot = Some(Arc::new(Snapshot {
                    programs: vec![program.clone()],
                    notes: vec![
                        "Synthetic QA fixture; no installed-program or startup inventory was read."
                            .into(),
                    ],
                    cancelled: false,
                    partial: false,
                }));
                if case == "optimizer-details" {
                    ui.dialog = Some(Dialog::Details(Arc::new(program)));
                }
            }
            "optimizer-error" => {
                self.error = Some(
                    "Synthetic QA fixture error. No optimizer inventory or settings were read."
                        .into(),
                );
            }
            _ => return Err(format!("Unsupported Optimizer QA fixture: {case}")),
        }
        if !intro {
            self.mark_feature_seen("optimizer");
        }
        self.optimizer_ui = ui;
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_optimizer_precondition(&self, action: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Optimizer UI actions require isolated fixture mode.".into());
        }
        let has_program = self
            .optimizer_ui
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| !snapshot.programs.is_empty());
        match action {
            "Applications" | "Active apps" | "Sleeping apps" | "Excluded apps" => Ok(()),
            "Sort Program" | "Sort Publisher" if has_program => Ok(()),
            "Details" if has_program && self.optimizer_ui.dialog.is_none() => Ok(()),
            "Close" | "Close dialog" | "Escape"
                if matches!(self.optimizer_ui.dialog.as_ref(), Some(Dialog::Details(_))) =>
            {
                Ok(())
            }
            _ => Err(format!(
                "Optimizer action is unavailable in this safe fixture state: {action}"
            )),
        }
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_optimizer_action_state(
        &self,
        action: &str,
    ) -> Result<serde_json::Value, String> {
        if !self.qa_fixture_mode() {
            return Err("Optimizer UI actions require isolated fixture mode.".into());
        }
        let dialog = if matches!(self.optimizer_ui.dialog.as_ref(), Some(Dialog::Details(_))) {
            "details"
        } else {
            "closed"
        };
        let state = serde_json::json!({
            "tab": optimizer_tab_label(self.optimizer_ui.tab),
            "sort": optimizer_sort_label(self.optimizer_ui.sort),
            "descending": self.optimizer_ui.descending,
            "dialog": dialog,
            "programs": self.optimizer_ui.snapshot.as_ref().map(|snapshot| snapshot.programs.len()),
        });
        let valid = match action {
            "Applications" | "Active apps" | "Sleeping apps" | "Excluded apps" => {
                state["tab"] == action
            }
            "Sort Program" => state["sort"] == "Program",
            "Sort Publisher" => state["sort"] == "Publisher",
            "Details" => state["dialog"] == "details",
            "Close" | "Close dialog" | "Escape" => state["dialog"] == "closed",
            _ => false,
        };
        if !valid {
            return Err(format!(
                "Optimizer action did not reach its expected safe state: {action}"
            ));
        }
        Ok(serde_json::json!({ "action": action, "state": state }))
    }

    fn begin_optimizer_scan(&mut self, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        self.optimizer_ui.loading = true;
        self.optimizer_ui.attempted = true;
        self.error = None;
        self.progress = "Reading installed applications and background registrations…".into();
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let root = self.data_dir.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let ctx = ctx.clone();
        thread::spawn(move || {
            let (settings, inventory) = std::panic::catch_unwind(|| {
                (optimizer_inventory::load_settings(&root), optimizer_inventory::scan(&cancel))
            }).unwrap_or_else(|_| (Err("The inventory worker ended unexpectedly. Reload before changing exclusions.".into()), Err("The inventory worker ended without a result.".into())));
            let _ = tx.send(Event::Optimizer(OptimizerEvent::Loaded {
                inventory,
                settings,
            }));
            ctx.request_repaint();
        });
    }
    pub(super) fn optimizer_event(&mut self, event: OptimizerEvent) {
        self.worker = None;
        match event {
            OptimizerEvent::Loaded {
                inventory,
                settings,
            } => {
                self.optimizer_ui.loading = false;
                match settings {
                    Ok(settings) => {
                        self.optimizer_ui.settings = settings;
                        self.optimizer_ui.settings_error = None;
                    }
                    Err(error) => self.optimizer_ui.settings_error = Some(error),
                }
                match inventory {
                    Ok(snapshot) => self.optimizer_ui.snapshot = Some(Arc::new(snapshot)),
                    Err(error) => {
                        self.optimizer_ui.snapshot = None;
                        self.error = Some(error);
                    }
                }
            }
            OptimizerEvent::Saved(result) => match result {
                Ok(settings) => {
                    self.optimizer_ui.settings = settings;
                    self.optimizer_ui.settings_error = None;
                    self.notice = Some("Optimization exclusion saved.".into());
                    self.optimizer_ui.dialog = None;
                }
                Err(error) => {
                    self.optimizer_ui.settings_error = Some(error.clone());
                    self.error = Some(error);
                    self.optimizer_ui.dialog = None;
                }
            },
        }
    }
    pub(super) fn optimizer_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if !self.feature_seen("optimizer") {
            if self.feature_intro(
                ui,
                t,
                "optimizer",
                "Review apps and startup options",
                "Start with a read-only inventory of installed applications and possible background entries. Impact and sleep state are unavailable in this build.",
                &[
                    (
                        theme::Icon::Optimizer,
                        "Improve overall performance",
                        "Review app registrations and possible background entries; impact has not been measured.",
                    ),
                    (
                        theme::Icon::Startup,
                        "More startup speed",
                        "Review startup-related registrations. Putting apps to sleep is unavailable in this build.",
                    ),
                ],
            ) {
                self.start_optimizer(ctx);
            }
            return;
        }
        if !self.optimizer_ui.attempted && !self.busy() && !self.qa_fixture_mode() {
            self.begin_optimizer_scan(ctx);
        }
        ui.horizontal_wrapped(|ui| {
            theme::tabs(ui, |ui| {
                for (tab, label, icon) in [
                    (Tab::Applications, "Applications", theme::Icon::Applications),
                    (Tab::Active, "Active apps", theme::Icon::Sun),
                    (Tab::Sleeping, "Sleeping apps", theme::Icon::Moon),
                    (Tab::Excluded, "Excluded apps", theme::Icon::EyeOff),
                ] {
                    if theme::tab_with_icon_count(
                        ui,
                        self.optimizer_ui.tab == tab,
                        icon,
                        label,
                        None,
                        t,
                    )
                    .clicked()
                    {
                        self.optimizer_ui.tab = tab;
                    }
                }
            });
        });
        ui.add_space(6.);
        ui.separator();
        ui.add_space(8.);
        if let Some(error) = &self.optimizer_ui.settings_error {
            theme::muted(
                ui,
                format!("Exclusions unavailable: {error} Reload before changing them."),
                t,
            );
            ui.add_space(8.);
            if self.optimizer_ui.tab == Tab::Excluded {
                return;
            }
        }
        if self.optimizer_ui.tab == Tab::Active {
            ui.label(RichText::new("Active app status unavailable").family(theme::semibold()));
            theme::muted(
                ui,
                "Background activity has not been measured. Applications lists installed registrations for review without labelling them as active.",
                t,
            );
            return;
        }
        if self.optimizer_ui.tab == Tab::Sleeping {
            ui.label(RichText::new("Sleep status unavailable").family(theme::semibold()));
            theme::muted(
                ui,
                "The background optimizer is unavailable in this build. A disabled startup entry does not establish that an app is sleeping.",
                t,
            );
            ui.add_space(12.);
            theme::primary(ui, "Activate all", t, false);
            return;
        }
        let Some(snapshot) = self.optimizer_ui.snapshot.clone() else {
            if !self.optimizer_ui.loading {
                theme::muted(ui, "No inventory loaded. Choose Scan again to retry.", t);
            }
            return;
        };
        let query = self.optimizer_ui.query.to_lowercase();
        let excluded_tab = self.optimizer_ui.tab == Tab::Excluded;
        let mut indices: Vec<_> = snapshot
            .programs
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                (!excluded_tab || self.optimizer_ui.settings.is_excluded(&p.key()))
                    && (query.is_empty()
                        || p.registration.display_name.to_lowercase().contains(&query)
                        || p.registration
                            .publisher
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&query))
            })
            .map(|(i, _)| i)
            .collect();
        indices.sort_by(|left, right| {
            let left_program = &snapshot.programs[*left];
            let right_program = &snapshot.programs[*right];
            let primary = match self.optimizer_ui.sort {
                SortColumn::Program => left_program
                    .registration
                    .display_name
                    .to_lowercase()
                    .cmp(&right_program.registration.display_name.to_lowercase()),
                SortColumn::Publisher => left_program
                    .registration
                    .publisher
                    .as_deref()
                    .unwrap_or("Unavailable")
                    .to_lowercase()
                    .cmp(
                        &right_program
                            .registration
                            .publisher
                            .as_deref()
                            .unwrap_or("Unavailable")
                            .to_lowercase(),
                    ),
            };
            let primary = if self.optimizer_ui.descending {
                primary.reverse()
            } else {
                primary
            };
            primary.then_with(|| {
                left_program
                    .registration
                    .display_name
                    .to_lowercase()
                    .cmp(&right_program.registration.display_name.to_lowercase())
            })
        });
        if !excluded_tab {
            theme::muted(
                ui,
                "Impact is not measured. Details lists possible background entries.",
                t,
            );
        } else {
            theme::muted(
                ui,
                "Excluded applications are omitted from future optimization. Removing an exclusion does not put an app to sleep.",
                t,
            );
        }
        if snapshot.cancelled || snapshot.partial {
            ui.add_space(6.);
            theme::muted(
                ui,
                if snapshot.cancelled {
                    "Scan stopped; this inventory is incomplete."
                } else {
                    "Some sources could not be fully examined."
                },
                t,
            );
        }
        if !snapshot.notes.is_empty() {
            egui::CollapsingHeader::new(format!("Inventory details ({})", snapshot.notes.len()))
                .show(ui, |ui| {
                    for note in &snapshot.notes {
                        theme::muted(ui, note, t);
                    }
                });
        }
        ui.add_space(10.);
        let known: HashSet<_> = snapshot.programs.iter().map(Program::key).collect();
        let retained: Vec<String> = if excluded_tab {
            self.optimizer_ui
                .settings
                .excluded_keys()
                .into_iter()
                .filter(|key| {
                    !known.contains(*key)
                        && (query.is_empty() || key.to_lowercase().contains(&query))
                })
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
        };
        theme::scroll_horizontal().id_salt("optimizer-table-width").auto_shrink([false,true]).show(ui,|ui| {
            let width = ui.available_width().max(560.);
            let name_width = width - 148. - 90. - 116. - 24.;
            let spacing_y = ui.spacing().item_spacing.y;
            ui.spacing_mut().item_spacing.y = 0.;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.;
                let program_header = optimizer_sort_heading(
                    ui,
                    "Program",
                    "Sort Program",
                    name_width,
                    self.optimizer_ui.sort == SortColumn::Program,
                    self.optimizer_ui.descending,
                    t,
                );
                if program_header.clicked() {
                    select_optimizer_sort(
                        &mut self.optimizer_ui.sort,
                        &mut self.optimizer_ui.descending,
                        SortColumn::Program,
                    );
                }
                let publisher_header = optimizer_sort_heading(
                    ui,
                    "Publisher",
                    "Sort Publisher",
                    148.,
                    self.optimizer_ui.sort == SortColumn::Publisher,
                    self.optimizer_ui.descending,
                    t,
                );
                if publisher_header.clicked() {
                    select_optimizer_sort(
                        &mut self.optimizer_ui.sort,
                        &mut self.optimizer_ui.descending,
                        SortColumn::Publisher,
                    );
                }
                for (label, w) in [("Impact", 90.), ("Actions", 116.)] {
                    theme::table_cell(ui,RichText::new(label).color(t.muted).size(theme::FONT_CAPTION),w,22.);
                }
            });
            ui.add_space(3.); ui.separator();
            let body_height = (ctx.content_rect().bottom()-ui.cursor().top()-74.-28.-24.).max(80.);
            theme::scroll_vertical().id_salt("optimizer-table-body").auto_shrink([false,false]).max_height(body_height)
                .show_rows(ui,theme::TABLE_ROW_HEIGHT,indices.len()+retained.len(),|ui,visible| {
                    for i in visible {
                        let program = indices.get(i).map(|index| &snapshot.programs[*index]);
                        let key = program.map(Program::key).unwrap_or_else(||retained[i-indices.len()].clone());
                        let name = program.map(|p|p.registration.display_name.as_str()).unwrap_or("Registration not found in this scan");
                        let excluded = self.optimizer_ui.settings_error.is_none() && self.optimizer_ui.settings.is_excluded(&key);
                        ui.push_id((&key,i),|ui| {
                            ui.allocate_ui_with_layout(Vec2::new(width,theme::TABLE_ROW_HEIGHT),Layout::left_to_right(Align::Center),|row| {
                                row.spacing_mut().item_spacing.x=8.; row.spacing_mut().item_spacing.y=spacing_y;
                                row.allocate_ui_with_layout(Vec2::new(name_width,40.),Layout::left_to_right(Align::Center),|cell| {
                                    cell.set_min_width(name_width); cell.set_max_width(name_width);
                                    cell.spacing_mut().item_spacing.x=8.;
                                    self.app_icons.show(cell,program.and_then(|p|p.registration.icon_resource()).as_deref(),22.);
                                    let response = cell.add_sized([(name_width-30.).max(80.),40.],egui::Button::new((RichText::new(name).family(theme::semibold()).color(t.foreground),egui::Atom::grow())).frame(false).truncate());
                                    #[cfg(debug_assertions)]
                                    theme::record_fixture_control(cell, "Details", &response);
                                    if response.clicked() { self.optimizer_ui.dialog=Some(optimizer_details_for(program,&key)); }
                                    response.on_hover_text(name).on_hover_text(&key);
                                });
                                let publisher = program.and_then(|p|p.registration.publisher.as_deref()).unwrap_or("Unavailable");
                                theme::table_cell(row,RichText::new(publisher).color(t.muted),148.,40.)
                                    .on_hover_text(publisher);
                                theme::table_cell(row,RichText::new("Unavailable").color(t.muted),90.,40.);
                                row.allocate_ui_with_layout(Vec2::new(80.,40.),Layout::left_to_right(Align::Center),|cell| {
                                    cell.set_min_width(80.); cell.set_max_width(80.);
                                    if excluded {
                                        if theme::row_action(cell,"Restore",!self.busy() && self.optimizer_ui.settings_error.is_none()).clicked() {
                                            self.optimizer_ui.dialog=Some(Dialog::Exclusion {key:key.clone(),name:name.to_owned(),excluded:false});
                                        }
                                    } else { theme::row_action(cell,"Sleep",false).on_hover_text("The background optimizer must be available before this app can be put to sleep."); }
                                });
                                let more=theme::row_more(row,true);
                                egui::Popup::menu(&more).show(|ui| {
                                    if ui.button("Details").clicked() { self.optimizer_ui.dialog=Some(optimizer_details_for(program,&key)); ui.close(); }
                                    if ui.add_enabled(!self.busy() && self.optimizer_ui.settings_error.is_none(),egui::Button::new(if excluded {"Remove exclusion"} else {"Exclude app"})).clicked() {
                                        self.optimizer_ui.dialog=Some(Dialog::Exclusion {key:key.clone(),name:name.to_owned(),excluded:!excluded}); ui.close();
                                    }
                                });
                            });
                            let y=ui.cursor().top();
                            ui.painter().hline(ui.max_rect().x_range(),y,egui::Stroke::new(1.,t.border));
                        });
                    }
                });
            ui.spacing_mut().item_spacing.y=spacing_y;
        });
        if indices.is_empty() && retained.is_empty() {
            theme::muted(
                ui,
                if query.is_empty() {
                    "No applications in this list."
                } else {
                    "No matching applications."
                },
                t,
            );
        }
    }
    pub(super) fn optimizer_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if !self.feature_seen("optimizer") {
            let compact = !self.feature_intro_wide(ctx);
            let mut start = false;
            theme::action_row(ui, |ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if compact {
                        start = theme::primary(ui, "Scan now", t, !self.busy());
                    } else {
                        theme::muted(
                            ui,
                            "Review installed applications and possible background entries before deciding what to change.",
                            t,
                        );
                    }
                });
            });
            if start {
                self.start_optimizer(ctx);
            }
            return;
        }
        theme::action_row(ui, |ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if self.optimizer_ui.loading {
                    if theme::secondary(ui, "Stop scan", true) {
                        self.cancel.store(true, Ordering::Relaxed);
                    }
                    theme::muted(ui, "Reading background registrations…", t);
                    ui.spinner();
                } else {
                    let summary = self
                        .optimizer_ui
                        .snapshot
                        .as_ref()
                        .map(|s| format!("{} registrations examined", s.programs.len()))
                        .unwrap_or_else(|| "Not scanned".into());
                    if theme::secondary(ui, "Scan again", !self.busy()) {
                        self.begin_optimizer_scan(ctx);
                    }
                    theme::muted(ui, summary, t);
                }
            });
        });
    }

    fn start_optimizer(&mut self, ctx: &egui::Context) {
        self.mark_feature_seen("optimizer");
        self.begin_optimizer_scan(ctx);
    }

    pub(super) fn optimizer_dialog(&mut self, ctx: &egui::Context) {
        if self.optimizer_ui.dialog.is_some()
            && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            let can_close = !self.busy()
                || matches!(
                    self.optimizer_ui.dialog.as_ref(),
                    Some(Dialog::Details(_) | Dialog::RetainedKey(_))
                );
            if can_close {
                self.optimizer_ui.dialog = None;
            }
            return;
        }
        let Some(dialog) = self.optimizer_ui.dialog.clone() else {
            return;
        };
        let t = theme::tokens(self.prefs.dark);
        let width = (ctx.content_rect().width() - 32.).clamp(280., 560.);
        let busy = self.busy();
        let can_close = !busy || matches!(dialog, Dialog::Details(_) | Dialog::RetainedKey(_));
        let mut close = false;
        let mut save = None;
        let response=egui::Modal::new(egui::Id::new("optimizer-dialog")).frame(theme::dialog_frame(t)).show(ctx,|ui| {
            ui.set_width(width);
            ui.horizontal(|ui| {
                ui.heading(match &dialog {Dialog::Details(_) | Dialog::RetainedKey(_)=>"Application details",Dialog::Exclusion {excluded:true,..}=>"Exclude application?",Dialog::Exclusion {..}=>"Remove exclusion?"});
                ui.with_layout(Layout::right_to_left(Align::Center), |actions| {
                    close |= theme::close_button(actions, "Close dialog", can_close);
                });
            });
            ui.add_space(12.);
            theme::scroll_vertical().id_salt("optimizer-dialog-body").max_height((ctx.content_rect().height()-190.).max(80.)).show(ui,|ui| {
                match &dialog {
                    Dialog::Details(program)=>{
                        optimizer_detail(ui,"Application",&program.registration.display_name,t);
                        optimizer_detail(ui,"Publisher",program.registration.publisher.as_deref().unwrap_or("Unavailable"),t);
                        optimizer_detail(ui,"Version",program.registration.version.as_deref().unwrap_or("Unavailable"),t);
                        optimizer_detail(ui,"Installed",program.registration.install_date.as_deref().unwrap_or("Unavailable"),t);
                        optimizer_detail(ui,"Impact","Not measured",t);
                        optimizer_detail(ui,"Sleep state","Unavailable",t);
                        optimizer_detail(ui,"Registration",&program.key(),t);
                        theme::muted(ui,&program.association_note,t);
                        ui.add_space(12.); ui.label(RichText::new("Background candidates").family(theme::semibold()));
                        if program.candidates.is_empty() {theme::muted(ui,"No unambiguous directory candidates were found. This does not prove that an app has no background components.",t);}
                        if !program.candidates.is_empty() {
                            theme::scroll_horizontal().id_salt("optimizer-component-columns").show(ui,|ui| {
                                ui.spacing_mut().item_spacing.y=0.;
                                let width=ui.available_width().max(460.);
                                let columns=[72.,120.,width-72.-120.-78.-24.,78.];
                                ui.horizontal(|ui| {ui.spacing_mut().item_spacing.x=8.; for (label,w) in ["Type","Program","File path","State"].into_iter().zip(columns) {theme::table_cell(ui,RichText::new(label).color(t.muted),w,22.);} });
                                theme::scroll_vertical().id_salt("optimizer-component-rows").max_height(176.).show_rows(ui,theme::TABLE_ROW_HEIGHT,program.candidates.len(),|ui,range| {
                                    for index in range {let entry=&program.candidates[index];
                                        let state=match &entry.enabled {dcleaner::startup::EnabledState::Enabled=>"Enabled",dcleaner::startup::EnabledState::Disabled=>"Disabled",dcleaner::startup::EnabledState::Unknown {..}=>"Unavailable"};
                                        ui.horizontal(|ui| {ui.spacing_mut().item_spacing.x=8.; for (text,w) in [entry.section.label().to_owned(),optimizer_field(&entry.program),optimizer_field(&entry.file_path),state.into()].into_iter().zip(columns) {theme::table_cell(ui,text.clone(),w,theme::TABLE_ROW_HEIGHT).on_hover_text(text);} });
                                    }
                                });
                            });
                        }
                    }
                    Dialog::RetainedKey(key)=>{
                        optimizer_detail(ui,"Saved registration",key,t);
                        theme::muted(ui,"This registration was not found in the current scan. Its exclusion is retained; an incomplete scan does not establish that it was uninstalled.",t);
                    }
                    Dialog::Exclusion {name,excluded,..}=>{
                        ui.label(RichText::new(name).family(theme::semibold())); ui.add_space(8.);
                        theme::muted(ui,if *excluded {"Keep this registration excluded from future optimization. This preference does not change its processes or background entries."} else {"Allow this registration to be considered for future optimization again. This does not start, stop or put it to sleep."},t);
                    }
                }
            });
            ui.add_space(12.); ui.separator(); ui.add_space(8.);
            if busy && matches!(dialog,Dialog::Exclusion {..}) {
                ui.horizontal(|ui| {ui.spinner(); theme::muted(ui,"Saving exclusion…",t);});
            }
            theme::action_row(ui,|ui| {
                if theme::secondary(ui,if matches!(dialog,Dialog::Details(_) | Dialog::RetainedKey(_)){"Close"} else {"Cancel"},can_close) {close=true;}
                if let Dialog::Exclusion {key,excluded,..}=&dialog {
                    if theme::primary(ui,if *excluded {"Exclude app"} else {"Remove exclusion"},t,!busy && !self.qa_fixture_mode() && self.optimizer_ui.settings_error.is_none()) {save=Some((key.clone(),*excluded));}
                }
            });
        });
        if can_close && (close || response.should_close()) {
            self.optimizer_ui.dialog = None;
        } else if let Some((key, excluded)) = save {
            if self.qa_fixture_mode() {
                return;
            }
            let root = self.data_dir.clone();
            let settings = self.optimizer_ui.settings.clone();
            let (tx, rx) = mpsc::channel();
            self.worker = Some(rx);
            let ctx = ctx.clone();
            self.progress = "Saving optimization exclusion…".into();
            thread::spawn(move || {
                let result = std::panic::catch_unwind(|| optimizer_inventory::save_exclusion(&root, &settings, &key, excluded))
                    .unwrap_or_else(|_| Err("The preference worker ended unexpectedly. Reload to check whether the exclusion was saved.".into()));
                let _ = tx.send(Event::Optimizer(OptimizerEvent::Saved(result)));
                ctx.request_repaint();
            });
        }
    }
}

#[cfg(debug_assertions)]
fn optimizer_qa_program() -> Program {
    let hive = RegistryHive::CurrentUser;
    let registry_source = RegistrySource {
        hive,
        view: RegistryView::Registry64,
    };
    Program {
        registration: InstalledProgram {
            identity: ProgramIdentity {
                hive,
                key_name: "dcleaner-qa-fixture".into(),
            },
            source: registry_source,
            display_name: "QA fixture application (synthetic)".into(),
            display_icon: None,
            publisher: Some("Synthetic fixture publisher".into()),
            version: Some("0.0-qa".into()),
            install_location: None,
            install_date: Some("20261015".into()),
            estimated_size_bytes: None,
            registered_uninstall_command: None,
            uninstall_command: None,
            uninstall_command_error: None,
            system_component: false,
            protected: false,
            no_remove: false,
        },
        candidates: vec![StartupEntry {
            id: StartupId("qa-fixture-component-1".into()),
            section: StartupSection::WindowsServices,
            program: FieldValue::Known {
                value: "Synthetic background component".into(),
            },
            publisher: FieldValue::Unknown {
                reason: "No publisher metadata is included in this fixture.".into(),
            },
            version: FieldValue::Unknown {
                reason: "No version metadata is included in this fixture.".into(),
            },
            file_path: FieldValue::Unknown {
                reason: "No executable path is included in this fixture.".into(),
            },
            command: FieldValue::Unknown {
                reason: "No command line is included in this fixture.".into(),
            },
            enabled: EnabledState::Unknown {
                reason: "The fixture does not represent an actual service state.".into(),
            },
            identity: EntryIdentity::WindowsService {
                name: "qa-fixture-service".into(),
            },
            can_change_enabled: false,
            change_limitation: Some("Synthetic QA fixture; no service control is available.".into()),
        }],
        association_note: "Synthetic QA fixture only. The component row is illustrative and was not associated with a real installation or native inventory.".into(),
    }
}

fn optimizer_details_for(program: Option<&Program>, key: &str) -> Dialog {
    program
        .map(|p| Dialog::Details(Arc::new(p.clone())))
        .unwrap_or_else(|| Dialog::RetainedKey(key.to_owned()))
}
fn optimizer_field(value: &FieldValue<String>) -> String {
    match value {
        FieldValue::Known { value } => value.clone(),
        FieldValue::Unknown { reason } => format!("Unavailable: {reason}"),
        FieldValue::NotApplicable => "Not applicable".into(),
    }
}
fn optimizer_detail(ui: &mut egui::Ui, label: &str, value: &str, t: Tokens) {
    ui.vertical(|ui| {
        theme::muted(ui, label, t);
        ui.add(egui::Label::new(value).wrap()).on_hover_text(value);
    });
    ui.add_space(6.);
}

fn select_optimizer_sort(current: &mut SortColumn, descending: &mut bool, selected: SortColumn) {
    if *current == selected {
        *descending = !*descending;
    } else {
        *current = selected;
        *descending = false;
    }
}

fn optimizer_sort_heading(
    ui: &mut egui::Ui,
    label: &str,
    accessible_label: &str,
    width: f32,
    selected: bool,
    descending: bool,
    t: Tokens,
) -> egui::Response {
    let text = if selected {
        format!("{label} {}", if descending { "↓" } else { "↑" })
    } else {
        label.to_owned()
    };
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 22.), egui::Sense::click());
    ui.painter().text(
        rect.left_center(),
        egui::Align2::LEFT_CENTER,
        text,
        egui::FontId::new(theme::FONT_CAPTION, theme::semibold()),
        if selected || response.hovered() {
            t.foreground
        } else {
            t.muted
        },
    );
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, true, accessible_label)
    });
    #[cfg(debug_assertions)]
    theme::record_fixture_control(ui, accessible_label, &response);
    response.on_hover_text(format!(
        "{accessible_label} in ascending or descending order"
    ))
}

#[cfg(debug_assertions)]
fn optimizer_tab_label(tab: Tab) -> &'static str {
    match tab {
        Tab::Applications => "Applications",
        Tab::Active => "Active apps",
        Tab::Sleeping => "Sleeping apps",
        Tab::Excluded => "Excluded apps",
    }
}

#[cfg(debug_assertions)]
fn optimizer_sort_label(sort: SortColumn) -> &'static str {
    match sort {
        SortColumn::Program => "Program",
        SortColumn::Publisher => "Publisher",
    }
}
