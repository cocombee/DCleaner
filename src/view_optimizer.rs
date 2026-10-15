use super::*;
use dcleaner::{
    optimizer_inventory::{self, Program, Settings, Snapshot},
    startup::FieldValue,
};

#[derive(Clone, Copy, Default, PartialEq)]
enum Tab {
    #[default]
    Applications,
    Active,
    Sleeping,
    Excluded,
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
    fn begin_optimizer_scan(&mut self, ctx: &egui::Context) {
        if self.busy() {
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
        if !self.optimizer_ui.attempted && !self.busy() {
            self.begin_optimizer_scan(ctx);
        }
        ui.horizontal_wrapped(|ui| {
            theme::tabs(ui, |ui| {
                for (tab, label) in [
                    (Tab::Applications, "Applications"),
                    (Tab::Active, "Active apps"),
                    (Tab::Sleeping, "Sleeping apps"),
                    (Tab::Excluded, "Excluded apps"),
                ] {
                    theme::tab_value(ui, &mut self.optimizer_ui.tab, tab, label);
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
        theme::control_row(ui, |ui| {
            ui.label(RichText::new("Search").color(t.muted));
            let width = ui.available_width().min(300.);
            theme::input(
                ui,
                &mut self.optimizer_ui.query,
                width,
                "Name or publisher…",
                true,
            );
            if !self.optimizer_ui.query.is_empty() && theme::field_action(ui, "Clear", true) {
                self.optimizer_ui.query.clear();
            }
        });
        ui.add_space(8.);
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
        indices.sort_by_cached_key(|i| {
            snapshot.programs[*i]
                .registration
                .display_name
                .to_lowercase()
        });
        if !excluded_tab {
            ui.label(RichText::new("Registered applications").family(theme::semibold()));
            theme::muted(
                ui,
                "Background activity and impact have not been measured. View possible background items in Details.",
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
        egui::ScrollArea::horizontal().id_salt("optimizer-table-width").auto_shrink([false,true]).show(ui,|ui| {
            let width = ui.available_width().max(560.);
            let name_width = width - 148. - 90. - 116. - 24.;
            let spacing_y = ui.spacing().item_spacing.y;
            ui.spacing_mut().item_spacing.y = 0.;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.;
                for (label,w) in [("Program",name_width),("Publisher",148.),("Impact",90.),("Actions",116.)] {
                    theme::table_cell(ui,RichText::new(label).color(t.muted).size(12.),w,22.);
                }
            });
            ui.add_space(3.); ui.separator();
            let body_height = (ctx.content_rect().bottom()-ui.cursor().top()-74.-28.-24.).max(80.);
            egui::ScrollArea::vertical().id_salt("optimizer-table-body").auto_shrink([false,false]).max_height(body_height)
                .show_rows(ui,44.,indices.len()+retained.len(),|ui,visible| {
                    for i in visible {
                        let program = indices.get(i).map(|index| &snapshot.programs[*index]);
                        let key = program.map(Program::key).unwrap_or_else(||retained[i-indices.len()].clone());
                        let name = program.map(|p|p.registration.display_name.as_str()).unwrap_or("Registration not found in this scan");
                        let excluded = self.optimizer_ui.settings_error.is_none() && self.optimizer_ui.settings.is_excluded(&key);
                        ui.push_id((&key,i),|ui| {
                            ui.allocate_ui_with_layout(Vec2::new(width,44.),Layout::left_to_right(Align::Center),|row| {
                                row.spacing_mut().item_spacing.x=8.; row.spacing_mut().item_spacing.y=spacing_y;
                                row.allocate_ui_with_layout(Vec2::new(name_width,40.),Layout::left_to_right(Align::Center),|cell| {
                                    cell.set_min_width(name_width); cell.set_max_width(name_width);
                                    cell.spacing_mut().item_spacing.x=8.;
                                    self.app_icons.show(cell,program.and_then(|p|p.registration.icon_resource()).as_deref(),22.);
                                    let response = cell.add_sized([(name_width-30.).max(80.),40.],egui::Button::new((RichText::new(name).family(theme::semibold()),egui::Atom::grow())).frame(false).truncate());
                                    if response.clicked() { self.optimizer_ui.dialog=Some(optimizer_details_for(program,&key)); }
                                    response.on_hover_text(name).on_hover_text(&key);
                                });
                                theme::table_cell(row,RichText::new(program.and_then(|p|p.registration.publisher.as_deref()).unwrap_or("Unavailable")).color(t.muted),148.,40.);
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
    pub(super) fn optimizer_dialog(&mut self, ctx: &egui::Context) {
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
            ui.heading(match &dialog {Dialog::Details(_) | Dialog::RetainedKey(_)=>"Application details",Dialog::Exclusion {excluded:true,..}=>"Exclude application?",Dialog::Exclusion {..}=>"Remove exclusion?"});
            ui.add_space(12.);
            egui::ScrollArea::vertical().id_salt("optimizer-dialog-body").max_height((ctx.content_rect().height()-190.).max(80.)).show(ui,|ui| {
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
                            egui::ScrollArea::horizontal().id_salt("optimizer-component-columns").show(ui,|ui| {
                                ui.spacing_mut().item_spacing.y=0.;
                                let width=ui.available_width().max(460.);
                                let columns=[72.,120.,width-72.-120.-78.-24.,78.];
                                ui.horizontal(|ui| {ui.spacing_mut().item_spacing.x=8.; for (label,w) in ["Type","Program","File path","State"].into_iter().zip(columns) {theme::table_cell(ui,RichText::new(label).color(t.muted),w,22.);} });
                                egui::ScrollArea::vertical().id_salt("optimizer-component-rows").max_height(176.).show_rows(ui,44.,program.candidates.len(),|ui,range| {
                                    for index in range {let entry=&program.candidates[index];
                                        let state=match &entry.enabled {dcleaner::startup::EnabledState::Enabled=>"Enabled",dcleaner::startup::EnabledState::Disabled=>"Disabled",dcleaner::startup::EnabledState::Unknown {..}=>"Unavailable"};
                                        ui.horizontal(|ui| {ui.spacing_mut().item_spacing.x=8.; for (text,w) in [entry.section.label().to_owned(),optimizer_field(&entry.program),optimizer_field(&entry.file_path),state.into()].into_iter().zip(columns) {theme::table_cell(ui,text.clone(),w,44.).on_hover_text(text);} });
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
                    if theme::primary(ui,if *excluded {"Exclude app"} else {"Remove exclusion"},t,!busy && self.optimizer_ui.settings_error.is_none()) {save=Some((key.clone(),*excluded));}
                }
            });
        });
        if can_close && (close || response.should_close()) {
            self.optimizer_ui.dialog = None;
        } else if let Some((key, excluded)) = save {
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
