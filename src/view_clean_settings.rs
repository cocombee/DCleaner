use super::{App, Event};
use crate::theme::{self, Tokens};
use dcleaner::{
    clean_settings::{
        CustomCleanSettings, ExclusionRule, ExclusionType, FileDeletionMode, FolderInclusion,
        InclusionLocation, InclusionRule, OverwriteType, WipeDrivePreference, load_settings,
        save_settings,
    },
    custom_clean::rule_id_for_inclusion,
};
use eframe::egui::{self, Align, Layout, RichText};
use std::{sync::mpsc, thread};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SettingsTab {
    #[default]
    Inclusions,
    Exclusions,
    RulesAndAge,
    Deletion,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum InclusionKind {
    #[default]
    File,
    Folder,
}

#[derive(Default)]
struct InclusionForm {
    kind: InclusionKind,
    location: String,
    filter: String,
    age_hours: String,
    recursive: bool,
    delete_self: bool,
    editing_index: Option<usize>,
}

pub(super) struct CleanSettingsUi {
    open: bool,
    operation: SettingsOperation,
    saved: Option<CustomCleanSettings>,
    draft: Option<CustomCleanSettings>,
    tab: SettingsTab,
    inclusion_form: InclusionForm,
    exclusion_type: ExclusionType,
    exclusion_value: String,
    exclusion_editing_index: Option<usize>,
    skipped_rule_id: String,
    drive_letter: String,
    form_error: Option<String>,
    load_error: Option<String>,
    save_error: Option<String>,
}

impl Default for CleanSettingsUi {
    fn default() -> Self {
        Self {
            open: false,
            operation: SettingsOperation::Idle,
            saved: None,
            draft: None,
            tab: SettingsTab::Inclusions,
            inclusion_form: InclusionForm::default(),
            exclusion_type: ExclusionType::File,
            exclusion_value: String::new(),
            exclusion_editing_index: None,
            skipped_rule_id: String::new(),
            drive_letter: String::new(),
            form_error: None,
            load_error: None,
            save_error: None,
        }
    }
}

impl CleanSettingsUi {
    pub(super) fn from_saved(result: Result<CustomCleanSettings, String>) -> Self {
        let mut state = Self::default();
        match result {
            Ok(settings) => state.saved = Some(settings),
            Err(error) => state.load_error = Some(error),
        }
        state
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SettingsOperation {
    #[default]
    Idle,
    Loading,
    Saving,
}

pub(super) enum CleanSettingsEvent {
    Loaded(Result<CustomCleanSettings, String>),
    Saved(Result<CustomCleanSettings, String>),
}

impl App {
    /// Call from the Custom Clean page to open its saved-settings editor.
    pub(super) fn clean_settings_configure_button(
        &mut self,
        ui: &mut egui::Ui,
        _t: Tokens,
        ctx: &egui::Context,
    ) {
        if theme::field_action(ui, "Configure", !self.busy()) {
            self.clean_settings_ui.open = true;
            self.clean_settings_ui.form_error = None;
            self.clean_settings_ui.load_error = None;
            self.clean_settings_ui.save_error = None;
            self.start_clean_settings_load(ctx);
        }
    }

    /// Last successfully loaded and saved settings for scanner integration.
    pub(super) fn clean_settings_snapshot(&self) -> Option<&CustomCleanSettings> {
        self.clean_settings_ui.saved.as_ref()
    }

    /// The `.custom` opt-in is deliberately false until the user saves `true`.
    pub(super) fn custom_clean_enabled(&self) -> bool {
        self.clean_settings_snapshot()
            .and_then(|settings| settings.rule_selection(".custom"))
            == Some(true)
    }

    pub(super) fn clean_settings_dialog(&mut self, ctx: &egui::Context) {
        if !self.clean_settings_ui.open {
            return;
        }
        if self.clean_settings_ui.operation == SettingsOperation::Idle
            && ctx.input(|input| input.key_pressed(egui::Key::Escape))
        {
            self.close_clean_settings_dialog();
            return;
        }

        let t = theme::tokens(self.prefs.dark);
        let busy = self.clean_settings_ui.operation != SettingsOperation::Idle;
        let editable = !busy && self.clean_settings_ui.draft.is_some();
        let body_height = (ctx.content_rect().height() - 245.).max(190.);
        let width = (ctx.content_rect().width() - 48.).clamp(360., 760.);
        let mut close = false;
        let mut retry = false;
        let mut submit = false;

        let response = egui::Modal::new(egui::Id::new("custom-clean-settings"))
            .frame(theme::dialog_frame(t))
            .show(ctx, |ui| {
                ui.set_width(width);
                ui.heading("Custom Clean settings");
                ui.add_space(4.);
                theme::muted(
                    ui,
                    "Edit scan rules and saved preferences. This form does not run cleanup actions.",
                    t,
                );
                ui.add_space(12.);

                if self.clean_settings_ui.operation == SettingsOperation::Loading {
                    theme::muted(ui, "Reading saved settings…", t);
                } else if self.clean_settings_ui.operation == SettingsOperation::Saving {
                    theme::muted(ui, "Saving settings…", t);
                }

                if let Some(error) = &self.clean_settings_ui.load_error {
                    ui.colored_label(t.attention, "Saved settings could not be read.");
                    ui.add(egui::Label::new(RichText::new(error).size(12.).color(t.muted)).wrap());
                    theme::muted(
                        ui,
                        "The original settings file is preserved. Correct the issue before saving changes.",
                        t,
                    );
                    retry = theme::field_action(ui, "Retry", !busy);
                } else if self.clean_settings_ui.draft.is_some() {
                    self.clean_settings_tabs(ui, t, editable);
                    ui.add_space(8.);
                    egui::ScrollArea::vertical()
                        .id_salt("custom-clean-settings-body")
                        .max_height(body_height)
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            match self.clean_settings_ui.tab {
                                SettingsTab::Inclusions => {
                                    self.inclusions_editor(ui, t, editable)
                                }
                                SettingsTab::Exclusions => {
                                    self.exclusions_editor(ui, t, editable)
                                }
                                SettingsTab::RulesAndAge => {
                                    self.rules_and_age_editor(ui, t, editable)
                                }
                                SettingsTab::Deletion => {
                                    self.deletion_editor(ui, t, editable)
                                }
                            }
                        });
                }

                if let Some(error) = &self.clean_settings_ui.form_error {
                    ui.add_space(6.);
                    ui.colored_label(t.attention, error);
                }
                if let Some(error) = &self.clean_settings_ui.save_error {
                    ui.add_space(6.);
                    ui.colored_label(t.attention, format!("Settings were not saved: {error}"));
                }

                ui.add_space(10.);
                ui.separator();
                ui.add_space(8.);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    submit = theme::primary(
                        ui,
                        "Save settings",
                        t,
                        editable && self.clean_settings_ui.load_error.is_none(),
                    );
                    close = theme::secondary(ui, "Cancel", !busy);
                });
            });

        if retry {
            self.clean_settings_ui.load_error = None;
            self.start_clean_settings_load(ctx);
        } else if submit {
            self.begin_save_clean_settings(ctx);
        } else if close || (response.should_close() && !busy) {
            self.close_clean_settings_dialog();
        }
    }

    pub(super) fn clean_settings_event(&mut self, event: CleanSettingsEvent) {
        match event {
            CleanSettingsEvent::Loaded(result) => {
                self.worker = None;
                self.clean_settings_ui.operation = SettingsOperation::Idle;
                match result {
                    Ok(settings) => {
                        self.clean_settings_ui.saved = Some(settings.clone());
                        self.clean_settings_ui.draft = Some(settings);
                        self.clean_settings_ui.load_error = None;
                        self.clean_settings_ui.save_error = None;
                    }
                    Err(error) => {
                        self.clean_settings_ui.saved = None;
                        self.clean_settings_ui.draft = None;
                        self.clean_settings_ui.load_error = Some(error);
                    }
                }
            }
            CleanSettingsEvent::Saved(result) => {
                self.worker = None;
                self.clean_settings_ui.operation = SettingsOperation::Idle;
                match result {
                    Ok(settings) => {
                        self.clean_settings_ui.saved = Some(settings.clone());
                        self.clean_settings_ui.draft = Some(settings);
                        self.clean_settings_ui.save_error = None;
                        self.clean_settings_ui.open = false;
                        self.invalidate();
                        self.custom_analysis = None;
                        self.notice = Some(
                            "Custom Clean settings saved. Scan again to review the updated rules."
                                .into(),
                        );
                    }
                    Err(error) => self.clean_settings_ui.save_error = Some(error),
                }
            }
        }
    }

    fn start_clean_settings_load(&mut self, ctx: &egui::Context) {
        if self.clean_settings_ui.operation != SettingsOperation::Idle || self.busy() {
            return;
        }
        let root = self.data_dir.clone();
        let context = ctx.clone();
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        self.clean_settings_ui.operation = SettingsOperation::Loading;
        thread::spawn(move || {
            let result = load_settings(&root).map_err(|error| error.to_string());
            let _ = sender.send(Event::CleanSettings(CleanSettingsEvent::Loaded(result)));
            context.request_repaint();
        });
    }

    fn begin_save_clean_settings(&mut self, ctx: &egui::Context) {
        let Some(settings) = self.clean_settings_ui.draft.as_ref() else {
            return;
        };
        if let Err(error) = settings.validate() {
            self.clean_settings_ui.form_error = Some(error.to_string());
            return;
        }
        if self.clean_settings_ui.operation != SettingsOperation::Idle || self.busy() {
            return;
        }
        let settings = settings.clone();
        let root = self.data_dir.clone();
        let context = ctx.clone();
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        self.clean_settings_ui.operation = SettingsOperation::Saving;
        self.clean_settings_ui.form_error = None;
        self.clean_settings_ui.save_error = None;
        thread::spawn(move || {
            let result = save_settings(&root, &settings)
                .and_then(|_| load_settings(&root))
                .map_err(|error| error.to_string());
            let _ = sender.send(Event::CleanSettings(CleanSettingsEvent::Saved(result)));
            context.request_repaint();
        });
    }

    fn close_clean_settings_dialog(&mut self) {
        self.clean_settings_ui.open = false;
        self.clean_settings_ui.draft = self.clean_settings_ui.saved.clone();
        self.clean_settings_ui.form_error = None;
        self.clean_settings_ui.save_error = None;
    }

    fn clean_settings_tabs(&mut self, ui: &mut egui::Ui, _t: Tokens, enabled: bool) {
        theme::tabs(ui, |ui| {
            ui.add_enabled_ui(enabled, |ui| {
                if theme::tab(
                    ui,
                    self.clean_settings_ui.tab == SettingsTab::Inclusions,
                    "Inclusions",
                )
                .clicked()
                {
                    self.clean_settings_ui.tab = SettingsTab::Inclusions;
                }
                if theme::tab(
                    ui,
                    self.clean_settings_ui.tab == SettingsTab::Exclusions,
                    "Exclusions",
                )
                .clicked()
                {
                    self.clean_settings_ui.tab = SettingsTab::Exclusions;
                }
                if theme::tab(
                    ui,
                    self.clean_settings_ui.tab == SettingsTab::RulesAndAge,
                    "Rules & age",
                )
                .clicked()
                {
                    self.clean_settings_ui.tab = SettingsTab::RulesAndAge;
                }
                if theme::tab(
                    ui,
                    self.clean_settings_ui.tab == SettingsTab::Deletion,
                    "Deletion",
                )
                .clicked()
                {
                    self.clean_settings_ui.tab = SettingsTab::Deletion;
                }
            });
        });
    }

    fn inclusions_editor(&mut self, ui: &mut egui::Ui, t: Tokens, editable: bool) {
        ui.label(RichText::new("Add a location").family(theme::semibold()));
        ui.add_space(6.);
        let kind_choices = ["File", "Folder"];
        let selected_kind = match self.clean_settings_ui.inclusion_form.kind {
            InclusionKind::File => "File",
            InclusionKind::Folder => "Folder",
        };
        let mut kind_changed = None;
        theme::control_row(ui, |ui| {
            theme::muted(ui, "Location type", t);
            theme::selector(
                ui,
                "clean-inclusion-kind",
                selected_kind,
                &kind_choices,
                |ui| {
                    if ui
                        .selectable_label(selected_kind == "File", "File")
                        .clicked()
                    {
                        kind_changed = Some(InclusionKind::File);
                    }
                    if ui
                        .selectable_label(selected_kind == "Folder", "Folder")
                        .clicked()
                    {
                        kind_changed = Some(InclusionKind::Folder);
                    }
                },
            );
        });
        if let Some(kind) = kind_changed {
            self.clean_settings_ui.inclusion_form.kind = kind;
        }
        ui.add_space(4.);
        theme::muted(
            ui,
            match self.clean_settings_ui.inclusion_form.kind {
                InclusionKind::File => "File path",
                InclusionKind::Folder => "Folder path",
            },
            t,
        );
        let location_width = ui.available_width();
        theme::input(
            ui,
            &mut self.clean_settings_ui.inclusion_form.location,
            location_width,
            r"C:\path\to\item",
            editable,
        );

        if self.clean_settings_ui.inclusion_form.kind == InclusionKind::Folder {
            ui.add_space(6.);
            theme::muted(ui, "File filters (optional, separated by semicolons)", t);
            let filter_width = ui.available_width();
            theme::input(
                ui,
                &mut self.clean_settings_ui.inclusion_form.filter,
                filter_width,
                "*.tmp; *.cache",
                editable,
            );
            theme::control_row(ui, |ui| {
                if theme::checkbox(
                    ui,
                    &mut self.clean_settings_ui.inclusion_form.recursive,
                    "Include subfolders",
                    editable,
                )
                .changed()
                    && !self.clean_settings_ui.inclusion_form.recursive
                {
                    self.clean_settings_ui.inclusion_form.delete_self = false;
                }
                if theme::checkbox(
                    ui,
                    &mut self.clean_settings_ui.inclusion_form.delete_self,
                    "Delete the folder itself",
                    editable,
                )
                .changed()
                    && self.clean_settings_ui.inclusion_form.delete_self
                {
                    self.clean_settings_ui.inclusion_form.recursive = true;
                }
            });
            theme::muted(
                ui,
                "Folder contents use recursion, filters, and age limits during scanning. Selecting folder removal blocks cleanup for this rule until that effect is supported.",
                t,
            );
        }

        if self.clean_settings_ui.inclusion_form.kind == InclusionKind::Folder {
            ui.add_space(6.);
            theme::muted(ui, "Minimum age for this rule (hours, optional)", t);
            let age_width = ui.available_width().min(220.);
            theme::input(
                ui,
                &mut self.clean_settings_ui.inclusion_form.age_hours,
                age_width,
                "1 to 10000, or leave blank",
                editable,
            );
        }
        ui.add_space(8.);
        let submit_label = if self
            .clean_settings_ui
            .inclusion_form
            .editing_index
            .is_some()
        {
            "Update location"
        } else {
            "Add location"
        };
        if theme::field_action(ui, submit_label, editable) {
            self.add_inclusion();
        }
        if self
            .clean_settings_ui
            .inclusion_form
            .editing_index
            .is_some()
            && theme::field_action(ui, "Cancel edit", editable)
        {
            self.clean_settings_ui.inclusion_form = InclusionForm::default();
        }
        ui.add_space(12.);
        ui.separator();
        ui.add_space(8.);
        ui.label(RichText::new("Included locations").family(theme::semibold()));
        let Some(draft) = self.clean_settings_ui.draft.as_mut() else {
            return;
        };
        if draft.inclusions.is_empty() {
            theme::muted(ui, "No custom file or folder locations are saved.", t);
        }
        let mut remove = None;
        let mut edit = None;
        let mut selection_changes = Vec::new();
        for (index, rule) in draft.inclusions.iter().enumerate() {
            ui.add_space(6.);
            ui.horizontal(|ui| {
                let id = rule_id_for_inclusion(rule);
                let mut selected = draft.rule_selection(&id).unwrap_or(true);
                if theme::checkbox(ui, &mut selected, "", editable).changed() {
                    selection_changes.push((id, selected));
                }
                ui.vertical(|ui| {
                    ui.add(
                        egui::Label::new(RichText::new(inclusion_location(rule)).strong())
                            .truncate(),
                    )
                    .on_hover_text(inclusion_location(rule));
                    let detail = inclusion_detail(rule);
                    theme::muted(ui, detail, t);
                });
                if theme::field_action(ui, "Edit", editable) {
                    edit = Some(index);
                }
                if theme::field_action(ui, "Remove", editable) {
                    remove = Some(index);
                }
            });
            ui.separator();
        }
        for (id, selected) in selection_changes {
            let _ = draft.set_rule_selection(&id, Some(selected));
        }
        if let Some(index) = remove {
            if index < draft.inclusions.len() {
                let id = rule_id_for_inclusion(&draft.inclusions[index]);
                let _ = draft.set_rule_selection(&id, None);
                draft.inclusions.remove(index);
                match self.clean_settings_ui.inclusion_form.editing_index {
                    Some(editing) if editing == index => {
                        self.clean_settings_ui.inclusion_form = InclusionForm::default();
                    }
                    Some(editing) if editing > index => {
                        self.clean_settings_ui.inclusion_form.editing_index = Some(editing - 1);
                    }
                    _ => {}
                }
            }
        }
        if let Some(index) = edit.filter(|index| Some(*index) != remove) {
            if let Some(rule) = draft.inclusions.get(index) {
                let mut form = InclusionForm {
                    editing_index: Some(index),
                    age_hours: rule
                        .age_threshold_hours
                        .map_or_else(String::new, |hours| hours.to_string()),
                    ..InclusionForm::default()
                };
                match &rule.location {
                    InclusionLocation::File(path) => {
                        form.kind = InclusionKind::File;
                        form.location = path.clone();
                    }
                    InclusionLocation::Folder(folder) => {
                        form.kind = InclusionKind::Folder;
                        form.location = folder.folder.clone();
                        form.filter = folder
                            .filter
                            .as_ref()
                            .map_or_else(String::new, |filters| filters.join("; "));
                        form.recursive = folder.recursive;
                        form.delete_self = folder.delete_self;
                    }
                }
                self.clean_settings_ui.inclusion_form = form;
            }
        }
    }

    fn add_inclusion(&mut self) {
        let form = &self.clean_settings_ui.inclusion_form;
        let location = form.location.trim();
        if location.is_empty() {
            self.clean_settings_ui.form_error = Some("Enter a file or folder path.".into());
            return;
        }
        let age_threshold_hours =
            if form.kind == InclusionKind::File || form.age_hours.trim().is_empty() {
                None
            } else {
                match form.age_hours.trim().parse::<u32>() {
                    Ok(hours) if (1..=10000).contains(&hours) => Some(f64::from(hours)),
                    _ => {
                        self.clean_settings_ui.form_error = Some(
                            "Enter a whole number from 1 to 10000 hours, or leave the field blank."
                                .into(),
                        );
                        return;
                    }
                }
            };
        let location = match form.kind {
            InclusionKind::File => InclusionLocation::File(location.to_owned()),
            InclusionKind::Folder => {
                let filters: Vec<String> = form
                    .filter
                    .split(';')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                    .map(ToOwned::to_owned)
                    .collect();
                InclusionLocation::Folder(FolderInclusion {
                    folder: location.to_owned(),
                    filter: (!filters.is_empty()).then_some(filters),
                    delete_self: form.delete_self,
                    recursive: form.recursive,
                })
            }
        };
        let rule = InclusionRule {
            location,
            age_threshold_hours,
        };
        let Some(draft) = self.clean_settings_ui.draft.as_mut() else {
            return;
        };
        let old_selection = form.editing_index.and_then(|index| {
            draft
                .inclusions
                .get(index)
                .map(rule_id_for_inclusion)
                .and_then(|id| draft.rule_selection(&id))
        });
        let old_rule = form.editing_index.and_then(|index| {
            draft
                .inclusions
                .get(index)
                .cloned()
                .map(|rule| (index, rule))
        });
        let old_identity = old_rule.as_ref().map(|(_, old)| rule_id_for_inclusion(old));
        if let Some((index, _)) = &old_rule {
            draft.inclusions[*index] = rule;
        } else {
            draft.inclusions.push(rule);
        }
        if let Err(error) = draft.validate() {
            if let Some((index, old)) = old_rule {
                draft.inclusions[index] = old;
            } else {
                draft.inclusions.pop();
            }
            self.clean_settings_ui.form_error = Some(error.to_string());
            return;
        }
        if let Some(old_identity) = old_identity {
            let new_identity =
                rule_id_for_inclusion(&draft.inclusions[form.editing_index.unwrap()]);
            if old_identity != new_identity {
                if let Some(selected) = old_selection {
                    let _ = draft.set_rule_selection(&new_identity, Some(selected));
                }
                let _ = draft.set_rule_selection(&old_identity, None);
            }
        }
        self.clean_settings_ui.inclusion_form.location.clear();
        self.clean_settings_ui.inclusion_form.filter.clear();
        self.clean_settings_ui.inclusion_form.age_hours.clear();
        self.clean_settings_ui.inclusion_form.delete_self = false;
        self.clean_settings_ui.inclusion_form.recursive = false;
        self.clean_settings_ui.inclusion_form.editing_index = None;
        self.clean_settings_ui.form_error = None;
    }

    fn exclusions_editor(&mut self, ui: &mut egui::Ui, t: Tokens, editable: bool) {
        ui.label(RichText::new("Protect paths and data").family(theme::semibold()));
        ui.add_space(4.);
        theme::muted(
            ui,
            "File and path exclusions are applied by the current Custom Clean scanner. Registry and cookie exclusions are saved for future support only.",
            t,
        );
        ui.add_space(10.);
        let type_choices = [
            "File",
            "Path",
            "Registry key",
            "Registry key value",
            "Cookie domain",
        ];
        let selected_type = exclusion_type_label(self.clean_settings_ui.exclusion_type);
        let mut selected_new_type = None;
        theme::control_row(ui, |ui| {
            theme::muted(ui, "Protection type", t);
            theme::selector(
                ui,
                "clean-exclusion-type",
                selected_type,
                &type_choices,
                |ui| {
                    for kind in [
                        ExclusionType::File,
                        ExclusionType::Path,
                        ExclusionType::RegistryKey,
                        ExclusionType::RegistryKeyValue,
                        ExclusionType::Cookie,
                    ] {
                        let label = exclusion_type_label(kind);
                        if ui.selectable_label(selected_type == label, label).clicked() {
                            selected_new_type = Some(kind);
                        }
                    }
                },
            );
        });
        if let Some(kind) = selected_new_type {
            self.clean_settings_ui.exclusion_type = kind;
        }
        ui.add_space(6.);
        let value_hint = if self.clean_settings_ui.exclusion_type == ExclusionType::Cookie {
            "example.com"
        } else {
            r"C:\path, registry key or value"
        };
        let value_width = ui.available_width();
        theme::input(
            ui,
            &mut self.clean_settings_ui.exclusion_value,
            value_width,
            value_hint,
            editable,
        );
        ui.add_space(6.);
        let submit_label = if self.clean_settings_ui.exclusion_editing_index.is_some() {
            "Update protection"
        } else {
            "Add protection"
        };
        if theme::field_action(ui, submit_label, editable) {
            self.add_exclusion();
        }
        if self.clean_settings_ui.exclusion_editing_index.is_some()
            && theme::field_action(ui, "Cancel edit", editable)
        {
            self.clean_settings_ui.exclusion_editing_index = None;
            self.clean_settings_ui.exclusion_value.clear();
            self.clean_settings_ui.exclusion_type = ExclusionType::File;
        }
        ui.add_space(12.);
        ui.separator();
        ui.add_space(8.);
        ui.label(RichText::new("Protected entries").family(theme::semibold()));
        let Some(draft) = self.clean_settings_ui.draft.as_mut() else {
            return;
        };
        if draft.exclusions.is_empty() {
            theme::muted(ui, "No protected entries are saved.", t);
        }
        let mut remove = None;
        let mut edit = None;
        for (index, rule) in draft.exclusions.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.add(egui::Label::new(RichText::new(&rule.path).strong()).truncate())
                        .on_hover_text(&rule.path);
                    ui.horizontal(|ui| {
                        theme::muted(ui, exclusion_type_label(rule.exclusion_type), t);
                        if exclusions_supported(rule.exclusion_type) {
                            theme::muted(ui, "Applied to the current scan", t);
                        } else {
                            ui.label(RichText::new("Stored only").size(11.).color(t.attention));
                        }
                    });
                });
                if theme::field_action(ui, "Edit", editable) {
                    edit = Some(index);
                }
                if theme::field_action(ui, "Remove", editable) {
                    remove = Some(index);
                }
            });
            ui.separator();
        }
        if let Some(index) = remove {
            if index < draft.exclusions.len() {
                draft.exclusions.remove(index);
                match self.clean_settings_ui.exclusion_editing_index {
                    Some(editing) if editing == index => {
                        self.clean_settings_ui.exclusion_editing_index = None;
                        self.clean_settings_ui.exclusion_value.clear();
                        self.clean_settings_ui.exclusion_type = ExclusionType::File;
                    }
                    Some(editing) if editing > index => {
                        self.clean_settings_ui.exclusion_editing_index = Some(editing - 1);
                    }
                    _ => {}
                }
            }
        }
        if let Some(index) = edit.filter(|index| Some(*index) != remove) {
            if let Some(rule) = draft.exclusions.get(index) {
                self.clean_settings_ui.exclusion_type = rule.exclusion_type;
                self.clean_settings_ui.exclusion_value = rule.path.clone();
                self.clean_settings_ui.exclusion_editing_index = Some(index);
            }
        }
    }

    fn add_exclusion(&mut self) {
        let path = self.clean_settings_ui.exclusion_value.trim();
        if path.is_empty() {
            self.clean_settings_ui.form_error = Some("Enter a path, key or cookie domain.".into());
            return;
        }
        let Some(draft) = self.clean_settings_ui.draft.as_mut() else {
            return;
        };
        let rule = ExclusionRule {
            exclusion_type: self.clean_settings_ui.exclusion_type,
            path: path.to_owned(),
        };
        let old_rule = self
            .clean_settings_ui
            .exclusion_editing_index
            .and_then(|index| draft.exclusions.get(index).cloned().map(|old| (index, old)));
        if let Some((index, _)) = &old_rule {
            draft.exclusions[*index] = rule;
        } else {
            draft.exclusions.push(rule);
        }
        if let Err(error) = draft.validate() {
            if let Some((index, old)) = old_rule {
                draft.exclusions[index] = old;
            } else {
                draft.exclusions.pop();
            }
            self.clean_settings_ui.form_error = Some(error.to_string());
            return;
        }
        self.clean_settings_ui.exclusion_value.clear();
        self.clean_settings_ui.exclusion_editing_index = None;
        self.clean_settings_ui.form_error = None;
    }

    fn rules_and_age_editor(&mut self, ui: &mut egui::Ui, t: Tokens, editable: bool) {
        ui.label(RichText::new("Age policy").family(theme::semibold()));
        ui.add_space(6.);
        let CleanSettingsUi {
            draft,
            skipped_rule_id,
            form_error,
            ..
        } = &mut self.clean_settings_ui;
        let Some(draft) = draft.as_mut() else {
            return;
        };
        theme::checkbox(
            ui,
            &mut draft.file_deletion.temp_folders_only_older_than_24h,
            "Only include Windows temporary files older than 24 hours",
            editable,
        );
        theme::muted(
            ui,
            "Applied by the current scanner to the supported temporary-file rules.",
            t,
        );
        let mut custom_enabled = draft.rule_selection(".custom") == Some(true);
        if theme::checkbox(
            ui,
            &mut custom_enabled,
            "Include custom file and folder rules in scans",
            editable,
        )
        .changed()
        {
            let _ = draft.set_rule_selection(".custom", Some(custom_enabled));
        }
        theme::muted(
            ui,
            "Custom locations stay inactive until this option is saved on.",
            t,
        );
        if !custom_enabled {
            ui.label(
                RichText::new("Rule checkboxes below are saved choices; scanning remains off until custom locations are enabled.")
                    .size(11.)
                    .color(t.muted),
            );
        }
        ui.add_space(6.);
        theme::checkbox(
            ui,
            &mut draft.file_deletion.recycle_bin_only_older_than_24h,
            "Only include Recycle Bin items older than 24 hours",
            editable,
        );
        ui.label(
            RichText::new(
                "Stored only · the Recycle Bin view does not currently consume this preference.",
            )
            .size(11.)
            .color(t.attention),
        );

        ui.add_space(14.);
        ui.separator();
        ui.add_space(8.);
        ui.label(RichText::new("Location rule choices").family(theme::semibold()));
        if draft.inclusions.is_empty() {
            theme::muted(
                ui,
                "Add a file or folder on the Inclusions tab to configure its rule.",
                t,
            );
        }
        let mut remove_indices = Vec::new();
        let mut selection_changes = Vec::new();
        for (index, rule) in draft.inclusions.iter().enumerate() {
            ui.horizontal(|ui| {
                let id = rule_id_for_inclusion(rule);
                let mut enabled = draft.rule_selection(&id).unwrap_or(true);
                if theme::checkbox(ui, &mut enabled, "", editable).changed() {
                    selection_changes.push((id, enabled));
                }
                ui.vertical(|ui| {
                    ui.add(egui::Label::new(inclusion_location(rule)).truncate())
                        .on_hover_text(inclusion_location(rule));
                    let age = rule.age_threshold_hours.map_or_else(
                        || "No age filter".to_owned(),
                        |hours| format!("At least {hours} hours old"),
                    );
                    theme::muted(ui, age, t);
                });
                if theme::field_action(ui, "Remove rule", editable) {
                    remove_indices.push(index);
                }
            });
            ui.separator();
        }
        for (id, enabled) in selection_changes {
            let _ = draft.set_rule_selection(&id, Some(enabled));
        }
        for index in remove_indices.into_iter().rev() {
            if index < draft.inclusions.len() {
                let id = rule_id_for_inclusion(&draft.inclusions[index]);
                let _ = draft.set_rule_selection(&id, None);
                draft.inclusions.remove(index);
            }
        }

        ui.add_space(14.);
        ui.separator();
        ui.add_space(8.);
        ui.label(RichText::new("Close-process preferences").family(theme::semibold()));
        theme::muted(
            ui,
            "These IDs are preserved for compatibility. Custom Clean does not close running applications.",
            t,
        );
        let skipped_width = ui.available_width();
        theme::input(
            ui,
            skipped_rule_id,
            skipped_width,
            "Rule identity",
            editable,
        );
        if theme::field_action(ui, "Add skipped rule", editable) {
            let id = skipped_rule_id.trim().to_owned();
            if id.is_empty() {
                *form_error = Some("Enter a rule identity.".into());
            } else if draft
                .skipped_close_programs
                .iter()
                .any(|existing| existing == &id)
            {
                *form_error = Some("That rule identity is already saved.".into());
            } else {
                draft.skipped_close_programs.push(id);
                if let Err(error) = draft.validate() {
                    draft.skipped_close_programs.pop();
                    *form_error = Some(error.to_string());
                } else {
                    skipped_rule_id.clear();
                    *form_error = None;
                }
            }
        }
        let mut remove_skipped = None;
        for (index, id) in draft.skipped_close_programs.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(id);
                if theme::field_action(ui, "Remove", editable) {
                    remove_skipped = Some(index);
                }
            });
        }
        if let Some(index) = remove_skipped {
            if index < draft.skipped_close_programs.len() {
                draft.skipped_close_programs.remove(index);
            }
        }
        theme::checkbox(
            ui,
            &mut draft.skip_show_registry_attention,
            "Suppress the registry attention prompt",
            editable,
        );
        theme::checkbox(
            ui,
            &mut draft.shutdown_after_cleaning,
            "Shut down after cleaning",
            editable,
        );
        theme::muted(
            ui,
            "Stored only · these preferences do not suppress warnings or shut down the computer.",
            t,
        );
    }

    fn deletion_editor(&mut self, ui: &mut egui::Ui, t: Tokens, editable: bool) {
        ui.label(RichText::new("File deletion preferences").family(theme::semibold()));
        ui.add_space(4.);
        theme::muted(
            ui,
            "These choices are saved preferences. Current cleanup uses its reviewed Recycle Bin flow and does not perform secure deletion or drive wiping.",
            t,
        );
        ui.add_space(10.);
        let state = &mut self.clean_settings_ui;
        let Some(draft) = state.draft.as_mut() else {
            return;
        };
        Self::advanced_options(
            ui,
            t,
            editable,
            draft,
            &mut state.drive_letter,
            &mut state.form_error,
        );
    }

    fn advanced_options(
        ui: &mut egui::Ui,
        t: Tokens,
        editable: bool,
        settings: &mut CustomCleanSettings,
        drive_letter: &mut String,
        form_error: &mut Option<String>,
    ) {
        {
            let options = &mut settings.advanced_filter_options;
            let deletion_choices = ["Normal", "Secure"];
            let selected_deletion = match options.file_deletion {
                FileDeletionMode::Normal => "Normal",
                FileDeletionMode::Secure => "Secure",
            };
            let mut new_deletion = None;
            theme::control_row(ui, |ui| {
                theme::muted(ui, "Deletion mode", t);
                theme::selector(
                    ui,
                    "clean-deletion-mode",
                    selected_deletion,
                    &deletion_choices,
                    |ui| {
                        if ui
                            .selectable_label(selected_deletion == "Normal", "Normal")
                            .clicked()
                        {
                            new_deletion = Some(FileDeletionMode::Normal);
                        }
                        if ui
                            .selectable_label(selected_deletion == "Secure", "Secure")
                            .clicked()
                        {
                            new_deletion = Some(FileDeletionMode::Secure);
                        }
                    },
                );
            });
            if let Some(mode) = new_deletion {
                options.file_deletion = mode;
            }
            theme::muted(
                ui,
                "Normal uses the reviewed Trash flow. Secure deletion is stored only and blocks cleanup while selected.",
                t,
            );

            ui.add_space(8.);
            let overwrite_choices = [
                "Disabled",
                "Single pass",
                "Three passes",
                "Seven passes",
                "Thirty-five passes",
            ];
            let selected_overwrite = overwrite_label(options.overwrite_type);
            let mut new_overwrite = None;
            theme::control_row(ui, |ui| {
                theme::muted(ui, "Overwrite pattern", t);
                theme::selector(
                    ui,
                    "clean-overwrite-pattern",
                    selected_overwrite,
                    &overwrite_choices,
                    |ui| {
                        for value in [
                            OverwriteType::Disabled,
                            OverwriteType::SinglePass,
                            OverwriteType::ThreePass,
                            OverwriteType::SevenPass,
                            OverwriteType::ThirtyFivePass,
                        ] {
                            let label = overwrite_label(value);
                            if ui
                                .selectable_label(selected_overwrite == label, label)
                                .clicked()
                            {
                                new_overwrite = Some(value);
                            }
                        }
                    },
                );
            });
            if let Some(overwrite) = new_overwrite {
                options.overwrite_type = overwrite;
            }
            theme::muted(
                ui,
                "Stored only · overwrite passes are not supported by the current cleaner.",
                t,
            );

            ui.add_space(10.);
            theme::checkbox(
                ui,
                &mut options.wipe_free_space,
                "Wipe free space",
                editable,
            );
            theme::checkbox(
                ui,
                &mut options.wipe_alternate_data_streams,
                "Wipe alternate data streams",
                editable,
            );
            theme::muted(
                ui,
                "Stored only · no free-space or stream wipe is performed.",
                t,
            );
        }

        ui.add_space(12.);
        ui.separator();
        ui.add_space(8.);
        ui.label(RichText::new("Per-drive MFT preferences").family(theme::semibold()));
        theme::muted(
            ui,
            "Drive wipe and MFT flags are preserved but are not applied.",
            t,
        );
        theme::input(
            ui,
            drive_letter,
            180.,
            "Drive letter, for example C",
            editable,
        );
        if theme::field_action(ui, "Add drive", editable) {
            let drive = drive_letter.trim().trim_end_matches(':').to_owned();
            let duplicate = settings
                .advanced_filter_options
                .wipe_free_space_drives
                .iter()
                .any(|entry| entry.drive.eq_ignore_ascii_case(&drive));
            if drive.len() != 1 || !drive.as_bytes()[0].is_ascii_alphabetic() {
                *form_error = Some("Enter one drive letter, such as C.".into());
            } else if duplicate {
                *form_error = Some("That drive already has a saved preference.".into());
            } else {
                settings
                    .advanced_filter_options
                    .wipe_free_space_drives
                    .push(WipeDrivePreference {
                        drive,
                        wipe_mft_free_space: false,
                    });
                if let Err(error) = settings.validate() {
                    settings
                        .advanced_filter_options
                        .wipe_free_space_drives
                        .pop();
                    *form_error = Some(error.to_string());
                } else {
                    drive_letter.clear();
                    *form_error = None;
                }
            }
        }

        let mut remove_drive = None;
        for (index, drive) in settings
            .advanced_filter_options
            .wipe_free_space_drives
            .iter_mut()
            .enumerate()
        {
            ui.horizontal(|ui| {
                ui.label(format!("{}:", drive.drive.to_ascii_uppercase()));
                theme::checkbox(
                    ui,
                    &mut drive.wipe_mft_free_space,
                    "Wipe MFT free space",
                    editable,
                );
                if theme::field_action(ui, "Remove", editable) {
                    remove_drive = Some(index);
                }
            });
        }
        if let Some(index) = remove_drive {
            if index
                < settings
                    .advanced_filter_options
                    .wipe_free_space_drives
                    .len()
            {
                settings
                    .advanced_filter_options
                    .wipe_free_space_drives
                    .remove(index);
            }
        }
    }
}

fn inclusion_location(rule: &InclusionRule) -> String {
    match &rule.location {
        InclusionLocation::File(path) => path.clone(),
        InclusionLocation::Folder(folder) => folder.folder.clone(),
    }
}

fn inclusion_detail(rule: &InclusionRule) -> String {
    let mut details = Vec::new();
    match &rule.location {
        InclusionLocation::File(_) => details.push("File".to_owned()),
        InclusionLocation::Folder(folder) => {
            details.push(if folder.recursive {
                "Includes subfolders".into()
            } else {
                "This folder only".into()
            });
            if let Some(filters) = &folder.filter {
                details.push(format!("Filters: {}", filters.join("; ")));
            }
            if folder.delete_self {
                details.push("Cleanup blocked for this rule: folder removal is unsupported".into());
            }
        }
    }
    if let Some(hours) = rule.age_threshold_hours {
        details.push(format!("At least {hours} hours old"));
    }
    details.join(" · ")
}

fn exclusion_type_label(kind: ExclusionType) -> &'static str {
    match kind {
        ExclusionType::File => "File",
        ExclusionType::Path => "Path",
        ExclusionType::RegistryKey => "Registry key",
        ExclusionType::RegistryKeyValue => "Registry key value",
        ExclusionType::Cookie => "Cookie domain",
    }
}

fn exclusions_supported(kind: ExclusionType) -> bool {
    matches!(kind, ExclusionType::File | ExclusionType::Path)
}

fn overwrite_label(value: OverwriteType) -> &'static str {
    match value {
        OverwriteType::Disabled => "Disabled",
        OverwriteType::SinglePass => "Single pass",
        OverwriteType::ThreePass => "Three passes",
        OverwriteType::SevenPass => "Seven passes",
        OverwriteType::ThirtyFivePass => "Thirty-five passes",
    }
}
