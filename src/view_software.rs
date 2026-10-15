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
use std::cmp::Ordering;

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
    selected: Option<String>,
    dialog: Option<SoftwareDialog>,
    settings: SoftwareSettings,
    settings_error: Option<String>,
    history: Vec<EffectHistory>,
    history_error: Option<String>,
    refresh_after_update: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SoftwareTab {
    #[default]
    All,
    Outdated,
    Current,
    Skipped,
    Ignored,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SoftwareSort {
    #[default]
    Name,
    Publisher,
    Installed,
    Available,
    Source,
}

impl SoftwareSort {
    const ALL: [Self; 5] = [
        Self::Name,
        Self::Publisher,
        Self::Installed,
        Self::Available,
        Self::Source,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Publisher => "Publisher",
            Self::Installed => "Installed version",
            Self::Available => "Available version",
            Self::Source => "Source",
        }
    }
}

#[derive(Clone)]
enum SoftwareDialog {
    UpdateReview(UpdateRequest),
    Details(SoftwareItem),
}

pub(super) enum SoftwareEvent {
    Progress(String),
    Loaded {
        inventory: Result<SoftwareSnapshot, String>,
        settings: Result<SoftwareSettings, String>,
        history: Result<Vec<EffectHistory>, String>,
    },
    UpdateFinished {
        request_id: Uuid,
        display_name: String,
        journal_created: bool,
        result: Result<UpdateReceipt, String>,
        journal_error: Option<String>,
    },
}

#[derive(Serialize)]
struct UpdateFailureReceipt<'a> {
    request_id: Uuid,
    error: &'a str,
}

impl App {
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
                | "software-error"
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

        let items = if matches!(case, "software-populated" | "software-details") {
            vec![
                software_qa_item(
                    "Example Editor",
                    "Example.Editor",
                    "1.0.0",
                    Some("1.1.0"),
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
        self.software_ui = SoftwareUi {
            snapshot: if case == "software-error" {
                None
            } else {
                Some(SoftwareSnapshot {
                    items,
                    registration_issues: Vec::new(),
                })
            },
            attempted: true,
            loading: false,
            load_error: (case == "software-error")
                .then(|| "Synthetic fixture error; WinGet and registry were not queried.".into()),
            selected: selected_item.as_ref().map(SoftwareItem::row_key),
            dialog: if case == "software-details" {
                selected_item.map(SoftwareDialog::Details)
            } else {
                None
            },
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
            .map(|(updates, _, _)| format!("{updates} updates"))
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
                        theme::Icon::Settings,
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
        let count_text = self
            .software_counts()
            .map(|(available, current, deferred)| {
                format!("{available} updates · {current} current · {deferred} deferred")
            })
            .unwrap_or_else(|| "Inventory not loaded".into());
        ui.set_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            theme::tabs(ui, |ui| {
                for (tab, label) in [
                    (SoftwareTab::All, "All"),
                    (SoftwareTab::Outdated, "Outdated"),
                    (SoftwareTab::Current, "Current"),
                    (SoftwareTab::Skipped, "Skipped version"),
                    (SoftwareTab::Ignored, "Ignored"),
                ] {
                    theme::tab_value(ui, &mut self.software_ui.tab, tab, label);
                }
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                theme::muted(ui, count_text, t);
            });
        });
        ui.add_space(5.);
        ui.separator();
        ui.add_space(6.);
        let sort_choices = SoftwareSort::ALL.map(SoftwareSort::label);
        theme::control_row(ui, |ui| {
            let search_width = theme::search_width(ui, &sort_choices);
            ui.label(RichText::new("Search").color(t.muted));
            theme::input(
                ui,
                &mut self.software_ui.query,
                search_width,
                "Name, publisher, package ID…",
                true,
            );
            ui.add_space(8.);
            ui.label(RichText::new("Sort by").color(t.muted));
            theme::selector(
                ui,
                "software-sort",
                self.software_ui.sort.label(),
                &sort_choices,
                |ui| {
                    for sort in SoftwareSort::ALL {
                        ui.selectable_value(&mut self.software_ui.sort, sort, sort.label());
                    }
                },
            );
            ui.add_space(8.);
            theme::checkbox(ui, &mut self.software_ui.descending, "Descending", true);
        });
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
            if theme::secondary(ui, "Retry", !self.busy()) {
                self.begin_software_load(ctx);
            }
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
        ui.add_space(8.);
        self.software_table(ui, t, ctx);

        self.software_history(ui, t);
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
        let busy = self.busy();
        let selected = self.selected_software_item().cloned();
        let mut refresh = false;
        let mut review = None;
        let mut skip = None;
        let mut ignore = None;
        ui.horizontal_wrapped(|ui| {
            theme::muted(
                ui,
                if self.software_ui.loading {
                    "WinGet inventory is running"
                } else {
                    "Only exact package and registration matches can update"
                },
                t,
            );
            ui.separator();
            if theme::secondary(ui, "Refresh", !busy) {
                refresh = true;
            }
            if let Some(item) = selected.as_ref() {
                if theme::primary(ui, "Review update", t, !busy && item.can_update()) {
                    review = Some(item.clone());
                }
                if let Some(identity) = item.identity.as_ref() {
                    let preference = self.software_ui.settings.preference_for(identity);
                    match preference.map(|value| value.state) {
                        Some(SoftwarePreferenceState::SkipVersion) => {
                            if theme::secondary(
                                ui,
                                "Restore skipped version",
                                !busy && self.software_ui.settings_error.is_none(),
                            ) {
                                skip = Some((item.clone(), true));
                            }
                        }
                        Some(SoftwarePreferenceState::Ignored) => {
                            if theme::secondary(
                                ui,
                                "Restore ignored package",
                                !busy && self.software_ui.settings_error.is_none(),
                            ) {
                                ignore = Some((item.clone(), true));
                            }
                        }
                        None if item.row.available_version.is_some() => {
                            if theme::secondary(
                                ui,
                                "Skip this version",
                                !busy && self.software_ui.settings_error.is_none(),
                            ) {
                                skip = Some((item.clone(), false));
                            }
                            if theme::secondary(
                                ui,
                                "Ignore package",
                                !busy && self.software_ui.settings_error.is_none(),
                            ) {
                                ignore = Some((item.clone(), false));
                            }
                        }
                        None => {
                            if theme::secondary(
                                ui,
                                "Ignore package",
                                !busy && self.software_ui.settings_error.is_none(),
                            ) {
                                ignore = Some((item.clone(), false));
                            }
                        }
                    }
                }
            }
        });
        if refresh {
            self.software_ui.attempted = false;
            self.software_ui.refresh_after_update = false;
            self.begin_software_load(ctx);
        }
        if let Some(item) = review {
            self.open_software_review(&item);
        }
        if let Some((item, restore)) = skip {
            if restore {
                self.restore_software_preference(&item);
            } else {
                self.skip_software_version(&item);
            }
        }
        if let Some((item, restore)) = ignore {
            if restore {
                self.restore_software_preference(&item);
            } else {
                self.ignore_software_package(&item);
            }
        }
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
                let body_height = dialog_body_max_height(ctx, 44.0);
                let response = egui::Modal::new(egui::Id::new("software-details-dialog"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(modal_width);
                        ui.heading("Program details");
                        ui.add_space(8.);
                        egui::ScrollArea::vertical()
                            .max_height(body_height)
                            .auto_shrink([false, true])
                            .show(ui, |body| self.software_details(body, t, &item));
                        ui.add_space(8.);
                        ui.separator();
                        ui.add_space(8.);
                        if theme::secondary(ui, "Close", true) {
                            close = true;
                        }
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
                        ui.heading("Review software update");
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
        }
    }

    pub(super) fn software_event(&mut self, event: SoftwareEvent) {
        match event {
            SoftwareEvent::Progress(progress) => self.progress = progress,
            SoftwareEvent::Loaded {
                inventory,
                settings,
                history,
            } => {
                self.worker = None;
                self.software_ui.loading = false;
                self.software_ui.attempted = true;
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
                        self.software_ui.snapshot = Some(snapshot);
                        self.software_ui.load_error = None;
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
                        self.software_ui.snapshot = None;
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

    fn open_software_review(&mut self, item: &SoftwareItem) {
        match software::prepare_update(item) {
            Ok(request) => self.software_ui.dialog = Some(SoftwareDialog::UpdateReview(request)),
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn selected_software_item(&self) -> Option<&SoftwareItem> {
        let key = self.software_ui.selected.as_deref()?;
        self.software_ui
            .snapshot
            .as_ref()?
            .items
            .iter()
            .find(|item| item.row_key() == key)
    }

    fn software_counts(&self) -> Option<(usize, usize, usize)> {
        let items = &self.software_ui.snapshot.as_ref()?.items;
        Some((
            items
                .iter()
                .filter(|item| item.status == SoftwareStatus::UpdateAvailable)
                .count(),
            items
                .iter()
                .filter(|item| item.status == SoftwareStatus::Current)
                .count(),
            items
                .iter()
                .filter(|item| {
                    matches!(
                        item.status,
                        SoftwareStatus::SkippedVersion | SoftwareStatus::Ignored
                    )
                })
                .count(),
        ))
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
        ui.horizontal_wrapped(|ui| {
            theme::muted(ui, format!("{} shown", items.len()), t);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                theme::muted(ui, "Updates may require vendor UI or a reboot", t);
            });
        });
        ui.add_space(6.);
        let table_width = ui.available_width().max(0.0);
        let action_width = 108.0;
        let state_width = 70.0;
        let version_width = 74.0;
        let name_width =
            (table_width - action_width - state_width - 2.0 * version_width - 32.0).max(120.0);
        let previous_y_spacing = ui.spacing().item_spacing.y;
        ui.spacing_mut().item_spacing.y = 0.;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            for (heading, width) in [
                ("Program", name_width),
                ("Installed", version_width),
                ("Available", version_width),
                ("Status", state_width),
                ("Actions", action_width),
            ] {
                table_heading(ui, heading, width, t);
            }
        });
        ui.add_space(3.);
        ui.separator();
        let body_height =
            (ctx.content_rect().bottom() - ui.cursor().top() - 74. - 28. - 50.).max(120.);
        egui::ScrollArea::vertical()
            .id_salt("software-table-body")
            .max_height(body_height)
            .auto_shrink([false, true])
            .show_rows(ui, 44.0, items.len(), |rows_ui, visible_rows| {
                for index in visible_rows {
                    let item = &items[index];
                    let key = item.row_key();
                    rows_ui.push_id(&key, |ui| {
                        let row_response = ui.allocate_ui_with_layout(
                            [table_width, 44.].into(),
                            Layout::left_to_right(Align::Center),
                            |row| {
                                row.set_min_height(44.0);
                                row.spacing_mut().item_spacing.x = 8.0;
                                row.spacing_mut().item_spacing.y = previous_y_spacing;
                                let selected = self.software_ui.selected.as_deref() == Some(&key);
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
                                            self.app_icons.show(cell, icon.as_deref(), 22.0);
                                            cell.scope(|cell| {
                                                cell.visuals_mut().selection.bg_fill = t.tint;
                                                cell.visuals_mut().selection.stroke.color =
                                                    t.foreground;
                                                cell.spacing_mut().button_padding.x = 0.;
                                                cell.add_sized(
                                                    [
                                                        (name_width - 30.).clamp(60., name_width),
                                                        40.,
                                                    ],
                                                    egui::Button::selectable(
                                                        selected,
                                                        (
                                                            RichText::new(&item.row.name)
                                                                .family(theme::semibold())
                                                                .color(t.foreground),
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
                                    version_width,
                                    40.,
                                );
                                theme::table_cell(
                                    row,
                                    RichText::new(
                                        item.row.available_version.as_deref().unwrap_or("—"),
                                    )
                                    .color(status_color(item.status, t)),
                                    version_width,
                                    40.,
                                );
                                theme::table_cell(
                                    row,
                                    RichText::new(status_label(item))
                                        .color(status_color(item.status, t)),
                                    state_width,
                                    40.,
                                );
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
                                        .unwrap_or("No safe update action is available.");
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
                                egui::Popup::menu(&more).show(|ui| {
                                    if ui.button("Details").clicked() {
                                        self.software_ui.selected = Some(key.clone());
                                        self.software_ui.dialog =
                                            Some(SoftwareDialog::Details(item.clone()));
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
                                                if ui
                                                    .add_enabled(
                                                        preference_actions_enabled,
                                                        egui::Button::new(
                                                            "Restore skipped version",
                                                        ),
                                                    )
                                                    .clicked()
                                                {
                                                    self.restore_software_preference(item);
                                                    ui.close();
                                                }
                                            }
                                            Some(SoftwarePreferenceState::Ignored) => {
                                                if ui
                                                    .add_enabled(
                                                        preference_actions_enabled,
                                                        egui::Button::new(
                                                            "Restore ignored package",
                                                        ),
                                                    )
                                                    .clicked()
                                                {
                                                    self.restore_software_preference(item);
                                                    ui.close();
                                                }
                                            }
                                            None if item.row.available_version.is_some() => {
                                                if ui
                                                    .add_enabled(
                                                        preference_actions_enabled,
                                                        egui::Button::new("Skip this version"),
                                                    )
                                                    .clicked()
                                                {
                                                    self.skip_software_version(item);
                                                    ui.close();
                                                }
                                                if ui
                                                    .add_enabled(
                                                        preference_actions_enabled,
                                                        egui::Button::new("Ignore package"),
                                                    )
                                                    .clicked()
                                                {
                                                    self.ignore_software_package(item);
                                                    ui.close();
                                                }
                                            }
                                            None => {
                                                if ui
                                                    .add_enabled(
                                                        preference_actions_enabled,
                                                        egui::Button::new("Ignore package"),
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
        if items.is_empty() {
            ui.add_space(8.);
            theme::muted(ui, "No packages match this view and search.", t);
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
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            detail(ui, "Status", status_label(item), t);
            detail(ui, "Name", &item.row.name, t);
            detail(ui, "Publisher", item.registration.as_ref().and_then(|program| program.publisher.as_deref()).unwrap_or("Not exposed by WinGet"), t);
            detail(ui, "Package ID", &item.row.package_id, t);
            detail(ui, "Source", &item.row.source_id, t);
            detail(ui, "Installed version", item.row.installed_version.as_deref().unwrap_or("Unknown"), t);
            detail(ui, "Available version", item.row.available_version.as_deref().unwrap_or("No update listed"), t);
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
    }
}

fn tab_matches(tab: SoftwareTab, item: &SoftwareItem) -> bool {
    match tab {
        SoftwareTab::All => true,
        SoftwareTab::Outdated => {
            item.row.available_version.is_some()
                && !matches!(
                    item.status,
                    SoftwareStatus::SkippedVersion | SoftwareStatus::Ignored
                )
        }
        SoftwareTab::Current => item.status == SoftwareStatus::Current,
        SoftwareTab::Skipped => item.status == SoftwareStatus::SkippedVersion,
        SoftwareTab::Ignored => item.status == SoftwareStatus::Ignored,
    }
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

fn sort_items(items: &mut [SoftwareItem], sort: SoftwareSort, descending: bool) {
    items.sort_by(|left, right| {
        let ordering = match sort {
            SoftwareSort::Name => left
                .row
                .name
                .to_lowercase()
                .cmp(&right.row.name.to_lowercase()),
            SoftwareSort::Publisher => publisher(left)
                .to_lowercase()
                .cmp(&publisher(right).to_lowercase()),
            SoftwareSort::Installed => version_sort(
                left.row.installed_version.as_deref(),
                right.row.installed_version.as_deref(),
            ),
            SoftwareSort::Available => version_sort(
                left.row.available_version.as_deref(),
                right.row.available_version.as_deref(),
            ),
            SoftwareSort::Source => left.row.source_id.cmp(&right.row.source_id),
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

fn publisher(item: &SoftwareItem) -> &str {
    item.registration
        .as_ref()
        .and_then(|program| program.publisher.as_deref())
        .unwrap_or("")
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
    theme::muted(ui, name, t);
    ui.add(egui::Label::new(value).wrap());
    ui.add_space(4.);
}

fn review_row(ui: &mut egui::Ui, label: &str, value: &str, t: Tokens) {
    theme::muted(ui, label, t);
    ui.add(egui::Label::new(value).wrap());
    ui.add_space(4.);
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

fn format_date(date: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(date)
        .map(|date| date.format("%d %b %Y, %H:%M").to_string())
        .unwrap_or_else(|_| date.to_owned())
}
