use super::{App, CleanupHistory, Event};
use crate::theme::{self, Tokens};
use dcleaner::{
    cleanup::{self, SystemTrash},
    domain::CleanupResult,
    duplicates::{
        self, DuplicateOptions, DuplicatePhase, DuplicateProgress, DuplicateReport, SkipReason,
    },
    store::{self, Journal},
};
#[cfg(debug_assertions)]
use dcleaner::{
    domain::Candidate,
    duplicates::{DuplicateFile, DuplicateGroup},
};
use eframe::egui::{self, Align, Layout, RichText, Vec2};
use std::{path::PathBuf, sync::Arc, thread};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ScanScope {
    #[default]
    Drives,
    Folders,
}

#[derive(Clone, Debug)]
struct DriveChoice {
    path: PathBuf,
    selected: bool,
}

pub(super) struct DuplicateUi {
    scope: ScanScope,
    drives: Vec<DriveChoice>,
    drives_loaded: bool,
    folders: Vec<PathBuf>,
    options: DuplicateOptions,
    minimum_size_text: String,
    file_types_text: String,
    options_open: bool,
    edit_locations: bool,
    report: Option<DuplicateReport>,
    cleanup_review: bool,
    acknowledge_all_copies: bool,
    expand_qa_details: bool,
}

impl Default for DuplicateUi {
    fn default() -> Self {
        let options = DuplicateOptions::default();
        Self {
            scope: ScanScope::Drives,
            drives: Vec::new(),
            drives_loaded: false,
            folders: Vec::new(),
            minimum_size_text: options.minimum_size.to_string(),
            file_types_text: String::new(),
            options,
            options_open: false,
            edit_locations: false,
            report: None,
            cleanup_review: false,
            acknowledge_all_copies: false,
            expand_qa_details: false,
        }
    }
}

impl DuplicateUi {
    #[cfg(debug_assertions)]
    pub(super) fn inert_fixture() -> Self {
        let options = DuplicateOptions::default();
        Self {
            scope: ScanScope::Folders,
            drives: Vec::new(),
            drives_loaded: true,
            folders: vec![PathBuf::from(r"C:\__dcleaner_qa_fixture__")],
            minimum_size_text: options.minimum_size.to_string(),
            file_types_text: String::new(),
            options,
            options_open: false,
            edit_locations: false,
            report: None,
            cleanup_review: false,
            acknowledge_all_copies: false,
            expand_qa_details: false,
        }
    }
}

pub(super) enum DuplicateEvent {
    Progress(String),
    Scanned(DuplicateReport),
    Cleaning {
        done: usize,
        total: usize,
    },
    Cleaned {
        result: Result<CleanupResult, String>,
        history: CleanupHistory,
    },
}

impl App {
    #[cfg(debug_assertions)]
    pub(super) fn qa_duplicates_precondition(&self, label: &str) -> Result<(), String> {
        if label == "Show options" && self.qa_fixture_mode() && !self.busy() {
            return Ok(());
        }
        if !self.qa_fixture_mode() || self.duplicate_ui.report.is_none() || self.busy() {
            return Err("Duplicate actions require a completed isolated fixture.".into());
        }
        let reviewing = self.duplicate_ui.cleanup_review;
        let valid = match label {
            "Keep oldest" | "Keep newest" | "Select all" | "Deselect all" | "Keep this copy" => {
                !reviewing
            }
            "Review 2 files" => {
                !reviewing
                    && self
                        .duplicate_ui
                        .report
                        .as_ref()
                        .is_some_and(|report| report.selected_ids().len() == 2)
            }
            "Keep files" | "Close duplicate review" => reviewing,
            _ => false,
        };
        valid
            .then_some(())
            .ok_or_else(|| format!("Duplicate action is unavailable: {label}"))
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_duplicates_action_state(
        &self,
        label: &str,
    ) -> Result<serde_json::Value, String> {
        if label == "Show options" && self.qa_fixture_mode() && self.duplicate_ui.options_open {
            return Ok(serde_json::json!({"options_open":true,"native_effects":false}));
        }
        let report = self
            .duplicate_ui
            .report
            .as_ref()
            .ok_or("No duplicate fixture report")?;
        let files = report
            .groups
            .iter()
            .map(|group| group.files.len())
            .sum::<usize>();
        let selected = report.selected_ids().len();
        let valid = match label {
            "Keep oldest" | "Keep newest" => report
                .groups
                .iter()
                .all(|group| group.files.iter().filter(|file| !file.selected).count() == 1),
            "Keep this copy" => report.groups.first().is_some_and(|group| {
                group.files.first().is_some_and(|file| !file.selected)
                    && group.files.iter().filter(|file| !file.selected).count() == 1
            }),
            "Select all" => selected == files,
            "Deselect all" => selected == 0,
            "Review 2 files" => self.duplicate_ui.cleanup_review && selected == 2,
            "Keep files" | "Close duplicate review" => !self.duplicate_ui.cleanup_review,
            _ => false,
        };
        if !valid {
            return Err(format!(
                "Duplicate action did not reach its expected state: {label}"
            ));
        }
        Ok(
            serde_json::json!({"selected": selected, "files": files, "review_open": self.duplicate_ui.cleanup_review, "native_effects": false}),
        )
    }

    #[cfg(debug_assertions)]
    pub(super) fn seed_duplicates_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Duplicate Finder QA fixtures require isolated fixture mode.".into());
        }
        if !matches!(
            case,
            "duplicates-intro"
                | "duplicates-setup"
                | "duplicates-empty"
                | "duplicates-populated"
                | "duplicates-selected"
                | "duplicates-details"
                | "duplicates-error"
        ) {
            return Err(format!("Unsupported Duplicate Finder QA fixture: {case}"));
        }
        self.duplicate_ui = DuplicateUi::inert_fixture();
        if matches!(case, "duplicates-intro" | "duplicates-setup") {
            self.duplicate_ui.report = None;
            self.error = None;
            if case == "duplicates-setup" {
                self.mark_feature_seen("duplicates");
                self.duplicate_ui.scope = ScanScope::Drives;
                self.duplicate_ui.drives = [r"C:\", r"D:\", r"G:\"]
                    .into_iter()
                    .map(|path| DriveChoice {
                        path: PathBuf::from(path),
                        selected: true,
                    })
                    .collect();
            }
        } else {
            self.mark_feature_seen("duplicates");
            let mut report = duplicate_qa_report(if case == "duplicates-selected" {
                "duplicates-populated"
            } else {
                case
            });
            if case == "duplicates-selected" {
                report.select_all();
            }
            self.duplicate_ui.expand_qa_details = case == "duplicates-details";
            self.duplicate_ui.report = Some(report);
            self.duplicate_ui.cleanup_review = false;
            self.duplicate_ui.acknowledge_all_copies = false;
            self.error = self
                .duplicate_ui
                .report
                .as_ref()
                .and_then(|report| report.error.clone());
        }
        self.notice = None;
        self.progress.clear();
        Ok(())
    }

    pub(super) fn duplicates_page(&mut self, ui: &mut egui::Ui, t: Tokens, _ctx: &egui::Context) {
        let busy = self.busy();
        if !self.feature_seen("duplicates") {
            if self.feature_intro(
                ui,
                t,
                "duplicates",
                "Find duplicate files",
                "Start a read-only scan of the selected locations. All detected drives are initially selected; review every match before moving files.",
                &[
                    (
                        theme::Icon::Duplicate,
                        "Declutter disk space",
                        "Find byte-for-byte matches in the selected locations; the scan does not move files.",
                    ),
                    (
                        theme::Icon::Brush,
                        "Clean more thoroughly, safely",
                        "Review the matching groups and confirm each proposed move to the Recycle Bin.",
                    ),
                ],
            ) {
                self.start_duplicate_scan(_ctx);
            }
            return;
        }
        if self.duplicate_ui.report.is_none() {
            ui.scope(|ui| {
                ui.spacing_mut().item_spacing.y = 0.;
                self.source_card(ui, t, busy);
                self.options_card(ui, t, busy);
            });
        } else {
            self.source_card(ui, t, busy);
            ui.add_space(4.);
            self.options_card(ui, t, busy);
        }
        ui.add_space(if self.duplicate_ui.report.is_some() {
            4.
        } else {
            10.
        });
        if self.duplicate_ui.report.is_some() {
            self.results_card(ui, t, busy);
        }
    }

    pub(super) fn duplicates_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if !self.feature_seen("duplicates") {
            let compact = !self.feature_intro_wide(ctx);
            let mut start = false;
            theme::action_row(ui, |ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if compact {
                        start = theme::primary(ui, "Start now", t, !self.busy());
                    } else {
                        theme::muted(
                            ui,
                            "Start a read-only scan, then review matching files before any move.",
                            t,
                        );
                    }
                });
            });
            if start {
                self.start_duplicate_scan(ctx);
            }
            return;
        }
        let busy = self.busy();
        self.duplicate_action_bar(ui, t, ctx, busy);
    }

    fn start_duplicate_scan(&mut self, ctx: &egui::Context) {
        self.mark_feature_seen("duplicates");
        if !self.qa_fixture_mode()
            && self.duplicate_ui.scope == ScanScope::Drives
            && !self.duplicate_ui.drives_loaded
        {
            self.refresh_duplicate_drives();
        }
        self.begin_duplicate_scan(ctx);
    }

    pub(super) fn duplicates_dialog(&mut self, ctx: &egui::Context) {
        if !self.duplicate_ui.cleanup_review {
            return;
        }
        let fixture_mode = self.qa_fixture_mode();
        let busy = self.busy();
        if !busy && ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.duplicate_ui.cleanup_review = false;
            self.duplicate_ui.acknowledge_all_copies = false;
            return;
        }
        let t = theme::tokens(self.prefs.dark);
        let Some(report) = self.duplicate_ui.report.as_ref() else {
            self.duplicate_ui.cleanup_review = false;
            return;
        };
        let selected = report.selected_ids();
        let selected_bytes = selected_size(report);
        let all_copies_selected = has_fully_selected_group(report);
        let partial = report.partial;
        let cancelled = report.cancelled;
        let selected_count = selected.len();
        egui::Modal::new(egui::Id::new("duplicate-cleanup-review")).show(ctx, |ui| {
            ui.set_width(460.);
            ui.horizontal(|ui| {
                ui.heading("Review duplicate files");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if theme::close_button(ui, "Close duplicate review", true) {
                        self.duplicate_ui.cleanup_review = false;
                        self.duplicate_ui.acknowledge_all_copies = false;
                    }
                });
            });
            ui.add_space(10.);
            ui.label(format!(
                "Move {} selected files ({}) to {}?",
                selected_count,
                size_text(selected_bytes),
                platform_trash_label()
            ));
            ui.add_space(8.);
            theme::muted(
                ui,
                "Each file is rechecked before it is moved. Files changed since the scan are skipped.",
                t,
            );
            if partial {
                ui.add_space(8.);
                ui.colored_label(
                    t.attention,
                    "This result is partial. Some entries were skipped, or a scan limit was reached.",
                );
            }
            if all_copies_selected {
                ui.add_space(12.);
                ui.colored_label(
                    t.attention,
                    "Every copy in at least one group is selected. Continuing can remove all copies in that group.",
                );
                theme::checkbox(
                    ui,
                    &mut self.duplicate_ui.acknowledge_all_copies,
                    "I reviewed the groups and want to continue",
                    true,
                );
            }
            ui.add_space(18.);
            ui.horizontal(|ui| {
                if theme::secondary(ui, "Keep files", true) {
                    self.duplicate_ui.cleanup_review = false;
                    self.duplicate_ui.acknowledge_all_copies = false;
                }
                let can_continue = !fixture_mode
                    && selected_count > 0
                    && !cancelled
                    && self.history_readable
                    && (!all_copies_selected || self.duplicate_ui.acknowledge_all_copies);
                if theme::primary(ui, "Move selected files", t, can_continue) {
                    self.begin_duplicate_cleanup(ctx);
                }
            });
        });
    }

    pub(super) fn duplicates_event(&mut self, event: DuplicateEvent) {
        match event {
            DuplicateEvent::Progress(text) => self.progress = text,
            DuplicateEvent::Scanned(report) => {
                self.worker = None;
                self.duplicate_ui.edit_locations = false;
                self.duplicate_ui.options_open = false;
                if report.cancelled {
                    self.set_notice(
                        "Duplicate scan cancelled. Review the partial results; they cannot be cleaned until you scan again.".into(),
                    );
                } else if report.partial {
                    self.set_notice(format!(
                        "Scan finished with partial results: {} entries skipped, {} skip details shown.",
                        report.skipped_count,
                        report.skipped_entries.len()
                    ));
                } else {
                    self.notice = None;
                }
                self.error = report.error.clone();
                self.duplicate_ui.report = Some(report);
                self.duplicate_ui.cleanup_review = false;
                self.duplicate_ui.acknowledge_all_copies = false;
            }
            DuplicateEvent::Cleaning { done, total } => {
                self.progress = format!("Reviewed {done} of {total} selected duplicate files");
            }
            DuplicateEvent::Cleaned { result, history } => {
                self.worker = None;
                self.duplicate_ui.cleanup_review = false;
                self.duplicate_ui.acknowledge_all_copies = false;
                self.duplicate_ui.report = None;
                match result {
                    Ok(record) => {
                        self.set_notice(format!(
                            "{} moved to {}. {} files cleaned; {} skipped{}.",
                            size_text(record.bytes),
                            platform_trash_label(),
                            record.files,
                            record.failed.len(),
                            if record.cancelled {
                                "; cleanup stopped"
                            } else {
                                ""
                            }
                        ));
                    }
                    Err(error) => {
                        self.error = Some(format!(
                            "Duplicate cleanup stopped: {error}. Review History for confirmed and uncertain outcomes."
                        ));
                    }
                }
                self.apply_cleanup_history(history);
            }
        }
    }

    fn source_card(&mut self, ui: &mut egui::Ui, t: Tokens, busy: bool) {
        if self.duplicate_ui.report.is_some() && !self.duplicate_ui.edit_locations {
            let summary = match self.duplicate_ui.scope {
                ScanScope::Drives => {
                    let selected = self
                        .duplicate_ui
                        .drives
                        .iter()
                        .filter(|drive| drive.selected)
                        .count();
                    format!(
                        "{selected} of {} drives selected",
                        self.duplicate_ui.drives.len()
                    )
                }
                ScanScope::Folders => format!(
                    "{} folder{} selected",
                    self.duplicate_ui.folders.len(),
                    if self.duplicate_ui.folders.len() == 1 {
                        ""
                    } else {
                        "s"
                    }
                ),
            };
            let edit = compact_summary_row(ui, t, "Scan locations", &summary, !busy);
            if edit {
                self.duplicate_ui.edit_locations = true;
            }
            return;
        }
        let mut scope_changed = false;
        let frame = (if self.duplicate_ui.report.is_none() {
            theme::joined_card(t, theme::JoinedEdge::Top)
        } else {
            theme::card(t)
        })
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = theme::LABEL_GAP;
            let width = ui.available_width();
            ui.set_min_width(width);
            let wide = width >= 650.;
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 0.;
                ui.allocate_ui_with_layout(
                    Vec2::new(if wide { width - 252. } else { width }, 210.),
                    Layout::top_down(Align::Min),
                    |ui| {
                        ui.spacing_mut().item_spacing.x = theme::LABEL_GAP;
                        ui.set_max_width(if wide { width - 252. } else { width });
                        ui.set_min_width(if wide { width - 252. } else { width });
                        ui.label(RichText::new("Where to look").family(theme::semibold()));
                        ui.add_space(12.);
                        ui.horizontal_wrapped(|ui| {
                            ui.add_enabled_ui(!busy, |ui| {
                                scope_changed |= theme::radio_value(
                                    ui,
                                    &mut self.duplicate_ui.scope,
                                    ScanScope::Drives,
                                    "Drives",
                                )
                                .changed();
                                scope_changed |= theme::radio_value(
                                    ui,
                                    &mut self.duplicate_ui.scope,
                                    ScanScope::Folders,
                                    "Choose specific folders",
                                )
                                .changed();
                            });
                        });
                        ui.add_space(16.);
                        match self.duplicate_ui.scope {
                            ScanScope::Drives => self.drive_picker(ui, t, busy),
                            ScanScope::Folders => self.folder_picker(ui, t, busy),
                        }
                    },
                );
                if wide {
                    ui.add_space(24.);
                    ui.allocate_ui_with_layout(
                        Vec2::new(228., 210.),
                        Layout::top_down(Align::Center),
                        |ui| {
                            ui.add_space(12.);
                            self.illustrations.feature(ui, "duplicates", 200.);
                            ui.add_space(8.);
                            let count = match self.duplicate_ui.scope {
                                ScanScope::Drives => self
                                    .duplicate_ui
                                    .drives
                                    .iter()
                                    .filter(|drive| drive.selected)
                                    .count(),
                                ScanScope::Folders => self.duplicate_ui.folders.len(),
                            };
                            ui.label(
                                RichText::new(format!(
                                    "{} selected",
                                    theme::counted_label(count, "location", "locations")
                                ))
                                .family(theme::semibold()),
                            );
                            theme::muted(ui, "Files stay untouched during a scan.", t);
                        },
                    );
                }
            });
        });
        ui.painter().hline(
            frame.response.rect.x_range(),
            frame.response.rect.bottom() - 0.5,
            egui::Stroke::new(1., t.border),
        );
        #[cfg(debug_assertions)]
        theme::record_region(
            ui,
            "duplicate-source-pane",
            frame.response.rect,
            theme::SECTION_RADIUS,
        );
        if scope_changed {
            self.invalidate_duplicate_report();
        }
    }

    fn drive_picker(&mut self, ui: &mut egui::Ui, t: Tokens, busy: bool) {
        let fixture_mode = self.qa_fixture_mode();
        let mut settings_changed = false;
        ui.horizontal_wrapped(|ui| {
            if theme::secondary(ui, "Select all drives", !busy) {
                settings_changed |= self.duplicate_ui.drives.iter().any(|drive| !drive.selected);
                for drive in &mut self.duplicate_ui.drives {
                    drive.selected = true;
                }
            }
            if theme::secondary(ui, "Clear", !busy) {
                settings_changed |= self.duplicate_ui.drives.iter().any(|drive| drive.selected);
                for drive in &mut self.duplicate_ui.drives {
                    drive.selected = false;
                }
            }
            if theme::secondary(ui, "Refresh drives", !busy && !fixture_mode) && !fixture_mode {
                self.refresh_duplicate_drives();
                settings_changed = true;
            }
        });
        if self.duplicate_ui.drives.is_empty() {
            theme::muted(
                ui,
                if fixture_mode {
                    "Drive roots are not loaded in this isolated fixture; no host drive inventory was queried."
                } else if self.duplicate_ui.drives_loaded {
                    "No accessible drive roots were found. Choose specific folders instead."
                } else {
                    "Drive roots have not been loaded. Choose Refresh drives or specific folders."
                },
                t,
            );
            if settings_changed {
                self.invalidate_duplicate_report();
            }
            return;
        }
        ui.add_space(12.);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = Vec2::new(16., 8.);
            for drive in &mut self.duplicate_ui.drives {
                // A drive root is one unbroken label, including its trailing slash.
                ui.allocate_ui_with_layout(
                    Vec2::new(88., 32.),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        ui.set_min_width(88.);
                        settings_changed |= theme::checkbox(
                            ui,
                            &mut drive.selected,
                            drive.path.display().to_string(),
                            !busy,
                        )
                        .changed();
                    },
                );
            }
        });
        ui.add_space(12.);
        theme::muted(
            ui,
            "Drive scanning is read-only. Select only the locations you want included.",
            t,
        );
        if settings_changed {
            self.invalidate_duplicate_report();
        }
    }

    fn refresh_duplicate_drives(&mut self) {
        let old = self
            .duplicate_ui
            .drives
            .iter()
            .map(|drive| (path_identity(&drive.path), drive.selected))
            .collect::<std::collections::HashMap<_, _>>();
        self.duplicate_ui.drives = available_drives()
            .into_iter()
            .map(|path| DriveChoice {
                selected: old.get(&path_identity(&path)).copied().unwrap_or(true),
                path,
            })
            .collect();
        self.duplicate_ui.drives_loaded = true;
    }

    fn folder_picker(&mut self, ui: &mut egui::Ui, t: Tokens, busy: bool) {
        let fixture_mode = self.qa_fixture_mode();
        let mut settings_changed = false;
        ui.horizontal_wrapped(|ui| {
            if theme::secondary(ui, "Add folder", !busy && !fixture_mode) && !fixture_mode {
                if let Some(folder) = rfd::FileDialog::new()
                    .set_title("Choose a folder to scan for duplicates")
                    .pick_folder()
                    && !self
                        .duplicate_ui
                        .folders
                        .iter()
                        .any(|existing| same_location(existing, &folder))
                {
                    self.duplicate_ui.folders.push(folder);
                    settings_changed = true;
                }
            }
            if theme::secondary(ui, "Clear folders", !busy) {
                settings_changed |= !self.duplicate_ui.folders.is_empty();
                self.duplicate_ui.folders.clear();
            }
        });
        if self.duplicate_ui.folders.is_empty() {
            theme::muted(ui, "Add one or more folders to scan.", t);
        } else {
            let mut remove_index = None;
            for (index, folder) in self.duplicate_ui.folders.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::Label::new(folder.display().to_string())
                            .truncate()
                            .show_tooltip_when_elided(false),
                    )
                    .on_hover_text(folder.display().to_string());
                    if theme::row_action(ui, "Remove", !busy).clicked() {
                        remove_index = Some(index);
                    }
                });
            }
            if let Some(index) = remove_index {
                self.duplicate_ui.folders.remove(index);
                settings_changed = true;
            }
            theme::muted(
                ui,
                "Overlapping folders are collapsed so each file is scanned once.",
                t,
            );
        }
        if settings_changed {
            self.invalidate_duplicate_report();
        }
    }

    fn options_card(&mut self, ui: &mut egui::Ui, t: Tokens, busy: bool) {
        if self.duplicate_ui.report.is_some() && !self.duplicate_ui.options_open {
            let mut attributes = Vec::new();
            if self.duplicate_ui.options.include_hidden {
                attributes.push("hidden");
            }
            if self.duplicate_ui.options.include_system {
                attributes.push("system");
            }
            if self.duplicate_ui.options.include_read_only {
                attributes.push("read-only");
            }
            if self.duplicate_ui.options.include_compressed {
                attributes.push("compressed");
            }
            let file_types = self.duplicate_ui.file_types_text.trim();
            let type_summary = if file_types.is_empty() {
                "all file types".to_owned()
            } else {
                format!("types: {file_types}")
            };
            let attribute_summary = if attributes.is_empty() {
                "default attributes".to_owned()
            } else {
                format!("includes {}", attributes.join(", "))
            };
            let summary = format!(
                "Minimum {} bytes · {type_summary} · {attribute_summary}",
                self.duplicate_ui.options.minimum_size
            );
            let edit = compact_summary_row(ui, t, "Scan criteria", &summary, !busy);
            if edit {
                self.duplicate_ui.options_open = true;
            }
            return;
        }
        let mut scan_option_changed = false;
        let frame = (if self.duplicate_ui.report.is_none() { theme::joined_card(t, theme::JoinedEdge::Bottom) } else { theme::card(t) }).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = theme::LABEL_GAP;
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Scan settings").family(theme::semibold()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    theme::checkbox(
                        ui,
                        &mut self.duplicate_ui.options_open,
                        "Show options",
                        true,
                    );
                });
            });
            theme::control_row(ui, |ui| {
                theme::muted(ui, "Minimum file size", t);
                scan_option_changed |= theme::input(ui, &mut self.duplicate_ui.minimum_size_text, 110., "65536", !busy).changed();
                theme::muted(ui, "bytes · default 65,536 bytes", t);
            });
            if self.duplicate_ui.options_open {
                ui.add_space(8.);
                theme::control_row(ui, |ui| {
                    theme::muted(ui, "File types", t);
                    scan_option_changed |= theme::input(ui, &mut self.duplicate_ui.file_types_text, 260., "All types, or: jpg, pdf, tar.gz", !busy).changed();
                });
                theme::muted(
                    ui,
                    "Leave blank for all types. Enter extensions separated by commas.",
                    t,
                );
                ui.add_space(6.);
                ui.horizontal_wrapped(|ui| {
                    scan_option_changed |= theme::checkbox(
                        ui,
                        &mut self.duplicate_ui.options.include_hidden,
                        "Include hidden files",
                        !busy,
                    )
                        .changed();
                    scan_option_changed |= theme::checkbox(
                        ui,
                        &mut self.duplicate_ui.options.include_system,
                        "Include system files",
                        !busy,
                    )
                        .changed();
                    scan_option_changed |= theme::checkbox(
                        ui,
                        &mut self.duplicate_ui.options.include_read_only,
                        "Include read-only files",
                        !busy,
                    )
                        .changed();
                    scan_option_changed |= theme::checkbox(
                        ui,
                        &mut self.duplicate_ui.options.include_compressed,
                        "Include compressed files",
                        !busy,
                    )
                        .changed();
                });
                theme::muted(
                    ui,
                    "Windows file attributes are checked where available. Portable filesystems may not expose every attribute.",
                    t,
                );
            }
        });
        #[cfg(debug_assertions)]
        theme::record_region(
            ui,
            "duplicate-options-pane",
            frame.response.rect,
            theme::SECTION_RADIUS,
        );
        #[cfg(not(debug_assertions))]
        let _ = frame;
        if scan_option_changed {
            self.invalidate_duplicate_report();
        }
    }

    fn results_card(&mut self, ui: &mut egui::Ui, t: Tokens, busy: bool) {
        let expand_qa_details = self.duplicate_ui.expand_qa_details;
        let compact_layout = ui.available_width() < 760.;
        let frame = if compact_layout {
            egui::Frame::new().inner_margin(0.)
        } else {
            theme::card(t)
        };
        frame.show(ui, |ui| {
            ui.set_width(ui.available_width());
            let Some(report) = &mut self.duplicate_ui.report else {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("No scan yet").family(theme::semibold()));
                    theme::muted(
                        ui,
                        "Scan selected locations to find byte-for-byte matches.",
                        t,
                    );
                });
                return;
            };

            if compact_layout {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(size_text(report.potential_reclaimable_bytes))
                            .size(theme::FONT_TITLE)
                            .family(theme::semibold()),
                    );
                    theme::muted(ui, "potentially reclaimable", t);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let summary = format!(
                            "{} groups · {} duplicate files",
                            report.groups.len(), report.duplicate_files
                        );
                        ui.add(egui::Label::new(RichText::new(&summary).color(t.muted)).truncate().show_tooltip_when_elided(false))
                            .on_hover_text(format!(
                                "{} candidates · {} read · {:.1}s elapsed",
                                report.candidate_files,
                                size_text(report.bytes_read),
                                report.elapsed_ms as f64 / 1000.
                            ));
                    });
                });
            } else {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(size_text(report.potential_reclaimable_bytes))
                            .size(theme::FONT_DISPLAY)
                            .family(theme::semibold()),
                    );
                    theme::muted(ui, "logical size beyond one copy per group", t);
                    theme::muted(
                        ui,
                        format!(
                            "{} candidates · {} read · {:.1}s",
                            report.candidate_files,
                            size_text(report.bytes_read),
                            report.elapsed_ms as f64 / 1000.
                        ),
                        t,
                    );
                });
            }
            if report.partial {
                ui.add_space(5.);
                ui.colored_label(
                    t.attention,
                    format!(
                        "Partial result · {} entries skipped · {} limit reached · {}",
                        report.skipped_count,
                        if report.truncated { "yes" } else { "no" },
                        if report.cancelled { "cancelled" } else { "review before cleaning" }
                    ),
                );
            }
            ui.add_space(if compact_layout { 4. } else { 8. });
            ui.horizontal_wrapped(|ui| {
                if theme::secondary(ui, "Keep oldest", !busy && !report.cancelled) {
                    report.keep_oldest();
                }
                if theme::secondary(ui, "Keep newest", !busy && !report.cancelled) {
                    report.keep_newest();
                }
                if theme::secondary(ui, "Select all", !busy && !report.cancelled) {
                    report.select_all();
                }
                if theme::secondary(ui, "Deselect all", !busy) {
                    report.deselect_all();
                }
                theme::muted(
                    ui,
                    format!(
                        "{} selected · {}",
                        report.selected_ids().len(),
                        size_text(selected_size(report))
                    ),
                    t,
                );
            });
            ui.separator();
            if report.groups.is_empty() {
                ui.add_space(10.);
                theme::muted(
                    ui,
                    if let Some(error) = report.error.as_deref() {
                        error
                    } else if report.cancelled {
                        "No verified duplicate groups were completed before cancellation."
                    } else {
                        "No identical files were found in this scan."
                    },
                    t,
                );
            } else {
                let cancelled = report.cancelled;
                for (group_index, group) in report.groups.iter_mut().enumerate() {
                            let selected_in_group = group.files.iter().filter(|file| file.selected).count();
                            let title = format!(
                                "{} · {} copies · {} · {}/{} selected",
                                group
                                    .files
                                    .first()
                                    .and_then(|file| file.candidate.path.file_name())
                                    .map(|name| name.to_string_lossy().into_owned())
                                    .unwrap_or_else(|| "Duplicate group".into()),
                                group.files.len(),
                                size_text(group.size),
                                selected_in_group,
                                group.files.len()
                            );
                            theme::Disclosure::new(title)
                                .id_salt(group.id)
                                .default_open(expand_qa_details || group_index == 0)
                                .show(ui, |ui| {
                                    ui.horizontal_wrapped(|ui| {
                                        let mut all_selected = group.files.iter().all(|file| file.selected);
                                        if theme::checkbox(
                                            ui,
                                            &mut all_selected,
                                            "Select every copy in this group",
                                            !busy && !cancelled,
                                        )
                                        .changed()
                                        {
                                            for file in &mut group.files {
                                                file.selected = all_selected;
                                            }
                                        }
                                    });
                                    ui.add_space(4.);
                                    for file_index in 0..group.files.len() {
                                        let mut keep_this_copy = false;
                                        let available_width = ui.available_width().max(1.);
                                        let checkbox_width = 28.;
                                        let action_width = ui
                                            .painter()
                                            .layout_no_wrap(
                                                "Keep this copy".into(),
                                                egui::FontId::new(
                                                    theme::FONT_CAPTION,
                                                    theme::semibold(),
                                                ),
                                                ui.visuals().text_color(),
                                            )
                                            .size()
                                            .x
                                            + 24.;
                                        let gap = ui.spacing().item_spacing.x;
                                        let text_width = (available_width
                                            - checkbox_width
                                            - action_width
                                            - gap * 2.)
                                            .max(1.);
                                        let row_top = ui.cursor().top();
                                        let row_left = ui.min_rect().left();
                                        let row_right = ui.min_rect().right();
                                        {
                                            let file = &mut group.files[file_index];
                                            ui.allocate_ui_with_layout(
                                                Vec2::new(available_width, 60.),
                                                Layout::left_to_right(Align::Center),
                                                |row| {
                                                    row.set_min_width(available_width);
                                                    row.set_max_width(available_width);
                                                    row.set_min_height(60.);
                                                    row.spacing_mut().item_spacing.x = gap;
                                                    row.allocate_ui_with_layout(
                                                        Vec2::new(checkbox_width, 60.),
                                                        Layout::left_to_right(Align::Center),
                                                        |cell| {
                                                            theme::checkbox_widget(
                                                                cell,
                                                                &mut file.selected,
                                                                !busy && !cancelled,
                                                            );
                                                        },
                                                    );
                                                    row.allocate_ui_with_layout(
                                                        Vec2::new(text_width, 60.),
                                                        Layout::top_down(Align::Min),
                                                        |text| {
                                                            text.set_min_width(text_width);
                                                            text.set_max_width(text_width);
                                                            text.spacing_mut().item_spacing.y = 0.;
                                                            let path = file.candidate.path.display().to_string();
                                                            let name = file.candidate.path.file_name()
                                                                .map(|name| name.to_string_lossy().into_owned())
                                                                .unwrap_or_else(|| "File".into());
                                                            text.add(egui::Label::new(
                                                                RichText::new(name).family(theme::semibold()),
                                                            ).truncate().show_tooltip_when_elided(false))
                                                            .on_hover_text(&path);
                                                            text.add(egui::Label::new(
                                                                RichText::new(&path).size(theme::FONT_CAPTION).color(t.muted),
                                                            ).truncate().show_tooltip_when_elided(false))
                                                            .on_hover_text(&path);
                                                            text.add(egui::Label::new(
                                                                RichText::new(format!(
                                                                    "Created {} · Modified {} · {}",
                                                                    datetime_display(file.candidate.created_ns),
                                                                    datetime_display(Some(file.candidate.modified_ns)),
                                                                    size_text(file.candidate.size),
                                                                )).size(theme::FONT_CAPTION).color(t.muted),
                                                            ).wrap())
                                                            .on_hover_text(format!(
                                                                "Created {} · Modified {} · {}",
                                                                datetime_display(file.candidate.created_ns),
                                                                datetime_display(Some(file.candidate.modified_ns)),
                                                                size_text(file.candidate.size),
                                                            ));
                                                        },
                                                    );
                                                    row.allocate_ui_with_layout(
                                                        Vec2::new(action_width, 60.),
                                                        Layout::right_to_left(Align::Center),
                                                        |action| {
                                                            keep_this_copy = theme::row_action(action, "Keep this copy", !busy && !cancelled)
                                                                .on_hover_text("Keep this file and select the other copies in this group for review.")
                                                                .clicked();
                                                        },
                                                    );
                                                },
                                            );
                                        }
                                        ui.painter().hline(
                                            row_left..=row_right,
                                            row_top + 59.,
                                            egui::Stroke::new(1., t.border),
                                        );
                                        if keep_this_copy {
                                            for (index, other) in
                                                group.files.iter_mut().enumerate()
                                            {
                                                other.selected = index != file_index;
                                            }
                                        }
                                    }
                                });
                }
            }
            if report.skipped_count > 0 {
                theme::Disclosure::new(format!(
                    "Skipped entries · {} total",
                    report.skipped_count
                ))
                .id_salt("duplicate-skipped-entries")
                .show(ui, |ui| {
                    for skipped in &report.skipped_entries {
                        ui.horizontal_wrapped(|ui| {
                            theme::muted(ui, skip_reason_label(&skipped.reason), t);
                            if let Some(path) = &skipped.path {
                                ui.add(egui::Label::new(path.display().to_string()).truncate().show_tooltip_when_elided(false))
                                    .on_hover_text(path.display().to_string());
                            }
                        });
                    }
                    if report.omitted_skip_details > 0 {
                        theme::muted(
                            ui,
                            format!(
                                "{} additional skip details were omitted to keep the report bounded.",
                                report.omitted_skip_details
                            ),
                            t,
                        );
                    }
                });
            }
        });
    }

    fn duplicate_action_bar(
        &mut self,
        ui: &mut egui::Ui,
        t: Tokens,
        ctx: &egui::Context,
        busy: bool,
    ) {
        let report = self.duplicate_ui.report.as_ref();
        let selected_count = report.map_or(0, |report| report.selected_ids().len());
        let selected_bytes = report.map_or(0, selected_size);
        let enabled = !busy
            && selected_count > 0
            && report.is_some_and(|report| !report.cancelled)
            && self.history_readable;
        ui.set_min_height(40.);
        ui.with_layout(
            Layout::right_to_left(Align::Center).with_main_wrap(true),
            |ui| {
                let label = if selected_count == 0 {
                    "Review files".into()
                } else {
                    format!(
                        "Review {}",
                        theme::counted_label(selected_count, "file", "files")
                    )
                };
                if theme::primary(ui, &label, t, enabled) {
                    self.duplicate_ui.cleanup_review = true;
                    self.duplicate_ui.acknowledge_all_copies = false;
                }
                theme::muted(
                    ui,
                    format!("{selected_count} selected · {}", size_text(selected_bytes)),
                    t,
                );
                ui.add_space(12.);
                if theme::secondary(ui, "Scan", !busy) {
                    self.begin_duplicate_scan(ctx);
                }
                if !self.history_readable {
                    theme::muted(ui, "History unavailable; review is disabled", t);
                }
            },
        );
    }

    fn begin_duplicate_scan(&mut self, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        let roots = match self.duplicate_ui.scope {
            ScanScope::Drives => self
                .duplicate_ui
                .drives
                .iter()
                .filter(|drive| drive.selected)
                .map(|drive| drive.path.clone())
                .collect::<Vec<_>>(),
            ScanScope::Folders => self.duplicate_ui.folders.clone(),
        };
        if roots.is_empty() {
            self.error = Some(match self.duplicate_ui.scope {
                ScanScope::Drives => "Select at least one accessible drive.".into(),
                ScanScope::Folders => "Add at least one folder to scan.".into(),
            });
            return;
        }
        self.duplicate_ui.edit_locations = false;
        let minimum_size = match self.duplicate_ui.minimum_size_text.trim().parse::<u64>() {
            Ok(value) => value,
            Err(_) => {
                self.error = Some("Minimum file size must be a non-negative byte count.".into());
                return;
            }
        };
        self.duplicate_ui.options.minimum_size = minimum_size;
        self.duplicate_ui.options.file_types = self
            .duplicate_ui
            .file_types_text
            .split([',', ';'])
            .map(str::trim)
            .filter(|kind| !kind.is_empty() && *kind != "*")
            .map(str::to_owned)
            .collect();
        let options = self.duplicate_ui.options.clone();
        self.error = None;
        self.notice = None;
        self.duplicate_ui.report = None;
        self.progress = "Preparing duplicate scan…".into();
        self.cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        let ctx = ctx.clone();
        thread::spawn(move || {
            let report = duplicates::scan(&roots, &options, &cancel, |progress| {
                let _ = tx.send(Event::Duplicate(DuplicateEvent::Progress(progress_text(
                    &progress,
                ))));
                ctx.request_repaint();
            });
            let _ = tx.send(Event::Duplicate(DuplicateEvent::Scanned(report)));
            ctx.request_repaint();
        });
    }

    fn begin_duplicate_cleanup(&mut self, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() || !self.history_readable {
            return;
        }
        let Some(report) = self.duplicate_ui.report.as_ref() else {
            self.duplicate_ui.cleanup_review = false;
            return;
        };
        let ids = report.selected_ids();
        let analysis = match duplicates::build_cleanup_analysis(report, &ids) {
            Ok(analysis) => analysis,
            Err(error) => {
                self.error = Some(error);
                self.duplicate_ui.cleanup_review = false;
                return;
            }
        };
        let root = self.data_dir.clone();
        self.error = None;
        self.duplicate_ui.cleanup_review = false;
        self.duplicate_ui.acknowledge_all_copies = false;
        self.progress = "Checking selected duplicate files…".into();
        self.cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        let ctx = ctx.clone();
        thread::spawn(move || {
            let result = Journal::create(&root, Uuid::new_v4()).and_then(|mut journal| {
                cleanup::clean(
                    &analysis,
                    &ids,
                    &cancel,
                    &mut SystemTrash,
                    &mut journal,
                    |done, total| {
                        let _ = tx.send(Event::Duplicate(DuplicateEvent::Cleaning { done, total }));
                        ctx.request_repaint();
                    },
                )
            });
            let _ = tx.send(Event::Duplicate(DuplicateEvent::Progress(
                "Refreshing cleanup history…".into(),
            )));
            ctx.request_repaint();
            let history = store::history(&root);
            let _ = tx.send(Event::Duplicate(DuplicateEvent::Cleaned {
                result,
                history,
            }));
            ctx.request_repaint();
        });
    }

    fn invalidate_duplicate_report(&mut self) {
        if self.duplicate_ui.report.take().is_some() {
            self.set_notice(
                "Scan settings changed. Run a new scan to review matching files.".into(),
            );
        }
        self.duplicate_ui.cleanup_review = false;
        self.duplicate_ui.acknowledge_all_copies = false;
    }
}

fn compact_summary_row(
    ui: &mut egui::Ui,
    t: Tokens,
    title: &str,
    summary: &str,
    enabled: bool,
) -> bool {
    let width = ui.available_width().max(1.);
    let title_width = 112.;
    let action_width = 52.;
    let gap = 8.;
    let summary_width = (width - title_width - action_width - gap * 2.).max(1.);
    let mut edit = false;
    ui.allocate_ui_with_layout(
        Vec2::new(width, 32.),
        Layout::left_to_right(Align::Center),
        |row| {
            row.set_min_width(width);
            row.set_max_width(width);
            row.spacing_mut().item_spacing.x = gap;
            theme::table_cell(
                row,
                RichText::new(title).family(theme::semibold()),
                title_width,
                32.,
            );
            theme::table_cell_with_tooltip(
                row,
                RichText::new(summary).color(t.muted),
                summary_width,
                32.,
                summary,
            );
            row.allocate_ui_with_layout(
                Vec2::new(action_width, 32.),
                Layout::right_to_left(Align::Center),
                |action| edit = theme::row_action(action, "Edit", enabled).clicked(),
            );
        },
    );
    edit
}

#[cfg(debug_assertions)]
fn duplicate_qa_report(case: &str) -> DuplicateReport {
    let is_error = case == "duplicates-error";
    let populated = matches!(case, "duplicates-populated" | "duplicates-details");
    let root = PathBuf::from(r"C:\__dcleaner_qa_fixture__");
    let groups = if populated {
        let size = 1_048_576;
        let timestamp = 1_700_000_000_000_000_000;
        vec![DuplicateGroup {
            id: Uuid::new_v4(),
            size,
            files: ["fixture-copy-a.bin", "fixture-copy-b.bin"]
                .into_iter()
                .map(|name| DuplicateFile {
                    candidate: Candidate {
                        id: Uuid::new_v4(),
                        path: root.join(name),
                        root: root.clone(),
                        size,
                        modified_ns: timestamp,
                        created_ns: Some(timestamp - 86_400_000_000_000),
                    },
                    selected: false,
                })
                .collect(),
        }]
    } else {
        Vec::new()
    };
    let duplicate_files: usize = groups.iter().map(|group| group.files.len()).sum();
    let duplicate_bytes = groups
        .iter()
        .map(|group| group.size.saturating_mul(group.files.len() as u64))
        .sum::<u64>();
    let potential_reclaimable_bytes = groups
        .iter()
        .map(|group| {
            group
                .size
                .saturating_mul(group.files.len().saturating_sub(1) as u64)
        })
        .sum::<u64>();
    DuplicateReport {
        id: Uuid::new_v4(),
        groups,
        roots_requested: 1,
        roots_available: usize::from(!is_error),
        entries_seen: if populated { 2 } else { 0 },
        candidate_files: duplicate_files,
        fingerprinted_files: duplicate_files,
        duplicate_files,
        duplicate_bytes,
        potential_reclaimable_bytes,
        filtered_count: 0,
        skipped_count: 0,
        skipped_entries: Vec::new(),
        omitted_skip_details: 0,
        bytes_read: 0,
        truncated: false,
        cancelled: false,
        partial: is_error,
        elapsed_ms: 0,
        error: is_error.then(|| "Synthetic QA fixture error. No folder was scanned.".into()),
    }
}

fn available_drives() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let logical_drives = unsafe { windows::Win32::Storage::FileSystem::GetLogicalDrives() };
        ('A'..='Z')
            .enumerate()
            .filter(|(index, _)| logical_drives & (1u32 << index) != 0)
            .map(|(_, letter)| PathBuf::from(format!("{letter}:\\")))
            .collect()
    }
    #[cfg(not(windows))]
    {
        vec![PathBuf::from("/")]
    }
}

fn has_fully_selected_group(report: &DuplicateReport) -> bool {
    report
        .groups
        .iter()
        .any(|group| !group.files.is_empty() && group.files.iter().all(|file| file.selected))
}

fn selected_size(report: &DuplicateReport) -> u64 {
    report
        .groups
        .iter()
        .flat_map(|group| &group.files)
        .filter(|file| file.selected)
        .map(|file| file.candidate.size)
        .fold(0, u64::saturating_add)
}

fn skip_reason_label(reason: &SkipReason) -> &'static str {
    match reason {
        SkipReason::UnavailableRoot => "Selected folder is unavailable",
        SkipReason::DirectoryUnreadable => "Folder could not be read",
        SkipReason::EntryUnreadable => "Folder entry could not be read",
        SkipReason::MetadataUnavailable => "File details are unavailable",
        SkipReason::LinkedEntry => "Link or redirected entry was skipped",
        SkipReason::OutsideRoot => "Entry resolved outside the selected folder",
        SkipReason::ChangedDuringRead => "File changed during the scan",
        SkipReason::UnreadableFile => "File could not be read",
        SkipReason::NonRegularFile => "Entry is not a regular file",
    }
}

fn size_text(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024. && unit + 1 < UNITS.len() {
        value /= 1024.;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn datetime_display(timestamp_ns: Option<u128>) -> String {
    let Some(timestamp_ns) = timestamp_ns else {
        return "unavailable".into();
    };
    let seconds = timestamp_ns / 1_000_000_000;
    let Ok(seconds) = i64::try_from(seconds) else {
        return "unavailable".into();
    };
    let nanos = (timestamp_ns % 1_000_000_000) as u32;
    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, nanos)
        .map(|date| {
            date.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|| "unavailable".into())
}

fn path_identity(path: &std::path::Path) -> String {
    let path = path.to_string_lossy();
    if cfg!(windows) {
        path.to_ascii_lowercase()
    } else {
        path.into_owned()
    }
}

fn same_location(left: &std::path::Path, right: &std::path::Path) -> bool {
    if cfg!(windows) {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    } else {
        left == right
    }
}

fn progress_text(progress: &DuplicateProgress) -> String {
    let phase = match progress.phase {
        DuplicatePhase::Traversal => "Finding files",
        DuplicatePhase::Fingerprinting => "Fingerprinting file contents",
        DuplicatePhase::Verification => "Verifying exact matches",
    };
    let mut message = format!(
        "{phase} · {} entries · {} of {} files",
        progress.entries_seen, progress.files_processed, progress.candidate_files
    );
    if let Some(path) = &progress.path {
        message.push_str(" · ");
        message.push_str(&path.display().to_string());
    }
    message
}

fn platform_trash_label() -> &'static str {
    if cfg!(windows) {
        "the Recycle Bin"
    } else if cfg!(target_os = "macos") {
        "Trash"
    } else {
        "system Trash"
    }
}
