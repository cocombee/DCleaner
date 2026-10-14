use super::{App, Event};
use crate::theme::{self, Tokens};
use dcleaner::{
    cleanup::{self, SystemTrash},
    domain::CleanupResult,
    duplicates::{
        self, DuplicateOptions, DuplicatePhase, DuplicateProgress, DuplicateReport, SkipReason,
    },
    store::{self, Journal},
};
use eframe::egui::{self, Align, Layout, RichText, Vec2};
use std::{
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
};
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
    folders: Vec<PathBuf>,
    options: DuplicateOptions,
    minimum_size_text: String,
    file_types_text: String,
    options_open: bool,
    report: Option<DuplicateReport>,
    cleanup_review: bool,
    acknowledge_all_copies: bool,
}

impl Default for DuplicateUi {
    fn default() -> Self {
        let options = DuplicateOptions::default();
        Self {
            scope: ScanScope::Drives,
            drives: available_drives()
                .into_iter()
                .map(|path| DriveChoice {
                    path,
                    selected: true,
                })
                .collect(),
            folders: Vec::new(),
            minimum_size_text: options.minimum_size.to_string(),
            file_types_text: String::new(),
            options,
            options_open: false,
            report: None,
            cleanup_review: false,
            acknowledge_all_copies: false,
        }
    }
}

pub(super) enum DuplicateEvent {
    Progress(String),
    Scanned(DuplicateReport),
    Cleaning { done: usize, total: usize },
    Cleaned(Result<CleanupResult, String>),
}

impl App {
    pub(super) fn duplicates_page(&mut self, ui: &mut egui::Ui, t: Tokens, _ctx: &egui::Context) {
        let busy = self.busy();
        self.source_card(ui, t, busy);
        ui.add_space(10.);
        self.options_card(ui, t, busy);
        ui.add_space(10.);
        if self.duplicate_ui.report.is_some() {
            self.results_card(ui, t, busy);
        }
    }

    pub(super) fn duplicates_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let busy = self.busy();
        self.duplicate_action_bar(ui, t, ctx, busy);
    }

    pub(super) fn duplicates_dialog(&mut self, ctx: &egui::Context) {
        if !self.duplicate_ui.cleanup_review {
            return;
        }
        if !self.busy() && ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
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
            ui.heading("Review duplicate files");
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
                ui.checkbox(
                    &mut self.duplicate_ui.acknowledge_all_copies,
                    "I reviewed the groups and want to continue",
                );
            }
            ui.add_space(18.);
            ui.horizontal(|ui| {
                if theme::secondary(ui, "Keep files", true) {
                    self.duplicate_ui.cleanup_review = false;
                    self.duplicate_ui.acknowledge_all_copies = false;
                }
                let can_continue = selected_count > 0
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
                if report.cancelled {
                    self.notice = Some(
                        "Duplicate scan cancelled. Review the partial results; they cannot be cleaned until you scan again.".into(),
                    );
                } else if report.partial {
                    self.notice = Some(format!(
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
            DuplicateEvent::Cleaned(result) => {
                self.worker = None;
                self.duplicate_ui.cleanup_review = false;
                self.duplicate_ui.acknowledge_all_copies = false;
                self.duplicate_ui.report = None;
                match result {
                    Ok(record) => {
                        self.notice = Some(format!(
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
                match store::history(&self.data_dir) {
                    Ok(history) => {
                        self.history = history;
                        self.history_readable = true;
                    }
                    Err(error) => {
                        self.error = Some(error);
                        self.history_readable = false;
                    }
                }
            }
        }
    }

    fn source_card(&mut self, ui: &mut egui::Ui, t: Tokens, busy: bool) {
        let mut scope_changed = false;
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Where to look").family(theme::semibold()));
            ui.add_space(8.);
            ui.horizontal_wrapped(|ui| {
                ui.add_enabled_ui(!busy, |ui| {
                    scope_changed |= ui
                        .radio_value(&mut self.duplicate_ui.scope, ScanScope::Drives, "Drives")
                        .changed();
                    scope_changed |= ui
                        .radio_value(
                            &mut self.duplicate_ui.scope,
                            ScanScope::Folders,
                            "Choose specific folders",
                        )
                        .changed();
                });
            });
            ui.add_space(8.);
            match self.duplicate_ui.scope {
                ScanScope::Drives => self.drive_picker(ui, t, busy),
                ScanScope::Folders => self.folder_picker(ui, t, busy),
            }
        });
        if scope_changed {
            self.invalidate_duplicate_report();
        }
    }

    fn drive_picker(&mut self, ui: &mut egui::Ui, t: Tokens, busy: bool) {
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
            if theme::secondary(ui, "Refresh drives", !busy) {
                let old = self
                    .duplicate_ui
                    .drives
                    .iter()
                    .map(|drive| (path_identity(&drive.path), drive.selected))
                    .collect::<std::collections::HashMap<_, _>>();
                let refreshed = available_drives()
                    .into_iter()
                    .map(|path| DriveChoice {
                        selected: old.get(&path_identity(&path)).copied().unwrap_or(true),
                        path,
                    })
                    .collect();
                settings_changed = true;
                self.duplicate_ui.drives = refreshed;
            }
        });
        if self.duplicate_ui.drives.is_empty() {
            theme::muted(
                ui,
                "No accessible drive roots were found. Choose specific folders instead.",
                t,
            );
            if settings_changed {
                self.invalidate_duplicate_report();
            }
            return;
        }
        egui::Grid::new("duplicate-drive-choices")
            .num_columns(2)
            .spacing(Vec2::new(26., 4.))
            .show(ui, |ui| {
                for (index, drive) in self.duplicate_ui.drives.iter_mut().enumerate() {
                    settings_changed |= ui
                        .add_enabled(
                            !busy,
                            egui::Checkbox::new(
                                &mut drive.selected,
                                drive.path.display().to_string(),
                            ),
                        )
                        .changed();
                    if index % 2 == 1 {
                        ui.end_row();
                    }
                }
            });
        theme::muted(
            ui,
            "Drive scanning is read-only. Select only the locations you want included.",
            t,
        );
        if settings_changed {
            self.invalidate_duplicate_report();
        }
    }

    fn folder_picker(&mut self, ui: &mut egui::Ui, t: Tokens, busy: bool) {
        let mut settings_changed = false;
        ui.horizontal_wrapped(|ui| {
            if theme::secondary(ui, "Add folder", !busy) {
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
                    ui.add(egui::Label::new(folder.display().to_string()).truncate())
                        .on_hover_text(folder.display().to_string());
                    if ui.small_button("Remove").clicked() {
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
        let mut scan_option_changed = false;
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Scan settings").family(theme::semibold()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.checkbox(&mut self.duplicate_ui.options_open, "Show options");
                });
            });
            ui.horizontal_wrapped(|ui| {
                theme::muted(ui, "Minimum file size", t);
                scan_option_changed |= ui
                    .add_enabled(
                        !busy,
                        egui::TextEdit::singleline(&mut self.duplicate_ui.minimum_size_text)
                            .desired_width(110.)
                            .hint_text("65536"),
                    )
                    .changed();
                theme::muted(ui, "bytes · default 65,536 bytes", t);
            });
            if self.duplicate_ui.options_open {
                ui.add_space(8.);
                ui.horizontal_wrapped(|ui| {
                    theme::muted(ui, "File types", t);
                    scan_option_changed |= ui
                        .add_enabled(
                            !busy,
                            egui::TextEdit::singleline(&mut self.duplicate_ui.file_types_text)
                                .desired_width(260.)
                                .hint_text("All types, or: jpg, pdf, tar.gz"),
                        )
                        .changed();
                });
                theme::muted(
                    ui,
                    "Leave blank for all types. Enter extensions separated by commas.",
                    t,
                );
                ui.add_space(6.);
                ui.horizontal_wrapped(|ui| {
                    scan_option_changed |= ui
                        .add_enabled(
                            !busy,
                            egui::Checkbox::new(
                                &mut self.duplicate_ui.options.include_hidden,
                                "Include hidden files",
                            ),
                        )
                        .changed();
                    scan_option_changed |= ui
                        .add_enabled(
                            !busy,
                            egui::Checkbox::new(
                                &mut self.duplicate_ui.options.include_system,
                                "Include system files",
                            ),
                        )
                        .changed();
                    scan_option_changed |= ui
                        .add_enabled(
                            !busy,
                            egui::Checkbox::new(
                                &mut self.duplicate_ui.options.include_read_only,
                                "Include read-only files",
                            ),
                        )
                        .changed();
                    scan_option_changed |= ui
                        .add_enabled(
                            !busy,
                            egui::Checkbox::new(
                                &mut self.duplicate_ui.options.include_compressed,
                                "Include compressed files",
                            ),
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
        if scan_option_changed {
            self.invalidate_duplicate_report();
        }
    }

    fn results_card(&mut self, ui: &mut egui::Ui, t: Tokens, busy: bool) {
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Duplicate results").family(theme::semibold()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if let Some(report) = &self.duplicate_ui.report {
                        theme::muted(
                            ui,
                            format!(
                                "{} groups · {} duplicate files",
                                report.groups.len(), report.duplicate_files
                            ),
                            t,
                        );
                    }
                });
            });
            ui.add_space(8.);
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

            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(size_text(report.potential_reclaimable_bytes))
                        .size(22.)
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
            ui.add_space(8.);
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
                    if report.cancelled {
                        "No verified duplicate groups were completed before cancellation."
                    } else {
                        "No identical files were found in this scan."
                    },
                    t,
                );
            } else {
                let cancelled = report.cancelled;
                egui::ScrollArea::vertical()
                    .id_salt("duplicate-groups")
                    .max_height(440.)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        for group in &mut report.groups {
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
                            egui::CollapsingHeader::new(title)
                                .id_salt(group.id)
                                .show(ui, |ui| {
                                    ui.horizontal_wrapped(|ui| {
                                        let mut all_selected = group.files.iter().all(|file| file.selected);
                                        if ui
                                            .add_enabled(
                                                !busy && !cancelled,
                                                egui::Checkbox::new(
                                                    &mut all_selected,
                                                    "Select every copy in this group",
                                                ),
                                            )
                                            .changed()
                                        {
                                            for file in &mut group.files {
                                                file.selected = all_selected;
                                            }
                                        }
                                        theme::muted(
                                            ui,
                                            "Groups contain byte-for-byte verified matches.",
                                            t,
                                        );
                                    });
                                    ui.add_space(4.);
                                    for file_index in 0..group.files.len() {
                                        let mut keep_this_copy = false;
                                        ui.separator();
                                        {
                                            let file = &mut group.files[file_index];
                                            ui.horizontal(|ui| {
                                            ui.add_enabled(
                                                !busy && !cancelled,
                                                egui::Checkbox::without_text(&mut file.selected),
                                            );
                                            ui.vertical(|ui| {
                                                let path = file.candidate.path.display().to_string();
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(
                                                            file.candidate
                                                                .path
                                                                .file_name()
                                                                .map(|name| name.to_string_lossy())
                                                                .unwrap_or_default(),
                                                        )
                                                        .family(theme::semibold()),
                                                    )
                                                    .truncate(),
                                                )
                                                .on_hover_text(&path);
                                                ui.add(egui::Label::new(path).truncate())
                                                    .on_hover_text(
                                                        file.candidate.path.display().to_string(),
                                                    );
                                                theme::muted(
                                                    ui,
                                                    format!(
                                                        "Created {} · Modified {} · {}",
                                                        datetime_display(file.candidate.created_ns),
                                                        datetime_display(Some(
                                                            file.candidate.modified_ns,
                                                        )),
                                                        size_text(file.candidate.size)
                                                    ),
                                                    t,
                                                );
                                            });
                                                ui.with_layout(
                                                    Layout::right_to_left(Align::Center),
                                                    |ui| {
                                                        keep_this_copy = ui
                                                            .add_enabled(
                                                                !busy && !cancelled,
                                                                egui::Button::new("Keep this copy"),
                                                            )
                                                            .on_hover_text(
                                                                "Keep this file and select the other copies in this group for review.",
                                                            )
                                                            .clicked();
                                                    },
                                                );
                                            });
                                        }
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
                    });
            }
            if report.skipped_count > 0 {
                egui::CollapsingHeader::new(format!(
                    "Skipped entries · {} total",
                    report.skipped_count
                ))
                .id_salt("duplicate-skipped-entries")
                .show(ui, |ui| {
                    for skipped in &report.skipped_entries {
                        ui.horizontal_wrapped(|ui| {
                            theme::muted(ui, skip_reason_label(&skipped.reason), t);
                            if let Some(path) = &skipped.path {
                                ui.add(egui::Label::new(path.display().to_string()).truncate())
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
        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            theme::muted(
                ui,
                format!("{selected_count} selected · {}", size_text(selected_bytes)),
                t,
            );
            ui.add_space(12.);
            if theme::secondary(ui, "Scan", !busy) {
                self.begin_duplicate_scan(ctx);
            }
            if theme::primary(ui, "Review files", t, enabled) {
                self.duplicate_ui.cleanup_review = true;
                self.duplicate_ui.acknowledge_all_copies = false;
            }
            if !self.history_readable {
                theme::muted(ui, "History unavailable; review is disabled", t);
            }
        });
    }

    fn begin_duplicate_scan(&mut self, ctx: &egui::Context) {
        if self.busy() {
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
        let (tx, rx) = mpsc::channel();
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
        if self.busy() || !self.history_readable {
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
        let (tx, rx) = mpsc::channel();
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
            let _ = tx.send(Event::Duplicate(DuplicateEvent::Cleaned(result)));
            ctx.request_repaint();
        });
    }

    fn invalidate_duplicate_report(&mut self) {
        if self.duplicate_ui.report.take().is_some() {
            self.notice =
                Some("Scan settings changed. Run a new scan to review matching files.".into());
        }
        self.duplicate_ui.cleanup_review = false;
        self.duplicate_ui.acknowledge_all_copies = false;
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
