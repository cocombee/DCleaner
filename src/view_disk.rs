use super::*;

#[derive(Default)]
pub(super) struct DiskUi {
    details: Option<Uuid>,
}

impl App {
    #[cfg(debug_assertions)]
    pub(super) fn qa_disk_detail_open(&self) -> bool {
        self.disk_ui.details.is_some()
    }
    #[cfg(debug_assertions)]
    pub(super) fn seed_disk_qa(&mut self, case: &str) {
        let root = PathBuf::from(r"C:\__dcleaner_visual_fixture__");
        let files = if case == "disk-empty" {
            Vec::new()
        } else {
            (0..24).map(|index| dcleaner::domain::Candidate {
                id: Uuid::from_u128(0xD15C_0000 + index),
                path: root.join(format!("Projects/Reference materials/Long directory name for column clipping checks/Archive-{index:02}-with-a-deliberately-long-filename-for-table-width-review.bin")),
                root: root.clone(),
                size: 31_244_000_000 / (index as u64 + 1),
                modified_ns: 0,
                created_ns: None,
            }).collect::<Vec<_>>()
        };
        self.disk_ui.details = if case == "disk-details" {
            files.first().map(|file| file.id)
        } else {
            None
        };
        self.disk = Some(DiskReport {
            root,
            count: files.len(),
            bytes: files.iter().map(|file| file.size).sum(),
            files,
            skipped: if case == "disk-partial" { 4 } else { 0 },
            partial: case == "disk-partial",
        });
    }
    pub(super) fn disk_page(&mut self, ui: &mut egui::Ui, t: Tokens, _ctx: &egui::Context) {
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());

            if let Some(report) = self.disk.clone() {
                ui.label(RichText::new("Largest files").family(theme::semibold()));
                ui.add_space(6.);

                let root = report.root.display().to_string();
                ui.add(egui::Label::new(root.clone()).truncate().show_tooltip_when_elided(false))
                    .on_hover_text(root);
                ui.add_space(8.);

                let summary = format!(
                    "{} · {} files scanned · {} skipped{}",
                    size(report.bytes),
                    report.count,
                    report.skipped,
                    if report.partial { " · partial results" } else { "" }
                );
                ui.label(summary);
                if report.partial {
                    theme::muted(
                        ui,
                        "Some entries could not be fully read. The totals and list describe only the files this scan observed.",
                        t,
                    );
                }
                if report.files.len() < report.count {
                    theme::muted(
                        ui,
                        format!("Showing the largest {} files.", report.files.len()),
                        t,
                    );
                }

                ui.add_space(10.);
                let size_width = 100.0;
                let actions_width = 82.0;
                let gap = ui.spacing().item_spacing.x;
                let path_width = (ui.available_width()
                    - ui.spacing().scroll.allocated_width()
                    - size_width
                    - actions_width
                    - gap * 2.)
                    .max(52.);

                ui.horizontal(|ui| {
                    theme::table_cell(
                        ui,
                        RichText::new("Path").family(theme::semibold()),
                        path_width,
                        32.,
                    );
                    ui.allocate_ui_with_layout(
                        Vec2::new(size_width, 32.),
                        Layout::right_to_left(Align::Center),
                        |ui| {
                            ui.label(RichText::new("Size").family(theme::semibold()));
                        },
                    );
                    ui.allocate_ui_with_layout(
                        Vec2::new(actions_width, 32.),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            ui.label(RichText::new("Details").family(theme::semibold()));
                        },
                    );
                });
                ui.separator();

                let body_height = (ui.clip_rect().bottom() - ui.cursor().top() - 28. - 24. - theme::LABEL_GAP)
                    .max(88.);
                if !report.files.is_empty() { ui.scope(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.;
                    let table_scroll = theme::scroll_vertical()
                    .id_salt("disk-results-table")
                        .max_height(body_height)
                    .auto_shrink([false, true])
                    .show_rows(ui, theme::TABLE_ROW_HEIGHT, report.files.len(), |ui, range| {
                        for index in range {
                            let file = &report.files[index];
                            let path = file.path.display().to_string();
                            ui.push_id(file.id, |ui| {
                                let row = ui.horizontal(|ui| {
                                    theme::table_cell_with_tooltip(
                                        ui,
                                        path.clone(),
                                        path_width,
                                        theme::TABLE_ROW_HEIGHT, path);
                                    ui.allocate_ui_with_layout(
                                        Vec2::new(size_width, theme::TABLE_ROW_HEIGHT),
                                        Layout::right_to_left(Align::Center),
                                        |ui| {
                                            ui.label(size(file.size));
                                        },
                                    );
                                    ui.allocate_ui_with_layout(
                                        Vec2::new(actions_width, theme::TABLE_ROW_HEIGHT),
                                        Layout::left_to_right(Align::Center),
                                        |ui| {
                                            if theme::row_action(ui, "Details", true).clicked() {
                                                self.disk_ui.details = Some(file.id);
                                            }
                                        },
                                    );
                                });
                                let rect = row.response.rect;
                                ui.painter().line_segment(
                                    [rect.left_bottom(), rect.right_bottom()],
                                    egui::Stroke::new(1., t.border),
                                );
                            });
                        }
                    });
                    #[cfg(debug_assertions)]
                    theme::record_scroll(_ctx, "disk-table", table_scroll.inner_rect, table_scroll.content_size, table_scroll.state.offset);
                    #[cfg(not(debug_assertions))]
                    let _ = table_scroll;
                }); }

                if report.files.is_empty() {
                    ui.add_space(20.);
                    theme::muted(ui, "No files were returned by this scan.", t);
                }
            } else {
                ui.add_space(28.);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("See where your space goes").size(theme::FONT_TITLE));
                    ui.add_space(8.);
                    theme::muted(
                        ui,
                        "Choose a folder for a read-only size analysis. DCleaner will not change the files.",
                        t,
                    );
                });
                ui.add_space(28.);
            }
        });
    }

    pub(super) fn disk_dialog(&mut self, ctx: &egui::Context) {
        let Some(selected_id) = self.disk_ui.details else {
            return;
        };
        let Some(file) = self
            .disk
            .as_ref()
            .and_then(|report| report.files.iter().find(|file| file.id == selected_id))
            .cloned()
        else {
            self.disk_ui.details = None;
            return;
        };

        let t = theme::tokens(self.prefs.dark);
        let path = file.path.display().to_string();
        let mut close = false;
        let mut copy_path = false;
        let response = egui::Modal::new(egui::Id::new("disk-file-details"))
            .frame(theme::dialog_frame(t))
            .show(ctx, |ui| {
                ui.set_width((ctx.content_rect().width() - 80.).clamp(300., 560.));
                ui.heading("File details");
                ui.add_space(12.);
                ui.label(
                    RichText::new(
                        file.path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("File name unavailable"),
                    )
                    .family(theme::semibold()),
                );
                ui.add_space(10.);
                ui.horizontal_wrapped(|ui| {
                    theme::muted(ui, "Size", t);
                    ui.label(size(file.size));
                });
                ui.add_space(8.);
                theme::muted(ui, "Full path", t);
                theme::scroll_vertical()
                    .id_salt("disk-details-path")
                    .max_height(150.)
                    .show(ui, |ui| {
                        ui.add(egui::Label::new(path.clone()).wrap());
                    });
                ui.add_space(16.);
                theme::action_row(ui, |ui| {
                    if theme::secondary(ui, "Close", true) {
                        close = true;
                    }
                    if theme::primary(ui, "Copy path", t, true) {
                        copy_path = true;
                    }
                });
            });

        if close || response.should_close() {
            self.disk_ui.details = None;
        }
        if copy_path {
            ctx.copy_text(path);
        }
    }
}
