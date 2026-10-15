use super::*;
use dcleaner::support::{self, BrowserHandoff, Destination, DiagnosticReport};

#[derive(Default)]
pub(super) struct HelpUi {
    preview: Option<DiagnosticReport>,
    export_status: Option<Result<(), String>>,
}

pub(super) enum HelpEvent {
    Browser(Result<BrowserHandoff, String>),
    Exported(Result<(), String>),
}

impl App {
    #[cfg(debug_assertions)]
    pub(super) fn seed_help_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Help QA fixtures require isolated fixture mode.".into());
        }
        if !matches!(case, "help" | "help-diagnostics") {
            return Err(format!("Unsupported Help QA fixture: {case}"));
        }
        self.page = Page::Help;
        self.help_ui = HelpUi::default();
        if case == "help-diagnostics" {
            self.help_ui.preview = Some(DiagnosticReport::new(
                self.settings_readable,
                self.history_readable,
            ));
        }
        self.error = None;
        self.notice = None;
        self.progress.clear();
        Ok(())
    }

    fn begin_help_handoff(&mut self, destination: Destination, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        self.error = None;
        self.notice = None;
        self.progress = "Requesting the default browser…".into();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let ctx = ctx.clone();
        thread::spawn(move || {
            let result = std::panic::catch_unwind(|| support::open_native(destination))
                .unwrap_or_else(|_| Err("The browser handoff ended without a result. Check your browser before trying again.".into()));
            let _ = tx.send(Event::Help(HelpEvent::Browser(result)));
            ctx.request_repaint();
        });
    }

    pub(super) fn help_event(&mut self, event: HelpEvent) {
        self.worker = None;
        match event {
            HelpEvent::Browser(result) => match result {
                Ok(handoff) => {
                    let label = match handoff.destination {
                        Destination::HelpCentre => "Help Centre",
                        Destination::ContactSupport => "Support",
                    };
                    self.notice = Some(format!(
                        "{label}: browser handoff accepted. If the page does not load, check your browser and connection."
                    ));
                }
                Err(error) => self.error = Some(error),
            },
            HelpEvent::Exported(result) => {
                self.help_ui.export_status = Some(result.clone());
                match result {
                    Ok(()) => {
                        self.notice = Some("Diagnostic report saved. Nothing was uploaded.".into())
                    }
                    Err(error) => self.error = Some(error),
                }
            }
        }
    }

    pub(super) fn help_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if self.qa_fixture_mode() {
            theme::muted(
                ui,
                "QA fixture — links and export are disabled; diagnostics are synthetic and local.",
                t,
            );
            ui.add_space(6.);
        }
        ui.set_max_width(555.);
        ui.label(
            RichText::new("Visit Help Centre")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
        ui.add_space(8.);
        theme::muted(
            ui,
            "Find guidance for scanning, reviewing results and managing supported changes.",
            t,
        );
        ui.add_space(16.);
        if theme::secondary(
            ui,
            "Go to Help Centre",
            !self.busy() && !self.qa_fixture_mode(),
        ) {
            self.begin_help_handoff(Destination::HelpCentre, ctx);
        }
        ui.add_space(28.);
        ui.separator();
        ui.add_space(20.);
        ui.label(
            RichText::new("DCleaner support")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
        ui.add_space(8.);
        theme::muted(
            ui,
            "Having trouble? Open the project's support page. You can also review and save a small local diagnostic report to share yourself.",
            t,
        );
        ui.add_space(16.);
        theme::action_row(ui, |ui| {
            if theme::secondary(
                ui,
                "Contact support",
                !self.busy() && !self.qa_fixture_mode(),
            ) {
                self.begin_help_handoff(Destination::ContactSupport, ctx);
            }
            if theme::secondary(ui, "Review diagnostics", !self.busy()) {
                self.help_ui.preview = Some(DiagnosticReport::new(
                    self.settings_readable,
                    self.history_readable,
                ));
                self.help_ui.export_status = None;
            }
        });
        ui.add_space(12.);
        theme::muted(
            ui,
            "Links open in your default browser. Diagnostics stay on this device until you choose to share them.",
            t,
        );
    }

    pub(super) fn help_dialog(&mut self, ctx: &egui::Context) {
        let Some(report) = self.help_ui.preview.clone() else {
            return;
        };
        let t = theme::tokens(self.prefs.dark);
        let busy = self.busy();
        let fixture_mode = self.qa_fixture_mode();
        let mut close = false;
        let mut save = false;
        let encoded = report.to_json().and_then(|bytes| {
            String::from_utf8(bytes).map_err(|_| "Diagnostic encoding is unavailable.".to_owned())
        });
        let response = egui::Modal::new(egui::Id::new("help-diagnostics"))
            .frame(theme::dialog_frame(t)).show(ctx, |ui| {
                ui.set_width((ctx.content_rect().width() - 32.).clamp(280., 560.));
                ui.heading("Review diagnostics");
                ui.add_space(12.);
                egui::ScrollArea::vertical().id_salt("help-diagnostic-preview")
                    .max_height((ctx.content_rect().height() - 220.).max(80.)).show(ui, |ui| {
                        theme::muted(ui, "This is the complete report: app version, operating system, architecture, time and whether preferences and history could be read. It contains no file paths, program lists or raw error messages.", t);
                        ui.add_space(12.);
                        match &encoded {
                            Ok(json) => { ui.add(egui::Label::new(RichText::new(json).monospace()).wrap()); }
                            Err(error) => { theme::muted(ui, error, t); }
                        }
                        ui.add_space(12.);
                        theme::muted(ui, "Choose a new filename. Existing files are preserved. Saving does not send the report to support.", t);
                        if let Some(status) = &self.help_ui.export_status {
                            ui.add_space(12.);
                            theme::muted(ui, match status {
                                Ok(()) => "Diagnostic report saved. Nothing was uploaded.",
                                Err(error) => error,
                            }, t);
                        }
                    });
                ui.add_space(12.);
                ui.separator();
                ui.add_space(8.);
                theme::action_row(ui, |ui| {
                    if theme::secondary(ui, "Close", !busy) { close = true; }
                    if theme::primary(ui, "Save report…", t, !busy && !fixture_mode && encoded.is_ok()) { save = true; }
                    if busy { ui.spinner(); }
                });
            });
        if !busy && (close || response.should_close()) {
            self.help_ui.preview = None;
        } else if save {
            self.begin_diagnostic_export(report, ctx);
        }
    }

    fn begin_diagnostic_export(&mut self, report: DiagnosticReport, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        // Only reached from the user's Save action after viewing the complete report.
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save diagnostic report")
            .add_filter("JSON report", &["json"])
            .set_file_name("DCleaner-diagnostics.json")
            .save_file()
        else {
            return;
        };
        self.error = None;
        self.notice = None;
        self.progress = "Saving diagnostic report…".into();
        self.help_ui.export_status = None;
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let ctx = ctx.clone();
        thread::spawn(move || {
            let result = std::panic::catch_unwind(|| support::export_new(&path, &report))
                .unwrap_or_else(|_| Err("Diagnostic export ended without a result. A partial new file may remain; check it before choosing a new filename.".into()));
            let _ = tx.send(Event::Help(HelpEvent::Exported(result)));
            ctx.request_repaint();
        });
    }
}
