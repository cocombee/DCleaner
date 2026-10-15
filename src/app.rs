use crate::theme::{self, Tokens};
use dcleaner::{
    clean_settings,
    cleanup::{self, SystemTrash},
    custom_clean,
    domain::{Analysis, Category, CleanupResult, Preferences},
    platform, scanner, store,
};
use eframe::egui::{self, Align, Color32, Layout, RichText, Vec2};
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread,
    time::Duration,
};
use uuid::Uuid;
#[path = "view_clean_settings.rs"]
mod view_clean_settings;
#[path = "view_cloud.rs"]
mod view_cloud;
#[path = "view_drivers.rs"]
mod view_drivers;
#[path = "view_duplicates.rs"]
mod view_duplicates;
#[path = "view_health.rs"]
mod view_health;
#[path = "view_help.rs"]
mod view_help;
#[path = "view_optimizer.rs"]
mod view_optimizer;
#[path = "view_privacy.rs"]
mod view_privacy;
#[path = "view_programs.rs"]
mod view_programs;
#[path = "view_recycle_bin.rs"]
mod view_recycle_bin;
#[path = "view_software.rs"]
mod view_software;
#[path = "view_startup.rs"]
mod view_startup;

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Overview,
    Clean,
    Disk,
    Duplicates,
    Cloud,
    Programs,
    Optimizer,
    Startup,
    Software,
    Drivers,
    History,
    Settings,
    Help,
}
impl Page {
    fn icon(self) -> theme::Icon {
        match self {
            Self::Overview => theme::Icon::Home,
            Self::Clean => theme::Icon::Brush,
            Self::Disk => theme::Icon::Disk,
            Self::Duplicates => theme::Icon::Duplicate,
            Self::Cloud => theme::Icon::Cloud,
            Self::Programs => theme::Icon::Programs,
            Self::Optimizer => theme::Icon::Optimizer,
            Self::Startup => theme::Icon::Startup,
            Self::Software => theme::Icon::Update,
            Self::Drivers => theme::Icon::Driver,
            Self::History => theme::Icon::History,
            Self::Settings => theme::Icon::Settings,
            Self::Help => theme::Icon::Help,
        }
    }
    fn description(self) -> &'static str {
        match self {
            Self::Overview => "Review your scan results and cleanup activity.",
            Self::Clean => "Choose what to scan, then review the files to remove.",
            Self::Disk => "Find the largest files in a folder.",
            Self::Duplicates => "Find identical files and review which copies to keep.",
            Self::Cloud => "Review cloud files and mail, then choose what to clean.",
            Self::Programs => "Review installed applications and their registered uninstallers.",
            Self::Optimizer => {
                "Review applications, background components and optimization exclusions."
            }
            Self::Startup => "Manage the programs and services that start automatically.",
            Self::Software => "Review available application updates and their current status.",
            Self::Drivers => "Review present devices and exact driver offers from Windows Update.",
            Self::History => "Review confirmed changes and interrupted operations.",
            Self::Settings => "Set your cleaning preferences and appearance.",
            Self::Help => "Find guidance, contact support and review local diagnostics.",
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Overview => "Health Check",
            Self::Clean => "Custom Clean",
            Self::Disk => "Disk Analyzer",
            Self::Duplicates => "Duplicate Finder",
            Self::Cloud => "Cloud Drive Cleaner",
            Self::Programs => "Uninstaller",
            Self::Optimizer => "Performance Optimizer",
            Self::Startup => "Startup Manager",
            Self::Software => "Software Updater",
            Self::Drivers => "Driver Updater",
            Self::History => "Cleanup History",
            Self::Settings => "Settings",
            Self::Help => "Help",
        }
    }
}
const PAGES: [Page; 13] = [
    Page::Overview,
    Page::Clean,
    Page::Programs,
    Page::Duplicates,
    Page::Cloud,
    Page::Optimizer,
    Page::Startup,
    Page::Software,
    Page::Drivers,
    Page::Disk,
    Page::History,
    Page::Settings,
    Page::Help,
];
enum Event {
    Cloud(view_cloud::CloudEvent),
    CleanSettings(view_clean_settings::CleanSettingsEvent),
    ConfiguredScanned(Result<custom_clean::CustomCleanReport, String>),
    Health(view_health::HealthEvent),
    Help(view_help::HelpEvent),
    RecycleBin(view_recycle_bin::RecycleBinEvent),
    Privacy(view_privacy::PrivacyEvent),
    Software(view_software::SoftwareEvent),
    Duplicate(view_duplicates::DuplicateEvent),
    Programs(view_programs::ProgramsEvent),
    Optimizer(view_optimizer::OptimizerEvent),
    Startup(view_startup::StartupEvent),
    Drivers(view_drivers::DriverEvent),
    Progress(String),
    Cleaned(Result<CleanupResult, String>),
    Disk(Result<DiskReport, String>),
}
#[derive(Clone)]
struct DiskReport {
    root: PathBuf,
    count: usize,
    bytes: u64,
    files: Vec<dcleaner::domain::Candidate>,
    skipped: usize,
    partial: bool,
}
pub struct App {
    logo_texture: Option<egui::TextureHandle>,
    cloud_ui: view_cloud::CloudUi,
    clean_settings_ui: view_clean_settings::CleanSettingsUi,
    custom_analysis: Option<custom_clean::CustomCleanReport>,
    custom_partial_acknowledged: bool,
    health_ui: view_health::HealthUi,
    help_ui: view_help::HelpUi,
    app_icons: crate::app_icons::IconCache,
    #[cfg(debug_assertions)]
    visual_capture: Option<crate::visual_qa::Capture>,
    software_ui: view_software::SoftwareUi,
    duplicate_ui: view_duplicates::DuplicateUi,
    program_ui: view_programs::ProgramsUi,
    optimizer_ui: view_optimizer::OptimizerUi,
    startup_ui: view_startup::StartupUi,
    drivers_ui: view_drivers::DriverUi,
    privacy_ui: view_privacy::PrivacyUi,
    recycle_bin_ui: view_recycle_bin::RecycleBinUi,
    clean_browser: bool,
    clean_bin: bool,
    page: Page,
    prefs: Preferences,
    categories: Vec<Category>,
    analysis: Option<Analysis>,
    selected: HashSet<Uuid>,
    history: Vec<CleanupResult>,
    disk: Option<DiskReport>,
    data_dir: PathBuf,
    worker: Option<Receiver<Event>>,
    cancel: Arc<AtomicBool>,
    progress: String,
    error: Option<String>,
    notice: Option<String>,
    search: String,
    group: String,
    confirm: bool,
    settings_readable: bool,
    history_readable: bool,
}
impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::new_with_context(&cc.egui_ctx)
    }
    pub(crate) fn new_with_context(context: &egui::Context) -> Self {
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert(
            "Inter".into(),
            Arc::new(egui::FontData::from_static(include_bytes!(
                "../assets/fonts/Inter-Regular.ttf"
            ))),
        );
        fonts
            .families
            .get_mut(&egui::FontFamily::Proportional)
            .unwrap()
            .insert(0, "Inter".into());
        fonts.font_data.insert(
            "Inter Semibold".into(),
            Arc::new(egui::FontData::from_static(include_bytes!(
                "../assets/fonts/Inter-SemiBold.ttf"
            ))),
        );
        fonts.families.insert(
            theme::semibold(),
            vec!["Inter Semibold".into(), "Inter".into()],
        );
        context.set_fonts(fonts);
        let logo_texture = dcleaner::brand::icon().ok().map(|icon| {
            context.load_texture(
                "dcleaner-brand",
                egui::ColorImage::from_rgba_unmultiplied(
                    [icon.width as usize, icon.height as usize],
                    &icon.rgba,
                ),
                egui::TextureOptions::LINEAR,
            )
        });
        let (data_dir, mut error) = match platform::data_directory() {
            Ok(p) => (p, None),
            Err(e) => (PathBuf::new(), Some(e)),
        };
        let (prefs, settings_readable) = match store::load_preferences(&data_dir) {
            Ok(p) => (p, true),
            Err(e) => {
                error = Some(e);
                (Preferences::default(), false)
            }
        };
        let (history, history_readable) = match store::history(&data_dir) {
            Ok(h) => (h, true),
            Err(e) => {
                error = Some(e);
                (vec![], false)
            }
        };
        let clean_settings_result =
            clean_settings::load_settings(&data_dir).map_err(|failure| failure.to_string());
        if let Err(failure) = &clean_settings_result {
            error = Some(failure.clone());
        }
        let clean_settings_ui =
            view_clean_settings::CleanSettingsUi::from_saved(clean_settings_result);
        #[cfg(debug_assertions)]
        let visual_capture = crate::visual_qa::Capture::from_environment();
        #[cfg(debug_assertions)]
        let qa_mode =
            visual_capture.is_some() || std::env::args().any(|arg| arg == "--render-offscreen-qa");
        #[cfg(debug_assertions)]
        let prefs = {
            let mut prefs = prefs;
            if qa_mode {
                prefs.dark = std::env::var("DCLEANER_QA_THEME").as_deref() != Ok("light");
            }
            prefs
        };
        theme::apply(context, prefs.dark);
        let initial_page = Page::Overview;
        #[cfg(debug_assertions)]
        let initial_page = if qa_mode {
            match std::env::var("DCLEANER_QA_PAGE").as_deref() {
                Ok("clean") => Page::Clean,
                Ok("browser") | Ok("recyclebin") => Page::Clean,
                Ok("duplicates") => Page::Duplicates,
                Ok("programs") => Page::Programs,
                Ok("optimizer") => Page::Optimizer,
                Ok("startup") => Page::Startup,
                Ok("software") => Page::Software,
                Ok("drivers") => Page::Drivers,
                Ok("disk") => Page::Disk,
                Ok("history") => Page::History,
                Ok("settings") => Page::Settings,
                Ok("help") => Page::Help,
                _ => Page::Overview,
            }
        } else {
            initial_page
        };
        #[cfg(debug_assertions)]
        let (clean_browser, clean_bin) = if qa_mode {
            let page = std::env::var("DCLEANER_QA_PAGE").unwrap_or_default();
            (page == "browser", page == "recyclebin")
        } else {
            (false, false)
        };
        #[cfg(not(debug_assertions))]
        let (clean_browser, clean_bin) = (false, false);
        Self {
            logo_texture,
            clean_settings_ui,
            custom_analysis: None,
            custom_partial_acknowledged: false,
            health_ui: Default::default(),
            help_ui: Default::default(),
            cloud_ui: Default::default(),
            #[cfg(debug_assertions)]
            visual_capture,
            software_ui: Default::default(),
            duplicate_ui: Default::default(),
            program_ui: Default::default(),
            optimizer_ui: Default::default(),
            startup_ui: Default::default(),
            drivers_ui: Default::default(),
            app_icons: Default::default(),
            privacy_ui: Default::default(),
            recycle_bin_ui: Default::default(),
            clean_browser,
            clean_bin,
            page: initial_page,
            prefs,
            categories: platform::categories(),
            analysis: None,
            selected: HashSet::new(),
            history,
            disk: None,
            data_dir,
            worker: None,
            cancel: Arc::new(AtomicBool::new(false)),
            progress: String::new(),
            error,
            notice: None,
            search: String::new(),
            group: if cfg!(windows) {
                "Windows".into()
            } else {
                "macOS".into()
            },
            confirm: false,
            settings_readable,
            history_readable,
        }
    }
    fn busy(&self) -> bool {
        self.worker.is_some()
    }
    fn begin_scan(&mut self, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        self.page = Page::Clean;
        self.error = None;
        self.analysis = None;
        self.custom_analysis = None;
        self.custom_partial_acknowledged = false;
        self.selected.clear();
        self.progress = "Preparing analysis…".into();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let categories = self.categories.clone();
        let ids = self.prefs.selected_categories.clone();
        let age = self.prefs.minimum_age_days;
        let root = self.data_dir.clone();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let result = clean_settings::load_settings(&root)
                .map_err(|error| error.to_string())
                .and_then(|settings| {
                    let options = custom_clean::ScanOptions {
                        categories,
                        selected_legacy_ids: ids,
                        default_age_days: age,
                        ..Default::default()
                    };
                    custom_clean::scan(&settings, &options, &cancel, |progress| {
                        let _ = tx.send(Event::Progress(format!(
                            "{} · {} files reviewed",
                            progress.rule_name, progress.visited
                        )));
                        ctx.request_repaint();
                    })
                });
            let _ = tx.send(Event::ConfiguredScanned(result));
            ctx.request_repaint();
        });
    }
    fn begin_clean(&mut self, ctx: &egui::Context) {
        if self.busy() || !self.history_readable {
            return;
        }
        let Some(analysis) = self.analysis.clone() else {
            return;
        };
        self.confirm = false;
        self.error = None;
        self.progress = "Checking selected files…".into();
        let ids: Vec<_> = self.selected.iter().copied().collect();
        let configured = self.custom_analysis.clone();
        let acknowledge_partial = self.custom_partial_acknowledged;
        let root = self.data_dir.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let result = (|| {
                let mut journal = store::DeferredJournal::new(&root, Uuid::new_v4());
                if let Some(report) = configured {
                    let settings =
                        clean_settings::load_settings(&root).map_err(|error| error.to_string())?;
                    custom_clean::clean(
                        &report,
                        &settings,
                        &ids,
                        acknowledge_partial,
                        &cancel,
                        &mut SystemTrash,
                        &mut journal,
                        |done, total| {
                            let _ = tx.send(Event::Progress(format!(
                                "Reviewed {done} of {total} selected files"
                            )));
                            ctx.request_repaint();
                        },
                    )
                } else {
                    cleanup::clean(
                        &analysis,
                        &ids,
                        &cancel,
                        &mut SystemTrash,
                        &mut journal,
                        |done, total| {
                            let _ = tx.send(Event::Progress(format!(
                                "Reviewed {done} of {total} selected files"
                            )));
                            ctx.request_repaint();
                        },
                    )
                }
            })();
            let _ = tx.send(Event::Cleaned(result));
            ctx.request_repaint();
        });
    }
    fn begin_disk(&mut self, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        let Some(root) = rfd::FileDialog::new()
            .set_title("Choose a folder to analyze")
            .pick_folder()
        else {
            return;
        };
        self.error = None;
        self.progress = "Reading folder sizes…".into();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let result = scanner::walk(&root, u128::MAX, &cancel, scanner::MAX_ENTRIES, |n| {
                let _ = tx.send(Event::Progress(format!("Folder analysis · {n} files")));
                ctx.request_repaint();
            });
            let output = if !result.available {
                Err("The folder is unavailable or redirects through a link.".into())
            } else {
                let count = result.files.len();
                let bytes = result.files.iter().map(|f| f.size).sum();
                let mut files = result.files;
                files.sort_by_key(|f| std::cmp::Reverse(f.size));
                files.truncate(100);
                Ok(DiskReport {
                    root,
                    count,
                    bytes,
                    files,
                    skipped: result.skipped,
                    partial: result.truncated || cancel.load(Ordering::Relaxed),
                })
            };
            let _ = tx.send(Event::Disk(output));
            ctx.request_repaint();
        });
    }
    fn poll(&mut self) {
        let events: Vec<_> = self
            .worker
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default();
        for event in events {
            match event {
                Event::Cloud(event) => self.cloud_event(event),
                Event::CleanSettings(event) => self.clean_settings_event(event),
                Event::ConfiguredScanned(result) => {
                    self.worker = None;
                    match result {
                        Ok(report) => {
                            let analysis = report.to_analysis();
                            if !analysis.cancelled {
                                self.selected = analysis
                                    .categories
                                    .iter()
                                    .flat_map(|category| category.files.iter().map(|file| file.id))
                                    .collect();
                            }
                            self.analysis = Some(analysis);
                            self.custom_analysis = Some(report);
                        }
                        Err(error) => self.error = Some(error),
                    }
                }
                Event::Software(event) => self.software_event(event),
                Event::Duplicate(event) => self.duplicates_event(event),
                Event::Programs(event) => self.programs_event(event),
                Event::Optimizer(event) => self.optimizer_event(event),
                Event::Startup(event) => self.startup_event(event),
                Event::Drivers(event) => self.drivers_event(event),
                Event::Health(event) => self.health_event(event),
                Event::Help(event) => self.help_event(event),
                Event::Privacy(event) => self.privacy_event(event),
                Event::RecycleBin(event) => self.recycle_bin_event(event),
                Event::Progress(text) => self.progress = text,
                Event::Cleaned(result) => {
                    self.worker = None;
                    match result {
                        Ok(r) => {
                            let cleaned: HashSet<_> = r.cleaned_ids.iter().copied().collect();
                            if let Some(a) = &mut self.analysis {
                                for c in &mut a.categories {
                                    c.files.retain(|f| !cleaned.contains(&f.id));
                                }
                            }
                            self.selected.clear();
                            self.notice = Some(format!(
                                "{} moved to {}. {} files cleaned; {} skipped{}.",
                                size(r.bytes),
                                platform::trash_label(),
                                r.files,
                                r.failed.len(),
                                if r.cancelled { "; cleanup stopped" } else { "" }
                            ));
                        }
                        Err(e) => {
                            self.error = Some(format!(
                                "Cleanup stopped: {e}. Review History for confirmed and uncertain outcomes."
                            ));
                            self.analysis = None;
                            self.custom_analysis = None;
                            self.selected.clear();
                        }
                    }
                    match store::history(&self.data_dir) {
                        Ok(h) => {
                            self.history = h;
                            self.history_readable = true;
                        }
                        Err(e) => {
                            self.error = Some(e);
                            self.history_readable = false;
                        }
                    }
                }
                Event::Disk(result) => {
                    self.worker = None;
                    match result {
                        Ok(d) => self.disk = Some(d),
                        Err(e) => self.error = Some(e),
                    }
                }
            }
        }
    }
    fn persist(&mut self) {
        if !self.settings_readable {
            return;
        }
        if let Err(e) = store::save_preferences(&self.data_dir, &self.prefs) {
            self.error = Some(e);
        }
    }
    fn invalidate(&mut self) {
        self.analysis = None;
        self.custom_analysis = None;
        self.custom_partial_acknowledged = false;
        self.selected.clear();
        self.persist();
    }
    fn export(&mut self) {
        let Some(analysis) = &self.analysis else {
            return;
        };
        let Some(path) = rfd::FileDialog::new()
            .set_title("Export analysis report")
            .set_file_name("DCleaner Report.json")
            .add_filter("JSON report", &["json"])
            .save_file()
        else {
            return;
        };
        let serialized = if let Some(report) = &self.custom_analysis {
            serde_json::to_vec_pretty(report)
        } else {
            serde_json::to_vec_pretty(analysis)
        };
        match serialized
            .map_err(|e| e.to_string())
            .and_then(|b| std::fs::write(path, b).map_err(|e| e.to_string()))
        {
            Ok(()) => self.notice = Some("Analysis report exported.".into()),
            Err(e) => self.error = Some(e),
        }
    }
    fn overview(&mut self, ui: &mut egui::Ui, t: Tokens) {
        let files = self
            .analysis
            .as_ref()
            .map(|analysis| {
                format!(
                    "{} · {} files{}",
                    size(analysis.bytes()),
                    analysis.count(),
                    if analysis.cancelled {
                        " · cancelled"
                    } else {
                        ""
                    }
                )
            })
            .unwrap_or_else(|| "Not scanned".into());
        let rows = [
            (
                theme::Icon::Brush,
                "Disk Cleaner",
                "Review temporary files and application caches",
                files,
                Page::Clean,
                false,
            ),
            (
                theme::Icon::Browser,
                "Browser Cleaner",
                "Review cookies, browsing history and downloads",
                self.privacy_overview_status(),
                Page::Clean,
                true,
            ),
            (
                theme::Icon::Startup,
                "Startup Manager",
                "Manage apps and services that start automatically",
                self.startup_overview_status(),
                Page::Startup,
                false,
            ),
            (
                theme::Icon::Update,
                "Software Updater",
                "Review available updates for installed apps",
                self.software_overview_status(),
                Page::Software,
                false,
            ),
        ];
        for (icon, title, description, status, page, browser) in rows {
            if finding_row(ui, t, icon, title, description, &status, !self.busy()) {
                self.page = page;
                if page == Page::Clean {
                    self.clean_browser = browser;
                }
            }
            ui.add_space(6.);
        }
        ui.add_space(24.);
        ui.label(
            RichText::new("Here’s what you’ve cleaned so far")
                .family(theme::semibold())
                .size(12.),
        );
        ui.add_space(12.);
        let saved: u64 = self.history.iter().map(|record| record.bytes).sum();
        let files: usize = self.history.iter().map(|record| record.files).sum();
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    let (dot, _) = ui.allocate_exact_size(Vec2::splat(10.), egui::Sense::hover());
                    ui.painter().circle_filled(dot.center(), 4., t.attention);
                    ui.label(
                        RichText::new(size(saved))
                            .family(theme::semibold())
                            .size(14.),
                    );
                    theme::muted(ui, "of space", t);
                });
                ui.horizontal(|ui| {
                    let (dot, _) = ui.allocate_exact_size(Vec2::splat(10.), egui::Sense::hover());
                    ui.painter().circle_filled(dot.center(), 4., t.primary);
                    ui.label(
                        RichText::new(files.to_string())
                            .family(theme::semibold())
                            .size(14.),
                    );
                    theme::muted(ui, "items moved to Trash", t);
                });
                ui.add_space(12.);
                if theme::row_action(ui, "All activity", true).clicked() {
                    self.page = Page::History;
                }
            });
            ui.add_space(28.);
            if self.history.is_empty() {
                theme::muted(ui, "Your cleanup activity will appear here.", t);
            } else {
                ui.vertical(|ui| {
                    for record in self.history.iter().take(3) {
                        history_row(ui, record, t);
                    }
                });
            }
        });
    }
    fn clean_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                self.clean_settings_configure_button(ui, t, ctx);
            });
        });
        ui.add_space(8.);
        theme::tabs(ui, |ui| {
            ui.add_enabled_ui(!self.busy(), |ui| {
                if theme::tab_value(ui, &mut self.clean_browser, false, "Junk").clicked() {
                    self.clean_bin = false;
                }
                theme::tab_value(ui, &mut self.clean_browser, true, "Browser");
            });
        });
        ui.add_space(16.);
        if self.clean_browser {
            self.privacy_page(ui, t, ctx);
            return;
        }
        if self.clean_bin {
            if theme::row_action(ui, "All junk categories", !self.busy()).clicked() {
                self.clean_bin = false;
            }
            ui.add_space(12.);
            self.recycle_bin_page(ui, t, ctx);
            return;
        }
        if let Some(report) = &self.custom_analysis {
            let busy = self.busy();
            if self.custom_selection_blocked() {
                for note in report.capabilities().iter().filter(|note| note.blocking()) {
                    theme::muted(ui, note.detail(), t);
                }
            }
            if report.partial() && !report.cancelled() {
                theme::muted(
                    ui,
                    "Some locations could not be scanned. Review the omissions before cleaning.",
                    t,
                );
                theme::checkbox(
                    ui,
                    &mut self.custom_partial_acknowledged,
                    "I reviewed the partial scan and want to clean only the listed files",
                    !busy,
                );
            }
            if report.cancelled() {
                theme::muted(ui, "Scan stopped. Scan again before cleaning.", t);
            }
            egui::CollapsingHeader::new("Scan details").show(ui, |ui| {
                for rule in report.rules().iter().filter(|rule| rule.selected()) {
                    theme::muted(
                        ui,
                        format!(
                            "{} · {} eligible · {} excluded · {} skipped{}",
                            rule.name(),
                            rule.eligible(),
                            rule.excluded(),
                            rule.skipped(),
                            if rule.truncated() { " · partial" } else { "" }
                        ),
                        t,
                    );
                    if let Some(reason) = rule.reason() {
                        theme::muted(ui, reason, t);
                    }
                }
                for entry in report.skipped_entries() {
                    theme::muted(
                        ui,
                        format!(
                            "{} · {}",
                            entry
                                .path()
                                .map(|path| path.display().to_string())
                                .unwrap_or_else(|| "Unavailable location".into()),
                            entry.reason().description()
                        ),
                        t,
                    );
                }
                if report.omitted_skip_details() > 0 {
                    theme::muted(
                        ui,
                        format!(
                            "{} additional omissions are counted; individual details are capped.",
                            report.omitted_skip_details()
                        ),
                        t,
                    );
                }
                for note in report.capabilities() {
                    theme::muted(ui, note.detail(), t);
                }
            });
            ui.add_space(12.);
        }
        let selection_width = if ui.available_width() > 800. {
            260.
        } else {
            210.
        };
        egui::Panel::left("clean-category-selection")
            .resizable(false)
            .exact_size(selection_width)
            .frame(
                egui::Frame::new()
                    .fill(t.sidebar)
                    .inner_margin(14)
                    .corner_radius(12),
            )
            .show(ui, |ui| {
                theme::tabs(ui, |ui| {
                    let os = if cfg!(windows) { "Windows" } else { "macOS" };
                    for group in [os, "Applications"] {
                        if theme::tab(ui, self.group == group, group).clicked() {
                            self.group = group.into();
                        }
                    }
                });
                ui.add_space(12.);
                theme::muted(
                    ui,
                    format!("Files at least {} days old", self.prefs.minimum_age_days),
                    t,
                );
                ui.add_space(12.);
                egui::Frame::new().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new("What to clean").family(theme::semibold()));
                    ui.add_space(8.);
                    let categories = self.categories.clone();
                    let busy = self.busy();
                    let mut changed = false;
                    for category in categories.iter().filter(|c| c.group == self.group) {
                        let mut checked = self.prefs.selected_categories.contains(&category.id);
                        let text_width =
                            (ui.available_width() - ui.spacing().icon_width - 8.).max(80.);
                        let title_height = ui
                            .painter()
                            .layout(
                                category.name.clone(),
                                ui.style().text_styles[&egui::TextStyle::Body].clone(),
                                t.foreground,
                                text_width,
                            )
                            .size()
                            .y;
                        let detail_height = ui
                            .painter()
                            .layout(
                                category.description.clone(),
                                egui::FontId::proportional(12.),
                                t.muted,
                                text_width,
                            )
                            .size()
                            .y;
                        let row_height = title_height + 4. + detail_height;
                        let mut row_changed = false;
                        ui.allocate_ui_with_layout(
                            Vec2::new(ui.available_width(), row_height),
                            Layout::left_to_right(Align::Center),
                            |ui| {
                                ui.set_min_height(row_height);
                                let check = theme::checkbox_widget(
                                    ui,
                                    egui::Checkbox::without_text(&mut checked),
                                    !busy,
                                )
                                .on_hover_text(&category.name);
                                check.widget_info(|| {
                                    egui::WidgetInfo::selected(
                                        egui::WidgetType::Checkbox,
                                        !busy,
                                        checked,
                                        &category.name,
                                    )
                                });
                                row_changed |= check.changed();
                                ui.vertical(|ui| {
                                    ui.set_width(text_width);
                                    ui.spacing_mut().item_spacing.y = 4.;
                                    let title = ui.add_enabled(
                                        !busy,
                                        egui::Label::new(&category.name)
                                            .sense(egui::Sense::click()),
                                    );
                                    let detail = ui.add_enabled(
                                        !busy,
                                        egui::Label::new(
                                            RichText::new(&category.description)
                                                .size(12.)
                                                .color(t.muted),
                                        )
                                        .sense(egui::Sense::click()),
                                    );
                                    if title.clicked() || detail.clicked() {
                                        checked = !checked;
                                        row_changed = true;
                                    }
                                });
                            },
                        );
                        if row_changed {
                            changed = true;
                            if checked {
                                self.prefs.selected_categories.push(category.id.clone());
                            } else {
                                self.prefs
                                    .selected_categories
                                    .retain(|id| id != &category.id);
                            }
                        }
                        ui.add_space(8.);
                    }
                    if changed {
                        self.invalidate();
                    }
                    if cfg!(windows) && self.group == "Windows" {
                        ui.add_space(12.);
                        ui.separator();
                        ui.add_space(12.);
                        ui.label(RichText::new("Recycle Bin").family(theme::semibold()));
                        theme::muted(ui, "Review items already in the Recycle Bin.", t);
                        if theme::row_action(ui, "Review", !busy).clicked() {
                            self.clean_bin = true;
                            self.recycle_bin_entered(ctx);
                        }
                    }
                });
            });
        theme::card(t).show(ui,|ui|{ui.set_width(ui.available_width());ui.label(RichText::new("Analysis results").family(theme::semibold()));ui.add_space(12.);
            if let Some(analysis)=self.analysis.clone(){
                ui.horizontal(|ui|{ui.label(RichText::new(size(analysis.bytes())).size(25.).family(theme::semibold()));theme::muted(ui,format!("{} files · {:.1}s elapsed{}",analysis.count(),analysis.elapsed_ms as f64/1000.,if analysis.cancelled{" · cancelled"}else{""}),t);});ui.add_space(10.);
                let search_width=ui.available_width();
                theme::input(ui,&mut self.search,search_width,"Search file paths or categories…",true);ui.add_space(10.);
                let query=self.search.to_lowercase();let busy=self.busy();
                for category in &analysis.categories{
                    if !query.is_empty()&&!category.name.to_lowercase().contains(&query)&&!category.files.iter().any(|f|f.path.to_string_lossy().to_lowercase().contains(&query)){continue;}
                    let status=if category.truncated{"Partial scan"}else if !category.available{"Not found"}else if category.files.is_empty(){"No eligible files"}else{""};
                    ui.horizontal(|ui|{let mut all=!category.files.is_empty()&&category.files.iter().all(|f|self.selected.contains(&f.id));if theme::checkbox_widget(ui,egui::Checkbox::without_text(&mut all),!busy&&!analysis.cancelled&&!category.files.is_empty()).changed(){for f in &category.files{if all{self.selected.insert(f.id);}else{self.selected.remove(&f.id);}}}
                        ui.label(&category.name);ui.with_layout(Layout::right_to_left(Align::Center),|ui|{ui.label(size(category.bytes()));theme::muted(ui,format!("{} files   {status}",category.files.len()),t);});});
                    if category.skipped>0{theme::muted(ui,format!("{} inaccessible or linked locations skipped",category.skipped),t);}
                    egui::CollapsingHeader::new(format!("View files — {}",category.name)).id_salt(&category.id).show(ui,|ui|{
                        egui::ScrollArea::vertical().max_height(220.).id_salt(format!("files-{}",category.id)).show(ui,|ui|{
                            for f in category.files.iter().filter(|f|query.is_empty()||category.name.to_lowercase().contains(&query)||f.path.to_string_lossy().to_lowercase().contains(&query)).take(200){ui.horizontal(|ui|{let mut selected=self.selected.contains(&f.id);if theme::checkbox_widget(ui,egui::Checkbox::without_text(&mut selected),!busy&&!analysis.cancelled).changed(){if selected{self.selected.insert(f.id);}else{self.selected.remove(&f.id);}}ui.add(egui::Label::new(RichText::new(f.path.to_string_lossy()).size(11.)).truncate()).on_hover_text(f.path.to_string_lossy());ui.label(RichText::new(size(f.size)).size(11.));});}
                            if category.files.len()>200{theme::muted(ui,"Showing up to 200 matching files. Export for the full list. Category selection includes all files.",t);}
                        });});ui.separator();
                }
            }else{ui.add_space(30.);ui.vertical_centered(|ui|{ui.label(RichText::new("Analyze first. Decide what to clean.").size(17.));ui.add_space(8.);theme::muted(ui,"Analysis only reads files; it does not change them.",t);});ui.add_space(35.);}
        });
    }
    fn clean_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        ui.horizontal_wrapped(|ui| {
            let busy = self.busy();
            if theme::secondary(ui, "Export report", !busy && self.analysis.is_some()) {
                self.export();
            }
            if theme::secondary(
                ui,
                "Scan now",
                !busy
                    && (!self.prefs.selected_categories.is_empty() || self.custom_clean_enabled()),
            ) {
                self.begin_scan(ctx);
            }
            let enabled = !busy
                && !self.selected.is_empty()
                && self.history_readable
                && !self.custom_selection_blocked()
                && self.analysis.as_ref().is_some_and(|a| !a.cancelled)
                && self
                    .custom_analysis
                    .as_ref()
                    .is_none_or(|report| !report.partial() || self.custom_partial_acknowledged);
            if theme::primary(ui, "Clean selected", t, enabled) {
                self.confirm = true;
            }
            theme::muted(ui, format!("{} files selected", self.selected.len()), t);
        });
    }
    fn custom_selection_blocked(&self) -> bool {
        let Some(report) = &self.custom_analysis else {
            return false;
        };
        report.capabilities().iter().any(|note| {
            note.blocking()
                && match note.rule_id() {
                    None => true,
                    Some(rule_id) => {
                        self.selected
                            .iter()
                            .filter_map(|id| report.file(*id))
                            .any(|file| {
                                file.eligibility().iter().any(|rule| {
                                    rule.eligible() && rule.selected() && rule.rule_id() == rule_id
                                })
                            })
                    }
                }
        })
    }
    fn disk_page(&mut self, ui: &mut egui::Ui, t: Tokens, _ctx: &egui::Context) {
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            if let Some(report) = &self.disk {
                ui.label(RichText::new("Largest files").family(theme::semibold()));
                theme::muted(ui, report.root.to_string_lossy(), t);
                ui.add_space(10.);
                ui.label(format!(
                    "{} in {} files · {} skipped{}",
                    size(report.bytes),
                    report.count,
                    report.skipped,
                    if report.partial {
                        " · partial scan"
                    } else {
                        ""
                    }
                ));
                ui.separator();
                for f in &report.files {
                    ui.horizontal(|ui| {
                        ui.add(egui::Label::new(f.path.to_string_lossy()).truncate())
                            .on_hover_text(f.path.to_string_lossy());
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(size(f.size));
                        });
                    });
                }
            } else {
                ui.add_space(50.);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("See where your space goes").size(18.));
                    ui.add_space(8.);
                    theme::muted(ui, "Choose a folder for a read-only size analysis.", t);
                });
                ui.add_space(50.);
            }
        });
    }
    fn history_page(&self, ui: &mut egui::Ui, t: Tokens) {
        theme::card(t).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Cleanup activity").family(theme::semibold()));
            ui.add_space(12.);
            if self.history.is_empty() {
                theme::muted(ui, "No cleanup records yet.", t);
            }
            for record in &self.history {
                history_row(ui, record, t);
            }
        });
    }
    fn settings_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        theme::card(t).show(ui,|ui|{ui.set_width(ui.available_width());ui.label(RichText::new("Cleaning preferences").family(theme::semibold()));ui.add_space(12.);theme::muted(ui,"Minimum file age",t);
            let mut changed=false;
            let age_labels:Vec<_>=[1,7,14,30,90].iter().map(|days|format!("{days} days or older")).collect();
            let age_choices:Vec<_>=age_labels.iter().map(String::as_str).collect();
            let selected_age=format!("{} days or older",self.prefs.minimum_age_days);
            ui.add_enabled_ui(self.settings_readable&&!self.busy(),|ui|{
                theme::selector(ui,"age",&selected_age,&age_choices,|ui|{for days in [1,7,14,30,90]{changed|=ui.selectable_value(&mut self.prefs.minimum_age_days,days,format!("{days} days or older")).changed();}});
            });
            if changed{self.invalidate();}ui.add_space(20.);ui.separator();ui.add_space(20.);ui.label(RichText::new("Appearance").family(theme::semibold()));ui.add_space(8.);
            if theme::checkbox(ui,&mut self.prefs.dark,"Dark mode",true).changed(){theme::apply(ctx,self.prefs.dark);self.persist();}
            ui.add_space(20.);ui.separator();ui.add_space(20.);ui.label(RichText::new("DCleaner 0.1.0 · Native Rust").family(theme::semibold()));theme::muted(ui,"Navy workspace, blue actions and Inter typography.",t);ui.add_space(8.);theme::muted(ui,"This foundation supports temp/cache cleanup, folder analysis and durable history. Full CCleaner parity is tracked in the project plan.",t);
            ui.add_space(8.);theme::muted(ui,format!("Data directory: {}",self.data_dir.display()),t);
        });
    }
}
impl App {
    #[cfg(debug_assertions)]
    pub(crate) fn qa_busy(&self) -> bool {
        self.busy() || self.app_icons.is_loading()
    }
    pub(crate) fn paint(&mut self, root: &mut egui::Ui) {
        self.poll();
        let ctx = root.ctx().clone();
        #[cfg(debug_assertions)]
        theme::begin_geometry_frame(&ctx);
        self.startup_refresh_external_state(&ctx);
        let t = theme::tokens(self.prefs.dark);
        let busy = self.busy();
        if busy {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        if ctx.input(|i| i.viewport().close_requested()) {
            self.cancel.store(true, Ordering::Relaxed);
        }
        let narrow = root.available_width() < 1000.;
        egui::Panel::left("icon-rail")
            .resizable(false)
            .exact_size(64.)
            .frame(
                egui::Frame::new()
                    .fill(t.rail)
                    .inner_margin(egui::Margin::symmetric(
                        10,
                        if cfg!(windows) { 4 } else { 20 },
                    )),
            )
            .show(root, |ui| {
                ui.vertical_centered(|ui| {
                    let (rect, _) = ui.allocate_exact_size(
                        Vec2::splat(if cfg!(windows) { 28. } else { 36. }),
                        egui::Sense::hover(),
                    );
                    if let Some(logo) = self.logo_texture.as_ref() {
                        ui.painter().image(
                            logo.id(),
                            rect,
                            egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1., 1.)),
                            Color32::WHITE,
                        );
                    }
                });
                ui.add_space(if cfg!(windows) { 26. } else { 28. });
                let rail_pages: &[Page] = if narrow {
                    &PAGES
                } else {
                    &[Page::Overview, Page::Settings, Page::Help]
                };
                egui::ScrollArea::vertical()
                    .id_salt("rail-destinations")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for &page in rail_pages {
                            if theme::navigation(
                                ui,
                                if !narrow && page == Page::Overview {
                                    "Maintenance"
                                } else {
                                    page.name()
                                },
                                page.icon(),
                                self.page == page
                                    || (!narrow
                                        && page == Page::Overview
                                        && !matches!(self.page, Page::Settings | Page::Help)),
                                !busy,
                                true,
                                t,
                            ) {
                                self.page = page;
                                self.search.clear();
                            }
                            ui.add_space(5.);
                        }
                    });
            });
        if !narrow {
            egui::Panel::left("section-navigation")
                .resizable(false)
                .exact_size(196.)
                .frame(
                    egui::Frame::new()
                        .fill(t.sidebar)
                        .inner_margin(egui::Margin {
                            left: 12,
                            right: 16,
                            top: if cfg!(windows) { 42 } else { 28 },
                            bottom: 28,
                        }),
                )
                .show(root, |ui| {
                    ui.spacing_mut().item_spacing.y = 4.;
                    egui::Frame::NONE
                        .inner_margin(egui::Margin {
                            left: 8,
                            ..Default::default()
                        })
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new("DCLEANER")
                                    .family(theme::semibold())
                                    .size(11.)
                                    .color(t.muted),
                            );
                        });
                    ui.add_space(6.);
                    for page in PAGES {
                        if matches!(page, Page::Settings | Page::Help) {
                            continue;
                        }
                        if theme::section_navigation(ui, page.name(), self.page == page, !busy, t) {
                            self.page = page;
                            self.search.clear();
                        }
                        ui.add_space(2.);
                    }
                    ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                        theme::muted(ui, "DCleaner · 0.1.0", t);
                    });
                });
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(t.canvas))
            .show(root, |ui| {
                theme::canvas_background(ui, self.prefs.dark);
                egui::Panel::bottom("page-actions")
                    .resizable(false)
                    .exact_size(74.)
                    .frame(
                        egui::Frame::new()
                            .fill(t.sidebar)
                            .stroke(egui::Stroke::new(1., t.border))
                            .inner_margin(egui::Margin::symmetric(28, 18)),
                    )
                    .show(ui, |ui| {
                        ui.spacing_mut().interact_size.y = theme::CONTROL_HEIGHT;
                        match self.page {
                            Page::Clean if self.clean_browser => self.privacy_footer(ui, t, &ctx),
                            Page::Clean if self.clean_bin => self.recycle_bin_footer(ui, t, &ctx),
                            Page::Clean => self.clean_footer(ui, t, &ctx),
                            Page::Duplicates => self.duplicates_footer(ui, t, &ctx),
                            Page::Cloud => self.cloud_footer(ui, t, &ctx),
                            Page::Programs => self.programs_footer(ui, t, &ctx),
                            Page::Optimizer => self.optimizer_footer(ui, t, &ctx),
                            Page::Startup => self.startup_footer(ui, t, &ctx),
                            Page::Software => self.software_footer(ui, t, &ctx),
                            Page::Drivers => self.drivers_footer(ui, t, &ctx),
                            Page::Overview => self.health_footer(ui, t, &ctx),
                            Page::Disk => {
                                if theme::primary(ui, "Choose folder", t, !busy) {
                                    self.begin_disk(&ctx);
                                }
                            }
                            _ => {
                                theme::muted(ui, "On this device", t);
                            }
                        }
                    });
                egui::Frame::new()
                    .inner_margin(egui::Margin {
                        left: 28,
                        right: 28,
                        top: if cfg!(windows) { 60 } else { 28 },
                        bottom: 28,
                    })
                    .show(ui, |ui| {
                        ui.heading(if self.page == Page::Overview && !self.health_started() {
                            "Your scan results"
                        } else {
                            self.page.name()
                        });
                        theme::muted(ui, self.page.description(), t);
                        ui.add_space(26.);
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .id_salt(self.page.name())
                            .show(ui, |ui| {
                                if let Some(error) = self.error.clone() {
                                    egui::Frame::new()
                                        .fill(Color32::from_rgba_unmultiplied(237, 85, 101, 20))
                                        .inner_margin(12)
                                        .corner_radius(10)
                                        .show(ui, |ui| {
                                            ui.horizontal_wrapped(|ui| {
                                                ui.label(
                                                    RichText::new(error)
                                                        .color(Color32::from_rgb(237, 115, 127)),
                                                );
                                                if ui.small_button("Dismiss").clicked() {
                                                    self.error = None;
                                                }
                                            });
                                        });
                                    ui.add_space(12.);
                                }
                                if let Some(notice) = self.notice.clone() {
                                    egui::Frame::new()
                                        .fill(t.tint)
                                        .inner_margin(12)
                                        .corner_radius(10)
                                        .show(ui, |ui| {
                                            ui.horizontal_wrapped(|ui| {
                                                ui.label(notice);
                                                if ui.small_button("Dismiss").clicked() {
                                                    self.notice = None;
                                                }
                                            });
                                        });
                                    ui.add_space(12.);
                                }
                                if busy
                                    && !matches!(
                                        self.page,
                                        Page::Overview | Page::Optimizer | Page::Cloud
                                    )
                                {
                                    theme::card(t).show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.spinner();
                                            ui.label(&self.progress);
                                            let can_stop = matches!(
                                                self.page,
                                                Page::Overview | Page::Disk | Page::Duplicates
                                            ) || (self.page == Page::Clean
                                                && !self.clean_browser
                                                && !self.clean_bin);
                                            if can_stop && ui.button("Stop").clicked() {
                                                self.cancel.store(true, Ordering::Relaxed);
                                            }
                                        });
                                    });
                                    ui.add_space(20.);
                                }
                                match self.page {
                                    Page::Overview => self.health_page(ui, t, &ctx),
                                    Page::Clean => self.clean_page(ui, t, &ctx),
                                    Page::Disk => self.disk_page(ui, t, &ctx),
                                    Page::Duplicates => self.duplicates_page(ui, t, &ctx),
                                    Page::Cloud => self.cloud_page(ui, t, &ctx),
                                    Page::Programs => self.programs_page(ui, t, &ctx),
                                    Page::Optimizer => self.optimizer_page(ui, t, &ctx),
                                    Page::Startup => self.startup_page(ui, t, &ctx),
                                    Page::Software => self.software_page(ui, t, &ctx),
                                    Page::Drivers => self.drivers_page(ui, t, &ctx),
                                    Page::History => self.history_page(ui, t),
                                    Page::Settings => self.settings_page(ui, t, &ctx),
                                    Page::Help => self.help_page(ui, t, &ctx),
                                }
                                ui.add_space(24.);
                            });
                    });
            });
        #[cfg(windows)]
        theme::window_chrome(root, t);
        self.duplicates_dialog(&ctx);
        self.programs_dialog(&ctx);
        self.optimizer_dialog(&ctx);
        self.startup_dialog(&ctx);
        self.software_dialog(&ctx);
        self.drivers_dialog(&ctx);
        self.health_dialog(&ctx);
        self.privacy_dialog(&ctx);
        self.recycle_bin_dialog(&ctx);
        self.clean_settings_dialog(&ctx);
        self.help_dialog(&ctx);
        self.cloud_dialog(&ctx);
        #[cfg(debug_assertions)]
        {
            let capture_busy = self.busy() || self.app_icons.is_loading();
            if let Some(capture) = self.visual_capture.as_mut() {
                capture.tick(&ctx, capture_busy);
            }
        }
        if self.confirm && !self.busy() && ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.confirm = false;
        }
        if self.confirm {
            egui::Modal::new(egui::Id::new("confirm-cleanup")).show(&ctx,|ui|{ui.set_width(400.);ui.heading("Ready to make some room?");ui.add_space(12.);ui.label(format!("Move {} selected files to {}? Changed or unavailable files are skipped. You can restore moved files from the system {}.",self.selected.len(),platform::trash_label(),platform::trash_label()));ui.add_space(20.);ui.horizontal(|ui|{if theme::secondary(ui,"Keep files",true){self.confirm=false;}if theme::primary(ui,"Move selected files",t,true){self.begin_clean(&ctx);}});});
        }
    }
}
impl eframe::App for App {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.paint(root);
    }
}
fn finding_row(
    ui: &mut egui::Ui,
    t: Tokens,
    icon: theme::Icon,
    title: &str,
    description: &str,
    status: &str,
    enabled: bool,
) -> bool {
    theme::card(t)
        .inner_margin(egui::Margin::symmetric(22, 16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let title_width = (ui.available_width() - 24. - 16. - 130. - 72. - 24.).max(150.);
            ui.allocate_ui_with_layout(
                Vec2::new(ui.available_width(), 34.),
                Layout::left_to_right(Align::Center),
                |ui| {
                    ui.set_min_height(34.);
                    ui.spacing_mut().item_spacing.x = 12.;
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(24.), egui::Sense::hover());
                    theme::paint_icon(ui.painter(), rect, icon, t.muted);
                    ui.allocate_ui_with_layout(
                        Vec2::new(title_width, 34.),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            ui.set_min_width(title_width);
                            ui.set_max_width(title_width);
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 3.;
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(title).family(theme::semibold()).size(14.),
                                    )
                                    .truncate(),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(description).color(t.muted).size(12.),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(description);
                            });
                        },
                    );
                    theme::table_cell(
                        ui,
                        RichText::new(status)
                            .color(if status == "Not scanned" {
                                t.muted
                            } else {
                                t.attention
                            })
                            .family(theme::semibold())
                            .size(12.),
                        130.,
                        28.,
                    );
                    theme::finding_action(ui, "Review", enabled).clicked()
                },
            )
            .inner
        })
        .inner
}
fn history_row(ui: &mut egui::Ui, r: &CleanupResult, t: Tokens) {
    ui.separator();
    ui.add_space(8.);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(if r.interrupted {
                "Interrupted cleanup"
            } else if r.cancelled {
                "Cleanup stopped"
            } else {
                "Cleanup completed"
            })
            .family(theme::semibold()),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(size(r.bytes));
        });
    });
    theme::muted(
        ui,
        format!(
            "{} · {} confirmed files · {} skipped · {} uncertain",
            date(&r.date),
            r.files,
            r.failed.len(),
            r.uncertain.len()
        ),
        t,
    );
    if !r.failed.is_empty() || !r.uncertain.is_empty() {
        egui::CollapsingHeader::new("Details").id_salt(r.id).show(ui,|ui|{for f in &r.failed{theme::muted(ui,format!("{} — {}",f.path.display(),f.reason.as_deref().unwrap_or("Skipped")),t);}for p in &r.uncertain{ui.label(format!("{} — outcome uncertain; inspect the system Trash before taking another action",p.display()));}});
    }
    ui.add_space(8.);
}
fn date(value: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|d| d.format("%d %b %Y, %H:%M").to_string())
        .unwrap_or(value.into())
}
pub fn size(bytes: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut i = 0;
    while value >= 1024. && i < 4 {
        value /= 1024.;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", units[i])
    }
}
