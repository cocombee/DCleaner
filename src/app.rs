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
#[cfg(debug_assertions)]
#[path = "qa_core.rs"]
mod qa_core;
#[path = "view_clean_settings.rs"]
mod view_clean_settings;
#[path = "view_cloud.rs"]
mod view_cloud;
#[path = "view_disk.rs"]
mod view_disk;
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
#[path = "view_settings.rs"]
mod view_settings;
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
fn navigation_pages(prefs: &Preferences) -> Vec<Page> {
    let mut pages = PAGES.to_vec();
    if prefs.menu_pin_landing_page {
        let landing = match prefs.landing_page {
            dcleaner::domain::LandingPage::HealthCheck => Page::Overview,
            dcleaner::domain::LandingPage::CustomClean => Page::Clean,
        };
        if let Some(index) = pages.iter().position(|page| *page == landing) {
            pages.remove(index);
            pages.insert(0, landing);
        }
    }
    pages
}

impl Page {
    fn icon(self) -> theme::Icon {
        match self {
            Self::Overview => theme::Icon::Heart,
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
    Settings(view_settings::SettingsEvent),
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
    illustrations: crate::illustrations::Illustrations,
    qa_fixture_mode: bool,
    logo_texture: Option<egui::TextureHandle>,
    cloud_ui: view_cloud::CloudUi,
    clean_settings_ui: view_clean_settings::CleanSettingsUi,
    settings_ui: view_settings::SettingsUi,
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
    clean_registry: bool,
    sidebar_collapsed: Option<bool>,
    clean_bin: bool,
    page: Page,
    prefs: Preferences,
    categories: Vec<Category>,
    analysis: Option<Analysis>,
    selected: HashSet<Uuid>,
    history: Vec<CleanupResult>,
    disk: Option<DiskReport>,
    disk_ui: view_disk::DiskUi,
    data_dir: PathBuf,
    worker: Option<Receiver<Event>>,
    cancel: Arc<AtomicBool>,
    progress: String,
    error: Option<String>,
    notice: Option<String>,
    search: String,
    confirm: bool,
    settings_readable: bool,
    history_readable: bool,
}
impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::new_with_context(&cc.egui_ctx)
    }
    pub(crate) fn new_with_context(context: &egui::Context) -> Self {
        Self::construct(context, false)
    }
    fn construct(context: &egui::Context, fixture: bool) -> Self {
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
            "Inter 550".into(),
            Arc::new(egui::FontData::from_static(include_bytes!(
                "../assets/fonts/Inter-550.ttf"
            ))),
        );
        fonts
            .families
            .insert(theme::semibold(), vec!["Inter 550".into(), "Inter".into()]);
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
        let (data_dir, mut error) = if fixture {
            (PathBuf::from("__dcleaner_in_memory_fixture__"), None)
        } else {
            match platform::data_directory() {
                Ok(p) => (p, None),
                Err(e) => (PathBuf::new(), Some(e)),
            }
        };
        let (prefs, settings_readable) = if fixture {
            (Preferences::default(), true)
        } else {
            match store::load_preferences(&data_dir) {
                Ok(p) => (p, true),
                Err(e) => {
                    error = Some(e);
                    (Preferences::default(), false)
                }
            }
        };
        let (history, history_readable) = if fixture {
            (Vec::new(), true)
        } else {
            match store::history(&data_dir) {
                Ok(h) => (h, true),
                Err(e) => {
                    error = Some(e);
                    (vec![], false)
                }
            }
        };
        let clean_settings_result = if fixture {
            Ok(Default::default())
        } else {
            clean_settings::load_settings(&data_dir).map_err(|failure| failure.to_string())
        };
        if let Err(failure) = &clean_settings_result {
            error = Some(failure.clone());
        }
        let clean_settings_ui =
            view_clean_settings::CleanSettingsUi::from_saved(clean_settings_result);
        #[cfg(debug_assertions)]
        let visual_capture = if fixture {
            None
        } else {
            crate::visual_qa::Capture::from_environment()
        };
        #[cfg(debug_assertions)]
        let qa_mode =
            visual_capture.is_some() || std::env::args().any(|arg| arg == "--render-offscreen-qa");
        #[cfg(debug_assertions)]
        let prefs = {
            let mut prefs = prefs;
            if qa_mode {
                prefs.dark = std::env::var("DCLEANER_QA_THEME").as_deref() != Ok("light");
                prefs.appearance = Some(if prefs.dark {
                    dcleaner::domain::AppearanceMode::Dark
                } else {
                    dcleaner::domain::AppearanceMode::Light
                });
            }
            prefs
        };
        let mut prefs = prefs;
        prefs.dark = prefs.effective_dark(
            context
                .system_theme()
                .map(|theme| theme == egui::Theme::Dark),
        );
        theme::apply(context, prefs.dark);
        let initial_page = match prefs.landing_page {
            dcleaner::domain::LandingPage::HealthCheck => Page::Overview,
            dcleaner::domain::LandingPage::CustomClean => Page::Clean,
        };
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
        #[cfg(debug_assertions)]
        let duplicate_ui = if fixture {
            view_duplicates::DuplicateUi::inert_fixture()
        } else {
            Default::default()
        };
        #[cfg(not(debug_assertions))]
        let duplicate_ui = Default::default();
        Self {
            illustrations: Default::default(),
            qa_fixture_mode: fixture,
            logo_texture,
            clean_settings_ui,
            settings_ui: Default::default(),
            custom_analysis: None,
            custom_partial_acknowledged: false,
            health_ui: Default::default(),
            help_ui: Default::default(),
            cloud_ui: Default::default(),
            #[cfg(debug_assertions)]
            visual_capture,
            software_ui: Default::default(),
            duplicate_ui,
            program_ui: Default::default(),
            optimizer_ui: Default::default(),
            startup_ui: Default::default(),
            drivers_ui: Default::default(),
            app_icons: Default::default(),
            privacy_ui: Default::default(),
            recycle_bin_ui: Default::default(),
            clean_browser,
            clean_registry: false,
            sidebar_collapsed: None,
            clean_bin,
            page: initial_page,
            prefs,
            categories: if fixture {
                Vec::new()
            } else {
                platform::categories()
            },
            analysis: None,
            selected: HashSet::new(),
            history,
            disk: None,
            disk_ui: Default::default(),
            data_dir,
            worker: None,
            cancel: Arc::new(AtomicBool::new(false)),
            progress: String::new(),
            error,
            notice: None,
            search: String::new(),
            confirm: false,
            settings_readable,
            history_readable,
        }
    }
    fn busy(&self) -> bool {
        self.worker.is_some()
    }
    fn qa_fixture_mode(&self) -> bool {
        self.qa_fixture_mode
    }
    #[cfg(debug_assertions)]
    pub(crate) fn new_fixture_with_context(
        context: &egui::Context,
        case: &str,
    ) -> Result<Self, String> {
        if !matches!(
            case,
            "cloud-intro"
                | "cloud-partial"
                | "cloud-selected"
                | "cloud-providers"
                | "disk-results"
                | "disk-partial"
                | "disk-details"
                | "disk-empty"
                | "startup-empty"
                | "startup-populated"
                | "startup-details"
                | "startup-error"
                | "startup-help"
                | "programs-empty"
                | "programs-populated"
                | "programs-details"
                | "programs-error"
                | "programs-intro"
                | "software-empty"
                | "software-populated"
                | "software-details"
                | "software-error"
                | "software-intro"
                | "software-batch-review"
                | "software-update-review"
                | "drivers-problem-categories"
                | "drivers-problem-categories-empty"
                | "drivers-restore-prompt"
                | "drivers-no-recent-updates"
                | "drivers-recent-updates"
                | "drivers-offered"
                | "optimizer-empty"
                | "optimizer-populated"
                | "optimizer-details"
                | "optimizer-error"
                | "optimizer-intro"
                | "drivers-empty"
                | "drivers-populated"
                | "drivers-details"
                | "drivers-error"
                | "drivers-intro"
                | "duplicates-empty"
                | "duplicates-populated"
                | "duplicates-selected"
                | "duplicates-details"
                | "duplicates-error"
                | "duplicates-intro"
                | "clean-empty"
                | "clean-populated"
                | "clean-selected"
                | "clean-details"
                | "clean-error"
                | "history-empty"
                | "history-populated"
                | "settings"
                | "settings-general"
                | "settings-scheduling"
                | "settings-updates"
                | "settings-privacy"
                | "settings-menu-layout"
                | "settings-my-subscription"
                | "settings-about"
                | "settings-updates-checking"
                | "settings-updates-no-release"
                | "settings-updates-latest-newer"
                | "settings-updates-latest-current"
                | "settings-updates-latest-unparseable"
                | "settings-updates-error"
                | "help"
                | "help-diagnostics"
                | "clean-settings-inclusions"
                | "clean-settings-cookies"
                | "clean-settings-popular-sites"
                | "clean-settings-exclusions"
                | "clean-settings-rules"
                | "clean-settings-deletion"
                | "health-welcome"
                | "health-activity"
                | "health-activity-unavailable"
                | "health-intro"
                | "health-privacy"
                | "health-privacy-expanded"
                | "health-privacy-review"
                | "health-finding-details"
                | "health-cookie-settings"
                | "health-scanning"
                | "health-cleaning"
                | "health-browser-review"
                | "health-space-review"
                | "health-space"
                | "health-issues"
                | "health-summary"
                | "health-error"
                | "privacy-empty"
                | "privacy-populated"
                | "privacy-selected"
                | "privacy-details"
                | "privacy-error"
                | "recyclebin-empty"
                | "recyclebin-populated"
                | "recyclebin-selected"
                | "recyclebin-details"
                | "recyclebin-error"
        ) {
            return Err(format!("Unsupported isolated visual fixture: {case}"));
        }
        let mut app = Self::construct(context, true);
        if case.starts_with("settings-") {
            app.seed_core_qa("settings")?;
            app.prefs.seen_features = vec!["health".into(), "software".into()];
            if case.starts_with("settings-updates-") {
                view_settings::seed_qa_tab(context, "updates")?;
                view_settings::seed_qa_update_case(&mut app.settings_ui, case)?;
            } else {
                view_settings::seed_qa_tab(context, case)?;
            }
        } else if case.starts_with("health-") {
            app.page = Page::Overview;
            app.seed_health_qa(case)?;
        } else if case.starts_with("privacy-") {
            app.page = Page::Clean;
            app.clean_browser = true;
            app.seed_privacy_qa(case)?;
        } else if case.starts_with("recyclebin-") {
            app.page = Page::Clean;
            app.clean_bin = true;
            app.seed_recycle_bin_qa(case)?;
        } else if case.starts_with("clean-settings-") {
            app.seed_clean_settings_qa(case)?;
        } else if case.starts_with("clean-") || case.starts_with("history-") || case == "settings" {
            app.seed_core_qa(case)?;
        } else if case == "help" || case == "help-diagnostics" {
            app.seed_help_qa(case)?;
        } else if case.starts_with("cloud-") {
            app.page = Page::Cloud;
            app.seed_cloud_qa(case);
        } else if case.starts_with("startup-") {
            app.page = Page::Startup;
            app.seed_startup_qa(case)?;
        } else if case.starts_with("programs-") {
            app.page = Page::Programs;
            app.seed_programs_qa(case)?;
        } else if case.starts_with("software-") {
            app.page = Page::Software;
            app.seed_software_qa(case)?;
        } else if case.starts_with("optimizer-") {
            app.page = Page::Optimizer;
            app.seed_optimizer_qa(case)?;
        } else if case.starts_with("drivers-") {
            app.page = Page::Drivers;
            app.seed_drivers_qa(case)?;
        } else if case.starts_with("duplicates-") {
            app.page = Page::Duplicates;
            app.seed_duplicates_qa(case)?;
        } else {
            app.page = Page::Disk;
            app.seed_disk_qa(case);
        }
        Ok(app)
    }
    fn begin_scan(&mut self, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
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
        if self.busy() || self.qa_fixture_mode() || !self.history_readable {
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
        if self.busy() || self.qa_fixture_mode() {
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
                Event::Settings(event) => {
                    self.worker = None;
                    view_settings::handle_event(&mut self.settings_ui, event);
                }
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
    fn feature_seen(&self, kind: &str) -> bool {
        self.prefs.seen_features.iter().any(|seen| seen == kind)
    }
    fn mark_feature_seen(&mut self, kind: &str) {
        if !self.feature_seen(kind) {
            self.prefs.seen_features.push(kind.to_owned());
            self.persist();
        }
    }
    fn feature_intro_wide(&self, ctx: &egui::Context) -> bool {
        let window_width = ctx.content_rect().width();
        window_width - if window_width < 1000. { 64. } else { 260. } - 2. * theme::CONTENT >= 780.
    }
    fn feature_intro(
        &mut self,
        ui: &mut egui::Ui,
        t: Tokens,
        kind: &str,
        title: &str,
        subtitle: &str,
        bullets: &[(theme::Icon, &str, &str)],
    ) -> bool {
        let wide = self.feature_intro_wide(ui.ctx());
        let art_width = if wide { 330. } else { 136. };
        let mut start = false;
        if kind == "health" {
            ui.vertical_centered(|ui| {
                self.illustrations
                    .feature(ui, kind, if wide { art_width } else { 190. });
                ui.add_space(20.);
                ui.label(
                    RichText::new(title)
                        .family(theme::semibold())
                        .size(theme::FONT_DISPLAY)
                        .color(t.foreground),
                );
                ui.add_space(10.);
                ui.add(
                    egui::Label::new(
                        RichText::new(subtitle)
                            .size(theme::FONT_CAPTION)
                            .line_height(Some(theme::CAPTION_LINE_HEIGHT))
                            .color(t.muted),
                    )
                    .wrap()
                    .halign(Align::Center),
                );
                ui.add_space(24.);
                if wide {
                    start = theme::primary(ui, "Scan now", t, !self.busy());
                }
            });
            return start;
        }
        ui.horizontal_top(|ui| {
            let text_width = (ui.available_width() - art_width - 28.).max(180.);
            ui.allocate_ui_with_layout(
                Vec2::new(text_width, 0.),
                Layout::top_down(Align::Min),
                |ui| {
                    ui.label(
                        RichText::new(title)
                            .family(theme::semibold())
                            .size(theme::FONT_TITLE)
                            .color(t.foreground),
                    );
                    ui.add_space(4.);
                    theme::muted(ui, subtitle, t);
                    if wide {
                        ui.add_space(20.);
                        Self::feature_intro_points(ui, t, bullets);
                        ui.add_space(8.);
                        start = theme::primary(
                            ui,
                            if kind == "duplicates" {
                                "Start now"
                            } else {
                                "Scan now"
                            },
                            t,
                            !self.busy(),
                        );
                    }
                },
            );
            ui.add_space(20.);
            self.illustrations.feature(ui, kind, art_width);
        });
        if !wide {
            ui.add_space(16.);
            Self::feature_intro_points(ui, t, bullets);
        }
        start
    }
    fn feature_intro_points(ui: &mut egui::Ui, t: Tokens, bullets: &[(theme::Icon, &str, &str)]) {
        for (index, (icon, heading, description)) in bullets.iter().enumerate() {
            if index > 0 {
                ui.add_space(12.);
            }
            ui.horizontal_top(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(26.), egui::Sense::hover());
                theme::paint_icon(ui.painter(), rect, *icon, t.primary);
                ui.add_space(8.);
                ui.with_layout(Layout::top_down(Align::Min), |ui| {
                    ui.spacing_mut().item_spacing.y = 4.;
                    ui.label(
                        RichText::new(*heading)
                            .family(theme::semibold())
                            .size(theme::FONT_TITLE)
                            .color(t.foreground),
                    );
                    theme::muted(ui, *description, t);
                });
            });
        }
    }
    fn persist(&mut self) {
        if self.qa_fixture_mode() {
            return;
        }
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
        if self.qa_fixture_mode() {
            return;
        }
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
                    self.clean_registry = false;
                }
            }
            ui.add_space(6.);
        }
        ui.add_space(24.);
        let today = if self.qa_fixture_mode() {
            chrono::NaiveDate::from_ymd_opt(2026, 10, 15).expect("valid fixture date")
        } else {
            chrono::Local::now().date_naive()
        };
        if crate::activity_chart::show(ui, t, &self.history, self.history_readable, today) {
            self.page = Page::History;
        }
    }
    fn clean_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        theme::tabs(ui, |ui| {
            ui.add_enabled_ui(!self.busy(), |ui| {
                if theme::tab_with_icon_count(
                    ui,
                    !self.clean_browser && !self.clean_registry,
                    theme::Icon::Trash,
                    "Junk",
                    None,
                    t,
                )
                .clicked()
                {
                    self.clean_browser = false;
                    self.clean_registry = false;
                    self.clean_bin = false;
                }
                if theme::tab_with_icon_count(
                    ui,
                    self.clean_browser,
                    theme::Icon::Browser,
                    "Browser",
                    None,
                    t,
                )
                .clicked()
                {
                    self.clean_browser = true;
                    self.clean_registry = false;
                }
                if theme::tab_with_icon_count(
                    ui,
                    self.clean_registry,
                    theme::Icon::Registry,
                    "Registry",
                    None,
                    t,
                )
                .clicked()
                {
                    self.clean_browser = false;
                    self.clean_registry = true;
                    self.clean_bin = false;
                }
            });
            if !self.clean_browser
                && !self.clean_registry
                && !self.clean_bin
                && self.analysis.is_some()
            {
                ui.add_space(8.);
                let width = (ui.available_width() - 8.).clamp(160., 260.);
                let enabled = !self.busy();
                theme::input(
                    ui,
                    &mut self.search,
                    width,
                    "Search files or categories…",
                    enabled,
                );
            }
        });
        ui.add_space(16.);
        if self.clean_registry {
            ui.add_space(32.);
            ui.vertical_centered(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(40.), egui::Sense::hover());
                theme::paint_icon(ui.painter(), rect, theme::Icon::Registry, t.primary);
                ui.add_space(16.);
                ui.label(RichText::new("Registry analysis is unavailable").size(theme::FONT_TITLE).family(theme::semibold()));
                ui.add_space(8.);
                theme::muted(ui, "The registry rule catalogue and verified cleanup owner are not implemented. No registry entries have been analyzed or selected.", t);
            });
            return;
        }
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
                self.clean_category_tree(ui, t, ctx);
            });
        theme::card(t).show(ui,|ui|{ui.set_width(ui.available_width());
            if let Some(analysis)=self.analysis.clone(){
                ui.label(RichText::new("Analysis results").family(theme::semibold()));ui.add_space(12.);
                ui.horizontal(|ui|{ui.label(RichText::new(size(analysis.bytes())).size(theme::FONT_DISPLAY).family(theme::semibold()));theme::muted(ui,format!("{} · {:.1}s elapsed{}",theme::counted_label(analysis.count(),"file","files"),analysis.elapsed_ms as f64/1000.,if analysis.cancelled{" · cancelled"}else{""}),t);});ui.add_space(10.);
                let query=self.search.to_lowercase();let busy=self.busy();
                for category in &analysis.categories{
                    if !query.is_empty()&&!category.name.to_lowercase().contains(&query)&&!category.files.iter().any(|f|f.path.to_string_lossy().to_lowercase().contains(&query)){continue;}
                    let status=if category.truncated{"Partial scan"}else if !category.available{"Not found"}else if category.files.is_empty(){"No eligible files"}else{""};
                    ui.horizontal(|ui|{let mut all=!category.files.is_empty()&&category.files.iter().all(|f|self.selected.contains(&f.id));if theme::checkbox_widget(ui,&mut all,!busy&&!analysis.cancelled&&!category.files.is_empty()).changed(){for f in &category.files{if all{self.selected.insert(f.id);}else{self.selected.remove(&f.id);}}}
                        ui.label(&category.name);ui.with_layout(Layout::right_to_left(Align::Center),|ui|{ui.label(size(category.bytes()));theme::muted(ui,format!("{} files   {status}",category.files.len()),t);});});
                    if category.skipped>0{theme::muted(ui,format!("{} inaccessible or linked locations skipped",category.skipped),t);}
                    egui::CollapsingHeader::new(format!("View files — {}",category.name)).id_salt(&category.id).show(ui,|ui|{
                        egui::ScrollArea::vertical().max_height(220.).id_salt(format!("files-{}",category.id)).show(ui,|ui|{
                            for f in category.files.iter().filter(|f|query.is_empty()||category.name.to_lowercase().contains(&query)||f.path.to_string_lossy().to_lowercase().contains(&query)).take(200){ui.horizontal(|ui|{let mut selected=self.selected.contains(&f.id);if theme::checkbox_widget(ui,&mut selected,!busy&&!analysis.cancelled).changed(){if selected{self.selected.insert(f.id);}else{self.selected.remove(&f.id);}}ui.add(egui::Label::new(RichText::new(f.path.to_string_lossy()).size(theme::FONT_CAPTION)).truncate()).on_hover_text(f.path.to_string_lossy());ui.label(RichText::new(size(f.size)).size(theme::FONT_CAPTION));});}
                            if category.files.len()>200{theme::muted(ui,"Showing up to 200 matching files. Export for the full list. Category selection includes all files.",t);}
                        });});ui.separator();
                }
            }else{
                ui.add_space(32.);
                ui.vertical_centered(|ui|{
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(36.), egui::Sense::hover());
                    theme::paint_icon(ui.painter(), rect, theme::Icon::Trash, t.primary);
                    ui.add_space(20.);
                    ui.label(RichText::new("Clean up system clutter").size(theme::FONT_TITLE).family(theme::semibold()));
                    ui.add_space(12.);
                    theme::muted(ui,"Temporary files, logs and application caches can accumulate. Choose supported categories, scan, then review the files to remove.",t);
                });
                ui.add_space(32.);
            }

        });
    }

    fn clean_category_tree(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let categories = self.categories.clone();
        let busy = self.busy();
        let mut changed = false;
        let selected_count = categories
            .iter()
            .filter(|category| self.prefs.selected_categories.contains(&category.id))
            .count();
        let mut all = !categories.is_empty() && selected_count == categories.len();
        let mixed = selected_count > 0 && !all;
        theme::control_row(ui, |ui| {
            if theme::checkbox_named(
                ui,
                &mut all,
                mixed,
                "Select all custom categories",
                !busy && !categories.is_empty(),
            )
            .changed()
            {
                self.prefs
                    .selected_categories
                    .retain(|id| !categories.iter().any(|category| &category.id == id));
                if all {
                    self.prefs
                        .selected_categories
                        .extend(categories.iter().map(|category| category.id.clone()));
                }
                changed = true;
            }
            ui.label("Select all");
            if theme::icon_action(ui, theme::Icon::Refresh, "Reset", !busy) {
                let defaults = Preferences::default();
                self.prefs.selected_categories = defaults
                    .selected_categories
                    .into_iter()
                    .filter(|id| categories.iter().any(|category| &category.id == id))
                    .collect();
                changed = true;
            }
        });
        ui.separator();
        let mut groups = Vec::new();
        for category in &categories {
            if !groups.contains(&category.group) {
                groups.push(category.group.clone());
            }
        }
        for group in groups {
            let members = categories
                .iter()
                .filter(|category| category.group == group)
                .collect::<Vec<_>>();
            let selected = members
                .iter()
                .filter(|category| self.prefs.selected_categories.contains(&category.id))
                .count();
            let mut checked = selected == members.len();
            let mixed = selected > 0 && !checked;
            let state_id = egui::Id::new(("custom-clean-group", &group));
            let mut open = ui
                .ctx()
                .data(|data| data.get_temp::<bool>(state_id).unwrap_or(true));
            ui.allocate_ui_with_layout(
                Vec2::new(ui.available_width(), 40.),
                Layout::left_to_right(Align::Center),
                |ui| {
                    ui.set_min_height(40.);
                    if theme::checkbox_named(
                        ui,
                        &mut checked,
                        mixed,
                        &format!("Select custom group {group}"),
                        !busy,
                    )
                    .changed()
                    {
                        self.prefs
                            .selected_categories
                            .retain(|id| !members.iter().any(|category| &category.id == id));
                        if checked {
                            self.prefs
                                .selected_categories
                                .extend(members.iter().map(|category| category.id.clone()));
                        }
                        changed = true;
                    }
                    let (icon_rect, _) =
                        ui.allocate_exact_size(Vec2::splat(18.), egui::Sense::hover());
                    theme::paint_icon(
                        ui.painter(),
                        icon_rect,
                        match group.as_str() {
                            "Windows" => theme::Icon::Windows,
                            "Applications" => theme::Icon::Applications,
                            _ => theme::Icon::Folder,
                        },
                        t.muted,
                    );
                    let name_width = (ui.available_width() - 30.).max(40.);
                    theme::table_cell(
                        ui,
                        RichText::new(&group).family(theme::semibold()),
                        name_width,
                        40.,
                    );
                    if theme::disclosure(
                        ui,
                        &format!(
                            "{} custom group {group}",
                            if open { "Collapse" } else { "Expand" }
                        ),
                        open,
                    )
                    .clicked()
                    {
                        open = !open;
                        ui.ctx().data_mut(|data| data.insert_temp(state_id, open));
                    }
                },
            );
            if open {
                ui.indent((&group, "custom-clean-leaves"), |ui| {
                    for category in members {
                        let mut checked = self.prefs.selected_categories.contains(&category.id);
                        let response = ui
                            .horizontal(|ui| {
                                let mut response = theme::checkbox_named(
                                    ui,
                                    &mut checked,
                                    false,
                                    &category.name,
                                    !busy,
                                );
                                let (icon_rect, _) =
                                    ui.allocate_exact_size(Vec2::splat(16.), egui::Sense::hover());
                                theme::paint_icon(
                                    ui.painter(),
                                    icon_rect,
                                    match category.id.as_str() {
                                        "chrome" | "edge" | "firefox" => theme::Icon::Browser,
                                        "temp" => theme::Icon::Trash,
                                        "crash" => theme::Icon::Info,
                                        _ => theme::Icon::Folder,
                                    },
                                    t.muted,
                                );
                                let name = ui
                                    .add_enabled(
                                        !busy,
                                        egui::Label::new(&category.name)
                                            .truncate()
                                            .sense(egui::Sense::click()),
                                    )
                                    .on_hover_text(&category.description);
                                if name.clicked() {
                                    checked = !checked;
                                    response.mark_changed();
                                }
                                response
                            })
                            .inner
                            .on_hover_text(&category.description);
                        if response.changed() {
                            self.prefs
                                .selected_categories
                                .retain(|id| id != &category.id);
                            if checked {
                                self.prefs.selected_categories.push(category.id.clone());
                            }
                            changed = true;
                        }
                    }
                });
            }
            ui.separator();
        }
        if categories.is_empty() {
            theme::muted(ui, "No supported file categories are available.", t);
        }
        ui.add_space(8.);
        theme::muted(
            ui,
            format!("Files at least {} days old", self.prefs.minimum_age_days),
            t,
        );
        if cfg!(windows) {
            ui.add_space(12.);
            if theme::row_action(ui, "Review Recycle Bin", !busy).clicked() {
                self.clean_bin = true;
                self.recycle_bin_entered(ctx);
            }
        }
        if changed {
            self.invalidate();
        }
    }

    fn clean_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if self.clean_registry {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                theme::primary(ui, "Clean and fix", t, false);
                theme::secondary(ui, "Scan now", false);
                theme::muted(ui, "Registry analysis unavailable", t);
            });
            return;
        }
        ui.with_layout(
            Layout::right_to_left(Align::Center).with_main_wrap(true),
            |ui| {
                let busy = self.busy();
                let enabled = !busy
                    && !self.selected.is_empty()
                    && self.history_readable
                    && !self.custom_selection_blocked()
                    && self.analysis.as_ref().is_some_and(|a| !a.cancelled)
                    && self
                        .custom_analysis
                        .as_ref()
                        .is_none_or(|report| !report.partial() || self.custom_partial_acknowledged);
                let label = if self.selected.is_empty() {
                    "Clean selected".into()
                } else {
                    format!(
                        "Clean {}",
                        theme::counted_label(self.selected.len(), "file", "files")
                    )
                };
                if theme::primary(ui, &label, t, enabled) {
                    self.confirm = true;
                }
                let bytes: u64 = self
                    .analysis
                    .iter()
                    .flat_map(|report| &report.categories)
                    .flat_map(|category| &category.files)
                    .filter(|file| self.selected.contains(&file.id))
                    .map(|file| file.size)
                    .sum();
                theme::muted(
                    ui,
                    format!(
                        "{} · {} selected",
                        theme::counted_label(self.selected.len(), "file", "files"),
                        size(bytes)
                    ),
                    t,
                );
                if theme::secondary(
                    ui,
                    "Scan now",
                    !busy
                        && (!self.prefs.selected_categories.is_empty()
                            || self.custom_clean_enabled()),
                ) {
                    self.begin_scan(ctx);
                }
                if theme::secondary(ui, "Export report", !busy && self.analysis.is_some()) {
                    self.export();
                }
            },
        );
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
        let mut settings = std::mem::take(&mut self.settings_ui);
        view_settings::show(self, &mut settings, ui, t, ctx);
        self.settings_ui = settings;
        if view_settings::take_check_request(&mut self.settings_ui) {
            if self.qa_fixture_mode() {
                // Fixture requests are handled by the view; this boundary never
                // grants them a network worker even if a future view regresses.
                view_settings::handle_event(
                    &mut self.settings_ui,
                    view_settings::SettingsEvent::ReleaseChecked(Err(
                        "Fixture network access is disabled.".into(),
                    )),
                );
                return;
            }
            let (sender, receiver) = mpsc::channel();
            self.worker = Some(receiver);
            self.progress = "Checking published DCleaner releases…".into();
            let context = ctx.clone();
            thread::spawn(move || {
                let result = view_settings::check_latest_release();
                let _ = sender.send(Event::Settings(
                    view_settings::SettingsEvent::ReleaseChecked(result),
                ));
                context.request_repaint();
            });
        }
    }
}
impl App {
    #[cfg(debug_assertions)]
    pub(crate) fn qa_busy(&self) -> bool {
        self.busy() || self.app_icons.is_loading()
    }
    #[cfg(debug_assertions)]
    pub(crate) fn qa_action_precondition(
        &self,
        label: &str,
        ctx: &egui::Context,
    ) -> Result<(), String> {
        if label.starts_with("Navigate ")
            || matches!(
                label,
                "Expand menu"
                    | "Collapse menu"
                    | "More tools"
                    | "Disk Analyzer"
                    | "Cleanup History"
            )
        {
            let valid = if let Some(name) = label.strip_prefix("Navigate ") {
                PAGES.iter().any(|page| page.name() == name)
            } else {
                match label {
                    "Expand menu" | "Collapse menu" => true,
                    "More tools" | "Disk Analyzer" | "Cleanup History" => self.page == Page::Clean,
                    _ => false,
                }
            };
            return if valid && !self.busy() {
                Ok(())
            } else {
                Err(format!("Navigation action is unavailable: {label}"))
            };
        }
        if self.page == Page::Clean && self.clean_browser && matches!(label, "Select all" | "Clear")
        {
            return self.qa_privacy_profile_action(label, false).map(|_| ());
        }
        if self.page == Page::Clean
            && (matches!(
                label,
                "Junk" | "Browser" | "Registry" | "Select all custom categories" | "Reset"
            ) || label.starts_with("Select custom group ")
                || label.starts_with("Collapse custom group ")
                || label.starts_with("Expand custom group "))
        {
            ctx.data_mut(|data| {
                data.insert_temp(
                    egui::Id::new("qa-custom-categories-before"),
                    self.prefs.selected_categories.clone(),
                )
            });
            return Ok(());
        }
        if self.page == Page::Optimizer && !matches!(label, "Start now" | "Scan now") {
            return self.qa_optimizer_precondition(label);
        }
        if self.page == Page::Programs && !matches!(label, "Start now" | "Scan now") {
            return self.qa_programs_precondition(label);
        }
        if self.page == Page::Duplicates && !matches!(label, "Start now" | "Scan now") {
            return self.qa_duplicates_precondition(label);
        }
        if self.page == Page::Cloud && !matches!(label, "Get started" | "Cleanup history") {
            return self.qa_cloud_precondition(label);
        }
        if self.page == Page::Software && label != "Start now" && label != "Scan now" {
            return self.qa_software_action_precondition(label);
        }
        if self.page == Page::Drivers && label != "Start now" && label != "Scan now" {
            return self.qa_driver_action_precondition(label);
        }
        if self.page == Page::Startup
            && matches!(
                label,
                "Enable startup item"
                    | "Close"
                    | "Disable startup item"
                    | "More"
                    | "Show details"
                    | "Remove"
                    | "Cancel"
                    | "Confirm fixture review"
            )
        {
            return self.qa_startup_action_precondition(label);
        }
        if self.page == Page::Settings {
            if !view_settings::qa_action_precondition(self, ctx, label) {
                return Err(format!(
                    "Settings action precondition is not satisfied: {label}"
                ));
            }
            let before = view_settings::qa_state(self, ctx);
            ctx.data_mut(|data| {
                data.insert_temp(egui::Id::new("qa-settings-before-action"), before)
            });
            return Ok(());
        }
        let cloud = self.qa_cloud_state();
        let valid = match (self.page, label) {
            (Page::Overview, label) if self.qa_health_action(label, false).is_some() => {
                self.qa_health_action(label, false).unwrap_or(false)
            }
            (Page::Cloud, "Get started") => cloud["introduced"] == false,
            (Page::Cloud, "Cleanup history") => cloud["history"] == false,
            (Page::Disk, "Details") => !self.qa_disk_detail_open(),
            (Page::Disk, "Close" | "Copy path") => self.qa_disk_detail_open(),
            (Page::Startup, "About Startup Manager") => !self.qa_startup_info_open(),
            (Page::Startup, "Got it") => self.qa_startup_info_open(),
            (Page::Startup, "Sort Program") => self.qa_startup_sort_state()["descending"] == false,
            (Page::Startup, "Sort Publisher") => true,
            (Page::Overview, "All statistics") => {
                self.feature_seen("health") && !self.health_started()
            }
            (Page::Overview, "Rescan") => self.feature_seen("health") && !self.health_started(),
            (page, "Scan now" | "Start now") => self
                .qa_intro_kind(page)
                .is_some_and(|kind| !self.feature_seen(kind)),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(format!(
                "Fixture action precondition is not satisfied: {label}"
            ))
        }
    }
    #[cfg(debug_assertions)]
    pub(crate) fn qa_action_state(
        &self,
        label: &str,
        ctx: &egui::Context,
    ) -> Result<serde_json::Value, String> {
        if !self.qa_fixture_mode() {
            return Err("UI action verification requires isolated fixture mode.".into());
        }
        if label.starts_with("Navigate ")
            || matches!(
                label,
                "Expand menu"
                    | "Collapse menu"
                    | "More tools"
                    | "Disk Analyzer"
                    | "Cleanup History"
            )
        {
            let valid = if let Some(name) = label.strip_prefix("Navigate ") {
                self.page.name() == name
            } else {
                match label {
                    "Expand menu" => self.sidebar_collapsed == Some(false),
                    "Collapse menu" => self.sidebar_collapsed == Some(true),
                    "More tools" => ctx
                        .data(|data| data.get_temp::<bool>(egui::Id::new("qa-more-tools-open")))
                        .unwrap_or(false),
                    "Disk Analyzer" => self.page == Page::Disk,
                    "Cleanup History" => self.page == Page::History,
                    _ => false,
                }
            };
            return if valid {
                Ok(
                    serde_json::json!({"page": self.page.name(), "sidebar_collapsed":self.sidebar_collapsed, "native_effects":false}),
                )
            } else {
                Err(format!(
                    "Navigation action did not reach its expected state: {label}"
                ))
            };
        }
        if self.page == Page::Clean && self.clean_browser && matches!(label, "Select all" | "Clear")
        {
            return self.qa_privacy_profile_action(label, true);
        }
        if self.page == Page::Clean
            && (matches!(
                label,
                "Junk" | "Browser" | "Registry" | "Select all custom categories" | "Reset"
            ) || label.starts_with("Select custom group ")
                || label.starts_with("Collapse custom group ")
                || label.starts_with("Expand custom group "))
        {
            let before = ctx
                .data(|data| {
                    data.get_temp::<Vec<String>>(egui::Id::new("qa-custom-categories-before"))
                })
                .unwrap_or_default();
            let known = self
                .categories
                .iter()
                .map(|category| category.id.clone())
                .collect::<Vec<_>>();
            let valid = match label {
                "Junk" => !self.clean_registry && !self.clean_browser,
                "Browser" => self.clean_browser && !self.clean_registry,
                "Registry" => self.clean_registry && !self.clean_browser,
                "Reset" => {
                    self.prefs.selected_categories
                        == Preferences::default()
                            .selected_categories
                            .into_iter()
                            .filter(|id| known.contains(id))
                            .collect::<Vec<_>>()
                        && self.analysis.is_none()
                }
                _ if label.starts_with("Collapse custom group ")
                    || label.starts_with("Expand custom group ") =>
                {
                    let (prefix, expected) = if label.starts_with("Collapse") {
                        ("Collapse custom group ", false)
                    } else {
                        ("Expand custom group ", true)
                    };
                    let group = label.trim_start_matches(prefix);
                    ctx.data(|data| {
                        data.get_temp::<bool>(egui::Id::new(("custom-clean-group", group)))
                    }) == Some(expected)
                }
                _ => {
                    let members = if label == "Select all custom categories" {
                        known.clone()
                    } else {
                        self.categories
                            .iter()
                            .filter(|category| {
                                category.group == label.trim_start_matches("Select custom group ")
                            })
                            .map(|category| category.id.clone())
                            .collect()
                    };
                    let previously_all =
                        !members.is_empty() && members.iter().all(|id| before.contains(id));
                    !members.is_empty()
                        && members
                            .iter()
                            .all(|id| self.prefs.selected_categories.contains(id) != previously_all)
                        && self.analysis.is_none()
                }
            };
            return if valid {
                Ok(
                    serde_json::json!({"tab": if self.clean_registry {"Registry"} else if self.clean_browser {"Browser"} else {"Junk"}, "selected_categories": self.prefs.selected_categories, "known_categories": known, "analysis_present": self.analysis.is_some(), "registry_effects_available": false}),
                )
            } else {
                Err(format!(
                    "Custom Clean action did not reach its expected state: {label}"
                ))
            };
        }
        if self.page == Page::Optimizer && !matches!(label, "Start now" | "Scan now") {
            return self.qa_optimizer_action_state(label);
        }
        if self.page == Page::Programs && !matches!(label, "Start now" | "Scan now") {
            return self.qa_programs_action_state(label);
        }
        if self.page == Page::Duplicates && !matches!(label, "Start now" | "Scan now") {
            return self.qa_duplicates_action_state(label);
        }
        if self.page == Page::Cloud && !matches!(label, "Get started" | "Cleanup history") {
            return self.qa_cloud_action_state(label);
        }
        if self.page == Page::Software && label != "Start now" && label != "Scan now" {
            return self.qa_software_action_state(label);
        }
        if self.page == Page::Drivers && label != "Start now" && label != "Scan now" {
            return self.qa_driver_action_state(label);
        }
        if self.page == Page::Startup
            && matches!(
                label,
                "Enable startup item"
                    | "Close"
                    | "Disable startup item"
                    | "More"
                    | "Show details"
                    | "Remove"
                    | "Cancel"
                    | "Confirm fixture review"
            )
        {
            return self.qa_startup_action_state(label);
        }
        let state = serde_json::json!({"page":self.page.name(),"settings":view_settings::qa_state(self, ctx),"health_started":self.health_started(),"health":self.qa_health_state(),"clean_settings":self.qa_clean_settings_state(),"cloud":self.qa_cloud_state(), "disk_details_open":self.qa_disk_detail_open(),"startup_info_open":self.qa_startup_info_open(),"startup_sort":self.qa_startup_sort_state(),"seen_features":self.prefs.seen_features});
        let valid = match (self.page, label) {
            (Page::Settings, label) => {
                let before = ctx
                    .data(|data| {
                        data.get_temp::<serde_json::Value>(egui::Id::new(
                            "qa-settings-before-action",
                        ))
                    })
                    .unwrap_or(serde_json::Value::Null);
                let settings = &state["settings"];
                match label {
                    "General" => settings["tab"] == "general",
                    "Scheduling" => settings["tab"] == "scheduling",
                    "Updates" => settings["tab"] == "updates",
                    "Privacy" => settings["tab"] == "privacy",
                    "Menu" | "Menu Layout" => settings["tab"] == "menu-layout",
                    "My Subscription" => settings["tab"] == "my-subscription",
                    "About" => settings["tab"] == "about",
                    "Light" => settings["appearance"] == "Light" && settings["dark"] == false,
                    "Dark" => settings["appearance"] == "Dark" && settings["dark"] == true,
                    "Auto" => settings["appearance"] == "System",
                    "Check for updates" => {
                        settings["update_check"] == "no_published_release"
                            && settings["update_check_pending"] == false
                    }
                    "Health Check" => settings["landing_page"] == "HealthCheck",
                    "Custom Clean" => settings["landing_page"] == "CustomClean",
                    "Always show the landing page at the top of the menu" => {
                        settings["menu_pin_landing_page"] != before["menu_pin_landing_page"]
                    }
                    "Reset" if before["reset_dialog_open"] == false => {
                        settings["reset_dialog_open"] == true
                            && settings["seen_features"] == before["seen_features"]
                    }
                    "Reset" => {
                        settings["reset_dialog_open"] == false
                            && settings["seen_features"]
                                .as_array()
                                .is_some_and(Vec::is_empty)
                    }
                    "Cancel" | "Close" => {
                        settings["reset_dialog_open"] == false
                            && settings["seen_features"] == before["seen_features"]
                    }
                    _ => false,
                }
            }
            (Page::Help, "Open Help") => true,
            (Page::Overview, label) if self.qa_health_action(label, true).is_some() => {
                self.qa_health_action(label, true).unwrap_or(false)
            }
            (Page::Cloud, "Get started") => state["cloud"]["introduced"] == true,
            (Page::Cloud, "Cleanup history") => state["cloud"]["history"] == true,
            (Page::Disk, "Details") => self.qa_disk_detail_open(),
            (Page::Disk, "Close") => !self.qa_disk_detail_open(),
            (Page::Disk, "Copy path") => self.qa_disk_detail_open(),
            (Page::Startup, "About Startup Manager") => self.qa_startup_info_open(),
            (Page::Startup, "Got it") => !self.qa_startup_info_open(),
            (Page::History, "All statistics") => true,
            (Page::Overview, "Rescan") => self.health_started(),
            (Page::Startup, "Sort Program") => {
                state["startup_sort"]["column"] == "Program"
                    && state["startup_sort"]["descending"] == true
            }
            (Page::Startup, "Sort Publisher") => {
                state["startup_sort"]["column"] == "Publisher"
                    && state["startup_sort"]["descending"] == false
            }
            (page, "Scan now" | "Start now") => self
                .qa_intro_kind(page)
                .is_some_and(|kind| self.feature_seen(kind)),
            _ => false,
        };
        if valid {
            Ok(state)
        } else {
            Err(format!(
                "The rendered action did not produce its expected UI state: {label}"
            ))
        }
    }
    #[cfg(debug_assertions)]
    fn qa_intro_kind(&self, page: Page) -> Option<&'static str> {
        match page {
            Page::Overview => Some("health"),
            Page::Programs => Some("programs"),
            Page::Software => Some("software"),
            Page::Drivers => Some("drivers"),
            Page::Optimizer => Some("optimizer"),
            Page::Duplicates => Some("duplicates"),
            _ => None,
        }
    }
    pub(crate) fn paint(&mut self, root: &mut egui::Ui) {
        self.poll();
        let ctx = root.ctx().clone();
        let effective_dark = self
            .prefs
            .effective_dark(ctx.system_theme().map(|theme| theme == egui::Theme::Dark));
        if self.prefs.dark != effective_dark {
            self.prefs.dark = effective_dark;
            theme::apply(&ctx, effective_dark);
        }
        #[cfg(debug_assertions)]
        theme::begin_geometry_frame(&ctx);
        if !self.qa_fixture_mode() {
            self.startup_refresh_external_state(&ctx);
        }
        let t = theme::tokens(self.prefs.dark);
        let busy = self.busy();
        if busy {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        if ctx.input(|i| i.viewport().close_requested()) {
            self.cancel.store(true, Ordering::Relaxed);
        }
        let narrow = self
            .sidebar_collapsed
            .unwrap_or(root.available_width() < 900.);
        let primary_pages = navigation_pages(&self.prefs)
            .into_iter()
            .filter(|page| {
                !matches!(
                    page,
                    Page::Disk | Page::History | Page::Settings | Page::Help
                )
            })
            .collect::<Vec<_>>();
        egui::Panel::left("main-navigation")
            .resizable(false)
            .exact_size(if narrow { 64. } else { 228. })
            .frame(
                egui::Frame::new()
                    .fill(t.sidebar)
                    .inner_margin(egui::Margin::symmetric(
                        if narrow { 10 } else { 12 },
                        if cfg!(windows) { 4 } else { 20 },
                    )),
            )
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(28.), egui::Sense::hover());
                    if let Some(logo) = self.logo_texture.as_ref() {
                        ui.painter().image(
                            logo.id(),
                            rect,
                            egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1., 1.)),
                            Color32::WHITE,
                        );
                    }
                    if !narrow {
                        ui.label(RichText::new("DCleaner").family(theme::semibold()));
                    }
                });
                ui.add_space(4.);
                if theme::icon_action(
                    ui,
                    theme::Icon::Menu,
                    if narrow {
                        "Expand menu"
                    } else {
                        "Collapse menu"
                    },
                    !busy,
                ) {
                    self.sidebar_collapsed = Some(!narrow);
                }
                ui.add_space(2.);
                ui.spacing_mut().item_spacing.y = 2.;
                for page in primary_pages {
                    let selected = self.page == page
                        || (page == Page::Clean && self.page == Page::Disk)
                        || (page == Page::Overview && self.page == Page::History);
                    if theme::navigation(ui, page.name(), page.icon(), selected, !busy, narrow, t) {
                        self.page = page;
                        self.search.clear();
                    }
                }
                ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                    ui.add_space(12.);
                    if theme::navigation(
                        ui,
                        Page::Settings.name(),
                        theme::Icon::Settings,
                        matches!(self.page, Page::Settings | Page::Help),
                        !busy,
                        narrow,
                        t,
                    ) {
                        self.page = Page::Settings;
                        self.search.clear();
                    }
                });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(t.canvas))
            .show(root, |ui| {
                theme::canvas_background(ui, self.prefs.dark);
                let status_overview = self.page == Page::Overview
                    && !self.health_started()
                    && self.feature_seen("health");
                let health_workflow = self.page == Page::Overview && self.health_started();
                if !status_overview
                    && !matches!(self.page, Page::Settings | Page::Help)
                    && !(health_workflow && self.health_progress_active())
                {
                    egui::Panel::bottom("page-actions")
                        .resizable(false)
                        .default_size(74.)
                        .min_size(74.)
                        .max_size(200.)
                        .frame(
                            egui::Frame::new()
                                .fill(t.sidebar)
                                .stroke(egui::Stroke::new(1., t.border))
                                .inner_margin(egui::Margin::symmetric(28, 18)),
                        )
                        .show(ui, |ui| {
                            ui.spacing_mut().interact_size.y = theme::CONTROL_HEIGHT;
                            match self.page {
                                Page::Clean if self.clean_browser => {
                                    self.privacy_footer(ui, t, &ctx)
                                }
                                Page::Clean if self.clean_bin => {
                                    self.recycle_bin_footer(ui, t, &ctx)
                                }
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
                }
                egui::Frame::new()
                    .inner_margin(egui::Margin {
                        left: 28,
                        right: 28,
                        top: if cfg!(windows) { 60 } else { 28 },
                        bottom: 28,
                    })
                    .show(ui, |ui| {
                        if !health_workflow {
                            ui.horizontal(|ui| {
                                ui.heading(
                                    if self.page == Page::Overview
                                        && !self.health_started()
                                        && self.feature_seen("health")
                                    {
                                        "Your scan results"
                                    } else {
                                        self.page.name()
                                    },
                                );
                                if self.page == Page::Startup {
                                    self.startup_info_button(ui);
                                }
                                if self.page == Page::Clean {
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        self.clean_settings_configure_button(ui, t, &ctx);
                                        let tools =
                                            theme::row_more(ui, !busy).on_hover_text("More tools");
                                        #[cfg(debug_assertions)]
                                        theme::record_fixture_control(ui, "More tools", &tools);
                                        let popup = egui::Popup::menu(&tools);
                                        #[cfg(debug_assertions)]
                                        let popup_id = popup.get_id();
                                        popup.show(|ui| {
                                            if theme::menu_action(
                                                ui,
                                                theme::Icon::Disk,
                                                "Disk Analyzer",
                                                !busy,
                                            )
                                            .clicked()
                                            {
                                                self.page = Page::Disk;
                                                ui.close();
                                            }
                                            if theme::menu_action(
                                                ui,
                                                theme::Icon::History,
                                                "Cleanup History",
                                                !busy,
                                            )
                                            .clicked()
                                            {
                                                self.page = Page::History;
                                                ui.close();
                                            }
                                        });
                                        #[cfg(debug_assertions)]
                                        {
                                            let open = egui::Popup::is_id_open(&ctx, popup_id);
                                            ctx.data_mut(|data| {
                                                data.insert_temp(
                                                    egui::Id::new("qa-more-tools-open"),
                                                    open,
                                                )
                                            });
                                        }
                                    });
                                }
                                if status_overview {
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if theme::header_action(ui, "Rescan", !busy) {
                                            self.rescan_health(&ctx);
                                        }
                                    });
                                }
                            });
                            if !matches!(self.page, Page::Settings | Page::Help) {
                                theme::muted(ui, self.page.description(), t);
                            }
                            ui.add_space(if matches!(self.page, Page::Settings | Page::Help) {
                                16.
                            } else {
                                26.
                            });
                        }
                        let page_scroll = egui::ScrollArea::vertical()
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
                                        Page::Overview
                                            | Page::Optimizer
                                            | Page::Cloud
                                            | Page::Settings
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
                        #[cfg(debug_assertions)]
                        theme::record_scroll(
                            &ctx,
                            "page-body",
                            page_scroll.inner_rect,
                            page_scroll.content_size,
                            page_scroll.state.offset,
                        );
                        #[cfg(not(debug_assertions))]
                        let _ = page_scroll;
                    });
            });
        #[cfg(windows)]
        theme::window_chrome(root, t);
        self.duplicates_dialog(&ctx);
        self.disk_dialog(&ctx);
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
                                        RichText::new(title)
                                            .family(theme::semibold())
                                            .size(theme::FONT_TITLE),
                                    )
                                    .truncate(),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(description)
                                            .color(t.muted)
                                            .size(theme::FONT_CAPTION),
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
                            .size(theme::FONT_CAPTION),
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
