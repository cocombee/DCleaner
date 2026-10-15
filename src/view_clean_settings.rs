use super::{App, Event};
use crate::theme::{self, Tokens};
use dcleaner::{
    clean_settings::{
        CustomCleanSettings, ExclusionRule, ExclusionType, FileDeletionMode, FolderInclusion,
        InclusionLocation, InclusionRule, OverwriteType, WipeDrivePreference, load_settings,
        save_settings,
    },
    custom_clean::rule_id_for_inclusion,
    privacy::{self, CookieExceptionSettings},
};
use eframe::egui::{self, Align, Layout, RichText};
use std::{sync::mpsc, thread};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SettingsTab {
    #[default]
    Cookies,
    FilesToClean,
    FilesToIgnore,
    DeletingFiles,
    Advanced,
}

const POPULAR_COOKIE_DOMAINS: &[&str] = &[
    "amazon.com",
    "bing.com",
    "discord.com",
    "duckduckgo.com",
    "ebay.com",
    "google.com",
    "instagram.com",
    "linkedin.com",
    "live.com",
    "microsoft.com",
    "msn.com",
    "netflix.com",
    "office.com",
    "pinterest.com",
    "quora.com",
    "reddit.com",
    "roblox.com",
    "samsung.com",
    "sharepoint.com",
    "tiktok.com",
    "weather.com",
    "whatsapp.com",
    "yahoo.com",
    "youtube.com",
    "wikipedia.org",
    "twitch.tv",
    "zoom.us",
];

#[cfg(debug_assertions)]
const DEFAULT_COOKIE_KEEP_DOMAINS: &[&str] = &[
    "services.adobe.com",
    "aol.com",
    "login.comcast.net",
    "webmail.earthlink.net",
    "facebook.com",
    "fastmail.fm",
    "google.com",
    "mail.lycos.com",
    "icloud.com",
    "login.live.com",
    "auth.me.com",
    "mail.netscape.com",
    "ovi.com",
    "twitter.com",
    "yahoo.com",
];

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
    cookies_only: bool,
    close_after_save: bool,
    operation: SettingsOperation,
    saved: Option<CustomCleanSettings>,
    draft: Option<CustomCleanSettings>,
    saved_cookies: Option<CookieExceptionSettings>,
    draft_cookie_domains: Option<Vec<String>>,
    cookie_domain_input: String,
    popular_sites_open: bool,
    popular_site_selected: Vec<bool>,
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
            cookies_only: false,
            close_after_save: false,
            operation: SettingsOperation::Idle,
            saved: None,
            draft: None,
            saved_cookies: None,
            draft_cookie_domains: None,
            cookie_domain_input: String::new(),
            popular_sites_open: false,
            popular_site_selected: Vec::new(),
            tab: SettingsTab::Cookies,
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
    Loaded {
        settings: Result<CustomCleanSettings, String>,
        cookies: Result<CookieExceptionSettings, String>,
    },
    Saved {
        settings: Result<CustomCleanSettings, String>,
        cookies: Option<Result<CookieExceptionSettings, String>>,
    },
}

impl App {
    #[cfg(debug_assertions)]
    pub(super) fn qa_clean_settings_state(&self) -> serde_json::Value {
        serde_json::json!({"open":self.clean_settings_ui.open, "cookies_only":self.clean_settings_ui.cookies_only, "popular_sites_open":self.clean_settings_ui.popular_sites_open})
    }
    pub(super) fn clean_settings_configure_button(
        &mut self,
        ui: &mut egui::Ui,
        _t: Tokens,
        ctx: &egui::Context,
    ) {
        if theme::field_action(ui, "Configure", !self.busy()) {
            self.open_clean_settings_editor(ctx, false);
        }
    }

    pub(super) fn open_health_cookie_settings(&mut self, ctx: &egui::Context) {
        self.open_clean_settings_editor(ctx, true);
    }

    fn open_clean_settings_editor(&mut self, ctx: &egui::Context, cookies_only: bool) {
        self.clean_settings_ui.open = true;
        self.clean_settings_ui.cookies_only = cookies_only;
        self.clean_settings_ui.close_after_save = false;
        self.clean_settings_ui.tab = SettingsTab::Cookies;
        self.clean_settings_ui.form_error = None;
        self.clean_settings_ui.load_error = None;
        self.clean_settings_ui.save_error = None;
        if self.qa_fixture_mode() {
            let settings = self.clean_settings_ui.saved.clone().unwrap_or_default();
            let cookies = self
                .clean_settings_ui
                .saved_cookies
                .clone()
                .unwrap_or_default();
            self.clean_settings_ui.saved = Some(settings.clone());
            self.clean_settings_ui.draft = Some(settings);
            self.clean_settings_ui.saved_cookies = Some(cookies.clone());
            self.clean_settings_ui.draft_cookie_domains = Some(cookies.keep_domains);
        } else {
            self.clean_settings_ui.draft = None;
            self.clean_settings_ui.draft_cookie_domains = None;
            self.start_clean_settings_load(ctx);
        }
    }

    fn clean_settings_changed(&self) -> bool {
        matches!((&self.clean_settings_ui.saved, &self.clean_settings_ui.draft), (Some(saved), Some(draft)) if saved != draft)
            || matches!((&self.clean_settings_ui.saved_cookies, &self.clean_settings_ui.draft_cookie_domains), (Some(saved), Some(draft)) if &saved.keep_domains != draft)
    }

    fn save_committed_clean_settings(&mut self, ctx: &egui::Context) {
        if self.clean_settings_ui.open
            && self.clean_settings_ui.operation == SettingsOperation::Idle
            && !self.busy()
            && !self.clean_settings_ui.popular_sites_open
            && self.clean_settings_ui.load_error.is_none()
            && self.clean_settings_ui.save_error.is_none()
            && self.clean_settings_changed()
        {
            self.begin_save_clean_settings(ctx);
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

    pub(super) fn sync_cookie_settings_owners(&mut self, settings: CookieExceptionSettings) {
        self.sync_privacy_cookie_settings(settings.clone());
        self.sync_health_cookie_settings(settings);
    }

    /// A failed read or write can leave the persisted cookie file unknown: a write may
    /// fail after its atomic rename. Keep drafts intact, but make every scan consumer
    /// unusable until a later successful read supplies a verified snapshot.
    pub(super) fn mark_cookie_settings_unverified(&mut self) {
        let message = "Cookie rules could not be verified. Reload the saved rules in Custom Clean settings before scanning or reviewing cleanup.";
        self.mark_privacy_cookie_settings_unverified(message);
        self.mark_health_cookie_settings_unverified(message);
        self.notice = Some(message.into());
    }

    pub(super) fn clean_settings_dialog(&mut self, ctx: &egui::Context) {
        if !self.clean_settings_ui.open {
            return;
        }
        self.save_committed_clean_settings(ctx);
        let escape_pressed = self.clean_settings_ui.operation == SettingsOperation::Idle
            && ctx.input(|input| input.key_pressed(egui::Key::Escape));
        let escape_cancelled_popular_sites =
            escape_pressed && self.clean_settings_ui.popular_sites_open;
        if escape_cancelled_popular_sites {
            self.clean_settings_ui.popular_sites_open = false;
            self.clean_settings_ui.popular_site_selected.clear();
        } else if escape_pressed {
            self.close_clean_settings_dialog();
            return;
        }

        let t = theme::tokens(self.prefs.dark);
        let busy = self.clean_settings_ui.operation != SettingsOperation::Idle;
        let editable = !busy
            && self.clean_settings_ui.draft.is_some()
            && self.clean_settings_ui.draft_cookie_domains.is_some();
        let width = (ctx.content_rect().width() - 100.).clamp(300., 760.);
        let mut close = false;
        let mut retry = false;

        let response = egui::Modal::new(egui::Id::new("custom-clean-settings"))
            .frame(theme::dialog_frame(t))
            .show(ctx, |ui| {
                ui.set_width(width);
                let content_top = ui.cursor().top();
                ui.horizontal(|ui| {
                    ui.heading(if self.clean_settings_ui.cookies_only { "Cookie settings" } else { "Custom Clean settings" });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        close = theme::close_button(ui, "Close settings", !busy);
                    });
                });
                ui.add_space(4.);
                theme::muted(
                    ui,
                    if self.clean_settings_ui.cookies_only { "Choose websites whose cookies you want to keep." } else { "Committed changes are saved automatically. These settings do not run cleanup." },
                    t,
                );
                if self.qa_fixture_mode() {
                    ui.add_space(4.);
                    theme::muted(
                        ui,
                        "QA fixture — changes stay in memory; no settings file is read or written.",
                        t,
                    );
                }
                ui.add_space(12.);

                if self.clean_settings_ui.operation == SettingsOperation::Loading {
                    theme::muted(ui, "Reading saved settings…", t);
                } else if self.clean_settings_ui.operation == SettingsOperation::Saving {
                    theme::muted(ui, "Saving settings…", t);
                }

                if let Some(error) = &self.clean_settings_ui.load_error {
                    ui.colored_label(t.attention, "One or both saved settings files could not be read.");
                    ui.add(egui::Label::new(RichText::new(error).size(theme::FONT_CAPTION).color(t.muted)).wrap());
                    theme::muted(
                        ui,
                        "Correct the unreadable settings file before saving. No changes can be saved until both settings files load successfully.",
                        t,
                    );
                    retry = theme::field_action(
                        ui,
                        "Retry",
                        !busy && !self.qa_fixture_mode(),
                    );
                } else if self.clean_settings_ui.draft.is_some() {
                    if !self.clean_settings_ui.cookies_only { self.clean_settings_tabs(ui, t, editable); }
                    ui.add_space(8.);
                    let body_height = (ctx.content_rect().height()
                        - (ui.cursor().top() - content_top)
                        - 48. - 48. - 32.).max(96.);
                    theme::scroll_vertical()
                        .id_salt("custom-clean-settings-body")
                        .max_height(body_height)
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            match self.clean_settings_ui.tab {
                                SettingsTab::Cookies => self.cookie_settings_editor(ui, t, editable),
                                SettingsTab::FilesToClean => {
                                    self.inclusions_editor(ui, t, editable);
                                    ui.add_space(12.);
                                    ui.separator();
                                    ui.add_space(8.);
                                    self.files_to_clean_editor(ui, t, editable);
                                }
                                SettingsTab::FilesToIgnore => self.exclusions_editor(ui, t, editable),
                                SettingsTab::DeletingFiles => self.deleting_files_editor(ui, t, editable),
                                SettingsTab::Advanced => self.advanced_editor(ui, t, editable),
                            }
                        });
                }

                if let Some(error) = &self.clean_settings_ui.form_error {
                    ui.add_space(6.);
                    ui.colored_label(t.attention, error);
                }
                if let Some(error) = &self.clean_settings_ui.save_error {
                    ui.add_space(6.);
                    ui.colored_label(t.attention, error);
                }

                if self.clean_settings_ui.save_error.is_some() {
                    retry |= theme::field_action(ui, "Reload saved settings", !busy && !self.qa_fixture_mode());
                }
            });

        if retry {
            self.clean_settings_ui.load_error = None;
            self.start_clean_settings_load(ctx);
        } else if close
            || (response.should_close()
                && !busy
                && !escape_cancelled_popular_sites
                && !self.clean_settings_ui.popular_sites_open)
        {
            if self.clean_settings_changed()
                && self.clean_settings_ui.save_error.is_none()
                && self.clean_settings_ui.form_error.is_none()
            {
                self.clean_settings_ui.close_after_save = true;
            } else {
                self.close_clean_settings_dialog();
            }
        }

        if self.clean_settings_ui.open && self.clean_settings_ui.popular_sites_open {
            self.popular_cookie_sites_dialog(ctx, t);
        }
        self.save_committed_clean_settings(ctx);
    }

    pub(super) fn clean_settings_event(&mut self, event: CleanSettingsEvent) {
        match event {
            CleanSettingsEvent::Loaded { settings, cookies } => {
                self.worker = None;
                self.clean_settings_ui.operation = SettingsOperation::Idle;
                let mut errors = Vec::new();
                match settings {
                    Ok(settings) => {
                        self.clean_settings_ui.saved = Some(settings.clone());
                        self.clean_settings_ui.draft = Some(settings);
                    }
                    Err(error) => {
                        self.clean_settings_ui.saved = None;
                        self.clean_settings_ui.draft = None;
                        errors.push(format!("Custom Clean settings: {error}"));
                    }
                }
                match cookies {
                    Ok(cookies) => {
                        self.clean_settings_ui.draft_cookie_domains =
                            Some(cookies.keep_domains.clone());
                        self.clean_settings_ui.saved_cookies = Some(cookies.clone());
                        self.sync_cookie_settings_owners(cookies);
                    }
                    Err(error) => {
                        self.clean_settings_ui.saved_cookies = None;
                        self.clean_settings_ui.draft_cookie_domains = None;
                        self.mark_cookie_settings_unverified();
                        errors.push(format!("Cookie exceptions: {error}"));
                    }
                }
                self.clean_settings_ui.load_error = (!errors.is_empty()).then(|| errors.join("\n"));
                self.clean_settings_ui.save_error = None;
            }
            CleanSettingsEvent::Saved { settings, cookies } => {
                self.worker = None;
                self.clean_settings_ui.operation = SettingsOperation::Idle;
                let mut errors = Vec::new();
                let cookie_write_uncertain = matches!(&cookies, Some(Err(_)));
                match settings {
                    Ok(settings) => {
                        self.clean_settings_ui.saved = Some(settings.clone());
                        self.clean_settings_ui.draft = Some(settings);
                    }
                    Err(error) => {
                        errors.push(format!("Custom Clean settings were not saved: {error}"))
                    }
                }
                match cookies {
                    Some(Ok(cookies)) => {
                        self.clean_settings_ui.saved_cookies = Some(cookies.clone());
                        self.clean_settings_ui.draft_cookie_domains = Some(cookies.keep_domains.clone());
                        self.sync_cookie_settings_owners(cookies);
                    }
                    Some(Err(error)) => errors.push(format!("Cookie exceptions were not saved: {error}")),
                    None => errors.push("Cookie exceptions were not attempted because Custom Clean settings could not be saved.".into()),
                }
                if cookie_write_uncertain {
                    self.mark_cookie_settings_unverified();
                }
                if errors.is_empty() {
                    self.clean_settings_ui.save_error = None;
                    self.clean_settings_ui.open = !self.clean_settings_ui.close_after_save;
                    self.clean_settings_ui.close_after_save = false;
                    self.invalidate();
                    self.custom_analysis = None;
                    self.notice = None;
                } else {
                    self.clean_settings_ui.save_error = Some(format!(
                        "{} The settings files are saved separately, so a write that returned an error may still have committed. Reload the saved settings before making another change. The panel remains open.",
                        errors.join(" ")
                    ));
                    if self.clean_settings_ui.saved.is_some() {
                        self.invalidate();
                        self.custom_analysis = None;
                    }
                }
            }
        }
    }

    fn start_clean_settings_load(&mut self, ctx: &egui::Context) {
        if self.qa_fixture_mode()
            || self.clean_settings_ui.operation != SettingsOperation::Idle
            || self.busy()
        {
            return;
        }
        if self.data_dir.as_os_str().is_empty() {
            self.clean_settings_ui.load_error =
                Some("Application data storage is unavailable.".into());
            return;
        }
        let root = self.data_dir.clone();
        let context = ctx.clone();
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        self.clean_settings_ui.operation = SettingsOperation::Loading;
        thread::spawn(move || {
            let settings = load_settings(&root).map_err(|error| error.to_string());
            let cookies = privacy::load_cookie_exception_settings(&root);
            let _ = sender.send(Event::CleanSettings(CleanSettingsEvent::Loaded {
                settings,
                cookies,
            }));
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
        let Some(cookie_domains) = self.clean_settings_ui.draft_cookie_domains.as_ref() else {
            return;
        };
        if let Err(error) = validate_cookie_domains(cookie_domains) {
            self.clean_settings_ui.form_error = Some(error);
            return;
        }
        if self.clean_settings_ui.operation != SettingsOperation::Idle || self.busy() {
            return;
        }
        if self.data_dir.as_os_str().is_empty() {
            self.clean_settings_ui.form_error =
                Some("Application data storage is unavailable; settings were not saved.".into());
            return;
        }
        let settings = settings.clone();
        let cookie_domains = cookie_domains.clone();
        let Some(saved_settings) = self.clean_settings_ui.saved.clone() else {
            return;
        };
        let Some(saved_cookies) = self.clean_settings_ui.saved_cookies.clone() else {
            return;
        };
        let settings_changed = settings != saved_settings;
        let cookies_changed = cookie_domains != saved_cookies.keep_domains;
        if self.qa_fixture_mode() {
            self.clean_settings_event(CleanSettingsEvent::Saved {
                settings: Ok(settings),
                cookies: Some(Ok(CookieExceptionSettings {
                    schema: 1,
                    keep_domains: cookie_domains,
                })),
            });
            return;
        }
        let root = self.data_dir.clone();
        let context = ctx.clone();
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        self.clean_settings_ui.operation = SettingsOperation::Saving;
        self.clean_settings_ui.form_error = None;
        self.clean_settings_ui.save_error = None;
        thread::spawn(move || {
            let settings_result = if settings_changed {
                save_settings(&root, &settings)
                    .and_then(|_| load_settings(&root))
                    .map_err(|error| error.to_string())
            } else {
                Ok(saved_settings)
            };
            let cookies_result = settings_result.as_ref().ok().map(|_| {
                if cookies_changed {
                    privacy::save_cookie_exception_settings(&root, &cookie_domains)
                } else {
                    Ok(saved_cookies)
                }
            });
            let _ = sender.send(Event::CleanSettings(CleanSettingsEvent::Saved {
                settings: settings_result,
                cookies: cookies_result,
            }));
            context.request_repaint();
        });
    }

    fn close_clean_settings_dialog(&mut self) {
        self.clean_settings_ui.open = false;
        self.clean_settings_ui.close_after_save = false;
        self.clean_settings_ui.popular_sites_open = false;
        self.clean_settings_ui.popular_site_selected.clear();
        self.clean_settings_ui.draft = self.clean_settings_ui.saved.clone();
        self.clean_settings_ui.draft_cookie_domains = self
            .clean_settings_ui
            .saved_cookies
            .as_ref()
            .map(|settings| settings.keep_domains.clone());
        self.clean_settings_ui.cookie_domain_input.clear();
        self.clean_settings_ui.form_error = None;
        self.clean_settings_ui.save_error = None;
    }

    fn clean_settings_tabs(&mut self, ui: &mut egui::Ui, _t: Tokens, enabled: bool) {
        theme::tabs(ui, |ui| {
            ui.add_enabled_ui(enabled, |ui| {
                if theme::tab(
                    ui,
                    self.clean_settings_ui.tab == SettingsTab::Cookies,
                    "Cookies",
                )
                .clicked()
                {
                    self.clean_settings_ui.tab = SettingsTab::Cookies;
                }
                if theme::tab(
                    ui,
                    self.clean_settings_ui.tab == SettingsTab::FilesToClean,
                    "Files to clean",
                )
                .clicked()
                {
                    self.clean_settings_ui.tab = SettingsTab::FilesToClean;
                }
                if theme::tab(
                    ui,
                    self.clean_settings_ui.tab == SettingsTab::FilesToIgnore,
                    "Files to ignore",
                )
                .clicked()
                {
                    self.clean_settings_ui.tab = SettingsTab::FilesToIgnore;
                }
                if theme::tab(
                    ui,
                    self.clean_settings_ui.tab == SettingsTab::DeletingFiles,
                    "Deleting files",
                )
                .clicked()
                {
                    self.clean_settings_ui.tab = SettingsTab::DeletingFiles;
                }
                if theme::tab(
                    ui,
                    self.clean_settings_ui.tab == SettingsTab::Advanced,
                    "Advanced",
                )
                .clicked()
                {
                    self.clean_settings_ui.tab = SettingsTab::Advanced;
                }
            });
        });
    }

    fn cookie_settings_editor(&mut self, ui: &mut egui::Ui, t: Tokens, editable: bool) {
        ui.label(
            RichText::new("Trusted websites")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
        ui.add_space(4.);
        theme::muted(
            ui,
            "Domains here are kept out of browser-cookie cleanup in Privacy and Health. Only domain names are stored; cookie contents are never read here.",
            t,
        );
        ui.add_space(4.);
        theme::muted(ui, "Bookmark import is unavailable in this build.", t);
        if theme::field_action(ui, "Add popular websites", editable) {
            let domains = self
                .clean_settings_ui
                .draft_cookie_domains
                .as_deref()
                .unwrap_or_default();
            self.clean_settings_ui.popular_site_selected = popular_cookie_site_defaults(domains);
            self.clean_settings_ui.popular_sites_open = true;
            self.clean_settings_ui.form_error = None;
        }
        ui.add_space(8.);
        theme::muted(ui, "Add another website", t);
        ui.horizontal(|ui| {
            let width = (ui.available_width() - 112.).max(100.);
            theme::input(
                ui,
                &mut self.clean_settings_ui.cookie_domain_input,
                width,
                "example.com",
                editable,
            );
            if theme::field_action(ui, "Allow", editable) {
                self.add_cookie_exception();
            }
        });

        ui.add_space(12.);
        ui.separator();
        ui.add_space(8.);
        ui.label(
            RichText::new("Trusted sites")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
        let Some(domains) = self.clean_settings_ui.draft_cookie_domains.as_mut() else {
            return;
        };
        if domains.is_empty() {
            theme::muted(ui, "No trusted website domains are saved.", t);
            return;
        }
        let mut remove = None;
        for (index, domain) in domains.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.add(egui::Label::new(RichText::new(domain).strong()).truncate())
                    .on_hover_text(domain);
                if theme::field_action(ui, "Delete", editable) {
                    remove = Some(index);
                }
            });
            ui.separator();
        }
        if let Some(index) = remove {
            if index < domains.len() {
                domains.remove(index);
            }
        }
    }

    fn add_cookie_exception(&mut self) {
        let normalized =
            match privacy::normalize_cookie_domain(&self.clean_settings_ui.cookie_domain_input) {
                Ok(domain) => domain,
                Err(error) => {
                    self.clean_settings_ui.form_error = Some(error);
                    return;
                }
            };
        let Some(domains) = self.clean_settings_ui.draft_cookie_domains.as_mut() else {
            return;
        };
        if domains.iter().any(|domain| domain == &normalized) {
            self.clean_settings_ui.form_error = Some("That website is already trusted.".into());
            return;
        }
        if domains.len() >= 256 {
            self.clean_settings_ui.form_error =
                Some("Keep at most 256 trusted website domains.".into());
            return;
        }
        domains.push(normalized);
        self.clean_settings_ui.cookie_domain_input.clear();
        self.clean_settings_ui.form_error = None;
    }

    fn popular_cookie_sites_dialog(&mut self, ctx: &egui::Context, t: Tokens) {
        let width = (ctx.content_rect().width() - 100.).clamp(300., 480.);
        let mut cancel = false;
        let mut allow = false;
        let response = egui::Modal::new(egui::Id::new("custom-clean-popular-sites"))
            .frame(theme::dialog_frame(t))
            .show(ctx, |ui| {
                ui.set_width(width);
                ui.label(
                    RichText::new("Add popular websites")
                        .family(theme::semibold())
                        .size(theme::FONT_TITLE),
                );
                ui.add_space(4.);
                theme::muted(
                    ui,
                    "Choose websites whose cookies should be kept during browser-cookie cleanup.",
                    t,
                );
                ui.add_space(8.);

                let max_height = (ctx.content_rect().height() - 250.).clamp(120., 400.);
                theme::scroll_vertical()
                    .id_salt("custom-clean-popular-sites-list")
                    .max_height(max_height)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        for (index, domain) in POPULAR_COOKIE_DOMAINS.iter().enumerate() {
                            let already_added = self
                                .clean_settings_ui
                                .draft_cookie_domains
                                .as_ref()
                                .is_some_and(|domains| {
                                    domains
                                        .iter()
                                        .any(|saved| saved.eq_ignore_ascii_case(domain))
                                });
                            if let Some(selected) =
                                self.clean_settings_ui.popular_site_selected.get_mut(index)
                            {
                                ui.horizontal(|ui| {
                                    theme::checkbox(ui, selected, *domain, !already_added);
                                    if already_added {
                                        theme::muted(ui, "Already added", t);
                                    }
                                });
                            }
                        }
                    });

                if let Some(error) = &self.clean_settings_ui.form_error {
                    ui.add_space(4.);
                    ui.colored_label(t.attention, error);
                }

                ui.add_space(8.);
                ui.separator();
                ui.add_space(8.);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    allow = theme::primary(ui, "Allow", t, true);
                    cancel = theme::secondary(ui, "Cancel", true);
                });
            });

        if allow {
            if self.add_selected_popular_cookie_sites() {
                self.clean_settings_ui.popular_sites_open = false;
                self.clean_settings_ui.popular_site_selected.clear();
            }
        } else if cancel || response.should_close() {
            self.clean_settings_ui.popular_sites_open = false;
            self.clean_settings_ui.popular_site_selected.clear();
        }
    }

    /// Apply selected entries atomically to the in-memory keep-domain draft.
    /// The enclosing editor persists committed changes; Cancel leaves this list unchanged.
    fn add_selected_popular_cookie_sites(&mut self) -> bool {
        let Some(domains) = self.clean_settings_ui.draft_cookie_domains.as_mut() else {
            self.clean_settings_ui.form_error =
                Some("Cookie settings are unavailable; no websites were added.".into());
            return false;
        };
        if let Err(error) = validate_cookie_domains(domains) {
            self.clean_settings_ui.form_error = Some(error);
            return false;
        }

        let mut normalized_existing = Vec::with_capacity(domains.len());
        for domain in domains.iter() {
            match privacy::normalize_cookie_domain(domain) {
                Ok(domain) => normalized_existing.push(domain),
                Err(error) => {
                    self.clean_settings_ui.form_error = Some(error);
                    return false;
                }
            }
        }

        let mut additions = Vec::new();
        for (index, domain) in POPULAR_COOKIE_DOMAINS.iter().enumerate() {
            if !self
                .clean_settings_ui
                .popular_site_selected
                .get(index)
                .copied()
                .unwrap_or(false)
            {
                continue;
            }
            let normalized = match privacy::normalize_cookie_domain(domain) {
                Ok(domain) => domain,
                Err(error) => {
                    self.clean_settings_ui.form_error = Some(error);
                    return false;
                }
            };
            if normalized_existing.iter().any(|saved| saved == &normalized)
                || additions.iter().any(|saved| saved == &normalized)
            {
                continue;
            }
            additions.push(normalized);
        }

        if domains.len().saturating_add(additions.len()) > 256 {
            self.clean_settings_ui.form_error =
                Some("Keep at most 256 trusted website domains.".into());
            return false;
        }
        let added = additions.len();
        domains.extend(additions);
        self.clean_settings_ui.form_error = Some(if added == 0 {
            "No new websites were added.".into()
        } else {
            format!("Added {added} websites.")
        });
        true
    }

    fn inclusions_editor(&mut self, ui: &mut egui::Ui, t: Tokens, editable: bool) {
        ui.label(
            RichText::new("Add a location")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
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
                    if theme::choice(ui, selected_kind == "File", "File").clicked() {
                        kind_changed = Some(InclusionKind::File);
                    }
                    if theme::choice(ui, selected_kind == "Folder", "Folder").clicked() {
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
        ui.label(
            RichText::new("Included locations")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
        let Some(draft) = self.clean_settings_ui.draft.as_mut() else {
            return;
        };
        if draft.inclusions.is_empty() {
            theme::muted(ui, "No custom file or folder locations are saved.", t);
        }
        let mut remove = None;
        let mut edit = None;
        for (index, rule) in draft.inclusions.iter().enumerate() {
            ui.add_space(6.);
            ui.horizontal(|ui| {
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
        ui.label(
            RichText::new("Protect paths and data")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
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
                        if theme::choice(ui, selected_type == label, label).clicked() {
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
        ui.label(
            RichText::new("Protected entries")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
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
                            ui.label(
                                RichText::new("Stored only")
                                    .size(theme::FONT_CAPTION)
                                    .color(t.attention),
                            );
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

    fn files_to_clean_editor(&mut self, ui: &mut egui::Ui, t: Tokens, editable: bool) {
        ui.label(
            RichText::new("Custom file and folder rules")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
        ui.add_space(6.);
        let Some(draft) = self.clean_settings_ui.draft.as_mut() else {
            return;
        };
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
                RichText::new("The choices below are saved, but scanning remains off until custom locations are enabled.")
                    .size(theme::FONT_CAPTION)
                    .color(t.muted),
            );
        }
        ui.add_space(12.);
        ui.separator();
        ui.add_space(8.);
        ui.label(
            RichText::new("Location rule choices")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
        if draft.inclusions.is_empty() {
            theme::muted(
                ui,
                "Add a file or folder on this tab to configure its rule.",
                t,
            );
        }
        let mut selection_changes = Vec::new();
        for rule in &draft.inclusions {
            ui.horizontal(|ui| {
                let id = rule_id_for_inclusion(rule);
                let mut enabled = draft.rule_selection(&id).unwrap_or(true);
                if theme::checkbox(ui, &mut enabled, "", editable).changed() {
                    selection_changes.push((id, enabled));
                }
                ui.vertical(|ui| {
                    let location = inclusion_location(rule);
                    ui.add(egui::Label::new(&location).truncate())
                        .on_hover_text(location);
                    let age = rule.age_threshold_hours.map_or_else(
                        || "No age filter".to_owned(),
                        |hours| format!("At least {hours} hours old"),
                    );
                    theme::muted(ui, age, t);
                });
            });
            ui.separator();
        }
        for (id, enabled) in selection_changes {
            let _ = draft.set_rule_selection(&id, Some(enabled));
        }
    }

    fn deleting_files_editor(&mut self, ui: &mut egui::Ui, t: Tokens, editable: bool) {
        ui.label(
            RichText::new("Windows temporary folders")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
        ui.add_space(4.);
        let Some(draft) = self.clean_settings_ui.draft.as_mut() else {
            return;
        };
        theme::checkbox(
            ui,
            &mut draft.file_deletion.temp_folders_only_older_than_24h,
            "Only include temporary files older than 24 hours",
            editable,
        );
        theme::muted(
            ui,
            "Applied by the current scanner to its supported temporary-file rules.",
            t,
        );
        ui.add_space(16.);
        ui.label(
            RichText::new("Recycle Bin")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
        ui.add_space(4.);
        theme::checkbox(
            ui,
            &mut draft.file_deletion.recycle_bin_only_older_than_24h,
            "Only include Recycle Bin items older than 24 hours",
            editable,
        );
        ui.label(
            RichText::new(
                "Stored only · the current Recycle Bin view does not consume this preference.",
            )
            .size(theme::FONT_CAPTION)
            .color(t.attention),
        );
    }

    fn advanced_editor(&mut self, ui: &mut egui::Ui, t: Tokens, editable: bool) {
        ui.label(
            RichText::new("File deletion")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
        ui.add_space(4.);
        theme::muted(
            ui,
            "These choices are saved preferences. Current cleanup uses its reviewed Recycle Bin flow and does not perform secure deletion or drive wiping.",
            t,
        );
        ui.add_space(10.);
        let CleanSettingsUi {
            draft,
            drive_letter,
            form_error,
            skipped_rule_id,
            ..
        } = &mut self.clean_settings_ui;
        let Some(draft) = draft.as_mut() else {
            return;
        };
        Self::advanced_options(ui, t, editable, draft, drive_letter, form_error);

        ui.add_space(14.);
        ui.separator();
        ui.add_space(8.);
        ui.label(
            RichText::new("Additional preferences")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
        theme::muted(
            ui,
            "Skipped close-process rules are preserved for compatibility. Custom Clean does not close running applications.",
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
                        if theme::choice(ui, selected_deletion == "Normal", "Normal").clicked() {
                            new_deletion = Some(FileDeletionMode::Normal);
                        }
                        if theme::choice(ui, selected_deletion == "Secure", "Secure").clicked() {
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
                            if theme::choice(ui, selected_overwrite == label, label).clicked() {
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
        ui.label(
            RichText::new("Per-drive MFT preferences")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
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

    #[cfg(debug_assertions)]
    pub(super) fn seed_clean_settings_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Custom Clean settings QA fixtures require isolated fixture mode.".into());
        }
        let tab = match case {
            "clean-settings-cookies" | "clean-settings-popular-sites" => SettingsTab::Cookies,
            "clean-settings-files-to-clean"
            | "clean-settings-inclusions"
            | "clean-settings-rules" => SettingsTab::FilesToClean,
            "clean-settings-files-to-ignore" | "clean-settings-exclusions" => {
                SettingsTab::FilesToIgnore
            }
            "clean-settings-deleting-files" => SettingsTab::DeletingFiles,
            "clean-settings-advanced" | "clean-settings-deletion" => SettingsTab::Advanced,
            _ => return Err(format!("Unsupported Custom Clean settings fixture: {case}")),
        };
        let mut settings = CustomCleanSettings::default();
        let inclusion = InclusionRule {
            location: InclusionLocation::Folder(FolderInclusion {
                folder: r"C:\__dcleaner_qa_fixture__\included".into(),
                filter: Some(vec!["*.tmp".into(), "*.cache".into()]),
                delete_self: false,
                recursive: true,
            }),
            age_threshold_hours: Some(24.0),
        };
        let inclusion_id = rule_id_for_inclusion(&inclusion);
        settings.inclusions.push(inclusion);
        settings.exclusions = vec![
            ExclusionRule {
                exclusion_type: ExclusionType::File,
                path: r"C:\__dcleaner_qa_fixture__\included\keep.tmp".into(),
            },
            ExclusionRule {
                exclusion_type: ExclusionType::Path,
                path: r"C:\__dcleaner_qa_fixture__\included\protected".into(),
            },
            ExclusionRule {
                exclusion_type: ExclusionType::RegistryKey,
                path: r"HKCU\Software\DCleanerFixture".into(),
            },
            ExclusionRule {
                exclusion_type: ExclusionType::Cookie,
                path: "example.invalid".into(),
            },
        ];
        settings.file_deletion.temp_folders_only_older_than_24h = true;
        settings.file_deletion.recycle_bin_only_older_than_24h = true;
        settings.advanced_filter_options.file_deletion = FileDeletionMode::Secure;
        settings.advanced_filter_options.overwrite_type = OverwriteType::SevenPass;
        settings.advanced_filter_options.wipe_free_space = true;
        settings.advanced_filter_options.wipe_alternate_data_streams = true;
        settings
            .advanced_filter_options
            .wipe_free_space_drives
            .push(WipeDrivePreference {
                drive: "C".into(),
                wipe_mft_free_space: true,
            });
        settings.skipped_close_programs = vec!["fixture.example-process".into()];
        settings.skip_show_registry_attention = true;
        settings.shutdown_after_cleaning = true;
        settings
            .set_rule_selection(".custom", Some(true))
            .map_err(|error| error.to_string())?;
        settings
            .set_rule_selection(&inclusion_id, Some(true))
            .map_err(|error| error.to_string())?;
        settings
            .validate()
            .map_err(|error| format!("Synthetic settings fixture is invalid: {error}"))?;

        self.page = super::Page::Clean;
        self.clean_browser = false;
        self.clean_bin = false;
        let mut state = CleanSettingsUi::default();
        state.saved = Some(settings.clone());
        state.draft = Some(settings);
        let cookies = CookieExceptionSettings {
            schema: 1,
            keep_domains: if case == "clean-settings-popular-sites" {
                DEFAULT_COOKIE_KEEP_DOMAINS
                    .iter()
                    .map(|domain| (*domain).to_owned())
                    .collect()
            } else {
                vec!["example.test".into(), "docs.example.test".into()]
            },
        };
        state.saved_cookies = Some(cookies.clone());
        state.draft_cookie_domains = Some(cookies.keep_domains.clone());
        state.tab = tab;
        state.open = true;
        if case == "clean-settings-popular-sites" {
            state.popular_site_selected = popular_cookie_site_defaults(&cookies.keep_domains);
            state.popular_sites_open = true;
        }
        self.clean_settings_ui = state;
        self.custom_analysis = None;
        self.analysis = None;
        self.selected.clear();
        self.error = None;
        self.notice = None;
        Ok(())
    }
}

fn validate_cookie_domains(domains: &[String]) -> Result<(), String> {
    if domains.len() > 256 {
        return Err("Keep at most 256 trusted website domains.".into());
    }
    for domain in domains {
        privacy::normalize_cookie_domain(domain)?;
    }
    Ok(())
}

fn popular_cookie_site_defaults(_domains: &[String]) -> Vec<bool> {
    vec![true; POPULAR_COOKIE_DOMAINS.len()]
}

#[cfg(test)]
mod draft_tests {
    #[cfg(debug_assertions)]
    use super::super::view_privacy::PrivacyEvent;
    use super::*;

    fn fixture() -> App {
        App::new_fixture_with_context(&egui::Context::default(), "clean-settings-cookies").unwrap()
    }

    #[test]
    fn committed_cookie_change_autosaves_in_memory_and_survives_close() {
        let mut app = fixture();
        app.clean_settings_ui
            .draft_cookie_domains
            .as_mut()
            .unwrap()
            .push("committed.example".into());
        app.save_committed_clean_settings(&egui::Context::default());
        assert!(app.clean_settings_ui.open);
        assert!(
            app.clean_settings_ui
                .saved_cookies
                .as_ref()
                .unwrap()
                .keep_domains
                .iter()
                .any(|domain| domain == "committed.example")
        );
        app.close_clean_settings_dialog();
        assert!(
            app.clean_settings_ui
                .draft_cookie_domains
                .as_ref()
                .unwrap()
                .iter()
                .any(|domain| domain == "committed.example")
        );
        assert!(app.worker.is_none());
    }

    #[test]
    fn nested_picker_cancel_does_not_commit_and_failed_save_does_not_retry() {
        let mut app = fixture();
        let before = app.clean_settings_ui.saved_cookies.clone();
        app.clean_settings_ui.popular_sites_open = true;
        app.clean_settings_ui.popular_site_selected = vec![true; POPULAR_COOKIE_DOMAINS.len()];
        app.save_committed_clean_settings(&egui::Context::default());
        assert_eq!(app.clean_settings_ui.saved_cookies, before);
        app.clean_settings_ui.popular_sites_open = false;
        app.clean_settings_ui.popular_site_selected.clear();
        app.clean_settings_ui
            .draft_cookie_domains
            .as_mut()
            .unwrap()
            .push("pending.example".into());
        app.clean_settings_ui.save_error = Some("uncertain fixture write".into());
        app.save_committed_clean_settings(&egui::Context::default());
        assert_eq!(app.clean_settings_ui.saved_cookies, before);
        assert!(app.clean_settings_changed());
        assert!(app.worker.is_none());
    }

    #[test]
    fn health_cookie_settings_uses_the_shared_cookie_only_editor() {
        let mut app = fixture();
        app.open_health_cookie_settings(&egui::Context::default());
        assert!(app.clean_settings_ui.open);
        assert!(app.clean_settings_ui.cookies_only);
        assert_eq!(app.clean_settings_ui.tab, SettingsTab::Cookies);
    }

    #[test]
    fn popular_site_defaults_match_shipped_suggestions_including_locked_existing_domains() {
        let defaults = popular_cookie_site_defaults(&["GOOGLE.COM".into()]);
        assert_eq!(POPULAR_COOKIE_DOMAINS.len(), 27);
        assert!(defaults.into_iter().all(|selected| selected));
        assert_eq!(
            &POPULAR_COOKIE_DOMAINS[24..],
            &["wikipedia.org", "twitch.tv", "zoom.us"]
        );
    }

    #[test]
    fn popular_site_allow_changes_only_the_unsaved_draft() {
        let mut app = fixture();
        let saved = app.clean_settings_ui.saved_cookies.clone();
        let original = app.clean_settings_ui.draft_cookie_domains.clone().unwrap();
        app.clean_settings_ui.popular_site_selected = popular_cookie_site_defaults(&original);
        assert!(app.add_selected_popular_cookie_sites());
        let draft = app.clean_settings_ui.draft_cookie_domains.as_ref().unwrap();
        assert!(
            POPULAR_COOKIE_DOMAINS
                .iter()
                .all(|domain| draft.iter().any(|kept| kept == domain))
        );
        assert_eq!(app.clean_settings_ui.saved_cookies, saved);
        app.close_clean_settings_dialog();
        assert_eq!(app.clean_settings_ui.draft_cookie_domains, Some(original));
    }

    #[test]
    fn popular_site_limit_rejects_the_entire_addition() {
        let mut app = fixture();
        let original: Vec<_> = (0..256)
            .map(|index| format!("site-{index}.example"))
            .collect();
        app.clean_settings_ui.draft_cookie_domains = Some(original.clone());
        app.clean_settings_ui.popular_site_selected = vec![true; POPULAR_COOKIE_DOMAINS.len()];
        assert!(!app.add_selected_popular_cookie_sites());
        assert_eq!(app.clean_settings_ui.draft_cookie_domains, Some(original));
    }

    #[cfg(debug_assertions)]
    fn seed_cookie_consumers(app: &mut App) {
        app.seed_privacy_qa("privacy-populated").unwrap();
        app.seed_health_qa("health-privacy").unwrap();
    }

    #[cfg(debug_assertions)]
    fn changed_cookie_settings() -> CookieExceptionSettings {
        CookieExceptionSettings {
            schema: 1,
            keep_domains: vec!["protected.example".into()],
        }
    }

    #[test]
    fn closing_restores_only_uncommitted_drafts() {
        let mut app = fixture();
        let saved = app.clean_settings_ui.saved.clone();
        let cookies = app.clean_settings_ui.saved_cookies.clone().unwrap();
        app.clean_settings_ui
            .draft
            .as_mut()
            .unwrap()
            .shutdown_after_cleaning = false;
        app.clean_settings_ui
            .draft_cookie_domains
            .as_mut()
            .unwrap()
            .push("unsaved.example".into());
        app.close_clean_settings_dialog();
        assert!(!app.clean_settings_ui.open);
        assert_eq!(app.clean_settings_ui.draft, saved);
        assert_eq!(
            app.clean_settings_ui.draft_cookie_domains,
            Some(cookies.keep_domains)
        );
    }

    #[test]
    fn partial_save_keeps_cookie_edits_and_requires_verified_reload() {
        let mut app = fixture();
        app.notice = None;
        let saved_cookies = app
            .clean_settings_ui
            .saved_cookies
            .clone()
            .unwrap()
            .keep_domains;
        app.clean_settings_ui
            .draft_cookie_domains
            .as_mut()
            .unwrap()
            .push("pending.example".into());
        let saved_settings = app.clean_settings_ui.draft.clone().unwrap();
        app.clean_settings_event(CleanSettingsEvent::Saved {
            settings: Ok(saved_settings.clone()),
            cookies: Some(Err("fixture cookie write failure".into())),
        });
        assert!(app.clean_settings_ui.open);
        assert_eq!(app.clean_settings_ui.saved, Some(saved_settings));
        assert_eq!(
            app.clean_settings_ui
                .saved_cookies
                .as_ref()
                .unwrap()
                .keep_domains,
            saved_cookies
        );
        assert!(
            app.clean_settings_ui
                .draft_cookie_domains
                .as_ref()
                .unwrap()
                .iter()
                .any(|domain| domain == "pending.example")
        );
        assert!(
            app.clean_settings_ui
                .save_error
                .as_ref()
                .unwrap()
                .contains("Reload the saved settings")
        );
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|notice| notice.contains("Reload the saved rules"))
        );
    }

    #[test]
    fn automatic_save_keeps_the_editor_open_after_both_stores_report_success() {
        let mut app = fixture();
        let settings = app.clean_settings_ui.draft.clone().unwrap();
        let cookies = CookieExceptionSettings {
            schema: 1,
            keep_domains: vec!["saved.example".into()],
        };
        app.clean_settings_event(CleanSettingsEvent::Saved {
            settings: Ok(settings),
            cookies: Some(Ok(cookies)),
        });
        assert!(app.clean_settings_ui.open);
        assert!(app.clean_settings_ui.save_error.is_none());
        assert_eq!(
            app.clean_settings_ui
                .saved_cookies
                .as_ref()
                .unwrap()
                .keep_domains,
            ["saved.example"]
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn privacy_save_syncs_health_and_invalidates_both_old_snapshots() {
        let mut app = fixture();
        seed_cookie_consumers(&mut app);
        assert!(app.privacy_cookie_test_state().2);
        assert!(app.health_cookie_test_state().3);

        let settings = changed_cookie_settings();
        app.privacy_event(PrivacyEvent::SettingsSaved(Ok(settings.clone())));

        let privacy = app.privacy_cookie_test_state();
        let health = app.health_cookie_test_state();
        assert_eq!(privacy.0, settings);
        assert!(privacy.1);
        assert!(!privacy.2);
        assert_eq!(health.0, settings);
        assert!(health.1);
        assert!(health.2);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn health_save_syncs_privacy_and_invalidates_both_old_snapshots() {
        let mut app = fixture();
        seed_cookie_consumers(&mut app);
        assert!(app.privacy_cookie_test_state().2);
        assert!(app.health_cookie_test_state().3);

        let settings = changed_cookie_settings();
        app.clean_settings_event(CleanSettingsEvent::Saved {
            settings: Ok(app.clean_settings_ui.saved.clone().unwrap()),
            cookies: Some(Ok(settings.clone())),
        });

        let privacy = app.privacy_cookie_test_state();
        let health = app.health_cookie_test_state();
        assert_eq!(privacy.0, settings);
        assert!(!privacy.2);
        assert_eq!(health.0, settings);
        assert!(health.2);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn ambiguous_cookie_save_failure_blocks_consumers_and_preserves_custom_draft() {
        let mut app = fixture();
        seed_cookie_consumers(&mut app);
        app.clean_settings_ui.draft_cookie_domains = Some(vec!["pending.example".into()]);
        let settings = app.clean_settings_ui.saved.clone().unwrap();

        app.clean_settings_event(CleanSettingsEvent::Saved {
            settings: Ok(settings),
            cookies: Some(Err("fixture post-rename sync failure".into())),
        });

        let privacy = app.privacy_cookie_test_state();
        let health = app.health_cookie_test_state();
        assert!(!privacy.1);
        assert!(!privacy.2);
        assert!(!health.1);
        assert!(health.2);
        assert!(health.3);
        assert_eq!(
            app.clean_settings_ui.draft_cookie_domains,
            Some(vec!["pending.example".into()])
        );
        assert!(app.clean_settings_ui.open);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn failed_owner_save_invalidates_other_view_and_requires_verified_reload() {
        let mut app = fixture();
        seed_cookie_consumers(&mut app);

        app.privacy_event(PrivacyEvent::SettingsSaved(Err(
            "fixture post-rename sync failure".into(),
        )));

        let privacy = app.privacy_cookie_test_state();
        let health = app.health_cookie_test_state();
        assert!(!privacy.1);
        assert!(!privacy.2);
        assert!(!health.1);
        assert!(health.2);

        let mut health_app = fixture();
        seed_cookie_consumers(&mut health_app);
        health_app.clean_settings_event(CleanSettingsEvent::Saved {
            settings: Ok(health_app.clean_settings_ui.saved.clone().unwrap()),
            cookies: Some(Err("fixture post-rename sync failure".into())),
        });
        let privacy = health_app.privacy_cookie_test_state();
        let health = health_app.health_cookie_test_state();
        assert!(!privacy.1);
        assert!(!privacy.2);
        assert!(!health.1);
        assert!(health.2);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn unreadable_cookie_load_blocks_both_consumers_until_verified_reload() {
        let mut app = fixture();
        seed_cookie_consumers(&mut app);

        app.clean_settings_event(CleanSettingsEvent::Loaded {
            settings: Ok(CustomCleanSettings::default()),
            cookies: Err("fixture corrupt cookie file".into()),
        });
        let privacy = app.privacy_cookie_test_state();
        let health = app.health_cookie_test_state();
        assert!(!privacy.1);
        assert!(!privacy.2);
        assert!(!health.1);
        assert!(health.2);

        let verified = changed_cookie_settings();
        app.clean_settings_event(CleanSettingsEvent::Loaded {
            settings: Ok(CustomCleanSettings::default()),
            cookies: Ok(verified.clone()),
        });
        let privacy = app.privacy_cookie_test_state();
        let health = app.health_cookie_test_state();
        assert_eq!(privacy.0, verified);
        assert!(privacy.1);
        assert!(!privacy.2);
        assert_eq!(health.0, verified);
        assert!(health.1);
        assert!(health.2);
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
