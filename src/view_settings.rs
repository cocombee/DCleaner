use super::*;
use dcleaner::domain::{AppearanceMode, LandingPage};
use reqwest::blocking::Client;
use serde::Deserialize;
use std::{io::Read, time::Duration};

const LATEST_RELEASE_URL: &str = "https://api.github.com/repos/cocombee/DCleaner/releases/latest";
const MAX_RELEASE_RESPONSE_BYTES: u64 = 64 * 1024;
const MAX_RELEASE_TAG_CHARS: usize = 128;
const MAX_RELEASE_NAME_CHARS: usize = 256;

#[derive(Default)]
pub(super) struct SettingsUi {
    update_check: UpdateCheckState,
    check_request_pending: bool,
}

impl SettingsUi {
    pub(super) fn is_checking(&self) -> bool {
        matches!(&self.update_check, UpdateCheckState::Checking)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum UpdateCheckState {
    #[default]
    Idle,
    Checking,
    NoPublishedRelease,
    Published(PublishedRelease),
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum LatestRelease {
    NoPublishedRelease,
    Published(PublishedRelease),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PublishedRelease {
    tag: String,
    name: Option<String>,
    current_version: Option<String>,
    update_available: Option<bool>,
    matches_installed_version: Option<bool>,
}

pub(super) enum SettingsEvent {
    ReleaseChecked(Result<LatestRelease, String>),
}

pub(super) fn begin_check(ui: &mut SettingsUi) -> bool {
    if matches!(&ui.update_check, UpdateCheckState::Checking) {
        return false;
    }
    ui.update_check = UpdateCheckState::Checking;
    ui.check_request_pending = true;
    true
}

pub(super) fn take_check_request(ui: &mut SettingsUi) -> bool {
    std::mem::take(&mut ui.check_request_pending)
}

pub(super) fn handle_event(ui: &mut SettingsUi, event: SettingsEvent) {
    ui.check_request_pending = false;
    match event {
        SettingsEvent::ReleaseChecked(Ok(LatestRelease::NoPublishedRelease)) => {
            ui.update_check = UpdateCheckState::NoPublishedRelease;
        }
        SettingsEvent::ReleaseChecked(Ok(LatestRelease::Published(release))) => {
            ui.update_check = UpdateCheckState::Published(release);
        }
        SettingsEvent::ReleaseChecked(Err(error)) => {
            ui.update_check = UpdateCheckState::Failed(error);
        }
    }
}

#[cfg(debug_assertions)]
pub(super) fn seed_qa_update_case(ui: &mut SettingsUi, case: &str) -> Result<(), String> {
    let case = case
        .strip_prefix("settings-updates-")
        .or_else(|| case.strip_prefix("updates-"))
        .unwrap_or(case);
    ui.update_check = match case {
        "idle" => UpdateCheckState::Idle,
        "checking" => UpdateCheckState::Checking,
        "no-release" => UpdateCheckState::NoPublishedRelease,
        "latest-newer" => UpdateCheckState::Published(PublishedRelease {
            tag: "v99.0.0".into(),
            name: Some("Synthetic newer release".into()),
            current_version: Some(env!("CARGO_PKG_VERSION").into()),
            update_available: Some(true),
            matches_installed_version: Some(false),
        }),
        "latest-current" => UpdateCheckState::Published(PublishedRelease {
            tag: format!("v{}", env!("CARGO_PKG_VERSION")),
            name: Some("Synthetic current release".into()),
            current_version: Some(env!("CARGO_PKG_VERSION").into()),
            update_available: Some(false),
            matches_installed_version: Some(true),
        }),
        "latest-unparseable" => UpdateCheckState::Published(PublishedRelease {
            tag: "preview-build".into(),
            name: Some("Synthetic preview".into()),
            current_version: None,
            update_available: None,
            matches_installed_version: None,
        }),
        "error" => UpdateCheckState::Failed(
            "GitHub rate-limited the release check. Try again later.".into(),
        ),
        _ => return Err(format!("Unsupported update-check QA case: {case}")),
    };
    ui.check_request_pending = false;
    Ok(())
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum SettingsTab {
    #[default]
    General,
    Scheduling,
    Updates,
    Privacy,
    MenuLayout,
    Subscription,
    About,
}

impl SettingsTab {
    const ALL: [(Self, &'static str); 7] = [
        (Self::General, "General"),
        (Self::MenuLayout, "Menu"),
        (Self::Scheduling, "Scheduling"),
        (Self::Updates, "Updates"),
        (Self::Privacy, "Privacy"),
        (Self::Subscription, "My Subscription"),
        (Self::About, "About"),
    ];

    #[cfg(debug_assertions)]
    fn from_qa_name(name: &str) -> Option<Self> {
        match name {
            "general" => Some(Self::General),
            "scheduling" => Some(Self::Scheduling),
            "updates" => Some(Self::Updates),
            "privacy" => Some(Self::Privacy),
            "menu-layout" => Some(Self::MenuLayout),
            "subscription" | "my-subscription" => Some(Self::Subscription),
            "about" => Some(Self::About),
            _ => None,
        }
    }
}

const TAB_ID: &str = "settings-main-tab";
const TAB_INITIALIZED_ID: &str = "settings-main-tab-initialized";
const RESET_DIALOG_ID: &str = "settings-reset-hidden-messages";
const RESET_ERROR_ID: &str = "settings-reset-hidden-messages-error";

pub(super) fn show(
    app: &mut App,
    settings_ui: &mut SettingsUi,
    ui: &mut egui::Ui,
    t: Tokens,
    ctx: &egui::Context,
) {
    let tab_id = egui::Id::new(TAB_ID);
    let initialized_id = egui::Id::new(TAB_INITIALIZED_ID);
    let initialized = ctx.data(|data| data.get_temp::<bool>(initialized_id).unwrap_or(false));
    let mut selected = ctx
        .data(|data| data.get_temp::<SettingsTab>(tab_id))
        .unwrap_or_default();

    if !initialized {
        #[cfg(debug_assertions)]
        if app.qa_fixture_mode() {
            if let Ok(name) = std::env::var("DCLEANER_QA_SETTINGS_TAB") {
                if let Some(tab) = SettingsTab::from_qa_name(&name) {
                    selected = tab;
                }
            }
        }
        ctx.data_mut(|data| {
            data.insert_temp(tab_id, selected);
            data.insert_temp(initialized_id, true);
        });
    }

    theme::tabs(ui, |ui| {
        for (tab, label) in SettingsTab::ALL {
            let icon = match tab {
                SettingsTab::General => theme::Icon::Home,
                SettingsTab::MenuLayout => theme::Icon::Menu,
                SettingsTab::Scheduling => theme::Icon::Calendar,
                SettingsTab::Updates => theme::Icon::Refresh,
                SettingsTab::Privacy => theme::Icon::Account,
                SettingsTab::Subscription => theme::Icon::Subscription,
                SettingsTab::About => theme::Icon::Info,
            };
            if theme::settings_tab(ui, selected == tab, icon, label, t).clicked() {
                selected = tab;
                ctx.data_mut(|data| data.insert_temp(tab_id, selected));
            }
        }
    });
    ui.add_space(16.);
    ui.separator();
    ui.add_space(16.);

    if !app.settings_readable {
        availability_note(
            ui,
            t,
            "Preferences could not be read. Settings that need to be saved are disabled until the preferences file is available.",
        );
        ui.add_space(12.);
    }

    match selected {
        SettingsTab::General => general(app, ui, t, ctx),
        SettingsTab::Scheduling => scheduling(ui, t),
        SettingsTab::Updates => updates(app, settings_ui, ui, t),
        SettingsTab::Privacy => privacy(ui, t),
        SettingsTab::MenuLayout => menu_layout(app, ui, t),
        SettingsTab::Subscription => subscription(ui, t),
        SettingsTab::About => about(app, ui, t),
    }

    reset_hidden_messages_dialog(app, ctx, t);
}

fn general(app: &mut App, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
    egui::Frame::NONE.show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Language", t);
        ui.horizontal_wrapped(|ui| {
            ui.add_enabled_ui(false, |ui| {
                theme::selector(ui, "settings-language", "English", &["English"], |ui| {
                    ui.label("English");
                });
            });
        });
        theme::muted(ui, "Only English is currently available in DCleaner.", t);

        section_divider(ui);
        section_title(ui, "Shortcuts", t);
        unavailable_setting(
            ui,
            t,
            "Add Clean Recycle Bin using DCleaner to the Recycle Bin context menu",
            "DCleaner has no action that installs these application-specific shell commands.",
        );
        ui.add_space(10.);
        unavailable_setting(
            ui,
            t,
            "Add Run Custom Clean Analysis to the Recycle Bin context menu",
            "DCleaner has no action that installs these application-specific shell commands.",
        );

        section_divider(ui);
        section_title(ui, "Advanced Settings", t);
        ui.horizontal_wrapped(|ui| {
            ui.with_layout(Layout::top_down(Align::Min), |ui| {
                ui.label(RichText::new("Show messages you previously hid.").size(theme::FONT_BODY));
                theme::muted(
                    ui,
                    "Reset DCleaner welcome messages that were dismissed.",
                    t,
                );
            });
            ui.add_space(16.);
            if theme::secondary(
                ui,
                "Reset",
                app.settings_readable && !app.busy() && !app.preferences_busy(),
            ) {
                ctx.data_mut(|data| {
                    data.insert_temp(egui::Id::new(RESET_DIALOG_ID), true);
                    data.insert_temp(egui::Id::new(RESET_ERROR_ID), String::new());
                });
            }
        });
        ui.add_space(12.);
        unavailable_setting(
            ui,
            t,
            "Skip the Windows permission prompt (User Account Control) when DCleaner starts.",
            "DCleaner does not change User Account Control or its launch-elevation behavior.",
        );
        ui.add_space(10.);
        unavailable_setting(
            ui,
            t,
            "Show tray icon",
            "DCleaner has no system-tray process or tray-icon preference.",
        );
    });
}

fn scheduling(ui: &mut egui::Ui, t: Tokens) {
    egui::Frame::NONE.show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(
            RichText::new("Keep your PC clean — automatically")
                .family(theme::semibold())
                .size(theme::FONT_TITLE),
        );
        ui.add_space(6.);
        theme::muted(
            ui,
            "Scheduled cleaning runs at times you choose, so you do not have to remember.",
            t,
        );
        ui.add_space(16.);
        unavailable_feature(
            ui,
            t,
            "Scheduled cleaning",
            "DCleaner does not create or run application cleaning schedules. Startup Manager's Windows task controls are separate.",
        );
        ui.add_space(12.);
        unavailable_feature(
            ui,
            t,
            "Recommended schedule and customized schedules",
            "No application cleaning schedules are available in DCleaner.",
        );
    });
}

fn updates(app: &mut App, settings_ui: &mut SettingsUi, ui: &mut egui::Ui, t: Tokens) {
    egui::Frame::NONE.show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Update DCleaner", t);
        ui.horizontal_wrapped(|ui| {
            if theme::secondary(
                ui,
                "Check for updates",
                !app.busy() && !settings_ui.is_checking(),
            ) {
                #[cfg(debug_assertions)]
                if app.qa_fixture_mode() {
                    handle_event(
                        settings_ui,
                        SettingsEvent::ReleaseChecked(Ok(LatestRelease::NoPublishedRelease)),
                    );
                } else {
                    let _ = begin_check(settings_ui);
                }
                #[cfg(not(debug_assertions))]
                {
                    let _ = begin_check(settings_ui);
                }
            }
            ui.add_space(10.);
            theme::muted(
                ui,
                "Checks the latest public GitHub release. It does not download or install updates.",
                t,
            );
        });
        update_check_result(ui, settings_ui, t);

        section_divider(ui);
        section_title(ui, "How do you want to handle updates?", t);
        ui.add_enabled_ui(false, |ui| {
            ui.vertical(|ui| {
                let _ = ui.radio(false, "Update automatically");
                let _ = ui.radio(true, "I’ll update manually");
            });
        });
        theme::muted(ui, "Updates are installed manually.", t);

        section_divider(ui);
        section_title(ui, "Get early access to what’s next", t);
        theme::muted(ui, "Try new improvements before public release.", t);
        ui.add_space(8.);
        let mut unknown_beta = false;
        theme::checkbox_mixed(
            ui,
            &mut unknown_beta,
            true,
            "Get early access to DCleaner releases",
            false,
        );
        theme::muted(
            ui,
            "Unavailable: DCleaner has no release channel or beta-update service.",
            t,
        );
    });
}

fn update_check_result(ui: &mut egui::Ui, settings_ui: &SettingsUi, t: Tokens) {
    match &settings_ui.update_check {
        UpdateCheckState::Idle => {}
        UpdateCheckState::Checking => {
            ui.add_space(6.);
            ui.horizontal(|ui| {
                ui.spinner();
                theme::muted(ui, "Checking the latest public release…", t);
            });
        }
        UpdateCheckState::NoPublishedRelease => {
            ui.add_space(6.);
            theme::muted(ui, "No published GitHub release was found.", t);
        }
        UpdateCheckState::Published(release) => {
            ui.add_space(6.);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Latest release").family(theme::semibold()));
                ui.label(&release.tag);
                if let Some(name) = release.name.as_deref() {
                    theme::muted(ui, format!("· {name}"), t);
                }
            });
            if let Some(version) = release.current_version.as_deref() {
                theme::muted(ui, format!("Installed version: {version}"), t);
            }
            match release.update_available {
                Some(true) => theme::muted(
                    ui,
                    "A newer release tag is available. This check does not download or install it.",
                    t,
                ),
                Some(false) if release.matches_installed_version == Some(true) => theme::muted(
                    ui,
                    "The installed version matches the latest release tag.",
                    t,
                ),
                Some(false) => theme::muted(
                    ui,
                    "The installed version is newer than the latest published release tag.",
                    t,
                ),
                None => theme::muted(
                    ui,
                    "Version comparison is unavailable; the release tag is shown without a version claim.",
                    t,
                ),
            }
        }
        UpdateCheckState::Failed(error) => {
            ui.add_space(6.);
            availability_note(ui, t, &format!("Update check unavailable: {error}"));
        }
    }
}

pub(super) fn check_latest_release() -> Result<LatestRelease, String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .map_err(|_| "The public release checker could not be initialized.".to_owned())?;
    let response = client
        .get(LATEST_RELEASE_URL)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .map_err(|error| {
            if error.is_timeout() {
                "The GitHub release check timed out.".to_owned()
            } else if error.is_connect() {
                "Could not connect to GitHub to check for a release.".to_owned()
            } else {
                "Could not check the latest public GitHub release.".to_owned()
            }
        })?;

    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(LatestRelease::NoPublishedRelease);
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err("GitHub rate-limited the release check. Try again later.".into());
    }
    if status == reqwest::StatusCode::FORBIDDEN
        && response
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|remaining| remaining.trim() == "0")
    {
        return Err("GitHub rate-limited the release check. Try again later.".into());
    }
    if !status.is_success() {
        return Err(format!(
            "GitHub returned HTTP {} for the public release check.",
            status.as_u16()
        ));
    }

    let mut body = Vec::with_capacity(8 * 1024);
    response
        .take(MAX_RELEASE_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| "The GitHub release response could not be read.".to_owned())?;
    if body.len() as u64 > MAX_RELEASE_RESPONSE_BYTES {
        return Err("The GitHub release response exceeded 64 KiB.".into());
    }
    parse_latest_release(&body, env!("CARGO_PKG_VERSION"))
}

#[derive(Deserialize)]
struct LatestReleaseWire {
    tag_name: String,
    name: Option<String>,
}

fn parse_latest_release(body: &[u8], current_version: &str) -> Result<LatestRelease, String> {
    let release: LatestReleaseWire = serde_json::from_slice(body)
        .map_err(|_| "GitHub returned an invalid release description.".to_owned())?;
    let raw_tag = release.tag_name.trim();
    if raw_tag.is_empty() || raw_tag.chars().any(char::is_control) {
        return Err("GitHub returned an invalid release tag.".into());
    }
    let tag = truncate_display_text(raw_tag, MAX_RELEASE_TAG_CHARS)
        .ok_or_else(|| "GitHub returned an invalid release tag.".to_owned())?;
    let name = release
        .name
        .as_deref()
        .and_then(|name| truncate_display_text(name, MAX_RELEASE_NAME_CHARS));
    let parsed_current = parse_numeric_version(current_version);
    let parsed_release = parse_numeric_version(raw_tag);
    let comparison = parsed_release.zip(parsed_current);
    let update_available = comparison.map(|(release, current)| release > current);
    let matches_installed_version = comparison.map(|(release, current)| release == current);

    Ok(LatestRelease::Published(PublishedRelease {
        tag,
        name,
        current_version: parsed_current.map(|_| current_version.to_owned()),
        update_available,
        matches_installed_version,
    }))
}

fn truncate_display_text(value: &str, max_chars: usize) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        return None;
    }
    let mut chars = value.chars();
    let mut bounded: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        bounded.push('…');
    }
    Some(bounded)
}

fn parse_numeric_version(value: &str) -> Option<[u64; 3]> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let mut parts = value.split('.');
    let mut parsed = [0; 3];
    for component in &mut parsed {
        let text = parts.next()?;
        if text.is_empty()
            || !text.bytes().all(|byte| byte.is_ascii_digit())
            || (text.len() > 1 && text.starts_with('0'))
        {
            return None;
        }
        *component = text.parse().ok()?;
    }
    parts.next().is_none().then_some(parsed)
}

fn privacy(ui: &mut egui::Ui, t: Tokens) {
    egui::Frame::NONE.show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Privacy", t);
        theme::muted(ui, "DCleaner does not collect app-usage analytics or send marketing data.", t);
        ui.add_space(14.);

        section_title(ui, "Improvements", t);
        let mut unknown_analytics = false;
        theme::checkbox_mixed(
            ui,
            &mut unknown_analytics,
            true,
            "Help improve our products and business processes by allowing us to analyze app-usage data in third-party tools.",
            false,
        );
        theme::muted(ui, "Unavailable: DCleaner has no analytics consent setting or third-party analytics preference.", t);

        section_divider(ui);
        section_title(ui, "Offers", t);
        let mut unknown_first_party_offers = false;
        theme::checkbox_mixed(
            ui,
            &mut unknown_first_party_offers,
            true,
            "Share app-usage data with DCleaner so we may offer you upgrades or our other products.",
            false,
        );
        let mut unknown_third_party_offers = false;
        theme::checkbox_mixed(
            ui,
            &mut unknown_third_party_offers,
            true,
            "Share app-usage data with DCleaner so we may offer third-party products.",
            false,
        );
        theme::muted(ui, "Unavailable: DCleaner has no offers or product-marketing consent settings.", t);
    });
}

fn menu_layout(app: &mut App, ui: &mut egui::Ui, t: Tokens) {
    egui::Frame::NONE.show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Menu structure", t);
        theme::muted(ui, "Choose how your menu is organized.", t);
        ui.add_enabled_ui(false, |ui| {
            ui.vertical(|ui| {
                let _ = ui.radio(false, "Categorized");
                let _ = ui.radio(true, "Flat");
            });
        });
        theme::muted(
            ui,
            "DCleaner uses a fixed flat sidebar; menu grouping cannot be changed.",
            t,
        );
        ui.add_space(8.);
        section_title(ui, "Landing page", t);
        theme::muted(ui, "Choose which page opens when DCleaner starts.", t);
        let editable = app.settings_readable && !app.busy() && !app.preferences_busy();
        let mut landing_page = app.prefs.landing_page;
        let mut pin_landing_page = app.prefs.menu_pin_landing_page;
        let mut changed = false;
        ui.add_enabled_ui(editable, |ui| {
            ui.vertical(|ui| {
                changed |= theme::radio_value(
                    ui,
                    &mut landing_page,
                    LandingPage::HealthCheck,
                    "Health Check",
                )
                .changed();
                changed |= theme::radio_value(
                    ui,
                    &mut landing_page,
                    LandingPage::CustomClean,
                    "Custom Clean",
                )
                .changed();
                changed |= theme::checkbox_text(
                    ui,
                    &mut pin_landing_page,
                    "Always show the landing page at the top of the menu",
                    editable,
                )
                .changed();
            });
        });
        ui.add_space(10.);
        if changed {
            if let Err(error) = commit_preferences(
                app,
                |prefs| {
                    prefs.landing_page = landing_page;
                    prefs.menu_pin_landing_page = pin_landing_page;
                },
                None,
            ) {
                app.error = Some(error);
            }
        }
        theme::muted(
            ui,
            "Landing-page and pin choices apply when DCleaner opens again.",
            t,
        );
    });
}

fn subscription(ui: &mut egui::Ui, t: Tokens) {
    egui::Frame::NONE.show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "Your subscription", t);
        theme::muted(
            ui,
            "Subscription details are unavailable because DCleaner does not have an account or subscription service.",
            t,
        );
    });
}

fn about(app: &mut App, ui: &mut egui::Ui, t: Tokens) {
    egui::Frame::NONE.show(ui, |ui| {
        ui.set_width(ui.available_width());
        section_title(ui, "About DCleaner", t);
        ui.label(RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION"))).size(theme::FONT_BODY));
        ui.add_space(10.);
        theme::muted(ui, "DCleaner is a local Windows utility. Its supported behavior and limitations are documented in the project guide.", t);
        ui.add_space(16.);
        if theme::secondary(ui, "Open Help", !app.busy()) {
            app.page = Page::Help;
        }
    });
}

fn reset_hidden_messages_dialog(app: &mut App, ctx: &egui::Context, t: Tokens) {
    let dialog_id = egui::Id::new(RESET_DIALOG_ID);
    if !ctx.data(|data| data.get_temp::<bool>(dialog_id).unwrap_or(false)) {
        return;
    }

    let mut close = false;
    let mut reset = false;
    let response = egui::Modal::new(egui::Id::new("settings-reset-confirmation"))
        .frame(theme::dialog_frame(t))
        .show(ctx, |ui| {
            ui.set_width((ctx.content_rect().width() - 40.).clamp(280., 460.));
            ui.horizontal(|ui| {
                ui.label(RichText::new("Show hidden messages again?").family(theme::semibold()).size(theme::FONT_TITLE));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    close |= theme::close_button(ui, "Close", !app.busy());
                });
            });
            ui.add_space(8.);
            theme::muted(ui, "This resets DCleaner’s dismissed welcome messages. It does not reset your other settings.", t);
            let reset_error = ctx.data(|data| data.get_temp::<String>(egui::Id::new(RESET_ERROR_ID)).unwrap_or_default());
            if !reset_error.is_empty() {
                ui.add_space(8.);
                ui.colored_label(t.attention, reset_error);
            }
            ui.add_space(18.);
            theme::action_row(ui, |ui| {
                if theme::secondary(ui, "Cancel", !app.busy()) {
                    close = true;
                }
                if theme::primary(ui, "Reset", t, app.settings_readable && !app.busy() && !app.preferences_busy()) {
                    reset = true;
                }
            });
        });

    if reset {
        match commit_preferences(
            app,
            |prefs| prefs.seen_features.clear(),
            Some("DCleaner welcome messages will be shown again."),
        ) {
            Ok(()) => {
                close = true;
                ctx.data_mut(|data| data.insert_temp(egui::Id::new(RESET_ERROR_ID), String::new()));
            }
            Err(error) => {
                ctx.data_mut(|data| data.insert_temp(egui::Id::new(RESET_ERROR_ID), error.clone()));
                app.error = Some(error);
            }
        }
    }
    if close || response.should_close() {
        ctx.data_mut(|data| {
            data.insert_temp(dialog_id, false);
            data.insert_temp(egui::Id::new(RESET_ERROR_ID), String::new());
        });
    }
}

fn commit_preferences(
    app: &mut App,
    change: impl FnOnce(&mut dcleaner::domain::Preferences),
    notice: Option<&str>,
) -> Result<(), String> {
    let fixture = app.qa_fixture_mode();
    let readable = app.settings_readable;
    let updated = updated_preferences(&app.prefs, change, |_preferences| {
        if fixture {
            Ok(())
        } else if !readable {
            Err("Preferences could not be read, so the change was not saved.".into())
        } else {
            Ok(())
        }
    })?;
    app.queue_preferences(updated, notice)
}

fn updated_preferences(
    current: &dcleaner::domain::Preferences,
    change: impl FnOnce(&mut dcleaner::domain::Preferences),
    persist: impl FnOnce(&dcleaner::domain::Preferences) -> Result<(), String>,
) -> Result<dcleaner::domain::Preferences, String> {
    let mut updated = current.clone();
    change(&mut updated);
    persist(&updated)?;
    Ok(updated)
}

const APPEARANCE_POPUP_ID: &str = "application-appearance-menu";

pub(super) fn appearance_control(app: &mut App, root: &mut egui::Ui) {
    let ctx = root.ctx().clone();
    let bounds = ctx.content_rect();
    let right_inset = if cfg!(windows) { 140. } else { 12. };
    let position = egui::pos2(bounds.right() - right_inset - 32., bounds.top());
    let current = app.prefs.appearance_mode();
    let (icon, name) = appearance_option(current);
    let enabled = app.settings_readable && !app.busy() && !app.preferences_busy();
    let t = theme::tokens(app.prefs.dark);
    let mut selected = None;
    egui::Area::new(egui::Id::new("application-appearance-control"))
        .order(egui::Order::Foreground)
        .fixed_pos(position)
        .show(&ctx, |ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(32.), egui::Sense::hover());
            let response = ui
                .add_enabled_ui(enabled, |ui| {
                    ui.put(rect, egui::Button::new("").frame(false).corner_radius(16))
                })
                .inner;
            if response.hovered()
                || egui::Popup::is_id_open(&ctx, egui::Id::new(APPEARANCE_POPUP_ID))
            {
                ui.painter().rect_filled(rect, 16., t.hover);
            }
            theme::paint_icon(ui.painter(), rect.shrink(8.), icon, t.muted);
            theme::focus_ring(ui, &response, 18);
            #[cfg(test)]
            ctx.data_mut(|data| {
                data.insert_temp(egui::Id::new(("appearance-focus", "trigger")), response.id)
            });
            response.widget_info(|| {
                egui::WidgetInfo::labeled(
                    egui::WidgetType::Button,
                    enabled,
                    format!("Theme: {name}"),
                )
            });
            #[cfg(debug_assertions)]
            theme::record_fixture_control(ui, "Appearance menu", &response);
            let response = response
                .on_hover_text(format!("Theme: {name}"))
                .on_disabled_hover_text(if app.preferences_busy() {
                    "Saving preferences…"
                } else if !app.settings_readable {
                    "Preferences are unavailable."
                } else {
                    "Wait for the current operation to finish."
                });
            egui::Popup::menu(&response)
                .id(egui::Id::new(APPEARANCE_POPUP_ID))
                .align(egui::RectAlign::BOTTOM_END)
                .frame(theme::dialog_frame(t).inner_margin(6.).corner_radius(12))
                .width(154.)
                .show(|ui| {
                    if !enabled {
                        ui.disable();
                    }
                    ui.spacing_mut().item_spacing.y = 0.;
                    for mode in [
                        AppearanceMode::Light,
                        AppearanceMode::Dark,
                        AppearanceMode::System,
                    ] {
                        let (icon, label) = appearance_option(mode);
                        let icon_id = ui.id().with(("appearance-icon", label));
                        let check_id = ui.id().with(("appearance-check", label));
                        ui.spacing_mut().button_padding = Vec2::new(12., 8.);
                        let painted = egui::Button::new((
                            egui::Atom::custom(icon_id, Vec2::splat(16.)),
                            RichText::new(label).size(theme::FONT_BODY).family(
                                if current == mode {
                                    theme::semibold()
                                } else {
                                    egui::FontFamily::Proportional
                                },
                            ),
                            egui::Atom::grow(),
                            egui::Atom::custom(check_id, Vec2::splat(12.)),
                        ))
                        .gap(12.)
                        .min_size(Vec2::new(154., 36.))
                        .fill(if current == mode {
                            t.tint
                        } else {
                            Color32::TRANSPARENT
                        })
                        .stroke(egui::Stroke::NONE)
                        .corner_radius(18)
                        .atom_ui(ui);
                        if let Some(rect) = painted.rect(icon_id) {
                            theme::paint_icon(ui.painter(), rect, icon, t.muted);
                        }
                        if current == mode {
                            if let Some(rect) = painted.rect(check_id) {
                                theme::paint_icon(
                                    ui.painter(),
                                    rect,
                                    theme::Icon::Check,
                                    t.foreground,
                                );
                            }
                        }
                        let response = painted.response;
                        theme::focus_ring(ui, &response, 20);
                        #[cfg(test)]
                        ctx.data_mut(|data| {
                            data.insert_temp(
                                egui::Id::new(("appearance-focus", label)),
                                response.id,
                            )
                        });
                        #[cfg(debug_assertions)]
                        theme::record_fixture_control(ui, label, &response);
                        if response.clicked() {
                            selected = Some(mode);
                            ui.close();
                        }
                    }
                });
        });
    if let Some(mode) = selected {
        let system_dark = ctx.system_theme().map(|system| system == egui::Theme::Dark);
        match commit_preferences(app, |prefs| prefs.set_appearance(mode, system_dark), None) {
            Ok(()) => {
                theme::apply(&ctx, app.prefs.effective_dark(system_dark));
                ctx.request_repaint();
            }
            Err(error) => app.error = Some(error),
        }
    }
}

fn appearance_option(mode: AppearanceMode) -> (theme::Icon, &'static str) {
    match mode {
        AppearanceMode::Light => (theme::Icon::Sun, "Light"),
        AppearanceMode::Dark => (theme::Icon::Moon, "Dark"),
        AppearanceMode::System => (theme::Icon::Startup, "System"),
    }
}

#[cfg(debug_assertions)]
pub(super) fn qa_appearance_open(ctx: &egui::Context) -> bool {
    egui::Popup::is_id_open(ctx, egui::Id::new(APPEARANCE_POPUP_ID))
}

fn section_title(ui: &mut egui::Ui, text: &str, t: Tokens) {
    ui.label(
        RichText::new(text)
            .family(theme::semibold())
            .size(theme::FONT_TITLE)
            .color(t.foreground),
    );
    ui.add_space(8.);
}

fn section_divider(ui: &mut egui::Ui) {
    ui.add_space(16.);
    ui.separator();
    ui.add_space(14.);
}

fn availability_note(ui: &mut egui::Ui, t: Tokens, text: &str) {
    egui::Frame::new()
        .fill(t.tint)
        .corner_radius(8.)
        .inner_margin(12.)
        .show(ui, |ui| theme::muted(ui, text, t));
}

fn unavailable_setting(ui: &mut egui::Ui, t: Tokens, label: &str, reason: &str) {
    let mut unknown = false;
    theme::checkbox_mixed(ui, &mut unknown, true, label, false).on_disabled_hover_text(reason);
    let _ = t;
}

fn unavailable_feature(ui: &mut egui::Ui, t: Tokens, label: &str, reason: &str) {
    ui.label(
        RichText::new(label)
            .size(theme::FONT_BODY)
            .color(t.foreground),
    );
    theme::muted(ui, format!("Unavailable — {reason}"), t);
}

#[cfg(debug_assertions)]
pub(super) fn seed_qa_tab(ctx: &egui::Context, name: &str) -> Result<(), String> {
    let name = name.strip_prefix("settings-").unwrap_or(name);
    let tab = SettingsTab::from_qa_name(name)
        .ok_or_else(|| format!("Unsupported Settings QA tab: {name}"))?;
    ctx.data_mut(|data| {
        data.insert_temp(egui::Id::new(TAB_ID), tab);
        data.insert_temp(egui::Id::new(TAB_INITIALIZED_ID), true);
        data.insert_temp(egui::Id::new(RESET_DIALOG_ID), false);
        data.insert_temp(egui::Id::new(RESET_ERROR_ID), String::new());
    });
    Ok(())
}

#[cfg(debug_assertions)]
pub(super) fn qa_selected_tab(ctx: &egui::Context) -> &'static str {
    match ctx
        .data(|data| data.get_temp::<SettingsTab>(egui::Id::new(TAB_ID)))
        .unwrap_or_default()
    {
        SettingsTab::General => "general",
        SettingsTab::Scheduling => "scheduling",
        SettingsTab::Updates => "updates",
        SettingsTab::Privacy => "privacy",
        SettingsTab::MenuLayout => "menu-layout",
        SettingsTab::Subscription => "my-subscription",
        SettingsTab::About => "about",
    }
}

#[cfg(debug_assertions)]
pub(super) fn qa_action_precondition(app: &App, ctx: &egui::Context, label: &str) -> bool {
    let label = if label == "Menu Layout" {
        "Menu"
    } else {
        label
    };
    let tab = ctx
        .data(|data| data.get_temp::<SettingsTab>(egui::Id::new(TAB_ID)))
        .unwrap_or_default();
    let reset_open = ctx.data(|data| {
        data.get_temp::<bool>(egui::Id::new(RESET_DIALOG_ID))
            .unwrap_or(false)
    });
    if SettingsTab::ALL
        .iter()
        .any(|(candidate, name)| *name == label && *candidate != tab)
    {
        return true;
    }
    match (tab, reset_open, label) {
        (SettingsTab::General, false, "Reset") => {
            app.settings_readable && !app.busy() && !app.preferences_busy()
        }
        (SettingsTab::General, true, "Reset" | "Cancel" | "Close") => !app.busy(),
        (SettingsTab::Updates, false, "Check for updates") => {
            !app.busy() && !app.settings_ui.is_checking()
        }
        (
            SettingsTab::MenuLayout,
            false,
            "Health Check" | "Custom Clean" | "Always show the landing page at the top of the menu",
        ) => app.settings_readable && !app.busy() && !app.preferences_busy(),
        (SettingsTab::About, false, "Open Help") => !app.busy(),
        _ => false,
    }
}

#[cfg(debug_assertions)]
pub(super) fn qa_state(app: &App, ctx: &egui::Context) -> serde_json::Value {
    serde_json::json!({
        "tab": qa_selected_tab(ctx),
        "appearance": format!("{:?}", app.prefs.appearance_mode()),
        "dark": app.prefs.dark,
        "landing_page": format!("{:?}", app.prefs.landing_page),
        "menu_pin_landing_page": app.prefs.menu_pin_landing_page,
        "seen_features": app.prefs.seen_features,
        "update_check": update_check_state_name(&app.settings_ui.update_check),
        "update_check_pending": app.settings_ui.check_request_pending,
        "latest_release_tag": match &app.settings_ui.update_check {
            UpdateCheckState::Published(release) => Some(release.tag.as_str()),
            _ => None,
        },
        "latest_release_comparison": match &app.settings_ui.update_check {
            UpdateCheckState::Published(release) => release.update_available,
            _ => None,
        },
        "latest_release_matches_installed": match &app.settings_ui.update_check {
            UpdateCheckState::Published(release) => release.matches_installed_version,
            _ => None,
        },
        "check_updates_enabled": qa_action_precondition(app, ctx, "Check for updates"),
        "reset_dialog_open": ctx.data(|data| data.get_temp::<bool>(egui::Id::new(RESET_DIALOG_ID)).unwrap_or(false)),
    })
}

#[cfg(any(test, debug_assertions))]
fn update_check_state_name(state: &UpdateCheckState) -> &'static str {
    match state {
        UpdateCheckState::Idle => "idle",
        UpdateCheckState::Checking => "checking",
        UpdateCheckState::NoPublishedRelease => "no_published_release",
        UpdateCheckState::Published(_) => "published_release",
        UpdateCheckState::Failed(_) => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcleaner::domain::AppearanceMode;

    #[test]
    fn appearance_menu_supports_keyboard_selection_escape_and_system_changes() {
        let ctx = egui::Context::default();
        let mut app = App::new_fixture_with_context(&ctx, "startup-populated").unwrap();
        let mut tick = 0_u32;
        let mut frame = |app: &mut App, key: Option<egui::Key>, system_theme| {
            tick += 1;
            let events = key
                .map(|key| {
                    vec![
                        egui::Event::Key {
                            key,
                            physical_key: None,
                            pressed: true,
                            repeat: false,
                            modifiers: egui::Modifiers::NONE,
                        },
                        egui::Event::Key {
                            key,
                            physical_key: None,
                            pressed: false,
                            repeat: false,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ]
                })
                .unwrap_or_default();
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(920., 612.),
                    )),
                    focused: true,
                    time: Some(tick as f64 / 30.),
                    system_theme: Some(system_theme),
                    events,
                    ..Default::default()
                },
                |root| app.paint(root),
            );
            output.textures_delta.clear();
        };
        let focus = |name| {
            let id = ctx
                .data(|data| data.get_temp::<egui::Id>(egui::Id::new(("appearance-focus", name))))
                .expect("rendered appearance control");
            ctx.memory_mut(|memory| memory.request_focus(id));
        };
        for _ in 0..4 {
            frame(&mut app, None, egui::Theme::Dark);
        }
        for (label, mode) in [
            ("Light", AppearanceMode::Light),
            ("Dark", AppearanceMode::Dark),
            ("System", AppearanceMode::System),
        ] {
            focus("trigger");
            frame(&mut app, Some(egui::Key::Enter), egui::Theme::Dark);
            for _ in 0..3 {
                frame(&mut app, None, egui::Theme::Dark);
            }
            assert!(qa_appearance_open(&ctx));
            focus(label);
            frame(&mut app, Some(egui::Key::Enter), egui::Theme::Dark);
            frame(&mut app, None, egui::Theme::Dark);
            assert!(!qa_appearance_open(&ctx));
            assert_eq!(app.prefs.appearance_mode(), mode);
        }
        frame(&mut app, None, egui::Theme::Light);
        assert!(!app.prefs.dark);
        frame(&mut app, None, egui::Theme::Dark);
        assert!(app.prefs.dark);
        focus("trigger");
        frame(&mut app, Some(egui::Key::Enter), egui::Theme::Dark);
        assert!(qa_appearance_open(&ctx));
        frame(&mut app, Some(egui::Key::Escape), egui::Theme::Dark);
        assert!(!qa_appearance_open(&ctx));
    }

    #[test]
    fn failed_preference_persistence_keeps_the_saved_snapshot_unchanged() {
        let saved = dcleaner::domain::Preferences::default();
        let result = updated_preferences(
            &saved,
            |next| next.set_appearance(AppearanceMode::Light, None),
            |_| Err("simulated persistence failure".into()),
        );
        assert!(result.is_err());
        assert_eq!(saved.appearance_mode(), AppearanceMode::System);
        assert!(saved.dark);
    }

    #[test]
    fn saved_preference_changes_commit_only_after_the_writer_succeeds() {
        let saved = dcleaner::domain::Preferences::default();
        let updated = updated_preferences(
            &saved,
            |next| {
                next.landing_page = LandingPage::CustomClean;
                next.menu_pin_landing_page = true;
            },
            |next| {
                assert_eq!(next.landing_page, LandingPage::CustomClean);
                assert!(next.menu_pin_landing_page);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(saved.landing_page, LandingPage::HealthCheck);
        assert_eq!(updated.landing_page, LandingPage::CustomClean);
        assert!(updated.menu_pin_landing_page);
    }

    #[test]
    fn release_parser_compares_only_strict_three_number_tags() {
        let newer =
            parse_latest_release(br#"{"tag_name":"v1.2.4","name":"DCleaner 1.2.4"}"#, "1.2.3")
                .unwrap();
        let LatestRelease::Published(release) = newer else {
            panic!("expected release metadata");
        };
        assert_eq!(release.tag, "v1.2.4");
        assert_eq!(release.name.as_deref(), Some("DCleaner 1.2.4"));
        assert_eq!(release.update_available, Some(true));

        let current = parse_latest_release(br#"{"tag_name":"v1.2.3"}"#, "1.2.3").unwrap();
        let LatestRelease::Published(current) = current else {
            panic!("expected release metadata");
        };
        assert_eq!(current.update_available, Some(false));

        let preview = parse_latest_release(br#"{"tag_name":"preview-build"}"#, "1.2.3").unwrap();
        let LatestRelease::Published(preview) = preview else {
            panic!("expected release metadata");
        };
        assert_eq!(preview.tag, "preview-build");
        assert_eq!(preview.update_available, None);

        assert_eq!(parse_numeric_version("v1.2.3"), Some([1, 2, 3]));
        for invalid in ["1.2", "1.2.3.4", "v01.2.3", "1.2.3-rc1", "1.2.x"] {
            assert_eq!(parse_numeric_version(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn release_display_fields_are_bounded_and_control_free() {
        let long_tag = "x".repeat(MAX_RELEASE_TAG_CHARS + 20);
        let long_name = "y".repeat(MAX_RELEASE_NAME_CHARS + 20);
        let body = serde_json::to_vec(&serde_json::json!({
            "tag_name": long_tag,
            "name": long_name,
        }))
        .unwrap();
        let LatestRelease::Published(release) = parse_latest_release(&body, "1.2.3").unwrap()
        else {
            panic!("expected release metadata");
        };
        assert_eq!(release.tag.chars().count(), MAX_RELEASE_TAG_CHARS + 1);
        assert_eq!(
            release.name.unwrap().chars().count(),
            MAX_RELEASE_NAME_CHARS + 1
        );

        assert!(parse_latest_release(br#"{"tag_name":"bad\nname"}"#, "1.2.3").is_err());
        let LatestRelease::Published(release) =
            parse_latest_release(br#"{"tag_name":"v1.2.4","name":"bad\nname"}"#, "1.2.3").unwrap()
        else {
            panic!("expected release metadata");
        };
        assert!(release.name.is_none());
    }

    #[test]
    fn check_state_allows_one_worker_request_and_records_its_result() {
        let mut state = SettingsUi::default();
        assert!(begin_check(&mut state));
        assert!(!begin_check(&mut state));
        assert!(state.is_checking());
        assert!(take_check_request(&mut state));
        assert!(!take_check_request(&mut state));

        handle_event(
            &mut state,
            SettingsEvent::ReleaseChecked(Ok(LatestRelease::NoPublishedRelease)),
        );
        assert!(!state.is_checking());
        assert_eq!(
            update_check_state_name(&state.update_check),
            "no_published_release"
        );
        assert!(!take_check_request(&mut state));
    }
}
