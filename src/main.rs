#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod activity_chart;
mod app;
mod app_icons;
mod illustrations;
#[cfg(debug_assertions)]
mod offscreen_qa;
mod render_config;
mod startup_load;
mod theme;
#[cfg(debug_assertions)]
mod visual_qa;
mod worker_events;
fn main() -> eframe::Result {
    // Detect this with OsString before any UTF-8 argv iteration, normal GUI,
    // single-instance restore, scan or SCM branch. Original arguments are opaque.
    if dcleaner::optimizer_helper::is_requested() {
        return dcleaner::optimizer_helper::run_current()
            .map_err(|error| eframe::Error::AppCreation(Box::new(error)));
    }
    if std::env::args().any(|arg| arg == "--optimizer-service") {
        #[cfg(windows)]
        return dcleaner::optimizer_service::run_dispatcher()
            .map_err(|error| eframe::Error::AppCreation(Box::new(error)));
        #[cfg(not(windows))]
        return Err(eframe::Error::AppCreation(Box::new(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "The Optimizer SCM host requires Windows.",
        ))));
    }
    if std::env::args().any(|arg| arg == "--optimizer-readiness-json") {
        let started = std::time::Instant::now();
        #[cfg(windows)]
        let report = match dcleaner::optimizer_service::query_current_session(
            started + std::time::Duration::from_secs(3),
            &std::sync::atomic::AtomicBool::new(false),
        ) {
            Ok(response) => {
                serde_json::json!({"connected":true,"response":response,"elapsed_ms":started.elapsed().as_millis(),"window_created":false,"native_effects":false})
            }
            Err(error) => {
                serde_json::json!({"connected":false,"error_code":error.raw_os_error(),"error":error.to_string(),"elapsed_ms":started.elapsed().as_millis(),"window_created":false,"native_effects":false})
            }
        };
        #[cfg(not(windows))]
        let report = serde_json::json!({"connected":false,"supported":false,"elapsed_ms":started.elapsed().as_millis(),"window_created":false,"native_effects":false});
        println!("{report}");
        return Ok(());
    }
    if std::env::args().any(|arg| arg == "--startup-readiness-json") {
        let started = std::time::Instant::now();
        let report = match startup_load::load() {
            Ok(data) => serde_json::json!({
                "startup_reads_elapsed_ms":started.elapsed().as_millis(),
                "preferences_readable":data.preferences.is_ok(),
                "history_readable":data.history.is_ok(),
                "clean_settings_readable":data.clean_settings.is_ok(),
                "window_created":false,"graphics_initialized":false,"native_effects":false,
            }),
            Err(_) => {
                serde_json::json!({"startup_reads_elapsed_ms":started.elapsed().as_millis(),"startup_data_available":false,"window_created":false,"graphics_initialized":false,"native_effects":false})
            }
        };
        println!("{report}");
        return Ok(());
    }
    #[cfg(debug_assertions)]
    if std::env::args().any(|arg| arg == "--render-offscreen-qa") {
        return offscreen_qa::run()
            .map_err(|error| eframe::Error::AppCreation(Box::new(std::io::Error::other(error))));
    }
    let browser_cache_only = std::env::args().any(|arg| arg == "--scan-browser-cache-json");
    if browser_cache_only || std::env::args().any(|arg| arg == "--scan-json") {
        let preferences = dcleaner::domain::Preferences::default();
        let categories = dcleaner::platform::categories();
        let selected = if browser_cache_only {
            categories
                .iter()
                .filter(|c| dcleaner::browser_cache::is_category(&c.id))
                .map(|c| c.id.clone())
                .collect()
        } else {
            preferences.selected_categories
        };
        let result = dcleaner::scanner::analyze(
            &categories,
            &selected,
            preferences.minimum_age_days,
            &std::sync::atomic::AtomicBool::new(false),
            |_, _| {},
        );
        match result {
            Ok(a) if browser_cache_only => println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "browser_cache_age_days":0,"native_effects":false,"window_created":false,"analysis":a
            })).unwrap()),
            Ok(a) => println!("{}", serde_json::to_string_pretty(&a).unwrap()),
            Err(e) => eprintln!("{e}"),
        };
        return Ok(());
    }
    #[cfg(windows)]
    let _instance = match dcleaner::instance::acquire("Local\\com.cocombee.dcleaner.native.v1") {
        Ok(Some(instance)) => instance,
        Ok(None) => {
            dcleaner::instance::show_existing();
            return Ok(());
        }
        Err(error) => {
            return Err(eframe::Error::AppCreation(Box::new(error)));
        }
    };
    let initial_size = [1240., 820.];
    #[cfg(debug_assertions)]
    let initial_size = if std::env::args().any(|arg| arg == "--render-qa")
        && std::env::var("DCLEANER_QA_SIZE").as_deref() == Ok("minimum")
    {
        [760., 600.]
    } else {
        initial_size
    };
    let viewport = eframe::egui::ViewportBuilder::default()
        .with_inner_size(initial_size)
        .with_min_inner_size([760., 600.])
        .with_decorations(!cfg!(windows))
        .with_app_id("com.cocombee.dcleaner");
    #[cfg(windows)]
    let window_icon = dcleaner::brand::windows_icon();
    #[cfg(not(windows))]
    let window_icon = dcleaner::brand::icon();
    let viewport = match window_icon {
        Ok(icon) => viewport.with_icon(icon),
        Err(_) => viewport,
    };
    let options = eframe::NativeOptions {
        viewport,
        renderer: eframe::Renderer::Wgpu,
        wgpu_options: render_config::configuration(),
        ..Default::default()
    };
    eframe::run_native(
        "DCleaner",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
