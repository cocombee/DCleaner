#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod app;
mod app_icons;
#[cfg(debug_assertions)]
mod offscreen_qa;
mod theme;
#[cfg(debug_assertions)]
mod visual_qa;
fn main() -> eframe::Result {
    #[cfg(debug_assertions)]
    if std::env::args().any(|arg| arg == "--render-offscreen-qa") {
        return offscreen_qa::run()
            .map_err(|error| eframe::Error::AppCreation(Box::new(std::io::Error::other(error))));
    }
    if std::env::args().any(|arg| arg == "--scan-json") {
        let preferences = dcleaner::domain::Preferences::default();
        let result = dcleaner::scanner::analyze(
            &dcleaner::platform::categories(),
            &preferences.selected_categories,
            preferences.minimum_age_days,
            &std::sync::atomic::AtomicBool::new(false),
            |_, _| {},
        );
        match result {
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
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size(initial_size)
            .with_min_inner_size([760., 600.])
            .with_decorations(!cfg!(windows))
            .with_app_id("com.cocombee.dcleaner"),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "DCleaner",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
