//! Blocking startup reads belong to a worker, never the first UI frame.
use dcleaner::{
    clean_settings,
    domain::{Category, CleanupResult, Preferences},
    platform, store,
};
use std::path::PathBuf;

pub struct StartupData {
    pub root: PathBuf,
    pub preferences: Result<Preferences, String>,
    pub history: Result<Vec<CleanupResult>, String>,
    pub clean_settings: Result<clean_settings::CustomCleanSettings, String>,
    pub categories: Vec<Category>,
}

pub fn load() -> Result<StartupData, String> {
    let root = platform::data_directory()?;
    if !root.is_absolute() {
        return Err("DCleaner's data directory is unavailable; no startup files were read.".into());
    }
    Ok(StartupData {
        preferences: store::load_preferences(&root),
        history: store::history(&root),
        clean_settings: clean_settings::load_settings(&root).map_err(|error| error.to_string()),
        categories: platform::categories(),
        root,
    })
}
