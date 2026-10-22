use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Category {
    #[serde(default)]
    pub cache_root_scopes: std::collections::HashMap<PathBuf, crate::browser_cache::RootScope>,
    pub id: String,
    pub name: String,
    pub group: String,
    pub description: String,
    pub roots: Vec<PathBuf>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub id: Uuid,
    pub path: PathBuf,
    pub root: PathBuf,
    pub size: u64,
    pub modified_ns: u128,
    pub created_ns: Option<u128>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CategoryResult {
    pub id: String,
    pub name: String,
    pub group: String,
    pub files: Vec<Candidate>,
    pub skipped: usize,
    pub available: bool,
    pub truncated: bool,
}
impl CategoryResult {
    pub fn bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CleanupPolicy {
    #[default]
    MinimumAge,
    CustomCleanRules,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Analysis {
    pub id: Uuid,
    pub date: String,
    pub minimum_age_days: u32,
    #[serde(default)]
    pub cleanup_policy: CleanupPolicy,
    pub elapsed_ms: u64,
    pub cancelled: bool,
    pub categories: Vec<CategoryResult>,
}
impl Analysis {
    pub fn count(&self) -> usize {
        self.categories.iter().map(|c| c.files.len()).sum()
    }
    pub fn bytes(&self) -> u64 {
        self.categories.iter().map(CategoryResult::bytes).sum()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileOutcome {
    pub file_id: Uuid,
    pub path: PathBuf,
    pub size: u64,
    pub success: bool,
    pub reason: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CleanupResult {
    pub id: Uuid,
    pub date: String,
    pub files: usize,
    pub bytes: u64,
    pub failed: Vec<FileOutcome>,
    pub cleaned_ids: Vec<Uuid>,
    pub cancelled: bool,
    pub uncertain: Vec<PathBuf>,
    pub interrupted: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Preferences {
    pub schema: u32,
    pub minimum_age_days: u32,
    pub selected_categories: Vec<String>,
    pub dark: bool,
    #[serde(default)]
    pub seen_features: Vec<String>,
    /// `None` keeps the legacy `dark` boolean authoritative for old preference files.
    #[serde(default)]
    pub appearance: Option<AppearanceMode>,
    #[serde(default)]
    pub landing_page: LandingPage,
    #[serde(default)]
    pub menu_pin_landing_page: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppearanceMode {
    Dark,
    Light,
    System,
}
impl AppearanceMode {
    pub fn effective_dark(self, system_dark: bool) -> bool {
        match self {
            Self::Dark => true,
            Self::Light => false,
            Self::System => system_dark,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandingPage {
    #[default]
    HealthCheck,
    CustomClean,
}
impl Preferences {
    pub fn appearance_mode(&self) -> AppearanceMode {
        self.appearance.unwrap_or(if self.dark {
            AppearanceMode::Dark
        } else {
            AppearanceMode::Light
        })
    }

    pub fn effective_dark(&self, system_dark: Option<bool>) -> bool {
        match self.appearance_mode() {
            AppearanceMode::System => system_dark.unwrap_or(self.dark),
            AppearanceMode::Dark => true,
            AppearanceMode::Light => false,
        }
    }

    pub fn set_appearance(&mut self, mode: AppearanceMode, system_dark: Option<bool>) {
        self.appearance = Some(mode);
        self.dark = match mode {
            AppearanceMode::System => system_dark.unwrap_or(self.dark),
            _ => mode.effective_dark(false),
        };
    }
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            schema: 1,
            minimum_age_days: 7,
            selected_categories: vec!["temp".into(), "crash".into()],
            dark: true,
            seen_features: Vec::new(),
            appearance: Some(AppearanceMode::System),
            landing_page: LandingPage::HealthCheck,
            menu_pin_landing_page: false,
        }
    }
}

#[cfg(test)]
mod preferences_tests {
    use super::*;

    #[test]
    fn legacy_preferences_keep_their_saved_dark_boolean() {
        let prefs: Preferences = serde_json::from_str(
            r#"{"schema":1,"minimum_age_days":7,"selected_categories":["temp"],"dark":false}"#,
        )
        .unwrap();
        assert_eq!(prefs.appearance, None);
        assert_eq!(prefs.appearance_mode(), AppearanceMode::Light);
        assert!(!prefs.effective_dark(None));
        assert_eq!(prefs.landing_page, LandingPage::HealthCheck);
        assert!(!prefs.menu_pin_landing_page);
    }

    #[test]
    fn system_appearance_uses_the_detected_theme_and_keeps_a_legacy_fallback() {
        let mut prefs = Preferences::default();
        prefs.set_appearance(AppearanceMode::System, Some(false));
        assert!(!prefs.dark);
        assert!(!prefs.effective_dark(Some(false)));
        assert!(prefs.effective_dark(Some(true)));
        assert!(!prefs.effective_dark(None));
    }

    #[test]
    fn menu_preferences_round_trip_without_losing_unrelated_defaults() {
        let mut prefs = Preferences::default();
        prefs.landing_page = LandingPage::CustomClean;
        prefs.menu_pin_landing_page = true;
        prefs.set_appearance(AppearanceMode::Dark, None);
        let encoded = serde_json::to_vec(&prefs).unwrap();
        let decoded: Preferences = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.landing_page, LandingPage::CustomClean);
        assert!(decoded.menu_pin_landing_page);
        assert!(decoded.effective_dark(None));
        assert_eq!(decoded.minimum_age_days, 7);
        assert_eq!(decoded.selected_categories, vec!["temp", "crash"]);
    }
}
