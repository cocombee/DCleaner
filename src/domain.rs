use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Category {
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
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            schema: 1,
            minimum_age_days: 7,
            selected_categories: vec!["temp".into(), "crash".into()],
            dark: true,
            seen_features: Vec::new(),
        }
    }
}
