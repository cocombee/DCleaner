use super::*;

#[cfg(debug_assertions)]
impl App {
    pub(crate) fn seed_core_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Core QA fixtures require isolated fixture mode.".into());
        }
        if !matches!(
            case,
            "clean-empty"
                | "clean-populated"
                | "clean-selected"
                | "clean-details"
                | "clean-error"
                | "history-empty"
                | "history-populated"
                | "settings"
        ) {
            return Err(format!("Unsupported core QA fixture: {case}"));
        }
        if self.busy() {
            return Err(
                "Core QA fixtures cannot replace state while an operation is running.".into(),
            );
        }

        self.clean_browser = false;
        self.clean_bin = false;
        self.custom_partial_acknowledged = false;
        self.selected.clear();
        self.error = None;
        self.notice = None;
        self.progress.clear();
        self.history_readable = true;
        self.settings_readable = true;

        match case {
            "clean-empty" | "clean-populated" | "clean-selected" | "clean-details"
            | "clean-error" => {
                self.page = Page::Clean;
                self.group = "Applications".into();
                let report = match case {
                    "clean-empty" => custom_clean::CustomCleanReport::visual_fixture_empty(),
                    "clean-populated" | "clean-selected" => {
                        custom_clean::CustomCleanReport::visual_fixture_populated()
                    }
                    "clean-details" => custom_clean::CustomCleanReport::visual_fixture_details(),
                    "clean-error" => custom_clean::CustomCleanReport::visual_fixture_error(),
                    _ => unreachable!(),
                };
                self.analysis = Some(report.to_analysis());
                if case == "clean-selected" {
                    self.selected = self
                        .analysis
                        .iter()
                        .flat_map(|report| &report.categories)
                        .flat_map(|category| &category.files)
                        .map(|file| file.id)
                        .collect();
                }
                self.custom_analysis = Some(report);
                self.notice = None;
                if case == "clean-error" {
                    self.error =
                        Some("Synthetic QA result: the fixture location is unavailable.".into());
                }
            }
            "history-empty" => {
                self.page = Page::History;
                self.history.clear();
            }
            "history-populated" => {
                self.page = Page::History;
                self.history = history_fixture();
            }
            "settings" => {
                self.page = Page::Settings;
                self.prefs.minimum_age_days = 14;
            }
            _ => unreachable!("supported core QA fixture was matched above"),
        }
        Ok(())
    }
}

#[cfg(debug_assertions)]
pub(super) fn history_fixture() -> Vec<CleanupResult> {
    use dcleaner::domain::FileOutcome;
    use std::path::PathBuf;

    vec![
        CleanupResult {
            id: Uuid::from_u128(0x2a61_7b2f_84c7_4f3a_9b20_0064_0000_0001),
            date: "2026-10-14T16:42:00+08:00".into(),
            files: 2,
            bytes: 98_304,
            failed: vec![FileOutcome {
                file_id: Uuid::from_u128(0x2a61_7b2f_84c7_4f3a_9b20_0064_0000_0011),
                path: PathBuf::from(r"C:\__dcleaner_qa_fixture__\cache\retained.tmp"),
                size: 4_096,
                success: false,
                reason: Some("Retained in this synthetic history preview.".into()),
            }],
            cleaned_ids: vec![
                Uuid::from_u128(0x2a61_7b2f_84c7_4f3a_9b20_0064_0000_0021),
                Uuid::from_u128(0x2a61_7b2f_84c7_4f3a_9b20_0064_0000_0022),
            ],
            cancelled: false,
            uncertain: Vec::new(),
            interrupted: false,
        },
        CleanupResult {
            id: Uuid::from_u128(0x2a61_7b2f_84c7_4f3a_9b20_0000_0000_0002),
            date: "2026-10-13T11:05:00+08:00".into(),
            files: 1,
            bytes: 12_288,
            failed: Vec::new(),
            cleaned_ids: vec![Uuid::from_u128(0x2a61_7b2f_84c7_4f3a_9b20_0000_0000_0023)],
            cancelled: false,
            uncertain: vec![PathBuf::from(
                r"C:\__dcleaner_qa_fixture__\cache\uncertain.tmp",
            )],
            interrupted: true,
        },
    ]
}
