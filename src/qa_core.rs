use super::*;

#[cfg(debug_assertions)]
impl App {
    pub(crate) fn seed_core_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Core QA fixtures require isolated fixture mode.".into());
        }
        if !matches!(
            case,
            "clean-ready"
                | "clean-info"
                | "clean-success"
                | "clean-failure"
                | "clean-history-unavailable"
                | "clean-progress"
                | "clean-empty"
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
        self.clean_registry = false;
        self.clean_bin = false;
        self.custom_partial_acknowledged = false;
        self.selected.clear();
        self.error = None;
        self.notice = None;
        self.progress.clear();
        self.history_readable = true;
        self.settings_readable = true;

        match case {
            "clean-ready"
            | "clean-info"
            | "clean-success"
            | "clean-failure"
            | "clean-progress"
            | "clean-history-unavailable" => {
                self.page = Page::Clean;
                self.analysis = None;
                self.custom_analysis = None;
                self.categories = [
                    ("temp", "Temporary files", "Windows"),
                    ("crashes", "Crash reports", "Windows"),
                    ("chrome", "Google Chrome cache", "Applications"),
                    ("edge", "Microsoft Edge cache", "Applications"),
                    ("firefox", "Mozilla Firefox cache", "Applications"),
                ]
                .into_iter()
                .map(|(id, name, group)| dcleaner::domain::Category {
                    cache_root_scopes: Default::default(),
                    id: id.into(),
                    name: name.into(),
                    group: group.into(),
                    description: "In-memory layout fixture; no filesystem roots.".into(),
                    roots: Vec::new(),
                })
                .collect();
                self.prefs.selected_categories = vec!["temp".into(), "crashes".into()];
                self.message_page = Page::Clean;
                match case {
                    "clean-info" => self.set_notice("Some locations could not be scanned. Review the omissions before cleaning.".into()),
                    "clean-success" => {
                        self.set_notice("The requested app update is verified. This is a synthetic layout preview.".into());
                        self.notice_kind = theme::StatusKind::Success;
                    },
                    "clean-failure" => self.error = Some("The selected location is unavailable. Your files have not been changed.".into()),
                    "clean-history-unavailable" => {
                        self.error = Some("Cleanup stopped: an item outcome is uncertain. Review History for confirmed and uncertain outcomes.".into());
                        self.apply_cleanup_history(Err("A cleanup record is damaged; preserved for recovery. This is a synthetic in-memory preview.".into()));
                    },
                    "clean-progress" => {
                        self.progress = format!("Finding files · 39808 entries · 0 of 4108 files · C:\\Windows\\WinSxS\\{}", "long-fixture-path-".repeat(16));
                    },
                    _ => {},
                }
            }
            "clean-empty" | "clean-populated" | "clean-selected" | "clean-details"
            | "clean-error" => {
                self.page = Page::Clean;
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
                self.categories = self
                    .analysis
                    .iter()
                    .flat_map(|analysis| &analysis.categories)
                    .map(|category| dcleaner::domain::Category {
                        cache_root_scopes: Default::default(),
                        id: category.id.clone(),
                        name: category.name.clone(),
                        group: "Applications".into(),
                        description: "Disposable fixture files for visual review.".into(),
                        roots: Vec::new(),
                    })
                    .collect();
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
