use super::*;
use crate::theme;
#[cfg(debug_assertions)]
use dcleaner::drivers::{
    DeviceInventory, DriverCatalogue, FieldFailure, FieldFailureKind, NativeIssue, SourceReport,
};
use dcleaner::{
    drivers::{
        self, CatalogueState, DeviceId, DeviceOffer, DriverCandidate, DriverDevice,
        DriverDeviceCategory, DriverRestoreIntent, DriverRestoreReceipt, DriverSettings,
        DriverSnapshot, DriverStatus, DriverUpdateIntent, DriverUpdateReceipt, FieldValue,
        InventoryQuality, RebootRequirement, WindowsDriverPlatform,
    },
    effects::EffectHistory,
};
use std::collections::{BTreeMap, BTreeSet};

const MAX_DRIVER_BATCH_OFFERS: usize = 16;
const MAX_RECENT_DRIVER_OPERATIONS: usize = 12;
const DRIVER_RESTORE_PROMPT_FEATURE: &str = "drivers-restore-prompt";

pub(super) struct DriverUi {
    snapshot: Option<DriverSnapshot>,
    attempted: bool,
    intro_fixture: bool,
    loading: bool,
    query: String,
    tab: DriverTab,
    sort: DriverSort,
    descending: bool,
    selected: Option<DeviceId>,
    selected_updates: Vec<SelectedDriverUpdate>,
    dialog: Option<DriverDialog>,
    settings: Option<DriverSettings>,
    settings_error: Option<String>,
    history: Vec<EffectHistory>,
    history_error: Option<String>,
    last_scan_completed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When set, this filters the current inventory down to devices whose
    /// identity matches a recent verified update receipt with a usable backup.
    problem_category_filter: Option<BTreeSet<DriverProblemCategory>>,
    problem_history_result: Option<ProblemHistoryResult>,
    collapsed_groups: BTreeSet<DriverDeviceCategory>,
    #[cfg(debug_assertions)]
    qa_last_category_toggle: Option<String>,
}

impl Default for DriverUi {
    fn default() -> Self {
        Self {
            snapshot: None,
            attempted: false,
            intro_fixture: false,
            loading: false,
            query: String::new(),
            tab: DriverTab::Outdated,
            sort: DriverSort::Release,
            descending: true,
            selected: None,
            selected_updates: Vec::new(),
            dialog: None,
            settings: None,
            settings_error: None,
            history: Vec::new(),
            history_error: None,
            last_scan_completed_at: None,
            problem_category_filter: None,
            problem_history_result: None,
            collapsed_groups: BTreeSet::new(),
            #[cfg(debug_assertions)]
            qa_last_category_toggle: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DriverTab {
    #[default]
    Outdated,
    NoOfferUnknown,
    Deferred,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DriverSort {
    Device,
    Installed,
    CandidateVersion,
    Release,
    State,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DriverProblemCategory {
    Sound,
    MonitorDisplay,
    MouseTracking,
    Camera,
    Printer,
    Keyboard,
    NetworkWifi,
    Computer,
    NotSure,
}

#[derive(Clone)]
enum ProblemHistoryResult {
    Matches {
        categories: BTreeSet<DriverProblemCategory>,
        records_reviewed: usize,
        devices_matched: usize,
    },
    NoRecentMatches {
        categories: BTreeSet<DriverProblemCategory>,
        records_reviewed: usize,
    },
    Unavailable {
        categories: BTreeSet<DriverProblemCategory>,
        history_unreadable: bool,
    },
}

impl DriverProblemCategory {
    const ALL: [Self; 9] = [
        Self::Sound,
        Self::MonitorDisplay,
        Self::MouseTracking,
        Self::Camera,
        Self::Printer,
        Self::Keyboard,
        Self::NetworkWifi,
        Self::Computer,
        Self::NotSure,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Sound => "Sound",
            Self::MonitorDisplay => "Monitor or display",
            Self::MouseTracking => "Mouse or tracking",
            Self::Camera => "Camera",
            Self::Printer => "Printer",
            Self::Keyboard => "Keyboard",
            Self::NetworkWifi => "Network or Wi-Fi",
            Self::Computer => "Computer",
            Self::NotSure => "Not sure",
        }
    }

    fn matches_device(self, category: DriverDeviceCategory) -> bool {
        use DriverDeviceCategory as Device;
        match self {
            Self::Sound => category == Device::Audio,
            Self::MonitorDisplay => matches!(category, Device::Display | Device::Monitor),
            Self::MouseTracking => {
                matches!(category, Device::Mouse | Device::Usb | Device::Bluetooth)
            }
            Self::Camera => category == Device::Camera,
            Self::Printer => matches!(category, Device::Printer | Device::Bluetooth),
            Self::Keyboard => {
                matches!(category, Device::Keyboard | Device::Usb | Device::Bluetooth)
            }
            Self::NetworkWifi => matches!(category, Device::Connectivity | Device::Bluetooth),
            Self::Computer => matches!(
                category,
                Device::Battery
                    | Device::Biometric
                    | Device::Computer
                    | Device::Multifunction
                    | Device::Other
                    | Device::Processor
                    | Device::Storage
                    | Device::System
                    | Device::Usb
            ),
            Self::NotSure => true,
        }
    }
}

#[derive(Clone)]
enum DriverDialog {
    Details(DriverDevice),
    RestoreFormerPrompt {
        suppress_message: bool,
    },
    ProblemCategories(BTreeSet<DriverProblemCategory>),
    Update(DriverUpdateIntent),
    BatchReview(Vec<SelectedDriverUpdate>),
    Restore {
        update_intent: DriverUpdateIntent,
        update_receipt: DriverUpdateReceipt,
        restore_intent: DriverRestoreIntent,
    },
}

#[derive(Clone)]
struct SelectedDriverUpdate {
    intent: DriverUpdateIntent,
    devices: Vec<SelectedDriverDevice>,
}

#[derive(Clone)]
struct SelectedDriverDevice {
    id: DeviceId,
    candidate: drivers::CandidateIdentity,
}

pub(super) struct DriverBatchItemResult {
    intent_id: Uuid,
    display_name: String,
    result: Result<DriverUpdateReceipt, String>,
}

pub(super) enum DriverEvent {
    Loaded {
        snapshot: DriverSnapshot,
        settings: Result<DriverSettings, String>,
        history: Result<Vec<EffectHistory>, String>,
        completed_at: chrono::DateTime<chrono::Utc>,
    },
    UpdateFinished {
        intent_id: Uuid,
        display_name: String,
        result: Result<DriverUpdateReceipt, String>,
    },
    BatchUpdateFinished {
        requested: usize,
        results: Vec<DriverBatchItemResult>,
    },
    RestoreFinished {
        restore_id: Uuid,
        display_name: String,
        result: Result<DriverRestoreReceipt, String>,
    },
}

enum DetailAction {
    Review(DriverUpdateIntent),
    Select(DriverUpdateIntent, DeviceId, bool),
    Restore {
        update_intent: DriverUpdateIntent,
        update_receipt: DriverUpdateReceipt,
        restore_intent: DriverRestoreIntent,
    },
    Ignore(DeviceId, bool),
    Skip(DeviceId, drivers::CandidateIdentity, bool),
    Error(String),
}

impl App {
    #[cfg(debug_assertions)]
    pub(super) fn seed_drivers_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Driver QA fixtures require isolated fixture mode.".into());
        }
        if case == "drivers-intro" {
            self.drivers_ui = DriverUi {
                intro_fixture: true,
                settings: Some(DriverSettings::default()),
                ..DriverUi::default()
            };
            self.error = None;
            self.notice = None;
            self.progress.clear();
            return Ok(());
        }
        let mut ui = DriverUi {
            attempted: true,
            settings: Some(DriverSettings::default()),
            ..DriverUi::default()
        };
        self.error = None;
        self.notice = None;
        self.progress.clear();
        match case {
            "drivers-empty" => ui.snapshot = Some(driver_qa_snapshot(false)),
            "drivers-restore-prompt" => {
                ui.dialog = Some(DriverDialog::RestoreFormerPrompt {
                    suppress_message: false,
                });
                ui.snapshot = Some(driver_qa_snapshot(true));
                ui.tab = DriverTab::NoOfferUnknown;
            }
            "drivers-problem-categories-empty" => {
                ui.dialog = Some(DriverDialog::ProblemCategories(BTreeSet::new()));
                ui.snapshot = Some(driver_qa_snapshot(true));
                ui.tab = DriverTab::NoOfferUnknown;
            }
            "drivers-populated" | "drivers-details" | "drivers-problem-categories" => {
                let snapshot = driver_qa_snapshot(true);
                // The synthetic device has no matching Windows Update offer, so show it under
                // the no-offer / unknown tab instead of hiding it in Outdated.
                ui.tab = DriverTab::NoOfferUnknown;
                if case == "drivers-details" {
                    if let Some(device) = snapshot.inventory.devices.first() {
                        ui.selected = device.id.clone();
                        ui.dialog = Some(DriverDialog::Details(device.clone()));
                    }
                }
                if case == "drivers-problem-categories" {
                    ui.dialog = Some(DriverDialog::ProblemCategories(BTreeSet::from([
                        DriverProblemCategory::Sound,
                        DriverProblemCategory::NetworkWifi,
                    ])));
                }
                ui.snapshot = Some(snapshot);
            }
            "drivers-offered" => {
                ui.snapshot = Some(driver_qa_offered_snapshot());
                ui.tab = DriverTab::Outdated;
            }
            "drivers-no-recent-updates" => {
                let snapshot = driver_qa_recent_snapshot();
                ui.tab = DriverTab::NoOfferUnknown;
                ui.problem_category_filter =
                    Some(BTreeSet::from([DriverProblemCategory::MonitorDisplay]));
                ui.problem_history_result = Some(ProblemHistoryResult::NoRecentMatches {
                    categories: ui.problem_category_filter.clone().unwrap_or_default(),
                    records_reviewed: 0,
                });
                ui.snapshot = Some(snapshot);
            }
            "drivers-recent-updates" => {
                let snapshot = driver_qa_recent_snapshot();
                ui.tab = DriverTab::NoOfferUnknown;
                ui.history = driver_qa_recent_history(&snapshot);
                ui.problem_category_filter =
                    Some(BTreeSet::from([DriverProblemCategory::MonitorDisplay]));
                let categories = ui.problem_category_filter.clone().unwrap_or_default();
                let records_reviewed = ui
                    .history
                    .iter()
                    .filter(|record| record.feature == "drivers")
                    .take(MAX_RECENT_DRIVER_OPERATIONS)
                    .count();
                let devices_matched = snapshot
                    .inventory
                    .devices
                    .iter()
                    .filter(|device| {
                        driver_problem_history_matches(
                            &ui.history,
                            device,
                            &categories,
                            MAX_RECENT_DRIVER_OPERATIONS,
                        )
                    })
                    .count();
                ui.problem_history_result = Some(if devices_matched == 0 {
                    ProblemHistoryResult::NoRecentMatches {
                        categories,
                        records_reviewed,
                    }
                } else {
                    ProblemHistoryResult::Matches {
                        categories,
                        records_reviewed,
                        devices_matched,
                    }
                });
                ui.snapshot = Some(snapshot);
            }
            "drivers-error" => {
                self.error = Some(
                    "Synthetic QA fixture error. No device inventory or update source was queried."
                        .into(),
                );
            }
            _ => return Err(format!("Unsupported Drivers QA fixture: {case}")),
        }
        self.drivers_ui = ui;
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_driver_state(&self) -> serde_json::Value {
        let dialog = match self.drivers_ui.dialog.as_ref() {
            Some(DriverDialog::Details(_)) => Some("details"),
            Some(DriverDialog::RestoreFormerPrompt { .. }) => Some("restore_former_prompt"),
            Some(DriverDialog::ProblemCategories(_)) => Some("problem_categories"),
            Some(DriverDialog::Update(_)) => Some("update_review"),
            Some(DriverDialog::BatchReview(_)) => Some("batch_review"),
            Some(DriverDialog::Restore { .. }) => Some("restore_review"),
            None => None,
        };
        let categories = match self.drivers_ui.dialog.as_ref() {
            Some(DriverDialog::ProblemCategories(categories)) => Some(
                categories
                    .iter()
                    .map(|category| category.label())
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        };
        let filter = self
            .drivers_ui
            .problem_category_filter
            .as_ref()
            .map(|categories| {
                categories
                    .iter()
                    .map(|category| category.label())
                    .collect::<Vec<_>>()
            });
        let problem_history = self
            .drivers_ui
            .problem_history_result
            .as_ref()
            .map(|result| match result {
                ProblemHistoryResult::Matches {
                    records_reviewed,
                    devices_matched,
                    ..
                } => serde_json::json!({
                    "state": "matches",
                    "records_reviewed": records_reviewed,
                    "devices_matched": devices_matched,
                }),
                ProblemHistoryResult::NoRecentMatches {
                    records_reviewed, ..
                } => serde_json::json!({
                    "state": "no_recent_matches",
                    "records_reviewed": records_reviewed,
                }),
                ProblemHistoryResult::Unavailable {
                    history_unreadable, ..
                } => serde_json::json!({
                    "state": "unavailable",
                    "history_unreadable": history_unreadable,
                }),
            });
        let restore_prompt_checked = match self.drivers_ui.dialog.as_ref() {
            Some(DriverDialog::RestoreFormerPrompt { suppress_message }) => Some(*suppress_message),
            _ => None,
        };
        serde_json::json!({
            "tab": driver_tab_name(self.drivers_ui.tab),
            "sort": driver_sort_name(self.drivers_ui.sort),
            "descending": self.drivers_ui.descending,
            "snapshot_present": self.drivers_ui.snapshot.is_some(),
            "device_count": self.drivers_ui.snapshot.as_ref().map_or(0, |snapshot| snapshot.inventory.devices.len()),
            "selected_device": self.drivers_ui.selected.as_ref().map(|id| id.0.as_str()),
            "selected_offer_count": self.drivers_ui.selected_updates.iter().map(|item| item.devices.len()).sum::<usize>(),
            "dialog": dialog,
            "collapsed_categories": self.drivers_ui.collapsed_groups.iter().map(|category| category.label()).collect::<Vec<_>>(),
            "problem_categories": categories,
            "problem_filter": filter,
            "problem_history": problem_history,
            "restore_prompt_checked": restore_prompt_checked,
            "restore_prompt_suppressed": self.feature_seen(DRIVER_RESTORE_PROMPT_FEATURE),
            "last_category_toggle": self.drivers_ui.qa_last_category_toggle.as_deref(),
            "worker_active": self.worker.is_some(),
            "fixture_mode": self.qa_fixture_mode(),
        })
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_driver_action_precondition(&self, label: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Driver action checks require isolated fixture mode.".into());
        }
        let has_snapshot = self.drivers_ui.snapshot.is_some();
        let dialog = self.drivers_ui.dialog.as_ref();
        let can_dismiss = !self.busy();
        let valid = match label {
            "Outdated drivers" | "No offer / unknown" | "Skipped & Ignored" => has_snapshot,
            "Sort Drivers" | "Sort Installed" | "Sort New version" | "Sort Released"
            | "Sort State" => has_snapshot,
            "Collapse Display" => {
                has_snapshot
                    && !self
                        .drivers_ui
                        .collapsed_groups
                        .contains(&DriverDeviceCategory::Display)
            }
            "Expand Display" => {
                has_snapshot
                    && self
                        .drivers_ui
                        .collapsed_groups
                        .contains(&DriverDeviceCategory::Display)
            }
            "Fix a problem" => {
                can_dismiss && dialog.is_none() && (has_snapshot || self.drivers_intro_active())
            }
            "Don't show this message again" => {
                can_dismiss && matches!(dialog, Some(DriverDialog::RestoreFormerPrompt { .. }))
            }
            "Find specific drivers" | "Not now" => {
                can_dismiss && matches!(dialog, Some(DriverDialog::RestoreFormerPrompt { .. }))
            }
            "Sound" | "Network" | "Network or Wi-Fi" => {
                can_dismiss && matches!(dialog, Some(DriverDialog::ProblemCategories(_)))
            }
            "Show relevant drivers" => {
                can_dismiss
                    && matches!(dialog, Some(DriverDialog::ProblemCategories(categories)) if !categories.is_empty())
            }
            "Cancel" | "Close" | "Close dialog" => can_dismiss && dialog.is_some(),
            "Clear history filter" => {
                can_dismiss && self.drivers_ui.problem_category_filter.is_some()
            }
            "Select this exact Windows Update offer" => {
                can_dismiss
                    && self.drivers_ui.tab == DriverTab::Outdated
                    && has_snapshot
                    && self.drivers_ui.snapshot.as_ref().is_some_and(|snapshot| {
                        snapshot
                            .inventory
                            .devices
                            .iter()
                            .any(|device| self.single_driver_offer_intent(device).is_some())
                    })
            }
            "Update selected" => can_dismiss && !self.drivers_ui.selected_updates.is_empty(),
            "Review restore" => {
                can_dismiss
                    && matches!(dialog, Some(DriverDialog::Details(device)) if self.driver_selected_restore_intent_with_limit(device, MAX_RECENT_DRIVER_OPERATIONS).is_some())
            }
            "More" | "More options" => {
                can_dismiss
                    && has_snapshot
                    && self
                        .drivers_ui
                        .snapshot
                        .as_ref()
                        .is_some_and(|snapshot| !snapshot.inventory.devices.is_empty())
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(format!(
                "Driver action precondition is not satisfied: {label}"
            ))
        }
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_driver_action_state(&self, label: &str) -> Result<serde_json::Value, String> {
        let state = self.qa_driver_state();
        let valid = match label {
            "Outdated drivers" | "No offer / unknown" | "Skipped & Ignored" => {
                state["tab"] == label
            }
            "Collapse Display" => self
                .drivers_ui
                .collapsed_groups
                .contains(&DriverDeviceCategory::Display),
            "Expand Display" => !self
                .drivers_ui
                .collapsed_groups
                .contains(&DriverDeviceCategory::Display),
            "Sort Drivers" => state["sort"] == "Drivers",
            "Sort Installed" => state["sort"] == "Installed",
            "Sort New version" => state["sort"] == "New version",
            "Sort Released" => state["sort"] == "Released",
            "Sort State" => state["sort"] == "State",
            "Fix a problem" => {
                state["dialog"] == "restore_former_prompt"
                    || state["dialog"] == "problem_categories"
            }
            "Don't show this message again" => {
                state["dialog"] == "restore_former_prompt"
                    && state["restore_prompt_checked"] == true
            }
            "Find specific drivers" => state["dialog"] == "problem_categories",
            "Not now" | "Close" | "Close dialog" | "Cancel" => state["dialog"].is_null(),
            "Sound" | "Network" | "Network or Wi-Fi" => {
                let expected = if label == "Network" {
                    "Network or Wi-Fi"
                } else {
                    label
                };
                state["dialog"] == "problem_categories" && state["last_category_toggle"] == expected
            }
            "Show relevant drivers" => {
                state["dialog"].is_null()
                    && !state["problem_filter"].is_null()
                    && !state["problem_history"].is_null()
            }
            "Clear history filter" => state["problem_filter"].is_null(),
            "Select this exact Windows Update offer" => {
                state["selected_offer_count"].as_u64().unwrap_or(0) > 0
            }
            "Update selected" => state["dialog"] == "batch_review",
            "Review restore" => state["dialog"] == "restore_review",
            "More" | "More options" => state["dialog"] == "details",
            _ => false,
        };
        if valid {
            Ok(state)
        } else {
            Err(format!(
                "Driver action did not reach its expected state: {label}"
            ))
        }
    }

    pub(super) fn drivers_event(&mut self, event: DriverEvent) {
        match event {
            DriverEvent::Loaded {
                snapshot,
                settings,
                history,
                completed_at,
            } => {
                self.worker = None;
                self.drivers_ui.loading = false;
                self.drivers_ui.attempted = true;
                self.drivers_ui.problem_category_filter = None;
                self.drivers_ui.problem_history_result = None;
                self.drivers_ui.snapshot = Some(snapshot);
                self.drivers_ui.last_scan_completed_at = Some(completed_at);
                match settings {
                    Ok(settings) => {
                        self.drivers_ui.settings = Some(settings);
                        self.drivers_ui.settings_error = None;
                    }
                    Err(error) => {
                        self.drivers_ui.settings = None;
                        self.drivers_ui.settings_error = Some(error);
                    }
                }
                match history {
                    Ok(history) => {
                        self.drivers_ui.history = history;
                        self.drivers_ui.history_error = None;
                    }
                    Err(error) => {
                        self.drivers_ui.history.clear();
                        self.drivers_ui.history_error = Some(error);
                    }
                }
                self.revalidate_selected_driver_offers();
                let selected_exists = self.drivers_ui.selected.as_ref().is_some_and(|id| {
                    self.drivers_ui.snapshot.as_ref().is_some_and(|snapshot| {
                        snapshot
                            .inventory
                            .devices
                            .iter()
                            .any(|device| device.id.as_ref() == Some(id))
                    })
                });
                if !selected_exists {
                    self.drivers_ui.selected = None;
                }
            }
            DriverEvent::UpdateFinished {
                intent_id,
                display_name,
                result,
            } => {
                self.worker = None;
                self.drivers_ui.dialog = None;
                self.drivers_ui.attempted = false;
                match result {
                    Ok(receipt) if receipt.intent_id == intent_id => {
                        self.error = None;
                        self.notice = Some(match receipt.phase {
                            drivers::DriverEffectPhase::Verified => format!(
                                "Windows verified the reviewed driver update for {display_name}. A signed package backup is recorded.{}",
                                reboot_note(receipt.reboot)
                            ),
                            drivers::DriverEffectPhase::AwaitingRestart => format!(
                                "Windows accepted the reviewed driver update for {display_name}, but requires a restart before verification. DCleaner will not restart Windows automatically.{}",
                                reboot_note(receipt.reboot)
                            ),
                            _ => format!(
                                "Windows returned an unverified result for {display_name}. Review Driver Updater history before retrying."
                            ),
                        });
                    }
                    Ok(_) => {
                        self.error = Some(
                            "The driver-update receipt did not match the reviewed intent. The outcome is uncertain; review history before retrying.".into(),
                        );
                    }
                    Err(error) => {
                        self.error = Some(format!(
                            "The reviewed driver update for {display_name} was not confirmed: {error}. Review history before retrying if Windows began the operation."
                        ));
                    }
                }
            }
            DriverEvent::BatchUpdateFinished { requested, results } => {
                self.worker = None;
                self.drivers_ui.dialog = None;
                self.drivers_ui.attempted = false;
                self.drivers_ui.selected_updates.clear();
                let mut completed = 0usize;
                let mut awaiting_restart = None;
                let mut failure = None;
                for item in results {
                    match item.result {
                        Ok(receipt) if receipt.intent_id == item.intent_id => match receipt.phase {
                            drivers::DriverEffectPhase::Verified => completed += 1,
                            drivers::DriverEffectPhase::AwaitingRestart => {
                                completed += 1;
                                awaiting_restart = Some(item.display_name);
                                break;
                            }
                            _ => {
                                failure = Some(format!(
                                    "Windows returned an unverified result for {}.",
                                    item.display_name
                                ));
                                break;
                            }
                        },
                        Ok(_) => {
                            failure = Some(format!(
                                "The receipt for {} did not match its reviewed intent.",
                                item.display_name
                            ));
                            break;
                        }
                        Err(error) => {
                            failure = Some(format!(
                                "The update for {} was not confirmed: {error}.",
                                item.display_name
                            ));
                            break;
                        }
                    }
                }
                if let Some(display_name) = awaiting_restart {
                    self.error = None;
                    self.notice = Some(format!(
                        "Windows accepted {completed} of {requested} reviewed driver updates and requires a restart for {display_name}. The remaining offers were not started. DCleaner will not restart Windows; rescan and review remaining devices after restart."
                    ));
                } else if let Some(failure) = failure {
                    self.error = Some(format!(
                        "{completed} of {requested} reviewed driver updates were verified. The batch stopped: {failure} Review Driver Updater history before retrying."
                    ));
                } else if completed == requested {
                    self.error = None;
                    self.notice = Some(drivers::representative_batch_completion_notice(completed));
                } else {
                    self.error = Some(format!(
                        "Only {completed} of {requested} reviewed driver updates returned results. The outcome is uncertain; review Driver Updater history before retrying."
                    ));
                }
            }
            DriverEvent::RestoreFinished {
                restore_id,
                display_name,
                result,
            } => {
                self.worker = None;
                self.drivers_ui.dialog = None;
                self.drivers_ui.attempted = false;
                match result {
                    Ok(receipt) if receipt.restore_id == restore_id => {
                        self.error = None;
                        self.notice = Some(match receipt.phase {
                            drivers::DriverEffectPhase::Verified => format!(
                                "Windows verified restoration of the saved driver for {display_name}.{}",
                                reboot_note(receipt.reboot)
                            ),
                            drivers::DriverEffectPhase::AwaitingRestart => format!(
                                "Windows staged the saved driver for {display_name}; a restart is required before verification. DCleaner will not restart Windows automatically.{}",
                                reboot_note(receipt.reboot)
                            ),
                            _ => format!(
                                "Windows did not verify restoration for {display_name}. Review Driver Updater history before retrying."
                            ),
                        });
                    }
                    Ok(_) => {
                        self.error = Some(
                            "The driver-restore receipt did not match the reviewed intent. The outcome is uncertain; review history before retrying.".into(),
                        );
                    }
                    Err(error) => {
                        self.error = Some(format!(
                            "The saved driver for {display_name} was not confirmed as restored: {error}. Review history before retrying if Windows began the operation."
                        ));
                    }
                }
            }
        }
    }

    pub(super) fn drivers_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if self.drivers_intro_active() {
            if self.feature_intro(
                ui,
                t,
                "drivers",
                "Review your device drivers",
                "Check detected devices and matching Windows Update offers before deciding whether to update a driver.",
                &[
                    (
                        theme::Icon::Driver,
                        "Easy to review",
                        "See the detected device, its current driver details, and any offer Windows actually returns.",
                    ),
                    (
                        theme::Icon::Info,
                        "Check the change first",
                        "Review the exact device and signed offer, plus backup and restart requirements, before confirming a supported update.",
                    ),
                ],
            ) {
                self.start_driver_scan(ctx);
            }
            return;
        }
        if !self.drivers_ui.attempted && !self.busy() && !self.qa_fixture_mode() {
            self.begin_driver_load(ctx);
        }

        if self.drivers_ui.problem_category_filter.is_none() {
            self.driver_tabs(ui, t);
        } else {
            ui.label(RichText::new("Recent driver updates").family(theme::semibold()));
            ui.add_space(4.);
        }
        ui.add_space(7.);
        if self.drivers_ui.problem_category_filter.is_none() && self.drivers_ui.snapshot.is_some() {
            self.driver_results_heading(ui, t);
            ui.add_space(7.);
        }
        self.driver_search(ui, t);
        ui.add_space(6.);

        if self.drivers_ui.loading {
            ui.horizontal(|ui| {
                ui.spinner();
                theme::muted(
                    ui,
                    "Reading present devices and Windows Update Agent offers. This native search cannot be cancelled once started.",
                    t,
                );
            });
            ui.add_space(5.);
        }

        if let Some(snapshot) = self.drivers_ui.snapshot.clone() {
            self.driver_problem_history_status(ui, t, &snapshot);
            ui.add_space(7.);
            let history_result_has_rows = !matches!(
                self.drivers_ui.problem_history_result.as_ref(),
                Some(
                    ProblemHistoryResult::NoRecentMatches { .. }
                        | ProblemHistoryResult::Unavailable { .. }
                )
            );
            if history_result_has_rows {
                self.driver_table(ui, t, ctx, &snapshot);
            }
            ui.add_space(7.);
            self.driver_sources_panel(ui, t, &snapshot);
            ui.add_space(8.);
            self.driver_history_panel(ui, t);
        } else if self.drivers_ui.loading {
            theme::card(t).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Windows is reading the device inventory and querying its configured update source…");
                });
            });
        } else if self.drivers_ui.attempted {
            status_card(
                ui,
                t,
                "Driver inventory unavailable",
                "No device or update result was returned. Use Scan again to try again.",
            );
        }
        if let Some(error) = self.drivers_ui.settings_error.as_deref() {
            ui.add_space(7.);
            status_card(
                ui,
                t,
                "Saved driver choices could not be read",
                &format!(
                    "{error} Skip and ignore controls are disabled. Driver actions are also blocked until saved choices can be read safely."
                ),
            );
        }
        if let Some(error) = self.drivers_ui.history_error.as_deref() {
            ui.add_space(7.);
            status_card(
                ui,
                t,
                "Driver operation history unavailable",
                &format!(
                    "{error} Saved driver changes cannot be offered for restore until history is readable."
                ),
            );
        }
    }

    pub(super) fn drivers_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if self.drivers_intro_active() {
            let compact = !self.feature_intro_wide(ctx);
            let mut start = false;
            let mut fix_problem = false;
            ui.horizontal_wrapped(|ui| {
                fix_problem = theme::secondary(ui, "Fix a problem", !self.busy());
                theme::muted(
                    ui,
                    if compact {
                        "Start a read-only device and driver scan"
                    } else {
                        "Choose Scan now in the introduction to read device and driver offers"
                    },
                    t,
                );
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    if compact && theme::primary(ui, "Scan now", t, !self.busy()) {
                        start = true;
                    }
                });
            });
            if fix_problem {
                self.open_driver_problem_flow();
            }
            if start {
                self.start_driver_scan(ctx);
            }
            return;
        }
        let busy = self.busy();
        let selected_updates = self.drivers_ui.selected_updates.clone();
        let last_scan = self.driver_last_scan_label();
        let mut refresh = false;
        let mut review_selected = false;
        let mut fix_problem = false;

        ui.horizontal_wrapped(|ui| {
            if theme::secondary(ui, "Fix a problem", !busy) {
                fix_problem = true;
            }
            theme::muted(
                ui,
                format!(
                    "{} selected · {last_scan}",
                    selected_updates
                        .iter()
                        .map(|update| update.devices.len())
                        .sum::<usize>()
                ),
                t,
            );
            ui.with_layout(egui::Layout::right_to_left(Align::Center), |actions| {
                if theme::primary(
                    actions,
                    "Update selected",
                    t,
                    !busy && !selected_updates.is_empty(),
                ) {
                    review_selected = true;
                }
                if theme::secondary(actions, "Scan again", !busy) {
                    refresh = true;
                }
            });
        });

        if refresh {
            self.drivers_ui.attempted = false;
            self.begin_driver_load(ctx);
        }
        if fix_problem {
            self.open_driver_problem_flow();
        }
        if review_selected {
            self.drivers_ui.dialog = Some(DriverDialog::BatchReview(selected_updates));
        }
    }

    fn open_driver_problem_flow(&mut self) {
        self.drivers_ui.dialog = Some(if self.feature_seen(DRIVER_RESTORE_PROMPT_FEATURE) {
            DriverDialog::ProblemCategories(BTreeSet::new())
        } else {
            DriverDialog::RestoreFormerPrompt {
                suppress_message: false,
            }
        });
    }

    pub(super) fn drivers_dialog(&mut self, ctx: &egui::Context) {
        let Some(dialog) = self.drivers_ui.dialog.clone() else {
            return;
        };
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            if !self.busy() || matches!(dialog, DriverDialog::Details(_)) {
                self.drivers_ui.dialog = None;
            }
            return;
        }
        let t = theme::tokens(self.prefs.dark);
        match dialog {
            DriverDialog::Details(device) => {
                let mut close = false;
                let mut action = None;
                let mut review_restore = false;
                let restore_option = if self.drivers_ui.problem_category_filter.is_some() {
                    self.driver_selected_restore_intent_with_limit(
                        &device,
                        MAX_RECENT_DRIVER_OPERATIONS,
                    )
                } else {
                    self.driver_selected_restore_intent(&device)
                };
                let width = (ctx.content_rect().width() - 32.).min(590.).max(300.);
                let max_height = (ctx.content_rect().height() - 235.).clamp(130., 520.);
                let response = egui::Modal::new(egui::Id::new("driver-device-details"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(width);
                        close |= driver_device_heading(ui, &device, true);
                        ui.add_space(5.);
                        egui::ScrollArea::vertical()
                            .max_height(max_height)
                            .auto_shrink([false, true])
                            .show(ui, |body| {
                                action = self.driver_details(body, t, &device);
                            });
                        ui.add_space(5.);
                        ui.separator();
                        ui.horizontal(|footer| {
                            if let Some(device_id) = device.id.as_ref() {
                                let ignored = self
                                    .drivers_ui
                                    .settings
                                    .as_ref()
                                    .is_some_and(|settings| settings.is_ignored(device_id));
                                if theme::secondary(
                                    footer,
                                    if ignored {
                                        "Stop ignoring updates"
                                    } else {
                                        "Ignore updates"
                                    },
                                    !self.busy()
                                        && self.drivers_ui.settings.is_some()
                                        && self.drivers_ui.settings_error.is_none(),
                                ) {
                                    action =
                                        Some(DetailAction::Ignore(device_id.clone(), !ignored));
                                }
                            }
                            footer.with_layout(Layout::right_to_left(Align::Center), |actions| {
                                if restore_option.is_some() {
                                    review_restore =
                                        theme::primary(actions, "Review restore", t, !self.busy());
                                    close |= theme::secondary(actions, "Close", true);
                                } else {
                                    close |= theme::primary(actions, "Close", t, true);
                                }
                            });
                        });
                    });
                let dismissed = close || response.should_close();
                if dismissed {
                    self.drivers_ui.dialog = None;
                }
                if review_restore && !dismissed {
                    action =
                        restore_option.map(|(update_intent, update_receipt, restore_intent)| {
                            DetailAction::Restore {
                                update_intent,
                                update_receipt,
                                restore_intent,
                            }
                        });
                }
                match action {
                    Some(DetailAction::Review(intent)) => {
                        self.drivers_ui.dialog = Some(DriverDialog::Update(intent));
                    }
                    Some(DetailAction::Select(intent, device_id, selected)) => {
                        self.set_driver_offer_selected(intent, device_id, selected);
                    }
                    Some(DetailAction::Restore {
                        update_intent,
                        update_receipt,
                        restore_intent,
                    }) => {
                        self.drivers_ui.dialog = Some(DriverDialog::Restore {
                            update_intent,
                            update_receipt,
                            restore_intent,
                        });
                    }
                    Some(DetailAction::Ignore(id, ignored)) => {
                        self.set_driver_ignored(id, ignored);
                    }
                    Some(DetailAction::Skip(id, candidate, skipped)) => {
                        self.set_driver_skipped(id, candidate, skipped);
                    }
                    Some(DetailAction::Error(error)) => self.error = Some(error),
                    None => {}
                }
            }
            DriverDialog::RestoreFormerPrompt {
                mut suppress_message,
            } => {
                let mut find_specific = false;
                let mut close = false;
                let width = (ctx.content_rect().width() - 32.).min(480.).max(300.);
                let response = egui::Modal::new(egui::Id::new("driver-restore-former-prompt"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(width);
                        close |= driver_dialog_heading(
                            ui,
                            "Want to restore former drivers?",
                            true,
                        );
                        ui.add_space(8.);
                        ui.label("If you're experiencing new issues after a recent update, restoring your drivers back to a previous version could help. Please note that it's not guaranteed to fix your issue.");
                        ui.add_space(7.);
                        theme::checkbox(
                            ui,
                            &mut suppress_message,
                            "Don't show this message again",
                            true,
                        );
                        ui.add_space(12.);
                        ui.horizontal_wrapped(|actions| {
                            if theme::secondary(actions, "Not now", true) {
                                close = true;
                            }
                            if theme::primary(actions, "Find specific drivers", t, true) {
                                find_specific = true;
                            }
                        });
                    });
                if find_specific {
                    if suppress_message {
                        self.mark_feature_seen(DRIVER_RESTORE_PROMPT_FEATURE);
                    }
                    self.drivers_ui.dialog = Some(DriverDialog::ProblemCategories(BTreeSet::new()));
                } else if close || response.should_close() {
                    self.drivers_ui.dialog = None;
                } else {
                    self.drivers_ui.dialog =
                        Some(DriverDialog::RestoreFormerPrompt { suppress_message });
                }
            }
            DriverDialog::ProblemCategories(mut selected) => {
                let mut show_relevant = false;
                let mut close = false;
                let width = (ctx.content_rect().width() - 32.).min(520.).max(300.);
                let max_height = (ctx.content_rect().height() - 160.).clamp(210., 620.);
                let response = egui::Modal::new(egui::Id::new("driver-problem-categories"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(width);
                        close |= driver_dialog_heading(
                            ui,
                            "What are you experiencing issues with?",
                            true,
                        );
                        ui.add_space(6.);
                        theme::muted(
                            ui,
                            "Choose categories to search recent saved driver updates.",
                            t,
                        );
                        ui.add_space(8.);
                        egui::ScrollArea::vertical()
                            .max_height(max_height)
                            .auto_shrink([false, true])
                            .show(ui, |body| {
                                for category in DriverProblemCategory::ALL {
                                    let mut checked = selected.contains(&category);
                                    let response =
                                        theme::checkbox(body, &mut checked, category.label(), true);
                                    #[cfg(debug_assertions)]
                                    if self.qa_fixture_mode() && response.changed() {
                                        self.drivers_ui.qa_last_category_toggle =
                                            Some(category.label().to_owned());
                                    }
                                    if response.changed() {
                                        if checked {
                                            selected.insert(category);
                                        } else {
                                            selected.remove(&category);
                                        }
                                    }
                                }
                            });
                        ui.add_space(8.);
                        ui.horizontal_wrapped(|actions| {
                            if theme::secondary(actions, "Cancel", true) {
                                close = true;
                            }
                            if theme::primary(
                                actions,
                                "Show relevant drivers",
                                t,
                                !selected.is_empty(),
                            ) {
                                show_relevant = true;
                            }
                        });
                    });
                if show_relevant {
                    let result = self.driver_problem_history_result(&selected);
                    self.drivers_ui.problem_category_filter = Some(selected);
                    self.drivers_ui.problem_history_result = Some(result);
                    self.drivers_ui.dialog = None;
                } else if close || response.should_close() {
                    self.drivers_ui.dialog = None;
                } else {
                    self.drivers_ui.dialog = Some(DriverDialog::ProblemCategories(selected));
                }
            }
            DriverDialog::Update(intent) => {
                let mut accept = false;
                let mut close = false;
                let can_dismiss = !self.busy();
                let width = (ctx.content_rect().width() - 32.).min(560.).max(300.);
                let body_height = (ctx.content_rect().height() - 180.).clamp(150., 560.);
                let response = egui::Modal::new(egui::Id::new("driver-update-review"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(width);
                        close |= driver_dialog_heading(ui, "Review driver update", can_dismiss);
                        ui.add_space(7.);
                        egui::ScrollArea::vertical()
                            .max_height(body_height)
                            .auto_shrink([false, true])
                            .show(ui, |body| self.driver_update_review(body, t, &intent));
                        ui.add_space(7.);
                        ui.separator();
                        ui.add_space(7.);
                        ui.horizontal_wrapped(|actions| {
                            if theme::secondary(actions, "Cancel", can_dismiss) {
                                close = true;
                            }
                            if theme::primary(
                                actions,
                                "Install reviewed driver",
                                t,
                                can_dismiss
                                    && self.drivers_ui.settings_error.is_none()
                                    && self.driver_intent_can_apply(&intent)
                                    && !self.qa_fixture_mode()
                                    && drivers::supported_update_actions().is_ok(),
                            ) {
                                accept = true;
                            }
                        });
                    });
                if can_dismiss && (close || response.should_close()) {
                    self.drivers_ui.dialog = None;
                } else if can_dismiss && accept {
                    self.begin_driver_update(intent, ctx);
                }
            }
            DriverDialog::BatchReview(selected_updates) => {
                let mut accept = false;
                let mut close = false;
                let can_dismiss = !self.busy();
                let can_apply = can_dismiss && self.driver_batch_can_apply(&selected_updates);
                let width = (ctx.content_rect().width() - 32.).min(600.).max(300.);
                let body_height = (ctx.content_rect().height() - 180.).clamp(150., 560.);
                let response = egui::Modal::new(egui::Id::new("driver-batch-review"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(width);
                        close |= driver_dialog_heading(
                            ui,
                            &format!("Review {} selected offers", selected_updates.len()),
                            can_dismiss,
                        );
                        ui.add_space(7.);
                        egui::ScrollArea::vertical()
                            .max_height(body_height)
                            .auto_shrink([false, true])
                            .show(ui, |body| {
                                self.driver_batch_review(body, t, &selected_updates)
                            });
                        ui.add_space(7.);
                        ui.separator();
                        ui.add_space(7.);
                        ui.horizontal_wrapped(|actions| {
                            if theme::secondary(actions, "Cancel", can_dismiss) {
                                close = true;
                            }
                            if theme::primary(actions, "Install reviewed updates", t, can_apply) {
                                accept = true;
                            }
                        });
                    });
                if can_dismiss && (close || response.should_close()) {
                    self.drivers_ui.dialog = None;
                } else if can_apply && accept {
                    self.begin_driver_batch(selected_updates, ctx);
                }
            }
            DriverDialog::Restore {
                update_intent,
                update_receipt,
                restore_intent,
            } => {
                let mut accept = false;
                let mut close = false;
                let can_dismiss = !self.busy();
                let width = (ctx.content_rect().width() - 32.).min(560.).max(300.);
                let body_height = (ctx.content_rect().height() - 180.).clamp(150., 560.);
                let response = egui::Modal::new(egui::Id::new("driver-restore-review"))
                    .frame(theme::dialog_frame(t))
                    .show(ctx, |ui| {
                        ui.set_width(width);
                        close |= driver_dialog_heading(ui, "Review driver restore", can_dismiss);
                        ui.add_space(7.);
                        egui::ScrollArea::vertical()
                            .max_height(body_height)
                            .auto_shrink([false, true])
                            .show(ui, |body| {
                                theme::muted(
                                    body,
                                    "DCleaner will stage the exact signed package saved before the verified update, then re-read this device. Nothing changes until you confirm.",
                                    t,
                                );
                                body.add_space(10.);
                                detail(
                                    body,
                                    "Device",
                                    &self.driver_display_name(&update_intent),
                                    t,
                                );
                                detail(
                                    body,
                                    "Device instance identity",
                                    &update_intent.device_instance_id,
                                    t,
                                );
                                detail(
                                    body,
                                    "Driver to restore",
                                    &update_receipt.original_state.version,
                                    t,
                                );
                                detail(
                                    body,
                                    "Original provider",
                                    &update_receipt.original_state.provider,
                                    t,
                                );
                                detail(
                                    body,
                                    "Original INF",
                                    &update_receipt.original_state.inf,
                                    t,
                                );
                                detail(
                                    body,
                                    "Saved package",
                                    &restore_intent.backup.relative_directory,
                                    t,
                                );
                                body.add_space(8.);
                                theme::muted(
                                    body,
                                    "The restore is revalidated against the current device and saved receipt. If Windows requires a restart, DCleaner will leave that decision to you.",
                                    t,
                                );
                            });
                        ui.add_space(7.);
                        ui.separator();
                        ui.add_space(7.);
                        ui.horizontal_wrapped(|actions| {
                            if theme::secondary(actions, "Cancel", can_dismiss) {
                                close = true;
                            }
                            if theme::primary(
                                actions,
                                "Restore saved driver",
                                t,
                                can_dismiss
                                    && !self.qa_fixture_mode()
                                    && drivers::supported_update_actions().is_ok(),
                            ) {
                                accept = true;
                            }
                        });
                    });
                if can_dismiss && (close || response.should_close()) {
                    self.drivers_ui.dialog = None;
                } else if can_dismiss && accept {
                    self.begin_driver_restore(update_intent, update_receipt, restore_intent, ctx);
                }
            }
        }
    }

    fn begin_driver_load(&mut self, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        self.drivers_ui.attempted = true;
        self.drivers_ui.loading = true;
        self.drivers_ui.problem_category_filter = None;
        self.drivers_ui.problem_history_result = None;
        self.progress =
            "Reading present devices and the configured Windows Update Agent source".into();
        let root = self.data_dir.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let repaint = ctx.clone();
        thread::spawn(move || {
            let settings = drivers::load_settings(&root).map_err(|error| error.to_string());
            let mut manager = drivers::DriverManager::new(WindowsDriverPlatform);
            let snapshot = manager.scan();
            let completed_at = chrono::Utc::now();
            let history = drivers::operation_history(&root);
            let _ = tx.send(Event::Drivers(DriverEvent::Loaded {
                snapshot,
                settings,
                history,
                completed_at,
            }));
            repaint.request_repaint();
        });
    }

    fn drivers_intro_active(&self) -> bool {
        if self.qa_fixture_mode() {
            self.drivers_ui.intro_fixture
        } else {
            !self.feature_seen("drivers")
        }
    }

    fn start_driver_scan(&mut self, ctx: &egui::Context) {
        self.mark_feature_seen("drivers");
        self.begin_driver_load(ctx);
    }

    fn begin_driver_update(&mut self, intent: DriverUpdateIntent, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        self.drivers_ui.selected_updates.retain(|selected| {
            !drivers::same_wua_update(&selected.intent.candidate, &intent.candidate)
        });
        let display_name = self.driver_display_name(&intent);
        self.drivers_ui.dialog = None;
        self.progress = "Windows is preparing the reviewed driver change. This phase cannot be cancelled; no automatic restart will occur.".into();
        self.error = None;
        let root = self.data_dir.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let repaint = ctx.clone();
        thread::spawn(move || {
            let mut platform = WindowsDriverPlatform;
            let result = drivers::apply_reviewed_update(&root, &intent, &mut platform)
                .map_err(|error| error.to_string());
            let _ = tx.send(Event::Drivers(DriverEvent::UpdateFinished {
                intent_id: intent.intent_id,
                display_name,
                result,
            }));
            repaint.request_repaint();
        });
    }

    fn begin_driver_batch(
        &mut self,
        selected_updates: Vec<SelectedDriverUpdate>,
        ctx: &egui::Context,
    ) {
        if self.busy() || self.qa_fixture_mode() || !self.driver_batch_can_apply(&selected_updates)
        {
            return;
        }
        let items: Vec<(DriverUpdateIntent, String)> = selected_updates
            .iter()
            .filter_map(|selected| {
                Some((
                    selected.intent.clone(),
                    self.driver_selected_group_label(selected),
                ))
            })
            .collect();
        if items.len() != selected_updates.len() || items.is_empty() {
            self.error = Some(
                "A selected device or exact Windows Update offer is no longer available. Refresh and review the selection again.".into(),
            );
            self.drivers_ui.dialog = None;
            return;
        }

        let requested = items.len();
        self.drivers_ui.dialog = None;
        self.progress = format!(
            "Windows is applying up to {requested} reviewed driver offers sequentially. No percentage is available; the batch stops on an unverified result or restart requirement."
        );
        self.error = None;
        let root = self.data_dir.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let repaint = ctx.clone();
        thread::spawn(move || {
            let mut platform = WindowsDriverPlatform;
            let mut results = Vec::with_capacity(requested);
            for (intent, display_name) in items {
                let operation_result =
                    drivers::apply_reviewed_update(&root, &intent, &mut platform);
                let continue_batch =
                    drivers::should_continue_driver_batch(intent.intent_id, &operation_result);
                let result = operation_result.map_err(|error| error.to_string());
                results.push(DriverBatchItemResult {
                    intent_id: intent.intent_id,
                    display_name,
                    result,
                });
                if !continue_batch {
                    break;
                }
            }
            let _ = tx.send(Event::Drivers(DriverEvent::BatchUpdateFinished {
                requested,
                results,
            }));
            repaint.request_repaint();
        });
    }

    fn begin_driver_restore(
        &mut self,
        update_intent: DriverUpdateIntent,
        update_receipt: DriverUpdateReceipt,
        restore_intent: DriverRestoreIntent,
        ctx: &egui::Context,
    ) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        let display_name = self.driver_display_name(&update_intent);
        self.drivers_ui.dialog = None;
        self.progress = "Windows is staging the reviewed saved driver. This phase cannot be cancelled; no automatic restart will occur.".into();
        self.error = None;
        let root = self.data_dir.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        let repaint = ctx.clone();
        thread::spawn(move || {
            let mut platform = WindowsDriverPlatform;
            let result = drivers::apply_reviewed_restore(
                &root,
                &update_intent,
                &update_receipt,
                &restore_intent,
                &mut platform,
            )
            .map_err(|error| error.to_string());
            let _ = tx.send(Event::Drivers(DriverEvent::RestoreFinished {
                restore_id: restore_intent.restore_id,
                display_name,
                result,
            }));
            repaint.request_repaint();
        });
    }

    fn driver_tabs(&mut self, ui: &mut egui::Ui, t: Tokens) {
        let counts = self.driver_tab_counts();
        theme::tabs(ui, |ui| {
            for (tab, label, count, icon) in [
                (
                    DriverTab::Outdated,
                    "Outdated drivers",
                    counts.0,
                    theme::Icon::Driver,
                ),
                (
                    DriverTab::NoOfferUnknown,
                    "No offer / unknown",
                    counts.1,
                    theme::Icon::Driver,
                ),
                (
                    DriverTab::Deferred,
                    "Skipped & Ignored",
                    counts.2,
                    theme::Icon::EyeOff,
                ),
            ] {
                let response = theme::tab_with_icon_count(
                    ui,
                    self.drivers_ui.tab == tab,
                    icon,
                    label,
                    count,
                    t,
                );
                if response.clicked() {
                    self.drivers_ui.tab = tab;
                    self.drivers_ui.problem_category_filter = None;
                    self.drivers_ui.problem_history_result = None;
                }
            }
        });
        match self.drivers_ui.tab {
            DriverTab::NoOfferUnknown => {
                theme::muted(ui, "No offer is not proof that a device is current.", t);
            }
            DriverTab::Outdated => {
                theme::muted(
                    ui,
                    "An offer means Windows Update Agent returned a matching driver.",
                    t,
                );
            }
            DriverTab::Deferred => {
                theme::muted(ui, "Saved local skip and ignore choices.", t);
            }
        }
        ui.add_space(4.);
        ui.separator();
    }

    fn driver_results_heading(&self, ui: &mut egui::Ui, t: Tokens) {
        let counts = self.driver_tab_counts();
        let (heading, subtitle) = match self.drivers_ui.tab {
            DriverTab::Outdated => match counts.0 {
                Some(0) => (
                    "No matching update offers in this result".to_owned(),
                    "No confirmed offer is available to select. A missing offer does not mean a driver is current.".to_owned(),
                ),
                Some(count) => (
                    format!("{count} {} with a matching update offer", if count == 1 { "device" } else { "devices" }),
                    "Review the exact Windows Update offer and any backup or restart requirements before selecting an update.".to_owned(),
                ),
                None => (
                    "Driver result count unavailable".to_owned(),
                    "Saved driver choices could not be read, so device status counts are unavailable.".to_owned(),
                ),
            },
            DriverTab::NoOfferUnknown => match counts.1 {
                Some(count) => (
                    format!("{count} {} without a confirmed update offer", if count == 1 { "device" } else { "devices" }),
                    "This includes no-offer and unknown states. Neither state confirms that a driver is current.".to_owned(),
                ),
                None => (
                    "Driver result count unavailable".to_owned(),
                    "Saved driver choices could not be read, so device status counts are unavailable.".to_owned(),
                ),
            },
            DriverTab::Deferred => match counts.2 {
                Some(count) => (
                    format!("{count} {} with skipped or ignored offers", if count == 1 { "device" } else { "devices" }),
                    "These are saved local choices for specific devices or exact update offers.".to_owned(),
                ),
                None => (
                    "Driver result count unavailable".to_owned(),
                    "Saved driver choices could not be read, so device status counts are unavailable.".to_owned(),
                ),
            },
        };

        ui.label(
            RichText::new(heading)
                .size(theme::FONT_TITLE)
                .family(theme::semibold()),
        );
        theme::muted(ui, subtitle, t);
    }

    fn driver_search(&mut self, ui: &mut egui::Ui, t: Tokens) {
        theme::control_row(ui, |ui| {
            ui.label(RichText::new("Search").color(t.muted));
            ui.add_space(8.);
            let width = (ui.available_width() - 8.).clamp(150., 360.);
            theme::input(
                ui,
                &mut self.drivers_ui.query,
                width,
                "Device, class, provider or offer…",
                true,
            );
        });
        if let Some(categories) = self.drivers_ui.problem_category_filter.as_ref() {
            let categories = match self.drivers_ui.problem_history_result.as_ref() {
                Some(
                    ProblemHistoryResult::Matches { categories, .. }
                    | ProblemHistoryResult::NoRecentMatches { categories, .. }
                    | ProblemHistoryResult::Unavailable { categories, .. },
                ) => categories,
                None => categories,
            };
            let labels = categories
                .iter()
                .map(|category| category.label())
                .collect::<Vec<_>>()
                .join(", ");
            let mut clear = false;
            ui.add_space(4.);
            ui.horizontal_wrapped(|ui| {
                theme::muted(ui, "Selected categories:", t);
                theme::muted(ui, labels, t);
                clear = theme::row_action(ui, "Clear history filter", true).clicked();
            });
            if clear {
                self.drivers_ui.problem_category_filter = None;
                self.drivers_ui.problem_history_result = None;
            }
        }
    }

    fn driver_problem_history_status(
        &self,
        ui: &mut egui::Ui,
        t: Tokens,
        snapshot: &DriverSnapshot,
    ) {
        let Some(result) = self.drivers_ui.problem_history_result.as_ref() else {
            return;
        };
        match result {
            ProblemHistoryResult::Matches {
                records_reviewed,
                devices_matched,
                ..
            } => status_card(
                ui,
                t,
                &format!("Recent matching updates · {devices_matched}"),
                &format!(
                    "{records_reviewed} records loaded · inventory {} · latest {MAX_RECENT_DRIVER_OPERATIONS} only.",
                    inventory_quality_label(snapshot.inventory.source.quality)
                ),
            ),
            ProblemHistoryResult::NoRecentMatches {
                records_reviewed, ..
            } => {
                status_card(
                    ui,
                    t,
                    "No restorable update in loaded history",
                    &format!(
                        "{records_reviewed} records loaded · inventory {} · latest {MAX_RECENT_DRIVER_OPERATIONS} only.",
                        inventory_quality_label(snapshot.inventory.source.quality)
                    ),
                );
                let caveat = if *records_reviewed == MAX_RECENT_DRIVER_OPERATIONS {
                    "No match does not mean a device is current. Older records may be outside this view."
                } else {
                    "No match does not mean a device is current."
                };
                theme::muted(ui, caveat, t);
            }
            ProblemHistoryResult::Unavailable {
                history_unreadable, ..
            } => {
                let (heading, message) = if *history_unreadable {
                    (
                        "Saved driver history unavailable",
                        "No recent history match can be shown until saved history is readable.",
                    )
                } else {
                    (
                        "Current device inventory unavailable",
                        "No history match can be shown until current devices can be read.",
                    )
                };
                status_card(ui, t, heading, message);
            }
        }
    }

    fn driver_table(
        &mut self,
        ui: &mut egui::Ui,
        t: Tokens,
        ctx: &egui::Context,
        snapshot: &DriverSnapshot,
    ) {
        let settings = self.drivers_ui.settings.clone().unwrap_or_default();
        let settings_readable =
            self.drivers_ui.settings_error.is_none() && self.drivers_ui.settings.is_some();
        let mut devices: Vec<(DriverDevice, DriverStatus)> = snapshot
            .inventory
            .devices
            .iter()
            .filter_map(|device| {
                let status = if settings_readable {
                    snapshot.status_for(device, &settings)
                } else {
                    DriverStatus::Unknown
                };
                (if let Some(categories) = self.drivers_ui.problem_category_filter.as_ref() {
                    categories
                        .iter()
                        .any(|category| category.matches_device(device.category()))
                        && self
                            .driver_selected_restore_intent_with_limit(
                                device,
                                MAX_RECENT_DRIVER_OPERATIONS,
                            )
                            .is_some()
                } else {
                    tab_matches(self.drivers_ui.tab, status)
                } && driver_matches_query(snapshot, device, &self.drivers_ui.query))
                .then(|| (device.clone(), status))
            })
            .collect();
        let sort = self.drivers_ui.sort;
        let descending = self.drivers_ui.descending;
        devices.sort_by(|(left, left_status), (right, right_status)| {
            left.category().cmp(&right.category()).then_with(|| {
                let ordering =
                    compare_devices(snapshot, left, *left_status, right, *right_status, sort);
                if descending {
                    ordering.reverse()
                } else {
                    ordering
                }
            })
        });

        let width = ui.available_width().max(340.);
        let update_columns = self.drivers_ui.tab == DriverTab::Outdated
            && self.drivers_ui.problem_category_filter.is_none();
        let show_offer = false;
        let show_installed = !update_columns;
        let show_candidate_version = update_columns;
        let show_release = update_columns;
        let show_state = !update_columns;
        let select_width = 32.;
        let more_width = 38.;
        let state_width = if show_state { 112. } else { 0. };
        let offer_width = if show_offer { 148. } else { 0. };
        let installed_width = if show_installed { 118. } else { 0. };
        let candidate_version_width = if show_candidate_version { 118. } else { 0. };
        let release_width = if show_release { 118. } else { 0. };
        let column_count = 3
            + show_state as usize
            + show_offer as usize
            + show_installed as usize
            + show_candidate_version as usize
            + show_release as usize;
        let gaps = 8. * column_count.saturating_sub(1) as f32;
        let name_width = (width
            - select_width
            - more_width
            - state_width
            - offer_width
            - installed_width
            - candidate_version_width
            - release_width
            - gaps)
            .max(112.);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.;
            table_heading(ui, "", select_width, t);
            if driver_sort_heading(
                ui,
                "Drivers",
                name_width,
                DriverSort::Device,
                self.drivers_ui.sort,
                self.drivers_ui.descending,
                t,
            )
            .clicked()
            {
                select_driver_header_sort(
                    &mut self.drivers_ui.sort,
                    &mut self.drivers_ui.descending,
                    DriverSort::Device,
                );
            }
            if show_installed {
                if driver_sort_heading(
                    ui,
                    "Installed",
                    installed_width,
                    DriverSort::Installed,
                    self.drivers_ui.sort,
                    self.drivers_ui.descending,
                    t,
                )
                .clicked()
                {
                    select_driver_header_sort(
                        &mut self.drivers_ui.sort,
                        &mut self.drivers_ui.descending,
                        DriverSort::Installed,
                    );
                }
            }
            if show_offer {
                table_heading(ui, "Windows Update offer", offer_width, t);
            }
            if show_candidate_version {
                if driver_sort_heading(
                    ui,
                    "New version",
                    candidate_version_width,
                    DriverSort::CandidateVersion,
                    self.drivers_ui.sort,
                    self.drivers_ui.descending,
                    t,
                )
                .on_hover_text(
                    "Only a version reported by Windows Update Agent is shown; DCleaner never infers one from an offer title.",
                )
                .clicked()
                {
                    select_driver_header_sort(
                        &mut self.drivers_ui.sort,
                        &mut self.drivers_ui.descending,
                        DriverSort::CandidateVersion,
                    );
                }
            }
            if show_release {
                if driver_sort_heading(
                    ui,
                    "Released",
                    release_width,
                    DriverSort::Release,
                    self.drivers_ui.sort,
                    self.drivers_ui.descending,
                    t,
                )
                .on_hover_text("Release dates are shown only when Windows Update Agent reports one.")
                .clicked()
                {
                    select_driver_header_sort(
                        &mut self.drivers_ui.sort,
                        &mut self.drivers_ui.descending,
                        DriverSort::Release,
                    );
                }
            }
            if show_state && driver_sort_heading(
                ui,
                "State",
                state_width,
                DriverSort::State,
                self.drivers_ui.sort,
                self.drivers_ui.descending,
                t,
            )
            .clicked()
            {
                select_driver_header_sort(
                    &mut self.drivers_ui.sort,
                    &mut self.drivers_ui.descending,
                    DriverSort::State,
                );
            }
            table_heading(ui, "", more_width, t);
        });
        ui.add_space(3.);
        ui.separator();

        if devices.is_empty() {
            let message = if snapshot.inventory.source.quality == InventoryQuality::Unavailable {
                "Windows did not return a device inventory. See the source details below."
            } else if self.drivers_ui.query.trim().is_empty()
                && self.drivers_ui.tab == DriverTab::NoOfferUnknown
                && matches!(
                    &snapshot.catalogue.state,
                    CatalogueState::Unavailable { .. }
                )
            {
                "Windows Update Agent did not return a result, so offer state remains unknown."
            } else if self.drivers_ui.problem_category_filter.is_some() {
                "No matching device remains in the loaded recent update history and current inventory for this search. This does not mean a device is current."
            } else {
                "No devices match this tab and search."
            };
            theme::card(t).show(ui, |ui| theme::muted(ui, message, t));
            return;
        }

        enum Row {
            Group(
                DriverDeviceCategory,
                usize,
                Vec<(DriverUpdateIntent, DeviceId)>,
            ),
            Device(DriverDevice, DriverStatus),
        }
        let mut grouped: BTreeMap<DriverDeviceCategory, Vec<(DriverDevice, DriverStatus)>> =
            BTreeMap::new();
        for (device, status) in devices {
            grouped
                .entry(device.category())
                .or_default()
                .push((device, status));
        }
        let mut rows = Vec::new();
        for (category, items) in grouped {
            let group_offers = items
                .iter()
                .filter_map(|(device, _)| {
                    Some((self.single_driver_offer_intent(device)?, device.id.clone()?))
                })
                .collect();
            rows.push(Row::Group(category, items.len(), group_offers));
            if !self.drivers_ui.collapsed_groups.contains(&category) {
                rows.extend(
                    items
                        .into_iter()
                        .map(|(device, status)| Row::Device(device, status)),
                );
            }
        }
        let table_width = width;
        let body_height = (ctx.content_rect().bottom() - ui.cursor().top() - 90.).max(140.);
        egui::ScrollArea::vertical()
            .id_salt("driver-device-table")
            .max_height(body_height)
            .auto_shrink([false, true])
            .show_rows(ui, 44., rows.len(), |body, visible_rows| {
                for index in visible_rows {
                    match &rows[index] {
                        Row::Group(category, count, offers) => {
                            body.allocate_ui_with_layout(
                                [table_width, 44.].into(),
                                Layout::left_to_right(Align::Center),
                                |group| {
                                    group.set_min_height(44.);
                                    group.spacing_mut().item_spacing.x = 8.;
                                    let all_selected = !offers.is_empty()
                                        && offers.iter().all(|(intent, device_id)| {
                                            self.driver_offer_selected(intent, device_id)
                                        });
                                    let any_selected = offers.iter().any(|(intent, device_id)| {
                                        self.driver_offer_selected(intent, device_id)
                                    });
                                    let mut selected = all_selected;
                                    let response = group
                                        .allocate_ui_with_layout(
                                            [select_width, 40.].into(),
                                            Layout::centered_and_justified(
                                                egui::Direction::LeftToRight,
                                            ),
                                            |cell| {
                                                theme::checkbox_named(
                                                    cell,
                                                    &mut selected,
                                                    any_selected && !all_selected,
                                                    "Select all actionable offers in this device category",
                                                    !offers.is_empty() && !self.busy(),
                                                )
                                            },
                                        )
                                        .inner;
                                    if response.changed() {
                                        for (intent, device_id) in offers {
                                            self.set_driver_offer_selected(
                                                intent.clone(),
                                                device_id.clone(),
                                                !all_selected,
                                            );
                                        }
                                    }
                                    let collapsed = self.drivers_ui.collapsed_groups.contains(category);
                                    let label = format!("{} ({count})", category.label());
                                    let disclosure_label = format!("{} {}", if collapsed { "Expand" } else { "Collapse" }, category.label());
                                    let chevron_id = group.id().with(("driver-category-chevron", category.label()));
                                    let button_width = (table_width - select_width - 8.).max(1.);
                                    group.spacing_mut().button_padding = egui::vec2(8., 0.);
                                    let painted = egui::Button::new((
                                        RichText::new(label).family(theme::semibold()).color(t.foreground),
                                        egui::Atom::grow(),
                                        egui::Atom::custom(chevron_id, egui::Vec2::splat(16.)),
                                    ))
                                    .fill(egui::Color32::TRANSPARENT)
                                    .stroke(egui::Stroke::NONE)
                                    .corner_radius(20)
                                    .min_size(egui::vec2(button_width, 40.))
                                    .atom_ui(group);
                                    if let Some(rect) = painted.rect(chevron_id) {
                                        let c = rect.center();
                                        let points = if collapsed {
                                            vec![c + egui::vec2(-2., -4.), c + egui::vec2(2., 0.), c + egui::vec2(-2., 4.)]
                                        } else {
                                            vec![c + egui::vec2(-4., -2.), c + egui::vec2(0., 2.), c + egui::vec2(4., -2.)]
                                        };
                                        group.painter().add(egui::Shape::line(points, egui::Stroke::new(1.05, t.muted)));
                                    }
                                    painted.response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, &disclosure_label));
                                    #[cfg(debug_assertions)]
                                    theme::record_fixture_control(group, &disclosure_label, &painted.response);
                                    if painted.response.clicked() {
                                        if collapsed {
                                            self.drivers_ui.collapsed_groups.remove(category);
                                        } else {
                                            self.drivers_ui.collapsed_groups.insert(*category);
                                        }
                                    }
                                },
                            );
                        }
                        Row::Device(device, status) => {
                            let id = device.id.as_ref().map(|id| id.0.as_str()).unwrap_or("unknown");
                            body.push_id(id, |row| {
                                row.allocate_ui_with_layout(
                                    [table_width, 44.].into(),
                                    Layout::left_to_right(Align::Center),
                                    |row| {
                                        row.set_min_height(44.);
                                        row.spacing_mut().item_spacing.x = 8.;
                                        let candidates = candidates_for(Some(snapshot), device);
                                        let single_intent = self.single_driver_offer_intent(device);
                                        let device_id = device.id.clone();
                                        let mut offer_selected = single_intent
                                            .as_ref()
                                            .zip(device_id.as_ref())
                                            .is_some_and(|(intent, id)| self.driver_offer_selected(intent, id));
                                        if offer_selected {
                                            row.painter().rect_filled(egui::Rect::from_min_size(row.cursor().min, [table_width,44.].into()), 0., t.tint);
                                        }
                                        let selection = row
                                            .allocate_ui_with_layout(
                                                [select_width, 40.].into(),
                                                Layout::centered_and_justified(
                                                    egui::Direction::LeftToRight,
                                                ),
                                                |cell| {
                                                    cell.set_min_width(select_width);
                                                    cell.set_max_width(select_width);
                                                    theme::checkbox_named(
                                                        cell,
                                                        &mut offer_selected,
                                                        false,
                                                        "Select this exact Windows Update offer",
                                                        single_intent.is_some() && !self.busy(),
                                                    )
                                                },
                                            )
                                            .inner
                                            .on_hover_text(if candidates.len() > 1 {
                                                "Open Details to select one exact offer for this device."
                                            } else if single_intent.is_some() {
                                                "Add this exact Windows Update offer to the reviewed selection."
                                            } else {
                                                "Selection requires one unambiguous, actionable offer."
                                            });
                                        if selection.changed()
                                            && let (Some(intent), Some(device_id)) =
                                                (single_intent.clone(), device_id.clone())
                                        {
                                            self.set_driver_offer_selected(
                                                intent,
                                                device_id,
                                                offer_selected,
                                            );
                                        }
                                        let name_response = row
                                            .allocate_ui_with_layout(
                                                [name_width, 40.].into(),
                                                Layout::left_to_right(Align::Center),
                                                |cell| {
                                                    cell.set_min_width(name_width);
                                                    cell.set_max_width(name_width);
                                                    cell.visuals_mut().selection.bg_fill = t.tint;
                                                    cell.visuals_mut().selection.stroke.color = t.foreground;
                                                    cell.spacing_mut().item_spacing.x = 8.;
                                                    let name = known(&device.friendly_name)
                                                        .unwrap_or("Device name unavailable");
                                                    let response = cell.add_sized(
                                                        [(name_width - 8.).max(64.), 40.],
                                                        egui::Button::selectable(
                                                            false,
                                                            (
                                                                RichText::new(name)
                                                                    .family(theme::semibold()),
                                                                egui::Atom::grow(),
                                                            ),
                                                        )
                                                        .frame(false)
                                                        .truncate(),
                                                    );
                                                    response.on_hover_text(device_identity_tooltip(device))
                                                },
                                            )
                                            .inner;
                                        if name_response.clicked() {
                                            self.drivers_ui.selected = device.id.clone();
                                        }
                                        if show_installed {
                                            let installed = field_display(&device.installed_version);
                                            theme::table_cell(
                                                row,
                                                RichText::new(installed).color(t.muted),
                                                installed_width,
                                                40.,
                                            )
                                            .on_hover_text(field_tooltip(&device.installed_version));
                                        }
                                        if show_offer {
                                            let offer = self
                                                .drivers_ui
                                                .snapshot
                                                .as_ref()
                                                .map(|current| offer_display(current, device))
                                                .unwrap_or_else(|| "Unknown".into());
                                            theme::table_cell(
                                                row,
                                                RichText::new(offer.clone())
                                                    .color(status_color(*status, t)),
                                                offer_width,
                                                40.,
                                            )
                                            .on_hover_text(offer);
                                        }
                                        if show_candidate_version {
                                            theme::table_cell(
                                                row,
                                                RichText::new(candidate_version_cell_display(
                                                    snapshot, device,
                                                ))
                                                .color(t.muted),
                                                candidate_version_width,
                                                40.,
                                            )
                                            .on_hover_text(candidate_version_tooltip(
                                                snapshot, device,
                                            ));
                                        }
                                        if show_release {
                                            let release = release_display(snapshot, device);
                                            theme::table_cell(
                                                row,
                                                RichText::new(release).color(t.muted),
                                                release_width,
                                                40.,
                                            ).on_hover_text(match candidates.as_slice() {
                                                [candidate] => field_tooltip(&candidate.release_date),
                                                _ => release_display(snapshot, device),
                                            });
                                        }
                                        if show_state { theme::table_cell(
                                            row,
                                            RichText::new(status_label(*status))
                                                .color(status_color(*status, t)),
                                            state_width,
                                            40.,
                                        ); }
                                        let more = row
                                            .allocate_ui_with_layout(
                                                [more_width, 40.].into(),
                                                Layout::left_to_right(Align::Center),
                                                |actions| theme::row_more(actions, !self.busy()),
                                            )
                                            .inner;
                                        #[cfg(debug_assertions)]
                                        if self.qa_fixture_mode() {
                                            theme::record_fixture_control(row, "More", &more);
                                        }
                                        if more.clicked() {
                                            self.drivers_ui.selected = device.id.clone();
                                            self.drivers_ui.dialog = Some(DriverDialog::Details(device.clone()));
                                        }
                                    },
                                );
                            });
                        }
                    }
                }
            });
    }

    fn driver_sources_panel(&self, ui: &mut egui::Ui, t: Tokens, snapshot: &DriverSnapshot) {
        egui::CollapsingHeader::new("Inventory and source details")
            .default_open(
                snapshot.inventory.source.quality != InventoryQuality::Complete
                    || !matches!(&snapshot.catalogue.state, CatalogueState::Read { .. }),
            )
            .id_salt("driver-source-details")
            .show(ui, |ui| {
                detail(
                    ui,
                    "SetupAPI inventory",
                    &format!(
                        "{:?} · {} present devices",
                        snapshot.inventory.source.quality,
                        snapshot.inventory.source.item_count
                    ),
                    t,
                );
                detail(ui, "Windows Update Agent", &catalogue_label(&snapshot.catalogue.state), t);
                if let CatalogueState::Read { source }
                | CatalogueState::Partial { source }
                | CatalogueState::Truncated { source } = &snapshot.catalogue.state
                {
                    detail(ui, "Selected update source", &source.label(), t);
                }
                if let CatalogueState::Unavailable { issue } = &snapshot.catalogue.state {
                    issue_line(ui, t, issue);
                }
                for issue in snapshot
                    .inventory
                    .source
                    .issues
                    .iter()
                    .chain(snapshot.catalogue.issues.iter())
                    .take(12)
                {
                    issue_line(ui, t, issue);
                }
                if snapshot.inventory.source.issues.len() + snapshot.catalogue.issues.len() > 12 {
                    theme::muted(ui, "Additional native read issues were omitted from this view.", t);
                }
                ui.add_space(5.);
                theme::muted(
                    ui,
                    "An offer means the selected Windows Update Agent source returned a matching driver update. No offer is not a comparison against every manufacturer catalogue. WUA does not expose a candidate driver version here, so DCleaner does not infer one. Device problem codes are read-only in this page.",
                    t,
                );
                ui.add_space(4.);
                theme::muted(
                    ui,
                    "The native SetupAPI/WUA search has no cancellation boundary. Driver installation and restore are review-gated, may require a restart, and never restart Windows automatically.",
                    t,
                );
            });
    }

    fn driver_history_panel(&self, ui: &mut egui::Ui, t: Tokens) {
        let records: Vec<&EffectHistory> = self
            .drivers_ui
            .history
            .iter()
            .filter(|record| record.feature == "drivers")
            .take(12)
            .collect();
        egui::CollapsingHeader::new(format!(
            "Driver operation history · {} loaded · latest 12 max",
            records.len()
        ))
            .default_open(false)
            .id_salt("driver-operation-history")
            .show(ui, |ui| {
                if records.is_empty() {
                    theme::muted(ui, "No recorded driver changes are available.", t);
                }
                for record in records {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(history_label(&record.state)).family(theme::semibold()));
                        theme::muted(ui, record.date.clone(), t);
                        if let Some(receipt) = record.receipt.as_ref() {
                            if let Ok(update) = serde_json::from_value::<DriverUpdateReceipt>(receipt.clone()) {
                                theme::muted(
                                    ui,
                                    format!("{:?} · restart {:?}", update.phase, update.reboot),
                                    t,
                                );
                            } else if let Ok(restore) = serde_json::from_value::<DriverRestoreReceipt>(receipt.clone()) {
                                theme::muted(
                                    ui,
                                    format!("{:?} · restart {:?}", restore.phase, restore.reboot),
                                    t,
                                );
                            }
                        } else {
                            theme::muted(ui, "No confirmed receipt · review before retrying", t);
                        }
                    });
                    ui.separator();
                }
                theme::muted(
                    ui,
                    "Incomplete or uncertain operations are never replayed automatically. A saved driver is offered for restore only when its confirmed receipt and exact current device identity pass validation.",
                    t,
                );
            });
    }

    fn driver_details(
        &self,
        ui: &mut egui::Ui,
        t: Tokens,
        device: &DriverDevice,
    ) -> Option<DetailAction> {
        let snapshot = self.drivers_ui.snapshot.as_ref()?;
        let Some(device_id) = device.id.as_ref() else {
            status_card(
                ui,
                t,
                "Actions unavailable",
                "Windows did not provide a stable identity for this device.",
            );
            return None;
        };
        let settings = self
            .drivers_ui
            .settings
            .as_ref()
            .filter(|_| self.drivers_ui.settings_error.is_none());
        let status = settings
            .map(|settings| snapshot.status_for(device, settings))
            .unwrap_or(DriverStatus::Unknown);
        driver_primary_field(ui, "Version", &device.installed_version, t);
        driver_primary_field(ui, "Device type", &device.class_name, t);
        driver_primary_field(ui, "Publisher", &device.provider, t);
        driver_primary_value(
            ui,
            "Status",
            status_label(status),
            "Based on the current device and update-source snapshot.",
            t,
        );
        ui.add_space(3.);
        ui.separator();

        let version_history = driver_device_version_history(&self.drivers_ui.history, device);
        let version_history_identity_available =
            device.id.as_ref().is_some_and(|id| !id.0.trim().is_empty())
                && known(&device.instance_id).is_some_and(|id| !id.trim().is_empty());
        let candidates = candidates_for(Some(snapshot), device);
        let mut action = None;

        egui::CollapsingHeader::new("Driver versions")
            .default_open(false)
            .id_salt("driver-device-version-history")
            .show(ui, |versions_ui| {
                versions_ui.label(
                    RichText::new("Saved version history")
                        .size(theme::FONT_BODY)
                        .family(theme::semibold()),
                );
                if self.drivers_ui.history_error.is_some() {
                    theme::muted(versions_ui, "Saved version history is unavailable.", t);
                } else if !version_history_identity_available {
                    theme::muted(
                        versions_ui,
                        "A stable device identity was unavailable, so matching history cannot be shown.",
                        t,
                    );
                } else if version_history.is_empty() {
                    theme::muted(versions_ui, "No saved driver changes for this device.", t);
                } else {
                    for entry in &version_history {
                        versions_ui.horizontal_wrapped(|row| {
                            row.label(RichText::new(&entry.status).family(theme::semibold()));
                            theme::muted(row, &entry.date, t);
                            if let Some(transition) = entry.transition.as_deref() {
                                theme::muted(row, transition.replace('→', "to"), t);
                            }
                        });
                    }
                }

                versions_ui.add_space(5.);
                versions_ui.separator();
                versions_ui.label(
                    RichText::new("Windows Update offers")
                        .size(theme::FONT_BODY)
                        .family(theme::semibold()),
                );
                if candidates.is_empty() {
                    match &device.offer {
                        DeviceOffer::NoOfferFromSource { source } => theme::muted(
                            versions_ui,
                            format!("No matching offer was returned by {}.", source.label()),
                            t,
                        ),
                        DeviceOffer::Unknown { failure } => theme::muted(
                            versions_ui,
                            format!("Offer state is unknown: {}", failure.summary()),
                            t,
                        ),
                        DeviceOffer::CandidateAvailable { .. } => theme::muted(
                            versions_ui,
                            "The exact offer details are not available in this inventory.",
                            t,
                        ),
                    };
                } else {
                    for candidate in &candidates {
                        candidate_details(versions_ui, t, candidate);
                        if self.driver_candidate_actionable(device, candidate)
                            && self.drivers_ui.settings_error.is_none()
                            && let Ok(intent) = drivers::prepare_update_intent(device, candidate)
                        {
                            let mut selected_offer = self.driver_offer_selected(&intent, device_id);
                            let response = theme::checkbox(
                                versions_ui,
                                &mut selected_offer,
                                "Select this exact offer for Update selected",
                                !self.busy(),
                            );
                            if response.changed() {
                                action = Some(DetailAction::Select(
                                    intent,
                                    device_id.clone(),
                                    selected_offer,
                                ));
                            }
                        }
                        if theme::row_action(
                            versions_ui,
                            "Review offer",
                            !self.busy()
                                && self.drivers_ui.settings_error.is_none()
                                && self.driver_candidate_actionable(device, candidate),
                        )
                        .clicked()
                        {
                            match drivers::prepare_update_intent(device, candidate) {
                                Ok(intent) => action = Some(DetailAction::Review(intent)),
                                Err(error) => {
                                    action = Some(DetailAction::Error(format!(
                                        "The selected driver offer is not ready for review: {error}"
                                    )))
                                }
                            }
                        }
                        versions_ui.separator();
                    }
                }
            });

        egui::CollapsingHeader::new("Advanced")
            .default_open(false)
            .id_salt("driver-device-advanced")
            .show(ui, |advanced| {
                let settings = self.drivers_ui.settings.as_ref();
                let skip_candidates = candidates_for(Some(snapshot), device);
                egui::CollapsingHeader::new("Skipped offers")
                    .default_open(false)
                    .id_salt("driver-device-saved-choices")
                    .show(advanced, |choices_ui| {
                        for candidate in skip_candidates {
                            let skipped = settings.is_some_and(|settings| {
                                settings.is_skipped(device_id, &candidate.identity)
                            });
                            let mut skip_value = skipped;
                            let label = format!(
                                "Skip this exact offer · {}",
                                known(&candidate.title).unwrap_or("Offer details unavailable")
                            );
                            let response = theme::checkbox(
                                choices_ui,
                                &mut skip_value,
                                label,
                                !self.busy() && self.drivers_ui.settings_error.is_none(),
                            );
                            if response.changed() {
                                action = Some(DetailAction::Skip(
                                    device_id.clone(),
                                    candidate.identity.clone(),
                                    skip_value,
                                ));
                            }
                        }
                        if self.drivers_ui.settings_error.is_some() {
                            theme::muted(
                                choices_ui,
                                "Saved choices are locked until the settings file is readable.",
                                t,
                            );
                        }
                    });
                advanced.add_space(5.);
                detail(advanced, "Device category", device.category().label(), t);
                detail(advanced, "Driver date", &field_display(&device.installed_date), t);
                detail(advanced, "Published INF", &field_display(&device.inf_path), t);
                detail(
                    advanced,
                    "Device instance identity",
                    &field_display(&device.instance_id),
                    t,
                );
                match device.problem_code.as_known() {
                    Some(problem) => detail(advanced, "Windows problem code", &problem.to_string(), t),
                    None => detail(advanced, "Windows problem code", "Unknown", t),
                }
                match &device.hardware_ids {
                    FieldValue::Known { value: ids } => {
                        egui::CollapsingHeader::new(format!("Hardware IDs · {}", ids.len()))
                            .default_open(false)
                            .show(advanced, |ids_ui| {
                                for id in ids.iter().take(20) {
                                    ids_ui.add(
                                        egui::Label::new(RichText::new(id).monospace()).wrap(),
                                    );
                                }
                                if ids.len() > 20 {
                                    theme::muted(
                                        ids_ui,
                                        "Additional hardware IDs are not shown here.",
                                        t,
                                    );
                                }
                            });
                    }
                    FieldValue::Unknown { failure } => detail(
                        advanced,
                        "Hardware IDs",
                        &format!("Unknown · {}", failure.summary()),
                        t,
                    ),
                }
                if device.has_confirmed_problem() == Some(true) {
                    theme::muted(
                        advanced,
                        "Windows reports a device problem code. This page can display it but cannot diagnose or repair it.",
                        t,
                    );
                }
            });
        Some(action).flatten()
    }

    fn driver_update_review(&self, ui: &mut egui::Ui, t: Tokens, intent: &DriverUpdateIntent) {
        let candidate = self.drivers_ui.snapshot.as_ref().and_then(|snapshot| {
            snapshot
                .catalogue
                .candidates
                .iter()
                .find(|candidate| &candidate.identity == &intent.candidate)
        });
        theme::muted(
            ui,
            "Nothing changes until you confirm. DCleaner rechecks the exact device, hardware IDs and Windows Update offer before download and install.",
            t,
        );
        ui.add_space(10.);
        review_detail(ui, "Device", &self.driver_display_name(intent), t);
        review_detail(
            ui,
            "Device class",
            candidate
                .and_then(|value| known(&value.class))
                .unwrap_or("Unavailable"),
            t,
        );
        review_detail(
            ui,
            "Offer title",
            candidate
                .and_then(|value| known(&value.title))
                .unwrap_or("Offer details unavailable"),
            t,
        );
        review_detail(
            ui,
            "Manufacturer",
            candidate
                .and_then(|value| known(&value.manufacturer))
                .unwrap_or("Unavailable"),
            t,
        );
        review_detail(
            ui,
            "Provider",
            candidate
                .and_then(|value| known(&value.provider))
                .unwrap_or(intent.provider.as_str()),
            t,
        );
        review_detail(
            ui,
            "Current installed version",
            known(&intent.installed_version).unwrap_or("Unknown"),
            t,
        );
        review_detail(
            ui,
            "Candidate version",
            &candidate
                .map(candidate_version_display)
                .unwrap_or_else(|| "Offer not available in this snapshot".into()),
            t,
        );
        review_detail(
            ui,
            "Offer release date",
            candidate
                .and_then(|value| known(&value.release_date))
                .unwrap_or("Unavailable"),
            t,
        );
        review_detail(ui, "Update source", &intent.candidate.source.label(), t);
        review_detail(
            ui,
            "Exact WUA update identity",
            &format!(
                "{} · revision {}",
                intent.candidate.update_id, intent.candidate.revision
            ),
            t,
        );
        review_detail(
            ui,
            "Matched hardware ID",
            &intent.candidate.driver_hardware_id,
            t,
        );
        review_detail(
            ui,
            "Installed INF",
            known(&intent.installed_inf).unwrap_or("Unknown"),
            t,
        );
        ui.add_space(8.);
        egui::Frame::new()
            .fill(t.tint)
            .corner_radius(8)
            .inner_margin(10.)
            .show(ui, |ui| {
                ui.label(RichText::new("Before Windows is changed").family(theme::semibold()));
                ui.add_space(4.);
                theme::muted(ui, "DCleaner writes a durable intent, creates a Windows restore point, exports and verifies the signed installed package, then revalidates the exact WUA revision before installation. Windows may require a restart; DCleaner never restarts automatically.", t);
                theme::muted(ui, "The Windows operation cannot be cancelled once started. A partial result stays in history as uncertain and is not retried automatically.", t);
            });
        if candidate.is_some_and(|candidate| candidate.eula_accepted.as_known() != Some(&true)) {
            ui.add_space(8.);
            status_card(
                ui,
                t,
                "Windows license acceptance required",
                "Accept the offer in Windows first. DCleaner will not accept a driver license on your behalf.",
            );
        }
        if candidate.is_none() {
            ui.add_space(8.);
            status_card(
                ui,
                t,
                "Offer could not be re-read",
                "Refresh the native inventory and review the exact offer again before continuing.",
            );
        }
        if drivers::supported_update_actions().is_err() {
            ui.add_space(8.);
            status_card(
                ui,
                t,
                "Native driver actions unavailable",
                "This build does not have a supported native install and restore boundary.",
            );
        }
    }

    fn driver_display_name(&self, intent: &DriverUpdateIntent) -> String {
        self.drivers_ui
            .snapshot
            .as_ref()
            .and_then(|snapshot| {
                snapshot
                    .inventory
                    .devices
                    .iter()
                    .find(|device| device.id.as_ref() == Some(&intent.device_id))
            })
            .and_then(|device| known(&device.friendly_name))
            .filter(|name| !name.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| "Selected device".into())
    }

    fn driver_batch_review(
        &self,
        ui: &mut egui::Ui,
        t: Tokens,
        selected_updates: &[SelectedDriverUpdate],
    ) {
        theme::muted(
            ui,
            "Offers with the same Windows Update GUID, revision, and source are grouped and sent once. Windows controls which matching devices receive an offer; DCleaner revalidates and verifies the representative device shown in each group, not every related device instance. Each offer gets its own synced intent, restore point, and signed package backup. The sequence stops at the first unverified result or restart requirement; it cannot be cancelled after a native operation starts.",
            t,
        );
        ui.add_space(8.);
        let Some(snapshot) = self.drivers_ui.snapshot.as_ref() else {
            status_card(
                ui,
                t,
                "Selection is no longer available",
                "Refresh the native inventory before reviewing driver updates.",
            );
            return;
        };
        for (index, selected) in selected_updates.iter().enumerate() {
            if index > 0 {
                ui.add_space(6.);
                ui.separator();
            }
            let candidate = snapshot
                .catalogue
                .candidates
                .iter()
                .find(|candidate| candidate.identity == selected.intent.candidate);
            ui.label(
                RichText::new(format!("Offer {} of {}", index + 1, selected_updates.len()))
                    .family(theme::semibold()),
            );
            review_detail(
                ui,
                "Matched devices",
                &self.driver_selected_group_label(selected),
                t,
            );
            if let Some(candidate) = candidate {
                review_detail(
                    ui,
                    "Windows Update offer",
                    known(&candidate.title).unwrap_or("Offer details unavailable"),
                    t,
                );
                review_detail(
                    ui,
                    "Provider / manufacturer",
                    &format!(
                        "{} / {}",
                        known(&candidate.provider).unwrap_or("Unknown"),
                        known(&candidate.manufacturer).unwrap_or("Unknown")
                    ),
                    t,
                );
                review_detail(
                    ui,
                    "Candidate version",
                    &candidate_version_display(candidate),
                    t,
                );
                review_detail(
                    ui,
                    "Offer release date",
                    known(&candidate.release_date).unwrap_or("Unavailable"),
                    t,
                );
                review_detail(
                    ui,
                    "Exact WUA identity",
                    &format!(
                        "{} · revision {} · {}",
                        candidate.identity.update_id,
                        candidate.identity.revision,
                        candidate.identity.source.label()
                    ),
                    t,
                );
                review_detail(
                    ui,
                    "WUA service identity",
                    if candidate.identity.source.service_id.is_empty() {
                        "No service ID reported by Windows Update Agent"
                    } else {
                        candidate.identity.source.service_id.as_str()
                    },
                    t,
                );
                for selected_device in &selected.devices {
                    if let Some(device) = snapshot
                        .inventory
                        .devices
                        .iter()
                        .find(|device| device.id.as_ref() == Some(&selected_device.id))
                    {
                        review_detail(
                            ui,
                            if selected_device.id == selected.intent.device_id {
                                "Representative device"
                            } else {
                                "Other selected device"
                            },
                            &format!(
                                "{} · {}",
                                known(&device.friendly_name).unwrap_or("Name unavailable"),
                                field_display(&device.instance_id)
                            ),
                            t,
                        );
                        review_detail(
                            ui,
                            "Current installed version",
                            &field_display(&device.installed_version),
                            t,
                        );
                        if let Some(candidate) = snapshot
                            .catalogue
                            .candidates
                            .iter()
                            .find(|candidate| candidate.identity == selected_device.candidate)
                        {
                            review_detail(
                                ui,
                                "Matched hardware ID",
                                &candidate.identity.driver_hardware_id,
                                t,
                            );
                        }
                    } else {
                        review_detail(ui, "Device instance", "No longer in inventory", t);
                    }
                }
                review_detail(
                    ui,
                    "Windows license state",
                    match candidate.eula_accepted.as_known() {
                        Some(true) => "Accepted",
                        Some(false) => "Not accepted",
                        None => "Unknown",
                    },
                    t,
                );
            } else {
                status_card(
                    ui,
                    t,
                    "Exact offer is no longer available",
                    "Refresh the inventory and select a current Windows Update offer.",
                );
            }
        }
        if selected_updates.len() > MAX_DRIVER_BATCH_OFFERS {
            ui.add_space(8.);
            status_card(
                ui,
                t,
                "Too many offers for one non-cancellable batch",
                "Select at most 16 unique Windows Update offers. Windows operations cannot be cancelled after they start, and the batch stops only at a verified result or a restart/error boundary.",
            );
        } else if !self.driver_batch_can_apply(selected_updates) {
            ui.add_space(8.);
            status_card(
                ui,
                t,
                "Selected offers cannot be applied yet",
                "A device, exact offer, saved choice, Windows license acceptance, or native action capability changed or is unavailable. Refresh and review the affected items again.",
            );
        }
    }

    fn driver_selected_group_label(&self, selected: &SelectedDriverUpdate) -> String {
        let Some(snapshot) = self.drivers_ui.snapshot.as_ref() else {
            return "Selected devices unavailable".into();
        };
        let names: Vec<String> = selected
            .devices
            .iter()
            .filter_map(|selected_device| {
                let device = snapshot
                    .inventory
                    .devices
                    .iter()
                    .find(|device| device.id.as_ref() == Some(&selected_device.id))?;
                Some(
                    known(&device.friendly_name)
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or("Name unavailable")
                        .to_owned(),
                )
            })
            .collect();
        if names.is_empty() {
            "Selected devices unavailable".into()
        } else {
            names.join(", ")
        }
    }

    fn driver_batch_can_apply(&self, selected_updates: &[SelectedDriverUpdate]) -> bool {
        if selected_updates.is_empty()
            || selected_updates.len() > MAX_DRIVER_BATCH_OFFERS
            || self.qa_fixture_mode()
            || self.drivers_ui.settings_error.is_some()
            || self.drivers_ui.settings.is_none()
            || drivers::supported_update_actions().is_err()
            || selected_updates
                .iter()
                .enumerate()
                .any(|(index, selected)| {
                    selected_updates[..index].iter().any(|previous| {
                        drivers::same_wua_update(
                            &previous.intent.candidate,
                            &selected.intent.candidate,
                        )
                    })
                })
        {
            return false;
        }
        let Some(snapshot) = self.drivers_ui.snapshot.as_ref() else {
            return false;
        };
        selected_updates.iter().all(|selected| {
            if selected.devices.is_empty()
                || !selected.devices.iter().any(|device| {
                    device.id == selected.intent.device_id
                        && device.candidate == selected.intent.candidate
                })
            {
                return false;
            }
            let Some(candidate) = snapshot
                .catalogue
                .candidates
                .iter()
                .find(|candidate| candidate.identity == selected.intent.candidate)
            else {
                return false;
            };
            if candidate.eula_accepted.as_known() != Some(&true) {
                return false;
            }
            selected.devices.iter().all(|selected_device| {
                let Some(device) = snapshot
                    .inventory
                    .devices
                    .iter()
                    .find(|device| device.id.as_ref() == Some(&selected_device.id))
                else {
                    return false;
                };
                let Some(device_candidate) = candidates_for(Some(snapshot), device)
                    .into_iter()
                    .find(|current| current.identity == selected_device.candidate)
                else {
                    return false;
                };
                drivers::same_wua_update(&device_candidate.identity, &candidate.identity)
                    && device_candidate.eula_accepted.as_known() == Some(&true)
                    && self.driver_candidate_actionable(device, device_candidate)
            })
        })
    }

    fn driver_offer_selected(&self, intent: &DriverUpdateIntent, device_id: &DeviceId) -> bool {
        self.drivers_ui.selected_updates.iter().any(|selected| {
            drivers::same_wua_update(&selected.intent.candidate, &intent.candidate)
                && selected.devices.iter().any(|selected_device| {
                    &selected_device.id == device_id
                        && selected_device.candidate == intent.candidate
                })
        })
    }

    fn set_driver_offer_selected(
        &mut self,
        intent: DriverUpdateIntent,
        device_id: DeviceId,
        selected: bool,
    ) {
        if selected {
            if let Some(existing) =
                self.drivers_ui.selected_updates.iter_mut().find(|item| {
                    drivers::same_wua_update(&item.intent.candidate, &intent.candidate)
                })
            {
                if let Some(existing_device) = existing
                    .devices
                    .iter_mut()
                    .find(|existing_device| existing_device.id == device_id)
                {
                    existing_device.candidate = intent.candidate.clone();
                    if existing.intent.device_id == device_id {
                        existing.intent = intent;
                    }
                } else {
                    existing.devices.push(SelectedDriverDevice {
                        id: device_id,
                        candidate: intent.candidate,
                    });
                }
            } else {
                let candidate = intent.candidate.clone();
                self.drivers_ui.selected_updates.push(SelectedDriverUpdate {
                    intent,
                    devices: vec![SelectedDriverDevice {
                        id: device_id,
                        candidate,
                    }],
                });
            }
        } else {
            let identity = intent.candidate.clone();
            for item in &mut self.drivers_ui.selected_updates {
                if drivers::same_wua_update(&item.intent.candidate, &identity) {
                    item.devices.retain(|selected_device| {
                        selected_device.id != device_id || selected_device.candidate != identity
                    });
                }
            }
            self.drivers_ui
                .selected_updates
                .retain(|item| !item.devices.is_empty());
            let Some(snapshot) = self.drivers_ui.snapshot.clone() else {
                return;
            };
            for item in &mut self.drivers_ui.selected_updates {
                if item.devices.iter().any(|selected_device| {
                    selected_device.id == item.intent.device_id
                        && selected_device.candidate == item.intent.candidate
                }) {
                    continue;
                }
                let Some(selected_device) = item.devices.first() else {
                    continue;
                };
                let Some(device) = snapshot
                    .inventory
                    .devices
                    .iter()
                    .find(|device| device.id.as_ref() == Some(&selected_device.id))
                else {
                    continue;
                };
                let Some(candidate) = candidates_for(Some(&snapshot), device)
                    .into_iter()
                    .find(|candidate| candidate.identity == selected_device.candidate)
                else {
                    continue;
                };
                if let Ok(intent) = drivers::prepare_update_intent(device, candidate) {
                    item.intent = intent;
                }
            }
        }
    }

    fn single_driver_offer_intent(&self, device: &DriverDevice) -> Option<DriverUpdateIntent> {
        let snapshot = self.drivers_ui.snapshot.as_ref()?;
        let candidates = candidates_for(Some(snapshot), device);
        if candidates.len() != 1 || !self.driver_candidate_actionable(device, candidates[0]) {
            return None;
        }
        drivers::prepare_update_intent(device, candidates[0]).ok()
    }

    fn revalidate_selected_driver_offers(&mut self) {
        let (Some(snapshot), Some(settings)) = (
            self.drivers_ui.snapshot.clone(),
            self.drivers_ui.settings.clone(),
        ) else {
            self.drivers_ui.selected_updates.clear();
            return;
        };
        let mut retained = Vec::new();
        for mut selected in std::mem::take(&mut self.drivers_ui.selected_updates) {
            selected.devices.retain(|selected_device| {
                let Some(device) = snapshot
                    .inventory
                    .devices
                    .iter()
                    .find(|device| device.id.as_ref() == Some(&selected_device.id))
                else {
                    return false;
                };
                let Some(candidate) = candidates_for(Some(&snapshot), device)
                    .into_iter()
                    .find(|candidate| candidate.identity == selected_device.candidate)
                else {
                    return false;
                };
                drivers::same_wua_update(&candidate.identity, &selected.intent.candidate)
                    && !settings.is_ignored(&selected_device.id)
                    && !settings.is_skipped(&selected_device.id, &candidate.identity)
            });
            if selected.devices.is_empty() {
                continue;
            }
            let representative_is_current = selected.devices.iter().any(|device| {
                device.id == selected.intent.device_id
                    && device.candidate == selected.intent.candidate
            });
            if !representative_is_current {
                let Some(selected_device) = selected.devices.first() else {
                    continue;
                };
                let Some(device) = snapshot
                    .inventory
                    .devices
                    .iter()
                    .find(|device| device.id.as_ref() == Some(&selected_device.id))
                else {
                    continue;
                };
                let Some(candidate) = candidates_for(Some(&snapshot), device)
                    .into_iter()
                    .find(|candidate| candidate.identity == selected_device.candidate)
                else {
                    continue;
                };
                let Ok(intent) = drivers::prepare_update_intent(device, candidate) else {
                    continue;
                };
                selected.intent = intent;
            }
            retained.push(selected);
        }
        self.drivers_ui.selected_updates = retained;
    }

    fn driver_intent_can_apply(&self, intent: &DriverUpdateIntent) -> bool {
        let Some(snapshot) = self.drivers_ui.snapshot.as_ref() else {
            return false;
        };
        let Some(candidate) = snapshot
            .catalogue
            .candidates
            .iter()
            .find(|candidate| candidate.identity == intent.candidate)
        else {
            return false;
        };
        let device = snapshot
            .inventory
            .devices
            .iter()
            .find(|device| device.id.as_ref() == Some(&intent.device_id));
        candidate.eula_accepted.as_known() == Some(&true)
            && device.is_some_and(|device| self.driver_candidate_actionable(device, candidate))
    }

    fn driver_candidate_actionable(
        &self,
        device: &DriverDevice,
        candidate: &DriverCandidate,
    ) -> bool {
        let Some(device_id) = device.id.as_ref() else {
            return false;
        };
        self.drivers_ui.settings.as_ref().is_some_and(|settings| {
            !settings.is_ignored(device_id) && !settings.is_skipped(device_id, &candidate.identity)
        })
    }

    fn driver_selected_restore_intent(
        &self,
        device: &DriverDevice,
    ) -> Option<(DriverUpdateIntent, DriverUpdateReceipt, DriverRestoreIntent)> {
        self.driver_selected_restore_intent_with_limit(device, usize::MAX)
    }

    fn driver_selected_restore_intent_with_limit(
        &self,
        device: &DriverDevice,
        max_records: usize,
    ) -> Option<(DriverUpdateIntent, DriverUpdateReceipt, DriverRestoreIntent)> {
        driver_history_restore_intent(&self.drivers_ui.history, device, max_records)
    }

    fn driver_problem_history_result(
        &self,
        categories: &BTreeSet<DriverProblemCategory>,
    ) -> ProblemHistoryResult {
        if self.drivers_ui.history_error.is_some() {
            return ProblemHistoryResult::Unavailable {
                categories: categories.clone(),
                history_unreadable: true,
            };
        }
        let Some(snapshot) = self.drivers_ui.snapshot.as_ref() else {
            return ProblemHistoryResult::Unavailable {
                categories: categories.clone(),
                history_unreadable: false,
            };
        };
        if snapshot.inventory.source.quality == InventoryQuality::Unavailable {
            return ProblemHistoryResult::Unavailable {
                categories: categories.clone(),
                history_unreadable: false,
            };
        }

        let records_reviewed = self
            .drivers_ui
            .history
            .iter()
            .filter(|record| record.feature == "drivers")
            .take(MAX_RECENT_DRIVER_OPERATIONS)
            .count();
        let devices_matched = snapshot
            .inventory
            .devices
            .iter()
            .filter(|device| {
                driver_problem_history_matches(
                    &self.drivers_ui.history,
                    device,
                    categories,
                    MAX_RECENT_DRIVER_OPERATIONS,
                )
            })
            .count();
        if devices_matched == 0 {
            ProblemHistoryResult::NoRecentMatches {
                categories: categories.clone(),
                records_reviewed,
            }
        } else {
            ProblemHistoryResult::Matches {
                categories: categories.clone(),
                records_reviewed,
                devices_matched,
            }
        }
    }

    fn driver_tab_counts(&self) -> (Option<usize>, Option<usize>, Option<usize>) {
        let Some(snapshot) = self.drivers_ui.snapshot.as_ref() else {
            return (None, None, None);
        };
        let Some(settings) = self.drivers_ui.settings.as_ref() else {
            return (None, None, None);
        };
        (
            snapshot
                .inventory
                .devices
                .iter()
                .filter(|device| {
                    snapshot.status_for(device, settings) == DriverStatus::UpdateAvailable
                })
                .count()
                .into(),
            snapshot
                .inventory
                .devices
                .iter()
                .filter(|device| {
                    matches!(
                        snapshot.status_for(device, settings),
                        DriverStatus::NoOfferFromSource | DriverStatus::Unknown
                    )
                })
                .count()
                .into(),
            snapshot
                .inventory
                .devices
                .iter()
                .filter(|device| {
                    matches!(
                        snapshot.status_for(device, settings),
                        DriverStatus::Skipped | DriverStatus::Ignored
                    )
                })
                .count()
                .into(),
        )
    }

    fn driver_last_scan_label(&self) -> String {
        let Some(completed_at) = self.drivers_ui.last_scan_completed_at.as_ref() else {
            return if self.drivers_ui.loading {
                "Last scan: running".into()
            } else {
                "Last scan: not recorded".into()
            };
        };
        let seconds = chrono::Utc::now()
            .signed_duration_since(completed_at.clone())
            .num_seconds()
            .max(0);
        let elapsed = match seconds {
            0..=59 => "a few seconds ago".to_owned(),
            60..=3599 => format!("{} minutes ago", seconds / 60),
            3600..=86_399 => format!("{} hours ago", seconds / 3600),
            86_400..=604_799 => format!("{} days ago", seconds / 86_400),
            _ => completed_at
                .with_timezone(&chrono::Local)
                .format("%e %b %Y, %H:%M")
                .to_string(),
        };
        format!("Last scan: {elapsed}")
    }

    fn set_driver_ignored(&mut self, device_id: DeviceId, ignored: bool) {
        if self.qa_fixture_mode() {
            self.error =
                Some("QA fixture mode is read-only; no driver preference was saved.".into());
            return;
        }
        let Some(current) = self.drivers_ui.settings.clone() else {
            self.error =
                Some("Saved driver choices are not readable; the device was not changed.".into());
            return;
        };
        let mut updated = current;
        if let Err(error) = updated.set_ignored(device_id, ignored) {
            self.error = Some(error.to_string());
            return;
        }
        match drivers::save_settings(&self.data_dir, &updated) {
            Ok(()) => {
                self.drivers_ui.settings = Some(updated);
                self.revalidate_selected_driver_offers();
                self.error = None;
                self.notice = Some(if ignored {
                    "This device is hidden under Skipped & Ignored. Windows was not changed.".into()
                } else {
                    "The device ignore choice was removed. Windows was not changed.".into()
                });
            }
            Err(error) => {
                self.error = Some(format!("The saved device choice was not written: {error}"))
            }
        }
    }

    fn set_driver_skipped(
        &mut self,
        device_id: DeviceId,
        candidate: drivers::CandidateIdentity,
        skipped: bool,
    ) {
        if self.qa_fixture_mode() {
            self.error =
                Some("QA fixture mode is read-only; no driver preference was saved.".into());
            return;
        }
        let Some(current) = self.drivers_ui.settings.clone() else {
            self.error =
                Some("Saved driver choices are not readable; the offer was not changed.".into());
            return;
        };
        let mut updated = current;
        if let Err(error) = updated.set_skipped(device_id, candidate, skipped) {
            self.error = Some(error.to_string());
            return;
        }
        match drivers::save_settings(&self.data_dir, &updated) {
            Ok(()) => {
                self.drivers_ui.settings = Some(updated);
                self.revalidate_selected_driver_offers();
                self.error = None;
                self.notice = Some(if skipped {
                    "This exact Windows Update offer is skipped. Windows was not changed.".into()
                } else {
                    "The saved skip choice was removed. Windows was not changed.".into()
                });
            }
            Err(error) => {
                self.error = Some(format!("The saved offer choice was not written: {error}"))
            }
        }
    }
}

#[cfg(debug_assertions)]
fn driver_qa_snapshot(populated: bool) -> DriverSnapshot {
    let issue = NativeIssue {
        source: "Synthetic QA fixture".into(),
        operation: "No native device or update-source query was issued.".into(),
        failure: FieldFailure {
            kind: FieldFailureKind::NotPresent,
            native_code: None,
        },
    };
    let devices = if populated {
        let instance_id = "QA\\SYNTHETIC\\DISPLAY".to_owned();
        vec![DriverDevice {
            id: DeviceId::from_instance_id(&instance_id),
            instance_id: FieldValue::Known { value: instance_id },
            friendly_name: FieldValue::Known {
                value: "QA fixture display adapter (synthetic)".into(),
            },
            class_name: FieldValue::Known {
                value: "Display".into(),
            },
            class_guid: "4d36e968-e325-11ce-bfc1-08002be10318".into(),
            hardware_ids: FieldValue::Known {
                value: vec!["QA\\SYNTHETIC\\DISPLAY".into()],
            },
            compatible_ids: FieldValue::Known { value: Vec::new() },
            provider: FieldValue::Known {
                value: "Synthetic fixture metadata".into(),
            },
            installed_version: FieldValue::Known {
                value: "0.0-qa".into(),
            },
            installed_date: FieldValue::Unknown {
                failure: issue.failure.clone(),
            },
            inf_path: FieldValue::Unknown {
                failure: issue.failure.clone(),
            },
            problem_code: FieldValue::Unknown {
                failure: issue.failure.clone(),
            },
            offer: DeviceOffer::Unknown {
                failure: issue.failure.clone(),
            },
        }]
    } else {
        Vec::new()
    };
    let inventory = DeviceInventory {
        source: SourceReport {
            quality: if populated {
                InventoryQuality::Partial
            } else {
                InventoryQuality::Unavailable
            },
            item_count: devices.len(),
            issues: vec![issue.clone()],
        },
        devices,
    };
    let catalogue = DriverCatalogue {
        state: CatalogueState::Unavailable {
            issue: issue.clone(),
        },
        candidates: Vec::new(),
        issues: vec![issue],
    };
    DriverSnapshot::assemble(inventory, catalogue)
}

#[cfg(debug_assertions)]
fn driver_qa_known_inventory() -> (DeviceInventory, drivers::WuaSource) {
    let mut inventory = driver_qa_snapshot(true).inventory;
    inventory.source.quality = InventoryQuality::Complete;
    inventory.source.issues.clear();
    let device = &mut inventory.devices[0];
    device.provider = FieldValue::Known {
        value: "Synthetic QA provider".into(),
    };
    device.installed_version = FieldValue::Known {
        value: "2.0-qa-synthetic".into(),
    };
    device.installed_date = FieldValue::Known {
        value: "2026-01-02-qa-synthetic".into(),
    };
    device.inf_path = FieldValue::Known {
        value: "oem2.inf".into(),
    };
    device.problem_code = FieldValue::Known { value: 0 };
    let source = drivers::WuaSource {
        server_selection: drivers::WuaServerSelection::PolicyDefault,
        service_id: String::new(),
        online_search: true,
    };
    (inventory, source)
}

#[cfg(debug_assertions)]
fn driver_qa_candidate_for_device(
    device: &DriverDevice,
    source: &drivers::WuaSource,
) -> DriverCandidate {
    let device_id = device
        .id
        .clone()
        .expect("QA device has a stable synthetic ID");
    let identity = drivers::CandidateIdentity {
        update_id: "00000000-0000-4000-8000-000000000071".into(),
        revision: 1,
        source: source.clone(),
        driver_hardware_id: "QA\\SYNTHETIC\\DISPLAY".into(),
    };
    let unavailable = || FieldValue::Unknown {
        failure: FieldFailure {
            kind: FieldFailureKind::NotProvidedByApi,
            native_code: None,
        },
    };
    DriverCandidate {
        id: identity.id(),
        identity,
        title: FieldValue::Known {
            value: "QA synthetic driver offer (not a real update)".into(),
        },
        manufacturer: FieldValue::Known {
            value: "Synthetic QA data".into(),
        },
        model: FieldValue::Known {
            value: "Synthetic display adapter".into(),
        },
        class: FieldValue::Known {
            value: "Display".into(),
        },
        provider: FieldValue::Known {
            value: "Synthetic QA provider".into(),
        },
        release_date: unavailable(),
        candidate_version: unavailable(),
        applicability: drivers::CandidateMatch::Matched {
            devices: vec![device_id],
        },
        eula_accepted: FieldValue::Known { value: true },
        installed: FieldValue::Known { value: false },
        hidden: FieldValue::Known { value: false },
    }
}

#[cfg(debug_assertions)]
fn driver_qa_offered_snapshot() -> DriverSnapshot {
    let (inventory, source) = driver_qa_known_inventory();
    let candidate = driver_qa_candidate_for_device(&inventory.devices[0], &source);
    DriverSnapshot::assemble(
        inventory,
        DriverCatalogue {
            state: CatalogueState::Read { source },
            candidates: vec![candidate],
            issues: Vec::new(),
        },
    )
}

#[cfg(debug_assertions)]
fn driver_qa_recent_snapshot() -> DriverSnapshot {
    let (inventory, source) = driver_qa_known_inventory();
    DriverSnapshot::assemble(
        inventory,
        DriverCatalogue {
            state: CatalogueState::Read { source },
            candidates: Vec::new(),
            issues: Vec::new(),
        },
    )
}

#[cfg(debug_assertions)]
fn driver_qa_recent_history(snapshot: &DriverSnapshot) -> Vec<EffectHistory> {
    let device = snapshot
        .inventory
        .devices
        .first()
        .expect("QA recent-history snapshot has one synthetic device");
    let source = drivers::WuaSource {
        server_selection: drivers::WuaServerSelection::PolicyDefault,
        service_id: String::new(),
        online_search: true,
    };
    let candidate = driver_qa_candidate_for_device(device, &source);
    let mut original = device.clone();
    original.provider = FieldValue::Known {
        value: "Synthetic QA provider".into(),
    };
    original.installed_version = FieldValue::Known {
        value: "1.0-qa-synthetic".into(),
    };
    original.installed_date = FieldValue::Known {
        value: "2025-12-31-qa-synthetic".into(),
    };
    original.inf_path = FieldValue::Known {
        value: "oem1.inf".into(),
    };
    let intent = drivers::prepare_update_intent(&original, &candidate)
        .expect("synthetic QA update intent is internally consistent");
    let backup_id =
        Uuid::parse_str("00000000-0000-4000-8000-000000000072").expect("fixed QA UUID is valid");
    let backup = drivers::DriverBackupReceipt {
        schema_version: drivers::DRIVER_SCHEMA_VERSION,
        backup_id,
        device_id: intent.device_id.clone(),
        device_instance_id: intent.device_instance_id.clone(),
        original_inf: "oem1.inf".into(),
        relative_directory: format!("drivers/backups/{backup_id}"),
        files: vec![
            drivers::DriverBackupFile {
                relative_path: "package/oem1.inf".into(),
                byte_length: 128,
                sha256: "a".repeat(64),
            },
            drivers::DriverBackupFile {
                relative_path: "package/fixture.cat".into(),
                byte_length: 256,
                sha256: "b".repeat(64),
            },
        ],
        manifest_sha256: "c".repeat(64),
        signature_verified: true,
    };
    let original_state = drivers::DriverInstalledState {
        provider: "Synthetic QA provider".into(),
        version: "1.0-qa-synthetic".into(),
        date: "2025-12-31-qa-synthetic".into(),
        inf: "oem1.inf".into(),
    };
    let installed_after = drivers::DriverInstalledState::from_device(device)
        .expect("synthetic current QA device has a complete installed state");
    let receipt = DriverUpdateReceipt {
        schema_version: drivers::DRIVER_SCHEMA_VERSION,
        intent_id: intent.intent_id,
        device_id: intent.device_id.clone(),
        device_instance_id: intent.device_instance_id.clone(),
        candidate: intent.candidate.clone(),
        original_state,
        backup: Some(backup),
        restore_point_sequence: Some(1),
        phase: drivers::DriverEffectPhase::Verified,
        download_result_code: Some(2),
        download_hresult: Some(0),
        download_item_result_code: Some(2),
        download_item_hresult: Some(0),
        downloaded_verified: true,
        wua_result_code: Some(2),
        hresult: Some(0),
        install_item_result_code: Some(2),
        install_item_hresult: Some(0),
        reboot: RebootRequirement::NotRequired,
        installed_after: Some(installed_after),
    };
    assert!(receipt.is_restore_eligible());
    vec![EffectHistory {
        id: intent.intent_id,
        feature: "drivers".into(),
        date: "2026-01-02T00:00:00Z · synthetic QA only".into(),
        intent: serde_json::to_value(intent).expect("QA intent serializes"),
        state: "verified".into(),
        receipt: Some(serde_json::to_value(receipt).expect("QA receipt serializes")),
    }]
}

fn candidates_for<'a>(
    snapshot: Option<&'a DriverSnapshot>,
    device: &DriverDevice,
) -> Vec<&'a DriverCandidate> {
    let (Some(snapshot), DeviceOffer::CandidateAvailable { candidates }) =
        (snapshot, &device.offer)
    else {
        return Vec::new();
    };
    candidates
        .iter()
        .filter_map(|id| {
            snapshot
                .catalogue
                .candidates
                .iter()
                .find(|candidate| candidate.id == *id)
        })
        .collect()
}

fn driver_history_restore_intent(
    history: &[EffectHistory],
    device: &DriverDevice,
    max_records: usize,
) -> Option<(DriverUpdateIntent, DriverUpdateReceipt, DriverRestoreIntent)> {
    let device_id = device.id.as_ref()?;
    for record in history
        .iter()
        .filter(|record| record.feature == "drivers")
        .take(max_records)
    {
        if record.state != "verified" {
            continue;
        }
        let Ok(intent) = serde_json::from_value::<DriverUpdateIntent>(record.intent.clone()) else {
            continue;
        };
        let Some(receipt_value) = record.receipt.clone() else {
            continue;
        };
        let Ok(receipt) = serde_json::from_value::<DriverUpdateReceipt>(receipt_value) else {
            continue;
        };
        if record.id != intent.intent_id
            || &intent.device_id != device_id
            || receipt.intent_id != intent.intent_id
            || receipt.device_id != intent.device_id
            || receipt.device_instance_id != intent.device_instance_id
            || receipt.candidate != intent.candidate
            || !receipt.is_restore_eligible()
        {
            continue;
        }
        let Ok(restore) = drivers::prepare_restore_intent(&intent, &receipt, device) else {
            continue;
        };
        return Some((intent, receipt, restore));
    }
    None
}

fn driver_problem_history_matches(
    history: &[EffectHistory],
    device: &DriverDevice,
    categories: &BTreeSet<DriverProblemCategory>,
    max_records: usize,
) -> bool {
    categories
        .iter()
        .any(|category| category.matches_device(device.category()))
        && driver_history_restore_intent(history, device, max_records).is_some()
}

fn tab_matches(tab: DriverTab, status: DriverStatus) -> bool {
    match tab {
        DriverTab::Outdated => status == DriverStatus::UpdateAvailable,
        DriverTab::NoOfferUnknown => matches!(
            status,
            DriverStatus::NoOfferFromSource | DriverStatus::Unknown
        ),
        DriverTab::Deferred => matches!(status, DriverStatus::Skipped | DriverStatus::Ignored),
    }
}

fn driver_matches_query(snapshot: &DriverSnapshot, device: &DriverDevice, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    let mut fields: Vec<&str> = [
        known(&device.friendly_name),
        known(&device.class_name),
        known(&device.provider),
        known(&device.instance_id),
    ]
    .into_iter()
    .flatten()
    .collect();
    if let Some(ids) = device.hardware_ids.as_known() {
        fields.extend(ids.iter().map(String::as_str));
    }
    if let Some(ids) = device.compatible_ids.as_known() {
        fields.extend(ids.iter().map(String::as_str));
    }
    fields.extend(
        candidates_for(Some(snapshot), device)
            .into_iter()
            .flat_map(|candidate| {
                [
                    known(&candidate.title),
                    known(&candidate.manufacturer),
                    known(&candidate.model),
                    known(&candidate.provider),
                ]
                .into_iter()
                .flatten()
            }),
    );
    fields
        .into_iter()
        .any(|value| value.to_lowercase().contains(&query))
}

fn offer_display(snapshot: &DriverSnapshot, device: &DriverDevice) -> String {
    match &device.offer {
        DeviceOffer::CandidateAvailable { .. } => {
            let candidates = candidates_for(Some(snapshot), device);
            match candidates.as_slice() {
                [candidate] => known(&candidate.title)
                    .unwrap_or("Offer details unavailable")
                    .to_owned(),
                candidates if !candidates.is_empty() => format!("{} offers", candidates.len()),
                _ => "Offer details unavailable".into(),
            }
        }
        DeviceOffer::NoOfferFromSource { .. } => "No matching offer".into(),
        DeviceOffer::Unknown { .. } => "Unknown".into(),
    }
}

fn release_display(snapshot: &DriverSnapshot, device: &DriverDevice) -> String {
    let candidates = candidates_for(Some(snapshot), device);
    match candidates.as_slice() {
        [candidate] => candidate
            .release_date
            .as_known()
            .filter(|date| !date.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| "Unknown".into()),
        candidates if candidates.len() > 1 => "Multiple offers".into(),
        _ => "—".into(),
    }
}

fn candidate_version_cell_display(snapshot: &DriverSnapshot, device: &DriverDevice) -> String {
    match candidates_for(Some(snapshot), device).as_slice() {
        [candidate] => candidate
            .candidate_version
            .as_known()
            .filter(|version| !version.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| "Unknown".into()),
        candidates if candidates.len() > 1 => "Multiple offers".into(),
        _ if matches!(&device.offer, DeviceOffer::Unknown { .. }) => "Unknown".into(),
        _ => "—".into(),
    }
}

fn candidate_version_tooltip(snapshot: &DriverSnapshot, device: &DriverDevice) -> String {
    match candidates_for(Some(snapshot), device).as_slice() {
        [candidate] => match &candidate.candidate_version {
            FieldValue::Known { value } if !value.trim().is_empty() => {
                "Candidate version reported by Windows Update Agent".into()
            }
            FieldValue::Known { .. } => {
                "Windows Update Agent returned an empty candidate version".into()
            }
            FieldValue::Unknown { failure } => failure.summary().into(),
        },
        candidates if candidates.len() > 1 => {
            "Several exact offers are available; review an offer to see its version field.".into()
        }
        _ => match &device.offer {
            DeviceOffer::Unknown { failure } => failure.summary().into(),
            DeviceOffer::NoOfferFromSource { .. } => {
                "The selected source returned no matching offer.".into()
            }
            DeviceOffer::CandidateAvailable { .. } => {
                "Exact offer details are unavailable in this result.".into()
            }
        },
    }
}

fn compare_devices(
    snapshot: &DriverSnapshot,
    left: &DriverDevice,
    left_status: DriverStatus,
    right: &DriverDevice,
    right_status: DriverStatus,
    sort: DriverSort,
) -> std::cmp::Ordering {
    let compare_text = |left: &str, right: &str| left.to_lowercase().cmp(&right.to_lowercase());
    let ordering = match sort {
        DriverSort::Device => compare_text(
            known(&left.friendly_name).unwrap_or(""),
            known(&right.friendly_name).unwrap_or(""),
        ),
        DriverSort::Installed => compare_text(
            known(&left.installed_version).unwrap_or(""),
            known(&right.installed_version).unwrap_or(""),
        ),
        DriverSort::CandidateVersion => compare_optional_text(
            candidate_version_sort_value(snapshot, left),
            candidate_version_sort_value(snapshot, right),
        ),
        DriverSort::Release => compare_optional_text(
            release_sort_value(snapshot, left),
            release_sort_value(snapshot, right),
        ),
        DriverSort::State => status_label(left_status).cmp(status_label(right_status)),
    };
    ordering.then_with(|| {
        compare_text(
            known(&left.friendly_name).unwrap_or(""),
            known(&right.friendly_name).unwrap_or(""),
        )
    })
}

fn compare_optional_text(left: Option<&str>, right: Option<&str>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.to_lowercase().cmp(&right.to_lowercase()),
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn candidate_version_sort_value<'a>(
    snapshot: &'a DriverSnapshot,
    device: &DriverDevice,
) -> Option<&'a str> {
    let candidates = candidates_for(Some(snapshot), device);
    match candidates.as_slice() {
        [candidate] => {
            known(&candidate.candidate_version).filter(|version| !version.trim().is_empty())
        }
        _ => None,
    }
}

fn release_sort_value<'a>(snapshot: &'a DriverSnapshot, device: &DriverDevice) -> Option<&'a str> {
    let candidates = candidates_for(Some(snapshot), device);
    match candidates.as_slice() {
        [candidate] => known(&candidate.release_date).filter(|date| !date.trim().is_empty()),
        _ => None,
    }
}

fn select_driver_header_sort(
    current: &mut DriverSort,
    descending: &mut bool,
    selected: DriverSort,
) {
    if *current == selected {
        *descending = !*descending;
    } else {
        *current = selected;
        *descending = false;
    }
}

fn status_label(status: DriverStatus) -> &'static str {
    match status {
        DriverStatus::UpdateAvailable => "Offer available",
        DriverStatus::NoOfferFromSource => "No offer",
        DriverStatus::Skipped => "Skipped",
        DriverStatus::Ignored => "Ignored",
        DriverStatus::Unknown => "Unknown",
    }
}

fn status_color(status: DriverStatus, t: Tokens) -> egui::Color32 {
    match status {
        DriverStatus::UpdateAvailable => t.primary,
        DriverStatus::Skipped | DriverStatus::Ignored | DriverStatus::Unknown => t.attention,
        DriverStatus::NoOfferFromSource => t.muted,
    }
}

fn catalogue_label(state: &CatalogueState) -> String {
    match state {
        CatalogueState::Read { .. } => "search completed".into(),
        CatalogueState::Partial { .. } => "partial search".into(),
        CatalogueState::Unavailable { .. } => "unavailable".into(),
        CatalogueState::Truncated { .. } => "result limit reached".into(),
    }
}

fn inventory_quality_label(quality: InventoryQuality) -> &'static str {
    match quality {
        InventoryQuality::Complete => "complete",
        InventoryQuality::Partial => "partial",
        InventoryQuality::Truncated => "truncated",
        InventoryQuality::Unavailable => "unavailable",
    }
}

fn known(field: &FieldValue<String>) -> Option<&str> {
    field.as_known().map(String::as_str)
}

fn field_display<T: std::fmt::Display>(field: &FieldValue<T>) -> String {
    match field {
        FieldValue::Known { value } if !value.to_string().trim().is_empty() => value.to_string(),
        FieldValue::Known { .. } => "Empty value reported by Windows".into(),
        FieldValue::Unknown { failure } => format!("Unknown · {}", failure.summary()),
    }
}

fn field_tooltip<T>(field: &FieldValue<T>) -> String {
    match field {
        FieldValue::Known { .. } => "Reported by Windows SetupAPI".into(),
        FieldValue::Unknown { failure } => failure.summary().into(),
    }
}

fn device_identity_tooltip(device: &DriverDevice) -> String {
    format!(
        "{}\n{}",
        field_display(&device.friendly_name),
        field_display(&device.instance_id)
    )
}

fn driver_dialog_heading(ui: &mut egui::Ui, title: &str, close_enabled: bool) -> bool {
    let mut close = false;
    ui.horizontal(|ui| {
        ui.heading(title);
        ui.with_layout(Layout::right_to_left(Align::Center), |actions| {
            close = theme::close_button(actions, "Close dialog", close_enabled);
        });
    });
    close
}

fn driver_device_heading(ui: &mut egui::Ui, device: &DriverDevice, close_enabled: bool) -> bool {
    let title = known(&device.friendly_name)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("Name unavailable");
    let mut close = false;
    ui.horizontal(|ui| {
        let close_width = 28.;
        let title_width =
            (ui.available_width() - close_width - ui.spacing().item_spacing.x).max(56.);
        let response = ui
            .allocate_ui_with_layout(
                [title_width, 30.].into(),
                Layout::left_to_right(Align::Center),
                |title_ui| {
                    title_ui.set_min_width(title_width);
                    title_ui.set_max_width(title_width);
                    title_ui.add(
                        egui::Label::new(
                            RichText::new(title)
                                .size(theme::FONT_DISPLAY)
                                .family(theme::semibold()),
                        )
                        .truncate(),
                    )
                },
            )
            .inner;
        response.on_hover_text(title);
        close = theme::close_button(ui, "Close dialog", close_enabled);
    });
    close
}

fn driver_primary_field(ui: &mut egui::Ui, label: &str, field: &FieldValue<String>, t: Tokens) {
    let value = match field {
        FieldValue::Known { value } if !value.trim().is_empty() => value.as_str(),
        FieldValue::Known { .. } => "Unavailable",
        FieldValue::Unknown { .. } => "Unknown",
    };
    let tooltip = format!("{value}\n{}", field_tooltip(field));
    driver_primary_value(ui, label, value, &tooltip, t);
}

fn driver_primary_value(ui: &mut egui::Ui, label: &str, value: &str, tooltip: &str, t: Tokens) {
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            [132., 24.].into(),
            Layout::left_to_right(Align::Center),
            |cell| {
                cell.set_min_size([132., 24.].into());
                cell.set_max_width(132.);
                theme::muted(cell, label, t);
            },
        );
        let width = ui.available_width();
        ui.allocate_ui_with_layout(
            [width, 24.].into(),
            Layout::left_to_right(Align::Center),
            |cell| {
                cell.set_min_size([width, 24.].into());
                cell.set_max_width(width);
                cell.add(egui::Label::new(RichText::new(value).size(theme::FONT_BODY)).truncate())
                    .on_hover_text(tooltip);
            },
        );
    });
}

struct DriverVersionHistoryEntry {
    date: String,
    status: String,
    transition: Option<String>,
}

fn driver_device_version_history(
    history: &[EffectHistory],
    device: &DriverDevice,
) -> Vec<DriverVersionHistoryEntry> {
    let (Some(device_id), Some(instance_id)) = (
        device.id.as_ref().filter(|id| !id.0.trim().is_empty()),
        known(&device.instance_id).filter(|id| !id.trim().is_empty()),
    ) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for record in history
        .iter()
        .filter(|record| record.feature == "drivers")
        .take(MAX_RECENT_DRIVER_OPERATIONS)
    {
        if let Ok(intent) = serde_json::from_value::<DriverUpdateIntent>(record.intent.clone()) {
            if record.id != intent.intent_id
                || &intent.device_id != device_id
                || intent.device_instance_id != instance_id
            {
                continue;
            }
            let transition = record.receipt.as_ref().and_then(|value| {
                let receipt = serde_json::from_value::<DriverUpdateReceipt>(value.clone()).ok()?;
                if record.state != "verified"
                    || receipt.phase != drivers::DriverEffectPhase::Verified
                    || receipt.intent_id != intent.intent_id
                    || receipt.device_id != intent.device_id
                    || receipt.device_instance_id != intent.device_instance_id
                    || receipt.candidate != intent.candidate
                {
                    return None;
                }
                let installed = receipt.installed_after.as_ref()?;
                (!receipt.original_state.version.trim().is_empty()
                    && !installed.version.trim().is_empty())
                .then(|| format!("{} → {}", receipt.original_state.version, installed.version))
            });
            entries.push(DriverVersionHistoryEntry {
                date: record.date.clone(),
                status: history_label(&record.state).to_owned(),
                transition,
            });
            continue;
        }

        if let Ok(intent) = serde_json::from_value::<DriverRestoreIntent>(record.intent.clone()) {
            if record.id != intent.restore_id
                || &intent.device_id != device_id
                || intent.device_instance_id != instance_id
            {
                continue;
            }
            let transition = record.receipt.as_ref().and_then(|value| {
                let receipt = serde_json::from_value::<DriverRestoreReceipt>(value.clone()).ok()?;
                if record.state != "restored"
                    || receipt.phase != drivers::DriverEffectPhase::Verified
                    || receipt.restore_id != intent.restore_id
                    || receipt.update_intent_id != intent.update_intent_id
                    || receipt.device_id != intent.device_id
                {
                    return None;
                }
                let restored = receipt.restored_state.as_ref()?;
                (!intent.expected_installed_state.version.trim().is_empty()
                    && !restored.version.trim().is_empty())
                .then(|| {
                    format!(
                        "{} → {}",
                        intent.expected_installed_state.version, restored.version
                    )
                })
            });
            entries.push(DriverVersionHistoryEntry {
                date: record.date.clone(),
                status: history_label(&record.state).to_owned(),
                transition,
            });
        }
    }
    entries
}

fn tab_header(ui: &mut egui::Ui, label: &str, width: f32, t: Tokens) -> egui::Response {
    theme::table_cell(
        ui,
        RichText::new(label)
            .size(theme::FONT_CAPTION)
            .color(t.muted),
        width,
        22.,
    )
}

fn table_heading(ui: &mut egui::Ui, label: &str, width: f32, t: Tokens) -> egui::Response {
    tab_header(ui, label, width, t)
}

fn driver_sort_heading(
    ui: &mut egui::Ui,
    label: &str,
    width: f32,
    sort: DriverSort,
    current: DriverSort,
    descending: bool,
    t: Tokens,
) -> egui::Response {
    let selected = sort == current;
    let indicator = if selected {
        if descending { " ↓" } else { " ↑" }
    } else {
        ""
    };
    let response = ui
        .allocate_ui_with_layout(
            [width, 22.].into(),
            egui::Layout::left_to_right(egui::Align::Center),
            |cell| {
                cell.set_min_size([width, 22.].into());
                cell.set_max_width(width);
                cell.add(
                    egui::Label::new(
                        RichText::new(format!("{label}{indicator}"))
                            .size(theme::FONT_CAPTION)
                            .color(if selected { t.foreground } else { t.muted }),
                    )
                    .truncate()
                    .sense(egui::Sense::click()),
                )
            },
        )
        .inner
        .on_hover_text(if selected {
            format!("Sorted by {label}; click to reverse")
        } else {
            format!("Sort by {label}")
        });
    #[cfg(debug_assertions)]
    theme::record_fixture_control(ui, &format!("Sort {label}"), &response);
    response
}

#[cfg(debug_assertions)]
fn driver_tab_name(tab: DriverTab) -> &'static str {
    match tab {
        DriverTab::Outdated => "Outdated drivers",
        DriverTab::NoOfferUnknown => "No offer / unknown",
        DriverTab::Deferred => "Skipped & Ignored",
    }
}

#[cfg(debug_assertions)]
fn driver_sort_name(sort: DriverSort) -> &'static str {
    match sort {
        DriverSort::Device => "Drivers",
        DriverSort::Installed => "Installed",
        DriverSort::CandidateVersion => "New version",
        DriverSort::Release => "Released",
        DriverSort::State => "State",
    }
}

fn detail(ui: &mut egui::Ui, name: &str, value: &str, t: Tokens) {
    theme::muted(ui, name, t);
    ui.add(egui::Label::new(value).wrap());
    ui.add_space(4.);
}

fn review_detail(ui: &mut egui::Ui, name: &str, value: &str, t: Tokens) {
    theme::muted(ui, name, t);
    ui.add(egui::Label::new(value).wrap());
    ui.add_space(5.);
}

fn candidate_details(ui: &mut egui::Ui, t: Tokens, candidate: &DriverCandidate) {
    detail(
        ui,
        "Offer",
        known(&candidate.title).unwrap_or("Offer details unavailable"),
        t,
    );
    detail(
        ui,
        "Provider / manufacturer",
        &format!(
            "{} / {}",
            known(&candidate.provider).unwrap_or("Unknown"),
            known(&candidate.manufacturer).unwrap_or("Unknown")
        ),
        t,
    );
    detail(
        ui,
        "Candidate version",
        &candidate_version_display(candidate),
        t,
    );
    detail(
        ui,
        "Release date",
        known(&candidate.release_date).unwrap_or("Unavailable"),
        t,
    );
    detail(
        ui,
        "Exact WUA identity",
        &format!(
            "{} · revision {}",
            candidate.identity.update_id, candidate.identity.revision
        ),
        t,
    );
    detail(
        ui,
        "License state",
        match candidate.eula_accepted.as_known() {
            Some(true) => "Accepted in Windows",
            Some(false) => "Not accepted in Windows",
            None => "Unknown",
        },
        t,
    );
}

fn candidate_version_display(candidate: &DriverCandidate) -> String {
    match candidate.candidate_version.as_known() {
        Some(version) if !version.trim().is_empty() => version.clone(),
        _ => field_display(&candidate.candidate_version),
    }
}

fn issue_line(ui: &mut egui::Ui, t: Tokens, issue: &drivers::NativeIssue) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{} · {}", issue.source, issue.operation)).color(t.muted));
        ui.label(issue.failure.summary());
        if let Some(code) = issue.failure.native_code {
            ui.label(
                RichText::new(format!("0x{code:08X}"))
                    .monospace()
                    .color(t.muted),
            );
        }
    });
}

fn history_label(state: &str) -> &str {
    match state {
        "verified" => "Update verified",
        "applied" => "Applied · restart or verification pending",
        "restored" => "Driver restored",
        "failed" => "Operation failed",
        "uncertain" => "Outcome uncertain · inspect before retry",
        other => other,
    }
}

fn reboot_note(requirement: RebootRequirement) -> String {
    match requirement {
        RebootRequirement::Required => " Restart required; it will not be automatic.".into(),
        RebootRequirement::NotRequired => " No restart was reported by Windows.".into(),
        RebootRequirement::Unknown => " Windows did not provide a restart requirement.".into(),
    }
}

fn status_card(ui: &mut egui::Ui, t: Tokens, heading: &str, body: &str) {
    egui::Frame::new()
        .fill(t.tint)
        .stroke(egui::Stroke::new(1., t.border))
        .corner_radius(9)
        .inner_margin(12.)
        .show(ui, |ui| {
            ui.label(RichText::new(heading).family(theme::semibold()));
            ui.add_space(4.);
            theme::muted(ui, body, t);
        });
}

#[cfg(all(test, debug_assertions))]
mod table_sort_tests {
    use super::*;

    #[test]
    fn header_selection_resets_direction_then_reverses_on_repeat() {
        let mut sort = DriverSort::Release;
        let mut descending = true;

        select_driver_header_sort(&mut sort, &mut descending, DriverSort::Device);
        assert_eq!(sort, DriverSort::Device);
        assert!(!descending);

        select_driver_header_sort(&mut sort, &mut descending, DriverSort::Device);
        assert_eq!(sort, DriverSort::Device);
        assert!(descending);
    }

    #[test]
    fn unavailable_values_sort_as_unknown_without_invented_metadata() {
        assert_eq!(
            compare_optional_text(None, Some("2026-01-01")),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_optional_text(Some("2026-01-01"), None),
            std::cmp::Ordering::Greater
        );
        assert_eq!(compare_optional_text(None, None), std::cmp::Ordering::Equal);
    }

    #[test]
    fn problem_history_requires_matching_category_verified_receipt_and_current_device() {
        let snapshot = driver_qa_recent_snapshot();
        let device = &snapshot.inventory.devices[0];
        let history = driver_qa_recent_history(&snapshot);
        let display = BTreeSet::from([DriverProblemCategory::MonitorDisplay]);
        let sound = BTreeSet::from([DriverProblemCategory::Sound]);
        let not_sure = BTreeSet::from([DriverProblemCategory::NotSure]);

        assert!(driver_problem_history_matches(
            &history,
            device,
            &display,
            MAX_RECENT_DRIVER_OPERATIONS,
        ));
        assert!(!driver_problem_history_matches(
            &history,
            device,
            &sound,
            MAX_RECENT_DRIVER_OPERATIONS,
        ));
        assert!(driver_problem_history_matches(
            &history,
            device,
            &not_sure,
            MAX_RECENT_DRIVER_OPERATIONS,
        ));

        let mut uncertain = history.clone();
        uncertain[0].state = "uncertain".into();
        assert!(!driver_problem_history_matches(
            &uncertain,
            device,
            &display,
            MAX_RECENT_DRIVER_OPERATIONS,
        ));

        let mut mismatched_journal_id = history.clone();
        mismatched_journal_id[0].id = Uuid::new_v4();
        assert!(!driver_problem_history_matches(
            &mismatched_journal_id,
            device,
            &display,
            MAX_RECENT_DRIVER_OPERATIONS,
        ));

        let mut ineligible_backup = history.clone();
        ineligible_backup[0]
            .receipt
            .as_mut()
            .expect("QA record has a receipt")["backup"]["signature_verified"] =
            serde_json::Value::Bool(false);
        assert!(!driver_problem_history_matches(
            &ineligible_backup,
            device,
            &display,
            MAX_RECENT_DRIVER_OPERATIONS,
        ));

        let mut changed_device = device.clone();
        changed_device.installed_version = FieldValue::Known {
            value: "3.0-qa-synthetic".into(),
        };
        assert!(!driver_problem_history_matches(
            &history,
            &changed_device,
            &display,
            MAX_RECENT_DRIVER_OPERATIONS,
        ));
    }

    #[test]
    fn device_version_history_shows_only_exact_verified_transitions() {
        let snapshot = driver_qa_recent_snapshot();
        let device = &snapshot.inventory.devices[0];
        let history = driver_qa_recent_history(&snapshot);

        let entries = driver_device_version_history(&history, device);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, "Update verified");
        assert_eq!(
            entries[0].transition.as_deref(),
            Some("1.0-qa-synthetic → 2.0-qa-synthetic")
        );

        let mut uncertain = history.clone();
        uncertain[0].state = "uncertain".into();
        let entries = driver_device_version_history(&uncertain, device);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].transition.is_none());

        let mut mismatched_receipt = history;
        mismatched_receipt[0]
            .receipt
            .as_mut()
            .expect("QA history has a receipt")["device_instance_id"] =
            serde_json::Value::String("different-device".into());
        let entries = driver_device_version_history(&mismatched_receipt, device);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].transition.is_none());
    }

    #[test]
    fn problem_history_reviews_only_latest_twelve_driver_records() {
        let snapshot = driver_qa_recent_snapshot();
        let device = &snapshot.inventory.devices[0];
        let mut old_records = driver_qa_recent_history(&snapshot);
        let verified_older = old_records.remove(0);
        let mut history = Vec::new();
        for day in (1..=MAX_RECENT_DRIVER_OPERATIONS).rev() {
            let mut newer_uncertain = verified_older.clone();
            newer_uncertain.id = Uuid::new_v4();
            newer_uncertain.date = format!("2026-02-{day:02}T00:00:00Z");
            newer_uncertain.state = "uncertain".into();
            history.push(newer_uncertain);
        }
        history.push(verified_older);
        let display = BTreeSet::from([DriverProblemCategory::MonitorDisplay]);

        assert!(driver_history_restore_intent(&history, device, usize::MAX).is_some());
        assert!(
            driver_history_restore_intent(&history, device, MAX_RECENT_DRIVER_OPERATIONS).is_none()
        );
        assert!(!driver_problem_history_matches(
            &history,
            device,
            &display,
            MAX_RECENT_DRIVER_OPERATIONS,
        ));
    }

    #[test]
    fn offered_fixture_uses_one_exact_synthetic_wua_match_without_invented_metadata() {
        let snapshot = driver_qa_offered_snapshot();
        let device = &snapshot.inventory.devices[0];
        assert_eq!(
            snapshot.status_for(device, &DriverSettings::default()),
            DriverStatus::UpdateAvailable
        );
        assert_eq!(candidates_for(Some(&snapshot), device).len(), 1);
        let candidate = &snapshot.catalogue.candidates[0];
        assert_eq!(candidate.candidate_version.as_known(), None);
        assert_eq!(candidate.release_date.as_known(), None);
        assert!(drivers::prepare_update_intent(device, candidate).is_ok());
    }
}
