//! Page-owned saved choices: bounded acknowledgement, no disk I/O on the UI thread.
use super::{App, Page, theme};
use dcleaner::{
    drivers::{self, DriverSettings},
    software::{self, SoftwareSettings},
};
use eframe::egui;
use std::{path::Path, sync::mpsc, thread};
const UNVERIFIED_PREFIX: &str = "Saved choices could not be verified: ";

#[cfg(test)]
#[path = "page_choice_save/tests.rs"]
mod tests;

#[derive(Clone)]
pub(super) enum Change {
    Driver {
        proposed: DriverSettings,
        notice: String,
    },
    Software(SoftwareSettings),
}
impl Change {
    fn origin(&self) -> Page {
        match self {
            Self::Driver { .. } => Page::Drivers,
            Self::Software(_) => Page::Software,
        }
    }
    fn progress(&self) -> &'static str {
        match self {
            Self::Driver { .. } => "Saving driver choices…",
            Self::Software(_) => "Saving updater choices…",
        }
    }
    fn write_and_verify(&self, root: &Path) -> Result<(), String> {
        let matches = match self {
            Self::Driver { proposed, .. } => {
                drivers::save_settings(root, proposed).map_err(|error| error.to_string())?;
                drivers::load_settings(root).map_err(|error| error.to_string())? == *proposed
            }
            Self::Software(proposed) => {
                software::save_settings(root, proposed).map_err(|error| error.to_string())?;
                software::load_settings(root).map_err(|error| error.to_string())? == *proposed
            }
        };
        if matches {
            Ok(())
        } else {
            Err("The saved choices did not match the requested change. Refresh to verify the current file before trying again.".into())
        }
    }
}

pub(super) struct Pending {
    receiver: mpsc::Receiver<Result<(), String>>,
    change: Change,
    #[cfg(debug_assertions)]
    _fixture_guard: Option<mpsc::SyncSender<Result<(), String>>>,
}

impl App {
    pub(super) fn queue_page_choices(&mut self, change: Change) -> Result<(), String> {
        if self.qa_fixture_mode() {
            return Err("Fixture mode does not save page choices.".into());
        }
        self.start_page_choices_writer(change, |root, value| value.write_and_verify(root))
    }

    fn start_page_choices_writer(
        &mut self,
        change: Change,
        write: impl FnOnce(&Path, &Change) -> Result<(), String> + Send + 'static,
    ) -> Result<(), String> {
        if self.busy() || self.preferences_busy() {
            return Err(
                "Wait for the current operation to finish before changing saved choices.".into(),
            );
        }
        if !self.data_dir.is_absolute() {
            return Err("The choices directory is unavailable; no writer was started.".into());
        }
        let root = self.data_dir.clone();
        let value = change.clone();
        let repaint = self.ui_context.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::Builder::new().name("dcleaner-page-choices".into()).spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| write(&root, &value)))
                .unwrap_or_else(|_| Err("The choices writer stopped unexpectedly. Refresh to verify the saved file before trying again.".into()));
            let _ = sender.send(result);
            repaint.request_repaint();
        }).map_err(|error| format!("Could not start the choices writer: {error}"))?;
        self.page_choices_job = Some(Pending {
            receiver,
            change,
            #[cfg(debug_assertions)]
            _fixture_guard: None,
        });
        self.ui_context.request_repaint();
        Ok(())
    }

    pub(super) fn page_choice_progress(&self) -> Option<&'static str> {
        self.page_choices_job
            .as_ref()
            .filter(|job| job.change.origin() == self.page)
            .map(|job| job.change.progress())
    }

    pub(super) fn page_choice_failure_visible(&self, error: &str) -> bool {
        let message = format!("{UNVERIFIED_PREFIX}{error}");
        self.error.as_deref() == Some(message.as_str())
            || (self.notice_page == Some(self.page)
                && self.notice.as_deref() == Some(message.as_str()))
    }

    pub(super) fn poll_page_choices(&mut self, ctx: &egui::Context) {
        let result = match self.page_choices_job.as_ref().map(|job| job.receiver.try_recv()) {
            Some(Ok(result)) => result,
            Some(Err(mpsc::TryRecvError::Disconnected)) => Err("The choices writer disconnected without a verified result. Refresh to check the saved file.".into()),
            _ => return,
        };
        let job = self.page_choices_job.take().unwrap();
        let origin = job.change.origin();
        match result {
            Ok(()) => {
                if self.page == origin {
                    self.error = None;
                }
                let notice = match job.change {
                    Change::Driver { proposed, notice } => {
                        self.apply_saved_driver_choices(proposed);
                        notice
                    }
                    Change::Software(proposed) => {
                        self.apply_saved_software_choices(proposed);
                        "The updater choice was saved and can be restored from this package row."
                            .into()
                    }
                };
                self.set_page_notice(notice, origin, theme::StatusKind::Success, false);
            }
            Err(error) => {
                match origin {
                    Page::Drivers => self.driver_choices_unverified(&error),
                    Page::Software => self.software_choices_unverified(&error),
                    _ => unreachable!(),
                }
                let message = format!("{UNVERIFIED_PREFIX}{error}");
                if self.close_after_preferences {
                    self.page = origin;
                    self.clear_unrelated_messages();
                    self.error = Some(message);
                } else {
                    self.set_page_notice(message, origin, theme::StatusKind::Error, true);
                }
                // Keep the failure visible before accepting another close request.
                self.close_after_preferences = false;
            }
        }
        self.finish_preferences_followups(ctx);
    }

    #[cfg(debug_assertions)]
    pub(super) fn seed_page_choices_saving_qa(&mut self, driver: bool, case: &str) {
        let (sender, receiver) = mpsc::sync_channel(1);
        if case.ends_with("-saved") {
            sender.send(Ok(())).unwrap();
        } else if case.ends_with("-failed") {
            sender.send(Err("Synthetic fixture: saved choices are unverified. No settings file was read or changed.".into())).unwrap();
        }
        self.page_choices_job = Some(Pending {
            receiver,
            change: if driver {
                Change::Driver {
                    proposed: DriverSettings::default(),
                    notice:
                        "Synthetic fixture: the driver choice was saved. Windows was not changed."
                            .into(),
                }
            } else {
                Change::Software(SoftwareSettings::default())
            },
            _fixture_guard: Some(sender),
        });
    }
}
