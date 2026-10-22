use super::*;
use dcleaner::{
    optimizer_activity::{self, Evidence as ActivityEvidence, Status as ActivityStatus},
    optimizer_inventory::{self, Program, Settings, Snapshot},
    optimizer_msi::{self, Evidence as InstallerEvidence, Status as InstallerStatus},
    programs::InstalledProgram,
    startup::FieldValue,
};
#[cfg(debug_assertions)]
use dcleaner::{
    programs::{ProgramIdentity, RegistryHive, RegistrySource, RegistryView},
    startup::{EnabledState, EntryIdentity, StartupEntry, StartupId, StartupSection},
};

#[derive(Clone, Copy, Default, PartialEq)]
enum Tab {
    #[default]
    Applications,
    Active,
    Sleeping,
    Excluded,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SortColumn {
    #[default]
    Program,
    Publisher,
}

#[derive(Default)]
pub(super) struct OptimizerUi {
    snapshot: Option<Arc<Snapshot>>,
    settings: Settings,
    settings_error: Option<String>,
    attempted: bool,
    loading: bool,
    query: String,
    tab: Tab,
    sort: SortColumn,
    descending: bool,
    dialog: Option<Dialog>,
    installer: InstallerInspection,
    #[cfg(debug_assertions)]
    qa_row_menus: Vec<egui::Id>,
}

#[derive(Default)]
struct InstallerInspection {
    requested: Option<InstalledProgram>,
    active: Option<InstallerJob>,
    result: Option<Arc<InstallerEvidence>>,
    activity: ActivityInspection,
}
struct InstallerJob {
    registration: InstalledProgram,
    cancel: Arc<AtomicBool>,
    receiver: Receiver<InstallerEvidence>,
}
impl Drop for InstallerJob {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
impl InstallerInspection {
    fn select(&mut self, program: Option<&InstalledProgram>) {
        self.activity.select(program);
        if self.requested.as_ref() != program {
            if let Some(job) = &self.active {
                job.cancel.store(true, Ordering::Relaxed);
            }
            self.requested = program.cloned();
            self.result = None;
        }
    }
    fn poll(&mut self) {
        self.activity.poll();
        let Some(job) = &self.active else { return };
        let result = match job.receiver.try_recv() {
            Ok(evidence) => evidence,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => installer_unavailable(
                "The component inspection ended unexpectedly. Close and reopen details to retry.",
            ),
        };
        let job = self.active.take().expect("inspected active job");
        if !job.cancel.load(Ordering::Relaxed) && self.requested.as_ref() == Some(&job.registration)
        {
            self.result = Some(Arc::new(result));
        }
    }
    fn start_with<F>(&mut self, inspect: F, ctx: egui::Context)
    where
        F: FnOnce(&InstalledProgram, &AtomicBool) -> InstallerEvidence + Send + 'static,
    {
        if self.active.is_some() || self.result.is_some() {
            return;
        }
        let Some(program) = self.requested.clone() else {
            return;
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let registration = program.clone();
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name("installer-details".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    inspect(&program, &worker_cancel)
                }))
                .unwrap_or_else(|_| installer_unavailable("The component inspection failed."));
                let _ = sender.send(result);
                ctx.request_repaint();
            }) {
            Ok(_) => {
                self.active = Some(InstallerJob {
                    registration,
                    cancel,
                    receiver,
                })
            }
            Err(_) => {
                self.result = Some(Arc::new(installer_unavailable(
                    "The component inspection could not start.",
                )))
            }
        }
    }
}

#[derive(Default)]
struct ActivityInspection {
    requested: Option<InstalledProgram>,
    active: Option<ActivityJob>,
    result: Option<Arc<ActivityEvidence>>,
}
struct ActivityJob {
    registration: InstalledProgram,
    cancel: Arc<AtomicBool>,
    receiver: Receiver<ActivityEvidence>,
}
impl Drop for ActivityJob {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
impl ActivityInspection {
    fn select(&mut self, registration: Option<&InstalledProgram>) {
        if self.requested.as_ref() != registration {
            if let Some(job) = &self.active {
                job.cancel.store(true, Ordering::Relaxed);
            }
            self.requested = registration.cloned();
            self.result = None;
        }
    }
    fn poll(&mut self) {
        let Some(job) = &self.active else { return };
        let result = match job.receiver.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => ActivityEvidence::unavailable(
                "Activity observation ended unexpectedly. Reopen details to retry.",
            ),
        };
        let job = self.active.take().expect("inspected activity job");
        if !job.cancel.load(Ordering::Relaxed) && self.requested.as_ref() == Some(&job.registration)
        {
            self.result = Some(Arc::new(result));
        }
    }
    fn start_with<F>(&mut self, installer: &InstallerEvidence, inspect: F, ctx: egui::Context)
    where
        F: FnOnce(&InstallerEvidence, &AtomicBool) -> ActivityEvidence + Send + 'static,
    {
        if installer.status != InstallerStatus::Inspected
            || self.active.is_some()
            || self.result.is_some()
        {
            return;
        }
        let Some(registration) = self.requested.clone() else {
            return;
        };
        let installer = installer.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name("optimizer-activity".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    inspect(&installer, &worker_cancel)
                }))
                .unwrap_or_else(|_| {
                    ActivityEvidence::unavailable(
                        "Activity observation failed. Reopen details to retry.",
                    )
                });
                let _ = sender.send(result);
                ctx.request_repaint();
            }) {
            Ok(_) => {
                self.active = Some(ActivityJob {
                    registration,
                    cancel,
                    receiver,
                })
            }
            Err(_) => {
                self.result = Some(Arc::new(ActivityEvidence::unavailable(
                    "Activity observation could not start.",
                )))
            }
        }
    }
}
fn installer_unavailable(note: &str) -> InstallerEvidence {
    InstallerEvidence {
        status: InstallerStatus::Unavailable,
        product: None,
        context: None,
        key_paths: Vec::new(),
        declared_rows_examined: 0,
        declared_rows_complete: false,
        covers_all_package_files: false,
        notes: vec![note.into()],
    }
}

#[cfg(test)]
mod installer_worker_tests {
    use super::*;

    #[test]
    fn changing_selection_cancels_the_old_request_and_discards_its_queued_result() {
        let original = optimizer_qa_program().registration;
        let mut changed = original.clone();
        changed.version = Some("changed while inspecting".into());
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut inspection = InstallerInspection::default();
        inspection.select(Some(&original));
        inspection.active = Some(InstallerJob {
            registration: original.clone(),
            cancel: cancel.clone(),
            receiver,
        });
        inspection.select(Some(&changed));
        assert!(cancel.load(Ordering::Relaxed));
        // Returning to the first registration must not resurrect a cancelled job.
        inspection.select(Some(&original));
        inspection.start_with(
            |_, _| panic!("a second worker must not run"),
            egui::Context::default(),
        );
        sender.send(installer_unavailable("stale result")).unwrap();
        inspection.poll();
        assert!(inspection.active.is_none());
        assert!(inspection.result.is_none());
    }

    #[test]
    fn details_closes_immediately_while_the_worker_is_blocked() {
        let program = optimizer_qa_program().registration;
        let mut inspection = InstallerInspection::default();
        inspection.select(Some(&program));
        let (started, ready) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        inspection.start_with(
            move |_, cancel| {
                started.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(5)).unwrap();
                assert!(cancel.load(Ordering::Relaxed));
                installer_unavailable("closed while reading")
            },
            egui::Context::default(),
        );
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        inspection.poll();
        assert!(inspection.active.is_some());
        inspection.select(None);
        assert!(inspection.requested.is_none());
        assert!(
            inspection
                .active
                .as_ref()
                .unwrap()
                .cancel
                .load(Ordering::Relaxed)
        );
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while inspection.active.is_some() && std::time::Instant::now() < deadline {
            inspection.poll();
            thread::yield_now();
        }
        assert!(inspection.active.is_none());
        assert!(inspection.result.is_none());
    }

    #[test]
    fn disconnected_worker_is_visible_and_not_restarted_every_frame() {
        let program = optimizer_qa_program().registration;
        let mut inspection = InstallerInspection::default();
        inspection.select(Some(&program));
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        inspection.active = Some(InstallerJob {
            registration: program,
            cancel: Arc::new(AtomicBool::new(false)),
            receiver,
        });
        inspection.poll();
        assert_eq!(
            inspection.result.as_ref().unwrap().status,
            InstallerStatus::Unavailable
        );
        inspection.start_with(
            |_, _| panic!("failed inspections require reopening details"),
            egui::Context::default(),
        );
        assert!(inspection.active.is_none());
    }
}
#[derive(Clone)]
enum Dialog {
    Details(Arc<Program>),
    RetainedKey(String),
    Exclusion {
        key: String,
        name: String,
        excluded: bool,
    },
}

#[cfg(test)]
mod activity_worker_tests {
    use super::*;

    fn inspected() -> InstallerEvidence {
        let mut evidence =
            installer_unavailable("Synthetic worker fixture; no native observation.");
        evidence.status = InstallerStatus::Inspected;
        evidence
    }

    #[test]
    fn changed_or_closed_selection_discards_activity_even_when_returning_to_the_same_app() {
        let original = optimizer_qa_program().registration;
        let mut changed = original.clone();
        changed.version = Some("changed".into());
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut inspection = ActivityInspection::default();
        inspection.select(Some(&original));
        inspection.active = Some(ActivityJob {
            registration: original.clone(),
            cancel: cancel.clone(),
            receiver,
        });
        inspection.select(Some(&changed));
        inspection.select(Some(&original));
        assert!(cancel.load(Ordering::Relaxed));
        inspection.start_with(
            &inspected(),
            |_, _| panic!("a concurrent activity worker must not start"),
            egui::Context::default(),
        );
        sender
            .send(ActivityEvidence::unavailable("stale fixture result"))
            .unwrap();
        inspection.poll();
        assert!(inspection.active.is_none() && inspection.result.is_none());
    }

    #[test]
    fn closing_details_does_not_wait_for_a_blocked_activity_reader() {
        let mut inspection = ActivityInspection::default();
        inspection.select(Some(&optimizer_qa_program().registration));
        let (started, ready) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        inspection.start_with(
            &inspected(),
            move |_, cancel| {
                started.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(5)).unwrap();
                assert!(cancel.load(Ordering::Relaxed));
                ActivityEvidence::unavailable("closed fixture")
            },
            egui::Context::default(),
        );
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        inspection.select(None);
        assert!(inspection.requested.is_none());
        assert!(
            inspection
                .active
                .as_ref()
                .unwrap()
                .cancel
                .load(Ordering::Relaxed)
        );
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while inspection.active.is_some() && std::time::Instant::now() < deadline {
            inspection.poll();
            thread::yield_now();
        }
        assert!(inspection.active.is_none() && inspection.result.is_none());
    }

    #[test]
    fn a_disconnected_activity_worker_is_reported_once_without_restart_spinning() {
        let program = optimizer_qa_program().registration;
        let mut inspection = ActivityInspection::default();
        inspection.select(Some(&program));
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        inspection.active = Some(ActivityJob {
            registration: program,
            cancel: Arc::new(AtomicBool::new(false)),
            receiver,
        });
        inspection.poll();
        assert_eq!(
            inspection.result.as_ref().unwrap().status,
            ActivityStatus::Unavailable
        );
        inspection.start_with(
            &inspected(),
            |_, _| panic!("failure must not restart every frame"),
            egui::Context::default(),
        );
        assert!(inspection.active.is_none());
    }
}
pub(super) enum OptimizerEvent {
    Loaded {
        inventory: Result<Snapshot, String>,
        settings: Result<Settings, String>,
    },
    Saved(Result<Settings, String>),
}

impl App {
    #[cfg(debug_assertions)]
    pub(super) fn seed_optimizer_qa(&mut self, case: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Optimizer QA fixtures require isolated fixture mode.".into());
        }
        let intro = case == "optimizer-intro";
        let mut ui = OptimizerUi {
            attempted: !intro,
            ..OptimizerUi::default()
        };
        self.error = None;
        self.notice = None;
        self.progress.clear();
        match case {
            "optimizer-intro" => {}
            "optimizer-empty" => {
                ui.snapshot = Some(Arc::new(Snapshot::default()));
            }
            "optimizer-populated"
            | "optimizer-excluded"
            | "optimizer-settings-unavailable"
            | "optimizer-details"
            | "optimizer-installer-details"
            | "optimizer-installer-partial"
            | "optimizer-installer-unavailable"
            | "optimizer-activity-details"
            | "optimizer-activity-no-match"
            | "optimizer-activity-error"
            | "optimizer-activity-loading" => {
                let program = optimizer_qa_program();
                if case == "optimizer-excluded" {
                    ui.settings = Settings::fixture_excluded(&program.key())?;
                    ui.tab = Tab::Excluded;
                } else if case == "optimizer-settings-unavailable" {
                    ui.settings_error = Some("Synthetic QA fixture: exclusion preferences could not be read. No settings file was inspected or changed.".into());
                }
                ui.snapshot = Some(Arc::new(Snapshot {
                    programs: vec![program.clone()],
                    notes: vec![
                        "Synthetic QA fixture; no installed-program or startup inventory was read."
                            .into(),
                    ],
                    cancelled: false,
                    partial: false,
                }));
                if case == "optimizer-details"
                    || case.starts_with("optimizer-installer-")
                    || case.starts_with("optimizer-activity-")
                {
                    if case.starts_with("optimizer-installer-")
                        || case.starts_with("optimizer-activity-")
                    {
                        let mut evidence = installer_unavailable(
                            "Synthetic QA references only; no installed package was inspected.",
                        );
                        evidence.status = if case.ends_with("unavailable") {
                            InstallerStatus::Unavailable
                        } else {
                            InstallerStatus::Inspected
                        };
                        evidence.declared_rows_complete =
                            case.ends_with("details") || case.starts_with("optimizer-activity-");
                        if evidence.status == InstallerStatus::Inspected {
                            evidence.key_paths.push(optimizer_msi::ComponentKeyPath {
                                component: Uuid::from_u128(1),
                                path: PathBuf::from(
                                    r"C:\Fixture\Example Application\background.exe",
                                ),
                            });
                            evidence.declared_rows_examined = 1;
                        }
                        ui.installer.requested = Some(program.registration.clone());
                        ui.installer.result = Some(Arc::new(evidence));
                        ui.installer.activity.select(Some(&program.registration));
                        if case.starts_with("optimizer-installer-") {
                            ui.installer.activity.result =
                                Some(Arc::new(ActivityEvidence::unavailable(
                                    "Activity was not sampled in this synthetic component fixture.",
                                )));
                        }
                        if case.starts_with("optimizer-activity-") && !case.ends_with("loading") {
                            let mut activity = ActivityEvidence {status: ActivityStatus::Observed, processes: Vec::new(), inspected_images: 1, unobservable_processes: 0, notes: vec!["Synthetic visual fixture. No process was inspected or measured.".into()]};
                            if case.ends_with("error") {
                                activity = ActivityEvidence::unavailable(
                                    "Synthetic visual fixture: native activity could not be read.",
                                );
                            } else if case.ends_with("details") {
                                activity.processes.push(optimizer_activity::ProcessUsage {
                                    pid: 42,
                                    creation_time: 1,
                                    registered_image: PathBuf::from(
                                        r"C:\Fixture\Example Application\background.exe",
                                    ),
                                    cpu_basis_points: Some(125),
                                    working_set_bytes: Some(48 * 1024 * 1024),
                                    private_committed_bytes: Some(32 * 1024 * 1024),
                                    elapsed_millis: 500,
                                });
                            }
                            ui.installer.activity.result = Some(Arc::new(activity));
                        }
                    }
                    ui.dialog = Some(Dialog::Details(Arc::new(program)));
                }
            }
            "optimizer-error" => {
                self.error = Some(
                    "Synthetic QA fixture error. No optimizer inventory or settings were read."
                        .into(),
                );
            }
            _ => return Err(format!("Unsupported Optimizer QA fixture: {case}")),
        }
        if !intro {
            self.mark_feature_seen("optimizer");
        }
        self.optimizer_ui = ui;
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_optimizer_precondition(
        &self,
        action: &str,
        ctx: &egui::Context,
    ) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Optimizer UI actions require isolated fixture mode.".into());
        }
        let has_program = self
            .optimizer_ui
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| !snapshot.programs.is_empty());
        match action {
            "More options" if has_program && self.optimizer_ui.dialog.is_none() => {
                let before = self.qa_optimizer_menu_open(ctx);
                ctx.data_mut(|data| {
                    data.insert_temp(egui::Id::new("qa-optimizer-menu-before"), before)
                });
                Ok(())
            }
            "Exclude app" | "Remove exclusion"
                if has_program
                    && self.optimizer_ui.dialog.is_none()
                    && self.qa_optimizer_menu_open(ctx)
                    && self.optimizer_ui.settings_error.is_none()
                    && ((action == "Remove exclusion")
                        == (self.optimizer_ui.settings.excluded_keys().count() > 0)) =>
            {
                ctx.data_mut(|data| {
                    data.insert_temp(
                        egui::Id::new("qa-optimizer-settings-before-review"),
                        self.optimizer_ui.settings.clone(),
                    )
                });
                Ok(())
            }
            "Restore"
                if has_program
                    && self.optimizer_ui.dialog.is_none()
                    && self.optimizer_ui.settings.excluded_keys().count() > 0 =>
            {
                ctx.data_mut(|data| {
                    data.insert_temp(
                        egui::Id::new("qa-optimizer-settings-before-review"),
                        self.optimizer_ui.settings.clone(),
                    )
                });
                Ok(())
            }
            "Cancel"
                if matches!(
                    self.optimizer_ui.dialog.as_ref(),
                    Some(Dialog::Exclusion { .. })
                ) =>
            {
                Ok(())
            }
            "Applications" | "Active apps" | "Sleeping apps" | "Excluded apps" => Ok(()),
            "Sort Program" | "Sort Publisher" if has_program => Ok(()),
            "Details" if has_program && self.optimizer_ui.dialog.is_none() => Ok(()),
            "Inspection details"
                if matches!(self.optimizer_ui.dialog.as_ref(), Some(Dialog::Details(_)))
                    && self
                        .optimizer_ui
                        .installer
                        .result
                        .as_ref()
                        .is_some_and(|r| !r.notes.is_empty()) =>
            {
                Ok(())
            }
            "Observation notes"
                if matches!(self.optimizer_ui.dialog.as_ref(), Some(Dialog::Details(_)))
                    && self
                        .optimizer_ui
                        .installer
                        .activity
                        .result
                        .as_ref()
                        .is_some_and(|r| !r.notes.is_empty()) =>
            {
                Ok(())
            }
            "Escape" if self.qa_optimizer_menu_open(ctx) => Ok(()),
            "Close" | "Close dialog" | "Escape" if self.optimizer_ui.dialog.is_some() => Ok(()),
            _ => Err(format!(
                "Optimizer action is unavailable in this safe fixture state: {action}"
            )),
        }
    }

    #[cfg(debug_assertions)]
    pub(super) fn qa_optimizer_action_state(
        &self,
        action: &str,
        ctx: &egui::Context,
    ) -> Result<serde_json::Value, String> {
        if !self.qa_fixture_mode() {
            return Err("Optimizer UI actions require isolated fixture mode.".into());
        }
        let dialog = match self.optimizer_ui.dialog.as_ref() {
            Some(Dialog::Details(_)) => "details",
            Some(Dialog::Exclusion { excluded: true, .. }) => "exclude_review",
            Some(Dialog::Exclusion {
                excluded: false, ..
            }) => "remove_exclusion_review",
            Some(Dialog::RetainedKey(_)) => "retained_details",
            None => "closed",
        };
        let settings_unchanged = ctx
            .data(|data| {
                data.get_temp::<Settings>(egui::Id::new("qa-optimizer-settings-before-review"))
            })
            .is_none_or(|before| before == self.optimizer_ui.settings);
        let state = serde_json::json!({
            "tab": optimizer_tab_label(self.optimizer_ui.tab),
            "sort": optimizer_sort_label(self.optimizer_ui.sort),
            "descending": self.optimizer_ui.descending,
            "dialog": dialog,
            "more_open": self.qa_optimizer_menu_open(ctx),
            "excluded_count": self.optimizer_ui.settings.excluded_keys().count(),
            "preference_error": self.optimizer_ui.settings_error.is_some(),
            "settings_unchanged": settings_unchanged,
            "programs": self.optimizer_ui.snapshot.as_ref().map(|snapshot| snapshot.programs.len()),
            "observed_processes": self.optimizer_ui.installer.activity.result.as_ref().map(|result| result.processes.len()),
            "activity_worker_active": self.optimizer_ui.installer.activity.active.is_some(),
        });
        let valid = match action {
            "More options" => {
                ctx.data(|data| data.get_temp::<bool>(egui::Id::new("qa-optimizer-menu-before")))
                    .is_some_and(|before| self.qa_optimizer_menu_open(ctx) != before)
                    && state["dialog"] == "closed"
            }
            "Exclude app" => {
                state["dialog"] == "exclude_review"
                    && state["more_open"] == false
                    && settings_unchanged
            }
            "Remove exclusion" | "Restore" => {
                state["dialog"] == "remove_exclusion_review"
                    && state["more_open"] == false
                    && settings_unchanged
            }
            "Cancel" => {
                state["dialog"] == "closed" && state["more_open"] == false && settings_unchanged
            }
            "Applications" | "Active apps" | "Sleeping apps" | "Excluded apps" => {
                state["tab"] == action
            }
            "Sort Program" => state["sort"] == "Program",
            "Sort Publisher" => state["sort"] == "Publisher",
            "Details" => state["dialog"] == "details",
            "Inspection details" | "Observation notes" => state["dialog"] == "details",
            "Close" | "Close dialog" | "Escape" => {
                state["dialog"] == "closed" && state["more_open"] == false && settings_unchanged
            }
            _ => false,
        };
        if !valid {
            return Err(format!(
                "Optimizer action did not reach its expected safe state: {action}"
            ));
        }
        Ok(serde_json::json!({ "action": action, "state": state }))
    }

    #[cfg(debug_assertions)]
    fn qa_optimizer_menu_open(&self, ctx: &egui::Context) -> bool {
        self.optimizer_ui
            .qa_row_menus
            .iter()
            .any(|id| egui::Popup::is_id_open(ctx, *id))
    }

    fn begin_optimizer_scan(&mut self, ctx: &egui::Context) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        self.optimizer_ui.loading = true;
        self.optimizer_ui.attempted = true;
        self.error = None;
        self.progress = "Reading installed applications and background registrations…".into();
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let root = self.data_dir.clone();
        let (tx, rx) = crate::worker_events::channel();
        self.worker = Some(rx);
        let ctx = ctx.clone();
        thread::spawn(move || {
            let (settings, inventory) = std::panic::catch_unwind(|| {
                (optimizer_inventory::load_settings(&root), optimizer_inventory::scan(&cancel))
            }).unwrap_or_else(|_| (Err("The inventory worker ended unexpectedly. Reload before changing exclusions.".into()), Err("The inventory worker ended without a result.".into())));
            let _ = tx.send(Event::Optimizer(OptimizerEvent::Loaded {
                inventory,
                settings,
            }));
            ctx.request_repaint();
        });
    }
    pub(super) fn optimizer_event(&mut self, event: OptimizerEvent) {
        self.worker = None;
        match event {
            OptimizerEvent::Loaded {
                inventory,
                settings,
            } => {
                self.optimizer_ui.loading = false;
                match settings {
                    Ok(settings) => {
                        self.optimizer_ui.settings = settings;
                        self.optimizer_ui.settings_error = None;
                    }
                    Err(error) => self.optimizer_ui.settings_error = Some(error),
                }
                match inventory {
                    Ok(snapshot) => self.optimizer_ui.snapshot = Some(Arc::new(snapshot)),
                    Err(error) => {
                        self.optimizer_ui.snapshot = None;
                        self.error = Some(error);
                    }
                }
            }
            OptimizerEvent::Saved(result) => match result {
                Ok(settings) => {
                    self.optimizer_ui.settings = settings;
                    self.optimizer_ui.settings_error = None;
                    self.set_notice("Optimization exclusion saved.".into());
                    self.optimizer_ui.dialog = None;
                }
                Err(error) => {
                    self.optimizer_ui.settings_error = Some(error.clone());
                    self.error = Some(error);
                    self.optimizer_ui.dialog = None;
                }
            },
        }
    }
    pub(super) fn optimizer_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        #[cfg(debug_assertions)]
        self.optimizer_ui.qa_row_menus.clear();
        if !self.feature_seen("optimizer") {
            if self.feature_intro(
                ui,
                t,
                "optimizer",
                "Review apps and startup options",
                "Start with a read-only inventory of installed applications and possible background entries. Impact and sleep state are unavailable in this build.",
                &[
                    (
                        theme::Icon::Optimizer,
                        "Improve overall performance",
                        "Review app registrations and possible background entries; impact has not been measured.",
                    ),
                    (
                        theme::Icon::Startup,
                        "More startup speed",
                        "Review startup-related registrations. Putting apps to sleep is unavailable in this build.",
                    ),
                ],
            ) {
                self.start_optimizer(ctx);
            }
            return;
        }
        if !self.optimizer_ui.attempted && !self.busy() && !self.qa_fixture_mode() {
            self.begin_optimizer_scan(ctx);
        }
        ui.horizontal_wrapped(|ui| {
            theme::tabs(ui, |ui| {
                for (tab, label, icon) in [
                    (Tab::Applications, "Applications", theme::Icon::Applications),
                    (Tab::Active, "Active apps", theme::Icon::Sun),
                    (Tab::Sleeping, "Sleeping apps", theme::Icon::Moon),
                    (Tab::Excluded, "Excluded apps", theme::Icon::EyeOff),
                ] {
                    if theme::tab_with_icon_count(
                        ui,
                        self.optimizer_ui.tab == tab,
                        icon,
                        label,
                        None,
                        t,
                    )
                    .clicked()
                    {
                        self.optimizer_ui.tab = tab;
                    }
                }
            });
        });
        ui.add_space(6.);
        ui.separator();
        ui.add_space(8.);
        if let Some(error) = &self.optimizer_ui.settings_error {
            theme::muted(
                ui,
                format!("Exclusions unavailable: {error} Reload before changing them."),
                t,
            );
            ui.add_space(8.);
            if self.optimizer_ui.tab == Tab::Excluded {
                return;
            }
        }
        if self.optimizer_ui.tab == Tab::Active {
            ui.label(RichText::new("Active app status unavailable").family(theme::semibold()));
            theme::muted(
                ui,
                "Background activity has not been measured. Applications lists installed registrations for review without labelling them as active.",
                t,
            );
            return;
        }
        if self.optimizer_ui.tab == Tab::Sleeping {
            ui.label(RichText::new("Sleep status unavailable").family(theme::semibold()));
            theme::muted(
                ui,
                "The background optimizer is unavailable in this build. A disabled startup entry does not establish that an app is sleeping.",
                t,
            );
            ui.add_space(12.);
            theme::primary(ui, "Activate all", t, false);
            return;
        }
        let Some(snapshot) = self.optimizer_ui.snapshot.clone() else {
            if !self.optimizer_ui.loading {
                theme::muted(ui, "No inventory loaded. Choose Scan again to retry.", t);
            }
            return;
        };
        let query = self.optimizer_ui.query.to_lowercase();
        let excluded_tab = self.optimizer_ui.tab == Tab::Excluded;
        let mut indices: Vec<_> = snapshot
            .programs
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                (!excluded_tab || self.optimizer_ui.settings.is_excluded(&p.key()))
                    && (query.is_empty()
                        || p.registration.display_name.to_lowercase().contains(&query)
                        || p.registration
                            .publisher
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&query))
            })
            .map(|(i, _)| i)
            .collect();
        indices.sort_by(|left, right| {
            let left_program = &snapshot.programs[*left];
            let right_program = &snapshot.programs[*right];
            let primary = match self.optimizer_ui.sort {
                SortColumn::Program => left_program
                    .registration
                    .display_name
                    .to_lowercase()
                    .cmp(&right_program.registration.display_name.to_lowercase()),
                SortColumn::Publisher => left_program
                    .registration
                    .publisher
                    .as_deref()
                    .unwrap_or("Unavailable")
                    .to_lowercase()
                    .cmp(
                        &right_program
                            .registration
                            .publisher
                            .as_deref()
                            .unwrap_or("Unavailable")
                            .to_lowercase(),
                    ),
            };
            let primary = if self.optimizer_ui.descending {
                primary.reverse()
            } else {
                primary
            };
            primary.then_with(|| {
                left_program
                    .registration
                    .display_name
                    .to_lowercase()
                    .cmp(&right_program.registration.display_name.to_lowercase())
            })
        });
        if !excluded_tab {
            theme::muted(
                ui,
                "Impact is not measured. Details lists possible background entries.",
                t,
            );
        } else {
            theme::muted(
                ui,
                "Excluded applications are omitted from future optimization. Removing an exclusion does not put an app to sleep.",
                t,
            );
        }
        if snapshot.cancelled || snapshot.partial {
            ui.add_space(6.);
            theme::muted(
                ui,
                if snapshot.cancelled {
                    "Scan stopped; this inventory is incomplete."
                } else {
                    "Some sources could not be fully examined."
                },
                t,
            );
        }
        if !snapshot.notes.is_empty() {
            theme::Disclosure::new(format!("Inventory details ({})", snapshot.notes.len())).show(
                ui,
                |ui| {
                    for note in &snapshot.notes {
                        theme::muted(ui, note, t);
                    }
                },
            );
        }
        ui.add_space(10.);
        let known: HashSet<_> = snapshot.programs.iter().map(Program::key).collect();
        let retained: Vec<String> = if excluded_tab {
            self.optimizer_ui
                .settings
                .excluded_keys()
                .into_iter()
                .filter(|key| {
                    !known.contains(*key)
                        && (query.is_empty() || key.to_lowercase().contains(&query))
                })
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
        };
        theme::scroll_horizontal().id_salt("optimizer-table-width").auto_shrink([false,true]).show(ui,|ui| {
            let width = ui.available_width().max(560.);
            let name_width = width - 148. - 90. - 116. - 24.;
            let spacing_y = ui.spacing().item_spacing.y;
            ui.spacing_mut().item_spacing.y = 0.;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.;
                let program_header = optimizer_sort_heading(
                    ui,
                    "Program",
                    "Sort Program",
                    name_width,
                    self.optimizer_ui.sort == SortColumn::Program,
                    self.optimizer_ui.descending,
                    t,
                );
                if program_header.clicked() {
                    select_optimizer_sort(
                        &mut self.optimizer_ui.sort,
                        &mut self.optimizer_ui.descending,
                        SortColumn::Program,
                    );
                }
                let publisher_header = optimizer_sort_heading(
                    ui,
                    "Publisher",
                    "Sort Publisher",
                    148.,
                    self.optimizer_ui.sort == SortColumn::Publisher,
                    self.optimizer_ui.descending,
                    t,
                );
                if publisher_header.clicked() {
                    select_optimizer_sort(
                        &mut self.optimizer_ui.sort,
                        &mut self.optimizer_ui.descending,
                        SortColumn::Publisher,
                    );
                }
                for (label, w) in [("Impact", 90.), ("Actions", 116.)] {
                    theme::table_cell(ui,RichText::new(label).color(t.muted).size(theme::FONT_CAPTION),w,22.);
                }
            });
            ui.add_space(3.); ui.separator();
            let body_height = (ctx.content_rect().bottom()-ui.cursor().top()-74.-28.-24.).max(80.);
            theme::scroll_vertical().id_salt("optimizer-table-body").auto_shrink([false,false]).max_height(body_height)
                .show_rows(ui,theme::TABLE_ROW_HEIGHT,indices.len()+retained.len(),|ui,visible| {
                    for i in visible {
                        let program = indices.get(i).map(|index| &snapshot.programs[*index]);
                        let key = program.map(Program::key).unwrap_or_else(||retained[i-indices.len()].clone());
                        let name = program.map(|p|p.registration.display_name.as_str()).unwrap_or("Registration not found in this scan");
                        let excluded = self.optimizer_ui.settings_error.is_none() && self.optimizer_ui.settings.is_excluded(&key);
                        ui.push_id((&key,i),|ui| {
                            ui.allocate_ui_with_layout(Vec2::new(width,theme::TABLE_ROW_HEIGHT),Layout::left_to_right(Align::Center),|row| {
                                row.spacing_mut().item_spacing.x=8.; row.spacing_mut().item_spacing.y=spacing_y;
                                row.allocate_ui_with_layout(Vec2::new(name_width,40.),Layout::left_to_right(Align::Center),|cell| {
                                    cell.set_min_width(name_width); cell.set_max_width(name_width);
                                    cell.spacing_mut().item_spacing.x=8.;
                                    self.app_icons.show(cell,program.and_then(|p|p.registration.icon_resource()).as_deref(),22.);
                                    let response = theme::frameless_button(cell,[(name_width-30.).max(80.),40.],egui::Button::new((RichText::new(name).family(theme::semibold()).color(t.foreground),egui::Atom::grow())).truncate());
                                    #[cfg(debug_assertions)]
                                    theme::record_fixture_control(cell, "Details", &response);
                                    theme::focus_ring(cell, &response, 18);
                                    if response.clicked() { self.optimizer_ui.dialog=Some(optimizer_details_for(program,&key)); }
                                    response.on_hover_text(format!("{name}\n{key}"));
                                });
                                let publisher = program.and_then(|p|p.registration.publisher.as_deref()).unwrap_or("Unavailable");
                                theme::table_cell_with_tooltip(row,RichText::new(publisher).color(t.muted),148.,40., publisher);
                                theme::table_cell_with_tooltip(row,RichText::new("Not measured").color(t.muted),90.,40., "Whole-app impact is not rated. Details can show read-only activity for matched Installer files; they may not cover every background component.");
                                row.allocate_ui_with_layout(Vec2::new(80.,40.),Layout::left_to_right(Align::Center),|cell| {
                                    cell.set_min_width(80.); cell.set_max_width(80.);
                                    if excluded {
                                        if theme::row_action(cell,"Restore",!self.busy() && self.optimizer_ui.settings_error.is_none()).clicked() {
                                            self.optimizer_ui.dialog=Some(Dialog::Exclusion {key:key.clone(),name:name.to_owned(),excluded:false});
                                        }
                                    } else { theme::row_action(cell,"Sleep",false).on_disabled_hover_text("Sleep and Wake are not connected in this build. This inventory cannot put an app to sleep."); }
                                });
                                let more=theme::row_more(row,true);
                                let popup = egui::Popup::menu(&more);
                                #[cfg(debug_assertions)]
                                self.optimizer_ui.qa_row_menus.push(popup.get_id());
                                popup.show(|ui| {
                                    if theme::menu_action(ui, theme::Icon::Info, "Details", true).clicked() { self.optimizer_ui.dialog=Some(optimizer_details_for(program,&key)); ui.close(); }
                                    if theme::menu_action(ui, if excluded {theme::Icon::Undo} else {theme::Icon::EyeOff}, if excluded {"Remove exclusion"} else {"Exclude app"}, !self.busy() && self.optimizer_ui.settings_error.is_none()).clicked() {
                                        self.optimizer_ui.dialog=Some(Dialog::Exclusion {key:key.clone(),name:name.to_owned(),excluded:!excluded}); ui.close();
                                    }
                                });
                            });
                            let y=ui.cursor().top();
                            ui.painter().hline(ui.max_rect().x_range(),y,egui::Stroke::new(1.,t.border));
                        });
                    }
                });
            ui.spacing_mut().item_spacing.y=spacing_y;
        });
        if indices.is_empty() && retained.is_empty() {
            theme::muted(
                ui,
                if query.is_empty() {
                    "No applications in this list."
                } else {
                    "No matching applications."
                },
                t,
            );
        }
    }
    pub(super) fn optimizer_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        if !self.feature_seen("optimizer") {
            let compact = !self.feature_intro_wide(ctx);
            let mut start = false;
            theme::action_row(ui, |ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if compact {
                        start = theme::primary(ui, "Scan now", t, !self.busy());
                    } else {
                        theme::muted(
                            ui,
                            "Review installed applications and possible background entries before deciding what to change.",
                            t,
                        );
                    }
                });
            });
            if start {
                self.start_optimizer(ctx);
            }
            return;
        }
        theme::action_row(ui, |ui| {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if self.optimizer_ui.loading {
                    if theme::secondary(ui, "Stop scan", true) {
                        self.cancel.store(true, Ordering::Relaxed);
                    }
                    theme::muted(ui, "Reading background registrations…", t);
                    ui.spinner();
                } else {
                    let summary = self
                        .optimizer_ui
                        .snapshot
                        .as_ref()
                        .map(|s| format!("{} registrations examined", s.programs.len()))
                        .unwrap_or_else(|| "Not scanned".into());
                    if theme::secondary(ui, "Scan again", !self.busy()) {
                        self.begin_optimizer_scan(ctx);
                    }
                    theme::muted(ui, summary, t);
                }
            });
        });
    }

    fn start_optimizer(&mut self, ctx: &egui::Context) {
        self.mark_feature_seen("optimizer");
        self.begin_optimizer_scan(ctx);
    }

    pub(super) fn optimizer_dialog(&mut self, ctx: &egui::Context) {
        let state = &mut self.optimizer_ui;
        let requested = match state.dialog.as_ref() {
            Some(Dialog::Details(program)) => Some(&program.registration),
            _ => None,
        };
        state.installer.select(requested);
        self.optimizer_ui.installer.poll();
        if !self.qa_fixture_mode() {
            self.optimizer_ui
                .installer
                .start_with(optimizer_msi::inspect, ctx.clone());
            if let Some(installer) = self.optimizer_ui.installer.result.clone() {
                self.optimizer_ui.installer.activity.start_with(
                    &installer,
                    optimizer_activity::inspect,
                    ctx.clone(),
                );
            }
        }
        if self.optimizer_ui.dialog.is_some()
            && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            let can_close = !self.busy()
                || matches!(
                    self.optimizer_ui.dialog.as_ref(),
                    Some(Dialog::Details(_) | Dialog::RetainedKey(_))
                );
            if can_close {
                self.optimizer_ui.dialog = None;
                self.optimizer_ui.installer.select(None);
            }
            return;
        }
        let Some(dialog) = self.optimizer_ui.dialog.clone() else {
            return;
        };
        let t = theme::tokens(self.prefs.dark);
        let width = (ctx.content_rect().width() - 32.).clamp(280., 560.);
        let busy = self.busy();
        let can_close = !busy || matches!(dialog, Dialog::Details(_) | Dialog::RetainedKey(_));
        let mut close = false;
        let mut save = None;
        let installer = self.optimizer_ui.installer.result.clone();
        let activity = self.optimizer_ui.installer.activity.result.clone();
        let response=egui::Modal::new(egui::Id::new("optimizer-dialog")).frame(theme::dialog_frame(t)).show(ctx,|ui| {
            ui.set_width(width);
            ui.horizontal(|ui| {
                let title = match &dialog {Dialog::Details(program)=>program.registration.display_name.as_str(),Dialog::RetainedKey(_)=>"Application details",Dialog::Exclusion {excluded:true,..}=>"Exclude application?",Dialog::Exclusion {..}=>"Remove exclusion?"};
                if let Dialog::Details(program) = &dialog {
                    let resource = if self.qa_fixture_mode() {None} else {program.registration.icon_resource()};
                    self.app_icons.show(ui, resource.as_deref(), 24.);
                }
                let title_width = (ui.available_width() - 36.).max(60.);
                let title_response = theme::table_cell_with_tooltip(ui, RichText::new(title).size(theme::FONT_DISPLAY).family(theme::semibold()), title_width, 32., title);
                #[cfg(debug_assertions)]
                theme::record_region(ui,"optimizer-details-title",title_response.rect,0);
                close |= theme::close_button(ui, "Close dialog", can_close);
            });
            ui.add_space(12.);
            let body = theme::scroll_vertical().id_salt("optimizer-dialog-body").max_height((ctx.content_rect().height()-190.).max(80.)).show(ui,|ui| {
                match &dialog {
                    Dialog::Details(program)=>{
                        let installed=program.registration.install_date.as_deref().map(super::view_programs::format_install_date).unwrap_or_else(||"Unavailable".into());
                        let metadata_width = ui.available_width();
                        let metadata = egui::Frame::new().fill(t.canvas).stroke(egui::Stroke::new(1.,t.border)).corner_radius(theme::SECTION_RADIUS).inner_margin(egui::Margin::symmetric(40,24)).show(ui, |ui| {
                            ui.set_min_width((metadata_width-80.).max(100.));
                            optimizer_detail(ui,"Version",program.registration.version.as_deref().unwrap_or("Unavailable"),t);
                            optimizer_detail(ui,"Publisher",program.registration.publisher.as_deref().unwrap_or("Unavailable"),t);
                            optimizer_detail(ui,"Installed",&installed,t);
                            optimizer_detail(ui,"Impact","Not measured",t);
                        });
                        #[cfg(debug_assertions)]
                        theme::record_region(ui,"optimizer-details-metadata",metadata.response.rect,theme::SECTION_RADIUS);
                        #[cfg(not(debug_assertions))]
                        let _ = metadata;
                        if installer.as_ref().is_some_and(|e| e.status == InstallerStatus::Inspected) {
                            optimizer_activity_details(ui, activity.as_deref(), t);
                        }
                        ui.add_space(12.);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Background candidates").family(theme::semibold()));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| theme::muted(ui,"Sleep unavailable",t));
                        });
                        theme::muted(ui,&program.association_note,t);
                        if program.candidates.is_empty() {theme::muted(ui,"No unambiguous directory candidates were found. This does not prove that an app has no background components.",t);}
                        if !program.candidates.is_empty() {
                            theme::scroll_horizontal().id_salt("optimizer-component-columns").show(ui,|ui| {
                                ui.spacing_mut().item_spacing.y=0.;
                                let width=ui.available_width().max(460.);
                                let columns=[72.,120.,width-72.-120.-78.-24.,78.];
                                ui.horizontal(|ui| {ui.spacing_mut().item_spacing.x=8.; for (label,w) in ["Type","Program","File path","State"].into_iter().zip(columns) {theme::table_cell(ui,RichText::new(label).color(t.muted),w,22.);} });
                                theme::scroll_vertical().id_salt("optimizer-component-rows").max_height(176.).show_rows(ui,theme::TABLE_ROW_HEIGHT,program.candidates.len(),|ui,range| {
                                    for index in range {let entry=&program.candidates[index];
                                        let state=match &entry.enabled {dcleaner::startup::EnabledState::Enabled=>"Enabled",dcleaner::startup::EnabledState::Disabled=>"Disabled",dcleaner::startup::EnabledState::Unknown {..}=>"Unavailable"};
                                        ui.horizontal(|ui| {ui.spacing_mut().item_spacing.x=8.; for (column,(text,w)) in [entry.section.label().to_owned(),optimizer_field(&entry.program),optimizer_field(&entry.file_path),state.into()].into_iter().zip(columns).enumerate() {let response=theme::table_cell_with_tooltip(ui,text.clone(),w,theme::TABLE_ROW_HEIGHT, text);
                                            #[cfg(debug_assertions)]
                                            if column==2 {theme::record_fixture_hover_target(ui,"Optimizer component path",&response);}
                                            #[cfg(not(debug_assertions))]
                                            let _=(column,response);
                                        } });
                                    }
                                });
                            });
                        }
                        if !self.qa_fixture_mode() || installer.is_some() {
                            optimizer_installer_details(ui, installer.as_deref(), t);
                        }
                    }
                    Dialog::RetainedKey(key)=>{
                        optimizer_detail(ui,"Saved registration",key,t);
                        theme::muted(ui,"This registration was not found in the current scan. Its exclusion is retained; an incomplete scan does not establish that it was uninstalled.",t);
                    }
                    Dialog::Exclusion {name,excluded,..}=>{
                        ui.label(RichText::new(name).family(theme::semibold())); ui.add_space(8.);
                        theme::muted(ui,if *excluded {"Keep this registration excluded from future optimization. This preference does not change its processes or background entries."} else {"Allow this registration to be considered for future optimization again. This does not start, stop or put it to sleep."},t);
                    }
                }
            });
            #[cfg(debug_assertions)]
            theme::record_scroll(ctx, "optimizer-details-body", body.inner_rect, body.content_size, body.state.offset);
            #[cfg(not(debug_assertions))]
            let _ = body;
            ui.add_space(12.); ui.separator(); ui.add_space(8.);
            if busy && matches!(dialog,Dialog::Exclusion {..}) {
                ui.horizontal(|ui| {ui.spinner(); theme::muted(ui,"Saving exclusion…",t);});
            }
            if matches!(dialog,Dialog::Details(_)) {
                close |= theme::centered_dialog_actions(ui,&["Close"],|ui| theme::primary(ui,"Close",t,can_close)).inner;
            } else { theme::action_row(ui,|ui| {
                if theme::secondary(ui,if matches!(dialog,Dialog::Details(_) | Dialog::RetainedKey(_)){"Close"} else {"Cancel"},can_close) {close=true;}
                if let Dialog::Exclusion {key,excluded,..}=&dialog {
                    if theme::primary(ui,if *excluded {"Exclude app"} else {"Remove exclusion"},t,!busy && !self.qa_fixture_mode() && self.optimizer_ui.settings_error.is_none()) {save=Some((key.clone(),*excluded));}
                }
            }); }
        });
        if can_close && (close || response.should_close()) {
            self.optimizer_ui.dialog = None;
            self.optimizer_ui.installer.select(None);
        } else if let Some((key, excluded)) = save {
            if self.qa_fixture_mode() {
                return;
            }
            let root = self.data_dir.clone();
            let settings = self.optimizer_ui.settings.clone();
            let (tx, rx) = crate::worker_events::channel();
            self.worker = Some(rx);
            let ctx = ctx.clone();
            self.progress = "Saving optimization exclusion…".into();
            thread::spawn(move || {
                let result = std::panic::catch_unwind(|| optimizer_inventory::save_exclusion(&root, &settings, &key, excluded))
                    .unwrap_or_else(|_| Err("The preference worker ended unexpectedly. Reload to check whether the exclusion was saved.".into()));
                let _ = tx.send(Event::Optimizer(OptimizerEvent::Saved(result)));
                ctx.request_repaint();
            });
        }
    }
}

#[cfg(debug_assertions)]
fn optimizer_qa_program() -> Program {
    let hive = RegistryHive::CurrentUser;
    let registry_source = RegistrySource {
        hive,
        view: RegistryView::Registry64,
    };
    Program {
        registration: InstalledProgram {
            identity: ProgramIdentity {
                hive,
                key_name: "dcleaner-qa-fixture".into(),
            },
            source: registry_source,
            display_name: "QA fixture application (synthetic)".into(),
            display_icon: None,
            publisher: Some("Synthetic fixture publisher".into()),
            version: Some("0.0-qa".into()),
            install_location: None,
            install_date: Some("20261015".into()),
            estimated_size_bytes: None,
            registered_uninstall_command: None,
            uninstall_command: None,
            uninstall_command_error: None,
            system_component: false,
            protected: false,
            no_remove: false,
        },
        candidates: vec![StartupEntry {
            id: StartupId("qa-fixture-component-1".into()),
            section: StartupSection::WindowsServices,
            program: FieldValue::Known {
                value: "Synthetic background component".into(),
            },
            publisher: FieldValue::Unknown {
                reason: "No publisher metadata is included in this fixture.".into(),
            },
            version: FieldValue::Unknown {
                reason: "No version metadata is included in this fixture.".into(),
            },
            file_path: FieldValue::Unknown {
                reason: "No executable path is included in this fixture.".into(),
            },
            command: FieldValue::Unknown {
                reason: "No command line is included in this fixture.".into(),
            },
            enabled: EnabledState::Unknown {
                reason: "The fixture does not represent an actual service state.".into(),
            },
            identity: EntryIdentity::WindowsService {
                name: "qa-fixture-service".into(),
            },
            can_change_enabled: false,
            change_limitation: Some("Synthetic QA fixture; no service control is available.".into()),
        }],
        association_note: "Synthetic QA fixture only. The component row is illustrative and was not associated with a real installation or native inventory.".into(),
    }
}

fn optimizer_details_for(program: Option<&Program>, key: &str) -> Dialog {
    program
        .map(|p| Dialog::Details(Arc::new(p.clone())))
        .unwrap_or_else(|| Dialog::RetainedKey(key.to_owned()))
}
fn optimizer_activity_details(ui: &mut egui::Ui, result: Option<&ActivityEvidence>, t: Tokens) {
    ui.add_space(12.);
    ui.label(RichText::new("Observed activity").family(theme::semibold()));
    let Some(result) = result else {
        theme::status_banner(
            ui,
            "Sampling matched processes…",
            theme::StatusKind::Info,
            true,
            false,
        );
        return;
    };
    if result.status != ActivityStatus::Observed {
        theme::status_banner(
            ui,
            if result.status == ActivityStatus::Cancelled {
                "Activity observation stopped."
            } else {
                "Activity observation is unavailable."
            },
            theme::StatusKind::Info,
            false,
            false,
        );
    } else if let Some((cpu, working, private)) = result.totals() {
        optimizer_detail(
            ui,
            "Matched processes",
            &result.processes.len().to_string(),
            t,
        );
        optimizer_detail(
            ui,
            "CPU during sample",
            &cpu.map(|value| format!("{}.{:02}%", value / 100, value % 100))
                .unwrap_or_else(|| "Unavailable".into()),
            t,
        );
        optimizer_detail(
            ui,
            "Working set",
            &working
                .map(super::size)
                .unwrap_or_else(|| "Unavailable".into()),
            t,
        );
        optimizer_detail(
            ui,
            "Private committed",
            &private
                .map(super::size)
                .unwrap_or_else(|| "Unavailable".into()),
            t,
        );
        let elapsed = result
            .processes
            .iter()
            .map(|p| p.elapsed_millis)
            .max()
            .unwrap_or(0);
        theme::muted(
            ui,
            format!(
                "Sample: {elapsed} ms. CPU time is normalized across logical processors; working set includes shared pages."
            ),
            t,
        );
    } else {
        theme::muted(
            ui,
            "No matching running process was observed in this sample. This does not establish zero activity.",
            t,
        );
    }
    theme::muted(
        ui,
        "Matched Installer files only. Other processes may be missing; these observations do not rate the whole app or estimate memory savings.",
        t,
    );
    if !result.notes.is_empty() {
        let header = theme::Disclosure::new("Observation notes")
            .id_salt("optimizer-activity-notes")
            .show(ui, |ui| {
                for note in &result.notes {
                    theme::muted(ui, note, t);
                }
            });
        #[cfg(debug_assertions)]
        theme::record_fixture_control(ui, "Observation notes", &header.header_response);
        #[cfg(not(debug_assertions))]
        let _ = header;
    }
}

fn optimizer_installer_details(ui: &mut egui::Ui, result: Option<&InstallerEvidence>, t: Tokens) {
    let Some(evidence) = result else {
        ui.add_space(12.);
        theme::status_banner(
            ui,
            "Reading Installer components…",
            theme::StatusKind::Info,
            true,
            false,
        );
        return;
    };
    if evidence.status == InstallerStatus::NotMsi {
        return;
    }
    ui.add_space(12.);
    if evidence.status != InstallerStatus::Inspected {
        theme::status_banner(
            ui,
            if evidence.status == InstallerStatus::Cancelled {
                "Installer component inspection stopped."
            } else {
                "Installer component references could not be verified."
            },
            theme::StatusKind::Info,
            false,
            false,
        );
    } else {
        ui.label(
            RichText::new(format!(
                "Installer file references ({})",
                evidence.key_paths.len()
            ))
            .family(theme::semibold()),
        );
        theme::muted(
            ui,
            "References may be shared and do not include every installed file.",
            t,
        );
        if !evidence.declared_rows_complete {
            theme::status_banner(
                ui,
                "Some Installer component references could not be inspected.",
                theme::StatusKind::Info,
                false,
                false,
            );
        }
        if evidence.key_paths.is_empty() {
            theme::muted(ui, "No local file key paths were returned.", t);
        } else {
            theme::scroll_vertical()
                .id_salt("optimizer-installer-paths")
                .max_height(144.)
                .show_rows(
                    ui,
                    theme::TABLE_ROW_HEIGHT,
                    evidence.key_paths.len(),
                    |ui, range| {
                        for index in range {
                            let reference = &evidence.key_paths[index];
                            let path = reference.path.to_string_lossy();
                            theme::table_cell_with_tooltip(
                                ui,
                                path.as_ref(),
                                ui.available_width(),
                                theme::TABLE_ROW_HEIGHT,
                                format!("{path}\nComponent: {}", reference.component),
                            );
                        }
                    },
                );
        }
    }
    if !evidence.notes.is_empty() {
        let header = theme::Disclosure::new("Inspection details").show(ui, |ui| {
            for note in &evidence.notes {
                theme::muted(ui, note, t);
            }
        });
        #[cfg(debug_assertions)]
        theme::record_fixture_control(ui, "Inspection details", &header.header_response);
        #[cfg(not(debug_assertions))]
        let _ = header;
    }
}
fn optimizer_field(value: &FieldValue<String>) -> String {
    match value {
        FieldValue::Known { value } => value.clone(),
        FieldValue::Unknown { reason } => format!("Unavailable: {reason}"),
        FieldValue::NotApplicable => "Not applicable".into(),
    }
}
fn optimizer_detail(ui: &mut egui::Ui, label: &str, value: &str, t: Tokens) {
    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout([120.,20.].into(), Layout::top_down(Align::Min), |ui| {
            ui.set_min_width(120.);
            ui.set_max_width(120.);
            theme::muted(ui,label,t);
        });
        let help = match label {
            "Working set" => "Resident process pages, including shared pages. This is not a memory-savings estimate.",
            "Private committed" => "Private committed memory can be resident or paged out; it is not private resident RAM.",
            "CPU during sample" => "Process CPU time divided by elapsed time and all active logical processors. This is not the app's overall impact rating.",
            _ => value,
        };
        ui.add(egui::Label::new(value).wrap()).on_hover_text(help);
    });
}

fn select_optimizer_sort(current: &mut SortColumn, descending: &mut bool, selected: SortColumn) {
    if *current == selected {
        *descending = !*descending;
    } else {
        *current = selected;
        *descending = false;
    }
}

fn optimizer_sort_heading(
    ui: &mut egui::Ui,
    label: &str,
    accessible_label: &str,
    width: f32,
    selected: bool,
    descending: bool,
    t: Tokens,
) -> egui::Response {
    let text = if selected {
        format!("{label} {}", if descending { "↓" } else { "↑" })
    } else {
        label.to_owned()
    };
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 22.), egui::Sense::click());
    let background = ui.painter().add(egui::Shape::Noop);
    theme::paint_frameless_hover_behind(ui, &response, 11, background);
    if response.has_focus() {
        theme::focus_ring(ui, &response, 13);
    }
    ui.painter().text(
        rect.left_center(),
        egui::Align2::LEFT_CENTER,
        text,
        egui::FontId::new(theme::FONT_CAPTION, theme::semibold()),
        if selected || response.hovered() {
            t.foreground
        } else {
            t.muted
        },
    );
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, true, accessible_label)
    });
    #[cfg(debug_assertions)]
    theme::record_fixture_control(ui, accessible_label, &response);
    response.on_hover_text(format!(
        "{accessible_label} in ascending or descending order"
    ))
}

#[cfg(debug_assertions)]
fn optimizer_tab_label(tab: Tab) -> &'static str {
    match tab {
        Tab::Applications => "Applications",
        Tab::Active => "Active apps",
        Tab::Sleeping => "Sleeping apps",
        Tab::Excluded => "Excluded apps",
    }
}

#[cfg(debug_assertions)]
fn optimizer_sort_label(sort: SortColumn) -> &'static str {
    match sort {
        SortColumn::Program => "Program",
        SortColumn::Publisher => "Publisher",
    }
}
