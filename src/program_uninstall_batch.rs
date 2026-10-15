//! Bounded sequential handoff and observation for selected program uninstallers.
//!
//! Each registration is re-read by `programs::handoff_uninstall` immediately
//! before its registered command is launched. A launched child remains owned
//! by the process adapter until it exits; the batch never kills it or advances
//! while its outcome is unknown.

#[cfg(any(windows, test))]
use crate::programs::UninstallCommand;
use crate::{
    effects::EffectJournal,
    programs::{
        self, InstalledProgram, ProcessPort, ProgramIdentity, RegistryPort,
        UninstallHandoffReceipt, UninstallRequest,
    },
};
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::time::Duration;
use std::{
    collections::HashMap,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;

const MAX_BATCH_SIZE: usize = 64;
const JOURNAL_FEATURE: &str = "program-uninstall-batch";
#[cfg(windows)]
const WAIT_INTERVAL: Duration = Duration::from_millis(200);

/// A confirmed review of a bounded set of registrations. Names are retained
/// for honest progress and result display; requests remain the execution source
/// of truth for identity, source and exact registered command.
#[derive(Clone, Debug, Serialize)]
pub struct BatchPlan {
    pub requests: Vec<UninstallRequest>,
    target_names: Vec<String>,
}

/// Prepare from the exact selected inventory records. Identical identities are
/// collapsed; conflicting source or command data for the same identity is an
/// error so the caller must refresh and review the registration again.
pub fn prepare(selected: &[InstalledProgram]) -> Result<BatchPlan, String> {
    if selected.is_empty() {
        return Err("Select at least one installed program.".into());
    }
    if selected.len() > MAX_BATCH_SIZE {
        return Err(format!(
            "A batch can contain at most {MAX_BATCH_SIZE} selected programs."
        ));
    }

    let mut indexes = HashMap::<ProgramIdentity, usize>::new();
    let mut requests: Vec<UninstallRequest> = Vec::new();
    let mut target_names = Vec::new();
    for program in selected {
        let request = programs::prepare_uninstall(program).map_err(|reasons| {
            format!(
                "{} cannot be uninstalled: {}",
                program.display_name,
                reasons
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        })?;
        if request.source.hive != request.identity.hive {
            return Err(format!(
                "{} has an inconsistent registry source. Refresh the program list and review it again.",
                program.display_name
            ));
        }
        if let Some(&index) = indexes.get(&request.identity) {
            let existing = &requests[index];
            if existing.source != request.source
                || existing.expected_registered_command != request.expected_registered_command
            {
                return Err(format!(
                    "{} appears more than once with conflicting registration data. Refresh the program list and review it again.",
                    program.display_name
                ));
            }
            continue;
        }
        indexes.insert(request.identity.clone(), requests.len());
        target_names.push(program.display_name.clone());
        requests.push(request);
    }

    if requests.len() > MAX_BATCH_SIZE {
        return Err(format!(
            "A batch can contain at most {MAX_BATCH_SIZE} distinct programs."
        ));
    }
    Ok(BatchPlan {
        requests,
        target_names,
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchPhase {
    Handoff,
    Wait,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BatchItemOutcome {
    NotStarted,
    HandoffFailed {
        message: String,
    },
    JournalFailed {
        phase: BatchPhase,
        message: String,
    },
    WaitUnknown {
        message: String,
    },
    Exited {
        success: bool,
        exit_code: Option<i32>,
        /// Always false: process exit does not establish that the registration,
        /// files, services, or other product state were removed.
        removal_confirmed: bool,
    },
}

impl BatchItemOutcome {
    pub fn status_label(&self) -> &'static str {
        match self {
            Self::NotStarted => "Not started",
            Self::HandoffFailed { .. } => "Could not start",
            Self::JournalFailed { .. } => "Journal failed",
            Self::WaitUnknown { .. } => "Outcome unknown",
            Self::Exited { success: true, .. } => {
                "Process exited successfully; removal unconfirmed"
            }
            Self::Exited { success: false, .. } => "Process exited with failure",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::HandoffFailed { message }
            | Self::WaitUnknown { message }
            | Self::JournalFailed { message, .. } => Some(message),
            Self::NotStarted | Self::Exited { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchItemResult {
    pub identity: ProgramIdentity,
    pub target_name: String,
    pub outcome: BatchItemOutcome,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchReport {
    pub batch_id: Uuid,
    pub selected_count: usize,
    pub items: Vec<BatchItemResult>,
    pub unstarted_count: usize,
    pub cancelled: bool,
    pub stopped: bool,
    pub stop_reason: Option<String>,
    pub journal_failures: Vec<String>,
}

impl BatchReport {
    pub fn summary(&self) -> String {
        let started = self.selected_count.saturating_sub(self.unstarted_count);
        let exited = self
            .items
            .iter()
            .filter(|item| matches!(item.outcome, BatchItemOutcome::Exited { .. }))
            .count();
        let mut summary = format!(
            "Started {started} of {} selected programs; {exited} uninstaller processes exited and removal remains unconfirmed.",
            self.selected_count
        );
        if self.cancelled {
            summary.push_str(" Cancellation stopped later launches.");
        } else if let Some(reason) = self.stop_reason.as_deref() {
            summary.push_str(&format!(" {reason}"));
        }
        if self.unstarted_count > 0 {
            let verb = if self.unstarted_count == 1 {
                "was"
            } else {
                "were"
            };
            summary.push_str(&format!(" {} {verb} not started.", self.unstarted_count));
        }
        if !self.journal_failures.is_empty() {
            summary.push_str(&format!(
                " {} journal write(s) failed.",
                self.journal_failures.len()
            ));
        }
        summary
    }
}

/// Process adapters must retain the actual child created by `launch`; the
/// runner takes that handle after `handoff_uninstall` returns its receipt.
pub trait OwnedProcessPort: ProcessPort {
    type Child;

    fn take_launched_child(&mut self) -> Result<Self::Child, String>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessExit {
    pub success: bool,
    pub code: Option<i32>,
}

/// Injectable wait boundary for fixture tests. Implementations must report an
/// error when they can no longer establish whether the owned child has exited.
pub trait ChildWaitPort<C> {
    fn try_wait(&mut self, child: &mut C) -> Result<Option<ProcessExit>, String>;
    fn wait_interval(&mut self);
}

#[derive(Serialize)]
struct HandoffIntent<'a> {
    batch_id: Uuid,
    ordinal: usize,
    target_name: &'a str,
    request: &'a UninstallRequest,
}

#[derive(Serialize)]
struct HandoffFailure<'a> {
    batch_id: Uuid,
    request_id: Uuid,
    error: &'a str,
}

#[derive(Serialize)]
struct WaitIntent<'a> {
    batch_id: Uuid,
    ordinal: usize,
    target_name: &'a str,
    request: &'a UninstallRequest,
    handoff: &'a UninstallHandoffReceipt,
}

#[derive(Serialize)]
struct WaitReceipt {
    batch_id: Uuid,
    request_id: Uuid,
    process_id: u32,
    process_exited: bool,
    exit_code: Option<i32>,
    outcome_unknown: bool,
    removal_confirmed: bool,
    error: Option<String>,
}

/// Sequential runner with injectable registry, owned-process and wait ports.
/// All durable writes go through `root`, allowing callers and tests to confine
/// effects to the selected application-data directory or a disposable fixture.
pub fn run_with_ports<R, P, W, F>(
    plan: &BatchPlan,
    root: &Path,
    cancel: &AtomicBool,
    registry: &R,
    process: &mut P,
    waiter: &mut W,
    mut progress: F,
) -> BatchReport
where
    R: RegistryPort,
    P: OwnedProcessPort,
    W: ChildWaitPort<P::Child>,
    F: FnMut(String),
{
    let batch_id = Uuid::new_v4();
    if plan.requests.len() > MAX_BATCH_SIZE {
        let report = oversized_report(plan, batch_id);
        progress(report.stop_reason.clone().unwrap_or_default());
        return report;
    }
    let mut report = empty_report(plan, batch_id);
    if let Some(reason) = invalid_plan_reason(plan) {
        report.stopped = true;
        report.stop_reason = Some(reason.clone());
        progress(reason);
        return report;
    }

    for index in 0..plan.requests.len() {
        if cancel.load(Ordering::Acquire) {
            stop_for_cancellation(&mut report);
            break;
        }

        let request = &plan.requests[index];
        let target_name = report.items[index].target_name.clone();
        progress(format!("Starting uninstaller for {target_name}"));
        let mut handoff_journal = match EffectJournal::create(
            root,
            JOURNAL_FEATURE,
            request.request_id,
            &HandoffIntent {
                batch_id,
                ordinal: index + 1,
                target_name: &target_name,
                request,
            },
        ) {
            Ok(journal) => journal,
            Err(error) => {
                record_journal_failure(&mut report, index, BatchPhase::Handoff, error);
                stop_after_failure(&mut report, "The handoff intent could not be journaled.");
                break;
            }
        };

        let handoff = match programs::handoff_uninstall(request, registry, process) {
            Ok(receipt) => receipt,
            Err(error) => {
                let message = error.to_string();
                if let Err(journal_error) = handoff_journal.finish(
                    "failed",
                    &HandoffFailure {
                        batch_id,
                        request_id: request.request_id,
                        error: &message,
                    },
                ) {
                    record_journal_failure(&mut report, index, BatchPhase::Handoff, journal_error);
                }
                report.items[index].outcome = BatchItemOutcome::HandoffFailed { message };
                stop_after_failure(
                    &mut report,
                    "An uninstall registration could not be handed off.",
                );
                break;
            }
        };

        let mut stop_after_current = false;
        if let Err(error) = handoff_journal.finish("handed_off", &handoff) {
            record_journal_failure(&mut report, index, BatchPhase::Handoff, error);
            stop_after_current = true;
        }

        let mut child = match process.take_launched_child() {
            Ok(child) => child,
            Err(error) => {
                report.items[index].outcome = BatchItemOutcome::WaitUnknown {
                    message: format!("The launched child handle was unavailable: {error}"),
                };
                stop_after_failure(
                    &mut report,
                    "The launched process could not be observed through its owned child handle.",
                );
                break;
            }
        };

        let mut wait_journal = match EffectJournal::create(
            root,
            JOURNAL_FEATURE,
            Uuid::new_v4(),
            &WaitIntent {
                batch_id,
                ordinal: index + 1,
                target_name: &target_name,
                request,
                handoff: &handoff,
            },
        ) {
            Ok(journal) => Some(journal),
            Err(error) => {
                record_journal_failure(&mut report, index, BatchPhase::Wait, error);
                stop_after_current = true;
                None
            }
        };

        let mut cancellation_reported = false;
        let mut waiting_reported = false;
        loop {
            if cancel.load(Ordering::Acquire) {
                report.cancelled = true;
                report.stopped = true;
                if report.stop_reason.is_none() {
                    report.stop_reason =
                        Some("Cancellation was requested; later launches were cancelled.".into());
                }
                if !cancellation_reported {
                    cancellation_reported = true;
                    progress(format!(
                        "Cancellation requested; waiting for {target_name} to exit"
                    ));
                }
            }
            match waiter.try_wait(&mut child) {
                Ok(Some(exit)) => {
                    report.items[index].outcome = BatchItemOutcome::Exited {
                        success: exit.success,
                        exit_code: exit.code,
                        removal_confirmed: false,
                    };
                    if let Some(journal) = wait_journal.as_mut() {
                        let receipt = WaitReceipt {
                            batch_id,
                            request_id: request.request_id,
                            process_id: handoff.process_id,
                            process_exited: true,
                            exit_code: exit.code,
                            outcome_unknown: false,
                            removal_confirmed: false,
                            error: None,
                        };
                        let state = if exit.success { "completed" } else { "failed" };
                        if let Err(error) = journal.finish(state, &receipt) {
                            record_journal_failure(&mut report, index, BatchPhase::Wait, error);
                            stop_after_current = true;
                        }
                    }
                    if !exit.success {
                        stop_after_current = true;
                        if report.stop_reason.is_none() {
                            report.stop_reason = Some(format!(
                                "The uninstaller for {target_name} exited with failure."
                            ));
                        }
                    }
                    break;
                }
                Ok(None) => {
                    if !waiting_reported {
                        waiting_reported = true;
                        progress(format!("Waiting for uninstaller: {target_name}"));
                    }
                    waiter.wait_interval();
                }
                Err(error) => {
                    report.items[index].outcome = BatchItemOutcome::WaitUnknown {
                        message: error.clone(),
                    };
                    stop_after_current = true;
                    if let Some(journal) = wait_journal.as_mut() {
                        let receipt = WaitReceipt {
                            batch_id,
                            request_id: request.request_id,
                            process_id: handoff.process_id,
                            process_exited: false,
                            exit_code: None,
                            outcome_unknown: true,
                            removal_confirmed: false,
                            error: Some(error),
                        };
                        if let Err(journal_error) = journal.finish("uncertain", &receipt) {
                            record_journal_failure(
                                &mut report,
                                index,
                                BatchPhase::Wait,
                                journal_error,
                            );
                        }
                    }
                    stop_after_failure(
                        &mut report,
                        "The running uninstaller outcome could not be established.",
                    );
                    break;
                }
            }
        }

        if stop_after_current {
            report.stopped = true;
            if report.stop_reason.is_none() {
                report.stop_reason = Some("A batch journal could not be preserved.".into());
            }
            break;
        }
    }

    report.unstarted_count = report
        .items
        .iter()
        .filter(|item| is_unstarted(&item.outcome))
        .count();
    report
}

/// Run the native Windows batch. The process adapter retains `std::process::Child`
/// and waits through `Child::try_wait`; it does not poll PIDs or terminate apps.
#[cfg(windows)]
pub fn run_native<F>(plan: &BatchPlan, root: &Path, cancel: &AtomicBool, progress: F) -> BatchReport
where
    F: FnMut(String),
{
    let mut process = WindowsOwnedProcess { child: None };
    let mut waiter = WindowsChildWait;
    run_with_ports(
        plan,
        root,
        cancel,
        &programs::WindowsRegistry,
        &mut process,
        &mut waiter,
        progress,
    )
}

/// Native program uninstall is unavailable away from Windows.
#[cfg(not(windows))]
pub fn run_native<F>(
    plan: &BatchPlan,
    _root: &Path,
    _cancel: &AtomicBool,
    mut progress: F,
) -> BatchReport
where
    F: FnMut(String),
{
    let batch_id = Uuid::new_v4();
    let mut report = if plan.requests.len() > MAX_BATCH_SIZE {
        oversized_report(plan, batch_id)
    } else {
        empty_report(plan, batch_id)
    };
    report.stopped = true;
    if report.stop_reason.is_none() {
        report.stop_reason =
            Some("Native uninstall batches are unavailable on this platform.".into());
    }
    progress(report.stop_reason.clone().unwrap_or_default());
    report
}

fn empty_report(plan: &BatchPlan, batch_id: Uuid) -> BatchReport {
    let items = plan
        .requests
        .iter()
        .enumerate()
        .map(|(index, request)| BatchItemResult {
            identity: request.identity.clone(),
            target_name: plan
                .target_names
                .get(index)
                .cloned()
                .unwrap_or_else(|| request.identity.key_name.clone()),
            outcome: BatchItemOutcome::NotStarted,
        })
        .collect();
    BatchReport {
        batch_id,
        selected_count: plan.requests.len(),
        unstarted_count: plan.requests.len(),
        items,
        cancelled: false,
        stopped: false,
        stop_reason: None,
        journal_failures: Vec::new(),
    }
}

fn oversized_report(plan: &BatchPlan, batch_id: Uuid) -> BatchReport {
    BatchReport {
        batch_id,
        selected_count: plan.requests.len(),
        items: Vec::new(),
        unstarted_count: plan.requests.len(),
        cancelled: false,
        stopped: true,
        stop_reason: Some(format!(
            "The uninstall batch exceeds the {MAX_BATCH_SIZE}-program limit."
        )),
        journal_failures: Vec::new(),
    }
}

fn invalid_plan_reason(plan: &BatchPlan) -> Option<String> {
    if plan.requests.is_empty() {
        return Some("The uninstall batch is empty.".into());
    }
    if plan.requests.len() > MAX_BATCH_SIZE {
        return Some(format!(
            "The uninstall batch exceeds the {MAX_BATCH_SIZE}-program limit."
        ));
    }
    if plan.requests.len() != plan.target_names.len() {
        return Some("The uninstall batch has inconsistent display data.".into());
    }
    let mut identities = HashMap::new();
    for request in &plan.requests {
        if request.source.hive != request.identity.hive {
            return Some("The uninstall batch contains an inconsistent registry source.".into());
        }
        if identities.insert(request.identity.clone(), ()).is_some() {
            return Some("The uninstall batch contains a duplicate program identity.".into());
        }
    }
    None
}

fn is_unstarted(outcome: &BatchItemOutcome) -> bool {
    matches!(
        outcome,
        BatchItemOutcome::NotStarted
            | BatchItemOutcome::HandoffFailed { .. }
            | BatchItemOutcome::JournalFailed {
                phase: BatchPhase::Handoff,
                ..
            }
    )
}

fn record_journal_failure(
    report: &mut BatchReport,
    index: usize,
    phase: BatchPhase,
    message: String,
) {
    let target_name = report
        .items
        .get(index)
        .map(|item| item.target_name.as_str())
        .unwrap_or("selected program");
    let detail = format!("{target_name} ({phase:?}): {message}");
    report.journal_failures.push(detail.clone());
    if let Some(item) = report.items.get_mut(index) {
        if matches!(item.outcome, BatchItemOutcome::NotStarted) {
            item.outcome = BatchItemOutcome::JournalFailed { phase, message };
        }
    }
}

fn stop_after_failure(report: &mut BatchReport, reason: &str) {
    report.stopped = true;
    if report.stop_reason.is_none() {
        report.stop_reason = Some(reason.into());
    }
}

fn stop_for_cancellation(report: &mut BatchReport) {
    report.cancelled = true;
    report.stopped = true;
    if report.stop_reason.is_none() {
        report.stop_reason =
            Some("The batch was cancelled before the next uninstaller started.".into());
    }
}

#[cfg(windows)]
struct WindowsOwnedProcess {
    child: Option<std::process::Child>,
}

#[cfg(windows)]
impl ProcessPort for WindowsOwnedProcess {
    fn launch(&mut self, command: &UninstallCommand) -> Result<u32, String> {
        if self.child.is_some() {
            return Err("A previous uninstaller child is still owned.".into());
        }
        let child = std::process::Command::new(&command.executable)
            .args(&command.arguments)
            .spawn()
            .map_err(|error| error.to_string())?;
        let process_id = child.id();
        self.child = Some(child);
        Ok(process_id)
    }
}

#[cfg(windows)]
impl OwnedProcessPort for WindowsOwnedProcess {
    type Child = std::process::Child;

    fn take_launched_child(&mut self) -> Result<Self::Child, String> {
        self.child
            .take()
            .ok_or_else(|| "No uninstaller child is available.".into())
    }
}

#[cfg(windows)]
struct WindowsChildWait;

#[cfg(windows)]
impl ChildWaitPort<std::process::Child> for WindowsChildWait {
    fn try_wait(&mut self, child: &mut std::process::Child) -> Result<Option<ProcessExit>, String> {
        child
            .try_wait()
            .map(|status| {
                status.map(|status| ProcessExit {
                    success: status.success(),
                    code: status.code(),
                })
            })
            .map_err(|error| error.to_string())
    }

    fn wait_interval(&mut self) {
        std::thread::sleep(WAIT_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::programs::{
        RawProgramRegistration, RegistryHive, RegistrySource, RegistrySourceRead, RegistryView,
    };
    use std::{
        cell::RefCell,
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    fn source() -> RegistrySource {
        RegistrySource {
            hive: RegistryHive::CurrentUser,
            view: RegistryView::Registry64,
        }
    }

    fn program(key: &str, name: &str, registered: &str) -> InstalledProgram {
        InstalledProgram {
            identity: ProgramIdentity {
                hive: RegistryHive::CurrentUser,
                key_name: key.to_ascii_lowercase(),
            },
            source: source(),
            display_name: name.into(),
            display_icon: None,
            publisher: None,
            version: None,
            install_location: None,
            install_date: None,
            estimated_size_bytes: None,
            registered_uninstall_command: Some(registered.into()),
            uninstall_command: Some(UninstallCommand {
                registered: registered.into(),
                executable: registered.split_whitespace().next().unwrap().into(),
                arguments: registered
                    .split_whitespace()
                    .skip(1)
                    .map(str::to_owned)
                    .collect(),
            }),
            uninstall_command_error: None,
            system_component: false,
            protected: false,
            no_remove: false,
        }
    }

    fn raw(key: &str, name: &str, registered: &str) -> RawProgramRegistration {
        RawProgramRegistration {
            key_name: key.into(),
            display_name: Some(name.into()),
            uninstall_string: Some(registered.into()),
            ..Default::default()
        }
    }

    #[derive(Default)]
    struct FixtureRegistry {
        entries: RefCell<HashMap<(RegistrySource, String), RawProgramRegistration>>,
    }

    impl FixtureRegistry {
        fn insert(&self, source: RegistrySource, key: &str, registration: RawProgramRegistration) {
            self.entries
                .borrow_mut()
                .insert((source, key.to_ascii_lowercase()), registration);
        }
    }

    impl RegistryPort for FixtureRegistry {
        fn read_source(
            &self,
            _source: RegistrySource,
        ) -> Result<programs::RegistrySourceRead, String> {
            Ok(RegistrySourceRead::default())
        }

        fn read_registration(
            &self,
            source: RegistrySource,
            identity: &ProgramIdentity,
        ) -> Result<Option<RawProgramRegistration>, String> {
            Ok(self
                .entries
                .borrow()
                .get(&(source, identity.key_name.clone()))
                .cloned())
        }
    }

    #[derive(Default)]
    struct FixtureProcess {
        next_child: usize,
        child: Option<usize>,
        events: Arc<Mutex<Vec<String>>>,
        launched_commands: Vec<UninstallCommand>,
    }

    impl ProcessPort for FixtureProcess {
        fn launch(&mut self, command: &UninstallCommand) -> Result<u32, String> {
            self.next_child += 1;
            let child = self.next_child;
            self.child = Some(child);
            self.launched_commands.push(command.clone());
            self.events.lock().unwrap().push(format!("launch-{child}"));
            Ok(child as u32 + 100)
        }
    }

    impl OwnedProcessPort for FixtureProcess {
        type Child = usize;

        fn take_launched_child(&mut self) -> Result<Self::Child, String> {
            self.child
                .take()
                .ok_or_else(|| "missing fixture child".into())
        }
    }

    enum WaitBehavior {
        Exit(ProcessExit),
        Unknown,
        CancelThenExit(Arc<AtomicBool>, ProcessExit),
    }

    struct FixtureWait {
        behavior: WaitBehavior,
        calls: HashMap<usize, usize>,
        events: Arc<Mutex<Vec<String>>>,
    }

    impl ChildWaitPort<usize> for FixtureWait {
        fn try_wait(&mut self, child: &mut usize) -> Result<Option<ProcessExit>, String> {
            let calls = self.calls.entry(*child).or_default();
            *calls += 1;
            if *calls == 1 && matches!(&self.behavior, WaitBehavior::CancelThenExit(_, _)) {
                if let WaitBehavior::CancelThenExit(cancel, _) = &self.behavior {
                    cancel.store(true, Ordering::Release);
                }
                return Ok(None);
            }
            match &self.behavior {
                WaitBehavior::Unknown => Err("fixture wait failure".into()),
                WaitBehavior::Exit(exit) => {
                    self.events.lock().unwrap().push(format!("exit-{child}"));
                    Ok(Some(*exit))
                }
                WaitBehavior::CancelThenExit(_, exit) => {
                    self.events.lock().unwrap().push(format!("exit-{child}"));
                    Ok(Some(*exit))
                }
            }
        }

        fn wait_interval(&mut self) {}
    }

    fn registry_for(programs: &[InstalledProgram]) -> FixtureRegistry {
        let registry = FixtureRegistry::default();
        for program in programs {
            registry.insert(
                program.source,
                &program.identity.key_name,
                raw(
                    &program.identity.key_name,
                    &program.display_name,
                    program.registered_uninstall_command.as_deref().unwrap(),
                ),
            );
        }
        registry
    }

    fn waiter(behavior: WaitBehavior, events: Arc<Mutex<Vec<String>>>) -> FixtureWait {
        FixtureWait {
            behavior,
            calls: HashMap::new(),
            events,
        }
    }

    #[test]
    fn prepare_deduplicates_exact_identity_and_rejects_conflicting_source() {
        let first = program("alpha", "Alpha", "alpha-uninstall.exe /remove");
        let duplicate = first.clone();
        let plan = prepare(&[first.clone(), duplicate]).unwrap();
        assert_eq!(plan.requests.len(), 1);
        assert_eq!(plan.target_names, ["Alpha"]);

        let mut conflicting = first.clone();
        conflicting.source.view = RegistryView::Registry32;
        assert!(prepare(&[first, conflicting]).is_err());
    }

    #[test]
    fn launches_in_order_and_waits_for_owned_child_before_next_launch() {
        let selected = [
            program("alpha", "Alpha", "alpha-uninstall.exe /remove"),
            program("beta", "Beta", "beta-uninstall.exe /remove"),
        ];
        let registry = registry_for(&selected);
        let plan = prepare(&selected).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut process = FixtureProcess {
            events: events.clone(),
            ..Default::default()
        };
        let mut waiter = waiter(
            WaitBehavior::Exit(ProcessExit {
                success: true,
                code: Some(0),
            }),
            events.clone(),
        );
        let root = tempfile::tempdir().unwrap();
        let report = run_with_ports(
            &plan,
            root.path(),
            &AtomicBool::new(false),
            &registry,
            &mut process,
            &mut waiter,
            |_| {},
        );

        assert_eq!(
            *events.lock().unwrap(),
            ["launch-1", "exit-1", "launch-2", "exit-2"]
        );
        assert!(report.items.iter().all(|item| matches!(
            item.outcome,
            BatchItemOutcome::Exited {
                success: true,
                removal_confirmed: false,
                ..
            }
        )));
        assert_eq!(report.unstarted_count, 0);
    }

    #[test]
    fn cancellation_during_wait_finishes_current_child_and_skips_later_items() {
        let selected = [
            program("alpha", "Alpha", "alpha-uninstall.exe /remove"),
            program("beta", "Beta", "beta-uninstall.exe /remove"),
        ];
        let registry = registry_for(&selected);
        let plan = prepare(&selected).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut process = FixtureProcess {
            events: events.clone(),
            ..Default::default()
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let mut waiter = waiter(
            WaitBehavior::CancelThenExit(
                cancel.clone(),
                ProcessExit {
                    success: true,
                    code: Some(0),
                },
            ),
            events.clone(),
        );
        let root = tempfile::tempdir().unwrap();
        let report = run_with_ports(
            &plan,
            root.path(),
            &cancel,
            &registry,
            &mut process,
            &mut waiter,
            |_| {},
        );

        assert_eq!(*events.lock().unwrap(), ["launch-1", "exit-1"]);
        assert!(report.cancelled);
        assert_eq!(report.unstarted_count, 1);
        assert!(matches!(
            report.items[1].outcome,
            BatchItemOutcome::NotStarted
        ));
    }

    #[test]
    fn command_and_protection_races_are_rejected_by_existing_handoff_owner() {
        for protected in [false, true] {
            let selected = [program("alpha", "Alpha", "alpha-uninstall.exe /reviewed")];
            let plan = prepare(&selected).unwrap();
            let registry = FixtureRegistry::default();
            let mut changed = raw(
                "alpha",
                "Alpha",
                if protected {
                    "alpha-uninstall.exe /reviewed"
                } else {
                    "alpha-uninstall.exe /changed"
                },
            );
            changed.protected = protected;
            registry.insert(source(), "alpha", changed);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut process = FixtureProcess {
                events: events.clone(),
                ..Default::default()
            };
            let mut waiter = waiter(
                WaitBehavior::Exit(ProcessExit {
                    success: true,
                    code: Some(0),
                }),
                events.clone(),
            );
            let root = tempfile::tempdir().unwrap();
            let report = run_with_ports(
                &plan,
                root.path(),
                &AtomicBool::new(false),
                &registry,
                &mut process,
                &mut waiter,
                |_| {},
            );

            assert!(matches!(
                report.items[0].outcome,
                BatchItemOutcome::HandoffFailed { .. }
            ));
            assert!(events.lock().unwrap().is_empty());
            assert!(report.stopped);
        }
    }

    #[test]
    fn unknown_or_failed_child_outcome_stops_the_batch() {
        for behavior in [
            WaitBehavior::Unknown,
            WaitBehavior::Exit(ProcessExit {
                success: false,
                code: Some(23),
            }),
        ] {
            let is_unknown = matches!(&behavior, WaitBehavior::Unknown);
            let selected = [
                program("alpha", "Alpha", "alpha-uninstall.exe /remove"),
                program("beta", "Beta", "beta-uninstall.exe /remove"),
            ];
            let registry = registry_for(&selected);
            let plan = prepare(&selected).unwrap();
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut process = FixtureProcess {
                events: events.clone(),
                ..Default::default()
            };
            let mut waiter = waiter(behavior, events.clone());
            let root = tempfile::tempdir().unwrap();
            let report = run_with_ports(
                &plan,
                root.path(),
                &AtomicBool::new(false),
                &registry,
                &mut process,
                &mut waiter,
                |_| {},
            );

            assert!(report.stopped);
            assert_eq!(report.unstarted_count, 1);
            assert!(matches!(
                report.items[1].outcome,
                BatchItemOutcome::NotStarted
            ));
            assert_eq!(process.launched_commands.len(), 1);
            match report.items[0].outcome {
                BatchItemOutcome::WaitUnknown { .. } => {
                    assert!(is_unknown);
                }
                BatchItemOutcome::Exited { success: false, .. } => {
                    assert!(!is_unknown);
                }
                ref outcome => panic!("unexpected outcome: {outcome:?}"),
            }
        }
    }
}
