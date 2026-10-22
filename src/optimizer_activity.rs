//! Read-only process observations for selected Installer executable references.
//!
//! This is deliberately not an app-wide impact classifier, a complete process
//! roster, exclusive component ownership, or permission to put anything to sleep.
//! A positive row requires a retained process and an exact native executable
//! mapping, not an executable name, publisher, command line or directory guess.
use crate::optimizer_msi::{Evidence as InstallerEvidence, Status as InstallerStatus};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

const MAX_IMAGES: usize = 32;
const MAX_PROCESSES: usize = 8192;
const MAX_MATCHES: usize = 128;
const SAMPLE_WINDOW: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Observed,
    Unavailable,
    Cancelled,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessUsage {
    pub pid: u32,
    pub creation_time: u64,
    pub registered_image: PathBuf,
    /// 10000 = 100% of all active logical processors, not one processor.
    pub cpu_basis_points: Option<u32>,
    /// Includes shared pages; this is not reclaimable memory.
    pub working_set_bytes: Option<u64>,
    /// Private committed bytes, not private resident RAM.
    pub private_committed_bytes: Option<u64>,
    pub elapsed_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    pub status: Status,
    pub processes: Vec<ProcessUsage>,
    pub inspected_images: usize,
    pub unobservable_processes: usize,
    pub notes: Vec<String>,
}

impl Evidence {
    pub fn unavailable(message: &str) -> Self {
        let mut value = Self::empty(Status::Unavailable);
        value.note(message);
        value
    }
    fn empty(status: Status) -> Self {
        Self {
            status,
            processes: Vec::new(),
            inspected_images: 0,
            unobservable_processes: 0,
            notes: Vec::new(),
        }
    }
    fn note(&mut self, message: &str) {
        if self.notes.len() < 8 && !self.notes.iter().any(|note| note == message) {
            self.notes.push(message.chars().take(512).collect());
        }
    }
    /// A missing measurement stays missing instead of becoming a zero total.
    pub fn totals(&self) -> Option<(Option<u32>, Option<u64>, Option<u64>)> {
        if self.status != Status::Observed || self.processes.is_empty() {
            return None;
        }
        let cpu = self
            .processes
            .iter()
            .try_fold(0u32, |sum, p| sum.checked_add(p.cpu_basis_points?))
            .filter(|sum| *sum <= 10000);
        let working = self
            .processes
            .iter()
            .try_fold(0u64, |sum, p| sum.checked_add(p.working_set_bytes?));
        let private = self
            .processes
            .iter()
            .try_fold(0u64, |sum, p| sum.checked_add(p.private_committed_bytes?));
        Some((cpu, working, private))
    }
}

fn cpu_rate(before: u64, after: u64, elapsed: Duration, processors: u32) -> Option<u32> {
    let ticks = after.checked_sub(before)?;
    let denominator = elapsed.as_nanos().checked_mul(u128::from(processors))?;
    if denominator == 0 {
        return None;
    }
    let used_nanos = u128::from(ticks).checked_mul(100)?;
    if used_nanos > denominator {
        return None;
    }
    let rate = used_nanos.checked_mul(10000)? / denominator;
    (rate <= 10000).then(|| rate as u32)
}

/// Runs on a background worker only. Blocking native file/process calls cannot
/// be given a hard wall-clock bound; cancellation is checked between bounded
/// observations and during the sample wait.
pub fn inspect(installer: &InstallerEvidence, cancel: &AtomicBool) -> Evidence {
    if cancel.load(Ordering::Relaxed) {
        return Evidence::empty(Status::Cancelled);
    }
    if installer.status != InstallerStatus::Inspected {
        return Evidence::empty(Status::NotApplicable);
    }
    if installer.key_paths.len() > 512 {
        return Evidence::unavailable("Installer reference count exceeds the observation limit.");
    }
    let paths = installer
        .key_paths
        .iter()
        .filter(|entry| {
            entry
                .path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
        })
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return Evidence::unavailable(
            "No executable Installer key paths are available for activity observation.",
        );
    }
    #[cfg(windows)]
    {
        native::inspect(&paths, cancel)
    }
    #[cfg(not(windows))]
    {
        let _ = paths;
        Evidence::unavailable("Native process activity is available only on Windows.")
    }
}

#[cfg(windows)]
mod native;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rates_use_all_processors_and_preserve_unavailable_counters() {
        assert_eq!(
            cpu_rate(1, 5_000_001, Duration::from_secs(1), 4),
            Some(1250)
        );
        assert_eq!(cpu_rate(5, 4, Duration::from_secs(1), 4), None);
        assert_eq!(cpu_rate(0, 10_000_001, Duration::from_secs(1), 1), None);
        assert_eq!(cpu_rate(0, 1, Duration::ZERO, 1), None);
        assert_eq!(cpu_rate(0, 1, Duration::from_secs(1), 0), None);
        assert_eq!(cpu_rate(0, u64::MAX, Duration::from_nanos(1), 4096), None);
    }
    #[test]
    fn absent_or_partial_observations_are_not_fabricated_zero_impact() {
        let mut evidence = Evidence::empty(Status::Observed);
        assert_eq!(evidence.totals(), None);
        evidence.processes.push(ProcessUsage {
            pid: 1,
            creation_time: 1,
            registered_image: "synthetic.exe".into(),
            cpu_basis_points: None,
            working_set_bytes: Some(10),
            private_committed_bytes: Some(5),
            elapsed_millis: 500,
        });
        assert_eq!(evidence.totals(), Some((None, Some(10), Some(5))));
        evidence.status = Status::Cancelled;
        assert_eq!(evidence.totals(), None);
    }
}
