use super::*;
use std::{
    fs,
    os::windows::process::CommandExt,
    process::{Child, Command, Stdio},
};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
fn spawn(root: &Path) -> (OwnedChild, PathBuf) {
    let exe = root.join("activity-child.exe");
    fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    let child = Command::new(&exe)
        .args([
            "--exact",
            "optimizer_activity::native::tests::activity_child",
            "--ignored",
            "--nocapture",
        ])
        .env("DCLEANER_ACTIVITY_CHILD_ROOT", root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000)
        .spawn()
        .unwrap();
    let mut child = OwnedChild(child);
    let until = Instant::now() + Duration::from_secs(5);
    while !root.join("ready").exists() {
        assert!(Instant::now() < until, "owned child did not become ready");
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "owned child exited before readiness"
        );
        thread::sleep(Duration::from_millis(5));
    }
    (child, exe)
}
fn stop(root: &Path, child: &mut OwnedChild) {
    fs::write(root.join("stop"), b"stop").unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < until, "owned child did not exit");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
#[ignore = "Private child entry; exercised by the owned-parent native activity tests."]
fn activity_child() {
    let root = PathBuf::from(
        std::env::var_os("DCLEANER_ACTIVITY_CHILD_ROOT").expect("private child root"),
    );
    assert!(root.is_absolute() && root.starts_with(std::env::temp_dir()));
    fs::write(root.join("ready"), b"ready").unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    let mut value = 1u64;
    while Instant::now() < until && !root.join("stop").exists() {
        for _ in 0..10000 {
            value = std::hint::black_box(value.wrapping_mul(1664525).wrapping_add(1013904223));
        }
    }
    std::hint::black_box(value);
}

#[test]
fn native_current_process_counters_are_bound_to_the_retained_image() {
    let path = std::env::current_exe().unwrap();
    let expected = Principal::current().unwrap();
    let result = observe(
        &[path],
        &[unsafe { GetCurrentProcessId() }],
        &expected,
        &AtomicBool::new(false),
        Duration::from_millis(100),
    );
    assert_eq!(result.status, Status::Observed);
    assert_eq!(result.processes.len(), 1, "{result:?}");
    let row = &result.processes[0];
    assert!(row.creation_time > 0 && row.elapsed_millis >= 100);
    assert!(row.cpu_basis_points.is_some());
    assert!(row.working_set_bytes.unwrap() > 0);
    assert!(row.private_committed_bytes.unwrap() > 0);
}

#[test]
fn public_sampler_uses_a_fresh_host_snapshot_for_the_exact_current_image() {
    let path = std::env::current_exe().unwrap();
    // The reference is synthetic; no installed MSI package or app is touched.
    // The public collector still performs its real self-support check, current
    // logon admission, process enumeration, file mapping and timed counters.
    let installer = InstallerEvidence {
        status: InstallerStatus::Inspected,
        product: Some(uuid::Uuid::new_v4()),
        context: None,
        key_paths: vec![crate::optimizer_msi::ComponentKeyPath {
            component: uuid::Uuid::new_v4(),
            path: path.clone(),
        }],
        declared_rows_examined: 1,
        declared_rows_complete: true,
        covers_all_package_files: false,
        notes: vec!["Synthetic current-image reference.".into()],
    };
    let result = super::super::inspect(&installer, &AtomicBool::new(false));
    if Principal::current().unwrap().logon_sid().unwrap().is_none() {
        assert_eq!(result.status, Status::Unavailable);
        assert!(result.processes.is_empty());
        println!("PUBLIC_ACTIVITY_SAMPLE interactive_logon=false observed_current_image=false");
    } else {
        assert_eq!(result.status, Status::Observed, "{result:?}");
        let row = result
            .processes
            .iter()
            .find(|p| p.pid == unsafe { GetCurrentProcessId() })
            .expect("current image must be observed by the public collector");
        assert_eq!(row.registered_image, path);
        assert!(row.elapsed_millis >= 500);
        assert!(row.working_set_bytes.is_some_and(|bytes| bytes > 0));
        println!(
            "PUBLIC_ACTIVITY_SAMPLE interactive_logon=true observed_current_image=true memory_known=true cpu_known={}",
            row.cpu_basis_points.is_some()
        );
    }
}

#[test]
fn native_owned_child_measures_activity_rejects_identical_copy_and_deduplicates_aliases() {
    let root = tempfile::tempdir().unwrap();
    let (mut child, exe) = spawn(root.path());
    let alias = root.path().join("same-image-alias.exe");
    fs::hard_link(&exe, &alias).unwrap();
    let copied = root.path().join("identical-but-different-image.exe");
    fs::copy(&exe, &copied).unwrap();
    let expected = Principal::current().unwrap();
    let pid = child.0.id();
    let cancel = AtomicBool::new(false);
    let result = observe(
        &[alias.clone(), exe, copied.clone()],
        &[pid, pid],
        &expected,
        &cancel,
        Duration::from_millis(250),
    );
    assert_eq!(result.status, Status::Observed);
    assert_eq!(result.inspected_images, 2);
    assert_eq!(result.processes.len(), 1, "{result:?}");
    let row = &result.processes[0];
    assert_eq!(row.pid, pid);
    assert_eq!(row.registered_image, alias);
    assert!(row.cpu_basis_points.is_some_and(|value| value > 0));
    assert!(row.working_set_bytes.is_some_and(|bytes| bytes > 0));
    let wrong = observe(
        &[copied],
        &[pid],
        &expected,
        &cancel,
        Duration::from_millis(50),
    );
    assert!(wrong.processes.is_empty());
    assert_eq!(wrong.totals(), None);
    stop(root.path(), &mut child);
    let exited = observe(
        &[alias],
        &[pid],
        &expected,
        &cancel,
        Duration::from_millis(50),
    );
    assert!(exited.processes.is_empty());
    assert_eq!(exited.totals(), None);
}

#[test]
fn native_exit_after_baseline_never_becomes_a_zero_cpu_receipt() {
    let root = tempfile::tempdir().unwrap();
    let (mut child, exe) = spawn(root.path());
    let expected = Principal::current().unwrap();
    let mut baseline_reached = false;
    let result = observe_started(
        &[exe],
        &[child.0.id()],
        &expected,
        &AtomicBool::new(false),
        Duration::from_millis(250),
        || {
            baseline_reached = true;
            fs::write(root.path().join("stop"), b"stop").unwrap();
        },
    );
    assert!(baseline_reached);
    assert!(result.processes.is_empty());
    assert_eq!(result.totals(), None);
    assert!(result.notes.iter().any(|n| n.contains("exited")));
    stop(root.path(), &mut child);
}

#[test]
fn native_cancellation_after_baseline_discards_the_unfinished_measurement() {
    let cancel = AtomicBool::new(false);
    let expected = Principal::current().unwrap();
    let result = observe_started(
        &[std::env::current_exe().unwrap()],
        &[unsafe { GetCurrentProcessId() }],
        &expected,
        &cancel,
        Duration::from_secs(1),
        || cancel.store(true, Ordering::Relaxed),
    );
    assert_eq!(result.status, Status::Cancelled);
    assert!(result.processes.is_empty());
    assert_eq!(result.totals(), None);
}
