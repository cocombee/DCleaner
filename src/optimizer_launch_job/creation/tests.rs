use super::*;
use crate::{optimizer_requests::Caller, optimizer_resources::Member};
use std::{
    ffi::OsString,
    fs,
    os::windows::{ffi::OsStringExt, fs::OpenOptionsExt},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};
use windows::Win32::System::{
    Environment::GetCommandLineW,
    Threading::{GetStartupInfoW, STARTUPINFOW},
};

/// Production waits for the aborted root's process object. Job accounting is
/// updated a moment later, so slower hosts can still count it as active.
fn settled_accounting(job: BorrowedHandle<'_>) -> JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let counts = accounting(job).unwrap();
        if counts.ActiveProcesses == 0 || Instant::now() >= deadline {
            return counts;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn own_top_level_windows() -> usize {
    use windows::{
        Win32::{
            Foundation::{HWND, LPARAM},
            UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId},
        },
        core::BOOL,
    };
    unsafe extern "system" fn count(window: HWND, argument: LPARAM) -> BOOL {
        let state = unsafe { &mut *(argument.0 as *mut (u32, usize)) };
        let mut process = 0;
        unsafe {
            GetWindowThreadProcessId(window, Some(&mut process));
        }
        if process == state.0 {
            state.1 += 1;
        }
        BOOL(1)
    }
    let mut state = (std::process::id(), 0usize);
    unsafe {
        EnumWindows(
            Some(count),
            windows::Win32::Foundation::LPARAM((&mut state as *mut (u32, usize)) as isize),
        )
    }
    .unwrap();
    state.1
}

const ENTRY: &str = "optimizer_launch_job::creation::tests::owned_creation_entry";
const MARKER: &str = "DCleaner native creation fixture v1";
fn no_cancel() -> AtomicBool {
    AtomicBool::new(false)
}
fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().collect()
}
fn member(principal: &Principal) -> Member {
    let caller = Caller::fixture_boot(
        &principal.user_sid().unwrap(),
        principal.session_id(),
        &principal
            .logon_sid()
            .unwrap()
            .expect("interactive fixture logon required"),
        principal.boot_id(),
    );
    Member::for_caller(&caller, "program:v1:hkcu:64:6372656174696f6e").unwrap()
}
fn wait(mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(6);
    while !done() {
        assert!(
            Instant::now() < deadline,
            "private creation fixture exceeded its bound"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
pub(crate) struct Fixture {
    dir: tempfile::TempDir,
    image: Option<fs::File>,
    command: OsString,
    environment: Vec<u16>,
}
impl Fixture {
    pub(crate) fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("optimizer-creation-fixture-")
            .tempdir()
            .unwrap();
        assert!(dir.path().is_absolute() && dir.path().starts_with(std::env::temp_dir()));
        fs::write(dir.path().join("fixture.marker"), MARKER).unwrap();
        let executable = dir.path().join("owned worker.exe");
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let image = fs::OpenOptions::new()
            .access_mode(0x8000_0000 | 0x2000_0000)
            .share_mode(windows::Win32::Storage::FileSystem::FILE_SHARE_READ.0)
            .open(&executable)
            .unwrap();
        let command = OsString::from(format!(
            r#""{}" --exact {ENTRY} --ignored --nocapture "spaces \"quoted\" café Ω""#,
            executable.display(),
        ));
        let mut environment = Vec::new();
        for item in [
            OsString::from(format!("=C:={}", dir.path().display())),
            OsString::from("DCLEANER_CREATION_EMPTY="),
            OsString::from("DCLEANER_CREATION_UNICODE=café Ω 日本語"),
            {
                let mut value: Vec<u16> = "DCLEANER_CREATION_OPAQUE=".encode_utf16().collect();
                value.push(0xd800);
                OsString::from_wide(&value)
            },
            {
                let mut value = OsString::from("SystemRoot=");
                value.push(std::env::var_os("SystemRoot").unwrap());
                value
            },
        ] {
            environment.extend(item.encode_wide());
            environment.push(0);
        }
        environment.push(0);
        Self {
            dir,
            image: Some(image),
            command,
            environment,
        }
    }
    pub(crate) fn image(&self) -> BorrowedHandle<'_> {
        self.image.as_ref().unwrap().as_handle()
    }
    pub(crate) fn input(&self) -> LaunchInput {
        LaunchInput::new(
            &self.dir.path().join("owned worker.exe"),
            &self.command,
            self.dir.path(),
            &self.environment,
        )
        .unwrap()
    }
    pub(crate) fn scope<'a>(&self, expected: &'a Principal) -> LaunchScope<'a> {
        LaunchScope {
            expected,
            member: member(expected),
            invocation: Uuid::new_v4(),
            instance: Uuid::new_v4(),
        }
    }
    pub(crate) fn marker(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // A resumed fixture releases itself; no production running-app kill.
        let _ = fs::write(self.marker("exit"), b"exit");
        drop(self.image.take());
    }
}

fn observed_fixture(fixture: &Fixture) -> serde_json::Value {
    let mut observed = None;
    wait(|| {
        observed = fs::read(fixture.marker("observed.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        observed.is_some()
    });
    observed.unwrap()
}

#[test]
#[ignore = "Private copied Rust image entry; invoked only by bounded native creation parents"]
fn owned_creation_entry() {
    let root = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    assert!(
        root.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("optimizer-creation-fixture-")
    );
    assert_eq!(
        fs::read_to_string(root.join("fixture.marker")).unwrap(),
        MARKER
    );
    let command = unsafe { GetCommandLineW() };
    let mut raw = Vec::new();
    for offset in 0..MAX_STRING {
        let unit = unsafe { command.0.add(offset).read() };
        if unit == 0 {
            break;
        }
        raw.push(unit);
    }
    let principal = Principal::current().unwrap();
    let captured = capture::current_helper_input(
        &principal,
        &std::env::current_exe().unwrap(),
        &OsString::from_wide(&raw),
        &no_cancel(),
    )
    .unwrap();
    let mut startup = STARTUPINFOW::default();
    unsafe {
        GetStartupInfoW(&mut startup);
    }
    let windows = own_top_level_windows();
    assert_eq!(
        windows, 0,
        "private Rust worker must create no application window"
    );
    let result = serde_json::json!({
        "command": raw,
        "arguments": std::env::args_os().map(|a| wide(&a)).collect::<Vec<_>>(),
        "directory": wide(std::env::current_dir().unwrap().as_os_str()),
        "unicode": wide(&std::env::var_os("DCLEANER_CREATION_UNICODE").unwrap()),
        "empty": wide(&std::env::var_os("DCLEANER_CREATION_EMPTY").unwrap()),
        "parent_path_absent": std::env::var_os("PATH").is_none(),
        "user": principal.user_sid().unwrap(), "session": principal.session_id(),
        "logon": principal.logon_sid().unwrap(), "boot": principal.boot_id(),
        "startup_flags": startup.dwFlags.0, "startup_show_window": startup.wShowWindow,
        "own_top_level_windows": windows,
        "captured_command": captured.command, "captured_directory": captured.directory,
        "captured_environment": captured.environment, "captured_show_window": captured.show_window,
    });
    fs::write(
        root.join("observed.json"),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(12);
    while !root.join("exit").exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn retained_selected_image_reaches_suspended_factory_without_resuming_private_child() {
    let fixture = Fixture::new();
    let principal = Principal::current().unwrap();
    let cancel = no_cancel();
    let expected =
        crate::optimizer_identity::inspect(&fixture.marker("owned worker.exe"), &cancel).unwrap();
    let pin = crate::optimizer_identity::PinnedImage::open(&expected, &cancel).unwrap();
    // Only this private Rust fixture image is created, with CREATE_NO_WINDOW
    // under the existing fixture owner. Synthetic member association is not
    // full production lease/effect authority. Its primary thread never resumes.
    let suspended = unsafe {
        PendingJob::fixture().unwrap().create_suspended(
            fixture.input(),
            pin.handle(),
            fixture.scope(&principal),
            &cancel,
            || {
                pin.revalidate(&cancel)
                    .map_err(|error| io::Error::other(error.message))
            },
        )
    }
    .unwrap();
    assert!(!fixture.marker("observed.json").exists());
    assert_eq!(pin.snapshot(), &expected);
    let failure = suspended.abort(io::Error::other("private pin fixture stops before resume"));
    assert_eq!(failure.outcome, LaunchOutcome::AbortedBeforeResume);
    assert!(!fixture.marker("observed.json").exists());
    pin.revalidate(&cancel).unwrap();
    eprintln!(
        "SELECTED_PIN factory_created_suspended=true primary_resumed=false owned_abort_confirmed=true original_launch=false"
    );
}

#[test]
fn original_wire_context_reaches_owned_native_input_and_aborts_without_resume() {
    use crate::optimizer_protocol::{
        self as codec, HelperRequest, OriginalContext, RequestEnvelope,
    };
    let fixture = Fixture::new();
    let principal = Principal::current().unwrap();
    let cancel = no_cancel();
    let expected = fixture.input();
    let original = OriginalContext::new(
        expected.command[..expected.command.len() - 1].to_vec(),
        expected.directory[..expected.directory.len() - 1].to_vec(),
        expected.environment.clone(),
        Some(0),
    )
    .unwrap();
    let request = RequestEnvelope {
        request_id: Uuid::new_v4(),
        request: HelperRequest::Reactivate {
            lease_id: Uuid::new_v4(),
            invocation_id: Uuid::new_v4(),
            original: Box::new(original),
        },
    };
    let mut frame = Vec::new();
    codec::write_request(&mut frame, &request).unwrap();
    let decoded = codec::read_request(&mut std::io::Cursor::new(frame))
        .unwrap()
        .unwrap();
    let HelperRequest::Reactivate { original, .. } = decoded.request else {
        unreachable!()
    };
    let input =
        LaunchInput::from_original_context(&fixture.marker("owned worker.exe"), &original).unwrap();
    assert_eq!(input.application, expected.application);
    assert_eq!(input.command, expected.command);
    assert_eq!(input.directory, expected.directory);
    assert_eq!(input.environment, expected.environment);
    assert_eq!(input.show_window, Some(0));
    assert!(LaunchInput::from_original_context(Path::new("relative.exe"), &original).is_err());
    let remote_directory = OriginalContext::new(
        original.command().to_vec(),
        r"\\server\share".encode_utf16().collect(),
        original.environment().to_vec(),
        original.show_window(),
    )
    .unwrap();
    assert!(
        LaunchInput::from_original_context(&fixture.marker("owned worker.exe"), &remote_directory)
            .is_err()
    );
    let suspended = unsafe {
        PendingJob::fixture().unwrap().create_suspended(
            input,
            fixture.image(),
            fixture.scope(&principal),
            &cancel,
            || Ok(()),
        )
    }
    .unwrap();
    assert!(!fixture.marker("observed.json").exists());
    assert!(matches!(
        suspended
            .abort(io::Error::other("fixture must not resume"))
            .outcome,
        LaunchOutcome::AbortedBeforeResume
    ));
    assert!(!fixture.marker("observed.json").exists());
    eprintln!(
        "ORIGINAL_WIRE_CONTEXT exact_utf16=true owner_selected_image=true staged=true aborted_before_resume=true original_executed=false physical_input=false"
    );
}

#[test]
fn original_launch_round_trips_inside_owned_job_before_lifetime_release() {
    let fixture = Fixture::new();
    let principal = Principal::current().unwrap();
    let cancel = no_cancel();
    let mut validations = 0;
    // The only launched target is this test image's private copy. Synthetic
    // member/pins substitute for unavailable complete app/lease authority here.
    let mut family = unsafe {
        PendingJob::fixture().unwrap().launch(
            fixture.input(),
            fixture.image.as_ref().unwrap().as_handle(),
            fixture.scope(&principal),
            &cancel,
            || {
                validations += 1;
                assert!(
                    !fixture.marker("observed.json").exists(),
                    "code ran before final validation"
                );
                Ok(())
            },
        )
    }
    .unwrap();
    assert_eq!(validations, 2);
    let observed = observed_fixture(&fixture);
    assert_eq!(
        observed["command"],
        serde_json::json!(wide(&fixture.command))
    );
    assert_eq!(
        observed["directory"],
        serde_json::json!(wide(fixture.dir.path().as_os_str()))
    );
    assert_eq!(
        observed["unicode"],
        serde_json::json!("café Ω 日本語".encode_utf16().collect::<Vec<_>>())
    );
    assert_eq!(observed["empty"], serde_json::json!([]));
    assert_eq!(observed["parent_path_absent"], true);
    assert_eq!(
        observed["captured_command"],
        serde_json::json!(
            wide(&fixture.command)
                .into_iter()
                .chain(Some(0))
                .collect::<Vec<_>>()
        )
    );
    assert_eq!(
        observed["captured_directory"],
        serde_json::json!(
            wide(fixture.dir.path().as_os_str())
                .into_iter()
                .chain(Some(0))
                .collect::<Vec<_>>()
        )
    );
    assert_eq!(
        observed["captured_environment"],
        serde_json::json!(fixture.environment)
    );
    assert!(observed["captured_show_window"].is_null());
    assert_eq!(
        observed["startup_flags"].as_u64().unwrap() & STARTF_USESHOWWINDOW.0 as u64,
        0
    );
    assert_eq!(observed["own_top_level_windows"], 0);
    assert_eq!(observed["user"], principal.user_sid().unwrap());
    assert_eq!(observed["session"], principal.session_id());
    assert_eq!(
        observed["logon"],
        serde_json::json!(principal.logon_sid().unwrap())
    );
    assert_eq!(observed["boot"], serde_json::json!(principal.boot_id()));
    let state = family.observe(&cancel).unwrap();
    if state.total_processes != 1 || state.active_processes != 1 {
        diagnose_owned_members(family.job.as_handle());
    }
    // Exactly one root is enforced before resume by admission and the final
    // gate. After resume Windows may add its headless console host, and an app
    // may add descendants; all remain part of the family, never ignored.
    assert!(state.total_processes >= state.active_processes && state.active_processes >= 1);
    assert!(!state.root_exited);
    fs::write(fixture.marker("exit"), b"exit").unwrap();
    // Image teardown can precede the retained process handle's signal. A
    // transient query error is unknown, never exit proof or a launch retry.
    wait(|| family.observe(&cancel).is_ok_and(|state| state.ended()));
    assert_eq!(family.observe(&cancel).unwrap().root_exit_code, Some(0));
    eprintln!(
        "OWNED_CREATION raw_command=true explicit_environment=true cwd=true identity=true job=true pre_resume_validation=true exit=true"
    );
}

#[test]
fn dropping_staged_original_aborts_only_its_owned_root_before_any_code_executes() {
    let fixture = Fixture::new();
    let principal = Principal::current().unwrap();
    let pending = unsafe {
        PendingJob::fixture().unwrap().create_suspended(
            fixture.input(),
            fixture.image(),
            fixture.scope(&principal),
            &no_cancel(),
            || Ok(()),
        )
    }
    .unwrap_or_else(|error| panic!("private staged creation failed: {error}"));
    let root = pending.suspended.root.try_clone().unwrap();
    thread::sleep(Duration::from_millis(40));
    assert!(!fixture.marker("observed.json").exists());
    assert_eq!(
        unsafe { WaitForSingleObject(handle(root.as_handle()), 0) },
        WAIT_TIMEOUT
    );
    drop(pending);
    assert_eq!(
        unsafe { WaitForSingleObject(handle(root.as_handle()), 1000) },
        WAIT_OBJECT_0
    );
    let mut code = 0;
    unsafe { GetExitCodeProcess(handle(root.as_handle()), &mut code) }.unwrap();
    assert_eq!(code, 0xDC01);
    assert!(!fixture.marker("observed.json").exists());
    eprintln!("STAGED_HANDOFF abandoned_stage=true root_signalled=true code_never_executed=true");
}

// Read-only diagnostics of this fixture's retained job; process IDs and paths
// are neither admission/effect authority nor exported reference evidence.
fn diagnose_owned_members(job: BorrowedHandle<'_>) {
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    for pid in owned_member_ids(job) {
        let process =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.unwrap();
        let process = unsafe { OwnedHandle::from_raw_handle(process.0) };
        let mut buffer = [0u16; 32768];
        let mut length = buffer.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(
                handle(process.as_handle()),
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut length,
            )
        }
        .unwrap();
        let path = PathBuf::from(OsString::from_wide(&buffer[..length as usize]));
        eprintln!(
            "OWNED_CREATION_DIAGNOSTIC member={:?}",
            path.file_name().unwrap()
        );
    }
}
fn owned_member_ids(job: BorrowedHandle<'_>) -> Vec<u32> {
    use windows::Win32::System::JobObjects::{
        JOBOBJECT_BASIC_PROCESS_ID_LIST, JobObjectBasicProcessIdList,
    };
    let mut words = [0usize; 128];
    unsafe {
        QueryInformationJobObject(
            Some(handle(job)),
            JobObjectBasicProcessIdList,
            words.as_mut_ptr().cast(),
            size_of_val(&words) as u32,
            None,
        )
    }
    .unwrap();
    let list = words.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>();
    let count = unsafe { (*list).NumberOfProcessIdsInList } as usize;
    assert!(count <= 126);
    (0..count)
        .map(|index| unsafe { (*list).ProcessIdList.as_ptr().add(index).read() as u32 })
        .collect()
}

#[test]
fn final_pin_refusal_and_cancellation_abort_suspended_child_before_code_runs() {
    for cancelled_on_validation in [false, true] {
        let fixture = Fixture::new();
        let principal = Principal::current().unwrap();
        let cancel = no_cancel();
        let pending = PendingJob::fixture().unwrap();
        let job = pending.job.try_clone().unwrap(); // fixture-only accounting proof.
        let mut validations = 0;
        let error = unsafe {
            pending.launch(
                fixture.input(),
                fixture.image.as_ref().unwrap().as_handle(),
                fixture.scope(&principal),
                &cancel,
                || {
                    validations += 1;
                    if validations == 2 {
                        if cancelled_on_validation {
                            cancel.store(true, Ordering::Release);
                        } else {
                            return Err(invalid("Fixture image pin changed."));
                        }
                    }
                    Ok(())
                },
            )
        }
        .err()
        .expect("final validation must refuse resume");
        assert_eq!(
            error.cause.kind(),
            if cancelled_on_validation {
                io::ErrorKind::Interrupted
            } else {
                io::ErrorKind::InvalidData
            }
        );
        assert_eq!(error.outcome, LaunchOutcome::AbortedBeforeResume);
        let counts = settled_accounting(job.as_handle());
        assert_eq!((counts.TotalProcesses, counts.ActiveProcesses), (1, 0));
        assert!(!fixture.marker("observed.json").exists());
    }
}

#[test]
fn identical_other_file_cannot_admit_created_root_and_creation_failure_is_not_retried() {
    let fixture = Fixture::new();
    let principal = Principal::current().unwrap();
    let pending = PendingJob::fixture().unwrap();
    let job = pending.job.try_clone().unwrap();
    let other = fixture.marker("identical.exe");
    fs::copy(fixture.marker("owned worker.exe"), &other).unwrap();
    let other = fs::OpenOptions::new()
        .access_mode(0x8000_0000 | 0x2000_0000)
        .share_mode(1)
        .open(other)
        .unwrap();
    let error = unsafe {
        pending.launch(
            fixture.input(),
            other.as_handle(),
            fixture.scope(&principal),
            &no_cancel(),
            || Ok(()),
        )
    }
    .err()
    .expect("identical bytes are not exact file identity");
    assert_eq!(error.cause.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.outcome, LaunchOutcome::AbortedBeforeResume);
    assert_eq!(settled_accounting(job.as_handle()).ActiveProcesses, 0);
    assert!(!fixture.marker("observed.json").exists());
    let mut input = fixture.input();
    input.application = local_path(&fixture.marker("missing.exe")).unwrap();
    let pending = PendingJob::fixture().unwrap();
    let job = pending.job.try_clone().unwrap();
    let mut attempts = 0;
    let error = unsafe {
        pending.launch(
            input,
            fixture.image.as_ref().unwrap().as_handle(),
            fixture.scope(&principal),
            &no_cancel(),
            || {
                attempts += 1;
                Ok(())
            },
        )
    }
    .err()
    .expect("missing target must not launch");
    assert_eq!(error.outcome, LaunchOutcome::NotCreated);
    assert_eq!(attempts, 1);
    assert_eq!(accounting(job.as_handle()).unwrap().TotalProcesses, 0);
}

#[test]
fn launch_input_rejects_ambiguous_paths_nuls_truncated_environments_and_limits() {
    let application = Path::new(r"C:\Fixture\app.exe");
    let directory = Path::new(r"C:\Fixture");
    let command = OsStr::new("original \"command\"");
    for path in [
        r"relative.exe",
        r"C:relative.exe",
        r"\\server\app.exe",
        r"\\.\pipe\app.exe",
        r"C:\Fixture\..\app.exe",
    ] {
        assert!(LaunchInput::new(Path::new(path), command, directory, &[0, 0]).is_err());
    }
    for env in [
        vec![],
        vec![0],
        vec![b'A' as u16, 0, 0],
        vec![0, 0, b'B' as u16, 0, 0],
        vec![b'=' as u16, 0, 0],
        vec![0; MAX_ENVIRONMENT + 1],
    ] {
        assert!(LaunchInput::new(application, command, directory, &env).is_err());
    }
    let nul = OsString::from_wide(&[65, 0, 66]);
    assert!(LaunchInput::new(application, &nul, directory, &[0, 0]).is_err());
    let oversized = OsString::from_wide(&vec![65; MAX_STRING]);
    assert!(LaunchInput::new(application, &oversized, directory, &[0, 0]).is_err());
    let surrogate = OsString::from_wide(&[65, 0xd800, 66]);
    assert_eq!(
        LaunchInput::new(application, &surrogate, directory, &[0, 0])
            .unwrap()
            .command,
        vec![65, 0xd800, 66, 0]
    );
    assert!(
        LaunchInput::new(
            application,
            command,
            directory,
            &[b'A' as u16, b'=' as u16, 0, 0]
        )
        .is_ok()
    );
}

#[test]
fn original_show_window_validation_preserves_only_defined_explicit_instructions() {
    let input = || {
        LaunchInput::new(
            Path::new(r"C:\Fixture\app.exe"),
            OsStr::new("original command"),
            Path::new(r"C:\Fixture"),
            &[0, 0],
        )
        .unwrap()
    };
    assert_eq!(
        input()
            .with_original_show_window(0, u16::MAX)
            .unwrap()
            .show_window,
        None
    );
    for show in 0..=11 {
        let result = input().with_original_show_window(STARTF_USESHOWWINDOW.0 | 0x100, show);
        if show == 10 {
            assert!(
                result.is_err(),
                "STARTUPINFO does not accept SW_SHOWDEFAULT"
            );
        } else {
            assert_eq!(result.unwrap().show_window, Some(show));
        }
    }
    for show in [12, u16::MAX] {
        assert!(
            input()
                .with_original_show_window(STARTF_USESHOWWINDOW.0, show)
                .is_err()
        );
    }
    assert_eq!(
        input()
            .with_original_show_window(STARTF_USESHOWWINDOW.0, 3)
            .unwrap()
            .with_original_show_window(0, 10)
            .unwrap()
            .show_window,
        None
    );
}

#[test]
fn staged_original_show_window_round_trips_as_native_metadata_without_creating_windows() {
    for (flags, show, expected) in [
        (0, u16::MAX, None),
        (STARTF_USESHOWWINDOW.0, 0, Some(0)),
        (STARTF_USESHOWWINDOW.0, 1, Some(1)),
        (STARTF_USESHOWWINDOW.0, 2, Some(2)),
        (STARTF_USESHOWWINDOW.0, 3, Some(3)),
        (STARTF_USESHOWWINDOW.0, 7, Some(7)),
    ] {
        let fixture = Fixture::new();
        let principal = Principal::current().unwrap();
        let cancel = no_cancel();
        let input = fixture
            .input()
            .with_original_show_window(flags, show)
            .unwrap();
        let pending = unsafe {
            PendingJob::fixture().unwrap().create_suspended(
                input,
                fixture.image(),
                fixture.scope(&principal),
                &cancel,
                || Ok(()),
            )
        }
        .unwrap_or_else(|error| panic!("private show-state staging failed: {error}"));
        assert!(
            !fixture.marker("observed.json").exists(),
            "staged original must not execute before resume"
        );
        let mut family = unsafe { pending.resume(&cancel, || Ok(())) }
            .unwrap_or_else(|error| panic!("private show-state resume failed: {error}"));
        let observed = observed_fixture(&fixture);
        let native_flags = observed["startup_flags"].as_u64().unwrap() as u32;
        assert_eq!(
            native_flags & STARTF_USESHOWWINDOW.0 != 0,
            expected.is_some()
        );
        if let Some(expected) = expected {
            assert_eq!(observed["startup_show_window"], expected);
        }
        assert_eq!(
            observed["captured_show_window"],
            serde_json::json!(expected)
        );
        assert_eq!(
            observed["captured_environment"],
            serde_json::json!(fixture.environment)
        );
        assert_eq!(observed["own_top_level_windows"], 0);
        assert_eq!(
            observed["command"],
            serde_json::json!(wide(&fixture.command))
        );
        assert_eq!(
            observed["directory"],
            serde_json::json!(wide(fixture.dir.path().as_os_str()))
        );
        assert_eq!(
            observed["unicode"],
            serde_json::json!("café Ω 日本語".encode_utf16().collect::<Vec<_>>())
        );
        fs::write(fixture.marker("exit"), b"exit").unwrap();
        wait(|| family.observe(&cancel).is_ok_and(|state| state.ended()));
        assert_eq!(family.observe(&cancel).unwrap().root_exit_code, Some(0));
        eprintln!(
            "ORIGINAL_SHOW_WINDOW explicit={} requested={} observed={} staged=true resume_once=true own_top_level_windows=0 retained_exit=0 physical_input=false",
            expected.is_some(),
            show,
            observed["startup_show_window"]
        );
    }
}

#[test]
fn helper_context_refuses_pre_cancel_and_effective_identity_fallback() {
    use windows::Win32::{
        Security::{ImpersonateAnonymousToken, RevertToSelf},
        System::Threading::GetCurrentThread,
    };
    let expected = Principal::current().unwrap();
    let error = capture::current_helper_input(
        &expected,
        Path::new("relative.exe"),
        OsStr::new(""),
        &AtomicBool::new(true),
    )
    .err()
    .expect("pre-cancel must refuse before native capture");
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    struct Revert(bool);
    impl Drop for Revert {
        fn drop(&mut self) {
            if self.0 {
                let _ = unsafe { RevertToSelf() };
            }
        }
    }
    unsafe { ImpersonateAnonymousToken(GetCurrentThread()) }.unwrap();
    let mut reset = Revert(true);
    let error = capture::current_helper_input(
        &expected,
        Path::new(r"C:\Fixture\app.exe"),
        OsStr::new("original command"),
        &no_cancel(),
    )
    .err();
    unsafe { RevertToSelf() }.unwrap();
    reset.0 = false;
    assert!(
        error.is_some(),
        "effective identity mismatch must not fall back to the process or service context"
    );
    assert_eq!(Principal::current().unwrap(), expected);
    eprintln!(
        "HELPER_CONTEXT_REFUSAL pre_cancel=true impersonated_effective_identity=true process_fallback=false restored=true physical_input=false"
    );
}

#[test]
fn invalid_scope_and_pre_cancel_never_create_a_native_root() {
    let fixture = Fixture::new();
    let principal = Principal::current().unwrap();
    for cancel_before in [false, true] {
        let pending = PendingJob::fixture().unwrap();
        let job = pending.job.try_clone().unwrap();
        let mut scope = fixture.scope(&principal);
        if !cancel_before {
            scope.invocation = Uuid::nil();
        }
        let error = unsafe {
            pending.launch(
                fixture.input(),
                fixture.image.as_ref().unwrap().as_handle(),
                scope,
                &AtomicBool::new(cancel_before),
                || panic!("validation must not run"),
            )
        }
        .err()
        .unwrap();
        assert_eq!(
            error.cause.kind(),
            if cancel_before {
                io::ErrorKind::Interrupted
            } else {
                io::ErrorKind::InvalidData
            }
        );
        assert_eq!(error.outcome, LaunchOutcome::NotCreated);
        assert_eq!(accounting(job.as_handle()).unwrap().TotalProcesses, 0);
    }
}

#[test]
fn unwind_during_final_pin_check_aborts_only_its_unresumed_private_child() {
    let fixture = Fixture::new();
    let principal = Principal::current().unwrap();
    let pending = PendingJob::fixture().unwrap();
    let job = pending.job.try_clone().unwrap();
    let mut checks = 0;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        pending.launch(
            fixture.input(),
            fixture.image.as_ref().unwrap().as_handle(),
            fixture.scope(&principal),
            &no_cancel(),
            || {
                checks += 1;
                assert!(checks != 2, "private injected final-pin unwind");
                Ok(())
            },
        )
    }));
    assert!(result.is_err());
    assert_eq!(checks, 2);
    let counts = settled_accounting(job.as_handle());
    assert_eq!((counts.TotalProcesses, counts.ActiveProcesses), (1, 0));
    assert!(!fixture.marker("observed.json").exists());
}

#[test]
fn changed_native_suspend_count_retains_uncertain_family_and_never_retries_resume() {
    use windows::Win32::System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        },
        Threading::{OpenThread, SuspendThread, THREAD_SUSPEND_RESUME},
    };
    let fixture = Fixture::new();
    let principal = Principal::current().unwrap();
    let pending = PendingJob::fixture().unwrap();
    let job = pending.job.try_clone().unwrap();
    let mut checks = 0;
    let revalidate = || {
        checks += 1;
        if checks == 2 {
            let ids = owned_member_ids(job.as_handle());
            assert_eq!(
                ids.len(),
                1,
                "only this fixture's newly created suspended root"
            );
            let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }.unwrap();
            let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot.0) };
            let mut entry = THREADENTRY32 {
                dwSize: size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            unsafe { Thread32First(handle(snapshot.as_handle()), &mut entry) }.unwrap();
            let mut found = false;
            for _ in 0..100_000 {
                if entry.th32OwnerProcessID == ids[0] {
                    let thread =
                        unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) }
                            .unwrap();
                    let thread = unsafe { OwnedHandle::from_raw_handle(thread.0) };
                    // Deliberate fixture-only violation of the exclusive
                    // launch owner's thread contract: 1 -> 2 suspensions.
                    assert_eq!(unsafe { SuspendThread(handle(thread.as_handle())) }, 1);
                    found = true;
                    break;
                }
                if unsafe { Thread32Next(handle(snapshot.as_handle()), &mut entry) }.is_err() {
                    break;
                }
            }
            assert!(
                found,
                "owned suspended thread must be found within the snapshot bound"
            );
        }
        Ok(())
    };
    let mut error = unsafe {
        pending.launch(
            fixture.input(),
            fixture.image.as_ref().unwrap().as_handle(),
            fixture.scope(&principal),
            &no_cancel(),
            revalidate,
        )
    }
    .err()
    .expect("unexpected native resume count must refuse acceptance");
    assert_eq!(checks, 2);
    assert_eq!(error.outcome, LaunchOutcome::ExecutionUncertain);
    assert_eq!(
        error.confirm_owned_abort().unwrap(),
        LaunchOutcome::ExecutionUncertain
    );
    let family = error
        .retained_family()
        .expect("uncertainty must retain native lifetime handles");
    let state = family.observe(&no_cancel()).unwrap();
    assert!(state.ended());
    assert_eq!(state.root_exit_code, Some(0xDC01));
    assert_eq!(settled_accounting(job.as_handle()).ActiveProcesses, 0);
    assert!(!fixture.marker("observed.json").exists());
    eprintln!(
        "OWNED_CREATION_UNCERTAINTY native_suspend_count_changed=true resume_retried=false family_retained=true aborted=true"
    );
}
