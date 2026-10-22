use super::*;
use std::{
    io::Read,
    os::windows::process::CommandExt,
    process::{Child, Command, Stdio},
    time::Duration,
};
use uuid::Uuid;

fn protect(path: &Path, extra: &str) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW,
    };
    let sid = Principal::current().unwrap().user_sid().unwrap();
    let sd = Descriptor::from_sddl(&format!(
        "O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY){extra}"
    ))
    .unwrap();
    let path: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    assert!(
        unsafe {
            SetFileSecurityW(
                PCWSTR(path.as_ptr()),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                sd.native(),
            )
        }
        .as_bool()
    );
}
fn pe() -> Vec<u8> {
    let mut b = vec![0; 1024];
    b[..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    for (at, value) in [
        (0x84, 0x8664u16),
        (0x86, 1),
        (0x94, 0xf0),
        (0x96, 0x22),
        (0x98, 0x20b),
        (0xdc, 3),
    ] {
        b[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (at, value) in [(0xa8, 0x1000u32), (0xd0, 0x2000), (0xd4, 0x200)] {
        b[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    b[512..].fill(0x5a);
    b
}
fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("protected-helper");
    std::fs::create_dir(&root).unwrap();
    protect(&root, "");
    let path = root.join("DCleaner.exe");
    std::fs::write(&path, pe()).unwrap();
    protect(&path, "");
    (dir, root, path)
}

#[test]
fn helper_acl_rejects_untrusted_mutation_owner_unknown_grants_and_inheritance_aliases() {
    let access = RegistryAccess::fixture().unwrap();
    let sid = Principal::current().unwrap().user_sid().unwrap();
    for read in ["FR", "FX", "0x00120089"] {
        let sd =
            Descriptor::from_sddl(&format!("O:{sid}D:P(A;;FA;;;{sid})(A;;{read};;;WD)")).unwrap();
        check_descriptor(&sd, &access, false).unwrap();
    }
    for grant in [
        "0x00000002",
        "0x00000004",
        "0x00000010",
        "0x00000040",
        "0x00000100",
        "0x00010000",
        "0x00040000",
        "0x00080000",
        "GW",
        "GA",
        "0x02000000",
    ] {
        let sd =
            Descriptor::from_sddl(&format!("O:{sid}D:P(A;;FA;;;{sid})(A;;{grant};;;WD)")).unwrap();
        assert!(
            check_descriptor(&sd, &access, false).is_err(),
            "grant {grant}"
        );
    }
    let ancestor =
        Descriptor::from_sddl(&format!("O:{sid}D:P(A;;FA;;;{sid})(A;;0x00000004;;;WD)")).unwrap();
    check_descriptor(&ancestor, &access, true).unwrap();
    assert!(check_descriptor(&ancestor, &access, false).is_err());
    let foreign = Descriptor::from_sddl("O:WDD:P(A;;FR;;;WD)").unwrap();
    assert!(check_descriptor(&foreign, &access, false).is_err());
    let creator =
        Descriptor::from_sddl(&format!("O:{sid}D:P(A;;FA;;;{sid})(A;OICI;FA;;;CO)")).unwrap();
    check_descriptor(&creator, &access, false).unwrap();
    let creator = Descriptor::from_sddl(&format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;CO)")).unwrap();
    assert!(check_descriptor(&creator, &access, false).is_err());
}

#[test]
fn retained_helper_file_blocks_writer_delete_and_parent_rename_and_honors_cancellation() {
    let (_dir, root, path) = fixture();
    let cancel = AtomicBool::new(false);
    let helper = ProtectedHelper::fixture(&path, &root, &cancel).unwrap();
    assert!(std::fs::write(&path, b"foreign").is_err());
    assert!(std::fs::remove_file(&path).is_err());
    assert!(std::fs::rename(&root, root.with_extension("renamed")).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), pe());
    helper.revalidate(&cancel).unwrap();
    cancel.store(true, Ordering::Release);
    assert!(helper.revalidate(&cancel).is_err());
    assert!(ProtectedHelper::fixture(&path, &root, &cancel).is_err());
    drop(helper);
}

#[test]
fn pinned_helper_bootstrap_prefix_requires_current_pins_and_does_not_install_a_hook() {
    let (_dir, root, path) = fixture();
    let cancel = AtomicBool::new(false);
    let helper = ProtectedHelper::fixture(&path, &root, &cancel).unwrap();
    let lease = Uuid::new_v4();
    let prefix = helper.debugger_prefix(lease, &cancel).unwrap();
    let mut raw = prefix.clone();
    raw.push(32);
    raw.extend("original command".encode_utf16());
    assert!(crate::optimizer_helper::parse(&raw).is_ok());
    assert!(
        prefix.ends_with(
            &format!(" {} --", lease.hyphenated())
                .encode_utf16()
                .collect::<Vec<_>>()
        )
    );
    assert_eq!(std::fs::read(&path).unwrap(), pe());
    assert!(helper.debugger_prefix(Uuid::nil(), &cancel).is_err());
    cancel.store(true, Ordering::Release);
    assert!(helper.debugger_prefix(lease, &cancel).is_err());
    cancel.store(false, Ordering::Release);
    protect(&path, "(A;;0x00000002;;;WD)");
    assert!(helper.debugger_prefix(lease, &cancel).is_err());
    protect(&path, "");
    assert!(helper.debugger_prefix(lease, &cancel).is_ok());
    eprintln!(
        "HELPER_BOOTSTRAP_PREFIX retained_pins=true cancellation=true late_acl_refused=true hook_installed=false original_launch=false"
    );
}

#[test]
fn preexisting_writer_hard_links_invalid_images_and_late_acl_change_cannot_supply_helper() {
    use std::os::windows::fs::OpenOptionsExt;
    let (_dir, root, path) = fixture();
    let cancel = AtomicBool::new(false);
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .open(&path)
        .unwrap();
    assert!(ProtectedHelper::fixture(&path, &root, &cancel).is_err());
    drop(writer);
    let link = root.join("alias.exe");
    std::fs::hard_link(&path, &link).unwrap();
    assert!(ProtectedHelper::fixture(&path, &root, &cancel).is_err());
    std::fs::remove_file(link).unwrap();
    let helper = ProtectedHelper::fixture(&path, &root, &cancel).unwrap();
    protect(&path, "(A;;0x00000002;;;WD)");
    assert!(helper.revalidate(&cancel).is_err());
    protect(&path, "");
    helper.revalidate(&cancel).unwrap();
    drop(helper);
    std::fs::write(&path, b"not a PE").unwrap();
    assert!(ProtectedHelper::fixture(&path, &root, &cancel).is_err());
}

#[test]
fn native_process_mapping_matches_original_file_and_rejects_a_byte_identical_copy() {
    let dir = tempfile::tempdir().unwrap();
    let current = std::env::current_exe().unwrap();
    let file = open(&current, false).unwrap();
    let process = process_handle(unsafe { GetCurrentProcessId() }).unwrap();
    mapped_image(process.as_handle(), file.as_handle()).unwrap();
    let copy = dir.path().join("copied-test.exe");
    std::fs::copy(&current, &copy).unwrap();
    let copied = open(&copy, false).unwrap();
    assert!(mapped_image(process.as_handle(), copied.as_handle()).is_err());
    assert!(process_handle(0).is_err());
    assert!(process_handle(4).is_err());
    alive(process.as_handle()).unwrap();
    assert!(creation(process.as_handle()).unwrap() > 0);
}

fn junction(link: &Path, target: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::{
        Foundation::GENERIC_WRITE, Storage::FileSystem::FILE_SHARE_DELETE,
        System::IO::DeviceIoControl,
    };
    std::fs::create_dir(link).unwrap();
    let native = format!(r"\??\{}", target.display());
    let sub: Vec<u16> = native.encode_utf16().collect();
    let print: Vec<u16> = target.as_os_str().encode_wide().collect();
    let length = 8 + 2 * (sub.len() + 1 + print.len() + 1);
    let mut data = Vec::new();
    data.extend(0xa0000003u32.to_le_bytes());
    data.extend((length as u16).to_le_bytes());
    data.extend(0u16.to_le_bytes());
    for n in [
        0u16,
        (sub.len() * 2) as u16,
        ((sub.len() + 1) * 2) as u16,
        (print.len() * 2) as u16,
    ] {
        data.extend(n.to_le_bytes());
    }
    for n in sub.into_iter().chain(Some(0)).chain(print).chain(Some(0)) {
        data.extend(n.to_le_bytes());
    }
    let name: Vec<_> = link.as_os_str().encode_wide().chain(Some(0)).collect();
    let handle = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .unwrap();
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    let mut returned = 0;
    unsafe {
        DeviceIoControl(
            HANDLE(handle.as_raw_handle()),
            0x000900a4,
            Some(data.as_ptr().cast()),
            data.len() as u32,
            None,
            0,
            Some(&mut returned),
            None,
        )
    }
    .unwrap();
}

#[test]
fn native_junction_and_untrusted_parent_grants_are_refused_without_following_alias() {
    let (dir, root, path) = fixture();
    let link = dir.path().join("helper-alias");
    junction(&link, &root);
    assert!(open(&link, true).is_err());
    assert!(
        ProtectedHelper::fixture(&link.join("DCleaner.exe"), &link, &AtomicBool::new(false))
            .is_err()
    );
    protect(&root, "(A;;0x00000002;;;WD)");
    assert!(ProtectedHelper::fixture(&path, &root, &AtomicBool::new(false)).is_err());
    protect(&root, "");
    assert!(ProtectedHelper::fixture(&path, &root, &AtomicBool::new(false)).is_ok());
    // Remove only the task-created junction itself; its target stays intact.
    std::fs::remove_dir(&link).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), pe());
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn child(exe: &Path, name: &[u16]) -> OwnedChild {
    let text = String::from_utf16(&name[..name.len() - 1]).unwrap();
    OwnedChild(
        Command::new(exe)
            .args([
                "--exact",
                "optimizer_pipe_security::helper_image::tests::private_helper_child",
                "--ignored",
                "--nocapture",
            ])
            .env("DCLEANER_PRIVATE_HELPER_PIPE", text)
            .creation_flags(0x08000000)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
fn exchange(
    policy: &Policy,
    listener: OwnedHandle,
    helper: Arc<ProtectedHelper>,
    expect_match: bool,
    child: &mut OwnedChild,
) {
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut pipe = unsafe { PipeIo::from_overlapped_byte_pipe(listener, deadline, &cancel) };
    pipe.accept().unwrap();
    let request = policy
        .read_authenticated_request(&mut pipe)
        .unwrap()
        .unwrap();
    let observed = HelperProcess::observe(policy, &request, pipe.as_handle(), helper, &cancel);
    if expect_match {
        observed.as_ref().unwrap().revalidate(&cancel).unwrap();
    } else {
        assert!(observed.is_err());
    }
    assert!(thread_token().unwrap().is_none());
    codec::write_response(
        &mut pipe,
        &codec::ResponseEnvelope {
            request_id: request.request().request_id,
            response: codec::ServiceResponse::Refused {
                reason: codec::Refusal::ServiceNotReady,
            },
        },
    )
    .unwrap();
    let mut eof = [0];
    assert_eq!(pipe.read(&mut eof).unwrap(), 0);
    while child.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(child.0.wait().unwrap().success());
    if let Ok(proof) = observed {
        assert!(proof.revalidate(&cancel).is_err());
    }
}

#[test]
fn native_pipe_helper_process_retains_image_incarnation_and_refuses_after_owned_child_exit() {
    let (_dir, root, path) = fixture();
    std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    protect(&path, "");
    let helper = ProtectedHelper::fixture(&path, &root, &AtomicBool::new(false)).unwrap();
    let (policy, listener, name) = Policy::fixture_endpoint().unwrap();
    let mut owned = child(&path, &name);
    exchange(&policy, listener, helper, true, &mut owned);
}

#[test]
fn matching_user_and_valid_frame_cannot_match_a_different_retained_helper_file() {
    let (_dir, root, path) = fixture();
    let helper = ProtectedHelper::fixture(&path, &root, &AtomicBool::new(false)).unwrap();
    let (policy, listener, name) = Policy::fixture_endpoint().unwrap();
    let mut owned = child(&std::env::current_exe().unwrap(), &name);
    exchange(&policy, listener, helper, false, &mut owned);
    if Principal::current().unwrap().user_sid().unwrap() != "S-1-5-18" {
        assert!(ProtectedHelper::for_service(&AtomicBool::new(false)).is_err());
    }
}

#[test]
#[ignore = "Only the private parent fixture launches this hidden, bounded pipe client"]
fn private_helper_child() {
    let name = std::env::var("DCLEANER_PRIVATE_HELPER_PIPE").expect("Private helper fixture only");
    assert!(name.starts_with(r"\\.\pipe\DCleaner-service-fixture-"));
    let principal = Principal::current().unwrap();
    let policy = Policy {
        owner: principal.user.clone(),
        client: principal,
        fixture: true,
    };
    let deadline = Instant::now() + Duration::from_secs(8);
    let cancel = AtomicBool::new(false);
    let pipe = policy
        .fixture_connect(&wide(&name), deadline, &cancel)
        .unwrap();
    let mut pipe = unsafe { PipeIo::from_overlapped_byte_pipe(pipe, deadline, &cancel) };
    let request = codec::RequestEnvelope {
        request_id: Uuid::new_v4(),
        request: match std::env::var("DCLEANER_PRIVATE_HELPER_OPERATION").as_deref() {
            Ok("reactivate") => codec::HelperRequest::Reactivate {
                lease_id: Uuid::new_v4(),
                invocation_id: Uuid::new_v4(),
                original: Box::new(crate::optimizer_protocol::OriginalContext::fixture()),
            },
            Err(std::env::VarError::NotPresent) => codec::HelperRequest::QueryReadiness {},
            _ => panic!("Unknown private helper fixture operation"),
        },
    };
    codec::write_request(&mut pipe, &request).unwrap();
    let response = codec::read_response(&mut pipe, &request).unwrap().unwrap();
    if let Ok(expected) = std::env::var("DCLEANER_PRIVATE_HELPER_EXPECT_REFUSAL") {
        let reason = match expected.as_str() {
            "not_ready" => codec::Refusal::ServiceNotReady,
            "unknown_lease" => codec::Refusal::UnknownLease,
            "not_authorized" => codec::Refusal::NotAuthorized,
            "recovery_required" => codec::Refusal::RecoveryRequired,
            "ownership_changed" => codec::Refusal::OwnershipChanged,
            _ => panic!("Unknown private helper fixture refusal"),
        };
        assert_eq!(
            response.response,
            codec::ServiceResponse::Refused { reason }
        );
    }
}
