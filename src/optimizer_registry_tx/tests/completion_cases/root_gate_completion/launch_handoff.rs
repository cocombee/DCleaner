//! Actual TxR/SQLite restoration between native creation and resume. The hook
//! roster/image association is synthetic and lives only in random HKCU keys;
//! these values cannot intercept anything. Only a private copied Rust test
//! image runs. This is not deployed IFEO/service or complete-app acceptance.
use super::*;
use crate::{
    optimizer_launch_job::{
        PendingJob,
        creation::{LaunchInput, LaunchOutcome, LaunchScope, tests::Fixture as Child},
    },
    optimizer_pipe_security::Principal,
};
use std::{ffi::OsStr, io, thread};

fn caller(principal: &Principal) -> Caller {
    Caller::fixture_boot(
        &principal.user_sid().unwrap(),
        principal.session_id(),
        &principal.logon_sid().unwrap().unwrap(),
        principal.boot_id(),
    )
}
fn scope<'a>(flow: &Flow, principal: &'a Principal) -> LaunchScope<'a> {
    LaunchScope {
        expected: principal,
        member: flow.members[0].clone(),
        invocation: Uuid::new_v4(),
        instance: flow.instance,
    }
}
fn wait(mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(6);
    while !done() {
        assert!(Instant::now() < deadline, "native launch handoff timed out");
        thread::sleep(Duration::from_millis(10));
    }
}
fn assert_hook(flow: &Flow, actor: usize) {
    for (index, name) in [Name::Debugger, Name::FilterFullPath]
        .into_iter()
        .enumerate()
    {
        let id = flow
            .reg
            .scope()
            .slot_identity(&Flow::path(actor), name)
            .unwrap();
        assert_eq!(
            native_state(&flow.reg, &Flow::path(actor), name),
            slot_state(true, Some(dword(2 + actor as u32 * 2 + index as u32))).unwrap()
        );
        assert_eq!(
            flow.catalog.inspect(&id).unwrap().unwrap().phase,
            Phase::Sleeping
        );
    }
    flow.assert_root(true);
}
fn sleeping(flow: &mut Flow) {
    assert_eq!(flow.mutate(0, true, 0).unwrap(), vec![Phase::Sleeping; 3]);
    assert_eq!(flow.mutate(1, true, 0).unwrap(), vec![Phase::Sleeping; 3]);
}
fn clear_original(flow: &mut Flow) {
    assert_eq!(
        flow.mutate(0, false, 0).unwrap(),
        vec![Phase::Sleeping, Phase::Awake, Phase::Awake]
    );
    assert!(matches!(
        flow.reg.open(&Flow::path(0)),
        Err(Failure::Native(2 | 3))
    ));
    assert_hook(flow, 1);
}

#[test]
fn native_original_launch_waits_for_durable_hook_restore_and_preserves_other_shared_hook() {
    require_txr!();
    for original in [None, Some(0), Some(1)] {
        let child = Child::new();
        let principal = Principal::current().unwrap();
        let mut flow = Flow::for_caller(original, caller(&principal));
        let cancel = AtomicBool::new(false);
        sleeping(&mut flow);
        clear_original(&mut flow);
        let pending = unsafe {
            PendingJob::fixture().unwrap().create_suspended(
                child.input(),
                child.image(),
                scope(&flow, &principal),
                &cancel,
                || {
                    assert!(!child.marker("observed.json").exists());
                    assert_hook(&flow, 1);
                    Ok(())
                },
            )
        }
        .unwrap_or_else(|error| panic!("private creation failed: {error}"));
        // Delay the owner deliberately: the API must not execute root code
        // while the restoration transaction/receipt remains outstanding.
        thread::sleep(Duration::from_millis(40));
        assert!(!child.marker("observed.json").exists());
        assert_eq!(flow.mutate(0, true, 0).unwrap(), vec![Phase::Sleeping; 3]);
        assert!(!child.marker("observed.json").exists());
        let mut family = unsafe {
            pending.resume(&cancel, || {
                assert_hook(&flow, 0);
                assert_hook(&flow, 1);
                assert!(!child.marker("observed.json").exists());
                Ok(())
            })
        }
        .unwrap_or_else(|error| panic!("private resume failed: {error}"));
        wait(|| child.marker("observed.json").exists());
        assert!(!family.observe(&cancel).unwrap().root_exited);
        std::fs::write(child.marker("exit"), b"exit").unwrap();
        wait(|| family.observe(&cancel).is_ok_and(|state| state.ended()));
        assert_eq!(family.observe(&cancel).unwrap().root_exit_code, Some(0));
        assert_hook(&flow, 0);
        assert_hook(&flow, 1);
    }
    eprintln!(
        "STAGED_HANDOFF baselines=3 shared_hooks=2 durable_restore_before_execution=true root_exit=true"
    );
}

#[test]
fn native_failed_restore_or_receipt_aborts_original_without_running_or_retrying_it() {
    require_txr!();
    for failure in [1, 6] {
        let child = Child::new();
        let principal = Principal::current().unwrap();
        let mut flow = Flow::for_caller(Some(0), caller(&principal));
        let cancel = AtomicBool::new(false);
        sleeping(&mut flow);
        clear_original(&mut flow);
        let pending = unsafe {
            PendingJob::fixture().unwrap().create_suspended(
                child.input(),
                child.image(),
                scope(&flow, &principal),
                &cancel,
                || Ok(()),
            )
        }
        .unwrap_or_else(|error| panic!("private creation failed: {error}"));
        let restoration = flow.mutate(0, true, failure);
        // A recorded unsuccessful attempt may return Ok(Uncertain); only all
        // observed/durably completed desired phases can settle restoration.
        assert!(
            !restoration
                .as_ref()
                .is_ok_and(|phases| { phases.iter().all(|phase| *phase == Phase::Sleeping) })
        );
        let error = pending.abort(io::Error::other("Fixture hook restoration did not settle."));
        assert_eq!(error.outcome, LaunchOutcome::AbortedBeforeResume);
        thread::sleep(Duration::from_millis(40));
        assert!(!child.marker("observed.json").exists());
        if failure == 6 {
            // Native hook restoration happened, but the resource COMMIT failed.
            // Native matching bytes alone must not release the suspended app.
            assert_eq!(
                native_state(&flow.reg, &Flow::path(0), Name::Debugger),
                slot_state(true, Some(dword(2))).unwrap()
            );
            let id = flow
                .reg
                .scope()
                .slot_identity(&Flow::path(0), Name::Debugger)
                .unwrap();
            assert_ne!(
                flow.catalog.inspect(&id).unwrap().unwrap().phase,
                Phase::Sleeping
            );
        }
        // Its bytes remain untouched; the group's phase may require review
        // because its reservation participates in the failed completion.
        assert_eq!(
            native_state(&flow.reg, &Flow::path(1), Name::Debugger),
            slot_state(true, Some(dword(4))).unwrap()
        );
    }
    eprintln!(
        "STAGED_HANDOFF failed_restore=true failed_resource_receipt=true abort_before_execution=true no_retry=true"
    );
}

#[test]
fn native_creation_failure_still_allows_owned_hook_restoration_without_launch_retry() {
    require_txr!();
    let child = Child::new();
    let principal = Principal::current().unwrap();
    let mut flow = Flow::for_caller(None, caller(&principal));
    let cancel = AtomicBool::new(false);
    sleeping(&mut flow);
    clear_original(&mut flow);
    let input = LaunchInput::new(
        &child.marker("missing.exe"),
        OsStr::new("private missing invocation"),
        &child.marker(""),
        &[0, 0],
    )
    .unwrap();
    let mut creates = 0;
    let result = unsafe {
        PendingJob::fixture().unwrap().create_suspended(
            input,
            child.image(),
            scope(&flow, &principal),
            &cancel,
            || {
                creates += 1;
                Ok(())
            },
        )
    };
    let error = result.err().expect("missing image must not launch");
    assert_eq!(error.outcome, LaunchOutcome::NotCreated);
    assert_eq!(creates, 1);
    assert_eq!(flow.mutate(0, true, 0).unwrap(), vec![Phase::Sleeping; 3]);
    assert_hook(&flow, 0);
    assert_hook(&flow, 1);
    assert!(!child.marker("observed.json").exists());
    eprintln!("STAGED_HANDOFF create_failed=true restore_settled=true create_attempts=1");
}
