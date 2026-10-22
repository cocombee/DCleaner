use super::*;
use windows::Win32::Security::{SID_AND_ATTRIBUTES, TOKEN_GROUPS};

fn group(text: &str) -> TokenBuffer {
    let sid = Sid::parse(text).unwrap();
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    let prefix = offset + size_of::<SID_AND_ATTRIBUTES>();
    let bytes = prefix + sid.0.len() * 4;
    let mut buffer = TokenBuffer {
        words: vec![0usize; bytes.div_ceil(size_of::<usize>())],
        bytes,
    };
    unsafe {
        let base = buffer.words.as_mut_ptr().cast::<u8>();
        base.cast::<u32>().write(1);
        ptr::copy_nonoverlapping(
            sid.0.as_ptr().cast::<u8>(),
            base.add(prefix),
            sid.0.len() * 4,
        );
        base.add(offset)
            .cast::<SID_AND_ATTRIBUTES>()
            .write(SID_AND_ATTRIBUTES {
                Sid: PSID(base.add(prefix).cast()),
                Attributes: 0xc000_0004,
            });
    }
    buffer
}
fn changed_logon(principal: &Principal) -> Principal {
    let mut changed = principal.clone();
    if let Some(logon) = &mut changed.logon {
        *logon.0.last_mut().unwrap() ^= 1;
    } else {
        changed.logon = Some(Sid::parse("S-1-5-5-1-2").unwrap());
    }
    changed
}

#[test]
fn bounded_logon_group_copy_owns_its_sid_and_accepts_no_missing_or_ambiguous_scope() {
    let input = group("S-1-5-5-12-34");
    let copied = logon_sid(&input).unwrap().unwrap();
    drop(input);
    assert_eq!(copied.text().unwrap(), "S-1-5-5-12-34");
    assert!(
        logon_sid(&TokenBuffer {
            words: vec![0],
            bytes: 4
        })
        .unwrap()
        .is_none()
    );
    for bytes in [0, 3, 9] {
        assert!(
            logon_sid(&TokenBuffer {
                words: vec![0],
                bytes
            })
            .is_err()
        );
    }
    let mut input = group("S-1-5-5-12-34");
    unsafe {
        input.words.as_mut_ptr().cast::<u32>().write(2);
    }
    assert!(logon_sid(&input).is_err());
}

#[test]
fn logon_group_parser_rejects_out_of_range_sid_flags_shape_and_exact_length_truncation() {
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    for mode in 0..7 {
        let mut input = group(if mode == 0 {
            "S-1-5-32-544"
        } else {
            "S-1-5-5-12-34"
        });
        unsafe {
            let base = input.words.as_mut_ptr().cast::<u8>();
            let item = &mut *base.add(offset).cast::<SID_AND_ATTRIBUTES>();
            match mode {
                1 => item.Sid = PSID(base.cast()),
                2 => item.Sid = PSID(base.add(input.bytes).cast()),
                3 => item.Attributes |= 0x10,
                4 => item.Attributes &= !4,
                5 => item.Attributes &= !0xc000_0000,
                6 => input.bytes -= 1,
                _ => (),
            }
        }
        assert!(logon_sid(&input).is_err(), "mode={mode}");
    }
}

#[test]
fn native_logon_scoped_endpoint_names_are_bounded_deterministic_and_separate_same_account_sessions()
{
    let actual = Principal::current().unwrap();
    let Some(logon) = actual.logon_sid().unwrap() else {
        assert!(Policy::local_system(actual).is_err());
        return;
    };
    assert!(logon.starts_with("S-1-5-5-"));
    assert_eq!(Principal::current().unwrap(), actual);
    let policy = Policy::local_system(actual.clone()).unwrap();
    let name = policy.pipe_name().unwrap();
    assert_eq!(
        name,
        Policy::local_system(actual.clone())
            .unwrap()
            .pipe_name()
            .unwrap()
    );
    assert!(name.len() <= 256);
    assert_ne!(
        name,
        Policy::local_system(changed_logon(&actual))
            .unwrap()
            .pipe_name()
            .unwrap()
    );
    let mut new_session = actual.clone();
    new_session.session ^= 1;
    assert_ne!(
        name,
        Policy::local_system(new_session)
            .unwrap()
            .pipe_name()
            .unwrap()
    );
    let mut new_boot = actual.clone();
    new_boot.boot = Uuid::new_v4();
    assert_ne!(
        name,
        Policy::local_system(new_boot).unwrap().pipe_name().unwrap()
    );
    let mut missing_boot = actual.clone();
    missing_boot.boot = Uuid::nil();
    assert!(Policy::local_system(missing_boot).is_err());
    let mut missing = actual;
    missing.logon = None;
    assert!(Policy::local_system(missing).is_err());
}

#[test]
fn native_same_account_session_with_another_logon_is_rejected_and_impersonation_reverts() {
    let (policy, name) = fixture();
    let server = policy.create_first(&name).unwrap();
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(5);
    let client = policy.connect_at(&name, deadline, &cancel).unwrap();
    let mut server = unsafe { PipeIo::from_overlapped_byte_pipe(server, deadline, &cancel) };
    let mut client = unsafe { PipeIo::from_overlapped_byte_pipe(client, deadline, &cancel) };
    server.accept().unwrap();
    let request = codec::RequestEnvelope {
        request_id: Uuid::new_v4(),
        request: codec::HelperRequest::QueryReadiness {},
    };
    codec::write_request(&mut client, &request).unwrap();
    let authenticated = policy
        .read_authenticated_request(&mut server)
        .unwrap()
        .unwrap();
    let caller = crate::optimizer_requests::Caller::authenticated(&authenticated).unwrap();
    assert_eq!(
        caller.boot_id(),
        Some(crate::optimizer_boot::current().unwrap())
    );
    assert_eq!(
        caller.logon_sid(),
        policy.client.logon_sid().unwrap().as_deref()
    );
    let mut stale = policy.clone();
    stale.client = changed_logon(&stale.client);
    assert_eq!(stale.client.user, policy.client.user);
    assert_eq!(stale.client.session, policy.client.session);
    assert_eq!(
        stale
            .authenticate_client(server.as_handle())
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(thread_token().unwrap().is_none());
    let mut prior_boot = policy.clone();
    prior_boot.client.boot = Uuid::new_v4();
    assert_eq!(
        prior_boot
            .authenticate_client(server.as_handle())
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(thread_token().unwrap().is_none());
    assert_eq!(
        policy.authenticate_client(server.as_handle()).unwrap(),
        policy.client
    );
    assert!(thread_token().unwrap().is_none());
}

#[test]
fn native_authenticated_legacy_nonce_query_requires_review_and_cannot_readmit_work() {
    use crate::optimizer_requests::{Admission, Caller, LeasePreflight, Ledger};
    let (policy, name) = fixture();
    if policy.client.logon.is_none() {
        assert!(Policy::local_system(policy.client).is_err());
        return;
    }
    let listener = policy.create_first(&name).unwrap();
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(5);
    let peer = policy.connect_at(&name, deadline, &cancel).unwrap();
    let mut server = unsafe { PipeIo::from_overlapped_byte_pipe(listener, deadline, &cancel) };
    let mut client = unsafe { PipeIo::from_overlapped_byte_pipe(peer, deadline, &cancel) };
    server.accept().unwrap();
    let mut receive = |command| {
        codec::write_request(
            &mut client,
            &codec::RequestEnvelope {
                request_id: Uuid::new_v4(),
                request: command,
            },
        )
        .unwrap();
        policy
            .read_authenticated_request(&mut server)
            .unwrap()
            .unwrap()
    };
    let caller = Caller::authenticated(&receive(codec::HelperRequest::QueryReadiness {})).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("requests.db");
    let mut ledger = Ledger::open(rusqlite::Connection::open(&path).unwrap()).unwrap();
    let legacy = Uuid::new_v4();
    let lease = Uuid::new_v4();
    let revision = Uuid::new_v4();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute("INSERT INTO invocations(account,session,invocation,lease,revision,phase,instance,nonce) VALUES(?1,?2,?3,?4,?5,2,?6,?7)",
        rusqlite::params![caller.account(),caller.session(),legacy.as_bytes().as_slice(),lease.as_bytes().as_slice(),revision.as_bytes().as_slice(),Uuid::new_v4().as_bytes().as_slice(),Uuid::new_v4().as_bytes().as_slice()]).unwrap();
    let query = receive(codec::HelperRequest::QueryInvocation {
        invocation_id: legacy,
    });
    assert!(matches!(
        ledger.query_authenticated(&query).unwrap(),
        codec::ServiceResponse::Refused {
            reason: codec::Refusal::RecoveryRequired
        }
    ));
    let request = receive(codec::HelperRequest::Reactivate {
        lease_id: lease,
        invocation_id: legacy,
        original: Box::new(crate::optimizer_protocol::OriginalContext::fixture()),
    });
    let preflight = || {
        LeasePreflight::from_owner_observation(
            caller.clone(),
            lease,
            revision,
            crate::optimizer_requests::ContextBinding::fixture_default(),
        )
        .unwrap()
    };
    assert!(matches!(
        ledger.admit_authenticated(&request, preflight()).unwrap(),
        Admission::Conflict
    ));
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM invocations", [], |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT phase FROM invocations", [], |r| r.get(0))
            .unwrap(),
        2
    );
    assert!(ledger.pending_for_review(1).unwrap().tickets.is_empty());
    let fresh = Uuid::new_v4();
    let request = receive(codec::HelperRequest::Reactivate {
        lease_id: lease,
        invocation_id: fresh,
        original: Box::new(crate::optimizer_protocol::OriginalContext::fixture()),
    });
    assert!(matches!(
        ledger.admit_authenticated(&request, preflight()).unwrap(),
        Admission::New(_)
    ));
    let query = receive(codec::HelperRequest::QueryInvocation {
        invocation_id: fresh,
    });
    assert!(matches!(
        ledger.query_authenticated(&query).unwrap(),
        codec::ServiceResponse::Invocation {
            state: codec::InvocationState::Queued,
            ..
        }
    ));
}
