//! Non-GUI helper bootstrap. Identifiers and retained command bytes are data,
//! never lease/image/effect authority. Original-context transfer is distinct
//! from protected lease admission, native effects and original launch ownership.
use std::io;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const ARGUMENT: &str = "--optimizer-reactivate";
const MAX_COMMAND_UNITS: usize = 32_766;

fn invalid() -> io::Error {
    // Never include original command text or caller-supplied tokens in errors.
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Invalid Optimizer helper bootstrap; no original application was launched.",
    )
}

pub fn is_requested() -> bool {
    std::env::args_os()
        .skip(1)
        .any(|argument| argument == ARGUMENT)
}

pub(crate) struct Bootstrap {
    lease: Uuid,
    original: Zeroizing<Vec<u16>>,
}

/// One captured invocation and one exchange, with no retry or fallback launch.
/// Even a completion-looking response cannot grant the helper local execution.
#[cfg(any(windows, test))]
fn handoff_refusal(
    bootstrap: &Bootstrap,
    capture: impl FnOnce(&[u16]) -> io::Result<crate::optimizer_protocol::OriginalContext>,
    exchange: impl FnOnce(
        Uuid,
        Uuid,
        crate::optimizer_protocol::OriginalContext,
    ) -> io::Result<crate::optimizer_protocol::ResponseEnvelope>,
) -> io::Error {
    let context = match capture(&bootstrap.original) {
        Ok(context) => context,
        Err(error) => {
            return io::Error::new(
                error.kind(),
                "Original helper context could not be captured; no original application was launched.",
            );
        }
    };
    if let Err(error) = exchange(bootstrap.lease, Uuid::new_v4(), context) {
        return io::Error::new(
            error.kind(),
            "Original invocation exchange failed; no local fallback was launched.",
        );
    }
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Native service launch ownership is not complete; no local fallback was launched.",
    )
}

/// Parse our canonical debugger prefix, not the destination application's argv.
/// Consume exactly the separator added after `--`, retaining all remaining
/// whitespace, quotes, backslashes and opaque UTF-16 without re-quoting.
pub(crate) fn parse(command: &[u16]) -> io::Result<Bootstrap> {
    if command.is_empty() || command.len() > MAX_COMMAND_UNITS || command.contains(&0) {
        return Err(invalid());
    }
    let end = if command[0] == b'"' as u16 {
        let close = command[1..]
            .iter()
            .position(|unit| *unit == b'"' as u16)
            .ok_or_else(invalid)?
            + 1;
        if close == 1 {
            return Err(invalid());
        }
        close + 1
    } else {
        let end = command
            .iter()
            .position(|unit| *unit == 32)
            .ok_or_else(invalid)?;
        if end == 0
            || command[..end]
                .iter()
                .any(|unit| *unit <= 32 || *unit == b'"' as u16)
        {
            return Err(invalid());
        }
        end
    };
    let prefix: Vec<u16> = format!(" {ARGUMENT} ").encode_utf16().collect();
    let at = end + prefix.len();
    if command.get(end..at) != Some(prefix.as_slice()) {
        return Err(invalid());
    }
    let identifier = command.get(at..at + 36).ok_or_else(invalid)?;
    if identifier.iter().any(|unit| *unit > 127) {
        return Err(invalid());
    }
    let text = String::from_utf16(identifier).map_err(|_| invalid())?;
    let lease = Uuid::parse_str(&text).map_err(|_| invalid())?;
    if lease.is_nil() || lease.hyphenated().to_string() != text {
        return Err(invalid());
    }
    let separator = [32, 45, 45, 32];
    if command.get(at + 36..at + 40) != Some(separator.as_slice()) {
        return Err(invalid());
    }
    let original = command
        .get(at + 40..)
        .filter(|tail| !tail.is_empty())
        .ok_or_else(invalid)?;
    Ok(Bootstrap {
        lease,
        original: Zeroizing::new(original.to_vec()),
    })
}

#[cfg(windows)]
pub(crate) fn debugger_prefix(path: &std::path::Path, lease: Uuid) -> io::Result<Vec<u16>> {
    use std::{
        os::windows::ffi::OsStrExt,
        path::{Component, Prefix},
    };
    if lease.is_nil()
        || !path.is_absolute()
        || !matches!(path.components().next(),Some(Component::Prefix(prefix)) if matches!(prefix.kind(),Prefix::Disk(_)|Prefix::VerbatimDisk(_)))
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(invalid());
    }
    let image: Vec<_> = path
        .as_os_str()
        .encode_wide()
        .take(MAX_COMMAND_UNITS)
        .collect();
    if image.is_empty() || image.contains(&0) || image.contains(&(b'"' as u16)) {
        return Err(invalid());
    }
    let mut prefix = vec![b'"' as u16];
    prefix.extend(image);
    prefix.extend(format!("\" {ARGUMENT} {} --", lease.hyphenated()).encode_utf16());
    // Leave room for the OS separator and at least one original command unit.
    if prefix.len() + 2 > MAX_COMMAND_UNITS {
        return Err(invalid());
    }
    Ok(prefix)
}

/// A Ready broker may receive the retained context through the authenticated
/// helper path. No response authorizes a local fallback launch; complete native
/// service launch/effect ownership is still required before success is offered.
pub fn run_current() -> io::Result<()> {
    #[cfg(windows)]
    {
        use crate::optimizer_protocol::{Readiness, ServiceResponse};
        use std::{
            sync::atomic::AtomicBool,
            time::{Duration, Instant},
        };
        use windows::Win32::System::Environment::GetCommandLineW;
        let pointer = unsafe { GetCommandLineW() };
        if pointer.is_null() {
            return Err(invalid());
        }
        let mut raw = Zeroizing::new(Vec::new());
        let mut terminated = false;
        for at in 0..=MAX_COMMAND_UNITS {
            let unit = unsafe { pointer.0.add(at).read() };
            if unit == 0 {
                terminated = true;
                break;
            }
            raw.push(unit);
        }
        if !terminated {
            return Err(invalid());
        }
        let bootstrap = parse(&raw)?;
        let cancel = AtomicBool::new(false);
        let response = crate::optimizer_service::query_current_session(
            Instant::now() + Duration::from_secs(3),
            &cancel,
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                "Optimizer broker is unavailable; no original application was launched.",
            )
        })?;
        let message = match response.response {
            ServiceResponse::Readiness {
                state: Readiness::RecoveryRequired,
                ..
            } => "Optimizer recovery is required; no original application was launched.",
            ServiceResponse::Readiness {
                state: Readiness::Ready,
                ..
            } => {
                use std::os::windows::ffi::OsStringExt;
                let principal = crate::optimizer_pipe_security::Principal::current()?;
                return Err(handoff_refusal(
                    &bootstrap,
                    |command| {
                        crate::optimizer_launch_job::creation::capture::current_helper_context(
                            &principal,
                            &std::ffi::OsString::from_wide(command),
                            &cancel,
                        )
                    },
                    |lease, invocation, context| {
                        crate::optimizer_service::reactivate_current_session(
                            lease,
                            invocation,
                            context,
                            Instant::now() + Duration::from_secs(5),
                            &cancel,
                        )
                    },
                ));
            }
            _ => "Optimizer helper is not ready; no original application was launched.",
        };
        Err(io::Error::new(io::ErrorKind::Unsupported, message))
    }
    #[cfg(not(windows))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "The Optimizer helper requires Windows; no original application was launched.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_handoff_captures_once_and_never_grants_retry_fallback_or_success() {
        use crate::optimizer_protocol::{
            InvocationState, OriginalContext, Refusal, ResponseEnvelope, ServiceResponse,
        };
        use std::cell::Cell;
        let mut tail: Vec<u16> = "\"C:\\Fixture\\original.exe\"  --quoted \"a b\" "
            .encode_utf16()
            .collect();
        tail.push(0xd800);
        let bootstrap = parse(&command(&tail)).unwrap();
        for case in 0..4 {
            let captures = Cell::new(0);
            let exchanges = Cell::new(0);
            let error = handoff_refusal(
                &bootstrap,
                |raw| {
                    captures.set(captures.get() + 1);
                    assert_eq!(raw, tail);
                    if case == 0 {
                        return Err(io::Error::other("PRIVATE CAPTURE DETAIL"));
                    }
                    Ok(OriginalContext::new(
                        raw.to_vec(),
                        "C:\\Fixture".encode_utf16().collect(),
                        vec![0, 0],
                        None,
                    )
                    .unwrap())
                },
                |lease, invocation, original| {
                    exchanges.set(exchanges.get() + 1);
                    assert_eq!(lease, bootstrap.lease);
                    assert!(!invocation.is_nil());
                    assert_eq!(original.command(), tail);
                    if case == 1 {
                        return Err(io::Error::other("PRIVATE EXCHANGE DETAIL"));
                    }
                    Ok(ResponseEnvelope {
                        request_id: Uuid::new_v4(),
                        response: if case == 2 {
                            ServiceResponse::Refused {
                                reason: Refusal::ServiceNotReady,
                            }
                        } else {
                            ServiceResponse::Invocation {
                                invocation_id: invocation,
                                state: InvocationState::VerifiedReenabled,
                            }
                        },
                    })
                },
            );
            assert_eq!(captures.get(), 1);
            assert_eq!(exchanges.get(), usize::from(case != 0));
            assert!(!error.to_string().contains("PRIVATE"));
            assert!(!error.to_string().contains("Fixture"));
            if case >= 2 {
                assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            }
        }
    }
    const LEASE: &str = "d24319c9-52b3-45c5-8459-a72938818404";
    fn command(tail: &[u16]) -> Vec<u16> {
        let mut raw: Vec<_> =
            format!("\"C:\\Program Files\\DCleaner\\DCleaner.exe\" {ARGUMENT} {LEASE} -- ")
                .encode_utf16()
                .collect();
        raw.extend_from_slice(tail);
        raw
    }
    #[test]
    fn bootstrap_retains_original_utf16_whitespace_quoting_and_unpaired_units() {
        let mut tail: Vec<_> =
            " \t\"C:\\Fixture\\original app.exe\" --name=\"a \\\"quote\\\"\"  \t"
                .encode_utf16()
                .collect();
        tail.push(0xd800);
        let parsed = parse(&command(&tail)).unwrap();
        assert_eq!(parsed.lease, Uuid::parse_str(LEASE).unwrap());
        assert_eq!(&*parsed.original, &tail);
        let raw = format!("C:\\DCleaner.exe {ARGUMENT} {LEASE} -- original")
            .encode_utf16()
            .collect::<Vec<_>>();
        assert!(parse(&raw).is_ok());
    }
    #[test]
    fn malformed_bootstrap_never_reinterprets_or_echoes_original_tokens() {
        for raw in [
            String::new(),
            format!("\"\" {ARGUMENT} {LEASE} -- secret-original"),
            format!(
                "\"C:\\DCleaner.exe\" {ARGUMENT} {} -- secret-original",
                Uuid::nil()
            ),
            format!(
                "\"C:\\DCleaner.exe\" {ARGUMENT} {} -- secret-original",
                LEASE.to_uppercase()
            ),
            format!("\"C:\\DCleaner.exe\" {ARGUMENT} \"{LEASE}\" -- secret-original"),
            format!("\"C:\\DCleaner.exe\" {ARGUMENT} {LEASE} secret-original"),
            format!("\"C:\\DCleaner.exe\" {ARGUMENT} {LEASE} -- "),
            format!("\"C:\\DCleaner.exe\" extra {ARGUMENT} {LEASE} -- secret-original"),
        ] {
            let error = parse(&raw.encode_utf16().collect::<Vec<_>>())
                .err()
                .expect("noncanonical bootstrap must refuse");
            assert!(!error.to_string().contains("secret-original"));
        }
    }
    #[test]
    fn bootstrap_bounds_complete_native_command_and_refuses_embedded_terminators() {
        let prefix = command(&[]).len();
        let maximum = command(&vec![65; MAX_COMMAND_UNITS - prefix]);
        assert_eq!(maximum.len(), MAX_COMMAND_UNITS);
        assert!(parse(&maximum).is_ok());
        let mut too_long = maximum;
        too_long.push(65);
        assert!(parse(&too_long).is_err());
        assert!(parse(&command(&[65, 0, 66])).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn prefix_generator_rejects_ambiguous_paths_and_round_trips_canonical_data() {
        use std::path::Path;
        let lease = Uuid::parse_str(LEASE).unwrap();
        for path in [
            r"relative.exe",
            r"C:relative.exe",
            r"\\server\helper.exe",
            r"\\.\pipe\helper",
            r"C:\Fixture\..\helper.exe",
            "C:\\Fixture\\bad\"helper.exe",
            "C:\\Fixture\\bad\0helper.exe",
        ] {
            assert!(debugger_prefix(Path::new(path), lease).is_err());
        }
        assert!(debugger_prefix(Path::new(r"C:\Fixture\helper.exe"), Uuid::nil()).is_err());
        let mut raw =
            debugger_prefix(Path::new(r"C:\Program Files\DCleaner\DCleaner.exe"), lease).unwrap();
        raw.push(32);
        raw.extend("original command".encode_utf16());
        let parsed = parse(&raw).unwrap();
        assert_eq!(parsed.lease, lease);
        assert_eq!(
            &*parsed.original,
            &"original command".encode_utf16().collect::<Vec<_>>()
        );
    }
}
