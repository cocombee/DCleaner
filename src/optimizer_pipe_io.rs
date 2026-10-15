//! Internal byte I/O for a future authenticated Windows helper channel.
//!
//! No production endpoint is created here. A caller must establish local pipe
//! security and authenticate both peers before dispatching any request. This
//! module neither authenticates identifiers nor grants native effect authority.
//!
//! A single absolute deadline covers connect/read/write, including fragmented
//! frames. Cancellation requests the specific overlapped operation and drains
//! native completion before releasing its buffer, event or OVERLAPPED. Windows
//! can delay cancellation completion, so the drain is not a hard time bound.

// Intentionally internal and unconnected until the authenticated endpoint exists.
#![allow(dead_code)]

use std::{
    io::{self, Read, Write},
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, OwnedHandle},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use windows::{
    Win32::{
        Foundation::{
            ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE,
            WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Storage::FileSystem::{ReadFile, WriteFile},
        System::{
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
            Pipes::ConnectNamedPipe,
            Threading::{CreateEventW, WaitForSingleObject},
        },
    },
    core::PCWSTR,
};

const POLL_MS: u32 = 25;
const CHUNK_BYTES: usize = 8 * 1024;

fn native_error(error: windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error(error.code().0 as u32 as u16 as i32)
}

fn interrupted(cancel: &AtomicBool, deadline: Instant) -> io::Result<()> {
    if cancel.load(Ordering::Acquire) {
        // Read::read_exact and Write::write_all retry ErrorKind::Interrupted.
        // Cancellation must terminate the exchange rather than trigger retries.
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "Optimizer pipe exchange was cancelled.",
        ))
    } else if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Optimizer pipe exchange deadline elapsed.",
        ))
    } else {
        Ok(())
    }
}

/// Exactly one operation owns its event, native state and borrowed data buffer.
/// A box keeps OVERLAPPED's address stable even if this Rust value moves.
struct Operation {
    pipe: HANDLE,
    event: OwnedHandle,
    native: Box<OVERLAPPED>,
    pending: bool,
}

impl Operation {
    fn new(pipe: HANDLE) -> io::Result<Self> {
        use std::os::windows::io::FromRawHandle;
        // SAFETY: unnamed manual-reset event, with no inherited handle.
        let event =
            unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.map_err(native_error)?;
        // SAFETY: new owned handle; wrap it before the following allocation.
        let event = unsafe { OwnedHandle::from_raw_handle(event.0) };
        let native = Box::new(OVERLAPPED {
            hEvent: HANDLE(event.as_raw_handle()),
            ..OVERLAPPED::default()
        });
        Ok(Self {
            pipe,
            event,
            native,
            pending: false,
        })
    }

    fn start(&mut self) -> *mut OVERLAPPED {
        self.pending = true;
        &mut *self.native
    }

    fn complete(
        &mut self,
        started: windows::core::Result<()>,
        connect: bool,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> io::Result<usize> {
        match started {
            Ok(()) => {
                if connect {
                    self.pending = false;
                    interrupted(cancel, deadline)?;
                    return Ok(0);
                }
                // Query OVERLAPPED even for immediate read/write completion.
                let count = self.transferred()?;
                interrupted(cancel, deadline)?;
                return Ok(count);
            }
            // A client may connect between CreateNamedPipe and ConnectNamedPipe.
            Err(error) if connect && error.code() == ERROR_PIPE_CONNECTED.to_hresult() => {
                self.pending = false;
                interrupted(cancel, deadline)?;
                return Ok(0);
            }
            Err(error) if error.code() == ERROR_IO_PENDING.to_hresult() => {}
            Err(error) => {
                self.pending = false;
                return Err(native_error(error));
            }
        }
        loop {
            interrupted(cancel, deadline)?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            let wait_ms = remaining.as_millis().clamp(1, POLL_MS as u128) as u32;
            // SAFETY: this operation owns the event until terminal completion.
            match unsafe { WaitForSingleObject(HANDLE(self.event.as_raw_handle()), wait_ms) } {
                WAIT_OBJECT_0 => {
                    let count = self.transferred()?;
                    // A completion can race cancellation/deadline. Do not claim
                    // delivery after observing either, even if bytes moved.
                    interrupted(cancel, deadline)?;
                    return Ok(count);
                }
                WAIT_TIMEOUT => {}
                WAIT_FAILED => return Err(io::Error::last_os_error()),
                _ => return Err(io::Error::other("Unexpected pipe event wait result.")),
            }
        }
    }

    fn transferred(&mut self) -> io::Result<usize> {
        let mut transferred = 0;
        // SAFETY: native state and caller buffer remain live until completion.
        let result =
            unsafe { GetOverlappedResult(self.pipe, &*self.native, &mut transferred, false) };
        if let Err(error) = &result
            && error.code() == ERROR_IO_INCOMPLETE.to_hresult()
        {
            // An unexpected early event must still drain in Drop.
            return Err(io::Error::other("Pipe completion was still pending."));
        }
        self.pending = false;
        result.map(|()| transferred as usize).map_err(native_error)
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if self.pending {
            // SAFETY: pipe, event, native state and caller buffer are still live.
            // Cancellation may lose a completion race (ERROR_NOT_FOUND); drain
            // regardless. A successful write here is not reported as delivery.
            unsafe {
                let _ = CancelIoEx(self.pipe, Some(&*self.native));
                let mut ignored = 0;
                let _ = GetOverlappedResult(self.pipe, &*self.native, &mut ignored, true);
            }
        }
    }
}

/// Serial, owned byte-pipe adapter. Errors/EOF permanently end this exchange.
pub(crate) struct PipeIo<'a> {
    pipe: OwnedHandle,
    deadline: Instant,
    cancel: &'a AtomicBool,
    ended: bool,
}

impl AsHandle for PipeIo<'_> {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.pipe.as_handle()
    }
}

impl<'a> PipeIo<'a> {
    /// Protocol/authentication failures also end an exchange, even if the last
    /// native byte operation succeeded. The owner must then drop the endpoint.
    pub(crate) fn end_exchange(&mut self) {
        self.ended = true;
    }

    /// Checkpoints also cover native authentication between byte operations.
    /// Failure does not itself claim cancellation/completion of an owned task.
    pub(crate) fn check_active(&self) -> io::Result<()> {
        self.check()
    }

    /// # Safety
    /// `pipe` must be an exclusively operated local named-pipe handle opened
    /// with FILE_FLAG_OVERLAPPED, PIPE_WAIT and byte read/type modes. No other
    /// code may close, disconnect, change modes or issue I/O on that handle.
    /// This constructor performs no peer authentication or descriptor check.
    pub(crate) unsafe fn from_overlapped_byte_pipe(
        pipe: OwnedHandle,
        deadline: Instant,
        cancel: &'a AtomicBool,
    ) -> Self {
        Self {
            pipe,
            deadline,
            cancel,
            ended: false,
        }
    }

    fn check(&self) -> io::Result<()> {
        if self.ended {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Optimizer pipe exchange has ended.",
            ))
        } else {
            interrupted(self.cancel, self.deadline)
        }
    }

    fn finish(&mut self, outcome: io::Result<usize>) -> io::Result<usize> {
        if outcome.is_err() {
            self.ended = true;
        }
        outcome
    }

    /// Accept once. Client handles must not call this method.
    pub(crate) fn accept(&mut self) -> io::Result<()> {
        let outcome = (|| {
            self.check()?;
            let mut operation = Operation::new(HANDLE(self.pipe.as_raw_handle()))?;
            self.check()?;
            // SAFETY: exclusive overlapped byte pipe; operation drains on return.
            let started = unsafe { ConnectNamedPipe(operation.pipe, Some(operation.start())) };
            operation.complete(started, true, self.deadline, self.cancel)
        })();
        self.finish(outcome).map(|_| ())
    }
}

impl Read for PipeIo<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let outcome = (|| {
            self.check()?;
            let count = buffer.len().min(CHUNK_BYTES);
            let mut operation = Operation::new(HANDLE(self.pipe.as_raw_handle()))?;
            self.check()?;
            // SAFETY: the borrowed buffer stays alive through Operation's Drop,
            // including cancellation completion. No concurrent I/O is possible.
            let started = unsafe {
                ReadFile(
                    operation.pipe,
                    Some(&mut buffer[..count]),
                    None,
                    Some(operation.start()),
                )
            };
            operation.complete(started, false, self.deadline, self.cancel)
        })();
        match outcome {
            // Win32 can report a peer's zero-byte write as a successful read of
            // zero bytes. It is not disconnect/clean frame EOF. Reject no-progress
            // input instead of retrying indefinitely or accepting a false EOF.
            Ok(0) => self.finish(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Pipe peer supplied a zero-byte read without disconnecting.",
            ))),
            Err(error) if error.raw_os_error() == Some(ERROR_BROKEN_PIPE.0 as i32) => {
                self.ended = true;
                Ok(0)
            }
            other => self.finish(other),
        }
    }
}

impl Write for PipeIo<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let outcome = (|| {
            self.check()?;
            let count = buffer.len().min(CHUNK_BYTES);
            let mut operation = Operation::new(HANDLE(self.pipe.as_raw_handle()))?;
            self.check()?;
            // SAFETY: same buffer/native/event lifetime invariant as Read.
            let started = unsafe {
                WriteFile(
                    operation.pipe,
                    Some(&buffer[..count]),
                    None,
                    Some(operation.start()),
                )
            };
            operation.complete(started, false, self.deadline, self.cancel)
        })();
        let outcome = match outcome {
            Ok(0) if !buffer.is_empty() => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Pipe write made no progress.",
            )),
            other => other,
        };
        self.finish(outcome)
    }

    /// No userspace buffering. This does NOT call blocking FlushFileBuffers and
    /// does not acknowledge peer receipt, acceptance or native completion.
    fn flush(&mut self) -> io::Result<()> {
        let result = self.check().map(|_| 0);
        self.finish(result).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer_protocol::{
        self as codec, HelperRequest, Readiness, RequestEnvelope, ResponseEnvelope, ServiceResponse,
    };
    use std::{os::windows::io::FromRawHandle, thread, time::Duration};
    use uuid::Uuid;
    use windows::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_SHARE_MODE,
            OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
        },
        System::Pipes::{
            CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
            PIPE_WAIT,
        },
    };

    // Test-only random local endpoint: no named service, elevation, GUI or
    // filesystem mutation. Default fixture ACL is NOT a production auth policy.
    fn listener() -> (Vec<u16>, OwnedHandle) {
        let name = format!(r"\\.\pipe\DCleaner-fixture-{}", Uuid::new_v4());
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let pipe = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                100,
                None,
            )
        };
        assert!(!pipe.is_invalid(), "{}", io::Error::last_os_error());
        (name, unsafe { OwnedHandle::from_raw_handle(pipe.0) })
    }

    fn open(name: &[u16]) -> OwnedHandle {
        let handle = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            )
        }
        .unwrap();
        unsafe { OwnedHandle::from_raw_handle(handle.0) }
    }

    fn stream(handle: OwnedHandle, cancel: &AtomicBool, after: Duration) -> PipeIo<'_> {
        // SAFETY: fixture constructors open exclusively owned local byte pipes
        // in overlapped/wait mode. No raw handle is retained elsewhere.
        unsafe { PipeIo::from_overlapped_byte_pipe(handle, Instant::now() + after, cancel) }
    }

    #[test]
    fn fragmented_protocol_roundtrip_and_preconnected_accept() {
        let (name, server) = listener();
        let client = open(&name); // Deterministically exercises PIPE_CONNECTED.
        let cancel = AtomicBool::new(false);
        let mut server = stream(server, &cancel, Duration::from_secs(5));
        server.accept().unwrap();
        thread::scope(|scope| {
            scope.spawn(move || {
                let request = codec::read_request(&mut server).unwrap().unwrap();
                let response = ResponseEnvelope {
                    request_id: request.request_id,
                    response: ServiceResponse::Readiness {
                        service_instance: Uuid::new_v4(),
                        state: Readiness::Unavailable,
                    },
                };
                let mut bytes = Vec::new();
                codec::write_response(&mut bytes, &response).unwrap();
                for byte in bytes {
                    server.write_all(&[byte]).unwrap();
                }
                // Acknowledge receipt before the server drops its endpoint.
                let mut ack = [0];
                server.read_exact(&mut ack).unwrap();
                assert_eq!(ack, [1]);
            });
            let mut client = stream(client, &cancel, Duration::from_secs(5));
            let request = RequestEnvelope {
                request_id: Uuid::new_v4(),
                request: HelperRequest::QueryReadiness {},
            };
            codec::write_request(&mut client, &request).unwrap();
            let response = codec::read_response(&mut client, &request)
                .unwrap()
                .unwrap();
            assert!(matches!(
                response.response,
                ServiceResponse::Readiness { .. }
            ));
            client.write_all(&[1]).unwrap();
        });
    }

    #[test]
    fn pending_accept_times_out_and_ends_exchange() {
        let (_, handle) = listener();
        let cancel = AtomicBool::new(false);
        let mut server = stream(handle, &cancel, Duration::from_millis(40));
        assert_eq!(server.accept().unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            server.accept().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[test]
    fn pending_accept_completes_after_client_arrives() {
        let (name, handle) = listener();
        let cancel = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut operation = Operation::new(HANDLE(handle.as_raw_handle())).unwrap();
        let started = unsafe { ConnectNamedPipe(operation.pipe, Some(operation.start())) };
        assert_eq!(
            started.as_ref().unwrap_err().code(),
            ERROR_IO_PENDING.to_hresult()
        );
        let _client = open(&name);
        assert_eq!(
            operation
                .complete(started, true, deadline, &cancel)
                .unwrap(),
            0
        );
        assert!(!operation.pending);
    }

    #[test]
    fn completed_cancel_race_drains_before_buffer_reuse() {
        use windows::Win32::Foundation::ERROR_NOT_FOUND;
        let (name, handle) = listener();
        let client = open(&name);
        let cancel = AtomicBool::new(false);
        let mut server = stream(handle, &cancel, Duration::from_secs(5));
        server.accept().unwrap();
        let mut buffer = [0; 4];
        let mut operation = Operation::new(HANDLE(server.pipe.as_raw_handle())).unwrap();
        let started = unsafe {
            ReadFile(
                operation.pipe,
                Some(&mut buffer),
                None,
                Some(operation.start()),
            )
        };
        assert_eq!(started.unwrap_err().code(), ERROR_IO_PENDING.to_hresult());
        let mut client = stream(client, &cancel, Duration::from_secs(5));
        client.write_all(b"done").unwrap();
        assert_eq!(
            unsafe { WaitForSingleObject(HANDLE(operation.event.as_raw_handle()), 5000) },
            WAIT_OBJECT_0
        );
        // Completion won the cancellation race. Drop must still retrieve its
        // terminal result before Rust can access/reuse the borrowed buffer.
        let cancellation = unsafe { CancelIoEx(operation.pipe, Some(&*operation.native)) };
        assert_eq!(
            cancellation.unwrap_err().code(),
            ERROR_NOT_FOUND.to_hresult()
        );
        drop(operation);
        assert_eq!(buffer, *b"done");
        buffer.fill(0);
        assert_eq!(buffer, [0; 4]);
    }

    #[test]
    fn immediate_completion_after_cancel_or_deadline_is_not_success() {
        for cancelled in [false, true] {
            let (name, handle) = listener();
            let client = open(&name);
            let cancel = AtomicBool::new(false);
            let mut server = stream(handle, &cancel, Duration::from_secs(5));
            server.accept().unwrap();
            let mut client = stream(client, &cancel, Duration::from_secs(5));
            client.write_all(b"x").unwrap();
            let mut byte = [0];
            let mut operation = Operation::new(HANDLE(server.pipe.as_raw_handle())).unwrap();
            let started = unsafe {
                ReadFile(
                    operation.pipe,
                    Some(&mut byte),
                    None,
                    Some(operation.start()),
                )
            };
            assert!(started.is_ok(), "Queued byte must complete immediately.");
            cancel.store(cancelled, Ordering::Release);
            let deadline = if cancelled {
                Instant::now() + Duration::from_secs(5)
            } else {
                Instant::now()
            };
            let result = operation.complete(started, false, deadline, &cancel);
            assert_eq!(
                result.unwrap_err().kind(),
                if cancelled {
                    io::ErrorKind::ConnectionAborted
                } else {
                    io::ErrorKind::TimedOut
                }
            );
            assert!(!operation.pending);
            drop(operation);
            assert_eq!(byte, *b"x"); // Bytes moved, but success was not claimed.
        }
    }

    #[test]
    fn peer_zero_byte_write_is_not_a_clean_frame_disconnect() {
        let (name, handle) = listener();
        let client = open(&name);
        let cancel = AtomicBool::new(false);
        let mut server = stream(handle, &cancel, Duration::from_secs(5));
        server.accept().unwrap();
        let mut operation = Operation::new(HANDLE(client.as_raw_handle())).unwrap();
        let started =
            unsafe { WriteFile(operation.pipe, Some(&[]), None, Some(operation.start())) };
        assert_eq!(
            operation
                .complete(
                    started,
                    false,
                    Instant::now() + Duration::from_secs(5),
                    &cancel
                )
                .unwrap(),
            0
        );
        server.deadline = Instant::now() + Duration::from_millis(100);
        // Windows may expose the zero write or leave a byte-mode read pending.
        // Neither case can become the codec's clean-disconnect Ok(None).
        let error = codec::read_request(&mut server).unwrap_err();
        assert!(matches!(error, codec::ProtocolError::Io(ref io)
            if matches!(io.kind(), io::ErrorKind::InvalidData | io::ErrorKind::TimedOut)));
        assert!(server.ended);
    }

    #[test]
    fn pending_read_cancellation_drains_and_does_not_retry() {
        let (name, handle) = listener();
        let _client = open(&name);
        let cancel = AtomicBool::new(false);
        let mut server = stream(handle, &cancel, Duration::from_secs(5));
        server.accept().unwrap();
        thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(40));
                cancel.store(true, Ordering::Release);
            });
            let mut byte = [0];
            assert_eq!(
                server.read_exact(&mut byte).unwrap_err().kind(),
                io::ErrorKind::ConnectionAborted
            );
            assert_eq!(
                server.read(&mut byte).unwrap_err().kind(),
                io::ErrorKind::NotConnected
            );
        });
    }

    #[test]
    fn deadline_is_shared_across_multiple_reads() {
        let (name, handle) = listener();
        let client = open(&name);
        let cancel = AtomicBool::new(false);
        let mut server = stream(handle, &cancel, Duration::from_millis(200));
        server.accept().unwrap();
        let mut client = stream(client, &cancel, Duration::from_secs(5));
        client.write_all(b"a").unwrap();
        assert_eq!(server.read(&mut [0]).unwrap(), 1);
        thread::sleep(Duration::from_millis(220));
        // A later operation must not restart the exchange budget, even when
        // another byte is already available and would complete immediately.
        client.write_all(b"b").unwrap();
        assert_eq!(
            server.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            server.write(b"x").unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[test]
    fn blocked_write_times_out_without_claiming_delivery() {
        let (name, handle) = listener();
        let _client = open(&name); // Deliberately never consumes the output.
        let cancel = AtomicBool::new(false);
        let mut server = stream(handle, &cancel, Duration::from_millis(50));
        server.accept().unwrap();
        let bytes = vec![0; 8 * 1024 * 1024];
        assert_eq!(
            server.write_all(&bytes).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            server.flush().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[test]
    fn disconnect_is_eof_and_terminal() {
        let (name, handle) = listener();
        let client = open(&name);
        let cancel = AtomicBool::new(false);
        let mut server = stream(handle, &cancel, Duration::from_secs(5));
        server.accept().unwrap();
        drop(client);
        assert_eq!(server.read(&mut [0]).unwrap(), 0);
        assert_eq!(server.read(&mut []).unwrap(), 0);
        assert_eq!(server.write(&[]).unwrap(), 0);
        assert_eq!(
            server.write(b"x").unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[test]
    fn precancelled_and_expired_exchanges_do_not_start_connect() {
        for cancelled in [false, true] {
            let (_, handle) = listener();
            let cancel = AtomicBool::new(cancelled);
            let mut server = stream(handle, &cancel, Duration::ZERO);
            assert_eq!(
                server.accept().unwrap_err().kind(),
                if cancelled {
                    io::ErrorKind::ConnectionAborted
                } else {
                    io::ErrorKind::TimedOut
                }
            );
            assert!(server.ended);
        }
    }
}
