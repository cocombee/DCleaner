//! One serial authenticated exchange at a time, retaining the first listener.
use super::*;
use crate::optimizer_pipe_io::PipeIo;
use crate::optimizer_pipe_security::helper_image::{HelperProcess, ProtectedHelper};
use std::{
    io::Read,
    os::windows::io::{AsHandle, OwnedHandle},
};

pub(super) struct Exchange {
    pub request: AuthenticatedRequest,
    pub reply: mpsc::SyncSender<ResponseEnvelope>,
    helper: Option<HelperProcess>,
    deadline: Instant,
    pub(super) endpoint_cancel: Arc<AtomicBool>,
    pub(super) inspection: Option<Result<super::images::SelectedImages, Refusal>>,
}
impl Exchange {
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }
    /// Budget only, never a substitute for native helper revalidation.
    pub(super) fn check_budget(&self, cancel: &AtomicBool) -> Result<(), Refusal> {
        if cancel.load(Ordering::Acquire)
            || self.endpoint_cancel.load(Ordering::Acquire)
            || Instant::now() >= self.deadline
        {
            Err(Refusal::ServiceNotReady)
        } else {
            Ok(())
        }
    }
    /// Connection/process evidence only, never complete lease/effect authority.
    /// The retained native handle survives the queue; a PID or earlier matching
    /// file observation cannot reconstruct it. No request is valid indefinitely
    /// merely because its frame entered the bounded owner queue.
    pub(super) fn revalidate(&self, cancel: &AtomicBool) -> Result<(), Refusal> {
        self.check_budget(cancel)?;
        if matches!(
            self.request.request().request,
            HelperRequest::Reactivate { .. }
        ) {
            self.helper
                .as_ref()
                .ok_or(Refusal::ServiceNotReady)?
                .revalidate(cancel)
                .map_err(|_| Refusal::OwnershipChanged)?;
        }
        // Native helper revalidation may block; expiry/cancellation cannot be
        // converted into current authority by a late successful observation.
        self.check_budget(cancel)
    }
}

pub(super) fn serve(
    policy: Policy,
    mut listener: OwnedHandle,
    cancel: Arc<AtomicBool>,
    requests: mpsc::SyncSender<Exchange>,
    helper: Option<Arc<ProtectedHelper>>,
) -> io::Result<()> {
    while !cancel.load(Ordering::Acquire) {
        let deadline = Instant::now() + Duration::from_secs(15);
        // This thread exclusively owns the listener and all its I/O. Each
        // operation drains before returning, including cancellation/error.
        let mut pipe = unsafe { PipeIo::from_overlapped_byte_pipe(listener, deadline, &cancel) };
        let result = exchange(
            &policy,
            &mut pipe,
            deadline,
            &requests,
            helper.as_ref(),
            &cancel,
        );
        // A poisoned exchange is never resumed. Native disconnect discards
        // unread bytes before a fresh exchange can use this same listener.
        listener = pipe.disconnect()?;
        if result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::NotConnected)
        {
            return result;
        }
    }
    Ok(())
}

fn exchange(
    policy: &Policy,
    pipe: &mut PipeIo<'_>,
    deadline: Instant,
    requests: &mpsc::SyncSender<Exchange>,
    helper: Option<&Arc<ProtectedHelper>>,
    cancel: &Arc<AtomicBool>,
) -> io::Result<()> {
    pipe.accept()?;
    let Some(request) = policy
        .read_authenticated_request(pipe)
        .map_err(io::Error::other)?
    else {
        return Ok(());
    };
    let id = request.request().request_id;
    let helper = if matches!(request.request().request, HelperRequest::Reactivate { .. }) {
        match helper {
            Some(helper) => match HelperProcess::observe(
                policy,
                &request,
                pipe.as_handle(),
                helper.clone(),
                cancel,
            ) {
                Ok(observed) => Some(observed),
                Err(_) => {
                    return finish_response(
                        pipe,
                        id,
                        ResponseEnvelope {
                            request_id: id,
                            response: ServiceResponse::Refused {
                                reason: Refusal::OwnershipChanged,
                            },
                        },
                    );
                }
            },
            None => None,
        }
    } else {
        None
    };
    pipe.check_active()?;
    let (reply, response) = mpsc::sync_channel(1);
    let response = match requests.try_send(Exchange {
        request,
        reply,
        helper,
        deadline,
        endpoint_cancel: cancel.clone(),
        inspection: None,
    }) {
        Ok(()) => loop {
            pipe.check_active()?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            match response.recv_timeout(remaining.min(Duration::from_millis(25))) {
                Ok(reply) => break reply,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "Service dispatch ended.",
                    ));
                }
            }
        },
        Err(mpsc::TrySendError::Full(_)) => ResponseEnvelope {
            request_id: id,
            response: ServiceResponse::Refused {
                reason: Refusal::ServiceNotReady,
            },
        },
        Err(mpsc::TrySendError::Disconnected(_)) => {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Service dispatch ended.",
            ));
        }
    };
    finish_response(pipe, id, response)
}

fn finish_response(pipe: &mut PipeIo<'_>, id: Uuid, response: ResponseEnvelope) -> io::Result<()> {
    if response.request_id != id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Service response correlation changed.",
        ));
    }
    pipe.check_active()?;
    codec::write_response(pipe, &response).map_err(io::Error::other)?;
    // Write completion is not peer receipt. Wait for this client's EOF within
    // the same deadline before disconnecting; never use blocking FlushFileBuffers.
    let mut extra = [0u8; 1];
    if pipe.read(&mut extra)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Only one request is allowed per connection.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
