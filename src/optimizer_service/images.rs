//! Retained selected-image observations, never complete lease/effect authority.
use super::*;
use crate::{optimizer_identity::PinnedImage, optimizer_requests::ContextBinding};

pub(super) struct SelectedImages {
    selection: Selection,
    pins: Vec<PinnedImage>,
    context: ContextBinding,
    registry: Result<Vec<crate::optimizer_registry_tx::resource::SlotSnapshot>, Refusal>,
}
impl SelectedImages {
    pub(super) fn observe(
        exchange: &Exchange,
        selection: Selection,
        stop: &AtomicBool,
    ) -> Result<Self, Refusal> {
        exchange.check_budget(stop)?;
        let HelperRequest::Reactivate { original, .. } = &exchange.request.request().request else {
            return Err(Refusal::NotAuthorized);
        };
        let context = ContextBinding::observe(original).map_err(|_| Refusal::ServiceNotReady)?;
        let mut pins = Vec::new();
        for expected in selection.images() {
            exchange.check_budget(stop)?;
            // This endpoint's cancellation flag also survives logoff/retirement.
            // Native I/O can block; expiry is checked after each bounded read.
            let pin = PinnedImage::open(expected, &exchange.endpoint_cancel)
                .map_err(|_| Refusal::OwnershipChanged);
            exchange.check_budget(stop)?;
            pins.push(pin?);
        }
        exchange.check_budget(stop)?;
        let registry = super::registry::observe(&selection, exchange, stop);
        exchange.check_budget(stop)?;
        Ok(Self {
            selection,
            pins,
            context,
            registry,
        })
    }
    pub(super) fn matches(
        &self,
        selection: &Selection,
        original: &crate::optimizer_protocol::OriginalContext,
    ) -> Result<bool, Refusal> {
        // A retained leaf is not namespace, helper, hook or resource authority.
        let same = self.selection == *selection
            && self.pins.len() == selection.images().len()
            && self.context
                == ContextBinding::observe(original).map_err(|_| Refusal::ServiceNotReady)?;
        if !same {
            return Ok(false);
        }
        let ids = selection.resources();
        match &self.registry {
            Ok(slots) => Ok(slots.len() == ids.len()
                && slots.iter().zip(ids).all(|(slot, id)| slot.id() == &id)),
            Err(reason) => Err(*reason),
        }
    }
}

pub(super) fn start(
    exchange: Exchange,
    selection: Selection,
    requests: mpsc::SyncSender<Exchange>,
    stop: Arc<AtomicBool>,
) -> io::Result<JoinHandle<()>> {
    start_with(exchange, selection, requests, stop, SelectedImages::observe)
}
pub(super) fn start_with(
    mut exchange: Exchange,
    selection: Selection,
    requests: mpsc::SyncSender<Exchange>,
    stop: Arc<AtomicBool>,
    observe: impl FnOnce(&Exchange, Selection, &AtomicBool) -> Result<SelectedImages, Refusal>
    + Send
    + 'static,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("optimizer-images".into())
        .spawn(move || {
            exchange.inspection = Some(observe(&exchange, selection, &stop));
            // Return the same authenticated exchange/retained helper to the owner.
            // This bounded queue never turns an image observation into admission.
            if let Err(error) = requests.try_send(exchange) {
                let exchange = match error {
                    mpsc::TrySendError::Full(exchange)
                    | mpsc::TrySendError::Disconnected(exchange) => exchange,
                };
                let _ = exchange.reply.try_send(ResponseEnvelope {
                    request_id: exchange.request.request().request_id,
                    response: ServiceResponse::Refused {
                        reason: Refusal::ServiceNotReady,
                    },
                });
            }
        })
}
