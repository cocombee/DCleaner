//! Read-only native slot data; not a resource association or effect preflight.
use super::*;
use crate::{
    optimizer_registration::RegistryView,
    optimizer_registry_tx::{
        Scope,
        resource::{self, SlotSnapshot},
    },
};

pub(super) fn observe(
    selection: &Selection,
    exchange: &Exchange,
    stop: &AtomicBool,
) -> Result<Vec<SlotSnapshot>, Refusal> {
    exchange.check_budget(stop)?;
    let mut scopes = Vec::new();
    for view in [RegistryView::Registry64, RegistryView::Registry32] {
        exchange.check_budget(stop)?;
        // This factory requires LocalSystem and cannot open a write scope.
        // No caller-supplied hive, machine, key path or privilege retry exists.
        if let Ok(scope) = Scope::for_service_ifeo_readonly(view) {
            scopes.push(scope);
        }
    }
    exchange.check_budget(stop)?;
    if scopes.is_empty() {
        return Err(Refusal::ServiceNotReady);
    }
    let snapshots = resource::observe_resources(
        &selection.resources(),
        &scopes,
        exchange.deadline(),
        &exchange.endpoint_cancel,
    )
    .map_err(|_| Refusal::ServiceNotReady);
    exchange.check_budget(stop)?;
    snapshots
}
