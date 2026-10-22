//! Scoped, read-only resolution of an IFEO value resource. No app association,
//! complete member roster, lock, creation permission or effect authority.
use super::*;
use crate::optimizer_resources::ResourceId;

#[derive(Eq, PartialEq)]
pub(crate) struct SlotSnapshot {
    id: ResourceId,
    path: String,
    name: Name,
    view: RegistryView,
    key_present: bool,
    value: Option<RawValue>,
}
impl SlotSnapshot {
    pub(crate) fn id(&self) -> &ResourceId {
        &self.id
    }
    pub(crate) fn path(&self) -> &str {
        &self.path
    }
    pub(crate) fn name(&self) -> Name {
        self.name
    }
    pub(crate) fn view(&self) -> RegistryView {
        self.view
    }
    pub(crate) fn catalog_state(&self) -> Result<Vec<u8>, Failure> {
        crate::optimizer_registry_completion::slot_state(self.key_present, self.value.clone())
            .map_err(|_| Failure::InvalidPlan)
    }
}

impl Scope {
    fn resolve_resource(&self, id: &ResourceId) -> Result<(String, Name), Failure> {
        let (kind, bytes) = id.native_parts().map_err(|_| Failure::InvalidPlan)?;
        if kind != 1 || bytes.len() % 2 != 0 {
            return Err(Failure::InvalidPlan);
        }
        let words: Vec<_> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let split = words
            .iter()
            .position(|word| *word == 0)
            .ok_or(Failure::InvalidPlan)?;
        let native = String::from_utf16(&words[..split]).map_err(|_| Failure::InvalidPlan)?;
        let name = [Name::Debugger, Name::FilterFullPath, Name::UseFilter]
            .into_iter()
            .find(|name| name.wide() == words[split + 1..])
            .ok_or(Failure::InvalidPlan)?;
        self.binding.validate_root(&self.key)?;
        let mut prefix = String::from_utf16(&binding::ordinal_identity(self.binding.root())?)
            .map_err(|_| Failure::Changed)?;
        prefix.push('\\');
        let path = native.strip_prefix(&prefix).ok_or(Failure::NotAuthorized)?;
        if path.split('\\').count() > 2 || !path.split('\\').all(component) {
            return Err(Failure::InvalidPlan);
        }
        // Require the exact canonical slot identity, including actual native
        // backing for shared registry views and the checked nearest ancestor.
        if self.slot_identity(path, name)? != *id {
            return Err(Failure::Changed);
        }
        Ok((path.into(), name))
    }

    fn resource_pass(
        &self,
        id: &ResourceId,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<SlotSnapshot, Failure> {
        resource_active(deadline, cancel)?;
        let (path, name) = self.resolve_resource(id)?;
        let key = observation_key(self, &path)?;
        let value = if let Some(key) = &key {
            let before = stamp(key)?;
            let value = read_value(key, name)?;
            self.binding.validate_child(key, &path)?;
            if stamp(key)? != before {
                return Err(Failure::Changed);
            }
            value
        } else {
            None
        };
        self.binding.validate_root(&self.key)?;
        if self.slot_identity(&path, name)? != *id
            || observation_key(self, &path)?.is_some() != key.is_some()
        {
            return Err(Failure::Changed);
        }
        resource_active(deadline, cancel)?;
        Ok(SlotSnapshot {
            id: id.clone(),
            path,
            name,
            view: self.view(),
            key_present: key.is_some(),
            value,
        })
    }

    /// Two agreeing bounded native reads, not an atomic snapshot. Native calls
    /// may block; budget checks do not promise a hard wall-clock bound.
    pub(crate) fn observe_resource(
        &self,
        id: &ResourceId,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<SlotSnapshot, Failure> {
        self.observe_resource_with(id, deadline, cancel, || {})
    }
    pub(super) fn observe_resource_with(
        &self,
        id: &ResourceId,
        deadline: Instant,
        cancel: &AtomicBool,
        between: impl FnOnce(),
    ) -> Result<SlotSnapshot, Failure> {
        resource_active(deadline, cancel)?;
        if deadline.saturating_duration_since(Instant::now()) > MAX_DURATION {
            return Err(Failure::Limited);
        }
        let first = self.resource_pass(id, deadline, cancel)?;
        between();
        let second = self.resource_pass(id, deadline, cancel)?;
        if first != second {
            return Err(Failure::Changed);
        }
        Ok(second)
    }
}

/// Resolve every selected registry slot, preserving input order. Unsupported,
/// missing or unreadable resources never produce a shortened successful set.
/// Agreement is native slot data only, never a complete app/member roster.
pub(crate) fn observe_resources(
    ids: &[ResourceId],
    scopes: &[Scope],
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Vec<SlotSnapshot>, Failure> {
    resource_active(deadline, cancel)?;
    if ids.is_empty() || ids.len() > 64 || scopes.is_empty() || scopes.len() > 2 {
        return Err(Failure::Limited);
    }
    let mut snapshots: Vec<SlotSnapshot> = Vec::new();
    for id in ids {
        resource_active(deadline, cancel)?;
        if snapshots.iter().any(|snapshot| snapshot.id() == id) {
            return Err(Failure::InvalidPlan);
        }
        let mut observed = None;
        let mut failure = Failure::NotAuthorized;
        for scope in scopes {
            match scope.observe_resource(id, deadline, cancel) {
                Ok(snapshot) => {
                    observed = Some(snapshot);
                    break;
                }
                Err(error @ (Failure::Cancelled | Failure::Deadline)) => return Err(error),
                Err(error) => failure = error,
            }
        }
        snapshots.push(observed.ok_or(failure)?);
    }
    resource_active(deadline, cancel)?;
    Ok(snapshots)
}

fn resource_active(deadline: Instant, cancel: &AtomicBool) -> Result<(), Failure> {
    if cancel.load(Ordering::Acquire) {
        return Err(Failure::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(Failure::Deadline);
    }
    Ok(())
}
