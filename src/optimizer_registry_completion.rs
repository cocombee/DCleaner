//! Exact value-slot reservation -> native intent receipt -> catalog completion.
//! This does not supply app association, shared-guard policy or helper authority.
#![allow(dead_code)]
use crate::{
    optimizer_intents::{
        Disposition, Intent, KeyKind, KeyState, Phase as IntentPhase, RawValue, RecordedAttempt,
    },
    optimizer_registry_tx::{Failure, Scope, Transaction},
    optimizer_resources::{
        Catalog, Claim, Error as ResourceError, Observation, Phase, ResourceId, Target,
    },
};
use serde::Serialize;
use std::{sync::atomic::AtomicBool, time::Instant};
use uuid::Uuid;

#[derive(Debug)]
pub(crate) enum Error {
    Invalid,
    Native(Failure),
    Resources(ResourceError),
}
impl From<Failure> for Error {
    fn from(e: Failure) -> Self {
        Self::Native(e)
    }
}
impl From<ResourceError> for Error {
    fn from(e: ResourceError) -> Self {
        Self::Resources(e)
    }
}

/// Canonical catalog bytes distinguish absent keys from existing empty slots.
/// Native association/state producers still have to independently prove them.
pub(crate) fn slot_state(key_present: bool, value: Option<RawValue>) -> Result<Vec<u8>, Error> {
    #[derive(Serialize)]
    struct State {
        version: u8,
        key_present: bool,
        value: Option<RawValue>,
    }
    if (!key_present && value.is_some()) || value.as_ref().is_some_and(|v| v.bytes.len() > 65536) {
        return Err(Error::Invalid);
    }
    serde_json::to_vec(&State {
        version: 1,
        key_present,
        value,
    })
    .map_err(|_| Error::Invalid)
}
struct Slot {
    claim: Claim,
    id: ResourceId,
    key_index: usize,
    value_index: usize,
}
/// Consumed live binding. Never persisted/deserialized or rebuilt from queries.
/// Claims already reserve bookkeeping; this type grants no native effect right.
pub(crate) struct Completion<'a> {
    scope: &'a Scope,
    intent: Intent,
    instance: Uuid,
    slots: Vec<Slot>,
}
impl<'a> Completion<'a> {
    pub(crate) fn bind(
        scope: &'a Scope,
        intent: Intent,
        claims: Vec<Claim>,
    ) -> Result<Self, Error> {
        if scope.view() != intent.view()
            || claims.is_empty()
            || claims.len() > 48
            || claims.len()
                < intent
                    .keys()
                    .iter()
                    .map(|k| k.values.iter().filter(|v| !k.kind.is_guard(v)).count())
                    .sum::<usize>()
        {
            return Err(Error::Invalid);
        }
        let instance = claims[0].instance();
        if claims.iter().any(|c| c.instance() != instance) {
            return Err(Error::Invalid);
        }
        let mut remaining = claims;
        let mut slots = Vec::new();
        for (key_index, key) in intent.keys().iter().enumerate() {
            for (value_index, value) in key.values.iter().enumerate() {
                let id = scope.planned_value_identity(&key.path, key.kind, value.name)?;
                let index = remaining.iter().position(|c| c.id() == &id);
                if key.kind.is_guard(value) && index.is_none() {
                    continue;
                }
                if slots.iter().any(|s: &Slot| s.id == id) {
                    return Err(Error::Invalid);
                }
                let index = index.ok_or(Error::Invalid)?;
                let claim = remaining.remove(index);
                let root_slot = value.name == crate::optimizer_intents::Name::UseFilter
                    && !key.path.contains('\\');
                if (claim.is_root_gate() && !root_slot)
                    || (key.kind.is_guard(value) && !claim.is_root_gate())
                {
                    return Err(Error::Invalid);
                }
                // IFEO key removal only restores an original absent namespace.
                // A preexisting key cannot be registered as "sleep by delete".
                if key.kind == KeyKind::RemoveKey && claim.target() != Target::Awake {
                    return Err(Error::Invalid);
                }
                if claim.expected()
                    != slot_state(key.kind.before_present(), value.expected.clone())?
                    || claim.desired()
                        != slot_state(key.kind.after_present(), value.desired.clone())?
                {
                    return Err(Error::Invalid);
                }
                slots.push(Slot {
                    claim,
                    id,
                    key_index,
                    value_index,
                });
            }
        }
        if !remaining.is_empty() {
            return Err(Error::Invalid);
        }
        let gates: Vec<_> = slots.iter().filter(|s| s.claim.is_root_gate()).collect();
        if !gates.is_empty() {
            let mut used = vec![false; gates.len()];
            for key in intent.keys() {
                let Some((parent, _)) = key.path.split_once('\\') else {
                    continue;
                };
                let parent_id =
                    scope.slot_identity(parent, crate::optimizer_intents::Name::UseFilter)?;
                let hook_id =
                    scope.slot_identity(&key.path, crate::optimizer_intents::Name::Debugger)?;
                let index = gates
                    .iter()
                    .position(|gate| gate.id == parent_id && gate.claim.covers_hook(&hook_id))
                    .ok_or(Error::Invalid)?;
                let debugger = key
                    .values
                    .iter()
                    .find(|v| v.name == crate::optimizer_intents::Name::Debugger)
                    .ok_or(Error::Invalid)?;
                let installing = key.kind != KeyKind::RemoveKey && debugger.desired.is_some();
                if !gates[index].claim.permits_hook(&hook_id, installing)
                    || (installing && gates[index].claim.target() != Target::Sleep)
                {
                    return Err(Error::Invalid);
                }
                used[index] = true;
            }
            // A root reservation protects a covered hook group, not unrelated
            // native work or a configuration-only success labelled as Sleep.
            if used.contains(&false) {
                return Err(Error::Invalid);
            }
        }
        Ok(Self {
            scope,
            intent,
            instance,
            slots,
        })
    }
    pub(crate) fn intent(&self) -> &Intent {
        &self.intent
    }
    /// Private KTM staging only. Public commit still requires the existing
    /// durable permit AND independently established native effect authority.
    pub(crate) fn stage<'run>(
        &'run self,
        deadline: Instant,
        cancel: &'run AtomicBool,
    ) -> Result<Transaction<'run>, Error> {
        let mut tx = Transaction::begin(self.scope, deadline, cancel)?;
        for key in self.intent.keys() {
            match key.kind {
                KeyKind::Existing => tx.stage_existing(&key.path, &key.values)?,
                KeyKind::Guarded => tx.stage_guarded(&key.path, &key.values)?,
                KeyKind::NewRoot => tx.stage_new_root(&key.path, &key.values)?,
                KeyKind::RemoveKey => tx.stage_remove_key(&key.path, &key.values)?,
                KeyKind::NewLeaf => {
                    let (parent, leaf) = key.path.split_once('\\').ok_or(Error::Invalid)?;
                    tx.stage_new_leaf(parent, leaf, &key.values)?;
                }
            }
        }
        Ok(tx)
    }
    /// Requires the sealed ticket from a successful journal COMMIT plus fresh
    /// independently authorized native roster/state observations. A saved phase
    /// enum or an IPC "success" message cannot enter this boundary.
    pub(crate) fn finish(
        self,
        catalog: &mut Catalog,
        recorded: RecordedAttempt,
        mut observations: Vec<Observation>,
    ) -> Result<Vec<Phase>, Error> {
        if !recorded.matches(&self.intent, self.instance) || observations.len() != self.slots.len()
        {
            return Err(Error::Invalid);
        }
        // Native observers may return any order. Match by the checked resource
        // identity, rejecting missing/duplicate evidence before any SQL update.
        let mut ordered = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            let index = observations
                .iter()
                .position(|o| o.id() == &slot.id)
                .ok_or(Error::Invalid)?;
            ordered.push(observations.remove(index));
        }
        let mut observations = ordered;
        let mut accepted = recorded.phase() == IntentPhase::ObservedDesired
            && recorded.observation().disposition == Disposition::Acknowledged
            && self.scope.guards_match(self.intent.keys()).unwrap_or(false);
        for (slot, observation) in self.slots.iter().zip(&observations) {
            let key = &self.intent.keys()[slot.key_index];
            accepted &= self
                .scope
                .slot_identity(&key.path, key.values[slot.value_index].name)
                .is_ok_and(|id| id == slot.id);
            let actual = recorded
                .observation()
                .keys
                .get(slot.key_index)
                .and_then(|k| match &k.key {
                    KeyState::Present { values, .. } => values
                        .get(slot.value_index)
                        .map(|v| (true, v.value.clone())),
                    KeyState::Missing => Some((false, None)),
                });
            accepted &= actual.is_some_and(|(present, value)| {
                slot_state(present, value).is_ok_and(|state| state == observation.actual())
            });
        }
        for observation in &mut observations {
            observation.constrain_completion(accepted);
        }
        Ok(catalog.finish_batch(
            self.slots
                .into_iter()
                .zip(observations)
                .map(|(s, o)| (s.claim, o))
                .collect(),
        )?)
    }
}
