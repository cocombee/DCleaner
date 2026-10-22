//! Two synthetic hook owners share an actual disposable native image root.
mod launch_handoff;
use super::*;
use crate::optimizer_resources::Target;

struct Flow {
    reg: Fixture,
    catalog: Catalog,
    journal: Journal,
    _dir: tempfile::TempDir,
    caller: Caller,
    members: [Member; 2],
    root_id: ResourceId,
    instance: Uuid,
    original: Option<u32>,
    resource_failure: Arc<AtomicBool>,
}
impl Flow {
    fn new(original: Option<u32>) -> Self {
        Self::for_caller(original, Caller::fixture("S-1-5-21-1-2-3-1001", 1))
    }
    fn for_caller(original: Option<u32>, caller: Caller) -> Self {
        let reg = Fixture::new();
        if let Some(value) = original {
            let root = reg.create("shared.exe");
            assert_eq!(write(&root, Name::UseFilter, &dword(value)), ERROR_SUCCESS);
        }
        let dir = tempfile::tempdir().unwrap();
        let resource_connection = Connection::open(dir.path().join("resources.db")).unwrap();
        let resource_failure = fail_commits(&resource_connection);
        let catalog = Catalog::open(resource_connection).unwrap();
        let journal =
            Journal::open(Connection::open(dir.path().join("intents.db")).unwrap()).unwrap();
        let members = [
            Member::for_caller(&caller, "program:v1:hkcu:64:61").unwrap(),
            Member::for_caller(&caller, "program:v1:hkcu:64:62").unwrap(),
        ];
        let root_id = reg
            .scope()
            .slot_identity("shared.exe", Name::UseFilter)
            .unwrap();
        let mut value = Self {
            reg,
            catalog,
            journal,
            _dir: dir,
            caller,
            members,
            root_id,
            instance: Uuid::new_v4(),
            original,
            resource_failure,
        };
        let observation = value.observation(&value.root_id, "shared.exe", Name::UseFilter, None);
        let hooks = value
            .members
            .iter()
            .enumerate()
            .map(|(actor, member)| {
                (
                    value
                        .reg
                        .scope()
                        .slot_identity(&Self::path(actor), Name::Debugger)
                        .unwrap(),
                    member.clone(),
                )
            })
            .collect();
        // Synthetic complete ownership/association only for this unique HKCU
        // fixture, not evidence about an installed app or real IFEO ownership.
        unsafe {
            value.catalog.register_root_gate(
                observation,
                slot_state(true, Some(dword(1))).unwrap(),
                hooks,
            )
        }
        .unwrap();
        value
    }
    fn observation(
        &self,
        id: &ResourceId,
        path: &str,
        name: Name,
        actor: Option<usize>,
    ) -> Observation {
        let members =
            actor.map_or_else(|| self.members.to_vec(), |i| vec![self.members[i].clone()]);
        unsafe {
            Observation::from_native(
                id.clone(),
                self.instance,
                native_state(&self.reg, path, name),
                members,
                true,
            )
        }
        .unwrap()
    }
    fn revision(&self, id: &ResourceId) -> Uuid {
        self.catalog.inspect(id).unwrap().unwrap().revision
    }
    fn path(actor: usize) -> String {
        format!("shared.exe\\owned{actor}")
    }
    fn mutate(
        &mut self,
        actor: usize,
        adding: bool,
        mode: u8,
    ) -> Result<Vec<Phase>, CompletionError> {
        let root_id = self.root_id.clone();
        self.catalog
            .request(
                &root_id,
                self.revision(&root_id),
                &self.caller,
                &self.members[actor],
                adding && mode != 10,
            )
            .unwrap();
        let root_observation = self.observation(&root_id, "shared.exe", Name::UseFilter, None);
        let root_claim = self
            .catalog
            .begin_root_gate(&root_id, self.revision(&root_id), root_observation)
            .unwrap();
        let needed = root_claim.target() == Target::Sleep;
        let root_present = self.reg.open("shared.exe").is_ok();
        let current = root_present
            .then(|| read_value(&self.reg.open("shared.exe").unwrap(), Name::UseFilter).unwrap())
            .flatten();
        let desired = if needed {
            Some(dword(1))
        } else {
            self.original.map(dword)
        };
        let root_kind = if !root_present {
            KeyKind::NewRoot
        } else if !needed && self.original.is_none() {
            KeyKind::RemoveKey
        } else {
            KeyKind::Guarded
        };
        let mut root_values = vec![change(Name::UseFilter, current, desired)];
        if root_kind == KeyKind::Guarded {
            root_values.push(change(Name::Debugger, None, None));
        }
        let root = KeyChange {
            path: "shared.exe".into(),
            kind: root_kind,
            values: root_values,
        };
        let path = if mode == 8 {
            "shared.exe\\unassociated".into()
        } else if mode == 9 {
            drop(self.reg.create("other.exe"));
            "other.exe\\owned".into()
        } else {
            Self::path(actor)
        };
        let leaf_values: Vec<_> = [Name::Debugger, Name::FilterFullPath]
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                let enabled = dword(2 + actor as u32 * 2 + index as u32);
                change(
                    name,
                    (!adding).then(|| enabled.clone()),
                    adding.then_some(enabled),
                )
            })
            .collect();
        let leaf = KeyChange {
            path: path.clone(),
            kind: if adding {
                KeyKind::NewLeaf
            } else {
                KeyKind::RemoveKey
            },
            values: leaf_values,
        };
        let mut claims = vec![root_claim];
        for value in &leaf.values {
            let id = self
                .reg
                .scope()
                .planned_value_identity(&path, leaf.kind, value.name)
                .unwrap();
            if adding {
                let observation = self.observation(&id, &path, value.name, Some(actor));
                self.catalog
                    .register(
                        observation,
                        slot_state(true, value.desired.clone()).unwrap(),
                    )
                    .unwrap();
            }
            self.catalog
                .request(
                    &id,
                    self.revision(&id),
                    &self.caller,
                    &self.members[actor],
                    adding,
                )
                .unwrap();
            let observation = self.observation(&id, &path, value.name, Some(actor));
            claims.push(
                self.catalog
                    .begin(&id, self.revision(&id), observation)
                    .unwrap()
                    .unwrap(),
            );
        }
        let keys = if root_kind == KeyKind::RemoveKey {
            vec![leaf, root]
        } else {
            vec![root, leaf]
        };
        let intent = Intent::from_owner(
            &self.caller,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            image(),
            RegistryView::Registry64,
            keys,
        )
        .unwrap();
        let binding = Completion::bind(self.reg.scope(), intent, claims)?;
        let receipt = commit(&mut self.journal, &binding, self.instance, mode, &self.reg);
        if mode == 7 {
            assert_eq!(
                write(
                    &self.reg.open("shared.exe").unwrap(),
                    Name::UseFilter,
                    &dword(7)
                ),
                ERROR_SUCCESS
            );
        }
        let mut observations = Vec::new();
        for key in binding.intent().keys() {
            for value in &key.values {
                if value.name == Name::Debugger && key.path == "shared.exe" {
                    continue;
                }
                let id = self
                    .reg
                    .scope()
                    .slot_identity(&key.path, value.name)
                    .unwrap();
                observations.push(self.observation(
                    &id,
                    &key.path,
                    value.name,
                    (key.path != "shared.exe").then_some(actor),
                ));
            }
        }
        self.resource_failure.store(mode == 6, Ordering::SeqCst);
        let result = binding.finish(&mut self.catalog, receipt, observations);
        self.resource_failure.store(false, Ordering::SeqCst);
        result
    }
    fn assert_root(&self, active: bool) {
        assert_eq!(
            native_state(&self.reg, "shared.exe", Name::UseFilter),
            slot_state(
                active || self.original.is_some(),
                if active {
                    Some(dword(1))
                } else {
                    self.original.map(dword)
                }
            )
            .unwrap()
        );
    }
}

#[test]
fn native_two_owned_hooks_keep_the_shared_gate_until_last_removal_and_preserve_original_namespace()
{
    require_txr!();
    for original in [None, Some(0), Some(1)] {
        let mut f = Flow::new(original);
        assert_eq!(f.mutate(0, true, 0).unwrap(), vec![Phase::Sleeping; 3]);
        f.assert_root(true);
        assert_eq!(f.mutate(1, true, 0).unwrap(), vec![Phase::Sleeping; 3]);
        f.assert_root(true);
        assert_eq!(
            f.mutate(0, false, 0).unwrap(),
            vec![Phase::Sleeping, Phase::Awake, Phase::Awake]
        );
        f.assert_root(true);
        assert!(matches!(
            f.reg.open(&Flow::path(0)),
            Err(Failure::Native(2))
        ));
        assert!(f.reg.open(&Flow::path(1)).is_ok());
        assert_eq!(f.mutate(1, false, 0).unwrap(), vec![Phase::Awake; 3]);
        f.assert_root(false);
        assert!(matches!(
            f.reg.open(&Flow::path(1)),
            Err(Failure::Native(2 | 3))
        ));
        // A later re-sleep still uses the first baseline and the same identities.
        assert_eq!(f.mutate(0, true, 0).unwrap(), vec![Phase::Sleeping; 3]);
        assert_eq!(f.mutate(0, false, 0).unwrap(), vec![Phase::Awake; 3]);
        f.assert_root(false);
        assert!(!f.catalog.requires_review(f.instance).unwrap());
    }
}

#[test]
fn native_cancelled_hook_group_retains_root_reservation_uncertainty_without_effect_replay() {
    require_txr!();
    let mut f = Flow::new(Some(1));
    assert_eq!(f.mutate(0, true, 1).unwrap(), vec![Phase::Uncertain; 3]);
    f.assert_root(false);
    assert!(matches!(
        f.reg.open(&Flow::path(0)),
        Err(Failure::Native(2))
    ));
    let state = f.observation(&f.root_id, "shared.exe", Name::UseFilter, None);
    assert!(
        f.catalog
            .begin_root_gate(&f.root_id, f.revision(&f.root_id), state)
            .is_err()
    );
    let state = f.observation(&f.root_id, "shared.exe", Name::UseFilter, None);
    assert!(matches!(
        f.catalog
            .reconcile(&f.root_id, f.revision(&f.root_id), state),
        Err(crate::optimizer_resources::Error::Incomplete)
    ));
    assert!(f.catalog.requires_review(f.instance).unwrap());
}

#[test]
fn native_root_group_catalog_commit_failure_keeps_every_reservation_changing() {
    require_txr!();
    let mut f = Flow::new(Some(1));
    assert!(matches!(
        f.mutate(0, true, 6),
        Err(CompletionError::Resources(_))
    ));
    assert_eq!(
        f.catalog.inspect(&f.root_id).unwrap().unwrap().phase,
        Phase::ChangingSleep
    );
    for name in [Name::Debugger, Name::FilterFullPath] {
        let id = f.reg.scope().value_identity(&Flow::path(0), name).unwrap();
        assert_eq!(
            f.catalog.inspect(&id).unwrap().unwrap().phase,
            Phase::ChangingSleep
        );
    }
    assert!(f.reg.open(&Flow::path(0)).is_ok());
    let state = f.observation(&f.root_id, "shared.exe", Name::UseFilter, None);
    assert!(matches!(
        f.catalog
            .begin_root_gate(&f.root_id, f.revision(&f.root_id), state),
        Err(crate::optimizer_resources::Error::Busy)
    ));
}

#[test]
fn native_late_foreign_root_change_makes_the_entire_hook_group_uncertain() {
    require_txr!();
    for original in [None, Some(1)] {
        let mut f = Flow::new(original);
        assert_eq!(f.mutate(0, true, 7).unwrap(), vec![Phase::Uncertain; 3]);
        assert_eq!(
            read_value(&f.reg.open("shared.exe").unwrap(), Name::UseFilter).unwrap(),
            Some(dword(7))
        );
        let state = f.observation(&f.root_id, "shared.exe", Name::UseFilter, None);
        assert!(
            f.catalog
                .begin_root_gate(&f.root_id, f.revision(&f.root_id), state)
                .is_err()
        );
    }
}

#[test]
fn native_completion_refuses_a_root_gate_role_on_a_debugger_or_filter_slot() {
    for child in [false, true] {
        let mut f = Flow::new(Some(0));
        let path = if child {
            "shared.exe\\wrong"
        } else {
            "shared.exe"
        };
        let kind = if child {
            KeyKind::NewLeaf
        } else {
            KeyKind::Existing
        };
        let id = f.reg.scope().slot_identity(path, Name::Debugger).unwrap();
        let observation = f.observation(&id, path, Name::Debugger, Some(0));
        let hook = f
            .reg
            .scope()
            .slot_identity("shared.exe\\candidate", Name::Debugger)
            .unwrap();
        // Deliberately false synthetic role proof: completion independently
        // rejects a root role bound to anything except image-root UseFilter.
        unsafe {
            f.catalog.register_root_gate(
                observation,
                slot_state(true, Some(dword(2))).unwrap(),
                vec![(hook, f.members[0].clone())],
            )
        }
        .unwrap();
        f.catalog
            .request(&id, f.revision(&id), &f.caller, &f.members[0], true)
            .unwrap();
        let observation = f.observation(&id, path, Name::Debugger, Some(0));
        let claim = f
            .catalog
            .begin_root_gate(&id, f.revision(&id), observation)
            .unwrap();
        let intent = Intent::from_owner(
            &f.caller,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            image(),
            RegistryView::Registry64,
            vec![KeyChange {
                path: path.into(),
                kind,
                values: vec![change(Name::Debugger, None, Some(dword(2)))],
            }],
        )
        .unwrap();
        assert!(matches!(
            Completion::bind(f.reg.scope(), intent, vec![claim]),
            Err(CompletionError::Invalid)
        ));
        assert_eq!(
            read_value(&f.reg.open("shared.exe").unwrap(), Name::UseFilter).unwrap(),
            Some(dword(0))
        );
        assert_eq!(
            read_value(&f.reg.open("shared.exe").unwrap(), Name::Debugger).unwrap(),
            None
        );
    }
}

#[test]
fn native_root_gate_cannot_authorize_an_unassociated_parent_hook_or_unrequested_install() {
    require_txr!();
    for mode in [8, 9, 10] {
        let mut f = Flow::new(Some(0));
        f.mutate(0, true, 0).unwrap();
        assert!(matches!(
            f.mutate(1, true, mode),
            Err(CompletionError::Invalid)
        ));
        f.assert_root(true);
        assert!(matches!(
            f.reg.open(&Flow::path(1)),
            Err(Failure::Native(2))
        ));
        assert!(matches!(
            f.reg.open("shared.exe\\unassociated"),
            Err(Failure::Native(2))
        ));
        assert!(f.reg.open(&Flow::path(0)).is_ok());
    }
}
