//! Checked, read-only direct-level IFEO snapshots. Never ownership/lease proof.
//! Two equal complete passes are historical observations, not a lock or CAS.
use super::*;
use windows::{
    Win32::{
        Foundation::ERROR_NO_MORE_ITEMS,
        System::Registry::{KEY_ENUMERATE_SUB_KEYS, RegEnumKeyExW, RegEnumValueW},
    },
    core::PWSTR,
};

const MAX_CHILDREN: usize = 64;
const MAX_VALUES: usize = 128;
const MAX_TOTAL_VALUES: usize = 512;
const MAX_VALUE_NAME: usize = 16_383;

/// Raw counted names preserve even non-Unicode/unknown registry values. They
/// are observations, never commands or names accepted by the mutation API.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Value {
    pub(crate) name: Vec<u16>,
    pub(crate) raw: RawValue,
}
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Node {
    native_name: String,
    stamp: Stamp,
    values: Vec<Value>,
    selected: Vec<(Name, Option<RawValue>)>,
}
impl Node {
    pub(crate) fn native_name(&self) -> &str {
        &self.native_name
    }
    pub(crate) fn values(&self) -> &[Value] {
        &self.values
    }
    pub(crate) fn subkey_count(&self) -> u32 {
        self.stamp.subkeys
    }
    pub(crate) fn selected(&self, name: Name) -> Option<&RawValue> {
        self.selected
            .iter()
            .find(|(n, _)| *n == name)
            .and_then(|(_, v)| v.as_ref())
    }
}
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Child {
    pub(crate) name: String,
    pub(crate) node: Node,
}
#[derive(Debug, Eq, PartialEq)]
struct Data {
    root: Option<Node>,
    children: Vec<Child>,
}
/// Live scope-bound result; no Clone/Deserialize or conversion to an ownership
/// observation. Missing image keys and existing empty keys remain distinct.
pub(crate) struct Snapshot<'a> {
    scope: &'a Scope,
    image: String,
    data: Data,
}
impl Snapshot<'_> {
    pub(crate) fn root(&self) -> Option<&Node> {
        self.data.root.as_ref()
    }
    pub(crate) fn children(&self) -> &[Child] {
        &self.data.children
    }
    /// Nested child namespaces are reported, never recursively inspected or
    /// silently treated as an owned leaf/filter.
    pub(crate) fn is_flat(&self) -> bool {
        self.data.children.iter().all(|c| c.node.stamp.subkeys == 0)
    }
    pub(crate) fn root_id(&self) -> Result<crate::optimizer_resources::ResourceId, Failure> {
        let native = self
            .data
            .root
            .as_ref()
            .map(|r| r.native_name.clone())
            .unwrap_or_else(|| format!("{}\\{}", self.scope.native_identity(), self.image));
        binding::value_identity_at(&native, Name::UseFilter)
    }
    pub(crate) fn hook_id(
        &self,
        child: usize,
    ) -> Result<crate::optimizer_resources::ResourceId, Failure> {
        let node = &self
            .data
            .children
            .get(child)
            .ok_or(Failure::InvalidPlan)?
            .node;
        binding::value_identity_at(&node.native_name, Name::Debugger)
    }
    pub(crate) fn revalidate(
        &self,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<bool, Failure> {
        Ok(observe(self.scope, &self.image, deadline, cancel)?.data == self.data)
    }
}
pub(super) fn observe<'a>(
    scope: &'a Scope,
    image: &str,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Snapshot<'a>, Failure> {
    observe_with(scope, image, deadline, cancel, || {})
}
pub(super) fn observe_with<'a>(
    scope: &'a Scope,
    image: &str,
    deadline: Instant,
    cancel: &AtomicBool,
    between_passes: impl FnOnce(),
) -> Result<Snapshot<'a>, Failure> {
    if !component(image) || deadline.saturating_duration_since(Instant::now()) > MAX_DURATION {
        return Err(Failure::InvalidPlan);
    }
    checkpoint(cancel, deadline)?;
    let first = pass(scope, image, deadline, cancel)?;
    between_passes();
    checkpoint(cancel, deadline)?;
    let second = pass(scope, image, deadline, cancel)?;
    if first != second {
        return Err(Failure::Changed);
    }
    Ok(Snapshot {
        scope,
        image: image.into(),
        data: second,
    })
}
#[derive(Default)]
struct Budget {
    values: usize,
    bytes: usize,
}
fn pass(
    scope: &Scope,
    image: &str,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Data, Failure> {
    checkpoint(cancel, deadline)?;
    let Some(key) =
        binding::open_chain(scope, image, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, None)?
    else {
        scope.binding.validate_root(&scope.key)?;
        return Ok(Data {
            root: None,
            children: vec![],
        });
    };
    let mut budget = Budget::default();
    let root = node(&key, &mut budget, deadline, cancel)?;
    if root.stamp.subkeys as usize > MAX_CHILDREN {
        return Err(Failure::Limited);
    }
    let names = children(&key, deadline, cancel)?;
    if names.len() != root.stamp.subkeys as usize {
        return Err(Failure::Changed);
    }
    let mut records = Vec::with_capacity(names.len());
    for name in names {
        checkpoint(cancel, deadline)?;
        let path = format!("{image}\\{name}");
        let child =
            binding::open_chain(scope, &path, KEY_QUERY_VALUE, None)?.ok_or(Failure::Changed)?;
        let data = node(&child, &mut budget, deadline, cancel)?;
        scope.binding.validate_child(&child, &path)?;
        records.push(Child { name, node: data });
    }
    if stamp(&key)? != root.stamp {
        return Err(Failure::Changed);
    }
    scope.binding.validate_child(&key, image)?;
    scope.binding.validate_root(&scope.key)?;
    checkpoint(cancel, deadline)?;
    Ok(Data {
        root: Some(root),
        children: records,
    })
}
fn node(
    key: &Key,
    budget: &mut Budget,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Node, Failure> {
    let before = stamp(key)?;
    if before.values as usize > MAX_VALUES {
        return Err(Failure::Limited);
    }
    let mut values = Vec::new();
    let mut names = vec![0u16; MAX_VALUE_NAME + 1];
    let mut bytes = vec![0u8; MAX_BYTES];
    for index in 0..=MAX_VALUES {
        checkpoint(cancel, deadline)?;
        let mut name_len = names.len() as u32;
        let mut data_len = bytes.len() as u32;
        let mut kind = 0u32;
        let code = unsafe {
            RegEnumValueW(
                key.0,
                index as u32,
                Some(PWSTR(names.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&mut kind),
                Some(bytes.as_mut_ptr()),
                Some(&mut data_len),
            )
        };
        if code == ERROR_NO_MORE_ITEMS {
            break;
        }
        if code == ERROR_MORE_DATA {
            return Err(Failure::Limited);
        }
        status(code)?;
        if index == MAX_VALUES
            || name_len as usize > MAX_VALUE_NAME
            || data_len as usize > MAX_BYTES
        {
            return Err(Failure::Limited);
        }
        budget.values += 1;
        budget.bytes += name_len as usize * 2 + data_len as usize;
        if budget.values > MAX_TOTAL_VALUES || budget.bytes > MAX_STAGED_BYTES {
            return Err(Failure::Limited);
        }
        values.push(Value {
            name: names[..name_len as usize].to_vec(),
            raw: RawValue {
                kind,
                bytes: bytes[..data_len as usize].to_vec(),
            },
        });
    }
    values.sort_by(|a, b| a.name.cmp(&b.name));
    if values.len() != before.values as usize || values.windows(2).any(|w| w[0].name == w[1].name) {
        return Err(Failure::Changed);
    }
    let mut selected = Vec::new();
    for name in [Name::UseFilter, Name::Debugger, Name::FilterFullPath] {
        checkpoint(cancel, deadline)?;
        selected.push((name, read_value(key, name)?));
    }
    if stamp(key)? != before {
        return Err(Failure::Changed);
    }
    Ok(Node {
        native_name: binding::native_name(key)?,
        stamp: before,
        values,
        selected,
    })
}
fn children(key: &Key, deadline: Instant, cancel: &AtomicBool) -> Result<Vec<String>, Failure> {
    let mut records = Vec::new();
    let mut name = [0u16; 256];
    for index in 0..=MAX_CHILDREN {
        checkpoint(cancel, deadline)?;
        let mut length = name.len() as u32;
        let code = unsafe {
            RegEnumKeyExW(
                key.0,
                index as u32,
                Some(PWSTR(name.as_mut_ptr())),
                &mut length,
                None,
                None,
                None,
                None,
            )
        };
        if code == ERROR_NO_MORE_ITEMS {
            break;
        }
        if code == ERROR_MORE_DATA {
            return Err(Failure::Limited);
        }
        status(code)?;
        if index == MAX_CHILDREN || length as usize >= name.len() {
            return Err(Failure::Limited);
        }
        let value =
            String::from_utf16(&name[..length as usize]).map_err(|_| Failure::NotAuthorized)?;
        if !component(&value) {
            return Err(Failure::NotAuthorized);
        }
        records.push(value);
    }
    records.sort();
    if records.windows(2).any(|w| w[0] == w[1]) {
        return Err(Failure::Changed);
    }
    Ok(records)
}
