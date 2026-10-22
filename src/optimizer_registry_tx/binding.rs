//! Native key-name/link/access binding for the fixed service scope.
use super::*;
use std::{ffi::c_void, os::windows::io::BorrowedHandle};
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, REG_LINK, REG_OPTION_OPEN_LINK};

pub(super) const READ_SECURITY: REG_SAM_FLAGS = REG_SAM_FLAGS(0x0002_0000);
const IFEO: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const MAX_NAME: usize = 65_540;
const MAX_FIXED_LINK_BYTES: usize = 2048;
#[repr(C)]
struct UnicodeString {
    length: u16,
    capacity: u16,
    buffer: *mut u16,
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryKey(
        key: HANDLE,
        class: i32,
        information: *mut c_void,
        length: u32,
        result: *mut u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
    fn RtlUpcaseUnicodeString(
        destination: *mut UnicodeString,
        source: *const UnicodeString,
        allocate: u8,
    ) -> i32;
}
pub(super) fn ordinal_identity(value: &str) -> Result<Vec<u16>, Failure> {
    let mut input: Vec<u16> = value.encode_utf16().collect();
    let bytes = input
        .len()
        .checked_mul(2)
        .filter(|v| *v <= u16::MAX as usize)
        .ok_or(Failure::Limited)?;
    let mut output = vec![0u16; input.len()];
    let source = UnicodeString {
        length: bytes as u16,
        capacity: bytes as u16,
        buffer: input.as_mut_ptr(),
    };
    let mut destination = UnicodeString {
        length: 0,
        capacity: bytes as u16,
        buffer: output.as_mut_ptr(),
    };
    let result = unsafe { RtlUpcaseUnicodeString(&mut destination, &source, 0) };
    if result < 0 {
        return Err(native_failure(result));
    }
    if destination.length as usize != bytes {
        return Err(Failure::Changed);
    }
    Ok(output)
}
fn native_failure(status: i32) -> Failure {
    Failure::Native(unsafe { RtlNtStatusToDosError(status) })
}
fn io_failure(error: std::io::Error) -> Failure {
    Failure::Native(error.raw_os_error().unwrap_or(5) as u32)
}

pub(super) fn native_name(key: &Key) -> Result<String, Failure> {
    let mut needed = 0;
    let code = unsafe { NtQueryKey(HANDLE(key.0.0), 3, std::ptr::null_mut(), 0, &mut needed) };
    if ![0x8000_0005u32 as i32, 0xc000_0023u32 as i32].contains(&code) {
        return Err(native_failure(code));
    }
    if !(6..=MAX_NAME as u32).contains(&needed) {
        return Err(Failure::Limited);
    }
    let capacity = needed as usize;
    let mut buffer = vec![0u32; capacity.div_ceil(4)];
    let code = unsafe {
        NtQueryKey(
            HANDLE(key.0.0),
            3,
            buffer.as_mut_ptr().cast(),
            capacity as u32,
            &mut needed,
        )
    };
    if code < 0 {
        return Err(native_failure(code));
    }
    if needed as usize > capacity || needed < 6 {
        return Err(Failure::Changed);
    }
    let bytes = buffer[0] as usize;
    if bytes == 0 || bytes % 2 != 0 || bytes + 4 > needed as usize {
        return Err(Failure::Changed);
    }
    let text =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().add(1).cast::<u16>(), bytes / 2) };
    let value = String::from_utf16(text).map_err(|_| Failure::Changed)?;
    if value.contains('\0') {
        return Err(Failure::Changed);
    }
    Ok(value)
}
fn no_link(key: &Key) -> Result<(), Failure> {
    let mut kind = windows::Win32::System::Registry::REG_VALUE_TYPE::default();
    let mut size = 0;
    let name = wide("SymbolicLinkValue");
    let result = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    if result != ERROR_SUCCESS && result != ERROR_MORE_DATA {
        return Err(Failure::Native(result.0));
    }
    if kind == REG_LINK {
        return Err(Failure::NotAuthorized);
    }
    Ok(())
}
fn link_target(key: &Key) -> Result<Option<Vec<u8>>, Failure> {
    let mut kind = REG_VALUE_TYPE::default();
    let mut size = 0;
    let name = wide("SymbolicLinkValue");
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    status(code)?;
    if kind != REG_LINK {
        return Ok(None);
    }
    if size == 0 || size % 2 != 0 || size as usize > MAX_FIXED_LINK_BYTES {
        return Err(Failure::Limited);
    }
    let mut bytes = vec![0u8; size as usize];
    let capacity = size;
    status(unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            Some(bytes.as_mut_ptr()),
            Some(&mut size),
        )
    })?;
    if kind != REG_LINK || size != capacity {
        return Err(Failure::Changed);
    }
    Ok(Some(bytes))
}
fn link_name(bytes: &[u8]) -> Result<String, Failure> {
    let words: Vec<_> = bytes
        .chunks_exact(2)
        .map(|w| u16::from_le_bytes([w[0], w[1]]))
        .collect();
    let name = String::from_utf16(&words).map_err(|_| Failure::Changed)?;
    // Registry link targets are counted native names, not nul-terminated text.
    if bytes.len() % 2 != 0 || name.is_empty() || name.contains('\0') {
        return Err(Failure::Changed);
    }
    Ok(name)
}
struct FixedAlias {
    key: Key,
    source: String,
    target: Vec<u8>,
}
impl FixedAlias {
    fn capture(key: Key, policy: &RegistryAccess, target: &str) -> Result<Self, Failure> {
        policy
            .verify(unsafe { BorrowedHandle::borrow_raw(key.0.0) })
            .map_err(io_failure)?;
        let bytes = link_target(&key)?.ok_or(Failure::NotAuthorized)?;
        if crate::optimizer_intents::same_registry_path(&link_name(&bytes)?, target) != Some(true) {
            return Err(Failure::NotAuthorized);
        }
        Ok(Self {
            source: native_name(&key)?,
            key,
            target: bytes,
        })
    }
    fn validate(&self, policy: &RegistryAccess) -> Result<(), Failure> {
        policy
            .verify(unsafe { BorrowedHandle::borrow_raw(self.key.0.0) })
            .map_err(io_failure)?;
        if crate::optimizer_intents::same_registry_path(&self.source, &native_name(&self.key)?)
            != Some(true)
            || link_target(&self.key)?.as_ref() != Some(&self.target)
        {
            return Err(Failure::Changed);
        }
        Ok(())
    }
}
pub(super) struct Binding {
    root: String,
    policy: RegistryAccess,
    writable: bool,
    fixed_alias: Option<FixedAlias>,
}
impl Binding {
    fn capture(key: &Key, policy: RegistryAccess, writable: bool) -> Result<Self, Failure> {
        no_link(key)?;
        policy
            .verify(unsafe { BorrowedHandle::borrow_raw(key.0.0) })
            .map_err(io_failure)?;
        Ok(Self {
            root: native_name(key)?,
            policy,
            writable,
            fixed_alias: None,
        })
    }
    #[cfg(test)]
    pub(super) fn fixture(key: &Key, writable: bool) -> Result<Self, Failure> {
        Self::capture(
            key,
            RegistryAccess::fixture().map_err(io_failure)?,
            writable,
        )
    }
    pub(super) fn root(&self) -> &str {
        &self.root
    }
    pub(super) fn can_write(&self) -> bool {
        self.writable
    }
    #[cfg(test)]
    pub(super) fn fixture_alias(&mut self, key: Key) -> Result<(), Failure> {
        self.fixed_alias = Some(FixedAlias::capture(key, &self.policy, &self.root)?);
        Ok(())
    }
    pub(super) fn validate_root(&self, key: &Key) -> Result<(), Failure> {
        if let Some(alias) = &self.fixed_alias {
            alias.validate(&self.policy)?;
        }
        no_link(key)?;
        self.policy
            .verify(unsafe { BorrowedHandle::borrow_raw(key.0.0) })
            .map_err(io_failure)?;
        if crate::optimizer_intents::same_registry_path(&self.root, &native_name(key)?)
            != Some(true)
        {
            return Err(Failure::Changed);
        }
        Ok(())
    }
    pub(super) fn validate_child(&self, key: &Key, path: &str) -> Result<(), Failure> {
        no_link(key)?;
        self.policy
            .verify(unsafe { BorrowedHandle::borrow_raw(key.0.0) })
            .map_err(io_failure)?;
        let expected = format!("{}\\{path}", self.root);
        if crate::optimizer_intents::same_registry_path(&expected, &native_name(key)?) != Some(true)
        {
            return Err(Failure::Changed);
        }
        Ok(())
    }
}

pub(super) fn open_fixed(view: RegistryView, writable: bool) -> Result<Scope, Failure> {
    let flags = match view {
        RegistryView::Registry32 => KEY_WOW64_32KEY,
        RegistryView::Registry64 => KEY_WOW64_64KEY,
    };
    let policy = RegistryAccess::machine().map_err(io_failure)?;
    let expected = format!(r"\REGISTRY\MACHINE\{IFEO}");
    let redirected = format!(
        r"\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\{}",
        IFEO.strip_prefix("SOFTWARE\\").ok_or(Failure::Changed)?
    );
    let parts: Vec<_> = IFEO.split('\u{5c}').collect();
    let mut parents: Vec<Key> = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        let parent = parents.last().map(|k| k.0).unwrap_or(HKEY_LOCAL_MACHINE);
        let rights = KEY_QUERY_VALUE
            | READ_SECURITY
            | flags
            | if writable && index + 1 == parts.len() {
                KEY_CREATE_SUB_KEY | KEY_SET_VALUE
            } else {
                REG_SAM_FLAGS(0)
            };
        let name = wide(part);
        let mut opened = HKEY::default();
        status(unsafe {
            RegOpenKeyExW(
                parent,
                PCWSTR(name.as_ptr()),
                Some(REG_OPTION_OPEN_LINK.0),
                rights,
                &mut opened,
            )
        })?;
        let key = Key(opened);
        // Only Windows' exact protected 32-bit IFEO alias may resolve once to
        // the fixed native root. Descendant/application links remain refused.
        if link_target(&key)?.is_some() {
            if view != RegistryView::Registry32
                || index + 1 != parts.len()
                || crate::optimizer_intents::same_registry_path(&native_name(&key)?, &redirected)
                    != Some(true)
            {
                return Err(Failure::NotAuthorized);
            }
            let alias = FixedAlias::capture(key, &policy, &expected)?;
            let mut scope = open_fixed(RegistryView::Registry64, writable)?;
            scope.binding.fixed_alias = Some(alias);
            scope.view_id = view;
            scope.binding.validate_root(&scope.key)?;
            return Ok(scope);
        }
        no_link(&key)?;
        let handle = unsafe { BorrowedHandle::borrow_raw(key.0.0) };
        if index + 1 == parts.len() {
            policy.verify(handle)
        } else {
            policy.verify_namespace(handle)
        }
        .map_err(io_failure)?;
        parents.push(key);
    }
    let key = parents.pop().ok_or(Failure::Changed)?;
    let binding = Binding::capture(&key, policy, writable)?;
    if ![expected, redirected].iter().any(|expected| {
        crate::optimizer_intents::same_registry_path(expected, binding.root()) == Some(true)
    }) {
        return Err(Failure::Changed);
    }
    Ok(Scope {
        key,
        view: flags,
        view_id: view,
        binding,
    })
}

pub(super) fn open_chain(
    scope: &Scope,
    path: &str,
    rights: REG_SAM_FLAGS,
    transaction: Option<HANDLE>,
) -> Result<Option<Key>, Failure> {
    if path.split('\u{5c}').count() > 2 || !path.split('\u{5c}').all(component) {
        return Err(Failure::InvalidPlan);
    }
    scope.binding.validate_root(&scope.key)?;
    let parts: Vec<_> = path.split('\u{5c}').collect();
    let mut opened: Vec<Key> = Vec::new();
    let mut relative = String::new();
    for (index, part) in parts.iter().enumerate() {
        if !relative.is_empty() {
            relative.push('\u{5c}');
        }
        relative.push_str(part);
        let parent = opened.last().map(|k| k.0).unwrap_or(scope.key.0);
        let access = KEY_QUERY_VALUE
            | READ_SECURITY
            | scope.view
            | if index + 1 == parts.len() {
                rights
            } else {
                REG_SAM_FLAGS(0)
            };
        let name = wide(part);
        let mut handle = HKEY::default();
        let result = unsafe {
            if let Some(tx) = transaction {
                RegOpenKeyTransactedW(
                    parent,
                    PCWSTR(name.as_ptr()),
                    Some(REG_OPTION_OPEN_LINK.0),
                    access,
                    &mut handle,
                    tx,
                    None,
                )
            } else {
                RegOpenKeyExW(
                    parent,
                    PCWSTR(name.as_ptr()),
                    Some(REG_OPTION_OPEN_LINK.0),
                    access,
                    &mut handle,
                )
            }
        };
        if [ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND].contains(&result) {
            return Ok(None);
        }
        status(result)?;
        let key = Key(handle);
        scope.binding.validate_child(&key, &relative)?;
        opened.push(key);
    }
    Ok(opened.pop())
}
pub(super) fn value_identity(
    key: &Key,
    name: Name,
) -> Result<crate::optimizer_resources::ResourceId, Failure> {
    value_identity_at(&native_name(key)?, name)
}
pub(super) fn value_identity_at(
    native: &str,
    name: Name,
) -> Result<crate::optimizer_resources::ResourceId, Failure> {
    let mut identity = Vec::new();
    for word in ordinal_identity(native)?
        .into_iter()
        .chain(Some(0))
        .chain(name.wide().into_iter())
    {
        identity.extend_from_slice(&word.to_le_bytes());
    }
    // Names come from a checked native key or a validated one-leaf slot below
    // its checked parent, including actual WOW64 backing. Fixed value names
    // have one spelling. A future slot is identity, never creation authority.
    unsafe { crate::optimizer_resources::ResourceId::from_native(1, &identity) }
        .map_err(|_| Failure::Limited)
}
