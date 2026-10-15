//! Internal KTM registry staging primitive, currently exercised only in HKCU fixtures.
//!
//! This is not lease authorization or an IFEO writer. A future protected owner
//! must validate scope/ownership/helper readiness, persist intent before commit,
//! then independently observe the post-state and sync a receipt. KTM and SQLite
//! are separate stores. Commit acknowledgement is not a durability or Sleep claim.
//! No fallback to ordinary writes, recursive deletion or privilege retry exists.

#![allow(dead_code)] // Production service/lease owner is not connected yet.

use crate::optimizer_registration::RegistryView;
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS, HANDLE, WIN32_ERROR},
        Globalization::{CSTR_EQUAL, CompareStringOrdinal},
        Storage::FileSystem::{CommitTransaction, CreateTransaction, RollbackTransaction},
        System::Registry::{
            HKEY, KEY_CREATE_SUB_KEY, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_32KEY,
            KEY_WOW64_64KEY, REG_CREATE_KEY_DISPOSITION, REG_CREATED_NEW_KEY,
            REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_VALUE_TYPE, RegCloseKey,
            RegCreateKeyTransactedW, RegDeleteValueW, RegOpenKeyExW, RegOpenKeyTransactedW,
            RegQueryValueExW, RegSetValueExW,
        },
    },
    core::PCWSTR,
};

const MAX_BYTES: usize = 64 * 1024;
const MAX_KEYS: usize = 16;
const MAX_STAGED_BYTES: usize = 1024 * 1024;
const MAX_DURATION: Duration = Duration::from_secs(30);

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Failure {
    InvalidPlan,
    Limited,
    Cancelled,
    Deadline,
    Ended,
    Changed,
    Native(u32),
    /// Commit was attempted: reconciliation is required, never automatic retry.
    CommitUncertain(i32),
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: uniquely owned non-predefined key, never escapes this module.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

/// A trusted, already opened local subtree. No production factory exists yet.
pub(crate) struct Scope {
    key: Key,
    view: REG_SAM_FLAGS,
}
impl Scope {
    /// # Safety
    /// Transfer exclusive ownership of a valid non-predefined, nontransacted
    /// local HKEY opened in exactly `view`. A transacted base would invalidate
    /// the public-read boundary. The
    /// future service owner must bind its actual hive/path/view to the durable
    /// intent and lease; a client-supplied path/handle is not authority. Do not
    /// construct from HKCU while impersonating or from any remote registry key.
    pub(crate) unsafe fn from_owned_key(key: HKEY, view: RegistryView) -> Self {
        Self {
            key: Key(key),
            view: match view {
                RegistryView::Registry32 => KEY_WOW64_32KEY,
                RegistryView::Registry64 => KEY_WOW64_64KEY,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Name {
    Debugger,
    FilterFullPath,
    UseFilter,
}
impl Name {
    fn wide(self) -> Vec<u16> {
        wide(match self {
            Self::Debugger => "Debugger",
            Self::FilterFullPath => "FilterFullPath",
            Self::UseFilter => "UseFilter",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawValue {
    pub(crate) kind: u32,
    pub(crate) bytes: Vec<u8>,
}
pub(crate) struct Change {
    pub(crate) name: Name,
    pub(crate) expected: Option<RawValue>,
    pub(crate) desired: Option<RawValue>,
}

/// Means only that CommitTransaction returned success. Always reobserve before
/// reporting a workflow result; this does not assert storage power-loss behavior.
#[derive(Debug)]
pub(crate) struct CommitAcknowledged;

pub(crate) struct Transaction<'a> {
    handle: OwnedHandle,
    scope: &'a Scope,
    cancel: &'a AtomicBool,
    deadline: Instant,
    ended: bool,
    paths: Vec<String>,
    bytes: usize,
}
impl<'a> Transaction<'a> {
    pub(crate) fn begin(
        scope: &'a Scope,
        deadline: Instant,
        cancel: &'a AtomicBool,
    ) -> Result<Self, Failure> {
        checkpoint(cancel, deadline)?;
        let duration = deadline.saturating_duration_since(Instant::now());
        if duration > MAX_DURATION {
            return Err(Failure::InvalidPlan);
        }
        // A nonzero KTM timeout is a backstop, not a hard syscall time bound.
        let timeout = duration.as_millis().clamp(1, 30_000) as u32;
        // SAFETY: default non-inheritable security, all reserved fields zero;
        // no distributed promotion or caller-provided native pointers.
        let handle = unsafe {
            CreateTransaction(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                0,
                0,
                timeout,
                PCWSTR::null(),
            )
        }
        .map_err(|e| Failure::Native(e.code().0 as u32))?;
        // SAFETY: new unique transaction handle, closed even on early failure.
        let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        let tx = Self {
            handle,
            scope,
            cancel,
            deadline,
            ended: false,
            paths: Vec::new(),
            bytes: 0,
        };
        tx.active()?;
        Ok(tx)
    }

    /// Stage exact selected raw changes on an existing relative key. No-op
    /// entries are rejected: a read alone is not a maintained commit-time
    /// precondition. Shared IFEO guards need their own reviewed owner strategy.
    pub(crate) fn stage_existing(&mut self, path: &str, changes: &[Change]) -> Result<(), Failure> {
        let result = (|| {
            self.validate_plan(path, changes)?;
            let key = self.open(path, KEY_QUERY_VALUE | KEY_SET_VALUE)?;
            let observed = self.open_public(path)?;
            self.stage_existing_values(&key, &observed, changes, || {})
        })();
        self.finish_stage(result)
    }

    /// Create exactly one new leaf below an existing one-component parent.
    /// Existing leaves are a conflict, including case aliases; no adoption.
    pub(crate) fn stage_new_leaf(
        &mut self,
        parent: &str,
        leaf: &str,
        changes: &[Change],
    ) -> Result<(), Failure> {
        let result = (|| {
            if changes.is_empty()
                || changes.len() > 3
                || !component(parent)
                || !component(leaf)
                || changes.iter().any(|c| c.expected.is_some())
            {
                return Err(Failure::InvalidPlan);
            }
            self.validate_plan(&format!("{parent}\\{leaf}"), changes)?;
            let parent = self.open(parent, KEY_CREATE_SUB_KEY)?;
            let leaf = wide(leaf);
            let mut key = HKEY::default();
            let mut disposition = REG_CREATE_KEY_DISPOSITION::default();
            // SAFETY: one validated leaf, live parent/transaction, bounded name;
            // no implicit ancestors, default inherited key security.
            status(unsafe {
                RegCreateKeyTransactedW(
                    parent.0,
                    PCWSTR(leaf.as_ptr()),
                    None,
                    PCWSTR::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_QUERY_VALUE | KEY_SET_VALUE | self.scope.view,
                    None,
                    &mut key,
                    Some(&mut disposition),
                    self.raw(),
                    None,
                )
            })?;
            let key = Key(key);
            if disposition != REG_CREATED_NEW_KEY {
                return Err(Failure::Changed);
            }
            self.write_values(&key, changes)
        })();
        self.finish_stage(result)
    }

    fn validate_plan(&mut self, path: &str, changes: &[Change]) -> Result<(), Failure> {
        self.active()?;
        if path.len() > 2 * 255 * 4 + 1
            || path.split('\\').count() > 2
            || !path.split('\\').all(component)
            || changes.is_empty()
            || changes.len() > 3
        {
            return Err(Failure::InvalidPlan);
        }
        for (i, change) in changes.iter().enumerate() {
            if change.expected == change.desired {
                return Err(Failure::InvalidPlan);
            }
            if changes[..i].iter().any(|c| c.name == change.name) {
                return Err(Failure::InvalidPlan);
            }
        }
        if self.paths.len() >= MAX_KEYS {
            return Err(Failure::Limited);
        }
        for seen in &self.paths {
            let a: Vec<u16> = path.encode_utf16().collect();
            let b: Vec<u16> = seen.encode_utf16().collect();
            // SAFETY: counted UTF-16 buffers; native ordinal registry-style
            // case comparison avoids lossy Unicode lowercase normalization.
            let comparison = unsafe { CompareStringOrdinal(&a, &b, true) };
            if comparison.0 == 0 {
                return Err(Failure::InvalidPlan);
            }
            if comparison == CSTR_EQUAL {
                return Err(Failure::InvalidPlan);
            }
        }
        let mut bytes = 0;
        for value in changes
            .iter()
            .flat_map(|c| [&c.expected, &c.desired])
            .flatten()
        {
            if value.bytes.len() > MAX_BYTES {
                return Err(Failure::Limited);
            }
            bytes += value.bytes.len();
        }
        if self.bytes + bytes > MAX_STAGED_BYTES {
            return Err(Failure::Limited);
        }
        self.bytes += bytes;
        self.paths.push(path.to_owned());
        Ok(())
    }

    fn open(&self, path: &str, rights: REG_SAM_FLAGS) -> Result<Key, Failure> {
        self.active()?;
        let path = wide(path);
        let mut key = HKEY::default();
        // SAFETY: nonempty validated relative path; every child is explicitly
        // opened in this transaction and the scope's selected registry view.
        status(unsafe {
            RegOpenKeyTransactedW(
                self.scope.key.0,
                PCWSTR(path.as_ptr()),
                None,
                rights | self.scope.view,
                &mut key,
                self.raw(),
                None,
            )
        })?;
        Ok(Key(key))
    }

    fn stage_existing_values(
        &self,
        key: &Key,
        observed: &Key,
        changes: &[Change],
        after_staging: impl FnOnce(),
    ) -> Result<(), Failure> {
        // TxR reads before the first write do NOT establish compare-and-set:
        // native race fixtures demonstrated a stale read can still commit.
        // Stage PRIVATE desired bytes first, then validate the still-public
        // pre-state. Ordinary writes after enlistment must invalidate commit;
        // post-state reconciliation remains required even after acknowledgement.
        self.write_values(key, changes)?;
        after_staging();
        for change in changes {
            self.active()?;
            if read_value(observed, change.name)? != change.expected {
                return Err(Failure::Changed);
            }
        }
        self.active()
    }

    fn write_values(&self, key: &Key, changes: &[Change]) -> Result<(), Failure> {
        for change in changes {
            self.active()?;
            let name = change.name.wide();
            // SAFETY: live transaction-bound key, nul-terminated fixed name,
            // bounded raw bytes. Native value types and bytes are preserved.
            match &change.desired {
                Some(value) => status(unsafe {
                    RegSetValueExW(
                        key.0,
                        PCWSTR(name.as_ptr()),
                        None,
                        REG_VALUE_TYPE(value.kind),
                        Some(&value.bytes),
                    )
                })?,
                None => status(unsafe { RegDeleteValueW(key.0, PCWSTR(name.as_ptr())) })?,
            }
        }
        self.active()
    }

    fn open_public(&self, path: &str) -> Result<Key, Failure> {
        self.active()?;
        let path = wide(path);
        let mut key = HKEY::default();
        // Read-only nontransacted view of this same validated local path/view.
        status(unsafe {
            RegOpenKeyExW(
                self.scope.key.0,
                PCWSTR(path.as_ptr()),
                None,
                KEY_QUERY_VALUE | self.scope.view,
                &mut key,
            )
        })?;
        Ok(Key(key))
    }

    fn finish_stage(&mut self, result: Result<(), Failure>) -> Result<(), Failure> {
        if result.is_err() {
            // Poison on any failed stage, including validation: no partial
            // batch may later be committed by a caller ignoring an error.
            self.ended = true;
            unsafe {
                let _ = RollbackTransaction(self.raw());
            }
        }
        result
    }
    fn raw(&self) -> HANDLE {
        HANDLE(self.handle.as_raw_handle())
    }
    fn active(&self) -> Result<(), Failure> {
        if self.ended {
            return Err(Failure::Ended);
        }
        checkpoint(self.cancel, self.deadline)
    }

    /// # Safety
    /// Caller must have durably recorded the exact intent and completed native
    /// lease/resource authorization and helper readiness checks. This primitive
    /// cannot prove those prerequisites. No production caller exists yet.
    pub(crate) unsafe fn commit_after_durable_intent(
        mut self,
    ) -> Result<CommitAcknowledged, Failure> {
        self.active()?;
        if self.paths.is_empty() {
            return Err(Failure::InvalidPlan);
        }
        // SAFETY: exclusively owned live transaction, all staged key handles
        // already closed. A failed commit has an uncertain external outcome.
        match unsafe { CommitTransaction(self.raw()) } {
            Ok(()) => {
                self.ended = true;
                Ok(CommitAcknowledged)
            }
            Err(error) => Err(Failure::CommitUncertain(error.code().0)),
        }
    }
}
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.ended {
            // SAFETY: uniquely owned transaction; best-effort rollback also on
            // unwind. Failure does not become an acknowledgement of success.
            unsafe {
                let _ = RollbackTransaction(self.raw());
            }
        }
    }
}

fn read_value(key: &Key, name: Name) -> Result<Option<RawValue>, Failure> {
    let name = name.wide();
    let mut kind = REG_VALUE_TYPE::default();
    let mut bytes = vec![0; MAX_BYTES];
    let mut size = bytes.len() as u32;
    // SAFETY: initialized bounded buffer with exact capacity; direct LSTATUS
    // is authoritative, not thread GetLastError. No size-query allocation race.
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            Some(bytes.as_mut_ptr()),
            Some(&mut size),
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if code == ERROR_MORE_DATA {
        return Err(Failure::Limited);
    }
    status(code)?;
    if size as usize > bytes.len() {
        return Err(Failure::Limited);
    }
    bytes.truncate(size as usize);
    Ok(Some(RawValue {
        kind: kind.0,
        bytes,
    }))
}
fn status(code: WIN32_ERROR) -> Result<(), Failure> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(Failure::Native(code.0))
    }
}
fn checkpoint(cancel: &AtomicBool, deadline: Instant) -> Result<(), Failure> {
    if cancel.load(Ordering::Acquire) {
        Err(Failure::Cancelled)
    } else if Instant::now() >= deadline {
        Err(Failure::Deadline)
    } else {
        Ok(())
    }
}
fn component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255 * 4
        && s != "."
        && s != ".."
        && s.encode_utf16().count() <= 255
        && !s.contains(['\\', '/', '\0'])
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::{
        Foundation::ERROR_TRANSACTIONAL_CONFLICT,
        System::Registry::{
            HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_BINARY, REG_DWORD, RegCreateKeyExW,
            RegDeleteTreeW, RegOpenKeyExW,
        },
    };

    /// Only tests construct scopes: unique HKCU fixture, never HKLM or IFEO.
    struct Fixture {
        scope: Option<Scope>,
        path: String,
    }
    impl Fixture {
        fn new() -> Self {
            Self::in_view(RegistryView::Registry64)
        }
        fn in_view(view: RegistryView) -> Self {
            let flags = match view {
                RegistryView::Registry32 => KEY_WOW64_32KEY,
                RegistryView::Registry64 => KEY_WOW64_64KEY,
            };
            let path = format!("Software\\DCleaner-TxR-Fixture-{}", uuid::Uuid::new_v4());
            let name = wide(&path);
            let mut key = HKEY::default();
            status(unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(name.as_ptr()),
                    None,
                    PCWSTR::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS | flags,
                    None,
                    &mut key,
                    None,
                )
            })
            .unwrap();
            Self {
                scope: Some(unsafe { Scope::from_owned_key(key, view) }),
                path,
            }
        }
        fn scope(&self) -> &Scope {
            self.scope.as_ref().unwrap()
        }
        fn create(&self, path: &str) -> Key {
            let name = wide(path);
            let mut key = HKEY::default();
            status(unsafe {
                RegCreateKeyExW(
                    self.scope().key.0,
                    PCWSTR(name.as_ptr()),
                    None,
                    PCWSTR::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS | self.scope().view,
                    None,
                    &mut key,
                    None,
                )
            })
            .unwrap();
            Key(key)
        }
        fn open(&self, path: &str) -> Result<Key, Failure> {
            let name = wide(path);
            let mut key = HKEY::default();
            status(unsafe {
                RegOpenKeyExW(
                    self.scope().key.0,
                    PCWSTR(name.as_ptr()),
                    None,
                    KEY_ALL_ACCESS | self.scope().view,
                    &mut key,
                )
            })?;
            Ok(Key(key))
        }
        fn tx<'a>(&'a self, cancel: &'a AtomicBool) -> Transaction<'a> {
            Transaction::begin(
                self.scope(),
                Instant::now() + Duration::from_secs(5),
                cancel,
            )
            .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(self.scope.take());
            // Exact random subtree created by this fixture; no computed global
            // roots, production keys or reusable user-supplied cleanup paths.
            assert!(self.path.starts_with("Software\\DCleaner-TxR-Fixture-"));
            let path = wide(&self.path);
            let result = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr())) };
            if !std::thread::panicking() {
                assert_eq!(result, ERROR_SUCCESS);
            }
        }
    }
    fn raw(kind: u32, bytes: &[u8]) -> RawValue {
        RawValue {
            kind,
            bytes: bytes.to_vec(),
        }
    }
    fn dword(n: u32) -> RawValue {
        raw(REG_DWORD.0, &n.to_le_bytes())
    }
    fn change(name: Name, expected: Option<RawValue>, desired: Option<RawValue>) -> Change {
        Change {
            name,
            expected,
            desired,
        }
    }
    fn write(key: &Key, name: Name, value: &RawValue) -> WIN32_ERROR {
        let name = name.wide();
        unsafe {
            RegSetValueExW(
                key.0,
                PCWSTR(name.as_ptr()),
                None,
                REG_VALUE_TYPE(value.kind),
                Some(&value.bytes),
            )
        }
    }
    // Fixture commits require no production lease/helper or durable journal:
    // all effects are disposable HKCU bytes owned by Fixture, never interception.
    fn commit_fixture(tx: Transaction<'_>) -> Result<CommitAcknowledged, Failure> {
        unsafe { tx.commit_after_durable_intent() }
    }

    #[test]
    fn committed_batch_preserves_raw_types_bytes_and_unselected_values() {
        let fixture = Fixture::new();
        let a = fixture.create("a.exe");
        let b = fixture.create("b.exe");
        let old = raw(REG_BINARY.0, &[0, 255, 0, 128]);
        assert_eq!(write(&a, Name::Debugger, &old), ERROR_SUCCESS);
        assert_eq!(write(&a, Name::FilterFullPath, &dword(91)), ERROR_SUCCESS);
        assert_eq!(write(&b, Name::UseFilter, &dword(1)), ERROR_SUCCESS);
        let cancel = AtomicBool::new(false);
        let mut tx = fixture.tx(&cancel);
        tx.stage_existing(
            "a.exe",
            &[change(
                Name::Debugger,
                Some(old),
                Some(raw(REG_BINARY.0, &[])),
            )],
        )
        .unwrap();
        tx.stage_existing("b.exe", &[change(Name::UseFilter, Some(dword(1)), None)])
            .unwrap();
        // Uncommitted changes are not visible through ordinary fixture handles.
        assert_eq!(read_value(&b, Name::UseFilter).unwrap(), Some(dword(1)));
        commit_fixture(tx).unwrap();
        assert_eq!(
            read_value(&a, Name::Debugger).unwrap(),
            Some(raw(REG_BINARY.0, &[]))
        );
        assert_eq!(
            read_value(&a, Name::FilterFullPath).unwrap(),
            Some(dword(91))
        );
        assert_eq!(read_value(&b, Name::UseFilter).unwrap(), None);
    }

    #[test]
    fn drop_and_unwind_roll_back_staged_values() {
        let fixture = Fixture::new();
        let a = fixture.create("a.exe");
        let cancel = AtomicBool::new(false);
        {
            let mut tx = fixture.tx(&cancel);
            tx.stage_existing("a.exe", &[change(Name::UseFilter, None, Some(dword(1)))])
                .unwrap();
        }
        assert_eq!(read_value(&a, Name::UseFilter).unwrap(), None);
        let panic = std::panic::catch_unwind(|| {
            let mut tx = fixture.tx(&cancel);
            tx.stage_existing("a.exe", &[change(Name::UseFilter, None, Some(dword(1)))])
                .unwrap();
            panic!("injected fixture unwind");
        });
        assert!(panic.is_err());
        assert_eq!(read_value(&a, Name::UseFilter).unwrap(), None);
    }

    #[test]
    fn mismatch_and_late_native_error_poison_the_entire_batch() {
        let fixture = Fixture::new();
        let a = fixture.create("a.exe");
        let b = fixture.create("b.exe");
        assert_eq!(write(&b, Name::Debugger, &dword(9)), ERROR_SUCCESS);
        let cancel = AtomicBool::new(false);
        for missing in [false, true] {
            let mut tx = fixture.tx(&cancel);
            tx.stage_existing("a.exe", &[change(Name::UseFilter, None, Some(dword(1)))])
                .unwrap();
            let result = if missing {
                tx.stage_existing(
                    "absent.exe",
                    &[change(Name::Debugger, None, Some(dword(1)))],
                )
            } else {
                tx.stage_existing(
                    "b.exe",
                    &[change(
                        Name::Debugger,
                        Some(raw(REG_BINARY.0, &9u32.to_le_bytes())),
                        None,
                    )],
                )
            };
            assert!(result.is_err());
            assert!(matches!(commit_fixture(tx), Err(Failure::Ended)));
            assert_eq!(read_value(&a, Name::UseFilter).unwrap(), None);
            assert_eq!(read_value(&b, Name::Debugger).unwrap(), Some(dword(9)));
        }
    }

    #[test]
    fn new_leaf_requires_existing_parent_and_never_adopts_existing_key() {
        let fixture = Fixture::new();
        drop(fixture.create("image.exe"));
        let cancel = AtomicBool::new(false);
        let mut tx = fixture.tx(&cancel);
        tx.stage_new_leaf(
            "image.exe",
            "owned",
            &[change(Name::Debugger, None, Some(dword(7)))],
        )
        .unwrap();
        assert!(matches!(
            fixture.open("image.exe\\owned"),
            Err(Failure::Native(2))
        ));
        commit_fixture(tx).unwrap();
        let leaf = fixture.open("image.exe\\owned").unwrap();
        assert_eq!(read_value(&leaf, Name::Debugger).unwrap(), Some(dword(7)));
        drop(leaf);
        let mut tx = fixture.tx(&cancel);
        assert_eq!(
            tx.stage_new_leaf(
                "IMAGE.EXE",
                "OWNED",
                &[change(Name::UseFilter, None, Some(dword(1)))]
            ),
            Err(Failure::Changed)
        );
        assert!(matches!(commit_fixture(tx), Err(Failure::Ended)));
        let mut tx = fixture.tx(&cancel);
        assert!(
            tx.stage_new_leaf(
                "missing.exe",
                "owned",
                &[change(Name::UseFilter, None, Some(dword(1)))]
            )
            .is_err()
        );
        drop(tx);
        assert!(matches!(
            fixture.open("missing.exe"),
            Err(Failure::Native(2))
        ));
        assert_eq!(
            read_value(&fixture.open("image.exe\\owned").unwrap(), Name::UseFilter).unwrap(),
            None
        );
    }

    #[test]
    fn invalid_and_over_budget_plans_never_commit_earlier_staging() {
        let fixture = Fixture::new();
        let a = fixture.create("a.exe");
        let cancel = AtomicBool::new(false);
        for path in [
            "",
            "..",
            "a.exe\\..",
            "a.exe/child",
            "a.exe\\child\\extra",
            "a.exe\0bad",
            "\\absolute",
        ] {
            let mut tx = fixture.tx(&cancel);
            tx.stage_existing("a.exe", &[change(Name::UseFilter, None, Some(dword(1)))])
                .unwrap();
            assert_eq!(
                tx.stage_existing(path, &[change(Name::Debugger, None, None)]),
                Err(Failure::InvalidPlan)
            );
            assert!(matches!(commit_fixture(tx), Err(Failure::Ended)));
            assert_eq!(read_value(&a, Name::UseFilter).unwrap(), None);
        }
        let mut tx = fixture.tx(&cancel);
        assert_eq!(
            tx.stage_existing(
                "a.exe",
                &[change(
                    Name::Debugger,
                    None,
                    Some(raw(REG_BINARY.0, &vec![0; MAX_BYTES + 1]))
                )]
            ),
            Err(Failure::Limited)
        );
        assert!(matches!(commit_fixture(tx), Err(Failure::Ended)));
        let mut tx = fixture.tx(&cancel);
        assert_eq!(
            tx.stage_existing(
                "a.exe",
                &[
                    change(Name::Debugger, None, None),
                    change(Name::Debugger, None, None)
                ]
            ),
            Err(Failure::InvalidPlan)
        );
        let mut tx = fixture.tx(&cancel);
        tx.stage_existing("a.exe", &[change(Name::Debugger, None, Some(dword(1)))])
            .unwrap();
        assert_eq!(
            tx.stage_existing("A.EXE", &[change(Name::UseFilter, None, Some(dword(1)))]),
            Err(Failure::InvalidPlan)
        );
    }

    #[test]
    fn cancellation_and_expired_deadline_block_commit_and_roll_back() {
        let fixture = Fixture::new();
        let a = fixture.create("a.exe");
        let cancel = AtomicBool::new(false);
        let mut tx = fixture.tx(&cancel);
        tx.stage_existing("a.exe", &[change(Name::UseFilter, None, Some(dword(1)))])
            .unwrap();
        cancel.store(true, Ordering::Release);
        assert!(matches!(commit_fixture(tx), Err(Failure::Cancelled)));
        assert_eq!(read_value(&a, Name::UseFilter).unwrap(), None);
        cancel.store(false, Ordering::Release);
        let mut tx = fixture.tx(&cancel);
        tx.stage_existing("a.exe", &[change(Name::UseFilter, None, Some(dword(1)))])
            .unwrap();
        tx.deadline = Instant::now();
        assert!(matches!(commit_fixture(tx), Err(Failure::Deadline)));
        assert_eq!(read_value(&a, Name::UseFilter).unwrap(), None);
        assert!(matches!(
            Transaction::begin(
                fixture.scope(),
                Instant::now() + Duration::from_secs(31),
                &cancel
            ),
            Err(Failure::InvalidPlan)
        ));
    }

    #[test]
    fn native_read_then_foreign_write_cannot_silently_overwrite_foreign_value() {
        let fixture = Fixture::new();
        let a = fixture.create("a.exe");
        assert_eq!(write(&a, Name::UseFilter, &dword(0)), ERROR_SUCCESS);
        let cancel = AtomicBool::new(false);
        let mut tx = fixture.tx(&cancel);
        let key = tx.open("a.exe", KEY_QUERY_VALUE).unwrap();
        assert_eq!(read_value(&key, Name::UseFilter).unwrap(), Some(dword(0)));
        drop(key);
        let foreign = write(&a, Name::UseFilter, &dword(2));
        let stage = tx.stage_existing(
            "a.exe",
            &[change(Name::UseFilter, Some(dword(0)), Some(dword(1)))],
        );
        eprintln!(
            "TxR read/conflict: foreign_status={} stage={stage:?}",
            foreign.0
        );
        if foreign == ERROR_SUCCESS {
            assert!(
                stage.is_err(),
                "foreign successful write must invalidate old observation"
            );
            assert!(commit_fixture(tx).is_err());
            assert_eq!(read_value(&a, Name::UseFilter).unwrap(), Some(dword(2)));
        } else {
            assert_eq!(foreign, ERROR_TRANSACTIONAL_CONFLICT);
            stage.unwrap();
            commit_fixture(tx).unwrap();
            assert_eq!(read_value(&a, Name::UseFilter).unwrap(), Some(dword(1)));
        }
    }

    #[test]
    fn native_write_conflicts_preserve_the_successful_writer_and_unrelated_data() {
        for same_value in [false, true] {
            let fixture = Fixture::new();
            let a = fixture.create("a.exe");
            assert_eq!(write(&a, Name::UseFilter, &dword(0)), ERROR_SUCCESS);
            let cancel = AtomicBool::new(false);
            let mut tx = fixture.tx(&cancel);
            tx.stage_existing(
                "a.exe",
                &[change(Name::UseFilter, Some(dword(0)), Some(dword(1)))],
            )
            .unwrap();
            let name = if same_value {
                Name::UseFilter
            } else {
                Name::Debugger
            };
            let foreign = write(&a, name, &dword(2));
            let commit = commit_fixture(tx);
            eprintln!(
                "TxR staged/conflict: same_value={same_value} foreign_status={} commit={commit:?}",
                foreign.0,
            );
            if foreign == ERROR_SUCCESS {
                assert!(commit.is_err());
                assert_eq!(read_value(&a, name).unwrap(), Some(dword(2)));
            } else {
                assert_eq!(foreign, ERROR_TRANSACTIONAL_CONFLICT);
                commit.unwrap();
                assert_eq!(read_value(&a, Name::UseFilter).unwrap(), Some(dword(1)));
                assert_eq!(read_value(&a, Name::Debugger).unwrap(), None);
            }
        }
    }

    #[test]
    fn competing_transactions_cannot_both_stage_conflicting_key_writes() {
        let fixture = Fixture::new();
        let a = fixture.create("a.exe");
        let cancel = AtomicBool::new(false);
        let mut first = fixture.tx(&cancel);
        let mut second = fixture.tx(&cancel);
        first
            .stage_existing("a.exe", &[change(Name::UseFilter, None, Some(dword(1)))])
            .unwrap();
        assert!(
            second
                .stage_existing("a.exe", &[change(Name::UseFilter, None, Some(dword(2)))])
                .is_err()
        );
        assert!(matches!(commit_fixture(second), Err(Failure::Ended)));
        commit_fixture(first).unwrap();
        assert_eq!(read_value(&a, Name::UseFilter).unwrap(), Some(dword(1)));
    }

    #[test]
    fn foreign_write_between_private_staging_and_public_validation_is_preserved() {
        for same_value in [true, false] {
            let fixture = Fixture::new();
            let a = fixture.create("a.exe");
            assert_eq!(write(&a, Name::UseFilter, &dword(0)), ERROR_SUCCESS);
            let cancel = AtomicBool::new(false);
            let mut tx = fixture.tx(&cancel);
            let key = tx.open("a.exe", KEY_QUERY_VALUE | KEY_SET_VALUE).unwrap();
            let observed = tx.open_public("a.exe").unwrap();
            let name = if same_value {
                Name::UseFilter
            } else {
                Name::Debugger
            };
            let mut foreign = ERROR_SUCCESS;
            let result = tx.stage_existing_values(
                &key,
                &observed,
                &[change(Name::UseFilter, Some(dword(0)), Some(dword(1)))],
                || {
                    foreign = write(&a, name, &dword(2));
                },
            );
            drop(key);
            eprintln!(
                "TxR staged/validation conflict: same_value={same_value} foreign_status={} stage={result:?}",
                foreign.0
            );
            if foreign == ERROR_SUCCESS {
                // Some native conflicts surface only at commit, even when
                // every value call succeeded. Never equate staging with effect.
                if result.is_ok() {
                    tx.paths.push("a.exe".into());
                }
                let _ = tx.finish_stage(result);
                let commit = commit_fixture(tx);
                eprintln!("TxR staged/validation conflict commit={commit:?}");
                assert!(
                    commit.is_err(),
                    "do not overwrite a successful intervening writer"
                );
                assert_eq!(read_value(&a, name).unwrap(), Some(dword(2)));
                if !same_value {
                    assert_eq!(read_value(&a, Name::UseFilter).unwrap(), Some(dword(0)));
                }
            } else {
                assert_eq!(foreign, ERROR_TRANSACTIONAL_CONFLICT);
                result.unwrap();
                // This low-level injected test did not call validate_plan.
                tx.paths.push("a.exe".into());
                commit_fixture(tx).unwrap();
                assert_eq!(read_value(&a, Name::UseFilter).unwrap(), Some(dword(1)));
            }
        }
    }

    #[test]
    fn both_views_preserve_intervening_deletes_creations_and_modify_revert() {
        for view in RegistryView::ALL {
            // These flags may name a shared HKCU key, not independent stores.
            let fixture = Fixture::in_view(view);
            let a = fixture.create("a.exe");
            let cancel = AtomicBool::new(false);
            for deleting in [false, true] {
                if deleting {
                    assert_eq!(write(&a, Name::UseFilter, &dword(0)), ERROR_SUCCESS);
                }
                let mut tx = fixture.tx(&cancel);
                tx.stage_existing(
                    "a.exe",
                    &[change(
                        Name::UseFilter,
                        if deleting { Some(dword(0)) } else { None },
                        if deleting { None } else { Some(dword(1)) },
                    )],
                )
                .unwrap();
                let foreign = write(&a, Name::UseFilter, &dword(2));
                let commit = commit_fixture(tx);
                eprintln!(
                    "TxR create/delete race: view={view:?} deleting={deleting} foreign_status={} commit={commit:?}",
                    foreign.0
                );
                if foreign == ERROR_SUCCESS {
                    assert!(matches!(commit, Err(Failure::CommitUncertain(_))));
                    assert_eq!(read_value(&a, Name::UseFilter).unwrap(), Some(dword(2)));
                } else {
                    assert_eq!(foreign, ERROR_TRANSACTIONAL_CONFLICT);
                    commit.unwrap();
                }
                let name = Name::UseFilter.wide();
                let code = unsafe { RegDeleteValueW(a.0, PCWSTR(name.as_ptr())) };
                assert!([ERROR_SUCCESS, ERROR_FILE_NOT_FOUND].contains(&code));
            }
            assert_eq!(write(&a, Name::UseFilter, &dword(0)), ERROR_SUCCESS);
            let mut tx = fixture.tx(&cancel);
            tx.stage_existing(
                "a.exe",
                &[change(Name::UseFilter, Some(dword(0)), Some(dword(1)))],
            )
            .unwrap();
            let foreign = write(&a, Name::UseFilter, &dword(2));
            if foreign == ERROR_SUCCESS {
                assert_eq!(write(&a, Name::UseFilter, &dword(0)), ERROR_SUCCESS);
                assert!(matches!(
                    commit_fixture(tx),
                    Err(Failure::CommitUncertain(_))
                ));
                assert_eq!(read_value(&a, Name::UseFilter).unwrap(), Some(dword(0)));
            } else {
                assert_eq!(foreign, ERROR_TRANSACTIONAL_CONFLICT);
                commit_fixture(tx).unwrap();
            }
        }
    }

    #[test]
    fn later_key_conflicts_roll_back_earlier_staging_and_replaced_keys_are_preserved() {
        let fixture = Fixture::new();
        let a = fixture.create("a.exe");
        let b = fixture.create("b.exe");
        let cancel = AtomicBool::new(false);
        let mut tx = fixture.tx(&cancel);
        tx.stage_existing("a.exe", &[change(Name::UseFilter, None, Some(dword(1)))])
            .unwrap();
        assert_eq!(write(&b, Name::Debugger, &dword(2)), ERROR_SUCCESS);
        assert_eq!(
            tx.stage_existing("b.exe", &[change(Name::Debugger, None, Some(dword(1)))]),
            Err(Failure::Changed)
        );
        assert!(matches!(commit_fixture(tx), Err(Failure::Ended)));
        assert_eq!(read_value(&a, Name::UseFilter).unwrap(), None);
        assert_eq!(read_value(&b, Name::Debugger).unwrap(), Some(dword(2)));
        drop(b);
        drop(a);

        let mut tx = fixture.tx(&cancel);
        tx.stage_existing("a.exe", &[change(Name::UseFilter, None, Some(dword(1)))])
            .unwrap();
        let path = wide("a.exe");
        let deleted = unsafe { RegDeleteTreeW(fixture.scope().key.0, PCWSTR(path.as_ptr())) };
        if deleted == ERROR_SUCCESS {
            let replacement = fixture.create("a.exe");
            assert_eq!(
                write(&replacement, Name::Debugger, &dword(99)),
                ERROR_SUCCESS
            );
            assert!(matches!(
                commit_fixture(tx),
                Err(Failure::CommitUncertain(_))
            ));
            assert_eq!(read_value(&replacement, Name::UseFilter).unwrap(), None);
            assert_eq!(
                read_value(&replacement, Name::Debugger).unwrap(),
                Some(dword(99))
            );
        } else {
            assert_eq!(deleted, ERROR_TRANSACTIONAL_CONFLICT);
            commit_fixture(tx).unwrap();
        }
    }

    #[test]
    fn new_leaf_rollback_and_concurrent_creation_never_adopt_foreign_state() {
        let fixture = Fixture::new();
        drop(fixture.create("image.exe"));
        let cancel = AtomicBool::new(false);
        let mut tx = fixture.tx(&cancel);
        tx.stage_new_leaf(
            "image.exe",
            "owned",
            &[change(Name::Debugger, None, Some(dword(7)))],
        )
        .unwrap();
        drop(tx);
        assert!(matches!(
            fixture.open("image.exe\\owned"),
            Err(Failure::Native(2))
        ));
        let mut tx = fixture.tx(&cancel);
        tx.stage_new_leaf(
            "image.exe",
            "owned",
            &[change(Name::Debugger, None, Some(dword(7)))],
        )
        .unwrap();
        let path = wide("image.exe\\owned");
        let mut key = HKEY::default();
        let created = unsafe {
            RegCreateKeyExW(
                fixture.scope().key.0,
                PCWSTR(path.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS | fixture.scope().view,
                None,
                &mut key,
                None,
            )
        };
        let commit;
        if created == ERROR_SUCCESS {
            let key = Key(key);
            assert_eq!(write(&key, Name::Debugger, &dword(99)), ERROR_SUCCESS);
            commit = commit_fixture(tx);
            assert!(matches!(commit, Err(Failure::CommitUncertain(_))));
            assert_eq!(read_value(&key, Name::Debugger).unwrap(), Some(dword(99)));
        } else {
            // A pending created key can also be hidden from this ordinary
            // create path as FILE_NOT_FOUND. Neither result grants a handle.
            assert!([ERROR_TRANSACTIONAL_CONFLICT, ERROR_FILE_NOT_FOUND].contains(&created));
            commit = commit_fixture(tx);
            commit.as_ref().unwrap();
            assert_eq!(
                read_value(&fixture.open("image.exe\\owned").unwrap(), Name::Debugger).unwrap(),
                Some(dword(7))
            );
        }
        eprintln!(
            "TxR leaf race: create_status={} commit={commit:?}",
            created.0
        );
    }

    #[test]
    fn no_op_guards_oversized_native_values_and_aggregate_work_are_rejected() {
        let fixture = Fixture::new();
        let a = fixture.create("a.exe");
        assert_eq!(
            write(
                &a,
                Name::Debugger,
                &raw(REG_BINARY.0, &vec![7; MAX_BYTES + 1])
            ),
            ERROR_SUCCESS
        );
        let cancel = AtomicBool::new(false);
        let mut tx = fixture.tx(&cancel);
        assert_eq!(
            tx.stage_existing("a.exe", &[change(Name::UseFilter, None, None)]),
            Err(Failure::InvalidPlan)
        );
        let mut tx = fixture.tx(&cancel);
        assert_eq!(
            tx.stage_existing("a.exe", &[change(Name::Debugger, None, Some(dword(1)))]),
            Err(Failure::Limited)
        );
        assert!(matches!(commit_fixture(tx), Err(Failure::Ended)));
        let mut tx = fixture.tx(&cancel);
        for i in 0..MAX_KEYS {
            let path = format!("key{i}.exe");
            drop(fixture.create(&path));
            tx.stage_existing(&path, &[change(Name::UseFilter, None, Some(dword(1)))])
                .unwrap();
        }
        assert_eq!(
            tx.stage_existing(
                "absent.exe",
                &[change(Name::UseFilter, None, Some(dword(1)))]
            ),
            Err(Failure::Limited)
        );
        assert!(matches!(commit_fixture(tx), Err(Failure::Ended)));
        assert_eq!(
            read_value(&fixture.open("key0.exe").unwrap(), Name::UseFilter).unwrap(),
            None
        );
        let mut tx = fixture.tx(&cancel);
        for i in 0..5 {
            let path = format!("large{i}.exe");
            drop(fixture.create(&path));
            let changes: Vec<_> = [Name::Debugger, Name::FilterFullPath, Name::UseFilter]
                .into_iter()
                .map(|name| change(name, None, Some(raw(REG_BINARY.0, &vec![0; MAX_BYTES]))))
                .collect();
            tx.stage_existing(&path, &changes).unwrap();
        }
        assert_eq!(
            tx.stage_existing(
                "absent.exe",
                &[
                    change(
                        Name::Debugger,
                        None,
                        Some(raw(REG_BINARY.0, &vec![0; MAX_BYTES]))
                    ),
                    change(Name::UseFilter, None, Some(dword(1)))
                ]
            ),
            Err(Failure::Limited)
        );
        assert!(matches!(commit_fixture(tx), Err(Failure::Ended)));
        assert_eq!(
            read_value(&fixture.open("large0.exe").unwrap(), Name::Debugger).unwrap(),
            None
        );
    }
}
