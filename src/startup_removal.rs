//! Narrow, reversible removal of one current-user Run registration.
//!
//! The caller must durably journal [`RemovalIntent`] before calling
//! [`RunValueRemovalManager::apply_removal`]. The native adapter only handles the
//! exact HKCU Run value and its same-name StartupApproved marker. Other startup
//! source kinds remain unsupported. Native changes use KTM registry transactions;
//! the adapter never falls back to ordinary registry writes when TxR is unavailable.

use crate::startup::{
    EntryIdentity, NativeState, ObservedState, RegistryHive, RegistryValueSnapshot, RegistryView,
    StartupError, StartupErrorKind, StartupId, StartupPlatform, WindowsStartupPlatform,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const REMOVAL_SCHEMA_VERSION: u32 = 1;
const MAX_VALUE_NAME_UTF16_UNITS: usize = 16_383;
const MAX_VALUE_BYTES: usize = 1024 * 1024;
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APPROVAL_KEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunValueSlots {
    /// Exact raw type and bytes from the selected Run value.
    pub run: Option<RegistryValueSnapshot>,
    /// Exact raw type and bytes from the matching StartupApproved value, if present.
    pub approval: Option<RegistryValueSnapshot>,
}

impl RunValueSlots {
    fn absent() -> Self {
        Self {
            run: None,
            approval: None,
        }
    }

    fn is_absent(&self) -> bool {
        self.run.is_none() && self.approval.is_none()
    }

    fn is_valid(&self, require_run: bool) -> bool {
        (!require_run || self.run.is_some())
            && self
                .run
                .iter()
                .chain(self.approval.iter())
                .all(|value| value.data.len() <= MAX_VALUE_BYTES)
    }

    fn contains_only_original_or_absent(&self, original: &Self) -> bool {
        slot_is_original_or_absent(&self.run, &original.run)
            && slot_is_original_or_absent(&self.approval, &original.approval)
    }
}

fn slot_is_original_or_absent(
    current: &Option<RegistryValueSnapshot>,
    original: &Option<RegistryValueSnapshot>,
) -> bool {
    current.is_none() || current == original
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemovalIntent {
    pub schema_version: u32,
    /// This ID is also the durable effect-journal operation ID.
    pub operation_id: Uuid,
    pub id: StartupId,
    pub identity: EntryIdentity,
    pub before: RunValueSlots,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemovalOutcome {
    Removed,
    NoChange,
    Uncertain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemovalReceipt {
    pub schema_version: u32,
    pub operation_id: Uuid,
    pub id: StartupId,
    pub identity: EntryIdentity,
    pub before: RunValueSlots,
    /// None means the native state could not be re-read after the attempt.
    pub after: Option<RunValueSlots>,
    pub outcome: RemovalOutcome,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemovalRestoreIntent {
    pub schema_version: u32,
    /// A new journal ID for this separately reviewed restoration.
    pub restore_id: Uuid,
    pub source_operation_id: Uuid,
    pub id: StartupId,
    pub identity: EntryIdentity,
    pub before: RunValueSlots,
    /// Exact slots observed when the restore review was prepared.
    pub expected_current: RunValueSlots,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemovalRestoreOutcome {
    Restored,
    AlreadyRestored,
    NoChange,
    Uncertain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemovalRestoreReceipt {
    pub schema_version: u32,
    pub restore_id: Uuid,
    pub source_operation_id: Uuid,
    pub id: StartupId,
    pub identity: EntryIdentity,
    pub before: RunValueSlots,
    pub expected_current: RunValueSlots,
    pub after: Option<RunValueSlots>,
    pub outcome: RemovalRestoreOutcome,
    pub error: Option<String>,
}

/// Platform seam for exact Run-value and StartupApproved snapshots. Native mutation
/// implementations stage changed values transactionally, compare the public state
/// after staging, and classify failed commit calls as uncertain.
pub trait RunValueRemovalPlatform {
    fn observe(&mut self, id: &StartupId) -> Result<ObservedState, StartupError>;
    fn observe_slots(&mut self, identity: &EntryIdentity) -> Result<RunValueSlots, StartupError>;
    fn remove_if_matches(
        &mut self,
        identity: &EntryIdentity,
        expected: &RunValueSlots,
    ) -> Result<(), RemovalPlatformError>;
    fn restore_if_matches(
        &mut self,
        identity: &EntryIdentity,
        expected_current: &RunValueSlots,
        desired: &RunValueSlots,
    ) -> Result<(), RemovalPlatformError>;
}

/// Distinguishes a rejected/rolled-back operation from a transaction whose
/// commit call was entered but did not acknowledge its outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemovalPlatformError {
    BeforeCommit(StartupError),
    CommitUncertain(StartupError),
}

impl From<StartupError> for RemovalPlatformError {
    fn from(error: StartupError) -> Self {
        Self::BeforeCommit(error)
    }
}

impl RemovalPlatformError {
    fn message(&self) -> String {
        match self {
            Self::BeforeCommit(error) | Self::CommitUncertain(error) => error.message.clone(),
        }
    }
}

pub struct RunValueRemovalManager<P> {
    platform: P,
}

impl<P: RunValueRemovalPlatform> RunValueRemovalManager<P> {
    pub fn new(platform: P) -> Self {
        Self { platform }
    }

    pub fn platform(&self) -> &P {
        &self.platform
    }

    pub fn platform_mut(&mut self) -> &mut P {
        &mut self.platform
    }

    pub fn prepare_removal(&mut self, id: &StartupId) -> Result<RemovalIntent, StartupError> {
        let observed = self.platform.observe(id)?;
        if observed.id != *id
            || StartupId::for_identity(&observed.identity) != *id
            || !supports_run_value_removal(&observed.identity)
        {
            return Err(error(
                StartupErrorKind::Unsupported,
                "Only a current-user Run value with a known registry view can be removed safely.",
            ));
        }
        let before = slots_from_observed(&observed)?;
        let intent = RemovalIntent {
            schema_version: REMOVAL_SCHEMA_VERSION,
            operation_id: Uuid::new_v4(),
            id: id.clone(),
            identity: observed.identity,
            before,
        };
        if !valid_removal_intent(&intent) {
            return Err(error(
                StartupErrorKind::InvalidIntent,
                "The selected Run registration could not be represented as a bounded removal intent.",
            ));
        }
        Ok(intent)
    }

    /// Call only after the caller durably journals `intent`. Native errors after
    /// entry are returned as an explicit outcome; the operation is never retried.
    pub fn apply_removal(
        &mut self,
        intent: &RemovalIntent,
    ) -> Result<RemovalReceipt, StartupError> {
        if !valid_removal_intent(intent) {
            return Err(error(
                StartupErrorKind::InvalidIntent,
                "The saved Run-value removal intent is invalid.",
            ));
        }
        let observed = self.platform.observe(&intent.id)?;
        if observed.id != intent.id
            || observed.identity != intent.identity
            || StartupId::for_identity(&observed.identity) != intent.id
        {
            return Err(error(
                StartupErrorKind::ChangedSinceReview,
                "The selected Run registration identity changed after review.",
            ));
        }
        let current = slots_from_observed(&observed)?;
        if current != intent.before {
            return Err(error(
                StartupErrorKind::ChangedSinceReview,
                "The Run value or StartupApproved bytes changed after review; no removal was attempted.",
            ));
        }

        let native_result = self
            .platform
            .remove_if_matches(&intent.identity, &intent.before);
        if let Err(RemovalPlatformError::BeforeCommit(failure)) = &native_result {
            if failure.kind == StartupErrorKind::ChangedSinceReview {
                return Err(failure.clone());
            }
        }
        let after = self.platform.observe_slots(&intent.identity).ok();
        let outcome = match (&native_result, &after) {
            (Ok(()), Some(state)) if state.is_absent() => RemovalOutcome::Removed,
            (Err(RemovalPlatformError::BeforeCommit(_)), Some(state))
                if state == &intent.before =>
            {
                RemovalOutcome::NoChange
            }
            _ => RemovalOutcome::Uncertain,
        };
        let error = native_result.err().map(|failure| failure.message());
        Ok(RemovalReceipt {
            schema_version: REMOVAL_SCHEMA_VERSION,
            operation_id: intent.operation_id,
            id: intent.id.clone(),
            identity: intent.identity.clone(),
            before: intent.before.clone(),
            after,
            outcome,
            error,
        })
    }

    pub fn prepare_restore_from_intent(
        &mut self,
        intent: &RemovalIntent,
    ) -> Result<RemovalRestoreIntent, StartupError> {
        if !valid_removal_intent(intent) {
            return Err(error(
                StartupErrorKind::InvalidIntent,
                "The saved Run-value removal intent is invalid.",
            ));
        }
        self.prepare_restore(
            intent.operation_id,
            intent.id.clone(),
            intent.identity.clone(),
            intent.before.clone(),
        )
    }

    pub fn prepare_restore_from_receipt(
        &mut self,
        receipt: &RemovalReceipt,
    ) -> Result<RemovalRestoreIntent, StartupError> {
        if !valid_removal_receipt(receipt) || receipt.outcome == RemovalOutcome::NoChange {
            return Err(error(
                StartupErrorKind::InvalidIntent,
                "The saved removal receipt does not authorize restoration.",
            ));
        }
        self.prepare_restore(
            receipt.operation_id,
            receipt.id.clone(),
            receipt.identity.clone(),
            receipt.before.clone(),
        )
    }

    fn prepare_restore(
        &mut self,
        source_operation_id: Uuid,
        id: StartupId,
        identity: EntryIdentity,
        before: RunValueSlots,
    ) -> Result<RemovalRestoreIntent, StartupError> {
        if !supports_run_value_removal(&identity)
            || StartupId::for_identity(&identity) != id
            || !before.is_valid(true)
        {
            return Err(error(
                StartupErrorKind::InvalidIntent,
                "The saved removal identity or raw snapshot is invalid.",
            ));
        }
        let expected_current = self.platform.observe_slots(&identity)?;
        if !expected_current.contains_only_original_or_absent(&before) {
            return Err(error(
                StartupErrorKind::ChangedSinceReview,
                "The registry slot now contains different bytes. Restoration refuses to replace it.",
            ));
        }
        let intent = RemovalRestoreIntent {
            schema_version: REMOVAL_SCHEMA_VERSION,
            restore_id: Uuid::new_v4(),
            source_operation_id,
            id,
            identity,
            before,
            expected_current,
        };
        if !valid_restore_intent(&intent) {
            return Err(error(
                StartupErrorKind::InvalidIntent,
                "The restore review could not be represented as a bounded intent.",
            ));
        }
        Ok(intent)
    }

    /// Restores only missing slots whose saved originals still match every present
    /// value. The caller must journal this fresh restore intent before calling.
    pub fn apply_restore(
        &mut self,
        intent: &RemovalRestoreIntent,
    ) -> Result<RemovalRestoreReceipt, StartupError> {
        if !valid_restore_intent(intent) {
            return Err(error(
                StartupErrorKind::InvalidIntent,
                "The saved Run-value restore intent is invalid.",
            ));
        }
        let current = self.platform.observe_slots(&intent.identity)?;
        if current != intent.expected_current {
            return Err(error(
                StartupErrorKind::ChangedSinceReview,
                "The Run registration changed after restore review; no value was written.",
            ));
        }
        if !current.contains_only_original_or_absent(&intent.before) {
            return Err(error(
                StartupErrorKind::ChangedSinceReview,
                "A registry slot contains different bytes. Restoration refuses to replace it.",
            ));
        }

        let native_result = if current == intent.before {
            Ok(())
        } else {
            self.platform
                .restore_if_matches(&intent.identity, &current, &intent.before)
        };
        if let Err(RemovalPlatformError::BeforeCommit(failure)) = &native_result {
            if failure.kind == StartupErrorKind::ChangedSinceReview {
                return Err(failure.clone());
            }
        }
        let after = self.platform.observe_slots(&intent.identity).ok();
        let outcome = match (&native_result, &after) {
            (Ok(()), Some(state)) if state == &intent.before => {
                if current == intent.before {
                    RemovalRestoreOutcome::AlreadyRestored
                } else {
                    RemovalRestoreOutcome::Restored
                }
            }
            (Err(RemovalPlatformError::BeforeCommit(_)), Some(state)) if state == &current => {
                RemovalRestoreOutcome::NoChange
            }
            _ => RemovalRestoreOutcome::Uncertain,
        };
        let error = native_result.err().map(|failure| failure.message());
        Ok(RemovalRestoreReceipt {
            schema_version: REMOVAL_SCHEMA_VERSION,
            restore_id: intent.restore_id,
            source_operation_id: intent.source_operation_id,
            id: intent.id.clone(),
            identity: intent.identity.clone(),
            before: intent.before.clone(),
            expected_current: intent.expected_current.clone(),
            after,
            outcome,
            error,
        })
    }
}

fn slots_from_observed(observed: &ObservedState) -> Result<RunValueSlots, StartupError> {
    match &observed.native {
        NativeState::StartupRunValue { value, approval } => Ok(RunValueSlots {
            run: Some(value.clone()),
            approval: approval.clone(),
        }),
        _ => Err(error(
            StartupErrorKind::Unsupported,
            "The selected item is not a readable Run registration.",
        )),
    }
}

pub fn supports_run_value_removal(identity: &EntryIdentity) -> bool {
    matches!(
        identity,
        EntryIdentity::StartupRunValue {
            hive: RegistryHive::CurrentUser,
            view: RegistryView::Registry32 | RegistryView::Registry64,
            key,
            value_name,
            approval_hive: RegistryHive::CurrentUser,
            approval_key,
        } if key.eq_ignore_ascii_case(RUN_KEY)
            && approval_key.eq_ignore_ascii_case(APPROVAL_KEY)
            && !value_name.is_empty()
            && value_name.encode_utf16().count() <= MAX_VALUE_NAME_UTF16_UNITS
            && !value_name.contains('\0')
    )
}

pub fn valid_removal_intent(intent: &RemovalIntent) -> bool {
    intent.schema_version == REMOVAL_SCHEMA_VERSION
        && !intent.operation_id.is_nil()
        && intent.id == StartupId::for_identity(&intent.identity)
        && supports_run_value_removal(&intent.identity)
        && intent.before.is_valid(true)
}

pub fn valid_removal_receipt(receipt: &RemovalReceipt) -> bool {
    if receipt.schema_version != REMOVAL_SCHEMA_VERSION
        || receipt.operation_id.is_nil()
        || receipt.id != StartupId::for_identity(&receipt.identity)
        || !supports_run_value_removal(&receipt.identity)
        || !receipt.before.is_valid(true)
        || receipt
            .after
            .as_ref()
            .is_some_and(|slots| !slots.is_valid(false))
    {
        return false;
    }
    match receipt.outcome {
        RemovalOutcome::Removed => {
            receipt.error.is_none() && receipt.after.as_ref().is_some_and(RunValueSlots::is_absent)
        }
        RemovalOutcome::NoChange => {
            receipt.error.is_some() && receipt.after.as_ref() == Some(&receipt.before)
        }
        RemovalOutcome::Uncertain => true,
    }
}

pub fn valid_restore_intent(intent: &RemovalRestoreIntent) -> bool {
    intent.schema_version == REMOVAL_SCHEMA_VERSION
        && !intent.restore_id.is_nil()
        && !intent.source_operation_id.is_nil()
        && intent.restore_id != intent.source_operation_id
        && intent.id == StartupId::for_identity(&intent.identity)
        && supports_run_value_removal(&intent.identity)
        && intent.before.is_valid(true)
        && intent.expected_current.is_valid(false)
        && intent
            .expected_current
            .contains_only_original_or_absent(&intent.before)
}

pub fn valid_restore_receipt(receipt: &RemovalRestoreReceipt) -> bool {
    if receipt.schema_version != REMOVAL_SCHEMA_VERSION
        || receipt.restore_id.is_nil()
        || receipt.source_operation_id.is_nil()
        || receipt.id != StartupId::for_identity(&receipt.identity)
        || !supports_run_value_removal(&receipt.identity)
        || !receipt.before.is_valid(true)
        || !receipt.expected_current.is_valid(false)
        || !receipt
            .expected_current
            .contains_only_original_or_absent(&receipt.before)
        || receipt
            .after
            .as_ref()
            .is_some_and(|slots| !slots.is_valid(false))
    {
        return false;
    }
    match receipt.outcome {
        RemovalRestoreOutcome::Restored => {
            receipt.error.is_none() && receipt.after.as_ref() == Some(&receipt.before)
        }
        RemovalRestoreOutcome::AlreadyRestored => {
            receipt.error.is_none()
                && receipt.expected_current == receipt.before
                && receipt.after.as_ref() == Some(&receipt.before)
        }
        RemovalRestoreOutcome::NoChange => {
            receipt.error.is_some() && receipt.after.as_ref() == Some(&receipt.expected_current)
        }
        RemovalRestoreOutcome::Uncertain => true,
    }
}

fn error(kind: StartupErrorKind, message: impl Into<String>) -> StartupError {
    StartupError::new(kind, message)
}

#[cfg(windows)]
pub struct WindowsRunValueRemovalPlatform {
    startup: WindowsStartupPlatform,
}

#[cfg(windows)]
impl WindowsRunValueRemovalPlatform {
    pub fn new() -> Self {
        Self {
            startup: WindowsStartupPlatform::new(),
        }
    }
}

#[cfg(windows)]
impl RunValueRemovalPlatform for WindowsRunValueRemovalPlatform {
    fn observe(&mut self, id: &StartupId) -> Result<ObservedState, StartupError> {
        self.startup.observe(id)
    }

    fn observe_slots(&mut self, identity: &EntryIdentity) -> Result<RunValueSlots, StartupError> {
        native::observe_slots(identity)
    }

    fn remove_if_matches(
        &mut self,
        identity: &EntryIdentity,
        expected: &RunValueSlots,
    ) -> Result<(), RemovalPlatformError> {
        native::remove_if_matches(identity, expected)
    }

    fn restore_if_matches(
        &mut self,
        identity: &EntryIdentity,
        expected_current: &RunValueSlots,
        desired: &RunValueSlots,
    ) -> Result<(), RemovalPlatformError> {
        native::restore_if_matches(identity, expected_current, desired)
    }
}

#[cfg(not(windows))]
pub struct WindowsRunValueRemovalPlatform;

#[cfg(not(windows))]
impl WindowsRunValueRemovalPlatform {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(windows))]
impl RunValueRemovalPlatform for WindowsRunValueRemovalPlatform {
    fn observe(&mut self, _id: &StartupId) -> Result<ObservedState, StartupError> {
        Err(error(
            StartupErrorKind::Unsupported,
            "Run-value removal is available only on Windows.",
        ))
    }

    fn observe_slots(&mut self, _identity: &EntryIdentity) -> Result<RunValueSlots, StartupError> {
        Err(error(
            StartupErrorKind::Unsupported,
            "Run-value removal is available only on Windows.",
        ))
    }

    fn remove_if_matches(
        &mut self,
        _identity: &EntryIdentity,
        _expected: &RunValueSlots,
    ) -> Result<(), RemovalPlatformError> {
        Err(error(
            StartupErrorKind::Unsupported,
            "Run-value removal is available only on Windows.",
        )
        .into())
    }

    fn restore_if_matches(
        &mut self,
        _identity: &EntryIdentity,
        _expected_current: &RunValueSlots,
        _desired: &RunValueSlots,
    ) -> Result<(), RemovalPlatformError> {
        Err(error(
            StartupErrorKind::Unsupported,
            "Run-value removal is available only on Windows.",
        )
        .into())
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr,
        time::Duration,
    };
    use windows::{
        Win32::{
            Foundation::{
                ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS, HANDLE,
            },
            Storage::FileSystem::{CommitTransaction, CreateTransaction, RollbackTransaction},
            System::Registry::{
                HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_32KEY,
                KEY_WOW64_64KEY, REG_SAM_FLAGS, REG_VALUE_TYPE, RegCloseKey, RegDeleteValueW,
                RegOpenKeyExW, RegOpenKeyTransactedW, RegQueryValueExW, RegSetValueExW,
            },
        },
        core::PCWSTR,
    };

    const ERROR_PATH_NOT_FOUND_RAW: u32 = 3;
    const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(30);

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: this uniquely owned key handle is closed once and never escapes native.
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    struct Transaction {
        handle: OwnedHandle,
        ended: bool,
    }

    impl Transaction {
        fn begin() -> Result<Self, RemovalPlatformError> {
            let timeout_ms = TRANSACTION_TIMEOUT.as_millis() as u32;
            let handle = unsafe {
                CreateTransaction(
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    0,
                    0,
                    timeout_ms,
                    PCWSTR::null(),
                )
            }
            .map_err(|error| {
                RemovalPlatformError::BeforeCommit(registry_error(
                    "start a transactional registry operation",
                    win32_code_from_hresult(error.code().0),
                ))
            })?;
            Ok(Self {
                handle: unsafe { OwnedHandle::from_raw_handle(handle.0) },
                ended: false,
            })
        }

        fn raw(&self) -> HANDLE {
            HANDLE(self.handle.as_raw_handle())
        }

        fn commit(mut self) -> Result<(), RemovalPlatformError> {
            match unsafe { CommitTransaction(self.raw()) } {
                Ok(()) => {
                    self.ended = true;
                    Ok(())
                }
                Err(error) => Err(RemovalPlatformError::CommitUncertain(registry_error(
                    "commit the transactional registry operation",
                    win32_code_from_hresult(error.code().0),
                ))),
            }
        }
    }

    impl Drop for Transaction {
        fn drop(&mut self) {
            if !self.ended {
                let _ = unsafe { RollbackTransaction(self.raw()) };
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn registry_error(action: &str, code: u32) -> StartupError {
        let kind = if code == ERROR_ACCESS_DENIED.0 {
            StartupErrorKind::Inaccessible
        } else {
            StartupErrorKind::NativeFailure
        };
        error(kind, format!("Could not {action} (Windows error {code})."))
    }

    fn win32_code_from_hresult(code: i32) -> u32 {
        let bits = code as u32;
        if bits & 0xffff_0000 == 0x8007_0000 {
            bits & 0x0000_ffff
        } else {
            bits
        }
    }

    fn validated_identity(
        identity: &EntryIdentity,
    ) -> Result<(&str, &str, &str, RegistryView), StartupError> {
        if !supports_run_value_removal(identity) {
            return Err(error(
                StartupErrorKind::Unsupported,
                "Only a current-user Run value with a known registry view can be removed safely.",
            ));
        }
        let EntryIdentity::StartupRunValue {
            key,
            value_name,
            approval_key,
            view,
            ..
        } = identity
        else {
            unreachable!("identity validated above")
        };
        Ok((key, approval_key, value_name, *view))
    }

    fn open_key(
        path: &str,
        access: REG_SAM_FLAGS,
        view: RegistryView,
    ) -> Result<Key, StartupError> {
        open_key_optional(path, access, view)?.ok_or_else(|| {
            error(
                StartupErrorKind::ChangedSinceReview,
                "A selected Run registry key no longer exists.",
            )
        })
    }

    fn open_key_optional(
        path: &str,
        access: REG_SAM_FLAGS,
        view: RegistryView,
    ) -> Result<Option<Key>, StartupError> {
        let view_flag = match view {
            RegistryView::Registry32 => KEY_WOW64_32KEY.0,
            RegistryView::Registry64 => KEY_WOW64_64KEY.0,
            RegistryView::LegacyUnknown => {
                return Err(error(
                    StartupErrorKind::Unsupported,
                    "The saved registry view is unknown; no native change was made.",
                ));
            }
        };
        let path = wide(path);
        let mut handle = HKEY(ptr::null_mut());
        let code = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(path.as_ptr()),
                None,
                REG_SAM_FLAGS(access.0 | view_flag),
                &mut handle,
            )
        };
        if code.0 == ERROR_FILE_NOT_FOUND.0 || code.0 == ERROR_PATH_NOT_FOUND_RAW {
            return Ok(None);
        }
        if code.0 == ERROR_ACCESS_DENIED.0 {
            return Err(registry_error("open the selected registry key", code.0));
        }
        if code != ERROR_SUCCESS {
            return Err(registry_error("open the selected registry key", code.0));
        }
        Ok(Some(Key(handle)))
    }

    fn open_transacted_key(
        path: &str,
        access: REG_SAM_FLAGS,
        view: RegistryView,
        transaction: &Transaction,
    ) -> Result<Key, StartupError> {
        let view_flag = match view {
            RegistryView::Registry32 => KEY_WOW64_32KEY.0,
            RegistryView::Registry64 => KEY_WOW64_64KEY.0,
            RegistryView::LegacyUnknown => {
                return Err(error(
                    StartupErrorKind::Unsupported,
                    "The saved registry view is unknown; no native change was made.",
                ));
            }
        };
        let path = wide(path);
        let mut handle = HKEY(ptr::null_mut());
        let code = unsafe {
            RegOpenKeyTransactedW(
                HKEY_CURRENT_USER,
                PCWSTR(path.as_ptr()),
                None,
                REG_SAM_FLAGS(access.0 | view_flag),
                &mut handle,
                transaction.raw(),
                None,
            )
        };
        if code.0 == ERROR_FILE_NOT_FOUND.0 || code.0 == ERROR_PATH_NOT_FOUND_RAW {
            return Err(error(
                StartupErrorKind::ChangedSinceReview,
                "A selected registry key disappeared before transactional staging.",
            ));
        }
        if code.0 == ERROR_ACCESS_DENIED.0 {
            return Err(registry_error("open a transactional registry key", code.0));
        }
        if code != ERROR_SUCCESS {
            return Err(registry_error("open a transactional registry key", code.0));
        }
        Ok(Key(handle))
    }

    fn read_value(key: HKEY, name: &str) -> Result<Option<RegistryValueSnapshot>, StartupError> {
        let name = wide(name);
        let mut value_type = REG_VALUE_TYPE(0);
        let mut length = 0u32;
        let first = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut value_type),
                None,
                Some(&mut length),
            )
        };
        if first.0 == ERROR_FILE_NOT_FOUND.0 {
            return Ok(None);
        }
        if first != ERROR_SUCCESS && first != ERROR_MORE_DATA {
            return Err(registry_error("query the selected registry value", first.0));
        }
        if length as usize > MAX_VALUE_BYTES {
            return Err(error(
                StartupErrorKind::Inaccessible,
                "The selected registry value exceeds the 1 MiB safety bound.",
            ));
        }
        let mut data = vec![0; length as usize];
        let mut actual_length = length;
        let second = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut value_type),
                Some(data.as_mut_ptr()),
                Some(&mut actual_length),
            )
        };
        if second.0 == ERROR_FILE_NOT_FOUND.0 {
            return Ok(None);
        }
        if second.0 == ERROR_MORE_DATA.0 {
            return Err(error(
                StartupErrorKind::ChangedSinceReview,
                "The selected registry value changed while it was being read.",
            ));
        }
        if second != ERROR_SUCCESS || actual_length as usize > data.len() {
            return Err(registry_error("read the selected registry value", second.0));
        }
        data.truncate(actual_length as usize);
        Ok(Some(RegistryValueSnapshot {
            value_type: value_type.0,
            data,
        }))
    }

    fn read_slots_on_keys(
        run_key: HKEY,
        approval_key: Option<HKEY>,
        name: &str,
    ) -> Result<RunValueSlots, StartupError> {
        Ok(RunValueSlots {
            run: read_value(run_key, name)?,
            approval: match approval_key {
                Some(key) => read_value(key, name)?,
                None => None,
            },
        })
    }

    pub(super) fn observe_slots(identity: &EntryIdentity) -> Result<RunValueSlots, StartupError> {
        let (run_path, approval_path, name, view) = validated_identity(identity)?;
        let run_key = open_key(run_path, KEY_QUERY_VALUE, view)?;
        let approval_key = open_key_optional(approval_path, KEY_QUERY_VALUE, view)?;
        read_slots_on_keys(run_key.0, approval_key.as_ref().map(|key| key.0), name)
    }

    pub(super) fn remove_if_matches(
        identity: &EntryIdentity,
        expected: &RunValueSlots,
    ) -> Result<(), RemovalPlatformError> {
        if !expected.is_valid(true) {
            return Err(error(
                StartupErrorKind::InvalidIntent,
                "The removal snapshot is invalid or exceeds the safety bound.",
            )
            .into());
        }
        let (run_path, approval_path, name, view) = validated_identity(identity)?;
        apply_transactional_slots(
            run_path,
            approval_path,
            name,
            view,
            expected,
            &RunValueSlots::absent(),
        )
    }

    pub(super) fn restore_if_matches(
        identity: &EntryIdentity,
        expected_current: &RunValueSlots,
        desired: &RunValueSlots,
    ) -> Result<(), RemovalPlatformError> {
        if !desired.is_valid(true)
            || !expected_current.is_valid(false)
            || !expected_current.contains_only_original_or_absent(desired)
        {
            return Err(error(
                StartupErrorKind::InvalidIntent,
                "The restore snapshots are invalid or would overwrite a changed registry value.",
            )
            .into());
        }
        let (run_path, approval_path, name, view) = validated_identity(identity)?;
        apply_transactional_slots(
            run_path,
            approval_path,
            name,
            view,
            expected_current,
            desired,
        )
    }

    fn apply_transactional_slots(
        run_path: &str,
        approval_path: &str,
        name: &str,
        view: RegistryView,
        expected: &RunValueSlots,
        desired: &RunValueSlots,
    ) -> Result<(), RemovalPlatformError> {
        apply_transactional_slots_with_hooks(
            run_path,
            approval_path,
            name,
            view,
            expected,
            desired,
            || {},
            || {},
        )
    }

    fn apply_transactional_slots_with_hooks(
        run_path: &str,
        approval_path: &str,
        name: &str,
        view: RegistryView,
        expected: &RunValueSlots,
        desired: &RunValueSlots,
        after_staging: impl FnOnce(),
        after_validation: impl FnOnce(),
    ) -> Result<(), RemovalPlatformError> {
        if expected == desired {
            return Err(error(
                StartupErrorKind::InvalidIntent,
                "A transactional registry operation must change at least one exact value.",
            )
            .into());
        }
        let transaction = Transaction::begin()?;
        let write_access = REG_SAM_FLAGS(KEY_QUERY_VALUE.0 | KEY_SET_VALUE.0);
        let run_tx = if expected.run != desired.run {
            Some(open_transacted_key(
                run_path,
                write_access,
                view,
                &transaction,
            )?)
        } else {
            None
        };
        let approval_tx = if expected.approval != desired.approval {
            Some(open_transacted_key(
                approval_path,
                write_access,
                view,
                &transaction,
            )?)
        } else {
            None
        };
        let run_public = open_key(run_path, KEY_QUERY_VALUE, view)?;
        let approval_public = open_key_optional(approval_path, KEY_QUERY_VALUE, view)?;

        // Stage every value that will change before validating its public
        // pre-state. Native fixtures for optimizer_registry_tx exercise this
        // TxR ordering, including intervening create/delete/modify races.
        if desired.run.is_none() {
            if let Some(key) = &run_tx {
                stage_value(key.0, name, None)?;
            }
        } else if expected.run != desired.run {
            if let Some(key) = &run_tx {
                stage_value(key.0, name, desired.run.as_ref())?;
            }
        }
        if desired.approval.is_none() {
            if let Some(key) = &approval_tx {
                stage_value(key.0, name, None)?;
            }
        } else if expected.approval != desired.approval {
            if let Some(key) = &approval_tx {
                stage_value(key.0, name, desired.approval.as_ref())?;
            }
        }
        after_staging();

        let public = read_slots_on_keys(
            run_public.0,
            approval_public.as_ref().map(|key| key.0),
            name,
        )?;
        if &public != expected {
            return Err(error(
                StartupErrorKind::ChangedSinceReview,
                "The registry values changed before transactional validation; staged changes were rolled back.",
            )
            .into());
        }
        after_validation();
        drop(approval_tx);
        drop(run_tx);
        drop(approval_public);
        drop(run_public);
        transaction.commit()
    }

    fn stage_value(
        key: HKEY,
        name: &str,
        desired: Option<&RegistryValueSnapshot>,
    ) -> Result<(), StartupError> {
        let name = wide(name);
        let status = match desired {
            Some(value) => unsafe {
                RegSetValueExW(
                    key,
                    PCWSTR(name.as_ptr()),
                    None,
                    REG_VALUE_TYPE(value.value_type),
                    Some(&value.data),
                )
            },
            None => unsafe { RegDeleteValueW(key, PCWSTR(name.as_ptr())) },
        };
        if status == ERROR_SUCCESS {
            return Ok(());
        }
        if status.0 == ERROR_FILE_NOT_FOUND.0 {
            return Err(error(
                StartupErrorKind::ChangedSinceReview,
                "A selected registry value disappeared before transactional staging.",
            ));
        }
        Err(registry_error(
            "stage a transactional registry value",
            status.0,
        ))
    }

    #[cfg(test)]
    mod transaction_fixtures {
        use super::*;
        use std::cell::Cell;
        use windows::Win32::Foundation::ERROR_TRANSACTIONAL_CONFLICT;
        use windows::Win32::System::Registry::{
            REG_OPTION_NON_VOLATILE, RegCreateKeyExW, RegDeleteTreeW,
        };

        const FIXTURE_PREFIX: &str = "Software\\DCleaner-Startup-Removal-Fixture-";

        struct Fixture {
            base: String,
            run_path: String,
            approval_path: String,
            view: RegistryView,
            run: Option<Key>,
            approval: Option<Key>,
        }

        impl Fixture {
            fn new(view: RegistryView) -> Self {
                Self::with_approval(view, true)
            }

            fn without_approval_key(view: RegistryView) -> Self {
                Self::with_approval(view, false)
            }

            fn with_approval(view: RegistryView, create_approval: bool) -> Self {
                let base = format!("{FIXTURE_PREFIX}{}", Uuid::new_v4());
                let run_path = format!("{base}\\Run");
                let approval_path = format!("{base}\\StartupApproved\\Run");
                let run = Some(create_key(&run_path, view));
                let approval = create_approval.then(|| create_key(&approval_path, view));
                Self {
                    base,
                    run_path,
                    approval_path,
                    view,
                    run,
                    approval,
                }
            }

            fn run(&self) -> HKEY {
                self.run.as_ref().expect("fixture run key").0
            }

            fn approval(&self) -> HKEY {
                self.approval.as_ref().expect("fixture approval key").0
            }

            fn read(&self, name: &str) -> RunValueSlots {
                read_slots_on_keys(self.run(), self.approval.as_ref().map(|key| key.0), name)
                    .unwrap()
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                drop(self.run.take());
                drop(self.approval.take());
                assert!(self.base.starts_with(FIXTURE_PREFIX));
                let path = wide(&self.base);
                let result = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(path.as_ptr())) };
                if !std::thread::panicking() {
                    assert_eq!(result, ERROR_SUCCESS);
                }
            }
        }

        fn view_flag(view: RegistryView) -> u32 {
            match view {
                RegistryView::Registry32 => KEY_WOW64_32KEY.0,
                RegistryView::Registry64 => KEY_WOW64_64KEY.0,
                RegistryView::LegacyUnknown => panic!("fixture requires an explicit view"),
            }
        }

        fn create_key(path: &str, view: RegistryView) -> Key {
            let path = wide(path);
            let mut handle = HKEY(ptr::null_mut());
            let result = unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(path.as_ptr()),
                    None,
                    PCWSTR::null(),
                    REG_OPTION_NON_VOLATILE,
                    REG_SAM_FLAGS(KEY_QUERY_VALUE.0 | KEY_SET_VALUE.0 | view_flag(view)),
                    None,
                    &mut handle,
                    None,
                )
            };
            assert_eq!(result, ERROR_SUCCESS);
            Key(handle)
        }

        fn raw(value_type: u32, data: &[u8]) -> RegistryValueSnapshot {
            RegistryValueSnapshot {
                value_type,
                data: data.to_vec(),
            }
        }

        fn write(key: HKEY, name: &str, value: &RegistryValueSnapshot) -> u32 {
            let name = wide(name);
            unsafe {
                RegSetValueExW(
                    key,
                    PCWSTR(name.as_ptr()),
                    None,
                    REG_VALUE_TYPE(value.value_type),
                    Some(&value.data),
                )
                .0
            }
        }

        fn test_slots() -> RunValueSlots {
            RunValueSlots {
                run: Some(raw(1, &[b'a', 0, b'.', 0, b'e', 0, b'x', 0, b'e', 0, 0, 0])),
                approval: Some(raw(3, &[2, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0])),
            }
        }

        fn seed(fixture: &Fixture, slots: &RunValueSlots) {
            let name = "FixtureEntry";
            assert_eq!(write(fixture.run(), name, slots.run.as_ref().unwrap()), 0);
            if let Some(approval) = &slots.approval {
                assert_eq!(write(fixture.approval(), name, approval), 0);
            }
        }

        #[test]
        fn transactional_remove_and_restore_preserve_exact_raw_slots_in_disposable_hkcu_keys() {
            for view in [RegistryView::Registry32, RegistryView::Registry64] {
                let fixture = Fixture::new(view);
                let original = test_slots();
                seed(&fixture, &original);
                assert_eq!(fixture.read("FixtureEntry"), original);

                apply_transactional_slots(
                    &fixture.run_path,
                    &fixture.approval_path,
                    "FixtureEntry",
                    fixture.view,
                    &original,
                    &RunValueSlots::absent(),
                )
                .unwrap();
                assert_eq!(fixture.read("FixtureEntry"), RunValueSlots::absent());

                apply_transactional_slots(
                    &fixture.run_path,
                    &fixture.approval_path,
                    "FixtureEntry",
                    fixture.view,
                    &RunValueSlots::absent(),
                    &original,
                )
                .unwrap();
                assert_eq!(fixture.read("FixtureEntry"), original);
            }
        }

        #[test]
        fn transactional_remove_handles_missing_startupapproved_key_without_creating_it() {
            let fixture = Fixture::without_approval_key(RegistryView::Registry64);
            let original = RunValueSlots {
                run: Some(raw(1, &[b'a', 0, 0, 0])),
                approval: None,
            };
            seed(&fixture, &original);
            apply_transactional_slots(
                &fixture.run_path,
                &fixture.approval_path,
                "FixtureEntry",
                fixture.view,
                &original,
                &RunValueSlots::absent(),
            )
            .unwrap();
            assert_eq!(fixture.read("FixtureEntry"), RunValueSlots::absent());
            assert!(fixture.approval.is_none());
        }

        #[test]
        fn transactional_validation_rolls_back_when_public_value_changed_after_staging() {
            let fixture = Fixture::new(RegistryView::Registry64);
            let original = test_slots();
            seed(&fixture, &original);
            let foreign = raw(
                1,
                &[
                    b'f', 0, b'o', 0, b'r', 0, b'e', 0, b'i', 0, b'g', 0, b'n', 0, 0, 0,
                ],
            );
            let foreign_status = Cell::new(u32::MAX);
            let result = apply_transactional_slots_with_hooks(
                &fixture.run_path,
                &fixture.approval_path,
                "FixtureEntry",
                fixture.view,
                &original,
                &RunValueSlots::absent(),
                || foreign_status.set(write(fixture.run(), "FixtureEntry", &foreign)),
                || {},
            );
            let state = fixture.read("FixtureEntry");
            if foreign_status.get() == ERROR_SUCCESS.0 {
                assert!(matches!(
                    result,
                    Err(RemovalPlatformError::BeforeCommit(StartupError {
                        kind: StartupErrorKind::ChangedSinceReview,
                        ..
                    }))
                ));
                assert_eq!(state.run, Some(foreign));
                assert_eq!(state.approval, original.approval);
            } else {
                assert_eq!(foreign_status.get(), ERROR_TRANSACTIONAL_CONFLICT.0);
                assert!(result.is_ok());
                assert_eq!(state, RunValueSlots::absent());
            }
        }

        #[test]
        fn transactional_commit_conflict_never_overwrites_a_successful_foreign_writer() {
            let fixture = Fixture::new(RegistryView::Registry64);
            let original = test_slots();
            seed(&fixture, &original);
            let foreign = raw(
                1,
                &[
                    b'f', 0, b'o', 0, b'r', 0, b'e', 0, b'i', 0, b'g', 0, b'n', 0, 0, 0,
                ],
            );
            let foreign_status = Cell::new(u32::MAX);
            let result = apply_transactional_slots_with_hooks(
                &fixture.run_path,
                &fixture.approval_path,
                "FixtureEntry",
                fixture.view,
                &original,
                &RunValueSlots::absent(),
                || {},
                || foreign_status.set(write(fixture.run(), "FixtureEntry", &foreign)),
            );
            let state = fixture.read("FixtureEntry");
            if foreign_status.get() == ERROR_SUCCESS.0 {
                assert!(matches!(
                    result,
                    Err(RemovalPlatformError::CommitUncertain(_))
                ));
                assert_eq!(state.run, Some(foreign));
                assert_eq!(state.approval, original.approval);
            } else {
                assert_eq!(foreign_status.get(), ERROR_TRANSACTIONAL_CONFLICT.0);
                assert!(result.is_ok());
                assert_eq!(state, RunValueSlots::absent());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakePlatform {
        states: HashMap<StartupId, ObservedState>,
        slots: HashMap<StartupId, RunValueSlots>,
        remove_calls: usize,
        restore_calls: usize,
        fail_after_run_delete: bool,
    }

    impl RunValueRemovalPlatform for FakePlatform {
        fn observe(&mut self, id: &StartupId) -> Result<ObservedState, StartupError> {
            self.states
                .get(id)
                .cloned()
                .ok_or_else(|| error(StartupErrorKind::UnknownId, "fixture entry is absent"))
        }

        fn observe_slots(
            &mut self,
            identity: &EntryIdentity,
        ) -> Result<RunValueSlots, StartupError> {
            let id = StartupId::for_identity(identity);
            self.slots
                .get(&id)
                .cloned()
                .ok_or_else(|| error(StartupErrorKind::UnknownId, "fixture slots are absent"))
        }

        fn remove_if_matches(
            &mut self,
            identity: &EntryIdentity,
            expected: &RunValueSlots,
        ) -> Result<(), RemovalPlatformError> {
            let id = StartupId::for_identity(identity);
            let current = self
                .slots
                .get_mut(&id)
                .ok_or_else(|| error(StartupErrorKind::UnknownId, "fixture slots are absent"))?;
            if current != expected {
                return Err(error(StartupErrorKind::ChangedSinceReview, "fixture changed").into());
            }
            self.remove_calls += 1;
            current.run = None;
            if self.fail_after_run_delete {
                return Err(RemovalPlatformError::CommitUncertain(error(
                    StartupErrorKind::NativeFailure,
                    "fixture commit acknowledgement was lost after a partial native change",
                )));
            }
            current.approval = None;
            self.states.remove(&id);
            Ok(())
        }

        fn restore_if_matches(
            &mut self,
            identity: &EntryIdentity,
            expected_current: &RunValueSlots,
            desired: &RunValueSlots,
        ) -> Result<(), RemovalPlatformError> {
            let id = StartupId::for_identity(identity);
            let current = self
                .slots
                .get_mut(&id)
                .ok_or_else(|| error(StartupErrorKind::UnknownId, "fixture slots are absent"))?;
            if current != expected_current || !current.contains_only_original_or_absent(desired) {
                return Err(error(StartupErrorKind::ChangedSinceReview, "fixture changed").into());
            }
            self.restore_calls += 1;
            if current.approval.is_none() {
                current.approval = desired.approval.clone();
            }
            if current.run.is_none() {
                current.run = desired.run.clone();
            }
            self.states
                .insert(id.clone(), observed_for(id, identity.clone(), desired));
            Ok(())
        }
    }

    fn identity(view: RegistryView) -> EntryIdentity {
        EntryIdentity::StartupRunValue {
            hive: RegistryHive::CurrentUser,
            view,
            key: RUN_KEY.into(),
            value_name: "FixtureEntry".into(),
            approval_hive: RegistryHive::CurrentUser,
            approval_key: APPROVAL_KEY.into(),
        }
    }

    fn slots() -> RunValueSlots {
        RunValueSlots {
            run: Some(RegistryValueSnapshot {
                value_type: 2,
                data: b"%ProgramFiles%\\Example\\app.exe\0".to_vec(),
            }),
            approval: Some(RegistryValueSnapshot {
                value_type: 3,
                data: vec![3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            }),
        }
    }

    fn observed_for(
        id: StartupId,
        identity: EntryIdentity,
        slots: &RunValueSlots,
    ) -> ObservedState {
        ObservedState {
            id,
            identity,
            enabled: crate::startup::EnabledState::Disabled,
            native: NativeState::StartupRunValue {
                value: slots.run.clone().expect("fixture run value"),
                approval: slots.approval.clone(),
            },
        }
    }

    fn manager() -> (
        RunValueRemovalManager<FakePlatform>,
        StartupId,
        RunValueSlots,
    ) {
        let identity = identity(RegistryView::Registry64);
        let id = StartupId::for_identity(&identity);
        let slots = slots();
        let observed = observed_for(id.clone(), identity, &slots);
        let mut platform = FakePlatform::default();
        platform.states.insert(id.clone(), observed);
        platform.slots.insert(id.clone(), slots.clone());
        (RunValueRemovalManager::new(platform), id, slots)
    }

    #[test]
    fn only_exact_current_user_run_value_with_known_view_is_eligible() {
        assert!(supports_run_value_removal(&identity(
            RegistryView::Registry64
        )));
        assert!(supports_run_value_removal(&identity(
            RegistryView::Registry32
        )));
        assert!(!supports_run_value_removal(&identity(
            RegistryView::LegacyUnknown
        )));
        let mut run_once = identity(RegistryView::Registry64);
        if let EntryIdentity::StartupRunValue { key, .. } = &mut run_once {
            *key = r"Software\Microsoft\Windows\CurrentVersion\RunOnce".into();
        }
        assert!(!supports_run_value_removal(&run_once));
        let mut machine = identity(RegistryView::Registry64);
        if let EntryIdentity::StartupRunValue { hive, .. } = &mut machine {
            *hive = RegistryHive::LocalMachine;
        }
        assert!(!supports_run_value_removal(&machine));
    }

    #[test]
    fn removal_snapshots_exact_raw_types_and_restore_refuses_foreign_collision() {
        let (mut manager, id, original) = manager();
        let intent = manager.prepare_removal(&id).unwrap();
        assert_eq!(intent.before, original);
        let receipt = manager.apply_removal(&intent).unwrap();
        assert_eq!(receipt.outcome, RemovalOutcome::Removed);
        assert_eq!(receipt.after, Some(RunValueSlots::absent()));
        assert!(valid_removal_receipt(&receipt));

        let restore = manager.prepare_restore_from_receipt(&receipt).unwrap();
        assert!(valid_restore_intent(&restore));
        let restored = manager.apply_restore(&restore).unwrap();
        assert_eq!(restored.outcome, RemovalRestoreOutcome::Restored);
        assert_eq!(restored.after, Some(original.clone()));
        assert!(valid_restore_receipt(&restored));

        let fake = manager.platform_mut();
        let changed = fake.slots.get_mut(&id).unwrap();
        changed.run.as_mut().unwrap().data = b"foreign.exe\0".to_vec();
        assert!(manager.prepare_restore_from_receipt(&receipt).is_err());
    }

    #[test]
    fn removal_supports_run_value_without_startupapproved_marker() {
        let (mut manager, id, _) = manager();
        let fake = manager.platform_mut();
        fake.slots.get_mut(&id).unwrap().approval = None;
        let observed = fake.states.get_mut(&id).unwrap();
        let NativeState::StartupRunValue { approval, .. } = &mut observed.native else {
            unreachable!();
        };
        *approval = None;

        let intent = manager.prepare_removal(&id).unwrap();
        assert_eq!(intent.before.approval, None);
        let receipt = manager.apply_removal(&intent).unwrap();
        assert_eq!(receipt.outcome, RemovalOutcome::Removed);
        assert_eq!(receipt.after, Some(RunValueSlots::absent()));
    }

    #[test]
    fn stale_raw_value_changes_abort_before_delete_call() {
        let (mut manager, id, _) = manager();
        let intent = manager.prepare_removal(&id).unwrap();
        manager
            .platform_mut()
            .slots
            .get_mut(&id)
            .unwrap()
            .run
            .as_mut()
            .unwrap()
            .data = b"new.exe\0".to_vec();
        assert_eq!(
            manager.apply_removal(&intent).unwrap_err().kind,
            StartupErrorKind::ChangedSinceReview
        );
        assert_eq!(manager.platform().remove_calls, 0);
    }

    #[test]
    fn uncertain_partial_delete_is_not_retried_and_reviewed_restore_fills_only_missing_slot() {
        let (mut manager, id, original) = manager();
        manager.platform_mut().fail_after_run_delete = true;
        let intent = manager.prepare_removal(&id).unwrap();
        let receipt = manager.apply_removal(&intent).unwrap();
        assert_eq!(receipt.outcome, RemovalOutcome::Uncertain);
        assert_eq!(
            receipt.after,
            Some(RunValueSlots {
                run: None,
                approval: original.approval.clone(),
            })
        );
        assert_eq!(manager.platform().remove_calls, 1);

        manager.platform_mut().fail_after_run_delete = false;
        let restore = manager.prepare_restore_from_receipt(&receipt).unwrap();
        let restored = manager.apply_restore(&restore).unwrap();
        assert_eq!(restored.outcome, RemovalRestoreOutcome::Restored);
        assert_eq!(restored.after, Some(original));
        assert_eq!(manager.platform().remove_calls, 1);
    }

    #[test]
    fn invalid_unbounded_or_nil_intents_are_refused() {
        let (mut manager, id, _) = manager();
        let mut intent = manager.prepare_removal(&id).unwrap();
        intent.operation_id = Uuid::nil();
        assert!(!valid_removal_intent(&intent));
        intent.operation_id = Uuid::new_v4();
        intent
            .before
            .run
            .as_mut()
            .unwrap()
            .data
            .resize(MAX_VALUE_BYTES + 1, 0);
        assert!(!valid_removal_intent(&intent));
    }
}
