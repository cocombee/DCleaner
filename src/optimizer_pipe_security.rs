//! Windows principal and descriptor boundary for the future optimizer service.
//!
//! Production pipes require LocalSystem ownership, an exact protected DACL and
//! client data rights without FILE_CREATE_PIPE_INSTANCE. Server-side caller
//! identity comes from the last message read, never from a frame's identifiers.
//! Live identity includes account, Windows session and the native logon SID.
//! This is not executable identity or complete durable lease/idempotency scope.
//!
//! Nothing here is called by application startup or installs a service. Tests
//! use a private current-owner policy and random names; they cannot prove the
//! deployed LocalSystem/protected-binary boundary.

#![allow(dead_code)] // Internal until protected service packaging/owner exist.

pub(crate) mod helper_image;

use crate::{
    optimizer_pipe_io::PipeIo,
    optimizer_protocol::{self as codec, ProtocolError, RequestEnvelope},
};
use std::{
    ffi::c_void,
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use windows::{
    Win32::{
        Foundation::{
            ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN, ERROR_NOT_FOUND, ERROR_PIPE_BUSY,
            ERROR_SEM_TIMEOUT, HANDLE, HLOCAL, LocalFree,
        },
        Security::{
            ACE_HEADER, ACL,
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
                SE_KERNEL_OBJECT, SE_OBJECT_TYPE, SE_REGISTRY_KEY,
            },
            DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorControl,
            GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, IsValidAcl,
            IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
            SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES, TOKEN_GROUPS,
            TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER, TokenLogonSid, TokenSessionId,
            TokenUser,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_ALL_ACCESS, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
            FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_MODE, FILE_WRITE_DATA, OPEN_EXISTING,
            PIPE_ACCESS_DUPLEX, READ_CONTROL, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
            SYNCHRONIZE,
        },
        System::{
            Pipes::{
                CreateNamedPipeW, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
                PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, WaitNamedPipeW,
            },
            Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
        },
    },
    core::{BOOL, PCWSTR, PWSTR},
};

// Native CreateFileW fixtures reject the same policy without READ_ATTRIBUTES,
// including outside the sandbox. This still excludes append/create-instance,
// attribute writes, DACL writes and generic write access.
pub(crate) const CLIENT_ACCESS: u32 =
    FILE_READ_DATA.0 | FILE_WRITE_DATA.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | SYNCHRONIZE.0;
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_ACL_BYTES: usize = 4096;
const MAX_SID_BYTES: usize = 68;

fn native(error: windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error((error.code().0 as u32 & 0xffff) as i32)
}
fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

struct LocalMemory(*mut c_void);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: ownership is received only from LocalAlloc-based Win32 APIs.
            unsafe { LocalFree(Some(HLOCAL(self.0))) };
        }
    }
}

/// Aligned owned SID bytes; no native pointer survives its source allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Sid(Vec<u32>);
impl Sid {
    fn parse(text: &str) -> io::Result<Self> {
        if text.len() > 184 || text.contains('\0') {
            return Err(invalid("Invalid SID string."));
        }
        let mut sid = PSID::default();
        // SAFETY: bounded NUL-terminated input and an output slot.
        unsafe { ConvertStringSidToSidW(PCWSTR(wide(text).as_ptr()), &mut sid) }.map_err(native)?;
        let memory = LocalMemory(sid.0);
        // SAFETY: the API returned a valid SID allocation of its native length.
        let result = unsafe { Self::copy(sid, MAX_SID_BYTES) }?;
        // The converter can accept aliases/noncanonical or overflowing numeric
        // strings. Require the exact native spelling before using it as identity.
        if result.text()? != text {
            return Err(invalid("SID text is not canonical."));
        }
        drop(memory);
        Ok(result)
    }

    /// `sid` must refer to a readable SID header in `available` readable bytes.
    unsafe fn copy(sid: PSID, available: usize) -> io::Result<Self> {
        if sid.0.is_null() || available < 8 {
            return Err(invalid("Missing SID header."));
        }
        // SAFETY: header is readable; validate variable length before native use.
        let count = unsafe { sid.0.cast::<u8>().add(1).read() } as usize;
        let bytes = 8 + count * 4;
        if bytes > available || bytes > MAX_SID_BYTES || count > 15 {
            return Err(invalid("SID exceeds its native buffer."));
        }
        // SAFETY: the entire variable-length SID is now inside the source bound.
        if !unsafe { IsValidSid(sid) }.as_bool() {
            return Err(invalid("Native SID is invalid."));
        }
        let mut owned = vec![0u32; bytes / 4];
        // SAFETY: disjoint allocations, bounded source and aligned destination.
        unsafe { ptr::copy_nonoverlapping(sid.0.cast::<u8>(), owned.as_mut_ptr().cast(), bytes) };
        Ok(Self(owned))
    }

    fn as_sid(&self) -> PSID {
        PSID(self.0.as_ptr().cast_mut().cast())
    }

    fn text(&self) -> io::Result<String> {
        let mut text = PWSTR::null();
        // SAFETY: this type owns a validated, aligned, immutable SID.
        unsafe { ConvertSidToStringSidW(self.as_sid(), &mut text) }.map_err(native)?;
        let _memory = LocalMemory(text.0.cast());
        // SAFETY: native output is a NUL-terminated SID string, at most 184 chars.
        unsafe { text.to_string() }.map_err(|_| invalid("Invalid native SID text."))
    }
}

struct TokenBuffer {
    words: Vec<usize>,
    bytes: usize,
}
impl TokenBuffer {
    fn as_ptr(&self) -> *const usize {
        self.words.as_ptr()
    }
}
fn token_information(
    token: BorrowedHandle<'_>,
    class: TOKEN_INFORMATION_CLASS,
) -> io::Result<TokenBuffer> {
    let token = HANDLE(token.as_raw_handle());
    let mut needed = 0;
    // SAFETY: sizing call has no output buffer.
    let sized = unsafe { GetTokenInformation(token, class, None, 0, &mut needed) };
    if let Err(error) = sized
        && error.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult()
    {
        return Err(native(error));
    }
    for _ in 0..2 {
        let capacity = needed as usize;
        if capacity == 0 || capacity > MAX_TOKEN_BYTES {
            return Err(invalid("Token information exceeds its inspection bound."));
        }
        // usize alignment supports TOKEN_USER's pointer and the session DWORD.
        let mut buffer = vec![0usize; capacity.div_ceil(size_of::<usize>())];
        // SAFETY: native capacity is no larger than the allocated aligned buffer.
        match unsafe {
            GetTokenInformation(
                token,
                class,
                Some(buffer.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        } {
            Ok(()) if needed > 0 && needed as usize <= capacity => {
                return Ok(TokenBuffer {
                    words: buffer,
                    bytes: needed as usize,
                });
            }
            Ok(()) => return Err(invalid("Token information length changed unexpectedly.")),
            Err(error) if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {}
            Err(error) => return Err(native(error)),
        }
    }
    Err(invalid("Token information did not stabilize."))
}

fn logon_sid(buffer: &TokenBuffer) -> io::Result<Option<Sid>> {
    if buffer.bytes < size_of::<u32>() || buffer.bytes > buffer.words.len() * size_of::<usize>() {
        return Err(invalid("Token logon groups are truncated."));
    }
    let count = unsafe { buffer.as_ptr().cast::<u32>().read() };
    if count == 0 {
        return Ok(None);
    }
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    let prefix = offset + size_of::<SID_AND_ATTRIBUTES>();
    if count != 1 || buffer.bytes < prefix {
        return Err(invalid("Token logon groups are ambiguous or truncated."));
    }
    let group = unsafe {
        buffer
            .as_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<SID_AND_ATTRIBUTES>()
            .read()
    };
    // SE_GROUP_LOGON_ID, SE_GROUP_ENABLED and SE_GROUP_USE_FOR_DENY_ONLY.
    if group.Attributes & 0xc000_0000 != 0xc000_0000
        || group.Attributes & 4 == 0
        || group.Attributes & 0x10 != 0
    {
        return Err(invalid("Token logon SID is not an enabled logon group."));
    }
    let start = buffer.as_ptr() as usize;
    let end = start
        .checked_add(buffer.bytes)
        .ok_or_else(|| invalid("Token logon buffer overflows."))?;
    let at = group.Sid.0 as usize;
    if at < start + prefix || at > end || at % std::mem::align_of::<u32>() != 0 {
        return Err(invalid("Token logon SID is outside its native payload."));
    }
    let sid = unsafe { Sid::copy(group.Sid, end - at) }?;
    let text = sid.text()?;
    if text.split('-').count() != 6 || !text.starts_with("S-1-5-5-") {
        return Err(invalid("Token group is not a logon SID."));
    }
    Ok(Some(sid))
}

fn thread_token() -> io::Result<Option<OwnedHandle>> {
    let mut token = HANDLE::default();
    // SAFETY: current-thread pseudo-handle and a new owned token output slot.
    match unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) } {
        Ok(()) => Ok(Some(unsafe { OwnedHandle::from_raw_handle(token.0) })),
        Err(error) if error.code() == ERROR_NO_TOKEN.to_hresult() => Ok(None),
        Err(error) => Err(native(error)),
    }
}

fn effective_token() -> io::Result<OwnedHandle> {
    if let Some(token) = thread_token()? {
        return Ok(token);
    }
    let mut token = HANDLE::default();
    // SAFETY: current-process pseudo-handle and an owned token output slot.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(native)?;
    Ok(unsafe { OwnedHandle::from_raw_handle(token.0) })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Principal {
    user: Sid,
    session: u32,
    logon: Option<Sid>,
    boot: uuid::Uuid,
}
impl Principal {
    /// The service obtains identity from a Windows session token, not a frame.
    pub(crate) fn logged_on_session(session: u32) -> io::Result<Self> {
        let (_, principal) = Self::logged_on_session_token(session)?;
        Ok(principal)
    }
    /// Retain the primary token from WTS for native creation in this exact live
    /// logon. Never substitute a caller-supplied token, PID or account string.
    pub(crate) fn logged_on_session_token(session: u32) -> io::Result<(OwnedHandle, Self)> {
        use std::os::windows::io::AsHandle;
        use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;
        Self::require_local_system()?;
        if session == 0 {
            return Err(denied("Session zero is not an interactive client."));
        }
        let mut token = HANDLE::default();
        unsafe { WTSQueryUserToken(session, &mut token) }.map_err(native)?;
        let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
        let principal = Self::from_token(token.as_handle())?;
        if principal.session != session
            || principal.user == Sid::parse("S-1-5-18")?
            || principal.logon.is_none()
        {
            return Err(denied(
                "The session token does not identify its interactive client.",
            ));
        }
        Ok((token, principal))
    }
    pub(crate) fn require_local_system() -> io::Result<()> {
        if thread_token()?.is_some() || Self::current()?.user != Sid::parse("S-1-5-18")? {
            return Err(denied(
                "The optimizer owner requires an unimpersonated LocalSystem process.",
            ));
        }
        Ok(())
    }
    pub(crate) fn current() -> io::Result<Self> {
        use std::os::windows::io::AsHandle;
        Self::from_token(effective_token()?.as_handle())
    }

    pub(crate) fn from_token(token: BorrowedHandle<'_>) -> io::Result<Self> {
        let user = token_information(token, TokenUser)?;
        if user.bytes < size_of::<TOKEN_USER>() {
            return Err(invalid("Token user buffer is truncated."));
        }
        // SAFETY: aligned buffer contains the fixed TOKEN_USER prefix.
        let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let start = user.as_ptr() as usize;
        let end = start + user.bytes;
        let at = sid.0 as usize;
        if at < start || at > end {
            return Err(invalid("Token user SID is outside its native buffer."));
        }
        // SAFETY: checked source allocation bound; copy validates SID length.
        let user = unsafe { Sid::copy(sid, end - at) }?;
        let session = token_information(token, TokenSessionId)?;
        if session.bytes < size_of::<u32>() {
            return Err(invalid("Token session buffer is truncated."));
        }
        // SAFETY: aligned buffer contains a session DWORD.
        let session = unsafe { session.as_ptr().cast::<u32>().read() };
        let logon = if user == Sid::parse("S-1-5-18")? {
            None
        } else {
            match token_information(token, TokenLogonSid) {
                Ok(buffer) => logon_sid(&buffer)?,
                Err(error) if error.raw_os_error() == Some(ERROR_NOT_FOUND.0 as i32) => None,
                Err(error) => return Err(error),
            }
        };
        Ok(Self {
            user,
            session,
            logon,
            boot: crate::optimizer_boot::current()?,
        })
    }

    pub(crate) fn user_sid(&self) -> io::Result<String> {
        self.user.text()
    }
    /// The owner Windows assigns to objects this process creates. Elevated
    /// administrator tokens default to BUILTIN\Administrators, not the user.
    #[cfg(test)]
    pub(crate) fn default_owner_sid() -> io::Result<String> {
        use std::os::windows::io::AsHandle;
        use windows::Win32::Security::{TOKEN_OWNER, TokenOwner};
        let token = effective_token()?;
        let owner = token_information(token.as_handle(), TokenOwner)?;
        if owner.bytes < size_of::<TOKEN_OWNER>() {
            return Err(invalid("Token owner buffer is truncated."));
        }
        // SAFETY: aligned buffer contains the fixed TOKEN_OWNER prefix.
        let sid = unsafe { (*owner.as_ptr().cast::<TOKEN_OWNER>()).Owner };
        let start = owner.as_ptr() as usize;
        let end = start + owner.bytes;
        let at = sid.0 as usize;
        if at < start || at > end {
            return Err(invalid("Token owner SID is outside its native buffer."));
        }
        // SAFETY: checked source allocation bound; copy validates SID length.
        unsafe { Sid::copy(sid, end - at) }?.text()
    }
    pub(crate) fn session_id(&self) -> u32 {
        self.session
    }
    pub(crate) fn logon_sid(&self) -> io::Result<Option<String>> {
        self.logon.as_ref().map(Sid::text).transpose()
    }
    pub(crate) fn boot_id(&self) -> uuid::Uuid {
        self.boot
    }
    pub(crate) fn is_current_logged_on_session(&self) -> io::Result<bool> {
        Ok(Self::logged_on_session(self.session)? == *self)
    }
}

pub(crate) struct Descriptor(LocalMemory);

/// Registry machine-scope policy; never accepts a caller-selected trust list.
pub(crate) struct RegistryAccess {
    trusted: Vec<Sid>,
    creator_owner: Sid,
}
impl RegistryAccess {
    pub(crate) fn machine() -> io::Result<Self> {
        Ok(Self {
            trusted: [
                "S-1-5-18",
                "S-1-5-32-544",
                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            ]
            .iter()
            .map(|sid| Sid::parse(sid))
            .collect::<io::Result<_>>()?,
            creator_owner: Sid::parse("S-1-3-0")?,
        })
    }
    #[cfg(test)]
    pub(crate) fn fixture() -> io::Result<Self> {
        let mut policy = Self::machine()?;
        policy.trusted.push(Principal::current()?.user);
        Ok(policy)
    }
    pub(crate) fn verify(&self, key: BorrowedHandle<'_>) -> io::Result<()> {
        self.verify_rights(key, false)
    }
    /// Ancestors must protect the child namespace. A value-only writer cannot
    /// redirect a checked descendant and is not authority over the final scope.
    pub(crate) fn verify_namespace(&self, key: BorrowedHandle<'_>) -> io::Result<()> {
        self.verify_rights(key, true)
    }
    fn verify_rights(&self, key: BorrowedHandle<'_>, ancestor: bool) -> io::Result<()> {
        let descriptor = Descriptor::from_handle(key, SE_REGISTRY_KEY)?;
        self.verify_descriptor_rights(&descriptor, ancestor)
    }
    fn verify_descriptor_rights(&self, descriptor: &Descriptor, ancestor: bool) -> io::Result<()> {
        if !self.trusted.contains(&descriptor.owner()?) {
            return Err(denied("Registry scope has an untrusted owner."));
        }
        for ace in descriptor.acl_bytes(false, false)? {
            if ace[1] & !0x1f != 0 {
                return Err(denied("Unsupported registry ACE flags."));
            }
            if ace[1] & 0x08 != 0 {
                continue;
            } // INHERIT_ONLY does not apply to this key.
            if ace[0] == 1 {
                continue;
            } // A deny ACE adds no access.
            if ace[0] != 0 || ace.len() < 16 {
                return Err(denied("Unsupported registry access ACE."));
            }
            let mask = u32::from_le_bytes(
                ace[4..8]
                    .try_into()
                    .map_err(|_| invalid("Invalid registry access mask."))?,
            );
            // Unknown/reserved grant bits cannot establish a read-only grant.
            // MAXIMUM_ALLOWED is an access request, not an accepted ACE grant.
            if mask & !0xf11f_003f != 0 {
                return Err(denied("Unsupported registry access mask."));
            }
            // Set/create/link/delete/ACL/owner rights and generic write/all.
            // Only fixed ancestors may have unrelated value-only writers.
            let mutation = if ancestor { 0x000d_0024 } else { 0x000d_0026 };
            if mask & (mutation | 0x5000_0000) == 0 {
                continue;
            }
            let mut aligned = vec![0u32; ace.len().div_ceil(4)];
            unsafe {
                ptr::copy_nonoverlapping(ace.as_ptr(), aligned.as_mut_ptr().cast::<u8>(), ace.len())
            };
            let sid =
                unsafe { Sid::copy(PSID(aligned.as_mut_ptr().add(2).cast()), ace.len() - 8) }?;
            // CREATOR OWNER is an inheritance placeholder, not another live
            // principal. The current owner was independently checked above;
            // each opened descendant must pass its own owner/access checks.
            let inherited_owner = sid == self.creator_owner && ace[1] & 0x03 != 0;
            if !self.trusted.contains(&sid) && !inherited_owner {
                return Err(denied(
                    "Registry scope grants mutation to an untrusted principal.",
                ));
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod registry_access_cases {
    use super::*;
    #[test]
    fn registry_policy_rejects_reserved_grants_and_untrusted_owner() {
        let policy = RegistryAccess::fixture().unwrap();
        let owner = Principal::current().unwrap().user_sid().unwrap();
        let read =
            Descriptor::from_sddl(&format!("O:{owner}D:P(A;;KA;;;{owner})(A;;KR;;;WD)")).unwrap();
        policy.verify_descriptor_rights(&read, false).unwrap();
        // The native SDDL parser retains the reserved grant in this descriptor;
        // key creation itself may normalize invalid grant bits away.
        let unknown = Descriptor::from_sddl(&format!(
            "O:{owner}D:P(A;;KA;;;{owner})(A;;0x02000000;;;WD)"
        ))
        .unwrap();
        assert!(policy.verify_descriptor_rights(&unknown, false).is_err());
        let foreign_owner = Descriptor::from_sddl("O:WDD:P(A;;KR;;;WD)").unwrap();
        assert!(
            policy
                .verify_descriptor_rights(&foreign_owner, false)
                .is_err()
        );
        let creator =
            Descriptor::from_sddl(&format!("O:{owner}D:P(A;;KA;;;{owner})(A;CI;KA;;;CO)")).unwrap();
        policy.verify_descriptor_rights(&creator, false).unwrap();
        let explicit_creator =
            Descriptor::from_sddl(&format!("O:{owner}D:P(A;;KA;;;{owner})(A;;KA;;;CO)")).unwrap();
        assert!(
            policy
                .verify_descriptor_rights(&explicit_creator, false)
                .is_err()
        );
    }
}
impl Descriptor {
    pub(crate) fn from_sddl(text: &str) -> io::Result<Self> {
        if text.len() > MAX_ACL_BYTES || text.contains('\0') {
            return Err(invalid("Security descriptor exceeds its input bound."));
        }
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: terminated bounded input; API returns LocalAlloc ownership.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide(text).as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(native)?;
        Ok(Self(LocalMemory(descriptor.0)))
    }

    fn from_pipe(pipe: BorrowedHandle<'_>) -> io::Result<Self> {
        Self::from_handle(pipe, SE_KERNEL_OBJECT)
    }

    pub(crate) fn from_file(file: BorrowedHandle<'_>) -> io::Result<Self> {
        Self::from_handle(file, SE_FILE_OBJECT)
    }

    fn from_handle(pipe: BorrowedHandle<'_>, kind: SE_OBJECT_TYPE) -> io::Result<Self> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: valid borrowed handle; API returns a self-relative LocalAlloc SD.
        let status = unsafe {
            GetSecurityInfo(
                HANDLE(pipe.as_raw_handle()),
                kind,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                Some(&mut descriptor),
            )
        };
        if status.0 != 0 {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        Ok(Self(LocalMemory(descriptor.0)))
    }

    pub(crate) fn native(&self) -> PSECURITY_DESCRIPTOR {
        PSECURITY_DESCRIPTOR(self.0.0)
    }

    fn owner(&self) -> io::Result<Sid> {
        let mut owner = PSID::default();
        let mut defaulted = BOOL::default();
        // SAFETY: valid native descriptor held alive by this allocation.
        unsafe { GetSecurityDescriptorOwner(self.native(), &mut owner, &mut defaulted) }
            .map_err(native)?;
        // SAFETY: native SD owns a valid owner SID or null (rejected by copy).
        unsafe { Sid::copy(owner, MAX_SID_BYTES) }
    }

    fn acl(&self) -> io::Result<Vec<Vec<u8>>> {
        self.acl_bytes(true, false)
    }

    pub(crate) fn verify_file(&self, expected: &Self) -> io::Result<()> {
        self.verify_storage_access(expected, true, false)
    }

    /// SQLite creates rollback journals by inheriting the already-verified
    /// root ACL. Only inheritance provenance may differ, never access grants.
    pub(crate) fn verify_journal(&self, expected: &Self) -> io::Result<()> {
        self.verify_storage_access(expected, false, true)
    }

    fn verify_storage_access(
        &self,
        expected: &Self,
        protected: bool,
        inherited: bool,
    ) -> io::Result<()> {
        if self.owner()? != expected.owner()?
            || self.acl_bytes(protected, inherited)? != expected.acl_bytes(true, false)?
        {
            return Err(denied(
                "Optimizer storage owner or exact access policy changed.",
            ));
        }
        Ok(())
    }

    fn acl_bytes(&self, protected: bool, inherited_file: bool) -> io::Result<Vec<Vec<u8>>> {
        let mut control = 0;
        let mut revision = 0;
        let mut present = BOOL::default();
        let mut defaulted = BOOL::default();
        let mut acl: *mut ACL = ptr::null_mut();
        // SAFETY: native APIs only inspect the live native descriptor.
        unsafe {
            GetSecurityDescriptorControl(self.native(), &mut control, &mut revision)
                .map_err(native)?;
            GetSecurityDescriptorDacl(self.native(), &mut present, &mut acl, &mut defaulted)
                .map_err(native)?;
        }
        if (protected && control & SE_DACL_PROTECTED.0 == 0) || !present.as_bool() || acl.is_null()
        {
            return Err(denied("Pipe DACL must be present, protected and non-null."));
        }
        // SAFETY: native descriptor owns this ACL; validate before walking it.
        if !unsafe { IsValidAcl(acl) }.as_bool() {
            return Err(invalid("Native pipe ACL is invalid."));
        }
        let header = unsafe { &*acl };
        if header.AclSize as usize > MAX_ACL_BYTES || header.AceCount > 16 {
            return Err(invalid("Pipe ACL exceeds its inspection bound."));
        }
        let mut entries = Vec::new();
        for index in 0..header.AceCount as u32 {
            let mut ace = ptr::null_mut();
            // SAFETY: GetAce validates the index in the live, valid bounded ACL.
            unsafe { GetAce(acl, index, &mut ace) }.map_err(native)?;
            let start = acl as usize;
            let end = start + header.AclSize as usize;
            let at = ace as usize;
            if at < start || at.saturating_add(size_of::<ACE_HEADER>()) > end {
                return Err(invalid("Pipe ACE header is outside its ACL."));
            }
            let size = unsafe { (*ace.cast::<ACE_HEADER>()).AceSize } as usize;
            if size < size_of::<ACE_HEADER>() || at.saturating_add(size) > end {
                return Err(invalid("Pipe ACE is outside its ACL."));
            }
            // SAFETY: complete ACE lies inside the validated native ACL.
            let mut bytes = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), size) }.to_vec();
            if inherited_file {
                bytes[1] &= !0x10;
            } // INHERITED_ACE is provenance, not added access.
            entries.push(bytes);
        }
        // Plain allow ACE order does not change this exact policy. Preserve
        // multiplicity while comparing order-independent byte representations.
        entries.sort_unstable();
        Ok(entries)
    }
}

/// Policy data comes from service ownership/configuration, never request fields.
/// The production constructor fixes the trusted service account to LocalSystem.
#[derive(Clone)]
pub(crate) struct Policy {
    owner: Sid,
    client: Principal,
    #[cfg(test)]
    fixture: bool,
}

/// Created only from a bounded frame and the identity on that same connection.
/// This is caller identity, not ownership of a lease or authority for effects.
pub(crate) struct AuthenticatedRequest {
    caller: Principal,
    request: RequestEnvelope,
}
impl AuthenticatedRequest {
    pub(crate) fn caller(&self) -> &Principal {
        &self.caller
    }
    pub(crate) fn request(&self) -> &RequestEnvelope {
        &self.request
    }
}

impl Policy {
    #[cfg(test)]
    pub(crate) fn fixture_endpoint() -> io::Result<(Self, OwnedHandle, Vec<u16>)> {
        let client = Principal::current()?;
        let policy = Self {
            owner: client.user.clone(),
            client,
            fixture: true,
        };
        let name = wide(&format!(
            r"\\.\pipe\DCleaner-service-fixture-{}",
            uuid::Uuid::new_v4()
        ));
        let pipe = policy.create_first(&name)?;
        Ok((policy, pipe, name))
    }

    #[cfg(test)]
    pub(crate) fn fixture_connect(
        &self,
        name: &[u16],
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> io::Result<OwnedHandle> {
        self.connect_at(name, deadline, cancel)
    }
    pub(crate) fn local_system(client: Principal) -> io::Result<Self> {
        if client.logon.is_none() || client.boot.is_nil() {
            return Err(denied("Interactive endpoint requires a native logon SID."));
        }
        Ok(Self {
            owner: Sid::parse("S-1-5-18")?,
            client,
            #[cfg(test)]
            fixture: false,
        })
    }
    fn client_access_sid(&self) -> io::Result<&Sid> {
        if let Some(logon) = &self.client.logon {
            return Ok(logon);
        }
        #[cfg(test)]
        if self.fixture {
            return Ok(&self.client.user);
        }
        Err(denied("Endpoint has no native logon SID."))
    }

    fn descriptor(&self) -> io::Result<Descriptor> {
        // Explicit masks avoid generic-right mapping differences in native ACLs.
        Descriptor::from_sddl(&format!(
            "O:{}D:P(A;;0x{:08X};;;S-1-5-18)(A;;0x{:08X};;;{})",
            self.owner.text()?,
            FILE_ALL_ACCESS.0,
            CLIENT_ACCESS,
            self.client_access_sid()?.text()?,
        ))
    }

    pub(crate) fn pipe_name(&self) -> io::Result<Vec<u16>> {
        let mut hash = crate::native_hash::Sha256::new()
            .map_err(|_| invalid("Endpoint scope hash is unavailable."))?;
        for part in [
            b"DCleaner.Reactivation.v3\0".as_slice(),
            self.client.user.text()?.as_bytes(),
            b"\0",
            &self.client.session.to_le_bytes(),
            self.client_access_sid()?.text()?.as_bytes(),
            self.client.boot.as_bytes(),
        ] {
            hash.update(part)
                .map_err(|_| invalid("Endpoint scope hash failed."))?;
        }
        let scope = hash
            .finish()
            .map_err(|_| invalid("Endpoint scope hash failed."))?;
        Ok(wide(&format!(
            r"\\.\pipe\DCleaner.Reactivation.v3.{}.{}",
            self.client.session, scope,
        )))
    }

    /// Before sending a frame: verify owner AND the exact protected ACE list.
    pub(crate) fn verify_service_pipe(&self, pipe: BorrowedHandle<'_>) -> io::Result<()> {
        let actual = Descriptor::from_pipe(pipe)?;
        self.verify_descriptor(&actual)
    }

    fn verify_descriptor(&self, actual: &Descriptor) -> io::Result<()> {
        if actual.owner()? != self.owner || actual.acl()? != self.descriptor()?.acl()? {
            return Err(denied(
                "Pipe owner or access policy does not match the service.",
            ));
        }
        Ok(())
    }

    /// Called only after a complete request has been read on this connection.
    /// Reverts before returning identity or permitting service dispatch.
    fn authenticate_client(&self, pipe: BorrowedHandle<'_>) -> io::Result<Principal> {
        if thread_token()?.is_some() {
            return Err(denied(
                "Cannot replace an existing thread impersonation context.",
            ));
        }
        // SAFETY: caller read this connected server pipe; checked no old context.
        unsafe { ImpersonateNamedPipeClient(HANDLE(pipe.as_raw_handle())) }.map_err(native)?;
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                // SAFETY: this scope alone established the current impersonation.
                // Microsoft requires ending the process if reverting fails.
                if unsafe { RevertToSelf() }.is_err() {
                    std::process::abort();
                }
            }
        }
        let revert = Revert;
        let principal = (|| {
            use std::os::windows::io::AsHandle;
            let token =
                thread_token()?.ok_or_else(|| denied("Pipe client has no queryable token."))?;
            Principal::from_token(token.as_handle())
        })();
        drop(revert);
        let principal = principal?;
        if principal != self.client {
            return Err(denied(
                "Pipe client account, session or logon is not authorized.",
            ));
        }
        Ok(principal)
    }

    /// Keeps frame parsing and native peer identity tied to one serial pipe.
    /// No dispatchable value escapes on parser/authentication failure, and the
    /// exchange is poisoned so callers cannot continue it after an error.
    pub(crate) fn read_authenticated_request(
        &self,
        pipe: &mut PipeIo<'_>,
    ) -> Result<Option<AuthenticatedRequest>, ProtocolError> {
        use std::os::windows::io::AsHandle;
        let result = (|| {
            let Some(request) = codec::read_request(pipe)? else {
                return Ok(None);
            };
            let caller = self
                .authenticate_client(pipe.as_handle())
                .map_err(ProtocolError::Io)?;
            pipe.check_active().map_err(ProtocolError::Io)?;
            Ok(Some(AuthenticatedRequest { caller, request }))
        })();
        if result.is_err() {
            pipe.end_exchange();
        }
        result
    }

    fn require_system_context(&self) -> io::Result<()> {
        if thread_token()?.is_some() || Principal::current()?.user != Sid::parse("S-1-5-18")? {
            return Err(denied(
                "Only the unimpersonated LocalSystem service may bind this endpoint.",
            ));
        }
        Ok(())
    }

    pub(crate) fn bind_first(&self) -> io::Result<OwnedHandle> {
        self.require_system_context()?;
        self.create_first(&self.pipe_name()?)
    }

    fn create_first(&self, name: &[u16]) -> io::Result<OwnedHandle> {
        let descriptor = self.descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.native().0,
            bInheritHandle: BOOL(0),
        };
        // SAFETY: internal terminated local name; descriptor remains alive for
        // creation, handle is non-inheritable, local-only, first-instance byte I/O.
        let pipe = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                16,
                8192,
                8192,
                100,
                Some(&attributes),
            )
        };
        if pipe.is_invalid() {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(pipe.0) })
    }

    pub(crate) fn connect(
        &self,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> io::Result<OwnedHandle> {
        if Principal::current()? != self.client {
            return Err(denied(
                "Client endpoint does not belong to this account/session/logon.",
            ));
        }
        let name = self.pipe_name()?;
        self.connect_at(&name, deadline, cancel)
    }

    fn connect_at(
        &self,
        name: &[u16],
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> io::Result<OwnedHandle> {
        loop {
            check_budget(deadline, cancel)?;
            // SAFETY: fixed local name, minimal specific rights, identification
            // SQOS prevents the peer from using this token to access resources.
            match unsafe {
                CreateFileW(
                    PCWSTR(name.as_ptr()),
                    CLIENT_ACCESS,
                    FILE_SHARE_MODE(0),
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    None,
                )
            } {
                Ok(pipe) => {
                    let pipe = unsafe { OwnedHandle::from_raw_handle(pipe.0) };
                    use std::os::windows::io::AsHandle;
                    self.verify_service_pipe(pipe.as_handle())?;
                    check_budget(deadline, cancel)?;
                    return Ok(pipe);
                }
                Err(error) if error.code() == ERROR_PIPE_BUSY.to_hresult() => {
                    check_budget(deadline, cancel)?;
                    let millis = deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis()
                        .clamp(1, 25) as u32;
                    // SAFETY: same local terminated name; finite native wait.
                    if let Err(error) =
                        unsafe { WaitNamedPipeW(PCWSTR(name.as_ptr()), millis) }.ok()
                        && error.code() != ERROR_SEM_TIMEOUT.to_hresult()
                    {
                        return Err(native(error));
                    }
                }
                Err(error) => return Err(native(error)),
            }
        }
    }
}

fn check_budget(deadline: Instant, cancel: &AtomicBool) -> io::Result<()> {
    if cancel.load(Ordering::Acquire) {
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "Pipe connection was cancelled.",
        ))
    } else if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Pipe connection deadline elapsed.",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    mod logon_cases;
    use super::*;
    use crate::{optimizer_pipe_io::PipeIo, optimizer_protocol as codec};
    use std::{io::Write, os::windows::io::AsHandle, time::Duration};
    use uuid::Uuid;
    use windows::Win32::{
        Foundation::ERROR_ACCESS_DENIED, Storage::FileSystem::FILE_CREATE_PIPE_INSTANCE,
    };

    // This deliberately weaker owner exists only inside this test module. No
    // production caller can select it. It verifies mechanics, not SYSTEM trust.
    fn fixture() -> (Policy, Vec<u16>) {
        let client = Principal::current().unwrap();
        let policy = Policy {
            owner: client.user.clone(),
            client,
            fixture: true,
        };
        let name = wide(&format!(
            r"\\.\pipe\DCleaner-security-fixture-{}",
            Uuid::new_v4()
        ));
        (policy, name)
    }

    #[test]
    fn native_principal_is_owned_canonical_and_session_scoped() {
        let actual = Principal::current().unwrap();
        let text = actual.user_sid().unwrap();
        assert_eq!(Sid::parse(&text).unwrap(), actual.user);
        assert_eq!(Sid::parse("S-1-5-18").unwrap().text().unwrap(), "S-1-5-18");
        for bad in [
            "S-1-5-18\0D:(A;;GA;;;WD)",
            "S-1-5-99999999999999999",
            "not-a-sid",
            "SY",
        ] {
            assert!(Sid::parse(bad).is_err());
        }
        let policy = Policy::local_system(actual.clone()).unwrap();
        let name = String::from_utf16(&policy.pipe_name().unwrap()).unwrap();
        assert!(name.starts_with(&format!(
            r"\\.\pipe\DCleaner.Reactivation.v3.{}.",
            actual.session_id()
        )));
        assert!(name.len() <= 256);
        assert!(!name.contains(&text));
        assert_eq!(name.matches('\0').count(), 1);
        assert_eq!(CLIENT_ACCESS, 0x0012_0083);
        assert_eq!(CLIENT_ACCESS & FILE_CREATE_PIPE_INSTANCE.0, 0);
    }

    #[test]
    fn exact_descriptor_rejects_extra_generic_null_and_unprotected_permissions() {
        let (policy, _) = fixture();
        let owner = policy.owner.text().unwrap();
        let client = policy.client_access_sid().unwrap().text().unwrap();
        let system = "(A;;0x001F01FF;;;S-1-5-18)";
        let minimum = format!("(A;;0x00120083;;;{client})");
        // Independent ordering of the same two plain allow entries is harmless.
        let reordered = Descriptor::from_sddl(&format!("O:{owner}D:P{minimum}{system}")).unwrap();
        policy.verify_descriptor(&reordered).unwrap();
        for text in [
            format!("O:{owner}D:{system}{minimum}"),
            format!("O:{owner}D:NO_ACCESS_CONTROL"),
            format!("O:{owner}D:P"),
            format!("O:{owner}D:P{system}{minimum}(A;;GR;;;WD)"),
            format!("O:{owner}D:P{system}{minimum}{minimum}"),
            format!("O:{owner}D:P{system}(A;;0x00120087;;;{client})"),
            format!("O:{owner}D:P{system}(A;;GW;;;{client})"),
            format!("O:{owner}D:P{system}(A;OI;0x00120083;;;{client})"),
        ] {
            let descriptor = Descriptor::from_sddl(&text).unwrap();
            assert!(policy.verify_descriptor(&descriptor).is_err());
        }
        let account = policy.client.user.text().unwrap();
        if account != client {
            let account_grant =
                Descriptor::from_sddl(&format!("O:{owner}D:P{system}(A;;0x00120083;;;{account})"))
                    .unwrap();
            assert!(policy.verify_descriptor(&account_grant).is_err());
        }
    }

    #[test]
    fn native_pipe_uses_minimal_client_open_and_rejects_production_owner_spoof() {
        let (policy, name) = fixture();
        let _server = policy.create_first(&name).unwrap();
        let cancel = AtomicBool::new(false);
        let client = policy
            .connect_at(&name, Instant::now() + Duration::from_secs(5), &cancel)
            .unwrap();
        policy.verify_service_pipe(client.as_handle()).unwrap();
        let production = Policy::local_system(policy.client.clone()).unwrap();
        if policy.owner != production.owner {
            assert_eq!(
                production
                    .verify_service_pipe(client.as_handle())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn existing_pipe_name_and_extra_server_instances_are_rejected() {
        let (policy, name) = fixture();
        let _server = policy.create_first(&name).unwrap();
        assert_eq!(
            policy.create_first(&name).unwrap_err().raw_os_error(),
            Some(ERROR_ACCESS_DENIED.0 as i32)
        );
        // Current-owner tests cannot model an attacker changing its own DACL,
        // but the unchanged restricted DACL must deny a second server handle.
        let extra = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                16,
                8192,
                8192,
                100,
                None,
            )
        };
        if !extra.is_invalid() {
            drop(unsafe { OwnedHandle::from_raw_handle(extra.0) });
            panic!("Client data rights unexpectedly admitted an extra server instance.");
        }
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(ERROR_ACCESS_DENIED.0 as i32)
        );
    }

    #[test]
    fn parsed_request_is_bound_to_native_caller_then_thread_reverts() {
        let (policy, name) = fixture();
        let server = policy.create_first(&name).unwrap();
        let cancel = AtomicBool::new(false);
        let client = policy
            .connect_at(&name, Instant::now() + Duration::from_secs(5), &cancel)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut server = unsafe { PipeIo::from_overlapped_byte_pipe(server, deadline, &cancel) };
        let mut client = unsafe { PipeIo::from_overlapped_byte_pipe(client, deadline, &cancel) };
        server.accept().unwrap();
        let request = codec::RequestEnvelope {
            request_id: Uuid::new_v4(),
            request: codec::HelperRequest::QueryReadiness {},
        };
        codec::write_request(&mut client, &request).unwrap();
        let authenticated = policy
            .read_authenticated_request(&mut server)
            .unwrap()
            .unwrap();
        assert_eq!(authenticated.request(), &request);
        assert_eq!(authenticated.caller(), &policy.client);
        assert!(thread_token().unwrap().is_none());
        let actual = policy.authenticate_client(server.as_handle()).unwrap();
        assert_eq!(actual, policy.client);
        assert!(thread_token().unwrap().is_none());
        let mut other_session = policy.clone();
        other_session.client.session ^= 1;
        assert_eq!(
            other_session
                .authenticate_client(server.as_handle())
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(thread_token().unwrap().is_none());
        let mut other_user = policy.clone();
        other_user.client.user = Sid::parse("S-1-5-7").unwrap();
        assert_eq!(
            other_user
                .authenticate_client(server.as_handle())
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(thread_token().unwrap().is_none());
        assert_eq!(
            policy.authenticate_client(server.as_handle()).unwrap(),
            actual
        );
    }

    #[test]
    fn existing_impersonation_is_preserved_and_never_replaced() {
        let (policy, name) = fixture();
        let server = policy.create_first(&name).unwrap();
        let cancel = AtomicBool::new(false);
        let client = policy
            .connect_at(&name, Instant::now() + Duration::from_secs(5), &cancel)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut server = unsafe { PipeIo::from_overlapped_byte_pipe(server, deadline, &cancel) };
        let mut client = unsafe { PipeIo::from_overlapped_byte_pipe(client, deadline, &cancel) };
        server.accept().unwrap();
        client.write_all(b"x").unwrap();
        use std::io::Read;
        server.read_exact(&mut [0]).unwrap();
        unsafe { ImpersonateNamedPipeClient(HANDLE(server.as_handle().as_raw_handle())) }.unwrap();
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                if unsafe { RevertToSelf() }.is_err() {
                    std::process::abort();
                }
            }
        }
        let restore = Restore;
        assert!(thread_token().unwrap().is_some());
        assert_eq!(
            policy
                .authenticate_client(server.as_handle())
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(thread_token().unwrap().is_some());
        drop(restore);
        assert!(thread_token().unwrap().is_none());
    }

    #[test]
    fn unauthorized_request_never_escapes_and_ends_the_connection() {
        let (policy, name) = fixture();
        let server = policy.create_first(&name).unwrap();
        let cancel = AtomicBool::new(false);
        let client = policy
            .connect_at(&name, Instant::now() + Duration::from_secs(5), &cancel)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut server = unsafe { PipeIo::from_overlapped_byte_pipe(server, deadline, &cancel) };
        let mut client = unsafe { PipeIo::from_overlapped_byte_pipe(client, deadline, &cancel) };
        server.accept().unwrap();
        let request = codec::RequestEnvelope {
            request_id: Uuid::new_v4(),
            request: codec::HelperRequest::QueryReadiness {},
        };
        codec::write_request(&mut client, &request).unwrap();
        let mut wrong_session = policy.clone();
        wrong_session.client.session ^= 1;
        assert!(
            matches!(wrong_session.read_authenticated_request(&mut server), Err(ProtocolError::Io(ref io)) if io.kind() == io::ErrorKind::PermissionDenied)
        );
        assert!(thread_token().unwrap().is_none());
        assert_eq!(
            server.write(b"response").unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert!(policy.read_authenticated_request(&mut server).is_err());
    }

    #[test]
    fn malformed_frame_never_becomes_an_authenticated_request() {
        let (policy, name) = fixture();
        let server = policy.create_first(&name).unwrap();
        let cancel = AtomicBool::new(false);
        let client = policy
            .connect_at(&name, Instant::now() + Duration::from_secs(5), &cancel)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut server = unsafe { PipeIo::from_overlapped_byte_pipe(server, deadline, &cancel) };
        let mut client = unsafe { PipeIo::from_overlapped_byte_pipe(client, deadline, &cancel) };
        server.accept().unwrap();
        client.write_all(b"not-a-frame!").unwrap();
        assert!(matches!(
            policy.read_authenticated_request(&mut server),
            Err(ProtocolError::InvalidMagic)
        ));
        assert!(thread_token().unwrap().is_none());
        assert_eq!(
            server.write(b"response").unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[test]
    fn authenticated_wire_ids_and_command_are_bound_to_durable_admission() {
        use crate::optimizer_requests::{
            Admission, Caller, LeasePreflight, Ledger, LedgerError, Phase,
        };
        let (policy, name) = fixture();
        let cancel = AtomicBool::new(false);
        let server = policy.create_first(&name).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let client = policy.connect_at(&name, deadline, &cancel).unwrap();
        let mut server = unsafe { PipeIo::from_overlapped_byte_pipe(server, deadline, &cancel) };
        let mut client = unsafe { PipeIo::from_overlapped_byte_pipe(client, deadline, &cancel) };
        server.accept().unwrap();
        let mut receive = |command| {
            let envelope = codec::RequestEnvelope {
                request_id: Uuid::new_v4(),
                request: command,
            };
            codec::write_request(&mut client, &envelope).unwrap();
            policy
                .read_authenticated_request(&mut server)
                .unwrap()
                .unwrap()
        };
        let directory = tempfile::tempdir().unwrap();
        let mut ledger =
            Ledger::open(rusqlite::Connection::open(directory.path().join("requests.db")).unwrap())
                .unwrap();
        let readiness = receive(codec::HelperRequest::QueryReadiness {});
        let owner = Caller::authenticated(&readiness).unwrap();
        let lease = Uuid::new_v4();
        let revision = Uuid::new_v4();
        let invocation = Uuid::new_v4();
        let preflight = || {
            LeasePreflight::from_owner_observation(
                owner.clone(),
                lease,
                revision,
                crate::optimizer_requests::ContextBinding::fixture_default(),
            )
            .unwrap()
        };
        assert!(matches!(
            ledger.admit_authenticated(&readiness, preflight()),
            Err(LedgerError::RequestMismatch)
        ));
        let query = receive(codec::HelperRequest::QueryInvocation {
            invocation_id: invocation,
        });
        assert!(
            matches!(ledger.query_authenticated(&query).unwrap(),codec::ServiceResponse::Invocation {invocation_id,state:codec::InvocationState::Unknown} if invocation_id==invocation)
        );
        assert!(matches!(
            ledger.admit_authenticated(&query, preflight()),
            Err(LedgerError::RequestMismatch)
        ));
        let request = receive(codec::HelperRequest::Reactivate {
            lease_id: lease,
            invocation_id: invocation,
            original: Box::new(crate::optimizer_protocol::OriginalContext::fixture()),
        });
        let wrong = LeasePreflight::from_owner_observation(
            owner.clone(),
            Uuid::new_v4(),
            revision,
            crate::optimizer_requests::ContextBinding::fixture_default(),
        )
        .unwrap();
        assert!(matches!(
            ledger.admit_authenticated(&request, wrong),
            Err(LedgerError::RequestMismatch)
        ));
        assert!(matches!(
            ledger.query_authenticated(&request),
            Err(LedgerError::RequestMismatch)
        ));
        let ticket = match ledger.admit_authenticated(&request, preflight()).unwrap() {
            Admission::New(ticket) => ticket,
            other => panic!("Unexpected native admission result {other:?}"),
        };
        assert_eq!(ticket.invocation(), invocation);
        assert_eq!(ticket.lease(), lease);
        let original = codec::OriginalContext::fixture();
        for field in 0..4 {
            let (mut command, mut directory, mut environment) = (
                original.command().to_vec(),
                original.directory().to_vec(),
                original.environment().to_vec(),
            );
            let mut show = original.show_window();
            match field {
                0 => command.push(0xdfff),
                1 => directory[0] = b'c' as u16,
                2 => {
                    let index = environment.len() - 3;
                    environment[index] = 0xdfff;
                }
                _ => show = None,
            }
            let substituted =
                codec::OriginalContext::new(command, directory, environment, show).unwrap();
            let digest = crate::optimizer_requests::ContextBinding::observe(&substituted).unwrap();
            let request = receive(codec::HelperRequest::Reactivate {
                lease_id: lease,
                invocation_id: invocation,
                original: Box::new(substituted),
            });
            assert!(matches!(
                ledger.admit_authenticated(&request, preflight()),
                Err(LedgerError::RequestMismatch)
            ));
            let fresh =
                LeasePreflight::from_owner_observation(owner.clone(), lease, revision, digest)
                    .unwrap();
            assert!(matches!(
                ledger.admit_authenticated(&request, fresh).unwrap(),
                Admission::Conflict
            ));
        }
        let changed = LeasePreflight::from_owner_observation(
            owner.clone(),
            lease,
            Uuid::new_v4(),
            crate::optimizer_requests::ContextBinding::fixture_default(),
        )
        .unwrap();
        assert!(matches!(
            ledger.admit_authenticated(&request, changed).unwrap(),
            Admission::Existing(Phase::Queued)
        ));
        let query = receive(codec::HelperRequest::QueryInvocation {
            invocation_id: invocation,
        });
        assert!(
            matches!(ledger.query_authenticated(&query).unwrap(),codec::ServiceResponse::Invocation {invocation_id,state:codec::InvocationState::Queued} if invocation_id==invocation)
        );
    }

    #[test]
    fn production_bind_requires_unimpersonated_system_identity() {
        let principal = Principal::current().unwrap();
        if principal.user == Sid::parse("S-1-5-18").unwrap() {
            Principal::require_local_system().unwrap(); // Never bind a production test endpoint.
            assert!(Policy::local_system(principal).is_err());
        } else {
            let policy = Policy::local_system(principal).unwrap();
            assert_eq!(
                policy.bind_first().unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn connect_cancel_deadline_and_busy_endpoint_are_bounded() {
        let (policy, name) = fixture();
        for cancelled in [false, true] {
            let cancel = AtomicBool::new(cancelled);
            let result = policy.connect_at(&name, Instant::now(), &cancel);
            assert_eq!(
                result.unwrap_err().kind(),
                if cancelled {
                    io::ErrorKind::ConnectionAborted
                } else {
                    io::ErrorKind::TimedOut
                }
            );
        }
        let _server = policy.create_first(&name).unwrap();
        let cancel = AtomicBool::new(false);
        let _first = policy
            .connect_at(&name, Instant::now() + Duration::from_secs(5), &cancel)
            .unwrap();
        assert_eq!(
            policy
                .connect_at(&name, Instant::now() + Duration::from_millis(50), &cancel)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
}
