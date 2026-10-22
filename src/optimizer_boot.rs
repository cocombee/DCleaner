//! Bounded native boot-environment identity, never inferred from wall time,
//! uptime, a saved row, a process ID or a random application-generated UUID.
//! Class 90 is a private NT interface, not a stable Win32 contract. Unknown
//! status/layout or missing identity refuses admission without a fallback.
#![allow(dead_code)]

use std::io;
use uuid::Uuid;

const BOOT_ENVIRONMENT_CLASS: u32 = 90;
const BOOT_ENVIRONMENT_BYTES: usize = 32;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        class: u32,
        data: *mut std::ffi::c_void,
        size: u32,
        returned: *mut u32,
    ) -> i32;
}

/// Fixed layout described by the phnt native header's
/// SYSTEM_BOOT_ENVIRONMENT_INFORMATION: GUID, firmware DWORD, alignment, flags.
/// https://github.com/winsiderss/phnt/blob/master/ntexapi.h
fn decode(status: i32, returned: u32, bytes: &[u8]) -> io::Result<Uuid> {
    if status != 0
        || returned as usize != BOOT_ENVIRONMENT_BYTES
        || bytes.len() != BOOT_ENVIRONMENT_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Native boot identity query or layout is unsupported.",
        ));
    }
    let id = Uuid::from_bytes_le(bytes[..16].try_into().expect("fixed GUID prefix"));
    if id.is_nil() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Native boot identity is missing.",
        ));
    }
    Ok(id)
}

pub(crate) fn current() -> io::Result<Uuid> {
    let mut words = [0u64; BOOT_ENVIRONMENT_BYTES / 8];
    let mut returned = 0;
    // SAFETY: fixed eight-byte-aligned output buffer, exact capacity and valid
    // returned-length slot. Query only; no privileges, processes or settings change.
    let status = unsafe {
        NtQuerySystemInformation(
            BOOT_ENVIRONMENT_CLASS,
            words.as_mut_ptr().cast(),
            BOOT_ENVIRONMENT_BYTES as u32,
            &mut returned,
        )
    };
    let bytes: Vec<u8> = words.into_iter().flat_map(u64::to_ne_bytes).collect();
    decode(status, returned, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_native_boot_layout_rejects_failure_truncation_growth_and_missing_identity() {
        let id = Uuid::new_v4();
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&id.to_bytes_le());
        assert_eq!(decode(0, 32, &bytes).unwrap(), id);
        for status in [1, -1, 0xc0000003u32 as i32] {
            assert!(decode(status, 32, &bytes).is_err());
        }
        for length in [0, 16, 24, 31, 33, 4096] {
            assert!(decode(0, length, &bytes).is_err());
        }
        for length in [0, 15, 24, 31] {
            assert!(decode(0, 32, &bytes[..length]).is_err());
        }
        assert!(decode(0, 32, &[0u8; 32]).is_err());
        bytes[16..].fill(255);
        assert_eq!(decode(0, 32, &bytes).unwrap(), id);
    }
    #[test]
    fn native_boot_identity_is_nonzero_and_stable_across_independent_reads_and_threads() {
        let first = current().unwrap();
        assert!(!first.is_nil());
        for _ in 0..3 {
            assert_eq!(current().unwrap(), first);
        }
        assert_eq!(std::thread::spawn(current).join().unwrap().unwrap(), first);
    }
}
