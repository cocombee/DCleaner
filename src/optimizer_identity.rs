//! Bounded, read-only Windows PE image observations for optimizer planning.
//!
//! A snapshot is not publisher trust, app/component association or permission to
//! modify a resource. Revalidation does not reserve the file after returning.
//! The native reader excludes ordinary write/delete opens while its handle is
//! held and compares handle observations before/after hashing; it does not claim
//! a filesystem transaction or protection against pre-existing mapped writes.

use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

pub const MAX_IMAGE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_HEADER_BYTES: usize = 1024 * 1024;
#[cfg(any(windows, test))]
const MAX_SECTIONS: usize = 96;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileIdentity {
    pub volume_serial: u64,
    pub file_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeFormat {
    Pe32,
    Pe32Plus,
}

/// Header fields, not a Windows-loader or signature validation result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PeHeader {
    pub machine: u16,
    pub format: PeFormat,
    pub characteristics: u16,
    pub subsystem: u16,
    pub sections: u16,
    pub entry_point_rva: u32,
    pub image_size: u32,
    pub headers_size: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImageSnapshot {
    pub requested_path: PathBuf,
    /// Native normalized DOS path, including its verbatim prefix. Parent
    /// redirection/aliases may make this differ from the requested spelling.
    pub final_path: PathBuf,
    pub identity: FileIdentity,
    pub size: u64,
    pub creation_time: u64,
    pub last_write_time: u64,
    pub attributes: u32,
    pub hard_links: u32,
    pub sha256: String,
    pub pe: PeHeader,
    /// Includes the separately read bounded header and the complete hash pass.
    pub bytes_read: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageErrorKind {
    UnsupportedPlatform,
    InvalidPath,
    NotFound,
    AccessDenied,
    Busy,
    NotRegularFile,
    ReparsePoint,
    ImageLimit,
    HeaderLimit,
    InvalidPe,
    Changed,
    Cancelled,
    IdentityUnavailable,
    HashFailure,
    NativeFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImageError {
    pub kind: ImageErrorKind,
    /// Filesystem operations retain Win32 codes; HashFailure retains NTSTATUS.
    pub native_code: Option<u32>,
    pub message: String,
}

fn error(kind: ImageErrorKind, message: &str) -> ImageError {
    ImageError {
        kind,
        native_code: None,
        message: message.into(),
    }
}

/// Reads one selected image with a finite byte/header bound. Cancellation is
/// checked between reads; blocking filesystem calls have no wall-clock bound.
pub fn inspect(path: &Path, cancel: &AtomicBool) -> Result<ImageSnapshot, ImageError> {
    #[cfg(windows)]
    {
        native::inspect_with_limit(path, cancel, MAX_IMAGE_BYTES)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, cancel);
        Err(error(
            ImageErrorKind::UnsupportedPlatform,
            "Windows image identity is unavailable on this platform.",
        ))
    }
}

/// Freshly reads the same requested path and rejects a changed identity,
/// content, resolved path or retained metadata. This grants no effect authority.
pub fn revalidate(
    expected: &ImageSnapshot,
    cancel: &AtomicBool,
) -> Result<ImageSnapshot, ImageError> {
    let current = inspect(&expected.requested_path, cancel)?;
    if current != *expected {
        return Err(error(
            ImageErrorKind::Changed,
            "The selected image changed after its previous observation.",
        ));
    }
    Ok(current)
}

#[cfg(any(windows, test))]
fn u16_at(bytes: &[u8], at: usize) -> Result<u16, ImageError> {
    let value = bytes
        .get(at..at.saturating_add(2))
        .ok_or_else(|| error(ImageErrorKind::InvalidPe, "The PE header is truncated."))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}
#[cfg(any(windows, test))]
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, ImageError> {
    let value = bytes
        .get(at..at.saturating_add(4))
        .ok_or_else(|| error(ImageErrorKind::InvalidPe, "The PE header is truncated."))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}
#[cfg(any(windows, test))]
fn pe_offset(bytes: &[u8], file_size: u64) -> Result<usize, ImageError> {
    if bytes.len() < 64 || bytes.get(..2) != Some(b"MZ") {
        return Err(error(
            ImageErrorKind::InvalidPe,
            "The selected file has no complete DOS image header.",
        ));
    }
    let at = u32_at(bytes, 0x3c)? as usize;
    if at > MAX_HEADER_BYTES - 24 {
        return Err(error(
            ImageErrorKind::HeaderLimit,
            "The PE header offset exceeds the inspection bound.",
        ));
    }
    if at < 64 || (at + 24) as u64 > file_size {
        return Err(error(
            ImageErrorKind::InvalidPe,
            "The PE header offset is outside the selected file.",
        ));
    }
    Ok(at)
}
#[cfg(any(windows, test))]
fn header_end(bytes: &[u8], file_size: u64) -> Result<usize, ImageError> {
    let at = pe_offset(bytes, file_size)?;
    if bytes.get(at..at + 4) != Some(b"PE\0\0") {
        return Err(error(
            ImageErrorKind::InvalidPe,
            "The selected file has no PE signature.",
        ));
    }
    let sections = u16_at(bytes, at + 6)? as usize;
    if !(1..=MAX_SECTIONS).contains(&sections) {
        return Err(error(
            ImageErrorKind::InvalidPe,
            "The PE section count is outside the Windows image limit.",
        ));
    }
    let optional_size = u16_at(bytes, at + 20)? as usize;
    let end = at + 24 + optional_size + sections * 40;
    if end > MAX_HEADER_BYTES {
        return Err(error(
            ImageErrorKind::HeaderLimit,
            "The PE headers exceed the inspection bound.",
        ));
    }
    if optional_size < 2 || end as u64 > file_size {
        return Err(error(
            ImageErrorKind::InvalidPe,
            "The PE optional header or section table is truncated.",
        ));
    }
    Ok(end)
}
#[cfg(any(windows, test))]
fn parse_header(bytes: &[u8], file_size: u64) -> Result<PeHeader, ImageError> {
    let at = pe_offset(bytes, file_size)?;
    let end = header_end(bytes, file_size)?;
    if end > bytes.len() {
        return Err(error(
            ImageErrorKind::InvalidPe,
            "The PE section table is incomplete.",
        ));
    }
    let optional = at + 24;
    let (format, minimum) = match u16_at(bytes, optional)? {
        0x10b => (PeFormat::Pe32, 96),
        0x20b => (PeFormat::Pe32Plus, 112),
        _ => {
            return Err(error(
                ImageErrorKind::InvalidPe,
                "The selected file has no supported PE optional header.",
            ));
        }
    };
    if (u16_at(bytes, at + 20)? as usize) < minimum {
        return Err(error(
            ImageErrorKind::InvalidPe,
            "The PE optional header omits required fields.",
        ));
    }
    let characteristics = u16_at(bytes, at + 22)?;
    if characteristics & 2 == 0 || characteristics & 0x2000 != 0 {
        return Err(error(
            ImageErrorKind::InvalidPe,
            "The selected PE is not marked as an executable image, or is a DLL.",
        ));
    }
    let headers_size = u32_at(bytes, optional + 60)?;
    let image_size = u32_at(bytes, optional + 56)?;
    if u16_at(bytes, at + 4)? == 0
        || headers_size < end as u32
        || u64::from(headers_size) > file_size
        || image_size < headers_size
    {
        return Err(error(
            ImageErrorKind::InvalidPe,
            "The PE machine or declared header/image bounds are invalid.",
        ));
    }
    Ok(PeHeader {
        machine: u16_at(bytes, at + 4)?,
        format,
        characteristics,
        subsystem: u16_at(bytes, optional + 68)?,
        sections: u16_at(bytes, at + 6)?,
        entry_point_rva: u32_at(bytes, optional + 16)?,
        image_size,
        headers_size,
    })
}

#[cfg(any(windows, test))]
fn header_matches_chunk(header: &[u8], offset: u64, chunk: &[u8]) -> bool {
    if offset >= header.len() as u64 {
        return true;
    }
    let start = offset as usize;
    let count = (header.len() - start).min(chunk.len());
    header[start..start + count] == chunk[..count]
}

#[cfg(windows)]
mod native {
    use super::*;
    use crate::native_hash::{HashError, Sha256};
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Seek, SeekFrom},
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        sync::atomic::Ordering,
    };
    use windows::{
        Win32::{
            Foundation::{GetLastError, HANDLE},
            Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN, FILE_ID_INFO,
                FILE_NAME_NORMALIZED, FILE_SHARE_READ, FILE_TYPE_DISK, FileIdInfo,
                GETFINALPATHNAMEBYHANDLE_FLAGS, GetFileInformationByHandle,
                GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW,
                VOLUME_NAME_DOS,
            },
        },
        core::Error as WindowsError,
    };

    const CHUNK: usize = 64 * 1024;
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Observation {
        identity: FileIdentity,
        size: u64,
        creation_time: u64,
        last_write_time: u64,
        attributes: u32,
        hard_links: u32,
    }
    fn cancelled(cancel: &AtomicBool) -> Result<(), ImageError> {
        if cancel.load(Ordering::Acquire) {
            Err(error(
                ImageErrorKind::Cancelled,
                "Image inspection was cancelled.",
            ))
        } else {
            Ok(())
        }
    }
    fn native_error(code: Option<u32>, operation: &str) -> ImageError {
        let kind = match code {
            Some(2 | 3) => ImageErrorKind::NotFound,
            Some(5) => ImageErrorKind::AccessDenied,
            Some(32 | 33) => ImageErrorKind::Busy,
            _ => ImageErrorKind::NativeFailure,
        };
        ImageError {
            kind,
            native_code: code,
            message: operation.into(),
        }
    }
    fn win_code(value: WindowsError) -> u32 {
        let code = value.code().0 as u32;
        if code & 0xffff0000 == 0x80070000 {
            code & 0xffff
        } else {
            code
        }
    }
    fn hash_error(value: HashError) -> ImageError {
        ImageError {
            kind: ImageErrorKind::HashFailure,
            native_code: match value {
                HashError::NativeFailure(code) => Some(code),
                HashError::InvalidObjectLength => None,
            },
            message: "Windows could not compute the image digest.".into(),
        }
    }
    fn handle(file: &File) -> HANDLE {
        HANDLE(file.as_raw_handle())
    }
    fn observe(file: &File) -> Result<Observation, ImageError> {
        if unsafe { GetFileType(handle(file)) } != FILE_TYPE_DISK {
            return Err(error(
                ImageErrorKind::NotRegularFile,
                "The selected image is not a disk file.",
            ));
        }
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(handle(file), &mut info) }.map_err(|e| {
            native_error(
                Some(win_code(e)),
                "Windows could not inspect the image handle.",
            )
        })?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
            return Err(error(
                ImageErrorKind::NotRegularFile,
                "The selected image is a directory.",
            ));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(error(
                ImageErrorKind::ReparsePoint,
                "The selected image is a reparse point.",
            ));
        }
        let mut identity = FILE_ID_INFO::default();
        unsafe {
            GetFileInformationByHandleEx(
                handle(file),
                FileIdInfo,
                (&mut identity as *mut FILE_ID_INFO).cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        }
        .map_err(|e| ImageError {
            kind: ImageErrorKind::IdentityUnavailable,
            native_code: Some(win_code(e)),
            message: "Windows could not provide the image's volume and file identity.".into(),
        })?;
        Ok(Observation {
            identity: FileIdentity {
                volume_serial: identity.VolumeSerialNumber,
                file_id: identity.FileId.Identifier,
            },
            size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
            creation_time: (u64::from(info.ftCreationTime.dwHighDateTime) << 32)
                | u64::from(info.ftCreationTime.dwLowDateTime),
            last_write_time: (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
                | u64::from(info.ftLastWriteTime.dwLowDateTime),
            attributes: info.dwFileAttributes,
            hard_links: info.nNumberOfLinks,
        })
    }
    fn final_path(file: &File) -> Result<PathBuf, ImageError> {
        // The normalized DOS spelling adds a verbatim drive/UNC prefix. Keep
        // bounded slack for that prefix and the terminating NUL.
        let mut buffer =
            vec![0u16; crate::optimizer_registration::MAX_EXECUTABLE_PATH_UTF16_UNITS + 8];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                handle(file),
                &mut buffer,
                GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
            )
        } as usize;
        if length == 0 {
            return Err(native_error(
                Some(unsafe { GetLastError() }.0),
                "Windows could not resolve the image handle's path.",
            ));
        }
        if length >= buffer.len() {
            return Err(error(
                ImageErrorKind::InvalidPath,
                "The resolved image path exceeds the inspection bound.",
            ));
        }
        let value = String::from_utf16(&buffer[..length]).map_err(|_| {
            error(
                ImageErrorKind::InvalidPath,
                "The resolved image path cannot be represented without loss.",
            )
        })?;
        Ok(PathBuf::from(value))
    }
    fn input_path(path: &Path) -> Result<(), ImageError> {
        if crate::optimizer_registration::image_name_from_absolute_path(path).is_none() {
            return Err(error(
                ImageErrorKind::InvalidPath,
                "A bounded absolute Windows image path is required.",
            ));
        }
        let text = path
            .to_str()
            .ok_or_else(|| {
                error(
                    ImageErrorKind::InvalidPath,
                    "The image path cannot be represented without loss.",
                )
            })?
            .replace('/', "\\");
        for part in text
            .split('\\')
            .filter(|part| !part.is_empty())
            .skip(if text.starts_with("\\\\") { 2 } else { 1 })
        {
            let base = part.split('.').next().unwrap_or("").to_ascii_uppercase();
            let numbered = ["COM", "LPT"].iter().any(|prefix| {
                base.strip_prefix(prefix).is_some_and(|suffix| {
                    matches!(
                        suffix,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
            });
            if part.ends_with(['.', ' '])
                || numbered
                || matches!(
                    base.as_str(),
                    "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
                )
            {
                return Err(error(
                    ImageErrorKind::InvalidPath,
                    "A device name or trailing path alias cannot identify an image.",
                ));
            }
        }
        Ok(())
    }
    fn read_until(
        file: &mut File,
        bytes: &mut Vec<u8>,
        end: usize,
        cancel: &AtomicBool,
    ) -> Result<(), ImageError> {
        if end > MAX_HEADER_BYTES {
            return Err(error(
                ImageErrorKind::HeaderLimit,
                "The PE headers exceed the inspection bound.",
            ));
        }
        let mut buffer = [0u8; CHUNK];
        while bytes.len() < end {
            cancelled(cancel)?;
            let wanted = (end - bytes.len()).min(buffer.len());
            let count = file.read(&mut buffer[..wanted]).map_err(|e| {
                native_error(
                    e.raw_os_error().map(|n| n as u32),
                    "The image header could not be read.",
                )
            })?;
            if count == 0 {
                return Err(error(
                    ImageErrorKind::InvalidPe,
                    "The image ended before its declared headers.",
                ));
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        Ok(())
    }
    pub(super) fn inspect_with_limit(
        path: &Path,
        cancel: &AtomicBool,
        image_limit: u64,
    ) -> Result<ImageSnapshot, ImageError> {
        cancelled(cancel)?;
        input_path(path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_SEQUENTIAL_SCAN.0)
            .open(path)
            .map_err(|e| {
                native_error(
                    e.raw_os_error().map(|n| n as u32),
                    "The selected image could not be opened for inspection.",
                )
            })?;
        let before = observe(&file)?;
        if before.size > image_limit {
            return Err(error(
                ImageErrorKind::ImageLimit,
                "The image exceeds the hashing byte bound.",
            ));
        }
        let final_before = final_path(&file)?;
        let mut prefix = Vec::new();
        read_until(&mut file, &mut prefix, 64, cancel)?;
        let pe = pe_offset(&prefix, before.size)?;
        read_until(&mut file, &mut prefix, pe + 24, cancel)?;
        let end = header_end(&prefix, before.size)?;
        read_until(&mut file, &mut prefix, end, cancel)?;
        let pe = parse_header(&prefix, before.size)?;
        file.seek(SeekFrom::Start(0)).map_err(|e| {
            native_error(
                e.raw_os_error().map(|n| n as u32),
                "The image could not be rewound for hashing.",
            )
        })?;
        let mut hash = Sha256::new().map_err(hash_error)?;
        let mut buffer = [0u8; CHUNK];
        let mut hashed = 0u64;
        while hashed < before.size {
            cancelled(cancel)?;
            let wanted = (before.size - hashed).min(CHUNK as u64) as usize;
            let count = file.read(&mut buffer[..wanted]).map_err(|e| {
                native_error(
                    e.raw_os_error().map(|n| n as u32),
                    "The image could not be read for hashing.",
                )
            })?;
            if count == 0 {
                break;
            }
            if !header_matches_chunk(&prefix, hashed, &buffer[..count]) {
                return Err(error(
                    ImageErrorKind::Changed,
                    "The PE header changed between inspection and hashing.",
                ));
            }
            hashed += count as u64;
            hash.update(&buffer[..count]).map_err(hash_error)?;
        }
        cancelled(cancel)?;
        // One byte is sufficient to detect growth without reading an unbounded
        // replacement stream. Successful snapshots count only returned bytes.
        let extra = file.read(&mut buffer[..1]).map_err(|e| {
            native_error(
                e.raw_os_error().map(|n| n as u32),
                "The image's end could not be checked.",
            )
        })?;
        if extra != 0 {
            return Err(error(
                ImageErrorKind::Changed,
                "The image grew during inspection.",
            ));
        }
        let after = observe(&file)?;
        let final_after = final_path(&file)?;
        cancelled(cancel)?;
        if hashed != before.size || before != after || final_before != final_after {
            return Err(error(
                ImageErrorKind::Changed,
                "The selected image changed during inspection.",
            ));
        }
        let sha256 = hash.finish().map_err(hash_error)?;
        Ok(ImageSnapshot {
            requested_path: path.to_path_buf(),
            final_path: final_after,
            identity: after.identity,
            size: after.size,
            creation_time: after.creation_time,
            last_write_time: after.last_write_time,
            attributes: after.attributes,
            hard_links: after.hard_links,
            sha256,
            pe,
            bytes_read: hashed + prefix.len() as u64,
        })
    }

    #[cfg(test)]
    mod path_tests {
        use super::*;

        #[test]
        fn rejects_ambiguous_device_and_relative_paths_before_opening() {
            for path in [
                r"app.exe",
                r"C:app.exe",
                r"C:\apps\..\app.exe",
                r"C:\apps\app.exe:stream",
                r"\\?\C:\apps\app.exe",
                r"\\.\PhysicalDrive0",
                r"C:\apps\NUL.exe",
                r"C:\apps\COM1.exe",
                r"C:\apps\LPT³.exe",
                r"C:\apps.\app.exe",
                r"C:\apps\app.exe ",
            ] {
                assert_eq!(
                    input_path(Path::new(path)).unwrap_err().kind,
                    ImageErrorKind::InvalidPath,
                    "{path}"
                );
            }
            for path in [
                r"C:\Program Files\Vendor\app.exe",
                r"C:/Apps/app.bin",
                r"\\server\share\Apps\app.exe",
                r"C:\Apps\COM10.exe",
            ] {
                assert!(input_path(Path::new(path)).is_ok(), "{path}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(format: PeFormat) -> Vec<u8> {
        let mut bytes = vec![0u8; 1024];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        let (machine, optional_size, magic): (u16, u16, u16) = match format {
            PeFormat::Pe32 => (0x14c, 0xe0, 0x10b),
            PeFormat::Pe32Plus => (0x8664, 0xf0, 0x20b),
        };
        bytes[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&optional_size.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&magic.to_le_bytes());
        bytes[0xa8..0xac].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[0xd0..0xd4].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[0xd4..0xd8].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0xdc..0xde].copy_from_slice(&3u16.to_le_bytes());
        bytes[512..].fill(0x5a);
        bytes
    }

    #[test]
    fn parses_both_pe_formats_without_claiming_loader_validity() {
        for format in [PeFormat::Pe32, PeFormat::Pe32Plus] {
            let bytes = image(format);
            let header = parse_header(&bytes, bytes.len() as u64).unwrap();
            assert_eq!(header.format, format);
            assert_eq!(header.sections, 1);
            assert_eq!(header.subsystem, 3);
            assert_eq!(header.entry_point_rva, 0x1000);
            assert_eq!(header.headers_size, 0x200);
            assert_eq!(header.image_size, 0x2000);
        }
    }

    #[test]
    fn rejects_dlls_missing_executable_flag_and_malformed_header_bounds() {
        let valid = image(PeFormat::Pe32Plus);
        for (offset, replacement) in [
            (0x96, 0x2022u16), // DLL
            (0x96, 0x20),      // executable flag absent
            (0x86, 0),         // section count
            (0x86, 97),
            (0x94, 2),     // optional header lacks required fields
            (0x98, 0x107), // unsupported optional-header magic
            (0x84, 0),     // missing machine
        ] {
            let mut bytes = valid.clone();
            bytes[offset..offset + 2].copy_from_slice(&replacement.to_le_bytes());
            assert_eq!(
                parse_header(&bytes, bytes.len() as u64).unwrap_err().kind,
                ImageErrorKind::InvalidPe
            );
        }
        for bytes in [&valid[..63], &valid[..431]] {
            assert_eq!(
                parse_header(bytes, valid.len() as u64).unwrap_err().kind,
                ImageErrorKind::InvalidPe
            );
        }
        let mut bytes = valid.clone();
        bytes[0xd4..0xd8].copy_from_slice(&100u32.to_le_bytes());
        assert_eq!(
            parse_header(&bytes, 1024).unwrap_err().kind,
            ImageErrorKind::InvalidPe
        );
        bytes[0xd4..0xd8].copy_from_slice(&2048u32.to_le_bytes());
        assert_eq!(
            parse_header(&bytes, 1024).unwrap_err().kind,
            ImageErrorKind::InvalidPe
        );
        bytes[0xd4..0xd8].copy_from_slice(&512u32.to_le_bytes());
        bytes[0xd0..0xd4].copy_from_slice(&256u32.to_le_bytes());
        assert_eq!(
            parse_header(&bytes, 1024).unwrap_err().kind,
            ImageErrorKind::InvalidPe
        );
    }

    #[test]
    fn hostile_offsets_and_declared_spans_fail_before_large_allocation() {
        let mut bytes = image(PeFormat::Pe32Plus);
        bytes[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            pe_offset(&bytes, u64::MAX).unwrap_err().kind,
            ImageErrorKind::HeaderLimit
        );
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        assert_eq!(
            header_end(&bytes, 431).unwrap_err().kind,
            ImageErrorKind::InvalidPe
        );
        bytes[0x3c..0x40].copy_from_slice(&32u32.to_le_bytes());
        assert_eq!(
            pe_offset(&bytes, 1024).unwrap_err().kind,
            ImageErrorKind::InvalidPe
        );
    }

    #[test]
    fn header_and_hash_pass_cannot_silently_describe_different_headers() {
        let header = image(PeFormat::Pe32Plus);
        for (index, chunk) in header.chunks(137).enumerate() {
            assert!(header_matches_chunk(
                &header[..432],
                (index * 137) as u64,
                chunk
            ));
        }
        let mut changed = header.clone();
        changed[400] ^= 1;
        assert!(!header_matches_chunk(
            &header[..432],
            274,
            &changed[274..548]
        ));
        // A change outside the parsed header is represented by the whole-file
        // digest, rather than this bounded comparison.
        changed[900] ^= 1;
        assert!(header_matches_chunk(&header[..432], 822, &changed[822..]));
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform_does_not_attempt_to_open_a_path() {
        assert_eq!(
            inspect(
                Path::new("/does-not-exist/dcleaner-fixture"),
                &AtomicBool::new(false)
            )
            .unwrap_err()
            .kind,
            ImageErrorKind::UnsupportedPlatform
        );
    }

    #[cfg(windows)]
    mod windows_tests {
        use super::*;
        use std::{fs, fs::OpenOptions, os::windows::fs::OpenOptionsExt};

        fn fixture() -> (tempfile::TempDir, PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            // Rust canonicalization produces a verbatim path. The native reader
            // deliberately accepts ordinary absolute paths only.
            let path = dir.path().join("selected-image.bin");
            fs::write(&path, image(PeFormat::Pe32Plus)).unwrap();
            (dir, path)
        }

        #[test]
        fn stable_fixture_is_hashed_without_execution_and_detects_changed_content() {
            let (_dir, path) = fixture();
            let cancel = AtomicBool::new(false);
            let before = inspect(&path, &cancel).unwrap();
            assert_eq!(before.size, 1024);
            assert_eq!(before.bytes_read, 1024 + 432);
            assert_eq!(before.sha256.len(), 64);
            assert_eq!(revalidate(&before, &cancel).unwrap(), before);
            let mut bytes = image(PeFormat::Pe32Plus);
            bytes[900] ^= 0xff;
            fs::write(&path, bytes).unwrap();
            let after = inspect(&path, &cancel).unwrap();
            assert_eq!(after.identity, before.identity);
            assert_ne!(after.sha256, before.sha256);
            assert_eq!(
                revalidate(&before, &cancel).unwrap_err().kind,
                ImageErrorKind::Changed
            );
        }

        #[test]
        fn replacement_and_hard_link_are_distinguished_by_file_identity() {
            let (dir, path) = fixture();
            let alias = dir.path().join("alias.bin");
            fs::hard_link(&path, &alias).unwrap();
            let cancel = AtomicBool::new(false);
            let before = inspect(&path, &cancel).unwrap();
            let linked = inspect(&alias, &cancel).unwrap();
            assert_eq!(before.identity, linked.identity);
            assert_eq!(before.sha256, linked.sha256);
            assert_ne!(before.final_path, linked.final_path);
            fs::rename(&path, dir.path().join("retained-original.bin")).unwrap();
            fs::write(&path, image(PeFormat::Pe32Plus)).unwrap();
            let replacement = inspect(&path, &cancel).unwrap();
            assert_eq!(replacement.sha256, before.sha256);
            assert_ne!(replacement.identity, before.identity);
            assert_eq!(
                revalidate(&before, &cancel).unwrap_err().kind,
                ImageErrorKind::Changed
            );
        }

        #[test]
        fn cancellation_size_limit_missing_image_and_writer_conflict_are_distinct() {
            let (dir, path) = fixture();
            let missing = dir.path().join("absent.bin");
            let cancel = AtomicBool::new(false);
            assert_eq!(
                inspect(&missing, &AtomicBool::new(true)).unwrap_err().kind,
                ImageErrorKind::Cancelled
            );
            assert_eq!(
                inspect(&missing, &cancel).unwrap_err().kind,
                ImageErrorKind::NotFound
            );
            assert_eq!(
                native::inspect_with_limit(&path, &cancel, 1023)
                    .unwrap_err()
                    .kind,
                ImageErrorKind::ImageLimit
            );
            let writer = OpenOptions::new()
                .write(true)
                .share_mode(7)
                .open(&path)
                .unwrap();
            let busy = inspect(&path, &cancel).unwrap_err();
            assert_eq!(busy.kind, ImageErrorKind::Busy);
            assert_eq!(busy.native_code, Some(32));
            drop(writer);
            assert!(inspect(&path, &cancel).is_ok());
        }
    }
}
