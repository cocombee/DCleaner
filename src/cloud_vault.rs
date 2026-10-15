//! OS-protected persistence for cloud OAuth registrations and token records.
//!
//! There is deliberately no plaintext-file fallback. Windows stores only
//! DPAPI-protected blobs under the caller-provided app-data directory; macOS
//! uses a generic-password item in Keychain. Other platforms report that no
//! native protected vault is available.

use crate::cloud_auth::RegistrationFamily;
use std::{fmt, path::PathBuf};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const MAX_VAULT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum VaultKey {
    Registration(RegistrationFamily),
    Account(Uuid),
}

impl VaultKey {
    fn stable_name(self) -> Result<String, VaultError> {
        Ok(match self {
            Self::Registration(RegistrationFamily::Google) => "registration-google".into(),
            Self::Registration(RegistrationFamily::Microsoft) => "registration-microsoft".into(),
            Self::Registration(RegistrationFamily::Dropbox) => "registration-dropbox".into(),
            Self::Account(id) if !id.is_nil() => format!("account-{id}"),
            Self::Account(_) => return Err(VaultError::InvalidKey),
        })
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registration(family) => f.debug_tuple("Registration").field(family).finish(),
            Self::Account(_) => f.write_str("Account([redacted])"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultError {
    Unavailable,
    Unsupported,
    InvalidKey,
    InvalidData,
    TooLarge,
    Io,
    Protection,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "The protected cloud credential vault is unavailable.",
            Self::Unsupported => {
                "Protected cloud credential storage is unavailable on this platform."
            }
            Self::InvalidKey => "The cloud credential vault key is invalid.",
            Self::InvalidData => "The protected cloud credential record is invalid.",
            Self::TooLarge => "The cloud credential record exceeded its safe size limit.",
            Self::Io => "The protected cloud credential record could not be accessed.",
            Self::Protection => {
                "The operating system could not protect or unlock the cloud credential record."
            }
        })
    }
}

impl std::error::Error for VaultError {}

/// Minimal storage boundary. Callers pass only bounded versioned codec bytes;
/// returned buffers are zeroizing and never included in diagnostics.
pub trait SecretVault {
    fn get(&mut self, key: VaultKey) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError>;
    fn put(&mut self, key: VaultKey, bytes: &[u8]) -> Result<(), VaultError>;
    fn delete(&mut self, key: VaultKey) -> Result<(), VaultError>;
}

/// Platform vault. On Windows `data_dir` must be the application's private
/// per-user data directory. It is used only for DPAPI ciphertext, never clear
/// credentials. macOS stores values in Keychain and does not write this path.
pub struct NativeVault {
    data_dir: PathBuf,
}

impl NativeVault {
    pub fn from_data_dir(data_dir: impl Into<PathBuf>) -> Result<Self, VaultError> {
        let data_dir = data_dir.into();
        if !data_dir.is_absolute() {
            return Err(VaultError::Unavailable);
        }
        Ok(Self { data_dir })
    }

    /// Selects the current user's local app-data location without creating it.
    pub fn for_current_user() -> Result<Self, VaultError> {
        let mut data_dir = dirs::data_local_dir().ok_or(VaultError::Unavailable)?;
        data_dir.push("DCleaner");
        data_dir.push("cloud-vault");
        Self::from_data_dir(data_dir)
    }
}

impl SecretVault for NativeVault {
    fn get(&mut self, key: VaultKey) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        let name = key.stable_name()?;
        #[cfg(windows)]
        {
            windows_vault::get(&self.data_dir, &name, key)
        }
        #[cfg(target_os = "macos")]
        {
            let _ = (&self.data_dir, &name);
            macos_vault::get(&name)
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = (&self.data_dir, name);
            Err(VaultError::Unsupported)
        }
    }

    fn put(&mut self, key: VaultKey, bytes: &[u8]) -> Result<(), VaultError> {
        if bytes.is_empty() || bytes.len() > MAX_VAULT_BYTES {
            return Err(VaultError::TooLarge);
        }
        let name = key.stable_name()?;
        #[cfg(windows)]
        {
            windows_vault::put(&self.data_dir, &name, key, bytes)
        }
        #[cfg(target_os = "macos")]
        {
            let _ = (&self.data_dir, &name);
            macos_vault::put(&name, bytes)
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = (&self.data_dir, name, bytes);
            Err(VaultError::Unsupported)
        }
    }

    fn delete(&mut self, key: VaultKey) -> Result<(), VaultError> {
        let name = key.stable_name()?;
        #[cfg(windows)]
        {
            windows_vault::delete(&self.data_dir, &name)
        }
        #[cfg(target_os = "macos")]
        {
            let _ = (&self.data_dir, &name);
            macos_vault::delete(&name)
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = (&self.data_dir, name);
            Err(VaultError::Unsupported)
        }
    }
}

#[cfg(windows)]
mod windows_vault {
    use super::*;
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
        path::{Path, PathBuf},
    };
    use windows::{
        Win32::{
            Foundation::{HLOCAL, LocalFree},
            Security::Cryptography::{
                CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
            },
            Storage::FileSystem::{
                FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
                MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
            },
        },
        core::PCWSTR,
    };

    const FILE_MAGIC: &[u8; 4] = b"DCV1";
    const MAX_CIPHER_BYTES: usize = MAX_VAULT_BYTES + 16 * 1024;
    const ENTROPY_PREFIX: &[u8] = b"DCleaner cloud vault v1\0";

    struct ProtectedBuffer(CRYPT_INTEGER_BLOB);

    impl Drop for ProtectedBuffer {
        fn drop(&mut self) {
            if !self.0.pbData.is_null() {
                // DPAPI output may contain plaintext on decrypt. Scrub before
                // releasing the system-allocated buffer.
                unsafe {
                    std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                    let _ = LocalFree(Some(HLOCAL(self.0.pbData.cast())));
                }
            }
        }
    }

    fn safe_directory(root: &Path, create: bool) -> Result<bool, VaultError> {
        let mut prefix = PathBuf::new();
        for component in root.components() {
            prefix.push(component.as_os_str());
            match fs::symlink_metadata(&prefix) {
                Ok(meta) => {
                    if !meta.is_dir()
                        || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
                    {
                        return Err(VaultError::Unavailable);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                    fs::create_dir(&prefix).map_err(|_| VaultError::Io)?;
                    let meta = fs::symlink_metadata(&prefix).map_err(|_| VaultError::Io)?;
                    if !meta.is_dir()
                        || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
                    {
                        return Err(VaultError::Unavailable);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(false);
                }
                Err(_) => return Err(VaultError::Io),
            }
        }
        Ok(true)
    }

    fn record_path(root: &Path, name: &str) -> PathBuf {
        root.join(format!("{name}.bin"))
    }

    fn inspect_file(path: &Path) -> Result<Option<File>, VaultError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(VaultError::Io),
        };
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            || metadata.len() as usize > MAX_CIPHER_BYTES + FILE_MAGIC.len()
        {
            return Err(VaultError::InvalidData);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path)
            .map_err(|_| VaultError::Io)?;
        let opened = file.metadata().map_err(|_| VaultError::Io)?;
        if !opened.is_file()
            || opened.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            || opened.len() as usize > MAX_CIPHER_BYTES + FILE_MAGIC.len()
        {
            return Err(VaultError::InvalidData);
        }
        // Keep the handle alive while the caller performs its bounded read.
        Ok(Some(file))
    }

    pub(super) fn get(
        root: &Path,
        name: &str,
        key: VaultKey,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        if !safe_directory(root, false)? {
            return Ok(None);
        }
        let path = record_path(root, name);
        let Some(file) = inspect_file(&path)? else {
            return Ok(None);
        };
        let mut stored = Zeroizing::new(Vec::new());
        file.take((MAX_CIPHER_BYTES + FILE_MAGIC.len() + 1) as u64)
            .read_to_end(&mut stored)
            .map_err(|_| VaultError::Io)?;
        if stored.len() > MAX_CIPHER_BYTES + FILE_MAGIC.len()
            || stored.get(..FILE_MAGIC.len()) != Some(FILE_MAGIC)
        {
            return Err(VaultError::InvalidData);
        }
        let plaintext = unprotect(&stored[FILE_MAGIC.len()..], key)?;
        if plaintext.len() > MAX_VAULT_BYTES || plaintext.is_empty() {
            return Err(VaultError::InvalidData);
        }
        Ok(Some(plaintext))
    }

    pub(super) fn put(
        root: &Path,
        name: &str,
        key: VaultKey,
        bytes: &[u8],
    ) -> Result<(), VaultError> {
        let _ = safe_directory(root, true)?;
        let target = record_path(root, name);
        if let Some(existing) = inspect_file(&target)? {
            drop(existing);
        }
        let protected = protect(bytes, key)?;
        if protected.len() > MAX_CIPHER_BYTES {
            return Err(VaultError::TooLarge);
        }
        let mut stored = Zeroizing::new(Vec::with_capacity(FILE_MAGIC.len() + protected.len()));
        stored.extend_from_slice(FILE_MAGIC);
        stored.extend_from_slice(&protected);
        let temporary = root.join(format!("{name}.{}.tmp", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(&temporary)
            .map_err(|_| VaultError::Io)?;
        let write_result = (|| {
            file.write_all(&stored).map_err(|_| VaultError::Io)?;
            file.sync_all().map_err(|_| VaultError::Io)?;
            drop(file);
            replace_atomically(&temporary, &target)
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }

    pub(super) fn delete(root: &Path, name: &str) -> Result<(), VaultError> {
        if !safe_directory(root, false)? {
            return Ok(());
        }
        let path = record_path(root, name);
        match inspect_file(&path)? {
            None => Ok(()),
            Some(file) => {
                drop(file);
                fs::remove_file(path).map_err(|_| VaultError::Io)
            }
        }
    }

    fn replace_atomically(source: &Path, destination: &Path) -> Result<(), VaultError> {
        use windows::Win32::Storage::FileSystem::{REPLACE_FILE_FLAGS, ReplaceFileW};
        let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let target_wide: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let source_wide = PCWSTR(source_wide.as_ptr());
        let target_wide = PCWSTR(target_wide.as_ptr());
        match inspect_file(destination)? {
            Some(file) => {
                drop(file);
                unsafe {
                    ReplaceFileW(
                        target_wide,
                        source_wide,
                        PCWSTR::null(),
                        REPLACE_FILE_FLAGS(0),
                        None,
                        None,
                    )
                }
                .map_err(|_| VaultError::Io)
            }
            None => unsafe {
                MoveFileExW(
                    source_wide,
                    target_wide,
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            }
            .map_err(|_| VaultError::Io),
        }
    }

    fn entropy(key: VaultKey) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let mut out = Zeroizing::new(ENTROPY_PREFIX.to_vec());
        out.extend_from_slice(key.stable_name()?.as_bytes());
        Ok(out)
    }

    fn protect(bytes: &[u8], key: VaultKey) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if bytes.is_empty() || bytes.len() > MAX_VAULT_BYTES {
            return Err(VaultError::TooLarge);
        }
        let entropy = entropy(key)?;
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(bytes.len()).map_err(|_| VaultError::TooLarge)?,
            pbData: bytes.as_ptr().cast_mut(),
        };
        let optional = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(entropy.len()).map_err(|_| VaultError::TooLarge)?,
            pbData: entropy.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let status = unsafe {
            CryptProtectData(
                &input,
                PCWSTR::null(),
                Some(&optional as *const _),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        let output = ProtectedBuffer(output);
        status.map_err(|_| VaultError::Protection)?;
        if output.0.cbData == 0 || output.0.cbData as usize > MAX_CIPHER_BYTES {
            return Err(VaultError::TooLarge);
        }
        Ok(Zeroizing::new(unsafe {
            std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize).to_vec()
        }))
    }

    fn unprotect(bytes: &[u8], key: VaultKey) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if bytes.is_empty() || bytes.len() > MAX_CIPHER_BYTES {
            return Err(VaultError::InvalidData);
        }
        let entropy = entropy(key)?;
        let input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(bytes.len()).map_err(|_| VaultError::InvalidData)?,
            pbData: bytes.as_ptr().cast_mut(),
        };
        let optional = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(entropy.len()).map_err(|_| VaultError::InvalidData)?,
            pbData: entropy.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let status = unsafe {
            CryptUnprotectData(
                &input,
                None,
                Some(&optional as *const _),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        let output = ProtectedBuffer(output);
        status.map_err(|_| VaultError::Protection)?;
        if output.0.cbData == 0 || output.0.cbData as usize > MAX_VAULT_BYTES {
            return Err(VaultError::InvalidData);
        }
        Ok(Zeroizing::new(unsafe {
            std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize).to_vec()
        }))
    }
}

#[cfg(target_os = "macos")]
mod macos_vault {
    use super::*;

    const SERVICE: &str = "com.cocombee.DCleaner.cloud-vault.v1";

    pub(super) fn get(name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        match security_framework::passwords::get_generic_password(SERVICE, name) {
            Ok(bytes) if !bytes.is_empty() && bytes.len() <= MAX_VAULT_BYTES => {
                Ok(Some(Zeroizing::new(bytes)))
            }
            Ok(_) => Err(VaultError::InvalidData),
            Err(error) if error.code() == -25300 => Ok(None),
            Err(_) => Err(VaultError::Protection),
        }
    }

    pub(super) fn put(name: &str, bytes: &[u8]) -> Result<(), VaultError> {
        security_framework::passwords::set_generic_password(SERVICE, name, bytes)
            .map_err(|_| VaultError::Protection)
    }

    pub(super) fn delete(name: &str) -> Result<(), VaultError> {
        match security_framework::passwords::delete_generic_password(SERVICE, name) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == -25300 => Ok(()),
            Err(_) => Err(VaultError::Protection),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemoryVault(HashMap<VaultKey, Zeroizing<Vec<u8>>>);

    impl SecretVault for MemoryVault {
        fn get(&mut self, key: VaultKey) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
            if key.stable_name().is_err() {
                return Err(VaultError::InvalidKey);
            }
            Ok(self.0.get(&key).map(|bytes| Zeroizing::new(bytes.to_vec())))
        }

        fn put(&mut self, key: VaultKey, bytes: &[u8]) -> Result<(), VaultError> {
            if key.stable_name().is_err() || bytes.is_empty() || bytes.len() > MAX_VAULT_BYTES {
                return Err(VaultError::InvalidData);
            }
            self.0.insert(key, Zeroizing::new(bytes.to_vec()));
            Ok(())
        }

        fn delete(&mut self, key: VaultKey) -> Result<(), VaultError> {
            self.0.remove(&key);
            Ok(())
        }
    }

    #[test]
    fn typed_keys_keep_provider_registration_and_account_records_separate() {
        let mut vault = MemoryVault::default();
        let account = Uuid::new_v4();
        vault
            .put(VaultKey::Registration(RegistrationFamily::Google), b"reg")
            .unwrap();
        vault.put(VaultKey::Account(account), b"account").unwrap();
        assert_eq!(
            vault
                .get(VaultKey::Registration(RegistrationFamily::Google))
                .unwrap()
                .unwrap()
                .as_slice(),
            b"reg"
        );
        assert_eq!(
            vault
                .get(VaultKey::Registration(RegistrationFamily::Dropbox))
                .unwrap(),
            None
        );
        assert_eq!(
            vault
                .get(VaultKey::Account(account))
                .unwrap()
                .unwrap()
                .as_slice(),
            b"account"
        );
        assert_eq!(
            vault.get(VaultKey::Account(Uuid::nil())),
            Err(VaultError::InvalidKey)
        );
    }

    #[test]
    fn fake_vault_rejects_empty_and_oversized_records_and_deletes_only_selected_key() {
        let mut vault = MemoryVault::default();
        let a = VaultKey::Registration(RegistrationFamily::Microsoft);
        let b = VaultKey::Registration(RegistrationFamily::Dropbox);
        assert_eq!(vault.put(a, b""), Err(VaultError::InvalidData));
        assert_eq!(
            vault.put(a, &vec![0; MAX_VAULT_BYTES + 1]),
            Err(VaultError::InvalidData)
        );
        vault.put(a, b"one").unwrap();
        vault.put(b, b"two").unwrap();
        vault.delete(a).unwrap();
        assert_eq!(vault.get(a).unwrap(), None);
        assert_eq!(vault.get(b).unwrap().unwrap().as_slice(), b"two");
    }
}
