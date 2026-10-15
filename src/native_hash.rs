use windows::Win32::Security::Cryptography::{
    BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE, BCRYPT_OBJECT_LENGTH,
    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_SHA256_ALGORITHM, BCryptCloseAlgorithmProvider,
    BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash, BCryptGetProperty, BCryptHashData,
    BCryptOpenAlgorithmProvider,
};
use windows::core::PCWSTR;

const MAX_OBJECT_LENGTH: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HashError {
    NativeFailure(u32),
    InvalidObjectLength,
}

pub(crate) struct Sha256 {
    algorithm: BCRYPT_ALG_HANDLE,
    hash: BCRYPT_HASH_HANDLE,
    object: Vec<u8>,
}

impl Sha256 {
    pub(crate) fn new() -> Result<Self, HashError> {
        let mut algorithm = BCRYPT_ALG_HANDLE::default();
        let status = unsafe {
            BCryptOpenAlgorithmProvider(
                &mut algorithm,
                BCRYPT_SHA256_ALGORITHM,
                PCWSTR::null(),
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            )
        };
        if status.0 < 0 {
            return Err(HashError::NativeFailure(status.0 as u32));
        }

        let mut property = [0u8; 4];
        let mut returned = 0u32;
        let status = unsafe {
            BCryptGetProperty(
                algorithm.into(),
                BCRYPT_OBJECT_LENGTH,
                Some(&mut property),
                &mut returned,
                0,
            )
        };
        if status.0 < 0 || returned != 4 {
            let _ = unsafe { BCryptCloseAlgorithmProvider(algorithm, 0) };
            return Err(HashError::NativeFailure(status.0 as u32));
        }

        let object_length = u32::from_le_bytes(property) as usize;
        if object_length == 0 || object_length > MAX_OBJECT_LENGTH {
            let _ = unsafe { BCryptCloseAlgorithmProvider(algorithm, 0) };
            return Err(HashError::InvalidObjectLength);
        }

        let mut object = vec![0u8; object_length];
        let mut hash = BCRYPT_HASH_HANDLE::default();
        let status = unsafe { BCryptCreateHash(algorithm, &mut hash, Some(&mut object), None, 0) };
        if status.0 < 0 {
            let _ = unsafe { BCryptCloseAlgorithmProvider(algorithm, 0) };
            return Err(HashError::NativeFailure(status.0 as u32));
        }

        Ok(Self {
            algorithm,
            hash,
            object,
        })
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) -> Result<(), HashError> {
        let status = unsafe { BCryptHashData(self.hash, bytes, 0) };
        if status.0 < 0 {
            Err(HashError::NativeFailure(status.0 as u32))
        } else {
            Ok(())
        }
    }

    pub(crate) fn finish(mut self) -> Result<String, HashError> {
        let mut output = [0u8; 32];
        let status = unsafe { BCryptFinishHash(self.hash, &mut output, 0) };
        unsafe {
            let _ = BCryptDestroyHash(self.hash);
            let _ = BCryptCloseAlgorithmProvider(self.algorithm, 0);
        }
        self.hash = BCRYPT_HASH_HANDLE::default();
        self.algorithm = BCRYPT_ALG_HANDLE::default();
        self.object.clear();
        if status.0 < 0 {
            return Err(HashError::NativeFailure(status.0 as u32));
        }
        Ok(output.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        unsafe {
            if !self.hash.is_invalid() {
                let _ = BCryptDestroyHash(self.hash);
            }
            if !self.algorithm.is_invalid() {
                let _ = BCryptCloseAlgorithmProvider(self.algorithm, 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Sha256;

    #[test]
    fn sha256_matches_standard_known_vectors() {
        for (input, expected) in [
            (
                b"".as_slice(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc".as_slice(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_slice(),
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            let mut hash = Sha256::new().expect("BCrypt SHA-256 provider should open");
            if !input.is_empty() {
                hash.update(input).expect("BCrypt should accept the input");
            }
            assert_eq!(
                hash.finish().expect("BCrypt should finish SHA-256"),
                expected
            );
        }
    }

    #[test]
    fn sha256_matches_standard_million_a_vector_when_chunked() {
        let input = vec![b'a'; 1_000_000];
        let mut hash = Sha256::new().expect("BCrypt SHA-256 provider should open");
        for chunk in input.chunks(8_191) {
            hash.update(chunk).expect("BCrypt should accept each chunk");
        }

        assert_eq!(
            hash.finish().expect("BCrypt should finish SHA-256"),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }
}
