//! Invocation equality data, never helper, image, lease or effect authority.
use super::LedgerError;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ContextBinding([u8; 32]);
impl std::fmt::Debug for ContextBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContextBinding { <redacted> }")
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::optimizer_protocol::OriginalContext;
    #[test]
    fn native_context_digest_is_canonical_lossless_and_distinguishes_every_original_field() {
        let original = OriginalContext::fixture();
        let baseline = ContextBinding::observe(&original).unwrap();
        let hexadecimal: String = baseline
            .bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            hexadecimal,
            "239e74f8adb015cf7f43c83bbb3e69b59e7b75dadd77cf13cf994d79c36ceddc"
        );
        assert_eq!(
            baseline,
            ContextBinding::observe(&original.clone()).unwrap()
        );
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
            let changed = OriginalContext::new(command, directory, environment, show).unwrap();
            assert_ne!(baseline, ContextBinding::observe(&changed).unwrap());
        }
        let a = OriginalContext::new(vec![65], vec![66, 67], vec![0, 0], None).unwrap();
        let b = OriginalContext::new(vec![65, 66], vec![67], vec![0, 0], None).unwrap();
        assert_ne!(
            ContextBinding::observe(&a).unwrap(),
            ContextBinding::observe(&b).unwrap()
        );
    }
}
impl ContextBinding {
    #[cfg(windows)]
    pub(crate) fn observe(
        original: &crate::optimizer_protocol::OriginalContext,
    ) -> Result<Self, LedgerError> {
        use crate::native_hash::Sha256;
        original
            .validate()
            .map_err(|_| LedgerError::RequestMismatch)?;
        let mut hash = Sha256::new().map_err(|_| LedgerError::ContextHash)?;
        hash.update(b"DCleaner original invocation context\0v1\0")
            .map_err(|_| LedgerError::ContextHash)?;
        for units in [
            original.command(),
            original.directory(),
            original.environment(),
        ] {
            hash.update(&(units.len() as u64).to_le_bytes())
                .map_err(|_| LedgerError::ContextHash)?;
            // Canonical UTF-16 LE without a UTF-8 conversion or JSON encoding.
            let mut bytes = zeroize::Zeroizing::new([0u8; 8192]);
            for chunk in units.chunks(bytes.len() / 2) {
                for (source, target) in chunk.iter().zip(bytes.chunks_exact_mut(2)) {
                    target.copy_from_slice(&source.to_le_bytes());
                }
                hash.update(&bytes[..chunk.len() * 2])
                    .map_err(|_| LedgerError::ContextHash)?;
            }
        }
        let show = original.show_window();
        hash.update(&[u8::from(show.is_some())])
            .map_err(|_| LedgerError::ContextHash)?;
        if let Some(show) = show {
            hash.update(&show.to_le_bytes())
                .map_err(|_| LedgerError::ContextHash)?;
        }
        Ok(Self(
            hash.finish_bytes().map_err(|_| LedgerError::ContextHash)?,
        ))
    }
    pub(super) fn stored(bytes: Vec<u8>) -> Result<Self, LedgerError> {
        Ok(Self(
            bytes.try_into().map_err(|_| LedgerError::CorruptDatabase)?,
        ))
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.0
    }
    #[cfg(test)]
    pub(super) fn fixture(byte: u8) -> Self {
        Self([byte; 32])
    }
    #[cfg(test)]
    pub(crate) fn fixture_default() -> Self {
        #[cfg(windows)]
        {
            Self::observe(&crate::optimizer_protocol::OriginalContext::fixture()).unwrap()
        }
        #[cfg(not(windows))]
        {
            Self::fixture(1)
        }
    }
}
