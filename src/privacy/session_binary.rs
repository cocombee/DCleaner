//! Bounded, read-only SNSS framing and a pure native-derived pinned-tab transform.
//! No path discovery, public scanner records, file effects or recovery authority.
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    sync::atomic::{AtomicBool, Ordering},
};

pub(super) const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_COMMANDS: usize = 100_000;
#[derive(Clone, Copy)]
struct Limits {
    bytes: usize,
    commands: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: MAX_BYTES,
            commands: MAX_COMMANDS,
        }
    }
}
struct Command {
    kind: u8,
    span: Range<usize>,
    payload: Range<usize>,
}
pub(super) struct Document<'a> {
    source: &'a [u8],
    commands: Vec<Command>,
}
#[derive(Debug, PartialEq)]
pub(super) enum Plan {
    /// Native status0 enters the separate generic file driver. This is not
    /// permission to delete a file; a reviewed current-ID owner is still needed.
    DeleteFile,
    /// Physical command counts describe the transform, not native GUI item units.
    RewritePinned {
        bytes: Vec<u8>,
        kept: Vec<usize>,
        removed_commands: usize,
    },
}
fn check(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Session observation was cancelled.".into())
    } else {
        Ok(())
    }
}
fn word(bytes: &[u8], at: usize) -> Result<u32, String> {
    let raw = bytes
        .get(at..at + 4)
        .ok_or("Session command has an unsupported short fixed payload.")?;
    Ok(u32::from_le_bytes(raw.try_into().unwrap()))
}
impl<'a> Document<'a> {
    pub(super) fn parse(source: &'a [u8], cancel: &AtomicBool) -> Result<Self, String> {
        Self::parse_with_limits(source, cancel, Limits::default())
    }
    fn parse_with_limits(
        source: &'a [u8],
        cancel: &AtomicBool,
        limits: Limits,
    ) -> Result<Self, String> {
        check(cancel)?;
        if source.len() > limits.bytes {
            return Err("Session exceeds the safe observation size limit.".into());
        }
        if source.len() < 8 || &source[..4] != b"SNSS" {
            return Err("Session header is unsupported or incomplete.".into());
        }
        let mut commands = Vec::new();
        let mut pos = 8;
        while pos < source.len() {
            check(cancel)?;
            if commands.len() >= limits.commands {
                return Err("Session command observation limit reached.".into());
            }
            let prefix = source
                .get(pos..pos + 3)
                .ok_or("Session command framing is incomplete.")?;
            let size = u16::from_le_bytes([prefix[0], prefix[1]]) as usize;
            let end = pos
                .checked_add(2)
                .and_then(|p| p.checked_add(size))
                .ok_or("Session command size overflow.")?;
            if size < 1 || end > source.len() {
                return Err("Session command size is invalid or incomplete.".into());
            }
            commands.push(Command {
                kind: prefix[2],
                span: pos..end,
                payload: pos + 3..end,
            });
            pos = end;
        }
        check(cancel)?;
        Ok(Self { source, commands })
    }
    pub(super) fn plan(&self, cancel: &AtomicBool) -> Result<Plan, String> {
        check(cancel)?;
        let mut pinned = BTreeSet::new();
        for command in &self.commands {
            check(cancel)?;
            if command.kind == 12 {
                let payload = &self.source[command.payload.clone()];
                let tab = word(payload, 0)?;
                let state = word(payload, 4)?;
                if state == 1 {
                    pinned.insert(tab);
                } else {
                    pinned.remove(&tab);
                }
            }
        }
        if pinned.is_empty() {
            return Ok(Plan::DeleteFile);
        }
        let mut selected = BTreeMap::new();
        for command in &self.commands {
            check(cancel)?;
            if command.kind == 7 {
                let payload = &self.source[command.payload.clone()];
                let tab = word(payload, 0)?;
                if pinned.contains(&tab) {
                    selected.insert(tab, word(payload, 4)?);
                }
            }
        }
        let mut bytes = Vec::with_capacity(self.source.len());
        bytes.extend_from_slice(&self.source[..8]);
        let mut kept = Vec::new();
        for (index, command) in self.commands.iter().enumerate() {
            check(cancel)?;
            let payload = &self.source[command.payload.clone()];
            let keep = match command.kind {
                2 | 8 | 9 | 12 => true,
                0 => !selected.is_empty() && selected.contains_key(&word(payload, 4)?),
                7 => {
                    let tab = word(payload, 0)?;
                    match selected.get(&tab) {
                        Some(index) => *index == word(payload, 4)?,
                        None => false,
                    }
                }
                1 | 6 => pickle_pair(payload)
                    .is_some_and(|(tab, index)| selected.get(&tab) == Some(&index)),
                _ => false,
            };
            if keep {
                kept.push(index);
                bytes.extend_from_slice(&self.source[command.span.clone()]);
            }
        }
        check(cancel)?;
        Ok(Plan::RewritePinned {
            bytes,
            removed_commands: self.commands.len() - kept.len(),
            kept,
        })
    }
}
fn pickle_pair(payload: &[u8]) -> Option<(u32, u32)> {
    let declared = word(payload, 0).ok()?;
    // Native uses the low16 bits of string length; framing limits payload to65534.
    let header = (payload.len() as u16 as u32).wrapping_sub(declared) as usize;
    if header == 0 || header > payload.len() || header % 4 != 0 || declared < 8 {
        return None;
    }
    Some((word(payload, header).ok()?, word(payload, header + 4).ok()?))
}

#[cfg(test)]
#[path = "session_binary_tests.rs"]
mod tests;
