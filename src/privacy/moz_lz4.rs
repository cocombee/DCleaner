//! Bounded Mozilla carrier and independent LZ4 block codec. No file access.
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) const MAX_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_CARRIER: usize = MAX_BYTES + MAX_BYTES / 255 + 32;
const MAGIC: &[u8; 8] = b"mozLz40\0";
fn invalid() -> String {
    "Mozilla session compression is malformed or exceeds its observation limit.".into()
}
fn check(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Mozilla session observation was cancelled.".into())
    } else {
        Ok(())
    }
}
fn length(input: &[u8], pos: &mut usize, base: usize, max: usize) -> Result<usize, String> {
    let mut size = base;
    if base == 15 {
        loop {
            let byte = *input.get(*pos).ok_or_else(invalid)? as usize;
            *pos += 1;
            size = size
                .checked_add(byte)
                .filter(|n| *n <= max)
                .ok_or_else(invalid)?;
            if byte != 255 {
                break;
            }
        }
    }
    if size > max { Err(invalid()) } else { Ok(size) }
}
pub(super) fn decoded_length(input: &[u8]) -> Result<usize, String> {
    if input.len() < 13 || input.len() > MAX_CARRIER || input.get(..8) != Some(MAGIC) {
        return Err(invalid());
    }
    let expected = u32::from_le_bytes(input[8..12].try_into().unwrap()) as usize;
    if expected > MAX_BYTES {
        return Err(invalid());
    }
    Ok(expected)
}
pub(super) fn decode(input: &[u8], cancel: &AtomicBool) -> Result<Vec<u8>, String> {
    check(cancel)?;
    let expected = decoded_length(input)?;
    let mut output = Vec::with_capacity(expected);
    let mut pos = 12;
    let mut last_match = None;
    loop {
        check(cancel)?;
        let token = *input.get(pos).ok_or_else(invalid)?;
        pos += 1;
        let literals = length(
            input,
            &mut pos,
            (token >> 4) as usize,
            expected - output.len(),
        )?;
        let end = pos
            .checked_add(literals)
            .filter(|end| *end <= input.len())
            .ok_or_else(invalid)?;
        output.extend_from_slice(&input[pos..end]);
        pos = end;
        if pos == input.len() {
            if output.len() != expected
                || last_match.is_some_and(|start| literals < 5 || start + 12 > expected)
            {
                return Err(invalid());
            }
            check(cancel)?;
            return Ok(output);
        }
        let raw = input.get(pos..pos + 2).ok_or_else(invalid)?;
        let offset = u16::from_le_bytes(raw.try_into().unwrap()) as usize;
        pos += 2;
        if offset == 0 || offset > output.len() {
            return Err(invalid());
        }
        let matches = length(
            input,
            &mut pos,
            (token & 15) as usize,
            expected - output.len(),
        )?
        .checked_add(4)
        .filter(|n| *n <= expected - output.len())
        .ok_or_else(invalid)?;
        let start = output.len();
        last_match = Some(start);
        for index in start..start + matches {
            if index & 1023 == 0 {
                check(cancel)?;
            }
            output.push(output[index - offset]);
        }
    }
}
fn extended(output: &mut Vec<u8>, mut size: usize) {
    while size >= 255 {
        output.push(255);
        size -= 255;
    }
    output.push(size as u8);
}
fn sequence(output: &mut Vec<u8>, literals: &[u8], matched: Option<(usize, usize)>) {
    let count = matched.map_or(0, |(_, size)| size - 4);
    output.push(((literals.len().min(15) as u8) << 4) | count.min(15) as u8);
    if literals.len() >= 15 {
        extended(output, literals.len() - 15);
    }
    output.extend_from_slice(literals);
    if let Some((offset, _)) = matched {
        output.extend_from_slice(&(offset as u16).to_le_bytes());
        if count >= 15 {
            extended(output, count - 15);
        }
    }
}
fn hash(input: &[u8], index: usize) -> usize {
    (u32::from_le_bytes(input[index..index + 4].try_into().unwrap()).wrapping_mul(2654435761) >> 16)
        as usize
}
pub(super) fn encode(input: &[u8], cancel: &AtomicBool) -> Result<Vec<u8>, String> {
    check(cancel)?;
    if input.len() > MAX_BYTES {
        return Err(invalid());
    }
    let mut output = Vec::with_capacity(input.len() + input.len() / 255 + 32);
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&(input.len() as u32).to_le_bytes());
    let mut table = vec![usize::MAX; 65536];
    let (mut anchor, mut pos) = (0, 0);
    while pos + 12 <= input.len() {
        check(cancel)?;
        let slot = hash(input, pos);
        let previous = table[slot];
        table[slot] = pos;
        if previous == usize::MAX
            || pos - previous > 65535
            || input[previous..previous + 4] != input[pos..pos + 4]
        {
            pos += 1;
            continue;
        }
        let mut size = 4;
        while pos + size < input.len() - 5 && input[previous + size] == input[pos + size] {
            if size & 1023 == 0 {
                check(cancel)?;
            }
            size += 1;
        }
        sequence(
            &mut output,
            &input[anchor..pos],
            Some((pos - previous, size)),
        );
        pos += size;
        anchor = pos;
        if pos >= 2 && pos + 2 <= input.len() {
            table[hash(input, pos - 2)] = pos - 2;
        }
    }
    sequence(&mut output, &input[anchor..], None);
    check(cancel)?;
    if output.len() > MAX_CARRIER {
        return Err(invalid());
    }
    Ok(output)
}

#[cfg(test)]
#[path = "moz_lz4_tests.rs"]
mod tests;
