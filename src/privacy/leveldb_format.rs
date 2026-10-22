//! Read-only LevelDB byte-format decoder. No Env, writable open or recovery.
//! Only the standard bytewise comparator and uncompressed/Snappy tables are
//! supported. Unknown tags/codecs and damaged tails fail the entire snapshot.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

type Result<T> = std::result::Result<T, String>;
pub(super) const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 500_000;
const MAX_KEYS: usize = 50_000;
const MAX_SEQUENCE: u64 = (1 << 56) - 1;
const MAGIC: u64 = 0xdb4775248b80fb57;

struct Work<'a> {
    cancel: &'a AtomicBool,
    records: usize,
    decoded: usize,
}
impl Work<'_> {
    fn step(&mut self) -> Result<()> {
        if self.cancel.load(Ordering::Relaxed) || self.records == MAX_RECORDS {
            return Err("LevelDB inspection stopped or exceeded its record limit.".into());
        }
        self.records += 1;
        Ok(())
    }
    fn bytes(&mut self, count: usize) -> Result<()> {
        self.decoded = self
            .decoded
            .checked_add(count)
            .ok_or("LevelDB size overflow.")?;
        if self.decoded > MAX_BYTES * 2 {
            return Err("LevelDB decoded-content limit reached.".into());
        }
        Ok(())
    }
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let value = self.0.get(..n).ok_or("Truncated LevelDB field.")?;
        self.0 = &self.0[n..];
        Ok(value)
    }
    fn var(&mut self) -> Result<u64> {
        let mut value = 0;
        for shift in (0..70).step_by(7) {
            let byte = self.take(1)?[0];
            if shift == 63 && byte > 1 {
                return Err("LevelDB varint overflow.".into());
            }
            value |= u64::from(byte & 127) << shift;
            if byte < 128 {
                return Ok(value);
            }
        }
        Err("LevelDB varint overflow.".into())
    }
    fn len(&mut self) -> Result<usize> {
        usize::try_from(self.var32()?).map_err(|_| "LevelDB length overflow.".into())
    }
    fn var32(&mut self) -> Result<u32> {
        let before = self.0.len();
        let value = self.var()?;
        if before - self.0.len() > 5 {
            return Err("LevelDB varint32 is overlong.".into());
        }
        u32::try_from(value).map_err(|_| "LevelDB varint32 overflow.".into())
    }
    fn offset(&mut self) -> Result<usize> {
        usize::try_from(self.var()?).map_err(|_| "LevelDB length overflow.".into())
    }
    fn slice(&mut self) -> Result<&'a [u8]> {
        let count = self.len()?;
        self.take(count)
    }
    fn done(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err("Unexpected LevelDB trailing bytes.".into())
        }
    }
}
fn fixed32(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| "Invalid LevelDB fixed32.")?,
    ))
}
fn fixed64(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| "Invalid LevelDB fixed64.")?,
    ))
}

const fn crc_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut value = i as u32;
        let mut bit = 0;
        while bit < 8 {
            value = (value >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(value & 1));
            bit += 1;
        }
        table[i] = value;
        i += 1;
    }
    table
}
fn masked_crc(parts: &[&[u8]]) -> u32 {
    const TABLE: [u32; 256] = crc_table();
    let mut crc = !0u32;
    for bytes in parts {
        for &byte in *bytes {
            crc = TABLE[((crc ^ u32::from(byte)) & 255) as usize] ^ (crc >> 8);
        }
    }
    (!crc).rotate_right(15).wrapping_add(0xa282ead8)
}

fn log_records(
    bytes: &[u8],
    work: &mut Work<'_>,
    mut record: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let mut pending = None::<Vec<u8>>;
    for block in bytes.chunks(32768) {
        let mut pos = 0;
        while pos < block.len() {
            work.step()?;
            let left = &block[pos..];
            if left.len() < 7 {
                if left.iter().any(|&b| b != 0) {
                    return Err("Nonzero LevelDB log trailer.".into());
                }
                break;
            }
            if left[..7] == [0; 7] {
                if left.iter().any(|&b| b != 0) {
                    return Err("Invalid LevelDB log padding.".into());
                }
                break;
            }
            let count = usize::from(u16::from_le_bytes([left[4], left[5]]));
            let kind = left[6];
            let data = left
                .get(7..7 + count)
                .ok_or("Truncated LevelDB log fragment.")?;
            if fixed32(&left[..4])? != masked_crc(&[&[kind], data]) {
                return Err("LevelDB log checksum mismatch.".into());
            }
            work.bytes(data.len())?;
            match kind {
                1 if pending.is_none() => record(data)?,
                2 if pending.is_none() => pending = Some(data.to_vec()),
                3 | 4 if pending.is_some() => {
                    let buffer = pending.as_mut().unwrap();
                    if buffer.len().saturating_add(data.len()) > MAX_BYTES {
                        return Err("LevelDB log record limit reached.".into());
                    }
                    buffer.extend_from_slice(data);
                    if kind == 4 {
                        record(&pending.take().unwrap())?;
                    }
                }
                _ => return Err("Invalid LevelDB log fragment order or type.".into()),
            }
            pos += 7 + count;
        }
    }
    if pending.is_some() {
        return Err("Incomplete LevelDB log record.".into());
    }
    Ok(())
}

// Raw Snappy framing used by LevelDB, not the stream framing protocol.
fn snappy(bytes: &[u8], work: &mut Work<'_>) -> Result<Vec<u8>> {
    let mut c = Cursor(bytes);
    let expected = c.len()?;
    if expected > MAX_BYTES {
        return Err("LevelDB Snappy expansion limit reached.".into());
    }
    work.bytes(expected)?;
    let mut out = Vec::with_capacity(expected);
    while !c.0.is_empty() {
        work.step()?;
        let tag = c.take(1)?[0];
        let (count, offset) = match tag & 3 {
            0 => {
                let code = usize::from(tag >> 2);
                let count = if code < 60 {
                    code + 1
                } else {
                    let mut value = 0usize;
                    for (i, &b) in c.take(code - 59)?.iter().enumerate() {
                        value |= usize::from(b) << (8 * i);
                    }
                    value.checked_add(1).ok_or("Snappy literal overflow.")?
                };
                if count > expected.saturating_sub(out.len()) {
                    return Err("Snappy literal exceeds output.".into());
                }
                out.extend_from_slice(c.take(count)?);
                continue;
            }
            1 => (
                4 + usize::from((tag >> 2) & 7),
                (usize::from(tag & 0xe0) << 3) | usize::from(c.take(1)?[0]),
            ),
            2 => (
                1 + usize::from(tag >> 2),
                usize::from(u16::from_le_bytes(c.take(2)?.try_into().unwrap())),
            ),
            _ => (1 + usize::from(tag >> 2), fixed32(c.take(4)?)? as usize),
        };
        if offset == 0 || offset > out.len() || count > expected.saturating_sub(out.len()) {
            return Err("Invalid Snappy copy.".into());
        }
        for _ in 0..count {
            out.push(out[out.len() - offset]);
        }
    }
    if out.len() != expected {
        return Err("Truncated Snappy output.".into());
    }
    Ok(out)
}

#[derive(Clone, Copy)]
struct Handle {
    offset: usize,
    size: usize,
}
fn handle(c: &mut Cursor<'_>) -> Result<Handle> {
    Ok(Handle {
        offset: c.offset()?,
        size: c.offset()?,
    })
}
fn read_block(bytes: &[u8], h: Handle, work: &mut Work<'_>) -> Result<Vec<u8>> {
    let end = h
        .offset
        .checked_add(h.size)
        .ok_or("LevelDB block overflow.")?;
    let trailer = end.checked_add(5).ok_or("LevelDB block overflow.")?;
    if trailer > bytes.len().saturating_sub(48) {
        return Err("LevelDB block points outside table.".into());
    }
    let data = &bytes[h.offset..end];
    let codec = bytes[end];
    if fixed32(&bytes[end + 1..trailer])? != masked_crc(&[data, &[codec]]) {
        return Err("LevelDB table checksum mismatch.".into());
    }
    match codec {
        0 => {
            work.bytes(data.len())?;
            Ok(data.to_vec())
        }
        1 => snappy(data, work),
        _ => Err("Unsupported LevelDB table compression.".into()),
    }
}
fn entries(
    bytes: &[u8],
    work: &mut Work<'_>,
    mut entry: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    let count_pos = bytes
        .len()
        .checked_sub(4)
        .ok_or("Missing LevelDB restart table.")?;
    let count = fixed32(&bytes[count_pos..])? as usize;
    if count == 0 || count > MAX_RECORDS {
        return Err("Invalid LevelDB restart count.".into());
    }
    let start = count_pos
        .checked_sub(count.checked_mul(4).ok_or("Restart overflow.")?)
        .ok_or("Invalid LevelDB restart table.")?;
    let mut restarts = Vec::with_capacity(count);
    for n in 0..count {
        let offset = fixed32(&bytes[start + n * 4..start + n * 4 + 4])? as usize;
        if (n == 0 && offset != 0)
            || (n > 0 && offset <= restarts[n - 1])
            || offset > start
            || (offset == start && start != 0)
        {
            return Err("Invalid LevelDB restart offset.".into());
        }
        restarts.push(offset);
    }
    let mut c = Cursor(&bytes[..start]);
    let mut key = Vec::new();
    let mut restart_index = 0;
    while !c.0.is_empty() {
        work.step()?;
        let offset = start - c.0.len();
        let shared = c.len()?;
        let unshared = c.len()?;
        let value_len = c.len()?;
        if restart_index < restarts.len() && restarts[restart_index] == offset {
            if shared != 0 {
                return Err("Shared prefix at LevelDB restart.".into());
            }
            restart_index += 1;
        } else if restart_index < restarts.len() && restarts[restart_index] < offset {
            return Err("LevelDB restart is not an entry boundary.".into());
        }
        if shared > key.len() || shared.saturating_add(unshared) > MAX_BYTES {
            return Err("Invalid LevelDB shared key.".into());
        }
        key.truncate(shared);
        key.extend_from_slice(c.take(unshared)?);
        work.bytes(key.len())?;
        entry(&key, c.take(value_len)?)?;
    }
    if start != 0 && restart_index != restarts.len() {
        return Err("Unvisited LevelDB restart.".into());
    }
    Ok(())
}

fn internal(key: &[u8]) -> Result<(&[u8], u64, u8)> {
    let n = key
        .len()
        .checked_sub(8)
        .ok_or("Short LevelDB internal key.")?;
    let trailer = fixed64(&key[n..])?;
    let kind = trailer as u8;
    if kind > 1 {
        return Err("Unsupported LevelDB value type.".into());
    }
    Ok((&key[..n], trailer >> 8, kind))
}
fn internal_order(a: &[u8], b: &[u8]) -> Result<std::cmp::Ordering> {
    let (ak, asq, at) = internal(a)?;
    let (bk, bsq, bt) = internal(b)?;
    Ok(ak
        .cmp(bk)
        .then_with(|| bsq.cmp(&asq))
        .then_with(|| bt.cmp(&at)))
}

#[derive(Default)]
struct Version {
    tables: BTreeMap<u64, (usize, Vec<u8>, Vec<u8>)>,
    levels: BTreeMap<u64, u64>,
    log: Option<u64>,
    previous_log: u64,
    comparator: bool,
    sequence: Option<u64>,
    next_file: Option<u64>,
}
impl Version {
    fn edit(&mut self, bytes: &[u8]) -> Result<()> {
        let mut c = Cursor(bytes);
        // An edit applies deletions before additions, independently of tag order.
        let mut deleted = Vec::new();
        let mut added = Vec::new();
        let mut fields = 0;
        while !c.0.is_empty() {
            fields += 1;
            if fields > MAX_RECORDS {
                return Err("LevelDB manifest field limit reached.".into());
            }
            match c.var32()? {
                1 => {
                    if c.slice()? != b"leveldb.BytewiseComparator" {
                        return Err("Unsupported LevelDB comparator.".into());
                    }
                    self.comparator = true;
                }
                2 => self.log = Some(c.var()?),
                3 => self.next_file = Some(c.var()?),
                4 => {
                    let seq = c.var()?;
                    if seq > MAX_SEQUENCE || self.sequence.is_some_and(|old| old > seq) {
                        return Err("Invalid LevelDB sequence.".into());
                    }
                    self.sequence = Some(seq);
                }
                5 => {
                    level(&mut c)?;
                    internal(c.slice()?)?;
                }
                6 => {
                    let level = level(&mut c)?;
                    deleted.push((level, c.var()?));
                }
                7 => {
                    let level = level(&mut c)?;
                    let number = c.var()?;
                    let size = c.len()?;
                    let smallest = c.slice()?.to_vec();
                    let largest = c.slice()?.to_vec();
                    if size > MAX_BYTES || internal_order(&smallest, &largest)?.is_gt() {
                        return Err("Invalid LevelDB table range/size.".into());
                    }
                    added.push((level, number, (size, smallest, largest)));
                }
                9 => self.previous_log = c.var()?,
                _ => return Err("Unsupported LevelDB manifest tag.".into()),
            }
            if added.len().saturating_add(deleted.len()) > MAX_RECORDS {
                return Err("LevelDB manifest edit limit reached.".into());
            }
        }
        for (level, number) in deleted {
            if self.levels.get(&number) == Some(&level) {
                self.tables.remove(&number);
                self.levels.remove(&number);
            }
        }
        for (level, number, table) in added {
            if self.tables.insert(number, table).is_some() {
                return Err("Duplicate live LevelDB table.".into());
            }
            self.levels.insert(number, level);
        }
        if self.tables.len() > 1024 {
            return Err("LevelDB live table limit reached.".into());
        }
        Ok(())
    }
}
fn level(c: &mut Cursor<'_>) -> Result<u64> {
    let level = u64::from(c.var32()?);
    if level < 7 {
        Ok(level)
    } else {
        Err("Invalid LevelDB level.".into())
    }
}

type State = BTreeMap<Vec<u8>, (u64, Option<Vec<u8>>)>;
fn observe(
    state: &mut State,
    retained: &mut usize,
    key: &[u8],
    seq: u64,
    value: Option<&[u8]>,
) -> Result<()> {
    if seq > MAX_SEQUENCE {
        return Err("LevelDB sequence overflow.".into());
    }
    if let Some((old_seq, old)) = state.get(key) {
        if *old_seq > seq {
            return Ok(());
        }
        if *old_seq == seq {
            return if old.as_deref() == value {
                Ok(())
            } else {
                Err("Conflicting LevelDB sequence.".into())
            };
        }
        *retained -= key.len() + old.as_ref().map_or(0, Vec::len);
    } else if state.len() == MAX_KEYS {
        return Err("LevelDB key limit reached.".into());
    }
    *retained = retained
        .checked_add(key.len())
        .and_then(|n| n.checked_add(value.map_or(0, <[u8]>::len)))
        .ok_or("LevelDB retained size overflow.")?;
    if *retained > MAX_BYTES {
        return Err("LevelDB retained-content limit reached.".into());
    }
    state.insert(key.to_vec(), (seq, value.map(<[u8]>::to_vec)));
    Ok(())
}

/// Only manifest-live tables and recoverable logs contribute. Stale table/log
/// files are deliberately excluded; all retained keys include their raw bytes.
pub(super) fn read(
    files: &BTreeMap<String, Vec<u8>>,
    cancel: &AtomicBool,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    Ok(inspect(files, cancel)?.records)
}

pub(super) struct Image {
    pub records: BTreeMap<Vec<u8>, Vec<u8>>,
    pub last_sequence: u64,
    pub writable_log: Option<String>,
}

pub(super) fn inspect(files: &BTreeMap<String, Vec<u8>>, cancel: &AtomicBool) -> Result<Image> {
    if files
        .values()
        .try_fold(0usize, |n, bytes| n.checked_add(bytes.len()))
        .is_none_or(|n| n > MAX_BYTES)
    {
        return Err("LevelDB snapshot limit reached.".into());
    }
    let mut work = Work {
        cancel,
        records: 0,
        decoded: 0,
    };
    work.step()?;
    let current = files.get("CURRENT").ok_or("Missing LevelDB CURRENT.")?;
    let manifest = std::str::from_utf8(current).map_err(|_| "Invalid LevelDB CURRENT encoding.")?;
    let manifest = manifest
        .strip_suffix('\n')
        .ok_or("Invalid LevelDB CURRENT terminator.")?;
    let number = manifest
        .strip_prefix("MANIFEST-")
        .ok_or("Invalid LevelDB manifest name.")?;
    if !digits(number) {
        return Err("Invalid LevelDB manifest number.".into());
    }
    let mut version = Version::default();
    log_records(
        files
            .get(manifest)
            .ok_or("Missing current LevelDB manifest.")?,
        &mut work,
        |record| version.edit(record),
    )?;
    if !version.comparator
        || version.sequence.is_none()
        || version.log.is_none()
        || version.next_file.is_none()
    {
        return Err("Incomplete LevelDB manifest metadata.".into());
    }
    let mut state = State::new();
    let mut last_sequence = version.sequence.unwrap();
    let mut retained = 0;
    for (&number, (size, smallest, largest)) in &version.tables {
        work.step()?;
        let a = files.get(&format!("{number:06}.ldb"));
        let b = files.get(&format!("{number:06}.sst"));
        if a.is_some() && b.is_some() {
            return Err("Ambiguous LevelDB table extensions.".into());
        }
        let bytes = a.or(b).ok_or("Missing live LevelDB table.")?;
        if bytes.len() != *size || bytes.len() < 48 || fixed64(&bytes[bytes.len() - 8..])? != MAGIC
        {
            return Err("Invalid LevelDB table footer/size.".into());
        }
        let mut footer = Cursor(&bytes[bytes.len() - 48..bytes.len() - 8]);
        let meta = handle(&mut footer)?;
        let index = handle(&mut footer)?;
        if footer.0.iter().any(|&b| b != 0) {
            return Err("Invalid LevelDB footer padding.".into());
        }
        // Validate the metaindex framing even though filters are unnecessary for iteration.
        let meta_bytes = read_block(bytes, meta, &mut work)?;
        entries(&meta_bytes, &mut work, |_, _| Ok(()))?;
        let index_bytes = read_block(bytes, index, &mut work)?;
        let mut blocks = Vec::new();
        let mut previous = None::<Vec<u8>>;
        entries(&index_bytes, &mut work, |key, value| {
            if previous
                .as_ref()
                .is_some_and(|old| internal_order(old, key).is_ok_and(|order| !order.is_lt()))
            {
                return Err("Unsorted LevelDB index.".into());
            }
            internal(key)?;
            previous = Some(key.to_vec());
            let mut c = Cursor(value);
            let h = handle(&mut c)?;
            c.done()?;
            blocks.push((key.to_vec(), h));
            Ok(())
        })?;
        let mut previous = None::<Vec<u8>>;
        let mut first = None::<Vec<u8>>;
        let mut end = 0;
        for (separator, h) in blocks {
            if h.offset < end {
                return Err("Overlapping LevelDB data blocks.".into());
            }
            end = h
                .offset
                .checked_add(h.size)
                .and_then(|n| n.checked_add(5))
                .ok_or("LevelDB block overflow.")?;
            if end > meta.offset || end > index.offset {
                return Err("LevelDB data block overlaps metadata.".into());
            }
            let data = read_block(bytes, h, &mut work)?;
            entries(&data, &mut work, |key, value| {
                let (user, seq, kind) = internal(key)?;
                if seq > version.sequence.unwrap() || (kind == 0 && !value.is_empty()) {
                    return Err("Invalid LevelDB table value/sequence.".into());
                }
                if let Some(old) = &previous {
                    if !internal_order(old, key)?.is_lt() {
                        return Err("Unsorted LevelDB data keys.".into());
                    }
                }
                if internal_order(key, &separator)?.is_gt() {
                    return Err("LevelDB index separator precedes data.".into());
                }
                first.get_or_insert_with(|| key.to_vec());
                previous = Some(key.to_vec());
                observe(
                    &mut state,
                    &mut retained,
                    user,
                    seq,
                    (kind == 1).then_some(value),
                )
            })?;
        }
        if first.as_ref() != Some(smallest) || previous.as_ref() != Some(largest) {
            return Err("LevelDB manifest/table key bounds differ.".into());
        }
    }
    let mut logs = Vec::new();
    for (name, bytes) in files {
        if let Some(stem) = name.strip_suffix(".log").filter(|s| digits(s)) {
            let n = stem
                .parse::<u64>()
                .map_err(|_| "LevelDB log number overflow.")?;
            if n >= version.log.unwrap() || n == version.previous_log {
                if *name != format!("{n:06}.log") {
                    return Err("Noncanonical LevelDB log number.".into());
                }
                logs.push((n, name, bytes));
            }
        }
    }
    logs.sort_by_key(|(n, _, _)| *n);
    let writable_log = logs
        .last()
        .filter(|(n, _, _)| *n >= version.log.unwrap())
        .map(|(_, name, _)| (*name).clone());
    let mut batch_entries = 0usize;
    for (_, _, bytes) in logs {
        log_records(bytes, &mut work, |record| {
            let mut c = Cursor(record);
            let sequence = fixed64(c.take(8)?)?;
            let count = fixed32(c.take(4)?)? as usize;
            batch_entries = batch_entries
                .checked_add(count)
                .ok_or("LevelDB batch entry overflow.")?;
            if batch_entries > MAX_RECORDS {
                return Err("LevelDB batch entry limit reached.".into());
            }
            if count > MAX_RECORDS
                || sequence > MAX_SEQUENCE
                || (count > 0
                    && sequence
                        .checked_add(count as u64 - 1)
                        .is_none_or(|n| n > MAX_SEQUENCE))
            {
                return Err("Invalid LevelDB write batch count/sequence.".into());
            }
            if let Some(end) = sequence
                .checked_add(count as u64)
                .and_then(|n| n.checked_sub(1))
            {
                last_sequence = last_sequence.max(end);
            }
            for n in 0..count {
                let kind = c.take(1)?[0];
                let key = c.slice()?;
                let value = match kind {
                    0 => None,
                    1 => Some(c.slice()?),
                    _ => return Err("Unsupported LevelDB write tag.".into()),
                };
                observe(&mut state, &mut retained, key, sequence + n as u64, value)?;
            }
            c.done()
        })?;
    }
    Ok(Image {
        records: state
            .into_iter()
            .filter_map(|(key, (_, value))| value.map(|value| (key, value)))
            .collect(),
        last_sequence,
        writable_log,
    })
}
fn digits(text: &str) -> bool {
    !text.is_empty() && text.len() <= 20 && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Encode an append-only WAL record at the existing physical block offset.
/// The caller chooses exact raw keys and a sequence above every recovered
/// record (including tombstones), and owns durable intent and file locking.
pub(super) fn append_batch(
    offset: usize,
    sequence: u64,
    rows: &[(Vec<u8>, Option<Vec<u8>>)],
) -> Result<Vec<u8>> {
    fn var(mut n: usize, out: &mut Vec<u8>) {
        while n >= 128 {
            out.push(n as u8 | 128);
            n >>= 7;
        }
        out.push(n as u8);
    }
    if rows.is_empty()
        || rows.len() > MAX_KEYS
        || sequence > MAX_SEQUENCE
        || sequence
            .checked_add(rows.len() as u64 - 1)
            .is_none_or(|n| n > MAX_SEQUENCE)
    {
        return Err("Invalid reviewed LevelDB batch size/sequence.".into());
    }
    let mut body = sequence.to_le_bytes().to_vec();
    body.extend((rows.len() as u32).to_le_bytes());
    let mut keys = std::collections::BTreeSet::new();
    for (key, value) in rows {
        if !keys.insert(key)
            || key.len() > u32::MAX as usize
            || value.as_ref().is_some_and(|v| v.len() > u32::MAX as usize)
        {
            return Err("Duplicate or oversized reviewed LevelDB key/value.".into());
        }
        let needed = key
            .len()
            .saturating_add(value.as_ref().map_or(0, Vec::len))
            .saturating_add(12);
        if body.len().saturating_add(needed) > MAX_BYTES {
            return Err("Reviewed LevelDB batch content limit reached.".into());
        }
        body.push(u8::from(value.is_some()));
        var(key.len(), &mut body);
        body.extend(key);
        if let Some(value) = value {
            var(value.len(), &mut body);
            body.extend(value);
        }
    }
    let mut out = Vec::new();
    let mut remaining = body.as_slice();
    let mut first = true;
    loop {
        let at = offset
            .checked_add(out.len())
            .ok_or("LevelDB append offset overflow.")?;
        let available = 32768 - at % 32768;
        if available < 7 {
            out.resize(out.len() + available, 0);
            continue;
        }
        let length = (available - 7).min(remaining.len());
        let last = length == remaining.len();
        let kind = match (first, last) {
            (true, true) => 1,
            (true, false) => 2,
            (false, false) => 3,
            _ => 4,
        };
        let data = &remaining[..length];
        out.extend(masked_crc(&[&[kind], data]).to_le_bytes());
        out.extend((length as u16).to_le_bytes());
        out.push(kind);
        out.extend(data);
        remaining = &remaining[length..];
        first = false;
        if last {
            break;
        }
    }
    if offset.checked_add(out.len()).is_none_or(|n| n > MAX_BYTES) {
        return Err("LevelDB appended log limit reached.".into());
    }
    Ok(out)
}

#[cfg(test)]
#[path = "leveldb_format_tests.rs"]
pub(super) mod tests;
