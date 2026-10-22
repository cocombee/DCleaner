//! Owned format fixtures, assembled independently of the decoder. The CRC
//! fixture writer uses the slow bit recurrence, not the production table.
use super::*;

#[test]
fn independently_written_wal_snappy_tables_and_mixed_stores_match_full_iterator() {
    fn hex(text: &str) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0);
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/leveldb-independent.json"
    ))
    .unwrap();
    assert_eq!(corpus["contains_only_owned_synthetic_data"], true);
    for dataset in corpus["datasets"].as_array().unwrap() {
        let files = dataset["files"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| (name.clone(), hex(value.as_str().unwrap())))
            .collect();
        let expected: BTreeMap<_, _> = dataset["expected"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (hex(key), hex(value.as_str().unwrap())))
            .collect();
        assert_eq!(
            read(&files, &AtomicBool::new(false))
                .unwrap_or_else(|e| panic!("{}: {e}", dataset["case"])),
            expected,
            "{}",
            dataset["case"]
        );
    }
}

pub(crate) fn var(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while n >= 128 {
        out.push(n as u8 | 128);
        n >>= 7;
    }
    out.push(n as u8);
    out
}
fn field(bytes: &[u8]) -> Vec<u8> {
    [var(bytes.len() as u64), bytes.to_vec()].concat()
}
fn crc(bytes: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in bytes {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0x82f63b78
            } else {
                c >> 1
            };
        }
    }
    !c
}
fn masked(bytes: &[u8]) -> [u8; 4] {
    crc(bytes)
        .rotate_right(15)
        .wrapping_add(0xa282ead8)
        .to_le_bytes()
}
pub(crate) fn log(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for record in records {
        let mut rest = record.as_slice();
        let mut first = true;
        loop {
            let available = 32768 - out.len() % 32768;
            if available < 7 {
                out.resize(out.len() + available, 0);
                continue;
            }
            let n = (available - 7).min(rest.len());
            let last = n == rest.len();
            let kind = match (first, last) {
                (true, true) => 1,
                (true, false) => 2,
                (false, false) => 3,
                _ => 4,
            };
            out.extend(masked(&[vec![kind], rest[..n].to_vec()].concat()));
            out.extend((n as u16).to_le_bytes());
            out.push(kind);
            out.extend(&rest[..n]);
            rest = &rest[n..];
            first = false;
            if last {
                break;
            }
        }
    }
    out
}
pub(crate) fn batch(sequence: u64, rows: &[(&[u8], Option<&[u8]>)]) -> Vec<u8> {
    let mut out = sequence.to_le_bytes().to_vec();
    out.extend((rows.len() as u32).to_le_bytes());
    for (key, value) in rows {
        out.push(u8::from(value.is_some()));
        out.extend(field(key));
        if let Some(value) = value {
            out.extend(field(value));
        }
    }
    out
}
pub(crate) fn empty() -> BTreeMap<String, Vec<u8>> {
    let mut manifest = vec![1];
    manifest.extend(field(b"leveldb.BytewiseComparator"));
    for (tag, n) in [(2, 3), (3, 20), (4, 10)] {
        manifest.push(tag);
        manifest.extend(var(n));
    }
    BTreeMap::from([
        ("CURRENT".into(), b"MANIFEST-000001\n".to_vec()),
        ("MANIFEST-000001".into(), log(&[manifest])),
    ])
}
fn key(user: &[u8], sequence: u64, kind: u8) -> Vec<u8> {
    [
        user.to_vec(),
        ((sequence << 8) | u64::from(kind)).to_le_bytes().to_vec(),
    ]
    .concat()
}
fn block(rows: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut restart = Vec::new();
    for (key, value) in rows {
        restart.push(out.len() as u32);
        out.push(0);
        out.extend(var(key.len() as u64));
        out.extend(var(value.len() as u64));
        out.extend(key);
        out.extend(value);
    }
    if restart.is_empty() {
        restart.push(0);
    }
    for n in &restart {
        out.extend(n.to_le_bytes());
    }
    out.extend((restart.len() as u32).to_le_bytes());
    out
}
fn framed(out: &mut Vec<u8>, data: &[u8], compressed: bool) -> Vec<u8> {
    let data = if compressed {
        let mut encoded = var(data.len() as u64);
        assert!(data.len() < 256);
        if data.len() <= 60 {
            encoded.push(((data.len() - 1) << 2) as u8);
        } else {
            encoded.extend([240, (data.len() - 1) as u8]);
        }
        encoded.extend(data);
        encoded
    } else {
        data.to_vec()
    };
    let handle = [var(out.len() as u64), var(data.len() as u64)].concat();
    out.extend(&data);
    out.push(u8::from(compressed));
    out.extend(masked(&[data, vec![u8::from(compressed)]].concat()));
    handle
}
fn table(rows: &[(Vec<u8>, Vec<u8>)], compressed: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let data_handle = framed(&mut out, &block(rows), compressed);
    let meta_handle = framed(&mut out, &block(&[]), false);
    let last = rows.last().unwrap().0.clone();
    let index_handle = framed(&mut out, &block(&[(last, data_handle)]), false);
    let mut footer = [meta_handle, index_handle].concat();
    footer.resize(40, 0);
    footer.extend(MAGIC.to_le_bytes());
    out.extend(footer);
    out
}
fn add_table(
    files: &mut BTreeMap<String, Vec<u8>>,
    number: u64,
    rows: &[(Vec<u8>, Vec<u8>)],
    compressed: bool,
) {
    let table = table(rows, compressed);
    let mut edit = vec![7, 0];
    edit.extend(var(number));
    edit.extend(var(table.len() as u64));
    edit.extend(field(&rows.first().unwrap().0));
    edit.extend(field(&rows.last().unwrap().0));
    files
        .get_mut("MANIFEST-000001")
        .unwrap()
        .extend(log(&[edit]));
    files.insert(format!("{number:06}.ldb"), table);
}
fn read_ok(files: &BTreeMap<String, Vec<u8>>) -> BTreeMap<Vec<u8>, Vec<u8>> {
    read(files, &AtomicBool::new(false)).unwrap()
}

#[test]
fn crc_has_independent_standard_vector() {
    assert_eq!(crc(b"123456789"), 0xe3069283);
    assert_eq!(
        masked_crc(&[b"1234", b"56789"]),
        u32::from_le_bytes(masked(b"123456789"))
    );
}
#[test]
fn wal_uses_full_binary_keys_latest_sequence_and_tombstones() {
    let mut files = empty();
    files.insert(
        "000003.log".into(),
        log(&[
            batch(11, &[(b"a\0one", Some(b"old")), (b"a\0two", Some(b"keep"))]),
            batch(
                14,
                &[
                    (b"a\0one", Some(b"new")),
                    (b"gone", Some(b"x")),
                    (b"gone", None),
                ],
            ),
        ]),
    );
    assert_eq!(
        read_ok(&files),
        BTreeMap::from([
            (b"a\0one".to_vec(), b"new".to_vec()),
            (b"a\0two".to_vec(), b"keep".to_vec())
        ])
    );
}
#[test]
fn active_manifest_not_all_files_controls_live_tables() {
    let mut files = empty();
    add_table(
        &mut files,
        4,
        &[(key(b"gone", 2, 1), b"old".to_vec())],
        false,
    );
    let mut deletion = vec![6, 0];
    deletion.extend(var(4));
    files
        .get_mut("MANIFEST-000001")
        .unwrap()
        .extend(log(&[deletion]));
    files.insert("MANIFEST-000019".into(), vec![255]);
    add_table(
        &mut files,
        8,
        &[(key(b"live", 8, 1), b"now".to_vec())],
        true,
    );
    files.insert("000002.log".into(), vec![255]); // Older than log number, not replayed.
    assert_eq!(
        read_ok(&files),
        BTreeMap::from([(b"live".to_vec(), b"now".to_vec())])
    );
}
#[test]
fn tables_and_wal_merge_by_sequence_not_filename() {
    let mut files = empty();
    add_table(
        &mut files,
        8,
        &[
            (key(b"a", 9, 1), b"nine".to_vec()),
            (key(b"a", 3, 1), b"three".to_vec()),
            (key(b"b", 8, 0), vec![]),
        ],
        true,
    );
    add_table(
        &mut files,
        9,
        &[
            (key(b"a", 5, 1), b"five".to_vec()),
            (key(b"b", 2, 1), b"old".to_vec()),
        ],
        false,
    );
    files.insert(
        "000003.log".into(),
        log(&[batch(11, &[(b"a", None), (b"c", Some(b"twelve"))])]),
    );
    assert_eq!(
        read_ok(&files),
        BTreeMap::from([(b"c".to_vec(), b"twelve".to_vec())])
    );
}
#[test]
fn fragmented_large_records_and_zero_header_boundary_reassemble() {
    let huge = vec![b'x'; 100_000];
    let mut files = empty();
    files.insert(
        "000003.log".into(),
        log(&[batch(11, &[(b"large", Some(&huge))])]),
    );
    assert_eq!(read_ok(&files).get(b"large".as_slice()), Some(&huge));
    let mut work = Work {
        cancel: &AtomicBool::new(false),
        records: 0,
        decoded: 0,
    };
    let records = [vec![7; 32754], vec![8; 10]];
    let mut seen = Vec::new();
    log_records(&log(&records), &mut work, |v| {
        seen.push(v.to_vec());
        Ok(())
    })
    .unwrap();
    assert_eq!(seen, records);
}
#[test]
fn checksums_missing_live_files_and_conflicting_versions_refuse() {
    let mut files = empty();
    add_table(&mut files, 4, &[(key(b"a", 2, 1), vec![7])], false);
    let mut bad = files.clone();
    bad.get_mut("000004.ldb").unwrap()[4] ^= 1;
    assert!(read(&bad, &AtomicBool::new(false)).is_err());
    let mut bad = files.clone();
    bad.remove("000004.ldb");
    assert!(read(&bad, &AtomicBool::new(false)).is_err());
    let mut bad = files.clone();
    add_table(&mut bad, 5, &[(key(b"a", 2, 1), vec![8])], false);
    assert!(read(&bad, &AtomicBool::new(false)).is_err());
    let mut bad = files;
    bad.insert(
        "000003.log".into(),
        log(&[batch(11, &[(b"a", Some(b"x"))])]),
    );
    bad.get_mut("000003.log").unwrap()[0] ^= 1;
    assert!(read(&bad, &AtomicBool::new(false)).is_err());
}
#[test]
fn manifest_current_comparator_and_unknown_tags_refuse() {
    for current in [
        "../MANIFEST-000001\n",
        "MANIFEST-000001",
        "MANIFEST-1\ntrailing",
        "MANIFEST-18446744073709551616\n",
    ] {
        let mut files = empty();
        files.insert("CURRENT".into(), current.as_bytes().to_vec());
        assert!(read(&files, &AtomicBool::new(false)).is_err());
    }
    for edit in [
        vec![10],
        [vec![1], field(b"custom.Comparator")].concat(),
        vec![4, 1],
        vec![5, 7],
    ] {
        let mut files = empty();
        files
            .get_mut("MANIFEST-000001")
            .unwrap()
            .extend(log(&[edit]));
        assert!(read(&files, &AtomicBool::new(false)).is_err());
    }
}
#[test]
fn snappy_all_copy_types_overlap_and_invalid_lengths() {
    // output 'abcabcabcabcabcabc': literal abc, copy1/2/4 each length >=4.
    let encoded = [18, 8, b'a', b'b', b'c', 1, 3, 18, 3, 0, 23, 3, 0, 0, 0];
    let mut work = Work {
        cancel: &AtomicBool::new(false),
        records: 0,
        decoded: 0,
    };
    assert_eq!(snappy(&encoded, &mut work).unwrap(), b"abcabcabcabcabcabc");
    for bad in [
        &[5, 1, 0][..],
        &[1, 0, b'a', 2, 1, 0],
        &[2, 0, b'a'],
        &[255; 12],
    ] {
        assert!(snappy(bad, &mut work).is_err());
    }
}
#[test]
fn block_prefixes_restarts_and_bounds_are_checked() {
    let mut work = Work {
        cancel: &AtomicBool::new(false),
        records: 0,
        decoded: 0,
    };
    let mut shared = vec![0, 3, 1, b'a', b'b', b'c', 1, 2, 1, 1, b'd', 2];
    shared.extend(0u32.to_le_bytes());
    shared.extend(1u32.to_le_bytes());
    let mut keys = Vec::new();
    entries(&shared, &mut work, |k, _| {
        keys.push(k.to_vec());
        Ok(())
    })
    .unwrap();
    assert_eq!(keys, [b"abc".to_vec(), b"abd".to_vec()]);
    let mut bad = shared.clone();
    bad[7] = 5;
    assert!(entries(&bad, &mut work, |_, _| Ok(())).is_err());
    let mut bad = shared;
    let n = bad.len();
    bad[n - 8] = 1;
    assert!(entries(&bad, &mut work, |_, _| Ok(())).is_err());
}
#[test]
fn truncated_and_malformed_inputs_never_yield_a_partial_success() {
    let mut files = empty();
    add_table(&mut files, 4, &[(key(b"a", 2, 1), vec![7])], false);
    let table = files["000004.ldb"].clone();
    for n in 0..table.len() {
        let mut bad = files.clone();
        bad.insert("000004.ldb".into(), table[..n].to_vec());
        assert!(read(&bad, &AtomicBool::new(false)).is_err());
    }
    let wal = log(&[batch(11, &[(b"a", Some(b"new"))])]);
    for n in 1..wal.len() {
        let mut bad = empty();
        bad.insert("000003.log".into(), wal[..n].to_vec());
        assert!(read(&bad, &AtomicBool::new(false)).is_err());
    }
    assert!(read(&files, &AtomicBool::new(true)).is_err());
}
#[test]
fn previous_log_and_empty_batch_have_native_recovery_shape() {
    let mut files = empty();
    files
        .get_mut("MANIFEST-000001")
        .unwrap()
        .extend(log(&[vec![9, 2]]));
    files.insert(
        "000002.log".into(),
        log(&[batch(11, &[(b"previous", Some(b"yes"))])]),
    );
    files.insert("000003.log".into(), log(&[batch(12, &[])]));
    assert_eq!(read_ok(&files).len(), 1);
}
#[test]
fn manifest_deletion_obeys_level_and_sst_alias_is_supported() {
    let mut files = empty();
    add_table(&mut files, 4, &[(key(b"a", 2, 1), vec![7])], false);
    files
        .get_mut("MANIFEST-000001")
        .unwrap()
        .extend(log(&[vec![6, 1, 4]])); // Different level does not remove L0.
    let table = files.remove("000004.ldb").unwrap();
    files.insert("000004.sst".into(), table);
    assert_eq!(read_ok(&files).len(), 1);
}

#[test]
fn varint32_fields_do_not_accept_varint64_encodings() {
    let mut files = empty();
    let mut bad = 11u64.to_le_bytes().to_vec();
    bad.extend(1u32.to_le_bytes());
    bad.push(1);
    // Key length 1 encoded across six bytes; valid varint64, invalid varint32.
    bad.extend([0x81, 0x80, 0x80, 0x80, 0x80, 0]);
    bad.push(b'a');
    bad.extend([1, b'v']);
    files.insert("000003.log".into(), log(&[bad]));
    assert!(
        read(&files, &AtomicBool::new(false))
            .unwrap_err()
            .contains("varint32")
    );
    let mut files = empty();
    files
        .get_mut("MANIFEST-000001")
        .unwrap()
        .extend(log(&[vec![0x81, 0x80, 0x80, 0x80, 0x80, 0, 0]]));
    assert!(
        read(&files, &AtomicBool::new(false))
            .unwrap_err()
            .contains("varint32")
    );
}

#[test]
fn append_sequences_follow_deleted_and_empty_batch_high_watermarks() {
    let mut files = empty();
    files.insert(
        "000003.log".into(),
        log(&[batch(30, &[(b"gone", None)]), batch(50, &[])]),
    );
    let image = inspect(&files, &AtomicBool::new(false)).unwrap();
    assert!(image.records.is_empty());
    assert_eq!(image.last_sequence, 49);
    assert_eq!(image.writable_log.as_deref(), Some("000003.log"));
    let append = append_batch(
        files["000003.log"].len(),
        50,
        &[(b"restored".to_vec(), Some(b"value".to_vec()))],
    )
    .unwrap();
    files.get_mut("000003.log").unwrap().extend(append);
    assert_eq!(
        read_ok(&files),
        BTreeMap::from([(b"restored".to_vec(), b"value".to_vec())])
    );
    let image = inspect(&files, &AtomicBool::new(false)).unwrap();
    assert_eq!(image.last_sequence, 50);
}

#[test]
fn appended_physical_records_honor_every_block_boundary_case() {
    for offset in [
        0, 7, 32760, 32761, 32762, 32763, 32764, 32765, 32766, 32767, 32768,
    ] {
        let mut before = if offset == 0 {
            Vec::new()
        } else if offset == 32768 {
            log(&[vec![7; 32761]])
        } else {
            log(&[vec![7; offset - 7]])
        };
        assert_eq!(before.len(), offset);
        let rows = [
            (b"one\0a".to_vec(), None),
            (b"two\0b".to_vec(), Some(vec![8; 100_000])),
        ];
        before.extend(append_batch(offset, 11, &rows).unwrap());
        let mut observed = Vec::new();
        let cancel = AtomicBool::new(false);
        log_records(
            &before,
            &mut Work {
                cancel: &cancel,
                records: 0,
                decoded: 0,
            },
            |record| {
                observed.push(record.to_vec());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            observed.last(),
            Some(&batch(
                11,
                &[(b"one\0a", None), (b"two\0b", Some(&vec![8; 100_000]))]
            ))
        );
    }
    assert!(append_batch(0, MAX_SEQUENCE, &[(vec![1], None), (vec![2], None)]).is_err());
    assert!(append_batch(0, 1, &[(vec![1], None), (vec![1], None)]).is_err());
}
