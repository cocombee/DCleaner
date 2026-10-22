use super::*;

fn carrier(size: usize, block: &[u8]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&(size as u32).to_le_bytes());
    bytes.extend_from_slice(block);
    bytes
}
#[test]
fn literal_extended_and_overlapping_match_vectors_decode_to_exact_owned_bytes() {
    let cancel = AtomicBool::new(false);
    assert_eq!(decode(&carrier(0, &[0]), &cancel).unwrap(), b"");
    assert_eq!(
        decode(&carrier(3, &[0x30, b'a', b'b', b'c']), &cancel).unwrap(),
        b"abc"
    );
    // One literal, seven copied bytes with offset1, then five final literals.
    assert_eq!(
        decode(&carrier(13, b"\x13a\x01\x00\x50bcdef"), &cancel).unwrap(),
        b"aaaaaaaabcdef"
    );
    let mut block = vec![0xf0, 255, 10];
    block.extend_from_slice(&[b'z'; 280]);
    assert_eq!(decode(&carrier(280, &block), &cancel).unwrap(), [b'z'; 280]);
    let mut block = b"\x1fa\x01\x00\xff\x0a\x50bcdef".to_vec();
    assert_eq!(
        decode(&carrier(290, &block), &cancel).unwrap(),
        [vec![b'a'; 285], b"bcdef".to_vec()].concat()
    );
    block[3] = 0; // Zero offset is invalid even with an otherwise valid shape.
    block[2] = 0;
    assert!(decode(&carrier(290, &block), &cancel).is_err());
}
#[test]
fn malformed_headers_offsets_lengths_tail_rules_and_output_sizes_refuse() {
    let cancel = AtomicBool::new(false);
    for block in [
        &b""[..],
        &b"\xf0"[..],
        &b"\xf0\xff"[..],
        &b"\x00\x00\x00"[..],
        &b"\x10a\x02\x00\x50bcdef"[..],
        &b"\x10a\x01"[..],
    ] {
        assert!(decode(&carrier(20, block), &cancel).is_err(), "{block:?}");
    }
    assert!(decode(&carrier(12, b"\x17a\x01\x00"), &cancel).is_err());
    assert!(decode(&carrier(10, b"\x14a\x01\x00\x10b"), &cancel).is_err());
    for size in [0, 2, 4, MAX_BYTES + 1, u32::MAX as usize] {
        assert!(decode(&carrier(size, b"\x30abc"), &cancel).is_err());
    }
    let good = carrier(3, b"\x30abc");
    for cut in 0..good.len() {
        assert!(decode(&good[..cut], &cancel).is_err());
    }
    for pos in 0..8 {
        let mut bad = good.clone();
        bad[pos] ^= 1;
        assert!(decode(&bad, &cancel).is_err());
    }
}
#[test]
fn encoder_respects_independent_block_tail_rules_and_compresses_repetition() {
    let cancel = AtomicBool::new(false);
    for size in [
        0,
        1,
        4,
        5,
        12,
        13,
        14,
        15,
        270,
        280,
        65535,
        65536,
        131072,
        1024 * 1024,
    ] {
        let source = (0..size).map(|n| (n % 37) as u8).collect::<Vec<_>>();
        let encoded = encode(&source, &cancel).unwrap();
        assert_eq!(decode(&encoded, &cancel).unwrap(), source);
        if size >= 65535 {
            assert!(encoded.len() < source.len() / 10);
        }
    }
}
#[test]
fn arbitrary_bounded_carriers_never_panic_or_exceed_declared_output() {
    let cancel = AtomicBool::new(false);
    let mut seed = 0x93ac2471u32;
    for index in 0..10000 {
        let size = index % 257;
        let block = (0..index % 97)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed as u8
            })
            .collect::<Vec<_>>();
        if let Ok(bytes) = decode(&carrier(size, &block), &cancel) {
            assert_eq!(bytes.len(), size);
        }
    }
}
#[test]
fn cancellation_and_decoded_or_encoded_bounds_are_explicit() {
    let cancel = AtomicBool::new(true);
    assert!(encode(b"owned", &cancel).unwrap_err().contains("cancelled"));
    assert!(
        decode(&carrier(3, b"\x30abc"), &cancel)
            .unwrap_err()
            .contains("cancelled")
    );
    cancel.store(false, Ordering::Relaxed);
    assert!(encode(&vec![0; MAX_BYTES + 1], &cancel).is_err());
    assert!(decode(&carrier(MAX_BYTES + 1, b"\x00"), &cancel).is_err());
    assert!(decode(&vec![0; MAX_CARRIER + 1], &cancel).is_err());
}
#[test]
fn pinned_upstream_lz4_vectors_decode_without_relying_on_the_rust_encoder() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/mozilla-lz4.json")).unwrap();
    let cancel = AtomicBool::new(false);
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 20);
    for case in cases {
        let hex = case["block_hex"].as_str().unwrap();
        let block = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let expected = case["plain"].as_str().unwrap().as_bytes();
        assert_eq!(
            decode(&carrier(expected.len(), &block), &cancel).unwrap(),
            expected,
            "{}",
            case["name"]
        );
    }
}
