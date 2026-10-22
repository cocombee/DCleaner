use super::*;
fn uncancelled() -> AtomicBool {
    AtomicBool::new(false)
}
fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|n| n.to_le_bytes()).collect()
}
fn carrier(commands: &[(u8, Vec<u8>)], version: u32) -> Vec<u8> {
    let mut out = b"SNSS".to_vec();
    out.extend_from_slice(&version.to_le_bytes());
    for (kind, payload) in commands {
        out.extend_from_slice(&u16::try_from(payload.len() + 1).unwrap().to_le_bytes());
        out.push(*kind);
        out.extend_from_slice(payload);
    }
    out
}
fn parse_plan(bytes: &[u8]) -> Result<Plan, String> {
    Document::parse(bytes, &uncancelled())?.plan(&uncancelled())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn all_owned_native_session_cases_match_framing_replay_and_selective_bytes_without_mutation() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/chromium-session.json")).unwrap();
    let (mut supported, mut unsupported, mut kept_total, mut rewrite, mut delete) = (0, 0, 0, 0, 0);
    for case in corpus["cases"].as_array().unwrap() {
        let bytes = unhex(case["source_hex"].as_str().unwrap());
        let before = bytes.clone();
        let plan = parse_plan(&bytes);
        if case["status"] == "unsupported" {
            assert!(plan.is_err(), "{}", case["name"]);
            unsupported += 1;
            continue;
        }
        match plan.unwrap_or_else(|e| panic!("{}: {e}", case["name"])) {
            Plan::DeleteFile => {
                assert_eq!(
                    case["expected"]["disposition"], "delete_file",
                    "{}",
                    case["name"]
                );
                delete += 1;
            }
            Plan::RewritePinned {
                bytes,
                kept,
                removed_commands,
            } => {
                assert_eq!(
                    case["expected"]["disposition"], "rewrite_pinned",
                    "{}",
                    case["name"]
                );
                let wanted = case["expected"]["kept"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n.as_u64().unwrap() as usize)
                    .collect::<Vec<_>>();
                assert_eq!(kept, wanted, "{}", case["name"]);
                assert_eq!(
                    hex(&bytes),
                    case["expected"]["after_hex"].as_str().unwrap(),
                    "{}",
                    case["name"]
                );
                assert_eq!(
                    removed_commands + kept.len(),
                    Document::parse(&before, &uncancelled())
                        .unwrap()
                        .commands
                        .len()
                );
                kept_total += kept.len();
                rewrite += 1;
            }
        }
        assert_eq!(bytes, before);
        supported += 1;
    }
    assert_eq!(
        (supported, unsupported, kept_total, rewrite, delete),
        (941, 65, 1869, 850, 91)
    );
}

#[test]
fn raw_header_records_duplicate_navigation_payloads_and_order_are_preserved() {
    let opaque = vec![0, 255, 128, 0, 222, 173, 190, 239];
    let mut navigation = words(&[16, 11, 3]);
    navigation.extend_from_slice(&opaque);
    let commands = vec![
        (12, words(&[11, 1])),
        (7, words(&[11, 2])),
        (7, words(&[11, 3])),
        (0, words(&[55, 11])),
        (0, words(&[55, 99])),
        (6, navigation.clone()),
        (6, navigation.clone()),
        (6, words(&[8, 11, 2])),
        (1, words(&[8, 11, 3])),
        (2, opaque.clone()),
        (8, vec![]),
        (9, vec![255]),
        (13, b"synthetic unrelated".to_vec()),
    ];
    let source = carrier(&commands, 0xffffffff);
    let Plan::RewritePinned {
        bytes,
        kept,
        removed_commands,
    } = parse_plan(&source).unwrap()
    else {
        panic!()
    };
    assert_eq!(kept, vec![0, 2, 3, 5, 6, 8, 9, 10, 11]);
    assert_eq!(removed_commands, 4);
    let expected = carrier(
        &kept
            .iter()
            .map(|i| commands[*i].clone())
            .collect::<Vec<_>>(),
        0xffffffff,
    );
    assert_eq!(bytes, expected);
    assert_eq!(&bytes[..8], &source[..8]);
    assert_eq!(
        bytes
            .windows(opaque.len())
            .filter(|part| *part == opaque)
            .count(),
        3
    );
}

#[test]
fn pin_and_index_replay_use_final_dwords_even_for_high_bit_ids_and_late_pin_events() {
    let id = 0xffffffff;
    let source = carrier(
        &[
            (7, words(&[id, 0xffffffff])),
            (6, words(&[8, id, 0xffffffff])),
            (12, words(&[id, 1])),
        ],
        3,
    );
    let Plan::RewritePinned {
        kept,
        removed_commands,
        ..
    } = parse_plan(&source).unwrap()
    else {
        panic!()
    };
    assert_eq!(kept, vec![0, 1, 2]);
    assert_eq!(removed_commands, 0);
    for state in [0, 2, 255, 256, 0x01000001, 0xffffffff] {
        let source = carrier(
            &[
                (12, words(&[id, 1])),
                (12, words(&[id, state])),
                (7, words(&[id, 0])),
            ],
            1,
        );
        assert_eq!(parse_plan(&source).unwrap(), Plan::DeleteFile);
    }
}

#[test]
fn framing_limits_and_cancellation_refuse_incomplete_plans_without_source_changes() {
    let source = carrier(&[(12, words(&[11, 1])), (7, words(&[11, 3]))], 1);
    let before = source.clone();
    let strict = Limits {
        bytes: source.len(),
        commands: 2,
    };
    assert!(Document::parse_with_limits(&source, &uncancelled(), strict).is_ok());
    assert!(
        Document::parse_with_limits(
            &source,
            &uncancelled(),
            Limits {
                bytes: source.len() - 1,
                ..strict
            }
        )
        .is_err()
    );
    assert!(
        Document::parse_with_limits(
            &source,
            &uncancelled(),
            Limits {
                commands: 1,
                ..strict
            }
        )
        .is_err()
    );
    let cancelled = AtomicBool::new(true);
    assert!(Document::parse(&source, &cancelled).is_err());
    let doc = Document::parse(&source, &uncancelled()).unwrap();
    assert!(doc.plan(&cancelled).is_err());
    assert!(
        Document::parse(&carrier(&[], 1), &uncancelled())
            .unwrap()
            .plan(&cancelled)
            .is_err()
    );
    for invalid in [
        b"SNSS".to_vec(),
        carrier(&[], 1).into_iter().chain([0, 0, 12]).collect(),
        source[..source.len() - 1].to_vec(),
    ] {
        assert!(parse_plan(&invalid).is_err());
    }
    assert_eq!(source, before);
}

#[test]
fn unsafe_fixed_payloads_do_not_turn_into_generic_file_cleanup_authority() {
    let only_unknown = carrier(&[(0, vec![]), (7, vec![]), (255, vec![])], 1);
    assert_eq!(parse_plan(&only_unknown).unwrap(), Plan::DeleteFile);
    let malformed_pin = carrier(&[(12, vec![])], 1);
    assert!(parse_plan(&malformed_pin).is_err());
    let malformed_selected = carrier(&[(12, words(&[11, 1])), (7, words(&[11]))], 1);
    assert!(parse_plan(&malformed_selected).is_err());
    let empty_map = carrier(&[(12, words(&[11, 1])), (0, vec![])], 1);
    let Plan::RewritePinned { kept, .. } = parse_plan(&empty_map).unwrap() else {
        panic!()
    };
    assert_eq!(kept, vec![0]);
    let short_unpinned = carrier(&[(12, words(&[11, 1])), (7, words(&[99]))], 1);
    assert!(parse_plan(&short_unpinned).is_ok());
}

#[test]
fn pickle_alignment_bounds_and_payload_pairs_follow_native_selection() {
    let base = vec![(12, words(&[11, 1])), (7, words(&[11, 3]))];
    for payload in [
        vec![],
        words(&[0]),
        words(&[0xffffffff]),
        words(&[12, 11, 3]),
        words(&[7, 11, 3]),
        words(&[8, 99, 3]),
        words(&[8, 11, 4]),
    ] {
        let mut commands = base.clone();
        commands.push((6, payload));
        let Plan::RewritePinned { kept, .. } = parse_plan(&carrier(&commands, 1)).unwrap() else {
            panic!()
        };
        assert_eq!(kept, vec![0, 1]);
    }
    let mut commands = base;
    commands.push((6, words(&[8, 0xfeedface, 11, 3])));
    let Plan::RewritePinned { kept, .. } = parse_plan(&carrier(&commands, 1)).unwrap() else {
        panic!()
    };
    assert_eq!(kept, vec![0, 1, 2]);
}

#[test]
fn maximum_record_length_and_byte_identical_rewrite_do_not_invent_removed_units() {
    let source = carrier(
        &[
            (12, words(&[11, 1])),
            (7, words(&[11, 3])),
            (2, vec![0x99; 65534]),
            (8, vec![]),
            (9, vec![]),
        ],
        0,
    );
    let Plan::RewritePinned {
        bytes,
        kept,
        removed_commands,
    } = parse_plan(&source).unwrap()
    else {
        panic!()
    };
    assert_eq!(bytes, source);
    assert_eq!(kept, vec![0, 1, 2, 3, 4]);
    assert_eq!(removed_commands, 0);
}
