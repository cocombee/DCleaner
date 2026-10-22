use super::*;
use serde_json::Value;

fn selected(name: &str) -> Field {
    match name {
        "dns_referrals" => Field::DnsReferrals,
        "dns_startup" => Field::DnsStartup,
        "media_engagement" => Field::MediaEngagement,
        "site_engagement" => Field::SiteEngagement,
        _ => panic!("unrecognized owned field"),
    }
}
fn parse(bytes: &[u8]) -> Document<'_> {
    Document::parse(bytes, &AtomicBool::new(false)).unwrap()
}

#[test]
fn owned_non_null_and_all_selected_subset_oracle_preserves_unselected_settings() {
    let corpus: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/preferences-json.json")).unwrap();
    let mut transforms = 0;
    let mut observations = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let source = case["source"].as_str().unwrap().as_bytes();
        let before = source.to_vec();
        let document = parse(source);
        let expected: Vec<Field> = case["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| selected(v.as_str().unwrap()))
            .collect();
        assert_eq!(
            document.history_fields().unwrap(),
            expected,
            "{}",
            case["name"]
        );
        observations += expected.len();
        for transform in case["transforms"].as_array().unwrap() {
            let fields: Vec<Field> = transform["selected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| selected(v.as_str().unwrap()))
                .collect();
            let changed = document.remove_history(&fields).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&changed).unwrap(),
                transform["expected"],
                "{}: {fields:?}",
                case["name"]
            );
            let remaining = parse(&changed).history_fields().unwrap();
            assert_eq!(
                remaining,
                expected
                    .iter()
                    .filter(|f| !fields.contains(f))
                    .copied()
                    .collect::<Vec<_>>()
            );
            assert_eq!(source, before);
            transforms += 1;
        }
    }
    assert_eq!(observations, 92);
    assert_eq!(transforms, 237);
}

#[test]
fn edits_preserve_unrelated_numeric_lexemes_unicode_escapes_and_whitespace_bytes() {
    let source = br#"{
  "before":18446744073709551617, "dns_prefetching" : {
    "keep_a" : [1.2345678901234567890123456789e+120, "\u0061\/\uD83D\uDE00"],
    "host_referral_list" : ["private"],
    "keep_b" : -0.00000000000000000001, "startup_list": {"url":"private"}
  }, "after": 1e-100
}
"#;
    let document = parse(source);
    for selected in [
        vec![Field::DnsReferrals],
        vec![Field::DnsStartup],
        vec![Field::DnsReferrals, Field::DnsStartup],
    ] {
        let changed = document.remove_history(&selected).unwrap();
        for required in [
            &br#""before":18446744073709551617"#[..],
            &br#""keep_a" : [1.2345678901234567890123456789e+120, "\u0061\/\uD83D\uDE00"]"#[..],
            &br#""keep_b" : -0.00000000000000000001"#[..],
            &br#"}, "after": 1e-100
}
"#[..],
        ] {
            assert!(
                changed
                    .windows(required.len())
                    .any(|bytes| bytes == required)
            );
        }
        parse(&changed);
        let original_value: Value = serde_json::from_slice(source).unwrap();
        let changed_value: Value = serde_json::from_slice(&changed).unwrap();
        assert_eq!(
            original_value["dns_prefetching"]["keep_a"],
            changed_value["dns_prefetching"]["keep_a"]
        );
    }
}

#[test]
fn member_removal_handles_first_middle_last_only_adjacent_and_split_runs() {
    for keys in [
        vec!["host_referral_list"],
        vec!["startup_list", "host_referral_list"],
        vec!["host_referral_list", "keep", "startup_list"],
        vec!["keep", "startup_list", "host_referral_list"],
        vec!["host_referral_list", "startup_list", "keep"],
    ] {
        for white in ["", " ", "\r\n\t"] {
            let body = keys
                .iter()
                .map(|key| format!("{white}\"{key}\"{white}:{white}false{white}"))
                .collect::<Vec<_>>()
                .join(",");
            let source = format!("{{{white}\"dns_prefetching\":{{{body}}}{white}}}");
            let document = parse(source.as_bytes());
            for fields in [
                vec![Field::DnsReferrals],
                vec![Field::DnsStartup],
                vec![Field::DnsReferrals, Field::DnsStartup],
            ] {
                let available = document.history_fields().unwrap();
                if fields.iter().any(|field| !available.contains(field)) {
                    continue;
                }
                let changed = document.remove_history(&fields).unwrap();
                let mut expected: Value = serde_json::from_str(&source).unwrap();
                for field in &fields {
                    expected["dns_prefetching"]
                        .as_object_mut()
                        .unwrap()
                        .remove(field.key());
                }
                assert_eq!(serde_json::from_slice::<Value>(&changed).unwrap(), expected);
            }
        }
    }
}

#[test]
fn escaped_member_names_are_decoded_once_and_all_duplicates_are_rejected() {
    let source = br#"{"dns_prefetching":{"host\u005freferral_list":false},"profile":{"content_settings":{"exceptions":{"site\u005fengagement":0}}}}"#;
    let document = parse(source);
    assert_eq!(
        document.history_fields().unwrap(),
        vec![Field::DnsReferrals, Field::SiteEngagement]
    );
    let changed = document.remove_history(&[Field::DnsReferrals]).unwrap();
    assert!(
        changed
            .windows(br#""site\u005fengagement":0"#.len())
            .any(|bytes| bytes == br#""site\u005fengagement":0"#)
    );
    for bad in [
        br#"{"dns_prefetching":{"host_referral_list":0,"host\u005freferral_list":1}}"#.as_slice(),
        br#"{"profile":{},"profile":null}"#.as_slice(),
        br#"{"unrelated":[{"same":0,"same":1}]}"#.as_slice(),
    ] {
        assert!(
            Document::parse(bad, &AtomicBool::new(false))
                .unwrap_err_message()
                .contains("duplicate")
        );
    }
}

#[test]
fn missing_null_non_object_and_unsupported_ancestors_remain_distinct() {
    for source in [
        "null",
        "{}",
        r#"{"dns_prefetching":false}"#,
        r#"{"profile":null}"#,
        r#"{"profile":{"content_settings":null}}"#,
        r#"{"profile":{"content_settings":{"exceptions":[]}}}"#,
    ] {
        assert!(
            parse(source.as_bytes())
                .history_fields()
                .unwrap()
                .is_empty()
        );
    }
    for source in [
        "[]",
        "false",
        r#"{"profile":false}"#,
        r#"{"profile":{"content_settings":[]}}"#,
    ] {
        assert!(parse(source.as_bytes()).history_fields().is_err());
    }
    let document =
        parse(br#"{"dns_prefetching":{"startup_list":null,"host_referral_list":false}}"#);
    assert!(document.remove_history(&[]).is_err());
    assert!(document.remove_history(&[Field::DnsStartup]).is_err());
    assert!(document.remove_history(&[Field::SiteEngagement]).is_err());
    assert_eq!(
        document
            .remove_history(&[Field::DnsReferrals, Field::DnsReferrals])
            .unwrap(),
        br#"{"dns_prefetching":{"startup_list":null}}"#
    );
}

#[test]
fn malformed_utf8_surrogates_syntax_and_nonfinite_numbers_do_not_get_authority() {
    for source in [
        b"".as_slice(),
        b"\xff",
        b"\xef\xbb\xbf{}",
        b"{} {}",
        b"[1,]",
        b"{\"a\":1,}",
        b"{\"a\" 0}",
        b"{\"a\":01}",
        b"{\"a\":NaN}",
        b"{\"a\":1e999}",
        br#"{"a":"\uD800"}"#,
        br#"{"a":"\uDC00"}"#,
        br#"{"a":"\x00"}"#,
    ] {
        assert!(
            Document::parse(source, &AtomicBool::new(false)).is_err(),
            "{source:?}"
        );
    }
    assert_eq!(
        parse(br#"{"dns_prefetching":{"startup_list":"\uD83D\uDE00"}}"#)
            .history_fields()
            .unwrap(),
        vec![Field::DnsStartup]
    );
}

#[test]
fn observation_byte_value_depth_limits_and_cancellation_are_explicit() {
    let cancelled = AtomicBool::new(true);
    assert!(
        Document::parse(b"{}", &cancelled)
            .unwrap_err_message()
            .contains("cancelled")
    );
    for (source, limits) in [
        (
            b"{}".as_slice(),
            Limits {
                bytes: 1,
                ..Limits::default()
            },
        ),
        (
            b"[0,1,2]",
            Limits {
                values: 3,
                ..Limits::default()
            },
        ),
        (
            b"[[[0]]]",
            Limits {
                depth: 2,
                ..Limits::default()
            },
        ),
    ] {
        assert!(Document::parse_with_limits(source, &AtomicBool::new(false), limits).is_err());
    }
    let source = format!(
        "{}0{}",
        "[".repeat(MAX_DEPTH + 1),
        "]".repeat(MAX_DEPTH + 1)
    );
    assert!(Document::parse(source.as_bytes(), &AtomicBool::new(false)).is_err());
    let source = format!("[{}]", "0,".repeat(MAX_VALUES) + "0");
    assert!(
        Document::parse(source.as_bytes(), &AtomicBool::new(false))
            .unwrap_err_message()
            .contains("limit")
    );
}

// Keep the private document and its payload out of panic formatting.
trait ErrorMessage {
    fn unwrap_err_message(self) -> String;
}
impl<T> ErrorMessage for Result<T, String> {
    fn unwrap_err_message(self) -> String {
        match self {
            Err(message) => message,
            Ok(_) => panic!("unexpected accepted JSON"),
        }
    }
}
