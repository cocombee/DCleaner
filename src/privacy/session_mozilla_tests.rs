use super::*;
use serde_json::{Value, json};
fn observe(source: &[u8]) -> Result<Plan, String> {
    plan(source, Encoding::Json, &AtomicBool::new(false))
}
fn rewritten(plan: Plan) -> (Vec<u8>, usize, usize, usize, usize) {
    let Plan::RewritePinned {
        bytes,
        pinned_tabs,
        retained_tabs,
        removed_tabs,
        skipped_windows,
    } = plan
    else {
        panic!("expected rewrite")
    };
    (
        bytes,
        pinned_tabs,
        retained_tabs,
        removed_tabs,
        skipped_windows,
    )
}
#[test]
fn native_selection_keeps_missing_keys_and_whole_retained_tabs_but_prunes_containers() {
    let source=br#"{"secretRoot":1,"windows":[{"selected":2,"tabs":[{"pinned":true,"entries":[{"url":"https://fixture.invalid/a"},{"url":"https://fixture.invalid/b"}],"privateToken":1234567890123456789},{"pinned":false,"secret":"remove"},{"entries":[],"missingPin":"retained"},null],"cookies":["remove"]},{"tabs":[{"pinned":0}],"other":4}]}"#;
    let (bytes, pins, retained, removed, skipped) = rewritten(observe(source).unwrap());
    assert_eq!((pins, retained, removed, skipped), (1, 3, 2, 0));
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 1);
    assert_eq!(value["windows"][0].as_object().unwrap().len(), 1);
    assert_eq!(
        value["windows"][0]["tabs"][0]["entries"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(value["windows"][0]["tabs"][1]["missingPin"], "retained");
    assert!(value["windows"][0]["tabs"][2].is_null());
    assert_eq!(value["windows"][1], json!({"tabs":[]}));
    assert!(
        std::str::from_utf8(&bytes)
            .unwrap()
            .contains("1234567890123456789")
    );
}
#[test]
fn every_owned_native_semantic_case_matches_without_native_gui_counter_claims() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/mozilla-session.json")).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert!(cases.len() >= 500);
    for case in cases {
        let result = observe(case["source"].as_str().unwrap().as_bytes());
        match case["kind"].as_str().unwrap() {
            "delete" => assert!(
                matches!(result, Ok(Plan::DeleteFile)),
                "{}: {result:?}",
                case["name"]
            ),
            "rewrite" => {
                let (bytes, pins, retained, removed, skipped) = rewritten(result.unwrap());
                assert_eq!(
                    serde_json::from_slice::<Value>(&bytes).unwrap(),
                    case["expected"],
                    "{}",
                    case["name"]
                );
                assert_eq!(
                    json!([pins, retained, removed, skipped]),
                    case["counts"],
                    "{}",
                    case["name"]
                );
            }
            "unsupported" => assert!(result.is_err(), "{}", case["name"]),
            _ => panic!("unknown fixture status"),
        }
    }
}
#[test]
fn pinned_numbers_follow_low_dword_or_truncated_double_semantics() {
    for (raw, pin) in [
        ("4294967296", false),
        ("-4294967296", false),
        ("4294967297", true),
        ("18446744073709551615", true),
        ("4294967296.0", true),
        ("-0.9", false),
        ("0.9", false),
        ("1.1", true),
        ("-1.1", true),
        ("1e300", true),
        ("-0.0", false),
    ] {
        let source = format!("{{\"windows\":[{{\"tabs\":[{{\"pinned\":{raw}}}]}}]}}");
        assert_eq!(
            matches!(
                observe(source.as_bytes()).unwrap(),
                Plan::RewritePinned { .. }
            ),
            pin,
            "{raw}"
        );
    }
}
#[test]
fn wrong_tabs_container_is_skipped_without_gaining_tab_effect_authority() {
    let source=br#"{"windows":[{"tabs":null,"unchanged":"kept"},{"tabs":[{"pinned":true}],"remove":1}],"remove":2}"#;
    let (bytes, pins, retained, removed, skipped) = rewritten(observe(source).unwrap());
    assert_eq!((pins, retained, removed, skipped), (1, 1, 0, 1));
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap(),
        json!({"windows":[{"tabs":null,"unchanged":"kept"},{"tabs":[{"pinned":true}]}]})
    );
    assert!(matches!(
        observe(br#"{"windows":[{"tabs":{}}]}"#).unwrap(),
        Plan::DeleteFile
    ));
}
#[test]
fn missing_or_malformed_structure_duplicates_and_nonfinite_numbers_never_fall_back() {
    for source in [
        &b"null"[..],
        b"[]",
        b"{}",
        br#"{"windows":null}"#,
        br#"{"windows":[{}]}"#,
        br#"{"windows":[0]}"#,
        br#"{"windows":[],"windows":[]}"#,
        br#"{"windows":[{"tabs":[{"pinned":true,"pinned":false}]}]}"#,
        br#"{"windows":[],"a":1e999}"#,
        b"{\"windows\":[]}\x0b",
        b"{\"windows\":[]}x",
        b"\xff",
        b"",
    ] {
        assert!(observe(source).is_err(), "{source:?}");
    }
}
#[test]
fn compressed_and_plain_routes_have_identical_selection_and_valid_output_carriers() {
    let source=br#"{"windows":[{"tabs":[{"pinned":true,"entries":[{"url":"owned"}]},{"pinned":false}]}],"drop":1}"#;
    let cancel = AtomicBool::new(false);
    let compressed = moz_lz4::encode(source, &cancel).unwrap();
    let plain = rewritten(observe(source).unwrap());
    let encoded = rewritten(plan(&compressed, Encoding::MozLz4, &cancel).unwrap());
    assert_eq!(moz_lz4::decode(&encoded.0, &cancel).unwrap(), plain.0);
    assert_eq!(
        (plain.1, plain.2, plain.3, plain.4),
        (encoded.1, encoded.2, encoded.3, encoded.4)
    );
    assert!(plan(b"bad carrier", Encoding::MozLz4, &cancel).is_err());
    let no_pin = moz_lz4::encode(br#"{"windows":[]}"#, &cancel).unwrap();
    assert!(matches!(
        plan(&no_pin, Encoding::MozLz4, &cancel).unwrap(),
        Plan::DeleteFile
    ));
}
#[test]
fn unicode_keys_bom_and_retained_raw_lexemes_survive_without_value_reserialization() {
    let source=br#"{"wind\u006fws":[{"tabs":[{"pinned":true,"escaped":"\u2603","number":1.2300,"large":9007199254740993}]}]}"#;
    let before = [b"\xef\xbb\xbf".as_slice(), source.as_slice()].concat();
    let (bytes, ..) = rewritten(observe(&before).unwrap());
    let output = std::str::from_utf8(&bytes).unwrap();
    assert!(output.contains(r#""escaped":"\u2603","number":1.2300,"large":9007199254740993"#));
    assert!(output.starts_with("{\"windows\""));
}
#[test]
fn input_depth_value_bounds_and_cancellation_are_explicit() {
    let cancel = AtomicBool::new(true);
    assert!(
        plan(b"{}", Encoding::Json, &cancel)
            .unwrap_err()
            .contains("cancelled")
    );
    let deep = format!(
        "{{\"windows\":[],\"extra\":{}0{}}}",
        "[".repeat(66),
        "]".repeat(66)
    );
    assert!(observe(deep.as_bytes()).unwrap_err().contains("limit"));
    let many = format!("{{\"windows\":[],\"extra\":[{}0]}}", "0,".repeat(100_000));
    assert!(observe(many.as_bytes()).unwrap_err().contains("limit"));
    assert!(
        observe(&vec![b' '; moz_lz4::MAX_BYTES + 1])
            .unwrap_err()
            .contains("size")
    );
}
