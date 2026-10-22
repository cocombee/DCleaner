use super::*;
use crate::privacy::PrivacyCategory;
use serde_json::Value;

fn document(bytes: &[u8]) -> Document<'_> {
    Document::parse(bytes, &AtomicBool::new(false)).unwrap()
}
fn kind(name: &str) -> (PrivacyCategory, Field) {
    if name == "last_download" {
        (
            PrivacyCategory::LastDownloadLocation,
            Field::LastDownloadLocation,
        )
    } else {
        (PrivacyCategory::SnapLocation, Field::SnapLocation)
    }
}

#[test]
fn all_native_owned_location_cases_match_string_eligibility_and_conditional_effects() {
    let corpus: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/location-json.json")).unwrap();
    let mut candidates = 0;
    let mut accepted = 0;
    let mut unsupported = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let bytes = serde_json::to_vec(&case["input"]).unwrap();
        let before = bytes.clone();
        let doc = document(&bytes);
        let (category, field) = kind(case["kind"].as_str().unwrap());
        let fields = doc.fields(category);
        if case["status"] == "unsupported_parent" {
            assert!(fields.is_err(), "{}", case["name"]);
            unsupported += 1;
            continue;
        }
        let fields = fields.unwrap();
        let count = case["records"].as_u64().unwrap() as usize;
        assert_eq!(fields.len(), count, "{}", case["name"]);
        if count == 1 {
            assert_eq!(fields, vec![field]);
            let after = doc.apply_fields(&fields).unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&after).unwrap(),
                case["after"],
                "{}",
                case["name"]
            );
            candidates += 1;
        } else {
            assert!(doc.apply_fields(&[field]).is_err(), "{}", case["name"]);
        }
        assert_eq!(bytes, before);
        accepted += 1;
    }
    assert_eq!((accepted, unsupported, candidates), (541, 8, 247));
}

#[test]
fn reset_copies_raw_configured_string_and_preserves_unrelated_lexemes_and_markers() {
    let source=br#"{"savefile":{"default_directory":"last","type":false,"keep":18446744073709551617},"download":{"default_directory":"C:\\D\u006fwnloads\u0000folder","keep":1.234567890123456789e+110},"snap":{"save_location":"private","used":true}}"#;
    let after = document(source)
        .apply_fields(&[Field::LastDownloadLocation])
        .unwrap();
    let token = br#""C:\\D\u006fwnloads\u0000folder""#;
    assert_eq!(
        after
            .windows(token.len())
            .filter(|part| *part == token)
            .count(),
        2
    );
    for kept in [
        br#""type":false"#.as_slice(),
        br#""keep":18446744073709551617"#,
        br#""keep":1.234567890123456789e+110"#,
        br#""snap":{"save_location":"private","used":true}"#,
    ] {
        assert!(after.windows(kept.len()).any(|part| part == kept));
    }
    let parsed: Value = serde_json::from_slice(&after).unwrap();
    assert_eq!(
        parsed["savefile"]["default_directory"],
        parsed["download"]["default_directory"]
    );
    assert_eq!(
        document(&after)
            .fields(PrivacyCategory::LastDownloadLocation)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn marker_ownership_requires_a_string_primary_and_keeps_unselected_groups() {
    let source=br#"{"savefile":{"type":{"kept":true}},"snap":{"used":[1]},"download":{"default_directory":"configured"}}"#;
    let doc = document(source);
    assert!(
        doc.fields(PrivacyCategory::LastDownloadLocation)
            .unwrap()
            .is_empty()
    );
    assert!(
        doc.fields(PrivacyCategory::SnapLocation)
            .unwrap()
            .is_empty()
    );
    assert!(doc.apply_fields(&[Field::LastDownloadLocation]).is_err());
    assert!(doc.apply_fields(&[Field::SnapLocation]).is_err());
    let source=br#"{"savefile":{"default_directory":"","type":null,"keep":"x"},"download":{"default_directory":""},"snap":{"save_location":"","used":false,"keep":"y"}}"#;
    let last = document(source)
        .apply_fields(&[Field::LastDownloadLocation])
        .unwrap();
    let last: Value = serde_json::from_slice(&last).unwrap();
    assert_eq!(last["savefile"], serde_json::json!({"keep":"x"}));
    assert_eq!(last["download"]["default_directory"], "");
    assert_eq!(last["snap"]["used"], false);
    let snap = document(source)
        .apply_fields(&[Field::SnapLocation])
        .unwrap();
    let snap: Value = serde_json::from_slice(&snap).unwrap();
    assert_eq!(snap["snap"], serde_json::json!({"keep":"y"}));
    assert_eq!(snap["savefile"]["default_directory"], "");
    assert!(snap["savefile"].get("type").is_some());
}

#[test]
fn mixed_history_and_location_edits_are_disjoint_and_do_not_require_unselected_groups() {
    let source=br#"{"dns_prefetching":{"startup_list":false},"savefile":{"default_directory":"last","type":4},"download":{"default_directory":"configured"},"snap":{"save_location":"lastsnap","used":7},"unrelated":0}"#;
    let after = document(source)
        .apply_fields(&[
            Field::DnsStartup,
            Field::LastDownloadLocation,
            Field::SnapLocation,
        ])
        .unwrap();
    let parsed: Value = serde_json::from_slice(&after).unwrap();
    assert_eq!(parsed["dns_prefetching"], serde_json::json!({}));
    assert_eq!(
        parsed["savefile"],
        serde_json::json!({"default_directory":"configured","type":4})
    );
    assert_eq!(parsed["snap"], serde_json::json!({}));
    assert_eq!(parsed["unrelated"], 0);
    let source=br#"{"profile":false,"savefile":{"default_directory":"last"},"download":{"default_directory":"configured"},"snap":false}"#;
    let doc = document(source);
    assert!(doc.fields(PrivacyCategory::History).is_err());
    assert!(doc.fields(PrivacyCategory::SnapLocation).is_err());
    assert!(doc.apply_fields(&[Field::LastDownloadLocation]).is_ok());
}

#[test]
fn already_configured_location_counts_once_without_inventing_a_removed_member() {
    let source=br#"{"savefile":{"default_directory":"configured","type":"kept"},"download":{"default_directory":"configured"}}"#;
    let doc = document(source);
    assert_eq!(
        doc.fields(PrivacyCategory::LastDownloadLocation).unwrap(),
        vec![Field::LastDownloadLocation]
    );
    assert_eq!(
        doc.apply_fields(&[Field::LastDownloadLocation, Field::LastDownloadLocation])
            .unwrap(),
        source
    );
    assert!(doc.remove_history(&[Field::LastDownloadLocation]).is_err());
}
