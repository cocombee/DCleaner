use dcleaner::clean_settings::{
    self, AdvancedFilterOptions, CleanSettingsError, CustomCleanEffect, CustomCleanSettings,
    EffectSupport, ExclusionRule, ExclusionType, FileDeletionMode, FileDeletionPolicy,
    FolderInclusion, InclusionLocation, InclusionRule, OverwriteType, WipeDrivePreference,
    effect_support, load_settings, save_settings,
};
use std::{collections::BTreeMap, fs};

fn custom_settings() -> CustomCleanSettings {
    CustomCleanSettings {
        inclusions: vec![
            InclusionRule {
                location: InclusionLocation::File(r"C:\Temp\one.log".into()),
                age_threshold_hours: Some(48.5),
            },
            InclusionRule {
                location: InclusionLocation::Folder(FolderInclusion {
                    folder: r"D:\Work\cache".into(),
                    filter: Some(vec!["*.tmp".into(), "*.cache".into()]),
                    delete_self: true,
                    recursive: false,
                }),
                age_threshold_hours: None,
            },
        ],
        exclusions: vec![ExclusionRule {
            exclusion_type: ExclusionType::RegistryKeyValue,
            path: r"HKCU\Software\Example\Keep".into(),
        }],
        file_deletion: FileDeletionPolicy {
            temp_folders_only_older_than_24h: false,
            recycle_bin_only_older_than_24h: true,
        },
        advanced_filter_options: AdvancedFilterOptions {
            file_deletion: FileDeletionMode::Secure,
            overwrite_type: OverwriteType::ThirtyFivePass,
            wipe_free_space: true,
            wipe_alternate_data_streams: true,
            wipe_free_space_drives: vec![WipeDrivePreference {
                drive: "C".into(),
                wipe_mft_free_space: true,
            }],
        },
        rule_selections: Some(BTreeMap::from([
            (".custom".into(), true),
            ("windows.tempfiles".into(), false),
        ])),
        skipped_close_programs: vec!["browser.rule".into()],
        skip_show_registry_attention: true,
        shutdown_after_cleaning: true,
        ..CustomCleanSettings::default()
    }
}

#[test]
fn shipped_defaults_and_optional_rule_record_are_preserved() {
    let defaults = CustomCleanSettings::default();
    assert_eq!(
        defaults.schema,
        clean_settings::CLEAN_SETTINGS_SCHEMA_VERSION
    );
    assert_eq!(defaults.inclusions, Vec::<InclusionRule>::new());
    assert_eq!(defaults.rule_selections, None);
    assert!(defaults.file_deletion.temp_folders_only_older_than_24h);
    assert!(!defaults.file_deletion.recycle_bin_only_older_than_24h);
    assert_eq!(
        defaults.advanced_filter_options.file_deletion,
        FileDeletionMode::Normal
    );
    assert_eq!(
        defaults.advanced_filter_options.overwrite_type,
        OverwriteType::Disabled
    );
    assert!(!defaults.advanced_filter_options.wipe_free_space);
    assert!(!defaults.advanced_filter_options.wipe_alternate_data_streams);
    assert!(
        defaults
            .advanced_filter_options
            .wipe_free_space_drives
            .is_empty()
    );
    assert!(!defaults.skip_show_registry_attention);
    assert!(!defaults.shutdown_after_cleaning);

    let domains: Vec<_> = defaults
        .exclusions
        .iter()
        .filter(|rule| rule.exclusion_type == ExclusionType::Cookie)
        .map(|rule| rule.path.as_str())
        .collect();
    assert_eq!(domains.len(), 15);
    assert!(domains.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(!domains.iter().any(|domain| domain.contains("piriform")));

    let partial = serde_json::json!({
        "schema": clean_settings::CLEAN_SETTINGS_SCHEMA_VERSION,
        "rule-selections": {".custom": true, "windows.tempfiles": false}
    });
    let loaded: CustomCleanSettings = serde_json::from_value(partial).unwrap();
    assert_eq!(loaded.rule_selection(".custom"), Some(true));
    assert_eq!(loaded.rule_selection("windows.tempfiles"), Some(false));
    assert_eq!(loaded.rule_selection("windows.registry"), None);
    assert_eq!(loaded.exclusions, defaults.exclusions);
}

#[test]
fn persisted_shape_matches_the_observed_custom_clean_fields() {
    let settings = custom_settings();
    let json = serde_json::to_value(&settings).unwrap();

    assert_eq!(
        json["inclusions"][0]["location"],
        serde_json::json!(r"C:\Temp\one.log")
    );
    assert_eq!(json["inclusions"][0]["age-threshold-hours"], 48.5);
    assert_eq!(
        json["inclusions"][1]["location"]["folder"],
        r"D:\Work\cache"
    );
    assert_eq!(
        json["inclusions"][1]["location"]["filter"],
        serde_json::json!(["*.tmp", "*.cache"])
    );
    assert_eq!(json["inclusions"][1]["location"]["delete-self"], true);
    assert_eq!(json["inclusions"][1]["location"]["recursive"], false);
    assert_eq!(
        json["exclusions"][0]["exclusion-type"],
        "registry_key_value"
    );
    assert_eq!(
        json["file-deletion"]["temp-folders-only-older-than-24h"],
        false
    );
    assert_eq!(
        json["file-deletion"]["recycle-bin-only-older-than-24h"],
        true
    );
    assert_eq!(json["advanced-filter-options"]["file-deletion"], "secure");
    assert_eq!(
        json["advanced-filter-options"]["overwrite-type"],
        "thirty_five_pass"
    );
    assert_eq!(
        json["advanced-filter-options"]["wipe-free-space-drives"][0]["wipe_mft_free_space"],
        true
    );
    assert_eq!(json["rule-selections"][".custom"], true);
    assert_eq!(json["rule-selections"]["windows.tempfiles"], false);
    assert_eq!(json["skipped-close-programs"][0], "browser.rule");
    assert_eq!(json["skip-show-registry-attention"], true);
    assert_eq!(json["shut-down-after-cleaning"], true);

    let decoded: CustomCleanSettings = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, settings);
}

#[test]
fn setting_rule_overrides_can_be_added_changed_and_removed() {
    let mut settings = CustomCleanSettings::default();
    assert_eq!(settings.rule_selections, None);
    settings.set_rule_selection(".custom", Some(false)).unwrap();
    assert_eq!(settings.rule_selection(".custom"), Some(false));
    settings.set_rule_selection(".custom", Some(true)).unwrap();
    assert_eq!(settings.rule_selection(".custom"), Some(true));
    settings.set_rule_selection(".custom", None).unwrap();
    assert_eq!(settings.rule_selections, None);
    assert!(settings.set_rule_selection("  ", Some(true)).is_err());
}

#[test]
fn preferences_do_not_authorize_any_custom_clean_effect() {
    for effect in [
        CustomCleanEffect::ApplyInclusions,
        CustomCleanEffect::ApplyExclusions,
        CustomCleanEffect::EnforceTemporaryAge,
        CustomCleanEffect::EnforceRecycleBinAge,
        CustomCleanEffect::SecureFileDeletion,
        CustomCleanEffect::OverwritePasses,
        CustomCleanEffect::WipeFreeSpace,
        CustomCleanEffect::WipeAlternateDataStreams,
        CustomCleanEffect::WipeDriveMftFreeSpace,
        CustomCleanEffect::ApplyRuleSelections,
        CustomCleanEffect::SkipCloseProcesses,
        CustomCleanEffect::SuppressRegistryAttention,
        CustomCleanEffect::ShutdownAfterCleaning,
    ] {
        assert_eq!(effect_support(effect), EffectSupport::StoredOnly);
    }
}

#[test]
fn versioned_settings_round_trip_through_atomic_store() {
    let directory = tempfile::tempdir().unwrap();
    let settings = custom_settings();
    save_settings(directory.path(), &settings).unwrap();
    assert_eq!(load_settings(directory.path()).unwrap(), settings);

    let replacement = CustomCleanSettings::default();
    save_settings(directory.path(), &replacement).unwrap();
    assert_eq!(load_settings(directory.path()).unwrap(), replacement);
    assert_eq!(
        fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count(),
        0
    );
}

#[test]
fn corrupt_or_future_settings_are_rejected_without_rewriting_original_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(clean_settings::CLEAN_SETTINGS_FILE);
    let corrupt = b"{not json";
    fs::write(&path, corrupt).unwrap();
    assert!(load_settings(directory.path()).is_err());
    assert!(save_settings(directory.path(), &CustomCleanSettings::default()).is_err());
    assert_eq!(fs::read(&path).unwrap(), corrupt);

    let future = serde_json::json!({"schema": 999});
    let future_bytes = serde_json::to_vec(&future).unwrap();
    fs::write(&path, &future_bytes).unwrap();
    assert!(load_settings(directory.path()).is_err());
    assert!(save_settings(directory.path(), &CustomCleanSettings::default()).is_err());
    assert_eq!(fs::read(&path).unwrap(), future_bytes);
}

#[test]
fn invalid_settings_are_rejected_before_replacing_existing_file() {
    let directory = tempfile::tempdir().unwrap();
    let existing = CustomCleanSettings::default();
    save_settings(directory.path(), &existing).unwrap();
    let path = directory.path().join(clean_settings::CLEAN_SETTINGS_FILE);
    let before = fs::read(&path).unwrap();

    let mut bad = custom_settings();
    bad.schema += 1;
    assert!(save_settings(directory.path(), &bad).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);

    let mut bad = custom_settings();
    bad.exclusions.push(bad.exclusions[0].clone());
    assert!(bad.validate().is_err());

    let mut bad = custom_settings();
    bad.advanced_filter_options
        .wipe_free_space_drives
        .push(WipeDrivePreference {
            drive: "c".into(),
            wipe_mft_free_space: false,
        });
    assert!(bad.validate().is_err());

    let mut bad = custom_settings();
    bad.inclusions.push(bad.inclusions[0].clone());
    assert!(bad.validate().is_err());

    let mut bad = custom_settings();
    bad.inclusions[0].age_threshold_hours = Some(f64::NAN);
    assert!(bad.validate().is_err());

    let mut bad = custom_settings();
    if let InclusionLocation::Folder(folder) = &mut bad.inclusions[1].location {
        folder.folder = String::new();
    }
    assert!(bad.validate().is_err());
}

#[test]
fn settings_store_rejects_relative_roots_and_unknown_fields() {
    assert!(load_settings(std::path::Path::new("relative")).is_err());
    assert!(
        save_settings(
            std::path::Path::new("relative"),
            &CustomCleanSettings::default()
        )
        .is_err()
    );

    let unknown = serde_json::json!({
        "schema": clean_settings::CLEAN_SETTINGS_SCHEMA_VERSION,
        "unreviewed-effect": true
    });
    assert!(serde_json::from_value::<CustomCleanSettings>(unknown).is_err());
}

#[test]
fn settings_errors_remain_displayable() {
    let error = CleanSettingsError("bad settings".into());
    assert_eq!(error.to_string(), "bad settings");
}
