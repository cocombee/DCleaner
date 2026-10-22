use super::*;
use std::sync::atomic::AtomicUsize;

const INPUT: &[u8] = br#"{"dns_prefetching":{"host_referral_list":["private"],"startup_list":false,"keep":18446744073709551617},"profile":{"content_settings":{"exceptions":{"media_engagement":{},"site_engagement":0,"keep":"\uD83D\uDE00"}}},"unrelated":1.234567890123456789e+110}"#;
struct Closed;
impl BrowserRuntime for Closed {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        Ok(vec![])
    }
}
struct NoFiles;
impl crate::cleanup::TrashPort for NoFiles {
    fn move_to_trash(&mut self, _: &Path) -> Result<(), String> {
        panic!("JSON/SQL test attempted a file move")
    }
}
fn fixture(root: &Path, browser: Browser) -> BrowserProfile {
    fs::create_dir_all(root).unwrap();
    fs::write(root.join("Preferences"), INPUT).unwrap();
    BrowserProfile {
        browser,
        id: "owned-preferences".into(),
        name: "Owned preferences".into(),
        root: dunce::canonicalize(root).unwrap(),
    }
}
fn scan(profile: &BrowserProfile) -> PrivacyReport {
    scan_profiles_with_settings(
        std::slice::from_ref(profile),
        &[PrivacyCategory::History],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    )
}
fn reviews(report: &PrivacyReport) -> Vec<Review> {
    report
        .records
        .iter()
        .filter_map(|r| {
            if let RecordLocator::Preferences(p) = &r.locator {
                Some(p.clone())
            } else {
                None
            }
        })
        .collect()
}
fn field(report: &PrivacyReport, wanted: Field) -> Review {
    reviews(report)
        .into_iter()
        .find(|r| r.field == wanted)
        .unwrap()
}
fn run(data: &Path, plan: &PrivacyPlan) -> PrivacyReceipt {
    clean_privacy_with_runtime_and_trash(
        data,
        plan,
        &AtomicBool::new(false),
        &Closed,
        &mut NoFiles,
        &mut |_, _| {},
    )
    .unwrap()
}

#[test]
fn all_thirteen_recent_preferences_only_profiles_are_discovered_and_scanned_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let mut families = 0;
    for browser in Browser::ALL.iter().copied().filter(|b| b.is_chromium()) {
        let base = temp.path().join(browser.cache_category());
        let profile = fixture(&base.join("Preferences only"), browser);
        let stamp = file_stamp(&profile.root.join("Preferences")).unwrap();
        let mut inventory = ProfileInventory::default();
        profile_discovery::user_data_profiles(browser, &base, &mut inventory);
        assert!(
            !inventory.partial && inventory.profiles.len() == 1,
            "{browser:?}: {:?}",
            inventory.skipped
        );
        let report = scan(&inventory.profiles[0]);
        assert!(!report.partial, "{browser:?}: {:?}", report.skipped);
        assert_eq!(report.records.len(), 4);
        assert_eq!(
            report
                .records
                .iter()
                .map(PrivacyRecord::item_count)
                .sum::<usize>(),
            4
        );
        assert!(report.records.iter().all(|r| r.size_bytes().is_none()
            && r.source_file().is_none()
            && !r.site.contains("private")));
        assert_eq!(
            file_stamp(&profile.root.join("Preferences")).unwrap(),
            stamp
        );
        assert_eq!(fs::read(profile.root.join("Preferences")).unwrap(), INPUT);
        families += 1;
    }
    assert_eq!(families, 13);
}

#[test]
fn owned_field_count_matrix_matches_file_inventory_without_mutation() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/preferences-json.json")).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut observations = 0;
    for (index, case) in corpus["cases"].as_array().unwrap().iter().enumerate() {
        let profile = fixture(&temp.path().join(index.to_string()), Browser::Chrome);
        let source = case["source"].as_str().unwrap().as_bytes();
        fs::write(profile.root.join("Preferences"), source).unwrap();
        let stamp = file_stamp(&profile.root.join("Preferences")).unwrap();
        let report = scan(&profile);
        assert!(!report.partial, "{}: {:?}", case["name"], report.skipped);
        let wanted = case["fields"].as_array().unwrap().len();
        assert_eq!(reviews(&report).len(), wanted);
        observations += wanted;
        assert_eq!(
            file_stamp(&profile.root.join("Preferences")).unwrap(),
            stamp
        );
        assert_eq!(fs::read(profile.root.join("Preferences")).unwrap(), source);
    }
    assert_eq!(observations, 92);
}

#[test]
#[cfg(windows)]
fn reviewed_cleanup_and_restore_preserve_unselected_fields_and_exact_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome);
    let data = temp.path().join("data");
    let report = scan(&profile);
    let chosen = field(&report, Field::DnsReferrals);
    assert!(report.records.iter().all(PrivacyRecord::actionable));
    assert!(build_cleanup_plan(&report, &[Uuid::new_v4()]).is_err());
    let plan = build_cleanup_plan(&report, &[chosen.id, chosen.id]).unwrap();
    let receipt = run(&data, &plan);
    assert_eq!(
        (
            receipt.selected,
            receipt.deleted,
            receipt.skipped,
            receipt.uncertain
        ),
        (1, 1, 0, false),
        "{:?}",
        receipt.errors
    );
    let after = fs::read(profile.root.join("Preferences")).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&after).unwrap();
    assert!(
        parsed["dns_prefetching"]
            .get("host_referral_list")
            .is_none()
    );
    assert_eq!(parsed["dns_prefetching"]["startup_list"], false);
    assert!(
        after
            .windows(b"18446744073709551617".len())
            .any(|w| w == b"18446744073709551617")
    );
    assert!(
        after
            .windows(br#""keep":"\uD83D\uDE00""#.len())
            .any(|w| w == br#""keep":"\uD83D\uDE00""#)
    );
    assert_eq!(fs::read(&receipt.backups[0]).unwrap(), INPUT);
    assert!(recover_privacy_operations(&data).unwrap().is_empty());
    let options = list_privacy_restore_options(&data).unwrap();
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].state, PrivacyRecoveryState::Ready);
    let restore = prepare_privacy_restore_with_runtime(&data, options[0].id, &Closed).unwrap();
    assert!(restore.restores_preferences());
    assert!(!restore.restores_site_storage_keys());
    let restored = restore_privacy_database_with_runtime(&data, &restore, &Closed).unwrap();
    assert!(restored.restored && !restored.uncertain);
    assert_eq!(
        fs::read(restored.current_state_backup.unwrap()).unwrap(),
        after
    );
    assert_eq!(fs::read(profile.root.join("Preferences")).unwrap(), INPUT);
    assert_eq!(
        list_privacy_restore_options(&data).unwrap()[0].state,
        PrivacyRecoveryState::Restored
    );
    assert!(restore_privacy_database_with_runtime(&data, &restore, &Closed).is_err());
}

#[test]
#[cfg(windows)]
fn same_stamp_content_drift_blocks_cleanup_and_stale_restore_review() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome);
    let path = profile.root.join("Preferences");
    let data = temp.path().join("data");
    let report = scan(&profile);
    let chosen = field(&report, Field::DnsReferrals);
    let plan = build_cleanup_plan(&report, &[chosen.id]).unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let original_stamp = file_stamp(&path).unwrap();
    let changed = String::from_utf8(INPUT.to_vec())
        .unwrap()
        .replace("private", "privacy");
    fs::write(&path, changed.as_bytes()).unwrap();
    filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(modified)).unwrap();
    assert_eq!(file_stamp(&path).unwrap(), original_stamp);
    let receipt = run(&data, &plan);
    assert_eq!((receipt.deleted, receipt.skipped), (0, 1));
    assert_eq!(fs::read(&path).unwrap(), changed.as_bytes());
    let current = scan(&profile);
    let chosen = field(&current, Field::DnsReferrals);
    assert_eq!(
        run(&data, &build_cleanup_plan(&current, &[chosen.id]).unwrap()).deleted,
        1
    );
    let option = list_privacy_restore_options(&data)
        .unwrap()
        .into_iter()
        .find(|o| o.state == PrivacyRecoveryState::Ready)
        .unwrap();
    let review = prepare_privacy_restore_with_runtime(&data, option.id, &Closed).unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let stamp = file_stamp(&path).unwrap();
    let after = fs::read(&path).unwrap();
    let altered = String::from_utf8(after)
        .unwrap()
        .replace("1.234567890123456789e+110", "2.234567890123456789e+110");
    fs::write(&path, altered.as_bytes()).unwrap();
    filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(modified)).unwrap();
    assert_eq!(file_stamp(&path).unwrap(), stamp);
    assert!(restore_privacy_database_with_runtime(&data, &review, &Closed).is_err());
    assert_eq!(fs::read(&path).unwrap(), altered.as_bytes());
}

#[test]
#[cfg(windows)]
fn same_byte_same_stamp_replacement_does_not_authorize_the_new_file() {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle, SetFileTime,
        },
    };
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome);
    let path = profile.root.join("Preferences");
    let data = temp.path().join("data");
    let report = scan(&profile);
    let chosen = field(&report, Field::DnsReferrals);
    let original = chosen.source.signature.clone();
    let old = File::open(&path).unwrap();
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe {
        GetFileInformationByHandle(HANDLE(old.as_raw_handle()), &mut info).unwrap();
    }
    drop(old);
    let replacement = profile.root.join("replacement");
    fs::write(&replacement, INPUT).unwrap();
    let new = OpenOptions::new().write(true).open(&replacement).unwrap();
    unsafe {
        SetFileTime(
            HANDLE(new.as_raw_handle()),
            Some(&info.ftCreationTime),
            None,
            Some(&info.ftLastWriteTime),
        )
        .unwrap();
    }
    drop(new);
    fs::remove_file(&path).unwrap();
    fs::rename(&replacement, &path).unwrap();
    let (_, current) = read_held(&mut File::open(&path).unwrap(), &AtomicBool::new(false)).unwrap();
    assert_eq!(current.hash, original.hash);
    assert_eq!(current.stamp, original.stamp);
    assert_ne!(current.identity, original.identity);
    let receipt = run(&data, &build_cleanup_plan(&report, &[chosen.id]).unwrap());
    assert_eq!((receipt.deleted, receipt.skipped), (0, 1));
    assert_eq!(fs::read(path).unwrap(), INPUT);
}

#[test]
#[cfg(windows)]
fn held_write_has_durable_intent_and_excludes_writes_replacement_and_ancestor_moves() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome);
    let data = temp.path().join("data");
    let chosen = field(&scan(&profile), Field::DnsReferrals);
    let receipt = clean_group(
        &data,
        Uuid::new_v4(),
        std::slice::from_ref(&chosen),
        &AtomicBool::new(false),
        &Closed,
        |lease, after| {
            let pending = entries(&data)?;
            assert_eq!(pending.len(), 1);
            assert!(pending[0].outcome.is_none());
            assert_eq!(pending[0].intent.selected[0].0, chosen.id);
            let (backup, _) = before_image(&data, &pending[0])?;
            assert_eq!(backup, INPUT);
            assert_eq!(
                read_held(&mut lease.file, &AtomicBool::new(false))?.0,
                INPUT
            );
            assert!(
                OpenOptions::new()
                    .write(true)
                    .open(chosen.source.path())
                    .is_err()
            );
            assert!(fs::rename(chosen.source.path(), profile.root.join("moved")).is_err());
            assert!(fs::rename(&profile.root, temp.path().join("moved-profile")).is_err());
            lease.write(after)
        },
    )
    .unwrap();
    assert_eq!(receipt.deleted, 1);
    assert!(!receipt.uncertain);
}

#[test]
#[cfg(windows)]
fn partial_write_is_uncertain_preserves_recovery_and_blocks_replay_and_restore() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome);
    let data = temp.path().join("data");
    let chosen = field(&scan(&profile), Field::DnsReferrals);
    let calls = AtomicUsize::new(0);
    let receipt = clean_group(
        &data,
        Uuid::new_v4(),
        std::slice::from_ref(&chosen),
        &AtomicBool::new(false),
        &Closed,
        |lease, after| {
            calls.fetch_add(1, Ordering::Relaxed);
            lease.file.seek(SeekFrom::Start(0)).unwrap();
            lease.file.write_all(&after[..after.len() / 2]).unwrap();
            lease.file.sync_all().unwrap();
            Err("owned partial write".into())
        },
    )
    .unwrap();
    assert!(receipt.uncertain);
    assert_eq!(receipt.deleted, 0);
    assert_eq!(fs::read(&receipt.backups[0]).unwrap(), INPUT);
    let current = fs::read(chosen.source.path()).unwrap();
    assert_ne!(current, INPUT);
    let items = recover_privacy_operations(&data).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].unresolved_ids, vec![chosen.id]);
    let option = list_privacy_restore_options(&data).unwrap().remove(0);
    assert_eq!(option.state, PrivacyRecoveryState::Uncertain);
    assert!(prepare_privacy_restore_with_runtime(&data, option.id, &Closed).is_err());
    assert!(
        clean_group(
            &data,
            Uuid::new_v4(),
            &[chosen.clone()],
            &AtomicBool::new(false),
            &Closed,
            |_, _| {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(fs::read(chosen.source.path()).unwrap(), current);
}

#[test]
#[cfg(windows)]
fn a_complete_source_write_without_a_receipt_stays_interrupted_after_restart() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome);
    let chosen = field(&scan(&profile), Field::DnsReferrals);
    let data = temp.path().join("data");
    assert_eq!(
        clean(
            &data,
            Uuid::new_v4(),
            &[chosen.clone()],
            &AtomicBool::new(false),
            &Closed
        )
        .unwrap()
        .deleted,
        1
    );
    let after = fs::read(chosen.source.path()).unwrap();
    let id = options(&data).unwrap()[0].id;
    let path = private_dir(&data, false)
        .unwrap()
        .join(format!("{id}.jsonl"));
    let journal = fs::read(&path).unwrap();
    let end = journal.iter().position(|b| *b == b'\n').unwrap() + 1;
    fs::write(&path, &journal[..end]).unwrap(); // Owned restart state: durable intent, no outcome.
    assert_eq!(
        options(&data).unwrap()[0].state,
        PrivacyRecoveryState::Interrupted
    );
    assert_eq!(
        recover_privacy_operations(&data).unwrap()[0].unresolved_ids,
        vec![chosen.id]
    );
    assert!(prepare_restore(&data, id, &Closed).is_err());
    let current = field(&scan(&profile), Field::DnsStartup);
    assert!(
        clean_group(
            &data,
            Uuid::new_v4(),
            &[current],
            &AtomicBool::new(false),
            &Closed,
            |_, _| panic!("interrupted cleanup was replayed")
        )
        .is_err()
    );
    assert_eq!(fs::read(chosen.source.path()).unwrap(), after);
}

#[test]
#[cfg(windows)]
fn partial_restore_keeps_current_copy_and_blocks_all_automatic_retries() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome);
    let data = temp.path().join("data");
    let chosen = field(&scan(&profile), Field::DnsReferrals);
    assert_eq!(
        clean(
            &data,
            Uuid::new_v4(),
            &[chosen.clone()],
            &AtomicBool::new(false),
            &Closed
        )
        .unwrap()
        .deleted,
        1
    );
    let after = fs::read(chosen.source.path()).unwrap();
    let id = options(&data).unwrap()[0].id;
    let plan = prepare_restore(&data, id, &Closed).unwrap().unwrap();
    let restore_plan = plan.preferences.unwrap();
    let receipt = restore_effect(&data, &restore_plan, &Closed, |lease, before| {
        lease.file.seek(SeekFrom::Start(0)).unwrap();
        lease.file.write_all(&before[..before.len() / 2]).unwrap();
        lease.file.sync_all().unwrap();
        Err("owned partial restore".into())
    })
    .unwrap();
    assert!(receipt.uncertain && !receipt.restored);
    assert_eq!(
        fs::read(receipt.current_state_backup.unwrap()).unwrap(),
        after
    );
    let partial = fs::read(chosen.source.path()).unwrap();
    assert_eq!(
        options(&data).unwrap()[0].state,
        PrivacyRecoveryState::Uncertain
    );
    assert!(restore(&data, &restore_plan, &Closed).is_err());
    assert!(blocked(&data, &chosen.source, None).is_err());
    assert_eq!(fs::read(chosen.source.path()).unwrap(), partial);
}

struct BoundaryRuntime<'a> {
    calls: AtomicUsize,
    open: bool,
    cancel: Option<&'a AtomicBool>,
}
impl BrowserRuntime for BoundaryRuntime<'_> {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        if self.calls.fetch_add(1, Ordering::Relaxed) >= 2 {
            if let Some(cancel) = self.cancel {
                cancel.store(true, Ordering::Relaxed);
            }
            if self.open {
                return Ok(vec![RunningBrowser {
                    browser: Browser::Chrome,
                    pid: 42,
                    executable: "chrome.exe".into(),
                }]);
            }
        }
        Ok(vec![])
    }
}
#[test]
#[cfg(windows)]
fn browser_opening_and_cancellation_after_intent_refuse_before_first_effect() {
    for open in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let profile = fixture(&temp.path().join("profile"), Browser::Chrome);
        let data = temp.path().join("data");
        let chosen = field(&scan(&profile), Field::DnsReferrals);
        let cancel = AtomicBool::new(false);
        let runtime = BoundaryRuntime {
            calls: AtomicUsize::new(0),
            open,
            cancel: (!open).then_some(&cancel),
        };
        let receipt = clean_group(
            &data,
            Uuid::new_v4(),
            &[chosen.clone()],
            &cancel,
            &runtime,
            |_, _| panic!("refused write attempted"),
        )
        .unwrap();
        assert_eq!(
            (receipt.deleted, receipt.skipped, receipt.uncertain),
            (0, 1, false)
        );
        assert_eq!(fs::read(chosen.source.path()).unwrap(), INPUT);
        assert!(recover_privacy_operations(&data).unwrap().is_empty());
        assert_eq!(
            options(&data).unwrap()[0].state,
            PrivacyRecoveryState::Unavailable
        );
    }
}

#[test]
#[cfg(windows)]
fn cancellation_after_attempt_does_not_abandon_post_verification() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome);
    let chosen = field(&scan(&profile), Field::DnsReferrals);
    let cancel = AtomicBool::new(false);
    let data = temp.path().join("data");
    let receipt = clean_group(
        &data,
        Uuid::new_v4(),
        &[chosen],
        &cancel,
        &Closed,
        |lease, after| {
            lease.write(after)?;
            cancel.store(true, Ordering::Relaxed);
            Ok(())
        },
    )
    .unwrap();
    assert!(receipt.cancelled && !receipt.uncertain);
    assert_eq!(receipt.deleted, 1);
    assert_eq!(
        options(&data).unwrap()[0].state,
        PrivacyRecoveryState::Ready
    );
}

#[test]
#[cfg(windows)]
fn damaged_backup_and_truncated_journal_never_replay_or_restore() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome);
    let chosen = field(&scan(&profile), Field::DnsReferrals);
    let data = temp.path().join("data");
    let receipt = clean(
        &data,
        Uuid::new_v4(),
        &[chosen.clone()],
        &AtomicBool::new(false),
        &Closed,
    )
    .unwrap();
    assert_eq!(receipt.deleted, 1);
    let after = fs::read(chosen.source.path()).unwrap();
    let id = options(&data).unwrap()[0].id;
    fs::write(&receipt.backups[0], b"{}").unwrap();
    assert_eq!(
        options(&data).unwrap()[0].state,
        PrivacyRecoveryState::Ready
    );
    assert!(prepare_restore(&data, id, &Closed).is_err());
    assert_eq!(fs::read(chosen.source.path()).unwrap(), after);
    let path = private_dir(&data, false)
        .unwrap()
        .join(format!("{id}.jsonl"));
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(b"{\"kind\":").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(recovery(&data).is_err());
    assert!(
        clean(
            &data,
            Uuid::new_v4(),
            &[chosen],
            &AtomicBool::new(false),
            &Closed
        )
        .unwrap()
        .deleted
            == 0
    );
    assert_eq!(fs::read(profile.root.join("Preferences")).unwrap(), after);
}

#[test]
#[cfg(windows)]
fn hardlinked_source_and_recovery_path_conflicts_do_not_grant_effects() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome);
    let path = profile.root.join("Preferences");
    let alias = temp.path().join("outside-owned-alias");
    fs::hard_link(&path, &alias).unwrap();
    let report = scan(&profile);
    assert!(report.partial && report.records.is_empty());
    assert_eq!(fs::read(&alias).unwrap(), INPUT);
    fs::remove_file(&alias).unwrap();
    let report = scan(&profile);
    let chosen = field(&report, Field::DnsReferrals);
    let data = temp.path().join("data");
    fs::create_dir_all(&data).unwrap();
    fs::write(data.join("privacy-preferences"), b"owned conflict").unwrap();
    let receipt = clean(
        &data,
        Uuid::new_v4(),
        &[chosen],
        &AtomicBool::new(false),
        &Closed,
    )
    .unwrap();
    assert_eq!(receipt.deleted, 0);
    assert_eq!(fs::read(path).unwrap(), INPUT);
}

#[test]
fn unsupported_and_malformed_sources_are_explicit_and_do_not_leak_payloads() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome);
    for bytes in [
        b"{private-payload".as_slice(),
        br#"{"profile":false}"#,
        br#"{"dns_prefetching":{"startup_list":0,"startup_list":1}}"#,
        b"\xff",
    ] {
        fs::write(profile.root.join("Preferences"), bytes).unwrap();
        let report = scan(&profile);
        assert!(report.partial);
        assert!(report.records.is_empty());
        assert!(
            report
                .skipped
                .iter()
                .all(|s| !s.reason.contains("private-payload"))
        );
        assert_eq!(fs::read(profile.root.join("Preferences")).unwrap(), bytes);
    }
}

#[test]
#[cfg(windows)]
fn cleanup_and_restore_reserve_receipt_capacity_before_any_source_effect() {
    let temp = tempfile::tempdir().unwrap();
    let mut profile = fixture(&temp.path().join("oversized-label"), Browser::Chrome);
    profile.name = "a".repeat(MAX_META);
    let chosen = field(&scan(&profile), Field::DnsReferrals);
    let data = temp.path().join("oversized-data");
    assert!(
        clean_group(
            &data,
            Uuid::new_v4(),
            &[chosen],
            &AtomicBool::new(false),
            &Closed,
            |_, _| panic!("oversized intent reached its effect")
        )
        .is_err()
    );
    assert_eq!(fs::read(profile.root.join("Preferences")).unwrap(), INPUT);
    assert!(!data.exists());

    let profile = fixture(&temp.path().join("journal-capacity"), Browser::Chrome);
    let chosen = field(&scan(&profile), Field::DnsReferrals);
    let data = temp.path().join("journal-data");
    assert_eq!(
        clean(
            &data,
            Uuid::new_v4(),
            &[chosen],
            &AtomicBool::new(false),
            &Closed
        )
        .unwrap()
        .deleted,
        1
    );
    let after = fs::read(profile.root.join("Preferences")).unwrap();
    let id = options(&data).unwrap()[0].id;
    let path = private_dir(&data, false)
        .unwrap()
        .join(format!("{id}.jsonl"));
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    for _ in 0..31 {
        let operation = Uuid::new_v4();
        for event in [
            Event::RestoreStart { operation },
            Event::RestoreDone {
                operation,
                outcome: Outcome::Refused,
            },
        ] {
            let mut bytes = serde_json::to_vec(&event).unwrap();
            bytes.push(b'\n');
            file.write_all(&bytes).unwrap();
        }
    }
    file.sync_all().unwrap();
    drop(file);
    assert_eq!(entries(&data).unwrap()[0].journal_events, 64);
    assert!(prepare_restore(&data, id, &Closed).is_err());
    assert_eq!(fs::read(profile.root.join("Preferences")).unwrap(), after);
}

#[test]
#[cfg(windows)]
fn mixed_sql_and_json_plan_keeps_distinct_effect_and_recovery_owners() {
    let temp = tempfile::tempdir().unwrap();
    let profile = fixture(&temp.path().join("profile"), Browser::Chrome);
    let data = temp.path().join("data");
    let conn = Connection::open(profile.root.join("Web Data")).unwrap();
    conn.execute_batch("CREATE TABLE keywords(id INTEGER,prepopulate_id INTEGER,safe_for_autoreplace INTEGER,url TEXT);CREATE TABLE meta(key TEXT,value);INSERT INTO keywords VALUES(7,0,1,'https://owned.test/');INSERT INTO meta VALUES('Default Search Provider ID',-1);").unwrap();
    drop(conn);
    let report = scan(&profile);
    assert!(!report.partial, "{:?}", report.skipped);
    let json = field(&report, Field::DnsReferrals);
    let sql = report
        .records
        .iter()
        .find(|r| matches!(&r.locator, RecordLocator::Database(_)))
        .unwrap()
        .id;
    let receipt = run(
        &data,
        &build_cleanup_plan(&report, &[json.id, sql]).unwrap(),
    );
    assert_eq!(
        (receipt.selected, receipt.deleted, receipt.skipped),
        (2, 2, 0),
        "{:?}",
        receipt.errors
    );
    assert!(!receipt.uncertain);
    let options = list_privacy_restore_options(&data).unwrap();
    assert_eq!(options.len(), 2);
    let json_option = options
        .iter()
        .find(|o| o.database_name == "Preferences")
        .unwrap();
    let restore = prepare_privacy_restore_with_runtime(&data, json_option.id, &Closed).unwrap();
    assert!(
        restore_privacy_database_with_runtime(&data, &restore, &Closed)
            .unwrap()
            .restored
    );
    assert_eq!(fs::read(profile.root.join("Preferences")).unwrap(), INPUT);
    assert_eq!(
        Connection::open(profile.root.join("Web Data"))
            .unwrap()
            .query_row("SELECT COUNT(*) FROM keywords", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
