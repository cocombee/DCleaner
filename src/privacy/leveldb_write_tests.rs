use super::*;
use crate::privacy::leveldb_format::tests::{batch, empty, log};

struct Closed;
impl BrowserRuntime for Closed {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        Ok(Vec::new())
    }
}
struct Open;
impl BrowserRuntime for Open {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        Ok(vec![RunningBrowser {
            browser: Browser::Chrome,
            pid: 42,
            executable: "chrome.exe".into(),
        }])
    }
}
fn fixture() -> (tempfile::TempDir, BrowserProfile, PathBuf, Vec<Review>) {
    fixture_at("Local Storage/leveldb")
}
fn fixture_at(relative: &str) -> (tempfile::TempDir, BrowserProfile, PathBuf, Vec<Review>) {
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap().join("profile");
    let path = root.join(relative);
    fs::create_dir_all(&path).unwrap();
    let profile = BrowserProfile {
        id: "fixture".into(),
        browser: Browser::Chrome,
        name: "Owned profile".into(),
        root,
    };
    let mut files = empty();
    files.insert("LOCK".into(), vec![]);
    files.insert(
        "000003.log".into(),
        log(&[batch(
            11,
            &[
                (b"VERSION", Some(b"1")),
                (b"_https://one.test\0a", Some(b"one value")),
                (b"_https://one.test\0b", Some(b"two value")),
                (b"META:https://other.test", Some(b"metadata")),
            ],
        )]),
    );
    for (name, bytes) in files {
        fs::write(path.join(name), bytes).unwrap();
    }
    let report = scan_profiles_with_settings(
        std::slice::from_ref(&profile),
        &[PrivacyCategory::Cookies],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    );
    assert_eq!(report.records.len(), 3, "{:?}", report.skipped);
    let reviews = report
        .records
        .iter()
        .map(|record| match &record.locator {
            RecordLocator::LevelDb(review) => review.clone(),
            _ => panic!("wrong owner"),
        })
        .collect();
    (temp, profile, path, reviews)
}

#[test]
#[cfg(windows)]
fn recursive_scopes_clean_and_restore_only_reviewed_keys_and_hold_every_ancestor() {
    for relative in [
        "databases/extension/deep/store",
        "IndexedDB/chrome-extension_owned/deep/store",
        "IndexedDB/桶/深/store",
    ] {
        let (temp, profile, path, reviews) = fixture_at(relative);
        let store = reviews[0].store.as_ref().unwrap();
        let before = snapshot(store);
        let other = profile.root.join("IndexedDB/extension/untouched/store");
        fs::create_dir_all(&other).unwrap();
        for (name, bytes) in &before {
            fs::write(other.join(name), bytes).unwrap();
        }
        fs::write(other.join("LOCK"), []).unwrap();
        {
            let lease = Lease::acquire(store, store.log.as_deref().unwrap()).unwrap();
            // Intermediate buckets must be held, not just the leaf store.
            let parent = path.parent().unwrap();
            assert!(fs::rename(parent, parent.with_extension("replaced")).is_err());
            drop(lease);
        }
        let chosen = reviews
            .iter()
            .find(|r| r.key.ends_with(b"\0a"))
            .unwrap()
            .clone();
        let result = clean(
            &data(&temp),
            Uuid::new_v4(),
            &[chosen.clone()],
            &AtomicBool::new(false),
            &Closed,
        )
        .unwrap();
        assert_eq!(
            (result.deleted, result.skipped, result.uncertain),
            (1, 0, false),
            "{:?}",
            result.errors
        );
        let mut expected = leveldb_format::read(&before, &AtomicBool::new(false)).unwrap();
        expected.remove(&chosen.key);
        assert_eq!(
            leveldb_format::read(&snapshot(store), &AtomicBool::new(false)).unwrap(),
            expected
        );
        let other_after = leveldb::snapshot(
            &profile.root,
            &other,
            &AtomicBool::new(false),
            &mut leveldb::scan_budget(),
        )
        .unwrap();
        assert_eq!(other_after, before);
        let options = options(&data(&temp)).unwrap();
        let plan =
            prepare_privacy_restore_with_runtime(&data(&temp), options[0].id, &Closed).unwrap();
        assert!(plan.restores_site_storage_keys());
        assert_eq!(plan.database_name(), "Site storage");
        assert!(same_named_path(&plan.database, &path));
        let result = restore_privacy_database_with_runtime(&data(&temp), &plan, &Closed).unwrap();
        assert!(result.restored && !result.uncertain, "{:?}", result.errors);
        assert_eq!(
            leveldb_format::read(&snapshot(store), &AtomicBool::new(false)).unwrap(),
            leveldb_format::read(&before, &AtomicBool::new(false)).unwrap()
        );
        assert_eq!(
            leveldb::snapshot(
                &profile.root,
                &other,
                &AtomicBool::new(false),
                &mut leveldb::scan_budget()
            )
            .unwrap(),
            before
        );
    }
}

#[test]
fn persisted_legacy_scope_remains_local_and_new_scope_cannot_escape_or_take_earlier_ownership() {
    let (_temp, profile, _path, reviews) = fixture();
    let original = reviews[0].store.as_ref().unwrap();
    let mut value = serde_json::to_value(original.as_ref()).unwrap();
    value.as_object_mut().unwrap().remove("directory");
    let legacy: Store = serde_json::from_value(value).unwrap();
    assert_eq!(legacy.path(), profile.root.join("Local Storage/leveldb"));
    legacy.scope().unwrap();
    for relative in [
        "outside/store",
        "WebStorage/../outside/store",
        "IndexedDB/https_example.test_0.indexeddb.leveldb",
    ] {
        let mut changed = legacy.clone();
        changed.directory = Some(profile.root.join(relative));
        assert!(changed.scope().is_err(), "{relative}");
    }
    let mut changed = legacy.clone();
    changed.directory = profile.root.parent().map(|p| p.join("WebStorage/store"));
    assert!(changed.scope().is_err());
}

#[test]
#[cfg(windows)]
fn moved_recursive_store_cannot_reuse_old_reviewed_ids() {
    let (temp, profile, path, reviews) = fixture_at("IndexedDB/extension/bucket/store");
    let before = snapshot(reviews[0].store.as_ref().unwrap());
    let moved = profile.root.join("IndexedDB/extension/bucket/moved");
    fs::rename(&path, &moved).unwrap();
    let receipt = clean(
        &data(&temp),
        Uuid::new_v4(),
        &reviews[..1],
        &AtomicBool::new(false),
        &Closed,
    )
    .unwrap();
    assert_eq!(
        (receipt.deleted, receipt.skipped, receipt.uncertain),
        (0, 1, false)
    );
    assert!(entries(&data(&temp)).unwrap().is_empty());
    assert_eq!(
        leveldb::snapshot(
            &profile.root,
            &moved,
            &AtomicBool::new(false),
            &mut leveldb::scan_budget()
        )
        .unwrap(),
        before
    );
}
fn data(temp: &tempfile::TempDir) -> PathBuf {
    temp.path().join("data")
}
fn snapshot(store: &Store) -> BTreeMap<String, Vec<u8>> {
    leveldb::snapshot(
        &store.root,
        &store.path(),
        &AtomicBool::new(false),
        &mut leveldb::scan_budget(),
    )
    .unwrap()
}

#[test]
fn mutation_preserves_full_keys_and_unselected_values_without_source_writes() {
    let (_temp, _profile, _path, reviews) = fixture();
    let store = reviews[0].store.as_ref().unwrap();
    let before = snapshot(store);
    let selected = &reviews[1..2];
    let mutation = deletions(&before, selected, &AtomicBool::new(false)).unwrap();
    let mut after = before.clone();
    after
        .get_mut(&mutation.log)
        .unwrap()
        .extend(&mutation.append);
    let mut expected = leveldb_format::read(&before, &AtomicBool::new(false)).unwrap();
    expected.remove(&selected[0].key);
    assert_eq!(
        leveldb_format::read(&after, &AtomicBool::new(false)).unwrap(),
        expected
    );
    assert_eq!(snapshot(store), before);
    assert!(
        deletions(
            &before,
            &[selected[0].clone(), selected[0].clone()],
            &AtomicBool::new(false)
        )
        .is_err()
    );
}

#[test]
fn mutated_review_key_value_identity_and_source_are_rejected() {
    let (_temp, _profile, path, reviews) = fixture();
    let store = reviews[0].store.as_ref().unwrap();
    let before = snapshot(store);
    let mut wrong = reviews[0].clone();
    wrong.value_hash[0] ^= 1;
    assert!(deletions(&before, &[wrong], &AtomicBool::new(false)).is_err());
    let mut wrong = reviews[0].clone();
    wrong.raw_site = "different.test".into();
    assert!(deletions(&before, &[wrong], &AtomicBool::new(false)).is_err());
    let mut changed = before.clone();
    changed.get_mut("000003.log").unwrap().push(0);
    assert!(deletions(&changed, &reviews, &AtomicBool::new(false)).is_err());
    let bytes = fs::read(path.join("000003.log")).unwrap();
    fs::rename(path.join("000003.log"), path.join("old.log")).unwrap();
    fs::write(path.join("000003.log"), bytes).unwrap();
    assert!(deletions(&before, &reviews, &AtomicBool::new(false)).is_err());
}

#[test]
#[cfg(windows)]
fn native_delete_and_reviewed_restore_preserve_every_unselected_key() {
    let (temp, _profile, path, reviews) = fixture();
    let store = reviews[0].store.as_ref().unwrap();
    let before = snapshot(store);
    let chosen = reviews
        .iter()
        .find(|r| r.key.ends_with(b"\0a"))
        .unwrap()
        .clone();
    let result = clean(
        &data(&temp),
        Uuid::new_v4(),
        &[chosen.clone()],
        &AtomicBool::new(false),
        &Closed,
    )
    .unwrap();
    assert_eq!(
        (result.deleted, result.skipped, result.uncertain),
        (1, 0, false),
        "{:?}",
        result.errors
    );
    let after = snapshot(store);
    let mut expected = leveldb_format::read(&before, &AtomicBool::new(false)).unwrap();
    expected.remove(&chosen.key);
    assert_eq!(
        leveldb_format::read(&after, &AtomicBool::new(false)).unwrap(),
        expected
    );
    assert_eq!(fs::read_dir(&path).unwrap().count(), 4);
    assert!(path.join("LOCK").exists());
    assert!(recovery(&data(&temp)).unwrap().is_empty());
    let choices = options(&data(&temp)).unwrap();
    assert_eq!(choices[0].state, PrivacyRecoveryState::Ready);
    let plan = prepare_privacy_restore_with_runtime(&data(&temp), choices[0].id, &Closed).unwrap();
    let receipt = restore_privacy_database_with_runtime(&data(&temp), &plan, &Closed).unwrap();
    assert!(
        receipt.restored && !receipt.uncertain,
        "{:?}",
        receipt.errors
    );
    assert_eq!(
        leveldb_format::read(&snapshot(store), &AtomicBool::new(false)).unwrap(),
        leveldb_format::read(&before, &AtomicBool::new(false)).unwrap()
    );
    assert_eq!(
        options(&data(&temp)).unwrap()[0].state,
        PrivacyRecoveryState::Restored
    );
    assert!(restore_privacy_database_with_runtime(&data(&temp), &plan, &Closed).is_err());
}

#[test]
#[cfg(windows)]
fn durable_disk_intent_precedes_effect_and_partial_append_is_not_retried() {
    let (temp, _profile, _path, reviews) = fixture();
    let operation = Uuid::new_v4();
    let result = clean_group(
        &data(&temp),
        operation,
        &reviews,
        &AtomicBool::new(false),
        &Closed,
        |lease, mutation| {
            let durable = entries(&data(&temp)).unwrap();
            assert_eq!(durable.len(), 1);
            assert!(durable[0].outcome.is_none());
            let intent = load_intent(&data(&temp), &durable[0]).unwrap();
            assert_eq!(intent.append, mutation.append);
            assert_eq!(intent.keys.len(), reviews.len());
            lease.writer.seek(SeekFrom::End(0)).unwrap();
            lease
                .writer
                .write_all(&mutation.append[..mutation.append.len() / 2])
                .unwrap();
            lease.writer.sync_all().unwrap();
            Err("owned partial append fault".into())
        },
    )
    .unwrap();
    assert_eq!(result.deleted, 0);
    assert!(result.uncertain);
    assert_eq!(
        recovery(&data(&temp)).unwrap()[0].unresolved_ids.len(),
        reviews.len()
    );
    let mut called = false;
    assert!(
        clean_group(
            &data(&temp),
            operation,
            &reviews,
            &AtomicBool::new(false),
            &Closed,
            |_, _| {
                called = true;
                Ok(())
            }
        )
        .is_err()
    );
    assert!(!called);
    let option = &options(&data(&temp)).unwrap()[0];
    assert_eq!(option.state, PrivacyRecoveryState::Uncertain);
    assert!(prepare_privacy_restore_with_runtime(&data(&temp), option.id, &Closed).is_err());
}

#[test]
#[cfg(windows)]
fn post_effect_failure_stays_uncertain_even_when_complete_tombstones_exist() {
    let (temp, _profile, _path, reviews) = fixture();
    let result = clean_group(
        &data(&temp),
        Uuid::new_v4(),
        &reviews,
        &AtomicBool::new(false),
        &Closed,
        |lease, mutation| {
            lease.append(mutation.before_len, &mutation.append)?;
            Err("owned post-effect observation error".into())
        },
    )
    .unwrap();
    assert_eq!(result.deleted, 0);
    assert!(result.uncertain);
    assert_eq!(recovery(&data(&temp)).unwrap().len(), 1);
}

#[test]
#[cfg(windows)]
fn native_lock_and_write_sharing_protect_files_and_release_on_drop() {
    use std::os::windows::fs::OpenOptionsExt;
    let (_temp, _profile, path, reviews) = fixture();
    let store = reviews[0].store.as_ref().unwrap();
    let log = store.log.as_ref().unwrap();
    let mut lease = Lease::acquire(store, log).unwrap();
    assert!(Lease::acquire(store, log).is_err());
    assert!(
        OpenOptions::new()
            .write(true)
            .open(path.join("CURRENT"))
            .is_err()
    );
    assert!(fs::rename(path.join("CURRENT"), path.join("CURRENT.old")).is_err());
    assert!(
        OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(7)
            .open(path.join("LOCK"))
            .is_err()
    );
    assert_eq!(
        lease.observe(store, &AtomicBool::new(false)).unwrap(),
        snapshot(store)
    );
    drop(lease);
    assert!(Lease::acquire(store, log).is_ok());
}

#[test]
#[cfg(windows)]
fn original_windows_range_lock_excludes_rust_transaction_owner() {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{LockFile, UnlockFile},
    };
    let (_temp, _profile, path, reviews) = fixture();
    let store = reviews[0].store.as_ref().unwrap();
    let file = OpenOptions::new()
        .read(true)
        .share_mode(7)
        .open(path.join("LOCK"))
        .unwrap();
    unsafe { LockFile(HANDLE(file.as_raw_handle()), 0, 0, u32::MAX, u32::MAX) }.unwrap();
    assert!(Lease::acquire(store, store.log.as_ref().unwrap()).is_err());
    unsafe { UnlockFile(HANDLE(file.as_raw_handle()), 0, 0, u32::MAX, u32::MAX) }.unwrap();
    assert!(Lease::acquire(store, store.log.as_ref().unwrap()).is_ok());
}

#[test]
#[cfg(windows)]
fn cancellation_after_complete_append_finishes_verification_and_can_restore() {
    let (temp, _profile, _path, reviews) = fixture();
    let cancel = AtomicBool::new(false);
    let result = clean_group(
        &data(&temp),
        Uuid::new_v4(),
        &reviews,
        &cancel,
        &Closed,
        |lease, mutation| {
            lease.append(mutation.before_len, &mutation.append)?;
            cancel.store(true, Ordering::Relaxed);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(result.deleted, reviews.len());
    assert!(!result.uncertain && result.cancelled);
    assert_eq!(
        options(&data(&temp)).unwrap()[0].state,
        PrivacyRecoveryState::Ready
    );
}

#[test]
#[cfg(windows)]
fn browser_restart_policy_drift_cancel_and_failed_intent_prevent_effects() {
    let (temp, _profile, _path, reviews) = fixture();
    let store = reviews[0].store.as_ref().unwrap();
    let before = snapshot(store);
    assert!(
        clean(
            &data(&temp),
            Uuid::new_v4(),
            &reviews,
            &AtomicBool::new(false),
            &Open
        )
        .is_err()
    );
    let stopped = AtomicBool::new(true);
    assert!(
        clean(&data(&temp), Uuid::new_v4(), &reviews, &stopped, &Closed)
            .unwrap()
            .cancelled
    );
    save_cookie_exception_settings(&data(&temp), &["one.test".into()]).unwrap();
    assert!(
        clean_group(
            &data(&temp),
            Uuid::new_v4(),
            &reviews,
            &AtomicBool::new(false),
            &Closed,
            |_, _| panic!("unreviewed policy effect")
        )
        .is_err()
    );
    save_cookie_exception_settings(&data(&temp), &[]).unwrap();
    fs::write(data(&temp).join("privacy-leveldb"), b"blocked directory").unwrap();
    assert!(
        clean_group(
            &data(&temp),
            Uuid::new_v4(),
            &reviews,
            &AtomicBool::new(false),
            &Closed,
            |_, _| panic!("missing durable intent effect")
        )
        .is_err()
    );
    assert_eq!(snapshot(store), before);
}

#[test]
#[cfg(windows)]
fn confirmed_restore_refuses_new_browser_values_and_changed_durable_backup() {
    let (temp, _profile, path, reviews) = fixture();
    let result = clean(
        &data(&temp),
        Uuid::new_v4(),
        &reviews[..1],
        &AtomicBool::new(false),
        &Closed,
    )
    .unwrap();
    assert_eq!(result.deleted, 1);
    let id = options(&data(&temp)).unwrap()[0].id;
    assert!(prepare_privacy_restore_with_runtime(&data(&temp), id, &Open).is_err());
    let original = fs::read(&result.backups[0]).unwrap();
    fs::write(&result.backups[0], b"{}").unwrap();
    assert!(prepare_privacy_restore_with_runtime(&data(&temp), id, &Closed).is_err());
    fs::write(&result.backups[0], original).unwrap();
    let plan = prepare_privacy_restore_with_runtime(&data(&temp), id, &Closed).unwrap();
    let files = leveldb::snapshot(
        &reviews[0].store.as_ref().unwrap().root,
        &path,
        &AtomicBool::new(false),
        &mut leveldb::scan_budget(),
    )
    .unwrap();
    let image = leveldb_format::inspect(&files, &AtomicBool::new(false)).unwrap();
    let log = image.writable_log.unwrap();
    let extra = leveldb_format::append_batch(
        files[&log].len(),
        image.last_sequence + 1,
        &[(b"unrelated new key".to_vec(), Some(b"new value".to_vec()))],
    )
    .unwrap();
    OpenOptions::new()
        .append(true)
        .open(path.join(log))
        .unwrap()
        .write_all(&extra)
        .unwrap();
    assert!(restore_privacy_database_with_runtime(&data(&temp), &plan, &Closed).is_err());
}

#[test]
#[cfg(windows)]
fn public_cleanup_ids_route_to_leveldb_owner_without_sqlite_or_trash() {
    let (temp, profile, _path, _) = fixture();
    let report = scan_profiles_with_settings(
        &[profile],
        &[PrivacyCategory::Cookies],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(build_cleanup_plan(&report, &[Uuid::new_v4()]).is_err());
    let plan = build_cleanup_plan(&report, &[report.records[0].id, report.records[0].id]).unwrap();
    let receipt = clean_privacy_with_runtime(
        &data(&temp),
        &plan,
        &AtomicBool::new(false),
        &Closed,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(
        (receipt.selected, receipt.deleted),
        (1, 1),
        "{:?}",
        receipt.errors
    );
    assert_eq!(list_privacy_restore_options(&data(&temp)).unwrap().len(), 1);
}

#[test]
#[cfg(windows)]
fn independent_writer_corpus_survives_native_delete_and_restore() {
    fn unhex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn export(
        base: &Path,
        case: &str,
        state: &str,
        files: &BTreeMap<String, Vec<u8>>,
        expected: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) {
        let path = base.join(case).join(state);
        fs::create_dir_all(&path).unwrap();
        for (name, bytes) in files {
            fs::write(path.join(name), bytes).unwrap();
        }
        fs::write(path.join("LOCK"), []).unwrap();
        let expected: BTreeMap<_, _> = expected.iter().map(|(k, v)| (hex(k), hex(v))).collect();
        fs::write(
            path.join("expected.json"),
            serde_json::to_vec(&expected).unwrap(),
        )
        .unwrap();
    }
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/leveldb-independent.json"
    ))
    .unwrap();
    let output = std::env::var_os("DCLEANER_LEVELDB_INTEROP_OUTPUT").map(PathBuf::from);
    for dataset in corpus["datasets"].as_array().unwrap() {
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap().join("profile");
        let path = root.join("Local Storage/leveldb");
        fs::create_dir_all(&path).unwrap();
        for (name, bytes) in dataset["files"].as_object().unwrap() {
            fs::write(path.join(name), unhex(bytes.as_str().unwrap())).unwrap();
        }
        fs::write(path.join("LOCK"), []).unwrap();
        let profile = BrowserProfile {
            id: "independent".into(),
            browser: Browser::Chrome,
            name: "Independent fixture".into(),
            root,
        };
        let report = scan_profiles_with_settings(
            &[profile],
            &[PrivacyCategory::Cookies],
            &Default::default(),
            &AtomicBool::new(false),
            |_| {},
        );
        assert!(!report.partial, "{} {:?}", dataset["case"], report.skipped);
        let key = b"_https://fixture.test\0key000";
        let chosen = report
            .records
            .iter()
            .find(|r| matches!(&r.locator,RecordLocator::LevelDb(review)if review.key==key))
            .unwrap();
        let store = match &chosen.locator {
            RecordLocator::LevelDb(r) => r.store.as_ref().unwrap(),
            _ => unreachable!(),
        };
        let before = snapshot(store);
        let expected: BTreeMap<_, _> = dataset["expected"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (unhex(k), unhex(v.as_str().unwrap())))
            .collect();
        assert_eq!(
            leveldb_format::read(&before, &AtomicBool::new(false)).unwrap(),
            expected
        );
        let plan = build_cleanup_plan(&report, &[chosen.id]).unwrap();
        let receipt = clean_privacy_with_runtime(
            &data(&temp),
            &plan,
            &AtomicBool::new(false),
            &Closed,
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!(
            (receipt.deleted, receipt.uncertain),
            (1, false),
            "{} {:?}",
            dataset["case"],
            receipt.errors
        );
        let mut cleaned = expected.clone();
        cleaned.remove(key.as_slice());
        let after = snapshot(store);
        assert_eq!(
            leveldb_format::read(&after, &AtomicBool::new(false)).unwrap(),
            cleaned
        );
        for (name, bytes) in &before {
            if Some(name) != store.log.as_ref() {
                assert_eq!(&after[name], bytes);
            }
        }
        if let Some(output) = &output {
            export(
                output,
                dataset["case"].as_str().unwrap(),
                "cleaned",
                &after,
                &cleaned,
            );
        }
        let id = list_privacy_restore_options(&data(&temp)).unwrap()[0].id;
        let restore = prepare_privacy_restore_with_runtime(&data(&temp), id, &Closed).unwrap();
        let restored =
            restore_privacy_database_with_runtime(&data(&temp), &restore, &Closed).unwrap();
        assert!(
            restored.restored && !restored.uncertain,
            "{:?}",
            restored.errors
        );
        let after = snapshot(store);
        assert_eq!(
            leveldb_format::read(&after, &AtomicBool::new(false)).unwrap(),
            expected
        );
        for (name, bytes) in &before {
            if Some(name) != store.log.as_ref() {
                assert_eq!(&after[name], bytes);
            }
        }
        if let Some(output) = &output {
            export(
                output,
                dataset["case"].as_str().unwrap(),
                "restored",
                &after,
                &expected,
            );
        }
    }
}

#[test]
#[cfg(windows)]
fn damaged_pending_metadata_cannot_unblock_a_previous_uncertain_write() {
    let (temp, profile, _path, reviews) = fixture();
    let result = clean_group(
        &data(&temp),
        Uuid::new_v4(),
        &reviews[..1],
        &AtomicBool::new(false),
        &Closed,
        |lease, m| {
            lease.append(m.before_len, &m.append)?;
            Err("owned observation failure".into())
        },
    )
    .unwrap();
    assert!(result.uncertain);
    let root = private_dir(&data(&temp), false).unwrap();
    let id = entries(&data(&temp)).unwrap()[0].info.id;
    let path = root.join(format!("{id}.jsonl"));
    let bytes = fs::read(&path).unwrap();
    let mut changed = Vec::new();
    for line in bytes.split(|&b| b == b'\n').filter(|line| !line.is_empty()) {
        let mut event: Event = serde_json::from_slice(line).unwrap();
        if let Event::Start { info } = &mut event {
            info.root = temp.path().join("different-profile");
        }
        changed.extend(serde_json::to_vec(&event).unwrap());
        changed.push(b'\n');
    }
    fs::write(&path, &changed).unwrap();
    let report = scan_profiles_with_settings(
        &[profile],
        &[PrivacyCategory::Cookies],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    );
    let fresh = report
        .records
        .iter()
        .map(|r| match &r.locator {
            RecordLocator::LevelDb(k) => k.clone(),
            _ => unreachable!(),
        })
        .collect::<Vec<_>>();
    let before = snapshot(fresh[0].store.as_ref().unwrap());
    assert!(
        clean_group(
            &data(&temp),
            Uuid::new_v4(),
            &fresh,
            &AtomicBool::new(false),
            &Closed,
            |_, _| panic!("damaged pending metadata effect")
        )
        .is_err()
    );
    assert_eq!(snapshot(fresh[0].store.as_ref().unwrap()), before);
    changed.pop();
    fs::write(path, changed).unwrap();
    assert!(options(&data(&temp)).is_err());
}

#[test]
#[cfg(windows)]
fn cleanup_reserves_sequence_space_for_its_reviewed_restore() {
    let (temp, profile, path, _) = fixture();
    let mut edit = vec![4];
    edit.extend(crate::privacy::leveldb_format::tests::var((1u64 << 56) - 2));
    OpenOptions::new()
        .append(true)
        .open(path.join("MANIFEST-000001"))
        .unwrap()
        .write_all(&log(&[edit]))
        .unwrap();
    let report = scan_profiles_with_settings(
        &[profile],
        &[PrivacyCategory::Cookies],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    );
    let review = match &report.records[0].locator {
        RecordLocator::LevelDb(r) => r.clone(),
        _ => unreachable!(),
    };
    let before = snapshot(review.store.as_ref().unwrap());
    assert!(
        clean_group(
            &data(&temp),
            Uuid::new_v4(),
            &[review.clone()],
            &AtomicBool::new(false),
            &Closed,
            |_, _| panic!("missing restore sequence effect")
        )
        .is_err()
    );
    assert_eq!(snapshot(review.store.as_ref().unwrap()), before);
    assert!(!data(&temp).exists());
}
