use super::*;
fn bytes(pinned: bool) -> Vec<u8> {
    let mut bytes = b"SNSS\x01\x00\x00\x00".to_vec();
    let mut add = |kind: u8, payload: &[u8]| {
        bytes.extend_from_slice(&((payload.len() + 1) as u16).to_le_bytes());
        bytes.push(kind);
        bytes.extend_from_slice(payload);
    };
    if pinned {
        add(12, &[11, 0, 0, 0, 1, 0, 0, 0]);
        add(7, &[11, 0, 0, 0, 3, 0, 0, 0]);
        add(6, &[8, 0, 0, 0, 11, 0, 0, 0, 3, 0, 0, 0]);
    }
    add(255, b"owned private session value");
    bytes
}
fn fixture(root: &Path) -> BrowserProfile {
    fs::create_dir_all(root.join("Sessions")).unwrap();
    fs::write(root.join("Sessions/Session_1"), bytes(true)).unwrap();
    BrowserProfile {
        browser: Browser::Chrome,
        id: "owned-session".into(),
        name: "Owned session".into(),
        root: dunce::canonicalize(root).unwrap(),
    }
}
fn scan(p: &BrowserProfile) -> PrivacyReport {
    scan_profiles_with_settings(
        std::slice::from_ref(p),
        &[PrivacyCategory::Sessions],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    )
}
fn review(report: &PrivacyReport) -> Review {
    report
        .records
        .iter()
        .find_map(|r| match &r.locator {
            RecordLocator::Preferences(r) => Some(r.clone()),
            _ => None,
        })
        .unwrap()
}
struct Closed;
impl BrowserRuntime for Closed {
    fn running_browsers(&self) -> Result<Vec<RunningBrowser>, String> {
        Ok(vec![])
    }
}
struct NoTrash;
impl crate::cleanup::TrashPort for NoTrash {
    fn move_to_trash(&mut self, _: &Path) -> Result<(), String> {
        panic!("unexpected Trash effect")
    }
}
fn run(data: &Path, report: &PrivacyReport) -> PrivacyReceipt {
    let ids = report.records.iter().map(|r| r.id).collect::<Vec<_>>();
    clean_privacy_with_runtime_and_trash(
        data,
        &build_cleanup_plan(report, &ids).unwrap(),
        &AtomicBool::new(false),
        &Closed,
        &mut NoTrash,
        &mut |_, _| {},
    )
    .unwrap()
}

#[test]
#[cfg(windows)]
fn current_session_rewrite_and_restore_bind_exact_bytes_and_schema2_targets() {
    let temp = tempfile::tempdir().unwrap();
    let p = fixture(&temp.path().join("profile"));
    let data = temp.path().join("data");
    let report = scan(&p);
    let chosen = review(&report);
    assert!(chosen.is_session());
    let receipt = run(&data, &report);
    assert_eq!(
        (receipt.deleted, receipt.skipped, receipt.uncertain),
        (1, 0, false),
        "{:?}",
        receipt.errors
    );
    assert_eq!(fs::read(&receipt.backups[0]).unwrap(), bytes(true));
    let after = fs::read(chosen.source.path()).unwrap();
    let options = list_privacy_restore_options(&data).unwrap();
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].categories, vec![PrivacyCategory::Sessions]);
    assert_eq!(options[0].database_name, "Sessions/Session_1");
    let plan = prepare_privacy_restore_with_runtime(&data, options[0].id, &Closed).unwrap();
    assert!(plan.restores_sessions() && !plan.restores_preferences());
    let receipt = restore_privacy_database_with_runtime(&data, &plan, &Closed).unwrap();
    assert!(receipt.restored && !receipt.uncertain);
    assert_eq!(
        fs::read(receipt.current_state_backup.unwrap()).unwrap(),
        after
    );
    assert_eq!(fs::read(chosen.source.path()).unwrap(), bytes(true));
}

#[test]
#[cfg(windows)]
fn same_stamp_session_drift_refuses_old_rewrite_and_restore_reviews() {
    let temp = tempfile::tempdir().unwrap();
    let p = fixture(&temp.path().join("profile"));
    let data = temp.path().join("data");
    let report = scan(&p);
    let chosen = review(&report);
    let path = chosen.source.path();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let stamp = file_stamp(&path).unwrap();
    let mut changed = bytes(true);
    *changed.last_mut().unwrap() ^= 1;
    fs::write(&path, &changed).unwrap();
    filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(modified)).unwrap();
    assert_eq!(file_stamp(&path).unwrap(), stamp);
    assert_eq!(run(&data, &report).deleted, 0);
    assert_eq!(fs::read(&path).unwrap(), changed);
    assert_eq!(run(&data, &scan(&p)).deleted, 1);
    let option = list_privacy_restore_options(&data)
        .unwrap()
        .into_iter()
        .find(|o| o.state == PrivacyRecoveryState::Ready)
        .unwrap();
    let plan = prepare_privacy_restore_with_runtime(&data, option.id, &Closed).unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let stamp = file_stamp(&path).unwrap();
    let mut changed = fs::read(&path).unwrap();
    changed[4] ^= 1;
    fs::write(&path, &changed).unwrap();
    filetime::set_file_mtime(&path, filetime::FileTime::from_system_time(modified)).unwrap();
    assert_eq!(file_stamp(&path).unwrap(), stamp);
    assert!(restore_privacy_database_with_runtime(&data, &plan, &Closed).is_err());
    assert_eq!(fs::read(path).unwrap(), changed);
}

#[test]
#[cfg(windows)]
fn uncertain_session_write_cannot_be_reclassified_into_a_new_trash_operation() {
    let temp = tempfile::tempdir().unwrap();
    let p = fixture(&temp.path().join("profile"));
    let data = temp.path().join("data");
    let chosen = review(&scan(&p));
    let new_image = bytes(false);
    let receipt = clean_group(
        &data,
        Uuid::new_v4(),
        &[chosen.clone()],
        &AtomicBool::new(false),
        &Closed,
        |lease, _| {
            lease.write(&new_image)?;
            Err("injected uncertain session write".into())
        },
    )
    .unwrap();
    assert!(receipt.uncertain && receipt.deleted == 0);
    let current = scan(&p);
    assert_eq!(current.records.len(), 1);
    assert!(matches!(current.records[0].locator, RecordLocator::File(_)));
    let receipt = run(&data, &current);
    assert_eq!(receipt.deleted, 0);
    assert_eq!(fs::read(chosen.source.path()).unwrap(), new_image);
    assert_eq!(
        list_privacy_restore_options(&data).unwrap()[0].state,
        PrivacyRecoveryState::Uncertain
    );
}

#[test]
#[cfg(windows)]
fn unresolved_trash_intent_beyond_history_display_limit_blocks_new_rewrite() {
    let temp = tempfile::tempdir().unwrap();
    let p = fixture(&temp.path().join("profile"));
    let data = temp.path().join("data");
    let root = data.join("operations");
    fs::create_dir_all(&root).unwrap();
    for n in 0..102 {
        let id = Uuid::new_v4();
        let mut events = vec![crate::store::JournalEvent::Start {
            id,
            date: format!("{n:04}"),
        }];
        if n == 0 {
            events.push(crate::store::JournalEvent::Intent {
                file_id: Uuid::new_v4(),
                path: p.root.join("Sessions/Session_1"),
                size: 1,
            });
        } else {
            events.push(crate::store::JournalEvent::Finish { cancelled: false });
        }
        let text = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap() + "\n")
            .collect::<String>();
        fs::write(root.join(format!("{id}.jsonl")), text).unwrap();
    }
    assert_eq!(crate::store::history(&data).unwrap().len(), 100);
    let receipt = run(&data, &scan(&p));
    assert_eq!(receipt.deleted, 0);
    assert_eq!(
        fs::read(p.root.join("Sessions/Session_1")).unwrap(),
        bytes(true)
    );
}

#[test]
#[cfg(windows)]
fn byte_identical_session_write_uncertainty_still_blocks_fresh_ids() {
    let temp = tempfile::tempdir().unwrap();
    let p = fixture(&temp.path().join("profile"));
    let path = p.root.join("Sessions/Session_1");
    let session_binary::Plan::RewritePinned {
        bytes: unchanged, ..
    } = session_binary::Document::parse(&bytes(true), &AtomicBool::new(false))
        .unwrap()
        .plan(&AtomicBool::new(false))
        .unwrap()
    else {
        panic!()
    };
    fs::write(&path, &unchanged).unwrap();
    let data = temp.path().join("data");
    let chosen = review(&scan(&p));
    let receipt = clean_group(
        &data,
        Uuid::new_v4(),
        &[chosen],
        &AtomicBool::new(false),
        &Closed,
        |_, _| Err("injected no-change uncertainty".into()),
    )
    .unwrap();
    assert!(receipt.uncertain);
    assert_eq!(run(&data, &scan(&p)).deleted, 0);
    assert_eq!(fs::read(path).unwrap(), unchanged);
}

#[test]
#[cfg(windows)]
fn legacy_json_and_session_schema2_journals_coexist_without_cross_format_authority() {
    let temp = tempfile::tempdir().unwrap();
    let p = fixture(&temp.path().join("profile"));
    fs::write(
        p.root.join("Preferences"),
        br#"{"dns_prefetching":{"startup_list":false}}"#,
    )
    .unwrap();
    let data = temp.path().join("data");
    let report = scan_profiles_with_settings(
        &[p.clone()],
        &[PrivacyCategory::History, PrivacyCategory::Sessions],
        &Default::default(),
        &AtomicBool::new(false),
        |_| {},
    );
    assert!(!report.partial, "{:?}", report.skipped);
    assert_eq!(report.records.len(), 2);
    assert_eq!(run(&data, &report).deleted, 2);
    let root = private_dir(&data, false).unwrap();
    let entries = entries(&data).unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .any(|e| e.intent.version == 1 && e.intent.source.relative.is_none())
    );
    assert!(
        entries
            .iter()
            .any(|e| e.intent.version == 2 && e.intent.source.relative.is_some())
    );
    for entry in &entries {
        let text = fs::read_to_string(root.join(format!("{}.jsonl", entry.intent.id))).unwrap();
        let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert!(first["intent"]["selected"][0][1].is_string());
        if entry.intent.version == 1 {
            assert!(first["intent"]["source"].get("relative").is_none());
        } else {
            assert_eq!(first["intent"]["selected"][0][1], "session_file");
        }
    }
    let session = entries.iter().find(|e| e.intent.version == 2).unwrap();
    let backup = root.join(format!("{}.before", session.intent.id));
    let saved = root.join("owned.saved");
    fs::rename(&backup, &saved).unwrap();
    assert_eq!(list_privacy_restore_options(&data).unwrap().len(), 2);
    assert!(prepare_privacy_restore_with_runtime(&data, session.intent.id, &Closed).is_err());
    fs::rename(saved, backup).unwrap();
    let journal = root.join(format!("{}.jsonl", session.intent.id));
    let text = fs::read_to_string(&journal).unwrap();
    let mut rewritten = String::new();
    for line in text.lines() {
        let mut event: Event = serde_json::from_str(line).unwrap();
        if let Event::Start { intent } = &mut event {
            intent.version = 1;
        }
        rewritten += &(serde_json::to_string(&event).unwrap() + "\n");
    }
    fs::write(journal, rewritten).unwrap();
    assert!(list_privacy_restore_options(&data).is_err());
}

#[test]
#[cfg(windows)]
fn partial_session_restore_preserves_current_copy_and_blocks_automatic_retry() {
    let temp = tempfile::tempdir().unwrap();
    let p = fixture(&temp.path().join("profile"));
    let data = temp.path().join("data");
    assert_eq!(run(&data, &scan(&p)).deleted, 1);
    let option = list_privacy_restore_options(&data).unwrap().remove(0);
    let plan = prepare_privacy_restore_with_runtime(&data, option.id, &Closed).unwrap();
    let current = fs::read(p.root.join("Sessions/Session_1")).unwrap();
    let receipt = restore_effect(
        &data,
        plan.preferences.as_ref().unwrap(),
        &Closed,
        |lease, _| {
            lease.write(b"SNSS")?;
            Err("injected partial restore".into())
        },
    )
    .unwrap();
    assert!(receipt.uncertain && !receipt.restored);
    assert_eq!(
        fs::read(receipt.current_state_backup.unwrap()).unwrap(),
        current
    );
    assert!(prepare_privacy_restore_with_runtime(&data, option.id, &Closed).is_err());
    assert_eq!(
        fs::read(p.root.join("Sessions/Session_1")).unwrap(),
        b"SNSS"
    );
}

#[test]
#[cfg(windows)]
fn session_targets_refuse_json_path_aliases_absolute_paths_and_undeclared_families() {
    let temp = tempfile::tempdir().unwrap();
    let p = fixture(temp.path());
    let chosen = review(&scan(&p));
    let mut wrong = chosen.clone();
    wrong.field = Field::DnsReferrals.into();
    assert!(preflight(&Closed, &[wrong]).is_err());
    let mut source = (*chosen.source).clone();
    source.relative = Some(source.path());
    let mut wrong = chosen.clone();
    wrong.source = Arc::new(source);
    assert!(preflight(&Closed, &[wrong]).is_err());
    let mut source = (*chosen.source).clone();
    source.browser = Browser::Firefox;
    let mut wrong = chosen.clone();
    wrong.source = Arc::new(source);
    assert!(preflight(&Closed, &[wrong]).is_err());
    assert_eq!(fs::read(chosen.source.path()).unwrap(), bytes(true));
}
