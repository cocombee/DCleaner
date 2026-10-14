use dcleaner::effects::{self, EffectJournal};
use serde_json::json;
use uuid::Uuid;
#[test]
fn durable_intent_survives_without_receipt_as_uncertain() {
    let root = tempfile::tempdir().unwrap();
    let id = Uuid::new_v4();
    drop(
        EffectJournal::create(
            root.path(),
            "startup",
            id,
            &json!({"before":true,"after":false}),
        )
        .unwrap(),
    );
    let result = effects::history(root.path(), "startup").unwrap();
    assert_eq!(result[0].id, id);
    assert_eq!(result[0].state, "uncertain");
    assert!(result[0].receipt.is_none());
}
#[test]
fn receipt_survives_restart_and_duplicate_finish_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let mut journal = EffectJournal::create(
        root.path(),
        "uninstaller",
        Uuid::new_v4(),
        &json!({"id":"fixture"}),
    )
    .unwrap();
    journal
        .finish("handed_off", &json!({"process_id":42}))
        .unwrap();
    assert!(journal.finish("completed", &json!({})).is_err());
    drop(journal);
    let history = effects::history(root.path(), "uninstaller").unwrap();
    assert_eq!(history[0].state, "handed_off");
    assert_eq!(history[0].receipt.as_ref().unwrap()["process_id"], 42);
}
#[test]
fn truncated_receipt_is_uncertain_and_original_bytes_remain() {
    let root = tempfile::tempdir().unwrap();
    let id = Uuid::new_v4();
    drop(EffectJournal::create(root.path(), "startup", id, &json!({})).unwrap());
    let path = root
        .path()
        .join("effects/startup")
        .join(format!("{id}.jsonl"));
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{partial")
        .unwrap();
    assert_eq!(
        effects::history(root.path(), "startup").unwrap()[0].state,
        "uncertain"
    );
    assert!(std::fs::read(&path).unwrap().ends_with(b"{partial"));
}
#[test]
fn effect_journal_rejects_invalid_scope_before_writing() {
    let root = tempfile::tempdir().unwrap();
    assert!(EffectJournal::create(root.path(), "../escape", Uuid::new_v4(), &json!({})).is_err());
    assert!(!root.path().join("effects").exists());
}

#[test]
fn unknown_receipt_state_remains_uncertain() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let id = Uuid::new_v4();
    drop(EffectJournal::create(root.path(), "startup", id, &json!({})).unwrap());
    let path = root
        .path()
        .join("effects/startup")
        .join(format!("{id}.jsonl"));
    std::fs::OpenOptions::new().append(true).open(path).unwrap().write_all(b"{\"phase\":\"receipt\",\"state\":\"invented-success\",\"date\":\"2026-10-15\",\"payload\":{}}\n").unwrap();
    let records = effects::history(root.path(), "startup").unwrap();
    assert_eq!(records[0].state, "uncertain");
    assert!(records[0].receipt.is_none());
}
