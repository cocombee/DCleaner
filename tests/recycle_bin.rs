use dcleaner::{
    effects,
    recycle_bin::{
        self, InventoryCompletion, ItemOperationState, PortError, PortItem, RecycleBinPort,
        RecycleBinSize,
    },
};
use std::{ffi::OsString, fs, path::PathBuf, sync::atomic::AtomicBool};
use uuid::Uuid;

struct FakeItem {
    shell: PortItem,
    size: RecycleBinSize,
    metadata_error: Option<PortError>,
}

struct FakeRecycleBin {
    items: Vec<FakeItem>,
    data_dir: PathBuf,
    restored: Vec<PortItem>,
    purged: Vec<PortItem>,
    next_restore_error: Option<PortError>,
    remove_before_error: bool,
}

impl FakeRecycleBin {
    fn new(data_dir: PathBuf) -> Self {
        Self {
            items: vec![],
            data_dir,
            restored: vec![],
            purged: vec![],
            next_restore_error: None,
            remove_before_error: false,
        }
    }

    fn add(&mut self, token: u8, name: &str, size: RecycleBinSize) -> PortItem {
        let item = PortItem::new(
            vec![token],
            OsString::from(name),
            PathBuf::from(r"C:\fixture\original"),
            1_700_000_000 + i64::from(token),
        );
        self.items.push(FakeItem {
            shell: item.clone(),
            size,
            metadata_error: None,
        });
        item
    }

    fn assert_intent_is_durable(&self) {
        let directory = self.data_dir.join("effects/recycle-bin");
        let entries = fs::read_dir(directory).expect("intent directory must exist before effect");
        let mut saw_intent = false;
        for entry in entries {
            let body = fs::read_to_string(entry.unwrap().path()).unwrap();
            let first_line: serde_json::Value =
                serde_json::from_str(body.lines().next().unwrap()).unwrap();
            saw_intent |= first_line["phase"] == "intent";
        }
        assert!(saw_intent, "the durable intent must precede every effect");
    }

    fn remove(&mut self, item: &PortItem) {
        self.items.retain(|current| current.shell != *item);
    }
}

impl RecycleBinPort for FakeRecycleBin {
    fn list(&mut self) -> Result<Vec<PortItem>, PortError> {
        Ok(self.items.iter().map(|entry| entry.shell.clone()).collect())
    }

    fn metadata(&mut self, item: &PortItem) -> Result<RecycleBinSize, PortError> {
        let entry = self
            .items
            .iter()
            .find(|entry| entry.shell == *item)
            .ok_or_else(|| PortError::unavailable("fake item is missing"))?;
        if let Some(error) = entry.metadata_error.clone() {
            Err(error)
        } else {
            Ok(entry.size)
        }
    }

    fn restore_one(&mut self, item: &PortItem) -> Result<(), PortError> {
        self.assert_intent_is_durable();
        if let Some(error) = self.next_restore_error.take() {
            if self.remove_before_error {
                self.remove(item);
            }
            return Err(error);
        }
        self.remove(item);
        self.restored.push(item.clone());
        Ok(())
    }

    fn purge_one(&mut self, item: &PortItem) -> Result<(), PortError> {
        self.assert_intent_is_durable();
        self.remove(item);
        self.purged.push(item.clone());
        Ok(())
    }
}

fn inventory(port: &mut FakeRecycleBin) -> recycle_bin::RecycleBinInventory {
    recycle_bin::inventory(port, &AtomicBool::new(false), |_, _| {})
}

#[test]
fn inventory_keeps_directory_entry_counts_out_of_byte_totals() {
    let root = tempfile::tempdir().unwrap();
    let mut port = FakeRecycleBin::new(root.path().to_path_buf());
    port.add(1, "file.bin", RecycleBinSize::Bytes(4096));
    port.add(2, "folder", RecycleBinSize::Entries(3));

    let report = inventory(&mut port);

    assert_eq!(report.completion, InventoryCompletion::Complete);
    assert_eq!(report.item_count(), 2);
    assert_eq!(report.known_file_bytes, 4096);
    assert_eq!(report.items[0].size(), Some(RecycleBinSize::Bytes(4096)));
    assert_eq!(report.items[1].size(), Some(RecycleBinSize::Entries(3)));
}

#[test]
fn reviewed_selection_rejects_unknown_ids_and_deduplicates_repeated_ids() {
    let root = tempfile::tempdir().unwrap();
    let mut port = FakeRecycleBin::new(root.path().to_path_buf());
    port.add(1, "one.txt", RecycleBinSize::Bytes(1));
    let report = inventory(&mut port);
    let id = report.items[0].id();

    let selected = recycle_bin::reviewed_selection(&report, &[id, id]).unwrap();
    assert_eq!(selected.len(), 1);
    assert!(recycle_bin::reviewed_selection(&report, &[Uuid::new_v4()]).is_err());
}

#[test]
fn purge_is_per_item_journaled_and_does_not_touch_unselected_items() {
    let root = tempfile::tempdir().unwrap();
    let mut port = FakeRecycleBin::new(root.path().to_path_buf());
    let keep = port.add(1, "keep.txt", RecycleBinSize::Bytes(20));
    port.add(2, "purge.txt", RecycleBinSize::Bytes(40));
    let report = inventory(&mut port);
    let selected_id = report.items[1].id();
    let selection = recycle_bin::reviewed_selection(&report, &[selected_id]).unwrap();

    let result = recycle_bin::purge_selected(
        root.path(),
        &selection,
        &mut port,
        &AtomicBool::new(false),
        |_, _| {},
    );

    assert_eq!(result.receipts.len(), 1);
    assert_eq!(result.receipts[0].state, ItemOperationState::Purged);
    assert_eq!(port.items.len(), 1);
    assert_eq!(port.items[0].shell, keep);
    assert_eq!(port.purged.len(), 1);
    let history = effects::history(root.path(), "recycle-bin").unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].state, "applied");
    assert_eq!(history[0].intent["operation"], "purge");
    assert_eq!(history[0].receipt.as_ref().unwrap()["outcome"], "purged");
}

#[test]
fn changed_item_is_not_restored_and_the_change_is_receipted() {
    let root = tempfile::tempdir().unwrap();
    let mut port = FakeRecycleBin::new(root.path().to_path_buf());
    port.add(1, "changed.txt", RecycleBinSize::Bytes(10));
    let report = inventory(&mut port);
    let selection = recycle_bin::reviewed_selection(&report, &[report.items[0].id()]).unwrap();
    port.items[0].size = RecycleBinSize::Bytes(11);

    let result = recycle_bin::restore_selected(
        root.path(),
        &selection,
        &mut port,
        &AtomicBool::new(false),
        |_, _| {},
    );

    assert_eq!(result.receipts[0].state, ItemOperationState::Changed);
    assert!(port.restored.is_empty());
    assert_eq!(port.items.len(), 1);
    let history = effects::history(root.path(), "recycle-bin").unwrap();
    assert_eq!(history[0].state, "failed");
    assert_eq!(history[0].receipt.as_ref().unwrap()["outcome"], "changed");
}

#[test]
fn restore_is_per_item_journaled_and_verifies_removal_from_the_bin() {
    let root = tempfile::tempdir().unwrap();
    let mut port = FakeRecycleBin::new(root.path().to_path_buf());
    let keep = port.add(1, "keep.txt", RecycleBinSize::Bytes(12));
    port.add(2, "restore.txt", RecycleBinSize::Bytes(24));
    let report = inventory(&mut port);
    let selection = recycle_bin::reviewed_selection(&report, &[report.items[1].id()]).unwrap();

    let result = recycle_bin::restore_selected(
        root.path(),
        &selection,
        &mut port,
        &AtomicBool::new(false),
        |_, _| {},
    );

    assert_eq!(
        result.completion,
        recycle_bin::OperationCompletion::Complete
    );
    assert_eq!(result.receipts[0].state, ItemOperationState::Restored);
    assert_eq!(port.items.len(), 1);
    assert_eq!(port.items[0].shell, keep);
    assert_eq!(port.restored.len(), 1);
    let history = effects::history(root.path(), "recycle-bin").unwrap();
    assert_eq!(history[0].state, "restored");
    assert_eq!(history[0].intent["operation"], "restore");
    assert_eq!(history[0].receipt.as_ref().unwrap()["outcome"], "restored");
}

#[test]
fn explicit_access_denial_is_reported_and_does_not_remove_the_item() {
    let root = tempfile::tempdir().unwrap();
    let mut port = FakeRecycleBin::new(root.path().to_path_buf());
    port.add(1, "denied.txt", RecycleBinSize::Bytes(7));
    let report = inventory(&mut port);
    let selection = recycle_bin::reviewed_selection(&report, &[report.items[0].id()]).unwrap();
    port.next_restore_error = Some(PortError::denied("fixture denial"));

    let result = recycle_bin::restore_selected(
        root.path(),
        &selection,
        &mut port,
        &AtomicBool::new(false),
        |_, _| {},
    );

    assert_eq!(result.receipts[0].state, ItemOperationState::Denied);
    assert_eq!(port.items.len(), 1);
    assert!(port.restored.is_empty());
    let history = effects::history(root.path(), "recycle-bin").unwrap();
    assert_eq!(history[0].state, "failed");
    assert_eq!(history[0].receipt.as_ref().unwrap()["outcome"], "denied");
}

#[test]
fn unreadable_metadata_makes_inventory_partial_and_blocks_effects() {
    let root = tempfile::tempdir().unwrap();
    let mut port = FakeRecycleBin::new(root.path().to_path_buf());
    port.add(1, "unreadable.txt", RecycleBinSize::Bytes(9));
    port.items[0].metadata_error = Some(PortError::denied("fixture metadata denial"));

    let report = inventory(&mut port);
    assert_eq!(report.completion, InventoryCompletion::Partial);
    assert_eq!(report.items.len(), 1);
    assert!(!report.items[0].is_size_readable());
    let selection = recycle_bin::reviewed_selection(&report, &[report.items[0].id()]).unwrap();

    let result = recycle_bin::purge_selected(
        root.path(),
        &selection,
        &mut port,
        &AtomicBool::new(false),
        |_, _| {},
    );

    assert_eq!(result.receipts[0].state, ItemOperationState::Denied);
    assert!(port.purged.is_empty());
    assert_eq!(port.items.len(), 1);
}

#[test]
fn cancellation_before_an_item_has_no_side_effect_or_journal_intent() {
    let root = tempfile::tempdir().unwrap();
    let mut port = FakeRecycleBin::new(root.path().to_path_buf());
    port.add(1, "one.txt", RecycleBinSize::Bytes(1));
    let report = inventory(&mut port);
    let selection = recycle_bin::reviewed_selection(&report, &[report.items[0].id()]).unwrap();

    let result = recycle_bin::purge_selected(
        root.path(),
        &selection,
        &mut port,
        &AtomicBool::new(true),
        |_, _| {},
    );

    assert_eq!(
        result.completion,
        recycle_bin::OperationCompletion::Cancelled
    );
    assert_eq!(result.receipts[0].state, ItemOperationState::Cancelled);
    assert!(port.purged.is_empty());
    assert!(!root.path().join("effects/recycle-bin").exists());
}

#[test]
fn post_effect_error_and_missing_item_are_reported_uncertain_not_replayed() {
    let root = tempfile::tempdir().unwrap();
    let mut port = FakeRecycleBin::new(root.path().to_path_buf());
    port.add(1, "maybe-restored.txt", RecycleBinSize::Bytes(1));
    let report = inventory(&mut port);
    let selection = recycle_bin::reviewed_selection(&report, &[report.items[0].id()]).unwrap();
    port.next_restore_error = Some(PortError::failed("native result was interrupted"));
    port.remove_before_error = true;

    let result = recycle_bin::restore_selected(
        root.path(),
        &selection,
        &mut port,
        &AtomicBool::new(false),
        |_, _| {},
    );

    assert_eq!(result.receipts[0].state, ItemOperationState::Uncertain);
    let history = effects::history(root.path(), "recycle-bin").unwrap();
    assert_eq!(history[0].state, "uncertain");
}

#[test]
fn inventory_cancellation_returns_explicit_partial_state() {
    let root = tempfile::tempdir().unwrap();
    let mut port = FakeRecycleBin::new(root.path().to_path_buf());
    port.add(1, "one.txt", RecycleBinSize::Bytes(1));
    let report = recycle_bin::inventory(&mut port, &AtomicBool::new(true), |_, _| {});
    assert_eq!(report.completion, InventoryCompletion::Cancelled);
    assert!(report.items.is_empty());
}
