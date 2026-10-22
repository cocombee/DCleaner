use crate::domain::{CleanupResult, FileOutcome, Preferences};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JournalEvent {
    Start {
        id: Uuid,
        date: String,
    },
    Intent {
        file_id: Uuid,
        path: PathBuf,
        size: u64,
    },
    Outcome {
        outcome: FileOutcome,
    },
    Finish {
        cancelled: bool,
    },
}
pub trait JournalSink {
    fn append(&mut self, event: &JournalEvent) -> Result<(), String>;
    /// Return only after every event is durable. Default sinks retain their
    /// individual-write behavior; the file sink can share one flush.
    fn append_batch(&mut self, events: &[JournalEvent]) -> Result<(), String> {
        for event in events {
            self.append(event)?;
        }
        Ok(())
    }
}
/// Opens no file until the effect owner has completed its preflight and writes
/// its first event. A rejected request must not leave an empty history record.
pub struct DeferredJournal {
    root: PathBuf,
    id: Uuid,
    journal: Option<Journal>,
}
impl DeferredJournal {
    pub fn new(root: &Path, id: Uuid) -> Self {
        Self {
            root: root.to_owned(),
            id,
            journal: None,
        }
    }
}
impl JournalSink for DeferredJournal {
    fn append(&mut self, event: &JournalEvent) -> Result<(), String> {
        if self.journal.is_none() {
            if !matches!(event, JournalEvent::Start { .. }) {
                return Err("A cleanup journal must begin with its start event.".into());
            }
            self.journal = Some(Journal::create(&self.root, self.id)?);
        }
        self.journal
            .as_mut()
            .expect("journal opened above")
            .append(event)
    }
    fn append_batch(&mut self, events: &[JournalEvent]) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        if self.journal.is_none() {
            self.append(&events[0])?;
            return self.append_batch(&events[1..]);
        }
        self.journal
            .as_mut()
            .expect("journal opened above")
            .append_batch(events)
    }
}
pub struct Journal {
    file: File,
}
impl Journal {
    pub fn create(root: &Path, id: Uuid) -> Result<Self, String> {
        fs::create_dir_all(root.join("operations")).map_err(|e| e.to_string())?;
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(root.join("operations").join(format!("{id}.jsonl")))
            .map_err(|e| e.to_string())?;
        Ok(Self { file })
    }
}
impl JournalSink for Journal {
    fn append(&mut self, event: &JournalEvent) -> Result<(), String> {
        self.append_batch(std::slice::from_ref(event))
    }
    fn append_batch(&mut self, events: &[JournalEvent]) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        let mut lines = Vec::new();
        for event in events {
            serde_json::to_writer(&mut lines, event).map_err(|e| e.to_string())?;
            lines.push(b'\n');
        }
        self.file
            .write_all(&lines)
            .and_then(|_| self.file.sync_all())
            .map_err(|e| format!("Could not preserve the cleanup journal: {e}"))
    }
}
pub fn load_preferences(root: &Path) -> Result<Preferences, String> {
    let file = root.join("preferences.json");
    if !file.exists() {
        return Ok(Preferences::default());
    }
    let settings: Preferences = serde_json::from_slice(&fs::read(file).map_err(|e| e.to_string())?)
        .map_err(|e| format!("Settings are unreadable; original bytes were preserved: {e}"))?;
    if settings.schema != 1 || !(1..=365).contains(&settings.minimum_age_days) {
        return Err(
            "Unsupported settings schema or invalid file age; settings were preserved.".into(),
        );
    }
    Ok(settings)
}
pub fn save_preferences(root: &Path, settings: &Preferences) -> Result<(), String> {
    fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let file = root.join("preferences.json");
    let temp = root.join(format!("preferences.{}.tmp", Uuid::new_v4()));
    let mut output = File::create(&temp).map_err(|e| e.to_string())?;
    output
        .write_all(&serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?)
        .and_then(|_| output.sync_all())
        .map_err(|e| e.to_string())?;
    // Windows rename replaces an existing ordinary file; a failing replace preserves it.
    fs::rename(&temp, &file)
        .map_err(|e| format!("Settings save failed; previous settings remain: {e}"))
}
pub fn project_events(events: &[JournalEvent]) -> Result<CleanupResult, String> {
    let Some(JournalEvent::Start { id, date }) = events.first() else {
        return Err("Journal has no valid start event.".into());
    };
    let mut record = CleanupResult {
        id: *id,
        date: date.clone(),
        ..Default::default()
    };
    let mut pending = HashMap::new();
    let mut finished = false;
    for event in events.iter().skip(1) {
        if finished {
            return Err("Journal contains records after its finish event.".into());
        }
        match event {
            JournalEvent::Intent {
                file_id,
                path,
                size,
            } => {
                if pending.insert(*file_id, (path.clone(), *size)).is_some() {
                    return Err("Duplicate unresolved file intent.".into());
                }
            }
            JournalEvent::Outcome { outcome } => {
                let Some((expected_path, expected_size)) = pending.remove(&outcome.file_id) else {
                    return Err("Outcome has no matching intent.".into());
                };
                if expected_path != outcome.path || expected_size != outcome.size {
                    return Err("Outcome identity differs from its intent.".into());
                }
                if outcome.success {
                    record.files += 1;
                    record.bytes += outcome.size;
                    record.cleaned_ids.push(outcome.file_id);
                } else {
                    record.failed.push(outcome.clone());
                }
            }
            JournalEvent::Finish { cancelled } => {
                record.cancelled = *cancelled;
                finished = true;
            }
            JournalEvent::Start { .. } => {
                return Err("Multiple operation identities in one journal.".into());
            }
        }
    }
    record.interrupted = !finished;
    record.uncertain = pending.into_values().map(|(path, _)| path).collect();
    Ok(record)
}
pub fn history(root: &Path) -> Result<Vec<CleanupResult>, String> {
    let dir = root.join("operations");
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut records = vec![];
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_none_or(|e| e != "jsonl") {
            continue;
        }
        let file = File::open(&path).map_err(|e| e.to_string())?;
        let mut events = vec![];
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|e| e.to_string())?;
            events.push(serde_json::from_str(&line).map_err(|e| {
                format!("A cleanup record is damaged; preserved for recovery ({e}).")
            })?);
        }
        records.push(project_events(&events)?);
    }
    records.sort_by(|a, b| b.date.cmp(&a.date));
    records.truncate(100);
    Ok(records)
}
