//! Durable boundaries for native operations that are not file-to-Trash cleanups.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
enum Entry {
    Intent {
        schema: u32,
        id: Uuid,
        feature: String,
        date: String,
        payload: Value,
    },
    Receipt {
        state: String,
        date: String,
        payload: Value,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EffectHistory {
    pub id: Uuid,
    pub feature: String,
    pub date: String,
    pub intent: Value,
    pub state: String,
    pub receipt: Option<Value>,
}
pub struct EffectJournal {
    file: File,
    finished: bool,
}
const MAX_HISTORY_BYTES: u64 = 4 * 1024 * 1024;
fn feature_directory(root: &Path, feature: &str) -> Result<PathBuf, String> {
    if !root.is_absolute()
        || feature.is_empty()
        || feature.len() > 64
        || !feature.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
    {
        return Err(
            "An absolute application-data directory and a valid native feature are required."
                .into(),
        );
    }
    Ok(root.join("effects").join(feature))
}
impl EffectJournal {
    pub fn create(
        root: &Path,
        feature: &str,
        id: Uuid,
        intent: &impl Serialize,
    ) -> Result<Self, String> {
        let directory = feature_directory(root, feature)?;
        fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(format!("{id}.jsonl")))
            .map_err(|e| e.to_string())?;
        let mut result = Self {
            file,
            finished: false,
        };
        result.append(&Entry::Intent {
            schema: 1,
            id,
            feature: feature.into(),
            date: chrono::Utc::now().to_rfc3339(),
            payload: serde_json::to_value(intent).map_err(|e| e.to_string())?,
        })?;
        Ok(result)
    }
    fn append(&mut self, entry: &Entry) -> Result<(), String> {
        let mut bytes = serde_json::to_vec(entry).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        self.file
            .write_all(&bytes)
            .and_then(|_| self.file.sync_all())
            .map_err(|e| format!("The native operation journal could not be preserved: {e}"))
    }
    pub fn finish(&mut self, state: &str, receipt: &impl Serialize) -> Result<(), String> {
        if self.finished
            || ![
                "failed",
                "handed_off",
                "applied",
                "restored",
                "verified",
                "completed",
                "uncertain",
            ]
            .contains(&state)
        {
            return Err("Invalid or duplicate native operation receipt.".into());
        }
        self.append(&Entry::Receipt {
            state: state.into(),
            date: chrono::Utc::now().to_rfc3339(),
            payload: serde_json::to_value(receipt).map_err(|e| e.to_string())?,
        })?;
        self.finished = true;
        Ok(())
    }
}
/// An intent without a complete durable receipt remains uncertain. Never replay it automatically.
pub fn history(root: &Path, feature: &str) -> Result<Vec<EffectHistory>, String> {
    let directory = feature_directory(root, feature)?;
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for (index, entry) in fs::read_dir(directory)
        .map_err(|e| e.to_string())?
        .enumerate()
    {
        if index >= 1000 {
            return Err("Native operation history exceeds its review limit.".into());
        }
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
            continue;
        }
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if crate::scanner::is_link(&meta) || !meta.is_file() {
            return Err("Linked native history was rejected.".into());
        }
        let mut bytes = Vec::new();
        File::open(&path)
            .map_err(|e| e.to_string())?
            .take(MAX_HISTORY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_HISTORY_BYTES {
            return Err(
                "Native operation history exceeds its size limit; original bytes were preserved."
                    .into(),
            );
        }
        let lines = BufReader::new(bytes.as_slice())
            .lines()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        if lines.is_empty() || lines.len() > 2 {
            return Err(
                "Native operation history is malformed; original bytes were preserved.".into(),
            );
        }
        let first: Entry = serde_json::from_str(&lines[0]).map_err(|e| {
            format!("Native operation intent is unreadable; original bytes were preserved: {e}")
        })?;
        let Entry::Intent {
            schema: 1,
            id,
            feature: record_feature,
            date,
            payload,
        } = first
        else {
            return Err(
                "Unsupported native operation intent; original bytes were preserved.".into(),
            );
        };
        if record_feature != feature
            || path.file_stem().and_then(|s| s.to_str()) != Some(id.to_string().as_str())
        {
            return Err("Native operation history identity differs from its file.".into());
        }
        let (state, receipt) = if let Some(line) = lines.get(1) {
            match serde_json::from_str::<Entry>(line) {
                Ok(Entry::Receipt { state, payload, .. })
                    if [
                        "failed",
                        "handed_off",
                        "applied",
                        "restored",
                        "verified",
                        "completed",
                        "uncertain",
                    ]
                    .contains(&state.as_str()) =>
                {
                    (state, Some(payload))
                }
                _ => ("uncertain".into(), None),
            }
        } else {
            ("uncertain".into(), None)
        };
        result.push(EffectHistory {
            id,
            feature: record_feature,
            date,
            intent: payload,
            state,
            receipt,
        });
    }
    result.sort_by(|a, b| b.date.cmp(&a.date));
    Ok(result)
}
