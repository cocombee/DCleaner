//! Read-only installed-program and startup-component inventory for Performance Optimizer.
//!
//! Candidate links are lexical path-containment proposals only. They do not
//! establish executable identity, publisher trust, ownership, impact, Sleep
//! state, or permission to mutate a component.

use crate::{
    programs::{self, InstalledProgram, RegistryHive, RegistryView},
    startup::{
        FieldValue, InventoryQuality, MAX_ITEMS_PER_SOURCE, SourceState, StartupEntry,
        StartupInventory, StartupManager, StartupSection, WindowsStartupPlatform,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

const SETTINGS_FILE: &str = "optimizer-inventory-settings.json";
const SETTINGS_LOCK_FILE: &str = ".optimizer-inventory-settings.lock";
const SETTINGS_SCHEMA: u32 = 1;
const MAX_SETTINGS_BYTES: usize = 512 * 1024;
const MAX_EXCLUDED_KEYS: usize = 200;
const MAX_REGISTRATION_NAME_BYTES: usize = 1024;
const MAX_PROGRAMS: usize = 8_192;
const MAX_PROGRAM_RECORD_BYTES: usize = 128 * 1024;
const MAX_PROGRAM_BYTES: usize = 16 * 1024 * 1024;
const MAX_STARTUP_ITEMS: usize = MAX_ITEMS_PER_SOURCE * 3;
const MAX_STARTUP_RECORD_BYTES: usize = 64 * 1024;
const MAX_STARTUP_BYTES: usize = 16 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_ID_BYTES: usize = 128;
const MAX_ASSOCIATION_COMPARISONS: usize = 1_000_000;
const MAX_NOTES: usize = 128;
const MAX_NOTE_CHARS: usize = 512;

static SETTINGS_WRITER: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Program {
    pub registration: InstalledProgram,
    pub candidates: Vec<StartupEntry>,
    pub association_note: String,
}

impl Program {
    /// Exact uninstall registration identity, including its registry view.
    /// The display name and other mutable metadata are deliberately excluded.
    pub fn key(&self) -> String {
        let hive = hive_code(self.registration.source.hive);
        let view = view_code(self.registration.source.view);
        let canonical_name = self.registration.identity.key_name.to_lowercase();
        format!(
            "program:v1:{hive}:{view}:{}",
            encode_hex(canonical_name.as_bytes())
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    pub programs: Vec<Program>,
    pub notes: Vec<String>,
    pub cancelled: bool,
    pub partial: bool,
}

/// Registered applications and read-only startup sources. Cancellation is
/// observed between native calls and during bounded association; it cannot
/// interrupt a call in flight.
pub fn scan(cancel: &AtomicBool) -> Result<Snapshot, String> {
    let mut manager = StartupManager::new(WindowsStartupPlatform::new());
    scan_with_inventory_sources(cancel, programs::installed_programs, |section| {
        manager.inventory(section)
    })
}

fn scan_with_inventory_sources<P, S>(
    cancel: &AtomicBool,
    read_programs: P,
    mut read_startup: S,
) -> Result<Snapshot, String>
where
    P: FnOnce() -> Result<programs::InventorySnapshot, String>,
    S: FnMut(StartupSection) -> StartupInventory,
{
    if cancel.load(Ordering::Relaxed) {
        return Ok(cancelled_snapshot(
            "Scan cancelled before inventory started.",
        ));
    }

    let inventory = read_programs()?;
    let mut startup = Vec::with_capacity(3);
    let mut cancelled = cancel.load(Ordering::Relaxed);

    if !cancelled {
        for section in [
            StartupSection::StartupApps,
            StartupSection::ScheduledTasks,
            StartupSection::WindowsServices,
        ] {
            if cancel.load(Ordering::Relaxed) {
                cancelled = true;
                break;
            }
            startup.push(read_startup(section));
            if cancel.load(Ordering::Relaxed) {
                cancelled = true;
                break;
            }
        }
    }

    let incomplete = startup.len() != 3;
    let mut snapshot = assemble_with_cancel(inventory, startup, cancelled || incomplete, cancel);
    if incomplete {
        snapshot.partial = true;
        add_note(
            &mut snapshot.notes,
            "Cancellation stopped the scan between native inventory calls; unqueried startup sources are omitted.",
        );
    }
    if cancel.load(Ordering::Relaxed) {
        mark_cancelled(&mut snapshot);
    }
    Ok(snapshot)
}

fn cancelled_snapshot(note: &str) -> Snapshot {
    Snapshot {
        notes: vec![note.to_owned()],
        cancelled: true,
        partial: true,
        ..Snapshot::default()
    }
}

fn observe_cancellation(cancel: Option<&AtomicBool>, snapshot: &mut Snapshot) -> bool {
    if cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed)) {
        mark_cancelled(snapshot);
        true
    } else {
        false
    }
}

fn mark_cancelled(snapshot: &mut Snapshot) {
    if !snapshot.cancelled {
        add_note(
            &mut snapshot.notes,
            "Cancellation was observed during bounded inventory processing; unprocessed data may be omitted.",
        );
    }
    snapshot.cancelled = true;
    snapshot.partial = true;
}

#[cfg(test)]
fn assemble(
    inventory: programs::InventorySnapshot,
    startup: Vec<StartupInventory>,
    cancelled: bool,
) -> Snapshot {
    assemble_inner(inventory, startup, cancelled, None)
}

fn assemble_with_cancel(
    inventory: programs::InventorySnapshot,
    startup: Vec<StartupInventory>,
    cancelled: bool,
    cancel: &AtomicBool,
) -> Snapshot {
    // If cancellation was already observed after a native call, finish processing
    // the captured, bounded data. Otherwise remain responsive during larger CPU work.
    let cancel_during_assembly = (!cancelled).then_some(cancel);
    assemble_inner(inventory, startup, cancelled, cancel_during_assembly)
}

fn assemble_inner(
    inventory: programs::InventorySnapshot,
    startup: Vec<StartupInventory>,
    cancelled: bool,
    cancel: Option<&AtomicBool>,
) -> Snapshot {
    let mut snapshot = Snapshot {
        cancelled,
        partial: cancelled,
        ..Snapshot::default()
    };
    if cancelled {
        add_note(
            &mut snapshot.notes,
            "Scan was cancelled between native inventory calls; returned results may be partial.",
        );
    }
    for error in inventory.errors {
        snapshot.partial = true;
        add_note(
            &mut snapshot.notes,
            &format!(
                "Installed-program source {} reported an incomplete read: {}",
                registry_source_label(error.source.hive, error.source.view),
                error.message
            ),
        );
    }

    let mut program_bytes = 0usize;
    let mut registrations = Vec::new();
    for registration in inventory.programs {
        if observe_cancellation(cancel, &mut snapshot) {
            break;
        }
        if registrations.len() >= MAX_PROGRAMS {
            snapshot.partial = true;
            add_note(
                &mut snapshot.notes,
                "Installed-program inventory exceeded the row bound; later registrations were omitted.",
            );
            break;
        }
        let Some(size) = program_record_bytes(&registration) else {
            snapshot.partial = true;
            add_note(
                &mut snapshot.notes,
                "An installed-program record exceeded a per-record field bound and was omitted.",
            );
            continue;
        };
        if size > MAX_PROGRAM_RECORD_BYTES || program_bytes.saturating_add(size) > MAX_PROGRAM_BYTES
        {
            snapshot.partial = true;
            add_note(
                &mut snapshot.notes,
                "Installed-program metadata exceeded the aggregate byte bound; later registrations were omitted.",
            );
            break;
        }
        program_bytes += size;
        registrations.push(Program {
            registration,
            candidates: Vec::new(),
            association_note: String::new(),
        });
    }

    let was_cancelled = snapshot.cancelled;
    let startup_entries = collect_startup_entries(startup, &mut snapshot, cancel);
    if was_cancelled || !snapshot.cancelled {
        associate(&mut registrations, startup_entries, &mut snapshot, cancel);
    } else {
        for program in &mut registrations {
            program.association_note =
                "Candidate association was omitted because the scan was cancelled.".into();
        }
    }
    snapshot.programs = registrations;
    snapshot
}

fn collect_startup_entries(
    inventories: Vec<StartupInventory>,
    snapshot: &mut Snapshot,
    cancel: Option<&AtomicBool>,
) -> Vec<StartupEntry> {
    let expected_sections = [
        StartupSection::StartupApps,
        StartupSection::ScheduledTasks,
        StartupSection::WindowsServices,
    ];
    let mut collected: Vec<Option<StartupEntry>> = Vec::new();
    let mut seen: HashMap<(StartupSection, String), usize> = HashMap::new();
    let mut duplicate_keys = HashSet::new();
    let mut total_bytes = 0usize;
    let mut total_seen = 0usize;

    'inventories: for inventory in inventories {
        if observe_cancellation(cancel, snapshot) {
            break;
        }
        if inventory.quality != InventoryQuality::Complete {
            snapshot.partial = true;
            add_note(
                &mut snapshot.notes,
                &format!(
                    "{} inventory quality is {:?}; missing or inaccessible entries may be omitted.",
                    inventory.section.label(),
                    inventory.quality
                ),
            );
        }
        if !expected_sections.contains(&inventory.section) {
            snapshot.partial = true;
            add_note(
                &mut snapshot.notes,
                "A startup inventory returned an unsupported section; its entries were omitted.",
            );
            continue;
        }
        for source in &inventory.sources {
            if observe_cancellation(cancel, snapshot) {
                break 'inventories;
            }
            match &source.state {
                SourceState::Read { .. } => {}
                SourceState::NotPresent => add_note(
                    &mut snapshot.notes,
                    &format!(
                        "{} source {} is not present.",
                        inventory.section.label(),
                        source.source
                    ),
                ),
                SourceState::Inaccessible { reason } | SourceState::Failed { reason } => {
                    snapshot.partial = true;
                    add_note(
                        &mut snapshot.notes,
                        &format!(
                            "{} source {} could not be read: {reason}",
                            inventory.section.label(),
                            source.source
                        ),
                    );
                }
                SourceState::Truncated { limit, reason } => {
                    snapshot.partial = true;
                    add_note(
                        &mut snapshot.notes,
                        &format!(
                            "{} source {} was truncated at {limit} items: {reason}",
                            inventory.section.label(),
                            source.source
                        ),
                    );
                }
            }
        }
        if inventory.entries.len() > MAX_ITEMS_PER_SOURCE {
            snapshot.partial = true;
            add_note(
                &mut snapshot.notes,
                &format!(
                    "{} startup entries exceeded the per-source bound; excess entries were omitted.",
                    inventory.section.label()
                ),
            );
        }
        for entry in inventory.entries.into_iter().take(MAX_ITEMS_PER_SOURCE) {
            if observe_cancellation(cancel, snapshot) {
                break 'inventories;
            }
            total_seen = total_seen.saturating_add(1);
            if total_seen > MAX_STARTUP_ITEMS {
                snapshot.partial = true;
                add_note(
                    &mut snapshot.notes,
                    "Startup inventory exceeded the aggregate item bound; later entries were omitted.",
                );
                break;
            }
            if entry.section != inventory.section {
                snapshot.partial = true;
                add_note(
                    &mut snapshot.notes,
                    "A startup entry's section disagreed with its source and was omitted.",
                );
                continue;
            }
            if entry.id.0.len() > MAX_ID_BYTES {
                snapshot.partial = true;
                add_note(
                    &mut snapshot.notes,
                    "A startup entry identity exceeded the byte bound and was omitted.",
                );
                continue;
            }
            let Some(size) = startup_entry_bytes(&entry) else {
                snapshot.partial = true;
                add_note(
                    &mut snapshot.notes,
                    "A startup entry exceeded a per-record byte bound and was omitted.",
                );
                continue;
            };
            if size > MAX_STARTUP_RECORD_BYTES
                || total_bytes.saturating_add(size) > MAX_STARTUP_BYTES
            {
                snapshot.partial = true;
                add_note(
                    &mut snapshot.notes,
                    "Startup entry data exceeded its aggregate byte bound; later entries were omitted.",
                );
                break;
            }
            total_bytes += size;

            let key = (entry.section, entry.id.0.clone());
            if duplicate_keys.contains(&key) {
                continue;
            }
            if let Some(index) = seen.get(&key).copied() {
                let prior = collected[index].take();
                let same = prior.as_ref() == Some(&entry);
                duplicate_keys.insert(key);
                snapshot.partial = true;
                add_note(
                    &mut snapshot.notes,
                    if same {
                        "A duplicate startup identity was omitted from candidate association."
                    } else {
                        "Conflicting startup records shared an identity; all copies were omitted from candidate association."
                    },
                );
            } else {
                seen.insert(key, collected.len());
                collected.push(Some(entry));
            }
        }
    }
    collected.into_iter().flatten().collect()
}

fn associate(
    programs: &mut [Program],
    entries: Vec<StartupEntry>,
    snapshot: &mut Snapshot,
    cancel: Option<&AtomicBool>,
) {
    let mut key_counts: HashMap<String, usize> = HashMap::new();
    let mut keys = Vec::with_capacity(programs.len());
    for program in programs.iter() {
        if observe_cancellation(cancel, snapshot) {
            break;
        }
        let key = program.key();
        *key_counts.entry(key.clone()).or_default() += 1;
        keys.push(key);
    }

    let mut roots = Vec::new();
    let mut root_notes: Vec<Vec<&'static str>> = vec![Vec::new(); programs.len()];
    for (index, program) in programs.iter().enumerate() {
        if observe_cancellation(cancel, snapshot) {
            break;
        }
        if key_counts.get(&keys[index]).copied().unwrap_or_default() != 1 {
            root_notes[index].push("Duplicate registration identity; candidate links omitted.");
            snapshot.partial = true;
            continue;
        }
        if program.registration.identity.hive != program.registration.source.hive {
            root_notes[index]
                .push("Registration hive and source hive disagree; candidate links omitted.");
            snapshot.partial = true;
            continue;
        }
        let Some(install_location) = program.registration.install_location.as_deref() else {
            root_notes[index].push("No registered install location; candidate links omitted.");
            continue;
        };
        match parse_windows_path(install_location) {
            Ok(root) => roots.push((index, root)),
            Err(reason) => root_notes[index].push(reason),
        }
    }

    let mut comparisons = 0usize;
    let mut invalid_path_count = 0usize;
    let mut unassociated_count = 0usize;
    for entry in entries {
        if observe_cancellation(cancel, snapshot) {
            break;
        }
        let path = match &entry.file_path {
            FieldValue::Known { value } => match parse_windows_path(Path::new(value)) {
                Ok(path) => path,
                Err(_) => {
                    invalid_path_count = invalid_path_count.saturating_add(1);
                    continue;
                }
            },
            _ => {
                invalid_path_count = invalid_path_count.saturating_add(1);
                continue;
            }
        };
        if roots.len() > MAX_ASSOCIATION_COMPARISONS.saturating_sub(comparisons) {
            snapshot.partial = true;
            add_note(
                &mut snapshot.notes,
                "Candidate association reached its comparison bound; remaining startup entries were left unlinked.",
            );
            break;
        }
        let mut matches = Vec::new();
        for (root_index, (index, root)) in roots.iter().enumerate() {
            if root_index % 256 == 0 && observe_cancellation(cancel, snapshot) {
                break;
            }
            if is_proper_descendant(root, &path) {
                matches.push(*index);
            }
        }
        if snapshot.cancelled && cancel.is_some_and(|cancel| cancel.load(Ordering::Relaxed)) {
            break;
        }
        comparisons += roots.len();
        match matches.as_slice() {
            [index] => programs[*index].candidates.push(entry),
            [] => unassociated_count = unassociated_count.saturating_add(1),
            _ => {
                snapshot.partial = true;
                for index in matches {
                    root_notes[index].push("A startup path is contained by multiple registered roots; that candidate was omitted.");
                }
            }
        }
    }

    if invalid_path_count > 0 {
        snapshot.partial = true;
        add_note(
            &mut snapshot.notes,
            &format!(
                "{invalid_path_count} startup entries had no safe absolute executable path; name and publisher were not used as substitutes."
            ),
        );
    }
    if unassociated_count > 0 {
        add_note(
            &mut snapshot.notes,
            &format!(
                "{unassociated_count} startup paths had no unique registered install-root match."
            ),
        );
    }

    for (index, program) in programs.iter_mut().enumerate() {
        if program.candidates.is_empty() && root_notes[index].is_empty() {
            root_notes[index]
                .push("No unique startup path was contained by this registered install root.");
        }
        if !program.candidates.is_empty() {
            root_notes[index].push("Links are lexical suggestions only; executable identity, symlinks, shared-root ownership, and runtime state are unverified.");
        }
        program.association_note = root_notes[index].join(" ");
        if program.key().len() > MAX_REGISTRATION_NAME_BYTES * 2 + 64 {
            program
                .association_note
                .push_str(" This identity exceeds the saved-exclusion key bound.");
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsPath(Vec<String>);

fn parse_windows_path(path: &Path) -> Result<WindowsPath, &'static str> {
    let text = path
        .to_str()
        .ok_or("Install or startup path is not valid Unicode; association omitted.")?;
    if text.is_empty() || text.len() > MAX_PATH_BYTES || text.trim() != text || text.contains('\0')
    {
        return Err(
            "Install or startup path is empty, overlong, or contains invalid whitespace; association omitted.",
        );
    }
    let normalized = text.replace('/', "\\");
    let lower = normalized.to_ascii_lowercase();
    if lower.starts_with("\\\\?\\")
        || lower.starts_with("\\\\.\\")
        || lower.starts_with("\\??\\")
        || lower.starts_with("\\\\??\\")
        || normalized.starts_with("\\\\")
    {
        return Err("UNC or device paths are not associated.");
    }
    let bytes = normalized.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err("Relative or non-drive-absolute paths are not associated.");
    }
    if normalized[2..].contains(':') {
        return Err("Alternate data stream or malformed drive syntax is not associated.");
    }
    let mut tail = &normalized[3..];
    if let Some(without_final_separator) = tail.strip_suffix('\\') {
        tail = without_final_separator;
    }
    let mut components: Vec<String> = Vec::new();
    for component in tail.split('\\') {
        if component.is_empty() {
            return Err("Repeated separators are not associated.");
        }
        if component == "." || component == ".." {
            return Err("Dot-segment paths are not associated.");
        }
        if component.ends_with(['.', ' '])
            || component
                .chars()
                .any(|character| matches!(character, '<' | '>' | '"' | '|' | '?' | '*'))
            || is_reserved_device_name(component)
        {
            return Err("Invalid or reserved Windows path components are not associated.");
        }
        components.push(component.to_owned());
    }
    if components.is_empty() {
        return Err("A drive root is too broad to be an installation root or candidate.");
    }
    let mut result = vec![format!("{}:", (bytes[0] as char).to_ascii_uppercase())];
    result.extend(components);
    Ok(WindowsPath(result))
}

fn is_reserved_device_name(component: &str) -> bool {
    let base = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ["COM", "LPT"].iter().any(|prefix| {
            base.strip_prefix(*prefix).is_some_and(|suffix| {
                suffix.len() == 1 && (b'1'..=b'9').contains(&suffix.as_bytes()[0])
            })
        })
}

fn is_proper_descendant(root: &WindowsPath, candidate: &WindowsPath) -> bool {
    candidate.0.len() > root.0.len()
        && root
            .0
            .iter()
            .zip(&candidate.0)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn program_record_bytes(program: &InstalledProgram) -> Option<usize> {
    let mut total = program
        .identity
        .key_name
        .len()
        .saturating_add(program.display_name.len());
    for value in [
        program.display_icon.as_deref(),
        program.publisher.as_deref(),
        program.version.as_deref(),
        program.install_date.as_deref(),
        program.registered_uninstall_command.as_deref(),
        program.uninstall_command_error.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        total = total.checked_add(value.len())?;
    }
    if let Some(path) = &program.install_location {
        total = total.checked_add(path.to_str()?.len())?;
    }
    if let Some(command) = &program.uninstall_command {
        total = total.checked_add(command.registered.len())?;
        total = total.checked_add(command.executable.len())?;
        if command.arguments.len() > 512 {
            return None;
        }
        for argument in &command.arguments {
            total = total.checked_add(argument.len())?;
            if total > MAX_PROGRAM_RECORD_BYTES {
                return None;
            }
        }
    }
    (total <= MAX_PROGRAM_RECORD_BYTES).then_some(total)
}

fn startup_entry_bytes(entry: &StartupEntry) -> Option<usize> {
    let mut total = entry.id.0.len();
    for field in [
        &entry.program,
        &entry.publisher,
        &entry.version,
        &entry.file_path,
        &entry.command,
    ] {
        let size = match field {
            FieldValue::Known { value } | FieldValue::Unknown { reason: value } => value.len(),
            FieldValue::NotApplicable => 0,
        };
        total = total.checked_add(size)?;
    }
    total = total.checked_add(entry.change_limitation.as_deref().map_or(0, str::len))?;
    let identity_bytes = match &entry.identity {
        crate::startup::EntryIdentity::StartupRunValue {
            key,
            value_name,
            approval_key,
            ..
        } => key.len() + value_name.len() + approval_key.len(),
        crate::startup::EntryIdentity::StartupFolderItem { path }
        | crate::startup::EntryIdentity::ScheduledTask { path } => path.len(),
        crate::startup::EntryIdentity::ContextMenuRegistration {
            key, registration, ..
        } => key.len() + registration.len(),
        crate::startup::EntryIdentity::WindowsService { name } => name.len(),
    };
    total = total.checked_add(identity_bytes)?;
    (total <= MAX_STARTUP_RECORD_BYTES).then_some(total)
}

fn add_note(notes: &mut Vec<String>, note: &str) {
    if notes.len() >= MAX_NOTES {
        if notes.last().is_some_and(|last| {
            last == "Additional inventory notes were omitted by the note bound."
        }) {
            return;
        }
        if let Some(last) = notes.last_mut() {
            *last = "Additional inventory notes were omitted by the note bound.".into();
        }
        return;
    }
    notes.push(note.chars().take(MAX_NOTE_CHARS).collect());
}

fn registry_source_label(hive: RegistryHive, view: RegistryView) -> &'static str {
    match (hive, view) {
        (RegistryHive::CurrentUser, RegistryView::Registry32) => "HKCU 32-bit uninstall registry",
        (RegistryHive::CurrentUser, RegistryView::Registry64) => "HKCU 64-bit uninstall registry",
        (RegistryHive::LocalMachine, RegistryView::Registry32) => "HKLM 32-bit uninstall registry",
        (RegistryHive::LocalMachine, RegistryView::Registry64) => "HKLM 64-bit uninstall registry",
    }
}

fn hive_code(hive: RegistryHive) -> &'static str {
    match hive {
        RegistryHive::CurrentUser => "hkcu",
        RegistryHive::LocalMachine => "hklm",
    }
}

fn view_code(view: RegistryView) -> &'static str {
    match view {
        RegistryView::Registry32 => "32",
        RegistryView::Registry64 => "64",
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || value.len() % 2 != 0
        || value.len() > MAX_REGISTRATION_NAME_BYTES * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        bytes.push(high << 4 | low);
    }
    Some(bytes)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn validate_key(key: &str) -> Result<(), String> {
    if key.len() > MAX_REGISTRATION_NAME_BYTES * 2 + 64 {
        return Err("The installed-program identity exceeds the saved-exclusion bound.".into());
    }
    let mut parts = key.splitn(5, ':');
    if parts.next() != Some("program") || parts.next() != Some("v1") {
        return Err("The saved exclusion is not a supported installed-program identity.".into());
    }
    if !matches!(parts.next(), Some("hkcu" | "hklm")) || !matches!(parts.next(), Some("32" | "64"))
    {
        return Err("The saved exclusion has an invalid registry hive or view.".into());
    }
    let encoded = parts
        .next()
        .ok_or_else(|| "The saved exclusion has no registration identity.".to_owned())?;
    if parts.next().is_some() {
        return Err("The saved exclusion contains extra identity fields.".into());
    }
    let name =
        String::from_utf8(decode_hex(encoded).ok_or_else(|| {
            "The saved exclusion has an invalid registration encoding.".to_owned()
        })?)
        .map_err(|_| "The saved exclusion registration is not UTF-8.".to_owned())?;
    if name.trim().is_empty()
        || name.len() > MAX_REGISTRATION_NAME_BYTES
        || name.to_lowercase() != name
        || name.contains(['\\', '/', '\0'])
        || name == "."
        || name == ".."
    {
        return Err("The saved exclusion has an invalid registry subkey identity.".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Settings {
    schema: u32,
    excluded_program_keys: BTreeSet<String>,
    /// Exact bytes read from disk. `None` represents an absent settings file.
    /// This provenance is process-local and is not serialized.
    disk_snapshot: Option<Arc<[u8]>>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            schema: SETTINGS_SCHEMA,
            excluded_program_keys: BTreeSet::new(),
            disk_snapshot: None,
        }
    }
}

impl Settings {
    pub fn is_excluded(&self, key: &str) -> bool {
        self.excluded_program_keys.contains(key)
    }

    pub fn excluded_keys(&self) -> impl Iterator<Item = &str> {
        self.excluded_program_keys.iter().map(String::as_str)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != SETTINGS_SCHEMA || self.excluded_program_keys.len() > MAX_EXCLUDED_KEYS {
            return Err(
                "Unsupported optimizer inventory settings schema or exclusion count.".into(),
            );
        }
        for key in &self.excluded_program_keys {
            validate_key(key)?;
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskSettings {
    schema: u32,
    excluded_program_keys: Vec<String>,
}

impl From<&Settings> for DiskSettings {
    fn from(settings: &Settings) -> Self {
        Self {
            schema: settings.schema,
            excluded_program_keys: settings.excluded_program_keys.iter().cloned().collect(),
        }
    }
}

pub fn load_settings(root: &Path) -> Result<Settings, String> {
    validate_root(root)?;
    let path = root.join(SETTINGS_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Settings::default());
        }
        Err(error) => {
            return Err(format!(
                "Optimizer settings could not be inspected: {error}"
            ));
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_SETTINGS_BYTES as u64
    {
        return Err("Optimizer settings are linked, not a regular file, or exceed the safe size limit; original bytes were preserved.".into());
    }
    let file = open_settings_data(&path)
        .map_err(|error| format!("Optimizer settings could not be opened: {error}"))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| format!("Optimizer settings could not be verified: {error}"))?;
    if opened_metadata.file_type().is_symlink()
        || !opened_metadata.is_file()
        || opened_metadata.len() > MAX_SETTINGS_BYTES as u64
    {
        return Err("Optimizer settings changed to a linked, non-regular, or oversized file; original bytes were preserved.".into());
    }
    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    file.take(MAX_SETTINGS_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Optimizer settings could not be read: {error}"))?;
    if bytes.len() > MAX_SETTINGS_BYTES {
        return Err(
            "Optimizer settings exceed the safe size limit; original bytes were preserved.".into(),
        );
    }
    let disk: DiskSettings = serde_json::from_slice(&bytes).map_err(|error| {
        format!("Optimizer settings could not be decoded; original bytes were preserved: {error}")
    })?;
    if disk.schema != SETTINGS_SCHEMA || disk.excluded_program_keys.len() > MAX_EXCLUDED_KEYS {
        return Err("Unsupported optimizer settings schema or exclusion count; original bytes were preserved.".into());
    }
    let mut excluded_program_keys = BTreeSet::new();
    for key in disk.excluded_program_keys {
        validate_key(&key)?;
        if !excluded_program_keys.insert(key) {
            return Err("Duplicate optimizer exclusion identities were found; original bytes were preserved.".into());
        }
    }
    Ok(Settings {
        schema: disk.schema,
        excluded_program_keys,
        disk_snapshot: Some(Arc::from(bytes)),
    })
}

/// Persist only an app-local exclusion preference; this never changes a service,
/// startup registration, process, or native optimizer component.
pub fn save_exclusion(
    root: &Path,
    expected: &Settings,
    key: &str,
    excluded: bool,
) -> Result<Settings, String> {
    validate_root(root)?;
    validate_key(key)?;
    expected.validate()?;
    let writer = SETTINGS_WRITER.get_or_init(|| Mutex::new(()));
    let _guard = writer.lock().map_err(|_| {
        "Optimizer settings writer lock was poisoned; settings were preserved.".to_owned()
    })?;

    fs::create_dir_all(root)
        .map_err(|error| format!("Optimizer settings directory could not be created: {error}"))?;
    let _file_lock = acquire_settings_file_lock(root)?;
    let current = load_settings(root)?;
    if !same_precondition(&current, expected) {
        return Err("Optimizer settings changed or disappeared since they were loaded; reload before saving.".into());
    }

    let mut updated = current.clone();
    if excluded {
        updated.excluded_program_keys.insert(key.to_owned());
    } else {
        updated.excluded_program_keys.remove(key);
    }
    updated.validate()?;
    if updated.excluded_program_keys == current.excluded_program_keys {
        return Ok(current);
    }

    let bytes = serde_json::to_vec_pretty(&DiskSettings::from(&updated))
        .map_err(|error| format!("Optimizer settings could not be encoded: {error}"))?;
    if bytes.len() > MAX_SETTINGS_BYTES {
        return Err(
            "Optimizer settings exceed the safe size limit; previous settings remain.".into(),
        );
    }
    let destination = root.join(SETTINGS_FILE);
    if let Ok(metadata) = fs::symlink_metadata(&destination) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("The existing optimizer settings path is linked or not a regular file; it was preserved.".into());
        }
    }
    let temporary = root.join(format!(
        "optimizer-inventory-settings.{}.tmp",
        Uuid::new_v4()
    ));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| {
                format!("Temporary optimizer settings file could not be created: {error}")
            })?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| {
                format!("Temporary optimizer settings file could not be synced: {error}")
            })?;
        drop(file);
        fs::rename(&temporary, &destination).map_err(|error| {
            format!("Optimizer settings could not be atomically replaced: {error}")
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    updated.disk_snapshot = Some(Arc::from(bytes));
    Ok(updated)
}

fn same_precondition(current: &Settings, expected: &Settings) -> bool {
    current.schema == expected.schema
        && current.excluded_program_keys == expected.excluded_program_keys
        && match (&current.disk_snapshot, &expected.disk_snapshot) {
            (None, None) => true,
            (Some(current), Some(expected)) => current.as_ref() == expected.as_ref(),
            _ => false,
        }
}

fn acquire_settings_file_lock(root: &Path) -> Result<File, String> {
    let path = root.join(SETTINGS_LOCK_FILE);
    let mut attempts = 0;
    let file = loop {
        attempts += 1;
        if attempts > 3 {
            return Err(
                "Optimizer settings lock path kept changing; settings were preserved.".into(),
            );
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err("The optimizer settings lock is linked or not a regular file; settings were preserved.".into());
                }
                break open_settings_lock(&path).map_err(|error| {
                    format!("Optimizer settings lock could not be opened: {error}")
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    Ok(file) => break file,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(format!(
                            "Optimizer settings lock could not be created: {error}"
                        ));
                    }
                }
            }
            Err(error) => {
                return Err(format!(
                    "Optimizer settings lock could not be inspected: {error}"
                ));
            }
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("Optimizer settings lock could not be verified: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(
            "The optimizer settings lock is linked or not a regular file; settings were preserved."
                .into(),
        );
    }
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => {
            "Optimizer settings are being changed by another writer; reload before saving.".into()
        }
        std::fs::TryLockError::Error(error) => {
            format!("Optimizer settings lock could not be acquired: {error}")
        }
    })?;
    Ok(file)
}

#[cfg(windows)]
fn open_settings_lock(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(windows)]
fn open_settings_data(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
fn open_settings_data(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(not(windows))]
fn open_settings_lock(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().read(true).write(true).open(path)
}

fn validate_root(root: &Path) -> Result<(), String> {
    if root.is_absolute() {
        Ok(())
    } else {
        Err("The optimizer settings directory must be absolute.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        programs::{InstalledProgram, ProgramIdentity, RegistrySource},
        startup::{EnabledState, EntryIdentity, SourceOutcome, StartupId},
    };
    use std::{path::PathBuf, process::Command, sync::atomic::AtomicBool};
    use tempfile::tempdir;

    fn registration(
        hive: RegistryHive,
        view: RegistryView,
        name: &str,
        install_location: Option<&str>,
    ) -> InstalledProgram {
        InstalledProgram {
            identity: ProgramIdentity {
                hive,
                key_name: name.to_lowercase(),
            },
            source: RegistrySource { hive, view },
            display_name: "Same display name".into(),
            display_icon: None,
            publisher: Some("Untrusted metadata".into()),
            version: None,
            install_location: install_location.map(PathBuf::from),
            install_date: None,
            estimated_size_bytes: None,
            registered_uninstall_command: None,
            uninstall_command: None,
            uninstall_command_error: None,
            system_component: false,
            protected: false,
            no_remove: false,
        }
    }

    fn program(registration: InstalledProgram) -> Program {
        Program {
            registration,
            candidates: Vec::new(),
            association_note: String::new(),
        }
    }

    fn startup_entry(path: FieldValue<String>, id: &str) -> StartupEntry {
        StartupEntry {
            id: StartupId(id.into()),
            section: StartupSection::StartupApps,
            program: FieldValue::Known {
                value: "Same display name".into(),
            },
            publisher: FieldValue::Known {
                value: "Untrusted metadata".into(),
            },
            version: FieldValue::NotApplicable,
            file_path: path,
            command: FieldValue::Unknown {
                reason: "not used for association".into(),
            },
            enabled: EnabledState::Unknown {
                reason: "not classified".into(),
            },
            identity: EntryIdentity::StartupFolderItem {
                path: format!(r"C:\Startup\{id}.lnk"),
            },
            can_change_enabled: false,
            change_limitation: Some("inventory-only".into()),
        }
    }

    fn startup_inventory(section: StartupSection, entries: Vec<StartupEntry>) -> StartupInventory {
        StartupInventory {
            section,
            quality: InventoryQuality::Complete,
            entries,
            sources: Vec::new(),
        }
    }

    fn program_inventory(programs: Vec<InstalledProgram>) -> programs::InventorySnapshot {
        programs::InventorySnapshot {
            programs,
            errors: Vec::new(),
        }
    }

    #[test]
    fn scan_composition_observes_cancellation_from_last_source() {
        let cancel = AtomicBool::new(false);
        let mut calls = Vec::new();
        let result = scan_with_inventory_sources(
            &cancel,
            || {
                Ok(program_inventory(vec![registration(
                    RegistryHive::CurrentUser,
                    RegistryView::Registry64,
                    "app",
                    None,
                )]))
            },
            |section| {
                calls.push(section);
                if section == StartupSection::WindowsServices {
                    cancel.store(true, Ordering::Relaxed);
                }
                startup_inventory(section, Vec::new())
            },
        )
        .unwrap();

        assert_eq!(
            calls,
            [
                StartupSection::StartupApps,
                StartupSection::ScheduledTasks,
                StartupSection::WindowsServices,
            ]
        );
        assert!(result.cancelled);
        assert!(result.partial);
        assert_eq!(result.programs.len(), 1);
    }

    #[test]
    fn scan_composition_stops_after_cancellation_inside_a_source() {
        let cancel = AtomicBool::new(false);
        let mut calls = Vec::new();
        let result = scan_with_inventory_sources(
            &cancel,
            || Ok(program_inventory(Vec::new())),
            |section| {
                calls.push(section);
                if section == StartupSection::ScheduledTasks {
                    cancel.store(true, Ordering::Relaxed);
                }
                startup_inventory(section, Vec::new())
            },
        )
        .unwrap();

        assert_eq!(
            calls,
            [StartupSection::StartupApps, StartupSection::ScheduledTasks]
        );
        assert!(result.cancelled);
        assert!(result.partial);
        assert!(
            result
                .notes
                .iter()
                .any(|note| note.contains("unqueried startup sources"))
        );
    }

    #[test]
    fn startup_source_quality_and_failures_are_visible() {
        let mut inventory = startup_inventory(
            StartupSection::StartupApps,
            vec![startup_entry(
                FieldValue::Known {
                    value: r"C:\Apps\Tool\tool.exe".into(),
                },
                "readable",
            )],
        );
        inventory.quality = InventoryQuality::Partial;
        inventory.sources = vec![
            SourceOutcome {
                source: "startup folder".into(),
                state: SourceState::Read { items: 1 },
            },
            SourceOutcome {
                source: "registry run key".into(),
                state: SourceState::NotPresent,
            },
            SourceOutcome {
                source: "task store".into(),
                state: SourceState::Inaccessible {
                    reason: "access denied".into(),
                },
            },
            SourceOutcome {
                source: "service store".into(),
                state: SourceState::Truncated {
                    limit: 10,
                    reason: "fixture bound".into(),
                },
            },
        ];
        let mut snapshot = Snapshot::default();
        let entries = collect_startup_entries(vec![inventory], &mut snapshot, None);

        assert_eq!(entries.len(), 1);
        assert!(snapshot.partial);
        assert!(
            snapshot
                .notes
                .iter()
                .any(|note| note.contains("quality is Partial"))
        );
        assert!(
            snapshot
                .notes
                .iter()
                .any(|note| note.contains("not present"))
        );
        assert!(
            snapshot
                .notes
                .iter()
                .any(|note| note.contains("could not be read: access denied"))
        );
        assert!(
            snapshot
                .notes
                .iter()
                .any(|note| note.contains("was truncated at 10 items"))
        );
    }

    #[test]
    fn startup_duplicate_conflicting_and_malformed_entries_are_omitted() {
        let identical = startup_entry(
            FieldValue::Known {
                value: r"C:\Apps\Tool\tool.exe".into(),
            },
            "same-id",
        );
        let mut conflict_a = startup_entry(
            FieldValue::Known {
                value: r"C:\Apps\Tool\a.exe".into(),
            },
            "conflict-id",
        );
        let conflict_b = startup_entry(
            FieldValue::Known {
                value: r"C:\Apps\Tool\b.exe".into(),
            },
            "conflict-id",
        );
        conflict_a.section = StartupSection::StartupApps;
        let mut wrong_section = startup_entry(
            FieldValue::Known {
                value: r"C:\Apps\Tool\wrong.exe".into(),
            },
            "wrong-section",
        );
        wrong_section.section = StartupSection::ScheduledTasks;
        let long_id = "x".repeat(MAX_ID_BYTES + 1);
        let malformed = startup_entry(
            FieldValue::Known {
                value: r"C:\Apps\Tool\long.exe".into(),
            },
            &long_id,
        );
        let inventory = startup_inventory(
            StartupSection::StartupApps,
            vec![
                identical.clone(),
                identical,
                conflict_a,
                conflict_b,
                wrong_section,
                malformed,
            ],
        );
        let mut snapshot = Snapshot::default();
        let entries = collect_startup_entries(vec![inventory], &mut snapshot, None);

        assert!(entries.is_empty());
        assert!(snapshot.partial);
        assert!(
            snapshot
                .notes
                .iter()
                .any(|note| note.contains("duplicate startup identity"))
        );
        assert!(
            snapshot
                .notes
                .iter()
                .any(|note| note.contains("Conflicting startup records"))
        );
        assert!(
            snapshot
                .notes
                .iter()
                .any(|note| note.contains("section disagreed"))
        );
        assert!(
            snapshot
                .notes
                .iter()
                .any(|note| note.contains("identity exceeded the byte bound"))
        );
    }

    #[test]
    fn registration_key_uses_hive_view_and_registration_not_display_name() {
        let first = program(registration(
            RegistryHive::CurrentUser,
            RegistryView::Registry32,
            "Vendor.App",
            None,
        ));
        let other_hive = program(registration(
            RegistryHive::LocalMachine,
            RegistryView::Registry32,
            "Vendor.App",
            None,
        ));
        let other_view = program(registration(
            RegistryHive::CurrentUser,
            RegistryView::Registry64,
            "Vendor.App",
            None,
        ));
        let other_registration = program(registration(
            RegistryHive::CurrentUser,
            RegistryView::Registry32,
            "Vendor.Other",
            None,
        ));
        assert_ne!(first.key(), other_hive.key());
        assert_ne!(first.key(), other_view.key());
        assert_ne!(first.key(), other_registration.key());
        let mixed_case = program(registration(
            RegistryHive::CurrentUser,
            RegistryView::Registry32,
            "VENDOR.APP",
            None,
        ));
        assert_eq!(first.key(), mixed_case.key());
    }

    #[test]
    fn path_association_respects_component_boundaries_and_ambiguity() {
        let mut rows = vec![
            program(registration(
                RegistryHive::CurrentUser,
                RegistryView::Registry64,
                "one",
                Some(r"C:\Apps\Tool"),
            )),
            program(registration(
                RegistryHive::LocalMachine,
                RegistryView::Registry64,
                "two",
                Some(r"C:\Apps\Tool\Shared"),
            )),
        ];
        let entries = vec![
            startup_entry(
                FieldValue::Known {
                    value: r"C:\Apps\Tool\tool.exe".into(),
                },
                "inside",
            ),
            startup_entry(
                FieldValue::Known {
                    value: r"C:\Apps\Toolbox\tool.exe".into(),
                },
                "boundary",
            ),
            startup_entry(
                FieldValue::Known {
                    value: r"C:\Apps\Tool\Shared\helper.exe".into(),
                },
                "shared",
            ),
        ];
        let mut snapshot = Snapshot::default();
        associate(&mut rows, entries, &mut snapshot, None);
        assert_eq!(
            rows[0]
                .candidates
                .iter()
                .map(|entry| entry.id.0.as_str())
                .collect::<Vec<_>>(),
            ["inside"]
        );
        assert!(rows[1].candidates.is_empty());
        assert!(
            rows[1]
                .association_note
                .contains("multiple registered roots")
        );
        assert!(
            snapshot
                .notes
                .iter()
                .any(|note| note.contains("no unique registered install-root match"))
        );
    }

    #[test]
    fn invalid_relative_unc_device_and_dot_paths_never_associate() {
        let invalid = [
            r"relative\app.exe",
            r"C:\Apps\Tool\..\Other\app.exe",
            r"\\server\share\Tool\app.exe",
            r"\\?\C:\Apps\Tool\app.exe",
            r"\??\C:\Apps\Tool\app.exe",
            r"C:\Apps\\nested\",
        ];
        for (index, path) in invalid.into_iter().enumerate() {
            let mut rows = vec![program(registration(
                RegistryHive::CurrentUser,
                RegistryView::Registry64,
                "tool",
                Some(r"C:\Apps\Tool"),
            ))];
            let entries = vec![startup_entry(
                FieldValue::Known { value: path.into() },
                &format!("invalid-{index}"),
            )];
            let mut snapshot = Snapshot::default();
            associate(&mut rows, entries, &mut snapshot, None);
            assert!(
                rows[0].candidates.is_empty(),
                "associated invalid path {path}"
            );
            assert!(snapshot.partial);
        }
    }

    #[test]
    fn duplicate_program_identity_makes_candidate_ambiguous() {
        let registration = registration(
            RegistryHive::CurrentUser,
            RegistryView::Registry64,
            "same",
            Some(r"C:\Apps\Tool"),
        );
        let mut rows = vec![program(registration.clone()), program(registration)];
        let entries = vec![startup_entry(
            FieldValue::Known {
                value: r"C:\Apps\Tool\tool.exe".into(),
            },
            "candidate",
        )];
        let mut snapshot = Snapshot::default();
        associate(&mut rows, entries, &mut snapshot, None);
        assert!(rows.iter().all(|row| row.candidates.is_empty()));
        assert!(rows.iter().all(|row| {
            row.association_note
                .contains("Duplicate registration identity")
        }));
    }

    #[test]
    fn aggregate_program_limit_is_explicit_and_bounded() {
        let rows = (0..=MAX_PROGRAMS)
            .map(|index| {
                registration(
                    RegistryHive::CurrentUser,
                    RegistryView::Registry64,
                    &format!("app-{index}"),
                    None,
                )
            })
            .collect();
        let snapshot = assemble(program_inventory(rows), Vec::new(), false);
        assert_eq!(snapshot.programs.len(), MAX_PROGRAMS);
        assert!(snapshot.partial);
        assert!(snapshot.notes.iter().any(|note| note.contains("row bound")));
    }

    #[test]
    fn cancelled_scan_returns_without_starting_native_inventory() {
        let cancel = AtomicBool::new(true);
        let snapshot = scan(&cancel).unwrap();
        assert!(snapshot.cancelled);
        assert!(snapshot.partial);
        assert!(snapshot.programs.is_empty());
    }

    #[test]
    fn exclusion_round_trips_durably_and_keeps_history_after_uninstall() {
        let directory = tempdir().unwrap();
        let key = program(registration(
            RegistryHive::LocalMachine,
            RegistryView::Registry64,
            "vendor.app",
            None,
        ))
        .key();
        let empty = load_settings(directory.path()).unwrap();
        let saved = save_exclusion(directory.path(), &empty, &key, true).unwrap();
        assert!(saved.is_excluded(&key));
        let reopened = load_settings(directory.path()).unwrap();
        assert!(reopened.is_excluded(&key));
        assert_eq!(reopened.excluded_keys().collect::<Vec<_>>(), [key.as_str()]);
        let removed = save_exclusion(directory.path(), &reopened, &key, false).unwrap();
        assert!(!removed.is_excluded(&key));
    }

    #[test]
    fn stale_or_disappeared_settings_are_rejected() {
        let directory = tempdir().unwrap();
        let key = program(registration(
            RegistryHive::CurrentUser,
            RegistryView::Registry64,
            "app",
            None,
        ))
        .key();
        let stale = load_settings(directory.path()).unwrap();
        let first = save_exclusion(directory.path(), &stale, &key, true).unwrap();
        assert!(save_exclusion(directory.path(), &stale, &key, false).is_err());
        fs::remove_file(directory.path().join(SETTINGS_FILE)).unwrap();
        assert!(save_exclusion(directory.path(), &first, &key, false).is_err());
    }

    #[test]
    fn cooperating_writer_lock_preserves_settings_while_another_writer_holds_it() {
        let directory = tempdir().unwrap();
        let key = program(registration(
            RegistryHive::CurrentUser,
            RegistryView::Registry64,
            "app",
            None,
        ))
        .key();
        let lock_path = directory.path().join(SETTINGS_LOCK_FILE);
        let held_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(lock_path)
            .unwrap();
        held_lock.try_lock().unwrap();

        let mut command = Command::new(std::env::current_exe().unwrap());
        command.arg("settings_writer_lock_child_helper").env(
            "DCLEANER_OPTIMIZER_SETTINGS_LOCK_TEST_ROOT",
            directory.path(),
        );
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "lock child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!directory.path().join(SETTINGS_FILE).exists());

        drop(held_lock);
        let expected = load_settings(directory.path()).unwrap();
        let saved = save_exclusion(directory.path(), &expected, &key, true).unwrap();
        assert!(saved.is_excluded(&key));
    }

    #[test]
    fn settings_writer_lock_child_helper() {
        let Ok(root) = std::env::var("DCLEANER_OPTIMIZER_SETTINGS_LOCK_TEST_ROOT") else {
            return;
        };
        let result = acquire_settings_file_lock(Path::new(&root));
        assert!(
            result
                .err()
                .is_some_and(|error| error.contains("another writer")),
            "a second process acquired an already-held settings lock"
        );
    }

    #[test]
    fn corrupt_future_unknown_and_duplicate_settings_are_preserved() {
        let directory = tempdir().unwrap();
        let key = program(registration(
            RegistryHive::CurrentUser,
            RegistryView::Registry64,
            "app",
            None,
        ))
        .key();
        for bytes in [
            br"{".as_slice(),
            br#"{"schema":2,"excluded_program_keys":[]}"#,
            br#"{"schema":1,"excluded_program_keys":[],"foreign":true}"#,
            br#"{"schema":1,"excluded_program_keys":["program:v1:hkcu:64:617070","program:v1:hkcu:64:617070"]}"#,
        ] {
            let path = directory.path().join(SETTINGS_FILE);
            fs::write(&path, bytes).unwrap();
            let before = fs::read(&path).unwrap();
            assert!(save_exclusion(directory.path(), &Settings::default(), &key, true).is_err());
            assert_eq!(fs::read(path).unwrap(), before);
        }
    }

    #[test]
    fn settings_reject_noncanonical_identity_and_count_overflow() {
        let directory = tempdir().unwrap();
        let invalid = r#"{"schema":1,"excluded_program_keys":["program:v1:hkcu:64:2e2e"]}"#;
        fs::write(directory.path().join(SETTINGS_FILE), invalid).unwrap();
        assert!(load_settings(directory.path()).is_err());
        let too_many = DiskSettings {
            schema: SETTINGS_SCHEMA,
            excluded_program_keys: (0..=MAX_EXCLUDED_KEYS)
                .map(|index| {
                    format!(
                        "program:v1:hkcu:64:{}",
                        encode_hex(format!("app-{index}").as_bytes())
                    )
                })
                .collect(),
        };
        fs::write(
            directory.path().join(SETTINGS_FILE),
            serde_json::to_vec(&too_many).unwrap(),
        )
        .unwrap();
        assert!(load_settings(directory.path()).is_err());
    }
}
