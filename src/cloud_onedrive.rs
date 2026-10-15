//! Bounded, read-only OneDrive metadata inventory.
//!
//! A scan covers one existing drive exposed by Microsoft Graph. Drive choices
//! come from `/me/drives`; the adapter does not call `/me/drive`, which can
//! provision a licensed but unprovisioned drive. Folder sizes are omitted
//! because Graph's folder size can aggregate descendants, while this inventory
//! model does not represent that distinction. External `remoteItem` targets
//! are never followed; their presence marks the page incomplete.

use crate::{
    cloud_http::{
        AccessToken, CloudHttpError, GRAPH_FIELDS, MAX_RESPONSE_BYTES, MetadataHttp, ReadEndpoint,
        validate_cursor,
    },
    cloud_inventory::{
        AccountScope, ContentHash, HashAlgorithm, IncompletePageReason, PageCompleteness,
        PageCursor, Provider, ProviderFailure, ProviderTimestamp, ProviderTimestampBasis,
        RemoteItemDraft, RemoteItemKind, RemotePage, RemotePort, SizeAccuracy, SizeObservation,
        TrashStatus, UnknownFieldReason,
    },
};
use reqwest::Url;
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use uuid::Uuid;

const PAGE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PAGE_ITEMS: usize = 1_000;
const MAX_SCAN_IDS: usize = 50_000;
const MAX_VISITED_PAGES: usize = 50_000;
const MAX_RETAINED_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_NAME_BYTES: usize = 4_096;
const MAX_NEXT_LINK_BYTES: usize = 8 * 1024;
const MAX_DRIVES_PER_PAGE: usize = 100;
const MAX_DRIVE_CHOICES: usize = 1_000;
const MAX_DRIVE_PAGES: usize = 100;
const ID_STATE_OVERHEAD: usize = 128;
const QUEUE_STATE_OVERHEAD: usize = 32;
const TOKEN_STATE_OVERHEAD: usize = 32;
const DRIVE_FIELDS: &str = "id,driveType,name,owner";

/// Construct an adapter from a token already granted by its authorization
/// owner. Construction creates a bounded HTTPS client but makes no request.
pub struct OneDriveClient(OneDriveAdapter<NativeTransport>);

impl OneDriveClient {
    pub fn new(token: AccessToken) -> Result<Self, CloudHttpError> {
        Self::new_with_drive(token, None)
    }

    /// Construct a client bound to a drive selected from `drive_choices`.
    /// Passing `None` preserves the single-existing-drive default and returns
    /// a selection-required failure during scope discovery when several drives
    /// exist. Construction performs no Graph request.
    pub fn new_with_drive(
        token: AccessToken,
        selected_drive: Option<String>,
    ) -> Result<Self, CloudHttpError> {
        if selected_drive
            .as_deref()
            .is_some_and(|value| !valid_identifier(value))
        {
            return Err(CloudHttpError::InvalidIdentifier);
        }
        Ok(Self(OneDriveAdapter {
            transport: NativeTransport(MetadataHttp::new(token)?),
            selected_drive,
            pending: None,
        }))
    }

    /// List bounded, existing drive choices for the signed-in account.
    pub fn drive_choices(
        &mut self,
        cancel: &AtomicBool,
    ) -> Result<Vec<DriveChoice>, ProviderFailure> {
        self.0.drive_choices(cancel)
    }
}

/// A selectable, already-existing Microsoft Graph drive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriveChoice {
    id: String,
    name: String,
    drive_type: Option<String>,
}

impl DriveChoice {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn drive_type(&self) -> Option<&str> {
        self.drive_type.as_deref()
    }
}

impl RemotePort for OneDriveClient {
    fn current_scope(&mut self, cancel: &AtomicBool) -> Result<AccountScope, ProviderFailure> {
        self.0.current_scope(cancel)
    }

    fn list_page(
        &mut self,
        expected_scope: &AccountScope,
        cursor: Option<&PageCursor>,
        cancel: &AtomicBool,
    ) -> Result<RemotePage, ProviderFailure> {
        self.0.list_page(expected_scope, cursor, cancel)
    }
}

trait GraphTransport {
    fn read(
        &mut self,
        endpoint: ReadEndpoint<'_>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<Vec<u8>, CloudHttpError>;
}

struct NativeTransport(MetadataHttp);

impl GraphTransport for NativeTransport {
    fn read(
        &mut self,
        endpoint: ReadEndpoint<'_>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<Vec<u8>, CloudHttpError> {
        self.0.read(endpoint, cancel, deadline)
    }
}

struct OneDriveAdapter<T> {
    transport: T,
    selected_drive: Option<String>,
    pending: Option<WalkState>,
}

struct WalkState {
    scope: AccountScope,
    drive_id: String,
    expected_cursor: Option<String>,
    queue: VecDeque<FolderRef>,
    active: Option<FolderRef>,
    skip_token: Option<String>,
    seen_page_tokens: HashSet<String>,
    seen_items: HashMap<String, bool>,
    visited_pages: usize,
    retained_bytes: usize,
}

enum FolderRef {
    Root,
    Item(String),
}

impl FolderRef {
    fn id(&self) -> Option<&str> {
        match self {
            Self::Root => None,
            Self::Item(id) => Some(id),
        }
    }

    fn retained_bytes(&self) -> usize {
        match self {
            Self::Root => 0,
            Self::Item(id) => id.len().saturating_add(QUEUE_STATE_OVERHEAD),
        }
    }
}

impl WalkState {
    fn new(scope: AccountScope) -> Result<Self, ProviderFailure> {
        let drive_id = scope
            .storage_id()
            .filter(|value| valid_identifier(value))
            .ok_or(ProviderFailure::MalformedResponse)?
            .to_owned();
        let mut queue = VecDeque::new();
        queue.push_back(FolderRef::Root);
        Ok(Self {
            scope,
            drive_id,
            expected_cursor: None,
            queue,
            active: None,
            skip_token: None,
            seen_page_tokens: HashSet::new(),
            seen_items: HashMap::new(),
            visited_pages: 0,
            retained_bytes: 0,
        })
    }

    fn reserve(&mut self, additional: usize) -> Result<(), ProviderFailure> {
        if self
            .retained_bytes
            .checked_add(additional)
            .map_or(true, |bytes| bytes > MAX_RETAINED_STATE_BYTES)
        {
            return Err(ProviderFailure::ResponseLimit);
        }
        self.retained_bytes += additional;
        Ok(())
    }

    fn track_item(&mut self, id: &str) -> Result<(), ProviderFailure> {
        if self.seen_items.contains_key(id) {
            return Err(ProviderFailure::MalformedResponse);
        }
        if self.seen_items.len() >= MAX_SCAN_IDS {
            return Err(ProviderFailure::ResponseLimit);
        }
        self.reserve(id.len().saturating_add(ID_STATE_OVERHEAD))?;
        self.seen_items.insert(id.to_owned(), false);
        Ok(())
    }

    fn queue_folder(&mut self, id: &str) -> Result<(), ProviderFailure> {
        let queued = self
            .seen_items
            .get(id)
            .ok_or(ProviderFailure::MalformedResponse)?;
        if *queued {
            return Ok(());
        }
        self.reserve(id.len().saturating_add(QUEUE_STATE_OVERHEAD))?;
        *self
            .seen_items
            .get_mut(id)
            .ok_or(ProviderFailure::MalformedResponse)? = true;
        self.queue.push_back(FolderRef::Item(id.to_owned()));
        Ok(())
    }

    fn add_page_token(&mut self, token: &str) -> Result<(), ProviderFailure> {
        if !self.seen_page_tokens.insert(token.to_owned()) {
            return Err(ProviderFailure::MalformedResponse);
        }
        if let Err(error) = self.reserve(token.len().saturating_add(TOKEN_STATE_OVERHEAD)) {
            self.seen_page_tokens.remove(token);
            return Err(error);
        }
        Ok(())
    }

    fn set_skip_token(&mut self, token: String) -> Result<(), ProviderFailure> {
        self.reserve(token.len().saturating_add(TOKEN_STATE_OVERHEAD))?;
        self.skip_token = Some(token);
        Ok(())
    }

    fn take_skip_token(&mut self) -> Option<String> {
        let token = self.skip_token.take()?;
        self.retained_bytes = self
            .retained_bytes
            .saturating_sub(token.len().saturating_add(TOKEN_STATE_OVERHEAD));
        Some(token)
    }

    fn clear_page_tokens(&mut self) {
        for token in self.seen_page_tokens.drain() {
            self.retained_bytes = self
                .retained_bytes
                .saturating_sub(token.len().saturating_add(TOKEN_STATE_OVERHEAD));
        }
    }

    fn clear_expected_cursor(&mut self) {
        if let Some(cursor) = self.expected_cursor.take() {
            self.retained_bytes = self
                .retained_bytes
                .saturating_sub(cursor.len().saturating_add(TOKEN_STATE_OVERHEAD));
        }
    }

    fn has_more(&self) -> bool {
        self.active.is_some() || !self.queue.is_empty()
    }
}

impl<T: GraphTransport> OneDriveAdapter<T> {
    fn read_user_until(
        &mut self,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<WireUser, ProviderFailure> {
        check_cancel(cancel)?;
        check_deadline(deadline)?;
        let bytes = self
            .transport
            .read(ReadEndpoint::GraphMe, cancel, deadline)
            .map_err(provider_error)?;
        check_cancel(cancel)?;
        check_deadline(deadline)?;
        check_body(&bytes)?;
        let user: WireUser =
            serde_json::from_slice(&bytes).map_err(|_| ProviderFailure::MalformedResponse)?;
        if !valid_identifier(&user.id) {
            return Err(ProviderFailure::MalformedResponse);
        }
        Ok(user)
    }

    fn read_drives_page_until(
        &mut self,
        cursor: Option<&str>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<WireDrivesPage, ProviderFailure> {
        check_cancel(cancel)?;
        check_deadline(deadline)?;
        let bytes = self
            .transport
            .read(ReadEndpoint::GraphDrives { cursor }, cancel, deadline)
            .map_err(provider_error)?;
        check_cancel(cancel)?;
        check_deadline(deadline)?;
        check_body(&bytes)?;
        serde_json::from_slice(&bytes).map_err(|_| ProviderFailure::MalformedResponse)
    }

    fn drive_choices_until(
        &mut self,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<Vec<DriveChoice>, ProviderFailure> {
        let mut choices = Vec::new();
        let mut seen_ids = HashSet::new();
        let mut seen_tokens = HashSet::new();
        let mut cursor = None;

        for _ in 0..MAX_DRIVE_PAGES {
            let page = self.read_drives_page_until(cursor.as_deref(), cancel, deadline)?;
            for drive in page.value {
                let choice = drive_choice(drive)?;
                if !seen_ids.insert(choice.id.clone()) {
                    return Err(ProviderFailure::MalformedResponse);
                }
                if choices.len() >= MAX_DRIVE_CHOICES {
                    return Err(ProviderFailure::ResponseLimit);
                }
                choices.push(choice);
            }
            match page.next_link.as_deref() {
                Some(next_link) => {
                    let token = extract_drives_skip_token(next_link)?;
                    if !seen_tokens.insert(token.clone()) {
                        return Err(ProviderFailure::MalformedResponse);
                    }
                    cursor = Some(token);
                }
                None => return Ok(choices),
            }
        }
        Err(ProviderFailure::ResponseLimit)
    }

    fn drive_exists_until(
        &mut self,
        selected_drive: &str,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<bool, ProviderFailure> {
        let mut seen_ids = HashSet::new();
        let mut seen_tokens = HashSet::new();
        let mut cursor = None;
        let mut count = 0usize;

        for _ in 0..MAX_DRIVE_PAGES {
            let page = self.read_drives_page_until(cursor.as_deref(), cancel, deadline)?;
            for drive in page.value {
                let choice = drive_choice(drive)?;
                if !seen_ids.insert(choice.id.clone()) {
                    return Err(ProviderFailure::MalformedResponse);
                }
                count += 1;
                if count > MAX_DRIVE_CHOICES {
                    return Err(ProviderFailure::ResponseLimit);
                }
                if choice.id == selected_drive {
                    return Ok(true);
                }
            }
            match page.next_link.as_deref() {
                Some(next_link) => {
                    let token = extract_drives_skip_token(next_link)?;
                    if !seen_tokens.insert(token.clone()) {
                        return Err(ProviderFailure::MalformedResponse);
                    }
                    cursor = Some(token);
                }
                None => return Ok(false),
            }
        }
        Err(ProviderFailure::ResponseLimit)
    }

    fn drive_choices(&mut self, cancel: &AtomicBool) -> Result<Vec<DriveChoice>, ProviderFailure> {
        let deadline = Instant::now() + PAGE_TIMEOUT;
        let _user = self.read_user_until(cancel, deadline)?;
        self.drive_choices_until(cancel, deadline)
    }

    fn scope_until(
        &mut self,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<AccountScope, ProviderFailure> {
        let user = self.read_user_until(cancel, deadline)?;
        let drive_id = match self.selected_drive.clone() {
            Some(selected) => {
                if !self.drive_exists_until(&selected, cancel, deadline)? {
                    return Err(ProviderFailure::Unavailable);
                }
                selected
            }
            None => {
                let mut choices = self.drive_choices_until(cancel, deadline)?;
                match choices.len() {
                    0 => return Err(ProviderFailure::Unavailable),
                    1 => {
                        let choice = choices.pop().ok_or(ProviderFailure::MalformedResponse)?;
                        self.selected_drive = Some(choice.id.clone());
                        choice.id
                    }
                    _ => return Err(ProviderFailure::StorageSelectionRequired),
                }
            }
        };
        AccountScope::new(Provider::OneDrive, user.id, Some(drive_id))
            .map_err(|_| ProviderFailure::MalformedResponse)
    }

    fn current_scope(&mut self, cancel: &AtomicBool) -> Result<AccountScope, ProviderFailure> {
        self.scope_until(cancel, Instant::now() + PAGE_TIMEOUT)
    }

    fn validate_cursor_state(
        &self,
        expected_scope: &AccountScope,
        cursor: Option<&PageCursor>,
    ) -> Result<(), ProviderFailure> {
        if let Some(cursor) = cursor {
            if !cursor.belongs_to(expected_scope)
                || Uuid::parse_str(cursor.provider_value())
                    .map(|value| value.to_string() != cursor.provider_value())
                    .unwrap_or(true)
            {
                return Err(ProviderFailure::MalformedResponse);
            }
            let state = self
                .pending
                .as_ref()
                .ok_or(ProviderFailure::MalformedResponse)?;
            if state.scope != *expected_scope
                || state.expected_cursor.as_deref() != Some(cursor.provider_value())
            {
                return Err(ProviderFailure::MalformedResponse);
            }
        } else if self.pending.is_some() {
            return Err(ProviderFailure::MalformedResponse);
        }
        Ok(())
    }

    fn list_page(
        &mut self,
        expected_scope: &AccountScope,
        cursor: Option<&PageCursor>,
        cancel: &AtomicBool,
    ) -> Result<RemotePage, ProviderFailure> {
        if expected_scope.provider() != Provider::OneDrive || expected_scope.storage_id().is_none()
        {
            return Err(ProviderFailure::MalformedResponse);
        }
        self.validate_cursor_state(expected_scope, cursor)?;

        // One deadline covers both identity reads, the children request and
        // post-read scope validation. Continuation URLs are never fetched.
        let deadline = Instant::now() + PAGE_TIMEOUT;
        let observed_before = self.scope_until(cancel, deadline)?;
        if observed_before != *expected_scope {
            self.pending = None;
            return Err(ProviderFailure::AccountScopeMismatch);
        }

        let mut state = match cursor {
            Some(_) => {
                let mut state = self
                    .pending
                    .take()
                    .ok_or(ProviderFailure::MalformedResponse)?;
                state.clear_expected_cursor();
                state
            }
            None => WalkState::new(observed_before.clone())?,
        };
        if state.scope != observed_before || state.visited_pages >= MAX_VISITED_PAGES {
            return Err(if state.scope != observed_before {
                ProviderFailure::AccountScopeMismatch
            } else {
                ProviderFailure::ResponseLimit
            });
        }

        let folder = state
            .active
            .take()
            .or_else(|| state.queue.pop_front())
            .ok_or(ProviderFailure::MalformedResponse)?;
        let graph_cursor = state.take_skip_token();
        let bytes = self
            .transport
            .read(
                ReadEndpoint::GraphChildren {
                    drive_id: &state.drive_id,
                    folder_id: folder.id(),
                    cursor: graph_cursor.as_deref(),
                },
                cancel,
                deadline,
            )
            .map_err(provider_error)?;
        check_cancel(cancel)?;
        check_deadline(deadline)?;
        check_body(&bytes)?;
        let wire: WireChildrenPage =
            serde_json::from_slice(&bytes).map_err(|_| ProviderFailure::MalformedResponse)?;
        state.visited_pages += 1;

        let next_graph_cursor = wire
            .next_link
            .as_deref()
            .map(|url| extract_skip_token(url, &state.drive_id, folder.id()))
            .transpose()?;
        if let Some(token) = &next_graph_cursor {
            state.add_page_token(token)?;
        }

        let mut rows = Vec::with_capacity(wire.value.len());
        let mut omitted_coverage = false;
        for item in wire.value {
            check_cancel(cancel)?;
            check_deadline(deadline)?;
            if !valid_identifier(&item.id) || !valid_display_name(&item.name) {
                return Err(ProviderFailure::MalformedResponse);
            }
            let item_id = item.id.clone();
            if item
                .parent_reference
                .as_ref()
                .and_then(|parent| parent.drive_id.as_deref())
                .is_some_and(|parent_drive| parent_drive != state.drive_id)
            {
                return Err(ProviderFailure::MalformedResponse);
            }
            if item
                .remote_item
                .as_ref()
                .is_some_and(|value| !value.is_object())
                || item
                    .deleted
                    .as_ref()
                    .is_some_and(|value| !value.is_object())
            {
                return Err(ProviderFailure::MalformedResponse);
            }

            state.track_item(&item.id)?;
            let is_remote_item = item.remote_item.is_some();
            let decoded = decode_item(item)?;
            let Some((draft, is_folder)) = decoded else {
                // Unknown DriveItem facets (for example an unsupported
                // package-like object) cannot be represented by this model.
                omitted_coverage = true;
                continue;
            };
            if is_remote_item {
                // Keep only the local shortcut row. Its target and any target
                // descendants are outside this drive's traversal boundary.
                omitted_coverage = true;
            } else if is_folder {
                state.queue_folder(&item_id)?;
            }
            rows.push(draft);
        }

        check_cancel(cancel)?;
        check_deadline(deadline)?;
        let observed_after = self.scope_until(cancel, deadline)?;
        if observed_after != *expected_scope {
            return Err(ProviderFailure::AccountScopeMismatch);
        }

        if let Some(token) = next_graph_cursor {
            state.active = Some(folder);
            state.set_skip_token(token)?;
        } else {
            state.retained_bytes = state.retained_bytes.saturating_sub(folder.retained_bytes());
            state.clear_page_tokens();
        }

        let next_cursor = if state.has_more() {
            let value = Uuid::new_v4().to_string();
            state.reserve(value.len().saturating_add(TOKEN_STATE_OVERHEAD))?;
            state.expected_cursor = Some(value.clone());
            let cursor = PageCursor::new(expected_scope, value)
                .map_err(|_| ProviderFailure::MalformedResponse)?;
            self.pending = Some(state);
            Some(cursor)
        } else {
            self.pending = None;
            None
        };

        let mut page = RemotePage::new(observed_after, rows, next_cursor);
        if omitted_coverage {
            page = page.with_completeness(PageCompleteness::Incomplete(
                IncompletePageReason::ProviderTruncatedResults,
            ));
        }
        Ok(page)
    }
}

impl<T: GraphTransport> RemotePort for OneDriveAdapter<T> {
    fn current_scope(&mut self, cancel: &AtomicBool) -> Result<AccountScope, ProviderFailure> {
        OneDriveAdapter::current_scope(self, cancel)
    }

    fn list_page(
        &mut self,
        expected_scope: &AccountScope,
        cursor: Option<&PageCursor>,
        cancel: &AtomicBool,
    ) -> Result<RemotePage, ProviderFailure> {
        OneDriveAdapter::list_page(self, expected_scope, cursor, cancel)
    }
}

#[derive(Deserialize)]
struct WireUser {
    id: String,
}

#[derive(Deserialize)]
struct WireDrivesPage {
    #[serde(deserialize_with = "decode_drives")]
    value: Vec<WireDrive>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireDrive {
    id: String,
    name: String,
    drive_type: Option<String>,
}

#[derive(Deserialize)]
struct WireChildrenPage {
    #[serde(deserialize_with = "decode_items")]
    value: Vec<WireDriveItem>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireDriveItem {
    id: String,
    name: String,
    size: Option<u64>,
    e_tag: Option<String>,
    c_tag: Option<String>,
    file: Option<WireFileFacet>,
    folder: Option<serde_json::Value>,
    parent_reference: Option<WireParentReference>,
    deleted: Option<serde_json::Value>,
    remote_item: Option<serde_json::Value>,
    last_modified_date_time: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireParentReference {
    drive_id: Option<String>,
}

#[derive(Deserialize)]
struct WireFileFacet {
    hashes: Option<WireHashes>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireHashes {
    quick_xor_hash: Option<String>,
}

fn decode_items<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<WireDriveItem>, D::Error> {
    struct Items;
    impl<'de> Visitor<'de> for Items {
        type Value = Vec<WireDriveItem>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("at most 1000 OneDrive child items")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut rows = Vec::new();
            for _ in 0..MAX_PAGE_ITEMS {
                match seq.next_element()? {
                    Some(row) => rows.push(row),
                    None => return Ok(rows),
                }
            }
            if seq.next_element::<de::IgnoredAny>()?.is_some() {
                return Err(de::Error::custom("OneDrive page item bound exceeded"));
            }
            Ok(rows)
        }
    }
    decoder.deserialize_seq(Items)
}

fn decode_drives<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<WireDrive>, D::Error> {
    struct Drives;
    impl<'de> Visitor<'de> for Drives {
        type Value = Vec<WireDrive>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("at most 100 OneDrive drives")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut rows = Vec::new();
            for _ in 0..MAX_DRIVES_PER_PAGE {
                match seq.next_element()? {
                    Some(row) => rows.push(row),
                    None => return Ok(rows),
                }
            }
            if seq.next_element::<de::IgnoredAny>()?.is_some() {
                return Err(de::Error::custom("OneDrive drive page bound exceeded"));
            }
            Ok(rows)
        }
    }
    decoder.deserialize_seq(Drives)
}

fn drive_choice(drive: WireDrive) -> Result<DriveChoice, ProviderFailure> {
    if !valid_identifier(&drive.id)
        || !valid_display_name(&drive.name)
        || drive
            .drive_type
            .as_deref()
            .is_some_and(|value| !valid_revision(value))
    {
        return Err(ProviderFailure::MalformedResponse);
    }
    Ok(DriveChoice {
        id: drive.id,
        name: drive.name,
        drive_type: drive.drive_type,
    })
}

fn decode_item(item: WireDriveItem) -> Result<Option<(RemoteItemDraft, bool)>, ProviderFailure> {
    if item
        .folder
        .as_ref()
        .is_some_and(|folder| !folder.is_object())
    {
        return Err(ProviderFailure::MalformedResponse);
    }

    let remote_item = item.remote_item.is_some();
    let local_is_folder = item.folder.is_some();
    let local_is_file = item.file.is_some();
    if local_is_folder && local_is_file {
        return Err(ProviderFailure::MalformedResponse);
    }
    let remote_kind = item
        .remote_item
        .as_ref()
        .map(remote_item_kind)
        .transpose()?;
    let is_folder = match (local_is_folder, local_is_file, remote_kind) {
        (true, false, _) => true,
        (false, true, _) => false,
        (false, false, Some(Some(kind))) => kind,
        (false, false, _) => return Ok(None),
        (true, true, _) => return Err(ProviderFailure::MalformedResponse),
    };
    let trash_status = if item.deleted.is_some() {
        TrashStatus::Trashed
    } else {
        TrashStatus::Unknown(UnknownFieldReason::NotProvided)
    };
    let timestamp = item
        .last_modified_date_time
        .as_deref()
        .map(|value| {
            let timestamp = chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| ProviderFailure::MalformedResponse)?;
            ProviderTimestamp::new(
                timestamp.timestamp_millis(),
                ProviderTimestampBasis::Modified,
            )
            .map_err(|_| ProviderFailure::MalformedResponse)
        })
        .transpose()?;
    let revision = item.c_tag.or(item.e_tag);
    if revision
        .as_ref()
        .is_some_and(|value| !valid_revision(value))
    {
        return Err(ProviderFailure::MalformedResponse);
    }

    // Graph can expose an aggregate size on a folder. The current inventory
    // model cannot distinguish that from item content size, so omit it.
    let (size, hash) = if is_folder || remote_item {
        (None, None)
    } else {
        let size = item
            .size
            .map(|bytes| {
                (bytes <= i64::MAX as u64)
                    .then_some(SizeObservation::new(
                        bytes,
                        SizeAccuracy::ProviderReportedExact,
                    ))
                    .ok_or(ProviderFailure::MalformedResponse)
            })
            .transpose()?;
        let hash = item
            .file
            .and_then(|file| file.hashes)
            .and_then(|hashes| hashes.quick_xor_hash)
            .map(|value| {
                if !valid_base64_shape(&value) {
                    return Err(ProviderFailure::MalformedResponse);
                }
                ContentHash::new(
                    Provider::OneDrive,
                    HashAlgorithm::ProviderNative("quickXorHash".to_owned()),
                    value,
                )
                .map_err(|_| ProviderFailure::MalformedResponse)
            })
            .transpose()?;
        (size, hash)
    };

    Ok(Some((
        RemoteItemDraft::new(
            item.id,
            item.name,
            if is_folder {
                RemoteItemKind::Folder
            } else {
                RemoteItemKind::File
            },
        )
        .with_provider_revision(revision)
        .with_provider_timestamp(timestamp)
        .with_size(size)
        .with_content_hash(hash)
        .with_trash_status(trash_status),
        is_folder,
    )))
}

fn remote_item_kind(value: &serde_json::Value) -> Result<Option<bool>, ProviderFailure> {
    let object = value
        .as_object()
        .ok_or(ProviderFailure::MalformedResponse)?;
    let is_folder = object.get("folder").is_some_and(|facet| !facet.is_null());
    let is_file = object.get("file").is_some_and(|facet| !facet.is_null());
    if is_folder && is_file {
        return Err(ProviderFailure::MalformedResponse);
    }
    if is_folder {
        if !object
            .get("folder")
            .is_some_and(serde_json::Value::is_object)
        {
            return Err(ProviderFailure::MalformedResponse);
        }
        Ok(Some(true))
    } else if is_file {
        if !object.get("file").is_some_and(serde_json::Value::is_object) {
            return Err(ProviderFailure::MalformedResponse);
        }
        Ok(Some(false))
    } else {
        Ok(None)
    }
}

fn extract_skip_token(
    next_link: &str,
    drive_id: &str,
    folder_id: Option<&str>,
) -> Result<String, ProviderFailure> {
    if next_link.len() > MAX_NEXT_LINK_BYTES {
        return Err(ProviderFailure::MalformedResponse);
    }
    let url = Url::parse(next_link).map_err(|_| ProviderFailure::MalformedResponse)?;
    let expected = crate::cloud_http::read_url(&ReadEndpoint::GraphChildren {
        drive_id,
        folder_id,
        cursor: None,
    })
    .map_err(provider_error)?;
    if url.scheme() != "https"
        || url.host_str() != Some("graph.microsoft.com")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || has_user_info(&url)
        || url.fragment().is_some()
        || url.path() != expected.path()
    {
        return Err(ProviderFailure::MalformedResponse);
    }

    let mut skip_token = None;
    let mut saw_top = false;
    let mut saw_select = false;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "$skiptoken" if skip_token.is_none() => {
                validate_cursor(&value).map_err(provider_error)?;
                skip_token = Some(value.into_owned());
            }
            "$top" if !saw_top && value == "200" => saw_top = true,
            "$select" if !saw_select && value == GRAPH_FIELDS => saw_select = true,
            _ => return Err(ProviderFailure::MalformedResponse),
        }
    }
    skip_token.ok_or(ProviderFailure::MalformedResponse)
}

fn extract_drives_skip_token(next_link: &str) -> Result<String, ProviderFailure> {
    if next_link.len() > MAX_NEXT_LINK_BYTES {
        return Err(ProviderFailure::MalformedResponse);
    }
    let url = Url::parse(next_link).map_err(|_| ProviderFailure::MalformedResponse)?;
    let expected = crate::cloud_http::read_url(&ReadEndpoint::GraphDrives { cursor: None })
        .map_err(provider_error)?;
    if url.scheme() != "https"
        || url.host_str() != Some("graph.microsoft.com")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || has_user_info(&url)
        || url.fragment().is_some()
        || url.path() != expected.path()
    {
        return Err(ProviderFailure::MalformedResponse);
    }

    let mut skip_token = None;
    let mut saw_top = false;
    let mut saw_select = false;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "$skiptoken" if skip_token.is_none() => {
                validate_cursor(&value).map_err(provider_error)?;
                skip_token = Some(value.into_owned());
            }
            "$top" if !saw_top && value == "100" => saw_top = true,
            "$select" if !saw_select && value == DRIVE_FIELDS => saw_select = true,
            _ => return Err(ProviderFailure::MalformedResponse),
        }
    }
    skip_token.ok_or(ProviderFailure::MalformedResponse)
}

fn has_user_info(url: &Url) -> bool {
    url.as_str()
        .split_once("://")
        .and_then(|(_, remainder)| {
            remainder
                .split(|character| matches!(character, '/' | '?' | '#'))
                .next()
        })
        .map_or(true, |authority| authority.contains('@'))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value != "."
        && value != ".."
        && !value.chars().any(char::is_control)
}

fn valid_display_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_NAME_BYTES && !value.chars().any(char::is_control)
}

fn valid_revision(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES && !value.chars().any(char::is_control)
}

fn valid_base64_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return false;
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return false;
    }
    let data_len = bytes.len() - padding;
    if !bytes[..data_len]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/')
    {
        return false;
    }
    if bytes[data_len..].iter().any(|byte| *byte != b'=') {
        return false;
    }
    let final_sextet = bytes
        .get(data_len.saturating_sub(1))
        .and_then(|byte| base64_sextet(*byte));
    match padding {
        0 => data_len % 4 == 0,
        1 => data_len % 4 == 3 && final_sextet.is_some_and(|value| value & 0b11 == 0),
        2 => data_len % 4 == 2 && final_sextet.is_some_and(|value| value & 0b1111 == 0),
        _ => false,
    }
}

fn base64_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn check_cancel(cancel: &AtomicBool) -> Result<(), ProviderFailure> {
    if cancel.load(Ordering::Relaxed) {
        Err(ProviderFailure::Cancelled)
    } else {
        Ok(())
    }
}

fn check_deadline(deadline: Instant) -> Result<(), ProviderFailure> {
    if Instant::now() >= deadline {
        Err(ProviderFailure::TimedOut)
    } else {
        Ok(())
    }
}

fn check_body(bytes: &[u8]) -> Result<(), ProviderFailure> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        Err(ProviderFailure::ResponseLimit)
    } else {
        Ok(())
    }
}

fn provider_error(error: CloudHttpError) -> ProviderFailure {
    match error {
        CloudHttpError::Cancelled => ProviderFailure::Cancelled,
        CloudHttpError::TimedOut => ProviderFailure::TimedOut,
        CloudHttpError::ResponseLimit => ProviderFailure::ResponseLimit,
        CloudHttpError::ClientUnavailable => ProviderFailure::ClientUnavailable,
        CloudHttpError::Transport => ProviderFailure::Transport,
        CloudHttpError::HttpStatus(401) => ProviderFailure::AuthenticationRequired,
        CloudHttpError::HttpStatus(403) => ProviderFailure::PermissionDenied,
        CloudHttpError::HttpStatus(429) => ProviderFailure::RateLimited,
        CloudHttpError::HttpStatus(500..=599) => ProviderFailure::TemporarilyUnavailable,
        CloudHttpError::HttpStatus(_) => ProviderFailure::Other,
        CloudHttpError::InvalidToken
        | CloudHttpError::InvalidCursor
        | CloudHttpError::InvalidIdentifier
        | CloudHttpError::InvalidResponse => ProviderFailure::MalformedResponse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud_inventory::{InventoryIssueKind, SnapshotStatus, scan};
    use std::collections::VecDeque;

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ExpectedRead {
        Me,
        Drives {
            cursor: Option<String>,
        },
        Children {
            drive_id: String,
            folder_id: Option<String>,
            cursor: Option<String>,
        },
    }

    struct FakeTransport {
        replies: VecDeque<(ExpectedRead, Result<Vec<u8>, CloudHttpError>)>,
        calls: Vec<ExpectedRead>,
    }

    impl GraphTransport for FakeTransport {
        fn read(
            &mut self,
            endpoint: ReadEndpoint<'_>,
            cancel: &AtomicBool,
            deadline: Instant,
        ) -> Result<Vec<u8>, CloudHttpError> {
            if cancel.load(Ordering::Relaxed) {
                return Err(CloudHttpError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(CloudHttpError::TimedOut);
            }
            let actual = match endpoint {
                ReadEndpoint::GraphMe => ExpectedRead::Me,
                ReadEndpoint::GraphDrives { cursor } => ExpectedRead::Drives {
                    cursor: cursor.map(str::to_owned),
                },
                ReadEndpoint::GraphChildren {
                    drive_id,
                    folder_id,
                    cursor,
                } => ExpectedRead::Children {
                    drive_id: drive_id.to_owned(),
                    folder_id: folder_id.map(str::to_owned),
                    cursor: cursor.map(str::to_owned),
                },
                _ => return Err(CloudHttpError::InvalidIdentifier),
            };
            self.calls.push(actual.clone());
            let Some((expected, response)) = self.replies.pop_front() else {
                return Err(CloudHttpError::Transport);
            };
            if expected != actual {
                return Err(CloudHttpError::InvalidIdentifier);
            }
            response
        }
    }

    fn reply(
        expected: ExpectedRead,
        body: &str,
    ) -> (ExpectedRead, Result<Vec<u8>, CloudHttpError>) {
        (expected, Ok(body.as_bytes().to_vec()))
    }

    fn push_scope(replies: &mut VecDeque<(ExpectedRead, Result<Vec<u8>, CloudHttpError>)>) {
        replies.push_back(reply(ExpectedRead::Me, r#"{"id":"user-1"}"#));
        replies.push_back(reply(
            ExpectedRead::Drives { cursor: None },
            r#"{"value":[{"id":"drive-1","name":"Personal","driveType":"personal"}]}"#,
        ));
    }

    fn children(folder_id: Option<&str>, cursor: Option<&str>) -> ExpectedRead {
        ExpectedRead::Children {
            drive_id: "drive-1".to_owned(),
            folder_id: folder_id.map(str::to_owned),
            cursor: cursor.map(str::to_owned),
        }
    }

    fn push_scan_page(
        replies: &mut VecDeque<(ExpectedRead, Result<Vec<u8>, CloudHttpError>)>,
        folder_id: Option<&str>,
        cursor: Option<&str>,
        body: &str,
    ) {
        // scan's before/after identity reads plus the adapter's own bounded
        // before/after checks around the Graph children request.
        push_scope(replies);
        push_scope(replies);
        replies.push_back(reply(children(folder_id, cursor), body));
        push_scope(replies);
        push_scope(replies);
    }

    fn scope() -> AccountScope {
        AccountScope::new(Provider::OneDrive, "user-1", Some("drive-1".into())).unwrap()
    }

    fn next_link(folder_id: Option<&str>, token: &str) -> String {
        let mut url = crate::cloud_http::read_url(&ReadEndpoint::GraphChildren {
            drive_id: "drive-1",
            folder_id,
            cursor: None,
        })
        .unwrap();
        url.query_pairs_mut().append_pair("$skiptoken", token);
        url.to_string()
    }

    fn drives_next_link(token: &str) -> String {
        let mut url =
            crate::cloud_http::read_url(&ReadEndpoint::GraphDrives { cursor: None }).unwrap();
        url.query_pairs_mut().append_pair("$skiptoken", token);
        url.to_string()
    }

    fn replace_query_value(url: &str, key: &str, expected: &str, replacement: &str) -> String {
        let original = url;
        let mut url = Url::parse(original).unwrap();
        let mut replaced = false;
        let mut pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(name, value)| {
                let name = name.into_owned();
                let mut value = value.into_owned();
                if name == key {
                    assert_eq!(value, expected, "unexpected query value for {key}");
                    value = replacement.to_owned();
                    replaced = true;
                }
                (name, value)
            })
            .collect();
        assert!(replaced, "query parameter {key} should be present");

        url.set_query(None);
        for (name, value) in pairs.drain(..) {
            url.query_pairs_mut().append_pair(&name, &value);
        }
        let replaced_url = url.to_string();
        assert_ne!(replaced_url, original);
        replaced_url
    }

    fn make_adapter(
        replies: VecDeque<(ExpectedRead, Result<Vec<u8>, CloudHttpError>)>,
        selected_drive: Option<&str>,
    ) -> OneDriveAdapter<FakeTransport> {
        OneDriveAdapter {
            transport: FakeTransport {
                replies,
                calls: Vec::new(),
            },
            selected_drive: selected_drive.map(str::to_owned),
            pending: None,
        }
    }

    #[test]
    fn drive_choices_use_existing_drive_list_and_validated_paging() {
        let link = drives_next_link("drive+page");
        let mut replies = VecDeque::new();
        replies.push_back(reply(ExpectedRead::Me, r#"{"id":"user-1"}"#));
        replies.push_back(reply(
            ExpectedRead::Drives { cursor: None },
            &format!(
                r#"{{"value":[{{"id":"drive-1","name":"Personal","driveType":"personal"}}],"@odata.nextLink":{}}}"#,
                serde_json::to_string(&link).unwrap()
            ),
        ));
        replies.push_back(reply(
            ExpectedRead::Drives {
                cursor: Some("drive+page".to_owned()),
            },
            r#"{"value":[{"id":"drive-2","name":"Work","driveType":"business"}]}"#,
        ));

        let mut adapter = make_adapter(replies, None);
        let choices = adapter.drive_choices(&AtomicBool::new(false)).unwrap();
        assert_eq!(choices.len(), 2);
        assert_eq!(
            (choices[0].id(), choices[0].name()),
            ("drive-1", "Personal")
        );
        assert_eq!(choices[0].drive_type(), Some("personal"));
        assert_eq!((choices[1].id(), choices[1].name()), ("drive-2", "Work"));
        assert_eq!(
            adapter.transport.calls,
            vec![
                ExpectedRead::Me,
                ExpectedRead::Drives { cursor: None },
                ExpectedRead::Drives {
                    cursor: Some("drive+page".to_owned()),
                },
            ]
        );
    }

    #[test]
    fn default_selection_requires_exactly_one_existing_drive() {
        let link = drives_next_link("second-drive-page");
        let mut replies = VecDeque::new();
        replies.push_back(reply(ExpectedRead::Me, r#"{"id":"user-1"}"#));
        replies.push_back(reply(
            ExpectedRead::Drives { cursor: None },
            &format!(
                r#"{{"value":[{{"id":"drive-1","name":"Personal"}}],"@odata.nextLink":{}}}"#,
                serde_json::to_string(&link).unwrap()
            ),
        ));
        replies.push_back(reply(
            ExpectedRead::Drives {
                cursor: Some("second-drive-page".to_owned()),
            },
            r#"{"value":[{"id":"drive-2","name":"Work"}]}"#,
        ));
        let mut adapter = make_adapter(replies, None);
        assert_eq!(
            adapter.current_scope(&AtomicBool::new(false)),
            Err(ProviderFailure::StorageSelectionRequired)
        );
        assert_eq!(
            adapter.transport.calls,
            vec![
                ExpectedRead::Me,
                ExpectedRead::Drives { cursor: None },
                ExpectedRead::Drives {
                    cursor: Some("second-drive-page".to_owned()),
                },
            ]
        );

        let mut replies = VecDeque::new();
        replies.push_back(reply(ExpectedRead::Me, r#"{"id":"user-1"}"#));
        replies.push_back(reply(
            ExpectedRead::Drives { cursor: None },
            r#"{"value":[]}"#,
        ));
        let mut adapter = make_adapter(replies, None);
        assert_eq!(
            adapter.current_scope(&AtomicBool::new(false)),
            Err(ProviderFailure::Unavailable)
        );
    }

    #[test]
    fn selected_drive_is_checked_against_existing_drive_membership() {
        let link = drives_next_link("second-page");
        let mut replies = VecDeque::new();
        replies.push_back(reply(ExpectedRead::Me, r#"{"id":"user-1"}"#));
        replies.push_back(reply(
            ExpectedRead::Drives { cursor: None },
            &format!(
                r#"{{"value":[{{"id":"drive-1","name":"Personal"}}],"@odata.nextLink":{}}}"#,
                serde_json::to_string(&link).unwrap()
            ),
        ));
        replies.push_back(reply(
            ExpectedRead::Drives {
                cursor: Some("second-page".to_owned()),
            },
            r#"{"value":[{"id":"drive-2","name":"Work"}]}"#,
        ));
        let mut adapter = make_adapter(replies, Some("drive-2"));
        assert_eq!(
            adapter.current_scope(&AtomicBool::new(false)).unwrap(),
            AccountScope::new(Provider::OneDrive, "user-1", Some("drive-2".into())).unwrap()
        );
    }

    #[test]
    fn drive_next_link_is_reduced_to_one_validated_opaque_token() {
        let valid = drives_next_link("opaque+/token==");
        assert_eq!(
            extract_drives_skip_token(&valid).unwrap(),
            "opaque+/token=="
        );
        for invalid in [
            valid.replace("graph.microsoft.com", "attacker.example"),
            valid.replace("/v1.0/me/drives", "/v1.0/me/drive"),
            format!("{valid}&other=1"),
            format!("{valid}&$skiptoken=second"),
            replace_query_value(&valid, "$top", "100", "101"),
        ] {
            assert_eq!(
                extract_drives_skip_token(&invalid),
                Err(ProviderFailure::MalformedResponse)
            );
        }
    }

    #[test]
    fn paginates_fixed_graph_route_and_walks_local_folders() {
        let link = next_link(None, "next+token");
        let root_first = format!(
            r#"{{"value":[
              {{"id":"file-1","name":"first.txt","size":123,"eTag":"etag","cTag":"ctag","file":{{"hashes":{{"quickXorHash":"AAAAAAAAAAAAAAAAAAAAAAAAAAA="}}}},"lastModifiedDateTime":"2025-01-02T03:04:05Z","parentReference":{{"driveId":"drive-1"}}}},
              {{"id":"folder-1","name":"folder","size":999,"folder":{{"childCount":1}},"eTag":"folder-etag","parentReference":{{"driveId":"drive-1"}}}},
              {{"id":"shared-link","name":"shared","size":999,"folder":{{}},"remoteItem":{{"id":"outside-drive-item","folder":{{}}}},"parentReference":{{"driveId":"drive-1"}}}}
            ],"@odata.nextLink":{}}}"#,
            serde_json::to_string(&link).unwrap()
        );
        let mut replies = VecDeque::new();
        push_scan_page(&mut replies, None, None, &root_first);
        push_scan_page(&mut replies, None, Some("next+token"), r#"{"value":[]}"#);
        push_scan_page(
            &mut replies,
            Some("folder-1"),
            None,
            r#"{"value":[{"id":"nested-1","name":"nested.txt","size":42,"file":{},"parentReference":{"driveId":"drive-1"}}]}"#,
        );
        let mut adapter = OneDriveAdapter {
            transport: FakeTransport {
                replies,
                calls: Vec::new(),
            },
            selected_drive: None,
            pending: None,
        };

        let snapshot = scan(&mut adapter, &scope(), &AtomicBool::new(false));
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        assert!(snapshot.issues().iter().any(|issue| {
            issue.kind()
                == InventoryIssueKind::ProviderReportedIncomplete(
                    IncompletePageReason::ProviderTruncatedResults,
                )
        }));
        assert_eq!(snapshot.items().len(), 4);
        let file = snapshot
            .items()
            .iter()
            .find(|item| item.provider_item_id() == "file-1")
            .unwrap();
        assert_eq!(file.size().unwrap().bytes(), 123);
        assert_eq!(file.provider_revision(), Some("ctag"));
        assert_eq!(
            file.content_hash().unwrap().algorithm(),
            &HashAlgorithm::ProviderNative("quickXorHash".to_owned())
        );
        assert_eq!(
            file.provider_timestamp().unwrap().basis(),
            ProviderTimestampBasis::Modified
        );
        for id in ["folder-1", "shared-link"] {
            let folder = snapshot
                .items()
                .iter()
                .find(|item| item.provider_item_id() == id)
                .unwrap();
            assert_eq!(folder.kind(), RemoteItemKind::Folder);
            assert!(folder.size().is_none());
            assert!(folder.content_hash().is_none());
        }
        assert!(
            snapshot
                .items()
                .iter()
                .any(|item| item.provider_item_id() == "nested-1")
        );
        assert!(adapter.transport.replies.is_empty());
        assert!(
            adapter
                .transport
                .calls
                .iter()
                .any(|call| { call == &children(None, Some("next+token")) })
        );
    }

    #[test]
    fn next_link_is_reduced_to_one_validated_opaque_token() {
        let valid = next_link(Some("folder-1"), "opaque+/token==");
        assert_eq!(
            extract_skip_token(&valid, "drive-1", Some("folder-1")).unwrap(),
            "opaque+/token=="
        );

        for invalid in [
            valid.replace("graph.microsoft.com", "attacker.example"),
            valid.replace("/items/folder-1/children", "/items/other/children"),
            format!("{valid}&other=1"),
            format!("{valid}&$skiptoken=second"),
            replace_query_value(&valid, "$top", "200", "201"),
        ] {
            assert_eq!(
                extract_skip_token(&invalid, "drive-1", Some("folder-1")),
                Err(ProviderFailure::MalformedResponse)
            );
        }
    }

    #[test]
    fn rejects_invalid_quickxor_base64_shape() {
        for invalid in ["", "abc", "****", "AA=A", "AAAA===="] {
            assert!(!valid_base64_shape(invalid), "accepted {invalid:?}");
        }
        assert!(valid_base64_shape("AAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    }

    #[test]
    fn provider_cursor_is_single_use_and_scope_bound() {
        let expected = scope();
        let other_scope =
            AccountScope::new(Provider::OneDrive, "different-user", Some("drive-1".into()))
                .unwrap();
        let foreign = PageCursor::new(&other_scope, Uuid::new_v4().to_string()).unwrap();
        let mut adapter = OneDriveAdapter {
            transport: FakeTransport {
                replies: VecDeque::new(),
                calls: Vec::new(),
            },
            selected_drive: Some("drive-1".to_owned()),
            pending: None,
        };
        assert_eq!(
            adapter.list_page(&expected, Some(&foreign), &AtomicBool::new(false)),
            Err(ProviderFailure::MalformedResponse)
        );
        assert!(adapter.transport.calls.is_empty());
    }
}
