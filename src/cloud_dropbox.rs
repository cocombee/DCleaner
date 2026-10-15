//! Read-only Dropbox root metadata adapter.
//!
//! This adapter traverses only the current account's API-visible root through
//! Dropbox's metadata RPCs. It never downloads content or mutates remote data.

use crate::{
    cloud_http::{
        AccessToken, CloudHttpError, MAX_CURSOR_BYTES, MAX_RESPONSE_BYTES, MetadataHttp,
        ReadEndpoint,
    },
    cloud_inventory::{
        AccountScope, ContentHash, HashAlgorithm, PageCursor, Provider, ProviderFailure,
        ProviderTimestamp, ProviderTimestampBasis, RemoteItemDraft, RemoteItemKind, RemotePage,
        RemotePort, SizeAccuracy, SizeObservation, TrashStatus,
    },
};
use chrono::DateTime;
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const MAX_PAGE_ITEMS: usize = 1_000;
const MAX_ID_BYTES: usize = 512;
const MAX_NAME_BYTES: usize = 4_096;
const MAX_REVISION_BYTES: usize = 512;
const HTTP_DEADLINE: Duration = Duration::from_secs(30);
const DROPBOX_CONTENT_HASH: &str = "DropboxContentHash";

trait DropboxTransport {
    fn read(
        &mut self,
        endpoint: ReadEndpoint<'_>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<Vec<u8>, CloudHttpError>;
}

struct NativeTransport(MetadataHttp);

impl NativeTransport {
    fn new(token: AccessToken) -> Result<Self, CloudHttpError> {
        MetadataHttp::new(token).map(Self)
    }
}

impl DropboxTransport for NativeTransport {
    fn read(
        &mut self,
        endpoint: ReadEndpoint<'_>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<Vec<u8>, CloudHttpError> {
        self.0.read(endpoint, cancel, deadline)
    }
}

/// Dropbox inventory adapter. Construction prepares an HTTPS client but makes
/// no account request; there are no upload, download, Trash, or delete methods.
pub struct DropboxClient(DropboxAdapter<NativeTransport>);

impl DropboxClient {
    pub fn new(token: AccessToken) -> Result<Self, CloudHttpError> {
        Ok(Self(DropboxAdapter {
            transport: NativeTransport::new(token)?,
        }))
    }
}

impl RemotePort for DropboxClient {
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

struct DropboxAdapter<T> {
    transport: T,
}

impl<T: DropboxTransport> RemotePort for DropboxAdapter<T> {
    fn current_scope(&mut self, cancel: &AtomicBool) -> Result<AccountScope, ProviderFailure> {
        if cancel.load(Ordering::Relaxed) {
            return Err(ProviderFailure::Cancelled);
        }
        let bytes = self
            .transport
            .read(ReadEndpoint::DropboxAccount, cancel, deadline())
            .map_err(provider_error)?;
        if cancel.load(Ordering::Relaxed) {
            return Err(ProviderFailure::Cancelled);
        }
        let wire: WireAccount = decode_json(&bytes)?;
        if !valid_account_id(&wire.account_id)
            || !matches!(wire.root_info.tag.as_str(), "user" | "team")
            || !valid_text(&wire.root_info.root_namespace_id, MAX_ID_BYTES)
        {
            return Err(ProviderFailure::MalformedResponse);
        }
        AccountScope::new(
            Provider::Dropbox,
            wire.account_id,
            Some(wire.root_info.root_namespace_id),
        )
        .map_err(|_| ProviderFailure::MalformedResponse)
    }

    fn list_page(
        &mut self,
        expected_scope: &AccountScope,
        cursor: Option<&PageCursor>,
        cancel: &AtomicBool,
    ) -> Result<RemotePage, ProviderFailure> {
        if cancel.load(Ordering::Relaxed) {
            return Err(ProviderFailure::Cancelled);
        }
        if expected_scope.provider() != Provider::Dropbox
            || expected_scope.storage_id().is_none()
            || cursor.is_some_and(|cursor| !cursor.belongs_to(expected_scope))
        {
            return Err(ProviderFailure::AccountScopeMismatch);
        }

        // Keep direct adapter calls bound to the same Dropbox account and root,
        // even when callers do not use the inventory scan's surrounding checks.
        let observed = self.current_scope(cancel)?;
        if observed != *expected_scope {
            return Err(ProviderFailure::AccountScopeMismatch);
        }
        let root_namespace = observed
            .storage_id()
            .ok_or(ProviderFailure::AccountScopeMismatch)?;
        let endpoint = match cursor {
            Some(cursor) => ReadEndpoint::DropboxContinue {
                root_namespace,
                cursor: cursor.provider_value(),
            },
            None => ReadEndpoint::DropboxFiles { root_namespace },
        };
        if cancel.load(Ordering::Relaxed) {
            return Err(ProviderFailure::Cancelled);
        }
        let bytes = self
            .transport
            .read(endpoint, cancel, deadline())
            .map_err(provider_error)?;
        if cancel.load(Ordering::Relaxed) {
            return Err(ProviderFailure::Cancelled);
        }
        decode_page(&bytes, &observed)
    }
}

fn deadline() -> Instant {
    Instant::now() + HTTP_DEADLINE
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

fn decode_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ProviderFailure> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ProviderFailure::ResponseLimit);
    }
    serde_json::from_slice(bytes).map_err(|_| ProviderFailure::MalformedResponse)
}

#[derive(Deserialize)]
struct WireAccount {
    account_id: String,
    root_info: WireRootInfo,
}

#[derive(Deserialize)]
struct WireRootInfo {
    #[serde(rename = ".tag")]
    tag: String,
    root_namespace_id: String,
}

#[derive(Deserialize)]
struct WirePage {
    #[serde(deserialize_with = "decode_entries")]
    entries: Vec<WireEntry>,
    cursor: String,
    has_more: bool,
}

#[derive(Deserialize)]
#[serde(tag = ".tag", rename_all = "snake_case")]
enum WireEntry {
    File(WireFile),
    Folder(WireFolder),
    Deleted(WireDeleted),
}

#[derive(Deserialize)]
struct WireFile {
    id: String,
    name: String,
    size: u64,
    rev: String,
    content_hash: String,
    server_modified: Option<String>,
}

#[derive(Deserialize)]
struct WireFolder {
    id: String,
    name: String,
    size: Option<u64>,
    rev: Option<String>,
    content_hash: Option<String>,
    server_modified: Option<String>,
}

#[derive(Deserialize)]
struct WireDeleted {
    name: String,
    path_lower: Option<String>,
    path_display: Option<String>,
}

fn decode_entries<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<WireEntry>, D::Error> {
    struct Entries;
    impl<'de> Visitor<'de> for Entries {
        type Value = Vec<WireEntry>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("at most 1000 Dropbox metadata entries")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut entries = Vec::new();
            for _ in 0..MAX_PAGE_ITEMS {
                match seq.next_element()? {
                    Some(entry) => entries.push(entry),
                    None => return Ok(entries),
                }
            }
            if seq.next_element::<de::IgnoredAny>()?.is_some() {
                return Err(de::Error::custom("Dropbox entry limit exceeded"));
            }
            Ok(entries)
        }
    }
    decoder.deserialize_seq(Entries)
}

fn decode_page(bytes: &[u8], scope: &AccountScope) -> Result<RemotePage, ProviderFailure> {
    let wire: WirePage = decode_json(bytes)?;
    if !valid_cursor(&wire.cursor) {
        return Err(ProviderFailure::MalformedResponse);
    }
    let next_cursor = if wire.has_more {
        Some(PageCursor::new(scope, wire.cursor).map_err(|_| ProviderFailure::MalformedResponse)?)
    } else {
        // Dropbox still returns a cursor on terminal pages. It can be used for
        // later change polling, but this one-shot inventory must not continue it.
        None
    };
    let mut items = Vec::with_capacity(wire.entries.len());
    for entry in wire.entries {
        items.push(decode_entry(entry)?);
    }
    Ok(RemotePage::new(scope.clone(), items, next_cursor))
}

fn decode_entry(entry: WireEntry) -> Result<RemoteItemDraft, ProviderFailure> {
    match entry {
        WireEntry::File(file) => {
            if !valid_text(&file.id, MAX_ID_BYTES)
                || !valid_text(&file.name, MAX_NAME_BYTES)
                || !valid_text(&file.rev, MAX_REVISION_BYTES)
                || !valid_content_hash(&file.content_hash)
            {
                return Err(ProviderFailure::MalformedResponse);
            }
            let hash = ContentHash::new(
                Provider::Dropbox,
                HashAlgorithm::ProviderNative(DROPBOX_CONTENT_HASH.into()),
                file.content_hash.to_ascii_lowercase(),
            )
            .map_err(|_| ProviderFailure::MalformedResponse)?;
            let timestamp = parse_server_modified(file.server_modified)?;
            Ok(
                RemoteItemDraft::new(file.id, file.name, RemoteItemKind::File)
                    .with_size(Some(SizeObservation::new(
                        file.size,
                        SizeAccuracy::ProviderReportedExact,
                    )))
                    .with_provider_revision(Some(file.rev))
                    .with_content_hash(Some(hash))
                    .with_provider_timestamp(timestamp)
                    .with_trash_status(TrashStatus::NotTrashed),
            )
        }
        WireEntry::Folder(folder) => {
            if !valid_text(&folder.id, MAX_ID_BYTES)
                || !valid_text(&folder.name, MAX_NAME_BYTES)
                || folder.size.is_some()
                || folder.rev.is_some()
                || folder.content_hash.is_some()
            {
                return Err(ProviderFailure::MalformedResponse);
            }
            let timestamp = parse_server_modified(folder.server_modified)?;
            Ok(
                RemoteItemDraft::new(folder.id, folder.name, RemoteItemKind::Folder)
                    .with_provider_timestamp(timestamp)
                    .with_trash_status(TrashStatus::NotTrashed),
            )
        }
        WireEntry::Deleted(deleted) => {
            // DeletedMetadata has no stable file ID and does not say whether
            // the old entry was a file or folder. Do not fabricate either.
            if !valid_text(&deleted.name, MAX_NAME_BYTES)
                || deleted
                    .path_lower
                    .as_deref()
                    .is_some_and(|path| !valid_path(path))
                || deleted
                    .path_display
                    .as_deref()
                    .is_some_and(|path| !valid_path(path))
            {
                return Err(ProviderFailure::MalformedResponse);
            }
            Err(ProviderFailure::MalformedResponse)
        }
    }
}

fn parse_server_modified(
    value: Option<String>,
) -> Result<Option<ProviderTimestamp>, ProviderFailure> {
    value
        .map(|value| {
            let parsed = DateTime::parse_from_rfc3339(&value)
                .map_err(|_| ProviderFailure::MalformedResponse)?;
            ProviderTimestamp::new(parsed.timestamp_millis(), ProviderTimestampBasis::Modified)
                .map(Some)
                .map_err(|_| ProviderFailure::MalformedResponse)
        })
        .transpose()
        .map(Option::flatten)
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.trim().is_empty()
        && !value.chars().any(char::is_control)
}

fn valid_account_id(value: &str) -> bool {
    // Dropbox documents account_id as a stable 40-character identifier. Keep
    // it opaque instead of depending on the current example's textual prefix.
    value.is_ascii() && value.len() == 40 && valid_text(value, MAX_ID_BYTES)
}

fn valid_cursor(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_CURSOR_BYTES && !value.chars().any(char::is_control)
}

fn valid_path(value: &str) -> bool {
    value.len() <= MAX_NAME_BYTES && value.starts_with('/') && !value.chars().any(char::is_control)
}

fn valid_content_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ExpectedRead {
        Account,
        Files { root: String },
        Continue { root: String, cursor: String },
    }

    struct FakeTransport {
        replies: VecDeque<(ExpectedRead, Result<Vec<u8>, CloudHttpError>)>,
        calls: Vec<ExpectedRead>,
    }

    impl FakeTransport {
        fn new(replies: Vec<(ExpectedRead, Result<Vec<u8>, CloudHttpError>)>) -> Self {
            Self {
                replies: replies.into(),
                calls: Vec::new(),
            }
        }
    }

    impl DropboxTransport for FakeTransport {
        fn read(
            &mut self,
            endpoint: ReadEndpoint<'_>,
            _: &AtomicBool,
            _: Instant,
        ) -> Result<Vec<u8>, CloudHttpError> {
            let actual = match endpoint {
                ReadEndpoint::DropboxAccount => ExpectedRead::Account,
                ReadEndpoint::DropboxFiles { root_namespace } => ExpectedRead::Files {
                    root: root_namespace.to_owned(),
                },
                ReadEndpoint::DropboxContinue {
                    root_namespace,
                    cursor,
                } => ExpectedRead::Continue {
                    root: root_namespace.to_owned(),
                    cursor: cursor.to_owned(),
                },
                _ => panic!("unexpected non-Dropbox read endpoint"),
            };
            let (expected, response) = self.replies.pop_front().expect("missing fixture reply");
            assert_eq!(actual, expected);
            self.calls.push(actual);
            response
        }
    }

    fn scope() -> AccountScope {
        AccountScope::new(
            Provider::Dropbox,
            account_id(),
            Some("root-namespace".into()),
        )
        .unwrap()
    }

    fn account_id() -> String {
        "dbid:fixture-account-identifier-00000000".into()
    }

    fn account_reply() -> (ExpectedRead, Result<Vec<u8>, CloudHttpError>) {
        (
            ExpectedRead::Account,
            Ok(format!(
                r#"{{"account_id":"{}","email":"mutable@example.invalid","root_info":{{".tag":"team","root_namespace_id":"root-namespace","home_namespace_id":"home-namespace"}}}}"#,
                account_id()
            )
            .into_bytes()),
        )
    }

    fn page_reply(
        expected: ExpectedRead,
        entries: &str,
        cursor: &str,
        has_more: bool,
    ) -> (ExpectedRead, Result<Vec<u8>, CloudHttpError>) {
        let body = format!(r#"{{"entries":{entries},"cursor":"{cursor}","has_more":{has_more}}}"#);
        (expected, Ok(body.into_bytes()))
    }

    fn file_json(id: &str, name: &str, size: &str, hash: &str) -> String {
        format!(
            r#"{{".tag":"file","id":"{id}","name":"{name}","size":{size},"rev":"rev-1","content_hash":"{hash}","server_modified":"2025-03-04T05:06:07.123Z"}}"#
        )
    }

    #[test]
    fn account_scope_uses_stable_account_and_root_ids_only() {
        let mut adapter = DropboxAdapter {
            transport: FakeTransport::new(vec![account_reply()]),
        };
        let observed = adapter.current_scope(&AtomicBool::new(false)).unwrap();
        assert_eq!(observed.provider(), Provider::Dropbox);
        assert_eq!(observed.subject_id(), account_id());
        assert_eq!(observed.storage_id(), Some("root-namespace"));
        assert!(!format!("{observed:?}").contains("fixture-account"));
        assert_eq!(adapter.transport.calls, [ExpectedRead::Account]);
    }

    #[test]
    fn account_scope_rejects_unrecognized_root_and_noncanonical_account_identity() {
        let mut adapter = DropboxAdapter {
            transport: FakeTransport::new(vec![
                (
                    ExpectedRead::Account,
                    Ok(br#"{"account_id":"dbid:fixture-account-identifier-00000000","root_info":{".tag":"unknown","root_namespace_id":"root-namespace"}}"#.to_vec()),
                ),
            ]),
        };
        assert_eq!(
            adapter.current_scope(&AtomicBool::new(false)),
            Err(ProviderFailure::MalformedResponse)
        );

        let mut adapter = DropboxAdapter {
            transport: FakeTransport::new(vec![(
                ExpectedRead::Account,
                Ok(br#"{"account_id":"wrong-id","root_info":{".tag":"user","root_namespace_id":"root-namespace"}}"#.to_vec()),
            )]),
        };
        assert_eq!(
            adapter.current_scope(&AtomicBool::new(false)),
            Err(ProviderFailure::MalformedResponse)
        );
    }

    #[test]
    fn cancellation_before_direct_scope_or_page_call_does_not_touch_transport() {
        let mut adapter = DropboxAdapter {
            transport: FakeTransport::new(vec![]),
        };
        let cancel = AtomicBool::new(true);
        assert_eq!(
            adapter.current_scope(&cancel),
            Err(ProviderFailure::Cancelled)
        );
        assert_eq!(
            adapter.list_page(&scope(), None, &cancel),
            Err(ProviderFailure::Cancelled)
        );
        assert!(adapter.transport.calls.is_empty());
    }

    #[test]
    fn list_and_continue_are_bound_to_account_root_and_has_more() {
        let expected_scope = scope();
        let hash = "A".repeat(64);
        let first_entries = format!(
            "[{},{{\".tag\":\"folder\",\"id\":\"folder-1\",\"name\":\"Folder\"}}]",
            file_json("file-1", "zero.bin", "0", &hash)
        );
        let transport = FakeTransport::new(vec![
            account_reply(), // scan's initial scope observation
            account_reply(),
            page_reply(
                ExpectedRead::Files {
                    root: "root-namespace".into(),
                },
                &first_entries,
                "continue-token",
                true,
            ),
            account_reply(),
            account_reply(), // scan's scope check before the second page
            account_reply(),
            page_reply(
                ExpectedRead::Continue {
                    root: "root-namespace".into(),
                    cursor: "continue-token".into(),
                },
                "[]",
                "terminal-cursor",
                false,
            ),
            account_reply(), // scan verifies the account again after the terminal page
        ]);
        let mut adapter = DropboxAdapter { transport };
        let snapshot =
            crate::cloud_inventory::scan(&mut adapter, &expected_scope, &AtomicBool::new(false));
        assert_eq!(
            snapshot.status(),
            crate::cloud_inventory::SnapshotStatus::Complete
        );
        assert_eq!(snapshot.items().len(), 2);
        let file = &snapshot.items()[0];
        assert_eq!(file.kind(), RemoteItemKind::File);
        assert_eq!(file.size().unwrap().bytes(), 0);
        assert_eq!(file.mime_type(), None);
        assert_eq!(file.provider_revision(), Some("rev-1"));
        assert_eq!(
            file.provider_timestamp().unwrap().basis(),
            ProviderTimestampBasis::Modified
        );
        assert_eq!(
            file.provider_timestamp().unwrap().unix_millis(),
            1_741_064_767_123
        );
        assert_eq!(file.trash_status(), TrashStatus::NotTrashed);
        let hash = file.content_hash().unwrap();
        assert_eq!(hash.digest(), "a".repeat(64));
        assert_eq!(
            hash.algorithm(),
            &HashAlgorithm::ProviderNative(DROPBOX_CONTENT_HASH.into())
        );
        let folder = &snapshot.items()[1];
        assert_eq!(folder.kind(), RemoteItemKind::Folder);
        assert_eq!(folder.size(), None);
        assert_eq!(folder.content_hash(), None);
        assert_eq!(folder.mime_type(), None);
        assert_eq!(folder.provider_timestamp(), None);
        assert_eq!(folder.trash_status(), TrashStatus::NotTrashed);
        assert_eq!(
            adapter.transport.calls,
            [
                ExpectedRead::Account,
                ExpectedRead::Account,
                ExpectedRead::Files {
                    root: "root-namespace".into(),
                },
                ExpectedRead::Account,
                ExpectedRead::Account,
                ExpectedRead::Account,
                ExpectedRead::Continue {
                    root: "root-namespace".into(),
                    cursor: "continue-token".into(),
                },
                ExpectedRead::Account,
            ]
        );
    }

    #[test]
    fn mismatched_direct_scope_or_cursor_is_rejected_before_transport() {
        let expected_scope = scope();
        let other = AccountScope::new(
            Provider::Dropbox,
            "dbid:another-account-identifier-00000000",
            Some("other-root".into()),
        )
        .unwrap();
        let cursor = PageCursor::new(&other, "foreign-cursor").unwrap();
        let mut adapter = DropboxAdapter {
            transport: FakeTransport::new(vec![account_reply()]),
        };
        assert_eq!(
            adapter.list_page(&other, None, &AtomicBool::new(false)),
            Err(ProviderFailure::AccountScopeMismatch)
        );
        assert_eq!(
            adapter.list_page(&expected_scope, Some(&cursor), &AtomicBool::new(false)),
            Err(ProviderFailure::AccountScopeMismatch)
        );
        assert_eq!(adapter.transport.calls, [ExpectedRead::Account]);
    }

    #[test]
    fn deleted_metadata_is_explicitly_rejected_without_fabricated_id_or_kind() {
        let body = br#"{"entries":[{".tag":"deleted","name":"gone.txt","path_lower":"/gone.txt"}],"cursor":"cursor","has_more":false}"#;
        assert_eq!(
            decode_page(body, &scope()),
            Err(ProviderFailure::MalformedResponse)
        );
    }

    #[test]
    fn missing_or_malformed_file_fields_fail_and_empty_hashes_never_pass() {
        let scope = scope();
        let bad_entries = [
            r#"[{".tag":"file","name":"missing-id","size":0,"rev":"r","content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]"#,
            r#"[{".tag":"file","id":"i","name":"missing-size","rev":"r","content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]"#,
            r#"[{".tag":"file","id":"i","name":"missing-revision","size":0,"content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]"#,
            r#"[{".tag":"file","id":"i","name":"missing-hash","size":0,"rev":"r"}]"#,
            r#"[{".tag":"file","id":"i","name":"bad-hash","size":0,"rev":"r","content_hash":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}]"#,
            r#"[{".tag":"file","id":"i","name":"negative-size","size":-1,"rev":"r","content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]"#,
        ];
        for entries in bad_entries {
            let body = format!(r#"{{"entries":{entries},"cursor":"c","has_more":false}}"#);
            assert_eq!(
                decode_page(body.as_bytes(), &scope),
                Err(ProviderFailure::MalformedResponse)
            );
        }
    }

    #[test]
    fn folder_content_fields_and_bad_timestamps_fail_closed() {
        let scope = scope();
        for entry in [
            r#"{".tag":"folder","id":"f","name":"folder","size":1}"#,
            r#"{".tag":"folder","id":"f","name":"folder","content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            r#"{".tag":"file","id":"i","name":"bad-time","size":1,"rev":"r","content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","server_modified":"not a date"}"#,
        ] {
            let body = format!(r#"{{"entries":[{entry}],"cursor":"c","has_more":false}}"#);
            assert_eq!(
                decode_page(body.as_bytes(), &scope),
                Err(ProviderFailure::MalformedResponse)
            );
        }
    }

    #[test]
    fn response_entry_and_cursor_bounds_are_enforced() {
        let scope = scope();
        let rows = std::iter::repeat_n(
            r#"{".tag":"folder","id":"f","name":"folder"}"#,
            MAX_PAGE_ITEMS + 1,
        )
        .collect::<Vec<_>>()
        .join(",");
        let body = format!(r#"{{"entries":[{rows}],"cursor":"c","has_more":false}}"#);
        assert_eq!(
            decode_page(body.as_bytes(), &scope),
            Err(ProviderFailure::MalformedResponse)
        );
        let too_long_cursor = "c".repeat(MAX_CURSOR_BYTES + 1);
        let body = format!(r#"{{"entries":[],"cursor":"{too_long_cursor}","has_more":false}}"#);
        assert_eq!(
            decode_page(body.as_bytes(), &scope),
            Err(ProviderFailure::MalformedResponse)
        );
        assert!(matches!(
            decode_json::<WirePage>(&vec![b' '; MAX_RESPONSE_BYTES + 1]),
            Err(ProviderFailure::ResponseLimit)
        ));
    }

    #[test]
    fn provider_http_failures_map_to_safe_core_classes() {
        assert_eq!(
            provider_error(CloudHttpError::HttpStatus(401)),
            ProviderFailure::AuthenticationRequired
        );
        assert_eq!(
            provider_error(CloudHttpError::HttpStatus(403)),
            ProviderFailure::PermissionDenied
        );
        assert_eq!(
            provider_error(CloudHttpError::HttpStatus(429)),
            ProviderFailure::RateLimited
        );
        assert_eq!(
            provider_error(CloudHttpError::HttpStatus(503)),
            ProviderFailure::TemporarilyUnavailable
        );
        assert_eq!(
            provider_error(CloudHttpError::HttpStatus(409)),
            ProviderFailure::Other
        );
        assert_eq!(
            provider_error(CloudHttpError::TimedOut),
            ProviderFailure::TimedOut
        );
        assert_eq!(
            provider_error(CloudHttpError::ResponseLimit),
            ProviderFailure::ResponseLimit
        );
        assert_eq!(
            provider_error(CloudHttpError::Transport),
            ProviderFailure::Transport
        );
    }
}
