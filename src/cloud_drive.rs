//! Independent Google Drive metadata reads. No OAuth or remote effects occur here.
//!
//! A supplied access token is short-lived input from the future authorization
//! owner; it is never persisted, logged, serialized or accepted as proof of an
//! entire-account inventory. Only files visible to its granted scopes are read.

pub use crate::cloud_http::{AccessToken, CloudHttpError as DriveError};
#[cfg(test)]
use crate::cloud_http::{DRIVE_FIELDS as LIST_FIELDS, MAX_CURSOR_BYTES, read_bounded};
use crate::cloud_http::{MAX_RESPONSE_BYTES, MetadataHttp, ReadEndpoint, validate_cursor};
use crate::cloud_inventory::{
    AccountScope, ContentHash, HashAlgorithm, IncompletePageReason, PageCompleteness, PageCursor,
    Provider, ProviderFailure, RemoteItemDraft, RemoteItemKind, RemotePage, RemotePort,
    SizeAccuracy, SizeObservation, TrashStatus, UnknownFieldReason,
};
use crate::cloud_inventory::{ProviderTimestamp, ProviderTimestampBasis};
#[cfg(test)]
use reqwest::Url;
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
#[cfg(test)]
use std::io::Read;
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const MAX_PAGE_ITEMS: usize = 1_000;
#[cfg(test)]
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const VISIBLE_STORAGE: &str = "drive:user:api-visible:untrashed";

// Callers cannot introduce URLs, query fields, methods, downloads or effects.
enum MetadataRequest<'a> {
    Account,
    Files { cursor: Option<&'a str> },
}

#[cfg(test)]
fn request_url(request: &MetadataRequest<'_>) -> Result<Url, DriveError> {
    crate::cloud_http::read_url(&match request {
        MetadataRequest::Account => ReadEndpoint::GoogleDriveAccount,
        MetadataRequest::Files { cursor } => ReadEndpoint::GoogleDriveFiles { cursor: *cursor },
    })
}

trait MetadataTransport {
    fn get(
        &mut self,
        request: MetadataRequest<'_>,
        cancel: &AtomicBool,
    ) -> Result<Vec<u8>, DriveError>;
}

struct NativeTransport {
    http: MetadataHttp,
}
impl NativeTransport {
    fn new(token: AccessToken) -> Result<Self, DriveError> {
        Ok(Self {
            http: MetadataHttp::new(token)?,
        })
    }
}
impl MetadataTransport for NativeTransport {
    fn get(
        &mut self,
        request: MetadataRequest<'_>,
        cancel: &AtomicBool,
    ) -> Result<Vec<u8>, DriveError> {
        self.http.read(
            match request {
                MetadataRequest::Account => ReadEndpoint::GoogleDriveAccount,
                MetadataRequest::Files { cursor } => ReadEndpoint::GoogleDriveFiles { cursor },
            },
            cancel,
            Instant::now() + Duration::from_secs(30),
        )
    }
}

#[derive(Deserialize)]
struct WireAccount {
    user: WireUser,
}
#[derive(Deserialize)]
struct WireUser {
    #[serde(rename = "permissionId")]
    permission_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WirePage {
    #[serde(deserialize_with = "decode_files")]
    files: Vec<WireFile>,
    next_page_token: Option<String>,
    #[serde(default)]
    incomplete_search: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireFile {
    id: String,
    name: String,
    mime_type: String,
    size: Option<String>,
    version: Option<String>,
    modified_time: Option<String>,
    sha256_checksum: Option<String>,
    md5_checksum: Option<String>,
    trashed: Option<bool>,
}
fn decode_files<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<WireFile>, D::Error> {
    struct Files;
    impl<'de> Visitor<'de> for Files {
        type Value = Vec<WireFile>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("at most 1000 Drive metadata rows")
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
                return Err(de::Error::custom("Drive row bound exceeded"));
            }
            Ok(rows)
        }
    }
    decoder.deserialize_seq(Files)
}

fn decode_page(bytes: &[u8]) -> Result<WirePage, DriveError> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(DriveError::ResponseLimit);
    }
    let page: WirePage = serde_json::from_slice(bytes).map_err(|_| DriveError::InvalidResponse)?;
    if let Some(cursor) = &page.next_page_token {
        validate_cursor(cursor)?;
    }
    Ok(page)
}

/// Real read-only adapter, ready for the independent OAuth owner to supply a
/// granted token. Construction does not contact an account or open a browser.
/// It deliberately exposes no upload, download, Trash or delete operation.
pub struct DriveClient(DriveAdapter<NativeTransport>);
impl DriveClient {
    pub fn new(token: AccessToken) -> Result<Self, DriveError> {
        Ok(Self(DriveAdapter {
            transport: NativeTransport::new(token)?,
        }))
    }
}
impl RemotePort for DriveClient {
    fn current_scope(&mut self, cancel: &AtomicBool) -> Result<AccountScope, ProviderFailure> {
        self.0.current_scope(cancel)
    }
    fn list_page(
        &mut self,
        scope: &AccountScope,
        cursor: Option<&PageCursor>,
        cancel: &AtomicBool,
    ) -> Result<RemotePage, ProviderFailure> {
        self.0.list_page(scope, cursor, cancel)
    }
}

struct DriveAdapter<T> {
    transport: T,
}
impl<T: MetadataTransport> RemotePort for DriveAdapter<T> {
    fn current_scope(&mut self, cancel: &AtomicBool) -> Result<AccountScope, ProviderFailure> {
        let bytes = self
            .transport
            .get(MetadataRequest::Account, cancel)
            .map_err(provider_error)?;
        if cancel.load(Ordering::Relaxed) {
            return Err(ProviderFailure::Cancelled);
        }
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ProviderFailure::ResponseLimit);
        }
        let account: WireAccount =
            serde_json::from_slice(&bytes).map_err(|_| ProviderFailure::MalformedResponse)?;
        AccountScope::new(
            Provider::GoogleDrive,
            account.user.permission_id,
            Some(VISIBLE_STORAGE.into()),
        )
        .map_err(|_| ProviderFailure::MalformedResponse)
    }

    fn list_page(
        &mut self,
        expected: &AccountScope,
        cursor: Option<&PageCursor>,
        cancel: &AtomicBool,
    ) -> Result<RemotePage, ProviderFailure> {
        if expected.provider() != Provider::GoogleDrive
            || expected.storage_id() != Some(VISIBLE_STORAGE)
            || cursor.is_some_and(|cursor| !cursor.belongs_to(expected))
        {
            return Err(ProviderFailure::MalformedResponse);
        }
        // Also bind direct adapter calls, rather than relying only on scan's
        // before/after checks. A token is never switched or refreshed here.
        let observed = self.current_scope(cancel)?;
        if observed != *expected {
            return Err(ProviderFailure::AccountScopeMismatch);
        }
        let bytes = self
            .transport
            .get(
                MetadataRequest::Files {
                    cursor: cursor.map(PageCursor::provider_value),
                },
                cancel,
            )
            .map_err(provider_error)?;
        if cancel.load(Ordering::Relaxed) {
            return Err(ProviderFailure::Cancelled);
        }
        let wire = decode_page(&bytes).map_err(provider_error)?;
        let next = wire
            .next_page_token
            .map(|value| PageCursor::new(&observed, value))
            .transpose()
            .map_err(|_| ProviderFailure::MalformedResponse)?;
        let mut rows = Vec::new();
        for file in wire.files {
            if cancel.load(Ordering::Relaxed) {
                return Err(ProviderFailure::Cancelled);
            }
            rows.push(decode_file(file).map_err(provider_error)?);
        }
        let mut page = RemotePage::new(observed, rows, next);
        if wire.incomplete_search {
            page = page.with_completeness(PageCompleteness::Incomplete(
                IncompletePageReason::ProviderReportedIncompleteSearch,
            ));
        }
        Ok(page)
    }
}

fn provider_error(error: DriveError) -> ProviderFailure {
    match error {
        DriveError::Cancelled => ProviderFailure::Cancelled,
        DriveError::TimedOut => ProviderFailure::TimedOut,
        DriveError::ResponseLimit => ProviderFailure::ResponseLimit,
        DriveError::ClientUnavailable => ProviderFailure::ClientUnavailable,
        DriveError::Transport => ProviderFailure::Transport,
        DriveError::HttpStatus(401) => ProviderFailure::AuthenticationRequired,
        DriveError::HttpStatus(403) => ProviderFailure::PermissionDenied,
        DriveError::HttpStatus(429) => ProviderFailure::RateLimited,
        DriveError::HttpStatus(500..=599) => ProviderFailure::TemporarilyUnavailable,
        DriveError::HttpStatus(_) => ProviderFailure::Other,
        _ => ProviderFailure::MalformedResponse,
    }
}

fn decimal(value: &str) -> Result<u64, DriveError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(DriveError::InvalidResponse);
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(DriveError::InvalidResponse)
}

fn decode_file(file: WireFile) -> Result<RemoteItemDraft, DriveError> {
    if file.trashed == Some(true) {
        return Err(DriveError::InvalidResponse);
    }
    let folder = file.mime_type == "application/vnd.google-apps.folder";
    let shortcut = file.mime_type == "application/vnd.google-apps.shortcut";
    let size = file.size.as_deref().map(decimal).transpose()?;
    let timestamp = file
        .modified_time
        .as_deref()
        .map(|value| {
            let time = chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| DriveError::InvalidResponse)?;
            ProviderTimestamp::new(time.timestamp_millis(), ProviderTimestampBasis::Modified)
                .map_err(|_| DriveError::InvalidResponse)
        })
        .transpose()?;
    if let Some(version) = &file.version {
        decimal(version)?;
    }
    let hash = match (file.sha256_checksum, file.md5_checksum) {
        (Some(value), _) => Some(
            ContentHash::new(Provider::GoogleDrive, HashAlgorithm::Sha256, value)
                .map_err(|_| DriveError::InvalidResponse)?,
        ),
        (None, Some(value)) => Some(
            ContentHash::new(Provider::GoogleDrive, HashAlgorithm::Md5, value)
                .map_err(|_| DriveError::InvalidResponse)?,
        ),
        _ => None,
    };
    if (folder || shortcut) && (size.is_some() || hash.is_some()) {
        return Err(DriveError::InvalidResponse);
    }
    Ok(RemoteItemDraft::new(
        file.id,
        file.name,
        if folder {
            RemoteItemKind::Folder
        } else {
            RemoteItemKind::File
        },
    )
    .with_mime_type(Some(file.mime_type))
    .with_provider_revision(file.version)
    .with_provider_timestamp(timestamp)
    .with_size(size.map(|n| SizeObservation::new(n, SizeAccuracy::ProviderReportedExact)))
    .with_content_hash(hash)
    .with_trash_status(if file.trashed == Some(false) {
        TrashStatus::NotTrashed
    } else {
        TrashStatus::Unknown(UnknownFieldReason::NotProvided)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{self, Cursor};

    struct FakeTransport {
        replies: VecDeque<(&'static str, Result<Vec<u8>, DriveError>)>,
    }
    impl MetadataTransport for FakeTransport {
        fn get(
            &mut self,
            request: MetadataRequest<'_>,
            _: &AtomicBool,
        ) -> Result<Vec<u8>, DriveError> {
            let (kind, reply) = self.replies.pop_front().expect("unexpected fixture call");
            assert_eq!(
                kind,
                match request {
                    MetadataRequest::Account => "account",
                    MetadataRequest::Files { .. } => "files",
                }
            );
            reply
        }
    }
    fn scope() -> AccountScope {
        AccountScope::new(
            Provider::GoogleDrive,
            "fixture-account",
            Some(VISIBLE_STORAGE.into()),
        )
        .unwrap()
    }
    fn account() -> (&'static str, Result<Vec<u8>, DriveError>) {
        (
            "account",
            Ok(br#"{"user":{"permissionId":"fixture-account"}}"#.to_vec()),
        )
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn continuation_data_cannot_change_host_path_query_policy_or_method() {
        let cursor = "opaque&fields=secret#https://attacker.invalid/?token=private";
        let url = request_url(&MetadataRequest::Files {
            cursor: Some(cursor),
        })
        .unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("www.googleapis.com"));
        assert_eq!(url.path(), "/drive/v3/files");
        assert!(url.fragment().is_none());
        let query = url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(query.get("pageToken").map(|s| s.as_ref()), Some(cursor));
        assert_eq!(query.get("fields").map(|s| s.as_ref()), Some(LIST_FIELDS));
        assert_eq!(query.get("q").map(|s| s.as_ref()), Some("trashed=false"));
        assert_eq!(query.get("spaces").map(|s| s.as_ref()), Some("drive"));
        assert_eq!(query.get("corpora").map(|s| s.as_ref()), Some("user"));
        assert_eq!(query.len(), 8);
    }

    #[test]
    fn invalid_tokens_and_control_bearing_or_oversized_cursors_are_rejected() {
        for value in [
            "".to_owned(),
            "\r\ninjected".into(),
            "private token".into(),
            "bad=middle".into(),
            "a".repeat(MAX_TOKEN_BYTES + 1),
        ] {
            assert!(matches!(
                AccessToken::new(value),
                Err(DriveError::InvalidToken)
            ));
        }
        assert!(AccessToken::new("valid-token._~+/==".into()).is_ok());
        for cursor in [
            "".to_owned(),
            "a\n".into(),
            "x".repeat(MAX_CURSOR_BYTES + 1),
        ] {
            assert!(matches!(
                request_url(&MetadataRequest::Files {
                    cursor: Some(&cursor)
                }),
                Err(DriveError::InvalidCursor)
            ));
        }
    }

    #[test]
    fn response_body_limit_is_enforced_even_without_content_length() {
        let cancel = AtomicBool::new(false);
        let mut input = io::repeat(b'a').take((MAX_RESPONSE_BYTES + 1) as u64);
        assert_eq!(
            read_bounded(&mut input, &cancel, deadline()),
            Err(DriveError::ResponseLimit)
        );
        let mut exact = io::repeat(b'a').take(MAX_RESPONSE_BYTES as u64);
        assert_eq!(
            read_bounded(&mut exact, &cancel, deadline()).unwrap().len(),
            MAX_RESPONSE_BYTES
        );
    }

    #[test]
    fn cancellation_after_blocking_read_discards_its_bytes() {
        struct CancelRead<'a>(&'a AtomicBool);
        impl Read for CancelRead<'_> {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                bytes[0] = b'a';
                self.0.store(true, Ordering::Relaxed);
                Ok(1)
            }
        }
        let cancel = AtomicBool::new(false);
        assert_eq!(
            read_bounded(&mut CancelRead(&cancel), &cancel, deadline()),
            Err(DriveError::Cancelled)
        );
    }

    #[test]
    fn expired_or_precancelled_body_does_not_invoke_the_reader() {
        struct NoRead;
        impl Read for NoRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("read must not start")
            }
        }
        assert_eq!(
            read_bounded(&mut NoRead, &AtomicBool::new(false), Instant::now()),
            Err(DriveError::TimedOut)
        );
        assert_eq!(
            read_bounded(&mut NoRead, &AtomicBool::new(true), deadline()),
            Err(DriveError::Cancelled)
        );
    }

    #[test]
    fn read_failures_do_not_expose_input_errors_or_partial_success() {
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("private token or file name"))
            }
        }
        let error = read_bounded(&mut Failing, &AtomicBool::new(false), deadline()).unwrap_err();
        assert_eq!(error, DriveError::Transport);
        assert!(!error.to_string().contains("private"));
        assert_eq!(
            read_bounded(
                &mut Cursor::new(b"complete"),
                &AtomicBool::new(false),
                deadline()
            )
            .unwrap(),
            b"complete"
        );
    }

    #[test]
    fn malformed_duplicate_and_excess_rows_never_become_empty_success() {
        for body in [
            b"{}".as_slice(),
            b"{\"files\":[],\"files\":[]}",
            b"{\"files\":[{\"id\":\"x\"}]}",
            b"{\"files\":[],\"nextPageToken\":\"\"}",
            b"{\"files\":[],\"incompleteSearch\":\"false\"}",
        ] {
            assert!(decode_page(body).is_err());
        }
        let rows = (0..=MAX_PAGE_ITEMS).map(|i| serde_json::json!({"id":i.to_string(),"name":"fixture","mimeType":"text/plain"})).collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&serde_json::json!({"files":rows})).unwrap();
        assert!(matches!(
            decode_page(&bytes),
            Err(DriveError::InvalidResponse)
        ));
        let valid = decode_page(b"{\"files\":[],\"incompleteSearch\":true}").unwrap();
        assert!(valid.files.is_empty());
        assert!(valid.incomplete_search);
    }

    #[test]
    fn drive_pages_retain_real_field_semantics_and_provider_incomplete_search() {
        let page_one=br#"{"files":[{"id":"blob","name":"fixture.bin","mimeType":"application/octet-stream","size":"10","version":"2","sha256Checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","trashed":false},{"id":"folder","name":"fixture folder","mimeType":"application/vnd.google-apps.folder","trashed":false}],"nextPageToken":"next"}"#.to_vec();
        let page_two=br#"{"files":[{"id":"sheet","name":"fixture sheet","mimeType":"application/vnd.google-apps.spreadsheet","size":"4"}],"incompleteSearch":true}"#.to_vec();
        let transport = FakeTransport {
            replies: VecDeque::from([
                account(),
                account(),
                ("files", Ok(page_one)),
                account(),
                account(),
                account(),
                ("files", Ok(page_two)),
                account(),
            ]),
        };
        let mut adapter = DriveAdapter { transport };
        let snapshot =
            crate::cloud_inventory::scan(&mut adapter, &scope(), &AtomicBool::new(false));
        assert_eq!(
            snapshot.status(),
            crate::cloud_inventory::SnapshotStatus::Partial
        );
        assert_eq!(snapshot.items().len(), 3);
        assert!(adapter.transport.replies.is_empty());
        let blob = &snapshot.items()[0];
        assert_eq!(blob.provider_revision(), Some("2"));
        assert_eq!(
            blob.size().unwrap().accuracy(),
            SizeAccuracy::ProviderReportedExact
        );
        assert_eq!(blob.trash_status(), TrashStatus::NotTrashed);
        assert_eq!(
            blob.content_hash().unwrap().algorithm(),
            &HashAlgorithm::Sha256
        );
        assert_eq!(snapshot.items()[1].kind(), RemoteItemKind::Folder);
        assert!(snapshot.items()[1].size().is_none());
        assert_eq!(snapshot.items()[2].size().unwrap().bytes(), 4);
        assert!(snapshot.items()[2].content_hash().is_none());
        assert_eq!(snapshot.large_item_candidates(5).candidates().len(), 1);
    }

    #[test]
    fn adapter_rejects_changed_account_and_foreign_cursor_before_listing() {
        let mut changed = DriveAdapter {
            transport: FakeTransport {
                replies: VecDeque::from([(
                    "account",
                    Ok(br#"{"user":{"permissionId":"other-account"}}"#.to_vec()),
                )]),
            },
        };
        assert!(matches!(
            changed.list_page(&scope(), None, &AtomicBool::new(false)),
            Err(ProviderFailure::AccountScopeMismatch)
        ));
        assert!(changed.transport.replies.is_empty());
        let other = AccountScope::new(
            Provider::GoogleDrive,
            "other-account",
            Some(VISIBLE_STORAGE.into()),
        )
        .unwrap();
        let cursor = PageCursor::new(&other, "opaque").unwrap();
        let mut no_calls = DriveAdapter {
            transport: FakeTransport {
                replies: VecDeque::new(),
            },
        };
        assert!(matches!(
            no_calls.list_page(&scope(), Some(&cursor), &AtomicBool::new(false)),
            Err(ProviderFailure::MalformedResponse)
        ));
    }

    #[test]
    fn unknown_sizes_and_missing_trash_stay_unknown_and_invalid_values_fail() {
        let decode = |value: serde_json::Value| {
            decode_file(serde_json::from_value::<WireFile>(value).unwrap())
        };
        for extra in [
            serde_json::json!({"size":"-1"}),
            serde_json::json!({"size":"9223372036854775808"}),
            serde_json::json!({"version":"not-a-version"}),
            serde_json::json!({"trashed":true}),
            serde_json::json!({"sha256Checksum":"not-a-hash"}),
            serde_json::json!({"mimeType":"application/vnd.google-apps.shortcut","size":"5"}),
        ] {
            let mut value =
                serde_json::json!({"id":"fixture","name":"fixture","mimeType":"text/plain"});
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(matches!(decode(value), Err(DriveError::InvalidResponse)));
        }
        let mut adapter=DriveAdapter {transport:FakeTransport {replies:VecDeque::from([account(),account(),("files",Ok(br#"{"files":[{"id":"fixture","name":"fixture","mimeType":"text/plain"}]}"#.to_vec())),account()])}};
        let snapshot =
            crate::cloud_inventory::scan(&mut adapter, &scope(), &AtomicBool::new(false));
        assert!(snapshot.is_complete());
        assert!(snapshot.items()[0].size().is_none());
        assert_eq!(
            snapshot.items()[0].trash_status(),
            TrashStatus::Unknown(UnknownFieldReason::NotProvided)
        );
    }
}
