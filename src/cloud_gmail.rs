//! Independent, read-only Gmail message metadata inventory.
//!
//! This adapter lists only messages visible under the supplied token, and the
//! fixed listing excludes Spam and Trash. It fetches metadata headers only; it
//! never fetches bodies or exposes any message mutation operation. A complete
//! snapshot means all pages exposed by this API-visible listing were traversed,
//! not that Gmail provided an atomic mailbox snapshot or a claim of every item
//! in an account.

use crate::{
    cloud_http::{
        AccessToken, CloudHttpError, MAX_CURSOR_BYTES, MAX_RESPONSE_BYTES, MetadataHttp,
        ReadEndpoint, validate_cursor,
    },
    cloud_inventory::{
        AccountScope, PageCursor, Provider, ProviderFailure, ProviderTimestamp,
        ProviderTimestampBasis, RemoteItemDraft, RemoteItemKind, RemotePage, RemotePort,
        SizeAccuracy, SizeObservation, TrashStatus, UnknownFieldReason,
    },
};
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const MAX_PAGE_ITEMS: usize = 25;
const MAX_GMAIL_ID_BYTES: usize = 512;
const MAX_LABEL_ID_BYTES: usize = 512;
const PAGE_TIMEOUT: Duration = Duration::from_secs(30);
const VISIBLE_MAILBOX: &str = "gmail:user:api-visible:excluding-spam-trash";

/// No email address, message body or token is retained. Subject is used only as
/// the inventory display name; other header values are not requested or kept.
pub struct GmailClient(MailAdapter<NativeTransport>);

impl GmailClient {
    /// Construct a read-only adapter without contacting an account or opening
    /// an authorization UI. The future auth owner supplies an already granted
    /// token with `openid` and an appropriate Gmail read scope.
    pub fn new(token: AccessToken) -> Result<Self, CloudHttpError> {
        Ok(Self(MailAdapter {
            transport: NativeTransport(MetadataHttp::new(token)?),
        }))
    }
}

impl RemotePort for GmailClient {
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

trait GmailTransport {
    fn read(
        &mut self,
        endpoint: ReadEndpoint<'_>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<Vec<u8>, CloudHttpError>;
}

struct NativeTransport(MetadataHttp);

impl GmailTransport for NativeTransport {
    fn read(
        &mut self,
        endpoint: ReadEndpoint<'_>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<Vec<u8>, CloudHttpError> {
        self.0.read(endpoint, cancel, deadline)
    }
}

struct MailAdapter<T> {
    transport: T,
}
impl<T: GmailTransport> RemotePort for MailAdapter<T> {
    fn current_scope(&mut self, cancel: &AtomicBool) -> Result<AccountScope, ProviderFailure> {
        MailAdapter::current_scope(self, cancel)
    }
    fn list_page(
        &mut self,
        scope: &AccountScope,
        cursor: Option<&PageCursor>,
        cancel: &AtomicBool,
    ) -> Result<RemotePage, ProviderFailure> {
        MailAdapter::list_page(self, scope, cursor, cancel)
    }
}

impl<T: GmailTransport> MailAdapter<T> {
    fn scope_until(
        &mut self,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<AccountScope, ProviderFailure> {
        let bytes = self
            .transport
            .read(ReadEndpoint::GoogleUserInfo, cancel, deadline)
            .map_err(provider_error)?;
        check_cancel(cancel)?;
        check_deadline(deadline)?;
        check_body(&bytes)?;
        let user: WireUserInfo =
            serde_json::from_slice(&bytes).map_err(|_| ProviderFailure::MalformedResponse)?;
        if user.sub.is_empty() || user.sub.len() > 255 || user.sub.chars().any(char::is_control) {
            return Err(ProviderFailure::MalformedResponse);
        }
        AccountScope::new(Provider::Gmail, user.sub, Some(VISIBLE_MAILBOX.into()))
            .map_err(|_| ProviderFailure::MalformedResponse)
    }

    fn current_scope(&mut self, cancel: &AtomicBool) -> Result<AccountScope, ProviderFailure> {
        self.scope_until(cancel, Instant::now() + PAGE_TIMEOUT)
    }

    fn list_page(
        &mut self,
        expected_scope: &AccountScope,
        cursor: Option<&PageCursor>,
        cancel: &AtomicBool,
    ) -> Result<RemotePage, ProviderFailure> {
        if expected_scope.provider() != Provider::Gmail
            || expected_scope.storage_id() != Some(VISIBLE_MAILBOX)
            || cursor.is_some_and(|page| !page.belongs_to(expected_scope))
        {
            return Err(ProviderFailure::MalformedResponse);
        }

        // One absolute deadline covers this scope check, list request, all
        // sequential metadata GETs, and the final account recheck.
        let deadline = Instant::now() + PAGE_TIMEOUT;
        let before = self.scope_until(cancel, deadline)?;
        if before != *expected_scope {
            return Err(ProviderFailure::AccountScopeMismatch);
        }
        check_cancel(cancel)?;
        check_deadline(deadline)?;

        let bytes = self
            .transport
            .read(
                ReadEndpoint::GmailMessages {
                    cursor: cursor.map(PageCursor::provider_value),
                },
                cancel,
                deadline,
            )
            .map_err(provider_error)?;
        check_cancel(cancel)?;
        check_deadline(deadline)?;
        check_body(&bytes)?;
        let listed: WireMessagePage =
            serde_json::from_slice(&bytes).map_err(|_| ProviderFailure::MalformedResponse)?;
        if let Some(value) = &listed.next_page_token {
            validate_cursor(value).map_err(provider_error)?;
            if value.len() > MAX_CURSOR_BYTES {
                return Err(ProviderFailure::MalformedResponse);
            }
        }

        let mut rows = Vec::with_capacity(listed.messages.len());
        for listed_message in listed.messages {
            check_cancel(cancel)?;
            if Instant::now() >= deadline {
                return Err(ProviderFailure::TimedOut);
            }
            validate_gmail_identifier(&listed_message.id)?;
            validate_gmail_identifier(&listed_message.thread_id)?;

            let message_bytes = self
                .transport
                .read(
                    ReadEndpoint::GmailMessage {
                        id: &listed_message.id,
                    },
                    cancel,
                    deadline,
                )
                .map_err(provider_error)?;
            check_cancel(cancel)?;
            check_deadline(deadline)?;
            check_body(&message_bytes)?;
            let message: WireMessage = serde_json::from_slice(&message_bytes)
                .map_err(|_| ProviderFailure::MalformedResponse)?;
            check_cancel(cancel)?;
            rows.push(decode_message(
                message,
                &listed_message.id,
                &listed_message.thread_id,
            )?);
        }

        let after = self.scope_until(cancel, deadline)?;
        if after != *expected_scope {
            return Err(ProviderFailure::AccountScopeMismatch);
        }
        let next = listed
            .next_page_token
            .map(|value| PageCursor::new(expected_scope, value))
            .transpose()
            .map_err(|_| ProviderFailure::MalformedResponse)?;
        check_cancel(cancel)?;
        check_deadline(deadline)?;
        Ok(RemotePage::new(expected_scope.clone(), rows, next))
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

fn validate_gmail_identifier(value: &str) -> Result<(), ProviderFailure> {
    if value.is_empty()
        || value.len() > MAX_GMAIL_ID_BYTES
        || value == "."
        || value == ".."
        || value.chars().any(char::is_control)
    {
        Err(ProviderFailure::MalformedResponse)
    } else {
        Ok(())
    }
}

#[derive(Deserialize)]
struct WireUserInfo {
    sub: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireMessagePage {
    #[serde(default, deserialize_with = "decode_message_refs")]
    messages: Vec<WireMessageRef>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireMessageRef {
    id: String,
    thread_id: String,
}

fn decode_message_refs<'de, D: Deserializer<'de>>(
    decoder: D,
) -> Result<Vec<WireMessageRef>, D::Error> {
    struct MessageRefs;
    impl<'de> Visitor<'de> for MessageRefs {
        type Value = Vec<WireMessageRef>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("at most 25 Gmail message references")
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
                return Err(de::Error::custom("Gmail page item bound exceeded"));
            }
            Ok(rows)
        }
    }
    decoder.deserialize_seq(MessageRefs)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireMessage {
    id: String,
    thread_id: String,
    label_ids: Option<Vec<String>>,
    size_estimate: Option<u64>,
    internal_date: Option<String>,
    history_id: Option<String>,
    payload: Option<WirePayload>,
}

#[derive(Deserialize)]
struct WirePayload {
    #[serde(default)]
    headers: Vec<WireHeader>,
}

#[derive(Deserialize)]
struct WireHeader {
    name: String,
    value: String,
}

fn decode_message(
    message: WireMessage,
    expected_id: &str,
    expected_thread_id: &str,
) -> Result<RemoteItemDraft, ProviderFailure> {
    if message.id != expected_id || message.thread_id != expected_thread_id {
        return Err(ProviderFailure::MalformedResponse);
    }
    validate_gmail_identifier(&message.id)?;
    validate_gmail_identifier(&message.thread_id)?;

    let mut subject = None;
    if let Some(payload) = message.payload {
        for header in payload.headers {
            if header.name.eq_ignore_ascii_case("subject") {
                if subject.is_some() {
                    return Err(ProviderFailure::MalformedResponse);
                }
                subject = Some(header.value);
            }
        }
    }

    let trash_status = if let Some(labels) = &message.label_ids {
        for label in labels {
            if label.is_empty()
                || label.len() > MAX_LABEL_ID_BYTES
                || label.chars().any(char::is_control)
            {
                return Err(ProviderFailure::MalformedResponse);
            }
            if label == "TRASH" || label == "SPAM" {
                // This conflicts with the fixed messages.list query, which
                // explicitly excludes both categories.
                return Err(ProviderFailure::MalformedResponse);
            }
        }
        TrashStatus::NotTrashed
    } else {
        TrashStatus::Unknown(UnknownFieldReason::NotProvided)
    };

    let size = match message.size_estimate {
        Some(bytes) if bytes <= i64::MAX as u64 => Some(SizeObservation::new(
            bytes,
            SizeAccuracy::GmailMessageEstimate,
        )),
        Some(_) => return Err(ProviderFailure::MalformedResponse),
        None => None,
    };
    let timestamp = message
        .internal_date
        .map(|value| {
            let millis = signed_decimal(&value)?;
            // Gmail notes that API-imported mail may have internalDate based
            // on its Date header, so callers should display this as Gmail's
            // internal message date rather than verified original delivery.
            ProviderTimestamp::new(millis, ProviderTimestampBasis::Received)
                .map_err(|_| ProviderFailure::MalformedResponse)
        })
        .transpose()?;
    let revision = message
        .history_id
        .map(|value| {
            nonnegative_int64(&value)?;
            Ok::<_, ProviderFailure>(value)
        })
        .transpose()?;

    Ok(RemoteItemDraft::new(
        message.id,
        subject.unwrap_or_else(|| "(No subject)".to_owned()),
        RemoteItemKind::Mail,
    )
    .with_size(size)
    .with_provider_revision(revision)
    .with_provider_timestamp(timestamp)
    .with_trash_status(trash_status))
}

fn signed_decimal(value: &str) -> Result<i64, ProviderFailure> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProviderFailure::MalformedResponse);
    }
    value
        .parse::<i64>()
        .map_err(|_| ProviderFailure::MalformedResponse)
}

fn nonnegative_int64(value: &str) -> Result<i64, ProviderFailure> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProviderFailure::MalformedResponse);
    }
    value
        .parse::<i64>()
        .map_err(|_| ProviderFailure::MalformedResponse)
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
    use crate::cloud_inventory::{InventoryIssueKind, SnapshotStatus, UnknownFieldReason, scan};
    use std::collections::VecDeque;

    #[derive(Debug, Eq, PartialEq)]
    enum ExpectedRead {
        UserInfo,
        List(Option<String>),
        Message(String),
    }

    struct FakeTransport {
        replies: VecDeque<(ExpectedRead, Result<Vec<u8>, CloudHttpError>)>,
        calls: Vec<ExpectedRead>,
        deadlines: Vec<Instant>,
        cancel_after_call: Option<usize>,
    }

    impl FakeTransport {
        fn new(replies: Vec<(ExpectedRead, Result<Vec<u8>, CloudHttpError>)>) -> Self {
            Self {
                replies: replies.into(),
                calls: Vec::new(),
                deadlines: Vec::new(),
                cancel_after_call: None,
            }
        }

        fn cancel_after(mut self, call_number: usize) -> Self {
            self.cancel_after_call = Some(call_number);
            self
        }
    }

    impl GmailTransport for FakeTransport {
        fn read(
            &mut self,
            endpoint: ReadEndpoint<'_>,
            cancel: &AtomicBool,
            deadline: Instant,
        ) -> Result<Vec<u8>, CloudHttpError> {
            let actual = match endpoint {
                ReadEndpoint::GoogleUserInfo => ExpectedRead::UserInfo,
                ReadEndpoint::GmailMessages { cursor } => {
                    ExpectedRead::List(cursor.map(str::to_owned))
                }
                ReadEndpoint::GmailMessage { id } => ExpectedRead::Message(id.to_owned()),
                _ => panic!("unexpected endpoint in Gmail fixture"),
            };
            let (expected, response) = self.replies.pop_front().expect("fixture read overrun");
            assert_eq!(actual, expected);
            self.calls.push(actual);
            self.deadlines.push(deadline);
            if self.cancel_after_call == Some(self.calls.len()) {
                cancel.store(true, Ordering::Relaxed);
            }
            response
        }
    }

    fn scope(subject: &str) -> AccountScope {
        AccountScope::new(Provider::Gmail, subject, Some(VISIBLE_MAILBOX.to_owned())).unwrap()
    }

    fn read(endpoint: ExpectedRead, body: &str) -> (ExpectedRead, Result<Vec<u8>, CloudHttpError>) {
        (endpoint, Ok(body.as_bytes().to_vec()))
    }

    fn user() -> (ExpectedRead, Result<Vec<u8>, CloudHttpError>) {
        user_for("google-subject-1")
    }

    fn user_for(subject: &str) -> (ExpectedRead, Result<Vec<u8>, CloudHttpError>) {
        read(
            ExpectedRead::UserInfo,
            &serde_json::json!({"sub":subject}).to_string(),
        )
    }

    fn message_list(ids: &[(&str, &str)], next: Option<&str>) -> String {
        let messages = ids
            .iter()
            .map(|(id, thread)| serde_json::json!({"id":id,"threadId":thread}))
            .collect::<Vec<_>>();
        serde_json::json!({"messages":messages,"nextPageToken":next}).to_string()
    }

    fn metadata(
        id: &str,
        thread: &str,
        labels: Option<&[&str]>,
        size: Option<u64>,
        date: Option<&str>,
        history: Option<&str>,
        subjects: &[&str],
    ) -> String {
        let mut message = serde_json::json!({
            "id":id,
            "threadId":thread,
            "payload":{"headers":subjects.iter().map(|value| serde_json::json!({"name":"Subject","value":value})).collect::<Vec<_>>()}
        });
        if let Some(labels) = labels {
            message["labelIds"] = serde_json::json!(labels);
        }
        if let Some(size) = size {
            message["sizeEstimate"] = serde_json::json!(size);
        }
        if let Some(date) = date {
            message["internalDate"] = serde_json::json!(date);
        }
        if let Some(history) = history {
            message["historyId"] = serde_json::json!(history);
        }
        message.to_string()
    }

    #[test]
    fn scan_keeps_only_metadata_and_uses_one_page_deadline() {
        let list = message_list(&[("m1", "t1"), ("m2", "t2")], None);
        let mut client = MailAdapter {
            transport: FakeTransport::new(vec![
                user(),
                user(),
                read(ExpectedRead::List(None), &list),
                read(
                    ExpectedRead::Message("m1".into()),
                    &metadata(
                        "m1",
                        "t1",
                        Some(&["INBOX"]),
                        Some(123),
                        Some("1700000000000"),
                        Some("987"),
                        &["Hello"],
                    ),
                ),
                read(
                    ExpectedRead::Message("m2".into()),
                    &metadata("m2", "t2", None, None, None, None, &[]),
                ),
                user(),
                user(),
            ]),
        };
        let snapshot = scan(
            &mut client,
            &scope("google-subject-1"),
            &AtomicBool::new(false),
        );
        assert_eq!(snapshot.status(), SnapshotStatus::Complete);
        assert_eq!(snapshot.items().len(), 2);
        assert_eq!(snapshot.items()[0].display_name(), "Hello");
        assert_eq!(snapshot.items()[0].size().unwrap().bytes(), 123);
        assert_eq!(
            snapshot.items()[0].size().unwrap().accuracy(),
            SizeAccuracy::GmailMessageEstimate
        );
        let timestamp = snapshot.items()[0].provider_timestamp().unwrap();
        assert_eq!(timestamp.unix_millis(), 1_700_000_000_000);
        assert_eq!(timestamp.basis(), ProviderTimestampBasis::Received);
        assert_eq!(snapshot.items()[0].provider_revision(), Some("987"));
        assert_eq!(snapshot.items()[0].trash_status(), TrashStatus::NotTrashed);
        assert_eq!(snapshot.items()[1].display_name(), "(No subject)");
        assert!(snapshot.items()[1].size().is_none());
        assert!(snapshot.items()[1].provider_timestamp().is_none());
        assert_eq!(
            snapshot.items()[1].trash_status(),
            TrashStatus::Unknown(UnknownFieldReason::NotProvided)
        );
        assert!(client.transport.replies.is_empty());
        // The top-level scope calls have independent deadlines; all calls
        // inside the page (scope/list/message metadata/scope) share one.
        assert!(
            client.transport.deadlines[1..6]
                .windows(2)
                .all(|pair| pair[0] == pair[1])
        );
    }

    #[test]
    fn scan_keeps_gmail_timestamp_semantics_and_does_not_accept_spam_or_trash() {
        let list = message_list(&[("m1", "t1")], None);
        let transport = FakeTransport::new(vec![
            user(),
            user(),
            read(ExpectedRead::List(None), &list),
            read(
                ExpectedRead::Message("m1".into()),
                &metadata(
                    "m1",
                    "t1",
                    Some(&["INBOX"]),
                    Some(99),
                    Some("1700000000000"),
                    Some("4"),
                    &["Subject"],
                ),
            ),
            user(),
            user(),
        ]);
        let mut client = MailAdapter { transport };
        let snapshot = scan(
            &mut client,
            &scope("google-subject-1"),
            &AtomicBool::new(false),
        );
        assert_eq!(snapshot.status(), SnapshotStatus::Complete);
        assert_eq!(snapshot.items().len(), 1);
        assert_eq!(
            snapshot.items()[0].provider_timestamp().unwrap().basis(),
            ProviderTimestampBasis::Received
        );

        for excluded_label in ["TRASH", "SPAM"] {
            let list = message_list(&[("m1", "t1")], None);
            let transport = FakeTransport::new(vec![
                user(),
                user(),
                read(ExpectedRead::List(None), &list),
                read(
                    ExpectedRead::Message("m1".into()),
                    &metadata(
                        "m1",
                        "t1",
                        Some(&[excluded_label]),
                        Some(99),
                        Some("1700000000000"),
                        Some("4"),
                        &["Subject"],
                    ),
                ),
                user(),
            ]);
            let mut client = MailAdapter { transport };
            let snapshot = scan(
                &mut client,
                &scope("google-subject-1"),
                &AtomicBool::new(false),
            );
            assert_eq!(snapshot.status(), SnapshotStatus::Failed);
            assert!(snapshot.items().is_empty());
            assert!(snapshot.issues().iter().any(|issue| matches!(
                issue.kind(),
                InventoryIssueKind::ProviderPageFailed(ProviderFailure::MalformedResponse)
            )));
        }
    }

    #[test]
    fn mismatched_ids_and_duplicate_subject_headers_fail_closed() {
        let mismatched = WireMessage {
            id: "other".into(),
            thread_id: "thread".into(),
            label_ids: Some(vec![]),
            size_estimate: None,
            internal_date: None,
            history_id: None,
            payload: None,
        };
        assert_eq!(
            decode_message(mismatched, "expected", "thread"),
            Err(ProviderFailure::MalformedResponse)
        );

        let duplicate: WireMessage = serde_json::from_str(&metadata(
            "m1",
            "t1",
            Some(&[]),
            None,
            None,
            None,
            &["first", "second"],
        ))
        .unwrap();
        assert_eq!(
            decode_message(duplicate, "m1", "t1"),
            Err(ProviderFailure::MalformedResponse)
        );
    }

    #[test]
    fn control_bearing_subject_is_rejected_by_inventory_validation() {
        let list = message_list(&[("m1", "t1")], None);
        let transport = FakeTransport::new(vec![
            user(),
            user(),
            read(ExpectedRead::List(None), &list),
            read(
                ExpectedRead::Message("m1".into()),
                &metadata(
                    "m1",
                    "t1",
                    Some(&["INBOX"]),
                    None,
                    None,
                    None,
                    &["bad\nsubject"],
                ),
            ),
            user(),
            user(),
        ]);
        let mut client = MailAdapter { transport };
        let snapshot = scan(
            &mut client,
            &scope("google-subject-1"),
            &AtomicBool::new(false),
        );
        assert_eq!(snapshot.status(), SnapshotStatus::Partial);
        assert!(snapshot.items().is_empty());
        assert!(snapshot.issues().iter().any(|issue| matches!(
            issue.kind(),
            InventoryIssueKind::MalformedRow(
                crate::cloud_inventory::InvalidRowReason::InvalidDisplayName
            )
        )));
    }

    #[test]
    fn cancellation_between_message_gets_stops_the_page() {
        let list = message_list(&[("m1", "t1"), ("m2", "t2")], None);
        let transport = FakeTransport::new(vec![
            user(),
            read(ExpectedRead::List(None), &list),
            read(
                ExpectedRead::Message("m1".into()),
                &metadata("m1", "t1", Some(&["INBOX"]), None, None, None, &[]),
            ),
        ])
        .cancel_after(3);
        let mut adapter = MailAdapter { transport };
        let result = adapter.list_page(&scope("google-subject-1"), None, &AtomicBool::new(false));
        assert_eq!(result, Err(ProviderFailure::Cancelled));
        assert_eq!(adapter.transport.calls.len(), 3);
        assert_eq!(
            adapter.transport.calls.last(),
            Some(&ExpectedRead::Message("m1".into()))
        );
    }

    #[test]
    fn foreign_cursors_wrong_scope_and_oversized_lists_do_not_issue_message_gets() {
        let foreign_scope = scope("different-subject");
        let foreign_cursor = PageCursor::new(&foreign_scope, "opaque-page").unwrap();
        let mut adapter = MailAdapter {
            transport: FakeTransport::new(vec![]),
        };
        assert_eq!(
            adapter.list_page(
                &scope("google-subject-1"),
                Some(&foreign_cursor),
                &AtomicBool::new(false),
            ),
            Err(ProviderFailure::MalformedResponse)
        );
        assert!(adapter.transport.calls.is_empty());

        let mut switched = MailAdapter {
            transport: FakeTransport::new(vec![user_for("another-google-subject")]),
        };
        assert_eq!(
            switched.list_page(&scope("google-subject-1"), None, &AtomicBool::new(false),),
            Err(ProviderFailure::AccountScopeMismatch)
        );
        assert_eq!(
            switched.transport.calls.as_slice(),
            &[ExpectedRead::UserInfo]
        );

        let ids = (0..=MAX_PAGE_ITEMS)
            .map(|index| (format!("m{index}"), format!("t{index}")))
            .collect::<Vec<_>>();
        let json = serde_json::json!({
            "messages": ids.iter().map(|(id, thread)| serde_json::json!({"id":id,"threadId":thread})).collect::<Vec<_>>()
        });
        assert!(serde_json::from_value::<WireMessagePage>(json).is_err());
    }

    #[test]
    fn continuation_cursor_is_forwarded_as_an_opaque_page_token() {
        let first = message_list(&[], Some("opaque-next"));
        let second = message_list(&[], None);
        let mut client = MailAdapter {
            transport: FakeTransport::new(vec![
                user(),
                user(),
                read(ExpectedRead::List(None), &first),
                user(),
                user(),
                user(),
                user(),
                read(ExpectedRead::List(Some("opaque-next".into())), &second),
                user(),
                user(),
            ]),
        };
        let snapshot = scan(
            &mut client,
            &scope("google-subject-1"),
            &AtomicBool::new(false),
        );
        assert_eq!(snapshot.status(), SnapshotStatus::Complete);
        assert_eq!(
            client
                .transport
                .calls
                .iter()
                .filter(|call| matches!(call, ExpectedRead::List(_)))
                .count(),
            2
        );
        assert!(client.transport.replies.is_empty());
    }

    #[test]
    fn timestamp_and_revision_values_must_be_numeric_and_representable() {
        assert!(signed_decimal("1700000000000").is_ok());
        assert!(signed_decimal("-1").is_ok());
        for bad in ["", "+1", " 1", "1x", "9223372036854775808"] {
            assert_eq!(signed_decimal(bad), Err(ProviderFailure::MalformedResponse));
        }
        assert!(nonnegative_int64("123").is_ok());
        for bad in ["", "-1", "1.0", "9223372036854775808"] {
            assert_eq!(
                nonnegative_int64(bad),
                Err(ProviderFailure::MalformedResponse)
            );
        }
        assert!(ProviderTimestamp::new(i64::MAX, ProviderTimestampBasis::Received).is_err());
    }
}
