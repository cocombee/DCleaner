//! Bounded HTTPS transport for fixed, read-only provider metadata operations.
//! Even POST variants here are documented metadata RPCs, never mutation APIs.

use reqwest::{Method, Url, blocking::Client, header};
use std::{
    fmt,
    io::Read,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(crate) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_CURSOR_BYTES: usize = 2048;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
pub(crate) const DRIVE_FIELDS: &str = "nextPageToken,incompleteSearch,files(id,name,mimeType,size,version,sha256Checksum,md5Checksum,trashed,modifiedTime)";
pub(crate) const GRAPH_FIELDS: &str =
    "id,name,size,eTag,cTag,file,folder,parentReference,deleted,remoteItem,lastModifiedDateTime";

/// No Debug, Serialize or public accessor. Transport copies are not claimed scrubbed.
pub struct AccessToken(Zeroizing<String>);
impl AccessToken {
    /// Authenticated requests are constructed only by the crate's fixed-route
    /// transports. Never expose the credential to views, logs or serialization.
    pub(crate) fn authorize(
        &self,
        request: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        request.bearer_auth(self.0.as_str())
    }
    pub fn new(value: String) -> Result<Self, CloudHttpError> {
        let value = Zeroizing::new(value);
        let token = value.trim_end_matches('=');
        if value.is_empty()
            || value.len() > MAX_TOKEN_BYTES
            || token.is_empty()
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
        {
            return Err(CloudHttpError::InvalidToken);
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudHttpError {
    InvalidToken,
    InvalidCursor,
    InvalidIdentifier,
    Cancelled,
    TimedOut,
    ClientUnavailable,
    Transport,
    HttpStatus(u16),
    ResponseLimit,
    InvalidResponse,
}
impl fmt::Display for CloudHttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidToken => "Cloud access token is invalid.",
            Self::InvalidCursor => "Cloud continuation token is invalid.",
            Self::InvalidIdentifier => "Cloud metadata identifier is invalid.",
            Self::Cancelled => "Cloud metadata read was cancelled.",
            Self::TimedOut => "Cloud metadata read exceeded its deadline.",
            Self::ClientUnavailable => "Cloud HTTPS client could not be initialized.",
            Self::Transport => "Cloud metadata transport failed; no automatic retry was made.",
            Self::ResponseLimit => "Cloud metadata response exceeded its bound.",
            Self::InvalidResponse => "Cloud provider returned invalid or incomplete metadata.",
            Self::HttpStatus(code) => {
                return write!(
                    f,
                    "Cloud provider returned HTTP {code}; no automatic retry was made."
                );
            }
        })
    }
}
impl std::error::Error for CloudHttpError {}

/// Fixed read routes only. No endpoint accepts a URL, arbitrary method or body.
pub(crate) enum ReadEndpoint<'a> {
    GoogleDriveAccount,
    GoogleDriveFiles {
        cursor: Option<&'a str>,
    },
    GoogleUserInfo,
    GraphMe,
    GraphDrives {
        cursor: Option<&'a str>,
    },
    GraphChildren {
        drive_id: &'a str,
        folder_id: Option<&'a str>,
        cursor: Option<&'a str>,
    },
    GmailMessages {
        cursor: Option<&'a str>,
    },
    GmailMessage {
        id: &'a str,
    },
    DropboxAccount,
    DropboxFiles {
        root_namespace: &'a str,
    },
    DropboxContinue {
        root_namespace: &'a str,
        cursor: &'a str,
    },
}
struct RequestParts {
    url: Url,
    method: Method,
    body: Option<Vec<u8>>,
    path_root: Option<header::HeaderValue>,
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
pub(crate) fn validate_cursor(value: &str) -> Result<(), CloudHttpError> {
    if bounded(value, MAX_CURSOR_BYTES) {
        Ok(())
    } else {
        Err(CloudHttpError::InvalidCursor)
    }
}
fn identifier(value: &str) -> Result<(), CloudHttpError> {
    if bounded(value, 512) && value != "." && value != ".." {
        Ok(())
    } else {
        Err(CloudHttpError::InvalidIdentifier)
    }
}
fn request_parts(endpoint: &ReadEndpoint<'_>) -> Result<RequestParts, CloudHttpError> {
    let base = match endpoint {
        ReadEndpoint::GoogleDriveAccount => "https://www.googleapis.com/drive/v3/about",
        ReadEndpoint::GoogleDriveFiles { .. } => "https://www.googleapis.com/drive/v3/files",
        ReadEndpoint::GoogleUserInfo => "https://openidconnect.googleapis.com/v1/userinfo",
        ReadEndpoint::GraphMe => "https://graph.microsoft.com/v1.0/me",
        ReadEndpoint::GraphDrives { .. } => "https://graph.microsoft.com/v1.0/me/drives",
        ReadEndpoint::GraphChildren { .. } => "https://graph.microsoft.com/v1.0/drives",
        ReadEndpoint::GmailMessages { .. } | ReadEndpoint::GmailMessage { .. } => {
            "https://gmail.googleapis.com/gmail/v1/users/me/messages"
        }
        ReadEndpoint::DropboxAccount => "https://api.dropboxapi.com/2/users/get_current_account",
        ReadEndpoint::DropboxFiles { .. } => "https://api.dropboxapi.com/2/files/list_folder",
        ReadEndpoint::DropboxContinue { .. } => {
            "https://api.dropboxapi.com/2/files/list_folder/continue"
        }
    };
    let mut p = RequestParts {
        url: Url::parse(base).map_err(|_| CloudHttpError::ClientUnavailable)?,
        method: Method::GET,
        body: None,
        path_root: None,
    };
    match endpoint {
        ReadEndpoint::GoogleDriveAccount => {
            p.url
                .query_pairs_mut()
                .append_pair("fields", "user(permissionId)");
        }
        ReadEndpoint::GoogleDriveFiles { cursor } => {
            p.url
                .query_pairs_mut()
                .append_pair("fields", DRIVE_FIELDS)
                .append_pair("pageSize", "1000")
                .append_pair("corpora", "user")
                .append_pair("spaces", "drive")
                .append_pair("includeItemsFromAllDrives", "true")
                .append_pair("supportsAllDrives", "true")
                .append_pair("q", "trashed=false");
            if let Some(c) = cursor {
                validate_cursor(c)?;
                p.url.query_pairs_mut().append_pair("pageToken", c);
            }
        }
        ReadEndpoint::GoogleUserInfo => {}
        ReadEndpoint::GraphMe => {
            p.url.query_pairs_mut().append_pair("$select", "id");
        }
        ReadEndpoint::GraphDrives { cursor } => {
            p.url
                .query_pairs_mut()
                .append_pair("$select", "id,driveType,name,owner")
                .append_pair("$top", "100");
            if let Some(cursor) = cursor {
                validate_cursor(cursor)?;
                p.url.query_pairs_mut().append_pair("$skiptoken", cursor);
            }
        }
        ReadEndpoint::GraphChildren {
            drive_id,
            folder_id,
            cursor,
        } => {
            identifier(drive_id)?;
            {
                let mut segments = p
                    .url
                    .path_segments_mut()
                    .map_err(|_| CloudHttpError::InvalidIdentifier)?;
                segments.push(drive_id);
                if let Some(folder) = folder_id {
                    identifier(folder)?;
                    segments.push("items").push(folder);
                } else {
                    segments.push("root");
                }
                segments.push("children");
            }
            p.url
                .query_pairs_mut()
                .append_pair("$top", "200")
                .append_pair("$select", GRAPH_FIELDS);
            if let Some(cursor) = cursor {
                validate_cursor(cursor)?;
                p.url.query_pairs_mut().append_pair("$skiptoken", cursor);
            }
        }
        ReadEndpoint::GmailMessages { cursor } => {
            p.url
                .query_pairs_mut()
                .append_pair("maxResults", "25")
                .append_pair("includeSpamTrash", "false")
                .append_pair(
                    "fields",
                    "messages(id,threadId),nextPageToken,resultSizeEstimate",
                );
            if let Some(c) = cursor {
                validate_cursor(c)?;
                p.url.query_pairs_mut().append_pair("pageToken", c);
            }
        }
        ReadEndpoint::GmailMessage { id } => {
            identifier(id)?;
            p.url
                .path_segments_mut()
                .map_err(|_| CloudHttpError::InvalidIdentifier)?
                .push(id);
            p.url.query_pairs_mut().append_pair("format","metadata").append_pair("metadataHeaders","Subject")
                .append_pair("fields","id,threadId,labelIds,sizeEstimate,internalDate,historyId,payload(headers(name,value))");
        }
        ReadEndpoint::DropboxAccount => p.method = Method::POST,
        ReadEndpoint::DropboxFiles { root_namespace }
        | ReadEndpoint::DropboxContinue { root_namespace, .. } => {
            identifier(root_namespace)?;
            p.method = Method::POST;
            let root =
                serde_json::to_string(&serde_json::json!({".tag":"root","root":root_namespace}))
                    .map_err(|_| CloudHttpError::InvalidIdentifier)?;
            let mut header = header::HeaderValue::from_str(&root)
                .map_err(|_| CloudHttpError::InvalidIdentifier)?;
            header.set_sensitive(true);
            p.path_root = Some(header);
            p.body=Some(match endpoint {
                ReadEndpoint::DropboxContinue {cursor,..}=>{validate_cursor(cursor)?;serde_json::to_vec(&serde_json::json!({"cursor":cursor}))},
                _=>serde_json::to_vec(&serde_json::json!({"path":"","recursive":true,"include_deleted":false,"include_mounted_folders":true,"include_non_downloadable_files":true,"limit":1000})),
            }.map_err(|_|CloudHttpError::InvalidResponse)?);
        }
    }
    Ok(p)
}
pub(crate) fn read_url(endpoint: &ReadEndpoint<'_>) -> Result<Url, CloudHttpError> {
    Ok(request_parts(endpoint)?.url)
}

pub(crate) struct MetadataHttp {
    client: Client,
    token: AccessToken,
}
impl MetadataHttp {
    pub(crate) fn new(token: AccessToken) -> Result<Self, CloudHttpError> {
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .referer(false)
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| CloudHttpError::ClientUnavailable)?;
        Ok(Self { client, token })
    }
    pub(crate) fn read(
        &mut self,
        endpoint: ReadEndpoint<'_>,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Result<Vec<u8>, CloudHttpError> {
        if cancel.load(Ordering::Relaxed) {
            return Err(CloudHttpError::Cancelled);
        }
        let deadline = deadline.min(Instant::now() + Duration::from_secs(30));
        if Instant::now() >= deadline {
            return Err(CloudHttpError::TimedOut);
        }
        let p = request_parts(&endpoint)?;
        let mut request = self
            .client
            .request(p.method, p.url)
            .bearer_auth(self.token.0.as_str())
            .header(header::ACCEPT, "application/json")
            .timeout(deadline.saturating_duration_since(Instant::now()));
        if let Some(body) = p.body {
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        if let Some(root) = p.path_root {
            request = request.header("Dropbox-API-Path-Root", root);
        }
        let response = request.send();
        if cancel.load(Ordering::Relaxed) {
            return Err(CloudHttpError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(CloudHttpError::TimedOut);
        }
        let mut response = response.map_err(|e| {
            if e.is_timeout() {
                CloudHttpError::TimedOut
            } else {
                CloudHttpError::Transport
            }
        })?;
        if !response.status().is_success() {
            return Err(CloudHttpError::HttpStatus(response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(CloudHttpError::ResponseLimit);
        }
        if response.headers().contains_key(header::CONTENT_ENCODING) {
            return Err(CloudHttpError::InvalidResponse);
        }
        read_bounded(&mut response, cancel, deadline)
    }
}
pub(crate) fn read_bounded(
    input: &mut impl Read,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<Vec<u8>, CloudHttpError> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(CloudHttpError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(CloudHttpError::TimedOut);
        }
        let allowance = (MAX_RESPONSE_BYTES - bytes.len() + 1).min(chunk.len());
        let read = input.read(&mut chunk[..allowance]);
        if cancel.load(Ordering::Relaxed) {
            return Err(CloudHttpError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(CloudHttpError::TimedOut);
        }
        let count = read.map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                CloudHttpError::TimedOut
            } else {
                CloudHttpError::Transport
            }
        })?;
        if count == 0 {
            return Ok(bytes);
        }
        if bytes.len().saturating_add(count) > MAX_RESPONSE_BYTES {
            return Err(CloudHttpError::ResponseLimit);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dropbox_read_rpc_body_cannot_select_mutation_or_change_the_origin() {
        let p = request_parts(&ReadEndpoint::DropboxContinue {
            root_namespace: "root-id",
            cursor: "opaque & https://invalid/#",
        })
        .unwrap();
        assert_eq!(p.method, Method::POST);
        assert_eq!(
            p.url.as_str(),
            "https://api.dropboxapi.com/2/files/list_folder/continue"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&p.body.unwrap()).unwrap()["cursor"],
            "opaque & https://invalid/#"
        );
        assert!(p.path_root.unwrap().is_sensitive());
        let p = request_parts(&ReadEndpoint::DropboxFiles {
            root_namespace: "root-id",
        })
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&p.body.unwrap()).unwrap();
        assert_eq!(body["recursive"], true);
        assert_eq!(body["include_deleted"], false);
        assert_eq!(body["limit"], 1000);
    }
    #[test]
    fn gmail_identifier_is_one_encoded_path_segment_and_body_download_is_unavailable() {
        let p = request_parts(&ReadEndpoint::GmailMessage {
            id: "opaque/../?format=raw#",
        })
        .unwrap();
        assert_eq!(p.method, Method::GET);
        assert_eq!(p.url.host_str(), Some("gmail.googleapis.com"));
        assert!(p.url.fragment().is_none());
        assert!(p.url.path().contains("opaque%2F..%2F%3Fformat=raw%23"));
        assert_eq!(
            p.url.query_pairs().find(|(k, _)| k == "format").unwrap().1,
            "metadata"
        );
        assert!(p.body.is_none());
        assert!(matches!(
            request_parts(&ReadEndpoint::GmailMessage { id: ".." }),
            Err(CloudHttpError::InvalidIdentifier)
        ));
    }
}
