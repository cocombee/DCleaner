//! Native OAuth authorization, refresh and bounded credential records.
//!
//! No provider registration is embedded here. The authorization method is the
//! only entry point that starts a loopback listener or opens the system
//! browser; refresh performs one fixed HTTPS token request without retry.

use crate::{
    cloud_http::AccessToken,
    cloud_inventory::Provider,
    cloud_vault::{SecretVault, VaultError, VaultKey},
};
use oauth2::{CsrfToken, PkceCodeChallenge};
use reqwest::{Url, blocking::Client, header};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_REGISTRATION_BYTES: usize = 8 * 1024;
const MAX_TOKEN_RECORD_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_SCOPE_COUNT: usize = 32;
const MAX_SCOPE_BYTES: usize = 512;
const MAX_HTTP_RESPONSE_BYTES: usize = 64 * 1024;
const AUTH_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const TOKEN_TIMEOUT: Duration = Duration::from_secs(30);
const CALLBACK_PATH: &str = "/oauth2/callback";
const CALLBACK_REQUEST_LIMIT: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RegistrationFamily {
    Google,
    Microsoft,
    Dropbox,
}

impl RegistrationFamily {
    const fn tag(self) -> u8 {
        match self {
            Self::Google => 1,
            Self::Microsoft => 2,
            Self::Dropbox => 3,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Google),
            2 => Some(Self::Microsoft),
            3 => Some(Self::Dropbox),
            _ => None,
        }
    }
}

/// Public client configuration supplied by the operator. Google Drive and
/// Gmail share one Google client registration; authorization scopes stay
/// provider-specific. Client secrets are never exposed by a getter or Debug.
#[derive(Clone)]
pub struct ClientRegistration {
    family: RegistrationFamily,
    client_id: Zeroizing<String>,
    google_desktop_secret: Option<Zeroizing<String>>,
}

impl ClientRegistration {
    pub fn new(
        family: RegistrationFamily,
        client_id: String,
        google_desktop_secret: Option<String>,
    ) -> Result<Self, AuthError> {
        let client_id = Zeroizing::new(client_id);
        if !valid_registration_value(&client_id, 1024) {
            return Err(AuthError::InvalidRegistration);
        }
        let secret = match (family, google_desktop_secret) {
            (RegistrationFamily::Google, Some(value)) => {
                let value = Zeroizing::new(value);
                if !valid_registration_value(&value, 2048) {
                    return Err(AuthError::InvalidRegistration);
                }
                Some(value)
            }
            (RegistrationFamily::Google, None)
            | (RegistrationFamily::Microsoft, None)
            | (RegistrationFamily::Dropbox, None) => None,
            _ => return Err(AuthError::InvalidRegistration),
        };
        Ok(Self {
            family,
            client_id,
            google_desktop_secret: secret,
        })
    }

    pub const fn family(&self) -> RegistrationFamily {
        self.family
    }

    /// Client IDs/app keys are public registration identifiers, not tokens.
    pub fn client_id(&self) -> &str {
        self.client_id.as_str()
    }

    pub fn save_to(&self, vault: &mut dyn SecretVault) -> Result<(), VaultError> {
        let bytes = self.encode().map_err(|_| VaultError::InvalidData)?;
        vault.put(VaultKey::Registration(self.family), &bytes)
    }

    pub fn load_from(
        vault: &mut dyn SecretVault,
        family: RegistrationFamily,
    ) -> Result<Option<Self>, VaultError> {
        let Some(bytes) = vault.get(VaultKey::Registration(family))? else {
            return Ok(None);
        };
        let registration = Self::decode(&bytes).map_err(|_| VaultError::InvalidData)?;
        if registration.family != family {
            return Err(VaultError::InvalidData);
        }
        Ok(Some(registration))
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        let id = self.client_id.as_bytes();
        let secret = self
            .google_desktop_secret
            .as_ref()
            .map(|s| s.as_bytes())
            .unwrap_or_default();
        if id.len() > 1024 || secret.len() > 2048 {
            return Err(AuthError::InvalidRegistration);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(16 + id.len() + secret.len()));
        out.extend_from_slice(b"DCRG\x01");
        out.push(self.family.tag());
        push_u16(&mut out, id.len())?;
        out.extend_from_slice(id);
        push_u16(&mut out, secret.len())?;
        out.extend_from_slice(secret);
        if out.len() > MAX_REGISTRATION_BYTES {
            return Err(AuthError::InvalidRegistration);
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.len() > MAX_REGISTRATION_BYTES || bytes.len() < 10 || &bytes[..5] != b"DCRG\x01" {
            return Err(AuthError::InvalidRegistration);
        }
        let mut reader = RecordReader::new(&bytes[5..]);
        let family =
            RegistrationFamily::from_tag(reader.byte()?).ok_or(AuthError::InvalidRegistration)?;
        let client_id = reader.string(1024)?;
        let secret = reader.secret_string(2048)?;
        if !reader.finished() {
            return Err(AuthError::InvalidRegistration);
        }
        let secret = if secret.is_empty() {
            None
        } else {
            Some(secret.to_string())
        };
        Self::new(family, client_id, secret)
    }
}

impl fmt::Debug for ClientRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientRegistration")
            .field("family", &self.family)
            .field("client_id", &"[redacted]")
            .field(
                "google_desktop_secret",
                &self.google_desktop_secret.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// Provider token data is intentionally not serializable or printable.
pub struct TokenSet {
    provider: Provider,
    account_id: Uuid,
    client_id: Zeroizing<String>,
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    expires_at_unix_seconds: u64,
    scopes: Vec<String>,
}

impl Clone for TokenSet {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider,
            account_id: self.account_id,
            client_id: self.client_id.clone(),
            access_token: self.access_token.clone(),
            refresh_token: self.refresh_token.clone(),
            expires_at_unix_seconds: self.expires_at_unix_seconds,
            scopes: self.scopes.clone(),
        }
    }
}

impl TokenSet {
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    pub const fn account_id(&self) -> Uuid {
        self.account_id
    }

    /// Public OAuth client registration identifier this token set was issued
    /// to. Controllers should compare it with the selected registration before
    /// using or refreshing these credentials.
    pub fn registration_client_id(&self) -> &str {
        self.client_id.as_str()
    }

    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.scopes.iter().map(String::as_str)
    }

    pub fn has_refresh_token(&self) -> bool {
        self.refresh_token.is_some()
    }

    /// Makes a temporary transport token. The returned type also suppresses
    /// Debug/serialization and zeroizes its owned string on drop.
    pub fn access_token(&self) -> Result<AccessToken, AuthError> {
        AccessToken::new(self.access_token.to_string()).map_err(|_| AuthError::InvalidTokenRecord)
    }

    /// Changes only the local vault identity. The controller must first verify
    /// that a fresh provider scope exactly matches the existing account scope;
    /// this method does not make or assert that provider identity claim.
    pub fn rebind_account(mut self, existing_local_uuid: Uuid) -> Result<Self, AuthError> {
        if existing_local_uuid.is_nil() {
            return Err(AuthError::InvalidTokenRecord);
        }
        self.account_id = existing_local_uuid;
        Ok(self)
    }

    pub fn save_to(&self, vault: &mut dyn SecretVault) -> Result<(), VaultError> {
        let bytes = self.encode().map_err(|_| VaultError::InvalidData)?;
        vault.put(VaultKey::Account(self.account_id), &bytes)
    }

    pub fn load_from(
        vault: &mut dyn SecretVault,
        account_id: Uuid,
    ) -> Result<Option<Self>, VaultError> {
        if account_id.is_nil() {
            return Err(VaultError::InvalidKey);
        }
        let Some(bytes) = vault.get(VaultKey::Account(account_id))? else {
            return Ok(None);
        };
        let tokens = Self::decode(&bytes).map_err(|_| VaultError::InvalidData)?;
        if tokens.account_id != account_id {
            return Err(VaultError::InvalidData);
        }
        Ok(Some(tokens))
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        if self.account_id.is_nil()
            || !valid_registration_value(&self.client_id, 1024)
            || !valid_token(&self.access_token)
            || self
                .refresh_token
                .as_ref()
                .is_some_and(|token| !valid_opaque_secret(token, MAX_TOKEN_BYTES))
            || self.scopes.len() > MAX_SCOPE_COUNT
        {
            return Err(AuthError::InvalidTokenRecord);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(512));
        out.extend_from_slice(b"DCTK\x02");
        out.push(provider_tag(self.provider));
        out.extend_from_slice(self.account_id.as_bytes());
        push_u16(&mut out, self.client_id.len())?;
        out.extend_from_slice(self.client_id.as_bytes());
        out.extend_from_slice(&self.expires_at_unix_seconds.to_le_bytes());
        push_u16(&mut out, self.access_token.len())?;
        out.extend_from_slice(self.access_token.as_bytes());
        let refresh = self
            .refresh_token
            .as_ref()
            .map(|s| s.as_bytes())
            .unwrap_or_default();
        push_u16(&mut out, refresh.len())?;
        out.extend_from_slice(refresh);
        push_u16(&mut out, self.scopes.len())?;
        for scope in &self.scopes {
            if !valid_scope(scope) {
                return Err(AuthError::InvalidTokenRecord);
            }
            push_u16(&mut out, scope.len())?;
            out.extend_from_slice(scope.as_bytes());
        }
        if out.len() > MAX_TOKEN_RECORD_BYTES {
            return Err(AuthError::InvalidTokenRecord);
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.len() > MAX_TOKEN_RECORD_BYTES || bytes.len() < 36 || &bytes[..5] != b"DCTK\x02" {
            return Err(AuthError::InvalidTokenRecord);
        }
        let mut reader = RecordReader::new(&bytes[5..]);
        let provider = provider_from_tag(reader.byte()?).ok_or(AuthError::InvalidTokenRecord)?;
        let account_id =
            Uuid::from_slice(reader.take(16)?).map_err(|_| AuthError::InvalidTokenRecord)?;
        if account_id.is_nil() {
            return Err(AuthError::InvalidTokenRecord);
        }
        let client_id = reader.secret_string(1024)?;
        if !valid_registration_value(&client_id, 1024) {
            return Err(AuthError::InvalidTokenRecord);
        }
        let expires_at_unix_seconds = u64::from_le_bytes(reader.take(8)?.try_into().unwrap());
        let access_token = reader.secret_string(MAX_TOKEN_BYTES)?;
        if !valid_token(&access_token) {
            return Err(AuthError::InvalidTokenRecord);
        }
        let refresh_token = reader.secret_string(MAX_TOKEN_BYTES)?;
        let refresh_token = if refresh_token.is_empty() {
            None
        } else {
            Some(refresh_token)
        };
        if refresh_token
            .as_ref()
            .is_some_and(|value| !valid_opaque_secret(value, MAX_TOKEN_BYTES))
        {
            return Err(AuthError::InvalidTokenRecord);
        }
        let count = usize::from(reader.u16()?);
        if count > MAX_SCOPE_COUNT {
            return Err(AuthError::InvalidTokenRecord);
        }
        let mut scopes = Vec::with_capacity(count);
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let scope = reader.string(MAX_SCOPE_BYTES)?;
            if !valid_scope(&scope) || !seen.insert(scope.clone()) {
                return Err(AuthError::InvalidTokenRecord);
            }
            scopes.push(scope);
        }
        if !reader.finished() {
            return Err(AuthError::InvalidTokenRecord);
        }
        Ok(Self {
            provider,
            account_id,
            client_id,
            access_token,
            refresh_token,
            expires_at_unix_seconds,
            scopes,
        })
    }
}

impl fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSet")
            .field("provider", &self.provider)
            .field("account_id", &"[redacted]")
            .field("client_id", &"[redacted]")
            .field("access_token", &"[redacted]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .field("scope_count", &self.scopes.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthProgress {
    OpeningBrowser,
    WaitingForCallback,
    ExchangingCode,
    RefreshingToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    InvalidRegistration,
    ProviderMismatch,
    InvalidTokenRecord,
    RegistrationMismatch,
    InvalidCallback,
    UserDenied,
    AuthorizationRejected,
    Cancelled,
    TimedOut,
    ListenerUnavailable,
    BrowserUnavailable,
    ClientUnavailable,
    Transport,
    HttpStatus(u16),
    ResponseLimit,
    InvalidResponse,
    InsufficientScope,
    MissingRefreshToken,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRegistration => "The provider client registration is invalid.",
            Self::ProviderMismatch => "The provider does not match this client registration.",
            Self::InvalidTokenRecord => "The protected provider token record is invalid.",
            Self::RegistrationMismatch => {
                "The provider token belongs to a different client registration."
            }
            Self::InvalidCallback => "The local authorization callback was invalid.",
            Self::UserDenied => "Authorization was declined by the user.",
            Self::AuthorizationRejected => "The provider rejected the authorization request.",
            Self::Cancelled => "Authorization was cancelled.",
            Self::TimedOut => "Authorization exceeded its time limit.",
            Self::ListenerUnavailable => "The local authorization callback could not be opened.",
            Self::BrowserUnavailable => "The system browser handoff failed.",
            Self::ClientUnavailable => "The secure token client could not be initialized.",
            Self::Transport => "The provider token request failed; no automatic retry was made.",
            Self::HttpStatus(code) => {
                return write!(
                    f,
                    "The provider returned HTTP {code}; no automatic retry was made."
                );
            }
            Self::ResponseLimit => "The provider token response exceeded its safe size limit.",
            Self::InvalidResponse => "The provider token response was invalid or incomplete.",
            Self::InsufficientScope => {
                "The provider did not grant the requested cloud access scope."
            }
            Self::MissingRefreshToken => {
                "The protected account has no refresh token; reconnect is required."
            }
        })
    }
}

impl std::error::Error for AuthError {}

/// Opaque validated provider authorization URL. Callers should hand it to the
/// system browser and must not log it because it includes one-time OAuth state.
pub struct AuthorizationUrl(Zeroizing<String>);

impl AuthorizationUrl {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Browser seam. Native production flows pass only a fixed-provider HTTPS URL.
pub trait BrowserPort {
    fn open(&mut self, url: &AuthorizationUrl) -> Result<(), AuthError>;
}

pub struct NativeAuthorizer;

impl NativeAuthorizer {
    /// Starts one explicit system-browser PKCE flow and a loopback receiver.
    pub fn authorize(
        provider: Provider,
        registration: &ClientRegistration,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(AuthProgress),
    ) -> Result<TokenSet, AuthError> {
        let plan = AuthPlan::new(provider, registration.family)?;
        let mut callback = LoopbackCallback::bind(&plan)?;
        let mut browser = NativeBrowser;
        let mut tokens = NativeTokenHttp::new()?;
        let redirect_uri = callback.redirect_uri().to_owned();
        authorize_with_ports(
            provider,
            registration,
            &plan,
            &redirect_uri,
            &mut callback,
            &mut browser,
            &mut tokens,
            cancel,
            progress,
        )
    }

    /// Exchanges one refresh token for a fresh access token. A provider may
    /// rotate refresh tokens; when it does not, the existing token is kept.
    pub fn refresh(
        provider: Provider,
        registration: &ClientRegistration,
        tokens: &TokenSet,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(AuthProgress),
    ) -> Result<TokenSet, AuthError> {
        let plan = AuthPlan::new(provider, registration.family)?;
        if tokens.provider != provider {
            return Err(AuthError::ProviderMismatch);
        }
        if tokens.client_id.as_str() != registration.client_id() {
            return Err(AuthError::RegistrationMismatch);
        }
        let refresh = tokens
            .refresh_token
            .as_ref()
            .ok_or(AuthError::MissingRefreshToken)?;
        check_cancel(cancel)?;
        progress(AuthProgress::RefreshingToken);
        let mut token_http = NativeTokenHttp::new()?;
        let response = token_http.refresh(&plan, registration, refresh, cancel)?;
        if cancel.load(Ordering::Relaxed) {
            return Err(AuthError::Cancelled);
        }
        token_set_from_response(
            provider,
            tokens.account_id,
            response,
            Some(tokens),
            &plan,
            registration.client_id(),
        )
    }
}

#[derive(Clone)]
struct AuthPlan {
    provider: Provider,
    family: RegistrationFamily,
    authorize_endpoint: &'static str,
    token_endpoint: &'static str,
    scopes: Vec<&'static str>,
    required_scopes: Vec<&'static str>,
    redirect_mode: RedirectMode,
}

#[derive(Clone, Copy)]
enum RedirectMode {
    DynamicIp,
    DynamicLocalhost,
    DropboxFixed,
}

impl AuthPlan {
    fn new(provider: Provider, family: RegistrationFamily) -> Result<Self, AuthError> {
        let correct = match provider {
            Provider::GoogleDrive | Provider::Gmail => family == RegistrationFamily::Google,
            Provider::OneDrive => family == RegistrationFamily::Microsoft,
            Provider::Dropbox => family == RegistrationFamily::Dropbox,
        };
        if !correct {
            return Err(AuthError::ProviderMismatch);
        }
        Ok(match provider {
            Provider::GoogleDrive => Self {
                provider,
                family,
                authorize_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
                token_endpoint: "https://oauth2.googleapis.com/token",
                scopes: vec!["openid", "https://www.googleapis.com/auth/drive"],
                required_scopes: vec!["openid", "https://www.googleapis.com/auth/drive"],
                redirect_mode: RedirectMode::DynamicIp,
            },
            Provider::Gmail => Self {
                provider,
                family,
                authorize_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
                token_endpoint: "https://oauth2.googleapis.com/token",
                scopes: vec!["openid", "https://www.googleapis.com/auth/gmail.modify"],
                required_scopes: vec!["openid", "https://www.googleapis.com/auth/gmail.modify"],
                redirect_mode: RedirectMode::DynamicIp,
            },
            Provider::OneDrive => Self {
                provider,
                family,
                authorize_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                token_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                scopes: vec!["openid", "offline_access", "User.Read", "Files.ReadWrite"],
                required_scopes: vec!["User.Read", "Files.ReadWrite"],
                redirect_mode: RedirectMode::DynamicLocalhost,
            },
            Provider::Dropbox => Self {
                provider,
                family,
                authorize_endpoint: "https://www.dropbox.com/oauth2/authorize",
                token_endpoint: "https://api.dropbox.com/oauth2/token",
                scopes: vec![
                    "account_info.read",
                    "files.metadata.read",
                    "files.content.write",
                ],
                required_scopes: vec![
                    "account_info.read",
                    "files.metadata.read",
                    "files.content.write",
                ],
                redirect_mode: RedirectMode::DropboxFixed,
            },
        })
    }

    fn scope_string(&self) -> String {
        self.scopes.join(" ")
    }

    fn redirect_for(&self, port: u16) -> String {
        match self.redirect_mode {
            RedirectMode::DynamicIp => {
                format!("http://127.0.0.1:{port}{CALLBACK_PATH}")
            }
            RedirectMode::DynamicLocalhost => {
                format!("http://localhost:{port}{CALLBACK_PATH}")
            }
            RedirectMode::DropboxFixed => {
                format!("http://127.0.0.1:{port}{CALLBACK_PATH}")
            }
        }
    }
}

fn authorize_with_ports<C, B, T>(
    provider: Provider,
    registration: &ClientRegistration,
    plan: &AuthPlan,
    redirect_uri: &str,
    callback: &mut C,
    browser: &mut B,
    token_http: &mut T,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(AuthProgress),
) -> Result<TokenSet, AuthError>
where
    C: CallbackPort,
    B: BrowserPort,
    T: TokenPort,
{
    if plan.provider != provider || plan.family != registration.family {
        return Err(AuthError::ProviderMismatch);
    }
    check_cancel(cancel)?;
    let state = CsrfToken::new_random();
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let url = build_authorization_url(registration, plan, redirect_uri, &state, &challenge)?;
    progress(AuthProgress::OpeningBrowser);
    browser.open(&url)?;
    progress(AuthProgress::WaitingForCallback);
    let code = callback.wait(state.secret(), cancel)?;
    check_cancel(cancel)?;
    progress(AuthProgress::ExchangingCode);
    let response = token_http.exchange_code(
        plan,
        registration,
        &code,
        verifier.secret(),
        redirect_uri,
        cancel,
    )?;
    if cancel.load(Ordering::Relaxed) {
        return Err(AuthError::Cancelled);
    }
    token_set_from_response(
        provider,
        Uuid::new_v4(),
        response,
        None,
        plan,
        registration.client_id(),
    )
}

fn build_authorization_url(
    registration: &ClientRegistration,
    plan: &AuthPlan,
    redirect_uri: &str,
    state: &CsrfToken,
    challenge: &PkceCodeChallenge,
) -> Result<AuthorizationUrl, AuthError> {
    let mut url =
        Url::parse(plan.authorize_endpoint).map_err(|_| AuthError::InvalidRegistration)?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("client_id", registration.client_id())
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &plan.scope_string())
            .append_pair("state", state.secret())
            .append_pair("code_challenge", challenge.as_str())
            .append_pair("code_challenge_method", "S256");
        match plan.provider {
            Provider::GoogleDrive | Provider::Gmail => {
                query.append_pair("access_type", "offline");
                query.append_pair("prompt", "consent");
                query.append_pair("include_granted_scopes", "true");
            }
            Provider::OneDrive => {
                query.append_pair("response_mode", "query");
            }
            Provider::Dropbox => {
                query.append_pair("token_access_type", "offline");
            }
        }
    }
    Ok(AuthorizationUrl(Zeroizing::new(url.into())))
}

trait CallbackPort {
    fn wait(&mut self, state: &str, cancel: &AtomicBool) -> Result<Zeroizing<String>, AuthError>;
}

struct LoopbackCallback {
    listener: TcpListener,
    redirect_uri: String,
    expected_host: String,
}

impl LoopbackCallback {
    fn bind(plan: &AuthPlan) -> Result<Self, AuthError> {
        let listener = match plan.redirect_mode {
            RedirectMode::DropboxFixed => TcpListener::bind(("127.0.0.1", 53682)),
            RedirectMode::DynamicIp | RedirectMode::DynamicLocalhost => {
                TcpListener::bind(("127.0.0.1", 0))
            }
        }
        .map_err(|_| AuthError::ListenerUnavailable)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| AuthError::ListenerUnavailable)?;
        let port = listener
            .local_addr()
            .map_err(|_| AuthError::ListenerUnavailable)?
            .port();
        let host = match plan.redirect_mode {
            RedirectMode::DynamicLocalhost => {
                format!("localhost:{port}")
            }
            RedirectMode::DynamicIp => format!("127.0.0.1:{port}"),
            RedirectMode::DropboxFixed => format!("127.0.0.1:{port}"),
        };
        Ok(Self {
            listener,
            redirect_uri: plan.redirect_for(port),
            expected_host: host,
        })
    }

    fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
}

impl CallbackPort for LoopbackCallback {
    fn wait(&mut self, state: &str, cancel: &AtomicBool) -> Result<Zeroizing<String>, AuthError> {
        let deadline = Instant::now() + AUTH_TIMEOUT;
        loop {
            check_cancel(cancel)?;
            if Instant::now() >= deadline {
                return Err(AuthError::TimedOut);
            }
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
                    let result =
                        read_and_validate_callback(&mut stream, &self.expected_host, state);
                    let valid_oauth_response = result.is_ok()
                        || matches!(
                            &result,
                            Err(AuthError::UserDenied | AuthError::AuthorizationRejected)
                        );
                    let (status, body) = if valid_oauth_response {
                        (
                            "200 OK",
                            "Authorization response received. You can return to DCleaner.\n",
                        )
                    } else {
                        ("400 Bad Request", "Invalid authorization callback.\n")
                    };
                    let header = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(body.as_bytes());
                    return result;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(_) => return Err(AuthError::ListenerUnavailable),
            }
        }
    }
}

fn read_and_validate_callback(
    stream: &mut TcpStream,
    expected_host: &str,
    expected_state: &str,
) -> Result<Zeroizing<String>, AuthError> {
    let mut request = Zeroizing::new(Vec::with_capacity(1024));
    let mut byte = [0u8; 1];
    while request.len() < CALLBACK_REQUEST_LIMIT {
        match stream.read(&mut byte) {
            Ok(0) => return Err(AuthError::InvalidCallback),
            Ok(_) => {
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return Err(AuthError::InvalidCallback),
        }
    }
    if request.len() >= CALLBACK_REQUEST_LIMIT || !request.ends_with(b"\r\n\r\n") {
        return Err(AuthError::InvalidCallback);
    }
    parse_callback_request(&request, expected_host, expected_state)
}

fn parse_callback_request(
    request: &[u8],
    expected_host: &str,
    expected_state: &str,
) -> Result<Zeroizing<String>, AuthError> {
    let text = std::str::from_utf8(request).map_err(|_| AuthError::InvalidCallback)?;
    if text
        .chars()
        .any(|c| c.is_control() && c != '\r' && c != '\n')
    {
        return Err(AuthError::InvalidCallback);
    }
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(AuthError::InvalidCallback)?;
    let mut parts = request_line.split(' ');
    if parts.next() != Some("GET") {
        return Err(AuthError::InvalidCallback);
    }
    let target = parts.next().ok_or(AuthError::InvalidCallback)?;
    if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) || parts.next().is_some() {
        return Err(AuthError::InvalidCallback);
    }
    if target.starts_with("//") || target.contains('#') || target.contains(' ') {
        return Err(AuthError::InvalidCallback);
    }
    let (path, raw_query) = target.split_once('?').ok_or(AuthError::InvalidCallback)?;
    if path != CALLBACK_PATH || raw_query.is_empty() || !valid_percent_encoding(raw_query) {
        return Err(AuthError::InvalidCallback);
    }
    let mut hosts = 0usize;
    let mut lengths = 0usize;
    let mut content_length_zero = true;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(AuthError::InvalidCallback);
        }
        let (name, value) = line.split_once(':').ok_or(AuthError::InvalidCallback)?;
        if name.eq_ignore_ascii_case("host") {
            hosts += 1;
            if !value.trim().eq_ignore_ascii_case(expected_host) {
                return Err(AuthError::InvalidCallback);
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(AuthError::InvalidCallback);
        } else if name.eq_ignore_ascii_case("content-length") {
            lengths += 1;
            if value.trim() != "0" {
                content_length_zero = false;
            }
        }
    }
    if hosts != 1 || lengths > 1 || !content_length_zero {
        return Err(AuthError::InvalidCallback);
    }

    let url =
        Url::parse(&format!("http://127.0.0.1{target}")).map_err(|_| AuthError::InvalidCallback)?;
    let mut params = BTreeMap::<String, Zeroizing<String>>::new();
    for (key, value) in url.query_pairs() {
        if key.is_empty() || key.len() > 64 || value.len() > 4096 {
            return Err(AuthError::InvalidCallback);
        }
        if !allowed_callback_parameter(&key) || params.contains_key(key.as_ref()) {
            return Err(AuthError::InvalidCallback);
        }
        params.insert(key.into_owned(), Zeroizing::new(value.into_owned()));
    }
    let received_state = params.get("state").ok_or(AuthError::InvalidCallback)?;
    if received_state.len() != expected_state.len() {
        return Err(AuthError::InvalidCallback);
    }
    let equal = received_state
        .as_bytes()
        .ct_eq(expected_state.as_bytes())
        .unwrap_u8()
        == 1;
    if !equal {
        return Err(AuthError::InvalidCallback);
    }
    let code = params.remove("code");
    let error = params.remove("error");
    match (code, error) {
        (Some(code), None) if valid_opaque_secret(&code, 4096) => Ok(code),
        (None, Some(error)) if error.as_str() == "access_denied" => Err(AuthError::UserDenied),
        (None, Some(_)) => Err(AuthError::AuthorizationRejected),
        _ => Err(AuthError::InvalidCallback),
    }
}

fn allowed_callback_parameter(value: &str) -> bool {
    matches!(
        value,
        "state"
            | "code"
            | "error"
            | "error_description"
            | "error_uri"
            | "scope"
            | "authuser"
            | "prompt"
            | "session_state"
            | "iss"
            | "error_subcode"
            | "error_codes"
            | "timestamp"
            | "trace_id"
            | "correlation_id"
    )
}

fn valid_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

trait TokenPort {
    fn exchange_code(
        &mut self,
        plan: &AuthPlan,
        registration: &ClientRegistration,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        cancel: &AtomicBool,
    ) -> Result<TokenResponse, AuthError>;

    fn refresh(
        &mut self,
        plan: &AuthPlan,
        registration: &ClientRegistration,
        refresh_token: &str,
        cancel: &AtomicBool,
    ) -> Result<TokenResponse, AuthError>;
}

#[derive(Deserialize)]
struct RawTokenResponse {
    #[serde(deserialize_with = "deserialize_secret")]
    access_token: SecretText,
    token_type: String,
    expires_in: u64,
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    refresh_token: Option<SecretText>,
    scope: Option<String>,
}

struct SecretText(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_string(SecretTextVisitor)
    }
}

struct SecretTextVisitor;
impl<'de> serde::de::Visitor<'de> for SecretTextVisitor {
    type Value = SecretText;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded OAuth token string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(SecretText(Zeroizing::new(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(SecretText(Zeroizing::new(value)))
    }
}

fn deserialize_secret<'de, D>(deserializer: D) -> Result<SecretText, D::Error>
where
    D: serde::Deserializer<'de>,
{
    SecretText::deserialize(deserializer)
}

fn deserialize_optional_secret<'de, D>(deserializer: D) -> Result<Option<SecretText>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<SecretText>::deserialize(deserializer)
}

struct TokenResponse {
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    expires_in: u64,
    scopes: Option<Vec<String>>,
}

impl TryFrom<RawTokenResponse> for TokenResponse {
    type Error = AuthError;

    fn try_from(raw: RawTokenResponse) -> Result<Self, Self::Error> {
        if !raw.token_type.eq_ignore_ascii_case("bearer")
            || !valid_token(&raw.access_token.0)
            || raw.expires_in == 0
            || raw.expires_in > 365 * 24 * 60 * 60
        {
            return Err(AuthError::InvalidResponse);
        }
        let scopes = raw.scope.map(parse_scopes).transpose()?;
        Ok(Self {
            access_token: raw.access_token.0,
            refresh_token: raw.refresh_token.map(|token| token.0),
            expires_in: raw.expires_in,
            scopes,
        })
    }
}

fn parse_scopes(value: String) -> Result<Vec<String>, AuthError> {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for scope in value.split_ascii_whitespace() {
        if !valid_scope(scope) || !seen.insert(scope.to_owned()) || result.len() == MAX_SCOPE_COUNT
        {
            return Err(AuthError::InvalidResponse);
        }
        result.push(scope.to_owned());
    }
    Ok(result)
}

struct NativeTokenHttp {
    client: Client,
}

impl NativeTokenHttp {
    fn new() -> Result<Self, AuthError> {
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .no_proxy()
            .referer(false)
            .connect_timeout(Duration::from_secs(10))
            .timeout(TOKEN_TIMEOUT)
            .build()
            .map_err(|_| AuthError::ClientUnavailable)?;
        Ok(Self { client })
    }

    fn post(
        &mut self,
        plan: &AuthPlan,
        fields: &[(&str, &str)],
        cancel: &AtomicBool,
    ) -> Result<TokenResponse, AuthError> {
        check_cancel(cancel)?;
        let deadline = Instant::now() + TOKEN_TIMEOUT;
        let mut response = self
            .client
            .post(plan.token_endpoint)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .timeout(deadline.saturating_duration_since(Instant::now()))
            .form(fields)
            .send()
            .map_err(map_reqwest)?;
        if cancel.load(Ordering::Relaxed) {
            return Err(AuthError::Cancelled);
        }
        if !response.status().is_success() {
            return Err(AuthError::HttpStatus(response.status().as_u16()));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .by_ref()
            .take((MAX_HTTP_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::TimedOut {
                    AuthError::TimedOut
                } else {
                    AuthError::Transport
                }
            })?;
        if bytes.len() > MAX_HTTP_RESPONSE_BYTES {
            return Err(AuthError::ResponseLimit);
        }
        let parsed: RawTokenResponse =
            serde_json::from_slice(&bytes).map_err(|_| AuthError::InvalidResponse)?;
        TokenResponse::try_from(parsed)
    }
}

impl TokenPort for NativeTokenHttp {
    fn exchange_code(
        &mut self,
        plan: &AuthPlan,
        registration: &ClientRegistration,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        cancel: &AtomicBool,
    ) -> Result<TokenResponse, AuthError> {
        let client_id = registration.client_id();
        let grant_type = "authorization_code";
        let mut fields = vec![
            ("grant_type", grant_type),
            ("client_id", client_id),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", redirect_uri),
        ];
        if let Some(secret) = registration.google_desktop_secret.as_ref() {
            fields.push(("client_secret", secret.as_str()));
        }
        self.post(plan, &fields, cancel)
    }

    fn refresh(
        &mut self,
        plan: &AuthPlan,
        registration: &ClientRegistration,
        refresh_token: &str,
        cancel: &AtomicBool,
    ) -> Result<TokenResponse, AuthError> {
        let client_id = registration.client_id();
        let grant_type = "refresh_token";
        let scope = plan.scope_string();
        let mut fields = vec![
            ("grant_type", grant_type),
            ("client_id", client_id),
            ("refresh_token", refresh_token),
        ];
        if plan.provider != Provider::Dropbox {
            fields.push(("scope", scope.as_str()));
        }
        if let Some(secret) = registration.google_desktop_secret.as_ref() {
            fields.push(("client_secret", secret.as_str()));
        }
        self.post(plan, &fields, cancel)
    }
}

fn map_reqwest(error: reqwest::Error) -> AuthError {
    if error.is_timeout() {
        AuthError::TimedOut
    } else {
        AuthError::Transport
    }
}

fn token_set_from_response(
    provider: Provider,
    account_id: Uuid,
    response: TokenResponse,
    previous: Option<&TokenSet>,
    plan: &AuthPlan,
    client_id: &str,
) -> Result<TokenSet, AuthError> {
    let scopes = response.scopes.unwrap_or_else(|| {
        previous.map(|old| old.scopes.clone()).unwrap_or_else(|| {
            plan.scopes
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect()
        })
    });
    if plan
        .required_scopes
        .iter()
        .any(|required| !scopes.iter().any(|scope| scope == required))
    {
        return Err(AuthError::InsufficientScope);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::InvalidResponse)?
        .as_secs();
    let expires_at_unix_seconds = now
        .checked_add(response.expires_in)
        .ok_or(AuthError::InvalidResponse)?;
    let refresh_token = response
        .refresh_token
        .or_else(|| previous.and_then(|old| old.refresh_token.clone()));
    Ok(TokenSet {
        provider,
        account_id,
        client_id: Zeroizing::new(client_id.to_owned()),
        access_token: response.access_token,
        refresh_token,
        expires_at_unix_seconds,
        scopes,
    })
}

struct NativeBrowser;

impl BrowserPort for NativeBrowser {
    fn open(&mut self, url: &AuthorizationUrl) -> Result<(), AuthError> {
        native_browser_handoff(url.as_str())
    }
}

#[cfg(windows)]
fn native_browser_handoff(url: &str) -> Result<(), AuthError> {
    use windows::{
        Win32::{
            Foundation::HINSTANCE,
            UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
        },
        core::{PCWSTR, w},
    };
    let wide: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    let result: HINSTANCE = unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            PCWSTR(wide.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if result.0 as isize <= 32 {
        Err(AuthError::BrowserUnavailable)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn native_browser_handoff(url: &str) -> Result<(), AuthError> {
    use std::process::Command;
    let status = Command::new("/usr/bin/open")
        .arg(url)
        .status()
        .map_err(|_| AuthError::BrowserUnavailable)?;
    if status.success() {
        Ok(())
    } else {
        Err(AuthError::BrowserUnavailable)
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn native_browser_handoff(_url: &str) -> Result<(), AuthError> {
    Err(AuthError::BrowserUnavailable)
}

fn check_cancel(cancel: &AtomicBool) -> Result<(), AuthError> {
    if cancel.load(Ordering::Relaxed) {
        Err(AuthError::Cancelled)
    } else {
        Ok(())
    }
}

fn valid_registration_value(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn valid_opaque_secret(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn valid_token(value: &str) -> bool {
    let trimmed = value.trim_end_matches('=');
    !value.is_empty()
        && value.len() <= MAX_TOKEN_BYTES
        && !trimmed.is_empty()
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte))
        && value.bytes().skip(trimmed.len()).all(|byte| byte == b'=')
}

fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCOPE_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn provider_tag(provider: Provider) -> u8 {
    match provider {
        Provider::GoogleDrive => 1,
        Provider::Gmail => 2,
        Provider::OneDrive => 3,
        Provider::Dropbox => 4,
    }
}

fn provider_from_tag(tag: u8) -> Option<Provider> {
    match tag {
        1 => Some(Provider::GoogleDrive),
        2 => Some(Provider::Gmail),
        3 => Some(Provider::OneDrive),
        4 => Some(Provider::Dropbox),
        _ => None,
    }
}

fn push_u16(out: &mut Vec<u8>, length: usize) -> Result<(), AuthError> {
    out.extend_from_slice(
        &u16::try_from(length)
            .map_err(|_| AuthError::InvalidTokenRecord)?
            .to_le_bytes(),
    );
    Ok(())
}

struct RecordReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> RecordReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], AuthError> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or(AuthError::InvalidTokenRecord)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(AuthError::InvalidTokenRecord)?;
        self.cursor = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, AuthError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, AuthError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn string(&mut self, max: usize) -> Result<String, AuthError> {
        let length = usize::from(self.u16()?);
        if length > max {
            return Err(AuthError::InvalidTokenRecord);
        }
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| AuthError::InvalidTokenRecord)
    }
    fn secret_string(&mut self, max: usize) -> Result<Zeroizing<String>, AuthError> {
        let length = usize::from(self.u16()?);
        if length > max {
            return Err(AuthError::InvalidTokenRecord);
        }
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| AuthError::InvalidTokenRecord)
    }
    fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(family: RegistrationFamily) -> ClientRegistration {
        ClientRegistration::new(
            family,
            "test-client-id-for-fixture".to_owned(),
            (family == RegistrationFamily::Google).then(|| "fixture-secret".to_owned()),
        )
        .unwrap()
    }

    #[test]
    fn provider_family_and_permissions_are_not_conflated() {
        assert!(AuthPlan::new(Provider::Gmail, RegistrationFamily::Google).is_ok());
        assert!(matches!(
            AuthPlan::new(Provider::OneDrive, RegistrationFamily::Google),
            Err(AuthError::ProviderMismatch)
        ));
        let drive = AuthPlan::new(Provider::GoogleDrive, RegistrationFamily::Google).unwrap();
        let gmail = AuthPlan::new(Provider::Gmail, RegistrationFamily::Google).unwrap();
        assert!(
            drive
                .scopes
                .contains(&"https://www.googleapis.com/auth/drive")
        );
        assert!(
            !drive
                .scopes
                .contains(&"https://www.googleapis.com/auth/gmail.modify")
        );
        assert!(
            gmail
                .scopes
                .contains(&"https://www.googleapis.com/auth/gmail.modify")
        );
        assert!(
            AuthPlan::new(Provider::OneDrive, RegistrationFamily::Microsoft)
                .unwrap()
                .required_scopes
                .contains(&"Files.ReadWrite")
        );
    }

    #[test]
    fn registration_codec_is_bounded_family_bound_and_rejects_trailing_bytes() {
        let original = registration(RegistrationFamily::Google);
        let bytes = original.encode().unwrap();
        let restored = ClientRegistration::decode(&bytes).unwrap();
        assert_eq!(restored.family(), RegistrationFamily::Google);
        assert_eq!(restored.client_id(), original.client_id());
        let mut malformed = bytes.to_vec();
        malformed.push(0);
        assert_eq!(
            ClientRegistration::decode(&malformed).unwrap_err(),
            AuthError::InvalidRegistration
        );
        assert_eq!(
            ClientRegistration::new(
                RegistrationFamily::Dropbox,
                "id".into(),
                Some("secret".into())
            )
            .unwrap_err(),
            AuthError::InvalidRegistration
        );
    }

    #[test]
    fn token_codec_round_trips_secrets_without_debug_leaks_and_checks_uuid_key() {
        let plan = AuthPlan::new(Provider::GoogleDrive, RegistrationFamily::Google).unwrap();
        let response = TokenResponse {
            access_token: Zeroizing::new("token-value-123".to_owned()),
            refresh_token: Some(Zeroizing::new("refresh-value-123".to_owned())),
            expires_in: 3600,
            scopes: None,
        };
        let tokens = token_set_from_response(
            Provider::GoogleDrive,
            Uuid::new_v4(),
            response,
            None,
            &plan,
            "fixture-client",
        )
        .unwrap();
        let bytes = tokens.encode().unwrap();
        let restored = TokenSet::decode(&bytes).unwrap();
        assert_eq!(restored.provider(), Provider::GoogleDrive);
        assert_eq!(restored.scopes().collect::<Vec<_>>(), plan.scopes);
        assert!(format!("{restored:?}").contains("[redacted]"));
        assert!(!format!("{restored:?}").contains("token-value-123"));
        let mut malformed = bytes.to_vec();
        malformed.push(0);
        assert_eq!(
            TokenSet::decode(&malformed).unwrap_err(),
            AuthError::InvalidTokenRecord
        );
    }

    #[test]
    fn callback_parser_checks_method_host_path_state_and_duplicate_fields() {
        let valid = b"GET /oauth2/callback?code=fixture-code&state=nonce-123&scope=openid HTTP/1.1\r\nHost: 127.0.0.1:49211\r\nConnection: close\r\n\r\n";
        assert_eq!(
            parse_callback_request(valid, "127.0.0.1:49211", "nonce-123")
                .unwrap()
                .as_str(),
            "fixture-code"
        );
        let wrong_host = String::from_utf8(valid.to_vec())
            .unwrap()
            .replace("127.0.0.1:49211", "127.0.0.1:49212");
        assert_eq!(
            parse_callback_request(wrong_host.as_bytes(), "127.0.0.1:49211", "nonce-123")
                .unwrap_err(),
            AuthError::InvalidCallback
        );
        let duplicate = b"GET /oauth2/callback?code=a&code=b&state=nonce-123 HTTP/1.1\r\nHost: 127.0.0.1:49211\r\n\r\n";
        assert_eq!(
            parse_callback_request(duplicate, "127.0.0.1:49211", "nonce-123").unwrap_err(),
            AuthError::InvalidCallback
        );
        let denied = b"GET /oauth2/callback?error=access_denied&state=nonce-123 HTTP/1.1\r\nHost: 127.0.0.1:49211\r\n\r\n";
        assert_eq!(
            parse_callback_request(denied, "127.0.0.1:49211", "nonce-123").unwrap_err(),
            AuthError::UserDenied
        );
        let wrong_state =
            b"GET /oauth2/callback?code=a&state=wrong HTTP/1.1\r\nHost: 127.0.0.1:49211\r\n\r\n";
        assert_eq!(
            parse_callback_request(wrong_state, "127.0.0.1:49211", "nonce-123").unwrap_err(),
            AuthError::InvalidCallback
        );
    }

    #[test]
    fn authorization_url_uses_fixed_provider_https_endpoints_and_correct_redirect_policy() {
        let dropbox = AuthPlan::new(Provider::Dropbox, RegistrationFamily::Dropbox).unwrap();
        assert_eq!(
            dropbox.redirect_for(53682),
            "http://127.0.0.1:53682/oauth2/callback"
        );
        assert_eq!(
            dropbox.authorize_endpoint,
            "https://www.dropbox.com/oauth2/authorize"
        );
        let microsoft = AuthPlan::new(Provider::OneDrive, RegistrationFamily::Microsoft).unwrap();
        assert_eq!(
            microsoft.redirect_for(1234),
            "http://localhost:1234/oauth2/callback"
        );
        let google = AuthPlan::new(Provider::Gmail, RegistrationFamily::Google).unwrap();
        assert!(matches!(google.redirect_mode, RedirectMode::DynamicIp));
    }
}
