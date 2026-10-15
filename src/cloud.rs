//! Cloud workflow owner. Provider inventory is bound to the connected identity;
//! browser consent and provider effects are invoked only by explicit UI commands.

use crate::{
    cloud_actions::{ActionError, ActionReceipt, ActionTarget, NativeActions, RestoreCapability},
    cloud_auth::{
        AuthProgress, ClientRegistration, NativeAuthorizer, RegistrationFamily, TokenSet,
    },
    cloud_drive::DriveClient,
    cloud_gmail::GmailClient,
    cloud_inventory::{
        self, AccountScope, PageCursor, Provider, ProviderFailure, RemotePage, RemotePort,
        ScanItemId, Snapshot, SnapshotStatus, TrashStatus,
    },
    cloud_onedrive::{DriveChoice, OneDriveClient},
    cloud_store::{
        AccountInput, AccountRecord, CloudAction, CloudStore, OperationInput, OperationPage,
        OperationRecord, OperationState, OperationStatusCode, TerminalState,
    },
    cloud_vault::{NativeVault, SecretVault, VaultKey},
};
use std::{
    collections::HashSet,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const PROVIDERS: [Provider; 4] = [
    Provider::GoogleDrive,
    Provider::OneDrive,
    Provider::Dropbox,
    Provider::Gmail,
];

pub const fn family(provider: Provider) -> RegistrationFamily {
    match provider {
        Provider::GoogleDrive | Provider::Gmail => RegistrationFamily::Google,
        Provider::OneDrive => RegistrationFamily::Microsoft,
        Provider::Dropbox => RegistrationFamily::Dropbox,
    }
}

pub struct Workspace {
    pub registrations: Vec<(RegistrationFamily, String)>,
    pub registration_error: Option<String>,
    pub accounts: Vec<AccountRecord>,
    pub history: OperationPage,
    pub restore_attempts: HashSet<Uuid>,
}
pub struct HistoryPage {
    pub history: OperationPage,
    pub restore_attempts: HashSet<Uuid>,
}
// The UI has one worker; this additionally serializes public service calls.
// Credentials, account generations and recovery never overlap a provider effect.
static CLOUD_WORK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn cloud_work() -> std::sync::MutexGuard<'static, ()> {
    CLOUD_WORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn history_page(store: &CloudStore, before: Option<Uuid>) -> Result<HistoryPage, String> {
    let history = store.operations(None, before, 200).map_err(message)?;
    let mut restore_attempts = HashSet::new();
    for record in &history.records {
        if record.action() == CloudAction::Trash
            && store.has_restore_attempt(record.id()).map_err(message)?
        {
            restore_attempts.insert(record.id());
        }
    }
    Ok(HistoryPage {
        history,
        restore_attempts,
    })
}

/// Tokens stay in memory until an actual storage scope has been selected.
/// No Debug/serialization: this value is never written into UI diagnostics.
pub struct PendingConnection {
    tokens: TokenSet,
    client_id: String,
    choices: Vec<DriveChoice>,
}
impl PendingConnection {
    pub fn choices(&self) -> &[DriveChoice] {
        &self.choices
    }
}
pub enum Connection {
    Connected(AccountRecord),
    ChooseDrive(PendingConnection),
}

pub fn load(data_dir: &Path, recover_interrupted: bool) -> Result<Workspace, String> {
    let _work = cloud_work();
    let mut store = CloudStore::open(data_dir).map_err(message)?;
    if recover_interrupted {
        store.mark_interrupted_uncertain().map_err(message)?;
    }
    let mut registrations = Vec::new();
    let mut registration_error = None;
    match vault(data_dir) {
        Ok(mut vault) => {
            for family in [
                RegistrationFamily::Google,
                RegistrationFamily::Microsoft,
                RegistrationFamily::Dropbox,
            ] {
                match ClientRegistration::load_from(&mut vault, family) {
                    Ok(Some(registration)) => {
                        registrations.push((family, registration.client_id().to_owned()))
                    }
                    Ok(None) => {}
                    Err(error) => {
                        registration_error = Some(message(error));
                        break;
                    }
                }
            }
        }
        Err(error) => registration_error = Some(error),
    }
    let history = history_page(&store, None)?;
    Ok(Workspace {
        registrations,
        registration_error,
        accounts: store.accounts().map_err(message)?,
        history: history.history,
        restore_attempts: history.restore_attempts,
    })
}

pub fn save_registration(
    data_dir: &Path,
    provider: Provider,
    client_id: String,
    google_secret: Option<String>,
) -> Result<(), String> {
    let _work = cloud_work();
    let registration =
        ClientRegistration::new(family(provider), client_id, google_secret).map_err(message)?;
    registration.save_to(&mut vault(data_dir)?).map_err(message)
}

pub fn connect(
    data_dir: &Path,
    provider: Provider,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(AuthProgress),
) -> Result<Connection, String> {
    let _work = cloud_work();
    let mut vault = vault(data_dir)?;
    let registration = ClientRegistration::load_from(&mut vault, family(provider))
        .map_err(message)?
        .ok_or("Cloud sign-in is unavailable in this build. DCleaner's provider integration has not been configured.")?;
    let tokens =
        NativeAuthorizer::authorize(provider, &registration, cancel, progress).map_err(message)?;
    let client_id = registration.client_id().to_owned();
    if provider == Provider::OneDrive {
        let mut client =
            OneDriveClient::new(tokens.access_token().map_err(message)?).map_err(message)?;
        let choices = client.drive_choices(cancel).map_err(provider_error)?;
        if choices.is_empty() {
            return Err(
                "No existing OneDrive storage is available. DCleaner has not created a drive."
                    .into(),
            );
        }
        if choices.len() > 1 {
            return Ok(Connection::ChooseDrive(PendingConnection {
                tokens,
                client_id,
                choices,
            }));
        }
        return finish_connect(
            data_dir,
            tokens,
            client_id,
            Some(choices[0].id().to_owned()),
            cancel,
        )
        .map(Connection::Connected);
    }
    finish_connect(data_dir, tokens, client_id, None, cancel).map(Connection::Connected)
}

pub fn choose_drive(
    data_dir: &Path,
    pending: PendingConnection,
    drive: &str,
    cancel: &AtomicBool,
) -> Result<AccountRecord, String> {
    let _work = cloud_work();
    if !pending.choices.iter().any(|choice| choice.id() == drive) {
        return Err("Choose one of the drives returned by your provider.".into());
    }
    finish_connect(
        data_dir,
        pending.tokens,
        pending.client_id,
        Some(drive.to_owned()),
        cancel,
    )
}

fn finish_connect(
    data_dir: &Path,
    tokens: TokenSet,
    client_id: String,
    drive: Option<String>,
    cancel: &AtomicBool,
) -> Result<AccountRecord, String> {
    let mut port = NativePort::new(&tokens, drive)?;
    let scope = port.current_scope(cancel).map_err(provider_error)?;
    if scope.provider() != tokens.provider() {
        return Err("The provider account did not match this connection.".into());
    }
    let mut store = CloudStore::open(data_dir).map_err(message)?;
    let existing = store.known_account_for_scope(&scope).map_err(message)?;
    let account_id = existing
        .as_ref()
        .map(AccountRecord::id)
        .unwrap_or(tokens.account_id());
    let label = existing
        .as_ref()
        .map(|record| record.label().to_owned())
        .unwrap_or_else(|| {
            format!(
                "{} account {}",
                scope.provider().label(),
                &account_id.to_string()[..8]
            )
        });
    let tokens = tokens.rebind_account(account_id).map_err(message)?;
    let mut vault = vault(data_dir)?;
    tokens.save_to(&mut vault).map_err(message)?;
    match store.upsert_account(AccountInput {
        id: account_id,
        scope,
        client_id,
        label,
    }) {
        Ok(record) => Ok(record),
        Err(error) => {
            // A previously connected account keeps its fresh credential. For a
            // new unrecorded identity, remove the orphan credential if possible.
            if existing.is_none() {
                let _ = vault.delete(VaultKey::Account(account_id));
            }
            Err(message(error))
        }
    }
}

pub fn disconnect(data_dir: &Path, id: Uuid, generation: Uuid) -> Result<(), String> {
    let _work = cloud_work();
    let mut store = CloudStore::open(data_dir).map_err(message)?;
    let _ = checked_account(&store, id, generation)?;
    vault(data_dir)?
        .delete(VaultKey::Account(id))
        .map_err(message)?;
    store
        .deactivate_account_for_generation(id, generation)
        .map_err(message)
}

pub fn scan(
    data_dir: &Path,
    id: Uuid,
    generation: Uuid,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(AuthProgress),
) -> Result<Snapshot, String> {
    let _work = cloud_work();
    let store = CloudStore::open(data_dir).map_err(message)?;
    let account = checked_account(&store, id, generation)?;
    let tokens = account_tokens(data_dir, &account, cancel, progress)?;
    let mut port = NativePort::new(&tokens, account.scope().storage_id().map(str::to_owned))?;
    Ok(cloud_inventory::scan(&mut port, account.scope(), cancel))
}

pub fn history(data_dir: &Path, before: Option<Uuid>) -> Result<HistoryPage, String> {
    let _work = cloud_work();
    history_page(&CloudStore::open(data_dir).map_err(message)?, before)
}

/// Consumed once by the effect owner. A snapshot is not effect authority;
/// account scope, acknowledgments, selections and fresh preflight all matter.
pub struct TrashReview {
    account_id: Uuid,
    generation: Uuid,
    scope: AccountScope,
    id: Uuid,
    items: Vec<ActionTarget>,
}
#[derive(Default)]
pub struct BatchOutcome {
    pub confirmed: usize,
    pub failed: usize,
    pub uncertain: usize,
    pub cancelled: bool,
}

pub fn review_trash(
    account: &AccountRecord,
    snapshot: &Snapshot,
    ids: &[ScanItemId],
    partial_ack: bool,
    all_copies_ack: bool,
    race_ack: bool,
) -> Result<TrashReview, String> {
    if account.scope() != snapshot.scope() {
        return Err("The scan belongs to another account or storage scope.".into());
    }
    if ids.is_empty() || ids.len() > 200 {
        return Err("Review between 1 and 200 cloud items per batch.".into());
    }
    if !race_ack {
        return Err(
            "Review the provider preflight and concurrent-change limitation before continuing."
                .into(),
        );
    }
    if snapshot.status() == SnapshotStatus::Failed {
        return Err("This scan failed. Scan again before cleanup.".into());
    }
    if !snapshot.is_complete() && !partial_ack {
        return Err("Review and acknowledge the incomplete scan before cleanup.".into());
    }
    let selected: HashSet<_> = ids.iter().copied().collect();
    if selected.len() != ids.len() {
        return Err("The cleanup selection contains repeated rows.".into());
    }
    if snapshot
        .possible_duplicate_groups()
        .groups()
        .iter()
        .any(|group| group.item_ids().iter().all(|id| selected.contains(id)))
        && !all_copies_ack
    {
        return Err("This selection includes every shown copy in a possible duplicate group. Review that choice explicitly.".into());
    }
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        let item = snapshot
            .items()
            .iter()
            .find(|item| item.id() == *id)
            .ok_or("A selected cloud row is stale or belongs to another scan.")?;
        if item.trash_status() != TrashStatus::NotTrashed {
            return Err(
                "A selected item's current trash state is unknown or already trashed. Scan again."
                    .into(),
            );
        }
        items.push(ActionTarget::from_item(snapshot.scope(), item).map_err(message)?);
    }
    Ok(TrashReview {
        account_id: account.id(),
        generation: account.generation(),
        scope: snapshot.scope().clone(),
        id: Uuid::new_v4(),
        items,
    })
}

pub fn trash(
    data_dir: &Path,
    review: TrashReview,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(AuthProgress),
) -> Result<BatchOutcome, String> {
    let _work = cloud_work();
    let mut store = CloudStore::open(data_dir).map_err(message)?;
    let account = checked_account(&store, review.account_id, review.generation)?;
    if account.scope() != &review.scope {
        return Err("The reviewed cloud scope changed. Scan again.".into());
    }
    let tokens = account_tokens(data_dir, &account, cancel, progress)?;
    // Establish the live identity before the first journal reservation. The
    // action adapter independently repeats scope and item checks per write.
    let mut port = NativePort::new(&tokens, account.scope().storage_id().map(str::to_owned))?;
    if port.current_scope(cancel).map_err(provider_error)? != review.scope {
        return Err("The provider account changed. Reconnect before cleanup.".into());
    }
    let mut actions = NativeActions::new(
        tokens.access_token().map_err(message)?,
        review.scope.clone(),
    )
    .map_err(message)?;
    execute_trash(&mut store, &review, cancel, |target| {
        actions.trash(target, cancel)
    })
}

fn execute_trash(
    store: &mut CloudStore,
    review: &TrashReview,
    cancel: &AtomicBool,
    mut effect: impl FnMut(&ActionTarget) -> Result<ActionReceipt, ActionError>,
) -> Result<BatchOutcome, String> {
    let mut outcome = BatchOutcome::default();
    for target in &review.items {
        if cancel.load(Ordering::Relaxed) {
            outcome.cancelled = true;
            break;
        }
        checked_account(store, review.account_id, review.generation)?;
        if store
            .has_uncertain(review.account_id, target.provider_item_id())
            .map_err(message)?
        {
            // Never dispatch a new effect against an unresolved previous intent.
            outcome.failed += 1;
            continue;
        }
        let metadata = record_json(target.to_json().map_err(message)?)?;
        let operation = store
            .reserve_operation_for_generation(
                OperationInput {
                    account_id: review.account_id,
                    action: CloudAction::Trash,
                    review_key: review.id,
                    item_key: target.restore_source_row(),
                    remote_id: target.provider_item_id().to_owned(),
                    name: target.display_name().to_owned(),
                    revision: Some(target.revision().to_owned()),
                    metadata,
                },
                review.generation,
            )
            .map_err(message)?;
        match effect(target) {
            Ok(receipt) => {
                if receipt.target() != target {
                    return Err("Provider receipt did not match the reviewed item. The reserved outcome remains uncertain.".into());
                }
                let receipt = record_json(receipt.to_json().map_err(message)?)?;
                store.finish_operation(operation.id(),TerminalState::Confirmed,Some(&receipt),None).map_err(|_|"The provider acknowledged trash, but its durable outcome could not be saved. Check history before any retry.")?;
                outcome.confirmed += 1;
            }
            Err(error) => {
                let unknown = error == ActionError::OutcomeUnknown;
                store.finish_operation(operation.id(),if unknown{TerminalState::Uncertain}else{TerminalState::Failed},None,Some(action_status(error))).map_err(|_|"The provider outcome could not be saved. Check history before any retry.")?;
                if unknown {
                    outcome.uncertain += 1;
                } else {
                    outcome.failed += 1;
                }
                if error == ActionError::Cancelled || cancel.load(Ordering::Relaxed) {
                    outcome.cancelled = true;
                    break;
                }
            }
        }
    }
    Ok(outcome)
}

pub fn can_restore_record(record: &OperationRecord) -> bool {
    record.action() == CloudAction::Trash
        && record.state() == OperationState::Confirmed
        && ActionReceipt::from_json(record.metadata().as_bytes()).is_ok_and(|receipt| {
            receipt.restore_capability() == RestoreCapability::Available
                && receipt.target().provider_item_id() == record.remote_id()
                && receipt.target().display_name() == record.name()
                && Some(receipt.target().revision()) == record.revision()
                && receipt.target().restore_source_row() == record.item_key()
        })
}

pub fn restore(
    data_dir: &Path,
    account: &AccountRecord,
    record: &OperationRecord,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(AuthProgress),
) -> Result<BatchOutcome, String> {
    let _work = cloud_work();
    let mut store = CloudStore::open(data_dir).map_err(message)?;
    let account = checked_account(&store, account.id(), account.generation())?;
    // Reread the journal by its durable UUID, never trust an old UI receipt.
    let durable = store
        .operation(record.id())
        .map_err(message)?
        .ok_or("This cleanup history entry no longer exists.")?;
    if &durable != record || durable.account_id() != account.id() || !can_restore_record(&durable) {
        return Err(
            "This history entry cannot be restored. Reload history and review its current state."
                .into(),
        );
    }
    if store.has_restore_attempt(durable.id()).map_err(message)? {
        return Err("A restore was already attempted for this entry. Review its recorded outcome before any further change.".into());
    }
    if store
        .has_uncertain(account.id(), durable.remote_id())
        .map_err(message)?
    {
        return Err("This item has an unresolved operation. Check its provider state before attempting another change.".into());
    }
    let receipt = ActionReceipt::from_json(durable.metadata().as_bytes()).map_err(message)?;
    if receipt.target().scope().map_err(message)? != *account.scope() {
        return Err("The restore receipt belongs to another cloud account or storage.".into());
    }
    let tokens = account_tokens(data_dir, &account, cancel, progress)?;
    let mut port = NativePort::new(&tokens, account.scope().storage_id().map(str::to_owned))?;
    if port.current_scope(cancel).map_err(provider_error)? != *account.scope() {
        return Err("The remote cloud identity changed. Reconnect this account.".into());
    }
    if cancel.load(Ordering::Relaxed) {
        return Ok(BatchOutcome {
            cancelled: true,
            ..Default::default()
        });
    }
    let mut actions = NativeActions::new(
        tokens.access_token().map_err(message)?,
        account.scope().clone(),
    )
    .map_err(message)?;
    let intent = store
        .reserve_operation_for_generation(
            OperationInput {
                account_id: account.id(),
                action: CloudAction::Restore,
                review_key: durable.id(),
                item_key: durable.id(),
                remote_id: durable.remote_id().to_owned(),
                name: durable.name().to_owned(),
                revision: durable.revision().map(str::to_owned),
                metadata: durable.metadata().to_owned(),
            },
            account.generation(),
        )
        .map_err(message)?;
    match actions.restore(&receipt, cancel) {
        Ok(_) => {
            store.finish_operation(intent.id(),TerminalState::Confirmed,None,None).map_err(|_|"The provider acknowledged restore, but its durable outcome could not be saved. Check history before retrying.")?;
            Ok(BatchOutcome {
                confirmed: 1,
                ..Default::default()
            })
        }
        Err(error) => {
            let unknown = error == ActionError::OutcomeUnknown;
            store
                .finish_operation(
                    intent.id(),
                    if unknown {
                        TerminalState::Uncertain
                    } else {
                        TerminalState::Failed
                    },
                    None,
                    Some(action_status(error)),
                )
                .map_err(
                    |_| "The restore outcome could not be saved. Check history before retrying.",
                )?;
            Ok(BatchOutcome {
                uncertain: usize::from(unknown),
                failed: usize::from(!unknown),
                cancelled: error == ActionError::Cancelled,
                ..Default::default()
            })
        }
    }
}

fn record_json(bytes: Vec<u8>) -> Result<String, String> {
    String::from_utf8(bytes).map_err(|_| "The cloud operation record could not be encoded.".into())
}
fn action_status(error: ActionError) -> OperationStatusCode {
    // Closed local vocabulary; raw provider errors and responses never enter
    // the journal or UI. Unknown outcomes are conveyed by the operation state.
    match error {
        ActionError::Cancelled => OperationStatusCode::Cancelled,
        ActionError::ScopeMismatch => OperationStatusCode::AccountChanged,
        ActionError::ChangedSinceScan => OperationStatusCode::ProviderConflict,
        ActionError::AlreadyTrashed | ActionError::NotTrashed => {
            OperationStatusCode::AlreadySatisfied
        }
        ActionError::HttpRejected(401) => OperationStatusCode::AuthenticationRequired,
        ActionError::HttpRejected(403) => OperationStatusCode::PermissionDenied,
        ActionError::HttpRejected(404) => OperationStatusCode::ProviderNotFound,
        ActionError::HttpRejected(409 | 412) => OperationStatusCode::ProviderConflict,
        ActionError::HttpRejected(429) => OperationStatusCode::RateLimited,
        ActionError::TimedOut | ActionError::Transport | ActionError::HttpRejected(500..=599) => {
            OperationStatusCode::TemporarilyUnavailable
        }
        ActionError::InvalidResponse | ActionError::ResponseLimit => {
            OperationStatusCode::InvalidResponse
        }
        _ => OperationStatusCode::Other,
    }
}

fn checked_account(
    store: &CloudStore,
    id: Uuid,
    generation: Uuid,
) -> Result<AccountRecord, String> {
    store
        .accounts()
        .map_err(message)?
        .into_iter()
        .find(|account| account.id() == id && account.generation() == generation)
        .ok_or_else(|| {
            "This account changed or was disconnected. Reload it before continuing.".into()
        })
}
fn vault(data_dir: &Path) -> Result<NativeVault, String> {
    NativeVault::from_data_dir(data_dir.join("cloud-vault")).map_err(message)
}
fn account_tokens(
    data_dir: &Path,
    account: &AccountRecord,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(AuthProgress),
) -> Result<TokenSet, String> {
    let mut vault = vault(data_dir)?;
    let registration = ClientRegistration::load_from(&mut vault, family(account.scope().provider())).map_err(message)?
        .ok_or("The provider application registration is missing. Configure it and reconnect this account.")?;
    let tokens = TokenSet::load_from(&mut vault, account.id())
        .map_err(message)?
        .ok_or("The protected sign-in credential is missing. Reconnect this account.")?;
    if tokens.provider() != account.scope().provider()
        || tokens.account_id() != account.id()
        || registration.client_id() != account.client_id()
        || tokens.registration_client_id() != account.client_id()
    {
        return Err(
            "The application registration or protected account changed. Reconnect this account."
                .into(),
        );
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "The system clock is unavailable.")?
        .as_secs();
    if tokens.expires_at_unix_seconds() <= now.saturating_add(120) {
        let refreshed =
            NativeAuthorizer::refresh(tokens.provider(), &registration, &tokens, cancel, progress)
                .map_err(message)?;
        refreshed.save_to(&mut vault).map_err(message)?;
        Ok(refreshed)
    } else {
        Ok(tokens)
    }
}

enum NativePort {
    Drive(DriveClient),
    Gmail(GmailClient),
    OneDrive(OneDriveClient),
    Dropbox(crate::cloud_dropbox::DropboxClient),
}
impl NativePort {
    fn new(tokens: &TokenSet, storage: Option<String>) -> Result<Self, String> {
        let token = tokens.access_token().map_err(message)?;
        Ok(match tokens.provider() {
            Provider::GoogleDrive => Self::Drive(DriveClient::new(token).map_err(message)?),
            Provider::Gmail => Self::Gmail(GmailClient::new(token).map_err(message)?),
            Provider::OneDrive => {
                Self::OneDrive(OneDriveClient::new_with_drive(token, storage).map_err(message)?)
            }
            Provider::Dropbox => {
                Self::Dropbox(crate::cloud_dropbox::DropboxClient::new(token).map_err(message)?)
            }
        })
    }
}
impl RemotePort for NativePort {
    fn current_scope(&mut self, cancel: &AtomicBool) -> Result<AccountScope, ProviderFailure> {
        match self {
            Self::Drive(p) => p.current_scope(cancel),
            Self::Gmail(p) => p.current_scope(cancel),
            Self::OneDrive(p) => p.current_scope(cancel),
            Self::Dropbox(p) => p.current_scope(cancel),
        }
    }
    fn list_page(
        &mut self,
        scope: &AccountScope,
        cursor: Option<&PageCursor>,
        cancel: &AtomicBool,
    ) -> Result<RemotePage, ProviderFailure> {
        match self {
            Self::Drive(p) => p.list_page(scope, cursor, cancel),
            Self::Gmail(p) => p.list_page(scope, cursor, cancel),
            Self::OneDrive(p) => p.list_page(scope, cursor, cancel),
            Self::Dropbox(p) => p.list_page(scope, cursor, cancel),
        }
    }
}
fn message(error: impl std::fmt::Display) -> String {
    error.to_string()
}
pub fn provider_error(error: ProviderFailure) -> String {
    match error {
        ProviderFailure::AuthenticationRequired => "Sign-in expired. Reconnect this account.",
        ProviderFailure::PermissionDenied => {
            "The provider denied access. Review DCleaner's granted permissions."
        }
        ProviderFailure::RateLimited => "The provider rate-limited this request. Try again later.",
        ProviderFailure::StorageSelectionRequired => {
            "Choose an existing storage drive before continuing."
        }
        ProviderFailure::Unavailable => "No existing provider storage is available.",
        ProviderFailure::Cancelled => "Cloud operation cancelled.",
        ProviderFailure::AccountScopeMismatch => {
            "The remote account or storage changed. Reconnect before continuing."
        }
        ProviderFailure::TimedOut => "The provider request exceeded its deadline.",
        ProviderFailure::ResponseLimit => {
            "The provider response exceeded its bound. The scan is incomplete."
        }
        ProviderFailure::ClientUnavailable => "The cloud HTTPS client is unavailable.",
        ProviderFailure::MalformedResponse => "The provider returned invalid metadata.",
        ProviderFailure::Transport
        | ProviderFailure::TemporarilyUnavailable
        | ProviderFailure::Other => {
            "The provider could not complete this request. No automatic retry was made."
        }
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud_inventory::{
        ContentHash, HashAlgorithm, RemoteItemDraft, RemoteItemKind, SizeAccuracy, SizeObservation,
    };

    struct FixturePort {
        scope: AccountScope,
        rows: Vec<RemoteItemDraft>,
    }
    impl RemotePort for FixturePort {
        fn current_scope(&mut self, _: &AtomicBool) -> Result<AccountScope, ProviderFailure> {
            Ok(self.scope.clone())
        }
        fn list_page(
            &mut self,
            _: &AccountScope,
            _: Option<&PageCursor>,
            _: &AtomicBool,
        ) -> Result<RemotePage, ProviderFailure> {
            Ok(RemotePage::new(
                self.scope.clone(),
                std::mem::take(&mut self.rows),
                None,
            ))
        }
    }
    fn fixture() -> (tempfile::TempDir, CloudStore, AccountRecord, Snapshot) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = CloudStore::open(dir.path()).unwrap();
        let scope = AccountScope::new(
            Provider::GoogleDrive,
            "fixture-subject",
            Some("drive:user:api-visible:untrashed".into()),
        )
        .unwrap();
        let account = store
            .upsert_account(AccountInput {
                id: Uuid::new_v4(),
                scope: scope.clone(),
                client_id: "fixture-client".into(),
                label: "Fixture Drive".into(),
            })
            .unwrap();
        let rows = ["file-a", "file-b"]
            .into_iter()
            .map(|id| {
                RemoteItemDraft::new(id, id, RemoteItemKind::File)
                    .with_provider_revision(Some("1".into()))
                    .with_trash_status(TrashStatus::NotTrashed)
                    .with_size(Some(SizeObservation::new(
                        12,
                        SizeAccuracy::ProviderReportedExact,
                    )))
                    .with_content_hash(Some(
                        ContentHash::new(
                            Provider::GoogleDrive,
                            HashAlgorithm::Md5,
                            "0123456789abcdef0123456789abcdef",
                        )
                        .unwrap(),
                    ))
            })
            .collect();
        let snapshot = cloud_inventory::scan(
            &mut FixturePort {
                scope: scope.clone(),
                rows,
            },
            &scope,
            &AtomicBool::new(false),
        );
        (dir, store, account, snapshot)
    }
    #[test]
    fn cloud_review_rejects_foreign_scan_rows_scope_and_duplicate_all_copies_without_ack() {
        let (_dir, mut store, account, snapshot) = fixture();
        let ids: Vec<_> = snapshot.items().iter().map(|i| i.id()).collect();
        assert!(review_trash(&account, &snapshot, &ids, false, false, true).is_err());
        assert!(review_trash(&account, &snapshot, &ids, false, true, true).is_ok());
        assert!(review_trash(&account, &snapshot, &ids[..1], false, false, false).is_err());
        assert!(review_trash(&account, &snapshot, &[ids[0], ids[0]], false, true, true).is_err());
        let other = store
            .upsert_account(AccountInput {
                id: Uuid::new_v4(),
                scope: AccountScope::new(
                    Provider::GoogleDrive,
                    "other-subject",
                    Some("drive:user:api-visible:untrashed".into()),
                )
                .unwrap(),
                client_id: "fixture-client".into(),
                label: "Other".into(),
            })
            .unwrap();
        assert!(review_trash(&other, &snapshot, &ids[..1], false, true, true).is_err());
        let (_, _, _, foreign) = fixture();
        assert!(
            review_trash(
                &account,
                &snapshot,
                &[foreign.items()[0].id()],
                false,
                true,
                true
            )
            .is_err()
        );
    }
    #[test]
    fn cloud_intent_precedes_dispatch_unknown_is_durable_and_blocks_another_effect() {
        let (_dir, mut store, account, snapshot) = fixture();
        let id = snapshot.items()[0].id();
        let review = review_trash(&account, &snapshot, &[id], false, false, true).unwrap();
        let result = execute_trash(&mut store, &review, &AtomicBool::new(false), |_| {
            Err(ActionError::OutcomeUnknown)
        })
        .unwrap();
        assert_eq!(result.uncertain, 1);
        assert_eq!(result.confirmed, 0);
        let page = store.operations(None, None, 200).unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].state(), OperationState::Uncertain);
        let mut dispatched = false;
        let next = review_trash(&account, &snapshot, &[id], false, false, true).unwrap();
        let result = execute_trash(&mut store, &next, &AtomicBool::new(false), |_| {
            dispatched = true;
            Err(ActionError::OutcomeUnknown)
        })
        .unwrap();
        assert!(!dispatched);
        assert_eq!(result.failed, 1);
        assert_eq!(store.operations(None, None, 200).unwrap().records.len(), 1);
    }
    #[test]
    fn cloud_cancel_and_changed_account_generation_prevent_dispatch() {
        let (_dir, mut store, account, snapshot) = fixture();
        let id = snapshot.items()[0].id();
        let review = review_trash(&account, &snapshot, &[id], false, false, true).unwrap();
        let mut dispatched = false;
        let outcome = execute_trash(&mut store, &review, &AtomicBool::new(true), |_| {
            dispatched = true;
            Err(ActionError::OutcomeUnknown)
        })
        .unwrap();
        assert!(outcome.cancelled);
        assert!(!dispatched);
        assert!(
            store
                .operations(None, None, 200)
                .unwrap()
                .records
                .is_empty()
        );
        store
            .upsert_account(AccountInput {
                id: account.id(),
                scope: account.scope().clone(),
                client_id: account.client_id().to_owned(),
                label: "Reconnected".into(),
            })
            .unwrap();
        assert!(
            execute_trash(&mut store, &review, &AtomicBool::new(false), |_| {
                dispatched = true;
                Err(ActionError::OutcomeUnknown)
            })
            .is_err()
        );
        assert!(!dispatched);
    }
}
