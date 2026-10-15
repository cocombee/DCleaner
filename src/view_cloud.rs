use super::*;
use dcleaner::{
    cloud::{self, Connection, PendingConnection, Workspace},
    cloud_auth::AuthProgress,
    cloud_inventory::{Provider, RemoteItem, RemoteItemKind, ScanItemId, SizeAccuracy, Snapshot},
    cloud_store::{AccountRecord, CloudAction, OperationRecord, OperationStatusCode},
};
use std::collections::HashSet;

#[derive(Default)]
pub(super) struct CloudUi {
    attempted: bool,
    reload: bool,
    introduced: bool,
    workspace: Option<Workspace>,
    account: Option<Uuid>,
    snapshot: Option<Arc<Snapshot>>,
    selected: HashSet<ScanItemId>,
    ignored: HashSet<ScanItemId>,
    filter: CloudFilter,
    query: String,
    sort: CloudSort,
    descending: bool,
    shown_count: Option<usize>,
    more_open_for: Option<ScanItemId>,
    history_before: Option<Uuid>,
    history_back: Vec<Option<Uuid>>,
    older_days: u32,
    pending: Option<PendingConnection>,
    dialog: Option<CloudDialog>,
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum CloudFilter {
    #[default]
    All,
    Large,
    Duplicates,
    Older,
    Ignored,
    History,
}
impl CloudFilter {
    const ALL: [Self; 6] = [
        Self::All,
        Self::Large,
        Self::Duplicates,
        Self::Older,
        Self::Ignored,
        Self::History,
    ];
    fn label(self) -> &'static str {
        match self {
            Self::All => "All items",
            Self::Large => "Large files",
            Self::Duplicates => "Possible duplicates",
            Self::Older => "Older items",
            Self::Ignored => "Ignored",
            Self::History => "Cleanup history",
        }
    }
    fn help(self) -> &'static str {
        match self {
            Self::All => {
                "Choose individual items after review. Folders and shortcuts cannot be moved to trash here."
            }
            Self::Large => {
                "Items are at least 100 MB. Estimates may not equal quota reclaimed after trashing."
            }
            Self::Duplicates => {
                "Provider hashes suggest possible duplicates; content equality is not verified."
            }
            Self::Older => "Age comes from provider metadata and may not reflect last use.",
            Self::Ignored => {
                "Ignored items remain in the scan and are excluded only from this results view."
            }
            Self::History => {
                "History shows local operation receipts; uncertain outcomes are never retried automatically."
            }
        }
    }
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum CloudSort {
    #[default]
    Name,
    Size,
    Date,
}
const MAX_HISTORY_BACK_PAGES: usize = 500;
enum CloudDialog {
    Disconnect(AccountRecord),
    Details(RemoteItem),
    Trash {
        ids: Vec<ScanItemId>,
        partial: bool,
        copies: bool,
        race: bool,
    },
    Restore(OperationRecord),
}
pub(super) enum CloudEvent {
    Progress(String),
    Failed(String),
    Loaded(Result<Workspace, String>),
    Connected(Result<Connection, String>),
    Chosen(Result<AccountRecord, String>),
    Disconnected(Result<(), String>),
    Scanned {
        account: Uuid,
        generation: Uuid,
        result: Result<Snapshot, String>,
    },
    History {
        before: Option<Uuid>,
        from: Option<Uuid>,
        back: bool,
        result: Result<cloud::HistoryPage, String>,
    },
    Changed(Result<cloud::BatchOutcome, String>),
}

impl App {
    #[cfg(debug_assertions)]
    pub(super) fn qa_cloud_state(&self) -> serde_json::Value {
        let dialog = match self.cloud_ui.dialog.as_ref() {
            Some(CloudDialog::Details(_)) => "details",
            Some(CloudDialog::Trash { .. }) => "trash-review",
            Some(CloudDialog::Disconnect(_)) => "disconnect-review",
            Some(CloudDialog::Restore(_)) => "restore-review",
            None => "closed",
        };
        let has_rows =
            self.cloud_ui.snapshot.is_some() && self.cloud_ui.shown_count.unwrap_or(0) > 0;
        serde_json::json!({
            "introduced": self.cloud_ui.introduced,
            "history": self.cloud_ui.filter == CloudFilter::History,
            "filter": self.cloud_ui.filter.label(),
            "sort": cloud_sort_label(self.cloud_ui.sort),
            "descending": self.cloud_ui.descending,
            "shown": self.cloud_ui.shown_count,
            "selected": self.cloud_ui.selected.len(),
            "row_actions": if has_rows { vec!["Review", "More options"] } else { Vec::<&str>::new() },
            "more_open": self.cloud_ui.more_open_for.is_some(),
            "dialog": dialog,
        })
    }
    #[cfg(debug_assertions)]
    pub(super) fn qa_cloud_precondition(&self, action: &str) -> Result<(), String> {
        if !self.qa_fixture_mode() {
            return Err("Cloud visual actions require isolated fixture mode.".into());
        }
        let has_account = self.cloud_ui.account.is_some();
        let has_rows =
            self.cloud_ui.snapshot.is_some() && self.cloud_ui.shown_count.unwrap_or(0) > 0;
        match action {
            "All items" | "Large files" | "Possible duplicates" | "Older items" | "Ignored"
                if has_account =>
            {
                Ok(())
            }
            "Sort Name" | "Sort Size" | "Sort Provider date" if has_rows => Ok(()),
            "Review" | "More options" if has_rows && self.cloud_ui.dialog.is_none() => Ok(()),
            "Clear selection" | "Review 1 item"
                if has_rows
                    && self.cloud_ui.selected.len() == 1
                    && self.cloud_ui.dialog.is_none() =>
            {
                Ok(())
            }
            "Keep items" if matches!(self.cloud_ui.dialog, Some(CloudDialog::Trash { .. })) => {
                Ok(())
            }
            "Details" if has_rows && self.cloud_ui.dialog.is_none() => Ok(()),
            "Close" | "Escape" if matches!(self.cloud_ui.dialog, Some(CloudDialog::Details(_))) => {
                Ok(())
            }
            _ => Err(format!(
                "Cloud action is not available in the current safe fixture state: {action}"
            )),
        }
    }
    #[cfg(debug_assertions)]
    pub(super) fn qa_cloud_action_state(&self, action: &str) -> Result<serde_json::Value, String> {
        if !self.qa_fixture_mode() {
            return Err("Cloud visual actions require isolated fixture mode.".into());
        }
        let state = self.qa_cloud_state();
        let valid = match action {
            "All items" | "Large files" | "Possible duplicates" | "Older items" | "Ignored" => {
                state["filter"] == action
            }
            "Sort Name" => state["sort"] == "Name",
            "Sort Size" => state["sort"] == "Size",
            "Sort Provider date" => state["sort"] == "Provider date",
            "Review" | "Details" => state["dialog"] == "details",
            "Review 1 item" => state["dialog"] == "trash-review",
            "Clear selection" => state["selected"] == 0,
            "More options" => state["more_open"] == true,
            "Close" | "Escape" | "Keep items" => state["dialog"] == "closed",
            _ => false,
        };
        if !valid {
            return Err(format!(
                "Cloud action did not reach its expected safe state: {action}"
            ));
        }
        Ok(serde_json::json!({"action": action, "state": state}))
    }
    #[cfg(debug_assertions)]
    pub(super) fn seed_cloud_qa(&mut self, case: &str) {
        self.cloud_ui = CloudUi {
            attempted: true,
            introduced: case == "cloud-providers",
            workspace: Some(Workspace {
                registrations: Vec::new(),
                registration_error: None,
                accounts: Vec::new(),
                history: dcleaner::cloud_store::OperationPage {
                    records: Vec::new(),
                    next_cursor: None,
                },
                restore_attempts: HashSet::new(),
            }),
            ..Default::default()
        };
        if matches!(case, "cloud-selected" | "cloud-partial") {
            let scope = dcleaner::cloud_inventory::AccountScope::new(
                Provider::GoogleDrive,
                "fixture-subject",
                Some("fixture-drive".into()),
            )
            .expect("valid synthetic scope");
            let account = AccountRecord::visual_preview_fixture(scope.clone());
            let snapshot = if case == "cloud-partial" {
                Snapshot::visual_preview_partial_fixture(scope)
            } else {
                Snapshot::visual_preview_fixture(scope)
            };
            self.cloud_ui.introduced = true;
            self.cloud_ui.account = Some(account.id());
            self.cloud_ui.selected = snapshot.items().iter().map(RemoteItem::id).collect();
            self.cloud_ui.snapshot = Some(Arc::new(snapshot));
            self.cloud_ui
                .workspace
                .as_mut()
                .unwrap()
                .accounts
                .push(account);
            self.notice = None;
        }
    }
    fn begin_cloud_job(
        &mut self,
        label: &str,
        ctx: &egui::Context,
        job: impl FnOnce(&std::path::Path, &AtomicBool, &mut dyn FnMut(AuthProgress)) -> CloudEvent
        + Send
        + 'static,
    ) {
        if self.busy() || self.qa_fixture_mode() {
            return;
        }
        self.error = None;
        self.notice = None;
        self.progress = label.into();
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let path = self.data_dir.clone();
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.worker = Some(rx);
        thread::spawn(move || {
            let event=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let progress_tx=tx.clone(); let repaint=ctx.clone();
                let mut progress=move |stage:AuthProgress| {
                    let text=match stage { AuthProgress::OpeningBrowser=>"Opening provider sign-in…",AuthProgress::WaitingForCallback=>"Waiting for provider consent…",AuthProgress::ExchangingCode=>"Completing provider sign-in…",AuthProgress::RefreshingToken=>"Refreshing the protected sign-in…" };
                    let _=progress_tx.send(Event::Cloud(CloudEvent::Progress(text.into()))); repaint.request_repaint();
                };
                job(&path,&cancel,&mut progress)
            })).unwrap_or_else(|_| CloudEvent::Failed("Cloud operation ended unexpectedly. Check cleanup history for any uncertain changes before trying again.".into()));
            let _ = tx.send(Event::Cloud(event));
            ctx.request_repaint();
        });
    }

    pub(super) fn cloud_event(&mut self, event: CloudEvent) {
        if let CloudEvent::Progress(text) = &event {
            self.progress = text.clone();
            return;
        }
        self.worker = None;
        match event {
            CloudEvent::Progress(_) => {}
            CloudEvent::Failed(error) => {
                self.cloud_ui.dialog = None;
                self.cloud_ui.reload = true;
                self.error = Some(error);
            }
            CloudEvent::Loaded(result) => match result {
                Ok(workspace) => {
                    let previous = self.cloud_account();
                    if !workspace
                        .accounts
                        .iter()
                        .any(|a| Some(a.id()) == self.cloud_ui.account)
                    {
                        self.cloud_ui.account = workspace.accounts.first().map(AccountRecord::id);
                    }
                    let current = workspace
                        .accounts
                        .iter()
                        .find(|a| Some(a.id()) == self.cloud_ui.account);
                    let binding_changed = match (previous.as_ref(), current) {
                        (Some(old), Some(new)) => {
                            old.generation() != new.generation() || old.scope() != new.scope()
                        }
                        (None, None) => false,
                        _ => true,
                    };
                    if binding_changed {
                        self.clear_cloud_results();
                    }
                    self.cloud_ui.history_before = None;
                    self.cloud_ui.history_back.clear();
                    self.cloud_ui.workspace = Some(workspace);
                }
                Err(error) => {
                    self.cloud_ui.workspace = None;
                    self.clear_cloud_results();
                    self.error = Some(error);
                }
            },
            CloudEvent::Connected(result) => match result {
                Ok(Connection::Connected(account)) => self.cloud_connected(account),
                Ok(Connection::ChooseDrive(pending)) => self.cloud_ui.pending = Some(pending),
                Err(error) => self.error = Some(error),
            },
            CloudEvent::Chosen(result) => match result {
                Ok(account) => self.cloud_connected(account),
                Err(error) => self.error = Some(error),
            },
            CloudEvent::Disconnected(result) => match result {
                Ok(()) => {
                    self.cloud_ui.dialog = None;
                    self.cloud_ui.reload = true;
                    self.clear_cloud_results();
                    self.notice=Some("Disconnected on this device. Cleanup history remains available. You can revoke DCleaner's grant in your provider account settings.".into());
                }
                Err(error) => {
                    self.cloud_ui.dialog = None;
                    self.cloud_ui.reload = true;
                    self.error = Some(error);
                }
            },
            CloudEvent::Scanned {
                account,
                generation,
                result,
            } => {
                let current = self.cloud_ui.workspace.as_ref().and_then(|w| {
                    w.accounts
                        .iter()
                        .find(|a| a.id() == account && a.generation() == generation)
                });
                if self.cloud_ui.account == Some(account) && current.is_some() {
                    self.clear_cloud_results();
                    match result {
                        Ok(snapshot) => self.cloud_ui.snapshot = Some(Arc::new(snapshot)),
                        Err(error) => self.error = Some(error),
                    }
                }
            }
            CloudEvent::History {
                before,
                from,
                back,
                result,
            } => match result {
                Ok(page) => {
                    if let Some(workspace) = self.cloud_ui.workspace.as_mut() {
                        workspace.history = page.history;
                        workspace.restore_attempts = page.restore_attempts;
                        if back {
                            self.cloud_ui.history_back.pop();
                        } else {
                            self.cloud_ui.history_back.push(from);
                            if self.cloud_ui.history_back.len() > MAX_HISTORY_BACK_PAGES {
                                self.cloud_ui.history_back.remove(0);
                            }
                        }
                        self.cloud_ui.history_before = before;
                    }
                }
                Err(error) => self.error = Some(error),
            },
            CloudEvent::Changed(result) => {
                self.cloud_ui.dialog = None;
                self.clear_cloud_results();
                self.cloud_ui.reload = true;
                self.cloud_ui.filter = CloudFilter::History;
                self.cloud_ui.history_before = None;
                self.cloud_ui.history_back.clear();
                match result {
                    Ok(outcome) => {
                        self.notice = Some(format!(
                            "{} confirmed · {} failed · {} uncertain{}. Review each outcome below. Scan again before making another cleanup selection.",
                            outcome.confirmed,
                            outcome.failed,
                            outcome.uncertain,
                            if outcome.cancelled { " · stopped" } else { "" }
                        ))
                    }
                    Err(error) => self.error = Some(error),
                }
            }
        }
    }
    fn cloud_connected(&mut self, account: AccountRecord) {
        self.cloud_ui.account = Some(account.id());
        self.cloud_ui.pending = None;
        self.cloud_ui.reload = true;
        self.cloud_ui.introduced = true;
        self.clear_cloud_results();
        self.notice=Some("Connected to the provider account and selected storage. Scan to review its current API-visible items.".into());
    }
    fn clear_cloud_results(&mut self) {
        self.cloud_ui.snapshot = None;
        self.cloud_ui.selected.clear();
        self.cloud_ui.shown_count = None;
        self.cloud_ui.more_open_for = None;
        self.cloud_ui.ignored.clear();
    }
    fn cloud_account(&self) -> Option<AccountRecord> {
        self.cloud_ui
            .workspace
            .as_ref()?
            .accounts
            .iter()
            .find(|a| Some(a.id()) == self.cloud_ui.account)
            .cloned()
    }
    fn cloud_storage_available(&self) -> bool {
        self.cloud_ui
            .workspace
            .as_ref()
            .is_some_and(|workspace| workspace.registration_error.is_none())
    }
    fn begin_cloud_scan(&mut self, ctx: &egui::Context) {
        let Some(account) = self.cloud_account() else {
            return;
        };
        self.clear_cloud_results();
        self.begin_cloud_job(
            "Gathering cloud metadata…",
            ctx,
            move |path, cancel, progress| CloudEvent::Scanned {
                account: account.id(),
                generation: account.generation(),
                result: cloud::scan(path, account.id(), account.generation(), cancel, progress),
            },
        );
    }
    pub(super) fn cloud_page(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let compact_layout = ui.available_width() < 760.;
        if self.cloud_ui.older_days == 0 {
            self.cloud_ui.older_days = 365;
        }
        if !self.qa_fixture_mode()
            && (!self.cloud_ui.attempted || self.cloud_ui.reload)
            && !self.busy()
        {
            // No cloud worker is active while loading, so interrupted journal
            // rows can be safely recovered as uncertain after worker failure.
            let recover = true;
            self.cloud_ui.attempted = true;
            self.cloud_ui.reload = false;
            self.begin_cloud_job("Loading connected accounts…", ctx, move |path, _, _| {
                CloudEvent::Loaded(cloud::load(path, recover))
            });
        }
        let busy = self.busy();
        if busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(&self.progress);
                if theme::row_action(ui, "Stop", true).clicked() {
                    self.cancel.store(true, Ordering::Relaxed);
                }
            });
            ui.add_space(if compact_layout { 6. } else { 20. });
        }
        if self.cloud_ui.workspace.is_none() {
            theme::muted(
                ui,
                "Connected accounts could not be loaded. Retry to review protected provider setup.",
                t,
            );
            if theme::secondary(ui, "Retry", !busy) {
                self.cloud_ui.reload = true;
            }
            return;
        }
        let registration_error = self
            .cloud_ui
            .workspace
            .as_ref()
            .and_then(|workspace| workspace.registration_error.clone());
        if let Some(error) = registration_error.as_deref() {
            ui.horizontal_wrapped(|ui| {
                theme::muted(ui, error, t);
                if theme::secondary(ui, "Retry protected storage", !busy) {
                    self.cloud_ui.reload = true;
                }
            });
            ui.add_space(12.);
        }
        let accounts = self
            .cloud_ui
            .workspace
            .as_ref()
            .map(|w| w.accounts.clone())
            .unwrap_or_default();
        if !self.cloud_ui.introduced
            && accounts.is_empty()
            && self.cloud_ui.filter != CloudFilter::History
        {
            ui.add_space(24.);
            if ui.available_width() >= 760. {
                let text_width = ui.available_width() - 340.;
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        Vec2::new(text_width, 0.),
                        Layout::top_down(Align::Min),
                        |ui| {
                            cloud_intro_steps(ui, t);
                        },
                    );
                    self.illustrations.cloud(ui, 320.);
                });
            } else {
                ui.vertical_centered(|ui| self.illustrations.cloud(ui, 220.));
                ui.add_space(16.);
                cloud_intro_steps(ui, t);
            }
            ui.add_space(16.);
            if ui.available_width() >= 760. {
                if theme::primary(ui, "Get started", t, !busy) {
                    self.cloud_ui.introduced = true;
                }
            }
            ui.add_space(12.);
            if theme::secondary(ui, "Cleanup history", !busy) {
                self.cloud_ui.filter = CloudFilter::History;
            }
            return;
        }
        if !accounts.is_empty() {
            let old = self.cloud_ui.account;
            let account_labels: Vec<String> = accounts
                .iter()
                .map(|account| account.label().to_owned())
                .collect();
            let account_choices: Vec<&str> = account_labels.iter().map(String::as_str).collect();
            let selected_account = self
                .cloud_account()
                .map(|account| account.label().to_owned())
                .unwrap_or_else(|| "Choose an account".into());
            theme::control_row(ui, |ui| {
                ui.label(RichText::new("Account").color(t.muted));
                ui.add_enabled_ui(!busy, |ui| {
                    theme::selector(
                        ui,
                        "cloud-account",
                        &selected_account,
                        &account_choices,
                        |ui| {
                            for (account, label) in accounts.iter().zip(&account_labels) {
                                ui.selectable_value(
                                    &mut self.cloud_ui.account,
                                    Some(account.id()),
                                    label,
                                );
                            }
                        },
                    );
                });
                if theme::field_action(ui, "Add account", !busy) {
                    self.cloud_ui.filter = CloudFilter::All;
                    self.cloud_ui.account = None;
                }
                if let Some(account) = self.cloud_account() {
                    let provider = account.scope().provider();
                    if theme::field_action(ui, "Reconnect", !busy && registration_error.is_none()) {
                        self.begin_cloud_job(
                            "Reconnecting to provider…",
                            ctx,
                            move |path, cancel, progress| {
                                CloudEvent::Connected(cloud::connect(
                                    path, provider, cancel, progress,
                                ))
                            },
                        );
                    }
                    if theme::field_action(ui, "Disconnect", !busy) {
                        self.cloud_ui.dialog = Some(CloudDialog::Disconnect(account));
                    }
                }
            });
            if old != self.cloud_ui.account {
                self.clear_cloud_results();
            }
            ui.add_space(if compact_layout { 6. } else { 20. });
        }
        if self.cloud_ui.account.is_none() {
            ui.horizontal(|ui| {
                if theme::tab(ui, self.cloud_ui.filter != CloudFilter::History, "Accounts")
                    .clicked()
                {
                    self.cloud_ui.filter = CloudFilter::All;
                }
                if theme::tab(
                    ui,
                    self.cloud_ui.filter == CloudFilter::History,
                    "Cleanup history",
                )
                .clicked()
                {
                    self.cloud_ui.filter = CloudFilter::History;
                }
            });
            ui.add_space(20.);
            if self.cloud_ui.filter == CloudFilter::History {
                self.cloud_history(ui, t, ctx);
                return;
            }
            self.cloud_providers(ui, t, ctx);
            return;
        }
        let previous_filter = self.cloud_ui.filter;
        theme::tabs(ui, |ui| {
            ui.add_enabled_ui(!busy, |ui| {
                for filter in CloudFilter::ALL {
                    theme::tab_value(ui, &mut self.cloud_ui.filter, filter, filter.label())
                        .on_hover_text(filter.help());
                }
            });
        });
        if self.cloud_ui.filter != previous_filter {
            self.cloud_ui.more_open_for = None;
        }
        ui.add_space(if compact_layout { 6. } else { 20. });
        if self.cloud_ui.filter == CloudFilter::History {
            self.cloud_history(ui, t, ctx);
            return;
        }
        if let Some(snapshot) = self.cloud_ui.snapshot.clone() {
            self.cloud_results(ui, t, ctx, &snapshot);
        } else {
            ui.add_space(50.);
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new("Ready to review your cloud")
                        .family(theme::semibold())
                        .size(theme::FONT_DISPLAY),
                );
                ui.add_space(12.);
                theme::muted(
                    ui,
                    "Scan the selected account to see its current files or messages. Nothing is selected for cleanup automatically.",
                    t,
                );
            });
        }
    }
    fn cloud_providers(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        ui.vertical_centered(|ui| {
            ui.label(
                RichText::new("Clean your cloud storage account")
                    .family(theme::semibold())
                    .size(theme::FONT_DISPLAY),
            );
            ui.add_space(8.);
            theme::muted(ui, "Connect an account to scan and review its files.", t);
        });
        ui.add_space(24.);

        let columns = if ui.available_width() >= 720. { 3 } else { 2 };
        let storage = [Provider::GoogleDrive, Provider::OneDrive, Provider::Dropbox];
        for providers in storage.chunks(columns) {
            ui.columns(columns, |cells| {
                for (cell, provider) in cells.iter_mut().zip(providers) {
                    self.cloud_provider_card(cell, t, ctx, *provider);
                }
            });
            ui.add_space(16.);
        }

        ui.add_space(16.);
        ui.vertical_centered(|ui| {
            ui.label(
                RichText::new("Organize and clean your mailbox")
                    .family(theme::semibold())
                    .size(theme::FONT_DISPLAY),
            );
            ui.add_space(8.);
            theme::muted(
                ui,
                "Connect your mailbox to review messages before cleanup.",
                t,
            );
        });
        ui.add_space(24.);
        let card_width = (ui.available_width()
            - ui.spacing().item_spacing.x * (columns - 1) as f32)
            / columns as f32;
        ui.horizontal(|ui| {
            ui.add_space(((ui.available_width() - card_width) / 2.).max(0.));
            ui.allocate_ui_with_layout(
                Vec2::new(card_width, 224.),
                Layout::top_down(Align::Min),
                |ui| self.cloud_provider_card(ui, t, ctx, Provider::Gmail),
            );
        });
        ui.add_space(16.);
        theme::muted(
            ui,
            "Connecting requires account authorization. DCleaner never uses CCleaner's service credentials.",
            t,
        );
    }

    fn cloud_provider_card(
        &mut self,
        ui: &mut egui::Ui,
        t: Tokens,
        ctx: &egui::Context,
        provider: Provider,
    ) {
        let busy = self.busy();
        let account_saved = self.cloud_ui.workspace.as_ref().is_some_and(|workspace| {
            workspace
                .accounts
                .iter()
                .any(|account| account.scope().provider() == provider)
        });
        ui.push_id(provider.label(), |ui| {
            theme::card(t).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_min_height(192.);
                ui.vertical_centered(|ui| {
                    ui.add_space(10.);
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(52.), egui::Sense::hover());
                    paint_provider(ui.painter(), rect, provider);
                    ui.add_space(16.);
                    ui.label(
                        RichText::new(provider.label())
                            .family(theme::semibold())
                            .size(theme::FONT_TITLE),
                    );
                    ui.add_space(6.);
                    theme::muted(
                        ui,
                        if account_saved {
                            "Account saved on this device"
                        } else {
                            "Not connected"
                        },
                        t,
                    );
                    ui.add_space(16.);
                    if theme::primary(ui, "Connect", t, !busy) {
                        self.begin_cloud_job(
                            "Connecting to provider…",
                            ctx,
                            move |path, cancel, progress| {
                                CloudEvent::Connected(cloud::connect(
                                    path, provider, cancel, progress,
                                ))
                            },
                        );
                    }
                });
            });
        });
    }
    fn cloud_results(
        &mut self,
        ui: &mut egui::Ui,
        t: Tokens,
        _ctx: &egui::Context,
        snapshot: &Snapshot,
    ) {
        let busy = self.busy();
        let storage_available = self.cloud_storage_available();
        let compact_layout = ui.available_width() < 760.;
        let has_query = !self.cloud_ui.query.is_empty();
        let older_filter = self.cloud_ui.filter == CloudFilter::Older;
        let reserved =
            52. + if has_query { 68. } else { 0. } + if older_filter { 148. } else { 0. };
        let search_width = (ui.available_width() - reserved).clamp(150., 480.);
        theme::control_row(ui, |ui| {
            ui.label(RichText::new("Search").color(t.muted));
            theme::input(
                ui,
                &mut self.cloud_ui.query,
                search_width,
                "Files or messages",
                !busy,
            );
            if has_query && theme::field_action(ui, "Clear", !busy) {
                self.cloud_ui.query.clear();
            }
            if older_filter {
                ui.label(RichText::new("Days").color(t.muted));
                ui.add_enabled_ui(!busy, |ui| {
                    ui.add_sized(
                        Vec2::new(92., 32.),
                        egui::DragValue::new(&mut self.cloud_ui.older_days).range(1..=36500),
                    );
                });
            }
        });
        ui.add_space(if compact_layout { 5. } else { 12. });
        if !snapshot.is_complete() {
            theme::muted(
                ui,
                "This scan is incomplete. Only returned items are shown; omissions and provider limits may affect duplicate groups. Review issues before selecting cleanup.",
                t,
            );
            egui::CollapsingHeader::new(format!("Scan issues ({})", snapshot.issues().len()))
                .id_salt("cloud-partial-scan-issues")
                .default_open(false)
                .show(ui, |ui| {
                    for issue in snapshot.issues() {
                        theme::muted(
                            ui,
                            &format!("{:?} ×{}", issue.kind(), issue.occurrences()),
                            t,
                        );
                    }
                });
            ui.add_space(12.);
        }
        ui.add_space(if compact_layout { 4. } else { 12. });
        let query = self.cloud_ui.query.trim().to_lowercase();
        let duplicate_ids: HashSet<_> = snapshot
            .possible_duplicate_groups()
            .groups()
            .iter()
            .flat_map(|g| g.item_ids().iter().copied())
            .collect();
        let mut rows: Vec<_> = snapshot
            .items()
            .iter()
            .filter(|item| {
                let ignored = self.cloud_ui.ignored.contains(&item.id());
                if (self.cloud_ui.filter == CloudFilter::Ignored) != ignored {
                    return false;
                }
                if !query.is_empty() && !item.display_name().to_lowercase().contains(&query) {
                    return false;
                }
                match self.cloud_ui.filter {
                    CloudFilter::Large => item.size().is_some_and(|s| s.bytes() >= 100_000_000),
                    CloudFilter::Duplicates => duplicate_ids.contains(&item.id()),
                    CloudFilter::Older => item.provider_timestamp().is_some_and(|date| {
                        date.unix_millis()
                            < chrono::Utc::now().timestamp_millis().saturating_sub(
                                i64::from(self.cloud_ui.older_days.max(1)) * 86_400_000,
                            )
                    }),
                    _ => true,
                }
            })
            .collect();
        rows.sort_by(|a, b| {
            let order = match self.cloud_ui.sort {
                CloudSort::Name => a
                    .display_name()
                    .to_lowercase()
                    .cmp(&b.display_name().to_lowercase()),
                CloudSort::Size => a
                    .size()
                    .map(|s| s.bytes())
                    .cmp(&b.size().map(|s| s.bytes())),
                CloudSort::Date => a
                    .provider_timestamp()
                    .map(|d| d.unix_millis())
                    .cmp(&b.provider_timestamp().map(|d| d.unix_millis())),
            };
            let order = order.then_with(|| a.id().uuid().cmp(&b.id().uuid()));
            if self.cloud_ui.descending {
                order.reverse()
            } else {
                order
            }
        });
        if self
            .cloud_ui
            .more_open_for
            .is_some_and(|open| !rows.iter().any(|item| item.id() == open))
        {
            self.cloud_ui.more_open_for = None;
        }
        self.cloud_ui.shown_count = Some(rows.len());
        ui.add_space(if compact_layout { 2. } else { 8. });
        // The parent page can reserve a vertical scrollbar. Keep the table
        // inside that actual content width instead of forcing a wider grid.
        let width = ui.available_width().max(1.);
        let checkbox_width = 28.;
        let size_width = if compact_layout { 84. } else { 108. };
        let date_width = if compact_layout { 104. } else { 150. };
        let action_width = if compact_layout { 100. } else { 138. };
        let visible_gaps = 4.;
        let name_width =
            (width - checkbox_width - size_width - date_width - action_width - 8. * visible_gaps)
                .max(1.);
        ui.scope(|ui| {
            ui.set_min_width(width);
            ui.set_max_width(width);
            ui.spacing_mut().item_spacing.x = 8.;
            ui.horizontal(|ui| {
                theme::table_cell(ui,"",checkbox_width,32.);
                let columns = [
                    (CloudSort::Name, "Name", name_width),
                    (CloudSort::Size, "Size", size_width),
                    (CloudSort::Date, "Provider date", date_width),
                ];
                for (sort, label, column_width) in columns {
                    let accessible_label = format!("Sort {label}");
                    let response = cloud_sort_header(
                        ui,
                        label,
                        &accessible_label,
                        column_width,
                        self.cloud_ui.sort == sort,
                        self.cloud_ui.descending,
                        t,
                    );
                    if response.clicked() {
                        if self.cloud_ui.sort == sort {
                            self.cloud_ui.descending = !self.cloud_ui.descending;
                        } else {
                            self.cloud_ui.sort = sort;
                            self.cloud_ui.descending = false;
                        }
                    }
                }
                theme::table_cell(ui,"Actions",action_width,32.);
            });
            ui.separator();
            egui::ScrollArea::vertical()
                .id_salt("cloud-table-y")
                .max_height(410.)
                .show_rows(ui, 44., rows.len(), |ui, range| {
                    ui.spacing_mut().item_spacing.y = 0.;
                    for index in range {
                        let item = rows[index];
                        let row_top = ui.cursor().top();
                        let row_left = ui.min_rect().left();
                        let row_right = ui.min_rect().right();
                        ui.push_id(item.id(), |ui| {
                            ui.horizontal(|ui| {
                                ui.allocate_ui_with_layout(
                                    Vec2::new(checkbox_width, 44.),
                                    Layout::left_to_right(Align::Center),
                                    |ui| {
                                        let mut selected = self.cloud_ui.selected.contains(&item.id());
                                        let eligible = matches!(item.kind(), RemoteItemKind::File | RemoteItemKind::Mail)
                                            && self.cloud_ui.filter != CloudFilter::Ignored;
                                        if theme::checkbox_widget(ui, &mut selected, !busy && eligible).changed() {
                                            if selected { self.cloud_ui.selected.insert(item.id()); }
                                            else { self.cloud_ui.selected.remove(&item.id()); }
                                        }
                                    },
                                );
                                theme::table_cell(
                                    ui,
                                    RichText::new(item.display_name()).family(theme::semibold()),
                                    name_width,
                                    44.,
                                ).on_hover_text(item.display_name());
                                theme::table_cell(ui, cloud_size(item), size_width, 44.)
                                    .on_hover_text("Size is provider-reported. Gmail and other estimates are marked ≈; — means unknown.");
                                let date = item.provider_timestamp()
                                    .and_then(|d| chrono::DateTime::from_timestamp_millis(d.unix_millis()))
                                    .map(|d| d.format("%d %b %Y").to_string())
                                    .unwrap_or_else(|| "—".into());
                                theme::table_cell(ui, date, date_width, 44.);
                                ui.allocate_ui_with_layout(
                                    Vec2::new(action_width, 44.),
                                    Layout::left_to_right(Align::Center),
                                    |ui| {
                                        if theme::row_action(ui, "Review", !busy).clicked() {
                                            self.cloud_ui.dialog = Some(CloudDialog::Details(item.clone()));
                                        }
                                        let more = theme::row_more(ui, !busy);
                                        let popup = egui::Popup::menu(&more);
                                        let popup_id = popup.get_id();
                                        let popup_ctx = popup.ctx().clone();
                                        popup.show(|ui| {
                                            let details = ui.add_enabled(!busy, egui::Button::new("Details"));
                                            #[cfg(debug_assertions)]
                                            theme::record_fixture_control(ui, "Details", &details);
                                            if details.clicked() {
                                                self.cloud_ui.dialog = Some(CloudDialog::Details(item.clone()));
                                                ui.close();
                                            }
                                            if self.cloud_ui.filter == CloudFilter::Ignored {
                                                if ui.add_enabled(!busy, egui::Button::new("Include in results")).clicked() {
                                                    self.cloud_ui.ignored.remove(&item.id());
                                                    ui.close();
                                                }
                                            } else {
                                                if ui.add_enabled(!busy, egui::Button::new("Ignore for this scan")).clicked() {
                                                    self.cloud_ui.ignored.insert(item.id());
                                                    self.cloud_ui.selected.remove(&item.id());
                                                    ui.close();
                                                }
                                                if ui.add_enabled(
                                                    !busy && storage_available && matches!(item.kind(), RemoteItemKind::File | RemoteItemKind::Mail),
                                                    egui::Button::new("Move to trash…"),
                                                ).clicked() {
                                                    self.cloud_ui.dialog = Some(CloudDialog::Trash { ids: vec![item.id()], partial: false, copies: false, race: false });
                                                    ui.close();
                                                }
                                            }
                                        });
                                        let popup_open = egui::Popup::is_id_open(&popup_ctx, popup_id);
                                        if popup_open {
                                            self.cloud_ui.more_open_for = Some(item.id());
                                        } else if self.cloud_ui.more_open_for == Some(item.id()) {
                                            self.cloud_ui.more_open_for = None;
                                        }
                                    },
                                );
                            });
                        });
                        ui.painter().hline(
                            row_left..=row_right,
                            row_top + 43.,
                            egui::Stroke::new(1., t.border),
                        );
                    }
            });
        });
        if rows.is_empty() {
            ui.add_space(24.);
            theme::muted(ui, self.cloud_ui.filter.help(), t);
            theme::muted(
                ui,
                "No items match this view. Change the filter or scan again.",
                t,
            );
        }
    }
    fn cloud_history(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let busy = self.busy();
        let storage_available = self.cloud_storage_available();
        let Some(workspace) = self.cloud_ui.workspace.as_ref() else {
            return;
        };
        let records = workspace.history.records().to_vec();
        let next = workspace.history.next_cursor();
        theme::muted(
            ui,
            "Confirmed outcomes are provider acknowledgments. An uncertain operation may have changed the remote item; it is never retried automatically. Restore requires the same connected account and provider support.",
            t,
        );
        ui.add_space(16.);
        for record in records {
            let restore_attempted = workspace.restore_attempts.contains(&record.id());
            let can_restore = cloud::can_restore_record(&record) && !restore_attempted;
            let restore_reason = restore_unavailable_reason(&record, restore_attempted);
            ui.push_id(record.id(), |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new(record.name()).family(theme::semibold()));
                        theme::muted(
                            ui,
                            &format!("{:?} · {:?}", record.action(), record.state()),
                            t,
                        );
                        if let Some(status) = record.status_code() {
                            theme::muted(ui, operation_status_text(status), t);
                        }
                        if !can_restore {
                            theme::muted(ui, restore_reason, t);
                        }
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let connected = self.cloud_ui.workspace.as_ref().is_some_and(|w| {
                            w.accounts.iter().any(|a| a.id() == record.account_id())
                        });
                        let response = theme::row_action(
                            ui,
                            "Review restore",
                            !busy && storage_available && connected && can_restore,
                        );
                        if response.clicked() {
                            self.cloud_ui.dialog = Some(CloudDialog::Restore(record.clone()));
                        }
                        response.on_hover_text(if !storage_available {
                            "Protected credential storage is unavailable. Retry before restoring."
                        } else if can_restore && connected {
                            "Review this confirmed provider trash receipt before restoring."
                        } else if can_restore {
                            "Reconnect the original account before reviewing restore."
                        } else {
                            restore_reason
                        });
                    });
                });
                ui.separator();
            });
        }
        if self
            .cloud_ui
            .workspace
            .as_ref()
            .is_some_and(|w| w.history.records().is_empty())
        {
            theme::muted(
                ui,
                "No cloud cleanup operations are recorded on this device.",
                t,
            );
        }
        ui.horizontal(|ui| {
            if let Some(previous) = self.cloud_ui.history_back.last().copied() {
                if theme::secondary(ui, "Newer outcomes", !busy) {
                    let from = self.cloud_ui.history_before;
                    self.begin_cloud_job("Loading cloud history…", ctx, move |path, _, _| {
                        CloudEvent::History {
                            before: previous,
                            from,
                            back: true,
                            result: cloud::history(path, previous),
                        }
                    });
                }
            }
            if let Some(cursor) = next {
                if theme::secondary(ui, "Older outcomes", !busy) {
                    let from = self.cloud_ui.history_before;
                    let before = Some(cursor);
                    self.begin_cloud_job("Loading cloud history…", ctx, move |path, _, _| {
                        CloudEvent::History {
                            before,
                            from,
                            back: false,
                            result: cloud::history(path, before),
                        }
                    });
                }
            }
        });
    }
    pub(super) fn cloud_footer(&mut self, ui: &mut egui::Ui, t: Tokens, ctx: &egui::Context) {
        let busy = self.busy();
        let storage_available = self.cloud_storage_available();
        let compact = ui.available_width() < 760.;
        ui.horizontal(|ui| {
            if self.cloud_ui.account.is_some() && self.cloud_ui.filter != CloudFilter::History {
                if theme::secondary(
                    ui,
                    if self.cloud_ui.snapshot.is_some() {
                        "Scan again"
                    } else {
                        "Scan files"
                    },
                    !busy && storage_available,
                ) {
                    self.begin_cloud_scan(ctx);
                }
            }
            ui.with_layout(
                Layout::right_to_left(Align::Center).with_main_wrap(true),
                |ui| {
                    if self.cloud_ui.filter == CloudFilter::History {
                        if theme::secondary(ui, "Refresh history", !busy) {
                            self.cloud_ui.reload = true;
                        }
                        return;
                    }
                    if self.cloud_ui.account.is_some() {
                        let selected = self.cloud_ui.selected.len();
                        let count = self
                            .cloud_ui
                            .shown_count
                            .map(|shown| format!("{shown} shown · {selected} selected"))
                            .unwrap_or_else(|| format!("{selected} selected"));
                        let label = if selected == 0 {
                            "Review selected".into()
                        } else {
                            format!("Review {}", theme::counted_label(selected, "item", "items"))
                        };
                        if theme::primary(
                            ui,
                            &label,
                            t,
                            !busy && storage_available && !self.cloud_ui.selected.is_empty(),
                        )
                        .then_some(())
                        .is_some()
                        {
                            self.cloud_ui.dialog = Some(CloudDialog::Trash {
                                ids: self.cloud_ui.selected.iter().copied().collect(),
                                partial: false,
                                copies: false,
                                race: false,
                            });
                        }
                        theme::muted(ui, &count, t);
                        if selected > 0 && theme::secondary(ui, "Clear selection", !busy) {
                            self.cloud_ui.selected.clear();
                        }
                    } else if !self.cloud_ui.introduced && compact {
                        if theme::primary(ui, "Get started", t, !busy) {
                            self.cloud_ui.introduced = true;
                        }
                    } else {
                        theme::muted(ui, "Choose a provider to connect", t);
                    }
                },
            );
        });
    }
    pub(super) fn cloud_dialog(&mut self, ctx: &egui::Context) {
        let t = theme::tokens(self.prefs.dark);
        let busy = self.busy();
        let storage_available = self
            .cloud_ui
            .workspace
            .as_ref()
            .is_some_and(|workspace| workspace.registration_error.is_none());
        if self.cloud_ui.pending.is_some() {
            let choices = self.cloud_ui.pending.as_ref().unwrap().choices();
            let mut chosen = None;
            let mut cancel = false;
            let response=egui::Modal::new(egui::Id::new("cloud-drive-choice")).frame(theme::dialog_frame(t)).show(ctx,|ui|{ui.set_width(460.);ui.heading("Choose your OneDrive");ui.add_space(12.);theme::muted(ui,"Select an existing drive. DCleaner has not created or provisioned storage.",t);ui.add_space(16.);for choice in choices{if theme::secondary(ui,&format!("{} · {}",choice.name(),choice.drive_type().unwrap_or("Drive")),!busy){chosen=Some(choice.id().to_owned());}}if theme::secondary(ui,"Cancel",!busy){cancel=true;}});
            if response.should_close() && !busy {
                cancel = true;
            }
            if cancel {
                self.cloud_ui.pending = None;
            }
            if let Some(drive) = chosen {
                let pending = self.cloud_ui.pending.take().unwrap();
                self.begin_cloud_job(
                    "Verifying selected cloud storage…",
                    ctx,
                    move |path, cancel, _| {
                        CloudEvent::Chosen(cloud::choose_drive(path, pending, &drive, cancel))
                    },
                );
            }
            return;
        }
        let Some(mut dialog) = self.cloud_ui.dialog.take() else {
            return;
        };
        let mut close = false;
        let mut command = None;
        let response=egui::Modal::new(egui::Id::new("cloud-review")).frame(theme::dialog_frame(t)).show(ctx,|ui|{
            ui.set_width((ctx.content_rect().width()-80.).clamp(280.,580.));
            match &mut dialog{
                CloudDialog::Disconnect(account)=>{
                    ui.heading("Disconnect this account?");ui.add_space(12.);ui.label(account.label());theme::muted(ui,"This removes DCleaner's protected credential on this device. It keeps cleanup history and does not revoke the provider grant or alter your remote files.",t);ui.add_space(20.);theme::action_row(ui,|ui|{if theme::secondary(ui,"Keep connected",!busy){close=true;}if theme::primary(ui,"Disconnect",t,!busy){command=Some(CloudCommand::Disconnect(account.id(),account.generation()));}});
                },
                CloudDialog::Details(item)=>{
                    ui.heading("Item details");ui.add_space(16.);ui.label(RichText::new(item.display_name()).family(theme::semibold()));
                    for(label,value)in[("Type",format!("{:?}",item.kind())),("Size",cloud_size(item)),("Size source",item.size().map(|s|format!("{:?}",s.accuracy())).unwrap_or_else(||"Unknown".into())),("Provider revision",item.provider_revision().unwrap_or("Unknown").to_owned()),("Trash state",format!("{:?}",item.trash_status())),("Hash evidence",item.content_hash().map(|h|format!("{:?} · equality unverified",h.algorithm())).unwrap_or_else(||"Not supplied".into()))]{ui.horizontal_wrapped(|ui|{theme::muted(ui,label,t);ui.label(value);});}
                    if let Some(date)=item.provider_timestamp(){ui.add_space(8.);ui.label(format!("{}: {}",if self.cloud_account().is_some_and(|a|a.scope().provider()==Provider::Gmail){"Gmail internal date"}else{"Provider modified date"},chrono::DateTime::from_timestamp_millis(date.unix_millis()).map(|d|d.to_rfc3339()).unwrap_or_else(||"Unknown".into())));}
                    ui.add_space(20.);theme::action_row(ui,|ui|{if theme::secondary(ui,"Close",true){close=true;}if theme::primary(ui,"Review trash",t,!busy&&storage_available&&matches!(item.kind(),RemoteItemKind::File|RemoteItemKind::Mail)){command=Some(CloudCommand::Review(item.id()));}});
                },
                CloudDialog::Trash{ids,partial,copies,race}=>{
                    ui.heading("Review cloud cleanup");ui.add_space(12.);theme::muted(ui,"Move only the reviewed items to provider trash. This may affect synced devices. Provider trash retention varies and quota may remain occupied; DCleaner never permanently deletes cloud content.",t);
                    if let Some(snapshot)=self.cloud_ui.snapshot.as_ref(){
                        egui::ScrollArea::vertical().max_height(230.).show(ui,|ui|{for item in snapshot.items().iter().filter(|item|ids.contains(&item.id())){ui.horizontal(|ui|{theme::table_cell(ui,item.display_name(),350.,28.);ui.label(cloud_size(item));});}});
                        if !snapshot.is_complete(){theme::checkbox(ui,partial,"I reviewed the partial-scan issues and missing items.",!busy);}
                        let selected:HashSet<_>=ids.iter().copied().collect();let all_copies=snapshot.possible_duplicate_groups().groups().iter().any(|g|g.item_ids().iter().all(|id|selected.contains(id)));
                        if all_copies{theme::checkbox(ui,copies,"I intend to trash every displayed copy in at least one possible duplicate group.",!busy);}
                        theme::checkbox(ui,race,"I reviewed these items. Some provider APIs cannot atomically guard changes made after preflight.",!busy);
                        if !storage_available{theme::muted(ui,"Protected credential storage is unavailable. Retry before starting a cloud change.",t);}
                        ui.add_space(16.);let ready=storage_available&&*race&&(snapshot.is_complete()||*partial)&&(!all_copies||*copies)&&ids.len()<=200;
                        if ids.len()>200{theme::muted(ui,"Review at most 200 items per cleanup batch.",t);}
                        theme::action_row(ui,|ui|{if theme::secondary(ui,"Keep items",!busy){close=true;}if theme::primary(ui,"Move to trash",t,!busy&&ready){command=Some(CloudCommand::Trash(ids.clone(),*partial,*copies,*race));}});
                    }else{theme::muted(ui,"These results expired. Scan the connected account again.",t);if theme::secondary(ui,"Close",true){close=true;}}
                },
                CloudDialog::Restore(record)=>{
                    let restore_attempted=self.cloud_ui.workspace.as_ref().is_some_and(|workspace|workspace.restore_attempts.contains(&record.id()));
                    let connected=self.cloud_ui.workspace.as_ref().is_some_and(|workspace|workspace.accounts.iter().any(|account|account.id()==record.account_id()));
                    let can_restore=cloud::can_restore_record(record)&&!restore_attempted;
                    ui.heading("Review restore");ui.add_space(12.);ui.label(record.name());theme::muted(ui,"Restore uses the original connected account and a fresh provider check. Provider retention, conflicting paths and unsupported storage types can prevent restoration. An uncertain outcome is never automatically retried.",t);if !can_restore{theme::muted(ui,restore_unavailable_reason(record,restore_attempted),t);}if !connected{theme::muted(ui,"Reconnect the original account before restoring.",t);}if !storage_available{theme::muted(ui,"Protected credential storage is unavailable. Retry before restoring.",t);}ui.add_space(20.);theme::action_row(ui,|ui|{if theme::secondary(ui,"Cancel",!busy){close=true;}if theme::primary(ui,"Restore item",t,!busy&&storage_available&&connected&&can_restore){command=Some(CloudCommand::Restore(record.clone()));}});
                },
            }
        });
        if response.should_close() && !busy {
            close = true;
        }
        if !close {
            self.cloud_ui.dialog = Some(dialog);
        }
        if let Some(command) = command {
            self.run_cloud_command(command, ctx);
        }
    }
    fn run_cloud_command(&mut self, command: CloudCommand, ctx: &egui::Context) {
        match command {
            CloudCommand::Disconnect(id, generation) => {
                self.begin_cloud_job("Disconnecting this device…", ctx, move |path, _, _| {
                    CloudEvent::Disconnected(cloud::disconnect(path, id, generation))
                })
            }
            CloudCommand::Review(id) => {
                self.cloud_ui.dialog = Some(CloudDialog::Trash {
                    ids: vec![id],
                    partial: false,
                    copies: false,
                    race: false,
                })
            }
            CloudCommand::Trash(ids, partial, copies, race) => {
                if !self.cloud_storage_available() {
                    self.error = Some(
                        "Protected credential storage is unavailable. Retry before starting a cloud change.".into(),
                    );
                    return;
                }
                let Some(account) = self.cloud_account() else {
                    return;
                };
                let Some(snapshot) = self.cloud_ui.snapshot.clone() else {
                    return;
                };
                match cloud::review_trash(&account, &snapshot, &ids, partial, copies, race) {
                    Ok(review) => self.begin_cloud_job(
                        "Reviewing cloud items before trash…",
                        ctx,
                        move |path, cancel, progress| {
                            CloudEvent::Changed(cloud::trash(path, review, cancel, progress))
                        },
                    ),
                    Err(error) => self.error = Some(error),
                }
            }
            CloudCommand::Restore(record) => {
                if !self.cloud_storage_available() {
                    self.error = Some(
                        "Protected credential storage is unavailable. Retry before restoring."
                            .into(),
                    );
                    return;
                }
                let restore_attempted = self
                    .cloud_ui
                    .workspace
                    .as_ref()
                    .is_some_and(|workspace| workspace.restore_attempts.contains(&record.id()));
                if restore_attempted || !cloud::can_restore_record(&record) {
                    self.error =
                        Some(restore_unavailable_reason(&record, restore_attempted).into());
                    return;
                }
                let account = self
                    .cloud_ui
                    .workspace
                    .as_ref()
                    .and_then(|w| w.accounts.iter().find(|a| a.id() == record.account_id()))
                    .cloned();
                let Some(account) = account else {
                    return;
                };
                self.begin_cloud_job(
                    "Reviewing provider restore…",
                    ctx,
                    move |path, cancel, progress| {
                        CloudEvent::Changed(cloud::restore(
                            path, &account, &record, cancel, progress,
                        ))
                    },
                );
            }
        }
    }
}
enum CloudCommand {
    Disconnect(Uuid, Uuid),
    Review(ScanItemId),
    Trash(Vec<ScanItemId>, bool, bool, bool),
    Restore(OperationRecord),
}
fn cloud_sort_header(
    ui: &mut egui::Ui,
    label: &str,
    accessible_label: &str,
    width: f32,
    selected: bool,
    descending: bool,
    t: Tokens,
) -> egui::Response {
    let shown = if selected {
        format!("{label} {}", if descending { "↓" } else { "↑" })
    } else {
        label.to_owned()
    };
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 32.), egui::Sense::click());
    let color = if selected || response.hovered() {
        t.foreground
    } else {
        t.muted
    };
    ui.painter().text(
        rect.left_center(),
        egui::Align2::LEFT_CENTER,
        shown,
        egui::FontId::new(theme::FONT_CAPTION, theme::semibold()),
        color,
    );
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, true, accessible_label)
    });
    #[cfg(debug_assertions)]
    theme::record_fixture_control(ui, accessible_label, &response);
    response.on_hover_text(format!("{accessible_label} by {label}"))
}

#[cfg(any(test, debug_assertions))]
fn cloud_sort_label(sort: CloudSort) -> &'static str {
    match sort {
        CloudSort::Name => "Name",
        CloudSort::Size => "Size",
        CloudSort::Date => "Provider date",
    }
}

fn cloud_size(item: &RemoteItem) -> String {
    item.size()
        .map(|s| {
            format!(
                "{}{}",
                if s.accuracy() == SizeAccuracy::ProviderReportedExact {
                    ""
                } else {
                    "≈ "
                },
                size(s.bytes())
            )
        })
        .unwrap_or_else(|| "—".into())
}

fn operation_status_text(status: OperationStatusCode) -> &'static str {
    match status {
        OperationStatusCode::Interrupted => {
            "Interrupted before a final provider outcome was saved."
        }
        OperationStatusCode::ProviderConflict => "The provider reported a conflicting change.",
        OperationStatusCode::ProviderNotFound => "The provider could not find this item.",
        OperationStatusCode::AuthenticationRequired => "Provider authorization needs attention.",
        OperationStatusCode::PermissionDenied => "The provider denied this action.",
        OperationStatusCode::RateLimited => "The provider rate limit was reached.",
        OperationStatusCode::TemporarilyUnavailable => "The provider is temporarily unavailable.",
        OperationStatusCode::InvalidResponse => "The provider returned an invalid response.",
        OperationStatusCode::Cancelled => "The operation was stopped.",
        OperationStatusCode::Other => "The provider did not confirm the operation.",
        OperationStatusCode::AlreadySatisfied => {
            "The provider reports this state is already satisfied."
        }
        OperationStatusCode::AccountChanged => "The connected account changed during review.",
    }
}

fn restore_unavailable_reason(record: &OperationRecord, restore_attempted: bool) -> &'static str {
    if record.action() != CloudAction::Trash {
        return "This is a restore operation; restoring it again is not supported.";
    }
    if restore_attempted {
        return "A restore attempt is already recorded for this trash operation.";
    }
    match record.state() {
        dcleaner::cloud_store::OperationState::Started => {
            "This operation has no final outcome yet. Review it after recovery."
        }
        dcleaner::cloud_store::OperationState::Failed => {
            "The trash operation failed, so there is no confirmed item to restore."
        }
        dcleaner::cloud_store::OperationState::Uncertain => {
            "The provider outcome is uncertain. Verify it before taking another action."
        }
        dcleaner::cloud_store::OperationState::Confirmed => {
            "The confirmed provider receipt does not include a supported restore instruction."
        }
    }
}

/// Provider marks are vector geometry, kept separate from the navigation icon.
fn cloud_intro_steps(ui: &mut egui::Ui, t: Tokens) {
    for (index, icon, title, description) in [
        (
            0,
            theme::Icon::Cloud,
            "Sign in to your cloud account",
            "Connect Google Drive, Gmail, OneDrive or Dropbox through your provider account.",
        ),
        (
            1,
            theme::Icon::Duplicate,
            "Scan your files",
            "Review possible duplicates, large files and older items. Scanning leaves your content in place.",
        ),
        (
            2,
            theme::Icon::Brush,
            "Choose what to clean",
            "Inspect each item before moving it to provider trash. Check the outcome in cleanup history.",
        ),
    ] {
        ui.horizontal_top(|ui| {
            let text_width = (ui.available_width() - 44.).max(120.);
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(28.), egui::Sense::hover());
            theme::paint_icon(ui.painter(), rect, icon, t.primary);
            ui.add_space(8.);
            ui.vertical(|ui| {
                ui.set_width(text_width);
                ui.label(
                    RichText::new(title)
                        .family(theme::semibold())
                        .size(theme::FONT_TITLE),
                );
                ui.add_space(6.);
                ui.add(egui::Label::new(RichText::new(description).color(t.muted)).wrap());
                if index == 0 {
                    ui.add_space(10.);
                    ui.horizontal(|ui| {
                        for provider in cloud::PROVIDERS {
                            let (rect, response) =
                                ui.allocate_exact_size(Vec2::splat(22.), egui::Sense::hover());
                            paint_provider(ui.painter(), rect, provider);
                            response.on_hover_text(provider.label());
                        }
                    });
                }
            });
        });
        ui.add_space(20.);
    }
}

fn paint_provider(p: &egui::Painter, rect: egui::Rect, provider: Provider) {
    let point = |x: f32, y: f32| rect.min + Vec2::new(x, y) * (rect.width() / 36.);
    let polygon = |xy: &[(f32, f32)], color| {
        p.add(egui::Shape::convex_polygon(
            xy.iter().map(|&(x, y)| point(x, y)).collect(),
            color,
            egui::Stroke::NONE,
        ))
    };
    let blue = Color32::from_rgb(0, 120, 240);
    match provider {
        Provider::GoogleDrive => {
            polygon(
                &[(13., 3.), (23., 3.), (36., 26.), (26., 26.)],
                Color32::from_rgb(255, 193, 7),
            );
            polygon(
                &[(13., 3.), (0., 26.), (5., 34.), (18., 11.)],
                Color32::from_rgb(15, 157, 88),
            );
            polygon(
                &[(5., 34.), (31., 34.), (36., 26.), (10., 26.)],
                Color32::from_rgb(66, 133, 244),
            );
        }
        Provider::Gmail => {
            polygon(
                &[
                    (2., 8.),
                    (8., 8.),
                    (18., 16.),
                    (28., 8.),
                    (34., 8.),
                    (34., 31.),
                    (28., 31.),
                    (28., 16.),
                    (18., 24.),
                    (8., 16.),
                    (8., 31.),
                    (2., 31.),
                ],
                Color32::from_rgb(234, 67, 53),
            );
            polygon(
                &[(2., 8.), (8., 13.), (8., 31.), (2., 31.)],
                Color32::from_rgb(66, 133, 244),
            );
            polygon(
                &[(28., 13.), (34., 8.), (34., 31.), (28., 31.)],
                Color32::from_rgb(52, 168, 83),
            );
        }
        Provider::OneDrive => {
            p.circle_filled(
                point(15., 16.),
                rect.width() * 0.29,
                Color32::from_rgb(0, 90, 170),
            );
            p.circle_filled(
                point(24., 20.),
                rect.width() * 0.27,
                Color32::from_rgb(0, 120, 212),
            );
            p.circle_filled(point(8., 23.), rect.width() * 0.20, blue);
            p.rect_filled(
                egui::Rect::from_min_max(point(7., 21.), point(29., 30.)),
                5.,
                blue,
            );
        }
        Provider::Dropbox => {
            for (x, y) in [(9., 8.), (27., 8.), (9., 21.), (27., 21.), (18., 31.)] {
                polygon(
                    &[(x, y - 6.), (x + 9., y), (x, y + 6.), (x - 9., y)],
                    Color32::from_rgb(0, 97, 255),
                );
            }
        }
    }
}
