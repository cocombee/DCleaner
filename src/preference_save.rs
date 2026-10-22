//! Serialized preference writes, separate from maintenance workers.
use super::{App, Page, Preferences, theme};
use eframe::egui;
use std::{path::Path, sync::mpsc, thread};
const SAVE_ERROR_PREFIX: &str = "Preferences were not saved: ";

pub(super) struct Pending {
    receiver: mpsc::Receiver<Result<(), String>>,
    proposed: Preferences,
    commit: bool,
    origin: Page,
    notice: Option<String>,
    #[cfg(debug_assertions)]
    _fixture_guard: Option<mpsc::Sender<Result<(), String>>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcleaner::domain::LandingPage;
    use std::time::{Duration, Instant};

    fn fixture() -> (egui::Context, App, tempfile::TempDir) {
        let ctx = egui::Context::default();
        let mut app = App::new_fixture_with_context(&ctx, "settings-menu-layout").unwrap();
        let root = tempfile::tempdir().unwrap();
        app.data_dir = root.path().to_owned();
        app.qa_fixture_mode = false;
        dcleaner::store::save_preferences(root.path(), &app.prefs).unwrap();
        (ctx, app, root)
    }

    fn command(output: &egui::FullOutput, close: bool) -> bool {
        output.viewport_output.values().any(|v| {
            v.commands.iter().any(|c| {
                if close {
                    matches!(c, egui::ViewportCommand::Close)
                } else {
                    matches!(c, egui::ViewportCommand::CancelClose)
                }
            })
        })
    }

    fn text_shape(shape: &egui::Shape, text: &str) -> bool {
        match shape {
            egui::Shape::Text(value) => value.galley.job.text.contains(text),
            egui::Shape::Vec(shapes) => shapes.iter().any(|shape| text_shape(shape, text)),
            _ => false,
        }
    }

    fn settle(ctx: &egui::Context, app: &mut App) -> bool {
        let until = Instant::now() + Duration::from_secs(3);
        let mut closed = false;
        while app.preferences_busy() && Instant::now() < until {
            let mut out = ctx.run_ui(Default::default(), |_| app.poll(ctx));
            out.textures_delta.clear();
            closed |= command(&out, true);
            thread::yield_now();
        }
        assert!(!app.preferences_busy(), "owned writer must finish");
        closed
    }

    #[test]
    fn blocked_writer_keeps_frames_responsive_and_commits_only_after_success() {
        let (ctx, mut app, root) = fixture();
        let before = app.prefs.landing_page;
        let mut proposed = app.prefs.clone();
        proposed.landing_page = LandingPage::CustomClean;
        proposed.set_appearance(dcleaner::domain::AppearanceMode::Light, None);
        let (entered, ready) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        app.start_preferences_writer(proposed, true, Page::Settings, None, move |path, value| {
            entered.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            dcleaner::store::save_preferences(path, value)
        })
        .unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(app.prefs.landing_page, before);
        assert!(
            !app.busy(),
            "saving welcome flags must not swallow the maintenance action which follows them"
        );
        let start = Instant::now();
        let mut pending_notice = false;
        for tick in 0..3 {
            let mut out = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(920., 612.),
                    )),
                    time: Some(tick as f64 / 30.),
                    ..Default::default()
                },
                |ui| app.paint(ui),
            );
            out.textures_delta.clear();
            pending_notice |= out
                .shapes
                .iter()
                .any(|shape| text_shape(&shape.shape, "Saving preferences…"));
        }
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(
            pending_notice,
            "a slow save must have visible feedback on its owner page"
        );
        assert_eq!(app.prefs.landing_page, before);
        release.send(()).unwrap();
        assert!(!settle(&ctx, &mut app));
        assert_eq!(app.prefs.landing_page, LandingPage::CustomClean);
        assert_eq!(
            app.prefs.appearance_mode(),
            dcleaner::domain::AppearanceMode::Light
        );
        assert!(!app.prefs.dark);
        assert_eq!(ctx.theme(), egui::Theme::Light);
        assert_eq!(
            dcleaner::store::load_preferences(root.path())
                .unwrap()
                .landing_page,
            LandingPage::CustomClean
        );
    }

    #[test]
    fn deferred_welcome_flags_follow_reset_and_close_waits_for_the_last_write() {
        let (ctx, mut app, root) = fixture();
        app.prefs.seen_features = vec!["health".into(), "software".into()];
        let mut proposed = app.prefs.clone();
        proposed.seen_features.clear();
        let (entered, ready) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        app.start_preferences_writer(
            proposed,
            true,
            Page::Settings,
            Some("reset saved".into()),
            move |path, value| {
                entered.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(5)).unwrap();
                dcleaner::store::save_preferences(path, value)
            },
        )
        .unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        app.mark_feature_seen("duplicates");
        app.mark_feature_seen("duplicates");
        assert_eq!(app.deferred_seen_features.len(), 1);
        let mut out = ctx.run_ui(Default::default(), |_| app.handle_preferences_close(&ctx));
        out.textures_delta.clear();
        assert!(command(&out, false) && !command(&out, true));
        app.page = Page::Duplicates;
        release.send(()).unwrap();
        assert!(settle(&ctx, &mut app));
        assert_eq!(app.prefs.seen_features, vec!["duplicates"]);
        assert_eq!(
            dcleaner::store::load_preferences(root.path())
                .unwrap()
                .seen_features,
            vec!["duplicates"]
        );
        assert!(app.notice_page == Some(Page::Settings));
    }

    #[test]
    fn failed_save_preserves_old_bytes_and_reports_on_its_owner_without_auto_closing() {
        for closing in [false, true] {
            let (ctx, mut app, root) = fixture();
            let before = std::fs::read(root.path().join("preferences.json")).unwrap();
            let landing = app.prefs.landing_page;
            let mut proposed = app.prefs.clone();
            proposed.landing_page = LandingPage::CustomClean;
            let (entered, ready) = mpsc::channel();
            let (release, wait) = mpsc::channel();
            app.start_preferences_writer(
                proposed,
                true,
                Page::Settings,
                Some("must not appear".into()),
                move |_, _| {
                    entered.send(()).unwrap();
                    wait.recv_timeout(Duration::from_secs(5)).unwrap();
                    Err("fixture write failure".into())
                },
            )
            .unwrap();
            ready.recv_timeout(Duration::from_secs(2)).unwrap();
            if closing {
                let mut out =
                    ctx.run_ui(Default::default(), |_| app.handle_preferences_close(&ctx));
                out.textures_delta.clear();
                assert!(command(&out, false));
            }
            app.page = Page::Duplicates;
            release.send(()).unwrap();
            assert!(!settle(&ctx, &mut app));
            assert_eq!(app.prefs.landing_page, landing);
            assert_eq!(
                std::fs::read(root.path().join("preferences.json")).unwrap(),
                before
            );
            if closing {
                assert!(app.page == Page::Settings);
                assert!(
                    app.error
                        .as_ref()
                        .unwrap()
                        .contains("fixture write failure")
                );
            } else {
                assert!(app.page == Page::Duplicates);
                assert!(app.notice_page == Some(Page::Settings));
                assert!(
                    app.notice
                        .as_ref()
                        .unwrap()
                        .contains("fixture write failure")
                );
                assert!(matches!(app.notice_kind, theme::StatusKind::Error));
            }
            assert!(!app.close_after_preferences);
            let mut out = ctx.run_ui(Default::default(), |_| app.handle_preferences_close(&ctx));
            out.textures_delta.clear();
            assert!(!command(&out, false), "a subsequent close is not trapped");
            if !closing {
                app.error = Some("unrelated operation error".into());
            }
            let mut retry = app.prefs.clone();
            retry.landing_page = LandingPage::CustomClean;
            app.queue_preferences(retry, None).unwrap();
            assert!(!settle(&ctx, &mut app));
            assert_eq!(
                dcleaner::store::load_preferences(root.path())
                    .unwrap()
                    .landing_page,
                LandingPage::CustomClean
            );
            assert!(
                !app.notice
                    .as_deref()
                    .is_some_and(|m| m.starts_with(SAVE_ERROR_PREFIX))
            );
            if closing {
                assert!(app.error.is_none());
            } else {
                assert_eq!(app.error.as_deref(), Some("unrelated operation error"));
            }
        }
    }

    #[test]
    fn a_disconnected_writer_cannot_commit_or_trigger_a_close() {
        let (ctx, mut app, _) = fixture();
        let before = app.prefs.landing_page;
        let mut proposed = app.prefs.clone();
        proposed.landing_page = LandingPage::CustomClean;
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        app.preferences_job = Some(Pending {
            receiver,
            proposed,
            commit: true,
            origin: Page::Settings,
            notice: None,
            #[cfg(debug_assertions)]
            _fixture_guard: None,
        });
        app.close_after_preferences = true;
        assert!(!settle(&ctx, &mut app));
        assert_eq!(app.prefs.landing_page, before);
        assert!(
            app.error
                .as_ref()
                .unwrap()
                .contains("stopped without a saved result")
        );
    }

    #[test]
    fn failed_draft_error_survives_a_later_background_flag_save() {
        let (ctx, mut app, root) = fixture();
        let before = app.prefs.landing_page;
        let mut proposed = app.prefs.clone();
        proposed.landing_page = LandingPage::CustomClean;
        let (entered, ready) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        app.start_preferences_writer(proposed, true, Page::Settings, None, move |_, _| {
            entered.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            Err("fixture draft failure".into())
        })
        .unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        app.mark_feature_seen("duplicates");
        release.send(()).unwrap();
        assert!(!settle(&ctx, &mut app));
        let saved = dcleaner::store::load_preferences(root.path()).unwrap();
        assert_eq!(app.prefs.landing_page, before);
        assert_eq!(saved.landing_page, before);
        assert!(saved.seen_features.contains(&"duplicates".into()));
        assert!(
            app.notice
                .as_ref()
                .unwrap()
                .contains("fixture draft failure")
        );
        assert!(app.preferences_failed_draft);
    }
}

impl App {
    #[cfg(debug_assertions)]
    pub(super) fn seed_preferences_saving_qa(&mut self) -> Result<(), String> {
        if !self.qa_fixture_mode() || self.preferences_busy() {
            return Err("Pending preferences require an idle isolated fixture.".into());
        }
        let (sender, receiver) = mpsc::channel();
        self.preferences_job = Some(Pending {
            receiver,
            proposed: self.prefs.clone(),
            commit: true,
            origin: self.page,
            notice: None,
            _fixture_guard: Some(sender),
        });
        Ok(())
    }
    pub(super) fn preferences_busy(&self) -> bool {
        self.preferences_job.is_some() || self.page_choices_job.is_some()
    }

    pub(super) fn preference_save_notice_visible(&self) -> bool {
        !self.busy()
            && self
                .preferences_job
                .as_ref()
                .is_some_and(|job| job.origin == self.page)
    }

    pub(super) fn queue_preferences(
        &mut self,
        proposed: Preferences,
        notice: Option<&str>,
    ) -> Result<(), String> {
        if self.qa_fixture_mode() {
            self.prefs = proposed;
            if let Some(notice) = notice {
                self.set_notice(notice.into());
            }
            return Ok(());
        }
        if !self.settings_readable {
            return Err("Preferences could not be read, so the change was not saved.".into());
        }
        self.start_preferences_writer(
            proposed,
            true,
            self.page,
            notice.map(str::to_owned),
            dcleaner::store::save_preferences,
        )
        .map_err(|error| {
            self.preferences_failed_draft = true;
            format!("{SAVE_ERROR_PREFIX}{error}")
        })
    }

    pub(super) fn persist_preferences(&mut self) {
        if self.qa_fixture_mode() || !self.settings_readable {
            return;
        }
        if self.preferences_busy() {
            self.preferences_dirty = true;
            self.preferences_dirty_origin = Some(self.page);
            return;
        }
        self.preferences_dirty = false;
        let origin = self.preferences_dirty_origin.take().unwrap_or(self.page);
        if let Err(error) = self.start_preferences_writer(
            self.prefs.clone(),
            false,
            origin,
            None,
            dcleaner::store::save_preferences,
        ) {
            self.preference_save_error(origin, error, false);
        }
    }

    fn start_preferences_writer(
        &mut self,
        proposed: Preferences,
        commit: bool,
        origin: Page,
        notice: Option<String>,
        write: impl FnOnce(&Path, &Preferences) -> Result<(), String> + Send + 'static,
    ) -> Result<(), String> {
        if self.preferences_busy() {
            return Err("Preferences are still being saved.".into());
        }
        if !self.data_dir.is_absolute() {
            return Err(
                "The preferences directory is unavailable; no settings were written.".into(),
            );
        }
        let root = self.data_dir.clone();
        let value = proposed.clone();
        let ctx = self.ui_context.clone();
        let (sender, receiver) = mpsc::channel();
        thread::Builder::new()
            .name("dcleaner-preferences".into())
            .spawn(move || {
                let result = write(&root, &value);
                let _ = sender.send(result);
                ctx.request_repaint();
            })
            .map_err(|error| format!("Could not start the preferences writer: {error}"))?;
        self.preferences_job = Some(Pending {
            receiver,
            proposed,
            commit,
            origin,
            notice,
            #[cfg(debug_assertions)]
            _fixture_guard: None,
        });
        self.ui_context.request_repaint();
        Ok(())
    }

    fn preference_save_error(&mut self, origin: Page, error: String, failed_draft: bool) {
        self.preferences_failed_draft |= failed_draft;
        let message = format!("{SAVE_ERROR_PREFIX}{error}");
        if self.close_after_preferences {
            self.page = origin;
            self.clear_unrelated_messages();
            self.error = Some(message);
        } else {
            self.set_page_notice(message, origin, theme::StatusKind::Error, true);
        }
        // Show the failure before allowing a subsequent close request.
        self.close_after_preferences = false;
    }

    pub(super) fn poll_preferences(&mut self, ctx: &egui::Context) {
        let result = match self
            .preferences_job
            .as_ref()
            .map(|job| job.receiver.try_recv())
        {
            Some(Ok(result)) => result,
            Some(Err(mpsc::TryRecvError::Disconnected)) => {
                Err("The preferences writer stopped without a saved result.".into())
            }
            _ => return,
        };
        let job = self.preferences_job.take().unwrap();
        match result {
            Ok(()) => {
                if job.commit || !self.preferences_failed_draft {
                    if self
                        .notice
                        .as_deref()
                        .is_some_and(|m| m.starts_with(SAVE_ERROR_PREFIX))
                    {
                        self.notice = None;
                        self.notice_page = None;
                    }
                    if self
                        .error
                        .as_deref()
                        .is_some_and(|m| m.starts_with(SAVE_ERROR_PREFIX))
                    {
                        self.error = None;
                    }
                    self.preferences_failed_draft = false;
                }
                if job.commit {
                    self.prefs = job.proposed;
                    self.prefs.dark = self
                        .prefs
                        .effective_dark(ctx.system_theme().map(|t| t == egui::Theme::Dark));
                    theme::apply(ctx, self.prefs.dark);
                }
                if let Some(notice) = job.notice {
                    self.set_page_notice(notice, job.origin, theme::StatusKind::Info, false);
                }
            }
            Err(error) => self.preference_save_error(job.origin, error, job.commit),
        }
        self.finish_preferences_followups(ctx);
    }

    pub(super) fn finish_preferences_followups(&mut self, ctx: &egui::Context) {
        let deferred = std::mem::take(&mut self.deferred_seen_features);
        for feature in deferred {
            if !self.feature_seen(&feature) {
                self.prefs.seen_features.push(feature);
                self.preferences_dirty = true;
            }
        }
        if self.preferences_dirty {
            self.persist_preferences();
        } else {
            self.preferences_dirty_origin = None;
        }
        if self.close_after_preferences && !self.preferences_busy() {
            self.close_after_preferences = false;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    pub(super) fn handle_preferences_close(&mut self, ctx: &egui::Context) {
        if self.preferences_busy() {
            self.close_after_preferences = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
    }
}
