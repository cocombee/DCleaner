use super::*;

#[test]
fn routine_page_notices_expire_at_the_deadline_and_do_not_reappear_on_return() {
    let ctx = egui::Context::default();
    let mut app = App::new_fixture_with_context(&ctx, "software-populated").unwrap();
    app.set_page_notice(
        "Verified update".into(),
        Page::Software,
        theme::StatusKind::Success,
        false,
    );
    let deadline = app.notice_deadline.unwrap();
    app.expire_notice_at(deadline - Duration::from_nanos(1), &ctx);
    assert_eq!(app.notice.as_deref(), Some("Verified update"));
    app.page = Page::Duplicates;
    app.expire_notice_at(deadline, &ctx);
    assert!(app.notice.is_none());
    app.page = Page::Software;
    assert!(app.notice_page.is_none());
    assert!(app.notice_deadline.is_none());
}

#[test]
fn renewed_notices_survive_the_old_deadline_and_errors_keep_their_recovery_state() {
    let ctx = egui::Context::default();
    let mut app = App::new_fixture_with_context(&ctx, "software-populated").unwrap();
    app.set_notice("Old message".into());
    let old_deadline = Instant::now() - Duration::from_secs(1);
    app.notice_deadline = Some(old_deadline);
    app.set_notice("New message".into());
    app.expire_notice_at(old_deadline, &ctx);
    assert_eq!(app.notice.as_deref(), Some("New message"));
    for kind in [theme::StatusKind::Error, theme::StatusKind::Info] {
        app.set_page_notice("Recovery required".into(), Page::Software, kind, true);
        app.error = Some("Unresolved owner error".into());
        app.progress = "Active operation".into();
        app.expire_notice_at(Instant::now() + Duration::from_secs(86400), &ctx);
        assert_eq!(app.notice.as_deref(), Some("Recovery required"));
        assert_eq!(app.error.as_deref(), Some("Unresolved owner error"));
        assert_eq!(app.progress, "Active operation");
        assert!(!app.cancel.load(Ordering::Relaxed));
    }
}

#[test]
fn cleanup_completion_uses_worker_history_and_preserves_primary_failure() {
    let ctx = egui::Context::default();
    for duplicates in [false, true] {
        for history_ok in [false, true] {
            let mut app = App::new_fixture_with_context(
                &ctx,
                if duplicates {
                    "duplicates-selected"
                } else {
                    "clean-selected"
                },
            )
            .unwrap();
            app.data_dir = PathBuf::from(r"C:\__DCleaner_NEVER_READ_TERMINAL_FIXTURE__");
            app.error = None;
            let prior = qa_core::history_fixture();
            app.history = prior.clone();
            let history = if history_ok {
                Ok(vec![prior[1].clone()])
            } else {
                Err("fixture history unavailable".into())
            };
            let (tx, rx) = crate::worker_events::channel();
            app.worker = Some(rx);
            let event = if duplicates {
                Event::Duplicate(view_duplicates::DuplicateEvent::Cleaned {
                    result: Err("fixture uncertain effect".into()),
                    history,
                })
            } else {
                Event::Cleaned {
                    result: Err("fixture uncertain effect".into()),
                    history,
                }
            };
            tx.send(event).unwrap();
            app.poll(&ctx);
            assert!(!app.busy());
            assert_eq!(app.history_readable, history_ok);
            assert!(
                app.error
                    .as_ref()
                    .unwrap()
                    .contains("fixture uncertain effect")
            );
            if history_ok {
                assert_eq!(app.history.len(), 1);
                assert_eq!(app.history[0].id, prior[1].id);
            } else {
                assert!(
                    app.error
                        .as_ref()
                        .unwrap()
                        .contains("fixture history unavailable")
                );
                assert_eq!(
                    app.history.len(),
                    prior.len(),
                    "retain old rows without presenting them as a fresh successful read"
                );
            }
        }
    }
}

#[test]
fn successful_cleanup_receipt_survives_unreadable_history_and_cannot_enable_more_cleanup() {
    let ctx = egui::Context::default();
    let mut app = App::new_fixture_with_context(&ctx, "clean-selected").unwrap();
    app.data_dir = PathBuf::from(r"C:\__DCleaner_NEVER_READ_TERMINAL_FIXTURE__");
    let file = app
        .analysis
        .as_ref()
        .unwrap()
        .categories
        .iter()
        .flat_map(|c| &c.files)
        .next()
        .unwrap()
        .clone();
    let mut receipt = qa_core::history_fixture().remove(0);
    receipt.files = 1;
    receipt.bytes = file.size;
    receipt.cleaned_ids = vec![file.id];
    receipt.failed.clear();
    let (tx, rx) = crate::worker_events::channel();
    app.worker = Some(rx);
    tx.send(Event::Cleaned {
        result: Ok(receipt),
        history: Err("fixture history unavailable".into()),
    })
    .unwrap();
    app.poll(&ctx);
    assert!(!app.history_readable);
    assert!(app.selected.is_empty());
    assert!(
        app.analysis
            .as_ref()
            .unwrap()
            .categories
            .iter()
            .flat_map(|c| &c.files)
            .all(|f| f.id != file.id)
    );
    assert!(app.notice.as_ref().unwrap().contains("moved to"));
    assert!(
        app.error
            .as_ref()
            .unwrap()
            .contains("fixture history unavailable")
    );
}

#[test]
fn progress_bursts_leave_actual_ui_poll_responsive_and_completion_is_immediate() {
    let ctx = egui::Context::default();
    let mut app = App::new_fixture_with_context(&ctx, "disk-partial").unwrap();
    let (tx, rx) = crate::worker_events::channel();
    app.worker = Some(rx);
    for n in 0..100_000 {
        tx.send(Event::Duplicate(view_duplicates::DuplicateEvent::Progress(
            format!("Finding files {n}"),
        )))
        .unwrap();
    }
    let start = std::time::Instant::now();
    app.poll(&ctx);
    let progress_elapsed = start.elapsed();
    assert_eq!(app.progress, "Finding files 99999");
    assert!(app.busy());
    for n in 0..100_000 {
        tx.send(Event::Progress(format!("obsolete {n}"))).unwrap();
    }
    tx.send(Event::Disk(Err("fixture terminal failure".into())))
        .unwrap();
    let start = std::time::Instant::now();
    app.poll(&ctx);
    let completion_elapsed = start.elapsed();
    assert!(!app.busy());
    assert_eq!(app.error.as_deref(), Some("fixture terminal failure"));
    assert!(!app.progress.starts_with("obsolete"));
    eprintln!(
        "UI_PROGRESS_BURST produced=200000 progress_poll_us={} completion_poll_us={} completion_frames=1 native_effects=false window_created=false",
        progress_elapsed.as_micros(),
        completion_elapsed.as_micros()
    );
}

#[test]
fn state_errors_and_scan_reports_remain_lossless_beside_display_progress() {
    for progress in [
        Event::Duplicate(view_duplicates::DuplicateEvent::Cleaning { done: 1, total: 2 }),
        Event::Privacy(view_privacy::PrivacyEvent::CleanupProgress { done: 1, total: 2 }),
        Event::RecycleBin(view_recycle_bin::RecycleBinEvent::InventoryProgress {
            done: 1,
            total: 2,
        }),
        Event::RecycleBin(view_recycle_bin::RecycleBinEvent::OperationProgress {
            operation: dcleaner::recycle_bin::RecycleBinOperation::Restore,
            done: 1,
            total: 2,
        }),
    ] {
        let (tx, rx) = crate::worker_events::channel();
        tx.send(progress).unwrap();
        tx.send(Event::Progress("latest display".into())).unwrap();
        assert!(matches!(rx.try_recv(), Ok(Event::Progress(text)) if text == "latest display"));
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }
    let (tx, rx) = crate::worker_events::channel();
    tx.send(Event::Progress("old display".into())).unwrap();
    tx.send(Event::Health(view_health::HealthEvent::RunningBrowsers(
        Err("inventory error".into()),
    )))
    .unwrap();
    tx.send(Event::Health(view_health::HealthEvent::ScanProgress {
        step: dcleaner::health::HealthStep::Privacy,
        completed: 4,
        total: Some(8),
        detail: None,
    }))
    .unwrap();
    tx.send(Event::Health(view_health::HealthEvent::ScanFinished(
        dcleaner::health::HealthStepReport::failed(
            dcleaner::health::HealthStep::Privacy,
            "failed current scan",
        ),
    )))
    .unwrap();
    tx.send(Event::Cleaned {
        result: Err("uncertain cleanup".into()),
        history: Err("history error".into()),
    })
    .unwrap();
    tx.send(Event::Settings(
        view_settings::SettingsEvent::ReleaseChecked(Err("release error".into())),
    ))
    .unwrap();
    drop(tx);
    assert!(matches!(
        rx.try_recv(),
        Ok(Event::Health(view_health::HealthEvent::RunningBrowsers(
            Err(_)
        )))
    ));
    assert!(matches!(
        rx.try_recv(),
        Ok(Event::Health(view_health::HealthEvent::ScanFinished(_)))
    ));
    assert!(matches!(
        rx.try_recv(),
        Ok(Event::Cleaned {
            result: Err(_),
            history: Err(_)
        })
    ));
    assert!(matches!(
        rx.try_recv(),
        Ok(Event::Settings(
            view_settings::SettingsEvent::ReleaseChecked(Err(_))
        ))
    ));
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
}

#[test]
fn feature_notices_stay_on_their_owner_page_even_when_background_work_finishes_elsewhere() {
    let ctx = egui::Context::default();
    let mut app = App::new_fixture_with_context(&ctx, "software-populated").unwrap();
    let message = "Unique verified update result";
    app.set_notice(message.into());
    let paint = |app: &mut App| {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(1240., 820.),
                )),
                ..Default::default()
            },
            |root| app.paint(root),
        );
        fn contains(shape: &egui::Shape, text: &str) -> bool {
            match shape {
                egui::Shape::Text(text_shape) => text_shape.galley.job.text.contains(text),
                egui::Shape::Vec(shapes) => shapes.iter().any(|shape| contains(shape, text)),
                _ => false,
            }
        }
        let visible = output
            .shapes
            .iter()
            .any(|shape| contains(&shape.shape, message));
        output.textures_delta.clear();
        visible
    };
    assert!(paint(&mut app));
    app.page = Page::Duplicates;
    assert!(!paint(&mut app));
    app.message_origin = Some(Page::Software);
    app.set_notice(message.into());
    app.message_origin = None;
    assert!(
        !paint(&mut app),
        "background results must not appear on the current unrelated page"
    );
    app.page = Page::Software;
    assert!(paint(&mut app));
}

#[test]
fn blocked_startup_reader_leaves_frames_responsive_and_commits_loaded_preferences() {
    let ctx = egui::Context::default();
    let mut app = App::new_fixture_with_context(&ctx, "startup-populated").unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    app.settings_readable = false;
    app.begin_initial_load(&ctx, move || {
        entered_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut preferences = Preferences::default();
        preferences.set_appearance(dcleaner::domain::AppearanceMode::Light, None);
        preferences.landing_page = dcleaner::domain::LandingPage::CustomClean;
        Ok(crate::startup_load::StartupData {
            root: PathBuf::from(r"C:\__in_memory_startup_fixture__"),
            preferences: Ok(preferences),
            history: Ok(Vec::new()),
            clean_settings: Ok(Default::default()),
            categories: Vec::new(),
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(app.busy());
    let started = std::time::Instant::now();
    for tick in 0..3 {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(920., 612.),
                )),
                time: Some(tick as f64 / 30.),
                ..Default::default()
            },
            |root| app.paint(root),
        );
        output.textures_delta.clear();
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "blocked storage must not block the UI thread"
    );
    assert!(!app.settings_readable);
    release_tx.send(()).unwrap();
    let until = std::time::Instant::now() + Duration::from_secs(2);
    while app.busy() && std::time::Instant::now() < until {
        app.poll(&ctx);
        thread::yield_now();
    }
    assert!(!app.busy());
    assert!(app.settings_readable && app.history_readable);
    assert!(app.page == Page::Clean);
    assert!(!app.prefs.dark);
    assert_eq!(ctx.theme(), egui::Theme::Light);
}

#[test]
fn disconnected_startup_reader_is_reported_without_losing_queued_events() {
    let ctx = egui::Context::default();
    let mut app = App::new_fixture_with_context(&ctx, "startup-populated").unwrap();
    app.data_dir = PathBuf::new();
    app.qa_fixture_mode = false;
    let (sender, receiver) = crate::worker_events::channel();
    app.worker = Some(receiver);
    sender
        .send(Event::Progress("queued fixture progress".into()))
        .unwrap();
    drop(sender);
    app.poll(&ctx);
    assert_eq!(app.progress, "queued fixture progress");
    app.poll(&ctx);
    assert!(app.worker.is_none());
    assert!(
        app.busy(),
        "startup failure must keep maintenance actions blocked"
    );
    assert!(app.error.unwrap().contains("Startup loading stopped"));
}
