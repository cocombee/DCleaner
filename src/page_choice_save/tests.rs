use super::*;
use dcleaner::{
    drivers::DeviceId,
    programs::{ProgramIdentity, RegistryHive, RegistrySource, RegistryView},
    software::{SoftwareIdentity, SoftwarePreference, SoftwarePreferenceState},
};
use std::time::{Duration, Instant};

fn fixture(driver: bool) -> (egui::Context, App, tempfile::TempDir, Change) {
    let context = egui::Context::default();
    let app = App::new_fixture_with_context(
        &context,
        if driver {
            "drivers-populated"
        } else {
            "software-populated"
        },
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut app = app;
    app.data_dir = root.path().to_owned();
    let change = if driver {
        let mut proposed = app.driver_choices_for_test().unwrap().clone();
        proposed
            .set_ignored(
                DeviceId::from_instance_id("QA\\SYNTHETIC\\DISPLAY").unwrap(),
                true,
            )
            .unwrap();
        Change::Driver {
            proposed,
            notice: "Fixture verified driver choices".into(),
        }
    } else {
        let mut proposed = app.software_choices_for_test().clone();
        proposed
            .set(SoftwarePreference {
                identity: SoftwareIdentity {
                    registration: ProgramIdentity {
                        hive: RegistryHive::CurrentUser,
                        key_name: "fixture-example-editor".into(),
                    },
                    registry_source: RegistrySource {
                        hive: RegistryHive::CurrentUser,
                        view: RegistryView::Registry64,
                    },
                    package_id: "example.editor".into(),
                    source_id: software::WINGET_SOURCE.into(),
                },
                state: SoftwarePreferenceState::Ignored,
                skipped_version: None,
            })
            .unwrap();
        Change::Software(proposed)
    };
    (context, app, root, change)
}

fn choices(app: &App, driver: bool) -> serde_json::Value {
    if driver {
        serde_json::to_value(app.driver_choices_for_test().unwrap()).unwrap()
    } else {
        serde_json::to_value(app.software_choices_for_test()).unwrap()
    }
}
fn command(output: &egui::FullOutput, close: bool) -> bool {
    output.viewport_output.values().any(|view| {
        view.commands.iter().any(|command| {
            if close {
                matches!(command, egui::ViewportCommand::Close)
            } else {
                matches!(command, egui::ViewportCommand::CancelClose)
            }
        })
    })
}
fn settle(context: &egui::Context, app: &mut App) -> bool {
    let until = Instant::now() + Duration::from_secs(5);
    let mut closed = false;
    while app.preferences_busy() && Instant::now() < until {
        let mut output = context.run_ui(Default::default(), |_| app.poll(context));
        output.textures_delta.clear();
        closed |= command(&output, true);
        thread::yield_now();
    }
    assert!(
        !app.preferences_busy(),
        "the bounded owner must receive a terminal acknowledgement"
    );
    closed
}

#[test]
fn blocked_page_writers_keep_actual_frames_responsive_and_close_waits_for_verified_commit() {
    for driver in [true, false] {
        let (context, mut app, root, change) = fixture(driver);
        let before = choices(&app, driver);
        let (entered, ready) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        app.start_page_choices_writer(change.clone(), move |root, value| {
            entered.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(10)).unwrap();
            value.write_and_verify(root)
        })
        .unwrap();
        ready.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(app.busy() && app.preferences_busy());
        assert_eq!(choices(&app, driver), before);
        app.qa_fixture_mode = false;
        assert!(
            app.queue_page_choices(change.clone()).is_err(),
            "a second writer must not start"
        );
        assert!(
            app.queue_preferences(app.prefs.clone(), None).is_err(),
            "global choices share the admission/close guard"
        );
        app.qa_fixture_mode = true;
        let started = Instant::now();
        for _ in 0..3 {
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(920., 612.),
                    )),
                    ..Default::default()
                },
                |ui| app.paint(ui),
            );
            assert!(!output.shapes.is_empty());
            assert!(!command(&output, true));
            output.textures_delta.clear();
        }
        let frames_ms = started.elapsed().as_secs_f64() * 1000.;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "three UI frames waited for the blocked disk writer"
        );
        let mut output = context.run_ui(Default::default(), |_| {
            app.handle_preferences_close(&context)
        });
        assert!(command(&output, false) && !command(&output, true));
        output.textures_delta.clear();
        assert_eq!(choices(&app, driver), before);
        release.send(()).unwrap();
        assert!(
            settle(&context, &mut app),
            "successful read-back releases the deferred close"
        );
        assert_ne!(choices(&app, driver), before);
        assert!(app.notice_page == Some(change.origin()));
        match change {
            Change::Driver { proposed, .. } => {
                assert_eq!(drivers::load_settings(root.path()).unwrap(), proposed)
            }
            Change::Software(proposed) => {
                assert_eq!(software::load_settings(root.path()).unwrap(), proposed)
            }
        }
        eprintln!(
            "PAGE_CHOICE_SAVE driver={driver} blocked_writer=true frames=3 elapsed_ms={frames_ms:.3} deferred_close=true verified_readback=true physical_input=false"
        );
    }
}

#[test]
fn failed_or_panicked_page_writer_preserves_choices_and_does_not_hide_failure_by_closing() {
    for driver in [true, false] {
        for panic in [false, true] {
            let (context, mut app, _root, change) = fixture(driver);
            let before = choices(&app, driver);
            let (release, wait) = mpsc::sync_channel(1);
            app.start_page_choices_writer(change.clone(), move |_, _| {
                wait.recv_timeout(Duration::from_secs(5)).unwrap();
                if panic {
                    panic!("owned fixture writer failure")
                }
                Err("fixture disk unavailable".into())
            })
            .unwrap();
            app.handle_preferences_close(&context);
            release.send(()).unwrap();
            assert!(!settle(&context, &mut app));
            assert!(!app.close_after_preferences);
            assert_eq!(choices(&app, driver), before);
            assert!(app.page == change.origin());
            assert!(
                app.error
                    .as_deref()
                    .unwrap()
                    .contains("could not be verified")
            );
            assert!(!app.busy());
        }
    }
}

#[test]
fn disconnected_page_writer_is_uncertain_and_error_notice_stays_on_its_owner_page() {
    for driver in [true, false] {
        let (context, mut app, _root, change) = fixture(driver);
        let before = choices(&app, driver);
        let (sender, receiver) = mpsc::sync_channel(1);
        app.page_choices_job = Some(Pending {
            receiver,
            change: change.clone(),
            _fixture_guard: None,
        });
        drop(sender);
        app.page = Page::Help;
        assert!(app.page_choice_progress().is_none());
        assert!(!settle(&context, &mut app));
        assert_eq!(choices(&app, driver), before);
        assert!(app.page == Page::Help);
        assert!(app.notice_page == Some(change.origin()));
        assert!(matches!(app.notice_kind, theme::StatusKind::Error));
        assert!(app.notice.as_deref().unwrap().contains("disconnected"));
    }
}

#[test]
fn actual_async_page_writes_preserve_corrupt_existing_settings_and_require_refresh() {
    for driver in [true, false] {
        let (context, mut app, root, change) = fixture(driver);
        let before = choices(&app, driver);
        let path = root.path().join(if driver {
            "drivers-settings.json"
        } else {
            "software-settings.json"
        });
        let original = b"{ corrupt original fixture settings";
        std::fs::write(&path, original).unwrap();
        app.start_page_choices_writer(change, |root, value| value.write_and_verify(root))
            .unwrap();
        assert!(!settle(&context, &mut app));
        assert_eq!(std::fs::read(path).unwrap(), original);
        assert_eq!(choices(&app, driver), before);
        assert!(
            app.notice
                .as_deref()
                .unwrap()
                .contains("could not be verified")
        );
    }
}

#[test]
fn actual_driver_and_software_choice_entrypoints_commit_only_through_the_owned_writer() {
    for driver in [true, false] {
        let (context, mut app, root, change) = fixture(driver);
        let before = choices(&app, driver);
        app.qa_fixture_mode = false;
        match &change {
            Change::Driver { .. } => app.set_driver_ignored(
                DeviceId::from_instance_id("QA\\SYNTHETIC\\DISPLAY").unwrap(),
                true,
            ),
            Change::Software(proposed) => app.save_proposed_software_settings(proposed.clone()),
        }
        assert!(app.page_choices_job.is_some());
        assert_eq!(
            choices(&app, driver),
            before,
            "entrypoint must not apply an unacknowledged choice"
        );
        assert!(!settle(&context, &mut app));
        assert!(matches!(app.notice_kind, theme::StatusKind::Success));
        match change {
            Change::Driver { proposed, .. } => {
                assert_eq!(drivers::load_settings(root.path()).unwrap(), proposed)
            }
            Change::Software(proposed) => {
                assert_eq!(software::load_settings(root.path()).unwrap(), proposed)
            }
        }
        assert_ne!(choices(&app, driver), before);
    }
}
