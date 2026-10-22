//! Actual App startup on an owned hidden surface. No native event-loop/window
//! visibility code, input bridge, clipboard dispatch, cleanup or preferences edit.
use super::*;
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

fn selected_root(expected: Option<&OsStr>, configured: Option<&OsStr>) -> Result<PathBuf, String> {
    let root =
        PathBuf::from(expected.ok_or("Explicit DCLEANER_NATIVE_STARTUP_DATA_DIR is required.")?);
    if !root.is_absolute() || configured.map(Path::new) != Some(root.as_path()) {
        return Err("The explicit absolute startup root must match DCLEANER_DATA_DIR.".into());
    }
    use std::os::windows::fs::MetadataExt;
    let metadata = fs::symlink_metadata(&root).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
        return Err("An existing ordinary startup directory is required.".into());
    }
    Ok(root)
}

fn top_metadata(root: &Path) -> io::Result<BTreeMap<std::ffi::OsString, (u64, SystemTime, bool)>> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if result.len() >= 1024 {
            return Err(io::Error::other("Startup directory entry bound exceeded."));
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        result.insert(
            entry.file_name(),
            (metadata.len(), metadata.modified()?, metadata.is_dir()),
        );
    }
    Ok(result)
}

fn preference_bytes(root: &Path) -> io::Result<Option<Vec<u8>>> {
    let path = root.join("preferences.json");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    use std::os::windows::fs::MetadataExt;
    if !metadata.is_file() || metadata.len() > 1_048_576 || metadata.file_attributes() & 0x400 != 0
    {
        return Err(io::Error::other(
            "Probe preference file is linked, nonregular or over its read bound.",
        ));
    }
    fs::read(path).map(Some)
}

#[test]
fn startup_probe_requires_an_explicit_matching_existing_absolute_root() {
    let temp = tempfile::tempdir().unwrap();
    let p = temp.path().as_os_str();
    assert_eq!(selected_root(Some(p), Some(p)).unwrap(), temp.path());
    assert!(selected_root(None, Some(p)).is_err());
    assert!(selected_root(Some(p), None).is_err());
    assert!(selected_root(Some(OsStr::new("relative")), Some(OsStr::new("relative"))).is_err());
    assert!(selected_root(Some(p), Some(OsStr::new("different"))).is_err());
}

#[test]
fn startup_probe_refuses_missing_and_file_roots_and_bounds_preference_reads() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("file");
    fs::write(&file, b"fixture").unwrap();
    assert!(selected_root(Some(file.as_os_str()), Some(file.as_os_str())).is_err());
    let missing = temp.path().join("missing");
    assert!(selected_root(Some(missing.as_os_str()), Some(missing.as_os_str())).is_err());
    assert_eq!(preference_bytes(temp.path()).unwrap(), None);
    let prefs = temp.path().join("preferences.json");
    fs::write(&prefs, b"original fixture bytes").unwrap();
    assert_eq!(
        preference_bytes(temp.path()).unwrap().unwrap(),
        b"original fixture bytes"
    );
    fs::File::options()
        .write(true)
        .open(prefs)
        .unwrap()
        .set_len(1_048_577)
        .unwrap();
    assert!(preference_bytes(temp.path()).is_err());
}

#[test]
#[ignore = "Opt-in actual read-only App startup + hidden no-activate DX12 surface. Explicit matching existing data root; no native loop, visibility or input"]
fn native_app_startup_renders_without_visibility_or_input() {
    let root = selected_root(
        std::env::var_os("DCLEANER_NATIVE_STARTUP_DATA_DIR").as_deref(),
        std::env::var_os("DCLEANER_DATA_DIR").as_deref(),
    )
    .unwrap();
    let scale: f32 = match std::env::var("DCLEANER_NATIVE_STARTUP_SCALE").as_deref() {
        Ok("2") => 2.,
        Ok("1") | Err(_) => 1.,
        _ => panic!("Only explicit probe scale 1 or 2 is supported"),
    };
    let pixels = [(1240. * scale) as u32, (820. * scale) as u32];
    let original_preferences = preference_bytes(&root).unwrap();
    let before = top_metadata(&root).unwrap();
    let started = Instant::now();
    // Mirror main's embedded viewport-icon decode, but never create a native icon
    // or pass a window to eframe's visibility/event-loop machinery.
    let _viewport_icon = dcleaner::brand::icon().unwrap();
    let brand_ms = started.elapsed().as_secs_f64() * 1000.;
    let window = HiddenWindow(unsafe {
        CreateWindowExW(
            WS_EX_NOACTIVATE,
            w!("STATIC"),
            w!("DCleaner invisible App startup probe"),
            WS_POPUP,
            0,
            0,
            pixels[0] as i32,
            pixels[1] as i32,
            None,
            None,
            None,
            None,
        )
        .unwrap()
    });
    assert!(!unsafe { IsWindowVisible(window.0) }.as_bool());
    assert_ne!(unsafe { GetForegroundWindow() }, window.0);
    let config = configuration_for(false);
    let egui_wgpu::WgpuSetup::CreateNew(setup) = config.wgpu_setup else {
        panic!("explicit setup")
    };
    let instance = wgpu::Instance::new(setup.instance_descriptor);
    let surface = unsafe {
        instance
            .create_surface_unsafe(wgpu::SurfaceTargetUnsafe::RawHandle {
                raw_display_handle: Some(wgpu::rwh::RawDisplayHandle::Windows(
                    wgpu::rwh::WindowsDisplayHandle::new(),
                )),
                raw_window_handle: wgpu::rwh::RawWindowHandle::Win32(
                    wgpu::rwh::Win32WindowHandle::new(
                        NonZeroIsize::new(window.0.0 as isize).unwrap(),
                    ),
                ),
            })
            .unwrap()
    };
    let surface_ms = started.elapsed().as_secs_f64() * 1000.;
    let adapters = pollster::block_on(instance.enumerate_adapters(wgpu::Backends::DX12));
    let adapter = setup.native_adapter_selector.unwrap()(&adapters, Some(&surface)).unwrap();
    let info = adapter.get_info();
    let adapter_ms = started.elapsed().as_secs_f64() * 1000.;
    let (device, queue) =
        pollster::block_on(adapter.request_device(&(setup.device_descriptor)(&adapter))).unwrap();
    let device_ms = started.elapsed().as_secs_f64() * 1000.;
    let mut surface_config = surface
        .get_default_config(&adapter, pixels[0], pixels[1])
        .unwrap();
    surface_config.format =
        egui_wgpu::preferred_framebuffer_format(&surface.get_capabilities(&adapter).formats)
            .unwrap();
    surface_config.present_mode = config.surface.present_mode;
    surface_config.desired_maximum_frame_latency =
        config.surface.desired_maximum_frame_latency.unwrap();
    surface.configure(&device, &surface_config);
    let configured_ms = started.elapsed().as_secs_f64() * 1000.;
    let mut renderer = egui_wgpu::Renderer::new(
        &device,
        surface_config.format,
        egui_wgpu::RendererOptions::default(),
    );
    let renderer_ms = started.elapsed().as_secs_f64() * 1000.;
    let ctx = eframe::egui::Context::default();
    let app_started = Instant::now();
    let mut app = crate::app::App::new_with_context(&ctx);
    let app_construct_ms = app_started.elapsed().as_secs_f64() * 1000.;
    let mut frames = Vec::new();
    let mut ready_at = None;
    let mut presented = 0;
    let mut discarded_theme_commands = 0;
    let mut final_state = serde_json::Value::Null;
    for tick in 0..120 {
        assert!(!unsafe { IsWindowVisible(window.0) }.as_bool());
        assert_ne!(unsafe { GetForegroundWindow() }, window.0);
        let frame = Instant::now();
        let mut input = eframe::egui::RawInput {
            screen_rect: Some(eframe::egui::Rect::from_min_size(
                eframe::egui::Pos2::ZERO,
                eframe::egui::vec2(1240., 820.),
            )),
            time: Some(started.elapsed().as_secs_f64()),
            ..Default::default()
        };
        let viewport = input
            .viewports
            .get_mut(&eframe::egui::ViewportId::ROOT)
            .unwrap();
        viewport.native_pixels_per_point = Some(scale);
        viewport.focused = Some(false);
        assert!(input.events.is_empty());
        let mut output = ctx.run_ui(input, |ui| app.paint(ui));
        let layout_ms = frame.elapsed().as_secs_f64() * 1000.;
        let updates = std::mem::take(&mut output.textures_delta.set);
        let frees = std::mem::take(&mut output.textures_delta.free);
        output.textures_delta.clear();
        assert!(output.platform_output.commands.is_empty());
        for command in output.viewport_output.values().flat_map(|v| &v.commands) {
            match command {
                eframe::egui::ViewportCommand::SetTheme(_) => discarded_theme_commands += 1,
                _ => panic!(
                    "Unexpected viewport command in the input-free probe: {:?}",
                    std::mem::discriminant(command)
                ),
            }
        }
        final_state = app.native_startup_probe_state(&root);
        assert_eq!(final_state["fixture_mode"], false);
        assert_eq!(final_state["preference_writer_active"], false);
        if ready_at.is_none()
            && final_state["expected_root_loaded"] == true
            && final_state["startup_worker_active"] == false
        {
            ready_at = Some(
                serde_json::json!({"frame":tick,"elapsed_app_ms":app_started.elapsed().as_secs_f64()*1000.}),
            );
        }
        for (id, deltas) in &updates {
            for delta in deltas {
                renderer.update_texture(&device, &queue, *id, delta);
            }
        }
        let jobs = ctx.tessellate(std::mem::take(&mut output.shapes), output.pixels_per_point);
        let meshes_ms = frame.elapsed().as_secs_f64() * 1000.;
        let screen = egui_wgpu::ScreenDescriptor {
            size_in_pixels: pixels,
            pixels_per_point: output.pixels_per_point,
        };
        let texture = match surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(t)
            | wgpu::CurrentSurfaceTexture::Suboptimal(t) => Some(t),
            wgpu::CurrentSurfaceTexture::Occluded => None,
            other => panic!("hidden startup surface acquisition: {other:?}"),
        };
        let acquired_ms = frame.elapsed().as_secs_f64() * 1000.;
        if let Some(texture) = texture {
            let view = texture.texture.create_view(&Default::default());
            let mut encoder = device.create_command_encoder(&Default::default());
            let extra = renderer.update_buffers(&device, &queue, &mut encoder, &jobs, &screen);
            {
                let mut pass = encoder
                    .begin_render_pass(&wgpu::RenderPassDescriptor {
                        label: Some("invisible actual App startup"),
                        color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                            view: &view,
                            depth_slice: None,
                            resolve_target: None,
                            ops: wgpu::Operations {
                                load: wgpu::LoadOp::Clear(wgpu::Color::BLACK),
                                store: wgpu::StoreOp::Store,
                            },
                        })],
                        ..Default::default()
                    })
                    .forget_lifetime();
                renderer.render(&mut pass, &jobs, &screen);
            }
            queue.submit(extra.into_iter().chain(Some(encoder.finish())));
            queue.present(texture);
            device
                .poll(wgpu::PollType::Wait {
                    submission_index: None,
                    timeout: Some(Duration::from_secs(10)),
                })
                .unwrap();
            presented += 1;
        }
        for id in frees {
            renderer.free_texture(&id);
        }
        frames.push(serde_json::json!({"frame":tick,"layout_ms":layout_ms,"meshes_ms":meshes_ms,"acquired_ms":acquired_ms,"total_ms":frame.elapsed().as_secs_f64()*1000.}));
        if tick >= 7 && ready_at.is_some() {
            break;
        }
        if app_started.elapsed() > Duration::from_secs(5) {
            break;
        }
        if tick >= 7 {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(!unsafe { IsWindowVisible(window.0) }.as_bool());
    assert_ne!(unsafe { GetForegroundWindow() }, window.0);
    let report = serde_json::json!({
        "adapter":info.name,"backend":format!("{:?}",info.backend),"format":format!("{:?}",surface_config.format),"scale":scale,"pixels":pixels,
        "brand_ms":brand_ms,"surface_ms":surface_ms,"adapter_ms":adapter_ms,"device_ms":device_ms,"configured_ms":configured_ms,"renderer_ms":renderer_ms,
        "app_construct_ms":app_construct_ms,"total_ms":started.elapsed().as_secs_f64()*1000.,"data_ready":ready_at,"state":final_state,"frames":frames,"presented":presented,
        "preferences_bytes_unchanged":original_preferences==preference_bytes(&root).unwrap(),"top_level_metadata_unchanged":before==top_metadata(&root).unwrap(),
        "actual_saved_data":true,"fixture_data":false,"invisible_owned_window":true,"visible_window":false,"activation_requested":false,"physical_input":false,
        "cleanup_or_settings_effects":false,"native_event_loop":false,"viewport_commands_dispatched":0,"discarded_theme_commands":discarded_theme_commands,"single_instance_path":false,"cold_cache_controlled":false,"process_image_load_timed":false,"screenshots_saved":false
    });
    eprintln!("NATIVE_APP_STARTUP {report}");
    assert!(
        ready_at.is_some(),
        "actual startup data did not become ready within the bounded probe"
    );
    assert!(
        presented > 0,
        "no actual App frames could be presented on the invisible surface"
    );
}
