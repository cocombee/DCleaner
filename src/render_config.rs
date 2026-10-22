//! Direct3D renderer policy, with an explicit software recovery mode.
use eframe::{egui_wgpu, wgpu};

pub fn configuration() -> egui_wgpu::WgpuConfiguration {
    configuration_for(std::env::args().any(|arg| arg == "--software-rendering"))
}

fn configuration_for(software_only: bool) -> egui_wgpu::WgpuConfiguration {
    let mut setup = egui_wgpu::WgpuSetupCreateNew::without_display_handle();
    #[cfg(windows)]
    {
        setup.instance_descriptor.backends = wgpu::Backends::DX12;
        // DEBUG disables shader optimization in DX12. WARP executes those shaders
        // on the CPU, so keep them optimized even in a diagnostic build.
        setup
            .instance_descriptor
            .flags
            .remove(wgpu::InstanceFlags::DEBUG);
        setup.native_adapter_selector = Some(std::sync::Arc::new(move |adapters, surface| {
            adapters.iter().filter(|adapter| surface.is_none_or(|surface| adapter.is_surface_supported(surface)))
                .filter(|adapter| !software_only || adapter.get_info().device_type == wgpu::DeviceType::Cpu)
                .min_by_key(|adapter| adapter_rank(adapter.get_info().device_type)).cloned()
                .ok_or_else(|| if software_only { "The Windows software renderer is unavailable.".into() }
                    else { "No supported Direct3D renderer is available. Try --software-rendering for recovery.".into() })
        }));
    }
    egui_wgpu::WgpuConfiguration {
        wgpu_setup: egui_wgpu::WgpuSetup::CreateNew(setup),
        surface: egui_wgpu::SurfaceConfig {
            present_mode: wgpu::PresentMode::Fifo,
            desired_maximum_frame_latency: Some(1),
        },
        ..Default::default()
    }
}

fn adapter_rank(kind: wgpu::DeviceType) -> u8 {
    match kind {
        wgpu::DeviceType::IntegratedGpu => 0,
        wgpu::DeviceType::DiscreteGpu => 1,
        wgpu::DeviceType::VirtualGpu => 2,
        wgpu::DeviceType::Other => 3,
        wgpu::DeviceType::Cpu => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    mod hidden_surface;

    #[cfg(windows)]
    #[test]
    #[ignore = "Opt-in Direct3D device/shader test; CPU unless hardware explicitly selected; no window or physical input"]
    fn direct3d_initializes_egui_without_a_window() {
        let started = std::time::Instant::now();
        let benchmark = std::env::var("DCLEANER_SOFTWARE_BENCH").ok();
        let software_only = benchmark.as_deref() != Some("hardware");
        let config = configuration_for(software_only);
        let egui_wgpu::WgpuSetup::CreateNew(setup) = config.wgpu_setup else {
            panic!("explicit setup required")
        };
        let instance = wgpu::Instance::new(setup.instance_descriptor);
        let adapters = pollster::block_on(instance.enumerate_adapters(wgpu::Backends::DX12));
        let adapter = setup.native_adapter_selector.unwrap()(&adapters, None).unwrap();
        let info = adapter.get_info();
        if software_only {
            assert_eq!(info.device_type, wgpu::DeviceType::Cpu);
        } else {
            assert_ne!(info.device_type, wgpu::DeviceType::Cpu);
        }
        assert_eq!(info.backend, wgpu::Backend::Dx12);
        let (device, queue) =
            pollster::block_on(adapter.request_device(&(setup.device_descriptor)(&adapter)))
                .unwrap();
        let scale = if benchmark.is_some() { 2. } else { 1. };
        let dimensions = if benchmark.is_some() {
            [2480, 1640]
        } else {
            [760, 600]
        };
        let frames = if benchmark.is_some() { 32 } else { 4 };
        let dithering = benchmark.as_deref() != Some("no-dither");
        let mut renderer = egui_wgpu::Renderer::new(
            &device,
            wgpu::TextureFormat::Bgra8Unorm,
            egui_wgpu::RendererOptions {
                dithering,
                ..Default::default()
            },
        );
        let texture = device.create_texture(&wgpu::TextureDescriptor {
            label: Some("inert software-render fixture"),
            size: wgpu::Extent3d {
                width: dimensions[0],
                height: dimensions[1],
                depth_or_array_layers: 1,
            },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: wgpu::TextureFormat::Bgra8Unorm,
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            view_formats: &[],
        });
        let view = texture.create_view(&Default::default());
        let ctx = eframe::egui::Context::default();
        let case =
            std::env::var("DCLEANER_RENDER_BENCH_CASE").unwrap_or_else(|_| "clean-ready".into());
        let mut app = crate::app::App::new_fixture_with_context(&ctx, &case).unwrap();
        let setup_elapsed_ms = started.elapsed().as_secs_f64() * 1000.;
        let mut warm_frames = Vec::new();
        let mut stages = [0.; 3];
        let mut first_frame_ms = None;
        for tick in 0..frames {
            let frame_started = std::time::Instant::now();
            let mut input = eframe::egui::RawInput {
                screen_rect: Some(eframe::egui::Rect::from_min_size(
                    eframe::egui::Pos2::ZERO,
                    eframe::egui::vec2(dimensions[0] as f32 / scale, dimensions[1] as f32 / scale),
                )),
                time: Some(tick as f64 / 30.),
                ..Default::default()
            };
            input
                .viewports
                .get_mut(&eframe::egui::ViewportId::ROOT)
                .unwrap()
                .native_pixels_per_point = Some(scale);
            let mut output = ctx.run_ui(input, |root| app.paint(root));
            let layout_done = frame_started.elapsed().as_secs_f64() * 1000.;
            for (id, deltas) in &output.textures_delta.set {
                for delta in deltas {
                    renderer.update_texture(&device, &queue, *id, delta);
                }
            }
            let jobs = ctx.tessellate(output.shapes, output.pixels_per_point);
            let meshes_done = frame_started.elapsed().as_secs_f64() * 1000.;
            let screen = egui_wgpu::ScreenDescriptor {
                size_in_pixels: dimensions,
                pixels_per_point: output.pixels_per_point,
            };
            let mut encoder = device.create_command_encoder(&Default::default());
            let extra = renderer.update_buffers(&device, &queue, &mut encoder, &jobs, &screen);
            {
                let mut pass = encoder
                    .begin_render_pass(&wgpu::RenderPassDescriptor {
                        label: Some("inert software UI frame"),
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
            device
                .poll(wgpu::PollType::Wait {
                    submission_index: None,
                    timeout: Some(std::time::Duration::from_secs(10)),
                })
                .unwrap();
            for id in &output.textures_delta.free {
                renderer.free_texture(id);
            }
            output.textures_delta.clear();
            if tick == 0 {
                first_frame_ms = Some(frame_started.elapsed().as_secs_f64() * 1000.);
            }
            if tick >= 8 {
                let elapsed = frame_started.elapsed().as_secs_f64() * 1000.;
                warm_frames.push(elapsed);
                stages[0] += layout_done;
                stages[1] += meshes_done - layout_done;
                stages[2] += elapsed - meshes_done;
            }
        }
        device.poll(wgpu::PollType::wait_indefinitely()).unwrap();
        eprintln!(
            "adapter={} backend={:?} elapsed_ms={} frames_drawn={} pixels={:?} dithering={} warm_mean_ms={:.2} warm_max_ms={:.2} window_created=false physical_input=false",
            info.name,
            info.backend,
            started.elapsed().as_millis(),
            frames,
            dimensions,
            dithering,
            warm_frames.iter().sum::<f64>() / warm_frames.len().max(1) as f64,
            warm_frames.iter().copied().fold(0., f64::max)
        );
        eprintln!(
            "warm_stage_mean_ms layout={:.2} texture_and_tessellation={:.2} render_and_sync={:.2}",
            stages[0] / warm_frames.len().max(1) as f64,
            stages[1] / warm_frames.len().max(1) as f64,
            stages[2] / warm_frames.len().max(1) as f64
        );
        eprintln!(
            "GPU_FIXTURE {}",
            serde_json::json!({
                "case": case,
                "adapter": info.name,
                "software": software_only,
                "frames": frames,
                "pixels": dimensions,
                "setup_elapsed_ms": setup_elapsed_ms,
                "first_frame_ms": first_frame_ms,
                "warm_samples": warm_frames.len(),
                "warm_mean_ms": warm_frames.iter().sum::<f64>() / warm_frames.len().max(1) as f64,
                "warm_max_ms": warm_frames.iter().copied().fold(0., f64::max),
                "warm_layout_mean_ms": stages[0] / warm_frames.len().max(1) as f64,
                "warm_mesh_mean_ms": stages[1] / warm_frames.len().max(1) as f64,
                "warm_render_sync_mean_ms": stages[2] / warm_frames.len().max(1) as f64,
                "synthetic_fixture": true,
                "window_created": false,
                "physical_input": false,
                "native_effects": false,
            })
        );
    }
    #[test]
    fn windows_policy_has_no_opengl_and_bounds_queued_frames() {
        assert!(adapter_rank(wgpu::DeviceType::DiscreteGpu) < adapter_rank(wgpu::DeviceType::Cpu));
        let config = configuration_for(true);
        assert_eq!(config.surface.present_mode, wgpu::PresentMode::Fifo);
        assert_eq!(config.surface.desired_maximum_frame_latency, Some(1));
        let egui_wgpu::WgpuSetup::CreateNew(setup) = config.wgpu_setup else {
            panic!("expected explicit renderer setup")
        };
        #[cfg(windows)]
        {
            assert_eq!(setup.instance_descriptor.backends, wgpu::Backends::DX12);
            assert!(setup.native_adapter_selector.unwrap()(&[], None).is_err());
        }
    }
}
