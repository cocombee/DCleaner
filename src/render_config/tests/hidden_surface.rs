//! Opt-in swapchain probe. This never enters eframe's native event loop or shows
//! a window; the ordinary first-frame visibility command must not run here.
use super::*;
mod startup;
use std::{num::NonZeroIsize, time::Instant};
use windows::{
    Win32::{
        Foundation::HWND,
        UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, IsWindowVisible, WS_EX_NOACTIVATE, WS_POPUP,
        },
    },
    core::w,
};

struct HiddenWindow(HWND);
impl Drop for HiddenWindow {
    fn drop(&mut self) {
        unsafe {
            let _ = DestroyWindow(self.0);
        }
    }
}

#[test]
#[ignore = "Opt-in Direct3D native swapchain probe; invisible no-activate owned window, no physical input"]
fn direct3d_configures_and_presents_an_invisible_native_surface() {
    let started = Instant::now();
    // No WS_VISIBLE, no ShowWindow, and no normal application/event-loop code.
    // Lifetime order keeps this owned HWND alive until the surface is dropped.
    let window = HiddenWindow(unsafe {
        CreateWindowExW(
            WS_EX_NOACTIVATE,
            w!("STATIC"),
            w!("DCleaner invisible swapchain fixture"),
            WS_POPUP,
            0,
            0,
            1240,
            820,
            None,
            None,
            None,
            None,
        )
        .unwrap()
    });
    assert!(!unsafe { IsWindowVisible(window.0) }.as_bool());
    let config = configuration_for(false);
    let egui_wgpu::WgpuSetup::CreateNew(setup) = config.wgpu_setup else {
        panic!("explicit native renderer setup required")
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
    let surface_ms = started.elapsed().as_millis();
    let adapters = pollster::block_on(instance.enumerate_adapters(wgpu::Backends::DX12));
    let adapter = setup.native_adapter_selector.unwrap()(&adapters, Some(&surface)).unwrap();
    let info = adapter.get_info();
    let adapter_ms = started.elapsed().as_millis();
    let (device, queue) =
        pollster::block_on(adapter.request_device(&(setup.device_descriptor)(&adapter))).unwrap();
    let device_ms = started.elapsed().as_millis();
    let mut surface_config = surface.get_default_config(&adapter, 1240, 820).unwrap();
    surface_config.present_mode = config.surface.present_mode;
    surface_config.desired_maximum_frame_latency =
        config.surface.desired_maximum_frame_latency.unwrap();
    surface.configure(&device, &surface_config);
    let configured_ms = started.elapsed().as_millis();
    let mut presented = 0;
    let mut occluded = 0;
    for _ in 0..3 {
        assert!(!unsafe { IsWindowVisible(window.0) }.as_bool());
        let texture = match surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(texture)
            | wgpu::CurrentSurfaceTexture::Suboptimal(texture) => texture,
            wgpu::CurrentSurfaceTexture::Occluded => {
                occluded += 1;
                continue;
            }
            other => panic!("hidden surface acquisition: {other:?}"),
        };
        let view = texture.texture.create_view(&Default::default());
        let mut encoder = device.create_command_encoder(&Default::default());
        {
            let _pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("invisible surface clear"),
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
            });
        }
        queue.submit([encoder.finish()]);
        queue.present(texture);
        device
            .poll(wgpu::PollType::Wait {
                submission_index: None,
                timeout: Some(std::time::Duration::from_secs(10)),
            })
            .unwrap();
        presented += 1;
    }
    assert!(!unsafe { IsWindowVisible(window.0) }.as_bool());
    eprintln!(
        "HIDDEN_SURFACE adapter={} backend={:?} surface_ms={surface_ms} adapter_ms={adapter_ms} device_ms={device_ms} configured_ms={configured_ms} total_ms={} presented={presented} occluded={occluded} visible_window=false activation_requested=false physical_input=false",
        info.name,
        info.backend,
        started.elapsed().as_millis()
    );
}
