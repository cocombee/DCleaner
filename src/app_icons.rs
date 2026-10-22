//! Read application artwork from local registered resources without launching them.
use eframe::egui::{self, ColorImage, TextureHandle};
use std::{
    collections::{HashMap, HashSet},
    sync::mpsc,
    thread,
};

const MAX_ICON_RESULTS_PER_FRAME: usize = 16;
#[cfg(any(windows, test))]
mod browser_sources;

#[derive(Default)]
pub struct IconCache {
    images: HashMap<String, Option<(TextureHandle, TextureHandle)>>,
    pending: HashSet<String>,
    drained_frame: Option<u64>,
    worker: Option<(
        mpsc::Sender<String>,
        mpsc::Receiver<(String, Option<ColorImage>)>,
    )>,
}

impl IconCache {
    #[cfg(debug_assertions)]
    pub fn is_loading(&self) -> bool {
        !self.pending.is_empty()
    }
    fn drain_results(&mut self, ui: &egui::Ui) {
        let frame = ui.ctx().cumulative_frame_nr();
        if self.drained_frame == Some(frame) {
            return;
        }
        self.drained_frame = Some(frame);
        if let Some((_, receiver)) = &self.worker {
            let mut processed = 0;
            while processed < MAX_ICON_RESULTS_PER_FRAME {
                let Ok((key, image)) = receiver.try_recv() else {
                    break;
                };
                processed += 1;
                self.pending.remove(&key);
                let texture = image.map(|image| {
                    let mono = ui.ctx().load_texture(
                        format!("application-icon-mono-{}", self.images.len()),
                        crate::theme::monochrome_image(image.clone()),
                        egui::TextureOptions::LINEAR,
                    );
                    let color = ui.ctx().load_texture(
                        format!("application-icon-{}", self.images.len()),
                        image,
                        egui::TextureOptions::LINEAR,
                    );
                    (color, mono)
                });
                self.images.insert(key, texture);
            }
            // Continue a ready backlog next frame. A blocked native extraction
            // wakes the UI when it returns; it must not cause an idle repaint loop.
            if processed == MAX_ICON_RESULTS_PER_FRAME {
                ui.ctx().request_repaint();
            }
        }
    }

    /// Reserves the same slot even when no native icon is available.
    pub fn show(&mut self, ui: &mut egui::Ui, resource: Option<&str>, size: f32) {
        self.show_with_fallback(ui, resource, size, None);
    }
    pub fn show_browser(&mut self, ui: &mut egui::Ui, resource: Option<&str>, size: f32) {
        self.show_with_fallback(ui, resource, size, Some(crate::theme::Icon::Browser));
    }
    fn show_with_fallback(
        &mut self,
        ui: &mut egui::Ui,
        resource: Option<&str>,
        size: f32,
        fallback: Option<crate::theme::Icon>,
    ) {
        self.drain_results(ui);
        let key = resource.map(str::trim).filter(|key| !key.is_empty());
        if let Some(key) = key {
            if !self.images.contains_key(key) && !self.pending.contains(key) {
                if self.worker.is_none() {
                    let (request_tx, request_rx) = mpsc::channel::<String>();
                    let (result_tx, result_rx) = mpsc::channel();
                    let context = ui.ctx().clone();
                    thread::spawn(move || {
                        while let Ok(key) = request_rx.recv() {
                            let result = extract(&key);
                            if result_tx.send((key, result)).is_err() {
                                break;
                            }
                            context.request_repaint();
                        }
                    });
                    self.worker = Some((request_tx, result_rx));
                }
                // Keep corrupt or unusually large inventories from growing the queue forever.
                if self.pending.len() + self.images.len() < 4096 {
                    self.pending.insert(key.to_owned());
                    if let Some((sender, _)) = &self.worker {
                        let _ = sender.send(key.to_owned());
                    }
                }
            }
        }
        let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
        if let Some((color, mono)) = key
            .and_then(|key| self.images.get(key))
            .and_then(Option::as_ref)
        {
            let texture = if ui.visuals().dark_mode { mono } else { color };
            ui.painter().image(
                texture.id(),
                rect,
                egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1., 1.)),
                egui::Color32::WHITE,
            );
        } else if let Some(icon) = fallback {
            crate::theme::paint_icon(ui.painter(), rect, icon, ui.visuals().weak_text_color());
        } else {
            // A quiet document outline denotes missing artwork; it does not invent a brand.
            let stroke = egui::Stroke::new(1., ui.visuals().weak_text_color());
            let r = rect.shrink(size * 0.18);
            ui.painter()
                .rect_stroke(r, 2., stroke, egui::StrokeKind::Inside);
            ui.painter()
                .hline(r.left() + 3. ..=r.right() - 3., r.center().y, stroke);
        }
    }
    #[cfg(debug_assertions)]
    pub(crate) fn seed_qa_image(
        &mut self,
        context: &egui::Context,
        key: String,
        image: ColorImage,
    ) {
        let mono = context.load_texture(
            format!("qa-browser-mono-{}", self.images.len()),
            crate::theme::monochrome_image(image.clone()),
            egui::TextureOptions::LINEAR,
        );
        let color = context.load_texture(
            format!("qa-browser-color-{}", self.images.len()),
            image,
            egui::TextureOptions::LINEAR,
        );
        self.images.insert(key, Some((color, mono)));
    }
}

/// Prefer observed executable artwork; supplement stopped browsers from their
/// fixed App Paths registrations. Worker-only, read-only artwork metadata:
/// neither registration nor an icon grants browser identity/cleanup authority.
pub fn browser_icon_sources(
    processes: &[dcleaner::privacy::RunningBrowser],
) -> HashMap<dcleaner::privacy::Browser, String> {
    #[cfg(windows)]
    {
        use windows::{
            Win32::{
                Foundation::CloseHandle,
                System::Threading::{
                    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
                    QueryFullProcessImageNameW,
                },
            },
            core::PWSTR,
        };
        let mut resources = HashMap::new();
        for process in processes {
            if resources.contains_key(&process.browser) {
                continue;
            }
            let Ok(handle) =
                (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process.pid) })
            else {
                continue;
            };
            let mut buffer = vec![0u16; 32_768];
            let mut length = buffer.len() as u32;
            let result = unsafe {
                QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_WIN32,
                    PWSTR(buffer.as_mut_ptr()),
                    &mut length,
                )
            };
            let _ = unsafe { CloseHandle(handle) };
            if result.is_err() || length as usize > buffer.len() {
                continue;
            }
            let Ok(path) = String::from_utf16(&buffer[..length as usize]) else {
                continue;
            };
            let path = std::path::PathBuf::from(path);
            if path.is_absolute()
                && path.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .eq_ignore_ascii_case(&process.executable)
                })
            {
                resources.insert(process.browser, path.to_string_lossy().into_owned());
            }
        }
        browser_sources::supplement(resources, browser_sources::registered_path)
    }
    #[cfg(not(windows))]
    {
        let _ = processes;
        HashMap::new()
    }
}

fn resource_locator(raw: &str) -> Option<(std::path::PathBuf, i32)> {
    let raw = raw.trim().strip_prefix('@').unwrap_or(raw.trim());
    let (path, index) = match raw.rsplit_once(',') {
        Some((path, index)) if index.trim().parse::<i32>().is_ok() => {
            (path.trim(), index.trim().parse().ok()?)
        }
        _ => (raw, 0),
    };
    let path = expand_path_variables(path.trim_matches('"'))?;
    // Never resolve UNC, device, URL, shell commands, or relative locators.
    if path.starts_with("\\\\") || path.contains('\0') {
        return None;
    }
    let path = std::path::PathBuf::from(path);
    if !path.is_absolute() || !path.is_file() {
        return None;
    }
    Some((path, index))
}

fn expand_path_variables(raw: &str) -> Option<String> {
    expand_path_variables_with(raw, |name| std::env::var(name).ok())
}
fn expand_path_variables_with(
    raw: &str,
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Option<String> {
    let mut output = String::new();
    let mut remaining = raw;
    while let Some(start) = remaining.find('%') {
        output.push_str(&remaining[..start]);
        let tail = &remaining[start + 1..];
        let end = tail.find('%')?;
        let name = &tail[..end];
        if name.is_empty()
            || !name
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'(' | b')'))
        {
            return None;
        }
        output.push_str(&lookup(name)?);
        remaining = &tail[end + 1..];
    }
    output.push_str(remaining);
    Some(output)
}

#[cfg(not(windows))]
fn extract(_: &str) -> Option<ColorImage> {
    None
}

#[cfg(windows)]
fn extract(raw: &str) -> Option<ColorImage> {
    use std::{mem::size_of, os::windows::ffi::OsStrExt};
    use windows::{
        Win32::{
            Graphics::Gdi::*,
            UI::{Shell::ExtractIconExW, WindowsAndMessaging::*},
        },
        core::PCWSTR,
    };
    if let Some(product) = raw.strip_prefix("msi:") {
        return extract_msi_product(product);
    }
    let (path, index) = resource_locator(raw)?;
    let wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    const SIDE: usize = 32;
    unsafe {
        let mut icon = HICON::default();
        if ExtractIconExW(PCWSTR(wide.as_ptr()), index, Some(&mut icon), None, 1) == 0
            || icon.is_invalid()
        {
            return None;
        }
        let dc = CreateCompatibleDC(None);
        if dc.is_invalid() {
            let _ = DestroyIcon(icon);
            return None;
        }
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: SIDE as i32,
                biHeight: -(SIDE as i32),
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits = std::ptr::null_mut();
        let bitmap = match CreateDIBSection(Some(dc), &info, DIB_RGB_COLORS, &mut bits, None, 0) {
            Ok(bitmap) if !bits.is_null() => bitmap,
            _ => {
                let _ = DeleteDC(dc);
                let _ = DestroyIcon(icon);
                return None;
            }
        };
        let previous = SelectObject(dc, HGDIOBJ(bitmap.0));
        let pixels = std::slice::from_raw_parts_mut(bits as *mut u8, SIDE * SIDE * 4);
        pixels.fill(0);
        let first =
            DrawIconEx(dc, 0, 0, icon, SIDE as i32, SIDE as i32, 0, None, DI_NORMAL).is_ok();
        let _ = GdiFlush();
        let black = pixels.to_vec();
        pixels.fill(255);
        let second =
            DrawIconEx(dc, 0, 0, icon, SIDE as i32, SIDE as i32, 0, None, DI_NORMAL).is_ok();
        let _ = GdiFlush();
        let mut rgba = vec![0_u8; black.len()];
        for ((b, w), out) in black
            .chunks_exact(4)
            .zip(pixels.chunks_exact(4))
            .zip(rgba.chunks_exact_mut(4))
        {
            let alpha = 255_u16.saturating_sub(w[0].saturating_sub(b[0]) as u16);
            for (dst, src) in [2_usize, 1, 0].iter().enumerate() {
                out[dst] = if alpha == 0 {
                    0
                } else {
                    ((b[*src] as u16 * 255) / alpha).min(255) as u8
                };
            }
            out[3] = alpha as u8;
        }
        SelectObject(dc, previous);
        let _ = DeleteObject(HGDIOBJ(bitmap.0));
        let _ = DeleteDC(dc);
        let _ = DestroyIcon(icon);
        (first && second).then(|| ColorImage::from_rgba_unmultiplied([SIDE, SIDE], &rgba))
    }
}

#[cfg(windows)]
fn extract_msi_product(product: &str) -> Option<ColorImage> {
    use windows::{
        Win32::System::ApplicationInstallationAndServicing::*,
        core::{PCWSTR, PWSTR},
    };
    let product = uuid::Uuid::parse_str(product).ok()?;
    let product = format!("{{{product}}}").to_ascii_uppercase();
    let wide: Vec<u16> = product.encode_utf16().chain(Some(0)).collect();
    let code = PCWSTR(wide.as_ptr());
    struct Handle(MSIHANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                let _ = MsiCloseHandle(self.0);
            }
        }
    }
    // Fixed properties and SQL only. These APIs read the registered product;
    // no install, advertise, repair, provide-component or custom-action API runs.
    unsafe fn property(code: PCWSTR, name: PCWSTR) -> Option<String> {
        let mut data = vec![0u16; 32768];
        let mut count = data.len() as u32;
        let status = unsafe {
            MsiGetProductInfoW(code, name, Some(PWSTR(data.as_mut_ptr())), Some(&mut count))
        };
        if status != 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&data[..count as usize]))
    }
    unsafe fn field(record: MSIHANDLE, column: u32) -> Option<String> {
        let mut data = vec![0u16; 32768];
        let mut count = data.len() as u32;
        if unsafe {
            MsiRecordGetStringW(
                record,
                column,
                Some(PWSTR(data.as_mut_ptr())),
                Some(&mut count),
            )
        } != 0
        {
            return None;
        }
        Some(String::from_utf16_lossy(&data[..count as usize]))
    }
    unsafe {
        if let Some(icon) = property(code, INSTALLPROPERTY_PRODUCTICON) {
            if let Some(image) = resource_locator(&icon).and_then(|_| extract(&icon)) {
                return Some(image);
            }
        }
        let package = property(code, INSTALLPROPERTY_LOCALPACKAGE)?;
        let (package, _) = resource_locator(&package)?;
        let package: Vec<u16> = package
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut database = MSIHANDLE::default();
        let status = MsiOpenDatabaseW(PCWSTR(package.as_ptr()), MSIDBOPEN_READONLY, &mut database);
        if status != 0 {
            return None;
        }
        let database = Handle(database);
        let query = windows::core::w!("SELECT `ComponentId` FROM `Component`");
        let mut view = MSIHANDLE::default();
        let status = MsiDatabaseOpenViewW(database.0, query, &mut view);
        if status != 0 {
            return None;
        }
        let view = Handle(view);
        if MsiViewExecute(view.0, MSIHANDLE::default()) != 0 {
            return None;
        }
        for _ in 0..4096 {
            let mut record = MSIHANDLE::default();
            if MsiViewFetch(view.0, &mut record) != 0 {
                break;
            }
            let record = Handle(record);
            let Some(component) = field(record.0, 1) else {
                continue;
            };
            let Ok(component) = uuid::Uuid::parse_str(&component) else {
                continue;
            };
            let component: Vec<u16> = format!("{{{component}}}")
                .to_ascii_uppercase()
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut path = vec![0u16; 32768];
            let mut count = path.len() as u32;
            if MsiGetComponentPathW(
                code,
                PCWSTR(component.as_ptr()),
                Some(PWSTR(path.as_mut_ptr())),
                Some(&mut count),
            ) != INSTALLSTATE_LOCAL
            {
                continue;
            }
            let path = String::from_utf16_lossy(&path[..count as usize]);
            if !path.to_ascii_lowercase().ends_with(".exe") {
                continue;
            }
            if let Some(image) = resource_locator(&path).and_then(|_| extract(&path)) {
                return Some(image);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artwork_expansion_supports_parenthesized_windows_variables_without_shell_parsing() {
        let result =
            expand_path_variables_with(r"%ProgramFiles(x86)%\Browser\chrome.exe", |name| {
                (name == "ProgramFiles(x86)").then(|| r"C:\Program Files (x86)".into())
            });
        assert_eq!(
            result.as_deref(),
            Some(r"C:\Program Files (x86)\Browser\chrome.exe")
        );
        assert!(expand_path_variables_with("%ProgramFiles(x86)%", |_| None).is_none());
        for bad in ["%bad=name%", "%bad\0name%", "%unterminated"] {
            assert!(expand_path_variables_with(bad, |_| Some("unexpected".into())).is_none());
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "Read-only registered-browser artwork capture; explicit new absolute DCLEANER_QA_BROWSER_CAPTURE_DIR, no browser processes or native app launch"]
    fn native_registered_browser_artwork_without_processes() {
        use dcleaner::privacy::Browser;
        let resources = browser_icon_sources(&[]);
        let destination =
            std::env::var_os("DCLEANER_QA_BROWSER_CAPTURE_DIR").map(std::path::PathBuf::from);
        if let Some(dir) = &destination {
            assert!(
                dir.is_absolute() && !dir.exists(),
                "explicit fresh capture directory required"
            );
            std::fs::create_dir(dir).unwrap();
        }
        let mut captured = Vec::new();
        for (browser, name) in [
            (Browser::Chrome, "chrome"),
            (Browser::Edge, "edge"),
            (Browser::Firefox, "firefox"),
        ] {
            let Some(resource) = resources.get(&browser) else {
                continue;
            };
            let Some(image) = extract(resource) else {
                continue;
            };
            assert_eq!(image.size, [32, 32]);
            assert!(image.pixels.iter().any(|p| p.a() > 0));
            if let Some(dir) = &destination {
                let file = std::fs::File::create(dir.join(format!("{name}.png"))).unwrap();
                let mut encoder = png::Encoder::new(file, 32, 32);
                encoder.set_color(png::ColorType::Rgba);
                encoder.set_depth(png::BitDepth::Eight);
                let mut writer = encoder.write_header().unwrap();
                let bytes = image
                    .pixels
                    .iter()
                    .flat_map(|pixel| pixel.to_srgba_unmultiplied())
                    .collect::<Vec<_>>();
                writer.write_image_data(&bytes).unwrap();
            }
            captured.push(serde_json::json!({"browser":name,"resource":resource,"file":format!("{name}.png"),"size":[32,32]}));
        }
        if let Some(dir) = destination {
            std::fs::write(dir.join("manifest.json"),serde_json::to_vec_pretty(&serde_json::json!({"kind":"read-only-native-registered-browser-artwork","processes_supplied":0,"native_app_launch":false,"captured":captured})).unwrap()).unwrap();
        }
        eprintln!(
            "REGISTERED_BROWSER_ARTWORK native_sources={} captured={} processes_supplied=0 native_launch=false",
            resources.len(),
            captured.len()
        );
    }

    #[test]
    fn ready_icon_backlog_is_bounded_across_all_rows_and_drains_on_later_frames() {
        let context = egui::Context::default();
        let (requests, _request_rx) = mpsc::channel();
        let (results, result_rx) = mpsc::channel();
        let total = MAX_ICON_RESULTS_PER_FRAME * 2 + 5;
        let mut cache = IconCache {
            worker: Some((requests, result_rx)),
            ..Default::default()
        };
        for index in 0..total {
            let key = format!("synthetic-icon-{index}");
            cache.pending.insert(key.clone());
            results
                .send((key, Some(ColorImage::filled([32, 32], egui::Color32::RED))))
                .unwrap();
        }
        for completed in [16, 32, total] {
            let mut output = context.run_ui(Default::default(), |ui| {
                // A table may call show repeatedly. The budget belongs to the
                // whole frame, not each row or each show call.
                for _ in 0..100 {
                    cache.show(ui, None, 22.);
                }
            });
            assert_eq!(cache.images.len(), completed);
            assert_eq!(cache.pending.len(), total - completed);
            assert!(output.textures_delta.set.len() <= 2 * MAX_ICON_RESULTS_PER_FRAME + 1);
            // This fixture checks upload scheduling without a GPU renderer.
            output.textures_delta.clear();
        }
        assert!(cache.images.values().all(Option::is_some));
    }

    #[test]
    fn missing_artwork_results_obey_the_same_frame_budget_without_losing_keys() {
        let context = egui::Context::default();
        let (requests, _request_rx) = mpsc::channel();
        let (results, result_rx) = mpsc::channel();
        let total = MAX_ICON_RESULTS_PER_FRAME + 3;
        let mut cache = IconCache {
            worker: Some((requests, result_rx)),
            ..Default::default()
        };
        for index in 0..total {
            let key = format!("synthetic-missing-icon-{index}");
            cache.pending.insert(key.clone());
            results.send((key, None)).unwrap();
        }
        for completed in [MAX_ICON_RESULTS_PER_FRAME, total] {
            let mut output = context.run_ui(Default::default(), |ui| {
                for _ in 0..100 {
                    cache.show(ui, None, 22.);
                }
            });
            assert_eq!(cache.images.len(), completed);
            assert_eq!(cache.pending.len(), total - completed);
            output.textures_delta.clear();
        }
        assert!(cache.images.values().all(Option::is_none));
    }
    #[test]
    fn locators_do_not_resolve_network_urls_or_commands() {
        for raw in [
            r"\\server\share\app.exe",
            r"\\?\C:\app.exe",
            "https://example.com/a.ico",
            "shell:AppsFolder",
            "app.exe",
            "cmd.exe /c app.exe",
        ] {
            assert!(resource_locator(raw).is_none(), "{raw}");
        }
    }
    #[cfg(windows)]
    #[test]
    fn native_executable_artwork_is_transparent_and_coloured() {
        let root = std::env::var("WINDIR").unwrap();
        let resource = format!(r"{root}\System32\notepad.exe");
        if !std::path::Path::new(&resource).is_file() {
            return;
        }
        let image = extract(&resource).expect("a native executable icon");
        assert_eq!(image.size, [32, 32]);
        assert!(image.pixels.iter().any(|pixel| pixel.a() > 0));
        assert!(image.pixels.iter().any(|pixel| pixel.a() < 255));
    }
    #[cfg(windows)]
    #[test]
    #[ignore = "Read-only native MSI check; explicitly set DCLEANER_QA_MSI_PRODUCT to an installed product GUID."]
    fn native_registered_msi_product_artwork() {
        let product =
            std::env::var("DCLEANER_QA_MSI_PRODUCT").expect("explicit installed MSI product GUID");
        let image = extract_msi_product(&product)
            .expect("artwork owned by the exact registered MSI product");
        assert_eq!(image.size, [32, 32]);
        assert!(image.pixels.iter().any(|pixel| pixel.a() > 0));
    }
}
