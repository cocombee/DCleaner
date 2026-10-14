//! Read application artwork from local registered resources without launching them.
use eframe::egui::{self, ColorImage, TextureHandle};
use std::{
    collections::{HashMap, HashSet},
    sync::mpsc,
    thread,
};

#[derive(Default)]
pub struct IconCache {
    images: HashMap<String, Option<TextureHandle>>,
    pending: HashSet<String>,
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
    /// Reserves the same slot even when no native icon is available.
    pub fn show(&mut self, ui: &mut egui::Ui, resource: Option<&str>, size: f32) {
        if let Some((_, receiver)) = &self.worker {
            for (key, image) in receiver.try_iter() {
                self.pending.remove(&key);
                let texture = image.map(|image| {
                    ui.ctx().load_texture(
                        format!("application-icon-{}", self.images.len()),
                        image,
                        egui::TextureOptions::LINEAR,
                    )
                });
                self.images.insert(key, texture);
            }
        }
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
        if let Some(texture) = key
            .and_then(|key| self.images.get(key))
            .and_then(Option::as_ref)
        {
            ui.painter().image(
                texture.id(),
                rect,
                egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1., 1.)),
                egui::Color32::WHITE,
            );
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
                .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
        {
            return None;
        }
        output.push_str(&std::env::var(name).ok()?);
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
