//! Embedded, flat DCleaner artwork. No filesystem, browser or native reads.
use eframe::egui::{self, ColorImage, TextureHandle, Vec2};
use std::io::Cursor;

const CLOUD: &[u8] = include_bytes!("../assets/illustrations/cloud-cleanup.png");

#[derive(Default)]
pub struct Illustrations {
    cloud: Option<TextureHandle>,
}

impl Illustrations {
    pub fn cloud(&mut self, ui: &mut egui::Ui, width: f32) {
        if self.cloud.is_none() {
            if let Ok(image) = decode(CLOUD) {
                self.cloud = Some(ui.ctx().load_texture(
                    "cloud-cleanup-illustration",
                    image,
                    egui::TextureOptions::LINEAR,
                ));
            }
        }
        if let Some(image) = &self.cloud {
            let width = width.min(ui.available_width());
            ui.add(
                egui::Image::new(image).fit_to_exact_size(Vec2::new(width, width * 260. / 360.)),
            );
        }
    }
}

fn decode(bytes: &[u8]) -> Result<ColorImage, String> {
    let mut reader = png::Decoder::new(Cursor::new(bytes))
        .read_info()
        .map_err(|error| error.to_string())?;
    let info = reader.info();
    if info.width > 1024
        || info.height > 1024
        || info.color_type != png::ColorType::Rgba
        || info.bit_depth != png::BitDepth::Eight
    {
        return Err("Artwork must be bounded RGBA8.".into());
    }
    let mut pixels = vec![
        0;
        reader
            .output_buffer_size()
            .ok_or("Artwork buffer unavailable")?
    ];
    let output = reader
        .next_frame(&mut pixels)
        .map_err(|error| error.to_string())?;
    Ok(ColorImage::from_rgba_unmultiplied(
        [output.width as usize, output.height as usize],
        &pixels[..output.buffer_size()],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embedded_cloud_art_is_rgba_with_transparent_surroundings() {
        let image = decode(CLOUD).unwrap();
        assert_eq!(image.size, [720, 520]);
        assert_eq!(image.pixels[0].a(), 0);
        assert!(image.pixels.iter().any(|pixel| pixel.a() == 255));
    }
}
