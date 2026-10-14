//! Debug-only export of the application's rendered framebuffer for design review.
use eframe::egui;
use std::{
    fs::File,
    io::BufWriter,
    path::PathBuf,
    time::{Duration, Instant},
};

pub struct Capture {
    path: PathBuf,
    frames: u32,
    requested: bool,
    started: Instant,
}
impl Capture {
    pub fn from_environment() -> Option<Self> {
        if !std::env::args().any(|arg| arg == "--render-qa") {
            return None;
        }
        let path = PathBuf::from(std::env::var_os("DCLEANER_QA_CAPTURE")?);
        if !path.is_absolute() || path.extension().and_then(|v| v.to_str()) != Some("png") {
            return None;
        }
        Some(Self {
            path,
            frames: 0,
            requested: false,
            started: Instant::now(),
        })
    }
    pub fn tick(&mut self, ctx: &egui::Context, busy: bool) {
        let screenshot = ctx.input(|input| {
            input.events.iter().find_map(|event| {
                if let egui::Event::Screenshot { image, .. } = event {
                    Some(image.clone())
                } else {
                    None
                }
            })
        });
        if let Some(image) = screenshot {
            let output = (|| -> Result<(), Box<dyn std::error::Error>> {
                if let Some(parent) = self.path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let file = BufWriter::new(File::create(&self.path)?);
                let mut encoder =
                    png::Encoder::new(file, image.width() as u32, image.height() as u32);
                encoder.set_color(png::ColorType::Rgba);
                encoder.set_depth(png::BitDepth::Eight);
                let pixels: Vec<u8> = image
                    .pixels
                    .iter()
                    .flat_map(|color| color.to_array())
                    .collect();
                encoder.write_header()?.write_image_data(&pixels)?;
                Ok(())
            })();
            if let Err(error) = output {
                eprintln!("Native frame export failed: {error}");
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if busy {
            self.frames = 0;
        } else {
            self.frames += 1;
        }
        if self.started.elapsed() > Duration::from_secs(90) {
            eprintln!("Native frame export timed out before a complete frame was available.");
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        } else if !busy && self.frames >= 20 && !self.requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            self.requested = true;
        }
        ctx.request_repaint_after(Duration::from_millis(80));
    }
}
