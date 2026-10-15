//! Debug-only CPU rendering of the same egui layout, without a native window.
//! This is layout evidence, not a substitute for installed/GPU visual acceptance.
use eframe::egui::{self, ColorImage, TextureId, epaint};
use std::{
    collections::HashMap,
    fs::File,
    io::BufWriter,
    path::Path,
    time::{Duration, Instant},
};

#[derive(Default)]
struct Textures {
    images: HashMap<TextureId, ColorImage>,
    pending_free: Vec<TextureId>,
}
impl Textures {
    fn apply(&mut self, delta: &mut egui::TexturesDelta) -> Result<(), String> {
        self.pending_free.extend(delta.free.drain());
        for (id, updates) in std::mem::take(&mut delta.set) {
            for update in updates {
                let egui::ImageData::Color(image) = &update.image;
                if image.width() > 8192 || image.height() > 8192 {
                    return Err("Offscreen texture exceeds the QA limit.".into());
                }
                if let Some([x, y]) = update.pos {
                    let original = self
                        .images
                        .get_mut(&id)
                        .ok_or("Offscreen texture patch has no original.")?;
                    if x + image.width() > original.width()
                        || y + image.height() > original.height()
                    {
                        return Err("Offscreen texture patch is out of bounds.".into());
                    }
                    for row in 0..image.height() {
                        let start = (y + row) * original.width() + x;
                        original.pixels[start..start + image.width()].copy_from_slice(
                            &image.pixels[row * image.width()..(row + 1) * image.width()],
                        );
                    }
                } else {
                    self.images.insert(id, (**image).clone());
                }
            }
        }
        Ok(())
    }
    fn finish_frame(&mut self) {
        for id in self.pending_free.drain(..) {
            self.images.remove(&id);
        }
    }
}

fn sample(image: &ColorImage, uv: egui::Pos2) -> [f32; 4] {
    let x = (uv.x * image.width() as f32 - 0.5).clamp(0., image.width().saturating_sub(1) as f32);
    let y = (uv.y * image.height() as f32 - 0.5).clamp(0., image.height().saturating_sub(1) as f32);
    let x0 = x.floor() as usize;
    let y0 = y.floor() as usize;
    let x1 = (x0 + 1).min(image.width() - 1);
    let y1 = (y0 + 1).min(image.height() - 1);
    let colours = [
        image[(x0, y0)].to_array(),
        image[(x1, y0)].to_array(),
        image[(x0, y1)].to_array(),
        image[(x1, y1)].to_array(),
    ];
    let dx = x - x0 as f32;
    let dy = y - y0 as f32;
    std::array::from_fn(|channel| {
        let upper = colours[0][channel] as f32 * (1. - dx) + colours[1][channel] as f32 * dx;
        let lower = colours[2][channel] as f32 * (1. - dx) + colours[3][channel] as f32 * dx;
        (upper * (1. - dy) + lower * dy) / 255.
    })
}

fn edge(a: egui::Pos2, b: egui::Pos2, p: egui::Pos2) -> f64 {
    (b.x as f64 - a.x as f64) * (p.y as f64 - a.y as f64)
        - (b.y as f64 - a.y as f64) * (p.x as f64 - a.x as f64)
}
fn top_left(a: egui::Pos2, b: egui::Pos2) -> bool {
    b.y < a.y || (b.y == a.y && b.x > a.x)
}

fn rasterize(
    primitives: &[epaint::ClippedPrimitive],
    textures: &Textures,
    width: usize,
    height: usize,
    scale: f32,
) -> Result<Vec<u8>, String> {
    if width == 0
        || height == 0
        || width.saturating_mul(height) > 8_000_000
        || !scale.is_finite()
        || scale <= 0.
    {
        return Err("Invalid offscreen frame size.".into());
    }
    let mut pixels = vec![[0f32; 4]; width * height];
    for primitive in primitives {
        let epaint::Primitive::Mesh(mesh) = &primitive.primitive else {
            return Err(
                "A paint callback requires a native renderer; no partial QA image was written."
                    .into(),
            );
        };
        let image = textures
            .images
            .get(&mesh.texture_id)
            .ok_or("Offscreen mesh texture is missing.")?;
        if image.width() == 0 || image.height() == 0 {
            return Err("Empty offscreen texture.".into());
        }
        let clip = primitive.clip_rect * scale;
        for indices in mesh.indices.chunks_exact(3) {
            let mut vertices = [
                mesh.vertices[indices[0] as usize],
                mesh.vertices[indices[1] as usize],
                mesh.vertices[indices[2] as usize],
            ];
            for vertex in &mut vertices {
                vertex.pos *= scale;
            }
            let mut area = edge(vertices[0].pos, vertices[1].pos, vertices[2].pos);
            if area.abs() < 1e-12 {
                continue;
            }
            if area < 0. {
                vertices.swap(1, 2);
                area = -area;
            }
            let [a, b, c] = vertices;
            let left = a
                .pos
                .x
                .min(b.pos.x)
                .min(c.pos.x)
                .max(clip.left())
                .max(0.)
                .floor() as usize;
            let top = a
                .pos
                .y
                .min(b.pos.y)
                .min(c.pos.y)
                .max(clip.top())
                .max(0.)
                .floor() as usize;
            let right = a
                .pos
                .x
                .max(b.pos.x)
                .max(c.pos.x)
                .min(clip.right())
                .min(width as f32)
                .ceil()
                .max(0.) as usize;
            let bottom = a
                .pos
                .y
                .max(b.pos.y)
                .max(c.pos.y)
                .min(clip.bottom())
                .min(height as f32)
                .ceil()
                .max(0.) as usize;
            for y in top..bottom {
                for x in left..right {
                    let point = egui::pos2(x as f32 + 0.5, y as f32 + 0.5);
                    if !clip.contains(point) {
                        continue;
                    }
                    let weights = [
                        edge(b.pos, c.pos, point),
                        edge(c.pos, a.pos, point),
                        edge(a.pos, b.pos, point),
                    ];
                    let inclusions = [
                        top_left(b.pos, c.pos),
                        top_left(c.pos, a.pos),
                        top_left(a.pos, b.pos),
                    ];
                    if weights
                        .iter()
                        .zip(inclusions)
                        .any(|(weight, inclusive)| *weight < 0. || (*weight == 0. && !inclusive))
                    {
                        continue;
                    }
                    let weights = weights.map(|weight| (weight / area) as f32);
                    let uv = egui::pos2(
                        a.uv.x * weights[0] + b.uv.x * weights[1] + c.uv.x * weights[2],
                        a.uv.y * weights[0] + b.uv.y * weights[1] + c.uv.y * weights[2],
                    );
                    let texel = sample(image, uv);
                    let colours = [a.color.to_array(), b.color.to_array(), c.color.to_array()];
                    let source: [f32; 4] = std::array::from_fn(|channel| {
                        texel[channel]
                            * (colours[0][channel] as f32 * weights[0]
                                + colours[1][channel] as f32 * weights[1]
                                + colours[2][channel] as f32 * weights[2])
                            / 255.
                    });
                    let target = &mut pixels[y * width + x];
                    for channel in 0..4 {
                        target[channel] = source[channel] + target[channel] * (1. - source[3]);
                    }
                }
            }
        }
    }
    Ok(pixels
        .into_iter()
        .flat_map(|pixel| {
            let alpha = pixel[3].clamp(0., 1.);
            std::array::from_fn::<u8, 4, _>(|channel| {
                let value = if channel == 3 {
                    alpha
                } else if alpha > 0. {
                    pixel[channel] / alpha
                } else {
                    0.
                };
                (value.clamp(0., 1.) * 255.).round() as u8
            })
        })
        .collect())
}

fn save_png(path: &Path, width: usize, height: usize, pixels: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let file = File::create(path).map_err(|error| error.to_string())?;
    let mut encoder = png::Encoder::new(BufWriter::new(file), width as u32, height as u32);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .and_then(|mut writer| writer.write_image_data(pixels))
        .map_err(|error| error.to_string())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UiAction {
    label: String,
    occurrence: Option<usize>,
}

fn click_point(
    context: &egui::Context,
    action: &UiAction,
    dimensions: [usize; 2],
) -> Result<egui::Pos2, String> {
    let geometry = crate::theme::geometry_json(context);
    let controls = geometry["controls"]
        .as_array()
        .ok_or("Control geometry unavailable")?;
    let matches: Vec<_> = controls
        .iter()
        .filter(|control| control["label"] == action.label && control["enabled"] == true)
        .filter(|control| {
            let rect = |key: &str| -> Option<egui::Rect> {
                let values = control[key].as_array()?;
                Some(egui::Rect::from_min_size(
                    egui::pos2(values[0].as_f64()? as f32, values[1].as_f64()? as f32),
                    egui::vec2(values[2].as_f64()? as f32, values[3].as_f64()? as f32),
                ))
            };
            let Some(bounds) = rect("rect") else {
                return false;
            };
            let Some(clip) = rect("clip_rect") else {
                return false;
            };
            let center = bounds.center();
            clip.contains(center)
                && center.x >= 0.
                && center.y >= 0.
                && center.x < dimensions[0] as f32
                && center.y < dimensions[1] as f32
                && context
                    .layer_id_at(center)
                    .is_some_and(|layer| control["layer"] == format!("{layer:?}"))
        })
        .collect();
    if matches.len() > 1 && action.occurrence.is_none() {
        return Err(format!(
            "Ambiguous rendered control; specify its occurrence: {}",
            action.label
        ));
    }
    let control = matches
        .get(action.occurrence.unwrap_or(0))
        .ok_or_else(|| format!("Enabled rendered control not found: {}", action.label))?;
    let rect = control["rect"]
        .as_array()
        .ok_or("Control bounds unavailable")?;
    let number = |index: usize| {
        rect.get(index)
            .and_then(serde_json::Value::as_f64)
            .map(|value| value as f32)
            .ok_or("Invalid control bound")
    };
    let point = egui::pos2(number(0)? + number(2)? / 2., number(1)? + number(3)? / 2.);
    if point.x < 0.
        || point.y < 0.
        || point.x >= dimensions[0] as f32
        || point.y >= dimensions[1] as f32
    {
        return Err("Requested control is outside the rendered viewport.".into());
    }
    Ok(point)
}

fn capture_mesh_frame(
    context: &egui::Context,
    output: &egui::FullOutput,
    textures: &Textures,
    dimensions: [usize; 2],
    destination: &Path,
) -> Result<(), String> {
    let primitives = context.tessellate(output.shapes.clone(), output.pixels_per_point);
    let pixels = rasterize(
        &primitives,
        textures,
        dimensions[0],
        dimensions[1],
        output.pixels_per_point,
    )?;
    save_png(destination, dimensions[0], dimensions[1], &pixels)
}

pub fn run() -> Result<(), String> {
    let destination = std::path::PathBuf::from(
        std::env::var_os("DCLEANER_QA_CAPTURE")
            .ok_or("Offscreen QA needs an explicit output path.")?,
    );
    if !destination.is_absolute()
        || destination
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("png")
    {
        return Err("Offscreen QA needs an absolute PNG path.".into());
    }
    let data_directory = std::path::PathBuf::from(std::env::var_os("DCLEANER_DATA_DIR").ok_or("Offscreen QA requires an isolated DCLEANER_DATA_DIR; normal application data is never used.")?);
    if !data_directory.is_absolute() {
        return Err("Offscreen QA data directory must be absolute.".into());
    }
    let dimensions = match std::env::var("DCLEANER_QA_SIZE").as_deref() {
        Ok("minimum") => [760usize, 600],
        Ok("reference") => [920, 612],
        _ => [1240, 820],
    };
    let fixture_case = std::env::var("DCLEANER_QA_CASE")
        .map_err(|_| "Offscreen QA requires an explicit supported DCLEANER_QA_CASE; host inventories are never loaded.".to_string())?;
    let mut actions: std::collections::VecDeque<UiAction> =
        serde_json::from_str(&std::env::var("DCLEANER_QA_ACTIONS").unwrap_or_else(|_| "[]".into()))
            .map_err(|error| format!("Invalid fixture UI actions: {error}"))?;
    if actions.len() > 16
        || actions.iter().any(|action| {
            !matches!(
                action.label.as_str(),
                "Get started"
                    | "Clear selection"
                    | "Clear"
                    | "Review 1 item"
                    | "Keep items"
                    | "Cleanup history"
                    | "Details"
                    | "Close"
                    | "Copy path"
                    | "About Startup Manager"
                    | "Got it"
                    | "Scan now"
                    | "Start now"
                    | "Sort Program"
                    | "Sort Publisher"
                    | "All statistics"
                    | "Rescan"
                    | "Cookie settings"
                    | "Close settings"
                    | "Clean"
                    | "Resolve"
                    | "Back to findings"
                    | "Show Temporary internet files"
                    | "Hide Temporary internet files"
                    | "Select all Health findings"
                    | "Stop scan"
                    | "Stop cleaning"
                    | "Skip"
                    | "General"
                    | "Scheduling"
                    | "Updates"
                    | "Privacy"
                    | "Menu Layout"
                    | "Menu"
                    | "Expand menu"
                    | "Collapse menu"
                    | "More tools"
                    | "Disk Analyzer"
                    | "Cleanup History"
                    | "Navigate Health Check"
                    | "Navigate Custom Clean"
                    | "Navigate Uninstaller"
                    | "Navigate Duplicate Finder"
                    | "Navigate Cloud Drive Cleaner"
                    | "Navigate Performance Optimizer"
                    | "Navigate Startup Manager"
                    | "Navigate Software Updater"
                    | "Navigate Driver Updater"
                    | "Navigate Settings"
                    | "My Subscription"
                    | "About"
                    | "Light"
                    | "Dark"
                    | "Auto"
                    | "Health Check"
                    | "Custom Clean"
                    | "Always show the landing page at the top of the menu"
                    | "Reset"
                    | "Cancel"
                    | "Open Help"
                    | "Select all"
                    | "Select all eligible updates"
                    | "Select App updates"
                    | "Collapse App updates"
                    | "Expand App updates"
                    | "Sort Importance"
                    | "Junk"
                    | "Browser"
                    | "Registry"
                    | "Select all custom categories"
                    | "Select custom group Applications"
                    | "Collapse custom group Applications"
                    | "Expand custom group Applications"
                    | "Skip closing browsers"
                    | "Cancel browser review"
                    | "Enable startup item"
                    | "Disable startup item"
                    | "More"
                    | "Show details"
                    | "Remove"
                    | "Confirm fixture review"
                    | "Check for updates"
                    | "Outdated software"
                    | "Up-to-date software"
                    | "Skipped & ignored"
                    | "Sort Software"
                    | "Sort Current version"
                    | "Sort New version"
                    | "Update"
                    | "Update all"
                    | "Update selected"
                    | "Close dialog"
                    | "Outdated drivers"
                    | "No offer / unknown"
                    | "Skipped & Ignored"
                    | "Sort Drivers"
                    | "Sort Installed"
                    | "Sort Released"
                    | "Sort State"
                    | "Fix a problem"
                    | "Sound"
                    | "Network or Wi-Fi"
                    | "Show relevant drivers"
                    | "Sort Name"
                    | "Sort Size"
                    | "Sort Provider date"
                    | "Review"
                    | "More options"
                    | "All items"
                    | "Large files"
                    | "Possible duplicates"
                    | "Older items"
                    | "Ignored"
                    | "Keep oldest"
                    | "Keep newest"
                    | "Deselect all"
                    | "Keep this copy"
                    | "Review 2 files"
                    | "Keep files"
                    | "Close duplicate review"
                    | "Close Health review"
                    | "Find specific drivers"
                    | "Not now"
                    | "Don't show this message again"
                    | "Clear history filter"
                    | "Review restore"
                    | "Installed"
                    | "Disabled · unavailable"
                    | "Uninstall"
                    | "Row details"
                    | "Row uninstall"
                    | "Close finding details"
                    | "Scan details"
                    | "Hide scan details"
                    | "I reviewed the partial-scan warning"
                    | "Close details"
                    | "Applications"
                    | "Active apps"
                    | "Sleeping apps"
                    | "Excluded apps"
                    | "Select this exact Windows Update offer"
                    | "Collapse Display"
                    | "Expand Display"
            )
        })
        || (!actions.is_empty()
            && !fixture_case.starts_with("cloud-")
            && !fixture_case.starts_with("disk-")
            && !fixture_case.starts_with("startup-")
            && !fixture_case.starts_with("health-")
            && !fixture_case.starts_with("clean-")
            && !fixture_case.starts_with("privacy-")
            && !fixture_case.starts_with("settings-")
            && !fixture_case.starts_with("software-")
            && !fixture_case.starts_with("drivers-")
            && !fixture_case.starts_with("duplicates-")
            && !fixture_case.starts_with("programs-")
            && !fixture_case.starts_with("optimizer-")
            && !fixture_case.ends_with("-intro"))
    {
        return Err("Fixture actions must use the bounded, effect-free page action set.".into());
    }
    let context = egui::Context::default();
    let mut app = crate::app::App::new_fixture_with_context(&context, &fixture_case)?;
    let mut textures = Textures::default();
    let started = Instant::now();
    let mut idle_frames = 0;
    let mut pending_events = Vec::new();
    let mut release_at = None;
    let mut clear_fixture_pointer = false;
    let mut awaiting_action: Option<UiAction> = None;
    let mut action_log = Vec::new();
    let mut copy_request_observed = false;
    let requested_scroll = std::env::var("DCLEANER_QA_SCROLL")
        .ok()
        .map(|value| {
            value
                .parse::<u16>()
                .ok()
                .filter(|value| *value <= 2000)
                .ok_or("Fixture scroll must be between 0 and 2000 points.")
        })
        .transpose()?
        .unwrap_or(0);
    let mut scrolled = requested_scroll == 0;
    loop {
        let mut input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(dimensions[0] as f32, dimensions[1] as f32),
            )),
            time: Some(started.elapsed().as_secs_f64()),
            focused: true,
            events: std::mem::take(&mut pending_events),
            ..Default::default()
        };
        if let Some(viewport) = input.viewports.get_mut(&egui::ViewportId::ROOT) {
            viewport.native_pixels_per_point = Some(1.);
            viewport.focused = Some(true);
        }
        let mut output = context.run_ui(input, |root| app.paint(root));
        copy_request_observed |= output.platform_output.commands.iter().any(
            |command| matches!(command,egui::OutputCommand::CopyText(text) if !text.is_empty()),
        );
        textures.apply(&mut output.textures_delta)?;
        if let Some(point) = release_at.take() {
            pending_events.push(egui::Event::PointerButton {
                pos: point,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            });
            clear_fixture_pointer = true;
            idle_frames = 0;
            textures.finish_frame();
            continue;
        }
        if clear_fixture_pointer {
            // Settle captures without an incidental tooltip from the last
            // fixture click. This only changes this owned egui input stream.
            pending_events.push(egui::Event::PointerGone);
            clear_fixture_pointer = false;
            idle_frames = 0;
            textures.finish_frame();
            continue;
        }
        if app.qa_busy() {
            idle_frames = 0;
        } else {
            idle_frames += 1;
        }
        if idle_frames >= 20 {
            if !scrolled {
                pending_events.extend([
                    egui::Event::PointerMoved(egui::pos2(
                        dimensions[0] as f32 - 80.,
                        dimensions[1] as f32 * 0.65,
                    )),
                    egui::Event::MouseWheel {
                        phase: egui::TouchPhase::Move,
                        unit: egui::MouseWheelUnit::Point,
                        delta: egui::vec2(0., -(requested_scroll as f32)),
                        modifiers: egui::Modifiers::NONE,
                    },
                ]);
                scrolled = true;
                idle_frames = 0;
                textures.finish_frame();
                continue;
            }
            if let Some(action) = awaiting_action.take() {
                let state = app.qa_action_state(&action.label, &context)?;
                if action.label == "Copy path" && !copy_request_observed {
                    return Err(
                        "Copy path did not emit a copy request; no native clipboard was touched."
                            .into(),
                    );
                }
                let stem = destination
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .ok_or("Capture stem unavailable")?;
                capture_mesh_frame(
                    &context,
                    &output,
                    &textures,
                    dimensions,
                    &destination
                        .with_file_name(format!("{stem}.step-{:02}-after.png", action_log.len())),
                )?;
                action_log.push(serde_json::json!({"label":action.label,"occurrence":action.occurrence,"post_state":state,"physical_input":false}));
            }
            if let Some(action) = actions.pop_front() {
                app.qa_action_precondition(&action.label, &context)?;
                copy_request_observed = false;
                let point = click_point(&context, &action, dimensions)?;
                let stem = destination
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .ok_or("Capture stem unavailable")?;
                capture_mesh_frame(
                    &context,
                    &output,
                    &textures,
                    dimensions,
                    &destination
                        .with_file_name(format!("{stem}.step-{:02}-before.png", action_log.len())),
                )?;
                pending_events.extend([
                    egui::Event::PointerMoved(point),
                    egui::Event::PointerButton {
                        pos: point,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers: egui::Modifiers::NONE,
                    },
                ]);
                release_at = Some(point);
                awaiting_action = Some(action);
                idle_frames = 0;
                textures.finish_frame();
                continue;
            }
            let primitives = context.tessellate(output.shapes, output.pixels_per_point);
            let pixels = rasterize(
                &primitives,
                &textures,
                dimensions[0],
                dimensions[1],
                output.pixels_per_point,
            )?;
            save_png(&destination, dimensions[0], dimensions[1], &pixels)?;
            std::fs::write(destination.with_extension("actions.json"),serde_json::to_vec_pretty(&serde_json::json!({"in_memory_egui_events":true,"physical_input":false,"native_effects":false,"actions":action_log})).map_err(|error|error.to_string())?).map_err(|error|error.to_string())?;
            std::fs::write(
                destination.with_extension("layout.json"),
                serde_json::to_vec_pretty(&crate::theme::geometry_json(&context))
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            std::fs::write(destination.with_extension("renderer.json"), serde_json::to_vec_pretty(&serde_json::json!({"renderer":"CPU rasterization of actual egui meshes; no OS window", "fixture":fixture_case,"synthetic_data":true,"host_inventory":false,"native_framebuffer":false,"physical_input":false,"installed_acceptance":false,"size":dimensions,"scale":output.pixels_per_point})).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
            return Ok(());
        }
        textures.finish_frame();
        if started.elapsed() > Duration::from_secs(120) {
            return Err("Offscreen QA timed out; no completed-frame claim.".into());
        }
        std::thread::sleep(Duration::from_millis(80));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::Color32;
    fn rectangle(colour: Color32, clip: egui::Rect) -> epaint::ClippedPrimitive {
        let mut mesh = epaint::Mesh::with_texture(TextureId::Managed(0));
        mesh.add_colored_rect(
            egui::Rect::from_min_max(egui::pos2(0., 0.), egui::pos2(4., 4.)),
            colour,
        );
        epaint::ClippedPrimitive {
            clip_rect: clip,
            primitive: epaint::Primitive::Mesh(mesh),
        }
    }
    fn white_texture() -> Textures {
        Textures {
            images: HashMap::from([(
                TextureId::Managed(0),
                ColorImage::filled([1, 1], Color32::WHITE),
            )]),
            pending_free: Vec::new(),
        }
    }
    #[test]
    fn shared_diagonal_is_blended_once_and_scissor_is_respected() {
        let clip = egui::Rect::from_min_max(egui::pos2(1., 1.), egui::pos2(3., 3.));
        let primitive = rectangle(Color32::from_rgba_premultiplied(128, 0, 0, 128), clip);
        let pixels = rasterize(&[primitive], &white_texture(), 4, 4, 1.).unwrap();
        for y in 0..4 {
            for x in 0..4 {
                let pixel = &pixels[(y * 4 + x) * 4..(y * 4 + x + 1) * 4];
                if (1..3).contains(&x) && (1..3).contains(&y) {
                    assert_eq!(pixel, &[255, 0, 0, 128]);
                } else {
                    assert_eq!(pixel, &[0, 0, 0, 0]);
                }
            }
        }
    }
    #[test]
    fn texture_patch_requires_a_bounded_existing_texture() {
        let mut textures = white_texture();
        let mut update = egui::TexturesDelta::default();
        update.push(
            TextureId::Managed(0),
            epaint::ImageDelta::partial(
                [0, 0],
                ColorImage::filled([1, 1], Color32::BLUE),
                egui::TextureOptions::LINEAR,
            ),
        );
        textures.apply(&mut update).unwrap();
        assert_eq!(
            textures.images[&TextureId::Managed(0)].pixels[0],
            Color32::BLUE
        );
        let mut invalid = egui::TexturesDelta::default();
        invalid.push(
            TextureId::Managed(0),
            epaint::ImageDelta::partial(
                [1, 0],
                ColorImage::filled([1, 1], Color32::BLUE),
                egui::TextureOptions::LINEAR,
            ),
        );
        assert!(textures.apply(&mut invalid).is_err());
    }
}
