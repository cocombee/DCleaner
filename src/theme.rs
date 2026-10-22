use eframe::egui::{self, Color32, FontFamily, FontId, RichText, Stroke, Vec2};
pub const CONTENT: f32 = 28.;
pub const PAGE_PADDING: i8 = 40;
pub const LABEL_GAP: f32 = 8.;
pub const CONTROL_HEIGHT: f32 = 40.;
pub const CONTROL_PADDING_X: f32 = 16.;
pub const CHECKBOX_SIZE: f32 = 18.;
pub const CONTROL_RADIUS: u8 = 20;
pub const SECTION_RADIUS: u8 = 16;
pub const FIELD_HEIGHT: f32 = 32.;
pub const FIELD_RADIUS: u8 = 16;
pub const TAB_HEIGHT: f32 = 40.;
pub const TABLE_ACTION_HEIGHT: f32 = 26.;
pub const TABLE_ROW_HEIGHT: f32 = 48.;
pub const FONT_CAPTION: f32 = 12.;
pub const FONT_BODY: f32 = 13.;
pub const FONT_TITLE: f32 = 16.;
pub const FONT_DISPLAY: f32 = 24.;
pub const CAPTION_LINE_HEIGHT: f32 = 16.;

#[derive(Clone, Copy, PartialEq)]
pub enum StatusKind {
    Info,
    Success,
    Error,
}

pub fn status_banner(
    ui: &mut egui::Ui,
    message: &str,
    kind: StatusKind,
    progress: bool,
    can_stop: bool,
) -> bool {
    let dark = ui.visuals().dark_mode;
    let (foreground, background) = match (dark, kind) {
        (true, StatusKind::Info) => (
            Color32::from_rgb(235, 204, 112),
            Color32::from_rgb(57, 49, 29),
        ),
        (true, StatusKind::Success) => (
            Color32::from_rgb(153, 216, 172),
            Color32::from_rgb(29, 51, 37),
        ),
        (true, StatusKind::Error) => (
            Color32::from_rgb(247, 159, 159),
            Color32::from_rgb(61, 34, 34),
        ),
        (false, StatusKind::Info) => (
            Color32::from_rgb(112, 79, 0),
            Color32::from_rgb(255, 246, 214),
        ),
        (false, StatusKind::Success) => (
            Color32::from_rgb(29, 99, 53),
            Color32::from_rgb(225, 245, 231),
        ),
        (false, StatusKind::Error) => (
            Color32::from_rgb(155, 39, 39),
            Color32::from_rgb(255, 230, 230),
        ),
    };
    let width = ui.available_width();
    let mut stop = false;
    let frame = egui::Frame::new()
        .fill(background)
        .corner_radius(u8::MAX)
        .inner_margin(egui::Margin::symmetric(20, 10))
        .show(ui, |ui| {
            ui.set_min_width((width - 40.).max(1.));
            ui.horizontal(|ui| {
                ui.set_min_height(26.);
                if progress {
                    ui.add(egui::Spinner::new().size(18.).color(foreground));
                } else {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.), egui::Sense::hover());
                    paint_icon(
                        ui.painter(),
                        rect,
                        if kind == StatusKind::Success {
                            Icon::Check
                        } else {
                            Icon::Info
                        },
                        foreground,
                    );
                }
                let label =
                    egui::Label::new(RichText::new(message).size(FONT_BODY).color(foreground));
                let text_width = (ui.available_width() - if can_stop { 76. } else { 0. }).max(1.);
                ui.allocate_ui_with_layout(
                    Vec2::new(text_width, 26.),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.set_max_width(text_width);
                        if progress {
                            ui.add(label.truncate().show_tooltip_when_elided(false))
                                .on_hover_text(message);
                        } else {
                            ui.add(label.wrap());
                        }
                    },
                );
                if can_stop {
                    stop = row_action(ui, "Stop", true).clicked();
                }
            });
        });
    record_control(ui, "status-banner", frame.response.rect, u8::MAX);
    stop
}

#[cfg(test)]
mod typography_tests {
    use super::*;

    #[test]
    fn both_themes_use_only_the_four_font_size_tokens() {
        let allowed = [FONT_CAPTION, FONT_BODY, FONT_TITLE, FONT_DISPLAY];
        for dark in [false, true] {
            let context = egui::Context::default();
            apply(&context, dark);
            for (style, font) in &context
                .style_of(if dark {
                    egui::Theme::Dark
                } else {
                    egui::Theme::Light
                })
                .text_styles
            {
                assert!(allowed.contains(&font.size), "{style:?}: {}", font.size);
            }
        }
        assert!(FONT_CAPTION < FONT_BODY && FONT_BODY < FONT_TITLE && FONT_TITLE < FONT_DISPLAY);
    }

    #[test]
    fn dark_palette_is_neutral_and_light_retains_brand_blue() {
        let t = tokens(true);
        for color in [
            t.sidebar,
            t.canvas,
            t.foreground,
            t.card,
            t.muted,
            t.border,
            t.primary,
            t.primary_text,
            t.tint,
            t.hover,
        ] {
            assert_eq!(color.r(), color.g());
            assert_eq!(color.g(), color.b());
            assert_eq!(color.a(), 255);
        }
        assert!(t.primary.r() > t.card.r() + 150);
        assert!(t.muted.r() > t.canvas.r() + 100);
        assert_eq!(tokens(false).primary, dcleaner::brand::BLUE);
    }

    #[test]
    fn monochrome_art_keeps_alpha_and_tonal_order() {
        for alpha in [0, 64, 128, 255] {
            let color = Color32::from_rgba_unmultiplied(57, 153, 217, alpha);
            let mono = monochrome(color);
            assert_eq!(mono.a(), alpha);
            assert_eq!(mono.r(), mono.g());
            assert_eq!(mono.g(), mono.b());
        }
        assert!(monochrome(Color32::LIGHT_BLUE).r() > monochrome(Color32::DARK_BLUE).r());
    }
}

#[cfg(test)]
mod tooltip_tests {
    use super::*;
    fn full_text_count(shape: &egui::Shape, expected: &str) -> usize {
        match shape {
            egui::Shape::Text(text) => {
                usize::from(!text.galley.elided && text.galley.text() == expected)
            }
            egui::Shape::Vec(shapes) => shapes
                .iter()
                .map(|shape| full_text_count(shape, expected))
                .sum(),
            _ => 0,
        }
    }
    #[test]
    fn elided_cells_have_one_automatic_or_custom_tooltip_in_both_themes() {
        let full = "Full fixture registration and executable path";
        let detail = "Matched component identity and full fixture path";
        for dark in [false, true] {
            for mode in ["automatic", "same-custom", "richer-custom"] {
                let context = egui::Context::default();
                apply(&context, dark);
                context.style_mut_of(
                    if dark {
                        egui::Theme::Dark
                    } else {
                        egui::Theme::Light
                    },
                    |style| {
                        style.interaction.tooltip_delay = 0.;
                        style.interaction.tooltip_grace_time = 0.;
                    },
                );
                let mut point = None;
                let mut final_counts = (0, 0);
                for frame in 0..7 {
                    let mut rect = egui::Rect::NOTHING;
                    let events = if frame == 1 {
                        vec![egui::Event::PointerMoved(point.unwrap())]
                    } else {
                        vec![]
                    };
                    let mut output = context.run_ui(
                        egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(
                                egui::Pos2::ZERO,
                                Vec2::new(760., 600.),
                            )),
                            focused: true,
                            time: Some(frame as f64 * 0.2),
                            events,
                            ..Default::default()
                        },
                        |ui| {
                            let response = match mode {
                                "automatic" => table_cell(ui, full, 80., 32.),
                                "same-custom" => table_cell_with_tooltip(ui, full, 80., 32., full),
                                _ => table_cell_with_tooltip(ui, full, 80., 32., detail),
                            };
                            rect = response.rect;
                        },
                    );
                    if point.is_none() {
                        point = Some(rect.center());
                    }
                    final_counts = (
                        output
                            .shapes
                            .iter()
                            .map(|s| full_text_count(&s.shape, full))
                            .sum(),
                        output
                            .shapes
                            .iter()
                            .map(|s| full_text_count(&s.shape, detail))
                            .sum(),
                    );
                    output.textures_delta.clear();
                }
                assert_eq!(
                    final_counts,
                    if mode == "richer-custom" {
                        (0, 1)
                    } else {
                        (1, 0)
                    },
                    "{dark} {mode}"
                );
            }
        }
    }
}

#[cfg(debug_assertions)]
#[derive(Clone, Default, serde::Serialize)]
struct GeometryFrame {
    controls: Vec<ControlGeometry>,
    scroll_areas: Vec<serde_json::Value>,
}
#[cfg(debug_assertions)]
pub fn record_scroll(
    ctx: &egui::Context,
    name: &str,
    inner: egui::Rect,
    content: Vec2,
    offset: Vec2,
) {
    ctx.data_mut(|data| {
        let id = egui::Id::new("native-control-geometry");
        if let Some(mut frame) = data.get_temp::<GeometryFrame>(id) {
            frame.scroll_areas.push(serde_json::json!({"name":name,"viewport":[inner.left(),inner.top(),inner.width(),inner.height()],"content":[content.x,content.y],"offset":[offset.x,offset.y]}));
            data.insert_temp(id, frame);
        }
    });
}
#[cfg(debug_assertions)]
#[derive(Clone, serde::Serialize)]
struct ControlGeometry {
    role: String,
    rect: [f32; 4],
    radius: u8,
    clip_rect: [f32; 4],
    layer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expanded: Option<bool>,
}
#[cfg(debug_assertions)]
pub fn begin_geometry_frame(ctx: &egui::Context) {
    if std::env::args().any(|arg| arg == "--render-qa" || arg == "--render-offscreen-qa") {
        reset_geometry_frame(ctx);
    }
}
#[cfg(debug_assertions)]
fn reset_geometry_frame(ctx: &egui::Context) {
    ctx.data_mut(|data| {
        data.insert_temp(
            egui::Id::new("native-control-geometry"),
            GeometryFrame::default(),
        )
    });
}
#[cfg(all(test, debug_assertions))]
pub(crate) fn begin_fixture_geometry_test(ctx: &egui::Context) {
    reset_geometry_frame(ctx);
}
#[cfg(debug_assertions)]
pub fn geometry_json(ctx: &egui::Context) -> serde_json::Value {
    let mut frame = ctx.data(|data| {
        serde_json::to_value(
            data.get_temp::<GeometryFrame>(egui::Id::new("native-control-geometry"))
                .unwrap_or_default(),
        )
        .unwrap_or_default()
    });
    frame["font_tokens"] = serde_json::json!({"caption":FONT_CAPTION,"body":FONT_BODY,"title":FONT_TITLE,"display":FONT_DISPLAY});
    if let Some(controls) = frame["controls"].as_array_mut() {
        for control in controls {
            let rect = |name: &str| -> Option<egui::Rect> {
                let values = control[name].as_array()?;
                Some(egui::Rect::from_min_size(
                    egui::pos2(
                        values.get(0)?.as_f64()? as f32,
                        values.get(1)?.as_f64()? as f32,
                    ),
                    egui::vec2(
                        values.get(2)?.as_f64()? as f32,
                        values.get(3)?.as_f64()? as f32,
                    ),
                ))
            };
            let targetable = rect("rect")
                .zip(rect("clip_rect"))
                .is_some_and(|(bounds, clip)| {
                    let center = bounds.center();
                    control["enabled"] == true
                        && clip.contains(center)
                        && ctx
                            .layer_id_at(center)
                            .is_some_and(|layer| control["layer"] == format!("{layer:?}"))
                });
            control["targetable"] = serde_json::json!(targetable);
        }
    }
    frame
}
fn record_control(ui: &egui::Ui, role: &str, rect: egui::Rect, radius: u8) {
    #[cfg(debug_assertions)]
    ui.ctx().data_mut(|data| {
        let id = egui::Id::new("native-control-geometry");
        if let Some(mut frame) = data.get_temp::<GeometryFrame>(id) {
            frame.controls.push(ControlGeometry {
                role: role.to_owned(),
                rect: [rect.left(), rect.top(), rect.width(), rect.height()],
                radius,
                clip_rect: [
                    ui.clip_rect().left(),
                    ui.clip_rect().top(),
                    ui.clip_rect().width(),
                    ui.clip_rect().height(),
                ],
                layer: format!("{:?}", ui.layer_id()),
                label: None,
                enabled: None,
                id: None,
                expanded: None,
            });
            data.insert_temp(id, frame);
        }
    });
    let _ = (ui, role, rect, radius);
}

#[cfg(debug_assertions)]
pub(crate) fn record_region(ui: &egui::Ui, role: &str, rect: egui::Rect, radius: u8) {
    record_control(ui, role, rect, radius);
}

fn record_labeled_control(
    ui: &egui::Ui,
    role: &str,
    rect: egui::Rect,
    radius: u8,
    label: &str,
    enabled: bool,
) {
    record_control(ui, role, rect, radius);
    #[cfg(debug_assertions)]
    ui.ctx().data_mut(|data| {
        let id = egui::Id::new("native-control-geometry");
        if let Some(mut frame) = data.get_temp::<GeometryFrame>(id) {
            if let Some(control) = frame.controls.last_mut() {
                control.label = Some(label.to_owned());
                control.enabled = Some(enabled && ui.is_enabled());
            }
            data.insert_temp(id, frame);
        }
    });
    let _ = (label, enabled);
}
#[cfg(debug_assertions)]
pub(crate) fn record_fixture_hover_target(ui: &egui::Ui, label: &str, response: &egui::Response) {
    record_labeled_control(
        ui,
        "hover-target",
        response.rect,
        0,
        label,
        response.enabled(),
    );
}
#[cfg(debug_assertions)]
pub(crate) fn record_fixture_control(ui: &egui::Ui, label: &str, response: &egui::Response) {
    record_labeled_control(
        ui,
        "icon-action",
        response.rect,
        13,
        label,
        response.enabled(),
    );
    if !ui.ctx().data(|data| {
        data.get_temp::<GeometryFrame>(egui::Id::new("native-control-geometry"))
            .is_some()
    }) {
        return;
    }
    let expanded = egui::collapsing_header::CollapsingState::load(ui.ctx(), response.id)
        .map(|state| state.is_open());
    ui.ctx().data_mut(|data| {
        let id = egui::Id::new("native-control-geometry");
        if let Some(mut frame) = data.get_temp::<GeometryFrame>(id) {
            if let Some(control) = frame.controls.last_mut() {
                control.id = Some(response.id.value());
                control.expanded = expanded;
                if expanded.is_some() {
                    control.role = "disclosure".into();
                    control.radius = (response.rect.height() / 2.) as u8;
                }
            }
            data.insert_temp(id, frame);
        }
    });
}

fn field_style(ui: &mut egui::Ui) {
    ui.spacing_mut().interact_size.y = FIELD_HEIGHT;
    ui.spacing_mut().button_padding = Vec2::new(12., 6.);
    let visuals = ui.visuals_mut();
    for visual in [
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        visual.corner_radius = FIELD_RADIUS.into();
    }
}

pub fn hover_help(ui: &egui::Ui, response: &egui::Response, label: &str, text: &str) {
    response.clone().on_hover_text(text);
    #[cfg(debug_assertions)]
    {
        record_labeled_control(
            ui,
            "hover-help",
            response.rect,
            0,
            label,
            response.enabled(),
        );
        ui.ctx()
            .data_mut(|data| data.insert_temp(egui::Id::new(("hover-help", label)), response.id));
    }
    let _ = (ui, label);
}

#[cfg(debug_assertions)]
pub fn qa_tooltip_open(ctx: &egui::Context, label: &str) -> bool {
    ctx.data(|data| data.get_temp::<egui::Id>(egui::Id::new(("hover-help", label))))
        .is_some_and(|id| egui::Tooltip::was_tooltip_open_last_frame(ctx, id))
}

/// Sets the row height before laying out labels, so earlier labels are not
/// positioned against a shorter default row than the fields that follow.
pub fn control_row<R>(
    ui: &mut egui::Ui,
    contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    let response = ui
        .scope(|ui| {
            field_style(ui);
            ui.horizontal_wrapped(contents)
        })
        .inner;
    record_control(ui, "field-row", response.response.rect, 0);
    response
}

pub fn action_row<R>(
    ui: &mut egui::Ui,
    contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    ui.scope(|ui| {
        ui.spacing_mut().interact_size.y = CONTROL_HEIGHT;
        ui.horizontal_wrapped(contents)
    })
    .inner
}

pub fn scroll_vertical() -> egui::ScrollArea {
    egui::ScrollArea::vertical()
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
}

/// Product-details dialogs share the centered action group in the reference.
/// Labels use the same measured button owner; narrow groups wrap at full width.
pub fn centered_dialog_actions<R>(
    ui: &mut egui::Ui,
    labels: &[&str],
    contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    let width = ui.available_width();
    let needed = labels
        .iter()
        .map(|label| action_width(ui, label, CONTROL_PADDING_X))
        .sum::<f32>()
        + ui.spacing().item_spacing.x * labels.len().saturating_sub(1) as f32;
    ui.allocate_ui_with_layout(
        Vec2::new(width, CONTROL_HEIGHT),
        egui::Layout::left_to_right(egui::Align::Center),
        |row| {
            // Text/widget bounds quantize independently; retain subpixel slack
            // without moving the group's measured center or forcing a wrap.
            let group_width = needed.ceil().min(width);
            let rect = egui::Rect::from_min_size(
                row.cursor().min + Vec2::new((width - needed).max(0.) / 2., 0.),
                Vec2::new(group_width, CONTROL_HEIGHT),
            );
            let group = row.scope_builder(
                egui::UiBuilder::new()
                    .max_rect(rect)
                    .layout(egui::Layout::left_to_right(egui::Align::Center).with_main_wrap(true)),
                contents,
            );
            record_control(row, "centered-dialog-actions", group.response.rect, 0);
            group.inner
        },
    )
}

pub fn scroll_horizontal() -> egui::ScrollArea {
    egui::ScrollArea::horizontal()
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
}

pub fn tabs<R>(
    ui: &mut egui::Ui,
    contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<R> {
    ui.scope(|ui| {
        ui.spacing_mut().interact_size.y = TAB_HEIGHT;
        ui.spacing_mut().button_padding = Vec2::new(12., 4.);
        ui.spacing_mut().item_spacing.x = 4.;
        let visuals = ui.visuals_mut();
        for visual in [
            &mut visuals.widgets.inactive,
            &mut visuals.widgets.hovered,
            &mut visuals.widgets.active,
            &mut visuals.widgets.open,
        ] {
            visual.corner_radius = ((TAB_HEIGHT / 2.) as u8).into();
        }
        ui.horizontal_wrapped(contents)
    })
    .inner
}

pub fn tab(ui: &mut egui::Ui, selected: bool, label: &str) -> egui::Response {
    let response = stable_selectable(
        ui,
        selected,
        RichText::new(label).family(if selected {
            semibold()
        } else {
            FontFamily::Proportional
        }),
    );
    record_labeled_control(
        ui,
        "tab",
        response.rect,
        (TAB_HEIGHT / 2.) as u8,
        label,
        ui.is_enabled(),
    );
    response
}

pub fn choice(ui: &mut egui::Ui, selected: bool, label: &str) -> egui::Response {
    let response = stable_selectable(
        ui,
        selected,
        RichText::new(label).family(if selected {
            semibold()
        } else {
            FontFamily::Proportional
        }),
    );
    record_labeled_control(
        ui,
        "choice",
        response.rect,
        FIELD_RADIUS,
        label,
        ui.is_enabled(),
    );
    response
}

pub(crate) fn stable_selectable(
    ui: &mut egui::Ui,
    selected: bool,
    text: RichText,
) -> egui::Response {
    let mut button = egui::Button::selectable(selected, text);
    if selected
        && ui.is_enabled()
        && let Some(response) = ui.ctx().read_response(ui.next_auto_id())
        && response.enabled()
        && (response.hovered() || response.is_pointer_button_down_on())
    {
        let t = tokens(ui.visuals().dark_mode);
        let hover = if ui.visuals().dark_mode {
            Color32::from_gray(210)
        } else {
            t.primary.gamma_multiply(0.8)
        };
        button = button.fill(if response.is_pointer_button_down_on() {
            hover.gamma_multiply(0.85)
        } else {
            hover
        });
    }
    // Inactive unselected labels have no frame stroke. Keep that same margin
    // on hover, rather than adding a border that moves this and following tabs.
    ui.add(if selected {
        button
    } else {
        button.stroke(Stroke::NONE)
    })
}

pub fn choice_value<T: PartialEq>(
    ui: &mut egui::Ui,
    current: &mut T,
    value: T,
    label: &str,
) -> egui::Response {
    let mut response = choice(ui, *current == value, label);
    if response.clicked() && *current != value {
        *current = value;
        response.mark_changed();
    }
    response
}
pub fn tab_with_icon_count(
    ui: &mut egui::Ui,
    selected: bool,
    icon: Icon,
    label: &str,
    count: Option<usize>,
    t: Tokens,
) -> egui::Response {
    let text = count
        .map(|count| format!("{label} ({count})"))
        .unwrap_or_else(|| label.to_owned());
    let family = if selected {
        semibold()
    } else {
        FontFamily::Proportional
    };
    // Reserve the heavier state's width so changing tabs never shifts peers.
    let font = FontId::new(FONT_BODY, semibold());
    let width = ui
        .painter()
        .layout_no_wrap(text.clone(), font, t.foreground)
        .size()
        .x
        + 48.;
    let icon_id = ui.id().with(("page-tab-icon", label));
    let background = ui.painter().add(egui::Shape::Noop);
    let base = if selected {
        if ui.visuals().dark_mode {
            t.card
        } else {
            t.canvas
        }
    } else if ui.visuals().dark_mode {
        Color32::TRANSPARENT
    } else {
        t.sidebar
    };
    let painted = ui
        .allocate_ui_with_layout(
            Vec2::new(width, 40.),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.spacing_mut().button_padding = Vec2::new(12., 6.);
                egui::Button::new((
                    egui::Atom::custom(icon_id, Vec2::splat(16.)),
                    RichText::new(text)
                        .family(family.clone())
                        .size(FONT_BODY)
                        .color(t.foreground),
                ))
                .selected(selected)
                .fill(Color32::TRANSPARENT)
                .stroke(Stroke::new(
                    1.,
                    if selected && ui.visuals().dark_mode {
                        t.muted
                    } else if selected {
                        t.primary
                    } else {
                        t.border
                    },
                ))
                .corner_radius(20)
                .min_size(Vec2::new(width, 40.))
                .atom_ui(ui)
            },
        )
        .inner;
    ui.painter().set(
        background,
        egui::Shape::rect_filled(
            painted.response.rect,
            20,
            if painted.response.enabled() && painted.response.hovered() {
                t.hover
            } else {
                base
            },
        ),
    );
    if let Some(rect) = painted.rect(icon_id) {
        paint_icon(ui.painter(), rect, icon, t.primary);
    }
    focus_ring(ui, &painted.response, 22);
    record_labeled_control(
        ui,
        "page-tab",
        painted.response.rect,
        20,
        label,
        ui.is_enabled(),
    );
    painted.response
}

/// Settings sections use the source's icon-over-label tabs and active underline.
pub fn settings_tab(
    ui: &mut egui::Ui,
    selected: bool,
    icon: Icon,
    label: &str,
    t: Tokens,
) -> egui::Response {
    let width = ui
        .painter()
        .layout_no_wrap(
            label.to_owned(),
            FontId::new(FONT_BODY, semibold()),
            t.foreground,
        )
        .size()
        .x
        + 16.;
    let response = ui.add_sized(Vec2::new(width, 64.), egui::Button::new("").frame(false));
    if response.hovered() {
        ui.painter().rect_filled(response.rect, 32, t.hover);
    }
    let colour = if selected { t.foreground } else { t.muted };
    paint_icon(
        ui.painter(),
        egui::Rect::from_center_size(
            egui::pos2(response.rect.center().x, response.rect.top() + 19.),
            Vec2::splat(20.),
        ),
        icon,
        colour,
    );
    ui.painter().text(
        egui::pos2(response.rect.center().x, response.rect.top() + 43.),
        egui::Align2::CENTER_CENTER,
        label,
        FontId::new(
            FONT_BODY,
            if selected {
                semibold()
            } else {
                FontFamily::Proportional
            },
        ),
        colour,
    );
    if selected {
        ui.painter().line_segment(
            [
                egui::pos2(response.rect.left(), response.rect.bottom() - 1.),
                egui::pos2(response.rect.right(), response.rect.bottom() - 1.),
            ],
            Stroke::new(2., t.primary),
        );
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Button, ui.is_enabled(), selected, label)
    });
    record_labeled_control(
        ui,
        "settings-tab",
        response.rect,
        32,
        label,
        ui.is_enabled(),
    );
    #[cfg(debug_assertions)]
    if label == "Menu" {
        record_fixture_control(ui, "Menu Layout", &response);
    }
    focus_ring(ui, &response, 34);
    response
}

pub fn radio_value<T: PartialEq>(
    ui: &mut egui::Ui,
    current: &mut T,
    value: T,
    label: &str,
) -> egui::Response {
    let response = ui.radio_value(current, value, label);
    record_labeled_control(ui, "radio", response.rect, 9, label, ui.is_enabled());
    response
}

pub fn tab_value<T: PartialEq>(
    ui: &mut egui::Ui,
    current: &mut T,
    value: T,
    label: &str,
) -> egui::Response {
    let mut response = tab(ui, *current == value, label);
    if response.clicked() && *current != value {
        *current = value;
        response.mark_changed();
    }
    response
}

pub fn input(
    ui: &mut egui::Ui,
    value: &mut String,
    width: f32,
    hint: &str,
    enabled: bool,
) -> egui::Response {
    let response = ui
        .add_enabled_ui(enabled, |ui| {
            let frame = egui::Frame::new()
                .fill(ui.visuals().extreme_bg_color)
                .stroke(ui.visuals().widgets.inactive.bg_stroke)
                .corner_radius(FIELD_RADIUS)
                .inner_margin(egui::Margin::symmetric(16, 0));
            // A custom TextEdit frame bypasses egui's automatic hover paint. Keep
            // its existing metrics while reserving the background before the text.
            let background = ui.painter().add(egui::Shape::Noop);
            let invisible = egui::Frame {
                fill: Color32::TRANSPARENT,
                stroke: Stroke::new(frame.stroke.width, Color32::TRANSPARENT),
                ..frame
            };
            let response = ui.add(
                egui::TextEdit::singleline(value)
                    .interactive(ui.is_enabled())
                    .desired_width(width.max(60.))
                    .min_size(Vec2::new(width.max(60.), FIELD_HEIGHT))
                    .vertical_align(egui::Align::Center)
                    .frame(invisible)
                    .clip_text(true)
                    .hint_text(hint),
            );
            let fill = if response.enabled() && response.hovered() {
                tokens(ui.visuals().dark_mode).hover
            } else {
                frame.fill
            };
            ui.painter().set(
                background,
                egui::Shape::Rect(egui::epaint::RectShape::new(
                    response.rect,
                    FIELD_RADIUS,
                    fill,
                    frame.stroke,
                    egui::StrokeKind::Inside,
                )),
            );
            response
        })
        .inner;
    focus_ring(ui, &response, FIELD_RADIUS + 2);
    record_labeled_control(
        ui,
        "input",
        response.rect,
        FIELD_RADIUS,
        &format!("Text field: {hint}"),
        enabled,
    );
    response
}

pub fn selector_width(ui: &egui::Ui, labels: &[&str]) -> f32 {
    let font = ui.style().text_styles[&egui::TextStyle::Button].clone();
    let label_width = labels
        .iter()
        .map(|label| {
            ui.painter()
                .layout_no_wrap((*label).to_owned(), font.clone(), ui.visuals().text_color())
                .size()
                .x
        })
        .fold(0., f32::max);
    (label_width + 24. + ui.spacing().icon_width + ui.spacing().icon_spacing + 2.).ceil()
}

pub fn selector<R>(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    selected: &str,
    choices: &[&str],
    contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::InnerResponse<Option<R>> {
    ui.scope(|ui| {
        field_style(ui);
        let width = selector_width(ui, choices).max(selector_width(ui, &[selected]));
        let response = egui::ComboBox::from_id_salt(id)
            .width(width)
            .selected_text(selected)
            .show_ui(ui, contents);
        focus_ring(ui, &response.response, FIELD_RADIUS + 2);
        record_labeled_control(
            ui,
            "selector",
            response.response.rect,
            FIELD_RADIUS,
            &format!("Select: {selected}"),
            ui.is_enabled(),
        );
        response
    })
    .inner
}

pub fn field_action(ui: &mut egui::Ui, label: &str, enabled: bool) -> bool {
    action_button(ui, label, enabled, None, FIELD_HEIGHT, 12., "field-action").clicked()
}

pub fn checkbox<'a>(
    ui: &mut egui::Ui,
    checked: &'a mut bool,
    label: impl egui::IntoAtoms<'a>,
    enabled: bool,
) -> egui::Response {
    checkbox_mixed(ui, checked, false, label, enabled)
}
pub fn checkbox_widget(ui: &mut egui::Ui, checked: &mut bool, enabled: bool) -> egui::Response {
    checkbox_mixed(ui, checked, false, (), enabled)
}
pub fn checkbox_text(
    ui: &mut egui::Ui,
    checked: &mut bool,
    label: &str,
    enabled: bool,
) -> egui::Response {
    checkbox(ui, checked, label, enabled)
}
pub fn checkbox_named(
    ui: &mut egui::Ui,
    checked: &mut bool,
    mixed: bool,
    label: &str,
    enabled: bool,
) -> egui::Response {
    let response = checkbox_mixed(ui, checked, mixed, (), enabled);
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, enabled, *checked, label)
    });
    record_labeled_control(ui, "checkbox", response.rect, 4, label, enabled);
    response.on_hover_text(label)
}
pub fn checkbox_mixed<'a>(
    ui: &mut egui::Ui,
    checked: &'a mut bool,
    mixed: bool,
    label: impl egui::IntoAtoms<'a>,
    enabled: bool,
) -> egui::Response {
    let t = tokens(ui.visuals().dark_mode);
    let selected = *checked || mixed;
    let atoms = label.into_atoms();
    let control_label: Option<String> = atoms.text().map(|text| text.to_string());
    let width = atoms
        .text()
        .map_or(24., |text| {
            ui.painter()
                .layout_no_wrap(
                    text.to_string(),
                    FontId::new(FONT_BODY, FontFamily::Proportional),
                    t.foreground,
                )
                .size()
                .x
                + CHECKBOX_SIZE
                + LABEL_GAP
        })
        .min(ui.available_width())
        .max(24.);
    let response = ui
        .allocate_ui_with_layout(
            Vec2::new(width, 24.),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.set_max_width(width);
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                ui.spacing_mut().icon_width = CHECKBOX_SIZE;
                ui.spacing_mut().icon_width_inner = 9.;
                ui.spacing_mut().interact_size.y = 24.;
                ui.spacing_mut().icon_spacing = LABEL_GAP;
                let visuals = ui.visuals_mut();
                visuals.override_text_color = Some(t.foreground);
                for visual in [
                    &mut visuals.widgets.inactive,
                    &mut visuals.widgets.hovered,
                    &mut visuals.widgets.active,
                    &mut visuals.widgets.open,
                    &mut visuals.widgets.noninteractive,
                ] {
                    visual.corner_radius = 4.into();
                    visual.bg_fill = if selected { t.primary } else { t.canvas };
                    visual.weak_bg_fill = visual.bg_fill;
                    visual.bg_stroke = Stroke::new(
                        1.2,
                        if selected {
                            t.primary
                        } else {
                            t.muted.gamma_multiply(0.7)
                        },
                    );
                    visual.fg_stroke = Stroke::new(
                        1.5,
                        if selected && visuals.dark_mode {
                            t.primary_text
                        } else if selected {
                            Color32::WHITE
                        } else {
                            t.foreground
                        },
                    );
                }
                visuals.widgets.hovered.bg_stroke = Stroke::new(1.5, t.primary);
                visuals.widgets.hovered.bg_fill = if selected {
                    if visuals.dark_mode {
                        Color32::from_gray(210)
                    } else {
                        t.primary.gamma_multiply(0.8)
                    }
                } else {
                    t.hover
                };
                visuals.widgets.hovered.weak_bg_fill = visuals.widgets.hovered.bg_fill;
                visuals.widgets.active.bg_fill =
                    visuals.widgets.hovered.bg_fill.gamma_multiply(0.85);
                visuals.widgets.active.weak_bg_fill = visuals.widgets.active.bg_fill;
                ui.add_enabled(
                    enabled,
                    egui::Checkbox::new(checked, atoms).indeterminate(mixed),
                )
            },
        )
        .inner;
    focus_ring(ui, &response, 6);
    if let Some(label) = control_label {
        record_labeled_control(ui, "checkbox", response.rect, 4, &label, enabled);
    } else {
        record_control(ui, "checkbox", response.rect, 4);
    }
    response
}

pub fn semibold() -> FontFamily {
    FontFamily::Name("Inter 550".into())
}
#[derive(Clone, Copy)]
pub struct Tokens {
    pub sidebar: Color32,
    pub attention: Color32,
    pub canvas: Color32,
    pub foreground: Color32,
    pub card: Color32,
    pub muted: Color32,
    pub border: Color32,
    pub primary: Color32,
    pub primary_text: Color32,
    pub tint: Color32,
    pub hover: Color32,
}
pub fn tokens(dark: bool) -> Tokens {
    let blue = dcleaner::brand::BLUE;
    if dark {
        Tokens {
            sidebar: Color32::from_gray(24),
            attention: Color32::from_rgb(235, 204, 112),
            canvas: Color32::from_gray(33),
            foreground: Color32::from_gray(243),
            card: Color32::from_gray(47),
            muted: Color32::from_gray(175),
            border: Color32::from_gray(65),
            primary: Color32::from_gray(237),
            primary_text: Color32::from_gray(24),
            tint: Color32::from_gray(53),
            hover: Color32::from_gray(72),
        }
    } else {
        Tokens {
            sidebar: Color32::from_rgb(247, 250, 252),
            attention: Color32::from_rgb(136, 88, 0),
            canvas: Color32::from_rgb(241, 245, 248),
            foreground: Color32::from_rgb(24, 51, 67),
            card: Color32::WHITE,
            muted: Color32::from_rgb(77, 104, 120),
            border: Color32::from_rgb(217, 227, 233),
            primary: blue,
            primary_text: Color32::from_rgb(7, 29, 43),
            tint: Color32::from_rgba_unmultiplied(blue.r(), blue.g(), blue.b(), 38),
            hover: Color32::from_rgba_unmultiplied(blue.r(), blue.g(), blue.b(), 20),
        }
    }
}
pub fn apply(ctx: &egui::Context, dark: bool) {
    let t = tokens(dark);
    let mut style = egui::Style::default();
    style.visuals = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    style.visuals.override_text_color = None;
    style.visuals.panel_fill = t.canvas;
    style.visuals.window_fill = t.card;
    style.visuals.extreme_bg_color = t.card;
    style.visuals.selection.bg_fill = t.primary;
    style.visuals.hyperlink_color = t.primary;
    style.visuals.selection.stroke = Stroke::new(1., t.primary_text);
    if dark {
        style.visuals.error_fg_color = Color32::from_rgb(247, 159, 159);
        style.visuals.warn_fg_color = t.attention;
    }
    for state in [
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
        &mut style.visuals.widgets.noninteractive,
    ] {
        state.corner_radius = u8::MAX.into();
        state.bg_fill = t.card;
        state.weak_bg_fill = t.card;
        state.bg_stroke = Stroke::new(1., t.border);
        state.fg_stroke = Stroke::new(1.125, t.foreground);
    }
    style.visuals.widgets.hovered.bg_fill = t.hover;
    style.visuals.widgets.hovered.weak_bg_fill = t.hover;
    style.visuals.widgets.active.bg_fill = t.tint;
    style.visuals.widgets.active.weak_bg_fill = t.tint;
    style.spacing.item_spacing = Vec2::new(LABEL_GAP, LABEL_GAP);
    style.spacing.button_padding = Vec2::new(16., 8.);
    style.spacing.scroll = egui::style::ScrollStyle::solid();
    style.spacing.scroll.foreground_color = true;
    style.spacing.scroll.dormant_handle_opacity = 0.35;
    style.text_styles.insert(
        egui::TextStyle::Body,
        FontId::new(FONT_BODY, FontFamily::Proportional),
    );
    style
        .text_styles
        .insert(egui::TextStyle::Button, FontId::new(FONT_BODY, semibold()));
    style.text_styles.insert(
        egui::TextStyle::Small,
        FontId::new(FONT_CAPTION, FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Heading,
        FontId::new(FONT_DISPLAY, semibold()),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        FontId::new(FONT_CAPTION, FontFamily::Monospace),
    );
    for font in style.text_styles.values_mut() {
        if ![FONT_CAPTION, FONT_BODY, FONT_TITLE, FONT_DISPLAY].contains(&font.size) {
            font.size = FONT_BODY;
        }
    }
    let theme = if dark {
        egui::Theme::Dark
    } else {
        egui::Theme::Light
    };
    ctx.set_theme(theme);
    ctx.set_style_of(theme, style);
}
pub fn card(t: Tokens) -> egui::Frame {
    egui::Frame::new()
        .fill(t.card)
        .corner_radius(SECTION_RADIUS)
        .inner_margin(CONTENT)
}

#[derive(Clone, Copy)]
pub enum JoinedEdge {
    Left,
    Right,
    Top,
    Bottom,
}

pub fn joined_radius(edge: JoinedEdge) -> egui::CornerRadius {
    let r = SECTION_RADIUS;
    match edge {
        JoinedEdge::Left => egui::CornerRadius {
            nw: r,
            sw: r,
            ne: 0,
            se: 0,
        },
        JoinedEdge::Right => egui::CornerRadius {
            nw: 0,
            sw: 0,
            ne: r,
            se: r,
        },
        JoinedEdge::Top => egui::CornerRadius {
            nw: r,
            sw: 0,
            ne: r,
            se: 0,
        },
        JoinedEdge::Bottom => egui::CornerRadius {
            nw: 0,
            sw: r,
            ne: 0,
            se: r,
        },
    }
}

pub fn joined_card(t: Tokens, edge: JoinedEdge) -> egui::Frame {
    card(t)
        .fill(match edge {
            JoinedEdge::Left | JoinedEdge::Top => t.sidebar,
            JoinedEdge::Right | JoinedEdge::Bottom => t.card,
        })
        .corner_radius(joined_radius(edge))
}
pub fn canvas_background(ui: &egui::Ui, dark: bool) {
    if !dark {
        return;
    }
    ui.painter()
        .rect_filled(ui.max_rect(), 0., tokens(true).canvas);
}

/// Keep alpha and tonal detail while removing hue from dark-mode artwork.
pub fn monochrome(color: Color32) -> Color32 {
    let [r, g, b, a] = color.to_srgba_unmultiplied();
    let gray = ((r as u32 * 54 + g as u32 * 183 + b as u32 * 19 + 128) / 256) as u8;
    Color32::from_rgba_unmultiplied(gray, gray, gray, a)
}

pub fn monochrome_image(mut image: egui::ColorImage) -> egui::ColorImage {
    for pixel in &mut image.pixels {
        *pixel = monochrome(*pixel);
    }
    image
}
pub fn dialog_frame(t: Tokens) -> egui::Frame {
    egui::Frame::new()
        .fill(t.card)
        .stroke(Stroke::new(1., t.border))
        .corner_radius(SECTION_RADIUS)
        .inner_margin(24.)
}
pub fn primary(ui: &mut egui::Ui, label: &str, t: Tokens, enabled: bool) -> bool {
    action_button(
        ui,
        label,
        enabled,
        Some(t),
        CONTROL_HEIGHT,
        CONTROL_PADDING_X,
        "primary",
    )
    .clicked()
}
pub fn secondary(ui: &mut egui::Ui, label: &str, enabled: bool) -> bool {
    action_button(
        ui,
        label,
        enabled,
        None,
        CONTROL_HEIGHT,
        CONTROL_PADDING_X,
        "secondary",
    )
    .clicked()
}
pub fn header_action(ui: &mut egui::Ui, label: &str, enabled: bool) -> bool {
    action_button(ui, label, enabled, None, 28., 12., "header-action").clicked()
}
pub fn close_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> bool {
    let response = ui.add_enabled(
        enabled,
        egui::Button::new("")
            .frame(false)
            .min_size(Vec2::splat(28.)),
    );
    paint_frameless_hover(ui, &response, 14);
    let center = response.rect.center();
    let stroke = Stroke::new(
        1.05,
        if enabled {
            ui.visuals().text_color()
        } else {
            ui.visuals().weak_text_color()
        },
    );
    ui.painter()
        .line_segment([center - Vec2::splat(4.), center + Vec2::splat(4.)], stroke);
    ui.painter().line_segment(
        [center + Vec2::new(-4., 4.), center + Vec2::new(4., -4.)],
        stroke,
    );
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, label));
    record_labeled_control(ui, "icon-action", response.rect, 14, label, enabled);
    focus_ring(ui, &response, 16);
    response.on_hover_text(label).clicked()
}
pub fn icon_action(ui: &mut egui::Ui, icon: Icon, label: &str, enabled: bool) -> bool {
    let plain = matches!(icon, Icon::Menu);
    let response = ui
        .scope(|ui| {
            ui.spacing_mut().interact_size = Vec2::splat(28.);
            ui.spacing_mut().button_padding = Vec2::ZERO;
            ui.add_enabled(
                enabled,
                egui::Button::new("")
                    .min_size(Vec2::splat(28.))
                    .frame(!plain)
                    .corner_radius(14),
            )
        })
        .inner;
    if plain {
        paint_frameless_hover(ui, &response, 14);
    }
    let t = tokens(ui.visuals().dark_mode);
    paint_icon(
        ui.painter(),
        response.rect.shrink(6.),
        icon,
        if enabled && !plain {
            t.primary
        } else {
            t.muted
        },
    );
    record_labeled_control(ui, "header-icon-action", response.rect, 14, label, enabled);
    focus_ring(ui, &response, 16);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, label));
    response.on_hover_text(label).clicked()
}
fn action_icon(label: &str) -> Option<(Icon, bool)> {
    match label {
        "Configure" | "Cookie settings" => Some((Icon::Settings, false)),
        "Check for updates" => Some((Icon::Update, false)),
        "Rescan" | "Scan again" => Some((Icon::Refresh, true)),
        "Refresh"
        | "Refresh profiles"
        | "Refresh status"
        | "Refresh history"
        | "Refresh available drives" => Some((Icon::Refresh, false)),
        "Export report" | "Export JSON" | "Save to text file" => Some((Icon::Export, false)),
        "Choose folder" | "Add folder" | "Open in folder" | "Open file location" => {
            Some((Icon::Folder, false))
        }
        _ => None,
    }
}
fn action_width(ui: &egui::Ui, label: &str, padding: f32) -> f32 {
    let text_width = ui
        .painter()
        .layout_no_wrap(
            label.into(),
            FontId::new(FONT_BODY, semibold()),
            ui.visuals().text_color(),
        )
        .size()
        .x;
    text_width
        + 2. * padding
        + if action_icon(label).is_some() {
            24.
        } else {
            0.
        }
}
fn action_button(
    ui: &mut egui::Ui,
    label: &str,
    enabled: bool,
    primary: Option<Tokens>,
    height: f32,
    padding: f32,
    role: &str,
) -> egui::Response {
    let t = tokens(ui.visuals().dark_mode);
    let colour = primary.map_or(t.foreground, |t| t.primary_text);
    let icon = action_icon(label);
    let radius = if height == CONTROL_HEIGHT {
        CONTROL_RADIUS
    } else {
        (height / 2.) as u8
    };
    let width = action_width(ui, label, padding);
    let icon_id = egui::Id::new("action-button-icon");
    let text = RichText::new(label)
        .family(semibold())
        .size(FONT_BODY)
        .color(colour);
    let mut button = match icon {
        Some((_, true)) => egui::Button::new((text, egui::Atom::custom(icon_id, Vec2::splat(16.)))),
        Some((_, false)) => {
            egui::Button::new((egui::Atom::custom(icon_id, Vec2::splat(16.)), text))
        }
        None => egui::Button::new(text),
    }
    .corner_radius(radius)
    .min_size(Vec2::new(width, height));
    if primary.is_some() {
        button = button.stroke(Stroke::NONE);
    }
    // Allocate the whole control before entering its child UI. A scope starts
    // at the remaining row width, so a long label can grow beyond a wrapped
    // footer instead of moving to the next line.
    let painted = ui
        .allocate_ui_with_layout(
            Vec2::new(width, height),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.spacing_mut().button_padding = Vec2::new(padding, 4.);
                ui.spacing_mut().interact_size.y = height;
                if let Some(t) = primary {
                    let visuals = ui.visuals_mut();
                    visuals.widgets.inactive.bg_fill = t.primary;
                    visuals.widgets.inactive.weak_bg_fill = t.primary;
                    let hover = if visuals.dark_mode {
                        Color32::from_gray(210)
                    } else {
                        dcleaner::brand::BLUE.gamma_multiply(0.8)
                    };
                    visuals.widgets.hovered.bg_fill = hover;
                    visuals.widgets.hovered.weak_bg_fill = hover;
                    visuals.widgets.active.bg_fill = hover.gamma_multiply(0.85);
                    visuals.widgets.active.weak_bg_fill = visuals.widgets.active.bg_fill;
                }
                ui.add_enabled_ui(enabled, |ui| button.atom_ui(ui)).inner
            },
        )
        .inner;
    if let (Some((icon, _)), Some(rect)) = (icon, painted.rect(icon_id)) {
        paint_icon(
            ui.painter(),
            rect,
            icon,
            if enabled { colour } else { t.muted },
        );
    }
    let response = painted.response;
    focus_ring(ui, &response, radius + 2);
    record_labeled_control(ui, role, response.rect, radius, label, enabled);
    response
}
pub fn row_action(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    compact_action(ui, label, enabled, TABLE_ACTION_HEIGHT)
}
pub fn finding_action(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    compact_action(ui, label, enabled, 28.)
}
fn compact_action(ui: &mut egui::Ui, label: &str, enabled: bool, height: f32) -> egui::Response {
    let response = ui
        .add_enabled_ui(enabled, |ui| {
            // Table actions gained 2 px at each vertical edge. Explicitly set
            // the height so the surrounding row cannot inherit a taller field.
            ui.spacing_mut().button_padding = Vec2::new(12., 4.);
            ui.spacing_mut().interact_size.y = height;
            let font = FontId::new(FONT_CAPTION, semibold());
            let galley =
                ui.painter()
                    .layout_no_wrap(label.to_owned(), font, ui.visuals().text_color());
            let response = ui.add(
                egui::Button::new("")
                    .corner_radius((height / 2.) as u8)
                    .min_size(Vec2::new(galley.size().x + 24., height)),
            );
            if ui.is_rect_visible(response.rect) {
                // Inter's line box includes unequal ascender/descender space.
                // Centre the rendered glyph bounds rather than that line box.
                let position = response.rect.center() - galley.mesh_bounds.center().to_vec2();
                ui.painter().galley(
                    position,
                    galley,
                    ui.style().interact(&response).text_color(),
                );
            }
            response.widget_info(|| {
                egui::WidgetInfo::labeled(egui::WidgetType::Button, ui.is_enabled(), label)
            });
            response
        })
        .inner;
    focus_ring(ui, &response, (height / 2.) as u8 + 2);
    record_labeled_control(
        ui,
        if height == TABLE_ACTION_HEIGHT {
            "table-action"
        } else {
            "finding-action"
        },
        response.rect,
        (height / 2.) as u8,
        label,
        enabled,
    );
    response
}
pub fn table_cell(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    width: f32,
    height: f32,
) -> egui::Response {
    table_cell_inner(ui, text.into(), width, height, true)
}
/// Custom help replaces the label's automatic ellipsis tooltip, so a truncated
/// cell has one tooltip owner and retains its richer explanatory content.
pub fn table_cell_with_tooltip(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    width: f32,
    height: f32,
    tooltip: impl Into<egui::WidgetText>,
) -> egui::Response {
    table_cell_inner(ui, text.into(), width, height, false).on_hover_text(tooltip)
}
fn table_cell_inner(
    ui: &mut egui::Ui,
    text: egui::WidgetText,
    width: f32,
    height: f32,
    automatic_tooltip: bool,
) -> egui::Response {
    ui.allocate_ui_with_layout(
        Vec2::new(width, height),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.set_min_size(Vec2::new(width, height));
            ui.set_max_width(width);
            ui.add(
                egui::Label::new(text)
                    .truncate()
                    .show_tooltip_when_elided(automatic_tooltip),
            )
        },
    )
    .inner
}
pub fn menu_action(ui: &mut egui::Ui, icon: Icon, label: &str, enabled: bool) -> egui::Response {
    let t = tokens(ui.visuals().dark_mode);
    // Popup UIs initially inherit a wide layout bound. Keep contextual options
    // compact instead of allowing a grow atom to claim the entire page width.
    ui.set_max_width(224.);
    let icon_id = ui.id().with(("option-icon", label));
    let background = ui.painter().add(egui::Shape::Noop);
    let painted = ui
        .add_enabled_ui(enabled, |ui| {
            ui.spacing_mut().button_padding = Vec2::new(8., 5.);
            egui::Button::new((
                egui::Atom::custom(icon_id, Vec2::splat(16.)),
                RichText::new(label)
                    .family(FontFamily::Proportional)
                    .size(FONT_BODY),
                egui::Atom::grow(),
            ))
            .gap(8.)
            .frame(false)
            .corner_radius(15)
            .min_size(Vec2::new(ui.available_width().clamp(180., 224.), 30.))
            .atom_ui(ui)
        })
        .inner;
    paint_frameless_hover_behind(ui, &painted.response, 15, background);
    if let Some(rect) = painted.rect(icon_id) {
        paint_icon(
            ui.painter(),
            rect,
            icon,
            if enabled { t.foreground } else { t.muted },
        );
    }
    record_labeled_control(ui, "menu-option", painted.response.rect, 15, label, enabled);
    focus_ring(ui, &painted.response, 17);
    painted.response
}

pub fn row_more(ui: &mut egui::Ui, enabled: bool) -> egui::Response {
    let response = ui
        .scope(|ui| {
            ui.spacing_mut().button_padding = Vec2::ZERO;
            ui.add_enabled(
                enabled,
                egui::Button::new("")
                    .min_size(Vec2::splat(TABLE_ACTION_HEIGHT))
                    .corner_radius((TABLE_ACTION_HEIGHT / 2.) as u8),
            )
        })
        .inner;
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, "More options")
    });
    let colour = ui.visuals().text_color();
    for offset in [-4., 0., 4.] {
        ui.painter()
            .circle_filled(response.rect.center() + Vec2::new(offset, 0.), 0.9, colour);
    }
    focus_ring(ui, &response, (TABLE_ACTION_HEIGHT / 2.) as u8 + 2);
    record_labeled_control(
        ui,
        "row-more",
        response.rect,
        (TABLE_ACTION_HEIGHT / 2.) as u8,
        "More options",
        enabled,
    );
    response.on_hover_text("More options")
}
pub fn disclosure(ui: &mut egui::Ui, label: &str, open: bool) -> egui::Response {
    let response = ui.add_sized(
        Vec2::splat(TABLE_ACTION_HEIGHT),
        egui::Button::new("").frame(false),
    );
    paint_frameless_hover(ui, &response, (TABLE_ACTION_HEIGHT / 2.) as u8);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, label));
    let center = response.rect.center();
    let direction = if open { -1. } else { 1. };
    ui.painter().add(egui::Shape::line(
        vec![
            center + Vec2::new(-4., -2. * direction),
            center + Vec2::new(0., 2. * direction),
            center + Vec2::new(4., -2. * direction),
        ],
        Stroke::new(1.2, ui.visuals().text_color()),
    ));
    record_labeled_control(
        ui,
        "disclosure",
        response.rect,
        (TABLE_ACTION_HEIGHT / 2.) as u8,
        label,
        true,
    );
    focus_ring(ui, &response, (TABLE_ACTION_HEIGHT / 2.) as u8 + 2);
    response.on_hover_text(label)
}
#[cfg(windows)]
pub fn window_chrome(ui: &mut egui::Ui, t: Tokens) {
    let ctx = ui.ctx().clone();
    let rect = ctx.content_rect();
    let maximized = ctx.input(|input| input.viewport().maximized.unwrap_or(false));
    let drag_rect = egui::Rect::from_min_max(
        rect.min + Vec2::new(64., 5.),
        egui::pos2(rect.right() - 176., rect.top() + 32.),
    );
    let drag = ui.interact(
        drag_rect,
        ui.id().with("window-drag"),
        egui::Sense::click_and_drag(),
    );
    if drag.drag_started() {
        ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
    }
    if drag.double_clicked() {
        ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
    }
    for (offset, name) in [
        (0., "Close"),
        (
            44.,
            if maximized {
                "Restore window"
            } else {
                "Maximize"
            },
        ),
        (88., "Minimize"),
    ] {
        let button_rect = egui::Rect::from_min_size(
            egui::pos2(rect.right() - offset - 44., rect.top()),
            Vec2::new(44., 32.),
        );
        let response = ui.place(button_rect, egui::Button::new("").frame(false));
        response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, name));
        let painter = ui.painter().with_clip_rect(rect);
        if response.hovered() {
            painter.rect_filled(
                button_rect,
                button_rect.height() / 2.,
                if name == "Close" && !ui.visuals().dark_mode {
                    Color32::from_rgb(164, 46, 59)
                } else {
                    t.hover
                },
            );
        }
        let center = button_rect.center();
        let stroke = Stroke::new(0.9, t.muted);
        if name == "Minimize" {
            painter.line_segment(
                [center - Vec2::new(5., 0.), center + Vec2::new(5., 0.)],
                stroke,
            );
        } else if name == "Close" {
            painter.line_segment(
                [center - Vec2::splat(4.5), center + Vec2::splat(4.5)],
                stroke,
            );
            painter.line_segment(
                [center + Vec2::new(-4.5, 4.5), center + Vec2::new(4.5, -4.5)],
                stroke,
            );
        } else {
            painter.rect_stroke(
                egui::Rect::from_center_size(center, Vec2::splat(9.)),
                0.,
                stroke,
                egui::StrokeKind::Inside,
            );
        }
        focus_ring(ui, &response, (button_rect.height() / 2.) as u8 + 2);
        if response.clicked() {
            ctx.send_viewport_cmd(match name {
                "Close" => egui::ViewportCommand::Close,
                "Minimize" => egui::ViewportCommand::Minimized(true),
                _ => egui::ViewportCommand::Maximized(!maximized),
            });
        }
        response.on_hover_text(name);
    }
    if !maximized {
        use egui::{CursorIcon as C, ResizeDirection as D};
        let edge = 5.;
        let corner = 9.;
        let regions = [
            (
                D::NorthWest,
                C::ResizeNwSe,
                egui::Rect::from_min_size(rect.min, Vec2::splat(corner)),
            ),
            (
                D::NorthEast,
                C::ResizeNeSw,
                egui::Rect::from_min_size(
                    egui::pos2(rect.right() - corner, rect.top()),
                    Vec2::splat(corner),
                ),
            ),
            (
                D::SouthWest,
                C::ResizeNeSw,
                egui::Rect::from_min_size(
                    egui::pos2(rect.left(), rect.bottom() - corner),
                    Vec2::splat(corner),
                ),
            ),
            (
                D::SouthEast,
                C::ResizeNwSe,
                egui::Rect::from_min_size(rect.max - Vec2::splat(corner), Vec2::splat(corner)),
            ),
            (
                D::North,
                C::ResizeVertical,
                egui::Rect::from_min_max(
                    rect.min + Vec2::new(corner, 0.),
                    egui::pos2(rect.right() - corner, rect.top() + edge),
                ),
            ),
            (
                D::South,
                C::ResizeVertical,
                egui::Rect::from_min_max(
                    egui::pos2(rect.left() + corner, rect.bottom() - edge),
                    rect.max - Vec2::new(corner, 0.),
                ),
            ),
            (
                D::West,
                C::ResizeHorizontal,
                egui::Rect::from_min_max(
                    rect.min + Vec2::new(0., corner),
                    egui::pos2(rect.left() + edge, rect.bottom() - corner),
                ),
            ),
            (
                D::East,
                C::ResizeHorizontal,
                egui::Rect::from_min_max(
                    egui::pos2(rect.right() - edge, rect.top() + corner),
                    rect.max - Vec2::new(0., corner),
                ),
            ),
        ];
        for (direction, cursor, region) in regions {
            let response = ui
                .interact(
                    region,
                    ui.id().with(format!("window-resize-{direction:?}")),
                    egui::Sense::drag(),
                )
                .on_hover_cursor(cursor);
            if response.drag_started() {
                ctx.send_viewport_cmd(egui::ViewportCommand::BeginResize(direction));
            }
        }
    }
}
pub fn counted_label(count: usize, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}
pub fn muted(ui: &mut egui::Ui, label: impl Into<String>, t: Tokens) {
    ui.label(
        RichText::new(label.into())
            .color(t.muted)
            .size(FONT_CAPTION)
            .line_height(Some(CAPTION_LINE_HEIGHT)),
    );
}
pub(crate) fn focus_ring(ui: &egui::Ui, response: &egui::Response, radius: u8) {
    if response.enabled() && response.hovered() {
        ui.painter().rect_stroke(
            response.rect,
            radius.saturating_sub(2),
            Stroke::new(1.2, tokens(ui.visuals().dark_mode).muted),
            egui::StrokeKind::Inside,
        );
    }
    keyboard_focus_ring(ui, response, radius);
}

/// Switch tracks already express state; only keyboard focus adds an outline.
pub(crate) fn keyboard_focus_ring(ui: &egui::Ui, response: &egui::Response, radius: u8) {
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect.expand(2.),
            radius,
            Stroke::new(2., ui.visuals().selection.bg_fill),
            egui::StrokeKind::Outside,
        );
    }
}

fn frameless_hover_shape(ui: &egui::Ui, response: &egui::Response, radius: u8) -> egui::Shape {
    if response.enabled() && (response.hovered() || response.is_pointer_button_down_on()) {
        let t = tokens(ui.visuals().dark_mode);
        egui::Shape::rect_filled(
            response.rect,
            radius,
            if response.is_pointer_button_down_on() {
                t.tint
            } else {
                t.hover
            },
        )
    } else {
        egui::Shape::Noop
    }
}

// Reserve the background before a text button paints, so hover feedback cannot
// cover its label. Icon-only owners can paint before their own glyph instead.
pub(crate) fn paint_frameless_hover_behind(
    ui: &egui::Ui,
    response: &egui::Response,
    radius: u8,
    background: egui::layers::ShapeIdx,
) {
    ui.painter()
        .set(background, frameless_hover_shape(ui, response, radius));
}

fn paint_frameless_hover(ui: &egui::Ui, response: &egui::Response, radius: u8) {
    ui.painter()
        .add(frameless_hover_shape(ui, response, radius));
}

pub(crate) fn frameless_button(
    ui: &mut egui::Ui,
    size: impl Into<Vec2>,
    button: egui::Button<'_>,
) -> egui::Response {
    let background = ui.painter().add(egui::Shape::Noop);
    let response = ui.add_sized(size, button.frame(false));
    paint_frameless_hover_behind(
        ui,
        &response,
        (response.rect.height() / 2.) as u8,
        background,
    );
    response
}

/// The same egui disclosure, identity and layout, with the shared frameless
/// control feedback painted behind its label. Body controls keep their own
/// styles, and the resting header introduces no new card or border.
pub(crate) struct Disclosure(egui::CollapsingHeader);
impl Disclosure {
    pub(crate) fn new(text: impl Into<egui::WidgetText>) -> Self {
        Self(egui::CollapsingHeader::new(text))
    }
    pub(crate) fn id_salt(self, id: impl egui::AsIdSalt) -> Self {
        Self(self.0.id_salt(id))
    }
    pub(crate) fn default_open(self, open: bool) -> Self {
        Self(self.0.default_open(open))
    }
    pub(crate) fn show<R>(
        self,
        ui: &mut egui::Ui,
        contents: impl FnOnce(&mut egui::Ui) -> R,
    ) -> egui::collapsing_header::CollapsingResponse<R> {
        let background = ui.painter().add(egui::Shape::Noop);
        let response = self.0.show(ui, contents);
        paint_frameless_hover_behind(
            ui,
            &response.header_response,
            (response.header_response.rect.height() / 2.) as u8,
            background,
        );
        response
    }
}

#[derive(Clone, Copy)]
pub enum Icon {
    Search,
    Sun,
    Moon,
    Info,
    EyeOff,
    Forward,
    Undo,
    Check,
    Calendar,
    Menu,
    Account,
    Heart,
    Subscription,
    Windows,
    Applications,
    ContextMenu,
    Services,
    WindowCheck,
    Registry,
    Cookie,
    Trash,
    Refresh,
    Folder,
    Export,
    Home,
    Brush,
    Disk,
    Duplicate,
    Cloud,
    Programs,
    Optimizer,
    Browser,
    Update,
    Driver,
    Startup,
    History,
    Settings,
    Help,
}

pub fn navigation(
    ui: &mut egui::Ui,
    label: &str,
    icon: Icon,
    selected: bool,
    enabled: bool,
    compact: bool,
    t: Tokens,
) -> bool {
    let response = ui
        .add_enabled_ui(enabled, |ui| {
            ui.add_sized(
                Vec2::new(ui.available_width(), 40.),
                egui::Button::new("")
                    .selected(selected)
                    .fill(Color32::TRANSPARENT)
                    .stroke(Stroke::NONE)
                    .corner_radius(20),
            )
        })
        .inner;
    if selected || (enabled && response.hovered()) {
        ui.painter().rect_filled(
            response.rect,
            20,
            if enabled && response.hovered() {
                t.hover
            } else {
                t.tint
            },
        );
    }
    let colour = if enabled { t.foreground } else { t.muted };
    let icon_rect = egui::Rect::from_center_size(
        egui::pos2(
            if compact {
                response.rect.center().x
            } else {
                response.rect.left() + 26.
            },
            response.rect.center().y,
        ),
        Vec2::splat(20.),
    );
    paint_icon(ui.painter(), icon_rect, icon, colour);
    if !compact {
        ui.painter().text(
            egui::pos2(response.rect.left() + 48., response.rect.center().y),
            egui::Align2::LEFT_CENTER,
            label,
            FontId::new(
                FONT_BODY,
                if selected {
                    semibold()
                } else {
                    FontFamily::Proportional
                },
            ),
            colour,
        );
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Button, enabled, selected, label)
    });
    focus_ring(ui, &response, 22);
    record_labeled_control(
        ui,
        if compact {
            "rail-navigation"
        } else {
            "navigation"
        },
        response.rect,
        20,
        &format!("Navigate {label}"),
        enabled,
    );
    response.on_hover_text(label).clicked()
}

pub fn paint_icon(p: &egui::Painter, rect: egui::Rect, icon: Icon, colour: Color32) {
    let point = |x: f32, y: f32| rect.min + Vec2::new(x, y) * (rect.width() / 20.);
    let stroke = Stroke::new(0.96, colour);
    let line = |coords: &[(f32, f32)]| {
        p.add(egui::Shape::line(
            coords.iter().map(|&(x, y)| point(x, y)).collect(),
            stroke,
        ))
    };
    match icon {
        Icon::Sun => {
            p.circle_stroke(point(10., 10.), rect.width() * 0.225, stroke);
            for (a, b) in [
                ((10., 0.), (10., 3.)),
                ((10., 17.), (10., 20.)),
                ((0., 10.), (3., 10.)),
                ((17., 10.), (20., 10.)),
                ((3., 3.), (5., 5.)),
                ((15., 15.), (17., 17.)),
                ((3., 17.), (5., 15.)),
                ((15., 5.), (17., 3.)),
            ] {
                line(&[a, b]);
            }
        }
        Icon::Moon => {
            let mut points = Vec::new();
            for index in 0..=20 {
                let angle =
                    -std::f32::consts::FRAC_PI_2 - index as f32 * std::f32::consts::PI * 1.5 / 20.;
                points.push(point(10. + 8. * angle.cos(), 10. + 8. * angle.sin()));
            }
            let start = 6_f32.atan2(2.);
            let end = (-2_f32).atan2(-6.) + std::f32::consts::TAU;
            for index in 0..=16 {
                let angle = start + (end - start) * index as f32 / 16.;
                points.push(point(
                    16. + 40_f32.sqrt() * angle.cos(),
                    4. + 40_f32.sqrt() * angle.sin(),
                ));
            }
            p.add(egui::Shape::line(points, stroke));
        }
        Icon::Search => {
            p.circle_stroke(point(8., 8.), rect.width() * 0.275, stroke);
            line(&[(12., 12.), (18., 18.)]);
        }
        Icon::Applications => {
            line(&[(6., 3.), (18., 3.), (18., 15.)]);
            line(&[(2., 7.), (14., 7.), (14., 19.), (2., 19.), (2., 7.)]);
        }
        Icon::ContextMenu => {
            line(&[
                (3., 2.),
                (3., 15.),
                (7., 11.),
                (10., 18.),
                (13., 16.),
                (9., 10.),
                (15., 10.),
                (3., 2.),
            ]);
            line(&[(12., 3.), (18., 3.)]);
            line(&[(15., 6.), (18., 6.)]);
        }
        Icon::Services => {
            line(&[(2., 2.), (16., 2.), (16., 10.)]);
            line(&[(2., 2.), (2., 15.), (9., 15.)]);
            line(&[(4., 5.), (13., 5.)]);
            line(&[(4., 8.), (9., 8.)]);
            paint_icon(
                p,
                egui::Rect::from_min_size(point(9., 9.), Vec2::splat(rect.width() * 0.5)),
                Icon::Settings,
                colour,
            );
        }
        Icon::WindowCheck => {
            line(&[(2., 3.), (18., 3.), (18., 17.), (2., 17.), (2., 3.)]);
            line(&[(2., 7.), (18., 7.)]);
            line(&[(6., 11.), (9., 14.), (15., 9.)]);
        }
        Icon::Windows => {
            for x in [2., 11.] {
                for y in [2., 11.] {
                    p.rect_stroke(
                        egui::Rect::from_two_pos(point(x, y), point(x + 7., y + 7.)),
                        0,
                        stroke,
                        egui::StrokeKind::Inside,
                    );
                }
            }
        }
        Icon::Subscription => {
            line(&[(3., 4.), (17., 4.), (17., 15.), (3., 15.), (3., 4.)]);
            line(&[(1., 18.), (19., 18.)]);
            line(&[
                (10., 12.),
                (6., 8.),
                (7., 6.),
                (9., 6.),
                (10., 8.),
                (11., 6.),
                (13., 6.),
                (14., 8.),
                (10., 12.),
            ]);
        }
        Icon::Info => {
            p.circle_stroke(point(10., 10.), rect.width() * 0.4, stroke);
            line(&[(10., 9.), (10., 14.)]);
            p.circle_filled(point(10., 6.), rect.width() * 0.03, colour);
        }
        Icon::Check => {
            line(&[(4., 10.), (8., 14.), (16., 6.)]);
        }
        Icon::Forward => {
            line(&[(3., 10.), (16., 10.)]);
            line(&[(11., 5.), (16., 10.), (11., 15.)]);
        }
        Icon::Undo => {
            line(&[(3., 7.), (12., 7.), (16., 10.), (16., 15.), (12., 18.)]);
            line(&[(7., 3.), (3., 7.), (7., 11.)]);
        }
        Icon::EyeOff => {
            line(&[
                (2., 10.),
                (6., 5.),
                (11., 4.),
                (16., 7.),
                (18., 10.),
                (14., 15.),
                (9., 16.),
                (4., 13.),
                (2., 10.),
            ]);
            line(&[(3., 2.), (17., 18.)]);
        }
        Icon::Calendar => {
            line(&[(3., 5.), (17., 5.), (17., 18.), (3., 18.), (3., 5.)]);
            line(&[(3., 9.), (17., 9.)]);
            line(&[(6., 2.), (6., 7.)]);
            line(&[(14., 2.), (14., 7.)]);
            for x in [6., 10., 14.] {
                for y in [12., 15.] {
                    p.circle_filled(point(x, y), rect.width() * 0.02625, colour);
                }
            }
        }
        Icon::Menu => {
            for y in [5., 10., 15.] {
                line(&[(3., y), (17., y)]);
            }
        }
        Icon::Account => {
            p.circle_stroke(point(10., 6.), rect.width() * 0.18, stroke);
            line(&[
                (3., 18.),
                (3., 15.),
                (6., 12.),
                (14., 12.),
                (17., 15.),
                (17., 18.),
                (3., 18.),
            ]);
        }
        Icon::Heart => {
            for pts in [
                [(10., 6.), (6., 0.), (0., 4.), (3., 10.)],
                [(3., 10.), (5., 13.), (8., 15.), (10., 17.)],
                [(10., 17.), (12., 15.), (15., 13.), (17., 10.)],
                [(17., 10.), (20., 4.), (14., 0.), (10., 6.)],
            ] {
                p.add(egui::epaint::CubicBezierShape::from_points_stroke(
                    pts.map(|(x, y)| point(x, y)),
                    false,
                    Color32::TRANSPARENT,
                    stroke,
                ));
            }
            line(&[(6., 9.), (9., 12.), (14., 7.)]);
        }

        Icon::Registry => {
            for x in [3., 11.] {
                for y in [3., 11.] {
                    p.rect_stroke(
                        egui::Rect::from_two_pos(point(x, y), point(x + 6., y + 6.)),
                        0,
                        stroke,
                        egui::StrokeKind::Inside,
                    );
                }
            }
        }
        Icon::Cookie => {
            line(&[
                (17., 10.),
                (16., 15.),
                (12., 18.),
                (7., 18.),
                (3., 14.),
                (2., 9.),
                (4., 5.),
                (8., 2.),
                (11., 2.),
                (11., 6.),
                (14., 6.),
                (14., 10.),
                (17., 10.),
            ]);
            for (x, y) in [(6., 9.), (9., 6.), (8., 14.), (12., 12.)] {
                p.circle_filled(point(x, y), rect.width() * 0.02625, colour);
            }
        }
        Icon::Trash => {
            line(&[(3., 5.), (17., 5.)]);
            line(&[(7., 5.), (7., 2.), (13., 2.), (13., 5.)]);
            line(&[(5., 5.), (6., 18.), (14., 18.), (15., 5.)]);
            line(&[(8., 8.), (8., 15.)]);
            line(&[(12., 8.), (12., 15.)]);
        }
        Icon::Refresh => {
            line(&[(16., 7.), (14., 4.), (10., 3.), (6., 4.), (3., 8.)]);
            line(&[(16., 3.), (16., 7.), (12., 7.)]);
            line(&[(4., 13.), (6., 16.), (10., 17.), (14., 16.), (17., 12.)]);
            line(&[(4., 17.), (4., 13.), (8., 13.)]);
        }
        Icon::Folder => {
            line(&[
                (2., 6.),
                (2., 16.),
                (18., 16.),
                (18., 6.),
                (10., 6.),
                (8., 3.),
                (2., 3.),
                (2., 6.),
            ]);
        }
        Icon::Export => {
            line(&[(4., 9.), (4., 17.), (16., 17.), (16., 9.)]);
            line(&[(10., 12.), (10., 2.)]);
            line(&[(6., 6.), (10., 2.), (14., 6.)]);
        }
        Icon::Cloud => {
            line(&[
                (5., 15.),
                (3., 15.),
                (1.5, 13.),
                (1.5, 10.5),
                (3.5, 8.5),
                (5.5, 8.5),
                (6., 5.),
                (9., 3.5),
                (12., 4.),
                (14., 7.),
                (16., 7.),
                (18.5, 9.5),
                (18.5, 12.5),
                (16., 15.),
                (14., 15.),
            ]);
            let mut gear = Vec::new();
            for i in 0..32 {
                let a = i as f32 * std::f32::consts::TAU / 32.;
                let r = if i % 4 == 0 || i % 4 == 3 { 3.8 } else { 2.9 };
                gear.push(point(10. + a.cos() * r, 14. + a.sin() * r));
            }
            gear.push(gear[0]);
            p.add(egui::Shape::line(gear, stroke));
            p.circle_stroke(point(10., 14.), rect.width() * 0.06, stroke);
        }
        Icon::Optimizer => {
            line(&[
                (7., 12.),
                (7., 8.),
                (13., 2.),
                (18., 2.),
                (18., 7.),
                (12., 13.),
                (8., 13.),
            ]);
            p.circle_stroke(point(13.5, 6.5), rect.width() * 0.085, stroke);
            line(&[(7., 8.), (3., 8.), (2., 13.), (6., 12.)]);
            line(&[(12., 13.), (12., 17.), (7., 18.), (8., 14.)]);
            line(&[(5., 15.), (2., 18.)]);
        }
        Icon::Duplicate => {
            line(&[(7., 2.), (17., 2.), (17., 14.)]);
            line(&[(3., 6.), (13., 6.), (13., 18.), (3., 18.), (3., 6.)]);
            line(&[(6., 10.), (10., 10.)]);
            line(&[(6., 13.), (10., 13.)]);
        }
        Icon::Programs => {
            line(&[(2., 3.), (18., 3.), (18., 9.)]);
            line(&[(2., 3.), (2., 15.), (10., 15.)]);
            line(&[(2., 7.), (18., 7.)]);
            line(&[(12., 11.), (18., 11.)]);
            line(&[(13., 11.), (13., 18.), (17., 18.), (17., 11.)]);
            line(&[(14., 9.), (16., 9.)]);
            line(&[(15., 13.), (15., 16.)]);
        }
        Icon::Browser => {
            line(&[(2., 3.), (18., 3.), (18., 17.), (2., 17.), (2., 3.)]);
            line(&[(2., 7.), (18., 7.)]);
            p.circle_filled(point(5., 5.), rect.width() * 0.02625, colour);
            p.circle_filled(point(8., 5.), rect.width() * 0.02625, colour);
            line(&[(12., 10.), (12., 15.), (14., 13.), (17., 14.)]);
        }
        Icon::Update => {
            line(&[(2., 4.), (18., 4.), (18., 15.), (2., 15.), (2., 4.)]);
            line(&[(5., 18.), (15., 18.)]);
            line(&[(10., 15.), (10., 18.)]);
            line(&[(10., 12.), (10., 6.)]);
            line(&[(6., 10.), (10., 6.), (14., 10.)]);
        }
        Icon::Driver => {
            line(&[(5., 5.), (15., 5.), (15., 15.), (5., 15.), (5., 5.)]);
            line(&[(8., 8.), (12., 8.), (12., 12.), (8., 12.), (8., 8.)]);
            for position in [7., 10., 13.] {
                line(&[(position, 2.), (position, 5.)]);
                line(&[(position, 15.), (position, 18.)]);
                line(&[(2., position), (5., position)]);
                line(&[(15., position), (18., position)]);
            }
        }
        Icon::Startup => {
            line(&[(2., 3.), (18., 3.), (18., 14.), (2., 14.), (2., 3.)]);
            line(&[(10., 14.), (10., 18.)]);
            line(&[(6., 18.), (14., 18.)]);
        }
        Icon::Home => {
            line(&[(2., 9.), (10., 2.), (18., 9.)]);
            line(&[
                (4., 8.),
                (4., 18.),
                (8., 18.),
                (8., 12.),
                (12., 12.),
                (12., 18.),
                (16., 18.),
                (16., 8.),
            ]);
        }
        Icon::Brush => {
            // Angled broom with a bound head and separate bristles.
            line(&[(11., 11.), (17., 2.), (19., 3.), (13., 12.)]);
            line(&[
                (8., 10.),
                (15., 14.),
                (12., 18.),
                (6., 19.),
                (2., 16.),
                (6., 14.),
                (8., 10.),
            ]);
            line(&[(7., 12.), (14., 16.)]);
            line(&[(6., 15.), (4., 17.)]);
            line(&[(9., 16.), (7., 18.)]);
            // Cleaning sparkles distinguish this from a generic pencil.
            line(&[(4., 2.), (4., 7.)]);
            line(&[(1.5, 4.5), (6.5, 4.5)]);
            line(&[(9., 1.), (9., 4.)]);
            line(&[(7.5, 2.5), (10.5, 2.5)]);
        }
        Icon::Disk => {
            p.circle_stroke(point(10., 10.), rect.width() * 0.4, stroke);
            p.circle_stroke(point(10., 10.), rect.width() * 0.1, stroke);
            line(&[(13., 4.), (16., 7.)]);
        }
        Icon::History => {
            p.circle_stroke(point(10., 10.), rect.width() * 0.4, stroke);
            line(&[(10., 5.), (10., 10.), (14., 12.)]);
        }
        Icon::Help => {
            p.circle_stroke(point(10., 10.), rect.width() * 0.4, stroke);
            line(&[
                (7., 7.),
                (8., 5.5),
                (11., 5.5),
                (13., 7.),
                (13., 9.),
                (10., 11.),
                (10., 12.),
            ]);
            p.circle_filled(point(10., 15.), rect.width() * 0.03375, colour);
        }
        Icon::Settings => {
            let mut gear = Vec::new();
            for i in 0..32 {
                let a = i as f32 * std::f32::consts::TAU / 32.;
                let r = if i % 4 == 0 || i % 4 == 3 { 8. } else { 6.2 };
                gear.push(point(10. + a.cos() * r, 10. + a.sin() * r));
            }
            gear.push(gear[0]);
            p.add(egui::Shape::line(gear, stroke));
            p.circle_stroke(point(10., 10.), rect.width() * 0.15, stroke);
        }
    }
}
