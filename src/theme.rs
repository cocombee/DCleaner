use eframe::egui::{self, Color32, FontFamily, FontId, RichText, Stroke, Vec2};
pub const CONTENT: f32 = 28.;
pub const LABEL_GAP: f32 = 8.;
pub const CONTROL_HEIGHT: f32 = 36.;
pub const CONTROL_RADIUS: u8 = 18;
pub const SECTION_RADIUS: u8 = 16;
pub const FIELD_HEIGHT: f32 = 32.;
pub const FIELD_RADIUS: u8 = 8;
pub const TAB_HEIGHT: f32 = 28.;
pub const TABLE_ACTION_HEIGHT: f32 = 22.;

#[cfg(debug_assertions)]
#[derive(Clone, Default, serde::Serialize)]
struct GeometryFrame {
    controls: Vec<ControlGeometry>,
}
#[cfg(debug_assertions)]
#[derive(Clone, serde::Serialize)]
struct ControlGeometry {
    role: String,
    rect: [f32; 4],
    radius: u8,
}
#[cfg(debug_assertions)]
pub fn begin_geometry_frame(ctx: &egui::Context) {
    if std::env::args().any(|arg| arg == "--render-qa" || arg == "--render-offscreen-qa") {
        ctx.data_mut(|data| {
            data.insert_temp(
                egui::Id::new("native-control-geometry"),
                GeometryFrame::default(),
            )
        });
    }
}
#[cfg(debug_assertions)]
pub fn geometry_json(ctx: &egui::Context) -> serde_json::Value {
    ctx.data(|data| {
        serde_json::to_value(
            data.get_temp::<GeometryFrame>(egui::Id::new("native-control-geometry"))
                .unwrap_or_default(),
        )
        .unwrap_or_default()
    })
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
            });
            data.insert_temp(id, frame);
        }
    });
    let _ = (ui, role, rect, radius);
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
            visual.corner_radius = 14.into();
        }
        ui.horizontal_wrapped(contents)
    })
    .inner
}

pub fn tab(ui: &mut egui::Ui, selected: bool, label: &str) -> egui::Response {
    let response = ui.selectable_label(
        selected,
        RichText::new(label).family(if selected {
            semibold()
        } else {
            FontFamily::Proportional
        }),
    );
    record_control(ui, "tab", response.rect, 14);
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
    let frame = egui::Frame::new()
        .fill(ui.visuals().extreme_bg_color)
        .stroke(ui.visuals().widgets.inactive.bg_stroke)
        .corner_radius(FIELD_RADIUS)
        .inner_margin(egui::Margin::symmetric(10, 0));
    let response = ui.add_enabled(
        enabled,
        egui::TextEdit::singleline(value)
            .desired_width(width.max(60.))
            .min_size(Vec2::new(width.max(60.), FIELD_HEIGHT))
            .vertical_align(egui::Align::Center)
            .frame(frame)
            .clip_text(true)
            .hint_text(hint),
    );
    focus_ring(ui, &response, FIELD_RADIUS + 2);
    record_control(ui, "input", response.rect, FIELD_RADIUS);
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
        record_control(ui, "selector", response.response.rect, FIELD_RADIUS);
        response
    })
    .inner
}

pub fn search_width(ui: &egui::Ui, choices: &[&str]) -> f32 {
    let font = ui.style().text_styles[&egui::TextStyle::Body].clone();
    let text_width = |text: &str| {
        ui.painter()
            .layout_no_wrap(text.to_owned(), font.clone(), ui.visuals().text_color())
            .size()
            .x
    };
    let fixed = text_width("Search")
        + text_width("Sort by")
        + text_width("Descending")
        + selector_width(ui, choices)
        + ui.spacing().icon_width
        + ui.spacing().icon_spacing
        + 48.;
    (ui.available_width() - fixed).clamp(150., 320.)
}

pub fn field_action(ui: &mut egui::Ui, label: &str, enabled: bool) -> bool {
    let response = ui
        .scope(|ui| {
            ui.spacing_mut().button_padding = Vec2::new(12., 4.);
            ui.add_enabled(
                enabled,
                egui::Button::new(label)
                    .corner_radius(16)
                    .min_size(Vec2::new(0., FIELD_HEIGHT)),
            )
        })
        .inner;
    focus_ring(ui, &response, 18);
    record_control(ui, "field-action", response.rect, 16);
    response.clicked()
}

pub fn checkbox<'a>(
    ui: &mut egui::Ui,
    checked: &'a mut bool,
    label: impl egui::IntoAtoms<'a>,
    enabled: bool,
) -> egui::Response {
    checkbox_widget(ui, egui::Checkbox::new(checked, label), enabled)
}

pub fn checkbox_widget(
    ui: &mut egui::Ui,
    checkbox: egui::Checkbox<'_>,
    enabled: bool,
) -> egui::Response {
    let response = ui
        .scope(|ui| {
            let visuals = ui.visuals_mut();
            for visual in [
                &mut visuals.widgets.inactive,
                &mut visuals.widgets.hovered,
                &mut visuals.widgets.active,
                &mut visuals.widgets.open,
                &mut visuals.widgets.noninteractive,
            ] {
                visual.corner_radius = 3.into();
            }
            ui.add_enabled(enabled, checkbox)
        })
        .inner;
    focus_ring(ui, &response, 5);
    record_control(ui, "checkbox", response.rect, 3);
    response
}

pub fn semibold() -> FontFamily {
    FontFamily::Name("Inter Semibold".into())
}
#[derive(Clone, Copy)]
pub struct Tokens {
    pub rail: Color32,
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
    if dark {
        Tokens {
            rail: Color32::from_rgb(8, 29, 46),
            sidebar: Color32::from_rgb(8, 29, 46),
            attention: Color32::from_rgb(246, 205, 52),
            canvas: Color32::from_rgb(7, 29, 43),
            foreground: Color32::from_rgb(239, 244, 247),
            card: Color32::from_rgb(13, 45, 68),
            muted: Color32::from_rgb(165, 182, 191),
            border: Color32::from_rgb(37, 65, 81),
            primary: Color32::from_rgb(0, 113, 246),
            primary_text: Color32::WHITE,
            tint: Color32::from_rgb(17, 74, 109),
            hover: Color32::from_rgb(18, 56, 75),
        }
    } else {
        Tokens {
            rail: Color32::from_rgb(227, 236, 242),
            sidebar: Color32::from_rgb(247, 250, 252),
            attention: Color32::from_rgb(136, 88, 0),
            canvas: Color32::from_rgb(241, 245, 248),
            foreground: Color32::from_rgb(24, 51, 67),
            card: Color32::WHITE,
            muted: Color32::from_rgb(77, 104, 120),
            border: Color32::from_rgb(217, 227, 233),
            primary: Color32::from_rgb(7, 109, 224),
            primary_text: Color32::WHITE,
            tint: Color32::from_rgb(224, 238, 252),
            hover: Color32::from_rgb(232, 241, 247),
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
    style.visuals.selection.stroke = Stroke::new(1., t.primary_text);
    for state in [
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.noninteractive,
    ] {
        state.corner_radius = 6.into();
        state.bg_fill = t.card;
        state.weak_bg_fill = t.card;
        state.bg_stroke = Stroke::new(1., t.border);
        state.fg_stroke = Stroke::new(1.5, t.foreground);
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
        FontId::new(13., FontFamily::Proportional),
    );
    style
        .text_styles
        .insert(egui::TextStyle::Button, FontId::new(13., semibold()));
    style.text_styles.insert(
        egui::TextStyle::Small,
        FontId::new(11., FontFamily::Proportional),
    );
    style
        .text_styles
        .insert(egui::TextStyle::Heading, FontId::new(22., semibold()));
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
pub fn canvas_background(ui: &egui::Ui, dark: bool) {
    if !dark {
        return;
    }
    let rect = ui.max_rect();
    let top = Color32::from_rgb(12, 45, 64);
    let bottom = Color32::from_rgb(7, 29, 43);
    let mut mesh = egui::Mesh::default();
    mesh.colored_vertex(rect.left_top(), top);
    mesh.colored_vertex(rect.right_top(), top);
    mesh.colored_vertex(rect.left_bottom(), bottom);
    mesh.colored_vertex(rect.right_bottom(), bottom);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(2, 1, 3);
    ui.painter().add(egui::Shape::mesh(mesh));
}
pub fn dialog_frame(t: Tokens) -> egui::Frame {
    egui::Frame::new()
        .fill(t.card)
        .stroke(Stroke::new(1., t.border))
        .corner_radius(SECTION_RADIUS)
        .inner_margin(24.)
}
pub fn primary(ui: &mut egui::Ui, label: &str, t: Tokens, enabled: bool) -> bool {
    let response = ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(label).color(t.primary_text))
            .fill(t.primary)
            .stroke(Stroke::NONE)
            .corner_radius(CONTROL_RADIUS)
            .min_size(Vec2::new(120., CONTROL_HEIGHT)),
    );
    focus_ring(ui, &response, CONTROL_RADIUS + 2);
    record_control(ui, "primary", response.rect, CONTROL_RADIUS);
    response.clicked()
}
pub fn secondary(ui: &mut egui::Ui, label: &str, enabled: bool) -> bool {
    let font = ui.style().text_styles[&egui::TextStyle::Button].clone();
    let width = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font, ui.visuals().text_color())
        .size()
        .x
        + 32.;
    ui.allocate_ui_with_layout(
        Vec2::new(width.max(100.), CONTROL_HEIGHT),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            let response = ui.add_enabled(
                enabled,
                egui::Button::new(label)
                    .corner_radius(CONTROL_RADIUS)
                    .min_size(Vec2::new(100., CONTROL_HEIGHT)),
            );
            focus_ring(ui, &response, CONTROL_RADIUS + 2);
            record_control(ui, "secondary", response.rect, CONTROL_RADIUS);
            response.clicked()
        },
    )
    .inner
}
pub fn row_action(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    compact_action(ui, label, enabled, TABLE_ACTION_HEIGHT)
}
pub fn finding_action(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    compact_action(ui, label, enabled, 28.)
}
fn compact_action(ui: &mut egui::Ui, label: &str, enabled: bool, height: f32) -> egui::Response {
    let response = ui
        .scope(|ui| {
            ui.spacing_mut().button_padding = Vec2::new(10., 2.);
            let font = FontId::new(12., semibold());
            let width = (ui
                .painter()
                .layout_no_wrap(label.to_owned(), font, ui.visuals().text_color())
                .size()
                .x
                + 20.)
                .max(72.);
            ui.add_enabled(
                enabled,
                egui::Button::new(RichText::new(label).family(semibold()).size(12.))
                    .corner_radius((height / 2.) as u8)
                    .min_size(Vec2::new(width, height)),
            )
        })
        .inner;
    focus_ring(ui, &response, (height / 2.) as u8 + 2);
    record_control(
        ui,
        if height == TABLE_ACTION_HEIGHT {
            "table-action"
        } else {
            "finding-action"
        },
        response.rect,
        (height / 2.) as u8,
    );
    response
}
pub fn table_cell(
    ui: &mut egui::Ui,
    text: impl Into<egui::WidgetText>,
    width: f32,
    height: f32,
) -> egui::Response {
    ui.allocate_ui_with_layout(
        Vec2::new(width, height),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.set_min_size(Vec2::new(width, height));
            ui.set_max_width(width);
            ui.add(egui::Label::new(text).truncate())
        },
    )
    .inner
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
            .circle_filled(response.rect.center() + Vec2::new(offset, 0.), 1.2, colour);
    }
    focus_ring(ui, &response, (TABLE_ACTION_HEIGHT / 2.) as u8 + 2);
    record_control(
        ui,
        "row-more",
        response.rect,
        (TABLE_ACTION_HEIGHT / 2.) as u8,
    );
    response.on_hover_text("More options")
}
#[cfg(windows)]
pub fn window_chrome(ui: &mut egui::Ui, t: Tokens) {
    let ctx = ui.ctx().clone();
    let rect = ctx.content_rect();
    let maximized = ctx.input(|input| input.viewport().maximized.unwrap_or(false));
    let drag_rect = egui::Rect::from_min_max(
        rect.min + Vec2::new(64., 5.),
        egui::pos2(rect.right() - 132., rect.top() + 32.),
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
                0.,
                if name == "Close" {
                    Color32::from_rgb(164, 46, 59)
                } else {
                    t.hover
                },
            );
        }
        let center = button_rect.center();
        let stroke = Stroke::new(1.2, t.muted);
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
        focus_ring(ui, &response, 2);
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
pub fn muted(ui: &mut egui::Ui, label: impl Into<String>, t: Tokens) {
    ui.label(RichText::new(label.into()).color(t.muted).size(12.));
}
fn focus_ring(ui: &egui::Ui, response: &egui::Response, radius: u8) {
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect.expand(2.),
            radius,
            Stroke::new(2., ui.visuals().selection.bg_fill),
            egui::StrokeKind::Outside,
        );
    }
}

#[derive(Clone, Copy)]
pub enum Icon {
    Home,
    Brush,
    Disk,
    Duplicate,
    Programs,
    Browser,
    Update,
    Driver,
    Startup,
    History,
    Settings,
}

pub fn section_navigation(
    ui: &mut egui::Ui,
    label: &str,
    selected: bool,
    enabled: bool,
    t: Tokens,
) -> bool {
    let response = ui
        .add_enabled_ui(enabled, |ui| {
            ui.spacing_mut().button_padding = Vec2::new(8., 6.);
            ui.add_sized(
                Vec2::new(ui.available_width(), 30.),
                egui::Button::new((
                    RichText::new(label)
                        .family(if selected {
                            semibold()
                        } else {
                            FontFamily::Proportional
                        })
                        .size(12.)
                        .color(if selected { t.foreground } else { t.muted }),
                    egui::Atom::grow(),
                ))
                .wrap_mode(egui::TextWrapMode::Truncate)
                .fill(if selected {
                    t.tint
                } else {
                    Color32::TRANSPARENT
                })
                .stroke(Stroke::NONE)
                .corner_radius(6),
            )
        })
        .inner;
    focus_ring(ui, &response, 8);
    response.on_hover_text(label).clicked()
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
    let id = ui.make_persistent_id(("navigation-icon", label));
    let colour = t.foreground;
    let atoms = (
        egui::Atom::custom(id, Vec2::splat(20.)),
        RichText::new(if compact { "" } else { label })
            .family(semibold())
            .color(colour),
        egui::Atom::grow(),
    );
    let response = ui
        .add_enabled_ui(enabled, |ui| {
            let button = if compact {
                ui.spacing_mut().button_padding = Vec2::new(6., 6.);
                egui::Button::new(egui::Atom::custom(id, Vec2::splat(20.))).gap(0.)
            } else {
                egui::Button::new(atoms).gap(12.)
            };
            button
                .selected(selected)
                .fill(if selected {
                    t.tint
                } else {
                    Color32::TRANSPARENT
                })
                .stroke(Stroke::NONE)
                .corner_radius(6)
                .min_size(Vec2::new(ui.available_width(), CONTROL_HEIGHT))
                .atom_ui(ui)
        })
        .inner;
    if compact {
        response.widget_info(|| {
            egui::WidgetInfo::selected(egui::WidgetType::Button, enabled, selected, label)
        });
    }
    if let Some(rect) = response.rect(id) {
        paint_icon(
            ui.painter(),
            rect,
            icon,
            if enabled { colour } else { t.muted },
        );
    }
    focus_ring(ui, &response.response, 8);
    record_control(
        ui,
        if compact {
            "rail-navigation"
        } else {
            "navigation"
        },
        response.response.rect,
        6,
    );
    response.response.on_hover_text(label).clicked()
}

pub fn paint_icon(p: &egui::Painter, rect: egui::Rect, icon: Icon, colour: Color32) {
    let point = |x: f32, y: f32| rect.min + Vec2::new(x, y) * (rect.width() / 20.);
    let stroke = Stroke::new(1.6, colour);
    let line = |coords: &[(f32, f32)]| {
        p.add(egui::Shape::line(
            coords.iter().map(|&(x, y)| point(x, y)).collect(),
            stroke,
        ))
    };
    match icon {
        Icon::Duplicate => {
            line(&[(7., 2.), (17., 2.), (17., 14.)]);
            line(&[(3., 6.), (13., 6.), (13., 18.), (3., 18.), (3., 6.)]);
            line(&[(6., 10.), (10., 10.)]);
            line(&[(6., 13.), (10., 13.)]);
        }
        Icon::Programs => {
            line(&[(2., 3.), (18., 3.), (18., 15.), (2., 15.), (2., 3.)]);
            line(&[(2., 7.), (18., 7.)]);
            line(&[(14., 11.), (14., 19.)]);
            line(&[(11., 16.), (14., 19.), (17., 16.)]);
        }
        Icon::Browser => {
            line(&[(2., 3.), (18., 3.), (18., 17.), (2., 17.), (2., 3.)]);
            line(&[(2., 7.), (18., 7.)]);
            p.circle_filled(point(5., 5.), rect.width() * 0.035, colour);
            p.circle_filled(point(8., 5.), rect.width() * 0.035, colour);
            line(&[(12., 10.), (12., 15.), (14., 13.), (17., 14.)]);
        }
        Icon::Update => {
            line(&[(2., 4.), (18., 4.), (18., 15.), (2., 15.), (2., 4.)]);
            line(&[(5., 18.), (15., 18.)]);
            line(&[(10., 15.), (10., 18.)]);
            line(&[(5., 12.), (8., 9.), (11., 11.), (15., 7.)]);
            line(&[(12., 7.), (15., 7.), (15., 10.)]);
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
            line(&[(6., 9.), (13., 2.), (18., 7.), (11., 14.)]);
            line(&[
                (6., 9.),
                (11., 14.),
                (7., 18.),
                (2., 18.),
                (2., 13.),
                (6., 9.),
            ]);
            line(&[(4., 16.), (6., 14.)]);
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
        Icon::Settings => {
            p.circle_stroke(point(10., 10.), rect.width() * 0.15, stroke);
            p.circle_stroke(point(10., 10.), rect.width() * 0.33, stroke);
            for angle in 0..8 {
                let a = angle as f32 * std::f32::consts::FRAC_PI_4;
                let direction = Vec2::angled(a);
                p.line_segment(
                    [
                        point(10., 10.) + direction * 7.,
                        point(10., 10.) + direction * 9.,
                    ],
                    stroke,
                );
            }
        }
    }
}
