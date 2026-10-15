use super::theme::{self, Tokens};
use dcleaner::domain::CleanupResult;
use eframe::egui::{self, Align, Color32, FontId, Layout, RichText, Stroke, Vec2};

use chrono::{Datelike, NaiveDate};

const MONTH_COUNT: usize = 6;
const MAX_HISTORY_RECORDS: usize = 100;
const CHART_HEIGHT: f32 = 126.0;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActivitySummary {
    total_bytes: Option<u64>,
    total_files: Option<u64>,
    monthly_bytes: [u64; MONTH_COUNT],
    monthly_records: [usize; MONTH_COUNT],
    months: [NaiveDate; MONTH_COUNT],
    record_count: usize,
    invalid_dates: usize,
    overflowed: bool,
    monthly_overflowed: bool,
    too_many_records: bool,
}

fn month_start(date: NaiveDate) -> NaiveDate {
    NaiveDate::from_ymd_opt(date.year(), date.month(), 1)
        .expect("a valid date always has a valid first-of-month date")
}

fn shift_month(date: NaiveDate, offset: i32) -> NaiveDate {
    let index = date.year() * 12 + date.month() as i32 - 1 + offset;
    let year = index.div_euclid(12);
    let month = index.rem_euclid(12) as u32 + 1;
    NaiveDate::from_ymd_opt(year, month, 1)
        .expect("shifted month remains within chrono's supported date range")
}

fn aggregate(history: &[CleanupResult], today: NaiveDate) -> ActivitySummary {
    let current_month = month_start(today);
    let months = std::array::from_fn(|index| {
        shift_month(current_month, index as i32 - (MONTH_COUNT as i32 - 1))
    });
    let mut summary = ActivitySummary {
        total_bytes: Some(0),
        total_files: Some(0),
        monthly_bytes: [0; MONTH_COUNT],
        monthly_records: [0; MONTH_COUNT],
        months,
        record_count: history.len(),
        invalid_dates: 0,
        overflowed: false,
        monthly_overflowed: false,
        too_many_records: history.len() > MAX_HISTORY_RECORDS,
    };

    if summary.too_many_records {
        summary.total_bytes = None;
        summary.total_files = None;
        return summary;
    }

    for record in history {
        summary.total_bytes = summary
            .total_bytes
            .and_then(|total| total.checked_add(record.bytes));
        summary.total_files = summary
            .total_files
            .and_then(|total| total.checked_add(u64::try_from(record.files).ok()?));

        let parsed = chrono::DateTime::parse_from_rfc3339(&record.date);
        let Some(date) = parsed.ok().map(|date| date.date_naive()) else {
            summary.invalid_dates = summary.invalid_dates.saturating_add(1);
            continue;
        };
        let date_month = date.year() * 12 + date.month() as i32 - 1;
        let first_month = months[0].year() * 12 + months[0].month() as i32 - 1;
        let index = date_month - first_month;
        if !(0..MONTH_COUNT as i32).contains(&index) {
            continue;
        }
        let index = index as usize;
        summary.monthly_records[index] = summary.monthly_records[index].saturating_add(1);
        match summary.monthly_bytes[index].checked_add(record.bytes) {
            Some(bytes) => summary.monthly_bytes[index] = bytes,
            None => summary.monthly_overflowed = true,
        }
    }
    summary.overflowed |= summary.total_bytes.is_none() || summary.total_files.is_none();
    summary
}

/// Draws a six-month cleanup activity summary. Returns `true` when the user
/// selects All statistics. `today` makes month selection deterministic.
pub fn show(
    ui: &mut egui::Ui,
    t: Tokens,
    history: &[CleanupResult],
    history_readable: bool,
    today: NaiveDate,
) -> bool {
    let summary = history_readable.then(|| aggregate(history, today));
    ui.label(
        RichText::new("Here’s what you’ve cleaned so far")
            .family(theme::semibold())
            .size(theme::FONT_CAPTION)
            .color(t.foreground),
    );
    ui.add_space(8.0);

    let all_statistics_clicked = if ui.available_width() >= 520.0 {
        ui.horizontal_top(|ui| {
            let gap = 24.0_f32;
            let layout_gap = ui.spacing().item_spacing.x;
            let chart_width = (ui.available_width() - 220.0 - gap).max(180.0);
            let clicked = ui
                .allocate_ui_with_layout(
                    Vec2::new(220.0, 0.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        ui.set_min_width(220.);
                        ui.set_max_width(220.);
                        render_totals(ui, t, summary.as_ref(), history_readable)
                    },
                )
                .inner;
            ui.add_space((gap - layout_gap).max(0.0));
            ui.allocate_ui_with_layout(
                Vec2::new(chart_width, 0.0),
                Layout::top_down(Align::Min),
                |ui| render_chart(ui, t, summary.as_ref(), history_readable),
            );
            clicked
        })
        .inner
    } else {
        let clicked = render_totals(ui, t, summary.as_ref(), history_readable);
        ui.add_space(12.0);
        ui.separator();
        ui.add_space(10.0);
        render_chart(ui, t, summary.as_ref(), history_readable);
        clicked
    };

    if let Some(summary) = &summary {
        if summary.invalid_dates > 0 {
            ui.add_space(6.0);
            ui.label(
                RichText::new(format!(
                    "{} record(s) have an invalid date and are omitted from the chart.",
                    summary.invalid_dates
                ))
                .size(theme::FONT_CAPTION)
                .color(t.muted)
                .line_height(Some(16.0)),
            );
        }
        if summary.too_many_records {
            ui.add_space(6.0);
            ui.label(
                RichText::new("Cleanup history exceeds the supported display limit.")
                    .size(theme::FONT_CAPTION)
                    .color(t.muted)
                    .line_height(Some(16.0)),
            );
        }
        if summary.overflowed || summary.monthly_overflowed {
            ui.add_space(6.0);
            ui.label(
                RichText::new("A total exceeded the supported numeric range and is unavailable.")
                    .size(theme::FONT_CAPTION)
                    .color(t.muted)
                    .line_height(Some(16.0)),
            );
        }
    }

    all_statistics_clicked
}

fn render_totals(
    ui: &mut egui::Ui,
    t: Tokens,
    summary: Option<&ActivitySummary>,
    history_readable: bool,
) -> bool {
    ui.vertical(|ui| {
        let (bytes, bytes_label, files, files_label) = if !history_readable {
            (
                "Unavailable".to_owned(),
                "space recovered",
                "Unavailable".to_owned(),
                "files moved to Trash",
            )
        } else if let Some(summary) = summary {
            if summary.too_many_records {
                (
                    "Unavailable".to_owned(),
                    "space recovered",
                    "Unavailable".to_owned(),
                    "files moved to Trash",
                )
            } else {
                (
                    summary
                        .total_bytes
                        .map(format_bytes)
                        .unwrap_or_else(|| "Unavailable".into()),
                    "of space",
                    summary
                        .total_files
                        .map(format_count)
                        .unwrap_or_else(|| "Unavailable".into()),
                    "items moved to Trash",
                )
            }
        } else {
            (
                "Unavailable".to_owned(),
                "space recovered",
                "Unavailable".to_owned(),
                "files moved to Trash",
            )
        };

        metric_row(ui, t, &bytes, bytes_label, t.attention);
        ui.add_space(6.0);
        metric_row(ui, t, &files, files_label, t.primary);
        ui.add_space(10.0);
        theme::secondary(ui, "All statistics", true)
    })
    .inner
}

fn metric_row(ui: &mut egui::Ui, t: Tokens, value: &str, label: &str, color: Color32) {
    ui.horizontal(|ui| {
        let (dot, _) = ui.allocate_exact_size(Vec2::splat(10.0), egui::Sense::hover());
        ui.painter().circle_filled(dot.center(), 4.0, color);
        ui.label(
            RichText::new(value)
                .family(theme::semibold())
                .size(theme::FONT_TITLE)
                .color(t.foreground),
        );
        theme::muted(ui, label, t);
    });
}

fn render_chart(
    ui: &mut egui::Ui,
    t: Tokens,
    summary: Option<&ActivitySummary>,
    history_readable: bool,
) {
    let width = ui.available_width().max(1.0);
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(width, CHART_HEIGHT), egui::Sense::hover());
    let painter = ui.painter().with_clip_rect(rect);
    let x_inset = 16.0_f32.min(rect.width() / 2.0);
    let plot = egui::Rect::from_min_max(
        rect.left_top() + Vec2::new(x_inset, 12.0),
        rect.right_bottom() - Vec2::new(x_inset, 28.0),
    );
    for index in 0..MONTH_COUNT {
        let x = plot.left() + plot.width() * index as f32 / (MONTH_COUNT - 1) as f32;
        painter.vline(
            x,
            plot.top()..=plot.bottom(),
            Stroke::new(1.0, t.border.gamma_multiply(0.45)),
        );
    }

    let summary = summary.filter(|_| history_readable);
    let has_period_records =
        summary.is_some_and(|summary| summary.monthly_records.iter().any(|&count| count > 0));
    let chart_available = summary.is_some_and(|summary| !summary.too_many_records);
    let chart_overflowed = summary.is_some_and(|summary| summary.monthly_overflowed);

    if !history_readable {
        centered_chart_message(&painter, plot, "Cleanup history unavailable", t.muted);
    } else if summary.is_some_and(|summary| summary.too_many_records) {
        centered_chart_message(&painter, plot, "History exceeds display limit", t.muted);
    } else if summary.is_none_or(|summary| summary.monthly_records.iter().all(|&count| count == 0))
    {
        let text = if summary.is_some_and(|summary| summary.record_count == 0) {
            "No cleanup records yet"
        } else {
            "No cleanup records in this period"
        };
        centered_chart_message(&painter, plot, text, t.muted);
    } else if chart_overflowed {
        centered_chart_message(&painter, plot, "Chart total unavailable", t.muted);
    } else if let Some(summary) = summary.filter(|_| chart_available) {
        let peak = summary.monthly_bytes.iter().copied().max().unwrap_or(0);
        let denominator = peak.max(1) as f64;
        let bottom = plot.bottom();
        let points: Vec<_> = summary
            .monthly_bytes
            .iter()
            .enumerate()
            .map(|(index, &value)| {
                let x = plot.left()
                    + plot.width() * index as f32 / (MONTH_COUNT.saturating_sub(1) as f32);
                let ratio = (value as f64 / denominator).clamp(0.0, 1.0) as f32;
                egui::pos2(x, bottom - ratio * plot.height())
            })
            .collect();

        if peak > 0 {
            for index in 0..points.len().saturating_sub(1) {
                let area = vec![
                    points[index],
                    points[index + 1],
                    egui::pos2(points[index + 1].x, bottom),
                    egui::pos2(points[index].x, bottom),
                ];
                painter.add(egui::Shape::convex_polygon(
                    area,
                    Color32::from_rgba_unmultiplied(
                        t.primary.r(),
                        t.primary.g(),
                        t.primary.b(),
                        38,
                    ),
                    Stroke::NONE,
                ));
            }
        }
        painter.add(egui::Shape::line(
            points.clone(),
            Stroke::new(2.0, t.primary),
        ));
        if let Some(pointer) = response.hover_pos() {
            let nearest = points.iter().enumerate().min_by(|(_, a), (_, b)| {
                (a.x - pointer.x).abs().total_cmp(&(b.x - pointer.x).abs())
            });
            if let Some((index, _)) = nearest {
                let _ = response.clone().on_hover_text(format!(
                    "{} · {} recovered",
                    summary.months[index].format("%B %Y"),
                    format_bytes(summary.monthly_bytes[index])
                ));
            }
        }

        if peak == 0 && has_period_records {
            ui.add_space(4.0);
            theme::muted(ui, "No space was recovered in this period.", t);
        }
    } else {
        centered_chart_message(&painter, plot, "No cleanup records in this period", t.muted);
    }

    if history_readable {
        if let Some(summary) = summary.filter(|summary| !summary.too_many_records) {
            for (index, month) in summary.months.iter().enumerate() {
                let x = plot.left()
                    + plot.width() * index as f32 / (MONTH_COUNT.saturating_sub(1) as f32);
                painter.text(
                    egui::pos2(x, rect.bottom() - 12.0),
                    egui::Align2::CENTER_CENTER,
                    month.format("%b").to_string(),
                    FontId::proportional(theme::FONT_CAPTION),
                    t.muted,
                );
            }
        }
    }
}

fn centered_chart_message(
    painter: &egui::Painter,
    rect: egui::Rect,
    message: &str,
    color: Color32,
) {
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        message,
        FontId::proportional(theme::FONT_BODY),
        color,
    );
}

fn format_count(value: u64) -> String {
    let mut output = String::new();
    let digits = value.to_string();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(digit);
    }
    output
}

fn format_bytes(bytes: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", units[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn result(date: &str, files: usize, bytes: u64) -> CleanupResult {
        CleanupResult {
            id: Uuid::new_v4(),
            date: date.into(),
            files,
            bytes,
            ..CleanupResult::default()
        }
    }

    #[test]
    fn aggregates_actual_confirmed_bytes_and_files_by_month() {
        let history = vec![
            result("2026-06-01T10:00:00+08:00", 2, 1_024),
            result("2026-06-30T23:59:00-07:00", 3, 2_048),
            result("2026-05-10T09:00:00Z", 1, 4_096),
            result("2025-12-31T23:00:00Z", 5, 8_192),
        ];
        let summary = aggregate(&history, NaiveDate::from_ymd_opt(2026, 6, 15).unwrap());

        assert_eq!(summary.total_bytes, Some(15_360));
        assert_eq!(summary.total_files, Some(11));
        assert_eq!(
            summary.months[0],
            NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()
        );
        assert_eq!(summary.monthly_bytes, [0, 0, 0, 0, 4_096, 3_072]);
        assert_eq!(summary.monthly_records, [0, 0, 0, 0, 1, 2]);
        assert!(!summary.too_many_records);
    }

    #[test]
    fn invalid_dates_still_count_in_totals_but_are_not_plotted() {
        let history = vec![
            result("not-a-date", 1, 500),
            result("2026-06-14T12:00:00Z", 1, 700),
        ];
        let summary = aggregate(&history, NaiveDate::from_ymd_opt(2026, 6, 15).unwrap());

        assert_eq!(summary.total_bytes, Some(1_200));
        assert_eq!(summary.total_files, Some(2));
        assert_eq!(summary.invalid_dates, 1);
        assert_eq!(summary.monthly_bytes[5], 700);
        assert_eq!(summary.monthly_records[5], 1);
    }

    #[test]
    fn checked_aggregates_do_not_report_wrapped_totals() {
        let history = vec![
            result("2026-06-01T00:00:00Z", 1, u64::MAX),
            result("2026-06-02T00:00:00Z", 1, 1),
        ];
        let summary = aggregate(&history, NaiveDate::from_ymd_opt(2026, 6, 15).unwrap());

        assert_eq!(summary.total_bytes, None);
        assert!(summary.overflowed);
        assert_eq!(summary.monthly_bytes[5], u64::MAX);
    }

    #[test]
    fn display_limit_fails_closed_instead_of_showing_a_partial_total() {
        let history = vec![result("2026-06-01T00:00:00Z", 1, 1); MAX_HISTORY_RECORDS + 1];
        let summary = aggregate(&history, NaiveDate::from_ymd_opt(2026, 6, 15).unwrap());

        assert!(summary.too_many_records);
        assert_eq!(summary.total_bytes, None);
        assert_eq!(summary.total_files, None);
        assert_eq!(summary.monthly_records, [0; MONTH_COUNT]);
    }

    #[test]
    fn calendar_window_crosses_year_boundary_deterministically() {
        let summary = aggregate(&[], NaiveDate::from_ymd_opt(2026, 2, 1).unwrap());
        let expected = [
            (2025, 9),
            (2025, 10),
            (2025, 11),
            (2025, 12),
            (2026, 1),
            (2026, 2),
        ];
        for (month, (year, number)) in summary.months.iter().zip(expected) {
            assert_eq!((month.year(), month.month()), (year, number));
        }
    }
}
