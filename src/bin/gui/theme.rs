//! System light/dark theme with Chia green accents.

use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Stroke, Style, TextStyle, Theme, Visuals,
};

/// Chia brand green (approx. #3AAC59).
pub const CHIA_GREEN: Color32 = Color32::from_rgb(0x3A, 0xAC, 0x59);
pub const CHIA_GREEN_ACTIVE: Color32 = Color32::from_rgb(0x28, 0x7E, 0x3F);
pub const DANGER: Color32 = Color32::from_rgb(0xC4, 0x3C, 0x3C);

/// Follow the OS theme and install accented light/dark visuals.
pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::System);
    ctx.set_visuals_of(Theme::Light, accented(Visuals::light()));
    ctx.set_visuals_of(Theme::Dark, accented(Visuals::dark()));

    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.spacing.button_padding = egui::vec2(14.0, 8.0);
        style.spacing.window_margin = egui::Margin::same(16);
        style.spacing.indent = 18.0;
        bump_text(style);
    });
}

fn bump_text(style: &mut Style) {
    use FontFamily::Proportional;
    use TextStyle::*;

    style
        .text_styles
        .insert(Heading, FontId::new(24.0, Proportional));
    style
        .text_styles
        .insert(Body, FontId::new(15.0, Proportional));
    style
        .text_styles
        .insert(Button, FontId::new(15.0, Proportional));
    style
        .text_styles
        .insert(Small, FontId::new(13.0, Proportional));
    style
        .text_styles
        .insert(Monospace, FontId::new(13.0, FontFamily::Monospace));
}

fn accented(mut visuals: Visuals) -> Visuals {
    visuals.selection.bg_fill = CHIA_GREEN;
    // Selected text must contrast with the green fill (was green-on-green).
    visuals.selection.stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.hyperlink_color = CHIA_GREEN;
    // Default weak text (~60% alpha) disappears on light cards; keep secondary copy readable.
    visuals.weak_text_alpha = 0.88;
    visuals.weak_text_color = Some(if visuals.dark_mode {
        Color32::from_rgb(0xB8, 0xC0, 0xC8)
    } else {
        Color32::from_rgb(0x3D, 0x47, 0x54)
    });
    visuals.widgets.active.bg_fill = CHIA_GREEN_ACTIVE;
    visuals.widgets.hovered.bg_fill = if visuals.dark_mode {
        Color32::from_rgb(0x2A, 0x3A, 0x30)
    } else {
        Color32::from_rgb(0xE8, 0xF5, 0xEC)
    };
    visuals.widgets.open.bg_fill = if visuals.dark_mode {
        Color32::from_rgb(0x2A, 0x3A, 0x30)
    } else {
        Color32::from_rgb(0xE8, 0xF5, 0xEC)
    };
    visuals.window_corner_radius = CornerRadius::same(8);
    visuals.menu_corner_radius = CornerRadius::same(8);
    visuals
}

/// Secondary / explanatory copy — uses theme weak color (tuned for contrast).
pub fn muted(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).weak()
}

/// Filled primary action (Start / Finish / Look up).
pub fn primary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(egui::RichText::new(label).color(Color32::WHITE).strong())
            .fill(CHIA_GREEN)
            .stroke(Stroke::NONE)
            .corner_radius(CornerRadius::same(6))
            .min_size(egui::vec2(140.0, 36.0)),
    )
}

/// Outline / gray secondary action.
pub fn secondary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(label)
            .corner_radius(CornerRadius::same(6))
            .min_size(egui::vec2(120.0, 32.0)),
    )
}

/// Card frame for vault summary / form sections.
pub fn card_frame(ui: &egui::Ui) -> egui::Frame {
    let visuals = ui.visuals();
    let fill = if visuals.dark_mode {
        Color32::from_rgb(0x2A, 0x2A, 0x2E)
    } else {
        Color32::from_rgb(0xF4, 0xF6, 0xF5)
    };
    let stroke = if visuals.dark_mode {
        Color32::from_rgb(0x3A, 0x3A, 0x40)
    } else {
        Color32::from_rgb(0xD8, 0xDE, 0xDA)
    };
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, stroke))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(egui::Margin::same(14))
}

pub fn status_frame(ui: &egui::Ui, is_error: bool) -> egui::Frame {
    let dark = ui.visuals().dark_mode;
    let fill = if is_error {
        if dark {
            Color32::from_rgb(0x3A, 0x22, 0x22)
        } else {
            Color32::from_rgb(0xFD, 0xEB, 0xEB)
        }
    } else if dark {
        Color32::from_rgb(0x22, 0x32, 0x28)
    } else {
        Color32::from_rgb(0xE8, 0xF5, 0xEC)
    };
    egui::Frame::new()
        .fill(fill)
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::same(12))
}
