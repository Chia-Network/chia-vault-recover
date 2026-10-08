//! Address-first egui GUI for vault recovery (wizard).

mod app;
mod session;
mod theme;

use eframe::egui;

fn app_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../../../assets/icon-1024.png"))
        .expect("embedded app icon is a valid PNG")
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([720.0, 780.0])
            .with_title("Chia Vault Recover")
            .with_icon(app_icon()),
        ..Default::default()
    };
    eframe::run_native(
        "Chia Vault Recover",
        options,
        Box::new(|cc| {
            theme::apply(&cc.egui_ctx);
            Ok(Box::new(app::App::new()))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::app_icon;

    #[test]
    fn app_icon_is_square_png() {
        let icon = app_icon();
        assert_eq!(icon.width, 1024);
        assert_eq!(icon.height, 1024);
        assert_eq!(icon.rgba.len(), 1024 * 1024 * 4);
    }
}
