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

    /// 16px and 32px ICNS slots must be ARGB. PNG in icp4/icp5/icp6 is scrambled
    /// by Icon Services in Finder, Activity Monitor, and Trash.
    #[test]
    fn macos_icon_small_sizes_are_argb() {
        let bytes = include_bytes!("../../../assets/icon.icns");
        let chunks = icns_chunks(bytes);
        let types: Vec<&str> = chunks.iter().map(|(typ, _)| *typ).collect();
        for banned in ["icp4", "icp5", "icp6"] {
            assert!(!types.contains(&banned), "{banned} must not store a PNG");
        }
        for ostype in ["ic04", "ic05"] {
            let data = icns_chunk(&chunks, ostype);
            assert!(data.starts_with(b"ARGB"), "{ostype} must be ARGB");
        }
        for ostype in [
            "ic07", "ic08", "ic09", "ic10", "ic11", "ic12", "ic13", "ic14",
        ] {
            let data = icns_chunk(&chunks, ostype);
            assert!(
                data.starts_with(b"\x89PNG\r\n\x1a\n"),
                "{ostype} must be PNG"
            );
        }
    }

    fn icns_chunks(bytes: &[u8]) -> Vec<(&str, &[u8])> {
        assert!(bytes.starts_with(b"icns"), "icns magic");
        let total = u32::from_be_bytes(bytes[4..8].try_into().expect("icns length")) as usize;
        assert_eq!(total, bytes.len());
        let mut off = 8;
        let mut chunks = Vec::new();
        while off + 8 <= bytes.len() {
            let typ = std::str::from_utf8(&bytes[off..off + 4]).expect("icns type");
            let size = u32::from_be_bytes(bytes[off + 4..off + 8].try_into().expect("chunk length"))
                as usize;
            assert!(size >= 8 && off + size <= bytes.len(), "{typ} chunk size");
            chunks.push((typ, &bytes[off + 8..off + size]));
            off += size;
        }
        assert_eq!(off, bytes.len());
        chunks
    }

    fn icns_chunk<'a>(chunks: &[(&'a str, &'a [u8])], ostype: &str) -> &'a [u8] {
        chunks
            .iter()
            .find(|(typ, _)| *typ == ostype)
            .unwrap_or_else(|| panic!("missing {ostype}"))
            .1
    }
}
