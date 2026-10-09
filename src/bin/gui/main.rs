//! Address-first egui GUI for vault recovery (wizard).

mod app;
mod session;
mod startup;
mod theme;

use std::sync::Arc;

use eframe::egui;

const APP_NAME: &str = "Chia Vault Recover";

fn app_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../../../assets/icon-1024.png"))
        .expect("embedded app icon is a valid PNG")
}

fn main() {
    let smoke = startup::smoke_flag(std::env::args().skip(1));
    startup::install(smoke);
    startup::write_log(&format!("starting (log {})", startup::log_path().display()));
    if let Err(err) = start_gui() {
        startup::fail(&err);
    }
}

/// wgpu first (hardware, then a software adapter), then OpenGL.
///
/// `run_native` returns the surface/device error instead of keeping the
/// process alive, and the window already exists by then. Each attempt gets a
/// fresh closure because eframe consumes the app creator.
fn start_gui() -> Result<(), String> {
    let attempts = [
        Attempt {
            renderer: eframe::Renderer::Wgpu,
            software_only: false,
        },
        Attempt {
            renderer: eframe::Renderer::Wgpu,
            software_only: true,
        },
        Attempt {
            renderer: eframe::Renderer::Glow,
            software_only: false,
        },
    ];
    let mut errors = Vec::new();
    for attempt in attempts {
        let label = attempt.label();
        startup::write_log(&format!("trying {label}"));
        match run_attempt(attempt) {
            Ok(()) => {
                startup::write_log(&format!("{label} exited cleanly"));
                return Ok(());
            }
            Err(err) => {
                let message = format!("{label} failed: {err}");
                startup::write_log(&message);
                errors.push(message);
            }
        }
    }
    Err(format!(
        "Chia Vault Recover could not open a window.\n\n{}\n\nDetails were saved to:\n{}",
        errors.join("\n\n"),
        startup::log_path().display()
    ))
}

#[derive(Clone, Copy)]
struct Attempt {
    renderer: eframe::Renderer,
    software_only: bool,
}

impl Attempt {
    fn label(self) -> &'static str {
        match (self.renderer, self.software_only) {
            (eframe::Renderer::Wgpu, false) => "wgpu",
            (eframe::Renderer::Wgpu, true) => "wgpu software",
            (eframe::Renderer::Glow, _) => "opengl",
        }
    }
}

fn run_attempt(attempt: Attempt) -> eframe::Result<()> {
    eframe::run_native(
        APP_NAME,
        native_options(attempt),
        Box::new(|cc| {
            theme::apply(&cc.egui_ctx);
            Ok(Box::new(app::App::new()))
        }),
    )
}

fn native_options(attempt: Attempt) -> eframe::NativeOptions {
    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([720.0, 780.0])
            .with_title(APP_NAME)
            .with_icon(app_icon()),
        // A renderer error must come back to `main`. The other setting exits
        // the process with status 0 and never returns the error.
        run_and_return: true,
        renderer: attempt.renderer,
        ..Default::default()
    };
    if attempt.renderer == eframe::Renderer::Wgpu {
        options.wgpu_options = wgpu_config(attempt.software_only);
    }
    options
}

fn wgpu_config(software_only: bool) -> eframe::egui_wgpu::WgpuConfiguration {
    let mut config = eframe::egui_wgpu::WgpuConfiguration::default();
    if let eframe::egui_wgpu::WgpuSetup::CreateNew(create) = &mut config.wgpu_setup {
        create.native_adapter_selector = Some(Arc::new(move |adapters, surface| {
            select_adapter(adapters, surface, software_only)
        }));
    }
    config
}

/// Prefer a discrete or integrated GPU that can present. A CPU adapter
/// (DirectX WARP on Windows) is last, and is the only candidate when
/// `software_only` is set.
fn select_adapter(
    adapters: &[eframe::wgpu::Adapter],
    surface: Option<&eframe::wgpu::Surface<'_>>,
    software_only: bool,
) -> Result<eframe::wgpu::Adapter, String> {
    let describe = |adapter: &eframe::wgpu::Adapter| {
        let info = adapter.get_info();
        format!(
            "{} backend={:?} type={:?}",
            info.name, info.backend, info.device_type
        )
    };
    let mut compatible: Vec<eframe::wgpu::Adapter> = adapters
        .iter()
        .filter(|adapter| {
            let info = adapter.get_info();
            if software_only && !is_software(&info) {
                return false;
            }
            surface.is_none_or(|surface| !surface.get_capabilities(adapter).formats.is_empty())
        })
        .cloned()
        .collect();
    if compatible.is_empty() {
        let listed = if adapters.is_empty() {
            "(none enumerated)".to_string()
        } else {
            adapters.iter().map(describe).collect::<Vec<_>>().join("; ")
        };
        let kind = if software_only { "software " } else { "" };
        return Err(format!(
            "no {kind}surface-compatible wgpu adapter. available: {listed}"
        ));
    }
    compatible.sort_by_key(|adapter| device_rank(adapter.get_info().device_type));
    let chosen = compatible[0].clone();
    startup::write_log(&format!("selected wgpu adapter: {}", describe(&chosen)));
    Ok(chosen)
}

fn is_software(info: &eframe::wgpu::AdapterInfo) -> bool {
    if info.device_type == eframe::wgpu::DeviceType::Cpu {
        return true;
    }
    let name = info.name.to_ascii_lowercase();
    name.contains("warp")
        || name.contains("basic render driver")
        || name.contains("swiftshader")
        || name.contains("llvmpipe")
}

fn device_rank(device_type: eframe::wgpu::DeviceType) -> u8 {
    match device_type {
        eframe::wgpu::DeviceType::DiscreteGpu => 0,
        eframe::wgpu::DeviceType::IntegratedGpu => 1,
        eframe::wgpu::DeviceType::VirtualGpu => 2,
        eframe::wgpu::DeviceType::Cpu => 4,
        _ => 3,
    }
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
