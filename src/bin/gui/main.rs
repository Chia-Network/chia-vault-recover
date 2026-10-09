//! Address-first egui GUI for vault recovery (wizard).
//!
//! On Windows this binary uses the GUI subsystem, so a double-click does not
//! open a console. Startup errors are written to `gui.log` and shown in a dialog.
#![cfg_attr(windows, windows_subsystem = "windows")]

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
    let smoke = std::env::args().skip(1).any(|arg| arg == "--smoke");
    startup::install();
    startup::write_log(&format!("starting (log {})", startup::log_path().display()));
    if let Err(err) = start_gui(smoke) {
        startup::fail(&err);
    }
}

/// Stock wgpu, then one more `run_native` that keeps only CPU adapters.
///
/// The first call uses [`eframe::egui_wgpu::WgpuConfiguration::default`], so
/// `WGPU_POWER_PREF` still applies. The retry runs only when that call returns
/// `Err`: a non-CPU adapter was surface-compatible and then `request_device`
/// failed. Each call gets a new app closure because eframe consumes it.
fn start_gui(smoke: bool) -> Result<(), String> {
    startup::write_log("attempt: wgpu");
    if let Err(err) = run(eframe::NativeOptions::default(), smoke) {
        let first = format!("wgpu failed: {err}");
        startup::write_log(&first);
        startup::write_log("attempt: wgpu cpu");
        let retry = eframe::NativeOptions {
            wgpu_options: cpu_wgpu_config(),
            ..Default::default()
        };
        if let Err(err) = run(retry, smoke) {
            let second = format!("wgpu cpu failed: {err}");
            startup::write_log(&second);
            return Err(format!(
                "{first}\n\n{second}\n\nDetails were saved to:\n{}",
                startup::log_path().display()
            ));
        }
    }
    Ok(())
}

fn run(mut options: eframe::NativeOptions, smoke: bool) -> eframe::Result<()> {
    options.viewport = egui::ViewportBuilder::default()
        .with_inner_size([720.0, 780.0])
        .with_title(APP_NAME)
        .with_icon(app_icon());
    eframe::run_native(
        APP_NAME,
        options,
        Box::new(move |cc| {
            theme::apply(&cc.egui_ctx);
            Ok(Box::new(app::App::new(smoke)))
        }),
    )
}

fn cpu_wgpu_config() -> eframe::egui_wgpu::WgpuConfiguration {
    let mut config = eframe::egui_wgpu::WgpuConfiguration::default();
    if let eframe::egui_wgpu::WgpuSetup::CreateNew(create) = &mut config.wgpu_setup {
        create.native_adapter_selector = Some(Arc::new(select_cpu_adapter));
    }
    config
}

fn select_cpu_adapter(
    adapters: &[eframe::wgpu::Adapter],
    surface: Option<&eframe::wgpu::Surface<'_>>,
) -> Result<eframe::wgpu::Adapter, String> {
    let listed: Vec<AdapterListing> = adapters
        .iter()
        .map(|adapter| AdapterListing {
            device_type: adapter.get_info().device_type,
            surface_compatible: surface
                .is_none_or(|surface| !surface.get_capabilities(adapter).formats.is_empty()),
        })
        .collect();
    let Some(index) = first_cpu_index(&listed) else {
        let available = if adapters.is_empty() {
            "(none enumerated)".to_string()
        } else {
            adapters
                .iter()
                .map(|adapter| {
                    let info = adapter.get_info();
                    format!(
                        "{} backend={:?} type={:?}",
                        info.name, info.backend, info.device_type
                    )
                })
                .collect::<Vec<_>>()
                .join("; ")
        };
        return Err(format!(
            "no surface-compatible CPU wgpu adapter. available: {available}"
        ));
    };
    Ok(adapters[index].clone())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AdapterListing {
    device_type: eframe::wgpu::DeviceType,
    surface_compatible: bool,
}

/// First `DeviceType::Cpu` adapter that can present. Other device types are ignored.
fn first_cpu_index(adapters: &[AdapterListing]) -> Option<usize> {
    adapters.iter().position(|adapter| {
        adapter.device_type == eframe::wgpu::DeviceType::Cpu && adapter.surface_compatible
    })
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

    #[test]
    fn cpu_selector_keeps_only_a_presentable_cpu_adapter() {
        use super::first_cpu_index;
        use eframe::wgpu::DeviceType::{Cpu, DiscreteGpu, IntegratedGpu, Other, VirtualGpu};

        let adapters = [
            listing(DiscreteGpu, true),
            listing(IntegratedGpu, true),
            listing(VirtualGpu, true),
            listing(Other, true),
            listing(Cpu, false),
            listing(Cpu, true),
        ];
        assert_eq!(first_cpu_index(&adapters), Some(5));
        assert_eq!(
            first_cpu_index(&[listing(Cpu, true), listing(Cpu, true)]),
            Some(0)
        );
        assert_eq!(first_cpu_index(&[listing(DiscreteGpu, true)]), None);
        assert_eq!(first_cpu_index(&[]), None);
    }

    fn listing(
        device_type: eframe::wgpu::DeviceType,
        surface_compatible: bool,
    ) -> super::AdapterListing {
        super::AdapterListing {
            device_type,
            surface_compatible,
        }
    }

    fn icns_chunk<'a>(chunks: &[(&'a str, &'a [u8])], ostype: &str) -> &'a [u8] {
        chunks
            .iter()
            .find(|(typ, _)| *typ == ostype)
            .unwrap_or_else(|| panic!("missing {ostype}"))
            .1
    }
}
