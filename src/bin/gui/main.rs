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

const SOFTWARE_RENDERER_EXPLANATION: &str = "\
The graphics driver crashed on the last launch. This launch uses the DirectX 12 \
software renderer. Delete gui-renderer.crash in the app directory to try the \
hardware renderer again.";

/// Primary renderer, then one CPU-adapter `run_native` if that returns `Err`.
///
/// On Windows the primary instance is DirectX 12 unless `WGPU_BACKEND` is set.
/// `WGPU_POWER_PREF` still applies, because the first attempt does not install
/// an adapter selector. A native driver abort never returns here, so Windows
/// writes `gui-renderer.crash` before `run_native` and the next process skips
/// to the CPU adapter. Each call gets a new app closure because eframe consumes it.
fn start_gui(smoke: bool) -> Result<(), String> {
    let marker = read_startup_marker();
    match startup::plan_from_marker(marker.as_deref()) {
        startup::StartupPlan::Stop => Err(both_crashed_message()),
        startup::StartupPlan::Primary => {
            match run_attempt(startup::AttemptKind::Primary, false, smoke) {
                Ok(()) => Ok(()),
                Err(err) => {
                    let first = format!("{}: {err}", failure_prefix(startup::AttemptKind::Primary));
                    startup::write_log(&first);
                    run_attempt(startup::AttemptKind::Cpu, false, smoke).map_err(|second| {
                        let cpu =
                            format!("{}: {second}", failure_prefix(startup::AttemptKind::Cpu));
                        startup::write_log(&cpu);
                        format!(
                            "{first}\n\n{cpu}\n\nDetails were saved to:\n{}",
                            startup::log_path().display()
                        )
                    })
                }
            }
        }
        startup::StartupPlan::Cpu { explain } => {
            if explain {
                startup::write_log(SOFTWARE_RENDERER_EXPLANATION);
                startup::show_dialog(SOFTWARE_RENDERER_EXPLANATION);
            }
            run_attempt(startup::AttemptKind::Cpu, true, smoke).map_err(|err| {
                let cpu = format!("{}: {err}", failure_prefix(startup::AttemptKind::Cpu));
                startup::write_log(&cpu);
                format!(
                    "{cpu}\n\nDetails were saved to:\n{}",
                    startup::log_path().display()
                )
            })
        }
    }
}

fn run_attempt(
    kind: startup::AttemptKind,
    because_hardware_crash: bool,
    smoke: bool,
) -> Result<(), String> {
    arm_crash_marker(kind);
    startup::write_log(attempt_log(kind));
    let options = eframe::NativeOptions {
        wgpu_options: wgpu_config(kind == startup::AttemptKind::Cpu),
        ..Default::default()
    };
    match run(options, smoke) {
        Ok(()) => {
            finish_crash_marker(kind, because_hardware_crash, true);
            Ok(())
        }
        Err(err) => {
            finish_crash_marker(kind, because_hardware_crash, false);
            Err(err.to_string())
        }
    }
}

fn run(mut options: eframe::NativeOptions, smoke: bool) -> eframe::Result<()> {
    if let eframe::egui_wgpu::WgpuSetup::CreateNew(create) = &options.wgpu_options.wgpu_setup {
        startup::write_log(&format!(
            "creating wgpu instance backends={:?}",
            create.instance_descriptor.backends
        ));
    }
    options.viewport = egui::ViewportBuilder::default()
        .with_inner_size([720.0, 780.0])
        .with_title(APP_NAME)
        .with_icon(app_icon());
    eframe::run_native(
        APP_NAME,
        options,
        Box::new(move |cc| {
            // `Painter::set_window` configures the surface before this closure.
            startup::write_log("surface configured");
            theme::apply(&cc.egui_ctx);
            let app = app::App::new(smoke);
            startup::write_log("app created");
            Ok(Box::new(app))
        }),
    )
}

fn wgpu_config(cpu_only: bool) -> eframe::egui_wgpu::WgpuConfiguration {
    let mut config = eframe::egui_wgpu::WgpuConfiguration::default();
    let eframe::egui_wgpu::WgpuSetup::CreateNew(create) = &mut config.wgpu_setup else {
        return config;
    };
    #[cfg(windows)]
    {
        create.instance_descriptor.backends =
            windows_backends(std::env::var("WGPU_BACKEND").ok().as_deref());
    }
    if cpu_only {
        create.native_adapter_selector = Some(Arc::new(select_cpu_adapter));
    }
    let inner = Arc::clone(&create.device_descriptor);
    create.device_descriptor = Arc::new(move |adapter| {
        let info = adapter.get_info();
        startup::write_log(&format!(
            "request_device: {} backend={:?} type={:?}",
            info.name, info.backend, info.device_type
        ));
        inner(adapter)
    });
    config
}

/// Windows defaults to DX12. A non-empty `WGPU_BACKEND` list still wins.
#[cfg(any(windows, test))]
fn windows_backends(wgpu_backend: Option<&str>) -> eframe::wgpu::Backends {
    match wgpu_backend.map(eframe::wgpu::Backends::from_comma_list) {
        Some(backends) if !backends.is_empty() => backends,
        _ => eframe::wgpu::Backends::DX12,
    }
}

fn read_startup_marker() -> Option<String> {
    #[cfg(windows)]
    {
        startup::read_crash_marker()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn arm_crash_marker(kind: startup::AttemptKind) {
    #[cfg(windows)]
    {
        let marker = startup::marker_to_write(kind);
        startup::write_crash_marker(marker);
        startup::write_log(&format!("crash marker: {marker}"));
    }
    #[cfg(not(windows))]
    {
        let _ = kind;
    }
}

fn finish_crash_marker(kind: startup::AttemptKind, because_hardware_crash: bool, ok: bool) {
    let next = startup::marker_after_return(kind, because_hardware_crash, ok);
    #[cfg(windows)]
    match next {
        Some(text) => startup::write_crash_marker(text),
        None => startup::clear_crash_marker(),
    }
    #[cfg(not(windows))]
    let _ = next;
}

fn attempt_log(kind: startup::AttemptKind) -> &'static str {
    #[cfg(windows)]
    return match kind {
        startup::AttemptKind::Primary => "attempt: dx12",
        startup::AttemptKind::Cpu => "attempt: dx12-cpu",
    };
    #[cfg(not(windows))]
    return match kind {
        startup::AttemptKind::Primary => "attempt: wgpu",
        startup::AttemptKind::Cpu => "attempt: wgpu cpu",
    };
}

fn failure_prefix(kind: startup::AttemptKind) -> &'static str {
    #[cfg(windows)]
    return match kind {
        startup::AttemptKind::Primary => "dx12 failed",
        startup::AttemptKind::Cpu => "dx12-cpu failed",
    };
    #[cfg(not(windows))]
    return match kind {
        startup::AttemptKind::Primary => "wgpu failed",
        startup::AttemptKind::Cpu => "wgpu cpu failed",
    };
}

fn both_crashed_message() -> String {
    format!(
        "The graphics driver crashed on the last two launches, including the DirectX 12 software renderer.\n\nDelete gui-renderer.crash in the app directory to try again.\n\nDetails were saved to:\n{}",
        startup::log_path().display()
    )
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
    fn windows_backend_defaults_to_dx12_and_honors_wgpu_backend() {
        use eframe::wgpu::Backends;

        assert_eq!(super::windows_backends(None), Backends::DX12);
        assert_eq!(super::windows_backends(Some("")), Backends::DX12);
        assert_eq!(
            super::windows_backends(Some("not-a-backend")),
            Backends::DX12
        );
        assert_eq!(super::windows_backends(Some("dx12")), Backends::DX12);
        assert_eq!(super::windows_backends(Some("d3d12")), Backends::DX12);
        assert_eq!(super::windows_backends(Some("vulkan")), Backends::VULKAN);
        assert_eq!(super::windows_backends(Some("vk")), Backends::VULKAN);
        assert_eq!(
            super::windows_backends(Some("dx12, gl")),
            Backends::DX12 | Backends::GL
        );
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
