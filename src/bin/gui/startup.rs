//! Startup failures go to a log file and, on Windows, a native dialog.
//!
//! eframe reports a renderer failure with `log::error!` and returns it.
//! Nothing in this process was listening, and a double-clicked console
//! window closes with the process, so the failure was invisible.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SMOKE: AtomicBool = AtomicBool::new(false);
static LOG_LOCK: Mutex<()> = Mutex::new(());

pub fn smoke_flag(args: impl IntoIterator<Item = impl AsRef<str>>) -> bool {
    args.into_iter().any(|arg| {
        let arg = arg.as_ref();
        arg == "--smoke" || arg == "--self-test"
    })
}

pub fn smoke_requested() -> bool {
    SMOKE.load(Ordering::Relaxed)
}

pub fn install(smoke: bool) {
    SMOKE.store(smoke, Ordering::Relaxed);
    log::set_max_level(log::LevelFilter::Warn);
    let _ = log::set_boxed_logger(Box::new(FileLog));
    std::panic::set_hook(Box::new(|info| {
        let message = panic_message(info);
        write_log(&message);
        show_dialog("Chia Vault Recover", &message);
    }));
}

pub fn log_path() -> PathBuf {
    log_path_from(std::env::var_os("LOCALAPPDATA").as_deref())
}

pub fn write_log(message: &str) {
    let _guard = LOG_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let line = format!("{} {message}", utc_stamp());
    eprintln!("{line}");
    let path = log_path();
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{line}");
    }
}

pub fn mark_smoke_frame() {
    static ONCE: AtomicBool = AtomicBool::new(false);
    if ONCE.swap(true, Ordering::Relaxed) {
        return;
    }
    write_log("smoke: first frame");
}

pub fn fail(message: &str) -> ! {
    write_log(message);
    show_dialog("Chia Vault Recover", message);
    std::process::exit(1);
}

fn log_path_from(local_app_data: Option<&std::ffi::OsStr>) -> PathBuf {
    if let Some(dir) = local_app_data
        .map(Path::new)
        .filter(|dir| !dir.as_os_str().is_empty())
    {
        return dir.join("chia-vault-recover").join("gui.log");
    }
    chia_vault_recover::app_dir().join("gui.log")
}

fn panic_message(info: &std::panic::PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    let text = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload");
    match info.location() {
        Some(location) => format!("panic at {location}: {text}"),
        None => format!("panic: {text}"),
    }
}

fn dialog_suppressed() -> bool {
    smoke_requested() || std::env::var_os("CI").is_some()
}

fn dialog_body(message: &str) -> String {
    const MAX_CHARS: usize = 1200;
    let count = message.chars().count();
    if count <= MAX_CHARS {
        return message.to_string();
    }
    let end = message
        .char_indices()
        .nth(MAX_CHARS)
        .map(|(index, _)| index)
        .unwrap_or(message.len());
    format!(
        "{}\n…\nThe full error is in:\n{}",
        &message[..end],
        log_path().display()
    )
}

fn show_dialog(title: &str, message: &str) {
    if dialog_suppressed() {
        return;
    }
    show_native_dialog(title, &dialog_body(message));
}

#[cfg(windows)]
fn show_native_dialog(title: &str, message: &str) {
    let title = wide(title);
    let message = wide(message);
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            windows_sys::Win32::UI::WindowsAndMessaging::MB_OK
                | windows_sys::Win32::UI::WindowsAndMessaging::MB_ICONERROR
                | windows_sys::Win32::UI::WindowsAndMessaging::MB_SETFOREGROUND,
        );
    }
}

#[cfg(not(windows))]
fn show_native_dialog(_title: &str, _message: &str) {}

#[cfg(windows)]
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

struct FileLog;

impl log::Log for FileLog {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            write_log(&format!("{}: {}", record.level(), record.args()));
        }
    }

    fn flush(&self) {}
}

fn utc_stamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let tod = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Days since the Unix epoch to a civil year, month, and day (Howard Hinnant).
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year as i32, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::{civil_from_days, dialog_body, log_path_from, smoke_flag};
    use std::path::Path;

    #[test]
    fn smoke_flag_accepts_the_two_spellings() {
        assert!(smoke_flag(["--smoke"]));
        assert!(smoke_flag(["--self-test"]));
        assert!(smoke_flag(["chia-vault-recover-gui", "--smoke"]));
        assert!(!smoke_flag(["--help"]));
        assert!(!smoke_flag(["--smoke-test"]));
    }

    #[test]
    fn log_path_prefers_local_app_data() {
        let path = log_path_from(Some(Path::new(r"C:\Users\me\AppData\Local").as_os_str()));
        assert_eq!(
            path,
            Path::new(r"C:\Users\me\AppData\Local")
                .join("chia-vault-recover")
                .join("gui.log")
        );
    }

    #[test]
    fn empty_local_app_data_uses_the_app_dir() {
        assert_eq!(
            log_path_from(Some(std::ffi::OsStr::new(""))),
            chia_vault_recover::app_dir().join("gui.log")
        );
        assert_eq!(
            log_path_from(None),
            chia_vault_recover::app_dir().join("gui.log")
        );
    }

    #[test]
    fn civil_dates_match_the_unix_epoch() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_735), (2026, 10, 9));
    }

    #[test]
    fn dialog_body_keeps_short_text_and_points_at_the_log() {
        assert_eq!(dialog_body("wgpu failed"), "wgpu failed");
        let long = "x".repeat(1300);
        let body = dialog_body(&long);
        assert!(body.contains("The full error is in:"));
        assert!(body.contains("gui.log"));
        assert!(body.chars().count() < long.chars().count() + 200);
    }
}
