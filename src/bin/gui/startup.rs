//! Startup failures go to `gui.log` in the app directory and to an error dialog.
//!
//! eframe reports a renderer failure with `log::error!` and returns it. The GUI
//! binary has no console on Windows, so this is the record of that error.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, TryLockError};
use std::time::{SystemTime, UNIX_EPOCH};

static LOG_LOCK: Mutex<()> = Mutex::new(());

pub fn install() {
    log::set_max_level(log::LevelFilter::Info);
    let _ = log::set_boxed_logger(Box::new(FileLog));
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = panic_message(info);
        write_log(&message);
        show_dialog(&message);
        previous(info);
    }));
}

pub fn log_path() -> PathBuf {
    chia_vault_recover::app_dir().join("gui.log")
}

pub fn write_log(message: &str) {
    let _guard = match LOG_LOCK.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::WouldBlock) => return,
        Err(TryLockError::Poisoned(err)) => err.into_inner(),
    };
    let line = format!("{} {message}", unix_secs());
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

pub fn fail(message: &str) -> ! {
    write_log(message);
    show_dialog(message);
    std::process::exit(1);
}

fn panic_message(info: &std::panic::PanicHookInfo<'_>) -> String {
    let text = info.payload_as_str().unwrap_or("non-string panic payload");
    match info.location() {
        Some(location) => format!("panic at {location}: {text}"),
        None => format!("panic: {text}"),
    }
}

fn show_dialog(message: &str) {
    if std::env::var_os("CI").is_some() {
        return;
    }
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Error)
        .set_title("Chia Vault Recover")
        .set_description(message)
        .show();
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

struct FileLog;

impl log::Log for FileLog {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            write_log(&format!("{}: {}", record.level(), record.args()));
        }
    }

    fn flush(&self) {}
}
