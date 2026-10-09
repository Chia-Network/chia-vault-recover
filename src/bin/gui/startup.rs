//! Startup failures go to `gui.log` in the app directory and to an error dialog.
//!
//! eframe reports a renderer failure with `log::error!` and returns it. The GUI
//! binary has no console on Windows, so this is the record of that error.
//! A native abort never returns, so Windows also records the attempt in
//! `gui-renderer.crash` before `run_native` and installs an exception filter.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, TryLockError};
use std::time::{SystemTime, UNIX_EPOCH};

static LOG_LOCK: Mutex<()> = Mutex::new(());
#[cfg(windows)]
static LOGGED_EXCEPTION: AtomicBool = AtomicBool::new(false);

pub fn install() {
    enable_rust_backtrace();
    #[cfg(windows)]
    install_exception_handlers();
    log::set_max_level(log::LevelFilter::Info);
    let _ = log::set_boxed_logger(Box::new(FileLog));
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = panic_message(info);
        write_log(&message);
        let backtrace = std::backtrace::Backtrace::force_capture();
        write_log(&format!("{backtrace}"));
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
    append_log_line(message);
}

pub fn fail(message: &str) -> ! {
    write_log(message);
    show_dialog(message);
    std::process::exit(1);
}

pub(crate) fn show_dialog(message: &str) {
    if std::env::var_os("CI").is_some() {
        return;
    }
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Error)
        .set_title("Chia Vault Recover")
        .set_description(message)
        .show();
}

/// Which renderer launch to attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptKind {
    Primary,
    Cpu,
}

/// What a previous process left in `gui-renderer.crash`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupPlan {
    /// No crash was recorded. Try the primary renderer.
    Primary,
    /// The primary renderer crashed. Use the CPU adapter.
    ///
    /// `explain` is set only for the launch that first notices `dx12`, so the
    /// dialog is not repeated once software rendering has succeeded.
    Cpu { explain: bool },
    /// The CPU attempt crashed too. Stop instead of looping.
    Stop,
}

/// `dx12` means the primary attempt died. `dx12-soft` means a later launch
/// should stay on the CPU adapter without asking again. `dx12-cpu` means the
/// CPU attempt itself died.
pub fn plan_from_marker(marker: Option<&str>) -> StartupPlan {
    match marker.map(str::trim) {
        Some("dx12") => StartupPlan::Cpu { explain: true },
        Some("dx12-soft") => StartupPlan::Cpu { explain: false },
        Some("dx12-cpu") => StartupPlan::Stop,
        _ => StartupPlan::Primary,
    }
}

#[cfg(any(windows, test))]
pub fn marker_to_write(kind: AttemptKind) -> &'static str {
    match kind {
        AttemptKind::Primary => "dx12",
        AttemptKind::Cpu => "dx12-cpu",
    }
}

/// Marker to persist after `run_native` returns.
///
/// `None` deletes the file. A successful CPU attempt that was entered because
/// the primary renderer had crashed stays on software (`dx12-soft`). A Rust
/// `Err` is not a native crash, so it clears the marker.
pub fn marker_after_return(
    kind: AttemptKind,
    because_hardware_crash: bool,
    ok: bool,
) -> Option<&'static str> {
    if ok && kind == AttemptKind::Cpu && because_hardware_crash {
        Some("dx12-soft")
    } else {
        None
    }
}

#[cfg(windows)]
pub fn read_crash_marker() -> Option<String> {
    let text = std::fs::read_to_string(crash_marker_path()).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(windows)]
pub fn write_crash_marker(attempt: &str) {
    let path = crash_marker_path();
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::File::create(&path) {
        Ok(mut file) => {
            let _ = writeln!(file, "{attempt}");
            let _ = file.sync_all();
        }
        Err(err) => append_log_line(&format!("crash marker write failed: {err}")),
    }
}

#[cfg(windows)]
pub fn clear_crash_marker() {
    let _ = std::fs::remove_file(crash_marker_path());
}

#[cfg(windows)]
fn crash_marker_path() -> PathBuf {
    chia_vault_recover::app_dir().join("gui-renderer.crash")
}

fn enable_rust_backtrace() {
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        // Safety: GUI startup, on the main thread, before any other thread exists.
        unsafe { std::env::set_var("RUST_BACKTRACE", "1") };
    }
}

fn panic_message(info: &std::panic::PanicHookInfo<'_>) -> String {
    let text = info.payload_as_str().unwrap_or("non-string panic payload");
    match info.location() {
        Some(location) => format!("panic at {location}: {text}"),
        None => format!("panic: {text}"),
    }
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn append_log_line(message: &str) {
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
        let _ = file.sync_all();
    }
}

/// Access violations, stack overflows, and fast-fail codes. First-chance noise
/// (C++ exceptions, thread names, `OutputDebugString`) is ignored so the
/// vectored handler can keep searching.
#[cfg(any(windows, test))]
fn is_fatal_exception(code: u32) -> bool {
    matches!(
        code,
        0xC000_0005 | // STATUS_ACCESS_VIOLATION
        0xC000_0006 | // STATUS_IN_PAGE_ERROR
        0xC000_001D | // STATUS_ILLEGAL_INSTRUCTION
        0xC000_0025 | // STATUS_NONCONTINUABLE_EXCEPTION
        0xC000_0026 | // STATUS_INVALID_DISPOSITION
        0xC000_0094 | // STATUS_INTEGER_DIVIDE_BY_ZERO
        0xC000_0096 | // STATUS_PRIVILEGED_INSTRUCTION
        0xC000_00FD | // STATUS_STACK_OVERFLOW
        0xC000_0374 | // STATUS_HEAP_CORRUPTION
        0xC000_0409 | // STATUS_STACK_BUFFER_OVERRUN (fast-fail)
        0xC000_041D | // STATUS_FATAL_USER_CALLBACK_EXCEPTION
        0x4000_0015 // STATUS_FATAL_APP_EXIT
    )
}

#[cfg(windows)]
fn install_exception_handlers() {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        AddVectoredExceptionHandler, SetUnhandledExceptionFilter,
    };
    // Safety: process startup, before other threads. The handlers only record
    // fatal codes and always continue the search.
    unsafe {
        AddVectoredExceptionHandler(1, Some(vectored_exception));
        SetUnhandledExceptionFilter(Some(unhandled_exception));
    }
}

#[cfg(windows)]
unsafe extern "system" fn vectored_exception(
    info: *mut windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    unsafe { note_exception(info.cast_const()) };
    windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_SEARCH
}

#[cfg(windows)]
unsafe extern "system" fn unhandled_exception(
    info: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    unsafe { note_exception(info) };
    windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_CONTINUE_SEARCH
}

#[cfg(windows)]
unsafe fn note_exception(
    info: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) {
    let Some(line) = (unsafe { exception_line(info) }) else {
        return;
    };
    if LOGGED_EXCEPTION.swap(true, Ordering::SeqCst) {
        return;
    }
    // Skip the log mutex: the crashed thread may already hold it.
    append_log_line(&line);
}

#[cfg(windows)]
unsafe fn exception_line(
    info: *const windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> Option<String> {
    if info.is_null() {
        return None;
    }
    let record = unsafe { (*info).ExceptionRecord };
    if record.is_null() {
        return None;
    }
    let record = unsafe { &*record };
    let code = record.ExceptionCode as u32;
    if !is_fatal_exception(code) {
        return None;
    }
    Some(format!(
        "unhandled exception code={code:#X} address={:p}",
        record.ExceptionAddress
    ))
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

#[cfg(test)]
mod tests {
    use super::{
        AttemptKind, StartupPlan, is_fatal_exception, marker_after_return, marker_to_write,
        plan_from_marker,
    };

    #[test]
    fn crash_marker_plans_the_next_launch() {
        assert_eq!(plan_from_marker(None), StartupPlan::Primary);
        assert_eq!(plan_from_marker(Some("")), StartupPlan::Primary);
        assert_eq!(plan_from_marker(Some("nope")), StartupPlan::Primary);
        assert_eq!(
            plan_from_marker(Some("dx12")),
            StartupPlan::Cpu { explain: true }
        );
        assert_eq!(
            plan_from_marker(Some(" dx12\n")),
            StartupPlan::Cpu { explain: true }
        );
        assert_eq!(
            plan_from_marker(Some("dx12-soft")),
            StartupPlan::Cpu { explain: false }
        );
        assert_eq!(plan_from_marker(Some("dx12-cpu")), StartupPlan::Stop);
    }

    #[test]
    fn marker_names_match_the_attempt_that_is_about_to_run() {
        assert_eq!(marker_to_write(AttemptKind::Primary), "dx12");
        assert_eq!(marker_to_write(AttemptKind::Cpu), "dx12-cpu");
    }

    #[test]
    fn successful_software_fallback_stays_on_software() {
        assert_eq!(marker_after_return(AttemptKind::Primary, false, true), None);
        assert_eq!(marker_after_return(AttemptKind::Cpu, false, true), None);
        assert_eq!(
            marker_after_return(AttemptKind::Cpu, true, true),
            Some("dx12-soft")
        );
        assert_eq!(marker_after_return(AttemptKind::Cpu, true, false), None);
        assert_eq!(marker_after_return(AttemptKind::Primary, true, false), None);
    }

    #[test]
    fn fatal_exception_codes_are_the_ones_that_kill_the_process() {
        assert!(is_fatal_exception(0xC000_0005));
        assert!(is_fatal_exception(0xC000_00FD));
        assert!(is_fatal_exception(0xC000_0409));
        assert!(is_fatal_exception(0x4000_0015));
        assert!(!is_fatal_exception(0xE06D_7363));
        assert!(!is_fatal_exception(0x406D_1388));
        assert!(!is_fatal_exception(0x4001_0006));
    }
}
