//! Embed the Windows executable icon. macOS and Linux pick the icon up
//! elsewhere: the `.app` bundle, and the GUI window icon at runtime.

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        embed_windows_icon();
    }
}

fn embed_windows_icon() {
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/icon.ico");
    res.compile().expect("compile Windows icon resource");
}
