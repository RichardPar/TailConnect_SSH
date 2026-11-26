//! tc-win: the Windows app, shipped as TailConnectSSH.exe. See app.rs.
//!
//! Built with `cargo build --release --target x86_64-pc-windows-gnu
//! --features wingui`.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod app;

#[cfg(windows)]
fn main() {
    app::main()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("tc-win is the Windows app (TailConnectSSH.exe); on Linux, use tcs-gui and tcs-tray");
    std::process::exit(1);
}
