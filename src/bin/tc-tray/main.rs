//! tc-tray (installed as `tcs-tray`): the Linux panel icon and menu. See
//! linux.rs. (On Windows the tray icon is part of the app, tc-win.)

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    linux::main().await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tcs-tray is for Linux desktops; on Windows, the tray icon is part of TailConnectSSH.exe");
    std::process::exit(1);
}
