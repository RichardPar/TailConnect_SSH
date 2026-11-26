//! Windows builds: embed the app icon and version details in the programs
//! (Explorer, the taskbar, the Start menu and Task Manager show them).
//! Needs MinGW's windres (mingw-w64), or $WINDRES; without it the programs
//! just get Windows' default icon.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=packaging/windows/TailConnectSSH.ico");
    println!("cargo:rerun-if-env-changed=WINDRES");
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("windows-gnu") {
        return;
    }
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let ico = root.join("packaging/windows/TailConnectSSH.ico");
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let mut nums: Vec<u32> = version.split(['.', '-']).filter_map(|p| p.parse().ok()).collect();
    nums.resize(4, 0);
    let commas = nums.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    for (bin, desc) in [
        ("tc-win", "TailConnect-SSH"),
        ("tcd", "TailConnect-SSH service"),
        ("tc", "TailConnect-SSH command line"),
    ] {
        let rc = out.join(format!("{bin}.rc"));
        let obj = out.join(format!("{bin}-res.o"));
        let text = format!(
            r#"1 ICON "{ico}"
1 VERSIONINFO
FILEVERSION {commas}
PRODUCTVERSION {commas}
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "FileDescription", "{desc}"
      VALUE "ProductName", "TailConnect-SSH"
      VALUE "FileVersion", "{version}"
      VALUE "ProductVersion", "{version}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
            ico = ico.display().to_string().replace('\\', "/"),
        );
        std::fs::write(&rc, text).unwrap();
        let windres = std::env::var("WINDRES").unwrap_or_else(|_| {
            let arch = target.split('-').next().unwrap_or("x86_64");
            format!("{arch}-w64-mingw32-windres")
        });
        let ok = std::process::Command::new(&windres)
            .arg("--input")
            .arg(&rc)
            .arg("--output")
            .arg(&obj)
            .arg("--output-format=coff")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            println!("cargo:rustc-link-arg-bin={bin}={}", obj.display());
        } else {
            println!("cargo:warning={windres} not found or failed: {bin}.exe gets the default icon");
        }
    }
}
