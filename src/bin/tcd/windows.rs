//! tcd on Windows: the TailConnectSSH service, and installing it.
//!
//! `tcd install` (elevated; it asks for elevation if needed) copies tcd.exe,
//! tcs.exe, TailConnectSSH.exe and wintun.dll from its own folder to
//! Program Files\TailConnect-SSH and sets up:
//! * the TailConnectSSH service (automatic, restarted if it fails), running
//!   `tcd.exe FLAGS service`;
//! * that folder on the system PATH (for `tcs`);
//! * firewall rules: inbound to tcd.exe (direct paths from peers) and to the
//!   tunnel's addresses (peers reaching this PC's services; tcd's packet
//!   filter applies the network's rules);
//! * the app in the Start menu, at every user's sign-in, and in Settings →
//!   Apps (whose Uninstall runs `tcd uninstall`).
//!
//! Upgrading is installing again: the service keeps its flags unless new
//! ones are given. Keys and settings live in ProgramData\TailConnect-SSH,
//! readable only by SYSTEM and Administrators.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tailconnect::client::win::{is_elevated, powershell, ps_quote, run, run_elevated};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use super::Flags;

pub const SERVICE: &str = "TailConnectSSH";
const DISPLAY: &str = "TailConnect-SSH";
const APP_EXE: &str = "TailConnectSSH.exe";
/// What the installer copies (those present in its folder).
const FILES: &[&str] = &[
    "tcd.exe",
    "tcs.exe",
    APP_EXE,
    "wintun.dll",
    "TailConnectSSH.ico",
    "README.txt",
    "LICENSE-wintun.txt",
];
const UNINSTALL_KEY: &str = r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\TailConnect-SSH";
const RUN_KEY: &str = r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run";
const FW_DIRECT: &str = "TailConnect-SSH (direct paths)";
const FW_TUNNEL: &str = "TailConnect-SSH (tunnel)";

fn install_dir() -> PathBuf {
    let pf = std::env::var_os("ProgramFiles").unwrap_or_else(|| OsString::from(r"C:\Program Files"));
    PathBuf::from(pf).join("TailConnect-SSH")
}

fn state_dir() -> PathBuf {
    let pd = std::env::var_os("ProgramData").unwrap_or_else(|| OsString::from(r"C:\ProgramData"));
    PathBuf::from(pd).join("TailConnect-SSH")
}

// ---- the service ----

static FLAGS: OnceLock<Flags> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Run under the Service Control Manager.
pub fn run_service(mut flags: Flags) -> Result<()> {
    // The default state folder follows %ProgramData%.
    if flags.state_dir == Path::new(super::DEFAULT_STATE_DIR) {
        flags.state_dir = state_dir();
    }
    let _ = FLAGS.set(flags);
    service_dispatcher::start(SERVICE, ffi_service_main).context("starting as a service (only the Service Control Manager can do this; run `tcd` without `service` in a console)")?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    let flags = FLAGS.get().cloned().expect("flags");
    log_to_file(&flags.state_dir);
    if let Err(e) = serve(flags) {
        tracing::error!("service: {e:#}");
    }
}

fn status(state: ServiceState, accept: ServiceControlAccept, code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn serve(flags: Flags) -> Result<()> {
    let handle = service_control_handler::register(SERVICE, |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            tailconnect::client::request_shutdown();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
    ))?;
    let r = (|| -> Result<()> {
        let d = tailconnect::client::Daemon::new(super::options(flags))?;
        tokio::runtime::Runtime::new()?.block_on(d.run())
    })();
    // MagicDNS rules must not outlive the tunnel.
    tailconnect::client::win::clear_dns();
    if let Err(e) = &r {
        tracing::error!("{e:#}");
    }
    tracing::info!("service stopped");
    handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        if r.is_ok() { 0 } else { 1 },
    ))?;
    r
}

/// Log to tcd.log in the state folder (a service has no console); the
/// previous run's log is kept as tcd.log.1.
fn log_to_file(dir: &Path) {
    let _ = std::fs::create_dir_all(dir);
    let path = dir.join("tcd.log");
    let _ = std::fs::rename(&path, dir.join("tcd.log.1"));
    let file = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(_) => return,
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,russh=warn".into()),
        )
        .with_ansi(false)
        .with_writer(std::sync::Mutex::new(file))
        .init();
}

// ---- install ----

/// Re-run this command elevated, waiting for it, if we aren't.
fn elevate(args: &str) -> Result<bool> {
    if is_elevated() {
        return Ok(false);
    }
    println!("Asking Windows for administrator rights...");
    let exe = std::env::current_exe()?;
    let code = run_elevated(&exe, args, true)?;
    if code != 0 {
        bail!("{args} failed (exit code {code})");
    }
    Ok(true)
}

fn quote_arg(a: &str) -> String {
    if a.is_empty() || a.contains([' ', '\t', '"']) {
        format!("\"{}\"", a.replace('"', "\\\""))
    } else {
        a.to_string()
    }
}

/// The flags the installed service runs with now, if it's installed.
fn current_flags() -> Option<String> {
    let out = run("sc.exe", &["qc", SERVICE]).ok()?;
    let line = out.lines().find(|l| l.trim_start().starts_with("BINARY_PATH_NAME"))?;
    let path = line.split_once(':')?.1.trim();
    // "C:\...\tcd.exe" FLAGS service
    let rest = path.strip_prefix('"').and_then(|p| p.split_once('"')).map(|(_, r)| r)?;
    let rest = rest.trim().strip_suffix("service").unwrap_or(rest.trim()).trim();
    Some(rest.to_string())
}

fn service_exists() -> bool {
    run("sc.exe", &["query", SERVICE]).is_ok()
}

/// Stop the service and wait until it has.
fn stop_service() {
    if run("sc.exe", &["stop", SERVICE]).is_err() {
        return;
    }
    for _ in 0..60 {
        match run("sc.exe", &["query", SERVICE]) {
            Ok(o) if o.contains("STOPPED") => return,
            Err(_) => return,
            _ => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

/// Stop the app (tray) in every session, so its files can be replaced,
/// and wait for it to be gone.
fn stop_app() {
    if run("taskkill.exe", &["/F", "/IM", APP_EXE]).is_err() {
        return;
    }
    for _ in 0..20 {
        match run("tasklist.exe", &["/FI", &format!("IMAGENAME eq {APP_EXE}"), "/NH"]) {
            Ok(o) if o.contains(APP_EXE) => std::thread::sleep(Duration::from_millis(250)),
            _ => return,
        }
    }
}

pub fn install(args: Vec<String>) -> Result<()> {
    let joined: String = args.iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" ");
    if elevate(format!("install {joined}").trim())? {
        println!("Installed. `tcs` is on the PATH of new command prompts.");
        return Ok(());
    }
    let src = std::env::current_exe()?
        .parent()
        .map(Path::to_path_buf)
        .context("this program's folder")?;
    let dst = install_dir();
    for f in ["tcd.exe", "tcs.exe", "wintun.dll"] {
        if !src.join(f).exists() {
            bail!(
                "{} not found: install from the unzipped TailConnect-SSH folder",
                src.join(f).display()
            );
        }
    }
    let flags = if args.is_empty() {
        current_flags().unwrap_or_default()
    } else {
        joined
    };
    let upgrade = service_exists();
    if upgrade {
        println!("Stopping the {SERVICE} service...");
        stop_service();
    }
    stop_app();

    // Files.
    let same = std::fs::canonicalize(&src).ok() == std::fs::canonicalize(&dst).ok();
    if !same {
        std::fs::create_dir_all(&dst).with_context(|| format!("creating {}", dst.display()))?;
        // Files set aside by an earlier upgrade.
        if let Ok(entries) = std::fs::read_dir(&dst) {
            for e in entries.flatten() {
                if e.path().extension().is_some_and(|x| x == "old") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        for f in FILES {
            let from = src.join(f);
            if from.exists() {
                // A file Windows still holds can't be replaced, but can be renamed.
                let to = dst.join(f);
                if to.exists() && std::fs::remove_file(&to).is_err() {
                    let _ = std::fs::rename(&to, dst.join(format!("{f}.old")));
                }
                std::fs::copy(&from, &to).with_context(|| format!("copying {f} to {}", dst.display()))?;
            }
        }
        println!("Copied the programs to {}", dst.display());
    }
    let tcd = dst.join("tcd.exe");
    let app = dst.join(APP_EXE);

    // The service.
    let bin = format!("\"{}\" {flags} service", tcd.display()).replace("  ", " ");
    if upgrade {
        run("sc.exe", &["config", SERVICE, "binPath=", &bin, "start=", "auto"])?;
    } else {
        run(
            "sc.exe",
            &[
                "create",
                SERVICE,
                "binPath=",
                &bin,
                "start=",
                "auto",
                "DisplayName=",
                DISPLAY,
            ],
        )?;
    }
    let _ = run(
        "sc.exe",
        &[
            "description",
            SERVICE,
            "Connects this PC to its TailConnect-SSH network (SSH over TLS).",
        ],
    );
    let _ = run(
        "sc.exe",
        &[
            "failure",
            SERVICE,
            "reset=",
            "86400",
            "actions=",
            "restart/5000/restart/5000/restart/30000",
        ],
    );

    // PATH, firewall, Start menu, sign-in, Settings → Apps.
    let version = env!("CARGO_PKG_VERSION");
    let script = format!(
        r#"$dir = {dir}
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if (-not (($path -split ';') -contains $dir)) {{ [Environment]::SetEnvironmentVariable('Path', ($path.TrimEnd(';') + ';' + $dir), 'Machine') }}
Remove-NetFirewallRule -DisplayName {fw_direct} -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName {fw_tunnel} -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName {fw_direct} -Direction Inbound -Action Allow -Program {tcd} -Profile Any | Out-Null
New-NetFirewallRule -DisplayName {fw_tunnel} -Direction Inbound -Action Allow -LocalAddress '100.64.0.0/10','fd74:6373:7368::/48' -Profile Any | Out-Null
if (Test-Path {app}) {{
  $lnk = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\TailConnect-SSH.lnk'
  $s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
  $s.TargetPath = {app}; $s.WorkingDirectory = $dir; $s.Description = 'TailConnect-SSH'
  if (Test-Path {ico}) {{ $s.IconLocation = {ico} }}
  $s.Save()
  New-ItemProperty -Path {run_key} -Name 'TailConnect-SSH' -Value ('"' + {app} + '" --tray') -PropertyType String -Force | Out-Null
}}
New-Item -Path {uninstall_key} -Force | Out-Null
$u = {uninstall_key}
New-ItemProperty -Path $u -Name DisplayName -Value 'TailConnect-SSH' -Force | Out-Null
New-ItemProperty -Path $u -Name DisplayVersion -Value {version} -Force | Out-Null
New-ItemProperty -Path $u -Name Publisher -Value 'TailConnect-SSH' -Force | Out-Null
New-ItemProperty -Path $u -Name InstallLocation -Value $dir -Force | Out-Null
New-ItemProperty -Path $u -Name DisplayIcon -Value $(if (Test-Path {ico}) {{ {ico} }} else {{ {tcd} }}) -Force | Out-Null
New-ItemProperty -Path $u -Name UninstallString -Value ('"' + {tcd} + '" uninstall') -Force | Out-Null
New-ItemProperty -Path $u -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $u -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
"#,
        dir = ps_quote(&dst.to_string_lossy()),
        tcd = ps_quote(&tcd.to_string_lossy()),
        app = ps_quote(&app.to_string_lossy()),
        ico = ps_quote(&dst.join("TailConnectSSH.ico").to_string_lossy()),
        fw_direct = ps_quote(FW_DIRECT),
        fw_tunnel = ps_quote(FW_TUNNEL),
        run_key = ps_quote(RUN_KEY),
        uninstall_key = ps_quote(UNINSTALL_KEY),
        version = ps_quote(version),
    );
    powershell(&script).context("setting up PATH, firewall rules and shortcuts")?;

    run("sc.exe", &["start", SERVICE]).context("starting the service")?;
    println!(
        "{} the {SERVICE} service ({}).",
        if upgrade {
            "Upgraded and restarted"
        } else {
            "Installed and started"
        },
        if flags.is_empty() {
            "default settings".to_string()
        } else {
            format!("tcd {flags}")
        }
    );
    // The app, in the signed-in user's session and unelevated: explorer.exe
    // starts it as the desktop's user.
    // (setup.exe opens it itself from its Finish page: TCS_NO_APP=1.)
    if app.exists() && std::env::var_os("TCS_NO_APP").is_none() {
        let _ = std::process::Command::new("explorer.exe").arg(&app).spawn();
    }
    // Logged in already (kept from an earlier install)?
    let joined = std::fs::read_to_string(state_dir().join("state.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .is_some_and(|v| v.get("server").is_some_and(|s| s.is_string()));
    if !upgrade && !joined {
        println!("Next: log in from the TailConnect-SSH app, or in an Administrator prompt:");
        println!("  tcs up --server HUB --authkey KEY [--tls-fingerprint sha256:...]");
    }
    Ok(())
}

pub fn uninstall(purge: bool) -> Result<()> {
    if elevate(if purge { "uninstall --purge" } else { "uninstall" })? {
        println!("Removed TailConnect-SSH.");
        return Ok(());
    }
    if service_exists() {
        println!("Stopping and removing the {SERVICE} service...");
        stop_service();
        run("sc.exe", &["delete", SERVICE]).context("removing the service")?;
    }
    stop_app();
    tailconnect::client::win::clear_dns();
    let dst = install_dir();
    let script = format!(
        r#"$dir = {dir}
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$new = (($path -split ';') | Where-Object {{ $_ -and $_ -ne $dir }}) -join ';'
if ($new -ne $path) {{ [Environment]::SetEnvironmentVariable('Path', $new, 'Machine') }}
Remove-NetFirewallRule -DisplayName {fw_direct} -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName {fw_tunnel} -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\TailConnect-SSH.lnk') -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path {run_key} -Name 'TailConnect-SSH' -Force -ErrorAction SilentlyContinue
Remove-Item -Path {uninstall_key} -Recurse -Force -ErrorAction SilentlyContinue
"#,
        dir = ps_quote(&dst.to_string_lossy()),
        fw_direct = ps_quote(FW_DIRECT),
        fw_tunnel = ps_quote(FW_TUNNEL),
        run_key = ps_quote(RUN_KEY),
        uninstall_key = ps_quote(UNINSTALL_KEY),
    );
    powershell(&script).context("removing PATH, firewall rules and shortcuts")?;
    if purge {
        let _ = std::fs::remove_dir_all(state_dir());
    }
    // The installed folder: everything but this running tcd.exe now, and
    // the folder itself once this process has exited.
    let me = std::env::current_exe().ok().and_then(|p| std::fs::canonicalize(p).ok());
    if let Ok(entries) = std::fs::read_dir(&dst) {
        for e in entries.flatten() {
            if std::fs::canonicalize(e.path()).ok() != me {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    if dst.exists() {
        // cmd.exe has its own quoting: pass its command line as is.
        let cmd = format!("/c ping -n 3 127.0.0.1 >nul & rmdir /s /q \"{}\"", dst.display());
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("cmd.exe")
            .raw_arg(&cmd)
            .creation_flags(0x0800_0000 | 0x0000_0008) // no window, detached
            .spawn();
    }
    if purge {
        println!("Removed TailConnect-SSH, with its keys and settings.");
    } else {
        println!(
            "Removed TailConnect-SSH. Keys and settings are kept in {} (`tcd uninstall --purge` deletes them).",
            state_dir().display()
        );
    }
    Ok(())
}
