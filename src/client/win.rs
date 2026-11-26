//! Windows system plumbing for tcd: the Wintun adapter's settings, MagicDNS
//! through NRPT rules, and the state folder's permissions.
//!
//! MagicDNS: an NRPT rule per zone (`.richard.tc.internal`, …) sends those
//! names to 100.100.100.100, which tcd answers inside the tunnel; other
//! names resolve as before. With an exit node in use, a rule for `.` sends
//! every name there. The adapter's connection-specific suffix is this
//! machine's zone, so short names (`laptop`) work. The rules are tagged with
//! a comment and removed when the tunnel goes down and when tcd starts.

use std::net::Ipv6Addr;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, bail};
use tracing::{info, warn};

/// No console window for the commands tcd runs.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// The comment on tcd's NRPT rules.
const NRPT_TAG: &str = "TailConnect-SSH";

/// The Wintun adapter's GUID: the same every time, so Windows keeps one
/// network for it rather than adding "TailConnect-SSH 2", "… 3".
pub const ADAPTER_GUID: u128 = 0x5c1e_7a20_9d3b_4c8e_a6f1_7463_7373_6801;

/// wintun.dll, beside tcd.exe.
pub fn wintun_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("wintun.dll")))
        .unwrap_or_else(|| PathBuf::from("wintun.dll"))
}

/// Run a program, failing with its output if it fails.
pub fn run(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if !out.status.success() {
        let mut msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if msg.is_empty() {
            msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
        bail!("{program} {}: {msg}", args.join(" "));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Run a PowerShell script (passed encoded, so nothing needs quoting).
pub fn powershell(script: &str) -> Result<String> {
    let script = format!("$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\n{script}");
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    run(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &crate::base64(&utf16),
        ],
    )
}

/// A PowerShell single-quoted string.
pub fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Limit `dir` (tcd's state: keys, settings) to SYSTEM and Administrators.
/// ProgramData's own permissions would let every user read it.
pub fn restrict_dir(dir: &Path) {
    let d = dir.to_string_lossy();
    if let Err(e) = run(
        "icacls.exe",
        &[
            &d,
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "/q",
        ],
    ) {
        warn!("restricting {d}: {e:#}");
    }
}

/// Settings for a new adapter: its IPv6 address (and so the route for the
/// tailnet's /48), and a low metric so its routes and DNS come first.
/// Returns whether IPv6 is set up.
pub fn configure_adapter(name: &str, ip6: Ipv6Addr, prefix: u8) -> bool {
    let iface = format!("interface={name}");
    for fam in ["ipv4", "ipv6"] {
        if let Err(e) = run("netsh.exe", &["interface", fam, "set", "interface", &iface, "metric=5"]) {
            warn!("{name}: setting the {fam} metric: {e:#}");
        }
    }
    match run(
        "netsh.exe",
        &[
            "interface",
            "ipv6",
            "add",
            "address",
            &iface,
            &format!("address={ip6}/{prefix}"),
            "store=active",
        ],
    ) {
        Ok(_) => true,
        Err(e) if e.to_string().contains("already exists") || e.to_string().contains("Object already") => true,
        Err(e) => {
            warn!("no IPv6 in the tunnel: {e:#}");
            false
        }
    }
}

/// Point Windows at MagicDNS for `zones` (all names with `all`), with
/// `search` as the adapter's DNS suffix.
pub fn apply_dns(adapter: String, search: String, zones: Vec<String>, all: bool) {
    tokio::task::spawn_blocking(move || {
        let mut namespaces: Vec<String> = std::iter::once(&search)
            .chain(zones.iter())
            .map(|z| format!(".{z}"))
            .collect();
        if all {
            namespaces.push(".".into());
        }
        namespaces.dedup();
        let list = namespaces.iter().map(|n| ps_quote(n)).collect::<Vec<_>>().join(",");
        let script = format!(
            "Get-DnsClientNrptRule | Where-Object Comment -eq {tag} | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}\n\
             foreach ($n in @({list})) {{ Add-DnsClientNrptRule -Namespace $n -NameServers {dns} -Comment {tag} | Out-Null }}\n\
             Set-DnsClient -InterfaceAlias {adapter} -ConnectionSpecificSuffix {search} -RegisterThisConnectionsAddress $false\n\
             Clear-DnsClientCache",
            tag = ps_quote(NRPT_TAG),
            dns = ps_quote(&crate::MAGIC_DNS_IP.to_string()),
            adapter = ps_quote(&adapter),
            search = ps_quote(&search),
        );
        match powershell(&script) {
            Ok(_) => info!(
                "MagicDNS: {} via {} (suffix {search})",
                namespaces.join(", "),
                crate::MAGIC_DNS_IP
            ),
            Err(e) => warn!(
                "MagicDNS not configured ({e:#}); names still resolve with `nslookup NAME {}`",
                crate::MAGIC_DNS_IP
            ),
        }
    });
}

/// Remove tcd's NRPT rules (the tunnel is down, or tcd is starting).
pub fn clear_dns() {
    let script = format!(
        "Get-DnsClientNrptRule | Where-Object Comment -eq {tag} | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}\n\
         Clear-DnsClientCache",
        tag = ps_quote(NRPT_TAG)
    );
    if let Err(e) = powershell(&script) {
        warn!("removing MagicDNS rules: {e:#}");
    }
}

/// Is this process running elevated (an administrator past UAC, or SYSTEM)?
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // SAFETY: the token handle is checked and closed; the buffer is sized
    // for TOKEN_ELEVATION.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut e as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && e.TokenIsElevated != 0
    }
}

/// Run `exe ARGS` elevated (Windows asks the user to confirm, or for an
/// administrator's password) and wait for it: its exit code, or an error if
/// the user said no.
pub fn run_elevated(exe: &Path, args: &str, show: bool) -> Result<u32> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows_sys::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let (verb, file, params) = (wide("runas"), wide(&exe.to_string_lossy()), wide(args));
    // SAFETY: the strings outlive the call; the process handle is closed.
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = if show { SW_SHOWNORMAL } else { SW_HIDE };
        if ShellExecuteExW(&mut info) == 0 {
            let e = std::io::Error::last_os_error();
            // ERROR_CANCELLED: the user said no.
            if e.raw_os_error() == Some(1223) {
                bail!("cancelled");
            }
            bail!("running {} as administrator: {e}", exe.display());
        }
        if info.hProcess.is_null() {
            return Ok(0);
        }
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 0u32;
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
        Ok(code)
    }
}
