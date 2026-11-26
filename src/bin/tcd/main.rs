//! tcd: the TailConnect machine daemon.
//!
//! On Windows it also runs as the TailConnectSSH service and installs
//! itself (`tcd install`, `tcd uninstall`): see windows.rs.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tailconnect::client::{Daemon, Options, api::DEFAULT_SOCKET};

#[cfg(windows)]
mod windows;

#[cfg(unix)]
const DEFAULT_STATE_DIR: &str = "/var/lib/tailconnect-ssh";
/// (Windows: %ProgramData%\TailConnect-SSH.)
#[cfg(windows)]
const DEFAULT_STATE_DIR: &str = r"C:\ProgramData\TailConnect-SSH";
/// `tcs0`, so it can run beside the WireGuard TailConnect's `tc0`.
#[cfg(unix)]
const DEFAULT_TUN: &str = "tcs0";
/// The Wintun adapter's name.
#[cfg(windows)]
const DEFAULT_TUN: &str = "TailConnect-SSH";

#[derive(Parser, Clone)]
#[command(
    name = "tcd",
    version,
    about = "TailConnect daemon: TUN device, SSH-over-TLS tunnels and MagicDNS"
)]
pub struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    #[command(flatten)]
    opts: Flags,
}

#[derive(clap::Args, Clone)]
pub struct Flags {
    #[arg(long, env = "TC_STATE_DIR", default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,
    /// Local API socket for `tc` (a named pipe on Windows).
    #[arg(long, env = "TC_SOCKET", default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    /// Name of the TUN interface (the Wintun adapter on Windows).
    #[arg(long, default_value = DEFAULT_TUN)]
    tun: String,
    #[arg(long, default_value_t = tailconnect::DEFAULT_MTU)]
    mtu: u16,
    /// TCP port for direct SSH sessions with peers (0 = hub only).
    #[arg(long, default_value_t = 7443)]
    direct_port: u16,
    /// Don't configure the system's DNS for MagicDNS (systemd-resolved on
    /// Linux, NRPT rules on Windows).
    #[arg(long)]
    no_dns: bool,
    /// Name to register with (default: the system hostname).
    #[arg(long)]
    hostname: Option<String>,
    /// As an exit node: resolvers to answer the DNS lookups of the machines
    /// using it (comma-separated addresses; default: this host's own).
    #[arg(long, value_delimiter = ',')]
    exit_dns: Vec<std::net::IpAddr>,
    /// As an exit node: send the traffic forwarded for others out through
    /// this interface (a VPN's tun0, a second uplink), never the normal
    /// connection: while it's down, that traffic is blocked (kill switch).
    #[arg(long)]
    exit_interface: Option<String>,
    /// Inside the Android app: the socket the app's VpnService connects to,
    /// to provide the VPN interface and the underlying network's details.
    #[cfg(unix)]
    #[arg(long)]
    bridge: Option<PathBuf>,
    /// Android: the underlying network's DNS servers, until the app reports
    /// them (comma-separated).
    #[cfg(unix)]
    #[arg(long, value_delimiter = ',')]
    android_dns: Vec<std::net::IpAddr>,
    /// Android: this device's addresses on the underlying network, as
    /// ADDRESS/PREFIX (comma-separated).
    #[cfg(unix)]
    #[arg(long, value_delimiter = ',')]
    android_addrs: Vec<String>,
}

#[derive(Subcommand, Clone)]
enum Cmd {
    /// Windows: install (or upgrade) TailConnect-SSH from this folder:
    /// the files to Program Files\TailConnect-SSH, the service (running
    /// `tcd service ARGS`; default: the arguments it had before), PATH,
    /// firewall rules, the app in the Start menu and at sign-in.
    #[cfg(windows)]
    Install {
        /// tcd's arguments for the service.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Windows: remove the service, the app and the installed files (keys
    /// and settings stay in ProgramData\TailConnect-SSH, unless --purge).
    #[cfg(windows)]
    Uninstall {
        #[arg(long)]
        purge: bool,
    },
    /// Windows: run as the TailConnectSSH service (the Service Control
    /// Manager starts this).
    #[cfg(windows)]
    #[command(hide = true)]
    Service,
}

fn hostname() -> String {
    #[cfg(unix)]
    let h = std::fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_string());
    #[cfg(windows)]
    let h = std::env::var("COMPUTERNAME").map(|s| s.trim().to_ascii_lowercase());
    h.ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "node".into())
}

pub fn options(f: Flags) -> Options {
    Options {
        state_dir: f.state_dir,
        socket: f.socket,
        tun_name: f.tun,
        mtu: f.mtu,
        direct_port: f.direct_port,
        dns: !f.no_dns,
        hostname: f.hostname.unwrap_or_else(hostname),
        exit_dns: f
            .exit_dns
            .into_iter()
            .map(|ip| std::net::SocketAddr::new(ip, 53))
            .collect(),
        exit_interface: f.exit_interface,
        #[cfg(unix)]
        android: f.bridge.map(|bridge| tailconnect::client::android::AndroidOpts {
            bridge,
            dns: f.android_dns,
            addrs: f
                .android_addrs
                .iter()
                .filter_map(|a| {
                    let (ip, len) = a.split_once('/')?;
                    Some((ip.parse().ok()?, len.parse().ok()?))
                })
                .collect(),
        }),
    }
}

fn log_to_stderr() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,russh=warn".into()),
        )
        .init();
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd.clone() {
        #[cfg(windows)]
        Some(Cmd::Install { args }) => windows::install(args),
        #[cfg(windows)]
        Some(Cmd::Uninstall { purge }) => windows::uninstall(purge),
        #[cfg(windows)]
        Some(Cmd::Service) => windows::run_service(cli.opts),
        None => {
            log_to_stderr();
            let d = Daemon::new(options(cli.opts))?;
            tokio::runtime::Runtime::new()?.block_on(d.run())
        }
    }
}
