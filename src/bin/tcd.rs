//! tcd: the TailConnect machine daemon.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tailconnect::client::{Daemon, Options, api::DEFAULT_SOCKET};

#[derive(Parser)]
#[command(
    name = "tcd",
    version,
    about = "TailConnect daemon: TUN device, SSH-over-TLS tunnels and MagicDNS"
)]
struct Cli {
    #[arg(long, env = "TC_STATE_DIR", default_value = "/var/lib/tailconnect")]
    state_dir: PathBuf,
    /// Local API socket for `tc`.
    #[arg(long, env = "TC_SOCKET", default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    /// Name of the TUN interface.
    #[arg(long, default_value = "tc0")]
    tun: String,
    #[arg(long, default_value_t = tailconnect::DEFAULT_MTU)]
    mtu: u16,
    /// TCP port for direct SSH sessions with peers (0 = hub only).
    #[arg(long, default_value_t = 7443)]
    direct_port: u16,
    /// Don't configure systemd-resolved for MagicDNS.
    #[arg(long)]
    no_dns: bool,
    /// Name to register with (default: the system hostname).
    #[arg(long)]
    hostname: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,russh=warn".into()),
        )
        .init();
    let cli = Cli::parse();
    let hostname = cli.hostname.unwrap_or_else(|| {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "node".into())
    });
    let d = Daemon::new(Options {
        state_dir: cli.state_dir,
        socket: cli.socket,
        tun_name: cli.tun,
        mtu: cli.mtu,
        direct_port: cli.direct_port,
        dns: !cli.no_dns,
        hostname,
    })?;
    d.run().await
}
