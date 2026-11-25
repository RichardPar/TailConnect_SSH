//! tc: command-line front end to tcd.

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use tailconnect::client::api::{self, DEFAULT_SOCKET, Request, Status};

#[derive(Parser)]
#[command(name = "tc", version, about = "Control the TailConnect daemon")]
struct Cli {
    #[arg(long, global = true, env = "TC_SOCKET", default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect to the network (joining it, given an auth key).
    Up {
        /// Hub address: host, host:port or https://host (port 443 by default).
        #[arg(long)]
        server: Option<String>,
        /// Pre-auth key from `tc-control authkey create`.
        #[arg(long)]
        authkey: Option<String>,
        /// SHA-256 fingerprint of the hub's self-signed TLS certificate.
        #[arg(long)]
        tls_fingerprint: Option<String>,
    },
    /// Disconnect, keeping this machine's registration.
    Down,
    /// Disconnect and forget the server.
    Logout,
    /// Show this machine and its peers.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Print the tailnet address of this machine, or of a peer.
    Ip { name: Option<String> },
}

fn print_status(s: &Status) {
    match &s.me {
        Some(me) => println!(
            "{} {}.{} ({})  via {}  [{}]",
            me.ip,
            me.name,
            s.domain,
            s.tun.as_deref().unwrap_or("no tun"),
            s.server.as_deref().unwrap_or("?"),
            s.phase
        ),
        None => println!(
            "{}{}",
            s.phase,
            s.server.as_ref().map(|x| format!(" (server {x})")).unwrap_or_default()
        ),
    }
    if let Some(e) = &s.last_error {
        println!("last error: {e}");
    }
    for p in &s.peers {
        let state = match (p.online, p.path.as_str(), p.e2e) {
            (false, _, _) => "offline",
            (_, "hub", true) => "hub, e2e",
            (_, path, _) => path,
        };
        println!("{:<15} {:<24} {}", p.ip, p.name, state);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let req = match &cli.cmd {
        Cmd::Up {
            server,
            authkey,
            tls_fingerprint,
        } => Request::Up {
            server: server.clone(),
            auth_key: authkey.clone(),
            tls_fingerprint: tls_fingerprint.clone(),
        },
        Cmd::Down => Request::Down,
        Cmd::Logout => Request::Logout,
        Cmd::Status { .. } | Cmd::Ip { .. } => Request::Status,
    };
    let resp = api::call(&cli.socket, &req).await?;
    if !resp.ok {
        bail!("{}", resp.error.unwrap_or_else(|| "failed".into()));
    }
    let status = resp.status.unwrap_or_default();
    match cli.cmd {
        Cmd::Status { json: true } => println!("{}", serde_json::to_string_pretty(&status)?),
        Cmd::Status { json: false } | Cmd::Up { .. } => print_status(&status),
        Cmd::Down | Cmd::Logout => println!("{}", status.phase),
        Cmd::Ip { name } => {
            let ip = match name {
                None => status.me.map(|m| m.ip),
                Some(n) => {
                    let short = n.strip_suffix(&format!(".{}", status.domain)).unwrap_or(&n);
                    status.peers.iter().find(|p| p.name == short).map(|p| p.ip)
                }
            };
            match ip {
                Some(ip) => println!("{ip}"),
                None => bail!("not found"),
            }
        }
    }
    Ok(())
}
