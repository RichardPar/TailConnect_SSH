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
        /// Send internet traffic through this exit node (name, name.account
        /// or address); "" to stop. Remembered across restarts.
        #[arg(long)]
        exit_node: Option<String>,
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

/// How a peer relates to this machine, from what it may open here.
fn relation(me_account: &str, p: &api::PeerStatus) -> Option<String> {
    let all = p.inbound.iter().any(|x| x == "*");
    let ports = p.inbound.join(",");
    if p.account == me_account {
        return match (all, p.inbound.is_empty()) {
            (true, _) => None,
            (false, true) => Some("rules: can't open connections here".into()),
            (false, false) => Some(format!("rules: can open {ports} here")),
        };
    }
    Some(match (all, p.inbound.is_empty()) {
        (true, _) => "has access to this machine".into(),
        (false, true) => "shared with you".into(),
        (false, false) => format!("has access to this machine on {ports}"),
    })
}

fn bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n}B")
    } else {
        format!("{v:.1}{}", U[i])
    }
}

fn print_status(s: &Status) {
    match &s.me {
        Some(me) => println!(
            "{} {}.{}.{} ({})  via {}  [{}]",
            me.ip,
            me.name,
            me.account,
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
    if let Some(n) = &s.notice {
        println!("notice: {n}");
    }
    if s.exit_serving {
        println!("exit node: this machine forwards internet traffic for its account");
    }
    match (&s.exit_in_use, &s.exit_problem) {
        (Some(e), _) => println!("exit node: internet traffic and DNS go through {e}"),
        (None, Some(p)) => println!("exit node: {p}; internet traffic goes direct"),
        _ => {}
    }
    if let Some(e) = &s.last_error {
        println!("last error: {e}");
    }
    let me_account = s.me.as_ref().map(|m| m.account.as_str()).unwrap_or("");
    for p in &s.peers {
        let path = match (p.online, p.path.as_str(), p.e2e) {
            (false, _, _) => "offline",
            (_, "hub", true) => "hub, e2e",
            (_, path, _) => path,
        };
        let in_use = s.exit_in_use.as_deref() == Some(format!("{}.{}", p.name, p.account).as_str());
        let path = match (p.exit_node, in_use) {
            (_, true) => format!("{path}; exit node (in use)"),
            (true, false) => format!("{path}; exit node"),
            _ => path.to_string(),
        };
        let name = format!("{}.{}", p.name, p.account);
        let counts = if p.rx > 0 || p.tx > 0 {
            format!("; rx {} tx {}", bytes(p.rx), bytes(p.tx))
        } else {
            String::new()
        };
        match relation(me_account, p) {
            Some(r) => println!("{:<15} {:<28} {path}; {r}{counts}", p.ip, name),
            None => println!("{:<15} {:<28} {path}{counts}", p.ip, name),
        }
    }
    if s.filter_dropped > 0 {
        println!("filter: {} packets dropped", s.filter_dropped);
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
            exit_node,
        } => Request::Up {
            server: server.clone(),
            auth_key: authkey.clone(),
            tls_fingerprint: tls_fingerprint.clone(),
            exit_node: exit_node.clone(),
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
                    // NAME (own account), NAME.ACCOUNT or NAME.ACCOUNT.DOMAIN
                    let n = n.to_ascii_lowercase();
                    let rel = n.strip_suffix(&format!(".{}", status.domain)).unwrap_or(&n);
                    let mine = status.me.as_ref().map(|m| m.account.clone()).unwrap_or_default();
                    let (name, account) = rel.split_once('.').unwrap_or((rel, mine.as_str()));
                    status
                        .peers
                        .iter()
                        .find(|p| p.name == name && p.account == account)
                        .map(|p| p.ip)
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
