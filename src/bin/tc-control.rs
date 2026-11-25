//! tc-control: the TailConnect hub (coordination server and relay).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tailconnect::server::{self, db::Db};

#[derive(Parser)]
#[command(
    name = "tc-control",
    version,
    about = "TailConnect hub: SSH-over-TLS coordination server and relay"
)]
struct Cli {
    /// Directory holding the database, SSH host key and TLS certificate.
    #[arg(
        long,
        global = true,
        env = "TC_STATE_DIR",
        default_value = "/var/lib/tailconnect-control"
    )]
    state_dir: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the hub.
    Serve {
        /// Address to listen on.
        #[arg(long, default_value = "[::]:443")]
        listen: SocketAddr,
        /// MagicDNS domain: machines resolve as NAME.DOMAIN.
        #[arg(long, default_value = "tc.internal")]
        domain: String,
        /// PEM certificate chain (for example from Let's Encrypt). Without
        /// it, a self-signed certificate is created in the state directory.
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// PEM private key for --tls-cert.
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
        /// Names for the self-signed certificate (default: this host's name).
        #[arg(long = "tls-name")]
        tls_names: Vec<String>,
    },
    /// Print the TLS fingerprint and SSH host key clients need to pin.
    Fingerprint,
    /// Manage pre-auth keys.
    #[command(subcommand)]
    Authkey(AuthkeyCmd),
    /// Manage machines.
    #[command(subcommand)]
    Nodes(NodesCmd),
}

#[derive(Subcommand)]
enum AuthkeyCmd {
    /// Create a key. It's shown once.
    Create {
        /// Allow any number of machines to join with it.
        #[arg(long)]
        reusable: bool,
        /// Hours until it expires (default: never).
        #[arg(long)]
        expires_hours: Option<u64>,
    },
    List,
    Revoke {
        id: i64,
    },
}

#[derive(Subcommand)]
enum NodesCmd {
    List,
    Remove { name: String },
    Rename { name: String, new_name: String },
}

fn open_db(dir: &Path) -> Result<Db> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    Db::open(&dir.join("tailconnect.db"))
}

fn fmt_time(t: Option<i64>) -> String {
    match t {
        None => "-".into(),
        Some(t) => {
            let ago = tailconnect::now_unix() - t;
            match ago {
                i64::MIN..0 => format!("in {}", human(-ago)),
                0..5 => "just now".into(),
                _ => format!("{} ago", human(ago)),
            }
        }
    }
}

fn human(s: i64) -> String {
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m", s / 60),
        3600..86400 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86400),
    }
}

fn self_signed_names(extra: Vec<String>) -> Vec<String> {
    if !extra.is_empty() {
        return extra;
    }
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let mut v = vec!["localhost".to_string()];
    if !host.is_empty() {
        v.insert(0, host);
    }
    v
}

fn load_tls(
    dir: &Path,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    names: Vec<String>,
) -> Result<tailconnect::tls::ServerTls> {
    match (cert, key) {
        (Some(c), Some(k)) => tailconnect::tls::server_from_pem(&c, &k),
        _ => tailconnect::tls::server_self_signed(dir, self_signed_names(names)),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,russh=warn".into()),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve {
            listen,
            domain,
            tls_cert,
            tls_key,
            tls_names,
        } => {
            let domain = domain.trim_matches('.').to_ascii_lowercase();
            if domain.is_empty() {
                bail!("--domain must not be empty");
            }
            let tls = load_tls(&cli.state_dir, tls_cert, tls_key, tls_names)?;
            server::run(server::Options {
                listen,
                state_dir: cli.state_dir,
                domain,
                tls,
            })
            .await
        }
        Cmd::Fingerprint => {
            let key = tailconnect::keys::load_or_create(&cli.state_dir.join("ssh_host_ed25519_key"))?;
            let cert = cli.state_dir.join("tls-cert.pem");
            println!("SSH host key:     {}", tailconnect::keys::key_id(key.public_key()));
            if cert.exists() {
                let tls = tailconnect::tls::server_from_pem(&cert, &cli.state_dir.join("tls-key.pem"))?;
                println!("TLS fingerprint:  {}", tls.fingerprint);
                println!(
                    "\nJoin a machine with:\n  sudo tc up --server HOST --tls-fingerprint {} --authkey KEY",
                    tls.fingerprint
                );
            } else {
                println!("TLS fingerprint:  (no self-signed certificate yet; run `serve` once, or use --tls-cert)");
            }
            Ok(())
        }
        Cmd::Authkey(c) => {
            let db = open_db(&cli.state_dir)?;
            match c {
                AuthkeyCmd::Create {
                    reusable,
                    expires_hours,
                } => {
                    let exp = expires_hours.map(|h| tailconnect::now_unix() + (h as i64) * 3600);
                    println!("{}", db.create_authkey(reusable, exp)?);
                }
                AuthkeyCmd::List => {
                    println!(
                        "{:<4} {:<16} {:<9} {:<5} {:<8} {:<12} CREATED",
                        "ID", "PREFIX", "REUSABLE", "USED", "REVOKED", "EXPIRES"
                    );
                    for k in db.authkeys()? {
                        println!(
                            "{:<4} {:<16} {:<9} {:<5} {:<8} {:<12} {}",
                            k.id,
                            format!("{}…", k.prefix),
                            k.reusable,
                            k.used,
                            k.revoked,
                            fmt_time(k.expires),
                            fmt_time(Some(k.created))
                        );
                    }
                }
                AuthkeyCmd::Revoke { id } => {
                    if !db.revoke_authkey(id)? {
                        bail!("no auth key with id {id}");
                    }
                    println!("revoked");
                }
            }
            Ok(())
        }
        Cmd::Nodes(c) => {
            let db = open_db(&cli.state_dir)?;
            match c {
                NodesCmd::List => {
                    println!("{:<20} {:<15} {:<20} {:<10} KEY", "NAME", "IP", "HOSTNAME", "LAST SEEN");
                    for n in db.nodes()? {
                        let key: String = n.key.chars().take(32).collect();
                        println!(
                            "{:<20} {:<15} {:<20} {:<10} {key}…",
                            n.name,
                            n.ip,
                            n.hostname,
                            fmt_time(n.last_seen)
                        );
                    }
                }
                NodesCmd::Remove { name } => {
                    if !db.remove_node(&name)? {
                        bail!("no machine named {name}");
                    }
                    println!("removed {name}");
                }
                NodesCmd::Rename { name, new_name } => {
                    let n = db.rename_node(&name, &new_name)?;
                    println!("renamed {name} to {n}");
                }
            }
            Ok(())
        }
    }
}
