//! tc-control: the TailConnect hub (coordination server and relay), and its
//! admin CLI. The admin commands work directly on the database, whether or
//! not the hub is running; a running hub applies changes within a second.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tailconnect::server::{
    self, acme,
    db::{Db, Role, Status},
    portal::Signup,
};

/// A password from the terminal (asked twice), or one line of standard
/// input in scripts. Returns its hash.
fn read_password() -> Result<String> {
    use std::io::IsTerminal;
    let pw = if std::io::stdin().is_terminal() {
        let a = rpassword::prompt_password("Password (at least 10 characters): ")?;
        let b = rpassword::prompt_password("Again: ")?;
        if a != b {
            bail!("the passwords don't match");
        }
        a
    } else {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_string()
    };
    tailconnect::server::auth::hash_password(&pw)
}

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
        default_value = "/var/lib/tailconnect-ssh-control"
    )]
    state_dir: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

// Serve has many options; the enum is parsed once.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Cmd {
    /// Run the hub.
    Serve {
        /// Address to listen on.
        #[arg(long, default_value = "[::]:443")]
        listen: SocketAddr,
        /// MagicDNS domain: machines resolve as NAME.ACCOUNT.DOMAIN.
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
        /// Addresses new machines get: a part of 100.64.0.0/10, for example
        /// 100.96.0.0/16 to stay clear of another network using 100.64.0.x.
        #[arg(long, default_value = "100.64.0.0/10")]
        ip_pool: String,
        /// Don't serve the web portal (SSH only on --listen).
        #[arg(long)]
        no_portal: bool,
        /// Who may create accounts in the portal: off, approval, invite or open.
        #[arg(long, default_value = "approval")]
        signup: String,
        /// The address machines join with, shown in the portal's join
        /// commands (default: the host name the browser used).
        #[arg(long, default_value = "")]
        public_url: String,
        /// Extra host names the portal answers to (IP addresses, localhost,
        /// this host's name and the certificate's names always work).
        #[arg(long = "portal-host")]
        portal_hosts: Vec<String>,
        /// Also serve the portal over plain HTTP on this address, for
        /// example 127.0.0.1:7741 for use through an SSH tunnel.
        #[arg(long)]
        portal_listen: Option<SocketAddr>,
        /// Get the certificate from Let's Encrypt for these names
        /// (comma-separated), and renew it automatically.
        #[arg(long, conflicts_with = "tls_cert")]
        acme_domain: Option<String>,
        /// Contact address for the Let's Encrypt account (optional).
        #[arg(long, requires = "acme_domain")]
        acme_email: Option<String>,
        /// Use Let's Encrypt's test service (untrusted certificates, generous limits).
        #[arg(long, requires = "acme_domain", conflicts_with = "acme_directory")]
        acme_staging: bool,
        /// Another ACME server's directory URL.
        #[arg(long, requires = "acme_domain")]
        acme_directory: Option<String>,
        /// PEM root certificate to trust for the ACME server's own HTTPS
        /// (for test servers such as Pebble).
        #[arg(long, requires = "acme_domain")]
        acme_ca_root: Option<PathBuf>,
        /// Prove the name through DNS instead of a connection: `duckdns`
        /// (token in the TC_DUCKDNS_TOKEN environment variable). No port has
        /// to be reachable for Let's Encrypt.
        #[arg(long, requires = "acme_domain")]
        acme_dns: Option<String>,
        /// Answer Let's Encrypt's checks on this port-80 address (for example
        /// [::]:80), when --listen isn't reachable as port 443.
        #[arg(long, requires = "acme_domain", conflicts_with = "acme_dns")]
        acme_http_listen: Option<SocketAddr>,
    },
    /// Print the TLS fingerprint and SSH host key clients need to pin.
    Fingerprint,
    /// Create a new admin token (replacing the old one) for signing in to
    /// the portal as an operator without an account. Shown once.
    AdminToken,
    /// Invites: let someone create an account without approval.
    #[command(subcommand)]
    Invites(InvitesCmd),
    /// Accounts: each is a separate network.
    #[command(subcommand)]
    Accounts(AccountsCmd),
    /// Pre-auth keys, which let machines join an account.
    #[command(subcommand)]
    Authkey(AuthkeyCmd),
    /// Machines. NODE is an ID from `nodes list`, or NAME.ACCOUNT.
    #[command(subcommand)]
    Nodes(NodesCmd),
    /// Access rules within an account: FROM may open TO on PORTS.
    #[command(subcommand)]
    Rules(RulesCmd),
    /// Shares: let another account's machines connect to one machine.
    #[command(subcommand)]
    Shares(SharesCmd),
}

#[derive(Subcommand)]
enum InvitesCmd {
    Create {
        /// Days until it expires.
        #[arg(long, default_value_t = 7)]
        days: u32,
    },
    List,
    Revoke {
        id: i64,
    },
}

#[derive(Subcommand)]
enum AccountsCmd {
    /// Create an account (lower-case letters, digits and -, at most 32).
    Create {
        name: String,
        /// Let it manage the server in the portal.
        #[arg(long)]
        operator: bool,
        /// Set a password for the portal (asked for, or read from standard input).
        #[arg(long)]
        password: bool,
    },
    /// Set an account's portal password (asked for, or read from standard input).
    Passwd {
        name: String,
    },
    /// Make an account an operator or a tenant.
    Role {
        name: String,
        role: String,
    },
    /// Activate an account that signed up and waits for approval.
    Approve {
        name: String,
    },
    List,
    /// Cut an account's machines off and stop its shares, keeping everything.
    Suspend {
        name: String,
    },
    /// Undo `suspend`.
    Activate {
        name: String,
    },
    /// Delete an account with its machines, keys, rules and shares.
    Delete {
        name: String,
    },
}

#[derive(Subcommand)]
enum AuthkeyCmd {
    /// Create a key. It's shown once.
    Create {
        /// Account the machines join (may be left out when there is only one).
        #[arg(long)]
        account: Option<String>,
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
    List {
        #[arg(long)]
        account: Option<String>,
    },
    Remove {
        node: String,
    },
    Rename {
        node: String,
        new_name: String,
    },
    /// Replace a machine's tags (comma-separated; "" clears them).
    Tag {
        node: String,
        tags: String,
    },
    /// Let a (Linux) machine route internet traffic for the machines of its
    /// account, or stop it. Off for every machine until turned on.
    ExitNode {
        node: String,
        /// on or off
        state: String,
    },
}

#[derive(Subcommand)]
enum RulesCmd {
    List {
        #[arg(long)]
        account: Option<String>,
    },
    /// Add a rule. The first rule switches the account from "everything
    /// allowed" to "only what the rules allow".
    Add {
        #[arg(long)]
        account: String,
        /// `*`, `tag:NAME` or a machine name.
        from: String,
        /// `*`, `tag:NAME` or a machine name.
        to: String,
        /// `*`, or a list like `tcp:22,tcp:443,udp:53,8000-8100,icmp`.
        #[arg(default_value = "*")]
        ports: String,
    },
    Delete {
        id: i64,
    },
}

#[derive(Subcommand)]
enum SharesCmd {
    List,
    /// Offer a machine to another account. Pending until accepted.
    Create {
        node: String,
        account: String,
        /// `*` (default) or a port list such as `tcp:80,tcp:443`.
        #[arg(default_value = "*")]
        ports: String,
    },
    /// Accept a share on the recipient account's behalf.
    Accept {
        id: i64,
    },
    /// Change which ports a share allows.
    Ports {
        id: i64,
        ports: String,
    },
    /// End a share.
    Revoke {
        id: i64,
    },
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

/// The account to use when `--account` was left out: the only one.
fn only_account(db: &Db, given: Option<String>) -> Result<String> {
    if let Some(a) = given {
        return Ok(a);
    }
    let all = db.accounts()?;
    match all.as_slice() {
        [one] => Ok(one.name.clone()),
        [] => bail!("there are no accounts yet: create one with `tc-control accounts create NAME`"),
        _ => bail!("there are several accounts: pass --account NAME"),
    }
}

fn admin(dir: &Path, cmd: Cmd) -> Result<()> {
    let mut db = open_db(dir)?;
    match cmd {
        Cmd::Accounts(c) => match c {
            AccountsCmd::Create {
                name,
                operator,
                password,
            } => {
                let hash = if password { Some(read_password()?) } else { None };
                let role = if operator { Role::Operator } else { Role::Tenant };
                let a = db.create_account_with(&name, Status::Active, role, hash.as_deref())?;
                println!("created account {}", a.name);
                println!(
                    "next: tc-control authkey create --account {} --reusable --expires-hours 24",
                    a.name
                );
            }
            AccountsCmd::List => {
                let nodes = db.nodes()?;
                println!(
                    "{:<4} {:<20} {:<10} {:<9} {:<9} {:<9} CREATED",
                    "ID", "NAME", "STATUS", "ROLE", "PASSWORD", "MACHINES"
                );
                for a in db.accounts()? {
                    let n = nodes.iter().filter(|n| n.account_id == a.id).count();
                    println!(
                        "{:<4} {:<20} {:<10} {:<9} {:<9} {:<9} {}",
                        a.id,
                        a.name,
                        a.status.as_str(),
                        a.role.as_str(),
                        if a.has_password { "yes" } else { "no" },
                        n,
                        fmt_time(Some(a.created))
                    );
                }
            }
            AccountsCmd::Passwd { name } => {
                db.account(&name)?;
                let h = read_password()?;
                db.set_password(&name, Some(&h))?;
                println!("password set for {name} (its portal sessions have ended)");
            }
            AccountsCmd::Role { name, role } => {
                db.set_role(&name, Role::parse(&role)?)?;
                println!("{name} is now a {role}");
            }
            AccountsCmd::Approve { name } => {
                db.set_account_status(&name, Status::Active)?;
                println!("approved {name}");
            }
            AccountsCmd::Suspend { name } => {
                db.set_account_status(&name, Status::Suspended)?;
                println!("suspended {name}");
            }
            AccountsCmd::Activate { name } => {
                db.set_account_status(&name, Status::Active)?;
                println!("activated {name}");
            }
            AccountsCmd::Delete { name } => {
                db.delete_account(&name)?;
                println!("deleted {name}");
            }
        },
        Cmd::Authkey(c) => match c {
            AuthkeyCmd::Create {
                account,
                reusable,
                expires_hours,
            } => {
                let account = only_account(&db, account)?;
                let exp = expires_hours.map(|h| tailconnect::now_unix() + (h as i64) * 3600);
                println!("{}", db.create_authkey(&account, reusable, exp)?);
            }
            AuthkeyCmd::List => {
                println!(
                    "{:<4} {:<14} {:<16} {:<9} {:<5} {:<8} {:<12} CREATED",
                    "ID", "ACCOUNT", "PREFIX", "REUSABLE", "USED", "REVOKED", "EXPIRES"
                );
                for k in db.authkeys()? {
                    println!(
                        "{:<4} {:<14} {:<16} {:<9} {:<5} {:<8} {:<12} {}",
                        k.id,
                        k.account,
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
        },
        Cmd::Nodes(c) => match c {
            NodesCmd::List { account } => {
                println!(
                    "{:<4} {:<28} {:<15} {:<16} {:<5} {:<10} KEY",
                    "ID", "NAME", "IP", "TAGS", "EXIT", "LAST SEEN"
                );
                for n in db.nodes()? {
                    if account.as_ref().is_some_and(|a| *a != n.account) {
                        continue;
                    }
                    let key: String = n.key.chars().take(32).collect();
                    let tags = if n.tags.is_empty() {
                        "-".into()
                    } else {
                        n.tags.join(",")
                    };
                    println!(
                        "{:<4} {:<28} {:<15} {:<16} {:<5} {:<10} {key}…",
                        n.id,
                        format!("{}.{}", n.name, n.account),
                        n.ip,
                        tags,
                        if n.exit_node { "yes" } else { "-" },
                        fmt_time(n.last_seen)
                    );
                }
            }
            NodesCmd::Remove { node } => {
                let n = db.find_node(&node)?;
                db.remove_node(n.id)?;
                println!("removed {}.{}", n.name, n.account);
            }
            NodesCmd::Rename { node, new_name } => {
                let n = db.find_node(&node)?;
                let new = db.rename_node(n.id, &new_name)?;
                println!("renamed {}.{} to {new}.{}", n.name, n.account, n.account);
            }
            NodesCmd::ExitNode { node, state } => {
                let n = db.find_node(&node)?;
                let on = match state.as_str() {
                    "on" => true,
                    "off" => false,
                    _ => bail!("say on or off"),
                };
                db.set_exit_node(n.id, on)?;
                println!(
                    "{}.{}: exit node {}",
                    n.name,
                    n.account,
                    if on {
                        "on (machines of its account can use it with `tcs up --exit-node`)"
                    } else {
                        "off"
                    }
                );
            }
            NodesCmd::Tag { node, tags } => {
                let n = db.find_node(&node)?;
                let tags: Vec<String> = tags.split(',').map(String::from).collect();
                let set = db.set_tags(n.id, &tags)?;
                println!(
                    "{}.{}: tags {}",
                    n.name,
                    n.account,
                    if set.is_empty() { "-".into() } else { set.join(",") }
                );
            }
        },
        Cmd::Rules(c) => match c {
            RulesCmd::List { account } => {
                println!("{:<4} {:<14} {:<20} {:<20} PORTS", "ID", "ACCOUNT", "FROM", "TO");
                for r in db.rules()? {
                    if account.as_ref().is_some_and(|a| *a != r.account) {
                        continue;
                    }
                    println!("{:<4} {:<14} {:<20} {:<20} {}", r.id, r.account, r.src, r.dst, r.ports);
                }
            }
            RulesCmd::Add {
                account,
                from,
                to,
                ports,
            } => {
                let first = !db.rules()?.iter().any(|r| r.account == account);
                let id = db.add_rule(&account, &from, &to, &ports)?;
                println!("added rule {id}");
                if first {
                    println!("note: {account} now allows only what its rules allow");
                }
            }
            RulesCmd::Delete { id } => {
                db.delete_rule(id)?;
                println!("deleted rule {id}");
            }
        },
        Cmd::Shares(c) => match c {
            SharesCmd::List => {
                println!(
                    "{:<4} {:<28} {:<14} {:<9} {:<20} CREATED",
                    "ID", "MACHINE", "SHARED WITH", "STATUS", "PORTS"
                );
                for s in db.shares()? {
                    println!(
                        "{:<4} {:<28} {:<14} {:<9} {:<20} {}",
                        s.id,
                        format!("{}.{}", s.node, s.owner),
                        s.account,
                        if s.accepted { "active" } else { "pending" },
                        s.ports,
                        fmt_time(Some(s.created))
                    );
                }
            }
            SharesCmd::Create { node, account, ports } => {
                let n = db.find_node(&node)?;
                let id = db.create_share(n.id, &account, &ports)?;
                println!(
                    "shared {}.{} with {account} (share {id}, pending until accepted)",
                    n.name, n.account
                );
                println!("accept on their behalf with: tc-control shares accept {id}");
            }
            SharesCmd::Accept { id } => {
                db.accept_share(id)?;
                println!("share {id} accepted");
            }
            SharesCmd::Ports { id, ports } => {
                let p = db.set_share_ports(id, &ports)?;
                println!("share {id}: ports {p}");
            }
            SharesCmd::Revoke { id } => {
                db.revoke_share(id)?;
                println!("share {id} revoked");
            }
        },
        Cmd::AdminToken => {
            println!("{}", db.new_admin_token()?);
            eprintln!("(shown once; it replaces any previous admin token and ends that token's sessions)");
        }
        Cmd::Invites(c) => match c {
            InvitesCmd::Create { days } => {
                if !(1..=90).contains(&days) {
                    bail!("--days must be 1 to 90");
                }
                println!("{}", db.create_invite(tailconnect::now_unix() + days as i64 * 86400)?);
            }
            InvitesCmd::List => {
                println!("{:<4} {:<22} {:<16} {:<12} CREATED", "ID", "CODE", "STATUS", "EXPIRES");
                let now = tailconnect::now_unix();
                for i in db.invites()? {
                    let state = match (&i.used_by, i.revoked, i.expires <= now) {
                        (Some(u), _, _) => format!("used by {u}"),
                        (None, true, _) => "revoked".into(),
                        (None, false, true) => "expired".into(),
                        _ => "unused".into(),
                    };
                    println!(
                        "{:<4} {:<22} {:<16} {:<12} {}",
                        i.id,
                        format!("{}…", i.prefix),
                        state,
                        fmt_time(Some(i.expires)),
                        fmt_time(Some(i.created))
                    );
                }
            }
            InvitesCmd::Revoke { id } => {
                db.revoke_invite(id)?;
                println!("invite {id} revoked");
            }
        },
        Cmd::Serve { .. } | Cmd::Fingerprint => unreachable!(),
    }
    Ok(())
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
            ip_pool,
            no_portal,
            signup,
            public_url,
            portal_hosts,
            portal_listen,
            acme_domain,
            acme_email,
            acme_staging,
            acme_directory,
            acme_ca_root,
            acme_dns,
            acme_http_listen,
        } => {
            let domain = domain.trim_matches('.').to_ascii_lowercase();
            if domain.is_empty() {
                bail!("--domain must not be empty");
            }
            let acme = match acme_domain {
                None => None,
                Some(d) => {
                    let domains = acme::parse_domains(&d)?;
                    let method = match (acme_dns.as_deref(), acme_http_listen) {
                        (Some("duckdns"), _) => {
                            let token = std::env::var("TC_DUCKDNS_TOKEN").unwrap_or_default();
                            if token.trim().is_empty() {
                                bail!("--acme-dns duckdns needs the DuckDNS token in TC_DUCKDNS_TOKEN");
                            }
                            if domains.len() != 1 || !domains[0].ends_with(".duckdns.org") {
                                bail!("--acme-dns duckdns takes one NAME.duckdns.org domain");
                            }
                            acme::Method::DuckDns {
                                token: token.trim().to_string(),
                            }
                        }
                        (Some(other), _) => bail!("--acme-dns: unknown provider {other:?} (only duckdns)"),
                        (None, Some(addr)) => acme::Method::Http(addr),
                        (None, None) => {
                            // TLS-ALPN-01: Let's Encrypt connects to port 443.
                            let public_443 = !public_url.is_empty()
                                && tailconnect::client::parse_server(&public_url).is_ok_and(|(_, p)| p == 443);
                            if listen.port() != 443 && !public_443 {
                                bail!(
                                    "Let's Encrypt checks the name on port 443, but --listen is port {}: listen on 443, \
                                     forward port 443 to this one and say so with --public-url HOST, use \
                                     --acme-http-listen [::]:80, or --acme-dns duckdns",
                                    listen.port()
                                );
                            }
                            acme::Method::TlsAlpn
                        }
                    };
                    let directory = match (acme_staging, acme_directory) {
                        (true, _) => acme::LETS_ENCRYPT_STAGING.to_string(),
                        (false, Some(d)) => d,
                        (false, None) => acme::LETS_ENCRYPT.to_string(),
                    };
                    Some(acme::Config {
                        domains,
                        email: acme_email.filter(|e| !e.trim().is_empty()),
                        directory,
                        ca_root: acme_ca_root,
                        method,
                        dir: cli.state_dir.join("acme"),
                    })
                }
            };
            // With Let's Encrypt, the self-signed certificate (for its names)
            // is served only until the first real one arrives.
            let tls_names = match (&acme, tls_names.is_empty()) {
                (Some(a), true) => a.domains.clone(),
                _ => tls_names,
            };
            let tls = load_tls(&cli.state_dir, tls_cert, tls_key, tls_names)?;
            let portal = if no_portal {
                None
            } else {
                Some(server::PortalOptions {
                    signup: Signup::parse(&signup)?,
                    public_server: public_url,
                    hosts: portal_hosts,
                    plain_listen: portal_listen,
                })
            };
            server::run(server::Options {
                listen,
                state_dir: cli.state_dir,
                domain,
                tls,
                portal,
                ip_pool: tailconnect::server::db::parse_pool(&ip_pool)?,
                acme,
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
        cmd => admin(&cli.state_dir, cmd),
    }
}
