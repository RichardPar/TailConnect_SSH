//! The local API between `tc` and `tcd`: one JSON request line, one JSON
//! response line, over a Unix socket (Linux) or a named pipe (Windows).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::proto::Node;

#[cfg(unix)]
pub const DEFAULT_SOCKET: &str = "/run/tailconnect-ssh/tcd.sock";
#[cfg(windows)]
pub const DEFAULT_SOCKET: &str = r"\\.\pipe\tailconnect-ssh";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Connect (and register, given an auth key).
    Up {
        #[serde(default)]
        server: Option<String>,
        #[serde(default)]
        auth_key: Option<String>,
        #[serde(default)]
        tls_fingerprint: Option<String>,
        /// Send internet traffic through this exit node ("" for none).
        #[serde(default)]
        exit_node: Option<String>,
    },
    /// Disconnect, keeping the registration.
    Down,
    /// Disconnect and forget the server and its keys.
    Logout,
    Status,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Status {
    /// `stopped`, `connecting`, `running` or `needs-login`.
    pub phase: String,
    pub server: Option<String>,
    pub me: Option<Node>,
    pub domain: String,
    pub tun: Option<String>,
    pub direct_port: u16,
    pub last_error: Option<String>,
    /// From the hub, for example when this machine's account is suspended.
    #[serde(default)]
    pub notice: Option<String>,
    /// Packets the filter dropped since tcd started.
    #[serde(default)]
    pub filter_dropped: u64,
    /// The chosen exit node, as given.
    #[serde(default)]
    pub exit_node: Option<String>,
    /// The exit node internet traffic goes through now (name.account).
    #[serde(default)]
    pub exit_in_use: Option<String>,
    /// Why the chosen exit node isn't in use.
    #[serde(default)]
    pub exit_problem: Option<String>,
    /// This machine forwards internet traffic for its account.
    #[serde(default)]
    pub exit_serving: bool,
    /// The interface forwarded traffic leaves through, if one is set.
    #[serde(default)]
    pub exit_interface: Option<String>,
    /// Why forwarded traffic is blocked right now (the kill switch).
    #[serde(default)]
    pub exit_interface_problem: Option<String>,
    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub name: String,
    /// Full MagicDNS name.
    #[serde(default)]
    pub fqdn: String,
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// What this peer may open on this machine (`["*"]` = everything).
    #[serde(default)]
    pub inbound: Vec<String>,
    pub ip: Ipv4Addr,
    pub online: bool,
    /// `direct`, `hub` or `-` (offline).
    pub path: String,
    pub endpoints: Vec<SocketAddr>,
    /// The peer offers to be this machine's exit node.
    #[serde(default)]
    pub exit_node: bool,
    /// This machine (an exit node) may carry the peer's internet traffic.
    #[serde(default)]
    pub exit_client: bool,
    /// An end-to-end session for relayed traffic is established.
    #[serde(default)]
    pub e2e: bool,
    /// Bytes received from and sent to the peer since the tunnel started.
    #[serde(default)]
    pub rx: u64,
    #[serde(default)]
    pub tx: u64,
}

/// Send one request to `tcd`.
pub async fn call(socket: &Path, req: &Request) -> Result<Response> {
    let s = connect(socket).await?;
    let (r, mut w) = tokio::io::split(s);
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    let mut r = BufReader::new(r);
    let mut out = String::new();
    r.read_line(&mut out).await?;
    if out.is_empty() {
        return Err(anyhow!("tcd closed the connection"));
    }
    Ok(serde_json::from_str(&out)?)
}

#[cfg(unix)]
async fn connect(socket: &Path) -> Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to tcd at {} (is tcd running?)", socket.display()))
}

#[cfg(windows)]
async fn connect(socket: &Path) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    const ERROR_PIPE_BUSY: i32 = 231;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(socket.as_os_str()) {
            Ok(c) => return Ok(c),
            // Every instance is busy for a moment: try again shortly.
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && std::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "connecting to the TailConnect-SSH service at {} (is it running?)",
                        socket.display()
                    )
                });
            }
        }
    }
}
