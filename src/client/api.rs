//! The local API between `tc` and `tcd`: one JSON request line, one JSON
//! response line, over a Unix socket.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::proto::Node;

pub const DEFAULT_SOCKET: &str = "/run/tailconnect/tcd.sock";

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
    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub name: String,
    pub ip: Ipv4Addr,
    pub online: bool,
    /// `direct`, `hub` or `-` (offline).
    pub path: String,
    pub endpoints: Vec<SocketAddr>,
    /// An end-to-end session for relayed traffic is established.
    #[serde(default)]
    pub e2e: bool,
}

/// Send one request to `tcd`.
pub async fn call(socket: &Path, req: &Request) -> Result<Response> {
    let s = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to tcd at {} (is tcd running?)", socket.display()))?;
    let (r, mut w) = s.into_split();
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
