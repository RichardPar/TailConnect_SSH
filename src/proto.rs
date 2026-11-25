//! Control messages exchanged between `tcd` and `tc-control` as JSON inside
//! `CONTROL` frames.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

/// A machine on the network, as the hub describes it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node {
    /// Short name, unique on the server (`laptop`).
    pub name: String,
    /// Tailnet address.
    pub ip: Ipv4Addr,
    /// SSH public key in OpenSSH form (`ssh-ed25519 AAAA...`). For direct
    /// sessions this is both the peer's host key and its client key.
    pub key: String,
    /// Whether the machine currently has a session to the hub.
    #[serde(default)]
    pub online: bool,
    /// Addresses where the machine accepts direct SSH sessions.
    #[serde(default)]
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// First message on every hub session.
    Hello {
        version: u32,
        hostname: String,
        /// Needed only when this machine key is not registered yet.
        #[serde(default)]
        auth_key: Option<String>,
        /// Local addresses where direct sessions are accepted.
        #[serde(default)]
        endpoints: Vec<SocketAddr>,
        /// Port of the direct listener (0 = none). The hub adds the address
        /// it sees the machine connecting from, with this port.
        #[serde(default)]
        listen_port: u16,
    },
    /// The machine's direct endpoints changed.
    Endpoints {
        endpoints: Vec<SocketAddr>,
        listen_port: u16,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Registration accepted: this is who you are.
    Welcome {
        node: Node,
        /// MagicDNS domain (`tc.internal`).
        domain: String,
        prefix_len: u8,
    },
    /// The full list of peers. Sent after `Welcome` and whenever it changes.
    NetMap { peers: Vec<Node> },
    /// Fatal error; the hub closes the session after sending it.
    Error { message: String },
}

/// Fully qualified MagicDNS name.
pub fn fqdn(name: &str, domain: &str) -> String {
    format!("{name}.{domain}")
}
