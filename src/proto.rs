//! Control messages exchanged between `tcd` and `tc-control` as JSON inside
//! `CONTROL` frames.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

/// A machine on the network, as the hub describes it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node {
    /// Short name, unique within its account (`laptop`).
    pub name: String,
    /// The account (network) the machine belongs to.
    #[serde(default)]
    pub account: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
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
    /// What this peer may open on the receiving machine, as a port spec
    /// list (see [`crate::acl::Access::to_wire`]): `["*"]` for everything,
    /// empty for replies only. A missing field means replies only, so the
    /// receiver's packet filter fails closed.
    #[serde(default)]
    pub inbound: Vec<String>,
    /// In a machine's own entry: it should route internet traffic for its
    /// account. In a peer's entry: the peer offers to be this machine's
    /// exit node.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exit_node: bool,
    /// In a peer's entry, in an exit node's map: the peer may send its
    /// internet traffic through this machine (its own account's machines,
    /// and those of accounts it's shared with as an exit node).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exit_client: bool,
    /// In a machine's own entry: when its key expires (Unix time; absent:
    /// never).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,
    /// The machine's MagicDNS zone: `ACCOUNT.<hub domain>`, or its account's
    /// own domain. Its full name is `NAME.ZONE`. (Empty from older hubs: use
    /// `ACCOUNT.<domain>`.)
    #[serde(default)]
    pub zone: String,
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
    /// Bytes exchanged with each peer since the tunnel started, for the
    /// portal's traffic view. Sent every 30 seconds while the counts change.
    /// Only counts: nothing about what the traffic is.
    Traffic { peers: Vec<PeerTraffic> },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerTraffic {
    pub ip: Ipv4Addr,
    /// Bytes received from the peer.
    pub rx: u64,
    /// Bytes sent to the peer.
    pub tx: u64,
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
    NetMap {
        peers: Vec<Node>,
        /// Why the map is empty or limited (for example a suspended account).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notice: Option<String>,
    },
    /// Fatal error; the hub closes the session after sending it.
    Error { message: String },
}

/// Fully qualified MagicDNS name: `name.account.domain`.
pub fn fqdn(name: &str, account: &str, domain: &str) -> String {
    format!("{name}.{account}.{domain}")
}
