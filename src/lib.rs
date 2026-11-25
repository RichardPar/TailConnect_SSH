//! TailConnect-SSH: a self-hosted mesh network that tunnels IP packets over
//! SSH, wrapped in TLS on port 443 so it passes through firewalls and proxies
//! that only allow HTTPS.
//!
//! * `tc-control` is the hub: it registers machines, hands out addresses,
//!   pushes the network map and relays packets between machines that have no
//!   direct path.
//! * `tcd` is the machine daemon: it keeps one SSH-over-TLS session to the hub,
//!   runs a TUN device, opens direct SSH sessions to peers it can reach, and
//!   answers MagicDNS queries.
//! * `tc` is the command-line front end to `tcd`.

pub mod acl;
pub mod client;
pub mod dns;
pub mod e2e;
pub mod filter;
pub mod frame;
pub mod keys;
pub mod packet;
pub mod proto;
pub mod server;
pub mod tls;
pub mod transport;

/// Protocol version spoken between `tcd` and `tc-control`.
/// Version 2: relayed packets are end-to-end encrypted (`SEALED` frames);
/// the hub no longer relays plaintext.
/// Version 3: accounts, sharing and access rules; peers carry `inbound`,
/// which the receiving machine's packet filter enforces.
pub const PROTOCOL_VERSION: u32 = 3;

/// The tailnet address range: 100.64.0.0/10 (carrier-grade NAT space).
pub const TAILNET_NET: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 64, 0, 0);
pub const TAILNET_PREFIX: u8 = 10;

/// The in-tunnel MagicDNS resolver address.
pub const MAGIC_DNS_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 100, 100, 100);

/// ALPN protocol id offered and required on every TLS connection.
pub const ALPN: &[u8] = b"tc-ssh/1";

/// Default MTU of the TUN device. Packets travel inside SSH inside TLS inside
/// TCP, so there is no fragmentation concern on the wire; 1400 keeps inner
/// TCP segments a sensible size.
pub const DEFAULT_MTU: u16 = 1400;

/// Is `ip` inside 100.64.0.0/10?
pub fn in_tailnet(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

/// Current Unix time in seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
