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
pub mod knock;
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

/// ALPN protocol id that older `tcd` offered on every TLS connection. Still
/// accepted, and offered again when a server from before SSH sniffing turns
/// down the browser ALPN that `tcd` now offers ([`tls::ALPN_CLIENT`]).
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

/// The tunnel's IPv6 range, a ULA /48. Each machine's IPv6 address is its
/// IPv4 address in the last 32 bits, so only IPv4 needs allocating. (A
/// different prefix from the WireGuard TailConnect's, so both can run on one
/// machine.)
pub const TAILNET6: std::net::Ipv6Addr = std::net::Ipv6Addr::new(0xfd74, 0x6373, 0x7368, 0, 0, 0, 0, 0);
pub const TAILNET6_PREFIX: u8 = 48;

/// The IPv6 address that goes with a tailnet IPv4 address.
pub fn ip6_of(v4: std::net::Ipv4Addr) -> std::net::Ipv6Addr {
    let p = TAILNET6.segments();
    let o = v4.octets();
    std::net::Ipv6Addr::new(
        p[0],
        p[1],
        p[2],
        0,
        0,
        0,
        u16::from_be_bytes([o[0], o[1]]),
        u16::from_be_bytes([o[2], o[3]]),
    )
}

/// Is `ip` inside the tunnel's IPv6 range?
pub fn in_tailnet6(ip: std::net::Ipv6Addr) -> bool {
    ip.segments()[..3] == TAILNET6.segments()[..3]
}

/// The machine (by its IPv4 address) a tunnel address belongs to: itself for
/// IPv4, the embedded IPv4 address for IPv6.
pub fn machine_of(ip: std::net::IpAddr) -> Option<std::net::Ipv4Addr> {
    match ip {
        std::net::IpAddr::V4(v4) if in_tailnet(v4) => Some(v4),
        std::net::IpAddr::V6(v6) if in_tailnet6(v6) => {
            let s = v6.segments();
            if s[3..6] != [0, 0, 0] {
                return None;
            }
            let v4 = std::net::Ipv4Addr::from(((s[6] as u32) << 16) | s[7] as u32);
            in_tailnet(v4).then_some(v4)
        }
        _ => None,
    }
}

/// Current Unix time in seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Options for a file only its owner may read: mode 0600 on Unix. (On
/// Windows, tcd's state folder is limited to SYSTEM and Administrators.)
pub fn private_file(o: &mut std::fs::OpenOptions) -> &mut std::fs::OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}

/// Standard base64 (for PowerShell's -EncodedCommand on Windows).
pub fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(&[0xff, 0xfe, 0x00]), "//4A");
    }

    #[test]
    fn ipv6_addresses_follow_ipv4() {
        let v4 = Ipv4Addr::new(100, 96, 0, 2);
        let v6 = ip6_of(v4);
        assert_eq!(v6.to_string(), "fd74:6373:7368::6460:2");
        assert_eq!(machine_of(IpAddr::V6(v6)), Some(v4));
        assert_eq!(machine_of(IpAddr::V4(v4)), Some(v4));
        assert_eq!(machine_of("fd74:6373:7368:1::6460:2".parse().unwrap()), None);
        assert_eq!(machine_of("2001:db8::1".parse().unwrap()), None);
        assert_eq!(machine_of("8.8.8.8".parse().unwrap()), None);
    }
}
