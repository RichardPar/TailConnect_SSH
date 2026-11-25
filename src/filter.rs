//! The receiving machine's stateful packet filter.
//!
//! Every packet that arrives for this machine (over a direct link, or
//! decrypted from the hub) passes through here before reaching the TUN
//! device. For each peer the hub says what that peer may open on this
//! machine ([`Access`]):
//!
//! * `All`: everything passes;
//! * otherwise, a packet passes if it belongs to a flow this machine
//!   started (TCP and UDP by address and ports, ping by identifier), opens a
//!   connection to an allowed port, is a ping and `icmp` is allowed, or is an
//!   ICMP error (needed for path-MTU discovery);
//! * a peer that isn't in the network map gets nothing at all.
//!
//! The filter runs on the receiver, so a compromised sender can't switch it
//! off. Packet sources can be trusted: direct links and end-to-end sessions
//! are bound to the peer's key, and its inner source address is checked
//! against it before this filter sees the packet.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::acl::{Access, PROTO_ICMP, PROTO_TCP, PROTO_UDP};

const TCP_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const TCP_CLOSED_TIMEOUT: Duration = Duration::from_secs(5);
const UDP_TIMEOUT: Duration = Duration::from_secs(120);
const ICMP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_FLOWS: usize = 65536;

const TCP_RST: u8 = 0x04;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_UNREACHABLE: u8 = 3;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_PARAM_PROBLEM: u8 = 12;

/// A flow this machine started: (peer, protocol, local port, peer port).
/// For ping, the local "port" is the echo identifier and the peer port 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    peer: Ipv4Addr,
    proto: u8,
    local: u16,
    remote: u16,
}

struct L4 {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    /// Not the first fragment: no transport header.
    later_fragment: bool,
    sport: u16,
    dport: u16,
    tcp_flags: u8,
    icmp_type: u8,
    icmp_id: u16,
}

fn parse(p: &[u8]) -> Option<L4> {
    let (src, dst) = crate::packet::ipv4_addrs(p)?;
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    let proto = p[9];
    let frag = u16::from_be_bytes([p[6], p[7]]) & 0x1fff;
    let mut l = L4 {
        src,
        dst,
        proto,
        later_fragment: frag != 0,
        sport: 0,
        dport: 0,
        tcp_flags: 0,
        icmp_type: 0,
        icmp_id: 0,
    };
    if l.later_fragment {
        return Some(l);
    }
    let t = p.get(ihl..)?;
    match proto {
        PROTO_TCP | PROTO_UDP => {
            l.sport = u16::from_be_bytes([*t.first()?, *t.get(1)?]);
            l.dport = u16::from_be_bytes([*t.get(2)?, *t.get(3)?]);
            if proto == PROTO_TCP {
                l.tcp_flags = *t.get(13)?;
            }
        }
        PROTO_ICMP => {
            l.icmp_type = *t.first()?;
            if matches!(l.icmp_type, ICMP_ECHO_REQUEST | ICMP_ECHO_REPLY) {
                l.icmp_id = u16::from_be_bytes([*t.get(4)?, *t.get(5)?]);
            }
        }
        _ => {}
    }
    Some(l)
}

#[derive(Default)]
pub struct Filter {
    /// What each peer may open on this machine. Peers not listed get nothing.
    peers: HashMap<Ipv4Addr, Access>,
    flows: HashMap<FlowKey, Instant>,
    dropped: u64,
    ops: u64,
}

impl Filter {
    /// Replace the peer policy. Flows with peers that are gone or now
    /// unrestricted are forgotten.
    pub fn set_peers(&mut self, peers: impl IntoIterator<Item = (Ipv4Addr, Access)>) {
        self.peers = peers.into_iter().collect();
        let peers = &self.peers;
        self.flows
            .retain(|k, _| peers.get(&k.peer).is_some_and(|a| !a.is_all()));
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// A packet this machine is sending: remember the flow if the peer is
    /// restricted, so its replies pass.
    pub fn outbound(&mut self, pkt: &[u8], now: Instant) {
        let Some(l) = parse(pkt) else { return };
        if self.peers.get(&l.dst).is_none_or(Access::is_all) || l.later_fragment {
            return;
        }
        let (key, ttl) = match l.proto {
            PROTO_TCP => {
                let ttl = if l.tcp_flags & TCP_RST != 0 {
                    TCP_CLOSED_TIMEOUT
                } else {
                    TCP_TIMEOUT
                };
                (
                    FlowKey {
                        peer: l.dst,
                        proto: PROTO_TCP,
                        local: l.sport,
                        remote: l.dport,
                    },
                    ttl,
                )
            }
            PROTO_UDP => (
                FlowKey {
                    peer: l.dst,
                    proto: PROTO_UDP,
                    local: l.sport,
                    remote: l.dport,
                },
                UDP_TIMEOUT,
            ),
            PROTO_ICMP if l.icmp_type == ICMP_ECHO_REQUEST => (
                FlowKey {
                    peer: l.dst,
                    proto: PROTO_ICMP,
                    local: l.icmp_id,
                    remote: 0,
                },
                ICMP_TIMEOUT,
            ),
            _ => return,
        };
        if self.flows.len() >= MAX_FLOWS && !self.flows.contains_key(&key) {
            self.sweep(now);
            if self.flows.len() >= MAX_FLOWS {
                return;
            }
        }
        self.flows.insert(key, now + ttl);
        self.maybe_sweep(now);
    }

    /// May this packet from a peer reach the TUN device?
    pub fn inbound(&mut self, pkt: &[u8], now: Instant) -> bool {
        let ok = self.check(pkt, now);
        if !ok {
            self.dropped += 1;
        }
        ok
    }

    fn check(&mut self, pkt: &[u8], now: Instant) -> bool {
        let Some(l) = parse(pkt) else { return false };
        let Some(access) = self.peers.get(&l.src) else {
            return false;
        };
        if access.is_all() {
            return true;
        }
        if l.later_fragment {
            return false;
        }
        match l.proto {
            PROTO_TCP | PROTO_UDP => {
                let key = FlowKey {
                    peer: l.src,
                    proto: l.proto,
                    local: l.dport,
                    remote: l.sport,
                };
                if let Some(exp) = self.flows.get_mut(&key)
                    && *exp > now
                {
                    if l.proto == PROTO_TCP && l.tcp_flags & TCP_RST != 0 {
                        *exp = now + TCP_CLOSED_TIMEOUT;
                    }
                    return true;
                }
                access.allows(l.proto, l.dport)
            }
            PROTO_ICMP => match l.icmp_type {
                ICMP_ECHO_REPLY => {
                    let key = FlowKey {
                        peer: l.src,
                        proto: PROTO_ICMP,
                        local: l.icmp_id,
                        remote: 0,
                    };
                    self.flows.get(&key).is_some_and(|e| *e > now)
                }
                ICMP_ECHO_REQUEST => access.allows(PROTO_ICMP, 0),
                ICMP_UNREACHABLE | ICMP_TIME_EXCEEDED | ICMP_PARAM_PROBLEM => true,
                _ => false,
            },
            _ => false,
        }
    }

    fn maybe_sweep(&mut self, now: Instant) {
        self.ops += 1;
        if self.ops.is_multiple_of(4096) {
            self.sweep(now);
        }
    }

    fn sweep(&mut self, now: Instant) {
        self.flows.retain(|_, e| *e > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    const PEER: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

    fn ip(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p.extend_from_slice(l4);
        p
    }

    fn tcp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&sport.to_be_bytes());
        t[2..4].copy_from_slice(&dport.to_be_bytes());
        t[12] = 0x50;
        t[13] = flags;
        ip(src, dst, PROTO_TCP, &t)
    }

    fn icmp(src: Ipv4Addr, dst: Ipv4Addr, ty: u8, id: u16) -> Vec<u8> {
        let mut t = vec![0u8; 8];
        t[0] = ty;
        t[4..6].copy_from_slice(&id.to_be_bytes());
        ip(src, dst, PROTO_ICMP, &t)
    }

    fn filter(a: &str) -> Filter {
        let mut f = Filter::default();
        let access = if a.is_empty() {
            Access::none()
        } else {
            Access::parse(a).unwrap()
        };
        f.set_peers([(PEER, access)]);
        f
    }

    #[test]
    fn replies_only() {
        let now = Instant::now();
        let mut f = filter("");
        assert!(
            !f.inbound(&tcp(PEER, ME, 5000, 22, 0x02), now),
            "SYN from no-initiate peer"
        );
        f.outbound(&tcp(ME, PEER, 40000, 80, 0x02), now);
        assert!(f.inbound(&tcp(PEER, ME, 80, 40000, 0x12), now), "SYN-ACK reply");
        assert!(!f.inbound(&tcp(PEER, ME, 80, 40001, 0x12), now), "other port");
        assert!(!f.inbound(&icmp(PEER, ME, ICMP_ECHO_REQUEST, 7), now));
        f.outbound(&icmp(ME, PEER, ICMP_ECHO_REQUEST, 9), now);
        assert!(f.inbound(&icmp(PEER, ME, ICMP_ECHO_REPLY, 9), now));
        assert!(!f.inbound(&icmp(PEER, ME, ICMP_ECHO_REPLY, 10), now));
        assert!(f.inbound(&icmp(PEER, ME, ICMP_UNREACHABLE, 0), now));
        assert!(
            !f.inbound(&tcp(PEER, ME, 80, 40000, 0x10), now + TCP_TIMEOUT * 2),
            "expired"
        );
        assert_eq!(f.dropped(), 5);
    }

    #[test]
    fn allowed_ports() {
        let now = Instant::now();
        let mut f = filter("tcp:22,icmp");
        assert!(f.inbound(&tcp(PEER, ME, 5000, 22, 0x02), now));
        assert!(!f.inbound(&tcp(PEER, ME, 5000, 23, 0x02), now));
        assert!(f.inbound(&icmp(PEER, ME, ICMP_ECHO_REQUEST, 1), now));
    }

    #[test]
    fn unknown_peers_get_nothing_and_all_gets_everything() {
        let now = Instant::now();
        let mut f = Filter::default();
        assert!(!f.inbound(&tcp(PEER, ME, 1, 2, 0x02), now));
        f.set_peers([(PEER, Access::All)]);
        assert!(f.inbound(&tcp(PEER, ME, 1, 2, 0x02), now));
    }

    #[test]
    fn reset_shortens_flow() {
        let now = Instant::now();
        let mut f = filter("");
        f.outbound(&tcp(ME, PEER, 40000, 80, 0x02), now);
        assert!(f.inbound(&tcp(PEER, ME, 80, 40000, TCP_RST), now));
        assert!(!f.inbound(&tcp(PEER, ME, 80, 40000, 0x10), now + Duration::from_secs(6)));
    }
}
