//! Minimal IPv4 header handling: enough to route packets and answer DNS.

use std::net::Ipv4Addr;

pub const PROTO_UDP: u8 = 17;

/// Source and destination of an IPv4 packet, or `None` if it isn't one.
pub fn ipv4_addrs(p: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    Some((src, dst))
}

/// A UDP datagram inside an IPv4 packet.
pub struct Udp<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp(p: &[u8]) -> Option<Udp<'_>> {
    let (src, dst) = ipv4_addrs(p)?;
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    if p[9] != PROTO_UDP || ihl < 20 || p.len() < ihl + 8 {
        return None;
    }
    // Fragmented packets are not ours to answer.
    let frag = u16::from_be_bytes([p[6], p[7]]);
    if frag & 0x3fff != 0 {
        return None;
    }
    let total = (u16::from_be_bytes([p[2], p[3]]) as usize).min(p.len());
    let u = &p[ihl..total];
    let ulen = (u16::from_be_bytes([u[4], u[5]]) as usize).min(u.len());
    if ulen < 8 {
        return None;
    }
    Some(Udp {
        src,
        dst,
        sport: u16::from_be_bytes([u[0], u[1]]),
        dport: u16::from_be_bytes([u[2], u[3]]),
        payload: &u[8..ulen],
    })
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in data.chunks(2) {
        let w = if c.len() == 2 {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from_be_bytes([c[0], 0])
        };
        sum += w as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv4/UDP packet.
pub fn build_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6] = 0x40; // don't fragment
    p[8] = 64; // TTL
    p[9] = PROTO_UDP;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let c = checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    // UDP checksum over the pseudo-header.
    let mut ph = Vec::with_capacity(12 + 8 + payload.len());
    ph.extend_from_slice(&src.octets());
    ph.extend_from_slice(&dst.octets());
    ph.extend_from_slice(&[0, PROTO_UDP]);
    ph.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    ph.extend_from_slice(&p[20..]);
    let mut uc = checksum(&ph);
    if uc == 0 {
        uc = 0xffff;
    }
    p[26..28].copy_from_slice(&uc.to_be_bytes());
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_round_trip() {
        let a = Ipv4Addr::new(100, 64, 0, 1);
        let b = Ipv4Addr::new(100, 100, 100, 100);
        let p = build_udp(a, b, 5353, 53, b"hello");
        assert_eq!(checksum(&p[..20]), 0, "IPv4 header checksum verifies");
        let u = parse_udp(&p).unwrap();
        assert_eq!(
            (u.src, u.dst, u.sport, u.dport, u.payload),
            (a, b, 5353, 53, &b"hello"[..])
        );
    }
}
