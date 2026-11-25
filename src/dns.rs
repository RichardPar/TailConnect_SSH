//! MagicDNS: a tiny resolver answering for tailnet names, reached in-tunnel
//! at 100.100.100.100:53, from the local network map only.
//!
//! Every machine is `name.ZONE`, where its account's zone is
//! `account.<domain>` or the account's own domain (`acme.internal`).
//! Relative names work too: `name.account`, and plain `name` for machines
//! of this machine's own account.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_PTR: u16 = 12;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;
const RCODE_FORMERR: u8 = 1;
const TTL: u32 = 60;

/// Names this machine can resolve.
#[derive(Debug, Default, Clone)]
pub struct Zone {
    /// The hub's domain: every account's default zone is under it.
    pub domain: String,
    /// This machine's account: its machines also resolve by bare name.
    pub account: String,
    /// Full names (`name.zone`) → address.
    pub fqdns: HashMap<String, Ipv4Addr>,
    /// Relative names (`name.account`, and `name` for our own account) → address.
    pub relative: HashMap<String, Ipv4Addr>,
    /// Every zone with a machine in it.
    pub zones: HashSet<String>,
}

impl Zone {
    pub fn insert(&mut self, name: &str, account: &str, zone: &str, ip: Ipv4Addr) {
        let zone = if zone.is_empty() {
            format!("{account}.{}", self.domain)
        } else {
            zone.to_string()
        };
        self.fqdns.insert(format!("{name}.{zone}"), ip);
        self.relative.insert(format!("{name}.{account}"), ip);
        if account == self.account {
            self.relative.insert(name.to_string(), ip);
        }
        self.zones.insert(zone);
    }

    /// The zones names should be routed here for: the hub's domain (it holds
    /// every default zone) and every account's own domain outside it.
    pub fn routed_zones(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .zones
            .iter()
            .filter(|z| **z != self.domain && !z.ends_with(&format!(".{}", self.domain)))
            .cloned()
            .collect();
        v.sort();
        v.insert(0, self.domain.clone());
        v
    }

    fn lookup(&self, qname: &str) -> Lookup {
        let q = qname.trim_end_matches('.').to_ascii_lowercase();
        if let Some(ip) = self.fqdns.get(&q) {
            return Lookup::Found(*ip);
        }
        // A zone itself exists (it holds machines) but has no address.
        if q == self.domain || self.zones.contains(&q) {
            return Lookup::NoData;
        }
        let ours =
            q.ends_with(&format!(".{}", self.domain)) || self.zones.iter().any(|z| q.ends_with(&format!(".{z}")));
        if ours {
            return Lookup::NxDomain;
        }
        match self.relative.get(&q) {
            Some(ip) => Lookup::Found(*ip),
            None if !q.contains('.') => Lookup::NxDomain,
            None => Lookup::NotOurs,
        }
    }

    fn reverse(&self, qname: &str) -> Option<String> {
        let q = qname.trim_end_matches('.').to_ascii_lowercase();
        let rev = q.strip_suffix(".in-addr.arpa")?;
        let o: Vec<u8> = rev.split('.').rev().map(|x| x.parse().ok()).collect::<Option<_>>()?;
        if o.len() != 4 {
            return None;
        }
        let ip = Ipv4Addr::new(o[0], o[1], o[2], o[3]);
        self.fqdns.iter().find(|(_, v)| **v == ip).map(|(k, _)| k.clone())
    }
}

enum Lookup {
    Found(Ipv4Addr),
    NoData,
    NxDomain,
    NotOurs,
}

fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    loop {
        let len = *msg.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None; // no compression in questions
        }
        let l = msg.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(l).into_owned());
        pos += len;
        if labels.len() > 127 {
            return None;
        }
    }
    Some((labels.join("."), pos))
}

fn encode_name(name: &str, out: &mut Vec<u8>) {
    for l in name.trim_end_matches('.').split('.') {
        out.push(l.len() as u8);
        out.extend_from_slice(l.as_bytes());
    }
    out.push(0);
}

/// Is the query for MagicDNS (a tailnet name, or a reverse lookup of a
/// tunnel address)? Other names go to the exit node, when one is in use.
pub fn is_local(zone: &Zone, q: &[u8]) -> bool {
    let Some((name, _)) = read_name(q, 12) else { return true };
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rev) = n.strip_suffix(".in-addr.arpa") {
        let o: Vec<u8> = rev.split('.').rev().filter_map(|x| x.parse().ok()).collect();
        return o.len() == 4 && crate::in_tailnet(Ipv4Addr::new(o[0], o[1], o[2], o[3]));
    }
    if n.ends_with(".ip6.arpa") {
        // fd74:6373:7368::/48, as nibbles reversed: 8.6.3.7.3.7.3.6.4.7.d.f.ip6.arpa
        return n.ends_with("8.6.3.7.3.7.3.6.4.7.d.f.ip6.arpa");
    }
    !matches!(zone.lookup(&n), Lookup::NotOurs)
}

/// Answer one DNS query message. Returns `None` for things that aren't queries.
pub fn answer(zone: &Zone, q: &[u8]) -> Option<Vec<u8>> {
    if q.len() < 12 || q[2] & 0x80 != 0 {
        return None; // too short, or a response
    }
    let qd = u16::from_be_bytes([q[4], q[5]]);
    let mut resp = Vec::with_capacity(128);
    resp.extend_from_slice(&q[0..2]); // id
    let rd = q[2] & 0x01;
    let header = |rcode: u8, an: u16, resp: &mut Vec<u8>| {
        resp.truncate(2);
        resp.push(0x80 | 0x04 | rd); // QR, AA, RD copied
        resp.push(0x80 | rcode); // RA
        resp.extend_from_slice(&[0, 1]);
        resp.extend_from_slice(&an.to_be_bytes());
        resp.extend_from_slice(&[0, 0, 0, 0]);
    };
    if qd != 1 {
        header(RCODE_FORMERR, 0, &mut resp);
        resp[5] = 0; // qdcount 0
        return Some(resp);
    }
    let (name, pos) = read_name(q, 12)?;
    let qtype = u16::from_be_bytes([*q.get(pos)?, *q.get(pos + 1)?]);
    let question = &q[12..pos + 4];

    let mut answers = Vec::new();
    let mut an: u16 = 0;
    let rcode;
    if qtype == TYPE_PTR {
        match zone.reverse(&name) {
            Some(target) => {
                let mut rdata = Vec::new();
                encode_name(&target, &mut rdata);
                push_rr(&mut answers, &mut an, TYPE_PTR, &rdata);
                rcode = 0;
            }
            None => {
                rcode = if name.ends_with("in-addr.arpa") {
                    RCODE_NXDOMAIN
                } else {
                    RCODE_REFUSED
                }
            }
        }
    } else {
        rcode = match zone.lookup(&name) {
            Lookup::Found(ip) => {
                if qtype == TYPE_A || qtype == 255 {
                    push_rr(&mut answers, &mut an, TYPE_A, &ip.octets());
                }
                if qtype == TYPE_AAAA || qtype == 255 {
                    push_rr(&mut answers, &mut an, TYPE_AAAA, &crate::ip6_of(ip).octets());
                }
                0
            }
            Lookup::NoData => 0,
            Lookup::NxDomain => RCODE_NXDOMAIN,
            Lookup::NotOurs => RCODE_REFUSED,
        };
    }
    header(rcode, an, &mut resp);
    resp.extend_from_slice(question);
    resp.extend_from_slice(&answers);
    Some(resp)
}

fn push_rr(out: &mut Vec<u8>, count: &mut u16, ty: u16, rdata: &[u8]) {
    *count += 1;
    out.extend_from_slice(&[0xc0, 12]); // pointer to the question name
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&[0, 1]); // IN
    out.extend_from_slice(&TTL.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, ty: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        encode_name(name, &mut q);
        q.extend_from_slice(&ty.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    fn zone() -> Zone {
        let mut z = Zone {
            domain: "tc.internal".into(),
            account: "richard".into(),
            ..Default::default()
        };
        z.insert("laptop", "richard", "", Ipv4Addr::new(100, 64, 0, 2));
        z.insert("nas", "alice", "", Ipv4Addr::new(100, 64, 0, 9));
        z
    }

    #[test]
    fn answers_fqdn_and_relative_names() {
        for n in [
            "laptop.richard.tc.internal",
            "LAPTOP.richard.tc.internal.",
            "laptop",
            "laptop.richard",
        ] {
            let r = answer(&zone(), &query(n, TYPE_A)).unwrap();
            assert_eq!(r[3] & 0x0f, 0, "{n}");
            assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1);
            assert_eq!(&r[r.len() - 4..], &[100, 64, 0, 2]);
        }
    }

    #[test]
    fn aaaa_answers_carry_the_derived_ipv6_address() {
        let r = answer(&zone(), &query("laptop", TYPE_AAAA)).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1);
        assert_eq!(
            &r[r.len() - 16..],
            &crate::ip6_of(Ipv4Addr::new(100, 64, 0, 2)).octets()
        );
        let r = answer(&zone(), &query("laptop", 255)).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 2, "ANY: A and AAAA");
    }

    #[test]
    fn other_accounts_need_the_account() {
        for n in ["nas.alice.tc.internal", "nas.alice"] {
            let r = answer(&zone(), &query(n, TYPE_A)).unwrap();
            assert_eq!(&r[r.len() - 4..], &[100, 64, 0, 9], "{n}");
        }
        let r = answer(&zone(), &query("nas", TYPE_A)).unwrap();
        assert_eq!(r[3] & 0x0f, RCODE_NXDOMAIN);
        let r = answer(&zone(), &query("alice.tc.internal", TYPE_A)).unwrap();
        assert_eq!((r[3] & 0x0f, r[7]), (0, 0), "account name: no data");
    }

    #[test]
    fn accounts_with_their_own_domain() {
        let mut z = zone();
        z.insert("web", "acme", "acme.internal", Ipv4Addr::new(100, 64, 0, 7));
        for n in ["web.acme.internal", "web.acme"] {
            let r = answer(&z, &query(n, TYPE_A)).unwrap();
            assert_eq!(&r[r.len() - 4..], &[100, 64, 0, 7], "{n}");
        }
        let r = answer(&z, &query("web.acme.tc.internal", TYPE_A)).unwrap();
        assert_eq!(r[3] & 0x0f, RCODE_NXDOMAIN, "not under the default zone any more");
        let r = answer(&z, &query("nope.acme.internal", TYPE_A)).unwrap();
        assert_eq!(r[3] & 0x0f, RCODE_NXDOMAIN, "the account's domain is ours");
        assert!(is_local(&z, &query("nope.acme.internal", TYPE_A)));
        assert_eq!(z.routed_zones(), vec!["tc.internal", "acme.internal"]);
        let r = answer(&z, &query("7.0.64.100.in-addr.arpa", TYPE_PTR)).unwrap();
        assert!(r.windows(4).any(|w| w == b"acme"), "PTR gives the full name");
    }

    #[test]
    fn nxdomain_and_refused() {
        let r = answer(&zone(), &query("nope.richard.tc.internal", TYPE_A)).unwrap();
        assert_eq!(r[3] & 0x0f, RCODE_NXDOMAIN);
        let r = answer(&zone(), &query("laptop.tc.internal", TYPE_A)).unwrap();
        assert_eq!(r[3] & 0x0f, RCODE_NXDOMAIN);
        let r = answer(&zone(), &query("example.com", TYPE_A)).unwrap();
        assert_eq!(r[3] & 0x0f, RCODE_REFUSED);
    }

    #[test]
    fn which_names_stay_local() {
        let z = zone();
        assert!(is_local(&z, &query("laptop", TYPE_A)));
        assert!(
            is_local(&z, &query("nope.richard.tc.internal", TYPE_A)),
            "ours, even if it doesn't exist"
        );
        assert!(!is_local(&z, &query("example.com", TYPE_A)));
        assert!(is_local(&z, &query("2.0.64.100.in-addr.arpa", TYPE_PTR)));
        assert!(!is_local(&z, &query("1.1.168.192.in-addr.arpa", TYPE_PTR)));
    }

    #[test]
    fn reverse_lookup() {
        let r = answer(&zone(), &query("2.0.64.100.in-addr.arpa", TYPE_PTR)).unwrap();
        assert_eq!(r[3] & 0x0f, 0);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1);
    }
}
