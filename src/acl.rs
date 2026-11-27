//! Access specifications shared by the hub (which computes them) and `tcd`
//! (whose packet filter enforces them).
//!
//! * A **port spec** is `*` (everything, including ping) or a comma-separated
//!   list of `22`, `8000-8100` (TCP and UDP), `tcp:443`, `udp:53`,
//!   `tcp:8000-8100`, `icmp` (ping).
//! * A **selector** names machines within an account: `*`, `tag:NAME` or a
//!   machine name.
//! * A **rule** is *from → to on ports*.

use std::fmt;
use std::str::FromStr;

use anyhow::{Result, anyhow, bail};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proto {
    Both,
    Tcp,
    Udp,
    Icmp,
}

/// One entry of a port spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortRule {
    pub proto: Proto,
    pub lo: u16,
    pub hi: u16,
}

impl FromStr for PortRule {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim().to_ascii_lowercase();
        if s == "icmp" {
            return Ok(PortRule {
                proto: Proto::Icmp,
                lo: 0,
                hi: 0,
            });
        }
        let (proto, range) = match s.split_once(':') {
            Some(("tcp", r)) => (Proto::Tcp, r),
            Some(("udp", r)) => (Proto::Udp, r),
            Some((p, _)) => bail!("unknown protocol {p:?} (use tcp, udp or icmp)"),
            None => (Proto::Both, s.as_str()),
        };
        let port = |p: &str| -> Result<u16> {
            match p.trim().parse::<u16>() {
                Ok(0) | Err(_) => Err(anyhow!("bad port {p:?}")),
                Ok(n) => Ok(n),
            }
        };
        let (lo, hi) = match range.split_once('-') {
            Some((a, b)) => (port(a)?, port(b)?),
            None => {
                let p = port(range)?;
                (p, p)
            }
        };
        if lo > hi {
            bail!("bad port range {range:?}");
        }
        Ok(PortRule { proto, lo, hi })
    }
}

impl fmt::Display for PortRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = match self.proto {
            Proto::Icmp => return write!(f, "icmp"),
            Proto::Both => "",
            Proto::Tcp => "tcp:",
            Proto::Udp => "udp:",
        };
        if self.lo == self.hi {
            write!(f, "{p}{}", self.lo)
        } else {
            write!(f, "{p}{}-{}", self.lo, self.hi)
        }
    }
}

impl PortRule {
    fn allows(&self, proto: u8, port: u16) -> bool {
        let p = match (self.proto, proto) {
            (Proto::Icmp, PROTO_ICMP) => return true,
            (Proto::Both, PROTO_TCP | PROTO_UDP) => true,
            (Proto::Tcp, PROTO_TCP) => true,
            (Proto::Udp, PROTO_UDP) => true,
            _ => false,
        };
        p && (self.lo..=self.hi).contains(&port)
    }
}

/// What one machine may open on another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// Everything.
    All,
    /// Only these; an empty list means nothing (replies only).
    Ports(Vec<PortRule>),
}

impl Default for Access {
    fn default() -> Self {
        Access::none()
    }
}

impl Access {
    pub fn none() -> Self {
        Access::Ports(Vec::new())
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Access::Ports(v) if v.is_empty())
    }

    pub fn is_all(&self) -> bool {
        matches!(self, Access::All)
    }

    /// Parse a port spec: `*`, or a comma-separated list.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.len() > 4096 {
            bail!("port list too long");
        }
        if spec == "*" || spec.eq_ignore_ascii_case("all") {
            return Ok(Access::All);
        }
        let mut v = Vec::new();
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if part == "*" {
                return Ok(Access::All);
            }
            v.push(part.parse()?);
            if v.len() > MAX_PORT_ENTRIES {
                bail!("at most {MAX_PORT_ENTRIES} entries in a port list (use ranges, such as tcp:8000-8100)");
            }
        }
        if v.is_empty() {
            bail!("empty port spec (use * for everything)");
        }
        v.sort();
        v.dedup();
        Ok(Access::Ports(v))
    }

    pub fn union(&mut self, other: &Access) {
        match (&mut *self, other) {
            (Access::All, _) => {}
            (_, Access::All) => *self = Access::All,
            (Access::Ports(a), Access::Ports(b)) => {
                a.extend_from_slice(b);
                a.sort();
                a.dedup();
            }
        }
    }

    /// May a new connection with this protocol and destination port (ICMP:
    /// an echo request) be opened?
    pub fn allows(&self, proto: u8, port: u16) -> bool {
        match self {
            Access::All => true,
            Access::Ports(v) => v.iter().any(|r| r.allows(proto, port)),
        }
    }

    /// Wire form: `["*"]` for everything, `[]` for nothing.
    pub fn to_wire(&self) -> Vec<String> {
        match self {
            Access::All => vec!["*".into()],
            Access::Ports(v) => v.iter().map(|r| r.to_string()).collect(),
        }
    }

    /// Parse the wire form. Entries that don't parse are ignored, so an
    /// unknown entry can only ever grant less: the filter fails closed.
    pub fn from_wire(v: &[String]) -> Self {
        if v.iter().any(|s| s == "*") {
            return Access::All;
        }
        let mut rules: Vec<PortRule> = v.iter().filter_map(|s| s.parse().ok()).collect();
        rules.sort();
        rules.dedup();
        Access::Ports(rules)
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Access::All => write!(f, "*"),
            Access::Ports(v) if v.is_empty() => write!(f, "nothing"),
            Access::Ports(v) => {
                let s: Vec<String> = v.iter().map(|r| r.to_string()).collect();
                write!(f, "{}", s.join(","))
            }
        }
    }
}

/// Which machines of an account a rule applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Any,
    Tag(String),
    Name(String),
}

impl Selector {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim().to_ascii_lowercase();
        if s == "*" {
            return Ok(Selector::Any);
        }
        if let Some(t) = s.strip_prefix("tag:") {
            return Ok(Selector::Tag(valid_label(t, "tag")?));
        }
        Ok(Selector::Name(valid_label(&s, "machine name")?))
    }

    pub fn matches(&self, name: &str, tags: &[String]) -> bool {
        match self {
            Selector::Any => true,
            Selector::Tag(t) => tags.iter().any(|x| x == t),
            Selector::Name(n) => n == name,
        }
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Selector::Any => write!(f, "*"),
            Selector::Tag(t) => write!(f, "tag:{t}"),
            Selector::Name(n) => write!(f, "{n}"),
        }
    }
}

/// A DNS-label-like name: `a-z0-9-`, 1 to 63 characters, no leading or
/// trailing `-`. Used for account names, machine names in selectors, tags.
/// The most entries a port list may have: every machine checks them on
/// every new connection, and they travel in every network map.
pub const MAX_PORT_ENTRIES: usize = 64;

pub fn valid_label(s: &str, what: &str) -> Result<String> {
    let s = s.trim().to_ascii_lowercase();
    let ok = !s.is_empty()
        && s.len() <= 63
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-');
    if !ok {
        bail!("bad {what} {s:?}: use 1-63 of a-z, 0-9 and -, not starting or ending with -");
    }
    Ok(s)
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub from: Selector,
    pub to: Selector,
    pub ports: Access,
}

impl Rule {
    pub fn compile(from: &str, to: &str, ports: &str) -> Result<Self> {
        Ok(Rule {
            from: Selector::parse(from)?,
            to: Selector::parse(to)?,
            ports: Access::parse(ports)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_specs() {
        let a = Access::parse("tcp:443, 22,8000-8100,udp:53,icmp").unwrap();
        assert!(a.allows(PROTO_TCP, 443));
        assert!(!a.allows(PROTO_UDP, 443));
        assert!(a.allows(PROTO_UDP, 22) && a.allows(PROTO_TCP, 8050));
        assert!(a.allows(PROTO_UDP, 53) && !a.allows(PROTO_TCP, 53));
        assert!(a.allows(PROTO_ICMP, 0));
        assert!(!a.allows(PROTO_TCP, 80));
        assert_eq!(Access::from_wire(&a.to_wire()), a);
        assert_eq!(Access::parse("*").unwrap(), Access::All);
        for bad in ["", "tcp:0", "sctp:5", "10-5", "tcp:x"] {
            assert!(Access::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn wire_fails_closed() {
        let a = Access::from_wire(&["tcp:22".into(), "future:thing".into()]);
        assert_eq!(a, Access::Ports(vec!["tcp:22".parse().unwrap()]));
        assert!(Access::from_wire(&[]).is_none());
    }

    #[test]
    fn union() {
        let mut a = Access::parse("tcp:22").unwrap();
        a.union(&Access::parse("tcp:22,icmp").unwrap());
        assert_eq!(a.to_string(), "tcp:22,icmp");
        a.union(&Access::All);
        assert!(a.is_all());
    }

    #[test]
    fn selectors() {
        let tags = vec!["server".to_string()];
        assert!(Selector::parse("*").unwrap().matches("x", &[]));
        assert!(Selector::parse("tag:server").unwrap().matches("x", &tags));
        assert!(!Selector::parse("tag:db").unwrap().matches("x", &tags));
        assert!(Selector::parse("Web").unwrap().matches("web", &[]));
        assert!(Selector::parse("tag:").is_err() && Selector::parse("a b").is_err());
    }
}
