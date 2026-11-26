//! Telling a new network from a change on the same one, from the device's
//! addresses (and, on Android, the network's handle): on another network
//! the old connections are dead, so tcd reconnects at once rather than
//! waiting for them to time out.

use std::net::IpAddr;

/// This device's network: as the Android app reports it, or read from the
/// interfaces elsewhere.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Network {
    /// Android's handle for it (0: not reported yet).
    pub id: u64,
    pub dns: Vec<IpAddr>,
    pub addrs: Vec<(IpAddr, u8)>,
}

/// What a network report means for tcd.
#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    None,
    /// The same network, other addresses: re-report the endpoints.
    Addresses,
    /// Another network: reconnect (the old connections are dead).
    Network,
}

impl Network {
    /// How `new` differs from `self`, the network reported before (the
    /// Android app's reports; desktops use the outgoing address instead).
    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn change(&self, new: &Network) -> Change {
        let v4 = |n: &Network| -> Vec<IpAddr> {
            let mut v: Vec<IpAddr> = n.addrs.iter().map(|(a, _)| *a).filter(|a| a.is_ipv4()).collect();
            v.sort();
            v
        };
        let (old4, new4) = (v4(self), v4(new));
        let moved = (self.id != 0 && new.id != self.id)
            // The same network handle (or none yet) with entirely new IPv4
            // addresses: as good as a new network.
            || (!old4.is_empty() && !new4.is_empty() && !old4.iter().any(|a| new4.contains(a)));
        if moved {
            Change::Network
        } else if self.addrs != new.addrs {
            Change::Addresses
        } else {
            Change::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_changes() {
        let a = |s: &str| (s.parse::<IpAddr>().unwrap(), 24u8);
        let wifi = Network {
            id: 101,
            dns: vec![],
            addrs: vec![a("192.168.10.50"), a("fe80::1")],
        };
        let mut renewed = wifi.clone();
        renewed.addrs.push(a("2a00::5"));
        assert_eq!(wifi.change(&wifi), Change::None);
        assert_eq!(wifi.change(&renewed), Change::Addresses);
        let mobile = Network {
            id: 102,
            dns: vec![],
            addrs: vec![a("10.20.30.40")],
        };
        assert_eq!(wifi.change(&mobile), Change::Network);
        // No handle yet (from the command line), then the same network…
        let start = Network {
            id: 0,
            dns: vec![],
            addrs: vec![a("192.168.10.50")],
        };
        assert_eq!(start.change(&wifi), Change::Addresses);
        // …or a different one.
        assert_eq!(start.change(&mobile), Change::Network);
    }
}
