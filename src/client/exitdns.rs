//! DNS through exit nodes, on every platform: the exit node's forwarder,
//! and the queries a machine sends to its exit node.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Port of the exit node's DNS forwarder, on its tunnel address.
pub const DNS_PORT: u16 = 41653;

/// The host's resolvers, from /etc/resolv.conf.
pub fn system_resolvers() -> Vec<SocketAddr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|a| a.trim().parse::<std::net::IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

/// Answer DNS queries on `bind`:[`DNS_PORT`] for machines `allowed` to use
/// this exit node, by asking `upstreams` (in turn). Runs until cancelled.
pub async fn dns_forwarder(
    bind: Ipv4Addr,
    upstreams: Vec<SocketAddr>,
    allowed: Arc<dyn Fn(Ipv4Addr) -> bool + Send + Sync>,
    cancel: CancellationToken,
    mark: Option<u32>,
) {
    // The tunnel address may take a moment to be usable.
    let sock = loop {
        match tokio::net::UdpSocket::bind((bind, DNS_PORT)).await {
            Ok(s) => break Arc::new(s),
            Err(e) => {
                debug!("exit node DNS: binding {bind}:{DNS_PORT}: {e}");
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
        }
    };
    if upstreams.is_empty() {
        warn!("exit node DNS: no resolvers (see --exit-dns); lookups through this exit node will fail");
    } else {
        info!("exit node DNS: answering on {bind}:{DNS_PORT} with {upstreams:?}");
    }
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = tokio::select! {
            _ = cancel.cancelled() => return,
            r = sock.recv_from(&mut buf) => match r { Ok(x) => x, Err(_) => continue },
        };
        let std::net::IpAddr::V4(from_ip) = from.ip() else {
            continue;
        };
        if !allowed(from_ip) || n < 12 {
            continue;
        }
        let q = buf[..n].to_vec();
        let (sock, ups) = (sock.clone(), upstreams.clone());
        tokio::spawn(async move {
            for up in ups {
                if let Ok(a) = ask(up, &q, mark).await {
                    let _ = sock.send_to(&a, from).await;
                    return;
                }
            }
        });
    }
}

async fn ask(up: SocketAddr, q: &[u8], mark: Option<u32>) -> Result<Vec<u8>> {
    let local: SocketAddr = if up.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let s = tokio::net::UdpSocket::bind(local).await?;
    if let Some(m) = mark {
        // Out through the exit interface (and its kill switch) too.
        crate::transport::set_mark(&s, m);
    }
    s.send_to(q, up).await?;
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = tokio::time::timeout(Duration::from_secs(4), s.recv_from(&mut buf)).await??;
        // Only the server we asked, with the query's ID.
        if from == up && n >= 2 && buf[..2] == q[..2] {
            return Ok(buf[..n].to_vec());
        }
    }
}

/// Queries this machine sent to its exit node's DNS forwarder, to map the
/// answers back to MagicDNS: (client port, DNS ID) → when.
#[derive(Default)]
pub struct Pending(HashMap<(u16, u16), std::time::Instant>);

impl Pending {
    pub fn add(&mut self, port: u16, id: u16) {
        let now = std::time::Instant::now();
        if self.0.len() > 4096 {
            self.0.retain(|_, t| now.duration_since(*t) < Duration::from_secs(10));
        }
        self.0.insert((port, id), now);
    }

    pub fn take(&mut self, port: u16, id: u16) -> bool {
        self.0
            .remove(&(port, id))
            .is_some_and(|t| t.elapsed() < Duration::from_secs(10))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_dns_queries() {
        let mut p = Pending::default();
        p.add(5353, 7);
        assert!(!p.take(5353, 8));
        assert!(p.take(5353, 7));
        assert!(!p.take(5353, 7), "only once");
    }
}
