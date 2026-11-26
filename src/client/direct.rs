//! Direct SSH-in-TLS sessions between peers.
//!
//! Every machine listens on its direct port with its machine key as SSH host
//! key, and accepts only clients whose key is in its network map. Each side
//! also tries to dial the other's reported endpoints, checking the host key
//! against the network map. When both succeed at once, both sides keep the
//! link dialled by the machine with the smaller key.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::AsyncRead;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

use super::{Daemon, Link};
use crate::frame::{self, Frame};
use crate::keys::key_id;
use crate::proto::Node;
use crate::transport::{self, HostKey, KeyPolicy};

const RETRY: Duration = Duration::from_secs(30);

pub async fn listen(d: Arc<Daemon>) -> Result<()> {
    let port = d.opts.direct_port;
    let listener = match TcpListener::bind(("::", port)).await {
        Ok(l) => l,
        Err(_) => TcpListener::bind(("0.0.0.0", port))
            .await
            .with_context(|| format!("binding port {port}"))?,
    };
    info!("direct sessions on port {port}");
    let tls = TlsAcceptor::from(crate::tls::server_ephemeral()?.config);
    let ssh = transport::server_ssh_config((*d.key).clone());
    let dw = Arc::downgrade(&d);
    let policy: KeyPolicy = Arc::new(move |k| dw.upgrade().is_some_and(|d| d.peer_ip_by_key(&key_id(k)).is_some()));
    loop {
        let (tcp, addr) = listener.accept().await?;
        // Replies on accepted sessions must use the real network too, not an
        // exit node's routes.
        crate::transport::set_mark(&tcp, super::exit::MARK);
        crate::transport::fail_fast(&tcp);
        let (d, tls, ssh, policy) = (d.clone(), tls.clone(), ssh.clone(), policy.clone());
        tokio::spawn(async move {
            match transport::accept(tcp, tls, ssh, policy).await {
                Ok(conn) => {
                    let key = key_id(&conn.client_key);
                    let Some(ip) = d.peer_ip_by_key(&key) else { return };
                    let transport::ServerConn { handle, stream, .. } = conn;
                    run_link(d, ip, key.clone(), key, stream, addr).await;
                    let _ = handle
                        .disconnect(russh::Disconnect::ByApplication, String::new(), "en".into())
                        .await;
                }
                Err(e) => debug!("direct from {addr}: {e:#}"),
            }
        });
    }
}

/// Periodically try to open direct links to online peers that have none.
pub async fn dialer(d: Arc<Daemon>) {
    loop {
        tokio::select! {
            _ = d.map_changed.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
        if d.hub_tx.read().unwrap().is_none() {
            continue;
        }
        let now = Instant::now();
        let todo: Vec<Node> = {
            let mut net = d.net.write().unwrap();
            net.peers
                .values_mut()
                .filter(|p| p.node.online && p.direct.is_none() && !p.node.endpoints.is_empty())
                .filter(|p| p.last_attempt.is_none_or(|t| now.duration_since(t) > RETRY))
                .map(|p| {
                    p.last_attempt = Some(now);
                    p.node.clone()
                })
                .collect()
        };
        for n in todo {
            tokio::spawn(dial(d.clone(), n));
        }
    }
}

async fn dial(d: Arc<Daemon>, n: Node) {
    let Ok(tls) = crate::tls::client_config(crate::tls::Verify::Any) else {
        return;
    };
    for ep in &n.endpoints {
        // Never a tunnel address (IPv4 or IPv6): that would be a "direct"
        // session running inside the tunnel itself.
        if crate::machine_of(ep.ip()).is_some() || ep.ip() == std::net::IpAddr::V4(crate::MAGIC_DNS_IP) {
            continue;
        }
        // The address as the server name: no SNI is sent, as for any
        // HTTPS connection to an IP address.
        let r = transport::dial(
            *ep,
            &ep.ip().to_string(),
            tls.clone(),
            d.key.clone(),
            "peer",
            HostKey::Pinned(n.key.clone()),
            Duration::from_secs(3),
        )
        .await;
        match r {
            Ok(conn) => {
                let transport::ClientConn { handle, stream, .. } = conn;
                run_link(d.clone(), n.ip, n.key.clone(), d.my_key.clone(), stream, *ep).await;
                let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
                return;
            }
            Err(e) => debug!("direct to {} at {ep}: {e:#}", n.name),
        }
    }
}

/// Carry packets over one direct link until it ends.
async fn run_link<S>(d: Arc<Daemon>, ip: Ipv4Addr, peer_key: String, dialer: String, stream: S, addr: SocketAddr)
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut rd, wr) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel::<Frame>(1024);
    let writer = tokio::spawn(frame::writer_task(wr, rx));
    let id = d.next_link.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let name = {
        let mut net = d.net.write().unwrap();
        let Some(p) = net.peers.get_mut(&ip).filter(|p| p.node.key == peer_key) else {
            writer.abort();
            return;
        };
        // When both sides dialled, both keep the link dialled by the smaller
        // key and close the other. Replacing a link drops its sender, which
        // ends its writer and so closes it.
        if p.direct.as_ref().is_some_and(|l| l.dialer <= dialer) {
            debug!("duplicate direct link to {}; closing it", p.node.name);
            writer.abort();
            return;
        }
        p.direct = Some(Link {
            id,
            tx: tx.clone(),
            since: std::time::Instant::now(),
            dialer: dialer.clone(),
        });
        p.node.name.clone()
    };
    info!("direct path to {name} via {addr}");
    drop(tx);

    loop {
        match frame::read_frame(&mut rd).await {
            Ok(Some(f)) if f.kind == frame::PACKET => d.inbound(f.payload, ip),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    {
        let mut net = d.net.write().unwrap();
        if let Some(p) = net.peers.get_mut(&ip)
            && p.direct.as_ref().is_some_and(|l| l.id == id)
        {
            p.direct = None;
            p.last_attempt = None;
        }
    }
    writer.abort();
    info!("direct path to {name} closed; using the hub");
    d.map_changed.notify_one();
}
