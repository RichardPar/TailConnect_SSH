//! `tcd`: the machine daemon.
//!
//! It keeps one SSH-in-TLS session to the hub, which carries control
//! messages and relayed packets. Alongside, it accepts and opens direct
//! SSH-in-TLS sessions with peers it can reach; packets to such a peer skip
//! the hub. A TUN device carries the machine's own traffic, and an in-tunnel
//! resolver at 100.100.100.100 answers MagicDNS queries.

pub mod api;
mod direct;
mod localapi;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use russh::keys::PrivateKey;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::dns::Zone;
use crate::frame::{self, Frame};
use crate::keys::key_id;
use crate::proto::{ClientMsg, Node, ServerMsg};
use crate::transport::{self, HostKey};

pub struct Options {
    pub state_dir: PathBuf,
    pub socket: PathBuf,
    pub tun_name: String,
    pub mtu: u16,
    /// Port for direct peer sessions; 0 disables them.
    pub direct_port: u16,
    /// Configure systemd-resolved for MagicDNS.
    pub dns: bool,
    pub hostname: String,
}

/// What survives a restart.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct State {
    server: Option<String>,
    tls_fingerprint: Option<String>,
    server_host_key: Option<String>,
    want_up: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Stopped,
    Connecting,
    Running,
    NeedsLogin,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Stopped => "stopped",
            Phase::Connecting => "connecting",
            Phase::Running => "running",
            Phase::NeedsLogin => "needs-login",
        }
    }
}

/// A direct session to a peer.
#[derive(Clone)]
struct Link {
    id: u64,
    tx: mpsc::Sender<Frame>,
    /// Key of the side that dialled; used to pick one link when both sides
    /// dial each other at once.
    dialer: String,
}

struct PeerState {
    node: Node,
    direct: Option<Link>,
    last_attempt: Option<Instant>,
}

#[derive(Default)]
struct Net {
    me: Option<Node>,
    domain: String,
    peers: HashMap<Ipv4Addr, PeerState>,
    zone: Zone,
}

impl Net {
    fn rebuild_zone(&mut self) {
        let mut z = Zone {
            domain: self.domain.clone(),
            names: HashMap::new(),
        };
        for p in self.peers.values() {
            z.names.insert(p.node.name.clone(), p.node.ip);
        }
        if let Some(me) = &self.me {
            z.names.insert(me.name.clone(), me.ip);
        }
        self.zone = z;
    }
}

struct Tun {
    ip: Ipv4Addr,
    cancel: CancellationToken,
}

pub struct Daemon {
    opts: Options,
    key: Arc<PrivateKey>,
    my_key: String,
    state_path: PathBuf,
    state: Mutex<State>,
    net: RwLock<Net>,
    phase: RwLock<Phase>,
    last_error: RwLock<Option<String>>,
    hub_tx: RwLock<Option<mpsc::Sender<Frame>>>,
    tun_tx: RwLock<Option<mpsc::Sender<Vec<u8>>>>,
    tun: Mutex<Option<Tun>>,
    run: Mutex<Option<CancellationToken>>,
    map_changed: Notify,
    /// End-to-end encryption for packets relayed by the hub.
    e2e: crate::e2e::E2e,
    next_link: AtomicU64,
}

impl Daemon {
    pub fn new(opts: Options) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&opts.state_dir).with_context(|| format!("creating {}", opts.state_dir.display()))?;
        let key = crate::keys::load_or_create(&opts.state_dir.join("machine_key"))?;
        let my_key = key_id(key.public_key());
        let e2e = crate::e2e::E2e::new(crate::keys::x25519_private(&key)?);
        let state_path = opts.state_dir.join("state.json");
        let state: State = match std::fs::read(&state_path) {
            Ok(b) => serde_json::from_slice(&b).context("parsing state.json")?,
            Err(_) => State::default(),
        };
        Ok(Arc::new(Daemon {
            opts,
            key: Arc::new(key),
            my_key,
            state_path,
            state: Mutex::new(state),
            net: RwLock::new(Net::default()),
            phase: RwLock::new(Phase::Stopped),
            last_error: RwLock::new(None),
            hub_tx: RwLock::new(None),
            tun_tx: RwLock::new(None),
            tun: Mutex::new(None),
            run: Mutex::new(None),
            map_changed: Notify::new(),
            next_link: AtomicU64::new(1),
            e2e,
        }))
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        info!("machine key: {}", self.my_key);
        let api = tokio::spawn(localapi::serve(self.clone()));
        if self.opts.direct_port != 0 {
            let d = self.clone();
            tokio::spawn(async move {
                if let Err(e) = direct::listen(d).await {
                    warn!("direct listener: {e:#}");
                }
            });
            tokio::spawn(direct::dialer(self.clone()));
        }
        if self.state.lock().unwrap().want_up {
            self.start(None, None);
        }
        tokio::select! {
            r = api => r?,
            _ = shutdown_signal() => {
                info!("shutting down");
                self.stop(Phase::Stopped);
                Ok(())
            }
        }
    }

    fn save_state(&self) {
        let st = self.state.lock().unwrap().clone();
        let tmp = self.state_path.with_extension("json.tmp");
        let r = std::fs::write(&tmp, serde_json::to_vec_pretty(&st).unwrap())
            .and_then(|_| std::fs::rename(&tmp, &self.state_path));
        if let Err(e) = r {
            warn!("saving state: {e}");
        }
    }

    fn set_phase(&self, p: Phase) {
        *self.phase.write().unwrap() = p;
    }

    /// Start (or restart) the hub connection loop.
    fn start(self: &Arc<Self>, auth_key: Option<String>, first: Option<oneshot::Sender<Result<()>>>) {
        let cancel = CancellationToken::new();
        if let Some(old) = self.run.lock().unwrap().replace(cancel.clone()) {
            old.cancel();
        }
        self.set_phase(Phase::Connecting);
        tokio::spawn(self.clone().hub_loop(cancel, auth_key, first));
    }

    /// Stop the hub loop, tear down the tunnel and forget the network map.
    fn stop(&self, phase: Phase) {
        if let Some(c) = self.run.lock().unwrap().take() {
            c.cancel();
        }
        if let Some(t) = self.tun.lock().unwrap().take() {
            t.cancel.cancel();
        }
        *self.tun_tx.write().unwrap() = None;
        *self.hub_tx.write().unwrap() = None;
        *self.net.write().unwrap() = Net::default();
        self.e2e.sync(&[]);
        self.set_phase(phase);
    }

    async fn hub_loop(
        self: Arc<Self>,
        cancel: CancellationToken,
        mut auth_key: Option<String>,
        mut first: Option<oneshot::Sender<Result<()>>>,
    ) {
        let mut backoff = Duration::from_secs(1);
        loop {
            self.set_phase(Phase::Connecting);
            let started = Instant::now();
            let r = tokio::select! {
                r = self.hub_once(&mut auth_key, &mut first) => r,
                _ = cancel.cancelled() => return,
            };
            *self.hub_tx.write().unwrap() = None;
            let err = match r {
                Ok(()) => "hub closed the session".to_string(),
                Err(HubError::Fatal(m)) => {
                    warn!("{m}");
                    *self.last_error.write().unwrap() = Some(m.clone());
                    if let Some(f) = first.take() {
                        let _ = f.send(Err(anyhow!(m)));
                    }
                    if self.run.lock().unwrap().as_ref().is_some_and(|c| !c.is_cancelled()) {
                        self.stop(Phase::NeedsLogin);
                    }
                    return;
                }
                Err(HubError::Retry(e)) => format!("{e:#}"),
            };
            if cancel.is_cancelled() {
                return;
            }
            warn!("hub: {err}");
            *self.last_error.write().unwrap() = Some(err.clone());
            if let Some(f) = first.take().filter(|f| !f.is_closed()) {
                // `tc up` is waiting: report rather than retry silently.
                let _ = f.send(Err(anyhow!(err)));
                self.stop(Phase::Stopped);
                return;
            }
            if started.elapsed() > Duration::from_secs(30) {
                backoff = Duration::from_secs(1);
            }
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = cancel.cancelled() => return,
            }
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }

    async fn hub_once(
        self: &Arc<Self>,
        auth_key: &mut Option<String>,
        first: &mut Option<oneshot::Sender<Result<()>>>,
    ) -> Result<(), HubError> {
        let st = self.state.lock().unwrap().clone();
        let server = st
            .server
            .clone()
            .ok_or_else(|| HubError::Fatal("no server configured".into()))?;
        let (host, port) = parse_server(&server).map_err(|e| HubError::Fatal(e.to_string()))?;
        let verify = match &st.tls_fingerprint {
            Some(fp) => crate::tls::Verify::Pinned(fp.clone()),
            None => crate::tls::Verify::WebPki,
        };
        let tls = crate::tls::client_config(verify).map_err(HubError::Retry)?;
        let host_key = match &st.server_host_key {
            Some(k) => HostKey::Pinned(k.clone()),
            None => HostKey::Tofu,
        };
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .with_context(|| format!("resolving {host}"))
            .map_err(HubError::Retry)?
            .collect();
        let mut last = anyhow!("{host} has no addresses");
        let mut conn = None;
        for a in addrs {
            match transport::dial(
                a,
                &host,
                tls.clone(),
                self.key.clone(),
                "tailconnect",
                host_key.clone(),
                Duration::from_secs(10),
            )
            .await
            {
                Ok(c) => {
                    conn = Some(c);
                    break;
                }
                Err(e) => {
                    if e.to_string().contains("host key changed") {
                        return Err(HubError::Fatal(format!(
                            "{e:#}; if the server was reinstalled, run `tc logout` and join again"
                        )));
                    }
                    last = e;
                }
            }
        }
        let conn = conn.ok_or(HubError::Retry(last))?;
        if st.server_host_key.is_none() {
            info!("trusting server SSH host key {} (first use)", conn.host_key);
            self.state.lock().unwrap().server_host_key = Some(conn.host_key.clone());
            self.save_state();
        }
        let transport::ClientConn { handle, stream, .. } = conn;
        let (mut rd, wr) = tokio::io::split(stream);
        let (tx, rx) = mpsc::channel::<Frame>(1024);
        let writer = tokio::spawn(frame::writer_task(wr, rx));
        let _guard = scopeguard(move || writer.abort());

        let port = self.opts.direct_port;
        let mut endpoints = local_endpoints(port);
        let hello = ClientMsg::Hello {
            version: crate::PROTOCOL_VERSION,
            hostname: self.opts.hostname.clone(),
            auth_key: auth_key.clone(),
            endpoints: endpoints.clone(),
            listen_port: port,
        };
        tx.send(Frame::control(&hello))
            .await
            .map_err(|_| HubError::Retry(anyhow!("writer closed")))?;

        // Re-report endpoints when local addresses change.
        let tx_ep = tx.clone();
        let ep_task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let now = local_endpoints(port);
                if now != endpoints {
                    endpoints = now.clone();
                    let m = ClientMsg::Endpoints {
                        endpoints: now,
                        listen_port: port,
                    };
                    if tx_ep.send(Frame::control(&m)).await.is_err() {
                        break;
                    }
                }
            }
        });
        let _ep_guard = scopeguard(move || ep_task.abort());

        // End-to-end session housekeeping: handshake retries and expiry.
        let tx_tick = tx.clone();
        let d = self.clone();
        let tick_task = tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(1));
            loop {
                t.tick().await;
                for m in d.e2e.tick() {
                    let _ = tx_tick.try_send(Frame {
                        kind: frame::SEALED,
                        payload: m,
                    });
                }
            }
        });
        let _tick_guard = scopeguard(move || tick_task.abort());

        let mut running = false;
        let result = loop {
            let f = match frame::read_frame(&mut rd).await {
                Ok(Some(f)) => f,
                Ok(None) => break Ok(()),
                Err(e) => break Err(HubError::Retry(e.into())),
            };
            if f.kind == frame::SEALED {
                self.open_sealed(&f.payload, &tx);
                continue;
            }
            if f.kind != frame::CONTROL {
                continue;
            }
            let msg: ServerMsg = match serde_json::from_slice(&f.payload) {
                Ok(m) => m,
                Err(e) => {
                    debug!("bad control message: {e}");
                    continue;
                }
            };
            match msg {
                ServerMsg::Welcome {
                    node,
                    domain,
                    prefix_len,
                } => {
                    info!("joined as {} ({}) in {domain}", node.name, node.ip);
                    *auth_key = None;
                    {
                        let mut net = self.net.write().unwrap();
                        net.me = Some(node.clone());
                        net.domain = domain.clone();
                        net.rebuild_zone();
                    }
                    if let Err(e) = self.ensure_tun(node.ip, prefix_len, &domain) {
                        break Err(HubError::Fatal(format!("creating TUN device: {e:#}")));
                    }
                    if !running {
                        running = true;
                        *self.hub_tx.write().unwrap() = Some(tx.clone());
                        *self.last_error.write().unwrap() = None;
                        self.set_phase(Phase::Running);
                        let changed = {
                            let mut st = self.state.lock().unwrap();
                            let c = !st.want_up;
                            st.want_up = true;
                            c
                        };
                        if changed {
                            self.save_state();
                        }
                        if let Some(f) = first.take() {
                            let _ = f.send(Ok(()));
                        }
                    }
                }
                ServerMsg::NetMap { peers } => self.apply_netmap(peers),
                ServerMsg::Error { message } => break Err(HubError::Fatal(format!("server: {message}"))),
            }
        };
        let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
        result
    }

    fn apply_netmap(&self, peers: Vec<Node>) {
        let mut net = self.net.write().unwrap();
        let mut old = std::mem::take(&mut net.peers);
        for n in peers {
            let (direct, last_attempt) = match old.remove(&n.ip) {
                // Keep a direct link only if it's still the same machine.
                Some(p) if p.node.key == n.key => (p.direct, p.last_attempt),
                _ => (None, None),
            };
            let direct = if n.online { direct } else { None };
            net.peers.insert(
                n.ip,
                PeerState {
                    node: n,
                    direct,
                    last_attempt,
                },
            );
        }
        net.rebuild_zone();
        debug!("network map: {} peers", net.peers.len());
        let keys: Vec<(Ipv4Addr, [u8; 32])> = net
            .peers
            .values()
            .filter_map(|p| {
                let k = crate::keys::parse_key_id(&p.node.key)
                    .and_then(|k| crate::keys::x25519_public(&k))
                    .map_err(|e| warn!("peer {} has an unusable key: {e:#}", p.node.name))
                    .ok()?;
                Some((p.node.ip, k))
            })
            .collect();
        drop(net);
        self.e2e.sync(&keys);
        self.map_changed.notify_one();
    }

    /// Create the TUN device, or recreate it if our address changed.
    fn ensure_tun(self: &Arc<Self>, ip: Ipv4Addr, prefix_len: u8, domain: &str) -> Result<()> {
        let mut tun = self.tun.lock().unwrap();
        if tun.as_ref().is_some_and(|t| t.ip == ip) {
            return Ok(());
        }
        if let Some(old) = tun.take() {
            old.cancel.cancel();
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len as u32)
        };
        let mut cfg = tun::Configuration::default();
        cfg.tun_name(&self.opts.tun_name)
            .address(ip)
            .netmask(Ipv4Addr::from(mask))
            .mtu(self.opts.mtu)
            .up();
        let dev = tun::create_as_async(&cfg).context("opening /dev/net/tun (tcd needs root or CAP_NET_ADMIN)")?;
        let (mut rd, mut wr) = tokio::io::split(dev);
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
        *self.tun_tx.write().unwrap() = Some(tx);

        let c = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = c.cancelled() => break,
                    p = rx.recv() => match p {
                        Some(p) => if let Err(e) = wr.write_all(&p).await { debug!("tun write: {e}"); },
                        None => break,
                    },
                }
            }
        });
        let c = cancel.clone();
        let d = self.clone();
        let mtu = self.opts.mtu as usize;
        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu + 64];
            loop {
                tokio::select! {
                    _ = c.cancelled() => break,
                    n = rd.read(&mut buf) => match n {
                        Ok(0) => break,
                        Ok(n) => d.outbound(buf[..n].to_vec()),
                        Err(e) => { warn!("tun read: {e}"); break; }
                    },
                }
            }
        });
        info!("{} up with {ip}/{prefix_len}", self.opts.tun_name);
        *tun = Some(Tun { ip, cancel });
        drop(tun);
        if self.opts.dns {
            configure_dns(&self.opts.tun_name, domain);
        }
        Ok(())
    }

    /// A packet from the TUN device, leaving this machine.
    fn outbound(&self, pkt: Vec<u8>) {
        let Some((_, dst)) = crate::packet::ipv4_addrs(&pkt) else {
            return;
        };
        if dst == crate::MAGIC_DNS_IP {
            self.answer_dns(&pkt);
            return;
        }
        let (direct, known) = {
            let net = self.net.read().unwrap();
            match net.peers.get(&dst) {
                Some(p) => (p.direct.as_ref().map(|l| l.tx.clone()), true),
                None => (None, false),
            }
        };
        if !known {
            return;
        }
        let pkt = match direct {
            Some(tx) => match tx.try_send(Frame::packet(pkt)) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => return,
                Err(mpsc::error::TrySendError::Closed(f)) => f.payload,
            },
            None => pkt,
        };
        // Through the hub, sealed end to end.
        let hub = self.hub_tx.read().unwrap().clone();
        if let Some(tx) = hub {
            for m in self.e2e.seal(dst, pkt) {
                let _ = tx.try_send(Frame {
                    kind: frame::SEALED,
                    payload: m,
                });
            }
        }
    }

    /// A sealed message from the hub: `[sender address][e2e message]`.
    fn open_sealed(&self, msg: &[u8], hub: &mpsc::Sender<Frame>) {
        if msg.len() < 5 {
            return;
        }
        let src = Ipv4Addr::new(msg[0], msg[1], msg[2], msg[3]);
        let opened = self.e2e.open(src, &msg[4..]);
        for m in opened.replies {
            let _ = hub.try_send(Frame {
                kind: frame::SEALED,
                payload: m,
            });
        }
        if let Some(pkt) = opened.packet {
            self.inbound(pkt, src);
        }
    }

    /// A packet arriving for this machine from the peer at `via`, over a
    /// direct link or decrypted from the hub.
    fn inbound(&self, pkt: Vec<u8>, via: Ipv4Addr) {
        let Some((src, dst)) = crate::packet::ipv4_addrs(&pkt) else {
            return;
        };
        {
            let net = self.net.read().unwrap();
            if net.me.as_ref().map(|m| m.ip) != Some(dst) {
                return;
            }
            if src != via || !net.peers.contains_key(&src) {
                debug!("dropping packet from {src} (via {via:?})");
                return;
            }
        }
        let tun = self.tun_tx.read().unwrap().clone();
        if let Some(tx) = tun {
            let _ = tx.try_send(pkt);
        }
    }

    fn answer_dns(&self, pkt: &[u8]) {
        let Some(u) = crate::packet::parse_udp(pkt) else {
            return;
        };
        if u.dport != 53 {
            return;
        }
        let resp = {
            let net = self.net.read().unwrap();
            crate::dns::answer(&net.zone, u.payload)
        };
        if let Some(resp) = resp {
            let out = crate::packet::build_udp(crate::MAGIC_DNS_IP, u.src, 53, u.sport, &resp);
            let tun = self.tun_tx.read().unwrap().clone();
            if let Some(tx) = tun {
                let _ = tx.try_send(out);
            }
        }
    }

    fn peer_ip_by_key(&self, key: &str) -> Option<Ipv4Addr> {
        self.net
            .read()
            .unwrap()
            .peers
            .values()
            .find(|p| p.node.key == key)
            .map(|p| p.node.ip)
    }

    fn status(&self) -> api::Status {
        let st = self.state.lock().unwrap().clone();
        let net = self.net.read().unwrap();
        let mut peers: Vec<api::PeerStatus> = net
            .peers
            .values()
            .map(|p| api::PeerStatus {
                name: p.node.name.clone(),
                ip: p.node.ip,
                online: p.node.online,
                path: if p.direct.is_some() {
                    "direct".into()
                } else if p.node.online {
                    "hub".into()
                } else {
                    "-".into()
                },
                endpoints: p.node.endpoints.clone(),
                e2e: self.e2e.established(p.node.ip),
            })
            .collect();
        peers.sort_by_key(|p| p.ip);
        api::Status {
            phase: self.phase.read().unwrap().as_str().into(),
            server: st.server,
            me: net.me.clone(),
            domain: net.domain.clone(),
            tun: self.tun.lock().unwrap().as_ref().map(|_| self.opts.tun_name.clone()),
            direct_port: self.opts.direct_port,
            last_error: self.last_error.read().unwrap().clone(),
            peers,
        }
    }
}

enum HubError {
    /// Don't retry: needs the user (bad auth key, removed, host key changed).
    Fatal(String),
    Retry(anyhow::Error),
}

/// `host`, `host:port`, `https://host[:port]` or `[v6]:port`; default port 443.
pub fn parse_server(s: &str) -> Result<(String, u16)> {
    let s = s.trim();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("ssh://"))
        .unwrap_or(s);
    let s = s.trim_end_matches('/');
    if s.is_empty() {
        bail!("empty server address");
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').ok_or_else(|| anyhow!("bad IPv6 address in {s}"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().context("bad port")?,
            None => 443,
        };
        return Ok((h.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Ok((h.to_string(), p.parse().context("bad port")?)),
        _ => Ok((s.to_string(), 443)),
    }
}

/// Addresses of this machine's interfaces where peers may reach the direct
/// listener: everything except loopback, link-local and the tailnet.
fn local_endpoints(port: u16) -> Vec<SocketAddr> {
    if port == 0 {
        return vec![];
    }
    let mut out = Vec::new();
    if let Ok(ifs) = if_addrs::get_if_addrs() {
        for i in ifs {
            let ip = i.ip();
            let ok = match ip {
                IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !crate::in_tailnet(v4),
                IpAddr::V6(v6) => !v6.is_loopback() && (v6.segments()[0] & 0xffc0) != 0xfe80,
            };
            if ok {
                out.push(SocketAddr::new(ip, port));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Point systemd-resolved at the in-tunnel resolver for our domain.
fn configure_dns(tun: &str, domain: &str) {
    let tun = tun.to_string();
    let domain = domain.to_string();
    tokio::task::spawn_blocking(move || {
        let run = |args: &[&str]| std::process::Command::new("resolvectl").args(args).output();
        let dns = crate::MAGIC_DNS_IP.to_string();
        match run(&["dns", &tun, &dns]) {
            Ok(o) if o.status.success() => {
                let _ = run(&["domain", &tun, &domain]);
                info!("MagicDNS: *.{domain} via {dns} on {tun}");
            }
            Ok(o) => warn!(
                "MagicDNS not configured (resolvectl: {}); names still resolve with `dig @{dns}`",
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => warn!("MagicDNS not configured (resolvectl: {e}); names still resolve with `dig @{dns}`"),
        }
    });
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

/// Run `f` when dropped.
fn scopeguard<F: FnOnce()>(f: F) -> impl Drop {
    struct G<F: FnOnce()>(Option<F>);
    impl<F: FnOnce()> Drop for G<F> {
        fn drop(&mut self) {
            if let Some(f) = self.0.take() {
                f()
            }
        }
    }
    G(Some(f))
}

#[cfg(test)]
mod tests {
    use super::parse_server;

    #[test]
    fn server_addresses() {
        assert_eq!(
            parse_server("hub.example.com").unwrap(),
            ("hub.example.com".into(), 443)
        );
        assert_eq!(
            parse_server("https://hub.example.com/").unwrap(),
            ("hub.example.com".into(), 443)
        );
        assert_eq!(parse_server("10.0.0.1:8443").unwrap(), ("10.0.0.1".into(), 8443));
        assert_eq!(parse_server("[::1]:9").unwrap(), ("::1".into(), 9));
        assert_eq!(parse_server("[::1]").unwrap(), ("::1".into(), 443));
    }
}
