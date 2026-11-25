//! `tcd`: the machine daemon.
//!
//! It keeps one SSH-in-TLS session to the hub, which carries control
//! messages and relayed packets. Alongside, it accepts and opens direct
//! SSH-in-TLS sessions with peers it can reach; packets to such a peer skip
//! the hub. A TUN device carries the machine's own traffic (IPv4 and IPv6),
//! and an in-tunnel resolver at 100.100.100.100 answers MagicDNS queries.
//! A machine can be an exit node for its account, or send its internet
//! traffic through one (see [`exit`]).

pub mod api;
mod direct;
mod exit;
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
    /// Resolvers an exit node uses for its clients (default: the host's).
    pub exit_dns: Vec<SocketAddr>,
}

/// What survives a restart.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct State {
    server: Option<String>,
    tls_fingerprint: Option<String>,
    server_host_key: Option<String>,
    want_up: bool,
    /// The exit node to send internet traffic through (name or address).
    #[serde(default)]
    exit_node: Option<String>,
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
    /// From the hub, when the map is empty or limited (suspended account).
    notice: Option<String>,
}

impl Net {
    fn rebuild_zone(&mut self) {
        let mut z = Zone {
            domain: self.domain.clone(),
            account: self.me.as_ref().map(|m| m.account.clone()).unwrap_or_default(),
            ..Default::default()
        };
        for p in self.peers.values() {
            z.insert(&p.node.name, &p.node.account, p.node.ip);
        }
        if let Some(me) = &self.me {
            z.insert(&me.name, &me.account, me.ip);
        }
        self.zone = z;
    }
}

struct Tun {
    ip: Ipv4Addr,
    /// The IPv6 address is set too.
    v6: bool,
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
    /// What each peer may open on this machine; enforced on every packet
    /// that arrives.
    filter: Mutex<crate::filter::Filter>,
    /// Bytes (received, sent) per peer since the tunnel started.
    traffic: Mutex<HashMap<Ipv4Addr, (u64, u64)>>,
    /// This machine's exit node role, while on.
    serving: Mutex<Option<exit::Serving>>,
    /// The exit node this machine's internet traffic goes through now.
    exit_in_use: RwLock<Option<Ipv4Addr>>,
    /// Why the chosen exit node isn't in use.
    exit_problem: RwLock<Option<String>>,
    /// DNS queries forwarded to the exit node, awaiting answers.
    dns_pending: Mutex<exit::Pending>,
    /// The hub's addresses from the last successful lookup.
    hub_addrs: Mutex<Vec<SocketAddr>>,
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
            filter: Mutex::new(Default::default()),
            traffic: Mutex::new(HashMap::new()),
            serving: Mutex::new(None),
            exit_in_use: RwLock::new(None),
            exit_problem: RwLock::new(None),
            dns_pending: Mutex::new(Default::default()),
            hub_addrs: Mutex::new(Vec::new()),
        }))
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        info!("machine key: {}", self.my_key);
        // Leftovers of a previous run (after a crash): routes, NAT.
        exit::cleanup();
        // tcd's own connections keep using the real network when an exit
        // node is in use.
        transport::SOCKET_MARK.store(exit::MARK, std::sync::atomic::Ordering::Relaxed);
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
        self.stop_using_exit(None);
        if let Some(s) = self.serving.lock().unwrap().take() {
            exit::unserve(s);
        }
        if let Some(t) = self.tun.lock().unwrap().take() {
            t.cancel.cancel();
        }
        *self.tun_tx.write().unwrap() = None;
        *self.hub_tx.write().unwrap() = None;
        self.filter.lock().unwrap().set_peers([]);
        self.traffic.lock().unwrap().clear();
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
        // Remember the hub's addresses: with an exit node in use, DNS goes
        // through the tunnel, which is down while reconnecting.
        let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(a) => {
                let a: Vec<SocketAddr> = a.collect();
                *self.hub_addrs.lock().unwrap() = a.clone();
                a
            }
            Err(e) => {
                let cached = self.hub_addrs.lock().unwrap().clone();
                if cached.is_empty() {
                    return Err(HubError::Retry(anyhow!(e).context(format!("resolving {host}"))));
                }
                debug!("resolving {host}: {e}; using {cached:?}");
                cached
            }
        };
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

        // Traffic counts for the portal, while they change.
        let tx_tr = tx.clone();
        let d = self.clone();
        let every = std::env::var("TC_TRAFFIC_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30u64)
            .max(1);
        let tr_task = tokio::spawn(async move {
            let mut last: Vec<crate::proto::PeerTraffic> = Vec::new();
            loop {
                tokio::time::sleep(Duration::from_secs(every)).await;
                let mut now: Vec<crate::proto::PeerTraffic> = d
                    .traffic
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(ip, (rx, tx))| crate::proto::PeerTraffic {
                        ip: *ip,
                        rx: *rx,
                        tx: *tx,
                    })
                    .collect();
                now.sort_by_key(|p| p.ip);
                if now != last {
                    let m = ClientMsg::Traffic { peers: now.clone() };
                    if tx_tr.send(Frame::control(&m)).await.is_err() {
                        break;
                    }
                    last = now;
                }
            }
        });
        let _tr_guard = scopeguard(move || tr_task.abort());

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
                    info!("joined as {}.{} ({}) in {domain}", node.name, node.account, node.ip);
                    *auth_key = None;
                    {
                        let mut net = self.net.write().unwrap();
                        net.me = Some(node.clone());
                        net.domain = domain.clone();
                        net.rebuild_zone();
                    }
                    if let Err(e) = self.ensure_tun(node.ip, prefix_len, &domain, &node.account) {
                        break Err(HubError::Fatal(format!("creating TUN device: {e:#}")));
                    }
                    self.set_role(node.exit_node);
                    self.reconcile_exit();
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
                ServerMsg::NetMap { peers, notice } => {
                    if let Some(n) = &notice {
                        warn!("hub: {n}");
                    }
                    self.apply_netmap(peers, notice)
                }
                ServerMsg::Error { message } => break Err(HubError::Fatal(format!("server: {message}"))),
            }
        };
        let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
        result
    }

    fn apply_netmap(&self, peers: Vec<Node>, notice: Option<String>) {
        // The filter first: it denies peers it doesn't know, so a peer that is
        // added is restricted before it's reachable, and one that is removed
        // is cut off at once.
        self.filter
            .lock()
            .unwrap()
            .set_peers(peers.iter().map(|n| (n.ip, crate::acl::Access::from_wire(&n.inbound))));
        let mut net = self.net.write().unwrap();
        net.notice = notice;
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
        self.reconcile_exit();
        self.map_changed.notify_one();
    }

    /// Turn this machine's exit node role on or off, as its map entry says.
    fn set_role(self: &Arc<Self>, on: bool) {
        let mut serving = self.serving.lock().unwrap();
        match (on, serving.is_some()) {
            (true, false) => match exit::serve(&self.opts.tun_name) {
                Ok(s) => {
                    let me = self.net.read().unwrap().me.as_ref().map(|m| m.ip);
                    if let Some(ip) = me {
                        let ups = if self.opts.exit_dns.is_empty() {
                            exit::system_resolvers()
                        } else {
                            self.opts.exit_dns.clone()
                        };
                        let d = Arc::downgrade(self);
                        let allowed: Arc<dyn Fn(Ipv4Addr) -> bool + Send + Sync> =
                            Arc::new(move |ip| d.upgrade().is_some_and(|d| d.may_use_me_as_exit(ip)));
                        tokio::spawn(exit::dns_forwarder(ip, ups, allowed, s.dns.clone()));
                    }
                    *serving = Some(s);
                }
                Err(e) => warn!("exit node: {e:#}"),
            },
            (false, true) => exit::unserve(serving.take().expect("serving")),
            _ => {}
        }
    }

    /// May the peer at `ip` send its internet traffic through this machine?
    /// Only while the role is on, for machines of this machine's own account
    /// that may open everything here (as the hub decided when it offered us).
    fn may_use_me_as_exit(&self, ip: Ipv4Addr) -> bool {
        if self.serving.lock().unwrap().is_none() {
            return false;
        }
        let net = self.net.read().unwrap();
        let Some(me) = &net.me else { return false };
        net.peers
            .get(&ip)
            .is_some_and(|p| p.node.account == me.account && crate::acl::Access::from_wire(&p.node.inbound).is_all())
    }

    /// Use the chosen exit node if it's offered and online; otherwise go
    /// direct, and say why.
    fn reconcile_exit(&self) {
        let want = self
            .state
            .lock()
            .unwrap()
            .exit_node
            .clone()
            .filter(|s| !s.trim().is_empty());
        let Some(want) = want else {
            self.stop_using_exit(None);
            return;
        };
        let found = {
            let net = self.net.read().unwrap();
            find_peer(&net, &want).map(|p| (p.node.ip, p.node.exit_node, p.node.online, p.node.name.clone()))
        };
        let problem = match found {
            None => Some(format!("exit node {want} isn't in the network map")),
            Some((_, false, _, n)) => Some(format!("{n} doesn't offer to be this machine's exit node")),
            Some((_, _, false, n)) => Some(format!("{n} is offline")),
            Some((ip, true, true, n)) => {
                if *self.exit_in_use.read().unwrap() == Some(ip) {
                    return;
                }
                let v6 = self.tun.lock().unwrap().as_ref().is_some_and(|t| t.v6);
                match exit::route_via(&self.opts.tun_name, v6) {
                    Ok(()) => {
                        *self.exit_in_use.write().unwrap() = Some(ip);
                        *self.exit_problem.write().unwrap() = None;
                        self.e2e.set_exit(Some(ip));
                        info!("exit node: internet traffic goes through {n}");
                        if self.opts.dns {
                            let (d, a) = self.dns_names();
                            exit_dns_routing(&self.opts.tun_name, true, &d, &a);
                        }
                        return;
                    }
                    Err(e) => Some(format!("routing through {n}: {e:#}")),
                }
            }
        };
        self.stop_using_exit(problem);
    }

    /// The MagicDNS domain and this machine's account.
    fn dns_names(&self) -> (String, String) {
        let net = self.net.read().unwrap();
        (
            net.domain.clone(),
            net.me.as_ref().map(|m| m.account.clone()).unwrap_or_default(),
        )
    }

    /// Stop sending internet traffic through an exit node.
    fn stop_using_exit(&self, problem: Option<String>) {
        if let Some(p) = &problem
            && self.exit_problem.read().unwrap().as_ref() != Some(p)
        {
            warn!("{p}; internet traffic goes direct");
        }
        *self.exit_problem.write().unwrap() = problem;
        if self.exit_in_use.write().unwrap().take().is_some() {
            exit::unroute();
            self.e2e.set_exit(None);
            if self.opts.dns {
                let (d, a) = self.dns_names();
                exit_dns_routing(&self.opts.tun_name, false, &d, &a);
            }
            info!("exit node: no longer in use");
        }
    }

    /// Create the TUN device, or recreate it if our address changed.
    fn ensure_tun(self: &Arc<Self>, ip: Ipv4Addr, prefix_len: u8, domain: &str, account: &str) -> Result<()> {
        let mut tun = self.tun.lock().unwrap();
        if tun.as_ref().is_some_and(|t| t.ip == ip) {
            return Ok(());
        }
        if let Some(old) = tun.take() {
            old.cancel.cancel();
        }
        // Totals count from when the tunnel started.
        self.traffic.lock().unwrap().clear();
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
        // IPv6: the address derived from the IPv4 one, routing the /48.
        let ip6 = crate::ip6_of(ip);
        let v6 = match exit_cmd(&[
            "ip",
            "-6",
            "addr",
            "replace",
            &format!("{ip6}/{}", crate::TAILNET6_PREFIX),
            "dev",
            &self.opts.tun_name,
        ]) {
            Ok(()) => true,
            Err(e) => {
                warn!("no IPv6 in the tunnel: {e:#}");
                false
            }
        };
        info!(
            "{} up with {ip}/{prefix_len}{}",
            self.opts.tun_name,
            if v6 {
                format!(" and {ip6}/{}", crate::TAILNET6_PREFIX)
            } else {
                String::new()
            }
        );
        *tun = Some(Tun { ip, v6, cancel });
        drop(tun);
        if self.opts.dns {
            configure_dns(&self.opts.tun_name, domain, account);
        }
        Ok(())
    }

    /// A packet from the TUN device, leaving this machine: to a peer by its
    /// tunnel address (IPv4 or IPv6), or to the internet through the exit node.
    fn outbound(&self, pkt: Vec<u8>) {
        let Some((_, dst)) = crate::packet::ip_addrs(&pkt) else {
            return;
        };
        if dst == IpAddr::V4(crate::MAGIC_DNS_IP) {
            self.answer_dns(&pkt);
            return;
        }
        let peer = match crate::machine_of(dst) {
            Some(m) => {
                if !self.net.read().unwrap().peers.contains_key(&m) {
                    return;
                }
                self.filter.lock().unwrap().outbound(&pkt, Instant::now());
                m
            }
            // Not a tunnel address: the internet, if an exit node is in use.
            None => match *self.exit_in_use.read().unwrap() {
                Some(e) => e,
                None => return,
            },
        };
        self.send_to_peer(peer, pkt);
    }

    /// Send a packet to a peer: over the direct link if there is one, else
    /// sealed end to end through the hub.
    fn send_to_peer(&self, peer: Ipv4Addr, pkt: Vec<u8>) {
        let direct = self
            .net
            .read()
            .unwrap()
            .peers
            .get(&peer)
            .and_then(|p| p.direct.as_ref().map(|l| l.tx.clone()));
        self.traffic.lock().unwrap().entry(peer).or_default().1 += pkt.len() as u64;
        let pkt = match direct {
            Some(tx) => match tx.try_send(Frame::packet(pkt)) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => return,
                Err(mpsc::error::TrySendError::Closed(f)) => f.payload,
            },
            None => pkt,
        };
        let hub = self.hub_tx.read().unwrap().clone();
        if let Some(tx) = hub {
            for m in self.e2e.seal(peer, pkt) {
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

    /// A packet from the peer at `via`, over a direct link or decrypted from
    /// the hub. It reaches the TUN device if it's for this machine and the
    /// filter allows it, if it's an internet reply from our exit node, or if
    /// this machine is an exit node the peer may use and it's for the internet.
    fn inbound(&self, mut pkt: Vec<u8>, via: Ipv4Addr) {
        let Some((src, dst)) = crate::packet::ip_addrs(&pkt) else {
            return;
        };
        let (me, known) = {
            let net = self.net.read().unwrap();
            (net.me.as_ref().map(|m| m.ip), net.peers.contains_key(&via))
        };
        let Some(me) = me else { return };
        if !known {
            return;
        }
        let from_tunnel = crate::machine_of(src);
        let ok = if crate::machine_of(dst) == Some(me) {
            match from_tunnel {
                Some(m) if m == via => {
                    if !self.filter.lock().unwrap().inbound(&pkt, Instant::now()) {
                        return;
                    }
                    // An answer from our exit node's DNS forwarder: make it
                    // look like MagicDNS's.
                    if *self.exit_in_use.read().unwrap() == Some(via) {
                        self.unforward_dns(&mut pkt, via);
                    }
                    true
                }
                // An internet reply, from the exit node in use.
                None => *self.exit_in_use.read().unwrap() == Some(via),
                _ => false,
            }
        } else {
            // For somewhere else: forward it only as an exit node, only for
            // the internet, and only for machines allowed to use it.
            from_tunnel == Some(via)
                && crate::machine_of(dst).is_none()
                && dst != IpAddr::V4(crate::MAGIC_DNS_IP)
                && !matches!(dst, IpAddr::V6(v6) if crate::in_tailnet6(v6))
                && self.may_use_me_as_exit(via)
        };
        if !ok {
            debug!("dropping packet {src} -> {dst} (via {via})");
            return;
        }
        self.traffic.lock().unwrap().entry(via).or_default().0 += pkt.len() as u64;
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
        let exit = *self.exit_in_use.read().unwrap();
        let (resp, local) = {
            let net = self.net.read().unwrap();
            (
                crate::dns::answer(&net.zone, u.payload),
                crate::dns::is_local(&net.zone, u.payload),
            )
        };
        // With an exit node in use, other names are resolved there, so the
        // local network's resolver sees none of this machine's lookups.
        if let (Some(e), false) = (exit, local)
            && u.payload.len() >= 2
        {
            let me = match u.src {
                s if crate::in_tailnet(s) => s,
                _ => return,
            };
            let id = u16::from_be_bytes([u.payload[0], u.payload[1]]);
            self.dns_pending.lock().unwrap().add(u.sport, id);
            let fwd = crate::packet::build_udp(me, e, u.sport, exit::DNS_PORT, u.payload);
            self.filter.lock().unwrap().outbound(&fwd, Instant::now());
            self.send_to_peer(e, fwd);
            return;
        }
        if let Some(resp) = resp {
            let out = crate::packet::build_udp(crate::MAGIC_DNS_IP, u.src, 53, u.sport, &resp);
            let tun = self.tun_tx.read().unwrap().clone();
            if let Some(tx) = tun {
                let _ = tx.try_send(out);
            }
        }
    }

    /// Readdress an answer from the exit node's DNS forwarder to come from
    /// MagicDNS, if it answers a query we forwarded.
    fn unforward_dns(&self, pkt: &mut Vec<u8>, exit_ip: Ipv4Addr) {
        let Some(u) = crate::packet::parse_udp(pkt) else { return };
        if u.src != exit_ip || u.sport != exit::DNS_PORT || u.payload.len() < 2 {
            return;
        }
        let id = u16::from_be_bytes([u.payload[0], u.payload[1]]);
        if self.dns_pending.lock().unwrap().take(u.dport, id) {
            *pkt = crate::packet::build_udp(crate::MAGIC_DNS_IP, u.dst, 53, u.dport, u.payload);
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
        let traffic = self.traffic.lock().unwrap().clone();
        let st = self.state.lock().unwrap().clone();
        let net = self.net.read().unwrap();
        let mut peers: Vec<api::PeerStatus> = net
            .peers
            .values()
            .map(|p| api::PeerStatus {
                name: p.node.name.clone(),
                account: p.node.account.clone(),
                tags: p.node.tags.clone(),
                inbound: crate::acl::Access::from_wire(&p.node.inbound).to_wire(),
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
                exit_node: p.node.exit_node,
                rx: traffic.get(&p.node.ip).map_or(0, |t| t.0),
                tx: traffic.get(&p.node.ip).map_or(0, |t| t.1),
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
            notice: net.notice.clone(),
            filter_dropped: self.filter.lock().unwrap().dropped(),
            exit_node: st.exit_node.clone(),
            exit_in_use: self
                .exit_in_use
                .read()
                .unwrap()
                .and_then(|ip| net.peers.get(&ip))
                .map(|p| format!("{}.{}", p.node.name, p.node.account)),
            exit_problem: self.exit_problem.read().unwrap().clone(),
            exit_serving: self.serving.lock().unwrap().is_some(),
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
/// Our own account's names are searched (`laptop` → `laptop.richard.tc.internal`);
/// the whole domain is routed here.
fn configure_dns(tun: &str, domain: &str, account: &str) {
    let tun = tun.to_string();
    let search = format!("{account}.{domain}");
    let route = format!("~{domain}");
    let domain = domain.to_string();
    tokio::task::spawn_blocking(move || {
        let run = |args: &[&str]| std::process::Command::new("resolvectl").args(args).output();
        let dns = crate::MAGIC_DNS_IP.to_string();
        match run(&["dns", &tun, &dns]) {
            Ok(o) if o.status.success() => {
                let _ = run(&["domain", &tun, &search, &route]);
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

/// While an exit node is in use, send every name to MagicDNS (which passes
/// names outside it to the exit node); otherwise only MagicDNS names.
fn exit_dns_routing(tun: &str, all: bool, domain: &str, account: &str) {
    let tun = tun.to_string();
    let search = format!("{account}.{domain}");
    let route = format!("~{domain}");
    tokio::task::spawn_blocking(move || {
        let run = |args: &[&str]| std::process::Command::new("resolvectl").args(args).output();
        let mut domains = vec!["domain", tun.as_str(), search.as_str(), route.as_str()];
        if all {
            domains.push("~.");
        }
        let _ = run(&domains);
        let _ = run(&["default-route", &tun, if all { "yes" } else { "no" }]);
    });
}

/// Run a system command (iproute2 and the like).
fn exit_cmd(args: &[&str]) -> Result<()> {
    let out = std::process::Command::new(args[0]).args(&args[1..]).output()?;
    if !out.status.success() {
        bail!("{}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// A peer by short name, `name.account`, full MagicDNS name or address.
fn find_peer<'a>(net: &'a Net, s: &str) -> Option<&'a PeerState> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = s.parse::<IpAddr>() {
        let m = crate::machine_of(ip)?;
        return net.peers.get(&m);
    }
    let rel = s.strip_suffix(&format!(".{}", net.domain)).unwrap_or(&s);
    let my_account = net.me.as_ref().map(|m| m.account.as_str()).unwrap_or("");
    let (name, account) = rel.split_once('.').unwrap_or((rel, my_account));
    net.peers
        .values()
        .find(|p| p.node.name == name && p.node.account == account)
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
