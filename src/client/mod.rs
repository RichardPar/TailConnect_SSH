//! `tcd`: the machine daemon.
//!
//! It keeps one SSH-in-TLS session to the hub, which carries control
//! messages and relayed packets. Alongside, it accepts and opens direct
//! SSH-in-TLS sessions with peers it can reach; packets to such a peer skip
//! the hub. A TUN device carries the machine's own traffic (IPv4 and IPv6),
//! and an in-tunnel resolver at 100.100.100.100 answers MagicDNS queries.
//! A machine can be an exit node for its account, or send its internet
//! traffic through one (see [`exit`]).

#[cfg(unix)]
pub mod android;
pub mod api;
mod direct;
#[cfg_attr(windows, path = "exit_windows.rs")]
mod exit;
mod exitdns;
mod localapi;
mod netchange;
pub mod view;
#[cfg(windows)]
pub mod win;

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
    /// As an exit node: send the forwarded traffic out through this
    /// interface (a VPN's tun0, say), blocking it while it's down.
    pub exit_interface: Option<String>,
    /// Inside the Android app: the bridge to its VpnService (see android.rs).
    #[cfg(unix)]
    pub android: Option<android::AndroidOpts>,
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
    /// When it came up.
    since: Instant,
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
            z.insert(&p.node.name, &p.node.account, &p.node.zone, p.node.ip);
        }
        if let Some(me) = &self.me {
            z.insert(&me.name, &me.account, &me.zone, me.ip);
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
    /// The DNS configuration last applied: (search zone, routed zones, all).
    dns_applied: Mutex<Option<(String, Vec<String>, bool)>>,
    /// DNS queries forwarded to the exit node, awaiting answers.
    dns_pending: Mutex<exit::Pending>,
    /// The hub's addresses from the last successful lookup.
    hub_addrs: Mutex<Vec<SocketAddr>>,
    next_link: AtomicU64,
    /// Inside the Android app: the bridge to its VpnService.
    #[cfg(unix)]
    bridge: Option<Arc<android::Bridge>>,
    /// Android: the VPN interface needs new routes (an exit node in use, or
    /// not); a task asks the app for a new one.
    retun: Notify,
    /// This machine's addresses changed: report the direct endpoints now.
    endpoints_changed: Notify,
}

impl Daemon {
    pub fn new(opts: Options) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&opts.state_dir).with_context(|| format!("creating {}", opts.state_dir.display()))?;
        #[cfg(windows)]
        win::restrict_dir(&opts.state_dir);
        let key = crate::keys::load_or_create(&opts.state_dir.join("machine_key"))?;
        let my_key = key_id(key.public_key());
        let e2e = crate::e2e::E2e::new(crate::keys::x25519_private(&key)?);
        let state_path = opts.state_dir.join("state.json");
        let state: State = match std::fs::read(&state_path) {
            Ok(b) => serde_json::from_slice(&b).context("parsing state.json")?,
            Err(_) => State::default(),
        };
        #[cfg(unix)]
        let bridge = match &opts.android {
            Some(a) => Some(android::Bridge::listen(a)?),
            None => None,
        };
        #[cfg(unix)]
        if bridge.is_some() {
            transport::KEEPALIVE_SECS.store(10, std::sync::atomic::Ordering::Relaxed);
        }
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
            dns_applied: Mutex::new(None),
            hub_addrs: Mutex::new(Vec::new()),
            #[cfg(unix)]
            bridge,
            retun: Notify::new(),
            endpoints_changed: Notify::new(),
        }))
    }

    /// Running inside the Android app?
    fn is_android(&self) -> bool {
        #[cfg(unix)]
        return self.bridge.is_some();
        #[cfg(not(unix))]
        false
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        info!("machine key: {}", self.my_key);
        #[cfg(unix)]
        if let Some(b) = &self.bridge {
            // The app reports the network: on a new one, reconnect at once.
            let (d, rt) = (Arc::downgrade(&self), tokio::runtime::Handle::current());
            b.set_on_network(Box::new(move |old, new| {
                let change = old.change(new);
                if let Some(d) = d.upgrade() {
                    rt.spawn(async move { d.network_changed(change) });
                }
            }));
        }
        if !self.is_android() {
            // Elsewhere, look at this machine's addresses every 2 seconds:
            // a laptop moving from Wi-Fi to Ethernet, a second uplink taking
            // over.
            let d = self.clone();
            tokio::spawn(async move {
                let (mut last, mut last_out) = (local_network(), outgoing_address());
                loop {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let (now, out) = (local_network(), outgoing_address());
                    let change = desktop_change(last_out, out, &last, &now);
                    if out.is_some() {
                        last_out = out;
                    } else if last_out.is_some() && now.addrs.is_empty() {
                        // Offline: coming back counts as a new network.
                        last_out = None;
                    }
                    last = now;
                    d.network_changed(change);
                }
            });
        }
        if self.is_android() {
            // New routes mean a new VPN interface from the app.
            let d = self.clone();
            tokio::spawn(async move {
                loop {
                    d.retun.notified().await;
                    d.android_retun();
                }
            });
        } else {
            // Leftovers of a previous run (after a crash): routes, NAT.
            exit::cleanup();
            // tcd's own connections keep using the real network when an exit
            // node is in use.
            transport::SOCKET_MARK.store(exit::MARK, std::sync::atomic::Ordering::Relaxed);
        }
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
            #[cfg(unix)]
            if let Some(b) = &self.bridge {
                b.close_tun();
            }
            // (On Linux the DNS settings go with the interface.)
            #[cfg(windows)]
            {
                *self.dns_applied.lock().unwrap() = None;
                tokio::task::spawn_blocking(win::clear_dns);
            }
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
        // Retry quickly at first (a network that's just come up may need a
        // moment), then back off to every 30 s.
        const FIRST_RETRY: Duration = Duration::from_millis(250);
        let mut backoff = FIRST_RETRY;
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
                backoff = FIRST_RETRY;
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
        let found: std::io::Result<Vec<SocketAddr>> = match self.resolver() {
            // Android: no /etc/resolv.conf; ask the underlying network's DNS.
            Some(servers) => crate::client::resolve_via(&host, port, &servers).await,
            None => tokio::net::lookup_host((host.as_str(), port))
                .await
                .map(|a| a.collect()),
        };
        let addrs: Vec<SocketAddr> = match found {
            Ok(a) => {
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
        let mut endpoints = self.endpoints(port);
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
        let d_ep = self.clone();
        let ep_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                    _ = d_ep.endpoints_changed.notified() => {}
                }
                let now = d_ep.endpoints(port);
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
                    if let Err(e) = self.ensure_tun(node.ip, prefix_len) {
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
        self.update_dns();
        self.map_changed.notify_one();
    }

    /// Turn this machine's exit node role on or off, as its map entry says.
    fn set_role(self: &Arc<Self>, on: bool) {
        if on && self.is_android() {
            warn!("exit node: this device can't be an exit node (not supported on Android)");
            return;
        }
        let mut serving = self.serving.lock().unwrap();
        match (on, serving.is_some()) {
            (true, false) => match exit::serve(&self.opts.tun_name, self.opts.exit_interface.as_deref()) {
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
                        let mark = s.iface.as_ref().map(|_| exit::EXIT_MARK);
                        tokio::spawn(exit::dns_forwarder(ip, ups, allowed, s.dns.clone(), mark));
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
    /// Only while the role is on, and only for machines the hub offered us
    /// to: this account's, and those of accounts this machine is shared with
    /// as an exit node, if they may open everything here.
    fn may_use_me_as_exit(&self, ip: Ipv4Addr) -> bool {
        if self.serving.lock().unwrap().is_none() {
            return false;
        }
        let net = self.net.read().unwrap();
        let Some(me) = &net.me else { return false };
        // The hub says who may (`exit_client`: this account's machines, and
        // accounts it's shared with as an exit node). Older hubs don't say:
        // then this account's machines that may open everything here.
        net.peers.get(&ip).is_some_and(|p| {
            p.node.exit_client
                || (p.node.account == me.account && crate::acl::Access::from_wire(&p.node.inbound).is_all())
        })
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
                let keep: Vec<IpAddr> = self.hub_addrs.lock().unwrap().iter().map(|a| a.ip()).collect();
                // Android: the default routes come with a new VPN interface.
                let routed = if self.is_android() {
                    Ok(())
                } else {
                    exit::route_via(&self.opts.tun_name, v6, &keep)
                };
                match routed {
                    Ok(()) => {
                        *self.exit_in_use.write().unwrap() = Some(ip);
                        if self.is_android() {
                            self.retun.notify_one();
                        }
                        *self.exit_problem.write().unwrap() = None;
                        self.e2e.set_exit(Some(ip));
                        info!("exit node: internet traffic goes through {n}");
                        self.update_dns();
                        return;
                    }
                    Err(e) => Some(format!("routing through {n}: {e:#}")),
                }
            }
        };
        self.stop_using_exit(problem);
    }

    /// Point systemd-resolved at MagicDNS: this machine's own zone as the
    /// search domain (`laptop` → `laptop.<zone>`), every zone with machines
    /// routed here, and everything while an exit node is in use. Applied
    /// only when that changes.
    fn update_dns(&self) {
        // (Android: DNS comes with the VPN interface.)
        if !self.opts.dns || self.is_android() || self.tun.lock().unwrap().is_none() {
            return;
        }
        let want = {
            let net = self.net.read().unwrap();
            let Some(me) = &net.me else { return };
            let search = if me.zone.is_empty() {
                format!("{}.{}", me.account, net.domain)
            } else {
                me.zone.clone()
            };
            // The search domain is routed here anyway. Listing it again as a
            // routing-only domain (`~zone`) would make resolved drop it as a
            // search domain, and short names would stop working.
            let routes: Vec<String> = net.zone.routed_zones().into_iter().filter(|z| *z != search).collect();
            (search, routes, self.exit_in_use.read().unwrap().is_some())
        };
        let mut applied = self.dns_applied.lock().unwrap();
        if applied.as_ref() == Some(&want) {
            return;
        }
        *applied = Some(want.clone());
        #[cfg(unix)]
        apply_dns(&self.opts.tun_name, want.0, want.1, want.2);
        #[cfg(windows)]
        win::apply_dns(self.opts.tun_name.clone(), want.0, want.1, want.2);
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
            if self.is_android() {
                self.retun.notify_one();
            } else {
                exit::unroute();
            }
            self.e2e.set_exit(None);
            self.update_dns();
            info!("exit node: no longer in use");
        }
    }

    /// Create the TUN device, or recreate it if our address changed.
    fn ensure_tun(self: &Arc<Self>, ip: Ipv4Addr, prefix_len: u8) -> Result<()> {
        #[cfg(unix)]
        let spec = self.bridge.as_ref().map(|_| self.tun_spec(ip));
        let mut tun = self.tun.lock().unwrap();
        if tun.as_ref().is_some_and(|t| t.ip == ip) {
            return Ok(());
        }
        if let Some(old) = tun.take() {
            old.cancel.cancel();
        }
        // Totals count from when the tunnel started.
        self.traffic.lock().unwrap().clear();
        let cancel = CancellationToken::new();
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);

        // Android: the app makes the interface, with its addresses, routes
        // and DNS (see android.rs).
        #[cfg(unix)]
        if let (Some(b), Some(spec)) = (self.bridge.clone(), spec) {
            *self.tun_tx.write().unwrap() = Some(tx);
            *tun = Some(Tun {
                ip,
                v6: true,
                cancel: cancel.clone(),
            });
            drop(tun);
            let d = self.clone();
            tokio::spawn(async move {
                let dev = match b.request_tun(&spec).await {
                    Ok(fd) => android::FdTun::new(fd).map_err(anyhow::Error::from),
                    Err(e) => Err(e),
                };
                match dev {
                    Ok(dev) if !cancel.is_cancelled() => {
                        info!("VPN interface up: {:?}, routes {:?}", spec.addresses, spec.routes);
                        d.spawn_tun_io(dev, rx, cancel);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("android: {e:#}");
                        *d.last_error.write().unwrap() = Some(format!("{e:#}"));
                    }
                }
            });
            return Ok(());
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
        #[cfg(windows)]
        cfg.platform_config(|p| {
            p.device_guid(win::ADAPTER_GUID);
            p.wintun_file(win::wintun_path());
        });
        #[cfg(unix)]
        let what = "opening /dev/net/tun (tcd needs root or CAP_NET_ADMIN)";
        #[cfg(windows)]
        let what =
            "creating the Wintun adapter (tcd needs to run as SYSTEM or an administrator, with wintun.dll beside it)";
        let dev = tun::create_as_async(&cfg).context(what)?;
        *self.tun_tx.write().unwrap() = Some(tx);
        self.spawn_tun_io(dev, rx, cancel.clone());
        // IPv6: the address derived from the IPv4 one, routing the /48.
        let ip6 = crate::ip6_of(ip);
        #[cfg(unix)]
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
        #[cfg(windows)]
        let v6 = win::configure_adapter(&self.opts.tun_name, ip6, crate::TAILNET6_PREFIX);
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
        // A new interface: configure its DNS from scratch.
        *self.dns_applied.lock().unwrap() = None;
        self.update_dns();
        Ok(())
    }

    /// Move packets between the device and the tunnel until cancelled.
    fn spawn_tun_io<D>(self: &Arc<Self>, dev: D, mut rx: mpsc::Receiver<Vec<u8>>, cancel: CancellationToken)
    where
        D: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(dev);
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
        let d = self.clone();
        let mtu = self.opts.mtu as usize;
        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu + 64];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    n = rd.read(&mut buf) => match n {
                        Ok(0) => break,
                        Ok(n) => d.outbound(buf[..n].to_vec()),
                        Err(e) => { warn!("tun read: {e}"); break; }
                    },
                }
            }
        });
    }

    /// Android: the VPN interface to ask the app for: this machine's
    /// addresses, the tailnet (and everything, with an exit node), MagicDNS
    /// with this machine's zone as the search domain.
    #[cfg(unix)]
    fn tun_spec(&self, ip: Ipv4Addr) -> android::TunSpec {
        let mut routes = vec![
            format!("{}/{}", crate::TAILNET_NET, crate::TAILNET_PREFIX),
            format!("{}/{}", crate::TAILNET6, crate::TAILNET6_PREFIX),
        ];
        if self.exit_in_use.read().unwrap().is_some() {
            routes.extend(["0.0.0.0/0".to_string(), "::/0".to_string()]);
        }
        let search = {
            let net = self.net.read().unwrap();
            net.me.as_ref().map(|me| {
                if me.zone.is_empty() {
                    format!("{}.{}", me.account, net.domain)
                } else {
                    me.zone.clone()
                }
            })
        };
        android::TunSpec {
            addresses: vec![format!("{ip}/32"), format!("{}/128", crate::ip6_of(ip))],
            routes,
            dns: vec![crate::MAGIC_DNS_IP.to_string()],
            search: search.into_iter().collect(),
            mtu: self.opts.mtu,
        }
    }

    /// The device's network changed. On another network the hub
    /// connection and direct links are dead (their addresses are gone):
    /// drop the links and reconnect now, rather than after the keepalive
    /// timeout. Otherwise, report the new endpoints.
    fn network_changed(self: &Arc<Self>, change: netchange::Change) {
        match change {
            netchange::Change::None => {}
            netchange::Change::Addresses => self.endpoints_changed.notify_one(),
            netchange::Change::Network => {
                let connected = self.run.lock().unwrap().is_some();
                if !connected {
                    return;
                }
                info!("this device moved to another network; reconnecting");
                {
                    let mut net = self.net.write().unwrap();
                    for p in net.peers.values_mut() {
                        // Dropping a link's sender ends it; dial again soon.
                        p.direct = None;
                        p.last_attempt = None;
                    }
                }
                self.start(None, None);
                self.map_changed.notify_one();
            }
        }
    }

    /// Android: a new VPN interface with the current routes.
    fn android_retun(self: &Arc<Self>) {
        let old = self.tun.lock().unwrap().take();
        if let Some(t) = old {
            t.cancel.cancel();
            if let Err(e) = self.ensure_tun(t.ip, crate::TAILNET_PREFIX) {
                warn!("android: {e:#}");
            }
        }
    }

    /// Android: the underlying network's DNS servers (for the hub's name
    /// and other names); None elsewhere (the system resolves).
    fn resolver(&self) -> Option<Vec<SocketAddr>> {
        #[cfg(unix)]
        return self.bridge.as_ref().map(|b| b.resolvers());
        #[cfg(not(unix))]
        None
    }

    /// Where peers may reach the direct listener. Android: the addresses
    /// the app reports (an app can't list them itself).
    fn endpoints(&self, port: u16) -> Vec<SocketAddr> {
        #[cfg(unix)]
        if let Some(b) = &self.bridge {
            if port == 0 {
                return vec![];
            }
            let mut out: Vec<SocketAddr> = b
                .network
                .read()
                .unwrap()
                .addrs
                .iter()
                .map(|(ip, _)| *ip)
                .filter(|ip| usable_endpoint(*ip))
                .map(|ip| SocketAddr::new(ip, port))
                .collect();
            out.sort();
            out.dedup();
            return out;
        }
        local_endpoints(port)
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

    /// A peer sends through the hub while we have a direct link to it: the
    /// peer no longer has that link (it moved to another network, say), so
    /// ours is dead too, and replies sent over it would be lost until it
    /// timed out. Drop it. (Not a link just made: packets sent before it
    /// was up can still be arriving through the hub.)
    fn drop_stale_link(&self, src: Ipv4Addr) {
        const SETTLE: Duration = Duration::from_secs(10);
        let stale = self
            .net
            .read()
            .unwrap()
            .peers
            .get(&src)
            .and_then(|p| p.direct.as_ref())
            .is_some_and(|l| l.since.elapsed() > SETTLE);
        if !stale {
            return;
        }
        let mut net = self.net.write().unwrap();
        if let Some(p) = net.peers.get_mut(&src) {
            // Dropping its sender ends the link; it's dialled again later.
            p.direct = None;
            p.last_attempt = None;
            info!("{} sends through the hub: its direct path is gone", p.node.name);
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
            self.drop_stale_link(src);
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
        // Android: every app's DNS comes here; names outside the tailnet
        // go to the underlying network's servers.
        if let (false, Some(servers)) = (local, self.resolver()) {
            let tun = self.tun_tx.read().unwrap().clone();
            let (q, src, sport) = (u.payload.to_vec(), u.src, u.sport);
            #[cfg(unix)]
            let bridge = self.bridge.clone();
            tokio::spawn(async move {
                #[cfg(unix)]
                let mut servers = servers;
                #[cfg(unix)]
                let mut answer = android::exchange(&servers, &q).await;
                // The device moved to another network while asking: ask its
                // servers instead.
                #[cfg(unix)]
                if answer.is_none()
                    && let Some(now) = bridge.map(|b| b.resolvers())
                    && now != servers
                {
                    servers = now;
                    answer = android::exchange(&servers, &q).await;
                }
                #[cfg(unix)]
                match (answer, tun) {
                    (Some(a), Some(tx)) => {
                        let out = crate::packet::build_udp(crate::MAGIC_DNS_IP, src, 53, sport, &a);
                        let _ = tx.try_send(out);
                    }
                    (None, _) => {
                        // Once a minute at most.
                        static LAST: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
                        let mut last = LAST.lock().unwrap();
                        if last.is_none_or(|t| t.elapsed() > Duration::from_secs(60)) {
                            *last = Some(Instant::now());
                            warn!("DNS: no answer from {servers:?}");
                        }
                    }
                    _ => {}
                }
                #[cfg(not(unix))]
                let _ = (servers, q, src, sport, tun);
            });
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
        // Lock `serving` once: a lock taken inside the struct expression
        // below lives until its end, so taking it twice would deadlock.
        let serving = {
            let g = self.serving.lock().unwrap();
            (
                g.is_some(),
                g.as_ref().and_then(|s| s.iface.clone()),
                g.as_ref().and_then(|s| s.iface_problem.read().unwrap().clone()),
            )
        };
        let traffic = self.traffic.lock().unwrap().clone();
        let st = self.state.lock().unwrap().clone();
        let net = self.net.read().unwrap();
        let mut peers: Vec<api::PeerStatus> = net
            .peers
            .values()
            .map(|p| api::PeerStatus {
                name: p.node.name.clone(),
                account: p.node.account.clone(),
                fqdn: format!(
                    "{}.{}",
                    p.node.name,
                    if p.node.zone.is_empty() {
                        format!("{}.{}", p.node.account, net.domain)
                    } else {
                        p.node.zone.clone()
                    }
                ),
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
                exit_client: p.node.exit_client && serving.0,
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
            exit_serving: serving.0,
            exit_interface: serving.1,
            exit_interface_problem: serving.2,
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
/// May peers try `ip` for a direct session? Not loopback, link-local or a
/// tunnel address.
fn usable_endpoint(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !crate::in_tailnet(v4),
        IpAddr::V6(v6) => !v6.is_loopback() && (v6.segments()[0] & 0xffc0) != 0xfe80 && !crate::in_tailnet6(v6),
    }
}

/// Resolve `host` through `servers` (Android, which has no system
/// resolver tcd can use).
pub async fn resolve_via(host: &str, port: u16, servers: &[SocketAddr]) -> std::io::Result<Vec<SocketAddr>> {
    #[cfg(unix)]
    return android::resolve(host, port, servers)
        .await
        .map_err(|e| std::io::Error::other(format!("{e:#}")));
    #[cfg(not(unix))]
    {
        let _ = servers;
        tokio::net::lookup_host((host, port)).await.map(|a| a.collect())
    }
}

/// The address this machine reaches the internet from (the default route's
/// source), or None offline. A UDP "connect" sends nothing. A tunnel
/// address (an exit node in use) says nothing about the real network.
fn outgoing_address() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("1.1.1.1:53").ok()?;
    let ip = s.local_addr().ok()?.ip();
    usable_endpoint(ip).then_some(ip)
}

/// Desktops: another network when the outgoing address changes (Wi-Fi to
/// Ethernet, a second uplink taking over) or comes back after being gone;
/// otherwise new endpoints if the addresses changed. (Addresses that stay,
/// such as Docker's or a VM bridge's, don't hide a move.)
fn desktop_change(
    last_out: Option<IpAddr>,
    out: Option<IpAddr>,
    last: &netchange::Network,
    now: &netchange::Network,
) -> netchange::Change {
    match (last_out, out) {
        (Some(a), Some(b)) if a != b => netchange::Change::Network,
        (None, Some(_)) => netchange::Change::Network,
        _ if last.addrs != now.addrs => netchange::Change::Addresses,
        _ => netchange::Change::None,
    }
}

/// This machine's network, from its interfaces' usable addresses.
fn local_network() -> netchange::Network {
    let mut addrs: Vec<(IpAddr, u8)> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .map(|i| i.ip())
        .filter(|ip| usable_endpoint(*ip))
        .map(|ip| (ip, 0))
        .collect();
    addrs.sort();
    addrs.dedup();
    netchange::Network {
        id: 0,
        dns: vec![],
        addrs,
    }
}

fn local_endpoints(port: u16) -> Vec<SocketAddr> {
    if port == 0 {
        return vec![];
    }
    let mut out = Vec::new();
    if let Ok(ifs) = if_addrs::get_if_addrs() {
        for i in ifs {
            let ip = i.ip();
            if usable_endpoint(ip) {
                out.push(SocketAddr::new(ip, port));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(unix)]
/// Configure systemd-resolved for `tun`: MagicDNS as its server, `search`
/// as its search domain, `routes` (and `.` with `all`) routed to it.
fn apply_dns(tun: &str, search: String, routes: Vec<String>, all: bool) {
    let tun = tun.to_string();
    tokio::task::spawn_blocking(move || {
        let run = |args: &[&str]| std::process::Command::new("resolvectl").args(args).output();
        let dns = crate::MAGIC_DNS_IP.to_string();
        match run(&["dns", &tun, &dns]) {
            Ok(o) if o.status.success() => {
                let mut domains: Vec<String> = vec![search.clone()];
                domains.extend(routes.iter().map(|z| format!("~{z}")));
                if all {
                    domains.push("~.".into());
                }
                let mut args = vec!["domain", tun.as_str()];
                args.extend(domains.iter().map(String::as_str));
                let _ = run(&args);
                let _ = run(&["default-route", &tun, if all { "yes" } else { "no" }]);
                info!("MagicDNS: {} via {dns} on {tun} (search {search})", routes.join(", "));
            }
            Ok(o) => warn!(
                "MagicDNS not configured (resolvectl: {}); names still resolve with `dig @{dns}`",
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => warn!("MagicDNS not configured (resolvectl: {e}); names still resolve with `dig @{dns}`"),
        }
    });
}

/// Run a system command (iproute2 and the like).
#[cfg(unix)]
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
    // A full name, in any account's zone.
    if let Some(p) = net.peers.values().find(|p| {
        let zone = if p.node.zone.is_empty() {
            format!("{}.{}", p.node.account, net.domain)
        } else {
            p.node.zone.clone()
        };
        s == format!("{}.{zone}", p.node.name)
    }) {
        return Some(p);
    }
    let rel = s.strip_suffix(&format!(".{}", net.domain)).unwrap_or(&s);
    let my_account = net.me.as_ref().map(|m| m.account.as_str()).unwrap_or("");
    let (name, account) = rel.split_once('.').unwrap_or((rel, my_account));
    net.peers
        .values()
        .find(|p| p.node.name == name && p.node.account == account)
}

/// Asks a running daemon to shut down (the Windows service's Stop).
static SHUTDOWN: Notify = Notify::const_new();

/// Shut down the daemon, as SIGTERM does on Linux.
pub fn request_shutdown() {
    SHUTDOWN.notify_one();
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
            _ = SHUTDOWN.notified() => {}
        }
    }
    #[cfg(windows)]
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = SHUTDOWN.notified() => {}
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
    fn desktop_network_changes() {
        use super::{
            desktop_change,
            netchange::{Change, Network},
        };
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        let net = |a: &[&str]| Network {
            id: 0,
            dns: vec![],
            addrs: a.iter().map(|s| (ip(s), 0)).collect(),
        };
        let (wifi, both) = (
            net(&["172.17.0.1", "192.168.10.50"]),
            net(&["10.0.0.9", "172.17.0.1", "192.168.10.50"]),
        );
        let eth = net(&["10.0.0.9", "172.17.0.1"]);
        let (w, e) = (Some(ip("192.168.10.50")), Some(ip("10.0.0.9")));
        assert_eq!(desktop_change(w, w, &wifi, &wifi), Change::None);
        // Ethernet plugged in, Wi-Fi still the way out: new endpoints only.
        assert_eq!(desktop_change(w, w, &wifi, &both), Change::Addresses);
        // The way out moves to Ethernet (Docker's address stays): a new network.
        assert_eq!(desktop_change(w, e, &both, &eth), Change::Network);
        // Back online after being offline.
        assert_eq!(desktop_change(None, w, &net(&[]), &wifi), Change::Network);
        // Offline: nothing to reconnect to yet.
        assert_eq!(desktop_change(w, None, &wifi, &net(&[])), Change::Addresses);
    }

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
