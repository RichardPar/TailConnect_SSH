//! `tc-control`: the hub.
//!
//! Accepts SSH-in-TLS sessions on port 443, registers machines, pushes the
//! network map, and relays packets between machines that have no direct
//! path. Relayed packets are end-to-end encrypted between the machines
//! ([`crate::e2e`]): the hub sees only the destination address, and tells the
//! receiver which machine sent each message.
//!
//! Accounts, shares and access rules ([`policy`]) decide each machine's
//! network map and what each peer may open on it. The hub relays only
//! between machines that are in each other's maps; the receiving machine's
//! packet filter enforces the rest.

pub mod acme;
pub mod auth;
pub mod db;
pub mod policy;
pub mod portal;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc, watch};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::frame::{self, Frame};
use crate::keys::key_id;
use crate::proto::{ClientMsg, Node, ServerMsg};
use crate::transport::{self, KeyPolicy, ServerConn};

pub struct Options {
    pub listen: SocketAddr,
    pub state_dir: PathBuf,
    pub domain: String,
    pub tls: crate::tls::ServerTls,
    /// The web portal, on the same port (by ALPN). `None`: SSH only.
    pub portal: Option<PortalOptions>,
    /// Addresses new machines get (within 100.64.0.0/10).
    pub ip_pool: (u32, u32),
    /// Get and renew the certificate from Let's Encrypt (or another ACME
    /// server). `tls` is then only served until the first one arrives.
    pub acme: Option<acme::Config>,
    /// How long machines stay authorised (`None`: forever).
    pub key_expiry: Option<i64>,
    /// Ephemeral machines are removed after being offline this long (seconds).
    pub ephemeral_timeout: i64,
}

pub struct PortalOptions {
    pub signup: portal::Signup,
    /// Shown in join commands; empty: the host name the browser used.
    pub public_server: String,
    /// Extra host names the portal answers to.
    pub hosts: Vec<String>,
    /// Also serve the portal over plain HTTP here (for example
    /// 127.0.0.1:7741, reached through an SSH tunnel).
    pub plain_listen: Option<SocketAddr>,
}

/// A connected machine.
struct Session {
    conn_id: u64,
    key: String,
    tx: mpsc::Sender<Frame>,
    endpoints: Vec<SocketAddr>,
    kill: Arc<Notify>,
    /// Addresses in this machine's current network map: the only ones the
    /// hub relays its messages to.
    allowed: HashSet<Ipv4Addr>,
}

pub struct Hub {
    db: Mutex<db::Db>,
    domain: String,
    /// Online machines by tailnet address.
    sessions: RwLock<HashMap<Ipv4Addr, Session>>,
    /// Bumped whenever any machine's view of the network may have changed.
    map_version: watch::Sender<u64>,
    next_conn: AtomicU64,
    /// Accounts, machines, rules and shares, from one read of the database.
    snapshot: RwLock<Arc<policy::Snapshot>>,
    /// The latest traffic report of each machine, by address. In memory only.
    traffic: Mutex<HashMap<Ipv4Addr, TrafficReport>>,
}

/// A machine's latest traffic report, with speeds from the one before.
#[derive(Clone, Debug)]
pub struct TrafficReport {
    pub at: std::time::Instant,
    /// Peer address → (received, sent, receive rate, send rate), bytes and bytes/s.
    pub peers: HashMap<Ipv4Addr, (u64, u64, f64, f64)>,
}

/// Speeds older than this are shown as zero: the machine stopped reporting,
/// so its traffic stopped.
pub const TRAFFIC_STALE: Duration = Duration::from_secs(90);

impl Hub {
    fn record_traffic(&self, ip: Ipv4Addr, peers: Vec<crate::proto::PeerTraffic>) {
        let now = std::time::Instant::now();
        let mut all = self.traffic.lock().unwrap();
        let prev = all.get(&ip).cloned();
        let mut map = HashMap::new();
        for p in peers.into_iter().take(4096) {
            let (rr, tr) = match prev.as_ref().and_then(|r| r.peers.get(&p.ip).map(|o| (r.at, *o))) {
                Some((at, (orx, otx, _, _))) if p.rx >= orx && p.tx >= otx => {
                    let dt = now.duration_since(at).as_secs_f64().max(1.0);
                    ((p.rx - orx) as f64 / dt, (p.tx - otx) as f64 / dt)
                }
                // First report, or the tunnel restarted: no speed yet.
                _ => (0.0, 0.0),
            };
            map.insert(p.ip, (p.rx, p.tx, rr, tr));
        }
        all.insert(ip, TrafficReport { at: now, peers: map });
    }

    /// Traffic reports, with stale speeds zeroed.
    fn traffic(&self) -> HashMap<Ipv4Addr, TrafficReport> {
        let now = std::time::Instant::now();
        let mut out = self.traffic.lock().unwrap().clone();
        for r in out.values_mut() {
            if now.duration_since(r.at) > TRAFFIC_STALE {
                for v in r.peers.values_mut() {
                    v.2 = 0.0;
                    v.3 = 0.0;
                }
            }
        }
        out
    }
}

/// Parse a duration: a number with s, m, h or d (180d, 12h, 30m, 90s).
pub fn parse_duration(s: &str) -> Result<i64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: i64 = num
        .parse()
        .with_context(|| format!("bad duration {s:?} (use e.g. 180d, 12h, 30m)"))?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("bad duration {s:?} (use e.g. 180d, 12h, 30m)"),
    };
    if n <= 0 {
        bail!("duration must be positive");
    }
    Ok(n * mult)
}

/// A machine's view of the network.
struct MapView {
    me: Node,
    peers: Vec<Node>,
    notice: Option<String>,
}

impl Hub {
    fn bump(&self) {
        self.map_version.send_modify(|v| *v += 1);
    }

    /// Reload the policy snapshot from the database.
    fn refresh(&self) -> Result<()> {
        let s = policy::Snapshot::load(&self.db.lock().unwrap())?;
        *self.snapshot.write().unwrap() = Arc::new(s);
        Ok(())
    }

    fn snapshot(&self) -> Arc<policy::Snapshot> {
        self.snapshot.read().unwrap().clone()
    }

    /// The network map for the machine with `key`, or `None` if it no
    /// longer exists.
    fn view(&self, key: &str) -> Option<MapView> {
        let snap = self.snapshot();
        let me = snap.by_key(key)?;
        let sessions = self.sessions.read().unwrap();
        let node = |n: &policy::SNode, inbound: Vec<String>, exit_node: bool| {
            let s = sessions.get(&n.ip);
            Node {
                name: n.name.clone(),
                account: n.account.clone(),
                tags: n.tags.clone(),
                ip: n.ip,
                key: n.key.clone(),
                online: s.is_some(),
                endpoints: s.map(|s| s.endpoints.clone()).unwrap_or_default(),
                inbound,
                exit_node,
                expires: None,
            }
        };
        let (peers, notice) = match snap.peers_of(me) {
            Some(ps) => (
                ps.iter()
                    .map(|p| node(p.node, p.inbound.to_wire(), p.exit_node))
                    .collect(),
                None,
            ),
            None => (vec![], me.cutoff.clone()),
        };
        let expires = me.expires;
        let mut me = node(me, vec![], me.exit_node && me.active);
        me.expires = expires;
        me.endpoints.clear();
        Some(MapView { me, peers, notice })
    }

    /// Route one sealed message from the machine at `from`. The hub can't
    /// read it: it swaps the 4-byte destination for the sender's address,
    /// which the receiver relies on (and checks cryptographically).
    fn route(&self, from: Ipv4Addr, mut msg: Vec<u8>) {
        if msg.len() < 5 {
            return;
        }
        let dst = Ipv4Addr::new(msg[0], msg[1], msg[2], msg[3]);
        if dst == from {
            return;
        }
        msg[..4].copy_from_slice(&from.octets());
        let sessions = self.sessions.read().unwrap();
        // Only between machines that are in each other's network maps.
        if !sessions.get(&from).is_some_and(|s| s.allowed.contains(&dst)) {
            return;
        }
        if let Some(s) = sessions.get(&dst) {
            // Drop rather than block when the receiver is slow; TCP inside
            // the tunnel will back off.
            let _ = s.tx.try_send(Frame {
                kind: frame::SEALED,
                payload: msg,
            });
        }
    }

    /// Remove ephemeral machines that have been offline for `timeout` seconds.
    /// Machines with a session are never removed.
    async fn remove_ephemeral(self: Arc<Self>, timeout: i64) {
        let every = Duration::from_secs((timeout / 2).clamp(1, 60) as u64);
        loop {
            tokio::time::sleep(every).await;
            let now = crate::now_unix();
            let online: HashSet<Ipv4Addr> = self.sessions.read().unwrap().keys().copied().collect();
            let Ok(nodes) = self.db.lock().unwrap().nodes() else {
                continue;
            };
            let mut removed = false;
            for n in nodes {
                let idle = now - n.last_seen.unwrap_or(n.created);
                if n.ephemeral && !online.contains(&n.ip) && idle >= timeout {
                    match self.db.lock().unwrap().remove_node(n.id) {
                        Ok(()) => {
                            info!(
                                "removed ephemeral machine {}.{} ({}), offline for {idle}s",
                                n.name, n.account, n.ip
                            );
                            removed = true;
                        }
                        Err(e) => warn!("removing ephemeral machine {}: {e:#}", n.name),
                    }
                }
            }
            if removed {
                if let Err(e) = self.refresh() {
                    warn!("reloading policy: {e:#}");
                }
                self.bump();
            }
        }
    }

    /// Watch the database for changes made by other processes (the admin
    /// CLI), and cut off machines that were removed.
    async fn watch_db(self: Arc<Self>) {
        let mut last = self.db.lock().unwrap().data_version().unwrap_or(0);
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let v = match self.db.lock().unwrap().data_version() {
                Ok(v) => v,
                Err(e) => {
                    warn!("database: {e}");
                    continue;
                }
            };
            // A key expiring changes who's in the network, though nothing in
            // the database changes.
            let expiry_due = self.snapshot().next_expiry.is_some_and(|e| e <= crate::now_unix());
            if v == last && !expiry_due {
                continue;
            }
            last = v;
            if let Err(e) = self.refresh() {
                warn!("reloading policy: {e:#}");
                continue;
            }
            let snap = self.snapshot();
            for s in self.sessions.read().unwrap().values() {
                if snap.by_key(&s.key).is_none() {
                    s.kill.notify_one();
                }
            }
            self.bump();
        }
    }
}

pub async fn run(opts: Options) -> Result<()> {
    std::fs::create_dir_all(&opts.state_dir)?;
    let host_key = crate::keys::load_or_create(&opts.state_dir.join("ssh_host_ed25519_key"))?;
    let mut db = db::Db::open(&opts.state_dir.join("tailconnect.db"))?;
    db.set_pool(opts.ip_pool);
    db.set_key_expiry(opts.key_expiry);
    // For the admin CLI's and the portal's "default" expiry.
    db.set_setting(
        "key_expiry",
        &opts.key_expiry.map_or("never".to_string(), |s| s.to_string()),
    )?;
    info!("SSH host key: {}", key_id(host_key.public_key()));
    info!("TLS certificate SHA-256: {}", opts.tls.fingerprint);

    let hub = Arc::new(Hub {
        db: Mutex::new(db),
        domain: opts.domain.clone(),
        sessions: RwLock::new(HashMap::new()),
        map_version: watch::channel(0).0,
        next_conn: AtomicU64::new(1),
        snapshot: RwLock::new(Arc::default()),
        traffic: Mutex::new(HashMap::new()),
    });
    hub.refresh()?;
    tokio::spawn(hub.clone().watch_db());
    tokio::spawn(hub.clone().remove_ephemeral(opts.ephemeral_timeout));

    let ssh = transport::server_ssh_config(host_key);
    let portal = match &opts.portal {
        Some(po) => Some(start_portal(&hub, &opts, po).await?),
        None => None,
    };
    // ALPN: tcd asks for tc-ssh/1, browsers for http/1.1, ACME validators
    // for acme-tls/1.
    let mut alpn = vec![crate::ALPN.to_vec()];
    if portal.is_some() {
        alpn.push(crate::tls::ALPN_HTTP.to_vec());
    }
    let tls_config = match &opts.acme {
        None => {
            let mut c = (*opts.tls.config).clone();
            c.alpn_protocols = alpn;
            Arc::new(c)
        }
        Some(a) => {
            // Serve the self-signed certificate until the first one arrives.
            let fallback = acme::certified_key(
                &std::fs::read(opts.state_dir.join("tls-cert.pem")).context("reading the fallback certificate")?,
                &std::fs::read(opts.state_dir.join("tls-key.pem")).context("reading the fallback key")?,
            )?;
            let store = acme::CertStore::new(fallback);
            if matches!(a.method, acme::Method::TlsAlpn) {
                alpn.push(acme::ALPN_ACME.to_vec());
            }
            if let acme::Method::Http(addr) = a.method {
                let s = store.clone();
                tokio::spawn(async move {
                    if let Err(e) = acme::serve_http01(addr, s).await {
                        warn!("{e:#}");
                    }
                });
            }
            tokio::spawn(acme::run(Arc::new(a.clone()), store.clone()));
            crate::tls::server_with_resolver(store, alpn)?
        }
    };
    let tls = TlsAcceptor::from(tls_config);
    let listener = TcpListener::bind(opts.listen)
        .await
        .with_context(|| format!("listening on {}", opts.listen))?;
    info!(
        "listening on {} (SSH inside TLS{})",
        opts.listen,
        if portal.is_some() { ", and the web portal" } else { "" }
    );

    // Any key may authenticate: unknown keys may only register, with an
    // auth key, in their Hello message.
    let policy: KeyPolicy = Arc::new(|_| true);
    loop {
        let (tcp, peer) = listener.accept().await?;
        let (hub, tls, ssh, policy, portal) = (hub.clone(), tls.clone(), ssh.clone(), policy.clone(), portal.clone());
        tokio::spawn(async move {
            tcp.set_nodelay(true).ok();
            let tls = match tokio::time::timeout(Duration::from_secs(20), tls.accept(tcp)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return debug!("{peer}: TLS handshake: {e}"),
                Err(_) => return debug!("{peer}: TLS handshake timed out"),
            };
            // tcd asks for tc-ssh/1; anything else (browsers) is the portal.
            let alpn = tls.get_ref().1.alpn_protocol();
            if alpn == Some(acme::ALPN_ACME) {
                // A TLS-ALPN-01 validation: the handshake was the answer.
                return;
            }
            let is_ssh = alpn == Some(crate::ALPN);
            if !is_ssh {
                if let Some(router) = portal {
                    portal::serve_conn(router, tls, portal::ConnInfo { peer, tls: true }).await;
                }
                return;
            }
            let conn = tokio::time::timeout(Duration::from_secs(20), transport::accept_ssh(tls, ssh, policy)).await;
            match conn {
                Ok(Ok(conn)) => {
                    if let Err(e) = serve(hub, conn, peer).await {
                        info!("{peer}: {e:#}");
                    }
                }
                Ok(Err(e)) => debug!("{peer}: {e:#}"),
                Err(_) => debug!("{peer}: SSH handshake timed out"),
            }
        });
    }
}

/// Set up the web portal; returns its router. It has its own database
/// connection, so the hub notices its changes like the CLI's.
async fn start_portal(hub: &Arc<Hub>, opts: &Options, po: &PortalOptions) -> Result<axum::Router> {
    let db = db::Db::open(&opts.state_dir.join("tailconnect.db"))?;
    let mut hosts: Vec<String> = po.hosts.iter().map(|h| h.trim().to_ascii_lowercase()).collect();
    hosts.extend(opts.tls.names.iter().cloned());
    if let Some(a) = &opts.acme {
        hosts.extend(a.domains.iter().cloned());
    }
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        hosts.push(h.trim().to_ascii_lowercase());
    }
    if !po.public_server.is_empty() {
        let (h, _) = crate::client::parse_server(&po.public_server)?;
        hosts.push(h.to_ascii_lowercase());
    }
    hosts.retain(|h| !h.is_empty());
    hosts.sort();
    hosts.dedup();
    let operators = db
        .accounts()?
        .iter()
        .filter(|a| a.role == db::Role::Operator && a.has_password)
        .count();
    if operators == 0 {
        warn!(
            "portal: no operator can sign in yet: create one with `tc-control accounts create NAME --operator --password`, or use `tc-control admin-token`"
        );
    }
    let cfg = portal::Config {
        signup: po.signup,
        domain: opts.domain.clone(),
        // With Let's Encrypt, join commands name the certificate's domain and
        // need no fingerprint.
        public_server: match (&opts.acme, po.public_server.is_empty()) {
            (Some(a), true) => a.domains[0].clone(),
            _ => po.public_server.clone(),
        },
        tls_fingerprint: (opts.tls.self_signed && opts.acme.is_none()).then(|| opts.tls.fingerprint.clone()),
        hosts,
    };
    info!(
        "portal: sign-up {}; answers to IP addresses, localhost and {}",
        po.signup.as_str(),
        if cfg.hosts.is_empty() {
            "no other names".into()
        } else {
            cfg.hosts.join(", ")
        }
    );
    let h = hub.clone();
    let online: portal::OnlineFn = Arc::new(move || h.sessions.read().unwrap().keys().copied().collect());
    let h = hub.clone();
    let traffic: portal::TrafficFn = Arc::new(move || h.traffic());
    let router = portal::router(portal::Portal::new(cfg, db, online, traffic));
    if let Some(addr) = po.plain_listen {
        let l = TcpListener::bind(addr)
            .await
            .with_context(|| format!("portal: listening on {addr}"))?;
        if !addr.ip().is_loopback() {
            warn!("portal: plain HTTP on {addr}: passwords cross the network unencrypted");
        }
        info!("portal: also plain HTTP on {addr}");
        let r = router.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, peer)) = l.accept().await else { continue };
                let r = r.clone();
                tokio::spawn(portal::serve_conn(r, tcp, portal::ConnInfo { peer, tls: false }));
            }
        });
    }
    Ok(router)
}

async fn serve(hub: Arc<Hub>, conn: ServerConn, peer: SocketAddr) -> Result<()> {
    let key = key_id(&conn.client_key);
    let ServerConn { handle, stream, .. } = conn;
    let close = || async {
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "bye".into(), "en".into())
            .await;
    };
    let (mut rd, wr) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel::<Frame>(1024);
    let writer = tokio::spawn(frame::writer_task(wr, rx));

    // Hello.
    let hello = tokio::time::timeout(Duration::from_secs(15), frame::read_frame(&mut rd))
        .await
        .map_err(|_| anyhow!("no hello"))??
        .ok_or_else(|| anyhow!("closed before hello"))?;
    let (hostname, auth_key, endpoints, listen_port) = match serde_json::from_slice(&hello.payload) {
        Ok(ClientMsg::Hello {
            version,
            hostname,
            auth_key,
            endpoints,
            listen_port,
        }) if hello.kind == frame::CONTROL => {
            if version < crate::PROTOCOL_VERSION {
                let message = format!(
                    "tcd protocol version {version} is too old (the hub needs {}, with end-to-end encryption); upgrade tcd",
                    crate::PROTOCOL_VERSION
                );
                let _ = tx.send(Frame::control(&ServerMsg::Error { message })).await;
                drop(tx);
                let _ = writer.await;
                close().await;
                bail!("client protocol version {version} too old");
            }
            (hostname, auth_key, endpoints, listen_port)
        }
        _ => bail!("expected hello"),
    };

    let registered = hub.db.lock().unwrap().node_by_key(&key)?;
    let node = match (registered, auth_key) {
        // `tc up --authkey` on a registered machine: renew its authorisation.
        (Some(_), Some(ak)) => {
            let r = hub.db.lock().unwrap().reauthorize(&key, &ak);
            match r {
                Ok(n) => {
                    info!("renewed {}.{} ({})", n.name, n.account, n.ip);
                    hub.refresh()?;
                    hub.bump();
                    n
                }
                Err(e) => {
                    let _ = tx
                        .send(Frame::control(&ServerMsg::Error { message: e.to_string() }))
                        .await;
                    drop(tx);
                    let _ = writer.await;
                    close().await;
                    return Err(e.context("renewal refused"));
                }
            }
        }
        (Some(n), None) => n,
        (None, Some(ak)) => {
            let r = hub.db.lock().unwrap().register(&key, &hostname, &ak);
            match r {
                Ok(n) => {
                    info!("registered {}.{} ({}) at {} from {peer}", n.name, n.account, n.ip, key);
                    hub.refresh()?;
                    n
                }
                Err(e) => {
                    let _ = tx
                        .send(Frame::control(&ServerMsg::Error { message: e.to_string() }))
                        .await;
                    drop(tx);
                    let _ = writer.await;
                    close().await;
                    return Err(e.context("registration refused"));
                }
            }
        }
        (None, None) => {
            let msg = "this machine is not registered; join with an auth key";
            let _ = tx.send(Frame::control(&ServerMsg::Error { message: msg.into() })).await;
            drop(tx);
            let _ = writer.await;
            close().await;
            bail!("unregistered machine without auth key");
        }
    };
    hub.db.lock().unwrap().touch(&key)?;
    let ip = node.ip;

    let conn_id = hub.next_conn.fetch_add(1, Ordering::Relaxed);
    let kill = Arc::new(Notify::new());
    let observed = peer.ip();
    {
        let mut sessions = hub.sessions.write().unwrap();
        if let Some(old) = sessions.remove(&ip) {
            old.kill.notify_one();
        }
        sessions.insert(
            ip,
            Session {
                conn_id,
                key: key.clone(),
                tx: tx.clone(),
                endpoints: with_observed(endpoints, observed, listen_port),
                kill: kill.clone(),
                allowed: HashSet::new(),
            },
        );
    }
    let label = format!("{}.{}", node.name, node.account);
    info!("{label} ({ip}) online from {peer}");

    let mut version = hub.map_version.subscribe();
    // The first map goes out from the loop below, triggered by this bump.
    version.mark_changed();
    hub.bump();

    // Reader: route packets inline, pass control messages to the loop.
    let (ctl_tx, mut ctl_rx) = mpsc::channel::<ClientMsg>(16);
    let hub_r = hub.clone();
    let mut reader = tokio::spawn(async move {
        loop {
            match frame::read_frame(&mut rd).await {
                // Plain PACKET frames are never relayed: they would be
                // readable here.
                Ok(Some(f)) if f.kind == frame::SEALED => hub_r.route(ip, f.payload),
                Ok(Some(f)) if f.kind == frame::CONTROL => match serde_json::from_slice(&f.payload) {
                    Ok(m) => {
                        if ctl_tx.send(m).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => debug!("bad control message: {e}"),
                },
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(e) => {
                    debug!("read: {e}");
                    break;
                }
            }
        }
    });

    let mut last_me: Option<Node> = None;
    loop {
        tokio::select! {
            _ = &mut reader => break,
            _ = kill.notified() => break,
            r = version.changed() => {
                if r.is_err() { break; }
                version.borrow_and_update();
                // Removed?
                let Some(view) = hub.view(&key) else { break };
                // First map, or renamed: (re)introduce the machine to itself.
                if last_me.as_ref() != Some(&view.me) {
                    last_me = Some(view.me.clone());
                    let w = ServerMsg::Welcome {
                        node: view.me,
                        domain: hub.domain.clone(),
                        prefix_len: crate::TAILNET_PREFIX,
                    };
                    if tx.send(Frame::control(&w)).await.is_err() {
                        break;
                    }
                }
                let allowed: HashSet<Ipv4Addr> = view.peers.iter().map(|p| p.ip).collect();
                if let Some(s) = hub.sessions.write().unwrap().get_mut(&ip)
                    && s.conn_id == conn_id
                {
                    s.allowed = allowed;
                }
                let m = ServerMsg::NetMap { peers: view.peers, notice: view.notice };
                if tx.send(Frame::control(&m)).await.is_err() {
                    break;
                }
            }
            Some(m) = ctl_rx.recv() => {
                match m {
                    ClientMsg::Endpoints { endpoints, listen_port } => {
                        if let Some(s) = hub.sessions.write().unwrap().get_mut(&ip)
                            && s.conn_id == conn_id {
                                s.endpoints = with_observed(endpoints, observed, listen_port);
                            }
                        hub.bump();
                    }
                    ClientMsg::Traffic { peers } => hub.record_traffic(ip, peers),
                    ClientMsg::Hello { .. } => {}
                }
            }
        }
    }

    reader.abort();
    {
        let mut sessions = hub.sessions.write().unwrap();
        if sessions.get(&ip).is_some_and(|s| s.conn_id == conn_id) {
            sessions.remove(&ip);
        }
    }
    let _ = hub.db.lock().unwrap().touch(&key);
    hub.bump();
    drop(tx);
    writer.abort();
    close().await;
    info!("{label} ({ip}) offline");
    Ok(())
}

/// Add the address we see the machine coming from, with its listen port,
/// to the endpoints it reported, and drop anything unusable.
fn with_observed(mut eps: Vec<SocketAddr>, observed: IpAddr, port: u16) -> Vec<SocketAddr> {
    eps.retain(|e| match e.ip() {
        IpAddr::V4(v4) => !crate::in_tailnet(v4) && !v4.is_unspecified() && e.port() != 0,
        IpAddr::V6(v6) => !v6.is_unspecified() && e.port() != 0,
    });
    if port != 0 {
        let ip = match observed {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(observed),
            v4 => v4,
        };
        let ep = SocketAddr::new(ip, port);
        if !eps.contains(&ep) {
            eps.insert(0, ep);
        }
    }
    eps.truncate(16);
    eps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::PeerTraffic;

    fn hub() -> Hub {
        Hub {
            db: Mutex::new(db::Db::memory()),
            domain: "tc.internal".into(),
            sessions: RwLock::new(HashMap::new()),
            map_version: watch::channel(0).0,
            next_conn: AtomicU64::new(1),
            snapshot: RwLock::new(Arc::default()),
            traffic: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn traffic_speeds_from_consecutive_reports() {
        let h = hub();
        let me = Ipv4Addr::new(100, 64, 0, 1);
        let peer = Ipv4Addr::new(100, 64, 0, 2);
        h.record_traffic(
            me,
            vec![PeerTraffic {
                ip: peer,
                rx: 1000,
                tx: 500,
            }],
        );
        assert_eq!(
            h.traffic()[&me].peers[&peer],
            (1000, 500, 0.0, 0.0),
            "first report: no speed yet"
        );
        // Pretend the first report was 10 seconds ago.
        h.traffic.lock().unwrap().get_mut(&me).unwrap().at -= Duration::from_secs(10);
        h.record_traffic(
            me,
            vec![PeerTraffic {
                ip: peer,
                rx: 21000,
                tx: 1500,
            }],
        );
        let (rx, tx, rr, tr) = h.traffic()[&me].peers[&peer];
        assert_eq!((rx, tx), (21000, 1500));
        assert!((rr - 2000.0).abs() < 50.0 && (tr - 100.0).abs() < 5.0, "{rr} {tr}");
        // A restarted tunnel (smaller totals) has no speed, not a negative one.
        h.traffic.lock().unwrap().get_mut(&me).unwrap().at -= Duration::from_secs(10);
        h.record_traffic(
            me,
            vec![PeerTraffic {
                ip: peer,
                rx: 10,
                tx: 10,
            }],
        );
        assert_eq!(h.traffic()[&me].peers[&peer].2, 0.0);
        // A machine that stopped reporting: speeds drop to zero, totals stay.
        h.traffic
            .lock()
            .unwrap()
            .get_mut(&me)
            .unwrap()
            .peers
            .get_mut(&peer)
            .unwrap()
            .2 = 99.0;
        h.traffic.lock().unwrap().get_mut(&me).unwrap().at -= TRAFFIC_STALE + Duration::from_secs(1);
        assert_eq!(h.traffic()[&me].peers[&peer], (10, 10, 0.0, 0.0));
    }
}
