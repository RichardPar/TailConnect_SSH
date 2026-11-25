//! `tc-control`: the hub.
//!
//! Accepts SSH-in-TLS sessions on port 443, registers machines, pushes the
//! network map, and relays packets between machines that have no direct
//! path. Relayed packets are end-to-end encrypted between the machines
//! ([`crate::e2e`]): the hub sees only the destination address, and tells the
//! receiver which machine sent each message.

pub mod db;

use std::collections::HashMap;
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
}

/// A connected machine.
struct Session {
    conn_id: u64,
    key: String,
    tx: mpsc::Sender<Frame>,
    endpoints: Vec<SocketAddr>,
    kill: Arc<Notify>,
}

pub struct Hub {
    db: Mutex<db::Db>,
    domain: String,
    /// Online machines by tailnet address.
    sessions: RwLock<HashMap<Ipv4Addr, Session>>,
    /// Bumped whenever any machine's view of the network may have changed.
    map_version: watch::Sender<u64>,
    next_conn: AtomicU64,
}

impl Hub {
    fn bump(&self) {
        self.map_version.send_modify(|v| *v += 1);
    }

    fn netmap_for(&self, me: Ipv4Addr) -> Result<Vec<Node>> {
        let nodes = self.db.lock().unwrap().nodes()?;
        let sessions = self.sessions.read().unwrap();
        Ok(nodes
            .into_iter()
            .filter(|n| n.ip != me)
            .map(|n| {
                let s = sessions.get(&n.ip);
                Node {
                    name: n.name,
                    ip: n.ip,
                    key: n.key,
                    online: s.is_some(),
                    endpoints: s.map(|s| s.endpoints.clone()).unwrap_or_default(),
                }
            })
            .collect())
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
        if let Some(s) = sessions.get(&dst) {
            // Drop rather than block when the receiver is slow; TCP inside
            // the tunnel will back off.
            let _ = s.tx.try_send(Frame {
                kind: frame::SEALED,
                payload: msg,
            });
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
            if v == last {
                continue;
            }
            last = v;
            let known: std::collections::HashSet<String> = match self.db.lock().unwrap().nodes() {
                Ok(n) => n.into_iter().map(|n| n.key).collect(),
                Err(_) => continue,
            };
            for s in self.sessions.read().unwrap().values() {
                if !known.contains(&s.key) {
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
    let db = db::Db::open(&opts.state_dir.join("tailconnect.db"))?;
    info!("SSH host key: {}", key_id(host_key.public_key()));
    info!("TLS certificate SHA-256: {}", opts.tls.fingerprint);

    let hub = Arc::new(Hub {
        db: Mutex::new(db),
        domain: opts.domain.clone(),
        sessions: RwLock::new(HashMap::new()),
        map_version: watch::channel(0).0,
        next_conn: AtomicU64::new(1),
    });
    tokio::spawn(hub.clone().watch_db());

    let ssh = transport::server_ssh_config(host_key);
    let tls = TlsAcceptor::from(opts.tls.config.clone());
    let listener = TcpListener::bind(opts.listen)
        .await
        .with_context(|| format!("listening on {}", opts.listen))?;
    info!("listening on {} (SSH inside TLS)", opts.listen);

    // Any key may authenticate: unknown keys may only register, with an
    // auth key, in their Hello message.
    let policy: KeyPolicy = Arc::new(|_| true);
    loop {
        let (tcp, peer) = listener.accept().await?;
        let (hub, tls, ssh, policy) = (hub.clone(), tls.clone(), ssh.clone(), policy.clone());
        tokio::spawn(async move {
            match transport::accept(tcp, tls, ssh, policy).await {
                Ok(conn) => {
                    if let Err(e) = serve(hub, conn, peer).await {
                        info!("{peer}: {e:#}");
                    }
                }
                Err(e) => debug!("{peer}: {e:#}"),
            }
        });
    }
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
        (Some(n), _) => n,
        (None, Some(ak)) => {
            let r = hub.db.lock().unwrap().register(&key, &hostname, &ak);
            match r {
                Ok(n) => {
                    info!("registered {} ({}) at {} from {peer}", n.name, n.ip, key);
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
            },
        );
    }
    info!("{} ({ip}) online from {peer}", node.name);

    let welcome = ServerMsg::Welcome {
        node: Node {
            name: node.name.clone(),
            ip,
            key: key.clone(),
            online: true,
            endpoints: vec![],
        },
        domain: hub.domain.clone(),
        prefix_len: crate::TAILNET_PREFIX,
    };
    let _ = tx.send(Frame::control(&welcome)).await;
    let mut version = hub.map_version.subscribe();
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

    let mut last_name = node.name.clone();
    loop {
        tokio::select! {
            _ = &mut reader => break,
            _ = kill.notified() => break,
            r = version.changed() => {
                if r.is_err() { break; }
                version.borrow_and_update();
                // Renamed or removed?
                let row = hub.db.lock().unwrap().node_by_key(&key);
                match row {
                    Ok(None) => break,
                    Ok(Some(n)) if n.name != last_name => {
                        last_name = n.name.clone();
                        let w = ServerMsg::Welcome {
                            node: Node { name: n.name, ip, key: key.clone(), online: true, endpoints: vec![] },
                            domain: hub.domain.clone(),
                            prefix_len: crate::TAILNET_PREFIX,
                        };
                        let _ = tx.send(Frame::control(&w)).await;
                    }
                    _ => {}
                }
                let Ok(peers) = hub.netmap_for(ip) else { continue };
                if tx.send(Frame::control(&ServerMsg::NetMap { peers })).await.is_err() {
                    break;
                }
            }
            Some(m) = ctl_rx.recv() => {
                if let ClientMsg::Endpoints { endpoints, listen_port } = m {
                    if let Some(s) = hub.sessions.write().unwrap().get_mut(&ip)
                        && s.conn_id == conn_id {
                            s.endpoints = with_observed(endpoints, observed, listen_port);
                        }
                    hub.bump();
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
    info!("{last_name} ({ip}) offline");
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
