//! SSH-inside-TLS connections.
//!
//! Dialling: TCP → TLS (ALPN `tc-ssh/1`) → SSH, public-key auth with the
//! machine key → one session channel used as a byte stream for frames.
//!
//! Accepting: the reverse, with the SSH public key the client proved it holds
//! handed to the caller as its identity.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{ChannelStream, client, server};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::keys::key_id;

const KEEPALIVE: Duration = Duration::from_secs(15);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// How the client checks the SSH host key.
#[derive(Debug, Clone)]
pub enum HostKey {
    /// Must equal this key id.
    Pinned(String),
    /// Trust on first use: accept and report it.
    Tofu,
}

pub struct ClientHandler {
    expect: HostKey,
    seen: Arc<Mutex<Option<String>>>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            return Ok(false);
        };
        let id = key_id(key);
        *self.seen.lock().unwrap() = Some(id.clone());
        Ok(match &self.expect {
            HostKey::Pinned(want) => *want == id,
            HostKey::Tofu => true,
        })
    }
}

/// A live client connection. Keep `handle` alive as long as `stream` is used.
pub struct ClientConn {
    pub handle: client::Handle<ClientHandler>,
    pub stream: ChannelStream<client::Msg>,
    /// The server's SSH host key id, as verified.
    pub host_key: String,
}

fn client_ssh_config() -> Arc<client::Config> {
    Arc::new(client::Config {
        inactivity_timeout: Some(KEEPALIVE * 4),
        keepalive_interval: Some(KEEPALIVE),
        keepalive_max: 3,
        nodelay: true,
        window_size: 8 << 20,
        ..Default::default()
    })
}

pub fn server_ssh_config(host_key: PrivateKey) -> Arc<server::Config> {
    Arc::new(server::Config {
        inactivity_timeout: Some(KEEPALIVE * 4),
        keepalive_interval: Some(KEEPALIVE),
        keepalive_max: 3,
        nodelay: true,
        window_size: 8 << 20,
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![host_key],
        ..Default::default()
    })
}

/// Mark outgoing sockets with this firewall mark (0: don't). tcd sets it so
/// that, while an exit node is in use, its own connections still go out
/// through the real network.
pub static SOCKET_MARK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

async fn connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let sock = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    let mark = SOCKET_MARK.load(std::sync::atomic::Ordering::Relaxed);
    if mark != 0 {
        use std::os::fd::AsRawFd;
        set_mark(sock.as_raw_fd(), mark);
    }
    sock.connect(addr).await
}

/// Set a socket's firewall mark (needs CAP_NET_ADMIN; ignored without).
pub fn set_mark(fd: std::os::fd::RawFd, mark: u32) {
    let m: libc::c_uint = mark;
    // SAFETY: setsockopt on a valid fd with a pointer to a c_uint of the given size.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &m as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if r != 0 {
        tracing::debug!("SO_MARK: {}", std::io::Error::last_os_error());
    }
}

/// Dial `addr` and bring up SSH-in-TLS.
///
/// `sni` is the TLS server name (a host name, or an IP literal).
pub async fn dial(
    addr: SocketAddr,
    sni: &str,
    tls: Arc<rustls::ClientConfig>,
    key: Arc<PrivateKey>,
    user: &str,
    host_key: HostKey,
    connect_timeout: Duration,
) -> Result<ClientConn> {
    let tcp = tokio::time::timeout(connect_timeout, connect(addr))
        .await
        .map_err(|_| anyhow!("connect to {addr} timed out"))?
        .with_context(|| format!("connect to {addr}"))?;
    tcp.set_nodelay(true).ok();
    tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake_client(tcp, sni, tls, key, user, host_key))
        .await
        .map_err(|_| anyhow!("handshake with {addr} timed out"))?
}

async fn handshake_client(
    tcp: TcpStream,
    sni: &str,
    tls: Arc<rustls::ClientConfig>,
    key: Arc<PrivateKey>,
    user: &str,
    host_key: HostKey,
) -> Result<ClientConn> {
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).context("bad TLS server name")?;
    let tls = TlsConnector::from(tls)
        .connect(name, tcp)
        .await
        .context("TLS handshake")?;
    let seen = Arc::new(Mutex::new(None));
    let handler = ClientHandler {
        expect: host_key.clone(),
        seen: seen.clone(),
    };
    let mut handle = client::connect_stream(client_ssh_config(), tls, handler)
        .await
        .map_err(|e| {
            if let HostKey::Pinned(want) = &host_key
                && let Some(got) = seen.lock().unwrap().as_ref().filter(|g| *g != want)
            {
                return anyhow!("SSH host key changed: expected {want}, server presented {got}");
            }
            anyhow!("SSH handshake: {e}")
        })?;
    let auth = handle
        .authenticate_publickey(user, PrivateKeyWithHashAlg::new(key, None))
        .await
        .context("SSH authentication")?;
    if !auth.success() {
        bail!("SSH public-key authentication rejected");
    }
    let channel = handle.channel_open_session().await.context("opening SSH channel")?;
    let host_key = seen.lock().unwrap().clone().unwrap_or_default();
    Ok(ClientConn {
        handle,
        stream: channel.into_stream(),
        host_key,
    })
}

/// Decides whether an authenticated client key may proceed.
pub type KeyPolicy = Arc<dyn Fn(&PublicKey) -> bool + Send + Sync>;

struct ServerHandler {
    policy: KeyPolicy,
    authed: Option<PublicKey>,
    tx: Option<oneshot::Sender<(ChannelStream<server::Msg>, PublicKey)>>,
}

impl server::Handler for ServerHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: server::VerifiedPublicKey<'_>,
    ) -> Result<server::Auth, Self::Error> {
        if (self.policy)(key.public_key) {
            self.authed = Some(key.public_key.clone());
            Ok(server::Auth::Accept)
        } else {
            Ok(server::Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        match (self.authed.clone(), self.tx.take()) {
            (Some(key), Some(tx)) => {
                reply.accept().await;
                let _ = tx.send((channel.into_stream(), key));
            }
            _ => {
                reply
                    .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                    .await
            }
        }
        Ok(())
    }
}

/// An accepted connection.
pub struct ServerConn {
    pub handle: server::Handle,
    pub stream: ChannelStream<server::Msg>,
    /// The client's proven public key.
    pub client_key: PublicKey,
}

impl ServerConn {
    pub async fn close(&self) {
        let _ = self
            .handle
            .disconnect(russh::Disconnect::ByApplication, "closing".into(), "en".into())
            .await;
    }
}

/// Accept TLS then SSH on `tcp`, and wait for the client's session channel.
pub async fn accept(
    tcp: TcpStream,
    tls: TlsAcceptor,
    ssh: Arc<server::Config>,
    policy: KeyPolicy,
) -> Result<ServerConn> {
    tcp.set_nodelay(true).ok();
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
        let tls = tls.accept(tcp).await.context("TLS handshake")?;
        accept_ssh(tls, ssh, policy).await
    })
    .await
    .map_err(|_| anyhow!("handshake timed out"))?
}

/// Run SSH on an already accepted stream (the hub accepts TLS itself, to
/// choose between SSH and the web portal by ALPN).
pub async fn accept_ssh<S>(stream: S, ssh: Arc<server::Config>, policy: KeyPolicy) -> Result<ServerConn>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = oneshot::channel();
    let handler = ServerHandler {
        policy,
        authed: None,
        tx: Some(tx),
    };
    let running = server::run_stream(ssh, stream, handler)
        .await
        .map_err(|e| anyhow!("SSH: {e}"))?;
    let handle = running.handle();
    tokio::spawn(async move {
        if let Err(e) = running.await {
            tracing::debug!("ssh session ended: {e}");
        }
    });
    let (stream, client_key) = rx
        .await
        .map_err(|_| anyhow!("client closed before opening a channel"))?;
    Ok(ServerConn {
        handle,
        stream,
        client_key,
    })
}
