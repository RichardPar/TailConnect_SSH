//! SSH-inside-TLS connections.
//!
//! Dialling: TCP → TLS (ALPN `h2, http/1.1`, like a browser) → SSH,
//! public-key auth with the machine key → one session channel used as a byte
//! stream for frames. A server from before SSH sniffing turns that ALPN down,
//! so a failed handshake is tried once more offering `tc-ssh/1`.
//!
//! Accepting: the reverse, with the SSH public key the client proved it holds
//! handed to the caller as its identity. Servers send nothing until the
//! client has: its first bytes (`SSH-`, or an HTTP request) say which it is.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{ChannelStream, client, server};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::keys::key_id;

/// Seconds between SSH keepalives on an idle connection. A connection that
/// misses three is dead: with 5 s that's noticed in 15–20 s, so a failed
/// link (the Wi-Fi gone, a dead uplink) moves to another path quickly. The
/// Android app sets 10 s (fewer wake-ups of a phone's radio; Android tells
/// it about network changes anyway).
pub static KEEPALIVE_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(5);

fn keepalive() -> Duration {
    Duration::from_secs(KEEPALIVE_SECS.load(std::sync::atomic::Ordering::Relaxed).max(1))
}
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

/// The SSH algorithms both ends offer: only what TailConnect needs, all
/// strong. AEAD ciphers only (no CBC/CTR with a separate MAC), no
/// compression (compressing before encrypting can leak hints about the
/// content), Ed25519 keys only (every machine and hub key is Ed25519). Key
/// exchange stays russh's default: ML-KEM-768 + X25519 (post-quantum
/// hybrid) first, then X25519, never SHA-1.
fn preferred() -> russh::Preferred {
    use std::borrow::Cow;
    russh::Preferred {
        key: Cow::Owned(vec![russh::keys::Algorithm::Ed25519]),
        cipher: Cow::Borrowed(&[russh::cipher::CHACHA20_POLY1305, russh::cipher::AES_256_GCM]),
        compression: Cow::Borrowed(&[russh::compression::NONE]),
        ..russh::Preferred::DEFAULT
    }
}

fn client_ssh_config() -> Arc<client::Config> {
    Arc::new(client::Config {
        preferred: preferred(),
        inactivity_timeout: Some(keepalive() * 4),
        keepalive_interval: Some(keepalive()),
        keepalive_max: 3,
        nodelay: true,
        window_size: 8 << 20,
        ..Default::default()
    })
}

pub fn server_ssh_config(host_key: PrivateKey) -> Arc<server::Config> {
    Arc::new(server::Config {
        preferred: preferred(),
        inactivity_timeout: Some(keepalive() * 4),
        keepalive_interval: Some(keepalive()),
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
        set_mark(&sock, mark);
    }
    fail_fast(&sock);
    sock.connect(addr).await
}

/// Give up on a connection whose sent data (keepalives included) goes
/// unacknowledged for two keepalive intervals, instead of the kernel's
/// minutes of retransmitting: a dead path is noticed in about that long.
/// Linux and Android (TCP_USER_TIMEOUT); elsewhere the SSH keepalives do it.
#[cfg(target_os = "linux")]
pub fn fail_fast(sock: &impl std::os::fd::AsRawFd) {
    let ms: libc::c_uint = (keepalive().as_millis() * 2) as libc::c_uint;
    // SAFETY: setsockopt on a valid fd with a pointer to a c_uint of the given size.
    let r = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_USER_TIMEOUT,
            &ms as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if r != 0 {
        tracing::debug!("TCP_USER_TIMEOUT: {}", std::io::Error::last_os_error());
    }
}

#[cfg(not(target_os = "linux"))]
pub fn fail_fast<S>(_sock: &S) {}

/// Set a socket's firewall mark (needs CAP_NET_ADMIN; ignored without).
#[cfg(unix)]
pub fn set_mark(sock: &impl std::os::fd::AsRawFd, mark: u32) {
    let fd = sock.as_raw_fd();
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

/// Windows has no firewall marks: while an exit node is in use, a host route
/// keeps the hub on the real network instead (see the client's exit module).
#[cfg(windows)]
pub fn set_mark(_sock: &impl std::os::windows::io::AsRawSocket, _mark: u32) {}

/// Dial `addr` and bring up SSH-in-TLS.
///
/// `sni` is the TLS server name (a host name, or an IP literal, which sends
/// no name at all).
pub async fn dial(
    addr: SocketAddr,
    sni: &str,
    tls: crate::tls::ClientTls,
    key: Arc<PrivateKey>,
    user: &str,
    host_key: HostKey,
    connect_timeout: Duration,
) -> Result<ClientConn> {
    let attempt = |config: Arc<rustls::ClientConfig>| {
        let (key, host_key) = (key.clone(), host_key.clone());
        async move {
            let tcp = tokio::time::timeout(connect_timeout, connect(addr))
                .await
                .map_err(|_| Failed::other(anyhow!("connect to {addr} timed out")))?
                .with_context(|| format!("connect to {addr}"))
                .map_err(Failed::other)?;
            tcp.set_nodelay(true).ok();
            tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                handshake_client(tcp, sni, config, key, user, host_key),
            )
            .await
            .map_err(|_| Failed::other(anyhow!("handshake with {addr} timed out")))
            .and_then(|r| r)
        }
    };
    match attempt(tls.modern).await {
        Ok(c) => Ok(c),
        // Only a server that is clearly from before SSH sniffing gets the
        // old ALPN: retrying on any failure would put tc-ssh/1 on the wire
        // whenever a peer is merely down or refuses us.
        Err(Failed {
            old_server: true,
            error,
        }) => {
            tracing::debug!("{addr}: {error:#}; an older server, trying the old ALPN");
            attempt(tls.legacy).await.map_err(|f| f.error)
        }
        Err(f) => Err(f.error),
    }
}

/// A failed dial, and whether the server looked like one from before SSH
/// sniffing: it refused the browser ALPN (an older peer) or answered SSH
/// with HTTP (an older hub's portal).
struct Failed {
    old_server: bool,
    error: anyhow::Error,
}

impl Failed {
    fn other(error: anyhow::Error) -> Self {
        Failed {
            old_server: false,
            error,
        }
    }
}

/// Wraps a stream and keeps the first bytes read from it.
struct FirstBytes<S> {
    inner: S,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for FirstBytes<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let mut seen = self.seen.lock().unwrap();
        if seen.len() < 8 {
            let new = &buf.filled()[before..];
            let n = new.len().min(8 - seen.len());
            seen.extend_from_slice(&new[..n]);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FirstBytes<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Did the TLS handshake fail because the server accepts none of our ALPN
/// protocols?
fn refused_alpn(e: &std::io::Error) -> bool {
    use rustls::AlertDescription::NoApplicationProtocol;
    e.get_ref()
        .and_then(|i| i.downcast_ref::<rustls::Error>())
        .is_some_and(|e| {
            matches!(
                e,
                rustls::Error::AlertReceived(NoApplicationProtocol) | rustls::Error::NoApplicationProtocol
            )
        })
}

async fn handshake_client(
    tcp: TcpStream,
    sni: &str,
    tls: Arc<rustls::ClientConfig>,
    key: Arc<PrivateKey>,
    user: &str,
    host_key: HostKey,
) -> Result<ClientConn, Failed> {
    let name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .context("bad TLS server name")
        .map_err(Failed::other)?;
    let tls = TlsConnector::from(tls).connect(name, tcp).await.map_err(|e| Failed {
        old_server: refused_alpn(&e),
        error: anyhow!(e).context("TLS handshake"),
    })?;
    let first = Arc::new(Mutex::new(Vec::new()));
    let tls = FirstBytes {
        inner: tls,
        seen: first.clone(),
    };
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
                return Failed::other(anyhow!("SSH host key changed: expected {want}, server presented {got}"));
            }
            Failed {
                old_server: first.lock().unwrap().starts_with(b"HTTP/"),
                error: anyhow!("SSH handshake: {e}"),
            }
        })?;
    let r: Result<ClientConn> = async {
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
    .await;
    r.map_err(Failed::other)
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
        let mut tls = tls.accept(tcp).await.context("TLS handshake")?;
        let (is_ssh, first) = sniff_ssh(&mut tls).await?;
        if !is_ssh {
            // Look like a web server with nothing here.
            let _ = tls.write_all(NOT_FOUND).await;
            let _ = tls.shutdown().await;
            bail!("not SSH");
        }
        accept_ssh(Prefixed::new(first, tls), ssh, policy).await
    })
    .await
    .map_err(|_| anyhow!("handshake timed out"))?
}

/// The reply to anything but SSH on a direct listener.
pub const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

/// Read the first bytes the client sends and say whether they start an SSH
/// session (`SSH-`). Returns the bytes read, which must be replayed (see
/// [`Prefixed`]). An SSH client sends its version line at once; a browser
/// sends its request at once.
pub async fn sniff_ssh<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<(bool, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 256];
    while buf.len() < 4 {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if !b"SSH-".starts_with(&buf[..buf.len().min(4)]) {
            return Ok((false, buf));
        }
    }
    Ok((buf.starts_with(b"SSH-"), buf))
}

/// A stream that first yields `prefix` (bytes already read from it).
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Prefixed { prefix, pos: 0, inner }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = &mut *self;
        if me.pos < me.prefix.len() {
            let n = (me.prefix.len() - me.pos).min(buf.remaining());
            buf.put_slice(&me.prefix[me.pos..me.pos + n]);
            me.pos += n;
            if me.pos == me.prefix.len() {
                me.prefix = Vec::new();
                me.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Run SSH on an already accepted stream (the hub accepts TLS itself, to
/// choose between SSH and the web portal).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sniffs_ssh_and_replays() {
        for (input, ssh) in [
            (&b"SSH-2.0-russh\r\n"[..], true),
            (b"GET / HTTP/1.1\r\n", false),
            (b"S", false),
            (b"", false),
        ] {
            let (mut a, mut b) = tokio::io::duplex(1024);
            a.write_all(input).await.unwrap();
            drop(a);
            let (is_ssh, first) = sniff_ssh(&mut b).await.unwrap();
            assert_eq!(is_ssh, ssh, "{input:?}");
            let mut all = Vec::new();
            Prefixed::new(first, b).read_to_end(&mut all).await.unwrap();
            assert_eq!(all, input);
        }
    }

    #[tokio::test]
    async fn sniff_decides_on_a_split_prefix() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let t = tokio::spawn(async move { sniff_ssh(&mut b).await.unwrap() });
        a.write_all(b"SS").await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        a.write_all(b"H-2.0").await.unwrap();
        let (is_ssh, first) = t.await.unwrap();
        assert!(is_ssh);
        assert!(first.starts_with(b"SSH-"));
    }

    /// A server on localhost; `old` makes it behave like one from before
    /// sniffing (only tc-ssh/1, SSH at once). Counts TLS connections.
    async fn server(old: bool, allow: bool) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use russh::keys::{Algorithm, PrivateKey};
        let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let mut cfg = (*crate::tls::server_ephemeral().unwrap().config).clone();
        if old {
            cfg.alpn_protocols = vec![crate::ALPN.to_vec()];
        }
        let tls = TlsAcceptor::from(Arc::new(cfg));
        let ssh = server_ssh_config(host);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n2 = n.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = l.accept().await.unwrap();
                n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (tls, ssh) = (tls.clone(), ssh.clone());
                let policy: KeyPolicy = Arc::new(move |_| allow);
                tokio::spawn(async move {
                    let r = if old {
                        match tls.accept(tcp).await {
                            Ok(t) => accept_ssh(t, ssh, policy).await,
                            Err(e) => Err(e.into()),
                        }
                    } else {
                        accept(tcp, tls, ssh, policy).await
                    };
                    if let Ok(c) = r {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        drop(c);
                    }
                });
            }
        });
        (addr, n)
    }

    async fn try_dial(addr: SocketAddr) -> Result<ClientConn> {
        use russh::keys::{Algorithm, PrivateKey};
        let key = Arc::new(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap());
        let tls = crate::tls::client_config(crate::tls::Verify::Any).unwrap();
        dial(
            addr,
            "127.0.0.1",
            tls,
            key,
            "peer",
            HostKey::Tofu,
            Duration::from_secs(2),
        )
        .await
    }

    #[tokio::test]
    async fn new_server_needs_one_connection() {
        let (addr, n) = server(false, true).await;
        try_dial(addr).await.unwrap();
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn old_server_gets_the_old_alpn() {
        let (addr, n) = server(true, true).await;
        try_dial(addr).await.unwrap();
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn refusal_by_a_new_server_is_not_retried() {
        let (addr, n) = server(false, false).await;
        assert!(try_dial(addr).await.is_err());
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn http_answer_means_an_old_hub() {
        // An old hub's portal: http/1.1, and HTTP back to anything.
        let mut cfg = (*crate::tls::server_ephemeral().unwrap().config).clone();
        cfg.alpn_protocols = vec![crate::tls::ALPN_HTTP.to_vec()];
        let tls = TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n2 = n.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = l.accept().await.unwrap();
                n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let tls = tls.clone();
                tokio::spawn(async move {
                    if let Ok(mut t) = tls.accept(tcp).await {
                        let mut b = [0u8; 64];
                        let _ = t.read(&mut b).await;
                        let _ = t.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                        let _ = t.shutdown().await;
                    }
                });
            }
        });
        assert!(try_dial(addr).await.is_err());
        // The legacy retry happened (and failed: the ALPN is refused).
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
