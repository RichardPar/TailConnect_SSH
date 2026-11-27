//! SSH-inside-TLS connections.
//!
//! Dialling: TCP → TLS (ALPN `h2, http/1.1`, like a browser) → the opening
//! request that proves the client may connect ([`crate::knock`]) → SSH,
//! public-key auth with the machine key → one session channel used as a byte
//! stream for frames. Older servers are met halfway: one that answers the
//! opening request as a web server gets SSH straight after TLS, and one from
//! before SSH sniffing (it turns the browser ALPN down) gets `tc-ssh/1`.
//!
//! Accepting: the reverse, with the SSH public key the client proved it holds
//! handed to the caller as its identity. Servers send nothing until the
//! client has: its first bytes (the opening request, `SSH-` from an older
//! client, or anything else) say which it is.

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

/// Average seconds between SSH keepalives. The dialling side sends them at
/// random intervals around this (0.6–1.4 times it), so an idle link has no
/// regular beat for traffic analysis to pick out, and treats a connection
/// whose keepalive goes unanswered for two intervals as dead: with 5 s
/// that's noticed in about 15 s, so a failed link (the Wi-Fi gone, a dead
/// uplink) moves to another path quickly. The Android app sets 10 s (fewer
/// wake-ups of a phone's radio; Android tells it about network changes
/// anyway).
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
    pub handle: Arc<client::Handle<ClientHandler>>,
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

/// The client sends its own keepalives (see [`keep_alive`]).
fn client_ssh_config() -> Arc<client::Config> {
    Arc::new(client::Config {
        preferred: preferred(),
        inactivity_timeout: None,
        keepalive_interval: None,
        nodelay: true,
        window_size: 8 << 20,
        ..Default::default()
    })
}

/// A server's own keepalive starts only after three intervals without hearing
/// from the client, so it stays quiet while the client sends its randomly
/// timed ones (an older client sends one every interval); two unanswered
/// ones close the connection.
pub fn server_ssh_config(host_key: PrivateKey) -> Arc<server::Config> {
    Arc::new(server::Config {
        preferred: preferred(),
        inactivity_timeout: Some(keepalive() * 8),
        keepalive_interval: Some(keepalive() * 3),
        keepalive_max: 2,
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
/// no name at all). `open` is the secret for the opening request (see
/// [`crate::knock`]); `None` goes straight to SSH, as older clients did.
#[allow(clippy::too_many_arguments)]
pub async fn dial(
    addr: SocketAddr,
    sni: &str,
    tls: crate::tls::ClientTls,
    key: Arc<PrivateKey>,
    user: &str,
    host_key: HostKey,
    connect_timeout: Duration,
    open: Option<crate::knock::Open>,
) -> Result<ClientConn> {
    // The Host header a browser would send.
    let host = match (sni.parse::<std::net::IpAddr>().is_ok(), addr.port()) {
        (true, 443) if addr.is_ipv4() => addr.ip().to_string(),
        (true, 443) => format!("[{}]", addr.ip()),
        (true, _) => addr.to_string(),
        (false, 443) => sni.to_string(),
        (false, port) => format!("{sni}:{port}"),
    };
    let attempt = |config: Arc<rustls::ClientConfig>, open: Option<crate::knock::Open>| {
        let (key, host_key, host) = (key.clone(), host_key.clone(), host.clone());
        async move {
            let tcp = tokio::time::timeout(connect_timeout, connect(addr))
                .await
                .map_err(|_| Failed::other(anyhow!("connect to {addr} timed out")))?
                .with_context(|| format!("connect to {addr}"))
                .map_err(Failed::other)?;
            tcp.set_nodelay(true).ok();
            tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                handshake_client(tcp, sni, &host, config, key, user, host_key, open),
            )
            .await
            .map_err(|_| Failed::other(anyhow!("handshake with {addr} timed out")))
            .and_then(|r| r)
        }
    };
    // Each step down is taken only when the server clearly is an older one:
    // retrying on any failure would put plain SSH, or tc-ssh/1, on the wire
    // whenever a peer is merely down or refuses us.
    let mut r = attempt(tls.modern.clone(), open).await;
    let mut refused = false;
    if open.is_some()
        && let Err(Failed {
            older: Older::NoOpening,
            error,
        }) = &r
    {
        tracing::debug!("{addr}: {error:#}; an older server, or one that doesn't know us: trying SSH at once");
        refused = true;
        r = attempt(tls.modern.clone(), None).await;
    }
    let r = match r {
        Ok(c) => Ok(c),
        Err(Failed {
            older: Older::NoSniffing,
            error,
        }) => {
            tracing::debug!("{addr}: {error:#}; an older server, trying the old ALPN");
            attempt(tls.legacy, None).await.map_err(|f| f.error)
        }
        Err(f) => Err(f.error),
    };
    // A server that hides SSH and doesn't know us fails every step; say so
    // rather than how the last one failed.
    r.map_err(|e| {
        if refused {
            e.context(format!(
                "{addr} answered as a plain web server: it doesn't know this machine's key or \
                 auth key, or it isn't a TailConnect-SSH server"
            ))
        } else {
            e
        }
    })
}

/// What a failed dial says about the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Older {
    /// Nothing: it's down, refused us, or failed some other way.
    No,
    /// It answered the opening request as a web server: from before it, or
    /// it doesn't accept our proof.
    NoOpening,
    /// It refused the browser ALPN (an older peer) or answered SSH with HTTP
    /// (an older hub's portal): from before SSH sniffing.
    NoSniffing,
}

struct Failed {
    older: Older,
    error: anyhow::Error,
}

impl Failed {
    fn other(error: anyhow::Error) -> Self {
        Failed {
            older: Older::No,
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

/// Send the opening request on `tls` and read the answer. Returns the bytes
/// read after the answer's head (the start of SSH).
async fn open_client<S: AsyncRead + AsyncWrite + Unpin>(
    tls: &mut S,
    host: &str,
    proof: &str,
    hint: Option<u32>,
) -> Result<Vec<u8>, Failed> {
    let io = |e: std::io::Error| Failed::other(anyhow!(e).context("opening request"));
    tls.write_all(crate::knock::request(host, proof, hint).as_bytes())
        .await
        .map_err(io)?;
    tls.flush().await.map_err(io)?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let end = loop {
        if let Some(end) = crate::knock::head_end(&buf) {
            break end;
        }
        if buf.len() > 16 * 1024 {
            return Err(Failed {
                older: Older::NoOpening,
                error: anyhow!("the server answered the opening request with a long page"),
            });
        }
        let n = tls.read(&mut tmp).await.map_err(io)?;
        if n == 0 {
            return Err(Failed::other(anyhow!(
                "the server closed the connection on the opening request"
            )));
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let status = buf.split(|&b| b == b'\n').next().unwrap_or_default();
    if status.starts_with(b"HTTP/1.1 101 ") {
        return Ok(buf[end..].to_vec());
    }
    let status = String::from_utf8_lossy(status).trim().to_string();
    Err(Failed {
        older: if status.starts_with("HTTP/") {
            Older::NoOpening
        } else {
            Older::No
        },
        error: anyhow!("the server answered the opening request with {status:?}"),
    })
}

#[allow(clippy::too_many_arguments)]
async fn handshake_client(
    tcp: TcpStream,
    sni: &str,
    host: &str,
    tls: Arc<rustls::ClientConfig>,
    key: Arc<PrivateKey>,
    user: &str,
    host_key: HostKey,
    open: Option<crate::knock::Open>,
) -> Result<ClientConn, Failed> {
    let name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .context("bad TLS server name")
        .map_err(Failed::other)?;
    let mut tls = TlsConnector::from(tls).connect(name, tcp).await.map_err(|e| Failed {
        older: if refused_alpn(&e) { Older::NoSniffing } else { Older::No },
        error: anyhow!(e).context("TLS handshake"),
    })?;
    let rest = match open {
        Some(o) => {
            let exporter =
                crate::knock::exporter(tls.get_ref().1).ok_or_else(|| Failed::other(anyhow!("no TLS exporter")))?;
            open_client(&mut tls, host, &crate::knock::proof(&o.secret, &exporter), o.hint).await?
        }
        None => Vec::new(),
    };
    let first = Arc::new(Mutex::new(Vec::new()));
    let tls = FirstBytes {
        inner: Prefixed::new(rest, tls),
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
                older: if open.is_none() && first.lock().unwrap().starts_with(b"HTTP/") {
                    Older::NoSniffing
                } else {
                    Older::No
                },
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
        let handle = Arc::new(handle);
        tokio::spawn(keep_alive(Arc::downgrade(&handle)));
        Ok(ClientConn {
            handle,
            stream: channel.into_stream(),
            host_key,
        })
    }
    .await;
    r.map_err(Failed::other)
}

/// Send keepalives at random intervals (see [`KEEPALIVE_SECS`]) while the
/// connection's handle lives, and close the connection when one goes
/// unanswered for two intervals.
async fn keep_alive(handle: std::sync::Weak<client::Handle<ClientHandler>>) {
    loop {
        let base = keepalive().as_secs_f64();
        let wait = base * (0.6 + 0.8 * rand::random::<f64>());
        tokio::time::sleep(Duration::from_secs_f64(wait)).await;
        let Some(h) = handle.upgrade() else { return };
        if h.is_closed() {
            return;
        }
        match tokio::time::timeout(keepalive() * 2, h.send_ping()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return,
            Err(_) => {
                tracing::debug!("keepalive unanswered; closing the connection");
                let _ = h
                    .disconnect(russh::Disconnect::ByApplication, "keepalive timeout", "en")
                    .await;
                return;
            }
        }
    }
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

/// How a direct listener lets clients in.
#[derive(Clone)]
pub struct Admit {
    /// The secrets an opening request may prove (see [`crate::knock`]).
    pub secrets: Vec<crate::knock::Secret>,
    /// Refuse plain SSH (older clients), as the hub says (`--hide-ssh`).
    pub hide_ssh: bool,
}

/// Accept TLS then SSH on `tcp`, and wait for the client's session channel.
/// Anything but an accepted opening request (or, unless `hide_ssh`, plain
/// SSH) gets a 404, like a web server with nothing there.
pub async fn accept(
    tcp: TcpStream,
    tls: TlsAcceptor,
    ssh: Arc<server::Config>,
    policy: KeyPolicy,
    admit: impl FnOnce() -> Admit,
) -> Result<ServerConn> {
    tcp.set_nodelay(true).ok();
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
        let mut tls = tls.accept(tcp).await.context("TLS handshake")?;
        let exporter = crate::knock::exporter(tls.get_ref().1);
        let admit = admit();
        let first = read_first(&mut tls, |k, _| {
            exporter.is_some_and(|e| admit.secrets.iter().any(|s| crate::knock::proof(s, &e) == k))
        })
        .await?;
        let rest = match first {
            First::Open(rest) => {
                tls.write_all(crate::knock::accepted().as_bytes()).await?;
                tls.flush().await?;
                rest
            }
            First::Ssh(b) if !admit.hide_ssh => b,
            First::Ssh(_) | First::Other(_) => {
                let _ = tls.write_all(NOT_FOUND).await;
                let _ = tls.shutdown().await;
                bail!("not an accepted opening");
            }
        };
        accept_ssh(Prefixed::new(rest, tls), ssh, policy).await
    })
    .await
    .map_err(|_| anyhow!("handshake timed out"))?
}

/// The reply to anything else on a direct listener.
pub const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

/// What a client sent first, after TLS.
#[derive(Debug, PartialEq, Eq)]
pub enum First {
    /// An opening request whose proof was accepted; the bytes after it.
    Open(Vec<u8>),
    /// `SSH-` straight away (an older client); the bytes read, to replay.
    Ssh(Vec<u8>),
    /// Anything else (a browser, a probe); the bytes read, to replay.
    Other(Vec<u8>),
}

/// Read what the client sends first and sort it (see [`First`]). `accept`
/// checks an opening request's `Sec-WebSocket-Key` (with its whole head). Every client sends at
/// once: an SSH client its version line, a browser or `tcd` a request.
pub async fn read_first<S: AsyncRead + Unpin>(
    s: &mut S,
    accept: impl FnOnce(&str, &[u8]) -> bool,
) -> std::io::Result<First> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Ok(First::Other(buf));
        }
        buf.extend_from_slice(&tmp[..n]);
        let k = buf.len().min(4);
        let (ssh, get) = (b"SSH-".starts_with(&buf[..k]), b"GET ".starts_with(&buf[..k]));
        if k < 4 && (ssh || get) {
            continue;
        }
        if ssh {
            return Ok(First::Ssh(buf));
        }
        if !get {
            return Ok(First::Other(buf));
        }
        if let Some(end) = crate::knock::head_end(&buf) {
            let head = &buf[..end];
            let ok = crate::knock::key_of(head).is_some_and(|k| accept(k, head));
            return Ok(if ok {
                First::Open(buf[end..].to_vec())
            } else {
                First::Other(buf)
            });
        }
        if buf.len() > 16 * 1024 {
            return Ok(First::Other(buf));
        }
    }
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
    use crate::knock;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    #[tokio::test]
    async fn sorts_the_first_bytes_and_replays() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let open = format!("GET / HTTP/1.1\r\nHost: a\r\nSec-WebSocket-Key: {key}\r\n\r\nSSH-2.0-x\r\n");
        let wrong = "GET / HTTP/1.1\r\nSec-WebSocket-Key: AAAA\r\n\r\n";
        for (input, want) in [
            (&b"SSH-2.0-russh\r\n"[..], First::Ssh(b"SSH-2.0-russh\r\n".to_vec())),
            (
                b"GET / HTTP/1.1\r\n\r\n",
                First::Other(b"GET / HTTP/1.1\r\n\r\n".to_vec()),
            ),
            (wrong.as_bytes(), First::Other(wrong.as_bytes().to_vec())),
            (open.as_bytes(), First::Open(b"SSH-2.0-x\r\n".to_vec())),
            (b"S", First::Other(b"S".to_vec())),
            (b"POST /", First::Other(b"POST /".to_vec())),
            (b"", First::Other(Vec::new())),
        ] {
            let (mut a, mut b) = tokio::io::duplex(4096);
            a.write_all(input).await.unwrap();
            drop(a);
            let got = read_first(&mut b, |k, _| k == key).await.unwrap();
            assert_eq!(got, want, "{:?}", String::from_utf8_lossy(input));
            if let First::Other(first) = got {
                let mut all = Vec::new();
                Prefixed::new(first, b).read_to_end(&mut all).await.unwrap();
                assert_eq!(all, input);
            }
        }
    }

    #[tokio::test]
    async fn waits_for_a_split_opening() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let t = tokio::spawn(async move { read_first(&mut b, |k, _| k == "k").await.unwrap() });
        for part in [&b"G"[..], b"ET / HTTP/1.1\r\nSec-WebSocket-Key: k\r\n", b"\r\n"] {
            a.write_all(part).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(t.await.unwrap(), First::Open(Vec::new()));
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        /// From before SSH sniffing: only tc-ssh/1, SSH at once.
        Old,
        /// Takes the opening request, and plain SSH.
        New,
        /// Takes only the opening request (`--hide-ssh`).
        Hidden,
    }

    /// A server on localhost. Counts TLS connections; returns the secret
    /// that opens it.
    async fn server(mode: Mode, allow: bool) -> (SocketAddr, Arc<AtomicUsize>, knock::Secret) {
        use russh::keys::{Algorithm, PrivateKey};
        let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let secret = knock::secret_for_key(&key_id(host.public_key()));
        let mut cfg = (*crate::tls::server_ephemeral().unwrap().config).clone();
        if mode == Mode::Old {
            cfg.alpn_protocols = vec![crate::ALPN.to_vec()];
        }
        let tls = TlsAcceptor::from(Arc::new(cfg));
        let ssh = server_ssh_config(host);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = l.accept().await.unwrap();
                n2.fetch_add(1, SeqCst);
                let (tls, ssh) = (tls.clone(), ssh.clone());
                let policy: KeyPolicy = Arc::new(move |_| allow);
                tokio::spawn(async move {
                    let r = if mode == Mode::Old {
                        match tls.accept(tcp).await {
                            Ok(t) => accept_ssh(t, ssh, policy).await,
                            Err(e) => Err(e.into()),
                        }
                    } else {
                        let admit = Admit {
                            secrets: vec![secret],
                            hide_ssh: mode == Mode::Hidden,
                        };
                        accept(tcp, tls, ssh, policy, move || admit).await
                    };
                    if let Ok(c) = r {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        drop(c);
                    }
                });
            }
        });
        (addr, n, secret)
    }

    async fn try_dial(addr: SocketAddr, open: Option<knock::Secret>) -> Result<ClientConn> {
        let open = open.map(knock::Open::with);
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
            open,
        )
        .await
    }

    #[tokio::test]
    async fn new_server_needs_one_connection() {
        let (addr, n, secret) = server(Mode::New, true).await;
        try_dial(addr, Some(secret)).await.unwrap();
        assert_eq!(n.load(SeqCst), 1);
        // Without a secret: plain SSH, still accepted.
        try_dial(addr, None).await.unwrap();
        assert_eq!(n.load(SeqCst), 2);
    }

    #[tokio::test]
    async fn a_wrong_proof_falls_back_to_plain_ssh() {
        // As with a server from before the opening request (it 404s it).
        let (addr, n, _) = server(Mode::New, true).await;
        try_dial(addr, Some([9; 32])).await.unwrap();
        assert_eq!(n.load(SeqCst), 2);
    }

    #[tokio::test]
    async fn a_hidden_server_takes_only_the_proof() {
        let (addr, n, secret) = server(Mode::Hidden, true).await;
        assert!(try_dial(addr, None).await.is_err());
        assert!(try_dial(addr, Some([9; 32])).await.is_err());
        let tried = n.load(SeqCst);
        try_dial(addr, Some(secret)).await.unwrap();
        assert_eq!(n.load(SeqCst), tried + 1);
    }

    #[tokio::test]
    async fn old_server_gets_the_old_alpn() {
        let (addr, n, secret) = server(Mode::Old, true).await;
        try_dial(addr, Some(secret)).await.unwrap();
        assert_eq!(n.load(SeqCst), 2);
    }

    #[tokio::test]
    async fn refusal_by_a_new_server_is_not_retried() {
        let (addr, n, secret) = server(Mode::New, false).await;
        assert!(try_dial(addr, Some(secret)).await.is_err());
        assert_eq!(n.load(SeqCst), 1);
    }

    #[tokio::test]
    async fn a_silent_link_is_closed_by_the_keepalive() {
        // A proxy that forwards, then goes silent without closing anything:
        // TCP still acknowledges, so only an unanswered keepalive tells.
        let (server_addr, _, secret) = server(Mode::New, true).await;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let frozen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f2 = frozen.clone();
        tokio::spawn(async move {
            let (a, _) = l.accept().await.unwrap();
            let b = TcpStream::connect(server_addr).await.unwrap();
            let (ar, aw) = a.into_split();
            let (br, bw) = b.into_split();
            for (mut r, mut w) in [(ar, bw), (br, aw)] {
                let f = f2.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = r.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if !f.load(SeqCst) {
                            let _ = w.write_all(&buf[..n]).await;
                        }
                    }
                    // Keep the sockets open.
                    std::future::pending::<()>().await;
                    drop(w);
                });
            }
        });
        let mut conn = try_dial(addr, Some(secret)).await.unwrap();
        frozen.store(true, SeqCst);
        let t = std::time::Instant::now();
        let mut b = [0u8; 16];
        let r = tokio::time::timeout(Duration::from_secs(30), conn.stream.read(&mut b)).await;
        assert!(matches!(r, Ok(Ok(0)) | Ok(Err(_))), "{r:?}");
        // Up to 1.4 intervals to the next keepalive, then 2 for its answer.
        assert!(
            t.elapsed() < keepalive().mul_f64(3.4) + Duration::from_secs(1),
            "{:?}",
            t.elapsed()
        );
    }

    #[tokio::test]
    async fn http_answer_means_an_old_hub() {
        // An old hub's portal: http/1.1, and HTTP back to anything.
        let mut cfg = (*crate::tls::server_ephemeral().unwrap().config).clone();
        cfg.alpn_protocols = vec![crate::tls::ALPN_HTTP.to_vec()];
        let tls = TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = l.accept().await.unwrap();
                n2.fetch_add(1, SeqCst);
                let tls = tls.clone();
                tokio::spawn(async move {
                    if let Ok(mut t) = tls.accept(tcp).await {
                        let mut b = [0u8; 2048];
                        let _ = t.read(&mut b).await;
                        let _ = t.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                        let _ = t.shutdown().await;
                    }
                });
            }
        });
        assert!(try_dial(addr, Some([1; 32])).await.is_err());
        // The opening request, plain SSH, then the legacy ALPN (refused).
        assert_eq!(n.load(SeqCst), 3);
    }
}
