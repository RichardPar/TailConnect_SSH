//! tcd inside the Android app (`tcd --bridge PATH`).
//!
//! The app runs tcd as a child process and provides what an app process
//! can't do itself, over a Unix socket at PATH that tcd listens on:
//!
//! * the VPN interface: only the app's VpnService can create one, so tcd
//!   asks for it (addresses, routes, DNS, search domain, MTU) and receives
//!   its file descriptor (SCM_RIGHTS). A new set of routes (an exit node
//!   in use, or not) means a new interface;
//! * the underlying network: its DNS servers and this device's addresses,
//!   which tcd uses to resolve the hub and other names, and as its direct
//!   endpoints.
//!
//! The VPN leaves the app itself out (`addDisallowedApplication`), so
//! tcd's own connections use the real network.
//!
//! Protocol: newline-delimited JSON, as in the Go app it replaces:
//!
//! ```text
//! tcd → app  {"Type":"tun","ID":n,"Addresses":[…],"Routes":[…],"DNS":[…],"Search":[…],"MTU":1400}
//! app → tcd  {"Type":"tun-reply","ID":n,"OK":true}        with the fd attached
//! tcd → app  {"Type":"close"}                              no tunnel now: close the interface
//! app → tcd  {"Type":"network","ID":h,"DNS":[…],"Addresses":["192.168.1.20/24",…]}
//! ```
//!
//! A network message's ID is Android's handle for the underlying network
//! (`Network.getNetworkHandle()`): a new one means the device moved to
//! another network (Wi-Fi to mobile data, say), and tcd reconnects at once
//! rather than waiting for the old connections to time out.
//!
//! ```text
//! ```
//!
//! On Android every app's DNS goes to the VPN's server (100.100.100.100):
//! tcd answers tailnet names itself and forwards the rest to the
//! underlying network's servers (or the exit node's, when one is in use).

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

/// `tcd --bridge PATH --android-dns … --android-addrs …`.
#[derive(Debug, Clone, Default)]
pub struct AndroidOpts {
    pub bridge: PathBuf,
    /// The underlying network's DNS servers, until the app reports them.
    pub dns: Vec<IpAddr>,
    /// This device's addresses on it (with prefix length).
    pub addrs: Vec<(IpAddr, u8)>,
}

pub use super::netchange::{Change, Network};

/// A VPN interface to ask the app for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunSpec {
    pub addresses: Vec<String>,
    pub routes: Vec<String>,
    pub dns: Vec<String>,
    pub search: Vec<String>,
    pub mtu: u16,
}

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(rename_all = "PascalCase")]
struct Message {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(default, skip_serializing_if = "is_zero", rename = "ID")]
    id: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    routes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "DNS")]
    dns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    search: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero16", rename = "MTU")]
    mtu: u16,
    #[serde(default, skip_serializing_if = "is_false", rename = "OK")]
    ok: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    error: String,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}
fn is_zero16(v: &u16) -> bool {
    *v == 0
}
fn is_false(v: &bool) -> bool {
    !*v
}

type Reply = Result<OwnedFd, String>;

/// Called with the network before and after each report from the app.
pub type OnNetwork = Box<dyn Fn(&Network, &Network) + Send>;

pub struct Bridge {
    /// The app's connection, for sending (the reader thread has a clone).
    conn: Mutex<Option<UnixStream>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    next_id: AtomicU64,
    pub network: RwLock<Network>,
    /// Called after the app reports the network: (before, now).
    on_network: Mutex<Option<OnNetwork>>,
}

impl Bridge {
    /// Listen on the bridge socket (only this user may connect).
    pub fn listen(o: &AndroidOpts) -> Result<Arc<Bridge>> {
        let _ = std::fs::remove_file(&o.bridge);
        let ln = UnixListener::bind(&o.bridge).map_err(|e| anyhow!("bridge socket {}: {e}", o.bridge.display()))?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&o.bridge, std::fs::Permissions::from_mode(0o600))?;
        }
        let b = Arc::new(Bridge {
            conn: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            network: RwLock::new(Network {
                id: 0,
                dns: o.dns.clone(),
                addrs: o.addrs.clone(),
            }),
            on_network: Mutex::new(None),
        });
        let b2 = b.clone();
        std::thread::spawn(move || {
            for s in ln.incoming() {
                match s {
                    Ok(s) => {
                        info!("android: the app connected to the bridge");
                        let reader = match s.try_clone() {
                            Ok(r) => r,
                            Err(e) => {
                                warn!("android bridge: {e}");
                                continue;
                            }
                        };
                        *b2.conn.lock().unwrap() = Some(s);
                        let b3 = b2.clone();
                        std::thread::spawn(move || b3.read_loop(reader));
                    }
                    Err(e) => warn!("android bridge: {e}"),
                }
            }
        });
        Ok(b)
    }

    pub fn set_on_network(&self, f: OnNetwork) {
        *self.on_network.lock().unwrap() = Some(f);
    }

    fn send(&self, m: &Message) -> Result<()> {
        let mut line = serde_json::to_vec(m)?;
        line.push(b'\n');
        let mut c = self.conn.lock().unwrap();
        let s = c
            .as_mut()
            .ok_or_else(|| anyhow!("the app isn't connected to the bridge"))?;
        s.write_all(&line)?;
        Ok(())
    }

    /// Ask the app for a VPN interface; its file descriptor.
    pub async fn request_tun(&self, spec: &TunSpec) -> Result<OwnedFd> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let m = Message {
            kind: "tun".into(),
            id,
            addresses: spec.addresses.clone(),
            routes: spec.routes.clone(),
            dns: spec.dns.clone(),
            search: spec.search.clone(),
            mtu: spec.mtu,
            ..Default::default()
        };
        // The app may still be connecting.
        let mut tries = 0;
        while let Err(e) = self.send(&m) {
            tries += 1;
            if tries > 50 {
                self.pending.lock().unwrap().remove(&id);
                return Err(e);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(Ok(fd))) => Ok(fd),
            Ok(Ok(Err(e))) => bail!("the app couldn't create the VPN interface: {e}"),
            _ => {
                self.pending.lock().unwrap().remove(&id);
                bail!("the app didn't answer the VPN interface request")
            }
        }
    }

    /// Tell the app the tunnel is down (close the interface).
    pub fn close_tun(&self) {
        let _ = self.send(&Message {
            kind: "close".into(),
            ..Default::default()
        });
    }

    fn read_loop(&self, s: UnixStream) {
        let mut buf: Vec<u8> = Vec::new();
        let mut fds: Vec<OwnedFd> = Vec::new();
        loop {
            let mut chunk = [0u8; 16384];
            match recv_with_fds(s.as_raw_fd(), &mut chunk, &mut fds) {
                Ok(0) => {
                    info!("android: the app disconnected from the bridge");
                    return;
                }
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => {
                    warn!("android bridge: {e}");
                    return;
                }
            }
            while let Some(i) = buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buf.drain(..=i).collect();
                let m: Message = match serde_json::from_slice(&line) {
                    Ok(m) => m,
                    Err(e) => {
                        debug!("android bridge: bad message: {e}");
                        continue;
                    }
                };
                match m.kind.as_str() {
                    "tun-reply" => {
                        let r = if m.ok {
                            if fds.is_empty() {
                                Err("no file descriptor came with the reply".to_string())
                            } else {
                                Ok(fds.remove(0))
                            }
                        } else {
                            Err(if m.error.is_empty() {
                                "refused".into()
                            } else {
                                m.error.clone()
                            })
                        };
                        if let Some(tx) = self.pending.lock().unwrap().remove(&m.id) {
                            let _ = tx.send(r);
                        }
                    }
                    "network" => {
                        let dns: Vec<IpAddr> = m.dns.iter().filter_map(|d| d.parse().ok()).collect();
                        let addrs: Vec<(IpAddr, u8)> = m.addresses.iter().filter_map(|a| parse_prefix(a)).collect();
                        info!("android: network {}: DNS {dns:?}, addresses {addrs:?}", m.id);
                        let new = Network { id: m.id, dns, addrs };
                        let old = std::mem::replace(&mut *self.network.write().unwrap(), new.clone());
                        if let Some(f) = self.on_network.lock().unwrap().as_ref() {
                            f(&old, &new);
                        }
                    }
                    other => debug!("android bridge: unknown message {other}"),
                }
            }
        }
    }

    /// The underlying network's DNS servers (public ones if it reported none).
    pub fn resolvers(&self) -> Vec<SocketAddr> {
        let mut v: Vec<SocketAddr> = self
            .network
            .read()
            .unwrap()
            .dns
            .iter()
            .map(|ip| SocketAddr::new(*ip, 53))
            .collect();
        if v.is_empty() {
            v = vec!["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()];
        }
        v
    }
}

/// "192.168.1.20/24" → (address, 24).
fn parse_prefix(s: &str) -> Option<(IpAddr, u8)> {
    let (a, l) = s
        .split_once('/')
        .unwrap_or((s, if s.contains(':') { "128" } else { "32" }));
    Some((a.parse().ok()?, l.parse().ok()?))
}

/// recvmsg, collecting any file descriptors that came with the bytes.
fn recv_with_fds(fd: RawFd, buf: &mut [u8], fds: &mut Vec<OwnedFd>) -> io::Result<usize> {
    const MAX_FDS: usize = 4;
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE((MAX_FDS * std::mem::size_of::<RawFd>()) as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // SAFETY: msghdr is plain data; zeroed is a valid empty value.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    // SAFETY: msg points at live buffers of the stated sizes.
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: walking the control messages recvmsg filled in, within msg.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c) as *const RawFd;
                let len = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<RawFd>();
                for i in 0..len {
                    fds.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    Ok(n as usize)
}

/// The VPN interface the app handed over: one packet per read and write.
pub struct FdTun {
    fd: AsyncFd<OwnedFd>,
}

impl FdTun {
    pub fn new(fd: OwnedFd) -> io::Result<FdTun> {
        // SAFETY: fcntl on a file descriptor we own.
        unsafe {
            let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
            if flags < 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: we own the fd and it stays registered only while this
        // FdTun (which owns it) lives.
        let fd = unsafe { AsyncFd::register(fd) }.map_err(|e| io::Error::other(e.to_string()))?;
        Ok(FdTun { fd })
    }
}

impl AsyncRead for FdTun {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            // SAFETY: reading into the initialised, unfilled part of buf.
            let r = guard.try_io(|f| {
                let n = unsafe {
                    libc::read(
                        f.as_raw_fd(),
                        unfilled.as_mut_ptr() as *mut libc::c_void,
                        unfilled.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match r {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for FdTun {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;
            // SAFETY: writing from a live slice.
            let r = guard.try_io(|f| {
                let n = unsafe { libc::write(f.as_raw_fd(), data.as_ptr() as *const libc::c_void, data.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match r {
                Ok(r) => return Poll::Ready(r),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ---- DNS over the underlying network ----

/// A DNS query for `name`, of `qtype` (1 = A, 28 = AAAA).
fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // recursion desired, 1 question
    for label in name.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

/// Skip a (possibly compressed) name at `i`; the offset after it.
fn skip_name(m: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let l = *m.get(i)? as usize;
        if l == 0 {
            return Some(i + 1);
        }
        if l & 0xc0 == 0xc0 {
            return Some(i + 2);
        }
        i += 1 + l;
    }
}

/// The A and AAAA addresses in a DNS answer.
fn answer_addrs(m: &[u8]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    if m.len() < 12 {
        return out;
    }
    let qd = u16::from_be_bytes([m[4], m[5]]) as usize;
    let an = u16::from_be_bytes([m[6], m[7]]) as usize;
    let mut i = 12;
    for _ in 0..qd {
        let Some(j) = skip_name(m, i) else { return out };
        i = j + 4;
    }
    for _ in 0..an {
        let Some(j) = skip_name(m, i) else { return out };
        if j + 10 > m.len() {
            return out;
        }
        let t = u16::from_be_bytes([m[j], m[j + 1]]);
        let len = u16::from_be_bytes([m[j + 8], m[j + 9]]) as usize;
        let d = j + 10;
        if d + len > m.len() {
            return out;
        }
        match (t, len) {
            (1, 4) => out.push(IpAddr::V4(Ipv4Addr::new(m[d], m[d + 1], m[d + 2], m[d + 3]))),
            (28, 16) => {
                let b: [u8; 16] = m[d..d + 16].try_into().unwrap();
                out.push(IpAddr::V6(b.into()));
            }
            _ => {}
        }
        i = d + len;
    }
    out
}

/// Ask `servers` in turn; the first answer to `q` (matched by its ID).
pub async fn exchange(servers: &[SocketAddr], q: &[u8]) -> Option<Vec<u8>> {
    for s in servers {
        let local: SocketAddr = if s.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let Ok(sock) = tokio::net::UdpSocket::bind(local).await else {
            continue;
        };
        if sock.send_to(q, s).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; 4096];
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while let Ok(Ok((n, from))) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
            if from == *s && n >= 2 && buf[..2] == q[..2] {
                return Some(buf[..n].to_vec());
            }
        }
    }
    None
}

/// Resolve the hub's host name through `servers` (an address is used as is).
pub async fn resolve(host: &str, port: u16, servers: &[SocketAddr]) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let mut out = Vec::new();
    for qtype in [1u16, 28] {
        let q = query(rand::random(), host, qtype);
        if let Some(a) = exchange(servers, &q).await {
            out.extend(answer_addrs(&a).into_iter().map(|ip| SocketAddr::new(ip, port)));
        }
    }
    if out.is_empty() {
        bail!("can't resolve {host} (DNS servers {servers:?})");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_answers() {
        // A hand-made answer: question tailconnect.duckdns.org A, one CNAME
        // (compressed name) and one A record.
        let mut m = query(0x1234, "tailconnect.duckdns.org", 1);
        m[2] = 0x81;
        m[3] = 0x80;
        m[7] = 2; // two answers
        // CNAME: name pointer to the question (offset 12), type 5.
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12]);
        // A: 90.192.119.100
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 90, 192, 119, 100]);
        assert_eq!(answer_addrs(&m), vec!["90.192.119.100".parse::<IpAddr>().unwrap()]);
        assert_eq!(
            parse_prefix("192.168.1.20/24"),
            Some(("192.168.1.20".parse().unwrap(), 24))
        );
        assert_eq!(parse_prefix("fe80::1"), Some(("fe80::1".parse().unwrap(), 128)));
    }

    #[test]
    fn bridge_messages() {
        let m: Message =
            serde_json::from_str(r#"{"Type":"network","DNS":["192.168.10.254"],"Addresses":["192.168.10.50/24"]}"#)
                .unwrap();
        assert_eq!(m.kind, "network");
        assert_eq!(m.dns, vec!["192.168.10.254"]);
        let t = Message {
            kind: "tun".into(),
            id: 3,
            routes: vec!["100.64.0.0/10".into()],
            mtu: 1400,
            ..Default::default()
        };
        let s = serde_json::to_string(&t).unwrap();
        assert!(
            s.contains(r#""Type":"tun""#) && s.contains(r#""ID":3"#) && s.contains(r#""MTU":1400"#),
            "{s}"
        );
        assert!(!s.contains("Addresses"), "{s}");
    }
}
