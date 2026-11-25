//! End-to-end encryption for traffic relayed through the hub.
//!
//! SSH sessions to the hub end at the hub, so a packet relayed between two
//! machines would otherwise be readable there. Instead, each pair of machines
//! runs a Noise IK handshake (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) through
//! the hub and seals every relayed packet with the resulting keys. The hub
//! sees only the destination address it needs for routing.
//!
//! Keys: each machine's X25519 key is derived from its Ed25519 SSH machine
//! key, so the network map's SSH keys are all a peer needs.
//!
//! Wire format of a sealed message (the payload after the 4-byte peer
//! address that the hub routes on):
//!
//! ```text
//! INIT  [1][sender index u32][Noise msg 1, payload = timestamp u64]
//! RESP  [2][sender index u32][receiver index u32][Noise msg 2]
//! DATA  [3][receiver index u32][counter u64][ChaCha20-Poly1305 ciphertext]
//! ```
//!
//! As in WireGuard:
//! * the initiator's timestamp lets the responder drop replayed handshakes;
//! * a responder sends only after the initiator's first data message proves
//!   the session (the initiator sends an empty keepalive if it has nothing
//!   queued);
//! * sessions are rekeyed after 2 minutes and refused after 3;
//! * a sliding window drops replayed data messages.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use snow::{Builder, HandshakeState, StatelessTransportState};
use tracing::debug;

const PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"tailconnect-ssh e2e v1";

const MSG_INIT: u8 = 1;
const MSG_RESP: u8 = 2;
const MSG_DATA: u8 = 3;

const TAG: usize = 16;
const DATA_HDR: usize = 1 + 4 + 8;

pub const REKEY_AFTER: Duration = Duration::from_secs(120);
pub const REJECT_AFTER: Duration = Duration::from_secs(180);
const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
const RETRY: Duration = Duration::from_secs(2);
const QUEUE_MAX: usize = 64;
const QUEUE_TTL: Duration = Duration::from_secs(5);
const PENDING_TTL: Duration = Duration::from_secs(15);

struct Session {
    local: u32,
    remote: u32,
    transport: StatelessTransportState,
    created: Instant,
    send: AtomicU64,
    replay: Mutex<Replay>,
}

impl Session {
    fn usable(&self, now: Instant) -> bool {
        now.duration_since(self.created) < REJECT_AFTER && self.send.load(Ordering::Relaxed) < REJECT_AFTER_MESSAGES
    }

    fn wants_rekey(&self, now: Instant) -> bool {
        now.duration_since(self.created) >= REKEY_AFTER || self.send.load(Ordering::Relaxed) >= REKEY_AFTER_MESSAGES
    }
}

struct Pending {
    hs: HandshakeState,
    local: u32,
    sent: Instant,
}

struct Peer {
    remote_static: [u8; 32],
    /// Used for sending.
    current: Option<Arc<Session>>,
    /// The session `current` replaced; still accepted for receiving.
    previous: Option<Arc<Session>>,
    /// A session we answered as responder, not yet proven by the initiator.
    next: Option<Arc<Session>>,
    pending: Option<Pending>,
    queue: VecDeque<(Instant, Vec<u8>)>,
    /// Latest handshake timestamp accepted from this peer.
    last_ts: u64,
}

impl Peer {
    fn new(remote_static: [u8; 32]) -> Self {
        Peer {
            remote_static,
            current: None,
            previous: None,
            next: None,
            pending: None,
            queue: VecDeque::new(),
            last_ts: 0,
        }
    }

    fn can_initiate(&self, now: Instant) -> bool {
        self.pending
            .as_ref()
            .is_none_or(|p| now.duration_since(p.sent) >= RETRY)
    }

    fn find(&self, local: u32) -> Option<(Arc<Session>, bool)> {
        if let Some(s) = self.current.as_ref().filter(|s| s.local == local) {
            return Some((s.clone(), false));
        }
        if let Some(s) = self.previous.as_ref().filter(|s| s.local == local) {
            return Some((s.clone(), false));
        }
        self.next
            .as_ref()
            .filter(|s| s.local == local)
            .map(|s| (s.clone(), true))
    }

    fn install(&mut self, s: Arc<Session>) {
        self.previous = self.current.replace(s);
    }
}

/// Result of [`E2e::open`].
#[derive(Default)]
pub struct Opened {
    /// A decrypted IP packet from the peer, ready for the TUN device.
    pub packet: Option<Vec<u8>>,
    /// Sealed messages to send back through the hub.
    pub replies: Vec<Vec<u8>>,
}

pub struct E2e {
    local_private: [u8; 32],
    peers: Mutex<HashMap<Ipv4Addr, Peer>>,
    /// The exit node this machine uses: its packets may come from any
    /// address outside the tunnel (internet replies).
    exit: Mutex<Option<Ipv4Addr>>,
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn builder(local: &[u8; 32]) -> Builder<'_> {
    Builder::new(PARAMS.parse().expect("valid Noise params"))
        .prologue(PROLOGUE)
        .expect("prologue")
        .local_private_key(local)
        .expect("local key")
}

fn header(peer: Ipv4Addr, kind: u8, cap: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + cap);
    v.extend_from_slice(&peer.octets());
    v.push(kind);
    v
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(i..i + 8)?.try_into().ok()?))
}

impl E2e {
    pub fn new(local_private: [u8; 32]) -> Self {
        E2e {
            local_private,
            peers: Mutex::new(HashMap::new()),
            exit: Mutex::new(None),
        }
    }

    /// Replace the set of peers. Sessions survive for peers whose key is
    /// unchanged.
    pub fn sync(&self, peers: &[(Ipv4Addr, [u8; 32])]) {
        let mut map = self.peers.lock().unwrap();
        let mut old = std::mem::take(&mut *map);
        for (ip, key) in peers {
            let p = match old.remove(ip) {
                Some(p) if p.remote_static == *key => p,
                _ => Peer::new(*key),
            };
            map.insert(*ip, p);
        }
    }

    /// The exit node this machine uses, if any.
    pub fn set_exit(&self, ip: Option<Ipv4Addr>) {
        *self.exit.lock().unwrap() = ip;
    }

    /// Whether a session with the peer at `ip` is established.
    pub fn established(&self, ip: Ipv4Addr) -> bool {
        let now = Instant::now();
        self.peers
            .lock()
            .unwrap()
            .get(&ip)
            .and_then(|p| p.current.as_ref())
            .is_some_and(|s| s.usable(now))
    }

    /// Seal an IP packet for `dst`. Returns the messages to send through the
    /// hub: a data message, a handshake, both, or none (packet queued).
    pub fn seal(&self, dst: Ipv4Addr, pkt: Vec<u8>) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut out = Vec::new();
        let session = {
            let mut peers = self.peers.lock().unwrap();
            let Some(p) = peers.get_mut(&dst) else {
                return out;
            };
            match p.current.clone().filter(|s| s.usable(now)) {
                Some(s) => {
                    if s.wants_rekey(now) && p.can_initiate(now) {
                        out.extend(self.initiate(dst, p, now));
                    }
                    s
                }
                None => {
                    if p.queue.len() >= QUEUE_MAX {
                        p.queue.pop_front();
                    }
                    p.queue.push_back((now, pkt));
                    if p.can_initiate(now) {
                        out.extend(self.initiate(dst, p, now));
                    }
                    return out;
                }
            }
        };
        out.extend(encrypt(dst, &session, &pkt));
        out
    }

    fn initiate(&self, dst: Ipv4Addr, p: &mut Peer, now: Instant) -> Option<Vec<u8>> {
        let r = (|| -> Result<Vec<u8>> {
            let mut hs = builder(&self.local_private)
                .remote_public_key(&p.remote_static)?
                .build_initiator()?;
            let local: u32 = rand::random();
            let mut buf = [0u8; 256];
            let n = hs.write_message(&now_nanos().to_be_bytes(), &mut buf)?;
            let mut m = header(dst, MSG_INIT, 4 + n);
            m.extend_from_slice(&local.to_be_bytes());
            m.extend_from_slice(&buf[..n]);
            p.pending = Some(Pending { hs, local, sent: now });
            Ok(m)
        })();
        r.map_err(|e| debug!("e2e handshake to {dst}: {e}")).ok()
    }

    /// Process a sealed message that the hub says came from `src`.
    pub fn open(&self, src: Ipv4Addr, msg: &[u8]) -> Opened {
        let mut out = Opened::default();
        let now = Instant::now();
        let mut peers = self.peers.lock().unwrap();
        let Some(p) = peers.get_mut(&src) else {
            return out;
        };
        let r = match msg.first() {
            Some(&MSG_INIT) => self.on_init(src, p, msg, &mut out),
            Some(&MSG_RESP) => on_resp(src, p, msg, now, &mut out),
            Some(&MSG_DATA) => on_data(src, p, msg, now, &mut out, *self.exit.lock().unwrap() == Some(src)),
            _ => Err(anyhow!("unknown message type")),
        };
        if let Err(e) = r {
            debug!("e2e from {src}: {e}");
        }
        out
    }

    fn on_init(&self, src: Ipv4Addr, p: &mut Peer, msg: &[u8], out: &mut Opened) -> Result<()> {
        let sender = u32_at(msg, 1).ok_or_else(|| anyhow!("short init"))?;
        let mut hs = builder(&self.local_private).build_responder()?;
        let mut payload = [0u8; 64];
        let n = hs.read_message(&msg[5..], &mut payload)?;
        if hs.get_remote_static() != Some(&p.remote_static[..]) {
            return Err(anyhow!("handshake from a key that isn't {src}'s"));
        }
        let ts = u64_at(&payload[..n], 0).ok_or_else(|| anyhow!("init without timestamp"))?;
        if ts <= p.last_ts {
            return Err(anyhow!("replayed handshake"));
        }
        p.last_ts = ts;
        let local: u32 = rand::random();
        let mut buf = [0u8; 128];
        let n = hs.write_message(&[], &mut buf)?;
        let mut m = header(src, MSG_RESP, 8 + n);
        m.extend_from_slice(&local.to_be_bytes());
        m.extend_from_slice(&sender.to_be_bytes());
        m.extend_from_slice(&buf[..n]);
        p.next = Some(Arc::new(Session {
            local,
            remote: sender,
            transport: hs.into_stateless_transport_mode()?,
            created: Instant::now(),
            send: AtomicU64::new(0),
            replay: Mutex::new(Replay::default()),
        }));
        out.replies.push(m);
        Ok(())
    }

    /// Housekeeping, called about once a second: expire old sessions and
    /// queued packets, and retry handshakes. Returns messages to send.
    pub fn tick(&self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut out = Vec::new();
        let mut peers = self.peers.lock().unwrap();
        for (ip, p) in peers.iter_mut() {
            for slot in [&mut p.current, &mut p.previous, &mut p.next] {
                if slot.as_ref().is_some_and(|s| !s.usable(now)) {
                    *slot = None;
                }
            }
            while p.queue.front().is_some_and(|(t, _)| now.duration_since(*t) > QUEUE_TTL) {
                p.queue.pop_front();
            }
            if p.pending
                .as_ref()
                .is_some_and(|x| now.duration_since(x.sent) > PENDING_TTL)
            {
                p.pending = None;
            }
            if !p.queue.is_empty() && p.current.is_none() && p.can_initiate(now) {
                out.extend(self.initiate(*ip, p, now));
            }
        }
        out
    }
}

fn on_resp(src: Ipv4Addr, p: &mut Peer, msg: &[u8], now: Instant, out: &mut Opened) -> Result<()> {
    let sender = u32_at(msg, 1).ok_or_else(|| anyhow!("short response"))?;
    let receiver = u32_at(msg, 5).ok_or_else(|| anyhow!("short response"))?;
    if p.pending.as_ref().is_none_or(|x| x.local != receiver) {
        return Err(anyhow!("response to no handshake of ours"));
    }
    let Pending { mut hs, local, .. } = p.pending.take().unwrap();
    let mut payload = [0u8; 64];
    if let Err(e) = hs.read_message(&msg[9..], &mut payload) {
        return Err(anyhow!("bad response: {e}"));
    }
    let s = Arc::new(Session {
        local,
        remote: sender,
        transport: hs.into_stateless_transport_mode()?,
        created: now,
        send: AtomicU64::new(0),
        replay: Mutex::new(Replay::default()),
    });
    p.install(s.clone());
    debug!("e2e session with {src} established (initiator)");
    flush(src, p, &s, now, out, true);
    Ok(())
}

fn on_data(src: Ipv4Addr, p: &mut Peer, msg: &[u8], now: Instant, out: &mut Opened, exit: bool) -> Result<()> {
    let receiver = u32_at(msg, 1).ok_or_else(|| anyhow!("short data"))?;
    let counter = u64_at(msg, 5).ok_or_else(|| anyhow!("short data"))?;
    let (s, unconfirmed) = p.find(receiver).ok_or_else(|| anyhow!("data for unknown session"))?;
    if !s.usable(now) {
        return Err(anyhow!("data for expired session"));
    }
    let ct = &msg[DATA_HDR..];
    let mut pt = vec![0u8; ct.len().saturating_sub(TAG)];
    let n = s
        .transport
        .read_message(counter, ct, &mut pt)
        .map_err(|e| anyhow!("decrypt: {e}"))?;
    pt.truncate(n);
    if !s.replay.lock().unwrap().accept(counter) {
        return Err(anyhow!("replayed data message {counter}"));
    }
    if unconfirmed {
        // The initiator has proven the session: start using it.
        p.next = None;
        p.install(s.clone());
        debug!("e2e session with {src} established (responder)");
        flush(src, p, &s, now, out, false);
    }
    if pt.is_empty() {
        return Ok(()); // keepalive
    }
    // The sealed packet must really be from that peer (its IPv4 or IPv6
    // address); from our exit node, also from outside the tunnel.
    match crate::packet::ip_addrs(&pt).map(|(s, _)| (s, crate::machine_of(s))) {
        Some((_, Some(m))) if m == src => out.packet = Some(pt),
        Some((_, None)) if exit => out.packet = Some(pt),
        _ => return Err(anyhow!("inner source doesn't match sender {src}")),
    }
    Ok(())
}

/// Send queued packets on a new session; as initiator, send a keepalive if
/// there were none so the responder can start using the session.
fn flush(dst: Ipv4Addr, p: &mut Peer, s: &Session, now: Instant, out: &mut Opened, keepalive: bool) {
    let mut sent = false;
    while let Some((t, pkt)) = p.queue.pop_front() {
        if now.duration_since(t) <= QUEUE_TTL {
            out.replies.extend(encrypt(dst, s, &pkt));
            sent = true;
        }
    }
    if keepalive && !sent {
        out.replies.extend(encrypt(dst, s, &[]));
    }
}

fn encrypt(dst: Ipv4Addr, s: &Session, pkt: &[u8]) -> Option<Vec<u8>> {
    let counter = s.send.fetch_add(1, Ordering::Relaxed);
    if counter >= REJECT_AFTER_MESSAGES {
        return None;
    }
    let mut m = header(dst, MSG_DATA, DATA_HDR + pkt.len() + TAG);
    m.extend_from_slice(&s.remote.to_be_bytes());
    m.extend_from_slice(&counter.to_be_bytes());
    let start = m.len();
    m.resize(start + pkt.len() + TAG, 0);
    match s.transport.write_message(counter, pkt, &mut m[start..]) {
        Ok(n) => {
            m.truncate(start + n);
            Some(m)
        }
        Err(e) => {
            debug!("e2e encrypt: {e}");
            None
        }
    }
}

/// Sliding window over the last 1984 counters (RFC 6479 style ring of words).
#[derive(Default)]
struct Replay {
    highest: Option<u64>,
    bits: [u64; WINDOW_WORDS],
}

const WINDOW_WORDS: usize = 32;
const WINDOW: u64 = (WINDOW_WORDS * 64) as u64;

impl Replay {
    fn bit(&mut self, n: u64) -> (&mut u64, u64) {
        let i = (n / 64) as usize % WINDOW_WORDS;
        (&mut self.bits[i], 1 << (n % 64))
    }

    fn accept(&mut self, n: u64) -> bool {
        match self.highest {
            Some(h) if n <= h => {
                // One word less than the ring, so the word being reused for
                // newer counters is never consulted for old ones.
                if h - n >= WINDOW - 64 {
                    return false;
                }
                let (w, b) = self.bit(n);
                if *w & b != 0 {
                    return false;
                }
                *w |= b;
                true
            }
            h => {
                // Clear the words skipped over by moving the window forward.
                let from = h.map(|h| h / 64 + 1).unwrap_or(0);
                let to = n / 64;
                if to.saturating_sub(from) >= WINDOW_WORDS as u64 || h.is_none() {
                    self.bits = [0; WINDOW_WORDS];
                } else {
                    for word in from..=to {
                        self.bits[word as usize % WINDOW_WORDS] = 0;
                    }
                }
                self.highest = Some(n);
                let (w, b) = self.bit(n);
                *w |= b;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::{Algorithm, PrivateKey};

    struct Node {
        ip: Ipv4Addr,
        e2e: E2e,
        pubkey: [u8; 32],
    }

    fn node(last: u8) -> Node {
        let k = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        Node {
            ip: Ipv4Addr::new(100, 64, 0, last),
            e2e: E2e::new(crate::keys::x25519_private(&k).unwrap()),
            pubkey: crate::keys::x25519_public(k.public_key()).unwrap(),
        }
    }

    fn pair() -> (Node, Node) {
        let (a, b) = (node(1), node(2));
        a.e2e.sync(&[(b.ip, b.pubkey)]);
        b.e2e.sync(&[(a.ip, a.pubkey)]);
        (a, b)
    }

    fn packet(src: Ipv4Addr, dst: Ipv4Addr, body: &[u8]) -> Vec<u8> {
        crate::packet::build_udp(src, dst, 1000, 2000, body)
    }

    /// What the hub does: strip the destination, deliver with the sender's
    /// address. Runs until no more messages are produced, returning the
    /// packets delivered to each side.
    fn relay(a: &Node, b: &Node, mut from_a: Vec<Vec<u8>>, mut from_b: Vec<Vec<u8>>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let (mut got_a, mut got_b) = (vec![], vec![]);
        while !from_a.is_empty() || !from_b.is_empty() {
            for m in std::mem::take(&mut from_a) {
                assert_eq!(&m[..4], &b.ip.octets());
                let o = b.e2e.open(a.ip, &m[4..]);
                got_b.extend(o.packet);
                from_b.extend(o.replies);
            }
            for m in std::mem::take(&mut from_b) {
                assert_eq!(&m[..4], &a.ip.octets());
                let o = a.e2e.open(b.ip, &m[4..]);
                got_a.extend(o.packet);
                from_a.extend(o.replies);
            }
        }
        (got_a, got_b)
    }

    #[test]
    fn handshake_then_both_ways() {
        let (a, b) = pair();
        let p1 = packet(a.ip, b.ip, b"hello bravo");
        let out = a.e2e.seal(b.ip, p1.clone());
        assert_eq!(out.len(), 1, "first packet is queued behind a handshake");
        let (_, got_b) = relay(&a, &b, out, vec![]);
        assert_eq!(got_b, vec![p1], "queued packet delivered after handshake");
        assert!(a.e2e.established(b.ip) && b.e2e.established(a.ip));

        let p2 = packet(b.ip, a.ip, b"hello alpha");
        let out = b.e2e.seal(a.ip, p2.clone());
        assert_eq!(out.len(), 1, "no new handshake needed");
        assert!(
            !out[0].windows(11).any(|w| w == b"hello alpha"),
            "plaintext not visible"
        );
        let (got_a, _) = relay(&a, &b, vec![], out);
        assert_eq!(got_a, vec![p2]);
    }

    #[test]
    fn simultaneous_handshakes_converge() {
        let (a, b) = pair();
        let pa = packet(a.ip, b.ip, b"a");
        let pb = packet(b.ip, a.ip, b"b");
        let (got_a, got_b) = relay(&a, &b, a.e2e.seal(b.ip, pa.clone()), b.e2e.seal(a.ip, pb.clone()));
        assert_eq!((got_a, got_b), (vec![pb.clone()], vec![pa.clone()]));
        for _ in 0..3 {
            let (got_a, got_b) = relay(&a, &b, a.e2e.seal(b.ip, pa.clone()), b.e2e.seal(a.ip, pb.clone()));
            assert_eq!((got_a, got_b), (vec![pb.clone()], vec![pa.clone()]));
        }
    }

    #[test]
    fn replays_and_tampering_are_dropped() {
        let (a, b) = pair();
        relay(&a, &b, a.e2e.seal(b.ip, packet(a.ip, b.ip, b"x")), vec![]);
        let m = a.e2e.seal(b.ip, packet(a.ip, b.ip, b"once")).pop().unwrap();
        assert!(b.e2e.open(a.ip, &m[4..]).packet.is_some());
        assert!(b.e2e.open(a.ip, &m[4..]).packet.is_none(), "replayed data");
        let mut t = a.e2e.seal(b.ip, packet(a.ip, b.ip, b"tamper")).pop().unwrap();
        *t.last_mut().unwrap() ^= 1;
        assert!(b.e2e.open(a.ip, &t[4..]).packet.is_none(), "tampered data");
    }

    #[test]
    fn replayed_handshake_is_dropped() {
        let (a, b) = pair();
        let init = a.e2e.seal(b.ip, packet(a.ip, b.ip, b"x")).pop().unwrap();
        assert_eq!(b.e2e.open(a.ip, &init[4..]).replies.len(), 1);
        assert!(b.e2e.open(a.ip, &init[4..]).replies.is_empty());
    }

    #[test]
    fn wrong_key_or_spoofed_source_is_dropped() {
        let (a, b) = pair();
        let (c, d) = (node(3), node(4));
        c.e2e.sync(&[(b.ip, b.pubkey)]);
        d.e2e.sync(&[(b.ip, b.pubkey)]);
        b.e2e.sync(&[(a.ip, a.pubkey), (c.ip, c.pubkey), (d.ip, d.pubkey)]);
        // c, with a proper session, sealing a packet that claims to be from a.
        relay(&c, &b, c.e2e.seal(b.ip, packet(c.ip, b.ip, b"x")), vec![]);
        assert!(b.e2e.established(c.ip));
        let m = c.e2e.seal(b.ip, packet(a.ip, b.ip, b"spoof")).pop().unwrap();
        assert!(b.e2e.open(c.ip, &m[4..]).packet.is_none());
        // d's handshake, delivered as if it came from a: refused.
        let init = d.e2e.seal(b.ip, packet(d.ip, b.ip, b"x")).pop().unwrap();
        assert!(b.e2e.open(a.ip, &init[4..]).replies.is_empty());
        assert!(!b.e2e.established(a.ip));
    }

    #[test]
    fn exit_node_may_send_internet_sources_only_when_chosen() {
        let (a, b) = pair();
        relay(&a, &b, a.e2e.seal(b.ip, packet(a.ip, b.ip, b"x")), vec![]);
        let web = Ipv4Addr::new(93, 184, 216, 34);
        // From a's IPv6 address: fine.
        let v6 = {
            let mut p = vec![0u8; 40];
            p[0] = 0x60;
            p[8..24].copy_from_slice(&crate::ip6_of(a.ip).octets());
            p[24..40].copy_from_slice(&crate::ip6_of(b.ip).octets());
            p
        };
        let m = a.e2e.seal(b.ip, v6).pop().unwrap();
        assert!(b.e2e.open(a.ip, &m[4..]).packet.is_some());
        // An internet source: only if b uses a as its exit node.
        let m = a.e2e.seal(b.ip, packet(web, b.ip, b"reply")).pop().unwrap();
        assert!(b.e2e.open(a.ip, &m[4..]).packet.is_none());
        b.e2e.set_exit(Some(a.ip));
        let m = a.e2e.seal(b.ip, packet(web, b.ip, b"reply")).pop().unwrap();
        assert!(b.e2e.open(a.ip, &m[4..]).packet.is_some());
        // Even then, never another machine's tunnel address.
        let m = a
            .e2e
            .seal(b.ip, packet(Ipv4Addr::new(100, 64, 0, 9), b.ip, b"spoof"))
            .pop()
            .unwrap();
        assert!(b.e2e.open(a.ip, &m[4..]).packet.is_none());
    }

    #[test]
    fn replay_window() {
        let mut r = Replay::default();
        assert!(r.accept(5));
        assert!(!r.accept(5));
        assert!(r.accept(3));
        assert!(r.accept(5000));
        assert!(!r.accept(3), "fell out of the window");
        assert!(r.accept(4999));
        assert!(!r.accept(4999));
        assert!(r.accept(4000));
        assert!(r.accept(100_000));
        assert!(!r.accept(4000));
    }
}
