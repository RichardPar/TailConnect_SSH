//! The opening request that lets a machine in, so that probing a hub or a
//! direct port never reaches SSH.
//!
//! After TLS, a new `tcd` sends what looks like a browser's WebSocket
//! upgrade. Its `Sec-WebSocket-Key` is a proof (16 bytes, base64, the same
//! shape as a real key) that it knows a secret the server knows:
//!
//! * to the hub: the hub's SSH host key id (pinned at the first connection),
//!   or, when joining, the auth key it was given;
//! * to a peer's direct port: that peer's key id, from the network map.
//!
//! The proof is bound to the TLS session (an RFC 5705 exporter), so seeing
//! one, even by sitting in the middle of an unauthenticated TLS connection,
//! doesn't help to open another. A server that accepts it answers
//! `101 Switching Protocols` and runs SSH on the stream. Anything else gets
//! the web portal (hub) or a 404 (direct port), like any web server. With
//! the hub's `--hide-ssh`, a plain `SSH-` opening (older `tcd`) is no longer
//! accepted either.

use sha2::{Digest, Sha256};

/// The TLS exporter label (RFC 5705: labels start with `EXPORTER`).
const LABEL: &[u8] = b"EXPORTER-tailconnect-ssh-open-v1";

/// A secret both ends know; the proof is derived from it.
pub type Secret = [u8; 32];

/// The secret for a server whose SSH key id is `key_id` (the hub's host key,
/// or a peer's machine key).
pub fn secret_for_key(key_id: &str) -> Secret {
    derive(b"key", key_id.trim().as_bytes())
}

/// The secret for joining with an auth key. The hub stores only
/// `auth_key_hash` (hex SHA-256 of the key), so this is derived from that.
pub fn secret_for_auth_key(auth_key: &str) -> Secret {
    secret_for_auth_key_hash(&hex::encode(Sha256::digest(auth_key.trim().as_bytes())))
}

pub fn secret_for_auth_key_hash(auth_key_hash: &str) -> Secret {
    derive(b"authkey", auth_key_hash.as_bytes())
}

fn derive(kind: &[u8], v: &[u8]) -> Secret {
    let mut h = Sha256::new();
    h.update(b"tailconnect-ssh open secret\0");
    h.update(kind);
    h.update([0]);
    h.update(v);
    h.finalize().into()
}

/// The TLS session's exporter value for the proof.
pub fn exporter<D>(conn: &rustls::ConnectionCommon<D>) -> Option<[u8; 32]> {
    conn.export_keying_material([0u8; 32], LABEL, None).ok()
}

/// The proof for `secret` on the TLS session with this exporter value, as
/// it goes in `Sec-WebSocket-Key`.
pub fn proof(secret: &Secret, exporter: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"tailconnect-ssh open proof\0");
    h.update(secret);
    h.update(exporter);
    base64(&h.finalize()[..16])
}

/// The request a client opens with. `host` is the `Host` header (name or
/// address, with the port unless it's 443).
pub fn request(host: &str, key: &str) -> String {
    format!(
        "GET / HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: Upgrade\r\n\
         Pragma: no-cache\r\n\
         Cache-Control: no-cache\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\
         Upgrade: websocket\r\n\
         Origin: https://{host}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Accept-Encoding: gzip, deflate, br, zstd\r\n\
         Accept-Language: en-GB,en;q=0.9\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\
         \r\n"
    )
}

/// The server's answer to an accepted request.
pub fn accepted() -> String {
    let accept: [u8; 20] = rand::random();
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         \r\n",
        base64(&accept)
    )
}

/// The `Sec-WebSocket-Key` of a request head (`GET` with a WebSocket
/// upgrade), if it is one.
pub fn key_of(head: &[u8]) -> Option<&str> {
    let head = std::str::from_utf8(head).ok()?;
    let mut lines = head.split("\r\n");
    if !lines.next()?.starts_with("GET ") {
        return None;
    }
    lines.find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("sec-websocket-key")
            .then(|| value.trim())
    })
}

/// Where an HTTP head ends (just past `\r\n\r\n`), if it has.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(&[0u8; 16]).len(), 24);
    }

    #[test]
    fn request_carries_the_proof() {
        let e = [7u8; 32];
        let k = proof(&secret_for_key("SHA256:abc"), &e);
        let req = request("hub.example:8443", &k);
        let end = head_end(req.as_bytes()).unwrap();
        assert_eq!(end, req.len());
        assert_eq!(key_of(req.as_bytes()), Some(k.as_str()));
        // Another secret or session gives another proof.
        assert_ne!(proof(&secret_for_key("SHA256:abd"), &e), k);
        assert_ne!(proof(&secret_for_key("SHA256:abc"), &[8u8; 32]), k);
        assert_eq!(
            secret_for_auth_key(" tckey-x "),
            secret_for_auth_key_hash(&hex::encode(Sha256::digest(b"tckey-x")))
        );
        assert_eq!(key_of(b"POST / HTTP/1.1\r\nSec-WebSocket-Key: x\r\n\r\n"), None);
        assert_eq!(key_of(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"), None);
    }
}
