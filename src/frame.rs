//! Framing used inside the SSH channel.
//!
//! Every connection carries one SSH session channel. On it, both sides send
//! frames of `[kind: u8][len: u32 big-endian][payload]`. Kind `CONTROL` is a
//! JSON message (see [`crate::proto`]); kind `PACKET` is one raw IP packet
//! (only on direct peer links); kind `SEALED` is an end-to-end encrypted
//! message relayed by the hub (see [`crate::e2e`]), prefixed with a 4-byte
//! IPv4 address: the destination from client to hub, the sender from hub to
//! client. Kind `PAD` is filler that readers skip (see [`writer_task`]).

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

pub const CONTROL: u8 = 0;
pub const PACKET: u8 = 1;
pub const SEALED: u8 = 2;
/// Filler: carries nothing and is skipped by every reader (older versions
/// skip unknown kinds too).
pub const PAD: u8 = 3;

/// Largest frame accepted. Control frames can hold a large network map;
/// packet frames are limited separately to `MAX_PACKET`.
pub const MAX_FRAME: usize = 8 << 20;
pub const MAX_PACKET: usize = 65535;

#[derive(Debug, Clone)]
pub struct Frame {
    pub kind: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn packet(p: Vec<u8>) -> Self {
        Frame {
            kind: PACKET,
            payload: p,
        }
    }

    pub fn control<T: serde::Serialize>(msg: &T) -> Self {
        Frame {
            kind: CONTROL,
            payload: serde_json::to_vec(msg).expect("control message serialises"),
        }
    }
}

/// Read one frame. Returns `Ok(None)` on a clean end of stream.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Frame>> {
    let mut hdr = [0u8; 5];
    match r.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let kind = hdr[0];
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    let limit = match kind {
        PACKET => MAX_PACKET,
        SEALED => MAX_PACKET + 64,
        _ => MAX_FRAME,
    };
    if len > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds limit {limit}"),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(Some(Frame { kind, payload }))
}

async fn put_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> io::Result<()> {
    let mut hdr = [0u8; 5];
    hdr[0] = f.kind;
    hdr[1..].copy_from_slice(&(f.payload.len() as u32).to_be_bytes());
    w.write_all(&hdr).await?;
    w.write_all(&f.payload).await
}

/// Write one frame and flush.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> io::Result<()> {
    put_frame(w, f).await?;
    w.flush().await
}

/// Drain `rx` into `w`, batching whatever is queued before each flush.
/// Returns when `rx` closes or a write fails.
///
/// Each flush is padded with a `PAD` frame to one of a few sizes (see
/// [`padded_len`]), so someone watching the TLS records can't read the size
/// of each packet in the tunnel (a ping, a TCP ACK, a DNS query). The pad
/// goes last, so the first frame on a connection (the hub's `Hello`) is
/// still first.
pub async fn writer_task<W: AsyncWrite + Unpin>(w: W, mut rx: mpsc::Receiver<Frame>) -> io::Result<()> {
    let mut w = BufWriter::with_capacity(256 * 1024, w);
    while let Some(f) = rx.recv().await {
        let mut size = 5 + f.payload.len();
        put_frame(&mut w, &f).await?;
        let mut n = 0;
        while n < 256 {
            match rx.try_recv() {
                Ok(f) => {
                    size += 5 + f.payload.len();
                    put_frame(&mut w, &f).await?;
                }
                Err(_) => break,
            }
            n += 1;
        }
        put_pad(&mut w, size).await?;
        w.flush().await?;
    }
    let _ = w.shutdown().await;
    Ok(())
}

/// The size a flush of `n` bytes is padded to: 256, 512 or 1024 bytes, then
/// the next multiple of 512 up to 16 KiB, then the next multiple of 4 KiB.
/// A pad frame needs at least its 5-byte header, so the result is either `n`
/// or at least `n + 5`.
pub fn padded_len(n: usize) -> usize {
    let bucket = |n: usize| match n {
        0..=256 => 256,
        257..=512 => 512,
        513..=1024 => 1024,
        1025..=16384 => n.div_ceil(512) * 512,
        _ => n.div_ceil(4096) * 4096,
    };
    let b = bucket(n);
    if b == n || b >= n + 5 { b } else { bucket(n + 5) }
}

const ZEROS: [u8; 8192] = [0; 8192];

async fn put_pad<W: AsyncWrite + Unpin>(w: &mut W, n: usize) -> io::Result<()> {
    let total = padded_len(n);
    if total == n {
        return Ok(());
    }
    let len = total - n - 5;
    let mut hdr = [PAD, 0, 0, 0, 0];
    hdr[1..].copy_from_slice(&(len as u32).to_be_bytes());
    w.write_all(&hdr).await?;
    w.write_all(&ZEROS[..len]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let (a, mut b) = tokio::io::duplex(1 << 16);
        let (tx, rx) = mpsc::channel(8);
        let w = tokio::spawn(writer_task(a, rx));
        tx.send(Frame::packet(vec![1, 2, 3])).await.unwrap();
        tx.send(Frame::control(&serde_json::json!({"type": "x"})))
            .await
            .unwrap();
        drop(tx);
        let mut got = Vec::new();
        while let Some(f) = read_frame(&mut b).await.unwrap() {
            if f.kind != PAD {
                got.push(f);
            }
        }
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].kind, &got[0].payload), (PACKET, &vec![1, 2, 3]));
        assert_eq!(got[1].kind, CONTROL);
        w.await.unwrap().unwrap();
    }

    #[test]
    fn pad_sizes() {
        for n in 1..70_000 {
            let p = padded_len(n);
            assert!(p == n || p >= n + 5, "{n} -> {p}");
            assert!(p - n <= 4096 + 5, "{n} -> {p}");
        }
        assert_eq!(padded_len(60), 256);
        assert_eq!(padded_len(253), 512);
        assert_eq!(padded_len(433), 512);
        assert_eq!(padded_len(1405), 1536);
        assert_eq!(padded_len(1536), 1536);
        assert_eq!(padded_len(20_000), 20_480);
    }

    #[tokio::test]
    async fn flushes_are_padded() {
        let (a, mut b) = tokio::io::duplex(1 << 20);
        let (tx, rx) = mpsc::channel(8);
        let w = tokio::spawn(writer_task(a, rx));
        for len in [40usize, 400, 1400, 3000] {
            tx.send(Frame::packet(vec![7; len])).await.unwrap();
            // Read one flush: the packet, then a pad up to the bucket.
            let f = read_frame(&mut b).await.unwrap().unwrap();
            assert_eq!((f.kind, f.payload.len()), (PACKET, len));
            let pad = read_frame(&mut b).await.unwrap().unwrap();
            assert_eq!(pad.kind, PAD);
            assert_eq!(5 + len + 5 + pad.payload.len(), padded_len(5 + len));
        }
        drop(tx);
        assert!(read_frame(&mut b).await.unwrap().is_none());
        w.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_oversized_packet() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let mut hdr = vec![PACKET];
        hdr.extend_from_slice(&((MAX_PACKET + 1) as u32).to_be_bytes());
        a.write_all(&hdr).await.unwrap();
        assert!(read_frame(&mut b).await.is_err());
    }
}
