//! Framing used inside the SSH channel.
//!
//! Every connection carries one SSH session channel. On it, both sides send
//! frames of `[kind: u8][len: u32 big-endian][payload]`. Kind `CONTROL` is a
//! JSON message (see [`crate::proto`]); kind `PACKET` is one raw IP packet
//! (only on direct peer links); kind `SEALED` is an end-to-end encrypted
//! message relayed by the hub (see [`crate::e2e`]), prefixed with a 4-byte
//! IPv4 address: the destination from client to hub, the sender from hub to
//! client.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

pub const CONTROL: u8 = 0;
pub const PACKET: u8 = 1;
pub const SEALED: u8 = 2;

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
pub async fn writer_task<W: AsyncWrite + Unpin>(w: W, mut rx: mpsc::Receiver<Frame>) -> io::Result<()> {
    let mut w = BufWriter::with_capacity(256 * 1024, w);
    while let Some(f) = rx.recv().await {
        put_frame(&mut w, &f).await?;
        let mut n = 0;
        while n < 256 {
            match rx.try_recv() {
                Ok(f) => put_frame(&mut w, &f).await?,
                Err(_) => break,
            }
            n += 1;
        }
        w.flush().await?;
    }
    let _ = w.shutdown().await;
    Ok(())
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
        let f1 = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!((f1.kind, f1.payload), (PACKET, vec![1, 2, 3]));
        let f2 = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(f2.kind, CONTROL);
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
