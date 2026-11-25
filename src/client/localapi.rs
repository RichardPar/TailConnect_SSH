//! The Unix socket `tc` talks to. Anyone may read status; changing state
//! needs root.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tracing::debug;

use super::api::{Request, Response};
use super::{Daemon, Phase};

pub async fn serve(d: Arc<Daemon>) -> Result<()> {
    let path = d.opts.socket.clone();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    loop {
        let (s, _) = listener.accept().await?;
        let d = d.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(d, s).await {
                debug!("local api: {e:#}");
            }
        });
    }
}

async fn handle(d: Arc<Daemon>, s: UnixStream) -> Result<()> {
    let uid = s.peer_cred().map(|c| c.uid()).unwrap_or(u32::MAX);
    let (r, mut w) = s.into_split();
    let mut line = String::new();
    BufReader::new(r).read_line(&mut line).await?;
    let req: Request = serde_json::from_str(&line).context("bad request")?;
    let privileged = !matches!(req, Request::Status);
    let resp = if privileged && uid != 0 && uid != daemon_uid() {
        Response {
            ok: false,
            error: Some("permission denied: run this as root (sudo)".into()),
            status: None,
        }
    } else {
        match dispatch(&d, req).await {
            Ok(()) => Response {
                ok: true,
                error: None,
                status: Some(d.status()),
            },
            Err(e) => Response {
                ok: false,
                error: Some(format!("{e:#}")),
                status: Some(d.status()),
            },
        }
    };
    let mut out = serde_json::to_vec(&resp)?;
    out.push(b'\n');
    w.write_all(&out).await?;
    Ok(())
}

async fn dispatch(d: &Arc<Daemon>, req: Request) -> Result<()> {
    match req {
        Request::Status => Ok(()),
        Request::Down => {
            d.stop(Phase::Stopped);
            d.state.lock().unwrap().want_up = false;
            d.save_state();
            Ok(())
        }
        Request::Logout => {
            d.stop(Phase::NeedsLogin);
            *d.state.lock().unwrap() = Default::default();
            d.save_state();
            Ok(())
        }
        Request::Up {
            server,
            auth_key,
            tls_fingerprint,
        } => {
            let fp = tls_fingerprint
                .map(|f| crate::tls::normalise_fingerprint(&f))
                .transpose()?;
            {
                let mut st = d.state.lock().unwrap();
                if let Some(s) = server {
                    super::parse_server(&s)?;
                    if st.server.as_deref() != Some(s.as_str()) {
                        // A different server: forget the old one's keys.
                        st.server_host_key = None;
                        st.tls_fingerprint = None;
                    }
                    st.server = Some(s);
                }
                if fp.is_some() {
                    st.tls_fingerprint = fp;
                }
                if st.server.is_none() {
                    return Err(anyhow!("no server configured: pass --server"));
                }
            }
            d.save_state();
            let (tx, rx) = oneshot::channel();
            d.start(auth_key.filter(|k| !k.trim().is_empty()), Some(tx));
            match tokio::time::timeout(Duration::from_secs(45), rx).await {
                Ok(Ok(r)) => r,
                Ok(Err(_)) => Err(anyhow!("connection attempt was cancelled")),
                Err(_) => Err(anyhow!(
                    "timed out waiting for the server; still trying in the background"
                )),
            }
        }
    }
}

fn daemon_uid() -> u32 {
    // The daemon's own uid: lets an unprivileged test daemon be driven by
    // the same user. In production tcd runs as root, so this is 0.
    std::fs::metadata("/proc/self")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap_or(0)
}
