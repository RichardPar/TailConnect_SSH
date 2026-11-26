//! The local API `tc` and the apps talk to: a Unix socket on Linux, a named
//! pipe on Windows. Anyone may read status. Connecting, disconnecting and
//! choosing an exit node need root or the `tailconnect-ssh` group on Linux;
//! on Windows any signed-in user may. Joining a network and logging out need
//! root, or on Windows an elevated administrator (or SYSTEM).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;

use super::api::{Request, Response};
use super::{Daemon, Phase};

pub use platform::serve;

/// Who's asking.
struct Caller {
    /// May do anything: root (or tcd's own user), or on Windows an
    /// elevated administrator or SYSTEM.
    admin: bool,
    /// May connect, disconnect and choose the exit node.
    operator: bool,
}

#[cfg(unix)]
mod platform {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    use anyhow::{Context, Result};
    use tokio::net::UnixListener;
    use tracing::debug;

    use super::{Caller, Daemon, daemon_uid, handle, in_operator_group};

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
            let cred = s.peer_cred().ok();
            let uid = cred.as_ref().map(|c| c.uid()).unwrap_or(u32::MAX);
            let caller = Caller {
                admin: uid == 0 || uid == daemon_uid(),
                operator: cred
                    .as_ref()
                    .is_some_and(|c| in_operator_group(c.uid(), c.gid(), c.pid())),
            };
            let d = d.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(d, s, caller).await {
                    debug!("local api: {e:#}");
                }
            });
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::os::windows::io::AsRawHandle;
    use std::sync::Arc;

    use anyhow::{Context, Result};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tracing::debug;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};

    use super::{Caller, Daemon, handle};

    /// SYSTEM and Administrators: full control; signed-in users: read and
    /// write (so they can send requests); nobody else, nor other machines.
    const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

    fn create(name: &str, first: bool) -> std::io::Result<NamedPipeServer> {
        let sddl: Vec<u16> = SDDL.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SDDL string; sd receives a LocalAlloc'd
        // descriptor, freed below after the pipe has copied it.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        // SAFETY: sa is a valid SECURITY_ATTRIBUTES for the call's duration.
        let r = unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(name, &mut sa as *mut _ as *mut std::ffi::c_void)
        };
        // SAFETY: sd came from ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(sd as _) };
        r
    }

    pub async fn serve(d: Arc<Daemon>) -> Result<()> {
        let name = d.opts.socket.to_string_lossy().to_string();
        let mut server = create(&name, true).with_context(|| format!("creating {name} (is tcd already running?)"))?;
        loop {
            server.connect().await?;
            let client = server;
            server = create(&name, false)?;
            let caller = Caller {
                admin: client_elevated(&client),
                // The pipe's permissions let only signed-in users in.
                operator: true,
            };
            let d = d.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(d, client, caller).await {
                    debug!("local api: {e:#}");
                }
            });
        }
    }

    /// Is the client process running elevated (an administrator past UAC,
    /// or SYSTEM)?
    fn client_elevated(p: &NamedPipeServer) -> bool {
        let mut pid = 0u32;
        // SAFETY: a connected pipe handle and a u32 out-parameter.
        if unsafe { GetNamedPipeClientProcessId(p.as_raw_handle() as HANDLE, &mut pid) } == 0 {
            return false;
        }
        // SAFETY: handles are checked and closed; the out-parameters are
        // sized for TOKEN_ELEVATION.
        unsafe {
            let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if proc.is_null() {
                return false;
            }
            let mut token: HANDLE = std::ptr::null_mut();
            let ok = OpenProcessToken(proc, TOKEN_QUERY, &mut token);
            CloseHandle(proc);
            if ok == 0 {
                return false;
            }
            let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut e as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            );
            CloseHandle(token);
            ok != 0 && e.TokenIsElevated != 0
        }
    }
}

#[cfg(unix)]
const DENIED_OPERATOR: &str = "permission denied: run this as root (sudo), or join the tailconnect-ssh group";
#[cfg(unix)]
const DENIED_ADMIN: &str = "permission denied: run this as root (sudo)";
#[cfg(windows)]
const DENIED_OPERATOR: &str = "permission denied";
#[cfg(windows)]
const DENIED_ADMIN: &str = "permission denied: run this as administrator (an elevated command prompt)";

async fn handle<S: AsyncRead + AsyncWrite>(d: Arc<Daemon>, s: S, caller: Caller) -> Result<()> {
    let (r, mut w) = tokio::io::split(s);
    let mut line = String::new();
    BufReader::new(r).read_line(&mut line).await?;
    let req: Request = serde_json::from_str(&line).context("bad request")?;
    let privileged = !matches!(req, Request::Status);
    let allowed = !privileged || caller.admin || (operator_request(&req) && caller.operator);
    let resp = if !allowed {
        Response {
            ok: false,
            error: Some(
                if operator_request(&req) {
                    DENIED_OPERATOR
                } else {
                    DENIED_ADMIN
                }
                .into(),
            ),
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
            exit_node,
        } => {
            // Only choosing an exit node, while connected: no reconnect.
            let running = *d.phase.read().unwrap() == Phase::Running;
            if exit_node.is_some() && server.is_none() && auth_key.is_none() && tls_fingerprint.is_none() && running {
                d.state.lock().unwrap().exit_node = exit_node.filter(|e| !e.trim().is_empty());
                d.save_state();
                d.reconcile_exit();
                return match d.exit_problem.read().unwrap().clone() {
                    Some(p) => Err(anyhow!("{p}")),
                    None => Ok(()),
                };
            }
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
                        st.network_secret = None;
                    }
                    st.server = Some(s);
                }
                if fp.is_some() {
                    st.tls_fingerprint = fp;
                }
                if let Some(e) = exit_node {
                    st.exit_node = Some(e).filter(|e| !e.trim().is_empty());
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

#[cfg(unix)]
/// Members of this group may connect, disconnect and choose the exit node
/// (the panel icon's menu); joining a network and logging out stay root's.
pub const OPERATOR_GROUP: &str = "tailconnect-ssh";

/// A request an operator may make: Down, or Up that reuses the saved login.
fn operator_request(req: &Request) -> bool {
    match req {
        Request::Down => true,
        Request::Up {
            server,
            auth_key,
            tls_fingerprint,
            ..
        } => server.is_none() && auth_key.is_none() && tls_fingerprint.is_none(),
        _ => false,
    }
}

#[cfg(unix)]
/// Is the peer in OPERATOR_GROUP: by its primary gid, its process's
/// supplementary groups, or its user being listed in /etc/group (so a user
/// just added counts at once, without logging out and in)?
fn in_operator_group(uid: u32, gid: u32, pid: Option<i32>) -> bool {
    let groups = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let Some(want) = group_gid(&groups, OPERATOR_GROUP) else {
        return false;
    };
    if gid == want {
        return true;
    }
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    if let Some(user) = user_name(&passwd, uid)
        && group_members(&groups, OPERATOR_GROUP).contains(&user)
    {
        return true;
    }
    let Some(pid) = pid else { return false };
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    status_groups(&status).contains(&want)
}

#[cfg(unix)]
fn group_gid(group_file: &str, name: &str) -> Option<u32> {
    group_file.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name).then_some(())?;
        f.nth(1)?.parse().ok()
    })
}

#[cfg(unix)]
fn group_members<'a>(group_file: &'a str, name: &str) -> Vec<&'a str> {
    group_file
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 4 && f[0] == name).then(|| f[3].split(',').filter(|m| !m.is_empty()).collect())
        })
        .unwrap_or_default()
}

#[cfg(unix)]
fn user_name(passwd: &str, uid: u32) -> Option<&str> {
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 3 && f[2].parse() == Ok(uid)).then_some(f[0])
    })
}

#[cfg(unix)]
fn status_groups(status: &str) -> Vec<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Groups:"))
        .map(|g| g.split_whitespace().filter_map(|x| x.parse().ok()).collect())
        .unwrap_or_default()
}

#[cfg(unix)]
fn daemon_uid() -> u32 {
    // The daemon's own uid: lets an unprivileged test daemon be driven by
    // the same user. In production tcd runs as root, so this is 0.
    std::fs::metadata("/proc/self")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap_or(0)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn operator_permissions() {
        assert!(operator_request(&Request::Down));
        assert!(operator_request(&Request::Up {
            server: None,
            auth_key: None,
            tls_fingerprint: None,
            exit_node: Some("x".into())
        }));
        assert!(!operator_request(&Request::Up {
            server: Some("h".into()),
            auth_key: None,
            tls_fingerprint: None,
            exit_node: None
        }));
        assert!(!operator_request(&Request::Up {
            server: None,
            auth_key: Some("k".into()),
            tls_fingerprint: None,
            exit_node: None
        }));
        assert!(!operator_request(&Request::Logout));
        let g = "root:x:0:\nsudo:x:27:richard\ntailconnect-ssh:x:987:richard\n";
        assert_eq!(group_gid(g, "tailconnect-ssh"), Some(987));
        assert_eq!(group_gid(g, "tailconnect"), None);
        assert_eq!(group_members(g, "tailconnect-ssh"), vec!["richard"]);
        assert!(group_members("tailconnect-ssh:x:987:\n", "tailconnect-ssh").is_empty());
        let pw = "root:x:0:0::/root:/bin/sh\nrichard:x:1000:1000::/home/richard:/bin/bash\n";
        assert_eq!(user_name(pw, 1000), Some("richard"));
        assert_eq!(user_name(pw, 5), None);
        assert_eq!(
            status_groups("Name:\tx\nGroups:\t4 27 987 \nNSpid: 1\n"),
            vec![4, 27, 987]
        );
    }
}
