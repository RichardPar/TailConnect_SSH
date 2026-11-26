//! How the daemon's status is put into words, shared by `tc`, the panel
//! icon and the window, so they all say the same thing.

use super::api::{PeerStatus, Status};

/// The overall look: the icon's colour, the window's headline colour.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Look {
    Connected,
    Disconnected,
    Attention,
}

/// Something about this machine that needs the user's attention.
pub fn problem(s: &Status) -> Option<String> {
    s.notice
        .clone()
        .or_else(|| s.exit_interface_problem.clone())
        .or_else(|| {
            s.exit_problem
                .clone()
                .map(|p| format!("{p}; internet traffic goes direct"))
        })
        .or_else(|| (s.phase == "connecting").then(|| s.last_error.clone()).flatten())
}

/// The look for a status (`None`: the service isn't running).
pub fn look(s: Option<&Status>) -> Look {
    match s {
        None => Look::Attention,
        Some(s) if problem(s).is_some() => Look::Attention,
        Some(s) if s.phase == "running" => Look::Connected,
        Some(_) => Look::Disconnected,
    }
}

/// A one-word-or-so headline: "Connected", "Logged out"…
pub fn headline(s: Option<&Status>) -> &'static str {
    match s {
        None => "The service isn't running",
        Some(s) => match s.phase.as_str() {
            "running" => "Connected",
            "connecting" => "Connecting…",
            "needs-login" => "Logged out",
            _ if s.server.is_none() => "Not set up",
            _ => "Disconnected",
        },
    }
}

/// This machine has joined a network it can reconnect to without a key.
pub fn logged_in(s: &Status) -> bool {
    s.server.is_some() && s.phase != "needs-login"
}

/// This machine's full MagicDNS name and address.
pub fn my_name(s: &Status) -> Option<(String, String)> {
    let me = s.me.as_ref()?;
    let zone = if me.zone.is_empty() {
        format!("{}.{}", me.account, s.domain)
    } else {
        me.zone.clone()
    };
    Some((format!("{}.{zone}", me.name), me.ip.to_string()))
}

/// A peer's full name, or name.account.
pub fn peer_name(p: &PeerStatus) -> String {
    if p.fqdn.is_empty() {
        format!("{}.{}", p.name, p.account)
    } else {
        p.fqdn.clone()
    }
}

/// How a peer relates to this machine, from what it may open here.
pub fn relation(me_account: &str, p: &PeerStatus) -> Option<String> {
    let all = p.inbound.iter().any(|x| x == "*");
    let ports = p.inbound.join(",");
    if p.account == me_account {
        return match (all, p.inbound.is_empty()) {
            (true, _) => None,
            (false, true) => Some("rules: can't open connections here".into()),
            (false, false) => Some(format!("rules: can open {ports} here")),
        };
    }
    Some(match (all, p.inbound.is_empty()) {
        (true, _) => "has access to this machine".into(),
        (false, true) => "shared with you".into(),
        (false, false) => format!("has access to this machine on {ports}"),
    })
}

/// The path to a peer: `offline`, `direct`, `hub` or `hub, e2e`, and its
/// exit node role.
pub fn path(s: &Status, p: &PeerStatus) -> String {
    let path = match (p.online, p.path.as_str(), p.e2e) {
        (false, _, _) => "offline",
        (_, "hub", true) => "hub, e2e",
        (_, path, _) => path,
    };
    let in_use = s.exit_in_use.as_deref() == Some(format!("{}.{}", p.name, p.account).as_str());
    match (p.exit_node, in_use) {
        (_, true) => format!("{path}; exit node (in use)"),
        (true, false) => format!("{path}; exit node"),
        _ => path.to_string(),
    }
}

pub fn bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n}B")
    } else {
        format!("{v:.1}{}", U[i])
    }
}

/// The web portal's address, on the hub.
pub fn portal_url(s: &Status) -> Option<String> {
    let (host, port) = super::parse_server(s.server.as_ref()?).ok()?;
    let host = if host.contains(':') { format!("[{host}]") } else { host };
    Some(if port == 443 {
        format!("https://{host}/")
    } else {
        format!("https://{host}:{port}/")
    })
}

/// The exit nodes on offer (name.account), and which is chosen: 0 for
/// none, else 1 + its index.
pub struct ExitChoice {
    pub names: Vec<String>,
    pub selected: usize,
}

/// `None` when there's nothing to choose from.
pub fn exit_choice(s: &Status) -> Option<ExitChoice> {
    let names: Vec<String> = s
        .peers
        .iter()
        .filter(|p| p.exit_node)
        .map(|p| format!("{}.{}", p.name, p.account))
        .collect();
    if names.is_empty() && s.exit_node.is_none() {
        return None;
    }
    let chosen = s.exit_in_use.clone().or_else(|| s.exit_node.clone());
    let selected = chosen
        .and_then(|c| {
            names
                .iter()
                .position(|n| *n == c || n.split('.').next() == Some(c.as_str()))
        })
        .map(|i| i + 1)
        .unwrap_or(0);
    Some(ExitChoice { names, selected })
}

/// The app's icon, `size` pixels square, as RGBA: a disc in the look's
/// colour (teal, grey, amber) with a white ring and dot (a node on the
/// network), or a white "!" when something needs attention.
pub fn icon_rgba(size: u32, look: Look) -> Vec<u8> {
    let (r, g, b) = match look {
        Look::Connected => (0x14, 0x9c, 0x8c),
        Look::Disconnected => (0x8a, 0x8f, 0x98),
        Look::Attention => (0xe0, 0x9a, 0x16),
    };
    let n = size as usize;
    let mut data = vec![0u8; n * n * 4];
    let c = (size as f32 - 1.0) / 2.0;
    let rad = size as f32 / 2.0 - 0.5;
    for y in 0..n {
        for x in 0..n {
            let (dx, dy) = (x as f32 - c, y as f32 - c);
            let d = (dx * dx + dy * dy).sqrt();
            // Anti-aliased disc edge.
            let alpha = (rad - d + 0.5).clamp(0.0, 1.0);
            if alpha == 0.0 {
                continue;
            }
            let white = match look {
                Look::Attention => {
                    // "!": a bar and a dot, centred.
                    let w = (size as f32 * 0.09).max(1.0);
                    let bar = dx.abs() <= w && dy >= -rad * 0.55 && dy <= rad * 0.15;
                    let dot = dx.abs() <= w && dy >= rad * 0.32 && dy <= rad * 0.55;
                    bar || dot
                }
                _ => {
                    let ring = (d - rad * 0.55).abs() <= (size as f32 * 0.07).max(0.8);
                    let dot = d <= rad * 0.2;
                    ring || dot
                }
            };
            let i = (y * n + x) * 4;
            let (pr, pg, pb) = if white { (255, 255, 255) } else { (r, g, b) };
            data[i..i + 4].copy_from_slice(&[pr, pg, pb, (alpha * 255.0) as u8]);
        }
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str, exit: bool) -> PeerStatus {
        PeerStatus {
            name: name.into(),
            fqdn: String::new(),
            account: "a".into(),
            tags: vec![],
            inbound: vec!["*".into()],
            ip: "100.96.0.9".parse().unwrap(),
            online: true,
            path: "direct".into(),
            endpoints: vec![],
            exit_node: exit,
            exit_client: false,
            e2e: false,
            rx: 0,
            tx: 0,
        }
    }

    #[test]
    fn words() {
        let mut s = Status {
            phase: "running".into(),
            server: Some("hub.example:8443".into()),
            peers: vec![peer("x", false), peer("y", true)],
            ..Default::default()
        };
        assert_eq!(look(Some(&s)), Look::Connected);
        assert_eq!(headline(Some(&s)), "Connected");
        assert_eq!(portal_url(&s).as_deref(), Some("https://hub.example:8443/"));
        let c = exit_choice(&s).unwrap();
        assert_eq!((c.names.clone(), c.selected), (vec!["y.a".to_string()], 0));
        s.exit_node = Some("y".into());
        assert_eq!(exit_choice(&s).unwrap().selected, 1);
        s.exit_problem = Some("y.a is offline".into());
        assert_eq!(look(Some(&s)), Look::Attention);
        assert_eq!(path(&s, &s.peers[1]), "direct; exit node");
        assert_eq!(look(None), Look::Attention);
        assert_eq!(bytes(1536), "1.5KiB");
    }
}
