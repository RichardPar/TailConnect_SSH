//! Exit nodes (Linux): the system plumbing.
//!
//! **Serving** (this machine's exit node role is on):
//! * IP forwarding on, IPv6 too. Interfaces that take router advertisements
//!   (`accept_ra` = 1) are moved to 2 first, so the host keeps its own IPv6
//!   addresses and routes.
//! * An nftables table `tailconnect-ssh-exit` masquerades traffic from the
//!   tunnel leaving by another interface.
//! * Where a firewall's forward policy is DROP (ufw), iptables rules tagged
//!   `tailconnect-ssh-exit` let the tunnel's traffic (and its replies) through.
//! * A DNS forwarder on the tunnel address, port [`DNS_PORT`], resolves for
//!   the machines using this exit node, with this machine's resolvers.
//!
//! **Using an exit node**: policy routing, as `wg-quick` does, leaving the
//! main routing table alone:
//!
//! | Rule | Effect |
//! |---|---|
//! | `5270: fwmark 0x7443 lookup main` | tcd's own connections (to the hub and peers) use the real network |
//! | `5271: lookup main suppress_prefixlength 0` | every route of the main table except its default: the LAN, the tunnel |
//! | `5272: lookup 7443` | table 7443: the default routes into the tunnel |
//!
//! **Exit interface** (`tcd --exit-interface tun0`): the traffic forwarded
//! for others leaves through that interface (a commercial VPN, say) instead
//! of the normal connection; the host's own traffic is untouched. Rules
//! that match only packets coming in from the tunnel:
//!
//! | Rule | Effect |
//! |---|---|
//! | `5260: iif tcs0 lookup main suppress_prefixlength 1` | the main table's specific routes (the LAN, the tunnel), not its default nor OpenVPN's `0.0.0.0/1` + `128.0.0.0/1` |
//! | `5261: iif tcs0 lookup 7444` | table 7444: the default out of the interface, and an `unreachable` default (metric 4000) |
//! | `5262: fwmark 0x7444 lookup 7444` | the DNS forwarder's lookups for its clients |
//!
//! **Kill switch**: while the interface is down or gone, its route is gone
//! and the `unreachable` default answers: the traffic is refused, never sent
//! out the normal way. Every 5 seconds the route is put back (with the
//! interface's current gateway) if the interface is up. IPv6 goes through
//! the interface only if it has a global IPv6 address; otherwise it's blocked.
//!
//! Everything is undone when the role ends, the exit node is no longer used,
//! or tcd stops, and leftovers are removed when tcd starts (after a crash).

use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Firewall mark on tcd's own sockets.
pub const MARK: u32 = 0x7443;
/// Routing table holding the default routes into the tunnel.
pub const TABLE: u32 = 7443;
const PREFS: [u32; 6] = [5260, 5261, 5262, 5270, 5271, 5272];
/// Routing table for traffic leaving through the exit interface.
pub const EXIT_TABLE: u32 = 7444;
/// Firewall mark on the DNS forwarder's sockets when an exit interface is set.
pub const EXIT_MARK: u32 = 0x7444;
const NFT_TABLE: &str = "tailconnect-ssh-exit";
const TAG: &str = "tailconnect-ssh-exit";

pub use super::exitdns::{DNS_PORT, Pending, dns_forwarder, system_resolvers};

/// Did running a command fail because it isn't installed?
fn is_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

fn run(args: &[&str]) -> Result<String> {
    let out = Command::new(args[0]).args(&args[1..]).output()?;
    if !out.status.success() {
        bail!("{}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn run_input(args: &[&str], input: &str) -> Result<()> {
    use std::io::Write;
    let mut child = Command::new(args[0])
        .args(&args[1..])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    child.stdin.take().expect("stdin").write_all(input.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("{}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn read_sysctl(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn write_sysctl(path: &str, v: &str) -> Result<()> {
    std::fs::write(path, v).map_err(|e| anyhow::anyhow!("{path}: {e}"))
}

// ---- serving ----

/// What enabling the exit node role changed, to restore it afterwards.
pub struct Serving {
    sysctls: Vec<(String, String)>,
    /// iptables rules added: (command, table, chain, rule).
    iptables: Vec<IptRule>,
    pub dns: CancellationToken,
    /// The exit interface, when one is set.
    pub iface: Option<String>,
    /// Why forwarded traffic is blocked right now (the kill switch).
    pub iface_problem: Arc<std::sync::RwLock<Option<String>>>,
}

type IptRule = (&'static str, &'static str, &'static str, Vec<String>);

/// Insert an iptables rule (tagged), recording it for removal.
fn ipt_add(
    added: &mut Vec<IptRule>,
    cmd: &'static str,
    table: &'static str,
    chain: &'static str,
    rule: &[&str],
) -> Result<()> {
    let mut r: Vec<String> = rule.iter().map(|s| s.to_string()).collect();
    r.extend(["-m", "comment", "--comment", TAG].map(String::from));
    let mut a = vec![cmd, "-w", "-t", table, "-I", chain, "1"];
    a.extend(r.iter().map(String::as_str));
    run(&a)?;
    added.push((cmd, table, chain, r));
    Ok(())
}

/// The forward rules for the tunnel: its traffic out, and the replies.
fn forward_rules(tun: &str) -> [Vec<&str>; 2] {
    [
        vec!["-i", tun, "-j", "ACCEPT"],
        vec![
            "-o",
            tun,
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    ]
}

/// NAT with iptables, where nftables isn't installed: masquerade what the
/// tunnel's addresses send out by any other interface, and let it through
/// the filter. (iptables' nat POSTROUTING can't match the incoming
/// interface, so this matches the tailnet's source addresses.)
fn iptables_nat(tun: &str, added: &mut Vec<IptRule>) -> Result<()> {
    let v4 = format!("{}/{}", crate::TAILNET_NET, crate::TAILNET_PREFIX);
    let v6 = format!("{}/{}", crate::TAILNET6, crate::TAILNET6_PREFIX);
    for (cmd, src) in [("iptables", v4.as_str()), ("ip6tables", v6.as_str())] {
        let r = ipt_add(
            added,
            cmd,
            "nat",
            "POSTROUTING",
            &["-s", src, "!", "-o", tun, "-j", "MASQUERADE"],
        )
        .and_then(|_| {
            for rule in forward_rules(tun) {
                ipt_add(added, cmd, "filter", "FORWARD", &rule)?;
            }
            Ok(())
        });
        match (cmd, r) {
            (_, Ok(())) => {}
            // IPv4 is what matters; IPv6 NAT may not be available.
            ("ip6tables", Err(e)) => warn!("exit node: no IPv6 forwarding (ip6tables NAT: {e:#})"),
            (_, Err(e)) => return Err(e),
        }
    }
    Ok(())
}

fn remove_iptables(rules: &[IptRule]) {
    for (cmd, table, chain, r) in rules.iter().rev() {
        let mut a = vec![*cmd, "-w", "-t", table, "-D", chain];
        a.extend(r.iter().map(String::as_str));
        let _ = run(&a);
    }
}

const FORWARD_V4: &str = "/proc/sys/net/ipv4/ip_forward";
const FORWARD_V6: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

/// Turn on forwarding and NAT for traffic from `tun`.
pub fn serve(tun: &str, iface: Option<&str>) -> Result<Serving> {
    let mut sysctls = Vec::new();
    // Keep router advertisements working where the host relies on them:
    // forwarding on makes accept_ra=1 stop accepting them.
    if let Ok(dir) = std::fs::read_dir("/proc/sys/net/ipv6/conf") {
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if ["all", "default", "lo", tun].contains(&name.as_str()) {
                continue;
            }
            let p = format!("/proc/sys/net/ipv6/conf/{name}/accept_ra");
            if read_sysctl(&p).as_deref() == Some("1") && write_sysctl(&p, "2").is_ok() {
                sysctls.push((p, "1".into()));
            }
        }
    }
    for p in [FORWARD_V4, FORWARD_V6] {
        let Some(old) = read_sysctl(p) else { continue };
        if old != "1" {
            match write_sysctl(p, "1") {
                Ok(()) => sysctls.push((p.into(), old)),
                Err(e) if p == FORWARD_V6 => warn!("exit node: IPv6 forwarding not available: {e}"),
                Err(e) => {
                    restore(&sysctls);
                    return Err(e);
                }
            }
        }
    }
    let _ = run(&["nft", "delete", "table", "inet", NFT_TABLE]);
    let script = format!(
        "table inet {NFT_TABLE} {{
            chain postrouting {{
                type nat hook postrouting priority srcnat; policy accept;
                iifname \"{tun}\" oifname != \"{tun}\" masquerade
            }}
            chain forward {{
                type filter hook forward priority filter; policy accept;
                iifname \"{tun}\" accept
                oifname \"{tun}\" ct state established,related accept
            }}
        }}"
    );
    let mut iptables = Vec::new();
    match run_input(&["nft", "-f", "-"], &script) {
        Ok(()) => {
            // A firewall whose forward policy is DROP (ufw, Docker) would
            // still drop it.
            for cmd in ["iptables", "ip6tables"] {
                let drops = run(&[cmd, "-w", "-S", "FORWARD"]).is_ok_and(|s| s.lines().any(|l| l == "-P FORWARD DROP"));
                if !drops {
                    continue;
                }
                for rule in forward_rules(tun) {
                    if let Err(e) = ipt_add(&mut iptables, cmd, "filter", "FORWARD", &rule) {
                        warn!("exit node: {e}");
                    }
                }
            }
        }
        // No nftables here (Debian 11 and older): iptables, as its
        // forward chain would otherwise drop, and its NAT.
        Err(e) if is_not_found(&e) => {
            info!("exit node: nft isn't installed; using iptables for NAT");
            if let Err(e) = iptables_nat(tun, &mut iptables) {
                remove_iptables(&iptables);
                restore(&sysctls);
                bail!("exit node: setting up NAT (iptables): {e:#}");
            }
        }
        Err(e) => {
            restore(&sysctls);
            bail!("exit node: setting up NAT (nft): {e}");
        }
    }
    let dns = CancellationToken::new();
    let iface_problem = Arc::new(std::sync::RwLock::new(None));
    if let Some(i) = iface {
        // Replies come back on the interface from addresses the main table
        // routes elsewhere: loose reverse-path filtering there.
        let rp = format!("/proc/sys/net/ipv4/conf/{i}/rp_filter");
        if let Some(old) = read_sysctl(&rp)
            && old != "2"
            && write_sysctl(&rp, "2").is_ok()
        {
            sysctls.push((rp, old));
        }
        if let Err(e) = iface_rules(tun) {
            unserve(Serving {
                sysctls,
                iptables,
                dns,
                iface: None,
                iface_problem,
            });
            bail!("exit node: routing through {i}: {e}");
        }
        tokio::spawn(watch_iface(i.to_string(), iface_problem.clone(), dns.clone()));
        info!("exit node: forwarding internet traffic from {tun} through {i} (blocked while {i} is down)");
    } else {
        info!("exit node: forwarding internet traffic from {tun}");
    }
    Ok(Serving {
        sysctls,
        iptables,
        dns,
        iface: iface.map(String::from),
        iface_problem,
    })
}

/// The policy rules sending forwarded traffic (and the DNS forwarder's) to
/// the exit interface's table, with the kill switch's unreachable default.
fn iface_rules(tun: &str) -> Result<()> {
    let table = EXIT_TABLE.to_string();
    let mark = format!("{EXIT_MARK:#x}");
    for f in ["-4", "-6"] {
        for p in [5260, 5261, 5262] {
            while run(&["ip", f, "rule", "del", "pref", &p.to_string()]).is_ok() {}
        }
        let _ = run(&["ip", f, "route", "flush", "table", &table]);
        let def = if f == "-4" { "0.0.0.0/0" } else { "::/0" };
        run(&[
            "ip",
            f,
            "route",
            "replace",
            "unreachable",
            def,
            "metric",
            "4000",
            "table",
            &table,
        ])?;
        run(&[
            "ip",
            f,
            "rule",
            "add",
            "iif",
            tun,
            "lookup",
            "main",
            "suppress_prefixlength",
            "1",
            "pref",
            "5260",
        ])?;
        run(&["ip", f, "rule", "add", "iif", tun, "lookup", &table, "pref", "5261"])?;
        run(&[
            "ip", f, "rule", "add", "fwmark", &mark, "lookup", &table, "pref", "5262",
        ])?;
    }
    Ok(())
}

/// Is the interface present, up and with a link? (Asked with `ip link`,
/// which, unlike /sys, always answers for tcd's own network namespace.)
fn iface_up(i: &str) -> bool {
    run(&["ip", "-o", "link", "show", "dev", i]).is_ok_and(|l| link_up(&l))
}

/// From `ip -o link` output: flags include UP and LOWER_UP.
fn link_up(line: &str) -> bool {
    let flags = line.split('<').nth(1).and_then(|r| r.split('>').next()).unwrap_or("");
    let f: Vec<&str> = flags.split(',').collect();
    f.contains(&"UP") && f.contains(&"LOWER_UP")
}

/// The gateway of the interface's widest route in the main table, if any:
/// `default via G dev i`, or OpenVPN's `0.0.0.0/1 via G dev i`.
fn iface_gateway(f: &str, i: &str) -> Option<String> {
    widest_gateway(&run(&["ip", f, "route", "show", "table", "main", "dev", i]).ok()?)
}

/// The gateway of the widest route with one in `ip route show` output.
fn widest_gateway(routes: &str) -> Option<String> {
    let mut best: Option<(u8, String)> = None;
    for l in routes.lines() {
        let w: Vec<&str> = l.split_whitespace().collect();
        let Some(pos) = w.iter().position(|x| *x == "via") else {
            continue;
        };
        let Some(gw) = w.get(pos + 1) else { continue };
        let len = match w[0] {
            "default" => 0,
            p => p.split('/').nth(1).and_then(|l| l.parse().ok()).unwrap_or(128),
        };
        if best.as_ref().is_none_or(|(b, _)| len < *b) {
            best = Some((len, gw.to_string()));
        }
    }
    best.map(|(_, g)| g)
}

/// Does the interface have a global IPv6 address?
fn iface_has_v6(i: &str) -> bool {
    run(&["ip", "-6", "addr", "show", "dev", i, "scope", "global"]).is_ok_and(|s| s.contains("inet6"))
}

/// Keep the default route out of the exit interface while it's up, and
/// report when it isn't (the kill switch then blocks forwarded traffic).
async fn watch_iface(i: String, problem: Arc<std::sync::RwLock<Option<String>>>, cancel: CancellationToken) {
    let table = EXIT_TABLE.to_string();
    let mut last: Option<Option<String>> = None;
    loop {
        let now = if iface_up(&i) {
            for f in ["-4", "-6"] {
                if f == "-6" && !iface_has_v6(&i) {
                    let _ = run(&["ip", "-6", "route", "del", "default", "dev", &i, "table", &table]);
                    continue;
                }
                let mut args = vec!["ip", f, "route", "replace", "default"];
                let gw = iface_gateway(f, &i);
                if let Some(g) = &gw {
                    args.extend(["via", g.as_str()]);
                }
                args.extend(["dev", i.as_str(), "metric", "0", "table", table.as_str()]);
                if let Err(e) = run(&args) {
                    debug!("exit interface route: {e}");
                }
            }
            None
        } else {
            Some(format!("{i} is down: exit traffic is blocked until it is up"))
        };
        if last.as_ref() != Some(&now) {
            match &now {
                Some(p) => warn!("exit node: {p}"),
                None if last.is_some() => info!("exit node: {i} is up again; forwarding through it"),
                None => {}
            }
            *problem.write().unwrap() = now.clone();
            last = Some(now);
        }
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}

fn restore(sysctls: &[(String, String)]) {
    for (p, v) in sysctls.iter().rev() {
        if let Err(e) = write_sysctl(p, v) {
            warn!("exit node: restoring {e}");
        }
    }
}

/// Undo [`serve`].
pub fn unserve(s: Serving) {
    s.dns.cancel();
    let table = EXIT_TABLE.to_string();
    for f in ["-4", "-6"] {
        for p in [5260, 5261, 5262] {
            while run(&["ip", f, "rule", "del", "pref", &p.to_string()]).is_ok() {}
        }
        let _ = run(&["ip", f, "route", "flush", "table", &table]);
    }
    let _ = run(&["nft", "delete", "table", "inet", NFT_TABLE]);
    remove_iptables(&s.iptables);
    restore(&s.sysctls);
    info!("exit node: stopped forwarding");
}

// ---- using an exit node ----

/// Send everything without a more specific route into `tun`. (`_keep`, the
/// hub's addresses, stay on the real network through tcd's socket mark.)
pub fn route_via(tun: &str, v6: bool, _keep: &[IpAddr]) -> Result<()> {
    unroute();
    let mark = format!("{MARK:#x}");
    let table = TABLE.to_string();
    let families: &[&str] = if v6 { &["-4", "-6"] } else { &["-4"] };
    for f in families {
        let def = if *f == "-4" { "0.0.0.0/0" } else { "::/0" };
        run(&["ip", f, "route", "replace", def, "dev", tun, "table", &table])?;
        run(&[
            "ip", f, "rule", "add", "fwmark", &mark, "lookup", "main", "pref", "5270",
        ])?;
        run(&[
            "ip",
            f,
            "rule",
            "add",
            "lookup",
            "main",
            "suppress_prefixlength",
            "0",
            "pref",
            "5271",
        ])?;
        run(&["ip", f, "rule", "add", "lookup", &table, "pref", "5272"])?;
    }
    Ok(())
}

/// Undo [`route_via`] (and leftovers from a crash).
pub fn unroute() {
    let table = TABLE.to_string();
    for f in ["-4", "-6"] {
        for p in PREFS {
            // A rule may have been added more than once.
            for _ in 0..8 {
                if run(&["ip", f, "rule", "del", "pref", &p.to_string()]).is_err() {
                    break;
                }
            }
        }
        let _ = run(&["ip", f, "route", "flush", "table", &table]);
        let _ = run(&["ip", f, "route", "flush", "table", &EXIT_TABLE.to_string()]);
    }
}

/// Remove everything a previous tcd may have left behind.
pub fn cleanup() {
    unroute();
    if run(&["nft", "delete", "table", "inet", NFT_TABLE]).is_ok() {
        info!("exit node: removed a leftover NAT table");
    }
    for cmd in ["iptables", "ip6tables"] {
        for (table, chain) in [("filter", "FORWARD"), ("nat", "POSTROUTING")] {
            let Ok(rules) = run(&[cmd, "-w", "-t", table, "-S", chain]) else {
                continue;
            };
            for l in rules.lines().filter(|l| l.contains(TAG)) {
                // "-A CHAIN ..." → "-D CHAIN ..."
                let spec: Vec<String> = shell_words(l.trim_start_matches(&format!("-A {chain}")));
                let mut a = vec![cmd, "-w", "-t", table, "-D", chain];
                a.extend(spec.iter().map(String::as_str));
                let _ = run(&a);
            }
        }
    }
}

/// Split iptables -S output into words (it quotes comments).
fn shell_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            ' ' if !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iptables_rule_words() {
        let l = r#"-A FORWARD -i tcs0 -m comment --comment "tailconnect-ssh-exit" -j ACCEPT"#;
        assert_eq!(
            shell_words(l.trim_start_matches("-A FORWARD")),
            vec![
                "-i",
                "tcs0",
                "-m",
                "comment",
                "--comment",
                "tailconnect-ssh-exit",
                "-j",
                "ACCEPT"
            ]
        );
    }

    #[test]
    fn link_state() {
        assert!(link_up(
            "5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN"
        ));
        assert!(!link_up(
            "5: tun0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 qdisc noop state DOWN"
        ));
        assert!(!link_up(
            "7: vpn0@if3: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 state LOWERLAYERDOWN"
        ));
    }

    #[test]
    fn exit_interface_gateway() {
        let openvpn = "0.0.0.0/1 via 10.8.0.1 metric 50\n10.8.0.0/24 proto kernel scope link src 10.8.0.6\n128.0.0.0/1 via 10.8.0.1";
        assert_eq!(widest_gateway(openvpn).as_deref(), Some("10.8.0.1"));
        let eth = "default via 192.168.2.1 proto dhcp metric 100\n192.168.2.0/24 proto kernel scope link";
        assert_eq!(widest_gateway(eth).as_deref(), Some("192.168.2.1"));
        // Point-to-point (wg0, tun0 without via): straight out of the device.
        assert_eq!(widest_gateway("10.0.0.0/24 proto kernel scope link src 10.0.0.2"), None);
    }
}
