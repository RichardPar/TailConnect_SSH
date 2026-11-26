//! Exit nodes (Windows): using one. (Being one isn't supported on Windows
//! yet; `serve` says so.)
//!
//! Internet traffic goes into the tunnel through `0.0.0.0/1` and
//! `128.0.0.0/1` routes on the adapter (`::/1` and `8000::/1` for IPv6),
//! which win over the default route without replacing it. Each hub address
//! that was reached through the default route gets a host route through
//! that same interface and gateway first, so tcd's connection to the hub
//! stays on the real network. Peers on the LAN keep their more specific
//! routes. Everything is undone when the exit node is no longer used; the
//! adapter's routes also go with the adapter.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Result, bail};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::win::{powershell, ps_quote};

/// (Linux's socket marks have no Windows equivalent; see the module docs.)
pub const MARK: u32 = 0;
pub const EXIT_MARK: u32 = 0;

pub use super::exitdns::{DNS_PORT, Pending, dns_forwarder, system_resolvers};

/// This machine's exit node role (never on, on Windows).
pub struct Serving {
    pub dns: CancellationToken,
    pub iface: Option<String>,
    pub iface_problem: Arc<std::sync::RwLock<Option<String>>>,
}

pub fn serve(_tun: &str, _iface: Option<&str>) -> Result<Serving> {
    bail!("this machine can't be an exit node: that isn't supported on Windows yet")
}

pub fn unserve(_s: Serving) {}

/// Host routes added for the hub: (prefix, interface index).
static HUB_ROUTES: Mutex<Vec<(String, u32)>> = Mutex::new(Vec::new());
/// The adapter the default routes were added to.
static ROUTED_TUN: Mutex<Option<String>> = Mutex::new(None);

/// Send everything without a more specific route into the adapter `tun`,
/// keeping `keep` (the hub's addresses) on the real network.
pub fn route_via(tun: &str, v6: bool, keep: &[IpAddr]) -> Result<()> {
    unroute();
    *ROUTED_TUN.lock().unwrap() = Some(tun.to_string());
    let hubs = keep
        .iter()
        .map(|a| ps_quote(&a.to_string()))
        .collect::<Vec<_>>()
        .join(",");
    let mut defaults = vec!["'0.0.0.0/1'", "'128.0.0.0/1'"];
    if v6 {
        defaults.extend(["'::/1'", "'8000::/1'"]);
    }
    // Hub routes first (while the default route still decides), printed as
    // "prefix ifindex" so they can be removed later.
    let script = format!(
        "$tun = (Get-NetAdapter -Name {tun}).ifIndex\n\
         foreach ($h in @({hubs})) {{\n\
           $r = Find-NetRoute -RemoteIPAddress $h | Where-Object {{ $_.DestinationPrefix }} | Select-Object -First 1\n\
           if ($r -and $r.InterfaceIndex -ne $tun -and $r.DestinationPrefix -match '/0$') {{\n\
             $p = if ($h -like '*:*') {{ \"$h/128\" }} else {{ \"$h/32\" }}\n\
             New-NetRoute -DestinationPrefix $p -InterfaceIndex $r.InterfaceIndex -NextHop $r.NextHop -RouteMetric 0 -PolicyStore ActiveStore | Out-Null\n\
             Write-Output \"$p $($r.InterfaceIndex)\"\n\
           }}\n\
         }}\n\
         foreach ($d in @({defaults})) {{\n\
           $nh = if ($d -like '*:*') {{ '::' }} else {{ '0.0.0.0' }}\n\
           New-NetRoute -DestinationPrefix $d -InterfaceIndex $tun -NextHop $nh -RouteMetric 0 -PolicyStore ActiveStore | Out-Null\n\
         }}",
        tun = ps_quote(tun),
        defaults = defaults.join(","),
    );
    let out = match powershell(&script) {
        Ok(o) => o,
        Err(e) => {
            unroute();
            return Err(e);
        }
    };
    let mut added = HUB_ROUTES.lock().unwrap();
    for l in out.lines() {
        if let Some((p, i)) = l.trim().split_once(' ')
            && let Ok(i) = i.parse()
        {
            info!("exit node: the hub ({p}) stays on interface {i}");
            added.push((p.to_string(), i));
        }
    }
    Ok(())
}

/// Undo [`route_via`].
pub fn unroute() {
    let routes: Vec<(String, u32)> = std::mem::take(&mut *HUB_ROUTES.lock().unwrap());
    let mut script = String::new();
    for (p, i) in &routes {
        script.push_str(&format!(
            "Remove-NetRoute -DestinationPrefix {} -InterfaceIndex {i} -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue\n",
            ps_quote(p)
        ));
    }
    if let Some(tun) = ROUTED_TUN.lock().unwrap().take() {
        script.push_str(&format!(
            "Get-NetRoute -InterfaceAlias {} -PolicyStore ActiveStore -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1','::/1','8000::/1' }} | \
             Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue",
            ps_quote(&tun)
        ));
    }
    if script.is_empty() {
        return;
    }
    if let Err(e) = powershell(&script) {
        warn!("exit node: removing routes: {e:#}");
    }
}

/// Leftovers of a previous run: tcd's DNS rules (routes go with the adapter).
pub fn cleanup() {
    super::win::clear_dns();
}
