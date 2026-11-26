# TailConnect-SSH

A self-hosted mesh VPN in Rust that carries IP traffic over **SSH inside TLS on port 443**, instead of WireGuard over UDP. To a firewall or proxy it looks like ordinary HTTPS, so it works on networks that allow only outbound web traffic.

This is a Rust rewrite of [TailConnect](../TailConnect) (Go, WireGuard). It is at the Linux MVP stage: see [Status](#status).

## How it works

```
             TLS :443 ─ SSH ─ frames            TLS :443 ─ SSH ─ frames
  ┌──────┐ ───────────────────────► ┌──────────┐ ◄─────────────────────── ┌──────┐
  │ tcd  │   control + relayed      │tc-control│     control + relayed    │ tcd  │
  │alpha │   packets                │  (hub)   │     packets              │bravo │
  └──┬───┘                          └──────────┘                          └──┬───┘
     │ tcs0 100.64.0.1                                      tcs0 100.64.0.2 │
     └───────────────── direct TLS ─ SSH session (port 7443) ────────────────┘
                        when one machine can reach the other
```

- **Hub (`tc-control`).** Every machine keeps one session to the hub: TCP → TLS (ALPN `tc-ssh/1`) → SSH public-key auth → one SSH channel. On that channel, both sides exchange frames: JSON control messages (hello, welcome, network map) and sealed packets. The hub registers machines with pre-auth keys, gives each an address in `100.64.0.0/10`, pushes the network map whenever it changes, and relays packets between machines with no direct path.
- **End-to-end encryption of relayed traffic.** Before relaying anything, two machines run a Noise IK handshake (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) through the hub. Every relayed packet is then sealed with ChaCha20-Poly1305. The hub sees only the 4-byte destination address, and tells the receiver which machine sent each message. It never relays plaintext. The receiver checks, by cryptography, that the message came from that machine's key, and that the inner packet's source address is that machine's. Details are in [src/e2e.rs](src/e2e.rs).
- **Direct paths.** Each `tcd` also listens on port 7443 (TLS + SSH again) and reports its addresses to the hub, which adds the public address it sees. Peers dial each other's endpoints. Each side checks the other's SSH key against the network map, so only machines on the network get in. If the two dial each other at the same moment, both keep the link dialled by the smaller key. When a direct link drops, traffic goes back through the hub straight away, and the daemon dials again.
- **Machine identity** is an Ed25519 SSH key (`/var/lib/tailconnect-ssh/machine_key`). The hub knows machines by their public key. Clients trust the hub's SSH host key on first use and pin it.
- **TLS** uses either a trusted certificate (`--tls-cert/--tls-key`, for example from Let's Encrypt) or a self-signed one generated on first start. Clients pin a self-signed certificate by its SHA-256 fingerprint (`--tls-fingerprint`).
- **MagicDNS.** `tcd` answers DNS at `100.100.100.100`, inside the tunnel, from its own network map. Every machine is `name.account.tc.internal`, and plain `name` works for machines of the same account. `tcd` sets this up through `systemd-resolved` (`resolvectl`) when that's available: `tc.internal` is routed to the tunnel, and the machine's own `account.tc.internal` is its search domain. The resolver also answers `name.account` when asked directly (`dig @100.100.100.100 nas.alice`), but systemd-resolved doesn't apply search domains to names with a dot in them, so applications should use the full name for other accounts' machines.

### Per-account DNS domains

By default, an account's machines are `NAME.ACCOUNT.tc.internal`, under the hub's `--domain`. An account can choose a domain of its own instead, such as `acme.internal`, and its machines become `laptop.acme.internal` for everyone who can see them.
- **Setting it:**
  - an account: **My account → MagicDNS domain** in the portal;
  - an operator, for any account: `tcs-control accounts domain NAME acme.internal`, or **DNS domain** on the Accounts tab;
  - `default` (or an empty value) goes back to `NAME.ACCOUNT.tc.internal`.
- **Which domains are allowed:**
  - accounts may choose only domains ending in one of the hub's `--tenant-domain-suffixes` (default `internal`, as in `acme.internal`); operators may set any domain;
  - a domain can't be the hub's own domain or under it, and two accounts can't share one.
- **On the machines:** MagicDNS answers for every account's domain it knows of. `tcd` routes each such domain to it through systemd-resolved, and makes the machine's own zone its search domain, so `laptop` still works. The account-relative form `laptop.acme` works when asking MagicDNS directly.

### Key expiry, machine approval, ephemeral machines

| | |
|---|---|
| **Key expiry** | A machine's authorization lasts 180 days (the hub's `--key-expiry 180d`, or `never`). When it expires, the machine is cut off at that moment, with a notice in `tcs status`. `sudo tcs up --authkey KEY`, with a key of its own account, renews it. Owners and operators can set a machine's expiry or make it never expire: **Expiry** on the portal's Machines tab, or `tcs-control nodes expiry NODE never\|default\|90d`. `tcs status` warns two weeks ahead. Machines that joined before expiry existed never expire. |
| **Machine approval** | An account can require approval for new machines: **My account → Require approval for new machines**, or `tcs-control accounts approval NAME on`. A new machine then stays cut off, with a notice, until the owner or an operator approves it: **Approve** on the Machines tab, or `tcs-control nodes approve NODE`. Keys created as **pre-approved** (`authkey create --preapproved`) skip this. |
| **Ephemeral machines** | Machines that join with an **ephemeral** key (`authkey create --ephemeral`) are removed once they've been offline for the hub's `--ephemeral-timeout` (30 minutes by default). This suits CI runners and short-lived containers. Machines with an open connection are never removed. |

**Cut off** (an expired key, waiting for approval, or a suspended account) means the machine keeps its keys and its connection to the hub, gets an empty network map with the reason as a notice, and is invisible to every other machine. When the reason goes away, it's back within a second, with nothing to redo.

### IPv6 and exit nodes

**IPv6 inside the tunnel.**
- **Addresses.** Every machine also has an IPv6 address: its IPv4 address in the last 32 bits of `fd74:6373:7368::/48`, a private (ULA) range. For example, `100.96.0.2` goes with `fd74:6373:7368::6460:2`.
- **What works over it.** Ping, TCP and UDP work to that address too, and MagicDNS answers AAAA queries with it. Access rules, shares and the packet filter apply to IPv6 exactly as to IPv4.
- **Side by side.** The range differs from the WireGuard TailConnect's, so both can run on one machine.

**Exit nodes** (Linux). An exit node is a machine that other machines of its account can send all their internet traffic through, for example to browse from a café as if from home.

1. **Turn it on:** `sudo tcs-control nodes exit-node gw.richard on`, or **Exit node: off** on the portal's Machines tab. Every machine's role is off until then. Within a second, the machine turns on IP forwarding and NAT for traffic from the tunnel, and its `tcs status` says `exit node: this machine forwards internet traffic for its account`.
2. **Use it:** `sudo tcs up --exit-node gw` (a short name, `name.account`, full name or address). `tcs status` then says `exit node: internet traffic and DNS go through gw.richard`. The choice is kept across restarts.
3. **Stop using it:** `sudo tcs up --exit-node ""`.

| Traffic | Path while using an exit node |
|---|---|
| Internet, IPv4 and IPv6 | Through the tunnel to the exit node, then out from there (NAT to its address) |
| The local network, and anything else the machine has a more specific route for | Direct, as before |
| Other machines in the network | Through the tunnel, as before |
| tcd's own connections to the hub and to peers | Direct: they carry the tunnel |
| DNS | Names outside MagicDNS are resolved by the exit node, so the local network's resolver sees none of the lookups. MagicDNS names are answered on the machine itself. |

How it works and what to know:
- **Using one.** The machine uses policy routing, as `wg-quick` does, leaving the main routing table alone:
  - `tcd`'s own sockets carry firewall mark `0x7443` and use the main table;
  - every other route of the main table except its default still applies;
  - table 7443 holds the default routes into the tunnel.
- **DNS.** systemd-resolved sends every name to MagicDNS while the exit node is in use. MagicDNS passes names outside it to the exit node's forwarder, on its tunnel address at port 41653, through the tunnel, and readdresses the answers. Only UDP lookups go through; the rare lookup over TCP fails rather than going anywhere else.
- **Serving.** The exit node:
  - turns on forwarding, moving interfaces that take router advertisements to `accept_ra=2` first, so the host keeps its own IPv6 setup;
  - adds an nftables table `tailconnect-ssh-exit` that masquerades traffic from the tunnel;
  - where a firewall's forward policy is DROP (ufw), adds iptables rules tagged `tailconnect-ssh-exit`.
  - Its DNS forwarder uses the host's resolvers, or the ones given with `tcd --exit-dns 1.1.1.1,9.9.9.9`.
- **Cleanup.** Everything is undone when the role is turned off or `tcd` stops, and leftovers of a crash are removed when `tcd` starts.
- **Who may use an exit node.** Only machines of its own account, and only those that may open everything on it: access rules that limit a machine rule it out, and a share never makes a machine an exit node for another account. The exit node enforces this itself: it forwards only for machines allowed to use it, and only to addresses outside the tunnel.
- **Falling back.** If the exit node goes away (turned off, removed or offline), the machine falls back to its own internet connection and `tcs status` says why. It returns to the exit node by itself when it's back.
- **IPv6 to the internet** works if the exit node has a global IPv6 address. Otherwise programs fall back to IPv4.

**Sending exit traffic through another VPN.** An exit node can send the traffic it forwards for others out through one particular interface instead of its normal connection, for example a commercial VPN's `tun0` or a second uplink. Machines using it then appear on the internet from that VPN, while the exit node's own traffic is unchanged. In `/etc/default/tailconnect-ssh` on the exit node, set `TCD_ARGS="--exit-interface tun0"`, then restart the service. Its `tcs status` says `exit node: this machine forwards internet traffic for its account, through tun0`.
- **Kill switch.** While the interface is down or missing, for example while the VPN reconnects, forwarded traffic is **blocked**, never sent out through the normal connection. `tcs status` warns `tun0 is down: exit traffic is blocked until it is up`. tcd checks every 5 seconds, and routes through the interface again once it's back, even if it was recreated.
- **How.** Policy rules match only packets coming in from the tunnel:
  - rule 5260 lets the main table's specific routes apply (the LAN, the tunnel), but not its default nor OpenVPN's `0.0.0.0/1` + `128.0.0.0/1` pair;
  - rule 5261 sends everything else to table 7444. That table holds the default route out of the interface, via the gateway of its widest route if it has one (an Ethernet uplink), or straight out of it (`tun0`, `wg0`). It also holds an `unreachable` default with metric 4000, which is what answers while the interface is down.
  - Reverse-path filtering on the interface is set to loose, and restored afterwards.
- **DNS** for the machines using the exit node goes out through the interface too: the forwarder's sockets carry mark `0x7444`, which rule 5262 sends to the same table, so the kill switch covers it. Give public resolvers with `--exit-dns` if the host's own are on its LAN, for example `TCD_ARGS="--exit-interface tun0 --exit-dns 1.1.1.1,9.9.9.9"`, or the VPN provider's.
- **IPv6** goes through the interface if it has a global IPv6 address. Otherwise IPv6 is blocked and programs use IPv4.
- **The LAN** of the exit node, and the other machines in the network, are still reached directly.

### Accounts, sharing and access rules

| | |
|---|---|
| **Account** | A separate network on the hub. Its machines see and reach each other and nothing of other accounts, unless a machine is shared. Machine names are unique per account; addresses are unique across the hub. An account can be **suspended**: its machines stay connected but get an empty map with a notice, and its shares stop working, until it's activated again. |
| **Share** | Lets every machine of another account connect to *one* machine, optionally only on some ports. It's **one-way**: the shared machine can only reply, never open connections back, and the account's other machines stay invisible. A share is **pending** until it's accepted. If two accounts share a machine with each other, the two machines can both open connections. |
| **Tag** | A label on a machine (`server`, `staff`) that rules can select. |
| **Access rule** | *from → to on ports* within one account. From and to are `*`, `tag:NAME` or a machine name. Ports are `*`, or a list like `tcp:22,tcp:443,udp:53,8000-8100,icmp`. An account with no rules lets every machine reach every other. Once it has rules, only what they allow can be opened. Rules are one-way, and replies always get back. Machines that no rule connects in either direction don't see each other at all. |

How it's enforced:

- **Network maps.** The hub computes each machine's peers from accounts, shares and rules. Other machines' names, addresses and keys never reach it.
- **Relay.** The hub relays only between machines that are in each other's maps.
- **Packet filter.** Each peer in a map comes with what it may open on the receiving machine. That machine's stateful filter checks every arriving packet, whether over a direct path or decrypted from the hub, before it reaches the TUN device.
  - It passes replies to flows this machine started (TCP and UDP by ports, ping by identifier), new connections to allowed ports, and ICMP errors. It drops everything else and counts it in `tc status`.
  - It sits on the receiver, so a compromised sender can't switch it off. Each packet's source is bound to the peer's key, so it can't be forged.
  - It fails closed: a peer it doesn't know gets nothing, and a missing or unknown port entry grants nothing.

### Web portal

The hub serves a web portal on the same port, 443. During the TLS handshake, `tcd` asks for SSH (ALPN `tc-ssh/1`) and browsers ask for HTTP/1.1, so one listener answers both. Open `https://your-hub/` in a browser. With a self-signed certificate the browser warns once: compare the fingerprint `tc-control fingerprint` prints, then accept it.

| Tab | Who | What's there |
|---|---|---|
| Machines | everyone | Machines with online status, address, MagicDNS name, tags and **traffic** (current speeds and totals; click for the breakdown per peer); set tags, rename, remove. Operators see every account's. |
| Auth keys | everyone | Create keys (1 hour to 90 days, single-use or reusable). A new key is shown once, with the full `tc up` command, including `--tls-fingerprint` for a self-signed certificate. Revoke keys. |
| Access rules | everyone | Add and delete rules (operators pick the account) |
| Sharing | everyone | Share a machine with an account, or create a single-use **share link**; change ports; revoke. Accept, decline or remove shares offered to you, and redeem links. |
| Accounts | operators | Add accounts (with or without a portal password, tenant or operator); approve sign-ups; suspend and reactivate; change role; reset passwords; delete. Create and revoke **invites**. |
| My account | everyone | Change your password (this signs you out everywhere else) |

**Scripts** use the same API, under `/api/v1`, with the admin token as a bearer token: `curl -H "Authorization: Bearer $TC_ADMIN_TOKEN" https://hub.example.com/api/v1/machines`. Every endpoint is in [docs/api.md](docs/api.md).

**Signing in.** Accounts sign in with a name and password. Accounts without a password only own machines. The **admin token** (`tc-control admin-token`) signs in as an operator without an account, for recovery.

**Sign-up** (`--signup`):
- `off`: only operators create accounts;
- `approval` (the default): new accounts wait for an operator;
- `invite`: an invite code is needed;
- `open`: anyone who can reach the portal.

A valid invite skips approval in every mode except `off`.

**How the portal is protected:**
- Passwords are hashed with argon2id (19 MiB, 2 passes), and at most four hashes are computed at once.
- **Guessing is limited:** 10 tries per client address (an IPv4 address or IPv6 /64), then one every 6 seconds; 20 per account, then one a minute. A sign-in takes the same time whether or not the account exists.
- **Sessions** are random tokens held in memory, in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` over TLS), and last 12 hours.
  - A password, role or status change ends that account's sessions, even when made with the CLI.
  - Replacing the admin token ends token sessions.
- **Requests:**
  - writes are accepted only as JSON from the portal's own origin;
  - the portal answers only to IP addresses, `localhost`, the hub's hostname, the certificate's names, the `--public-url` host and `--portal-host` names (against DNS rebinding);
  - every response carries a strict Content Security Policy, HSTS over TLS, and `X-Frame-Options: DENY`.
- **Data:**
  - the UI builds pages from text only, never from HTML, so names that machines report can't inject anything;
  - tenants see only their own account (other accounts' objects answer 404, as if they didn't exist), apart from shares.
- `--portal-listen 127.0.0.1:7741` also serves the portal over plain HTTP, for use through `ssh -L`. On any other address it warns that passwords would cross the network unencrypted.
- `--no-portal` turns the portal off.

### HTTPS with Let's Encrypt

The hub can get a free, publicly trusted certificate from Let's Encrypt and renew it by itself: no certbot, no web server, no cron job. Machines then join with just `--server hub.example.com`, without `--tls-fingerprint`, and browsers trust the portal.

**What you need:**
- a DNS name pointing at the hub's public address;
- one of the three ways for Let's Encrypt to check that the name is yours:

| Check | Options | What must be reachable from the internet |
|---|---|---|
| TLS-ALPN-01 (default) | `--listen [::]:443 --acme-domain hub.example.com` | The hub's port 443. The check is answered on the same port as SSH and the portal. Behind a router that forwards 443 to another port, add `--public-url hub.example.com`. |
| HTTP-01 | `--listen [::]:8443 --acme-http-listen [::]:80 --acme-domain hub.example.com` | Port 80, which answers the checks and redirects everything else to HTTPS |
| DNS-01 with DuckDNS | `--acme-domain myhub.duckdns.org --acme-dns duckdns`, with `TC_DUCKDNS_TOKEN=…` in `/etc/default/tailconnect-ssh-control` | Nothing. The hub sets the TXT record through DuckDNS's API, and waits until DuckDNS's name servers serve it before asking Let's Encrypt to check. |

`tc-control` refuses settings that can't work, such as TLS-ALPN-01 with `--listen` on another port and no `--public-url`, instead of failing later.

**How it behaves:**
- **Getting the certificate.** At start, the hub serves its self-signed certificate until the real one arrives, usually within a minute.
- **Renewal.** It renews after two thirds of the certificate's lifetime (30 days before expiry), with no restart.
- **Failures.** It retries after 2 minutes, 10 minutes, an hour, then every 6 hours, and logs why (`journalctl -u tailconnect-ssh-control | grep acme`).
- **Test service.** Try `--acme-staging` first: Let's Encrypt's test service has generous rate limits, but its certificates aren't trusted. Test and real certificates are stored apart, so dropping `--acme-staging` needs no cleanup.
- **Other options.** `--acme-email` sets the account's contact address. `--acme-directory URL` uses another ACME server, and `--acme-ca-root PEM` trusts its test CA.
- **Storage.** Certificates and the ACME account are kept in `acme/` in the hub's state directory. Losing it only means fetching again.

**Machines that joined with a pinned self-signed certificate** stop connecting once the hub serves the Let's Encrypt one, because the pin no longer matches. Point each at the name: `sudo tcs up --server hub.example.com`. A new server address drops the old pin, and the machine keeps its registration and address; no auth key is needed.

**Traffic reports:**
- **What's reported.** Every machine counts the bytes it exchanges with each peer, over direct paths and through the hub alike. It sends the counts to the hub every 30 seconds while they change, over its control connection: only counts, nothing about what the traffic is.
- **What the hub keeps.** Only each machine's latest report, in memory: nothing goes to disk or into history.
- **Speeds** are the change between two reports. They drop to zero when a machine stops reporting.
- **Totals** count from when the machine's tunnel last started.
- **Direction.** ↓ is what the machine received and ↑ what it sent, from its own point of view. Packets its packet filter drops aren't counted as received.
- **Who sees what.** Tenants see their own machines' traffic. In the per-peer breakdown, a peer is named only if it's one of the account's own machines or linked by a share; any other peer, such as a removed machine, shows as "another machine". Operators see everything.
- **On the machine.** `tcs status` shows the same counts per peer.

### Desktop app (Linux)

Two programs, both installed by `install.sh client`:

- **`tcs-gui`**, the TailConnect window, in the applications menu. It shows:
  - the connection, this machine's name and address (with a copy button), the hub, and any problem;
  - Connect or Disconnect, the exit node (chosen from the machines that offer it), and a button that opens the web portal;
  - "Log in…" (hub, auth key, and a TLS fingerprint for a self-signed hub) and "Log out…";
  - the network's other machines: online or not, their addresses (with copy buttons), the path to each (`direct`, `hub, e2e`), what they may open here, and the traffic exchanged.
- **`tcs-tray`**, an icon in the desktop panel that starts at login. It works with any panel that shows StatusNotifierItem icons: Cinnamon, KDE, MATE, XFCE and Ubuntu's GNOME; plain GNOME needs the AppIndicator extension. Clicking the icon opens the window. The icon is:
  - teal while connected;
  - grey while disconnected or logged out;
  - amber with a "!" when something needs attention, such as the service not running, the account suspended, the chosen exit node unavailable, or the exit interface down. A desktop notification says what went wrong.

  Its menu has the state, this machine's address (click to copy), Connect or Disconnect, "Copy address of" each other machine, the exit node, and the web portal.

Connecting, disconnecting and choosing an exit node need root or membership of the `tailconnect-ssh` group. `install.sh client` creates that group and adds the user who ran it, effective at once. Logging in and out from the window ask for an administrator's password (through polkit's `pkexec`); in a terminal they're `sudo tcs up --server … --authkey …` and `sudo tcs logout`.

The window is built only with `--features gui`, which needs GTK 4.14 or later and its development files (`sudo apt install libgtk-4-dev`). Machines that run it need the GTK 4 libraries (`libgtk-4-1`), which desktop distributions already have.

### Windows

A Windows 10 (2004+) or 11 PC joins like any other machine: it gets an address and a name, reaches peers directly or through the hub, and resolves MagicDNS names in every program.

- **Install**: run `tailconnect-ssh-VERSION-windows-amd64-setup.exe` and accept the Windows prompt. The wizard installs, then offers to open the app. For scripts, run `setup.exe /S`, or unzip the `.zip` and run `install.cmd` (or `tcd install` as administrator). Either way it sets up:
  - `C:\Program Files\TailConnect-SSH` and the **TailConnectSSH** service, which starts with Windows and restarts if it fails;
  - `tcs` on the PATH;
  - firewall rules for peers' direct connections and for the tunnel;
  - the app in the Start menu, at sign-in, and in Settings → Apps.

  Running a newer setup.exe upgrades in place. Settings → Apps → Uninstall runs `tcd uninstall`; add `--purge` to also delete the keys.
- **The app** (`TailConnectSSH.exe`): an icon by the clock (teal, grey or amber, as on Linux) whose right-click menu has the address, Connect/Disconnect, the other machines and the exit node. Left-click opens a small window:
  - a header card in the state's colour, with this PC's name, its address (click to copy) and a Connect switch;
  - the exit node;
  - the machines, with their paths (`direct`, `relay · e2e`, `offline`);
  - the web portal, "Hub & key" and logging out.

  It follows Windows' light or dark theme. Closing the window keeps the icon.
- **Permissions**: any signed-in user may connect, disconnect and choose the exit node. Logging in and out need an administrator: the app asks Windows for elevation, and `tcs up --authkey` / `tcs logout` need an elevated prompt.
- **How**:
  - a Wintun adapter "TailConnect-SSH" (`wintun.dll` beside `tcd.exe`);
  - MagicDNS through NRPT rules for the network's zones, plus the PC's zone as the adapter's DNS suffix, so short names work. The rules are removed when the tunnel goes down;
  - an exit node is used through `0.0.0.0/1` + `128.0.0.0/1` routes on the adapter, with a host route keeping the hub on the real network;
  - the local API is the named pipe `\\.\pipe\tailconnect-ssh`;
  - keys and the service's log (`tcd.log`) are in `C:\ProgramData\TailConnect-SSH`, readable only by administrators.
- **Not yet**: being an exit node.

Build the packages on Linux (needs `rustup target add x86_64-pc-windows-gnu`, `mingw-w64`, `nsis` and `zip`):

```sh
packaging/windows/build.sh     # dist/tailconnect-ssh-VERSION-windows-amd64-setup.exe and .zip
```

It downloads Wintun once from wintun.net, checks it against a pinned SHA-256, and embeds the app icon in the programs. The programs aren't code-signed, so SmartScreen may warn the first time: choose **More info → Run anyway**.

### Security notes

- **All traffic between machines is end-to-end encrypted.** Direct paths are SSH sessions between the two machines. Relayed traffic is sealed with per-pair Noise sessions that the hub can't read or forge. The hub still sees metadata: which machines talk to each other, when, and how much.
- **E2E keys.** Each machine's X25519 key is derived from its Ed25519 SSH machine key (the libsodium `ed25519_sk_to_curve25519` conversion). Peers' keys come from the network map, so no second key needs distributing.
- **Sessions:**
  - they're rekeyed every 2 minutes and refused after 3, so a stolen session key exposes at most a few minutes of traffic (forward secrecy comes from the ephemeral Noise keys);
  - a handshake carries a timestamp, so replayed handshakes are dropped;
  - data messages carry a counter checked against a replay window.
- **The hub is trusted to hand out the right keys**, as with WireGuard-based meshes: a malicious hub could put a key of its own in a network map. It can't read or alter traffic between machines whose keys it reported truthfully.
- Unknown keys can authenticate to the hub, but all they can do is register, and only with a valid auth key. Auth keys are stored as SHA-256 hashes. They can be single-use or reusable, given an expiry, and revoked.
- Isolation between accounts, one-way sharing and access rules are enforced by the hub (maps, relay) and by each receiving machine's packet filter. See [Accounts, sharing and access rules](#accounts-sharing-and-access-rules).

## Build

```sh
cargo build --release                  # target/release/{tc-control,tcd,tc,tc-tray}
cargo build --release --features gui   # also the window, tc-gui (needs libgtk-4-dev)
```

## Quick start

`packaging/linux/install.sh` installs with systemd:
- **Binaries** go to `/opt/tailconnect-ssh/bin`, with commands linked as `tcs` (the client CLI) and `tcs-control` (the hub's admin CLI).
- **State** lives in `/var/lib/tailconnect-ssh` and `/var/lib/tailconnect-ssh-control`.
- **Services** are `tailconnect-ssh` and `tailconnect-ssh-control`.
- **Settings** go in `/etc/default/tailconnect-ssh` (`TCD_ARGS`) and `/etc/default/tailconnect-ssh-control` (`TC_CONTROL_ARGS`).
- **Side by side:** none of these names, nor the `tcs0` interface, overlap the WireGuard TailConnect's (`tcd`, `tc`, `tc0`, `/var/lib/tailconnect`), so both can be installed on one machine.

On the **hub** (it needs a public address, or port 443 forwarded to it):

```sh
cargo build --release
sudo packaging/linux/install.sh hub --listen [::]:443        # arguments go to /etc/default/tailconnect-ssh-control
sudo tcs-control fingerprint                                  # note the TLS fingerprint
sudo tcs-control accounts create richard --operator --password   # for the web portal
# now open https://hub.example.com/ and sign in; or carry on in the terminal:
sudo tcs-control authkey create --account richard --reusable --expires-hours 24
```

On **every machine** (the hub can be one too):

```sh
sudo packaging/linux/install.sh client     # or BIN=DIR for binaries built elsewhere
sudo tcs up --server hub.example.com --tls-fingerprint <FINGERPRINT> --authkey <KEY>
tcs status
ping bravo            # MagicDNS: bravo.richard.tc.internal
```

To upgrade, build and run the same `install.sh` command again: it keeps settings and state, and restarts the service. `sudo packaging/linux/install.sh uninstall` removes everything except state and settings; add `--purge` to delete those too.

If another network on the machine already uses `100.64.0.x`, as the WireGuard TailConnect does, give the hub a separate part of the range, for example `--ip-pool 100.96.0.0/16`.

Sharing a machine with another account, and access rules within one:

```sh
sudo tcs-control accounts create alice
sudo tcs-control shares create web.richard alice tcp:80,tcp:443   # pending
sudo tcs-control shares accept 1                                  # on alice's behalf
# alice's machines now reach http://web.richard; web can't open connections to them

sudo tcs-control nodes tag laptop.richard staff
sudo tcs-control nodes tag web.richard server
sudo tcs-control rules add --account richard tag:staff tag:server tcp:22,tcp:443
# richard's laptops may open SSH and HTTPS on web; nothing else in richard is reachable now
```

With a trusted certificate (`--tls-cert fullchain.pem --tls-key privkey.pem` in the hub's arguments), leave out `--tls-fingerprint`.

The command tables below use the binaries' own names (`tc-control`, `tcd`, `tc`); installed, the CLIs are `tcs-control` and `tcs`.

## Commands

| Command | What it does |
|---|---|
| `tc-control serve [--listen [::]:443] [--domain tc.internal] [--tls-cert F --tls-key F] [--tls-name NAME…]` | Run the hub |
| `tc-control fingerprint` | Print the TLS fingerprint and SSH host key |
| `tc-control serve … [--signup off\|approval\|invite\|open] [--public-url HOST] [--portal-host NAME…] [--portal-listen ADDR] [--no-portal]` | Web portal options |
| `tc-control serve … [--key-expiry 180d\|never] [--ephemeral-timeout 30m] [--tenant-domain-suffixes internal]` | How long machines stay authorized; when ephemeral machines are removed; which domains accounts may choose |
| `tc-control accounts create NAME [--operator] [--password]` / `list` / `passwd NAME` / `role NAME operator\|tenant` / `approve NAME` / `approval NAME on\|off` / `domain NAME DOMAIN\|default` / `suspend NAME` / `activate NAME` / `delete NAME` | Accounts (deleting removes the account's machines, keys, rules and shares); passwords are asked for twice, or read from standard input |
| `tc-control invites create [--days N]` / `list` / `revoke ID` | Invites for sign-up |
| `tc-control admin-token` | New admin token for the portal (replaces the old one) |
| `tc-control authkey create [--account NAME] [--reusable] [--expires-hours N] [--ephemeral] [--preapproved]` / `list` / `revoke ID` | Pre-auth keys; machines join the key's account |
| `tc-control nodes list [--account NAME]` / `remove NODE` / `rename NODE NEW` / `tag NODE TAG,…` / `exit-node NODE on\|off` / `approve NODE` / `expiry NODE never\|default\|90d` | Machines; `NODE` is an ID or `name.account` |
| `tc-control rules list [--account NAME]` / `add --account NAME FROM TO [PORTS]` / `delete ID` | Access rules |
| `tc-control shares list` / `create NODE ACCOUNT [PORTS]` / `accept ID` / `ports ID PORTS` / `revoke ID` | Shares |
| `tcd [--tun tcs0] [--direct-port 7443] [--mtu 1400] [--no-dns] [--hostname NAME] [--exit-dns IP,…] [--exit-interface IFACE]` | Machine daemon (needs root or `CAP_NET_ADMIN`) |
| `tc up [--server HOST[:PORT]] [--authkey KEY] [--tls-fingerprint FP] [--exit-node NAME]` | Join or reconnect; `--exit-node` alone switches the exit node without reconnecting (`""` for none) |
| `tc-tray`, `tc-gui` | Panel icon and menu; the window (see "Desktop app") |
| `tc down` / `tc logout` | Disconnect / disconnect and forget the server |
| `tc status [--json]`, `tc ip [NAME]` | Show this machine, its peers, the path to each (`direct` or `hub`), and what they may do (`shared with you`, `has access to this machine on tcp:80`, `rules: can open tcp:22 here`) |

The admin commands work on the database directly, whether or not the hub is running. A running hub applies changes within a second, and a removed machine is cut off. A database from before accounts existed is migrated on first open, with its machines and keys moved into an account named `default`.

`--state-dir` (`TC_STATE_DIR`) and `--socket` (`TC_SOCKET`) change where things are kept.

## Tests

```sh
cargo test                    # unit tests: framing, DNS, packets, database, keys, e2e crypto, ACLs, filter, policy, portal API
cargo build && tests/e2e-netns.sh   # end to end, no root needed
PEBBLE=… CHALLTESTSRV=… tests/acme-pebble.sh   # Let's Encrypt against Pebble, no root needed
```

`tests/acme-pebble.sh` tests built-in Let's Encrypt against [Pebble](https://github.com/letsencrypt/pebble), Let's Encrypt's test ACME server. Get `pebble` and `pebble-challtestsrv` from Pebble's releases and check their SHA-256 digests. The script checks:
- all three ways of proving the name;
- that port 80 redirects to HTTPS;
- renewal of 90-second certificates, without a restart;
- reuse of the saved certificate after a restart.

`tests/e2e-netns.sh` runs a hub and three machines in two accounts, in unprivileged user and network namespaces linked by veth pairs. It checks:

- joining, and refusal of a used single-use key or a wrong TLS fingerprint;
- ping, TCP and MagicDNS through the hub, with end-to-end sessions up both ways;
- traffic counts in `tc status`, and in the portal with a per-peer breakdown;
- IPv6 inside the tunnel (ping6 both ways, MagicDNS AAAA);
- an account moving to its own DNS domain and back;
- machine approval: a new machine is cut off and invisible until approved;
- an ephemeral machine removed once offline;
- a key that expires, cutting the machine off at once, and renewal with `tcs up --authkey`;
- exit nodes, using an extra namespace as "the internet":
  - IPv4 and IPv6 leaving through the exit node with NAT, and DNS resolved there;
  - an exit node serving only its own account;
  - falling back when the role is turned off, and returning when it's back;
  - the choice kept across restarts, and working over a direct path;
  - an exit interface: forwarded traffic leaving through a "VPN" interface while the exit node's own traffic doesn't, and the kill switch blocking it while that interface is down;
- the admin HTTP API with a bearer token;
- isolation between accounts (maps, DNS, traffic);
- a share that's one-way and limited to some ports, including changing the ports live;
- suspending and reactivating an account;
- a tag-based access rule, and that deleting it restores everything;
- direct SSH paths after a restart, with share limits still enforced on them;
- that a machine removed by the operator is cut off;
- the web portal on port 443 beside SSH: signing in, creating the key a machine joins with, tagging, refusing unknown host names and cross-site writes, and sign-up waiting for approval.

## Status

Done (Linux MVP):

- the hub on 443 with SSH inside TLS, registration with auth keys, address allocation, a pushed network map, and relaying with source checks;
- `tcd` with a TUN device, direct SSH paths with fallback to the hub, MagicDNS (A and PTR records), the local API and the `tc` CLI;
- end-to-end encryption of relayed traffic (Noise IK per pair of machines, rekeying, replay protection);
- accounts, one-way sharing with port limits, tag-based access rules, account suspension, and a stateful packet filter on each receiving machine;
- traffic reports per machine and peer in the portal and `tcs status`;
- a desktop app for Linux: a window (`tcs-gui`, GTK 4) and a panel icon with a menu (`tcs-tray`);
- a Windows client: a service with a Wintun adapter, MagicDNS through NRPT, using exit nodes, `tcs`, an installer, and an app (tray icon, menu and window);
- IPv6 inside the tunnel, and exit nodes (Linux) with DNS through the exit node, optionally out through another VPN with a kill switch;
- key expiry with renewal, machine approval, ephemeral machines;
- per-account MagicDNS domains;
- an admin HTTP API for scripts (`/api/v1`, bearer token; [docs/api.md](docs/api.md));
- the web portal on port 443 (by ALPN): passwords, operator and tenant roles, sign-up with approval or invites, share links, the admin token;
- built-in Let's Encrypt: TLS-ALPN-01 on the hub's own port, HTTP-01, or DNS-01 through DuckDNS, with automatic renewal;
- an admin CLI, systemd units, and unit and end-to-end tests.

Roadmap toward parity with the Go TailConnect:

1. Windows (Wintun) and Android (VpnService) clients
