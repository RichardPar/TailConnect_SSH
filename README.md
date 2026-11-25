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
| Machines | everyone | Machines with online status, address, MagicDNS name and tags; set tags, rename, remove. Operators see every account's. |
| Auth keys | everyone | Create keys (1 hour to 90 days, single-use or reusable). A new key is shown once, with the full `tc up` command, including `--tls-fingerprint` for a self-signed certificate. Revoke keys. |
| Access rules | everyone | Add and delete rules (operators pick the account) |
| Sharing | everyone | Share a machine with an account, or create a single-use **share link**; change ports; revoke. Accept, decline or remove shares offered to you, and redeem links. |
| Accounts | operators | Add accounts (with or without a portal password, tenant or operator); approve sign-ups; suspend and reactivate; change role; reset passwords; delete. Create and revoke **invites**. |
| My account | everyone | Change your password (this signs you out everywhere else) |

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
cargo build --release      # target/release/{tc-control,tcd,tc}
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
| `tc-control accounts create NAME [--operator] [--password]` / `list` / `passwd NAME` / `role NAME operator\|tenant` / `approve NAME` / `suspend NAME` / `activate NAME` / `delete NAME` | Accounts (deleting removes the account's machines, keys, rules and shares); passwords are asked for twice, or read from standard input |
| `tc-control invites create [--days N]` / `list` / `revoke ID` | Invites for sign-up |
| `tc-control admin-token` | New admin token for the portal (replaces the old one) |
| `tc-control authkey create [--account NAME] [--reusable] [--expires-hours N]` / `list` / `revoke ID` | Pre-auth keys; machines join the key's account |
| `tc-control nodes list [--account NAME]` / `remove NODE` / `rename NODE NEW` / `tag NODE TAG,…` | Machines; `NODE` is an ID or `name.account` |
| `tc-control rules list [--account NAME]` / `add --account NAME FROM TO [PORTS]` / `delete ID` | Access rules |
| `tc-control shares list` / `create NODE ACCOUNT [PORTS]` / `accept ID` / `ports ID PORTS` / `revoke ID` | Shares |
| `tcd [--tun tcs0] [--direct-port 7443] [--mtu 1400] [--no-dns] [--hostname NAME]` | Machine daemon (needs root or `CAP_NET_ADMIN`) |
| `tc up [--server HOST[:PORT]] [--authkey KEY] [--tls-fingerprint FP]` | Join or reconnect |
| `tc down` / `tc logout` | Disconnect / disconnect and forget the server |
| `tc status [--json]`, `tc ip [NAME]` | Show this machine, its peers, the path to each (`direct` or `hub`), and what they may do (`shared with you`, `has access to this machine on tcp:80`, `rules: can open tcp:22 here`) |

The admin commands work on the database directly, whether or not the hub is running. A running hub applies changes within a second, and a removed machine is cut off. A database from before accounts existed is migrated on first open, with its machines and keys moved into an account named `default`.

`--state-dir` (`TC_STATE_DIR`) and `--socket` (`TC_SOCKET`) change where things are kept.

## Tests

```sh
cargo test                    # unit tests: framing, DNS, packets, database, keys, e2e crypto, ACLs, filter, policy, portal API
cargo build && tests/e2e-netns.sh   # end to end, no root needed
```

`tests/e2e-netns.sh` runs a hub and three machines in two accounts, in unprivileged user and network namespaces linked by veth pairs. It checks:

- joining, and refusal of a used single-use key or a wrong TLS fingerprint;
- ping, TCP and MagicDNS through the hub, with end-to-end sessions up both ways;
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
- the web portal on port 443 (by ALPN): passwords, operator and tenant roles, sign-up with approval or invites, share links, the admin token;
- an admin CLI, systemd units, and unit and end-to-end tests.

Roadmap toward parity with the Go TailConnect:

1. Built-in Let's Encrypt; traffic reports in the portal; an admin HTTP API for scripts
2. IPv6 inside the tunnel, exit nodes
3. Key expiry, machine approval, ephemeral machines; per-account DNS domains
4. Windows (Wintun) and Android (VpnService) clients
