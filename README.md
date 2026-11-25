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
     │ tc0 100.64.0.1                                         tc0 100.64.0.2 │
     └───────────────── direct TLS ─ SSH session (port 7443) ────────────────┘
                        when one machine can reach the other
```

- **Hub (`tc-control`).** Every machine keeps one session to the hub: TCP → TLS (ALPN `tc-ssh/1`) → SSH public-key auth → one SSH channel. On that channel, both sides exchange frames: JSON control messages (hello, welcome, network map) and sealed packets. The hub registers machines with pre-auth keys, gives each an address in `100.64.0.0/10`, pushes the network map whenever it changes, and relays packets between machines with no direct path.
- **End-to-end encryption of relayed traffic.** Before relaying anything, two machines run a Noise IK handshake (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) through the hub. Every relayed packet is then sealed with ChaCha20-Poly1305. The hub sees only the 4-byte destination address, and tells the receiver which machine sent each message. It never relays plaintext. The receiver checks, by cryptography, that the message came from that machine's key, and that the inner packet's source address is that machine's. Details are in [src/e2e.rs](src/e2e.rs).
- **Direct paths.** Each `tcd` also listens on port 7443 (TLS + SSH again) and reports its addresses to the hub, which adds the public address it sees. Peers dial each other's endpoints. Each side checks the other's SSH key against the network map, so only machines on the network get in. If the two dial each other at the same moment, both keep the link dialled by the smaller key. When a direct link drops, traffic goes back through the hub straight away, and the daemon dials again.
- **Machine identity** is an Ed25519 SSH key (`/var/lib/tailconnect/machine_key`). The hub knows machines by their public key. Clients trust the hub's SSH host key on first use and pin it.
- **TLS** uses either a trusted certificate (`--tls-cert/--tls-key`, for example from Let's Encrypt) or a self-signed one generated on first start. Clients pin a self-signed certificate by its SHA-256 fingerprint (`--tls-fingerprint`).
- **MagicDNS.** `tcd` answers DNS for `name.tc.internal` and bare `name` at `100.100.100.100`, inside the tunnel. It sets this up through `systemd-resolved` (`resolvectl`) when that's available.

### Security notes

- **All traffic between machines is end-to-end encrypted.** Direct paths are SSH sessions between the two machines. Relayed traffic is sealed with per-pair Noise sessions that the hub can't read or forge. The hub still sees metadata: which machines talk to each other, when, and how much.
- **E2E keys.** Each machine's X25519 key is derived from its Ed25519 SSH machine key (the libsodium `ed25519_sk_to_curve25519` conversion). Peers' keys come from the network map, so no second key needs distributing.
- **Sessions:**
  - they're rekeyed every 2 minutes and refused after 3, so a stolen session key exposes at most a few minutes of traffic (forward secrecy comes from the ephemeral Noise keys);
  - a handshake carries a timestamp, so replayed handshakes are dropped;
  - data messages carry a counter checked against a replay window.
- **The hub is trusted to hand out the right keys**, as with WireGuard-based meshes: a malicious hub could put a key of its own in a network map. It can't read or alter traffic between machines whose keys it reported truthfully.
- Unknown keys can authenticate to the hub, but all they can do is register, and only with a valid auth key. Auth keys are stored as SHA-256 hashes. They can be single-use or reusable, given an expiry, and revoked.
- Within the network there are no access rules yet: every machine can reach every other.

## Build

```sh
cargo build --release      # target/release/{tc-control,tcd,tc}
```

## Quick start

On the **hub** (it needs a public address, or port 443 forwarded to it):

```sh
sudo install target/release/tc-control /usr/local/bin/
sudo cp packaging/tc-control.service /etc/systemd/system/
sudo systemctl enable --now tc-control
sudo TC_STATE_DIR=/var/lib/tailconnect-control tc-control fingerprint   # note the TLS fingerprint
sudo TC_STATE_DIR=/var/lib/tailconnect-control tc-control authkey create --reusable --expires-hours 24
```

On **every machine**:

```sh
sudo install target/release/tcd target/release/tc /usr/local/bin/
sudo cp packaging/tcd.service /etc/systemd/system/
sudo systemctl enable --now tcd
sudo tc up --server hub.example.com --tls-fingerprint <FINGERPRINT> --authkey <KEY>
tc status
ping bravo            # MagicDNS
```

With a trusted certificate (`tc-control serve --tls-cert fullchain.pem --tls-key privkey.pem`), leave out `--tls-fingerprint`.

## Commands

| Command | What it does |
|---|---|
| `tc-control serve [--listen [::]:443] [--domain tc.internal] [--tls-cert F --tls-key F] [--tls-name NAME…]` | Run the hub |
| `tc-control fingerprint` | Print the TLS fingerprint and SSH host key |
| `tc-control authkey create [--reusable] [--expires-hours N]` / `list` / `revoke ID` | Pre-auth keys |
| `tc-control nodes list` / `remove NAME` / `rename NAME NEW` | Machines (the running hub picks changes up within a second; a removed machine is cut off) |
| `tcd [--tun tc0] [--direct-port 7443] [--mtu 1400] [--no-dns] [--hostname NAME]` | Machine daemon (needs root or `CAP_NET_ADMIN`) |
| `tc up [--server HOST[:PORT]] [--authkey KEY] [--tls-fingerprint FP]` | Join or reconnect |
| `tc down` / `tc logout` | Disconnect / disconnect and forget the server |
| `tc status [--json]`, `tc ip [NAME]` | Show this machine, its peers and the path to each (`direct` or `hub`) |

`--state-dir` (`TC_STATE_DIR`) and `--socket` (`TC_SOCKET`) change where things are kept.

## Tests

```sh
cargo test                    # unit tests: framing, DNS, packets, database, keys, e2e crypto
cargo build && tests/e2e-netns.sh   # end to end, no root needed
```

`tests/e2e-netns.sh` runs a hub and two machines in unprivileged user and network namespaces, linked by a veth pair. It checks:

- joining, and refusal of a bad auth key or a wrong TLS fingerprint;
- ping and a 10 MiB TCP transfer through the hub, with end-to-end sessions up both ways;
- MagicDNS;
- direct SSH paths after a restart;
- that a machine removed by the operator is cut off.

## Status

Done (Linux MVP):

- the hub on 443 with SSH inside TLS, registration with auth keys, address allocation, a pushed network map, and relaying with source checks;
- `tcd` with a TUN device, direct SSH paths with fallback to the hub, MagicDNS (A and PTR records), the local API and the `tc` CLI;
- end-to-end encryption of relayed traffic (Noise IK per pair of machines, rekeying, replay protection);
- an admin CLI, systemd units, and unit and end-to-end tests.

Roadmap toward parity with the Go TailConnect:

1. Accounts (tenants), one-way sharing, tag-based access rules with an in-tunnel packet filter
2. Built-in Let's Encrypt; the web portal served on the same port 443 (selected by ALPN)
3. IPv6 inside the tunnel, exit nodes
4. Key expiry, machine approval, ephemeral machines
5. Windows (Wintun) and Android (VpnService) clients
