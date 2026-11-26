#!/bin/sh
# Tests tcd's Android mode (tcd --bridge) on Linux, with no phone and no
# root: everything runs in an unprivileged user and network namespace.
#
#   cargo build && tests/android-bridge.sh
#
# tests/fake_android_app.py plays the app's VpnService: it answers tcd's
# requests for a VPN interface with a real TUN interface and reports the
# "underlying network", whose DNS server is tests/tiny_dns.py. It checks:
# joining a hub, the interface handed over with the right addresses, routes
# and DNS, MagicDNS answers from tcd, other names forwarded to the
# underlying network's server, an immediate reconnect when the device moves
# to another network (keeping the interface), and the interface closed on
# `tc down`.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/debug}
T=$(mktemp -d)
trap 'rm -rf "${T:?}"' EXIT
export ROOT BIN T

unshare -Urn sh -eu <<'EOF'
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- app:"; cat "$T/app.log"; echo "--- tcd:"; tail -20 "$T/tcd.log" | sed 's/\x1b\[[0-9;]*m//g'; exit 1; }
pass() { echo "PASS: $*"; }
ip link set lo up

python3 "$ROOT/tests/tiny_dns.py" 127.0.0.53 web.example=203.0.113.10 >/dev/null 2>&1 &
PIDS="$PIDS $!"

H=$T/hub
"$BIN/tc-control" accounts create test --state-dir "$H" >/dev/null
KEY=$("$BIN/tc-control" authkey create --account test --state-dir "$H" | grep -o 'tckey-[A-Za-z0-9_-]*')
"$BIN/tc-control" serve --state-dir "$H" --listen 127.0.0.1:18443 --no-portal >"$T/hub.log" 2>&1 &
PIDS="$PIDS $!"
timeout 10 sh -c "until grep -q 'TLS certificate SHA-256' '$T/hub.log'; do sleep 0.1; done" || fail "hub didn't start"
FP=$(sed -n 's/.*TLS certificate SHA-256: *\([0-9a-f]*\).*/\1/p' "$T/hub.log" | head -1)

N=$T/node
mkdir -p "$N"
RUST_LOG=info "$BIN/tcd" --state-dir "$N" --socket "$N/tcd.sock" --bridge "$N/bridge.sock" \
    --hostname phone --android-dns 127.0.0.53 --direct-port 7443 >"$T/tcd.log" 2>&1 &
PIDS="$PIDS $!"
python3 "$ROOT/tests/fake_android_app.py" "$N/bridge.sock" 127.0.0.53 "$T/move" >"$T/app.log" 2>&1 &
PIDS="$PIDS $!"

timeout 10 sh -c "until grep -q connected '$T/app.log'; do sleep 0.1; done" || fail "the app didn't connect to the bridge"
pass "the app connects to the bridge"

TC="$BIN/tc --socket $N/tcd.sock"
$TC up --server 127.0.0.1:18443 --tls-fingerprint "$FP" --authkey "$KEY" >/dev/null || fail "tc up"
timeout 15 sh -c "until grep -q '^tun ' '$T/app.log'; do sleep 0.1; done" || fail "no VPN interface request"
grep '^tun andr0 ' "$T/app.log" | grep -q '"100.64.0.1/32"' || fail "wrong addresses"
grep '^tun andr0 ' "$T/app.log" | grep -q '"100.64.0.0/10"' || fail "no tailnet route"
grep '^tun andr0 ' "$T/app.log" | grep -q '"DNS": \["100.100.100.100"\]' || fail "no MagicDNS server"
grep '^tun andr0 ' "$T/app.log" | grep -q '"Search": \["test.tc.internal"\]' || fail "no search domain"
pass "the VPN interface is requested with the right addresses, routes and DNS"
timeout 10 sh -c "until grep -q 'VPN interface up' '$T/tcd.log'; do sleep 0.1; done" || fail "tcd didn't take the interface"
ip -o addr show andr0 | grep -q 100.64.0.1 || fail "interface address"
pass "tcd takes the interface's file descriptor"

$TC status | grep -q running || fail "not running"
A=$(timeout 5 dig +short +tries=1 +time=3 @100.100.100.100 phone.test.tc.internal) || true
[ "$A" = 100.64.0.1 ] || fail "MagicDNS: phone.test.tc.internal = '$A'"
pass "MagicDNS names are answered by tcd, through the interface"
A=$(timeout 8 dig +short +tries=1 +time=5 @100.100.100.100 web.example) || true
[ "$A" = 203.0.113.10 ] || fail "forwarding: web.example = '$A'"
pass "other names are forwarded to the underlying network's DNS server"

touch "$T/move"
timeout 10 sh -c "until grep -q 'moved to another network; reconnecting' '$T/tcd.log'; do sleep 0.1; done" || fail "no reconnect on a new network"
timeout 15 sh -c "until [ \$(grep -c 'joined as phone.test' '$T/tcd.log') -ge 2 ]; do sleep 0.1; done" || fail "didn't join again after moving"
[ "$(grep -c '^tun ' "$T/app.log")" = 1 ] || fail "the VPN interface was replaced on a network change"
A=$(timeout 5 dig +short +tries=1 +time=3 @100.100.100.100 phone.test.tc.internal) || true
[ "$A" = 100.64.0.1 ] || fail "MagicDNS after moving: '$A'"
pass "moving to another network reconnects at once, keeping the VPN interface"

$TC down >/dev/null
timeout 10 sh -c "until grep -q '^close' '$T/app.log'; do sleep 0.1; done" || fail "no close on down"
timeout 10 sh -c "while ip link show andr0 >/dev/null 2>&1; do sleep 0.1; done" || fail "interface still there after down"
pass "tc down closes the interface"
EOF
