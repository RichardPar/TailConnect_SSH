#!/usr/bin/env bash
# End-to-end test without root: runs in unprivileged user + network namespaces.
#
#   ns A: tc-control on :443, machine "alpha"
#   ns B: machine "bravo", reaching the hub over a veth pair (10.99.0.0/24)
#
# Checks: join with an auth key, refusal of bad keys and TLS pins, ping and
# TCP both ways over the hub with end-to-end encryption, MagicDNS, direct SSH sessions between the
# machines after a restart, and removal of a machine by the operator.
#
# Usage: tests/e2e-netns.sh   (after `cargo build`)
set -euo pipefail

if [[ "${TC_E2E_INNER:-}" != 1 ]]; then
    exec env TC_E2E_INNER=1 unshare -Urn --fork "$0" "$@"
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/debug}
W=$(mktemp -d "${TMPDIR:-/tmp}/tc-e2e.XXXXXX")
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    sleep 0.5
    for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done
    pkill -9 -P $$ 2>/dev/null || true
    if [[ "${KEEP:-}" != 1 ]]; then rm -rf "$W"; else echo "logs in $W"; fi
}
trap cleanup EXIT
# Unix socket paths are limited to 108 bytes: work in $W with relative paths.
cd "$W"

pass() { echo "PASS: $*"; }
fail() {
    echo "FAIL: $*"
    for f in "$W"/*.log; do echo "--- $f"; tail -n 30 "$f"; done
    exit 1
}
wait_for() { # tries cmd...
    local n=$1; shift
    for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
    return 1
}

ip link set lo up

# Namespace B, connected by veth.
unshare -n --fork --kill-child sleep infinity &
BPID=$!
PIDS+=("$BPID")
sleep 0.3
inB() { nsenter -n -t "$BPID" "$@"; }
ip link add vA type veth peer name vB netns "$BPID"
ip addr add 10.99.0.1/24 dev vA
ip link set vA up
inB ip link set lo up
inB ip addr add 10.99.0.2/24 dev vB
inB ip link set vB up

# Hub.
export TC_STATE_DIR="$W/hub"
"$BIN/tc-control" serve --listen 0.0.0.0:443 --domain tc.internal --tls-name hub.test >"$W/hub.log" 2>&1 &
PIDS+=("$!")
wait_for 40 grep -q "listening on" "$W/hub.log" || fail "hub did not start"
FP=$("$BIN/tc-control" fingerprint | awk '/TLS fingerprint/ {print $3}')
KEY=$("$BIN/tc-control" authkey create --reusable)
unset TC_STATE_DIR
pass "hub up, TLS fingerprint $FP"

start_tcd() { # name ns direct_port
    local name=$1 ns=$2 port=$3
    local cmd=("$BIN/tcd" --state-dir "$W/$name" --socket "$name.sock" --tun "tc-$name"
        --hostname "$name" --direct-port "$port" --no-dns)
    if [[ $ns == B ]]; then inB "${cmd[@]}" >>"$W/$name.log" 2>&1 & else "${cmd[@]}" >>"$W/$name.log" 2>&1 & fi
    PIDS+=("$!")
    wait_for 20 test -S "$name.sock" || fail "tcd $name did not start"
}
tc_() { local name=$1; shift; "$BIN/tc" --socket "$name.sock" "$@"; }

# Phase 1: hub only.
start_tcd alpha A 0
start_tcd bravo B 0
tc_ alpha up --server 127.0.0.1:443 --tls-fingerprint "$FP" --authkey "$KEY" || fail "alpha up"
tc_ bravo up --server 10.99.0.1 --tls-fingerprint "$FP" --authkey "$KEY" || fail "bravo up"
A_IP=$(tc_ alpha ip)
B_IP=$(tc_ bravo ip)
pass "joined: alpha=$A_IP bravo=$B_IP"

# Bad auth key and a wrong pin are refused.
start_tcd charlie B 0
if tc_ charlie up --server 10.99.0.1 --tls-fingerprint "$FP" --authkey tckey-wrong 2>"$W/err"; then fail "bad auth key accepted"; fi
grep -q "invalid auth key" "$W/err" || fail "unexpected error: $(cat "$W/err")"
if tc_ charlie up --server 10.99.0.1 --tls-fingerprint "$(printf '0%.0s' {1..64})" --authkey "$KEY" 2>"$W/err"; then fail "wrong TLS pin accepted"; fi
pass "bad auth key and wrong TLS fingerprint refused"

wait_for 20 sh -c "'$BIN/tc' --socket alpha.sock status | grep -q 'bravo.*hub'" || fail "alpha doesn't see bravo"
ping -c 3 -W 2 "$B_IP" >/dev/null || fail "ping alpha -> bravo over hub"
inB ping -c 3 -W 2 "$A_IP" >/dev/null || fail "ping bravo -> alpha over hub"
pass "ping both ways through the hub"
tc_ alpha status | grep -q 'bravo.*hub, e2e' || fail "alpha has no end-to-end session with bravo"
tc_ bravo status | grep -q 'alpha.*hub, e2e' || fail "bravo has no end-to-end session with alpha"
pass "relayed traffic is end-to-end encrypted (Noise IK sessions up both ways)"

ANS=$(dig +short +time=2 +tries=2 @100.100.100.100 bravo.tc.internal A)
[[ "$ANS" == "$B_IP" ]] || fail "MagicDNS bravo.tc.internal -> '$ANS'"
ANS=$(inB dig +short +time=2 +tries=2 @100.100.100.100 alpha A)
[[ "$ANS" == "$A_IP" ]] || fail "MagicDNS alpha -> '$ANS'"
pass "MagicDNS resolves FQDN and short names"

# TCP over the tunnel.
inB python3 -c "
import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$B_IP', 9000)); s.listen(1); c,_=s.accept(); n=0
while True:
    d=c.recv(65536)
    if not d: break
    n+=len(d)
c.sendall(str(n).encode()); c.close()" &
sleep 0.5
GOT=$(python3 -c "
import socket,time; s=socket.create_connection(('$B_IP', 9000)); t=time.time()
b=b'x'*65536
for _ in range(160): s.sendall(b)
s.shutdown(socket.SHUT_WR); print(s.recv(100).decode(), round(10/(time.time()-t),1))")
[[ "${GOT%% *}" == $((160 * 65536)) ]] || fail "TCP transfer got '$GOT'"
pass "10 MiB TCP transfer over hub (${GOT##* } MiB/s)"

# Phase 2: restart with direct sessions enabled.
for n in alpha bravo; do tc_ "$n" down >/dev/null; done
pkill -f "tcd --state-dir $W/alpha" || true
pkill -f "tcd --state-dir $W/bravo" || true
sleep 0.5
rm -f alpha.sock bravo.sock
start_tcd alpha A 7443
start_tcd bravo B 7443
tc_ alpha up >/dev/null || fail "alpha up (rejoin)"
tc_ bravo up >/dev/null || fail "bravo up (rejoin)"
[[ "$(tc_ alpha ip)" == "$A_IP" ]] || fail "alpha changed address on rejoin"
wait_for 60 sh -c "'$BIN/tc' --socket alpha.sock status | grep -q 'bravo.*direct'" || fail "no direct path alpha->bravo"
wait_for 20 sh -c "'$BIN/tc' --socket bravo.sock status | grep -q 'alpha.*direct'" || fail "no direct path bravo->alpha"
ping -c 3 -W 2 "$B_IP" >/dev/null || fail "ping alpha -> bravo direct"
inB ping -c 3 -W 2 "$A_IP" >/dev/null || fail "ping bravo -> alpha direct"
pass "direct SSH path both ways, ping works"

# Remove a machine from the hub: it is cut off.
TC_STATE_DIR="$W/hub" "$BIN/tc-control" nodes remove bravo >/dev/null
wait_for 20 sh -c "'$BIN/tc' --socket alpha.sock status | grep -qv bravo && ! '$BIN/tc' --socket alpha.sock status | grep -q bravo" || fail "bravo still in alpha's map"
if ping -c 2 -W 1 "$B_IP" >/dev/null 2>&1; then fail "removed machine still reachable"; fi
wait_for 20 sh -c "'$BIN/tc' --socket bravo.sock status | grep -q needs-login" || fail "bravo not logged out"
pass "removed machine is cut off and needs login"

echo "ALL PASSED"
