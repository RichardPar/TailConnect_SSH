#!/usr/bin/env bash
# End-to-end test without root: runs in unprivileged user + network namespaces.
#
#   ns A: tc-control on :443, machine "alpha" (account richard)
#   ns B: machine "bravo" (richard), reaching the hub over veth 10.99.0.0/24
#   ns C: machine "charlie" (alice), reaching the hub over veth 10.98.0.0/24
#
#   ns I: "the internet", linked only to ns A: a web address (203.0.113.10,
#         2001:db8:1::10) and a DNS server. alpha can be the exit node to it.
#
# Each machine needs its own namespace: two TUN devices in one namespace
# would both route 100.64.0.0/10, and traffic would leave through either.
#
# Checks: joining, refusal of bad keys and TLS pins, ping/TCP/MagicDNS over
# the hub with end-to-end encryption, account isolation, a one-way share
# limited to some ports, access rules, suspending an account, direct SSH
# paths (with the packet filter still enforced on them), removal, and the web
# portal on the same port: sign-in, keys, tags, host and origin checks,
# sign-up with approval.
#
# Usage: tests/e2e-netns.sh   (after `cargo build`; BIN=target/release to test that)
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
    # Anything else started for this run has $W on its command line.
    pkill -9 -f -- "$W" 2>/dev/null || true
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

unshare -n --fork --kill-child sleep infinity &
CPID=$!
PIDS+=("$CPID")
sleep 0.3
inC() { nsenter -n -t "$CPID" "$@"; }
ip link add vA2 type veth peer name vC netns "$CPID"
ip addr add 10.98.0.1/24 dev vA2
ip link set vA2 up
inC ip link set lo up
inC ip addr add 10.98.0.2/24 dev vC
inC ip link set vC up

unshare -n --fork --kill-child sleep infinity &
IPID=$!
PIDS+=("$IPID")
sleep 0.3
inI() { nsenter -n -t "$IPID" "$@"; }
ip link add vA3 type veth peer name vI netns "$IPID"
ip addr add 203.0.113.1/24 dev vA3
ip -6 addr add 2001:db8:1::1/64 dev vA3 nodad
ip link set vA3 up
inI ip link set lo up
inI ip addr add 203.0.113.10/24 dev vI
inI ip -6 addr add 2001:db8:1::10/64 dev vI nodad
inI ip link set vI up
inI ip route add default via 203.0.113.1
inI ip -6 route add default via 2001:db8:1::1
# The web: a TCP server answering with the address it sees the client at.
for a in 203.0.113.10 2001:db8:1::10; do
    nsenter -n -t "$IPID" python3 -c "
import socket,sys; fam = socket.AF_INET6 if ':' in '$a' else socket.AF_INET
s=socket.socket(fam); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('$a', 8080)); s.listen(8)
while True:
    c,peer=s.accept(); c.sendall(peer[0].encode()); c.close()
# $W" &
    PIDS+=("$!")
done
nsenter -n -t "$IPID" python3 "$ROOT/tests/tiny_dns.py" 203.0.113.10 web.example=203.0.113.10 &
PIDS+=("$!")

# Hub, with two accounts.
ctl() { TC_STATE_DIR="$W/hub" "$BIN/tc-control" "$@"; }
TC_STATE_DIR="$W/hub" "$BIN/tc-control" serve --listen 0.0.0.0:443 --domain tc.internal --tls-name hub.test >"$W/hub.log" 2>&1 &
PIDS+=("$!")
wait_for 40 grep -q "listening on" "$W/hub.log" || fail "hub did not start"
FP=$(ctl fingerprint | awk '/TLS fingerprint/ {print $3}')
PW="correct horse battery staple"
echo "$PW" | ctl accounts create richard --operator --password >/dev/null
ctl accounts create alice >/dev/null
KR=$(ctl authkey create --account richard --reusable)
pass "hub up, accounts richard (operator) and alice"

# ---- Web portal on the same port ----
JAR="$W/cookies"
curl_() { curl -sk --max-time 5 "$@"; }
apic() { # METHOD PATH [JSON]
    if [[ $# -ge 3 ]]; then
        curl_ -b "$JAR" -c "$JAR" -X "$1" -H 'Content-Type: application/json' -d "$3" "https://127.0.0.1$2"
    else
        curl_ -b "$JAR" -c "$JAR" -X "$1" "https://127.0.0.1$2"
    fi
}
curl_ https://127.0.0.1/ | grep -q "<title>TailConnect</title>" || fail "portal page not served on :443"
[[ $(curl_ -o /dev/null -w '%{http_version}' https://127.0.0.1/) == 1.1 ]] || fail "portal not on HTTP/1.1"
[[ $(curl_ -o /dev/null -w '%{http_code}' -H 'Host: evil.example' https://127.0.0.1/) == 421 ]] || fail "unknown host name accepted"
apic POST /api/login '{"name":"richard","password":"wrong password!"}' | grep -q "wrong name or password" || fail "wrong password accepted"
apic POST /api/login "{\"name\":\"richard\",\"password\":\"$PW\"}" | grep -q '"ok":true' || fail "portal sign-in"
apic GET /api/me | grep -q '"operator":true' || fail "portal /me"
[[ $(curl_ -b "$JAR" -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H 'Origin: https://evil.example' \
    -d '{"expires_hours":1}' https://127.0.0.1/api/keys) == 403 ]] || fail "cross-site write accepted"
KA=$(apic POST /api/keys '{"account":"alice","expires_hours":1}' | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')
[[ $KA == tckey-* ]] || fail "portal didn't create a key for alice"
R=$(curl_ -X POST -H 'Content-Type: application/json' -d "{\"name\":\"mallory\",\"password\":\"$PW\"}" https://127.0.0.1/api/signup)
[[ $R == *pending* ]] || fail "sign-up should wait for approval: $R"
ctl accounts list | grep -q "mallory.*pending" || fail "pending account not in the database"
pass "portal on :443 beside SSH: sign-in, key for alice, host/origin checks, sign-up pending approval"

# ---- Admin HTTP API with a bearer token ----
TOK=$(ctl admin-token 2>/dev/null)
bear() { curl_ -H "Authorization: Bearer $TOK" "$@"; }
bear https://127.0.0.1/api/v1/status | grep -q '"operator":true' || fail "API: status with the admin token"
RID=$(bear -H 'Content-Type: application/json' -d '{"account":"alice","from":"*","to":"*","ports":"icmp"}' https://127.0.0.1/api/v1/rules | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
[[ -n $RID ]] || fail "API: creating a rule"
[[ $(bear -o /dev/null -w '%{http_code}' -X DELETE https://127.0.0.1/api/v1/rules/$RID) == 200 ]] || fail "API: DELETE with a bearer token"
[[ $(curl_ -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer tc-admin-wrong' https://127.0.0.1/api/v1/machines) == 401 ]] || fail "API: wrong token accepted"
pass "admin HTTP API: bearer token from tc-control admin-token, /api/v1 status, rule created and deleted, wrong token refused"

NS_alpha=A NS_bravo=B NS_charlie=C NS_delta=B
start_tcd() { # name direct_port
    local name=$1 port=$2 ns_var="NS_$1"
    # Traffic reports every 2 seconds instead of 30, so the test needn't wait.
    local cmd=(env TC_TRAFFIC_INTERVAL=2 "$BIN/tcd" --state-dir "$W/$name" --socket "$name.sock" --tun "tc-$name"
        --hostname "$name" --direct-port "$port" --no-dns --exit-dns 203.0.113.10)
    # Not through a shell function: $! must be the process itself (nsenter
    # execs into tcd), or cleanup would leave it running.
    local pre
    pre=$(ns_prefix "${!ns_var}")
    $pre "${cmd[@]}" >>"$W/$name.log" 2>&1 &
    PIDS+=("$!")
    wait_for 20 test -S "$name.sock" || fail "tcd $name did not start"
}
stop_tcd() {
    tc_ "$1" down >/dev/null || true
    pkill -f "tcd --state-dir $W/$1 " || true
    sleep 0.3
    rm -f "$1.sock"
}
tc_() { local name=$1; shift; "$BIN/tc" --socket "$name.sock" "$@"; }
ns_prefix() { # A|B|C -> command prefix entering that namespace
    case $1 in
        B) echo "nsenter -n -t $BPID" ;;
        C) echo "nsenter -n -t $CPID" ;;
        I) echo "nsenter -n -t $IPID" ;;
        *) echo "" ;;
    esac
}
on() { # machine cmd...  (run in that machine's namespace)
    local ns_var="NS_$1" pre; shift
    pre=$(ns_prefix "${!ns_var}")
    $pre "$@"
}
status_has() { tc_ "$1" status | grep -q -- "$2"; }
wait_status() { # machine regex message
    wait_for 20 status_has "$1" "$2" || { tc_ "$1" status; fail "$3"; }
}
wait_status_not() {
    wait_for 20 sh -c "! '$BIN/tc' --socket '$1.sock' status | grep -q -- '$2'" || { tc_ "$1" status; fail "$3"; }
}
can_ping() { on "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1 || on "$1" ping -c 2 -W 1 "$2" >/dev/null 2>&1; }
cant_ping() { ! on "$1" ping -c 2 -W 1 "$2" >/dev/null 2>&1; }
# A TCP server on machine $1, address $2, port $3, answering "ok" to every connection.
serve_tcp() {
    local ns_var="NS_$1" pre
    pre=$(ns_prefix "${!ns_var}")
    $pre python3 -c "
import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$2', $3)); s.listen(8)
while True:
    c,_=s.accept(); c.sendall(b'ok'); c.close()
# $W" &
    PIDS+=("$!")
}
can_tcp() { # from-machine ip port
    on "$1" python3 -c "
import socket,sys; s=socket.create_connection(('$2', $3), timeout=3); sys.exit(0 if s.recv(2)==b'ok' else 1)" 2>/dev/null
}

# ---- Joining ----
start_tcd alpha 0
start_tcd bravo 0
start_tcd charlie 0
start_tcd delta 0
tc_ alpha up --server 127.0.0.1:443 --tls-fingerprint "$FP" --authkey "$KR" >/dev/null || fail "alpha up"
tc_ bravo up --server 10.99.0.1 --tls-fingerprint "$FP" --authkey "$KR" >/dev/null || fail "bravo up"
tc_ charlie up --server 10.98.0.1 --tls-fingerprint "$FP" --authkey "$KA" >/dev/null || fail "charlie up"
A=$(tc_ alpha ip); B=$(tc_ bravo ip); C=$(tc_ charlie ip)
pass "joined: alpha=$A bravo=$B (richard), charlie=$C (alice, with the portal's key)"
ONLINE=$(apic GET /api/machines | python3 -c "import json,sys; print(sorted(m['name']+'.'+m['account'] for m in json.load(sys.stdin) if m['online']))")
[[ $ONLINE == "['alpha.richard', 'bravo.richard', 'charlie.alice']" ]] || fail "portal's online machines: $ONLINE"

if tc_ delta up --server 10.99.0.1 --tls-fingerprint "$FP" --authkey "$KA" 2>"$W/err"; then fail "used single-use key accepted"; fi
grep -q "already been used" "$W/err" || fail "unexpected error: $(cat "$W/err")"
if tc_ delta up --server 10.99.0.1 --tls-fingerprint "$(printf '0%.0s' {1..64})" --authkey "$KR" 2>"$W/err"; then fail "wrong TLS pin accepted"; fi
stop_tcd delta
pass "used single-use key and wrong TLS fingerprint refused"

# ---- Hub path, E2E, DNS ----
wait_status alpha "bravo.richard.*hub" "alpha doesn't see bravo"
can_ping alpha "$B" || fail "ping alpha -> bravo over hub"
can_ping bravo "$A" || fail "ping bravo -> alpha over hub"
wait_status alpha "bravo.richard.*hub, e2e" "no e2e session alpha -> bravo"
wait_status bravo "alpha.richard.*hub, e2e" "no e2e session bravo -> alpha"
pass "ping both ways through the hub, end-to-end encrypted"

for q in bravo.richard.tc.internal bravo bravo.richard; do
    ANS=$(dig +short +time=2 +tries=2 @100.100.100.100 "$q" A)
    [[ "$ANS" == "$B" ]] || fail "MagicDNS $q -> '$ANS'"
done
pass "MagicDNS: bravo.richard.tc.internal, bravo.richard, bravo"

serve_tcp bravo "$B" 9000
sleep 0.5
can_tcp alpha "$B" 9000 || fail "TCP alpha -> bravo"
pass "TCP over the hub"

# ---- Traffic reports ----
python3 -c "
import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(200): s.sendto(b'x'*1000, ('$B', 9999))"
wait_for 20 status_has alpha "bravo.richard.*tx [0-9.]*[KM]iB" || { tc_ alpha status; fail "tc status shows no traffic counts"; }
traffic_ok() {
    apic GET /api/machines | python3 -c "
import json,sys; m=[m for m in json.load(sys.stdin) if m['name']=='alpha'][0]
t=m['traffic']; sys.exit(0 if t and t['tx'] >= 200000 else 1)"
}
wait_for 20 traffic_ok || fail "portal shows no traffic for alpha: $(apic GET /api/machines)"
AID=$(apic GET /api/machines | python3 -c "import json,sys; print([m['id'] for m in json.load(sys.stdin) if m['name']=='alpha'][0])")
apic GET "/api/machines/$AID/traffic" | python3 -c "
import json,sys; r=json.load(sys.stdin); p={x['peer']: x for x in r['peers']}
assert r['reported'] and p['bravo.richard']['tx'] >= 200000, r" || fail "traffic breakdown for alpha"
pass "traffic: counted by tcd, shown in tc status, reported to the portal with a per-peer breakdown"

# ---- Isolation ----
status_has alpha charlie && fail "alpha sees charlie (another account)"
[[ $(tc_ charlie status | grep -c 100.64) == 1 ]] || { tc_ charlie status; fail "charlie sees other accounts' machines"; }
cant_ping charlie "$A" || fail "charlie reached alpha without a share"
cant_ping alpha "$C" || fail "alpha reached charlie"
ANS=$(on charlie dig +short +time=2 +tries=1 @100.100.100.100 alpha.richard.tc.internal A)
[[ -z "$ANS" ]] || fail "charlie resolves alpha.richard before any share"
pass "accounts are isolated (maps, DNS, traffic)"

# ---- One-way share, limited ports ----
serve_tcp alpha "$A" 9000
serve_tcp alpha "$A" 9001
SID=$(ctl shares create alpha.richard alice icmp,tcp:9000 | grep -o 'share [0-9]*' | awk '{print $2}')
sleep 2
status_has charlie alpha && fail "pending share already in effect"
ctl shares accept "$SID" >/dev/null
wait_status charlie "alpha.richard.*shared with you" "share not visible to charlie"
wait_status alpha "charlie.alice.*has access to this machine on tcp:9000,icmp" "share not visible on alpha"
can_ping charlie "$A" || fail "charlie can't ping shared alpha"
can_tcp charlie "$A" 9000 || fail "charlie can't reach shared port 9000"
can_tcp charlie "$A" 9001 && fail "charlie reached unshared port 9001"
cant_ping alpha "$C" || fail "shared alpha opened a connection to charlie"
status_has bravo charlie && fail "bravo (not shared) sees charlie"
ANS=$(on charlie dig +short +time=2 +tries=2 @100.100.100.100 alpha.richard A)
[[ "$ANS" == "$A" ]] || fail "charlie resolves alpha.richard -> '$ANS'"
wait_status charlie "filter: [0-9]* packets dropped" "charlie's filter didn't count alpha's pings"
pass "share: charlie -> alpha on icmp,tcp:9000 only; alpha can't open connections back; bravo not exposed"

ctl shares ports "$SID" tcp:9001 >/dev/null
wait_status alpha "charlie.alice.*on tcp:9001" "share ports not updated"
can_tcp charlie "$A" 9001 || fail "new share port 9001 not reachable"
can_tcp charlie "$A" 9000 && fail "old share port 9000 still reachable"
pass "share ports changed live"

# ---- Suspension ----
ctl accounts suspend alice >/dev/null
wait_status charlie "notice: account alice is suspended" "charlie not told about suspension"
wait_status_not alpha charlie "alpha still sees suspended charlie"
cant_ping charlie "$A" || fail "suspended charlie reached alpha"
ctl accounts activate alice >/dev/null
wait_status charlie "alpha.richard.*shared with you" "share not restored after activation"
can_tcp charlie "$A" 9001 || fail "charlie can't reach alpha after activation"
pass "suspending alice cuts charlie off; activating restores it"

# ---- Access rules within richard ----
AID=$(apic GET /api/machines | python3 -c "import json,sys; print([m['id'] for m in json.load(sys.stdin) if m['name']=='alpha'][0])")
apic POST "/api/machines/$AID/tags" '{"tags":"staff"}' | grep -q staff || fail "tagging through the portal"
ctl nodes tag bravo.richard server >/dev/null
RID=$(ctl rules add --account richard tag:staff tag:server tcp:9000 | grep -o 'rule [0-9]*' | awk '{print $2}')
wait_status bravo "alpha.richard.*rules: can open tcp:9000 here" "rule not in bravo's map"
wait_status alpha "bravo.richard.*rules: can't open connections here" "rule not in alpha's map"
can_tcp alpha "$B" 9000 || fail "rule doesn't allow alpha -> bravo:9000"
cant_ping alpha "$B" || fail "rule should block ping alpha -> bravo"
cant_ping bravo "$A" || fail "rule should block bravo -> alpha"
ctl rules delete "$RID" >/dev/null
wait_status_not bravo "rules:" "deleting the last rule didn't restore everything"
can_ping bravo "$A" || fail "ping bravo -> alpha after deleting the rule"
pass "rules: tag:staff -> tag:server on tcp:9000 only; deleting the rule restores everything"

# ---- IPv6 inside the tunnel ----
A6=$(python3 -c "import ipaddress; print(ipaddress.IPv6Address(int(ipaddress.IPv6Address('fd74:6373:7368::')) + int(ipaddress.IPv4Address('$A'))))")
B6=$(python3 -c "import ipaddress; print(ipaddress.IPv6Address(int(ipaddress.IPv6Address('fd74:6373:7368::')) + int(ipaddress.IPv4Address('$B'))))")
on bravo ip -6 addr show dev tc-bravo | grep -q "$B6" || fail "bravo has no tunnel IPv6 address $B6"
wait_for 10 can_ping alpha "$B6" || fail "ping6 alpha -> bravo ($B6)"
can_ping bravo "$A6" || fail "ping6 bravo -> alpha ($A6)"
ANS=$(dig +short +time=2 +tries=2 @100.100.100.100 bravo AAAA)
[[ "$ANS" == "$B6" ]] || fail "MagicDNS AAAA bravo -> '$ANS'"
pass "IPv6 inside the tunnel: addresses derived from IPv4, ping6 both ways, MagicDNS AAAA"

# ---- Exit nodes ----
web() { # machine address: what the web server sees us as
    local ns_var="NS_$1" pre; pre=$(ns_prefix "${!ns_var}")
    $pre python3 -c "
import socket,sys; s=socket.create_connection(('$2', 8080), timeout=3); print(s.recv(100).decode())" 2>/dev/null
}
[[ -z "$(web bravo 203.0.113.10)" ]] || fail "bravo reaches the internet without an exit node"
ctl nodes exit-node alpha.richard on >/dev/null
wait_status alpha "exit node: this machine forwards" "alpha didn't become an exit node"
wait_status bravo "alpha.richard.*exit node" "bravo isn't offered alpha as exit node"
tc_ bravo up --exit-node alpha >/dev/null || fail "bravo up --exit-node alpha"
wait_status bravo "internet traffic and DNS go through alpha.richard" "bravo not using alpha"
SEEN=$(web bravo 203.0.113.10)
[[ "$SEEN" == 203.0.113.1 ]] || fail "IPv4 through the exit node: web sees '$SEEN'"
SEEN6=$(web bravo 2001:db8:1::10)
[[ "$SEEN6" == 2001:db8:1::1 ]] || fail "IPv6 through the exit node: web sees '$SEEN6'"
ANS=$(on bravo dig +short +time=2 +tries=2 @100.100.100.100 web.example A)
[[ "$ANS" == 203.0.113.10 ]] || fail "DNS through the exit node: web.example -> '$ANS'"
ANS=$(on bravo dig +short +time=2 +tries=2 @100.100.100.100 alpha A)
[[ "$ANS" == "$A" ]] || fail "MagicDNS names still answered locally while using an exit node"
on bravo ip rule | grep -q "lookup 7443" || fail "no policy routing rule on bravo"
pass "exit node: bravo's IPv4 and IPv6 internet traffic leaves through alpha (NAT), DNS resolved there"

if tc_ charlie up --exit-node alpha.richard 2>"$W/err"; then fail "charlie (alice) may use richard's exit node"; fi
grep -q "doesn't offer\|isn't in the network map" "$W/err" || fail "unexpected: $(cat "$W/err")"
pass "an exit node serves only its own account"

ctl nodes exit-node alpha.richard off >/dev/null
wait_status bravo "goes direct" "bravo didn't fall back when alpha stopped being an exit node"
[[ -z "$(web bravo 203.0.113.10)" ]] || fail "bravo still reaches the internet after the role was turned off"
on bravo ip rule | grep -q "lookup 7443" && fail "policy routing left behind on bravo"
wait_status_not alpha "this machine forwards" "alpha still forwarding"
ctl nodes exit-node alpha.richard on >/dev/null
wait_status bravo "internet traffic and DNS go through alpha.richard" "bravo didn't return to alpha"
pass "turning the role off: bravo falls back to direct, and returns when it's back on"

# ---- Direct paths (filter still applies) ----
for n in alpha bravo charlie; do stop_tcd "$n"; done
start_tcd alpha 7443
start_tcd bravo 7443
start_tcd charlie 7443
for n in alpha bravo charlie; do tc_ "$n" up >/dev/null || fail "$n up (rejoin)"; done
[[ "$(tc_ alpha ip)" == "$A" ]] || fail "alpha changed address on rejoin"
wait_for 60 status_has alpha 'bravo.richard *direct' || { tc_ alpha status; fail "no direct path alpha->bravo"; }
wait_for 60 status_has charlie 'alpha.richard *direct' || { tc_ charlie status; fail "no direct path charlie->alpha"; }
can_ping alpha "$B" || fail "ping alpha -> bravo direct"
can_ping bravo "$A" || fail "ping bravo -> alpha direct"
can_tcp charlie "$A" 9001 || fail "charlie -> alpha:9001 over direct path"
can_tcp charlie "$A" 9000 && fail "charlie reached unshared alpha:9000 over direct path"
cant_ping alpha "$C" || fail "alpha opened a connection to charlie over direct path"
pass "direct SSH paths; share limits still enforced on them"
wait_status bravo "internet traffic and DNS go through alpha.richard" "bravo's exit node choice not kept across a restart"
[[ "$(web bravo 203.0.113.10)" == 203.0.113.1 ]] || fail "exit node over the direct path"
pass "exit node choice kept across restarts; works over the direct path too"

# ---- Removal ----
ctl nodes remove bravo.richard >/dev/null
wait_status_not alpha bravo "bravo still in alpha's map"
cant_ping alpha "$B" || fail "removed machine still reachable"
wait_status bravo needs-login "bravo not logged out"
pass "removed machine is cut off and needs login"

echo "ALL PASSED"
