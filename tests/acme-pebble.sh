#!/usr/bin/env bash
# End-to-end test of built-in Let's Encrypt against Pebble, Let's Encrypt's
# test ACME server, in unprivileged user + network namespaces (no root, no
# internet exposure). Checks:
#   * TLS-ALPN-01 on the hub's own port 443, beside SSH and the portal;
#   * HTTP-01 on port 80 with HTTPS on 8443, and port 80 redirecting;
#   * DNS-01 through DuckDNS (a fake DuckDNS API writing TXT records into
#     pebble-challtestsrv, which Pebble and the hub's propagation check query);
#   * renewal of 90-second certificates after two thirds of their lifetime,
#     without a restart;
#   * the saved certificate being reused after a restart.
#
# Pebble isn't bundled. Get pebble and pebble-challtestsrv for linux-amd64
# from https://github.com/letsencrypt/pebble/releases (check the SHA-256
# digests shown there), then:
#
#   cargo build
#   PEBBLE=/path/to/pebble CHALLTESTSRV=/path/to/pebble-challtestsrv tests/acme-pebble.sh
set -u

if [[ "${TC_ACME_INNER:-}" != 1 ]]; then
    : "${PEBBLE:?set PEBBLE to the pebble binary}" "${CHALLTESTSRV:?set CHALLTESTSRV to the pebble-challtestsrv binary}"
    exec env TC_ACME_INNER=1 unshare -Urn --fork "$0" "$@"
fi
ROOT=$(cd "$(dirname "$0")/.." && pwd)
B=${BIN:-$ROOT/target/debug}
T=$(mktemp -d "${TMPDIR:-/tmp}/tc-acme.XXXXXX")
cp "$ROOT/tests/fake_duckdns.py" "$T/"
cleanup() { kill $(jobs -p) 2>/dev/null; sleep 0.3; [[ "${KEEP:-}" == 1 ]] && echo "logs in $T" || rm -rf "${T:?}"; }
trap cleanup EXIT
cd "$T"; ip link set lo up
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; for f in "$T"/*.log; do echo "--- $f"; sed 's/\x1b\[[0-9;]*m//g' "$f" | tail -15; done; exit 1; }
waitlog() { # file pattern count seconds
    for _ in $(seq $(($4 * 2))); do [[ $(grep -c "$2" "$1" 2>/dev/null) -ge $3 ]] && return 0; sleep 0.5; done; return 1
}
# A CA for Pebble's own HTTPS endpoint.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=test-ca -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -keyout pb.key -out pb.csr 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\n' > ext.cnf
openssl x509 -req -in pb.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out pb.pem 2>/dev/null
cat > pebble.json <<JSON
{"pebble": {"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
  "certificate": "pb.pem", "privateKey": "pb.key", "httpPort": 80, "tlsPort": 443,
  "ocspResponderURL": "", "externalAccountBindingRequired": false,
  "retryAfter": {"authz": 1, "order": 1}, "keyAlgorithm": "ecdsa",
  "profiles": {"default": {"description": "90-second certificates", "validityPeriod": 90}}}}
JSON
"$CHALLTESTSRV" -defaultIPv4 127.0.0.1 -defaultIPv6 "" \
    -dnsserver 127.0.0.1:8053 -management 127.0.0.1:8055 -http01 "" -https01 "" -tlsalpn01 "" -doh "" > challtestsrv.log 2>&1 &
PEBBLE_VA_NOSLEEP=1 PEBBLE_AUTHZREUSE=0 "$PEBBLE" -config pebble.json -dnsserver 127.0.0.1:8053 > pebble.log 2>&1 &
python3 fake_duckdns.py 2> duckdns.log &
sleep 2
curl -s --cacert ca.pem https://127.0.0.1:15000/roots/0 > root.pem; grep -q BEGIN root.pem || fail "no Pebble root"
ACME="--acme-directory https://127.0.0.1:14000/dir --acme-ca-root $T/ca.pem --acme-email test@example.com"
# A: TLS-ALPN-01 on the hub's own port 443.
TC_STATE_DIR=A $B/tc-control serve --listen 127.0.0.1:443 --acme-domain hub.test $ACME > A.log 2>&1 &
HUB_A=$!
# B: HTTP-01 on port 80, HTTPS on 8443.
TC_STATE_DIR=Bh $B/tc-control serve --listen 127.0.0.1:8443 --acme-http-listen 127.0.0.1:80 --acme-domain web.test $ACME > B.log 2>&1 &
# C: DNS-01 through (fake) DuckDNS, HTTPS on 9443: no port for the CA at all.
TC_DUCKDNS_TOKEN=test-token TC_DUCKDNS_URL=http://127.0.0.1:8099/update TC_DUCKDNS_NS=127.0.0.1:8053 \
    TC_STATE_DIR=C $B/tc-control serve --listen 127.0.0.1:9443 --acme-domain myhub.duckdns.org --acme-dns duckdns $ACME > C.log 2>&1 &

trusted() { # name port: the hub serves a certificate that chains to Pebble's root, for that name
    curl -s -o /dev/null -w '%{http_code}' --cacert root.pem --resolve "$1:$2:127.0.0.1" "https://$1:$2/" 2>/dev/null
}
serial() { echo | openssl s_client -connect 127.0.0.1:$2 -servername $1 2>/dev/null | openssl x509 -noout -serial; }

waitlog A.log "got a certificate" 1 60 || fail "A: no certificate (TLS-ALPN-01)"
[[ $(trusted hub.test 443) == 200 ]] || fail "A: certificate not trusted"
pass "TLS-ALPN-01 on :443 (same port as SSH and the portal): certificate issued, served, trusted for hub.test"
waitlog B.log "got a certificate" 1 60 || fail "B: no certificate (HTTP-01)"
[[ $(trusted web.test 8443) == 200 ]] || fail "B: certificate not trusted"
[[ $(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: web.test' http://127.0.0.1/portal) == "301 https://web.test/portal" ]] || fail "B: port 80 doesn't redirect"
pass "HTTP-01 on :80 with HTTPS on :8443: issued and trusted; port 80 redirects to HTTPS"
waitlog C.log "got a certificate" 1 90 || fail "C: no certificate (DNS-01)"
[[ $(trusted myhub.duckdns.org 9443) == 200 ]] || fail "C: certificate not trusted"
grep -q "DuckDNS serves the TXT record" C.log || fail "C: didn't wait for the TXT record"
pass "DNS-01 through DuckDNS (fake API, real DNS check): issued and trusted; waited for the TXT record"

S1=$(serial hub.test 443)
waitlog A.log "got a certificate" 2 120 || fail "A: no renewal of the 90-second certificate"
sleep 1
S2=$(serial hub.test 443)
[[ "$S1" != "$S2" && $(trusted hub.test 443) == 200 ]] || fail "A: renewed certificate not served ($S1 / $S2)"
pass "renewal after two thirds of the lifetime, swapped in without a restart ($S1 -> $S2)"

kill $HUB_A; sleep 1
TC_STATE_DIR=A $B/tc-control serve --listen 127.0.0.1:443 --acme-domain hub.test $ACME > A2.log 2>&1 &
waitlog A2.log "acme: certificate for hub.test expires" 1 20 || fail "A: saved certificate not loaded on restart"
grep -q "getting a certificate for" A2.log && fail "A: fetched a new certificate on restart instead of using the saved one"
[[ $(trusted hub.test 443) == 200 ]] || fail "A: saved certificate not served after restart"
pass "restart: the saved certificate is loaded and served"
echo "ALL PASSED"
