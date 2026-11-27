#!/bin/sh
# Download the latest TailConnect-SSH release from GitHub, check it, install
# it, and (for a machine) join the network. Asks for what it needs.
#
#   sh get.sh                 # asks: client (machine) or hub
#   sh get.sh client          # a machine running tcd
#   sh get.sh hub             # the hub, tc-control
#   curl -fsSL https://raw.githubusercontent.com/RichardPar/TailConnect_SSH/master/packaging/linux/get.sh | sh -s client
#
# Settings that skip a question (anything not set is asked):
#   VERSION=0.4.2             a release other than the latest
#   TC_SERVER=host:port       the hub to join
#   TC_AUTHKEY=tckey-...      the auth key (from the portal or `tcs-control authkey create`)
#   TC_TLS_FINGERPRINT=...    the hub's self-signed certificate fingerprint ("" for none)
#   TC_EXIT_NODE=name         an exit node to use ("" for none)
#
# Runs downloads as you and the install with sudo. Needs curl (or wget),
# tar and sha256sum.
set -eu

REPO=RichardPar/TailConnect_SSH

die() { echo "get.sh: $*" >&2; exit 1; }
say() { printf '%s\n' "$*" >&2; }

# Questions come from the terminal, so this also works as `curl ... | sh`.
TTY=/dev/tty
(: <"$TTY") 2>/dev/null || TTY=""

ask() { # ask VAR "question" [default]
    _var=$1 _q=$2 _def=${3:-}
    eval "_set=\${$_var+x}"
    if [ -n "$_set" ]; then return 0; fi
    [ -n "$TTY" ] || die "no terminal to ask '$_q': set $_var"
    if [ -n "$_def" ]; then printf '%s [%s]: ' "$_q" "$_def" >&2; else printf '%s: ' "$_q" >&2; fi
    IFS= read -r _a <"$TTY" || _a=""
    [ -n "$_a" ] || _a=$_def
    eval "$_var=\$_a"
}

ask_secret() { # ask_secret VAR "question": not echoed
    _var=$1 _q=$2
    eval "_set=\${$_var+x}"
    if [ -n "$_set" ]; then return 0; fi
    [ -n "$TTY" ] || die "no terminal to ask '$_q': set $_var"
    printf '%s: ' "$_q" >&2
    _old=$(stty -g <"$TTY" 2>/dev/null || true)
    stty -echo <"$TTY" 2>/dev/null || true
    IFS= read -r _a <"$TTY" || _a=""
    [ -n "$_old" ] && stty "$_old" <"$TTY" 2>/dev/null
    printf '\n' >&2
    eval "$_var=\$_a"
}

yes_no() { # yes_no "question" default(y|n)
    unset _r
    if [ -n "$TTY" ]; then ask _r "$1 (y/n)" "$2"; else _r=$2; fi
    case $_r in [yY]*) return 0 ;; *) return 1 ;; esac
}

fetch() { # fetch URL FILE
    if command -v curl >/dev/null; then
        curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null; then
        wget -q -O "$2" "$1"
    else
        die "needs curl or wget"
    fi
}

if [ "$(id -u)" = 0 ]; then SUDO=""; else
    command -v sudo >/dev/null || die "run as root, or install sudo"
    SUDO=sudo
fi
for c in tar sha256sum; do command -v $c >/dev/null || die "needs $c"; done

# What to install.
if [ -n "${1:-}" ]; then role=$1; else
    unset role
    ask role "Install a client (this machine joins a network) or the hub (tc-control)? client/hub" client
fi
case $role in
client | hub) ;;
*) die "unknown role '$role': client or hub" ;;
esac

case $(uname -m) in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "no release for $(uname -m) (amd64 and arm64 only)" ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# Which release.
if [ -z "${VERSION:-}" ]; then
    fetch "https://api.github.com/repos/$REPO/releases/latest" "$work/latest.json" ||
        die "couldn't ask GitHub for the latest release (set VERSION=x.y.z)"
    VERSION=$(sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' "$work/latest.json" | head -1)
    [ -n "$VERSION" ] || die "couldn't read the latest release (set VERSION=x.y.z)"
fi
VERSION=${VERSION#v}
name=tailconnect-ssh-$VERSION-linux-$arch
base=https://github.com/$REPO/releases/download/v$VERSION

installed=""
[ -x /opt/tailconnect-ssh/bin/tcd ] && installed=$(/opt/tailconnect-ssh/bin/tcd --version 2>/dev/null | awk '{print $NF}') || true
[ -x /opt/tailconnect-ssh/bin/tc-control ] && [ "$role" = hub ] &&
    installed=$(/opt/tailconnect-ssh/bin/tc-control --version 2>/dev/null | awk '{print $NF}') || true
if [ -n "$installed" ]; then say "installed: $installed; release: $VERSION ($arch)"; else say "release: $VERSION ($arch)"; fi
if [ -n "$installed" ] && [ "$installed" != "$VERSION" ] &&
    [ "$(printf '%s\n%s\n' "$installed" "$VERSION" | sort -V | tail -1)" = "$installed" ]; then
    yes_no "$installed is newer than the release ($VERSION). Install the older one anyway?" n ||
        die "kept $installed"
fi

say "downloading $name.tar.gz"
fetch "$base/$name.tar.gz" "$work/$name.tar.gz" || die "couldn't download $base/$name.tar.gz"
fetch "$base/SHA256SUMS" "$work/SHA256SUMS" || die "couldn't download SHA256SUMS"
want=$(awk -v f="$name.tar.gz" '{n=$2; sub(/^\*/,"",n); sub(/.*\//,"",n)} n==f {print $1}' "$work/SHA256SUMS")
[ -n "$want" ] || die "$name.tar.gz isn't in SHA256SUMS"
got=$(sha256sum "$work/$name.tar.gz" | awk '{print $1}')
[ "$want" = "$got" ] || die "checksum mismatch for $name.tar.gz"
say "checksum ok"
tar -xzf "$work/$name.tar.gz" -C "$work"
pkg=$work/$name
[ -x "$pkg/packaging/linux/install.sh" ] || die "the package has no installer"

if [ "$role" = hub ]; then
    if [ -f /etc/default/tailconnect-ssh-control ]; then
        say "keeping the hub's settings in /etc/default/tailconnect-ssh-control"
        $SUDO "$pkg/packaging/linux/install.sh" hub
    else
        unset listen public
        ask listen "Address to listen on" "[::]:443"
        ask public "Public address machines join with (host or host:port, empty for the browser's)" ""
        args="--listen $listen"
        [ -n "$public" ] && args="$args --public-url $public"
        token=""
        if yes_no "Get a Let's Encrypt certificate?" n; then
            unset acme
            ask acme "Name(s) for the certificate, comma-separated" "${public%%:*}"
            [ -n "$acme" ] || die "a name is needed for Let's Encrypt"
            args="$args --acme-domain $acme"
            if yes_no "Prove the name through DuckDNS (no port 80/443 needed)?" y; then
                args="$args --acme-dns duckdns"
                unset token
                ask_secret token "DuckDNS token"
                [ -n "$token" ] || die "the DuckDNS token is needed"
            fi
        fi
        if yes_no "Hide SSH from probes (--hide-ssh; every machine must run 0.4.1+)?" n; then
            args="$args --hide-ssh"
        fi
        # shellcheck disable=SC2086
        $SUDO "$pkg/packaging/linux/install.sh" hub $args
        if [ -n "$token" ]; then
            printf 'TC_DUCKDNS_TOKEN=%s\n' "$token" |
                $SUDO sh -c 'sed -i "/^#\{0,1\}TC_DUCKDNS_TOKEN=/d" /etc/default/tailconnect-ssh-control; cat >>/etc/default/tailconnect-ssh-control'
            $SUDO systemctl restart tailconnect-ssh-control
        fi
    fi
    say ""
    say "hub $VERSION running: systemctl status tailconnect-ssh-control"
    say "make a key for a machine: sudo tcs-control authkey create --help"
    exit 0
fi

# A client.
joined=no
[ -f /var/lib/tailconnect-ssh/state.json ] && joined=yes
$SUDO "$pkg/packaging/linux/install.sh" client

if [ $joined = yes ] && [ -z "${TC_AUTHKEY+x}" ] && [ -z "${TC_SERVER+x}" ]; then
    if ! yes_no "This machine has joined a network already. Join again (another hub or a new key)?" n; then
        say ""
        say "updated to $VERSION; the machine keeps its network"
        /usr/local/bin/tcs status 2>/dev/null || $SUDO /usr/local/bin/tcs status || true
        exit 0
    fi
fi

ask TC_SERVER "Hub address (host, host:port or https://host)"
[ -n "$TC_SERVER" ] || die "the hub's address is needed"
ask_secret TC_AUTHKEY "Auth key (tckey-..., from the portal or tcs-control authkey create)"
[ -n "$TC_AUTHKEY" ] || die "an auth key is needed to join"
ask TC_TLS_FINGERPRINT "Hub's TLS fingerprint (only for a self-signed certificate; empty if none)" ""
ask TC_EXIT_NODE "Exit node to send internet traffic through (empty for none)" ""

set -- up --server "$TC_SERVER" --authkey "$TC_AUTHKEY"
[ -n "$TC_TLS_FINGERPRINT" ] && set -- "$@" --tls-fingerprint "$TC_TLS_FINGERPRINT"
[ -n "$TC_EXIT_NODE" ] && set -- "$@" --exit-node "$TC_EXIT_NODE"
# tcd starts a moment after the install; wait for its socket.
i=0
while [ ! -S /run/tailconnect-ssh/tcd.sock ] && [ $i -lt 20 ]; do sleep 0.5; i=$((i + 1)); done
$SUDO /usr/local/bin/tcs "$@"
say ""
/usr/local/bin/tcs status 2>/dev/null || $SUDO /usr/local/bin/tcs status || true
say ""
say "joined with $VERSION. Log out and in again to use tcs without sudo (group tailconnect-ssh)."
