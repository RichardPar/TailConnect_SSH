#!/bin/sh
# Install TailConnect-SSH with systemd.
#
#   sudo packaging/linux/install.sh hub [ARGS...]   # tc-control (hub + portal) on :443
#   sudo packaging/linux/install.sh client          # tcd, the machine daemon
#   sudo packaging/linux/install.sh uninstall [--purge]
#
# Binaries go to /opt/tailconnect-ssh/bin, with commands linked in
# /usr/local/bin as `tcs` (the client CLI) and `tcs-control` (the hub's admin
# CLI). State lives in /var/lib/tailconnect-ssh{,-control}. Units are
# tailconnect-ssh.service and tailconnect-ssh-control.service. None of these
# names overlap the WireGuard TailConnect's (tcd, tc, /var/lib/tailconnect),
# so both can be installed side by side.
#
# Settings: /etc/default/tailconnect-ssh-control (TC_CONTROL_ARGS, for `hub`;
# ARGS given to `hub` are written there the first time) and
# /etc/default/tailconnect-ssh (TCD_ARGS). Existing settings are kept.
#
# `client` also installs the panel icon (`tcs-tray`, started at login from
# /etc/xdg/autostart/tailconnect-ssh-tray.desktop), the window (`tcs-gui`,
# in the applications menu as TailConnect; only when it was built, with
# `cargo build --release --features gui`), and creates the group
# tailconnect-ssh, whose members may connect, disconnect and choose the exit
# node without sudo; the installing user ($SUDO_USER) is added to it.
#
# Binaries are taken from target/release, or from the directory in $BIN.
set -eu

PREFIX=/opt/tailconnect-ssh
UNITS=/etc/systemd/system
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
BIN=${BIN:-$ROOT/target/release}

die() { echo "install.sh: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root (sudo)"
cmd=${1:-}
[ -n "$cmd" ] || die "usage: install.sh hub [ARGS...] | client | uninstall [--purge]"
shift

copy_bins() {
    for b in "$@"; do
        [ -x "$BIN/$b" ] || die "$BIN/$b not found: run cargo build --release, or set BIN"
    done
    install -d -m 0755 "$PREFIX/bin"
    for b in "$@"; do
        # Install via a temporary name, so a running binary isn't overwritten in place.
        install -m 0755 "$BIN/$b" "$PREFIX/bin/.$b.new"
        mv -f "$PREFIX/bin/.$b.new" "$PREFIX/bin/$b"
    done
    [ -f "$ROOT/README.md" ] && install -m 0644 "$ROOT/README.md" "$PREFIX/README.md"
    return 0
}

case $cmd in
hub)
    copy_bins tc-control
    ln -sf "$PREFIX/bin/tc-control" /usr/local/bin/tcs-control
    install -m 0644 "$HERE/tailconnect-ssh-control.service" "$UNITS/"
    if [ ! -f /etc/default/tailconnect-ssh-control ]; then
        # Readable by root only: it may hold TC_DUCKDNS_TOKEN.
        (umask 077 && printf '# Arguments for `tc-control serve` (see `tc-control serve --help`).\nTC_CONTROL_ARGS="%s"\n# For --acme-dns duckdns:\n#TC_DUCKDNS_TOKEN=\n' "$*" \
            >/etc/default/tailconnect-ssh-control)
    elif [ $# -gt 0 ]; then
        echo "keeping /etc/default/tailconnect-ssh-control (edit it to change the hub's arguments)"
    fi
    systemctl daemon-reload
    systemctl enable tailconnect-ssh-control >/dev/null 2>&1
    systemctl restart tailconnect-ssh-control
    echo "hub installed: systemctl status tailconnect-ssh-control; admin CLI: sudo tcs-control --help"
    ;;
client)
    copy_bins tcd tc tc-tray
    ln -sf "$PREFIX/bin/tc" /usr/local/bin/tcs
    ln -sf "$PREFIX/bin/tc-tray" /usr/local/bin/tcs-tray
    groupadd -r -f tailconnect-ssh
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] && ! id -nG "$SUDO_USER" | grep -qw tailconnect-ssh; then
        usermod -aG tailconnect-ssh "$SUDO_USER"
        echo "added $SUDO_USER to the tailconnect-ssh group: it may connect, disconnect and pick the exit node without sudo"
    fi
    if [ -x "$BIN/tc-gui" ]; then
        copy_bins tc-gui
        ln -sf "$PREFIX/bin/tc-gui" /usr/local/bin/tcs-gui
        install -m 0644 "$HERE/tailconnect-ssh.desktop" /usr/share/applications/tailconnect-ssh.desktop
    else
        echo "note: no window (tc-gui): build it with cargo build --release --features gui (needs libgtk-4-dev)"
        rm -f /usr/share/applications/tailconnect-ssh.desktop
    fi
    rm -f /etc/xdg/autostart/tailconnect-ssh.desktop # (its old name)
    install -m 0644 "$HERE/tailconnect-ssh-tray.desktop" /etc/xdg/autostart/tailconnect-ssh-tray.desktop
    if [ -f /etc/xdg/autostart/tailconnect.desktop ]; then
        echo "note: the WireGuard TailConnect's tray also starts at login (/etc/xdg/autostart/tailconnect.desktop)"
    fi
    install -m 0644 "$HERE/tailconnect-ssh.service" "$UNITS/"
    if [ ! -f /etc/default/tailconnect-ssh ]; then
        printf '# Arguments for tcd (see `tcd --help`).\nTCD_ARGS=""\n' >/etc/default/tailconnect-ssh
    fi
    systemctl daemon-reload
    systemctl enable tailconnect-ssh >/dev/null 2>&1
    systemctl restart tailconnect-ssh
    echo "client installed: sudo tcs up --server HOST [--tls-fingerprint FP] --authkey KEY; tcs status"
    ;;
uninstall)
    purge=no
    [ "${1:-}" = --purge ] && purge=yes
    for u in tailconnect-ssh tailconnect-ssh-control; do
        systemctl disable --now "$u" >/dev/null 2>&1 || true
        rm -f "$UNITS/$u.service"
    done
    systemctl daemon-reload
    rm -f /usr/local/bin/tcs /usr/local/bin/tcs-control /usr/local/bin/tcs-tray /usr/local/bin/tcs-gui \
        /usr/share/applications/tailconnect-ssh.desktop /etc/xdg/autostart/tailconnect-ssh.desktop \
        /etc/xdg/autostart/tailconnect-ssh-tray.desktop
    rm -rf "$PREFIX"
    if [ $purge = yes ]; then
        rm -rf /var/lib/tailconnect-ssh /var/lib/tailconnect-ssh-control \
            /etc/default/tailconnect-ssh /etc/default/tailconnect-ssh-control
        groupdel tailconnect-ssh 2>/dev/null || true
        echo "removed TailConnect-SSH with its keys, database and settings"
    else
        echo "removed TailConnect-SSH (state kept in /var/lib/tailconnect-ssh*, settings in /etc/default/tailconnect-ssh*; --purge deletes them)"
    fi
    ;;
*)
    die "unknown command $cmd"
    ;;
esac
