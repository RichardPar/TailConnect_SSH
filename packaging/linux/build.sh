#!/bin/sh
# Build the Linux packages:
#   dist/tailconnect-ssh-VERSION-linux-amd64.tar.gz
#   dist/tailconnect-ssh-VERSION-linux-arm64.tar.gz   (Raspberry Pi, Rock 5B, ...)
#
# Needs only Rust (rustup) and python3 with venv. The cross toolchain,
# cargo-zigbuild with Zig at pinned versions, is set up in target/tools on
# first use; nothing is installed outside the project. The programs are
# linked for glibc 2.31, so they run on Debian 11+, Ubuntu 20.04+ and
# Raspberry Pi OS (a plain build would need the build machine's glibc).
#
# The window (tc-gui) is added to the amd64 package when GTK 4's development
# files are installed (libgtk-4-dev): it's built natively, as it needs a
# desktop anyway.
#
# Install a package on a machine: unpack it, then
#   sudo ./packaging/linux/install.sh client      (or: hub [ARGS])
#
# ARCHES="arm64" packaging/linux/build.sh builds just one.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
cd "$ROOT"
ARCHES=${ARCHES:-"amd64 arm64"}
GLIBC=2.31
ZIGBUILD_VERSION=0.24.1
ZIG_VERSION=0.17.1
TOOLS=$ROOT/target/tools/zigbuild
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
BINS="tc-control tcd tc tc-tray"

# The cross toolchain, in the project.
if [ ! -x "$TOOLS/bin/cargo-zigbuild" ] || ! "$TOOLS/bin/pip" freeze 2>/dev/null | grep -qx "cargo-zigbuild==$ZIGBUILD_VERSION"; then
    echo "setting up cargo-zigbuild $ZIGBUILD_VERSION with Zig $ZIG_VERSION in target/tools ..."
    rm -rf "${TOOLS:?}"
    python3 -m venv "$TOOLS"
    "$TOOLS/bin/pip" install --quiet "cargo-zigbuild==$ZIGBUILD_VERSION" "ziglang==$ZIG_VERSION"
fi
PATH=$TOOLS/bin:$PATH
export PATH
# Smaller programs: strip symbols when linking.
CARGO_PROFILE_RELEASE_STRIP=symbols
export CARGO_PROFILE_RELEASE_STRIP

mkdir -p dist
for arch in $ARCHES; do
    case $arch in
    amd64) triple=x86_64-unknown-linux-gnu ;;
    arm64) triple=aarch64-unknown-linux-gnu ;;
    *) echo "build.sh: unknown arch $arch (amd64, arm64)" >&2; exit 1 ;;
    esac
    if command -v rustup >/dev/null && ! rustup target list --installed | grep -qx "$triple"; then
        rustup target add "$triple"
    fi
    args=""
    for b in $BINS; do args="$args --bin $b"; done
    # shellcheck disable=SC2086
    cargo zigbuild --release --target "$triple.$GLIBC" $args

    name=tailconnect-ssh-$VERSION-linux-$arch
    out=target/dist/$name
    rm -rf "${out:?}"
    mkdir -p "$out/bin" "$out/packaging"
    for b in $BINS; do
        cp "target/$triple/release/$b" "$out/bin/"
    done
    if [ "$arch" = amd64 ] && [ "$(uname -m)" = x86_64 ] && pkg-config --exists gtk4 2>/dev/null; then
        cargo build --release --features gui --bin tc-gui
        cp target/release/tc-gui "$out/bin/"
    fi
    cp -r packaging/linux "$out/packaging/"
    rm -f "$out/packaging/linux/build.sh"
    cp README.md "$out/"
    tar -czf "dist/$name.tar.gz" -C target/dist "$name"
    echo "dist/$name.tar.gz"
done
