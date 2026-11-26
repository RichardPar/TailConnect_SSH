#!/bin/sh
# Sets up the project's cross toolchain, cargo-zigbuild with Zig at pinned
# versions, in target/tools/zigbuild (inside the project; nothing is
# installed elsewhere), and prints its bin directory. Needs python3 (venv).
# Used by packaging/linux/build.sh and android/build.sh.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ZIGBUILD_VERSION=0.24.1
ZIG_VERSION=0.17.1
TOOLS=$ROOT/target/tools/zigbuild
if [ ! -x "$TOOLS/bin/cargo-zigbuild" ] || ! "$TOOLS/bin/pip" freeze 2>/dev/null | grep -qx "cargo-zigbuild==$ZIGBUILD_VERSION"; then
    echo "setting up cargo-zigbuild $ZIGBUILD_VERSION with Zig $ZIG_VERSION in target/tools ..." >&2
    rm -rf "${TOOLS:?}"
    python3 -m venv "$TOOLS"
    "$TOOLS/bin/pip" install --quiet "cargo-zigbuild==$ZIGBUILD_VERSION" "ziglang==$ZIG_VERSION" >&2
fi
echo "$TOOLS/bin"
