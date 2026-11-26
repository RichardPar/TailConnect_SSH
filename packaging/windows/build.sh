#!/bin/sh
# Build the Windows packages on Linux:
#   dist/tailconnect-ssh-VERSION-windows-amd64-setup.exe  (one-click installer)
#   dist/tailconnect-ssh-VERSION-windows-amd64.zip        (the same, unzipped: install.cmd)
# Needs: rustup target add x86_64-pc-windows-gnu; mingw-w64; nsis; zip; curl.
# Wintun is downloaded once from wintun.net, checked against a pinned
# SHA-256, and kept in target/wintun/.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
cd "$ROOT"
TARGET=x86_64-pc-windows-gnu
WINTUN_VERSION=0.14.1
WINTUN_SHA256=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
WINTUN_ZIP=target/wintun/wintun-$WINTUN_VERSION.zip
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

if [ ! -f "$WINTUN_ZIP" ]; then
    mkdir -p target/wintun
    curl -fsSL -o "$WINTUN_ZIP.tmp" "https://www.wintun.net/builds/wintun-$WINTUN_VERSION.zip"
    echo "$WINTUN_SHA256  $WINTUN_ZIP.tmp" | sha256sum -c --quiet
    mv "$WINTUN_ZIP.tmp" "$WINTUN_ZIP"
fi
echo "$WINTUN_SHA256  $WINTUN_ZIP" | sha256sum -c --quiet

cargo build --release --target $TARGET --features wingui --bin tcd --bin tc --bin tc-win

name=tailconnect-ssh-$VERSION-windows-amd64
out=target/dist/$name
rm -rf "$out"
mkdir -p "$out" dist
bin=target/$TARGET/release
x86_64-w64-mingw32-strip -o "$out/tcd.exe" "$bin/tcd.exe"
x86_64-w64-mingw32-strip -o "$out/tcs.exe" "$bin/tc.exe"
x86_64-w64-mingw32-strip -o "$out/TailConnectSSH.exe" "$bin/tc-win.exe"
unzip -p "$WINTUN_ZIP" wintun/bin/amd64/wintun.dll >"$out/wintun.dll"
unzip -p "$WINTUN_ZIP" wintun/LICENSE.txt | sed 's/\r*$/\r/' >"$out/LICENSE-wintun.txt"
cp "$HERE/TailConnectSSH.ico" "$HERE/install.cmd" "$out/"
sed 's/\r*$/\r/' "$HERE/README.txt" >"$out/README.txt"
rm -f "dist/$name.zip"
(cd target/dist && zip -qr "$ROOT/dist/$name.zip" "$name")
echo "dist/$name.zip"

makensis -V2 -DVERSION="$VERSION" -DSRC="$ROOT/$out" -DOUT="$ROOT/dist/$name-setup.exe" "$HERE/installer.nsi"
echo "dist/$name-setup.exe"
