#!/usr/bin/env bash
# Builds the TailConnect-SSH Android app:
#   dist/tailconnect-ssh-VERSION-android-arm64.apk
#
#   android/build.sh            # build
#   android/build.sh install    # … and install it on the device connected over USB (adb)
#
# Uses only the Android SDK's own tools (aapt2, javac, d8, zipalign,
# apksigner): no Gradle, no NDK, no libraries. tcd is built as a static
# arm64 program with the project's cross toolchain (cargo-zigbuild with Zig,
# set up in target/tools on first use, as packaging/linux/build.sh does) and
# shipped as lib/arm64-v8a/libtcs.so (packaging/zigbuild-tools.sh).
#
# Needs: Rust, python3, a JDK (17+) and the Android SDK with build-tools and
# a platform, found via $JAVA_HOME and $ANDROID_HOME (default ~/Android/jdk
# and ~/Android/Sdk).
#
# Signing: the first build creates a key in $KEYSTORE (default
# ~/.android/tailconnect-ssh.keystore). Keep it: Android only installs an
# update signed with the same key as the installed app.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
SDK=${ANDROID_HOME:-$HOME/Android/Sdk}
export JAVA_HOME=${JAVA_HOME:-$HOME/Android/jdk}
BT=$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)
PLATFORM=$(ls -d "$SDK"/platforms/android-* | sort -V | tail -1)/android.jar
ADB=$SDK/platform-tools/adb
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)
# Android needs an increasing integer version: minutes since 2026-01-01.
VERSION_CODE=${VERSION_CODE:-$(( ($(date +%s) - 1767225600) / 60 ))}
MIN_SDK=29
TARGET_SDK=36
OUT=$ROOT/target/android
KEYSTORE=${KEYSTORE:-$HOME/.android/tailconnect-ssh.keystore}
APK=$ROOT/dist/tailconnect-ssh-$VERSION-android-arm64.apk

for t in "$BT/aapt2" "$BT/d8" "$BT/zipalign" "$BT/apksigner" "$JAVA_HOME/bin/javac" "$PLATFORM"; do
	[[ -e $t ]] || { echo "missing: $t (set ANDROID_HOME / JAVA_HOME)" >&2; exit 1; }
done
export PATH=$JAVA_HOME/bin:$PATH

echo "== TailConnect-SSH $VERSION ($VERSION_CODE), $(basename "$(dirname "$PLATFORM")"), build-tools $(basename "$BT")"
rm -rf "${OUT:?}"
mkdir -p "$OUT"/{gen,classes,dex,apk/lib/arm64-v8a} "$ROOT/dist"

echo "== tcd (static arm64: libtcs.so)"
TOOLS_BIN=$("$ROOT/packaging/zigbuild-tools.sh")
if command -v rustup >/dev/null && ! rustup target list --installed | grep -qx aarch64-unknown-linux-musl; then
	rustup target add aarch64-unknown-linux-musl
fi
(cd "$ROOT" && PATH=$TOOLS_BIN:$PATH CARGO_PROFILE_RELEASE_STRIP=symbols \
	cargo zigbuild --release --target aarch64-unknown-linux-musl --bin tcd)
cp "$ROOT/target/aarch64-unknown-linux-musl/release/tcd" "$OUT/apk/lib/arm64-v8a/libtcs.so"

echo "== resources"
"$BT/aapt2" compile --dir "$HERE/res" -o "$OUT/res.zip"
"$BT/aapt2" link -I "$PLATFORM" --manifest "$HERE/AndroidManifest.xml" --java "$OUT/gen" \
	--min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK \
	--version-code "$VERSION_CODE" --version-name "$VERSION" \
	-o "$OUT/base.apk" "$OUT/res.zip"

echo "== Java"
javac -nowarn -source 17 -target 17 -encoding UTF-8 -classpath "$PLATFORM" -d "$OUT/classes" \
	$(find "$HERE/src" "$OUT/gen" -name '*.java') 2>&1 | grep -v "bootstrap class path\|^1 warning$" || true
[[ -n $(find "$OUT/classes" -name '*.class') ]] || { echo "javac failed" >&2; exit 1; }
"$BT/d8" --release --min-api $MIN_SDK --lib "$PLATFORM" --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')

echo "== APK"
cp "$OUT/base.apk" "$OUT/unsigned.apk"
(cd "$OUT/dex" && zip -q "$OUT/unsigned.apk" classes.dex)
(cd "$OUT/apk" && zip -q -r "$OUT/unsigned.apk" lib)
"$BT/zipalign" -f -p 4 "$OUT/unsigned.apk" "$OUT/aligned.apk"
if [[ ! -f $KEYSTORE ]]; then
	echo "== creating a signing key: $KEYSTORE (keep it: updates must be signed with the same key)"
	mkdir -p "$(dirname "$KEYSTORE")"
	keytool -genkeypair -keystore "$KEYSTORE" -storepass android -keypass android -alias tailconnect-ssh \
		-keyalg EC -groupname secp256r1 -validity 10000 -dname "CN=TailConnect-SSH" >/dev/null 2>&1
fi
"$BT/apksigner" sign --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android --ks-key-alias tailconnect-ssh \
	--out "$APK" "$OUT/aligned.apk"
rm -f "$OUT"/{unsigned,aligned,base}.apk "$OUT/res.zip"
ls -la "$APK"

if [[ ${1:-} == install ]]; then
	echo "== installing on $("$ADB" get-serialno)"
	"$ADB" install --no-incremental -r "$APK"
fi
