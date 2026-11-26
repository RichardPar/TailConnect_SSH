# TODO: the Android app

The app works: it's built, installed and tested on the user's phone. This
file lists what's left. See the README's "Android" section for how it works
and how to build it.

## Done

- `tcd --bridge`: Android mode in the daemon (`src/client/android.rs`, with
  the wiring in `src/client/mod.rs`). It covers:
  - the VPN interface, requested from the app;
  - the hub's name resolved through the phone's DNS servers;
  - non-tailnet DNS forwarded to the phone's network (or the exit node);
  - direct endpoints taken from the app's report;
  - using an exit node by asking for a new interface with default routes;
  - refusing to be an exit node.
- `tests/android-bridge.sh` with `tests/fake_android_app.py`: Android mode
  tested on Linux in an unprivileged namespace, 6 checks.
- The app, in `android/` (package `tailconnect.ssh`, targetSdk 36, minSdk
  29), with no Gradle and no NDK. `android/build.sh [install]` makes
  `dist/tailconnect-ssh-VERSION-android-arm64.apk`.
  - `tcd` is built as static musl arm64 with the project's toolchain
    (`packaging/zigbuild-tools.sh`).
  - `MainActivity` is a newly written UI in the Windows/Linux style.
    `VpnSvc` runs the daemon, serves the bridge and watches the network.
    `Api` is the local API client, `Words` ports `view.rs`, and `Ui` holds
    the drawing helpers.
  - The QR scanner reuses the Go app's `QrDecoder`, with a new scan
    screen.
- Tested on the phone (Samsung S21 FE, Android 16), joined as
  `richards-s21-fe.richard` at 100.64.0.7:
  - joining through a `tailconnect-ssh://join` link, which opened the
    login sheet pre-filled;
  - the VPN permission prompt, accepted by the user;
  - direct paths to the other machines;
  - ping by short and full name from the phone, and ping of the phone from
    dell3591;
  - internet names resolving through the forwarding;
  - exit node khadas (the public IP became the VPN's 146.70.175.94), and
    back to None;
  - the Connect switch off and on;
  - an in-place update that kept the login.

## Left to do

- [ ] **QR scanning with the camera** hasn't been tried. Make a key in the
      portal, tap "Scan QR code" in the app, and check the sheet fills in
      (camera permission prompt included).
- [ ] **Changing networks** (Wi-Fi to mobile data and back) hasn't been
      tried. The app reports network changes to `tcd`, but `tcd` doesn't
      react to them beyond the 30-second endpoint re-report and the hub
      connection's keepalive timeout. Consider calling
      `Bridge::set_on_network` with a function that re-reports endpoints at
      once and reconnects to the hub when the network changes.
- [ ] **Always-on VPN and starting after a reboot** haven't been tried.
      The manifest declares `SUPPORTS_ALWAYS_ON`. Without always-on, the
      app reconnects when it's opened (`want_up` is kept by `tcd`).
- [ ] **The old Go app** (`tailconnect.android`) is still on the phone, and
      useless, because its hub is gone. **Ask the user before uninstalling
      it** (`adb uninstall tailconnect.android`).
- [ ] Maybe: show the daemon's log more nicely, a Quick Settings tile, and
      a dark-mode check (the palette follows the system theme, but only
      light mode has been looked at).
