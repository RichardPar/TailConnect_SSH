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
  - an in-place update that kept the login;
  - the old Go app (`tailconnect.android`) is gone from the phone;
  - changing networks (Wi-Fi → mobile data → Wi-Fi, with
    `adb shell cmd wifi set-wifi-enabled …`): after each switch both
    directions worked and internet names resolved within 1–2 s, and the
    direct path to dell3591 was back straight away on Wi-Fi.
- Changing networks:
  - The app reports the network with Android's handle for it (`ID`). It
    follows the default network callback and also checks every 2 s,
    because Android 16 held the callbacks back in testing.
  - `tcd` (`Network::change`): on another network it drops its direct
    links and reconnects to the hub at once. If only the addresses change,
    it re-reports the endpoints. A DNS forward that fails while the device
    moves is retried with the new network's servers.
  - Every client: a peer that starts sending through the hub while we hold
    a direct link to it has lost that link, so we drop ours too
    (`drop_stale_link`, for links older than 10 s). Before this, dell3591's
    replies to the phone went into the dead link until it timed out.
  - `tests/android-bridge.sh` checks the reconnect (7 checks now).
- Faster failover, on every platform:
  - SSH keepalive every 5 s (10 s on Android), plus `TCP_USER_TIMEOUT` of
    two keepalives on Linux and Android. A silently dead connection (to the
    hub or a peer) is noticed in 13–15 s, down from 46 s (measured on
    dell3591 by black-holing its hub connection).
  - Desktops watch their outgoing address every 2 s and reconnect when it
    moves (Wi-Fi to Ethernet, a second uplink).
  - The app checks the network every second.
  - Hub retries start at 250 ms.
  - On the phone, Wi-Fi ↔ mobile data now recovers in 0.1–2 s.

## Left to do

- [ ] **QR scanning with the camera** hasn't been tried. Make a key in the
      portal, tap "Scan QR code" in the app, and check the sheet fills in
      (camera permission prompt included).
- [ ] **Always-on VPN and starting after a reboot** haven't been tried.
      The manifest declares `SUPPORTS_ALWAYS_ON`. Without always-on, the
      app reconnects when it's opened (`want_up` is kept by `tcd`).
- [ ] Maybe: show the daemon's log more nicely, a Quick Settings tile, and
      a dark-mode check (the palette follows the system theme, but only
      light mode has been looked at).
