"""Stand-in for the Android app's VpnService, for tests (tests/android-bridge.sh).

    python3 fake_android_app.py BRIDGE_SOCKET DNS_SERVER [MOVE_FILE]

Connects to tcd's bridge socket (`tcd --bridge`), reports the "underlying
network", and answers each "tun" request the way the app does: it creates a
real TUN interface (inside the test's network namespace), gives it the
requested addresses and routes, and passes its file descriptor to tcd
(SCM_RIGHTS). Like Android, a new interface replaces the previous one.
When MOVE_FILE appears, it reports another network (a new handle and new
addresses), as Android does when the device moves from Wi-Fi to mobile data.
Prints one line per event.
"""
import fcntl
import json
import os
import select
import socket
import struct
import subprocess
import sys
import time

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

bridge, dns = sys.argv[1], sys.argv[2]
move_file = sys.argv[3] if len(sys.argv) > 3 else None
moved = False


def ip(*args):
    subprocess.run(["ip", *args], check=True)


s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(100):
    try:
        s.connect(bridge)
        break
    except OSError:
        time.sleep(0.1)
else:
    sys.exit("can't connect to " + bridge)
print("connected", flush=True)


def send(msg, fd=None):
    line = (json.dumps(msg) + "\n").encode()
    if fd is None:
        s.sendall(line)
    else:
        socket.send_fds(s, [line], [fd])


send({"Type": "network", "ID": 1, "DNS": [dns], "Addresses": ["192.0.2.5/24"]})

n = 0
buf = b""
while True:
    ready, _, _ = select.select([s], [], [], 0.2)
    if move_file and not moved and os.path.exists(move_file):
        moved = True
        send({"Type": "network", "ID": 2, "DNS": [dns], "Addresses": ["198.51.100.7/24"]})
        print("moved", flush=True)
    if not ready:
        continue
    data = s.recv(65536)
    if not data:
        print("bridge closed", flush=True)
        break
    buf += data
    while b"\n" in buf:
        line, buf = buf.split(b"\n", 1)
        m = json.loads(line)
        if m["Type"] == "tun":
            name = "andr%d" % n
            n += 1
            fd = os.open("/dev/net/tun", os.O_RDWR)
            fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
            ip("link", "set", name, "mtu", str(m.get("MTU", 1400)), "up")
            for a in m.get("Addresses", []):
                ip("addr", "add", a, "dev", name)
            for r in m.get("Routes", []):
                ip("-6" if ":" in r else "-4", "route", "replace", r, "dev", name)
            for d in m.get("DNS", []):
                ip("route", "replace", d + "/32", "dev", name)
            send({"Type": "tun-reply", "ID": m["ID"], "OK": True}, fd)
            # tcd holds its own copy now; the interface lives while it does.
            os.close(fd)
            print("tun %s %s" % (name, json.dumps(m)), flush=True)
        elif m["Type"] == "close":
            print("close", flush=True)
