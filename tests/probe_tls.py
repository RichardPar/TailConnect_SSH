"""Probe a TLS port the way a censor's scanner might (tests/e2e-netns.sh).

    python3 probe_tls.py HOST PORT ALPN[,ALPN...] ssh|ws

Connects with TLS (no certificate check) offering those ALPN protocols, then
sends an SSH version line (`ssh`) or a WebSocket upgrade with a random key
(`ws`), and prints the first line of the answer, `tls-error`, or `closed`.
"""
import base64
import os
import socket
import ssl
import sys

host, port, alpn, what = sys.argv[1], int(sys.argv[2]), sys.argv[3].split(","), sys.argv[4]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(alpn)
try:
    s = ctx.wrap_socket(socket.create_connection((host, port), timeout=5))
except (ssl.SSLError, OSError):
    print("tls-error")
    sys.exit()
if what == "ssh":
    s.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
else:
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(
        ("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
         "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n\r\n" % (host, key)).encode()
    )
data = b""
try:
    while b"\n" not in data:
        b = s.recv(4096)
        if not b:
            break
        data += b
except (ssl.SSLError, OSError):
    pass
line = data.split(b"\n", 1)[0].decode(errors="replace").strip()
print(line or "closed")
