"""A tiny DNS server for tests: answers A queries from a fixed table.

    python3 tiny_dns.py ADDRESS NAME=IP [NAME=IP...]
"""
import socket
import struct
import sys

addr = sys.argv[1]
table = dict(kv.split("=", 1) for kv in sys.argv[2:])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((addr, 53))
while True:
    q, peer = s.recvfrom(512)
    if len(q) < 12:
        continue
    # Question name.
    i, labels = 12, []
    while q[i]:
        labels.append(q[i + 1 : i + 1 + q[i]].decode())
        i += 1 + q[i]
    qtype = struct.unpack("!H", q[i + 1 : i + 3])[0]
    question = q[12 : i + 5]
    name = ".".join(labels).lower()
    ip = table.get(name)
    if ip and qtype == 1:
        hdr = q[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1, 0, 0)
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
        s.sendto(hdr + question + rr, peer)
    else:
        rcode = 0 if ip else 3  # NXDOMAIN for unknown names
        hdr = q[:2] + bytes([0x81, 0x80 | rcode]) + struct.pack("!HHHH", 1, 0, 0, 0)
        s.sendto(hdr + question, peer)
