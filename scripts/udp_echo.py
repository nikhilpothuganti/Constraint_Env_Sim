#!/usr/bin/env python3
"""UDP echo server for the firmware's network self-test (boot/net_test.c).

Runs in the VM. Binds on all interfaces so it can start before the
simulator creates tap0 (192.168.1.100).
"""
import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 11111
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
print(f"udp_echo: listening on :{port}", flush=True)
while True:
    data, addr = s.recvfrom(65535)
    print(f"udp_echo: {len(data)} B from {addr[0]}:{addr[1]}", flush=True)
    s.sendto(data, addr)
