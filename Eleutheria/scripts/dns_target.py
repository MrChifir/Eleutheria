#!/usr/bin/env python3
"""Тестовый DNS-«роутер»: отвечает 203.0.113.99 на любой A-запрос и пишет, кто спрашивал: dns_target.py <addr> <log>"""
import socket, struct, sys
addr, log = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((addr, 53))
while True:
    data, peer = s.recvfrom(512)
    # имя из вопроса
    i, labels = 12, []
    while data[i]:
        labels.append(data[i + 1:i + 1 + data[i]].decode()); i += data[i] + 1
    qtype = struct.unpack(">H", data[i + 1:i + 3])[0]
    open(log, "a").write(f"{peer[0]} {'.'.join(labels)} type={qtype}\n")
    if qtype != 1:
        resp = data[:2] + b"\x81\x80" + data[4:6] + b"\x00\x00\x00\x00\x00\x00" + data[12:i + 5]
    else:
        resp = data[:2] + b"\x81\x80" + data[4:6] + b"\x00\x01\x00\x00\x00\x00" + data[12:i + 5] + \
               b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton("203.0.113.99")
    s.sendto(resp, peer)
