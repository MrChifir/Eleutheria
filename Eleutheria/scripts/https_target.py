#!/usr/bin/env python3
"""Тестовая https-цель для e2e (многопоточная, keep-alive): https_target.py <addr> <port> <cert> <key>"""
import http.server, ssl, sys

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        body = b"hello\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_HEAD = do_GET
    def log_message(self, *a): pass

addr, port, cert, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
srv = http.server.ThreadingHTTPServer((addr, port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
