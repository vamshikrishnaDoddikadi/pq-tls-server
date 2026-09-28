#!/usr/bin/env python3
"""Test backend for the end-to-end suite.

GET/POST /anything -> 200 with the request line, headers and body echoed back.
GET /big           -> 200 with the contents of $E2E_BIG_FILE (large-response test).
"""
import http.server, socketserver, sys, os
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _reply(self):
        n = int(self.headers.get("Content-Length") or 0)
        body_in = self.rfile.read(n) if n else b""
        if self.path.startswith("/big"):
            data = open(os.environ["E2E_BIG_FILE"], "rb").read()
        else:
            data = ("path=%s\n%s\nbody=%r\n" % (self.path, str(self.headers), body_in)).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    do_GET = _reply
    do_POST = _reply
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
