#!/usr/bin/env python3
"""
Simple HTTP backend for PQ-TLS Server demo.
Responds with JSON showing request info + PQ-TLS headers forwarded by the proxy.
"""

import http.server
import json
import datetime
import socket
import os

PORT = 8080

class DemoHandler(http.server.BaseHTTPRequestHandler):
    """Handles all requests and echoes back useful info."""

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Backend", f"demo-{socket.gethostname()}")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send_json({"status": "healthy", "pid": os.getpid()})
            return

        if self.path == "/slow":
            import time
            time.sleep(2)
            self._send_json({"message": "slow response after 2s"})
            return

        self._send_json({
            "message": "Hello from PQ-TLS demo backend!",
            "method": self.command,
            "path": self.path,
            "timestamp": datetime.datetime.now().isoformat(),
            "headers": dict(self.headers),
            "server_pid": os.getpid(),
            "pq_info": {
                "note": "If X-PQ-KEM or X-PQ-Cipher headers are present, "
                        "the connection was secured with post-quantum cryptography.",
                "kem_header": self.headers.get("X-PQ-KEM", "not present"),
                "cipher_header": self.headers.get("X-PQ-Cipher", "not present"),
            }
        })

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        self._send_json({
            "message": "POST received",
            "path": self.path,
            "body_size": len(body),
            "body_preview": body[:200].decode(errors="replace"),
            "timestamp": datetime.datetime.now().isoformat(),
        })

    def log_message(self, format, *args):
        print(f"[backend] {self.client_address[0]} - {format % args}")


if __name__ == "__main__":
    server = http.server.HTTPServer(("127.0.0.1", PORT), DemoHandler)
    print(f"[backend] Demo backend listening on http://127.0.0.1:{PORT}")
    print(f"[backend] Endpoints: / (echo), /health (health check), /slow (2s delay)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[backend] Shutting down")
        server.shutdown()
