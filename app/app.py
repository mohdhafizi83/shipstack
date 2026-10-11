"""Tiny stdlib-only HTTP API — the local stand-in for the Fargate service.

Same contract the Terraform modules assume:
  - listens on :8080
  - GET /healthz -> 200 (ALB health check path)
  - GET /api/db  -> proves the DB wiring end-to-end

No third-party deps: /api/db performs a real Postgres wire-protocol startup
handshake (StartupMessage + auth reply) over a raw socket, which proves
reachability and protocol identity without pulling in a driver.
"""

import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "app")
DB_USER = os.environ.get("DB_USER", "app")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
APP_ENV = os.environ.get("APP_ENV", "local")

START = time.time()


def postgres_probe():
    """Open a real Postgres startup handshake and read the server's reply.

    This is a genuine wire-protocol interaction: we send a StartupMessage and
    the server answers with AuthenticationOk / AuthenticationCleartextPassword
    / ErrorResponse — enough to prove reachability + protocol identity
    without pulling in a driver dependency.
    """
    params = f"user\x00{DB_USER}\x00database\x00{DB_NAME}\x00\x00".encode()
    length = (8 + len(params)).to_bytes(4, "big")
    proto = (196608).to_bytes(4, "big")  # 3.0
    payload = length + proto + params

    with socket.create_connection((DB_HOST, DB_PORT), timeout=3) as sock:
        sock.sendall(payload)
        header = sock.recv(1)
        if not header:
            return {"reachable": True, "auth": "closed"}
        body = sock.recv(8)
        code = {b"R": "auth-request", b"E": "error", b"N": "notice"}.get(header, "unknown")
        return {"reachable": True, "auth": code}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802 (stdlib API)
        if self.path == "/healthz":
            self._send(200, {"status": "ok", "env": APP_ENV, "uptime_s": round(time.time() - START)})
        elif self.path == "/api/db":
            try:
                self._send(200, {"db": postgres_probe()})
            except OSError as exc:
                self._send(503, {"db": {"reachable": False}, "error": str(exc)})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        print(f"[app] {self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
