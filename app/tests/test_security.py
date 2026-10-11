"""Security tests for app/app.py — run from repo root:

    python -m pytest app/tests -q

No network: the app is served on a 127.0.0.1 ephemeral port via
ThreadingHTTPServer, and the "origin" servers used by the /api/fetch tests
are local sockets too. The app module is loaded directly from app/app.py so
these tests pin the exact file that ships in the container.
"""

import http.server
import importlib.util
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

APP_PATH = Path(__file__).resolve().parents[1] / "app.py"
_spec = importlib.util.spec_from_file_location("shipstack_app", APP_PATH)
app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(app)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def start_server(handler_cls):
    """Serve handler_cls on an ephemeral 127.0.0.1 port; return (httpd, base_url)."""
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    return httpd, f"http://{host}:{port}"


def req(base, path, method="GET", headers=None, body=None):
    """Return (status, headers, parsed_json_or_bytes). HTTPError is a response."""
    request = urllib.request.Request(base + path, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=5) as resp:
            raw = resp.read()
            return resp.status, dict(resp.headers), _maybe_json(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, dict(exc.headers), _maybe_json(raw)


def _maybe_json(raw):
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return raw


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture()
def base(monkeypatch):
    """App under test with all security envs cleared (fail-closed defaults)."""
    for var in ("ADMIN_TOKEN", "WEBHOOK_SECRET", "DB_ALLOWED_CIDRS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("DB_HOST", "127.0.0.1")
    monkeypatch.setenv("DB_PORT", str(free_port()))
    httpd, url = start_server(app.Handler)
    yield url
    httpd.shutdown()
    httpd.server_close()


def sign(secret, timestamp, body):
    import hashlib
    import hmac
    return "sha256=" + hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()


SECURITY_HEADER_NAMES = (
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cache-Control",
)


# ---------------------------------------------------------------------------
# baseline contract (must not regress)
# ---------------------------------------------------------------------------

def test_healthz_contract(base):
    status, _, body = req(base, "/healthz")
    assert status == 200
    assert set(body) == {"status", "env", "uptime_s"}
    assert body["status"] == "ok"


def test_healthz_with_query_string(base):
    # strict path matching: query strings must not turn /healthz into a 404
    status, _, body = req(base, "/healthz?probe=1")
    assert status == 200 and body["status"] == "ok"


def test_unknown_paths_404(base):
    assert req(base, "/nope")[0] == 404
    assert req(base, "/api/webhook", method="POST", body=b"{}")[0] in (401, 503)  # routed, not 404
    assert req(base, "/api/nope", method="POST", body=b"{}")[0] == 404


def test_server_header_suppressed(base):
    status, headers, _ = req(base, "/healthz")
    assert status == 200
    assert "Python" not in headers.get("Server", "")
    assert headers.get("Server") == "shipstack"


# ---------------------------------------------------------------------------
# security headers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "path,method,expected",
    [("/healthz", "GET", 200), ("/nope", "GET", 404), ("/api/admin/stats", "GET", 503)],
)
def test_security_headers_on_every_response(base, path, method, expected):
    status, headers, _ = req(base, path, method=method)
    assert status == expected
    for name in SECURITY_HEADER_NAMES:
        assert name in headers, f"missing {name}"
    assert headers["Content-Security-Policy"] == (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Cache-Control"] == "no-store"


# ---------------------------------------------------------------------------
# error hygiene on /api/db
# ---------------------------------------------------------------------------

def test_db_error_does_not_leak_details(base, monkeypatch):
    # allow loopback so we exercise the *connection-failure* path, not the
    # SSRF guard: DB_PORT points at a closed port.
    monkeypatch.setenv("DB_ALLOWED_CIDRS", "127.0.0.0/8")
    status, _, body = req(base, "/api/db")
    assert status == 503
    assert body == {"db": {"reachable": False}}  # no "error" key, no host/port
    assert "127.0.0.1" not in json.dumps(body)


def test_db_blocked_when_host_resolves_private(base, monkeypatch):
    monkeypatch.setenv("DB_HOST", "169.254.169.254")  # cloud metadata IP
    status, _, body = req(base, "/api/db")
    assert status == 503
    assert body == {"db": {"reachable": False, "blocked": True}}


def test_db_blocked_loopback_by_default(base):
    # fail closed: loopback DB_HOST needs an explicit DB_ALLOWED_CIDRS
    status, _, body = req(base, "/api/db")
    assert status == 503
    assert body["db"]["blocked"] is True


def test_db_happy_path_still_works(base, monkeypatch):
    # fake Postgres: reply 'R' (auth request) to the StartupMessage
    class FakePg(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # never used; keep quiet
            self.send_error(501)

        def log_message(self, *args):
            pass

    class PgSocket(threading.Thread):
        def __init__(self):
            super().__init__(daemon=True)
            self.sock = socket.socket()
            self.sock.bind(("127.0.0.1", 0))
            self.sock.listen(1)
            self.port = self.sock.getsockname()[1]

        def run(self):
            conn, _ = self.sock.accept()
            conn.recv(1024)  # StartupMessage
            conn.sendall(b"R\x00\x00\x00\x08\x00\x00\x00\x00")
            conn.close()

    pg = PgSocket()
    pg.start()
    monkeypatch.setenv("DB_HOST", "127.0.0.1")
    monkeypatch.setenv("DB_PORT", str(pg.port))
    monkeypatch.setenv("DB_ALLOWED_CIDRS", "127.0.0.0/8")
    status, _, body = req(base, "/api/db")
    assert status == 200
    assert body == {"db": {"reachable": True, "auth": "auth-request"}}
    pg.sock.close()


# ---------------------------------------------------------------------------
# constant-time admin auth
# ---------------------------------------------------------------------------

def test_admin_disabled_when_token_unset(base):
    status, _, body = req(base, "/api/admin/stats")
    assert status == 503
    assert body == {"error": "admin disabled"}


def test_admin_missing_header(base, monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN", "s3cret-admin")
    status, headers, body = req(base, "/api/admin/stats")
    assert status == 401
    assert headers.get("WWW-Authenticate") == "Bearer"
    assert body == {"error": "unauthorized"}


def test_admin_wrong_token(base, monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN", "s3cret-admin")
    status, headers, body = req(base, "/api/admin/stats", headers={"Authorization": "Bearer wrong"})
    assert status == 401
    assert headers.get("WWW-Authenticate") == "Bearer"
    assert body == {"error": "unauthorized"}  # identical to missing-header case


def test_admin_correct_token(base, monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN", "s3cret-admin")
    status, _, body = req(base, "/api/admin/stats", headers={"Authorization": "Bearer s3cret-admin"})
    assert status == 200
    assert set(body) == {"uptime_s", "requests_served"}
    assert isinstance(body["requests_served"], int)


def test_admin_uses_constant_time_compare():
    # timing sanity: token checks must go through hmac.compare_digest, never
    # `==` (which short-circuits and leaks the matching prefix length).
    src = APP_PATH.read_text()
    assert src.count("hmac.compare_digest") >= 2  # admin + webhook
    assert "supplied == token" not in src
    assert "token == supplied" not in src


# ---------------------------------------------------------------------------
# mandatory webhook signatures
# ---------------------------------------------------------------------------

def webhook(base, body=b'{"event":"deploy.done"}', ts=None, sig=None, secret=None, headers=None):
    ts = str(int(time.time())) if ts is None else str(ts)
    if sig is None and secret is not None:
        sig = sign(secret, ts, body)
    hdrs = {"Content-Type": "application/json"}
    if ts is not None:
        hdrs["X-Webhook-Timestamp"] = ts
    if sig is not None:
        hdrs["X-Webhook-Signature"] = sig
    hdrs.update(headers or {})
    return req(base, "/api/webhook", method="POST", headers=hdrs, body=body)


def test_webhook_disabled_without_secret(base):
    # signature verification is MANDATORY: no secret => endpoint closed,
    # unsigned events are never accepted.
    status, _, body = webhook(base, secret=None)
    assert status == 503
    assert body == {"error": "webhook disabled"}


def test_webhook_valid_signature(base, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec")
    status, _, body = webhook(base, secret="whsec")
    assert status == 202
    assert body == {"accepted": True, "event": "deploy.done"}


def test_webhook_missing_signature(base, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec")
    status, _, body = webhook(base, sig=None)
    assert status == 401 and body == {"error": "invalid signature"}


def test_webhook_missing_timestamp(base, monkeypatch):
    # signature present but no timestamp header => rejected (nothing to pin
    # the signature's freshness against)
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec")
    body = b'{"event":"deploy.done"}'
    status, _, resp = req(base, "/api/webhook", method="POST",
                          headers={"X-Webhook-Signature": sign("whsec", 0, body)},
                          body=body)
    assert status == 401 and resp == {"error": "invalid signature"}


def test_webhook_bad_signature(base, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec")
    status, _, body = webhook(base, ts=int(time.time()), sig="sha256=" + "0" * 64)
    assert status == 401 and body == {"error": "invalid signature"}


def test_webhook_stale_timestamp(base, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec")
    status, _, body = webhook(base, ts=int(time.time()) - 301, secret="whsec")
    assert status == 401


def test_webhook_future_timestamp(base, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec")
    status, _, body = webhook(base, ts=int(time.time()) + 301, secret="whsec")
    assert status == 401


def test_webhook_replay_rejected(base, monkeypatch):
    # a captured valid request must die once its timestamp leaves the window
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec")
    clock = {"t": 1_700_000_000}
    monkeypatch.setattr(app, "_now", lambda: clock["t"])
    ts = clock["t"]
    body = b'{"event":"deploy.done"}'
    sig = sign("whsec", ts, body)
    status, _, _ = webhook(base, body=body, ts=ts, sig=sig)
    assert status == 202
    clock["t"] = ts + 301  # same valid signature, replayed after tolerance
    status, _, resp = webhook(base, body=body, ts=ts, sig=sig)
    assert status == 401 and resp == {"error": "invalid signature"}


def test_webhook_body_too_large(base, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec")
    big = b'{"event":"' + b"x" * 70000 + b'"}'
    status, _, body = webhook(base, body=big, secret="whsec")
    assert status == 413


def test_webhook_non_json_body(base, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec")
    status, _, body = webhook(base, body=b"i am not json", secret="whsec")
    assert status == 400 and body == {"error": "invalid body"}


def test_webhook_json_but_not_object(base, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec")
    status, _, body = webhook(base, body=b"[1,2,3]", secret="whsec")
    assert status == 400


# ---------------------------------------------------------------------------
# CSRF defense-in-depth (Origin vs Host)
# ---------------------------------------------------------------------------

def test_webhook_origin_mismatch_blocked(base, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec")
    status, _, body = webhook(base, secret="whsec", headers={"Origin": "http://evil.example"})
    assert status == 403 and body == {"error": "origin mismatch"}


def test_webhook_matching_origin_allowed(base, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec")
    host = base.split("://", 1)[1]
    status, _, body = webhook(base, secret="whsec", headers={"Origin": f"http://{host}"})
    assert status == 202


def test_webhook_no_origin_server_to_server_ok(base, monkeypatch):
    # non-browser callers send no Origin and are unaffected by the check
    monkeypatch.setenv("WEBHOOK_SECRET", "whsec")
    status, _, _ = webhook(base, secret="whsec")
    assert status == 202


# ---------------------------------------------------------------------------
# SSRF guard: /api/fetch
# ---------------------------------------------------------------------------

def fetch(base, url):
    import urllib.parse
    return req(base, "/api/fetch?url=" + urllib.parse.quote(url, safe=""))


def test_fetch_blocks_metadata_ip(base):
    status, _, body = fetch(base, "http://169.254.169.254/latest/meta-data/")
    assert status == 403 and body == {"error": "blocked address"}


def test_fetch_blocks_loopback(base):
    status, _, body = fetch(base, f"http://127.0.0.1:{free_port()}/")
    assert status == 403 and body == {"error": "blocked address"}


def test_fetch_blocks_internal_hostname(base):
    # localhost resolves to loopback -> blocked by the resolver check
    status, _, body = fetch(base, "http://localhost:8080/")
    assert status == 403


def test_fetch_rejects_bad_scheme(base):
    assert fetch(base, "ftp://example.com/x")[0] == 400
    assert fetch(base, "file:///etc/passwd")[0] == 400
    assert fetch(base, "")[0] == 400


def test_fetch_rejects_userinfo(base):
    # user:pass@ smuggling is rejected before DNS even runs
    status, _, body = fetch(base, "http://admin:secret@93.184.216.34/")
    assert status == 400 and body == {"error": "invalid url"}


def test_fetch_unresolvable_host(base):
    status, _, body = fetch(base, "http://nonexistent-host.invalid/")
    assert status == 502 and body == {"error": "fetch failed"}


class _OriginServer:
    """Local target for the fetch tests; loopback is unblocked by monkeypatch."""

    def __init__(self, mode):
        self.mode = mode

        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if outer.mode == "ok":
                    payload = b"hello"
                    self.send_response(200)
                elif outer.mode == "notfound":
                    payload = b"gone"
                    self.send_response(404)
                elif outer.mode == "redirect":
                    payload = b""
                    self.send_response(302)
                    self.send_header("Location", "http://169.254.169.254/")
                else:  # big
                    payload = b"x" * 70000
                    self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.httpd, self.url = start_server(H)

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture()
def unblocked(monkeypatch):
    # let the guard pass loopback so the *fetch behaviour* (redirect refusal,
    # size cap, status passthrough) can be tested against local targets.
    monkeypatch.setattr(app, "_ip_blocked", lambda ip: False)


def test_fetch_ok(base, unblocked):
    origin = _OriginServer("ok")
    status, _, body = fetch(base, origin.url + "/")
    assert status == 200 and body == {"ok": True, "bytes": 5, "status": 200}
    origin.stop()


def test_fetch_refuses_redirect(base, unblocked):
    origin = _OriginServer("redirect")
    status, _, body = fetch(base, origin.url + "/")
    assert status == 502 and body == {"error": "redirect refused"}
    origin.stop()


def test_fetch_caps_response_size(base, unblocked):
    origin = _OriginServer("big")
    status, _, body = fetch(base, origin.url + "/")
    assert status == 413 and body == {"error": "response too large"}
    origin.stop()


def test_fetch_passthrough_upstream_status(base, unblocked):
    origin = _OriginServer("notfound")
    status, _, body = fetch(base, origin.url + "/")
    assert status == 200 and body == {"ok": True, "bytes": 4, "status": 404}
    origin.stop()


# ---------------------------------------------------------------------------
# log hygiene
# ---------------------------------------------------------------------------

def test_logs_never_contain_secrets(base, monkeypatch, capsys):
    monkeypatch.setenv("ADMIN_TOKEN", "topsecret-admin-token")
    monkeypatch.setenv("WEBHOOK_SECRET", "topsecret-webhook-secret")
    req(base, "/api/admin/stats", headers={"Authorization": "***"})
    sig = sign("topsecret-webhook-secret", int(time.time()), b'{"event":"x"}')
    req(base, "/api/webhook", method="POST",
        headers={"X-Webhook-Timestamp": str(int(time.time())), "X-Webhook-Signature": sig},
        body=b'{"event":"x"}')
    logged = capsys.readouterr().out
    assert "topsecret-admin-token" not in logged
    assert "topsecret-webhook-secret" not in logged
    assert "sha256=" not in logged
