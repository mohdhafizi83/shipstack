"""Tiny stdlib-only HTTP API — the local stand-in for the Fargate service.

Same contract the Terraform modules assume:
  - listens on :8080
  - GET /healthz -> 200 (ALB health check path)
  - GET /api/db  -> proves the DB wiring end-to-end

Hardening added on top of the contract (see SECURITY.md for the threat model):
  - security headers on every response, Cache-Control: no-store on API output
  - error hygiene: 5xx bodies never echo exception text (host/port leak)
  - constant-time bearer auth for /api/admin/stats (hmac.compare_digest)
  - mandatory HMAC-SHA256 webhook signatures with timestamp tolerance
  - SSRF guard: URL and DB_HOST resolution blocked for private/loopback/
    link-local/multicast/reserved ranges (169.254.169.254 included)
  - Origin-vs-Host check on POSTs as CSRF defense-in-depth

No third-party deps: /api/db performs a real Postgres wire-protocol startup
handshake (StartupMessage + auth reply) over a raw socket, which proves
reachability and protocol identity without pulling in a driver.
"""

import hashlib
import hmac
import ipaddress
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_ENV = os.environ.get("APP_ENV", "local")

MAX_BODY = 65536          # request bodies (webhook) and fetch responses
WEBHOOK_TOLERANCE_S = 300  # replay window for webhook timestamps
FETCH_TIMEOUT_S = 3

START = time.time()

# Response counter for /api/admin/stats. ThreadingHTTPServer serves requests
# on multiple threads, so the increment is lock-guarded.
_LOCK = threading.Lock()
REQUESTS_SERVED = 0


def _now():
    """Single clock indirection so tests can shift time (replay tests)."""
    return time.time()


# --------------------------------------------------------------------------
# SSRF guard
# --------------------------------------------------------------------------

def _ip_blocked(ip):
    """True if an IP must never be contacted from inside the service.

    WHY: the classic container-side SSRF target is the cloud metadata IP
    (169.254.169.254), but internal admin services, multicast and reserved
    space are all fair game once you have an arbitrary-fetch primitive, so
    the deny list is range-based, not IP-based. Anything unparseable is
    treated as blocked (fail closed).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _resolve_ips(host, port):
    """All IPs a hostname resolves to (raises socket.gaierror if none)."""
    return sorted({info[4][0] for info in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)})


def _allowed_by_cidrs(ip, cidrs):
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in cidrs)


def _parse_cidr_list(raw):
    """Parse a comma-separated CIDR allowlist; bad entries are dropped."""
    nets = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            nets.append(ipaddress.ip_network(chunk, strict=False))
        except ValueError:
            continue
    return nets


def _db_settings():
    return {
        "host": os.environ.get("DB_HOST", "localhost"),
        "port": int(os.environ.get("DB_PORT", "5432")),
        "name": os.environ.get("DB_NAME", "app"),
        "user": os.environ.get("DB_USER", "app"),
        # DB_HOST is operator config, but env injection is a real threat
        # (a bad Helm value / SSM typo can point the app at metadata or an
        # internal admin host). The guard therefore fails closed: private
        # space is blocked unless explicitly allowed via DB_ALLOWED_CIDRS.
        # In docker-compose the DB genuinely lives on the private bridge
        # network, so compose sets DB_ALLOWED_CIDRS=172.16.0.0/12.
        "allow": _parse_cidr_list(os.environ.get("DB_ALLOWED_CIDRS", "")),
    }


def db_host_blocked():
    """True if DB_HOST resolves into a blocked range (and is not allowed).

    Unresolvable hosts are NOT blocked here — that is an outage, not a
    policy violation, and /api/db already reports it as unreachable.
    """
    cfg = _db_settings()
    try:
        ips = _resolve_ips(cfg["host"], cfg["port"])
    except (socket.gaierror, UnicodeError):
        return False
    return any(_ip_blocked(ip) and not _allowed_by_cidrs(ip, cfg["allow"]) for ip in ips)


def postgres_probe():
    """Open a real Postgres startup handshake and read the server's reply.

    This is a genuine wire-protocol interaction: we send a StartupMessage and
    the server answers with AuthenticationOk / AuthenticationCleartextPassword
    / ErrorResponse — enough to prove reachability + protocol identity
    without pulling in a driver dependency.
    """
    cfg = _db_settings()
    params = f"user\x00{cfg['user']}\x00database\x00{cfg['name']}\x00\x00".encode()
    length = (8 + len(params)).to_bytes(4, "big")
    proto = (196608).to_bytes(4, "big")  # 3.0
    payload = length + proto + params

    with socket.create_connection((cfg["host"], cfg["port"]), timeout=3) as sock:
        sock.sendall(payload)
        header = sock.recv(1)
        if not header:
            return {"reachable": True, "auth": "closed"}
        body = sock.recv(8)
        code = {b"R": "auth-request", b"E": "error", b"N": "notice"}.get(header, "unknown")
        return {"reachable": True, "auth": code}


# --------------------------------------------------------------------------
# Webhook signature verification (Stripe-style)
# --------------------------------------------------------------------------

def webhook_verify(secret, timestamp_raw, signature_raw, body):
    """Return True only if the HMAC signature is valid and inside the window.

    WHY: signatures are MANDATORY (the caller fails closed when the secret is
    unset — an unsigned webhook must never be accepted just because someone
    forgot to configure one). The signed payload is "{timestamp}.{body}" so a
    captured request cannot be replayed after the ±300s window expires.
    All comparisons use hmac.compare_digest to avoid byte-position timing
    side channels.
    """
    if not timestamp_raw or not signature_raw:
        return False
    try:
        timestamp = int(timestamp_raw)
    except ValueError:
        return False
    if abs(_now() - timestamp) > WEBHOOK_TOLERANCE_S:
        return False
    if not signature_raw.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), f"{timestamp_raw}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256=" + expected, signature_raw.lower())


def origin_matches(headers):
    """CSRF defense-in-depth: a browser always sends Origin on cross-origin
    POSTs; server-to-server callers don't send it at all. If Origin is
    present it must match Host. (The app is cookie-less, so classic CSRF
    does not apply — this is the belt in the braces.)
    """
    origin = headers.get("Origin")
    if not origin:
        return True  # non-browser caller
    parsed = urllib.parse.urlparse(origin)
    host = headers.get("Host", "")
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return False
    return parsed.netloc.lower() == host.lower()


# --------------------------------------------------------------------------
# Guarded outbound fetch (the SSRF demo endpoint)
# --------------------------------------------------------------------------

class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects are a classic SSRF pivot (public URL -> 302 -> metadata),
    so the opener never follows them; the caller reports 502 instead."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


_FETCH_OPENER = urllib.request.build_opener(_RefuseRedirect)


def guarded_fetch(url):
    """Fetch a URL under the SSRF policy. Returns a dict for the response
    body, or raises _FetchError(status, payload).

    Checks, in order: scheme allowlist -> no userinfo -> every resolved IP
    passes the blocklist -> no redirects -> size cap. DNS is re-resolved by
    urllib after the check (TOCTOU via DNS rebinding is documented as out of
    scope for a demo without an egress proxy — see SECURITY.md).
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise _FetchError(400, {"error": "invalid url"})
    if parsed.username or parsed.password:
        raise _FetchError(400, {"error": "invalid url"})  # user:pass@ smuggling
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        ips = _resolve_ips(parsed.hostname, port)
    except (socket.gaierror, UnicodeError):
        raise _FetchError(502, {"error": "fetch failed"}) from None
    for ip in ips:
        if _ip_blocked(ip):
            raise _FetchError(403, {"error": "blocked address"})

    try:
        # scheme allowlist + resolver IP policy are enforced above; file://
        # and redirects can never reach urlopen here
        resp = _FETCH_OPENER.open(url, timeout=FETCH_TIMEOUT_S)  # nosec B310
        with resp:
            data = resp.read(MAX_BODY + 1)
            status = resp.status
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise _FetchError(502, {"error": "redirect refused"}) from None
        with exc:
            data = exc.read(MAX_BODY + 1)
            status = exc.code
    except (OSError, ValueError):
        raise _FetchError(502, {"error": "fetch failed"}) from None

    if len(data) > MAX_BODY:
        raise _FetchError(413, {"error": "response too large"})
    return {"ok": True, "bytes": len(data), "status": status}


class _FetchError(Exception):
    def __init__(self, status, payload):
        super().__init__(payload.get("error", "fetch error"))
        self.status = status
        self.payload = payload


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------

# Sent on EVERY response. WHY each: CSP default-deny (this API returns JSON;
# nothing should ever load subresources), nosniff (no MIME confusion),
# frame-ancestors/X-Frame-Options (clickjacking), base-uri (no <base>
# hijack), form-action (no exfil forms), no-referrer (no URL leak),
# Permissions-Policy (no device access), no-store (API data must not sit in
# shared caches).
SECURITY_HEADERS = (
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cache-Control", "no-store"),
)


class Handler(BaseHTTPRequestHandler):
    server_version = "shipstack"
    sys_version = ""  # suppress the Python version from the Server header

    def version_string(self):
        # Fingerprinting hygiene: "shipstack" says nothing about the runtime.
        return "shipstack"

    def _send(self, code, body, extra_headers=()):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        for header, value in SECURITY_HEADERS:
            self.send_header(header, value)
        for header, value in extra_headers:
            self.send_header(header, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _count(self):
        global REQUESTS_SERVED
        with _LOCK:
            REQUESTS_SERVED += 1

    # -- GET routes (strict path match; query strings live in urlparse) ----

    def do_GET(self):  # noqa: N802 (stdlib API)
        self._count()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/healthz":
            self._send(200, {"status": "ok", "env": APP_ENV, "uptime_s": round(_now() - START)})
        elif path == "/api/db":
            self._db()
        elif path == "/api/admin/stats":
            self._admin_stats()
        elif path == "/api/fetch":
            self._fetch(parsed.query)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802 (stdlib API)
        self._count()
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/webhook":
            self._webhook()
        else:
            self._send(404, {"error": "not found"})

    # -- endpoint implementations ------------------------------------------

    def _db(self):
        # SSRF guard on operator config: a hostile/typo'd DB_HOST pointing at
        # the metadata IP is refused before any socket is opened.
        if db_host_blocked():
            self._send(503, {"db": {"reachable": False, "blocked": True}})
            return
        try:
            self._send(200, {"db": postgres_probe()})
        except OSError as exc:
            # Error hygiene: str(exc) contains host/port ("connect to
            # 10.0.0.5:5432 refused") — internal topology never ships to
            # clients; it goes to the server log instead.
            print(f"[app] db probe failed: {exc}", flush=True)
            self._send(503, {"db": {"reachable": False}})

    def _admin_stats(self):
        token = os.environ.get("ADMIN_TOKEN", "")
        if not token:
            # Fail closed: no config => endpoint does not exist, not "open".
            self._send(503, {"error": "admin disabled"})
            return
        auth = self.headers.get("Authorization", "")
        challenge = (("WWW-Authenticate", "Bearer"),)
        if not auth.startswith("Bearer "):
            self._send(401, {"error": "unauthorized"}, challenge)
            return
        supplied = auth[len("Bearer "):]
        # Constant-time compare: `==` on tokens leaks the matching prefix
        # length through timing; compare_digest does not short-circuit.
        if not hmac.compare_digest(supplied.encode(), token.encode()):
            self._send(401, {"error": "unauthorized"}, challenge)
            return
        with _LOCK:
            served = REQUESTS_SERVED
        self._send(200, {"uptime_s": round(_now() - START), "requests_served": served})

    def _webhook(self):
        secret = os.environ.get("WEBHOOK_SECRET", "")
        if not secret:
            # Signature verification is MANDATORY: unset secret => disabled,
            # never "accept unsigned". Same fail-closed shape as admin.
            self._send(503, {"error": "webhook disabled"})
            return
        if not origin_matches(self.headers):
            self._send(403, {"error": "origin mismatch"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, {"error": "invalid body"})
            return
        if length > MAX_BODY:
            self.close_connection = True  # do not let the client stream the rest
            self._send(413, {"error": "body too large"})
            return
        body = self.rfile.read(length)

        ok = webhook_verify(
            secret,
            self.headers.get("X-Webhook-Timestamp", ""),
            self.headers.get("X-Webhook-Signature", ""),
            body,
        )
        if not ok:
            # One generic message for every auth failure (missing header,
            # bad sig, stale/future timestamp) — nothing for an attacker to
            # binary-search over.
            self._send(401, {"error": "invalid signature"})
            return

        try:
            payload = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": "invalid body"})
            return
        if not isinstance(payload, dict):
            self._send(400, {"error": "invalid body"})
            return
        self._send(202, {"accepted": True, "event": payload.get("event")})

    def _fetch(self, query):
        params = urllib.parse.parse_qs(query)
        url = params.get("url", [""])[0]
        try:
            result = guarded_fetch(url)
        except _FetchError as err:
            self._send(err.status, err.payload)
            return
        self._send(200, result)

    # -- logging ------------------------------------------------------------

    def log_message(self, fmt, *args):
        # Only method/path/status ever reach this sink — headers (including
        # Authorization and X-Webhook-Signature) are never logged, so secrets
        # cannot leak into CloudWatch via the access log.
        print(f"[app] {self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    # bind all interfaces: inside ECS/Fargate and compose the task gets its
    # own network namespace and the ALB target must be reachable by IP
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # nosec B104
