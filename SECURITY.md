# Security

Security posture of the local parity stack (`app/` + `local/nginx.conf` +
`docker-compose.yml`) and how it maps to the cloud modules. Every control
below is enforced by a test in [`app/tests/test_security.py`](app/tests/test_security.py)
— run with `python -m pytest app/tests -q` from the repo root, no network
needed.

## Threat model

| Endpoint | Threat | Control | Test |
| --- | --- | --- | --- |
| all | Response sniffing/caching of API data | `Cache-Control: no-store` on every response | `test_security_headers_on_every_response` |
| all | Clickjacking / `<base>` hijack / form exfil / MIME confusion | CSP `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `Permissions-Policy` | `test_security_headers_on_every_response` |
| all | Runtime fingerprinting | `Server: shipstack` (no Python version), nginx `server_tokens off` | `test_server_header_suppressed` |
| all | Secret leakage via access logs | Log line is method/path/status only — `Authorization` and signature headers never logged | `test_logs_never_contain_secrets` |
| `/api/db` | Topology leak through error messages | 503 body is `{"db":{"reachable":false}}`; exception detail (host/port) goes to server log only | `test_db_error_does_not_leak_details` |
| `/api/db` | Env-injection SSRF via `DB_HOST` (typo'd/injected value pointing at metadata IP) | Resolver guard: `DB_HOST` must not resolve to private/loopback/link-local/multicast/reserved space unless explicitly allowed via `DB_ALLOWED_CIDRS` | `test_db_blocked_when_host_resolves_private`, `test_db_blocked_loopback_by_default` |
| `/api/admin/stats` | Token guessing via timing side channel | `hmac.compare_digest` (no short-circuit `==`); missing and wrong token return byte-identical 401 + `WWW-Authenticate: Bearer` | `test_admin_uses_constant_time_compare`, `test_admin_wrong_token` |
| `/api/admin/stats` | Endpoint live with no credential configured | Fail closed: `ADMIN_TOKEN` unset ⇒ 503 `admin disabled`, never "open" | `test_admin_disabled_when_token_unset` |
| `/api/webhook` | Unsigned event forgery | HMAC-SHA256 over `"{timestamp}.{body}"` (Stripe-style) is **mandatory**; `WEBHOOK_SECRET` unset ⇒ 503, never accept-unsigned | `test_webhook_valid_signature`, `test_webhook_disabled_without_secret`, `test_webhook_missing_signature` |
| `/api/webhook` | Replay of a captured valid request | Timestamp header with ±300 s tolerance; a valid signature outside the window is rejected | `test_webhook_replay_rejected`, `test_webhook_stale_timestamp`, `test_webhook_future_timestamp` |
| `/api/webhook` | Oracle probing (which check failed?) | One generic 401 `invalid signature` for every auth failure | `test_webhook_bad_signature` |
| `/api/webhook` | Memory exhaustion via huge body | 64 KiB cap ⇒ 413 (app) and `client_max_body_size 1m` (nginx) | `test_webhook_body_too_large` |
| `/api/webhook` | Browser-driven CSRF | Origin-vs-Host check ⇒ 403 when `Origin` present and mismatched; server-to-server callers send no Origin and are unaffected | `test_webhook_origin_mismatch_blocked`, `test_webhook_matching_origin_allowed` |
| `/api/fetch` | SSRF to cloud metadata / internal services | Scheme allowlist (http/https), no userinfo, every resolved IP checked against private/loopback/link-local/multicast/reserved (incl. 169.254.169.254), redirects refused outright, 3 s timeout, 64 KiB response cap | `test_fetch_blocks_metadata_ip`, `test_fetch_rejects_userinfo`, `test_fetch_refuses_redirect`, `test_fetch_caps_response_size` |
| CI | Malicious action update / dependency CVE / committed secret | Actions pinned to full commit SHAs; bandit + pip-audit (zero-dep proof); gitleaks on full history | enforced in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |
| IaC | Encryption off, public buckets, weak TLS | Checkov fail-on-HIGH gate (pre-existing) | enforced in CI |

## Design decisions, stated plainly

**No cookies ⇒ classic CSRF does not apply.** The app is stateless: auth is
a bearer header, webhooks are signed, and nothing sets a cookie. A
cross-site form can't ride ambient credentials that don't exist. The
Origin-vs-Host check on POSTs is defense-in-depth for the case where a
future change *does* introduce cookie auth — it fails the browser case
loudly (403) before that mistake matters.

**Signatures are mandatory, fail-closed.** The failure mode of optional
signatures is silent: someone forgets to configure the secret and the
endpoint quietly accepts forged events. Here, unset `WEBHOOK_SECRET` or
`ADMIN_TOKEN` disables the endpoint (503) — misconfiguration cannot widen
the attack surface.

**SSRF resolver policy.** The guard checks *every* IP the hostname resolves
to, after DNS, against `ipaddress` range predicates (`is_private`,
`is_loopback`, `is_link_local`, `is_multicast`, `is_reserved`,
`is_unspecified`) — not a string match on "169.254.169.254". Redirects are
refused rather than followed, because a public URL that 302s to the
metadata IP is the classic bypass. The same policy is applied to `DB_HOST`
so a poisoned environment variable can't point the DB probe internally;
legitimate private DBs (the compose network) opt in explicitly via
`DB_ALLOWED_CIDRS`, which keeps the default deny visible in config.

**Constant-time comparisons.** Token and signature checks use
`hmac.compare_digest`. `==` on secrets short-circuits at the first
differing byte, which is measurable over repeated requests and leaks the
secret prefix. There is a test that greps for this (`test_admin_uses_constant_time_compare`)
because reviewers should not have to trust prose.

**Error hygiene.** 5xx bodies are fixed strings. `str(exc)` on a
`ConnectionRefusedError` contains internal host and port — that is
topology intelligence, and it goes to the server log (CloudWatch in prod),
never to the client.

## Out of scope (honest limits of a demo stack)

- **TLS termination** — local nginx is plain HTTP; prod is ACM + ALB/CloudFront
  (cert issuance itself is out of scope, see README limitations).
- **DNS-rebinding TOCTOU on `/api/fetch`** — the guard resolves, then
  `urllib` resolves again; a hostile DNS server could answer differently
  between the two. Closing this properly needs a custom resolver-bound
  socket or an egress proxy; for a demo endpoint that is blocked by default
  behind no auth only in local mode, the documented residual risk is
  accepted rather than papered over.
- **Rate limiting at the app** — nginx `limit_req` covers the local edge;
  prod rate limiting is ALB/WAF territory.
- **Secrets management** — compose env vars are local-only; prod uses SSM
  Parameter Store via the `iam-roles` module's scoped read grants.
- **Multi-tenant isolation** — single-tenant demo; no per-user authz model.
