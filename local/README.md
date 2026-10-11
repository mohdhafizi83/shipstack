# Local parity stack

Zero-AWS-account way to exercise the same request flow the cloud modules
describe. Useful for reviewers who want to see the architecture behave, and
for developing the app container against realistic dependencies.

## Run it

```bash
# from the repo root
docker compose up --build
```

Then:

```bash
curl -s localhost:18080/healthz   # -> {"status":"ok","env":"local",...}
curl -s localhost:18080/          # static page (the "CloudFront + S3" half)
curl -s localhost:18080/api/db    # app -> postgres wire handshake (the "ALB + Fargate + RDS" half)
```

## Endpoints

| Endpoint | Method | Without config | With config |
| --- | --- | --- | --- |
| `/healthz` | GET | `200 {status,env,uptime_s}` | same |
| `/api/db` | GET | `200 {db:{reachable,auth}}` (compose allows the private DB range) | `503 {db:{reachable:false}}` on failure — never echoes host/port; `blocked:true` if `DB_HOST` resolves into a guarded range |
| `/api/webhook` | POST | `503 webhook disabled` (signatures are mandatory) | `202` with valid `X-Webhook-Signature` + fresh `X-Webhook-Timestamp`; `401` otherwise |
| `/api/admin/stats` | GET | `503 admin disabled` | `200 {uptime_s,requests_served}` with `Authorization: Bearer $ADMIN_TOKEN` |
| `/api/fetch?url=` | GET | guarded demo: `403 blocked address` for private/loopback/metadata IPs, `502 redirect refused` | `200 {ok,bytes,status}` for public http/https |

Every response carries the security header set (CSP default-deny, nosniff,
DENY framing, no-referrer, no-store); nginx adds rate limiting
(`10r/s` per IP, burst 20) and a 1 MiB body cap at the edge. Full threat
model: [../SECURITY.md](../SECURITY.md). Tests: `python -m pytest app/tests -q`.

Tear down with `docker compose down` (add `-v` to drop the postgres volume).

## How it maps to the modules

| Local container      | Cloud equivalent                          | Module               |
| -------------------- | ----------------------------------------- | -------------------- |
| nginx (port 8080)    | ALB (TLS, health checks) + CloudFront/S3  | `ecs-service`, `s3-static-site` |
| app (Python, :8080)  | Fargate task (same port, same /healthz)   | `ecs-service`        |
| postgres:16          | RDS Postgres (same engine major version)  | `rds-postgres`       |
| compose env vars     | SSM Parameter Store `secrets`             | `iam-roles` (read perms) |

Deliberate differences (local is a parity demo, not a full emulator): no IAM
roles, no TLS termination in nginx, no autoscaling, and `/api/db` does a
Postgres startup-handshake probe instead of SQL queries.
