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
