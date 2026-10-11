# shipstack

[![CI](https://github.com/mohdhafizi83/shipstack/actions/workflows/ci.yml/badge.svg)](https://github.com/mohdhafizi83/shipstack/actions/workflows/ci.yml)

Reusable Terraform modules for a small production AWS stack — Fargate API
behind an ALB, private Postgres, static site on CloudFront — with the plan and
a policy scan running in CI **before** anything can be applied.

## The problem this solves

Infrastructure review breaks when the only evidence a reviewer gets is an
`apply` log. By then the change is live. Two things fix that, and both are
implemented here:

1. **`terraform plan` in CI on every PR.** Not as a formality — the plan here
   runs with *fake* AWS credentials (see Design notes), so it is fast, safe to
   run on fork PRs, and still shows the full ~30-resource diff of a production
   stack. A reviewer comments on the plan, not on the incident.
2. **A policy scan (Checkov) that fails the build on HIGH findings.** Encryption
   off, public buckets, TLS 1.0, wildcard-admin policies — caught at PR time,
   not at audit time.

The repo is the proof: this README's claims are enforced by
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) on every push.

## What's inside

```
modules/
  ecs-service/      Fargate service + ALB + target group + autoscaling + log group
  rds-postgres/     private, encrypted Postgres with SG-based access control
  s3-static-site/   private S3 + CloudFront OAC (bucket is never public)
  iam-roles/        least-privilege task/execution role builders
  policy-doc/       one audited code path for every IAM policy document
examples/production/  all modules wired with realistic variables + commented remote-state backend
local/ + docker-compose.yml  local parity stack (app + postgres + nginx), zero cloud account needed
.github/
  workflows/ci.yml            fmt / validate / plan / checkov  ← the tests
  deploy.yml.example          PR-plan / main-apply pattern with OIDC (documented, not active)
```

## Running it

**CI checks locally** (needs Terraform ≥ 1.7 only):

```bash
cd examples/production
terraform init -backend=false
terraform plan -var ci_plan_mode=true   # works with no AWS account
```

**Local parity stack** (needs Docker):

```bash
docker compose up --build
curl -s localhost:18080/healthz   # {"status":"ok","env":"local",...}
curl -s localhost:18080/api/db    # app performs a real Postgres handshake
```

See [`local/README.md`](local/README.md) for how each container maps to a module.

## Design notes

**Least privilege as a module interface.** `iam-roles` takes *resource ARNs*,
not policy JSON: you hand it the SSM parameter ARNs the task may read, the ECR
repos it may pull, the one log group it may write. The only `"Resource": "*"`
left is `ecr:GetAuthorizationToken`, which genuinely has no resource-level
scoping (AWS docs). Every statement carries a `Sid` and flows through
`policy-doc`, so there is exactly one place to audit how policies get built.
Trust policies pin `aws:SourceAccount`.

**The DB is never reachable from the internet.** `publicly_accessible = false`,
private subnets only, and ingress is a list of *security groups* (a joiner SG
the tasks attach), never a CIDR. `rds.force_ssl = 1` in the parameter group.
The joiner-SG pattern also breaks the module cycle you'd otherwise hit wiring
db → SG ← service.

**S3 stays private; CloudFront is the only door.** The static-site bucket uses
Origin Access Control with a bucket policy conditioned on the distribution's
own ARN (`aws:SourceArn`), plus full public-access-block. There is no
public-read path at all — a bucket policy typo can't expose the site because
the policy can only ever name the distribution.

**Blue-green-capable by construction.** The task definition is referenced by
*family*, not revision, and the service runs `maximum_percent=200 /
minimum_healthy_percent=100` with a deployment circuit breaker + automatic
rollback. Every deploy registers a new revision under the same family; the
old tasks drain only after the ALB health check passes on the new ones. The
family + target-group layout is also exactly what a CodeDeploy blue/green
cutover would extend.

**Plan-time-safe by discipline.** No module uses a data source that calls AWS
APIs (`aws_caller_identity`, `aws_vpc`, AMI lookups are all absent — the region
and account id are *variables*). That's what lets CI plan with fake creds. It's
a constraint that pays for itself: the plan is hermetic and fork-PR-safe.

**Cost knobs.** `examples/production` has one `size` variable:
- `size = "dev"` → `db.t4g.micro`, single-AZ, 1×256/512 tasks, Terraform-managed
  DB password in Secrets Manager, deletion protection off, final snapshot skipped.
- `size = "prod"` → `db.r6g.large` Multi-AZ, 3×1024/2048 tasks with autoscaling
  to 10, deletion protection on, password managed outside state.
CloudFront sits at `PriceClass_100` (no edge premium unless you need it), log
retention and noncurrent-version expiry are bounded so logging can't silently
grow the bill.

## Sample plan summary

Real output from `terraform plan` on `examples/production` (size = prod):

```
Plan: 56 to add, 0 to change, 0 to destroy.
```

(`size = "dev"` plans 59 — the extra 3 are the Terraform-managed master
password bootstrap: `random_password` + Secrets Manager secret + version.)

## Honest limitations

- **AWS-only.** No multi-cloud abstraction, and no multi-region support —
  one region per state file, by design, not by omission oversight.
- **No NAT gateway** in the example network (private subnets have no route to
  the internet, so tasks can't pull images in a real apply). Real deployments
  add one; the example keeps the plan honest about what's there.
- **ACM certs are placeholder ARNs** — certificate issuance (DNS validation
  pipeline) is deliberately out of scope.
- **No VPC endpoints** for ECR/S3/SSM/CloudWatch, which real prod should have
  to keep traffic off the NAT path.
- **Checkov only** (not tfsec too): one scanner keeps CI fast and gives one
  finding backlog to triage.
- The local stack is a *parity demo*, not a full emulator — no IAM, no ALB
  behavior beyond proxying.

## License

MIT — see [LICENSE](LICENSE).
