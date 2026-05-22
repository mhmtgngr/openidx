# OpenIDX Production Deployment Runbook

This guide walks an operator from an empty AWS account to a running, hardened
OpenIDX deployment on EKS. It ties together the three pieces that already live
in this repo:

- **Terraform** (`deployments/terraform/`) — VPC, EKS, RDS (PostgreSQL),
  ElastiCache (Redis).
- **Helm chart** (`deployments/kubernetes/helm/openidx/`) — all services +
  admin console, with `values-prod.yaml` for production posture.
- **Container images** — published by `.github/workflows/docker.yml` to
  `ghcr.io/mhmtgngr/openidx/<service>` as multi-arch (amd64/arm64) manifests on
  every push to `main` and on `vX.Y.Z` tags.

> The services **refuse to start in production with insecure config**. Each
> service calls `config.ValidateProductionConfig` at startup (see
> `internal/common/config/security_check.go`), which blocks boot when
> `APP_ENV=production` and any critical setting is unsafe. The
> [production config checklist](#production-config-checklist) lists exactly
> what must be set.

---

## Prerequisites

| Tool | Version | Used for |
|------|---------|----------|
| Terraform | ≥ 1.7 | provision AWS infrastructure |
| Helm | ≥ 3.14 | deploy the chart |
| kubectl | matching cluster (1.29) | operate the cluster |
| AWS CLI | v2 | credentials + `eks update-kubeconfig` |

You also need: an AWS account with admin access for the bootstrap, a DNS zone
for your public hostnames, and a TLS story (this guide uses cert-manager +
Let's Encrypt).

---

## Step 1 — Provision infrastructure (Terraform)

### 1a. Bootstrap the state backend (once per account/region)

The root config stores state in an S3 bucket with a DynamoDB lock table. Those
must exist first, so create them with the local-backend bootstrap config:

```bash
cd deployments/terraform/bootstrap
terraform init
terraform apply        # creates openidx-terraform-state + openidx-terraform-locks
```

Defaults (`variables.tf`): region `eu-west-1`, bucket `openidx-terraform-state`,
lock table `openidx-terraform-locks`. Override with `-var` if needed, and keep
this config's local `terraform.tfstate` somewhere safe.

### 1b. Provision the platform

```bash
cd deployments/terraform
terraform init                       # uses the S3 backend created above
terraform apply -var environment=prod
```

This creates the VPC, the EKS cluster (`cluster_version = 1.29`), an RDS
PostgreSQL instance, and an ElastiCache Redis cluster. Note the outputs:

```bash
terraform output      # cluster_endpoint, cluster_name, rds_endpoint, redis_endpoint
```

### 1c. Connect kubectl

```bash
aws eks update-kubeconfig --name "$(terraform output -raw cluster_name)" --region eu-west-1
kubectl get nodes
```

---

## Step 2 — Cluster prerequisites

Install the controllers the chart depends on (Helm references an `nginx`
ingress class, cert-manager cluster-issuer annotations, and — in prod — the
External Secrets Operator):

```bash
# Ingress
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx -n ingress-nginx --create-namespace

# TLS (cert-manager) — then create a ClusterIssuer named "letsencrypt-prod"
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager -n cert-manager --create-namespace \
  --set crds.enabled=true

# External Secrets Operator (prod pulls secrets from AWS Secrets Manager)
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace
```

Then create a `ClusterSecretStore` (named `openidx-secret-store` to match
`values-prod.yaml`) pointing at AWS Secrets Manager, using IRSA for access.

---

## Step 3 — Secrets

In production the chart sets `externalSecrets.enabled=true`, so it does **not**
read plaintext secrets from `values.yaml`. Instead it creates `ExternalSecret`
resources that pull the keys below from your secret store, under the prefix
`openidx/prod` (the `externalSecrets.remoteKeyPrefix`):

| Secret store key | Becomes env var | Notes |
|------------------|-----------------|-------|
| `openidx/prod/database-url` | `DATABASE_URL` | full DSN to RDS, e.g. `postgres://USER:PASS@HOST:5432/openidx?sslmode=verify-full` |
| `openidx/prod/redis-url` | `REDIS_URL` | `rediss://:PASS@HOST:6379` (TLS scheme) |
| `openidx/prod/jwt-secret` | `JWT_SECRET` | ≥ 32 random bytes |
| `openidx/prod/encryption-key` | `ENCRYPTION_KEY` | ≥ 32 random bytes |
| `openidx/prod/postgres-password` | `POSTGRES_PASSWORD` | RDS password |
| `openidx/prod/redis-password` | `REDIS_PASSWORD` | ElastiCache auth token |

Generate strong values:

```bash
openssl rand -base64 48   # for each of jwt-secret, encryption-key, access-session-secret
```

Put them in AWS Secrets Manager, e.g.:

```bash
aws secretsmanager create-secret --name openidx/prod/jwt-secret \
  --secret-string "$(openssl rand -base64 48)"
# ...repeat for the other keys, and store database-url / redis-url with the
# RDS / ElastiCache endpoints from Terraform (use sslmode=verify-full and rediss://).
```

The remaining production-critical settings (`APP_ENV`, `CSRF_ENABLED`,
`CORS_ALLOWED_ORIGINS`, `TLS_ENABLED`, `AUDIT_STREAM_ALLOWED_ORIGINS`, etc.) are
plain config, not secrets — set them via the chart (see next step and the
checklist).

---

## Step 4 — Deploy with Helm

Edit `deployments/kubernetes/helm/openidx/values-prod.yaml`:

- Replace the placeholder hosts (`api.openidx.example.com`,
  `admin.openidx.example.com`) and `auditService.allowedOrigins`.
- Set `externalSecrets.secretStoreRef.name` to your `ClusterSecretStore`.
- Pin every `image.tag` to the release you are deploying (a `vX.Y.Z` tag that
  the image pipeline has published — never `latest` in prod).

Then:

```bash
cd deployments/kubernetes/helm/openidx
helm dependency build                 # vendors the postgresql/redis/etc subcharts (Chart.lock)
helm upgrade --install openidx . \
  -n openidx --create-namespace \
  -f values-prod.yaml
```

`values-prod.yaml` disables the in-cluster postgresql/redis/elasticsearch
subcharts (you're using managed RDS/ElastiCache), enables autoscaling and
NetworkPolicies, and turns on external secrets.

---

## Step 5 — Verify

```bash
kubectl -n openidx get pods            # all Running / Ready
kubectl -n openidx logs deploy/openidx-identity-service | head   # no "production security validation failed"
kubectl -n openidx get ingress        # api + admin hosts, TLS secrets populated
```

If a service crash-loops with `production security validation failed`, read the
error — it lists exactly which checklist item is wrong.

Health endpoints: each service serves `GET /health` (liveness) and exposes
Prometheus metrics at `GET /metrics`.

---

## Production config checklist

`ValidateProduction()` (in `internal/common/config/config.go`) **blocks
startup** when `APP_ENV=production` and any of these are unsafe. Defaults shown
are the development defaults that are unsafe for prod.

| Env var | Dev default | Production requirement |
|---------|-------------|------------------------|
| `APP_ENV` | `development` | `production` (enables the gate) |
| `ACCESS_SESSION_SECRET` | `change-me-in-production-32bytes!` | secure random, ≥ 32 bytes, no `change-me` |
| `JWT_SECRET` | _(empty)_ | secure random, ≥ 32 bytes, no `change` |
| `ENCRYPTION_KEY` | _(empty)_ | secure random, ≥ 32 bytes, no `change` |
| `CORS_ALLOWED_ORIGINS` | `*` | explicit origin list (not `*`) |
| `CSRF_ENABLED` | `false` | `true` |
| `DATABASE_SSL_MODE` | `disable` | `require`, `verify-ca`, or `verify-full` |
| `REDIS_TLS_ENABLED` | `false` | `true` (use a `rediss://` URL) |
| `TLS_ENABLED` | `false` | `true` (inter-service TLS) |
| `AUDIT_STREAM_ALLOWED_ORIGINS` | _(empty)_ | explicit WebSocket origins (not empty, not `*`) |
| `DEBUG_OTP_IN_RESPONSE` | `false` | `false` — must never be `true` |

There are also non-blocking advisories from `ProductionWarnings()` covering the
same surface; check service logs at startup.

---

## Observability

The Helm chart ships PrometheusRules and (via `monitoring.*` values) wires the
services' `/metrics` endpoints for scraping. For a self-contained local stack,
`docker compose -f deployments/docker/docker-compose.yml up` brings up the
backends:

| UI | URL (local compose) |
|----|---------------------|
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3001 (admin / admin) |
| Jaeger | http://localhost:16686 |

Traces are emitted when `TRACING_ENABLED=true` (services export OTLP to
`jaeger:4317`).

---

## Upgrades and rollback

```bash
# Upgrade to a new release tag
helm upgrade openidx . -n openidx -f values-prod.yaml   # after bumping image.tag

# Roll back to the previous revision
helm rollback openidx -n openidx
```

Database migrations run on service startup; deploy is forward-only — take an RDS
snapshot before major upgrades.
