# Kubernetes Deployment (Helm)

Deploy OpenIDX to Kubernetes using the Helm chart.

## Prerequisites

- Kubernetes 1.27+
- Helm 3.12+
- `kubectl` configured for your cluster
- Ingress controller (nginx recommended)
- cert-manager (for TLS)

## Install

Each tagged release publishes the chart to GHCR as a cosign-signed OCI
artifact (chart version = release version — pick one from the
[releases page](https://github.com/mhmtgngr/openidx/releases); signature
verification is in
[RELEASING.md](https://github.com/mhmtgngr/openidx/blob/main/docs/RELEASING.md)):

```bash
helm install openidx oci://ghcr.io/mhmtgngr/openidx/charts/openidx \
  --version <X.Y.Z> \
  --namespace openidx \
  --create-namespace \
  -f values-production.yaml
```

Or install from a repository checkout:

```bash
# Add dependency charts
helm dependency update deployments/kubernetes/helm/openidx

helm install openidx deployments/kubernetes/helm/openidx \
  --namespace openidx \
  --create-namespace \
  -f values-production.yaml
```

`values-production.yaml` is your install's own file; [Configuration](#configuration)
shows what goes in it. The chart refuses to render without the secrets and
the issuer it names.

The install itself bootstraps the platform: a post-install/pre-upgrade
hook Job runs the database migrations (`helm install` waits for it to
complete — if the install errors, inspect it with
`kubectl -n openidx logs job/openidx-migrate`), and the chart deploys
OPA with the policy it ships, or with the ConfigMap `opa.policyConfigMap`
names. The services consult OPA only when `ENABLE_OPA_AUTHZ=true`, which
is off by default and not ready to turn on yet
([#980](https://github.com/mhmtgngr/openidx/issues/980)).

## Configuration

### Required values

The chart refuses to render until these are set:

- `secrets.postgresPassword`, `secrets.redisPassword` and
  `secrets.encryptionKey`, while the bundled PostgreSQL and Redis are on;
- `config.oauthIssuer`: the public URL of this install's OAuth service, on a
  domain you own, for example `https://auth.example.com`. It is the `iss` of
  every token and the base of the discovery document. Browsers, phones and
  emailed links are sent to it: the access proxy's sign-in page posts
  credentials there, and magic links and push-MFA enrollment point there. It
  has no default. Up to v1.38.0 it defaulted to a domain this project does not
  own, and the chart now refuses any value that names it.

Set them with `--set` flags or a values file:

```bash
helm install openidx deployments/kubernetes/helm/openidx \
  --namespace openidx \
  --create-namespace \
  --set secrets.postgresPassword="$(openssl rand -base64 32)" \
  --set secrets.redisPassword="$(openssl rand -base64 32)" \
  --set secrets.encryptionKey="$(openssl rand -base64 24)" \
  --set config.oauthIssuer="https://auth.example.com"
```

The ingress hosts default to empty, which Kubernetes reads as any host name,
served without TLS. Set `ingress.hosts` and `adminConsole.ingress.hosts` to
your own names, with a `tls` entry for each, as below. The first API host is
also the access proxy's host for vendor-access links unless
`config.accessProxyDomain` is set; with no host, those links are refused.

Or create a `values-production.yaml`:

```yaml
secrets:
  postgresPassword: "your-postgres-password"
  redisPassword: "your-redis-password"
  encryptionKey: "your-32-byte-encryption-key!!!"

config:
  oauthIssuer: "https://auth.example.com"

ingress:
  hosts:
    - host: api.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: api-tls
      hosts:
        - api.example.com

adminConsole:
  ingress:
    hosts:
      - host: admin.example.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: admin-tls
        hosts:
          - admin.example.com
```

Replace `example.com` with your own domain. `config.viteApiUrl` and
`config.viteOauthUrl` are build-time settings of the console image: the
published image calls the origin it is served from, so leave them empty.

```bash
helm install openidx deployments/kubernetes/helm/openidx \
  --namespace openidx \
  -f values-production.yaml
```

The chart generates `INTERNAL_SERVICE_TOKEN`, the secret the services present
to one another on calls no user makes, into the `<release>-internal-token`
Secret on the first install and keeps it on every upgrade. Set
`secrets.internalServiceToken` instead when the chart is rendered without a
cluster (Argo CD, Flux), because each such render would otherwise make a new
one. A value stored under the same key in `<release>-secrets` wins.

### The audit service's edge port

The API Ingress sends `/api/v1/audit` to the audit service's `edge` port
(8014), not its `http` port (8004). The listener behind `edge` serves every
audit route except event ingestion (`POST /api/v1/audit/events`), which is for
the platform's own services: an Ingress cannot match on method, so it cannot
refuse that POST while passing the console's `GET` of the same path. A custom
Ingress or gateway in front of the audit service should do the same.

### An external database

`postgresql.enabled=false` points the chart at a database you run. The
migration Job connects with the DSN in `<release>-db-url` and needs two things
a plain application role does not have:

1. **`CREATE ROLE`, once.** Migration v53 provisions `openidx_app` — the
   `NOSUPERUSER NOBYPASSRLS` runtime role the row-level-security belt is
   enforced against. Either give the migration role `CREATEROLE`, or create the
   role yourself before the first install and v53 will skip it:

    ```sql
    CREATE ROLE openidx_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
    ```

    (With the bundled PostgreSQL a hook Job does exactly this — see
    `migrations.roleBootstrap` — because the subchart creates `openidx`
    without `CREATEROLE`. That Job does not render when
    `postgresql.enabled=false`, since the chart has no superuser credential
    for a database it does not run.)

2. **Ownership of the schema.** Migrations create and alter every table, and the
   RLS belt is `FORCE`d, so the owner is subject to its own policies. The
   migrator sets `app.bypass_rls` for the duration of each migration
   transaction, which is what lets a non-superuser owner run the seeds; you do
   not need to grant `BYPASSRLS` to anything.

`redis.enabled=false` needs nothing beyond a reachable URL.

### External Secrets Operator

For production, use External Secrets Operator to pull secrets from AWS Secrets Manager, HashiCorp Vault, or other providers:

```yaml
externalSecrets:
  enabled: true
  refreshInterval: "1h"
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  remoteKeyPrefix: "openidx"
```

### Scaling

Enable horizontal pod autoscaling:

```yaml
identityService:
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 80

oauthService:
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 80
```

### Disabling Services

Disable services you don't need:

```yaml
governanceService:
  enabled: false

provisioningService:
  enabled: false
```

## Upgrade

```bash
helm upgrade openidx deployments/kubernetes/helm/openidx \
  --namespace openidx \
  -f values-production.yaml
```

An install that kept the old default issuer or ingress hosts has to set its
own before the upgrade renders, including with `--reuse-values`, which carries
the old defaults forward. Relying parties that were configured with the old
issuer need the new one.

## Uninstall

```bash
helm uninstall openidx --namespace openidx
```

## Verify

```bash
# Check pods
kubectl get pods -n openidx

# Check services
kubectl get svc -n openidx

# Check ingress
kubectl get ingress -n openidx

# View logs
kubectl logs -n openidx -l app.kubernetes.io/component=identity-service

# Port-forward for debugging
kubectl port-forward -n openidx svc/openidx-identity-service 8001:8001
```

## Chart Structure

```
helm/openidx/
├── Chart.yaml               # Chart metadata and dependencies
├── values.yaml              # Default values
├── values-prod.yaml         # Production profile (External Secrets, HA)
└── templates/
    ├── _helpers.tpl          # Template helpers
    ├── configmap.yaml        # Service configuration
    ├── secrets.yaml          # Kubernetes/External secrets
    ├── serviceaccount.yaml   # Service account
    ├── ingress.yaml          # API + admin console ingress
    ├── hpa.yaml              # Horizontal pod autoscalers
    ├── pdb.yaml              # Pod disruption budgets
    ├── networkpolicy.yaml    # Optional hardened network profile
    ├── migrate-job.yaml      # DB migrations (post-install/pre-upgrade hook)
    ├── opa.yaml              # OPA policy engine (Deployment + Service)
    ├── servicemonitor.yaml   # Opt-in Prometheus scraping (all 8 services)
    ├── backup-cronjob.yaml   # Opt-in encrypted backups (PVC or S3)
    ├── prometheus-rules.yaml # Alerting rules
    ├── alertmanager-config.yaml
    ├── identity-service.yaml
    ├── governance-service.yaml
    ├── provisioning-service.yaml
    ├── audit-service.yaml
    ├── admin-api.yaml
    ├── oauth-service.yaml
    ├── gateway-service.yaml
    ├── access-service.yaml
    ├── admin-console.yaml
    ├── pam-broker.yaml       # Guacamole-based PAM session brokers
    ├── ziti-fabric.yaml      # OpenZiti controller/router (ZTNA overlay)
    └── NOTES.txt             # Post-install notes
```
