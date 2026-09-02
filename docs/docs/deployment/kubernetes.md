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
  --create-namespace
```

Or install from a repository checkout:

```bash
# Add dependency charts
helm dependency update deployments/kubernetes/helm/openidx

# Install with default values
helm install openidx deployments/kubernetes/helm/openidx \
  --namespace openidx \
  --create-namespace
```

The install itself bootstraps the platform: a post-install/pre-upgrade
hook Job runs the database migrations (`helm install` waits for it to
complete — if the install errors, inspect it with
`kubectl -n openidx logs job/openidx-migrate`), and the chart deploys
OPA for the policy engine — load your policies into the ConfigMap named
by `opa.policyConfigMap`, because governance fails closed while OPA has
no policies.

## Configuration

### Required Secrets

You must provide secrets either via `--set` flags or a values file:

```bash
helm install openidx deployments/kubernetes/helm/openidx \
  --namespace openidx \
  --create-namespace \
  --set secrets.postgresPassword="$(openssl rand -base64 32)" \
  --set secrets.redisPassword="$(openssl rand -base64 32)" \
  --set secrets.jwtSecret="$(openssl rand -hex 32)" \
  --set secrets.encryptionKey="$(openssl rand -base64 24)"
```

Or create a `values-production.yaml`:

```yaml
secrets:
  postgresPassword: "your-postgres-password"
  redisPassword: "your-redis-password"
  jwtSecret: "your-64-char-hex-secret"
  encryptionKey: "your-32-byte-encryption-key!!!"

config:
  oauthIssuer: "https://auth.yourdomain.com"
  viteApiUrl: "https://api.yourdomain.com"
  viteOauthUrl: "https://auth.yourdomain.com"

ingress:
  hosts:
    - host: api.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: api-tls
      hosts:
        - api.yourdomain.com

adminConsole:
  ingress:
    hosts:
      - host: admin.yourdomain.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: admin-tls
        hosts:
          - admin.yourdomain.com
```

```bash
helm install openidx deployments/kubernetes/helm/openidx \
  --namespace openidx \
  -f values-production.yaml
```

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
