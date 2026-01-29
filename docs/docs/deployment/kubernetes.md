# Kubernetes Deployment (Helm)

Deploy OpenIDX to Kubernetes using the Helm chart.

## Prerequisites

- Kubernetes 1.27+
- Helm 3.12+
- `kubectl` configured for your cluster
- Ingress controller (nginx recommended)
- cert-manager (for TLS)

## Install

```bash
# Add dependency charts
helm dependency update deployments/kubernetes/helm/openidx

# Install with default values
helm install openidx deployments/kubernetes/helm/openidx \
  --namespace openidx \
  --create-namespace
```

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
  --set secrets.encryptionKey="$(openssl rand -base64 24)" \
  --set secrets.keycloakAdminPassword="$(openssl rand -base64 16)"
```

Or create a `values-production.yaml`:

```yaml
secrets:
  postgresPassword: "your-postgres-password"
  redisPassword: "your-redis-password"
  jwtSecret: "your-64-char-hex-secret"
  encryptionKey: "your-32-byte-encryption-key!!!"
  keycloakAdminPassword: "your-keycloak-password"

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
├── Chart.yaml              # Chart metadata and dependencies
├── values.yaml             # Default values
└── templates/
    ├── _helpers.tpl         # Template helpers
    ├── configmap.yaml       # Service configuration
    ├── secrets.yaml         # Kubernetes/External secrets
    ├── serviceaccount.yaml  # Service account
    ├── ingress.yaml         # API + admin console ingress
    ├── hpa.yaml             # Horizontal pod autoscalers
    ├── identity-service.yaml
    ├── governance-service.yaml
    ├── provisioning-service.yaml
    ├── audit-service.yaml
    ├── admin-api.yaml
    ├── oauth-service.yaml
    ├── admin-console.yaml
    └── NOTES.txt            # Post-install notes
```
