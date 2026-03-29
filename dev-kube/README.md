# OpenIDX Local Kubernetes Development

Complete local Kubernetes development setup for OpenIDX using kind (Kubernetes in Docker).

## Prerequisites

Install the following tools:

```bash
# kind - Kubernetes in Docker
go install sigs.k8s.io/kind@latest

# kubectl - Kubernetes CLI
# macOS: brew install kubectl
# Linux: curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"

# skaffold - Development workflow
go install github.com/GoogleContainerTools/skaffold@latest

# Docker - Container runtime
# Install from https://docs.docker.com/get-docker/
```

Verify installation:
```bash
kind version
kubectl version --client
skaffold version
docker --version
```

## Quick Start

### One-command startup

```bash
./scripts/dev-kube.sh dev
```

This will:
1. Create a kind cluster (if needed)
2. Build all Docker images
3. Deploy all services
4. Start skaffold dev mode with hot reload

### Quick restart (cluster already exists)

```bash
./scripts/dev-kube.sh start
```

## Commands

| Command | Description |
|---------|-------------|
| `dev` | Full dev mode (create cluster + deploy + skaffold dev) |
| `create-cluster` | Create kind cluster with port mappings |
| `load-images` | Build and load Docker images to kind |
| `deploy` | Deploy services to cluster |
| `port-forward` | Setup port forwarding |
| `start` | Quick start (deploy + port-forward) |
| `cleanup` | Delete cluster and resources |
| `status` | Show cluster status |
| `logs <service>` | Follow logs for a service |
| `restart <svc>` | Restart a deployment |

## Services

Once running, services are accessible at:

| Service | Port | Description |
|---------|------|-------------|
| Admin Console | 3000 | React frontend |
| API Gateway | 9080 | APISIX gateway |
| Identity Service | 8001 | User management |
| Governance Service | 8002 | Access reviews |
| Provisioning Service | 8003 | SCIM provisioning |
| Audit Service | 8004 | Audit logging |
| Admin API | 8005 | Admin operations |
| OAuth Service | 8006 | OAuth/OIDC |

Access the admin console at: http://localhost:3000

## Development Workflow

### Hot Reload with Skaffold

When running `./scripts/dev-kube.sh dev`, skaffold watches for file changes:

- **Go files**: Auto-rebuild and restart affected pods
- **React files**: Auto-sync to admin console pod with Vite HMR

### Manual Deployment

```bash
# 1. Create cluster
./scripts/dev-kube.sh create-cluster

# 2. Deploy infrastructure and services
./scripts/dev-kube.sh deploy

# 3. Setup port forwarding (in another terminal)
./scripts/dev-kube.sh port-forward
```

### View Logs

```bash
# All pods in namespace
kubectl logs -n openidx-dev -f --all-containers

# Specific service
./scripts/dev-kube.sh logs identity-service
# or
kubectl logs -n openidx-dev -f deployment/identity-service
```

### Debug a Pod

```bash
# Shell into a running pod
kubectl exec -it -n openidx-dev deployment/identity-service -- sh

# Describe pod for troubleshooting
kubectl describe -n openidx-dev pod/<pod-name>
```

## Configuration

### Secrets

Development secrets are stored in `dev-kube/secrets-env.yaml`. For production use:

```bash
# Generate secrets
./scripts/generate-secrets.sh

# Or create manually
kubectl create secret generic openidx-secrets \
  -n openidx-dev \
  --from-literal=POSTGRES_PASSWORD=your-password \
  --from-literal=REDIS_PASSWORD=your-password \
  --from-literal=JWT_SECRET=your-jwt-secret
```

### Environment Variables

Edit `dev-kube/configmap.yaml` to change environment variables for all services.

### Resource Limits

Default resource limits are set for development. Adjust in `dev-kube/services.yaml` if needed.

## Storage

Local persistent volumes are created at:
- `/tmp/openidx/postgres` - PostgreSQL data
- `/tmp/openidx/redis` - Redis data
- `/tmp/openidx/elasticsearch` - Elasticsearch data
- `/tmp/openidx/etcd` - etcd data

Data persists across cluster restarts. To clean up:

```bash
sudo rm -rf /tmp/openidx
```

## Troubleshooting

### Cluster won't start

```bash
# Check kind status
kind get clusters

# Delete and recreate
kind delete cluster --name openidx-dev
./scripts/dev-kube.sh create-cluster
```

### Pods not starting

```bash
# Check pod status
kubectl get pods -n openidx-dev

# Describe a problematic pod
kubectl describe -n openidx-dev pod/<pod-name>

# Check logs
kubectl logs -n openidx-dev <pod-name>
```

### Port conflicts

If ports are already in use, edit the port mappings in `scripts/dev-kube.sh` `create_kind_config()` function.

### Images not loading

```bash
# Verify images in kind
docker exec openidx-dev-control-plane crictl images | grep openidx

# Rebuild and load
./scripts/dev-kube.sh load-images
```

### Elasticsearch issues

Elasticsearch may require more memory. Increase limits in `dev-kube/elasticsearch.yaml`.

## Cleaning Up

### Stop everything but keep data

```bash
# Stop port forwarding
pkill -f "kubectl port-forward"

# Scale down deployments
kubectl scale deployment -n openidx-dev --all --replicas=0
```

### Full cleanup

```bash
./scripts/dev-kube.sh cleanup
```

This will prompt to delete:
- Local registry
- Local data volumes

## Production Deployment

For production, use the Helm chart in `deployments/kubernetes/helm/openidx/`:

```bash
helm install openidx ./deployments/kubernetes/helm/openidx \
  --values ./deployments/kubernetes/helm/openidx/values.yaml \
  --namespace openidx \
  --create-namespace
```

## Additional Resources

- [kind documentation](https://kind.sigs.k8s.io/)
- [skaffold documentation](https://skaffold.dev/docs/)
- [kubectl documentation](https://kubernetes.io/docs/reference/kubectl/)
