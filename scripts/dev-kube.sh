#!/usr/bin/env bash
# dev-kube.sh - Local Kubernetes development setup for OpenIDX
# Uses kind (Kubernetes in Docker) for local development

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEV_KUBE_DIR="${REPO_ROOT}/dev-kube"
CLUSTER_NAME="openidx-dev"
KIND_CONFIG="${DEV_KUBE_DIR}/kind-config.yaml"
REGISTRY_PORT="5000"
REGISTRY_NAME="kind-registry"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Check dependencies
check_dependencies() {
    local missing=()

    command -v kind >/dev/null 2>&1 || missing+=("kind")
    command -v kubectl >/dev/null 2>&1 || missing+=("kubectl")
    command -v docker >/dev/null 2>&1 || missing+=("docker")
    command -v skaffold >/dev/null 2>&1 || missing+=("skaffold")

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required dependencies: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  kind:    go install sigs.k8s.io/kind@latest"
        echo "  kubectl: https://kubernetes.io/docs/tasks/tools/"
        echo "  docker:  https://docs.docker.com/get-docker/"
        echo "  skaffold: https://skaffold.dev/docs/install/"
        exit 1
    fi
}

# Create kind cluster configuration
create_kind_config() {
    cat > "${KIND_CONFIG}" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
nodes:
  - role: control-plane
    # Port mappings for service access
    extraPortMappings:
      - containerPort: 3000
        hostPort: 3000
        protocol: TCP
      - containerPort: 8001
        hostPort: 8001
        protocol: TCP
      - containerPort: 8002
        hostPort: 8002
        protocol: TCP
      - containerPort: 8003
        hostPort: 8003
        protocol: TCP
      - containerPort: 8004
        hostPort: 8004
        protocol: TCP
      - containerPort: 8005
        hostPort: 8005
        protocol: TCP
      - containerPort: 8006
        hostPort: 8006
        protocol: TCP
      - containerPort: 8080
        hostPort: 8080
        protocol: TCP
      - containerPort: 9080
        hostPort: 9080
        protocol: TCP
      - containerPort: 9180
        hostPort: 9180
        protocol: TCP
    # Mount local directories for persistent volumes
    extraMounts:
      - hostPath: /tmp/openidx/postgres
        containerPath: /tmp/openidx/postgres
      - hostPath: /tmp/openidx/redis
        containerPath: /tmp/openidx/redis
      - hostPath: /tmp/openidx/elasticsearch
        containerPath: /tmp/openidx/elasticsearch
      - hostPath: /tmp/openidx/etcd
        containerPath: /tmp/openidx/etcd
# Enable registry
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${REGISTRY_PORT}"]
      endpoint = ["http://${REGISTRY_NAME}:${REGISTRY_PORT}"]
EOF
}

# Create local registry
create_registry() {
    log_info "Creating local registry..."

    # Check if registry exists
    if docker inspect "${REGISTRY_NAME}" >/dev/null 2>&1; then
        log_info "Registry already exists"
        return
    fi

    docker run -d \
        --restart=always \
        -p "127.0.0.1:${REGISTRY_PORT}:5000" \
        --name "${REGISTRY_NAME}" \
        registry:2

    # Connect registry to kind network
    docker network connect "kind" "${REGISTRY_NAME}" 2>/dev/null || true

    log_success "Registry created at localhost:${REGISTRY_PORT}"
}

# Delete registry
delete_registry() {
    log_info "Removing local registry..."
    docker stop "${REGISTRY_NAME}" 2>/dev/null || true
    docker rm "${REGISTRY_NAME}" 2>/dev/null || true
    log_success "Registry removed"
}

# Create kind cluster
create_kind_cluster() {
    log_info "Creating kind cluster '${CLUSTER_NAME}'..."

    check_dependencies

    # Create local directories for volumes
    mkdir -p /tmp/openidx/{postgres,redis,elasticsearch,etcd}

    # Create kind config
    create_kind_config

    # Delete existing cluster if it exists
    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        log_warn "Cluster '${CLUSTER_NAME}' already exists. Deleting..."
        kind delete cluster --name "${CLUSTER_NAME}"
    fi

    # Create registry
    create_registry

    # Create cluster
    kind create cluster --config "${KIND_CONFIG}"

    # Wait for cluster to be ready
    kubectl wait --for=condition=ready nodes --all --timeout=300s

    log_success "Kind cluster '${CLUSTER_NAME}' created"
}

# Build and load images to kind
load_images() {
    log_info "Building and loading Docker images to kind..."

    check_dependencies

    # Build all images using skaffold
    cd "${REPO_ROOT}"

    # Build images with kind target
    skaffold build --kind --cluster-name="${CLUSTER_NAME}" --push=false

    log_success "Images loaded to kind cluster"
}

# Deploy services to cluster
deploy() {
    log_info "Deploying services to cluster..."

    check_dependencies

    # Ensure cluster context
    kubectl config use-context "kind-${CLUSTER_NAME}"

    # Apply secrets and configs
    log_info "Applying infrastructure..."
    kubectl apply -k "${DEV_KUBE_DIR}"

    # Wait for deployments to be ready
    log_info "Waiting for deployments to be ready..."
    kubectl wait --for=condition=available \
        -n openidx-dev \
        deployment --all \
        --timeout=600s

    log_success "Services deployed"
}

# Port forwarding
port_forward() {
    log_info "Setting up port forwarding..."

    check_dependencies

    # Kill existing port-forward processes
    pkill -f "kubectl port-forward" 2>/dev/null || true

    # Port forward in background
    kubectl port-forward -n openidx-dev svc/identity-service 8001:8001 &
    kubectl port-forward -n openidx-dev svc/governance-service 8002:8002 &
    kubectl port-forward -n openidx-dev svc/provisioning-service 8003:8003 &
    kubectl port-forward -n openidx-dev svc/audit-service 8004:8004 &
    kubectl port-forward -n openidx-dev svc/admin-api 8005:8005 &
    kubectl port-forward -n openidx-dev svc/oauth-service 8006:8006 &
    kubectl port-forward -n openidx-dev svc/apisix 9080:9080 &
    kubectl port-forward -n openidx-dev svc/admin-console 3000:3000 &

    log_success "Port forwarding active"
    log_info "Services accessible at:"
    echo "  Admin Console:  http://localhost:3000"
    echo "  API Gateway:    http://localhost:9080"
    echo "  Identity:       http://localhost:8001"
    echo "  Governance:     http://localhost:8002"
    echo "  Provisioning:   http://localhost:8003"
    echo "  Audit:          http://localhost:8004"
    echo "  Admin API:      http://localhost:8005"
    echo "  OAuth:          http://localhost:8006"
}

# Start skaffold dev mode
dev() {
    log_info "Starting skaffold dev mode..."

    check_dependencies

    # Ensure cluster context
    kubectl config use-context "kind-${CLUSTER_NAME}"

    cd "${REPO_ROOT}"
    skaffold dev --profile=dev
}

# Cleanup - delete cluster
cleanup() {
    log_info "Cleaning up..."

    check_dependencies

    # Kill port-forward processes
    pkill -f "kubectl port-forward" 2>/dev/null || true

    # Delete cluster
    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        kind delete cluster --name "${CLUSTER_NAME}"
        log_success "Cluster '${CLUSTER_NAME}' deleted"
    else
        log_warn "Cluster '${CLUSTER_NAME}' not found"
    fi

    # Optionally delete registry
    read -p "Delete local registry? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        delete_registry
    fi

    # Clean up local volumes
    read -p "Delete local data volumes? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo rm -rf /tmp/openidx
        log_success "Local volumes deleted"
    fi
}

# Show cluster status
status() {
    log_info "Cluster status..."

    check_dependencies

    kubectl config use-context "kind-${CLUSTER_NAME}" 2>/dev/null || {
        log_error "Cluster '${CLUSTER_NAME}' not found"
        exit 1
    }

    echo ""
    echo "=== Nodes ==="
    kubectl get nodes

    echo ""
    echo "=== Pods (openidx-dev) ==="
    kubectl get pods -n openidx-dev

    echo ""
    echo "=== Services (openidx-dev) ==="
    kubectl get svc -n openidx-dev

    echo ""
    echo "=== PVCs (openidx-dev) ==="
    kubectl get pvc -n openidx-dev
}

# Get logs
logs() {
    local service="${1:-}"
    check_dependencies

    if [ -z "$service" ]; then
        log_error "Usage: $0 logs <service-name>"
        echo "Available services:"
        kubectl get deployments -n openidx-dev -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | sed 's/^/  /'
        exit 1
    fi

    kubectl logs -n openidx-dev -f "deployment/${service}"
}

# Main command dispatcher
case "${1:-help}" in
    create-cluster)
        create_kind_cluster
        ;;
    load-images)
        load_images
        ;;
    deploy)
        deploy
        ;;
    port-forward)
        port_forward
        ;;
    dev)
        # Full dev workflow: create cluster, deploy, and start skaffold dev
        create_kind_cluster
        deploy
        dev
        ;;
    start)
        # Quick start - assumes cluster exists
        deploy
        port_forward
        ;;
    cleanup)
        cleanup
        ;;
    status)
        status
        ;;
    logs)
        logs "${2:-}"
        ;;
    restart)
        kubectl rollout restart deployment -n openidx-dev "$2"
        ;;
    *)
        cat <<EOF
OpenIDX Local Kubernetes Development

Usage: $0 <command>

Commands:
    create-cluster    Create kind cluster with port mappings
    load-images       Build and load Docker images to kind
    deploy            Deploy services to cluster
    port-forward      Setup port forwarding for services
    dev               Full dev mode (create + deploy + skaffold dev)
    start             Quick start (deploy + port-forward, assumes cluster exists)
    cleanup           Delete cluster and cleanup resources
    status            Show cluster status
    logs <service>    Follow logs for a service
    restart <svc>     Restart a deployment

Examples:
    $0 dev                # Full development workflow
    $0 create-cluster     # Just create the cluster
    $0 deploy             # Deploy services
    $0 logs identity-service  # View identity service logs

Services:
    identity-service      User identity management
    governance-service    Access governance
    provisioning-service  SCIM provisioning
    audit-service         Audit logging
    admin-api             Admin API
    oauth-service         OAuth/OIDC
    admin-console         React frontend
    apisix                API Gateway
    postgres              PostgreSQL database
    redis                 Cache
    elasticsearch         Audit log storage
    opa                   Policy engine
    etcd                  APISIX configuration storage

EOF
        ;;
esac
