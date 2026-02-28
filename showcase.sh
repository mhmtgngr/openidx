#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#
#  OpenIDX Showcase Controller
#  ─────────────────────────────
#  Control script for managing OpenIDX services at openidx.tdv.org
#
#  USAGE:
#    ./showcase.sh start     # Start all services
#    ./showcase.sh stop      # Stop all services
#    ./showcase.sh status    # Check service health
#    ./showcase.sh build     # Build frontend
#    ./showcase.sh logs      # Show service logs
#    ./showcase.sh demo      # Run demo workflow
#
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN="${DOMAIN:-openidx.tdv.org}"
DEPLOY_DIR="$PROJECT_DIR/deployments/docker"
FRONTEND_DIR="$PROJECT_DIR/frontend"
WEB_DIR="$PROJECT_DIR/web/admin-console"
PORTS_CONF="$PROJECT_DIR/deploy/ports.conf"

# Colors
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' B='\033[0;34m' M='\033[0;35m'
C='\033[0;36m' NC='\033[0m' W='\033[1;37m'

# Load port configuration
load_ports_config() {
    if [ -f "$PORTS_CONF" ]; then
        source "$PORTS_CONF"
    else
        # Default ports
        FRONTEND_PORT="${FRONTEND_PORT:-3000}"
        DEV_PORT="${DEV_PORT:-5173}"
        GATEWAY_HTTP_PORT="${GATEWAY_HTTP_PORT:-8088}"
        GATEWAY_HTTPS_PORT="${GATEWAY_HTTPS_PORT:-8443}"
        FRONTEND_ALT_PORT="${FRONTEND_ALT_PORT:-8081}"
        IDENTITY_PORT="${IDENTITY_PORT:-8001}"
        ADMIN_API_PORT="${ADMIN_API_PORT:-8005}"
        OAUTH_PORT="${OAUTH_PORT:-8006}"
        ACCESS_PORT="${ACCESS_PORT:-8007}"
        DEMO_APP_PORT="${DEMO_APP_PORT:-8090}"
        POSTGRES_PORT="${POSTGRES_PORT:-5432}"
        REDIS_PORT="${REDIS_PORT:-6379}"
        ELASTICSEARCH_PORT="${ELASTICSEARCH_PORT:-9200}"
    fi
}

load_ports_config

# Service ports (for health checks) - use loaded config
declare -A SERVICES=(
    [postgres]="${POSTGRES_PORT:-5432}"
    [redis]="${REDIS_PORT:-6379}"
    [identity-service]="${IDENTITY_PORT:-8001}"
    [governance-service]="8002"
    [provisioning-service]="8003"
    [audit-service]="8004"
    [admin-api]="${ADMIN_API_PORT:-8005}"
    [oauth-service]="${OAUTH_PORT:-8006}"
    [access-service]="${ACCESS_PORT:-8007}"
    [gateway-service]="${GATEWAY_HTTP_PORT:-8088}"
    [demo-app]="${DEMO_APP_PORT:-8090}"
    [nginx]="${FRONTEND_PORT:-3000}"
)

# ── Logging ───────────────────────────────────────────────────────
log()      { echo -e "${G}[$(date '+%H:%M:%S')]${NC} ✓ $1"; }
warn()     { echo -e "${Y}[$(date '+%H:%M:%S')]${NC} ⚠ $1"; }
err()      { echo -e "${R}[$(date '+%H:%M:%S')]${NC} ✗ $1"; }
info()     { echo -e "${B}[$(date '+%H:%M:%S')]${NC} ℹ $1"; }
header()   { echo -e "${M}$1${NC}"; }
separator() { echo -e "${C}────────────────────────────────────────────────${NC}"; }

# ── Utility Functions ─────────────────────────────────────────────
check_docker() {
    if ! command -v docker &> /dev/null; then
        err "Docker is not installed or not in PATH"
        exit 1
    fi
    if ! docker info &> /dev/null; then
        err "Docker daemon is not running"
        exit 1
    fi
}

check_port_available() {
    local port="$1"
    local service_name="${2:-service}"

    if nc -z localhost "$port" 2>/dev/null; then
        return 1  # Port is in use
    fi
    return 0  # Port is available
}

find_available_port() {
    local preferred="$1"
    local fallback="${2:-}"

    if check_port_available "$preferred"; then
        echo "$preferred"
    elif [ -n "$fallback" ] && check_port_available "$fallback"; then
        echo "$fallback"
    else
        # Find next available port
        local port=$((preferred + 1))
        while [ $port -le $((preferred + 100)) ]; do
            if check_port_available "$port"; then
                echo "$port"
                return 0
            fi
            port=$((port + 1))
        done
        return 1
    fi
}

scan_ports() {
    header "🔍 Port Availability Scan"
    separator

    local ports=(
        "$FRONTEND_PORT:Frontend"
        "$DEV_PORT:Dev Server"
        "$GATEWAY_HTTP_PORT:API Gateway"
        "$GATEWAY_HTTPS_PORT:Gateway HTTPS"
        "$IDENTITY_PORT:Identity Service"
        "$ADMIN_API_PORT:Admin API"
        "$OAUTH_PORT:OAuth Service"
        "$DEMO_APP_PORT:Demo App"
    )

    local available=0
    local total=${#ports[@]}

    for entry in "${ports[@]}"; do
        IFS=':' read -r port name <<< "$entry"
        if check_port_available "$port"; then
            log "  Port $port ($name) - AVAILABLE"
            available=$((available + 1))
        else
            err "  Port $port ($name) - IN USE"
        fi
    done

    separator
    info "Available: $available/$total ports"
    echo

    # Suggest alternatives if needed
    if [ $available -lt $total ]; then
        header "💡 Port Alternatives"
        separator
        echo "  Frontend:  3000, 8081, 8443, 9001"
        echo "  Gateway:   8088, 9080, 9081"
        echo "  Dev:       5173, 5174, 3000"
        echo
        info "Edit $PORTS_CONF to change ports"
        echo
    fi
}

wait_for_service() {
    local url="$1"
    local name="${2:-service}"
    local max_wait="${3:-30}"
    local count=0

    info "Waiting for $name to be ready..."
    while [ $count -lt $max_wait ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            log "$name is ready!"
            return 0
        fi
        count=$((count + 1))
        sleep 1
        echo -n "."
    done
    echo
    err "$name failed to start within ${max_wait}s"
    return 1
}

# ── Service Management ───────────────────────────────────────────
start_infra() {
    header "🚀 Starting Infrastructure Services"
    separator

    cd "$DEPLOY_DIR"

    # Start infrastructure (postgres, redis, elasticsearch)
    info "Starting PostgreSQL, Redis, and Elasticsearch..."
    docker-compose -f docker-compose.infra.yml up -d

    # Wait for postgres
    wait_for_service http://localhost:5432 "PostgreSQL" 30 || return 1

    # Wait for redis
    wait_for_service http://localhost:6379 "Redis" 10 || return 1

    log "Infrastructure services started"
    echo
}

start_core_services() {
    header "🔧 Starting Core Services"
    separator

    cd "$DEPLOY_DIR"

    # Start core OpenIDX services
    info "Starting Identity, Governance, Provisioning, Audit services..."
    docker-compose up -d identity-service governance-service provisioning-service audit-service

    # Wait for identity service
    wait_for_service http://localhost:8001/health "Identity Service" 30 || return 1
    wait_for_service http://localhost:8005/health "Admin API" 30 || return 1
    wait_for_service http://localhost:8006/health "OAuth Service" 30 || return 1

    log "Core services started"
    echo
}

start_gateway() {
    header "🌐 Starting API Gateway"
    separator

    cd "$DEPLOY_DIR"

    # Start APISIX gateway
    info "Starting APISIX Gateway..."
    docker-compose up -d apisix

    sleep 5

    # Check APISIX health
    if curl -sf http://localhost:9080/apisix/prometheus/metrics > /dev/null 2>&1; then
        log "APISIX Gateway is running"
    else
        warn "APISIX Gateway may not be fully ready"
    fi
    echo
}

start_frontend() {
    header "🎨 Starting Frontend"
    separator

    # Check if frontend is built
    if [ ! -d "$FRONTEND_DIR/assets" ]; then
        warn "Frontend not built. Building now..."
        build_frontend
    fi

    # Start nginx to serve frontend
    cd "$DEPLOY_DIR"
    info "Starting Nginx for $DOMAIN..."
    docker-compose up -d nginx

    sleep 3

    if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
        log "Frontend is running"
    else
        warn "Frontend may not be fully ready"
    fi
    echo
}

start_demo() {
    header "🎬 Starting Demo Application"
    separator

    cd "$DEPLOY_DIR"
    info "Starting demo app..."
    docker-compose up -d demo-app

    wait_for_service http://localhost:8090/health "Demo App" 15 || return 1

    log "Demo application started"
    echo
}

build_frontend() {
    header "🔨 Building Frontend"
    separator

    local admin_console_dist="$WEB_DIR/dist"
    local frontend_dist="$PROJECT_DIR/frontend"

    if [ -f "$WEB_DIR/package.json" ]; then
        info "Building admin console..."
        cd "$WEB_DIR"

        # Install dependencies if needed
        if [ ! -d "node_modules" ]; then
            info "Installing dependencies..."
            npm ci --silent
        fi

        # Build for production with domain configuration
        info "Building for $DOMAIN..."
        VITE_API_URL="https://$DOMAIN" \
        VITE_OAUTH_URL="https://$DOMAIN" \
        VITE_APP_ENV=production \
        npm run build

        log "Admin console built successfully"

        # Copy to frontend deployment directory
        info "Deploying to $frontend_dist..."
        mkdir -p "$frontend_dist"
        cp -r dist/* "$frontend_dist/"

        log "Frontend deployed successfully"
    else
        err "No package.json found in $WEB_DIR"
    fi
    echo
}

# ── Main Commands ────────────────────────────────────────────────
start_all() {
    header "╔══════════════════════════════════════╗"
    header "║   OpenIDX Showcase - $DOMAIN   ║"
    header "╚══════════════════════════════════════╝"
    echo

    check_docker
    start_infra
    start_core_services
    start_gateway
    start_frontend
    start_demo

    header "✨ All Services Started"
    separator
    echo
    info "Access the application at:"
    echo "   • Frontend:    http://localhost:8080"
    echo "   • API:        http://localhost:8088"
    echo "   • Demo App:   http://localhost:8090"
    echo "   • Health:     http://localhost:8001/health"
    echo
}

stop_all() {
    header "🛑 Stopping All Services"
    separator

    cd "$DEPLOY_DIR"
    docker-compose down

    # Also stop infra
    docker-compose -f docker-compose.infra.yml down

    log "All services stopped"
    echo
}

check_service_health() {
    local service="$1"
    local port="$2"
    local health_url="${3:-http://localhost:$port/health}"

    # Check if port is open first
    if nc -z localhost "$port" 2>/dev/null; then
        # Try health endpoint
        if curl -sf "$health_url" > /dev/null 2>&1; then
            echo "healthy"
            return 0
        else
            # Port open but health check failed
            echo "running"
            return 1
        fi
    else
        echo "down"
        return 2
    fi
}

show_status() {
    header "📊 OpenIDX Showcase Status"
    separator
    info "Domain: $DOMAIN"
    echo

    header "Core Services"
    separator

    # Check core services with health endpoints
    local services=(
        "identity-service:8001:http://localhost:8001/health"
        "admin-api:8005:http://localhost:8005/health"
        "oauth-service:8006:http://localhost:8006/health"
        "demo-app:8090:http://localhost:8090/health"
        "gateway-service:8088"
        "access-service:8007"
    )

    local running=0
    local total=${#services[@]}

    for svc in "${services[@]}"; do
        IFS=':' read -r name port health_url <<< "$svc"

        if check_service_health "$name" "$port" "$health_url" | grep -q "healthy"; then
            log "  $name (:$port)"
            running=$((running + 1))
        elif check_service_health "$name" "$port" "$health_url" | grep -q "running"; then
            warn "  $name (:$port) - Running (health check pending)"
            running=$((running + 1))
        else
            err "  $name (:$port) - Down"
        fi
    done

    separator
    info "Core Services: $running/$total running"
    echo

    # Infrastructure
    header "Infrastructure"
    separator

    local infra_running=0
    local infra_total=3

    if nc -z localhost 5432 2>/dev/null; then
        log "  PostgreSQL (:5432)"
        infra_running=$((infra_running + 1))
    else
        err "  PostgreSQL (:5432) - Down"
    fi

    if nc -z localhost 6379 2>/dev/null; then
        log "  Redis (:6379)"
        infra_running=$((infra_running + 1))
    else
        err "  Redis (:6379) - Down"
    fi

    if nc -z localhost 9200 2>/dev/null; then
        log "  Elasticsearch (:9200)"
        infra_running=$((infra_running + 1))
    else
        err "  Elasticsearch (:9200) - Down"
    fi

    separator
    info "Infrastructure: $infra_running/$infra_total running"
    echo

    # Frontend status
    header "Frontend"
    separator

    # Check admin console build
    local admin_console_dist="$WEB_DIR/dist"
    local frontend_dist="$PROJECT_DIR/frontend"

    if [ -d "$admin_console_dist/assets" ]; then
        log "  Admin Console built: Yes"
        log "  Location: $admin_console_dist"
    else
        warn "  Admin Console built: No"
        info "  To build: cd $WEB_DIR && npm run build"
    fi

    if [ -d "$frontend_dist/assets" ]; then
        log "  Frontend deployed: Yes"
    else
        warn "  Frontend deployed: No (copy from $admin_console_dist)"
    fi

    if nc -z localhost "${FRONTEND_PORT:-3000}" 2>/dev/null; then
        log "  Nginx serving: Yes (port ${FRONTEND_PORT:-3000})"
    else
        warn "  Nginx serving: No (port ${FRONTEND_PORT:-3000} not accessible)"
    fi

    # Check if dev server is running
    if nc -z localhost "${DEV_PORT:-5173}" 2>/dev/null; then
        log "  Dev server: Yes (port ${DEV_PORT:-5173})"
    fi
    echo

    # Access URLs
    header "🔗 Access URLs"
    separator
    echo "  • Local Dev:     http://localhost:8080"
    echo "  • Demo App:      http://localhost:8090"
    echo "  • API Gateway:   http://localhost:8088"
    echo "  • OAuth:         http://localhost:8006"
    echo "  • Health Check:  http://localhost:8001/health"
    echo

    # Docker containers
    header "🐳 Docker Containers"
    separator
    docker ps --filter "name=openidx" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || \
        warn "No OpenIDX containers found"
    echo
}

show_logs() {
    local service="${1:-}"

    if [ -z "$service" ]; then
        header "📋 Recent Logs (All Services)"
        separator
        cd "$DEPLOY_DIR"
        docker-compose logs --tail=50 -f
    else
        header "📋 Logs: $service"
        separator
        cd "$DEPLOY_DIR"
        docker-compose logs -f "$service"
    fi
}

run_demo() {
    header "🎬 Running Demo Workflow"
    separator

    # Start all services
    start_all

    # Run demo tests
    info "Running demo tests..."
    if [ -f "$WEB_DIR/e2e/demo-app-login.spec.ts" ]; then
        cd "$WEB_DIR"
        npx playwright test demo-app-login --reporter=list
    fi

    header "Demo Complete"
    echo
    info "Demo is accessible at http://localhost:8090"
    echo
}

show_help() {
    cat << 'HELP'
╔══════════════════════════════════════════════════════════════╗
║          OpenIDX Showcase Controller                           ║
║          Domain: openidx.tdv.org                               ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
    ./showcase.sh [command]

COMMANDS:
    start       Start all services for showcase
    stop        Stop all services
    restart     Restart all services
    status      Show service health status
    build       Build frontend for production
    logs [svc]  Show logs (all or specific service)
    demo        Start services and run demo workflow
    health      Run comprehensive health check
    scan        Scan for available ports
    ports       Show current port configuration

ENVIRONMENT VARIABLES:
    DOMAIN      Override domain (default: openidx.tdv.org)

PORT CONFIGURATION:
    Edit deploy/ports.conf to customize ports for your environment

EXAMPLES:
    ./showcase.sh start              # Start all services
    ./showcase.sh status             # Check service health
    ./showcase.sh scan               # Check port availability
    ./showcase.sh ports              # Show port configuration
    ./showcase.sh logs oauth-service # View OAuth service logs
    DOMAIN=openidx.local ./showcase.sh start

HELP
}

show_ports() {
    header "📋 Port Configuration"
    separator
    info "Config file: $PORTS_CONF"
    echo

    cat "$PORTS_CONF" 2>/dev/null || cat << EOF
# Port configuration not found. Using defaults:
FRONTEND_PORT=${FRONTEND_PORT:-3000}
DEV_PORT=${DEV_PORT:-5173}
GATEWAY_HTTP_PORT=${GATEWAY_HTTP_PORT:-8088}
ADMIN_API_PORT=${ADMIN_API_PORT:-8005}
OAUTH_PORT=${OAUTH_PORT:-8006}
EOF
    echo
}

# ── Main Entry Point ─────────────────────────────────────────────
main() {
    case "${1:-}" in
        start)
            # First scan ports to detect conflicts
            scan_ports
            start_all
            ;;
        stop)
            stop_all
            ;;
        restart)
            stop_all
            sleep 2
            start_all
            ;;
        status|health)
            show_status
            ;;
        build)
            build_frontend
            ;;
        logs)
            show_logs "${2:-}"
            ;;
        demo)
            run_demo
            ;;
        scan)
            scan_ports
            ;;
        ports)
            show_ports
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
}

main "$@"
