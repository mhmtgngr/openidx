#!/bin/bash
# Environment check script for OpenIDX
# This script is called by the openidx CLI doctor command

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check result tracking
PASS=0
WARN=0
FAIL=0

# Helper functions
check_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASS++))
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    if [ -n "$2" ]; then
        echo -e "  ${YELLOW}$2${NC}"
    fi
    ((WARN++))
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
    if [ -n "$2" ]; then
        echo -e "  ${RED}$2${NC}"
    fi
    ((FAIL++))
}

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           OpenIDX Environment Check                       ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo

# Check OS
echo -e "${BLUE}System${NC}"
OS_INFO="$(uname -s) $(uname -m)"
check_pass "Operating System: $OS_INFO"

# Check Go
echo -e "\n${BLUE}Required Tools${NC}"
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    check_pass "Go: $GO_VERSION"
else
    check_fail "Go" "Install from: https://go.dev/doc/install"
fi

# Check Docker
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version | awk '{print $3}' | tr -d ',')
    if docker info &> /dev/null; then
        check_pass "Docker: $DOCKER_VERSION"
    else
        check_fail "Docker" "Docker is installed but daemon is not running"
    fi
else
    check_fail "Docker" "Install from: https://docs.docker.com/get-docker/"
fi

# Check Docker Compose
if docker compose version &> /dev/null; then
    COMPOSE_VERSION=$(docker compose version --short 2>/dev/null || echo "v2")
    check_pass "Docker Compose: $COMPOSE_VERSION"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_VERSION=$(docker-compose --version | awk '{print $3}' | tr -d ',')
    check_pass "Docker Compose: $COMPOSE_VERSION"
else
    check_fail "Docker Compose" "Install Docker Desktop or docker-compose standalone"
fi

# Check Node.js
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    check_pass "Node.js: $NODE_VERSION"
else
    check_fail "Node.js" "Install from: https://nodejs.org/"
fi

# Check npm
if command -v npm &> /dev/null; then
    NPM_VERSION=$(npm --version)
    check_pass "npm: v$NPM_VERSION"
else
    check_fail "npm" "Usually installed with Node.js"
fi

# Check Make
if command -v make &> /dev/null; then
    check_pass "Make"
else
    check_fail "Make" "Install with: apt install make (Linux) or via Homebrew (macOS)"
fi

# Optional tools
echo -e "\n${BLUE}Optional Tools${NC}"

if command -v golangci-lint &> /dev/null; then
    LINT_VERSION=$(golangci-lint --version | awk '{print $4}')
    check_pass "golangci-lint: $LINT_VERSION"
else
    check_warn "golangci-lint" "Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
fi

if command -v kubectl &> /dev/null; then
    KUBECTL_VERSION=$(kubectl version --client --short 2>/dev/null | awk '{print $3}')
    check_pass "kubectl: $KUBECTL_VERSION"
else
    check_warn "kubectl" "Install from: https://kubernetes.io/docs/tasks/tools/"
fi

if command -v helm &> /dev/null; then
    HELM_VERSION=$(helm version --short 2>/dev/null)
    check_pass "Helm: $HELM_VERSION"
else
    check_warn "Helm" "Install from: https://helm.sh/docs/intro/install/"
fi

if command -v trivy &> /dev/null; then
    TRIVY_VERSION=$(trivy --version 2>/dev/null | head -1)
    check_pass "Trivy: $TRIVY_VERSION"
else
    check_warn "Trivy" "Install with: go install github.com/aquasecurity/trivy/cmd/trivy@latest"
fi

# Port availability
echo -e "\n${BLUE}Port Availability${NC}"
PORTS=("3000" "5432" "6379" "8001" "8006" "8088" "9200")
PORTS_IN_USE=()

for port in "${PORTS[@]}"; do
    if lsof -i ":$port" &> /dev/null || ss -tuln | grep -q ":$port "; then
        PORTS_IN_USE+=("$port")
    fi
done

if [ ${#PORTS_IN_USE[@]} -eq 0 ]; then
    check_pass "All required ports available"
else
    check_warn "Ports in use" "Ports: ${PORTS_IN_USE[*]}"
fi

# Environment variables
echo -e "\n${BLUE}Environment${NC}"

if [ -f ".env" ]; then
    check_pass ".env file exists"
else
    check_fail ".env file" "Create from .env.example: cp .env.example .env"
fi

# Summary
echo -e "\n${CYAN}Summary${NC}"
echo -e "  ${GREEN}Passed:${NC}  $PASS"
echo -e "  ${YELLOW}Warnings:${NC} $WARN"
echo -e "  ${RED}Failed:${NC}   $FAIL"

if [ $FAIL -gt 0 ]; then
    echo -e "\n${RED}❌ Some checks failed. Please install missing dependencies.${NC}"
    exit 1
elif [ $WARN -gt 0 ]; then
    echo -e "\n${YELLOW}⚠ Some optional tools are missing, but core requirements are met.${NC}"
else
    echo -e "\n${GREEN}✅ All checks passed! Your environment is ready.${NC}"
fi
