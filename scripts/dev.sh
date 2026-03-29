#!/bin/bash
# Development environment startup script for OpenIDX
# This script is called by the openidx CLI dev command

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo -e "${BLUE}Starting OpenIDX development environment...${NC}"

# Check if docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running. Please start Docker first.${NC}"
    exit 1
fi

# Check if docker compose is available
if docker compose version > /dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
elif docker-compose version > /dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
else
    echo -e "${RED}Error: docker compose is not installed${NC}"
    exit 1
fi

# Parse arguments
COMPOSE_FILE="$PROJECT_ROOT/deployments/docker/docker-compose.yml"
INFRA_ONLY=false
BACKGROUND=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --infra|-i)
            COMPOSE_FILE="$PROJECT_ROOT/deployments/docker/docker-compose.infra.yml"
            INFRA_ONLY=true
            shift
            ;;
        --background|-b)
            BACKGROUND=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Start services
echo -e "${GREEN}Starting services with docker compose...${NC}"
cd "$PROJECT_ROOT"

if [ "$INFRA_ONLY" = true ]; then
    $DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d
    echo -e "${GREEN}Infrastructure services started${NC}"
else
    $DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d

    if [ "$BACKGROUND" = false ]; then
        echo -e "${GREEN}Services started in foreground${NC}"
        $DOCKER_COMPOSE -f "$COMPOSE_FILE" up
    else
        echo -e "${GREEN}Services started in background${NC}"
    fi
fi
