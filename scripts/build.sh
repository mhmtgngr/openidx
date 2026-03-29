#!/bin/bash
# Build script for OpenIDX services
# This script is called by the openidx CLI build command

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_OUTPUT="$PROJECT_ROOT/bin"

# Parse arguments
BUILD_WEB=false
BUILD_SERVICES=false
BUILD_ALL=false
TARGET_SERVICE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --web|-w)
            BUILD_WEB=true
            shift
            ;;
        --services|-s)
            BUILD_SERVICES=true
            shift
            ;;
        --all|-a)
            BUILD_ALL=true
            shift
            ;;
        --output|-o)
            TARGET_SERVICE="$2"
            BUILD_SERVICES=true
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# Default: build all if nothing specified
if [ "$BUILD_WEB" = false ] && [ "$BUILD_SERVICES" = false ] && [ "$BUILD_ALL" = false ]; then
    BUILD_ALL=true
fi

if [ "$BUILD_ALL" = true ]; then
    BUILD_WEB=true
    BUILD_SERVICES=true
fi

echo -e "${BLUE}Building OpenIDX...${NC}"

# Create build output directory
mkdir -p "$BUILD_OUTPUT"

# Build Go services
if [ "$BUILD_SERVICES" = true ]; then
    if [ -n "$TARGET_SERVICE" ]; then
        echo -e "${GREEN}Building service: $TARGET_SERVICE${NC}"
        go build -o "$BUILD_OUTPUT/$TARGET_SERVICE" "./cmd/$TARGET_SERVICE"
        echo -e "${GREEN}✓ Built $TARGET_SERVICE${NC}"
    else
        echo -e "${GREEN}Building Go services...${NC}"
        SERVICES=(
            "identity-service"
            "governance-service"
            "provisioning-service"
            "audit-service"
            "gateway-service"
            "admin-api"
            "oauth-service"
            "access-service"
        )

        for service in "${SERVICES[@]}"; do
            if [ -d "$PROJECT_ROOT/cmd/$service" ]; then
                echo -e "  Building $service..."
                go build -o "$BUILD_OUTPUT/$service" "./cmd/$service"
            fi
        done
        echo -e "${GREEN}✓ All services built${NC}"
    fi
fi

# Build web applications
if [ "$BUILD_WEB" = true ]; then
    echo -e "${GREEN}Building web applications...${NC}"
    if [ -d "$PROJECT_ROOT/web/admin-console" ]; then
        cd "$PROJECT_ROOT/web/admin-console"
        npm run build
        echo -e "${GREEN}✓ Web console built${NC}"
        cd "$PROJECT_ROOT"
    fi
fi

echo -e "${GREEN}✓ Build complete${NC}"
