#!/bin/bash
# Test script for OpenIDX
# This script is called by the openidx CLI test command

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Parse arguments
TEST_UNIT=false
TEST_INTEGRATION=false
TEST_E2E=false
COVERAGE=false
VERBOSE=false
RUN_PATTERN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --unit|-u)
            TEST_UNIT=true
            shift
            ;;
        --integration|-i)
            TEST_INTEGRATION=true
            shift
            ;;
        --e2e|-e)
            TEST_E2E=true
            shift
            ;;
        --coverage|-c)
            COVERAGE=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --run|-r)
            RUN_PATTERN="$2"
            shift 2
            ;;
        *)
            # Default: unit tests if no specific test type
            if [ "$TEST_UNIT" = false ] && [ "$TEST_INTEGRATION" = false ] && [ "$TEST_E2E" = false ]; then
                TEST_UNIT=true
            fi
            shift
            ;;
    esac
done

echo -e "${BLUE}Running OpenIDX tests...${NC}"

# Run unit tests
if [ "$TEST_UNIT" = true ]; then
    echo -e "${GREEN}Running unit tests...${NC}"

    TEST_ARGS=("test")
    [ "$VERBOSE" = true ] && TEST_ARGS+=("-v")
    [ "$COVERAGE" = true ] && TEST_ARGS+=("-coverprofile=coverage.out" "-covermode=atomic")
    [ -n "$RUN_PATTERN" ] && TEST_ARGS+=("-run=$RUN_PATTERN")
    TEST_ARGS+=("./...")

    go "${TEST_ARGS[@]}"

    if [ "$COVERAGE" = true ]; then
        echo -e "${GREEN}Generating coverage report...${NC}"
        go tool cover -html=coverage.out -o coverage.html
        echo -e "${GREEN}✓ Coverage report: coverage.html${NC}"
    fi
fi

# Run integration tests
if [ "$TEST_INTEGRATION" = true ]; then
    echo -e "${GREEN}Running integration tests...${NC}"

    TEST_ARGS=("test" "-tags=integration")
    [ "$VERBOSE" = true ] && TEST_ARGS+=("-v")
    TEST_ARGS+=("./test/integration/...")

    go "${TEST_ARGS[@]}"
fi

# Run E2E tests
if [ "$TEST_E2E" = true ]; then
    echo -e "${GREEN}Running E2E tests...${NC}"

    if [ -d "$PROJECT_ROOT/test/e2e" ]; then
        cd "$PROJECT_ROOT/test/e2e"
        npm test
        cd "$PROJECT_ROOT"
    else
        echo -e "${YELLOW}Warning: E2E tests not found${NC}"
    fi
fi

echo -e "${GREEN}✓ Tests complete${NC}"
