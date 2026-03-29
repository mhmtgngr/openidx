#!/bin/bash
# Database seeding script for OpenIDX
#
# Seed data is automatically loaded on first `docker compose up` via
# deployments/docker/init-db.sql. This script re-applies seed data
# to a running database for reset scenarios.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Default to docker-compose postgres
DATABASE_URL="${DATABASE_URL:-postgres://openidx:$(grep POSTGRES_PASSWORD "$PROJECT_ROOT/.env" 2>/dev/null | cut -d= -f2)@localhost:5432/openidx?sslmode=disable}"

echo -e "${BLUE}OpenIDX Database Seeder${NC}"
echo

# Check psql
if ! command -v psql &> /dev/null; then
    echo -e "${YELLOW}psql not found. Trying via docker...${NC}"
    PSQL_CMD="docker exec openidx-postgres psql -U openidx -d openidx"
else
    PSQL_CMD="psql $DATABASE_URL"
fi

# Check connectivity
if ! $PSQL_CMD -c '\q' 2>/dev/null; then
    echo -e "${RED}Error: Cannot connect to database${NC}"
    echo -e "  Make sure PostgreSQL is running (docker compose up -d postgres)"
    echo -e "  Or set DATABASE_URL environment variable"
    exit 1
fi

echo -e "${GREEN}Connected to database${NC}"

# Check if seed data already exists
ADMIN_EXISTS=$($PSQL_CMD -tAc "SELECT count(*) FROM users WHERE email='admin@openidx.local'" 2>/dev/null || echo "0")

if [ "$ADMIN_EXISTS" -gt 0 ] && [ "${1:-}" != "--force" ]; then
    echo -e "${YELLOW}Seed data already present (admin user exists)${NC}"
    echo -e "  Use ${BLUE}--force${NC} to re-apply"
    echo
    echo -e "${BLUE}Existing seed credentials:${NC}"
else
    echo -e "${GREEN}Applying seed data from init-db.sql...${NC}"
    $PSQL_CMD -f "$PROJECT_ROOT/deployments/docker/init-db.sql" 2>/dev/null || true
    echo -e "${GREEN}Done${NC}"
    echo
    echo -e "${BLUE}Seed credentials:${NC}"
fi

echo -e "  Admin:         ${GREEN}admin@openidx.local${NC}"
echo -e "  Test users:    jsmith, jdoe, bwilson, amartin"
echo -e "  OAuth clients: admin-console (public), api-service (confidential), test-client"
echo -e "  API client:    ${GREEN}api-service${NC} / ${GREEN}api-service-secret${NC}"
echo -e "  Roles:         admin, user, manager, auditor, developer"
echo -e "  Groups:        Administrators, Developers, DevOps, QA, Finance, HR"
