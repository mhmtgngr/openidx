#!/bin/bash
# Database seeding script for OpenIDX
# This script is called by the openidx CLI seed command

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

echo -e "${BLUE}Seeding database with test data...${NC}"

# Check if DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo -e "${RED}Error: DATABASE_URL environment variable is not set${NC}"
    echo -e "  Run: export DATABASE_URL='postgres://user:pass@localhost:5432/openidx?sslmode=disable'"
    exit 1
fi

# Check if database is accessible
if ! psql "$DATABASE_URL" -c '\q' 2>/dev/null; then
    echo -e "${RED}Error: Cannot connect to database${NC}"
    echo -e "  Make sure PostgreSQL is running and DATABASE_URL is correct"
    exit 1
fi

# Run seed migrations
echo -e "${GREEN}Running seed migrations...${NC}"
if [ -f "$PROJECT_ROOT/migrations/010_seed_data.up.sql" ]; then
    psql "$DATABASE_URL" -f "$PROJECT_ROOT/migrations/010_seed_data.up.sql"
    echo -e "${GREEN}✓ Seed data applied${NC}"
else
    echo -e "${YELLOW}Warning: Seed file not found${NC}"
fi

echo -e "${GREEN}✓ Database seeded${NC}"
echo
echo -e "${BLUE}Seed data created:${NC}"
echo -e "  Admin user:     ${GREEN}admin@openidx.local${NC} / ${GREEN}admin123${NC}"
echo -e "  Test user:      ${GREEN}user@openidx.local${NC} / ${GREEN}user123${NC}"
echo -e "  Test roles:     Admin, User, Auditor"
echo -e "  Test policies:  Default access policies"
