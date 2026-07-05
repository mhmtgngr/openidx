#!/usr/bin/env bash
# deploy-box.sh — one-command production deploy for the compose box.
#
# Runs ON the box, from the repo root. Encodes the standard release chain:
#   checkout tag -> pg_dump backup -> build services -> migrate (compose
#   gates app services on it) -> restart -> verify (health, versions,
#   migration level, restart counts, Ziti data plane).
#
# Usage:
#   scripts/deploy-box.sh v1.16.0            # deploy a specific release tag
#   scripts/deploy-box.sh                    # deploy the highest v* tag
#   EXPECT_MIGRATION=68 scripts/deploy-box.sh v1.16.0
#
# Aborts on any failure BEFORE touching the running stack; the backup is
# taken before anything is rebuilt or restarted.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$REPO_ROOT/deployments/docker/docker-compose.prod.yml}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/openidx}"
EXPECT_MIGRATION="${EXPECT_MIGRATION:-}"
PG_USER="${PG_USER:-openidx}"
PG_DB="${PG_DB:-openidx}"
SERVICES=(identity-service governance-service provisioning-service audit-service gateway-service admin-api oauth-service access-service)

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
dc()  { docker compose -f "$COMPOSE_FILE" "$@"; }

cd "$REPO_ROOT"
[ -f "$COMPOSE_FILE" ] || die "compose file not found: $COMPOSE_FILE"
command -v docker >/dev/null || die "docker not installed"

# ---- 1. Resolve and check out the release tag -------------------------------
VERSION="${1:-}"
git fetch --tags origin >/dev/null
if [ -z "$VERSION" ]; then
  VERSION="$(git tag -l 'v*' --sort=-v:refname | head -1)"
  [ -n "$VERSION" ] || die "no v* tags found"
fi
git rev-parse "refs/tags/$VERSION" >/dev/null 2>&1 || die "tag $VERSION does not exist"
log "Deploying $VERSION ($(git rev-parse --short "refs/tags/$VERSION^{}"))"
git checkout -q "refs/tags/$VERSION"

# ---- 2. Backup (before anything changes) ------------------------------------
mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_FILE="$BACKUP_DIR/openidx-pre-$VERSION-$STAMP.dump"
log "Backing up database to $BACKUP_FILE"
dc exec -T postgres pg_dump -U "$PG_USER" -Fc "$PG_DB" > "$BACKUP_FILE"
[ -s "$BACKUP_FILE" ] || die "backup file is empty — aborting before any changes"
log "Backup OK ($(du -h "$BACKUP_FILE" | cut -f1))"

# ---- 3. Build the 8 services + migrate --------------------------------------
log "Building images (8 services + migrate + admin-console)"
dc build --pull migrate "${SERVICES[@]}" admin-console

# ---- 4. Migrate, then roll the services -------------------------------------
# The compose file gates app services on migrate completing successfully,
# so `up -d` runs the migration first and only then swaps the services.
log "Running migrations + rolling services"
dc up -d --remove-orphans
log "Waiting for services to settle"
sleep 20

# ---- 5. Verify ---------------------------------------------------------------
FAIL=0

log "Migration level"
MIG="$(dc exec -T postgres psql -U "$PG_USER" -d "$PG_DB" -tAc \
  'SELECT COALESCE(MAX(version),0) FROM schema_migrations')"
echo "   schema_migrations = $MIG"
if [ -n "$EXPECT_MIGRATION" ] && [ "$MIG" != "$EXPECT_MIGRATION" ]; then
  echo "   MISMATCH: expected $EXPECT_MIGRATION"; FAIL=1
fi

log "Container state (running / restart count)"
for svc in "${SERVICES[@]}"; do
  cid="$(dc ps -q "$svc" || true)"
  if [ -z "$cid" ]; then echo "   $svc: NOT RUNNING"; FAIL=1; continue; fi
  state="$(docker inspect -f '{{.State.Status}} restarts={{.RestartCount}}' "$cid")"
  echo "   $svc: $state"
  case "$state" in running*) ;; *) FAIL=1 ;; esac
done

log "Health endpoints (version stamp)"
# Canonical internal ports (deployments/docker/docker-compose.yml).
declare -A PORTS=(
  [identity-service]=8001 [governance-service]=8002 [provisioning-service]=8003
  [audit-service]=8004 [admin-api]=8005 [oauth-service]=8006
  [access-service]=8007 [gateway-service]=8008
)
for svc in "${SERVICES[@]}"; do
  port="${PORTS[$svc]}"
  body="$(curl -fsS --max-time 5 "http://localhost:${port}/health" 2>/dev/null || true)"
  if [ -z "$body" ]; then echo "   $svc (:$port): NO RESPONSE"; FAIL=1; continue; fi
  echo "   $svc (:$port): $(echo "$body" | head -c 160)"
  case "$body" in *"$VERSION"*) ;; *) echo "      note: version stamp does not mention $VERSION" ;; esac
done

log "Ziti data plane"
curl -fsS --max-time 5 http://localhost:8007/api/v1/access/ziti/status 2>/dev/null | head -c 300 \
  || { echo "   ziti status endpoint unreachable"; FAIL=1; }
echo

if [ "$FAIL" -ne 0 ]; then
  die "verification FAILED — investigate before walking away. Backup: $BACKUP_FILE"
fi
log "Deploy of $VERSION complete. Backup retained at $BACKUP_FILE"
