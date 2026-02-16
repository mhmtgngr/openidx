#!/usr/bin/env bash
# restore-postgres.sh — Restore PostgreSQL database from a pg_dump backup
#
# Usage:
#   ./scripts/restore-postgres.sh <backup-file>
#
# Environment variables:
#   PGHOST       PostgreSQL host   (default: localhost)
#   PGPORT       PostgreSQL port   (default: 5432)
#   PGUSER       Database user     (default: openidx)
#   PGPASSWORD   Database password (required)
#   PGDATABASE   Database name     (default: openidx)

set -euo pipefail

PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-openidx}"
PGDATABASE="${PGDATABASE:-openidx}"

if [ -z "${PGPASSWORD:-}" ]; then
  echo "ERROR: PGPASSWORD is required" >&2
  exit 1
fi

if [ $# -lt 1 ]; then
  echo "Usage: $0 <backup-file>" >&2
  exit 1
fi

BACKUP_FILE="$1"
if [ ! -f "$BACKUP_FILE" ]; then
  echo "ERROR: Backup file not found: ${BACKUP_FILE}" >&2
  exit 1
fi

echo "==> WARNING: This will DROP and RECREATE the database '${PGDATABASE}'."
echo "    Backup file: ${BACKUP_FILE}"
echo ""
read -rp "Continue? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
  echo "Aborted."
  exit 0
fi

echo "==> Terminating active connections to ${PGDATABASE} ..."
psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c \
  "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${PGDATABASE}' AND pid <> pg_backend_pid();" \
  2>/dev/null || true

echo "==> Dropping database ${PGDATABASE} ..."
dropdb -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" --if-exists "$PGDATABASE"

echo "==> Creating database ${PGDATABASE} ..."
createdb -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" "$PGDATABASE"

echo "==> Restoring from ${BACKUP_FILE} ..."
pg_restore \
  -h "$PGHOST" \
  -p "$PGPORT" \
  -U "$PGUSER" \
  -d "$PGDATABASE" \
  --no-owner \
  --no-acl \
  --exit-on-error \
  "$BACKUP_FILE"

echo "==> Restore complete."
