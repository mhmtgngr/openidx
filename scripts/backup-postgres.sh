#!/usr/bin/env bash
# backup-postgres.sh — Dump PostgreSQL database using pg_dump in custom format
#
# Usage:
#   ./scripts/backup-postgres.sh
#
# Environment variables:
#   PGHOST           PostgreSQL host       (default: localhost)
#   PGPORT           PostgreSQL port       (default: 5432)
#   PGUSER           Database user         (default: openidx)
#   PGPASSWORD       Database password     (required)
#   PGDATABASE       Database name         (default: openidx)
#   BACKUP_DIR       Directory for backups (default: ./backups/postgres)
#   RETENTION_DAYS   Days to keep backups  (default: 30)

set -euo pipefail

PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-openidx}"
PGDATABASE="${PGDATABASE:-openidx}"
BACKUP_DIR="${BACKUP_DIR:-./backups/postgres}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

if [ -z "${PGPASSWORD:-}" ]; then
  echo "ERROR: PGPASSWORD is required" >&2
  exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="${PGDATABASE}_${TIMESTAMP}.dump"

mkdir -p "$BACKUP_DIR"

echo "==> Backing up ${PGDATABASE}@${PGHOST}:${PGPORT} ..."
pg_dump \
  -h "$PGHOST" \
  -p "$PGPORT" \
  -U "$PGUSER" \
  -d "$PGDATABASE" \
  -Fc \
  --no-owner \
  --no-acl \
  -f "${BACKUP_DIR}/${FILENAME}"

SIZE=$(du -h "${BACKUP_DIR}/${FILENAME}" | cut -f1)
echo "==> Backup complete: ${BACKUP_DIR}/${FILENAME} (${SIZE})"

# Cleanup old backups
DELETED=$(find "$BACKUP_DIR" -name "*.dump" -mtime +"$RETENTION_DAYS" -delete -print | wc -l)
if [ "$DELETED" -gt 0 ]; then
  echo "==> Removed ${DELETED} backup(s) older than ${RETENTION_DAYS} days"
fi
