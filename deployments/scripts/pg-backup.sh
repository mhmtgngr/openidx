#!/usr/bin/env bash
#
# Automated PostgreSQL backup for the OpenIDX box.
#
# Dumps the OpenIDX database (custom/compressed format) from the Postgres podman
# container to a HOST directory OUTSIDE the container — so backups survive
# container loss — records a sha256 + the schema version alongside each dump,
# and rotates dumps older than the retention window.
#
# Designed to be run by the oidx-pg-backup.timer systemd user unit, or by hand.
# Idempotent and safe to run repeatedly.
#
# Env overrides (all optional):
#   OIDX_PG_CONTAINER            podman container name        (default: oidx-pg)
#   OIDX_DB / OIDX_DB_USER       database + owner role        (default: openidx / openidx)
#   OIDX_BACKUP_DIR              host output dir              (default: /home/cmit/oidx-runtime/backups)
#   OIDX_BACKUP_RETENTION_DAYS   delete dumps older than N    (default: 14)
set -euo pipefail

CONTAINER="${OIDX_PG_CONTAINER:-oidx-pg}"
DB="${OIDX_DB:-openidx}"
DB_USER="${OIDX_DB_USER:-openidx}"
BACKUP_DIR="${OIDX_BACKUP_DIR:-/home/cmit/oidx-runtime/backups}"
RETENTION_DAYS="${OIDX_BACKUP_RETENTION_DAYS:-14}"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }

mkdir -p "$BACKUP_DIR"

# Fail early if the container isn't running.
if ! podman inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
  log "ERROR: container '$CONTAINER' is not running"; exit 1
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out="$BACKUP_DIR/openidx-${ts}.dump"

# pg_dump inside the container (local socket, owner trust), streamed to a host
# file via a .partial rename so a crash never leaves a half-written "good" dump.
log "dumping $DB from $CONTAINER -> $out"
podman exec "$CONTAINER" pg_dump -U "$DB_USER" -d "$DB" -Fc --no-owner --no-privileges > "${out}.partial"
mv "${out}.partial" "$out"

sha256sum "$out" | awk '{print $1}' > "${out}.sha256"
podman exec "$CONTAINER" psql -U "$DB_USER" -d "$DB" -tAc \
  "SELECT MAX(version) FROM schema_migrations;" 2>/dev/null | tr -d '[:space:]' > "${out}.schema_version" || true

size="$(du -h "$out" | awk '{print $1}')"
log "backup OK: $out ($size, schema v$(cat "${out}.schema_version" 2>/dev/null || echo '?'))"

# Rotation: drop dumps + their sidecars older than the retention window.
find "$BACKUP_DIR" -maxdepth 1 -name 'openidx-*.dump*' -type f -mtime +"$RETENTION_DAYS" -print -delete | \
  sed 's/^/  rotated out: /' || true

log "current backups: $(ls -1 "$BACKUP_DIR"/openidx-*.dump 2>/dev/null | wc -l)"
