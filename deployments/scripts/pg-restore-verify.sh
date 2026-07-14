#!/usr/bin/env bash
#
# Restore-verify for OpenIDX Postgres backups.
#
# A backup you have never restored is not a backup. This restores the latest
# dump into a throwaway scratch database inside the same Postgres container,
# sanity-checks it (schema version + table count + a core table), then drops the
# scratch DB. It never touches the live `openidx` database.
#
# Run by the oidx-pg-restore-verify.timer (weekly) or by hand. Exit non-zero if
# the latest dump fails checksum or doesn't restore into a sane schema.
#
# Env overrides mirror pg-backup.sh, plus:
#   OIDX_RESTORE_SCRATCH_DB   scratch db name (default: openidx_restore_verify)
set -euo pipefail

CONTAINER="${OIDX_PG_CONTAINER:-oidx-pg}"
DB_USER="${OIDX_DB_USER:-openidx}"
BACKUP_DIR="${OIDX_BACKUP_DIR:-/home/cmit/oidx-runtime/backups}"
SCRATCH="${OIDX_RESTORE_SCRATCH_DB:-openidx_restore_verify}"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }

latest="$(ls -t "$BACKUP_DIR"/openidx-*.dump 2>/dev/null | head -1 || true)"
[ -n "$latest" ] || { log "ERROR: no backup found in $BACKUP_DIR"; exit 1; }
log "verifying latest backup: $latest"

# 1. Checksum (if the sidecar exists).
if [ -f "${latest}.sha256" ]; then
  actual="$(sha256sum "$latest" | awk '{print $1}')"
  [ "$actual" = "$(cat "${latest}.sha256")" ] || { log "ERROR: checksum mismatch for $latest"; exit 1; }
  log "checksum OK"
fi

# 2. Fresh scratch DB.
podman exec "$CONTAINER" psql -U "$DB_USER" -d postgres -c "DROP DATABASE IF EXISTS ${SCRATCH};" >/dev/null
podman exec "$CONTAINER" psql -U "$DB_USER" -d postgres -c "CREATE DATABASE ${SCRATCH};" >/dev/null

cleanup() { podman exec "$CONTAINER" psql -U "$DB_USER" -d postgres -c "DROP DATABASE IF EXISTS ${SCRATCH};" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# 3. Restore the host dump into the scratch DB. pg_restore may emit non-fatal
#    warnings (roles/extensions) — the post-restore checks are the real gate.
podman exec -i "$CONTAINER" pg_restore -U "$DB_USER" -d "${SCRATCH}" --no-owner --no-privileges < "$latest" \
  > /tmp/oidx-restore-verify.log 2>&1 || log "pg_restore reported warnings (see /tmp/oidx-restore-verify.log)"

# 4. Sanity checks.
ver="$(podman exec "$CONTAINER" psql -U "$DB_USER" -d "${SCRATCH}" -tAc "SELECT MAX(version) FROM schema_migrations;" 2>/dev/null | tr -d '[:space:]')"
tables="$(podman exec "$CONTAINER" psql -U "$DB_USER" -d "${SCRATCH}" -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';" 2>/dev/null | tr -d '[:space:]')"
users="$(podman exec "$CONTAINER" psql -U "$DB_USER" -d "${SCRATCH}" -tAc "SELECT count(*) FROM users;" 2>/dev/null | tr -d '[:space:]' || echo 'n/a')"

log "restored: schema v${ver:-?}, ${tables:-0} public tables, users=${users}"
if [ -z "$ver" ] || [ "${tables:-0}" -lt 20 ]; then
  log "ERROR: restore verification FAILED (schema=$ver tables=$tables)"; exit 1
fi
log "restore verify OK"
