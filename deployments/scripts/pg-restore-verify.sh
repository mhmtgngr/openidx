#!/usr/bin/env bash
#
# Restore-verify for OpenIDX Postgres backups.
#
# A backup you have never restored is not a backup. By default this restores
# the latest LOCAL dump into a throwaway scratch database inside the same
# Postgres container, sanity-checks it (schema version + table count + a core
# table), then drops the scratch DB. It never touches the live `openidx`
# database.
#
# With --from-offbox it instead fetches the latest encrypted copy that
# pg-backup.sh shipped to OIDX_BACKUP_OFFBOX_TARGET, checks the ciphertext's
# sha256, decrypts it with the age identity in OIDX_BACKUP_AGE_IDENTITY, checks
# the plaintext's sha256, and restores it into a THROWAWAY Postgres container
# (no network, removed afterwards) -- the live container is never given a file
# that came from off the box. That is the disaster-recovery path rehearsed:
# what you would have if this VM were gone.
#
# Run by the oidx-pg-restore-verify.timer (weekly) or by hand. Exit non-zero if
# the backup fails a checksum or doesn't restore into a sane schema.
#
# Env overrides mirror pg-backup.sh, plus:
#   OIDX_RESTORE_SCRATCH_DB   scratch db name (default: openidx_restore_verify)
# and for --from-offbox:
#   OIDX_BACKUP_OFFBOX_TARGET the same target pg-backup.sh uploads to
#   OIDX_BACKUP_AGE_IDENTITY  age identity (private key) file that decrypts it
#   OIDX_RESTORE_IMAGE        image for the throwaway container (default: the
#                             image of OIDX_PG_CONTAINER when it exists, else
#                             docker.io/library/postgres:16-alpine)
set -euo pipefail

CONTAINER="${OIDX_PG_CONTAINER:-oidx-pg}"
DB_USER="${OIDX_DB_USER:-openidx}"
BACKUP_DIR="${OIDX_BACKUP_DIR:-/home/cmit/oidx-runtime/backups}"
SCRATCH="${OIDX_RESTORE_SCRATCH_DB:-openidx_restore_verify}"
OFFBOX_TARGET="${OIDX_BACKUP_OFFBOX_TARGET:-}"
AGE_IDENTITY="${OIDX_BACKUP_AGE_IDENTITY:-}"

FROM_OFFBOX=0
for arg in "$@"; do
  case "$arg" in
    --from-offbox) FROM_OFFBOX=1 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg (expected --from-offbox)" >&2; exit 64 ;;
  esac
done

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }

WORK=""          # temp dir holding the fetched + decrypted copy
THROWAWAY=""     # throwaway container name, when one was started
SCRATCH_IN=""    # container holding the scratch DB to drop
cleanup() {
  if [ -n "$SCRATCH_IN" ] && [ -z "$THROWAWAY" ]; then
    podman exec "$SCRATCH_IN" psql -U "$DB_USER" -d postgres -c "DROP DATABASE IF EXISTS ${SCRATCH};" >/dev/null 2>&1 || true
  fi
  [ -z "$THROWAWAY" ] || podman rm -f "$THROWAWAY" >/dev/null 2>&1 || true
  [ -z "$WORK" ] || rm -rf "$WORK"
}
trap cleanup EXIT

# verify_sha <file> <sidecar>: the sidecar holds the bare hex digest.
verify_sha() {
  local actual
  actual="$(sha256sum "$1" | awk '{print $1}')"
  [ "$actual" = "$(tr -d '[:space:]' < "$2")" ] || { log "ERROR: checksum mismatch for $1"; exit 1; }
}

# restore_and_check <container> <dump>: restore into a fresh scratch DB in the
# container, then the sanity checks every restore must pass.
restore_and_check() {
  local c="$1" dump="$2" ver tables users rlog
  SCRATCH_IN="$c"
  podman exec "$c" psql -U "$DB_USER" -d postgres -c "DROP DATABASE IF EXISTS ${SCRATCH};" >/dev/null
  podman exec "$c" psql -U "$DB_USER" -d postgres -c "CREATE DATABASE ${SCRATCH};" >/dev/null

  # pg_restore may emit non-fatal warnings (roles/extensions) — the
  # post-restore checks are the real gate.
  rlog="$(mktemp "${TMPDIR:-/tmp}/oidx-restore-verify.XXXXXX.log")"
  podman exec -i "$c" pg_restore -U "$DB_USER" -d "${SCRATCH}" --no-owner --no-privileges < "$dump" \
    > "$rlog" 2>&1 || log "pg_restore reported warnings (see $rlog)"

  ver="$(podman exec "$c" psql -U "$DB_USER" -d "${SCRATCH}" -tAc "SELECT MAX(version) FROM schema_migrations;" 2>/dev/null | tr -d '[:space:]')"
  tables="$(podman exec "$c" psql -U "$DB_USER" -d "${SCRATCH}" -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';" 2>/dev/null | tr -d '[:space:]')"
  users="$(podman exec "$c" psql -U "$DB_USER" -d "${SCRATCH}" -tAc "SELECT count(*) FROM users;" 2>/dev/null | tr -d '[:space:]' || echo 'n/a')"

  log "restored: schema v${ver:-?}, ${tables:-0} public tables, users=${users}"
  if [ -z "$ver" ] || [ "${tables:-0}" -lt 20 ]; then
    log "ERROR: restore verification FAILED (schema=$ver tables=$tables)"; exit 1
  fi
}

# --- off-box fetch -----------------------------------------------------------

offbox_mode() {
  case "$1" in
    ssh://*) echo ssh ;;
    file://*|/*) echo local ;;
    *:*) echo rclone ;;
    *) echo unknown ;;
  esac
}

parse_ssh_target() {
  local rest="${1#ssh://}" hostport
  hostport="${rest%%/*}"
  SSH_PATH="/${rest#*/}"
  [ "$hostport" != "$rest" ] || SSH_PATH="."
  SSH_HOST="${hostport%:*}"
  SSH_PORT=22
  [ "$hostport" = "$SSH_HOST" ] || SSH_PORT="${hostport##*:}"
}

# offbox_list: names of the complete copies (those whose .age.sha256 marker,
# uploaded last, is present), one per line.
offbox_list() {
  case "$(offbox_mode "$OFFBOX_TARGET")" in
    rclone) rclone lsf --files-only --include 'openidx-*.dump.age.sha256' "${OFFBOX_TARGET%/}" ;;
    ssh)
      parse_ssh_target "$OFFBOX_TARGET"
      # shellcheck disable=SC2029
      ssh -p "$SSH_PORT" -o BatchMode=yes "$SSH_HOST" \
        "cd $(printf '%q' "$SSH_PATH") && ls -1 -- openidx-*.dump.age.sha256 2>/dev/null" || true ;;
    local)
      (cd "${OFFBOX_TARGET#file://}" && ls -1 -- openidx-*.dump.age.sha256 2>/dev/null) || true ;;
    *) log "ERROR: OIDX_BACKUP_OFFBOX_TARGET '$OFFBOX_TARGET' is not an rclone remote, ssh:// or a directory"; exit 1 ;;
  esac | sed 's/\.sha256$//'
}

# offbox_get <name> <dest-dir>
offbox_get() {
  case "$(offbox_mode "$OFFBOX_TARGET")" in
    rclone) rclone copyto "${OFFBOX_TARGET%/}/$1" "$2/$1" ;;
    ssh)
      parse_ssh_target "$OFFBOX_TARGET"
      rsync -t -e "ssh -p $SSH_PORT -o BatchMode=yes" "$SSH_HOST:$SSH_PATH/$1" "$2/" ;;
    local) cp -p "${OFFBOX_TARGET#file://}/$1" "$2/" ;;
  esac
}

# start_throwaway: a fresh Postgres with no network, removed on exit.
start_throwaway() {
  local image="${OIDX_RESTORE_IMAGE:-}" i
  if [ -z "$image" ]; then
    image="$(podman inspect -f '{{.ImageName}}' "$CONTAINER" 2>/dev/null || true)"
    [ -n "$image" ] || image="docker.io/library/postgres:16-alpine"
  fi
  THROWAWAY="oidx-restore-verify-$(date -u +%Y%m%d%H%M%S)-$$"
  log "starting throwaway container $THROWAWAY ($image, --network none)"
  podman run -d --rm --name "$THROWAWAY" --network none \
    -e POSTGRES_USER="$DB_USER" -e POSTGRES_PASSWORD="$(head -c 18 /dev/urandom | base64)" \
    -e POSTGRES_DB=postgres "$image" >/dev/null
  # The image's entrypoint runs a temporary server for initdb and then
  # restarts; a connection that lands on the temporary one is cut. Wait for
  # the entrypoint to say init is over, then for the real server.
  # (The log is captured first: `podman logs | grep -q` under pipefail fails
  # whenever grep exits before podman has finished writing.)
  local logs
  for i in $(seq 1 90); do
    logs="$(podman logs "$THROWAWAY" 2>&1 || true)"
    if grep -q 'PostgreSQL init process complete' <<<"$logs" \
       && podman exec "$THROWAWAY" pg_isready -U "$DB_USER" -d postgres >/dev/null 2>&1; then
      break
    fi
    [ "$i" -lt 90 ] || { log "ERROR: throwaway Postgres did not become ready"; exit 1; }
    sleep 1
  done
  # The roles the dump's policies and grants name, so the restore reproduces
  # them instead of skipping each with a warning. NOLOGIN: nothing connects.
  podman exec "$THROWAWAY" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -qc \
    "DO \$\$ BEGIN
       IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_app') THEN CREATE ROLE openidx_app NOLOGIN; END IF;
       IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'openidx_bypass') THEN CREATE ROLE openidx_bypass NOLOGIN BYPASSRLS; END IF;
     END \$\$;" >/dev/null
}

if [ "$FROM_OFFBOX" = 1 ]; then
  [ -n "$OFFBOX_TARGET" ] || { log "ERROR: --from-offbox needs OIDX_BACKUP_OFFBOX_TARGET"; exit 1; }
  if [ -z "$AGE_IDENTITY" ] || [ ! -s "$AGE_IDENTITY" ]; then
    log "ERROR: --from-offbox needs OIDX_BACKUP_AGE_IDENTITY, an age identity file"; exit 1
  fi
  command -v age >/dev/null 2>&1 || { log "ERROR: age is not installed"; exit 1; }

  enc="$(offbox_list | sort | tail -1)"
  [ -n "$enc" ] || { log "ERROR: no complete off-box copy found at $OFFBOX_TARGET"; exit 1; }
  log "verifying latest off-box copy: $OFFBOX_TARGET/$enc"

  WORK="$(mktemp -d "${TMPDIR:-/tmp}/oidx-offbox-verify.XXXXXX")"
  chmod 700 "$WORK"
  plain="${enc%.age}"
  offbox_get "$enc" "$WORK"
  offbox_get "${enc}.sha256" "$WORK"
  offbox_get "${plain}.sha256" "$WORK"

  verify_sha "$WORK/$enc" "$WORK/${enc}.sha256"
  log "ciphertext checksum OK"
  age -d -i "$AGE_IDENTITY" -o "$WORK/$plain" "$WORK/$enc"
  rm -f "$WORK/$enc"
  verify_sha "$WORK/$plain" "$WORK/${plain}.sha256"
  log "decrypted; plaintext checksum OK"

  start_throwaway
  restore_and_check "$THROWAWAY" "$WORK/$plain"
  log "off-box restore verify OK ($enc)"
  exit 0
fi

# Names carry a sortable UTC timestamp, so the last one by name is the newest.
latest="$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'openidx-*.dump' 2>/dev/null | sort | tail -1 || true)"
[ -n "$latest" ] || { log "ERROR: no backup found in $BACKUP_DIR"; exit 1; }
log "verifying latest backup: $latest"

# Checksum (if the sidecar exists).
if [ -f "${latest}.sha256" ]; then
  verify_sha "$latest" "${latest}.sha256"
  log "checksum OK"
fi

restore_and_check "$CONTAINER" "$latest"
log "restore verify OK"
