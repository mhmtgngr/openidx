#!/usr/bin/env bash
#
# Automated PostgreSQL backup for the OpenIDX box.
#
# Dumps the OpenIDX database (custom/compressed format) from the Postgres podman
# container to a HOST directory OUTSIDE the container — so backups survive
# container loss — records a sha256 + the schema version alongside each dump,
# and rotates dumps older than the retention window.
#
# Optionally (OIDX_BACKUP_OFFBOX_TARGET set) it then encrypts the new dump with
# age to the recipients in OIDX_BACKUP_AGE_RECIPIENTS and ships it OFF the box,
# so a lost VM is not a lost database. It never uploads an unencrypted dump:
# with a target but no usable recipients file, the off-box step fails and says
# so. See deployments/scripts/README.md for setup and the restore drill.
#
# Designed to be run by the oidx-pg-backup.timer systemd user unit, or by hand.
# Idempotent and safe to run repeatedly.
#
# Env overrides (all optional):
#   OIDX_PG_CONTAINER            podman container name        (default: oidx-pg)
#   OIDX_DB / OIDX_DB_USER       database + owner role        (default: openidx / openidx)
#   OIDX_BACKUP_DIR              host output dir              (default: /home/cmit/oidx-runtime/backups)
#   OIDX_BACKUP_RETENTION_DAYS   delete dumps older than N    (default: 14)
#
# Off-box copy (all optional; nothing leaves the box unless TARGET is set):
#   OIDX_BACKUP_OFFBOX_TARGET          where to put the encrypted copy:
#                                        remote:bucket/openidx       an rclone remote path
#                                        ssh://user@host[:port]/path rsync over ssh
#                                        /some/dir or file:///dir    a local or mounted dir
#   OIDX_BACKUP_AGE_RECIPIENTS         file of age recipient public keys (required with TARGET)
#   OIDX_BACKUP_SIGNING_KEY            box-held ssh private key (no passphrase) that signs
#                                      each copy's manifest (required with TARGET). age
#                                      gives confidentiality only: anyone holding the
#                                      PUBLIC recipient key can encrypt a forged dump, and
#                                      the checksums sit on the same storage. The
#                                      signature is what the restore drill trusts.
#   OIDX_BACKUP_OFFBOX_RETENTION_DAYS  delete off-box copies older than N (default: 30; 0 keeps all)
#
# Monitoring (optional):
#   OIDX_BACKUP_TEXTFILE_DIR     node-exporter textfile collector dir; writes
#                                openidx_backup.prom with
#                                openidx_backup_last_success_timestamp_seconds{kind="local|offbox"}
#
# The off-box result is also written to $OIDX_BACKUP_DIR/last-offbox.json.
# Exit status: 0 = all requested steps succeeded; 1 = the local dump failed;
# 2 = the local dump succeeded but the off-box copy failed.
set -euo pipefail

CONTAINER="${OIDX_PG_CONTAINER:-oidx-pg}"
DB="${OIDX_DB:-openidx}"
DB_USER="${OIDX_DB_USER:-openidx}"
BACKUP_DIR="${OIDX_BACKUP_DIR:-/home/cmit/oidx-runtime/backups}"
RETENTION_DAYS="${OIDX_BACKUP_RETENTION_DAYS:-14}"
OFFBOX_TARGET="${OIDX_BACKUP_OFFBOX_TARGET:-}"
AGE_RECIPIENTS="${OIDX_BACKUP_AGE_RECIPIENTS:-}"
SIGNING_KEY="${OIDX_BACKUP_SIGNING_KEY:-}"
# The ssh signature namespace; pg-restore-verify.sh verifies under the same one.
SIG_NAMESPACE="openidx-backup"
OFFBOX_RETENTION_DAYS="${OIDX_BACKUP_OFFBOX_RETENTION_DAYS:-30}"
TEXTFILE_DIR="${OIDX_BACKUP_TEXTFILE_DIR:-}"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }

# write_metric <kind> <unix-seconds>: record the last success of one kind in the
# textfile collector, keeping the other kind's line. Written to a temp file and
# renamed, so node-exporter never reads a half-written file.
write_metric() {
  [ -n "$TEXTFILE_DIR" ] || return 0
  local kind="$1" when="$2" prom="$TEXTFILE_DIR/openidx_backup.prom" tmp other
  mkdir -p "$TEXTFILE_DIR"
  tmp="$(mktemp "$TEXTFILE_DIR/.openidx_backup.prom.XXXXXX")"
  {
    echo '# HELP openidx_backup_last_success_timestamp_seconds Unix time of the last successful OpenIDX database backup, by kind.'
    echo '# TYPE openidx_backup_last_success_timestamp_seconds gauge'
    for other in local offbox; do
      if [ "$other" = "$kind" ]; then
        echo "openidx_backup_last_success_timestamp_seconds{kind=\"$kind\"} $when"
      elif [ -f "$prom" ]; then
        grep -E "^openidx_backup_last_success_timestamp_seconds\{kind=\"$other\"\} " "$prom" || true
      fi
    done
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$prom"
}

# json_str <text>: a JSON string literal (quotes, backslashes, control chars).
json_str() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/ }"; s="${s//$'\r'/ }"; s="${s//$'\t'/ }"
  printf '"%s"' "$s"
}

# write_offbox_status <result> <object> <bytes> <error>
write_offbox_status() {
  local tmp
  tmp="$(mktemp "$BACKUP_DIR/.last-offbox.json.XXXXXX")"
  {
    printf '{\n'
    printf '  "timestamp": %s,\n' "$(json_str "$(date -u +%FT%TZ)")"
    printf '  "unix_time": %s,\n' "$(date -u +%s)"
    printf '  "result": %s,\n' "$(json_str "$1")"
    printf '  "target": %s,\n' "$(json_str "$OFFBOX_TARGET")"
    printf '  "object": %s,\n' "$(json_str "$2")"
    printf '  "bytes": %s,\n' "${3:-0}"
    printf '  "error": %s\n' "$(json_str "$4")"
    printf '}\n'
  } > "$tmp"
  mv -f "$tmp" "$BACKUP_DIR/last-offbox.json"
}

# offbox_mode <target>: rclone | ssh | local
offbox_mode() {
  case "$1" in
    ssh://*) echo ssh ;;
    file://*|/*) echo local ;;
    *:*) echo rclone ;;
    *) echo unknown ;;
  esac
}

# Parse ssh://user@host[:port]/path into SSH_HOST, SSH_PORT, SSH_PATH.
parse_ssh_target() {
  local rest="${1#ssh://}" hostport
  hostport="${rest%%/*}"
  SSH_PATH="/${rest#*/}"
  [ "$hostport" != "$rest" ] || SSH_PATH="."
  SSH_HOST="${hostport%:*}"
  SSH_PORT=22
  [ "$hostport" = "$SSH_HOST" ] || SSH_PORT="${hostport##*:}"
}

# offbox_put <local-file>...: copy files to the target, in order. The caller
# passes the ciphertext first and its .sha256 last: the .age.sha256 is the
# "complete" marker the restore drill looks for. Every step returns on its own
# failure: this runs on the right of `||`, where set -e does not apply.
offbox_put() {
  local mode dest f
  mode="$(offbox_mode "$OFFBOX_TARGET")"
  case "$mode" in
    rclone)
      for f in "$@"; do
        rclone copyto "$f" "${OFFBOX_TARGET%/}/$(basename "$f")" || return 1
      done ;;
    ssh)
      parse_ssh_target "$OFFBOX_TARGET"
      # shellcheck disable=SC2029 # the path is quoted for the remote shell on purpose
      ssh -p "$SSH_PORT" -o BatchMode=yes "$SSH_HOST" "mkdir -p -- $(printf '%q' "$SSH_PATH")" || return 1
      for f in "$@"; do
        rsync -s -t --partial -e "ssh -p $SSH_PORT -o BatchMode=yes" "$f" "$SSH_HOST:$SSH_PATH/" || return 1
      done ;;
    local)
      dest="${OFFBOX_TARGET#file://}"
      mkdir -p "$dest" || return 1
      for f in "$@"; do
        cp -p "$f" "$dest/.$(basename "$f").partial" || return 1
        mv -f "$dest/.$(basename "$f").partial" "$dest/$(basename "$f")" || return 1
      done ;;
    *)
      log "ERROR: OIDX_BACKUP_OFFBOX_TARGET '$OFFBOX_TARGET' is not an rclone remote (name:path), ssh://user@host/path or a directory"
      return 1 ;;
  esac
}

# offbox_prune: delete off-box copies older than OFFBOX_RETENTION_DAYS. Only
# names this script writes (openidx-*.dump.*) are ever considered.
offbox_prune() {
  [ "$OFFBOX_RETENTION_DAYS" -gt 0 ] 2>/dev/null || return 0
  local mode dest
  mode="$(offbox_mode "$OFFBOX_TARGET")"
  case "$mode" in
    rclone)
      rclone delete --min-age "${OFFBOX_RETENTION_DAYS}d" --include 'openidx-*.dump.*' "${OFFBOX_TARGET%/}" ;;
    ssh)
      parse_ssh_target "$OFFBOX_TARGET"
      # shellcheck disable=SC2029
      ssh -p "$SSH_PORT" -o BatchMode=yes "$SSH_HOST" \
        "find $(printf '%q' "$SSH_PATH") -maxdepth 1 -type f -name 'openidx-*.dump.*' -mtime +$OFFBOX_RETENTION_DAYS -print -delete" ;;
    local)
      dest="${OFFBOX_TARGET#file://}"
      find "$dest" -maxdepth 1 -type f -name 'openidx-*.dump.*' -mtime +"$OFFBOX_RETENTION_DAYS" -print -delete ;;
  esac | sed 's/^/  off-box rotated out: /' || true
}

# offbox_copy <dump>: encrypt, upload, prune. Returns non-zero on any failure;
# writes last-offbox.json and, on success, the offbox metric.
offbox_copy() {
  local dump="$1" name stage enc bytes err=""
  name="$(basename "$dump")"

  # Refuse to upload anything unencrypted. Every way of getting here without a
  # usable recipient list is a failure, never a fallback to plaintext.
  if [ -z "$AGE_RECIPIENTS" ]; then
    err="OIDX_BACKUP_AGE_RECIPIENTS is not set; refusing to upload an unencrypted dump"
  elif [ ! -s "$AGE_RECIPIENTS" ]; then
    err="age recipients file '$AGE_RECIPIENTS' is missing or empty; refusing to upload an unencrypted dump"
  elif ! grep -qE '^(age1|ssh-ed25519 |ssh-rsa )' "$AGE_RECIPIENTS"; then
    err="age recipients file '$AGE_RECIPIENTS' holds no age1/ssh recipient; refusing to upload an unencrypted dump"
  elif ! command -v age >/dev/null 2>&1; then
    err="age is not installed; refusing to upload an unencrypted dump"
  elif [ -z "$SIGNING_KEY" ] || [ ! -r "$SIGNING_KEY" ]; then
    err="OIDX_BACKUP_SIGNING_KEY is not set or not readable; refusing to upload a copy nobody could tell from a forgery"
  elif ! command -v ssh-keygen >/dev/null 2>&1; then
    err="ssh-keygen is not installed; it signs the off-box copy"
  elif [ "$(offbox_mode "$OFFBOX_TARGET")" = rclone ] && ! command -v rclone >/dev/null 2>&1; then
    err="rclone is not installed (target '$OFFBOX_TARGET' is an rclone remote)"
  elif [ "$(offbox_mode "$OFFBOX_TARGET")" = ssh ] && ! command -v rsync >/dev/null 2>&1; then
    err="rsync is not installed (target '$OFFBOX_TARGET' is ssh://)"
  fi
  if [ -n "$err" ]; then
    log "ERROR: off-box: $err"
    write_offbox_status failure "" 0 "$err"
    return 1
  fi

  # Stage the ciphertext beside the dumps (same filesystem, owner-only) and
  # remove it afterwards: the local copy that is kept is the plain dump.
  stage="$(mktemp -d "$BACKUP_DIR/.offbox-stage.XXXXXX")"
  chmod 700 "$stage"
  enc="$stage/${name}.age"
  if ! age -e -R "$AGE_RECIPIENTS" -o "$enc" "$dump" 2>"$stage/age.err"; then
    err="age encryption failed: $(head -c 300 "$stage/age.err")"
    log "ERROR: off-box: $err"; rm -rf "$stage"
    write_offbox_status failure "${name}.age" 0 "$err"
    return 1
  fi
  sha256sum "$enc" | awk '{print $1}' > "${enc}.sha256"
  bytes="$(stat -c %s "$enc")"
  if [ ! -s "${enc}.sha256" ] || ! cp -p "${dump}.sha256" "$stage/${name}.sha256"; then
    err="could not write the checksum sidecars"
    log "ERROR: off-box: $err"; rm -rf "$stage"
    write_offbox_status failure "${name}.age" "$bytes" "$err"
    return 1
  fi
  local extra=()
  [ -s "${dump}.schema_version" ] && { cp -p "${dump}.schema_version" "$stage/"; extra+=("$stage/${name}.schema_version"); }

  # The manifest binds the copy's name to both hashes, and the box's signing
  # key signs it. The restore drill trusts the hashes only through this
  # signature: the .sha256 sidecars sit on the same storage as the copy, so
  # whoever can replace one can replace the other. The name inside the
  # manifest stops a genuine signed copy from being presented under another
  # (newer) name.
  local manifest="$stage/${name}.manifest"
  {
    echo "openidx-backup-manifest v1"
    echo "name ${name}.age"
    echo "age_sha256 $(cat "${enc}.sha256")"
    echo "dump_sha256 $(tr -d '[:space:]' < "${dump}.sha256")"
    echo "schema_version $(tr -d '[:space:]' < "${dump}.schema_version" 2>/dev/null || true)"
    echo "created $(date -u +%FT%TZ)"
  } > "$manifest"
  if ! ssh-keygen -Y sign -q -f "$SIGNING_KEY" -n "$SIG_NAMESPACE" "$manifest" </dev/null 2>"$stage/sign.err" \
     || [ ! -s "${manifest}.sig" ]; then
    err="signing the manifest failed (the key must have no passphrase): $(head -c 300 "$stage/sign.err")"
    log "ERROR: off-box: $err"; rm -rf "$stage"
    write_offbox_status failure "${name}.age" "$bytes" "$err"
    return 1
  fi

  log "off-box: uploading ${name}.age ($bytes bytes) -> $OFFBOX_TARGET"
  if ! offbox_put "$enc" "$stage/${name}.sha256" "${extra[@]}" "$manifest" "${manifest}.sig" "${enc}.sha256" 2>"$stage/put.err"; then
    err="upload failed: $(tail -c 300 "$stage/put.err")"
    log "ERROR: off-box: $err"; rm -rf "$stage"
    write_offbox_status failure "${name}.age" "$bytes" "$err"
    return 1
  fi
  rm -rf "$stage"

  offbox_prune || log "WARN: off-box retention pass failed (the upload itself succeeded)"
  write_offbox_status success "${name}.age" "$bytes" ""
  write_metric offbox "$(date -u +%s)"
  log "off-box OK: ${name}.age"
}

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
write_metric local "$(date -u +%s)"

# Rotation: drop dumps + their sidecars older than the retention window.
find "$BACKUP_DIR" -maxdepth 1 -name 'openidx-*.dump*' -type f -mtime +"$RETENTION_DAYS" -print -delete | \
  sed 's/^/  rotated out: /' || true

log "current backups: $(find "$BACKUP_DIR" -maxdepth 1 -name 'openidx-*.dump' -type f | wc -l)"

if [ -n "$OFFBOX_TARGET" ]; then
  offbox_copy "$out" || exit 2
fi
