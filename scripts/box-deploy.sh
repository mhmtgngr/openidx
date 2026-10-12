#!/usr/bin/env bash
# box-deploy.sh — staged release deploy for the single-host reference box.
#
# The reference box runs the services as rootless `systemd --user` units
# (oidx-*.service) from binaries in ~/oidx-runtime/bin, Postgres in the
# `oidx-pg` podman container, and the console from a dist/ directory that is
# bind-mounted into oidx-nginx. This script is the step-by-step deploy that
# was rewritten in a temp folder for every release until v1.44.0.
#
# It is NOT scripts/deploy-box.sh, which deploys the docker-compose stack
# (deployments/docker/docker-compose.prod.yml) by building images from a tag.
#
# Before running it, build into the stage directory:
#   $STAGE/oidx-<bin>   for every name in BINS (default below; includes migrate)
#   $STAGE/dist/        the console build (same-origin prod build)
#   $STAGE/VERSION      the release, e.g. v1.44.0
#
# Run one step at a time and read its output before the next:
#
#   VERSION=v1.45.0 EXPECT_SCHEMA=236 scripts/box-deploy.sh preflight
#   ... rehearse  dump  stop  migrate  swap  start  verify
#   ... rollback   (only if needed)
#
# Settings (environment):
#   VERSION         release; STAGE defaults to $RT/stage-$VERSION
#   STAGE           stage directory (overrides VERSION for the path)
#   EXPECT_SCHEMA   schema version the release's migrations end at (required
#                   by rehearse, migrate, verify)
#   TS              rollback suffix; default: $STAGE/rollback_ts, else now.
#                   Saved to $STAGE/rollback_ts so every step uses the same one.
#   UNITS           systemd user units to stop/start (without .service)
#   BINS            binaries to swap (staged as $STAGE/oidx-<bin>)
#   RT              runtime dir (default ~/oidx-runtime)
#   ENVF            env file holding DATABASE_URL and the owner URL comment
#   DIST            live console dist dir (bind-mounted; replaced IN place)
#   PG_CONTAINER    live Postgres container (default oidx-pg)
#   LOG_DIR         unit logs (default /tmp/oidx-logs/<svc>.log)
#   EDGE_HOST       public host for the edge check (default openidx.tdv.org)
#   CONSOLE_MARKER  optional string the new console bundle must contain
#   REHEARSE_DUMP   dump to rehearse on (default: newest $RT/backups/*.dump)
#   REHEARSE_PORT   loopback port for the throwaway Postgres (default 55499)
#   REHEARSE_KEEP=1 leave the throwaway container running afterwards
#   OWNER_DATABASE_URL  owner URL; default: the postgres://openidx:... URL in
#                   the comment at the top of $ENVF. Never printed.
#
# Secrets: database URLs are only ever handed to child processes through
# their environment. Nothing here echoes them, and xtrace is refused.
set -euo pipefail
case $- in *x*) echo "refusing to run with xtrace on (it would print database URLs)" >&2; exit 2;; esac

RT=${RT:-$HOME/oidx-runtime}
ENVF=${ENVF:-$HOME/.config/oidx/common.env}
DIST=${DIST:-$HOME/openidx/web/admin-console/dist}
PG_CONTAINER=${PG_CONTAINER:-oidx-pg}
LOG_DIR=${LOG_DIR:-/tmp/oidx-logs}
EDGE_HOST=${EDGE_HOST:-openidx.tdv.org}
UNITS=${UNITS:-"oidx-access oidx-admin-api oidx-audit oidx-governance oidx-identity oidx-oauth oidx-provisioning"}
BINS=${BINS:-"access-service admin-api audit-service governance-service identity-service oauth-service provisioning-service migrate"}
REHEARSE_PORT=${REHEARSE_PORT:-55499}
REHEARSE_IMAGE=${REHEARSE_IMAGE:-docker.io/library/postgres:16-alpine}
VERSION=${VERSION:-}
if [ -z "${STAGE:-}" ] && [ -n "$VERSION" ]; then STAGE=$RT/stage-$VERSION; fi
STAGE=${STAGE:-}
EXPECT_SCHEMA=${EXPECT_SCHEMA:-}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*"; }

usage() {
  sed -n '2,47p' "$0"
  echo
  echo "usage: $0 preflight|rehearse|dump|stop|migrate|swap|start|verify|rollback|help"
}

need_stage() {
  [ -n "$STAGE" ] || die "set VERSION or STAGE"
  [ -d "$STAGE" ] || die "stage dir not found: $STAGE"
  [ -n "$VERSION" ] || VERSION=$(cat "$STAGE/VERSION" 2>/dev/null || true)
  [ -n "$VERSION" ] || die "no VERSION and no $STAGE/VERSION"
  TS=${TS:-$(cat "$STAGE/rollback_ts" 2>/dev/null || date +%s)}
  echo "$TS" > "$STAGE/rollback_ts"
}
need_schema() { [[ "$EXPECT_SCHEMA" =~ ^[0-9]+$ ]] || die "set EXPECT_SCHEMA to the release's last migration number"; }

# The owner URL lives in the comment at the top of common.env
# ("Rollback (if needed): postgres://openidx:..."). Read, never printed.
owner_url() {
  if [ -n "${OWNER_DATABASE_URL:-}" ]; then printf '%s' "$OWNER_DATABASE_URL"; return; fi
  grep -oE 'postgres(ql)?://openidx:[^ ]+' "$ENVF" | head -1 || true
}
app_url() { grep -E '^DATABASE_URL=' "$ENVF" | head -1 | cut -d= -f2- || true; }
pg() { podman exec -i "$PG_CONTAINER" psql -U openidx -d openidx -v ON_ERROR_STOP=1 -Atq "$@"; }
live_schema() { pg -c 'select coalesce(max(version), 0) from schema_migrations'; }
unit_list() { local u; for u in $UNITS; do printf '%s.service ' "$u"; done; }
# `systemctl is-active` exits 3 for an inactive unit; under pipefail that would end the step.
unit_states() { # shellcheck disable=SC2046
  { systemctl --user is-active $(unit_list) || true; } | paste -sd' '; }
log_file() { local s=${1#oidx-}; printf '%s/%s.log' "$LOG_DIR" "${s%-api}"; }
strip_ansi() { sed -E 's/\x1b\[[0-9;]*m//g'; }

step_preflight() {
  need_stage
  echo "stage=$STAGE version=$VERSION ts=$TS expect_schema=${EXPECT_SCHEMA:-unset}"
  local b missing=0
  for b in $BINS; do [ -x "$STAGE/oidx-$b" ] || { echo "missing $STAGE/oidx-$b"; missing=1; }; done
  [ -f "$STAGE/dist/index.html" ] || { echo "missing $STAGE/dist/index.html"; missing=1; }
  [ "$missing" = 0 ] || die "stage incomplete"
  local cur; cur=$(live_schema)
  echo "$cur" > "$STAGE/prev_schema"
  echo "live schema: $cur (saved to $STAGE/prev_schema)"
  if [ -n "$EXPECT_SCHEMA" ] && [ "$cur" -ge "$EXPECT_SCHEMA" ]; then echo "note: live schema is already at or past $EXPECT_SCHEMA"; fi
  # `version` is read-only, so it runs as the app role.
  echo "staged migrate on live: $(DATABASE_URL=$(app_url) "$STAGE/oidx-migrate" version 2>&1 | strip_ansi | tail -1 | cut -c1-160 || true)"
  echo "owner URL found: $([ -n "$(owner_url)" ] && echo yes || echo NO)"
  echo "units: $(unit_states)"
  df -h "$HOME" | tail -1
}

# Restore a dump into a throwaway postgres:16-alpine container and run the
# staged migrations there. Never a scratch database inside oidx-pg: roles are
# cluster-global, and migrations create and alter roles.
step_rehearse() {
  need_stage; need_schema
  local dump=${REHEARSE_DUMP:-}
  if [ -z "$dump" ]; then
    # shellcheck disable=SC2012
    dump=$(ls -1t "$RT"/backups/*.dump 2>/dev/null | head -1 || true)
  fi
  [ -s "$dump" ] || die "no dump to rehearse on (set REHEARSE_DUMP or run the nightly backup / dump step)"
  local name=oidx-rehearse-$TS log=$STAGE/rehearse-$TS.log
  local pw; pw=$(openssl rand -hex 24)
  say "rehearsing on $(basename "$dump") in container $name (127.0.0.1:$REHEARSE_PORT), log $log"
  podman rm -f "$name" >/dev/null 2>&1 || true
  # POSTGRES_PASSWORD is passed by name so it is not on the podman command line.
  POSTGRES_PASSWORD=$pw podman run -d --name "$name" \
    -e POSTGRES_USER=openidx -e POSTGRES_DB=openidx -e POSTGRES_PASSWORD \
    -p "127.0.0.1:$REHEARSE_PORT:5432" "$REHEARSE_IMAGE" >/dev/null
  if [ "${REHEARSE_KEEP:-0}" != 1 ]; then
    # shellcheck disable=SC2064
    trap "podman rm -f '$name' >/dev/null 2>&1 || true" EXIT
  fi
  for _ in $(seq 1 60); do
    podman exec "$name" pg_isready -U openidx -d openidx -q 2>/dev/null && break
    sleep 1
  done
  podman exec "$name" pg_isready -U openidx -d openidx -q || die "throwaway postgres did not come up"
  sleep 2   # the entrypoint restarts the server once after initdb

  # The dump's grants name the live cluster's roles; create them (no login,
  # same BYPASSRLS flag, same memberships) so the restore and the migrations
  # see the shape production has.
  local roles
  roles=$(pg -c "select format('CREATE ROLE %I NOLOGIN%s;', rolname, case when rolbypassrls then ' BYPASSRLS' else '' end)
                 from pg_roles where rolname !~ '^pg_' and rolname <> 'openidx' order by rolname")
  roles+=$'\n'$(pg -c "select format('GRANT %I TO %I;', r.rolname, m.rolname)
                 from pg_auth_members a join pg_roles r on r.oid = a.roleid join pg_roles m on m.oid = a.member
                 where r.rolname !~ '^pg_' and m.rolname !~ '^pg_' and m.rolname <> 'openidx'")
  printf '%s\n' "$roles" | podman exec -i "$name" psql -U openidx -d openidx -q -v ON_ERROR_STOP=1 >>"$log" 2>&1 \
    || die "creating roles in the throwaway container failed (see $log)"

  say "restoring"
  podman exec -i "$name" pg_restore -U openidx -d openidx < "$dump" >>"$log" 2>&1 || true
  local errs; errs=$(grep -c 'error:' "$log" || true)
  echo "pg_restore errors: $errs (expected: a few already-exists notices, e.g. schema public)"
  grep 'error:' "$log" | cut -c1-200 | head -5 || true

  say "migrating with the staged binary"
  local url="postgres://openidx:$pw@127.0.0.1:$REHEARSE_PORT/openidx?sslmode=disable" rc=0
  DATABASE_URL=$url "$STAGE/oidx-migrate" up >>"$log" 2>&1 || rc=$?
  strip_ansi < "$log" | grep -E 'Applying|error|FATAL|completed' | cut -c1-200 | tail -20 || true
  [ "$rc" = 0 ] || die "rehearsal migrate failed (exit $rc); nothing on the live box was touched"
  local got
  got=$(podman exec "$name" psql -U openidx -d openidx -Atq -c 'select max(version) from schema_migrations')
  echo "rehearsal schema: $got (expected $EXPECT_SCHEMA)"
  echo "staged migrate version: $(DATABASE_URL=$url "$STAGE/oidx-migrate" version 2>&1 | strip_ansi | tail -1 | cut -c1-160 || true)"
  [ "$got" = "$EXPECT_SCHEMA" ] || die "rehearsal ended at schema $got, not $EXPECT_SCHEMA"
  say "rehearsal OK"
  [ "${REHEARSE_KEEP:-0}" != 1 ] || echo "container $name kept (REHEARSE_KEEP=1); remove with: podman rm -f $name"
}

step_dump() {
  need_stage
  mkdir -p "$RT/backups"
  local f
  f=$RT/backups/pre-v${EXPECT_SCHEMA:-$VERSION}-$(date +%Y%m%d-%H%M%S).dump
  podman exec "$PG_CONTAINER" pg_dump -U openidx -Fc openidx > "$f"
  [ -s "$f" ] || die "dump is empty: $f"
  echo "$f" > "$STAGE/predeploy_dump"
  ls -la "$f"
}

step_stop() {
  local u
  for u in $UNITS; do systemctl --user stop "$u.service"; done
  echo "units: $(unit_states)"
}

step_migrate() {
  need_stage; need_schema
  local url rc=0 log
  url=$(owner_url)
  [ -n "$url" ] || die "no owner URL (set OWNER_DATABASE_URL or keep it in the $ENVF header comment)"
  log=$STAGE/migrate-$TS.log
  DATABASE_URL=$url "$STAGE/oidx-migrate" up >"$log" 2>&1 || rc=$?
  strip_ansi < "$log" | grep -E 'Applying|NOTICE|error|FATAL|completed' | cut -c1-200 || true
  [ "$rc" = 0 ] || die "migrate failed (exit $rc), full output in $log; services are still stopped"
  local got; got=$(live_schema)
  echo "live schema now: $got (expected $EXPECT_SCHEMA)"
  [ "$got" = "$EXPECT_SCHEMA" ] || die "live schema is $got, not $EXPECT_SCHEMA"
}

step_swap() {
  need_stage
  local b
  for b in $BINS; do
    if [ -f "$RT/bin/oidx-$b" ]; then cp -p "$RT/bin/oidx-$b" "$RT/bin/oidx-$b.rollback-$TS"; fi
    install -m 755 "$STAGE/oidx-$b" "$RT/bin/oidx-$b"
  done
  mkdir -p "$RT/dist-backups"
  tar -C "$(dirname "$DIST")" -czf "$RT/dist-backups/dist-pre-$VERSION-$TS.tgz" "$(basename "$DIST")"
  # Into the directory, not over it: it is bind-mounted into oidx-nginx.
  rsync -a --delete "$STAGE/dist/" "$DIST/"
  echo "binaries + dist swapped (rollback suffix $TS, dist backup dist-pre-$VERSION-$TS.tgz)"
}

step_start() {
  local u
  for u in $UNITS; do systemctl --user start "$u.service"; done
  sleep 6
  echo "units: $(unit_states)"
}

step_verify() {
  echo "units: $(unit_states)"
  local p out
  for p in $(ss -ltnH 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un || true); do
    out=$(curl -s -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/health" 2>/dev/null || true)
    if [ "$out" = "200" ]; then
      echo "port $p /health 200: $(curl -s -m 3 "http://127.0.0.1:$p/health" 2>/dev/null | cut -c1-120 || true)"
    fi
  done
  # The edge routes by SNI: localhost would get the default vhost.
  echo "edge: $(curl -s -m 5 -o /dev/null -w '%{http_code}' --resolve "$EDGE_HOST:443:127.0.0.1" "https://$EDGE_HOST/" 2>/dev/null || true)"
  if [ -n "$EXPECT_SCHEMA" ]; then echo "live schema: $(live_schema) (expected $EXPECT_SCHEMA)"; fi
  if [ -n "${CONSOLE_MARKER:-}" ]; then
    echo "console bundles containing marker: $(grep -l -- "$CONSOLE_MARKER" "$DIST"/assets/*.js 2>/dev/null | wc -l || true)"
  fi
  # Units log to files, not journald. grep exits 1 on no match, which is the good case.
  local u
  for u in $UNITS; do
    echo "== $u ($(log_file "$u"))"
    tail -n 300 "$(log_file "$u")" 2>/dev/null \
      | grep -iE 'error|fatal|refus|AUTHZ|bypass pool|42501' | tail -4 | cut -c1-200 || true
  done
  echo "Background work runs on a 5-minute tick: run verify again after it."
}

step_rollback() {
  need_stage
  say "rolling back binaries and console to suffix $TS (database untouched)"
  local u b restored=0
  for u in $UNITS; do systemctl --user stop "$u.service"; done
  for b in $BINS; do
    if [ -f "$RT/bin/oidx-$b.rollback-$TS" ]; then
      install -m 755 "$RT/bin/oidx-$b.rollback-$TS" "$RT/bin/oidx-$b"; restored=$((restored + 1))
    else
      echo "no $RT/bin/oidx-$b.rollback-$TS (left as is)"
    fi
  done
  echo "binaries restored: $restored"
  local tgz=$RT/dist-backups/dist-pre-$VERSION-$TS.tgz
  if [ -f "$tgz" ]; then
    local tmp; tmp=$(mktemp -d)
    tar -C "$tmp" -xzf "$tgz"
    rsync -a --delete "$tmp/$(basename "$DIST")/" "$DIST/"
    rm -rf "$tmp"
    echo "console restored from $(basename "$tgz")"
  else
    echo "no console backup $tgz (left as is)"
  fi
  local dump prev
  dump=$(cat "$STAGE/predeploy_dump" 2>/dev/null || echo '<the pre-deploy dump in '"$RT"'/backups>')
  prev=$(cat "$STAGE/prev_schema" 2>/dev/null || echo '<previous schema>')
  cat <<EOF

The database was NOT changed. If the release's migrations must be undone too,
pick one (services stay stopped until you run the start step):

  a) migrate down with the staged binary, as the owner (keeps data written since):
       DATABASE_URL="\$OWNER_URL" $STAGE/oidx-migrate down $prev

  b) restore the pre-deploy dump (loses everything written since the dump):
       podman exec -i $PG_CONTAINER pg_restore -U openidx -d openidx --clean --if-exists --single-transaction < $dump

Then: $0 start && $0 verify
EOF
}

case "${1:-help}" in
  preflight) step_preflight ;;
  rehearse)  step_rehearse ;;
  dump)      step_dump ;;
  stop)      step_stop ;;
  migrate)   step_migrate ;;
  swap)      step_swap ;;
  start)     step_start ;;
  verify)    step_verify ;;
  rollback)  step_rollback ;;
  help|-h|--help) usage ;;
  *) usage; exit 2 ;;
esac
