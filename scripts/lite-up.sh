#!/usr/bin/env bash
# lite-up.sh — start the OpenIDX lite install and say where to sign in.
#
# Usage:
#   ./scripts/lite-up.sh                         first run, and every run after it
#   ./scripts/lite-up.sh --url URL               the address browsers use to reach the
#                                                console (default http://localhost:3000)
#   ./scripts/lite-up.sh --with COMPONENT        add an optional component; repeatable:
#                                                elasticsearch, guacamole, ziti, observability
#   ./scripts/lite-up.sh --without COMPONENT     take one out again
#   ./scripts/lite-up.sh --reset-admin-password  give the admin a new random password
#
# What it does:
#   1. writes .env with random secrets (scripts/generate-secrets.sh) when there
#      is none, readable by you only;
#   2. records the URL and the components you chose in .env;
#   3. starts deployments/docker/docker-compose.lite.yml and waits until every
#      service reports healthy and every setup job has finished;
#   4. the first time, gives the seeded admin a random password and prints it,
#      once. Nothing stores it.
#
# Running it again is safe: it keeps the secrets and the admin password, and
# changes only what you ask for. It prints no secret except that one-time
# admin password.
#
# For automation:
#   OPENIDX_ADMIN_PASSWORD_FILE=PATH  write a new admin password to PATH (mode 600)
#                                     instead of printing it
#   LITE_WAIT_SECONDS=N               how long to wait for health (default 600)
#   OPENIDX_VERSION, OPENIDX_IMAGE_REGISTRY
#                                     pick other images (see the compose file)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="deployments/docker/docker-compose.lite.yml"
ENV_FILE="$REPO_ROOT/.env"
COMPOSE_ENV="$REPO_ROOT/deployments/docker/.env"
PROJECT="openidx-lite"
COMPONENTS="elasticsearch guacamole ziti observability"
ADMIN_ID="00000000-0000-0000-0000-000000000001"
WAIT_SECONDS="${LITE_WAIT_SECONDS:-600}"

die() { echo "lite-up: $*" >&2; exit 1; }
note() { echo "==> $*"; }

usage() {
  sed -n '2,/^set -euo pipefail/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//'
}

# --- arguments ---------------------------------------------------------------
url_arg=""
reset_password=0
with=()
without=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --url) [ "$#" -ge 2 ] || die "--url needs a value"; url_arg="$2"; shift 2 ;;
    --url=*) url_arg="${1#--url=}"; shift ;;
    --with) [ "$#" -ge 2 ] || die "--with needs a component"; with+=("$2"); shift 2 ;;
    --with=*) with+=("${1#--with=}"); shift ;;
    --without) [ "$#" -ge 2 ] || die "--without needs a component"; without+=("$2"); shift 2 ;;
    --without=*) without+=("${1#--without=}"); shift ;;
    --reset-admin-password) reset_password=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

is_component() {
  local c
  for c in $COMPONENTS; do [ "$c" = "$1" ] && return 0; done
  return 1
}
for c in ${with[@]+"${with[@]}"} ${without[@]+"${without[@]}"}; do
  is_component "$c" || die "unknown component '$c'; choose from: $COMPONENTS"
done

if [ -n "$url_arg" ]; then
  url_arg="${url_arg%/}"
  [[ "$url_arg" =~ ^https?://[][A-Za-z0-9.:_-]+$ ]] \
    || die "--url must be scheme://host[:port] with no path, e.g. http://203.0.113.10:3000"
fi

# --- preflight ---------------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "docker is not installed: https://docs.docker.com/engine/install/"
if ! docker info >/dev/null 2>&1; then
  die "cannot reach the Docker daemon. Start it, or add your user to the docker group (then log in again), or run this with sudo."
fi
compose_version="$(docker compose version --short 2>/dev/null || true)"
compose_version="${compose_version#v}"
[ -n "$compose_version" ] || die "the Docker Compose plugin is missing (docker compose version failed): https://docs.docker.com/compose/install/linux/"
IFS=. read -r cv_major cv_minor _ <<< "$compose_version"
if [ "${cv_major:-0}" -lt 2 ] || { [ "${cv_major:-0}" -eq 2 ] && [ "${cv_minor:-0}" -lt 20 ]; }; then
  die "Docker Compose $compose_version is too old; the lite install needs 2.20 or later (optional dependencies)"
fi

mem_bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
case "$mem_bytes" in ''|*[!0-9]*) mem_bytes=0 ;; esac
if [ "$mem_bytes" -gt 0 ] && [ "$mem_bytes" -lt $((3500 * 1024 * 1024)) ]; then
  echo "warning: Docker has $((mem_bytes / 1024 / 1024)) MiB of memory; the lite install is sized for 4 GB." >&2
fi
arch="$(docker info --format '{{.Architecture}}' 2>/dev/null || echo unknown)"
case "$arch" in
  x86_64|amd64) ;;
  *) echo "warning: this host is $arch. The published images carry amd64 binaries, so they run here only under emulation." >&2 ;;
esac

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

# --- secrets -----------------------------------------------------------------
if [ ! -e "$ENV_FILE" ]; then
  # A database volume without the .env that created it cannot be opened: the
  # passwords in it are the ones that .env held.
  if docker volume inspect "${PROJECT}_postgres_data" >/dev/null 2>&1; then
    die "there is lite data (volume ${PROJECT}_postgres_data) but no .env. Restore the .env it was created with, or delete the data with: docker compose -f $COMPOSE_FILE down -v"
  fi
  note "Writing .env with random secrets (scripts/generate-secrets.sh; values not shown)"
  gen_err="$(mktemp)"
  # generate-secrets.sh prints the first characters of each secret; keep them
  # off the screen and out of any log this runs into.
  if ! bash "$SCRIPT_DIR/generate-secrets.sh" >/dev/null 2>"$gen_err"; then
    cat "$gen_err" >&2
    rm -f "$gen_err"
    die "scripts/generate-secrets.sh failed"
  fi
  rm -f "$gen_err"
  chmod 600 "$ENV_FILE"
else
  note "Using the existing .env"
fi

# Compose reads .env from the directory holding the compose file.
if [ ! -e "$COMPOSE_ENV" ]; then
  ln -s ../../.env "$COMPOSE_ENV" 2>/dev/null || cp "$ENV_FILE" "$COMPOSE_ENV"
fi

env_get() { # env_get KEY -> the value in .env, empty when absent
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1
}

# env_set KEY VALUE: replace or append one line. Written to a temporary file
# and moved into place, so an interrupted run never leaves half a .env; the
# temporary file is created owner-only, and so is the result.
ENV_TMP=""
trap '[ -z "$ENV_TMP" ] || rm -f "$ENV_TMP"' EXIT
env_set() {
  local key="$1" value="$2"
  if [ "$(env_get "$key")" = "$value" ] && grep -q "^$key=" "$ENV_FILE"; then
    return 0
  fi
  ENV_TMP="$(umask 077 && mktemp "$ENV_FILE.XXXXXX")"
  awk -v k="$key" -v v="$value" '
    BEGIN { done = 0 }
    index($0, k "=") == 1 { if (!done) { print k "=" v; done = 1 } ; next }
    { print }
    END { if (!done) print k "=" v }
  ' "$ENV_FILE" > "$ENV_TMP"
  mv "$ENV_TMP" "$ENV_FILE"
  ENV_TMP=""
  # A copy (no symlink support) must follow.
  if [ ! -L "$COMPOSE_ENV" ]; then
    cp "$ENV_FILE" "$COMPOSE_ENV"
  fi
}

# --- settings ----------------------------------------------------------------
console_port="${OPENIDX_CONSOLE_PORT:-$(env_get OPENIDX_CONSOLE_PORT)}"
console_port="${console_port:-3000}"
public_url="$url_arg"
[ -n "$public_url" ] || public_url="$(env_get OPENIDX_PUBLIC_URL)"
[ -n "$public_url" ] || public_url="http://localhost:$console_port"

# COMPOSE_PROFILES in .env is what compose itself reads, so plain
# `docker compose -f ... ps|logs|down` sees the same components this script
# started. Entries that are not lite components are left alone.
profiles=",$(env_get COMPOSE_PROFILES),"
for c in ${with[@]+"${with[@]}"}; do
  case "$profiles" in *",$c,"*) ;; *) profiles="$profiles$c," ;; esac
done
for c in ${without[@]+"${without[@]}"}; do
  profiles="${profiles//,$c,/,}"
done
profiles="$(printf '%s' "$profiles" | tr -s ',' | sed -e 's/^,//' -e 's/,$//')"
enabled() { case ",$profiles," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

es_url=""; guac_url=""; ziti_enabled=false; tracing=false
enabled elasticsearch && es_url="http://elasticsearch:9200"
enabled guacamole && guac_url="http://guacamole:8080/guacamole"
enabled ziti && ziti_enabled=true
enabled observability && tracing=true

env_set OPENIDX_PUBLIC_URL "$public_url"
env_set COMPOSE_PROFILES "$profiles"
env_set OPENIDX_ELASTICSEARCH_URL "$es_url"
env_set OPENIDX_GUACAMOLE_URL "$guac_url"
env_set OPENIDX_ZITI_ENABLED "$ziti_enabled"
env_set OPENIDX_TRACING_ENABLED "$tracing"

# The values just written are the ones compose must use, whatever this shell
# happens to export.
export OPENIDX_PUBLIC_URL="$public_url" COMPOSE_PROFILES="$profiles"
export OPENIDX_ELASTICSEARCH_URL="$es_url" OPENIDX_GUACAMOLE_URL="$guac_url"
export OPENIDX_ZITI_ENABLED="$ziti_enabled" OPENIDX_TRACING_ENABLED="$tracing"

if ! compose config -q; then
  die "the compose file does not resolve with this .env (above). A .env from an older version may lack a variable; compare it with a fresh scripts/generate-secrets.sh output."
fi

# --- start -------------------------------------------------------------------
for c in ${without[@]+"${without[@]}"}; do
  core_services="$(COMPOSE_PROFILES='' compose config --services | sort)"
  profile_services="$(COMPOSE_PROFILES="$c" compose config --services | sort)"
  gone="$(comm -13 <(printf '%s\n' "$core_services") <(printf '%s\n' "$profile_services") | tr '\n' ' ')"
  if [ -n "${gone// /}" ]; then
    note "Removing $c: $gone"
    # shellcheck disable=SC2086 # one word per service
    COMPOSE_PROFILES="${profiles:+$profiles,}$c" compose rm -sf $gone
  fi
done

note "Starting the lite stack (components: ${profiles:-none}); the first run pulls the images"
if ! compose up -d --remove-orphans; then
  echo >&2
  echo "lite-up: docker compose up failed. If it could not pull an image, check that OPENIDX_VERSION" >&2
  echo "(default in $COMPOSE_FILE) names a published release." >&2
  compose ps -a >&2 || true
  exit 1
fi

# --- wait --------------------------------------------------------------------
# Ready means: every service of the active profiles has a container; each
# long-running one is running and healthy (or has no health check), and each
# setup job (restart: no) has exited 0.
note "Waiting for every service to report healthy (up to ${WAIT_SECONDS}s)"
expected="$(compose config --services | sort)"
deadline=$((SECONDS + WAIT_SECONDS))
while :; do
  pending=""       # "service:state" words, for the message
  failed=""
  troubled=""      # service names, for the logs
  for svc in $expected; do
    mapfile -t ids < <(compose ps -a -q "$svc" 2>/dev/null || true)
    states=""
    if [ "${#ids[@]}" -gt 0 ] && [ -n "${ids[0]}" ]; then
      states="$(docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} {{.State.ExitCode}} {{.RestartCount}} {{.HostConfig.RestartPolicy.Name}}' "${ids[@]}" 2>/dev/null || true)"
    fi
    if [ -z "$states" ]; then
      pending="$pending $svc:no-container"
      continue
    fi
    while read -r status health code restarts policy; do
      if [ "$policy" = "no" ] || [ -z "$policy" ]; then
        # A setup job: done when it has exited 0.
        case "$status" in
          exited) [ "$code" = "0" ] || { failed="$failed $svc:exit-$code"; troubled="$troubled $svc"; } ;;
          *) pending="$pending $svc:$status" ;;
        esac
      elif [ "$restarts" -ge 3 ] || [ "$status" = "dead" ]; then
        failed="$failed $svc:restarted-$restarts-times"
        troubled="$troubled $svc"
      else
        case "$status/$health" in
          running/healthy|running/none) ;;
          *) pending="$pending $svc:$status/$health"; troubled="$troubled $svc" ;;
        esac
      fi
    done <<< "$states"
  done
  if [ -z "$pending" ] && [ -z "$failed" ]; then
    break
  fi
  if [ -n "$failed" ] || [ "$SECONDS" -ge "$deadline" ]; then
    echo >&2
    [ -z "$failed" ] || echo "lite-up: failed:$failed" >&2
    [ -z "$pending" ] || echo "lite-up: not ready after ${WAIT_SECONDS}s:$pending" >&2
    while read -r svc; do
      [ -n "$svc" ] || continue
      echo "--- last log lines of $svc ---" >&2
      compose logs --no-color --tail 30 "$svc" >&2 || true
    done < <(tr ' ' '\n' <<< "$troubled" | sort -u)
    exit 1
  fi
  sleep 5
done
note "Every service is healthy"

# --- the admin password ------------------------------------------------------
# The seeded admin arrives with the published password Admin@123. It is
# replaced once: when password_changed_at is still empty, which nothing but a
# real password change sets (a hash upgrade at sign-in leaves it alone). So a
# second run leaves a password the admin chose untouched, and a new volume
# gets a new password.
#
# The hash is bcrypt from pgcrypto, created in a scratch schema and dropped in
# the same transaction; the first sign-in upgrades it to Argon2id. The
# password travels on psql's standard input and as a bound parameter, so it is
# in no command line and not in the statement text the server would log on an
# error.
new_password() {
  local out="" chunk
  while :; do
    chunk="$(LC_ALL=C tr -dc 'A-Za-z0-9' <<< "$(head -c 4096 /dev/urandom | LC_ALL=C tr -d '\0')")"
    out="$out$chunk"
    [ "${#out}" -ge 24 ] || continue
    local p="${out:0:6}-${out:6:6}-${out:12:6}-${out:18:6}"
    # The console's password policy: upper, lower, digit and a symbol.
    if [[ "$p" =~ [A-Z] && "$p" =~ [a-z] && "$p" =~ [0-9] ]]; then
      printf '%s' "$p"
      return 0
    fi
    out=""
  done
}

admin_password="$(new_password)"
force=false
[ "$reset_password" -eq 1 ] && force=true
result="$(compose exec -T postgres psql -U openidx -d openidx -X -qAt -v ON_ERROR_STOP=1 <<SQL
BEGIN;
SET LOCAL app.bypass_rls = 'on';
SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto') AS had_pgcrypto \gset
\if :had_pgcrypto
SELECT n.nspname AS crypto_schema FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = 'pgcrypto' \gset
\else
CREATE SCHEMA openidx_lite_pw;
CREATE EXTENSION pgcrypto WITH SCHEMA openidx_lite_pw;
\set crypto_schema openidx_lite_pw
\endif
UPDATE users
   SET password_hash = :"crypto_schema".crypt(\$1, :"crypto_schema".gen_salt('bf', 12)),
       password_changed_at = now(),
       password_must_change = false,
       failed_login_count = 0,
       locked_until = NULL
 WHERE id = '$ADMIN_ID'
   AND (password_changed_at IS NULL OR \$2::boolean)
RETURNING 'admin-password-set'
\bind '$admin_password' '$force'
\g
\if :had_pgcrypto
\else
DROP EXTENSION pgcrypto;
DROP SCHEMA openidx_lite_pw;
\endif
COMMIT;
SQL
)" || die "could not set the admin password (the database refused; see above)"

password_line=""
if grep -qx 'admin-password-set' <<< "$result"; then
  if [ -n "${OPENIDX_ADMIN_PASSWORD_FILE:-}" ]; then
    ( umask 077 && printf '%s\n' "$admin_password" > "$OPENIDX_ADMIN_PASSWORD_FILE" )
    password_line="  Password  written to $OPENIDX_ADMIN_PASSWORD_FILE"
  else
    password_line="  Password  $admin_password
            Shown this once and stored nowhere: note it now, then change it
            in the console (My Security). Lost it? ./scripts/lite-up.sh --reset-admin-password"
  fi
else
  password_line="  Password  the one set on an earlier run (not shown again).
            Lost it? ./scripts/lite-up.sh --reset-admin-password"
fi
unset admin_password

# --- where to go -------------------------------------------------------------
cat <<EOF

OpenIDX lite is running.

  Console   $public_url
  Sign in   admin
$password_line

EOF
case "$public_url" in
  http://localhost:*|http://127.0.0.1:*)
    # The browser must keep typing this URL, so the tunnel's local end is the
    # URL's port and its far end is the console's published port.
    url_port="${public_url##*:}"
    cat <<EOF
  From another machine, tunnel the port and open the same URL there:
      ssh -L $url_port:localhost:$console_port <you>@<this-host>
  or let browsers use this host's address (it must be what they type):
      ./scripts/lite-up.sh --url http://<this-host>:$console_port

EOF
    ;;
esac
cat <<EOF
  Components: ${profiles:-none}. Add one with --with elasticsearch|guacamole|ziti|observability
  (each needs more memory; docs/GETTING-STARTED.md#lite-install).
  Status: docker compose -f $COMPOSE_FILE ps
  Stop:   docker compose -f $COMPOSE_FILE down      (add -v to delete the data too)
EOF
