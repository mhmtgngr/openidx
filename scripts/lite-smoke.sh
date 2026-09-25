#!/usr/bin/env bash
# lite-smoke.sh — sign in to a running lite install the way the console does,
# and check the promises the lite install makes.
#
# Usage:
#   OPENIDX_ADMIN_PASSWORD_FILE=<file> scripts/lite-smoke.sh [console-url]
#
#   console-url   defaults to OPENIDX_PUBLIC_URL from the environment or .env,
#                 then http://localhost:3000.
#   The admin password is read from OPENIDX_ADMIN_PASSWORD_FILE. It is never
#   taken from the command line and never printed.
#   OPENIDX_ADMIN_USERNAME   the account to sign in as (default: admin).
#   LITE_SMOKE_CONTAINERS=0  skip the checks that read the running containers
#                            (port bindings, memory limits). They run by default
#                            whenever docker can see the lite project.
#   LITE_SMOKE_TOKEN_OUT     write the admin access token this run mints to this
#                            file (mode 600), for checks that follow; unset, it
#                            is written nowhere.
#   LITE_BUDGET_MIB          what the running containers' limits may add up to
#                            (default 2304: the core stack's budget, see the
#                            compose file's header; raise it for profiles).
#
# What it proves, in order:
#   1. the console is served, and discovery on the console's own origin names
#      that origin as the issuer (same-origin API, no fixed host baked in);
#   2. the seeded default password no longer signs in;
#   3. the admin signs in through the console's flow: /oauth/authorize, then
#      POST /oauth/login, then the PKCE code exchange at /oauth/token;
#   4. every core service answers an authenticated admin call through the
#      console's edge, and refuses the same call without a token;
#   5. no host port but the console's is published beyond 127.0.0.1, every
#      container has a memory limit, and the limits fit the budget.
#
# Requires curl, jq, openssl and python3. Exit status is non-zero if any check
# fails.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
COMPOSE_FILE="deployments/docker/docker-compose.lite.yml"

for tool in curl jq openssl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "lite-smoke: $tool is required" >&2; exit 2; }
done

env_value() { # env_value KEY -> value from .env, empty when absent
  [ -f .env ] || return 0
  sed -n "s/^$1=//p" .env | tail -n 1
}

URL="${1:-${OPENIDX_PUBLIC_URL:-$(env_value OPENIDX_PUBLIC_URL)}}"
URL="${URL:-http://localhost:3000}"
URL="${URL%/}"
USERNAME="${OPENIDX_ADMIN_USERNAME:-admin}"
PASSWORD_FILE="${OPENIDX_ADMIN_PASSWORD_FILE:-}"
BUDGET_MIB="${LITE_BUDGET_MIB:-2304}"
CLIENT_ID="admin-console"
REDIRECT_URI="$URL/login"

if [ -z "$PASSWORD_FILE" ] || [ ! -r "$PASSWORD_FILE" ]; then
  echo "lite-smoke: set OPENIDX_ADMIN_PASSWORD_FILE to a readable file holding the admin password" >&2
  exit 2
fi
PASSWORD="$(tr -d '\r\n' < "$PASSWORD_FILE")"
[ -n "$PASSWORD" ] || { echo "lite-smoke: $PASSWORD_FILE is empty" >&2; exit 2; }

PASS=0
FAIL=0
pass() { echo "  PASS $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL $1: $2"; FAIL=$((FAIL + 1)); }

urlencode() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
urldecode() { python3 -c 'import sys,urllib.parse;print(urllib.parse.unquote(sys.argv[1]))' "$1"; }
jwt_payload() {
  python3 -c 'import sys,base64,json;p=sys.argv[1].split(".")[1];p+="="*(-len(p)%4);print(json.dumps(json.loads(base64.urlsafe_b64decode(p))))' "$1"
}
status_of() { # status_of METHOD PATH [curl args...] -> HTTP status, 000 on no answer
  local method="$1" path="$2"
  shift 2
  curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X "$method" "$@" "$URL$path" || true
}

# new_verifier -> a fresh PKCE code verifier (RFC 7636: 43 to 128 characters).
new_verifier() { openssl rand -base64 48 | tr -d '=+/\n' | cut -c1-64; }

# begin_login VERIFIER -> prints the login_session /oauth/authorize hands the
# login page. The verifier is made by the caller: this runs in a command
# substitution, so nothing it assigns would survive it.
begin_login() {
  local challenge location
  challenge="$(printf '%s' "$1" | openssl dgst -binary -sha256 | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  location="$(curl -s -o /dev/null -D - --max-time 15 \
    "$URL/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$(urlencode "$REDIRECT_URI")&scope=openid+profile+email&code_challenge=$challenge&code_challenge_method=S256" \
    | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')" || true
  case "$location" in
    "$URL/login?"*) ;;
    *) echo ""; return 0 ;;
  esac
  urldecode "$(printf '%s' "$location" | sed -n 's/.*login_session=\([^&]*\).*/\1/p')"
}

# post_login SESSION PASSWORD -> prints the login response body
post_login() {
  jq -nc --arg u "$USERNAME" --arg p "$2" --arg s "$1" '{username:$u,password:$p,login_session:$s}' \
    | curl -s --max-time 30 -X POST "$URL/oauth/login" -H 'Content-Type: application/json' --data-binary @- || true
}

echo "OpenIDX lite smoke test against $URL"
echo

echo "1. The console and its origin"
code="$(status_of GET /)"
body="$(curl -s --max-time 15 "$URL/" || true)"
if [ "$code" = "200" ] && grep -q 'id="root"' <<< "$body"; then
  pass "the console is served at $URL/"
else
  fail "console" "GET / answered $code without the SPA root element"
fi
issuer="$(curl -s --max-time 15 "$URL/.well-known/openid-configuration" | jq -r '.issuer // empty' 2>/dev/null || true)"
if [ "$issuer" = "$URL" ]; then
  pass "discovery on the console's origin names it as the issuer"
else
  fail "issuer" "discovery at $URL says issuer '${issuer:-<none>}'"
fi
for path in /metrics /debug/pprof/; do
  # Captured first: grep -q exits at its first match, and under pipefail the
  # writer it leaves behind would turn a match into a failure status.
  body="$(curl -s --max-time 15 "$URL$path" || true)"
  if grep -qE '^# (HELP|TYPE) |Types of profiles available' <<< "$body"; then
    fail "operational endpoint" "$path is reachable through the console's port"
  else
    pass "$path is not served through the console's port"
  fi
done
echo

echo "2. The seeded default password is gone"
session="$(begin_login "$(new_verifier)")"
if [ -z "$session" ]; then
  fail "authorize" "/oauth/authorize did not send the browser to $URL/login with a login_session"
else
  resp="$(post_login "$session" 'Admin@123')"
  if printf '%s' "$resp" | jq -e '.redirect_url // .code // .mfa_required' >/dev/null 2>&1; then
    fail "default password" "the seeded password Admin@123 still signs in"
  else
    pass "the seeded password Admin@123 is refused"
  fi
fi
echo

echo "3. The admin signs in through the console's flow"
TOKEN=""
VERIFIER="$(new_verifier)"
session="$(begin_login "$VERIFIER")"
if [ -z "$session" ]; then
  fail "authorize" "/oauth/authorize did not send the browser to $URL/login with a login_session"
else
  pass "/oauth/authorize sends the browser to the console's login page"
  resp="$(post_login "$session" "$PASSWORD")"
  code_param="$(printf '%s' "$resp" | jq -r 'if .code then .code elif .redirect_url then (.redirect_url | capture("[?&]code=(?<c>[^&]+)").c) else empty end' 2>/dev/null || true)"
  if [ -z "$code_param" ]; then
    fail "login" "POST /oauth/login returned no code: $(printf '%s' "$resp" | jq -c '{error, error_description, mfa_required}' 2>/dev/null || echo unreadable)"
  else
    pass "POST /oauth/login accepts the admin password"
    TOKEN="$(curl -s --max-time 30 -X POST "$URL/oauth/token" \
      --data-urlencode grant_type=authorization_code \
      --data-urlencode "code=$(urldecode "$code_param")" \
      --data-urlencode "client_id=$CLIENT_ID" \
      --data-urlencode "redirect_uri=$REDIRECT_URI" \
      --data-urlencode "code_verifier=$VERIFIER" | jq -r '.access_token // empty' 2>/dev/null || true)"
    if [ -n "$TOKEN" ]; then
      pass "the PKCE code exchange at /oauth/token returns an access token"
      if [ -n "${LITE_SMOKE_TOKEN_OUT:-}" ]; then
        ( umask 077 && printf '%s' "$TOKEN" > "$LITE_SMOKE_TOKEN_OUT" )
      fi
      claims="$(jwt_payload "$TOKEN" 2>/dev/null || echo '{}')"
      if printf '%s' "$claims" | jq -e --arg iss "$URL" '.iss == $iss and ((.roles // []) | any(. == "admin"))' >/dev/null 2>&1; then
        pass "the token is issued by $URL and carries the admin role"
      else
        fail "token claims" "iss/roles are $(printf '%s' "$claims" | jq -c '{iss, roles}' 2>/dev/null || echo unreadable)"
      fi
    else
      fail "token" "the code exchange returned no access_token"
    fi
  fi
fi
echo

echo "4. Every core service answers through the console, and only with a token"
while read -r service path; do
  if [ -n "$TOKEN" ]; then
    code="$(status_of GET "$path" -H "Authorization: Bearer $TOKEN")"
    if [ "$code" = "200" ]; then
      pass "$service: GET $path with the admin token -> 200"
    else
      fail "$service" "GET $path with the admin token answered $code"
    fi
  else
    fail "$service" "no admin token to call $path with"
  fi
  code="$(status_of GET "$path")"
  if [ "$code" = "401" ]; then
    pass "$service: GET $path without a token -> 401"
  else
    fail "$service" "GET $path without a token answered $code, expected 401"
  fi
done <<'CALLS'
identity-service /api/v1/identity/users
admin-api /api/v1/dashboard
governance-service /api/v1/governance/reviews
provisioning-service /api/v1/provisioning/rules
audit-service /api/v1/audit/events
access-service /api/v1/access/ziti/status
oauth-service /api/v1/oauth/clients
CALLS
code="$(status_of GET /api/v1/identity/users -H 'Authorization: Bearer not-a-token')"
if [ "$code" = "401" ]; then
  pass "a malformed bearer token is refused (401)"
else
  fail "bad token" "GET /api/v1/identity/users with a malformed token answered $code"
fi
echo

containers_visible() {
  [ "${LITE_SMOKE_CONTAINERS:-1}" != "0" ] || return 1
  command -v docker >/dev/null 2>&1 || return 1
  [ -n "$(docker compose -f "$COMPOSE_FILE" ps -q 2>/dev/null || true)" ]
}

if containers_visible; then
  echo "5. Ports and memory of the running containers"
  mapfile -t ids < <(docker compose -f "$COMPOSE_FILE" ps -q)
  # One line per published port: <service> <container-port> <host-ip>
  published="$(docker inspect -f '{{$s := index .Config.Labels "com.docker.compose.service"}}{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{$s}} {{$p}} {{.HostIp}}{{"\n"}}{{end}}{{end}}' "${ids[@]}" | sed '/^$/d')"
  exposed=""
  while read -r service port hostip; do
    [ -n "$service" ] || continue
    if [ "$service" = "admin-console" ] && [ "$port" = "8080/tcp" ]; then
      continue
    fi
    [ "$hostip" = "127.0.0.1" ] || exposed="$exposed $service:$port@${hostip:-all}"
  done <<< "$published"
  count="$(grep -c . <<< "$published" || true)"
  if [ -z "$exposed" ]; then
    pass "every published port except the console's is bound to 127.0.0.1 ($count published)"
  else
    fail "ports" "published beyond loopback:$exposed"
  fi

  # <service> <memory limit bytes> <oom-killed> <restart count> <status>
  limits="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}} {{.HostConfig.Memory}} {{.State.OOMKilled}} {{.RestartCount}} {{.State.Status}}' "${ids[@]}")"
  unlimited="$(awk '$5 == "running" && $2 == 0 {print $1}' <<< "$limits" | tr '\n' ' ')"
  if [ -z "$unlimited" ]; then
    pass "every running container has a memory limit"
  else
    fail "memory limits" "no limit on: $unlimited"
  fi
  total_mib="$(awk '$5 == "running" {s += $2} END {printf "%d", s / 1048576}' <<< "$limits")"
  if [ "$total_mib" -le "$BUDGET_MIB" ]; then
    pass "the running containers' limits add up to ${total_mib} MiB, within the ${BUDGET_MIB} MiB budget"
  else
    fail "budget" "the running containers' limits add up to ${total_mib} MiB, over the ${BUDGET_MIB} MiB budget"
  fi
  troubled="$(awk '$3 == "true" || $4 != 0 {print $1 "(oom=" $3 ",restarts=" $4 ")"}' <<< "$limits" | tr '\n' ' ')"
  if [ -z "$troubled" ]; then
    pass "no container was OOM-killed or restarted"
  else
    fail "stability" "$troubled"
  fi
  echo
  echo "   Measured memory use (docker stats, one sample):"
  docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}' "${ids[@]}" | sort | sed 's/^/     /' || true
  echo
fi

echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
