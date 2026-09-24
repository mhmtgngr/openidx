#!/usr/bin/env bash
# Runs the README's quick start and asserts it works.
#
# WHY THIS EXISTS: nothing in CI, no test and no Makefile target had ever run
# scripts/generate-secrets.sh, so three separate defects sat in the first two
# commands a new operator types, each of which stopped the install dead:
#
#   1. The script aborted on its own first line of work. `tr -dc … </dev/urandom
#      | head -c 32` under `set -o pipefail` always ends with tr killed by
#      SIGPIPE, so the pipeline returned 141 and `set -e` quit. It never once
#      produced a .env.
#   2. docker-compose.yml declares OPENIDX_APP_PASSWORD and APISIX_ADMIN_KEY as
#      required, in an error message that tells you to run this script -- and
#      the script did not write either of them.
#   3. Compose reads .env from the directory holding the compose file, so the
#      .env written at the repo root was never seen by the documented
#      `docker compose -f deployments/docker/docker-compose.yml` command.
#
# Case 4 below is the one that keeps this from happening again on its own: it
# derives the required-variable list FROM the compose file, so a `${VAR:?…}`
# added later fails here instead of failing the operator.
#
# Cases 8-10 cover the quick start the README gives now, the lite install
# (#961): the lite compose file resolves after the generator, and
# scripts/lite-up.sh writes the secrets once, sets the admin password once and
# prints no other secret. The lite-install CI job runs the same path on a real
# stack.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
GEN="scripts/generate-secrets.sh"
COMPOSE_FILE="deployments/docker/docker-compose.yml"

TMP="$(mktemp -d)"
fail() { echo "FAIL: $1"; exit 1; }

# The documented path writes into the working tree. Both files are gitignored,
# but restore whatever was there so running this locally is not destructive.
ROOT_ENV="$REPO_ROOT/.env"
COMPOSE_ENV="$REPO_ROOT/deployments/docker/.env"
[ -e "$ROOT_ENV" ] && cp -P "$ROOT_ENV" "$TMP/root.env.saved"
[ -e "$COMPOSE_ENV" ] && cp -P "$COMPOSE_ENV" "$TMP/compose.env.saved"
restore() {
  rm -f "$ROOT_ENV" "$COMPOSE_ENV"
  [ -e "$TMP/root.env.saved" ] && cp -P "$TMP/root.env.saved" "$ROOT_ENV"
  [ -e "$TMP/compose.env.saved" ] && cp -P "$TMP/compose.env.saved" "$COMPOSE_ENV"
  rm -rf "$TMP"
}
trap restore EXIT

# --- 1. the script completes ------------------------------------------------
# The defect this pins exits 141 and writes nothing, so both halves matter.
if ! bash "$GEN" "$TMP/a.env" >/dev/null 2>"$TMP/a.err"; then
  echo "--- stderr ---"; cat "$TMP/a.err"
  fail "1: $GEN exited non-zero"
fi
[ -s "$TMP/a.env" ] || fail "1: $GEN produced no output file"

# --- 2. every secret is the length it claims --------------------------------
# A generator that returns a SHORT string is worse than one that fails: it
# hands out weak key material and says nothing.
len_of() { sed -n "s/^$1=//p" "$TMP/a.env" | head -1 | tr -d '\n' | wc -c; }
check_len() {
  local var="$1" want="$2" got
  got="$(len_of "$var")"
  [ "$got" = "$want" ] || fail "2: $var is $got characters, expected $want"
}
check_len ENCRYPTION_KEY 32          # AES-256 key material: exactly 32.
check_len ACCESS_SESSION_SECRET 32
check_len POSTGRES_PASSWORD 32
check_len OPENIDX_APP_PASSWORD 32

# --- 3. the secrets are actually random -------------------------------------
# Guards against a "fix" that swaps randomness for a constant fallback.
bash "$GEN" "$TMP/b.env" >/dev/null 2>&1 || fail "3: second run failed"
for v in POSTGRES_PASSWORD ACCESS_SESSION_SECRET ENCRYPTION_KEY; do
  a="$(sed -n "s/^$v=//p" "$TMP/a.env" | head -1)"
  b="$(sed -n "s/^$v=//p" "$TMP/b.env" | head -1)"
  [ -n "$a" ] || fail "3: $v is empty"
  [ "$a" != "$b" ] || fail "3: $v was identical across two runs"
done

# --- 4. compose's required variables are all generated ----------------------
# Derived from the compose file, not hardcoded: `${VAR:?message}` is compose's
# "refuse to start without this", so anything spelled that way must be in the
# generated .env or the quick start stops on it.
missing=""
for v in $(grep -oE '\$\{[A-Z0-9_]+ *:?\?' "$COMPOSE_FILE" \
            | tr -d '${:?' | sort -u); do
  grep -q "^${v}=" "$TMP/a.env" || missing="$missing $v"
done
[ -z "$missing" ] && : || fail "4: compose requires these, the generator does not write them:$missing"

# --- 5. no dead Keycloak configuration --------------------------------------
# Nothing in the Go or TypeScript reads a KEYCLOAK_* variable and the compose
# service is gone; writing them told a new operator this runs on Keycloak.
if grep -q 'KEYCLOAK' "$TMP/a.env"; then
  fail "5: generated .env still contains KEYCLOAK_* settings"
fi

# --- 6. the two README commands work together -------------------------------
# The point of the whole file. Run the documented invocation verbatim and
# require compose to resolve it. `config` interpolates and validates without
# contacting a daemon, so this is safe in CI.
rm -f "$ROOT_ENV" "$COMPOSE_ENV"
bash "$GEN" >/dev/null 2>&1 || fail "6: $GEN failed when run with no arguments"
[ -s "$ROOT_ENV" ] || fail "6: $GEN wrote no $ROOT_ENV"
[ -e "$COMPOSE_ENV" ] || fail "6: compose cannot see the secrets -- no $COMPOSE_ENV"

if docker compose version >/dev/null 2>&1; then
  if ! docker compose -f "$COMPOSE_FILE" config >/dev/null 2>"$TMP/c.err"; then
    echo "--- stderr ---"; head -5 "$TMP/c.err"
    fail "6: 'docker compose -f $COMPOSE_FILE config' failed after the documented setup"
  fi
else
  # Not a pass: say which assertion did not run rather than implying it did.
  echo "note: docker compose not installed; case 6 checked the files only"
fi

# --- 7. a fresh install gets enforcement ------------------------------------
# #956: a new install enforces application assignment and evaluates ABAC in
# observe mode. The compose fallbacks keep an older .env on today's behaviour,
# so these generated lines are the only thing that turns enforcement on, and
# losing them would silently ship every new install in report mode.
grep -qx 'ACCESS_ASSIGNMENT_ENFORCE=true' "$TMP/a.env" \
  || fail "7: the generated .env does not enforce application assignment"
grep -qx 'ABAC_ENFORCE=observe' "$TMP/a.env" \
  || fail "7: the generated .env does not put ABAC in observe"

# --- 8. the lite install's required variables are all generated -------------
# The README's quick start is now scripts/lite-up.sh and the lite compose file;
# case 4's rule, applied to that file.
LITE_FILE="deployments/docker/docker-compose.lite.yml"
missing=""
# shellcheck disable=SC2016 # the characters tr deletes, not an expansion
for v in $(grep -oE '\$\{[A-Z0-9_]+ *:?\?' "$LITE_FILE" \
            | tr -d '${:?' | sort -u); do
  grep -q "^${v}=" "$TMP/a.env" || missing="$missing $v"
done
[ -z "$missing" ] || fail "8: the lite file requires these, the generator does not write them:$missing"

# --- 9. the lite file resolves, with and without every optional component ----
if docker compose version >/dev/null 2>&1; then
  for profiles in "" "elasticsearch,guacamole,ziti,observability"; do
    if ! COMPOSE_PROFILES="$profiles" docker compose -f "$LITE_FILE" config -q 2>"$TMP/l.err"; then
      echo "--- stderr ---"; head -5 "$TMP/l.err"
      fail "9: 'docker compose -f $LITE_FILE config' failed with COMPOSE_PROFILES='$profiles'"
    fi
  done
else
  echo "note: docker compose not installed; case 9 did not run"
fi

# --- 10. scripts/lite-up.sh: secrets once, the admin password once, nothing leaked
# The first-run script is exercised against a stand-in for the docker CLI, so
# its own logic is checked here without a daemon: every container reports
# healthy, and "psql" answers the way the database does -- the admin password
# is replaced the first time and on --reset-admin-password, never otherwise.
# The lite-install CI job runs the same script against a real stack.
rm -f "$ROOT_ENV" "$COMPOSE_ENV"
STUB="$TMP/stub"
mkdir -p "$STUB/bin"
cat > "$STUB/bin/docker" <<'STUBEOF'
#!/usr/bin/env bash
case "$1" in
  info)
    case "$*" in
      *MemTotal*) echo 4102029312 ;;
      *Architecture*) echo x86_64 ;;
    esac
    exit 0 ;;
  volume) exit 1 ;;
  inspect)
    shift 3   # inspect -f FORMAT
    for id in "$@"; do
      case "$id" in
        *migrate|*seed) echo "exited none 0 0 no" ;;
        *) echo "running healthy 0 0 unless-stopped" ;;
      esac
    done
    exit 0 ;;
  compose)
    case " $* " in
      *" version "*) echo 2.29.1 ;;
      *" config --services "*) printf 'postgres\nmigrate\nseed\noauth-service\n' ;;
      *" ps "*) echo "cid-${*: -1}" ;;
      *" exec "*)
        sql="$(cat)"
        bind="$(awk '$1 == "\\bind" {print $2, $3}' <<< "$sql" | tr -d "'")"
        pw="${bind% *}"
        force="${bind#* }"
        [ -n "$pw" ] || { echo "stub: the SQL carries no bound password" >&2; exit 3; }
        if [ ! -e "$STUB_STATE/pw" ] || [ "$force" = "true" ]; then
          printf '%s' "$pw" > "$STUB_STATE/pw"
          echo "admin-password-set"
        fi ;;
    esac
    exit 0 ;;
esac
exit 0
STUBEOF
chmod +x "$STUB/bin/docker"
lite_up() { PATH="$STUB/bin:$PATH" STUB_STATE="$STUB" bash scripts/lite-up.sh "$@"; }
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }  # GNU, then BSD

lite_up >"$TMP/l1.out" 2>&1 || { tail -20 "$TMP/l1.out"; fail "10: lite-up.sh failed on a fresh checkout"; }
[ -s "$ROOT_ENV" ] || fail "10: lite-up.sh wrote no .env"
[ -e "$COMPOSE_ENV" ] || fail "10: lite-up.sh left compose without its .env"
case "$(mode_of "$ROOT_ENV")" in
  600) ;;
  *) fail "10: .env holds every secret and must be readable by its owner only" ;;
esac
first_pw="$(cat "$STUB/pw" 2>/dev/null || true)"
[ -n "$first_pw" ] || fail "10: the first run did not set the admin password"
grep -qF -- "Password  $first_pw" "$TMP/l1.out" || fail "10: the first run did not print the new admin password"
while IFS='=' read -r key value; do
  case "$key" in *PASSWORD*|*SECRET*|*_KEY|*PWD) ;; *) continue ;; esac
  [ "${#value}" -ge 8 ] || continue
  if grep -qF -- "${value:0:8}" "$TMP/l1.out"; then
    fail "10: lite-up.sh printed part of $key"
  fi
done < "$ROOT_ENV"

cp "$ROOT_ENV" "$TMP/env.first"
lite_up >"$TMP/l2.out" 2>&1 || fail "10: a second run failed"
cmp -s "$ROOT_ENV" "$TMP/env.first" || fail "10: a second run changed .env"
[ "$(cat "$STUB/pw")" = "$first_pw" ] || fail "10: a second run replaced the admin password"
if grep -qF -- "$first_pw" "$TMP/l2.out"; then
  fail "10: a second run printed the admin password again"
fi

lite_up --with elasticsearch >"$TMP/l3.out" 2>&1 || fail "10: --with elasticsearch failed"
grep -qx 'COMPOSE_PROFILES=elasticsearch' "$ROOT_ENV" || fail "10: --with did not add the profile"
grep -qx 'OPENIDX_ELASTICSEARCH_URL=http://elasticsearch:9200' "$ROOT_ENV" \
  || fail "10: --with elasticsearch did not point audit-service at it"
lite_up --without elasticsearch >"$TMP/l4.out" 2>&1 || fail "10: --without elasticsearch failed"
grep -qx 'COMPOSE_PROFILES=' "$ROOT_ENV" || fail "10: --without did not remove the profile"
grep -qx 'OPENIDX_ELASTICSEARCH_URL=' "$ROOT_ENV" || fail "10: --without left audit-service pointed at Elasticsearch"

if lite_up --url http://idp.example.com/console >"$TMP/l5.out" 2>&1; then
  fail "10: --url accepted a URL with a path; the console is served at the root of its origin"
fi

OPENIDX_ADMIN_PASSWORD_FILE="$TMP/admin.pw" lite_up --reset-admin-password >"$TMP/l6.out" 2>&1 \
  || fail "10: --reset-admin-password failed"
new_pw="$(cat "$STUB/pw")"
[ "$new_pw" != "$first_pw" ] || fail "10: --reset-admin-password kept the old password"
[ "$(tr -d '\n' < "$TMP/admin.pw")" = "$new_pw" ] || fail "10: OPENIDX_ADMIN_PASSWORD_FILE does not hold the new password"
case "$(mode_of "$TMP/admin.pw")" in
  600) ;;
  *) fail "10: the admin password file must be readable by its owner only" ;;
esac
if grep -qF -- "$new_pw" "$TMP/l6.out"; then
  fail "10: the password was printed although OPENIDX_ADMIN_PASSWORD_FILE was set"
fi

echo "FIRST_RUN_SELFTEST=OK"
