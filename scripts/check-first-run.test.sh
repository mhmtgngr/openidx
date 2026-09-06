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
check_len JWT_SECRET 64
check_len POSTGRES_PASSWORD 32
check_len OPENIDX_APP_PASSWORD 32

# --- 3. the secrets are actually random -------------------------------------
# Guards against a "fix" that swaps randomness for a constant fallback.
bash "$GEN" "$TMP/b.env" >/dev/null 2>&1 || fail "3: second run failed"
for v in POSTGRES_PASSWORD JWT_SECRET ENCRYPTION_KEY; do
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

echo "FIRST_RUN_SELFTEST=OK"
