#!/usr/bin/env bash
# Run the database-gated Go packages against a real PostgreSQL, one at a time.
#
# WHY THIS EXISTS. `go test ./...` on a workstation with no database is not the
# suite CI runs. Every DB-backed helper in this tree skips when it can find
# neither a Docker daemon nor TEST_POSTGRES_DSN, and a skip is silent:
# the run says `ok` for a package whose tests never executed. Three commits on
# this branch were pushed after a clean local `go test ./...` and went red in
# CI on a test that had skipped locally -- a fixture that had stopped matching
# the schema its code reads. Nothing was wrong with the discipline; the command
# simply was not running the tests.
#
# Each package gets its OWN database, owned by an unprivileged role (dbsuite_app),
# and runs the way the CI unit matrix runs it:
#
#   TEST_POSTGRES_DSN            that role on that database. The suites that
#                                build their own tables use it, and the
#                                row-level-security belts require a role that
#                                does not bypass RLS, as CI's openidx_app does.
#   TEST_POSTGRES_SUPERUSER_DSN  the admin URL on that database. The suites that
#                                build the whole schema from the migrations take
#                                a scratch database of their own from it
#                                (testsupport.ScratchDatabase), so no Docker
#                                daemon is needed; internal/migrations' role
#                                tests use it too.
#
# Packages run sequentially: several fixtures use fixed table names, and
# internal/migrations changes cluster-wide roles.
#
# Usage:
#   OPENIDX_DB_SUITE_ADMIN_URL=postgres://postgres@localhost:5432/postgres \
#     scripts/db-suite.sh [package ...]
#
# The admin URL needs CREATE DATABASE. Without it the script says so and exits
# 2 rather than pretending the suite passed -- the whole point is that a silent
# skip is what this replaces.
set -uo pipefail
cd "$(dirname "$0")/.."

ADMIN_URL="${OPENIDX_DB_SUITE_ADMIN_URL:-}"
if [ -z "$ADMIN_URL" ]; then
  echo "db-suite: set OPENIDX_DB_SUITE_ADMIN_URL to a PostgreSQL URL that may CREATE DATABASE." >&2
  echo "db-suite: refusing to run -- a suite that silently skips is what this script exists to replace." >&2
  exit 2
fi
if ! command -v psql >/dev/null 2>&1; then
  echo "db-suite: psql is not on PATH; it is needed to create one database per package." >&2
  exit 2
fi

# The default list is every package holding a database-gated helper. Keep it in
# step with scripts/check-test-reachability.sh, which counts those helpers.
DEFAULT_PKGS="internal/abac internal/access internal/admin internal/audit
              internal/common/celldir internal/common/database internal/common/events
              internal/common/middleware internal/directory internal/governance
              internal/identity internal/migrations internal/oauth internal/organization
              internal/portal internal/provisioning internal/signingkeys internal/vault
              internal/webhooks cmd/openidx/commands cmd/rekey"
PKGS="${*:-$DEFAULT_PKGS}"

# The per-package URL is the admin URL with its database name replaced. Split on
# the last '/' before any query string so a socket URL (…/db?host=/var/run) works.
base="${ADMIN_URL%%\?*}"
query=""
case "$ADMIN_URL" in *\?*) query="?${ADMIN_URL#*\?}";; esac
prefix="${base%/*}"

# The unprivileged role, with a fresh password each run.
app_pw="$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
if ! psql "$ADMIN_URL" -qAt -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<SQL
SELECT 'CREATE ROLE dbsuite_app' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbsuite_app')\gexec
ALTER ROLE dbsuite_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB PASSWORD '$app_pw';
SQL
then
  echo "db-suite: could not create the role dbsuite_app; OPENIDX_DB_SUITE_ADMIN_URL must be a superuser" >&2
  exit 2
fi
# user:password@ for the app role, on the admin URL's host and port.
hostpart="${prefix#*://}"
hostpart="${hostpart#*@}"
scheme="${prefix%%://*}"

rc=0
for pkg in $PKGS; do
  db="dbsuite_$(echo "$pkg" | tr '/' '_')"
  psql "$ADMIN_URL" -qAtc "DROP DATABASE IF EXISTS $db WITH (FORCE);" >/dev/null 2>&1
  if ! psql "$ADMIN_URL" -qAtc "CREATE DATABASE $db OWNER dbsuite_app;" >/dev/null 2>&1; then
    echo "db-suite: could not create $db; check that OPENIDX_DB_SUITE_ADMIN_URL may CREATE DATABASE" >&2
    exit 2
  fi
  echo "=== $pkg ==="
  TEST_POSTGRES_DSN="$scheme://dbsuite_app:$app_pw@$hostpart/$db$query" \
    TEST_POSTGRES_SUPERUSER_DSN="$prefix/$db$query" \
    OPENIDX_TEST_DATABASE_URL= \
    go test "./$pkg/" -count=1 -timeout 30m
  [ "$?" -ne 0 ] && rc=1
  psql "$ADMIN_URL" -qAtc "DROP DATABASE IF EXISTS $db WITH (FORCE);" >/dev/null 2>&1
done

if [ "$rc" -eq 0 ]; then
  echo "db-suite: every database-gated package passed against a real PostgreSQL"
else
  echo "db-suite: at least one package failed" >&2
fi
exit "$rc"
