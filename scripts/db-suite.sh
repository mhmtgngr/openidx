#!/usr/bin/env bash
# Run the database-gated Go packages against a real PostgreSQL, one at a time.
#
# WHY THIS EXISTS. `go test ./...` on a workstation with no database is not the
# suite CI runs. Every DB-backed helper in this tree skips when it can find
# neither a Docker daemon nor OPENIDX_TEST_DATABASE_URL, and a skip is silent:
# the run says `ok` for a package whose tests never executed. Three commits on
# this branch were pushed after a clean local `go test ./...` and went red in
# CI on a test that had skipped locally -- a fixture that had stopped matching
# the schema its code reads. Nothing was wrong with the discipline; the command
# simply was not running the tests.
#
# Each package gets its OWN database, because the shared helpers DROP and
# recreate the public schema on every call (see internal/identity/testdb_test.go)
# and several seed fixed UUIDs. They run sequentially for the same reason, plus
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

# The default list is every package holding a helper that reads a
# *_DATABASE_URL. Keep it in step with scripts/check-test-reachability.sh, which
# counts those helpers.
DEFAULT_PKGS="internal/access internal/admin internal/audit internal/common/middleware
              internal/directory internal/governance internal/identity internal/migrations
              internal/oauth internal/provisioning internal/vault"
PKGS="${*:-$DEFAULT_PKGS}"

# The per-package URL is the admin URL with its database name replaced. Split on
# the last '/' before any query string so a socket URL (…/db?host=/var/run) works.
base="${ADMIN_URL%%\?*}"
query=""
case "$ADMIN_URL" in *\?*) query="?${ADMIN_URL#*\?}";; esac
prefix="${base%/*}"

rc=0
for pkg in $PKGS; do
  db="dbsuite_$(echo "$pkg" | tr '/' '_')"
  psql "$ADMIN_URL" -qAtc "DROP DATABASE IF EXISTS $db;" >/dev/null 2>&1
  if ! psql "$ADMIN_URL" -qAtc "CREATE DATABASE $db;" >/dev/null 2>&1; then
    echo "db-suite: could not create $db; check that OPENIDX_DB_SUITE_ADMIN_URL may CREATE DATABASE" >&2
    exit 2
  fi
  echo "=== $pkg ==="
  OPENIDX_TEST_DATABASE_URL="$prefix/$db$query" go test "./$pkg/" -count=1 -timeout 30m
  [ "$?" -ne 0 ] && rc=1
  psql "$ADMIN_URL" -qAtc "DROP DATABASE IF EXISTS $db;" >/dev/null 2>&1
done

if [ "$rc" -eq 0 ]; then
  echo "db-suite: every database-gated package passed against a real PostgreSQL"
else
  echo "db-suite: at least one package failed" >&2
fi
exit "$rc"
