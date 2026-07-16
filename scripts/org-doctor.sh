#!/usr/bin/env bash
# org-doctor.sh — diagnose an "organization empty" / no-tenant-resolved install.
#
# Symptom this catches: a fresh Docker/self-hosted deploy where the UI shows
# empty lists ("organization empty", 0 users/groups/apps) even though migrations
# ran. The usual root cause is one of:
#   (a) the seeded default org row is missing, or
#   (b) DEFAULT_ORG_FALLBACK is not set (defaults to false), so a request with no
#       tenant subdomain/JWT signal resolves NO org and org-scoped reads (under
#       the RLS belt) come back empty / rejected.
#
# Usage:
#   DATABASE_URL=postgres://openidx:PASS@localhost:5432/openidx?sslmode=disable \
#     scripts/org-doctor.sh
#   # or point it at a running compose Postgres container:
#   PG_CONTAINER=openidx-postgres scripts/org-doctor.sh
#
# It is read-only; it changes nothing.
set -euo pipefail

DEFAULT_ORG_ID="00000000-0000-0000-0000-000000000010"
PG_CONTAINER="${PG_CONTAINER:-}"
PG_USER="${PG_USER:-openidx}"
PG_DB="${PG_DB:-openidx}"

# psql runner: prefer DATABASE_URL, else a named container, else localhost.
# row_security is disabled per-call via PGOPTIONS so diagnostics see all rows
# without a `SET` status line leaking into captured output.
psql_q() {
	local sql="$1"
	if [ -n "${DATABASE_URL:-}" ]; then
		PGOPTIONS="-c row_security=off" psql "$DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "$sql"
	elif [ -n "$PG_CONTAINER" ]; then
		docker exec -e PGOPTIONS="-c row_security=off" -i "$PG_CONTAINER" \
			psql -U "$PG_USER" -d "$PG_DB" -X -A -t -v ON_ERROR_STOP=1 -c "$sql"
	else
		PGOPTIONS="-c row_security=off" psql -U "$PG_USER" -d "$PG_DB" -X -A -t -v ON_ERROR_STOP=1 -c "$sql"
	fi
}

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
info() { printf '  \033[36mℹ\033[0m %s\n' "$*"; }

echo "OpenIDX org-doctor"
echo "=================="

# 1. Can we reach the DB and did migrations run?
echo "1. Database + migrations"
if ! ver=$(psql_q "SELECT max(version) FROM schema_migrations;" 2>/dev/null); then
	bad "cannot query schema_migrations — is the DB reachable and migrated? (run the 'migrate up' step)"
	exit 1
fi
ok "schema_migrations present, latest version = ${ver:-<none>}"

# 2. Does the organizations table + default org row exist?
echo "2. Default organization row"
if ! psql_q "SELECT 1 FROM information_schema.tables WHERE table_name='organizations';" | grep -q 1; then
	bad "organizations table missing — migration 025 (multitenancy) has not run. Re-run migrations."
	exit 1
fi
row=$(psql_q "SELECT slug||'|'||status FROM organizations WHERE id='${DEFAULT_ORG_ID}';" 2>/dev/null || true)
if [ -z "$row" ]; then
	bad "default org ${DEFAULT_ORG_ID} is MISSING. Migration 025 should seed it; re-run 'migrate up'."
	info "manual fix (as the DB OWNER, not the app role):"
	info "  INSERT INTO organizations (id,name,slug,domain,plan,status,max_users,max_applications)"
	info "  VALUES ('${DEFAULT_ORG_ID}','Default Organization','default',NULL,'enterprise','active',999999,999999)"
	info "  ON CONFLICT (id) DO NOTHING;"
else
	ok "default org exists: slug/status = ${row}"
fi

# 3. Are there users, and are they attached to the default org?
echo "3. Users + org attachment"
utotal=$(psql_q "SELECT count(*) FROM users;" 2>/dev/null || echo 0)
uorg=$(psql_q "SELECT count(*) FROM users WHERE org_id='${DEFAULT_ORG_ID}';" 2>/dev/null || echo 0)
unullorg=$(psql_q "SELECT count(*) FROM users WHERE org_id IS NULL;" 2>/dev/null || echo 0)
info "users total=${utotal}, in default org=${uorg}, org_id NULL=${unullorg}"
if [ "${unullorg:-0}" != "0" ]; then
	bad "${unullorg} users have org_id NULL — under the RLS belt they are invisible to the app."
	info "fix (as OWNER): UPDATE users SET org_id='${DEFAULT_ORG_ID}' WHERE org_id IS NULL;  (also groups/roles/applications)"
elif [ "${utotal:-0}" = "0" ]; then
	info "no users yet — run the seed step (docker-compose 'seed' service / seed.sql) or create an admin."
else
	ok "all users carry an org_id"
fi

# 4. Is the RLS belt on? (explains why missing org_id => empty lists)
echo "4. Row-Level Security belt"
rls=$(psql_q "SELECT count(*) FROM pg_policies WHERE tablename='users';" 2>/dev/null || echo 0)
if [ "${rls:-0}" != "0" ]; then
	ok "RLS policies present on users (${rls}) — the app MUST resolve an org per request or reads return empty."
else
	info "no RLS policies on users — org scoping is by query filter only."
fi

# 5. The config switch every app service needs for single-tenant.
echo "5. DEFAULT_ORG_FALLBACK (the usual culprit)"
info "This is an app-service ENV, not a DB value. For a single-tenant install every"
info "OpenIDX service must run with:  DEFAULT_ORG_FALLBACK=true"
info "and (optionally)                DEFAULT_ORG_ID=${DEFAULT_ORG_ID}"
info "Without it, a request that carries no tenant subdomain/JWT resolves NO org and"
info "the API returns empty/blocked results — exactly the 'organization empty' symptom."
info "Check a running container, e.g.:  docker exec openidx-identity-service printenv DEFAULT_ORG_FALLBACK"
info "The bundled deployments/docker/docker-compose*.yml now set this to true by default."

echo ""
echo "Summary: if the default org exists and users carry org_id, but the UI is still"
echo "empty, set DEFAULT_ORG_FALLBACK=true on every service and restart. If the org or"
echo "org_id attachment is missing, re-run the migrate (and seed) steps as the DB owner."
