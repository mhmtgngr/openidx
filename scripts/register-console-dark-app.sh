#!/usr/bin/env bash
# Register the OpenIDX admin console as a BrowZer dark app (Phase 5.2 of the
# dark-platform spec: docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md).
#
# This inserts (idempotently) a proxy_routes row for the console SPA so the
# access-service reconcilers converge:
#   - a Ziti service `openidx-console` (host.v1 -> the SPA upstream), and
#   - a BrowZer overlay route serving console.<domain> via the bootstrapper.
# The reconciler owns all Ziti/APISIX mutations (never hand-config); this seed
# only declares desired state in the DB.
#
# The console shell is TIER 1 (any enrolled user may load it); its same-origin
# /api/* calls tunnel to the Tier-2 dark backends, which enforce device-trust at
# dial time. getAPIBaseURL() already returns window.location.origin in PROD, so
# no console code change is needed for same-origin BrowZer.
#
# Idempotent: re-running upserts by name. DRY_RUN=1 prints the SQL without
# touching the DB (used by the test).
set -euo pipefail

CONSOLE_HOST=${CONSOLE_HOST:-console.tdv.org}
CONSOLE_UPSTREAM=${CONSOLE_UPSTREAM:-127.0.0.1:8443}   # nginx-served SPA (TLS)
CONSOLE_SCHEME=${CONSOLE_SCHEME:-https}
ZITI_SERVICE=${ZITI_SERVICE:-openidx-console}          # MUST match defaultDarkServices()
ORG_ID=${ORG_ID:-00000000-0000-0000-0000-000000000010}
DRY_RUN=${DRY_RUN:-0}

# psql runner: prefers a local psql, falls back to the oidx-pg container.
PG_CONTAINER=${PG_CONTAINER:-oidx-pg}
PG_USER=${PG_USER:-openidx}
PG_DB=${PG_DB:-openidx}
run_sql() {
	if command -v psql >/dev/null 2>&1 && [ -n "${PGHOST:-}" ]; then
		PGPASSWORD=${PGPASSWORD:-openidx} psql -h "${PGHOST}" -p "${PGPORT:-55432}" \
			-U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 -c "$1"
	elif command -v docker >/dev/null 2>&1; then
		docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 -c "$1"
	else
		echo "ERROR: no psql and no docker to reach Postgres" >&2
		return 1
	fi
}

FROM_URL="https://${CONSOLE_HOST}"
TO_URL="${CONSOLE_SCHEME}://${CONSOLE_UPSTREAM}"

# Upsert by name. hosting_mode=direct: the edge router hosts the SPA upstream
# itself (host.v1), matching the reconciler's dark-service host.v1 model.
SQL=$(cat <<SQL
SET app.bypass_rls = 'on';
INSERT INTO proxy_routes
  (name, description, from_url, to_url, require_auth, enabled, priority,
   ziti_enabled, ziti_service_name, browzer_enabled, landing_path, hosting_mode, org_id)
VALUES
  ('openidx-console', 'Admin console (BrowZer dark app, Tier 1 shell)',
   '${FROM_URL}', '${TO_URL}', true, true, 20,
   true, '${ZITI_SERVICE}', true, '/', 'direct', '${ORG_ID}')
ON CONFLICT (name) DO UPDATE SET
   from_url          = EXCLUDED.from_url,
   to_url            = EXCLUDED.to_url,
   ziti_enabled      = EXCLUDED.ziti_enabled,
   ziti_service_name = EXCLUDED.ziti_service_name,
   browzer_enabled   = EXCLUDED.browzer_enabled,
   hosting_mode      = EXCLUDED.hosting_mode,
   enabled           = EXCLUDED.enabled;
SQL
)

if [ "$DRY_RUN" = "1" ]; then
	echo "-- DRY_RUN: would register console BrowZer dark app --"
	echo "$SQL"
	exit 0
fi

# proxy_routes.name has no explicit UNIQUE constraint in older schemas; add one
# defensively so ON CONFLICT (name) works. Idempotent.
run_sql "SET app.bypass_rls='on'; DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='proxy_routes_name_key') THEN
    ALTER TABLE proxy_routes ADD CONSTRAINT proxy_routes_name_key UNIQUE (name);
  END IF;
END \$\$;" >/dev/null 2>&1 || true

run_sql "$SQL"
echo "Registered console BrowZer dark app: ${FROM_URL} -> ${TO_URL} (ziti service ${ZITI_SERVICE})"
echo "The access-service reconciler will converge the Ziti service + BrowZer route on its next tick."
