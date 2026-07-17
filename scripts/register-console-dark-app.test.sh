#!/usr/bin/env bash
# Test for register-console-dark-app.sh: asserts the DRY_RUN SQL declares the
# console as a Tier-1 BrowZer dark app with the exact Ziti service name the
# reconciler's defaultDarkServices() expects. No DB needed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(DRY_RUN=1 bash "$HERE/register-console-dark-app.sh")"

fail() { echo "FAIL: $1"; echo "--- output ---"; echo "$OUT"; exit 1; }

echo "$OUT" | grep -q "INSERT INTO proxy_routes"                 || fail "no proxy_routes insert"
echo "$OUT" | grep -q "'openidx-console'"                         || fail "route not named openidx-console"
echo "$OUT" | grep -q "ziti_service_name" && echo "$OUT" | grep -q "openidx-console" || fail "ziti service name missing"
echo "$OUT" | grep -q "browzer_enabled"                           || fail "browzer flag missing"
echo "$OUT" | grep -qi "https://console.tdv.org"                  || fail "console host wrong"
echo "$OUT" | grep -q "ON CONFLICT (name) DO UPDATE"              || fail "not idempotent (no upsert)"
# Must NOT touch the DB in dry-run.
echo "$OUT" | grep -qi "Registered console" && fail "dry-run must not claim to have registered"

# Cross-check: the ziti_service_name MUST equal what the Go reconciler models.
grep -q '"openidx-console"' "$HERE/../internal/access/ziti_reconciler.go" \
	|| fail "openidx-console not in defaultDarkServices() (reconciler/seed drift)"

echo "PASS: console registered as Tier-1 BrowZer dark app (openidx-console), idempotent, dry-run safe"
