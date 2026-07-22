#!/usr/bin/env bash
# Route-set assertions for the DARK_MODE variants of seed-edge-routes.sh, using
# DRY_RUN=1 so nothing touches APISIX. Run from deployments/apisix-edge/.
set -euo pipefail
cd "$(dirname "$0")"

fail() { echo "FAIL: $1"; exit 1; }
# Match the whole route name (anchored) so e.g. "openidx-oauth" never matches
# "openidx-api-oauth".
has()  { echo "$1" | grep -qx "put $2"; }
hasnt(){ echo "$1" | grep -qx "put $2" && return 1 || return 0; }

# --- off (default): full public set ---
off=$(DARK_MODE=off DRY_RUN=1 bash seed-edge-routes.sh 2>&1)
has "$off" openidx-api-admin      || fail "off: admin route missing"
has "$off" openidx-api-enroll     || fail "off: enroll route missing"
has "$off" openidx-spa            || fail "off: SPA route missing"
echo "OK off (full set)"

# --- tier2: management dropped, Tier-0 + Tier-1 kept ---
t2=$(DARK_MODE=tier2 DRY_RUN=1 bash seed-edge-routes.sh 2>&1)
hasnt "$t2" openidx-api-admin       || fail "tier2: admin route MUST be dropped"
hasnt "$t2" openidx-api-governance  || fail "tier2: governance route MUST be dropped"
hasnt "$t2" openidx-api-audit       || fail "tier2: audit route MUST be dropped"
hasnt "$t2" openidx-scim            || fail "tier2: scim route MUST be dropped"
hasnt "$t2" openidx-api-access      || fail "tier2: /api/v1/access/* catch-all MUST be dropped"
has   "$t2" openidx-api-enroll      || fail "tier2: enroll route MUST stay (Tier 0)"
has   "$t2" openidx-wellknown       || fail "tier2: well-known MUST stay (Tier 0)"
has   "$t2" openidx-oauth           || fail "tier2: oauth auth surface MUST stay (Tier 0)"
has   "$t2" openidx-api-identity    || fail "tier2: identity self-service stays (Tier 1)"
has   "$t2" openidx-spa             || fail "tier2: SPA stays (Tier 1)"
echo "OK tier2 (management dropped)"

# --- tier1: only Tier-0 bootstrap ---
t1=$(DARK_MODE=tier1 DRY_RUN=1 bash seed-edge-routes.sh 2>&1)
hasnt "$t1" openidx-api-admin       || fail "tier1: admin route MUST be dropped"
hasnt "$t1" openidx-api-identity    || fail "tier1: identity self-service MUST be dropped"
hasnt "$t1" openidx-spa             || fail "tier1: SPA MUST be dropped"
has   "$t1" openidx-api-enroll      || fail "tier1: enroll route MUST stay (Tier 0)"
has   "$t1" openidx-wellknown       || fail "tier1: well-known MUST stay (Tier 0)"
has   "$t1" openidx-oauth           || fail "tier1: oauth auth surface MUST stay (Tier 0)"
echo "OK tier1 (Tier-0 bootstrap only)"

echo "ALL PASS"
