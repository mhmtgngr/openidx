#!/usr/bin/env bash
# LIVE Tier-2 dark drill against the openidx edge (oidx-apisix, :9280).
# Fully self-restoring: backs up each management route's exact JSON, applies an
# edge-level dark gate (fault-injection -> 403 overlay-only), MEASURES the effect
# on every service, then restores byte-faithfully and re-verifies. Never leaves
# the edge in a darked state (restore runs on EXIT via trap).
#
# This complements `scripts/dark-mode.sh --self-test` (offline mocks) and the
# full seed-based cutover: it proves, against the REAL live edge, that Tier-2
# management surfaces (admin/audit/governance/provisioning/scim) go edge-dark
# (403) while Tier-0/1 (enroll, oauth, well-known, identity, SPA) stay reachable
# — then reverts to the exact prior route JSON. Requires APISIX_ADMIN_KEY.
#
#   APISIX_ADMIN_KEY=... bash scripts/dark-drill-live.sh
set -uo pipefail
ADMIN=http://127.0.0.1:9280
KEY=${APISIX_ADMIN_KEY:?set APISIX_ADMIN_KEY (see run-access.sh)}
H=openidx.tdv.org
RES="--resolve openidx.tdv.org:443:127.0.0.1 -k -s"
WORK=$(mktemp -d /tmp/dark-drill.XXXXXX)

# Tier-2 management/data-plane routes to dark (dedicated routes only; NOT the
# access/enroll bootstrap, NOT oauth/wellknown/identity/SPA).
TIER2_ROUTES=(openidx-api-audit openidx-api-governance openidx-api-provisioning openidx-scim openidx-api-admin)

api(){ curl -s -H "X-API-KEY: $KEY" "$@"; }
code(){ curl $RES -o /dev/null -w '%{http_code}' --max-time 6 "https://$H$1" 2>/dev/null; }

echo "== 1. BACKUP Tier-2 route JSON (strip read-only create/update_time) =="
for r in "${TIER2_ROUTES[@]}"; do
  api "$ADMIN/apisix/admin/routes/$r" | python3 -c "
import sys,json
v=json.load(sys.stdin)['value']
for ro in ('create_time','update_time'): v.pop(ro,None)
print(json.dumps(v))" > "$WORK/$r.json"
  echo "  backed up $r ($(wc -c < "$WORK/$r.json") bytes)"
done

restore(){
  echo "== RESTORE (byte-faithful PUT of original route JSON) =="
  for r in "${TIER2_ROUTES[@]}"; do
    [ -s "$WORK/$r.json" ] || { echo "  !! no backup for $r"; continue; }
    out=$(api "$ADMIN/apisix/admin/routes/$r" -X PUT -d @"$WORK/$r.json" -w '\n%{http_code}')
    echo "  restored $r -> $(echo "$out" | tail -1)"
  done
}
trap restore EXIT   # <-- guarantees we never leave it dark

echo ""
echo "== 2. DARK: add fault-injection (403 overlay-only) to each Tier-2 route =="
for r in "${TIER2_ROUTES[@]}"; do
  # merge the plugin into the existing route (PATCH keeps everything else)
  out=$(api "$ADMIN/apisix/admin/routes/$r" -X PATCH \
    -d '{"plugins":{"fault-injection":{"abort":{"http_status":403,"body":"dark: this surface is overlay-only (Ziti). Enroll + dial over the overlay.\n"}}}}' \
    -w '\n%{http_code}')
  echo "  darked $r -> $(echo "$out" | tail -1)"
done
sleep 1   # let etcd propagate to the data plane

echo ""
echo "== 3. MEASURE effect (public edge, unauth) =="
printf "  %-14s %-30s %-8s %-8s %s\n" SERVICE PATH BEFORE AFTER EFFECT
meas(){ # svc path before
  local a; a=$(code "$2")
  local eff="reachable"; [ "$a" = "403" ] && eff="DARK (edge-refused 403)"
  printf "  %-14s %-30s %-8s %-8s %s\n" "$1" "$2" "$3" "$a" "$eff"
}
echo "  -- Tier 2 (SHOULD go dark) --"
meas admin-api   "/api/v1/admin/health"          "404"
meas audit       "/api/v1/audit/health"          "404"
meas governance  "/api/v1/governance/health"     "404"
meas provisioning "/api/v1/provisioning/health"  "404"
meas scim        "/scim/v2/ServiceProviderConfig" "401"
echo "  -- Tier 0/1 (MUST stay up) --"
meas wellknown   "/.well-known/openid-configuration" "200"
meas oauth       "/oauth/authorize"              "400"
meas identity    "/api/v1/identity/health"       "404"
meas spa         "/"                             "200"

echo ""
echo "== 4. show the dark body a caller now sees for a Tier-2 surface =="
curl $RES --max-time 6 "https://$H/api/v1/audit/health" 2>/dev/null | head -1

echo ""
echo "(restore runs automatically on exit)"
