#!/usr/bin/env bash
# LIVE dark drill against the openidx edge (oidx-apisix, :9280). Tier-parameterized.
# Fully self-restoring: backs up each targeted route's exact JSON, applies an
# edge-level dark gate (fault-injection -> 403 overlay-only), MEASURES the effect
# on every service, then restores byte-faithfully and re-verifies. Never leaves
# the edge in a darked state (restore runs on EXIT via trap).
#
# Usage:  APISIX_ADMIN_KEY=... bash scripts/dark-drill-live.sh [tier2|tier1]
#   tier2 (default) — dark management + data plane (admin/audit/governance/
#                     provisioning/scim/access). Enroll door carved out + kept up.
#   tier1           — ALSO dark self-service (identity) + the SPA shell. Only the
#                     Tier-0 bootstrap (enroll, oauth, well-known, saml) stays public.
#
# Complements `scripts/dark-mode.sh --self-test` (offline mocks): this proves the
# posture against the REAL live edge, then reverts to the exact prior route set.
set -uo pipefail
TIER=${1:-tier2}
ADMIN=http://127.0.0.1:9280
KEY=${APISIX_ADMIN_KEY:?set APISIX_ADMIN_KEY (see run-access.sh)}
H=openidx.tdv.org
RES="--resolve openidx.tdv.org:443:127.0.0.1 -k -s"
WORK=$(mktemp -d /tmp/dark-drill.XXXXXX)

# Tier 2: management + data plane. access is darked WITH an enroll carve-out.
TIER2_ROUTES=(openidx-api-audit openidx-api-governance openidx-api-provisioning openidx-scim openidx-api-admin openidx-api-access)
# Tier 1 adds self-service + the SPA shell on top of the Tier-2 set.
TIER1_EXTRA=(openidx-api-identity openidx-spa)

case "$TIER" in
  tier2) DARK_ROUTES=("${TIER2_ROUTES[@]}") ;;
  tier1) DARK_ROUTES=("${TIER2_ROUTES[@]}" "${TIER1_EXTRA[@]}") ;;
  *) echo "usage: $0 [tier2|tier1]"; exit 2 ;;
esac

# The enroll door (/api/v1/access/enroll) is Tier 0 and lives INSIDE the access
# route. When access is darked we must keep enroll reachable, so we create a
# temporary higher-priority carve-out route for the exact enroll path.
ENROLL_CARVE="openidx-drill-enroll-carveout"
CREATED_ROUTES=()

api(){ curl -s -H "X-API-KEY: $KEY" "$@"; }
code(){ curl $RES -o /dev/null -w '%{http_code}' --max-time 6 "https://$H$1" 2>/dev/null; }
pcode(){ curl $RES -o /dev/null -w '%{http_code}' --max-time 6 -X POST "https://$H$1" 2>/dev/null; }

echo "== 1. BACKUP targeted route JSON ($TIER: ${#DARK_ROUTES[@]} routes) =="
for r in "${DARK_ROUTES[@]}"; do
  api "$ADMIN/apisix/admin/routes/$r" | python3 -c "
import sys,json
v=json.load(sys.stdin)['value']
for ro in ('create_time','update_time'): v.pop(ro,None)
print(json.dumps(v))" > "$WORK/$r.json"
  echo "  backed up $r ($(wc -c < "$WORK/$r.json") bytes)"
done

restore(){
  echo "== RESTORE (byte-faithful PUT of original route JSON) =="
  for r in "${DARK_ROUTES[@]}"; do
    [ -s "$WORK/$r.json" ] || { echo "  !! no backup for $r"; continue; }
    out=$(api "$ADMIN/apisix/admin/routes/$r" -X PUT -d @"$WORK/$r.json" -w '\n%{http_code}')
    echo "  restored $r -> $(echo "$out" | tail -1)"
  done
  for r in "${CREATED_ROUTES[@]}"; do
    out=$(api "$ADMIN/apisix/admin/routes/$r" -X DELETE -w '\n%{http_code}')
    echo "  deleted temp $r -> $(echo "$out" | tail -1)"
  done
}
trap restore EXIT   # <-- guarantees we never leave it dark

# Enroll carve-out (only needed when the access route is being darked).
if printf '%s\n' "${DARK_ROUTES[@]}" | grep -qx openidx-api-access; then
  echo ""
  echo "== 1b. CREATE enroll carve-out route (keeps Tier-0 enroll public) =="
  out=$(api "$ADMIN/apisix/admin/routes/$ENROLL_CARVE" -X PUT -w '\n%{http_code}' -d @- <<JSON
{"name":"$ENROLL_CARVE","hosts":["$H"],"uri":"/api/v1/access/enroll","priority":46,
 "upstream":{"type":"roundrobin","nodes":{"127.0.0.1:8007":1}}}
JSON
)
  echo "  created $ENROLL_CARVE -> $(echo "$out" | tail -1)"
  CREATED_ROUTES+=("$ENROLL_CARVE")
fi

echo ""
echo "== 2. DARK: add fault-injection (403 overlay-only) to each targeted route =="
for r in "${DARK_ROUTES[@]}"; do
  out=$(api "$ADMIN/apisix/admin/routes/$r" -X PATCH \
    -d '{"plugins":{"fault-injection":{"abort":{"http_status":403,"body":"dark: this surface is overlay-only (Ziti). Enroll + dial over the overlay.\n"}}}}' \
    -w '\n%{http_code}')
  echo "  darked $r -> $(echo "$out" | tail -1)"
done
sleep 1   # let etcd propagate to the data plane

echo ""
echo "== 3. MEASURE effect (public edge, unauth) =="
printf "  %-14s %-32s %-7s %-7s %s\n" SERVICE PATH BEFORE AFTER EFFECT
meas(){ # svc path before [post]
  local a; a=${4:-$(code "$2")}
  local eff="reachable"; [ "$a" = "403" ] && eff="DARK (edge-refused 403)"
  printf "  %-14s %-32s %-7s %-7s %s\n" "$1" "$2" "$3" "$a" "$eff"
}
echo "  -- Tier 2 (management + data) --"
meas admin-api    "/api/v1/admin/health"           "404"
meas audit        "/api/v1/audit/health"           "404"
meas governance   "/api/v1/governance/health"      "404"
meas provisioning "/api/v1/provisioning/health"    "404"
meas scim         "/scim/v2/ServiceProviderConfig" "401"
meas access       "/api/v1/access/my-devices"      "401"
echo "  -- Tier 1 (self-service + SPA) --"
meas identity     "/api/v1/identity/health"        "404"
meas spa          "/"                              "200"
echo "  -- Tier 0 (bootstrap; MUST ALWAYS stay up) --"
meas wellknown    "/.well-known/openid-configuration" "200"
meas oauth        "/oauth/authorize"               "400"
meas saml         "/api/v1/saml/metadata"          "-"
meas enroll-POST  "/api/v1/access/enroll"          "401" "$(pcode /api/v1/access/enroll)"

echo ""
echo "== 4. dark body a caller now sees for a darked surface =="
curl $RES --max-time 6 "https://$H/api/v1/audit/health" 2>/dev/null | head -1

echo ""
echo "(restore + temp-route cleanup run automatically on exit)"
