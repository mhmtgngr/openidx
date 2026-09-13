#!/usr/bin/env bash
# Test for ddos-drill.sh (global-scale plan task 1.5). Runs the drill's own
# --check mode (which syntax-checks every scenario and asserts the wiring) and
# then verifies the guardrails that stop the day from being pointed at
# production or reported as a false green.
set -uo pipefail
cd "$(dirname "$0")/.."

fail() { echo "FAIL: $1"; exit 1; }

# --check must pass on the committed scenarios.
bash scripts/ddos-drill.sh --check >/tmp/ddos-check.out 2>&1 || { cat /tmp/ddos-check.out; fail "--check should pass on the committed scenarios"; }
grep -q "geçti" /tmp/ddos-check.out || fail "--check did not report success"
echo "OK --check passes on the six scenarios"

# A live run must refuse a production or loopback URL rather than attack it.
for bad in https://api.prod.example https://localhost:8443 https://openidx.prod.internal; do
  out="$(BASE_URL= bash scripts/ddos-drill.sh --url "$bad" 2>&1)"
  echo "$out" | grep -q "reddedildi" || fail "live run must refuse $bad"
done
echo "OK live run refuses production and loopback targets"

# Every scenario file must exist and name a threshold — the drill would fail
# --check otherwise, but assert it here too so a deleted scenario is loud.
for s in jwks-flood token-flood login-spray slowloris scim-bulk audit-search; do
  f="test/load/ddos/$s.js"
  [ -f "$f" ] || fail "scenario $f missing"
  grep -q "thresholds" "$f" || fail "$f has no thresholds"
done
echo "OK all six scenarios present with thresholds"

# The VERIFY invariant — the prize the whole day defends — must be watched by
# the flood scenarios.
for s in jwks-flood token-flood slowloris audit-search; do
  grep -q "verify_latency_ms" "test/load/ddos/$s.js" || fail "$s does not watch VERIFY latency"
done
echo "OK flood scenarios watch the VERIFY invariant"

echo "ALL PASS"
