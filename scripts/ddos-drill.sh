#!/usr/bin/env bash
# ddos-drill.sh — run the OpenIDX DDoS game-day (global-scale plan task 1.5).
#
# A design that says "the edge absorbs this" is not evidence. This drill runs
# the six k6 scenarios in test/load/ddos against a STAGING cell while watching
# the one thing that must not move — VERIFY latency — and the one that must
# hold — legitimate ISSUE success. Anything it cannot measure it reports as
# unknown, never as a pass (the k8s-chaos-drill contract).
#
# Two modes:
#   --check         no cluster, no k6: syntax-check every scenario and assert
#                   the drill's own wiring. Runs in CI.
#   (default)       run the scenarios against --url with k6. Needs k6 and a
#                   staging BASE_URL; refuses a loopback or *.prod* host so the
#                   day is never pointed at production by accident.
#
# Usage:
#   scripts/ddos-drill.sh --check
#   scripts/ddos-drill.sh --url https://staging.openidx.example \
#       --verify-token "$TOKEN" [--only jwks-flood]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DDOS_DIR="$HERE/test/load/ddos"
MODE="run"
URL="${BASE_URL:-}"
ONLY=""

SCENARIOS=(jwks-flood token-flood login-spray slowloris scim-bulk audit-search)

while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --url) URL="$2"; shift 2 ;;
    --verify-token) export VERIFY_TOKEN="$2"; shift 2 ;;
    --only) ONLY="$2"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

FAIL=0
pass() { printf '  \033[0;32m✅ %s\033[0m\n' "$1"; }
fail() { printf '  \033[0;31m❌ %s\033[0m\n' "$1"; FAIL=1; }
note() { printf '  ℹ️  %s\n' "$1"; }

echo "🌊 OpenIDX DDoS game-day"

# ---- structural checks (both modes) -------------------------------------
echo "── Senaryolar ──"
for s in "${SCENARIOS[@]}"; do
  f="$DDOS_DIR/$s.js"
  if [ ! -f "$f" ]; then fail "$s.js eksik"; continue; fi
  # k6 scripts are ES modules; node --check parses them without executing.
  if command -v node >/dev/null 2>&1; then
    if node --check "$f" 2>/dev/null; then pass "$s.js (sözdizimi)"; else fail "$s.js sözdizimi hatası"; fi
  else
    note "node yok: $s.js sözdizimi doğrulanamadı"
  fi
  # Every scenario must state a threshold: a load test with no pass/fail line
  # is a load generator, not a drill.
  grep -q "thresholds" "$f" || fail "$s.js bir eşik (thresholds) tanımlamıyor"
done

# The VERIFY invariant must be asserted by every scenario that touches the
# edge or issue plane; a scenario that floods without watching the prize
# proves nothing about it.
for s in jwks-flood token-flood slowloris audit-search; do
  grep -q "verify_latency_ms" "$DDOS_DIR/$s.js" || fail "$s.js VERIFY gecikmesini izlemiyor"
done

if [ "$MODE" = "check" ]; then
  [ "$FAIL" -eq 0 ] && echo "✅ ddos-drill --check geçti" || echo "❌ ddos-drill --check başarısız"
  exit "$FAIL"
fi

# ---- live run -----------------------------------------------------------
# The target guard runs FIRST, before the k6 check: refusing to attack
# production or loopback must not depend on whether a load tool is installed.
if [ -z "$URL" ]; then fail "--url <staging edge> gerekli"; exit 1; fi
case "$URL" in
  *localhost*|*127.0.0.1*|*.prod*|*prod.*) fail "reddedildi: $URL üretim veya loopback görünüyor; oyun günü STAGING hücresine karşı koşar"; exit 1 ;;
esac
if ! command -v k6 >/dev/null 2>&1; then
  fail "k6 kurulu değil (https://k6.io); --check ile yapı doğrulaması yapabilirsiniz"
  exit 1
fi

export BASE_URL="$URL"
mkdir -p "$HERE/docs/evidence"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SUMMARY="$HERE/docs/evidence/ddos-gameday-$STAMP.md"
{
  echo "# DDoS game-day — $STAMP"
  echo
  echo "- target: \`$URL\`"
  echo "- scenarios: ${SCENARIOS[*]}"
  echo
  echo "| scenario | k6 exit | thresholds |"
  echo "|---|---|---|"
} > "$SUMMARY"

for s in "${SCENARIOS[@]}"; do
  [ -n "$ONLY" ] && [ "$ONLY" != "$s" ] && continue
  echo "── $s ──"
  json="$HERE/docs/evidence/ddos-$s-$STAMP.json"
  if k6 run --summary-export "$json" "$DDOS_DIR/$s.js"; then
    pass "$s: eşikler karşılandı"
    echo "| $s | 0 (pass) | met |" >> "$SUMMARY"
  else
    fail "$s: bir eşik karşılanmadı — kanıt $json"
    echo "| $s | non-zero (FAIL) | see json |" >> "$SUMMARY"
  fi
done

echo
note "özet: $SUMMARY"
[ "$FAIL" -eq 0 ] && echo "✅ oyun günü: VERIFY korundu, ISSUE meşru trafik geçti" || echo "❌ oyun günü: yukarıdaki senaryo(lar) iddiayı çürüttü"
exit "$FAIL"
