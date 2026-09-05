#!/usr/bin/env bash
# Self-test for check-e2e-suite.sh: each way the register can go wrong has to
# make it red, and a correct register has to make it green.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-e2e-suite.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
mk() { # mk <register-body>
  rm -rf "$TMP/e2e"; mkdir -p "$TMP/e2e"
  : > "$TMP/e2e/alpha.spec.ts"
  : > "$TMP/e2e/beta.spec.ts"
  printf '%s\n' "$1" > "$TMP/e2e/suite.txt"
}
expect() { # expect <want-rc> <name>
  local want="$1" name="$2" rc
  SH_E2E_DIR="$TMP/e2e" SH_E2E_REGISTER="$TMP/e2e/suite.txt" bash "$GUARD" >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq "$want" ]; then pass=$((pass+1)); echo "  ok   $name"
  else fail=$((fail+1)); echo "  FAIL $name (rc=$rc, want $want)"; fi
}

mk 'run  e2e/alpha.spec.ts
hold e2e/beta.spec.ts  asserts a route the app does not have'
expect 0 "a complete register with a reason is green"

mk 'run  e2e/alpha.spec.ts'
expect 1 "a spec file missing from the register is red"

mk 'run  e2e/alpha.spec.ts
hold e2e/beta.spec.ts'
expect 1 "a hold with no reason is red"

mk 'run  e2e/alpha.spec.ts
hold e2e/beta.spec.ts  reason
run  e2e/gamma.spec.ts'
expect 1 "a register naming a file that does not exist is red"

mk 'hold e2e/alpha.spec.ts  reason
hold e2e/beta.spec.ts   reason'
expect 1 "a register with nothing to run is red"

mk 'run  e2e/alpha.spec.ts
run  e2e/alpha.spec.ts
hold e2e/beta.spec.ts  reason'
expect 1 "a file listed twice is red"

mk 'maybe e2e/alpha.spec.ts
hold  e2e/beta.spec.ts  reason'
expect 1 "an unknown status word is red"

mk '# only comments and blanks

run  e2e/alpha.spec.ts
hold e2e/beta.spec.ts  reason'
expect 0 "comments and blank lines are ignored"

echo "check-e2e-suite.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
