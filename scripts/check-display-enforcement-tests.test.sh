#!/usr/bin/env bash
# Self-test: check-display-enforcement-tests.sh must go red on each way the
# display = enforcement table can name a test the release run cannot run, and
# must stay green on the table the repository has.
#
# A guard that cannot be shown to go red is itself the defect it hunts. Each
# fixture below is a small tree in the shape of one regression.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-display-enforcement-tests.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

# fixture <name> <table row>... -> prints the fixture root. Three tests exist:
# TestAlphaHolds (internal/alpha), TestBetaRefuses (internal/beta) and
# TestGammaEndToEnd (test/integration, behind the integration tag).
fixture() {
  local d="$tmp/$1"
  shift
  mkdir -p "$d/docs/evidence" "$d/internal/alpha" "$d/internal/beta" "$d/test/integration"
  printf 'module example.test/fixture\n' >"$d/go.mod"
  {
    printf '# Fixture\n\n## Automated checks\n\n'
    printf '| Grant | Tests | Where they run |\n|---|---|---|\n'
    printf '%s\n' "$@"
    printf '\n## Runs\n\nNothing yet.\n'
  } >"$d/docs/evidence/display-equals-enforcement.md"
  printf 'package alpha\n\nimport "testing"\n\nfunc TestAlphaHolds(t *testing.T) {}\n' \
    >"$d/internal/alpha/alpha_test.go"
  printf 'package beta\n\nimport "testing"\n\nfunc TestBetaRefuses(t *testing.T) {}\n' \
    >"$d/internal/beta/beta_test.go"
  printf '//go:build integration\n\npackage integration\n\nimport "testing"\n\nfunc TestGammaEndToEnd(t *testing.T) {}\n' \
    >"$d/test/integration/gamma_test.go"
  echo "$d"
}

# expect <ok|red> <label> <root> [finding]
# A red case must exit 1 AND print the finding it is about. Any non-zero exit
# is not enough: a guard that crashed, or was not there at all, would pass
# every red case.
expect() {
  local want="$1" label="$2" root="$3" says="${4:-}" rc=0 out
  out="$(OPENIDX_EVIDENCE_ROOT="$root" bash "$GUARD" --enforce 2>&1)" || rc=$?
  if { [ "$want" = ok ] && [ "$rc" -eq 0 ]; } ||
    { [ "$want" = red ] && [ "$rc" -eq 1 ] && [[ "$out" == *"$says"* ]]; }; then
    echo "  ok   $label"
    pass=$((pass + 1))
  else
    echo "  FAIL $label (wanted $want${says:+ saying \"$says\"}, exit $rc)"
    printf '%s\n' "$out" | sed 's/^/       /'
    fail=$((fail + 1))
  fi
}

ALPHA='| Alpha | `TestAlphaHolds` | the unit job |'
BETA='| Beta | `TestBetaRefuses`, both halves | the unit job |'

echo "check-display-enforcement-tests.test:"

# The real table is the case that matters most: if a test it names is renamed,
# this is what says so.
expect ok "the committed table resolves" "$ROOT"

expect ok "every name resolves, once" "$(fixture resolves "$ALPHA" "$BETA")"

# ---- the mapping the release run reads ---------------------------------------
d="$(fixture mapped "$ALPHA" '| Gamma | `TestGammaEndToEnd`, `TestBetaRefuses` | the integration job; the unit job |')"
got="$(OPENIDX_EVIDENCE_ROOT="$d" bash "$GUARD" --map 2>&1)"
want="$(printf 'internal/alpha\tTestAlphaHolds\trun\tAlpha\ntest/integration\tTestGammaEndToEnd\tintegration\tGamma\ninternal/beta\tTestBetaRefuses\trun\tGamma')"
if [ "$got" = "$want" ]; then
  echo "  ok   --map gives each test's package, in table order, and marks test/integration"
  pass=$((pass + 1))
else
  echo "  FAIL --map gives each test's package, in table order, and marks test/integration"
  printf '       got:\n%s\n       want:\n%s\n' "$got" "$want"
  fail=$((fail + 1))
fi

# ---- the regressions -----------------------------------------------------------
# The one this guard exists for: a test renamed and the table left behind.
d="$(fixture renamed "$ALPHA" "$BETA")"
sed -i 's/TestAlphaHolds/TestAlphaHoldsNow/' "$d/internal/alpha/alpha_test.go"
expect red "a named test that was renamed" "$d" "no _test.go defines func TestAlphaHolds("

# --map on a finding must print nothing a caller could run.
out="$(OPENIDX_EVIDENCE_ROOT="$d" bash "$GUARD" --map 2>/dev/null)"
rc=$?
if [ "$rc" -eq 1 ] && [ -z "$out" ]; then
  echo "  ok   --map on a finding exits non-zero and prints no mapping"
  pass=$((pass + 1))
else
  echo "  FAIL --map on a finding exits non-zero and prints no mapping (exit $rc, output: $out)"
  fail=$((fail + 1))
fi

d="$(fixture twice "$ALPHA" "$BETA")"
printf 'package beta\n\nimport "testing"\n\nfunc TestAlphaHolds(t *testing.T) {}\n' >"$d/internal/beta/alpha_copy_test.go"
expect red "a name defined in two packages" "$d" "is defined 2 times"

expect red "a row that names no test" \
  "$(fixture empty "$ALPHA" '| Beta | covered by hand | nowhere |')" "row 'Beta' names no test"

expect red "a test named without backticks" \
  "$(fixture bare "$ALPHA" '| Beta | TestBetaRefuses, both halves | the unit job |')" \
  "names TestBetaRefuses without backticks"

d="$(fixture tagged "$ALPHA" "$BETA")"
printf '//go:build slow\n\npackage beta\n\nimport "testing"\n\nfunc TestBetaRefuses(t *testing.T) {}\n' \
  >"$d/internal/beta/beta_test.go"
expect red "a test behind a build tag outside test/integration" "$d" "is behind \`//go:build slow\`"

d="$(fixture module "$ALPHA" "$BETA")"
mkdir -p "$d/agent/internal/beta"
printf 'module example.test/agent\n' >"$d/agent/go.mod"
mv "$d/internal/beta/beta_test.go" "$d/agent/internal/beta/beta_test.go"
expect red "a test in another Go module" "$d" "is in the Go module at agent/"

# Go does not build testdata, so a definition there is not a test.
d="$(fixture testdata "$ALPHA" "$BETA")"
mkdir -p "$d/internal/beta/testdata"
mv "$d/internal/beta/beta_test.go" "$d/internal/beta/testdata/beta_test.go"
expect red "a definition under testdata does not count" "$d" "no _test.go defines func TestBetaRefuses("

expect red "only integration-job tests: the release run would run nothing" \
  "$(fixture onlyintegration '| Gamma | `TestGammaEndToEnd` | the integration job |')" \
  "no test in the table is one the release run can run"

# ---- the table itself ----------------------------------------------------------
d="$(fixture nosection "$ALPHA")"
sed -i 's/^## Automated checks$/## Checks/' "$d/docs/evidence/display-equals-enforcement.md"
expect red "no Automated checks section" "$d" "has no '## Automated checks' section"

d="$(fixture nocolumn "$ALPHA")"
sed -i 's/^| Grant | Tests | Where they run |$/| Grant | Checks | Where they run |/' "$d/docs/evidence/display-equals-enforcement.md"
expect red "a table with no Tests column" "$d" "has no Grant or no Tests column"

d="$(fixture nodoc "$ALPHA")"
rm "$d/docs/evidence/display-equals-enforcement.md"
expect red "no evidence doc" "$d" "display-equals-enforcement.md is missing"

echo "check-display-enforcement-tests.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
