#!/usr/bin/env bash
# Self-test: run-display-enforcement-tests.sh must fail on every result that is
# not a pass, and must pass only when every named test printed its own PASS.
#
# The release run is the only caller, and it runs once per release. So a
# regression in how it reads `go test -v` would first show on a release, as a
# green report over tests that skipped. The cases below run it against a
# stand-in `go` that prints canned output, and a stand-in `psql`, in a small
# tree whose table names three tests: TestAlphaHolds (internal/alpha),
# TestBetaRefuses (internal/beta) and TestGammaEndToEnd (test/integration).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="$ROOT/scripts/run-display-enforcement-tests.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

# The fixture tree, shared by every case.
tree="$tmp/tree"
mkdir -p "$tree/docs/evidence" "$tree/internal/alpha" "$tree/internal/beta" "$tree/test/integration"
printf 'module example.test/fixture\n' >"$tree/go.mod"
cat >"$tree/docs/evidence/display-equals-enforcement.md" <<'MD'
# Fixture

## Automated checks

| Grant | Tests | Where they run |
|---|---|---|
| Alpha | `TestAlphaHolds` | the unit job |
| Beta | `TestBetaRefuses`, both halves | the unit job |
| Gamma | `TestGammaEndToEnd` | the integration job |

## Runs
MD
printf 'package alpha\n\nimport "testing"\n\nfunc TestAlphaHolds(t *testing.T) {}\n' \
  >"$tree/internal/alpha/alpha_test.go"
printf 'package beta\n\nimport "testing"\n\nfunc TestBetaRefuses(t *testing.T) {}\n' \
  >"$tree/internal/beta/beta_test.go"
printf '//go:build integration\n\npackage integration\n\nimport "testing"\n\nfunc TestGammaEndToEnd(t *testing.T) {}\n' \
  >"$tree/test/integration/gamma_test.go"

# The stand-ins. `go test ... ./<pkg>` prints $FAKE_GO/<pkg>.out and exits
# with $FAKE_GO/<pkg>.rc (0 when absent), and logs its arguments to
# $FAKE_GO/calls.
bin="$tmp/bin"
mkdir -p "$bin"
cat >"$bin/go" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  version) echo "go version go0.0-fixture linux/amd64" ;;
  test)
    pkg="${!#}"
    pkg="${pkg#./}"
    echo "$*" >>"$FAKE_GO/calls"
    cat "$FAKE_GO/${pkg//\//_}.out" 2>/dev/null
    exit "$(cat "$FAKE_GO/${pkg//\//_}.rc" 2>/dev/null || echo 0)"
    ;;
  *) exit 3 ;;
esac
SH
printf '#!/bin/sh\necho 16.99\n' >"$bin/psql"
chmod +x "$bin/go" "$bin/psql"

# scenario <name> <alpha output> <beta output> [beta exit code]
scenario() {
  local d="$tmp/$1"
  mkdir -p "$d/go"
  printf '%s\n' "$2" >"$d/go/internal_alpha.out"
  printf '%s\n' "$3" >"$d/go/internal_beta.out"
  [ -z "${4:-}" ] || echo "$4" >"$d/go/internal_beta.rc"
  echo "$d"
}

# run <scenario dir> <database url> [tree]: runs the runner on the scenario,
# leaving its exit code in $rc.
run() {
  local d="$1" db="$2" root="${3:-$tree}"
  env PATH="$bin:$PATH" FAKE_GO="$d/go" OPENIDX_EVIDENCE_ROOT="$root" \
    OPENIDX_TEST_DATABASE_URL="$db" bash "$RUNNER" "$d/out" >"$d/stdout" 2>&1
  rc=$?
}

# check <label> <predicate> [argument...]: records whether the predicate holds.
check() {
  local label="$1"
  shift
  if "$@"; then
    echo "  ok   $label"
    pass=$((pass + 1))
  else
    echo "  FAIL $label (the runner exited $rc)"
    sed 's/^/       /' "$d/stdout" 2>/dev/null | tail -n 15
    fail=$((fail + 1))
  fi
}

# exited <code> [text]...: the runner exited <code>, and its report says each text.
exited() {
  local text
  [ "$rc" -eq "$1" ] || return 1
  shift
  for text in "$@"; do
    grep -qF -- "$text" "$d/out/report.md" 2>/dev/null || return 1
  done
}

# called [call]...: the stand-in go ran exactly these `go test` calls, or none.
called() {
  local want
  if [ "$#" -eq 0 ]; then
    [ ! -e "$d/go/calls" ]
    return
  fi
  [ "$(wc -l <"$d/go/calls")" -eq "$#" ] || return 1
  for want in "$@"; do
    grep -qxF -- "$want" "$d/go/calls" || return 1
  done
}

# row <test> <package> <result>: the report's line for one test.
row() { printf "| \`%s\` | \`%s\` | %s |" "$1" "$2" "$3"; }

A_PASS='=== RUN   TestAlphaHolds
--- PASS: TestAlphaHolds (0.01s)
PASS
ok  	example.test/fixture/internal/alpha	0.02s'
B_PASS='=== RUN   TestBetaRefuses
--- PASS: TestBetaRefuses (0.01s)
PASS
ok  	example.test/fixture/internal/beta	0.02s'

echo "run-display-enforcement-tests.test:"

# ---- the green case ------------------------------------------------------------
d="$(scenario green "$A_PASS" "$B_PASS")"
run "$d" postgres://fixture
check "every test printed its own PASS: exit 0, and the report says so" \
  exited 0 "$(row TestAlphaHolds internal/alpha PASS)" "$(row TestBetaRefuses internal/beta PASS)" \
  "**Postgres:** 16.99"
check "the report lists the integration-job test as running there" \
  exited 0 "$(row TestGammaEndToEnd test/integration 'runs in the integration job')"
check "one go test per package, anchored to the names, and none for test/integration" \
  called 'test -count=1 -v -run ^(TestAlphaHolds)$ ./internal/alpha' \
  'test -count=1 -v -run ^(TestBetaRefuses)$ ./internal/beta'

# ---- every way a named test can fail to pass -----------------------------------
d="$(scenario skip "$A_PASS" '--- SKIP: TestBetaRefuses (0.00s)
    beta_test.go:9: OPENIDX_TEST_DATABASE_URL set but unreachable
PASS
ok  	example.test/fixture/internal/beta	0.01s')"
run "$d" postgres://fixture
check "a skipped test fails the run, though go test said ok" \
  exited 1 "$(row TestBetaRefuses internal/beta SKIP)"

d="$(scenario failed "$A_PASS" '--- FAIL: TestBetaRefuses (0.01s)
FAIL
FAIL	example.test/fixture/internal/beta	0.01s' 1)"
run "$d" postgres://fixture
check "a failed test fails the run" exited 1 "$(row TestBetaRefuses internal/beta FAIL)"

d="$(scenario absent "$A_PASS" 'testing: warning: no tests to run
PASS
ok  	example.test/fixture/internal/beta	0.01s')"
run "$d" postgres://fixture
check "a test that never ran fails the run" \
  exited 1 "$(row TestBetaRefuses internal/beta 'did not run')"

# A PASS for a longer name is not a PASS for this one.
d="$(scenario prefix "$A_PASS" '--- PASS: TestBetaRefusesAgain (0.01s)
PASS')"
run "$d" postgres://fixture
check "a PASS for <name>Again is not a PASS for <name>" \
  exited 1 "$(row TestBetaRefuses internal/beta 'did not run')"

d="$(scenario subskip "$A_PASS" '=== RUN   TestBetaRefuses
=== RUN   TestBetaRefuses/against_the_database
--- PASS: TestBetaRefuses (0.01s)
    --- SKIP: TestBetaRefuses/against_the_database (0.00s)
PASS')"
run "$d" postgres://fixture
check "a passing test whose subtest skipped fails the run" \
  exited 1 "$(row TestBetaRefuses internal/beta 'SKIP in a subtest')"

d="$(scenario badexit "$A_PASS" "$B_PASS" 2)"
run "$d" postgres://fixture
check "go test exiting non-zero fails the run, even with every PASS printed" \
  exited 1 "go test ./internal/beta exited 2"

# ---- it refuses to run rather than run blind -----------------------------------
d="$(scenario nodb "$A_PASS" "$B_PASS")"
run "$d" ""
check "no OPENIDX_TEST_DATABASE_URL: exit 2" exited 2
check "no OPENIDX_TEST_DATABASE_URL: nothing run" called

cp -r "$tree" "$tmp/renamed-tree"
sed -i 's/TestBetaRefuses/TestBetaRefusesNow/' "$tmp/renamed-tree/internal/beta/beta_test.go"
d="$(scenario unresolved "$A_PASS" "$B_PASS")"
run "$d" postgres://fixture "$tmp/renamed-tree"
check "a table that does not resolve: exit 1" exited 1
check "a table that does not resolve: nothing run" called

echo "run-display-enforcement-tests.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
