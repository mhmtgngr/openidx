#!/usr/bin/env bash
# Self-test for check-go-toolchain-pin.sh.
#
# The guard's value is entirely in going red on the shape that cost a CI run, so
# that shape is the first case. The negative cases matter as much: a guard that
# reddens on the correct form is one somebody deletes.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-go-toolchain-pin.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

run_case() {
    local name="$1" want="$2" body="$3"
    local wf="$TMP/wf.yml"
    printf '%s\n' "$body" > "$wf"
    local out rc
    out=$(cd "$ROOT" && CHECK_GO_TOOLCHAIN_FILES="$wf" bash "$GUARD" --enforce 2>&1)
    rc=$?
    if [ "$rc" -eq "$want" ]; then
        echo "  ok   $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL $name (exit $rc, want $want)"
        echo "$out" | sed 's/^/       /'
        FAIL=$((FAIL + 1))
    fi
}

# The exact shape that failed Unit Tests (internal/notifications).
run_case "a loose minor version is a finding" 1 'jobs:
  test:
    steps:
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26"
          cache: true'

run_case "an env-var version spec is a finding too" 1 'jobs:
  test:
    steps:
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}'

# Even an exact version is refused: it duplicates the pin, and two pins drift.
run_case "an exact version is still a second pin" 1 'jobs:
  test:
    steps:
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26.8"'

run_case "go-version-file is the correct form" 0 'jobs:
  test:
    steps:
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true'

# A go-version key that belongs to something else must not be attributed to
# setup-go, or the guard becomes a nuisance on matrix definitions.
run_case "a matrix go-version is not a setup-go input" 0 'jobs:
  build:
    strategy:
      matrix:
        go-version: ["1.26"]
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod'

run_case "a cache key mentioning go-version is not an input" 0 'jobs:
  test:
    steps:
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - uses: actions/cache@v4
        with:
          key: os-go-build-${{ env.GO_VERSION }}-x'

run_case "a workflow with no setup-go passes" 0 'jobs:
  docs:
    steps:
      - uses: actions/checkout@v7
      - run: echo hello'

echo
echo "check-go-toolchain-pin.test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
