#!/usr/bin/env bash
# Self-test for check-run-blocks-can-fail.sh.
#
# The negatives carry the weight here. A guard that reddens on `|| true`, on a
# block that sets -e, or on the last command in a block is one somebody turns
# off within a week — and then the real finding it exists for goes unreported.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-run-blocks-can-fail.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

run_case() {
    local name="$1" want="$2" body="$3"
    local wf="$TMP/wf.yml"
    printf '%s\n' "$body" > "$wf"
    local out rc
    out=$(cd "$ROOT" && CHECK_RUN_BLOCK_FILES="$wf" bash "$GUARD" --enforce 2>&1)
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

# The exact shape that let a checker run without being able to fail.
run_case "an unguarded gate mid-block is a finding" 1 'jobs:
  test:
    steps:
      - name: check
        run: |
          set -uo pipefail
          go run ./tools/sqlprepare -fail
          echo done'

run_case "guarding it with an explicit exit passes" 0 'jobs:
  test:
    steps:
      - name: check
        run: |
          set -uo pipefail
          if ! go run ./tools/sqlprepare -fail; then
            echo "::error::found SQL the database refuses"
            exit 1
          fi
          echo done'

# The last command IS the step exit code -- that is how the integration suite
# gates today, and calling it a finding would be wrong.
run_case "the last command needs no guard" 0 'jobs:
  test:
    steps:
      - name: check
        run: |
          set -uo pipefail
          echo preparing
          go test ./...'

# With -e a bare failure already aborts.
run_case "a block that sets -e is out of scope" 0 'jobs:
  test:
    steps:
      - name: check
        run: |
          set -euo pipefail
          go build ./...
          echo done'

# No set line at all: the step is the runner default, not this rule.
run_case "a block with no set line is out of scope" 0 'jobs:
  test:
    steps:
      - name: check
        run: |
          go build ./...
          echo done'

# Saying "this may fail" out loud is deliberate and must pass.
run_case "an explicit || true is deliberate" 0 'jobs:
  test:
    steps:
      - name: check
        run: |
          set -uo pipefail
          go vet ./... || true
          echo done'

run_case "an || with a message is deliberate too" 0 'jobs:
  test:
    steps:
      - name: check
        run: |
          set -uo pipefail
          make lint || echo "lint is advisory here"
          echo done'

# Commands that are not gates are none of its business.
run_case "non-gating commands are ignored" 0 'jobs:
  test:
    steps:
      - name: check
        run: |
          set -uo pipefail
          curl -sf http://localhost:8001/health
          docker compose up -d
          echo done'

# ---------------------------------------------------------------------------
# RULE 2: a gate piped into another command reports that command's status.
#
# The positive case is the real line, verbatim, that carried the agent module's
# entire test suite past CI for as long as it existed -- the whole endpoint
# agent, plus the gomobile engine on every enrolled phone, under a step named
# for testing that could not go red. No `set` line at all here, which is the
# point: GitHub's default `bash -e` does not make a pipeline fail.
run_case "a gate piped into tail is a finding, even with no set line" 1 'jobs:
  smoke:
    steps:
      - name: go vet + build (windows target)
        run: |
          go vet ./...
          go test ./internal/... 2>&1 | tail -20'

# ...and -e does not rescue it either, so the rule must not be scoped to
# -e-less blocks the way rule 1 is.
run_case "a piped gate under an explicit -e is still a finding" 1 'jobs:
  smoke:
    steps:
      - name: check
        run: |
          set -e
          go test ./... | tail -5'

# The negatives. pipefail is the author saying "the first failure is the
# status", which is exactly the thing rule 2 asks for.
run_case "pipefail makes a piped gate legitimate" 0 'jobs:
  smoke:
    steps:
      - name: check
        run: |
          set -euo pipefail
          go test ./... | tee test.log'

run_case "set -o pipefail on its own line counts too" 0 'jobs:
  smoke:
    steps:
      - name: check
        run: |
          set -o pipefail
          go test ./... | tee test.log'

# `||` is an or, not a pipe. Rule 1 already accepts it and rule 2 must not
# double back and reject the same line.
run_case "|| true is not a pipe" 0 'jobs:
  smoke:
    steps:
      - name: check
        run: |
          set -uo pipefail
          go test ./... || true
          echo done'

# A pipe in a non-gating command is somebody formatting output, not a gate
# throwing its status away.
run_case "a pipe in a non-gating command is ignored" 0 'jobs:
  smoke:
    steps:
      - name: check
        run: |
          set -e
          docker compose logs | tail -50'

echo
echo "check-run-blocks-can-fail.test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
