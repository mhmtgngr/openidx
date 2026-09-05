#!/usr/bin/env bash
# Keeps web/admin-console/e2e/suite.txt honest.
#
# The 50-file Playwright suite was written against a mocked console and never
# ran until this branch wired it into CI. Running it found that a large part of
# it asserts against fixtures, routes and DOM shapes the product does not have.
# The CI job therefore runs the files that hold against a real stack, and the
# rest are recorded — not deleted, not `test.skip`'d, still runnable with
# `npm run test:e2e` — as `hold` lines with the reason.
#
# An exclusion list nobody can see is how a gate quietly stops covering things.
# So the register names EVERY spec file, and this guard fails when:
#   * a spec file on disk is missing from the register (adding one forces a
#     decision: is it in the gate or not, and why),
#   * the register names a file that no longer exists (a rename would otherwise
#     drop it from the gate silently),
#   * a `hold` line carries no reason,
#   * nothing is left to run.
#
# --enforce is accepted for symmetry with the other guards; the script always
# enforces.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E_DIR="${SH_E2E_DIR:-$ROOT/web/admin-console/e2e}"
REGISTER="${SH_E2E_REGISTER:-$E2E_DIR/suite.txt}"

fail=0
note() { echo "check-e2e-suite: $*" >&2; fail=1; }

if [ ! -f "$REGISTER" ]; then
  note "register not found: $REGISTER"
  exit 1
fi

declare -A listed=()
run_count=0
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
  lineno=$((lineno + 1))
  case "$line" in ''|'#'*) continue ;; esac
  status=$(printf '%s\n' "$line" | awk '{print $1}')
  spec=$(printf '%s\n' "$line" | awk '{print $2}')
  reason=$(printf '%s\n' "$line" | awk '{$1=""; $2=""; print}' | sed 's/^ *//; s/ *$//')
  case "$status" in
    run|hold) ;;
    *) note "$REGISTER:$lineno: status must be 'run' or 'hold', got '$status'"; continue ;;
  esac
  if [ -z "$spec" ]; then
    note "$REGISTER:$lineno: no spec file named"
    continue
  fi
  if [ ! -f "$E2E_DIR/${spec#e2e/}" ]; then
    note "$REGISTER:$lineno: $spec does not exist — a rename dropped it from the gate"
    continue
  fi
  if [ -n "${listed[$spec]:-}" ]; then
    note "$REGISTER:$lineno: $spec listed twice"
    continue
  fi
  listed[$spec]=$status
  if [ "$status" = hold ] && [ -z "$reason" ]; then
    note "$REGISTER:$lineno: 'hold $spec' needs a reason on the same line"
  fi
  [ "$status" = run ] && run_count=$((run_count + 1))
done < "$REGISTER"

for f in "$E2E_DIR"/*.spec.ts; do
  [ -e "$f" ] || continue
  rel="e2e/$(basename "$f")"
  if [ -z "${listed[$rel]:-}" ]; then
    note "$rel is not in $REGISTER — add it as 'run' or as 'hold <reason>'"
  fi
done

if [ "$run_count" -eq 0 ]; then
  note "no 'run' entries: the browser-journey job would assert nothing"
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "check-e2e-suite: ${#listed[@]} spec file(s) registered, $run_count in the CI gate"
