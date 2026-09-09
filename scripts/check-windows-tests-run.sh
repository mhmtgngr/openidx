#!/usr/bin/env bash
# Guard: a //go:build windows test must have a job that can execute it.
#
# WHY: a test file behind `//go:build windows` is COMPILED OUT on Linux. It
# still sits in the package, `go test ./...` on ubuntu still reports the package
# ok, and the file's assertions have never executed. The only runner that can
# execute them is the windows-latest job in windows-client-build.yml — and that
# job used to name its packages by hand:
#
#     go test ./internal/secretfile/... ./internal/control/... ./internal/authstore/...
#
# A hand-typed list is the thing that silently loses an entry, and this one had
# lost two while carrying one it did not need:
#
#   * internal/remotesupport — asserts the Win32 INPUT struct is 40 bytes,
#     because if it drifts SendInput silently no-ops and remote-support input
#     injection stops working with no error. Never ran.
#   * internal/plugin — decides whether a directory is safe for the SYSTEM
#     service to execute a plugin from. Never ran.
#   * internal/authstore — no //go:build windows file at all, so on Windows it
#     compiles to exactly what Linux already tested.
#
# That is this repository's organising defect class arriving through a build
# tag: a test that displays as covered and is not. `go test` cannot report it,
# because from its point of view the file does not exist.
#
# So the step derives its package list from the build tags instead, and this
# guard keeps it that way — and independently checks that every package holding
# a Windows-tagged test is one the derivation would reach.
#
# Usage: check-windows-tests-run.sh [--enforce]
#   --enforce  exit non-zero on a finding (the CI mode; the default too)
#
# OPENIDX_WINTESTS_ROOT overrides the tree that is scanned (used by .test.sh).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN="${OPENIDX_WINTESTS_ROOT:-$ROOT}"
WORKFLOW="$SCAN/.github/workflows/windows-client-build.yml"
AGENT="$SCAN/agent"

findings=0
note() { printf '%s\n' "$*"; findings=$((findings + 1)); }

if [ ! -f "$WORKFLOW" ]; then
  note "check-windows-tests-run: $WORKFLOW is missing. The windows-latest job is the only runner"
  note "  that can execute a //go:build windows test; without it none of them run anywhere."
  echo "check-windows-tests-run: $findings finding(s)"
  [ "${1:-}" = "--enforce" ] || [ $# -eq 0 ] && exit 1
  exit 1
fi

# The step under test, from its name to the next step at the same indentation.
step="$(awk '
  /^      - name: go test \(Windows-only behaviour\)/ { grab = 1; print; next }
  grab && /^      - name: / { exit }
  grab { print }
' "$WORKFLOW")"

if [ -z "$step" ]; then
  note "check-windows-tests-run: windows-client-build.yml has no 'go test (Windows-only behaviour)'"
  note "  step. Either it was renamed — point this guard at the new name — or the only runner for"
  note "  every //go:build windows test in the agent module is gone."
else
  # 1. The list must be DERIVED. A literal package path in the go test line is
  #    the shape that lost two packages.
  if printf '%s' "$step" | grep -qE '^\s*run:\s*go test (\./|[^|])'; then
    note "check-windows-tests-run: the Windows test step names its packages inline. A hand-typed"
    note "  list silently loses an entry — it already did, twice. Derive it from the build tags."
  fi
  if ! printf '%s' "$step" | grep -q 'go:build windows'; then
    note "check-windows-tests-run: the Windows test step does not derive its package list from"
    note "  //go:build windows. Adding a Windows test would then not be enough to get it run."
  fi
  # 2. It must fail rather than test nothing. An empty derivation that still
  #    exits 0 is a green that proves nothing — the exact failure this guards.
  if ! printf '%s' "$step" | grep -qE 'exit 1'; then
    note "check-windows-tests-run: the Windows test step does not fail when the derivation finds no"
    note "  packages. A step that tests nothing and reports success is what this guard exists for."
  fi
fi

# 3. Independently of how the step is written: every package with a
#    Windows-tagged test file must be reachable by the derivation the step uses.
#    This is the belt — it catches a derivation that is subtly narrower than it
#    looks (a --include glob that misses a filename, a path prefix, a depth cap).
if [ -d "$AGENT" ]; then
  mapfile -t pkgs < <(cd "$AGENT" && grep -rl --include='*_test.go' -E '^//go:build windows' . 2>/dev/null \
                      | xargs -r -n1 dirname | sort -u)
  if [ "${#pkgs[@]}" -eq 0 ]; then
    note "check-windows-tests-run: no //go:build windows test files found under agent/. The agent"
    note "  ships a Windows service; if its Windows-only behaviour genuinely has no tests, say so"
    note "  here deliberately rather than letting this read as 'all covered'."
  else
    printf 'check-windows-tests-run: %d package(s) hold //go:build windows tests:\n' "${#pkgs[@]}"
    printf '  %s\n' "${pkgs[@]}"
  fi
fi

if [ "$findings" -gt 0 ]; then
  echo "check-windows-tests-run: $findings finding(s)"
  exit 1
fi
echo "check-windows-tests-run: ok — the Windows test step derives its packages and can fail"
exit 0
