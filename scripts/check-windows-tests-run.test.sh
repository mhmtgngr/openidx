#!/usr/bin/env bash
# Self-test for check-windows-tests-run.sh.
#
# A guard that cannot be shown to go red is itself the defect it hunts. Each
# case below builds a tree in the shape of a real regression and requires the
# guard to fail on it; the last requires it to pass on the shape the repository
# actually has.
set -uo pipefail

GUARD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-windows-tests-run.sh"
REAL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pass=0
fail=0

check() { # name expected_exit root
  local name="$1" want="$2" root="$3" got
  OPENIDX_WINTESTS_ROOT="$root" bash "$GUARD" --enforce >/dev/null 2>&1
  got=$?
  if [ "$got" -eq "$want" ]; then
    printf '  ok    %s\n' "$name"
    pass=$((pass + 1))
  else
    printf '  FAIL  %s (exit %d, want %d)\n' "$name" "$got" "$want"
    fail=$((fail + 1))
  fi
}

# scaffold <dir> <step-body> — a tree with one Windows-tagged test and a
# workflow whose test step carries the given body.
scaffold() {
  local dir="$1" body="$2"
  mkdir -p "$dir/.github/workflows" "$dir/agent/internal/thing"
  printf '//go:build windows\n\npackage thing\n' > "$dir/agent/internal/thing/x_windows_test.go"
  {
    printf 'jobs:\n  windows-client:\n    steps:\n'
    printf '      - name: go test (Windows-only behaviour)\n'
    printf '%s\n' "$body"
    printf '      - name: Something after it\n        run: echo done\n'
  } > "$dir/.github/workflows/windows-client-build.yml"
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# 1. The regression itself: a hand-typed package list. This is the exact line
#    that lost internal/plugin and internal/remotesupport.
scaffold "$tmp/literal" '        run: go test ./internal/secretfile/... ./internal/control/...'
check "a hand-typed package list is refused" 1 "$tmp/literal"

# 2. Derived, but silent when the derivation is empty — a step that tests
#    nothing and reports success.
scaffold "$tmp/nofail" '        run: |
          mapfile -t pkgs < <(grep -rl "go:build windows" .)
          go test "${pkgs[@]}"'
check "a derivation that cannot fail on an empty list is refused" 1 "$tmp/nofail"

# 3. The step is gone entirely — no runner for any Windows test.
mkdir -p "$tmp/nostep/.github/workflows" "$tmp/nostep/agent"
printf 'jobs:\n  windows-client:\n    steps:\n      - name: Build MSI\n        run: echo hi\n' \
  > "$tmp/nostep/.github/workflows/windows-client-build.yml"
check "a missing Windows test step is refused" 1 "$tmp/nostep"

# 4. The workflow itself is gone.
mkdir -p "$tmp/noworkflow/agent"
check "a missing windows-client-build.yml is refused" 1 "$tmp/noworkflow"

# 5. The shape the fix has: derived from the build tags, and fails on empty.
scaffold "$tmp/good" '        run: |
          set -euo pipefail
          mapfile -t pkgs < <(grep -rl --include="*_test.go" -E "^//go:build windows" . \
                              | xargs -n1 dirname | sort -u)
          if [ "${#pkgs[@]}" -eq 0 ]; then
            echo "::error::nothing to test"
            exit 1
          fi
          go test "${pkgs[@]}"'
check "a derived, failing-on-empty step passes" 0 "$tmp/good"

# 6. And the real repository passes, which is the claim the CI job makes.
check "the repository as it stands passes" 0 "$REAL_ROOT"

printf 'check-windows-tests-run.test: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
