#!/usr/bin/env bash
# Self-test for check-release-dispatch.sh.
#
# The guard's whole value is that it goes red on the asymmetry it was written
# for, so each case below removes exactly one half of the dispatch path and
# asserts the guard notices. A guard nobody has seen fail is a guard nobody
# should trust.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-release-dispatch.sh"

pass=0; fail=0
expect() { # expect <ok|red> <name> ; workflow dir already staged in $WD
  local want="$1" name="$2" out rc
  out="$(OPENIDX_WORKFLOW_DIR="$WD" bash "$GUARD" 2>&1)"; rc=$?
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = red ] && [ $rc -ne 0 ]; }; then
    echo "  ok   $name"; pass=$((pass+1))
  else
    echo "  FAIL $name (rc=$rc, wanted $want)"; echo "$out" | sed 's/^/       /'; fail=$((fail+1))
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

stage() { # stage a pristine copy of the real workflows
  WD="$TMP/wf"; rm -rf "$WD"; mkdir -p "$WD"
  cp "$ROOT/.github/workflows/release.yml" "$ROOT/.github/workflows/docker.yml" "$WD/"
}

# The tree as it stands must pass, or every red case below proves nothing.
stage
expect ok "the real workflows hold both paths together"

# 1. release.yml stops being dispatchable at all.
stage
sed -i 's/^  workflow_dispatch:$/  # removed/' "$WD/release.yml"
expect red "release.yml not dispatchable"

# 2. The version resolves from the ref only — dispatch would release nothing.
stage
sed -i "s/inputs.version || github.ref_name/github.ref_name/" "$WD/release.yml"
expect red "version read from the ref only"

# 3. The dispatched version goes unvalidated.
stage
sed -i 's/Validate version input/Trust the caller/' "$WD/release.yml"
expect red "dispatched version unvalidated"

# 4. The hand-off is dropped — this is the gap the guard exists for.
stage
sed -i 's/gh workflow run docker.yml/echo skip/' "$WD/release.yml"
expect red "release.yml no longer starts docker.yml"

# 4b. The hand-off is there but carries no version.
stage
sed -i 's/-f version=/-f novalue=/' "$WD/release.yml"
expect red "hand-off passes no version"

# 4c. …and without actions: write it could not start anything anyway.
stage
sed -i 's/actions: write/actions: read/' "$WD/release.yml"
expect red "hand-off lacks actions: write"

# 5. docker.yml regresses to stamping on pushed tags only. This is the shape
#    the repository actually had before the dispatch path was completed.
stage
python3 - "$WD/docker.yml" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s = re.sub(
    r"    if: >-\n.*?\(github\.event_name == 'workflow_dispatch' && inputs\.version != ''\)\n",
    "    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')\n",
    s, flags=re.S)
open(p, 'w').write(s)
PY
expect red "docker.yml stamps on pushed tags only"

# 6. docker.yml stops accepting a version.
stage
sed -i 's/^      version:$/      unused:/' "$WD/docker.yml"
expect red "docker.yml takes no version input"

echo "check-release-dispatch.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
