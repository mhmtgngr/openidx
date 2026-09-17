#!/usr/bin/env bash
# Self-test for check-release-rollout.sh: each case bends the wave into a
# shape that still parses and still releases, and asserts the guard notices.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-release-rollout.sh"

pass=0; fail=0
expect() { # expect <ok|red> <name>
  local want="$1" name="$2" out rc
  out="$(OPENIDX_WORKFLOW_DIR="$WD" OPENIDX_CELLS_DIR="$CD" bash "$GUARD" 2>&1)"; rc=$?
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = red ] && [ $rc -ne 0 ]; }; then
    echo "  ok   $name"; pass=$((pass+1))
  else
    echo "  FAIL $name (rc=$rc, wanted $want)"; echo "$out" | sed 's/^/       /'; fail=$((fail+1))
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

stage() {
  WD="$TMP/wf"; CD="$TMP/cells"; rm -rf "$WD" "$CD"; mkdir -p "$WD" "$CD"
  cp "$ROOT/.github/workflows/release.yml" "$ROOT/.github/workflows/rollout-cell.yml" "$WD/"
  cp "$ROOT"/deployments/kubernetes/cells/*.yaml "$CD/"
}

stage
expect ok "the real wave holds"

# 1. us-1 stops waiting for eu-1: two production cells in parallel.
stage
sed -i 's/^    needs: rollout-eu-1$/    needs: rollout-canary-1/' "$WD/release.yml"
expect red "us-1 no longer waits for eu-1"

# 2. eu-1 rolls out over a failed canary.
stage
python3 - "$WD/release.yml" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read()
s=s.replace("    needs: rollout-canary-1\n    uses:", "    needs: rollout-canary-1\n    if: always()\n    uses:", 1)
open(p,'w').write(s)
PY
expect red "eu-1 runs with if: always()"

# 3. The canary gate is gone: releases on cell-less installs fail here.
stage
sed -i "s/    if: vars.CELL_ROLLOUT == 'true'/    if: true/" "$WD/release.yml"
expect red "wave not gated on CELL_ROLLOUT"

# 4. The eu-1 job deploys canary's identity.
stage
python3 - "$WD/release.yml" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read()
s=s.replace("      cell: eu-1\n", "      cell: canary-1\n", 1)
open(p,'w').write(s)
PY
expect red "eu-1 job rolls out cell canary-1"

# 5. The cell's kubeconfig is no longer reachable.
stage
sed -i '0,/    secrets: inherit/s//    # secrets: none/' "$WD/release.yml"
expect red "canary job drops secrets: inherit"

# 6. The upgrade is no longer atomic.
stage
sed -i 's/--atomic --wait/--wait/' "$WD/rollout-cell.yml"
expect red "upgrade without --atomic"

# 7. The job leaves the cell's environment.
stage
sed -i 's/^    environment: cell-\${{ inputs.cell }}$/    # environment: none/' "$WD/rollout-cell.yml"
expect red "job not in the cell environment"

# 8. Nobody reads CELL_ID back from the cluster.
stage
python3 - "$WD/rollout-cell.yml" <<'PY'
import sys; p=sys.argv[1]; s=open(p).read()
i=s.index("      - name: The cell answers as itself"); s=s[:i].rstrip()+"\n"; open(p,'w').write(s)
PY
expect red "post-deploy identity check removed"

# 9. A values file names another cell.
stage
sed -i 's/cellId: "us-1"/cellId: "eu-1"/' "$CD/us-1.yaml"
expect red "us-1.yaml names eu-1"

# 10. A wave cell has no values file at all.
stage
rm "$CD/canary-1.yaml"
expect red "canary-1 has no values file"

echo "check-release-rollout.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
