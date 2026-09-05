#!/usr/bin/env bash
# Self-test for check-version-sync.sh: it must go red on each way the tree
# drifted before VERSION existed, and green on a tree that agrees with itself.
set -uo pipefail
cd "$(dirname "$0")/.."

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
fails=0

expect() { # expect <want-exit> <label>
  local want="$1" label="$2" out rc
  out=$(SH_VERSION_ROOT="$WORK/tree" ./scripts/check-version-sync.sh --enforce 2>&1); rc=$?
  if [ "$rc" != "$want" ]; then
    echo "FAIL: $label — exited $rc, expected $want"
    printf '%s\n' "$out" | sed 's/^/    /'
    fails=$((fails+1))
  else
    echo "ok: $label"
  fi
}

fresh() {
  rm -rf "$WORK/tree"
  mkdir -p "$WORK/tree/web/admin-console" \
           "$WORK/tree/deployments/kubernetes/helm/openidx" \
           "$WORK/tree/client" "$WORK/tree/api/openapi"
  echo "9.9.9" > "$WORK/tree/VERSION"
  printf '{\n  "name": "x",\n  "version": "9.9.9",\n}\n' > "$WORK/tree/web/admin-console/package.json"
  printf 'version: 0.2.0\nappVersion: "9.9.9"\n' > "$WORK/tree/deployments/kubernetes/helm/openidx/Chart.yaml"
  printf 'name: openidx\nversion: 9.9.9+99900\n' > "$WORK/tree/client/pubspec.yaml"
  printf 'openapi: 3.0.3\ninfo:\n  title: a\n  version: 9.9.9\n' > "$WORK/tree/api/openapi/a.yaml"
}

fresh
expect 0 "a tree that agrees with VERSION passes"

fresh; sed -i 's/"version": "9.9.9"/"version": "1.27.0"/' "$WORK/tree/web/admin-console/package.json"
expect 1 "a stale console version is caught"

fresh; sed -i 's/appVersion: "9.9.9"/appVersion: "0.1.0"/' "$WORK/tree/deployments/kubernetes/helm/openidx/Chart.yaml"
expect 1 "a stale Chart appVersion is caught"

fresh; sed -i 's/^version: 9.9.9+99900/version: 1.33.2+13302/' "$WORK/tree/client/pubspec.yaml"
expect 1 "a stale Flutter version is caught"

fresh; sed -i 's/^  version: 9.9.9/  version: 0.1.0/' "$WORK/tree/api/openapi/a.yaml"
expect 1 "a stale OpenAPI spec version is caught"

# The chart's own `version:` moves on Helm's cadence, not the app's, and must
# not be dragged into this.
fresh; sed -i 's/^version: 0.2.0/version: 0.3.0/' "$WORK/tree/deployments/kubernetes/helm/openidx/Chart.yaml"
expect 0 "the chart's own version is not compared to the app's"

# A build number is allowed to differ from the semver part.
fresh; sed -i 's/^version: 9.9.9+99900/version: 9.9.9+12345/' "$WORK/tree/client/pubspec.yaml"
expect 0 "the Flutter build number is not part of the comparison"

fresh; rm "$WORK/tree/VERSION"
expect 1 "a missing VERSION file is itself the offence"

if [ "$fails" -gt 0 ]; then
  echo "check-version-sync self-test: $fails failure(s)"
  exit 1
fi
echo "check-version-sync self-test: all cases behaved"
