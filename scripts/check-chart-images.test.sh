#!/usr/bin/env bash
# Self-test for check-chart-images.sh: the guard must go red on each of the
# three regressions it exists to stop, and green on the tree as it stands.
# A guard nobody has watched fail is a guard nobody can trust.
set -uo pipefail
cd "$(dirname "$0")/.."

SRC="deployments/kubernetes/helm/openidx"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fails=0

expect() { # expect <want-exit> <label> [guard args...]
  local want="$1" label="$2"; shift 2
  local out rc
  out=$(CHART_DIR="$WORK/openidx" ./scripts/check-chart-images.sh --enforce 2>&1); rc=$?
  if [ "$rc" != "$want" ]; then
    echo "FAIL: $label — guard exited $rc, expected $want"
    printf '%s\n' "$out" | sed 's/^/    /'
    fails=$((fails+1))
  else
    echo "ok: $label"
  fi
}

fresh() { rm -rf "$WORK/openidx"; cp -r "$SRC" "$WORK/openidx"; }

# Green case: the chart as committed.
fresh
expect 0 "the chart as committed passes"

# Red 1 — the registry leak: the OpenIDX namespace back in the Bitnami global.
fresh
sed -i 's|^  imageRegistry: ""|  imageRegistry: ghcr.io/mhmtgngr/openidx|' "$WORK/openidx/values.yaml"
expect 1 "OpenIDX namespace in global.imageRegistry is caught"

# Red 2 — a subchart image pinned back to the live Bitnami namespace, whose
# pinned tags are 404 since Bitnami archived them.
fresh
sed -i 's|repository: bitnamilegacy/postgresql|repository: bitnami/postgresql|' "$WORK/openidx/values.yaml"
expect 1 "a pinned docker.io/bitnami tag is caught"

# Red 3 — a template reaching for the Bitnami global directly instead of the
# openidx.imageRegistry helper.
fresh
sed -i 's|{{ include "openidx.imageRegistry" . }}|{{ .Values.global.imageRegistry }}|' \
  "$WORK/openidx/templates/identity-service.yaml"
expect 1 "a template using the Bitnami global directly is caught"

if [ "$fails" -gt 0 ]; then
  echo "check-chart-images self-test: $fails failure(s)"
  exit 1
fi
echo "check-chart-images self-test: all cases behaved"
