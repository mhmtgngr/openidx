#!/usr/bin/env bash
# Runs the plans in plans.txt through the conformance suite's own runner,
# scripts/run-test-plan.py, against a suite that is already up.
#
# Usage: bash test/conformance/run-plans.sh <suite-checkout> <rendered-configs> <results-dir>
#   <suite-checkout>    a clone of the suite at the commit suite.env pins
#   <rendered-configs>  the directory setup_openidx.py wrote
#   <results-dir>       receives exports/ (one zip per plan) and run-test-plan.log
#
# Environment:
#   CONFORMANCE_SERVER  the suite's base URL (default https://localhost.emobix.co.uk:8443/)
#   PYTHON              the interpreter with requirements.txt installed (default python3)
#
# The exit code is the runner's. It is non-zero when any module failed, warned
# or was skipped without a matching entry in waivers/, when an entry there
# matched nothing, or when a module did not run to completion.
#
# --no-parallel: the plans use static clients with fixed aliases, and the
# logout plans end their user's sessions, so plans and modules run one at a
# time, as the runner itself does for any configuration with an alias.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <suite-checkout> <rendered-configs> <results-dir>" >&2
  exit 2
fi
suite="$1"
configs="$2"
results="$3"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

runner="$suite/scripts/run-test-plan.py"
if [ ! -f "$runner" ]; then
  echo "run-plans: $runner not found; is $suite a checkout of the conformance suite?" >&2
  exit 2
fi

plan_args=()
while read -r plan config; do
  case "$plan" in ''|'#'*) continue ;; esac
  if [ ! -f "$configs/$config" ]; then
    echo "run-plans: $configs/$config not found; run setup_openidx.py first" >&2
    exit 2
  fi
  plan_args+=("$plan" "$configs/$config")
done <"$here/plans.txt"

mkdir -p "$results/exports"
export CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://localhost.emobix.co.uk:8443/}"
# Development mode is how the runner drives a private suite: no API token,
# and the suite's certificate is not verified.
export CONFORMANCE_DEV_MODE=1

"${PYTHON:-python3}" "$runner" \
  --no-parallel \
  --verbose \
  --export-dir "$results/exports" \
  --expected-failures-file "$here/waivers/expected-failures.json" \
  --expected-skips-file "$here/waivers/expected-skips.json" \
  "${plan_args[@]}" 2>&1 | tee "$results/run-test-plan.log"
