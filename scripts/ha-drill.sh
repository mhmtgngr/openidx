#!/usr/bin/env bash
# ha-drill.sh — run one availability-guarantee test block and FAIL if it matched
# no tests. Guards against a silent false-green when a guarantee test is renamed
# or deleted: `go test -run <regex>` exits 0 with "[no tests to run]" if the
# regex matches nothing, so we assert that PASS lines actually appeared.
#
# Usage: ha-drill.sh "<label>" <package> "<-run regex>"
set -euo pipefail

label="$1"
pkg="$2"
run="$3"

echo "── ${label} ──"

# -v so we can count RUN/PASS lines. Capture output, still stream it.
out="$(go test -count=1 -v "$pkg" -run "$run" 2>&1)"
echo "$out" | grep -E '^(=== RUN|--- (PASS|FAIL)|ok|FAIL|panic)' || true

if echo "$out" | grep -q '\[no tests to run\]'; then
	echo "❌ DRILL ERROR: '$run' in $pkg matched NO tests — a guarantee test was renamed or removed."
	exit 1
fi
if echo "$out" | grep -qE '^(--- FAIL|FAIL|panic)'; then
	echo "❌ DRILL FAILED: a guarantee regressed in $pkg."
	exit 1
fi
if ! echo "$out" | grep -qE '^--- PASS'; then
	echo "❌ DRILL ERROR: no PASS results from $pkg — nothing was verified."
	exit 1
fi
echo ""
