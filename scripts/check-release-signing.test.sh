#!/usr/bin/env bash
# Self-test: check-release-signing.sh must go red on each way the pairing
# between "what signed it" and "what the file is called" can be broken.
#
# A guard nobody has seen fail is a guard nobody knows works.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-release-signing.sh"
REAL="$ROOT/.github/workflows/client-mobile-release.yml"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
expect() { # expect <want: ok|red> <label> <file>
  local want="$1" label="$2" file="$3" rc=0
  OPENIDX_RELEASE_WORKFLOW="$file" bash "$GUARD" >/dev/null 2>&1 || rc=$?
  if { [ "$want" = ok ] && [ "$rc" -eq 0 ]; } || { [ "$want" = red ] && [ "$rc" -ne 0 ]; }; then
    echo "  ok   $label"
    pass=$((pass + 1))
  else
    echo "  FAIL $label (wanted $want, exit $rc)"
    fail=$((fail + 1))
  fi
}

echo "check-release-signing.test:"

# The real workflow is the green case.
expect ok "the committed release workflow passes" "$REAL"

# 1. No keystore secret at all — can only ever debug-sign.
sed 's/ANDROID_KEYSTORE_BASE64/ANDROID_NOTHING/g' "$REAL" > "$tmp/no-secret.yml"
expect red "a workflow that never reads the keystore secret" "$tmp/no-secret.yml"

# 2. Signing configured but never verified — a silently-skipped patch ships as
#    if signed, which is the exact failure the apksigner step exists to catch.
sed 's/apksigner/notasigner/g' "$REAL" > "$tmp/no-verify.yml"
expect red "a workflow that never runs apksigner" "$tmp/no-verify.yml"

# 3. apksigner runs but does not reject the debug certificate by name.
sed 's/CN=Android Debug/CN=Something Else/' "$REAL" > "$tmp/no-debug-check.yml"
expect red "an apksigner check that does not name the debug certificate" "$tmp/no-debug-check.yml"

# 4. The suffix disappears — an unsigned build under the plain release name.
sed 's/-debugsigned/-release/g' "$REAL" > "$tmp/no-suffix.yml"
expect red "a workflow with no -debugsigned suffix" "$tmp/no-suffix.yml"

# 5. The suffix is computed and then dropped from the attached asset names.
sed 's/\${{ steps.apk.outputs.suffix }}//g' "$REAL" > "$tmp/suffix-dropped.yml"
expect red "a suffix that never reaches the release assets" "$tmp/suffix-dropped.yml"

# 6. An iOS artifact published without admitting it is unsigned.
sed 's/openidx-agent-ios-\${{ github.ref_name }}-unsigned/openidx-agent-ios-${{ github.ref_name }}/g' "$REAL" \
  | sed 's/openidx-agent-ios-\${GITHUB_REF_NAME}-unsigned/openidx-agent-ios-${GITHUB_REF_NAME}/g' > "$tmp/ios-unmarked.yml"
expect red "an iOS artifact whose name omits 'unsigned'" "$tmp/ios-unmarked.yml"

echo "check-release-signing.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
