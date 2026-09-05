#!/usr/bin/env bash
# Guard: a mobile release artifact must not claim a signature it does not have.
#
# Flutter's generated Android project signs the *release* build type with the
# *debug* keystore. A build that does nothing further still produces
# `app-release.apk`, and publishing that as `openidx-agent-android-v1.34.0.apk`
# tells an operator "release build" while meaning "debug key" — an APK the Play
# Store rejects, and one that permanently blocks a properly signed build from
# replacing it on any device that installed it, because the signing key changed.
#
# So client-mobile-release.yml must, together:
#   1. configure signing from ANDROID_KEYSTORE_BASE64 before building,
#   2. verify with apksigner that the built APK is not debug-signed,
#   3. suffix the filename when it could not sign, and
#   4. publish the suffix in the asset names it attaches to the release.
#
# Any one of those missing puts the pairing back. This checks all four.
#
# Usage: check-release-signing.sh [--enforce]
#   --enforce  exit non-zero on a finding (the CI mode; the default too)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="${OPENIDX_RELEASE_WORKFLOW:-$ROOT/.github/workflows/client-mobile-release.yml}"

fail=0
finding() {
  printf 'check-release-signing: %s\n' "$1" >&2
  fail=1
}

if [ ! -f "$WORKFLOW" ]; then
  finding "no release workflow at $WORKFLOW"
  exit 1
fi

body="$(cat "$WORKFLOW")"

# 1. The keystore secret has to be read somewhere in the job.
grep -q 'ANDROID_KEYSTORE_BASE64' <<<"$body" ||
  finding "the workflow never reads ANDROID_KEYSTORE_BASE64, so it can only ever debug-sign"

# 2. A signed build must be proven signed, not assumed.
grep -q 'apksigner' <<<"$body" ||
  finding "nothing runs apksigner, so a silently-skipped signing patch would ship as if signed"
grep -q 'CN=Android Debug' <<<"$body" ||
  finding "the apksigner check does not reject the Android debug certificate by name"

# 3. When it cannot sign, the filename has to say so.
grep -q -- '-debugsigned' <<<"$body" ||
  finding "no -debugsigned suffix: an unsigned build would ship under the plain release name"

# 4. …and the suffix must reach the names actually attached to the release.
#    A suffix computed and then dropped from the `files:` list is the same lie.
attached="$(sed -n '/^ *files: |/,/^ *[a-z_]*:/p' <<<"$body" | grep -c 'openidx-agent-android.*outputs.suffix' || true)"
if [ "$attached" -lt 2 ]; then
  finding "the release assets do not both carry steps.apk.outputs.suffix (found $attached of 2)"
fi

# 5. iOS ships unsigned; the artifact name has to admit it.
if grep -q 'openidx-agent-ios' <<<"$body"; then
  grep -q 'openidx-agent-ios.*unsigned' <<<"$body" ||
    finding "an iOS artifact is published without 'unsigned' in its name"
fi

if [ "$fail" -ne 0 ]; then
  echo "check-release-signing: FAIL" >&2
  exit 1
fi
echo "check-release-signing: ok — the Android artifact name tracks the key that signed it"
