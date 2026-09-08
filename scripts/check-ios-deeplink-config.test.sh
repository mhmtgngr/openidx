#!/usr/bin/env bash
# Self-test for check-ios-deeplink-config.sh.
#
# The positive case is the tree's own shape before the fix: five jobs running
# `flutter create --platforms=ios,android` and nothing registering the scheme.
# The negatives matter as much — a guard that reddens on the desktop matrix, or
# on a registration that happens in a later step, is one somebody switches off.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-ios-deeplink-config.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

run_case() {
    local name="$1" want="$2" body="$3"
    local wf="$TMP/wf.yml"
    printf '%s\n' "$body" > "$wf"
    local out rc
    out=$(cd "$ROOT" && CHECK_IOS_DEEPLINK_FILES="$wf" bash "$GUARD" --enforce 2>&1)
    rc=$?
    if [ "$rc" -eq "$want" ]; then
        echo "  ok   $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL $name (exit $rc, want $want)"
        echo "$out" | sed 's/^/       /'
        FAIL=$((FAIL + 1))
    fi
}

# The exact shape every mobile job had: iOS materialized, scheme never set.
run_case "an iOS runner with no registration is a finding" 1 'jobs:
  build-ios:
    steps:
      - name: Materialize platform runners
        working-directory: client
        run: flutter create --platforms=ios,android --project-name openidx_client .
      - name: Build
        working-directory: client
        run: flutter build ios --release --no-codesign'

run_case "registering it in a later step passes" 0 'jobs:
  build-ios:
    steps:
      - name: Materialize platform runners
        working-directory: client
        run: flutter create --platforms=ios,android --project-name openidx_client .
      - name: Register the iOS URL scheme
        run: bash scripts/ci-configure-ios-deeplinks.sh
      - name: Build
        working-directory: client
        run: flutter build ios --release --no-codesign'

run_case "registering it in the same step passes" 0 'jobs:
  build-ios:
    steps:
      - name: Materialize and configure
        run: |
          cd client && flutter create --platforms=ios,android --project-name openidx_client .
          cd .. && bash scripts/ci-configure-ios-deeplinks.sh'

# BEFORE the create there is no plist to patch, so this must still be a finding.
# It is the mirror of check-macos-pod-priming.sh, where the order is the other
# way round and priming afterwards is the same as not priming.
run_case "registering it BEFORE the create is still a finding" 1 'jobs:
  build-ios:
    steps:
      - name: Register the iOS URL scheme
        run: bash scripts/ci-configure-ios-deeplinks.sh
      - name: Materialize platform runners
        working-directory: client
        run: flutter create --platforms=ios,android --project-name openidx_client .'

# The desktop matrix never materializes iOS.
run_case "a non-iOS flutter create is out of scope" 1 'jobs:
  build:
    steps:
      - name: Materialize platform runner
        working-directory: client
        run: flutter create --platforms=macos .
      - name: Build
        run: flutter build macos --release'

# A registration in a DIFFERENT job does not cover this one: each job gets a
# fresh checkout and a fresh `flutter create`.
run_case "a registration in another job does not count" 1 'jobs:
  build-ios:
    steps:
      - name: Materialize platform runners
        working-directory: client
        run: flutter create --platforms=ios,android --project-name openidx_client .
  other:
    steps:
      - name: Register the iOS URL scheme
        run: bash scripts/ci-configure-ios-deeplinks.sh'

# A guard that finds nothing to check has stopped checking, and says so rather
# than reporting a pass it did not earn.
run_case "no iOS step anywhere is a finding, not a silent pass" 1 'jobs:
  build:
    steps:
      - name: Nothing to do
        run: echo hello'

echo
echo "check-ios-deeplink-config.test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
