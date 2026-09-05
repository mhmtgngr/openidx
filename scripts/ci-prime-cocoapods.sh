#!/usr/bin/env bash
# Creates the CocoaPods `trunk` spec source before a Flutter build needs it.
#
# WHY THIS EXISTS. `build (macos-latest)` in client-desktop-build.yml went red
# on a commit whose diff is Go files under internal/, SQL migrations, tests and
# docs -- nothing a Podfile can see. The Linux and Windows legs of the same
# matrix, on the same commit, were green; build-ios in client-mobile-build.yml
# resolved the same Podfile on a macOS runner three minutes later and was green
# too. What failed was this:
#
#     Cloning spec repo `trunk` from `https://cdn.cocoapods.org/`
#       $ /opt/homebrew/bin/git clone https://cdn.cocoapods.org/ -- trunk
#     [!] Unable to add a source with url `https://cdn.cocoapods.org/` named `trunk`.
#     Cloning into 'trunk'...
#     fatal: repository 'https://cdn.cocoapods.org/' not found
#
# Read it closely: CocoaPods is trying to GIT CLONE a CDN. Source::Manager
# probes the URL to decide whether it is a CDN before creating the source
# (sources_manager.rb, find_or_create_source_with_url ->
# create_source_with_url), and when that probe does not come back it falls
# through to the plain git path -- where cdn.cocoapods.org is, correctly, not a
# repository. So a moment of trouble at somebody else's CDN arrives as a
# nonsense git error, ninety seconds into a Flutter build, on a commit that
# touched no client code.
#
# Creating the source explicitly and up front, with a retry, moves that failure
# into a step of its own that costs seconds: `pod repo add-cdn` takes the CDN
# path by name and never probes, so the git fallback cannot be reached, and if
# the CDN is genuinely down the job goes red saying which host would not answer
# instead of insisting a URL is not a repository.
#
# WHAT THIS DOES NOT DO. It does not make `pod install` immune to the CDN. Once
# the source exists, resolution still fetches shard files over the same
# network, and an outage there is still a red build -- an honest one, in
# CocoaPods' own words. This closes the source-creation probe, which is what
# actually failed, and nothing else. Wrapping the whole `flutter build` in
# ci-retry.sh would cover the remainder at the price of running a real compile
# failure three times over, which is the worse trade.
#
# Safe to run anywhere: with no `pod` on PATH it says so and exits 0, and with
# the source already present it leaves it alone.
#
# Usage: bash scripts/ci-prime-cocoapods.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TRUNK_NAME="trunk"
TRUNK_URL="https://cdn.cocoapods.org/"

# Four tries at 10s, doubling: 10 + 20 + 40 = 70 seconds of patience at worst,
# against a Flutter build that costs minutes. Overridable so the self-test can
# exercise the give-up path without waiting out the real backoff, and so an
# operator debugging a job can ask for a single attempt.
ATTEMPTS="${COCOAPODS_PRIME_ATTEMPTS:-4}"
DELAY="${COCOAPODS_PRIME_DELAY:-10}"

if ! command -v pod >/dev/null 2>&1; then
  # Not a failure: every non-macOS leg of a build matrix lands here, and
  # CocoaPods is not this script's to install. A macOS runner without `pod`
  # gets a far better message from Flutter itself a step later.
  echo "ci-prime-cocoapods: no 'pod' on PATH -- nothing to prime" >&2
  exit 0
fi

# `pod repo list` prints each source name at column 0, so an exact-line match
# is the whole test. If trunk is already here -- as a CDN or as an older git
# clone -- leave it: `pod repo add-cdn` would fail on the name, and a source
# that exists is a source CocoaPods will not have to probe for.
if pod repo list 2>/dev/null | grep -qx "$TRUNK_NAME"; then
  echo "ci-prime-cocoapods: the '$TRUNK_NAME' spec source already exists; leaving it alone"
  exit 0
fi

echo "ci-prime-cocoapods: creating the '$TRUNK_NAME' spec source from $TRUNK_URL"
bash "$ROOT/scripts/ci-retry.sh" "$ATTEMPTS" "$DELAY" -- \
  pod repo add-cdn "$TRUNK_NAME" "$TRUNK_URL"
# The retry's exit status is this script's exit status. If the CDN is down for
# every attempt the job goes red -- late, but red. That is the point.
exit $?
