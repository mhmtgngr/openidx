#!/usr/bin/env bash
# Runs a command, and runs it again if it failed, with an exponential backoff.
#
# WHY THIS EXISTS: two CI jobs in this repo go red on other people's outages.
#
#   1. `build (identity-service)` died in 19 seconds on a commit that touched
#      no Go code: Docker Hub answered the HEAD for
#      library/alpine/manifests/3.24 with a 502, so BuildKit never resolved
#      the base image and no layer was ever built. The other nine matrix legs
#      pulled the same two images on the same commit without a problem.
#   2. `helm dependency build` fetches the bitnami subchart archives from a
#      CDN that resets the connection often enough to be noticed.
#
# Neither is a defect in the tree, and neither is a reason for a human to
# re-run a workflow by hand. Both are a reason to try once more, a few
# seconds later.
#
# It deliberately does NOT inspect the error. A wrapper that tries to
# recognise which failures are "transient" is a wrapper that will one day
# decide a real failure was transient and hide it. This one retries
# everything, which is only safe because the LAST attempt's exit status is
# the script's exit status: a genuinely broken command still ends red, just
# later. That trade -- a slower red, never a false green -- is the whole
# design.
#
# Usage: bash scripts/ci-retry.sh <attempts> <first-delay-seconds> -- cmd [args...]
#   attempts     total tries including the first (>= 1)
#   first-delay  seconds to wait after attempt 1; every later wait doubles
#
# Example: bash scripts/ci-retry.sh 3 5 -- helm dependency build "$CHART"
#          (tries at t=0, t=5s, t=15s, then gives up with helm's exit code)
set -uo pipefail

usage() {
  echo "usage: ci-retry.sh <attempts> <first-delay-seconds> -- command [args...]" >&2
  exit 2
}

[ "$#" -ge 4 ] || usage
attempts="$1"
delay="$2"
shift 2
[ "$1" = "--" ] || usage
shift

case "$attempts" in ''|*[!0-9]*) usage ;; esac
case "$delay" in ''|*[!0-9]*) usage ;; esac
[ "$attempts" -ge 1 ] || usage

n=1
rc=0
while : ; do
  "$@"
  rc=$?
  [ "$rc" -eq 0 ] && break
  [ "$n" -ge "$attempts" ] && break
  echo "ci-retry: attempt $n/$attempts failed (rc=$rc); retrying in ${delay}s: $*" >&2
  sleep "$delay"
  delay=$((delay * 2))
  n=$((n + 1))
done

if [ "$rc" -ne 0 ]; then
  # Named loudly on purpose: "it was flaky" is not a diagnosis, and a job that
  # burned every attempt deserves to say so in the log.
  echo "ci-retry: gave up after $n attempt(s) (rc=$rc): $*" >&2
elif [ "$n" -gt 1 ]; then
  echo "ci-retry: succeeded on attempt $n/$attempts: $*" >&2
fi
exit "$rc"
