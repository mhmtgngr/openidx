#!/usr/bin/env bash
# Guard: the dispatched release must publish everything the tagged release does.
#
# WHY: a release is cut two ways. Pushing a `vX.Y.Z` tag starts release.yml
# (binaries, GitHub Release, signed checksums, signed Helm chart) AND docker.yml
# (multi-arch images, then the release-tag job stamping X.Y.Z / X.Y / X /
# stable onto them). The second way is `workflow_dispatch`, which exists
# because some environments cannot push a tag ref at all -- a branch-scoped git
# credential answers HTTP 403 for refs/tags/*, and that is not a bug to route
# around, it is the session's write scope.
#
# The trap is that these two ways are NOT symmetric by default. On the dispatch
# path the tag is created by action-gh-release using GITHUB_TOKEN, and GitHub
# deliberately starts no workflow from a token-created push. So docker.yml
# never fires, and the dispatch publishes a release whose images still carry
# only their :sha tag -- exactly the "release whose version tags do not exist"
# that docker.yml's own retag job is commented against. It looks like a full
# release from the outside. That is this repository's organising defect class,
# arriving through the release door.
#
# So the two paths have to be held together:
#   1. release.yml is dispatchable and takes a version,
#   2. it resolves the version from EITHER trigger, not just the ref,
#   3. it validates a dispatched version rather than trusting the input,
#   4. on dispatch it hands off to docker.yml, and
#   5. docker.yml's stamping job is actually reachable from that hand-off.
#
# Miss 4 or 5 and the asymmetry is back, silently. This checks all five.
#
# Usage: check-release-dispatch.sh [--enforce]
#   --enforce  exit non-zero on a finding (the CI mode; the default too)
#
# OPENIDX_WORKFLOW_DIR overrides the workflow directory (used by the .test.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${OPENIDX_WORKFLOW_DIR:-$ROOT/.github/workflows}"

fail=0
finding() {
  printf 'check-release-dispatch: %s\n' "$1" >&2
  fail=1
}

release="$DIR/release.yml"
docker="$DIR/docker.yml"

for f in "$release" "$docker"; do
  if [ ! -f "$f" ]; then
    finding "no workflow at $f"
    exit 1
  fi
done

rbody="$(cat "$release")"
dbody="$(cat "$docker")"

# 1. release.yml has to be dispatchable, with a version to release.
grep -q 'workflow_dispatch:' <<<"$rbody" ||
  finding "release.yml is not dispatchable, so a session that cannot push tags cannot cut a release"
grep -qE '^ +version:' <<<"$rbody" ||
  finding "release.yml's dispatch takes no version input"

# 2. …and the version has to come from either trigger. A workflow that only
#    reads github.ref_name releases nothing when dispatched.
grep -q "inputs.version || github.ref_name" <<<"$rbody" ||
  finding "release.yml does not resolve the version from both triggers (inputs.version || github.ref_name)"

# 3. A dispatched version is user input; the tag ref was at least a real ref.
grep -q 'Validate version input' <<<"$rbody" ||
  finding "release.yml does not validate the dispatched version before releasing it"

# 4. The hand-off itself: on dispatch, release.yml must start docker.yml.
grep -q 'gh workflow run docker.yml' <<<"$rbody" ||
  finding "release.yml never starts docker.yml, so a dispatched release leaves the images unstamped"
grep -q 'actions: write' <<<"$rbody" ||
  finding "release.yml lacks the actions: write permission its docker.yml hand-off needs"
grep -q -- '-f version=' <<<"$rbody" ||
  finding "release.yml's docker.yml hand-off passes no version, so there is nothing to stamp"

# 5. …and docker.yml has to accept it. A hand-off into a job gated on
#    event_name == 'push' is a hand-off into a skipped job.
grep -qE "^ +version:" <<<"$dbody" ||
  finding "docker.yml's dispatch takes no version input, so release.yml's hand-off is dropped"
if grep -qE "if: github\.event_name == 'push' && startsWith\(github\.ref, 'refs/tags/v'\)$" <<<"$dbody"; then
  finding "docker.yml's release-tag job still runs on pushed tags only; a dispatched release would skip it"
fi
grep -q "github.event_name == 'workflow_dispatch' && inputs.version != ''" <<<"$dbody" ||
  finding "docker.yml's release-tag job is not reachable from a dispatch carrying a version"

# 6. …and it has to stamp the same NAMES, which is a second asymmetry hiding
#    behind the first. On a pushed tag the build job's metadata-action already
#    publishes the un-prefixed 1.2.3 / 1.2 / 1 through type=semver -- the form
#    RELEASING.md tells consumers to pull and a chart values.yaml pins. A
#    dispatch has no tag ref, type=semver matches nothing, and the retag job is
#    then the only thing that could create them. Stamping only vX.Y.Z there
#    reaches the job and still ships a release the documented pull misses.
for out in bare bare_major_minor bare_major; do
  grep -q "steps.version.outputs.$out" <<<"$dbody" ||
    finding "docker.yml's retag step does not stamp \$$out; a dispatched release would publish v1.2.3 but not the 1.2.3 the docs tell consumers to pull"
done

if [ "$fail" -eq 0 ]; then
  echo "check-release-dispatch: ok — the dispatched release stamps images like the tagged one"
fi
exit "$fail"
