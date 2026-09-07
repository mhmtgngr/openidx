#!/usr/bin/env bash
#
# run-ci-guards.test.sh — the runner's own cases.
#
# A runner that reports "all guards pass" having run none is worse than no
# runner: it is a green light nobody earned. So the cases below are mostly about
# what it must NOT do quietly — find nothing, skip something without saying so,
# or swallow a failing guard.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
RUNNER="$(pwd)/scripts/run-ci-guards.sh"

pass=0
fail=0

ok() {
	echo "  ok   $1"
	pass=$((pass + 1))
}
bad() {
	echo "  FAIL $1"
	shift
	printf '       %s\n' "$@"
	fail=$((fail + 1))
}

# A sandbox with its own workflows and its own scripts, so a case cannot be
# satisfied by the real repository's state.
sandbox() {
	local dir
	dir=$(mktemp -d)
	mkdir -p "$dir/.github/workflows" "$dir/scripts"
	cp "$RUNNER" "$dir/scripts/run-ci-guards.sh"
	echo "$dir"
}

# ---- it runs what the workflow names, and passes when they pass -------------
d=$(sandbox)
cat >"$d/.github/workflows/ci.yml" <<'YML'
jobs:
  guards:
    steps:
      - run: bash scripts/check-alpha.sh --enforce
      - run: bash scripts/check-alpha.test.sh
YML
printf '#!/usr/bin/env bash\nexit 0\n' >"$d/scripts/check-alpha.sh"
printf '#!/usr/bin/env bash\nexit 0\n' >"$d/scripts/check-alpha.test.sh"
out=$(cd "$d" && bash scripts/run-ci-guards.sh 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && [[ "$out" == *"all 2 gating guard invocation(s) pass"* ]]; then
	ok "runs both invocations the workflow names"
else
	bad "runs both invocations the workflow names" "rc=$rc" "$out"
fi
rm -rf "$d"

# ---- a failing guard fails the run, and is named ---------------------------
d=$(sandbox)
cat >"$d/.github/workflows/ci.yml" <<'YML'
jobs:
  guards:
    steps:
      - run: bash scripts/check-alpha.sh --enforce
      - run: bash scripts/check-beta.sh
YML
printf '#!/usr/bin/env bash\nexit 0\n' >"$d/scripts/check-alpha.sh"
printf '#!/usr/bin/env bash\necho "beta says no"\nexit 1\n' >"$d/scripts/check-beta.sh"
out=$(cd "$d" && bash scripts/run-ci-guards.sh 2>&1)
rc=$?
if [ "$rc" -eq 1 ] && [[ "$out" == *"check-beta.sh"* ]] && [[ "$out" == *"beta says no"* ]]; then
	ok "a failing guard fails the run, is named, and its output is shown"
else
	bad "a failing guard fails the run, is named, and its output is shown" "rc=$rc" "$out"
fi
rm -rf "$d"

# ---- `|| true` in the workflow is informational here too -------------------
d=$(sandbox)
cat >"$d/.github/workflows/ci.yml" <<'YML'
jobs:
  guards:
    steps:
      - run: bash scripts/check-soft.sh --all || true
YML
printf '#!/usr/bin/env bash\nexit 1\n' >"$d/scripts/check-soft.sh"
out=$(cd "$d" && bash scripts/run-ci-guards.sh 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && [[ "$out" == *"informational"* ]]; then
	ok "an invocation CI writes with || true does not fail the run, and says so"
else
	bad "an invocation CI writes with || true does not fail the run, and says so" "rc=$rc" "$out"
fi
rm -rf "$d"

# ---- an argument CI computes is reported as not run, never as a pass -------
d=$(sandbox)
cat >"$d/.github/workflows/ci.yml" <<'YML'
jobs:
  guards:
    steps:
      - run: bash scripts/check-ranged.sh --range "$base"
YML
printf '#!/usr/bin/env bash\nexit 0\n' >"$d/scripts/check-ranged.sh"
out=$(cd "$d" && bash scripts/run-ci-guards.sh 2>&1)
rc=$?
if [[ "$out" == *"not run"* ]] && [[ "$out" == *"CI still runs these"* ]] && [[ "$out" != *"all 1 gating"* ]]; then
	ok "an invocation whose argument CI computes is reported as not run"
else
	bad "an invocation whose argument CI computes is reported as not run" "rc=$rc" "$out"
fi
rm -rf "$d"

# ---- finding nothing is an error, not a pass ------------------------------
d=$(sandbox)
cat >"$d/.github/workflows/ci.yml" <<'YML'
jobs:
  build:
    steps:
      - run: go build ./...
YML
out=$(cd "$d" && bash scripts/run-ci-guards.sh 2>&1)
rc=$?
if [ "$rc" -eq 2 ] && [[ "$out" == *"found no guard invocations"* ]]; then
	ok "workflows naming no guard is an error, not an empty pass"
else
	bad "workflows naming no guard is an error, not an empty pass" "rc=$rc" "$out"
fi
rm -rf "$d"

# ---- against the real repository, it finds the guards that are there -------
found=$(bash "$RUNNER" --list | wc -l)
if [ "$found" -ge 40 ]; then
	ok "finds the repository's guard invocations ($found)"
else
	bad "finds the repository's guard invocations" "found only $found; the workflows call more than that"
fi

echo "run-ci-guards.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
