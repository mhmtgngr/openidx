#!/usr/bin/env bash
#
# run-ci-guards.sh — run every shell guard the workflows run, in one command.
#
# WHY THIS EXISTS. There are 29 guards under scripts/ with 27 self-tests, and
# the workflows invoke them from several different jobs with different flags.
# Nothing ran them as a set, so "I checked the guards" meant "I checked the ones
# I remembered", and the ones nobody remembered were found by CI twenty minutes
# later. That happened: a database-gated test helper that read only a private
# environment variable — so it would have skipped on every CI run — went in
# because check-test-reachability.sh was not among the guards run by hand
# beforehand.
#
# THE LIST IS DERIVED, NOT WRITTEN DOWN. It is read out of
# .github/workflows/*.yml, because a hand-kept copy would drift from CI exactly
# the way the matrix in ci.yml drifted from the tree, and a runner that omits
# the guard CI runs is worse than none: it says the guards passed.
#
# An invocation the workflow writes with `|| true` is run here too, and reported,
# but does not fail the run — matching what CI does with it rather than being
# stricter in a way that would push people to stop using this.
#
# Usage:
#   scripts/run-ci-guards.sh            # run them all
#   scripts/run-ci-guards.sh --list     # print what would run, and stop
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

WORKFLOWS=.github/workflows

if [ ! -d "$WORKFLOWS" ]; then
	echo "run-ci-guards: no $WORKFLOWS directory; run this from the repository" >&2
	exit 2
fi

# Every `bash scripts/check-*.sh ...` the workflows invoke, to the end of its
# line, deduplicated and sorted so a self-test sorts immediately before the guard
# it covers.
#
# To the end of the line matters: stopping at the first quote drops arguments,
# and an invocation run without its arguments either fails on usage — noise — or,
# worse, does something narrower than CI does and reports that as a pass.
mapfile -t INVOCATIONS < <(
	grep -ohE 'bash scripts/check-[a-z0-9-]+\.(test\.)?sh.*$' "$WORKFLOWS"/*.yml |
		sed -e 's/[[:space:]]*$//' -e "s/['\"]*$//" |
		sort -u
)

if [ "${#INVOCATIONS[@]}" -eq 0 ]; then
	echo "run-ci-guards: found no guard invocations in $WORKFLOWS — the pattern no longer matches how the" >&2
	echo "               workflows call them, so this script would report success having run nothing" >&2
	exit 2
fi

if [ "${1:-}" = "--list" ]; then
	printf '%s\n' "${INVOCATIONS[@]}"
	exit 0
fi

echo "run-ci-guards: ${#INVOCATIONS[@]} guard invocation(s) taken from $WORKFLOWS"
echo

failed=()
informational=()
needsCI=()
passed=0

for inv in "${INVOCATIONS[@]}"; do
	# `... || true` in the workflow means CI reads the output and does not gate
	# on it. Run it the same way and say so.
	soft=0
	cmd="$inv"
	if [[ "$cmd" == *"|| true" ]]; then
		soft=1
		cmd="${cmd%|| true}"
	fi

	# An argument the workflow computes -- a shell variable or a ${{ }}
	# expression -- has no value here. Running the command without it would
	# either fail on usage or quietly check less than CI does, and reporting
	# THAT as a pass is the failure this script exists to prevent. Say it is not
	# run instead.
	if [[ "$cmd" == *'$'* ]]; then
		printf '  %-58s not run (CI computes an argument)\n' "${cmd#bash scripts/}"
		needsCI+=("$cmd")
		continue
	fi

	printf '  %-58s ' "${cmd#bash scripts/}"
	if out=$(eval "$cmd" 2>&1); then
		echo "ok"
		passed=$((passed + 1))
	elif [ "$soft" -eq 1 ]; then
		echo "reported (informational in CI)"
		informational+=("$cmd")
	else
		echo "FAILED"
		failed+=("$cmd")
		# Show enough to act on without burying the summary.
		printf '%s\n' "$out" | tail -n 12 | sed 's/^/      /'
	fi
done

echo
if [ "${#needsCI[@]}" -gt 0 ]; then
	echo "run-ci-guards: ${#needsCI[@]} invocation(s) not run here because CI computes an argument for them."
	echo "               CI still runs these; this command does not stand in for a green CI run:"
	printf '  %s\n' "${needsCI[@]}"
	echo
fi

if [ "${#informational[@]}" -gt 0 ]; then
	echo "run-ci-guards: ${#informational[@]} informational finding(s) — CI reads these, it does not gate on them:"
	printf '  %s\n' "${informational[@]}"
	echo
fi

if [ "${#failed[@]}" -gt 0 ]; then
	echo "run-ci-guards: ${#failed[@]} of ${#INVOCATIONS[@]} FAILED — CI will fail on these:"
	printf '  %s\n' "${failed[@]}"
	exit 1
fi

echo "run-ci-guards: all $passed gating guard invocation(s) pass"
