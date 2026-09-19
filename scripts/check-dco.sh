#!/usr/bin/env bash
#
# check-dco.sh — every commit a pull request adds carries a Developer
# Certificate of Origin sign-off.
#
# WHY THIS EXISTS. CONTRIBUTING.md asks for `git commit -s`. A rule nobody
# checks is a rule the first hurried commit breaks, and a sign-off that is
# missing on the one commit that later matters is worth nothing; the check is
# what makes the sentence in CONTRIBUTING true.
#
# WHAT IS CHECKED. `git rev-list --no-merges <merge-base>..<head>`: the
# commits the pull request adds and nothing else. Merge commits are skipped
# because the merge button and "Update branch" produce them, they carry no
# contribution of their own, and they cannot be signed after the fact without
# rewriting history. The merge base, not the base ref's tip, bounds the range,
# so commits that reached the branch by merging the base in are not re-checked.
#
# A sign-off is `Signed-off-by: Name <email>` on its own line in the commit
# message. It is a statement, not a signature: no key is involved.
#
# Usage: scripts/check-dco.sh <base-rev> <head-rev>
# Environment, for the self-test: REPO=<path to a git repository> (default .)
set -uo pipefail
if [ $# -ne 2 ]; then
	echo "usage: $0 <base-rev> <head-rev>" >&2
	exit 2
fi
REPO="${REPO:-.}"
g() { git -C "$REPO" "$@"; }

if ! base="$(g merge-base "$1" "$2" 2>/dev/null)"; then
	echo "check-dco: cannot resolve a merge base for '$1' and '$2' in $REPO" >&2
	exit 2
fi
mapfile -t commits < <(g rev-list --no-merges "$base..$2")
if [ "${#commits[@]}" -eq 0 ]; then
	echo "check-dco: ok — no non-merge commits between $1 and $2"
	exit 0
fi

bad=0
for c in "${commits[@]}"; do
	if ! g log -1 --format=%B "$c" | grep -Eq '^Signed-off-by: [^<]+ <[^<>@[:space:]]+@[^<>[:space:]]+>[[:space:]]*$'; then
		echo "check-dco: no Signed-off-by: $(g log -1 --format='%h %s (%an)' "$c")"
		bad=$((bad + 1))
	fi
done

if [ "$bad" -ne 0 ]; then
	echo "check-dco: $bad of ${#commits[@]} commit(s) lack a Developer Certificate of Origin sign-off." >&2
	echo "           Fix the last commit with: git commit --amend -s" >&2
	echo "           Fix a branch with:        git rebase --signoff $1" >&2
	echo "           See CONTRIBUTING.md, 'Developer Certificate of Origin'." >&2
	exit 1
fi
echo "check-dco: ok — ${#commits[@]} commit(s) signed off"
