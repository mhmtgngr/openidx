#!/usr/bin/env bash
#
# changelog-assemble.sh — fold changelog.d/ fragments into a CHANGELOG release.
#
# WHY THIS EXISTS. Every pull request used to add its lines to the one
# `## [Unreleased]` section of CHANGELOG.md, at the same spot, so any two PRs in
# flight conflicted with each other on that file and nowhere else. Each PR now
# adds its own file, changelog.d/<slug>.md, and nothing touches CHANGELOG.md
# until a release is cut. This script is that release-time step.
#
# A fragment is Keep-a-Changelog headings followed by bullets:
#
#     ### Added
#     - **Thing.** What it does for whoever runs OpenIDX.
#       A continuation line, or a nested `  - bullet`, is indented.
#
#     ### Fixed
#     - ...
#
# Usage:
#   scripts/changelog-assemble.sh X.Y.Z [YYYY-MM-DD]   # cut the release section
#   scripts/changelog-assemble.sh --dry-run X.Y.Z [DATE] # print it, change nothing
#   scripts/changelog-assemble.sh --check              # validate the fragments only
#
# Cutting a release:
#   * merges every fragment, and whatever is still written under
#     `## [Unreleased]` in CHANGELOG.md, into a new `## [X.Y.Z] - DATE` section
#     directly under an emptied `## [Unreleased]`;
#   * groups the bullets by heading, in the order of HEADINGS below, and within a
#     heading keeps them in fragment-filename order (C-locale sort), so the
#     result depends only on the files and never on the order they were merged;
#   * moves the `[Unreleased]` compare link on to vX.Y.Z and adds the
#     `[X.Y.Z]` compare link under it;
#   * deletes the fragments it merged (README.md and .gitkeep stay).
#
# A heading not in HEADINGS, a bullet before any heading, or a line that is
# neither is refused with its file and line, before anything is written.
#
# CHANGELOG_ROOT overrides the tree it works on (used by the .test.sh).
set -euo pipefail
export LC_ALL=C

ROOT="${CHANGELOG_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CHANGELOG="$ROOT/CHANGELOG.md"
FRAGDIR="$ROOT/changelog.d"

# Keep a Changelog's six, in its order, then the two this CHANGELOG also uses.
HEADINGS="Added|Changed|Deprecated|Removed|Fixed|Security|Documentation|Upgrade notes"

usage() {
	sed -n '/^# Usage:/,/^# Cutting/p' "${BASH_SOURCE[0]}" | sed -e '$d' -e 's/^# \{0,1\}//' >&2
	exit 2
}

die() {
	echo "changelog-assemble: $*" >&2
	exit 1
}

MODE=write
case "${1:-}" in
--check) MODE=check; shift ;;
--dry-run) MODE=dry; shift ;;
-h | --help | "") usage ;;
esac

VERSION="" DATE=""
if [ "$MODE" != check ]; then
	VERSION="${1:-}"
	DATE="${2:-$(date -u +%Y-%m-%d)}"
	[ -n "$VERSION" ] || usage
	[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
		die "'$VERSION' is not X.Y.Z (no leading v)"
	[[ "$DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || die "'$DATE' is not YYYY-MM-DD"
fi

[ -f "$CHANGELOG" ] || die "no CHANGELOG.md under $ROOT"
grep -q '^## \[Unreleased\]' "$CHANGELOG" || die "CHANGELOG.md has no '## [Unreleased]' heading"

# Fragments in filename order. README.md documents the directory and is not one.
FRAGMENTS=()
if [ -d "$FRAGDIR" ]; then
	while IFS= read -r f; do
		FRAGMENTS+=("$f")
	done < <(find "$FRAGDIR" -maxdepth 1 -type f -name '*.md' ! -name 'README.md' | sort)
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Whatever was written under [Unreleased] the old way is released with the
# fragments rather than stranded above the new section. It is parsed by the same
# rules, first, as if it were a fragment that sorts before every other.
awk '
	/^## \[Unreleased\]/ { inside = 1; next }
	inside && /^## \[/ { exit }
	inside { print }
' "$CHANGELOG" >"$WORK/unreleased"
INPUTS=()
LABELS=()
if grep -q '[^[:space:]]' "$WORK/unreleased"; then
	INPUTS+=("$WORK/unreleased")
	LABELS+=("CHANGELOG.md [Unreleased]")
fi
for f in "${FRAGMENTS[@]+"${FRAGMENTS[@]}"}"; do
	INPUTS+=("$f")
	LABELS+=("changelog.d/$(basename "$f")")
done

if [ "${#INPUTS[@]}" -eq 0 ]; then
	if [ "$MODE" = check ]; then
		echo "changelog-assemble: ok — no fragments in changelog.d/"
		exit 0
	fi
	die "nothing to release: changelog.d/ has no fragments and [Unreleased] is empty"
fi

# Parse every input; print the assembled body on stdout, or the first problem
# of each file on stderr and exit 1.
LABELFILE="$WORK/labels"
for i in "${!INPUTS[@]}"; do
	printf '%s\t%s\n' "${INPUTS[$i]}" "${LABELS[$i]}"
done >"$LABELFILE"
awk -v headings="$HEADINGS" -v labelfile="$LABELFILE" '
	BEGIN {
		n = split(headings, order, "|")
		for (i = 1; i <= n; i++) allowed[order[i]] = 1
		FS = "\t"
		while ((getline l < labelfile) > 0) { split(l, kv, "\t"); label[kv[1]] = kv[2] }
		FS = " "
		bad = 0
	}
	FNR == 1 { heading = ""; entry = 0; incomment = 0 }
	function fail(msg) {
		printf "%s:%d: %s\n", label[FILENAME], FNR, msg > "/dev/stderr"
		bad = 1
	}
	{
		line = $0
		sub(/[ \t\r]+$/, "", line)
	}
	incomment { if (line ~ /-->/) incomment = 0; next }
	line ~ /^<!--/ { if (line !~ /-->/) incomment = 1; next }
	line == "" { next }
	line ~ /^### / {
		h = substr(line, 5)
		if (!(h in allowed)) {
			gsub(/\|/, ", ", headings)
			fail("heading \"### " h "\" is not one of: " headings)
			heading = ""
			next
		}
		heading = h; entry = 0
		next
	}
	line ~ /^- / {
		if (heading == "") { fail("a bullet before any ### heading"); next }
		body[heading] = body[heading] line "\n"
		entry = 1
		next
	}
	line ~ /^[ \t]+[^ \t]/ {
		if (!entry) { fail("an indented line with no bullet above it"); next }
		body[heading] = body[heading] line "\n"
		next
	}
	{ fail("expected \"### Heading\" or \"- bullet\", got: " line) }
	END {
		if (bad) exit 1
		first = 1
		for (i = 1; i <= n; i++) {
			if (!(order[i] in body)) continue
			if (!first) printf "\n"
			printf "### %s\n%s", order[i], body[order[i]]
			first = 0
		}
	}
' "${INPUTS[@]}" >"$WORK/body" || die "fix the lines above; nothing was written"

if ! grep -q '[^[:space:]]' "$WORK/body"; then
	[ "$MODE" = check ] && die "the fragments hold no bullets"
	die "nothing to release: the fragments hold no bullets"
fi

if [ "$MODE" = check ]; then
	echo "changelog-assemble: ok — ${#INPUTS[@]} fragment(s) parse"
	exit 0
fi

if grep -q "^## \[$(printf '%s' "$VERSION" | sed 's/\./\\./g')\]" "$CHANGELOG"; then
	die "CHANGELOG.md already has a [$VERSION] section"
fi

{
	printf '## [%s] - %s\n\n' "$VERSION" "$DATE"
	cat "$WORK/body"
} >"$WORK/section"

if [ "$MODE" = dry ]; then
	cat "$WORK/section"
	exit 0
fi

# The compare links. The previous release is the first versioned heading after
# [Unreleased]; the repository URL is read off the existing [Unreleased] link.
PREV=$(grep -m1 -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+[^]]*\]' "$CHANGELOG" | sed -E 's/^## \[(.*)\]$/\1/' || true)
BASE=$(grep -m1 -E '^\[Unreleased\]: ' "$CHANGELOG" | sed -E 's#^\[Unreleased\]: (.*)/compare/.*#\1#' || true)

awk -v section="$WORK/section" -v ver="$VERSION" -v prev="$PREV" -v base="$BASE" '
	/^## \[Unreleased\]/ {
		print
		print ""
		while ((getline l < section) > 0) print l
		print ""
		skipping = 1
		next
	}
	skipping && /^## \[/ { skipping = 0 }
	skipping { next }
	/^\[Unreleased\]: / && base != "" {
		print "[Unreleased]: " base "/compare/v" ver "...HEAD"
		if (prev != "") print "[" ver "]: " base "/compare/v" prev "...v" ver
		else print "[" ver "]: " base "/releases/tag/v" ver
		next
	}
	{ print }
' "$CHANGELOG" >"$WORK/CHANGELOG.md"

cat "$WORK/CHANGELOG.md" >"$CHANGELOG"
for f in "${FRAGMENTS[@]+"${FRAGMENTS[@]}"}"; do
	rm -f "$f"
done

echo "changelog-assemble: [$VERSION] - $DATE written from ${#INPUTS[@]} input(s); ${#FRAGMENTS[@]} fragment(s) removed"
[ -n "$BASE" ] || echo "changelog-assemble: no [Unreleased] compare link found; add the [$VERSION] link by hand" >&2
