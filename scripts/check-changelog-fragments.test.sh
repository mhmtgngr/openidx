#!/usr/bin/env bash
# Self-test for check-changelog-fragments.sh and the assembler it wraps,
# scripts/changelog-assemble.sh. Every case runs on a throwaway tree.
#
# The assembler must: group bullets by heading in the fixed order, keep
# fragment-filename order inside a heading whatever order the files were
# written in, carry legacy [Unreleased] lines into the release, move the
# compare links, delete only the fragments, refuse a malformed fragment
# before writing anything, and refuse to cut the same version twice.
set -uo pipefail
cd "$(dirname "$0")/.."

ASSEMBLE="$PWD/scripts/changelog-assemble.sh"
GUARD="$PWD/scripts/check-changelog-fragments.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
T="$WORK/tree"
fails=0

ok() { echo "ok: $1"; }
bad() {
	echo "FAIL: $1"
	[ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/    /'
	fails=$((fails + 1))
}

fresh() {
	rm -rf "$T"
	mkdir -p "$T/changelog.d"
	touch "$T/changelog.d/.gitkeep"
	echo "# docs, not a fragment" >"$T/changelog.d/README.md"
	cat >"$T/CHANGELOG.md" <<'MD'
# Changelog

Intro text.

## [Unreleased]

## [1.2.0] - 2026-01-02

### Fixed
- old fix

[Unreleased]: https://github.com/example/repo/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/example/repo/compare/v1.1.0...v1.2.0
MD
}

run() { # run <want-exit> <label> <cmd...>; leaves output in $OUT
	local want="$1" label="$2" rc
	shift 2
	OUT=$(CHANGELOG_ROOT="$T" "$@" 2>&1)
	rc=$?
	if [ "$rc" != "$want" ]; then
		bad "$label — exited $rc, expected $want" "$OUT"
		return 1
	fi
	ok "$label"
}

# --- the happy path -------------------------------------------------------
fresh
# Written out of filename order on purpose: z before a.
cat >"$T/changelog.d/zeta.md" <<'MD'
### Fixed
- zeta fix

### Added
- zeta added
MD
cat >"$T/changelog.d/alpha.md" <<'MD'
<!-- a comment is ignored -->
### Security
- alpha security
  continued on an indented line
  - nested bullet

### Added
- alpha added
MD
run 0 "valid fragments pass the guard" bash "$GUARD"
run 0 "a release is cut" bash "$ASSEMBLE" 1.3.0 2026-02-03

expected_section='## [Unreleased]

## [1.3.0] - 2026-02-03

### Added
- alpha added
- zeta added

### Fixed
- zeta fix

### Security
- alpha security
  continued on an indented line
  - nested bullet

## [1.2.0] - 2026-01-02'
got=$(sed -n '/^## \[Unreleased\]/,/^## \[1\.2\.0\]/p' "$T/CHANGELOG.md")
if [ "$got" = "$expected_section" ]; then
	ok "headings in fixed order, bullets in filename order"
else
	bad "assembled section differs" "$(diff <(echo "$expected_section") <(echo "$got"))"
fi

grep -qx '\[Unreleased\]: https://github.com/example/repo/compare/v1.3.0...HEAD' "$T/CHANGELOG.md" &&
	grep -qx '\[1.3.0\]: https://github.com/example/repo/compare/v1.2.0...v1.3.0' "$T/CHANGELOG.md" &&
	ok "compare links moved on" || bad "compare links not updated" "$(tail -4 "$T/CHANGELOG.md")"

if [ ! -e "$T/changelog.d/alpha.md" ] && [ ! -e "$T/changelog.d/zeta.md" ] &&
	[ -e "$T/changelog.d/README.md" ] && [ -e "$T/changelog.d/.gitkeep" ]; then
	ok "fragments removed, README and .gitkeep kept"
else
	bad "fragment cleanup wrong" "$(ls -A "$T/changelog.d")"
fi

grep -q '^Intro text\.$' "$T/CHANGELOG.md" && grep -q '^- old fix$' "$T/CHANGELOG.md" &&
	ok "the rest of the file is untouched" || bad "content outside the new section was lost"

# Determinism: the same inputs give byte-identical output.
first=$(cat "$T/CHANGELOG.md")
fresh
printf '### Added\n- alpha added\n\n### Security\n- alpha security\n  continued on an indented line\n  - nested bullet\n' >"$T/changelog.d/alpha.md"
printf '### Fixed\n- zeta fix\n\n### Added\n- zeta added\n' >"$T/changelog.d/zeta.md"
CHANGELOG_ROOT="$T" bash "$ASSEMBLE" 1.3.0 2026-02-03 >/dev/null 2>&1
[ "$(cat "$T/CHANGELOG.md")" = "$first" ] && ok "deterministic" || bad "two runs over the same fragments differ"

# --- refusing ---------------------------------------------------------------
run 1 "the same version cannot be cut twice" bash -c 'printf "### Added\n- x\n" >"$CHANGELOG_ROOT/changelog.d/x.md"; bash "$0" 1.3.0 2026-02-03' "$ASSEMBLE"

for case in \
	"unknown-heading|### Improvements\n- x\n|is not one of" \
	"bullet-first|- x\n### Added\n- y\n|a bullet before any ### heading" \
	"prose|### Added\nJust some prose.\n|expected" \
	"orphan-indent|### Added\n  indented with no bullet\n|no bullet above it"; do
	name="${case%%|*}"
	rest="${case#*|}"
	body="${rest%|*}"
	want="${rest##*|}"
	fresh
	printf -- "$body" >"$T/changelog.d/$name.md"
	before=$(cat "$T/CHANGELOG.md")
	if run 1 "guard refuses: $name" bash "$GUARD"; then
		grep -q "changelog.d/$name.md:[0-9]*: .*$want" <<<"$OUT" &&
			ok "  …and names the file, line and reason" || bad "  …message lacks file:line: $want" "$OUT"
	fi
	run 1 "assembler refuses: $name" bash "$ASSEMBLE" 9.9.9 2026-01-01
	[ "$(cat "$T/CHANGELOG.md")" = "$before" ] && [ -e "$T/changelog.d/$name.md" ] &&
		ok "  …and writes nothing" || bad "  …a refused run changed the tree"
done

fresh
run 1 "nothing to release is refused" bash "$ASSEMBLE" 1.3.0 2026-02-03
run 0 "the guard passes an empty changelog.d" bash "$GUARD"
run 1 "a v-prefixed version is refused" bash "$ASSEMBLE" v1.3.0
run 2 "no arguments prints usage" bash "$ASSEMBLE"

# --- the transition: lines still written under [Unreleased] -----------------
fresh
sed -i 's/^## \[Unreleased\]$/## [Unreleased]\n\n### Fixed\n- legacy fix\n/' "$T/CHANGELOG.md"
printf '### Fixed\n- fragment fix\n' >"$T/changelog.d/a.md"
run 0 "legacy [Unreleased] lines are released with the fragments" bash "$ASSEMBLE" 1.3.0 2026-02-03
got=$(sed -n '/^## \[1\.3\.0\]/,/^## \[1\.2\.0\]/p' "$T/CHANGELOG.md")
want='## [1.3.0] - 2026-02-03

### Fixed
- legacy fix
- fragment fix

## [1.2.0] - 2026-01-02'
[ "$got" = "$want" ] && ok "  …legacy first, then fragments, under one heading" || bad "  …legacy merge wrong" "$got"
[ "$(sed -n '/^## \[Unreleased\]/,/^## \[1\.3\.0\]/p' "$T/CHANGELOG.md" | grep -c 'legacy')" = 0 ] &&
	ok "  …and [Unreleased] is left empty" || bad "  …[Unreleased] still holds the legacy line"

# --- --dry-run --------------------------------------------------------------
fresh
printf '### Added\n- dry\n' >"$T/changelog.d/a.md"
before=$(cat "$T/CHANGELOG.md")
run 0 "--dry-run succeeds" bash "$ASSEMBLE" --dry-run 1.3.0 2026-02-03
[ "$OUT" = $'## [1.3.0] - 2026-02-03\n\n### Added\n- dry' ] && [ "$(cat "$T/CHANGELOG.md")" = "$before" ] &&
	[ -e "$T/changelog.d/a.md" ] && ok "  …prints the section and changes nothing" || bad "  …dry run wrong" "$OUT"

# --- the repository's own fragments -------------------------------------------
if OUT=$(bash "$GUARD" 2>&1); then ok "this repository's changelog.d/ parses"; else bad "this repository's changelog.d/ does not parse" "$OUT"; fi

echo
if [ "$fails" -gt 0 ]; then
	echo "check-changelog-fragments.test: $fails failure(s)"
	exit 1
fi
echo "check-changelog-fragments.test: all passed"
