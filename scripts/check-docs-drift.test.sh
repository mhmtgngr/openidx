#!/usr/bin/env bash
# Self-test: check-docs-drift.sh must go red on each way a document can cite
# something that is not there, and must stay green on the shapes that are not
# claims about a path -- globs, brace sets, elisions, Go symbols.
#
# The second half matters as much as the first. A guard that flags
# `internal/oauth/**` is a guard someone switches off within a week.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-docs-drift.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

# fixture <name> <register-body> <doc-body> -> prints the fixture root
fixture() {
  local name="$1" reg="$2" doc="$3"
  local d="$tmp/$name"
  mkdir -p "$d/docs" "$d/internal/oauth"
  : > "$d/internal/oauth/service.go"
  printf '%s\n' "$reg" > "$d/docs/doc-citations.txt"
  printf '%s\n' "$doc" > "$d/docs/guide.md"
  echo "$d"
}

expect() { # expect <want: ok|red> <label> <root>
  local want="$1" label="$2" root="$3" rc=0
  OPENIDX_DOCS_ROOT="$root" bash "$GUARD" --enforce >/dev/null 2>&1 || rc=$?
  if { [ "$want" = ok ] && [ "$rc" -eq 0 ]; } || { [ "$want" = red ] && [ "$rc" -ne 0 ]; }; then
    echo "  ok   $label"
    pass=$((pass + 1))
  else
    echo "  FAIL $label (wanted $want, exit $rc)"
    fail=$((fail + 1))
  fi
}

echo "check-docs-drift.test:"

# The real tree is the green case, and the one that matters most: if the
# register drifts from the docs, this is what says so.
expect ok "the committed docs and register agree" "$ROOT"

expect ok "a citation that resolves" \
  "$(fixture resolves '# none' 'See `internal/oauth/service.go` for the flow.')"

expect red "a citation that does not resolve" \
  "$(fixture broken '# none' 'See `internal/oauth/store.go` for the flow.')"

expect ok "a broken citation with a registered reason" \
  "$(fixture waived 'allow internal/oauth/store.go  deleted in P7.6, and that is the point' \
     'See `internal/oauth/store.go` for what was deleted.')"

expect red "a register entry with no reason" \
  "$(fixture noreason 'allow internal/oauth/store.go' \
     'See `internal/oauth/store.go`.')"

expect red "a waiver for a path that came back" \
  "$(fixture returned 'allow internal/oauth/service.go  it is gone' \
     'See `internal/oauth/service.go`.')"

expect red "a waiver no document cites any more" \
  "$(fixture unused 'allow internal/oauth/store.go  deleted' \
     'Nothing cites it.')"

# Build output is the awkward case: a waived path that is absent in a clean
# checkout and present after a local `mkdocs build`. Two rules have to hold at
# once, and only a real git repository can tell them apart --
# `git ls-files` says untracked while the filesystem says present:
#
#   - "came back" must mean COMMITTED, not merely present, or the guard fails
#     on any machine where the docs have been built once;
#   - the citation must still register as a citation, or the "nobody cites
#     this waiver" rule fires instead.
#
# Before this ordering, the same fixture read as green or red depending on
# whether the reader had run the docs build.
gitfixture() { # gitfixture <name> <register-body> <doc-body> -> fixture root
  local d="$tmp/$1"
  mkdir -p "$d/docs" "$d/internal/oauth"
  git -C "$d" init -q 2>/dev/null
  printf '%s\n' "$2" > "$d/docs/doc-citations.txt"
  printf '%s\n' "$3" > "$d/docs/guide.md"
  printf 'internal/oauth/\n' > "$d/.gitignore"
  git -C "$d" add -A >/dev/null 2>&1 || true
  # Created AFTER the commit and gitignored: present on disk, untracked.
  : > "$d/internal/oauth/service.go"
  echo "$d"
}

expect ok "a gitignored build path is waived, present on disk, and still counts as cited" \
  "$(gitfixture buildoutput 'allow internal/oauth/service.go  build output; gitignored' \
     'See `internal/oauth/service.go`.')"

expect ok "a skipped document" \
  "$(fixture skipped 'skip docs/guide.md  a dated audit, bannered as historical' \
     'See `internal/oauth/store.go`.')"

# The shapes that are not claims about one path. Each of these would be a
# false positive, and false positives are how a guard gets retired.
expect ok "a glob is not a path claim" \
  "$(fixture glob '# none' 'Everything under `internal/oauth/**` is affected.')"

expect ok "a brace set is not a path claim" \
  "$(fixture brace '# none' 'Both `internal/oauth/{store,client}.go` changed.')"

expect ok "an elision is not a path claim" \
  "$(fixture elision '# none' 'The old `mobile/src/...` files are gone.')"

expect ok "a Go symbol is not a path claim" \
  "$(fixture symbol '# none' 'Call `internal/oauth.isValidSessionID` first.')"

expect ok "a non-repo backtick is ignored" \
  "$(fixture prose '# none' 'Run `npm run build` and set `NODE_ENV=production`.')"

echo "check-docs-drift.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
