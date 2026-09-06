#!/usr/bin/env bash
# Proves check-codeowners.sh can actually go RED.
#
# Each fixture below is a line that was really in .github/CODEOWNERS before it
# was rewritten, or a shape one edit away from it. The last cases are the other
# half of the contract: a guard that flags a correct file gets deleted.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-codeowners.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0

t() { # name expected_rc file
  local name="$1" exp="$2" file="$3"
  bash "$CHECK" "$file" >/dev/null 2>&1
  local rc=$?
  if [ "$rc" = "$exp" ]; then
    echo "ok   $name (rc=$rc)"
  else
    echo "FAIL $name (rc=$rc, expected $exp)"; fail=$((fail + 1))
  fi
}

# The repository's own file must pass.
t "real .github/CODEOWNERS is clean" 0 "$ROOT/.github/CODEOWNERS"

printf '* @mhmtgngr\n' > "$WORK/ok-simple"
t "single catch-all rule passes" 0 "$WORK/ok-simple"

# `!` negation: unsupported by GitHub, reads as a literal path, matches nothing.
printf '* @mhmtgngr\n!/.github/workflows/** @mhmtgngr\n' > "$WORK/negation"
t "! negation is caught" 1 "$WORK/negation"

# A rule for a path that no longer exists (the real case: dependabot.yml).
printf '* @mhmtgngr\n.github/dependabot.yml @mhmtgngr\n' > "$WORK/ghost-path"
t "rule for a deleted path is caught" 1 "$WORK/ghost-path"

# A pattern with no owner silently disowns the subtree it matches.
printf '* @mhmtgngr\n/internal/oauth/**\n' > "$WORK/no-owner"
t "pattern with no owner is caught" 1 "$WORK/no-owner"

# A directory glob whose base directory is gone.
printf '* @mhmtgngr\n/frontend/** @mhmtgngr\n' > "$WORK/ghost-dir"
t "rule for a deleted directory is caught" 1 "$WORK/ghost-dir"

# A file with only comments owns nothing at all.
printf '# just a comment\n' > "$WORK/empty"
t "file with no rules is caught" 1 "$WORK/empty"

# Real paths and real globs must pass, or the guard becomes a nuisance.
printf '* @mhmtgngr\n/internal/oauth/** @mhmtgngr\n**/*.go @mhmtgngr\nMakefile @mhmtgngr\n' > "$WORK/ok-paths"
t "existing paths and globs pass" 0 "$WORK/ok-paths"

# An email owner is legal CODEOWNERS syntax.
printf '* someone@example.com\n' > "$WORK/ok-email"
t "email owner passes" 0 "$WORK/ok-email"

# Comments and blank lines are not rules.
printf '# owner of everything\n\n*   @mhmtgngr   # trailing comment\n' > "$WORK/ok-comments"
t "comments and trailing comments pass" 0 "$WORK/ok-comments"

if [ "$fail" -ne 0 ]; then
  echo "$fail case(s) failed"
  exit 1
fi
echo "all cases passed"
