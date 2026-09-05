#!/usr/bin/env bash
# .github/CODEOWNERS must describe a review process that can actually happen.
#
# The file this guard was written for was 212 lines naming eighteen
# @openidx/* teams in a repository under a PERSONAL namespace, which cannot
# have organization teams at all. Under "Require review from Code Owners" that
# is not cosmetic: GitHub resolves no owner for any path, so the rules either
# no-op silently — the file documenting a review nobody performs — or block
# every pull request with no reviewer able to clear it. Team existence cannot
# be checked from a clone, so this guard does not try. It checks the three
# defects that ARE mechanically visible, and each of them was present:
#
#   1. `!` negation patterns. GitHub's CODEOWNERS syntax has no negation. Such
#      a line is read as a literal path starting with "!", matches nothing, and
#      makes the file appear to exempt a directory it does not exempt.
#   2. A rule for a path that does not exist. The file assigned an owner to
#      .github/dependabot.yml months after the repository moved to Renovate and
#      deleted it. A rule for a deleted path is a rule that will never fire.
#   3. A pattern with no owner, which disowns everything it matches — the last
#      matching pattern wins, so one ownerless line can silently remove the
#      owner from a whole subtree.
#
# Usage: bash scripts/check-codeowners.sh [CODEOWNERS-file]
#        (default: .github/CODEOWNERS)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILE="${1:-$ROOT/.github/CODEOWNERS}"

if [ ! -f "$FILE" ]; then
  echo "check-codeowners: $FILE does not exist" >&2
  exit 1
fi

python3 - "$FILE" "$ROOT" <<'PYEOF'
import glob
import os
import sys

path, root = sys.argv[1], sys.argv[2]
failures = []
rules = 0

for lineno, raw in enumerate(open(path, encoding="utf-8"), 1):
    line = raw.split("#", 1)[0].strip()
    if not line:
        continue
    rules += 1
    parts = line.split()
    pattern, owners = parts[0], parts[1:]

    if pattern.startswith("!"):
        failures.append(
            f"{path}:{lineno}: `!` negation — GitHub CODEOWNERS has no negation "
            f"syntax; this line matches nothing: {line}"
        )
        continue

    if not owners:
        failures.append(
            f"{path}:{lineno}: pattern with no owner — the last matching pattern "
            f"wins, so this DISOWNS everything it matches: {line}"
        )
        continue

    for owner in owners:
        if not owner.startswith("@") and "@" not in owner:
            failures.append(f"{path}:{lineno}: {owner!r} is neither @handle, @org/team nor an email")

    # Does the pattern match anything in the tree? Only checked for patterns
    # anchored to a concrete path — a bare glob like *.go is left alone.
    probe = pattern.lstrip("/")
    if "*" not in probe and "?" not in probe:
        if not os.path.exists(os.path.join(root, probe)):
            failures.append(
                f"{path}:{lineno}: rule for {pattern!r}, which does not exist in the "
                f"repository — it can never fire"
            )
    elif probe.endswith("/**"):
        base = probe[:-3]
        if "*" not in base and "?" not in base and not os.path.isdir(os.path.join(root, base)):
            failures.append(
                f"{path}:{lineno}: rule for {pattern!r}, but {base!r} is not a directory "
                f"in the repository — it can never fire"
            )
    elif not glob.glob(os.path.join(root, probe), recursive=True):
        failures.append(
            f"{path}:{lineno}: rule for {pattern!r} matches no file in the repository — "
            f"it can never fire"
        )

if not rules:
    failures.append(f"{path}: no ownership rules at all — every path is unowned")

if failures:
    print("CODEOWNERS problems:", file=sys.stderr)
    for f in failures:
        print(f"  {f}", file=sys.stderr)
    sys.exit(1)

print(f"check-codeowners: {rules} rule(s), all with an owner and a path that exists")
PYEOF
