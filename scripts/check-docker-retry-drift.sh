#!/usr/bin/env bash
# The Docker build in .github/workflows/docker.yml is written twice -- one
# attempt, then a retry that runs only when the first failed -- because
# GitHub Actions has no step-level retry and a Docker Hub 502 on a base-image
# manifest had been turning the job red on commits that changed nothing.
#
# Duplication like that rots. Someone adds a build-arg, a platform, a cache
# scope to the first block and not the second, and from then on the retry
# builds a DIFFERENT image than the one that was tried first -- silently,
# because the retry only runs on days the registry is already misbehaving,
# which is exactly when nobody is reading the log carefully. On a push that
# image is the one that gets published.
#
# So the rule is mechanical: every docker/build-push-action step in a
# workflow must carry the same `with:` block. Comments and blank lines are
# ignored (prose may differ, behaviour may not).
#
# Usage: bash scripts/check-docker-retry-drift.sh [workflow.yml ...]
#        (default: .github/workflows/docker.yml)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

files=("$@")
if [ "${#files[@]}" -eq 0 ]; then
  files=("$ROOT/.github/workflows/docker.yml")
fi

python3 - "${files[@]}" <<'PYEOF'
import re, sys

USES = re.compile(r'^(\s*)(?:-\s+)?uses:\s*docker/build-push-action@')

def indent_of(line):
    return len(line) - len(line.lstrip())


def blocks(path):
    """Yield (line_no, normalised `with:` body) per build-push-action step."""
    lines = open(path, encoding="utf-8").read().split("\n")
    out = []
    i = 0
    while i < len(lines):
        m = USES.match(lines[i])
        if not m:
            i += 1
            continue
        # `- uses:` puts the key two columns right of the dash; `uses:` on its
        # own line is already at the key column.
        key_indent = len(m.group(1)) + (2 if "- " in lines[i][len(m.group(1)):len(m.group(1)) + 2] else 0)
        step_line = i + 1
        body, with_indent = None, None
        j = i + 1
        while j < len(lines):
            line = lines[j]
            if not line.strip():
                j += 1
                continue
            ind = indent_of(line)
            if with_indent is None:
                # Still scanning the step's own keys for `with:`.
                if ind < key_indent or (ind == key_indent and line.lstrip().startswith("- ")):
                    break                      # next step began; no with:
                if ind == key_indent and re.match(r'^\s*with:\s*$', line):
                    with_indent, body = ind, []
                j += 1
                continue
            if ind <= with_indent:
                break
            if line.lstrip().startswith("#"):
                j += 1
                continue
            body.append(line[with_indent:].rstrip())
            j += 1
        out.append((step_line, body))
        i = j
    return out


bad = []
for path in sys.argv[1:]:
    found = blocks(path)
    if not found:
        bad.append("%s: no docker/build-push-action step found; this guard is "
                   "watching the wrong file" % path)
        continue
    for line_no, body in found:
        if body is None:
            bad.append("%s:%d: build-push-action step has no `with:` block, so "
                       "it cannot be compared" % (path, line_no))
    ok = [(n, b) for n, b in found if b is not None]
    if len(ok) < 2:
        # One block cannot drift from itself. Say so rather than printing a
        # green tick that looks like the retry was checked.
        print("DOCKER_RETRY_DRIFT: %s has %d build step(s), nothing to compare"
              % (path, len(ok)))
        continue
    ref_line, ref = ok[0]
    for line_no, body in ok[1:]:
        if body != ref:
            only_ref = [x for x in ref if x not in body]
            only_this = [x for x in body if x not in ref]
            bad.append(
                "%s:%d: this build-push-action `with:` block differs from the "
                "one at line %d\n      only in line %d: %s\n      only in line "
                "%d: %s" % (path, line_no, ref_line, ref_line,
                            only_ref or "-", line_no, only_this or "-"))

print("DOCKER_RETRY_DRIFT=%d" % len(bad))
for b in bad:
    print("  - " + b)
sys.exit(1 if bad else 0)
PYEOF
