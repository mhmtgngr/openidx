#!/usr/bin/env bash
# Every `go test -race` invocation must carry an explicit `-timeout`.
#
# WHY. Go's default per-package test timeout is ten minutes, and that number is
# calibrated for uninstrumented tests. Under `-race` everything costs several
# times more, and this repo's database-backed suites start a Postgres container
# per test on top of that. At ten minutes a slow runner and a hung test produce
# the IDENTICAL failure:
#
#   FAIL github.com/openidx/openidx/internal/access  600.077s
#
# followed by the goroutine dump `go test` prints when it gives up -- fifty
# stacks deep, forty-eight of them parked in `testing.(*T).Parallel` behind the
# one serial test that was still running, and not one `WARNING: DATA RACE`
# anywhere in it. The check is named "Race Detector". It went red on a commit
# that changed no Go code, and it reported a diagnosis it had not made.
#
# That is this repository's own defect class arriving in its CI: a control that
# displays something it does not measure. An explicit `-timeout` is what makes
# the red mean what the check's name says -- generous enough that a slow runner
# passes, tight enough that a genuine hang still fails, and chosen rather than
# inherited.
#
# The rule is deliberately about PRESENCE, not about the value: what the right
# bound is depends on the suite, and a number picked on purpose can be argued
# with. A number nobody picked cannot.
#
# Usage: bash scripts/check-race-timeout.sh [file|dir ...]
#        (default: .github/workflows and Makefile)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

files=("$@")
if [ "${#files[@]}" -eq 0 ]; then
  files=("$ROOT/.github/workflows" "$ROOT/Makefile")
fi

python3 - "${files[@]}" <<'PYEOF'
import os, re, sys

# `go test` somewhere on the line, with -race as its own token. `-race` inside
# a comment is prose about the rule, not an invocation of it.
GO_TEST = re.compile(r'(?<![\w./-])go\s+test\b')
RACE = re.compile(r'(?<![\w-])-{1,2}race(?![\w-])')
TIMEOUT = re.compile(r'(?<![\w-])-{1,2}timeout(?:[= ]\S+)?')


def strip_comment(line):
    """Drop a leading # comment. Only leading: a `#` mid-command may be data."""
    s = line.lstrip()
    return "" if s.startswith("#") else line


def targets(paths):
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                if name.endswith((".yml", ".yaml", ".sh")) or name == "Makefile":
                    yield os.path.join(p, name)
        else:
            yield p


bad, seen = [], 0

for path in targets(sys.argv[1:]):
    try:
        raw = open(path, encoding="utf-8").read().split("\n")
    except OSError as exc:
        bad.append("%s: cannot read (%s)" % (path, exc))
        continue

    # Join shell line-continuations so a command split over several lines is
    # judged as the one command it is.
    joined, buf, start = [], "", 0
    for i, line in enumerate(raw):
        line = strip_comment(line)
        if not buf:
            start = i + 1
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        joined.append((start, buf + line))
        buf = ""
    if buf:
        joined.append((start, buf))

    for line_no, cmd in joined:
        if not GO_TEST.search(cmd) or not RACE.search(cmd):
            continue
        seen += 1
        if TIMEOUT.search(cmd):
            continue
        bad.append(
            "%s:%d: `go test -race` with no explicit -timeout. Go's ten-minute "
            "default is a bound for uninstrumented tests; under -race a slow "
            "runner and a hung test fail identically, and the check reports a "
            "diagnosis it did not make.\n      %s"
            % (path, line_no, cmd.strip()[:160]))

if seen == 0:
    bad.append("no `go test -race` invocation found in %s; this guard is "
               "watching the wrong file" % " ".join(sys.argv[1:]))

print("RACE_TIMEOUT: %d race invocation(s) examined" % seen)
print("RACE_TIMEOUT=%d" % len(bad))
for b in bad:
    print("  - " + b)
sys.exit(1 if bad else 0)
PYEOF
