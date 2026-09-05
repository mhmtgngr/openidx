#!/usr/bin/env bash
# Every Flutter build that runs on a macOS runner shells out to CocoaPods, and
# CocoaPods reaches cdn.cocoapods.org before it compiles anything. When that
# host does not answer the probe, CocoaPods falls back to `git clone`-ing the
# CDN and the job dies on `fatal: repository 'https://cdn.cocoapods.org/' not
# found` -- an error about somebody else's outage, wearing the costume of a
# broken checkout, minutes into a build. scripts/ci-prime-cocoapods.sh creates
# the spec source up front, with a retry, so that failure costs seconds and
# says what it is.
#
# THE DRIFT THIS GUARD STOPS. The priming step is opt-in per job, and the jobs
# that need it do not look alike: one is a three-OS matrix where only one leg
# is exposed, one builds iOS on a PR, one builds an unsigned archive on a tag.
# Add a fourth and there is nothing to remind you -- the build passes on every
# day the CDN is healthy, which is nearly all of them, and the day it is not
# the red lands on whoever pushed last. So: a job that names a macOS runner AND
# runs `flutter build` must invoke ci-prime-cocoapods.sh, BEFORE that build.
# Priming afterwards is the same as not priming, and reads as if it were not,
# which is worse -- so ordering is checked, not just presence.
#
# It deliberately says nothing about `if:` conditions. A matrix leg guarded by
# `if: matrix.os == 'macos-latest'` is correct and unverifiable from the text;
# what is verifiable is that the step is in the job and comes first.
#
# Comments are ignored throughout, so prose about macOS or about `flutter build
# linux` neither triggers the rule nor satisfies it.
#
# Usage: bash scripts/check-macos-pod-priming.sh [workflow.yml|dir ...]
#        (default: .github/workflows)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

files=("$@")
if [ "${#files[@]}" -eq 0 ]; then
  files=("$ROOT/.github/workflows")
fi

python3 - "${files[@]}" <<'PYEOF'
import os, re, sys

# `macos-14`, `macos-15`, `macos-latest` -- the runner labels. Narrow on
# purpose: `--enable-macos-desktop` is a build flag, not a runner.
MACOS = re.compile(r'\bmacos-(?:\d|latest\b)')
FLUTTER_BUILD = re.compile(r'\bflutter\s+build\b')
PRIME = "scripts/ci-prime-cocoapods.sh"


def indent_of(line):
    return len(line) - len(line.lstrip())


def significant(line):
    s = line.strip()
    return bool(s) and not s.startswith("#")


def parse_jobs(lines):
    """[(name, lo, hi)] over the file's `jobs:` mapping; whole file if absent."""
    jobs_at = None
    for i, line in enumerate(lines):
        if re.match(r'^jobs:\s*$', line):
            jobs_at = i
            break
    if jobs_at is None:
        return [("", 0, len(lines))]

    key_indent, starts = None, []
    for i in range(jobs_at + 1, len(lines)):
        line = lines[i]
        if not significant(line):
            continue
        ind = indent_of(line)
        if ind == 0:
            break                                   # left the jobs: mapping
        if key_indent is None:
            key_indent = ind
        if ind == key_indent and re.match(r'^\s*[A-Za-z0-9_.-]+:\s*$', line):
            starts.append((line.strip().rstrip(":"), i))

    if not starts:
        return [("", jobs_at, len(lines))]
    return [(name, lo, starts[n + 1][1] if n + 1 < len(starts) else len(lines))
            for n, (name, lo) in enumerate(starts)]


def workflow_files(targets):
    for t in targets:
        if os.path.isdir(t):
            for name in sorted(os.listdir(t)):
                if name.endswith((".yml", ".yaml")):
                    yield os.path.join(t, name)
        else:
            yield t


def first_match(lines, lo, hi, needle):
    """1-based line number of the first significant line matching, else None."""
    for i in range(lo, hi):
        line = lines[i]
        if not significant(line):
            continue
        if needle(line):
            return i + 1
    return None


bad, notes, exposed_seen = [], [], 0

for path in workflow_files(sys.argv[1:]):
    try:
        lines = open(path, encoding="utf-8").read().split("\n")
    except OSError as exc:
        bad.append("%s: cannot read (%s)" % (path, exc))
        continue

    for job, lo, hi in parse_jobs(lines):
        where = "%s%s" % (path, ":" + job if job else "")
        build_at = first_match(lines, lo, hi, lambda l: FLUTTER_BUILD.search(l))
        if build_at is None:
            continue
        runner_at = first_match(lines, lo, hi, lambda l: MACOS.search(l))
        if runner_at is None:
            # Android and Linux builds never touch CocoaPods. Saying so beats
            # printing nothing, which reads the same as "not examined".
            notes.append("%s: `flutter build` on no macOS runner, not exposed"
                         % where)
            continue

        exposed_seen += 1
        prime_at = first_match(lines, lo, hi, lambda l: PRIME in l)
        if prime_at is None:
            bad.append(
                "%s: runs `flutter build` (line %d) on a macOS runner (line %d) "
                "and never runs %s. CocoaPods will create its spec source "
                "mid-build, and a bad minute at cdn.cocoapods.org fails the job "
                "on a git error about a URL that is not a repository."
                % (where, build_at, runner_at, PRIME))
            continue
        if prime_at > build_at:
            bad.append(
                "%s: %s runs at line %d, AFTER `flutter build` at line %d. "
                "CocoaPods has already created the source by then, so this "
                "primes nothing while looking like it does -- move the step "
                "above the build." % (where, PRIME, prime_at, build_at))

if exposed_seen == 0:
    bad.append("no job builds Flutter on a macOS runner in %s; this guard is "
               "watching the wrong file" % " ".join(sys.argv[1:]))

for n in notes:
    print("MACOS_POD_PRIMING: " + n)
print("MACOS_POD_PRIMING=%d" % len(bad))
for b in bad:
    print("  - " + b)
sys.exit(1 if bad else 0)
PYEOF
