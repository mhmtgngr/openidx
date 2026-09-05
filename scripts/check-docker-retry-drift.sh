#!/usr/bin/env bash
# GitHub Actions has no step-level retry, so the steps in this repo that fail
# on other people's outages are written TWICE -- one attempt, then a retry that
# runs only when the first failed. This guard exists because that duplication
# rots, in two different directions.
#
# DIRECTION 1, DRIFT. Someone adds a build-arg, a platform, a cache scope to
# the first block and not the second, and from then on the retry builds a
# DIFFERENT image than the one that was tried first -- silently, because the
# retry only runs on days the registry is already misbehaving, which is exactly
# when nobody is reading the log carefully. On a push that image is the one
# that gets published. So: two steps in the same job using the same action must
# carry the same `with:` block. Comments and blank lines are ignored (prose may
# differ, behaviour may not).
#
# DIRECTION 2, THE SWALLOWED FAILURE. The idiom needs `continue-on-error: true`
# on the first attempt, and that flag is a hole: delete the retry step and the
# job sails past a step that failed. A buildx bootstrap that fails this way
# does not stop the build -- it falls back to the default driver and quietly
# produces a single-arch image. So: a step that is allowed to fail AND carries
# an `id:` must have a later step in the same job branch on its outcome. If you
# tolerate a failure you have to do something about it; if you do not, drop the
# `id:` and say plainly that the step is advisory (the Trivy and SARIF-upload
# steps are exactly that, and are not flagged).
#
# Both rules are grouped per JOB, not per file: two jobs may legitimately set
# the same action up differently, but a retry pair always lives in one job.
#
# The actions covered are the ones whose failures are somebody else's outage:
# the build itself, and -- since the `build (tools)` leg died at "Booting
# builder" on a Docker Hub auth timeout, before compiling anything -- the QEMU
# and buildx bootstraps that pull their own images before it.
#
# Usage: bash scripts/check-docker-retry-drift.sh [workflow.yml|dir ...]
#        (default: .github/workflows)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

files=("$@")
if [ "${#files[@]}" -eq 0 ]; then
  files=("$ROOT/.github/workflows")
fi

python3 - "${files[@]}" <<'PYEOF'
import os, re, sys

# action base name -> whether a `with:` block is mandatory. A build step with
# no inputs is meaningless and cannot be compared, so its absence is a finding;
# the setup actions are routinely used bare, and there a missing `with:` is
# only a problem when its twin has one.
RETRYABLE = {
    "docker/build-push-action": True,
    "docker/setup-buildx-action": False,
    "docker/setup-qemu-action": False,
}

USES = re.compile(r'^\s*(?:-\s+)?uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@')
KEY = re.compile(r'^([A-Za-z0-9_.-]+):\s*(.*)$')


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


def read_step(lines, lo, hi, dash_indent):
    """(line_no, {key: value}, normalised `with:` body or None) for one step."""
    key_indent = dash_indent + 2
    keys, body = {}, None

    m = KEY.match(lines[lo].lstrip()[2:])           # the `- uses: x` on the dash
    if m:
        keys[m.group(1)] = m.group(2).strip()

    i = lo + 1
    while i < hi:
        line = lines[i]
        if not significant(line) or indent_of(line) != key_indent:
            i += 1
            continue
        m = KEY.match(line.strip())
        if not m:
            i += 1
            continue
        keys[m.group(1)] = m.group(2).strip()
        if m.group(1) != "with":
            i += 1
            continue
        body = []
        j = i + 1
        while j < hi:
            inner = lines[j]
            if not inner.strip():
                j += 1
                continue
            if indent_of(inner) <= key_indent:
                break
            if inner.lstrip().startswith("#"):
                j += 1
                continue
            body.append(inner[key_indent:].rstrip())
            j += 1
        i = j
    return (lo + 1, keys, body)


def parse_steps(lines, lo, hi):
    """Every step in a job's line range, in order."""
    steps, i = [], lo
    in_steps, steps_indent, dash_indent = False, None, None
    while i < hi:
        line = lines[i]
        if not significant(line):
            i += 1
            continue
        ind = indent_of(line)
        if not in_steps:
            if re.match(r'^\s*steps:\s*$', line):
                in_steps, steps_indent, dash_indent = True, ind, None
            i += 1
            continue
        if ind <= steps_indent:
            in_steps = False                        # the steps: block ended
            continue                                # re-read this line
        if line.lstrip().startswith("- "):
            if dash_indent is None:
                dash_indent = ind
            if ind == dash_indent:
                j = i + 1
                while j < hi:
                    nxt = lines[j]
                    if significant(nxt):
                        nind = indent_of(nxt)
                        if nind <= steps_indent:
                            break
                        if nind == dash_indent and nxt.lstrip().startswith("- "):
                            break
                    j += 1
                steps.append(read_step(lines, i, j, dash_indent))
                i = j
                continue
        i += 1
    return steps


def workflow_files(targets):
    for t in targets:
        if os.path.isdir(t):
            for name in sorted(os.listdir(t)):
                if name.endswith((".yml", ".yaml")):
                    yield os.path.join(t, name)
        else:
            yield t


bad, notes, retryable_seen = [], [], 0

for path in workflow_files(sys.argv[1:]):
    try:
        lines = open(path, encoding="utf-8").read().split("\n")
    except OSError as exc:
        bad.append("%s: cannot read (%s)" % (path, exc))
        continue

    for job, lo, hi in parse_jobs(lines):
        where = "%s%s" % (path, ":" + job if job else "")
        steps = parse_steps(lines, lo, hi)

        # --- direction 1: the duplicated attempt must stay identical ---------
        groups = {}
        for line_no, keys, body in steps:
            m = USES.match("uses: " + keys.get("uses", "")) if keys.get("uses") else None
            if not m or m.group(1) not in RETRYABLE:
                continue
            groups.setdefault(m.group(1), []).append((line_no, body))

        for action, found in sorted(groups.items()):
            retryable_seen += len(found)
            if RETRYABLE[action]:
                for line_no, body in found:
                    if body is None:
                        bad.append("%s:%d: %s step has no `with:` block, so it "
                                   "cannot be compared" % (path, line_no, action))
                found = [(n, b) for n, b in found if b is not None]
            if len(found) < 2:
                # One step cannot drift from itself. Say so rather than
                # printing a tick that looks like a retry was verified.
                notes.append("%s: %s appears once, nothing to compare"
                             % (where, action))
                continue
            ref_line, ref = found[0]
            for line_no, body in found[1:]:
                if body == ref:
                    continue
                only_ref = [x for x in (ref or []) if x not in (body or [])]
                only_this = [x for x in (body or []) if x not in (ref or [])]
                if body is None or ref is None:
                    bad.append(
                        "%s:%d: this %s step %s a `with:` block while the one "
                        "at line %d %s -- the retry would not run what was "
                        "tried" % (path, line_no, action,
                                   "has" if body is not None else "has no",
                                   ref_line,
                                   "does not" if body is not None else "does"))
                    continue
                bad.append(
                    "%s:%d: this %s `with:` block differs from the one at line "
                    "%d\n      only in line %d: %s\n      only in line %d: %s"
                    % (path, line_no, action, ref_line, ref_line, only_ref or "-",
                       line_no, only_this or "-"))

        # --- direction 2: a tolerated failure must be acted on ---------------
        job_text = "\n".join(lines[lo:hi])
        for line_no, keys, _ in steps:
            if keys.get("continue-on-error", "").strip().strip("'\"") != "true":
                continue
            step_id = keys.get("id", "").strip().strip("'\"")
            if not step_id:
                continue                # advisory step, failure is the point
            if re.search(r'steps\.%s\.(outcome|conclusion)\b' % re.escape(step_id),
                         job_text):
                continue
            bad.append(
                "%s:%d: step id `%s` is allowed to fail but nothing in the job "
                "reads steps.%s.outcome -- the failure would pass silently. "
                "Add the retry that consumes it, or drop the `id:` to declare "
                "the step advisory." % (path, line_no, step_id, step_id))

if retryable_seen == 0:
    bad.append("no retryable docker step found in %s; this guard is watching "
               "the wrong file" % " ".join(sys.argv[1:]))

for n in notes:
    print("DOCKER_RETRY_DRIFT: " + n)
print("DOCKER_RETRY_DRIFT=%d" % len(bad))
for b in bad:
    print("  - " + b)
sys.exit(1 if bad else 0)
PYEOF
