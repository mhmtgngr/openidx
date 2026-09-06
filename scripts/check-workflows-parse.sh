#!/usr/bin/env bash
# Every file in .github/workflows/ must be a workflow GitHub can actually run.
#
# This exists because .github/workflows/client-desktop-build.yml shipped in
# #814 with a plain scalar containing ": " --
#
#     run: echo "TODO: fetch + stage openidx-agent sidecar for ..."
#
# -- which is not valid YAML. GitHub does not skip a workflow it cannot parse:
# it creates a run, names it after the FILE PATH instead of the workflow's
# `name:`, schedules zero jobs, and marks the run failed. So the desktop client
# was never built on any commit, and the signal that said so was a red check
# with no job, no log and no annotation pointing at the syntax. It sat like
# that across every push and pull request until someone parsed the file by
# hand.
#
# A workflow file is the one kind of source in this repo that CI cannot check
# by running it -- a broken one removes itself from CI. So it is checked here,
# by a job that only needs the file to exist.
#
# Three rules, all of them things GitHub itself requires:
#   1. the file parses as YAML;
#   2. it has a trigger (`on:`) -- note PyYAML resolves the bare key `on` to
#      the boolean True, which is why both spellings are accepted below;
#   3. it has at least one job. A workflow with no jobs is the same dead check
#      as an unparseable one, arrived at a different way.
#
# Usage: bash scripts/check-workflows-parse.sh [dir-or-file ...]
#        (default: .github/workflows)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

targets=("$@")
if [ "${#targets[@]}" -eq 0 ]; then
  targets=("$ROOT/.github/workflows")
fi

python3 - "${targets[@]}" <<'PYEOF'
import os
import sys

try:
    import yaml
except ImportError:
    print("check-workflows-parse: PyYAML is not installed; cannot verify workflows", file=sys.stderr)
    sys.exit(2)


def workflow_files(targets):
    for t in targets:
        if os.path.isdir(t):
            for name in sorted(os.listdir(t)):
                if name.endswith((".yml", ".yaml")):
                    yield os.path.join(t, name)
        else:
            yield t


failures = []
checked = 0

for path in workflow_files(sys.argv[1:]):
    checked += 1
    try:
        doc = yaml.safe_load(open(path, encoding="utf-8"))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"line {mark.line + 1}, column {mark.column + 1}" if mark else "unknown position"
        problem = getattr(exc, "problem", str(exc))
        failures.append(f"{path}: not valid YAML at {where}: {problem}")
        continue

    if not isinstance(doc, dict):
        failures.append(f"{path}: top level is {type(doc).__name__}, not a mapping")
        continue

    # PyYAML's 1.1 resolver turns the bare key `on` into the boolean True.
    if "on" not in doc and True not in doc:
        failures.append(f"{path}: no `on:` trigger — GitHub will never run it")

    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        failures.append(f"{path}: no jobs — the run would be red with nothing to look at")

if failures:
    print("Workflow files GitHub cannot run:", file=sys.stderr)
    for f in failures:
        print(f"  {f}", file=sys.stderr)
    print(file=sys.stderr)
    print("A workflow that does not parse still creates a FAILED run with zero", file=sys.stderr)
    print("jobs, named after the file. Fix the file; there is no log to read.", file=sys.stderr)
    sys.exit(1)

print(f"check-workflows-parse: {checked} workflow file(s) parse, are triggered, and define jobs")
PYEOF
