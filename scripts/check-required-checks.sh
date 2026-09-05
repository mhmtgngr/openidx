#!/usr/bin/env bash
# Every job in the CI workflow must either be REQUIRED or be declared
# informational, in the file, with a reason.
#
# The aggregate job (`status-check`, surfaced as "Required Checks") used to
# carry a hand-written list of seven job names, duplicated between its `needs:`
# and a bash array in its own step. The two drifted, and the drift was silent:
# test-frontend was in neither, and every guard job this repository added after
# it -- first-run, ui-safety-guards, selfheal, shell-prose,
# ci-resilience-guards, fault-matrix, field-fix-scoreboard,
# no-internal-topology -- could go red without Required Checks turning red. A
# guard nobody is required to pass is a guard that will eventually be broken by
# someone in a hurry, which is the same failure mode every check in this
# repository exists to prevent.
#
# So: `needs:` is the single list, the step derives its work from it, and this
# guard makes forgetting impossible. A job may sit outside `needs` only by
# saying so where a reader will see it -- a comment
#
#     # status-check: informational — <reason>
#
# in the lines immediately above the job id. The reason is mandatory: an
# exemption without one is how a required check quietly becomes optional.
#
# Usage: bash scripts/check-required-checks.sh [workflow.yml]
#        (default: .github/workflows/ci.yml)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILE="${1:-$ROOT/.github/workflows/ci.yml}"

python3 - "$FILE" <<'PYEOF'
import re
import sys

try:
    import yaml
except ImportError:
    print("check-required-checks: PyYAML is not installed", file=sys.stderr)
    sys.exit(2)

path = sys.argv[1]
try:
    doc = yaml.safe_load(open(path, encoding="utf-8"))
except yaml.YAMLError as exc:
    print(f"check-required-checks: {path} is not valid YAML: {exc}", file=sys.stderr)
    sys.exit(1)

jobs = (doc or {}).get("jobs") or {}
if "status-check" not in jobs:
    print(f"check-required-checks: {path} has no status-check job — nothing aggregates its results", file=sys.stderr)
    sys.exit(1)

needs = jobs["status-check"].get("needs") or []
if isinstance(needs, str):
    needs = [needs]
needs = set(needs)

# An exemption is a `# status-check: informational — reason` comment in the
# comment block directly above the job id, so it is read together with the job.
lines = open(path, encoding="utf-8").read().split("\n")
JOB_ID = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
MARK = re.compile(r"#\s*status-check:\s*informational\s*[—:-]\s*(.+?)\s*$")

exempt = {}
for i, line in enumerate(lines):
    m = JOB_ID.match(line)
    if not m or m.group(1) not in jobs:
        continue
    j = i - 1
    while j >= 0 and lines[j].strip().startswith("#"):
        mm = MARK.search(lines[j])
        if mm:
            exempt[m.group(1)] = mm.group(1)
            break
        j -= 1

failures = []

for name in sorted(jobs):
    if name == "status-check":
        continue
    if name in needs:
        if name in exempt:
            failures.append(
                f"{name}: declared informational AND listed in status-check's needs — pick one"
            )
        continue
    if name not in exempt:
        failures.append(
            f"{name}: not in status-check's `needs` and not declared informational. "
            f"Add it to `needs`, or write `# status-check: informational — <reason>` "
            f"above the job."
        )
    elif not exempt[name].strip():
        failures.append(f"{name}: declared informational with an empty reason")

for name in sorted(needs - set(jobs)):
    failures.append(f"status-check needs {name!r}, which is not a job in this workflow")

if failures:
    print("Required-checks register is out of date:", file=sys.stderr)
    for f in failures:
        print(f"  {f}", file=sys.stderr)
    sys.exit(1)

required = len(needs)
print(
    f"check-required-checks: {required} required job(s), "
    f"{len(exempt)} declared informational ({', '.join(sorted(exempt)) or 'none'})"
)
PYEOF
