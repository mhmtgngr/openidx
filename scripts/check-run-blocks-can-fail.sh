#!/usr/bin/env bash
# A gating command in a `run:` block that does not `set -e` must say `exit 1`
# itself, or it is not a gate.
#
# WHY THIS IS A GUARD. ci.yml's integration step opens with
#
#     set -uo pipefail
#
# -u and pipefail, no -e. A bare command that fails therefore does NOT stop the
# script: execution continues and the STEP's exit code is whatever the LAST
# command returned. Measured:
#
#     $ bash -c 'set -uo pipefail
#       false
#       echo "REACHED the line after a failure"
#       true'
#     REACHED the line after a failure          (exit 0)
#
# The block already knows this -- its service-health wait ends in an explicit
# `exit 1`. But a step added later reads like a gate and is not one. That is
# exactly what happened with `go run ./tools/sqlprepare -fail`, added to catch
# SQL the database refuses to plan: it printed its findings and the job stayed
# green. A checker that cannot fail is the defect this repository keeps finding,
# and it is easiest to introduce in the file whose whole job is checking.
#
# THE RULE, and what is NOT a finding:
#   - Only blocks that set shell options WITHOUT -e are examined. With -e a bare
#     failure aborts and no guard is needed.
#   - The LAST command in a block is fine unguarded: its status IS the step's.
#     That is how the integration suite itself gates.
#   - `|| true`, `|| echo ...`, `&&` chains and `if ! CMD` are all deliberate
#     and pass. Saying "this may fail" out loud is the point.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENFORCE=0
[ "${1:-}" = "--enforce" ] && ENFORCE=1

FILES="${CHECK_RUN_BLOCK_FILES:-$(ls .github/workflows/*.yml 2>/dev/null)}"

python3 - "$ENFORCE" $FILES <<'PYEOF'
import re, sys, yaml

enforce = sys.argv[1] == "1"
paths = sys.argv[2:]

# Commands whose failure is the point of running them.
GATING = re.compile(r'^\s*(go run|go test|go build|go vet|make |bash scripts/|npm run|npx )')

findings = 0
blocks = 0

for path in paths:
    try:
        doc = yaml.safe_load(open(path))
    except Exception as e:
        print("%s: could not parse (%s)" % (path, e))
        continue
    if not isinstance(doc, dict):
        continue
    for job_name, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for step in (job.get("steps") or []):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            opts = re.search(r'^\s*set -([a-z]+)', run, re.M)
            if not opts or "e" in opts.group(1):
                continue  # -e present, or no set line: a bare failure aborts
            blocks += 1

            lines = run.split("\n")
            last_cmd = max((i for i, l in enumerate(lines) if l.strip()
                            and not l.strip().startswith("#")), default=-1)

            for i, line in enumerate(lines):
                if not GATING.match(line):
                    continue
                stripped = line.strip()
                if stripped.startswith("if ! ") or "||" in stripped or stripped.endswith("&&"):
                    continue
                if i == last_cmd:
                    continue  # its status is the step's
                findings += 1
                print("%s: job %s, step %r" % (path, job_name, step.get("name", "?")))
                print("    %s" % stripped[:100])
                print("    runs under `set -%s` (no -e) and is not the last command, so its"
                      % opts.group(1))
                print("    failure is discarded. Wrap it: if ! CMD; then echo '::error::...'; exit 1; fi")

if findings == 0:
    print("check-run-blocks-can-fail: ok — %d run block(s) without -e, every gating "
          "command in them guarded" % blocks)
    sys.exit(0)

print()
print("check-run-blocks-can-fail: %d unguarded gating command(s)" % findings, file=sys.stderr)
sys.exit(1 if enforce else 0)
PYEOF
