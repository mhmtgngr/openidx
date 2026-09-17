#!/usr/bin/env bash
# Guard: the release wave rolls out cell by cell, in order, and stops on the
# first cell that does not come up.
#
# WHY: global-scale plan 4.3 puts a canary cell in front of the production
# cells -- canary-1, then eu-1, then us-1 -- so a bad release is a bad canary,
# not a bad region. The shape that makes that true lives in two workflow files
# and three values files, and every piece of it can drift into a wave that
# looks sequential and is not:
#   - a `needs` that names the wrong cell (or none) runs cells in parallel;
#   - an `if: always()` on a later cell rolls it out over a failed canary;
#   - a `with: cell:` naming a different cell than the job does deploys the
#     wrong identity into a cluster, and the cluster then stamps that identity
#     into every token it mints;
#   - a values file whose config.cellId is not its own name does the same
#     from the other side;
#   - dropping `--atomic` leaves a half-rolled cell standing when it fails;
#   - dropping `environment:` moves the cell's kubeconfig out of the one place
#     a required reviewer can be put in front of it;
#   - dropping the CELL_ROLLOUT gate turns every release on an install with no
#     cells into three failed jobs.
# None of these fails YAML parsing and none of them fails a release on an
# install that has not turned the wave on. So the shape is checked here.
#
# Usage: check-release-rollout.sh [--enforce]
# OPENIDX_WORKFLOW_DIR and OPENIDX_CELLS_DIR override the directories (the .test.sh uses them).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WF="${OPENIDX_WORKFLOW_DIR:-$ROOT/.github/workflows}"
CELLS="${OPENIDX_CELLS_DIR:-$ROOT/deployments/kubernetes/cells}"

python3 - "$WF" "$CELLS" <<'PYEOF'
import os, sys, yaml

wf, cells_dir = sys.argv[1], sys.argv[2]
findings = []
def finding(msg): findings.append(msg)

WAVE = ["canary-1", "eu-1", "us-1"]
CALLED = "./.github/workflows/rollout-cell.yml"

def load(path):
    try:
        return yaml.safe_load(open(path, encoding="utf-8"))
    except FileNotFoundError:
        finding(f"missing {path}")
        return None

release = load(os.path.join(wf, "release.yml"))
cell_wf = load(os.path.join(wf, "rollout-cell.yml"))
if release is None or cell_wf is None:
    print("\n".join("check-release-rollout: " + f for f in findings), file=sys.stderr)
    sys.exit(1)

jobs = release.get("jobs") or {}
def as_list(v):
    if v is None: return []
    return v if isinstance(v, list) else [v]

previous = None
for i, cell in enumerate(WAVE):
    name = f"rollout-{cell}"
    job = jobs.get(name)
    if not isinstance(job, dict):
        finding(f"release.yml has no job {name}; the wave is missing {cell}")
        previous = name
        continue
    if job.get("uses") != CALLED:
        finding(f"{name} does not call {CALLED} (uses={job.get('uses')!r})")
    with_ = job.get("with") or {}
    if with_.get("cell") != cell:
        finding(f"{name} rolls out cell {with_.get('cell')!r}, not {cell}: the wrong identity would be deployed")
    if not str(with_.get("version", "")).strip():
        finding(f"{name} passes no version; the cell would get nothing to roll out")
    if job.get("secrets") != "inherit":
        finding(f"{name} does not pass `secrets: inherit`; the called workflow cannot see the cell environment's KUBECONFIG")
    needs = as_list(job.get("needs"))
    if i == 0:
        if "helm-chart" not in needs:
            finding(f"{name} does not need helm-chart; the canary could roll out a chart that was not pushed")
        cond = str(job.get("if", ""))
        if "vars.CELL_ROLLOUT" not in cond:
            finding(f"{name} is not gated on vars.CELL_ROLLOUT; every release on an install with no cells would fail here")
    else:
        if needs != [previous]:
            finding(f"{name} needs {needs}, not [{previous}]: the wave is not sequential")
        cond = str(job.get("if", ""))
        if "always()" in cond or "failure()" in cond or job.get("continue-on-error"):
            finding(f"{name} runs even when the cell before it failed; a bad canary would still reach {cell}")
    previous = name

# The called workflow.
on = cell_wf.get("on", cell_wf.get(True)) or {}
call = (on.get("workflow_call") or {}) if isinstance(on, dict) else {}
inputs = call.get("inputs") or {}
for req in ("cell", "version"):
    if req not in inputs:
        finding(f"rollout-cell.yml takes no `{req}` input")
cjobs = cell_wf.get("jobs") or {}
if len(cjobs) != 1:
    finding(f"rollout-cell.yml has {len(cjobs)} jobs; one cell is one job")
for jname, job in cjobs.items():
    env = str(job.get("environment", ""))
    if "inputs.cell" not in env:
        finding(f"rollout-cell.yml job {jname} does not run in the cell's environment (environment={env!r}); the kubeconfig and the reviewer gate live there")
    runs = "\n".join(str(s.get("run", "")) for s in (job.get("steps") or []) if isinstance(s, dict))
    if "helm upgrade" not in runs:
        finding(f"rollout-cell.yml job {jname} never runs helm upgrade")
    if "--atomic" not in runs:
        finding(f"rollout-cell.yml upgrades without --atomic; a cell that fails to come up would be left half-rolled")
    if "deployments/kubernetes/cells/${CELL}.yaml" not in runs and 'cells/${CELL}.yaml' not in runs:
        finding(f"rollout-cell.yml does not layer the cell's own values file; the cell would get no identity")
    if "CELL_ID" not in runs:
        finding(f"rollout-cell.yml never reads CELL_ID back from the cluster; a cell answering as another cell would pass")

# Each wave cell has a values file that names itself.
for cell in WAVE:
    path = os.path.join(cells_dir, f"{cell}.yaml")
    doc = load(path)
    if doc is None:
        continue
    got = ((doc or {}).get("config") or {}).get("cellId")
    if got != cell:
        finding(f"{path} names cell {got!r}, not {cell!r}")

if findings:
    for f in findings:
        print("check-release-rollout: " + f, file=sys.stderr)
    sys.exit(1)
print("check-release-rollout: ok — the wave is canary-1 → eu-1 → us-1, atomic per cell, gated, and every cell names itself")
PYEOF
