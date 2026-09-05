#!/usr/bin/env bash
# Guard: a detached context that writes to the database must carry a tenant.
#
# WHY: the pool sets `app.org_id` at checkout from orgctx
# (internal/common/database/rls.go), and most of the schema sits behind FORCE
# ROW LEVEL SECURITY. A goroutine started with a bare `context.Background()`
# therefore runs with app.org_id EMPTY: reads return nothing and writes are
# refused by the policy's WITH CHECK. Neither failure is loud. A SELECT that
# returns no rows looks like "no data", and an INSERT that is refused reaches a
# best-effort audit path that logs at WARN and returns nil.
#
# This is not hypothetical. Three services -- oauth (SAML/SSO), identity and
# provisioning -- wrote every audit_events row this way. Each resolved the org
# correctly INTO THE ROW and commented that it had "captured the org
# synchronously", but never put it on the context the write ran on, so Postgres
# rejected all of them. The table had taken almost no rows in months while the
# unscoped table next to it took them all, and nothing anywhere said so. The
# audit archive worker had the same defect on the read side and produced empty
# archives reporting success.
#
# The rule: if a function hands `context.Background()` to a pool call, it must
# say which tenant it is acting for -- `orgctx.With(...)` for work that belongs
# to one org, `orgctx.WithBypassRLS(...)` for a job that legitimately spans
# them. Both are explicit; neither can be reached by accident.
#
# Usage: check-detached-org-writes.sh [--enforce]
#   --enforce  exit non-zero on a finding (the CI mode)
#   default    print findings and exit 0
#
# OPENIDX_SRC_ROOT overrides the repo root (used by the paired .test.sh).
set -uo pipefail

ROOT="${OPENIDX_SRC_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1

if [ ! -d "$ROOT" ]; then
  echo "check-detached-org-writes: no such root: $ROOT" >&2
  exit 2
fi

OPENIDX_SRC_ROOT="$ROOT" ENFORCE="$ENFORCE" python3 - <<'PY'
import os, pathlib, re, sys

root = pathlib.Path(os.environ["OPENIDX_SRC_ROOT"]).resolve()
enforce = os.environ["ENFORCE"] == "1"

# Only the application pool matters. internal/common/database/rls.go installs
# the app.org_id hook on THAT pool's checkout, so a direct pgx.Connect (the seed
# CLI, the credential rotators' admin connections) is outside RLS entirely and a
# conn.Close(context.Background()) is not a query at all. Matching `Pool.` keeps
# the guard to the calls where the tenant actually decides the outcome.
POOL_CALL = re.compile(r"\bPool\.(Exec|Query|QueryRow|Begin|SendBatch)\(")
BACKGROUND = re.compile(r"\bcontext\.Background\(\)")
# Either form of "I have said which tenant this is for".
SCOPED = re.compile(r"orgctx\.(With|WithBypassRLS)\b")

findings = []
for path in sorted(root.rglob("*.go")):
    rel = path.relative_to(root).as_posix()
    if not rel.startswith(("internal/", "cmd/")):
        continue
    if rel.endswith("_test.go") or "/migrations/" in rel:
        continue
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError as exc:
        findings.append(f"{rel}: cannot read ({exc})")
        continue

    for i, line in enumerate(lines):
        if not BACKGROUND.search(line):
            continue
        if SCOPED.search(line):
            continue                        # scoped on the same line
        # The context may be built on one line and used a few lines later, so
        # look at the surrounding block: the tenant must be named somewhere
        # between the Background() and the pool call that consumes it.
        window = "\n".join(lines[max(0, i - 3): i + 16])
        if not POOL_CALL.search(window):
            continue                        # not a database write at all
        if SCOPED.search(window):
            continue                        # scoped nearby
        findings.append(
            f"{rel}:{i+1}: context.Background() reaches a pool call with no "
            f"orgctx.With / orgctx.WithBypassRLS -- app.org_id will be empty, "
            f"so reads return nothing and writes are refused by RLS")

for f in findings:
    print(f"check-detached-org-writes: {f}", file=sys.stderr)

if findings:
    print(f"check-detached-org-writes: FAIL -- {len(findings)} detached "
          f"database call(s) with no tenant", file=sys.stderr)
    sys.exit(1 if enforce else 0)

print("check-detached-org-writes: ok -- every detached database call names its tenant")
PY
