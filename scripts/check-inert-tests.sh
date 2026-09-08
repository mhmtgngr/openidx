#!/usr/bin/env bash
# Guard: a Go test whose body is one unconditional t.Skip cannot fail.
#
# WHY: twenty-eight of them were in the tree. internal/governance/request_test.go
# was nine test functions and fourteen subtests, every one a bare
# t.Skip("DB mock not available - requires integration test") -- named after
# SubmitRequest / ApproveRequest / DenyRequest, methods this service has never
# had, while the package carried a container-backed setupTestDB the whole time.
# jit_test.go said "validation test - but still needs service init" over
# validation that runs before RequestElevation touches a database at all.
# response_test.go said "Requires real Redis client" in a package that has used
# miniredis since it was written.
#
# None of that is a skip. A skip is a decision made at RUN time about the
# environment -- no Docker daemon, no GPU, not this platform. A t.Skip with no
# condition is a decision made at WRITE time never to test the thing, wearing a
# skip's clothes so the count of tests keeps going up. It shows as a pass.
#
# So: a skip must be guarded by something. If a test cannot be written yet,
# delete it and leave the reason in the package's doc comment where a reader
# will find it, rather than a green tick that says the opposite.
#
# A comment is not a condition. The first cut of this guard required the skip to
# be the FIRST line of the body, and two inert tests sat behind a paragraph of
# explanation the whole time it was green: cmd/gateway-service's route-table test
# ("route conflicts in the routes package" -- untrue; the 63 routes register on a
# fresh engine without a murmur) and the integration suite's authorization-code
# expiry test. The prose is exactly where the reason for not writing the test
# gets parked, so the prose is where the guard has to look through.
#
# Usage: check-inert-tests.sh [--enforce]
#   --enforce  exit non-zero on a finding (the CI mode; the default too)
#
# OPENIDX_INERT_ROOT overrides the tree scanned (used by the .test.sh).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN="${OPENIDX_INERT_ROOT:-$ROOT}"

python3 - "$SCAN" <<'PY'
import os
import re
import sys

scan = sys.argv[1]
if not os.path.isdir(scan):
    print(f"check-inert-tests: no tree at {scan}", file=sys.stderr)
    sys.exit(1)

# A subtest whose entire body is one t.Skip, and a top-level test of the same
# shape. Both are matched on the literal source rather than on a parse, because
# the property is textual: nothing EXECUTABLE stands between the opening brace
# and the skip.
#
# PROSE is what may stand there -- blank lines and // comments -- and it does not
# make the skip conditional, so it does not clear the finding. Anything else
# (even a single statement) does, because then the guard can no longer tell from
# the text alone whether the skip is reached.
PROSE = r'((?:[ \t]*(?://[^\n]*)?\n)*)'
SUBTEST = re.compile(
    r't\.Run\(\s*"([^"]*)"\s*,\s*func\(t \*testing\.T\) \{[ \t]*\n'
    + PROSE
    + r'[ \t]*t\.Skipf?\([^\n]*\)\s*\n\s*\}\)'
)
TOPLEVEL = re.compile(
    r'func (Test\w+)\(t \*testing\.T\) \{[ \t]*\n'
    + PROSE
    + r'[ \t]*t\.Skipf?\([^\n]*\)\s*\n\}'
)


def buried(prose):
    """How the finding reads when an explanation stands in front of the skip."""
    n = len([ln for ln in prose.splitlines() if ln.strip()])
    if n == 0:
        return ""
    return f" (behind {n} comment line{'s' if n > 1 else ''})"

findings = []
scanned = 0
for root, dirs, names in os.walk(scan):
    dirs[:] = [d for d in dirs if d not in ("third_party", "node_modules", ".git", "vendor")]
    for name in names:
        if not name.endswith("_test.go"):
            continue
        path = os.path.join(root, name)
        src = open(path, encoding="utf-8", errors="replace").read()
        scanned += 1
        rel = os.path.relpath(path, scan)
        for m in SUBTEST.finditer(src):
            line = src[: m.start()].count("\n") + 1
            findings.append(
                f"{rel}:{line}: subtest {m.group(1)!r} is one unconditional t.Skip{buried(m.group(2))}"
            )
        for m in TOPLEVEL.finditer(src):
            line = src[: m.start()].count("\n") + 1
            findings.append(
                f"{rel}:{line}: {m.group(1)} is one unconditional t.Skip{buried(m.group(2))}"
            )

for f in sorted(findings):
    print(f"check-inert-tests: {f}", file=sys.stderr)

if findings:
    print(
        f"check-inert-tests: {len(findings)} test(s) that cannot fail. Give the skip a "
        "condition, write the test, or delete it -- do not leave a green tick over "
        "an untested thing.",
        file=sys.stderr,
    )
    sys.exit(1)

if scanned == 0:
    print(f"check-inert-tests: no _test.go files under {scan}", file=sys.stderr)
    sys.exit(1)

print(f"check-inert-tests: ok — {scanned} test file(s), none inert")
PY
