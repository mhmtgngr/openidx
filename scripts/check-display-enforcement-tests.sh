#!/usr/bin/env bash
# Guard: every test the display = enforcement table names must exist, once.
#
# WHY: docs/evidence/display-equals-enforcement.md says which test proves each
# grant is enforced where it is displayed. Its "Automated checks" table names
# them, and the release run (.github/workflows/display-equals-enforcement.yml,
# through scripts/run-display-enforcement-tests.sh) runs exactly the tests it
# names. The table is the only list. A second, hand-kept list in the workflow
# would drift from the doc the first time a test is renamed, and the release
# run would go on reporting the old name.
#
# A name in that table is a claim that a test by that name runs. If the test is
# renamed, deleted or defined twice, the claim is false, and without this guard
# the release run would be the first thing to notice: after the tag, when it
# costs the most. So the pull request fails instead, on:
#
#   - a name that no _test.go defines (`func TestX(` at column 0);
#   - a name defined more than once, so the package that runs it is a guess;
#   - a row that names no test, or names one without backticks: the run would
#     drop it without a word;
#   - a test the release run cannot reach: behind a build constraint outside
#     test/integration, or inside another Go module (agent/).
#
# Tests under test/integration need the stack the integration job starts. The
# release run does not rebuild that job. The mapping marks them `integration`,
# and the report says where they run.
#
# Usage: check-display-enforcement-tests.sh [--enforce]
#          check, and exit non-zero on a finding (the CI mode; the default too)
#        check-display-enforcement-tests.sh --map
#          check, then print one tab-separated line per named test, in table
#          order: <package dir> <test> <run|integration> <grant>
#          On a finding it prints the findings on stderr, nothing on stdout,
#          and exits non-zero.
#
# OPENIDX_EVIDENCE_ROOT overrides the tree that is read (used by the .test.sh).
set -uo pipefail

ROOT="${OPENIDX_EVIDENCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

case "${1:-}" in
  "" | --enforce) MODE=check ;;
  --map) MODE=map ;;
  *)
    echo "usage: check-display-enforcement-tests.sh [--enforce | --map]" >&2
    exit 2
    ;;
esac

if [ ! -d "$ROOT" ]; then
  echo "check-display-enforcement-tests: no such root: $ROOT" >&2
  exit 2
fi

EVIDENCE_ROOT="$ROOT" MODE="$MODE" python3 - <<'PY'
import os
import pathlib
import re
import sys

root = pathlib.Path(os.environ["EVIDENCE_ROOT"]).resolve()
mode = os.environ["MODE"]
DOC = "docs/evidence/display-equals-enforcement.md"
SECTION = "## Automated checks"

findings = []


def finding(msg):
    findings.append(msg)


def cells(line):
    # Split a table row on unescaped pipes and drop the outer ones.
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    return [c.strip() for c in re.split(r"(?<!\\)\|", body)]


# ---- the table ---------------------------------------------------------------
rows = []  # (grant, [test names])
doc = root / DOC
if not doc.is_file():
    finding(f"{DOC} is missing; it is where the tests to run are named")
else:
    lines = doc.read_text(encoding="utf-8").splitlines()
    start = next((i for i, l in enumerate(lines) if l.strip() == SECTION), None)
    if start is None:
        finding(f"{DOC} has no '{SECTION}' section")
    else:
        end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
        table = []
        for line in lines[start + 1:end]:
            if line.lstrip().startswith("|"):
                table.append(line)
            elif table:
                break
        if len(table) < 3:
            finding(f"the '{SECTION}' section of {DOC} has no table with rows")
        else:
            header = cells(table[0])
            if "Grant" not in header or "Tests" not in header:
                finding(f"the '{SECTION}' table has no Grant or no Tests column "
                        f"(its header is: {' | '.join(header)})")
            elif not re.fullmatch(r"\|?(\s*:?-{3,}:?\s*\|?)+", table[1].strip()):
                finding(f"the '{SECTION}' table's second line is not a separator row")
            else:
                gi, ti = header.index("Grant"), header.index("Tests")
                for n, line in enumerate(table[2:], 1):
                    row = cells(line)
                    if len(row) != len(header):
                        finding(f"row {n} of the '{SECTION}' table has {len(row)} cells, "
                                f"and the header has {len(header)}")
                        continue
                    grant, tests = row[gi], row[ti]
                    names = re.findall(r"`(Test\w*)`", tests)
                    bare = re.findall(r"\bTest[A-Z0-9_]\w*", re.sub(r"`[^`]*`", "", tests))
                    for b in bare:
                        finding(f"row '{grant}' names {b} without backticks; "
                                f"the run reads only backticked names, so it would skip it")
                    if not names:
                        finding(f"row '{grant}' names no test; a row without one would "
                                f"be dropped from the release run without a word")
                    rows.append((grant, names))

# ---- where each test is defined ---------------------------------------------
# Every `func TestX(` at column 0 of a _test.go file, the way `go test` sees the
# tree: directories named testdata, or starting with . or _, are not packages.
FUNC = re.compile(r"^func (Test\w*)\(", re.M)
BUILD = re.compile(r"^//go:build (.+)$", re.M)
SKIP_DIRS = {"node_modules", "vendor", "testdata", "third_party"}
defs = {}      # name -> [(package dir, file, build constraint or None)]
modules = []   # directories, other than the root, that hold their own go.mod
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = sorted(d for d in dirnames
                         if d not in SKIP_DIRS and not d.startswith((".", "_")))
    rel = pathlib.Path(dirpath).relative_to(root).as_posix()
    if rel != "." and "go.mod" in filenames:
        modules.append(rel)
    for name in sorted(filenames):
        if not name.endswith("_test.go"):
            continue
        path = pathlib.Path(dirpath) / name
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            finding(f"cannot read {path.relative_to(root).as_posix()}: {exc}")
            continue
        head = text.split("\npackage ", 1)[0]
        build = BUILD.search(head)
        for m in FUNC.finditer(text):
            defs.setdefault(m.group(1), []).append(
                (rel, path.relative_to(root).as_posix(), build.group(1).strip() if build else None))

# ---- resolve every name ------------------------------------------------------
mapping = []   # (package dir, test, run|integration, grant)
for grant, names in rows:
    for test in names:
        found = defs.get(test, [])
        if not found:
            finding(f"`{test}` (row '{grant}'): no _test.go defines func {test}(. If it was "
                    f"renamed or removed, change the table in the same pull request")
            continue
        if len(found) > 1:
            where = ", ".join(f for _, f, _ in found)
            finding(f"`{test}` (row '{grant}') is defined {len(found)} times ({where}); "
                    f"the run cannot tell which one the table means")
            continue
        pkg, path, build = found[0]
        module = next((m for m in modules if pkg == m or pkg.startswith(m + "/")), None)
        if module:
            finding(f"`{test}` ({path}) is in the Go module at {module}/; the release run "
                    f"tests the root module only")
            continue
        if pkg == "test/integration" or pkg.startswith("test/integration/"):
            mapping.append((pkg, test, "integration", grant))
            continue
        if build:
            finding(f"`{test}` ({path}) is behind `//go:build {build}`; the release run "
                    f"passes no build tags, so it would never run it")
            continue
        mapping.append((pkg, test, "run", grant))

if rows and not findings and not any(m[2] == "run" for m in mapping):
    finding("no test in the table is one the release run can run; a run of nothing "
            "would verify nothing")

if findings:
    for f in findings:
        print(f"check-display-enforcement-tests: {f}", file=sys.stderr)
    print(f"check-display-enforcement-tests: {len(findings)} finding(s) in {DOC}",
          file=sys.stderr)
    sys.exit(1)

if mode == "map":
    for pkg, test, how, grant in mapping:
        print(f"{pkg}\t{test}\t{how}\t{grant}")
    sys.exit(0)

tests = {m[1] for m in mapping}
here = {m[1] for m in mapping if m[2] == "run"}
pkgs = {m[0] for m in mapping if m[2] == "run"}
print(f"check-display-enforcement-tests: ok — {len(rows)} row(s) name {len(tests)} test(s), "
      f"each defined once: {len(here)} in {len(pkgs)} package(s) for the release run, "
      f"{len(tests) - len(here)} in the integration job")
PY
