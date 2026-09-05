#!/usr/bin/env bash
# Guard: a document must not cite a file that is not there.
#
# WHY: this is the most common way documentation goes wrong here, and the one
# a reader cannot detect. Prose that describes a feature inaccurately at least
# reads as a claim you can go and check. A path -- `internal/oauth/store.go`,
# `mobile/src/features/authenticator/` -- reads as a *fact*, and a reader who
# cannot find it assumes they are looking in the wrong place, not that the
# document is stale. Three sweeps of this repo's docs found the same class
# every time: a tree gets deleted or renamed and a dozen documents keep
# pointing at it. The mobile developer guide had fifteen `mobile/src/...`
# citations with a tick against each, for a tree deleted two commits earlier.
#
# Two of the fifty findings on this guard's first run were written by the very
# commit that preceded it. That is the argument for the guard: nobody, however
# careful, gets this right by attention.
#
# What counts as a citation: a backticked token starting with one of the
# repo's top-level directories. Deliberately NOT checked, because they are
# not claims about a path that exists:
#   - glob and brace forms (`internal/oauth/**`, `internal/{a,b}.go`) and
#     elisions (`mobile/src/...`) -- shorthand for a set, not a file
#   - Go symbol references (`internal/auth.ValidateToken`) -- a package path
#     plus an identifier
#
# Everything else must exist, or be registered in docs/doc-citations.txt with
# a reason. The register also fails when a listed path comes BACK -- a stale
# waiver is the same defect one level up.
#
# Usage: check-docs-drift.sh [--enforce]
#   --enforce  exit non-zero on a finding (the CI mode)
#   default    print findings and exit 0
#
# OPENIDX_DOCS_ROOT overrides the repo root (used by the paired .test.sh).
set -uo pipefail

ROOT="${OPENIDX_DOCS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1

if [ ! -d "$ROOT" ]; then
  echo "check-docs-drift: no such root: $ROOT" >&2
  exit 2
fi

OPENIDX_DOCS_ROOT="$ROOT" ENFORCE="$ENFORCE" python3 - <<'PY'
import os, re, sys, pathlib

root = pathlib.Path(os.environ["OPENIDX_DOCS_ROOT"]).resolve()
enforce = os.environ["ENFORCE"] == "1"

TOP = ("internal/", "cmd/", "web/", "client/", "agent/", "agent-android/",
       "docs/", "deployments/", "scripts/", "tools/", "test/", "api/",
       ".github/", "mobile/", "frontend/")

CITATION = re.compile(r"`([^`\s]+)`")
LOCATOR = re.compile(r"(:\d+(-\d+)?|#[^#]*)$")   # `file.go:12-40`, `page.md#anchor`

# `internal/auth.ValidateToken`, `internal/oauth.isValidSessionID`: a package
# path plus an identifier. Told apart from a filename by its suffix -- a dot
# followed by something that is not a file extension we ship.
EXTENSIONS = {"go", "ts", "tsx", "js", "jsx", "mjs", "dart", "py", "sh", "ps1",
              "md", "yaml", "yml", "json", "sql", "rego", "tf", "toml", "txt",
              "html", "css", "aar", "xcframework", "apk", "ipa", "gradle",
              "kts", "plist", "service", "lock", "mod", "sum", "env", "cmd"}

def is_go_symbol(p: str) -> bool:
    last = p.rsplit("/", 1)[-1]
    return "." in last and last.rsplit(".", 1)[1] not in EXTENSIONS

register = root / "docs" / "doc-citations.txt"
allowed, skipped, bad_register = {}, [], []
if register.exists():
    for n, raw in enumerate(register.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3 or parts[0] not in ("allow", "skip"):
            bad_register.append(f"{register.name}:{n}: expected `allow <path> <reason>` or "
                                f"`skip <glob> <reason>`, got: {line}")
            continue
        kind, target, reason = parts
        (allowed.setdefault(target, reason) if kind == "allow"
         else skipped.append((target, reason)))
else:
    bad_register.append(f"missing register: {register}")

def is_skipped(rel: str) -> bool:
    return any(pathlib.PurePath(rel).match(g) for g, _ in skipped)

def is_shorthand(p: str) -> bool:
    return any(c in p for c in "*{}") or "..." in p or is_go_symbol(p)

findings, seen_allowed = [], set()
docs = sorted(p for p in root.rglob("*.md")
              if "node_modules" not in p.parts and ".git" not in p.parts)

for doc in docs:
    rel = doc.relative_to(root).as_posix()
    if is_skipped(rel):
        continue
    try:
        body = doc.read_text(errors="replace")
    except OSError as exc:                       # unreadable is its own problem
        findings.append(f"{rel}: cannot read ({exc})")
        continue
    for lineno, line in enumerate(body.splitlines(), 1):
        for m in CITATION.finditer(line):
            raw = m.group(1)
            if not raw.startswith(TOP):
                continue
            # A `:12-40` line range or `#anchor` locates a place inside the
            # file; strip it before judging the shape. Sentence punctuation is
            # stripped only afterwards, so `mobile/src/...` is still read as an
            # elision rather than as a claim about `mobile/src/`.
            cited = LOCATOR.sub("", raw)
            if is_shorthand(cited):
                continue
            cited = cited.rstrip(",.;)")
            if (root / cited).exists():
                continue
            if cited in allowed:
                seen_allowed.add(cited)
                continue
            findings.append(f"{rel}:{lineno}: cites `{cited}`, which does not exist")

# A waiver for a path that came back is a waiver nobody rechecked.
returned = sorted(p for p in allowed if (root / p).exists())

for f in bad_register:
    print(f"check-docs-drift: {f}", file=sys.stderr)
for f in findings:
    print(f"check-docs-drift: {f}", file=sys.stderr)
for p in returned:
    print(f"check-docs-drift: docs/doc-citations.txt allows `{p}`, but it exists now — "
          f"drop the entry", file=sys.stderr)

stale = sorted(set(allowed) - seen_allowed - set(returned))
for p in stale:
    print(f"check-docs-drift: docs/doc-citations.txt allows `{p}`, but no document "
          f"cites it — drop the entry", file=sys.stderr)

total = len(findings) + len(returned) + len(stale) + len(bad_register)
if total:
    print(f"check-docs-drift: FAIL — {len(findings)} broken citation(s), "
          f"{len(returned) + len(stale)} stale waiver(s), "
          f"{len(bad_register)} register error(s)", file=sys.stderr)
    sys.exit(1 if enforce else 0)

print(f"check-docs-drift: ok — every path cited by {len(docs)} document(s) is there")
PY
