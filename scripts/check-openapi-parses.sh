#!/usr/bin/env bash
# Guard: every OpenAPI spec must parse, and every local $ref must resolve.
#
# WHY: five of the seven specs in api/openapi were not YAML at all. Commit
# 28df9119 wrote a shared-responses block INTO a path item, on top of that
# operation's `parameters:` key, and left the orphaned tail behind under a stray
# path-level `parameters:`. audit, governance, identity, oauth and provisioning
# all took the same damage, and it shipped in v1.34.0.
#
# Nothing noticed, because nothing in this repository ever parsed them. docs.yml
# copies api/openapi/* into the published site verbatim, so the API reference
# for five services was being served a file no parser accepts -- a documentation
# page that displays as documentation and is not.
#
# The check is deliberately cheap and total: parse each file, then resolve every
# local $ref against the document. A dangling '#/components/responses/Conflict'
# is the other half of the same failure -- the spec parses and still describes
# something that is not there.
#
# Usage: check-openapi-parses.sh [--enforce]
#   --enforce  exit non-zero on a finding (the CI mode; the default too)
#
# OPENIDX_OPENAPI_DIR overrides the directory scanned (used by the .test.sh).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${OPENIDX_OPENAPI_DIR:-$ROOT/api/openapi}"

if [ ! -d "$DIR" ]; then
  echo "check-openapi-parses: no spec directory at $DIR" >&2
  exit 1
fi

python3 - "$DIR" <<'PY'
import glob
import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - the CI image ships PyYAML
    print("check-openapi-parses: PyYAML is not installed", file=sys.stderr)
    sys.exit(1)

directory = sys.argv[1]
specs = sorted(glob.glob(os.path.join(directory, "*.yaml")))
if not specs:
    print(f"check-openapi-parses: no *.yaml under {directory}", file=sys.stderr)
    sys.exit(1)

fail = 0


def finding(msg):
    global fail
    print(f"check-openapi-parses: {msg}", file=sys.stderr)
    fail = 1


def resolve(doc, pointer):
    node = doc
    for part in pointer.lstrip("#/").split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return False
    return True


checked = 0
for path in specs:
    name = os.path.basename(path)
    raw = open(path, encoding="utf-8").read()
    try:
        doc = yaml.safe_load(raw)
    except Exception as exc:
        finding(f"{name} is not YAML: {str(exc).splitlines()[0]}")
        continue
    if not isinstance(doc, dict) or "paths" not in doc:
        finding(f"{name} parses but has no paths: -- it is not an OpenAPI document")
        continue

    # Local refs only; a remote $ref is somebody else's document to validate.
    seen = set()
    for line in raw.splitlines():
        if "$ref:" not in line or "#/" not in line:
            continue
        pointer = line.split("$ref:", 1)[1].strip().strip("'\"")
        if not pointer.startswith("#/") or pointer in seen:
            continue
        seen.add(pointer)
        if not resolve(doc, pointer):
            finding(f"{name} refers to {pointer}, which the document does not define")
    checked += 1

if fail == 0:
    print(f"check-openapi-parses: ok — {checked} spec(s) parse, every local $ref resolves")
sys.exit(fail)
PY
