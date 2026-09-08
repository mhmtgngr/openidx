#!/usr/bin/env bash
# Self-test for check-openapi-parses.sh.
#
# Case 2 is the one that matters: it reproduces the exact damage commit
# 28df9119 did to five specs -- a shared-responses block written into a path
# item on top of that operation's `parameters:` key -- and requires the guard to
# go red on it. Case 4 is the second half of that failure: a spec that parses
# and still refers to something it does not define, which is how
# access-service.yaml got through while the other five were obviously broken.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-openapi-parses.sh"

pass=0; fail=0
expect() { # expect <ok|red> <name>; spec dir staged in $WD
  local want="$1" name="$2" out rc
  out="$(OPENIDX_OPENAPI_DIR="$WD" bash "$GUARD" 2>&1)"; rc=$?
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = red ] && [ $rc -ne 0 ]; }; then
    echo "  ok   $name"; pass=$((pass+1))
  else
    echo "  FAIL $name (rc=$rc, wanted $want)"; echo "$out" | sed 's/^/       /'; fail=$((fail+1))
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

stage() { WD="$TMP/specs"; rm -rf "$WD"; mkdir -p "$WD"; cp "$ROOT/api/openapi/"*.yaml "$WD/"; }

# 1. The tree as it stands.
WD="$ROOT/api/openapi"
expect ok "every spec in the repository parses and resolves"

# 2. THE REGRESSION. Put governance-service.yaml back into the shape 28df9119
#    left it in: the responses block moved out of components and into a path
#    item, on top of that operation's parameters key.
stage
python3 - "$WD/governance-service.yaml" <<'PY'
import sys
p = sys.argv[1]
lines = open(p).read().splitlines()

start = lines.index("  responses:")
assert lines[start - 1] == "components:", "fixture drift: components.responses moved"
end = start + 1
while end < len(lines) and lines[end].startswith("    "):
    end += 1
block = lines[start + 1:end]
lines = lines[:start] + lines[end:]

# Overwrite the credential operation's parameters key with the block, exactly
# as the broken commit did.
i = lines.index("      parameters:")
lines = lines[:i] + ["      responses:"] + block + ["", "  parameters:"] + lines[i + 1:]
open(p, "w").write("\n".join(lines) + "\n")
PY
expect red "a responses block written into a path item"

# 3. Any spec that stops being YAML at all.
stage
printf '\n  this: is\n   not: valid\n     yaml: here\n' >>"$WD/audit-service.yaml"
expect red "a spec that no longer parses"

# 4. A spec that parses and refers to a response it does not define -- the
#    shape access-service.yaml was in.
stage
python3 - "$WD/access-service.yaml" <<'PY'
import sys
p = sys.argv[1]
lines = open(p).read().splitlines()
i = lines.index("    ServerError:")
end = i + 1
while end < len(lines) and lines[end].startswith("      "):
    end += 1
open(p, "w").write("\n".join(lines[:i] + lines[end:]) + "\n")
PY
expect red "a \$ref to a response the document does not define"

# 5. A document that parses but is not an OpenAPI spec at all.
stage
printf 'just: a mapping\n' >"$WD/governance-service.yaml"
expect red "a YAML file with no paths:"

# 6. An empty directory is a finding, not a pass -- a guard that greens on
#    nothing is the failure this whole file exists about.
WD="$TMP/empty"; rm -rf "$WD"; mkdir -p "$WD"
expect red "no specs found at all"

echo "check-openapi-parses.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
