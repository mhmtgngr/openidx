#!/usr/bin/env bash
# Prints what CodeQL actually found, into the job log.
#
# WHY THIS EXISTS: the CodeQL *results* check can fail a pull request while
# both CodeQL *jobs* pass. The jobs run the analysis and upload it; the check
# is GitHub reading the upload afterwards, and under its default rule a single
# alert with a security severity of 7.0 or higher fails the PR while two
# hundred mediums do not. The failure message names a count, never a rule:
#
#   "224 new alerts including 1 high severity security vulnerability"
#
# Everything that would say WHICH one lives behind the code-scanning API or
# the check's annotations. Neither is reachable from a CI log, so on this
# branch one high-severity alert was chased for two commits by inference from
# the diff -- and the first inference was wrong, which is the whole argument
# for this script. The analysis already writes the answer to disk
# (../results/<language>.sarif, kept after upload); nothing was reading it.
#
# So: after each analysis, print every result whose rule carries a security
# severity of 7.0 or higher, with its rule id, file and line, plus a count per
# rule for everything else. The next person to see a red CodeQL check reads
# the log instead of guessing.
#
# This step never fails the build. It is a window onto the analysis, not a
# second gate: the gate is the code-scanning check itself, and a diagnostic
# that can go red would only add a way to be wrong.
#
# Usage: bash scripts/codeql-alert-summary.sh <dir-or-sarif-file>...
set -uo pipefail

HIGH_SEVERITY_FLOOR=7.0

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <dir-or-sarif-file>..." >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "codeql-alert-summary: jq is not installed; skipping" >&2
  exit 0
fi

files=()
for arg in "$@"; do
  if [ -d "$arg" ]; then
    while IFS= read -r f; do files+=("$f"); done < <(find "$arg" -name '*.sarif' -type f | sort)
  elif [ -f "$arg" ]; then
    files+=("$arg")
  fi
done

if [ "${#files[@]}" -eq 0 ]; then
  echo "codeql-alert-summary: no .sarif files under: $*" >&2
  exit 0
fi

# The rule metadata CodeQL emits lives in tool.driver.rules for some packs and
# in tool.extensions[].rules for others; a result references it only by
# ruleId. Fold both into one id -> security-severity map before joining.
read -r -d '' PROGRAM <<'JQ'
def rules:
  [ .runs[]? | (.tool.driver.rules // []) + ([ .tool.extensions[]?.rules // [] ] | add // []) ]
  | add // [];

def sevmap:
  rules
  | map(select(.properties["security-severity"] != null))
  | map({key: .id, value: (.properties["security-severity"] | tonumber)})
  | from_entries;

sevmap as $sev
| [ .runs[]?.results[]? ]
| map({
    rule: (.ruleId // "<no rule id>"),
    sev:  ($sev[.ruleId // ""] // -1),
    at:   ((.locations[0].physicalLocation.artifactLocation.uri // "?")
           + ":" + ((.locations[0].physicalLocation.region.startLine // 0) | tostring))
  })
| (map(select(.sev >= $floor)) | sort_by(-.sev)) as $high
| (
    "  results: \(length)"
    + "  |  security-severity >= \($floor): \($high | length)"
  ),
  ( if ($high | length) > 0 then
      "  --- security-severity >= \($floor) (this is what fails the check) ---",
      ($high[] | "  [\(.sev)] \(.rule)\n        \(.at)")
    else
      "  (no result at or above the floor in this file)"
    end
  ),
  "  --- results per rule ---",
  ( group_by(.rule)
    | map({rule: .[0].rule, sev: .[0].sev, n: length})
    | sort_by(-.n)
    | .[]
    | "  \(.n)\tsev=\(.sev)\t\(.rule)" )
JQ

for f in "${files[@]}"; do
  echo "=== $f"
  jq -r --argjson floor "$HIGH_SEVERITY_FLOOR" "$PROGRAM" "$f" 2>&1 || {
    echo "  (could not read this file as SARIF)"
  }
  echo
done
exit 0
