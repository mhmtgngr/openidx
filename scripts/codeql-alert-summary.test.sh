#!/usr/bin/env bash
# Self-test for scripts/codeql-alert-summary.sh.
#
# The script exists to answer one question -- WHICH rule is the high-severity
# one -- so the test drives a SARIF that hides a single 7.5 among mediums, in
# the two shapes CodeQL really emits (rules under tool.driver, and rules under
# tool.extensions), and asserts the high one is named and the mediums are not
# mistaken for it.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/codeql-alert-summary.sh"

if ! command -v jq >/dev/null 2>&1; then
  echo "SKIP: jq not installed"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
pass=0
fail=0

check() { # check <name> <haystack> <needle>
  if printf '%s' "$2" | grep -qF -- "$3"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL: $1"
    echo "  expected to find: $3"
    echo "  in:"
    printf '%s\n' "$2" | sed 's/^/    /'
  fi
}

refute() { # refute <name> <haystack> <needle>
  if printf '%s' "$2" | grep -qF -- "$3"; then
    fail=$((fail + 1))
    echo "FAIL: $1"
    echo "  did not expect to find: $3"
  else
    pass=$((pass + 1))
  fi
}

# Shape 1: rules under tool.driver.rules. One 7.5 among two 5.0s.
cat >"$tmp/driver.sarif" <<'JSON'
{"runs":[{
  "tool":{"driver":{"name":"CodeQL","rules":[
    {"id":"go/disabled-certificate-check","properties":{"security-severity":"7.5"}},
    {"id":"go/log-injection","properties":{"security-severity":"5.0"}},
    {"id":"go/useless-assignment-to-local","properties":{}}
  ]}},
  "results":[
    {"ruleId":"go/log-injection","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":11}}}]},
    {"ruleId":"go/disabled-certificate-check","locations":[{"physicalLocation":{"artifactLocation":{"uri":"tools/x/main.go"},"region":{"startLine":48}}}]},
    {"ruleId":"go/log-injection","locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.go"},"region":{"startLine":22}}}]},
    {"ruleId":"go/useless-assignment-to-local","locations":[{"physicalLocation":{"artifactLocation":{"uri":"c.go"},"region":{"startLine":3}}}]}
  ]
}]}
JSON

out="$(bash "$SCRIPT" "$tmp/driver.sarif" 2>&1)"
check "driver: names the high rule"        "$out" "go/disabled-certificate-check"
check "driver: gives its file and line"    "$out" "tools/x/main.go:48"
check "driver: prints its severity"        "$out" "[7.5]"
check "driver: counts four results"        "$out" "results: 4"
check "driver: exactly one at the floor"   "$out" ">= 7.0: 1"
refute "driver: no medium above the floor" "$out" "[5]"

# Shape 2: rules under tool.extensions[].rules, which is what the CodeQL
# packs actually emit. Same assertions -- the lookup must find them there too.
cat >"$tmp/extensions.sarif" <<'JSON'
{"runs":[{
  "tool":{"driver":{"name":"CodeQL"},"extensions":[
    {"name":"codeql/javascript-queries","rules":[
      {"id":"js/prototype-pollution","properties":{"security-severity":"7.5"}},
      {"id":"js/unused-local-variable","properties":{}}
    ]}
  ]},
  "results":[
    {"ruleId":"js/unused-local-variable","locations":[{"physicalLocation":{"artifactLocation":{"uri":"web/x.ts"},"region":{"startLine":9}}}]},
    {"ruleId":"js/prototype-pollution","locations":[{"physicalLocation":{"artifactLocation":{"uri":"web/y.ts"},"region":{"startLine":140}}}]}
  ]
}]}
JSON

out="$(bash "$SCRIPT" "$tmp/extensions.sarif" 2>&1)"
check "extensions: names the high rule"     "$out" "js/prototype-pollution"
check "extensions: gives its file and line" "$out" "web/y.ts:140"

# A SARIF with nothing at the floor must say so rather than print nothing --
# silence would read as "the script did not run".
cat >"$tmp/clean.sarif" <<'JSON'
{"runs":[{"tool":{"driver":{"name":"CodeQL","rules":[
  {"id":"go/log-injection","properties":{"security-severity":"5.0"}}]}},
  "results":[{"ruleId":"go/log-injection","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}
JSON

out="$(bash "$SCRIPT" "$tmp/clean.sarif" 2>&1)"
check "clean: says nothing is at the floor" "$out" "no result at or above the floor"

# A directory argument must find the files inside it, and a run with no SARIF
# at all must not fail the build -- this is a diagnostic, never a gate.
out="$(bash "$SCRIPT" "$tmp" 2>&1)"
check "directory: reads every sarif in it" "$out" "go/disabled-certificate-check"
check "directory: reads the second one"    "$out" "js/prototype-pollution"

empty="$(mktemp -d)"
bash "$SCRIPT" "$empty" >/dev/null 2>&1
rc=$?
rm -rf "$empty"
if [ "$rc" -eq 0 ]; then pass=$((pass + 1)); else
  fail=$((fail + 1)); echo "FAIL: an empty directory must exit 0, got $rc"
fi

echo "codeql-alert-summary: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
