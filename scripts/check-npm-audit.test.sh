#!/usr/bin/env bash
# Self-test for check-npm-audit.sh.
#
# The gate exists to stay red on every HIGH or CRITICAL advisory but the ones
# excused on purpose, so most cases here are ways an exception could excuse
# more than it says: a lapsed date, a missing date, a second advisory against
# the same package, a registry error that prints no vulnerabilities at all.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-npm-audit.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

# run_case <name> <want-exit> <audit-json> <ignore-file-body>
run_case() {
    local name="$1" want="$2" report="$3" ignore="$4"
    printf '%s\n' "$report" > "$TMP/audit.json"
    printf '%s\n' "$ignore" > "$TMP/ignore"
    local out rc
    out=$(NPM_AUDIT_TODAY=2026-10-05 bash "$GUARD" "$TMP/audit.json" "$TMP/ignore" 2>&1)
    rc=$?
    if [ "$rc" -eq "$want" ]; then
        echo "  ok   $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL $name (exit $rc, want $want)"
        echo "$out" | sed 's/^/       /'
        FAIL=$((FAIL + 1))
    fi
}

advisory() { # <package> <GHSA id> <severity>
    printf '{"source":1,"name":"%s","dependency":"%s","title":"t","url":"https://github.com/advisories/%s","severity":"%s","range":"<9"}' "$1" "$1" "$2" "$3"
}
report() { # <vulnerabilities object body>
    printf '{"auditReportVersion":2,"vulnerabilities":{%s},"metadata":{}}' "$1"
}

BRACES=$(report "\"braces\":{\"name\":\"braces\",\"severity\":\"high\",\"via\":[$(advisory braces GHSA-vfj7-8cjw-p6xm high)]},\"micromatch\":{\"name\":\"micromatch\",\"severity\":\"high\",\"via\":[\"braces\"]}")
AXIOS=$(report "\"axios\":{\"name\":\"axios\",\"severity\":\"high\",\"via\":[$(advisory axios GHSA-c29m-xwm3-cm6r high)]}")
CRITICAL=$(report "\"x\":{\"name\":\"x\",\"severity\":\"critical\",\"via\":[$(advisory x GHSA-aaaa-bbbb-cccc critical)]}")
MODERATE=$(report "\"vitest\":{\"name\":\"vitest\",\"severity\":\"moderate\",\"via\":[$(advisory vitest GHSA-82fw-gwwq-j7x9 moderate)]}")
BRACES_TWICE=$(report "\"braces\":{\"name\":\"braces\",\"severity\":\"high\",\"via\":[$(advisory braces GHSA-vfj7-8cjw-p6xm high),$(advisory braces GHSA-dddd-eeee-ffff high)]}")

run_case "a clean audit passes" 0 "$(report "")" ""
run_case "an unexcused HIGH advisory fails" 1 "$AXIOS" ""
run_case "an unexcused CRITICAL advisory fails" 1 "$CRITICAL" ""
run_case "a MODERATE advisory does not gate" 0 "$MODERATE" ""
run_case "an in-date exception excuses its advisory and the packages flagged through it" 0 \
    "$BRACES" "GHSA-vfj7-8cjw-p6xm exp:2027-01-05"
run_case "an exception still excuses on its last day" 0 \
    "$BRACES" "GHSA-vfj7-8cjw-p6xm exp:2026-10-05"
run_case "an expired exception excuses nothing" 1 \
    "$BRACES" "GHSA-vfj7-8cjw-p6xm exp:2026-10-04"
run_case "an exception with no exp: excuses nothing" 1 \
    "$BRACES" "GHSA-vfj7-8cjw-p6xm"
run_case "a commented-out exception excuses nothing" 1 \
    "$BRACES" "# GHSA-vfj7-8cjw-p6xm exp:2027-01-05"
run_case "an exception names an advisory, not a package" 1 \
    "$BRACES_TWICE" "GHSA-vfj7-8cjw-p6xm exp:2027-01-05"
run_case "an exception for one advisory does not excuse another package" 1 \
    "$AXIOS" "GHSA-vfj7-8cjw-p6xm exp:2027-01-05"
run_case "a stale exception only warns" 0 \
    "$(report "")" "GHSA-vfj7-8cjw-p6xm exp:2027-01-05"
run_case "a registry error is not a clean audit" 1 \
    '{"error":{"code":"ENOAUDIT","summary":"audit endpoint returned an error"}}' ""
run_case "an empty report is not a clean audit" 1 "" ""

# The repository's own ignore file parses and excuses what it says it does.
printf '%s\n' "$BRACES" > "$TMP/audit.json"
if NPM_AUDIT_TODAY=2026-10-05 bash "$GUARD" "$TMP/audit.json" >/dev/null 2>&1; then
    echo "  ok   the repository's .npm-audit-ignore excuses the braces advisory"
    PASS=$((PASS + 1))
else
    echo "  FAIL the repository's .npm-audit-ignore does not excuse the braces advisory"
    FAIL=$((FAIL + 1))
fi

echo "check-npm-audit.test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
