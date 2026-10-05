#!/usr/bin/env bash
# Gate: the admin console's npm audit fails the build on any HIGH or CRITICAL
# advisory, except one listed in web/admin-console/.npm-audit-ignore with a
# reason and an expiry date.
#
# WHY: `npm audit --audit-level=high` has no way to say "this one advisory
# does not apply here". GHSA-vfj7-8cjw-p6xm (braces <= 3.0.3, stack exhaustion
# on deeply nested brace patterns) was published with no patched release, and
# braces reaches the console only through tailwindcss 3 at build time. With
# nothing to bump to, the plain audit went red on main and on every pull
# request at once, and stayed red: a gate that is red for everyone stops being
# read, and the next real advisory lands in a column of failures nobody opens.
#
# Trivy has the same problem solved by .trivyignore. This is that, for npm:
# every other HIGH or CRITICAL advisory still fails, an exception names the
# advisory it excuses (not the package, so a second advisory against the same
# package still fails), and every exception expires so it is looked at again.
#
# Usage: check-npm-audit.sh <npm-audit.json> [ignore-file]
#   <npm-audit.json>  the output of `npm audit --json`
#   [ignore-file]     defaults to web/admin-console/.npm-audit-ignore
#
# Ignore-file format, one advisory per line, `#` starts a comment:
#   GHSA-xxxx-xxxx-xxxx exp:YYYY-MM-DD
# An entry with no exp: or a past one excuses nothing.
#
# NPM_AUDIT_TODAY overrides today's date (YYYY-MM-DD; used by the .test.sh).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${1:-}"
IGNORE="${2:-$ROOT/web/admin-console/.npm-audit-ignore}"
TODAY="${NPM_AUDIT_TODAY:-$(date -u +%Y-%m-%d)}"

if [ -z "$REPORT" ] || [ ! -s "$REPORT" ]; then
    echo "check-npm-audit: no audit report at '${REPORT}'" >&2
    exit 1
fi

# A registry failure makes `npm audit --json` print an error object and no
# vulnerabilities. That is not a clean audit, and must not read as one.
if ! jq -e 'type == "object" and has("vulnerabilities")' "$REPORT" >/dev/null 2>&1; then
    echo "check-npm-audit: '$REPORT' is not an npm audit report:" >&2
    head -c 2000 "$REPORT" >&2
    echo >&2
    exit 1
fi

# Exceptions that are still in date, one id per line.
EXCUSED=""
if [ -f "$IGNORE" ]; then
    while read -r id exp _; do
        case "$id" in ''|\#*) continue ;; esac
        until="${exp#exp:}"
        if [ "$exp" = "$until" ] || ! [[ "$until" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
            echo "check-npm-audit: $IGNORE: '$id' has no exp:YYYY-MM-DD, so it excuses nothing"
            continue
        fi
        if [[ "$until" < "$TODAY" ]]; then
            echo "check-npm-audit: $IGNORE: '$id' expired on $until, so it excuses nothing"
            continue
        fi
        EXCUSED="$EXCUSED $id"
    done < "$IGNORE"
fi

# Every HIGH or CRITICAL advisory in the report, by GHSA id and package. A
# package flagged only because it depends on a flagged one carries no advisory
# of its own (its `via` is a package name), so it is decided by that package.
FINDINGS=0
EXCUSED_SEEN=""
while IFS=$'\t' read -r id name severity title; do
    if [[ " $EXCUSED " == *" $id "* ]]; then
        echo "  excused  $id ($name, $severity): $title"
        EXCUSED_SEEN="$EXCUSED_SEEN $id"
        continue
    fi
    FINDINGS=$((FINDINGS + 1))
    echo "  FINDING  $id ($name, $severity): $title"
done < <(jq -r '
    [.vulnerabilities[] | .via[] | objects
     | select(.severity == "high" or .severity == "critical")
     | [(.url | split("/") | last), .name, .severity, .title]]
    | unique | .[] | @tsv' "$REPORT")

for id in $EXCUSED; do
    [[ " $EXCUSED_SEEN " == *" $id "* ]] && continue
    echo "check-npm-audit: $IGNORE: '$id' no longer appears in the audit; remove the entry"
done

if [ "$FINDINGS" -eq 0 ]; then
    echo "check-npm-audit: ok — no HIGH or CRITICAL advisory outside $(basename "$IGNORE")"
    exit 0
fi

echo
echo "check-npm-audit: $FINDINGS HIGH/CRITICAL advisory(ies)." >&2
echo "Bump the dependency (npm audit fix, or npm update <package>). An entry in" >&2
echo "$(basename "$IGNORE") is for an advisory that does not apply here, with the reason." >&2
exit 1
