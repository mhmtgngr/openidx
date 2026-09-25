#!/usr/bin/env bash
# Guard: every Alertmanager configuration the compose files mount loads.
#
# WHY THIS EXISTS: Alertmanager expands no environment variables. The full
# stack's alertmanager.yml was written with ${SMTP_HOST:-localhost}-style
# placeholders anyway, so Alertmanager read them as text, refused the file
# ("too many colons in address") and restarted in a loop -- on every full-stack
# install, for as long as the file existed, and nothing in CI noticed because
# nothing loaded the file (#1004). The lite install found it by starting the
# observability profile on a real stack and watching Alertmanager restart
# seven times in twenty seconds.
#
# Two checks per file, both cheap and both deterministic:
#   1. No `${` outside a comment. A placeholder is wrong in this file
#      whatever surrounds it, and this check needs no tool, so it runs
#      everywhere.
#   2. `amtool check-config` accepts the file. amtool is Alertmanager's own
#      parser, so what it accepts, Alertmanager loads. It is looked for at
#      $AMTOOL, then on PATH; the CI job installs it from the pinned release.
#      Without it the guard FAILS rather than skipping the check: a guard that
#      passes for want of its tool is the silent hole this repository has been
#      burned by before.
#
# Usage: bash scripts/check-alertmanager-config.sh [--enforce] [file...]
#   Default files: deployments/docker/alertmanager/*.yml
#   Default: report and exit 0. --enforce: exit 1 on any offender.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

ENFORCE=0
if [ "${1:-}" = "--enforce" ]; then ENFORCE=1; shift; fi

files=("$@")
if [ "${#files[@]}" -eq 0 ]; then
  mapfile -t files < <(ls deployments/docker/alertmanager/*.yml 2>/dev/null)
fi
if [ "${#files[@]}" -eq 0 ]; then
  echo "offender: no Alertmanager configuration found under deployments/docker/alertmanager/"
  exit 1
fi

# $AMTOOL wins when it names something that runs; a path that does not is the
# same as none, and is reported as such rather than run into "No such file".
AMTOOL="${AMTOOL:-$(command -v amtool || true)}"
if [ -n "$AMTOOL" ] && [ ! -x "$AMTOOL" ]; then AMTOOL=""; fi
offenders=0
flag() { echo "offender: $1"; offenders=$((offenders+1)); }

for f in "${files[@]}"; do
  if [ ! -f "$f" ]; then
    flag "$f: not a file"
    continue
  fi
  # Outside comments: a comment may well say what a placeholder looks like.
  if grep -n '^[^#]*\${' "$f" >/dev/null; then
    flag "$f: contains a \${...} placeholder, which Alertmanager reads as text and refuses:"
    grep -n '^[^#]*\${' "$f" | sed 's/^/    /'
  fi
  if [ -z "$AMTOOL" ]; then
    flag "$f: not checked with amtool -- set AMTOOL=/path/to/amtool or put amtool on PATH (the Alertmanager release tarball carries it)"
    continue
  fi
  if ! out=$("$AMTOOL" check-config "$f" 2>&1); then
    flag "$f: amtool check-config refused it:"
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
done

echo "alertmanager-config: $offenders offender(s) across ${#files[@]} file(s)"
if [ "$ENFORCE" = 1 ] && [ "$offenders" -gt 0 ]; then exit 1; fi
exit 0
