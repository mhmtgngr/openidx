#!/usr/bin/env bash
# Guard: every console caller of api.pam.connect() must launch the session
# through openPamSessionWindow (lib/pam-session-handoff), and must not pull the
# connect URL out of the response itself.
#
# Why this is a guard and not a review note. The connect response carries a
# bearer URL. Handing it to window.open puts that token in the address bar and
# in browser history, and points the user at Guacamole's own chrome when the
# session fails. The Connections page knew this and opened a chrome-less
# /pam-session wrapper instead, handing the URL off through a single-use
# localStorage entry. Quick links — the END-USER launcher — called
# window.open(url) directly. Same token, same broker, opposite decision, and
# nothing failed: the second launcher was written later, by reading the API
# rather than the first launcher.
#
# The overlay flag the wrapper needs to explain a failed ZTNA launch rides in
# that same handoff, so a launcher that skips it also loses the one message
# that says "the OpenIDX client is not running on this machine".
#
# Two rules, because importing the helper does not prove you used it:
#   1. a caller of api.pam.connect must import openPamSessionWindow
#   2. a caller must not reference connect_url — reading the URL out of the
#      response is what the helper is for, and you cannot open it yourself
#      without doing so
#
# What this does NOT prove: that the helper is called on every path. A file can
# import it, avoid connect_url, and still do something odd with res.url. The
# unit tests in lib/pam-session-handoff.test.ts and the two launcher test files
# cover behaviour; this covers shape, which is what stops a THIRD launcher from
# rediscovering the wrong answer.
#
# Default: warn (exit 0). --enforce: exit 1 if any offender.
set -uo pipefail
cd "$(dirname "$0")/.."
SRC="${SH_CONSOLE_SRC:-web/admin-console/src}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1

HELPER='openPamSessionWindow'
offenders=0
callers=0

while IFS= read -r f; do
  # The helper's own module and every test file are exempt: the tests must be
  # able to name both the helper and the field to assert anything about them.
  case "$f" in
    */lib/pam-session-handoff.ts) continue;;
    *.test.ts|*.test.tsx) continue;;
  esac
  grep -q 'api\.pam\.connect(' "$f" || continue
  callers=$((callers+1))

  if ! grep -q "$HELPER" "$f"; then
    echo "offender: $f — calls api.pam.connect() but never $HELPER;"
    echo "          a brokered session must open through the /pam-session wrapper,"
    echo "          not by handing the token-bearing connect URL to the browser"
    offenders=$((offenders+1))
    continue
  fi
  if grep -q 'connect_url' "$f"; then
    echo "offender: $f — reads connect_url itself;"
    echo "          let $HELPER take the response, so the URL, the single-use"
    echo "          handoff key and the overlay flag are decided in one place"
    offenders=$((offenders+1))
  fi
done < <(find "$SRC" \( -name '*.ts' -o -name '*.tsx' \) -type f | sort)

echo "pam-launch-wrapper: $callers launcher(s), $offenders offender(s)"

# A rule that matches nothing passes forever. If no file calls api.pam.connect
# the launchers were renamed or moved and this guard is watching an empty set.
if [ "$callers" -eq 0 ]; then
  echo "pam-launch-wrapper: no caller of api.pam.connect() found — the guard's"
  echo "  pattern no longer matches the code it is supposed to watch. Update it."
  if [ "$ENFORCE" = 1 ]; then exit 1; fi
fi

if [ "$ENFORCE" = 1 ] && [ "$offenders" -gt 0 ]; then exit 1; fi
exit 0
