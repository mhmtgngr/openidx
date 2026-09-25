#!/usr/bin/env bash
# Self-test for check-alertmanager-config.sh: it must go red on the file that
# shipped broken (#1004), on a file amtool refuses, and when amtool is missing,
# and green on the files the compose files mount today.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
fails=0

expect() { # expect <want-exit> <label> <args...>
  local want="$1" label="$2"; shift 2
  local out rc
  out=$(bash scripts/check-alertmanager-config.sh --enforce "$@" 2>&1); rc=$?
  if [ "$rc" != "$want" ]; then
    echo "FAIL: $label -- exited $rc, expected $want"
    printf '%s\n' "$out" | sed 's/^/    /'
    fails=$((fails+1))
  else
    echo "ok: $label"
  fi
}

AMTOOL="${AMTOOL:-$(command -v amtool || true)}"
if [ -z "$AMTOOL" ]; then
  echo "FAIL: amtool not found -- set AMTOOL or put it on PATH; this self-test proves the amtool half can go red"
  exit 1
fi
export AMTOOL

# The files the compose files mount, as they are.
expect 0 "the shipped configurations load" deployments/docker/alertmanager/alertmanager.yml deployments/docker/alertmanager/alertmanager.lite.yml

# The shape that shipped broken: a placeholder Alertmanager reads as text.
cat > "$WORK/placeholder.yml" <<'Y'
global:
  resolve_timeout: 5m
  smtp_smarthost: '${SMTP_HOST:-localhost}:${SMTP_PORT:-587}'
route:
  receiver: default
receivers:
  - name: default
Y
expect 1 "a \${VAR:-default} placeholder is caught" "$WORK/placeholder.yml"

# No placeholder, but a file amtool refuses: the route names a receiver that
# does not exist. Only amtool catches this one.
cat > "$WORK/unknown-receiver.yml" <<'Y'
global:
  resolve_timeout: 5m
route:
  receiver: nobody
receivers:
  - name: default
Y
expect 1 "a file amtool refuses is caught" "$WORK/unknown-receiver.yml"

# A missing file is an offender, not a pass.
expect 1 "a missing file is caught" "$WORK/not-there.yml"

# Without amtool the guard must fail, not skip: a pass for want of the tool
# would be the silent hole this guard exists to close.
out=$(AMTOOL=/nonexistent/amtool PATH=/usr/bin:/bin bash scripts/check-alertmanager-config.sh --enforce deployments/docker/alertmanager/alertmanager.lite.yml 2>&1); rc=$?
if [ "$rc" != 1 ] || ! printf '%s' "$out" | grep -q 'not checked with amtool'; then
  echo "FAIL: a missing amtool should fail the guard and say so -- exited $rc"
  printf '%s\n' "$out" | sed 's/^/    /'
  fails=$((fails+1))
else
  echo "ok: a missing amtool fails the guard"
fi

# Without --enforce the guard reports and exits 0, like the other guards.
out=$(bash scripts/check-alertmanager-config.sh "$WORK/placeholder.yml" 2>&1); rc=$?
if [ "$rc" != 0 ] || ! printf '%s' "$out" | grep -q 'offender(s)' || ! printf '%s' "$out" | grep -q '^offender: '; then
  echo "FAIL: without --enforce the guard should report and exit 0 -- exited $rc"
  fails=$((fails+1))
else
  echo "ok: without --enforce the guard reports and exits 0"
fi

if [ "$fails" -gt 0 ]; then
  echo "check-alertmanager-config self-test: $fails failure(s)"
  exit 1
fi
echo "check-alertmanager-config self-test: all cases behave"
