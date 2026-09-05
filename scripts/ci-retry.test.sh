#!/usr/bin/env bash
# Proves ci-retry.sh retries, gives up, and -- above all -- never turns a
# real failure into a green tick.
#
# A retry wrapper is the easiest place in a build system to hide a broken
# test: swallow the last exit code and every red becomes a slow green. So the
# cases below assert the exit STATUS as well as the attempt COUNT, and the
# "gives up" case demands the command's own code (7) comes back out, not 0
# and not 1.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RETRY="$ROOT/scripts/ci-retry.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0

COUNT="$WORK/count"

# A fake command whose behaviour depends on how many times it has been run:
# it fails with rc 7 until it has been called $SUCCEED_ON times.
cat > "$WORK/flaky.sh" <<'EOF'
#!/usr/bin/env bash
n=$(( $(cat "$COUNT") + 1 ))
echo "$n" > "$COUNT"
if [ "$n" -ge "${SUCCEED_ON:-1}" ]; then exit 0; fi
exit 7
EOF
chmod +x "$WORK/flaky.sh"

check() { # name expected_rc expected_calls actual_rc
  local name="$1" exp_rc="$2" exp_calls="$3" rc="$4"
  local calls; calls="$(cat "$COUNT")"
  if [ "$rc" = "$exp_rc" ] && [ "$calls" = "$exp_calls" ]; then
    echo "ok   $name (rc=$rc, calls=$calls)"
  else
    echo "FAIL $name (rc=$rc beklenen $exp_rc, calls=$calls beklenen $exp_calls)"
    fail=$((fail + 1))
  fi
}

export COUNT

echo 0 > "$COUNT"
SUCCEED_ON=1 bash "$RETRY" 3 0 -- "$WORK/flaky.sh" >/dev/null 2>&1
check "ilk denemede basari tek cagri yapar" 0 1 $?

echo 0 > "$COUNT"
SUCCEED_ON=3 bash "$RETRY" 3 0 -- "$WORK/flaky.sh" >/dev/null 2>&1
check "ucuncu denemede toparlar" 0 3 $?

# THE IMPORTANT ONE: the command never recovers, so its exit code must
# survive the wrapper untouched. If this ever reports rc=0 the wrapper has
# become a way to make failing builds look healthy.
echo 0 > "$COUNT"
SUCCEED_ON=99 bash "$RETRY" 3 0 -- "$WORK/flaky.sh" >/dev/null 2>&1
check "pes edince komutun cikis kodu korunur" 7 3 $?

# attempts=1 means "no retry at all", not "retry once".
echo 0 > "$COUNT"
SUCCEED_ON=99 bash "$RETRY" 1 0 -- "$WORK/flaky.sh" >/dev/null 2>&1
check "attempts=1 yeniden denemez" 7 1 $?

# Backoff must actually grow: 3 attempts with a 1s first delay waits 1s then
# 2s, so the whole thing cannot finish in under 3 seconds. A wrapper that
# hammers a struggling registry three times in the same millisecond is not a
# backoff, and would make an outage worse rather than riding it out.
echo 0 > "$COUNT"
start="$(date +%s)"
SUCCEED_ON=99 bash "$RETRY" 3 1 -- "$WORK/flaky.sh" >/dev/null 2>&1
rc=$?
elapsed=$(( $(date +%s) - start ))
if [ "$rc" = 7 ] && [ "$elapsed" -ge 3 ]; then
  echo "ok   bekleme suresi katlanarak buyur (${elapsed}s)"
else
  echo "FAIL bekleme suresi katlanmadi (rc=$rc, ${elapsed}s, beklenen >=3s)"
  fail=$((fail + 1))
fi

# Malformed invocations must be rejected loudly (rc 2), not silently treated
# as "run the command once": a typo in a workflow would otherwise disable the
# retry without anyone noticing.
for bad in "3 5 helm version" "0 5 -- true" "x 5 -- true" "3 -- true"; do
  # shellcheck disable=SC2086
  bash "$RETRY" $bad >/dev/null 2>&1
  rc=$?
  if [ "$rc" = 2 ]; then
    echo "ok   hatali kullanim reddedilir: $bad"
  else
    echo "FAIL hatali kullanim reddedilmedi: $bad (rc=$rc)"
    fail=$((fail + 1))
  fi
done

if [ "$fail" -gt 0 ]; then
  echo "CI_RETRY_SELFTEST=FAILED($fail)"; exit 1
fi
echo "CI_RETRY_SELFTEST=OK"
