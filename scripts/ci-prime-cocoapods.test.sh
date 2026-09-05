#!/usr/bin/env bash
# Proves ci-prime-cocoapods.sh helps on a blip and NEVER turns a real outage
# into a green build.
#
# The script's whole job is to move one network failure out of a Flutter build
# and into a five-second step, so the property that matters is the same one
# ci-retry.sh is built around: the last attempt's exit status is the script's
# exit status. A `|| true` added here one day -- to "stop the macOS job being
# flaky" -- would make every CocoaPods outage look like a healthy prime, and
# the build would then fail further along with a stranger message than the one
# this exists to remove. Case 4 is that guard.
#
# `pod` is a fake on PATH: there is no CocoaPods on a Linux CI runner, and
# there should not need to be to test the logic around it.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRIME="$ROOT/scripts/ci-prime-cocoapods.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0
mkdir -p "$WORK/bin" "$WORK/nopod"

# A fake `pod`. FAKE_POD_REPOS is what `repo list` prints; FAKE_POD_FAILURES is
# how many `repo add-cdn` calls fail before one succeeds, counted in a file so
# the count survives across the retry wrapper's separate invocations.
cat > "$WORK/bin/pod" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "repo" ] && [ "${2:-}" = "list" ]; then
  printf '%s' "${FAKE_POD_REPOS:-}"
  exit 0
fi
if [ "${1:-}" = "repo" ] && [ "${2:-}" = "add-cdn" ]; then
  n=$(cat "$FAKE_POD_COUNTER" 2>/dev/null || echo 0)
  n=$((n + 1)); echo "$n" > "$FAKE_POD_COUNTER"
  if [ "$n" -le "${FAKE_POD_FAILURES:-0}" ]; then
    echo "fatal: repository 'https://cdn.cocoapods.org/' not found" >&2
    exit 1
  fi
  echo "added $3"
  exit 0
fi
exit 64
EOF
chmod +x "$WORK/bin/pod"

run() { # failures repos -> rc, with a fresh counter each time
  local failures="$1" repos="$2"
  : > "$WORK/counter"
  FAKE_POD_FAILURES="$failures" FAKE_POD_REPOS="$repos" \
    FAKE_POD_COUNTER="$WORK/counter" \
    COCOAPODS_PRIME_ATTEMPTS=3 COCOAPODS_PRIME_DELAY=1 \
    PATH="$WORK/bin:$PATH" bash "$PRIME" >"$WORK/out" 2>&1
  return $?
}

t() { # name expected_rc actual_rc
  if [ "$3" = "$2" ]; then
    echo "ok   $1 (rc=$3)"
  else
    echo "FAIL $1 (rc=$3, beklenen $2)"; sed 's/^/       /' "$WORK/out"; fail=$((fail + 1))
  fi
}

# 1. The healthy path: no trunk yet, the CDN answers, the source is created.
run 0 $'0 repos\n'; t "kaynak yoksa olusturulur" 0 $?
grep -q "creating the 'trunk'" "$WORK/out" || {
  echo "FAIL olusturma mesaji yok"; fail=$((fail + 1)); }

# 2. Already there -- as a CDN or as an older git clone. `pod repo add-cdn`
#    would fail on the name, so the script must not call it at all.
run 0 $'trunk\n- Type: CDN\n- URL:  https://cdn.cocoapods.org/\n'
t "mevcut kaynak birakilir" 0 $?
if grep -q "creating the 'trunk'" "$WORK/out"; then
  echo "FAIL mevcut kaynak yeniden olusturulmus"; fail=$((fail + 1))
fi

# 3. The case the script was written for: the first attempt hits the blip, the
#    second gets through. This is a green build that would have been red.
run 1 $'0 repos\n'; t "gecici hata sonrasi basarili" 0 $?

# 4. THE ONE THAT MATTERS: the CDN is down for every attempt. A real outage
#    stays red. If this ever passes with rc=0, someone has muted the failure.
run 9 $'0 repos\n'; t "kalici hata kirmizi kalir" 1 $?

# 5. No CocoaPods on PATH at all -- every non-macOS leg of a build matrix. Not
#    a failure, and it must say so rather than dying on `pod: command not
#    found` in a job that was never going to need it.
PATH="$WORK/nopod:/usr/bin:/bin" bash "$PRIME" >"$WORK/out" 2>&1
t "pod yoksa sessizce gecer" 0 $?
grep -q "nothing to prime" "$WORK/out" || {
  echo "FAIL pod yoklugu duyurulmamis"; fail=$((fail + 1)); }

echo
if [ "$fail" -eq 0 ]; then
  echo "ci-prime-cocoapods.test.sh: tum durumlar gecti"
else
  echo "ci-prime-cocoapods.test.sh: $fail durum basarisiz"
fi
exit $((fail > 0))
