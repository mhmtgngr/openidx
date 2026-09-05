#!/usr/bin/env bash
# Proves check-race-timeout.sh can actually go RED.
#
# The guard exists because a missing `-timeout` is invisible on every day the
# runner is fast, and on the day it is not the failure names the wrong thing
# ("Race Detector" for a package that simply ran long). So the red cases are
# the point: a bare `-race`, and one hidden inside a line continuation where
# reading the first line alone would suggest the flag is there.
#
# The green cases matter just as much. A guard that flags `-timeout=20m`
# because it only recognised the space-separated form, or that counts a
# commented-out example as an invocation, is one somebody switches off.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-race-timeout.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0

t() { # name expected_rc file
  local name="$1" exp="$2" file="$3"
  bash "$CHECK" "$file" >/dev/null 2>&1
  local rc=$?
  if [ "$rc" = "$exp" ]; then
    echo "ok   $name (rc=$rc)"
  else
    echo "FAIL $name (rc=$rc, beklenen $exp)"; fail=$((fail + 1))
  fi
}

# The real files must pass. If this goes red a race invocation has lost its
# timeout for real, and the guard is doing its job.
t "gercek workflow'lar temiz" 0 "$ROOT/.github/workflows"
t "gercek Makefile temiz" 0 "$ROOT/Makefile"

# MUST GO RED: the bare invocation this guard was written for.
cat > "$WORK/bare.yml" <<'EOF'
jobs:
  race:
    steps:
      - run: go test -race ./...
EOF
t "timeout'suz -race yakalanir" 1 "$WORK/bare.yml"

# GREEN: both spellings of the flag.
cat > "$WORK/ok.yml" <<'EOF'
jobs:
  race:
    steps:
      - run: go test -race -timeout 20m ./...
      - run: go test -v -race -timeout=25m ./internal/...
EOF
t "iki yazim da gecerli" 0 "$WORK/ok.yml"

# MUST GO RED: split over a continuation, with the timeout nowhere in it. The
# first line alone reads like a complete, unremarkable command.
cat > "$WORK/cont.yml" <<'EOF'
jobs:
  race:
    steps:
      - run: |
          go test -race \
            -coverprofile=cover.out \
            ./...
EOF
t "devam satirinda eksik timeout yakalanir" 1 "$WORK/cont.yml"

# GREEN: the same continuation with the flag on a later line. Judging line by
# line would call this red, which is the false positive that gets a guard
# deleted.
cat > "$WORK/cont-ok.yml" <<'EOF'
jobs:
  race:
    steps:
      - run: |
          go test -race \
            -timeout 20m \
            ./...
EOF
t "devam satirindaki timeout sayilir" 0 "$WORK/cont-ok.yml"

# GREEN: prose about the rule is not an invocation of it. A commented example
# must neither trip the rule nor satisfy it -- so this file has to pass on its
# second line alone.
cat > "$WORK/prose.yml" <<'EOF'
jobs:
  race:
    steps:
      # Was `go test -race ./...` until the ten-minute default bit us.
      - run: go test -race -timeout 20m ./...
EOF
t "yorumdaki ornek kural tetiklemez" 0 "$WORK/prose.yml"

# GREEN: a test run without -race keeps Go's default, and that is fine -- the
# rule is about the race detector's cost, not about timeouts in general. The
# race line keeps the guard's subject alive.
cat > "$WORK/norace.yml" <<'EOF'
jobs:
  unit:
    steps:
      - run: go test ./...
  race:
    steps:
      - run: go test -race -timeout 20m ./...
EOF
t "-race olmayan calistirma muaf" 0 "$WORK/norace.yml"

# MUST GO RED: nothing here runs the race detector, so the guard has lost its
# subject. A guard silently watching nothing is worse than no guard.
cat > "$WORK/nothing.yml" <<'EOF'
jobs:
  lint:
    steps:
      - run: go vet ./...
EOF
t "konusu kalmayan guard kirmizi" 1 "$WORK/nothing.yml"

echo
if [ "$fail" -eq 0 ]; then
  echo "check-race-timeout.test.sh: tum durumlar gecti"
else
  echo "check-race-timeout.test.sh: $fail durum basarisiz"
fi
exit $((fail > 0))
