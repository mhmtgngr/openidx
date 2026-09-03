#!/usr/bin/env bash
# Proves check-docker-retry-drift.sh can actually go RED.
#
# This guard exists to stop a duplicated build block from drifting, so the
# one thing it must never do is pass on a file where the two blocks already
# differ. Every case below is a mutation of a working fixture: change one
# line in the retry block, drop one line, remove the `with:` entirely -- each
# must be caught. The last two cases exist because the first draft of a guard
# like this is usually too eager, and a guard that flags a correct file just
# teaches people to delete it.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-docker-retry-drift.sh"
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

# The real workflow must pass. If this case ever goes red the two blocks in
# docker.yml have drifted for real, and the guard is doing its job.
t "gercek docker.yml temiz" 0 "$ROOT/.github/workflows/docker.yml"

fixture() { # name -> path, writes a two-attempt workflow
  cat > "$WORK/$1" <<'EOF'
jobs:
  build:
    steps:
      - name: Build and push
        id: build
        continue-on-error: true
        uses: docker/build-push-action@v6
        with:
          context: .
          file: Dockerfile
          platforms: linux/amd64
          push: false

      - name: Build and push (retry)
        if: steps.build.outcome == 'failure'
        uses: docker/build-push-action@v6
        with:
          context: .
          file: Dockerfile
          platforms: linux/amd64
          push: false
EOF
  echo "$WORK/$1"
}

t "iki ozdes blok gecerli" 0 "$(fixture ok.yml)"

# MUST GO RED: the retry would build a different platform than the attempt
# that failed -- the exact defect this guard was written for.
f="$(fixture drift.yml)"
python3 - "$f" <<'PY'
import sys
p = sys.argv[1]
src = open(p).read()
head, sep, tail = src.rpartition("platforms: linux/amd64")
open(p, "w").write(head + "platforms: linux/amd64,linux/arm64" + tail)
PY
t "degisen satir yakalanir" 1 "$f"

# MUST GO RED: a key present in one block and missing from the other.
f="$(fixture missing.yml)"
python3 - "$f" <<'PY'
import sys
p = sys.argv[1]
lines = open(p).read().split("\n")
drop = max(i for i, l in enumerate(lines) if l.strip() == "push: false")
del lines[drop]
open(p, "w").write("\n".join(lines))
PY
t "eksik satir yakalanir" 1 "$f"

# MUST GO RED: a build step with no `with:` at all cannot be compared, and
# silently skipping it is how a guard turns into decoration.
cat > "$WORK/nowith.yml" <<'EOF'
jobs:
  build:
    steps:
      - name: Build and push
        uses: docker/build-push-action@v6
        with:
          context: .

      - name: Build and push (retry)
        uses: docker/build-push-action@v6
EOF
t "with bloksuz adim yakalanir" 1 "$WORK/nowith.yml"

# MUST GO RED: pointed at a file with no build step, the guard is watching
# the wrong thing and must say so instead of printing a clean bill of health.
printf 'jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v7\n' > "$WORK/empty.yml"
t "yanlis dosya sessizce gecmez" 1 "$WORK/empty.yml"

# MUST STAY GREEN: only the comments differ. Prose is allowed to diverge;
# behaviour is not.
f="$(fixture comments.yml)"
python3 - "$f" <<'PY'
import sys
p = sys.argv[1]
src = open(p).read()
head, sep, tail = src.rpartition("          context: .")
open(p, "w").write(head + "          # the retry explains itself differently\n" + sep + tail)
PY
t "sadece yorum farki tetiklemez" 0 "$f"

# MUST STAY GREEN: one build step, nothing to compare against. It reports
# that plainly rather than pretending a retry was verified.
cat > "$WORK/single.yml" <<'EOF'
jobs:
  build:
    steps:
      - name: Build and push
        uses: docker/build-push-action@v6
        with:
          context: .
          push: false
EOF
t "tek adim karsilastirilamaz ama kirmizi degil" 0 "$WORK/single.yml"

if [ "$fail" -gt 0 ]; then
  echo "DOCKER_RETRY_DRIFT_SELFTEST=FAILED($fail)"; exit 1
fi
echo "DOCKER_RETRY_DRIFT_SELFTEST=OK"
