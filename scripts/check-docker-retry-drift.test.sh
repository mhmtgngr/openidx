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

# --- the bootstrap steps, added after `build (tools)` died at "Booting
# --- builder" on a Docker Hub auth timeout ------------------------------------

setup_fixture() { # name [extra-lines-for-the-retry] -> path
  cat > "$WORK/$1" <<EOF
jobs:
  build:
    steps:
      - name: Set up Docker Buildx
        id: buildx
        continue-on-error: true
        uses: docker/setup-buildx-action@v4

      - name: Set up Docker Buildx (retry)
        if: steps.buildx.outcome == 'failure'
        uses: docker/setup-buildx-action@v4
${2:-}
      - name: Build and push
        uses: docker/build-push-action@v6
        with:
          context: .
EOF
  echo "$WORK/$1"
}

# MUST STAY GREEN: two bare setup steps are identical by having no inputs at
# all. Only build-push-action is required to carry a `with:` block.
t "ciplak iki bootstrap adimi gecerli" 0 "$(setup_fixture setup-ok.yml)"

# MUST GO RED: the retry boots a builder the failed attempt never asked for.
t "bootstrap retry farkli girdi alirsa yakalanir" 1 \
  "$(setup_fixture setup-drift.yml '        with:
          driver: docker
')"

# MUST GO RED: `continue-on-error: true` with nothing reading the outcome is a
# hole, not a retry. Delete the retry step and the job sails past a buildx that
# never came up -- the build then falls back to the default driver and quietly
# produces a single-arch image.
cat > "$WORK/swallowed.yml" <<'EOF'
jobs:
  build:
    steps:
      - name: Set up Docker Buildx
        id: buildx
        continue-on-error: true
        uses: docker/setup-buildx-action@v4

      - name: Build and push
        uses: docker/build-push-action@v6
        with:
          context: .
EOF
t "tolere edilen hata tuketilmezse yakalanir" 1 "$WORK/swallowed.yml"

# MUST STAY GREEN: a step that is advisory ON PURPOSE -- an image scan whose
# findings are reported, not gated -- carries no `id:` and is not flagged.
# Without this case the rule above would push people to delete the guard.
cat > "$WORK/advisory.yml" <<'EOF'
jobs:
  build:
    steps:
      - name: Build and push
        uses: docker/build-push-action@v6
        with:
          context: .

      - name: Trivy image scan
        uses: aquasecurity/trivy-action@master
        continue-on-error: true
        with:
          image-ref: local
EOF
t "id tasimayan tavsiye adimi tetiklemez" 0 "$WORK/advisory.yml"

# MUST STAY GREEN: two JOBS may legitimately set the same action up
# differently -- a retry pair always lives inside one job. Comparing per file
# instead of per job would make this a false positive, and a guard that cries
# wolf on a correct file is one somebody switches off.
cat > "$WORK/twojobs.yml" <<'EOF'
jobs:
  build:
    steps:
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v4
        with:
          driver: docker-container

      - name: Build and push
        uses: docker/build-push-action@v6
        with:
          context: .

  release-tag:
    steps:
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v4
        with:
          driver: docker
EOF
t "farkli isler ayri degerlendirilir" 0 "$WORK/twojobs.yml"

if [ "$fail" -gt 0 ]; then
  echo "DOCKER_RETRY_DRIFT_SELFTEST=FAILED($fail)"; exit 1
fi
echo "DOCKER_RETRY_DRIFT_SELFTEST=OK"
