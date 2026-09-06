#!/usr/bin/env bash
# Proves check-required-checks.sh can actually go RED.
#
# The defect it guards is a job that quietly sits outside the required set, so
# the one thing this guard must never do is pass on a workflow where that has
# happened. The green cases matter just as much: a guard that fires on a
# correctly declared exemption gets deleted the first time someone needs one.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-required-checks.sh"
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
    echo "FAIL $name (rc=$rc, expected $exp)"; fail=$((fail + 1))
  fi
}

# The repository's own workflow must pass. If this goes red a real job has
# escaped the required set.
t "real ci.yml is clean" 0 "$ROOT/.github/workflows/ci.yml"

write() { # file body...
  cat > "$WORK/$1"
}

write ok.yml <<'EOF'
name: fixture
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  status-check:
    needs: [build]
    runs-on: ubuntu-latest
    steps:
      - run: echo aggregate
EOF
t "every job required passes" 0 "$WORK/ok.yml"

# The real defect: a job nobody aggregates.
write escaped.yml <<'EOF'
name: fixture
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  guard:
    runs-on: ubuntu-latest
    steps:
      - run: echo guard
  status-check:
    needs: [build]
    runs-on: ubuntu-latest
    steps:
      - run: echo aggregate
EOF
t "job outside needs and undeclared is caught" 1 "$WORK/escaped.yml"

# Declared informational, with a reason: allowed.
write exempt.yml <<'EOF'
name: fixture
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  # status-check: informational — posts a comparison comment, does not gate
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - run: echo bench
  status-check:
    needs: [build]
    runs-on: ubuntu-latest
    steps:
      - run: echo aggregate
EOF
t "declared informational with a reason passes" 0 "$WORK/exempt.yml"

# An exemption with no reason is how a required check quietly becomes optional.
write exempt-noreason.yml <<'EOF'
name: fixture
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  # status-check: informational
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - run: echo bench
  status-check:
    needs: [build]
    runs-on: ubuntu-latest
    steps:
      - run: echo aggregate
EOF
t "exemption without a reason is caught" 1 "$WORK/exempt-noreason.yml"

# Both required and exempt is a contradiction, and hides which one was meant.
write both.yml <<'EOF'
name: fixture
on: push
jobs:
  # status-check: informational — but it is also in needs
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  status-check:
    needs: [build]
    runs-on: ubuntu-latest
    steps:
      - run: echo aggregate
EOF
t "required and informational at once is caught" 1 "$WORK/both.yml"

# needs naming a job that does not exist would make the aggregate unrunnable.
write ghost-need.yml <<'EOF'
name: fixture
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
  status-check:
    needs: [build, deleted-job]
    runs-on: ubuntu-latest
    steps:
      - run: echo aggregate
EOF
t "needs naming a missing job is caught" 1 "$WORK/ghost-need.yml"

# No aggregate at all: nothing is required.
write no-aggregate.yml <<'EOF'
name: fixture
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
EOF
t "workflow with no status-check is caught" 1 "$WORK/no-aggregate.yml"

if [ "$fail" -ne 0 ]; then
  echo "$fail case(s) failed"
  exit 1
fi
echo "all cases passed"
