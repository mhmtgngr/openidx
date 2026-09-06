#!/usr/bin/env bash
# Proves check-workflows-parse.sh can actually go RED.
#
# The failure it exists to catch is invisible by construction: a workflow that
# does not parse takes itself out of CI, so nothing but this guard is left to
# report it. A guard for an invisible failure that silently passes is worse
# than no guard, hence the mutations below -- each is a real shape the file can
# take, and each must be caught. The last cases are the other half: a guard
# that flags a correct workflow gets deleted by the next person in a hurry.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-workflows-parse.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0

t() { # name expected_rc target
  local name="$1" exp="$2" target="$3"
  bash "$CHECK" "$target" >/dev/null 2>&1
  local rc=$?
  if [ "$rc" = "$exp" ]; then
    echo "ok   $name (rc=$rc)"
  else
    echo "FAIL $name (rc=$rc, expected $exp)"; fail=$((fail + 1))
  fi
}

# The repository's own workflows must pass. If this goes red, one of them is
# genuinely unrunnable and the guard is doing its job.
t "real .github/workflows is clean" 0 "$ROOT/.github/workflows"

# A valid workflow, as the baseline every mutation below starts from.
cat > "$WORK/good.yml" <<'EOF'
name: fixture
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Say something
        run: |
          echo "TODO: a colon inside a block scalar is fine"
EOF
t "valid workflow passes" 0 "$WORK/good.yml"

# The exact defect this guard was written for: `run: echo "TODO: ..."`. A
# plain YAML scalar may not contain ": ", and GitHub answers with a failed run
# carrying zero jobs.
cat > "$WORK/plain-scalar-colon.yml" <<'EOF'
name: fixture
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Say something
        run: echo "TODO: fetch the thing"
EOF
t "plain scalar with a colon is caught" 1 "$WORK/plain-scalar-colon.yml"

# Indentation damage — the commonest way a hand-edited workflow breaks.
cat > "$WORK/bad-indent.yml" <<'EOF'
name: fixture
on: push
jobs:
  build:
    runs-on: ubuntu-latest
   steps:
      - run: echo hi
EOF
t "broken indentation is caught" 1 "$WORK/bad-indent.yml"

# No trigger: the file parses, and GitHub will never run it.
cat > "$WORK/no-trigger.yml" <<'EOF'
name: fixture
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
EOF
t "missing on: trigger is caught" 1 "$WORK/no-trigger.yml"

# No jobs: the same dead check as an unparseable file, reached differently.
cat > "$WORK/no-jobs.yml" <<'EOF'
name: fixture
on: push
jobs: {}
EOF
t "empty jobs: is caught" 1 "$WORK/no-jobs.yml"

# `on` as a bare key resolves to the boolean True under PyYAML's 1.1 rules.
# If the guard only looked for the string "on", every workflow in this repo
# would be reported as untriggered — a false positive that would retire it.
cat > "$WORK/bare-on.yml" <<'EOF'
name: fixture
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
EOF
t "bare on: key is accepted (PyYAML resolves it to True)" 0 "$WORK/bare-on.yml"

# Quoted "on" is equally legal and must not be reported either.
cat > "$WORK/quoted-on.yml" <<'EOF'
name: fixture
"on":
  workflow_dispatch:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
EOF
t "quoted \"on\": key is accepted" 0 "$WORK/quoted-on.yml"

if [ "$fail" -ne 0 ]; then
  echo "$fail case(s) failed"
  exit 1
fi
echo "all cases passed"
