#!/usr/bin/env bash
# run-display-enforcement-tests.sh — run the tests the display = enforcement
# table names, and write the run report.
#
# WHY: docs/evidence/display-equals-enforcement.md asks for its table to be
# verified at least once per release, and nothing ran it per release. This is
# that run. .github/workflows/display-equals-enforcement.yml calls it on every
# release, and it is the same command on a workstation.
#
# THE LIST COMES FROM THE DOC. check-display-enforcement-tests.sh --map reads
# the table's "Automated checks" rows and says which package holds each test.
# This script keeps no list of its own, and it runs nothing when a name in the
# table does not resolve.
#
# A SKIP IS A FAILURE HERE. Every one of these tests skips when it has no
# database, so a run that "passes" may have verified nothing. Each named test
# must print its own `--- PASS` line. Anything else fails the run: `--- FAIL`,
# `--- SKIP`, a skipped subtest, no result line at all, or a `go test` that
# exits non-zero.
#
# ONE PACKAGE AT A TIME. The tests drop and rebuild the public schema of the
# database OPENIDX_TEST_DATABASE_URL names, so two packages at once would
# destroy each other's tables. Point it at a scratch database. It is required,
# because the report names the server the tests ran against.
#
# Tests under test/integration are not run here: they need the stack the
# integration job starts. The report lists them as running there.
#
# Usage: run-display-enforcement-tests.sh <output-dir>
#   Writes <output-dir>/report.md, and one `go test -v` log per package under
#   <output-dir>/logs/. Exits 0 only if every test it runs passes.
#
# EVIDENCE_REF names the ref under test in the report (default: the checked-out
# branch). The GitHub Actions variables fill in the runner and the run link.
# OPENIDX_EVIDENCE_ROOT overrides the tree (used by the .test.sh).
set -uo pipefail

ROOT="${OPENIDX_EVIDENCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CHECK="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-display-enforcement-tests.sh"
OUT="${1:-}"

if [ -z "$OUT" ]; then
  echo "usage: run-display-enforcement-tests.sh <output-dir>" >&2
  exit 2
fi
if [ -z "${OPENIDX_TEST_DATABASE_URL:-}" ]; then
  echo "run-display-enforcement-tests: OPENIDX_TEST_DATABASE_URL is not set." >&2
  echo "  Point it at a scratch database: the tests drop and rebuild its public schema." >&2
  exit 2
fi
mkdir -p "$OUT/logs" || exit 2
OUT="$(cd "$OUT" && pwd)"

# ---- what to run: the table, resolved --------------------------------------
if ! map="$(OPENIDX_EVIDENCE_ROOT="$ROOT" bash "$CHECK" --map)"; then
  echo "run-display-enforcement-tests: the table does not resolve, so nothing was run" >&2
  exit 1
fi

row_pkg=() row_test=() row_how=() row_grant=()
pkgs=()
declare -A pkg_tests=()
while IFS=$'\t' read -r pkg test how grant; do
  [ -n "$pkg" ] || continue
  row_pkg+=("$pkg") row_test+=("$test") row_how+=("$how") row_grant+=("$grant")
  [ "$how" = run ] || continue
  if [ -z "${pkg_tests[$pkg]+set}" ]; then
    pkgs+=("$pkg")
    pkg_tests[$pkg]=""
  fi
  case " ${pkg_tests[$pkg]} " in
    *" $test "*) ;;
    *) pkg_tests[$pkg]="${pkg_tests[$pkg]:+${pkg_tests[$pkg]} }$test" ;;
  esac
done <<<"$map"

# ---- what it runs on ---------------------------------------------------------
if command -v psql >/dev/null 2>&1; then
  if ! pg_version="$(psql "$OPENIDX_TEST_DATABASE_URL" -XAtqc 'SHOW server_version' 2>&1)"; then
    echo "run-display-enforcement-tests: cannot reach the database OPENIDX_TEST_DATABASE_URL names:" >&2
    echo "  $pg_version" >&2
    exit 2
  fi
else
  pg_version="unknown (psql is not installed)"
fi
go_version="$(go version 2>/dev/null)" || go_version="unknown"
go_version="${go_version#go version }"
commit="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null)" || commit="unknown"
ref="${EVIDENCE_REF:-}"
if [ -z "$ref" ]; then
  ref="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null)" || ref="unknown"
fi
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  runner="GitHub Actions, ${RUNNER_ENVIRONMENT:-unknown} runner ${RUNNER_NAME:-unknown}, image ${ImageOS:-unknown} ${ImageVersion:-unknown}, ${RUNNER_OS:-unknown} ${RUNNER_ARCH:-unknown}"
else
  runner="local, $(uname -srm)"
fi
run_url=""
if [ -n "${GITHUB_SERVER_URL:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ] && [ -n "${GITHUB_RUN_ID:-}" ]; then
  run_url="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
fi

# ---- run, one package at a time ---------------------------------------------
cd "$ROOT" || exit 2
declare -A result=()
bad_exit=()
for pkg in "${pkgs[@]}"; do
  read -r -a names <<<"${pkg_tests[$pkg]}"
  regex="^($(IFS='|'; echo "${names[*]}"))\$"
  log="$OUT/logs/${pkg//\//_}.log"
  [ "${GITHUB_ACTIONS:-}" = true ] && echo "::group::go test ./$pkg"
  echo "run-display-enforcement-tests: go test -count=1 -v -run '$regex' ./$pkg"
  go test -count=1 -v -run "$regex" "./$pkg" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  [ "${GITHUB_ACTIONS:-}" = true ] && echo "::endgroup::"
  [ "$rc" -eq 0 ] || bad_exit+=("go test ./$pkg exited $rc")

  # The name is followed by " (" on a result line, so a test renamed to
  # "<name>X" cannot pass for <name>, and a subtest ("<name>/...") is told
  # apart from its parent.
  for name in "${names[@]}"; do
    if grep -qE -- "--- FAIL: $name \(" "$log"; then
      r="FAIL"
    elif grep -qE -- "--- SKIP: $name \(" "$log"; then
      r="SKIP"
    elif grep -qE -- "--- PASS: $name \(" "$log"; then
      if grep -qE -- "--- SKIP: $name/" "$log"; then
        r="SKIP in a subtest"
      else
        r="PASS"
      fi
    else
      r="did not run"
    fi
    result[$pkg/$name]="$r"
  done
done

# ---- the report --------------------------------------------------------------
ran=0 elsewhere=0
failures=()
declare -A counted=()
for i in "${!row_test[@]}"; do
  key="${row_pkg[$i]}/${row_test[$i]}"
  [ -z "${counted[$key]+set}" ] || continue
  counted[$key]=1
  if [ "${row_how[$i]}" = run ]; then
    ran=$((ran + 1))
    if [ "${result[$key]:-did not run}" != PASS ]; then
      failures+=("${row_test[$i]} (${result[$key]:-did not run})")
    fi
  else
    elsewhere=$((elsewhere + 1))
  fi
done

# join <separator> <item>... prints the items with the separator between them.
join() {
  local sep="$1" out="" item
  shift
  for item in "$@"; do
    out="${out:+$out$sep}$item"
  done
  printf '%s' "$out"
}

ok=1
if [ "$ran" -eq 0 ]; then
  ok=0
  verdict="FAILED: no test was run, so nothing was verified."
elif [ "${#failures[@]}" -gt 0 ]; then
  ok=0
  verdict="FAILED: ${#failures[@]} of $ran tests did not pass: $(join ', ' "${failures[@]}")."
elif [ "${#bad_exit[@]}" -gt 0 ]; then
  ok=0
  verdict="FAILED: every named test passed, but $(join ', ' "${bad_exit[@]}")."
else
  verdict="Passed: all $ran tests run here passed."
fi
if [ "$elsewhere" -gt 0 ]; then
  verdict="$verdict $elsewhere run in the integration job, not here."
fi

{
  echo "# Display = enforcement: automated checks"
  echo
  echo "- **Date:** $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "- **Ref:** $ref"
  echo "- **Commit:** \`$commit\`"
  echo "- **Runner:** $runner"
  echo "- **Go:** $go_version"
  echo "- **Postgres:** $pg_version"
  if [ -n "$run_url" ]; then
    echo "- **Run:** $run_url"
  fi
  echo
  echo "These are the tests named in the \"Automated checks\" table of"
  echo "\`docs/evidence/display-equals-enforcement.md\` at this commit. They ran one"
  echo "package at a time against a migrated Postgres. A test that fails, skips or"
  echo "does not run fails the run."
  echo
  echo "| Grant | Test | Package | Result |"
  echo "|---|---|---|---|"
  for i in "${!row_test[@]}"; do
    if [ "${row_how[$i]}" = run ]; then
      r="${result[${row_pkg[$i]}/${row_test[$i]}]:-did not run}"
    else
      r="runs in the integration job"
    fi
    echo "| ${row_grant[$i]} | \`${row_test[$i]}\` | \`${row_pkg[$i]}\` | $r |"
  done
  echo
  echo "**$verdict**"
} >"$OUT/report.md"

echo
echo "run-display-enforcement-tests: $verdict"
echo "run-display-enforcement-tests: report at $OUT/report.md"
[ "$ok" -eq 1 ]
