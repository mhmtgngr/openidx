#!/usr/bin/env bash
# Guard: a database-backed test must have a path CI can actually take.
#
# WHY: ci.yml's unit matrix runs each package with a live Postgres attached and
# exports it as DATABASE_URL. It does not set OPENIDX_TEST_DATABASE_URL, which
# is the developer escape hatch for "I have Postgres but no Docker daemon". A
# setup helper that reads only that variable and calls t.Skip when it is unset
# therefore runs NOWHERE:
#
#   * not in CI, because the variable is unset there;
#   * not on a workstation, unless somebody exports it by hand.
#
# The suite still compiles, still appears in the package, and the job still
# reports success. Two suites were in that state when this guard was written --
# internal/oauth's SAML service-provider TENANT ISOLATION tests, and the v172
# migration test that proves per-organization replay protection. Both had been
# green-by-skipping since the day they were merged.
#
# That is this repository's organising defect class wearing a test's clothes: a
# control that displays without enforcing. A skipped test displays as a pass.
#
# So every function that gates on OPENIDX_TEST_DATABASE_URL must also be able to
# get a database without it -- by starting a container, by reading the
# DATABASE_URL that CI does set, or by delegating to a helper in the same
# directory that does one of those.
#
# Usage: check-test-reachability.sh [--enforce]
#   --enforce  exit non-zero on a finding (the CI mode; the default too)
#
# Escape hatch: put `//testreach:ignore <reason>` inside the function. The
# reason is mandatory -- a bare marker is itself a finding, for the same reason
# the orgscope lint demands one.
#
# OPENIDX_TESTREACH_ROOT overrides the tree that is scanned (used by .test.sh).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN="${OPENIDX_TESTREACH_ROOT:-$ROOT}"

GATE_VAR='Getenv("OPENIDX_TEST_DATABASE_URL")'

fail=0
finding() {
  printf 'check-test-reachability: %s\n' "$1" >&2
  fail=1
}

# Split every _test.go into top-level function blocks and emit one record per
# function:
#   <file> <TAB> <line> <TAB> <name> <TAB> <marker> <TAB> <body on one line>
#
# Splitting on a column-0 `func` is exact in gofmt'd Go, and every file here is
# gofmt'd (ci.yml's lint job enforces it), so no brace counting is needed.
#
# Two details the guard's own self-test caught:
#
#   * The file is captured where the function STARTS, not where it is flushed.
#     Flushing at the next file's first line reads FILENAME as that next file,
#     so the last function of every file was reported against its neighbour --
#     which made a cross-package delegation look same-package and pass.
#   * The marker's reason is the rest of ITS line, not the rest of the body.
#     Taking the body meant a bare //testreach:ignore always looked like it
#     carried a reason, because the code beneath it followed the marker.
scan_functions() {
  find "$SCAN" -name '*_test.go' \
    -not -path '*/vendor/*' -not -path '*/third_party/*' -not -path '*/node_modules/*' \
    -print0 |
    sort -z |
    xargs -0 -r awk '
      function flush() {
        if (fname != "") printf "%s\t%d\t%s\t%s\t%s\n", ffile, fline, fname, mark, body
        fname = ""; body = ""; mark = "-"
      }
      FNR == 1 { flush() }
      /^func / {
        flush()
        line = $0
        # func (r Recv) Name( … | func Name( …
        sub(/^func +(\([^)]*\) +)?/, "", line)
        n = index(line, "(")
        fname = (n > 1) ? substr(line, 1, n - 1) : "?"
        fline = FNR
        ffile = FILENAME
      }
      {
        i = index($0, "//testreach:ignore")
        if (i > 0) {
          reason = substr($0, i + length("//testreach:ignore"))
          gsub(/^[ \t]+|[ \t]+$/, "", reason)
          mark = (reason == "") ? "!BARE!" : reason
        }
        body = body " " $0
      }
      END { flush() }
    '
}

# A function reaches a database without the variable when it starts a container,
# reads the DATABASE_URL that CI supplies, or is handed a pool it did not open.
# Matched as call syntax, never as prose: the helper this guard was written for
# carried a comment saying it "does NOT use testcontainers", and a word-level
# grep would have read that as a fallback.
is_self_sufficient() {
  case "$1" in
    *"testcontainers.GenericContainer("*) return 0 ;;
    *"testsupport.RunOrSkip("*) return 0 ;;
    *'Getenv("DATABASE_URL")'*) return 0 ;;
  esac
  return 1
}

records="$(scan_functions)"
if [ -z "$records" ]; then
  echo "check-test-reachability: no _test.go files under $SCAN" >&2
  exit 1
fi

# Pass 1: which functions can stand on their own, keyed by directory. A helper
# is only reachable from tests in its own package, so the directory is the scope.
declare -A self_sufficient=()
while IFS=$'\t' read -r file line name marker body; do
  [ -n "${name:-}" ] || continue
  if is_self_sufficient "$body"; then
    self_sufficient["$(dirname "$file")|$name"]=1
  fi
done <<<"$records"

# Pass 2: every function gated on the variable must be self-sufficient, or call
# something in its own directory that is. One level of delegation is enough for
# every helper in this tree and keeps the guard readable; a deeper chain that
# trips this is told to say so with the marker.
checked=0
while IFS=$'\t' read -r file line name marker body; do
  case "$body" in *"$GATE_VAR"*) ;; *) continue ;; esac
  checked=$((checked + 1))

  if [ "$marker" = "!BARE!" ]; then
    finding "$file:$line: $name carries a bare //testreach:ignore; the marker needs a reason"
    continue
  elif [ "$marker" != "-" ]; then
    continue
  fi

  if is_self_sufficient "$body"; then
    continue
  fi

  delegates=0
  dir="$(dirname "$file")"
  for key in "${!self_sufficient[@]}"; do
    [ "${key%%|*}" = "$dir" ] || continue
    callee="${key##*|}"
    [ "$callee" = "$name" ] && continue
    case "$body" in *"$callee("*) delegates=1; break ;; esac
  done

  if [ "$delegates" -eq 0 ]; then
    finding "$file:$line: $name skips unless OPENIDX_TEST_DATABASE_URL is set, and ci.yml never sets it — this test runs nowhere. Start a container (testsupport.RunOrSkip), read DATABASE_URL, or delegate to a helper in this package that does."
  fi
done <<<"$records"

if [ "$fail" -eq 0 ]; then
  echo "check-test-reachability: ok — $checked database-gated test helper(s), every one reachable from CI"
fi
exit "$fail"
