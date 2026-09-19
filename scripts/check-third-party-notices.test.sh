#!/usr/bin/env bash
# Proves check-third-party-notices.sh can go RED, and stays green on a file
# that matches the module graph. A guard that cannot fail is a green tick that
# means nothing, so the test drives the script with a stub go-licenses whose
# answer it controls, and demands a red for each way the file can be wrong.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-third-party-notices.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0

# The stub answers `report ./...` with whatever STUB_CSV holds and exits STUB_RC.
cat >"$WORK/go-licenses" <<'STUB'
#!/usr/bin/env bash
[ "$1" = "report" ] || { echo "stub: unexpected arguments: $*" >&2; exit 9; }
cat "$STUB_CSV"
exit "${STUB_RC:-0}"
STUB
chmod +x "$WORK/go-licenses"
export GO_LICENSES="$WORK/go-licenses" NOTICES_FILE="$WORK/notices.md"

cat >"$WORK/full.csv" <<'CSV'
github.com/openidx/openidx,https://github.com/openidx/openidx/blob/HEAD/LICENSE,Apache-2.0
github.com/openidx/openidx/web/admin-console/node_modules/flatted/golang/pkg/flatted,https://github.com/openidx/openidx/blob/HEAD/web/admin-console/node_modules/flatted/LICENSE,ISC
github.com/zzz/last,https://github.com/zzz/last/blob/v1.0.0/LICENSE,MIT
github.com/aaa/first,https://github.com/aaa/first/blob/v2.3.4/LICENSE,Apache-2.0
CSV
grep -v 'zzz/last' "$WORK/full.csv" >"$WORK/dropped.csv"
: >"$WORK/empty.csv"

t() { # name expected_rc [env assignments...] -- args
	local name="$1" exp="$2"; shift 2
	local envs=()
	while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=("$1"); shift; done
	[ "${1:-}" = "--" ] && shift
	env "${envs[@]}" bash "$CHECK" "$@" >"$WORK/out" 2>&1
	local rc=$?
	if [ "$rc" = "$exp" ]; then
		echo "ok   $name (rc=$rc)"
	else
		echo "FAIL $name (rc=$rc, expected $exp)"; sed 's/^/      /' "$WORK/out"; fail=$((fail+1))
	fi
}

# --write generates the file; the checker then agrees with itself.
t "write generates the file" 0 STUB_CSV="$WORK/full.csv" -- --write
if grep -q 'github.com/aaa/first' "$NOTICES_FILE" && grep -q 'github.com/zzz/last' "$NOTICES_FILE"; then
	echo "ok   both third-party modules are listed"
else
	echo "FAIL a third-party module is missing from the generated file"; fail=$((fail+1))
fi
if grep -q 'openidx/openidx' "$NOTICES_FILE"; then
	echo "FAIL our own module (and the node_modules Go package under it) must not be listed as third-party"; fail=$((fail+1))
else
	echo "ok   our own module is excluded"
fi
if [ "$(grep -n 'aaa/first' "$NOTICES_FILE" | cut -d: -f1)" -lt "$(grep -n 'zzz/last' "$NOTICES_FILE" | cut -d: -f1)" ]; then
	echo "ok   entries are sorted by module path"
else
	echo "FAIL entries are not sorted"; fail=$((fail+1))
fi
if grep -q '^| MIT | 1 |$' "$NOTICES_FILE" && grep -q '^| Apache-2.0 | 1 |$' "$NOTICES_FILE"; then
	echo "ok   the summary counts each licence"
else
	echo "FAIL the summary does not count the licences"; fail=$((fail+1))
fi
t "a matching file passes (control)" 0 STUB_CSV="$WORK/full.csv" --

# MUST GO RED: the module graph changed (a dependency left) and the file did not.
t "a dependency removed from the graph makes the file stale" 1 STUB_CSV="$WORK/dropped.csv" --
# MUST GO RED: the file was edited by hand.
cp "$NOTICES_FILE" "$WORK/pristine.md"
echo "| [github.com/hand/edit](https://pkg.go.dev/github.com/hand/edit?tab=licenses) | MIT |" >>"$NOTICES_FILE"
t "a hand edit to the file is caught" 1 STUB_CSV="$WORK/full.csv" --
cp "$WORK/pristine.md" "$NOTICES_FILE"
# MUST GO RED, as a tool failure and not as a pass: no modules is not a clean bill.
t "an empty report is a failure, not a pass" 2 STUB_CSV="$WORK/empty.csv" --
t "a failing go-licenses is a failure, not a pass" 2 STUB_CSV="$WORK/full.csv" STUB_RC=1 --
# A missing file is a red with the fix named, not a crash.
rm -f "$NOTICES_FILE"
t "a missing file is red" 1 STUB_CSV="$WORK/full.csv" --
t "an unknown flag is refused" 2 STUB_CSV="$WORK/full.csv" -- --bogus

if [ "$fail" -ne 0 ]; then
	echo "check-third-party-notices.test: $fail case(s) FAILED"; exit 1
fi
echo "check-third-party-notices.test: all cases pass — the guard goes red on a stale, hand-edited or missing file and on a tool that answers nothing"
