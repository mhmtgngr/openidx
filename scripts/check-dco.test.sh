#!/usr/bin/env bash
# Proves check-dco.sh can go RED on a commit without a sign-off, and stays
# green on signed commits, on merge commits, and on an empty range. Built on a
# throwaway repository so the test never depends on this repository's history.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/check-dco.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0
export REPO="$WORK/repo"

g() { git -C "$REPO" -c user.name=Test -c user.email=test@example.invalid -c commit.gpgsign=false "$@"; }
commit() { # file message...
	echo "$RANDOM" >"$REPO/$1"; g add "$1" >/dev/null
	shift; g commit -q "$@"
}

t() { # name expected_rc base head
	local name="$1" exp="$2"
	bash "$CHECK" "$3" "$4" >"$WORK/out" 2>&1
	local rc=$?
	if [ "$rc" = "$exp" ]; then
		echo "ok   $name (rc=$rc)"
	else
		echo "FAIL $name (rc=$rc, expected $exp)"; sed 's/^/      /' "$WORK/out"; fail=$((fail+1))
	fi
}

git init -q -b main "$REPO"
commit base.txt -m "base" -s
g branch signed
g branch unsigned
g branch mixed

g checkout -q signed
commit a.txt -m "signed one" -s
commit b.txt -m "signed two" -s
t "two signed commits pass" 0 main signed

g checkout -q unsigned
commit c.txt -m "no sign-off here"
t "a commit without a sign-off is red" 1 main unsigned
grep -q "no Signed-off-by: .* no sign-off here" "$WORK/out" && echo "ok   the offending commit is named" || { echo "FAIL the offending commit is not named"; fail=$((fail+1)); }

# A sign-off without an address is not a sign-off.
g checkout -q mixed
commit d.txt -m "$(printf 'half a sign-off\n\nSigned-off-by: Someone')"
t "a Signed-off-by with no email is red" 1 main mixed

# A merge commit carries no sign-off and is not asked for one; the branch
# commits under it still are.
g checkout -q main
commit m.txt -m "main moved on" -s
g checkout -q signed
g merge -q --no-ff --no-edit main >/dev/null 2>&1
t "an unsigned merge commit over signed commits passes" 0 main signed
# ...and a merge does not launder an unsigned commit.
g checkout -q unsigned
g merge -q --no-ff --no-edit main >/dev/null 2>&1
t "a merge does not launder the unsigned commit under it" 1 main unsigned

# The range is bounded by the merge base: main's own new commit is not re-checked
# from the branch's side even when it lacks a sign-off.
g checkout -q main
commit n.txt -m "main again, unsigned"
g checkout -q signed
g merge -q --no-ff --no-edit main >/dev/null 2>&1
t "commits merged in from the base are not this branch's to sign" 0 main signed

t "an empty range passes" 0 main main
t "an unknown revision is a usage error, not a pass" 2 main no-such-branch
bash "$CHECK" main >/dev/null 2>&1; [ $? -eq 2 ] && echo "ok   missing arguments are refused (rc=2)" || { echo "FAIL missing arguments were not refused"; fail=$((fail+1)); }

if [ "$fail" -ne 0 ]; then
	echo "check-dco.test: $fail case(s) FAILED"; exit 1
fi
echo "check-dco.test: all cases pass — the guard goes red on an unsigned commit and stays green on signed, merged and empty ranges"
