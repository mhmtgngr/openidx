#!/usr/bin/env bash
# Self-test for check-keyboard-reachable.sh. A guard that cannot go red is
# worse than no guard: it reads as coverage and provides none. Every case here
# mutates a fixture and demands the outcome, including the two parser bugs the
# first version of the checker actually had -- it truncated attributes at the
# `>` inside `=>`, and it read a doc comment quoting `<div onClick>` as code.
set -uo pipefail
cd "$(dirname "$0")/.."
CHECK="scripts/check-keyboard-reachable.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $1"; exit 1; }

# Runs the checker over a fixture dir; echoes the offender count.
count_for() {
  SH_SRC_DIR="$1" bash "$CHECK" 2>/dev/null \
    | sed -n 's/^keyboard-unreachable offenders: //p'
}

mk() { mkdir -p "$(dirname "$1")"; cat > "$1"; }

# --- 1. a bare click-only div is an offender --------------------------------
D="$TMP/c1"; mk "$D/a.tsx" <<'EOF'
export function A() {
  return <div onClick={() => pick(1)}>row</div>
}
EOF
[ "$(count_for "$D")" = "1" ] || fail "1: click-only div should be an offender"

# --- 2. the full ARIA substitute passes -------------------------------------
D="$TMP/c2"; mk "$D/a.tsx" <<'EOF'
export function A() {
  return (
    <div role="button" tabIndex={0} onClick={pick} onKeyDown={onKey}>row</div>
  )
}
EOF
[ "$(count_for "$D")" = "0" ] || fail "2: role+tabIndex+onKeyDown should pass"

# --- 3. PARSER BUG ONE: attributes after an arrow function must still be seen.
# `onClick={() => pick()}` contains a `>`. A checker that ends the tag at the
# first `>` never sees the role/tabIndex/onKeyDown that follow, and reports a
# correctly-built control as broken.
D="$TMP/c3"; mk "$D/a.tsx" <<'EOF'
export function A() {
  return (
    <div
      onClick={() => pick(1)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === 'Enter') { pick(1) } }}
    >
      row
    </div>
  )
}
EOF
[ "$(count_for "$D")" = "0" ] || fail "3: attributes after an arrow fn must be seen"

# --- 4. PARSER BUG TWO: prose is not code -----------------------------------
# A comment that quotes the defect it is describing must not be reported.
D="$TMP/c4"; mk "$D/a.tsx" <<'EOF'
/**
 * This used to be a bare `<div onClick>`, which no keyboard could reach.
 */
// Another mention of <div onClick={x}> in a line comment.
export function A() {
  return <button onClick={pick}>row</button>
}
EOF
[ "$(count_for "$D")" = "0" ] || fail "4: comments must not be scanned as code"

# --- 5. a URL in a string is not a comment ----------------------------------
# The comment stripper must respect quotes, or it blanks the rest of the file
# from `https://` onwards and silently stops finding offenders after it.
D="$TMP/c5"; mk "$D/a.tsx" <<'EOF'
export function A() {
  const href = "https://example.test/docs"
  return <div onClick={() => open(href)}>row</div>
}
EOF
[ "$(count_for "$D")" = "1" ] || fail "5: a // inside a string must not blank the file"

# --- 6. aria-hidden declares a deliberate non-stop --------------------------
D="$TMP/c6"; mk "$D/a.tsx" <<'EOF'
export function A() {
  return <div className="scrim" onClick={close} aria-hidden="true" />
}
EOF
[ "$(count_for "$D")" = "0" ] || fail "6: aria-hidden scrim should pass"

# --- 7. natively interactive elements are never offenders -------------------
D="$TMP/c7"; mk "$D/a.tsx" <<'EOF'
export function A() {
  return (
    <>
      <button onClick={pick}>go</button>
      <a href="/x" onClick={pick}>go</a>
      <input onClick={pick} />
      <summary onClick={pick}>go</summary>
    </>
  )
}
EOF
[ "$(count_for "$D")" = "0" ] || fail "7: native controls should pass"

# --- 8. a partial ARIA pattern is still an offender -------------------------
# tabIndex without a key handler is the most tempting half-fix: the control
# takes focus and then does nothing when you press Enter.
D="$TMP/c8"; mk "$D/a.tsx" <<'EOF'
export function A() {
  return <div role="button" tabIndex={0} onClick={pick}>row</div>
}
EOF
[ "$(count_for "$D")" = "1" ] || fail "8: tabIndex without onKeyDown should be an offender"

# --- 9. test files are excluded ---------------------------------------------
D="$TMP/c9"; mk "$D/a.test.tsx" <<'EOF'
it('x', () => { render(<div onClick={pick}>row</div>) })
EOF
[ "$(count_for "$D")" = "0" ] || fail "9: .test.tsx should be skipped"

# --- 10. --enforce exits non-zero, the default does not ---------------------
D="$TMP/c10"; mk "$D/a.tsx" <<'EOF'
export function A() { return <div onClick={pick}>row</div> }
EOF
SH_SRC_DIR="$D" bash "$CHECK" >/dev/null 2>&1 \
  || fail "10: default mode must warn, not fail"
SH_SRC_DIR="$D" bash "$CHECK" --enforce >/dev/null 2>&1 \
  && fail "10: --enforce must exit non-zero when there are offenders"

# --- 11. a missing source dir is an error, not a silent pass ----------------
SH_SRC_DIR="$TMP/does-not-exist" bash "$CHECK" --enforce >/dev/null 2>&1
[ "$?" = "2" ] || fail "11: a missing source dir must exit 2"

# --- 12. the real tree passes ------------------------------------------------
bash "$CHECK" --enforce >/dev/null 2>&1 \
  || fail "12: the checked-in tree must have no offenders"

echo "KEYBOARD_REACHABLE_SELFTEST=OK"
