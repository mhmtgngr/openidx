#!/usr/bin/env bash
# Self-test for check-control-names.sh. A guard that cannot go red is worse
# than no guard, so every accept and every reject is exercised against a
# fixture -- including the three parser traps that produced real false results
# in this repo's other JSX guards.
set -uo pipefail
cd "$(dirname "$0")/.."
GUARD="scripts/check-control-names.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $1"; exit 1; }

mk() { mkdir -p "$TMP/src"; printf '%s' "$2" > "$TMP/src/$1"; }
run() { SH_SRC_DIR="$TMP/src" bash "$GUARD" 2>&1; }
count() { run | sed -n 's/^unnamed-controls offenders: //p'; }
reset() { rm -rf "$TMP/src"; mkdir -p "$TMP/src"; }

# --- 1. the real tree is clean --------------------------------------------
bash "$GUARD" --enforce >"$TMP/real.out" 2>&1 \
  || { cat "$TMP/real.out"; fail "1: the guard is not green on the real source tree"; }

# --- 2. an unnamed control is an offender ---------------------------------
reset
mk a.tsx '
export function A() {
  return <div><Input value={x} onChange={f} /></div>
}
'
[ "$(count)" = "1" ] || fail "2: an Input with no name was not reported ($(count))"

# --- 3. aria-label names it -----------------------------------------------
reset
mk a.tsx '
export function A() {
  return <div><Input aria-label={t("k")} value={x} onChange={f} /></div>
}
'
[ "$(count)" = "0" ] || fail "3: aria-label was not accepted"

# --- 4. a literal htmlFor/id association names it --------------------------
reset
mk a.tsx '
export function A() {
  return (
    <div>
      <Label htmlFor="who">{t("who")}</Label>
      <Input id="who" value={x} onChange={f} />
    </div>
  )
}
'
[ "$(count)" = "0" ] || fail "4: an htmlFor/id association was not accepted"

# --- 5. a TEMPLATE-LITERAL association names it ----------------------------
# The trap: a control inside a loop needs a unique id, so both halves are
# written `{`scope-${s}`}`. A matcher that only reads [A-Za-z0-9_-] sees
# neither, and reports every correctly-labelled row as an offender.
reset
mk a.tsx '
export function A() {
  return items.map((s) => (
    <div key={s}>
      <Checkbox id={`scope-${s}`} checked={has(s)} />
      <Label htmlFor={`scope-${s}`}>{s}</Label>
    </div>
  ))
}
'
[ "$(count)" = "0" ] || fail "5: a template-literal association was not accepted"

# --- 6. a wrapping <label> names it ----------------------------------------
reset
mk a.tsx '
export function A() {
  return <label>{t("k")}<input value={x} onChange={f} /></label>
}
'
[ "$(count)" = "0" ] || fail "6: a wrapping label was not accepted"

# --- 7. placeholder counts for an Input, not for a SelectTrigger -----------
# axe accepts a placeholder for its `label` rule, so this stays consistent
# with the gate in CI. A SelectTrigger is a button: once a value is chosen the
# placeholder is not rendered at all, so it names nothing.
reset
mk a.tsx '
export function A() {
  return (
    <div>
      <Input placeholder={t("k")} value={x} onChange={f} />
      <SelectTrigger className="w-40"><SelectValue placeholder={t("k")} /></SelectTrigger>
    </div>
  )
}
'
[ "$(count)" = "1" ] || fail "7: expected exactly the SelectTrigger to be reported ($(count))"

# --- 8. non-user-facing inputs are ignored ---------------------------------
reset
mk a.tsx '
export function A() {
  return <div><input type="hidden" value={x} /><input type="submit" /></div>
}
'
[ "$(count)" = "0" ] || fail "8: hidden/submit inputs were reported"

# --- 9. an htmlFor that names nothing is an offender -----------------------
# Reads as correct in review; names nothing at runtime.
reset
mk a.tsx '
export function A() {
  return (
    <div>
      <Label htmlFor="ghost">{t("k")}</Label>
      <Input aria-label={t("k")} value={x} onChange={f} />
    </div>
  )
}
'
[ "$(count)" = "1" ] || fail "9: a dangling htmlFor was not reported ($(count))"

# --- 10. an id on a CUSTOM component satisfies the label -------------------
# <SecretField id="x"> forwards its id to a real input, so the label is
# associated. Only collecting ids from known control tags would call this a
# dangling htmlFor and demand a change that makes the markup worse.
reset
mk a.tsx '
export function A() {
  return (
    <div>
      <Label htmlFor="client_secret">{t("k")}</Label>
      <SecretField id="client_secret" value={v} onChange={f} />
    </div>
  )
}
'
[ "$(count)" = "0" ] || fail "10: an id on a custom component was not accepted"

# --- 11. attributes AFTER an arrow function are still seen -----------------
# The trap that broke the first version of check-keyboard-reachable.sh: the
# '>' inside `(e) => f(e)` ends a naive regex, hiding every later attribute.
reset
mk a.tsx '
export function A() {
  return <Input onChange={(e) => setX(e.target.value)} aria-label={t("k")} />
}
'
[ "$(count)" = "0" ] || fail "11: an aria-label after an arrow function was not seen"

# --- 12. comments are not scanned as code ----------------------------------
# The other trap: a doc comment quoting markup to explain the rule.
reset
mk a.tsx '
// Prefer a label over aria-label. A bare <Input value={x} /> has no name.
/* Nor does <select value={x}>. */
export function A() {
  return <Input aria-label={t("k")} value={x} onChange={f} />
}
'
[ "$(count)" = "0" ] || fail "12: markup quoted inside a comment was scanned as code"

# --- 13. .test.tsx files are not scanned -----------------------------------
reset
mk a.test.tsx '
export function A() { return <Input value={x} onChange={f} /> }
'
[ "$(count)" = "0" ] || fail "13: a .test.tsx fixture was scanned"

# --- 14. --enforce actually fails ------------------------------------------
reset
mk a.tsx '
export function A() { return <select value={x} onChange={f}><option /></select> }
'
if SH_SRC_DIR="$TMP/src" bash "$GUARD" --enforce >/dev/null 2>&1; then
  fail "14: --enforce exited 0 with an offender present"
fi
SH_SRC_DIR="$TMP/src" bash "$GUARD" >/dev/null 2>&1 \
  || fail "14: the default (warn) mode should exit 0"

echo "CONTROL_NAMES_SELFTEST=OK"
