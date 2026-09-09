#!/usr/bin/env bash
# Mutation test for the pam-launch-wrapper guard. Each fixture is a launcher
# someone could plausibly write; the guard must separate them the way review
# would have, and must notice when it is watching nothing at all.
set -uo pipefail
cd "$(dirname "$0")/.."
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }
tmp=$(mktemp -d)

# The shape quick links actually had: the raw, token-bearing URL to the browser.
cat > "$tmp/raw-open.tsx" <<'TSX'
const connect = useMutation({
  mutationFn: (id: string) => api.pam.connect(id),
  onSuccess: (res) => { const url = res.connect_url || res.url; if (url) window.open(url, '_blank') },
})
TSX

# Imports the helper but still reads the URL out of the response — the "I know
# about the wrapper and went around it anyway" case that rule 1 alone misses.
cat > "$tmp/half-migrated.tsx" <<'TSX'
import { openPamSessionWindow } from '../lib/pam-session-handoff'
const connect = useMutation({
  mutationFn: (id: string) => api.pam.connect(id),
  onSuccess: (res) => { if (res.connect_url) window.location.assign(res.connect_url) },
})
TSX

cat > "$tmp/good.tsx" <<'TSX'
import { openPamSessionWindow } from '../lib/pam-session-handoff'
const connect = useMutation({
  mutationFn: (vars: { id: string; title: string }) => api.pam.connect(vars.id),
  onSuccess: (res, vars) => { openPamSessionWindow(res, vars.title) },
})
TSX

# Not a launcher at all — must not be dragged in just for mentioning PAM.
cat > "$tmp/unrelated.tsx" <<'TSX'
const entries = useQuery({ queryFn: () => api.pam.listEntries() })
const url = 'https://docs.example/pam'
window.open(url, '_blank')
TSX

out=$(SH_CONSOLE_SRC="$tmp" bash scripts/check-pam-launch-wrapper.sh)
echo "$out" | grep -q 'raw-open.tsx' && ok "flags a launcher that opens the raw connect URL" || bad "missed the raw window.open launcher"
echo "$out" | grep -q 'half-migrated.tsx' && ok "flags a launcher that reads connect_url itself" || bad "missed the half-migrated launcher"
echo "$out" | grep -q 'good.tsx' && bad "flagged a launcher that uses the wrapper" || ok "ignores a launcher that uses the wrapper"
echo "$out" | grep -q 'unrelated.tsx' && bad "flagged a file that never launches a session" || ok "ignores a non-launcher"
echo "$out" | grep -q '3 launcher(s), 2 offender(s)' && ok "counts launchers and offenders" || bad "wrong counts: $out"

SH_CONSOLE_SRC="$tmp" bash scripts/check-pam-launch-wrapper.sh --enforce >/dev/null 2>&1 && bad "enforce did not fail" || ok "enforce fails on an offender"

# The guard must not pass by matching nothing: a rename of api.pam.connect
# would otherwise leave it green over launchers it no longer sees.
empty=$(mktemp -d)
cat > "$empty/nothing.tsx" <<'TSX'
export const x = 1
TSX
out2=$(SH_CONSOLE_SRC="$empty" bash scripts/check-pam-launch-wrapper.sh)
echo "$out2" | grep -q 'no longer matches' && ok "says so when it matches no launcher" || bad "stayed quiet over an empty set"
SH_CONSOLE_SRC="$empty" bash scripts/check-pam-launch-wrapper.sh --enforce >/dev/null 2>&1 && bad "enforce passed over an empty set" || ok "enforce fails over an empty set"

# The helper's own module and the tests must be exempt, or the guard flags the
# very files that exist to define and prove the rule.
exempt=$(mktemp -d); mkdir -p "$exempt/lib"
cat > "$exempt/lib/pam-session-handoff.ts" <<'TS'
// mentions api.pam.connect( in its doc comment and reads connect_url
export function openPamSessionWindow(res) { return res.connect_url }
TS
cat > "$exempt/launcher.test.tsx" <<'TSX'
it('launches', () => { api.pam.connect('e1'); expect(res.connect_url).toBe('x') })
TSX
out3=$(SH_CONSOLE_SRC="$exempt" bash scripts/check-pam-launch-wrapper.sh)
echo "$out3" | grep -q 'offender:' && bad "flagged the helper or a test file" || ok "exempts the helper module and tests"

rm -rf "$tmp" "$empty" "$exempt"
[ "$fails" -eq 0 ] && echo "check-pam-launch-wrapper PASS" || { echo "FAIL ($fails)"; exit 1; }
