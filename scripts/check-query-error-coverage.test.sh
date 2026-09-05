#!/usr/bin/env bash
# Self-test for check-query-error-coverage.sh. A guard nobody has watched fail
# is a guard nobody can trust — and this one's per-query rule exists precisely
# because its file rule passed on a page it should have failed.
set -uo pipefail
cd "$(dirname "$0")/.."

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
fails=0

# REGISTER defaults to empty for the fixture cases; the two register tests set it.
REGISTER=""
run() {
  SH_PAGES_DIR="$WORK/pages" SH_PER_QUERY_REGISTER="$REGISTER" \
    ./scripts/check-query-error-coverage.sh --enforce 2>&1
}

expect() { # expect <want-exit> <label>
  local want="$1" label="$2" out rc
  out=$(run); rc=$?
  if [ "$rc" != "$want" ]; then
    echo "FAIL: $label — exited $rc, expected $want"
    printf '%s\n' "$out" | sed 's/^/    /'
    fails=$((fails+1))
  else
    echo "ok: $label"
  fi
}

fresh() { rm -rf "$WORK/pages"; mkdir -p "$WORK/pages"; }

# A page whose one named query IS gated: the shape the guard wants.
good_page() {
  cat > "$WORK/pages/$1" <<'TSX'
import { QueryGate } from '../components/query-gate'
export function Good() {
  const thingsQuery = useQuery({ queryKey: ['things'], queryFn: f })
  return <QueryGate query={thingsQuery} resource="things">{() => null}</QueryGate>
}
TSX
}

fresh; good_page ok.tsx
expect 0 "a page whose named query is gated passes"

# The network-topology defect: several named queries, only the first gated.
fresh; good_page ok.tsx
cat > "$WORK/pages/partial.tsx" <<'TSX'
import { QueryGate } from '../components/query-gate'
export function Partial() {
  const oneQuery = useQuery({ queryKey: ['one'], queryFn: f })
  const twoQuery = useQuery({ queryKey: ['two'], queryFn: f })
  const two = twoQuery.data ?? []
  return <QueryGate query={oneQuery} resource="one">{() => <List items={two} />}</QueryGate>
}
TSX
expect 1 "a second named query that never reaches a gate is caught"

# QueryGateAll's array form must satisfy the rule for every query in it.
fresh; good_page ok.tsx
cat > "$WORK/pages/all.tsx" <<'TSX'
import { QueryGateAll } from '../components/query-gate'
export function All() {
  const oneQuery = useQuery({ queryKey: ['one'], queryFn: f })
  const twoQuery = useQuery({ queryKey: ['two'], queryFn: f })
  return <QueryGateAll queries={[oneQuery, twoQuery]} resource="both"><div /></QueryGateAll>
}
TSX
expect 0 "queries={[a, b]} gates every query it names"

# The original file rule still has to bite.
fresh; good_page ok.tsx
cat > "$WORK/pages/ungated.tsx" <<'TSX'
export function Ungated() {
  const { data } = useQuery({ queryKey: ['x'], queryFn: f })
  return <List items={data ?? []} />
}
TSX
expect 1 "a page with no QueryError/QueryGate at all is caught"

# useQueryClient is not a query. This matched once and made every page red.
fresh; good_page ok.tsx
cat > "$WORK/pages/client.tsx" <<'TSX'
import { QueryGate } from '../components/query-gate'
export function WithClient() {
  const queryClient = useQueryClient()
  const rowsQuery = useQuery({ queryKey: ['rows'], queryFn: f })
  return <QueryGate query={rowsQuery} resource="rows">{() => <X qc={queryClient} />}</QueryGate>
}
TSX
expect 0 "useQueryClient is not counted as a query"

# The register may only shrink: an entry that is now fully gated is stale.
fresh; good_page ok.tsx
REGISTER="zero-trust.tsx"
cat > "$WORK/pages/zero-trust.tsx" <<'TSX'
import { QueryGateAll } from '../components/query-gate'
export function ZT() {
  const overviewQuery = useQuery({ queryKey: ['o'], queryFn: f })
  return <QueryGateAll queries={[overviewQuery]} resource="zt"><div /></QueryGateAll>
}
TSX
expect 1 "a register entry that is fully gated must be removed from the register"

# ...and an entry whose page is gone is stale too.
fresh; good_page ok.tsx
REGISTER="deleted-page.tsx"
expect 1 "register entries whose pages no longer exist are caught"
REGISTER=""

# A page ON the register with an ungated named query is tolerated — that is
# what the register is for — but only while it is on it.
fresh; good_page ok.tsx
cat > "$WORK/pages/on-register.tsx" <<'TSX'
import { QueryGate } from '../components/query-gate'
export function OnRegister() {
  const oneQuery = useQuery({ queryKey: ['one'], queryFn: f })
  const twoQuery = useQuery({ queryKey: ['two'], queryFn: f })
  const two = twoQuery.data ?? []
  return <QueryGate query={oneQuery} resource="one">{() => <List items={two} />}</QueryGate>
}
TSX
REGISTER="on-register.tsx"
expect 0 "a registered page with an ungated named query is tolerated"
REGISTER=""
expect 1 "the same page fails the moment it leaves the register"

if [ "$fails" -gt 0 ]; then
  echo "check-query-error-coverage self-test: $fails failure(s)"
  exit 1
fi
echo "check-query-error-coverage self-test: all cases behaved"
