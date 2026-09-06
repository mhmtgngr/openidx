#!/usr/bin/env bash
# Guard: every admin-console page that reads data with useQuery MUST render
# QueryError (directly or via QueryGate/QueryGateAll). Otherwise a 401/403
# silently becomes a "no data" empty state — the console-wide masking defect
# this sub-project fixes.
#
# TWO rules, because the first one alone was satisfiable by accident:
#
#   FILE rule — the file mentions QueryError/QueryGate at all. This is what the
#     guard checked from the start, and it is file-granular: ONE gate anywhere
#     in a file satisfied it for every useQuery in that file.
#
#   PER-QUERY rule — every `const fooQuery = useQuery(...)` in a file must
#     appear inside a `query={...}` or `queries={[...]}` prop somewhere in it.
#     network-topology.tsx passed the file rule with five queries and one gate:
#     identities was gated and services, routers, policies and sessions fell
#     through `?? []`, so a 403 drew a clean, believable, mostly-empty diagram.
#
#     Scope, stated rather than implied: this only sees queries bound to a
#     NAMED const, which is the shape a page uses when it intends to gate one.
#     A `const { data } = useQuery(...)` has no name to check and stays covered
#     by the file rule alone. Widening it is worth doing; claiming it already
#     covers them would not be.
#
#     The `[<(]` on the end of the name pattern is load-bearing: without it
#     `const queryClient = useQueryClient()` matches and every page in the
#     console becomes an offender.
#
# Default: warn (list offenders, exit 0). --enforce: exit 1 if any offender.
set -uo pipefail
cd "$(dirname "$0")/.."
PAGES="${SH_PAGES_DIR:-web/admin-console/src/pages}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1
ALLOWLIST="api-docs.tsx"

# Pages whose named queries are not all gated yet, each with the reason it is
# not a one-line fix. Pinned: this list may shrink, never grow — a page that is
# not on it and has an ungated named query fails.
#
#   ops-cockpit.tsx   11 named queries, one per independent subsystem card.
#                     An all-or-nothing gate would blank the whole cockpit
#                     because one subsystem is down, which is worse than the
#                     defect; it needs a gate per card.
#   app-publish.tsx   appsQuery/pathsQuery/appDetailQuery drive three separate
#                     panes with their own empty states.
#   zero-trust.tsx    overview/sessions/audit are three independent sections.
#   applications.tsx  ssoSettingsQuery feeds an optional inline settings block,
#                     not the page's main table.
PER_QUERY_REGISTER="${SH_PER_QUERY_REGISTER-ops-cockpit.tsx app-publish.tsx zero-trust.tsx applications.tsx}"
# Overridable (and settable to empty) so the self-test can exercise the
# register rules against a fixture directory instead of the real pages.

offenders=0
per_query_ok=0

while IFS= read -r f; do
  base=$(basename "$f")
  case " $ALLOWLIST " in *" $base "*) continue;; esac
  grep -q 'useQuery' "$f" || continue

  # FILE rule
  if ! grep -Eq 'QueryError|QueryGate' "$f"; then
    echo "offender: $f (no QueryError/QueryGate anywhere)"
    offenders=$((offenders+1))
    continue
  fi

  # PER-QUERY rule
  names=$(grep -oE 'const[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*=[[:space:]]*useQuery[<(]' "$f" \
          | sed -E 's/^const[[:space:]]+//; s/[[:space:]]*=[[:space:]]*useQuery[<(]$//')
  [ -z "$names" ] && continue
  # Everything passed to a query= / queries= prop, on one line or many.
  gated=$(tr '\n' ' ' < "$f" | grep -oE 'quer(y|ies)=\{[^}]*\}' || true)
  missing=""
  for n in $names; do
    printf '%s' "$gated" | grep -qE "\b${n}\b" || missing="$missing $n"
  done
  if [ -n "$missing" ]; then
    case " $PER_QUERY_REGISTER " in
      *" $base "*) continue;;
    esac
    echo "offender: $f — named quer(y|ies) never reach a gate:$missing"
    offenders=$((offenders+1))
  else
    per_query_ok=$((per_query_ok+1))
  fi
done < <(find "$PAGES" -name '*.tsx' ! -name '*.test.tsx' | sort)

# The register can only shrink. A page that gets its gates should leave it, and
# a page that is still on it while fully gated is a stale entry, not a pass.
for base in $PER_QUERY_REGISTER; do
  f=$(find "$PAGES" -name "$base" | head -1)
  if [ -z "$f" ]; then
    echo "offender: $base is on the per-query register but no longer exists — drop it"
    offenders=$((offenders+1))
    continue
  fi
  names=$(grep -oE 'const[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*[[:space:]]*=[[:space:]]*useQuery[<(]' "$f" \
          | sed -E 's/^const[[:space:]]+//; s/[[:space:]]*=[[:space:]]*useQuery[<(]$//')
  gated=$(tr '\n' ' ' < "$f" | grep -oE 'quer(y|ies)=\{[^}]*\}' || true)
  still=0
  for n in $names; do
    printf '%s' "$gated" | grep -qE "\b${n}\b" || still=1
  done
  if [ "$still" = 0 ]; then
    echo "offender: $base is fully gated now — remove it from PER_QUERY_REGISTER"
    offenders=$((offenders+1))
  fi
done

echo "query-error-coverage offenders: $offenders (pages with every named query gated: $per_query_ok)"
if [ "$ENFORCE" = 1 ] && [ "$offenders" -gt 0 ]; then exit 1; fi
exit 0
