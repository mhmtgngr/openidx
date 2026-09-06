#!/usr/bin/env bash
# Self-test: check-detached-org-writes.sh must go red on a detached pool call
# with no tenant, and stay green on every shape that legitimately has none.
#
# The green cases carry the weight. This guard fires on `context.Background()`,
# which appears all over a Go codebase for entirely good reasons -- closing a
# connection, a direct pgx.Connect outside the app pool, a job that has said it
# spans orgs. A guard that flags those is one somebody switches off in a week,
# and then the real finding it was written for goes unnoticed again.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-detached-org-writes.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

# fixture <name> <go-body> -> prints the fixture root
fixture() {
  local name="$1" body="$2"
  local d="$tmp/$name"
  mkdir -p "$d/internal/thing"
  printf '%s\n' "$body" > "$d/internal/thing/thing.go"
  echo "$d"
}

expect() { # expect <want: ok|red> <label> <root>
  local want="$1" label="$2" root="$3" rc=0
  OPENIDX_SRC_ROOT="$root" bash "$GUARD" --enforce >/dev/null 2>&1 || rc=$?
  if { [ "$want" = ok ] && [ "$rc" -eq 0 ]; } || { [ "$want" = red ] && [ "$rc" -ne 0 ]; }; then
    echo "  ok   $label"
    pass=$((pass + 1))
  else
    echo "  FAIL $label (wanted $want, exit $rc)"
    fail=$((fail + 1))
  fi
}

echo "check-detached-org-writes.test:"

# The real tree is the green case, and the one that matters most.
expect ok "the committed tree names a tenant on every detached pool call" "$ROOT"

expect red "a detached pool write with no tenant" \
  "$(fixture bare 'package thing
func f() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.db.Pool.Exec(ctx, `INSERT INTO audit_events (org_id) VALUES ($1)`, orgID)
}')"

# The bug this guard was written for: the org is resolved, and put in the ROW,
# but never on the context the write runs on. Reads as careful; is not.
expect red "an org resolved into the row but not onto the context" \
  "$(fixture rowonly 'package thing
func f(ctx context.Context) {
	orgID := "00000000-0000-0000-0000-000000000010"
	if org, err := orgctx.From(ctx); err == nil {
		orgID = org.ID
	}
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.db.Pool.Exec(bg, `INSERT INTO audit_events (org_id) VALUES ($1)`, orgID)
	}()
}')"

expect ok "a detached write that carries the org" \
  "$(fixture scoped 'package thing
func f(orgID string) {
	ctx, cancel := context.WithTimeout(
		orgctx.With(context.Background(), orgctx.Org{ID: orgID}), 5*time.Second)
	defer cancel()
	s.db.Pool.Exec(ctx, `INSERT INTO audit_events (org_id) VALUES ($1)`, orgID)
}')"

expect ok "a job that has declared it spans orgs" \
  "$(fixture bypass 'package thing
func f() {
	ctx, cancel := context.WithTimeout(orgctx.WithBypassRLS(context.Background()), 5*time.Second)
	defer cancel()
	s.db.Pool.Exec(ctx, `SELECT 1 FROM oauth_signing_keys`)
}')"

# --- the shapes that are not detached pool calls at all -----------------------
expect ok "closing a connection is not a query" \
  "$(fixture close 'package thing
func f() {
	conn, _ := pgx.Connect(cctx, dsn)
	defer conn.Close(context.Background())
}')"

expect ok "a direct pgx connection is outside the app pool and its RLS hook" \
  "$(fixture direct 'package thing
func f() {
	ctxDB, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, _ := pgx.Connect(ctxDB, dbURL)
	conn.Exec(ctxDB, `INSERT INTO organizations (name) VALUES ($1)`, "seed")
}')"

expect ok "a background context that never reaches the database" \
  "$(fixture nodb 'package thing
func f() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = httpClient.Do(req.WithContext(ctx))
}')"

expect ok "a test file is not checked" \
  "$(fixture testfile 'package thing')"
# Rename the fixture body into a _test.go so the exclusion is exercised.
mv "$tmp/testfile/internal/thing/thing.go" "$tmp/testfile/internal/thing/thing_test.go"
printf 'package thing\nfunc f() {\n\ts.db.Pool.Exec(context.Background(), `INSERT INTO audit_events DEFAULT VALUES`)\n}\n' \
  > "$tmp/testfile/internal/thing/thing_test.go"
expect ok "a detached write inside a _test.go is not a finding" "$tmp/testfile"

echo "check-detached-org-writes.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
