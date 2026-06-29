# Tenant-isolation test harness extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the tenant-isolation test gaps for the v2.0 GA ship gate — write-path RLS, belt breadth across representative tables, and the gateway `X-Org-Slug` strip — reusing the existing `test/integration/cross_org_test.go` harness.

**Architecture:** All new tests live in `test/integration/` behind the `integration` build tag, run via `make test-integration` against the running stack. They reuse the existing harness (the NOSUPERUSER `openidx_rls_test` role from `rlsRolePool`, plus `seedOrg`/`seedUserInOrg`/`bypassExec`). DB-level belts need only the DB; the gateway-strip test routes through `:8008` and self-skips if it's down.

**Tech Stack:** Go integration tests (build tag `integration`), pgx v5, the in-repo integration helpers; PostgreSQL RLS.

**Scope note:** Per the spec's "focused high-value" scope, Component 2 implements the **`X-Org-Slug` gateway-strip** negative (the documented boundary, provable with the admin token). The **`X-Org-ID` non-admin** negative is **deferred** — it needs a non-admin user credential + the full PKCE login flow to mint a non-privileged token, which is disproportionate machinery for this sub-project; tracked as a follow-on. The DB-level belt + the `X-Org-Slug` strip already cover the row layer and the documented header-strip boundary.

---

### Task 1: Extend the RLS test-role grants + write-path belt

**Files:**
- Modify: `test/integration/cross_org_test.go` (`rlsRolePool` grant list; add `TestRLSWriteBelt`)

- [ ] **Step 1: Extend `rlsRolePool`'s grants**

The shared test role currently only has `SELECT` on `users`/`organizations`. The write-belt needs DML on `users`, and Task 2 needs `SELECT` on three more tables. In `rlsRolePool`, replace the grant slice:

```go
	for _, stmt := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + roleName,
		`GRANT SELECT ON users TO ` + roleName,
		`GRANT SELECT ON organizations TO ` + roleName,
	} {
```

with:

```go
	for _, stmt := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + roleName,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON users TO ` + roleName,
		`GRANT SELECT ON organizations TO ` + roleName,
		`GRANT SELECT ON applications TO ` + roleName,
		`GRANT SELECT ON oauth_clients TO ` + roleName,
		`GRANT SELECT ON audit_events TO ` + roleName,
	} {
```

(Additive — `TestRLSBelt` still only reads `users`, so it's unaffected.)

- [ ] **Step 2: Add the write-path belt test**

Append to `test/integration/cross_org_test.go`:

```go
// TestRLSWriteBelt is the write-path counterpart to TestRLSBelt: under RLS, a
// session scoped to org A cannot plant rows in org B (WITH CHECK) and cannot
// mutate org B's rows (USING hides them → 0 rows affected). Runs on the
// NOSUPERUSER role so the policies actually apply.
func TestRLSWriteBelt(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()
	requireForceRLS(t, admin, "users")

	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgA := seedOrg(t, admin, "wbelt-a-"+suffix)
	orgB := seedOrg(t, admin, "wbelt-b-"+suffix)
	userB := seedUserInOrg(t, admin, orgB, "wbelt-userB-"+suffix, "wbelt-b-"+suffix+"@example.test")
	t.Cleanup(func() {
		bypassExec(t, admin, "DELETE FROM users WHERE org_id IN ($1,$2)", orgA, orgB)
		bypassExec(t, admin, "DELETE FROM organizations WHERE id IN ($1,$2)", orgA, orgB)
	})

	pool := rlsRolePool(t, admin)
	defer pool.Close()
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	_, err = conn.Exec(ctx, `select set_config('app.org_id', $1, false), set_config('app.bypass_rls', '', false)`, orgA)
	require.NoError(t, err)

	t.Run("INSERT into another org is rejected by WITH CHECK", func(t *testing.T) {
		_, err := conn.Exec(ctx,
			`INSERT INTO users (username, email, enabled, org_id) VALUES ($1,$2,true,$3)`,
			"wbelt-evil-"+suffix, "wbelt-evil-"+suffix+"@example.test", orgB)
		require.Error(t, err, "A-scoped session must not insert a row tagged org B")
	})

	t.Run("INSERT into own org succeeds", func(t *testing.T) {
		tag, err := conn.Exec(ctx,
			`INSERT INTO users (username, email, enabled, org_id) VALUES ($1,$2,true,$3)`,
			"wbelt-ok-"+suffix, "wbelt-ok-"+suffix+"@example.test", orgA)
		require.NoError(t, err, "A-scoped session must insert its own org's row")
		assert.Equal(t, int64(1), tag.RowsAffected())
	})

	t.Run("UPDATE of another org's row affects 0 rows", func(t *testing.T) {
		tag, err := conn.Exec(ctx, `UPDATE users SET name = 'x' WHERE id = $1`, userB)
		require.NoError(t, err)
		assert.Equal(t, int64(0), tag.RowsAffected(), "A-scoped UPDATE must not touch org B's row")
	})

	t.Run("DELETE of another org's row affects 0 rows", func(t *testing.T) {
		tag, err := conn.Exec(ctx, `DELETE FROM users WHERE id = $1`, userB)
		require.NoError(t, err)
		assert.Equal(t, int64(0), tag.RowsAffected(), "A-scoped DELETE must not touch org B's row")
	})
}

// requireForceRLS skips the suite (with guidance) unless FORCE ROW LEVEL
// SECURITY is active on the table — otherwise the belt assertions are vacuous.
func requireForceRLS(t *testing.T, db *pgxpool.Pool, table string) {
	t.Helper()
	var forced bool
	err := db.QueryRow(context.Background(),
		`SELECT relforcerowsecurity FROM pg_class WHERE relname = $1`, table).Scan(&forced)
	require.NoError(t, err)
	if !forced {
		t.Skipf("FORCE ROW LEVEL SECURITY not active on %s (migration v37 not applied?) — skipping belt", table)
	}
}
```

NOTE: if `TestRLSBelt` already defines a `requireForceRLS`-equivalent guard (it asserts FORCE is active), reuse that instead of adding a duplicate — check before adding, and if a helper with that purpose exists, call it and drop this one. The `users` table has a `name` column (used by the UPDATE); confirm with `\d users` if the UPDATE errors on an unknown column and switch to `email` if so.

- [ ] **Step 3: Compile-check under the integration tag**

Run: `cd /home/cmit/openidx && gofmt -w test/integration/cross_org_test.go && go vet -tags=integration ./test/integration/...`
Expected: no output (compiles clean under the build tag). The test itself runs in Task 4 against the live stack.

- [ ] **Step 4: Commit**

```bash
cd /home/cmit/openidx
git add test/integration/cross_org_test.go
git commit -m "test(integration): write-path RLS belt + extend test-role grants (v2.0 isolation)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Belt breadth across representative tables

**Files:**
- Modify: `test/integration/cross_org_test.go` (add `TestRLSBeltTables`)

- [ ] **Step 1: Add the table-driven read-belt**

Append to `test/integration/cross_org_test.go` (relies on Task 1's added SELECT grants):

```go
// TestRLSBeltTables generalizes the read-belt beyond `users`: for each
// representative scoped table, a row seeded in org B is invisible to an
// A-scoped session and visible under bypass. Proves the RLS guarantee isn't an
// artifact of the users table alone.
func TestRLSBeltTables(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()

	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgA := seedOrg(t, admin, "tbelt-a-"+suffix)
	orgB := seedOrg(t, admin, "tbelt-b-"+suffix)

	// Each case: a minimal INSERT (required NOT-NULL cols + org_id) and the
	// table name. Seeded under bypass; cleaned up under bypass.
	cases := []struct {
		table     string
		insertSQL string // one row; $1 = org_id, plus the unique suffix baked in
	}{
		{"users", `INSERT INTO users (username, email, enabled, org_id) VALUES ('tbelt-u-` + suffix + `','tbelt-u-` + suffix + `@example.test',true,$1)`},
		{"applications", `INSERT INTO applications (client_id, name, type, org_id) VALUES ('tbelt-app-` + suffix + `','tbelt app','web',$1)`},
		{"oauth_clients", `INSERT INTO oauth_clients (client_id, name, type, org_id) VALUES ('tbelt-oc-` + suffix + `','tbelt client','confidential',$1)`},
		{"audit_events", `INSERT INTO audit_events (event_type, category, action, outcome, org_id) VALUES ('tbelt','test','probe','success',$1)`},
	}

	for _, c := range cases {
		c := c
		t.Run(c.table, func(t *testing.T) {
			requireForceRLS(t, admin, c.table)
			bypassExec(t, admin, c.insertSQL, orgB) // seed one B row
			t.Cleanup(func() { bypassExec(t, admin, "DELETE FROM "+c.table+" WHERE org_id = $1", orgB) })

			pool := rlsRolePool(t, admin)
			defer pool.Close()
			conn, err := pool.Acquire(ctx)
			require.NoError(t, err)
			defer conn.Release()

			countB := func(bypass string) int {
				_, e := conn.Exec(ctx, `select set_config('app.org_id',$1,false), set_config('app.bypass_rls',$2,false)`, orgA, bypass)
				require.NoError(t, e)
				var n int
				require.NoError(t, conn.QueryRow(ctx, "SELECT count(*) FROM "+c.table+" WHERE org_id = $1", orgB).Scan(&n))
				return n
			}
			assert.Equal(t, 0, countB(""), "A-scoped session must not see org B rows in %s", c.table)
			assert.Greater(t, countB("on"), 0, "bypass must see org B rows in %s", c.table)
		})
	}
}
```

(`applications.type='web'` and `oauth_clients.type='confidential'` are representative valid values; if either column has a CHECK constraint that rejects them, the seed errors — switch to a value the constraint allows, discoverable from `\d <table>`.)

- [ ] **Step 2: Compile-check**

Run: `cd /home/cmit/openidx && gofmt -w test/integration/cross_org_test.go && go vet -tags=integration ./test/integration/...`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
cd /home/cmit/openidx
git add test/integration/cross_org_test.go
git commit -m "test(integration): parametrize the RLS read-belt over 4 representative tables

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Gateway `X-Org-Slug` strip negative

**Files:**
- Modify: `test/integration/helpers_test.go` (add `gatewayURL` + `apiRequestViaGateway`)
- Modify: `test/integration/cross_org_test.go` (add `TestCrossOrgSpoofing`)

- [ ] **Step 1: Add a gateway-routed request helper**

In `test/integration/helpers_test.go`, near the other URL vars (`oauthURL`, `identityURL`), add:

```go
	gatewayURL = envOrDefault("GATEWAY_URL", "http://localhost:8008")
```

and add a helper (mirroring `apiRequestWithHeaders`, but it's just a named base — reuse `apiRequestWithHeaders` with a `gatewayURL`-based URL in the test; no new function needed if `apiRequestWithHeaders` takes a full URL). Confirm `apiRequestWithHeaders` accepts a full URL (it does — callers pass `identityURL + path`). So the test builds `gatewayURL + path` and calls `apiRequestWithHeaders`.

- [ ] **Step 2: Add the spoofing test**

Append to `test/integration/cross_org_test.go`:

```go
// TestCrossOrgSpoofing proves the gateway is the security boundary for the
// client-supplied X-Org-Slug header: a request through the gateway (:8008)
// carrying a forged X-Org-Slug for another org is STRIPPED — the gateway
// re-derives org from the authenticated identity — so it cannot read the
// forged org's data. (Sending the header straight to a service is NOT a
// negative: services trust X-Org-Slug because the gateway sets it.)
//
// Skips if the gateway isn't reachable (CI may not start it; the box does).
func TestCrossOrgSpoofing(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()

	// Skip unless the gateway is up.
	if _, err := http.Get(gatewayURL + "/health"); err != nil {
		t.Skipf("gateway not reachable at %s (%v) — skipping X-Org-Slug strip test", gatewayURL, err)
	}

	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgB := seedOrg(t, db, "spoof-b-"+suffix)
	userB := seedUserInOrg(t, db, orgB, "spoof-userB-"+suffix, "spoof-b-"+suffix+"@example.test")
	t.Cleanup(func() {
		bypassExec(t, db, "DELETE FROM users WHERE id = $1", userB)
		bypassExec(t, db, "DELETE FROM organizations WHERE id = $1", orgB)
	})
	_ = ctx

	token := getAdminToken(t)
	// Through the gateway, forge X-Org-Slug for org B while reading org B's user
	// by id. The gateway strips the client header and scopes to the admin's
	// derived org (the install default, NOT the freshly-seeded org B), so the
	// read must NOT succeed against org B's row.
	status, _ := apiRequestWithHeaders(t, "GET",
		gatewayURL+"/api/v1/identity/users/"+userB, "", token,
		map[string]string{"X-Org-Slug": "spoof-b-" + suffix})
	assert.NotEqual(t, 200, status,
		"forged X-Org-Slug through the gateway must be stripped — org B's user must not read 200")
}
```

NOTE: confirm the gateway proxies `/api/v1/identity/users/:id` (it proxies `identity` per `internal/gateway/config.go`). If the gateway path prefix differs (e.g. it strips `/api`), adjust the URL to what the gateway actually routes — discoverable by curling `GATEWAY_URL/api/v1/identity/users/<id>` on the box. The assertion is deliberately `NotEqual 200` (a stripped request lands in the admin's default org → 404/empty for org B's id); if the gateway returns the admin's-org view, that's still not org B's row.

- [ ] **Step 3: Compile-check**

Run: `cd /home/cmit/openidx && gofmt -w test/integration/helpers_test.go test/integration/cross_org_test.go && go vet -tags=integration ./test/integration/...`
Expected: clean. (Ensure `net/http` is imported in `cross_org_test.go`; add it if not.)

- [ ] **Step 4: Commit**

```bash
cd /home/cmit/openidx
git add test/integration/helpers_test.go test/integration/cross_org_test.go
git commit -m "test(integration): gateway strips forged X-Org-Slug (cross-org spoofing negative)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Live run on the box

Run the extended suite against the full stack (it can't run in plain `go test` — needs the integration tag, the DB, and the gateway). No commit.

**Files:** none.

- [ ] **Step 1: Run the new tests against the live stack**

```bash
cd /home/cmit/openidx
export DATABASE_URL="postgres://openidx:devpassword@localhost:55432/openidx?sslmode=disable"   # owner DSN: seeds + creates the test role
export GATEWAY_URL="http://localhost:8008"
go test -tags=integration ./test/integration/ -run 'TestRLSWriteBelt|TestRLSBeltTables|TestCrossOrgSpoofing' -count=1 -v 2>&1 | tail -40
```
Expected: `--- PASS` for `TestRLSWriteBelt` (INSERT-other-org rejected; INSERT-own ok; UPDATE/DELETE-other-org 0 rows), `TestRLSBeltTables` (all 4 sub-tests: A sees 0 of B, bypass sees B), and `TestCrossOrgSpoofing` (forged X-Org-Slug through the gateway not 200). `ok test/integration`.

Note: the belt tests need the seeding to run as the **owner** (`openidx`) DSN (DDL to create the `openidx_rls_test` role + `bypassExec`), while the assertions use the dedicated NOSUPERUSER role internally — `integrationDB` uses `DATABASE_URL`, so set it to the owner DSN for this run (not `openidx_app`). The role-creation in `rlsRolePool` needs a superuser/owner; `openidx` qualifies.

- [ ] **Step 2: If a seed/grant/path assumption is wrong, fix forward**

If a table seed fails on a CHECK/NOT-NULL (`applications.type`, `oauth_clients.type`) or the gateway path 404s for a routing reason (not the strip), correct the specific value/URL in the test, re-run, and fold the fix into the relevant task's commit (amend or a follow-up commit). Do NOT loosen an assertion to make it pass — the negative (`0 rows`, `NotEqual 200`, INSERT error) must remain a real check.

- [ ] **Step 3: Report** — outcomes per test; no commit for this task.

---

## Notes for the executor
- Dependency order **1 → 2 → 3 → 4**. Task 2 relies on Task 1's added SELECT grants on the test role; both belts share `rlsRolePool`/`requireForceRLS`.
- These are `//go:build integration` tests — they compile-check with `go vet -tags=integration ./test/integration/...` (Tasks 1–3) but only *run* against the live stack (Task 4). A subagent can do Tasks 1–3 (write + vet); Task 4 needs the box.
- Reuse the existing harness — do not re-implement `rlsRolePool`, `seedOrg`, `seedUserInOrg`, `bypassExec`, `getAdminToken`, `apiRequestWithHeaders`.
- These tests **pin existing guarantees** (RLS already enforces) — they're characterization/regression tests, so they pass green on first correct run; their value is catching a future regression (and they'd fail if RLS were disabled or a grant/strip removed). That's why there's no classic red-first step.
- Out of scope (do NOT implement here): the `X-Org-ID` non-admin negative (needs non-admin-credential machinery — follow-on); exhaustive per-service HTTP matrix; the spoofed-JWT-claim vector (signature-protected).
