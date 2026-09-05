//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// integrationDSN returns the connection string for the test database, reading
// DATABASE_URL and falling back to the local docker-compose DSN built from
// POSTGRES_PASSWORD. Skips the suite if neither is usable.
func integrationDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		pw := os.Getenv("POSTGRES_PASSWORD")
		if pw == "" {
			t.Skip("DATABASE_URL/POSTGRES_PASSWORD not set; skipping cross-org DB seeding test")
		}
		dsn = fmt.Sprintf("postgres://openidx:%s@localhost:5432/openidx?sslmode=disable", pw)
	}
	return dsn
}

// integrationDB opens a pool against the test database. If it isn't usable the
// cross-org suite is skipped (it needs direct seeding, unlike the HTTP-only
// helpers).
func integrationDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := integrationDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("cannot connect to test DB: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("test DB not reachable: %v", err)
	}
	return pool
}

// rlsRolePool returns a pool connected as a dedicated NOSUPERUSER role.
//
// This matters because Postgres superusers (and roles with BYPASSRLS) ignore
// Row-Level Security entirely — even FORCE RLS — so a belt test run as the
// default `openidx` superuser (what the postgres Docker image and CI create)
// would see across orgs and silently pass nothing. Production RDS connects as a
// non-superuser master role, where the policies do apply; this role reproduces
// that. The role is created idempotently via the (superuser) admin pool and
// granted only what the belt assertions need (SELECT on users/organizations).
//
// extraTables are granted on top of the fixed list below. A caller that probes a
// table it did not name gets "permission denied", which reads as a belt failure
// and is not one -- so TestRLSBeltTables derives its argument from its own case
// table rather than keeping a second list in step by hand. That is exactly how
// six v140 cases came to fail here on a grant nobody had added.
func rlsRolePool(t *testing.T, admin *pgxpool.Pool, extraTables ...string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	const roleName = "openidx_rls_test"
	const rolePass = "rls_test_pw"

	// Idempotent role creation + grants (CREATE ROLE has no IF NOT EXISTS).
	_, err := admin.Exec(ctx, fmt.Sprintf(`DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%s') THEN
    CREATE ROLE %s LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s';
  ELSE
    ALTER ROLE %s LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s';
  END IF;
END $$;`, roleName, roleName, rolePass, roleName, rolePass))
	require.NoError(t, err, "create RLS test role")
	for _, stmt := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + roleName,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON users TO ` + roleName,
		`GRANT SELECT ON organizations TO ` + roleName,
		`GRANT SELECT ON applications TO ` + roleName,
		`GRANT SELECT ON oauth_clients TO ` + roleName,
		`GRANT SELECT ON audit_events TO ` + roleName,
		`GRANT SELECT ON api_keys TO ` + roleName,
		`GRANT SELECT ON proxy_routes TO ` + roleName,
		`GRANT SELECT ON attestation_campaigns TO ` + roleName,
		`GRANT SELECT ON attestation_items TO ` + roleName,
		`GRANT SELECT ON jit_grants TO ` + roleName,
		`GRANT SELECT ON request_approval_chains TO ` + roleName,
		// v138 — ISPM + AI tenant isolation
		`GRANT SELECT ON ispm_findings TO ` + roleName,
		`GRANT SELECT ON ispm_rules TO ` + roleName,
		`GRANT SELECT ON ai_agents TO ` + roleName,
		`GRANT SELECT ON ai_recommendations TO ` + roleName,
	} {
		_, err := admin.Exec(ctx, stmt)
		require.NoError(t, err, "grant to RLS test role: %s", stmt)
	}
	for _, tbl := range extraTables {
		_, err := admin.Exec(ctx, `GRANT SELECT, INSERT ON `+tbl+` TO `+roleName)
		require.NoError(t, err, "grant to RLS test role: %s", tbl)
	}

	// Build the role's DSN by swapping the userinfo on the admin DSN.
	u, err := url.Parse(integrationDSN(t))
	require.NoError(t, err)
	u.User = url.UserPassword(roleName, rolePass)
	pool, err := pgxpool.New(ctx, u.String())
	require.NoError(t, err, "connect as RLS test role")
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("RLS test role cannot connect (pg_hba?): %v", err)
	}
	return pool
}

// seedOrg upserts an organization by slug and returns its id.
func seedOrg(t *testing.T, db *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	err := db.QueryRow(context.Background(),
		`INSERT INTO organizations (name, slug, status)
		 VALUES ($1, $2, 'active')
		 ON CONFLICT (slug) DO UPDATE SET updated_at = NOW()
		 RETURNING id`, "Cross-Org Test "+slug, slug).Scan(&id)
	require.NoError(t, err, "seed org %s", slug)
	return id
}

// seedUserInOrg inserts a user directly into the given org and returns its id.
// users is FORCE-RLS once migration v37 is applied, so the insert runs in a
// transaction that sets app.bypass_rls — a raw pool connection carries no org
// scope and would otherwise fail the policy's WITH CHECK.
func seedUserInOrg(t *testing.T, db *pgxpool.Pool, orgID, username, email string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := db.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `select set_config('app.bypass_rls', 'on', true)`)
	require.NoError(t, err)
	var id string
	err = tx.QueryRow(ctx,
		`INSERT INTO users (username, email, enabled, org_id)
		 VALUES ($1, $2, true, $3)
		 RETURNING id`, username, email, orgID).Scan(&id)
	require.NoError(t, err, "seed user %s in org %s", username, orgID)
	require.NoError(t, tx.Commit(ctx))
	return id
}

// bypassExec runs a statement with app.bypass_rls set so test cleanup can touch
// FORCE-RLS tables (a raw pool connection carries no org scope). Best-effort.
func bypassExec(t *testing.T, db *pgxpool.Pool, sql string, args ...interface{}) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `select set_config('app.bypass_rls', 'on', true)`); err != nil {
		return
	}
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

// bypassQueryRow runs an INSERT ... RETURNING (or any single-row query) under
// app.bypass_rls and scans the first column into dest. Used to seed FK parents on
// FORCE-RLS tables and capture their ids.
func bypassQueryRow(t *testing.T, db *pgxpool.Pool, dest interface{}, sql string, args ...interface{}) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `select set_config('app.bypass_rls', 'on', true)`)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(ctx, sql, args...).Scan(dest))
	require.NoError(t, tx.Commit(ctx))
}

// TestCrossOrgIsolation verifies the v1.7.0 enforcement guarantee: a request
// scoped (via X-Org-Slug) to org A cannot read org B's resource — it gets 404
// (anti-enumeration), not 403 — while the same resource reads 200 under org B.
//
// Requires the running stack (make dev-infra) with the tenant resolver wired and
// DefaultOrgFallback off. Run: make test-integration.
func TestCrossOrgIsolation(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	slugA := "xorg-a-" + suffix
	slugB := "xorg-b-" + suffix

	orgA := seedOrg(t, db, slugA)
	orgB := seedOrg(t, db, slugB)
	t.Cleanup(func() {
		bypassExec(t, db, "DELETE FROM organizations WHERE id IN ($1,$2)", orgA, orgB)
	})

	userB := seedUserInOrg(t, db, orgB, "xorg-user-"+suffix, "xorg-"+suffix+"@example.test")
	t.Cleanup(func() {
		bypassExec(t, db, "DELETE FROM users WHERE id = $1", userB)
	})

	token := getAdminToken(t)
	url := identityURL + "/api/v1/identity/users/" + userB

	t.Run("same org reads 200", func(t *testing.T) {
		status, _ := apiRequestWithOrg(t, "GET", url, "", token, slugB)
		assert.Equal(t, 200, status, "org B should read its own user")
	})

	t.Run("cross org reads 404 not 403", func(t *testing.T) {
		status, _ := apiRequestWithOrg(t, "GET", url, "", token, slugA)
		assert.Equal(t, 404, status, "org A must not see org B's user (404, anti-enumeration)")
	})

	t.Run("platform-admin X-Org-ID cross-org read is audited", func(t *testing.T) {
		before := crossOrgAuditCount(t, db, orgB)
		status, _ := apiRequestWithOrgID(t, "GET", url, "", token, orgB)
		if status != 200 {
			t.Skipf("admin is not a platform admin in this environment (status %d); skipping audited-bypass assertion", status)
		}
		// Give the synchronous audit insert a beat (it runs inline in the resolver).
		after := crossOrgAuditCount(t, db, orgB)
		assert.Greater(t, after, before, "platform-admin cross-org read must write an audit_events row")
	})
}

func crossOrgAuditCount(t *testing.T, db *pgxpool.Pool, orgID string) int {
	t.Helper()
	var n int
	err := db.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM audit_events
		 WHERE event_type = 'platform_admin_cross_org_access' AND org_id = $1`, orgID).Scan(&n)
	require.NoError(t, err)
	return n
}

// TestRLSBelt is the v1.8.0 ship gate: Row-Level Security blocks cross-tenant
// reads even when the app-layer filter is "broken" (a raw SELECT that forgets to
// scope by org). It asserts FORCE ROW LEVEL SECURITY is active (migration v37)
// and skips with guidance if not.
//
// Seeding uses the admin (superuser) pool with app.bypass_rls; the read
// assertions run on a connection from a dedicated NOSUPERUSER role, because a
// superuser ignores RLS entirely (even FORCE) and would make every assertion
// vacuous. That non-superuser connection mirrors how production connects to
// RDS. All assertion statements share one acquired connection so the session
// GUCs (set with set_config(...,false)) persist, mimicking the production pool
// checkout hook.
func TestRLSBelt(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()
	ctx := context.Background()

	var forced bool
	if err := db.QueryRow(ctx,
		`SELECT relforcerowsecurity FROM pg_class WHERE relname = 'users'`).Scan(&forced); err != nil {
		t.Fatalf("checking RLS state: %v", err)
	}
	if !forced {
		t.Skip("FORCE ROW LEVEL SECURITY not active on users — migration v37 not applied to this DB; skipping RLS belt test")
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	var orgA, orgB, userB string

	// Seed cross-org rows on the admin pool under bypass (FORCE RLS would
	// otherwise reject the WITH CHECK on the org-B insert from an unset-org
	// session).
	seed, err := db.Acquire(ctx)
	require.NoError(t, err)
	_, err = seed.Exec(ctx, `select set_config('app.bypass_rls','on',false)`)
	require.NoError(t, err)
	require.NoError(t, seed.QueryRow(ctx,
		`INSERT INTO organizations (name, slug, status) VALUES ($1,$2,'active') RETURNING id`,
		"RLS A "+suffix, "rls-a-"+suffix).Scan(&orgA))
	require.NoError(t, seed.QueryRow(ctx,
		`INSERT INTO organizations (name, slug, status) VALUES ($1,$2,'active') RETURNING id`,
		"RLS B "+suffix, "rls-b-"+suffix).Scan(&orgB))
	require.NoError(t, seed.QueryRow(ctx,
		`INSERT INTO users (username, email, enabled, org_id) VALUES ($1,$2,true,$3) RETURNING id`,
		"rls-user-"+suffix, "rls-"+suffix+"@example.test", orgB).Scan(&userB))
	seed.Release()
	t.Cleanup(func() {
		c, err := db.Acquire(context.Background())
		if err != nil {
			return
		}
		defer c.Release()
		_, _ = c.Exec(context.Background(), `select set_config('app.bypass_rls','on',false)`)
		_, _ = c.Exec(context.Background(), "DELETE FROM users WHERE id=$1", userB)
		_, _ = c.Exec(context.Background(), "DELETE FROM organizations WHERE id IN ($1,$2)", orgA, orgB)
	})

	// Assertions run as a NOSUPERUSER role so the policies actually apply.
	rolePool := rlsRolePool(t, db)
	defer rolePool.Close()
	conn, err := rolePool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	setScope := func(orgID, bypass string) {
		_, err := conn.Exec(ctx,
			`select set_config('app.org_id', $1, false), set_config('app.bypass_rls', $2, false)`,
			orgID, bypass)
		require.NoError(t, err)
	}
	count := func(where string, arg string) int {
		var n int
		require.NoError(t, conn.QueryRow(ctx, "SELECT count(*) FROM users WHERE "+where, arg).Scan(&n))
		return n
	}

	t.Run("scoped to org A: cannot see org B's user even by id (404-equivalent)", func(t *testing.T) {
		setScope(orgA, "off")
		assert.Equal(t, 0, count("org_id = $1", orgB), "org A must not see org B rows")
		assert.Equal(t, 0, count("id = $1", userB), "org A must not see org B's user by id")
	})

	t.Run("scoped to org B: sees its own user", func(t *testing.T) {
		setScope(orgB, "off")
		assert.Equal(t, 1, count("id = $1", userB), "org B sees its own user")
	})

	t.Run("no scope set: fail-closed (0 rows)", func(t *testing.T) {
		setScope("", "off")
		assert.Equal(t, 0, count("id = $1", userB), "unset app.org_id must read nothing")
	})

	t.Run("bypass: sees across orgs", func(t *testing.T) {
		setScope("", "on")
		assert.Equal(t, 1, count("id = $1", userB), "bypass sees org B's user from any session")
	})
}

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
		tag, err := conn.Exec(ctx, `UPDATE users SET email = 'x@example.test' WHERE id = $1`, userB)
		require.NoError(t, err)
		assert.Equal(t, int64(0), tag.RowsAffected(), "A-scoped UPDATE must not touch org B's row")
	})
	t.Run("DELETE of another org's row affects 0 rows", func(t *testing.T) {
		tag, err := conn.Exec(ctx, `DELETE FROM users WHERE id = $1`, userB)
		require.NoError(t, err)
		assert.Equal(t, int64(0), tag.RowsAffected(), "A-scoped DELETE must not touch org B's row")
	})
}

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
	t.Cleanup(func() { bypassExec(t, admin, "DELETE FROM organizations WHERE id IN ($1,$2)", orgA, orgB) })

	cases := []struct {
		table     string
		insertSQL string // one row; $1 = org_id
	}{
		{"users", `INSERT INTO users (username, email, enabled, org_id) VALUES ('tbelt-u-` + suffix + `','tbelt-u-` + suffix + `@example.test',true,$1)`},
		{"applications", `INSERT INTO applications (client_id, name, type, org_id) VALUES ('tbelt-app-` + suffix + `','tbelt app','web',$1)`},
		{"oauth_clients", `INSERT INTO oauth_clients (client_id, name, type, org_id) VALUES ('tbelt-oc-` + suffix + `','tbelt client','confidential',$1)`},
		{"audit_events", `INSERT INTO audit_events (event_type, category, action, outcome, org_id) VALUES ('tbelt','test','probe','success',$1)`},
		{"attestation_campaigns", `INSERT INTO attestation_campaigns (name, campaign_type, org_id) VALUES ('tbelt-att-` + suffix + `','role_certification',$1)`},
		// v138 — the tables internal/admin used to read and mutate across
		// tenants by bare id. The belt is what stops a query that forgets its
		// org predicate from seeing another tenant's posture findings, rules,
		// AI agents or recommendations.
		{"ispm_findings", `INSERT INTO ispm_findings (check_type, severity, category, title, org_id) VALUES ('tbelt','low','accounts','tbelt finding',$1)`},
		{"ispm_rules", `INSERT INTO ispm_rules (name, category, check_type, org_id) VALUES ('tbelt rule','accounts','tbelt-` + suffix + `',$1)`},
		{"ai_agents", `INSERT INTO ai_agents (name, org_id) VALUES ('tbelt-agent-` + suffix + `',$1)`},
		{"ai_recommendations", `INSERT INTO ai_recommendations (recommendation_type, category, title, org_id) VALUES ('tbelt','security','tbelt rec',$1)`},
		// v140 — a spread across the fifteen tables that carried org_id for as
		// long as nine migrations without the belt underneath it. email_branding
		// is the one that was actually leaking: both its handlers ignored the
		// caller's org entirely, so every tenant read and overwrote the same row.
		{"email_branding", `INSERT INTO email_branding (header_text, org_id) VALUES ('tbelt brand',$1)`},
		{"scheduled_reports", `INSERT INTO scheduled_reports (name, report_type, schedule, org_id) VALUES ('tbelt-rep-` + suffix + `','soc2','0 0 * * *',$1)`},
		{"brokered_sessions", `INSERT INTO brokered_sessions (user_id, target, principal, org_id) VALUES (gen_random_uuid(),'tbelt.example.test','root',$1)`},
		{"ssh_ca", `INSERT INTO ssh_ca (public_key, vault_secret_id, org_id) VALUES ('ssh-ed25519 tbelt',gen_random_uuid(),$1)`},
		{"entitlement_warehouse", `INSERT INTO entitlement_warehouse (user_id, entitlement_type, entitlement_id, source, org_id) VALUES (gen_random_uuid(),'role','tbelt-ent','direct',$1)`},
		{"upstream_pools", `INSERT INTO upstream_pools (name, org_id) VALUES ('tbelt-pool-` + suffix + `',$1)`},
		// v141 — the compliance record. The admin log was listed WHERE 1=1 and
		// fetched by bare id; archives were listed, fetched AND restored by bare
		// id, so a tenant could name another tenant's export and have the
		// product read that file back for them.
		{"admin_audit_log", `INSERT INTO admin_audit_log (action, target_type, org_id) VALUES ('tbelt.probe','settings',$1)`},
		{"audit_archives", `INSERT INTO audit_archives (name, org_id) VALUES ('tbelt-arch-` + suffix + `',$1)`},
		{"audit_retention_policies", `INSERT INTO audit_retention_policies (name, retention_days, org_id) VALUES ('tbelt-ret-` + suffix + `',30,$1)`},
		// v142 — the busiest audit surface in the product, and the one that was
		// actually being read across tenants: QueryEvents opened WHERE 1=1, so
		// the console's Unified Audit page showed every tenant's enforcement
		// decisions, actor IPs and (through its users JOIN) e-mail addresses to
		// every tenant's admin.
		{"unified_audit_events", `INSERT INTO unified_audit_events (source, event_type, org_id) VALUES ('tbelt','tbelt.probe',$1)`},
		// v143 — the sign-in tables. social_providers is the live one: its list
		// query put the org predicate inside a LEFT JOIN's ON clause, which
		// filters nothing on the driving table, and get/update/delete then took
		// a bare id. The other four were keyed by the org-scoped user_id, so the
		// belt is depth — except where trusted_browsers was updated by bare id
		// and phone_call_challenges carried a nullable user.
		//
		// trusted_browsers and user_risk_baselines carry a NOT NULL / primary-key
		// FK to users, so their probe row has to bring its own user along: a CTE
		// creates one in the same org and the insert reads its id back.
		{"social_providers", `INSERT INTO social_providers (provider_key, display_name, org_id) VALUES ('tbelt-` + suffix + `','tbelt provider',$1)`},
		{"trusted_browsers", `WITH u AS (
			INSERT INTO users (username, email, enabled, org_id)
			VALUES ('tbelt-tb-` + suffix + `','tbelt-tb-` + suffix + `@example.test',true,$1) RETURNING id)
			INSERT INTO trusted_browsers (user_id, browser_hash, expires_at, org_id)
			SELECT u.id,'tbelt-` + suffix + `',NOW() + INTERVAL '1 day',$1 FROM u`},
		{"passwordless_preferences", `INSERT INTO passwordless_preferences (user_id, org_id) VALUES (NULL,$1)`},
		{"user_risk_baselines", `WITH u AS (
			INSERT INTO users (username, email, enabled, org_id)
			VALUES ('tbelt-rb-` + suffix + `','tbelt-rb-` + suffix + `@example.test',true,$1) RETURNING id)
			INSERT INTO user_risk_baselines (user_id, org_id) SELECT u.id,$1 FROM u`},
		{"phone_call_challenges", `INSERT INTO phone_call_challenges (phone_number, code_hash, expires_at, org_id) VALUES ('+900000000','x',NOW() + INTERVAL '1 hour',$1)`},
		// v144 — the SAML surface. saml_service_providers holds the federation
		// partners' ACS URLs and certificates and was listed, counted, fetched,
		// updated and deleted install-wide, so one tenant could repoint another
		// tenant's assertions. entity_id stays UNIQUE across the install on
		// purpose (it is what resolves the tenant on an inbound request), which
		// is why the probe row's is suffixed rather than per-org.
		{"saml_service_providers", `INSERT INTO saml_service_providers (name, entity_id, acs_url, org_id) VALUES ('tbelt sp','https://tbelt-` + suffix + `.example.test/metadata','https://tbelt-` + suffix + `.example.test/acs',$1)`},
		{"saml_sessions", `WITH u AS (
			INSERT INTO users (username, email, enabled, org_id)
			VALUES ('tbelt-saml-` + suffix + `','tbelt-saml-` + suffix + `@example.test',true,$1) RETURNING id)
			INSERT INTO saml_sessions (user_id, sp_id, sp_entity_id, session_index, name_id, name_id_format, expires_at, org_id)
			SELECT u.id, gen_random_uuid(), 'https://tbelt-` + suffix + `.example.test/metadata','idx-` + suffix + `','tbelt@example.test','emailAddress',NOW() + INTERVAL '1 hour',$1 FROM u`},
		// v145 — the credentials that stand in for a password. hardware_tokens
		// is the live one: every call site took a bare id, so an administrator
		// of one tenant could enumerate another's inventory and, worse, bind a
		// token sitting available there to one of their own users. Unlike the
		// v143 per-user tables, an inventory row exists before any user does,
		// which is why its probe needs no CTE and its serial is suffixed
		// per-probe rather than per-org — v145 re-scoped that key to
		// (org_id, serial_number), the opposite call from v144's entity_id,
		// because a serial resolves no tenant.
		{"hardware_tokens", `INSERT INTO hardware_tokens (serial_number, name, token_type, secret_key, org_id) VALUES ('tbelt-` + suffix + `','tbelt token','oath-hotp','x',$1)`},
		{"hardware_token_events", `WITH t AS (
			INSERT INTO hardware_tokens (serial_number, name, token_type, secret_key, org_id)
			VALUES ('tbelt-evt-` + suffix + `','tbelt token','oath-hotp','x',$1) RETURNING id)
			INSERT INTO hardware_token_events (token_id, event_type, org_id) SELECT t.id,'tbelt.probe',$1 FROM t`},
		// generated_by is NOT NULL and references users, so the bypass probes
		// bring their own administrator along the way v143's per-user rows do.
		{"mfa_bypass_codes", `WITH u AS (
			INSERT INTO users (username, email, enabled, org_id)
			VALUES ('tbelt-bc-` + suffix + `','tbelt-bc-` + suffix + `@example.test',true,$1) RETURNING id)
			INSERT INTO mfa_bypass_codes (user_id, code_hash, reason, generated_by, valid_until, org_id)
			SELECT u.id,'x','tbelt probe',u.id,NOW() + INTERVAL '1 hour',$1 FROM u`},
		{"mfa_bypass_audit", `INSERT INTO mfa_bypass_audit (id, action, org_id) VALUES (gen_random_uuid(),'tbelt.probe',$1)`},
		{"magic_links", `WITH u AS (
			INSERT INTO users (username, email, enabled, org_id)
			VALUES ('tbelt-ml-` + suffix + `','tbelt-ml-` + suffix + `@example.test',true,$1) RETURNING id)
			INSERT INTO magic_links (user_id, email, token_hash, expires_at, org_id)
			SELECT u.id,'tbelt-ml-` + suffix + `@example.test','x',NOW() + INTERVAL '1 hour',$1 FROM u`},
		// v146 — the four second factors the belt had skipped while mfa_totp,
		// mfa_push_devices and mfa_webauthn already carried org_id. Each is
		// UNIQUE(user_id), so the probe brings its own user rather than
		// colliding with one an earlier case made; that UNIQUE is deliberately
		// NOT re-scoped to (org_id, user_id), because user_id already
		// determines org_id and the per-org key would additionally accept one
		// user enrolled in two organizations.
		{"mfa_sms", `WITH u AS (
			INSERT INTO users (username, email, enabled, org_id)
			VALUES ('tbelt-sms-` + suffix + `','tbelt-sms-` + suffix + `@example.test',true,$1) RETURNING id)
			INSERT INTO mfa_sms (user_id, phone_number, country_code, org_id)
			SELECT u.id,'5550000000','+1',$1 FROM u`},
		{"mfa_email_otp", `WITH u AS (
			INSERT INTO users (username, email, enabled, org_id)
			VALUES ('tbelt-eotp-` + suffix + `','tbelt-eotp-` + suffix + `@example.test',true,$1) RETURNING id)
			INSERT INTO mfa_email_otp (user_id, email_address, org_id)
			SELECT u.id,'tbelt-eotp-` + suffix + `@example.test',$1 FROM u`},
		{"mfa_phone_call", `WITH u AS (
			INSERT INTO users (username, email, enabled, org_id)
			VALUES ('tbelt-pc-` + suffix + `','tbelt-pc-` + suffix + `@example.test',true,$1) RETURNING id)
			INSERT INTO mfa_phone_call (user_id, phone_number, country_code, org_id)
			SELECT u.id,'5550000001','+1',$1 FROM u`},
		{"mfa_otp_challenges", `WITH u AS (
			INSERT INTO users (username, email, enabled, org_id)
			VALUES ('tbelt-otpc-` + suffix + `','tbelt-otpc-` + suffix + `@example.test',true,$1) RETURNING id)
			INSERT INTO mfa_otp_challenges (user_id, method, recipient, code_hash, expires_at, org_id)
			SELECT u.id,'sms','+15550000002','x',NOW() + INTERVAL '5 minutes',$1 FROM u`},
	}

	// One list, not two: the role is granted exactly the tables the cases probe.
	probed := make([]string, 0, len(cases))
	for _, c := range cases {
		probed = append(probed, c.table)
	}

	for _, c := range cases {
		c := c
		t.Run(c.table, func(t *testing.T) {
			requireForceRLS(t, admin, c.table)
			bypassExec(t, admin, c.insertSQL, orgB)
			t.Cleanup(func() { bypassExec(t, admin, "DELETE FROM "+c.table+" WHERE org_id = $1", orgB) })

			pool := rlsRolePool(t, admin, probed...)
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

// TestPreResolutionLookupsUnderRLS is the P0-2 regression guard. A class of
// lookups key off a globally-unique credential/host BEFORE the tenant org is
// known (API-key validation by key_hash, proxy route resolution by host), so
// they carry no org filter. Under the NOSUPERUSER role with no app.org_id set —
// exactly how those queries run before tenant resolution — FORCE RLS returns
// ZERO rows, which is the live break the v1.8 cutover caused (API-key auth and
// the whole access proxy failed closed). The production fix wraps each in
// orgctx.WithBypassRLS, which sets app.bypass_rls='on'. This test pins both:
// the failure mode (no scope → 0 rows) and the remedy (bypass → the row).
func TestPreResolutionLookupsUnderRLS(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()
	requireForceRLS(t, admin, "api_keys")
	requireForceRLS(t, admin, "proxy_routes")

	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgA := seedOrg(t, admin, "preres-a-"+suffix)
	// api_keys has a CHECK (user_id IS NOT NULL OR service_account_id IS NOT NULL).
	userA := seedUserInOrg(t, admin, orgA, "preres-user-"+suffix, "preres-"+suffix+"@example.test")

	keyHash := "preres-hash-" + suffix
	host := "preres-" + suffix + ".example.test"
	fromURL := "https://" + host
	bypassExec(t, admin,
		`INSERT INTO api_keys (name, key_prefix, key_hash, user_id, org_id) VALUES ($1,$2,$3,$4,$5)`,
		"preres-key-"+suffix, "oidx_pr", keyHash, userA, orgA)
	bypassExec(t, admin,
		`INSERT INTO proxy_routes (name, from_url, to_url, org_id) VALUES ($1,$2,$3,$4)`,
		"preres-route-"+suffix, fromURL, "http://upstream.test", orgA)
	t.Cleanup(func() {
		bypassExec(t, admin, "DELETE FROM api_keys WHERE key_hash=$1", keyHash)
		bypassExec(t, admin, "DELETE FROM proxy_routes WHERE from_url=$1", fromURL)
		bypassExec(t, admin, "DELETE FROM users WHERE id=$1", userA)
		bypassExec(t, admin, "DELETE FROM organizations WHERE id=$1", orgA)
	})

	// One NOSUPERUSER connection; GUCs set with set_config(...,false) persist for
	// the session, mirroring the production pool checkout hook.
	rolePool := rlsRolePool(t, admin)
	defer rolePool.Close()
	conn, err := rolePool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	setBypass := func(v string) {
		_, err := conn.Exec(ctx,
			`select set_config('app.org_id', '', false), set_config('app.bypass_rls', $1, false)`, v)
		require.NoError(t, err)
	}
	keyCount := func() int {
		var n int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT count(*) FROM api_keys WHERE key_hash = $1`, keyHash).Scan(&n))
		return n
	}
	routeCount := func() int {
		var n int
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT count(*) FROM proxy_routes WHERE from_url LIKE '%' || $1 || '%' AND enabled=true`, host).Scan(&n))
		return n
	}

	t.Run("no scope, no bypass: pre-resolution lookups fail closed (the live break)", func(t *testing.T) {
		setBypass("off")
		assert.Equal(t, 0, keyCount(), "api_keys by key_hash must be invisible with no org/bypass")
		assert.Equal(t, 0, routeCount(), "proxy_routes by host must be invisible with no org/bypass")
	})

	t.Run("bypass: pre-resolution lookups resolve (the WithBypassRLS remedy)", func(t *testing.T) {
		setBypass("on")
		assert.Equal(t, 1, keyCount(), "WithBypassRLS makes the API key visible for validation")
		assert.Equal(t, 1, routeCount(), "WithBypassRLS makes the route resolvable by host")
	})
}

// TestCrossOrgSpoofing proves the gateway is the security boundary for the
// client-supplied X-Org-Slug header: a request through the gateway (:8008)
// carrying a forged X-Org-Slug for another org is STRIPPED — the gateway
// re-derives org from the authenticated identity — so it cannot read the forged
// org's data. (Sending the header straight to a service is NOT a negative:
// services trust X-Org-Slug because the gateway sets it.) Skips if the gateway
// isn't reachable (CI may not start it; the box does).
func TestCrossOrgSpoofing(t *testing.T) {
	db := integrationDB(t)
	defer db.Close()

	if _, err := http.Get(gatewayURL + "/health"); err != nil {
		t.Skipf("gateway not reachable at %s (%v) — skipping X-Org-Slug strip test", gatewayURL, err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgB := seedOrg(t, db, "spoof-b-"+suffix)
	userB := seedUserInOrg(t, db, orgB, "spoof-userB-"+suffix, "spoof-b-"+suffix+"@example.test")
	t.Cleanup(func() {
		bypassExec(t, db, "DELETE FROM users WHERE id = $1", userB)
		bypassExec(t, db, "DELETE FROM organizations WHERE id = $1", orgB)
	})

	// Use the error-returning login directly so the test SKIPS (not fatals) when
	// admin auth isn't available in this environment (e.g. the OAuth test client's
	// redirect_uri isn't registered on a dev box); it runs fully in CI, where the
	// existing cross-org suite authenticates successfully.
	token, err := doAdminLogin()
	if err != nil {
		t.Skipf("admin login unavailable in this env (%v) — skipping gateway X-Org-Slug strip test", err)
	}
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

// TestRLSBeltJITAndApprovalChains is the W2.10 belt gate: jit_grants and
// request_approval_chains (given org_id + the FORCE-RLS belt by migration v64)
// are invisible cross-org. Both need FK parents, so they can't ride the generic
// TestRLSBeltTables loop; this seeds the parents under bypass and asserts an
// A-scoped NOSUPERUSER session sees zero of org B's rows while bypass sees them.
func TestRLSBeltJITAndApprovalChains(t *testing.T) {
	admin := integrationDB(t)
	defer admin.Close()
	requireForceRLS(t, admin, "jit_grants")
	requireForceRLS(t, admin, "request_approval_chains")

	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgA := seedOrg(t, admin, "jitbelt-a-"+suffix)
	orgB := seedOrg(t, admin, "jitbelt-b-"+suffix)
	userB := seedUserInOrg(t, admin, orgB, "jitbelt-u-"+suffix, "jitbelt-"+suffix+"@example.test")

	// Seed org B's FK parents + rows under bypass (FORCE RLS would reject an
	// unset-org WITH CHECK on the org-B inserts).
	var roleB, reqB string
	bypassQueryRow(t, admin, &roleB,
		`INSERT INTO roles (name, org_id) VALUES ($1,$2) RETURNING id`, "jitbelt-role-"+suffix, orgB)
	bypassExec(t, admin,
		`INSERT INTO jit_grants (org_id, user_id, role_id, role_name, justification, duration, expires_at)
		 VALUES ($1,$2,$3,'jitbelt-role','t',' 1h', NOW() + interval '1 hour')`, orgB, userB, roleB)
	bypassQueryRow(t, admin, &reqB,
		`INSERT INTO access_requests (requester_id, resource_type, resource_id, resource_name, status, org_id)
		 VALUES ($1,'role',gen_random_uuid(),'jitbelt','pending',$2) RETURNING id`, userB, orgB)
	bypassExec(t, admin,
		`INSERT INTO request_approval_chains (org_id, request_id, escalation_due_at)
		 VALUES ($1,$2, NOW() + interval '1 day')`, orgB, reqB)
	t.Cleanup(func() {
		bypassExec(t, admin, "DELETE FROM request_approval_chains WHERE org_id=$1", orgB)
		bypassExec(t, admin, "DELETE FROM jit_grants WHERE org_id=$1", orgB)
		bypassExec(t, admin, "DELETE FROM access_requests WHERE org_id=$1", orgB)
		bypassExec(t, admin, "DELETE FROM roles WHERE id=$1", roleB)
		bypassExec(t, admin, "DELETE FROM users WHERE id=$1", userB)
		bypassExec(t, admin, "DELETE FROM organizations WHERE id IN ($1,$2)", orgA, orgB)
	})

	pool := rlsRolePool(t, admin)
	defer pool.Close()
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	countB := func(table, bypass string) int {
		_, e := conn.Exec(ctx, `select set_config('app.org_id',$1,false), set_config('app.bypass_rls',$2,false)`, orgA, bypass)
		require.NoError(t, e)
		var n int
		require.NoError(t, conn.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE org_id = $1", orgB).Scan(&n))
		return n
	}
	for _, table := range []string{"jit_grants", "request_approval_chains"} {
		assert.Equal(t, 0, countB(table, ""), "A-scoped session must not see org B rows in %s", table)
		assert.Greater(t, countB(table, "on"), 0, "bypass must see org B rows in %s", table)
	}
}
