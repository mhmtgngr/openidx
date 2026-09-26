// Package migrations_test, not migrations, so that it can reach
// adminPoolOrSkip in least_privilege_owner_test.go.
package migrations_test

import (
	"context"
	"regexp"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV206KeepsVerifiedDomainsAndLetsClaimsCoexist applies v206 over tenant
// domains as v38 left them -- verified and pending, with and without a token,
// one with no verified value at all -- and checks that a verified domain stays
// verified, every pending claim has a token afterwards and keeps the one it had,
// a second organization may now claim a domain another has claimed, only one
// claim to a domain can be verified, and rolling back restores the install-wide
// UNIQUE once, and only once, no domain is claimed twice.
func TestV206KeepsVerifiedDomainsAndLetsClaimsCoexist(t *testing.T) {
	db, _, cleanup := adminPoolOrSkip(t)
	defer cleanup()
	ctx := context.Background()
	pool := db.Pool

	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("reset schema (%s): %v", stmt, err)
		}
	}
	m := migrations.NewMigrator(pool.Raw(), zap.NewNop())
	if err := m.MigrateTo(ctx, 205); err != nil {
		t.Fatalf("migrate to 205: %v", err)
	}

	exec := func(query string, args ...interface{}) error {
		t.Helper()
		_, err := pool.Exec(ctx, query, args...)
		return err
	}
	scalar := func(query string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := pool.QueryRow(ctx, query, args...).Scan(&v); err != nil {
			t.Fatalf("read %q: %v", query, err)
		}
		return v
	}
	orgX := scalar(`INSERT INTO organizations (name, slug, status) VALUES ('v206 x', 'v206-x', 'active') RETURNING id::text`)
	orgY := scalar(`INSERT INTO organizations (name, slug, status) VALUES ('v206 y', 'v206-y', 'active') RETURNING id::text`)
	for _, row := range []struct {
		org, domain string
		verified    interface{}
		token       interface{}
	}{
		{orgX, "kept.v206.test", true, nil},                // verified by hand, no token
		{orgX, "pending.v206.test", false, nil},            // pending, no token
		{orgY, "tokened.v206.test", false, "existing-tok"}, // pending, issued a token by the API
		{orgY, "unknown.v206.test", nil, "other-tok"},      // no verified value at all
	} {
		if err := exec(`INSERT INTO tenant_domains (org_id, domain, domain_type, verified, verification_token)
			VALUES ($1::uuid, $2, 'custom', $3, $4)`, row.org, row.domain, row.verified, row.token); err != nil {
			t.Fatalf("seed %s: %v", row.domain, err)
		}
	}
	// v38: one claim per domain across the install, verified or not.
	if err := exec(`INSERT INTO tenant_domains (org_id, domain) VALUES ($1::uuid, 'pending.v206.test')`, orgY); err == nil {
		t.Fatal("before v206 a second organization could claim a claimed domain; the test is not starting from v38's schema")
	}

	if err := m.MigrateTo(ctx, 206); err != nil {
		t.Fatalf("migrate to 206: %v", err)
	}

	state := func(domain string) (verified, token string) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT verified::text, COALESCE(verification_token, '') FROM tenant_domains WHERE domain = $1 ORDER BY created_at LIMIT 1`,
			domain).Scan(&verified, &token); err != nil {
			t.Fatalf("read %s: %v", domain, err)
		}
		return verified, token
	}
	if v, tok := state("kept.v206.test"); v != "true" || tok != "" {
		t.Errorf("a verified domain after v206: verified=%s token=%q, want true and untouched", v, tok)
	}
	generated := regexp.MustCompile(`^[0-9a-f]{32}$`)
	if v, tok := state("pending.v206.test"); v != "false" || !generated.MatchString(tok) {
		t.Errorf("a pending claim with no token after v206: verified=%s token=%q, want false and a 32-hex token", v, tok)
	}
	if v, tok := state("tokened.v206.test"); v != "false" || tok != "existing-tok" {
		t.Errorf("a pending claim with a token after v206: verified=%s token=%q, want false and the token it had", v, tok)
	}
	if v, _ := state("unknown.v206.test"); v != "false" {
		t.Errorf("a claim with no verified value after v206: verified=%s, want false", v)
	}
	if got := scalar(`SELECT is_nullable FROM information_schema.columns WHERE table_name = 'tenant_domains' AND column_name = 'verified'`); got != "NO" {
		t.Errorf("tenant_domains.verified is_nullable = %s, want NO", got)
	}

	// Claims coexist; verification is unique; one claim per organization.
	if err := exec(`INSERT INTO tenant_domains (org_id, domain, verification_token) VALUES ($1::uuid, 'pending.v206.test', 'y-token')`, orgY); err != nil {
		t.Errorf("a second organization's claim to a pending domain was refused: %v", err)
	}
	if err := exec(`INSERT INTO tenant_domains (org_id, domain, verified) VALUES ($1::uuid, 'kept.v206.test', true)`, orgY); err == nil {
		t.Error("a second verified claim to a verified domain was stored")
	}
	if err := exec(`INSERT INTO tenant_domains (org_id, domain, verification_token) VALUES ($1::uuid, 'kept.v206.test', 'dup')`, orgX); err == nil {
		t.Error("an organization claimed a domain it already holds a second time")
	}

	// Rolling back cannot restore one claim per domain while two exist.
	if err := m.RollbackTo(ctx, 205); err == nil {
		t.Fatal("rolled back to 205 with two organizations claiming one domain; the UNIQUE it restores cannot hold")
	}
	if err := exec(`DELETE FROM tenant_domains WHERE org_id = $1::uuid AND domain = 'pending.v206.test'`, orgY); err != nil {
		t.Fatalf("remove the second claim: %v", err)
	}
	if err := m.RollbackTo(ctx, 205); err != nil {
		t.Fatalf("roll back to 205: %v", err)
	}
	if err := exec(`INSERT INTO tenant_domains (org_id, domain) VALUES ($1::uuid, 'pending.v206.test')`, orgY); err == nil {
		t.Error("after rolling back v206 a second organization can still claim a claimed domain")
	}
}
