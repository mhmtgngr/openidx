package migrations

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// TestV172SSFReceivedTenant applies v172 over a ledger whose rows carry the
// NULL tenant every install has, and checks the three things the migration is
// for: the backfill attributes them, the key becomes per-organization, and the
// down migration returns the install-wide key.
//
// The point of the composite key is the second assertion. Before v172 jti was
// the table's PRIMARY KEY, so two organizations could not both record the same
// SET id — the second INSERT would hit ON CONFLICT (jti) DO NOTHING, the event
// would already have been applied, and that tenant would lose replay protection
// for it from then on.
func TestV172SSFReceivedTenant(t *testing.T) {
	url := os.Getenv("OPENIDX_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("OPENIDX_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("connect: %v", err)
	}
	defer pool.Close()

	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("reset schema (%s): %v", stmt, err)
		}
	}
	m := NewMigrator(pool, zap.NewNop())

	// Stop one short of v172 and seed the shape the table has had since v99:
	// a recorded inbound event with no tenant at all.
	if err := m.MigrateTo(ctx, 171); err != nil {
		t.Fatalf("migrate to 171: %v", err)
	}
	var orgA, orgB string
	if err := pool.QueryRow(ctx,
		"SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1").Scan(&orgA); err != nil {
		t.Fatalf("read the oldest org: %v", err)
	}
	if err := pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ('ssf-b','ssf-b') RETURNING id::text").Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO ssf_received_events (jti, issuer, event_type, subject, outcome)
		VALUES ('jti-legacy', 'https://idp.example', 'session-revoked', 'a@x.test', 'applied')`); err != nil {
		t.Fatalf("seed a tenantless ledger row: %v", err)
	}
	var nullBefore int
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM ssf_received_events WHERE org_id IS NULL").Scan(&nullBefore)
	if nullBefore != 1 {
		t.Fatalf("seeded %d tenantless rows, want 1 — the fixture is not reproducing the shape v172 fixes", nullBefore)
	}

	if err := m.MigrateTo(ctx, 172); err != nil {
		t.Fatalf("migrate to 172: %v", err)
	}

	var nullAfter int
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM ssf_received_events WHERE org_id IS NULL").Scan(&nullAfter)
	if nullAfter != 0 {
		t.Errorf("%d ledger rows still carry a NULL tenant after v172", nullAfter)
	}
	var owner string
	if err := pool.QueryRow(ctx,
		"SELECT org_id::text FROM ssf_received_events WHERE jti='jti-legacy'").Scan(&owner); err != nil {
		t.Fatalf("read the backfilled row: %v", err)
	}
	if owner != orgA {
		t.Errorf("the legacy row was attributed to %s, want the oldest organization %s", owner, orgA)
	}

	// The key is now per-organization: the same SET id may be recorded once for
	// each tenant that received it.
	if _, err := pool.Exec(ctx, `
		INSERT INTO ssf_received_events (jti, org_id, issuer, outcome)
		VALUES ('jti-shared', $1::uuid, 'https://idp.example', 'applied')`, orgA); err != nil {
		t.Fatalf("org A record jti-shared: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO ssf_received_events (jti, org_id, issuer, outcome)
		VALUES ('jti-shared', $1::uuid, 'https://idp.example', 'applied')`, orgB); err != nil {
		t.Errorf("org B could not record the same SET id org A recorded (%v). With an "+
			"install-wide jti key the second tenant applies the event and fails to "+
			"record it, so it loses replay protection for that event", err)
	}
	// And still exactly once per tenant.
	if _, err := pool.Exec(ctx, `
		INSERT INTO ssf_received_events (jti, org_id, issuer, outcome)
		VALUES ('jti-shared', $1::uuid, 'https://idp.example', 'applied')`, orgB); err == nil {
		t.Error("the same SET id was recorded twice for one organization — replay protection is gone")
	}

	// Down returns the install-wide key, dropping the duplicate it cannot hold.
	if err := m.RollbackTo(ctx, 171); err != nil {
		t.Fatalf("rollback to 171: %v", err)
	}
	var dup int
	_ = pool.QueryRow(ctx, "SELECT COUNT(*) FROM ssf_received_events WHERE jti='jti-shared'").Scan(&dup)
	if dup != 1 {
		t.Errorf("after rollback jti-shared appears %d times, want 1 under the install-wide key", dup)
	}
	if err := m.MigrateTo(ctx, 172); err != nil {
		t.Fatalf("re-apply 172: %v", err)
	}
}
