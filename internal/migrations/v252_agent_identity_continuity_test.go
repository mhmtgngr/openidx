package migrations_test

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestDuplicateFingerprintsCollapseToNewest applies v252 over a fleet in which
// one machine has two live rows under the same fingerprint (possible once the
// key excludes retired rows and a retire is reverted by hand, or by a restore
// merging two tenants' data) and checks that the newest stays, the others are
// retired, the hostname is backfilled, and the rebuilt key lets a retired row
// share a fingerprint with a live one. Down restores the old key.
func TestDuplicateFingerprintsCollapseToNewest(t *testing.T) {
	db, _, cleanup := adminPoolOrSkip(t)
	defer cleanup()
	ctx := context.Background()
	pool := db.Pool
	m := migrations.NewMigrator(pool.Raw(), zap.NewNop())
	if err := m.MigrateTo(ctx, 251); err != nil {
		t.Fatalf("migrate to 251: %v", err)
	}
	var org string
	if err := pool.QueryRow(ctx,
		"INSERT INTO organizations (name, slug) VALUES ('v252','v252') RETURNING id::text").Scan(&org); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	// The v197 key forbids two rows with one fingerprint, so drop it to seed
	// the duplicate shape the migration must survive.
	if _, err := pool.Exec(ctx, `DROP INDEX IF EXISTS enrolled_agents_org_device_fingerprint_key`); err != nil {
		t.Fatal(err)
	}
	seed := func(id, seen string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO enrolled_agents (agent_id, device_id, status, auth_token_hash, enrolled_at, last_seen_at,
			                             compliance_status, metadata, device_fingerprint, org_id)
			VALUES ($1, $1, 'active', 'h', NOW() - interval '30 days', NOW() - $2::interval,
			        'unknown', '{"hostname":"PC-DUP"}', 'win:dup', $3)`, id, seen, org); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("agent-old", "10 days")
	seed("agent-mid", "2 days")
	seed("agent-new", "1 hour")

	if err := m.MigrateTo(ctx, 252); err != nil {
		t.Fatalf("migrate to 252: %v", err)
	}
	status := func(id string) (s string, retired bool, host string) {
		t.Helper()
		if err := pool.QueryRow(ctx,
			`SELECT status, retired_at IS NOT NULL, COALESCE(hostname,'') FROM enrolled_agents WHERE agent_id = $1`, id).
			Scan(&s, &retired, &host); err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		return
	}
	if s, r, h := status("agent-new"); s != "active" || r || h != "PC-DUP" {
		t.Errorf("newest row: status=%q retired=%v hostname=%q, want active, live, PC-DUP", s, r, h)
	}
	for _, id := range []string{"agent-old", "agent-mid"} {
		if s, r, _ := status(id); s != "retired" || !r {
			t.Errorf("%s: status=%q retired_at set=%v, want retired", id, s, r)
		}
	}
	// A second live row under the fingerprint is refused; a retired one is not.
	if _, err := pool.Exec(ctx, `
		INSERT INTO enrolled_agents (agent_id, device_id, status, auth_token_hash, enrolled_at, compliance_status, device_fingerprint, org_id)
		VALUES ('agent-dup', 'agent-dup', 'active', 'h', NOW(), 'unknown', 'win:dup', $1)`, org); err == nil {
		t.Error("the rebuilt key admits a second live row for one fingerprint")
	}

	if err := m.RollbackTo(ctx, 251); err != nil {
		t.Fatalf("down to 251: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM enrolled_agents WHERE device_fingerprint = 'win:dup' AND org_id = $1`, org).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("after down %d rows keep the fingerprint, want 1 (retired rows give theirs up)", n)
	}
}
