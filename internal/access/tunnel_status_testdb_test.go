package access

import (
	"context"
	"reflect"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// The fleet gauges on the migrated schema, across two organizations: agents
// per status; active devices per reported gap (once per gap however the list
// repeats it, a suspended device's gaps and a name outside the vocabulary not
// counted, a value that is not a list read as no gaps); the tunnel-down
// count; and the cache that answers a scrape from the previous figures until
// the window has passed.
func TestFleetGaugesCountTheFleetOnTheMigratedSchema(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	if err := db.Pool.QueryRow(bg, `INSERT INTO organizations (name, slug) VALUES ('fleet-gauges-b', 'fleet-gauges-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	seed := func(id, org, status, tunnel string) {
		t.Helper()
		if _, err := db.Pool.Exec(bg, `INSERT INTO enrolled_agents
			(agent_id, device_id, auth_token_hash, status, org_id, last_seen_at, tunnel_status, tunnel_last_seen)
			VALUES ($1, $1, 'x', $2, $3, NOW(), NULLIF($4, '')::jsonb,
			        CASE WHEN NULLIF($4, '')::jsonb->>'state' = 'up' THEN NOW() END)`, id, status, org, tunnel); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("fg-a1", orgA, "active", `{"state":"up","policy_gaps":["block_direct"]}`)
	seed("fg-a2", orgA, "active", `{"state":"down","policy_gaps":["full_tunnel","block_direct","block_direct","bogus"]}`)
	seed("fg-a3", orgA, "active", `{"state":"up"}`)
	seed("fg-a4", orgA, "pending", "")
	seed("fg-a5", orgA, "suspended", `{"state":"up","policy_gaps":["full_tunnel"]}`)
	seed("fg-a6", orgA, "revoked", "")
	seed("fg-b1", orgB, "active", `{"state":"off","policy_gaps":["full_tunnel"]}`)
	seed("fg-b2", orgB, "active", `{"state":"up","policy_gaps":"not-a-list"}`)

	c := newFleetCollector(db, zap.NewNop())
	reg := fleetRegistry(t, c)
	want := map[string]float64{
		"openidx_agents_by_state{state=active}":        5,
		"openidx_agents_by_state{state=pending}":       1,
		"openidx_agents_by_state{state=suspended}":     1,
		"openidx_agents_by_state{state=revoked}":       1,
		"openidx_tunnel_policy_gaps{gap=full_tunnel}":  2,
		"openidx_tunnel_policy_gaps{gap=block_direct}": 2,
	}
	if got := gatherFleet(t, reg); !reflect.DeepEqual(got, want) {
		t.Errorf("series = %v, want %v", got, want)
	}

	// Only fg-a2 is down: fg-a1, fg-a3 and fg-b2 are up and were seen up,
	// fg-b1's tunnel is off, fg-a5 is not active.
	if n, err := countTunnelDown(bg, db); err != nil || n != 1 {
		t.Errorf("tunnel-down count = %v, %v; want 1", n, err)
	}

	// The fleet moves; a scrape inside the window still sees the figures above.
	if _, err := db.Pool.Exec(bg, `UPDATE enrolled_agents SET status = 'revoked', tunnel_status = NULL WHERE agent_id = 'fg-a1'`); err != nil {
		t.Fatalf("revoke fg-a1: %v", err)
	}
	if got := gatherFleet(t, reg); !reflect.DeepEqual(got, want) {
		t.Errorf("a scrape inside the window did not answer from the cache: %v, want %v", got, want)
	}
	c.cache.at = time.Now().Add(-gaugeRefresh - time.Second)
	moved := map[string]float64{
		"openidx_agents_by_state{state=active}":        4,
		"openidx_agents_by_state{state=pending}":       1,
		"openidx_agents_by_state{state=suspended}":     1,
		"openidx_agents_by_state{state=revoked}":       2,
		"openidx_tunnel_policy_gaps{gap=full_tunnel}":  2,
		"openidx_tunnel_policy_gaps{gap=block_direct}": 1,
	}
	if got := gatherFleet(t, reg); !reflect.DeepEqual(got, moved) {
		t.Errorf("a scrape after the window = %v, want %v", got, moved)
	}
}
