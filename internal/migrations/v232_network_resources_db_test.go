package migrations_test

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV232NetworkTargetsHoldWhatANetworkResourceCovers applies v232 and
// checks the table's own refusals, then rolls back:
//
//   - a target with an address, a CIDR and a port range is stored, and its
//     protocols default to tcp and udp;
//   - a target with no address at all, or a protocol other than tcp/udp, or a
//     forward port outside 1-65535, is refused by the table;
//   - deleting the application deletes its target;
//   - the agent's tunnel columns exist, and rolling back to 231 removes the
//     tables and the columns.
func TestV232NetworkTargetsHoldWhatANetworkResourceCovers(t *testing.T) {
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
	if err := m.MigrateTo(ctx, 232); err != nil {
		t.Fatalf("migrate to 232: %v", err)
	}
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	org := scalar("SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1")
	app := scalar(`INSERT INTO applications (client_id, name, type, kind, org_id)
		VALUES ('network-v232', 'File servers', 'network', 'network', $1::uuid) RETURNING id::text`, org)

	if _, err := pool.Exec(ctx, `INSERT INTO network_targets (application_id, org_id, hosts, cidrs, port_ranges)
		VALUES ($1::uuid, $2::uuid, '{fs1.corp.example}', '{10.0.0.0/16}', '[{"low":445,"high":445}]')`, app, org); err != nil {
		t.Fatalf("a target with a host, a CIDR and a port range was refused: %v", err)
	}
	if got := scalar(`SELECT array_to_string(protocols, ',') FROM network_targets WHERE application_id = $1::uuid`, app); got != "tcp,udp" {
		t.Errorf("protocols defaulted to %q, want tcp,udp", got)
	}

	other := scalar(`INSERT INTO applications (client_id, name, type, kind, org_id)
		VALUES ('network-v232-b', 'Nothing', 'network', 'network', $1::uuid) RETURNING id::text`, org)
	for name, stmt := range map[string]string{
		"no address":       `INSERT INTO network_targets (application_id, org_id) VALUES ($1::uuid, $2::uuid)`,
		"protocol icmp":    `INSERT INTO network_targets (application_id, org_id, hosts, protocols) VALUES ($1::uuid, $2::uuid, '{a}', '{icmp}')`,
		"forward port 0":   `INSERT INTO network_targets (application_id, org_id, hosts, forward_port) VALUES ($1::uuid, $2::uuid, '{a}', 0)`,
		"not a cidr value": `INSERT INTO network_targets (application_id, org_id, cidrs) VALUES ($1::uuid, $2::uuid, '{not-a-cidr}')`,
	} {
		if _, err := pool.Exec(ctx, stmt, other, org); err == nil {
			t.Errorf("the table accepted a target with %s", name)
		}
	}

	if _, err := pool.Exec(ctx, `DELETE FROM applications WHERE id = $1::uuid`, app); err != nil {
		t.Fatalf("delete application: %v", err)
	}
	if got := scalar(`SELECT count(*)::text FROM network_targets WHERE application_id = $1::uuid`, app); got != "0" {
		t.Errorf("the target outlived its application (%s rows)", got)
	}
	if got := scalar(`SELECT count(*)::text FROM information_schema.columns
		WHERE table_name = 'enrolled_agents' AND column_name IN ('tunnel_status', 'tunnel_last_seen')`); got != "2" {
		t.Errorf("enrolled_agents has %s tunnel column(s), want 2", got)
	}

	if err := m.RollbackTo(ctx, 231); err != nil {
		t.Fatalf("roll back to 231: %v", err)
	}
	if got := scalar(`SELECT count(*)::text FROM information_schema.tables
		WHERE table_name IN ('network_targets', 'org_network_policy')`); got != "0" {
		t.Errorf("after the rollback %s table(s) remain, want 0", got)
	}
	if got := scalar(`SELECT count(*)::text FROM information_schema.columns
		WHERE table_name = 'enrolled_agents' AND column_name IN ('tunnel_status', 'tunnel_last_seen')`); got != "0" {
		t.Errorf("after the rollback %s tunnel column(s) remain, want 0", got)
	}
}
