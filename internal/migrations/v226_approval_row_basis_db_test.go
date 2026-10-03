package migrations_test

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV226RecordsWhyAnApproverIsOnTheRow applies v226 over a database holding
// an approval row written before it:
//
//   - the row keeps no basis, which governance decides as before;
//   - a new row takes a basis from the allowed set, and the CHECK refuses any
//     other;
//   - rolling back drops the constraint and both columns.
func TestV226RecordsWhyAnApproverIsOnTheRow(t *testing.T) {
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
	if err := m.MigrateTo(ctx, 225); err != nil {
		t.Fatalf("migrate to 225: %v", err)
	}
	var org string
	if err := pool.QueryRow(ctx, "SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1").Scan(&org); err != nil {
		t.Fatalf("read the oldest org: %v", err)
	}
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email) VALUES ($1::uuid, $2::text, $2::text || '@example.test') RETURNING id::text`, org, name)
	}
	requester, approver := user("v226-requester"), user("v226-approver")
	request := scalar(`INSERT INTO access_requests (org_id, requester_id, resource_type, resource_id, resource_name, justification, status)
		VALUES ($1::uuid, $2::uuid, 'role', gen_random_uuid(), 'role', 'release', 'pending') RETURNING id::text`, org, requester)
	old := scalar(`INSERT INTO access_request_approvals (org_id, request_id, approver_id, step_order, decision)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 1, 'pending') RETURNING id::text`, org, request, approver)

	if err := m.MigrateTo(ctx, 226); err != nil {
		t.Fatalf("migrate to 226: %v", err)
	}
	if got := scalar(`SELECT COALESCE(approver_basis, '<none>') FROM access_request_approvals WHERE id = $1::uuid`, old); got != "<none>" {
		t.Errorf("a row written before v226 has basis %q, want none", got)
	}
	role := scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1::uuid, 'v226-approvers', '') RETURNING id::text`, org)
	if _, err := pool.Exec(ctx, `INSERT INTO access_request_approvals (org_id, request_id, approver_id, step_order, decision, approver_basis, approver_basis_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 2, 'pending', 'role', $4::uuid)`, org, request, approver, role); err != nil {
		t.Errorf("a row with a role basis was refused: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_request_approvals (org_id, request_id, approver_id, step_order, decision, approver_basis)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 3, 'pending', 'friendship')`, org, request, approver); err == nil {
		t.Error("the CHECK accepted a basis outside the allowed set")
	}

	if err := m.RollbackTo(ctx, 225); err != nil {
		t.Fatalf("roll back to 225: %v", err)
	}
	if v, err := m.Version(ctx); err != nil || v != 225 {
		t.Fatalf("after the rollback the version is %d, %v; want 225", v, err)
	}
	if got := scalar(`SELECT count(*)::text FROM information_schema.columns
		WHERE table_name = 'access_request_approvals' AND column_name IN ('approver_basis', 'approver_basis_id')`); got != "0" {
		t.Errorf("after the rollback %s basis column(s) remain, want 0", got)
	}
}
