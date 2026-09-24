// Package migrations_test, not migrations, so that it can reach
// adminPoolOrSkip in least_privilege_owner_test.go.
package migrations_test

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV203UpgradeChangesNoPolicy applies v203 over the policies an install can
// hold before it: one with required methods and a grace period, as the console
// wrote them before #991, and one that took the old 24-hour column default. No
// code enforced either value, so after the upgrade both must read as a policy
// that accepts any enrolled factor with no grace period, which is what they
// did. The windows table must then keep one row per user per policy, lose the
// rows with the policy or the user, and go away on rollback.
func TestV203UpgradeChangesNoPolicy(t *testing.T) {
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
	if err := m.MigrateTo(ctx, 202); err != nil {
		t.Fatalf("migrate to 202: %v", err)
	}

	var org string
	if err := pool.QueryRow(ctx,
		"SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1").Scan(&org); err != nil {
		t.Fatalf("read the oldest org: %v", err)
	}
	var legacy, defaulted string
	if err := pool.QueryRow(ctx, `
		INSERT INTO mfa_policies (name, enabled, priority, conditions, required_methods, grace_period_hours, org_id)
		VALUES ('webauthn-only', true, 10, '{}', '["webauthn"]', 72, $1::uuid) RETURNING id::text`, org).Scan(&legacy); err != nil {
		t.Fatalf("seed a policy with methods: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO mfa_policies (name, enabled, priority, org_id)
		VALUES ('everyone', true, 20, $1::uuid) RETURNING id::text`, org).Scan(&defaulted); err != nil {
		t.Fatalf("seed a policy on the column defaults: %v", err)
	}
	var before int
	if err := pool.QueryRow(ctx, `SELECT grace_period_hours FROM mfa_policies WHERE id = $1::uuid`, defaulted).Scan(&before); err != nil {
		t.Fatalf("read the defaulted policy: %v", err)
	}
	if before != 24 {
		t.Fatalf("the column default gave %d hours before v203, want 24: the fixture is not the shape v203 clears", before)
	}

	if err := m.MigrateTo(ctx, 203); err != nil {
		t.Fatalf("migrate to 203: %v", err)
	}

	for _, id := range []string{legacy, defaulted} {
		var methods string
		var grace int
		if err := pool.QueryRow(ctx,
			`SELECT required_methods::text, grace_period_hours FROM mfa_policies WHERE id = $1::uuid`, id).Scan(&methods, &grace); err != nil {
			t.Fatalf("read policy %s: %v", id, err)
		}
		if methods != "[]" || grace != 0 {
			t.Errorf("policy %s kept required_methods %s and grace %d after v203; nothing enforced them before, so the upgrade would start windows nobody chose", id, methods, grace)
		}
	}
	var fresh string
	var freshGrace int
	if err := pool.QueryRow(ctx, `
		INSERT INTO mfa_policies (name, enabled, priority, org_id)
		VALUES ('after-v203', true, 30, $1::uuid) RETURNING id::text, grace_period_hours`, org).Scan(&fresh, &freshGrace); err != nil {
		t.Fatalf("insert a policy after v203: %v", err)
	}
	if freshGrace != 0 {
		t.Errorf("a new policy gets a %d-hour grace period by default, want 0", freshGrace)
	}

	// One window per user per policy.
	var user string
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (username, email, enabled, org_id)
		VALUES ('v203-user', 'v203-user@test.local', true, $1::uuid) RETURNING id::text`, org).Scan(&user); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	record := func(policy string) (bool, error) {
		tag, err := pool.Exec(ctx, `
			INSERT INTO mfa_policy_grace (org_id, policy_id, user_id) VALUES ($1::uuid, $2::uuid, $3::uuid)
			ON CONFLICT (policy_id, user_id) DO NOTHING`, org, policy, user)
		return tag.RowsAffected() == 1, err
	}
	if wrote, err := record(legacy); err != nil || !wrote {
		t.Fatalf("record the first window: wrote=%v err=%v", wrote, err)
	}
	if wrote, err := record(legacy); err != nil || wrote {
		t.Fatalf("a second sign-in rewrote the window's start (wrote=%v err=%v); it must keep the first", wrote, err)
	}
	if wrote, err := record(fresh); err != nil || !wrote {
		t.Fatalf("record a window under a second policy: wrote=%v err=%v", wrote, err)
	}
	windows := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM mfa_policy_grace WHERE user_id = $1::uuid`, user).Scan(&n); err != nil {
			t.Fatalf("count windows: %v", err)
		}
		return n
	}
	if n := windows(); n != 2 {
		t.Fatalf("%d windows, want 2", n)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM mfa_policies WHERE id = $1::uuid`, legacy); err != nil {
		t.Fatalf("delete a policy: %v", err)
	}
	if n := windows(); n != 1 {
		t.Errorf("%d windows after their policy was deleted, want 1", n)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, user); err != nil {
		t.Fatalf("delete the user: %v", err)
	}
	if n := windows(); n != 0 {
		t.Errorf("%d windows after their user was deleted, want 0", n)
	}

	// Down drops the table and restores the old default; the chain applies again.
	if err := m.RollbackTo(ctx, 202); err != nil {
		t.Fatalf("rollback to 202: %v", err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.mfa_policy_grace') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatalf("look for the table: %v", err)
	}
	if exists {
		t.Error("mfa_policy_grace survived the rollback")
	}
	var restored int
	if err := pool.QueryRow(ctx, `
		INSERT INTO mfa_policies (name, enabled, priority, org_id)
		VALUES ('after-rollback', true, 40, $1::uuid) RETURNING grace_period_hours`, org).Scan(&restored); err != nil {
		t.Fatalf("insert a policy after rollback: %v", err)
	}
	if restored != 24 {
		t.Errorf("after rollback a new policy gets %d hours by default, want the old 24", restored)
	}
	if err := m.MigrateTo(ctx, 203); err != nil {
		t.Fatalf("re-apply 203: %v", err)
	}
}
