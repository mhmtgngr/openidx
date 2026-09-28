// Package migrations_test, not migrations, so that it can reach
// adminPoolOrSkip in least_privilege_owner_test.go.
package migrations_test

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/migrations"
)

// TestV207KeepsEnrolledCredentialsAndRecordsTheAcceptedStep applies v207 over
// an install that already has a TOTP credential, and checks that the credential
// reads as having accepted no step yet -- so its owner's next code is accepted
// -- that the verifier's conditional UPDATE admits a step once and refuses it,
// or an earlier one, afterwards, and that rolling back removes the column.
func TestV207KeepsEnrolledCredentialsAndRecordsTheAcceptedStep(t *testing.T) {
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
	if err := m.MigrateTo(ctx, 206); err != nil {
		t.Fatalf("migrate to the version before it: %v", err)
	}

	var org, user string
	if err := pool.QueryRow(ctx,
		"SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1").Scan(&org); err != nil {
		t.Fatalf("read the oldest org: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (org_id, username, email, enabled) VALUES ($1::uuid, 'v207-user', 'v207-user@example.test', true)
		RETURNING id::text`, org).Scan(&user); err != nil {
		t.Fatalf("seed a user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO mfa_totp (user_id, secret, enabled, enrolled_at, org_id)
		VALUES ($1::uuid, 'JBSWY3DPEHPK3PXP', true, NOW(), $2::uuid)`, user, org); err != nil {
		t.Fatalf("seed a TOTP credential enrolled before v207: %v", err)
	}

	if err := m.MigrateTo(ctx, 207); err != nil {
		t.Fatalf("migrate to 207: %v", err)
	}

	var last int64
	if err := pool.QueryRow(ctx, `SELECT last_step FROM mfa_totp WHERE user_id = $1::uuid`, user).Scan(&last); err != nil {
		t.Fatalf("read last_step: %v", err)
	}
	if last != 0 {
		t.Fatalf("a credential enrolled before v207 reads last_step %d, want 0", last)
	}

	// The verifier's statement, for a step in 2026.
	accept := func(step int64) bool {
		t.Helper()
		tag, err := pool.Exec(ctx, `
			UPDATE mfa_totp SET last_step = $2
			WHERE user_id = $1::uuid AND org_id = $3::uuid AND enabled AND last_step < $2`, user, step, org)
		if err != nil {
			t.Fatalf("accept step %d: %v", step, err)
		}
		return tag.RowsAffected() == 1
	}
	const step = int64(59_000_000)
	if !accept(step) {
		t.Fatal("the credential's first code after the upgrade was refused")
	}
	if accept(step) {
		t.Fatal("the same step was accepted twice")
	}
	if accept(step - 1) {
		t.Fatal("an earlier step was accepted after a later one")
	}
	if !accept(step + 1) {
		t.Fatal("the next step was refused")
	}

	if err := m.RollbackTo(ctx, 206); err != nil {
		t.Fatalf("roll back past 207: %v", err)
	}
	var columns int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_name = 'mfa_totp' AND column_name = 'last_step'`).Scan(&columns); err != nil {
		t.Fatalf("look for the column: %v", err)
	}
	if columns != 0 {
		t.Error("rolling back v207 left mfa_totp.last_step behind")
	}
}
