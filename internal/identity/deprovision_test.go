package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// TestDeprovisionUser verifies the revocation fan-out: a disabled/deleted user's
// live sessions and API keys must be revoked (soft) or removed (hard). Redis is
// nil here — the marker-publish path is guarded and skipped, which is the exact
// degraded behavior when no Redis is wired.
func TestDeprovisionUser(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Minimal schema covering just the columns deprovisionUser touches.
	schema := []string{
		`CREATE TABLE sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL, org_id UUID NOT NULL,
			revoked BOOLEAN DEFAULT false, revoked_at TIMESTAMPTZ)`,
		`CREATE TABLE user_sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL)`,
		`CREATE TABLE api_keys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID, org_id UUID, status VARCHAR(50) DEFAULT 'active')`,
	}
	for _, s := range schema {
		if _, err := db.Pool.Exec(ctx, s); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	user := "11111111-1111-1111-1111-111111111111"
	other := "22222222-2222-2222-2222-222222222222"
	org := "33333333-3333-3333-3333-333333333333"

	seed := func() {
		db.Pool.Exec(ctx, `TRUNCATE sessions, user_sessions, api_keys`)
		db.Pool.Exec(ctx, `INSERT INTO sessions (user_id, org_id, revoked) VALUES ($1,$2,false)`, user, org)
		db.Pool.Exec(ctx, `INSERT INTO user_sessions (user_id) VALUES ($1)`, user)
		db.Pool.Exec(ctx, `INSERT INTO api_keys (user_id, org_id, status) VALUES ($1,$2,'active')`, user, org)
		// An unrelated user's rows must never be touched.
		db.Pool.Exec(ctx, `INSERT INTO sessions (user_id, org_id, revoked) VALUES ($1,$2,false)`, other, org)
		db.Pool.Exec(ctx, `INSERT INTO api_keys (user_id, org_id, status) VALUES ($1,$2,'active')`, other, org)
	}

	svc := &Service{db: db, redis: nil, logger: zap.NewNop()}

	count := func(q string, args ...interface{}) int {
		var n int
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	t.Run("soft revoke (disable)", func(t *testing.T) {
		seed()
		svc.deprovisionUser(ctx, user, org, false)

		if got := count(`SELECT COUNT(*) FROM sessions WHERE user_id=$1 AND revoked=true`, user); got != 1 {
			t.Errorf("target session should be revoked, got %d revoked", got)
		}
		if got := count(`SELECT COUNT(*) FROM api_keys WHERE user_id=$1 AND status='revoked'`, user); got != 1 {
			t.Errorf("target api key should be revoked, got %d", got)
		}
		// Rows are kept for audit under soft revoke.
		if got := count(`SELECT COUNT(*) FROM sessions WHERE user_id=$1`, user); got != 1 {
			t.Errorf("soft revoke must keep the session row, got %d", got)
		}
		// The other user is untouched.
		if got := count(`SELECT COUNT(*) FROM sessions WHERE user_id=$1 AND revoked=true`, other); got != 0 {
			t.Errorf("other user's session must not be revoked, got %d", got)
		}
		if got := count(`SELECT COUNT(*) FROM api_keys WHERE user_id=$1 AND status='active'`, other); got != 1 {
			t.Errorf("other user's api key must stay active, got %d", got)
		}
	})

	t.Run("hard delete", func(t *testing.T) {
		seed()
		svc.deprovisionUser(ctx, user, org, true)

		if got := count(`SELECT COUNT(*) FROM sessions WHERE user_id=$1`, user); got != 0 {
			t.Errorf("hard delete must remove sessions, got %d", got)
		}
		if got := count(`SELECT COUNT(*) FROM user_sessions WHERE user_id=$1`, user); got != 0 {
			t.Errorf("hard delete must remove user_sessions, got %d", got)
		}
		if got := count(`SELECT COUNT(*) FROM api_keys WHERE user_id=$1`, user); got != 0 {
			t.Errorf("hard delete must remove api_keys, got %d", got)
		}
		// The other user's rows survive.
		if got := count(`SELECT COUNT(*) FROM sessions WHERE user_id=$1`, other); got != 1 {
			t.Errorf("other user's session must survive, got %d", got)
		}
	})
}
