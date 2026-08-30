package identity

import (
	"context"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestUpdateActivitySlidesExpiry guards the "My Sessions is empty even though
// I'm logged in" fix: UpdateActivity (fired on every token refresh) must push
// expires_at forward, so an actively-used session created with a short TTL does
// not silently die at that TTL. A revoked session is never resurrected.
func TestUpdateActivitySlidesExpiry(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE sessions (
			id UUID PRIMARY KEY,
			user_id UUID NOT NULL,
			client_id TEXT, ip_address TEXT, user_agent TEXT,
			started_at TIMESTAMPTZ DEFAULT now(),
			last_seen_at TIMESTAMPTZ DEFAULT now(),
			expires_at TIMESTAMPTZ NOT NULL,
			org_id UUID NOT NULL,
			revoked BOOLEAN);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		org     = "00000000-0000-0000-0000-0000000000bb"
		user    = "11111111-0000-0000-0000-0000000000bb"
		live    = "bbbbbbbb-0000-0000-0000-000000000001"
		revoked = "bbbbbbbb-0000-0000-0000-000000000002"
	)
	ins := func(id string, rev bool, expOffset time.Duration) {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO sessions (id,user_id,client_id,ip_address,user_agent,expires_at,org_id,revoked)
			 VALUES ($1,$2,'c1','1.2.3.4','ua', now()+$3, $4, $5)`,
			id, user, expOffset, org, rev); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	// A live session near the end of its window, and a revoked one.
	ins(live, false, 5*time.Minute)
	ins(revoked, true, 5*time.Minute)

	repo := NewPostgresSessionRepository(db)
	octx := orgctx.With(ctx, orgctx.Org{ID: org})

	if err := repo.UpdateActivity(octx, live); err != nil {
		t.Fatalf("UpdateActivity(live): %v", err)
	}

	// The live session's expiry must now be far in the future (~sliding window),
	// not the original 5 minutes.
	var secondsLeft float64
	if err := db.Pool.QueryRow(ctx,
		`SELECT EXTRACT(EPOCH FROM (expires_at - NOW())) FROM sessions WHERE id = $1`, live,
	).Scan(&secondsLeft); err != nil {
		t.Fatalf("read expiry: %v", err)
	}
	if secondsLeft < (sessionSlidingWindow - time.Hour).Seconds() {
		t.Fatalf("expiry not slid forward: only %.0fs left, want ~%.0fs", secondsLeft, sessionSlidingWindow.Seconds())
	}

	// A revoked session must not be resurrected (UpdateActivity returns not-found
	// and its expiry is unchanged / it stays out of any active listing).
	if err := repo.UpdateActivity(octx, revoked); err == nil {
		t.Fatal("UpdateActivity(revoked): want ErrSessionNotFound, got nil")
	}
}
