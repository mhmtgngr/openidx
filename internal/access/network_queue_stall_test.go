package access

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// A revocation nobody applied, and nobody retried.
//
// Both network hand-off queues claim an item by setting state='processing', and
// both only ever select state='pending'. The write that moved a claimed item to
// 'done' discarded its error, so an item whose outcome could not be written
// stayed 'processing' for good: not applied, not retried, not dead-lettered,
// and outside every state the queue reports. No database failure is needed
// either -- being killed between the claim and the outcome does it.
//
// For the revocation queue that is a user who keeps their overlay attribute and
// their live circuits after governance took the access away, with the access
// review showing as actioned. For the grant queue it is the mirror: an approved
// request whose attribute is never added, reported as granted.
//
// Both drains now recover their own abandoned claims before taking new work.

const networkQueueSchema = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS network_grant_queue (
    id BIGSERIAL PRIMARY KEY, org_id UUID, user_id UUID NOT NULL, request_id UUID,
    attribute VARCHAR(128) NOT NULL, expires_at TIMESTAMPTZ,
    state VARCHAR(16) NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS network_revocation_queue (
    id BIGSERIAL PRIMARY KEY, org_id UUID, user_id UUID NOT NULL, reason VARCHAR(64) NOT NULL,
    attribute VARCHAR(128), state VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS ziti_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, ziti_id VARCHAR(255), org_id UUID);
CREATE TABLE IF NOT EXISTS enrolled_agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), enrolled_by_user_id UUID, ziti_identity_id VARCHAR(255));`

func networkQueueFixture(t *testing.T) (*Service, context.Context, *database.PostgresDB, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, nil, func() {}
	}
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, networkQueueSchema); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}
	return &Service{db: db, logger: zap.NewNop()}, ctx, db, cleanup
}

// seedStalledAndFresh inserts one item abandoned an hour ago and one a worker
// is still applying, and returns their ids.
func seedStalledAndFresh(t *testing.T, db *database.PostgresDB, ctx context.Context, table, cols, vals string) (int64, int64) {
	t.Helper()
	var stale, fresh int64
	if err := db.Pool.QueryRow(ctx,
		"INSERT INTO "+table+" ("+cols+", state, attempts, updated_at) VALUES ("+vals+
			", 'processing', 0, NOW() - INTERVAL '1 hour') RETURNING id").Scan(&stale); err != nil {
		t.Fatalf("seed the stalled item: %v", err)
	}
	if err := db.Pool.QueryRow(ctx,
		"INSERT INTO "+table+" ("+cols+", state, attempts, updated_at) VALUES ("+vals+
			", 'processing', 0, NOW()) RETURNING id").Scan(&fresh); err != nil {
		t.Fatalf("seed the in-flight item: %v", err)
	}
	return stale, fresh
}

func assertRequeued(t *testing.T, db *database.PostgresDB, ctx context.Context, table string, stale, fresh int64, what string) {
	t.Helper()
	var state string
	var attempts int
	if err := db.Pool.QueryRow(ctx,
		"SELECT state, attempts FROM "+table+" WHERE id = $1", stale).Scan(&state, &attempts); err != nil {
		t.Fatalf("read the stalled item back: %v", err)
	}
	if state != "pending" {
		t.Errorf("%s abandoned in 'processing' an hour ago is still %q. The drain only ever selects "+
			"'pending', so it is never applied and nothing anywhere says so.", what, state)
	}
	if attempts != 1 {
		t.Errorf("requeued with attempts=%d, want 1 — an item that keeps stalling must reach "+
			"networkQueueMaxAttempts and dead-letter rather than cycling for ever", attempts)
	}

	if err := db.Pool.QueryRow(ctx,
		"SELECT state FROM "+table+" WHERE id = $1", fresh).Scan(&state); err != nil {
		t.Fatalf("read the in-flight item back: %v", err)
	}
	if state != "processing" {
		t.Errorf("an item claimed moments ago was requeued (state %q); the worker holding it is still "+
			"applying it, and this is how the same change is sent twice", state)
	}
}

func TestARevocationAbandonedInProcessingIsRequeued(t *testing.T) {
	s, ctx, db, cleanup := networkQueueFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	stale, fresh := seedStalledAndFresh(t, db, ctx, "network_revocation_queue",
		"user_id, reason, attribute",
		"'33333333-3333-3333-3333-333333333333', 'access_review', 'jit-req-9'")

	s.requeueStalledNetworkItems(ctx, "network_revocation_queue")
	assertRequeued(t, db, ctx, "network_revocation_queue", stale, fresh,
		"a revocation governance ordered")
}

func TestAGrantAbandonedInProcessingIsRequeued(t *testing.T) {
	s, ctx, db, cleanup := networkQueueFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	stale, fresh := seedStalledAndFresh(t, db, ctx, "network_grant_queue",
		"user_id, attribute",
		"'11111111-1111-1111-1111-111111111111', 'jit-req-1'")

	s.requeueStalledNetworkItems(ctx, "network_grant_queue")
	assertRequeued(t, db, ctx, "network_grant_queue", stale, fresh,
		"an approved grant")
}

// Each drain recovers its own abandoned claims, so nothing else has to.
func TestTheNetworkDrainsRecoverTheirOwnAbandonedClaims(t *testing.T) {
	s, ctx, db, cleanup := networkQueueFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO network_revocation_queue (user_id, reason, attribute, state, attempts, updated_at)
		VALUES ('33333333-3333-3333-3333-333333333333', 'access_review', 'jit-req-9',
		        'processing', 0, NOW() - INTERVAL '1 hour');
		INSERT INTO network_grant_queue (user_id, attribute, state, attempts, updated_at)
		VALUES ('11111111-1111-1111-1111-111111111111', 'jit-req-1',
		        'processing', 0, NOW() - INTERVAL '1 hour')`); err != nil {
		t.Fatalf("seed the stalled items: %v", err)
	}

	// With no overlay configured both applications are no-ops that succeed, so
	// a full drain takes each recovered item to 'done'.
	s.drainNetworkRevocations(ctx)
	s.drainNetworkGrants(ctx)

	for _, table := range []string{"network_revocation_queue", "network_grant_queue"} {
		var state string
		if err := db.Pool.QueryRow(ctx, "SELECT state FROM "+table).Scan(&state); err != nil {
			t.Fatalf("read %s back: %v", table, err)
		}
		if state == "processing" {
			t.Errorf("after a full drain the %s item is still 'processing' — it was never recovered", table)
		}
	}
}
