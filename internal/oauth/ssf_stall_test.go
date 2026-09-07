package oauth

import (
	"context"
	"testing"
)

// A security event token that nobody delivered and nobody retried.
//
// drainSSFDelivery claims a row by setting state='processing', and it only ever
// selects state='pending'. The four writes that move a claimed row on --
// delivered, dead, pending-with-backoff, failed -- all discarded their errors,
// so a row whose outcome could not be written stayed 'processing' for good: not
// delivered, not retried, not dead-lettered, and absent from every count the
// admin page shows. The same happens whenever the process is killed between the
// claim and the outcome, which needs no database failure at all.
//
// These are CAEP events. A session-revoked notice stuck here is a downstream
// relying party that goes on honouring a session OpenIDX has already ended.

const ssfDeliverySchema = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE ssf_streams (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID, description VARCHAR(255),
	audience TEXT NOT NULL, delivery_endpoint TEXT NOT NULL, delivery_auth_enc TEXT,
	events_requested JSONB DEFAULT '[]', status VARCHAR(16) DEFAULT 'enabled',
	created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE ssf_stream_delivery (
	id BIGSERIAL PRIMARY KEY, org_id UUID,
	stream_id UUID NOT NULL REFERENCES ssf_streams(id) ON DELETE CASCADE,
	event_type TEXT NOT NULL, subject TEXT, set_jwt TEXT NOT NULL,
	state VARCHAR(16) DEFAULT 'pending', attempts INTEGER DEFAULT 0, last_error TEXT,
	next_attempt_at TIMESTAMPTZ DEFAULT NOW(),
	created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW());`

func TestASSFDeliveryAbandonedInProcessingIsRequeued(t *testing.T) {
	db, cleanup := ssfSetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := db.Pool.Exec(ctx, ssfDeliverySchema); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	tctx := NewTestOIDCContext(t)
	defer tctx.Cleanup()
	svc := tctx.Service
	svc.db = db

	var streamID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO ssf_streams (org_id, audience, delivery_endpoint)
		VALUES ('00000000-0000-0000-0000-0000000000aa', 'https://rp.example', 'https://rp.example/events')
		RETURNING id::text`).Scan(&streamID); err != nil {
		t.Fatalf("seed stream: %v", err)
	}

	// Two claimed rows: one abandoned long ago, one claimed a moment ago by a
	// worker that is still pushing it. Only the first is the drain's to take.
	var stale, fresh int64
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO ssf_stream_delivery (stream_id, event_type, set_jwt, state, attempts, updated_at)
		VALUES ($1, 'session-revoked', 'jwt', 'processing', 0, NOW() - INTERVAL '1 hour')
		RETURNING id`, streamID).Scan(&stale); err != nil {
		t.Fatalf("seed the stalled row: %v", err)
	}
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO ssf_stream_delivery (stream_id, event_type, set_jwt, state, attempts, updated_at)
		VALUES ($1, 'session-revoked', 'jwt', 'processing', 0, NOW())
		RETURNING id`, streamID).Scan(&fresh); err != nil {
		t.Fatalf("seed the in-flight row: %v", err)
	}

	svc.requeueStalledSSF(ctx)

	var state string
	var attempts int
	if err := db.Pool.QueryRow(ctx,
		`SELECT state, attempts FROM ssf_stream_delivery WHERE id = $1`, stale).Scan(&state, &attempts); err != nil {
		t.Fatalf("read the stalled row back: %v", err)
	}
	if state != "pending" {
		t.Errorf("a delivery abandoned in 'processing' an hour ago is still %q. The drain only ever "+
			"selects 'pending', so this security event is never sent and never retried.", state)
	}
	if attempts != 1 {
		t.Errorf("requeued with attempts=%d, want 1 — an item that keeps stalling must reach "+
			"ssfMaxAttempts and dead-letter rather than cycling for ever", attempts)
	}

	// The row a worker is still pushing must be left alone, or two workers
	// deliver the same event.
	if err := db.Pool.QueryRow(ctx,
		`SELECT state FROM ssf_stream_delivery WHERE id = $1`, fresh).Scan(&state); err != nil {
		t.Fatalf("read the in-flight row back: %v", err)
	}
	if state != "processing" {
		t.Errorf("a delivery claimed moments ago was requeued (state %q); the worker holding it is "+
			"still pushing, and this is how a receiver gets the same event twice", state)
	}
}

// The drain does the requeue itself, so recovery needs no separate scheduler.
func TestTheSSFDrainRecoversItsOwnAbandonedClaims(t *testing.T) {
	db, cleanup := ssfSetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	if _, err := db.Pool.Exec(ctx, ssfDeliverySchema); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	tctx := NewTestOIDCContext(t)
	defer tctx.Cleanup()
	svc := tctx.Service
	svc.db = db

	var streamID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO ssf_streams (org_id, audience, delivery_endpoint)
		VALUES ('00000000-0000-0000-0000-0000000000aa', 'https://rp.example', 'http://127.0.0.1:1/events')
		RETURNING id::text`).Scan(&streamID); err != nil {
		t.Fatalf("seed stream: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO ssf_stream_delivery (stream_id, event_type, set_jwt, state, attempts, updated_at)
		VALUES ($1, 'session-revoked', 'jwt', 'processing', 0, NOW() - INTERVAL '1 hour')`,
		streamID); err != nil {
		t.Fatalf("seed the stalled row: %v", err)
	}

	// The endpoint refuses the connection, so the push fails and the row is
	// rescheduled — but it had to be picked up at all, which is the point.
	n, err := svc.drainSSFDelivery(ctx)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if n != 1 {
		t.Fatalf("the drain claimed %d rows; the stalled one should have been requeued and picked up", n)
	}

	var state string
	if err := db.Pool.QueryRow(ctx,
		`SELECT state FROM ssf_stream_delivery WHERE stream_id = $1::uuid`, streamID).Scan(&state); err != nil {
		t.Fatalf("read the row back: %v", err)
	}
	if state == "processing" {
		t.Error("after a full drain the row is still 'processing' — it was never recovered")
	}
}
