package access

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/risk"
)

func TestDeviceTrusted(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	// Minimal known_devices table (columns the reader uses).
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE known_devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			fingerprint VARCHAR(255),
			trusted BOOLEAN DEFAULT false,
			org_id UUID
		);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}

	const userID = "00000000-0000-0000-0000-000000000001"
	const ip = "192.168.1.50"
	const ua = "Mozilla/5.0 (TestAgent)"
	fp := risk.ComputeDeviceFingerprint(ip, ua)

	// No row yet → not trusted.
	if s.deviceTrusted(ctx, userID, ip, ua) {
		t.Error("expected false with no known_devices row")
	}

	// Seed a row for this fingerprint, trusted=false → still not trusted.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO known_devices (user_id, fingerprint, trusted, org_id) VALUES ($1,$2,false,$3)`,
		userID, fp, "00000000-0000-0000-0000-000000000010"); err != nil {
		t.Fatalf("seed untrusted: %v", err)
	}
	if s.deviceTrusted(ctx, userID, ip, ua) {
		t.Error("expected false when row exists but trusted=false")
	}

	// Flip to trusted=true → trusted.
	if _, err := db.Pool.Exec(ctx,
		`UPDATE known_devices SET trusted=true WHERE user_id=$1 AND fingerprint=$2`, userID, fp); err != nil {
		t.Fatalf("flip trusted: %v", err)
	}
	if !s.deviceTrusted(ctx, userID, ip, ua) {
		t.Error("expected true when matching row has trusted=true")
	}

	// Different UA (different fingerprint) → no match → not trusted.
	if s.deviceTrusted(ctx, userID, ip, "Different UA") {
		t.Error("expected false for a non-matching fingerprint")
	}

	// Empty userID → not trusted, no query.
	if s.deviceTrusted(ctx, "", ip, ua) {
		t.Error("expected false for empty userID")
	}
}

func TestEnsureDeviceTrustRequest(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE known_devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			fingerprint VARCHAR(255),
			name VARCHAR(255),
			trusted BOOLEAN DEFAULT false,
			org_id UUID
		);
		CREATE TABLE device_trust_requests (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			device_id UUID,
			device_fingerprint VARCHAR(255),
			device_name VARCHAR(255),
			device_type VARCHAR(50),
			ip_address VARCHAR(64),
			user_agent TEXT,
			justification TEXT,
			status VARCHAR(20),
			reviewed_by UUID,
			reviewed_at TIMESTAMPTZ,
			review_notes TEXT,
			auto_expire_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}

	const userID = "00000000-0000-0000-0000-000000000001"
	const ip = "192.168.1.50"
	const ua = "Mozilla/5.0 (TestAgent)"
	fp := risk.ComputeDeviceFingerprint(ip, ua)

	pending := func() int {
		var n int
		db.Pool.QueryRow(ctx, `SELECT count(*) FROM device_trust_requests WHERE user_id=$1 AND status='pending'`, userID).Scan(&n)
		return n
	}

	// No known_devices row → no request created.
	s.ensureDeviceTrustRequest(ctx, userID, ip, ua)
	if pending() != 0 {
		t.Fatalf("expected 0 requests with no known_devices row, got %d", pending())
	}

	// Register the (untrusted) device.
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO known_devices (user_id, fingerprint, name, trusted) VALUES ($1,$2,'Test Laptop',false)`,
		userID, fp); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// First call → exactly one pending request.
	s.ensureDeviceTrustRequest(ctx, userID, ip, ua)
	if pending() != 1 {
		t.Fatalf("expected 1 request after first call, got %d", pending())
	}

	// Second call → still one (dedup).
	s.ensureDeviceTrustRequest(ctx, userID, ip, ua)
	if pending() != 1 {
		t.Fatalf("expected dedup to keep 1 request, got %d", pending())
	}

	// Empty userID → no-op.
	before := pending()
	s.ensureDeviceTrustRequest(ctx, "", ip, ua)
	if pending() != before {
		t.Fatalf("empty userID should not create a request")
	}
}
