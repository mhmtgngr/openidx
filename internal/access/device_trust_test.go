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
