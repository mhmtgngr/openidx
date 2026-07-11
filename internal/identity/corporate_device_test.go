package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestIsCorporateDevice guards the v75 fix: known_devices now has the
// device_type column isCorporateDevice filters on (pre-v75 the query errored
// on the missing column, the error was swallowed, and the check always
// returned false — auto_approve_corporate_devices was silently inert). The
// check matches device_type='corporate' or a Corporate name, org-scoped.
func TestIsCorporateDevice(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	// Mirrors known_devices post-v75 (v19 base + org_id + device_type).
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE known_devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			fingerprint VARCHAR(128) NOT NULL,
			name VARCHAR(255),
			ip_address VARCHAR(45),
			trusted BOOLEAN DEFAULT false,
			device_type VARCHAR(50),
			org_id UUID NOT NULL,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(user_id, fingerprint)
		);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		orgA  = "00000000-0000-0000-0000-00000000000a"
		orgB  = "00000000-0000-0000-0000-00000000000b"
		userA = "11111111-0000-0000-0000-00000000000a"
	)
	seed := func(fingerprint, name string, deviceType *string, org string) {
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO known_devices (user_id, fingerprint, name, device_type, org_id)
			VALUES ($1, $2, $3, $4, $5)
		`, userA, fingerprint, name, deviceType, org); err != nil {
			t.Fatalf("seed %s: %v", fingerprint, err)
		}
	}
	corporate := "corporate"
	seed("fp-typed", "MacBook Pro", &corporate, orgA)   // device_type path
	seed("fp-named", "Corporate Laptop 042", nil, orgA) // name path, NULL device_type
	seed("fp-personal", "Personal Phone", nil, orgA)    // neither

	s := &Service{db: db, logger: zap.NewNop()}
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	ctxB := orgctx.With(context.Background(), orgctx.Org{ID: orgB})

	if !s.isCorporateDevice(ctxA, "fp-typed") {
		t.Fatal("device_type='corporate' should be corporate in its own org")
	}
	if !s.isCorporateDevice(ctxA, "fp-named") {
		t.Fatal("name LIKE %Corporate% (NULL device_type) should be corporate")
	}
	if s.isCorporateDevice(ctxA, "fp-personal") {
		t.Fatal("plain personal device must not be corporate")
	}
	// Org scoping: org B must not inherit org A's corporate registration.
	if s.isCorporateDevice(ctxB, "fp-typed") {
		t.Fatal("cross-org: org B must not see org A's corporate device")
	}
	// No org in context fails closed.
	if s.isCorporateDevice(context.Background(), "fp-typed") {
		t.Fatal("no org context must fail closed (false)")
	}
}
