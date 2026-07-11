package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestGetUserPlatformAuthenticators guards the WebAuthn phantom-table fix:
// biometric/passwordless read WebAuthn credentials from mfa_webauthn (where the
// wired registration writes), not the phantom `webauthn_credentials` table that
// no migration creates and that carried an `authenticator_type` column
// mfa_webauthn lacks. The lookup is org-scoped and tolerates a NULL name.
func TestGetUserPlatformAuthenticators(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE mfa_webauthn (
			id UUID PRIMARY KEY, user_id UUID, name VARCHAR(255), org_id UUID,
			created_at TIMESTAMPTZ DEFAULT now(), last_used_at TIMESTAMPTZ);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		orgA  = "00000000-0000-0000-0000-00000000000a"
		orgB  = "00000000-0000-0000-0000-00000000000b"
		userA = "11111111-0000-0000-0000-00000000000a"
		userB = "11111111-0000-0000-0000-00000000000b"
	)
	exec := func(q string, a ...interface{}) {
		if _, err := db.Pool.Exec(ctx, q, a...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO mfa_webauthn (id, user_id, name, org_id) VALUES ($1,$2,'iPhone',$3)`, "aaaaaaaa-0000-0000-0000-000000000001", userA, orgA)
	// A second credential with a NULL name (COALESCE must handle it, not drop the row).
	exec(`INSERT INTO mfa_webauthn (id, user_id, name, org_id) VALUES ($1,$2,NULL,$3)`, "aaaaaaaa-0000-0000-0000-000000000002", userA, orgA)
	// Another org's credential must not leak into org A's view.
	exec(`INSERT INTO mfa_webauthn (id, user_id, name, org_id) VALUES ($1,$2,'AndroidB',$3)`, "bbbbbbbb-0000-0000-0000-000000000001", userB, orgB)

	s := &Service{db: db, logger: zap.NewNop()}

	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	auths, err := s.GetUserPlatformAuthenticators(ctxA, userA)
	if err != nil {
		t.Fatalf("GetUserPlatformAuthenticators(userA): %v", err)
	}
	if len(auths) != 2 {
		t.Fatalf("want 2 authenticators for userA (incl. the NULL-name one), got %d: %+v", len(auths), auths)
	}
	// The NULL-name credential must survive as an empty string, and every entry
	// is reported as a platform authenticator.
	for _, a := range auths {
		if a["authenticator_type"] != "platform" {
			t.Fatalf("authenticator_type: want platform, got %v", a["authenticator_type"])
		}
		if _, ok := a["name"].(string); !ok {
			t.Fatalf("name should be a (possibly empty) string, got %T", a["name"])
		}
	}

	// Cross-org: org A's context must not see org B's user's credential.
	if got, err := s.GetUserPlatformAuthenticators(ctxA, userB); err != nil || len(got) != 0 {
		t.Fatalf("cross-org: want 0 for userB under org A, got %d (err %v)", len(got), err)
	}
}
