package audit

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// TestCountMFAEnabledUsers guards the "MFA adoption 0.0%" false-compliance fix:
// WebAuthn credentials live in mfa_webauthn, but the ISO A.9 / SOC2 CC6 MFA
// counts read a phantom `webauthn_credentials` table that no migration creates,
// so the query errored and WebAuthn users were never counted (deterministic
// "MFA adoption rate is 0.0%"). countMFAEnabledUsers now unions mfa_totp and
// mfa_webauthn, org-scoped. DB-backed because it runs the real UNION query.
func TestCountMFAEnabledUsers(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE mfa_totp (user_id UUID, enabled BOOLEAN, org_id UUID);
		CREATE TABLE mfa_webauthn (user_id UUID, credential_id TEXT, org_id UUID);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	const (
		orgA        = "00000000-0000-0000-0000-00000000000a"
		orgB        = "00000000-0000-0000-0000-00000000000b"
		userTOTP    = "11111111-0000-0000-0000-000000000001" // TOTP only, org A
		userWebAuth = "11111111-0000-0000-0000-000000000002" // WebAuthn only, org A
		userBoth    = "11111111-0000-0000-0000-000000000003" // both, org A (dedup)
		userDisab   = "11111111-0000-0000-0000-000000000004" // TOTP disabled, org A
		userOrgB    = "11111111-0000-0000-0000-00000000000b" // WebAuthn, org B
	)
	exec := func(q string, a ...interface{}) {
		if _, err := db.Pool.Exec(ctx, q, a...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO mfa_totp (user_id, enabled, org_id) VALUES ($1,true,$4),($2,true,$4),($3,false,$4)`,
		userTOTP, userBoth, userDisab, orgA)
	exec(`INSERT INTO mfa_webauthn (user_id, credential_id, org_id) VALUES ($1,'c1',$4),($2,'c2',$4),($3,'c3',$5)`,
		userWebAuth, userBoth, userOrgB, orgA, orgB)

	s := &Service{db: db, logger: zap.NewNop()}

	// Org A: distinct MFA users = {TOTP, WebAuthn, Both} = 3. The disabled TOTP
	// user is excluded, org B's WebAuthn user is excluded, and userBoth is
	// counted once. Critically, the WebAuthn-only user is counted at all — the
	// whole point of the fix.
	if n := s.countMFAEnabledUsers(ctx, orgA); n != 3 {
		t.Fatalf("countMFAEnabledUsers(orgA): want 3 (TOTP + WebAuthn + both, deduped, org-scoped, WebAuthn included), got %d", n)
	}

	// Org B sees only its own WebAuthn user.
	if n := s.countMFAEnabledUsers(ctx, orgB); n != 1 {
		t.Fatalf("countMFAEnabledUsers(orgB): want 1, got %d", n)
	}

	// An org with no MFA rows resolves to 0 (not an error).
	if n := s.countMFAEnabledUsers(ctx, "00000000-0000-0000-0000-0000000000ff"); n != 0 {
		t.Fatalf("countMFAEnabledUsers(empty org): want 0, got %d", n)
	}
}
