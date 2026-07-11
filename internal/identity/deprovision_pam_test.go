package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestDeprovisionUser_RevokesPAMState pins the IAM→PAM lifecycle seam:
// disabling (or deleting) a user must revoke their live privileged access —
// active vault checkouts, direct user vault grants, and JIT elevations — not
// just sessions and API keys. Before this seam existed, a disabled user's
// checked-out credential lease and reveal grants stayed live until their
// natural expiry. DB-backed because the revocations are plain SQL against the
// real column names.
func TestDeprovisionUser_RevokesPAMState(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	const (
		orgID    = "00000000-0000-0000-0000-0000000000cc"
		userID   = "11111111-0000-0000-0000-0000000000c1"
		otherID  = "11111111-0000-0000-0000-0000000000c2"
		secretID = "44444444-0000-0000-0000-0000000000c1"
	)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})

	// Minimal schema for the tables deprovisionUser touches. No FKs so the
	// test seeds only what it needs.
	schema := []string{
		`CREATE TABLE sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID,
			revoked BOOLEAN, revoked_at TIMESTAMPTZ, expires_at TIMESTAMPTZ)`,
		`CREATE TABLE user_sessions (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID)`,
		`CREATE TABLE api_keys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID, status VARCHAR(32))`,
		`CREATE TABLE vault_checkouts (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID, secret_id UUID,
			principal_id UUID, mode VARCHAR(16), leased_at TIMESTAMPTZ DEFAULT NOW(),
			expires_at TIMESTAMPTZ, returned_at TIMESTAMPTZ, status VARCHAR(16))`,
		`CREATE TABLE vault_access_grants (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID, secret_id UUID,
			principal_type VARCHAR(32), principal_id UUID, actions TEXT[], expires_at TIMESTAMPTZ)`,
		`CREATE TABLE jit_grants (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID, org_id UUID,
			role_name VARCHAR(255), expires_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
			updated_at TIMESTAMPTZ DEFAULT NOW(), status VARCHAR(16))`,
	}
	for _, stmt := range schema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	seeds := []string{
		`INSERT INTO sessions (user_id, org_id, revoked, expires_at) VALUES ('` + userID + `','` + orgID + `',false,NOW()+'1h')`,
		`INSERT INTO api_keys (user_id, org_id, status) VALUES ('` + userID + `','` + orgID + `','active')`,
		`INSERT INTO vault_checkouts (org_id, secret_id, principal_id, mode, status) VALUES ('` + orgID + `','` + secretID + `','` + userID + `','reveal','active')`,
		`INSERT INTO vault_access_grants (org_id, secret_id, principal_type, principal_id, actions) VALUES ('` + orgID + `','` + secretID + `','user','` + userID + `','{use,reveal}')`,
		`INSERT INTO jit_grants (user_id, org_id, role_name, expires_at, status) VALUES ('` + userID + `','` + orgID + `','break-glass',NOW()+'1h','active')`,
		// Another user's live PAM state — must be untouched.
		`INSERT INTO vault_checkouts (org_id, secret_id, principal_id, mode, status) VALUES ('` + orgID + `','` + secretID + `','` + otherID + `','reveal','active')`,
		`INSERT INTO vault_access_grants (org_id, secret_id, principal_type, principal_id, actions) VALUES ('` + orgID + `','` + secretID + `','role','` + otherID + `','{use}')`,
	}
	for _, s := range seeds {
		if _, err := db.Pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	svc := &Service{db: db, logger: zap.NewNop()}
	svc.deprovisionUser(ctx, userID, orgID, false)

	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM vault_checkouts WHERE principal_id=$1 AND status='active'`, userID).Scan(&n); err != nil || n != 0 {
		t.Errorf("disabled user's checkout still active: %d (err %v)", n, err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM vault_access_grants
		  WHERE principal_type='user' AND principal_id=$1 AND (expires_at IS NULL OR expires_at > NOW())`,
		userID).Scan(&n); err != nil || n != 0 {
		t.Errorf("disabled user's vault grant still live: %d (err %v)", n, err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM jit_grants WHERE user_id=$1 AND status='active'`, userID).Scan(&n); err != nil || n != 0 {
		t.Errorf("disabled user's JIT grant still active: %d (err %v)", n, err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM sessions WHERE user_id=$1 AND (revoked IS NULL OR revoked=false)`, userID).Scan(&n); err != nil || n != 0 {
		t.Errorf("disabled user's session still live: %d (err %v)", n, err)
	}

	// Collateral check: the other principal's lease and role grant survive.
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM vault_checkouts WHERE principal_id=$1 AND status='active'`, otherID).Scan(&n); err != nil || n != 1 {
		t.Errorf("other user's checkout must survive: %d (err %v)", n, err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM vault_access_grants
		  WHERE principal_id=$1 AND (expires_at IS NULL OR expires_at > NOW())`, otherID).Scan(&n); err != nil || n != 1 {
		t.Errorf("role-principal grant must survive a user deprovision: %d (err %v)", n, err)
	}

	// Hard-delete path also runs the PAM revocations (idempotent re-run).
	svc.deprovisionUser(ctx, userID, orgID, true)
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=$1`, userID).Scan(&n); err != nil || n != 0 {
		t.Errorf("hard delete must remove session rows: %d (err %v)", n, err)
	}
}
