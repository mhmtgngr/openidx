package access

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

func TestKillSwitch_SeversAllPillars(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: testOrg})
	for _, stmt := range crossPillarSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	const secretID = "44444444-0000-0000-0000-000000000002"
	seeds := []string{
		`INSERT INTO users (id, org_id, username, email, enabled) VALUES ('` + testUser + `','` + testOrg + `','bob','bob@x.io',true)`,
		`INSERT INTO sessions (id, user_id, org_id, revoked, expires_at) VALUES (gen_random_uuid(),'` + testUser + `','` + testOrg + `',false,NOW()+'1h')`,
		`INSERT INTO api_keys (id, user_id, org_id, status) VALUES (gen_random_uuid(),'` + testUser + `','` + testOrg + `','active')`,
		`INSERT INTO vault_secrets (id, org_id, name, type) VALUES ('` + secretID + `','` + testOrg + `','db-root','password')`,
		`INSERT INTO vault_checkouts (id, org_id, secret_id, principal_id, mode, status) VALUES (gen_random_uuid(),'` + testOrg + `','` + secretID + `','` + testUser + `','reveal','active')`,
		`INSERT INTO vault_access_grants (id, org_id, secret_id, principal_type, principal_id, actions) VALUES (gen_random_uuid(),'` + testOrg + `','` + secretID + `','user','` + testUser + `','{use,reveal}')`,
		`INSERT INTO jit_grants (id, user_id, org_id, role_name, expires_at, status) VALUES (gen_random_uuid(),'` + testUser + `','` + testOrg + `','break-glass',NOW()+'2h','active')`,
		`INSERT INTO guacamole_sessions (id, org_id, connection_id, user_id, guac_session_uuid, status) VALUES (gen_random_uuid(),'` + testOrg + `',gen_random_uuid(),'` + testUser + `','guac-1','active')`,
		`INSERT INTO ziti_identities (id, org_id, ziti_id, name, user_id, enrolled) VALUES (gen_random_uuid(),'` + testOrg + `','zid-bob','bob','` + testUser + `',true)`,
	}
	for _, s := range seeds {
		if _, err := db.Pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v\n%s", err, s)
		}
	}

	s := &Service{db: db, logger: zap.NewNop()}
	res := s.executeKillSwitch(ctx, testOrg, testUser, "bob", testActor, "compromise suspected", false)

	if res.SessionsRevoked != 1 {
		t.Errorf("want 1 IAM session revoked, got %d", res.SessionsRevoked)
	}
	if res.APIKeysRevoked != 0 {
		t.Errorf("API keys must survive a non-disable kill switch, got %d revoked", res.APIKeysRevoked)
	}
	if res.CheckoutsRevoked != 1 || res.VaultGrantsExpired != 1 || res.JITGrantsRevoked != 1 {
		t.Errorf("PAM severance wrong: %+v", res)
	}
	if res.UserDisabled {
		t.Error("user must not be disabled without disable_user")
	}
	// Guacamole is not configured in this harness: the session must NOT be
	// claimed terminated, and a warning must say so (honesty contract).
	if res.GuacSessionsKilled != 0 {
		t.Errorf("guac termination fabricated: %+v", res)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning about unconfigured guacamole / disconnected ziti")
	}
	var guacStatus string
	if err := db.Pool.QueryRow(ctx,
		`SELECT status FROM guacamole_sessions WHERE user_id = $1`, testUser).Scan(&guacStatus); err != nil {
		t.Fatalf("read guac session: %v", err)
	}
	if guacStatus != "active" {
		t.Errorf("guac session row must stay active when the kill could not be executed, got %q", guacStatus)
	}

	// DB state actually severed.
	var n int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM sessions WHERE user_id=$1 AND (revoked IS NULL OR revoked=false)`,
		testUser).Scan(&n); err != nil || n != 0 {
		t.Errorf("live sessions remain: %d (err %v)", n, err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM vault_checkouts WHERE principal_id=$1 AND status='active'`,
		testUser).Scan(&n); err != nil || n != 0 {
		t.Errorf("active checkouts remain: %d (err %v)", n, err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM vault_access_grants
		  WHERE principal_type='user' AND principal_id=$1 AND (expires_at IS NULL OR expires_at > NOW())`,
		testUser).Scan(&n); err != nil || n != 0 {
		t.Errorf("live vault grants remain: %d (err %v)", n, err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM jit_grants WHERE user_id=$1 AND status='active'`,
		testUser).Scan(&n); err != nil || n != 0 {
		t.Errorf("active jit grants remain: %d (err %v)", n, err)
	}

	// Second run is a no-op (idempotent), and account stays enabled.
	res2 := s.executeKillSwitch(ctx, testOrg, testUser, "bob", testActor, "again", false)
	if res2.SessionsRevoked != 0 || res2.CheckoutsRevoked != 0 || res2.JITGrantsRevoked != 0 {
		t.Errorf("kill switch not idempotent: %+v", res2)
	}
	var enabled bool
	if err := db.Pool.QueryRow(ctx, `SELECT enabled FROM users WHERE id=$1`, testUser).Scan(&enabled); err != nil || !enabled {
		t.Errorf("user must stay enabled, got enabled=%v err=%v", enabled, err)
	}
}

func TestKillSwitch_DisableUser(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: testOrg})
	for _, stmt := range crossPillarSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}
	seeds := []string{
		`INSERT INTO users (id, org_id, username, email, enabled) VALUES ('` + testUser + `','` + testOrg + `','bob','bob@x.io',true)`,
		`INSERT INTO api_keys (id, user_id, org_id, status) VALUES (gen_random_uuid(),'` + testUser + `','` + testOrg + `','active')`,
	}
	for _, s := range seeds {
		if _, err := db.Pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	s := &Service{db: db, logger: zap.NewNop()}
	res := s.executeKillSwitch(ctx, testOrg, testUser, "bob", testActor, "offboarding", true)

	if !res.UserDisabled {
		t.Fatalf("user not disabled: %+v", res)
	}
	if res.APIKeysRevoked != 1 {
		t.Errorf("disable path must revoke API keys, got %d", res.APIKeysRevoked)
	}
	var enabled bool
	if err := db.Pool.QueryRow(ctx, `SELECT enabled FROM users WHERE id=$1`, testUser).Scan(&enabled); err != nil || enabled {
		t.Errorf("users.enabled must be false, got %v err=%v", enabled, err)
	}
}

func TestLifecycleSweep_RevokesDisabledUsersPAM(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	// The sweep runs with RLS bypass (background, cross-org), like production.
	ctx := orgctx.WithBypassRLS(context.Background())
	for _, stmt := range crossPillarSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	const (
		disabledUser = "11111111-0000-0000-0000-0000000000d1"
		activeUser   = "11111111-0000-0000-0000-0000000000d2"
		secretID     = "44444444-0000-0000-0000-000000000003"
	)
	seeds := []string{
		`INSERT INTO users (id, org_id, username, email, enabled) VALUES ('` + disabledUser + `','` + testOrg + `','mallory','m@x.io',false)`,
		`INSERT INTO users (id, org_id, username, email, enabled) VALUES ('` + activeUser + `','` + testOrg + `','carol','c@x.io',true)`,
		`INSERT INTO vault_secrets (id, org_id, name, type) VALUES ('` + secretID + `','` + testOrg + `','db','password')`,
		// Disabled user's live PAM state — all must be revoked by the sweep.
		`INSERT INTO vault_checkouts (id, org_id, secret_id, principal_id, mode, status) VALUES (gen_random_uuid(),'` + testOrg + `','` + secretID + `','` + disabledUser + `','reveal','active')`,
		`INSERT INTO vault_access_grants (id, org_id, secret_id, principal_type, principal_id, actions) VALUES (gen_random_uuid(),'` + testOrg + `','` + secretID + `','user','` + disabledUser + `','{use}')`,
		`INSERT INTO jit_grants (id, user_id, org_id, role_name, expires_at, status) VALUES (gen_random_uuid(),'` + disabledUser + `','` + testOrg + `','admin',NOW()+'1h','active')`,
		// Active user's state — must be untouched.
		`INSERT INTO vault_checkouts (id, org_id, secret_id, principal_id, mode, status) VALUES (gen_random_uuid(),'` + testOrg + `','` + secretID + `','` + activeUser + `','reveal','active')`,
		`INSERT INTO vault_access_grants (id, org_id, secret_id, principal_type, principal_id, actions) VALUES (gen_random_uuid(),'` + testOrg + `','` + secretID + `','role','` + activeUser + `','{use}')`,
		`INSERT INTO jit_grants (id, user_id, org_id, role_name, expires_at, status) VALUES (gen_random_uuid(),'` + activeUser + `','` + testOrg + `','ops',NOW()+'1h','active')`,
		// Orphaned checkout: principal's user row no longer exists.
		`INSERT INTO vault_checkouts (id, org_id, secret_id, principal_id, mode, status) VALUES (gen_random_uuid(),'` + testOrg + `','` + secretID + `','99999999-0000-0000-0000-000000000009','reveal','active')`,
		// Disabled user's live guacamole session: with no client configured it
		// must be left active (never fabricate a termination).
		`INSERT INTO guacamole_sessions (id, org_id, connection_id, user_id, guac_session_uuid, status) VALUES (gen_random_uuid(),'` + testOrg + `',gen_random_uuid(),'` + disabledUser + `','g-1','active')`,
	}
	for _, s := range seeds {
		if _, err := db.Pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	s := &Service{db: db, logger: zap.NewNop()}
	s.runLifecycleEnforcement(ctx)

	var n int
	// Disabled user + orphan: both checkouts revoked; carol's stays.
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM vault_checkouts WHERE status='active'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("want exactly carol's checkout active, got %d (err %v)", n, err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM vault_checkouts WHERE principal_id=$1 AND status='active'`, activeUser).Scan(&n); err != nil || n != 1 {
		t.Errorf("carol's checkout must survive, got %d (err %v)", n, err)
	}
	// Disabled user's direct grant expired; carol's role grant untouched (the
	// sweep only expires principal_type='user').
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM vault_access_grants WHERE principal_id=$1 AND (expires_at IS NULL OR expires_at > NOW())`,
		disabledUser).Scan(&n); err != nil || n != 0 {
		t.Errorf("mallory's grant still live: %d (err %v)", n, err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM vault_access_grants WHERE principal_id=$1 AND (expires_at IS NULL OR expires_at > NOW())`,
		activeUser).Scan(&n); err != nil || n != 1 {
		t.Errorf("carol's grant must survive: %d (err %v)", n, err)
	}
	// JIT: mallory revoked, carol active.
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM jit_grants WHERE user_id=$1 AND status='active'`, disabledUser).Scan(&n); err != nil || n != 0 {
		t.Errorf("mallory's jit grant still active: %d (err %v)", n, err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM jit_grants WHERE user_id=$1 AND status='active'`, activeUser).Scan(&n); err != nil || n != 1 {
		t.Errorf("carol's jit grant must survive: %d (err %v)", n, err)
	}
	// Guacamole honesty: no client → row still active.
	var guacStatus string
	if err := db.Pool.QueryRow(ctx,
		`SELECT status FROM guacamole_sessions WHERE user_id=$1`, disabledUser).Scan(&guacStatus); err != nil || guacStatus != "active" {
		t.Errorf("guac session must stay active without a client, got %q (err %v)", guacStatus, err)
	}

	// Idempotent second tick.
	s.runLifecycleEnforcement(ctx)
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM vault_checkouts WHERE status='active'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("second tick changed state: %d active (err %v)", n, err)
	}
}
