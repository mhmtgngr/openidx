package identity

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// Tenant isolation for the credentials that stand in for a password.
//
// Before v145 none of hardware_tokens, mfa_bypass_codes or their audit tables
// carried an org_id, and internal/identity/hardware_token.go and mfa_bypass.go
// read and wrote them by bare id. The two cases that matter most are not the
// disclosures:
//
//   - AssignHardwareToken took a bare token id AND a bare user id. An
//     administrator of one tenant could bind a token sitting available in
//     another tenant's inventory to one of their own users, or bind their own
//     token to somebody else's user. Either way a working second factor moves
//     across a tenant boundary.
//   - RevokeBypassCode took a bare code id. The break-glass credential exists
//     for the moment MFA is in the way, so revoking another tenant's is a
//     denial that lands at the worst possible time.
//
// These run against a real database when one is reachable and skip otherwise;
// the belt itself is proved under a NOSUPERUSER role by
// test/integration/cross_org_test.go.
const credentialIsolationSchema = `
CREATE TABLE IF NOT EXISTS organizations (id UUID PRIMARY KEY, name TEXT);
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY, username TEXT, email TEXT, org_id UUID NOT NULL, enabled BOOLEAN DEFAULT TRUE);
CREATE TABLE IF NOT EXISTS hardware_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    serial_number VARCHAR(50) NOT NULL,
    name VARCHAR(255),
    token_type VARCHAR(50) NOT NULL DEFAULT 'yubikey',
    secret_key VARCHAR(255) NOT NULL,
    counter BIGINT DEFAULT 0,
    manufacturer VARCHAR(100),
    model VARCHAR(100),
    firmware_version VARCHAR(50),
    status VARCHAR(20) DEFAULT 'available',
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ,
    assigned_by UUID REFERENCES users(id),
    last_used_at TIMESTAMPTZ,
    use_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    notes TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_at TIMESTAMPTZ,
    locked_until TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_hardware_tokens_org_serial ON hardware_tokens(org_id, serial_number);
CREATE TABLE IF NOT EXISTS hardware_token_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    token_id UUID REFERENCES hardware_tokens(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    ip_address TEXT, user_agent TEXT, details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS mfa_bypass_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    generated_by UUID REFERENCES users(id) NOT NULL,
    valid_from TIMESTAMPTZ DEFAULT NOW(),
    valid_until TIMESTAMPTZ NOT NULL,
    max_uses INTEGER DEFAULT 1,
    use_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active',
    used_at TIMESTAMPTZ, used_from_ip VARCHAR(45),
    revoked_at TIMESTAMPTZ, revoked_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS mfa_bypass_audit (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    bypass_code_id UUID REFERENCES mfa_bypass_codes(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    performed_by UUID REFERENCES users(id),
    ip_address VARCHAR(45), user_agent TEXT, details JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID, service TEXT, category TEXT, action TEXT, result TEXT,
    actor_id TEXT, target_id TEXT, target_type TEXT, metadata JSONB,
    actor_ip TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
);`

const (
	credOrgA   = "00000000-0000-0000-0000-0000000000e1"
	credOrgB   = "00000000-0000-0000-0000-0000000000e2"
	credUserA  = "00000000-0000-0000-0000-0000000000e3"
	credUserB  = "00000000-0000-0000-0000-0000000000e4"
	credAdminA = "00000000-0000-0000-0000-0000000000e5"
	credAdminB = "00000000-0000-0000-0000-0000000000e6"
)

func newCredentialIsolationService(t *testing.T) (*Service, context.Context, context.Context, *database.PostgresDB) {
	t.Helper()

	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, credentialIsolationSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	for _, org := range []string{credOrgA, credOrgB} {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			org, "org-"+org[len(org)-2:]); err != nil {
			t.Fatalf("seed org: %v", err)
		}
	}
	for _, u := range []struct{ id, org, name string }{
		{credUserA, credOrgA, "alice"}, {credAdminA, credOrgA, "admin-a"},
		{credUserB, credOrgB, "bob"}, {credAdminB, credOrgB, "admin-b"},
	} {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO users (id, username, email, org_id) VALUES ($1, $2, $3, $4)`,
			u.id, u.name, u.name+"@example.test", u.org); err != nil {
			t.Fatalf("seed user %s: %v", u.name, err)
		}
	}

	cipher, err := secretcrypt.New("credential-isolation-key-32bytes")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	s := &Service{db: db, cfg: &config.Config{}, logger: zap.NewNop(), idpCipher: cipher}
	return s,
		orgctx.With(ctx, orgctx.Org{ID: credOrgA}),
		orgctx.With(ctx, orgctx.Org{ID: credOrgB}),
		db
}

func TestHardwareTokenTenantIsolation(t *testing.T) {
	s, aCtx, bCtx, db := newCredentialIsolationService(t)

	tokB, err := s.CreateHardwareToken(bCtx, &CreateHardwareTokenRequest{
		SerialNumber: "SER-B-0001", Name: "org B spare", TokenType: "oath-hotp",
	}, credAdminB)
	if err != nil {
		t.Fatalf("seed org B token: %v", err)
	}

	t.Run("the inventory list stops at the tenant boundary", func(t *testing.T) {
		got, err := s.ListHardwareTokens(aCtx, "", "")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, tok := range got {
			if tok.ID == tokB.ID {
				t.Fatal("org A listed org B's hardware token; before v145 this query had " +
					"no tenant predicate at all and both its filters are optional")
			}
		}
	})

	t.Run("get by id cannot reach another tenant's token", func(t *testing.T) {
		if _, err := s.GetHardwareToken(aCtx, tokB.ID); err == nil {
			t.Error("org A read org B's hardware token by id")
		}
	})

	// The one that is a transfer of a credential rather than a disclosure.
	t.Run("assign cannot take another tenant's available token", func(t *testing.T) {
		if err := s.AssignHardwareToken(aCtx, tokB.ID, credUserA, credAdminA); err == nil {
			t.Error("org A bound org B's available token to its own user")
		}
		var assigned *string
		if err := db.Pool.QueryRow(context.Background(),
			"SELECT assigned_to FROM hardware_tokens WHERE id = $1", tokB.ID).Scan(&assigned); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if assigned != nil {
			t.Errorf("org B's token is now assigned to %s", *assigned)
		}
	})

	// The other direction, which a predicate on the UPDATE alone would miss.
	t.Run("assign cannot bind our own token to another tenant's user", func(t *testing.T) {
		tokA, err := s.CreateHardwareToken(aCtx, &CreateHardwareTokenRequest{
			SerialNumber: "SER-A-0001", Name: "org A spare",
		}, credAdminA)
		if err != nil {
			t.Fatalf("seed org A token: %v", err)
		}
		if err := s.AssignHardwareToken(aCtx, tokA.ID, credUserB, credAdminA); err == nil {
			t.Error("org A issued its own token to a user in org B")
		}
	})

	t.Run("revoke and report-lost cannot reach another tenant's token", func(t *testing.T) {
		if err := s.RevokeHardwareToken(aCtx, tokB.ID, credAdminA, "not mine"); err == nil {
			t.Error("org A revoked org B's token")
		}
		if err := s.ReportTokenLost(aCtx, tokB.ID, credAdminA); err == nil {
			t.Error("org A reported org B's token lost")
		}
		var status string
		if err := db.Pool.QueryRow(context.Background(),
			"SELECT status FROM hardware_tokens WHERE id = $1", tokB.ID).Scan(&status); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if status != "available" {
			t.Errorf("org B's token status = %q, want available", status)
		}
	})

	// The v145 re-scope, stated as a test so a later batch cannot "restore" the
	// install-wide constraint by analogy with v144's entity_id. A hardware
	// serial resolves no tenant, so an install-wide key only handed the first
	// registrant a veto and answered questions about another tenant's hardware.
	t.Run("two tenants may record the same serial", func(t *testing.T) {
		if _, err := s.CreateHardwareToken(aCtx, &CreateHardwareTokenRequest{
			SerialNumber: "SER-B-0001", Name: "org A's own device with that serial",
		}, credAdminA); err != nil {
			t.Errorf("org A could not register a serial org B already holds: %v. "+
				"The serial resolves no tenant, so an install-wide UNIQUE only lets the "+
				"first registrant veto everybody else and confirms the existence of "+
				"hardware another tenant owns", err)
		}
	})
}

func TestMFABypassTenantIsolation(t *testing.T) {
	s, aCtx, bCtx, db := newCredentialIsolationService(t)

	codeB, err := s.GenerateMFABypassCode(bCtx, &GenerateBypassCodeRequest{
		UserID: credUserB, Reason: "lost phone", ValidHours: 4, MaxUses: 1,
	}, credAdminB, "10.0.0.9")
	if err != nil {
		t.Fatalf("seed org B bypass code: %v", err)
	}

	t.Run("revoke by id cannot kill another tenant's break-glass", func(t *testing.T) {
		if err := s.RevokeBypassCode(aCtx, codeB.ID, credAdminA, "10.0.0.1"); err == nil {
			t.Error("org A revoked org B's bypass code")
		}
		var status string
		if err := db.Pool.QueryRow(context.Background(),
			"SELECT status FROM mfa_bypass_codes WHERE id = $1", codeB.ID).Scan(&status); err != nil {
			t.Fatalf("read back: %v", err)
		}
		if status != "active" {
			t.Errorf("org B's bypass code status = %q, want active", status)
		}
	})

	t.Run("revoke-all cannot reach another tenant's user", func(t *testing.T) {
		n, err := s.RevokeAllBypassCodes(aCtx, credUserB, credAdminA, "10.0.0.1")
		if err != nil {
			t.Fatalf("revoke all: %v", err)
		}
		if n != 0 {
			t.Errorf("org A revoked %d of org B's codes", n)
		}
	})

	t.Run("the list stops at the tenant boundary", func(t *testing.T) {
		codes, total, err := s.ListBypassCodes(aCtx, "", "", false, 50, 0)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if total != 0 || len(codes) != 0 {
			t.Errorf("org A saw %d of org B's bypass codes (total=%d)", len(codes), total)
		}
	})

	// The widest read in the file, and the console calls it with no user.
	t.Run("the audit log with no user filter stays inside the tenant", func(t *testing.T) {
		entries, err := s.GetBypassAuditLog(aCtx, "", 100, 0)
		if err != nil {
			t.Fatalf("audit log: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("org A read %d entries of org B's bypass history with an empty user filter; "+
				"an optional predicate is not a predicate", len(entries))
		}

		own, err := s.GetBypassAuditLog(bCtx, "", 100, 0)
		if err != nil {
			t.Fatalf("owner audit log: %v", err)
		}
		if len(own) == 0 {
			t.Error("org B cannot read its own bypass history; the tenant predicate is too tight")
		}
	})

	// The bypassed verification path: the belt is lifted there, so the org term
	// in the predicate is the only thing keeping it inside the tenant. Assert
	// it directly rather than trusting the comment.
	t.Run("verification does not accept a code from another tenant's user", func(t *testing.T) {
		ok, err := s.VerifyBypassCode(context.Background(), credUserA, codeB.Code, "10.0.0.1", "test")
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if ok {
			t.Error("org A's user signed in with org B's bypass code")
		}
	})

	t.Run("the owner can still spend its own code", func(t *testing.T) {
		ok, err := s.VerifyBypassCode(context.Background(), credUserB, codeB.Code, "10.0.0.9", "test")
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !ok {
			t.Fatal("org B's user could not spend its own bypass code; the belt or the " +
				"predicate has made break-glass unusable, which is the failure this " +
				"function has already had once")
		}
	})
}

// The audit write runs on the bypassed verification path, where nothing on the
// connection names a tenant. It must still land, and land in the right one.
func TestMFABypassAuditIsFiledUnderTheCodesOrg(t *testing.T) {
	s, _, bCtx, db := newCredentialIsolationService(t)

	code, err := s.GenerateMFABypassCode(bCtx, &GenerateBypassCodeRequest{
		UserID: credUserB, Reason: "kiosk rollout", ValidHours: 1, MaxUses: 1,
	}, credAdminB, "10.0.0.9")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// context.Background(): no organization anywhere, the shape the oauth
	// service's step-up reaches this on.
	if ok, err := s.VerifyBypassCode(context.Background(), credUserB, code.Code, "10.0.0.9", "test"); err != nil || !ok {
		t.Fatalf("verify: ok=%v err=%v", ok, err)
	}

	var org string
	if err := db.Pool.QueryRow(context.Background(),
		`SELECT org_id::text FROM mfa_bypass_audit WHERE bypass_code_id = $1 AND action = 'used'`,
		code.ID).Scan(&org); err != nil {
		t.Fatalf("the 'used' audit entry was not written at all: %v", err)
	}
	if org != credOrgB {
		t.Errorf("bypass use filed under org %s, want %s (the code's own organization)", org, credOrgB)
	}
}

// A token event written from the bypassed verification path takes its tenant
// from the token, not from the connection.
func TestHardwareTokenEventIsFiledUnderTheTokensOrg(t *testing.T) {
	s, _, bCtx, db := newCredentialIsolationService(t)

	tok, err := s.CreateHardwareToken(bCtx, &CreateHardwareTokenRequest{
		SerialNumber: "SER-B-EVT", Name: "org B", TokenType: "oath-hotp",
	}, credAdminB)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.AssignHardwareToken(bCtx, tok.ID, credUserB, credAdminB); err != nil {
		t.Fatalf("assign: %v", err)
	}

	// A wrong code on a context with no organization. The verification fails;
	// the event must not.
	if _, err := s.VerifyHardwareToken(context.Background(), credUserB, "000000", "10.0.0.9", "test"); err != nil {
		t.Fatalf("verify: %v", err)
	}

	var org string
	if err := db.Pool.QueryRow(context.Background(),
		`SELECT org_id::text FROM hardware_token_events
		 WHERE token_id = $1 AND event_type = 'failed'`, tok.ID).Scan(&org); err != nil {
		t.Fatalf("the 'failed' token event was not written at all: %v", err)
	}
	if org != credOrgB {
		t.Errorf("token event filed under org %s, want %s (the token's own organization)", org, credOrgB)
	}
}

// Guards the fallback rather than the happy path: a magic link is minted inside
// an organization, so its row must carry that organization even though the
// verification that reads it back spans every tenant.
func TestMagicLinkCarriesItsOrgThroughAPreResolutionVerify(t *testing.T) {
	s, _, bCtx, db := newCredentialIsolationService(t)

	if _, err := db.Pool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS magic_links (
		    id UUID PRIMARY KEY, org_id UUID NOT NULL, user_id UUID NOT NULL,
		    email VARCHAR(255) NOT NULL, token_hash TEXT NOT NULL,
		    purpose VARCHAR(50), redirect_url TEXT, ip_address VARCHAR(45),
		    user_agent TEXT, status VARCHAR(20) NOT NULL,
		    created_at TIMESTAMPTZ DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL,
		    used_at TIMESTAMPTZ);
		CREATE TABLE IF NOT EXISTS passwordless_preferences (
		    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID,
		    user_id UUID, magic_link_enabled BOOLEAN DEFAULT TRUE,
		    qr_login_enabled BOOLEAN DEFAULT TRUE, biometric_enabled BOOLEAN DEFAULT FALSE,
		    preferred_method VARCHAR(50), created_at TIMESTAMPTZ DEFAULT NOW(),
		    updated_at TIMESTAMPTZ DEFAULT NOW());`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	link, err := s.CreateMagicLink(bCtx, "bob@example.test", "login", "", "10.0.0.9", "test")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	var org string
	if err := db.Pool.QueryRow(context.Background(),
		"SELECT org_id::text FROM magic_links WHERE id = $1", link.ID).Scan(&org); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if org != credOrgB {
		t.Errorf("magic link filed under org %s, want %s", org, credOrgB)
	}

	// And the pre-resolution verify still works with no organization anywhere:
	// the visitor holds a link and nothing else, so a scoped query here would
	// mean no magic link in the product ever worked again.
	userID, purpose, err := s.VerifyMagicLink(context.Background(), link.Token, "10.0.0.9", "test")
	if err != nil {
		t.Fatalf("verify with no org on the context: %v", err)
	}
	if userID == "" || purpose != "login" {
		t.Errorf("verify returned user=%q purpose=%q", userID, purpose)
	}
}
