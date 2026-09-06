package identity

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// MFA bypass codes are the break-glass credential: a string that gets a user
// past multi-factor authentication entirely. Three functions decide what one is
// worth — VerifyBypassCode, RevokeBypassCode, RevokeAllBypassCodes — and no
// test named any of them.

const (
	bypassOrg   = "00000000-0000-0000-0000-0000000000b0"
	bypassUser  = "00000000-0000-0000-0000-0000000000b1"
	bypassAdmin = "00000000-0000-0000-0000-0000000000b2"
)

const bypassSchema = `
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL DEFAULT 'test'
);
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    org_id UUID NOT NULL
);
CREATE TABLE IF NOT EXISTS mfa_bypass_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    generated_by UUID REFERENCES users(id) NOT NULL,
    valid_from TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
    max_uses INTEGER DEFAULT 1,
    use_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active',
    used_at TIMESTAMP WITH TIME ZONE,
    used_from_ip VARCHAR(45),
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS mfa_bypass_audit (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    bypass_code_id UUID REFERENCES mfa_bypass_codes(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    performed_by UUID REFERENCES users(id),
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
`

func newBypassService(t *testing.T) (*Service, context.Context) {
	t.Helper()

	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: bypassOrg})
	if _, err := db.Pool.Exec(ctx, bypassSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO organizations (id) VALUES ($1) ON CONFLICT DO NOTHING`, bypassOrg); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	for id, name := range map[string]string{bypassUser: "alice", bypassAdmin: "root"} {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO users (id, username, org_id) VALUES ($1, $2, $3)`, id, name, bypassOrg); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
	}

	return &Service{db: db, cfg: &config.Config{}, logger: zap.NewNop()}, ctx
}

// issueBypassCode writes a code the way GenerateBypassCode does, so the tests
// read the same rows production does.
func issueBypassCode(t *testing.T, s *Service, ctx context.Context, code string, validUntil time.Time, maxUses int) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	id := uuid.New().String()
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO mfa_bypass_codes (id, org_id, user_id, code_hash, reason, generated_by, valid_until, max_uses, use_count, status)
		VALUES ($1, $2, $3, $4, 'test', $5, $6, $7, 0, 'active')`,
		id, bypassOrg, bypassUser, string(hash), bypassAdmin, validUntil, maxUses); err != nil {
		t.Fatalf("issue: %v", err)
	}
	return id
}

func bypassRow(t *testing.T, s *Service, ctx context.Context, id string) (status string, useCount int) {
	t.Helper()
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT status, use_count FROM mfa_bypass_codes WHERE id = $1`, id).Scan(&status, &useCount); err != nil {
		t.Fatalf("read row: %v", err)
	}
	return status, useCount
}

func auditActions(t *testing.T, s *Service, ctx context.Context) []string {
	t.Helper()
	rows, err := s.db.Pool.Query(ctx, `SELECT action FROM mfa_bypass_audit ORDER BY created_at`)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, a)
	}
	return out
}

func TestVerifyBypassCodeSpendsASingleUseCodeExactlyOnce(t *testing.T) {
	s, ctx := newBypassService(t)
	id := issueBypassCode(t, s, ctx, "BREAK-GLASS-1", time.Now().Add(time.Hour), 1)

	ok, err := s.VerifyBypassCode(ctx, bypassUser, "BREAK-GLASS-1", "10.0.0.1", "test")
	if err != nil || !ok {
		t.Fatalf("first use = (%v, %v), want (true, nil)", ok, err)
	}
	if status, count := bypassRow(t, s, ctx, id); status != "used" || count != 1 {
		t.Fatalf("after one use: status=%q count=%d, want used/1", status, count)
	}

	// The second presentation of the same string is the whole point.
	ok, err = s.VerifyBypassCode(ctx, bypassUser, "BREAK-GLASS-1", "10.0.0.1", "test")
	if err != nil {
		t.Fatalf("second use error: %v", err)
	}
	if ok {
		t.Fatal("a single-use bypass code was accepted twice")
	}

	if got := auditActions(t, s, ctx); len(got) != 1 || got[0] != "used" {
		t.Fatalf("audit = %v, want exactly one 'used'", got)
	}
}

func TestVerifyBypassCodeHonoursMaxUses(t *testing.T) {
	s, ctx := newBypassService(t)
	id := issueBypassCode(t, s, ctx, "THREE-TIMES", time.Now().Add(time.Hour), 3)

	for i := 1; i <= 3; i++ {
		ok, err := s.VerifyBypassCode(ctx, bypassUser, "THREE-TIMES", "10.0.0.1", "test")
		if err != nil || !ok {
			t.Fatalf("use %d = (%v, %v), want (true, nil)", i, ok, err)
		}
		status, count := bypassRow(t, s, ctx, id)
		if count != i {
			t.Fatalf("use %d: count=%d", i, count)
		}
		want := "active"
		if i == 3 {
			want = "used"
		}
		if status != want {
			t.Fatalf("use %d: status=%q, want %q", i, status, want)
		}
	}

	if ok, _ := s.VerifyBypassCode(ctx, bypassUser, "THREE-TIMES", "10.0.0.1", "test"); ok {
		t.Fatal("a 3-use code was accepted a fourth time")
	}
}

func TestVerifyBypassCodeRefusesExpiredWrongAndRevokedCodes(t *testing.T) {
	s, ctx := newBypassService(t)

	expired := issueBypassCode(t, s, ctx, "EXPIRED", time.Now().Add(-time.Minute), 1)
	live := issueBypassCode(t, s, ctx, "LIVE", time.Now().Add(time.Hour), 1)

	t.Run("expired", func(t *testing.T) {
		ok, err := s.VerifyBypassCode(ctx, bypassUser, "EXPIRED", "10.0.0.1", "test")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if ok {
			t.Fatal("an expired bypass code was accepted")
		}
		// And the row is marked, so it stops being scanned.
		if status, _ := bypassRow(t, s, ctx, expired); status != "expired" {
			t.Fatalf("status = %q, want expired", status)
		}
	})

	t.Run("wrong code", func(t *testing.T) {
		if ok, _ := s.VerifyBypassCode(ctx, bypassUser, "NOT-THE-CODE", "10.0.0.1", "test"); ok {
			t.Fatal("a wrong code was accepted")
		}
	})

	t.Run("another user's code", func(t *testing.T) {
		// Same string, different subject. The code is bound to a user, not
		// merely to being a valid string somewhere in the table.
		if ok, _ := s.VerifyBypassCode(ctx, bypassAdmin, "LIVE", "10.0.0.1", "test"); ok {
			t.Fatal("one user's bypass code let another user through")
		}
	})

	t.Run("revoked", func(t *testing.T) {
		if err := s.RevokeBypassCode(ctx, live, bypassAdmin, "10.0.0.9"); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if status, _ := bypassRow(t, s, ctx, live); status != "revoked" {
			t.Fatalf("status = %q, want revoked", status)
		}
		if ok, _ := s.VerifyBypassCode(ctx, bypassUser, "LIVE", "10.0.0.1", "test"); ok {
			t.Fatal("a revoked bypass code was accepted")
		}
	})
}

func TestRevokeBypassCodeIsIdempotentAndAudited(t *testing.T) {
	s, ctx := newBypassService(t)
	id := issueBypassCode(t, s, ctx, "ONE", time.Now().Add(time.Hour), 1)

	if err := s.RevokeBypassCode(ctx, id, bypassAdmin, "10.0.0.9"); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	// Revoking again is an error, not a silent success: "revoked" twice would
	// otherwise overwrite revoked_by and revoked_at with the second caller.
	if err := s.RevokeBypassCode(ctx, id, bypassUser, "10.0.0.8"); err == nil {
		t.Fatal("revoking an already-revoked code succeeded")
	}
	if err := s.RevokeBypassCode(ctx, uuid.New().String(), bypassAdmin, "10.0.0.9"); err == nil {
		t.Fatal("revoking a code that does not exist succeeded")
	}

	var revokedBy string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT revoked_by::text FROM mfa_bypass_codes WHERE id = $1`, id).Scan(&revokedBy); err != nil {
		t.Fatalf("read revoked_by: %v", err)
	}
	if revokedBy != bypassAdmin {
		t.Fatalf("revoked_by = %s, want the first admin", revokedBy)
	}
	if got := auditActions(t, s, ctx); len(got) != 1 || got[0] != "revoked" {
		t.Fatalf("audit = %v, want exactly one 'revoked'", got)
	}
}

func TestRevokeAllBypassCodesTakesOnlyTheActiveOnesForThatUser(t *testing.T) {
	s, ctx := newBypassService(t)

	a := issueBypassCode(t, s, ctx, "A", time.Now().Add(time.Hour), 1)
	b := issueBypassCode(t, s, ctx, "B", time.Now().Add(time.Hour), 1)
	spent := issueBypassCode(t, s, ctx, "C", time.Now().Add(time.Hour), 1)
	if ok, err := s.VerifyBypassCode(ctx, bypassUser, "C", "10.0.0.1", "test"); err != nil || !ok {
		t.Fatalf("spend C: (%v, %v)", ok, err)
	}

	n, err := s.RevokeAllBypassCodes(ctx, bypassUser, bypassAdmin, "10.0.0.9")
	if err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	if n != 2 {
		t.Fatalf("revoked %d, want the 2 still active", n)
	}
	for _, id := range []string{a, b} {
		if status, _ := bypassRow(t, s, ctx, id); status != "revoked" {
			t.Fatalf("%s status = %q, want revoked", id, status)
		}
	}
	// An already-spent code keeps its own history rather than being relabelled.
	if status, _ := bypassRow(t, s, ctx, spent); status != "used" {
		t.Fatalf("spent code status = %q, want used", status)
	}

	// Nothing left to revoke: no rows, and no audit entry claiming otherwise.
	before := len(auditActions(t, s, ctx))
	if n, err := s.RevokeAllBypassCodes(ctx, bypassUser, bypassAdmin, "10.0.0.9"); err != nil || n != 0 {
		t.Fatalf("second revoke-all = (%d, %v), want (0, nil)", n, err)
	}
	if after := len(auditActions(t, s, ctx)); after != before {
		t.Fatalf("audit grew from %d to %d on a no-op revoke-all", before, after)
	}
}
