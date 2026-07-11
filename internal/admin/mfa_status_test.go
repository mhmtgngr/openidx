package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestUserMFAStatus_RealTables guards the user_mfa_methods repoint: the admin
// MFA stats/status handlers and their org scoping must work against the real
// enrollment tables (mfa_totp, mfa_sms, mfa_email_otp, mfa_push_devices,
// mfa_webauthn, mfa_backup_codes). The old queries read the user_mfa_methods
// view that only legacy SQL files defined, so every one of these handlers
// 500'd/404'd unconditionally.
func TestUserMFAStatus_RealTables(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := orgctx.WithBypassRLS(context.Background())

	const (
		orgA = "00000000-0000-0000-0000-000000000010" // seeded default org
		orgB = "00000000-0000-0000-0000-0000000000b2"
		u1   = "11111111-0000-0000-0000-0000000000f1" // TOTP in org A
		u2   = "11111111-0000-0000-0000-0000000000f2" // SMS + backup codes in org A
		u3   = "11111111-0000-0000-0000-0000000000f3" // WebAuthn in org B
	)

	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org B (mfa test)', 'org-b-mfa-test')`, orgB)
	exec(`INSERT INTO users (id, username, email, org_id) VALUES ($1, 'mfa-u1', 'mfa-u1@test.local', $2)`, u1, orgA)
	exec(`INSERT INTO users (id, username, email, org_id) VALUES ($1, 'mfa-u2', 'mfa-u2@test.local', $2)`, u2, orgA)
	exec(`INSERT INTO users (id, username, email, org_id) VALUES ($1, 'mfa-u3', 'mfa-u3@test.local', $2)`, u3, orgB)

	// Real enrollments. A disabled TOTP row on u2 must NOT count.
	exec(`INSERT INTO mfa_totp (user_id, secret, enabled, org_id) VALUES ($1, 'sec1', true, $2)`, u1, orgA)
	exec(`INSERT INTO mfa_totp (user_id, secret, enabled, org_id) VALUES ($1, 'sec2', false, $2)`, u2, orgA)
	exec(`INSERT INTO mfa_sms (user_id, phone_number, country_code, verified, enabled) VALUES ($1, '+15551234567', '+1', true, true)`, u2)
	exec(`INSERT INTO mfa_backup_codes (user_id, code_hash, used, org_id) VALUES ($1, 'h1', false, $2)`, u2, orgA)
	exec(`INSERT INTO mfa_backup_codes (user_id, code_hash, used, org_id) VALUES ($1, 'h2', true, $2)`, u2, orgA)
	exec(`INSERT INTO mfa_webauthn (user_id, credential_id, public_key, org_id) VALUES ($1, 'cred-u3', 'pk', $2)`, u3, orgB)

	var totalA int
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE org_id = $1`, orgA).Scan(&totalA); err != nil {
		t.Fatalf("count org A users: %v", err)
	}

	s := &Service{db: db, logger: zap.NewNop()}
	newCtx := func(orgID, paramID string) (*gin.Context, *httptest.ResponseRecorder) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/mfa", nil)
		req = req.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: orgID}))
		c.Request = req
		c.Set("roles", []string{"admin"})
		if paramID != "" {
			c.Params = gin.Params{{Key: "id", Value: paramID}}
		}
		return c, w
	}

	t.Run("enrollment stats are derived and org-scoped", func(t *testing.T) {
		c, w := newCtx(orgA, "")
		s.handleMFAEnrollmentStats(c)
		if w.Code != http.StatusOK {
			t.Fatalf("stats: expected 200, got %d (%s)", w.Code, w.Body.String())
		}
		var stats MFAEnrollmentStats
		if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if stats.TotalUsers != totalA {
			t.Fatalf("total_users: want %d, got %d", totalA, stats.TotalUsers)
		}
		if stats.TOTPCount != 1 || stats.SMSCount != 1 || stats.AnyMFA != 2 {
			t.Fatalf("org A counts: want totp=1 sms=1 any=2, got %+v", stats)
		}
		if stats.WebAuthnCount != 0 {
			t.Fatalf("org B's webauthn enrollment leaked into org A stats: %+v", stats)
		}

		cB, wB := newCtx(orgB, "")
		s.handleMFAEnrollmentStats(cB)
		if wB.Code != http.StatusOK {
			t.Fatalf("org B stats: expected 200, got %d (%s)", wB.Code, wB.Body.String())
		}
		var statsB MFAEnrollmentStats
		if err := json.Unmarshal(wB.Body.Bytes(), &statsB); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if statsB.WebAuthnCount != 1 || statsB.TOTPCount != 0 || statsB.AnyMFA != 1 {
			t.Fatalf("org B counts: want webauthn=1 totp=0 any=1, got %+v", statsB)
		}
	})

	t.Run("single-user status reflects real enrollments", func(t *testing.T) {
		c, w := newCtx(orgA, u2)
		s.handleGetUserMFAStatus(c)
		if w.Code != http.StatusOK {
			t.Fatalf("u2 status: expected 200, got %d (%s)", w.Code, w.Body.String())
		}
		var st UserMFAStatus
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !st.SMSEnabled || st.TOTPEnabled || st.BackupCodesRemaining != 1 {
			t.Fatalf("u2: want sms=true totp=false backup=1, got %+v", st)
		}
	})

	t.Run("cross-org user status is not found", func(t *testing.T) {
		c, w := newCtx(orgA, u3)
		s.handleGetUserMFAStatus(c)
		if w.Code != http.StatusNotFound {
			t.Fatalf("org A reading org B user's MFA status: expected 404, got %d (%s)", w.Code, w.Body.String())
		}
	})

	t.Run("list covers every org user with derived flags", func(t *testing.T) {
		c, w := newCtx(orgA, "")
		s.handleListUserMFAStatus(c)
		if w.Code != http.StatusOK {
			t.Fatalf("list: expected 200, got %d (%s)", w.Code, w.Body.String())
		}
		var resp struct {
			Data  []UserMFAStatus `json:"data"`
			Total int             `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Total != totalA || len(resp.Data) != totalA {
			t.Fatalf("list: want %d org A users, got total=%d rows=%d", totalA, resp.Total, len(resp.Data))
		}
		byID := map[string]UserMFAStatus{}
		for _, row := range resp.Data {
			byID[row.UserID] = row
		}
		if !byID[u1].TOTPEnabled || byID[u1].SMSEnabled {
			t.Fatalf("u1: want totp only, got %+v", byID[u1])
		}
		if _, leaked := byID[u3]; leaked {
			t.Fatalf("org B user leaked into org A listing")
		}
	})
}
