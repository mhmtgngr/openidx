package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// An administrator resets a user's MFA: only an admin may, never their own,
// only for a user in their organization, and the named factors -- or all of
// them -- go in one step while another user's factors stay.
func TestAdminResetMFA(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)
	f := &pushFixture{t: t, db: db, ctx: orgctx.WithBypassRLS(context.Background()), suffix: fmt.Sprintf("%d", time.Now().UnixNano())}

	var orgB string
	if err := db.Pool.QueryRow(f.ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "reset-b-"+f.suffix).Scan(&orgB); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	admin := f.user("reset-admin", pushTestOrg)
	target := f.user("reset-target", pushTestOrg)
	bystander := f.user("reset-bystander", pushTestOrg)
	stranger := f.user("reset-stranger", orgB)

	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(f.ctx, q, args...); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	seedAll := func(user string) {
		exec(`INSERT INTO mfa_totp (user_id, secret, enabled, org_id) VALUES ($1, 'seed', true, $2)`, user, pushTestOrg)
		exec(`INSERT INTO mfa_webauthn (user_id, credential_id, public_key, name, org_id)
		      VALUES ($1::uuid, 'cred-1-'||$1::text, 'cose', 'Key 1', $2), ($1::uuid, 'cred-2-'||$1::text, 'cose', 'Key 2', $2)`, user, pushTestOrg)
		exec(`INSERT INTO mfa_email_otp (user_id, email_address, enabled, org_id) VALUES ($1::uuid, 'otp-'||$1::text||'@example.test', true, $2)`, user, pushTestOrg)
		exec(`INSERT INTO mfa_sms (user_id, phone_number, country_code, verified, enabled, org_id) VALUES ($1::uuid, '5550100', '+1', true, true, $2)`, user, pushTestOrg)
		exec(`INSERT INTO mfa_backup_codes (user_id, code_hash, org_id) VALUES ($1::uuid, 'h1-'||$1::text, $2), ($1::uuid, 'h2-'||$1::text, $2)`, user, pushTestOrg)
		f.device(user, pushTestOrg, "phone-a-"+user, true, "NOW()", "NOW()")
		f.device(user, pushTestOrg, "phone-b-"+user, true, "NOW()", "NOW()")
	}
	seedAll(target)
	seedAll(bystander)

	count := func(user, table string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(f.ctx, `SELECT count(*) FROM `+table+` WHERE user_id = $1::uuid`, user).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	call := func(caller string, roles []string, user, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Params = gin.Params{{Key: "id", Value: user}}
		c.Set("user_id", caller)
		c.Set("roles", roles)
		c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)).
			WithContext(orgctx.With(context.Background(), orgctx.Org{ID: pushTestOrg}))
		c.Request.Header.Set("Content-Type", "application/json")
		svc.handleAdminResetMFA(c)
		return w
	}
	admins := []string{"admin"}

	if w := call(admin, []string{"user"}, target, ``); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin reset: %d, want 403", w.Code)
	}
	if w := call(admin, admins, admin, ``); w.Code != http.StatusForbidden {
		t.Fatalf("self reset: %d, want 403", w.Code)
	}
	if w := call(admin, admins, stranger, ``); w.Code != http.StatusNotFound {
		t.Fatalf("another org's user: %d, want 404", w.Code)
	}
	if w := call(admin, admins, target, `{"factors":["password"]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown factor: %d, want 400", w.Code)
	}
	if n := count(target, "mfa_totp"); n != 1 {
		t.Fatalf("a refused reset removed TOTP: %d rows", n)
	}

	// Named factors: only those go.
	w := call(admin, admins, target, `{"factors":["TOTP","push","push"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("named reset: %d %s", w.Code, w.Body.String())
	}
	var got struct {
		Factors []string         `json:"factors"`
		Removed map[string]int64 `json:"removed"`
		Total   int64            `json:"total_removed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Factors, ",") != "push,totp" || got.Removed["push"] != 2 || got.Removed["totp"] != 1 || got.Total != 3 {
		t.Fatalf("named reset answered %+v", got)
	}
	if count(target, "mfa_totp") != 0 || count(target, "mfa_push_devices") != 0 {
		t.Fatal("named factors not removed")
	}
	if count(target, "mfa_webauthn") != 2 || count(target, "mfa_email_otp") != 1 {
		t.Fatal("a named reset removed factors it was not asked to")
	}
	f.waitAudit("mfa.admin_reset", target)

	// Empty body: everything else goes, unused backup codes included.
	if w := call(admin, admins, target, ``); w.Code != http.StatusOK {
		t.Fatalf("full reset: %d %s", w.Code, w.Body.String())
	}
	for _, table := range []string{"mfa_totp", "mfa_webauthn", "mfa_push_devices", "mfa_email_otp", "mfa_sms", "mfa_backup_codes", "mfa_phone_call"} {
		if n := count(target, table); n != 0 {
			t.Errorf("after a full reset %s still has %d rows", table, n)
		}
	}
	has, err := svc.hasSecondFactor(orgctx.With(context.Background(), orgctx.Org{ID: pushTestOrg}), target)
	if err != nil || has {
		t.Fatalf("after a full reset hasSecondFactor = %v (%v)", has, err)
	}

	// The bystander in the same org kept everything.
	for table, want := range map[string]int{"mfa_totp": 1, "mfa_webauthn": 2, "mfa_push_devices": 2, "mfa_email_otp": 1, "mfa_sms": 1, "mfa_backup_codes": 2} {
		if n := count(bystander, table); n != want {
			t.Errorf("bystander %s = %d, want %d", table, n, want)
		}
	}
}

func TestNormalizeMFAResetFactors(t *testing.T) {
	all, err := normalizeMFAResetFactors(nil)
	if err != nil || len(all) != len(mfaResetStatements) {
		t.Fatalf("empty request = %v (%v), want every factor", all, err)
	}
	got, err := normalizeMFAResetFactors([]string{" WebAuthn ", "sms", "webauthn"})
	if err != nil || strings.Join(got, ",") != "sms,webauthn" {
		t.Fatalf("normalize = %v (%v)", got, err)
	}
	if _, err := normalizeMFAResetFactors([]string{"password"}); err == nil {
		t.Fatal("unknown factor accepted")
	}
}
