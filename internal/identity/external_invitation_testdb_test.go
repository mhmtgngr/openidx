package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestAnExternalInvitationActivatesOnlyWithASecondFactor drives an external
// (vendor) invitation through the identity routes on the migrated schema:
//
//   - the invitation is checked against the invariants when it is issued: a
//     vendor that exists and is active, an address in its domains, a sponsor
//     who is an enabled internal user, a lifetime within a year and within the
//     contract (a defaulted one is cut back to the contract's end), only the
//     user role and only groups open to external users;
//   - the acceptance makes an account that cannot sign in (pending_mfa,
//     disabled) and hands back an authenticator secret;
//   - a wrong code leaves it so, the right code activates it, and only then
//     does the password sign-in accept it; the token is spent both times;
//   - an active external account cannot add an SMS factor, an internal one
//     reaches the handler, and an account past its expiry is refused at
//     sign-in even before any sweep has marked it.
func TestAnExternalInvitationActivatesOnlyWithASecondFactor(t *testing.T) {
	db, cleanup := setupMigratedDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	gin.SetMode(gin.TestMode)

	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("read (%s): %v", q, err)
		}
		return v
	}
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			org, name+"-"+suffix)
	}
	admin := user("inv-admin")
	sponsor := user("inv-sponsor")
	vendor := scalar(`INSERT INTO vendor_organizations (org_id, name, allowed_email_domains, contract_end)
		VALUES ($1, $2, '{supplier.example.test}', '2099-12-31') RETURNING id::text`, org, "Acme "+suffix)
	contractEnd := time.Now().UTC().AddDate(0, 0, 10)
	shortVendor := scalar(`INSERT INTO vendor_organizations (org_id, name, contract_end)
		VALUES ($1, $2, $3::date) RETURNING id::text`, org, "Short Contract "+suffix, contractEnd.Format("2006-01-02"))
	suspendedVendor := scalar(`INSERT INTO vendor_organizations (org_id, name, status)
		VALUES ($1, $2, 'suspended') RETURNING id::text`, org, "Paused "+suffix)
	externalSponsor := scalar(`
		INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		VALUES ($1, $2::text, $2::text || '@supplier.example.test', 'external', $3, $4, NOW() + interval '30 days')
		RETURNING id::text`, org, "inv-ext-sponsor-"+suffix, vendor, sponsor)
	openGroup := "inv-vendors-" + suffix
	closedGroup := "inv-finance-" + suffix
	scalar(`INSERT INTO groups (org_id, name, external_allowed) VALUES ($1, $2, true) RETURNING id::text`, org, openGroup)
	scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, closedGroup)

	svc := NewService(db, nil, &config.Config{}, zap.NewNop())
	engine := func(userID string) *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			if userID != "" {
				c.Set("user_id", userID)
				c.Set("roles", []string{"admin"})
			}
			c.Next()
		})
		r.GET("/invitations", svc.handleListInvitations)
		r.POST("/invitations", svc.handleCreateInvitation)
		r.POST("/invitations/:token/accept", svc.handleAcceptInvitation)
		r.POST("/invitations/:token/mfa", svc.handleCompleteInvitationMFA)
		r.POST("/mfa/sms/enroll", svc.strongFactorsOnlyForExternal("sms"), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"reached": true})
		})
		return r
	}
	call := func(r *gin.Engine, method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	asAdmin, public := engine(admin), engine("")
	invite := func(fields string) (int, map[string]interface{}) {
		t.Helper()
		return call(asAdmin, http.MethodPost, "/invitations", `{"user_type":"external",`+fields+`}`)
	}
	email := "vendor-" + suffix + "@supplier.example.test"

	t.Run("an external invitation is checked against the invariants when it is issued", func(t *testing.T) {
		for _, tc := range []struct {
			name, fields string
			status       int
			code         string
		}{
			{"no vendor", `"email":"` + email + `"`, http.StatusBadRequest, ""},
			{"a suspended vendor", `"email":"` + email + `","vendor_org_id":"` + suspendedVendor + `"`, http.StatusForbidden, "vendor_not_active"},
			{"an address outside the vendor's domains", `"email":"x-` + suffix + `@elsewhere.example.test","vendor_org_id":"` + vendor + `"`, http.StatusForbidden, "external_email_domain"},
			{"a role above user", `"email":"` + email + `","vendor_org_id":"` + vendor + `","roles":["admin"]`, http.StatusForbidden, "external_role_cap"},
			{"a group not open to external users", `"email":"` + email + `","vendor_org_id":"` + vendor + `","groups":["` + closedGroup + `"]`, http.StatusForbidden, "external_group_not_allowed"},
			{"a lifetime over a year", `"email":"` + email + `","vendor_org_id":"` + vendor + `","expires_in_days":400`, http.StatusForbidden, "external_expiry_invalid"},
			{"a lifetime past the contract", `"email":"y-` + suffix + `@example.test","vendor_org_id":"` + shortVendor + `","expires_in_days":30`, http.StatusForbidden, "external_expiry_invalid"},
			{"an external sponsor", `"email":"` + email + `","vendor_org_id":"` + vendor + `","sponsor_user_id":"` + externalSponsor + `"`, http.StatusForbidden, "external_sponsor_invalid"},
		} {
			code, body := invite(tc.fields)
			if code != tc.status || (tc.code != "" && body["code"] != tc.code) {
				t.Errorf("%s: %d %v, want %d %s", tc.name, code, body, tc.status, tc.code)
			}
		}
		if code, body := call(asAdmin, http.MethodPost, "/invitations", `{"email":"`+email+`","user_type":"contractor"}`); code != http.StatusBadRequest {
			t.Errorf("an unknown user_type: %d %v, want 400", code, body)
		}
		// The vendor's 90-day default is cut back to a 10-day contract.
		code, body := invite(`"email":"z-` + suffix + `@example.test","vendor_org_id":"` + shortVendor + `"`)
		if code != http.StatusCreated {
			t.Fatalf("a defaulted lifetime on a short contract: %d %v", code, body)
		}
		got := scalar(`SELECT account_expires_at::date::text FROM user_invitations WHERE id = $1`, body["id"])
		if got != contractEnd.Format("2006-01-02") {
			t.Errorf("a defaulted lifetime ends %s, want the contract's end %s", got, contractEnd.Format("2006-01-02"))
		}
	})

	var token string
	t.Run("the acceptance makes an account that cannot sign in", func(t *testing.T) {
		code, body := invite(`"email":"` + email + `","vendor_org_id":"` + vendor + `","sponsor_user_id":"` + sponsor +
			`","roles":["user"],"groups":["` + openGroup + `"],"expires_in_days":30`)
		if code != http.StatusCreated {
			t.Fatalf("issue: %d %v", code, body)
		}
		token, _ = body["token"].(string)

		code, list := call(asAdmin, http.MethodGet, "/invitations", "")
		found := false
		for _, raw := range list["invitations"].([]interface{}) {
			inv := raw.(map[string]interface{})
			if inv["token"] == token {
				found = inv["user_type"] == "external" && inv["vendor_org_id"] == vendor && inv["sponsor_user_id"] == sponsor
			}
		}
		if code != http.StatusOK || !found {
			t.Errorf("the invitation list does not show the external invitation with its vendor and sponsor: %d %v", code, list)
		}

		code, body = call(public, http.MethodPost, "/invitations/"+token+"/accept",
			`{"username":"vendor-`+suffix+`","password":"Correct-horse-battery-9","first_name":"Vera"}`)
		if code != http.StatusCreated || body["status"] != "pending_mfa" {
			t.Fatalf("accept: %d %v", code, body)
		}
		mfa, _ := body["mfa"].(map[string]interface{})
		if mfa == nil || mfa["secret"] == "" {
			t.Fatalf("the acceptance handed back no authenticator secret: %v", body)
		}
		var status, userType string
		var enabled bool
		if err := db.Pool.QueryRow(ctx, `SELECT account_status, user_type, enabled FROM users WHERE username = $1`,
			"vendor-"+suffix).Scan(&status, &userType, &enabled); err != nil {
			t.Fatal(err)
		}
		if status != "pending_mfa" || userType != "external" || enabled {
			t.Fatalf("the new account is %s/%s enabled=%v, want external/pending_mfa disabled", userType, status, enabled)
		}
		if n := scalar(`SELECT count(*)::text FROM user_roles ur JOIN users u ON u.id = ur.user_id WHERE u.username = $1`, "vendor-"+suffix); n != "1" {
			t.Errorf("the account holds %s role(s), want the user role", n)
		}
		if _, err := svc.AuthenticateUser(ctx, "vendor-"+suffix, "Correct-horse-battery-9"); !errors.Is(err, ErrAccountDisabled) {
			t.Errorf("an account waiting for its second factor signed in: %v", err)
		}
		if code, _ := call(public, http.MethodPost, "/invitations/"+token+"/accept",
			`{"username":"vendor2-`+suffix+`","password":"Correct-horse-battery-9"}`); code != http.StatusBadRequest {
			t.Errorf("a spent invitation was accepted again: %d", code)
		}

		secret := mfa["secret"].(string)
		if code, body := call(public, http.MethodPost, "/invitations/"+token+"/mfa",
			`{"secret":"`+secret+`","code":"000000"}`); code != http.StatusBadRequest {
			t.Errorf("a wrong code: %d %v, want 400", code, body)
		}
		if s := scalar(`SELECT account_status FROM users WHERE username = $1`, "vendor-"+suffix); s != "pending_mfa" {
			t.Errorf("a wrong code moved the account to %s", s)
		}
		goodCode, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if code, body := call(public, http.MethodPost, "/invitations/"+token+"/mfa",
			`{"secret":"`+secret+`","code":"`+goodCode+`"}`); code != http.StatusOK || body["status"] != "active" {
			t.Fatalf("the right code: %d %v", code, body)
		}
		u, err := svc.AuthenticateUser(ctx, "vendor-"+suffix, "Correct-horse-battery-9")
		if err != nil || u.UserType != "external" {
			t.Fatalf("the activated account could not sign in: %v %v", u, err)
		}
		if n := scalar(`SELECT count(*)::text FROM mfa_totp WHERE user_id = $1 AND enabled`, u.ID); n != "1" {
			t.Errorf("the activated account has %s enabled authenticator(s), want 1", n)
		}
		if code, _ := call(public, http.MethodPost, "/invitations/"+token+"/mfa",
			`{"secret":"`+secret+`","code":"`+goodCode+`"}`); code != http.StatusBadRequest {
			t.Errorf("the invitation activated an account twice: %d", code)
		}
	})

	t.Run("an external account cannot add a code factor, and its expiry ends sign-in", func(t *testing.T) {
		ext := scalar(`SELECT id::text FROM users WHERE username = $1`, "vendor-"+suffix)
		code, body := call(engine(ext), http.MethodPost, "/mfa/sms/enroll", `{}`)
		if code != http.StatusForbidden || body["code"] != "external_factor_not_allowed" {
			t.Errorf("SMS enrollment for an external user: %d %v", code, body)
		}
		if code, body := call(engine(sponsor), http.MethodPost, "/mfa/sms/enroll", `{}`); code != http.StatusOK {
			t.Errorf("SMS enrollment for an internal user did not reach the handler: %d %v", code, body)
		}

		if _, err := db.Pool.Exec(ctx, `UPDATE users SET account_expires_at = NOW() - interval '1 minute' WHERE id = $1`, ext); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.AuthenticateUser(ctx, "vendor-"+suffix, "Correct-horse-battery-9"); !errors.Is(err, ErrAccountDisabled) {
			t.Errorf("an account past its expiry signed in: %v", err)
		}
	})
}
