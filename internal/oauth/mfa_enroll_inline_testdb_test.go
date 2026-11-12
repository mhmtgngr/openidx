package oauth

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
	"github.com/pquerna/otp/totp"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// Inline enrolment end to end, against the migrated schema: a login refused
// for want of the required method opens an enrol session, the authenticator
// app is set up against it, and the sign-in completes with an authorization
// code, backup codes and a session stamped pwd+mfa. The session is single use,
// bounded in attempts, and not interchangeable with a challenge session.
func TestInlineEnrollmentCompletesTheSignIn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newMFAGraceFixture(t)
	f.setPolicy(`["totp"]`, 0)
	f.s.config.MFAInlineEnrollment = true

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
		c.Next()
	})
	router.POST("/oauth/login", f.s.handleLogin)
	router.POST("/oauth/mfa-verify", f.s.handleMFAVerify)
	router.POST("/oauth/mfa/enroll/totp/begin", f.s.handleMFAEnrollTOTPBegin)
	router.POST("/oauth/mfa/enroll/totp/finish", f.s.handleMFAEnrollTOTPFinish)
	router.POST("/oauth/mfa/enroll/webauthn/begin", f.s.handleMFAEnrollWebAuthnBegin)

	post := func(path string, body interface{}) (int, map[string]interface{}) {
		t.Helper()
		b, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		var resp map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp
	}
	login := func(name string) string {
		t.Helper()
		u := f.user(name, "email")
		ls := GenerateRandomToken(16)
		params, _ := json.Marshal(map[string]string{
			"client_id": "grace-client", "redirect_uri": "https://app.example.test/callback",
			"scope": "openid", "state": "st-1",
		})
		f.s.redis.Client.Set(context.Background(), "login_session:"+ls, params, time.Minute)
		code, resp := post("/oauth/login", map[string]string{"username": u.UserName, "password": mfaGracePassword, "login_session": ls})
		es, _ := resp["enroll_session"].(string)
		if code != http.StatusOK || es == "" || fmt.Sprint(resp["methods"]) != "[totp]" {
			t.Fatalf("login: want an enroll_session for [totp], got %d %v", code, resp)
		}
		return es
	}

	t.Run("totp enrolment issues the code", func(t *testing.T) {
		es := login("inline-ok")
		if code, _ := post("/oauth/mfa/enroll/webauthn/begin", map[string]string{"enroll_session": es}); code != http.StatusBadRequest {
			t.Fatalf("a method the session does not allow must be refused, got %d", code)
		}
		if code, _ := post("/oauth/mfa-verify", map[string]string{"mfa_session": es, "code": "123456"}); code != http.StatusBadRequest {
			t.Fatalf("an enrol session must not complete a challenge, got %d", code)
		}
		code, begin := post("/oauth/mfa/enroll/totp/begin", map[string]string{"enroll_session": es})
		key, _ := begin["manual_key"].(string)
		if code != http.StatusOK || key == "" || begin["qr_code_url"] == nil {
			t.Fatalf("begin: %d %v", code, begin)
		}
		if code, _ := post("/oauth/mfa/enroll/totp/finish", map[string]string{"enroll_session": es, "code": "000000"}); code != http.StatusUnauthorized {
			t.Fatalf("a wrong code: %d, want 401", code)
		}
		otp, _ := totp.GenerateCode(key, time.Now())
		code, done := post("/oauth/mfa/enroll/totp/finish", map[string]string{"enroll_session": es, "code": otp})
		if code != http.StatusOK || done["redirect_url"] == nil {
			t.Fatalf("finish: %d %v", code, done)
		}
		if codes, _ := done["backup_codes"].([]interface{}); len(codes) == 0 {
			t.Fatalf("no backup codes in %v", done)
		}
		if !strings.Contains(fmt.Sprint(done["redirect_url"]), "code=") {
			t.Fatalf("no authorization code in %v", done["redirect_url"])
		}
		if code, _ := post("/oauth/mfa/enroll/totp/finish", map[string]string{"enroll_session": es, "code": otp}); code != http.StatusBadRequest {
			t.Fatalf("the session is single use, replay got %d", code)
		}
	})

	t.Run("attempts are bounded", func(t *testing.T) {
		es := login("inline-brute")
		post("/oauth/mfa/enroll/totp/begin", map[string]string{"enroll_session": es})
		last := 0
		for i := 0; i < mfaEnrollMaxAttempts+1; i++ {
			last, _ = post("/oauth/mfa/enroll/totp/finish", map[string]string{"enroll_session": es, "code": "000000"})
		}
		if last == http.StatusOK || last == http.StatusUnauthorized {
			t.Fatalf("after %d wrong codes the session must be gone, got %d", mfaEnrollMaxAttempts+1, last)
		}
	})
}
