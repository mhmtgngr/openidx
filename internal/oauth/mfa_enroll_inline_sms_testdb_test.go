package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/sms"
)

// captureSMS is a delivering SMS provider that records the last code sent.
type captureSMS struct {
	mu   sync.Mutex
	last string
	to   string
}

func (p *captureSMS) SendOTP(_ context.Context, phone, code string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.last, p.to = code, phone
	return nil
}
func (p *captureSMS) SendMessage(context.Context, string, string) error { return nil }
func (p *captureSMS) code() string                                      { p.mu.Lock(); defer p.mu.Unlock(); return p.last }

// SMS inline enrolment: offered only when SMS is really deliverable and never
// to an external user; a texted code completes the pending sign-in; a wrong
// one is refused.
func TestInlineEnrollmentSMS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newMFAGraceFixture(t)
	f.setPolicy(`["sms","totp"]`, 0)
	f.s.config.MFAInlineEnrollment = true

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: f.org}))
		c.Next()
	})
	router.POST("/oauth/login", f.s.handleLogin)
	router.POST("/oauth/mfa/enroll/sms/begin", f.s.handleMFAEnrollSMSBegin)
	router.POST("/oauth/mfa/enroll/sms/finish", f.s.handleMFAEnrollSMSFinish)

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
	login := func(name, wantMethods string) string {
		t.Helper()
		u := f.user(name)
		ls := GenerateRandomToken(16)
		params, _ := json.Marshal(map[string]string{
			"client_id": "grace-client", "redirect_uri": "https://app.example.test/callback",
			"scope": "openid", "state": "st-1",
		})
		f.s.redis.Client.Set(context.Background(), "login_session:"+ls, params, time.Minute)
		code, resp := post("/oauth/login", map[string]string{"username": u.UserName, "password": mfaGracePassword, "login_session": ls})
		es, _ := resp["enroll_session"].(string)
		if code != http.StatusOK || es == "" || fmt.Sprint(resp["methods"]) != wantMethods {
			t.Fatalf("login: want an enroll_session for %s, got %d %v", wantMethods, code, resp)
		}
		return es
	}
	begin := map[string]string{"phone_number": "5551234567", "country_code": "+1"}

	t.Run("not offered when SMS is disabled", func(t *testing.T) {
		f.s.identityService.SetSMSProvider(nil)
		es := login("sms-off", "[totp]")
		begin["enroll_session"] = es
		if code, _ := post("/oauth/mfa/enroll/sms/begin", begin); code != http.StatusBadRequest {
			t.Fatalf("sms begin without the factor offered: %d, want 400", code)
		}
		// A configured but mock or disabled provider is not deliverable either.
		mock, err := sms.NewService(sms.Config{Provider: "mock", Enabled: true, AllowMock: true}, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		f.s.identityService.SetSMSProvider(mock)
		login("sms-mock", "[totp]")
	})

	t.Run("not offered to an external user", func(t *testing.T) {
		f.s.identityService.SetSMSProvider(&captureSMS{})
		ev := mfaEvaluation{EnrollmentRequired: true, External: true, RequiredMethods: []string{"sms", "totp"}}
		ext := &identity.User{ID: f.user("sms-ext").ID, UserType: "external"}
		_, methods, ok := f.s.offerInlineEnrollment(f.orgCtx, ext, map[string]string{"client_id": "grace-client"}, ev, "pwd")
		if !ok || fmt.Sprint(methods) != "[totp]" {
			t.Fatalf("external user offered %v (ok=%v), want [totp]", methods, ok)
		}
	})

	t.Run("enrol and verify completes the sign-in, wrong code refused", func(t *testing.T) {
		p := &captureSMS{}
		f.s.identityService.SetSMSProvider(p)
		es := login("sms-ok", "[sms totp]")
		if code, _ := post("/oauth/mfa/enroll/sms/finish", map[string]string{"enroll_session": es, "code": "123456"}); code != http.StatusBadRequest {
			t.Fatalf("finish before begin: %d, want 400", code)
		}
		begin["enroll_session"] = es
		if code, resp := post("/oauth/mfa/enroll/sms/begin", begin); code != http.StatusOK || p.code() == "" || p.to != "+15551234567" {
			t.Fatalf("begin: %d %v, sent %q to %q", code, resp, p.code(), p.to)
		}
		wrong := "000000"
		if p.code() == wrong {
			wrong = "111111"
		}
		if code, _ := post("/oauth/mfa/enroll/sms/finish", map[string]string{"enroll_session": es, "code": wrong}); code != http.StatusUnauthorized {
			t.Fatalf("wrong code: %d, want 401", code)
		}
		code, done := post("/oauth/mfa/enroll/sms/finish", map[string]string{"enroll_session": es, "code": p.code()})
		if code != http.StatusOK || !strings.Contains(fmt.Sprint(done["redirect_url"]), "code=") {
			t.Fatalf("finish: %d %v", code, done)
		}
		if code, _ := post("/oauth/mfa/enroll/sms/finish", map[string]string{"enroll_session": es, "code": p.code()}); code != http.StatusBadRequest {
			t.Fatalf("replay: %d, want 400", code)
		}
	})
}
