package oauth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TestHostedMFAMethods pins which factors the server-rendered login page will
// offer. WebAuthn needs a browser API call and the page carries no JavaScript,
// so it must not be offered — and, critically, a user left with no completable
// factor must produce an EMPTY list, because beginHostedMFA refuses the login in
// that case rather than issuing a code without a second factor.
func TestHostedMFAMethods(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"drops webauthn", []string{"webauthn", "totp"}, []string{"totp"}},
		{"keeps order", []string{"push", "totp", "backup"}, []string{"push", "totp", "backup"}},
		{"drops unknown", []string{"totp", "carrier-pigeon"}, []string{"totp"}},
		{"webauthn only leaves nothing", []string{"webauthn"}, []string{}},
		{"empty", nil, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostedMFAMethods(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("hostedMFAMethods(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("hostedMFAMethods(%v) = %v, want %v", tt.in, got, tt.want)
				}
			}
		})
	}
}

func TestCodeEntryMethod(t *testing.T) {
	for _, m := range []string{"totp", "sms", "email", "backup", "bypass"} {
		if !codeEntryMethod(m) {
			t.Errorf("codeEntryMethod(%q) = false, want true", m)
		}
	}
	for _, m := range []string{"push", "webauthn", ""} {
		if codeEntryMethod(m) {
			t.Errorf("codeEntryMethod(%q) = true, want false", m)
		}
	}
}

func newRenderContext(t *testing.T) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	return c, w
}

// TestRenderMFAPageIsSelfContained covers the server-rendered challenge: it must
// post back to the hosted verify endpoint, carry the session, offer the trust
// choice, and contain no script (the login page's CSP is script-src 'self').
func TestRenderMFAPageIsSelfContained(t *testing.T) {
	s := &Service{logger: zap.NewNop()}
	c, w := newRenderContext(t)

	s.renderMFAPage(c, "sess-123", []string{"totp", "push"}, "totp", "", "")
	body := w.Body.String()

	for _, want := range []string{
		`action="/oauth/authorize/mfa"`,
		`name="mfa_session" value="sess-123"`,
		`name="method" value="totp"`,
		`name="trust_browser"`,
		`action="/oauth/authorize/mfa/method"`, // switch to push
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
	if strings.Contains(strings.ToLower(body), "<script") {
		t.Error("the hosted MFA page must not contain script (CSP is script-src 'self')")
	}
}

// TestRenderMFAPageEscapesSession makes sure the session token is escaped into
// the hidden field rather than closing the attribute.
func TestRenderMFAPageEscapesSession(t *testing.T) {
	s := &Service{logger: zap.NewNop()}
	c, w := newRenderContext(t)

	s.renderMFAPage(c, `"><img src=x onerror=alert(1)>`, []string{"totp"}, "totp", "", "")
	body := w.Body.String()
	if strings.Contains(body, "<img src=x") {
		t.Error("mfa_session value was not escaped into the page")
	}
}

// TestRenderPushWaitPagePolls covers the JavaScript-free push wait: a meta
// refresh back to the wait endpoint carrying the session and challenge.
func TestRenderPushWaitPagePolls(t *testing.T) {
	s := &Service{logger: zap.NewNop()}
	c, w := newRenderContext(t)

	s.renderPushWaitPage(c, "sess-9", "chal-7", "42", true, "")
	body := w.Body.String()

	if !strings.Contains(body, `http-equiv="refresh"`) {
		t.Error("push wait page must refresh itself")
	}
	for _, want := range []string{"mfa_session=sess-9", "challenge_id=chal-7", "trust_browser=1"} {
		if !strings.Contains(body, want) {
			t.Errorf("refresh URL missing %q; body: %s", want, body)
		}
	}
	if !strings.Contains(body, ">42<") {
		t.Error("number-match code not shown")
	}
	if strings.Contains(strings.ToLower(body), "<script") {
		t.Error("the push wait page must not contain script")
	}
}

// TestHostedLoginEnforcesMFA is the regression guard for the bypass this work
// closed: the server-rendered login path (POST /oauth/authorize/callback) — the
// one every public client uses — must run the shared MFA evaluation and hand off
// to the challenge BEFORE it mints an authorization code. It previously went
// straight from password to code, so any user with TOTP or push enrolled could
// skip their second factor entirely by signing in there.
func TestHostedLoginEnforcesMFA(t *testing.T) {
	src, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("read service.go: %v", err)
	}
	fn := string(src)
	start := strings.Index(fn, "func (s *Service) handleAuthorizeCallback(")
	if start < 0 {
		t.Fatal("handleAuthorizeCallback not found")
	}
	fn = fn[start:]
	end := strings.Index(fn, "\n}\n")
	if end < 0 {
		t.Fatal("could not delimit handleAuthorizeCallback")
	}
	fn = fn[:end]

	evalAt := strings.Index(fn, "s.evaluateMFA(")
	challengeAt := strings.Index(fn, "s.beginHostedMFA(")
	issueAt := strings.Index(fn, "s.CreateAuthorizationCode(")

	if evalAt < 0 {
		t.Fatal("handleAuthorizeCallback must evaluate MFA (s.evaluateMFA) — without it the hosted login page skips the second factor")
	}
	if challengeAt < 0 {
		t.Fatal("handleAuthorizeCallback must hand off to the hosted MFA challenge (s.beginHostedMFA)")
	}
	if issueAt < 0 {
		t.Fatal("handleAuthorizeCallback should still issue a code when no factor is required")
	}
	if evalAt > issueAt || challengeAt > issueAt {
		t.Error("the MFA evaluation and challenge must come BEFORE the authorization code is issued")
	}
}
