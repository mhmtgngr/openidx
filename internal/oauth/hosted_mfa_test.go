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
	issueAt := strings.Index(fn, "s.issueHostedAuthorizationCode(")

	if evalAt < 0 {
		t.Fatal("handleAuthorizeCallback must evaluate MFA (s.evaluateMFA) — without it the hosted login page skips the second factor")
	}
	if challengeAt < 0 {
		t.Fatal("handleAuthorizeCallback must hand off to the hosted MFA challenge (s.beginHostedMFA)")
	}
	if issueAt < 0 {
		t.Fatal("handleAuthorizeCallback should still issue a code when no factor is required")
	}
	if strings.Contains(fn[:issueAt], "s.CreateAuthorizationCode(") {
		t.Error("the hosted path must not mint a code of its own; issue through the shared helper")
	}
	if evalAt > issueAt || challengeAt > issueAt {
		t.Error("the MFA evaluation and challenge must come BEFORE the authorization code is issued")
	}
}

// TestSessionMethodsHonoursPinnedList is the regression guard for a policy
// bypass in the first cut of this flow: the challenge pages re-derived the
// offerable factors from enrollment on every step, so a restriction the risk
// policy imposed at password time (e.g. "this login may only be completed with
// a phishing-resistant factor") silently disappeared as soon as the user
// switched method — they could finish with a weaker factor the challenge never
// offered. The list pinned into the session is authoritative.
func TestSessionMethodsHonoursPinnedList(t *testing.T) {
	s := &Service{logger: zap.NewNop()}

	// enrolledMethods returns nothing without an identity service, which is the
	// intersection's other half; assert on the pinned parsing and filtering.
	tests := []struct {
		name    string
		pinned  string
		want    []string
		enrolls []string
	}{
		{"pinned narrows enrollment", "totp", []string{"totp"}, []string{"totp", "backup", "push"}},
		{"pinned drops unenrolled", "totp,push", []string{"totp"}, []string{"totp"}},
		{"pinned filtered for completability", "webauthn,totp", []string{"totp"}, []string{"webauthn", "totp"}},
		{"absent pin falls back to enrollment", "", []string{"totp", "backup"}, []string{"totp", "backup"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.filterSessionMethods(tt.enrolls, tt.pinned)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// TestHostedLoginRecordsSession guards the other half of the divergence between
// the two login implementations: the server-rendered path issued a code without
// ever calling CreateSession, so a BrowZer / mobile / desktop sign-in produced
// no sessions row — the user's own "My Sessions" never listed it and an admin
// revoking sessions could not reach it.
func TestHostedLoginRecordsSession(t *testing.T) {
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

	if !strings.Contains(fn, "CreateSession(") {
		t.Error("the hosted login path must create a session, like the JSON path does")
	}
	if !strings.Contains(fn, "recordSessionAuthMethods(") {
		t.Error("the hosted login path must stamp the auth methods on the session")
	}
	if !strings.Contains(fn, "s.issueHostedAuthorizationCode(") {
		t.Error("the hosted login path should issue through the shared helper so the session is linked to the code")
	}
}

// TestRenderMFAPageWithNoMethods: every offered factor can disappear mid-flow
// (an admin removes the user's TOTP while they are on the challenge page). The
// page must refuse rather than index into an empty method list — and must never
// fall through to issuing anything.
func TestRenderMFAPageWithNoMethods(t *testing.T) {
	s := &Service{logger: zap.NewNop()}
	c, w := newRenderContext(t)

	s.renderMFAPage(c, "sess-1", nil, "totp", "", "")

	body := w.Body.String()
	if !strings.Contains(body, "expired") {
		t.Errorf("expected the expired/refused page, got: %s", body)
	}
	if strings.Contains(body, "/oauth/authorize/mfa\"") {
		t.Error("must not render a verify form with no completable factor")
	}
}

// TestHostedMFAStepsAreRateLimited pins the hosted challenge onto the strict
// auth tier. Its JSON twin (/oauth/mfa-verify) has always been there; without
// the same treatment the server-rendered TOTP form would accept unlimited
// guesses against a 5-minute session. The push wait page is the exception: it
// refreshes every 3s by design and only reads one challenge's status.
func TestHostedMFAStepsAreRateLimited(t *testing.T) {
	src, err := os.ReadFile("../common/middleware/ratelimit.go")
	if err != nil {
		t.Fatalf("read ratelimit.go: %v", err)
	}
	text := string(src)
	authAt := strings.Index(text, "var authPaths")
	pollAt := strings.Index(text, "var pollPaths")
	if authAt < 0 || pollAt < 0 {
		t.Fatal("could not find the path lists")
	}
	authBlock := text[authAt:pollAt]
	pollBlock := text[pollAt:]

	if !strings.Contains(authBlock, `"/oauth/authorize/mfa"`) {
		t.Error("the hosted MFA steps must be on the strict auth rate-limit tier")
	}
	if !strings.Contains(pollBlock, `"/oauth/authorize/mfa/wait"`) {
		t.Error("the hosted push wait page must be exempt as a status poll")
	}
}
