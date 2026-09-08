package access

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TestEnrollOAuth_RequiresTheEnrollScope pins the one refusal /agent/enroll/oauth
// makes before touching anything: a bearer without agent.enroll -- which is
// every console session token, since no browser client is granted it -- is
// answered 403 insufficient_scope and no agent is issued.
//
// The handler is constructed with no database on purpose. issueAgentCredentials
// tolerates that (its no-DB branch mints a credential anyway), so a handler
// that let the request through would produce a 200 here, and the test would
// say so.
func TestEnrollOAuth_RequiresTheEnrollScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewAgentAPIHandler(zap.NewNop(), nil, nil, nil)

	cases := []struct {
		name  string
		scope string
		set   bool
		want  int
	}{
		{"no scope claim at all", "", false, http.StatusForbidden},
		{"console scopes only", "openid profile email", true, http.StatusForbidden},
		{"a scope that merely contains the word", "agent.enrollment", true, http.StatusForbidden},
		{"agent.enroll among others", "openid profile offline_access agent.enroll", true, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/agent/enroll/oauth", nil)
			c.Set("user_id", "user-1")
			if tc.set {
				c.Set("scope", tc.scope)
			}
			h.HandleEnrollOAuth(c)
			if w.Code != tc.want {
				t.Fatalf("scope=%q: status %d, want %d (body %s)", tc.scope, w.Code, tc.want, w.Body.String())
			}
			if tc.want == http.StatusForbidden && !strings.Contains(w.Body.String(), "insufficient_scope") {
				t.Errorf("refusal body does not name insufficient_scope: %s", w.Body.String())
			}
		})
	}
}

// TestTokenScopeAllows pins the parse: space-delimited, exact token match.
func TestTokenScopeAllows(t *testing.T) {
	for _, tc := range []struct {
		scope string
		want  bool
	}{
		{"", false},
		{"agent.enroll", true},
		{"openid agent.enroll profile", true},
		{"agent.enrollment", false},
		{"agent.enroll.admin", false},
		{"  agent.enroll  ", true},
	} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		if tc.scope != "" {
			c.Set("scope", tc.scope)
		}
		if got := tokenScopeAllows(c, enrollScope); got != tc.want {
			t.Errorf("tokenScopeAllows(%q) = %v, want %v", tc.scope, got, tc.want)
		}
	}
}
