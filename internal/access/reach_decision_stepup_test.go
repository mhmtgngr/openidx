package access

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/accessdecision"
)

func TestOnlyStepUp(t *testing.T) {
	if !onlyStepUp([]string{accessdecision.ReasonStepUp}) {
		t.Fatal("a fresh factor alone is a step-up")
	}
	if onlyStepUp([]string{accessdecision.ReasonStepUp, accessdecision.ReasonNotAssigned}) {
		t.Fatal("a second reason is not cured by a fresh factor")
	}
}

func TestStepUpReturnTarget(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, method, uri, fwdURI, fwdMethod, want string
		ok                                         bool
	}{
		{"proxy GET", http.MethodGet, "/app/page?x=1", "", "", "/app/page?x=1", true},
		{"proxy POST", http.MethodPost, "/app/form", "", "", "/app/form", false},
		{"forward-auth GET", http.MethodGet, "/access/.auth/decide", "/app/page", "GET", "/app/page", true},
		{"forward-auth POST", http.MethodGet, "/access/.auth/decide", "/app/form", "POST", "/app/form", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(tc.method, tc.uri, nil)
			if tc.fwdURI != "" {
				c.Request.Header.Set("X-Forwarded-Uri", tc.fwdURI)
				c.Request.Header.Set("X-Forwarded-Method", tc.fwdMethod)
			}
			got, ok := stepUpReturnTarget(c)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("got %q %v, want %q %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// A situation with a judged fresh factor is a different cache entry from one
// without: a decision taken on a fresh session must not answer for a stale one.
func TestSituationKeySeparatesFreshness(t *testing.T) {
	base := situation{known: true, country: "TR", risk: 10}
	fresh, stale := base, base
	fresh.mfaKnown, fresh.freshMFA = true, true
	stale.mfaKnown = true
	if base.key() == fresh.key() || fresh.key() == stale.key() {
		t.Fatalf("keys collide: %q %q %q", base.key(), fresh.key(), stale.key())
	}
}

func TestLoginSessionFreshnessUnknownWithoutSID(t *testing.T) {
	s := &Service{}
	if known, _ := s.loginSessionFreshness(nil, &ProxySession{}, "org"); known {
		t.Fatal("a proxy session that names no login session leaves the condition unjudged")
	}
}
