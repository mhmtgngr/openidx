package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func csrfProbe(t *testing.T, cfg CSRFConfig, method string, withCookie bool, origin, referer string) (reached bool, status int) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Any("/c", CSRFProtection(cfg, zap.NewNop()), func(c *gin.Context) {
		reached = true
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(method, "/c", nil)
	if withCookie {
		req.AddCookie(&http.Cookie{Name: "_openidx_proxy_session", Value: "sess"})
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return reached, w.Code
}

// TestCSRFProtection exercises the wired CSRF middleware (access-service, cookie
// proxy sessions): it must enforce Origin/Referer only for cookie-authenticated
// state-changing requests, and allow everything else through.
func TestCSRFProtection(t *testing.T) {
	on := CSRFConfig{Enabled: true, TrustedDomain: "example.com"}

	cases := []struct {
		name    string
		cfg     CSRFConfig
		method  string
		cookie  bool
		origin  string
		referer string
		wantOK  bool // true = allowed (handler reached, 200); false = 403 blocked
	}{
		{"disabled passes through", CSRFConfig{Enabled: false}, "POST", true, "https://evil.com", "", true},
		{"safe GET not checked", on, "GET", true, "https://evil.com", "", true},
		{"POST no session cookie (bearer client)", on, "POST", false, "https://evil.com", "", true},
		{"POST cookie + matching Origin", on, "POST", true, "https://app.example.com", "", true},
		{"POST cookie + cross-origin Origin", on, "POST", true, "https://evil.com", "", false},
		{"POST cookie + no Origin + matching Referer", on, "POST", true, "", "https://app.example.com/x", true},
		{"POST cookie + no Origin + cross Referer", on, "POST", true, "", "https://evil.com/x", false},
		{"POST cookie + no Origin/Referer", on, "POST", true, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached, status := csrfProbe(t, tc.cfg, tc.method, tc.cookie, tc.origin, tc.referer)
			if tc.wantOK && (!reached || status != http.StatusOK) {
				t.Errorf("%s: want allowed (200), got reached=%v status=%d", tc.name, reached, status)
			}
			if !tc.wantOK && (reached || status != http.StatusForbidden) {
				t.Errorf("%s: want blocked (403), got reached=%v status=%d", tc.name, reached, status)
			}
		})
	}
}
