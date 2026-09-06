package access

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/config"
)

func ctxWith(t *testing.T, tlsState *tls.ConnectionState, header, value string) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest(http.MethodGet, "/access/.auth/callback", nil)
	req.TLS = tlsState
	if header != "" {
		req.Header.Set(header, value)
	}
	c.Request = req
	return c
}

func TestSessionCookieSecure(t *testing.T) {
	prod := &config.Config{Environment: "production"}
	staging := &config.Config{Environment: "staging"}
	dev := &config.Config{Environment: "development"}

	cases := []struct {
		name   string
		ctx    *gin.Context
		cfg    *config.Config
		secure bool
		why    string
	}{
		{
			name:   "TLS terminated in-process",
			ctx:    ctxWith(t, &tls.ConnectionState{}, "", ""),
			cfg:    dev,
			secure: true,
			why:    "the request arrived over TLS; the environment label is irrelevant",
		},
		{
			// The regression this function exists for: IsProduction() is false
			// here, and the old predicate shipped the ZTNA session cookie
			// without Secure over a real HTTPS deployment.
			name:   "TLS terminated at an ingress, environment is staging",
			ctx:    ctxWith(t, nil, "X-Forwarded-Proto", "https"),
			cfg:    staging,
			secure: true,
			why:    "X-Forwarded-Proto says the client leg was HTTPS",
		},
		{
			name:   "forwarded proto list, client hop first",
			ctx:    ctxWith(t, nil, "X-Forwarded-Proto", "https, http"),
			cfg:    staging,
			secure: true,
			why:    "the client's own hop is the first element",
		},
		{
			name:   "forwarded proto is uppercase",
			ctx:    ctxWith(t, nil, "X-Forwarded-Proto", "HTTPS"),
			cfg:    staging,
			secure: true,
			why:    "the header value is case-insensitive",
		},
		{
			name:   "plain HTTP but configured production",
			ctx:    ctxWith(t, nil, "", ""),
			cfg:    prod,
			secure: true,
			why:    "never weaker than the predicate this replaced",
		},
		{
			name:   "plain HTTP local development",
			ctx:    ctxWith(t, nil, "", ""),
			cfg:    dev,
			secure: false,
			why:    "a Secure cookie on http://localhost is one the browser never sends back",
		},
		{
			name:   "forwarded proto says http",
			ctx:    ctxWith(t, nil, "X-Forwarded-Proto", "http"),
			cfg:    dev,
			secure: false,
			why:    "the client leg was plain HTTP",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sessionCookieSecure(tc.ctx, tc.cfg); got != tc.secure {
				t.Fatalf("sessionCookieSecure = %v, want %v — %s", got, tc.secure, tc.why)
			}
		})
	}
}

// The helper is called from handlers that may run before a request is bound
// (and config is a pointer the caller owns); neither may panic.
func TestSessionCookieSecureHandlesNils(t *testing.T) {
	if sessionCookieSecure(nil, nil) {
		t.Fatal("no request and no config must not yield a Secure cookie")
	}
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if sessionCookieSecure(c, nil) {
		t.Fatal("a context with no bound request must not yield a Secure cookie")
	}
	if !sessionCookieSecure(c, &config.Config{Environment: "prod"}) {
		t.Fatal(`Environment "prod" is production and must yield a Secure cookie`)
	}
}
