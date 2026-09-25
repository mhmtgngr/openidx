package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// RFC 6749 §5.1: every token endpoint response that carries a token, and
// §5.2's error responses from the same endpoint, must say "Cache-Control:
// no-store" and "Pragma: no-cache". None did; the conformance suite's
// oidcc-refresh-token module is where it showed. These drive the MOUNTED
// routes (RegisterRoutes), because the headers are a property of the route and
// a handler-level test would pass with the route left bare.

// routedService mounts every oauth route on a fresh engine, with the tenant on
// the request context the way TenantResolver puts it there in the service.
// flowAuth is the interactive-flow middleware; nil mounts without it, as the
// development configuration does.
func routedService(t *testing.T, svc *Service, orgID string, flowAuth gin.HandlerFunc) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgID}))
		c.Next()
	})
	passthrough := func(c *gin.Context) { c.Next() }
	if flowAuth != nil {
		RegisterRoutes(r, svc, passthrough, flowAuth)
	} else {
		RegisterRoutes(r, svc, passthrough)
	}
	return r
}

func serve(r *gin.Engine, method, target, contentType, body string, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func assertNoStore(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (RFC 6749 §5.1); status %d body %s", got, w.Code, w.Body.String())
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache (RFC 6749 §5.1); status %d", got, w.Code)
	}
}

const formType = "application/x-www-form-urlencoded"

// Every grant's error answer, and the other endpoints that hand out a token or
// a token's contents. No database: each request is refused before one is read,
// which is the point -- the refusal has to carry the headers too.
func TestTokenBearingRoutesAreNoStoreOnEveryAnswer(t *testing.T) {
	svc := newLoginUITestService(t, "", ssoTestClient())
	r := routedService(t, svc, ssoTestOrg, nil)

	// Basic credentials AND a client_secret in the body: refused as two client
	// authentication methods before the code is looked up.
	twoMethods := []string{"Authorization", "Basic YzpzZWNyZXQ="}
	for _, tc := range []struct {
		name, method, path, contentType, body string
		header                                []string
	}{
		{"token: unknown grant_type", "POST", "/oauth/token", formType, "grant_type=password", nil},
		{"token: authorization_code, two client auth methods", "POST", "/oauth/token", formType,
			"grant_type=authorization_code&code=x&client_id=c&client_secret=s", twoMethods},
		{"token: refresh_token, unknown client", "POST", "/oauth/token", formType,
			"grant_type=refresh_token&refresh_token=x&client_id=ghost", nil},
		{"token: client_credentials, unknown client", "POST", "/oauth/token", formType,
			"grant_type=client_credentials&client_id=ghost&client_secret=x", nil},
		{"token: token exchange, no subject_token", "POST", "/oauth/token", formType,
			"grant_type=" + url.QueryEscape(grantTypeTokenExchange), nil},
		{"token: device_code, no device_code", "POST", "/oauth/token", formType,
			"grant_type=" + url.QueryEscape(grantTypeDeviceCode) + "&client_id=c", nil},
		{"device authorization: unknown client", "POST", "/oauth/device_authorization", formType, "client_id=ghost", nil},
		{"introspection: no client authentication", "POST", "/oauth/introspect", formType, "token=x", nil},
		{"userinfo GET: no bearer", "GET", "/oauth/userinfo", "", "", nil},
		{"userinfo POST: no bearer", "POST", "/oauth/userinfo", "", "", nil},
		{"step-up verify: no session", "POST", "/oauth/stepup-verify", "application/json", "{}", nil},
		{"social login callback: no code", "GET", "/oauth/social/callback", "", "", nil},
		// Registration answers carry client_secret and registration_access_token.
		{"registration: closed", "POST", "/oauth/register", "application/json", "{}", nil},
		{"registration read: no registration token", "GET", "/oauth/register/c", "", "", nil},
		{"registration update: no registration token", "PUT", "/oauth/register/c", "application/json", "{}", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := serve(r, tc.method, tc.path, tc.contentType, tc.body, tc.header...)
			if w.Code < 400 {
				t.Fatalf("expected a refusal to exercise the error path, got %d: %s", w.Code, w.Body.String())
			}
			assertNoStore(t, w)
		})
	}
}

// The success half, against a real database: a refresh grant and a
// client_credentials grant that actually mint a token, through the mounted
// /oauth/token route.
func TestTokenEndpointSuccessIsNoStore(t *testing.T) {
	f := newRefreshGrantFixture(t)
	r := routedService(t, f.svc, grantOrg, nil)

	decode := func(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
		t.Helper()
		var body map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("response is not JSON (%d): %s", w.Code, w.Body.String())
		}
		return body
	}

	t.Run("refresh_token", func(t *testing.T) {
		f.mintRefresh(t, "tok-nostore", "app", grantUser, "openid offline_access", "", "", time.Now().Add(time.Hour))
		w := serve(r, "POST", "/oauth/token", formType,
			creds("app", "s3cret", "grant_type", "refresh_token", "refresh_token", "tok-nostore").Encode())
		if w.Code != http.StatusOK {
			t.Fatalf("refresh grant: %d %s", w.Code, w.Body.String())
		}
		body := decode(t, w)
		if body["access_token"] == nil || body["refresh_token"] == nil {
			t.Fatalf("expected an access and a rotated refresh token, got %v", body)
		}
		assertNoStore(t, w)
	})

	t.Run("client_credentials", func(t *testing.T) {
		w := serve(r, "POST", "/oauth/token", formType,
			creds("app", "s3cret", "grant_type", "client_credentials").Encode())
		if w.Code != http.StatusOK {
			t.Fatalf("client_credentials grant: %d %s", w.Code, w.Body.String())
		}
		if decode(t, w)["access_token"] == nil {
			t.Fatal("no access_token in the response")
		}
		assertNoStore(t, w)
	})
}
