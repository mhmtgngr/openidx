package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type fakeAPIKeyValidator struct {
	info *APIKeyInfo
	err  error
}

func (f *fakeAPIKeyValidator) ValidateAPIKey(_ context.Context, _ string) (*APIKeyInfo, error) {
	return f.info, f.err
}

// runAPIKeyAuth drives AuthWithAPIKey with the given validator and an "oidx_"
// bearer key, returning whether the protected handler ran, the status, and the
// gin context it saw (for asserting attached identity).
func runAPIKeyAuth(t *testing.T, v APIKeyValidator) (reached bool, status int, seen *gin.Context) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/x", AuthWithAPIKey("http://127.0.0.1:0/jwks", v), func(c *gin.Context) {
		reached = true
		seen = c
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer oidx_testkey")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return reached, w.Code, seen
}

func TestAuthAPIKey_ValidUserKey_AttachesIdentity(t *testing.T) {
	v := &fakeAPIKeyValidator{info: &APIKeyInfo{KeyID: "k1", UserID: "u1", OrgID: "org-1", Scopes: []string{"read"}}}
	reached, status, c := runAPIKeyAuth(t, v)
	if !reached || status != http.StatusOK {
		t.Fatalf("valid key: reached=%v status=%d, want true/200", reached, status)
	}
	if got := c.GetString("user_id"); got != "u1" {
		t.Errorf("user_id = %q, want u1", got)
	}
	if got := c.GetString("org_id"); got != "org-1" {
		t.Errorf("org_id = %q, want org-1", got)
	}
	if got := c.GetString("api_key_id"); got != "k1" {
		t.Errorf("api_key_id = %q, want k1", got)
	}
	if got := c.GetString("auth_method"); got != "api_key" {
		t.Errorf("auth_method = %q, want api_key", got)
	}
}

func TestAuthAPIKey_InvalidKey_401(t *testing.T) {
	v := &fakeAPIKeyValidator{err: errors.New("revoked")}
	reached, status, _ := runAPIKeyAuth(t, v)
	if reached {
		t.Error("protected handler reached despite invalid API key (auth bypass)")
	}
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
}

func TestAuthAPIKey_ServiceAccount_GetsRoleAndDefaultOrg(t *testing.T) {
	v := &fakeAPIKeyValidator{info: &APIKeyInfo{KeyID: "k2", ServiceAccountID: "sa-1", OrgID: ""}}
	reached, status, c := runAPIKeyAuth(t, v)
	if !reached || status != http.StatusOK {
		t.Fatalf("sa key: reached=%v status=%d, want true/200", reached, status)
	}
	if got := c.GetString("service_account_id"); got != "sa-1" {
		t.Errorf("service_account_id = %q, want sa-1", got)
	}
	roles := c.GetStringSlice("roles")
	found := false
	for _, r := range roles {
		if r == "service_account" {
			found = true
		}
	}
	if !found {
		t.Errorf("roles = %v, want to contain service_account", roles)
	}
	// Empty OrgID falls back to the default org (API-key analog of the JWT path).
	if got := c.GetString("org_id"); got != "00000000-0000-0000-0000-000000000010" {
		t.Errorf("org_id = %q, want default org UUID", got)
	}
}
