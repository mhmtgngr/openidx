package provisioning

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/middleware"
)

// An administrator's ID token verifies against the key that signs their access
// token and carries the same roles. openIDXAuthMiddleware must refuse it; the
// same claims typed as an access token are the control.
func TestProvisioningRefusesAnIDToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://issuer.test"
	s := &Service{
		logger:          zap.NewNop(),
		config:          &config.Config{OAuthIssuer: issuer},
		jwksCachedKey:   &key.PublicKey,
		jwksCacheExpiry: time.Now().Add(time.Hour),
	}
	router := gin.New()
	router.GET("/scim/v2/Users", s.openIDXAuthMiddleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	sign := func(typ string) string {
		t.Helper()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "u1", "iss": issuer, "aud": "admin-console", "roles": []interface{}{"admin"},
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		if typ != "" {
			tok.Header["typ"] = typ
		}
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	call := func(bearer string) int {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	if code := call(sign("")); code != http.StatusUnauthorized {
		t.Fatalf("an admin's ID token answered %d, want 401", code)
	}
	if code := call(sign(middleware.AccessTokenType)); code != http.StatusOK {
		t.Fatalf("the same claims as an access token answered %d, want 200", code)
	}
}
