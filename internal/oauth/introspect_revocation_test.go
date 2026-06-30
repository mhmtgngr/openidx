package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// TestHandleIntrospectHonorsRevocation pins the P1 fix: /oauth/introspect must
// report a revoked access token as active:false (RFC 7662 §2.2). A
// signature-valid token introspects active until it is revoked via the Redis
// blacklist (the same store /oauth/revoke + /oauth/logout write), after which it
// must read inactive.
func TestHandleIntrospectHonorsRevocation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mini := miniredis.RunT(t)
	defer mini.Close()
	rc := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	defer rc.Close()

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	s := &Service{
		privateKey: pk,
		publicKey:  &pk.PublicKey,
		redis:      &database.RedisClient{Client: rc},
		logger:     zap.NewNop(),
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":       "user-xyz",
		"client_id": "test-client",
		"scope":     "openid",
		"iat":       float64(now.Unix()),
		"exp":       float64(now.Add(time.Hour).Unix()),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(pk)
	require.NoError(t, err)

	introspectActive := func() interface{} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		form := url.Values{"token": {signed}}
		c.Request = httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
		c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		s.handleIntrospect(c)
		require.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		return resp["active"]
	}

	// Before revocation: the signature-valid token introspects as active.
	require.Equal(t, true, introspectActive(), "valid token should introspect active:true")

	// Revoke via the Redis blacklist (the path IsAccessTokenRevoked reads).
	require.NoError(t, s.MarkAccessTokenRevoked(context.Background(), signed, now.Add(time.Hour)))

	// After revocation: must report inactive.
	require.Equal(t, false, introspectActive(), "revoked token must introspect active:false")
}
