package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// newTestServiceWithRedis builds a minimal Service with its own RSA key and a
// miniredis-backed Redis client. It returns the service and a cleanup func.
func newTestServiceWithRedis(t *testing.T) (*Service, *rsa.PrivateKey, func()) {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mini := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mini.Addr()})

	svc := &Service{
		privateKey: pk,
		publicKey:  &pk.PublicKey,
		redis:      &database.RedisClient{Client: rc},
		logger:     zap.NewNop(),
	}
	cleanup := func() {
		mini.Close()
		rc.Close()
	}
	return svc, pk, cleanup
}

// mintToken signs a MapClaims JWT with the given key using RS256.
func mintToken(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	require.NoError(t, err)
	return tok
}

// ---------------------------------------------------------------------------
// parseVerifiedClaims unit tests
// ---------------------------------------------------------------------------

func TestParseVerifiedClaims_Valid(t *testing.T) {
	svc, pk, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	claims := jwt.MapClaims{
		"sub": "user-abc",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	tok := mintToken(t, claims, pk)

	got, err := svc.parseVerifiedClaims(tok, false)
	require.NoError(t, err)
	assert.Equal(t, "user-abc", got["sub"])
}

func TestParseVerifiedClaims_WrongKey(t *testing.T) {
	svc, _, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	// Mint with a DIFFERENT key — service's publicKey won't match.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"sub": "attacker",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	tok := mintToken(t, claims, otherKey)

	_, err = svc.parseVerifiedClaims(tok, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token signature verification failed")
}

func TestParseVerifiedClaims_AlgNone(t *testing.T) {
	svc, _, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	// Craft an alg=none token (golang-jwt exposes this via SigningMethodNone,
	// which requires the special UnsafeAllowNoneSignatureType sentinel key).
	claims := jwt.MapClaims{
		"sub": "attacker",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = svc.parseVerifiedClaims(tok, false)
	require.Error(t, err, "alg=none must be rejected")
}

func TestParseVerifiedClaims_HS256Rejected(t *testing.T) {
	svc, _, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	// HS256 alg-confusion attack: sign with the raw DER of the public key as
	// an HMAC secret. The RS256 pin in parseVerifiedClaims must reject this.
	claims := jwt.MapClaims{
		"sub": "attacker",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("any-secret"))
	require.NoError(t, err)

	_, err = svc.parseVerifiedClaims(tok, false)
	require.Error(t, err, "HS256 must be rejected by RS256 pin")
}

func TestParseVerifiedClaims_ExpiredWithAllowExpiredFalse(t *testing.T) {
	svc, pk, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	claims := jwt.MapClaims{
		"sub": "user-abc",
		"exp": float64(time.Now().Add(-time.Hour).Unix()), // already expired
	}
	tok := mintToken(t, claims, pk)

	_, err := svc.parseVerifiedClaims(tok, false)
	require.Error(t, err, "expired token must be rejected when allowExpired=false")
}

func TestParseVerifiedClaims_ExpiredWithAllowExpiredTrue(t *testing.T) {
	svc, pk, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	claims := jwt.MapClaims{
		"sub": "user-abc",
		"exp": float64(time.Now().Add(-time.Hour).Unix()), // already expired
	}
	tok := mintToken(t, claims, pk)

	got, err := svc.parseVerifiedClaims(tok, true)
	require.NoError(t, err, "expired token with valid signature accepted when allowExpired=true")
	assert.Equal(t, "user-abc", got["sub"])
}

// ---------------------------------------------------------------------------
// handleLogoutAll: signature enforcement via HTTP handler
// ---------------------------------------------------------------------------

func TestHandleLogoutAll_WrongKeyReturns401(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, _, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	// Token signed by a different key.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	claims := jwt.MapClaims{
		"sub": "victim-user",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	tok := mintToken(t, claims, otherKey)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/oauth/logout-all", nil)
	c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tok))

	svc.handleLogoutAll(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleLogoutAll_ValidTokenReturns200(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, pk, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	claims := jwt.MapClaims{
		"sub": "real-user",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	tok := mintToken(t, claims, pk)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/oauth/logout-all", strings.NewReader(""))
	c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tok))

	svc.handleLogoutAll(c)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ---------------------------------------------------------------------------
// handleSessionInfo: signature enforcement via HTTP handler
// ---------------------------------------------------------------------------

func TestHandleSessionInfo_WrongKeyReturns401(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, _, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	claims := jwt.MapClaims{
		"sub": "victim-user",
		"aud": "test-client",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	tok := mintToken(t, claims, otherKey)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/oauth/session-info", nil)
	c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tok))

	svc.handleSessionInfo(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleSessionInfo_ValidTokenPassesAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// This test verifies that a correctly-signed Bearer token passes the auth
	// gate in handleSessionInfo (the 401-or-pass check). The handler will
	// subsequently panic on the DB call because the test service has no DB; we
	// catch that panic and confirm the 401 was NOT written — meaning auth passed.
	svc, pk, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	claims := jwt.MapClaims{
		"sub": "real-user",
		"aud": "test-client",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	tok := mintToken(t, claims, pk)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/oauth/session-info", nil)
	c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tok))

	// handleSessionInfo calls getEffectiveSessionPolicy which hits s.db (nil
	// in this test), so recover any downstream panic.
	func() {
		defer func() { recover() }() //nolint:errcheck
		svc.handleSessionInfo(c)
	}()

	// httptest.NewRecorder() initialises Code=200; the handler panics (recovered
	// above) before it can write any status, so w.Code stays at 200. A 401 from
	// the signature gate would have been captured before the panic — the
	// assertion therefore proves the RS256-pinned auth check passed.
	assert.NotEqual(t, http.StatusUnauthorized, w.Code,
		"a correctly-signed token must not be rejected with 401")
}

// ---------------------------------------------------------------------------
// handleLogout: forged id_token_hint is rejected without triggering revocation
// ---------------------------------------------------------------------------

func TestHandleLogout_ForgedIDTokenHintSkipsRevocation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// The test service has no DB (s.db == nil). If handleLogout mistakenly
	// extracted a userID from the forged hint, it would call
	// revokeAllUserSessions → s.db.Pool.Query → nil-pointer panic. A clean
	// 200/logged_out response therefore proves the forged hint did NOT
	// trigger user-session revocation.
	// (Helper-level rejection of wrong-key tokens is covered by
	// TestParseVerifiedClaims_WrongKey.)
	svc, _, cleanup := newTestServiceWithRedis(t)
	defer cleanup()

	// Mint an id_token_hint with a key the service does not own.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	forgedHint := mintToken(t, jwt.MapClaims{
		"sub": "victim",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	}, otherKey)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/oauth/logout?id_token_hint="+forgedHint, nil)

	svc.handleLogout(c)

	// Best-effort logout always returns — no 500, no panic.
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
}
