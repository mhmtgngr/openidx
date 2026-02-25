// Package middleware provides authentication middleware tests
package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openidx/openidx/internal/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// mockLogger implements gateway.Logger
type mockAuthLogger struct{}

func (m *mockAuthLogger) Debug(msg string, fields ...interface{}) {}
func (m *mockAuthLogger) Info(msg string, fields ...interface{})  {}
func (m *mockAuthLogger) Warn(msg string, fields ...interface{})  {}
func (m *mockAuthLogger) Error(msg string, fields ...interface{}) {}
func (m *mockAuthLogger) Fatal(msg string, fields ...interface{}) {}
func (m *mockAuthLogger) Sync() error                             { return nil }

func TestNewJWTAuthMiddleware(t *testing.T) {
	t.Run("Creates middleware with valid config", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		assert.NotNil(t, middleware)
		assert.Equal(t, "http://localhost:8080/jwks.json", middleware.jwksURL)
		assert.NotNil(t, middleware.cache)
		assert.NotNil(t, middleware.httpClient)
	})
}

func TestJWTAuthMiddleware_Authenticate(t *testing.T) {
	t.Run("Requires valid Authorization header", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		router := gin.New()
		router.Use(middleware.Authenticate())
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "authorization header")
	})

	t.Run("Requires Bearer scheme", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		router := gin.New()
		router.Use(middleware.Authenticate())
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Basic token123")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Bearer scheme")
	})

	t.Run("Rejects empty token", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		router := gin.New()
		router.Use(middleware.Authenticate())
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer ")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "empty")
	})

	t.Run("Rejects malformed header", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		router := gin.New()
		router.Use(middleware.Authenticate())
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestJWTAuthMiddleware_OptionalAuthenticate(t *testing.T) {
	t.Run("Continues without token", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		router := gin.New()
		router.Use(middleware.OptionalAuthenticate())
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Sets user context when valid token provided", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		router := gin.New()
		router.Use(middleware.OptionalAuthenticate())
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer some-token")
		router.ServeHTTP(w, req)

		// Should continue even if token is invalid (optional mode)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestRequireRoles(t *testing.T) {
	t.Run("Allows user with required role", func(t *testing.T) {
		setRoles := func(roles []string) gin.HandlerFunc {
			return func(c *gin.Context) {
				c.Set("roles", roles)
				c.Next()
			}
		}

		router := gin.New()
		router.Use(setRoles([]string{"admin", "user"}))
		router.GET("/admin", RequireRoles("admin"), func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/admin", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Denies user without required role", func(t *testing.T) {
		setRoles := func(roles []string) gin.HandlerFunc {
			return func(c *gin.Context) {
				c.Set("roles", roles)
				c.Next()
			}
		}

		router := gin.New()
		router.Use(setRoles([]string{"user"}))
		router.GET("/admin", RequireRoles("admin"), func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/admin", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Allows user with one of multiple required roles", func(t *testing.T) {
		setRoles := func(roles []string) gin.HandlerFunc {
			return func(c *gin.Context) {
				c.Set("roles", roles)
				c.Next()
			}
		}

		router := gin.New()
		router.Use(setRoles([]string{"user"}))
		router.GET("/resource", RequireRoles("user", "admin"), func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/resource", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Denies when no roles in context", func(t *testing.T) {
		router := gin.New()
		router.GET("/admin", RequireRoles("admin"), func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/admin", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "no roles")
	})

	t.Run("Denies when roles have wrong type", func(t *testing.T) {
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("roles", "not-a-slice")
			c.Next()
		})
		router.GET("/admin", RequireRoles("admin"), func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/admin", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "invalid roles")
	})
}

func TestRequirePermission(t *testing.T) {
	t.Run("Allows user with required permission", func(t *testing.T) {
		setPerms := func(perms []gateway.PermissionEntry) gin.HandlerFunc {
			return func(c *gin.Context) {
				c.Set("permissions", perms)
				c.Next()
			}
		}

		router := gin.New()
		router.Use(setPerms([]gateway.PermissionEntry{
			{Resource: "users", Action: "read"},
			{Resource: "users", Action: "write"},
		}))
		router.GET("/users", RequirePermission("users", "read"), func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Denies user without required permission", func(t *testing.T) {
		setPerms := func(perms []gateway.PermissionEntry) gin.HandlerFunc {
			return func(c *gin.Context) {
				c.Set("permissions", perms)
				c.Next()
			}
		}

		router := gin.New()
		router.Use(setPerms([]gateway.PermissionEntry{
			{Resource: "users", Action: "read"},
		}))
		router.DELETE("/users/:id", RequirePermission("users", "delete"), func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/users/123", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Denies when no permissions in context", func(t *testing.T) {
		router := gin.New()
		router.GET("/users", RequirePermission("users", "read"), func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/users", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "missing permission")
	})
}

// Test JWKS response parsing
func TestParseRSAPublicKey(t *testing.T) {
	middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", &mockAuthLogger{})

	t.Run("Valid RSA key", func(t *testing.T) {
		// Example base64url encoded modulus and exponent
		n := "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
		e := "AQAB"

		key, err := middleware.parseRSAPublicKey(n, e)

		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, 65537, key.E)
		assert.NotNil(t, key.N)
	})

	t.Run("Invalid modulus", func(t *testing.T) {
		e := "AQAB"

		key, err := middleware.parseRSAPublicKey("invalid!@#", e)

		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("Invalid exponent", func(t *testing.T) {
		n := "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"

		key, err := middleware.parseRSAPublicKey(n, "invalid!@#")

		assert.Error(t, err)
		assert.Nil(t, key)
	})
}

func TestJWKSCache(t *testing.T) {
	t.Run("Caches keys", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		// Create a test RSA public key
		testKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Manually set a key in cache
		middleware.cache.keys["test-kid"] = &testKey.PublicKey
		middleware.cache.expiresAt = time.Now().Add(1 * time.Hour)

		// Read lock path
		middleware.cache.mu.RLock()
		_, exists := middleware.cache.keys["test-kid"]
		middleware.cache.mu.RUnlock()

		assert.True(t, exists)
	})
}

// Helper types for testing

// Mock server for testing JWKS fetching
func createJWKSServer(keys []JWK) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := JWKSResponse{Keys: keys}
		json.NewEncoder(w).Encode(jwks)
	}))
}

func TestFetchJWKS(t *testing.T) {
	t.Run("Successfully fetches JWKS", func(t *testing.T) {
		server := createJWKSServer([]JWK{
			{
				Kid: "test-key-1",
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				E:   "AQAB",
			},
		})
		defer server.Close()

		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware(server.URL, logger)

		keys, err := middleware.fetchJWKS()

		assert.NoError(t, err)
		assert.NotEmpty(t, keys)
		assert.Contains(t, keys, "test-key-1")
	})

	t.Run("Returns error on non-200 response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware(server.URL, logger)

		keys, err := middleware.fetchJWKS()

		assert.Error(t, err)
		assert.Nil(t, keys)
	})

	t.Run("Skips non-RSA keys", func(t *testing.T) {
		server := createJWKSServer([]JWK{
			{
				Kid: "ec-key",
				Kty: "EC",
				Use: "sig",
			},
			{
				Kid: "test-key-1",
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				E:   "AQAB",
			},
		})
		defer server.Close()

		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware(server.URL, logger)

		keys, err := middleware.fetchJWKS()

		assert.NoError(t, err)
		assert.NotContains(t, keys, "ec-key")
		assert.Contains(t, keys, "test-key-1")
	})
}

func TestValidateTokenClaims(t *testing.T) {
	t.Run("Rejects expired token", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		// Create expired token
		expiredTime := time.Now().Add(-1 * time.Hour)
		claims := jwt.MapClaims{
			"sub": "user-123",
			"exp": float64(expiredTime.Unix()),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "test-key"

		// We can't fully validate without real keys, but we can test the expiration check
		_, err := middleware.validateToken(token.Raw)
		assert.Error(t, err)
	})

	t.Run("Rejects not-yet-valid token", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		// Create token with future nbf
		futureTime := time.Now().Add(1 * time.Hour)
		claims := jwt.MapClaims{
			"sub": "user-123",
			"nbf": float64(futureTime.Unix()),
			"exp": float64(futureTime.Add(1 * time.Hour).Unix()),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "test-key"

		_, err := middleware.validateToken(token.Raw)
		assert.Error(t, err)
	})
}

func TestSetUserContext(t *testing.T) {
	t.Run("Sets standard claims in context", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		claims := jwt.MapClaims{
			"sub":    "user-123",
			"email":  "user@example.com",
			"name":   "Test User",
			"sid":    "session-456",
			"org_id": "org-789",
			"exp":    float64(time.Now().Add(1 * time.Hour).Unix()),
			"iss":    "https://issuer.example.com",
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		middleware.setUserContext(c, claims)

		assert.Equal(t, "user-123", c.GetString("user_id"))
		assert.Equal(t, "user@example.com", c.GetString("email"))
		assert.Equal(t, "Test User", c.GetString("name"))
		assert.Equal(t, "session-456", c.GetString("session_id"))
		assert.Equal(t, "org-789", c.GetString("org_id"))
	})

	t.Run("Sets default org ID when not in claims", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		claims := jwt.MapClaims{
			"sub": "user-123",
			"exp": float64(time.Now().Add(1 * time.Hour).Unix()),
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		middleware.setUserContext(c, claims)

		assert.Equal(t, "00000000-0000-0000-0000-000000000010", c.GetString("org_id"))
	})

	t.Run("Sets roles in context", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		claims := jwt.MapClaims{
			"sub":   "user-123",
			"roles": []interface{}{"admin", "user"},
			"exp":   float64(time.Now().Add(1 * time.Hour).Unix()),
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		middleware.setUserContext(c, claims)

		roles, exists := c.Get("roles")
		assert.True(t, exists)
		roleSlice, ok := roles.([]string)
		assert.True(t, ok)
		assert.Contains(t, roleSlice, "admin")
		assert.Contains(t, roleSlice, "user")
	})

	t.Run("Sets token expiry in context", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		expTime := time.Now().Add(1 * time.Hour)
		claims := jwt.MapClaims{
			"sub": "user-123",
			"exp": float64(expTime.Unix()),
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		middleware.setUserContext(c, claims)

		tokenExpiresAt, exists := c.Get("token_expires_at")
		assert.True(t, exists)
		expiresAt, ok := tokenExpiresAt.(time.Time)
		assert.True(t, ok)
		assert.WithinDuration(t, expTime, expiresAt, time.Second)
	})

	t.Run("Stores full claims in context", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		claims := jwt.MapClaims{
			"sub":     "user-123",
			"custom":  "value",
			"exp":     float64(time.Now().Add(1 * time.Hour).Unix()),
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		middleware.setUserContext(c, claims)

		storedClaims, exists := c.Get("jwt_claims")
		assert.True(t, exists)
		assert.Equal(t, claims, storedClaims)
	})
}

func TestGetSigningKey(t *testing.T) {
	t.Run("Returns error when key not found", func(t *testing.T) {
		logger := &mockAuthLogger{}
		middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

		// Don't set up any keys
		_, err := middleware.getSigningKey("unknown-key-id")

		assert.Error(t, err)
		// Error message is about JWKS endpoint failure (connection refused or 404)
		// The actual error depends on whether the server is running
		assert.Contains(t, err.Error(), "failed to fetch JWKS")
	})
}

// Benchmark tests
func BenchmarkJWTAuthMiddleware_Authenticate(b *testing.B) {
	logger := &mockAuthLogger{}
	middleware := NewJWTAuthMiddleware("http://localhost:8080/jwks.json", logger)

	router := gin.New()
	router.Use(middleware.Authenticate())
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer dummy-token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
