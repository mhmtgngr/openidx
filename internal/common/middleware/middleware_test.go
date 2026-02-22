package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestCORS(t *testing.T) {
	router := gin.New()
	router.Use(CORS())
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("GET request with CORS headers", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Methods"))
		assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Headers"))
	})

	t.Run("OPTIONS preflight request", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		router.ServeHTTP(w, req)

		assert.Equal(t, 204, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestRequestID(t *testing.T) {
	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		requestID, exists := c.Get("request_id")
		assert.True(t, exists)
		assert.NotEmpty(t, requestID)
		c.String(200, "OK")
	})

	t.Run("Generates request ID", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	})

	t.Run("Uses provided request ID", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Request-ID", "custom-request-id")
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "custom-request-id", w.Header().Get("X-Request-ID"))
	})
}

func TestRequireRoles(t *testing.T) {
	// Setup test endpoint with role requirement using a custom middleware that sets roles first
	setRoles := func(roles []string) gin.HandlerFunc {
		return func(c *gin.Context) {
			c.Set("roles", roles)
			c.Next()
		}
	}

	t.Run("User has required role", func(t *testing.T) {
		router := gin.New()
		router.Use(setRoles([]string{"admin", "user"}))
		router.GET("/admin", RequireRoles("admin"), func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/admin", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
	})

	t.Run("User missing required role", func(t *testing.T) {
		router := gin.New()
		router.Use(setRoles([]string{"user"}))
		router.GET("/admin", RequireRoles("admin"), func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/admin", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 403, w.Code)
	})

	t.Run("User has one of multiple required roles", func(t *testing.T) {
		router := gin.New()
		router.Use(setRoles([]string{"user"}))
		router.GET("/user-or-admin", RequireRoles("user", "admin"), func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/user-or-admin", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
	})

	t.Run("No roles in context", func(t *testing.T) {
		router := gin.New()
		router.GET("/admin", RequireRoles("admin"), func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/admin", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 403, w.Code)
	})
}

func TestRateLimit(t *testing.T) {
	t.Run("Allows requests within limit", func(t *testing.T) {
		router := gin.New()
		router.Use(RateLimit(5, 1*time.Second))
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		// Make 5 requests (within limit)
		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:1234"
			router.ServeHTTP(w, req)

			assert.Equal(t, 200, w.Code, "Request %d should succeed", i+1)
		}
	})

	t.Run("Blocks requests exceeding limit", func(t *testing.T) {
		router := gin.New()
		router.Use(RateLimit(3, 1*time.Second))
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		// Make 3 requests (at limit)
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:1234"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}

		// 4th request should be blocked
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		router.ServeHTTP(w, req)

		assert.Equal(t, 429, w.Code)
		assert.NotEmpty(t, w.Header().Get("Retry-After"))
	})

	t.Run("Different IPs have separate limits", func(t *testing.T) {
		router := gin.New()
		router.Use(RateLimit(2, 1*time.Second))
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		// IP 1 makes 2 requests
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "192.168.1.1:1234"
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}

		// IP 2 should still be able to make requests
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.2:1234"
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)
	})
}

func TestTimeout(t *testing.T) {
	t.Run("Request completes within timeout", func(t *testing.T) {
		router := gin.New()
		router.Use(Timeout(100 * time.Millisecond))
		router.GET("/test", func(c *gin.Context) {
			time.Sleep(10 * time.Millisecond)
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
	})

	t.Run("Request exceeds timeout", func(t *testing.T) {
		router := gin.New()
		router.Use(Timeout(10 * time.Millisecond))
		router.GET("/test", func(c *gin.Context) {
			select {
			case <-time.After(50 * time.Millisecond):
				c.String(200, "OK")
			case <-c.Request.Context().Done():
				return
			}
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		// Should timeout
		assert.Equal(t, 504, w.Code)
	})
}

func TestRecovery(t *testing.T) {
	t.Run("Recovers from panic", func(t *testing.T) {
		router := gin.New()
		router.Use(Recovery())
		router.GET("/test", func(c *gin.Context) {
			panic("test panic")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)

		// Should not crash the server
		assert.NotPanics(t, func() {
			router.ServeHTTP(w, req)
		})

		assert.Equal(t, 500, w.Code)
	})

	t.Run("Normal request not affected", func(t *testing.T) {
		router := gin.New()
		router.Use(Recovery())
		router.GET("/test", func(c *gin.Context) {
			c.String(200, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "OK", w.Body.String())
	})
}

func TestParseRSAPublicKey(t *testing.T) {
	t.Run("Valid RSA public key", func(t *testing.T) {
		// Example valid base64url encoded n and e values
		// These are simplified for testing - real values would be longer
		n := "xGOr-H7A1G7YPl6_HvU6pZsJPqaLkTKcFnEpKl7R6CQd5k9qzGJcEcQvN7JDQQ"
		e := "AQAB" // Standard RSA exponent (65537)

		key, err := parseRSAPublicKey(n, e)

		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.NotNil(t, key.N)
		assert.Equal(t, 65537, key.E)
	})

	t.Run("Invalid base64 n value", func(t *testing.T) {
		n := "invalid!!!base64"
		e := "AQAB"

		key, err := parseRSAPublicKey(n, e)

		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("Invalid base64 e value", func(t *testing.T) {
		n := "xGOr-H7A1G7YPl6_HvU6pZsJPqaLkTKcFnEpKl7R6CQd5k9qzGJcEcQvN7JDQQ"
		e := "invalid!!!"

		key, err := parseRSAPublicKey(n, e)

		assert.Error(t, err)
		assert.Nil(t, key)
	})
}

// Benchmark tests
func BenchmarkCORS(b *testing.B) {
	router := gin.New()
	router.Use(CORS())
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	req, _ := http.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkRequestID(b *testing.B) {
	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	req, _ := http.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkRateLimit(b *testing.B) {
	router := gin.New()
	router.Use(RateLimit(1000, 1*time.Second))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
