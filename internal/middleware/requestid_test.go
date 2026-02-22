// Package middleware provides HTTP middleware for OpenIDX services
package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRequestID_GeneratesNewID(t *testing.T) {
	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Generates UUID when no header present", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		requestID := w.Header().Get(HeaderXRequestID)
		assert.NotEmpty(t, requestID)

		// Should be a valid UUID format (contains hyphens)
		assert.Contains(t, requestID, "-")

		// UUIDs are typically 36 characters
		assert.Equal(t, 36, len(requestID))
	})
}

func TestRequestID_UsesProvidedID(t *testing.T) {
	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Uses X-Request-ID from header if present", func(t *testing.T) {
		customID := "my-custom-request-id-12345"
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set(HeaderXRequestID, customID)
		router.ServeHTTP(w, req)

		requestID := w.Header().Get(HeaderXRequestID)
		assert.Equal(t, customID, requestID)
	})
}

func TestRequestID_ContextStorage(t *testing.T) {
	var capturedRequestID string

	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		capturedRequestID = GetRequestID(c)
		c.String(200, "OK")
	})

	t.Run("Stores request ID in Gin context", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.NotEmpty(t, capturedRequestID)
		assert.Equal(t, w.Header().Get(HeaderXRequestID), capturedRequestID)
	})
}

func TestRequestID_RequestContext(t *testing.T) {
	var capturedContextRequestID string

	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		// Access from request context
		capturedContextRequestID = GetRequestIDFromContext(c.Request.Context())
		c.String(200, "OK")
	})

	t.Run("Adds request ID to request context", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.NotEmpty(t, capturedContextRequestID)
		assert.Equal(t, w.Header().Get(HeaderXRequestID), capturedContextRequestID)
	})
}

func TestGetRequestID(t *testing.T) {
	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		id := GetRequestID(c)
		if id == "" {
			c.String(500, "no request id")
		} else {
			c.String(200, id)
		}
	})

	t.Run("Returns empty string when no request ID set", func(t *testing.T) {
		router2 := gin.New() // No middleware
		router2.GET("/test", func(c *gin.Context) {
			id := GetRequestID(c)
			c.String(200, id)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router2.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Empty(t, w.Body.String())
	})
}

func TestGetRequestIDFromContext(t *testing.T) {
	t.Run("Retrieves request ID from context", func(t *testing.T) {
		expectedID := "test-request-id"
		ctx := ContextWithRequestID(context.Background(), expectedID)

		actualID := GetRequestIDFromContext(ctx)
		assert.Equal(t, expectedID, actualID)
	})

	t.Run("Returns empty string when not in context", func(t *testing.T) {
		ctx := context.Background()
		id := GetRequestIDFromContext(ctx)
		assert.Empty(t, id)
	})
}

func TestContextWithRequestID(t *testing.T) {
	t.Run("Adds request ID to context", func(t *testing.T) {
		ctx := context.Background()
		requestID := "test-123"

		newCtx := ContextWithRequestID(ctx, requestID)

		// Original context should be unchanged
		id := GetRequestIDFromContext(ctx)
		assert.Empty(t, id)

		// New context should have the ID
		newID := GetRequestIDFromContext(newCtx)
		assert.Equal(t, requestID, newID)
	})
}

func TestRequestIDWithCustomGenerator(t *testing.T) {
	// Custom generator that uses a simple incrementing number pattern
	customGen := func() string {
		return "req-" + strings.Repeat("x", 10)
	}

	router := gin.New()
	router.Use(RequestIDWithCustomGenerator(customGen))
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Uses custom generator when no header", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		requestID := w.Header().Get(HeaderXRequestID)
		assert.True(t, strings.HasPrefix(requestID, "req-"))
		assert.Equal(t, 14, len(requestID)) // "req-" + 10 'x's
	})

	t.Run("Still uses provided header when present", func(t *testing.T) {
		customID := "my-custom-id"
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set(HeaderXRequestID, customID)
		router.ServeHTTP(w, req)

		requestID := w.Header().Get(HeaderXRequestID)
		assert.Equal(t, customID, requestID)
	})
}

func TestRequestID_MultipleRequests(t *testing.T) {
	router := gin.New()
	router.Use(RequestID())
	router.GET("/test", func(c *gin.Context) {
		c.String(200, "OK")
	})

	t.Run("Generates different IDs for different requests", func(t *testing.T) {
		var ids []string

		for i := 0; i < 10; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			router.ServeHTTP(w, req)

			id := w.Header().Get(HeaderXRequestID)
			ids = append(ids, id)
		}

		// All IDs should be unique
		uniqueIDs := make(map[string]bool)
		for _, id := range ids {
			uniqueIDs[id] = true
		}

		assert.Equal(t, 10, len(uniqueIDs), "All request IDs should be unique")
	})
}

func TestHeaderXRequestID(t *testing.T) {
	assert.Equal(t, "X-Request-ID", HeaderXRequestID)
}

func TestRequestIDKey(t *testing.T) {
	// Ensure the context key is unique and not a simple string that could collide
	key := string(RequestIDKey)
	assert.NotEmpty(t, key)
	assert.NotEqual(t, "request_id", key) // Should use custom type
}
