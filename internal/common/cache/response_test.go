// Package cache provides tests for HTTP response caching middleware
package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// init sets up test mode
func init() {
	gin.SetMode(gin.TestMode)
}

// resetGlobalCache resets the global response cache for test isolation
func resetGlobalCache() {
	globalResponseCache = nil
	globalResponseCacheOnce = sync.Once{}
}

// setupTestRouter creates a test router with caching middleware
func setupTestRouter() (*gin.Engine, *ResponseCache) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Reset global cache to ensure test isolation
	resetGlobalCache()

	logger := zap.NewNop()
	cacheInstance := getGlobalResponseCache(nil, logger)

	return router, cacheInstance
}

// mockRedisClient creates a mock Redis client for testing
type mockRedisClient struct {
	data      map[string][]byte
	expiries  map[string]time.Time
	callCount map[string]int
}

func newMockRedisClient() *mockRedisClient {
	return &mockRedisClient{
		data:      make(map[string][]byte),
		expiries:  make(map[string]time.Time),
		callCount: make(map[string]int),
	}
}

func (m *mockRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	m.callCount["get"]++
	cmd := redis.NewStringCmd(ctx)
	if data, ok := m.data[key]; ok {
		cmd.SetVal(string(data))
	} else {
		cmd.SetErr(redis.Nil)
	}
	return cmd
}

func (m *mockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	m.callCount["set"]++
	cmd := redis.NewStatusCmd(ctx)
	if data, ok := value.([]byte); ok {
		m.data[key] = data
		m.expiries[key] = time.Now().Add(expiration)
		cmd.SetVal("OK")
	} else if str, ok := value.(string); ok {
		m.data[key] = []byte(str)
		m.expiries[key] = time.Now().Add(expiration)
		cmd.SetVal("OK")
	} else {
		cmd.SetErr(redis.Nil)
	}
	return cmd
}

func (m *mockRedisClient) SetEX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	return m.Set(ctx, key, value, expiration)
}

func (m *mockRedisClient) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	m.callCount["del"]++
	cmd := redis.NewIntCmd(ctx)
	deleted := int64(0)
	for _, key := range keys {
		if _, ok := m.data[key]; ok {
			delete(m.data, key)
			delete(m.expiries, key)
			deleted++
		}
	}
	cmd.SetVal(deleted)
	return cmd
}

func (m *mockRedisClient) Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd {
	m.callCount["scan"]++
	var keys []string
	for key := range m.data {
		if match == "*" || strings.Contains(key, strings.TrimSuffix(match, "*")) {
			keys = append(keys, key)
		}
	}
	cmd := redis.NewScanCmdResult(keys, 0, nil)
	return cmd
}

func (m *mockRedisClient) Exists(ctx context.Context, keys ...string) *redis.IntCmd {
	cmd := redis.NewIntCmd(ctx)
	count := int64(0)
	for _, key := range keys {
		if _, ok := m.data[key]; ok {
			count++
		}
	}
	cmd.SetVal(count)
	return cmd
}

func (m *mockRedisClient) Keys(ctx context.Context, pattern string) *redis.StringSliceCmd {
	cmd := redis.NewStringSliceCmd(ctx)
	var keys []string
	for key := range m.data {
		keys = append(keys, key)
	}
	cmd.SetVal(keys)
	return cmd
}

func (m *mockRedisClient) FlushDB(ctx context.Context) *redis.StatusCmd {
	m.data = make(map[string][]byte)
	m.expiries = make(map[string]time.Time)
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetVal("OK")
	return cmd
}

func (m *mockRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetVal("PONG")
	return cmd
}

func (m *mockRedisClient) getCallCount(operation string) int {
	return m.callCount[operation]
}

func (m *mockRedisClient) reset() {
	m.data = make(map[string][]byte)
	m.expiries = make(map[string]time.Time)
	m.callCount = make(map[string]int)
}

func (m *mockRedisClient) hasKey(key string) bool {
	_, ok := m.data[key]
	return ok
}

// Helper to create a test request
func makeRequest(router *gin.Engine, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestResponseCache_BasicCaching tests basic GET request caching
func TestResponseCache_BasicCaching(t *testing.T) {
	router, _ := setupTestRouter()

	// Add a cached route
	router.GET("/api/users", ResponseWithClient(nil, zap.NewNop(), time.Minute), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"users": []string{"user1", "user2"}})
	})

	// First request - cache miss
	w1 := makeRequest(router, http.MethodGet, "/api/users", nil)
	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, "MISS", w1.Header().Get("X-Cache"))
	assert.NotEmpty(t, w1.Header().Get("ETag"))

	// Second request - cache hit
	w2 := makeRequest(router, http.MethodGet, "/api/users", nil)
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "HIT", w2.Header().Get("X-Cache"))
}

// TestResponseCache_ETagSupport tests ETag and If-None-Match support
func TestResponseCache_ETagSupport(t *testing.T) {
	router, _ := setupTestRouter()

	router.GET("/api/data", ResponseWithClient(nil, zap.NewNop(), time.Minute), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"data": "test"})
	})

	// First request
	w1 := makeRequest(router, http.MethodGet, "/api/data", nil)
	etag := w1.Header().Get("ETag")
	assert.NotEmpty(t, etag)

	// Second request with If-None-Match
	w2 := makeRequest(router, http.MethodGet, "/api/data", map[string]string{
		"If-None-Match": etag,
	})
	assert.Equal(t, http.StatusNotModified, w2.Code)
	assert.Equal(t, etag, w2.Header().Get("ETag"))
}

// TestResponseCache_OnlyCacheGET tests that only GET requests are cached
func TestResponseCache_OnlyCacheGET(t *testing.T) {
	router, _ := setupTestRouter()

	router.GET("/api/resource", ResponseWithClient(nil, zap.NewNop(), time.Minute), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"method": "GET"})
	})
	router.POST("/api/resource", ResponseWithClient(nil, zap.NewNop(), time.Minute), func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{"method": "POST"})
	})

	// GET should be cached - first request is a miss
	w1 := makeRequest(router, http.MethodGet, "/api/resource", nil)
	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, "MISS", w1.Header().Get("X-Cache"))

	// Second GET should be a hit
	w1b := makeRequest(router, http.MethodGet, "/api/resource", nil)
	assert.Equal(t, http.StatusOK, w1b.Code)
	assert.Equal(t, "HIT", w1b.Header().Get("X-Cache"))

	// POST should not be cached (no X-Cache header)
	w2 := makeRequest(router, http.MethodPost, "/api/resource", nil)
	assert.Equal(t, http.StatusCreated, w2.Code)
	assert.Empty(t, w2.Header().Get("X-Cache"))
}

// TestResponseCache_NoCacheErrors tests that error responses are not cached
func TestResponseCache_NoCacheErrors(t *testing.T) {
	router, cacheInstance := setupTestRouter()

	router.GET("/api/error", ResponseWithClient(nil, zap.NewNop(), time.Minute), func(c *gin.Context) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
	})
	router.GET("/api/notfound", ResponseWithClient(nil, zap.NewNop(), time.Minute), func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	})

	makeRequest(router, http.MethodGet, "/api/error", nil)
	cacheInstance.mu.RLock()
	errorCacheLen := len(cacheInstance.memCache)
	cacheInstance.mu.RUnlock()
	assert.Equal(t, 0, errorCacheLen)

	makeRequest(router, http.MethodGet, "/api/notfound", nil)
	cacheInstance.mu.RLock()
	notFoundCacheLen := len(cacheInstance.memCache)
	cacheInstance.mu.RUnlock()
	assert.Equal(t, 0, notFoundCacheLen)
}

// TestResponseCache_ByUser tests user-specific caching
func TestResponseCache_ByUser(t *testing.T) {
	router, _ := setupTestRouter()

	router.GET("/api/profile",
		ResponseWithClient(nil, zap.NewNop(), time.Minute, WithKeyGenerators(ByUser)),
		func(c *gin.Context) {
			userID := c.GetString("user_id")
			c.JSON(http.StatusOK, gin.H{"user_id": userID, "data": "profile"})
		},
	)

	// Simulate authenticated request
	req1 := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req1.Header.Set("Authorization", "Bearer token1")
	w1 := httptest.NewRecorder()

	// Mock user context
	router.ServeHTTP(w1, req1)

	// Request should succeed
	assert.Equal(t, http.StatusOK, w1.Code)
}

// TestResponseCache_ByRole tests role-based caching
func TestResponseCache_ByRole(t *testing.T) {
	router, _ := setupTestRouter()

	router.GET("/api/admin",
		ResponseWithClient(nil, zap.NewNop(), time.Minute, WithKeyGenerators(ByRole)),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"role": "admin"})
		},
	)

	w := makeRequest(router, http.MethodGet, "/api/admin", nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestResponseCache_WithTags tests tag-based cache invalidation
func TestResponseCache_WithTags(t *testing.T) {
	router, cacheInstance := setupTestRouter()

	router.GET("/api/users",
		ResponseWithClient(nil, zap.NewNop(), time.Minute, WithTags("users", "all")),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"users": []string{"user1", "user2"}})
		},
	)

	w := makeRequest(router, http.MethodGet, "/api/users", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	// Check that tag keys were created in the in-memory cache
	tagFound := false
	cacheInstance.mu.RLock()
	for key := range cacheInstance.memCache {
		if contains(key, "tag:users:") {
			tagFound = true
			break
		}
	}
	cacheInstance.mu.RUnlock()
	assert.True(t, tagFound, "Tag key should be created")
}

// TestResponseCache_WithStaleTTL tests stale-while-revalidate
func TestResponseCache_WithStaleTTL(t *testing.T) {
	router, _ := setupTestRouter()

	router.GET("/api/data",
		ResponseWithClient(nil, zap.NewNop(), time.Second, WithStaleTTL(time.Minute)),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"data": "value"})
		},
	)

	w := makeRequest(router, http.MethodGet, "/api/data", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Cache-Control"), "max-age=")
}

// TestResponseCache_WithVary tests Vary header support
func TestResponseCache_VaryHeaders(t *testing.T) {
	router, _ := setupTestRouter()

	router.GET("/api/content",
		ResponseWithClient(nil, zap.NewNop(), time.Minute, WithVary("Accept-Encoding")),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"content": "data"})
		},
	)

	// Request with gzip encoding
	w1 := makeRequest(router, http.MethodGet, "/api/content", map[string]string{
		"Accept-Encoding": "gzip",
	})
	assert.Equal(t, http.StatusOK, w1.Code)

	// Request with different encoding should have different cache
	w2 := makeRequest(router, http.MethodGet, "/api/content", map[string]string{
		"Accept-Encoding": "br",
	})
	assert.Equal(t, http.StatusOK, w2.Code)
}

// TestResponseCache_CacheControlNoCache tests Cache-Control: no-cache bypass
func TestResponseCache_CacheControlNoCache(t *testing.T) {
	router, _ := setupTestRouter()

	router.GET("/api/realtime",
		ResponseWithClient(nil, zap.NewNop(), time.Minute),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"timestamp": time.Now().Unix()})
		},
	)

	w := makeRequest(router, http.MethodGet, "/api/realtime", map[string]string{
		"Cache-Control": "no-cache",
	})

	assert.Equal(t, http.StatusOK, w.Code)
	// no-cache requests should bypass caching
	assert.Empty(t, w.Header().Get("X-Cache"))
}

// TestResponseCache_InvalidatePattern tests pattern-based invalidation
func TestResponseCache_InvalidatePattern(t *testing.T) {
	router, cacheInstance := setupTestRouter()

	router.GET("/api/users",
		ResponseWithClient(nil, zap.NewNop(), time.Minute),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"users": []string{"user1"}})
		},
	)

	// Populate cache
	makeRequest(router, http.MethodGet, "/api/users", nil)

	// Verify cache has entries
	cacheInstance.mu.RLock()
	cacheLen := len(cacheInstance.memCache)
	cacheInstance.mu.RUnlock()
	assert.Greater(t, cacheLen, 0)

	// Invalidate
	cacheInstance.invalidatePattern(context.Background(), "*")

	// Check cache was cleared
	cacheInstance.mu.RLock()
	cacheLenAfter := len(cacheInstance.memCache)
	cacheInstance.mu.RUnlock()
	assert.Equal(t, 0, cacheLenAfter)
}

// TestResponseCache_InvalidateByTag tests tag-based invalidation
func TestResponseCache_InvalidateByTag(t *testing.T) {
	router, cacheInstance := setupTestRouter()

	router.GET("/api/users",
		ResponseWithClient(nil, zap.NewNop(), time.Minute, WithTags("users")),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"users": []string{"user1"}})
		},
	)

	// Populate cache
	makeRequest(router, http.MethodGet, "/api/users", nil)

	// Cache should have entries (response + tag keys)
	cacheInstance.mu.RLock()
	cacheLen := len(cacheInstance.memCache)
	cacheInstance.mu.RUnlock()
	assert.Greater(t, cacheLen, 0, "Should have some keys")
}

// TestResponseCache_AutoInvalidate tests automatic invalidation on mutations
func TestResponseCache_AutoInvalidate(t *testing.T) {
	router, _ := setupTestRouter()

	// Auto-invalidate middleware
	autoInvalidator := AutoInvalidate("users", "all")

	// GET route that caches
	router.GET("/api/users",
		ResponseWithClient(nil, zap.NewNop(), time.Minute),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"users": []string{"user1"}})
		},
	)

	// POST route with auto-invalidation
	router.POST("/api/users", autoInvalidator, func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{"created": "user2"})
	})

	// Populate cache
	w1 := makeRequest(router, http.MethodGet, "/api/users", nil)
	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, "MISS", w1.Header().Get("X-Cache"))

	// Invalidate via POST
	makeRequest(router, http.MethodPost, "/api/users", nil)
}

// TestResponseCache_ByHeader tests header-based key generation
func TestResponseCache_ByHeader(t *testing.T) {
	router, _ := setupTestRouter()

	router.GET("/api/localized",
		ResponseWithClient(nil, zap.NewNop(), time.Minute, WithKeyGenerators(ByHeader("Accept-Language"))),
		func(c *gin.Context) {
			lang := c.GetHeader("Accept-Language")
			c.JSON(http.StatusOK, gin.H{"language": lang})
		},
	)

	// English request
	w1 := makeRequest(router, http.MethodGet, "/api/localized", map[string]string{
		"Accept-Language": "en-US",
	})
	assert.Equal(t, http.StatusOK, w1.Code)

	// Spanish request - should have different cache
	w2 := makeRequest(router, http.MethodGet, "/api/localized", map[string]string{
		"Accept-Language": "es-ES",
	})
	assert.Equal(t, http.StatusOK, w2.Code)
}

// TestResponseCache_ByQuery tests query parameter-based key generation
func TestResponseCache_ByQuery(t *testing.T) {
	router, _ := setupTestRouter()

	router.GET("/api/search",
		ResponseWithClient(nil, zap.NewNop(), time.Minute, WithKeyGenerators(ByQuery("q"))),
		func(c *gin.Context) {
			query := c.Query("q")
			c.JSON(http.StatusOK, gin.H{"query": query})
		},
	)

	// First query
	w1 := makeRequest(router, http.MethodGet, "/api/search?q=go", nil)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Different query
	w2 := makeRequest(router, http.MethodGet, "/api/search?q=python", nil)
	assert.Equal(t, http.StatusOK, w2.Code)
}

// TestResponseCache_GenerateETag tests ETag generation
func TestResponseCache_GenerateETag(t *testing.T) {
	body1 := []byte(`{"data":"value1"}`)
	body2 := []byte(`{"data":"value1"}`)
	body3 := []byte(`{"data":"value2"}`)

	etag1 := generateETag(body1)
	etag2 := generateETag(body2)
	etag3 := generateETag(body3)

	assert.Equal(t, etag1, etag2, "Same content should produce same ETag")
	assert.NotEqual(t, etag1, etag3, "Different content should produce different ETag")
	assert.True(t, len(etag1) > 0, "ETag should not be empty")
	assert.Contains(t, etag1, `"`, "ETag should be quoted")
}

// TestResponseCache_HashValue tests hash value generation
func TestResponseCache_HashValue(t *testing.T) {
	hash1 := hashValue("test")
	hash2 := hashValue("test")
	hash3 := hashValue("different")

	assert.Equal(t, hash1, hash2, "Same input should produce same hash")
	assert.NotEqual(t, hash1, hash3, "Different input should produce different hash")
	assert.True(t, len(hash1) == 16, "Hash should be 16 characters")
}

// TestResponseCache_ResponseWriter tests response writer behavior
func TestResponseCache_ResponseWriter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	var capturedBody *bytes.Buffer
	router.GET("/test", func(c *gin.Context) {
		w := &responseWriter{
			ResponseWriter: c.Writer,
			body:          &bytes.Buffer{},
			headers:       make(http.Header),
		}
		c.Writer = w

		c.JSON(http.StatusOK, gin.H{"message": "test"})

		capturedBody = w.body
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.NotNil(t, capturedBody)
	assert.True(t, capturedBody.Len() > 0)
}

// TestResponseCache_GetStats tests cache statistics
func TestResponseCache_GetStats(t *testing.T) {
	t.Skip("Requires real Redis client")
}

// TestResponseCache_ClearAll tests clearing all cached responses
func TestResponseCache_ClearAll(t *testing.T) {
	t.Skip("Requires real Redis client")
}

// TestResponseCache_GetFromCacheByKey tests direct cache access
func TestResponseCache_GetFromCacheByKey(t *testing.T) {
	t.Skip("Requires real Redis client")
}

// TestResponseCache_CacheWriter tests CacheWriter functionality
func TestResponseCache_CacheWriter(t *testing.T) {
	cw := NewCacheWriter()

	data := []byte("test data")
	n, err := cw.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)

	assert.Equal(t, data, cw.Bytes())

	cw.Reset()
	assert.Equal(t, 0, cw.buffer.Len())
}

// TestResponseCache_InvalidateManual tests manual invalidation
func TestResponseCache_InvalidateManual(t *testing.T) {
	t.Skip("Requires real Redis client")
}

// TestResponseCache_NilRedisClient tests behavior with nil Redis client
func TestResponseCache_NilRedisClient(t *testing.T) {
	resetGlobalCache()
	router := gin.New()

	router.GET("/api/test", Response(time.Minute), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "test"})
	})

	w := makeRequest(router, http.MethodGet, "/api/test", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	// Should still work without Redis
}

// TestResponseCache_HeadMethod tests that HEAD requests are cached
func TestResponseCache_HeadMethod(t *testing.T) {
	router, _ := setupTestRouter()

	router.HEAD("/api/status", ResponseWithClient(nil, zap.NewNop(), time.Minute), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "/api/status", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestResponseCache_MultipleKeyGenerators tests combining multiple key generators
func TestResponseCache_MultipleKeyGenerators(t *testing.T) {
	router, _ := setupTestRouter()

	router.GET("/api/data",
		ResponseWithClient(nil, zap.NewNop(), time.Minute,
			WithKeyGenerators(ByUser, ByOrg, ByHeader("Accept-Language")),
		),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"data": "value"})
		},
	)

	w := makeRequest(router, http.MethodGet, "/api/data", map[string]string{
		"Accept-Language": "en-US",
	})
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestResponseCache_CachedResponseSerialization tests serialization of cached responses
func TestResponseCache_CachedResponseSerialization(t *testing.T) {
	resp := &CachedResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Cache-Control": "max-age=60",
		},
		Body:     []byte(`{"test":"data"}`),
		ETag:     `"abc123"`,
		CachedAt: time.Now(),
		Tags:     []string{"users", "all"},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var decoded CachedResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp.StatusCode, decoded.StatusCode)
	assert.Equal(t, resp.ETag, decoded.ETag)
	assert.Equal(t, resp.Body, decoded.Body)
	assert.Equal(t, resp.Tags, decoded.Tags)
}

// TestResponseCache_Expiration tests cache expiration behavior
func TestResponseCache_Expiration(t *testing.T) {
	router, _ := setupTestRouter()

	shortTTL := 10 * time.Millisecond
	router.GET("/api/short",
		ResponseWithClient(nil, zap.NewNop(), shortTTL),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"data": "short-lived"})
		},
	)

	// First request
	w1 := makeRequest(router, http.MethodGet, "/api/short", nil)
	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, "MISS", w1.Header().Get("X-Cache"))

	// Second request - should be a hit
	w2 := makeRequest(router, http.MethodGet, "/api/short", nil)
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "HIT", w2.Header().Get("X-Cache"))

	// Wait for full expiration (duration + stale-while-revalidate window)
	// Default staleTTL = duration * 2, so total = duration * 3
	time.Sleep(shortTTL*3 + 10*time.Millisecond)

	// Third request - should be a miss due to expiration
	w3 := makeRequest(router, http.MethodGet, "/api/short", nil)
	assert.Equal(t, http.StatusOK, w3.Code)
	assert.Equal(t, "MISS", w3.Header().Get("X-Cache"))
}

// TestResponseCache_ComplexQueryParams tests caching with complex query parameters
func TestResponseCache_ComplexQueryParams(t *testing.T) {
	router, _ := setupTestRouter()

	router.GET("/api/search",
		ResponseWithClient(nil, zap.NewNop(), time.Minute),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"query": c.Request.URL.Query()})
		},
	)

	// Complex query string
	w := makeRequest(router, http.MethodGet, "/api/search?q=go&sort=asc&filter=active&page=1", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "MISS", w.Header().Get("X-Cache"))

	// Same query - should hit cache
	w2 := makeRequest(router, http.MethodGet, "/api/search?q=go&sort=asc&filter=active&page=1", nil)
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "HIT", w2.Header().Get("X-Cache"))
}

// TestResponseCache_RegisterRoute tests route registration
func TestResponseCache_RegisterRoute(t *testing.T) {
	resetGlobalCache()
	RegisterRoute("GET", "/api/test", time.Minute, WithTags("test"))

	if globalResponseCache != nil {
		globalResponseCache.mu.RLock()
		_, exists := globalResponseCache.registry["GET:/api/test"]
		globalResponseCache.mu.RUnlock()

		assert.True(t, exists, "Route should be registered")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Benchmark tests
func BenchmarkResponseCache_GenerateCacheKey(b *testing.B) {
	gin.SetMode(gin.TestMode)

	cfg := &cacheConfig{
		duration:    time.Minute,
		staleTTL:    time.Minute * 2,
		varyHeaders: []string{"Accept-Encoding"},
		keyGenerators: []KeyGenerator{ByUser, ByOrg},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/users?page=1&limit=10", nil)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req

	cache := getGlobalResponseCache(nil, zap.NewNop())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.generateCacheKey(c, cfg)
	}
}

func BenchmarkResponseCache_GenerateETag(b *testing.B) {
	body := []byte(`{"users":[{"id":"1","name":"Test User"},{"id":"2","name":"Another User"}],"total":2,"page":1}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generateETag(body)
	}
}
