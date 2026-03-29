// Package cache provides HTTP response caching middleware for OpenIDX services
package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// inMemoryCacheEntry holds a cached response with its expiry time
type inMemoryCacheEntry struct {
	data   []byte
	expiry time.Time
}

// ResponseCache handles caching of HTTP responses
type ResponseCache struct {
	redis    *redis.Client
	cache    *Cache
	logger   *zap.Logger
	mu       sync.RWMutex
	registry map[string]*cacheConfig
	memCache map[string]*inMemoryCacheEntry // in-memory fallback when redis is nil
}

// cacheConfig holds cache configuration for a specific route
type cacheConfig struct {
	duration      time.Duration
	keyGenerators []KeyGenerator
	tags          []string
	staleTTL      time.Duration
	varyHeaders   []string
}

// CachedResponse represents a stored HTTP response
type CachedResponse struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string]string   `json:"headers"`
	Body       []byte              `json:"body"`
	ETag       string              `json:"etag,omitempty"`
	CachedAt   time.Time           `json:"cached_at"`
	Tags       []string            `json:"tags,omitempty"`
}

// KeyGenerator generates a cache key component based on the request context
type KeyGenerator func(c *gin.Context) string

// Option configures the response cache middleware
type Option func(*cacheConfig)

// global response cache instance
var globalResponseCache *ResponseCache
var globalResponseCacheOnce sync.Once

// getGlobalResponseCache returns the global response cache instance
func getGlobalResponseCache(redisClient *redis.Client, logger *zap.Logger) *ResponseCache {
	globalResponseCacheOnce.Do(func() {
		if logger == nil {
			logger = zap.NewNop()
		}
		globalResponseCache = &ResponseCache{
			redis:    redisClient,
			cache:    New(redisClient, logger),
			logger:   logger.With(zap.String("component", "response_cache")),
			registry: make(map[string]*cacheConfig),
			memCache: make(map[string]*inMemoryCacheEntry),
		}
	})
	return globalResponseCache
}

// ByUser adds the user ID to the cache key
func ByUser(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(string); ok {
			return "user:" + uid
		}
	}
	return "user:anonymous"
}

// ByRole adds the user's roles to the cache key
func ByRole(c *gin.Context) string {
	if roles, exists := c.Get("roles"); exists {
		if roleList, ok := roles.([]string); ok {
			// Sort roles for consistent keys
			sorted := make([]string, len(roleList))
			copy(sorted, roleList)
			sort.Strings(sorted)
			return "roles:" + strings.Join(sorted, ",")
		}
	}
	return "roles:default"
}

// ByOrg adds the organization ID to the cache key
func ByOrg(c *gin.Context) string {
	if orgID, exists := c.Get("org_id"); exists {
		if oid, ok := orgID.(string); ok {
			return "org:" + oid
		}
	}
	return "org:default"
}

// ByHeader adds a specific header value to the cache key
func ByHeader(header string) KeyGenerator {
	return func(c *gin.Context) string {
		value := c.GetHeader(header)
		if value == "" {
			return "header:" + header + ":empty"
		}
		return "header:" + header + ":" + hashValue(value)
	}
}

// ByQuery adds a specific query parameter to the cache key
func ByQuery(param string) KeyGenerator {
	return func(c *gin.Context) string {
		value := c.Query(param)
		if value == "" {
			return "query:" + param + ":empty"
		}
		return "query:" + param + ":" + value
	}
}

// WithTags adds tags to the cached response for batch invalidation
func WithTags(tags ...string) Option {
	return func(cfg *cacheConfig) {
		cfg.tags = append(cfg.tags, tags...)
	}
}

// WithStaleTTL sets the stale-while-revalidate duration
func WithStaleTTL(staleDuration time.Duration) Option {
	return func(cfg *cacheConfig) {
		cfg.staleTTL = staleDuration
	}
}

// WithVary adds Vary header support for the cache key
func WithVary(headers ...string) Option {
	return func(cfg *cacheConfig) {
		cfg.varyHeaders = append(cfg.varyHeaders, headers...)
	}
}

// WithKeyGenerators adds key generators to the cache configuration
func WithKeyGenerators(generators ...KeyGenerator) Option {
	return func(cfg *cacheConfig) {
		cfg.keyGenerators = append(cfg.keyGenerators, generators...)
	}
}

// Response returns a middleware that caches HTTP GET responses
func Response(duration time.Duration, opts ...Option) gin.HandlerFunc {
	return func(c *gin.Context) {
		responseCache := getGlobalResponseCache(nil, nil)
		responseCache.handleRequest(c, duration, opts...)
	}
}

// ResponseWithClient returns a middleware that caches HTTP GET responses with a custom Redis client
func ResponseWithClient(redisClient *redis.Client, logger *zap.Logger, duration time.Duration, opts ...Option) gin.HandlerFunc {
	return func(c *gin.Context) {
		responseCache := getGlobalResponseCache(redisClient, logger)
		responseCache.handleRequest(c, duration, opts...)
	}
}

// handleRequest processes the request through the caching middleware
func (rc *ResponseCache) handleRequest(c *gin.Context, duration time.Duration, opts ...Option) {
	// Only cache GET and HEAD requests
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
		c.Next()
		return
	}

	// Skip if client has Cache-Control: no-cache or no-store
	if c.GetHeader("Cache-Control") == "no-cache" || c.GetHeader("Cache-Control") == "no-store" ||
		c.GetHeader("Pragma") == "no-cache" {
		c.Next()
		return
	}

	// Build cache configuration
	cfg := &cacheConfig{
		duration:    duration,
		staleTTL:    duration * 2, // Default stale-while-revalidate is 2x cache duration
		tags:        []string{},
		varyHeaders: []string{},
	}

	for _, opt := range opts {
		opt(cfg)
	}

	// Generate cache key
	cacheKey := rc.generateCacheKey(c, cfg)

	// Check for If-None-Match header (ETag support)
	ifNoneMatch := c.GetHeader("If-None-Match")

	// Try to get from cache
	cachedResp, err := rc.getFromCache(c.Request.Context(), cacheKey)
	if err == nil && cachedResp != nil {
		// Check if response is stale but still usable (stale-while-revalidate)
		isStale := time.Since(cachedResp.CachedAt) > cfg.duration
		withinStaleWindow := time.Since(cachedResp.CachedAt) <= (cfg.duration + cfg.staleTTL)

		// Handle ETag validation
		if ifNoneMatch != "" && cachedResp.ETag == ifNoneMatch {
			c.Status(http.StatusNotModified)
			c.Header("ETag", cachedResp.ETag)
			c.Header("Cache-Control", fmt.Sprintf("max-age=%d", int(cfg.duration.Seconds())))
			if isStale && withinStaleWindow {
				c.Header("X-Cache", "HIT_STALE")
			} else {
				c.Header("X-Cache", "HIT")
			}
			c.Abort()
			return
		}

		// Return cached response
		if isStale && withinStaleWindow {
			// Serve stale content in background, trigger revalidation
			rc.setHeaderFromCache(c, cachedResp)
			c.Header("X-Cache", "HIT_STALE")
			c.Header("Cache-Control", fmt.Sprintf("max-age=%d, stale-while-revalidate=%d",
				int(cfg.duration.Seconds()), int(cfg.staleTTL.Seconds())))

			// Trigger background refresh
			go rc.refreshCache(context.Background(), c, cacheKey, cfg)

			c.Abort()
			return
		} else if !isStale {
			// Fresh cache hit
			rc.setHeaderFromCache(c, cachedResp)
			c.Header("X-Cache", "HIT")
			c.Header("Cache-Control", fmt.Sprintf("max-age=%d", int(cfg.duration.Seconds())))
			c.Abort()
			return
		}
	}

	// Capture response - save original writer for header manipulation after c.Next()
	originalWriter := c.Writer
	w := &responseWriter{
		ResponseWriter: c.Writer,
		body:          &bytes.Buffer{},
		headers:       make(http.Header),
	}
	c.Writer = w

	// Set X-Cache header on original writer so it's visible in the response
	originalWriter.Header().Set("X-Cache", "MISS")

	c.Next()

	// Don't cache error responses or non-success status codes
	if c.Writer.Status() >= 400 {
		return
	}

	// Don't cache if explicitly prevented
	if c.GetHeader("Cache-Control") == "no-store" || c.GetHeader("Cache-Control") == "private" {
		return
	}

	// Store successful response in cache
	if c.Writer.Status() >= 200 && c.Writer.Status() < 300 {
		response := &CachedResponse{
			StatusCode: c.Writer.Status(),
			Headers:    w.headersClone(),
			Body:       w.body.Bytes(),
			CachedAt:   time.Now(),
			Tags:       cfg.tags,
		}

		// Generate ETag
		if len(response.Body) > 0 {
			response.ETag = generateETag(response.Body)
		}

		// Store in cache
		if err := rc.setToCache(c.Request.Context(), cacheKey, response, cfg.duration+cfg.staleTTL); err != nil {
			rc.logger.Debug("failed to cache response",
				zap.String("key", cacheKey),
				zap.Error(err),
			)
		} else {
			// Add tags for cache invalidation
			for _, tag := range cfg.tags {
				tagKey := "tag:" + tag + ":" + cacheKey
				if rc.redis != nil {
					rc.redis.SetEx(c.Request.Context(), tagKey, 1, cfg.duration+cfg.staleTTL)
				} else {
					rc.mu.Lock()
					rc.memCache[tagKey] = &inMemoryCacheEntry{
						data:   []byte("1"),
						expiry: time.Now().Add(cfg.duration + cfg.staleTTL),
					}
					rc.mu.Unlock()
				}
			}
		}

		// Add cache headers to the original writer so they appear in the response
		originalWriter.Header().Set("ETag", response.ETag)
		originalWriter.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(cfg.duration.Seconds())))
	}
}

// refreshCache refreshes a stale cache entry in the background
func (rc *ResponseCache) refreshCache(ctx context.Context, c *gin.Context, cacheKey string, cfg *cacheConfig) {
	// Create a new request context for the background refresh
	// We'll make a copy of the request and execute it
	// This is a simplified version - in production you'd want to use the full request

	// Store the refreshed response
	// The actual implementation would need access to the handler
	rc.logger.Debug("background cache refresh", zap.String("key", cacheKey))
}

// generateCacheKey generates a unique cache key for the request
func (rc *ResponseCache) generateCacheKey(c *gin.Context, cfg *cacheConfig) string {
	var parts []string

	// Add method
	parts = append(parts, c.Request.Method)

	// Add path
	parts = append(parts, c.Request.URL.Path)

	// Add query string for non-varying queries (all queries affect cache by default)
	// Exclude cache-busting query params
	queryStr := c.Request.URL.Query().Encode()
	if queryStr != "" {
		// Sort query params for consistent keys
		parts = append(parts, "query:"+hashValue(queryStr))
	}

	// Add vary headers
	for _, header := range cfg.varyHeaders {
		value := c.GetHeader(header)
		if value != "" {
			parts = append(parts, "vary:"+header+":"+hashValue(value))
		}
	}

	// Add custom key generators
	for _, gen := range cfg.keyGenerators {
		part := gen(c)
		if part != "" {
			parts = append(parts, part)
		}
	}

	// Hash the combined parts to get a consistent key
	key := strings.Join(parts, "|")
	return "response:" + hashValue(key)
}

// getFromCache retrieves a cached response
func (rc *ResponseCache) getFromCache(ctx context.Context, key string) (*CachedResponse, error) {
	if rc.redis == nil {
		// Use in-memory fallback
		rc.mu.RLock()
		entry, ok := rc.memCache[key]
		rc.mu.RUnlock()
		if !ok || time.Now().After(entry.expiry) {
			if ok {
				rc.mu.Lock()
				delete(rc.memCache, key)
				rc.mu.Unlock()
			}
			return nil, nil
		}
		var resp CachedResponse
		if err := json.Unmarshal(entry.data, &resp); err != nil {
			return nil, err
		}
		return &resp, nil
	}

	data, err := rc.redis.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var resp CachedResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// setToCache stores a response in the cache
func (rc *ResponseCache) setToCache(ctx context.Context, key string, resp *CachedResponse, ttl time.Duration) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	if rc.redis == nil {
		// Use in-memory fallback
		rc.mu.Lock()
		rc.memCache[key] = &inMemoryCacheEntry{
			data:   data,
			expiry: time.Now().Add(ttl),
		}
		rc.mu.Unlock()
		return nil
	}

	return rc.redis.SetEx(ctx, key, data, ttl).Err()
}

// setHeaderFromCache sets response headers from a cached response
func (rc *ResponseCache) setHeaderFromCache(c *gin.Context, resp *CachedResponse) {
	for key := range c.Writer.Header() {
		c.Writer.Header().Del(key)
	}
	for key, value := range resp.Headers {
		if key != "Date" { // Always set current Date
			c.Header(key, value)
		}
	}
	c.Header("Date", time.Now().Format(http.TimeFormat))
	c.Header("X-Cached-At", resp.CachedAt.Format(time.RFC3339))
	c.Status(resp.StatusCode)
}

// Invalidate removes cached responses matching a pattern or tag
func Invalidate(pattern string) func(c *gin.Context) {
	return func(c *gin.Context) {
		if globalResponseCache == nil {
			c.Next()
			return
		}
		globalResponseCache.invalidatePattern(c.Request.Context(), pattern)
		c.Next()
	}
}

// InvalidateByTag removes all cached responses with a specific tag
func InvalidateByTag(tag string) func(c *gin.Context) {
	return func(c *gin.Context) {
		if globalResponseCache == nil {
			c.Next()
			return
		}
		globalResponseCache.invalidateByTag(c.Request.Context(), tag)
		c.Next()
	}
}

// InvalidateByUser removes all cached responses for a specific user
func InvalidateByUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		if globalResponseCache == nil {
			c.Next()
			return
		}

		if userID, exists := c.Get("user_id"); exists {
			if uid, ok := userID.(string); ok {
				globalResponseCache.invalidatePattern(c.Request.Context(), "user:"+uid)
			}
		}
		c.Next()
	}
}

// AutoInvalidate invalidates cache entries automatically on mutations
func AutoInvalidate(patterns ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Only invalidate on successful mutations
		if c.Request.Method != http.MethodPost &&
			c.Request.Method != http.MethodPut &&
			c.Request.Method != http.MethodPatch &&
			c.Request.Method != http.MethodDelete {
			return
		}

		if c.Writer.Status() >= 200 && c.Writer.Status() < 300 {
			ctx := c.Request.Context()
			for _, pattern := range patterns {
				if globalResponseCache != nil {
					globalResponseCache.invalidatePattern(ctx, pattern)
				}
			}
		}
	}
}

// invalidatePattern removes all cache keys matching a pattern
func (rc *ResponseCache) invalidatePattern(ctx context.Context, pattern string) {
	if rc.redis == nil {
		// Use in-memory fallback
		rc.mu.Lock()
		for key := range rc.memCache {
			if strings.Contains(key, pattern) || pattern == "*" {
				delete(rc.memCache, key)
			}
		}
		rc.mu.Unlock()
		return
	}

	iter := rc.redis.Scan(ctx, 0, "response:*", 1000).Iterator()
	var keys []string

	for iter.Next(ctx) {
		key := iter.Val()
		// Simple pattern matching - in production use more sophisticated matching
		if strings.Contains(key, pattern) || pattern == "*" {
			keys = append(keys, key)
		}
		if len(keys) >= 100 {
			break
		}
	}

	if err := iter.Err(); err != nil {
		rc.logger.Error("failed to scan cache keys", zap.Error(err))
		return
	}

	if len(keys) > 0 {
		if err := rc.redis.Del(ctx, keys...).Err(); err != nil {
			rc.logger.Error("failed to delete cache keys",
				zap.Strings("keys", keys),
				zap.Error(err),
			)
		} else {
			rc.logger.Debug("invalidated cache keys",
				zap.Int("count", len(keys)),
				zap.String("pattern", pattern),
			)
		}
	}
}

// invalidateByTag removes all cache entries with a specific tag
func (rc *ResponseCache) invalidateByTag(ctx context.Context, tag string) {
	iter := rc.redis.Scan(ctx, 0, "tag:"+tag+":*", 1000).Iterator()
	var keys []string

	for iter.Next(ctx) {
		tagKey := iter.Val()
		// Extract the actual cache key from the tag key
		parts := strings.Split(tagKey, ":")
		if len(parts) >= 3 {
			// The actual cache key is the part after "tag:{tag}:"
			cacheKey := "response:" + strings.Join(parts[2:], ":")
			keys = append(keys, cacheKey)
			keys = append(keys, tagKey) // Also delete the tag key itself
		}
		if len(keys) >= 200 {
			break
		}
	}

	if err := iter.Err(); err != nil {
		rc.logger.Error("failed to scan tag keys", zap.Error(err))
		return
	}

	if len(keys) > 0 {
		if err := rc.redis.Del(ctx, keys...).Err(); err != nil {
			rc.logger.Error("failed to delete tagged cache keys",
				zap.Strings("keys", keys),
				zap.String("tag", tag),
				zap.Error(err),
			)
		} else {
			rc.logger.Debug("invalidated cache by tag",
				zap.Int("count", len(keys)/2),
				zap.String("tag", tag),
			)
		}
	}
}

// InvalidateManual manually invalidates cache entries by pattern
func InvalidateManual(redisClient *redis.Client, pattern string) error {
	if redisClient == nil {
		return fmt.Errorf("redis client is nil")
	}

	ctx := context.Background()
	iter := redisClient.Scan(ctx, 0, "response:*", 1000).Iterator()
	var keys []string

	for iter.Next(ctx) {
		key := iter.Val()
		if strings.Contains(key, pattern) || pattern == "*" {
			keys = append(keys, key)
		}
		if len(keys) >= 1000 {
			break
		}
	}

	if err := iter.Err(); err != nil {
		return err
	}

	if len(keys) > 0 {
		return redisClient.Del(ctx, keys...).Err()
	}

	return nil
}

// hashValue creates a SHA256 hash of a string for cache keys
func hashValue(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// generateETag creates an ETag for a response body
func generateETag(body []byte) string {
	h := sha256.New()
	h.Write(body)
	return `"` + hex.EncodeToString(h.Sum(nil))[:16] + `"`
}

// responseWriter wraps gin.ResponseWriter to capture response data
type responseWriter struct {
	gin.ResponseWriter
	body     *bytes.Buffer
	headers  http.Header
	written  bool
}

// Write captures the response body
func (w *responseWriter) Write(data []byte) (int, error) {
	if !w.written {
		w.written = true
	}
	w.body.Write(data)
	return w.ResponseWriter.Write(data)
}

// WriteHeader captures the status code
func (w *responseWriter) WriteHeader(statusCode int) {
	if !w.written {
		w.written = true
		w.ResponseWriter.WriteHeader(statusCode)
	}
}

// Header captures headers
func (w *responseWriter) Header() http.Header {
	if w.headers == nil {
		w.headers = make(http.Header)
	}
	// Mirror writes to the actual response header
	original := w.ResponseWriter.Header()
	for k, v := range original {
		w.headers[k] = v
	}
	return w.headers
}

func (w *responseWriter) headersClone() map[string]string {
	result := make(map[string]string)
	for k, v := range w.headers {
		if len(v) > 0 {
			result[k] = v[0]
		}
	}
	return result
}

// RegisterRoute registers cache configuration for a specific route path
func RegisterRoute(method, path string, duration time.Duration, opts ...Option) {
	if globalResponseCache == nil {
		globalResponseCache = getGlobalResponseCache(nil, nil)
	}

	globalResponseCache.mu.Lock()
	defer globalResponseCache.mu.Unlock()

	cfg := &cacheConfig{
		duration:    duration,
		staleTTL:    duration * 2,
		tags:        []string{},
		varyHeaders: []string{},
		keyGenerators: []KeyGenerator{},
	}

	for _, opt := range opts {
		opt(cfg)
	}

	globalResponseCache.registry[method+":"+path] = cfg
}

// GetStats returns cache statistics
func GetStats(redisClient *redis.Client) (map[string]interface{}, error) {
	if redisClient == nil {
		return nil, fmt.Errorf("redis client is nil")
	}

	ctx := context.Background()

	// Count response cache keys
	iter := redisClient.Scan(ctx, 0, "response:*", 1000).Iterator()
	count := 0
	for iter.Next(ctx) {
		count++
		if count >= 10000 {
			break
		}
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	// Count tag keys
	tagIter := redisClient.Scan(ctx, 0, "tag:*", 1000).Iterator()
	tagCount := 0
	for tagIter.Next(ctx) {
		tagCount++
		if tagCount >= 10000 {
			break
		}
	}

	return map[string]interface{}{
		"cached_responses": count,
		"tag_entries":      tagCount,
	}, nil
}

// ClearAll clears all cached responses
func ClearAll(redisClient *redis.Client) error {
	if redisClient == nil {
		return fmt.Errorf("redis client is nil")
	}

	ctx := context.Background()
	iter := redisClient.Scan(ctx, 0, "response:*", 10000).Iterator()
	var keys []string

	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}

	if err := iter.Err(); err != nil {
		return err
	}

	if len(keys) > 0 {
		return redisClient.Del(ctx, keys...).Err()
	}

	return nil
}

// MiddlewareKeyWithAuth wraps a route with user-specific caching
func MiddlewareKeyWithAuth() Option {
	return func(cfg *cacheConfig) {
		cfg.keyGenerators = append(cfg.keyGenerators, ByUser)
		cfg.tags = append(cfg.tags, "authenticated")
	}
}

// MiddlewareKeyWithOrg wraps a route with org-specific caching
func MiddlewareKeyWithOrg() Option {
	return func(cfg *cacheConfig) {
		cfg.keyGenerators = append(cfg.keyGenerators, ByOrg)
		cfg.tags = append(cfg.tags, "org-scoped")
	}
}

// CacheWriter is an io.Writer that can be used for streaming cached responses
type CacheWriter struct {
	buffer *bytes.Buffer
}

// NewCacheWriter creates a new cache writer
func NewCacheWriter() *CacheWriter {
	return &CacheWriter{
		buffer: &bytes.Buffer{},
	}
}

// Write implements io.Writer
func (cw *CacheWriter) Write(p []byte) (n int, err error) {
	return cw.buffer.Write(p)
}

// Bytes returns the buffered data
func (cw *CacheWriter) Bytes() []byte {
	return cw.buffer.Bytes()
}

// Reset clears the buffer
func (cw *CacheWriter) Reset() {
	cw.buffer.Reset()
}

// CopyReader reads from an io.Reader and caches the data
func (cw *CacheWriter) CopyReader(r io.Reader) (int64, error) {
	return io.Copy(cw.buffer, r)
}

// GetFromCacheByKey retrieves a cached response by exact key
func GetFromCacheByKey(redisClient *redis.Client, key string) (*CachedResponse, error) {
	if redisClient == nil {
		return nil, fmt.Errorf("redis client is nil")
	}

	ctx := context.Background()
	data, err := redisClient.Get(ctx, "response:"+key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var resp CachedResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// SetCacheByKey stores a response by exact key
func SetCacheByKey(redisClient *redis.Client, key string, resp *CachedResponse, ttl time.Duration) error {
	if redisClient == nil {
		return fmt.Errorf("redis client is nil")
	}

	ctx := context.Background()
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return redisClient.SetEx(ctx, "response:"+key, data, ttl).Err()
}
