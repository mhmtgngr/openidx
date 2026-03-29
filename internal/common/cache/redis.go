// Package cache provides a Redis-based caching layer for OpenIDX services
package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

var (
	// ErrCacheMiss is returned when a key is not found in cache
	ErrCacheMiss = errors.New("cache miss")

	// ErrRedisUnavailable is returned when Redis is not configured
	ErrRedisUnavailable = errors.New("redis unavailable")

	// ErrInvalidValue is returned when a value cannot be serialized
	ErrInvalidValue = errors.New("invalid cache value")
)

// Config holds configuration for the cache layer
type Config struct {
	// DefaultTTL is the default time-to-live for cache entries
	DefaultTTL time.Duration

	// KeyPrefix is a prefix added to all cache keys for namespacing
	KeyPrefix string

	// MaxRetries is the number of retries for failed operations
	MaxRetries int

	// EnableMetrics enables cache metrics collection
	EnableMetrics bool
}

// DefaultConfig returns sensible defaults for cache configuration
func DefaultConfig() Config {
	return Config{
		DefaultTTL:     5 * time.Minute,
		KeyPrefix:      "openidx:",
		MaxRetries:     2,
		EnableMetrics:  false,
	}
}

// Cache represents a Redis-based cache layer
type Cache struct {
	client   *redis.Client
	config   Config
	logger   *zap.Logger
	metrics  *metrics
}

// metrics holds cache operation metrics
type metrics struct {
	hits   int64
	misses int64
	sets   int64
	deletes int64
	errors int64
}

// New creates a new cache instance with the given Redis client
func New(client *redis.Client, logger *zap.Logger) *Cache {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Cache{
		client:  client,
		config:  DefaultConfig(),
		logger:  logger.With(zap.String("component", "cache")),
		metrics: &metrics{},
	}
}

// WithConfig sets a custom configuration for the cache
func (c *Cache) WithConfig(cfg Config) *Cache {
	if cfg.DefaultTTL > 0 {
		c.config.DefaultTTL = cfg.DefaultTTL
	}
	if cfg.KeyPrefix != "" {
		c.config.KeyPrefix = cfg.KeyPrefix
	}
	if cfg.MaxRetries > 0 {
		c.config.MaxRetries = cfg.MaxRetries
	}
	c.config.EnableMetrics = cfg.EnableMetrics
	return c
}

// Set stores a value in the cache with the default TTL
func (c *Cache) Set(ctx context.Context, key string, value interface{}) error {
	return c.SetWithTTL(ctx, key, value, c.config.DefaultTTL)
}

// SetWithTTL stores a value in the cache with a specific TTL
func (c *Cache) SetWithTTL(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if c.client == nil {
		return ErrRedisUnavailable
	}

	fullKey := c.fullKey(key)
	data, err := json.Marshal(value)
	if err != nil {
		c.metrics.errors++
		return fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	if err := c.retry(ctx, c.config.MaxRetries, func() error {
		return c.client.Set(ctx, fullKey, data, ttl).Err()
	}); err != nil {
		c.metrics.errors++
		return fmt.Errorf("failed to set cache key: %w", err)
	}

	c.metrics.sets++
	c.logger.Debug("cache set",
		zap.String("key", fullKey),
		zap.Duration("ttl", ttl),
	)
	return nil
}

// Get retrieves a value from the cache
func (c *Cache) Get(ctx context.Context, key string, dest interface{}) error {
	if c.client == nil {
		return ErrRedisUnavailable
	}

	fullKey := c.fullKey(key)
	data, err := c.client.Get(ctx, fullKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			c.metrics.misses++
			return ErrCacheMiss
		}
		c.metrics.errors++
		return fmt.Errorf("failed to get cache key: %w", err)
	}

	if err := json.Unmarshal(data, dest); err != nil {
		c.metrics.errors++
		return fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}

	c.metrics.hits++
	c.logger.Debug("cache hit", zap.String("key", fullKey))
	return nil
}

// Delete removes a key from the cache
func (c *Cache) Delete(ctx context.Context, key string) error {
	if c.client == nil {
		return ErrRedisUnavailable
	}

	fullKey := c.fullKey(key)
	if err := c.client.Del(ctx, fullKey).Err(); err != nil {
		c.metrics.errors++
		return fmt.Errorf("failed to delete cache key: %w", err)
	}

	c.metrics.deletes++
	c.logger.Debug("cache delete", zap.String("key", fullKey))
	return nil
}

// DeleteByPrefix removes all keys matching a prefix pattern
func (c *Cache) DeleteByPrefix(ctx context.Context, prefix string) (int, error) {
	if c.client == nil {
		return 0, ErrRedisUnavailable
	}

	fullPrefix := c.config.KeyPrefix + prefix
	iter := c.client.Scan(ctx, 0, fullPrefix+"*", 100).Iterator()
	var keys []string

	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}

	if err := iter.Err(); err != nil {
		c.metrics.errors++
		return 0, fmt.Errorf("failed to scan keys: %w", err)
	}

	if len(keys) > 0 {
		if err := c.client.Del(ctx, keys...).Err(); err != nil {
			c.metrics.errors++
			return 0, fmt.Errorf("failed to delete keys: %w", err)
		}
		c.metrics.deletes += int64(len(keys))
	}

	c.logger.Debug("cache delete by prefix",
		zap.String("prefix", fullPrefix),
		zap.Int("count", len(keys)),
	)
	return len(keys), nil
}

// Exists checks if a key exists in the cache
func (c *Cache) Exists(ctx context.Context, key string) (bool, error) {
	if c.client == nil {
		return false, ErrRedisUnavailable
	}

	fullKey := c.fullKey(key)
	count, err := c.client.Exists(ctx, fullKey).Result()
	if err != nil {
		c.metrics.errors++
		return false, fmt.Errorf("failed to check key existence: %w", err)
	}

	return count > 0, nil
}

// SetString stores a string value in the cache
func (c *Cache) SetString(ctx context.Context, key, value string) error {
	return c.SetStringWithTTL(ctx, key, value, c.config.DefaultTTL)
}

// SetStringWithTTL stores a string value with a specific TTL
func (c *Cache) SetStringWithTTL(ctx context.Context, key, value string, ttl time.Duration) error {
	if c.client == nil {
		return ErrRedisUnavailable
	}

	fullKey := c.fullKey(key)
	if err := c.retry(ctx, c.config.MaxRetries, func() error {
		return c.client.Set(ctx, fullKey, value, ttl).Err()
	}); err != nil {
		c.metrics.errors++
		return fmt.Errorf("failed to set string: %w", err)
	}

	c.metrics.sets++
	return nil
}

// GetString retrieves a string value from the cache
func (c *Cache) GetString(ctx context.Context, key string) (string, error) {
	if c.client == nil {
		return "", ErrRedisUnavailable
	}

	fullKey := c.fullKey(key)
	value, err := c.client.Get(ctx, fullKey).Result()
	if err != nil {
		if err == redis.Nil {
			c.metrics.misses++
			return "", ErrCacheMiss
		}
		c.metrics.errors++
		return "", fmt.Errorf("failed to get string: %w", err)
	}

	c.metrics.hits++
	return value, nil
}

// SetInt stores an integer value in the cache
func (c *Cache) SetInt(ctx context.Context, key string, value int64) error {
	return c.SetIntWithTTL(ctx, key, value, c.config.DefaultTTL)
}

// SetIntWithTTL stores an integer value with a specific TTL
func (c *Cache) SetIntWithTTL(ctx context.Context, key string, value int64, ttl time.Duration) error {
	if c.client == nil {
		return ErrRedisUnavailable
	}

	fullKey := c.fullKey(key)
	if err := c.retry(ctx, c.config.MaxRetries, func() error {
		return c.client.Set(ctx, fullKey, value, ttl).Err()
	}); err != nil {
		c.metrics.errors++
		return fmt.Errorf("failed to set int: %w", err)
	}

	c.metrics.sets++
	return nil
}

// GetInt retrieves an integer value from the cache
func (c *Cache) GetInt(ctx context.Context, key string) (int64, error) {
	if c.client == nil {
		return 0, ErrRedisUnavailable
	}

	fullKey := c.fullKey(key)
	value, err := c.client.Get(ctx, fullKey).Int64()
	if err != nil {
		if err == redis.Nil {
			c.metrics.misses++
			return 0, ErrCacheMiss
		}
		c.metrics.errors++
		return 0, fmt.Errorf("failed to get int: %w", err)
	}

	c.metrics.hits++
	return value, nil
}

// Increment atomically increments a numeric key by the given amount
func (c *Cache) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	if c.client == nil {
		return 0, ErrRedisUnavailable
	}

	fullKey := c.fullKey(key)
	value, err := c.client.IncrBy(ctx, fullKey, delta).Result()
	if err != nil {
		c.metrics.errors++
		return 0, fmt.Errorf("failed to increment: %w", err)
	}

	c.logger.Debug("cache increment",
		zap.String("key", fullKey),
		zap.Int64("delta", delta),
		zap.Int64("new_value", value),
	)
	return value, nil
}

// Decrement atomically decrements a numeric key by the given amount
func (c *Cache) Decrement(ctx context.Context, key string, delta int64) (int64, error) {
	if c.client == nil {
		return 0, ErrRedisUnavailable
	}

	fullKey := c.fullKey(key)
	value, err := c.client.DecrBy(ctx, fullKey, delta).Result()
	if err != nil {
		c.metrics.errors++
		return 0, fmt.Errorf("failed to decrement: %w", err)
	}

	c.logger.Debug("cache decrement",
		zap.String("key", fullKey),
		zap.Int64("delta", delta),
		zap.Int64("new_value", value),
	)
	return value, nil
}

// Expire sets a TTL on an existing key
func (c *Cache) Expire(ctx context.Context, key string, ttl time.Duration) error {
	if c.client == nil {
		return ErrRedisUnavailable
	}

	fullKey := c.fullKey(key)
	if err := c.client.Expire(ctx, fullKey, ttl).Err(); err != nil {
		c.metrics.errors++
		return fmt.Errorf("failed to set expiry: %w", err)
	}

	c.logger.Debug("cache expire",
		zap.String("key", fullKey),
		zap.Duration("ttl", ttl),
	)
	return nil
}

// TTL returns the remaining time to live for a key
func (c *Cache) TTL(ctx context.Context, key string) (time.Duration, error) {
	if c.client == nil {
		return 0, ErrRedisUnavailable
	}

	fullKey := c.fullKey(key)
	ttl, err := c.client.TTL(ctx, fullKey).Result()
	if err != nil {
		c.metrics.errors++
		return 0, fmt.Errorf("failed to get ttl: %w", err)
	}

	return ttl, nil
}

// GetSet sets a new value and returns the old value atomically
func (c *Cache) GetSet(ctx context.Context, key string, newValue interface{}) (string, error) {
	if c.client == nil {
		return "", ErrRedisUnavailable
	}

	fullKey := c.fullKey(key)
	oldValue, err := c.client.GetSet(ctx, fullKey, newValue).Result()
	if err != nil && err != redis.Nil {
		c.metrics.errors++
		return "", fmt.Errorf("failed to getset: %w", err)
	}

	c.metrics.sets++
	c.logger.Debug("cache getset", zap.String("key", fullKey))
	return oldValue, nil
}

// GetMultiple retrieves multiple keys at once
func (c *Cache) GetMultiple(ctx context.Context, keys []string) (map[string]string, error) {
	if c.client == nil {
		return nil, ErrRedisUnavailable
	}

	if len(keys) == 0 {
		return make(map[string]string), nil
	}

	fullKeys := make([]string, len(keys))
	for i, key := range keys {
		fullKeys[i] = c.fullKey(key)
	}

	values, err := c.client.MGet(ctx, fullKeys...).Result()
	if err != nil {
		c.metrics.errors++
		return nil, fmt.Errorf("failed to get multiple: %w", err)
	}

	result := make(map[string]string)
	for i, value := range values {
		if value != nil {
			if str, ok := value.(string); ok {
				result[keys[i]] = str
			}
		} else {
			c.metrics.misses++
		}
	}

	if len(result) > 0 {
		c.metrics.hits += int64(len(result))
	}
	return result, nil
}

// SetMultiple stores multiple key-value pairs at once
func (c *Cache) SetMultiple(ctx context.Context, items map[string]interface{}, ttl time.Duration) error {
	if c.client == nil {
		return ErrRedisUnavailable
	}

	if len(items) == 0 {
		return nil
	}

	pipe := c.client.Pipeline()
	for key, value := range items {
		fullKey := c.fullKey(key)
		data, err := json.Marshal(value)
		if err != nil {
			c.metrics.errors++
			return fmt.Errorf("%w: %v", ErrInvalidValue, err)
		}
		pipe.Set(ctx, fullKey, data, ttl)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		c.metrics.errors++
		return fmt.Errorf("failed to set multiple: %w", err)
	}

	c.metrics.sets += int64(len(items))
	return nil
}

// FlushAll removes all keys from the cache with the configured prefix
func (c *Cache) FlushAll(ctx context.Context) error {
	count, err := c.DeleteByPrefix(ctx, "")
	if err != nil {
		return err
	}
	c.logger.Debug("cache flushed", zap.Int("keys_deleted", count))
	return nil
}

// Metrics returns the current cache metrics
func (c *Cache) Metrics() map[string]int64 {
	return map[string]int64{
		"hits":    c.metrics.hits,
		"misses":  c.metrics.misses,
		"sets":    c.metrics.sets,
		"deletes": c.metrics.deletes,
		"errors":  c.metrics.errors,
	}
}

// ResetMetrics resets all metrics counters
func (c *Cache) ResetMetrics() {
	c.metrics = &metrics{}
}

// fullKey returns the full key with prefix
func (c *Cache) fullKey(key string) string {
	return c.config.KeyPrefix + key
}

// retry executes a function with retries
func (c *Cache) retry(ctx context.Context, maxRetries int, fn func() error) error {
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

// LockOptions holds options for distributed locks
type LockOptions struct {
	// TTL is the lock expiration time
	TTL time.Duration

	// RetryInterval is how often to retry acquiring the lock
	RetryInterval time.Duration

	// MaxRetries is the maximum number of retries before giving up
	MaxRetries int
}

// DefaultLockOptions returns sensible defaults for lock options
func DefaultLockOptions() LockOptions {
	return LockOptions{
		TTL:           10 * time.Second,
		RetryInterval: 100 * time.Millisecond,
		MaxRetries:    10,
	}
}

// AcquireLock attempts to acquire a distributed lock
func (c *Cache) AcquireLock(ctx context.Context, key string, opts LockOptions) (bool, error) {
	if c.client == nil {
		return false, ErrRedisUnavailable
	}

	fullKey := c.fullKey("lock:" + key)
	lockValue := fmt.Sprintf("%d", time.Now().UnixNano())

	for i := 0; i <= opts.MaxRetries; i++ {
		acquired, err := c.client.SetNX(ctx, fullKey, lockValue, opts.TTL).Result()
		if err != nil {
			c.metrics.errors++
			return false, fmt.Errorf("failed to acquire lock: %w", err)
		}

		if acquired {
			c.logger.Debug("lock acquired",
				zap.String("key", fullKey),
				zap.Duration("ttl", opts.TTL),
			)
			return true, nil
		}

		if i < opts.MaxRetries {
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(opts.RetryInterval):
			}
		}
	}

	return false, nil
}

// ReleaseLock releases a distributed lock
func (c *Cache) ReleaseLock(ctx context.Context, key string) error {
	if c.client == nil {
		return ErrRedisUnavailable
	}

	fullKey := c.fullKey("lock:" + key)
	if err := c.client.Del(ctx, fullKey).Err(); err != nil {
		c.metrics.errors++
		return fmt.Errorf("failed to release lock: %w", err)
	}

	c.logger.Debug("lock released", zap.String("key", fullKey))
	return nil
}

// TryAcquireLock attempts to acquire a lock without retries
func (c *Cache) TryAcquireLock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if c.client == nil {
		return false, ErrRedisUnavailable
	}

	fullKey := c.fullKey("lock:" + key)
	lockValue := fmt.Sprintf("%d", time.Now().UnixNano())

	acquired, err := c.client.SetNX(ctx, fullKey, lockValue, ttl).Result()
	if err != nil {
		c.metrics.errors++
		return false, fmt.Errorf("failed to try acquire lock: %w", err)
	}

	if acquired {
		c.logger.Debug("lock acquired (no retry)",
			zap.String("key", fullKey),
			zap.Duration("ttl", ttl),
		)
	}

	return acquired, nil
}
