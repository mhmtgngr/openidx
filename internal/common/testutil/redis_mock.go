// Package testutil provides testing utilities for OpenIDX services
package testutil

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// MockRedis manages a miniredis instance for testing
type MockRedis struct {
	mini    *miniredis.Miniredis
	client  *redis.Client
	logger  *zap.Logger
	mu      sync.RWMutex
	running bool
}

// NewMockRedis creates a new mock Redis instance
func NewMockRedis(logger *zap.Logger) *MockRedis {
	return &MockRedis{
		logger: logger.With(zap.String("component", "mock_redis")),
	}
}

// Setup initializes the miniredis instance and creates a client
func (m *MockRedis) Setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}

	mini, err := miniredis.Run()
	if err != nil {
		return fmt.Errorf("failed to start miniredis: %w", err)
	}

	m.mini = mini

	// Create a Redis client configured to use the miniredis server
	m.client = redis.NewClient(&redis.Options{
		Addr: mini.Addr(),
	})

	m.running = true
	m.logger.Debug("Mock Redis started", zap.String("addr", mini.Addr()))
	return nil
}

// Shutdown closes the miniredis instance
func (m *MockRedis) Shutdown() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	if m.client != nil {
		_ = m.client.Close()
	}

	if m.mini != nil {
		m.mini.Close()
	}

	m.running = false
	m.logger.Debug("Mock Redis stopped")
	return nil
}

// Client returns the Redis client
func (m *MockRedis) Client() *redis.Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.client
}

// Mini returns the underlying miniredis instance for direct manipulation
func (m *MockRedis) Mini() *miniredis.Miniredis {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mini
}

// ClearAll removes all keys from the mock Redis
func (m *MockRedis) ClearAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.mini == nil {
		return fmt.Errorf("mock redis not running")
	}

	return m.mini.FlushAll()
}

// ClearData removes all keys matching a pattern
func (m *MockRedis) ClearData(pattern string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.mini == nil {
		return fmt.Errorf("mock redis not running")
	}

	ctx := context.Background()
	iter := m.client.Scan(ctx, 0, pattern, 100).Iterator()
	keys := []string{}

	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan keys: %w", err)
	}

	if len(keys) > 0 {
		return m.client.Del(ctx, keys...).Err()
	}

	return nil
}

// FastForward advances the mock Redis time by the given duration
// This is useful for testing TTL expiration
func (m *MockRedis) FastForward(d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.mini == nil {
		return fmt.Errorf("mock redis not running")
	}

	m.mini.FastForward(d)
	return nil
}

// IsRunning returns true if the mock Redis is running
func (m *MockRedis) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// SetString directly sets a string value in miniredis
func (m *MockRedis) SetString(key, value string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.mini == nil {
		return fmt.Errorf("mock redis not running")
	}

	return m.mini.Set(key, value)
}

// GetString directly gets a string value from miniredis
func (m *MockRedis) GetString(key string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.mini == nil {
		return "", false
	}

	return m.mini.Get(key)
}

// Keys returns all keys matching a pattern
func (m *MockRedis) Keys(pattern string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.mini == nil {
		return nil, fmt.Errorf("mock redis not running")
	}

	return m.mini.Keys(pattern), nil
}

// RedisClient returns a mock RedisClient compatible with database.RedisClient
type RedisClient struct {
	client *redis.Client
	mini   *miniredis.Miniredus
}

// NewRedisClient creates a mock RedisClient wrapper
func NewRedisClient(mock *MockRedis) *RedisClient {
	return &RedisClient{
		client: mock.Client(),
		mini:   mock.Mini(),
	}
}

// SetFastForward sets the fastforward function on the underlying miniredis
func (r *RedisClient) SetFastForward(fn func(duration time.Duration)) {
	// No-op for mock
}

// Client returns the underlying redis.Client
func (r *RedisClient) Client() *redis.Client {
	return r.client
}

// Close closes the client
func (r *RedisClient) Close() error {
	return r.client.Close()
}
