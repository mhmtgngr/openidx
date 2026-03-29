// Package cache provides comprehensive tests for the Redis caching layer
package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// mustCreateTestRedis creates a test Redis server using miniredis
func mustCreateTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr: s.Addr(),
	})
	return s, client
}

func TestCache_New(t *testing.T) {
	t.Run("creates cache with valid client", func(t *testing.T) {
		s, client := mustCreateTestRedis(t)
		defer s.Close()

		cache := New(client, zap.NewNop())
		require.NotNil(t, cache)
	})

	t.Run("creates cache with nil logger", func(t *testing.T) {
		s, client := mustCreateTestRedis(t)
		defer s.Close()

		cache := New(client, nil)
		require.NotNil(t, cache)
	})

	t.Run("creates cache with default config", func(t *testing.T) {
		s, client := mustCreateTestRedis(t)
		defer s.Close()

		cache := New(client, zap.NewNop())
		assert.Equal(t, DefaultConfig().DefaultTTL, cache.config.DefaultTTL)
		assert.Equal(t, DefaultConfig().KeyPrefix, cache.config.KeyPrefix)
	})
}

func TestCache_WithConfig(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())

	customConfig := Config{
		DefaultTTL:    10 * time.Minute,
		KeyPrefix:     "custom:",
		MaxRetries:    5,
		EnableMetrics: true,
	}

	cache = cache.WithConfig(customConfig)

	assert.Equal(t, customConfig.DefaultTTL, cache.config.DefaultTTL)
	assert.Equal(t, customConfig.KeyPrefix, cache.config.KeyPrefix)
	assert.Equal(t, customConfig.MaxRetries, cache.config.MaxRetries)
	assert.Equal(t, customConfig.EnableMetrics, cache.config.EnableMetrics)
}

func TestCache_SetWithTTL(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		value     interface{}
		ttl       time.Duration
		wantErr   error
		checkKey  bool
		checkTTL  bool
	}{
		{
			name:     "set string value",
			key:      "test:string",
			value:    "hello world",
			ttl:      5 * time.Minute,
			wantErr:  nil,
			checkKey: true,
			checkTTL: true,
		},
		{
			name:     "set int value",
			key:      "test:int",
			value:    42,
			ttl:      5 * time.Minute,
			wantErr:  nil,
			checkKey: true,
		},
		{
			name:     "set struct value",
			key:      "test:struct",
			value:    struct{ Name string }{Name: "test"},
			ttl:      5 * time.Minute,
			wantErr:  nil,
			checkKey: true,
		},
		{
			name:     "set map value",
			key:      "test:map",
			value:    map[string]interface{}{"key": "value"},
			ttl:      5 * time.Minute,
			wantErr:  nil,
			checkKey: true,
		},
		{
			name:     "set slice value",
			key:      "test:slice",
			value:    []string{"a", "b", "c"},
			ttl:      5 * time.Minute,
			wantErr:  nil,
			checkKey: true,
		},
		{
			name:     "set with zero TTL",
			key:      "test:zero_ttl",
			value:    "value",
			ttl:      0,
			wantErr:  nil,
			checkKey: true,
		},
		{
			name:     "set with negative TTL",
			key:      "test:negative_ttl",
			value:    "value",
			ttl:      -1 * time.Minute,
			wantErr:  nil,
			checkKey: true,
		},
		{
			name:     "set with second TTL",
			key:      "test:second_ttl",
			value:    "value",
			ttl:      1 * time.Second,
			wantErr:  nil,
			checkKey: true,
			checkTTL: true,
		},
		{
			name:     "set with nanosecond TTL",
			key:      "test:nano_ttl",
			value:    "value",
			ttl:      500 * time.Millisecond,
			wantErr:  nil,
			checkKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, client := mustCreateTestRedis(t)
			defer s.Close()

			cache := New(client, zap.NewNop())
			ctx := context.Background()

			err := cache.SetWithTTL(ctx, tt.key, tt.value, tt.ttl)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)

				if tt.checkKey {
					fullKey := cache.fullKey(tt.key)
					exists, err := client.Exists(ctx, fullKey).Result()
					require.NoError(t, err)
					assert.Greater(t, exists, int64(0), "key should exist")
				}

				if tt.checkTTL {
					ttl, err := cache.TTL(ctx, tt.key)
					require.NoError(t, err)
					assert.Greater(t, ttl, 0*time.Second, "TTL should be positive")
					assert.LessOrEqual(t, ttl, tt.ttl, "TTL should not exceed set value")
				}
			}
		})
	}
}

func TestCache_Set(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	err := cache.Set(ctx, "default_ttl_key", "value")
	require.NoError(t, err)

	ttl, err := cache.TTL(ctx, "default_ttl_key")
	require.NoError(t, err)
	assert.Greater(t, ttl, 4*time.Minute)
	assert.LessOrEqual(t, ttl, 5*time.Minute)
}

func TestCache_Get(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*Cache, context.Context) error
		key         string
		dest        interface{}
		wantErr     error
		checkResult func(*testing.T, interface{})
	}{
		{
			name: "get existing string",
			setup: func(c *Cache, ctx context.Context) error {
				return c.Set(ctx, "string_key", "string_value")
			},
			key:     "string_key",
			dest:    new(string),
			wantErr: nil,
			checkResult: func(t *testing.T, v interface{}) {
				assert.Equal(t, "string_value", *v.(*string))
			},
		},
		{
			name: "get existing int",
			setup: func(c *Cache, ctx context.Context) error {
				return c.Set(ctx, "int_key", 123)
			},
			key:     "int_key",
			dest:    new(int),
			wantErr: nil,
			checkResult: func(t *testing.T, v interface{}) {
				assert.Equal(t, 123, *v.(*int))
			},
		},
		{
			name: "get existing struct",
			setup: func(c *Cache, ctx context.Context) error {
				type TestStruct struct {
					Name  string
					Value int
				}
				return c.Set(ctx, "struct_key", TestStruct{Name: "test", Value: 42})
			},
			key:     "struct_key",
			dest:    &struct{ Name string; Value int }{},
			wantErr: nil,
			checkResult: func(t *testing.T, v interface{}) {
				s := v.(*struct{ Name string; Value int })
				assert.Equal(t, "test", s.Name)
				assert.Equal(t, 42, s.Value)
			},
		},
		{
			name:  "get non-existent key",
			setup: func(c *Cache, ctx context.Context) error { return nil },
			key:   "non_existent_key",
			dest:  new(string),
			wantErr: ErrCacheMiss,
		},
		{
			name: "get existing map",
			setup: func(c *Cache, ctx context.Context) error {
				return c.Set(ctx, "map_key", map[string]string{"a": "1", "b": "2"})
			},
			key:     "map_key",
			dest:    &map[string]string{},
			wantErr: nil,
			checkResult: func(t *testing.T, v interface{}) {
				m := v.(*map[string]string)
				assert.Equal(t, "1", (*m)["a"])
				assert.Equal(t, "2", (*m)["b"])
			},
		},
		{
			name: "get existing slice",
			setup: func(c *Cache, ctx context.Context) error {
				return c.Set(ctx, "slice_key", []string{"x", "y", "z"})
			},
			key:     "slice_key",
			dest:    &[]string{},
			wantErr: nil,
			checkResult: func(t *testing.T, v interface{}) {
				s := v.(*[]string)
				assert.Len(t, *s, 3)
				assert.Equal(t, "x", (*s)[0])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, client := mustCreateTestRedis(t)
			defer s.Close()

			cache := New(client, zap.NewNop())
			ctx := context.Background()

			require.NoError(t, tt.setup(cache, ctx))

			err := cache.Get(ctx, tt.key, tt.dest)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, tt.dest)
				}
			}
		})
	}
}

func TestCache_Get_InvalidDestType(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	// Set a string value
	err := cache.Set(ctx, "key", "string_value")
	require.NoError(t, err)

	// Try to get into an incompatible type
	err = cache.Get(ctx, "key", new(int))
	assert.Error(t, err)
}

func TestCache_Delete(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*Cache, context.Context) string
		wantErr error
		verify  func(*testing.T, *Cache, context.Context, string)
	}{
		{
			name: "delete existing key",
			setup: func(c *Cache, ctx context.Context) string {
				key := "delete_me"
				c.Set(ctx, key, "value")
				return key
			},
			wantErr: nil,
			verify: func(t *testing.T, c *Cache, ctx context.Context, key string) {
				exists, _ := c.Exists(ctx, key)
				assert.False(t, exists)
			},
		},
		{
			name: "delete non-existent key",
			setup: func(c *Cache, ctx context.Context) string {
				return "does_not_exist"
			},
			wantErr: nil, // Redis Del doesn't error for non-existent keys
		},
		{
			name: "delete empty key",
			setup: func(c *Cache, ctx context.Context) string {
				return ""
			},
			wantErr: nil,
		},
		{
			name: "delete with special characters in key",
			setup: func(c *Cache, ctx context.Context) string {
				key := "key:with:colons:and:slashes/"
				c.Set(ctx, key, "value")
				return key
			},
			wantErr: nil,
			verify: func(t *testing.T, c *Cache, ctx context.Context, key string) {
				exists, _ := c.Exists(ctx, key)
				assert.False(t, exists)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, client := mustCreateTestRedis(t)
			defer s.Close()

			cache := New(client, zap.NewNop())
			ctx := context.Background()

			key := tt.setup(cache, ctx)
			err := cache.Delete(ctx, key)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				if tt.verify != nil {
					tt.verify(t, cache, ctx, key)
				}
			}
		})
	}
}

func TestCache_DeleteByPrefix(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(*Cache, context.Context) string
		expectedCount int
		wantErr       error
	}{
		{
			name: "delete single key by prefix",
			setup: func(c *Cache, ctx context.Context) string {
				c.Set(ctx, "prefix:key1", "value1")
				return "prefix:"
			},
			expectedCount: 1,
			wantErr:       nil,
		},
		{
			name: "delete multiple keys by prefix",
			setup: func(c *Cache, ctx context.Context) string {
				c.Set(ctx, "user:1", "value1")
				c.Set(ctx, "user:2", "value2")
				c.Set(ctx, "user:3", "value3")
				c.Set(ctx, "other:key", "keep")
				return "user:"
			},
			expectedCount: 3,
			wantErr:       nil,
		},
		{
			name: "delete with empty prefix (all keys)",
			setup: func(c *Cache, ctx context.Context) string {
				c.Set(ctx, "key1", "value1")
				c.Set(ctx, "key2", "value2")
				return ""
			},
			expectedCount: 2,
			wantErr:       nil,
		},
		{
			name: "delete with non-existent prefix",
			setup: func(c *Cache, ctx context.Context) string {
				c.Set(ctx, "key1", "value1")
				return "nonexistent:"
			},
			expectedCount: 0,
			wantErr:       nil,
		},
		{
			name: "delete with colon in middle",
			setup: func(c *Cache, ctx context.Context) string {
				c.Set(ctx, "a:b:c", "value1")
				c.Set(ctx, "a:b:d", "value2")
				c.Set(ctx, "a:x:y", "value3")
				return "a:b:"
			},
			expectedCount: 2,
			wantErr:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, client := mustCreateTestRedis(t)
			defer s.Close()

			cache := New(client, zap.NewNop())
			ctx := context.Background()

			prefix := tt.setup(cache, ctx)

			count, err := cache.DeleteByPrefix(ctx, prefix)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCount, count)
			}
		})
	}
}

func TestCache_Exists(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*Cache, context.Context, *miniredis.Miniredis) string
		wantBool bool
	}{
		{
			name: "existing key",
			setup: func(c *Cache, ctx context.Context, s *miniredis.Miniredis) string {
				key := "existing_key"
				c.Set(ctx, key, "value")
				return key
			},
			wantBool: true,
		},
		{
			name: "non-existing key",
			setup: func(c *Cache, ctx context.Context, s *miniredis.Miniredis) string {
				return "non_existing_key"
			},
			wantBool: false,
		},
		{
			name: "empty key",
			setup: func(c *Cache, ctx context.Context, s *miniredis.Miniredis) string {
				c.Set(ctx, "", "value")
				return ""
			},
			wantBool: true,
		},
		{
			name: "expired key",
			setup: func(c *Cache, ctx context.Context, s *miniredis.Miniredis) string {
				key := "expired_key"
				c.SetWithTTL(ctx, key, "value", 1*time.Second)
				s.FastForward(2 * time.Second)
				return key
			},
			wantBool: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, client := mustCreateTestRedis(t)
			defer s.Close()

			cache := New(client, zap.NewNop())
			ctx := context.Background()

			key := tt.setup(cache, ctx, s)

			exists, err := cache.Exists(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, tt.wantBool, exists)
		})
	}
}

func TestCache_TTL(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(*Cache, context.Context) string
		checkTTL  func(*testing.T, time.Duration)
		wantErr   error
	}{
		{
			name: "TTL of existing key",
			setup: func(c *Cache, ctx context.Context) string {
				key := "ttl_key"
				c.SetWithTTL(ctx, key, "value", 5*time.Minute)
				return key
			},
			checkTTL: func(t *testing.T, ttl time.Duration) {
				assert.Greater(t, ttl, 4*time.Minute)
				assert.LessOrEqual(t, ttl, 5*time.Minute)
			},
			wantErr: nil,
		},
		{
			name: "TTL of non-existing key",
			setup: func(c *Cache, ctx context.Context) string {
				return "non_existing"
			},
			checkTTL: func(t *testing.T, ttl time.Duration) {
				assert.Equal(t, time.Duration(-2), ttl) // Redis returns -2 for non-existent keys
			},
			wantErr: nil,
		},
		{
			name: "TTL of key without expiry",
			setup: func(c *Cache, ctx context.Context) string {
				key := "no_expiry_key"
				c.SetStringWithTTL(ctx, key, "value", 0)
				return key
			},
			checkTTL: func(t *testing.T, ttl time.Duration) {
				assert.Equal(t, time.Duration(-1), ttl) // Redis returns -1 for keys without expiry
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, client := mustCreateTestRedis(t)
			defer s.Close()

			cache := New(client, zap.NewNop())
			ctx := context.Background()

			key := tt.setup(cache, ctx)

			ttl, err := cache.TTL(ctx, key)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
				if tt.checkTTL != nil {
					tt.checkTTL(t, ttl)
				}
			}
		})
	}
}

func TestCache_Expiration(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	key := "expire_key"
	cache.SetWithTTL(ctx, key, "value", 1*time.Second)

	// Key should exist
	exists, err := cache.Exists(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)

	// Fast forward time
	s.FastForward(2 * time.Second)

	// Key should be expired
	exists, err = cache.Exists(ctx, key)
	require.NoError(t, err)
	assert.False(t, exists)

	// Get should return cache miss
	var result string
	err = cache.Get(ctx, key, &result)
	assert.ErrorIs(t, err, ErrCacheMiss)
}

func TestCache_Expire(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	key := "expire_update_key"
	cache.SetWithTTL(ctx, key, "value", 1*time.Second)

	// Update TTL to 10 minutes
	err := cache.Expire(ctx, key, 10*time.Minute)
	require.NoError(t, err)

	ttl, err := cache.TTL(ctx, key)
	require.NoError(t, err)
	assert.Greater(t, ttl, 9*time.Minute)
}

func TestCache_SetString(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	tests := []struct {
		name    string
		key     string
		value   string
		wantErr error
	}{
		{
			name:    "set simple string",
			key:     "string_key",
			value:   "hello world",
			wantErr: nil,
		},
		{
			name:    "set empty string",
			key:     "empty_string",
			value:   "",
			wantErr: nil,
		},
		{
			name:    "set string with special characters",
			key:     "special_key",
			value:   "hello\nworld\t\r\n",
			wantErr: nil,
		},
		{
			name:    "set unicode string",
			key:     "unicode_key",
			value:   "Hello 世界 🌍",
			wantErr: nil,
		},
		{
			name:    "set very long string",
			key:     "long_key",
			value:   string(make([]byte, 10000)),
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cache.SetString(ctx, tt.key, tt.value)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)

				retrieved, err := cache.GetString(ctx, tt.key)
				require.NoError(t, err)
				assert.Equal(t, tt.value, retrieved)
			}
		})
	}
}

func TestCache_GetString(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	// Set a string value
	err := cache.SetString(ctx, "get_string_key", "test_value")
	require.NoError(t, err)

	// Get it back
	value, err := cache.GetString(ctx, "get_string_key")
	require.NoError(t, err)
	assert.Equal(t, "test_value", value)

	// Try to get non-existent key
	_, err = cache.GetString(ctx, "non_existent")
	assert.ErrorIs(t, err, ErrCacheMiss)
}

func TestCache_SetInt_GetInt(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	tests := []struct {
		name    string
		key     string
		value   int64
	}{
		{
			name:  "zero",
			key:   "zero",
			value: 0,
		},
		{
			name:  "positive",
			key:   "positive",
			value: 42,
		},
		{
			name:  "negative",
			key:   "negative",
			value: -100,
		},
		{
			name:  "large",
			key:   "large",
			value: 9223372036854775807, // Max int64
		},
		{
			name:  "min int64",
			key:   "min",
			value: -9223372036854775808, // Min int64
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cache.SetInt(ctx, tt.key, tt.value)
			require.NoError(t, err)

			retrieved, err := cache.GetInt(ctx, tt.key)
			require.NoError(t, err)
			assert.Equal(t, tt.value, retrieved)
		})
	}
}

func TestCache_Increment(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	key := "increment_key"

	// Increment non-existing key (starts at 0)
	val, err := cache.Increment(ctx, key, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(1), val)

	// Increment by 10
	val, err = cache.Increment(ctx, key, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(11), val)

	// Increment by negative value (decrement)
	val, err = cache.Increment(ctx, key, -5)
	require.NoError(t, err)
	assert.Equal(t, int64(6), val)

	// Verify with GetInt
	retrieved, err := cache.GetInt(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, int64(6), retrieved)
}

func TestCache_Decrement(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	key := "decrement_key"

	// Set initial value
	cache.SetInt(ctx, key, 100)

	// Decrement by 10
	val, err := cache.Decrement(ctx, key, 10)
	require.NoError(t, err)
	assert.Equal(t, int64(90), val)

	// Decrement by negative value (increment)
	val, err = cache.Decrement(ctx, key, -5)
	require.NoError(t, err)
	assert.Equal(t, int64(95), val)

	// Decrement non-existing key (starts at 0, goes negative)
	val, err = cache.Decrement(ctx, "new_decrement_key", 5)
	require.NoError(t, err)
	assert.Equal(t, int64(-5), val)
}

func TestCache_GetSet(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	key := "getset_key"

	// Set initial value
	cache.SetString(ctx, key, "old_value")

	// GetSet with new value
	oldValue, err := cache.GetSet(ctx, key, "new_value")
	require.NoError(t, err)
	assert.Equal(t, "old_value", oldValue)

	// Verify new value
	newValue, err := cache.GetString(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, "new_value", newValue)

	// GetSet on non-existing key
	oldValue, err = cache.GetSet(ctx, "non_existing", "value")
	require.NoError(t, err)
	assert.Equal(t, "", oldValue)
}

func TestCache_GetMultiple(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	// Set multiple keys using SetString to avoid JSON marshaling
	cache.SetString(ctx, "key1", "value1")
	cache.SetString(ctx, "key2", "value2")
	cache.SetString(ctx, "key3", "value3")

	// Get multiple
	keys := []string{"key1", "key2", "key3", "non_existing"}
	results, err := cache.GetMultiple(ctx, keys)
	require.NoError(t, err)

	assert.Equal(t, "value1", results["key1"])
	assert.Equal(t, "value2", results["key2"])
	assert.Equal(t, "value3", results["key3"])
	assert.NotContains(t, results, "non_existing")

	// Empty keys list
	results, err = cache.GetMultiple(ctx, []string{})
	require.NoError(t, err)
	assert.Empty(t, results)

	// Test with JSON marshaled values (Set uses JSON)
	cache.Set(ctx, "json1", "value1")
	cache.Set(ctx, "json2", "value2")
	cache.Set(ctx, "json3", 42)

	keys2 := []string{"json1", "json2", "json3"}
	results2, err := cache.GetMultiple(ctx, keys2)
	require.NoError(t, err)

	// These will be JSON strings with quotes
	assert.Equal(t, "\"value1\"", results2["json1"])
	assert.Equal(t, "\"value2\"", results2["json2"])
	assert.Equal(t, "42", results2["json3"]) // Numbers don't get quotes
}

func TestCache_SetMultiple(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	items := map[string]interface{}{
		"multi_key1": "value1",
		"multi_key2": 42,
		"multi_key3": struct{ Name string }{Name: "test"},
	}

	err := cache.SetMultiple(ctx, items, 5*time.Minute)
	require.NoError(t, err)

	// Verify all keys were set
	var str string
	var num int
	var st struct{ Name string }

	require.NoError(t, cache.Get(ctx, "multi_key1", &str))
	assert.Equal(t, "value1", str)

	require.NoError(t, cache.Get(ctx, "multi_key2", &num))
	assert.Equal(t, 42, num)

	require.NoError(t, cache.Get(ctx, "multi_key3", &st))
	assert.Equal(t, "test", st.Name)
}

func TestCache_FlushAll(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	// Set multiple keys
	cache.Set(ctx, "key1", "value1")
	cache.Set(ctx, "key2", "value2")
	cache.Set(ctx, "key3", "value3")

	// Flush all
	err := cache.FlushAll(ctx)
	require.NoError(t, err)

	// Verify all keys are gone
	exists, _ := cache.Exists(ctx, "key1")
	assert.False(t, exists)

	exists, _ = cache.Exists(ctx, "key2")
	assert.False(t, exists)

	exists, _ = cache.Exists(ctx, "key3")
	assert.False(t, exists)
}

func TestCache_FlushAll_WithPrefix(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop()).WithConfig(Config{
		KeyPrefix: "test:",
	})
	ctx := context.Background()

	// Set keys
	cache.Set(ctx, "key1", "value1")
	cache.Set(ctx, "key2", "value2")

	// Flush
	cache.FlushAll(ctx)

	// Verify
	exists, _ := cache.Exists(ctx, "key1")
	assert.False(t, exists)
}

func TestCache_Metrics(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop()).WithConfig(Config{
		EnableMetrics: true,
	})
	ctx := context.Background()

	// Perform operations
	cache.Set(ctx, "key1", "value1")
	cache.Set(ctx, "key2", "value2")

	var result string
	cache.Get(ctx, "key1", &result) // Hit
	cache.Get(ctx, "non_existent", &result) // Miss

	cache.Delete(ctx, "key1")

	// Check metrics
	metrics := cache.Metrics()
	assert.Equal(t, int64(2), metrics["sets"])
	assert.Equal(t, int64(1), metrics["hits"])
	assert.Equal(t, int64(1), metrics["misses"])
	assert.Equal(t, int64(1), metrics["deletes"])

	// Reset metrics
	cache.ResetMetrics()
	metrics = cache.Metrics()
	assert.Equal(t, int64(0), metrics["sets"])
	assert.Equal(t, int64(0), metrics["hits"])
}

func TestCache_NilRedis(t *testing.T) {
	cache := New(nil, zap.NewNop())
	ctx := context.Background()

	tests := []struct {
		name   string
		method func() error
	}{
		{
			name: "set with nil redis",
			method: func() error {
				return cache.Set(ctx, "key", "value")
			},
		},
		{
			name: "get with nil redis",
			method: func() error {
				var dest string
				return cache.Get(ctx, "key", &dest)
			},
		},
		{
			name: "delete with nil redis",
			method: func() error {
				return cache.Delete(ctx, "key")
			},
		},
		{
			name: "exists with nil redis",
			method: func() error {
				_, err := cache.Exists(ctx, "key")
				return err
			},
		},
		{
			name: "increment with nil redis",
			method: func() error {
				_, err := cache.Increment(ctx, "key", 1)
				return err
			},
		},
		{
			name: "acquire lock with nil redis",
			method: func() error {
				_, err := cache.AcquireLock(ctx, "lock", DefaultLockOptions())
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.method()
			assert.ErrorIs(t, err, ErrRedisUnavailable)
		})
	}
}

func TestCache_AcquireLock(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	tests := []struct {
		name    string
		key     string
		opts    LockOptions
		setup   func(*Cache, context.Context)
		want    bool
		wantErr bool
	}{
		{
			name: "acquire free lock",
			key:  "lock1",
			opts: DefaultLockOptions(),
			want: true,
		},
		{
			name: "acquire held lock with retries",
			key:  "lock2",
			opts: LockOptions{
				TTL:           10 * time.Second,
				RetryInterval: 50 * time.Millisecond,
				MaxRetries:    2,
			},
			setup: func(c *Cache, ctx context.Context) {
				// Acquire lock in goroutine, release after delay
				go func() {
					c.AcquireLock(ctx, "lock2", DefaultLockOptions())
					time.Sleep(100 * time.Millisecond)
					c.ReleaseLock(ctx, "lock2")
				}()
				time.Sleep(50 * time.Millisecond) // Ensure lock is held first
			},
			want: true,
		},
		{
			name: "fail to acquire held lock",
			key:  "lock3",
			opts: LockOptions{
				TTL:           10 * time.Second,
				RetryInterval: 10 * time.Millisecond,
				MaxRetries:    1,
			},
			setup: func(c *Cache, ctx context.Context) {
				c.AcquireLock(ctx, "lock3", DefaultLockOptions())
			},
			want: false,
		},
		{
			name: "acquire with zero TTL",
			key:  "lock4",
			opts: LockOptions{
				TTL:           0,
				RetryInterval: 10 * time.Millisecond,
				MaxRetries:    0,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(cache, ctx)
			}

			acquired, err := cache.AcquireLock(ctx, tt.key, tt.opts)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, acquired)
			}
		})
	}
}

func TestCache_ReleaseLock(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	// Acquire and release lock
	acquired, err := cache.AcquireLock(ctx, "lock", DefaultLockOptions())
	require.NoError(t, err)
	require.True(t, acquired)

	// Release lock
	err = cache.ReleaseLock(ctx, "lock")
	require.NoError(t, err)

	// Should be able to acquire again
	acquired, err = cache.AcquireLock(ctx, "lock", DefaultLockOptions())
	require.NoError(t, err)
	assert.True(t, acquired)

	// Release non-existent lock (should not error)
	err = cache.ReleaseLock(ctx, "non_existent_lock")
	assert.NoError(t, err)
}

func TestCache_TryAcquireLock(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	// Acquire free lock
	acquired, err := cache.TryAcquireLock(ctx, "trylock", 10*time.Second)
	require.NoError(t, err)
	assert.True(t, acquired)

	// Try again (should fail)
	acquired, err = cache.TryAcquireLock(ctx, "trylock", 10*time.Second)
	require.NoError(t, err)
	assert.False(t, acquired)

	// Release and try again
	cache.ReleaseLock(ctx, "trylock")
	acquired, err = cache.TryAcquireLock(ctx, "trylock", 10*time.Second)
	require.NoError(t, err)
	assert.True(t, acquired)
}

func TestCache_ConcurrentAccess(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	const goroutines = 100
	const operationsPerGoroutine = 10

	var wg sync.WaitGroup
	errors := make(chan error, goroutines*operationsPerGoroutine)

	// Concurrent Set operations
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				key := fmt.Sprintf("concurrent_%d", id%10) // 10 unique keys
				if err := cache.Set(ctx, key, id*operationsPerGoroutine+j); err != nil {
					errors <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent set error: %v", err)
	}

	// Verify all keys still exist
	for i := 0; i < 10; i++ {
		exists, err := cache.Exists(ctx, fmt.Sprintf("concurrent_%d", i))
		require.NoError(t, err)
		assert.True(t, exists)
	}
}

func TestCache_ConcurrentLock(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	const goroutines = 10
	var wg sync.WaitGroup
	successCount := int64(0)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			acquired, err := cache.TryAcquireLock(ctx, "shared_lock", 1*time.Second)
			if err != nil {
				return
			}
			if acquired {
				// Hold lock briefly
				time.Sleep(50 * time.Millisecond)
				cache.ReleaseLock(ctx, "shared_lock")
				successCount++
			}
		}()
	}

	wg.Wait()

	// Only one goroutine should have acquired the lock at a time
	// but since they release and retry, multiple may succeed over time
	assert.Greater(t, successCount, int64(0))
	assert.LessOrEqual(t, successCount, int64(goroutines))
}

func TestCache_KeyPrefixing(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	// Create cache with custom prefix
	cache := New(client, zap.NewNop()).WithConfig(Config{
		KeyPrefix: "custom:prefix:",
	})
	ctx := context.Background()

	cache.Set(ctx, "mykey", "value")

	// Verify the full key in Redis
	fullKey := cache.fullKey("mykey")
	assert.Equal(t, "custom:prefix:mykey", fullKey)

	// Key should exist with full prefix
	exists, err := client.Exists(ctx, fullKey).Result()
	require.NoError(t, err)
	assert.Greater(t, exists, int64(0))

	// Should not exist without prefix
	exists, _ = client.Exists(ctx, "mykey").Result()
	assert.Equal(t, int64(0), exists)

	// Should be accessible through cache
	var result string
	err = cache.Get(ctx, "mykey", &result)
	require.NoError(t, err)
	assert.Equal(t, "value", result)
}

func TestCache_Invalidation(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	// Create related keys
	cache.Set(ctx, "user:1:name", "Alice")
	cache.Set(ctx, "user:1:email", "alice@example.com")
	cache.Set(ctx, "user:1:age", 30)
	cache.Set(ctx, "user:2:name", "Bob")

	// Invalidate all user:1 keys
	count, err := cache.DeleteByPrefix(ctx, "user:1:")
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	// Verify user:1 keys are gone
	exists, _ := cache.Exists(ctx, "user:1:name")
	assert.False(t, exists)

	exists, _ = cache.Exists(ctx, "user:1:email")
	assert.False(t, exists)

	exists, _ = cache.Exists(ctx, "user:1:age")
	assert.False(t, exists)

	// Verify user:2 key still exists
	exists, _ = cache.Exists(ctx, "user:2:name")
	assert.True(t, exists)
}

func TestCache_Fallback_WhenRedisDown(t *testing.T) {
	s, client := mustCreateTestRedis(t)

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	// Close the mock Redis to simulate failure
	s.Close()

	// All operations should fail gracefully
	tests := []struct {
		name string
		fn   func() error
	}{
		{
			name: "set fails",
			fn: func() error {
				return cache.Set(ctx, "key", "value")
			},
		},
		{
			name: "get fails",
			fn: func() error {
				var dest string
				return cache.Get(ctx, "key", &dest)
			},
		},
		{
			name: "delete fails",
			fn: func() error {
				return cache.Delete(ctx, "key")
			},
		},
		{
			name: "exists fails",
			fn: func() error {
				_, err := cache.Exists(ctx, "key")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			assert.Error(t, err)
		})
	}
}

func TestCache_RetryLogic(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop()).WithConfig(Config{
		MaxRetries: 3,
	})
	ctx := context.Background()

	// Normal operation should succeed
	err := cache.Set(ctx, "retry_key", "value")
	assert.NoError(t, err)

	// Verify metrics show no errors for successful operation
	metrics := cache.Metrics()
	assert.Equal(t, int64(0), metrics["errors"])
}

func TestCache_SetVariousTypes(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	type NestedStruct struct {
		Inner struct {
			Value int
		}
		Slice []string
	}

	type ComplexStruct struct {
		String   string
		Int      int
		Float    float64
		Bool     bool
		Nil      *string
		Slice    []int
		Map      map[string]interface{}
		Nested   NestedStruct
	}

	complexValue := ComplexStruct{
		String: "test",
		Int:    42,
		Float:  3.14,
		Bool:   true,
		Nil:    nil,
		Slice:  []int{1, 2, 3},
		Map:    map[string]interface{}{"key": "value"},
		Nested: NestedStruct{
			Inner: struct{ Value int }{Value: 100},
			Slice: []string{"a", "b"},
		},
	}

	err := cache.Set(ctx, "complex", complexValue)
	require.NoError(t, err)

	var retrieved ComplexStruct
	err = cache.Get(ctx, "complex", &retrieved)
	require.NoError(t, err)

	assert.Equal(t, complexValue.String, retrieved.String)
	assert.Equal(t, complexValue.Int, retrieved.Int)
	assert.InDelta(t, complexValue.Float, retrieved.Float, 0.01)
	assert.Equal(t, complexValue.Bool, retrieved.Bool)
	assert.Nil(t, retrieved.Nil)
	assert.Equal(t, 3, len(retrieved.Slice))
	assert.Equal(t, "value", retrieved.Map["key"])
	assert.Equal(t, 100, retrieved.Nested.Inner.Value)
}

func TestCache_DefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, 5*time.Minute, config.DefaultTTL)
	assert.Equal(t, "openidx:", config.KeyPrefix)
	assert.Equal(t, 2, config.MaxRetries)
	assert.False(t, config.EnableMetrics)
}

func TestCache_DefaultLockOptions(t *testing.T) {
	opts := DefaultLockOptions()

	assert.Equal(t, 10*time.Second, opts.TTL)
	assert.Equal(t, 100*time.Millisecond, opts.RetryInterval)
	assert.Equal(t, 10, opts.MaxRetries)
}

func TestCache_ErrorWrapping(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	t.Run("invalid value for JSON marshaling", func(t *testing.T) {
		// Use a channel which cannot be marshaled to JSON
		ch := make(chan int)
		err := cache.Set(ctx, "invalid", ch)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid cache value")
	})

	t.Run("get into invalid destination type", func(t *testing.T) {
		cache.SetString(ctx, "key", "string_value")

		// Try to get string into int
		var invalidDest int
		err := cache.Get(ctx, "key", &invalidDest)
		assert.Error(t, err)
	})
}

func TestCache_PatternOperations(t *testing.T) {
	s, client := mustCreateTestRedis(t)
	defer s.Close()

	cache := New(client, zap.NewNop()).WithConfig(Config{
		KeyPrefix: "test:",
	})
	ctx := context.Background()

	// Pattern: cache warming strategy
	t.Run("cache warming - preloading values", func(t *testing.T) {
		initialData := map[string]interface{}{
			"warm:key1": "value1",
			"warm:key2": "value2",
			"warm:key3": 123,
		}

		err := cache.SetMultiple(ctx, initialData, 10*time.Minute)
		require.NoError(t, err)

		// Verify all are loaded
		for key := range initialData {
			exists, _ := cache.Exists(ctx, key)
			assert.True(t, exists)
		}
	})

	// Clean up
	cache.DeleteByPrefix(ctx, "warm:")

	// Pattern: cache-through (write-through)
	t.Run("cache-through pattern", func(t *testing.T) {
		key := "cache_through:key"
		value := "through_value"

		// Write to cache first (async write to DB would follow)
		err := cache.Set(ctx, key, value)
		require.NoError(t, err)

		// Verify immediate read from cache
		var result string
		err = cache.Get(ctx, key, &result)
		require.NoError(t, err)
		assert.Equal(t, value, result)
	})

	// Pattern: cache-aside (lazy loading)
	t.Run("cache-aside pattern", func(t *testing.T) {
		key := "cache_aside:key"
		var result string

		// Try cache first (miss)
		err := cache.Get(ctx, key, &result)
		assert.ErrorIs(t, err, ErrCacheMiss)

		// Simulate loading from source and caching
		dataFromSource := "loaded_from_db"
		cache.Set(ctx, key, dataFromSource)

		// Retry cache (hit)
		err = cache.Get(ctx, key, &result)
		require.NoError(t, err)
		assert.Equal(t, dataFromSource, result)
	})
}

// Benchmark tests
func BenchmarkCache_Set(b *testing.B) {
	s, err := miniredis.Run()
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set(ctx, "bench_key", "bench_value")
	}
}

func BenchmarkCache_Get(b *testing.B) {
	s, err := miniredis.Run()
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})

	cache := New(client, zap.NewNop())
	ctx := context.Background()
	cache.Set(ctx, "bench_key", "bench_value")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result string
		cache.Get(ctx, "bench_key", &result)
	}
}

func BenchmarkCache_SetMultiple(b *testing.B) {
	s, err := miniredis.Run()
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	items := make(map[string]interface{})
	for i := 0; i < 100; i++ {
		items[fmt.Sprintf("key%d", i)] = fmt.Sprintf("value%d", i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.SetMultiple(ctx, items, 5*time.Minute)
	}
}

func BenchmarkCache_AcquireLock(b *testing.B) {
	s, err := miniredis.Run()
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})

	cache := New(client, zap.NewNop())
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		acquired, _ := cache.TryAcquireLock(ctx, "bench_lock", 10*time.Second)
		if acquired {
			cache.ReleaseLock(ctx, "bench_lock")
		}
	}
}
