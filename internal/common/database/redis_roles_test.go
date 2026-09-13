package database

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startMini(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	m, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(m.Close)
	return m
}

// With no role URLs, every role is the primary: one connection, one client,
// exactly today's behaviour for a single-Redis install.
func TestNewRedisFromConfig_RolesAliasPrimaryWhenUnset(t *testing.T) {
	m := startMini(t)
	rc, err := NewRedisFromConfig(RedisConfig{URL: "redis://" + m.Addr()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = rc.Close() })

	assert.Same(t, rc.Client, rc.RateLimit)
	assert.Same(t, rc.Client, rc.Revocation)
	assert.False(t, rc.HasDedicatedRateLimit())
	assert.False(t, rc.HasDedicatedRevocation())
	assert.Len(t, rc.distinctClients(), 1)
}

// With role URLs set, each role is its own connection to its own instance and
// a write through the role accessor lands only there.
func TestNewRedisFromConfig_DedicatedRolesAreSeparateInstances(t *testing.T) {
	primary, rl, rv := startMini(t), startMini(t), startMini(t)
	rc, err := NewRedisFromConfig(RedisConfig{
		URL:           "redis://" + primary.Addr(),
		RateLimitURL:  "redis://" + rl.Addr(),
		RevocationURL: "redis://" + rv.Addr(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = rc.Close() })

	assert.True(t, rc.HasDedicatedRateLimit())
	assert.True(t, rc.HasDedicatedRevocation())
	assert.Len(t, rc.distinctClients(), 3)

	ctx := context.Background()
	require.NoError(t, rc.Client.Set(ctx, "login_session:x", "1", 0).Err())
	require.NoError(t, rc.RateLimitDB().Set(ctx, "ratelimit:ip:_:1.2.3.4:1", "1", 0).Err())
	require.NoError(t, rc.RevocationDB().Set(ctx, "oauth:user_tokens_revoked_at:u1", "1", 0).Err())

	assert.ElementsMatch(t, []string{"login_session:x"}, primary.Keys())
	assert.ElementsMatch(t, []string{"ratelimit:ip:_:1.2.3.4:1"}, rl.Keys())
	assert.ElementsMatch(t, []string{"oauth:user_tokens_revoked_at:u1"}, rv.Keys())

	// Ping covers every instance: kill the revocation one and readiness must
	// go red even though the primary is fine.
	require.NoError(t, rc.PingContext(ctx))
	rv.Close()
	assert.Error(t, rc.PingContext(ctx), "a dead revocation instance must fail the health ping")
}

// An unreachable role instance is a startup error, not a silent alias back to
// the primary: silently sharing would recreate the exact failure mode the
// operator configured their way out of.
func TestNewRedisFromConfig_UnreachableRoleIsAnError(t *testing.T) {
	primary := startMini(t)
	_, err := NewRedisFromConfig(RedisConfig{
		URL:          "redis://" + primary.Addr(),
		RateLimitURL: "redis://127.0.0.1:1", // nothing listens here
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rate-limit role")
}

// Hand-built literals (the shape every existing test uses) keep working: the
// accessors fall back to Client when the role fields are nil.
func TestRedisClient_AccessorsAreNilSafe(t *testing.T) {
	m := startMini(t)
	c := redis.NewClient(&redis.Options{Addr: m.Addr()})
	t.Cleanup(func() { _ = c.Close() })

	rc := &RedisClient{Client: c}
	assert.Same(t, c, rc.RateLimitDB())
	assert.Same(t, c, rc.RevocationDB())

	var nilRC *RedisClient
	assert.Nil(t, nilRC.RateLimitDB())
	assert.Nil(t, nilRC.RevocationDB())

	withRoles := NewRedisClientWithRoles(c, nil, nil)
	assert.Same(t, c, withRoles.RateLimit)
	assert.Same(t, c, withRoles.Revocation)
}
