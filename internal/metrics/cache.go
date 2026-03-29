// Package metrics provides cache instrumentation for Prometheus metrics
package metrics

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// TracedRedisClient wraps redis.Client to collect cache metrics
type TracedRedisClient struct {
	*redis.Client
	serviceName string
}

// NewTracedRedisClient creates a new traced Redis client
func NewTracedRedisClient(client *redis.Client, serviceName string) *TracedRedisClient {
	return &TracedRedisClient{
		Client:      client,
		serviceName: serviceName,
	}
}

// Get wraps Get with metrics collection
func (t *TracedRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	cmd := t.Client.Get(ctx, key)
	err := cmd.Err()
	if err == redis.Nil {
		RecordCacheOperation(t.serviceName, "get", "miss")
	} else if err != nil {
		RecordCacheOperation(t.serviceName, "get", "error")
	} else {
		RecordCacheOperation(t.serviceName, "get", "hit")
	}
	return cmd
}

// Set wraps Set with metrics collection
func (t *TracedRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	cmd := t.Client.Set(ctx, key, value, expiration)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "set", "error")
	} else {
		RecordCacheOperation(t.serviceName, "set", "success")
	}
	return cmd
}

// Del wraps Del with metrics collection
func (t *TracedRedisClient) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	cmd := t.Client.Del(ctx, keys...)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "delete", "error")
	} else {
		RecordCacheOperation(t.serviceName, "delete", "success")
	}
	return cmd
}

// MGet wraps MGet with metrics collection
func (t *TracedRedisClient) MGet(ctx context.Context, keys ...string) *redis.SliceCmd {
	cmd := t.Client.MGet(ctx, keys...)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "mget", "error")
	} else {
		RecordCacheOperation(t.serviceName, "mget", "success")
	}
	return cmd
}

// MSet wraps MSet with metrics collection
func (t *TracedRedisClient) MSet(ctx context.Context, values ...interface{}) *redis.StatusCmd {
	cmd := t.Client.MSet(ctx, values...)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "mset", "error")
	} else {
		RecordCacheOperation(t.serviceName, "mset", "success")
	}
	return cmd
}

// Incr wraps Incr with metrics collection
func (t *TracedRedisClient) Incr(ctx context.Context, key string) *redis.IntCmd {
	cmd := t.Client.Incr(ctx, key)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "incr", "error")
	} else {
		RecordCacheOperation(t.serviceName, "incr", "success")
	}
	return cmd
}

// Decr wraps Decr with metrics collection
func (t *TracedRedisClient) Decr(ctx context.Context, key string) *redis.IntCmd {
	cmd := t.Client.Decr(ctx, key)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "decr", "error")
	} else {
		RecordCacheOperation(t.serviceName, "decr", "success")
	}
	return cmd
}

// Expire wraps Expire with metrics collection
func (t *TracedRedisClient) Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd {
	cmd := t.Client.Expire(ctx, key, expiration)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "expire", "error")
	} else {
		RecordCacheOperation(t.serviceName, "expire", "success")
	}
	return cmd
}

// HGet wraps HGet with metrics collection
func (t *TracedRedisClient) HGet(ctx context.Context, key, field string) *redis.StringCmd {
	cmd := t.Client.HGet(ctx, key, field)
	err := cmd.Err()
	if err == redis.Nil {
		RecordCacheOperation(t.serviceName, "hget", "miss")
	} else if err != nil {
		RecordCacheOperation(t.serviceName, "hget", "error")
	} else {
		RecordCacheOperation(t.serviceName, "hget", "hit")
	}
	return cmd
}

// HSet wraps HSet with metrics collection
func (t *TracedRedisClient) HSet(ctx context.Context, key string, values ...interface{}) *redis.IntCmd {
	cmd := t.Client.HSet(ctx, key, values...)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "hset", "error")
	} else {
		RecordCacheOperation(t.serviceName, "hset", "success")
	}
	return cmd
}

// HDel wraps HDel with metrics collection
func (t *TracedRedisClient) HDel(ctx context.Context, key string, fields ...string) *redis.IntCmd {
	cmd := t.Client.HDel(ctx, key, fields...)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "hdel", "error")
	} else {
		RecordCacheOperation(t.serviceName, "hdel", "success")
	}
	return cmd
}

// LLen wraps LLen with metrics collection
func (t *TracedRedisClient) LLen(ctx context.Context, key string) *redis.IntCmd {
	cmd := t.Client.LLen(ctx, key)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "llen", "error")
	} else {
		RecordCacheOperation(t.serviceName, "llen", "success")
	}
	return cmd
}

// LPush wraps LPush with metrics collection
func (t *TracedRedisClient) LPush(ctx context.Context, key string, values ...interface{}) *redis.IntCmd {
	cmd := t.Client.LPush(ctx, key, values...)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "lpush", "error")
	} else {
		RecordCacheOperation(t.serviceName, "lpush", "success")
	}
	return cmd
}

// RPop wraps RPop with metrics collection
func (t *TracedRedisClient) RPop(ctx context.Context, key string) *redis.StringCmd {
	cmd := t.Client.RPop(ctx, key)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "rpop", "error")
	} else {
		RecordCacheOperation(t.serviceName, "rpop", "success")
	}
	return cmd
}

// SAdd wraps SAdd with metrics collection
func (t *TracedRedisClient) SAdd(ctx context.Context, key string, members ...interface{}) *redis.IntCmd {
	cmd := t.Client.SAdd(ctx, key, members...)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "sadd", "error")
	} else {
		RecordCacheOperation(t.serviceName, "sadd", "success")
	}
	return cmd
}

// SIsMember wraps SIsMember with metrics collection
func (t *TracedRedisClient) SIsMember(ctx context.Context, key string, member interface{}) *redis.BoolCmd {
	cmd := t.Client.SIsMember(ctx, key, member)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "sismember", "error")
	} else {
		RecordCacheOperation(t.serviceName, "sismember", "success")
	}
	return cmd
}

// ZAdd wraps ZAdd with metrics collection
func (t *TracedRedisClient) ZAdd(ctx context.Context, key string, members ...redis.Z) *redis.IntCmd {
	cmd := t.Client.ZAdd(ctx, key, members...)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "zadd", "error")
	} else {
		RecordCacheOperation(t.serviceName, "zadd", "success")
	}
	return cmd
}

// ZRange wraps ZRange with metrics collection
func (t *TracedRedisClient) ZRange(ctx context.Context, key string, start, stop int64) *redis.StringSliceCmd {
	cmd := t.Client.ZRange(ctx, key, start, stop)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "zrange", "error")
	} else {
		RecordCacheOperation(t.serviceName, "zrange", "success")
	}
	return cmd
}

// Publish wraps Publish with metrics collection
func (t *TracedRedisClient) Publish(ctx context.Context, channel string, message interface{}) *redis.IntCmd {
	cmd := t.Client.Publish(ctx, channel, message)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "publish", "error")
	} else {
		RecordCacheOperation(t.serviceName, "publish", "success")
	}
	return cmd
}

// Subscribe wraps Subscribe with metrics collection
func (t *TracedRedisClient) Subscribe(ctx context.Context, channels ...string) *redis.PubSub {
	pubsub := t.Client.Subscribe(ctx, channels...)
	RecordCacheOperation(t.serviceName, "subscribe", "success")
	return pubsub
}

// Ping wraps Ping with metrics collection
func (t *TracedRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	cmd := t.Client.Ping(ctx)
	if cmd.Err() != nil {
		RecordCacheOperation(t.serviceName, "ping", "error")
	} else {
		RecordCacheOperation(t.serviceName, "ping", "success")
	}
	return cmd
}
