package database

import (
	"github.com/redis/go-redis/v9"

	"github.com/openidx/openidx/internal/common/redisclient"
)

// The Redis half moved to internal/common/redisclient so that a binary needing
// a Redis client does not link a PostgreSQL driver along with it. It lived in
// database.go next to NewPostgres and the pgx pool, which is why
// cmd/gateway-service -- whose only use of this package was NewRedisFromConfig
// -- shipped with pgx in its import graph for no other reason.
//
// These are aliases, not a second implementation. Every existing caller keeps
// working unchanged, and there is still one Redis constructor and one role
// split in the tree. A binary that wants to be free of the driver imports
// redisclient directly.

// RedisClient wraps the Redis client and its role-specific siblings. See
// redisclient.Client for the role contract -- which call sites must address
// RateLimit or Revocation rather than Client, and why.
type RedisClient = redisclient.Client

// RedisConfig holds configuration for creating a Redis client, with optional
// Sentinel failover and TLS.
type RedisConfig = redisclient.Config

// NewRedisFromConfig builds a Redis client (and its role siblings) from cfg.
func NewRedisFromConfig(cfg RedisConfig) (*RedisClient, error) {
	return redisclient.NewFromConfig(cfg)
}

// NewRedisClientWithRoles builds a client from three already-open clients. A
// nil role falls back to the primary, which is what a single-Redis install has.
func NewRedisClientWithRoles(primary, rateLimit, revocation *redis.Client) *RedisClient {
	return redisclient.NewWithRoles(primary, rateLimit, revocation)
}

// NewRedis opens a Redis client from a connection string.
func NewRedis(connString string) (*RedisClient, error) {
	return redisclient.New(connString)
}
