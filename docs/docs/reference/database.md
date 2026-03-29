# database

`import "github.com/openidx/openidx/internal/common/database"`

Package database provides connection management for PostgreSQL, Redis, and Elasticsearch with TLS support, connection pooling, and health checks.

## PostgreSQL

```go
type PostgresDB struct { Pool *pgxpool.Pool }

type PostgresTLSConfig struct {
    SSLMode     string  // "disable", "require", "verify-ca", "verify-full"
    SSLRootCert string  // Path to CA certificate
    SSLCert     string  // Path to client certificate (mTLS)
    SSLKey      string  // Path to client private key (mTLS)
}

func NewPostgres(connString string, tlsCfg ...PostgresTLSConfig) (*PostgresDB, error)
func (db *PostgresDB) Close() error
func (db *PostgresDB) Ping() error
```

Connection pool defaults: 25 max connections, 5 min connections, 1-hour max lifetime, 30-minute idle timeout, 1-minute health check period.

## Redis

```go
type RedisClient struct { Client *redis.Client }

type RedisConfig struct {
    URL string
    SentinelEnabled bool; SentinelMasterName string
    SentinelAddresses []string; SentinelPassword, Password string
    TLSEnabled bool; TLSCACert, TLSCert, TLSKey string; TLSSkipVerify bool
}

func NewRedis(connString string) (*RedisClient, error)
func NewRedisFromConfig(cfg RedisConfig) (*RedisClient, error)
func (r *RedisClient) Close() error
func (r *RedisClient) Ping() error
```

`NewRedis` is the simple constructor (no TLS). `NewRedisFromConfig` supports Sentinel failover and TLS/mTLS. Pool defaults: 10 connections, 5 min idle, 3 retries, 5-second dial timeout.

## Elasticsearch

```go
type ElasticsearchClient struct { Client *elasticsearch.Client; URL string }

type ElasticsearchConfig struct {
    URL, Username, Password string
    TLS bool; CACert string
}

func NewElasticsearchFromConfig(cfg ElasticsearchConfig) (*ElasticsearchClient, error)
```

Supports basic authentication and TLS with a custom CA certificate.
