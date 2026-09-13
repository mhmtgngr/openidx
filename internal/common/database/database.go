// Package database provides database connection utilities for OpenIDX services
package database

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// PostgresDB wraps the pgx connection pool.
//
// Pool is the primary (read-write) pool and MUST be used for all writes and for
// any read that must observe its own prior write (read-after-write). readPool,
// when non-nil, is an OPTIONAL pool pointed at a read replica / reader endpoint;
// callers opt into it via Reader() for read-mostly, lag-tolerant queries (e.g.
// signing-key/discovery reads, dashboards, audit/governance reports). When no
// replica is configured, Reader() returns the primary pool, so call sites are
// always correct by construction and simply lose the offload benefit.
type PostgresDB struct {
	// Pool applies the request's tenant scope to every query (see
	// scopedpool.go). It keeps the method set of *pgxpool.Pool, so the ~1,950
	// existing call sites read and compile unchanged while gaining the scope
	// that RLS_MODE=local needs. Raw() reaches the unscoped pool for
	// install-wide tables and pool statistics.
	Pool     *ScopedPool
	readPool *ScopedPool
}

// Reader returns the pool to use for read-mostly, replication-lag-tolerant
// queries. It returns the read-replica pool when one is configured
// (DATABASE_READ_URL), otherwise the primary pool. NEVER use Reader() for writes
// or for a read that must see a just-committed write from the same request — use
// Pool for those.
//
// It is scoped, like Pool. It was NOT, for one commit: task 2.1b moved the
// tenant scope into Pool's type and left Reader() handing out the bare pgx
// pool, which meant roughly a dozen read-path queries — user by id, by
// username, by email, sessions, groups, oauth clients — would have run with no
// app.org_id in RLS_MODE=local. Under FORCE RLS that is not an error: it is
// zero rows, so a login would simply say the user does not exist. A replica
// read is still a tenant read; Raw() stays the one way to ask for an unscoped
// one, by name.
func (db *PostgresDB) Reader() *ScopedPool {
	if db.readPool != nil {
		return db.readPool
	}
	return db.Pool
}

// HasReadReplica reports whether a distinct read-replica pool is configured.
func (db *PostgresDB) HasReadReplica() bool {
	return db.readPool != nil
}

// PostgresTLSConfig holds TLS configuration for PostgreSQL connections
type PostgresTLSConfig struct {
	SSLMode     string // disable, require, verify-ca, verify-full
	SSLRootCert string // Path to CA certificate
	SSLCert     string // Path to client certificate (mTLS)
	SSLKey      string // Path to client private key (mTLS)
}

// envInt32 reads an int32 from env var name, clamped to >= min, falling back to def
// (with default on empty/unparseable input). Used for pool sizing knobs.
func envInt32(name string, def, min int32) int32 {
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	// ParseInt with bitSize 32 bounds the result to int32 and errors on overflow, so a huge
	// env value (e.g. "3000000000") falls back to the default instead of silently wrapping.
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil || int32(n) < min {
		return def
	}
	return int32(n)
}

// envDuration reads a Go duration (e.g. "5s", "30s") from env var name, falling
// back to def on empty/unparseable input. Negative durations fall back to def;
// an explicit "0" is honored (used to disable statement_timeout).
func envDuration(name string, def time.Duration) time.Duration {
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return def
	}
	return d
}

// NewPostgres creates a new PostgreSQL connection pool.
// An optional PostgresTLSConfig can be provided to configure SSL parameters.
//
// If DATABASE_READ_URL is set, a second (read-only) pool is opened against it and
// exposed via (*PostgresDB).Reader() for read-mostly, replication-lag-tolerant
// queries. The same TLS config and pool settings are applied. If the replica
// can't be reached at startup, NewPostgres logs nothing here (no logger) but
// returns an error only for the PRIMARY — a bad replica must not take the service
// down, so a replica ping failure degrades to "no replica" (Reader() falls back
// to the primary) rather than failing startup.
func NewPostgres(connString string, tlsCfg ...PostgresTLSConfig) (*PostgresDB, error) {
	// Apply TLS config to connection string if provided
	if len(tlsCfg) > 0 {
		connString = applyPostgresTLS(connString, tlsCfg[0])
	}

	config, err := buildPoolConfig(connString)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test the connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db := &PostgresDB{Pool: NewScopedPool(pool)}

	// Optional read-replica pool. A replica is a pure optimization + warm standby;
	// its unavailability must never fail service startup, so we degrade to
	// primary-only (Reader() falls back to Pool) if it can't be opened/pinged.
	if readURL := os.Getenv("DATABASE_READ_URL"); readURL != "" {
		if len(tlsCfg) > 0 {
			readURL = applyPostgresTLS(readURL, tlsCfg[0])
		}
		if rp, rerr := openReadPool(readURL); rerr == nil {
			db.readPool = NewScopedPool(rp)
		}
		// On error: leave db.readPool nil. The audit checker (registered
		// separately) surfaces replica health; startup continues on the primary.
	}

	return db, nil
}

// openReadPool builds and pings a read-only pool for the reader endpoint. It uses
// the same buildPoolConfig (pool sizing, timeouts, RLS checkout — set_config is
// read-only-safe on a hot standby) as the primary.
func openReadPool(readURL string) (*pgxpool.Pool, error) {
	cfg, err := buildPoolConfig(readURL)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rp, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := rp.Ping(ctx); err != nil {
		rp.Close()
		return nil, err
	}
	return rp, nil
}

// buildPoolConfig parses connString and applies OpenIDX's pool sizing, timeout,
// and RLS settings. Split out from NewPostgres so the (DB-free) configuration
// can be unit-tested without a live Postgres.
func buildPoolConfig(connString string) (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Connection pool settings. Sized so the whole fleet fits under Postgres
	// max_connections: OpenIDX runs ~8 services against ONE database, so the old
	// 25-conn default per service allowed up to ~200 connections vs a typical
	// max_connections=100 — connection exhaustion under load. Default to 10 max /
	// 2 min per service (8*10=80, leaving headroom for migrations, admin, psql and
	// monitoring); raise DB_MAX_CONNS for a hot service (and Postgres
	// max_connections to match) if the openidx_db_connections saturation alert
	// fires.
	//
	// A transaction pooler in front of this is safe ONLY in RLS_MODE=local. In
	// the default session mode RLS stamps app.org_id as a SESSION GUC at pool
	// checkout (rls.go), the pooler hands that backend to the next client, and
	// the next tenant reads the previous tenant's rows — measured, not
	// theorised: docs/evidence/2026-09-13-rls-transaction-pooling.md. The Helm
	// chart refuses to render the unsafe combination.
	//
	// In local mode these numbers change meaning. They then size the pool of
	// CLIENT connections to the pooler, which are cheap, while the Postgres
	// backend budget belongs to the pooler (pgcat replicas × pool_size) and no
	// longer grows when a service autoscales. That is the point of the pooler:
	// keeping DB_MAX_CONNS small stops being the thing that protects Postgres,
	// so a hot service can be given a larger one without renegotiating
	// max_connections with every other service. See
	// docs/architecture/db-pooling.md.
	config.MaxConns = envInt32("DB_MAX_CONNS", 10, 1)
	config.MinConns = envInt32("DB_MIN_CONNS", 2, 0)
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 30 * time.Minute
	config.HealthCheckPeriod = time.Minute

	// Availability belt (Tier 1 — issue path): bound how long a single dial may
	// take. pgx's default ConnectTimeout is 0 (no timeout), so a runtime
	// reconnect to a *dead* primary during an RDS/Patroni failover can hang for
	// the OS TCP timeout (often minutes), pinning the acquiring request and
	// eventually exhausting the pool — a database failover cascading into a
	// service-wide outage. A short connect timeout makes failover fail fast and
	// lets the pool re-dial the promoted primary. Tunable via DB_CONNECT_TIMEOUT
	// (Go duration, e.g. "5s"); default 5s. HealthCheckPeriod above then evicts
	// dead conns within a minute so new acquires reconnect.
	config.ConnConfig.ConnectTimeout = envDuration("DB_CONNECT_TIMEOUT", 5*time.Second)

	// Optional per-statement timeout, applied as a server-side runtime parameter
	// on every pooled connection. Disabled by default (0) to avoid surprising
	// long-running work (migrations, bulk audit/governance reports); set
	// DB_STATEMENT_TIMEOUT (e.g. "30s") on request-serving services so a query
	// stuck on a degraded primary can't hold a connection open indefinitely.
	// NOTE: keep this UNSET on the migrate entrypoint (large index builds).
	if stmtTimeout := envDuration("DB_STATEMENT_TIMEOUT", 0); stmtTimeout > 0 {
		if config.ConnConfig.RuntimeParams == nil {
			config.ConnConfig.RuntimeParams = map[string]string{}
		}
		// Postgres statement_timeout is in milliseconds.
		config.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(stmtTimeout.Milliseconds(), 10)
	}

	// v1.8.0 RLS belt: stamp each connection with the request's tenant scope
	// (app.org_id / app.bypass_rls) at checkout from orgctx on the acquire ctx.
	configureRLS(config)

	return config, nil
}

// applyPostgresTLS modifies the connection string to include SSL parameters
func applyPostgresTLS(connString string, cfg PostgresTLSConfig) string {
	if cfg.SSLMode == "" || cfg.SSLMode == "disable" {
		return connString
	}

	u, err := url.Parse(connString)
	if err != nil {
		return connString
	}

	q := u.Query()
	q.Set("sslmode", cfg.SSLMode)
	if cfg.SSLRootCert != "" {
		q.Set("sslrootcert", cfg.SSLRootCert)
	}
	if cfg.SSLCert != "" {
		q.Set("sslcert", cfg.SSLCert)
	}
	if cfg.SSLKey != "" {
		q.Set("sslkey", cfg.SSLKey)
	}
	u.RawQuery = q.Encode()

	return u.String()
}

// Close closes the connection pool
func (db *PostgresDB) Close() error {
	if db.readPool != nil {
		db.readPool.Close()
	}
	db.Pool.Close()
	return nil
}

// PingRead verifies the read-replica connection is alive. Returns nil when no
// replica is configured (nothing to check).
func (db *PostgresDB) PingRead() error {
	if db.readPool == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return db.readPool.Ping(ctx)
}

// Ping verifies the database connection is alive
func (db *PostgresDB) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return db.Pool.Ping(ctx)
}

// RedisClient wraps the Redis client and its role-specific siblings.
//
// Client is the primary (session) instance: login/MFA/authcode state, email
// queue, leader locks, caches. RateLimit and Revocation are the two roles whose
// loss profile differs enough to deserve their own instance (see
// RedisConfig.RateLimitURL / RevocationURL). When a role URL is not configured
// the role field ALIASES Client — same *redis.Client, no second connection — so
// every call site can address the role it means and a single-Redis install
// behaves exactly as before.
//
// Call sites must address the role, never Client, for:
//   - rate-limit counters            → RateLimit
//   - revoked_session:* markers, the per-user revoke-all marker and the
//     per-token blacklist            → Revocation
//
// internal/revocation carries a static census test that fails the build when a
// revocation marker is written through Client.
type RedisClient struct {
	Client     *redis.Client
	RateLimit  *redis.Client
	Revocation *redis.Client
}

// RedisConfig holds configuration for creating a Redis client with optional
// Sentinel failover support and TLS.
type RedisConfig struct {
	// URL is the standard Redis connection string (used when Sentinel is disabled)
	URL string

	// Sentinel configuration
	SentinelEnabled    bool
	SentinelMasterName string
	SentinelAddresses  []string
	SentinelPassword   string

	// Password for the Redis master (extracted from URL when using Sentinel)
	Password string

	// TLS configuration
	TLSEnabled    bool
	TLSCACert     string // CA cert path
	TLSCert       string // Client cert path (mTLS)
	TLSKey        string // Client key path (mTLS)
	TLSSkipVerify bool   // Skip TLS verification (dev only)

	// Optional role instances. Plain Redis URLs; the TLS settings above apply
	// to them too. Empty = alias the primary. Sentinel addressing for a role
	// instance is deliberately not supported here: a role instance is a small,
	// single-purpose Redis and the managed-cache endpoints used in production
	// already hide failover behind one hostname.
	RateLimitURL  string
	RevocationURL string
}

// buildRedisTLSConfig constructs a *tls.Config from the RedisConfig TLS fields
func buildRedisTLSConfig(cfg RedisConfig) (*tls.Config, error) {
	if !cfg.TLSEnabled {
		return nil, nil
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.TLSCACert != "" {
		caCert, err := os.ReadFile(cfg.TLSCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read Redis CA cert %s: %w", cfg.TLSCACert, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse Redis CA certificate from %s", cfg.TLSCACert)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load Redis client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if cfg.TLSSkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}

	return tlsCfg, nil
}

// NewRedisFromConfig creates a Redis client from a RedisConfig.
// When SentinelEnabled is true, it uses redis.NewFailoverClient with Sentinel
// addresses for automatic master failover.
func NewRedisFromConfig(cfg RedisConfig) (*RedisClient, error) {
	tlsCfg, err := buildRedisTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	if cfg.SentinelEnabled {
		if len(cfg.SentinelAddresses) == 0 {
			return nil, fmt.Errorf("redis sentinel enabled but no sentinel addresses configured")
		}
		opt := &redis.FailoverOptions{
			MasterName:       cfg.SentinelMasterName,
			SentinelAddrs:    cfg.SentinelAddresses,
			SentinelPassword: cfg.SentinelPassword,
			Password:         cfg.Password,
			PoolSize:         10,
			MinIdleConns:     5,
			MaxRetries:       3,
			DialTimeout:      5 * time.Second,
			ReadTimeout:      3 * time.Second,
			WriteTimeout:     3 * time.Second,
			TLSConfig:        tlsCfg,
		}
		client := redis.NewFailoverClient(opt)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if _, err := client.Ping(ctx).Result(); err != nil {
			return nil, fmt.Errorf("failed to connect to Redis via Sentinel: %w", err)
		}
		return attachRedisRoles(&RedisClient{Client: client}, cfg, tlsCfg)
	}

	// Non-sentinel: parse URL and apply TLS
	primary, err := newRedisWithTLS(cfg.URL, tlsCfg)
	if err != nil {
		return nil, err
	}
	return attachRedisRoles(primary, cfg, tlsCfg)
}

// attachRedisRoles fills RateLimit and Revocation on a freshly built primary:
// a dedicated client when the role URL is set, the primary itself otherwise.
// A role instance that cannot be reached is a startup error, not a silent
// fallback to the primary — falling back would quietly recreate the shared
// instance the operator configured their way out of.
func attachRedisRoles(primary *RedisClient, cfg RedisConfig, tlsCfg *tls.Config) (*RedisClient, error) {
	primary.RateLimit = primary.Client
	primary.Revocation = primary.Client
	if cfg.RateLimitURL != "" {
		rl, err := newRedisWithTLS(cfg.RateLimitURL, tlsCfg)
		if err != nil {
			primary.Client.Close()
			return nil, fmt.Errorf("redis rate-limit role: %w", err)
		}
		primary.RateLimit = rl.Client
	}
	if cfg.RevocationURL != "" {
		rv, err := newRedisWithTLS(cfg.RevocationURL, tlsCfg)
		if err != nil {
			primary.Client.Close()
			if primary.RateLimit != primary.Client {
				primary.RateLimit.Close()
			}
			return nil, fmt.Errorf("redis revocation role: %w", err)
		}
		primary.Revocation = rv.Client
	}
	return primary, nil
}

// NewRedisClientWithRoles builds a RedisClient from already-constructed
// clients. Nil role clients alias the primary. It exists for tests and for
// callers that own the client lifecycle; production code goes through
// NewRedisFromConfig.
func NewRedisClientWithRoles(primary, rateLimit, revocation *redis.Client) *RedisClient {
	rc := &RedisClient{Client: primary, RateLimit: primary, Revocation: primary}
	if rateLimit != nil {
		rc.RateLimit = rateLimit
	}
	if revocation != nil {
		rc.Revocation = revocation
	}
	return rc
}

// distinctClients returns each underlying client once, aliases collapsed.
func (r *RedisClient) distinctClients() []*redis.Client {
	seen := map[*redis.Client]bool{}
	var out []*redis.Client
	for _, c := range []*redis.Client{r.Client, r.RateLimit, r.Revocation} {
		if c != nil && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// RateLimitDB returns the client rate-limit counters must use. Nil-safe for
// hand-built RedisClient literals (tests): a missing role aliases the primary.
func (r *RedisClient) RateLimitDB() *redis.Client {
	if r == nil {
		return nil
	}
	if r.RateLimit != nil {
		return r.RateLimit
	}
	return r.Client
}

// RevocationDB returns the client revocation markers must use (revoked_session:*,
// the per-user revoke-all marker, the per-token blacklist). Nil-safe like
// RateLimitDB. Every revocation call site goes through this accessor; the
// census test in internal/revocation rejects a marker written through Client.
func (r *RedisClient) RevocationDB() *redis.Client {
	if r == nil {
		return nil
	}
	if r.Revocation != nil {
		return r.Revocation
	}
	return r.Client
}

// PingContext verifies every distinct Redis instance is alive within ctx.
func (r *RedisClient) PingContext(ctx context.Context) error {
	for _, c := range r.distinctClients() {
		if _, err := c.Ping(ctx).Result(); err != nil {
			return err
		}
	}
	return nil
}

// HasDedicatedRateLimit reports whether rate-limit counters live on their own
// instance rather than sharing the primary.
func (r *RedisClient) HasDedicatedRateLimit() bool {
	return r.RateLimit != nil && r.RateLimit != r.Client
}

// HasDedicatedRevocation reports whether revocation markers live on their own
// instance rather than sharing the primary.
func (r *RedisClient) HasDedicatedRevocation() bool {
	return r.Revocation != nil && r.Revocation != r.Client
}

// NewRedis creates a new Redis client (backward-compatible, no TLS)
func NewRedis(connString string) (*RedisClient, error) {
	return newRedisWithTLS(connString, nil)
}

// newRedisWithTLS creates a Redis client with optional TLS configuration
func newRedisWithTLS(connString string, tlsCfg *tls.Config) (*RedisClient, error) {
	opt, err := redis.ParseURL(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	// Connection pool settings
	opt.PoolSize = 10
	opt.MinIdleConns = 5
	opt.MaxRetries = 3
	opt.DialTimeout = 5 * time.Second
	opt.ReadTimeout = 3 * time.Second
	opt.WriteTimeout = 3 * time.Second

	if tlsCfg != nil {
		opt.TLSConfig = tlsCfg
	}

	client := redis.NewClient(opt)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test the connection
	if _, err := client.Ping(ctx).Result(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisClient{Client: client, RateLimit: client, Revocation: client}, nil
}

// Close closes every distinct underlying connection once.
func (r *RedisClient) Close() error {
	var first error
	for _, c := range r.distinctClients() {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Ping verifies every distinct Redis instance is alive. A dead role instance
// is reported: readiness must not say "redis up" while revocation markers
// have nowhere to go.
func (r *RedisClient) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, c := range r.distinctClients() {
		if _, err := c.Ping(ctx).Result(); err != nil {
			return err
		}
	}
	return nil
}

// ElasticsearchClient wraps the Elasticsearch v8 client
type ElasticsearchClient struct {
	Client *elasticsearch.Client
	URL    string
}

// ElasticsearchConfig holds configuration for creating an Elasticsearch client
// with optional authentication and TLS.
type ElasticsearchConfig struct {
	URL      string
	Username string
	Password string
	TLS      bool
	CACert   string // CA cert path
}

// NewElasticsearchFromConfig creates an Elasticsearch client with auth and TLS support
func NewElasticsearchFromConfig(cfg ElasticsearchConfig) (*ElasticsearchClient, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("elasticsearch URL is required")
	}

	esCfg := elasticsearch.Config{
		Addresses: []string{cfg.URL},
	}

	if cfg.Username != "" {
		esCfg.Username = cfg.Username
		esCfg.Password = cfg.Password
	}

	if cfg.TLS {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

		if cfg.CACert != "" {
			caCert, err := os.ReadFile(cfg.CACert)
			if err != nil {
				return nil, fmt.Errorf("failed to read ES CA cert %s: %w", cfg.CACert, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse ES CA certificate from %s", cfg.CACert)
			}
			tlsCfg.RootCAs = pool
		}

		transport.TLSClientConfig = tlsCfg
		esCfg.Transport = transport
	}

	client, err := elasticsearch.NewClient(esCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create elasticsearch client: %w", err)
	}

	// Test connectivity AND authentication. Ping only surfaces transport errors; a
	// wrong password / missing creds against a security-enabled cluster comes back as
	// a 401/403 response with err == nil, so check the response status too — otherwise
	// a misconfigured credential silently "connects" and then fails every operation.
	res, err := client.Ping()
	if err != nil {
		return nil, fmt.Errorf("failed to ping elasticsearch: %w", err)
	}
	defer res.Body.Close()
	if res.IsError() {
		return nil, fmt.Errorf("elasticsearch ping failed: %s (check credentials/URL)", res.Status())
	}

	return &ElasticsearchClient{Client: client, URL: cfg.URL}, nil
}

// NewElasticsearch creates a new Elasticsearch client with connection validation (backward-compatible)
func NewElasticsearch(url string) (*ElasticsearchClient, error) {
	return NewElasticsearchFromConfig(ElasticsearchConfig{URL: url})
}

// Ping verifies the Elasticsearch connection is alive
func (es *ElasticsearchClient) Ping() error {
	res, err := es.Client.Ping()
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.IsError() {
		return fmt.Errorf("elasticsearch ping returned %s", res.Status())
	}
	return nil
}

// Index indexes a document into the specified index
func (es *ElasticsearchClient) Index(index, docID string, body []byte) error {
	res, err := es.Client.Index(
		index,
		bytes.NewReader(body),
		es.Client.Index.WithDocumentID(docID),
		es.Client.Index.WithRefresh("false"),
	)
	if err != nil {
		return fmt.Errorf("es index request: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("es index error: %s", res.Status())
	}
	return nil
}

// Search executes a search query against the specified index and returns the raw response body
func (es *ElasticsearchClient) Search(index string, query io.Reader) ([]byte, error) {
	res, err := es.Client.Search(
		es.Client.Search.WithIndex(index),
		es.Client.Search.WithBody(query),
	)
	if err != nil {
		return nil, fmt.Errorf("es search request: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("es read response: %w", err)
	}

	if res.IsError() {
		return nil, fmt.Errorf("es search error: %s", res.Status())
	}
	return body, nil
}

// EnsureIndex creates an index with the given mapping if it does not already exist
func (es *ElasticsearchClient) EnsureIndex(index, mapping string) error {
	// Check if index exists
	res, err := es.Client.Indices.Exists([]string{index})
	if err != nil {
		return fmt.Errorf("es check index: %w", err)
	}
	res.Body.Close()

	if res.StatusCode == 200 {
		return nil // already exists
	}

	// Create index with mapping
	res, err = es.Client.Indices.Create(
		index,
		es.Client.Indices.Create.WithBody(strings.NewReader(mapping)),
	)
	if err != nil {
		return fmt.Errorf("es create index: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		// Ignore "resource_already_exists_exception"
		if strings.Contains(string(body), "resource_already_exists_exception") {
			return nil
		}
		return fmt.Errorf("es create index error: %s %s", res.Status(), string(body))
	}
	return nil
}

// EsSearchResponse is the top-level Elasticsearch search response structure
type EsSearchResponse struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			Source json.RawMessage `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}
