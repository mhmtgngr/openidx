// Package redisclient is OpenIDX's Redis half, in a package of its own.
//
// IT EXISTS BECAUSE OF WHAT IT DOES NOT DRAG ALONG. All of this used to live in
// internal/common/database next to NewPostgres and the pgx pool, in one file,
// so every binary that wanted a Redis client linked a PostgreSQL driver as
// well. cmd/gateway-service is the clearest case: its only use of that package
// is NewRedisFromConfig, and it shipped with pgx in its import graph for no
// other reason.
//
// That is the same mixed-plane shape internal/common/jwksverify was split out
// of internal/common/middleware to fix, and it is fixed the same way: the code
// moved, nothing was copied, and internal/common/database keeps the old
// spellings as aliases so no call site had to change. A binary that wants to be
// free of the driver imports this package directly; everything else carries on
// through database.
//
// The three-role split (primary / rate-limit / revocation) and its reasons come
// with it unchanged -- see Client.
package redisclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client wraps the Redis connection and its role-specific siblings.
//
// Client is the primary (session) instance: login/MFA/authcode state, email
// queue, leader locks, caches. RateLimit and Revocation are the two roles whose
// loss profile differs enough to deserve their own instance (see
// Config.RateLimitURL / RevocationURL). When a role URL is not configured
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
type Client struct {
	Client     *redis.Client
	RateLimit  *redis.Client
	Revocation *redis.Client
}

// RedisConfig holds configuration for creating a Redis client with optional
// Sentinel failover support and TLS.
type Config struct {
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
func buildTLSConfig(cfg Config) (*tls.Config, error) {
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
func NewFromConfig(cfg Config) (*Client, error) {
	tlsCfg, err := buildTLSConfig(cfg)
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
		return attachRoles(&Client{Client: client}, cfg, tlsCfg)
	}

	// Non-sentinel: parse URL and apply TLS
	primary, err := newWithTLS(cfg.URL, tlsCfg)
	if err != nil {
		return nil, err
	}
	return attachRoles(primary, cfg, tlsCfg)
}

// attachRedisRoles fills RateLimit and Revocation on a freshly built primary:
// a dedicated client when the role URL is set, the primary itself otherwise.
// A role instance that cannot be reached is a startup error, not a silent
// fallback to the primary — falling back would quietly recreate the shared
// instance the operator configured their way out of.
func attachRoles(primary *Client, cfg Config, tlsCfg *tls.Config) (*Client, error) {
	primary.RateLimit = primary.Client
	primary.Revocation = primary.Client
	if cfg.RateLimitURL != "" {
		rl, err := newWithTLS(cfg.RateLimitURL, tlsCfg)
		if err != nil {
			primary.Client.Close()
			return nil, fmt.Errorf("redis rate-limit role: %w", err)
		}
		primary.RateLimit = rl.Client
	}
	if cfg.RevocationURL != "" {
		rv, err := newWithTLS(cfg.RevocationURL, tlsCfg)
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
// NewFromConfig.
func NewWithRoles(primary, rateLimit, revocation *redis.Client) *Client {
	rc := &Client{Client: primary, RateLimit: primary, Revocation: primary}
	if rateLimit != nil {
		rc.RateLimit = rateLimit
	}
	if revocation != nil {
		rc.Revocation = revocation
	}
	return rc
}

// distinctClients returns each underlying client once, aliases collapsed.
func (r *Client) distinctClients() []*redis.Client {
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
func (r *Client) RateLimitDB() *redis.Client {
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
func (r *Client) RevocationDB() *redis.Client {
	if r == nil {
		return nil
	}
	if r.Revocation != nil {
		return r.Revocation
	}
	return r.Client
}

// PingContext verifies every distinct Redis instance is alive within ctx.
func (r *Client) PingContext(ctx context.Context) error {
	for _, c := range r.distinctClients() {
		if _, err := c.Ping(ctx).Result(); err != nil {
			return err
		}
	}
	return nil
}

// HasDedicatedRateLimit reports whether rate-limit counters live on their own
// instance rather than sharing the primary.
func (r *Client) HasDedicatedRateLimit() bool {
	return r.RateLimit != nil && r.RateLimit != r.Client
}

// HasDedicatedRevocation reports whether revocation markers live on their own
// instance rather than sharing the primary.
func (r *Client) HasDedicatedRevocation() bool {
	return r.Revocation != nil && r.Revocation != r.Client
}

// NewRedis creates a new Redis client (backward-compatible, no TLS)
func New(connString string) (*Client, error) {
	return newWithTLS(connString, nil)
}

// newRedisWithTLS creates a Redis client with optional TLS configuration
func newWithTLS(connString string, tlsCfg *tls.Config) (*Client, error) {
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

	return &Client{Client: client, RateLimit: client, Revocation: client}, nil
}

// Close closes every distinct underlying connection once.
func (r *Client) Close() error {
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
func (r *Client) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, c := range r.distinctClients() {
		if _, err := c.Ping(ctx).Result(); err != nil {
			return err
		}
	}
	return nil
}
