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
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// PostgresDB wraps the pgx connection pool
type PostgresDB struct {
	Pool *pgxpool.Pool
}

// PostgresTLSConfig holds TLS configuration for PostgreSQL connections
type PostgresTLSConfig struct {
	SSLMode     string // disable, require, verify-ca, verify-full
	SSLRootCert string // Path to CA certificate
	SSLCert     string // Path to client certificate (mTLS)
	SSLKey      string // Path to client private key (mTLS)
}

// NewPostgres creates a new PostgreSQL connection pool.
// An optional PostgresTLSConfig can be provided to configure SSL parameters.
func NewPostgres(connString string, tlsCfg ...PostgresTLSConfig) (*PostgresDB, error) {
	// Apply TLS config to connection string if provided
	if len(tlsCfg) > 0 {
		connString = applyPostgresTLS(connString, tlsCfg[0])
	}

	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Connection pool settings
	config.MaxConns = 25
	config.MinConns = 5
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 30 * time.Minute
	config.HealthCheckPeriod = time.Minute

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

	return &PostgresDB{Pool: pool}, nil
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
	db.Pool.Close()
	return nil
}

// Ping verifies the database connection is alive
func (db *PostgresDB) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return db.Pool.Ping(ctx)
}

// RedisClient wraps the Redis client
type RedisClient struct {
	Client *redis.Client
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
		return &RedisClient{Client: client}, nil
	}

	// Non-sentinel: parse URL and apply TLS
	return newRedisWithTLS(cfg.URL, tlsCfg)
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

	return &RedisClient{Client: client}, nil
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	return r.Client.Close()
}

// Ping verifies the Redis connection is alive
func (r *RedisClient) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := r.Client.Ping(ctx).Result()
	return err
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

	// Test connectivity
	res, err := client.Ping()
	if err != nil {
		return nil, fmt.Errorf("failed to ping elasticsearch: %w", err)
	}
	res.Body.Close()

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
