// Package gateway provides API gateway functionality for OpenIDX
package gateway

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds gateway-specific configuration
type Config struct {
	// Server configuration
	Port int `mapstructure:"port"`

	// Service endpoints
	Services map[string]string `mapstructure:"services"`

	// JWT validation
	JWKSURL string `mapstructure:"jwks_url"`

	// Rate limiting
	EnableRateLimit bool          `mapstructure:"enable_rate_limit"`
	RateLimitConfig RateLimitConfig `mapstructure:"rate_limit"`

	// CORS
	AllowedOrigins []string `mapstructure:"allowed_origins"`

	// Timeouts
	RequestTimeout  time.Duration `mapstructure:"request_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`

	// Dependencies (injected, not from config)
	Redis          RedisClient
	Logger         Logger
	TracerShutdown TracerShutdownFunc
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	RequestsPerMinute   int `mapstructure:"requests_per_minute"`
	AuthRequestsPerMinute int `mapstructure:"auth_requests_per_minute"`
	WindowSeconds       int `mapstructure:"window_seconds"`
	BurstSize           int `mapstructure:"burst_size"`
}

// DefaultConfig returns default configuration values
func DefaultConfig() Config {
	return Config{
		Port: 8500,
		Services: map[string]string{
			"identity":   "http://localhost:8501",
			"oauth":      "http://localhost:8502",
			"governance": "http://localhost:8503",
			"audit":      "http://localhost:8504",
			"admin":      "http://localhost:8505",
			"risk":       "http://localhost:8506",
		},
		JWKSURL:         "http://localhost:8502/.well-known/jwks.json",
		EnableRateLimit: true,
		RateLimitConfig: RateLimitConfig{
			RequestsPerMinute:     100,
			AuthRequestsPerMinute: 20,
			WindowSeconds:         60,
			BurstSize:             10,
		},
		AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:5173"},
		RequestTimeout:   30 * time.Second,
		ShutdownTimeout:  30 * time.Second,
	}
}

// LoadConfig loads gateway configuration from environment variables
func LoadConfig() (Config, error) {
	cfg := DefaultConfig()

	// Override from environment
	if port := os.Getenv("GATEWAY_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			cfg.Port = p
		}
	}

	if jwks := os.Getenv("OAUTH_JWKS_URL"); jwks != "" {
		cfg.JWKSURL = jwks
	}

	// Load service URLs from environment
	services := []string{"identity", "oauth", "governance", "audit", "admin", "risk"}
	for _, svc := range services {
		envKey := fmt.Sprintf("%s_SERVICE_URL", strings.ToUpper(svc))
		if url := os.Getenv(envKey); url != "" {
			if cfg.Services == nil {
				cfg.Services = make(map[string]string)
			}
			cfg.Services[svc] = url
		}
	}

	if origins := os.Getenv("CORS_ALLOWED_ORIGINS"); origins != "" {
		cfg.AllowedOrigins = strings.Split(origins, ",")
	}

	if enabled := os.Getenv("ENABLE_RATE_LIMIT"); enabled != "" {
		cfg.EnableRateLimit = enabled == "true" || enabled == "1"
	}

	return cfg, nil
}

// LoadConfigWithViper loads configuration using Viper
func LoadConfigWithViper(v *viper.Viper) (Config, error) {
	cfg := DefaultConfig()

	if v.IsSet("port") {
		cfg.Port = v.GetInt("port")
	}

	if v.IsSet("jwks_url") {
		cfg.JWKSURL = v.GetString("jwks_url")
	}

	if v.IsSet("services") {
		cfg.Services = v.GetStringMapString("services")
	}

	if v.IsSet("enable_rate_limit") {
		cfg.EnableRateLimit = v.GetBool("enable_rate_limit")
	}

	if v.IsSet("rate_limit.requests_per_minute") {
		cfg.RateLimitConfig.RequestsPerMinute = v.GetInt("rate_limit.requests_per_minute")
	}

	if v.IsSet("rate_limit.auth_requests_per_minute") {
		cfg.RateLimitConfig.AuthRequestsPerMinute = v.GetInt("rate_limit.auth_requests_per_minute")
	}

	if v.IsSet("rate_limit.window_seconds") {
		cfg.RateLimitConfig.WindowSeconds = v.GetInt("rate_limit.window_seconds")
	}

	if v.IsSet("rate_limit.burst_size") {
		cfg.RateLimitConfig.BurstSize = v.GetInt("rate_limit.burst_size")
	}

	if v.IsSet("allowed_origins") {
		cfg.AllowedOrigins = v.GetStringSlice("allowed_origins")
	}

	if v.IsSet("request_timeout") {
		cfg.RequestTimeout = v.GetDuration("request_timeout")
	}

	return cfg, nil
}

// GetServiceURL returns the URL for a given service name
func (c *Config) GetServiceURL(serviceName string) (string, error) {
	if url, ok := c.Services[serviceName]; ok {
		return url, nil
	}
	return "", fmt.Errorf("service %s not found in configuration", serviceName)
}

// GetJWTConfig returns JWT validation configuration
func (c *Config) GetJWTConfig() (jwksURL string, enabled bool) {
	return c.JWKSURL, c.JWKSURL != ""
}

// GetRateLimitConfig returns rate limiting configuration
func (c *Config) GetRateLimitConfig() RateLimitConfig {
	return c.RateLimitConfig
}

// IsRateLimitEnabled returns true if rate limiting is enabled
func (c *Config) IsRateLimitEnabled() bool {
	return c.EnableRateLimit
}

// GetAllowedOrigins returns the list of allowed CORS origins
func (c *Config) GetAllowedOrigins() []string {
	if len(c.AllowedOrigins) == 0 {
		return []string{"*"}
	}
	return c.AllowedOrigins
}

// RedisClient defines the Redis client interface
type RedisClient interface {
	Get(ctx interface{}, key string) *RedisStringCmd
	Set(ctx interface{}, key string, value interface{}, expiration time.Duration) *RedisStatusCmd
	Incr(ctx interface{}, key string) *RedisIntCmd
	Expire(ctx interface{}, key string, expiration time.Duration) *RedisBoolCmd
	Pipeline() RedisPipeline
	Close() error
}

// RedisStringCmd mimics redis.StringCmd
type RedisStringCmd struct {
	Val string
	Err error
}

// RedisStatusCmd mimics redis.StatusCmd
type RedisStatusCmd struct {
	Val string
	Err error
}

// RedisIntCmd mimics redis.IntCmd
type RedisIntCmd struct {
	Val int64
	Err error
}

// RedisBoolCmd mimics redis.BoolCmd
type RedisBoolCmd struct {
	Val bool
	Err error
}

// RedisPipeline defines the pipeline interface for Redis
type RedisPipeline interface {
Exec() ([]interface{}, error)
}

// Logger defines the logging interface
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Fatal(msg string, fields ...interface{})
	Sync() error
}

// TracerShutdownFunc represents a tracer shutdown function
type TracerShutdownFunc func(ctx interface{}) error
