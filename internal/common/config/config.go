// Package config provides configuration management for OpenIDX services
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	// Service identification
	ServiceName string `mapstructure:"service_name"`
	Environment string `mapstructure:"environment"`
	Port        int    `mapstructure:"port"`
	LogLevel    string `mapstructure:"log_level"`

	// Database connections
	DatabaseURL      string `mapstructure:"database_url"`
	RedisURL         string `mapstructure:"redis_url"`
	ElasticsearchURL string `mapstructure:"elasticsearch_url"`

	// Keycloak configuration
	KeycloakURL      string `mapstructure:"keycloak_url"`
	KeycloakRealm    string `mapstructure:"keycloak_realm"`
	KeycloakClientID string `mapstructure:"keycloak_client_id"`
	KeycloakSecret   string `mapstructure:"keycloak_secret"`

	// OPA configuration
	OPAURL string `mapstructure:"opa_url"`

	// OAuth / OIDC settings
	OAuthIssuer  string `mapstructure:"oauth_issuer"`
	OAuthJWKSURL string `mapstructure:"oauth_jwks_url"`

	// Security settings
	JWTSecret          string `mapstructure:"jwt_secret"`
	EncryptionKey      string `mapstructure:"encryption_key"`
	CORSAllowedOrigins string `mapstructure:"cors_allowed_origins"`

	// Feature flags
	EnableMFA          bool `mapstructure:"enable_mfa"`
	EnableAuditLogging bool `mapstructure:"enable_audit_logging"`
	EnableRateLimit    bool `mapstructure:"enable_rate_limit"`

	// Rate limiting
	RateLimitRequests int `mapstructure:"rate_limit_requests"`
	RateLimitWindow   int `mapstructure:"rate_limit_window"`

	// SMTP configuration (for email notifications)
	SMTPHost     string `mapstructure:"smtp_host"`
	SMTPPort     int    `mapstructure:"smtp_port"`
	SMTPUsername string `mapstructure:"smtp_username"`
	SMTPPassword string `mapstructure:"smtp_password"`
	SMTPFrom     string `mapstructure:"smtp_from"`

	// WebAuthn configuration
	WebAuthn WebAuthnConfig `mapstructure:"webauthn"`

	// Push MFA configuration
	PushMFA PushMFAConfig `mapstructure:"push_mfa"`
}

// WebAuthnConfig holds WebAuthn/FIDO2 configuration
type WebAuthnConfig struct {
	RPID      string   `mapstructure:"rp_id"`       // Relying Party ID (e.g., "example.com")
	RPOrigins []string `mapstructure:"rp_origins"`  // Allowed origins
	Timeout   int      `mapstructure:"timeout"`     // Timeout in seconds (default: 60)
}

// PushMFAConfig holds Push MFA configuration
type PushMFAConfig struct {
	Enabled          bool   `mapstructure:"enabled"`
	FCMServerKey     string `mapstructure:"fcm_server_key"`      // Firebase Cloud Messaging server key
	APNSKeyID        string `mapstructure:"apns_key_id"`         // Apple Push Notification Service key ID
	APNSTeamID       string `mapstructure:"apns_team_id"`        // Apple team ID
	APNSKeyPath      string `mapstructure:"apns_key_path"`       // Path to APNS .p8 key file
	APNSBundleID     string `mapstructure:"apns_bundle_id"`      // APNS bundle identifier (e.g., "com.openidx.app")
	ChallengeTimeout int    `mapstructure:"challenge_timeout"`   // Timeout in seconds (default: 60)
	AutoApprove      bool   `mapstructure:"auto_approve"`        // Auto-approve for development (NEVER use in production)
}

// Load reads configuration from file and environment variables
func Load(serviceName string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v, serviceName)

	// Read from config file
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./configs")
	v.AddConfigPath("/etc/openidx")

	// Read config file (optional)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	// Read from environment variables
	v.SetEnvPrefix("OPENIDX")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// Also support non-prefixed env vars for common settings
	bindEnvVars(v)

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	cfg.ServiceName = serviceName

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper, serviceName string) {
	// Service defaults
	v.SetDefault("environment", "development")
	v.SetDefault("log_level", "info")

	// Port defaults per service
	ports := map[string]int{
		"identity-service":     8001,
		"governance-service":   8002,
		"provisioning-service": 8003,
		"audit-service":        8004,
		"admin-api":            8005,
		"gateway-service":      8006,
	}
	if port, ok := ports[serviceName]; ok {
		v.SetDefault("port", port)
	} else {
		v.SetDefault("port", 8080)
	}

	// Database defaults
	v.SetDefault("database_url", "postgres://openidx:openidx_secret@localhost:5432/openidx?sslmode=disable")
	v.SetDefault("redis_url", "redis://:redis_secret@localhost:6379")
	v.SetDefault("elasticsearch_url", "http://localhost:9200")

	// Keycloak defaults
	v.SetDefault("keycloak_url", "http://localhost:8180")
	v.SetDefault("keycloak_realm", "openidx")
	v.SetDefault("keycloak_client_id", "openidx-api")

	// OPA defaults
	v.SetDefault("opa_url", "http://localhost:8181")

	// Feature flag defaults
	v.SetDefault("enable_mfa", true)
	v.SetDefault("enable_audit_logging", true)
	v.SetDefault("enable_rate_limit", true)

	// Rate limiting defaults
	v.SetDefault("rate_limit_requests", 100)
	v.SetDefault("rate_limit_window", 60)

	// OAuth / OIDC defaults
	v.SetDefault("oauth_issuer", "http://localhost:8006")
	v.SetDefault("oauth_jwks_url", "http://localhost:8006/.well-known/jwks.json")

	// CORS defaults
	v.SetDefault("cors_allowed_origins", "*")

	// WebAuthn defaults
	v.SetDefault("webauthn.rp_id", "localhost")
	v.SetDefault("webauthn.rp_origins", []string{"http://localhost:3000", "http://localhost:8080"})
	v.SetDefault("webauthn.timeout", 60)

	// Push MFA defaults
	v.SetDefault("push_mfa.enabled", true)
	v.SetDefault("push_mfa.challenge_timeout", 60)
	v.SetDefault("push_mfa.auto_approve", false)
}

func bindEnvVars(v *viper.Viper) {
	// Common environment variable mappings
	envMappings := map[string]string{
		"database_url":      "DATABASE_URL",
		"redis_url":         "REDIS_URL",
		"elasticsearch_url": "ELASTICSEARCH_URL",
		"keycloak_url":      "KEYCLOAK_URL",
		"opa_url":           "OPA_URL",
		"environment":       "APP_ENV",
		"log_level":         "LOG_LEVEL",
		"port":              "PORT",
		"oauth_issuer":      "OAUTH_ISSUER",
		"oauth_jwks_url":    "OAUTH_JWKS_URL",
	}

	for key, env := range envMappings {
		v.BindEnv(key, env)
	}
}

func validate(cfg *Config) error {
	if cfg.DatabaseURL == "" {
		return fmt.Errorf("database_url is required")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

// GetCORSOrigins returns CORS allowed origins as a slice
func (c *Config) GetCORSOrigins() []string {
	if c.CORSAllowedOrigins == "*" {
		return []string{"*"}
	}
	return strings.Split(c.CORSAllowedOrigins, ",")
}

// IsDevelopment returns true if running in development mode
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development" || c.Environment == "dev"
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return c.Environment == "production" || c.Environment == "prod"
}
