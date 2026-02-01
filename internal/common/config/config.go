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

	// Access Proxy settings
	GovernanceURL      string `mapstructure:"governance_url"`
	AuditURL           string `mapstructure:"audit_url"`
	AccessSessionSecret string `mapstructure:"access_session_secret"`
	AccessProxyDomain  string `mapstructure:"access_proxy_domain"`

	// OpenZiti configuration
	ZitiEnabled       bool   `mapstructure:"ziti_enabled"`
	ZitiCtrlURL       string `mapstructure:"ziti_ctrl_url"`
	ZitiAdminUser     string `mapstructure:"ziti_admin_user"`
	ZitiAdminPassword string `mapstructure:"ziti_admin_password"`
	ZitiIdentityDir   string `mapstructure:"ziti_identity_dir"`

	// Continuous verification
	ContinuousVerifyEnabled  bool   `mapstructure:"continuous_verify_enabled"`
	ContinuousVerifyInterval int    `mapstructure:"continuous_verify_interval"`

	// GeoIP service (optional)
	GeoIPServiceURL string `mapstructure:"geoip_service_url"`

	// Apache Guacamole integration
	GuacamoleURL           string `mapstructure:"guacamole_url"`
	GuacamoleAdminUser     string `mapstructure:"guacamole_admin_user"`
	GuacamoleAdminPassword string `mapstructure:"guacamole_admin_password"`

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
		"access-service":       8007,
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

	// OPA defaults
	v.SetDefault("opa_url", "http://localhost:8281")

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

	// Access Proxy defaults
	v.SetDefault("governance_url", "http://localhost:8002")
	v.SetDefault("audit_url", "http://localhost:8004")
	v.SetDefault("access_session_secret", "change-me-in-production-32bytes!")
	v.SetDefault("access_proxy_domain", "localhost")

	// OpenZiti defaults
	v.SetDefault("ziti_enabled", false)
	v.SetDefault("ziti_ctrl_url", "https://ziti-controller:1280")
	v.SetDefault("ziti_admin_user", "admin")
	v.SetDefault("ziti_admin_password", "openidx_ziti_admin")
	v.SetDefault("ziti_identity_dir", "/ziti")

	// Continuous verification defaults
	v.SetDefault("continuous_verify_enabled", false)
	v.SetDefault("continuous_verify_interval", 30)

	// Guacamole defaults
	v.SetDefault("guacamole_url", "")
	v.SetDefault("guacamole_admin_user", "guacadmin")
	v.SetDefault("guacamole_admin_password", "guacadmin")

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
		"opa_url":           "OPA_URL",
		"environment":       "APP_ENV",
		"log_level":         "LOG_LEVEL",
		"port":              "PORT",
		"oauth_issuer":      "OAUTH_ISSUER",
		"oauth_jwks_url":         "OAUTH_JWKS_URL",
		"governance_url":         "GOVERNANCE_URL",
		"audit_url":              "AUDIT_URL",
		"access_session_secret":  "ACCESS_SESSION_SECRET",
		"access_proxy_domain":    "ACCESS_PROXY_DOMAIN",
		"ziti_enabled":              "ZITI_ENABLED",
		"ziti_ctrl_url":             "ZITI_CTRL_URL",
		"ziti_admin_user":           "ZITI_ADMIN_USER",
		"ziti_admin_password":       "ZITI_ADMIN_PASSWORD",
		"ziti_identity_dir":         "ZITI_IDENTITY_DIR",
		"continuous_verify_enabled": "CONTINUOUS_VERIFY_ENABLED",
		"continuous_verify_interval":"CONTINUOUS_VERIFY_INTERVAL",
		"geoip_service_url":        "GEOIP_SERVICE_URL",
		"guacamole_url":            "GUACAMOLE_URL",
		"guacamole_admin_user":     "GUACAMOLE_ADMIN_USER",
		"guacamole_admin_password": "GUACAMOLE_ADMIN_PASSWORD",
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
