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
	OPAURL        string `mapstructure:"opa_url"`
	EnableOPAAuthz bool  `mapstructure:"enable_opa_authz"`

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
	ZitiIdentityDir        string `mapstructure:"ziti_identity_dir"`
	ZitiInsecureSkipVerify bool   `mapstructure:"ziti_insecure_skip_verify"`

	// Continuous verification
	ContinuousVerifyEnabled  bool   `mapstructure:"continuous_verify_enabled"`
	ContinuousVerifyInterval int    `mapstructure:"continuous_verify_interval"`

	// GeoIP service (optional)
	GeoIPServiceURL string `mapstructure:"geoip_service_url"`

	// Apache Guacamole integration
	GuacamoleURL           string `mapstructure:"guacamole_url"`
	GuacamoleAdminUser     string `mapstructure:"guacamole_admin_user"`
	GuacamoleAdminPassword string `mapstructure:"guacamole_admin_password"`

	// BrowZer configuration (browser-native Ziti participation)
	BrowZerEnabled  bool   `mapstructure:"browzer_enabled"`
	BrowZerClientID string `mapstructure:"browzer_client_id"`

	// WebAuthn configuration
	WebAuthn WebAuthnConfig `mapstructure:"webauthn"`

	// Push MFA configuration
	PushMFA PushMFAConfig `mapstructure:"push_mfa"`

	// SMS MFA configuration
	SMS SMSConfig `mapstructure:"sms"`

	// Adaptive MFA / Risk-based authentication
	AdaptiveMFA AdaptiveMFAConfig `mapstructure:"adaptive_mfa"`
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

// SMSConfig holds SMS MFA configuration
type SMSConfig struct {
	Enabled       bool   `mapstructure:"enabled"`         // Enable SMS MFA
	Provider      string `mapstructure:"provider"`        // twilio, aws_sns, webhook, mock
	TwilioSID     string `mapstructure:"twilio_sid"`      // Twilio Account SID
	TwilioToken   string `mapstructure:"twilio_token"`    // Twilio Auth Token
	TwilioFrom    string `mapstructure:"twilio_from"`     // Twilio From Number
	AWSRegion     string `mapstructure:"aws_region"`      // AWS Region for SNS
	AWSAccessKey  string `mapstructure:"aws_access_key"`  // AWS Access Key (optional, uses IAM role if empty)
	AWSSecretKey  string `mapstructure:"aws_secret_key"`  // AWS Secret Key (optional, uses IAM role if empty)
	WebhookURL    string `mapstructure:"webhook_url"`     // Custom webhook URL for SMS delivery
	WebhookAPIKey string `mapstructure:"webhook_api_key"` // API key for webhook authentication
	MessagePrefix string `mapstructure:"message_prefix"`  // Prefix for OTP messages (default: "OpenIDX")
	OTPLength     int    `mapstructure:"otp_length"`      // Length of OTP code (default: 6)
	OTPExpiry     int    `mapstructure:"otp_expiry"`      // OTP expiry in seconds (default: 300)
	MaxAttempts   int    `mapstructure:"max_attempts"`    // Max verification attempts (default: 3)
}

// AdaptiveMFAConfig holds adaptive/risk-based MFA configuration
type AdaptiveMFAConfig struct {
	Enabled                  bool `mapstructure:"enabled"`                     // Enable adaptive MFA
	NewDeviceRiskScore       int  `mapstructure:"new_device_risk_score"`       // Risk score for new device (default: 30)
	NewLocationRiskScore     int  `mapstructure:"new_location_risk_score"`     // Risk score for new location (default: 20)
	ImpossibleTravelRiskScore int `mapstructure:"impossible_travel_risk_score"` // Risk score for impossible travel (default: 50)
	BlockedIPRiskScore       int  `mapstructure:"blocked_ip_risk_score"`       // Risk score for blocked IP (default: 40)
	FailedLoginRiskScore     int  `mapstructure:"failed_login_risk_score"`     // Risk score per recent failed login (default: 10)
	TrustedBrowserDays       int  `mapstructure:"trusted_browser_days"`        // Days to trust a browser (default: 30)
	LowRiskThreshold         int  `mapstructure:"low_risk_threshold"`          // Below this: skip MFA (default: 30)
	MediumRiskThreshold      int  `mapstructure:"medium_risk_threshold"`       // Below this: standard MFA (default: 50)
	HighRiskThreshold        int  `mapstructure:"high_risk_threshold"`         // Below this: strong MFA (default: 70)
	// Above high_risk_threshold: step-up auth + admin notification
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
	v.SetDefault("enable_opa_authz", false)

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
	v.SetDefault("ziti_insecure_skip_verify", false)

	// Continuous verification defaults
	v.SetDefault("continuous_verify_enabled", false)
	v.SetDefault("continuous_verify_interval", 30)

	// Guacamole defaults
	v.SetDefault("guacamole_url", "")
	v.SetDefault("guacamole_admin_user", "guacadmin")
	v.SetDefault("guacamole_admin_password", "guacadmin")

	// BrowZer defaults
	v.SetDefault("browzer_enabled", false)
	v.SetDefault("browzer_client_id", "browzer-client")

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

	// SMS MFA defaults
	v.SetDefault("sms.enabled", false)
	v.SetDefault("sms.provider", "mock")
	v.SetDefault("sms.message_prefix", "OpenIDX")
	v.SetDefault("sms.otp_length", 6)
	v.SetDefault("sms.otp_expiry", 300)
	v.SetDefault("sms.max_attempts", 3)

	// Adaptive MFA defaults
	v.SetDefault("adaptive_mfa.enabled", true)
	v.SetDefault("adaptive_mfa.new_device_risk_score", 30)
	v.SetDefault("adaptive_mfa.new_location_risk_score", 20)
	v.SetDefault("adaptive_mfa.impossible_travel_risk_score", 50)
	v.SetDefault("adaptive_mfa.blocked_ip_risk_score", 40)
	v.SetDefault("adaptive_mfa.failed_login_risk_score", 10)
	v.SetDefault("adaptive_mfa.trusted_browser_days", 30)
	v.SetDefault("adaptive_mfa.low_risk_threshold", 30)
	v.SetDefault("adaptive_mfa.medium_risk_threshold", 50)
	v.SetDefault("adaptive_mfa.high_risk_threshold", 70)
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
		"ziti_identity_dir":            "ZITI_IDENTITY_DIR",
		"ziti_insecure_skip_verify":    "ZITI_INSECURE_SKIP_VERIFY",
		"continuous_verify_enabled": "CONTINUOUS_VERIFY_ENABLED",
		"continuous_verify_interval":"CONTINUOUS_VERIFY_INTERVAL",
		"geoip_service_url":        "GEOIP_SERVICE_URL",
		"guacamole_url":            "GUACAMOLE_URL",
		"guacamole_admin_user":     "GUACAMOLE_ADMIN_USER",
		"guacamole_admin_password": "GUACAMOLE_ADMIN_PASSWORD",
		"browzer_enabled":          "BROWZER_ENABLED",
		"browzer_client_id":        "BROWZER_CLIENT_ID",
		"enable_opa_authz":         "ENABLE_OPA_AUTHZ",
		"jwt_secret":               "JWT_SECRET",
		"encryption_key":           "ENCRYPTION_KEY",
		"smtp_host":                "SMTP_HOST",
		"smtp_port":                "SMTP_PORT",
		"smtp_username":            "SMTP_USERNAME",
		"smtp_password":            "SMTP_PASSWORD",
		"smtp_from":                "SMTP_FROM",
		"sms.enabled":              "SMS_ENABLED",
		"sms.provider":             "SMS_PROVIDER",
		"sms.twilio_sid":           "TWILIO_ACCOUNT_SID",
		"sms.twilio_token":         "TWILIO_AUTH_TOKEN",
		"sms.twilio_from":          "TWILIO_FROM_NUMBER",
		"sms.aws_region":           "AWS_REGION",
		"sms.aws_access_key":       "AWS_ACCESS_KEY_ID",
		"sms.aws_secret_key":       "AWS_SECRET_ACCESS_KEY",
		"sms.webhook_url":          "SMS_WEBHOOK_URL",
		"sms.webhook_api_key":      "SMS_WEBHOOK_API_KEY",
		"adaptive_mfa.enabled":     "ADAPTIVE_MFA_ENABLED",
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

// ProductionWarnings returns a list of configuration issues that should be
// addressed before deploying to production. Returns nil if no issues found.
func (c *Config) ProductionWarnings() []string {
	if !c.IsProduction() {
		return nil
	}
	var warnings []string
	if c.JWTSecret == "" || strings.Contains(strings.ToLower(c.JWTSecret), "change") {
		warnings = append(warnings, "jwt_secret uses a default or placeholder value")
	}
	if c.EncryptionKey == "" || strings.Contains(strings.ToLower(c.EncryptionKey), "change") {
		warnings = append(warnings, "encryption_key uses a default or placeholder value")
	}
	if strings.Contains(c.AccessSessionSecret, "change-me") {
		warnings = append(warnings, "access_session_secret uses the default placeholder")
	}
	if c.CORSAllowedOrigins == "*" {
		warnings = append(warnings, "cors_allowed_origins is wildcard '*'; set specific origins for production")
	}
	return warnings
}
