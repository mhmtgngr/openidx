package config

import (
	"testing"
)

func TestIsProduction(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"production", true},
		{"prod", true},
		{"development", false},
		{"dev", false},
		{"staging", false},
		{"", false},
	}

	for _, tt := range tests {
		cfg := &Config{Environment: tt.env}
		if got := cfg.IsProduction(); got != tt.want {
			t.Errorf("IsProduction() with env=%q = %v, want %v", tt.env, got, tt.want)
		}
	}
}

func TestProductionWarnings_DevMode(t *testing.T) {
	cfg := &Config{Environment: "development"}
	warnings := cfg.ProductionWarnings()
	if warnings != nil {
		t.Error("expected nil warnings in development mode")
	}
}

func TestProductionWarnings_InsecureConfig(t *testing.T) {
	cfg := &Config{
		Environment:         "production",
		JWTSecret:           "CHANGE_ME_jwt_secret",
		EncryptionKey:       "CHANGE_ME_key",
		AccessSessionSecret: "change-me-session",
		CORSAllowedOrigins:  "*",
		CSRFEnabled:         false,
		DatabaseSSLMode:     "disable",
		RedisTLSEnabled:     false,
		TLS:                 TLSConfig{Enabled: false},
	}

	warnings := cfg.ProductionWarnings()
	if len(warnings) == 0 {
		t.Error("expected warnings for insecure production config")
	}

	// Should have warnings for each insecure setting
	if len(warnings) < 5 {
		t.Errorf("expected at least 5 warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestProductionWarnings_SecureConfig(t *testing.T) {
	cfg := &Config{
		Environment:         "production",
		JWTSecret:           "a-very-secure-random-jwt-secret-value",
		EncryptionKey:       "a-very-secure-random-encryption-key!",
		AccessSessionSecret: "a-very-secure-random-session-secret!",
		CORSAllowedOrigins:  "https://admin.openidx.io",
		CSRFEnabled:         true,
		DatabaseSSLMode:     "verify-full",
		RedisTLSEnabled:     true,
		TLS:                 TLSConfig{Enabled: true},
	}

	warnings := cfg.ProductionWarnings()
	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings for secure config, got %d: %v", len(warnings), warnings)
	}
}

func TestValidateProduction_DevMode(t *testing.T) {
	cfg := &Config{Environment: "development"}
	if err := cfg.ValidateProduction(); err != nil {
		t.Errorf("ValidateProduction should pass in dev mode, got: %v", err)
	}
}

func TestValidateProduction_InsecureConfig(t *testing.T) {
	cfg := &Config{
		Environment:         "production",
		JWTSecret:           "",
		EncryptionKey:       "",
		AccessSessionSecret: "change-me",
		CORSAllowedOrigins:  "*",
		CSRFEnabled:         false,
		DatabaseSSLMode:     "disable",
		RedisTLSEnabled:     false,
	}

	err := cfg.ValidateProduction()
	if err == nil {
		t.Error("expected error for insecure production config")
	}
}

func TestValidateProduction_SecureConfig(t *testing.T) {
	cfg := &Config{
		Environment:         "production",
		JWTSecret:           "a-very-secure-random-jwt-secret-value",
		EncryptionKey:       "a-very-secure-random-encryption-key!",
		AccessSessionSecret: "a-very-secure-random-session-secret!",
		CORSAllowedOrigins:  "https://admin.openidx.io",
		CSRFEnabled:         true,
		DatabaseSSLMode:     "verify-full",
		RedisTLSEnabled:     true,
		TLS:                 TLSConfig{Enabled: true},
	}

	err := cfg.ValidateProduction()
	if err != nil {
		t.Errorf("expected no error for secure production config, got: %v", err)
	}
}

func TestTLSConfig(t *testing.T) {
	tlsCfg := TLSConfig{
		Enabled:  true,
		CertFile: "/path/to/cert.pem",
		KeyFile:  "/path/to/key.pem",
		CAFile:   "/path/to/ca.pem",
	}

	if !tlsCfg.Enabled {
		t.Error("expected Enabled=true")
	}
	if tlsCfg.CertFile != "/path/to/cert.pem" {
		t.Errorf("expected CertFile=/path/to/cert.pem, got %s", tlsCfg.CertFile)
	}
}
