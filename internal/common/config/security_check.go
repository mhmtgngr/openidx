package config

import "go.uber.org/zap"

// ValidateProductionConfig performs critical security validation for production
// deployments. This MUST be called at service startup after configuration is loaded.
// Returns an error if any critical security issues are found, preventing server startup.
func ValidateProductionConfig(cfg *Config, log *zap.Logger) error {
	if !cfg.IsProduction() {
		return nil
	}

	if err := cfg.ValidateProduction(); err != nil {
		log.Error("SECURITY: Production validation failed - server startup blocked",
			zap.Error(err))
		return err
	}

	log.Info("SECURITY: Production configuration validated successfully")
	return nil
}

// LogSecurityWarnings logs actionable security warnings when running in
// production with insecure defaults. Call this at service startup after
// configuration is loaded.
func (c *Config) LogSecurityWarnings(log *zap.Logger) {
	if !c.IsProduction() {
		return
	}

	warnings := c.ProductionWarnings()

	for _, w := range warnings {
		log.Warn("SECURITY", zap.String("warning", w))
	}

	if len(warnings) > 0 {
		log.Warn("SECURITY: production deployment has insecure configuration",
			zap.Int("warning_count", len(warnings)))
	}
}
