package config

import "go.uber.org/zap"

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
