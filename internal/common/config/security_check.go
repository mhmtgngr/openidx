package config

import "go.uber.org/zap"

// ValidateProductionConfig performs critical security validation for production
// deployments. This MUST be called at service startup after configuration is loaded.
// Returns an error if any critical security issues are found, preventing server startup.
func ValidateProductionConfig(cfg *Config, log *zap.Logger) error {
	// Before anything environment-specific: a setting the operator set and
	// this build does not read. Reported everywhere, because development is
	// where someone tries a switch and needs to hear that it does nothing.
	for _, s := range RetiredSettingsInUse() {
		log.Warn("CONFIG: retired setting", zap.String("detail", s))
	}

	// The authorization controls that are configured but not deciding. Reported
	// everywhere for the same reason as the line above, and it is the stronger
	// case of the two: someone writes an ABAC deny policy, tests it, watches it
	// permit the request, and there is nothing anywhere that says the gate is in
	// report mode. Production gets Warn because an operator should have to look
	// at it; everything else gets Info because report-mode IS the designed
	// default there and a warning nobody can act on is a warning people learn to
	// skip.
	//
	// This is Config.ReportModeGates's only caller, and until v1.34.0 it had
	// none: the function existed, its own test proved it named every open
	// control, and no running process ever asked it. A list of every
	// authorization control that is switched off, which nothing displays, is the
	// defect this branch is about, one layer above the gates it describes.
	logReportModeGates(cfg, log)

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

// logReportModeGates writes one line per authorization control that is not
// enforcing, plus a summary line carrying the count.
//
// The summary exists because the per-gate lines are what an operator reads and
// the count is what a log query can alert on; without it "how many controls are
// open" is a grep over free text. It is emitted even at zero, so a dashboard can
// tell "fully enforcing" from "this build never reported".
func logReportModeGates(c *Config, log *zap.Logger) {
	open := c.ReportModeGates()
	write := log.Info
	if c.IsProduction() {
		write = log.Warn
	}
	for _, gate := range open {
		write("AUTHZ: control not enforcing", zap.String("gate", gate))
	}
	write("AUTHZ: report-mode summary",
		zap.Int("open_gates", len(open)),
		zap.Bool("fully_enforcing", len(open) == 0))
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
