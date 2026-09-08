package identity

import (
	"context"
	"encoding/json"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/sms"
)

// StartSMSConfigWatcher polls the system_settings table for SMS config changes
// and hot-swaps the SMS provider when a change is detected.
// This allows admin console settings changes to take effect without restarting the identity service.
func (s *Service) StartSMSConfigWatcher(ctx context.Context, interval time.Duration) {
	ctx = orgctx.WithBypassRLS(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastUpdatedAt time.Time

	s.logger.Info("SMS config watcher started", zap.Duration("interval", interval))

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("SMS config watcher stopped")
			return
		case <-ticker.C:
			s.checkAndReloadSMSConfig(ctx, &lastUpdatedAt)
		}
	}
}

func (s *Service) checkAndReloadSMSConfig(ctx context.Context, lastUpdatedAt *time.Time) {
	var updatedAt time.Time
	var valueBytes []byte

	err := s.db.Pool.QueryRow(ctx,
		"SELECT value, updated_at FROM system_settings WHERE key = 'sms_config'",
	).Scan(&valueBytes, &updatedAt)

	if err != nil {
		// No DB config row — keep using the env-var-based config set at startup
		return
	}

	if !updatedAt.After(*lastUpdatedAt) {
		// No change since last check
		return
	}

	*lastUpdatedAt = updatedAt

	var settings sms.DBSMSSettings
	if err := json.Unmarshal(valueBytes, &settings); err != nil {
		s.logger.Error("Failed to parse SMS config from database", zap.Error(err))
		return
	}

	// The OTP settings are the other half of this row, and nothing read them:
	// createOTPChallenge took DefaultOTPConfig() unconditionally, so an
	// administrator setting an eight-digit code saw it saved, clamped and read
	// back while every code the product sent stayed six digits.
	//
	// Applied before the provider is built, because they do not depend on it: a
	// row whose credentials no longer construct a provider is still the row that
	// says how long a code lives. Clamped here as well as at the write, because
	// a row stored before ValidateOTPSettings existed can still be in the table.
	sms.ValidateOTPSettings(&settings)
	s.SetOTPSettings(settings.OTPLength, settings.OTPExpiry, settings.MaxAttempts)

	cfg := settings.ToConfig()
	// The admin console can store provider "mock"; that must not become a live
	// provider outside development any more than an env var can.
	cfg.AllowMock = s.cfg != nil && s.cfg.IsDevelopment()

	newService, err := sms.NewService(cfg, s.logger)
	if err != nil {
		s.logger.Error("Failed to create SMS service from database config", zap.Error(err))
		return
	}

	s.SetSMSProvider(newService)
	s.logger.Info("SMS provider reloaded from database config",
		zap.String("provider", settings.Provider),
		zap.Bool("enabled", settings.Enabled),
		zap.Int("otp_length", settings.OTPLength),
		zap.Int("otp_expiry_seconds", settings.OTPExpiry),
		zap.Int("max_attempts", settings.MaxAttempts))
}
