// Package oauth provides session policy management for OAuth sessions
package oauth

import (
	"context"
	"encoding/json"
	"time"

	"go.uber.org/zap"
)

// SessionPolicy defines the effective session policy for a client
type SessionPolicy struct {
	IdleTimeout               int    `json:"idle_timeout"`                // seconds, 0 = disabled
	AbsoluteTimeout           int    `json:"absolute_timeout"`            // seconds, 0 = disabled
	RememberMeDuration        int    `json:"remember_me_duration"`        // seconds
	ReauthInterval            int    `json:"reauth_interval"`             // seconds, 0 = disabled
	BindSessionToIP           bool   `json:"bind_session_to_ip"`
	ForceLogoutOnPwdChange    bool   `json:"force_logout_on_password_change"`
	MaxConcurrentSessions     int    `json:"max_concurrent_sessions"`     // 0 = unlimited
	ConcurrentSessionStrategy string `json:"concurrent_session_strategy"` // deny_new, terminate_oldest, prompt_user
}

// DefaultSessionPolicy returns the system-wide default session policy
func DefaultSessionPolicy() SessionPolicy {
	return SessionPolicy{
		IdleTimeout:               1800,    // 30 minutes
		AbsoluteTimeout:           86400,   // 24 hours
		RememberMeDuration:        2592000, // 30 days
		ReauthInterval:            0,       // disabled
		BindSessionToIP:           false,
		ForceLogoutOnPwdChange:    true,
		MaxConcurrentSessions:     0, // unlimited
		ConcurrentSessionStrategy: "deny_new",
	}
}

// getEffectiveSessionPolicy loads the session policy for a given client.
// It starts from global admin settings and applies per-application overrides.
func (s *Service) getEffectiveSessionPolicy(ctx context.Context, clientID string) SessionPolicy {
	policy := DefaultSessionPolicy()

	// Load global settings from system_settings
	var settingsJSON string
	err := s.db.Pool.QueryRow(ctx,
		"SELECT value::text FROM system_settings WHERE key = 'settings'").Scan(&settingsJSON)
	if err == nil && settingsJSON != "" {
		var allSettings struct {
			Security struct {
				IdleTimeout               int    `json:"idle_timeout"`
				AbsoluteTimeout           int    `json:"absolute_timeout"`
				RememberMeDuration        int    `json:"remember_me_duration"`
				ReauthInterval            int    `json:"reauth_interval"`
				BindSessionToIP           bool   `json:"bind_session_to_ip"`
				ForceLogoutOnPwdChange    bool   `json:"force_logout_on_password_change"`
				MaxConcurrentSessions     int    `json:"max_concurrent_sessions"`
				ConcurrentSessionStrategy string `json:"concurrent_session_strategy"`
			} `json:"security"`
		}
		if jsonErr := json.Unmarshal([]byte(settingsJSON), &allSettings); jsonErr == nil {
			sec := allSettings.Security
			if sec.IdleTimeout > 0 {
				policy.IdleTimeout = sec.IdleTimeout
			}
			if sec.AbsoluteTimeout > 0 {
				policy.AbsoluteTimeout = sec.AbsoluteTimeout
			}
			if sec.RememberMeDuration > 0 {
				policy.RememberMeDuration = sec.RememberMeDuration
			}
			if sec.ReauthInterval > 0 {
				policy.ReauthInterval = sec.ReauthInterval
			}
			policy.BindSessionToIP = sec.BindSessionToIP
			policy.ForceLogoutOnPwdChange = sec.ForceLogoutOnPwdChange
			if sec.MaxConcurrentSessions > 0 {
				policy.MaxConcurrentSessions = sec.MaxConcurrentSessions
			}
			if sec.ConcurrentSessionStrategy != "" {
				policy.ConcurrentSessionStrategy = sec.ConcurrentSessionStrategy
			}
		}
	}

	// Apply per-application overrides from application_sso_settings
	if clientID != "" {
		var (
			idleTimeout     *int
			absoluteTimeout *int
			maxConcurrent   *int
			concStrategy    *string
			bindIP          *bool
		)
		err := s.db.Pool.QueryRow(ctx, `
			SELECT ass.idle_timeout, ass.absolute_timeout, ass.max_concurrent_sessions,
			       ass.concurrent_session_strategy, ass.bind_ip
			FROM application_sso_settings ass
			JOIN applications a ON a.id = ass.application_id
			WHERE a.client_id = $1
		`, clientID).Scan(&idleTimeout, &absoluteTimeout, &maxConcurrent, &concStrategy, &bindIP)
		if err == nil {
			if idleTimeout != nil && *idleTimeout > 0 {
				policy.IdleTimeout = *idleTimeout
			}
			if absoluteTimeout != nil && *absoluteTimeout > 0 {
				policy.AbsoluteTimeout = *absoluteTimeout
			}
			if maxConcurrent != nil && *maxConcurrent > 0 {
				policy.MaxConcurrentSessions = *maxConcurrent
			}
			if concStrategy != nil && *concStrategy != "" {
				policy.ConcurrentSessionStrategy = *concStrategy
			}
			if bindIP != nil {
				policy.BindSessionToIP = *bindIP
			}
		}
	}

	return policy
}

// isSessionIdle checks if a session has exceeded the idle timeout
func (s *Service) isSessionIdle(lastSeenAt time.Time, policy SessionPolicy) bool {
	if policy.IdleTimeout <= 0 {
		return false
	}
	return time.Since(lastSeenAt) > time.Duration(policy.IdleTimeout)*time.Second
}

// isSessionExpiredAbsolute checks if a session has exceeded the absolute timeout
func (s *Service) isSessionExpiredAbsolute(startedAt time.Time, policy SessionPolicy) bool {
	if policy.AbsoluteTimeout <= 0 {
		return false
	}
	return time.Since(startedAt) > time.Duration(policy.AbsoluteTimeout)*time.Second
}

// revokeSessionWithRedis marks a session as revoked in both DB and Redis
func (s *Service) revokeSessionWithRedis(ctx context.Context, sessionID string) error {
	// Mark in database
	_, err := s.db.Pool.Exec(ctx, `
		UPDATE sessions SET revoked = true, revoked_at = NOW() WHERE id = $1
	`, sessionID)
	if err != nil {
		return err
	}

	// Add to Redis revocation set (TTL = 25 hours to cover absolute timeout + buffer)
	s.redis.Client.Set(ctx, "revoked_session:"+sessionID, "1", 25*time.Hour)

	s.logger.Info("Session revoked", zap.String("session_id", sessionID))
	return nil
}
