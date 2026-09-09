// Package oauth provides session policy management for OAuth sessions
package oauth

import (
	"context"
	"time"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/syssettings"
	"go.uber.org/zap"
)

// SessionPolicy defines the effective session policy for a client
type SessionPolicy struct {
	IdleTimeout               int    `json:"idle_timeout"`         // seconds, 0 = disabled
	AbsoluteTimeout           int    `json:"absolute_timeout"`     // seconds, 0 = disabled
	RememberMeDuration        int    `json:"remember_me_duration"` // seconds
	ReauthInterval            int    `json:"reauth_interval"`      // seconds, 0 = disabled
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

	// Load the console's settings document.
	//
	// This block read `WHERE key = 'settings'` until v1.34.0. Nothing has ever
	// written a system_settings row under that key -- the console reads and
	// writes the whole document under 'system' (seeded by migration 010) --
	// so the query returned no rows on every install that has ever run and
	// every value an operator set on the Security tab was silently discarded
	// in favour of the compiled-in defaults below. See internal/common/
	// syssettings, which is now the single reader of this table.
	if settings, err := syssettings.Load(ctx, s.db.Pool); err == nil {
		sec := settings.Security
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

	// Apply per-application overrides from application_sso_settings
	if clientID != "" {
		var (
			idleTimeout     *int
			absoluteTimeout *int
			maxConcurrent   *int
			concStrategy    *string
			bindIP          *bool
		)
		org, oerr := orgctx.From(ctx)
		var err error
		if oerr != nil {
			err = oerr
		} else {
			err = s.db.Pool.QueryRow(ctx, `
				SELECT ass.idle_timeout, ass.absolute_timeout, ass.max_concurrent_sessions,
				       ass.concurrent_session_strategy, ass.bind_ip
				FROM application_sso_settings ass
				JOIN applications a ON a.id = ass.application_id
				WHERE a.client_id = $1 AND a.org_id = $2
			`, clientID, org.ID).Scan(&idleTimeout, &absoluteTimeout, &maxConcurrent, &concStrategy, &bindIP)
		}
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

// revokeSessionWithRedis marks a session as revoked in both DB and Redis
func (s *Service) revokeSessionWithRedis(ctx context.Context, sessionID string) error {
	// Mark in database
	_, err := s.db.Pool.Exec(ctx,
		//orgscope:ignore revokes by globally-unique session id; reachable from the cross-org background session sweep
		`UPDATE sessions SET revoked = true, revoked_at = NOW() WHERE id = $1
	`, sessionID)
	if err != nil {
		return err
	}

	// Add to Redis revocation set (TTL = 25 hours to cover absolute timeout + buffer)
	s.redis.Client.Set(ctx, "revoked_session:"+sessionID, "1", 25*time.Hour)

	s.logger.Info("Session revoked", zap.String("session_id", sessionID))
	return nil
}
