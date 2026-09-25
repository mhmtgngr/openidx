// Package oauth provides session policy management for OAuth sessions
package oauth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/syssettings"
)

// SessionPolicy defines the effective session policy for a client
type SessionPolicy struct {
	IdleTimeout               int    `json:"idle_timeout"`         // seconds, 0 = disabled
	AbsoluteTimeout           int    `json:"absolute_timeout"`     // seconds, 0 = disabled
	RememberMeDuration        int    `json:"remember_me_duration"` // seconds
	ReauthInterval            int    `json:"reauth_interval"`      // seconds, 0 = disabled
	BindSessionToIP           bool   `json:"bind_session_to_ip"`
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

// revokeSessionWithRedis ends one session: the refresh tokens bound to it are
// revoked, the row is marked revoked, the revoked_session marker is published
// and the relying parties the session reached are told. The expiry and
// inactivity sweeps, the concurrent-session eviction, force-login,
// /oauth/logout, logout-all and the SSF receiver all end sessions here.
func (s *Service) revokeSessionWithRedis(ctx context.Context, sessionID string) error {
	// What the session can still mint ends first, in the database. This used
	// to mark the row and write the marker, and leave the refresh tokens as
	// they were. The refresh grant did not read the row then, and the marker
	// lives 25 hours, so a device that came back after a day refreshed as if
	// the session had never ended; a native client keeps its refresh token
	// for 14 to 30 days. The grant now also checks the row (sessionIsLive);
	// the tokens are revoked here all the same, so the record says what
	// happened. If they cannot be revoked the row is left live, so the sweep
	// that called this tries again on its next tick rather than recording an
	// end that did not happen.
	if _, err := s.revokeSessionRefreshTokens(ctx, sessionID); err != nil {
		return err
	}

	// Mark in database
	_, err := s.db.Pool.Exec(ctx,
		//orgscope:ignore revokes by globally-unique session id; reachable from the cross-org background session sweep
		`UPDATE sessions SET revoked = true, revoked_at = NOW() WHERE id = $1
	`, sessionID)
	if err != nil {
		return err
	}

	// Add to Redis revocation set (TTL = 25 hours to cover absolute timeout +
	// buffer). The rows above are what hold after it expires; while it lives
	// it also stops a refresh that was already in flight when they were
	// revoked.
	s.redis.RevocationDB().Set(ctx, "revoked_session:"+sessionID, "1", 25*time.Hour)

	s.logger.Info("Session revoked", zap.String("session_id", sessionID))

	// Every relying party the session reached is told, from here, because
	// this is the one place a session stops being live (backchannel_logout.go).
	s.notifyBackchannelLogout(sessionID)
	return nil
}

// sessionIsLive reports whether sessionID names a session of the request's
// organization whose row exists, is not revoked and has not expired. The
// refresh grant asks it of every token bound to a session.
//
// The paths that end a session revoke the refresh tokens bound to it, and the
// marker in Redis stands in front of that. Neither covers a session that ended
// before those paths revoked anything -- its marker expired long ago -- nor a
// session that ended in a way nobody wrote down, like reaching its expiry
// between two sweeps, nor a future path that forgets. The session row is the
// record all of them share, so the grant reads it.
//
// An id that is not a UUID cannot name a session row: not live, and no query.
// An error means the question could not be answered, and the caller mints
// nothing.
func (s *Service) sessionIsLive(ctx context.Context, sessionID string) (bool, error) {
	if _, err := uuid.Parse(sessionID); err != nil {
		return false, nil
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		return false, err
	}
	var live bool
	err = s.db.Pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM sessions
			 WHERE id = $1::uuid AND org_id = $2
			   AND COALESCE(revoked, false) = false AND expires_at > NOW())`,
		sessionID, org.ID).Scan(&live)
	if err != nil {
		return false, err
	}
	return live, nil
}

// revokeSessionRefreshTokens revokes, in the database, every refresh token
// bound to sessionID, and reports how many. Keyed by the globally-unique
// session id alone, like the row update in revokeSessionWithRedis, because the
// sweeps that end sessions run across every organization with no tenant on the
// context. A request's context still carries its tenant's scope.
func (s *Service) revokeSessionRefreshTokens(ctx context.Context, sessionID string) (int64, error) {
	tag, err := s.db.Pool.Exec(ctx,
		//orgscope:ignore revokes by globally-unique session id; reachable from the cross-org background session sweep
		`UPDATE oauth_refresh_tokens SET revoked_at = NOW() WHERE session_id = $1 AND revoked_at IS NULL`,
		sessionID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
