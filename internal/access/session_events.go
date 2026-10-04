package access

// The privileged-access events of section 6.10 of the third-party access
// framework, for a SIEM: pam.session.started when a PAM entry session is
// recorded, pam.session.ended with why when one ends, and pam.break_glass when
// an entry's credential is revealed by break-glass. They go to the tenant's
// webhook subscribers. The people involved are told through notifications
// where they are told at all: an external user's sponsor, at the start
// (sponsor_notify.go).
//
// Best-effort: a session starts and ends whether or not its event could be
// published, and a failure is logged. Each event is published under the
// session's own organization and no row-level-security bypass, whatever the
// caller's context held, so a sweep running across tenants reaches only that
// tenant's subscribers.

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/webhooks"
)

// WebhookPublisher is what the access service needs of internal/webhooks.
type WebhookPublisher interface {
	Publish(ctx context.Context, eventType string, payload interface{}) error
}

// SetWebhookPublisher wires the webhook service the privileged-access events
// go out through. Without it nothing is published.
func (s *Service) SetWebhookPublisher(w WebhookPublisher) { s.webhooks = w }

// Why a PAM entry session ended, as pam.session.ended says it.
const (
	sessionEndGrantEnded     = "grant_ended"      // the grant that let the user connect ended
	sessionEndMaxDuration    = "max_duration"     // an external user's session reached its maximum length
	sessionEndAccountOff     = "account_disabled" // the user was disabled or deleted
	sessionEndKillSwitch     = "kill_switch"      // an administrator's kill switch
	sessionEndSponsor        = "sponsor_ended"    // the external user's sponsor ended it
	sessionEndRiskSuspended  = "risk_suspended"   // the session risk scorer suspended it
	sessionEndTerminalClosed = "closed"           // the browser terminal closed
	sessionEndRequested      = "ended"            // someone asked for it to end; the event names who
	sessionEndModeration     = "moderation_ended" // the moderation that admitted it ended
)

// publishPamEvent publishes eventType to orgID's webhook subscribers, and
// nobody else's.
func (s *Service) publishPamEvent(orgID, eventType string, payload map[string]interface{}) {
	if s.webhooks == nil {
		return
	}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})
	if err := s.webhooks.Publish(ctx, eventType, payload); err != nil {
		s.logger.Warn("publish a privileged access event failed", zap.String("event", eventType), zap.Error(err))
	}
}

// pamSessionStarted publishes pam.session.started for a session just recorded.
func (s *Service) pamSessionStarted(orgID, sessionID, userID string, entry *pamLaunchEntry, protocol string, recorded bool) {
	s.publishPamEvent(orgID, webhooks.EventPamSessionStarted, map[string]interface{}{
		"session_id":   sessionID,
		"entry_id":     entry.ID,
		"entry_name":   entry.Name,
		"user_id":      userID,
		"protocol":     protocol,
		"external":     entry.External,
		"recorded":     recorded,
		"admin_bypass": adminBypassed(entry.AdminBypass),
	})
}

// pamSessionEnded publishes pam.session.ended for a session that just ended,
// with why and, when someone asked for it, who. It reads the session back for
// the rest, under its own organization.
func (s *Service) pamSessionEnded(orgID, sessionID, reason, actorID string) {
	if s.webhooks == nil {
		return
	}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})
	var entryID, entryName, userID string
	var external, recorded bool
	var startedAt time.Time
	var endedAt *time.Time
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT s.entry_id::text, e.name, COALESCE(s.user_id::text, ''),
		       COALESCE(u.user_type, '') = 'external', COALESCE(s.recording_path, '') <> '',
		       s.started_at, s.ended_at
		  FROM pam_entry_sessions s
		  JOIN pam_entries e ON e.id = s.entry_id AND e.org_id = s.org_id
		  LEFT JOIN users u ON u.id = s.user_id AND u.org_id = s.org_id
		 WHERE s.id = $1 AND s.org_id = $2`, sessionID, orgID).
		Scan(&entryID, &entryName, &userID, &external, &recorded, &startedAt, &endedAt); err != nil {
		s.logger.Warn("an ended session could not be read back to publish it",
			zap.String("session_id", logsafe.Clean(sessionID)), zap.Error(err))
		return
	}
	payload := map[string]interface{}{
		"session_id": sessionID,
		"entry_id":   entryID,
		"entry_name": entryName,
		"user_id":    userID,
		"external":   external,
		"recorded":   recorded,
		"reason":     reason,
		"started_at": startedAt.UTC(),
	}
	if endedAt != nil {
		payload["ended_at"] = endedAt.UTC()
	}
	if actorID != "" {
		payload["actor_id"] = actorID
	}
	s.publishPamEvent(orgID, webhooks.EventPamSessionEnded, payload)
}
