package access

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/externalid"
	"github.com/openidx/openidx/internal/notifications"
)

// notifySponsorOfLaunchRequest tells an external (vendor) user's sponsor that
// the user asked for a launch approval on an entry, which the sponsor is the
// one to give (section 5.6 of the third-party access framework). Nothing for
// anyone who is not external. Best-effort: a failure is logged and the request
// stands, since the sponsor's queue lists it either way.
func (s *Service) notifySponsorOfLaunchRequest(ctx context.Context, orgID, userID, entryID, requestID, reason string) {
	acct, err := externalid.Load(ctx, s.db.Pool, orgID, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return
	}
	if err != nil {
		s.logger.Warn("notify sponsor: could not read the requester's account", zap.Error(err))
		return
	}
	if !acct.External() || acct.SponsorUserID == "" {
		return
	}
	var who, entryName string
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(NULLIF(u.email, ''), u.username), e.name
		  FROM users u, pam_entries e
		 WHERE u.id = $1::uuid AND u.org_id = $3 AND e.id = $2::uuid AND e.org_id = $3`,
		userID, entryID, orgID).Scan(&who, &entryName); err != nil {
		s.logger.Warn("notify sponsor: could not read the request's names", zap.Error(err))
		return
	}
	body := fmt.Sprintf("%s asks to open a privileged session on %s.", who, entryName)
	if reason != "" {
		body += " Reason: " + reason
	}
	if err := notifications.NewService(s.db, s.logger).CreateMultiChannelNotification(ctx,
		acct.SponsorUserID, orgID, notifications.TypeSponsoredAccess,
		"A vendor user you sponsor is waiting for your approval", body, "",
		map[string]interface{}{"request_id": requestID, "entry_id": entryID, "user_id": userID, "kind": "pam_launch_request"}); err != nil {
		s.logger.Warn("notify sponsor failed", zap.String("sponsor_id", acct.SponsorUserID), zap.Error(err))
	}
}

// notifySponsorOfModeration tells an external (vendor) user's sponsor that the
// user is waiting for a moderator on an entry that requires one, which the
// sponsor may be (entry_moderation.go). Best-effort: the request stands, and
// the sponsor's moderation queue lists it either way.
func (s *Service) notifySponsorOfModeration(ctx context.Context, orgID, userID, entryID, entryName, moderationID string) {
	acct, err := externalid.Load(ctx, s.db.Pool, orgID, userID)
	if err != nil {
		s.logger.Warn("notify sponsor of a moderation request: could not read the requester's account", zap.Error(err))
		return
	}
	if !acct.External() || acct.SponsorUserID == "" {
		return
	}
	var who string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(NULLIF(email, ''), username) FROM users WHERE id = $1::uuid AND org_id = $2`,
		userID, orgID).Scan(&who); err != nil {
		s.logger.Warn("notify sponsor of a moderation request: could not read the user's name", zap.Error(err))
		return
	}
	if err := notifications.NewService(s.db, s.logger).CreateMultiChannelNotification(ctx,
		acct.SponsorUserID, orgID, notifications.TypeSponsoredAccess,
		"A vendor user you sponsor is waiting for a moderator",
		fmt.Sprintf("%s wants to open a moderated session on %s. Join to watch it, and it can start.", who, entryName), "",
		map[string]interface{}{"moderation_id": moderationID, "entry_id": entryID, "user_id": userID, "kind": "moderation_requested"}); err != nil {
		s.logger.Warn("notify sponsor of a moderation request failed", zap.String("sponsor_id", acct.SponsorUserID), zap.Error(err))
	}
}

// notifySponsorOfSession tells an external (vendor) user's sponsor that the
// user's privileged session on entry started (invariant I6 of the third-party
// access framework), and stamps the session's sponsor_notified_at once the
// notification is written. A sponsor who switched the notification type off is
// not told, and the row says so by staying NULL. Best-effort: the session is
// already running, and a failure here is logged rather than ending it.
func (s *Service) notifySponsorOfSession(ctx context.Context, orgID, userID string, entry *pamLaunchEntry, sessionID string) {
	acct, err := externalid.Load(ctx, s.db.Pool, orgID, userID)
	if err != nil {
		s.logger.Warn("notify sponsor of a session: could not read the user's account", zap.Error(err))
		return
	}
	if !acct.External() || acct.SponsorUserID == "" {
		return
	}
	notif := notifications.NewService(s.db, s.logger)
	if !notif.Enabled(ctx, acct.SponsorUserID, "in_app", notifications.TypeSponsoredAccess) {
		return
	}
	var who string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT COALESCE(NULLIF(email, ''), username) FROM users WHERE id = $1::uuid AND org_id = $2`,
		userID, orgID).Scan(&who); err != nil {
		s.logger.Warn("notify sponsor of a session: could not read the user's name", zap.Error(err))
		return
	}
	if err := notif.CreateMultiChannelNotification(ctx, acct.SponsorUserID, orgID, notifications.TypeSponsoredAccess,
		"A vendor user you sponsor started a privileged session",
		fmt.Sprintf("%s opened a recorded session on %s. You can watch it or end it.", who, entry.Name), "",
		map[string]interface{}{"session_id": sessionID, "entry_id": entry.ID, "user_id": userID, "kind": "pam_session_started"}); err != nil {
		s.logger.Warn("notify sponsor of a session failed", zap.String("sponsor_id", acct.SponsorUserID), zap.Error(err))
		return
	}
	if _, err := s.db.Pool.Exec(ctx,
		`UPDATE pam_entry_sessions SET sponsor_notified_at = NOW() WHERE id = $1 AND org_id = $2`, sessionID, orgID); err != nil {
		s.logger.Warn("notify sponsor of a session: could not record it on the session", zap.Error(err))
	}
}
