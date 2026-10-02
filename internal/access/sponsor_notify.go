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
