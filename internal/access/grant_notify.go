package access

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/notifications"
)

// notifyPamGrant tells the granted user (or every member of a granted group)
// that they now have access to a PAM entry. Best-effort: logged, never fatal,
// and never notifies for role grants (roles expand dynamically; audit covers
// them). Mirrors the app-grant notification in the portal service.
func (s *Service) notifyPamGrant(ctx context.Context, orgID, entryID, principalType, principalID string) {
	recipients, err := s.grantRecipientUserIDs(ctx, orgID, principalType, principalID)
	if err != nil {
		s.logger.Warn("notify pam grant: resolve recipients failed", zap.Error(err))
		return
	}
	if len(recipients) == 0 {
		return
	}

	var entryName string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT name FROM pam_entries WHERE id = $1 AND org_id = $2`, entryID, orgID,
	).Scan(&entryName); err != nil {
		s.logger.Warn("notify pam grant: entry lookup failed", zap.Error(err))
		return
	}

	notif := notifications.NewService(s.db, s.logger)
	body := fmt.Sprintf("You've been granted access to %s.", entryName)
	for _, uid := range recipients {
		if err := notif.CreateMultiChannelNotification(ctx, uid, orgID, notifications.TypeAccessGranted,
			"New access granted", body, "/my-network",
			map[string]interface{}{"resource": entryName, "kind": "pam_entry"}); err != nil {
			s.logger.Warn("notify pam grant failed", zap.String("user_id", uid), zap.Error(err))
		}
	}
}

// notifyPamLaunchDecision tells the requester of a launch request what was
// decided, under the request_update type their access requests use (section
// 6.10 of the third-party access framework). Before, a requester learned of
// the decision by trying again. Best-effort: the decision stands either way.
func (s *Service) notifyPamLaunchDecision(ctx context.Context, orgID, requestID, status string) {
	var requesterID, entryName string
	if err := s.db.Pool.QueryRow(ctx, `
		SELECT r.requester_id::text, e.name
		  FROM pam_entry_access_requests r
		  JOIN pam_entries e ON e.id = r.entry_id AND e.org_id = r.org_id
		 WHERE r.id = $1 AND r.org_id = $2`, requestID, orgID).Scan(&requesterID, &entryName); err != nil {
		s.logger.Warn("notify a launch decision: could not read the request", zap.Error(err))
		return
	}
	title, body, kind := "Your session request was approved",
		fmt.Sprintf("You can now open a session on %s.", entryName), "launch_approved"
	if status != "approved" {
		title, body, kind = "Your session request was denied",
			fmt.Sprintf("Your request to open a session on %s was denied.", entryName), "launch_denied"
	}
	if err := notifications.NewService(s.db, s.logger).CreateMultiChannelNotification(ctx, requesterID, orgID,
		notifications.TypeRequestUpdate, title, body, "/my-network",
		map[string]interface{}{"request_id": requestID, "kind": kind}); err != nil {
		s.logger.Warn("notify a launch decision failed", zap.String("user_id", requesterID), zap.Error(err))
	}
}

// grantRecipientUserIDs resolves a grant principal to the user IDs to notify: a
// user is itself; a group expands to its members; a role notifies no one (role
// membership is dynamic — the grant is still audited).
func (s *Service) grantRecipientUserIDs(ctx context.Context, orgID, principalType, principalID string) ([]string, error) {
	switch principalType {
	case "user":
		return []string{principalID}, nil
	case "group":
		rows, err := s.db.Pool.Query(ctx,
			`SELECT user_id::text FROM group_memberships WHERE group_id = $1 AND org_id = $2`,
			principalID, orgID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		ids := []string{}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		return ids, rows.Err()
	default:
		return nil, nil
	}
}
