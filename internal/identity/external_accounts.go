package identity

import (
	"context"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// suspendSponsoredExternals suspends the live external (vendor) users that
// sponsorID answers for, because sponsorID is leaving: deleted, or disabled.
//
// The framework's decision D5: a departing sponsor suspends their external
// users rather than disabling them, so a new sponsor can take them over within
// the grace period, and a suspended account cannot sign in. Each account goes
// to 'suspended' with users.enabled false in one statement (the v214 CHECK
// refuses an enabled external account that is not live), and is then
// deprovisioned exactly as an administrator's disable deprovisions an
// account: sessions with their revocation markers, API keys, vault checkouts
// and grants, JIT elevations.
//
// DeleteUser calls it before removing the sponsor's row: the sponsor_user_id
// foreign key sets the column NULL on delete, which the v214 CHECK refuses
// for a live account, so a delete that skipped this would fail rather than
// leave a live external user with nobody answering for them. UpdateUser calls
// it when an administrator disables the sponsor. The other writers that
// disable accounts (directory sync, lifecycle policies, the kill switch) are
// covered by the external-account sweep.
//
// Returns the suspended user ids. Best-effort after the UPDATE, like
// deprovisionUser: a failure to revoke one class is logged, not fatal.
func (s *Service) suspendSponsoredExternals(ctx context.Context, orgID, sponsorID, reason string) ([]string, error) {
	if s.db == nil || s.db.Pool == nil {
		return nil, nil
	}
	rows, err := s.db.Pool.Query(ctx, `
		UPDATE users
		   SET account_status = 'suspended', enabled = false, status_changed_at = NOW(), updated_at = NOW()
		 WHERE sponsor_user_id = $1::uuid AND org_id = $2 AND user_type = 'external'
		   AND account_status IN ('invited', 'pending_mfa', 'active')
		RETURNING id::text`, sponsorID, orgID)
	if err != nil {
		return nil, err
	}
	var suspended []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		suspended = append(suspended, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	actor := actorIDFromContext(ctx)
	for _, id := range suspended {
		s.deprovisionUser(ctx, id, orgID, false)
		if _, err := s.db.Pool.Exec(ctx,
			`UPDATE users SET access_severed_at = NOW() WHERE id = $1::uuid AND org_id = $2`, id, orgID); err != nil {
			s.logger.Warn("could not record the severing of a suspended external user",
				zap.String("user_id", logsafe.Clean(id)), zap.Error(err))
		}
		s.logAuditEvent(ctx, "identity", "external_access", "external.suspended", "success", actor, id, "user",
			map[string]interface{}{"sponsor_user_id": sponsorID, "reason": reason})
	}
	return suspended, nil
}
