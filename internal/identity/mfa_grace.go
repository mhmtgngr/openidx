package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// MFAGraceStart returns when userID's grace period under policyID began, and
// whether this call began it.
//
// A policy that requires particular methods gives a user with none of them its
// grace period to add one, counted from the first sign-in at which the policy
// found them without one (migration v203). The first call for a pair records
// that moment; every later call reads it back. The deadline is the start plus
// the policy's grace_period_hours, computed by the caller, so raising the
// grace period extends every window already running.
//
// Two statements rather than one upsert: the INSERT is a no-op on every sign-in
// after the first, and ON CONFLICT DO NOTHING writes nothing, where DO UPDATE
// would rewrite the row on every sign-in. A concurrent first sign-in that loses
// the race finds the winner's row with the SELECT, which runs on a fresh
// snapshot.
func (s *Service) MFAGraceStart(ctx context.Context, policyID, userID string) (time.Time, bool, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return time.Time{}, false, err
	}
	var started time.Time
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO mfa_policy_grace (org_id, policy_id, user_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (policy_id, user_id) DO NOTHING
		RETURNING started_at`, org.ID, policyID, userID).Scan(&started)
	if err == nil {
		return started, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, fmt.Errorf("record MFA grace start: %w", err)
	}
	err = s.db.Pool.QueryRow(ctx, `
		SELECT started_at FROM mfa_policy_grace
		 WHERE policy_id = $1 AND user_id = $2 AND org_id = $3`, policyID, userID, org.ID).Scan(&started)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("read MFA grace start: %w", err)
	}
	return started, false, nil
}
