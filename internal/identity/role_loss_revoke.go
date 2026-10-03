package identity

import (
	"context"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/ssfsignal"
	"github.com/openidx/openidx/internal/revocation"
)

// claimsChanged tells the tenant's SSF receivers that what a token issued for
// these users says has changed: a role or a group was given to them or taken
// from them (CAEP token-claims-change). Unlike the token cut below, it goes in
// both directions: a downstream application that caches a user's roles is as
// out of date after a grant as after a removal, though only the removal is a
// security failure for this product's own enforcement point.
//
// The event goes through internal/common/ssfsignal; oauth-service's drainer
// reads the claims' new values when it signs. why names the path, and is the
// event's reason. Best-effort, like the marker: the change has been made, and
// a failure is logged.
func (s *Service) claimsChanged(ctx context.Context, why string, userIDs ...string) {
	if s.db == nil || s.db.Pool == nil {
		return
	}
	org, err := orgctx.From(ctx)
	if err != nil {
		s.logger.Error("a role or group changed, but the SSF signal has no organization to go to",
			zap.String("path", why), zap.Error(err))
		return
	}
	seen := make(map[string]struct{}, len(userIDs))
	for _, userID := range userIDs {
		if userID == "" {
			continue
		}
		if _, dup := seen[userID]; dup {
			continue
		}
		seen[userID] = struct{}{}
		s.claimsChangedIn(ctx, org.ID, why, userID)
	}
}

// claimsChangedIn is claimsChanged for one user of a named organization, for
// a caller that runs in none: the role-expiry sweep, which reads every
// organization's rows at once.
func (s *Service) claimsChangedIn(ctx context.Context, orgID, why, userID string) {
	if s.db == nil || s.db.Pool == nil {
		return
	}
	if err := ssfsignal.Enqueue(ctx, s.db.Pool, ssfsignal.Signal{
		OrgID: orgID, EventType: ssfsignal.TokenClaimsChange, SubjectID: userID,
		Claims: map[string]any{"reason": why},
	}); err != nil {
		s.logger.Error("a role or group changed, but the token-claims-change signal was not enqueued",
			zap.String("path", why), logsafe.String("user_id", userID), zap.Error(err))
	}
}

// revokeAfterRoleLoss cuts the outstanding tokens of users who have just LOST a
// role, and is deliberately not called when they have only gained one.
//
// WHY LOSING IS DIFFERENT FROM GAINING. The enforcement point takes the
// caller's role list from the JWT `roles` claim, not from `user_roles`
// (PermissionResolver, internal/common/middleware). So a role change reaches a
// live session only when the token is replaced:
//
//   - A GRANT that has not reached the token yet is a user who cannot do the
//     new thing until they sign in again. Mildly annoying, and not a control
//     failure -- nothing is permitted that should not be.
//   - A REVOCATION that has not reached the token is a user who keeps doing the
//     thing an administrator just stopped them doing, for the rest of that
//     token's life, while the API reports success and the audit log records it.
//
// The two are not symmetric, so cutting on every role write would be wrong in
// the cheap direction: it would end live sessions every time somebody was
// granted an extra role, for no security gain at all.
//
// Clearing the permission cache does not help and is not attempted here: that
// cache is keyed on (org, ROLE SET), and the entry a stale token resolves to is
// the entry every genuine holder of that role set resolves to. It is correct
// for them. What has to change is the token.
//
// Best-effort and loud, the contract every sever path in this product shares:
// the assignment is already gone from the database when this runs, so a Redis
// hiccup must not fail (or worse, retry) the administrative action -- but "the
// role was removed and the token carrying it was not cut" is what an operator
// needs in the record. why names the path, so the line says which control left
// a live credential.
func (s *Service) revokeAfterRoleLoss(ctx context.Context, why string, userIDs ...string) {
	// The receivers are told as well (claimsChanged), so every path that takes
	// a role or a group away through here tells them.
	s.claimsChanged(ctx, why, userIDs...)
	seen := make(map[string]struct{}, len(userIDs))
	for _, userID := range userIDs {
		if userID == "" {
			continue
		}
		// The marker is per user, not per assignment: one user losing three
		// roles in one call is revoked once.
		if _, dup := seen[userID]; dup {
			continue
		}
		seen[userID] = struct{}{}

		if err := revocation.RevokeUserTokens(ctx, s.redis.RevocationDB(), userID); err != nil {
			s.logger.Error("a role was removed, but the tokens still carrying it were not revoked",
				zap.String("path", why), logsafe.String("user_id", userID), zap.Error(err))
		}
	}
}

// lostRoles returns the ids in previous that are not in next.
//
// A wholesale role replacement is BOTH a grant and a revocation, and only the
// revocation half needs a token cut. Computing the difference is what keeps a
// pure addition from ending the user's session.
func lostRoles(previous, next []string) []string {
	keep := make(map[string]struct{}, len(next))
	for _, id := range next {
		keep[id] = struct{}{}
	}
	var lost []string
	for _, id := range previous {
		if _, still := keep[id]; !still {
			lost = append(lost, id)
		}
	}
	return lost
}
