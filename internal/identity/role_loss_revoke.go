package identity

import (
	"context"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/revocation"
)

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
