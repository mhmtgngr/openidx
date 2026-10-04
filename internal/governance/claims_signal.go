package governance

import (
	"context"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/ssfsignal"
)

// Telling the SSF receivers that a requester's token says something new
// (section 6.10 of the third-party access framework).
//
// A role or a group an access request gives is in every token issued while the
// requester holds it: oauth-service reads the "roles" and "groups" claims from
// user_roles and group_memberships when it issues one. So when one begins or
// ends, an application holding the requester's earlier token, or a session it
// made from one, is out of date, and nothing told it. Now the tenant's SSF
// receivers get a CAEP token-claims-change event:
//
//   - when the request is fulfilled (requestGranted), on approval or by
//     auto-approval;
//   - when its window ends (the expiry sweep).
//
// The event goes through internal/common/ssfsignal, the seam to the
// transmitter in oauth-service. This side names the requester and says why;
// the drainer reads the claims' new values when it signs.
//
// An elevation that ends with the account (the kill switch, deprovisioning, an
// external account's end) is told as the account's end, account-disabled or
// session-revoked, by the path that ends it.

// changesTokenClaims reports whether access of this type is in a token's
// claims. Only a role and a group are; an application, a PAM entry, a vault
// credential and a network service are each read where they are enforced.
// jitgrant.TokenCarries answers a different question, which tokens to cut, and
// answers yes for a type nobody classified; an event saying a claim changed
// when none did would be a false statement to every receiver.
func changesTokenClaims(resourceType string) bool {
	return resourceType == "role" || resourceType == "group"
}

// tokenClaimsChanged enqueues the event for the requester of a role or group
// request; access of any other type is not in the token, and nothing is
// enqueued. Best-effort, like the notifications beside it: the access has
// changed whether or not the receivers can be told, and a failure is logged.
func (s *Service) tokenClaimsChanged(ctx context.Context, orgID, requesterID, resourceType, why string) {
	if !changesTokenClaims(resourceType) {
		return
	}
	if err := ssfsignal.Enqueue(ctx, s.db.Pool, ssfsignal.Signal{
		OrgID: orgID, EventType: ssfsignal.TokenClaimsChange, SubjectID: requesterID,
		Claims: map[string]any{"reason": why},
	}); err != nil {
		s.logger.Error("the requester's token claims changed, but the SSF signal was not enqueued",
			logsafe.String("user_id", requesterID), zap.String("reason", why), zap.Error(err))
	}
}
