package admin

import (
	"context"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/ssfsignal"
	"github.com/openidx/openidx/internal/revocation"
)

// revokeAfterSever cuts the access tokens a user is already holding, after this
// service has disabled or deleted their account.
//
// SEVERING AND REVOKING ARE TWO THINGS. Disabling or deleting the row stops the
// NEXT login. /oauth/userinfo and /oauth/introspect consult the per-user
// revocation marker and the per-token blacklist and nothing else, so the access
// token already in that browser keeps answering until it expires on its own --
// an hour by default, and as long as the client's configured lifetime allows.
//
// Best-effort by contract, like every other sever path in the product: the
// account is already disabled when this runs, so a Redis hiccup must not fail
// the request that did the severing. It is loud rather than silent, because
// "the tokens were not actually cut" is exactly what an operator needs in the
// record after an offboarding or a containment.
//
// why names the path, so a log line says which control left a live credential
// behind rather than only that one did.
// signalAfterSever enqueues the SSF `account-disabled` signal for a user this
// package has just disabled or deleted, so the receivers that subscribed to
// that event in /.well-known/ssf-configuration stop honouring the account.
//
// Same contract as revokeAfterSever: the sever has already happened when this
// runs, so a failure to enqueue must not fail the request, and it is loud
// because "the partners were never told" is what an operator needs to see.
// The row goes into ssf_pending_events on the handle the sever used; the
// oauth-service drainer signs and fans it out to every subscribed stream.
func (s *Service) signalAfterSever(ctx context.Context, orgID, userID, why string) {
	if s.db == nil || s.db.Pool == nil || userID == "" {
		return
	}
	if err := ssfsignal.Enqueue(ctx, s.db.Pool, ssfsignal.Signal{
		OrgID: orgID, SubjectID: userID, Claims: map[string]any{"reason": why},
	}); err != nil {
		s.logger.Error("account severed, but the account-disabled signal was not enqueued",
			zap.String("path", why), logsafe.String("user_id", userID), zap.Error(err))
	}
}

func (s *Service) revokeAfterSever(ctx context.Context, userID, why string) {
	if s.redis == nil || userID == "" {
		return
	}
	if err := revocation.RevokeUserTokens(ctx, s.redis.RevocationDB(), userID); err != nil {
		s.logger.Error("account severed, but its outstanding access tokens were not revoked",
			zap.String("path", why), logsafe.String("user_id", userID), zap.Error(err))
	}
}
