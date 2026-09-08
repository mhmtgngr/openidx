package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Who may answer a push-MFA challenge, and from what device.
//
// The number-matching prompt is the last thing standing between a stolen
// password and a session, and VerifyPushMFAChallenge checked three things about
// it: that the challenge existed, that it had not expired, and that the two
// digits matched. Nothing about the caller, and nothing about the device.
//
// THE CALLER. POST /api/v1/identity/mfa/push/verify sits on the authenticated
// identity group, and isIdentitySelfService lets any authenticated user through
// anything under /mfa/ -- "the caller's own MFA enrollment/verification", says
// the comment. The handler read challenge_id and challenge_code from the body
// and passed them on. It never compared the challenge's user to the caller, so
// the sentence in that comment was not true of this route: any authenticated
// user who held a challenge id could answer somebody else's prompt.
//
// THE ATTEMPTS. A wrong code returned an error and left the challenge pending,
// so the two-digit match (10-99, ninety values) could be tried until it hit.
// A number match with unlimited attempts is not a number match.
//
// THE DEVICE. An admin revoking a phone (POST /users/:id/devices/:agentId/revoke)
// deletes its overlay identity, untrusts it and -- since v185 -- revokes the
// tokens it holds. Its push registration was untouched, so the revoked phone
// stayed on the approver list and could still approve. The push row has carried
// agent_id since v135; nothing read it.

// pushApprovalAttemptLimit is how many wrong number-matches a challenge
// tolerates before it is denied outright. Three, because the user is copying a
// number off the screen in front of them: a mis-tap is ordinary, a third one is
// not.
const pushApprovalAttemptLimit = 3

// ErrPushChallengeNotYours is returned when the caller is not the user the
// challenge was raised for.
var ErrPushChallengeNotYours = errors.New("this challenge belongs to another user")

// ErrPushDeviceNotApprovable is returned when the device the challenge was sent
// to may no longer answer for its user.
var ErrPushDeviceNotApprovable = errors.New("this device may no longer approve sign-ins")

// approvingDeviceUsable reports whether the device a challenge was delivered to
// is still allowed to answer it.
//
// Two questions, both about state the server owns:
//
//	the push row     still enabled? (a disabled registration is one the user or
//	                 an admin has switched off)
//	the agent row    if this push device was registered by a device enrolment
//	                 (v135 linkage), the enrolled agent must still be active --
//	                 a revoked one is a phone an admin has taken off the fleet,
//	                 and a pending one has not yet been let on.
//
// A self-enrolled authenticator carries no agent_id and is judged on the push
// row alone: that is the ordinary TOTP-app-shaped case and it must keep working.
func (s *Service) approvingDeviceUsable(ctx context.Context, deviceID string) (bool, string, error) {
	if s.db == nil || s.db.Pool == nil || deviceID == "" {
		// No database to consult (unit-test shape): no basis to refuse.
		return true, "", nil
	}

	var enabled bool
	var agentID string
	err := s.db.Pool.QueryRow(ctx, `
		SELECT enabled, COALESCE(agent_id, '')
		  FROM mfa_push_devices WHERE id = $1`, deviceID).Scan(&enabled, &agentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The registration is gone (deleted while the prompt was in flight).
			return false, "the device registration no longer exists", nil
		}
		return false, "", err
	}
	if !enabled {
		return false, "the device registration is disabled", nil
	}
	if agentID == "" {
		return true, "", nil
	}

	var status string
	//orgscope:ignore enrolled_agents is an install-wide fleet table with no org_id; keyed here by the globally-unique agent_id already recorded on this user's own push device
	err = s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx), `
		SELECT COALESCE(status, '') FROM enrolled_agents WHERE agent_id = $1`, agentID).Scan(&status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The push row names an agent the fleet no longer has. Refusing is
			// the safe reading: the enrolment that vouched for this approver is
			// gone.
			return false, "the enrolled device this approver belongs to no longer exists", nil
		}
		return false, "", err
	}
	switch status {
	case "active":
		return true, "", nil
	case "revoked":
		return false, "the enrolled device has been revoked", nil
	default:
		// pending, suspended, or anything an operator adds later: not active,
		// so not an approver. Named in the reason so the log says which.
		return false, "the enrolled device is not active (" + status + ")", nil
	}
}

// pushAttemptKey is the Redis counter for wrong number-matches on one challenge.
func pushAttemptKey(challengeID string) string {
	return "push_mfa_attempts:" + challengeID
}

// registerFailedPushAttempt counts a wrong number-match and reports whether the
// challenge has run out of attempts.
//
// With no Redis -- not configured, or unreachable -- the first wrong code is
// the last: strictness is the safe direction here, and it costs an honest user
// a fresh prompt rather than costing everyone the ability to sign in. It is
// never the other way round, because "the counter is unavailable" must not read
// as "unlimited guesses".
func (s *Service) registerFailedPushAttempt(ctx context.Context, challenge *PushMFAChallenge) bool {
	if s.redis == nil || s.redis.Client == nil {
		return true
	}
	key := pushAttemptKey(challenge.ID)
	n, err := s.redis.Client.Incr(ctx, key).Result()
	if err != nil {
		s.logger.Warn("push MFA: attempt counter unavailable; treating this wrong code as final",
			zap.String("challenge_id", logsafe.Clean(challenge.ID)), zap.Error(err))
		return true
	}
	if n == 1 {
		// Live only as long as the challenge can be answered.
		ttl := time.Until(challenge.ExpiresAt)
		if ttl < time.Minute {
			ttl = time.Minute
		}
		if err := s.redis.Client.Expire(ctx, key, ttl).Err(); err != nil {
			s.logger.Warn("push MFA: could not bound the attempt counter's lifetime",
				zap.String("challenge_id", logsafe.Clean(challenge.ID)), zap.Error(err))
		}
	}
	return n >= pushApprovalAttemptLimit
}

// denyChallengeForFailedAttempts burns a challenge that has been guessed at too
// often, so the guessing has somewhere to stop.
func (s *Service) denyChallengeForFailedAttempts(ctx context.Context, challenge *PushMFAChallenge) {
	now := time.Now()
	challenge.RespondedAt = &now
	challenge.Status = "denied"
	if err := s.updatePushChallenge(ctx, challenge); err != nil {
		s.logger.Error("push MFA: failed to deny a challenge after too many wrong codes",
			zap.String("challenge_id", logsafe.Clean(challenge.ID)), zap.Error(err))
	}
	s.logger.Warn("SECURITY: push MFA challenge denied after repeated wrong number-matches",
		zap.String("challenge_id", logsafe.Clean(challenge.ID)),
		zap.String("user_id", logsafe.Clean(challenge.UserID)),
		zap.Int("attempt_limit", pushApprovalAttemptLimit))
}

// pushChallengeBelongsTo reports whether callerUserID may answer this challenge.
// An empty caller is refused: the route is authenticated, so an empty subject
// means the token carried none and there is nothing to compare.
func pushChallengeBelongsTo(challenge *PushMFAChallenge, callerUserID string) error {
	if callerUserID == "" {
		return fmt.Errorf("%w: no authenticated user on the request", ErrPushChallengeNotYours)
	}
	if challenge.UserID != callerUserID {
		return ErrPushChallengeNotYours
	}
	return nil
}
