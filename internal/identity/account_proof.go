package identity

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
)

// RequireSignInMethodProof is requireFactorProof(changesSignInMethod) for a
// route another service mounts: POST /oauth/social/link/:provider_id/start,
// which the oauth-service authenticates itself. It reads the proof from the
// request's JSON body (current_password, or totp_code) and, when the account
// has a password or a second factor, checks it as a factor change is checked
// -- a wrong password counts against the sign-in lockout and a code is spent.
// It answers a refusal itself (403, reauthentication_*) and returns false;
// true means the request may go on.
func (s *Service) RequireSignInMethodProof(c *gin.Context, userID string) bool {
	if c.GetString("user_id") == "" {
		// The audit trail names the actor from the gin context.
		c.Set("user_id", userID)
	}
	need, err := s.factorProofNeeded(c.Request.Context(), userID, changesSignInMethod)
	if err != nil {
		s.logger.Error("could not decide whether a sign-in method change needs proof; refusing it",
			zap.String("user_id", logsafe.Clean(userID)), zap.Error(err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return false
	}
	if !need.required {
		return true
	}
	return s.checkFactorProof(c, userID, need, readFactorProof(c))
}
