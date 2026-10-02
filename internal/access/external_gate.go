package access

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/externalid"
)

// refuseIneffectiveExternal is invariant I4 of the third-party access
// framework at a privileged launch: an external (vendor) user launches nothing
// until the account is active with a strong second factor. It answers 403
// external_not_activated and reports true when it refused. It runs after the
// grant check, so an ungranted caller still reads "not permitted", and before
// the approval gate, so a refusal does not spend an approval.
func (s *Service) refuseIneffectiveExternal(c *gin.Context, orgID, userID string) bool {
	err := externalid.CheckEffective(c.Request.Context(), s.db.Pool, orgID, userID)
	if err == nil {
		return false
	}
	if errors.Is(err, externalid.ErrNotActivated) {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error(), "code": externalid.Code(err)})
		return true
	}
	s.logger.Error("could not check the caller's external account", zap.Error(err))
	c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check permissions"})
	return true
}
