package identity

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"
)

// writeExternalRefusal answers err when it is an external-identity refusal:
// the database guard of migration v214 (a role above the external ceiling, a
// group not open to external users, a delegation or an approval naming an
// external user) or a check in internal/externalid. Reports whether it
// answered.
//
// The refusal is the caller's request, so it is a 4xx with a stable code:
// 409 when the request conflicts with stored state (a group that still has
// external members), 403 otherwise. Without this the guard surfaced as the
// handler's generic 500, which tells an administrator nothing about what to
// change.
func writeExternalRefusal(c *gin.Context, err error) bool {
	r := externalid.Refusal(err)
	if r == nil {
		return false
	}
	status := http.StatusForbidden
	if errors.Is(r, externalid.ErrGroupHasExternal) {
		status = http.StatusConflict
	}
	c.JSON(status, gin.H{"error": r.Error(), "code": externalid.Code(r)})
	return true
}

// strongFactorsOnlyForExternal refuses method to an external (vendor) user:
// SMS, email and phone-call codes are not offered to one (decision D4 of the
// third-party access framework; internal/externalid.StrongFactors). It sits
// on the enrollment and challenge routes of those methods, so the sign-in
// that never offers them is matched by an account that cannot hold them.
// Anyone else passes.
func (s *Service) strongFactorsOnlyForExternal(method string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		org, err := orgctx.From(c.Request.Context())
		if userID == "" || err != nil || s.db == nil {
			c.Next()
			return
		}
		ext, err := externalid.IsExternal(c.Request.Context(), s.db.Pool, org.ID, userID)
		if err != nil {
			s.logger.Error("could not read the caller's user type for a factor enrollment", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		if ext && !externalid.FactorAllowed(externalid.TypeExternal, method) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": externalid.ErrFactorNotAllowed.Error(), "code": externalid.Code(externalid.ErrFactorNotAllowed),
			})
			return
		}
		c.Next()
	}
}
