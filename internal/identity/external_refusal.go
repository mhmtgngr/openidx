package identity

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

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
