package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/externalid"
)

// writeExternalRefusal answers err with 403 and a stable code when it is an
// external-identity refusal: the database guard of migration v214 refuses a
// delegation to or from an external (vendor) user (invariant I2), and the
// handler's generic 500 would tell the administrator nothing about why.
// Reports whether it answered.
func writeExternalRefusal(c *gin.Context, err error) bool {
	r := externalid.Refusal(err)
	if r == nil {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{"error": r.Error(), "code": externalid.Code(r)})
	return true
}
