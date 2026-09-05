// Admin API census. cmd/admin-api mounts eight route groups; this file
// reassembles them so the spec is compared against everything the binary
// serves, not just internal/admin's share of it.
package openapi_test

import (
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/admin"
	adminhandlers "github.com/openidx/openidx/internal/admin/handlers"
	"github.com/openidx/openidx/internal/credentials"
	"github.com/openidx/openidx/internal/notifications"
	"github.com/openidx/openidx/internal/organization"
	"github.com/openidx/openidx/internal/vault"
)

// adminAPIRoutes mounts every group cmd/admin-api/main.go mounts under /api/v1.
// The services are zero values: registration only reads the receiver's method
// set, never its fields, so no database is needed — and a gate that needed one
// would not run in the unit job.
func adminAPIRoutes(t *testing.T) []gin.RouteInfo {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v1 := r.Group("/api/v1")

	admin.RegisterRoutes(v1, &admin.Service{})
	organization.RegisterRoutes(v1, &organization.Service{})
	notifications.RegisterRoutes(v1, &notifications.Service{})
	adminhandlers.RegisterAllRoutes(v1, nil, zap.NewNop(), admin.RequireAdmin())

	selfheal := adminhandlers.NewSelfHealHandler(zap.NewNop(), t.TempDir(), t.TempDir(), nil)
	adminhandlers.SelfHealRoutes(v1, selfheal, admin.RequireAdmin(), admin.RequireAdmin())

	// cmd/admin-api puts vault, credential rotation and the PAM overview behind
	// an extra RequireAdmin on a sub-group of v1; the paths are the same.
	vaultGroup := v1.Group("")
	(&vault.Service{}).RegisterRoutes(vaultGroup)
	(&credentials.Service{}).RegisterRoutes(vaultGroup)
	admin.RegisterPAMRoutes(vaultGroup, &admin.Service{})

	return r.Routes()
}

func TestAdminAPISpecMatchesTheRouteTable(t *testing.T) {
	assertSpecMatchesRoutes(t, "admin-api.yaml", adminAPIRoutes(t))
}
