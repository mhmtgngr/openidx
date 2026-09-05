package openapi_test

import (
	"testing"

	"github.com/gin-gonic/gin"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/access"
	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/governance"
	"github.com/openidx/openidx/internal/identity"
	"github.com/openidx/openidx/internal/notifications"
	"github.com/openidx/openidx/internal/oauth"
	"github.com/openidx/openidx/internal/portal"
	"github.com/openidx/openidx/internal/provisioning"
)

// identity- and access-service register routes through middleware that reads
// the service's database and Redis handles (PermissionResolver takes
// svc.db.Pool), so a zero-value Service panics before the first route lands.
// Their constructors are pure assignment, though — no dial, no goroutine — so
// handing them zero-valued handles gives a service that can be routed but not
// used, which is exactly what a route census wants.
func stubDeps() (*database.PostgresDB, *database.RedisClient, *config.Config, *zap.Logger) {
	return &database.PostgresDB{}, &database.RedisClient{}, &config.Config{}, zap.NewNop()
}

// The same census the admin API gets, for the services whose RegisterRoutes
// takes a *gin.Engine and can be called on a zero-value Service: registration
// reads the receiver's method set, not its fields.
//
// Before this landed the four specs together described 41 of 175 routes.
// provisioning-service.yaml was silent on the whole outbound-SCIM target
// surface; oauth-service.yaml on SSF/CAEP stream management, device
// authorization, step-up, passwordless and social login; governance-service on
// ABAC policies, entitlements, privileged accounts and the SoD sweep; and
// audit-service on its usage and report endpoints. All of it routed.
//
// identity- and access-service came last: their RegisterRoutes reaches through
// the service to a live handle, so a zero value panics. No refactor was needed
// in the end — their constructors are pure assignment, so zero-valued handles
// produce a service that can be routed and not used. See stubDeps below.
func TestServiceSpecsCoverEveryRoute(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spec  string
		mount func(*gin.Engine)
	}{
		{
			name:  "provisioning",
			spec:  "provisioning-service.yaml",
			mount: func(r *gin.Engine) { provisioning.RegisterRoutes(r, &provisioning.Service{}) },
		},
		{
			name: "oauth",
			spec: "oauth-service.yaml",
			mount: func(r *gin.Engine) {
				oauth.RegisterRoutes(r, &oauth.Service{}, func(c *gin.Context) {})
			},
		},
		{
			name:  "governance",
			spec:  "governance-service.yaml",
			mount: func(r *gin.Engine) { governance.RegisterRoutes(r, &governance.Service{}) },
		},
		{
			name:  "audit",
			spec:  "audit-service.yaml",
			mount: func(r *gin.Engine) { audit.RegisterRoutes(r, &audit.Service{}) },
		},
		{
			// identity-service also mounts the self-service portal and the
			// notification routes under /api/v1/identity, so its spec covers
			// all three — that is what the binary serves.
			name: "identity",
			spec: "identity-service.yaml",
			mount: func(r *gin.Engine) {
				db, rd, cfg, log := stubDeps()
				identity.RegisterRoutes(r, identity.NewService(db, rd, cfg, log))
				g := r.Group("/api/v1/identity")
				portal.RegisterRoutes(g, &portal.Service{})
				notifications.RegisterRoutes(g, &notifications.Service{})
			},
		},
		{
			name: "access",
			spec: "access-service.yaml",
			mount: func(r *gin.Engine) {
				db, rd, cfg, log := stubDeps()
				access.RegisterRoutes(r, access.NewService(db, rd, cfg, log))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			r := gin.New()
			tc.mount(r)
			assertSpecMatchesRoutes(t, tc.spec, r.Routes())
		})
	}
}
