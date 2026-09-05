package openapi_test

import (
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/audit"
	"github.com/openidx/openidx/internal/governance"
	"github.com/openidx/openidx/internal/oauth"
	"github.com/openidx/openidx/internal/provisioning"
)

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
// access-service and identity-service are not here yet: their RegisterRoutes
// dereferences the service's database handle while registering, so a zero value
// panics. Documenting them needs that constructor untangled first, and this
// file should grow two more cases when it is.
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			r := gin.New()
			tc.mount(r)
			assertSpecMatchesRoutes(t, tc.spec, r.Routes())
		})
	}
}
