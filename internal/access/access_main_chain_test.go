package access

import (
	"context"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/middleware"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// accessMainChain mounts svc behind the middleware cmd/access-service puts in
// front of RegisterRoutes, in main.go's order, keeping every one that shapes a
// response the proxy's tests read: the security headers (the service-wide
// Content-Security-Policy), CSRF protection, the service's CORS handler and
// the tenant resolver. Admission control, tracing, the access log, rate
// limiting, metrics and the version header are left out; none of them changes
// what a browser or an upstream receives.
//
// auth stands in for the bearer middleware on /api/v1/access, which the
// session-cookie routes and the catch-all proxy never pass through.
func accessMainChain(t *testing.T, svc *Service, lookup middleware.OrgLookup, auth gin.HandlerFunc) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := svc.config
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.SecurityHeadersForEnv(cfg.IsProduction()))
	r.Use(middleware.CSRFProtection(middleware.CSRFConfig{
		Enabled:       cfg.CSRFEnabled,
		TrustedDomain: cfg.CSRFTrustedDomain,
	}, zap.NewNop()))
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})
	r.Use(middleware.TenantResolver(lookup, middleware.TenantResolverConfig{
		DefaultOrgFallback: true,
		DefaultOrgID:       middleware.DefaultOrgID,
		Logger:             zap.NewNop(),
	}))
	RegisterRoutes(r, svc, auth)
	return r
}

// defaultOrgOnly is an organization lookup that knows the install's default
// organization and nothing else, for a chain whose test has no database.
type defaultOrgOnly struct{}

func (defaultOrgOnly) ByID(_ context.Context, id string) (orgctx.Org, error) {
	if id == middleware.DefaultOrgID {
		return orgctx.Org{ID: id, Slug: "default"}, nil
	}
	return orgctx.Org{}, middleware.ErrOrgNotFound
}

func (defaultOrgOnly) BySlug(_ context.Context, slug string) (orgctx.Org, error) {
	if slug == "default" {
		return orgctx.Org{ID: middleware.DefaultOrgID, Slug: slug}, nil
	}
	return orgctx.Org{}, middleware.ErrOrgNotFound
}

// refuseBearerAPI is an auth stand-in that refuses every /api/v1/access call,
// for tests that drive only the unauthenticated surface.
func refuseBearerAPI(c *gin.Context) {
	c.AbortWithStatusJSON(401, gin.H{"error": "missing authorization header"})
}
