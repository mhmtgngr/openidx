package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// OrgLookup is the read-only org lookup the tenant resolver needs.
// Implementations typically wrap internal/organization.Service and
// return (zero-value, ErrOrgNotFound) when the org doesn't exist.
//
// The interface deliberately lives in the middleware package, not in
// internal/organization, because we want the middleware to be
// reusable from any service without dragging in the full org-service
// dependency tree (which itself depends on pgx).
type OrgLookup interface {
	// ByID returns the org with the given UUID. Returns
	// ErrOrgNotFound when no row matches.
	ByID(ctx context.Context, id string) (orgctx.Org, error)
	// BySlug returns the org with the given slug. Returns
	// ErrOrgNotFound when no row matches.
	BySlug(ctx context.Context, slug string) (orgctx.Org, error)
}

// ErrOrgNotFound is the sentinel an OrgLookup implementation returns
// when the requested org doesn't exist. The middleware distinguishes
// this from a generic lookup failure (the latter is a 500 server
// error; not-found is a 400 client error).
var ErrOrgNotFound = errors.New("organization not found")

// DefaultOrgID is the canonical UUID of the install's default
// organization. Migration v25 creates the row with this exact UUID
// (slug "default") and v35 backfills it into every pre-multitenancy
// row, so the Auth middleware, the tenant resolver's fallback, and
// the service mains all reference the same value.
const DefaultOrgID = "00000000-0000-0000-0000-000000000010"

// tenantSkipPaths are infrastructure endpoints the resolver passes
// through without resolving an org. Probes and scrapers are not
// org-scoped, and — more importantly — Kubernetes liveness probes
// must keep answering while the database (and therefore the org
// lookup) is down. Matches whole path segments: "/health" and
// "/health/ready" skip, "/healthcheck-export" does not.
//
// The login-branding endpoint is also exempt: it is a public,
// pre-authentication, pre-tenant bootstrap call (the SPA login page
// fetches it from the API host, where no tenant subdomain/JWT/
// X-Org-Slug signal exists yet) and it resolves the tenant itself from
// its ?org=/?domain= query parameters, returning safe defaults on a
// miss. Without this exemption, an install with DefaultOrgFallback off
// (the multi-tenant posture) would reject the call and the login page
// could never render tenant branding.
var tenantSkipPaths = []string{
	"/health",
	"/metrics",
	"/ready",
	"/live",
	"/api/v1/identity/branding",
}

// TenantResolverConfig governs how the middleware resolves the org.
//
// The defaults are tuned for the v1.6.0 ship gate: existing single
// tenant installs continue to work because DefaultOrgFallback is on
// and DefaultOrgID points at the install's default org.
type TenantResolverConfig struct {
	// DefaultOrgFallback, when true, makes the middleware attach the
	// install's default org rather than rejecting the request when
	// nothing resolves. v1.6.0 ships with this on. v1.7.0's final
	// PR flips it off once every service is org-scope aware.
	DefaultOrgFallback bool

	// DefaultOrgID is the UUID the resolver hands out when
	// DefaultOrgFallback is true and no upstream signal resolved. v25
	// created this org row with the canonical UUID
	// 00000000-0000-0000-0000-000000000010 and slug "default".
	// Required when DefaultOrgFallback is true.
	DefaultOrgID string

	// PlatformAdminPredicate, when set, is consulted to decide whether
	// the X-Org-ID header is honored and whether the platform-admin
	// marker should be attached to the context. It receives the gin
	// context and should return true if the actor is a platform admin
	// (typically: a super_admin role). When nil, the X-Org-ID header is
	// ignored and the platform-admin marker is never set.
	//
	// PRECONDITION: the predicate reads the GIN CONTEXT, which means it can
	// only answer once the auth middleware has populated it. Mount this
	// middleware after auth (as cmd/admin-api does, on the /api/v1 group) or
	// the predicate is false for every caller and steps 2 and 3 below are
	// unreachable — the request falls through to the default org. That is the
	// safe direction, and it is also invisible, which is why Logger exists.
	PlatformAdminPredicate func(*gin.Context) bool

	// Logger, when set, receives a warning when a request carries an X-Org-ID
	// header that this resolver cannot act on because auth has not run yet (no
	// roles in the gin context at all — an inability, distinct from "the caller
	// is not a platform admin", which is a decision).
	//
	// Six of the seven services that wire OnPlatformCrossOrg mount the resolver
	// globally, before route-level auth, so their platform-admin path is dead.
	// It stayed dead and unnoticed for a release because a dead branch and a
	// working one look identical from outside: the request resolves to the
	// default org either way. This turns that into a line in the log at the
	// moment someone tries to use the header.
	Logger *zap.Logger

	// OnPlatformCrossOrg, when set, is invoked exactly when a platform
	// admin resolves a request to an org via the X-Org-ID header (a
	// deliberate cross-org access). It MUST record an audit entry — this
	// is the mandatory audit trail for platform-admin org-boundary
	// crossings. It runs synchronously before the request proceeds.
	OnPlatformCrossOrg func(c *gin.Context, target orgctx.Org)
}

// TenantResolver returns the gin middleware that resolves the
// organization for each request and attaches it to ctx via orgctx.
//
// Resolution order (per v2.0 multi-tenancy design):
//  1. X-Org-Slug header (set by the gateway from the subdomain when
//     the install fronts wildcard *.openidx.io). Highest priority
//     because the URL is the most explicit tenant signal.
//  2. JWT claim "org_id" (already attached to the gin context by
//     the Auth middleware; the resolver does not re-parse the JWT).
//  3. X-Org-ID header, only honored when PlatformAdminPredicate
//     returns true. Lets ops/compliance tools cross org boundaries
//     without ambiguity. Every consumer that respects the
//     platform-admin marker is required to write an audit entry.
//  4. Default org fallback, if configured.
//
// Steps 2 and 3 READ THE GIN CONTEXT, so they exist only where this
// middleware is mounted AFTER the auth middleware that fills it. Mounted
// globally with router.Use — which is how identity, oauth, governance,
// audit, access and provisioning mount it — steps 2 and 3 cannot fire and
// every request lands on step 1 or step 4. Only cmd/admin-api mounts it on
// an authenticated group, so only there is the platform-admin path live.
// Set Logger to have the mismatch reported when a caller actually tries to
// use X-Org-ID against a resolver that cannot answer.
//
// On lookup failure: ErrOrgNotFound → 400. Any other error → 500.
//
// The middleware does NOT enforce org scoping itself. It only
// attaches the resolved org to the context. Service code that reads
// from orgctx is responsible for filtering by the carried org_id.
// That is the v1.7.0 surface; v1.6.0 only plumbs the context.
func TenantResolver(lookup OrgLookup, cfg TenantResolverConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if isTenantSkipPath(c.Request.URL.Path) {
			c.Next()
			return
		}

		org, err := resolveOrgFromRequest(c, lookup, cfg)
		if err != nil {
			if errors.Is(err, ErrOrgNotFound) {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error": err.Error(),
				})
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("tenant resolution failed: %v", err),
			})
			return
		}

		ctx := orgctx.With(c.Request.Context(), org)
		if cfg.PlatformAdminPredicate != nil && cfg.PlatformAdminPredicate(c) {
			ctx = orgctx.WithPlatformAdmin(ctx)
		}
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// warnUnanswerableCrossOrg reports the one case where a refused X-Org-ID means
// the resolver could not answer rather than that it answered "no": the header is
// present, a predicate is configured, and the gin context holds no roles at all,
// which is the shape of a resolver mounted ahead of the auth middleware that
// would have populated them.
//
// It is deliberately narrow. A caller who simply is not a platform admin has
// roles in context and gets nothing logged — that is a normal refusal, and a
// warning on it would be noise an operator learns to ignore, which is how this
// kind of signal stops working.
func warnUnanswerableCrossOrg(c *gin.Context, cfg TenantResolverConfig) {
	if cfg.Logger == nil || cfg.PlatformAdminPredicate == nil {
		return
	}
	if strings.TrimSpace(c.GetHeader("X-Org-ID")) == "" {
		return
	}
	if _, hasRoles := c.Get("roles"); hasRoles {
		return
	}
	cfg.Logger.Warn(
		"X-Org-ID ignored: TenantResolver ran before authentication, so the platform-admin predicate has no roles to read. "+
			"Mount the resolver after the auth middleware (see cmd/admin-api) if this service is meant to honor cross-org access.",
		zap.String("path", c.Request.URL.Path),
		zap.String("method", c.Request.Method),
	)
}

// isTenantSkipPath reports whether path is an infrastructure endpoint
// exempt from tenant resolution. Whole-segment matching: the skip
// entry must equal the path or be followed by "/".
func isTenantSkipPath(path string) bool {
	for _, sp := range tenantSkipPaths {
		if path == sp || strings.HasPrefix(path, sp+"/") {
			return true
		}
	}
	return false
}

func resolveOrgFromRequest(c *gin.Context, lookup OrgLookup, cfg TenantResolverConfig) (orgctx.Org, error) {
	ctx := c.Request.Context()

	// 1. X-Org-Slug header (gateway-set from subdomain).
	if slug := strings.TrimSpace(c.GetHeader("X-Org-Slug")); slug != "" {
		org, err := lookup.BySlug(ctx, slug)
		if err != nil {
			if errors.Is(err, ErrOrgNotFound) {
				return orgctx.Org{}, fmt.Errorf("unknown organization slug %q: %w", slug, ErrOrgNotFound)
			}
			return orgctx.Org{}, err
		}
		return org, nil
	}

	// 2. JWT claim "org_id" already on context (set by Auth middleware).
	// Note: the existing Auth middleware sets the default UUID when the
	// JWT lacks the claim, so we treat the default UUID and an unset
	// value identically — they both fall through to step 4.
	if v, ok := c.Get("org_id"); ok {
		if id, ok := v.(string); ok && id != "" && id != cfg.DefaultOrgID {
			org, err := lookup.ByID(ctx, id)
			if err != nil {
				if errors.Is(err, ErrOrgNotFound) {
					return orgctx.Org{}, fmt.Errorf("unknown organization in JWT: %w", ErrOrgNotFound)
				}
				return orgctx.Org{}, err
			}
			return org, nil
		}
	}

	// 3. X-Org-ID header (platform-admin only). This is a deliberate
	// cross-org access; emit the mandatory audit entry via the hook.
	if cfg.PlatformAdminPredicate != nil && cfg.PlatformAdminPredicate(c) {
		if id := strings.TrimSpace(c.GetHeader("X-Org-ID")); id != "" {
			org, err := lookup.ByID(ctx, id)
			if err != nil {
				if errors.Is(err, ErrOrgNotFound) {
					return orgctx.Org{}, fmt.Errorf("unknown organization in X-Org-ID header: %w", ErrOrgNotFound)
				}
				return orgctx.Org{}, err
			}
			if cfg.OnPlatformCrossOrg != nil {
				cfg.OnPlatformCrossOrg(c, org)
			}
			return org, nil
		}
	} else {
		warnUnanswerableCrossOrg(c, cfg)
	}

	// 4. Default org fallback.
	if cfg.DefaultOrgFallback {
		if cfg.DefaultOrgID == "" {
			return orgctx.Org{}, errors.New("DefaultOrgFallback enabled but DefaultOrgID empty")
		}
		org, err := lookup.ByID(ctx, cfg.DefaultOrgID)
		if err != nil {
			if errors.Is(err, ErrOrgNotFound) {
				return orgctx.Org{}, fmt.Errorf("default org %q not found in database: %w", cfg.DefaultOrgID, ErrOrgNotFound)
			}
			return orgctx.Org{}, err
		}
		return org, nil
	}

	return orgctx.Org{}, fmt.Errorf("no organization could be resolved: %w", ErrOrgNotFound)
}
