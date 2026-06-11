package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
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
	// (typically: users.is_platform_admin == true). When nil, the
	// X-Org-ID header is ignored and the platform-admin marker is
	// never set.
	PlatformAdminPredicate func(*gin.Context) bool
}

// TenantResolver returns the gin middleware that resolves the
// organization for each request and attaches it to ctx via orgctx.
//
// Resolution order (per v2.0 multi-tenancy design):
//   1. X-Org-Slug header (set by the gateway from the subdomain when
//      the install fronts wildcard *.openidx.io). Highest priority
//      because the URL is the most explicit tenant signal.
//   2. JWT claim "org_id" (already attached to the gin context by
//      the Auth middleware; the resolver does not re-parse the JWT).
//   3. X-Org-ID header, only honored when PlatformAdminPredicate
//      returns true. Lets ops/compliance tools cross org boundaries
//      without ambiguity. Every consumer that respects the
//      platform-admin marker is required to write an audit entry.
//   4. Default org fallback, if configured.
//
// On lookup failure: ErrOrgNotFound → 400. Any other error → 500.
//
// The middleware does NOT enforce org scoping itself. It only
// attaches the resolved org to the context. Service code that reads
// from orgctx is responsible for filtering by the carried org_id.
// That is the v1.7.0 surface; v1.6.0 only plumbs the context.
func TenantResolver(lookup OrgLookup, cfg TenantResolverConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
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

	// 3. X-Org-ID header (platform-admin only).
	if cfg.PlatformAdminPredicate != nil && cfg.PlatformAdminPredicate(c) {
		if id := strings.TrimSpace(c.GetHeader("X-Org-ID")); id != "" {
			org, err := lookup.ByID(ctx, id)
			if err != nil {
				if errors.Is(err, ErrOrgNotFound) {
					return orgctx.Org{}, fmt.Errorf("unknown organization in X-Org-ID header: %w", ErrOrgNotFound)
				}
				return orgctx.Org{}, err
			}
			return org, nil
		}
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
