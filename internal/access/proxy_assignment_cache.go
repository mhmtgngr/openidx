package access

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Assignment-overlay caching for the proxy forward-auth path.
//
// handleProxy's assignment overlay (service.go) runs once per request the
// proxy forwards — every XHR, image and stylesheet a browser fetches through
// a route, not once per page load. Both queries backing it are cached here on
// the same TTL and sync.Map pattern userGroupNames already uses for the
// role/group check beside it (route_group_authz.go): near-static data is
// worth staling by up to groupCacheTTL to keep this off the hot path.
//
// Both helpers deliberately re-apply orgctx.WithBypassRLS to whatever context
// they are given, rather than trusting the caller to have done so: the proxy
// data plane resolves its tenant from the host, before any org context
// exists, and `applications` / `user_application_assignments` /
// `group_memberships` / `group_application_assignments` are all
// FORCE ROW LEVEL SECURITY. Without the bypass, appaccess.Allowed's explicit
// `a.org_id = $2` predicate would additionally be filtered by whatever
// `app.org_id` happens to be set to (the default org, or nothing) — silently
// returning "not assigned" for every correctly assigned user whose org isn't
// that one. Bypassing RLS here does not widen the check: appaccess.Allowed
// already scopes explicitly by org id, so the bypass just makes that
// predicate the sole scope, which is the intent.

// routeAppEntry is one cached route→application resolution.
type routeAppEntry struct {
	appID, orgID string
	at           time.Time
}

// appForRoute resolves the application (if any) backing a route, cached for
// groupCacheTTL keyed by route id. A lookup failure logs and is treated as
// "no application" rather than failing closed: unlike userGroupNames (which
// only denies routes that already declare allowed_groups), failing closed
// here would let one transient Postgres error black out every app-backed
// route on the proxy at once. Falling back to "no application" instead just
// means that one request is decided by the legacy role/group check, same as
// it always was.
func (s *Service) appForRoute(ctx context.Context, routeID string) (appID, orgID string) {
	if v, ok := s.routeAppCache.Load(routeID); ok {
		if e, ok := v.(routeAppEntry); ok && time.Since(e.at) < groupCacheTTL {
			return e.appID, e.orgID
		}
	}

	var id, org string
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore proxy data-plane assignment check; the route→application link is looked up by route_id, scoped by that row's own org_id, before any org context is resolved — same reasoning as findRouteByHost
		"SELECT id, org_id FROM applications WHERE route_id = $1 ORDER BY id LIMIT 1", routeID).Scan(&id, &org)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.logger.Error("proxy: application lookup for route failed", zap.String("route_id", routeID), zap.Error(err))
		id, org = "", ""
	}

	s.routeAppCache.Store(routeID, routeAppEntry{appID: id, orgID: org, at: time.Now()})
	return id, org
}

// assignCacheEntry is one cached assignment-predicate result.
type assignCacheEntry struct {
	assigned bool
	at       time.Time
}

// assignmentAllowed reports whether userID may reach appID, cached for
// groupCacheTTL keyed by "userID|appID". fresh is true only when this call
// actually queried the predicate (a cache miss) rather than returning a
// memoized result — callers use it to throttle the report-mode audit record
// to roughly once per TTL per (user, application) instead of once per
// request, since every allowed request from an unassigned caller would
// otherwise emit an audit POST (see handleProxy).
func (s *Service) assignmentAllowed(ctx context.Context, userID, orgID, appID string) (assigned, fresh bool) {
	key := userID + "|" + appID
	if v, ok := s.assignCache.Load(key); ok {
		if e, ok := v.(assignCacheEntry); ok && time.Since(e.at) < groupCacheTTL {
			return e.assigned, false
		}
	}

	ok, err := appaccess.Allowed(orgctx.WithBypassRLS(ctx), s.db, userID, orgID, appID)
	if err != nil {
		s.logger.Error("proxy: assignment check failed", zap.String("application_id", appID), zap.Error(err))
		ok = false // fail closed: unlike a route lookup miss, a failed assignment check must not silently allow
	}

	s.assignCache.Store(key, assignCacheEntry{assigned: ok, at: time.Now()})
	return ok, true
}
