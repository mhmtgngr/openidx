package access

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// A host is served by one enabled route in the whole installation.
//
// The proxy and forward-auth find the route for a request by the host the
// browser addressed, before any organization is known, so whoever holds a host
// receives its traffic. Routes were matched with from_url LIKE '%'||host||'%'
// across every organization, highest priority first, and the route API took
// any from_url: an administrator of one organization could route another
// organization's host to an upstream of their choosing.
//
// Migration v211 gives proxy_routes a host column, from_url's host as
// proxy_route_host() normalizes it, and a unique index over the enabled
// routes' hosts. Everything that finds a route by host compares that column
// with proxy_route_host() of the request's host, and every writer that could
// put a route on a host answers 409 when another enabled route holds it: with
// the holder's name when it is the caller's own organization's route, and with
// nothing about the holder when it is another organization's.

// routeHostIndex is the unique index on the enabled routes' hosts.
const routeHostIndex = "idx_proxy_routes_enabled_host"

// isRouteHostTaken reports whether err is the host index refusing a write.
func isRouteHostTaken(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == routeHostIndex
}

// routeHostHolder is the enabled route that holds a host.
type routeHostHolder struct {
	Host            string
	OrgID           string
	ID              string
	Name            string
	FromURL         string
	ZitiServiceName string
	BrowZer         bool
}

// routeHostTakenError is a write refused because an enabled route already
// holds the host. Holder is nil when the host's holder could not be read back.
type routeHostTakenError struct {
	Holder *routeHostHolder
}

func (e *routeHostTakenError) Error() string {
	if e.Holder == nil {
		return "the host is already served by another enabled route"
	}
	return fmt.Sprintf("host %s is already served by another enabled route", e.Holder.Host)
}

// enabledRouteOnHost returns the enabled route holding the host fromURL names,
// or nil when none does (or fromURL names no host). It reads across
// organizations: a host is held for the whole installation.
func (s *Service) enabledRouteOnHost(ctx context.Context, fromURL string) (*routeHostHolder, error) {
	var h routeHostHolder
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore a host is held across organizations (migration v211); the holder's organization is read to decide what the 409 may say about it
		`SELECT host, org_id::text, id::text, name, from_url, COALESCE(ziti_service_name, ''), COALESCE(browzer_enabled, false)
		   FROM proxy_routes
		  WHERE enabled = true AND host = proxy_route_host($1)
		  LIMIT 1`, fromURL).Scan(&h.Host, &h.OrgID, &h.ID, &h.Name, &h.FromURL, &h.ZitiServiceName, &h.BrowZer)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// routeHostTaken is the error a writer returns when the host fromURL names is
// held: the holder read back after the index refused the write, when it can
// be.
func (s *Service) routeHostTaken(ctx context.Context, fromURL string) *routeHostTakenError {
	h, err := s.enabledRouteOnHost(ctx, fromURL)
	if err != nil {
		h = nil
	}
	return &routeHostTakenError{Holder: h}
}

// respondRouteHostTaken answers 409 for a write refused because the host is
// held. The caller's own organization is told which of its routes holds it;
// another organization's route is not described.
func respondRouteHostTaken(c *gin.Context, orgID string, e *routeHostTakenError) {
	h := e.Holder
	switch {
	case h == nil:
		c.JSON(http.StatusConflict, gin.H{"error": "that host is already served by another enabled route"})
	case h.OrgID == orgID:
		c.JSON(http.StatusConflict, gin.H{
			"error":    fmt.Sprintf("route %q already serves %s; a host is served by one enabled route", h.Name, h.Host),
			"host":     h.Host,
			"route_id": h.ID,
		})
	default:
		c.JSON(http.StatusConflict, gin.H{
			"error": fmt.Sprintf("%s is routed by another organization", h.Host),
			"host":  h.Host,
		})
	}
}

// answerRouteHostTaken answers 409 when err is the host index refusing a
// write of fromURL in orgID, and reports whether it did.
func (s *Service) answerRouteHostTaken(c *gin.Context, orgID, fromURL string, err error) bool {
	var taken *routeHostTakenError
	switch {
	case errors.As(err, &taken):
	case isRouteHostTaken(err):
		taken = s.routeHostTaken(c.Request.Context(), fromURL)
	default:
		return false
	}
	respondRouteHostTaken(c, orgID, taken)
	return true
}
