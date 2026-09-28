package audit

import (
	"context"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/middleware"
)

// Event ingestion is for OpenIDX's own services, and they prove it.
//
// POST /api/v1/audit/events writes whatever the body says: the actor, the
// client address, the action, the outcome and the details, filed under the
// organization X-Org-Slug names, and the sealer chains it like any other
// event, so the chain verifies over it. It used to take any caller at all, on
// the grounds that it was "protected by network isolation" -- and every
// reference edge forwarded the whole /api/v1/audit prefix to this service, so
// anyone who could reach the console could write a forged, chained event into
// any organization's trail.
//
// The credential is INTERNAL_SERVICE_TOKEN in X-Internal-Token: the secret
// access-service already presents to governance for its policy checks, and the
// only client of this route is access-service. A user's access token is not a
// substitute. Events describe what a service observed, and nothing in the
// product posts them on a user's behalf -- the console reads the trail and
// never writes to it -- so a bearer token here, whoever holds it, is refused
// like no credential at all.

// edgeListenerKey marks a request that arrived on the edge listener.
type edgeListenerKey struct{}

// MarkEdgeListener is the ConnContext of the listener the edge routes to
// (AUDIT_EDGE_ADDR). Requests on it reach every route but event ingestion.
//
// It exists for Kubernetes: an Ingress cannot match on method, so the chart
// cannot let GET /api/v1/audit/events through and refuse POST at the edge.
// Routing the audit prefix to a listener that has no ingestion does the same
// job, whatever the ingress controller. The other edges refuse the POST
// themselves.
func MarkEdgeListener(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, edgeListenerKey{}, true)
}

// viaEdgeListener reports whether the request came in through the listener
// MarkEdgeListener marks.
func viaEdgeListener(ctx context.Context) bool {
	v, _ := ctx.Value(edgeListenerKey{}).(bool)
	return v
}

// requireInternalService admits the ingestion route's one kind of caller: an
// OpenIDX service presenting the internal service token, on the internal
// listener.
func (s *Service) requireInternalService() gin.HandlerFunc {
	return func(c *gin.Context) {
		// The edge listener answers as if the route did not exist, which is
		// what the other edges answer too.
		if viaEdgeListener(c.Request.Context()) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		configured := ""
		if s.config != nil {
			configured = s.config.InternalServiceToken
		}
		if !middleware.ValidInternalToken(c.GetHeader(middleware.InternalTokenHeader), configured) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "audit events are accepted only from OpenIDX services presenting the internal service token",
			})
			return
		}
		c.Next()
	}
}
