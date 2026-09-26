// Package routes provides audit service route registration for the gateway
package routes

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"

	"github.com/gin-gonic/gin"
)

// auditIngestPath is the audit service's event ingestion route. Only OpenIDX's
// own services write events, over the internal network with the internal
// service token; nothing outside has a reason to reach it, so the gateway does
// not forward it.
const auditIngestPath = "/api/v1/audit/events"

// isEventIngestion reports whether r is POST /api/v1/audit/events. The path
// is compared cleaned, so a doubled or trailing slash does not walk around it;
// every other method on the path, and every other audit route, is forwarded
// as before.
func isEventIngestion(r *http.Request) bool {
	return r.Method == http.MethodPost && path.Clean(r.URL.Path) == auditIngestPath
}

// refuseEventIngestion answers the ingestion route with the 404 an unrouted
// path gets, before the proxy sees it.
func refuseEventIngestion(c *gin.Context) {
	if isEventIngestion(c.Request) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.Next()
}

// RegisterAuditRoutes registers routes for the audit service
func RegisterAuditRoutes(router *gin.RouterGroup, provider ServiceURLProvider) {
	serviceURL, err := provider.GetServiceURL("audit")
	if err != nil {
		serviceURL = "http://localhost:8504"
	}

	target, _ := url.Parse(serviceURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Proxy every path under this service prefix straight to the backend. All
	// routes share one handler and the groups carry no distinct middleware, so a
	// single catch-all is behaviourally identical to mirroring each endpoint —
	// and it avoids gin's static-vs-wildcard conflict (a catch-all "/*path"
	// cannot coexist with explicit siblings like "/users"). The backend owns
	// auth and routing; the gateway stays a thin pass-through, except for the
	// one route no caller outside the platform may reach.
	router.Any("/*path", refuseEventIngestion, proxyRequest(proxy))
}

// GetAuditURL returns the audit service URL
func GetAuditURL(provider ServiceURLProvider) string {
	if url, err := provider.GetServiceURL("audit"); err == nil {
		return url
	}
	return "http://localhost:8504"
}

// AuditProxy returns the audit service proxy handler
func AuditProxy(provider ServiceURLProvider) gin.HandlerFunc {
	serviceURL := GetAuditURL(provider)
	target, _ := url.Parse(serviceURL)
	proxy := httputil.NewSingleHostReverseProxy(target)

	forward := proxyRequest(proxy)
	return func(c *gin.Context) {
		if isEventIngestion(c.Request) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		forward(c)
	}
}
