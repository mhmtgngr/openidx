package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	gwmiddleware "github.com/openidx/openidx/internal/gateway/middleware"
)

// TestOrgSlugHeader_propagatesThroughProxy is the end-to-end check
// that the v1.7.0 #3 producer wiring actually reaches a backend: the
// gateway's OrgSlugHeader middleware runs, the reverse proxy forwards
// the derived header (it is not hop-by-hop, so removeHopByHopHeaders
// leaves it), and the upstream service sees X-Org-Slug ready for its
// TenantResolver.
func TestOrgSlugHeader_propagatesThroughProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var seen string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Org-Slug")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rp, err := NewReverseProxy(Config{
		TargetURL:      backend.URL,
		ServiceName:    "identity-service",
		RequestTimeout: 5 * time.Second,
		Logger:         &mockProxyLogger{},
	})
	if err != nil {
		t.Fatalf("NewReverseProxy: %v", err)
	}

	r := gin.New()
	r.Use(gwmiddleware.OrgSlugHeader("openidx.io"))
	r.GET("/api/v1/identity/users", rp.ServeHTTP)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/identity/users", nil)
	req.Host = "acme.openidx.io"
	// A client trying to spoof the tenant must not win.
	req.Header.Set("X-Org-Slug", "victim-org")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if seen != "acme" {
		t.Fatalf("backend saw X-Org-Slug = %q, want %q (derived from subdomain, spoof overridden)", seen, "acme")
	}
}
