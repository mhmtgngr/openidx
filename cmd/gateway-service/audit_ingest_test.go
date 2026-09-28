package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	gwmiddleware "github.com/openidx/openidx/internal/gateway/middleware"
)

// THE GATEWAY DOES NOT FORWARD AUDIT EVENT INGESTION.
//
// The gateway proxies /api/v1/audit/*path to the audit service with one
// catch-all, which forwarded POST /api/v1/audit/events too: the route that
// writes an event into any organization's trail, meant only for OpenIDX's own
// services. Driven through registerServiceRoutes, behind the tenant-header
// middleware main mounts, with a stand-in audit service that records what
// reaches it:
//
//   - POST /api/v1/audit/events is answered 404 by the gateway, and so are the
//     spellings the proxy would forward to the same handler -- a trailing
//     slash, a doubled slash, a dot segment -- and nothing reaches the service;
//   - the console's read of the same path, the other audit routes and the
//     other audit writes (report generation, export) are forwarded as before.
func TestTheGatewayDoesNotForwardAuditEventIngestion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var mu sync.Mutex
	var reached []string
	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reached = append(reached, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer audit.Close()
	t.Setenv("AUDIT_SERVICE_URL", audit.URL)

	router := gin.New()
	router.Use(gwmiddleware.OrgSlugHeader(""))
	registerServiceRoutes(router, &serviceURLProvider{})
	// A real listener: the reverse proxy needs a ResponseWriter that can
	// report a closed connection, which a recorder is not.
	gateway := httptest.NewServer(router)
	defer gateway.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	call := func(method, target string) int {
		t.Helper()
		req, err := http.NewRequest(method, gateway.URL+target, strings.NewReader(`{"action":"forged"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Internal-Token", "anything")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(reached)
	}

	for _, target := range []string{
		"/api/v1/audit/events",
		"/api/v1/audit/events/",
		"/api/v1/audit//events",
		"/api/v1/audit/./events",
		"/api/v1/audit/events?org=b",
	} {
		before := count()
		if code := call(http.MethodPost, target); code != http.StatusNotFound {
			t.Errorf("POST %s through the gateway answered %d, want 404", target, code)
		}
		if count() != before {
			t.Errorf("POST %s reached the audit service: %v", target, reached[before:])
		}
	}

	for _, fwd := range []struct{ method, target string }{
		{http.MethodGet, "/api/v1/audit/events"},
		{http.MethodGet, "/api/v1/audit/events/search?q=x"},
		{http.MethodGet, "/api/v1/audit/statistics"},
		{http.MethodPost, "/api/v1/audit/reports"},
		{http.MethodPost, "/api/v1/audit/export"},
	} {
		before := count()
		if code := call(fwd.method, fwd.target); code != http.StatusOK {
			t.Errorf("%s %s through the gateway answered %d, want the audit service's 200", fwd.method, fwd.target, code)
		}
		if count() != before+1 {
			t.Errorf("%s %s was not forwarded to the audit service", fwd.method, fwd.target)
		}
	}
}
