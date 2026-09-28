package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// The gateway refuses POST /api/v1/audit/events so that only OpenIDX's own
// services, on the internal network with the internal service token, can write
// events. The refusal compares the path cleaned, and a guard that only matches
// the canonical spelling is a guard an attacker spells differently: every form
// below is the same route to the audit service behind the proxy.
func TestTheGatewayRefusesEventIngestionHoweverItIsSpelled(t *testing.T) {
	for _, target := range []string{
		"/api/v1/audit/events",
		"//api/v1/audit/events",
		"/api/v1/audit/events/",
		"/api/v1/audit/events//",
		"/api/v1/audit/./events",
		"/api/v1/audit/x/../events",
		"/api/v1//audit//events",
		"/api/v1/audit/events/.",
		// net/http decodes the path before the guard sees it, so a
		// percent-encoded letter and an encoded separator both arrive as the
		// plain route.
		"/api/v1/audit/%65vents",
		"/api/v1/audit%2Fevents",
		"/./api/v1/audit/events",
	} {
		if !isEventIngestion(httptest.NewRequest(http.MethodPost, target, nil)) {
			t.Errorf("POST %q was not recognised as event ingestion", target)
		}
	}
}

// Only that one route and only that one method. The census of audit routes the
// gateway does forward is the rest of this package's job; what matters here is
// that closing the ingestion door did not close any other.
func TestTheGatewayStillForwardsEveryOtherAuditRequest(t *testing.T) {
	for _, tc := range []struct {
		method, target string
	}{
		{http.MethodGet, "/api/v1/audit/events"},    // the console reads the trail
		{http.MethodHead, "/api/v1/audit/events"},   // and may probe it
		{http.MethodPost, "/api/v1/audit/reports"},  // a neighbouring route
		{http.MethodPost, "/api/v1/audit/events/x"}, // a deeper path is not the route
		{http.MethodPost, "/api/v1/auditevents"},    // nor is a similar name
		{http.MethodPost, "/api/v1/audit"},
	} {
		if isEventIngestion(httptest.NewRequest(tc.method, tc.target, nil)) {
			t.Errorf("%s %q was refused as event ingestion; only POST on the exact route is",
				tc.method, tc.target)
		}
	}
}

// The middleware answers the ingestion route itself, with the 404 an unrouted
// path gets, and never calls the handler the proxy is mounted on.
func TestTheIngestionRefusalAnswers404AndNeverReachesTheProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	run := func(method, target string) (int, bool) {
		reached := false
		r := gin.New()
		r.Use(refuseEventIngestion)
		r.Any("/*any", func(c *gin.Context) {
			reached = true
			c.Status(http.StatusOK)
		})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, target, nil))
		return w.Code, reached
	}

	code, reached := run(http.MethodPost, "//api/v1/audit/events")
	if code != http.StatusNotFound {
		t.Errorf("ingestion answered %d, want 404", code)
	}
	if reached {
		t.Error("the request reached the proxy handler; the refusal must answer before it")
	}

	code, reached = run(http.MethodGet, "/api/v1/audit/events")
	if code != http.StatusOK || !reached {
		t.Errorf("a read of the trail answered %d reached=%v, want 200 and reached", code, reached)
	}
}
