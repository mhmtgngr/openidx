package health

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap/zaptest"
)

// The service Dockerfiles and the full Compose stack probe health with
// `wget --spider`, which sends HEAD. With the routes registered for GET only,
// gin answered 404 and Docker reported every service unhealthy while it served
// traffic (#1002). This holds each standard route to answering HEAD with the
// same status a GET gets.
func TestStandardRoutesAnswerHEADLikeGET(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name     string
		checkers []HealthChecker
		want     map[string]int // path -> status, for both methods
	}{
		{
			name: "healthy",
			checkers: []HealthChecker{
				&mockChecker{name: "database", status: "up", critical: true},
			},
			want: map[string]int{"/health": http.StatusOK, "/health/ready": http.StatusOK, "/health/live": http.StatusOK},
		},
		{
			name: "critical dependency down",
			checkers: []HealthChecker{
				&mockChecker{name: "database", status: "down", critical: true},
			},
			// /health and /health/ready say so; liveness is about the process.
			want: map[string]int{"/health": http.StatusServiceUnavailable, "/health/ready": http.StatusServiceUnavailable, "/health/live": http.StatusOK},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewHealthService(zaptest.NewLogger(t))
			for _, c := range tc.checkers {
				svc.RegisterCheck(c)
			}
			router := gin.New()
			svc.RegisterStandardRoutes(router, "")

			for path, want := range tc.want {
				for _, method := range []string{http.MethodGet, http.MethodHead} {
					rec := httptest.NewRecorder()
					req := httptest.NewRequest(method, path, nil)
					router.ServeHTTP(rec, req)
					if rec.Code != want {
						t.Errorf("%s %s: status %d, want %d", method, path, rec.Code, want)
					}
				}
			}
		})
	}
}

// A prober that probes /health with HEAD on a service whose health routes are
// mounted under another prefix must get the same answer.
func TestStandardRoutesAnswerHEADUnderAPrefix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := NewHealthService(zaptest.NewLogger(t))
	router := gin.New()
	svc.RegisterStandardRoutes(router, "/healthz")

	for _, path := range []string{"/healthz", "/healthz/ready", "/healthz/live"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("HEAD %s: status %d, want 200", path, rec.Code)
		}
	}
	// And the default prefix is not registered when another one is asked for.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/health", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("HEAD /health with routes under /healthz: status %d, want 404", rec.Code)
	}
}
