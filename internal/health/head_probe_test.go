package health

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap/zaptest"
)

// The images' HEALTHCHECK and the compose health checks run
// `wget -q --spider`, which sends HEAD. Registered for GET only, every
// health route answered HEAD with 404 and Docker marked the serving
// container unhealthy (#1002).
func TestTheHealthRoutesAnswerAHeadProbeAsTheyAnswerGet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	NewHealthService(zaptest.NewLogger(t)).RegisterStandardRoutes(router, "")

	for _, path := range []string{"/health", "/health/ready", "/health/live"} {
		get := httptest.NewRecorder()
		router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, path, nil))
		head := httptest.NewRecorder()
		router.ServeHTTP(head, httptest.NewRequest(http.MethodHead, path, nil))

		if get.Code != http.StatusOK {
			t.Fatalf("GET %s: got %d, want 200", path, get.Code)
		}
		if head.Code != get.Code {
			t.Errorf("HEAD %s: got %d, want %d as for GET", path, head.Code, get.Code)
		}
	}
}
