package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// The gateway image's HEALTHCHECK and its compose health check run
// `wget -q --spider`, which sends HEAD (#1002).
func TestTheGatewayHealthRoutesAnswerAHeadProbeAsTheyAnswerGet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc, err := NewService(Config{Logger: &zapLoggerWrapper{logger: zap.NewNop()}})
	require.NoError(t, err)
	router := gin.New()
	svc.RegisterRoutes(router)

	for _, path := range []string{"/health", "/ready"} {
		get := httptest.NewRecorder()
		router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, path, nil))
		head := httptest.NewRecorder()
		router.ServeHTTP(head, httptest.NewRequest(http.MethodHead, path, nil))

		assert.Equal(t, http.StatusOK, get.Code, "GET %s", path)
		assert.Equal(t, get.Code, head.Code, "HEAD %s answers as GET does", path)
	}
}
