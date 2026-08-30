package access

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestSelfServiceHandlersIgnoreUserIDQueryParam covers the two "my …" endpoints
// that used to fall back to ?user_id= when the request carried no authenticated
// caller ("dev-mode convenience"). Nothing gated that on the environment, and in
// development the access API runs under SoftAuth — which does NOT hard-block an
// anonymous request — so the query param let any caller read another user's
// overlay identity and reachable apps. The caller must come from the token only.
func TestSelfServiceHandlersIgnoreUserIDQueryParam(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Service{}

	handlers := map[string]gin.HandlerFunc{
		"my-ziti-identity": s.handleGetMyZitiIdentity,
		"my-ziti-services": s.handleMyZitiServices,
	}

	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			r := gin.New()
			r.GET("/self", h)

			w := httptest.NewRecorder()
			// No auth middleware ran → no user_id in context, but the caller
			// names a victim in the query string.
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/self?user_id=victim-user-id", nil))

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("anonymous request with ?user_id= returned %d, want 401 (the query param must not identify the caller); body: %s", w.Code, w.Body.String())
			}
		})
	}
}
