package access

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// A PAM route reached with no user on the context answers 401, not 500.
// On the reference box (SoftAuth, development) a .NET client calling
// /pam/entries, /pam/entries/:id and /guacamole/my-connections after its token
// lapsed got 500 "failed to check permissions": resolvePamCaller cast the
// empty user id to a uuid. Nothing is read for a caller who is nobody, so the
// test needs no database.
func TestResolvePamCallerRefusesAnonymous(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &Service{}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: "00000000-0000-0000-0000-000000000010"}))
		c.Next()
	})
	r.GET("/x", func(c *gin.Context) {
		if _, ok := svc.resolvePamCaller(c, "00000000-0000-0000-0000-000000000010"); ok {
			c.Status(http.StatusOK)
		}
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous caller: %d %s, want 401", w.Code, w.Body.String())
	}
}
