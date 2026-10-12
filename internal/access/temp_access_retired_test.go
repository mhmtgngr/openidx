package access

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// A retired link's page is the same for every token and needs nothing behind
// it: a Service with no database answers it, so it cannot be reading one.
func TestARetiredLinkGetsTheSamePageWhateverItsToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &Service{}
	r := gin.New()
	r.GET("/temp-access/:token", svc.handleRetiredTempAccess)
	var first string
	for _, token := range []string{"a1b2c3", "%3Cb%3Ex", strings.Repeat("f", 64)} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/temp-access/"+token, nil))
		if w.Code != http.StatusGone || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("%q: %d %s", token, w.Code, w.Header().Get("Content-Type"))
		}
		if first == "" {
			first = w.Body.String()
		} else if w.Body.String() != first {
			t.Fatalf("the page varies with the token %q", token)
		}
	}
	if !strings.Contains(first, "vendor user") {
		t.Errorf("the page should say how access works now: %s", first)
	}
}
