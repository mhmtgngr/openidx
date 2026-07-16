package audit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestExtractSubprotocolToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"", ""},
		{"access_token_abc.def.ghi", "abc.def.ghi"},
		{" access_token_xyz ", "xyz"},
		{"json, access_token_tok123", "tok123"},
		{"some-other-proto", ""},
		{"access_token_", ""},
	}
	for _, c := range cases {
		if got := extractSubprotocolToken(c.header); got != c.want {
			t.Errorf("extractSubprotocolToken(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}

// TestWebSocketStreamRejectsUnauthenticated proves the security fix: with a JWKS
// URL configured, a WebSocket upgrade with no access_token_ subprotocol is
// rejected with 401 (the audit trail must not stream unauthenticated). Without a
// JWKS URL (dev), it does not gate on auth.
func TestWebSocketStreamRejectsUnauthenticated(t *testing.T) {
	gin.SetMode(gin.TestMode)

	es := &EventStreamer{
		logger:  zap.NewNop(),
		jwksURL: "https://issuer.example/.well-known/jwks.json",
	}

	r := gin.New()
	r.GET("/stream", es.handleWebSocketStream)

	// No subprotocol token, no WebSocket upgrade headers → must be 401 (auth is
	// checked before the upgrade attempt).
	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated stream connect: status = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "access token") {
		t.Fatalf("expected an access-token error, got %s", w.Body.String())
	}
}
