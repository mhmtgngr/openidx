package control

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/sso"
)

// TestTokenRouteReturnsSessionToken covers the seam the desktop GUI needs to
// call the backend REST APIs at all: the engine owns the OAuth session, so the
// Dart ApiClient has no token of its own and every request would go out with no
// Authorization header. GET /token hands it the engine's token (refreshed
// transparently) over the same local control channel.
func TestTokenRouteReturnsSessionToken(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	tok := &sso.Tokens{
		AccessToken: makeJWT("user-42", "u@example.com", time.Now().Add(time.Hour).Unix()),
		ExpiresAt:   time.Now().Add(time.Hour).Unix(),
	}
	if err := saveToken(e.configDir, tok); err != nil {
		t.Fatal(err)
	}
	c, base, done := startTestServer(t, e)
	defer done()

	code, body := get(t, c, base, "/token")
	if code != http.StatusOK {
		t.Fatalf("code=%d body=%s", code, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, body)
	}
	if out.AccessToken != tok.AccessToken {
		t.Errorf("access_token = %q, want the stored session token", out.AccessToken)
	}
}

// TestTokenRouteUnauthenticated: signed out, the GUI must get a 401 it can turn
// into a sign-in prompt — never an empty token it would send as a Bearer header.
func TestTokenRouteUnauthenticated(t *testing.T) {
	e := newTestEngine(t, &fakeBackend{})
	c, base, done := startTestServer(t, e)
	defer done()

	code, body := get(t, c, base, "/token")
	if code != http.StatusUnauthorized {
		t.Fatalf("code=%d, want 401; body=%s", code, body)
	}
}
