package control

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// authWrap is the only authentication the control server has on Windows, and
// nothing drove it. Every case in server_test.go attaches the CORRECT bearer
// through dialControl's transport, so they prove the happy path and nothing
// about refusal; and on Unix the token is empty, so on the platform CI runs
// most the wrapper is a no-op and even the happy path proves nothing about it.
//
// These call the wrapper directly, with a token set, on every platform. What it
// guards: /token hands out the signed-in user's access token, /pam/connect
// launches a privileged session, /ziti/dial opens the overlay.

func authProbe(t *testing.T, configured, sent string) int {
	t.Helper()
	s := &Server{token: configured}
	reached := false
	h := s.authWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	if sent != "" {
		req.Header.Set("Authorization", sent)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusNoContent && !reached {
		t.Fatal("the wrapper answered 204 without calling the handler")
	}
	if w.Code != http.StatusNoContent && reached {
		t.Fatalf("the handler ran even though the wrapper answered %d", w.Code)
	}
	return w.Code
}

func TestControlAuthRefusesEverythingButTheExactBearer(t *testing.T) {
	const tok = "s3cret-control-token"

	for _, tc := range []struct {
		name string
		sent string
		want int
	}{
		{"the exact bearer", "Bearer " + tok, http.StatusNoContent},

		{"no header at all", "", http.StatusUnauthorized},
		{"empty header", " ", http.StatusUnauthorized},
		{"the token with no scheme", tok, http.StatusUnauthorized},
		{"a different scheme", "Basic " + tok, http.StatusUnauthorized},
		{"lowercase scheme", "bearer " + tok, http.StatusUnauthorized},
		{"a wrong token of the same length", "Bearer s3cret-control-tokeX", http.StatusUnauthorized},

		// The prefix cases are what a timing attack builds toward: guess one
		// byte, keep the ones that took marginally longer, extend. The
		// comparison is constant-time now, which no unit test can observe — but
		// each of these must still be refused, and a refactor that started
		// accepting a prefix would show up here.
		{"a correct prefix", "Bearer s3cret-control", http.StatusUnauthorized},
		{"one byte short", "Bearer " + tok[:len(tok)-1], http.StatusUnauthorized},
		{"one byte long", "Bearer " + tok + "x", http.StatusUnauthorized},
		{"leading whitespace", "Bearer  " + tok, http.StatusUnauthorized},
		{"trailing whitespace", "Bearer " + tok + " ", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := authProbe(t, tok, tc.sent); got != tc.want {
				t.Errorf("Authorization %q answered %d, want %d", tc.sent, got, tc.want)
			}
		})
	}
}

// TestControlAuthIsDisabledWhenNoTokenIsConfigured states the Unix contract
// rather than leaving it to be inferred: there the transport is a 0600 Unix
// socket and the file mode IS the authentication, so the wrapper must let
// everything through — including a request carrying a bogus Authorization
// header, which a browser or a confused client may well send.
//
// This is only safe because of what listener_unix.go guarantees, which
// listener_unix_test.go checks: the socket is 0600 from the instant it exists.
// If that ever stops being true, this permissiveness is the second half of the
// hole, so the two tests are worth reading together.
func TestControlAuthIsDisabledWhenNoTokenIsConfigured(t *testing.T) {
	for _, sent := range []string{"", "Bearer anything", "Basic Zm9vOmJhcg=="} {
		if got := authProbe(t, "", sent); got != http.StatusNoContent {
			t.Errorf("with no token configured, Authorization %q answered %d, want 204", sent, got)
		}
	}
}
