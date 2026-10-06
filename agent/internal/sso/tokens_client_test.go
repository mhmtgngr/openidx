package sso

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// tokenServer answers /oauth/token with status and body and records the form.
func tokenServer(t *testing.T, status int, body string) (*httptest.Server, *url.Values) {
	t.Helper()
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		form = r.Form
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &form
}

// TestASessionRecordsTheClientItWasIssuedTo: the tokens remember the client_id
// the exchange presented, so a later refresh or revocation presents the same.
func TestASessionRecordsTheClientItWasIssuedTo(t *testing.T) {
	srv, form := tokenServer(t, http.StatusOK,
		`{"access_token":"at2","refresh_token":"rt2","expires_in":3600,"token_type":"Bearer"}`)
	tok, err := RefreshWithClient(context.Background(), srv.URL, "rt1", DesktopClientID)
	if err != nil {
		t.Fatalf("RefreshWithClient: %v", err)
	}
	if form.Get("client_id") != DesktopClientID {
		t.Fatalf("presented client_id %q", form.Get("client_id"))
	}
	if tok.ClientID != DesktopClientID {
		t.Fatalf("ClientID = %q, want %s", tok.ClientID, DesktopClientID)
	}
	if tok.ClientOr(MobileClientID) != DesktopClientID {
		t.Fatal("ClientOr must prefer the recorded client")
	}
	legacy := &Tokens{AccessToken: "at"}
	if legacy.ClientOr(MobileClientID) != MobileClientID {
		t.Fatal("a session without a recorded client falls back to the caller's")
	}
	var nilTok *Tokens
	if nilTok.ClientOr(DesktopClientID) != DesktopClientID {
		t.Fatal("ClientOr on nil is the fallback")
	}
}

// TestARejectedRefreshIsTyped: a 400 (invalid_grant) means the refresh token
// is dead; a 503 means nothing about it.
func TestARejectedRefreshIsTyped(t *testing.T) {
	srv, _ := tokenServer(t, http.StatusBadRequest, `{"error":"invalid_grant"}`)
	_, err := RefreshWithClient(context.Background(), srv.URL, "rt-dead", DesktopClientID)
	var te *TokenError
	if !errors.As(err, &te) {
		t.Fatalf("want *TokenError, got %T: %v", err, err)
	}
	if !te.Rejected() || te.Status != 400 || te.Body != `{"error":"invalid_grant"}` {
		t.Fatalf("TokenError = %+v", *te)
	}

	srv2, _ := tokenServer(t, http.StatusServiceUnavailable, "")
	_, err = RefreshWithClient(context.Background(), srv2.URL, "rt", DesktopClientID)
	if !errors.As(err, &te) || te.Rejected() {
		t.Fatalf("a 503 is not a rejection: %v", err)
	}
}
