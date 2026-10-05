package desktoppam

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// connectServer answers the connect route with the given status and body.
func connectServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/connect") {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAStaleSecondFactorIsStepUpNotApproval(t *testing.T) {
	srv := connectServer(t, http.StatusForbidden,
		`{"error":"step_up_required","error_description":"this action requires a recently verified second factor","challenge_url":"/oauth/stepup-challenge"}`)
	_, err := Connect(context.Background(), srv.URL, "tok", "e1")
	if !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("want ErrStepUpRequired, got %v", err)
	}
	if errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("a stale factor must not be reported as approval required: %v", err)
	}
	if msg := UserMessage(err); !strings.Contains(msg, "second factor") {
		t.Fatalf("the user message must say what to do about the factor, got %q", msg)
	}
}

func TestAnUnapprovedEntryIsApprovalRequired(t *testing.T) {
	for _, body := range []string{
		`{"error":"session requires approval","approval_required":true}`,
		`{"error":"session requires approval"}`,
	} {
		srv := connectServer(t, http.StatusForbidden, body)
		_, err := Connect(context.Background(), srv.URL, "tok", "e1")
		if !errors.Is(err, ErrApprovalRequired) {
			t.Fatalf("body %s: want ErrApprovalRequired, got %v", body, err)
		}
		if msg := UserMessage(err); !strings.Contains(msg, "access request") {
			t.Fatalf("body %s: user message %q", body, msg)
		}
	}
}

func TestAnyOtherRefusalKeepsTheServersReason(t *testing.T) {
	srv := connectServer(t, http.StatusForbidden,
		`{"error":"this entry is reachable only over the overlay","code":"ztna_required_direct_reach"}`)
	_, err := Connect(context.Background(), srv.URL, "tok", "e1")
	if errors.Is(err, ErrApprovalRequired) || errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("an overlay refusal is neither approval nor step-up: %v", err)
	}
	var ref *Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("want a *Refusal, got %T: %v", err, err)
	}
	if ref.Status != 403 || ref.Code != "ztna_required_direct_reach" || !strings.Contains(ref.Detail, "overlay") {
		t.Fatalf("Refusal = %+v", *ref)
	}
	if msg := UserMessage(err); !strings.Contains(msg, "overlay") {
		t.Fatalf("the user must see the server's reason, got %q", msg)
	}
}

func TestARefusedTokenIsNotSignedIn(t *testing.T) {
	srv := connectServer(t, http.StatusForbidden, `{}`)
	_, err := Connect(context.Background(), srv.URL, "wrong", "e1")
	if !errors.Is(err, ErrNotSignedIn) {
		t.Fatalf("a 401 must say the session is over, got %v", err)
	}
	if msg := UserMessage(err); !strings.Contains(msg, "Sign in") {
		t.Fatalf("user message %q", msg)
	}
}

func TestANonJSONRefusalStillCarriesTheStatus(t *testing.T) {
	srv := connectServer(t, http.StatusBadGateway, "<html>bad gateway</html>")
	_, err := Connect(context.Background(), srv.URL, "tok", "e1")
	var ref *Refusal
	if !errors.As(err, &ref) || ref.Status != 502 {
		t.Fatalf("want a 502 Refusal, got %v", err)
	}
	if msg := UserMessage(err); !strings.Contains(msg, "502") {
		t.Fatalf("user message %q", msg)
	}
}

func TestASuccessfulConnectIsReturned(t *testing.T) {
	// No url in the answer, so nothing tries to open a browser from the test.
	srv := connectServer(t, http.StatusOK, `{"launch_type":"guacamole","entry_id":"e1","session_id":"s1"}`)
	res, err := Connect(context.Background(), srv.URL, "tok", "e1")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if res.SessionID != "s1" || res.LaunchType != "guacamole" {
		t.Fatalf("ConnectResult = %+v", *res)
	}
	if UserMessage(nil) != "" {
		t.Fatal("no error, no message")
	}
}
