package access

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// A watch ticket opens one socket, for the session, sponsor and organization
// it was minted for, within its minute -- and is spent by any attempt, so one
// presented wrongly cannot be retried rightly.
func TestWatchTicketsAreOneUseBoundAndShortLived(t *testing.T) {
	var s watchTicketStore
	now := time.Now()
	mint := func() string {
		t.Helper()
		tok, err := s.mint("sess", "user", "org", now)
		if err != nil || len(tok) < 40 {
			t.Fatalf("mint = %q, %v", tok, err)
		}
		return tok
	}

	tok := mint()
	if !s.consume(tok, "sess", "user", "org", now.Add(59*time.Second)) {
		t.Fatal("a fresh ticket for the right session, user and org was refused")
	}
	if s.consume(tok, "sess", "user", "org", now) {
		t.Fatal("a ticket opened a second socket")
	}

	for name, try := range map[string]func(string) bool{
		"another session":      func(k string) bool { return s.consume(k, "other", "user", "org", now) },
		"another user":         func(k string) bool { return s.consume(k, "sess", "other", "org", now) },
		"another organization": func(k string) bool { return s.consume(k, "sess", "user", "other", now) },
		"after its minute":     func(k string) bool { return s.consume(k, "sess", "user", "org", now.Add(watchTicketTTL)) },
	} {
		k := mint()
		if try(k) {
			t.Fatalf("a ticket was accepted for %s", name)
		}
		if s.consume(k, "sess", "user", "org", now) {
			t.Fatalf("a ticket refused for %s was still good afterwards", name)
		}
	}
	if s.consume("", "sess", "user", "org", now) {
		t.Fatal("no ticket was accepted")
	}

	// Expired tickets do not pile up: minting prunes them.
	mint()
	if _, err := s.mint("sess", "user", "org", now.Add(2*watchTicketTTL)); err != nil {
		t.Fatal(err)
	}
	if len(s.tickets) != 1 {
		t.Fatalf("%d tickets held after the old ones expired, want 1", len(s.tickets))
	}
}

// WHICH action, not just whether. The census (stepup_route_census_test.go)
// proves both sponsor writes carry a freshness gate, but not that the watch
// ticket is gated under remote_support.sponsor_watch and the end under
// remote_support.sponsor_end_session: swapped, both stay gated and every
// step-up record names the wrong act. This pins the mount line.
func TestTheSponsorWatchTicketCarriesItsOwnStepUpAction(t *testing.T) {
	b, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	const want = `RegisterRemoteSupportSponsorRoutes(api, svc.requireFreshMFA("remote_support.sponsor_watch"), svc.requireFreshMFA("remote_support.sponsor_end_session"))`
	if !strings.Contains(string(b), want) {
		t.Fatalf("service.go does not mount the sponsor's remote-support routes as\n  %s\n"+
			"The first gate is what a sponsor needs to mint a watch ticket; the second, to end the session.", want)
	}
}

// The watch step-up is the gate on watch-ticket, and only there: the end
// route takes the other one, and the socket and the list take neither.
func TestTheWatchStepUpGuardsTheTicketRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewRemoteSupportHandler(zap.NewNop(), nil, nil)
	r := gin.New()
	watchGate := func(c *gin.Context) { c.AbortWithStatus(http.StatusTeapot) }
	endGate := func(c *gin.Context) { c.AbortWithStatus(http.StatusPaymentRequired) }
	h.RegisterRemoteSupportSponsorRoutes(r.Group(""), watchGate, endGate)
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/remote-support/sponsored/sessions/x/watch-ticket", http.StatusTeapot},
		{http.MethodPost, "/remote-support/sponsored/sessions/x/end", http.StatusPaymentRequired},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.want {
			t.Fatalf("%s %s = %d, want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
}
