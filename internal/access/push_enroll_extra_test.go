package access

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/pushenroll"
)

// mintPushEnrollExtra is the FastPass seam: at enrollment it mints a push-enroll
// ticket bound to the enrolled device. These tests pin the contract the client
// depends on and the security invariant that trust flows only from the caller-
// supplied (server-verified) decision, never fabricated.

func newRedisHandler(t *testing.T) (*AgentAPIHandler, *redis.Client) {
	t.Helper()
	mini := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	h := &AgentAPIHandler{logger: zap.NewNop()}
	h.SetRedis(rc)
	return h, rc
}

func TestMintPushEnrollExtra_CarriesLinkageAndTrust(t *testing.T) {
	ctx := context.Background()
	h, rc := newRedisHandler(t)

	sess := &enrollmentSession{ID: "sess-1", CreatedByUID: "user-1", OrgID: "org-1", MFAVerified: true}
	creds := issuedAgentCredentials{AgentID: "agent-1", DeviceID: "device-1"}

	extra := h.mintPushEnrollExtra(ctx, sess, creds, true)
	if extra == nil {
		t.Fatal("expected push-enroll extra, got nil")
	}
	if extra["push_enroll_path"] != pushEnrollCompletePath {
		t.Fatalf("wrong path: %v", extra["push_enroll_path"])
	}
	tok, _ := extra["push_enroll_token"].(string)
	if tok == "" {
		t.Fatal("missing push_enroll_token")
	}

	got, err := pushenroll.Peek(ctx, rc, tok)
	if err != nil {
		t.Fatalf("Peek minted ticket: %v", err)
	}
	want := pushenroll.TicketData{
		UserID: "user-1", OrgID: "org-1", Trusted: true,
		AgentID: "agent-1", DeviceID: "device-1", EnrollmentSessionID: "sess-1",
	}
	if got != want {
		t.Fatalf("ticket mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestMintPushEnrollExtra_UntrustedStaysUntrusted(t *testing.T) {
	ctx := context.Background()
	h, rc := newRedisHandler(t)

	// Even with MFAVerified true on the session, the ticket's Trusted reflects the
	// decision passed in (the caller's decideAutoTrust result), not the raw MFA
	// flag — so a non-enforce/non-allowlisted org yields an untrusted approver.
	sess := &enrollmentSession{ID: "s", CreatedByUID: "u", OrgID: "o", MFAVerified: true}
	extra := h.mintPushEnrollExtra(ctx, sess, issuedAgentCredentials{AgentID: "a", DeviceID: "d"}, false)
	tok := extra["push_enroll_token"].(string)
	got, err := pushenroll.Peek(ctx, rc, tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Trusted {
		t.Fatal("ticket must be untrusted when the auto-trust decision was false")
	}
}

func TestMintPushEnrollExtra_NoRedisIsGraceful(t *testing.T) {
	h := &AgentAPIHandler{logger: zap.NewNop()} // no redis wired
	extra := h.mintPushEnrollExtra(context.Background(),
		&enrollmentSession{ID: "s", CreatedByUID: "u", OrgID: "o"},
		issuedAgentCredentials{AgentID: "a", DeviceID: "d"}, true)
	if extra != nil {
		t.Fatalf("expected nil extra when redis is absent, got %v", extra)
	}
}
