package pushenroll

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	mini := miniredis.RunT(t)
	return redis.NewClient(&redis.Options{Addr: mini.Addr()})
}

func TestMintPeekConsumeRoundTrip(t *testing.T) {
	ctx := context.Background()
	rc := newTestRedis(t)

	in := TicketData{
		UserID:              "user-1",
		OrgID:               "org-1",
		Trusted:             true,
		AgentID:             "agent-1",
		DeviceID:            "device-1",
		EnrollmentSessionID: "sess-1",
	}
	tok, err := Mint(ctx, rc, in, DefaultTTL)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok == "" {
		t.Fatal("Mint returned empty token")
	}

	got, err := Peek(ctx, rc, tok)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if got != in {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, in)
	}

	// Peek must NOT consume — a second Peek still succeeds.
	if _, err := Peek(ctx, rc, tok); err != nil {
		t.Fatalf("second Peek should still find the ticket: %v", err)
	}

	// Consume makes it single-use.
	if err := Consume(ctx, rc, tok); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if _, err := Peek(ctx, rc, tok); err == nil {
		t.Fatal("Peek after Consume should fail (ticket must be single-use)")
	}
}

func TestMintUniqueTokens(t *testing.T) {
	ctx := context.Background()
	rc := newTestRedis(t)
	d := TicketData{UserID: "u", OrgID: "o"}
	a, err := Mint(ctx, rc, d, DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Mint(ctx, rc, d, DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two mints produced identical tokens; tokens must be high-entropy unique")
	}
}

func TestMintZeroTTLFallsBackToDefault(t *testing.T) {
	ctx := context.Background()
	rc := newTestRedis(t)
	tok, err := Mint(ctx, rc, TicketData{UserID: "u", OrgID: "o"}, 0)
	if err != nil {
		t.Fatalf("Mint with zero ttl: %v", err)
	}
	ttl := rc.TTL(ctx, KeyPrefix+tok).Val()
	if ttl <= 0 || ttl > DefaultTTL {
		t.Fatalf("expected a positive TTL <= DefaultTTL, got %v", ttl)
	}
}

func TestPeekMissingTicket(t *testing.T) {
	rc := newTestRedis(t)
	if _, err := Peek(context.Background(), rc, "does-not-exist"); err == nil {
		t.Fatal("Peek of a missing ticket should error")
	}
}

func TestNilRedisIsGraceful(t *testing.T) {
	ctx := context.Background()
	if _, err := Mint(ctx, nil, TicketData{UserID: "u", OrgID: "o"}, DefaultTTL); err == nil {
		t.Fatal("Mint with nil redis should error")
	}
	if _, err := Peek(ctx, nil, "x"); err == nil {
		t.Fatal("Peek with nil redis should error")
	}
	// Consume with nil redis is a no-op (nothing to delete), not an error.
	if err := Consume(ctx, nil, "x"); err != nil {
		t.Fatalf("Consume with nil redis should be a no-op, got %v", err)
	}
}

func TestExpiredTicketNotBindable(t *testing.T) {
	ctx := context.Background()
	mini := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mini.Addr()})

	tok, err := Mint(ctx, rc, TicketData{UserID: "u", OrgID: "o"}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Fast-forward past the TTL.
	mini.FastForward(31 * time.Second)
	if _, err := Peek(ctx, rc, tok); err == nil {
		t.Fatal("expired ticket must not be readable")
	}
}
