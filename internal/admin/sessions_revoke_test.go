package admin

import (
	"context"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// TestPublishSessionRevocationsWritesMarkers pins the fix for the inert admin
// revoke: flipping sessions.revoked in Postgres is invisible to enforcement,
// because the oauth-service's refresh-grant check reads only the
// "revoked_session:<id>" Redis marker (internal/oauth/service.go). The key
// format asserted here is therefore load-bearing — change it and revocation
// silently stops working again.
func TestPublishSessionRevocationsWritesMarkers(t *testing.T) {
	mini := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	defer rc.Close()

	s := &Service{
		redis:  &database.RedisClient{Client: rc},
		logger: zap.NewNop(),
	}

	ids := []string{"11111111-aaaa-bbbb-cccc-000000000001", "11111111-aaaa-bbbb-cccc-000000000002"}
	warnings := s.publishSessionRevocations(context.Background(), ids)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}

	for _, id := range ids {
		key := "revoked_session:" + id
		val, err := mini.Get(key)
		if err != nil {
			t.Fatalf("marker %s not written: %v", key, err)
		}
		if val != "1" {
			t.Errorf("marker %s = %q, want \"1\"", key, val)
		}
		// The marker must expire on its own, but only after any refresh token
		// minted for the session could still be alive.
		ttl := mini.TTL(key)
		if ttl <= 0 {
			t.Errorf("marker %s has no TTL; it would live forever", key)
		}
		if ttl != revokedSessionMarkerTTL {
			t.Errorf("marker %s TTL = %v, want %v", key, ttl, revokedSessionMarkerTTL)
		}
	}
}

// TestPublishSessionRevocationsReportsFailures: the whole defect being fixed
// was a revoke that reported success while enforcement never heard about it.
// So when the marker write fails, the caller must get a warning to surface —
// a clean response would recreate the original bug one layer down.
func TestPublishSessionRevocationsReportsFailures(t *testing.T) {
	mini := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mini.Addr(), MaxRetries: -1})
	defer rc.Close()
	mini.Close() // markers can no longer be written

	s := &Service{
		redis:  &database.RedisClient{Client: rc},
		logger: zap.NewNop(),
	}

	warnings := s.publishSessionRevocations(context.Background(), []string{"dead-1", "dead-2"})
	if len(warnings) != 2 {
		t.Fatalf("expected one warning per failed marker, got %d: %v", len(warnings), warnings)
	}
	for _, w := range warnings {
		if !strings.Contains(w, "refresh tokens") {
			t.Errorf("warning %q does not say what the operator is exposed to", w)
		}
	}
}

// TestScrubLogValueCutsCRLF: session and user ids in the revoke handlers come
// from the URL path, so they are attacker-typeable; a CR/LF smuggled into one
// must not forge extra log lines.
func TestScrubLogValueCutsCRLF(t *testing.T) {
	in := "abc\r\nFAKE level=info msg=owned\rdef\n"
	if got := scrubLogValue(in); got != "abcFAKE level=info msg=owneddef" {
		t.Errorf("scrubLogValue(%q) = %q; CR/LF must be removed entirely", in, got)
	}
	if got := scrubLogValue("plain-uuid"); got != "plain-uuid" {
		t.Errorf("clean values must pass through unchanged, got %q", got)
	}
}

// TestPublishSessionRevocationsNilRedis: a Service constructed without Redis
// (tests, degraded boot) must warn rather than panic or stay silent.
func TestPublishSessionRevocationsNilRedis(t *testing.T) {
	s := &Service{logger: zap.NewNop()}

	warnings := s.publishSessionRevocations(context.Background(), []string{"x"})
	if len(warnings) != 1 {
		t.Fatalf("expected exactly one warning for unavailable redis, got %v", warnings)
	}

	if got := s.publishSessionRevocations(context.Background(), nil); got != nil {
		t.Errorf("no sessions should mean no warnings, got %v", got)
	}
}
