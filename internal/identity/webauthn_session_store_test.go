package identity

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// TestWebAuthnSessionSurvivesReplicaHop pins the fix for the caveat that made
// passkeys break past one replica: the challenge used to live only in the
// sync.Map of the replica that began the ceremony, so a finish request served
// by any other replica failed. Two Service instances sharing one Redis stand
// in for two replicas behind a load balancer.
func TestWebAuthnSessionSurvivesReplicaHop(t *testing.T) {
	mini := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	defer rc.Close()
	shared := &database.RedisClient{Client: rc}

	replicaA := &Service{redis: shared, logger: zap.NewNop()}
	replicaB := &Service{redis: shared, logger: zap.NewNop()}
	ctx := context.Background()

	replicaA.storeWebAuthnSession(ctx, "u1", "registration", `{"challenge":"abc"}`)

	got, err := replicaB.getWebAuthnSession(ctx, "u1", "registration")
	if err != nil {
		t.Fatalf("ceremony begun on replica A must be completable on replica B: %v", err)
	}
	if got != `{"challenge":"abc"}` {
		t.Errorf("session data = %q, want the stored challenge", got)
	}

	// Challenges must expire on their own rather than accumulate.
	if ttl := mini.TTL(webauthnSessionKey("u1", "registration")); ttl <= 0 || ttl > webauthnSessionTTL {
		t.Errorf("redis TTL = %v, want (0, %v]", ttl, webauthnSessionTTL)
	}

	// Deleting on either replica ends the ceremony everywhere.
	replicaB.deleteWebAuthnSession(ctx, "u1", "registration")
	if _, err := replicaA.getWebAuthnSession(ctx, "u1", "registration"); err == nil {
		t.Error("deleted session must not be retrievable from another replica")
	}
}

// TestWebAuthnSessionMemoryFallback: a Service without Redis (tests, degraded
// boot) keeps working on a single replica, and the fallback entries now carry
// an expiry instead of living forever.
func TestWebAuthnSessionMemoryFallback(t *testing.T) {
	s := &Service{logger: zap.NewNop()}
	ctx := context.Background()

	s.storeWebAuthnSession(ctx, "u2", "login", "payload")
	if got, err := s.getWebAuthnSession(ctx, "u2", "login"); err != nil || got != "payload" {
		t.Fatalf("memory fallback round-trip failed: %q, %v", got, err)
	}
	s.deleteWebAuthnSession(ctx, "u2", "login")
	if _, err := s.getWebAuthnSession(ctx, "u2", "login"); err == nil {
		t.Error("deleted fallback session must not be retrievable")
	}

	// An expired entry is treated as absent and purged on read.
	s.webauthnSessions.Store("u2:login",
		webauthnMemSession{data: "stale", expiresAt: time.Now().Add(-time.Second)})
	if _, err := s.getWebAuthnSession(ctx, "u2", "login"); err == nil {
		t.Error("expired fallback session must not be returned")
	}
	if _, still := s.webauthnSessions.Load("u2:login"); still {
		t.Error("expired fallback session must be purged on read")
	}

	// Concurrency smoke: the map is shared state on a hot login path.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.storeWebAuthnSession(ctx, "u3", "login", "x")
			_, _ = s.getWebAuthnSession(ctx, "u3", "login")
			s.deleteWebAuthnSession(ctx, "u3", "login")
		}()
	}
	wg.Wait()
}
