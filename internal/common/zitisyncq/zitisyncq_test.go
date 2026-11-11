package zitisyncq

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRequestDedupAndDrain(t *testing.T) {
	m := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: m.Addr()})
	ctx := context.Background()

	Request(ctx, rc, "u1")
	Request(ctx, rc, "u1") // debounced
	Request(ctx, rc, "u2")
	Request(ctx, nil, "u3") // nil-safe

	got := Drain(ctx, rc, 10)
	if len(got) != 2 {
		t.Fatalf("drain = %v, want 2 unique ids", got)
	}
	if again := Drain(ctx, rc, 10); len(again) != 0 {
		t.Fatalf("queue not emptied: %v", again)
	}
	// Still debounced: an immediate re-request does not re-queue.
	Request(ctx, rc, "u1")
	if again := Drain(ctx, rc, 10); len(again) != 0 {
		t.Fatalf("debounce ignored: %v", again)
	}
	m.FastForward(Debounce + 1)
	Request(ctx, rc, "u1")
	if again := Drain(ctx, rc, 10); len(again) != 1 {
		t.Fatalf("expected re-queue after debounce: %v", again)
	}
}
