package leader

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/testutil"
)

func TestIsLeaderForTick_NilClient_AlwaysRuns(t *testing.T) {
	// Single-instance / dev: no Redis → run unconditionally.
	for i := 0; i < 3; i++ {
		if !IsLeaderForTick(context.Background(), nil, "job", time.Minute) {
			t.Fatalf("nil client should always be leader (iteration %d)", i)
		}
	}
}

func TestIsLeaderForTick_OnlyOneWinsPerBucket(t *testing.T) {
	mr := testutil.NewMockRedis(zap.NewNop())
	if err := mr.Setup(); err != nil {
		t.Fatalf("miniredis setup: %v", err)
	}
	defer mr.Shutdown() //nolint:errcheck
	rdb := mr.Client()
	ctx := context.Background()

	// First call in the bucket wins; subsequent calls (same bucket) lose —
	// this is what stops N replicas from each running the same tick.
	if !IsLeaderForTick(ctx, rdb, "sweep", time.Hour) {
		t.Fatal("first caller should win the bucket")
	}
	for i := 0; i < 5; i++ {
		if IsLeaderForTick(ctx, rdb, "sweep", time.Hour) {
			t.Fatalf("a second caller won the same bucket (iteration %d)", i)
		}
	}

	// A different job name is an independent lock.
	if !IsLeaderForTick(ctx, rdb, "other", time.Hour) {
		t.Fatal("a different job name should win its own bucket")
	}
}

func TestIsLeaderForTick_NewBucketAllowsRunAgain(t *testing.T) {
	mr := testutil.NewMockRedis(zap.NewNop())
	if err := mr.Setup(); err != nil {
		t.Fatalf("miniredis setup: %v", err)
	}
	defer mr.Shutdown() //nolint:errcheck
	rdb := mr.Client()
	ctx := context.Background()

	// Use a tiny interval so the time bucket rolls over within the test.
	interval := time.Second
	if !IsLeaderForTick(ctx, rdb, "rollover", interval) {
		t.Fatal("first bucket should win")
	}
	// Within the same second, a second call loses.
	if IsLeaderForTick(ctx, rdb, "rollover", interval) {
		t.Fatal("same bucket should not win twice")
	}
	// After the bucket rolls over, a call wins again.
	time.Sleep(1100 * time.Millisecond)
	if !IsLeaderForTick(ctx, rdb, "rollover", interval) {
		t.Fatal("next bucket should win again")
	}
}

func TestRunPeriodic_StopsOnContextCancel(t *testing.T) {
	mr := testutil.NewMockRedis(zap.NewNop())
	if err := mr.Setup(); err != nil {
		t.Fatalf("miniredis setup: %v", err)
	}
	defer mr.Shutdown() //nolint:errcheck

	ctx, cancel := context.WithCancel(context.Background())
	runs := make(chan struct{}, 16)
	RunPeriodic(ctx, mr.Client(), zap.NewNop(), "tick", 20*time.Millisecond, func(context.Context) {
		runs <- struct{}{}
	})

	// Should fire at least once.
	select {
	case <-runs:
	case <-time.After(2 * time.Second):
		t.Fatal("periodic job never ran")
	}

	cancel()
	// Drain, then confirm it stops producing.
	time.Sleep(80 * time.Millisecond)
	for {
		select {
		case <-runs:
			continue
		default:
		}
		break
	}
	select {
	case <-runs:
		t.Fatal("periodic job kept running after context cancel")
	case <-time.After(100 * time.Millisecond):
	}
}
