package access

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestDesiredRouteHostingModeNormalization(t *testing.T) {
	if got := (DesiredRoute{HostingMode: "identity", BrowZerEnabled: true}).EffectiveMode(); got != "direct" {
		t.Fatalf("browzer route should be direct, got %q", got)
	}
	if got := (DesiredRoute{HostingMode: "identity"}).EffectiveMode(); got != "identity" {
		t.Fatalf("expected identity, got %q", got)
	}
	if got := (DesiredRoute{}).EffectiveMode(); got != "identity" {
		t.Fatalf("expected identity default, got %q", got)
	}
	if got := (DesiredRoute{HostingMode: "direct"}).EffectiveMode(); got != "direct" {
		t.Fatalf("expected direct, got %q", got)
	}
}

func TestReconcilerCoalescesAndSerializes(t *testing.T) {
	var runs int32
	rec := newTestReconciler(func() { atomic.AddInt32(&runs, 1); time.Sleep(20 * time.Millisecond) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec.Start(ctx)
	for i := 0; i < 50; i++ {
		rec.Enqueue()
	}
	time.Sleep(150 * time.Millisecond)
	if n := atomic.LoadInt32(&runs); n == 0 || n > 8 {
		t.Fatalf("expected a small coalesced number of runs, got %d", n)
	}
}

func newTestReconciler(run func()) *ZitiReconciler {
	rec := &ZitiReconciler{
		logger:  zap.NewNop(),
		period:  time.Hour, // disable periodic in this test
		trigger: make(chan struct{}, 1),
		status:  make(map[string]string),
	}
	rec.runOnce = func(context.Context) { run() }
	return rec
}
