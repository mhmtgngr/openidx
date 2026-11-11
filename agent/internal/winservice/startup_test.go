package winservice

import (
	"sync"
	"testing"
	"time"
)

// TestStartupReportsRunningBeforeSlowWork: the Running report must not wait on
// any startup work, even work that never returns.
func TestStartupReportsRunningBeforeSlowWork(t *testing.T) {
	var mu sync.Mutex
	var order []string
	block := make(chan struct{})
	defer close(block)
	started := make(chan struct{})

	done := make(chan struct{})
	go func() {
		startupSequence(
			func() { mu.Lock(); order = append(order, "running"); mu.Unlock() },
			func() { mu.Lock(); order = append(order, "work"); mu.Unlock(); close(started); <-block },
		)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("startupSequence blocked on slow work")
	}
	<-started
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "running" {
		t.Fatalf("order = %v, want running first", order)
	}
}
