package access

import (
	"context"
	"sync"
	"testing"
)

func TestZitiProvider_NilWhenEmpty(t *testing.T) {
	p := NewZitiProvider()
	if p.Get() != nil {
		t.Fatal("empty provider should return nil")
	}
	// Disconnect (Swap nil) on an empty provider must not panic.
	p.Swap(nil, nil)
	if p.Get() != nil {
		t.Fatal("after Swap(nil) Get should be nil")
	}
}

// Race the lock-free Get() against concurrent Swap()s — `go test -race` must be
// clean (this is the core concurrency guarantee of the runtime-reconnect path).
func TestZitiProvider_GetSwapRace(t *testing.T) {
	p := NewZitiProvider()
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = p.Get()
				}
			}
		}()
	}
	// Swapper: alternates between a sentinel manager and nil. We use a non-nil
	// *ZitiManager pointer (zero value) only as an identity — Get/Swap never
	// dereference it here.
	wg.Add(1)
	go func() {
		defer wg.Done()
		zm := &ZitiManager{}
		for i := 0; i < 2000; i++ {
			if i%2 == 0 {
				p.Swap(zm, func() {})
			} else {
				p.Swap(nil, nil)
			}
		}
		close(stop)
	}()
	wg.Wait()
}

func TestZitiProvider_StoreVisible(t *testing.T) {
	p := NewZitiProvider()
	zm := &ZitiManager{}
	p.Store(zm)
	if p.Get() != zm {
		t.Fatal("Store should make the manager visible to Get")
	}
	_ = context.Background()
}
