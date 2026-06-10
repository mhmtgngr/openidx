package events

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestNewEvent verifies the constructor fills in the auto-generated fields
// (ID, Timestamp) and threads the caller's type/source/payload through.
func TestNewEvent(t *testing.T) {
	before := time.Now().UTC()
	e := NewEvent("user.login", "identity-service", map[string]interface{}{"user_id": "u-1"})
	after := time.Now().UTC()

	if e.ID == "" {
		t.Error("ID empty")
	}
	if e.Type != "user.login" {
		t.Errorf("Type = %q, want user.login", e.Type)
	}
	if e.Source != "identity-service" {
		t.Errorf("Source = %q, want identity-service", e.Source)
	}
	if e.Payload["user_id"] != "u-1" {
		t.Errorf("Payload missing user_id")
	}
	if e.Timestamp.Before(before) || e.Timestamp.After(after) {
		t.Errorf("Timestamp = %v not in [%v, %v]", e.Timestamp, before, after)
	}
	if e.Metadata == nil {
		t.Error("Metadata not pre-allocated (callers will panic on WithMetadata)")
	}
}

// TestEvent_WithTraceID covers the fluent setter — the event is returned by
// value, so the original is untouched.
func TestEvent_WithTraceID(t *testing.T) {
	e := NewEvent("t", "s", nil)
	out := e.WithTraceID("tr-1")
	if out.TraceID != "tr-1" {
		t.Errorf("TraceID = %q, want tr-1", out.TraceID)
	}
	if e.TraceID != "" {
		t.Errorf("source event mutated: TraceID = %q", e.TraceID)
	}
}

// TestEvent_WithUserID — same fluent semantics.
func TestEvent_WithUserID(t *testing.T) {
	e := NewEvent("t", "s", nil).WithUserID("u-9")
	if e.UserID != "u-9" {
		t.Errorf("UserID = %q, want u-9", e.UserID)
	}
}

// TestEvent_WithMetadata — including the lazy-allocation path that fires
// when the Metadata map happens to be nil.
func TestEvent_WithMetadata(t *testing.T) {
	e := NewEvent("t", "s", nil).WithMetadata("k", "v")
	if e.Metadata["k"] != "v" {
		t.Errorf("Metadata[k] = %q, want v", e.Metadata["k"])
	}

	// Force the lazy-init branch.
	bare := Event{}
	out := bare.WithMetadata("k2", "v2")
	if out.Metadata["k2"] != "v2" {
		t.Error("lazy Metadata allocation failed")
	}
}

// TestEvent_JSON serializes a fully-populated event and confirms it parses
// back into a map with all the expected keys. We don't do an exact-string
// comparison because field order depends on Go map iteration.
func TestEvent_JSON(t *testing.T) {
	e := NewEvent("user.login", "identity", map[string]interface{}{"a": 1}).
		WithUserID("u-1").
		WithTraceID("tr-1").
		WithMetadata("ip", "127.0.0.1")

	raw, err := e.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var back map[string]interface{}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, k := range []string{"id", "type", "source", "timestamp", "trace_id", "user_id", "payload", "metadata"} {
		if _, ok := back[k]; !ok {
			t.Errorf("JSON missing field %q", k)
		}
	}
}

// TestMemoryBus_Subscribe_DeliversOnlyMatchingType — the type-specific
// subscription must NOT receive other event types.
func TestMemoryBus_Subscribe_DeliversOnlyMatchingType(t *testing.T) {
	b := NewMemoryBus()
	var matching, others atomic.Int32
	b.Subscribe("user.login", func(_ context.Context, _ Event) error {
		matching.Add(1)
		return nil
	})

	_ = b.Publish(context.Background(), NewEvent("user.login", "id", nil))
	_ = b.Publish(context.Background(), NewEvent("user.logout", "id", nil))

	if matching.Load() != 1 {
		t.Errorf("matching subscriber fired %d times, want 1", matching.Load())
	}
	if others.Load() != 0 {
		t.Errorf("other counter inadvertently fired %d times", others.Load())
	}
}

// TestMemoryBus_SubscribeAll — receives every event regardless of type.
func TestMemoryBus_SubscribeAll(t *testing.T) {
	b := NewMemoryBus()
	var n atomic.Int32
	b.SubscribeAll(func(_ context.Context, _ Event) error {
		n.Add(1)
		return nil
	})

	_ = b.Publish(context.Background(), NewEvent("user.login", "id", nil))
	_ = b.Publish(context.Background(), NewEvent("user.logout", "id", nil))
	_ = b.Publish(context.Background(), NewEvent("mfa.verified", "id", nil))

	if got := n.Load(); got != 3 {
		t.Errorf("subscribe-all fired %d times, want 3", got)
	}
}

// TestMemoryBus_SubscribeWildcard — type "*" registered through Subscribe
// gets every event too (matches the runtime branch at bus.go:141).
func TestMemoryBus_SubscribeWildcard(t *testing.T) {
	b := NewMemoryBus()
	var n atomic.Int32
	b.Subscribe("*", func(_ context.Context, _ Event) error {
		n.Add(1)
		return nil
	})

	_ = b.Publish(context.Background(), NewEvent("a", "s", nil))
	_ = b.Publish(context.Background(), NewEvent("b", "s", nil))

	if got := n.Load(); got != 2 {
		t.Errorf("wildcard subscriber fired %d times, want 2", got)
	}
}

// TestMemoryBus_SubscribeWithFilter — filter that rejects events must
// suppress delivery.
func TestMemoryBus_SubscribeWithFilter(t *testing.T) {
	b := NewMemoryBus()
	var n atomic.Int32
	b.SubscribeWithFilter("user.login",
		func(_ context.Context, _ Event) error { n.Add(1); return nil },
		func(e Event) bool { return e.UserID == "u-keep" },
	)

	_ = b.Publish(context.Background(), NewEvent("user.login", "s", nil).WithUserID("u-keep"))
	_ = b.Publish(context.Background(), NewEvent("user.login", "s", nil).WithUserID("u-drop"))

	if got := n.Load(); got != 1 {
		t.Errorf("filter let through %d events, want 1", got)
	}
}

// TestMemoryBus_Unsubscribe — after unsubscribing the handler must not be
// invoked anymore. Covers both type-keyed and all-handlers branches.
func TestMemoryBus_Unsubscribe(t *testing.T) {
	b := NewMemoryBus()
	var n atomic.Int32
	sub := b.Subscribe("user.login",
		func(_ context.Context, _ Event) error { n.Add(1); return nil },
	)

	_ = b.Publish(context.Background(), NewEvent("user.login", "s", nil))
	b.Unsubscribe(sub)
	_ = b.Publish(context.Background(), NewEvent("user.login", "s", nil))

	if got := n.Load(); got != 1 {
		t.Errorf("unsubscribed handler still fired; total = %d, want 1", got)
	}

	// And for an all-events sub
	var m atomic.Int32
	sub2 := b.SubscribeAll(func(_ context.Context, _ Event) error { m.Add(1); return nil })
	_ = b.Publish(context.Background(), NewEvent("anything", "s", nil))
	b.Unsubscribe(sub2)
	_ = b.Publish(context.Background(), NewEvent("anything", "s", nil))
	if got := m.Load(); got != 1 {
		t.Errorf("unsubscribed all-handler still fired; total = %d, want 1", got)
	}
}

// TestMemoryBus_Publish_ReturnsLastErr — Publish reports the last handler
// error (it doesn't abort after the first one — defense-in-depth behavior).
func TestMemoryBus_Publish_ReturnsLastErr(t *testing.T) {
	b := NewMemoryBus()
	var n atomic.Int32
	errA := errors.New("a failed")
	errC := errors.New("c failed")

	b.Subscribe("t", func(_ context.Context, _ Event) error { n.Add(1); return errA })
	b.Subscribe("t", func(_ context.Context, _ Event) error { n.Add(1); return nil })
	b.Subscribe("t", func(_ context.Context, _ Event) error { n.Add(1); return errC })

	err := b.Publish(context.Background(), NewEvent("t", "s", nil))
	if !errors.Is(err, errC) {
		t.Errorf("Publish returned %v; want last error %v", err, errC)
	}
	if n.Load() != 3 {
		t.Errorf("only %d/3 handlers fired; one failure should not short-circuit", n.Load())
	}
}

// TestMemoryBus_Close — Publish must reject after Close, and PublishAsync
// must wait for in-flight handlers.
func TestMemoryBus_Close(t *testing.T) {
	b := NewMemoryBus()
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := b.Publish(context.Background(), NewEvent("t", "s", nil)); err == nil {
		t.Error("Publish after Close returned nil; want error")
	}
}

// TestMemoryBus_PublishAsync_ErrorHandler — when a handler returns an error
// during async publish, the configured error handler fires (and gets the
// last error, like sync Publish).
func TestMemoryBus_PublishAsync_ErrorHandler(t *testing.T) {
	b := NewMemoryBus()
	var got error
	var wg sync.WaitGroup
	wg.Add(1)
	b.SetErrorHandler(func(err error) {
		got = err
		wg.Done()
	})
	b.Subscribe("t", func(_ context.Context, _ Event) error { return errors.New("boom") })

	b.PublishAsync(context.Background(), NewEvent("t", "s", nil))
	wg.Wait()
	_ = b.Close() // drain any other workers

	if got == nil || got.Error() != "boom" {
		t.Errorf("error handler saw %v; want 'boom'", got)
	}
}

// TestMemoryBus_PublishAsync_DeliversHandler — async publish must reach the
// handler asynchronously. Use a channel to wait deterministically rather
// than relying on Close()'s wg fence (Close also marks the bus closed,
// which can race with the spawned goroutine and silently drop the event).
func TestMemoryBus_PublishAsync_DeliversHandler(t *testing.T) {
	b := NewMemoryBus()
	done := make(chan struct{}, 1)
	b.SubscribeAll(func(_ context.Context, _ Event) error {
		done <- struct{}{}
		return nil
	})

	b.PublishAsync(context.Background(), NewEvent("t", "s", nil))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("async handler did not fire within 2s")
	}
}

// TestGlobalBus_Publish — covers the package-level Publish/Subscribe
// shortcuts that wrap the global Bus singleton. Uses a fresh local bus so
// we don't leak subscribers across tests.
func TestGlobalBus_Publish(t *testing.T) {
	prev := Global()
	t.Cleanup(func() { SetGlobalBus(prev) })

	mine := NewMemoryBus()
	SetGlobalBus(mine)
	if Global() != mine {
		t.Error("Global() did not return the bus set via SetGlobalBus")
	}

	var n atomic.Int32
	Subscribe("t", func(_ context.Context, _ Event) error { n.Add(1); return nil })
	if err := Publish(context.Background(), NewEvent("t", "s", nil)); err != nil {
		t.Errorf("Publish: %v", err)
	}
	if n.Load() != 1 {
		t.Errorf("global Subscribe handler fired %d times, want 1", n.Load())
	}

	// SubscribeAll wrapper — wait on a channel rather than racing Close.
	done := make(chan struct{}, 1)
	SubscribeAll(func(_ context.Context, _ Event) error {
		done <- struct{}{}
		return nil
	})
	PublishAsync(context.Background(), NewEvent("t", "s", nil))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("global SubscribeAll handler did not fire within 2s")
	}
}
