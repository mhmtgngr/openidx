package events

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewEvent(t *testing.T) {
	payload := map[string]interface{}{"key": "value"}
	event := NewEvent("user.created", "identity-service", payload)

	if event.ID == "" {
		t.Error("expected non-empty ID")
	}
	if event.Type != "user.created" {
		t.Errorf("expected type 'user.created', got %q", event.Type)
	}
	if event.Source != "identity-service" {
		t.Errorf("expected source 'identity-service', got %q", event.Source)
	}
	if event.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
	if event.Payload["key"] != "value" {
		t.Error("expected payload key=value")
	}
}

func TestEventChaining(t *testing.T) {
	event := NewEvent("test", "src", nil).
		WithTraceID("trace-123").
		WithUserID("user-456").
		WithMetadata("env", "test")

	if event.TraceID != "trace-123" {
		t.Errorf("expected traceID 'trace-123', got %q", event.TraceID)
	}
	if event.UserID != "user-456" {
		t.Errorf("expected userID 'user-456', got %q", event.UserID)
	}
	if event.Metadata["env"] != "test" {
		t.Error("expected metadata env=test")
	}
}

func TestEventJSON(t *testing.T) {
	event := NewEvent("test.event", "test", map[string]interface{}{"count": 42})
	data, err := event.JSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestMemoryBusPublishSubscribe(t *testing.T) {
	bus := NewMemoryBus()
	defer bus.Close()

	var received int32
	bus.Subscribe("test.event", func(ctx context.Context, event Event) error {
		atomic.AddInt32(&received, 1)
		return nil
	})

	event := NewEvent("test.event", "test", nil)
	if err := bus.Publish(context.Background(), event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("expected 1 event received, got %d", received)
	}
}

func TestMemoryBusSubscribeAll(t *testing.T) {
	bus := NewMemoryBus()
	defer bus.Close()

	var received int32
	bus.SubscribeAll(func(ctx context.Context, event Event) error {
		atomic.AddInt32(&received, 1)
		return nil
	})

	bus.Publish(context.Background(), NewEvent("type.a", "test", nil))
	bus.Publish(context.Background(), NewEvent("type.b", "test", nil))

	if atomic.LoadInt32(&received) != 2 {
		t.Errorf("expected 2 events received, got %d", received)
	}
}

func TestMemoryBusSubscribeWithFilter(t *testing.T) {
	bus := NewMemoryBus()
	defer bus.Close()

	var received int32
	bus.SubscribeWithFilter("test.event", func(ctx context.Context, event Event) error {
		atomic.AddInt32(&received, 1)
		return nil
	}, func(e Event) bool {
		return e.UserID == "target-user"
	})

	// Should be filtered out
	bus.Publish(context.Background(), NewEvent("test.event", "test", nil).WithUserID("other"))
	// Should pass filter
	bus.Publish(context.Background(), NewEvent("test.event", "test", nil).WithUserID("target-user"))

	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("expected 1 event (filtered), got %d", received)
	}
}

func TestMemoryBusUnsubscribe(t *testing.T) {
	bus := NewMemoryBus()
	defer bus.Close()

	var received int32
	sub := bus.Subscribe("test.event", func(ctx context.Context, event Event) error {
		atomic.AddInt32(&received, 1)
		return nil
	})

	bus.Publish(context.Background(), NewEvent("test.event", "test", nil))
	bus.Unsubscribe(sub)
	bus.Publish(context.Background(), NewEvent("test.event", "test", nil))

	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("expected 1 event after unsubscribe, got %d", received)
	}
}

func TestMemoryBusClose(t *testing.T) {
	bus := NewMemoryBus()

	if err := bus.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := bus.Publish(context.Background(), NewEvent("test", "test", nil))
	if err == nil {
		t.Error("expected error publishing to closed bus")
	}
}

func TestMemoryBusPublishAsync(t *testing.T) {
	bus := NewMemoryBus()

	var received int32
	bus.Subscribe("async.event", func(ctx context.Context, event Event) error {
		atomic.AddInt32(&received, 1)
		return nil
	})

	bus.PublishAsync(context.Background(), NewEvent("async.event", "test", nil))

	// Give the goroutine time to complete before checking
	time.Sleep(50 * time.Millisecond)

	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("expected 1 async event received, got %d", received)
	}

	bus.Close()
}

func TestEventConstants(t *testing.T) {
	// Verify important event constants are non-empty and well-formed
	constants := []string{
		EventUserCreated, EventUserLogin, EventUserLoginFailed,
		EventMFAEnabled, EventMFAVerified,
		EventSessionCreated, EventSessionRevoked,
		EventGroupCreated, EventRoleAssigned,
		EventSecurityAlert, EventImpossibleTravel,
		EventSystemStartup, EventSystemShutdown,
	}
	for _, c := range constants {
		if c == "" {
			t.Error("expected non-empty event constant")
		}
	}
}

func TestWithMetadataNilMap(t *testing.T) {
	event := Event{Type: "test"}
	event = event.WithMetadata("key", "value")

	if event.Metadata == nil {
		t.Error("expected non-nil metadata after WithMetadata")
	}
	if event.Metadata["key"] != "value" {
		t.Error("expected metadata key=value")
	}
}

func TestNewEventTimestampUTC(t *testing.T) {
	event := NewEvent("test", "src", nil)
	if event.Timestamp.Location() != time.UTC {
		t.Error("expected UTC timestamp")
	}
}
