package audit

import (
	"context"
	"testing"
	"time"

	"github.com/openidx/openidx/pkg/storage"
)

func TestAuditLogger_LogEvent(t *testing.T) {
	store := storage.NewMemoryAppendOnlyStore()
	logger := NewAuditLogger(store)

	ctx := context.Background()
	event := AuditEventForTest{
		EventType:    "authentication",
		ActorID:      "user-123",
		ActorType:    "user",
		ResourceID:   "resource-456",
		ResourceType: "api",
		Action:       "login",
		Metadata: map[string]interface{}{
			"ip":        "192.168.1.1",
			"user_agent": "Mozilla/5.0",
		},
	}

	err := logger.LogEvent(ctx, event)
	if err != nil {
		t.Fatalf("LogEvent failed: %v", err)
	}

	// Verify event was logged
	events, _ := logger.GetAllEvents(ctx)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// Verify ID was generated
	if events[0].ID == "" {
		t.Error("expected ID to be generated")
	}

	// Verify timestamp was set
	if events[0].Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}

	// Verify checksum was computed
	if events[0].Checksum == "" {
		t.Error("expected checksum to be computed")
	}
}

func TestAuditLogger_LogEventChain(t *testing.T) {
	store := storage.NewMemoryAppendOnlyStore()
	logger := NewAuditLogger(store)

	ctx := context.Background()

	// Log multiple events
	for i := 0; i < 5; i++ {
		event := AuditEventForTest{
			EventType:    "test",
			ActorID:      "user-123",
			ResourceID:   "resource-456",
			Action:       "action",
			Metadata:     map[string]interface{}{"index": i},
		}
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("LogEvent %d failed: %v", i, err)
		}
	}

	// Verify chain integrity
	valid, err := logger.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !valid {
		t.Error("expected chain to be valid")
	}
}

func TestAuditLogger_VerifyChecksum(t *testing.T) {
	store := storage.NewMemoryAppendOnlyStore()
	logger := NewAuditLogger(store)

	ctx := context.Background()
	event := AuditEventForTest{
		EventType:  "test",
		ActorID:    "user-123",
		Action:     "action",
	}

	if err := logger.LogEvent(ctx, event); err != nil {
		t.Fatalf("LogEvent failed: %v", err)
	}

	// Get the logged event
	events, _ := logger.GetAllEvents(ctx)
	if len(events) != 1 {
		t.Fatal("expected 1 event")
	}

	// Verify checksum
	if !logger.VerifyChecksum(events[0]) {
		t.Error("expected checksum to be valid")
	}

	// Tamper with the event
	events[0].Checksum = "invalid"
	if logger.VerifyChecksum(events[0]) {
		t.Error("expected checksum to be invalid after tampering")
	}
}

func TestAuditLogger_GetEventByID(t *testing.T) {
	store := storage.NewMemoryAppendOnlyStore()
	logger := NewAuditLogger(store)

	ctx := context.Background()
	event := AuditEventForTest{
		EventType:  "test",
		ActorID:    "user-123",
		Action:     "action",
	}

	if err := logger.LogEvent(ctx, event); err != nil {
		t.Fatalf("LogEvent failed: %v", err)
	}

	events, _ := logger.GetAllEvents(ctx)
	if len(events) != 1 {
		t.Fatal("expected 1 event")
	}

	// Get by ID
	found, err := logger.GetEventByID(ctx, events[0].ID)
	if err != nil {
		t.Fatalf("GetEventByID failed: %v", err)
	}
	if found.ID != events[0].ID {
		t.Errorf("expected ID %s, got %s", events[0].ID, found.ID)
	}

	// Try non-existent ID
	_, err = logger.GetEventByID(ctx, "non-existent")
	if err == nil {
		t.Error("expected error for non-existent ID")
	}
}

func TestAuditLogger_GetEventsByTimeRange(t *testing.T) {
	store := storage.NewMemoryAppendOnlyStore()
	logger := NewAuditLogger(store)

	ctx := context.Background()

	// Log events at different times
	now := time.Now().UTC().Truncate(time.Second)
	events := []AuditEventForTest{
		{EventType: "test", Action: "action1", Timestamp: now.Add(-2 * time.Hour)},
		{EventType: "test", Action: "action2", Timestamp: now.Add(-1 * time.Hour)},
		{EventType: "test", Action: "action3", Timestamp: now},
		{EventType: "test", Action: "action4", Timestamp: now.Add(1 * time.Hour)},
	}

	for _, event := range events {
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("LogEvent failed: %v", err)
		}
	}

	// Query range
	start := now.Add(-90 * time.Minute)
	end := now.Add(30 * time.Minute)

	result, err := logger.GetEventsByTimeRange(ctx, start, end)
	if err != nil {
		t.Fatalf("GetEventsByTimeRange failed: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 events in range, got %d", len(result))
	}
}

func TestAuditLogger_GetEventsByActor(t *testing.T) {
	store := storage.NewMemoryAppendOnlyStore()
	logger := NewAuditLogger(store)

	ctx := context.Background()

	events := []AuditEventForTest{
		{EventType: "test", ActorID: "user-1", Action: "action1"},
		{EventType: "test", ActorID: "user-2", Action: "action2"},
		{EventType: "test", ActorID: "user-1", Action: "action3"},
	}

	for _, event := range events {
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("LogEvent failed: %v", err)
		}
	}

	result, err := logger.GetEventsByActor(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetEventsByActor failed: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 events for user-1, got %d", len(result))
	}
}

func TestAuditLogger_GetEventsByResource(t *testing.T) {
	store := storage.NewMemoryAppendOnlyStore()
	logger := NewAuditLogger(store)

	ctx := context.Background()

	events := []AuditEventForTest{
		{EventType: "test", ResourceID: "resource-1", Action: "action1"},
		{EventType: "test", ResourceID: "resource-2", Action: "action2"},
		{EventType: "test", ResourceID: "resource-1", Action: "action3"},
	}

	for _, event := range events {
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("LogEvent failed: %v", err)
		}
	}

	result, err := logger.GetEventsByResource(ctx, "resource-1")
	if err != nil {
		t.Fatalf("GetEventsByResource failed: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 events for resource-1, got %d", len(result))
	}
}

func TestAuditLogger_GetEventsByType(t *testing.T) {
	store := storage.NewMemoryAppendOnlyStore()
	logger := NewAuditLogger(store)

	ctx := context.Background()

	events := []AuditEventForTest{
		{EventType: "authentication", Action: "login"},
		{EventType: "authorization", Action: "check"},
		{EventType: "authentication", Action: "logout"},
	}

	for _, event := range events {
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("LogEvent failed: %v", err)
		}
	}

	result, err := logger.GetEventsByType(ctx, "authentication")
	if err != nil {
		t.Fatalf("GetEventsByType failed: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 authentication events, got %d", len(result))
	}
}

func TestAuditLogger_ChainTamperingDetection(t *testing.T) {
	store := storage.NewMemoryAppendOnlyStore()
	logger := NewAuditLogger(store)

	ctx := context.Background()

	// Log 3 events
	for i := 0; i < 3; i++ {
		event := AuditEventForTest{
			EventType: "test",
			Action:    "action",
			Metadata: map[string]interface{}{"index": i},
		}
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("LogEvent failed: %v", err)
		}
	}

	// Verify initial chain is valid
	valid, err := logger.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !valid {
		t.Error("expected initial chain to be valid")
	}

	// Tamper with the store by directly modifying it
	allData, _ := store.ReadAll()
	if len(allData) > 1 {
		// Modify the second event's data
		allData[1][0] = 'X' // Corrupt the data
		t.Log("Tampered with audit log data")

		// Verify chain should now be invalid
		valid, err = logger.VerifyChain(ctx)
		if err == nil && valid {
			t.Error("expected chain to be invalid after tampering")
		}
	}
}

func TestAuditLogger_PreviousHashChain(t *testing.T) {
	store := storage.NewMemoryAppendOnlyStore()
	logger := NewAuditLogger(store)

	ctx := context.Background()

	var previousHash string
	for i := 0; i < 3; i++ {
		event := AuditEventForTest{
			EventType: "test",
			Action:    "action",
		}
		if err := logger.LogEvent(ctx, event); err != nil {
			t.Fatalf("LogEvent failed: %v", err)
		}

		events, _ := logger.GetAllEvents(ctx)
		lastEvent := events[len(events)-1]

		// Verify previous hash matches the previous event's checksum
		if lastEvent.PreviousHash != previousHash {
			t.Errorf("event %d: expected previous hash %s, got %s", i, previousHash, lastEvent.PreviousHash)
		}

		// Update previous hash for next iteration
		previousHash = lastEvent.Checksum
	}
}

func TestAuditLogger_EmptyStore(t *testing.T) {
	store := storage.NewMemoryAppendOnlyStore()
	logger := NewAuditLogger(store)

	ctx := context.Background()

	// Get all events from empty store
	events, err := logger.GetAllEvents(ctx)
	if err != nil {
		t.Fatalf("GetAllEvents failed: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}

	// Verify chain on empty store
	valid, err := logger.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !valid {
		t.Error("expected empty chain to be valid")
	}
}

func TestAuditLogger_CustomID(t *testing.T) {
	store := storage.NewMemoryAppendOnlyStore()
	logger := NewAuditLogger(store)

	ctx := context.Background()
	customID := "custom-event-id-123"
	event := AuditEventForTest{
		ID:        customID,
		EventType: "test",
		Action:    "action",
	}

	if err := logger.LogEvent(ctx, event); err != nil {
		t.Fatalf("LogEvent failed: %v", err)
	}

	// Verify custom ID was preserved
	found, err := logger.GetEventByID(ctx, customID)
	if err != nil {
		t.Fatalf("GetEventByID failed: %v", err)
	}
	if found.ID != customID {
		t.Errorf("expected ID %s, got %s", customID, found.ID)
	}
}
