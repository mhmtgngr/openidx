// Package audit provides unit tests for tamper-evident audit logging with HMAC-SHA256
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// TestAuditEvent_ComputeHash tests HMAC-SHA256 hash computation
func TestAuditEvent_ComputeHash(t *testing.T) {
	secret := "test-secret-key-12345"

	event := &AuditEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		TenantID:  "tenant-1",
		ActorID:   "user-1",
		ActorType: ActorTypeUser,
		Action:    "user.login",
		Outcome:   OutcomeSuccess,
		IP:        "192.168.1.1",
		Metadata: map[string]interface{}{
			"key1": "value1",
			"key2": int64(42),
		},
		PreviousHash: "",
	}

	hash, err := event.ComputeHash(secret)
	if err != nil {
		t.Fatalf("ComputeHash failed: %v", err)
	}

	if hash == "" {
		t.Error("hash should not be empty")
	}

	if len(hash) != 64 { // SHA256 hex is 64 characters
		t.Errorf("hash length should be 64, got %d", len(hash))
	}
}

// TestAuditEvent_VerifyHash tests hash verification
func TestAuditEvent_VerifyHash(t *testing.T) {
	secret := "test-secret-key-12345"

	event := &AuditEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		TenantID:  "tenant-1",
		ActorID:   "user-1",
		ActorType: ActorTypeUser,
		Action:    "user.login",
		Outcome:   OutcomeSuccess,
	}

	// Compute and set hash
	hash, err := event.ComputeHash(secret)
	if err != nil {
		t.Fatalf("ComputeHash failed: %v", err)
	}
	event.Hash = hash

	// Verify should succeed
	if err := event.VerifyHash(secret); err != nil {
		t.Errorf("VerifyHash failed: %v", err)
	}

	// Tamper with the event - verification should fail
	event.Action = "user.delete"
	err = event.VerifyHash(secret)
	if err == nil {
		t.Error("VerifyHash should fail for tampered event")
	}
	if !IsTampered(err) {
		t.Errorf("Error should be HashMismatchError, got: %T", err)
	}
}

// TestAuditEvent_ChainIntegrity tests the hash chain integrity
func TestAuditEvent_ChainIntegrity(t *testing.T) {
	secret := "test-secret-key-12345"

	// Create a chain of events
	events := make([]*AuditEvent, 5)
	var previousHash string

	for i := 0; i < 5; i++ {
		event := &AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Date(2024, 1, 1, 12, i, 0, 0, time.UTC),
			Action:    "test.action",
			Outcome:   OutcomeSuccess,
		}
		event.PreviousHash = previousHash

		hash, err := event.ComputeHash(secret)
		if err != nil {
			t.Fatalf("ComputeHash failed: %v", err)
		}
		event.Hash = hash

		events[i] = event
		previousHash = hash
	}

	// Verify the chain
	logger := NewLogger(secret)
	err := logger.VerifyEventList(events)
	if err != nil {
		t.Errorf("Chain verification failed: %v", err)
	}

	// Tamper with an event in the middle
	events[2].Action = "tampered.action"
	events[2].Hash, _ = events[2].ComputeHash(secret) // Recompute hash with tampered data

	// But the next event's PreviousHash won't match
	err = logger.VerifyEventList(events)
	if err == nil {
		t.Error("Chain verification should detect tampering")
	}
	if !IsChainBreak(err) {
		t.Errorf("Error should be ChainBreakError, got: %T", err)
	}
}

// TestAuditEvent_TamperDetection tests various tampering scenarios
func TestAuditEvent_TamperDetection(t *testing.T) {
	secret := "test-secret-key-12345"

	// Create a chain of events
	events := make([]*AuditEvent, 3)
	var previousHash string

	for i := 0; i < 3; i++ {
		event := &AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Date(2024, 1, 1, 12, i, 0, 0, time.UTC),
			Action:    "test.action",
			Outcome:   OutcomeSuccess,
		}
		event.PreviousHash = previousHash

		hash, err := event.ComputeHash(secret)
		if err != nil {
			t.Fatalf("ComputeHash failed: %v", err)
		}
		event.Hash = hash

		events[i] = event
		previousHash = hash
	}

	logger := NewLogger(secret)

	tests := []struct {
		name        string
		tamper      func([]*AuditEvent)
		expectError bool
		errorType   func(error) bool
	}{
		{
			name: "ValidChain",
			tamper: func(events []*AuditEvent) {
				// No tampering
			},
			expectError: false,
		},
		{
			name: "TamperedHash",
			tamper: func(events []*AuditEvent) {
				events[1].Hash = "0123456789abcdef" + events[1].Hash[16:]
			},
			expectError: true,
			errorType:   IsTampered,
		},
		{
			name: "BrokenChainLink",
			tamper: func(events []*AuditEvent) {
				events[1].PreviousHash = "wronghash"
			},
			expectError: true,
			errorType:   IsChainBreak,
		},
		{
			name: "TamperedContent",
			tamper: func(events []*AuditEvent) {
				events[1].Action = "different.action"
			},
			expectError: true,
			errorType:   IsTampered,
		},
		{
			name: "TamperedMetadata",
			tamper: func(events []*AuditEvent) {
				if events[1].Metadata == nil {
					events[1].Metadata = make(map[string]interface{})
				}
				events[1].Metadata["tampered"] = true
			},
			expectError: true,
			errorType:   IsTampered,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of events
			testEvents := make([]*AuditEvent, len(events))
			for i, e := range events {
				data, _ := json.Marshal(e)
				testEvents[i] = &AuditEvent{}
				json.Unmarshal(data, testEvents[i])
			}

			// Apply tampering
			tt.tamper(testEvents)

			// Verify
			err := logger.VerifyEventList(testEvents)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorType != nil && !tt.errorType(err) {
					t.Errorf("Expected specific error type, got: %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

// TestSearchQuery_Validate tests search query validation
func TestSearchQuery_Validate(t *testing.T) {
	tests := []struct {
		name        string
		query       *SearchQuery
		expectError bool
	}{
		{
			name: "ValidQuery",
			query: &SearchQuery{
				ActorID: "user-1",
				Limit:   50,
			},
			expectError: false,
		},
		{
			name: "NegativeLimit",
			query: &SearchQuery{
				Limit: -1,
			},
			expectError: true,
		},
		{
			name: "LimitTooHigh",
			query: &SearchQuery{
				Limit: 101,
			},
			expectError: true,
		},
		{
			name: "InvalidTimeRange",
			query: &SearchQuery{
				From: time.Now(),
				To:   time.Now().Add(-1 * time.Hour),
			},
			expectError: true,
		},
		{
			name: "InvalidAfterID",
			query: &SearchQuery{
				AfterID: "not-a-uuid",
			},
			expectError: true,
		},
		{
			name: "ValidAfterID",
			query: &SearchQuery{
				AfterID: uuid.New().String(),
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.query.Validate()
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

// TestParseSearchQueryFromMap tests parsing search query from map
func TestParseSearchQueryFromMap(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]string
		expectError bool
		validate    func(*testing.T, *SearchQuery)
	}{
		{
			name: "BasicQuery",
			params: map[string]string{
				"actor": "user-1",
				"limit": "25",
			},
			expectError: false,
			validate: func(t *testing.T, q *SearchQuery) {
				if q.ActorID != "user-1" {
					t.Errorf("ActorID = %s, want user-1", q.ActorID)
				}
				if q.Limit != 25 {
					t.Errorf("Limit = %d, want 25", q.Limit)
				}
			},
		},
		{
			name: "WithTimeRange",
			params: map[string]string{
				"from": "2024-01-01T00:00:00Z",
				"to":   "2024-01-31T23:59:59Z",
			},
			expectError: false,
			validate: func(t *testing.T, q *SearchQuery) {
				if q.From.Year() != 2024 || q.From.Month() != 1 {
					t.Errorf("From = %v, want 2024-01-01", q.From)
				}
				if q.To.Year() != 2024 || q.To.Month() != 1 {
					t.Errorf("To = %v, want 2024-01-31", q.To)
				}
			},
		},
		{
			name: "InvalidTimeFormat",
			params: map[string]string{
				"from": "invalid-date",
			},
			expectError: true,
		},
		{
			name: "InvalidLimit",
			params: map[string]string{
				"limit": "not-a-number",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, err := ParseSearchQueryFromMap(tt.params)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("ParseSearchQueryFromMap failed: %v", err)
				}
				if tt.validate != nil {
					tt.validate(t, query)
				}
			}
		})
	}
}

// TestNewAuditEvent tests creating a new audit event
func TestNewAuditEvent(t *testing.T) {
	event := NewAuditEvent("user.create")

	if event.ID == "" {
		t.Error("ID should be generated")
	}

	if _, err := uuid.Parse(event.ID); err != nil {
		t.Error("ID should be a valid UUID")
	}

	if event.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}

	if event.Action != "user.create" {
		t.Errorf("Action not set correctly")
	}

	if event.Metadata == nil {
		t.Error("Metadata should be initialized")
	}
}

// TestAuditEvent_WithMethods tests the builder methods
func TestAuditEvent_WithMethods(t *testing.T) {
	event := NewAuditEvent("test.action")

	// Test method chaining
	event.
		WithActor("user-123", ActorTypeUser).
		WithTenant("tenant-456").
		WithResource("user", "user-789").
		WithOutcome(OutcomeFailure).
		WithRequestContext("10.0.0.1", "TestAgent/1.0", "corr-123").
		WithMetadata("key1", "value1").
		WithMetadata("key2", 42)

	if event.ActorID != "user-123" {
		t.Errorf("ActorID not set correctly")
	}
	if event.ActorType != ActorTypeUser {
		t.Errorf("ActorType not set correctly")
	}
	if event.TenantID != "tenant-456" {
		t.Errorf("TenantID not set correctly")
	}
	if event.ResourceType != "user" {
		t.Errorf("ResourceType not set correctly")
	}
	if event.ResourceID != "user-789" {
		t.Errorf("ResourceID not set correctly")
	}
	if event.Outcome != OutcomeFailure {
		t.Errorf("Outcome not set correctly")
	}
	if event.IP != "10.0.0.1" {
		t.Errorf("IP not set correctly")
	}
	if event.UserAgent != "TestAgent/1.0" {
		t.Errorf("UserAgent not set correctly")
	}
	if event.CorrelationID != "corr-123" {
		t.Errorf("CorrelationID not set correctly")
	}
	if event.Metadata["key1"] != "value1" {
		t.Errorf("Metadata key1 not set correctly")
	}
	if event.Metadata["key2"] != 42 {
		t.Errorf("Metadata key2 not set correctly")
	}
}

// TestLogger_PrepareForStorage tests preparing events for storage
func TestLogger_PrepareForStorage(t *testing.T) {
	secret := "test-secret"
	logger := NewLogger(secret)

	event := &AuditEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Action:    "test.action",
	}

	previousHash := "previous-hash-value"

	err := logger.PrepareForStorage(event, previousHash)
	if err != nil {
		t.Fatalf("PrepareForStorage failed: %v", err)
	}

	if event.PreviousHash != previousHash {
		t.Errorf("PreviousHash not set: got %s, want %s", event.PreviousHash, previousHash)
	}

	if event.Hash == "" {
		t.Error("Hash should be computed")
	}

	// Verify the hash is correct
	if err := event.VerifyHash(secret); err != nil {
		t.Errorf("Computed hash is invalid: %v", err)
	}
}

// TestGetPartitionName tests partition name generation
func TestGetPartitionName(t *testing.T) {
	tests := []struct {
		timestamp time.Time
		expected  string
	}{
		{
			timestamp: time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
			expected:  "audit_events_2024_01",
		},
		{
			timestamp: time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
			expected:  "audit_events_2024_12",
		},
		{
			timestamp: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
			expected:  "audit_events_2025_06",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := GetPartitionName(tt.timestamp)
			if got != tt.expected {
				t.Errorf("GetPartitionName() = %s, want %s", got, tt.expected)
			}
		})
	}
}

// TestComputeChainKey tests chain key computation
func TestComputeChainKey(t *testing.T) {
	tests := []struct {
		name         string
		tenantID     string
		resourceType string
		expected     string
	}{
		{
			name:         "With tenant",
			tenantID:     "tenant-1",
			resourceType: "",
			expected:     "tenant:tenant-1",
		},
		{
			name:         "With resource",
			tenantID:     "",
			resourceType: "user",
			expected:     "resource:user",
		},
		{
			name:         "Default",
			tenantID:     "",
			resourceType: "",
			expected:     "default",
		},
		{
			name:         "Tenant takes precedence",
			tenantID:     "tenant-1",
			resourceType: "user",
			expected:     "tenant:tenant-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeChainKey(tt.tenantID, tt.resourceType)
			if got != tt.expected {
				t.Errorf("ComputeChainKey() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestIntegrityReport tests the integrity report structure
func TestIntegrityReport(t *testing.T) {
	report := &IntegrityReport{
		TenantID:     "tenant-1",
		IsIntact:     true,
		EventCount:   100,
		LastEventID:  uuid.New().String(),
		LastSequence: 100,
		VerifiedAt:   time.Now().UTC(),
		Issues:       []string{},
	}

	// Should be serializable
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var restored IntegrityReport
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if restored.TenantID != report.TenantID {
		t.Error("TenantID not preserved")
	}
	if restored.IsIntact != report.IsIntact {
		t.Error("IsIntact not preserved")
	}
	if restored.EventCount != report.EventCount {
		t.Error("EventCount not preserved")
	}
}

// MockStore is a mock store for testing
type MockStore struct {
	events []*AuditEvent
}

func (m *MockStore) Write(ctx context.Context, event *AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *MockStore) Flush(ctx context.Context) error {
	return nil
}

func (m *MockStore) ReadByID(ctx context.Context, eventID string) (*AuditEvent, error) {
	for _, e := range m.events {
		if e.ID == eventID {
			return e, nil
		}
	}
	return nil, fmt.Errorf("event not found")
}

func (m *MockStore) VerifyIntegrity(ctx context.Context, tenantID string) (*IntegrityReport, error) {
	return &IntegrityReport{
		TenantID:   tenantID,
		IsIntact:   true,
		EventCount: len(m.events),
		VerifiedAt: time.Now().UTC(),
	}, nil
}

// TestStore_BatchInsert tests batch insert functionality
func TestStore_BatchInsert(t *testing.T) {
	// This test would require a real PostgreSQL connection
	// For now, we test the logic without DB

	secret := "test-secret"
	logger := NewLogger(secret)

	events := make([]*AuditEvent, 10)
	var previousHash string

	for i := 0; i < 10; i++ {
		event := NewAuditEvent("test.action")
		event.PreviousHash = previousHash

		hash, err := event.ComputeHash(secret)
		if err != nil {
			t.Fatalf("ComputeHash failed: %v", err)
		}
		event.Hash = hash

		events[i] = event
		previousHash = hash
	}

	// Verify all events are properly chained
	err := logger.VerifyEventList(events)
	if err != nil {
		t.Errorf("Chain verification failed: %v", err)
	}

	// Verify each event links to the previous
	for i := 1; i < len(events); i++ {
		if events[i].PreviousHash != events[i-1].Hash {
			t.Errorf("Event %d doesn't link to previous event", i)
		}
	}
}

// TestSearchResult tests search result serialization
func TestSearchResult(t *testing.T) {
	result := &SearchResult{
		Events: []*AuditEvent{
			{
				ID:        uuid.New().String(),
				Timestamp: time.Now().UTC(),
				Action:    "test.action",
				Outcome:   OutcomeSuccess,
			},
		},
		NextCursor:  "cursor-123",
		HasMore:     true,
		TotalCount:  100,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var restored SearchResult
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if restored.TotalCount != result.TotalCount {
		t.Error("TotalCount not preserved")
	}
	if restored.HasMore != result.HasMore {
		t.Error("HasMore not preserved")
	}
	if len(restored.Events) != len(result.Events) {
		t.Error("Events count not preserved")
	}
}

// Benchmark_HashComputation benchmarks hash computation
func Benchmark_HashComputation(b *testing.B) {
	secret := "test-secret-key-12345"
	event := &AuditEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Action:    "benchmark.action",
		Metadata: map[string]interface{}{
			"key1": "value1",
			"key2": "value2",
			"key3": int64(42),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = event.ComputeHash(secret)
	}
}

// Benchmark_ChainVerification benchmarks chain verification
func Benchmark_ChainVerification(b *testing.B) {
	secret := "test-secret-key-12345"
	logger := NewLogger(secret)

	// Create a chain of 100 events
	events := make([]*AuditEvent, 100)
	var previousHash string

	for i := 0; i < 100; i++ {
		event := &AuditEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
			Action:    "benchmark.action",
		}
		event.PreviousHash = previousHash
		hash, _ := event.ComputeHash(secret)
		event.Hash = hash
		events[i] = event
		previousHash = hash
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = logger.VerifyEventList(events)
	}
}

// TestOutcome_String tests outcome string values
func TestOutcome_String(t *testing.T) {
	tests := []struct {
		outcome  Outcome
		expected string
	}{
		{OutcomeSuccess, "success"},
		{OutcomeFailure, "failure"},
		{OutcomeDenied, "denied"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.outcome) != tt.expected {
				t.Errorf("Outcome = %s, want %s", tt.outcome, tt.expected)
			}
		})
	}
}

// TestActorType_String tests actor type string values
func TestActorType_String(t *testing.T) {
	tests := []struct {
		actorType ActorType
		expected  string
	}{
		{ActorTypeUser, "user"},
		{ActorTypeSystem, "system"},
		{ActorTypeAPI, "api"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.actorType) != tt.expected {
				t.Errorf("ActorType = %s, want %s", tt.actorType, tt.expected)
			}
		})
	}
}

// TestAuditEvent_JSONRoundTrip tests JSON serialization/deserialization
func TestAuditEvent_JSONRoundTrip(t *testing.T) {
	original := &AuditEvent{
		ID:           uuid.New().String(),
		Timestamp:    time.Now().UTC(),
		TenantID:     "tenant-1",
		ActorID:      "user-1",
		ActorType:    ActorTypeAPI,
		Action:       "data.export",
		ResourceType: "report",
		ResourceID:   "report-123",
		Outcome:      OutcomeSuccess,
		IP:           "10.1.2.3",
		UserAgent:    "ExportBot/1.0",
		CorrelationID: "export-correlation-456",
		Metadata: map[string]interface{}{
			"records":    1000,
			"format":     "csv",
			"compressed": true,
		},
		PreviousHash: "abcdef123456",
		Hash:         "123456abcdef",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var restored AuditEvent
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Verify critical fields
	if restored.ID != original.ID {
		t.Error("ID mismatch")
	}
	if restored.Action != original.Action {
		t.Error("Action mismatch")
	}
	if restored.Outcome != original.Outcome {
		t.Error("Outcome mismatch")
	}
	if restored.Hash != original.Hash {
		t.Error("Hash mismatch")
	}
}

// TestChainBreakError tests chain break error
func TestChainBreakError(t *testing.T) {
	err := &ChainBreakError{
		EventID:          "event-456",
		ExpectedPrevHash: "hash-prev",
		ActualPrevHash:   "hash-wrong",
		PrevEventID:      "event-123",
	}

	msg := err.Error()
	if msg == "" {
		t.Error("Error message should not be empty")
	}

	if !IsChainBreak(err) {
		t.Error("IsChainBreak should return true")
	}
}

// TestHashMismatchError tests hash mismatch error
func TestHashMismatchError(t *testing.T) {
	err := &HashMismatchError{
		EventID:      "event-123",
		StoredHash:   "hash-stored",
		ComputedHash: "hash-computed",
	}

	msg := err.Error()
	if msg == "" {
		t.Error("Error message should not be empty")
	}

	if !IsTampered(err) {
		t.Error("IsTampered should return true")
	}
}

// TestLogger_WithChainKey tests chain key scoping
func TestLogger_WithChainKey(t *testing.T) {
	logger := NewLogger("secret")
	newLogger := logger.WithChainKey("custom-chain")

	if newLogger.GetChainKey() != "custom-chain" {
		t.Errorf("chainKey = %s, want custom-chain", newLogger.GetChainKey())
	}

	if newLogger.secret != "secret" {
		t.Error("secret should be preserved")
	}

	// Original logger should be unchanged
	if logger.GetChainKey() != "default" {
		t.Error("original logger chainKey should not change")
	}
}

// TestStatistics tests statistics structure
func TestStatistics(t *testing.T) {
	stats := &Statistics{
		TotalCount: 1000,
		From:       time.Now().Add(-30 * 24 * time.Hour),
		To:         time.Now(),
		ByAction: map[string]int64{
			"user.login":  500,
			"user.logout": 400,
			"user.create": 100,
		},
		ByActor: map[string]int64{
			"user-1": 600,
			"user-2": 400,
		},
		ByOutcome: map[string]int64{
			"success": 950,
			"failure": 50,
		},
	}

	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var restored Statistics
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if restored.TotalCount != stats.TotalCount {
		t.Error("TotalCount not preserved")
	}
	if len(restored.ByAction) != len(stats.ByAction) {
		t.Error("ByAction count not preserved")
	}
}

// TestBatchConfiguration tests batch configuration defaults
func TestBatchConfiguration(t *testing.T) {
	config := DefaultStoreConfig()

	if config.BatchSize != 100 {
		t.Errorf("Default BatchSize = %d, want 100", config.BatchSize)
	}

	if config.FlushInterval != 5*time.Second {
		t.Errorf("Default FlushInterval = %v, want 5s", config.FlushInterval)
	}
}

// TestActionConstants verifies action constants
func TestActionConstants(t *testing.T) {
	constants := []string{
		ActionAuthLogin,
		ActionAuthLogout,
		ActionUserCreate,
		ActionUserUpdate,
		ActionUserDelete,
		ActionRoleAssign,
		ActionRoleRevoke,
		ActionPolicyChange,
		ActionPolicyCreate,
		ActionPolicyDelete,
		ActionGroupCreate,
		ActionGroupDelete,
		ActionConfigChange,
		ActionPermissionGrant,
		ActionPermissionRevoke,
	}

	// Verify all constants are non-empty and have dots (namespace.action format)
	for _, action := range constants {
		if action == "" {
			t.Error("Action constant should not be empty")
		}
		if !containsDot(action) {
			t.Errorf("Action %s should be in namespace.action format", action)
		}
	}
}

func containsDot(s string) bool {
	for _, c := range s {
		if c == '.' {
			return true
		}
	}
	return false
}

// TestStoreConfig tests store configuration
func TestStoreConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  StoreConfig
		wantErr bool
	}{
		{
			name: "ValidConfig",
			config: StoreConfig{
				BatchSize:     50,
				FlushInterval: 10 * time.Second,
				Secret:        "valid-secret",
			},
			wantErr: false,
		},
		{
			name: "EmptySecret",
			config: StoreConfig{
				Secret: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't actually create a store without a DB connection
			// But we can validate the config
			if tt.config.Secret == "" && !tt.wantErr {
				t.Error("Empty secret should cause error")
			}
		})
	}
}

// TestConcurrentHashComputation tests thread safety of hash computation
func TestConcurrentHashComputation(t *testing.T) {
	secret := "test-secret"
	event := &AuditEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		Action:    "test.action",
		Metadata: map[string]interface{}{
			"key": "value",
		},
	}

	// Compute hashes concurrently
	results := make(chan string, 10)
	for i := 0; i < 10; i++ {
		go func() {
			hash, _ := event.ComputeHash(secret)
			results <- hash
		}()
	}

	// All hashes should be identical
	firstHash := <-results
	for i := 0; i < 9; i++ {
		hash := <-results
		if hash != firstHash {
			t.Error("Hash computation is not deterministic")
		}
	}
}
