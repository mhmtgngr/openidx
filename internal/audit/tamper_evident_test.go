// Package audit provides unit tests for tamper-evident audit logging with HMAC-SHA256
package audit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
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
		ID:            uuid.New().String(),
		Timestamp:     time.Now().UTC(),
		TenantID:      "tenant-1",
		ActorID:       "user-1",
		ActorType:     ActorTypeAPI,
		Action:        "data.export",
		ResourceType:  "report",
		ResourceID:    "report-123",
		Outcome:       OutcomeSuccess,
		IP:            "10.1.2.3",
		UserAgent:     "ExportBot/1.0",
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
