// Package audit provides structured, tamper-evident audit logging
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AuditEvent represents a tamper-evident audit log entry with blockchain-style hashing
type AuditEvent struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"`
	ActorID      string                 `json:"actor_id,omitempty"`
	ActorType    string                 `json:"actor_type,omitempty"`
	ResourceID   string                 `json:"resource_id,omitempty"`
	ResourceType string                 `json:"resource_type,omitempty"`
	Action       string                 `json:"action"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Checksum     string                 `json:"checksum"`     // SHA256 hash of event + previous hash
	PreviousHash string                 `json:"previous_hash"` // Hash of previous event for chain integrity
}

// AppendOnlyStore defines the storage interface for tamper-evident append-only logs
type AppendOnlyStore interface {
	Append(data []byte) error
	ReadAll() ([][]byte, error)
	GetLastHash() (string, error)
}

// AuditLogger provides structured, tamper-evident audit logging
type AuditLogger struct {
	storage AppendOnlyStore
}

// NewAuditLogger creates a new AuditLogger with the given append-only storage
func NewAuditLogger(storage AppendOnlyStore) *AuditLogger {
	return &AuditLogger{
		storage: storage,
	}
}

// LogEvent logs an audit event with tamper-evident checksum
// The checksum is computed as SHA256(event_data + previous_hash)
func (l *AuditLogger) LogEvent(ctx context.Context, event AuditEvent) error {
	// Generate UUID if not provided
	if event.ID == "" {
		event.ID = uuid.New().String()
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Get previous hash for chain integrity
	previousHash, err := l.storage.GetLastHash()
	if err != nil {
		return fmt.Errorf("failed to get previous hash: %w", err)
	}
	event.PreviousHash = previousHash

	// Compute checksum: SHA256 of event data (excluding checksum field) + previous hash
	checksum, err := l.computeChecksum(event, previousHash)
	if err != nil {
		return fmt.Errorf("failed to compute checksum: %w", err)
	}
	event.Checksum = checksum

	// Serialize event
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Append to storage
	if err := l.storage.Append(data); err != nil {
		return fmt.Errorf("failed to append event: %w", err)
	}

	return nil
}

// computeChecksum calculates SHA256 hash of event data plus previous hash
func (l *AuditLogger) computeChecksum(event AuditEvent, previousHash string) (string, error) {
	// Create a copy without checksum and previous hash for hashing
	eventCopy := event
	eventCopy.Checksum = ""
	eventCopy.PreviousHash = ""

	data, err := json.Marshal(eventCopy)
	if err != nil {
		return "", err
	}

	// Hash the event data combined with previous hash
	hasher := sha256.New()
	hasher.Write(data)
	hasher.Write([]byte(previousHash))

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyChecksum verifies the integrity of an audit event's checksum
func (l *AuditLogger) VerifyChecksum(event AuditEvent) bool {
	// Recompute checksum and compare
	expectedChecksum, err := l.computeChecksum(event, event.PreviousHash)
	if err != nil {
		return false
	}
	return expectedChecksum == event.Checksum
}

// VerifyChain verifies the integrity of the entire audit chain
// Returns true if all checksums are valid and the chain is intact
func (l *AuditLogger) VerifyChain(ctx context.Context) (bool, error) {
	events, err := l.GetAllEvents(ctx)
	if err != nil {
		return false, err
	}

	// Track the running hash
	expectedPreviousHash := ""
	if len(events) > 0 {
		expectedPreviousHash = events[0].PreviousHash
	}

	for i, event := range events {
		// Verify the event checksum
		if !l.VerifyChecksum(event) {
			return false, fmt.Errorf("checksum mismatch at event %d (ID: %s)", i, event.ID)
		}

		// Verify chain linkage
		if event.PreviousHash != expectedPreviousHash {
			return false, fmt.Errorf("chain broken at event %d (ID: %s): expected previous hash %s, got %s",
				i, event.ID, expectedPreviousHash, event.PreviousHash)
		}

		// Update expected previous hash for next event
		checksum, err := l.computeChecksum(event, event.PreviousHash)
		if err != nil {
			return false, err
		}
		expectedPreviousHash = checksum
	}

	return true, nil
}

// GetEventByID retrieves an audit event by its ID
func (l *AuditLogger) GetEventByID(ctx context.Context, id string) (*AuditEvent, error) {
	events, err := l.GetAllEvents(ctx)
	if err != nil {
		return nil, err
	}

	for _, event := range events {
		if event.ID == id {
			return &event, nil
		}
	}

	return nil, fmt.Errorf("audit event not found: %s", id)
}

// GetEventsByTimeRange retrieves all audit events within the specified time range
func (l *AuditLogger) GetEventsByTimeRange(ctx context.Context, start, end time.Time) ([]AuditEvent, error) {
	events, err := l.GetAllEvents(ctx)
	if err != nil {
		return nil, err
	}

	var result []AuditEvent
	for _, event := range events {
		if (event.Timestamp.Equal(start) || event.Timestamp.After(start)) &&
			(event.Timestamp.Equal(end) || event.Timestamp.Before(end)) {
			result = append(result, event)
		}
	}

	return result, nil
}

// GetAllEvents retrieves all audit events from storage
func (l *AuditLogger) GetAllEvents(ctx context.Context) ([]AuditEvent, error) {
	data, err := l.storage.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read events: %w", err)
	}

	events := make([]AuditEvent, 0, len(data))
	for _, d := range data {
		var event AuditEvent
		if err := json.Unmarshal(d, &event); err != nil {
			return nil, fmt.Errorf("failed to unmarshal event: %w", err)
		}
		events = append(events, event)
	}

	return events, nil
}

// GetEventsByActor retrieves all audit events for a specific actor
func (l *AuditLogger) GetEventsByActor(ctx context.Context, actorID string) ([]AuditEvent, error) {
	events, err := l.GetAllEvents(ctx)
	if err != nil {
		return nil, err
	}

	var result []AuditEvent
	for _, event := range events {
		if event.ActorID == actorID {
			result = append(result, event)
		}
	}

	return result, nil
}

// GetEventsByResource retrieves all audit events for a specific resource
func (l *AuditLogger) GetEventsByResource(ctx context.Context, resourceID string) ([]AuditEvent, error) {
	events, err := l.GetAllEvents(ctx)
	if err != nil {
		return nil, err
	}

	var result []AuditEvent
	for _, event := range events {
		if event.ResourceID == resourceID {
			result = append(result, event)
		}
	}

	return result, nil
}

// GetEventsByType retrieves all audit events of a specific type
func (l *AuditLogger) GetEventsByType(ctx context.Context, eventType string) ([]AuditEvent, error) {
	events, err := l.GetAllEvents(ctx)
	if err != nil {
		return nil, err
	}

	var result []AuditEvent
	for _, event := range events {
		if event.EventType == eventType {
			result = append(result, event)
		}
	}

	return result, nil
}
