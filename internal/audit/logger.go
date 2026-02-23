// Package audit provides tamper-evident audit logging with HMAC-SHA256 chain linking
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ActorType represents the type of actor performing an action
type ActorType string

const (
	ActorTypeUser   ActorType = "user"
	ActorTypeSystem ActorType = "system"
	ActorTypeAPI    ActorType = "api"
)

// Outcome represents the outcome of an audit event
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

// Action constants for audit events
const (
	ActionAuthLogin        = "auth.login"
	ActionAuthLogout       = "auth.logout"
	ActionUserCreate       = "user.create"
	ActionUserUpdate       = "user.update"
	ActionUserDelete       = "user.delete"
	ActionRoleAssign       = "role.assign"
	ActionRoleRevoke       = "role.revoke"
	ActionPolicyChange     = "policy.change"
	ActionPolicyCreate     = "policy.create"
	ActionPolicyDelete     = "policy.delete"
	ActionGroupCreate      = "group.create"
	ActionGroupDelete      = "group.delete"
	ActionConfigChange     = "config.change"
	ActionPermissionGrant  = "permission.grant"
	ActionPermissionRevoke = "permission.revoke"
)

// AuditEvent represents a tamper-evident audit log entry with HMAC-SHA256 chain linking
type AuditEvent struct {
	// Primary identification
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`

	// Tenant context
	TenantID string `json:"tenant_id,omitempty"`

	// Actor information
	ActorID   string    `json:"actor_id,omitempty"`
	ActorType ActorType `json:"actor_type,omitempty"`

	// Action information
	Action       string `json:"action"`
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`

	// Outcome
	Outcome Outcome `json:"outcome"`

	// Request context
	IP            string `json:"ip,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`

	// Additional data
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Tamper evidence - HMAC chain linking
	PreviousHash string `json:"previous_hash"`
	Hash         string `json:"hash"`
}

// NewAuditEvent creates a new audit event with generated ID
func NewAuditEvent(action string) *AuditEvent {
	return &AuditEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Action:    action,
		Metadata:  make(map[string]interface{}),
	}
}

// ComputeHash calculates the HMAC-SHA256 hash for this event
func (e *AuditEvent) ComputeHash(secret string) (string, error) {
	// Create a canonical representation for hashing
	data, err := e.canonicalBytes()
	if err != nil {
		return "", fmt.Errorf("failed to create canonical bytes: %w", err)
	}

	// Create HMAC with secret
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)

	return hex.EncodeToString(h.Sum(nil)), nil
}

// canonicalBytes creates a canonical byte representation for hashing
// The order of fields matters for consistency
func (e *AuditEvent) canonicalBytes() ([]byte, error) {
	// Build canonical representation
	canonical := []string{
		e.ID,
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.TenantID,
		e.ActorID,
		string(e.ActorType),
		e.Action,
		e.ResourceType,
		e.ResourceID,
		string(e.Outcome),
		e.IP,
		e.UserAgent,
		e.CorrelationID,
		e.PreviousHash,
	}

	// Add metadata as sorted JSON
	if len(e.Metadata) > 0 {
		metadataJSON, err := json.Marshal(e.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}
		canonical = append(canonical, string(metadataJSON))
	}

	// Join with null byte as delimiter
	return []byte(strings.Join(canonical, "\x00")), nil
}

// VerifyHash verifies that the stored hash matches the computed hash
func (e *AuditEvent) VerifyHash(secret string) error {
	computed, err := e.ComputeHash(secret)
	if err != nil {
		return err
	}

	if !hmac.Equal([]byte(e.Hash), []byte(computed)) {
		return &HashMismatchError{
			EventID:      e.ID,
			StoredHash:   e.Hash,
			ComputedHash: computed,
		}
	}

	return nil
}

// HashMismatchError is returned when hash verification fails
type HashMismatchError struct {
	EventID      string
	StoredHash   string
	ComputedHash string
}

func (e *HashMismatchError) Error() string {
	return fmt.Sprintf("hash mismatch for event %s: stored=%s, computed=%s",
		e.EventID, e.StoredHash, e.ComputedHash)
}

// IsTampered returns true if this error indicates tampering
func IsTampered(err error) bool {
	_, ok := err.(*HashMismatchError)
	return ok
}

// WithActor sets the actor information
func (e *AuditEvent) WithActor(actorID string, actorType ActorType) *AuditEvent {
	e.ActorID = actorID
	e.ActorType = actorType
	return e
}

// WithTenant sets the tenant ID
func (e *AuditEvent) WithTenant(tenantID string) *AuditEvent {
	e.TenantID = tenantID
	return e
}

// WithResource sets the resource information
func (e *AuditEvent) WithResource(resourceType, resourceID string) *AuditEvent {
	e.ResourceType = resourceType
	e.ResourceID = resourceID
	return e
}

// WithOutcome sets the outcome
func (e *AuditEvent) WithOutcome(outcome Outcome) *AuditEvent {
	e.Outcome = outcome
	return e
}

// WithRequestContext sets the request context information
func (e *AuditEvent) WithRequestContext(ip, userAgent, correlationID string) *AuditEvent {
	e.IP = ip
	e.UserAgent = userAgent
	e.CorrelationID = correlationID
	return e
}

// WithMetadata adds metadata to the event
func (e *AuditEvent) WithMetadata(key string, value interface{}) *AuditEvent {
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = value
	return e
}

// ChainLink represents the hash chain link information
type ChainLink struct {
	EventID      string    `json:"event_id"`
	Hash         string    `json:"hash"`
	PreviousHash string    `json:"previous_hash"`
	Timestamp    time.Time `json:"timestamp"`
}

// ChainState represents the current state of the hash chain
type ChainState struct {
	LastHash     string    `json:"last_hash"`
	LastEventID  string    `json:"last_event_id"`
	LastSequence int64     `json:"last_sequence"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Logger provides tamper-evident audit logging
type Logger struct {
	secret   string
	chainKey string // For multi-tenancy, can be tenant-specific
}

// NewLogger creates a new audit logger with HMAC secret
func NewLogger(secret string) *Logger {
	if secret == "" {
		panic("audit logger secret cannot be empty")
	}
	return &Logger{
		secret:   secret,
		chainKey: "default",
	}
}

// WithChainKey creates a logger with a specific chain key (e.g., for multi-tenancy)
func (l *Logger) WithChainKey(chainKey string) *Logger {
	return &Logger{
		secret:   l.secret,
		chainKey: chainKey,
	}
}

// prepareForStorage prepares an event for storage by computing its hash
func (l *Logger) prepareForStorage(event *AuditEvent, previousHash string) error {
	event.PreviousHash = previousHash

	// Compute the hash for this event
	hash, err := event.ComputeHash(l.secret)
	if err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}

	event.Hash = hash
	return nil
}

// computeEventHash is a convenience method to compute hash for an event
func (l *Logger) computeEventHash(event *AuditEvent, previousHash string) (string, error) {
	event.PreviousHash = previousHash
	return event.ComputeHash(l.secret)
}

// verifyEventChain verifies that a chain of events is intact
func (l *Logger) verifyEventChain(events []*AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	// Verify each event's hash and chain linkage
	for i, event := range events {
		if err := event.VerifyHash(l.secret); err != nil {
			return fmt.Errorf("event %d (%s) hash verification failed: %w", i, event.ID, err)
		}

		// Verify chain link to previous event
		if i > 0 {
			prevEvent := events[i-1]
			if event.PreviousHash != prevEvent.Hash {
				return &ChainBreakError{
					EventID:          event.ID,
					ExpectedPrevHash: prevEvent.Hash,
					ActualPrevHash:   event.PreviousHash,
					PrevEventID:      prevEvent.ID,
				}
			}
		}
	}

	return nil
}

// ChainBreakError is returned when the hash chain is broken
type ChainBreakError struct {
	EventID          string
	ExpectedPrevHash string
	ActualPrevHash   string
	PrevEventID      string
}

func (e *ChainBreakError) Error() string {
	return fmt.Sprintf("chain break detected at event %s: expected previous_hash=%s (from %s), got=%s",
		e.EventID, e.ExpectedPrevHash, e.PrevEventID, e.ActualPrevHash)
}

// IsChainBreak returns true if this error indicates a chain break
func IsChainBreak(err error) bool {
	_, ok := err.(*ChainBreakError)
	return ok
}

// computeChainKey computes the chain storage key for a given context
func computeChainKey(tenantID, resourceType string) string {
	if tenantID != "" {
		return fmt.Sprintf("tenant:%s", tenantID)
	}
	if resourceType != "" {
		return fmt.Sprintf("resource:%s", resourceType)
	}
	return "default"
}

// VerifyEvent verifies a single event's hash integrity
func (l *Logger) VerifyEvent(event *AuditEvent) error {
	return event.VerifyHash(l.secret)
}

// VerifyEventList verifies a list of events and their chain integrity
func (l *Logger) VerifyEventList(events []*AuditEvent) error {
	return l.verifyEventChain(events)
}
