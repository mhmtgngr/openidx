// Package events carries the platform's domain events.
//
// There is exactly one way to publish one: OutboxBus, which writes the event
// into the transaction that produced the state change it describes (see
// outbox.go). There used to be a second -- an in-memory Bus with subscriptions,
// a MemoryBus, and a package-level global with Publish/Subscribe helpers, 346
// lines of it. It was deleted, not because it was wrong but because NOTHING IN
// THE TREE IMPORTED IT: not one publisher, not one subscriber, in any service
// or test outside its own file.
//
// Leaving it would have been worse than leaving it unused. A developer looking
// for "the event bus" would find an in-memory one sitting next to the outbox
// and reach for whichever read more conveniently -- and the difference between
// them is that one loses everything when the process dies. "This session was
// revoked" must not be delivered on a best-effort basis to whoever happened to
// be subscribed in this replica.
//
// What is kept is the envelope and the event-type vocabulary: those are what an
// outbox row is made of.
package events

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Event represents a domain event
type Event struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	TraceID   string                 `json:"trace_id,omitempty"`
	UserID    string                 `json:"user_id,omitempty"`
	Payload   map[string]interface{} `json:"payload"`
	Metadata  map[string]string      `json:"metadata,omitempty"`
}

// NewEvent creates a new event with auto-generated ID and timestamp
func NewEvent(eventType, source string, payload map[string]interface{}) Event {
	return Event{
		ID:        uuid.New().String(),
		Type:      eventType,
		Source:    source,
		Timestamp: time.Now().UTC(),
		Payload:   payload,
		Metadata:  make(map[string]string),
	}
}

// WithTraceID adds a trace ID to the event
func (e Event) WithTraceID(traceID string) Event {
	e.TraceID = traceID
	return e
}

// WithUserID adds a user ID to the event
func (e Event) WithUserID(userID string) Event {
	e.UserID = userID
	return e
}

// WithMetadata adds metadata to the event
func (e Event) WithMetadata(key, value string) Event {
	if e.Metadata == nil {
		e.Metadata = make(map[string]string)
	}
	e.Metadata[key] = value
	return e
}

// JSON serializes the event to JSON
func (e Event) JSON() ([]byte, error) {
	return json.Marshal(e)
}

// Common event types
const (
	// User events
	EventUserCreated         = "user.created"
	EventUserUpdated         = "user.updated"
	EventUserDeleted         = "user.deleted"
	EventUserLogin           = "user.login"
	EventUserLoginFailed     = "user.login.failed"
	EventUserLogout          = "user.logout"
	EventUserPasswordChanged = "user.password.changed"
	EventUserLocked          = "user.locked"
	EventUserUnlocked        = "user.unlocked"

	// MFA events
	EventMFAEnabled   = "mfa.enabled"
	EventMFADisabled  = "mfa.disabled"
	EventMFAChallenge = "mfa.challenge"
	EventMFAVerified  = "mfa.verified"
	EventMFAFailed    = "mfa.failed"

	// Session events
	EventSessionCreated = "session.created"
	EventSessionRevoked = "session.revoked"
	EventSessionExpired = "session.expired"

	// Group events
	EventGroupCreated       = "group.created"
	EventGroupUpdated       = "group.updated"
	EventGroupDeleted       = "group.deleted"
	EventGroupMemberAdded   = "group.member.added"
	EventGroupMemberRemoved = "group.member.removed"

	// Role events
	EventRoleCreated  = "role.created"
	EventRoleUpdated  = "role.updated"
	EventRoleDeleted  = "role.deleted"
	EventRoleAssigned = "role.assigned"
	EventRoleRevoked  = "role.revoked"

	// Policy events
	EventPolicyCreated   = "policy.created"
	EventPolicyUpdated   = "policy.updated"
	EventPolicyDeleted   = "policy.deleted"
	EventPolicyEvaluated = "policy.evaluated"

	// Access events
	EventAccessGranted = "access.granted"
	EventAccessDenied  = "access.denied"
	EventAccessRevoked = "access.revoked"

	// Security events
	EventSecurityAlert      = "security.alert"
	EventSuspiciousActivity = "security.suspicious"
	EventImpossibleTravel   = "security.impossible_travel"
	EventBruteForceDetected = "security.brute_force"

	// System events
	EventSystemStartup  = "system.startup"
	EventSystemShutdown = "system.shutdown"
	EventConfigChanged  = "system.config.changed"
)
