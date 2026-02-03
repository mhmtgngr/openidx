// Package events provides an event bus for publish/subscribe messaging.
// This enables loose coupling between components - services can publish
// events without knowing who will consume them.
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
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

// EventHandler processes events
type EventHandler func(ctx context.Context, event Event) error

// Subscription represents an event subscription
type Subscription struct {
	ID        string
	EventType string
	Handler   EventHandler
	Filter    func(Event) bool
}

// Bus is the event bus interface
type Bus interface {
	// Publish publishes an event to all subscribers
	Publish(ctx context.Context, event Event) error

	// PublishAsync publishes an event asynchronously
	PublishAsync(ctx context.Context, event Event)

	// Subscribe subscribes to events of a specific type
	Subscribe(eventType string, handler EventHandler) *Subscription

	// SubscribeAll subscribes to all events
	SubscribeAll(handler EventHandler) *Subscription

	// SubscribeWithFilter subscribes with a custom filter
	SubscribeWithFilter(eventType string, handler EventHandler, filter func(Event) bool) *Subscription

	// Unsubscribe removes a subscription
	Unsubscribe(sub *Subscription)

	// Close shuts down the event bus
	Close() error
}

// MemoryBus is an in-memory event bus implementation
type MemoryBus struct {
	mu            sync.RWMutex
	subscriptions map[string][]*Subscription
	allHandlers   []*Subscription
	closed        bool
	wg            sync.WaitGroup
	errorHandler  func(error)
}

// NewMemoryBus creates a new in-memory event bus
func NewMemoryBus() *MemoryBus {
	return &MemoryBus{
		subscriptions: make(map[string][]*Subscription),
		allHandlers:   make([]*Subscription, 0),
		errorHandler:  func(err error) {}, // Default: ignore errors
	}
}

// SetErrorHandler sets the error handler for async operations
func (b *MemoryBus) SetErrorHandler(handler func(error)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.errorHandler = handler
}

// Publish publishes an event synchronously
func (b *MemoryBus) Publish(ctx context.Context, event Event) error {
	b.mu.RLock()
	if b.closed {
		b.mu.RUnlock()
		return fmt.Errorf("event bus is closed")
	}

	// Get handlers for this event type
	handlers := make([]*Subscription, 0)
	if subs, ok := b.subscriptions[event.Type]; ok {
		handlers = append(handlers, subs...)
	}
	// Add wildcard handlers
	if subs, ok := b.subscriptions["*"]; ok {
		handlers = append(handlers, subs...)
	}
	// Add all-event handlers
	handlers = append(handlers, b.allHandlers...)
	b.mu.RUnlock()

	// Call handlers
	var lastErr error
	for _, sub := range handlers {
		// Apply filter if present
		if sub.Filter != nil && !sub.Filter(event) {
			continue
		}

		if err := sub.Handler(ctx, event); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// PublishAsync publishes an event asynchronously
func (b *MemoryBus) PublishAsync(ctx context.Context, event Event) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		if err := b.Publish(ctx, event); err != nil {
			b.mu.RLock()
			handler := b.errorHandler
			b.mu.RUnlock()
			handler(err)
		}
	}()
}

// Subscribe subscribes to events of a specific type
func (b *MemoryBus) Subscribe(eventType string, handler EventHandler) *Subscription {
	return b.SubscribeWithFilter(eventType, handler, nil)
}

// SubscribeAll subscribes to all events
func (b *MemoryBus) SubscribeAll(handler EventHandler) *Subscription {
	sub := &Subscription{
		ID:        uuid.New().String(),
		EventType: "*",
		Handler:   handler,
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.allHandlers = append(b.allHandlers, sub)

	return sub
}

// SubscribeWithFilter subscribes with a custom filter
func (b *MemoryBus) SubscribeWithFilter(eventType string, handler EventHandler, filter func(Event) bool) *Subscription {
	sub := &Subscription{
		ID:        uuid.New().String(),
		EventType: eventType,
		Handler:   handler,
		Filter:    filter,
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subscriptions[eventType]; !ok {
		b.subscriptions[eventType] = make([]*Subscription, 0)
	}
	b.subscriptions[eventType] = append(b.subscriptions[eventType], sub)

	return sub
}

// Unsubscribe removes a subscription
func (b *MemoryBus) Unsubscribe(sub *Subscription) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Remove from type-specific subscriptions
	if subs, ok := b.subscriptions[sub.EventType]; ok {
		for i, s := range subs {
			if s.ID == sub.ID {
				b.subscriptions[sub.EventType] = append(subs[:i], subs[i+1:]...)
				return
			}
		}
	}

	// Remove from all handlers
	for i, s := range b.allHandlers {
		if s.ID == sub.ID {
			b.allHandlers = append(b.allHandlers[:i], b.allHandlers[i+1:]...)
			return
		}
	}
}

// Close shuts down the event bus
func (b *MemoryBus) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()

	// Wait for async handlers to complete
	b.wg.Wait()
	return nil
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
	EventMFAEnabled    = "mfa.enabled"
	EventMFADisabled   = "mfa.disabled"
	EventMFAChallenge  = "mfa.challenge"
	EventMFAVerified   = "mfa.verified"
	EventMFAFailed     = "mfa.failed"

	// Session events
	EventSessionCreated = "session.created"
	EventSessionRevoked = "session.revoked"
	EventSessionExpired = "session.expired"

	// Group events
	EventGroupCreated     = "group.created"
	EventGroupUpdated     = "group.updated"
	EventGroupDeleted     = "group.deleted"
	EventGroupMemberAdded = "group.member.added"
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
	EventSecurityAlert       = "security.alert"
	EventSuspiciousActivity  = "security.suspicious"
	EventImpossibleTravel    = "security.impossible_travel"
	EventBruteForceDetected  = "security.brute_force"

	// System events
	EventSystemStartup  = "system.startup"
	EventSystemShutdown = "system.shutdown"
	EventConfigChanged  = "system.config.changed"
)

// Global event bus instance
var globalBus Bus = NewMemoryBus()

// SetGlobalBus sets the global event bus
func SetGlobalBus(bus Bus) {
	globalBus = bus
}

// Publish publishes to the global event bus
func Publish(ctx context.Context, event Event) error {
	return globalBus.Publish(ctx, event)
}

// PublishAsync publishes asynchronously to the global event bus
func PublishAsync(ctx context.Context, event Event) {
	globalBus.PublishAsync(ctx, event)
}

// Subscribe subscribes to the global event bus
func Subscribe(eventType string, handler EventHandler) *Subscription {
	return globalBus.Subscribe(eventType, handler)
}

// SubscribeAll subscribes to all events on the global bus
func SubscribeAll(handler EventHandler) *Subscription {
	return globalBus.SubscribeAll(handler)
}

// Global returns the global event bus
func Global() Bus {
	return globalBus
}
