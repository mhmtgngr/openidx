// Package identity provides identity lifecycle management functionality
package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/events"
)

// Ensure User model supports state field - this is an extension to the User model
// In production, this would be a database field. For now, we track it via Attributes.

const (
	// AttributeKeyState stores the current state in User.Attributes
	AttributeKeyState = "lifecycle_state"
	// AttributeKeyStateSince stores when the current state was set
	AttributeKeyStateSince = "state_since"
	// AttributeKeyStateHistory stores the state transition history
	AttributeKeyStateHistory = "state_history"
	// AttributeKeyDeprovisionedAt stores when the user was deprovisioned
	AttributeKeyDeprovisionedAt = "deprovisioned_at"
)

// GetState retrieves the current lifecycle state from a User
func (u *User) GetState() IdentityState {
	if u.Attributes == nil {
		return StateCreated
	}
	if state, ok := u.Attributes[AttributeKeyState]; ok {
		return IdentityState(state)
	}
	return StateCreated
}

// SetState sets the lifecycle state on a User
func (u *User) SetState(state IdentityState) {
	if u.Attributes == nil {
		u.Attributes = make(map[string]string)
	}
	u.Attributes[AttributeKeyState] = string(state)
	u.Attributes[AttributeKeyStateSince] = time.Now().UTC().Format(time.RFC3339)
}

// GetStateSince returns when the current state was set
func (u *User) GetStateSince() (*time.Time, error) {
	if u.Attributes == nil {
		return nil, nil
	}
	sinceStr, ok := u.Attributes[AttributeKeyStateSince]
	if !ok {
		return nil, nil
	}
	since, err := time.Parse(time.RFC3339, sinceStr)
	if err != nil {
		return nil, err
	}
	return &since, nil
}

// RecordStateTransition records a state transition in the user's history
func (u *User) RecordStateTransition(from, to IdentityState, actor string) {
	if u.Attributes == nil {
		u.Attributes = make(map[string]string)
	}
	entry := fmt.Sprintf("%s|%s|%s|%s",
		time.Now().UTC().Format(time.RFC3339),
		from, to, actor,
	)
	history := u.Attributes[AttributeKeyStateHistory]
	if history != "" {
		u.Attributes[AttributeKeyStateHistory] = history + ";" + entry
	} else {
		u.Attributes[AttributeKeyStateHistory] = entry
	}
}

// GetStateHistory returns the state transition history
func (u *User) GetStateHistory() []StateTransition {
	if u.Attributes == nil {
		return nil
	}
	historyStr, ok := u.Attributes[AttributeKeyStateHistory]
	if !ok {
		return nil
	}

	entries := strings.Split(historyStr, ";")
	transitions := make([]StateTransition, 0, len(entries))
	for _, entry := range entries {
		parts := strings.Split(entry, "|")
		if len(parts) == 4 {
			timestamp, err := time.Parse(time.RFC3339, parts[0])
			if err != nil {
				continue
			}
			transitions = append(transitions, StateTransition{
				Timestamp: timestamp,
				From:      IdentityState(parts[1]),
				To:        IdentityState(parts[2]),
				Actor:     parts[3],
			})
		}
	}
	return transitions
}

// StateTransition represents a single state transition
type StateTransition struct {
	Timestamp time.Time     `json:"timestamp"`
	From      IdentityState `json:"from"`
	To        IdentityState `json:"to"`
	Actor     string        `json:"actor"`
}

// LifecycleTransition represents a requested state transition
type LifecycleTransition struct {
	UserID    string        `json:"user_id"`
	FromState IdentityState `json:"from_state"`
	ToState   IdentityState `json:"to_state"`
	Actor     string        `json:"actor"`
	Reason    *string       `json:"reason,omitempty"`
}

// LifecycleTransitionResult contains the result of a state transition
type LifecycleTransitionResult struct {
	UserID      string        `json:"user_id"`
	FromState   IdentityState `json:"from_state"`
	ToState     IdentityState `json:"to_state"`
	Success     bool          `json:"success"`
	Error       *string       `json:"error,omitempty"`
	TransitionedAt time.Time  `json:"transitioned_at"`
	Actions     []string      `json:"actions,omitempty"`
}

// LifecycleManager handles identity lifecycle state transitions
type LifecycleManager struct {
	repo          Repository
	logger        *zap.Logger
	eventBus      events.Bus
	webhookURL    *string
	emailService  WelcomeEmailSender
	sessionRevoker SessionRevoker
	retentionDays int
}

// SessionRevoker is an interface for revoking user sessions
type SessionRevoker interface {
	RevokeAllUserSessions(ctx context.Context, userID string) error
}

// WelcomeEmailSender is an interface for sending welcome emails
type WelcomeEmailSender interface {
	SendWelcomeEmail(ctx context.Context, to, userName string) error
}

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager(
	repo Repository,
	logger *zap.Logger,
	eventBus events.Bus,
	webhookURL *string,
	emailService WelcomeEmailSender,
	sessionRevoker SessionRevoker,
) *LifecycleManager {
	return &LifecycleManager{
		repo:          repo,
		logger:        logger.With(zap.String("component", "lifecycle")),
		eventBus:      eventBus,
		webhookURL:    webhookURL,
		emailService:  emailService,
		sessionRevoker: sessionRevoker,
		retentionDays: 90, // Default 90-day retention
	}
}

// SetRetentionDays sets the retention period before anonymizing PII
func (m *LifecycleManager) SetRetentionDays(days int) {
	m.retentionDays = days
}

// TransitionState performs a state transition for a user
func (m *LifecycleManager) TransitionState(
	ctx context.Context,
	userID string,
	toState IdentityState,
	actor string,
	reason *string,
) (*LifecycleTransitionResult, error) {
	// Get the user
	user, err := m.repo.GetUser(ctx, userID)
	if err != nil {
		return &LifecycleTransitionResult{
			UserID:    userID,
			ToState:   toState,
			Success:   false,
			Error:     stringPtr(fmt.Sprintf("user not found: %v", err)),
		}, fmt.Errorf("user not found: %w", err)
	}

	fromState := user.GetState()

	// Validate the transition
	if err := m.ValidateTransition(fromState, toState); err != nil {
		return &LifecycleTransitionResult{
			UserID:    userID,
			FromState: fromState,
			ToState:   toState,
			Success:   false,
			Error:     stringPtr(err.Error()),
		}, err
	}

	// Perform state-specific actions
	actions, err := m.executeTransitionActions(ctx, user, fromState, toState, actor)
	if err != nil {
		return &LifecycleTransitionResult{
			UserID:    userID,
			FromState: fromState,
			ToState:   toState,
			Success:   false,
			Error:     stringPtr(err.Error()),
		}, err
	}

	// Update the user's state
	user.SetState(toState)
	user.RecordStateTransition(fromState, toState, actor)

	// Apply additional state changes
	switch toState {
	case StateSuspended:
		user.Active = false
		user.Enabled = false
	case StateActive:
		user.Active = true
		user.Enabled = true
	case StateDeprovisioned:
		user.Active = false
		user.Enabled = false
		now := time.Now().UTC()
		user.Attributes[AttributeKeyDeprovisionedAt] = now.Format(time.RFC3339)
	}

	// Save the updated user
	if err := m.repo.UpdateUser(ctx, user); err != nil {
		m.logger.Error("Failed to update user state",
			zap.String("user_id", userID),
			zap.String("from", string(fromState)),
			zap.String("to", string(toState)),
			zap.Error(err),
		)
		return &LifecycleTransitionResult{
			UserID:    userID,
			FromState: fromState,
			ToState:   toState,
			Success:   false,
			Error:     stringPtr(fmt.Sprintf("failed to save: %v", err)),
		}, fmt.Errorf("failed to update user: %w", err)
	}

	// Publish event
	eventType := m.stateTransitionToEventType(fromState, toState)
	m.publishLifecycleEvent(ctx, eventType, user, fromState, toState, actor, reason)

	m.logger.Info("User state transitioned",
		zap.String("user_id", userID),
		zap.String("from", string(fromState)),
		zap.String("to", string(toState)),
		zap.String("actor", actor),
		zap.Strings("actions", actions),
	)

	return &LifecycleTransitionResult{
		UserID:         userID,
		FromState:      fromState,
		ToState:        toState,
		Success:        true,
		TransitionedAt: time.Now(),
		Actions:        actions,
	}, nil
}

// ValidateTransition validates if a state transition is allowed
func (m *LifecycleManager) ValidateTransition(from, to IdentityState) error {
	// Same state is a no-op
	if from == to {
		return fmt.Errorf("user is already in state %s", to)
	}

	// Check if transition is valid
	validStates, ok := ValidStateTransitions[from]
	if !ok {
		return fmt.Errorf("invalid current state: %s", from)
	}

	for _, validState := range validStates {
		if validState == to {
			return nil
		}
	}

	return fmt.Errorf("invalid state transition from %s to %s", from, to)
}

// executeTransitionActions executes actions required for a state transition
func (m *LifecycleManager) executeTransitionActions(
	ctx context.Context,
	user *User,
	from, to IdentityState,
	actor string,
) ([]string, error) {
	var actions []string

	switch to {
	case StateActive:
		// Activate: set status, send welcome email if new
		if from == StateCreated {
			if m.emailService != nil {
				if err := m.emailService.SendWelcomeEmail(
					ctx,
					user.GetPrimaryEmail(),
					user.GetFormattedName(),
				); err != nil {
					m.logger.Warn("Failed to send welcome email",
						zap.String("user_id", user.ID),
						zap.Error(err),
					)
				} else {
					actions = append(actions, "welcome_email_sent")
				}
			}
		}
		actions = append(actions, "status_activated")

	case StateSuspended:
		// Suspend: revoke sessions, disable login
		if m.sessionRevoker != nil {
			if err := m.sessionRevoker.RevokeAllUserSessions(ctx, user.ID); err != nil {
				m.logger.Warn("Failed to revoke sessions during suspension",
					zap.String("user_id", user.ID),
					zap.Error(err),
				)
			} else {
				actions = append(actions, "sessions_revoked")
			}
		}
		actions = append(actions, "login_disabled")

	case StateDeprovisioned:
		// Deprovision: remove access, mark for PII anonymization
		if m.sessionRevoker != nil {
			if err := m.sessionRevoker.RevokeAllUserSessions(ctx, user.ID); err != nil {
				m.logger.Warn("Failed to revoke sessions during deprovisioning",
					zap.String("user_id", user.ID),
					zap.Error(err),
				)
			} else {
				actions = append(actions, "sessions_revoked")
			}
		}
		actions = append(actions, "access_removed")
		// Schedule PII anonymization task
		actions = append(actions, "pii_anonymization_scheduled")
	}

	return actions, nil
}

// AnonymizeUser permanently removes PII data after retention period
func (m *LifecycleManager) AnonymizeUser(ctx context.Context, userID string) error {
	user, err := m.repo.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	state := user.GetState()
	if state != StateDeprovisioned {
		return fmt.Errorf("user must be deprovisioned before anonymization, current state: %s", state)
	}

	// Check if retention period has passed
	deprovisionedAtStr, ok := user.Attributes[AttributeKeyDeprovisionedAt]
	if !ok {
		return fmt.Errorf("deprovisioned timestamp not found")
	}
	deprovisionedAt, err := time.Parse(time.RFC3339, deprovisionedAtStr)
	if err != nil {
		return fmt.Errorf("invalid deprovisioned timestamp: %w", err)
	}

	retentionExpiry := deprovisionedAt.AddDate(0, 0, m.retentionDays)
	if time.Now().Before(retentionExpiry) {
		return fmt.Errorf("retention period not expired until %s", retentionExpiry)
	}

	// Anonymize PII
	user.UserName = fmt.Sprintf("anon_%s", uuid.New().String()[:8])
	user.SetEmail(fmt.Sprintf("anon_%s@deleted.local", uuid.New().String()[:8]))
	user.SetFirstName("Anonymous")
	user.SetLastName("User")
	if user.DisplayName != nil {
		anon := "Anonymous User"
		user.DisplayName = &anon
	}
	user.PhoneNumbers = nil
	user.Addresses = nil
	user.Photos = nil
	user.PasswordHash = nil

	// Mark as anonymized
	user.Attributes["anonymized_at"] = time.Now().UTC().Format(time.RFC3339)
	user.Attributes["anonymized_by"] = "system"

	if err := m.repo.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to update anonymized user: %w", err)
	}

	m.logger.Info("User PII anonymized",
		zap.String("user_id", userID),
		zap.Time("deprovisioned_at", deprovisionedAt),
		zap.Int("retention_days", m.retentionDays),
	)

	// Publish event
	m.publishLifecycleEvent(ctx, "user.anonymized", user, state, StateDeprovisioned, "system", nil)

	return nil
}

// GetTransitionHistory returns the state transition history for a user
func (m *LifecycleManager) GetTransitionHistory(ctx context.Context, userID string) ([]StateTransition, error) {
	user, err := m.repo.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	return user.GetStateHistory(), nil
}

// publishLifecycleEvent publishes a lifecycle state transition event
func (m *LifecycleManager) publishLifecycleEvent(
	ctx context.Context,
	eventType string,
	user *User,
	from, to IdentityState,
	actor string,
	reason *string,
) {
	payload := map[string]interface{}{
		"user_id":    user.ID,
		"username":   user.UserName,
		"email":      user.GetPrimaryEmail(),
		"from_state": string(from),
		"to_state":   string(to),
		"actor":      actor,
		"timestamp":  time.Now().UTC(),
	}

	if reason != nil {
		payload["reason"] = *reason
	}

	event := events.NewEvent(eventType, "lifecycle", payload)
	event = event.WithUserID(user.ID)

	if m.eventBus != nil {
		m.eventBus.PublishAsync(ctx, event)
	}

	// Send webhook notification
	if m.webhookURL != nil {
		m.sendWebhook(ctx, eventType, event)
	}
}

// sendWebhook sends a webhook notification for lifecycle events
func (m *LifecycleManager) sendWebhook(ctx context.Context, eventType string, event events.Event) {
	m.logger.Debug("Lifecycle webhook notification",
		zap.String("event_type", eventType),
		zap.String("event_id", event.ID),
		zap.Any("payload", event.Payload),
	)
	// In a real implementation, this would make an HTTP POST request
}

// stateTransitionToEventType maps a state transition to an event type
func (m *LifecycleManager) stateTransitionToEventType(from, to IdentityState) string {
	switch to {
	case StateActive:
		return "user.activated"
	case StateSuspended:
		return "user.suspended"
	case StateDeprovisioned:
		return "user.deprovisioned"
	default:
		return fmt.Sprintf("user.state.%s", to)
	}
}

// GetUsersByState returns users in a specific lifecycle state
func (m *LifecycleManager) GetUsersByState(ctx context.Context, state IdentityState, filter UserFilter) (*ListResponse, error) {
	// This would ideally be a database query, but for now we filter in memory
	// In production, add a state column to the users table
	allUsers, err := m.repo.ListUsers(ctx, filter)
	if err != nil {
		return nil, err
	}

	users, ok := allUsers.Resources.([]*User)
	if !ok {
		return allUsers, nil
	}

	filtered := make([]*User, 0)
	for _, user := range users {
		if user.GetState() == state {
			filtered = append(filtered, user)
		}
	}

	allUsers.Resources = filtered
	allUsers.TotalResults = len(filtered)
	return allUsers, nil
}

// GetUsersPendingAnonymization returns users who should be anonymized
func (m *LifecycleManager) GetUsersPendingAnonymization(ctx context.Context) ([]*User, error) {
	filter := UserFilter{PaginationParams: PaginationParams{Limit: 1000}}
	allUsers, err := m.repo.ListUsers(ctx, filter)
	if err != nil {
		return nil, err
	}

	users, ok := allUsers.Resources.([]*User)
	if !ok {
		return nil, nil
	}

	pending := make([]*User, 0)
	now := time.Now()
	retentionDuration := time.Duration(m.retentionDays) * 24 * time.Hour

	for _, user := range users {
		if user.GetState() != StateDeprovisioned {
			continue
		}

		deprovisionedAtStr, ok := user.Attributes[AttributeKeyDeprovisionedAt]
		if !ok {
			continue
		}
		deprovisionedAt, err := time.Parse(time.RFC3339, deprovisionedAtStr)
		if err != nil {
			continue
		}

		if now.Sub(deprovisionedAt) >= retentionDuration {
			pending = append(pending, user)
		}
	}

	return pending, nil
}

// BatchTransition transitions multiple users to the same state
func (m *LifecycleManager) BatchTransition(
	ctx context.Context,
	userIDs []string,
	toState IdentityState,
	actor string,
	reason *string,
) ([]*LifecycleTransitionResult, error) {
	results := make([]*LifecycleTransitionResult, len(userIDs))

	for i, userID := range userIDs {
		result, err := m.TransitionState(ctx, userID, toState, actor, reason)
		if err != nil {
			result.Error = stringPtr(err.Error())
		}
		results[i] = result
	}

	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	m.logger.Info("Batch state transition completed",
		zap.String("to_state", string(toState)),
		zap.Int("total", len(userIDs)),
		zap.Int("success", successCount),
		zap.Int("failed", len(userIDs)-successCount),
	)

	return results, nil
}

// IsActive checks if a user is in the Active state
func (m *LifecycleManager) IsActive(ctx context.Context, userID string) (bool, error) {
	user, err := m.repo.GetUser(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("user not found: %w", err)
	}
	return user.GetState() == StateActive && user.Active, nil
}

// CanLogin checks if a user is allowed to log in
func (m *LifecycleManager) CanLogin(ctx context.Context, userID string) (bool, error) {
	user, err := m.repo.GetUser(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("user not found: %w", err)
	}

	state := user.GetState()
	if state != StateActive {
		return false, nil
	}

	if user.IsLocked() {
		return false, nil
	}

	return user.Enabled && user.Active, nil
}

// LifecycleAuditLog represents an audit log entry for lifecycle operations
type LifecycleAuditLog struct {
	ID            string        `json:"id"`
	UserID        string        `json:"user_id"`
	Transition    StateTransition `json:"transition"`
	Reason        *string       `json:"reason,omitempty"`
	PerformedBy   string        `json:"performed_by"`
	IPAddress     *string       `json:"ip_address,omitempty"`
	UserAgent     *string       `json:"user_agent,omitempty"`
	Timestamp     time.Time     `json:"timestamp"`
}

// NewLifecycleAuditLog creates an audit log entry
func NewLifecycleAuditLog(userID, performedBy string, transition StateTransition, reason *string) *LifecycleAuditLog {
	return &LifecycleAuditLog{
		ID:          uuid.New().String(),
		UserID:      userID,
		Transition:  transition,
		Reason:      reason,
		PerformedBy: performedBy,
		Timestamp:   time.Now(),
	}
}

// LifecyclePolicy defines rules for automatic lifecycle transitions
type LifecyclePolicy struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Description     *string                `json:"description,omitempty"`
	Enabled         bool                   `json:"enabled"`
	AutoSuspend     *AutoSuspendPolicy     `json:"auto_suspend,omitempty"`
	AutoDeprovision *AutoDeprovisionPolicy `json:"auto_deprovision,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// AutoSuspendPolicy defines when to auto-suspend users
type AutoSuspendPolicy struct {
	Enabled              bool          `json:"enabled"`
	InactiveDays         int           `json:"inactive_days"`          // Suspend after N days of inactivity
	FailedLoginThreshold int           `json:"failed_login_threshold"` // Suspend after N failed logins
}

// AutoDeprovisionPolicy defines when to auto-deprovision users
type AutoDeprovisionPolicy struct {
	Enabled      bool `json:"enabled"`
	SuspendedDays int  `json:"suspended_days"` // Deprovision after N days in suspended state
}

// EvaluatePolicy evaluates a lifecycle policy against a user
func (m *LifecycleManager) EvaluatePolicy(ctx context.Context, policy *LifecyclePolicy, user *User) ([]IdentityState, error) {
	var suggestedTransitions []IdentityState

	if !policy.Enabled {
		return suggestedTransitions, nil
	}

	currentState := user.GetState()

	// Check auto-suspend policy
	if policy.AutoSuspend != nil && policy.AutoSuspend.Enabled && currentState == StateActive {
		// Check inactivity
		if policy.AutoSuspend.InactiveDays > 0 && user.LastLoginAt != nil {
			inactiveDuration := time.Since(*user.LastLoginAt)
			if inactiveDuration.Hours()/24 >= float64(policy.AutoSuspend.InactiveDays) {
				suggestedTransitions = append(suggestedTransitions, StateSuspended)
			}
		}
		// Check failed login threshold
		if policy.AutoSuspend.FailedLoginThreshold > 0 && user.FailedLoginCount >= policy.AutoSuspend.FailedLoginThreshold {
			suggestedTransitions = append(suggestedTransitions, StateSuspended)
		}
	}

	// Check auto-deprovision policy
	if policy.AutoDeprovision != nil && policy.AutoDeprovision.Enabled && currentState == StateSuspended {
		if policy.AutoDeprovision.SuspendedDays > 0 {
			stateSince, err := user.GetStateSince()
			if err == nil && stateSince != nil {
				suspendedDuration := time.Since(*stateSince)
				if suspendedDuration.Hours()/24 >= float64(policy.AutoDeprovision.SuspendedDays) {
					suggestedTransitions = append(suggestedTransitions, StateDeprovisioned)
				}
			}
		}
	}

	return suggestedTransitions, nil
}
