// Package governance provides access request workflow functionality
package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// RequestStatus represents the state of an access request
type RequestStatus string

const (
	StatusPending   RequestStatus = "pending"
	StatusApproved  RequestStatus = "approved"
	StatusDenied    RequestStatus = "denied"
	StatusExpired   RequestStatus = "expired"
	StatusCancelled RequestStatus = "cancelled"
	StatusFulfilled RequestStatus = "fulfilled"
)

// RequestEventType represents types of events that trigger notifications
type RequestEventType string

const (
	EventRequestSubmitted  RequestEventType = "request_submitted"
	EventRequestApproved   RequestEventType = "request_approved"
	EventRequestDenied     RequestEventType = "request_denied"
	EventRequestEscalated  RequestEventType = "request_escalated"
	EventRequestExpired    RequestEventType = "request_expired"
	EventRequestCancelled  RequestEventType = "request_cancelled"
)

// ApprovalStepType defines the type of approval step
type ApprovalStepType string

const (
	ApprovalStepTypeSpecificUser ApprovalStepType = "specific_user"   // Specific user must approve
	ApprovalStepTypeRole        ApprovalStepType = "role"            // Any user with role must approve
	ApprovalStepTypeGroup       ApprovalStepType = "group"           // Any user in group must approve
	ApprovalStepTypeManager     ApprovalStepType = "manager"         // Resource owner's manager
	ApprovalStepTypeAuto        ApprovalStepType = "auto"            // Automatic approval based on conditions
)

// ApprovalStep represents a single step in an approval chain
type ApprovalStep struct {
	Order          int              `json:"order"`                      // Step order (1-based)
	Type           ApprovalStepType `json:"type"`                       // Type of approval required
	ApproverID     string           `json:"approver_id,omitempty"`      // Specific user ID (for type=specific_user)
	RoleID         string           `json:"role_id,omitempty"`          // Role ID (for type=role)
	GroupID        string           `json:"group_id,omitempty"`         // Group ID (for type=group)
	MinApprovals   int              `json:"min_approvals"`              // Minimum number of approvals needed (default: 1)
	TimeoutMinutes int              `json:"timeout_minutes,omitempty"`  // Step timeout in minutes
	Conditions     map[string]interface{} `json:"conditions,omitempty"` // Auto-approval conditions

	// Legacy fields for backward compatibility
	StepOrder    int    `json:"step_order,omitempty"`
	ApproverType string `json:"approver_type,omitempty"` // "user", "role", "manager", "security_team"
	ApproverName string `json:"approver_name,omitempty"`
	Required     bool   `json:"required,omitempty"` // true = must approve, false = optional
}

// ApprovalChainConfig defines the approval workflow configuration
type ApprovalChainConfig struct {
	Steps            []ApprovalStep `json:"steps"`
	EscalateAfterHours int           `json:"escalate_after_hours"` // Default 24h
	EscalateTo       []string       `json:"escalate_to"`           // User IDs to escalate to
}

// AccessRequestDetail extends AccessRequest with workflow-specific fields
type AccessRequestDetail struct {
	AccessRequest
	ApprovalChain      []ApprovalStep `json:"approval_chain"`
	CurrentStep        int            `json:"current_step"`
	EscalationDueAt    *time.Time     `json:"escalation_due_at,omitempty"`
	EscalationNotified bool           `json:"escalation_notified"`
}

// NotificationHook is called when request state changes
type NotificationHook func(ctx context.Context, eventType RequestEventType, request *AccessRequestDetail) error

// RequestService handles access request workflow operations
type RequestService struct {
	db                *database.PostgresDB
	logger            *zap.Logger
	notificationHooks []NotificationHook
	escalationChecker *time.Ticker
	stopChan          chan struct{}
}

// NewRequestService creates a new request service instance
func NewRequestService(db *database.PostgresDB, logger *zap.Logger) *RequestService {
	return &RequestService{
		db:                db,
		logger:            logger,
		notificationHooks: []NotificationHook{},
		stopChan:          make(chan struct{}),
	}
}

// RegisterNotificationHook registers a callback for request state changes
func (s *RequestService) RegisterNotificationHook(hook NotificationHook) {
	s.notificationHooks = append(s.notificationHooks, hook)
}

// SubmitRequest submits a new access request with the specified approval chain
func (s *RequestService) SubmitRequest(ctx context.Context, requesterID, requestedRole, justification string, approvalChain ApprovalChainConfig) (*AccessRequestDetail, error) {
	if requesterID == "" {
		return nil, fmt.Errorf("requester_id is required")
	}
	if requestedRole == "" {
		return nil, fmt.Errorf("requested_role is required")
	}
	if justification == "" {
		return nil, fmt.Errorf("justification is required")
	}
	if len(approvalChain.Steps) == 0 {
		return nil, fmt.Errorf("approval chain must have at least one step")
	}

	// Set default escalation time if not configured
	escalateHours := approvalChain.EscalateAfterHours
	if escalateHours == 0 {
		escalateHours = 24
	}

	id := uuid.New().String()
	now := time.Now()
	escalationDueAt := now.Add(time.Duration(escalateHours) * time.Hour)

	// Serialize approval chain
	chainJSON, err := json.Marshal(approvalChain.Steps)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize approval chain: %w", err)
	}

	// Serialize escalation targets
	escalationJSON, _ := json.Marshal(approvalChain.EscalateTo)

	// Create the request
	_, err = s.db.Pool.Exec(ctx,
		`INSERT INTO access_requests (id, requester_id, resource_type, resource_id, resource_name, justification, status, priority, created_at, updated_at)
		 VALUES ($1, $2, 'role', $3, $4, $5, 'pending', 'normal', $6, $6)`,
		id, requesterID, requestedRole, requestedRole, justification, now)
	if err != nil {
		s.logger.Error("Failed to create access request",
			zap.String("requester_id", requesterID),
			zap.String("role", requestedRole),
			zap.Error(err))
		return nil, fmt.Errorf("failed to create access request: %w", err)
	}

	// Store approval chain configuration
	_, err = s.db.Pool.Exec(ctx,
		`INSERT INTO request_approval_chains (request_id, steps, escalate_after_hours, escalate_to, escalation_due_at, current_step, escalation_notified)
		 VALUES ($1, $2, $3, $4, $5, 0, false)`,
		id, chainJSON, escalateHours, escalationJSON, escalationDueAt)
	if err != nil {
		s.logger.Error("Failed to store approval chain",
			zap.String("request_id", id),
			zap.Error(err))
		// Clean up the request
		s.db.Pool.Exec(ctx, `DELETE FROM access_requests WHERE id = $1`, id)
		return nil, fmt.Errorf("failed to store approval chain: %w", err)
	}

	// Create approval records for each step
	for i, step := range approvalChain.Steps {
		approverID := step.ApproverID
		if approverID == "" && step.ApproverType == "manager" {
			// Resolve manager for requester
			managerID, err := s.resolveManager(ctx, requesterID)
			if err != nil {
				s.logger.Warn("Failed to resolve manager",
					zap.String("requester_id", requesterID),
					zap.Error(err))
				// Skip this step or use a default
				continue
			}
			approverID = managerID
			step.ApproverID = managerID
		}

		_, err := s.db.Pool.Exec(ctx,
			`INSERT INTO access_request_approvals (request_id, approver_id, step_order, decision, created_at)
			 VALUES ($1, $2, $3, 'pending', $4)`,
			id, approverID, i+1, now)
		if err != nil {
			s.logger.Error("Failed to create approval record",
				zap.String("request_id", id),
				zap.Int("step", i+1),
				zap.Error(err))
		}
	}

	detail := &AccessRequestDetail{
		AccessRequest: AccessRequest{
			ID:            id,
			RequesterID:   requesterID,
			ResourceType:  "role",
			ResourceID:    requestedRole,
			ResourceName:  requestedRole,
			Justification: justification,
			Status:        string(StatusPending),
			Priority:      "normal",
			CreatedAt:     now,
			UpdatedAt:     now,
		},
		ApprovalChain:      approvalChain.Steps,
		CurrentStep:        0,
		EscalationDueAt:    &escalationDueAt,
		EscalationNotified: false,
	}

	// Trigger notification hooks
	s.notifyHooks(ctx, EventRequestSubmitted, detail)

	s.logger.Info("Access request submitted",
		zap.String("request_id", id),
		zap.String("requester_id", requesterID),
		zap.String("role", requestedRole),
		zap.Int("approval_steps", len(approvalChain.Steps)))

	return detail, nil
}

// ApproveRequest processes an approval decision for a request
func (s *RequestService) ApproveRequest(ctx context.Context, requestID, approverID, comments string) (*AccessRequestDetail, error) {
	// Get the request and approval chain
	detail, err := s.getRequestDetail(ctx, requestID)
	if err != nil {
		return nil, err
	}

	if detail.Status != string(StatusPending) {
		return nil, fmt.Errorf("request is not in pending state: %s", detail.Status)
	}

	// Find the pending approval for this approver
	var approvalID string
	var stepOrder int
	err = s.db.Pool.QueryRow(ctx,
		`SELECT id, step_order FROM access_request_approvals
		 WHERE request_id = $1 AND approver_id = $2 AND decision = 'pending'
		 ORDER BY step_order ASC LIMIT 1`,
		requestID, approverID).Scan(&approvalID, &stepOrder)
	if err != nil {
		return nil, fmt.Errorf("no pending approval found for this approver: %w", err)
	}

	now := time.Now()

	// Update the approval
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE access_request_approvals SET decision = 'approved', comments = $1, decided_at = $2 WHERE id = $3`,
		comments, now, approvalID)
	if err != nil {
		return nil, fmt.Errorf("failed to update approval: %w", err)
	}

	// Check if all required approvals are complete
	var pendingCount int
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM access_request_approvals WHERE request_id = $1 AND decision = 'pending'`,
		requestID).Scan(&pendingCount)
	if err != nil {
		return nil, fmt.Errorf("failed to check pending approvals: %w", err)
	}

	if pendingCount == 0 {
		// All approvals complete - mark request as approved
		_, err = s.db.Pool.Exec(ctx,
			`UPDATE access_requests SET status = 'approved', updated_at = $1 WHERE id = $2`,
			now, requestID)
		if err != nil {
			return nil, fmt.Errorf("failed to update request status: %w", err)
		}

		detail.Status = string(StatusApproved)
		detail.UpdatedAt = now

		// Trigger notification hooks
		s.notifyHooks(ctx, EventRequestApproved, detail)

		s.logger.Info("Access request fully approved",
			zap.String("request_id", requestID),
			zap.String("final_approver", approverID))
	} else {
		s.logger.Info("Access request step approved",
			zap.String("request_id", requestID),
			zap.String("approver", approverID),
			zap.Int("step", stepOrder),
			zap.Int("remaining", pendingCount))
	}

	// Refresh and return
	return s.getRequestDetail(ctx, requestID)
}

// DenyRequest denies an access request
func (s *RequestService) DenyRequest(ctx context.Context, requestID, approverID, comments string) (*AccessRequestDetail, error) {
	// Get the request
	detail, err := s.getRequestDetail(ctx, requestID)
	if err != nil {
		return nil, err
	}

	if detail.Status != string(StatusPending) {
		return nil, fmt.Errorf("request is not in pending state: %s", detail.Status)
	}

	// Find the pending approval for this approver
	var approvalID string
	err = s.db.Pool.QueryRow(ctx,
		`SELECT id FROM access_request_approvals
		 WHERE request_id = $1 AND approver_id = $2 AND decision = 'pending' LIMIT 1`,
		requestID, approverID).Scan(&approvalID)
	if err != nil {
		return nil, fmt.Errorf("no pending approval found for this approver: %w", err)
	}

	now := time.Now()

	// Update the approval
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE access_request_approvals SET decision = 'denied', comments = $1, decided_at = $2 WHERE id = $3`,
		comments, now, approvalID)
	if err != nil {
		return nil, fmt.Errorf("failed to update approval: %w", err)
	}

	// Mark request as denied
	_, err = s.db.Pool.Exec(ctx,
		`UPDATE access_requests SET status = 'denied', updated_at = $1 WHERE id = $2`,
		now, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to update request status: %w", err)
	}

	detail.Status = string(StatusDenied)
	detail.UpdatedAt = now

	// Trigger notification hooks
	s.notifyHooks(ctx, EventRequestDenied, detail)

	s.logger.Info("Access request denied",
		zap.String("request_id", requestID),
		zap.String("denied_by", approverID),
		zap.String("comments", comments))

	return detail, nil
}

// CancelRequest cancels a pending request (only by requester)
func (s *RequestService) CancelRequest(ctx context.Context, requestID, requesterID string) error {
	result, err := s.db.Pool.Exec(ctx,
		`UPDATE access_requests SET status = 'cancelled', updated_at = $1
		 WHERE id = $2 AND requester_id = $3 AND status = 'pending'`,
		time.Now(), requestID, requesterID)
	if err != nil {
		return fmt.Errorf("failed to cancel request: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("request not found, not pending, or not owned by requester")
	}

	// Trigger notification hooks
	detail, _ := s.getRequestDetail(ctx, requestID)
	if detail != nil {
		s.notifyHooks(ctx, EventRequestCancelled, detail)
	}

	s.logger.Info("Access request cancelled",
		zap.String("request_id", requestID),
		zap.String("cancelled_by", requesterID))

	return nil
}

// StartEscalationChecker starts the background goroutine that checks for requests
// needing escalation and auto-escalates after the configured timeout
func (s *RequestService) StartEscalationChecker(ctx context.Context, checkInterval time.Duration) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	s.logger.Info("Request escalation checker started",
		zap.Duration("interval", checkInterval))

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Request escalation checker stopped")
			return
		case <-ticker.C:
			s.checkEscalations(ctx)
		}
	}
}

// checkEscalations finds pending requests that need escalation and processes them
func (s *RequestService) checkEscalations(ctx context.Context) {
	// Find pending requests past their escalation due time that haven't been notified
	rows, err := s.db.Pool.Query(ctx,
		`SELECT r.id, r.requester_id, r.resource_id, ac.steps, ac.escalate_to
		 FROM access_requests r
		 INNER JOIN request_approval_chains ac ON ac.request_id = r.id
		 WHERE r.status = 'pending'
		   AND ac.escalation_due_at <= NOW()
		   AND ac.escalation_notified = false`)
	if err != nil {
		s.logger.Error("Failed to query requests needing escalation", zap.Error(err))
		return
	}
	defer rows.Close()

	type escalationInfo struct {
		RequestID   string
		RequesterID string
		ResourceID  string
		Steps       []ApprovalStep
		EscalateTo  []string
	}

	var toEscalate []escalationInfo
	for rows.Next() {
		var info escalationInfo
		var stepsJSON, escalateJSON []byte

		if err := rows.Scan(&info.RequestID, &info.RequesterID, &info.ResourceID,
			&stepsJSON, &escalateJSON); err != nil {
			continue
		}

		json.Unmarshal(stepsJSON, &info.Steps)
		json.Unmarshal(escalateJSON, &info.EscalateTo)

		toEscalate = append(toEscalate, info)
	}

	for _, info := range toEscalate {
		// Mark as notified
		s.db.Pool.Exec(ctx,
			`UPDATE request_approval_chains SET escalation_notified = true WHERE request_id = $1`,
			info.RequestID)

		// Add escalation approvals for each escalation target
		now := time.Now()
		for _, escalatorID := range info.EscalateTo {
			if escalatorID == "" {
				continue
			}

			// Check if approver already exists
			var exists bool
			s.db.Pool.QueryRow(ctx,
				`SELECT EXISTS(SELECT 1 FROM access_request_approvals WHERE request_id = $1 AND approver_id = $2)`,
				info.RequestID, escalatorID).Scan(&exists)

			if !exists {
				s.db.Pool.Exec(ctx,
					`INSERT INTO access_request_approvals (request_id, approver_id, step_order, decision, created_at)
					 VALUES ($1, $2, 999, 'pending', $3)`,
					info.RequestID, escalatorID, now)
			}
		}

		// Get detail for notification
		detail, _ := s.getRequestDetail(ctx, info.RequestID)
		if detail != nil {
			s.notifyHooks(ctx, EventRequestEscalated, detail)
		}

		s.logger.Info("Access request escalated",
			zap.String("request_id", info.RequestID),
			zap.Int("escalation_targets", len(info.EscalateTo)))
	}

	// Also expire requests that have been pending too long (optional, configurable)
	// This can be enabled via policy configuration
}

// GetRequest retrieves a request with its full approval chain status
func (s *RequestService) GetRequest(ctx context.Context, requestID string) (*AccessRequestDetail, error) {
	return s.getRequestDetail(ctx, requestID)
}

// getRequestDetail retrieves the full request details including approval chain
func (s *RequestService) getRequestDetail(ctx context.Context, requestID string) (*AccessRequestDetail, error) {
	var detail AccessRequestDetail
	var stepsJSON []byte
	var escalationDueAt *time.Time

	// Get request and approval chain in one query
	err := s.db.Pool.QueryRow(ctx,
		`SELECT r.id, r.requester_id, r.resource_type, r.resource_id, r.resource_name,
		        r.justification, r.status, r.priority, r.expires_at, r.created_at, r.updated_at,
		        ac.steps, ac.current_step, ac.escalation_due_at, ac.escalation_notified
		 FROM access_requests r
		 LEFT JOIN request_approval_chains ac ON ac.request_id = r.id
		 WHERE r.id = $1`,
		requestID).Scan(
		&detail.ID, &detail.RequesterID, &detail.ResourceType, &detail.ResourceID,
		&detail.ResourceName, &detail.Justification, &detail.Status, &detail.Priority,
		&detail.ExpiresAt, &detail.CreatedAt, &detail.UpdatedAt,
		&stepsJSON, &detail.CurrentStep, &escalationDueAt, &detail.EscalationNotified)

	if err != nil {
		return nil, fmt.Errorf("request not found: %w", err)
	}

	detail.EscalationDueAt = escalationDueAt

	// Parse approval chain
	if stepsJSON != nil {
		json.Unmarshal(stepsJSON, &detail.ApprovalChain)
	}

	// Get approvals status
	rows, err := s.db.Pool.Query(ctx,
		`SELECT id, approver_id, step_order, decision, comments, decided_at, created_at
		 FROM access_request_approvals WHERE request_id = $1 ORDER BY step_order ASC`,
		requestID)
	if err == nil {
		defer rows.Close()

		for rows.Next() {
			var a Approval
			if err := rows.Scan(&a.ID, &a.ApproverID, &a.StepOrder,
				&a.Decision, &a.Comments, &a.DecidedAt, &a.CreatedAt); err != nil {
				continue
			}
			a.RequestID = requestID
			detail.Approvals = append(detail.Approvals, a)
		}
	}

	return &detail, nil
}

// resolveManager finds the manager of a user
func (s *RequestService) resolveManager(ctx context.Context, userID string) (string, error) {
	var managerID string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT manager_id FROM users WHERE id = $1`, userID).Scan(&managerID)
	if err != nil {
		return "", fmt.Errorf("failed to resolve manager: %w", err)
	}
	if managerID == "" {
		return "", fmt.Errorf("user has no manager assigned")
	}
	return managerID, nil
}

// notifyHooks calls all registered notification hooks
func (s *RequestService) notifyHooks(ctx context.Context, eventType RequestEventType, request *AccessRequestDetail) {
	for _, hook := range s.notificationHooks {
		if err := hook(ctx, eventType, request); err != nil {
			s.logger.Error("Notification hook failed",
				zap.String("event_type", string(eventType)),
				zap.String("request_id", request.ID),
				zap.Error(err))
		}
	}
}

// GetPendingApprovalsForUser returns all pending approvals for a specific approver
func (s *RequestService) GetPendingApprovalsForUser(ctx context.Context, userID string) ([]AccessRequestDetail, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT r.id, r.requester_id, r.resource_type, r.resource_id, r.resource_name,
		        r.justification, r.status, r.priority, r.created_at, r.updated_at,
		        ac.steps, ac.current_step
		 FROM access_request_approvals a
		 INNER JOIN access_requests r ON r.id = a.request_id
		 LEFT JOIN request_approval_chains ac ON ac.request_id = r.id
		 WHERE a.approver_id = $1 AND a.decision = 'pending' AND r.status = 'pending'
		 ORDER BY r.created_at ASC`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending approvals: %w", err)
	}
	defer rows.Close()

	var results []AccessRequestDetail
	for rows.Next() {
		var detail AccessRequestDetail
		var stepsJSON []byte

		if err := rows.Scan(
			&detail.ID, &detail.RequesterID, &detail.ResourceType, &detail.ResourceID,
			&detail.ResourceName, &detail.Justification, &detail.Status, &detail.Priority,
			&detail.CreatedAt, &detail.UpdatedAt, &stepsJSON, &detail.CurrentStep); err != nil {
			continue
		}

		if stepsJSON != nil {
			json.Unmarshal(stepsJSON, &detail.ApprovalChain)
		}

		results = append(results, detail)
	}

	if results == nil {
		return []AccessRequestDetail{}, nil
	}
	return results, nil
}
