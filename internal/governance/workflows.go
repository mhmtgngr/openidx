package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// AccessRequest represents a request for access to a role, group, or application
type AccessRequest struct {
	ID             string      `json:"id"`
	RequesterID    string      `json:"requester_id"`
	RequesterName  string      `json:"requester_name,omitempty"`
	ResourceType   string      `json:"resource_type"`
	ResourceID     string      `json:"resource_id"`
	ResourceName   string      `json:"resource_name"`
	Justification  string      `json:"justification"`
	Status         string      `json:"status"`
	Priority       string      `json:"priority"`
	ExpiresAt      *time.Time  `json:"expires_at,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
	Approvals      []Approval  `json:"approvals,omitempty"`
}

// Approval represents a single approval/denial decision on an access request
type Approval struct {
	ID           string     `json:"id"`
	RequestID    string     `json:"request_id"`
	ApproverID   string     `json:"approver_id"`
	ApproverName string     `json:"approver_name,omitempty"`
	StepOrder    int        `json:"step_order"`
	Decision     string     `json:"decision"`
	Comments     string     `json:"comments"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// ApprovalPolicy defines who must approve requests for specific resource types
type ApprovalPolicy struct {
	ID                    string                   `json:"id"`
	Name                  string                   `json:"name"`
	ResourceType          string                   `json:"resource_type"`
	ResourceID            *string                  `json:"resource_id,omitempty"`
	ApprovalSteps         []ApprovalStep           `json:"approval_steps"`
	AutoApproveConditions map[string]interface{}   `json:"auto_approve_conditions,omitempty"`
	MaxWaitHours          int                      `json:"max_wait_hours"`
	Enabled               bool                     `json:"enabled"`
	CreatedAt             time.Time                `json:"created_at"`
	UpdatedAt             time.Time                `json:"updated_at"`
}

// parseDuration converts a human-friendly duration string to time.Duration.
// Supports: "4h", "8h", "1d", "3d", "7d", "30d", "90d"
func parseDuration(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}
	unit := s[len(s)-1]
	value := s[:len(s)-1]
	var n int
	if _, err := fmt.Sscanf(value, "%d", &n); err != nil {
		return 0, fmt.Errorf("invalid duration value: %s", s)
	}
	switch unit {
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unsupported duration unit: %c", unit)
	}
}

// handleCreateAccessRequest creates a new access request
func (s *Service) handleCreateAccessRequest(c *gin.Context) {
	var body struct {
		ResourceType  string `json:"resource_type"`
		ResourceID    string `json:"resource_id"`
		ResourceName  string `json:"resource_name"`
		Justification string `json:"justification"`
		Priority      string `json:"priority"`
		Duration      string `json:"duration,omitempty"` // e.g. "4h", "1d", "7d", "30d" — empty means permanent
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if body.ResourceType == "" || body.ResourceName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resource_type and resource_name are required"})
		return
	}

	if body.Priority == "" {
		body.Priority = "normal"
	}

	requesterID := c.GetString("user_id")
	if requesterID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	if body.ResourceID == "" {
		body.ResourceID = uuid.New().String()
	}

	// Parse duration to calculate expires_at
	var expiresAt *time.Time
	if body.Duration != "" {
		d, err := parseDuration(body.Duration)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid duration: " + err.Error()})
			return
		}
		t := time.Now().Add(d)
		expiresAt = &t
	}

	id := uuid.New().String()
	now := time.Now()

	_, err := s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO access_requests (id, requester_id, resource_type, resource_id, resource_name, justification, status, priority, expires_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		id, requesterID, body.ResourceType, body.ResourceID, body.ResourceName,
		body.Justification, "pending", body.Priority, expiresAt, now, now,
	)
	if err != nil {
		s.logger.Error("Failed to create access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create access request"})
		return
	}

	// Find matching approval policy and create approval rows
	s.createApprovalRows(c.Request.Context(), id, body.ResourceType, body.ResourceID)

	c.JSON(http.StatusCreated, AccessRequest{
		ID:            id,
		RequesterID:   requesterID,
		ResourceType:  body.ResourceType,
		ResourceID:    body.ResourceID,
		ResourceName:  body.ResourceName,
		Justification: body.Justification,
		Status:        "pending",
		Priority:      body.Priority,
		ExpiresAt:     expiresAt,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
}

// createApprovalRows looks up approval policies and creates approval rows for a request
func (s *Service) createApprovalRows(ctx context.Context, requestID, resourceType, resourceID string) {
	// Try to find a matching policy (specific resource first, then generic)
	var stepsJSON []byte
	err := s.db.Pool.QueryRow(ctx,
		`SELECT approval_steps FROM approval_policies
		 WHERE resource_type = $1 AND (resource_id = $2 OR resource_id IS NULL) AND enabled = true
		 ORDER BY resource_id NULLS LAST LIMIT 1`,
		resourceType, resourceID,
	).Scan(&stepsJSON)
	if err != nil {
		// No matching policy — create a default admin approval
		adminID := "00000000-0000-0000-0000-000000000001"
		_, _ = s.db.Pool.Exec(ctx,
			`INSERT INTO access_request_approvals (id, request_id, approver_id, step_order, decision, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			uuid.New().String(), requestID, adminID, 1, "pending", time.Now(),
		)
		return
	}

	var steps []ApprovalStep
	if err := json.Unmarshal(stepsJSON, &steps); err != nil || len(steps) == 0 {
		return
	}

	for i, step := range steps {
		// Handle different approval step types
		switch step.Type {
		case ApprovalStepTypeSpecificUser:
			if step.ApproverID != "" {
				_, _ = s.db.Pool.Exec(ctx,
					`INSERT INTO access_request_approvals (id, request_id, approver_id, step_order, decision, created_at)
					 VALUES ($1, $2, $3, $4, $5, $6)`,
					uuid.New().String(), requestID, step.ApproverID, step.Order, "pending", time.Now(),
				)
			}
		case ApprovalStepTypeRole:
			// For role-based approval, we need to query users with this role
			// For now, skip role-based approvals in this implementation
			s.logger.Debug("Role-based approval step not yet implemented", zap.Int("step", i+1), zap.String("role_id", step.RoleID))
		case ApprovalStepTypeGroup:
			// For group-based approval, we need to query users in this group
			s.logger.Debug("Group-based approval step not yet implemented", zap.Int("step", i+1), zap.String("group_id", step.GroupID))
		case ApprovalStepTypeManager:
			// For manager approval, find the resource owner's manager
			s.logger.Debug("Manager-based approval step not yet implemented", zap.Int("step", i+1))
		case ApprovalStepTypeAuto:
			// Automatic approval - no human approver needed
			s.logger.Debug("Auto-approval step", zap.Int("step", i+1))
		default:
			s.logger.Warn("Unknown approval step type", zap.String("type", string(step.Type)))
		}
	}
}

// handleListAccessRequests lists access requests with optional filtering
func (s *Service) handleListAccessRequests(c *gin.Context) {
	status := c.Query("status")
	requesterID := c.Query("requester_id")

	limit := 20
	offset := 0
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	if o := c.Query("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	if offset < 0 {
		offset = 0
	}

	// Handle "me" as requester_id
	if requesterID == "me" {
		requesterID = c.GetString("user_id")
		if requesterID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
	}

	ctx := c.Request.Context()

	baseQuery := `SELECT ar.id, ar.requester_id, COALESCE(u.display_name, u.username, ''),
		ar.resource_type, ar.resource_id, ar.resource_name, ar.justification,
		ar.status, ar.priority, ar.expires_at, ar.created_at, ar.updated_at
		FROM access_requests ar
		LEFT JOIN users u ON u.id = ar.requester_id`
	countQuery := `SELECT COUNT(*) FROM access_requests ar`

	conditions := []string{}
	args := []interface{}{}
	argIdx := 1

	if status != "" {
		conditions = append(conditions, fmt.Sprintf("ar.status = $%d", argIdx))
		args = append(args, status)
		argIdx++
	}
	if requesterID != "" {
		conditions = append(conditions, fmt.Sprintf("ar.requester_id = $%d", argIdx))
		args = append(args, requesterID)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE "
		for i, cond := range conditions {
			if i > 0 {
				whereClause += " AND "
			}
			whereClause += cond
		}
	}

	var total int
	err := s.db.Pool.QueryRow(ctx, countQuery+whereClause, args...).Scan(&total)
	if err != nil {
		s.logger.Error("Failed to count access requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count access requests"})
		return
	}

	finalQuery := baseQuery + whereClause + " ORDER BY ar.created_at DESC"
	paginatedArgs := append([]interface{}{}, args...)
	finalQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	paginatedArgs = append(paginatedArgs, limit, offset)

	rows, err := s.db.Pool.Query(ctx, finalQuery, paginatedArgs...)
	if err != nil {
		s.logger.Error("Failed to query access requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query access requests"})
		return
	}
	defer rows.Close()

	requests := []AccessRequest{}
	for rows.Next() {
		var r AccessRequest
		var requesterName *string
		var expiresAt *time.Time
		if err := rows.Scan(&r.ID, &r.RequesterID, &requesterName,
			&r.ResourceType, &r.ResourceID, &r.ResourceName, &r.Justification,
			&r.Status, &r.Priority, &expiresAt, &r.CreatedAt, &r.UpdatedAt); err != nil {
			s.logger.Error("Failed to scan access request", zap.Error(err))
			continue
		}
		if requesterName != nil {
			r.RequesterName = *requesterName
		}
		r.ExpiresAt = expiresAt
		requests = append(requests, r)
	}

	c.JSON(http.StatusOK, gin.H{
		"requests": requests,
		"total":    total,
	})
}

// handleGetAccessRequest gets a single access request with its approvals
func (s *Service) handleGetAccessRequest(c *gin.Context) {
	id := c.Param("id")

	var r AccessRequest
	var requesterName *string
	var expiresAt *time.Time

	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT ar.id, ar.requester_id, COALESCE(u.display_name, u.username, ''),
		 ar.resource_type, ar.resource_id, ar.resource_name, ar.justification,
		 ar.status, ar.priority, ar.expires_at, ar.created_at, ar.updated_at
		 FROM access_requests ar
		 LEFT JOIN users u ON u.id = ar.requester_id
		 WHERE ar.id = $1`, id,
	).Scan(&r.ID, &r.RequesterID, &requesterName,
		&r.ResourceType, &r.ResourceID, &r.ResourceName, &r.Justification,
		&r.Status, &r.Priority, &expiresAt, &r.CreatedAt, &r.UpdatedAt)

	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Access request not found"})
			return
		}
		s.logger.Error("Failed to get access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get access request"})
		return
	}
	if requesterName != nil {
		r.RequesterName = *requesterName
	}
	r.ExpiresAt = expiresAt

	// Fetch approvals
	approvalRows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT a.id, a.request_id, a.approver_id, COALESCE(u.display_name, u.username, ''), a.step_order, a.decision, a.comments, a.decided_at, a.created_at
		 FROM access_request_approvals a
		 LEFT JOIN users u ON u.id = a.approver_id
		 WHERE a.request_id = $1
		 ORDER BY a.step_order ASC`, id,
	)
	if err != nil {
		s.logger.Error("Failed to query approvals", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get approvals"})
		return
	}
	defer approvalRows.Close()

	var approvals []Approval
	for approvalRows.Next() {
		var a Approval
		var approverName *string
		var decidedAt *time.Time
		if err := approvalRows.Scan(&a.ID, &a.RequestID, &a.ApproverID, &approverName,
			&a.StepOrder, &a.Decision, &a.Comments, &decidedAt, &a.CreatedAt); err != nil {
			s.logger.Error("Failed to scan approval", zap.Error(err))
			continue
		}
		if approverName != nil {
			a.ApproverName = *approverName
		}
		a.DecidedAt = decidedAt
		approvals = append(approvals, a)
	}

	if approvals == nil {
		approvals = []Approval{}
	}
	r.Approvals = approvals

	c.JSON(http.StatusOK, r)
}

// handleApproveRequest approves an access request
func (s *Service) handleApproveRequest(c *gin.Context) {
	id := c.Param("id")

	var body struct {
		Comments string `json:"comments"`
	}
	_ = c.ShouldBindJSON(&body)

	approverID := c.GetString("user_id")
	if approverID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	now := time.Now()

	result, err := s.db.Pool.Exec(c.Request.Context(),
		`UPDATE access_request_approvals
		 SET decision = 'approved', comments = $1, decided_at = $2
		 WHERE request_id = $3 AND approver_id = $4 AND decision = 'pending'`,
		body.Comments, now, id, approverID,
	)
	if err != nil {
		s.logger.Error("Failed to approve request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to approve request"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No pending approval found for this approver"})
		return
	}

	// Check if ALL approvals for this request are now approved
	var pendingCount int
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT COUNT(*) FROM access_request_approvals WHERE request_id = $1 AND decision = 'pending'`,
		id,
	).Scan(&pendingCount)
	if err != nil {
		s.logger.Error("Failed to check pending approvals", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check approval status"})
		return
	}

	if pendingCount == 0 {
		_, err = s.db.Pool.Exec(c.Request.Context(),
			`UPDATE access_requests SET status = 'approved', updated_at = $1 WHERE id = $2`,
			time.Now(), id,
		)
		if err != nil {
			s.logger.Error("Failed to update request status", zap.Error(err))
		}

		var request AccessRequest
		err = s.db.Pool.QueryRow(c.Request.Context(),
			`SELECT id, requester_id, resource_type, resource_id, resource_name, status FROM access_requests WHERE id = $1`, id,
		).Scan(&request.ID, &request.RequesterID, &request.ResourceType, &request.ResourceID, &request.ResourceName, &request.Status)
		if err == nil {
			if fulfillErr := s.fulfillRequest(c.Request.Context(), &request); fulfillErr != nil {
				s.logger.Error("Failed to fulfill approved request", zap.Error(fulfillErr))
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Request approved successfully"})
}

// handleDenyRequest denies an access request
func (s *Service) handleDenyRequest(c *gin.Context) {
	id := c.Param("id")

	var body struct {
		Comments string `json:"comments"`
	}
	_ = c.ShouldBindJSON(&body)

	approverID := c.GetString("user_id")
	if approverID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	now := time.Now()

	result, err := s.db.Pool.Exec(c.Request.Context(),
		`UPDATE access_request_approvals
		 SET decision = 'denied', comments = $1, decided_at = $2
		 WHERE request_id = $3 AND approver_id = $4 AND decision = 'pending'`,
		body.Comments, now, id, approverID,
	)
	if err != nil {
		s.logger.Error("Failed to deny request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deny request"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No pending approval found for this approver"})
		return
	}

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`UPDATE access_requests SET status = 'denied', updated_at = $1 WHERE id = $2`,
		time.Now(), id,
	)
	if err != nil {
		s.logger.Error("Failed to update request status to denied", zap.Error(err))
	}

	c.JSON(http.StatusOK, gin.H{"message": "Request denied"})
}

// handleCancelRequest allows the requester to cancel their own access request
func (s *Service) handleCancelRequest(c *gin.Context) {
	id := c.Param("id")

	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	var requesterID, status string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT requester_id, status FROM access_requests WHERE id = $1`, id,
	).Scan(&requesterID, &status)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Access request not found"})
			return
		}
		s.logger.Error("Failed to get access request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel request"})
		return
	}

	if requesterID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only the requester can cancel this request"})
		return
	}

	if status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Cannot cancel request with status: %s", status)})
		return
	}

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`UPDATE access_requests SET status = 'cancelled', updated_at = $1 WHERE id = $2`,
		time.Now(), id,
	)
	if err != nil {
		s.logger.Error("Failed to cancel request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel request"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Request cancelled"})
}

// handleListPendingApprovals returns pending approvals for the current user
func (s *Service) handleListPendingApprovals(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT ar.id, ar.requester_id, COALESCE(ru.display_name, ru.username, ''),
		        ar.resource_type, ar.resource_id, ar.resource_name, ar.justification,
		        ar.status, ar.priority, ar.created_at, ar.updated_at
		 FROM access_request_approvals a
		 JOIN access_requests ar ON ar.id = a.request_id
		 LEFT JOIN users ru ON ru.id = ar.requester_id
		 WHERE a.approver_id = $1 AND a.decision = 'pending'
		 ORDER BY ar.created_at DESC`, userID,
	)
	if err != nil {
		s.logger.Error("Failed to query pending approvals", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list pending approvals"})
		return
	}
	defer rows.Close()

	var results []AccessRequest
	for rows.Next() {
		var r AccessRequest
		var requesterName *string
		if err := rows.Scan(
			&r.ID, &r.RequesterID, &requesterName,
			&r.ResourceType, &r.ResourceID, &r.ResourceName, &r.Justification,
			&r.Status, &r.Priority,
			&r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			s.logger.Error("Failed to scan pending approval", zap.Error(err))
			continue
		}
		if requesterName != nil {
			r.RequesterName = *requesterName
		}
		results = append(results, r)
	}

	if results == nil {
		results = []AccessRequest{}
	}

	c.JSON(http.StatusOK, gin.H{"pending_approvals": results})
}

// handleListApprovalPolicies returns all approval policies
func (s *Service) handleListApprovalPolicies(c *gin.Context) {
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, resource_type, resource_id, approval_steps, auto_approve_conditions, max_wait_hours, enabled, created_at, updated_at
		 FROM approval_policies
		 ORDER BY created_at DESC`,
	)
	if err != nil {
		s.logger.Error("Failed to query approval policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list approval policies"})
		return
	}
	defer rows.Close()

	var policies []ApprovalPolicy
	for rows.Next() {
		var p ApprovalPolicy
		var resourceID *string
		var stepsJSON, autoApproveJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.ResourceType, &resourceID,
			&stepsJSON, &autoApproveJSON, &p.MaxWaitHours, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			s.logger.Error("Failed to scan approval policy", zap.Error(err))
			continue
		}
		p.ResourceID = resourceID
		if stepsJSON != nil {
			_ = json.Unmarshal(stepsJSON, &p.ApprovalSteps)
		}
		if p.ApprovalSteps == nil {
			p.ApprovalSteps = []ApprovalStep{}
		}
		if autoApproveJSON != nil {
			_ = json.Unmarshal(autoApproveJSON, &p.AutoApproveConditions)
		}
		policies = append(policies, p)
	}

	if policies == nil {
		policies = []ApprovalPolicy{}
	}

	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

// handleCreateApprovalPolicy creates a new approval policy
func (s *Service) handleCreateApprovalPolicy(c *gin.Context) {
	var body struct {
		Name                  string                   `json:"name"`
		ResourceType          string                   `json:"resource_type"`
		ResourceID            *string                  `json:"resource_id,omitempty"`
		ApprovalSteps         []ApprovalStep           `json:"approval_steps"`
		AutoApproveConditions map[string]interface{}   `json:"auto_approve_conditions,omitempty"`
		MaxWaitHours          int                      `json:"max_wait_hours"`
		Enabled               bool                     `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if body.Name == "" || body.ResourceType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and resource_type are required"})
		return
	}

	stepsJSON, err := json.Marshal(body.ApprovalSteps)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid approval_steps"})
		return
	}

	var autoApproveJSON []byte
	if body.AutoApproveConditions != nil {
		autoApproveJSON, err = json.Marshal(body.AutoApproveConditions)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid auto_approve_conditions"})
			return
		}
	}

	id := uuid.New().String()
	now := time.Now()

	_, err = s.db.Pool.Exec(c.Request.Context(),
		`INSERT INTO approval_policies (id, name, resource_type, resource_id, approval_steps, auto_approve_conditions, max_wait_hours, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		id, body.Name, body.ResourceType, body.ResourceID, stepsJSON, autoApproveJSON,
		body.MaxWaitHours, body.Enabled, now, now,
	)
	if err != nil {
		s.logger.Error("Failed to create approval policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create approval policy"})
		return
	}

	c.JSON(http.StatusCreated, ApprovalPolicy{
		ID:                    id,
		Name:                  body.Name,
		ResourceType:          body.ResourceType,
		ResourceID:            body.ResourceID,
		ApprovalSteps:         body.ApprovalSteps,
		AutoApproveConditions: body.AutoApproveConditions,
		MaxWaitHours:          body.MaxWaitHours,
		Enabled:               body.Enabled,
		CreatedAt:             now,
		UpdatedAt:             now,
	})
}

// handleUpdateApprovalPolicy updates an existing approval policy
func (s *Service) handleUpdateApprovalPolicy(c *gin.Context) {
	id := c.Param("id")

	var body struct {
		Name                  string                   `json:"name"`
		ResourceType          string                   `json:"resource_type"`
		ResourceID            *string                  `json:"resource_id,omitempty"`
		ApprovalSteps         []ApprovalStep           `json:"approval_steps"`
		AutoApproveConditions map[string]interface{}   `json:"auto_approve_conditions,omitempty"`
		MaxWaitHours          int                      `json:"max_wait_hours"`
		Enabled               bool                     `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	stepsJSON, err := json.Marshal(body.ApprovalSteps)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid approval_steps"})
		return
	}

	var autoApproveJSON []byte
	if body.AutoApproveConditions != nil {
		autoApproveJSON, err = json.Marshal(body.AutoApproveConditions)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid auto_approve_conditions"})
			return
		}
	}

	now := time.Now()
	result, err := s.db.Pool.Exec(c.Request.Context(),
		`UPDATE approval_policies
		 SET name = $1, resource_type = $2, resource_id = $3, approval_steps = $4,
		     auto_approve_conditions = $5, max_wait_hours = $6, enabled = $7, updated_at = $8
		 WHERE id = $9`,
		body.Name, body.ResourceType, body.ResourceID, stepsJSON,
		autoApproveJSON, body.MaxWaitHours, body.Enabled, now, id,
	)
	if err != nil {
		s.logger.Error("Failed to update approval policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update approval policy"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Approval policy not found"})
		return
	}

	c.JSON(http.StatusOK, ApprovalPolicy{
		ID:                    id,
		Name:                  body.Name,
		ResourceType:          body.ResourceType,
		ResourceID:            body.ResourceID,
		ApprovalSteps:         body.ApprovalSteps,
		AutoApproveConditions: body.AutoApproveConditions,
		MaxWaitHours:          body.MaxWaitHours,
		Enabled:               body.Enabled,
		UpdatedAt:             now,
	})
}

// handleDeleteApprovalPolicy deletes an approval policy
func (s *Service) handleDeleteApprovalPolicy(c *gin.Context) {
	id := c.Param("id")

	result, err := s.db.Pool.Exec(c.Request.Context(),
		`DELETE FROM approval_policies WHERE id = $1`, id,
	)
	if err != nil {
		s.logger.Error("Failed to delete approval policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete approval policy"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Approval policy not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Approval policy deleted"})
}

// fulfillRequest provisions the approved access by granting the requested resource
func (s *Service) fulfillRequest(ctx context.Context, request *AccessRequest) error {
	switch request.ResourceType {
	case "role":
		_, err := s.db.Pool.Exec(ctx,
			`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			request.RequesterID, request.ResourceID,
		)
		if err != nil {
			return fmt.Errorf("failed to assign role: %w", err)
		}
	case "group":
		_, err := s.db.Pool.Exec(ctx,
			`INSERT INTO group_memberships (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			request.RequesterID, request.ResourceID,
		)
		if err != nil {
			return fmt.Errorf("failed to add to group: %w", err)
		}
	default:
		s.logger.Warn("Fulfillment not implemented for resource type", zap.String("resource_type", request.ResourceType))
	}

	_, err := s.db.Pool.Exec(ctx,
		`UPDATE access_requests SET status = 'fulfilled', updated_at = $1 WHERE id = $2`,
		time.Now(), request.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update request status to fulfilled: %w", err)
	}

	request.Status = "fulfilled"
	return nil
}
