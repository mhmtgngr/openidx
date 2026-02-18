package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// LifecyclePolicy represents an automated de-provisioning policy
type LifecyclePolicy struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	PolicyType       string          `json:"policy_type"`
	Conditions       json.RawMessage `json:"conditions"`
	Actions          json.RawMessage `json:"actions"`
	Enabled          bool            `json:"enabled"`
	Schedule         string          `json:"schedule"`
	GracePeriodDays  int             `json:"grace_period_days"`
	NotifyBeforeDays int             `json:"notify_before_days"`
	LastRunAt        *time.Time      `json:"last_run_at"`
	NextRunAt        *time.Time      `json:"next_run_at"`
	CreatedBy        *string         `json:"created_by"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// LifecycleExecution represents a single execution of a lifecycle policy
type LifecycleExecution struct {
	ID            string          `json:"id"`
	PolicyID      string          `json:"policy_id"`
	Status        string          `json:"status"`
	UsersScanned  int             `json:"users_scanned"`
	UsersAffected int             `json:"users_affected"`
	ActionsTaken  json.RawMessage `json:"actions_taken"`
	StartedAt     time.Time       `json:"started_at"`
	CompletedAt   *time.Time      `json:"completed_at"`
	ErrorMessage  string          `json:"error_message,omitempty"`
}

// AffectedUser represents a user that would be affected by a lifecycle policy
type AffectedUser struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Email       string     `json:"email"`
	Enabled     bool       `json:"enabled"`
	LastLoginAt *time.Time `json:"last_login_at"`
	CreatedAt   time.Time  `json:"created_at"`
	Reason      string     `json:"reason"`
}

// --- Handlers ---

func (s *Service) handleListLifecyclePolicies(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, name, description, policy_type, conditions, actions, enabled, schedule,
		        grace_period_days, notify_before_days, last_run_at, next_run_at, created_by, created_at, updated_at
		 FROM lifecycle_policies ORDER BY name`)
	if err != nil {
		s.logger.Error("Failed to list lifecycle policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list policies"})
		return
	}
	defer rows.Close()

	var policies []LifecyclePolicy
	for rows.Next() {
		var p LifecyclePolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.PolicyType, &p.Conditions, &p.Actions,
			&p.Enabled, &p.Schedule, &p.GracePeriodDays, &p.NotifyBeforeDays,
			&p.LastRunAt, &p.NextRunAt, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	if policies == nil {
		policies = []LifecyclePolicy{}
	}
	c.JSON(http.StatusOK, gin.H{"data": policies})
}

func (s *Service) handleCreateLifecyclePolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Name             string          `json:"name"`
		Description      string          `json:"description"`
		PolicyType       string          `json:"policy_type"`
		Conditions       json.RawMessage `json:"conditions"`
		Actions          json.RawMessage `json:"actions"`
		Schedule         string          `json:"schedule"`
		GracePeriodDays  int             `json:"grace_period_days"`
		NotifyBeforeDays int             `json:"notify_before_days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.Name == "" || req.PolicyType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and policy_type are required"})
		return
	}

	validTypes := map[string]bool{
		"stale_account_disable": true, "disabled_account_cleanup": true,
		"orphan_detection": true, "password_expiry_enforcement": true,
		"scheduled_offboarding": true,
	}
	if !validTypes[req.PolicyType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy type"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	conds := req.Conditions
	if conds == nil {
		conds = json.RawMessage("{}")
	}
	acts := req.Actions
	if acts == nil {
		acts = json.RawMessage("{}")
	}

	if req.GracePeriodDays <= 0 {
		req.GracePeriodDays = 7
	}
	if req.NotifyBeforeDays <= 0 {
		req.NotifyBeforeDays = 3
	}
	if req.Schedule == "" {
		req.Schedule = "daily"
	}

	var id string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO lifecycle_policies (name, description, policy_type, conditions, actions, schedule,
		  grace_period_days, notify_before_days, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		req.Name, req.Description, req.PolicyType, conds, acts, req.Schedule,
		req.GracePeriodDays, req.NotifyBeforeDays, nilIfEmpty(userIDStr),
	).Scan(&id)
	if err != nil {
		s.logger.Error("Failed to create lifecycle policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create policy"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Policy created"})
}

func (s *Service) handleGetLifecyclePolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var p LifecyclePolicy
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, description, policy_type, conditions, actions, enabled, schedule,
		        grace_period_days, notify_before_days, last_run_at, next_run_at, created_by, created_at, updated_at
		 FROM lifecycle_policies WHERE id = $1`, id,
	).Scan(&p.ID, &p.Name, &p.Description, &p.PolicyType, &p.Conditions, &p.Actions,
		&p.Enabled, &p.Schedule, &p.GracePeriodDays, &p.NotifyBeforeDays,
		&p.LastRunAt, &p.NextRunAt, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}
	c.JSON(http.StatusOK, p)
}

func (s *Service) handleUpdateLifecyclePolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var req struct {
		Name             *string          `json:"name"`
		Description      *string          `json:"description"`
		Conditions       *json.RawMessage `json:"conditions"`
		Actions          *json.RawMessage `json:"actions"`
		Enabled          *bool            `json:"enabled"`
		Schedule         *string          `json:"schedule"`
		GracePeriodDays  *int             `json:"grace_period_days"`
		NotifyBeforeDays *int             `json:"notify_before_days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Dynamic update
	sets := []string{"updated_at = NOW()"}
	args := []interface{}{}
	argIdx := 1

	if req.Name != nil {
		sets = append(sets, pf("name = $%d", argIdx))
		args = append(args, *req.Name)
		argIdx++
	}
	if req.Description != nil {
		sets = append(sets, pf("description = $%d", argIdx))
		args = append(args, *req.Description)
		argIdx++
	}
	if req.Conditions != nil {
		sets = append(sets, pf("conditions = $%d", argIdx))
		args = append(args, *req.Conditions)
		argIdx++
	}
	if req.Actions != nil {
		sets = append(sets, pf("actions = $%d", argIdx))
		args = append(args, *req.Actions)
		argIdx++
	}
	if req.Enabled != nil {
		sets = append(sets, pf("enabled = $%d", argIdx))
		args = append(args, *req.Enabled)
		argIdx++
	}
	if req.Schedule != nil {
		sets = append(sets, pf("schedule = $%d", argIdx))
		args = append(args, *req.Schedule)
		argIdx++
	}
	if req.GracePeriodDays != nil {
		sets = append(sets, pf("grace_period_days = $%d", argIdx))
		args = append(args, *req.GracePeriodDays)
		argIdx++
	}
	if req.NotifyBeforeDays != nil {
		sets = append(sets, pf("notify_before_days = $%d", argIdx))
		args = append(args, *req.NotifyBeforeDays)
		argIdx++
	}

	args = append(args, id)
	query := pf("UPDATE lifecycle_policies SET %s WHERE id = $%d", joinSetClauses(sets), argIdx)

	tag, err := s.db.Pool.Exec(c.Request.Context(), query, args...)
	if err != nil {
		s.logger.Error("Failed to update lifecycle policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update policy"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Policy updated"})
}

func (s *Service) handleDeleteLifecyclePolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	tag, err := s.db.Pool.Exec(c.Request.Context(), "DELETE FROM lifecycle_policies WHERE id = $1", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete policy"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted"})
}

func (s *Service) handleExecuteLifecyclePolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var req struct {
		DryRun bool `json:"dry_run"`
	}
	_ = c.ShouldBindJSON(&req)

	// Load policy
	var p LifecyclePolicy
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, name, policy_type, conditions, actions FROM lifecycle_policies WHERE id = $1`, id,
	).Scan(&p.ID, &p.Name, &p.PolicyType, &p.Conditions, &p.Actions)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	// Find affected users
	affected := s.findAffectedUsers(c.Request.Context(), p)

	if req.DryRun {
		c.JSON(http.StatusOK, gin.H{"dry_run": true, "affected_users": affected, "count": len(affected)})
		return
	}

	// Create execution record
	var execID string
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`INSERT INTO lifecycle_executions (policy_id, status, users_scanned) VALUES ($1, 'running', $2) RETURNING id`,
		id, len(affected),
	).Scan(&execID)
	if err != nil {
		s.logger.Error("Failed to create lifecycle execution", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start execution"})
		return
	}

	// Execute actions
	go s.executeLifecyclePolicy(execID, p, affected)

	// Update last_run_at
	_, _ = s.db.Pool.Exec(c.Request.Context(),
		"UPDATE lifecycle_policies SET last_run_at = NOW() WHERE id = $1", id)

	c.JSON(http.StatusOK, gin.H{"execution_id": execID, "affected_count": len(affected), "status": "running"})
}

func (s *Service) findAffectedUsers(ctx context.Context, p LifecyclePolicy) []AffectedUser {
	var users []AffectedUser

	var conds map[string]interface{}
	_ = json.Unmarshal(p.Conditions, &conds)

	switch p.PolicyType {
	case "stale_account_disable":
		inactiveDays := 90
		if v, ok := conds["inactive_days"].(float64); ok {
			inactiveDays = int(v)
		}
		rows, err := s.db.Pool.Query(ctx,
			`SELECT id, username, email, enabled, last_login_at, created_at FROM users
			 WHERE enabled = true AND (last_login_at IS NULL OR last_login_at < NOW() - $1 * INTERVAL '1 day')
			 ORDER BY last_login_at NULLS FIRST LIMIT 500`, inactiveDays)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var u AffectedUser
				if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Enabled, &u.LastLoginAt, &u.CreatedAt); err == nil {
					u.Reason = pf("No login for %d+ days", inactiveDays)
					users = append(users, u)
				}
			}
		}

	case "disabled_account_cleanup":
		disabledDays := 180
		if v, ok := conds["disabled_days"].(float64); ok {
			disabledDays = int(v)
		}
		rows, err := s.db.Pool.Query(ctx,
			`SELECT id, username, email, enabled, last_login_at, created_at FROM users
			 WHERE enabled = false AND updated_at < NOW() - $1 * INTERVAL '1 day'
			 ORDER BY updated_at LIMIT 500`, disabledDays)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var u AffectedUser
				if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Enabled, &u.LastLoginAt, &u.CreatedAt); err == nil {
					u.Reason = pf("Disabled for %d+ days", disabledDays)
					users = append(users, u)
				}
			}
		}

	case "orphan_detection":
		rows, err := s.db.Pool.Query(ctx,
			`SELECT u.id, u.username, u.email, u.enabled, u.last_login_at, u.created_at FROM users u
			 LEFT JOIN group_memberships gm ON u.id = gm.user_id
			 WHERE gm.group_id IS NULL AND (u.last_login_at IS NULL OR u.last_login_at < NOW() - INTERVAL '30 days')
			 ORDER BY u.last_login_at NULLS FIRST LIMIT 500`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var u AffectedUser
				if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Enabled, &u.LastLoginAt, &u.CreatedAt); err == nil {
					u.Reason = "No group memberships and no recent login"
					users = append(users, u)
				}
			}
		}

	case "password_expiry_enforcement":
		maxAgeDays := 90
		if v, ok := conds["max_age_days"].(float64); ok {
			maxAgeDays = int(v)
		}
		rows, err := s.db.Pool.Query(ctx,
			`SELECT id, username, email, enabled, last_login_at, created_at FROM users
			 WHERE enabled = true AND (password_changed_at IS NULL OR password_changed_at < NOW() - $1 * INTERVAL '1 day')
			 ORDER BY password_changed_at NULLS FIRST LIMIT 500`, maxAgeDays)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var u AffectedUser
				if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Enabled, &u.LastLoginAt, &u.CreatedAt); err == nil {
					u.Reason = pf("Password older than %d days", maxAgeDays)
					users = append(users, u)
				}
			}
		}
	}

	if users == nil {
		users = []AffectedUser{}
	}
	return users
}

func (s *Service) executeLifecyclePolicy(execID string, p LifecyclePolicy, affected []AffectedUser) {
	ctx := context.Background()
	usersAffected := 0
	var actionsTaken []map[string]string

	var acts map[string]interface{}
	_ = json.Unmarshal(p.Actions, &acts)
	action, _ := acts["action"].(string)

	for _, u := range affected {
		var err error
		switch action {
		case "disable":
			_, err = s.db.Pool.Exec(ctx, "UPDATE users SET enabled = false, updated_at = NOW() WHERE id = $1", u.ID)
		case "delete":
			_, err = s.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", u.ID)
		case "force_password_reset":
			_, err = s.db.Pool.Exec(ctx, "UPDATE users SET password_must_change = true, updated_at = NOW() WHERE id = $1", u.ID)
		default:
			// Flag only - mark in actions taken
			action = "flagged"
		}

		status := "success"
		if err != nil {
			status = "error"
		}
		actionsTaken = append(actionsTaken, map[string]string{
			"user_id": u.ID, "username": u.Username, "action": action, "status": status, "reason": u.Reason,
		})
		if status == "success" {
			usersAffected++
		}
	}

	actionsJSON, _ := json.Marshal(actionsTaken)
	_, _ = s.db.Pool.Exec(ctx,
		`UPDATE lifecycle_executions SET status = 'completed', users_affected = $1,
		 actions_taken = $2, completed_at = NOW() WHERE id = $3`,
		usersAffected, actionsJSON, execID)
}

func (s *Service) handleListLifecycleExecutions(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	policyID := c.Param("id")
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, policy_id, status, users_scanned, users_affected, actions_taken, started_at, completed_at, error_message
		 FROM lifecycle_executions WHERE policy_id = $1 ORDER BY started_at DESC LIMIT 20`, policyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list executions"})
		return
	}
	defer rows.Close()

	var execs []LifecycleExecution
	for rows.Next() {
		var e LifecycleExecution
		if err := rows.Scan(&e.ID, &e.PolicyID, &e.Status, &e.UsersScanned, &e.UsersAffected,
			&e.ActionsTaken, &e.StartedAt, &e.CompletedAt, &e.ErrorMessage); err != nil {
			continue
		}
		execs = append(execs, e)
	}
	if execs == nil {
		execs = []LifecycleExecution{}
	}
	c.JSON(http.StatusOK, gin.H{"data": execs})
}

func (s *Service) handlePreviewLifecyclePolicy(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		PolicyType string          `json:"policy_type"`
		Conditions json.RawMessage `json:"conditions"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	p := LifecyclePolicy{
		PolicyType: req.PolicyType,
		Conditions: req.Conditions,
	}
	affected := s.findAffectedUsers(c.Request.Context(), p)
	c.JSON(http.StatusOK, gin.H{"affected_users": affected, "count": len(affected)})
}

// pf is a helper for fmt.Sprintf
func pf(format string, a ...interface{}) string {
	return fmt.Sprintf(format, a...)
}

// joinSetClauses joins SQL SET clauses
func joinSetClauses(clauses []string) string {
	result := ""
	for i, c := range clauses {
		if i > 0 {
			result += ", "
		}
		result += c
	}
	return result
}
