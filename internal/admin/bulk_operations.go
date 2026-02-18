package admin

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// BulkOperation represents a bulk operation on multiple entities
type BulkOperation struct {
	ID             string          `json:"id"`
	Type           string          `json:"type"`
	Status         string          `json:"status"`
	TotalItems     int             `json:"total_items"`
	ProcessedItems int             `json:"processed_items"`
	SuccessCount   int             `json:"success_count"`
	ErrorCount     int             `json:"error_count"`
	Errors         json.RawMessage `json:"errors"`
	Parameters     json.RawMessage `json:"parameters"`
	CreatedBy      *string         `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
	CompletedAt    *time.Time      `json:"completed_at"`
}

// BulkOperationItem represents an individual item in a bulk operation
type BulkOperationItem struct {
	ID           string     `json:"id"`
	OperationID  string     `json:"operation_id"`
	EntityID     *string    `json:"entity_id"`
	EntityName   string     `json:"entity_name"`
	Status       string     `json:"status"`
	ErrorMessage string     `json:"error_message,omitempty"`
	ProcessedAt  *time.Time `json:"processed_at,omitempty"`
}

// --- Handlers ---

func (s *Service) handleCreateBulkOperation(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	var req struct {
		Type       string          `json:"type"`
		UserIDs    []string        `json:"user_ids"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	validTypes := map[string]bool{
		"enable_users": true, "disable_users": true, "delete_users": true,
		"assign_role": true, "remove_role": true, "add_to_group": true,
		"remove_from_group": true, "reset_passwords": true,
	}
	if !validTypes[req.Type] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid operation type"})
		return
	}

	if len(req.UserIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_ids is required"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)
	params := req.Parameters
	if params == nil {
		params = json.RawMessage("{}")
	}

	ctx := c.Request.Context()

	// Create the bulk operation
	var opID string
	err := s.db.Pool.QueryRow(ctx,
		`INSERT INTO bulk_operations (type, status, total_items, parameters, created_by)
		 VALUES ($1, 'running', $2, $3, $4) RETURNING id`,
		req.Type, len(req.UserIDs), params, nilIfEmpty(userIDStr),
	).Scan(&opID)
	if err != nil {
		s.logger.Error("Failed to create bulk operation", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create operation"})
		return
	}

	// Insert items
	for _, uid := range req.UserIDs {
		// Look up username for display
		var username string
		_ = s.db.Pool.QueryRow(ctx, "SELECT username FROM users WHERE id = $1", uid).Scan(&username)
		if username == "" {
			username = uid
		}
		_, _ = s.db.Pool.Exec(ctx,
			`INSERT INTO bulk_operation_items (operation_id, entity_id, entity_name, status)
			 VALUES ($1, $2, $3, 'pending')`, opID, uid, username)
	}

	// Execute the operation
	go s.executeBulkOperation(opID, req.Type, req.UserIDs, params)

	c.JSON(http.StatusCreated, gin.H{"id": opID, "status": "running", "total_items": len(req.UserIDs)})
}

func (s *Service) executeBulkOperation(opID, opType string, userIDs []string, params json.RawMessage) {
	ctx := context.Background()
	successCount := 0
	errorCount := 0
	var errors []map[string]string

	var paramMap map[string]string
	_ = json.Unmarshal(params, &paramMap)

	for _, uid := range userIDs {
		var errMsg string

		switch opType {
		case "enable_users":
			_, err := s.db.Pool.Exec(ctx, "UPDATE users SET enabled = true, updated_at = NOW() WHERE id = $1", uid)
			if err != nil {
				errMsg = err.Error()
			}
		case "disable_users":
			_, err := s.db.Pool.Exec(ctx, "UPDATE users SET enabled = false, updated_at = NOW() WHERE id = $1", uid)
			if err != nil {
				errMsg = err.Error()
			}
		case "delete_users":
			_, err := s.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", uid)
			if err != nil {
				errMsg = err.Error()
			}
		case "assign_role":
			roleID := paramMap["role_id"]
			if roleID == "" {
				errMsg = "role_id parameter required"
			} else {
				_, err := s.db.Pool.Exec(ctx,
					`INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES ($1, $2, NOW())
					 ON CONFLICT (user_id, role_id) DO NOTHING`, uid, roleID)
				if err != nil {
					errMsg = err.Error()
				}
			}
		case "remove_role":
			roleID := paramMap["role_id"]
			if roleID == "" {
				errMsg = "role_id parameter required"
			} else {
				_, err := s.db.Pool.Exec(ctx, "DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2", uid, roleID)
				if err != nil {
					errMsg = err.Error()
				}
			}
		case "add_to_group":
			groupID := paramMap["group_id"]
			if groupID == "" {
				errMsg = "group_id parameter required"
			} else {
				_, err := s.db.Pool.Exec(ctx,
					`INSERT INTO group_memberships (user_id, group_id, joined_at) VALUES ($1, $2, NOW())
					 ON CONFLICT DO NOTHING`, uid, groupID)
				if err != nil {
					errMsg = err.Error()
				}
			}
		case "remove_from_group":
			groupID := paramMap["group_id"]
			if groupID == "" {
				errMsg = "group_id parameter required"
			} else {
				_, err := s.db.Pool.Exec(ctx, "DELETE FROM group_memberships WHERE user_id = $1 AND group_id = $2", uid, groupID)
				if err != nil {
					errMsg = err.Error()
				}
			}
		case "reset_passwords":
			_, err := s.db.Pool.Exec(ctx, "UPDATE users SET password_must_change = true, updated_at = NOW() WHERE id = $1", uid)
			if err != nil {
				errMsg = err.Error()
			}
		}

		now := time.Now()
		if errMsg != "" {
			errorCount++
			errors = append(errors, map[string]string{"user_id": uid, "error": errMsg})
			_, _ = s.db.Pool.Exec(ctx,
				"UPDATE bulk_operation_items SET status = 'error', error_message = $1, processed_at = $2 WHERE operation_id = $3 AND entity_id = $4",
				errMsg, now, opID, uid)
		} else {
			successCount++
			_, _ = s.db.Pool.Exec(ctx,
				"UPDATE bulk_operation_items SET status = 'success', processed_at = $1 WHERE operation_id = $2 AND entity_id = $3",
				now, opID, uid)
		}

		// Update progress
		_, _ = s.db.Pool.Exec(ctx,
			"UPDATE bulk_operations SET processed_items = processed_items + 1, success_count = $1, error_count = $2 WHERE id = $3",
			successCount, errorCount, opID)
	}

	// Mark completed
	errorsJSON, _ := json.Marshal(errors)
	if errors == nil {
		errorsJSON = []byte("[]")
	}
	_, _ = s.db.Pool.Exec(ctx,
		"UPDATE bulk_operations SET status = 'completed', errors = $1, completed_at = NOW() WHERE id = $2",
		errorsJSON, opID)
}

func (s *Service) handleListBulkOperations(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, type, status, total_items, processed_items, success_count, error_count,
		        errors, parameters, created_by, created_at, completed_at
		 FROM bulk_operations ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		s.logger.Error("Failed to list bulk operations", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list operations"})
		return
	}
	defer rows.Close()

	var ops []BulkOperation
	for rows.Next() {
		var op BulkOperation
		if err := rows.Scan(&op.ID, &op.Type, &op.Status, &op.TotalItems, &op.ProcessedItems,
			&op.SuccessCount, &op.ErrorCount, &op.Errors, &op.Parameters,
			&op.CreatedBy, &op.CreatedAt, &op.CompletedAt); err != nil {
			continue
		}
		ops = append(ops, op)
	}
	if ops == nil {
		ops = []BulkOperation{}
	}
	c.JSON(http.StatusOK, gin.H{"data": ops})
}

func (s *Service) handleGetBulkOperation(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	var op BulkOperation
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, type, status, total_items, processed_items, success_count, error_count,
		        errors, parameters, created_by, created_at, completed_at
		 FROM bulk_operations WHERE id = $1`, id,
	).Scan(&op.ID, &op.Type, &op.Status, &op.TotalItems, &op.ProcessedItems,
		&op.SuccessCount, &op.ErrorCount, &op.Errors, &op.Parameters,
		&op.CreatedBy, &op.CreatedAt, &op.CompletedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Operation not found"})
		return
	}

	// Fetch items
	itemRows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, operation_id, entity_id, entity_name, status, error_message, processed_at
		 FROM bulk_operation_items WHERE operation_id = $1 ORDER BY entity_name`, id)
	if err == nil {
		defer itemRows.Close()
		var items []BulkOperationItem
		for itemRows.Next() {
			var item BulkOperationItem
			if err := itemRows.Scan(&item.ID, &item.OperationID, &item.EntityID, &item.EntityName,
				&item.Status, &item.ErrorMessage, &item.ProcessedAt); err != nil {
				continue
			}
			items = append(items, item)
		}
		if items == nil {
			items = []BulkOperationItem{}
		}
		c.JSON(http.StatusOK, gin.H{"operation": op, "items": items})
		return
	}

	c.JSON(http.StatusOK, gin.H{"operation": op, "items": []interface{}{}})
}

func (s *Service) handleCancelBulkOperation(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	id := c.Param("id")
	tag, err := s.db.Pool.Exec(c.Request.Context(),
		"UPDATE bulk_operations SET status = 'cancelled', completed_at = NOW() WHERE id = $1 AND status IN ('pending', 'running')", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel operation"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Operation not found or already completed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Operation cancelled"})
}

func (s *Service) handleExportUsersCSV(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT u.id, u.username, u.email, u.first_name, u.last_name, u.enabled,
		        u.email_verified, u.created_at, u.last_login_at,
		        COALESCE(string_agg(DISTINCT r.name, ', '), '') as roles,
		        COALESCE(string_agg(DISTINCT g.name, ', '), '') as groups
		 FROM users u
		 LEFT JOIN user_roles ur ON u.id = ur.user_id
		 LEFT JOIN roles r ON ur.role_id = r.id
		 LEFT JOIN group_memberships gm ON u.id = gm.user_id
		 LEFT JOIN groups g ON gm.group_id = g.id
		 GROUP BY u.id ORDER BY u.username`)
	if err != nil {
		s.logger.Error("Failed to export users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to export users"})
		return
	}
	defer rows.Close()

	c.Header("Content-Type", "text/csv")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=users_export_%s.csv", time.Now().Format("2006-01-02")))

	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"ID", "Username", "Email", "First Name", "Last Name", "Enabled", "Email Verified", "Created At", "Last Login", "Roles", "Groups"})

	for rows.Next() {
		var id, username, email, firstName, lastName, roles, groups string
		var enabled, emailVerified bool
		var createdAt time.Time
		var lastLogin *time.Time

		if err := rows.Scan(&id, &username, &email, &firstName, &lastName, &enabled,
			&emailVerified, &createdAt, &lastLogin, &roles, &groups); err != nil {
			continue
		}

		lastLoginStr := ""
		if lastLogin != nil {
			lastLoginStr = lastLogin.Format(time.RFC3339)
		}

		_ = w.Write([]string{
			id, username, email, firstName, lastName,
			boolStr(enabled), boolStr(emailVerified),
			createdAt.Format(time.RFC3339), lastLoginStr,
			roles, groups,
		})
	}
	w.Flush()
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// trimmedLower returns a trimmed lowercase version of s
func trimmedLower(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
