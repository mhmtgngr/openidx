package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
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

	// Capture the org synchronously: the execution runs on a detached
	// context.Background goroutine, so it can't read the request org later.
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}

	// Create the bulk operation
	var opID string
	err = s.db.Pool.QueryRow(ctx,
		`INSERT INTO bulk_operations (type, status, total_items, parameters, created_by, org_id)
		 VALUES ($1, 'running', $2, $3, $4, $5) RETURNING id`,
		req.Type, len(req.UserIDs), params, nilIfEmpty(userIDStr), org.ID,
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
		_ = s.db.Pool.QueryRow(ctx, "SELECT username FROM users WHERE id = $1 AND org_id = $2", uid, org.ID).Scan(&username)
		if username == "" {
			username = uid
		}
		_, _ = s.db.Pool.Exec(ctx,
			`INSERT INTO bulk_operation_items (operation_id, entity_id, entity_name, status, org_id)
			 VALUES ($1, $2, $3, 'pending', $4)`, opID, uid, username, org.ID)
	}

	// Execute the operation (org captured above and threaded into the detached goroutine)
	go s.executeBulkOperation(org.ID, opID, req.Type, req.UserIDs, params)

	c.JSON(http.StatusCreated, gin.H{"id": opID, "status": "running", "total_items": len(req.UserIDs)})
}

func (s *Service) executeBulkOperation(orgID, opID, opType string, userIDs []string, params json.RawMessage) {
	// The org must travel on the CONTEXT, not only as an argument. Every table
	// touched below is behind the FORCE-RLS belt, and the pool sets app.org_id
	// at checkout from orgctx -- on a bare context.Background it is empty, so
	// reads return nothing and writes are refused. The orgID parameter was
	// already threaded here for the SQL predicates; this puts it where the
	// database can see it too.
	ctx, cancel := context.WithTimeout(
		orgctx.With(context.Background(), orgctx.Org{ID: orgID}), 15*time.Minute)
	defer cancel()
	successCount := 0
	errorCount := 0
	cancelled := false
	var errors []map[string]string

	var paramMap map[string]string
	_ = json.Unmarshal(params, &paramMap)

	for _, uid := range userIDs {
		// Cancel used to be a lie. handleCancelBulkOperation writes
		// status = 'cancelled' on the row and this loop never read that column:
		// it walked every id it was given and then wrote 'completed' over the
		// top, so pressing Cancel on a running bulk DELETE stopped nothing and
		// left no sign it had been ignored. Check before each account.
		var status string
		if err := s.db.Pool.QueryRow(ctx,
			"SELECT status FROM bulk_operations WHERE id = $1 AND org_id = $2", opID, orgID).Scan(&status); err == nil {
			if status == "cancelled" {
				cancelled = true
				break
			}
		}

		var errMsg string

		switch opType {
		case "enable_users":
			tag, err := s.db.Pool.Exec(ctx, "UPDATE users SET enabled = true, updated_at = NOW() WHERE id = $1 AND org_id = $2", uid, orgID)
			errMsg = bulkActionResult(tag, err)
		case "disable_users":
			tag, err := s.db.Pool.Exec(ctx, "UPDATE users SET enabled = false, updated_at = NOW() WHERE id = $1 AND org_id = $2", uid, orgID)
			errMsg = bulkActionResult(tag, err)
		case "delete_users":
			tag, err := s.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1 AND org_id = $2", uid, orgID)
			errMsg = bulkActionResult(tag, err)
		case "assign_role":
			roleID := paramMap["role_id"]
			if roleID == "" {
				errMsg = "role_id parameter required"
			} else {
				_, err := s.db.Pool.Exec(ctx,
					`INSERT INTO user_roles (user_id, role_id, assigned_at, org_id) VALUES ($1, $2, NOW(), $3)
					 ON CONFLICT (user_id, role_id) DO NOTHING`, uid, roleID, orgID)
				if err != nil {
					errMsg = err.Error()
				}
			}
		case "remove_role":
			roleID := paramMap["role_id"]
			if roleID == "" {
				errMsg = "role_id parameter required"
			} else {
				_, err := s.db.Pool.Exec(ctx, "DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2 AND org_id = $3", uid, roleID, orgID)
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
					`INSERT INTO group_memberships (user_id, group_id, joined_at, org_id) VALUES ($1, $2, NOW(), $3)
					 ON CONFLICT DO NOTHING`, uid, groupID, orgID)
				if err != nil {
					errMsg = err.Error()
				}
			}
		case "remove_from_group":
			groupID := paramMap["group_id"]
			if groupID == "" {
				errMsg = "group_id parameter required"
			} else {
				_, err := s.db.Pool.Exec(ctx, "DELETE FROM group_memberships WHERE user_id = $1 AND group_id = $2 AND org_id = $3", uid, groupID, orgID)
				if err != nil {
					errMsg = err.Error()
				}
			}
		case "reset_passwords":
			tag, err := s.db.Pool.Exec(ctx, "UPDATE users SET password_must_change = true, updated_at = NOW() WHERE id = $1 AND org_id = $2", uid, orgID)
			errMsg = bulkActionResult(tag, err)
		}

		now := time.Now()
		if errMsg != "" {
			errorCount++
			errors = append(errors, map[string]string{"user_id": uid, "error": errMsg})
			_, _ = s.db.Pool.Exec(ctx,
				"UPDATE bulk_operation_items SET status = 'error', error_message = $1, processed_at = $2 WHERE operation_id = $3 AND entity_id = $4 AND org_id = $5",
				errMsg, now, opID, uid, orgID)
		} else {
			successCount++
			_, _ = s.db.Pool.Exec(ctx,
				"UPDATE bulk_operation_items SET status = 'success', processed_at = $1 WHERE operation_id = $2 AND entity_id = $3 AND org_id = $4",
				now, opID, uid, orgID)
		}

		// Update progress
		_, _ = s.db.Pool.Exec(ctx,
			"UPDATE bulk_operations SET processed_items = processed_items + 1, success_count = $1, error_count = $2 WHERE id = $3 AND org_id = $4",
			successCount, errorCount, opID, orgID)
	}

	// Mark completed. The status predicate is what stops this overwriting a
	// run the administrator cancelled: the old statement wrote 'completed'
	// unconditionally, so a cancel that had already landed was erased and the
	// console showed a run that finished normally.
	errorsJSON, _ := json.Marshal(errors)
	if errors == nil {
		errorsJSON = []byte("[]")
	}
	final := "completed"
	if cancelled {
		final = "cancelled"
	}
	_, _ = s.db.Pool.Exec(ctx,
		`UPDATE bulk_operations SET status = $1, errors = $2, completed_at = NOW()
		 WHERE id = $3 AND org_id = $4 AND status <> 'cancelled'`,
		final, errorsJSON, opID, orgID)
}

// bulkActionResult turns one action's outcome into an error string.
//
// An action that matched no row is an error. `UPDATE users SET enabled = false
// WHERE id = $1 AND org_id = $2` against an id outside the caller's
// organization affects nothing and returns no error, so every such item used to
// be recorded 'success': a bulk disable over fifty foreign ids reported fifty
// successes and changed nothing. Same shape as v154's ExecuteLifecycleWorkflow,
// which reported a completed run having touched no account.
func bulkActionResult(tag pgconn.CommandTag, err error) string {
	if err != nil {
		return err.Error()
	}
	if tag.RowsAffected() == 0 {
		return "no matching user in this organization"
	}
	return ""
}

func (s *Service) handleListBulkOperations(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}

	org, ok := requireOrg(c)
	if !ok {
		return
	}

	// The org term. Without it this list returned every organization's bulk
	// runs -- their type ("delete_users"), their counts, and the role or group
	// id each applied.
	rows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, COALESCE(type, ''), COALESCE(status, ''), COALESCE(total_items, 0),
		        COALESCE(processed_items, 0), COALESCE(success_count, 0), COALESCE(error_count, 0),
		        COALESCE(errors, '[]'), COALESCE(parameters, '{}'), created_by, created_at, completed_at
		 FROM bulk_operations WHERE org_id = $1 ORDER BY created_at DESC LIMIT 50`, org.ID)
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
			s.logger.Warn("skipping unreadable bulk operation row", zap.Error(err))
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

	org, ok := requireOrg(c)
	if !ok {
		return
	}

	id := c.Param("id")
	var op BulkOperation
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT id, COALESCE(type, ''), COALESCE(status, ''), COALESCE(total_items, 0),
		        COALESCE(processed_items, 0), COALESCE(success_count, 0), COALESCE(error_count, 0),
		        COALESCE(errors, '[]'), COALESCE(parameters, '{}'), created_by, created_at, completed_at
		 FROM bulk_operations WHERE id = $1 AND org_id = $2`, id, org.ID,
	).Scan(&op.ID, &op.Type, &op.Status, &op.TotalItems, &op.ProcessedItems,
		&op.SuccessCount, &op.ErrorCount, &op.Errors, &op.Parameters,
		&op.CreatedBy, &op.CreatedAt, &op.CompletedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Operation not found"})
		return
	}

	// Fetch items. entity_name is the USERNAME the item acted on, so this list
	// is a directory extract: without the org term, opening another
	// organization's run returned their accounts, one row each, with what was
	// done to them and why it failed.
	itemRows, err := s.db.Pool.Query(c.Request.Context(),
		`SELECT id, operation_id, entity_id, COALESCE(entity_name, ''), COALESCE(status, ''),
		        COALESCE(error_message, ''), processed_at
		 FROM bulk_operation_items WHERE operation_id = $1 AND org_id = $2 ORDER BY entity_name`, id, org.ID)
	if err == nil {
		defer itemRows.Close()
		var items []BulkOperationItem
		for itemRows.Next() {
			var item BulkOperationItem
			if err := itemRows.Scan(&item.ID, &item.OperationID, &item.EntityID, &item.EntityName,
				&item.Status, &item.ErrorMessage, &item.ProcessedAt); err != nil {
				// error_message is NULL on every pending and every SUCCESSFUL
				// item, and it was scanned into a plain string with `continue`
				// on failure -- so this list showed only the items that had
				// already failed, and a run that succeeded looked empty. The
				// same defect v154 found in the lifecycle run log, in a
				// different file. COALESCEd above; a skip is now a logged fault.
				s.logger.Warn("skipping unreadable bulk operation item", zap.Error(err))
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

	org, ok := requireOrg(c)
	if !ok {
		return
	}

	id := c.Param("id")
	tag, err := s.db.Pool.Exec(c.Request.Context(),
		`UPDATE bulk_operations SET status = 'cancelled', completed_at = NOW()
		 WHERE id = $1 AND org_id = $2 AND status IN ('pending', 'running')`, id, org.ID)
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

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
