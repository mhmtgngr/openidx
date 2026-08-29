package portal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/notifications"
)

// AppAssignment is one principal (a user or a group) granted access to an
// application. It backs the admin "Manage access" dialog on the applications
// page — the one-click way to grant app access for demos and real use.
type AppAssignment struct {
	PrincipalType string `json:"principal_type"` // "user" | "group"
	PrincipalID   string `json:"principal_id"`
	PrincipalName string `json:"principal_name"`
	AssignedAt    string `json:"assigned_at"`
}

// handleListAppAssignments handles GET /portal/applications/:id/assignments (admin).
// It returns both the user- and group-level assignees of an application.
func (s *Service) handleListAppAssignments(c *gin.Context) {
	if _, ok := requireUserID(c); !ok {
		return
	}
	if !callerIsAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin role required to manage application access"})
		return
	}
	appID := c.Param("id")
	if appID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "application ID is required"})
		return
	}

	assignments, err := s.ListAppAssignments(c.Request.Context(), appID)
	if err != nil {
		s.logger.Error("failed to list app assignments", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list assignments"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"assignments": assignments})
}

// handleCreateAppAssignment handles POST /portal/applications/:id/assignments (admin).
// Body: {principal_type: "user"|"group", principal_id}. Idempotent.
func (s *Service) handleCreateAppAssignment(c *gin.Context) {
	assignerID, ok := requireUserID(c)
	if !ok {
		return
	}
	if !callerIsAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin role required to manage application access"})
		return
	}
	appID := c.Param("id")
	if appID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "application ID is required"})
		return
	}

	var req struct {
		PrincipalType string `json:"principal_type" binding:"required"`
		PrincipalID   string `json:"principal_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	err := s.CreateAppAssignment(c.Request.Context(), appID, req.PrincipalType, req.PrincipalID, assignerID)
	switch {
	case errors.Is(err, errInvalidPrincipalType):
		c.JSON(http.StatusBadRequest, gin.H{"error": "principal_type must be 'user' or 'group'"})
		return
	case errors.Is(err, errPrincipalNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "principal not found in this organization"})
		return
	case errors.Is(err, errApplicationNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	case err != nil:
		s.logger.Error("failed to create app assignment", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create assignment"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "assignment created"})
}

// handleDeleteAppAssignment handles DELETE /portal/applications/:id/assignments/:pid?type=user|group (admin).
func (s *Service) handleDeleteAppAssignment(c *gin.Context) {
	if _, ok := requireUserID(c); !ok {
		return
	}
	if !callerIsAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin role required to manage application access"})
		return
	}
	appID := c.Param("id")
	principalID := c.Param("pid")
	principalType := c.Query("type")
	if appID == "" || principalID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "application ID and principal ID are required"})
		return
	}

	err := s.DeleteAppAssignment(c.Request.Context(), appID, principalType, principalID)
	switch {
	case errors.Is(err, errInvalidPrincipalType):
		c.JSON(http.StatusBadRequest, gin.H{"error": "type must be 'user' or 'group'"})
		return
	case err != nil:
		s.logger.Error("failed to delete app assignment", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete assignment"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "assignment removed"})
}

var (
	errInvalidPrincipalType = errors.New("invalid principal type")
	errPrincipalNotFound    = errors.New("principal not found")
	errApplicationNotFound  = errors.New("application not found")
)

// ListAppAssignments returns the users and groups assigned to an application,
// scoped to the caller's org.
func (s *Service) ListAppAssignments(ctx context.Context, appID string) ([]AppAssignment, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}

	// Users assigned directly, then groups assigned — a stable, name-sorted list.
	rows, err := s.db.Pool.Query(ctx, `
		SELECT 'user' AS principal_type, u.id::text, COALESCE(u.username, u.email, u.id::text) AS name, uaa.assigned_at
		FROM user_application_assignments uaa
		JOIN users u ON u.id = uaa.user_id
		WHERE uaa.application_id = $1 AND uaa.org_id = $2
		UNION ALL
		SELECT 'group' AS principal_type, g.id::text, g.name, gaa.assigned_at
		FROM group_application_assignments gaa
		JOIN groups g ON g.id = gaa.group_id
		WHERE gaa.application_id = $1 AND gaa.org_id = $2
		ORDER BY principal_type, name`, appID, org.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	assignments := []AppAssignment{}
	for rows.Next() {
		var a AppAssignment
		var ts time.Time
		if err := rows.Scan(&a.PrincipalType, &a.PrincipalID, &a.PrincipalName, &ts); err != nil {
			return nil, err
		}
		a.AssignedAt = ts.Format(time.RFC3339)
		assignments = append(assignments, a)
	}
	return assignments, rows.Err()
}

// CreateAppAssignment grants an application to a user or group. Idempotent
// (ON CONFLICT DO NOTHING). Validates that the principal and application both
// belong to the caller's org before inserting.
func (s *Service) CreateAppAssignment(ctx context.Context, appID, principalType, principalID, assignerID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}

	// Application must exist in this org (grab its name for the notification).
	var appName string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT name FROM applications WHERE id = $1 AND org_id = $2`, appID, org.ID,
	).Scan(&appName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errApplicationNotFound
		}
		return err
	}

	var exists bool
	switch principalType {
	case "user":
		if err := s.db.Pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND org_id = $2)`, principalID, org.ID,
		).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return errPrincipalNotFound
		}
		if _, err = s.db.Pool.Exec(ctx,
			`INSERT INTO user_application_assignments (user_id, application_id, org_id)
			 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, principalID, appID, org.ID); err != nil {
			return err
		}
	case "group":
		if err := s.db.Pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1 AND org_id = $2)`, principalID, org.ID,
		).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return errPrincipalNotFound
		}
		if _, err = s.db.Pool.Exec(ctx,
			`INSERT INTO group_application_assignments (group_id, application_id, org_id, assigned_by)
			 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, principalID, appID, org.ID, assignerID); err != nil {
			return err
		}
	default:
		return errInvalidPrincipalType
	}

	// Best-effort notify the recipient(s) that they have a new app. A group
	// grant notifies every member. Never fails the assignment.
	s.notifyAppGranted(ctx, org.ID, principalType, principalID, appName)
	return nil
}

// notifyAppGranted tells the granted user (or every member of a granted group)
// that a new application is available. Best-effort: logged, never fatal.
func (s *Service) notifyAppGranted(ctx context.Context, orgID, principalType, principalID, appName string) {
	recipients, err := s.grantRecipients(ctx, orgID, principalType, principalID)
	if err != nil {
		s.logger.Warn("notify app grant: resolve recipients failed", zap.Error(err))
		return
	}
	notif := notifications.NewService(s.db, s.logger)
	body := fmt.Sprintf("You've been granted access to %s.", appName)
	for _, uid := range recipients {
		if err := notif.CreateMultiChannelNotification(ctx, uid, orgID, "access_granted",
			"New app available", body, "/portal/applications",
			map[string]interface{}{"application": appName}); err != nil {
			s.logger.Warn("notify app grant failed", zap.String("user_id", uid), zap.Error(err))
		}
	}
}

// grantRecipients resolves a grant principal to the user IDs that should be
// notified: a user is itself; a group expands to its members.
func (s *Service) grantRecipients(ctx context.Context, orgID, principalType, principalID string) ([]string, error) {
	switch principalType {
	case "user":
		return []string{principalID}, nil
	case "group":
		rows, err := s.db.Pool.Query(ctx,
			`SELECT user_id::text FROM group_memberships WHERE group_id = $1 AND org_id = $2`,
			principalID, orgID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		ids := []string{}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		return ids, rows.Err()
	default:
		return nil, nil
	}
}

// DeleteAppAssignment revokes an application grant from a user or group.
func (s *Service) DeleteAppAssignment(ctx context.Context, appID, principalType, principalID string) error {
	org, err := orgctx.From(ctx)
	if err != nil {
		return err
	}
	switch principalType {
	case "user":
		_, err = s.db.Pool.Exec(ctx,
			`DELETE FROM user_application_assignments WHERE user_id = $1 AND application_id = $2 AND org_id = $3`,
			principalID, appID, org.ID)
		return err
	case "group":
		_, err = s.db.Pool.Exec(ctx,
			`DELETE FROM group_application_assignments WHERE group_id = $1 AND application_id = $2 AND org_id = $3`,
			principalID, appID, org.ID)
		return err
	default:
		return errInvalidPrincipalType
	}
}
