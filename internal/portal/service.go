// Package portal provides self-service portal functionality for end users
package portal

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// UserApplication represents an application assigned to a user
type UserApplication struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	BaseURL     string `json:"base_url"`
	Protocol    string `json:"protocol"`
	LogoURL     string `json:"logo_url"`
	SSOEnabled  bool   `json:"sso_enabled"`
}

// GroupJoinRequest represents a user's request to join a group
type GroupJoinRequest struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	GroupID        string     `json:"group_id"`
	GroupName      string     `json:"group_name"`
	Justification  string     `json:"justification"`
	Status         string     `json:"status"`
	ReviewedBy     *string    `json:"reviewed_by,omitempty"`
	ReviewedAt     *time.Time `json:"reviewed_at,omitempty"`
	ReviewComments *string    `json:"review_comments,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// AccessOverview represents a summary of a user's current access
type AccessOverview struct {
	RolesCount      int                      `json:"roles_count"`
	GroupsCount     int                      `json:"groups_count"`
	AppsCount       int                      `json:"apps_count"`
	PendingRequests int                      `json:"pending_requests"`
	Roles           []map[string]interface{} `json:"roles"`
	Groups          []map[string]interface{} `json:"groups"`
}

// Service provides portal business logic
type Service struct {
	db     *database.PostgresDB
	logger *zap.Logger
}

// NewService creates a new portal service
func NewService(db *database.PostgresDB, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		logger: logger,
	}
}

// GetMyApplications returns the applications assigned to a user.
// If no assignments exist, it falls back to returning all enabled applications.
func (s *Service) GetMyApplications(ctx context.Context, userID string) ([]UserApplication, error) {
	query := `
		SELECT a.id, a.name, COALESCE(a.description, '') AS description,
		       COALESCE(a.base_url, '') AS base_url, COALESCE(a.protocol, '') AS protocol
		FROM user_application_assignments uaa
		JOIN applications a ON a.id = uaa.application_id
		WHERE uaa.user_id = $1 AND a.enabled = true
		ORDER BY a.name`

	rows, err := s.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user applications: %w", err)
	}
	defer rows.Close()

	var apps []UserApplication
	for rows.Next() {
		var app UserApplication
		if err := rows.Scan(&app.ID, &app.Name, &app.Description, &app.BaseURL, &app.Protocol); err != nil {
			return nil, fmt.Errorf("failed to scan application: %w", err)
		}
		apps = append(apps, app)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating application rows: %w", err)
	}

	// Fallback: if no assignments exist, return all enabled applications
	if len(apps) == 0 {
		fallbackQuery := `
			SELECT id, name, COALESCE(description, '') AS description,
			       COALESCE(base_url, '') AS base_url, COALESCE(protocol, '') AS protocol
			FROM applications
			WHERE enabled = true
			ORDER BY name`

		fallbackRows, err := s.db.Pool.Query(ctx, fallbackQuery)
		if err != nil {
			return nil, fmt.Errorf("failed to query all applications: %w", err)
		}
		defer fallbackRows.Close()

		for fallbackRows.Next() {
			var app UserApplication
			if err := fallbackRows.Scan(&app.ID, &app.Name, &app.Description, &app.BaseURL, &app.Protocol); err != nil {
				return nil, fmt.Errorf("failed to scan fallback application: %w", err)
			}
			apps = append(apps, app)
		}
		if err := fallbackRows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating fallback application rows: %w", err)
		}
	}

	return apps, nil
}

// GetAvailableGroups returns groups that allow self-join, along with membership and pending request status for the user.
func (s *Service) GetAvailableGroups(ctx context.Context, userID string) ([]map[string]interface{}, error) {
	query := `
		SELECT g.id, g.name, COALESCE(g.description, '') AS description,
		       EXISTS(SELECT 1 FROM group_memberships gm WHERE gm.group_id = g.id AND gm.user_id = $1) AS is_member,
		       EXISTS(SELECT 1 FROM group_join_requests gjr WHERE gjr.group_id = g.id AND gjr.user_id = $1 AND gjr.status = 'pending') AS has_pending_request
		FROM groups g
		WHERE g.allow_self_join = true
		ORDER BY g.name`

	rows, err := s.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query available groups: %w", err)
	}
	defer rows.Close()

	var groups []map[string]interface{}
	for rows.Next() {
		var id, name, description string
		var isMember, hasPendingRequest bool
		if err := rows.Scan(&id, &name, &description, &isMember, &hasPendingRequest); err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}
		groups = append(groups, map[string]interface{}{
			"id":                  id,
			"name":                name,
			"description":         description,
			"is_member":           isMember,
			"has_pending_request": hasPendingRequest,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating group rows: %w", err)
	}

	return groups, nil
}

// RequestGroupJoin handles a user's request to join a group.
// If the group does not require approval, the user is added directly.
func (s *Service) RequestGroupJoin(ctx context.Context, userID, groupID, justification string) error {
	// Check that the group allows self-join and whether approval is required
	var allowSelfJoin, requireApproval bool
	err := s.db.Pool.QueryRow(ctx,
		`SELECT allow_self_join, COALESCE(require_approval, true) FROM groups WHERE id = $1`,
		groupID,
	).Scan(&allowSelfJoin, &requireApproval)
	if err != nil {
		return fmt.Errorf("failed to query group: %w", err)
	}
	if !allowSelfJoin {
		return fmt.Errorf("group does not allow self-join")
	}

	if !requireApproval {
		// Add the user directly to the group
		_, err := s.db.Pool.Exec(ctx,
			`INSERT INTO group_memberships (id, group_id, user_id, created_at) VALUES ($1, $2, $3, $4)
			 ON CONFLICT DO NOTHING`,
			uuid.New().String(), groupID, userID, time.Now().UTC(),
		)
		if err != nil {
			return fmt.Errorf("failed to add user to group: %w", err)
		}
		return nil
	}

	// Insert a join request for approval
	_, err = s.db.Pool.Exec(ctx,
		`INSERT INTO group_join_requests (id, user_id, group_id, justification, status, created_at)
		 VALUES ($1, $2, $3, $4, 'pending', $5)`,
		uuid.New().String(), userID, groupID, justification, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("failed to create group join request: %w", err)
	}

	return nil
}

// GetMyGroupRequests returns the current user's group join requests.
func (s *Service) GetMyGroupRequests(ctx context.Context, userID string) ([]GroupJoinRequest, error) {
	query := `
		SELECT gjr.id, gjr.user_id, gjr.group_id, g.name AS group_name,
		       COALESCE(gjr.justification, '') AS justification, gjr.status,
		       gjr.reviewed_by, gjr.reviewed_at, gjr.review_comments, gjr.created_at
		FROM group_join_requests gjr
		JOIN groups g ON g.id = gjr.group_id
		WHERE gjr.user_id = $1
		ORDER BY gjr.created_at DESC`

	rows, err := s.db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query group requests: %w", err)
	}
	defer rows.Close()

	var requests []GroupJoinRequest
	for rows.Next() {
		var r GroupJoinRequest
		if err := rows.Scan(&r.ID, &r.UserID, &r.GroupID, &r.GroupName,
			&r.Justification, &r.Status, &r.ReviewedBy, &r.ReviewedAt,
			&r.ReviewComments, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan group request: %w", err)
		}
		requests = append(requests, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating group request rows: %w", err)
	}

	return requests, nil
}

// GetAccessOverview returns an overview of the user's current access entitlements.
func (s *Service) GetAccessOverview(ctx context.Context, userID string) (*AccessOverview, error) {
	overview := &AccessOverview{}

	// Count roles
	err := s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id = $1`, userID,
	).Scan(&overview.RolesCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count roles: %w", err)
	}

	// Count groups
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM group_memberships WHERE user_id = $1`, userID,
	).Scan(&overview.GroupsCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count groups: %w", err)
	}

	// Count apps
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_application_assignments WHERE user_id = $1`, userID,
	).Scan(&overview.AppsCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count apps: %w", err)
	}

	// Count pending requests
	err = s.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM group_join_requests WHERE user_id = $1 AND status = 'pending'`, userID,
	).Scan(&overview.PendingRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to count pending requests: %w", err)
	}

	// Get role names
	roleRows, err := s.db.Pool.Query(ctx,
		`SELECT r.id, r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1 ORDER BY r.name`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query roles: %w", err)
	}
	defer roleRows.Close()

	overview.Roles = []map[string]interface{}{}
	for roleRows.Next() {
		var id, name string
		if err := roleRows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		overview.Roles = append(overview.Roles, map[string]interface{}{
			"id":   id,
			"name": name,
		})
	}
	if err := roleRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating role rows: %w", err)
	}

	// Get group names
	groupRows, err := s.db.Pool.Query(ctx,
		`SELECT g.id, g.name FROM group_memberships gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = $1 ORDER BY g.name`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query groups: %w", err)
	}
	defer groupRows.Close()

	overview.Groups = []map[string]interface{}{}
	for groupRows.Next() {
		var id, name string
		if err := groupRows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}
		overview.Groups = append(overview.Groups, map[string]interface{}{
			"id":   id,
			"name": name,
		})
	}
	if err := groupRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating group rows: %w", err)
	}

	return overview, nil
}

// ReviewGroupRequest allows an admin to approve or deny a group join request.
func (s *Service) ReviewGroupRequest(ctx context.Context, requestID, reviewerID, decision, comments string) error {
	if decision != "approved" && decision != "denied" {
		return fmt.Errorf("invalid decision: must be 'approved' or 'denied'")
	}

	now := time.Now().UTC()

	// Update the request status
	tag, err := s.db.Pool.Exec(ctx,
		`UPDATE group_join_requests
		 SET status = $1, reviewed_by = $2, reviewed_at = $3, review_comments = $4
		 WHERE id = $5 AND status = 'pending'`,
		decision, reviewerID, now, comments, requestID,
	)
	if err != nil {
		return fmt.Errorf("failed to update group join request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("request not found or already reviewed")
	}

	// If approved, add the user to the group
	if decision == "approved" {
		var userID, groupID string
		err := s.db.Pool.QueryRow(ctx,
			`SELECT user_id, group_id FROM group_join_requests WHERE id = $1`, requestID,
		).Scan(&userID, &groupID)
		if err != nil {
			return fmt.Errorf("failed to fetch request details: %w", err)
		}

		_, err = s.db.Pool.Exec(ctx,
			`INSERT INTO group_memberships (id, group_id, user_id, created_at) VALUES ($1, $2, $3, $4)
			 ON CONFLICT DO NOTHING`,
			uuid.New().String(), groupID, userID, now,
		)
		if err != nil {
			return fmt.Errorf("failed to add user to group: %w", err)
		}
	}

	return nil
}

// getUserID extracts the user ID from the Gin context, falling back to a default.
func getUserID(c *gin.Context) string {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)
	if userIDStr == "" {
		userIDStr = "00000000-0000-0000-0000-000000000001"
	}
	return userIDStr
}

// handleGetMyApplications handles GET /portal/applications
func (s *Service) handleGetMyApplications(c *gin.Context) {
	userIDStr := getUserID(c)

	apps, err := s.GetMyApplications(c.Request.Context(), userIDStr)
	if err != nil {
		s.logger.Error("failed to get user applications", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get applications"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"applications": apps})
}

// handleGetAvailableGroups handles GET /portal/groups/available
func (s *Service) handleGetAvailableGroups(c *gin.Context) {
	userIDStr := getUserID(c)

	groups, err := s.GetAvailableGroups(c.Request.Context(), userIDStr)
	if err != nil {
		s.logger.Error("failed to get available groups", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get available groups"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"groups": groups})
}

// handleRequestGroupJoin handles POST /portal/groups/request
func (s *Service) handleRequestGroupJoin(c *gin.Context) {
	userIDStr := getUserID(c)

	var req struct {
		GroupID       string `json:"group_id" binding:"required"`
		Justification string `json:"justification"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	err := s.RequestGroupJoin(c.Request.Context(), userIDStr, req.GroupID, req.Justification)
	if err != nil {
		s.logger.Error("failed to request group join", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "group join request submitted"})
}

// handleGetMyGroupRequests handles GET /portal/groups/requests
func (s *Service) handleGetMyGroupRequests(c *gin.Context) {
	userIDStr := getUserID(c)

	requests, err := s.GetMyGroupRequests(c.Request.Context(), userIDStr)
	if err != nil {
		s.logger.Error("failed to get group requests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get group requests"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"requests": requests})
}

// handleGetAccessOverview handles GET /portal/access-overview
func (s *Service) handleGetAccessOverview(c *gin.Context) {
	userIDStr := getUserID(c)

	overview, err := s.GetAccessOverview(c.Request.Context(), userIDStr)
	if err != nil {
		s.logger.Error("failed to get access overview", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get access overview"})
		return
	}

	c.JSON(http.StatusOK, overview)
}

// handleReviewGroupRequest handles POST /portal/groups/requests/:id/review (admin only)
func (s *Service) handleReviewGroupRequest(c *gin.Context) {
	requestID := c.Param("id")
	if requestID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request ID is required"})
		return
	}

	reviewerID := getUserID(c)

	var req struct {
		Decision string `json:"decision" binding:"required"`
		Comments string `json:"comments"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	err := s.ReviewGroupRequest(c.Request.Context(), requestID, reviewerID, req.Decision, req.Comments)
	if err != nil {
		s.logger.Error("failed to review group request", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "group request reviewed"})
}

// RegisterRoutes registers all portal HTTP routes on the given router group.
func RegisterRoutes(router *gin.RouterGroup, svc *Service) {
	router.GET("/portal/applications", svc.handleGetMyApplications)
	router.GET("/portal/groups/available", svc.handleGetAvailableGroups)
	router.POST("/portal/groups/request", svc.handleRequestGroupJoin)
	router.GET("/portal/groups/requests", svc.handleGetMyGroupRequests)
	router.GET("/portal/access-overview", svc.handleGetAccessOverview)
	router.POST("/portal/groups/requests/:id/review", svc.handleReviewGroupRequest)
}
